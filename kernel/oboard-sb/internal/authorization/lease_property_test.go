package authorization

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

// deliveryOp is one step of a randomly generated delivery history: a lease
// message from the Controller (possibly stale or replayed), an emergency
// deny, or a kernel restart that reopens the store from disk.
type deliveryOp struct {
	kind  string
	lease *Lease
	deny  []string
	denyR int64
}

// A revocation the kernel has confirmed once must hold under every delivery
// order the transport can produce: messages may be lost, duplicated,
// reordered, and the process may restart between any two of them. The
// generator issues a monotonically increasing revision history in which one
// key is granted early and revoked at a fixed revision; the invariant is that
// once any message carrying the revocation has been applied, the key is never
// admitted again, whatever older message arrives afterwards.
func TestRevocationHoldsUnderRandomDeliveryOrder(t *testing.T) {
	const (
		revisions   = 12
		revokeAt    = int64(6)
		target      = "cred-target"
		otherPrefix = "cred-other-"
	)
	seeds := []int64{1, 7, 42, 1234, 98765, 31337, 2026, 9}
	for _, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			base := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
			now := base
			clock := func() time.Time { return now }

			// Build the Controller's authoritative history: revision r is
			// issued at base+r seconds, renewals share the digest and
			// advance the sequence.
			var history []*Lease
			for r := int64(1); r <= revisions; r++ {
				grants := map[string]string{}
				for i := 0; i < 3; i++ {
					grants[fmt.Sprintf("%s%d", otherPrefix, i)] = base.Add(time.Duration(r)*time.Second + 4*time.Minute).Format(time.RFC3339Nano)
				}
				var denied []string
				if r < revokeAt {
					grants[target] = base.Add(time.Duration(r)*time.Second + 4*time.Minute).Format(time.RFC3339Nano)
				} else if r == revokeAt {
					denied = []string{target}
				}
				for seq := int64(1); seq <= 1+int64(rng.Intn(3)); seq++ {
					history = append(history, &Lease{
						Revision: r,
						Sequence: seq,
						Digest:   fmt.Sprintf("digest-%d", r),
						IssuedAt: base.Add(time.Duration(r)*time.Second + time.Duration(seq-1)*100*time.Millisecond).Format(time.RFC3339Nano),
						Grants:   grants,
						Denied:   denied,
					})
				}
			}

			// Shuffle, drop, and duplicate the history into a delivery
			// sequence, then sprinkle restarts and an occasional emergency
			// deny through it.
			var ops []deliveryOp
			for _, lease := range history {
				copies := rng.Intn(3) // 0 = lost, 1 = once, 2 = replayed
				for c := 0; c < copies; c++ {
					ops = append(ops, deliveryOp{kind: "lease", lease: lease})
				}
			}
			// Guarantee the revocation is observable at least once so the
			// property is not vacuous: either the revoking snapshot or a
			// later one, plus an emergency deny at the same revision.
			ops = append(ops, deliveryOp{kind: "lease", lease: history[len(history)-1]})
			ops = append(ops, deliveryOp{kind: "deny", deny: []string{target}, denyR: revokeAt})
			rng.Shuffle(len(ops), func(i, j int) { ops[i], ops[j] = ops[j], ops[i] })
			for i := 0; i < 4; i++ {
				at := rng.Intn(len(ops) + 1)
				ops = append(ops[:at], append([]deliveryOp{{kind: "restart"}}, ops[at:]...)...)
			}

			path := filepath.Join(t.TempDir(), "kernel-authorization.json")
			store := NewStore(path)
			store.SetClock(clock)
			revoked := false
			for step, op := range ops {
				now = now.Add(200 * time.Millisecond)
				switch op.kind {
				case "restart":
					store = NewStore(path)
					store.SetClock(clock)
				case "deny":
					if err := store.Deny(op.deny, op.denyR); err != nil {
						t.Fatalf("step %d deny: %v", step, err)
					}
					revoked = true
				case "lease":
					result, err := store.UpdateWithResult(op.lease)
					if err != nil {
						t.Fatalf("step %d update revision %d sequence %d: %v", step, op.lease.Revision, op.lease.Sequence, err)
					}
					if result.Installed && op.lease.Revision >= revokeAt {
						revoked = true
					}
				}
				status := store.Status()
				// The Controller clock runs ahead of this compressed history;
				// the kernel clock never lags behind the newest installed
				// issuance, otherwise the check below would only prove the
				// lease is not yet valid.
				if issued, err := time.Parse(time.RFC3339Nano, status.IssuedAt); err == nil && issued.After(now) {
					now = issued
				}
				if status.Revision >= revokeAt {
					revoked = true
				}
				if revoked && store.Allows(target, now) {
					t.Fatalf("step %d (%s): revoked key admitted again; installed revision %d sequence %d", step, op.kind, status.Revision, status.Sequence)
				}
				// The unrelated keys stay admitted whenever a live lease is
				// installed: revocation of one key never widens.
				if status.Revision > 0 && !store.Allows(otherPrefix+"0", now) {
					t.Fatalf("step %d (%s): unrelated key lost its grant at revision %d", step, op.kind, status.Revision)
				}
			}
			if !revoked {
				t.Fatal("generated history never applied the revocation")
			}
			// A final restart must reproduce the same verdicts from disk.
			store = NewStore(path)
			store.SetClock(clock)
			if store.Allows(target, now) {
				t.Fatal("revocation lost across the final restart")
			}
			if !store.Denied(target) {
				t.Fatal("deny watermark not persisted")
			}
		})
	}
}
