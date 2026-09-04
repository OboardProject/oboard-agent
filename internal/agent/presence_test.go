package agent

import (
	"errors"
	"testing"
	"time"
)

func testPresenceEvents(count int, at time.Time) []connectionPresenceEvent {
	events := make([]connectionPresenceEvent, count)
	for index := range events {
		events[index] = connectionPresenceEvent{Sequence: uint64(index + 1), At: at.Format(time.RFC3339Nano)}
	}
	return events
}

func TestConnectionPresenceDeltaIsChunkedToContractBatchSize(t *testing.T) {
	runner := New(Config{})
	events := testPresenceEvents(connectionPresenceDeltaBatchSize*2+7, time.Now().UTC())
	var batches []connectionPresenceDelta
	write := func(payload any, wait bool) error {
		if !wait {
			t.Fatal("presence delta must observe the write result so undelivered events can be requeued")
		}
		message, ok := payload.(map[string]any)
		if !ok || message["type"] != "presence_delta" {
			t.Fatalf("unexpected presence payload %#v", payload)
		}
		batches = append(batches, message["presence_delta"].(connectionPresenceDelta))
		return nil
	}

	if err := runner.sendConnectionPresenceDelta(connectionPresenceDelta{Events: events, DroppedCount: 3}, write); err != nil {
		t.Fatal(err)
	}

	if len(batches) != 3 {
		t.Fatalf("presence batches = %d, want 3", len(batches))
	}
	sizes := []int{connectionPresenceDeltaBatchSize, connectionPresenceDeltaBatchSize, 7}
	dropped := []int64{3, 0, 0}
	next := uint64(1)
	for index, batch := range batches {
		if len(batch.Events) != sizes[index] {
			t.Fatalf("batch %d size = %d, want %d", index, len(batch.Events), sizes[index])
		}
		// The dropped counter describes the poll, so it is reported once.
		if batch.DroppedCount != dropped[index] {
			t.Fatalf("batch %d dropped_count = %d, want %d", index, batch.DroppedCount, dropped[index])
		}
		for _, event := range batch.Events {
			if event.Sequence != next {
				t.Fatalf("batch %d broke sequence order: got %d, want %d", index, event.Sequence, next)
			}
			next++
		}
	}
}

func TestConnectionPresenceDeltaRequeuesUndeliveredEvents(t *testing.T) {
	runner := New(Config{})
	events := testPresenceEvents(connectionPresenceDeltaBatchSize+4, time.Now().UTC())
	writes := 0
	write := func(any, bool) error {
		writes++
		if writes == 2 {
			return errors.New("websocket: close 1006 (abnormal closure)")
		}
		return nil
	}

	if err := runner.sendConnectionPresenceDelta(connectionPresenceDelta{Events: events, DroppedCount: 2}, write); err == nil {
		t.Fatal("a failed presence write was reported as delivered")
	}

	pending, dropped := runner.takePendingPresenceEvents()
	if len(pending) != 4 {
		t.Fatalf("requeued events = %d, want 4", len(pending))
	}
	if pending[0].Sequence != uint64(connectionPresenceDeltaBatchSize+1) {
		t.Fatalf("requeued first sequence = %d, want %d", pending[0].Sequence, connectionPresenceDeltaBatchSize+1)
	}
	// The first chunk carried the dropped counter and was accepted.
	if dropped != 0 {
		t.Fatalf("requeued dropped_count = %d, want 0", dropped)
	}
	if remaining, _ := runner.takePendingPresenceEvents(); len(remaining) != 0 {
		t.Fatalf("pending buffer was not consumed: %d events remain", len(remaining))
	}
}

func TestRequeuedPresenceEventsKeepNewestOnOverflow(t *testing.T) {
	runner := New(Config{})
	// A single failed send can carry more events than the buffer bound.
	runner.requeuePresenceEvents(testPresenceEvents(maxPendingPresenceEvents+10, time.Now().UTC()), 1)

	pending, dropped := runner.takePendingPresenceEvents()
	if len(pending) != maxPendingPresenceEvents {
		t.Fatalf("pending events = %d, want %d", len(pending), maxPendingPresenceEvents)
	}
	// Presence is state-like, so the oldest events are the ones to lose.
	if pending[0].Sequence != 11 {
		t.Fatalf("head sequence = %d, want 11", pending[0].Sequence)
	}
	if last := pending[len(pending)-1].Sequence; last != uint64(maxPendingPresenceEvents+10) {
		t.Fatalf("tail sequence = %d, want %d", last, maxPendingPresenceEvents+10)
	}
	// Ten overflow events plus the counter carried into the requeue.
	if dropped != 11 {
		t.Fatalf("dropped_count = %d, want 11", dropped)
	}
}

func TestExpiredPresenceEventsAreDroppedBeforeSend(t *testing.T) {
	now := time.Now().UTC()
	events := []connectionPresenceEvent{
		{Sequence: 1, At: now.Add(-connectionPresenceEventMaxAge - time.Minute).Format(time.RFC3339Nano)},
		{Sequence: 2, At: now.Add(-time.Second).Format(time.RFC3339Nano)},
		{Sequence: 3, At: "not-a-timestamp"},
	}

	kept, expired := dropExpiredPresenceEvents(events, now)

	// Controller fails the whole delta on one out-of-window event, so stale and
	// unparsable entries must never reach a batch.
	if len(kept) != 1 || kept[0].Sequence != 2 {
		t.Fatalf("kept events = %#v", kept)
	}
	if expired != 2 {
		t.Fatalf("expired = %d, want 2", expired)
	}
}

func TestDisabledConnectionAuditDiscardsPendingPresence(t *testing.T) {
	runner := New(Config{ConnectionAuditEnabled: false})
	runner.requeuePresenceEvents(testPresenceEvents(3, time.Now().UTC()), 5)

	delta, err := runner.collectConnectionPresenceDelta(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Events) != 0 || delta.DroppedCount != 0 {
		t.Fatalf("disabled audit returned presence data: %#v", delta)
	}
	if pending, dropped := runner.takePendingPresenceEvents(); len(pending) != 0 || dropped != 0 {
		t.Fatalf("disabled audit kept presence state: %d events, dropped=%d", len(pending), dropped)
	}
}
