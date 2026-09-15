package stealth

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"controller_url":"https://example.com","agent_token":"secret"}`)
	envelope, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(envelope) {
		t.Fatal("envelope should carry the magic prefix")
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("envelope leaks plaintext")
	}
	if bytes.Contains(envelope, []byte("example.com")) {
		t.Fatal("envelope leaks plaintext content")
	}
	decrypted, err := Decrypt(key, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
}

func TestEncryptUsesFreshNonces(t *testing.T) {
	key, _ := GenerateKey()
	first, _ := Encrypt(key, []byte("same"))
	second, _ := Encrypt(key, []byte("same"))
	if bytes.Equal(first, second) {
		t.Fatal("identical plaintext must encrypt to different envelopes")
	}
}

func TestDecryptRejectsWrongKeyAndTampering(t *testing.T) {
	key, _ := GenerateKey()
	envelope, _ := Encrypt(key, []byte("payload"))
	wrong, _ := GenerateKey()
	if _, err := Decrypt(wrong, envelope); err != ErrCorruptEnvelope {
		t.Fatalf("wrong key: got %v", err)
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := Decrypt(key, tampered); err != ErrCorruptEnvelope {
		t.Fatalf("tampered envelope: got %v", err)
	}
	if _, err := Decrypt(key, []byte("plain json")); err != ErrNotEncrypted {
		t.Fatalf("plaintext input: got %v", err)
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyfile")
	key, _ := GenerateKey()
	if err := SaveKey(path, key); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o", info.Mode().Perm())
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != KeyLen {
		t.Fatalf("loaded key length = %d", len(loaded))
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("short key file must be rejected")
	}
}

func TestPhysicalNameContractVector(t *testing.T) {
	// Pinned vector shared with the kernel's internal/stealth copy; the two
	// implementations must derive identical names. Changing this requires
	// changing both sides in one release.
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	const want = "4ff2c95637ba990b"
	if got := PhysicalName(key, "sing-box.json"); got != want {
		t.Fatalf("PhysicalName = %s, want %s", got, want)
	}
}

func TestPhysicalNameDeterministicAndDistinct(t *testing.T) {
	key, _ := GenerateKey()
	first := PhysicalName(key, "sing-box.json")
	if first != PhysicalName(key, "sing-box.json") {
		t.Fatal("name derivation must be deterministic")
	}
	if first == PhysicalName(key, "authorization.json") {
		t.Fatal("different logical names must derive different physical names")
	}
	if first != PhysicalName(append([]byte(nil), key...), "sing-box.json") {
		// A copy of the same key bytes must derive the same names.
		t.Fatal("copied key must derive identical names")
	}
	other, _ := GenerateKey()
	if first == PhysicalName(other, "sing-box.json") {
		t.Fatal("different keys must derive different names")
	}
	if len(first) != 16 {
		t.Fatalf("name length = %d", len(first))
	}
}

func TestRandomNameShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		name, err := RandomName()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidName(name) {
			t.Fatalf("generated name %q fails validation", name)
		}
		seen[name] = true
	}
	if len(seen) < 190 {
		t.Fatalf("expected near-unique names, got %d distinct in 200", len(seen))
	}
}

func TestGenerateIdentityCollisions(t *testing.T) {
	dir := t.TempDir()
	check := CollisionCheck{
		InstallDir:   dir,
		ConfigParent: dir,
		StateParent:  dir,
		LogDir:       dir,
		RunDir:       dir,
		SystemdUnits: dir,
		InitDir:      dir,
	}
	identity, err := GenerateIdentity(check)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Validate(); err != nil {
		t.Fatal(err)
	}
	// Occupy every generated name, then verify generation picks different
	// free names instead of reusing any of them.
	occupied := map[string]bool{}
	for _, name := range []string{identity.AgentName, identity.InstallDirName, identity.CoreName, identity.RealmName, identity.ConfigDirName, identity.StateDirName, identity.AgentLogName, identity.CoreLogName, identity.SocketName, identity.SshdName, identity.SshName, identity.StagingPrefix, identity.ConfigFileName, identity.KeyFileName} {
		occupied[name] = true
		for _, suffix := range []string{"", ".log", ".sock", ".service"} {
			_ = os.WriteFile(filepath.Join(dir, name+suffix), []byte("x"), 0o600)
		}
	}
	second, err := GenerateIdentity(check)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{second.AgentName, second.InstallDirName, second.CoreName, second.RealmName, second.ConfigDirName, second.StateDirName, second.AgentLogName, second.CoreLogName, second.SocketName, second.SshdName, second.SshName, second.StagingPrefix, second.ConfigFileName, second.KeyFileName} {
		if occupied[name] {
			t.Fatalf("regenerated identity reused occupied name %q", name)
		}
	}
}

func TestGenerateIdentityExhaustsRetries(t *testing.T) {
	dir := t.TempDir()
	// Pin the random source to one name and mark it taken everywhere, so
	// every retry collides and generation must fail instead of reusing it.
	original := randomName
	defer func() { randomName = original }()
	randomName = func() (string, error) { return "aaaaaaaaaa", nil }
	check := CollisionCheck{InstallDir: dir}
	_ = os.MkdirAll(filepath.Join(dir, "aaaaaaaaaa"), 0o700)
	if _, err := GenerateIdentity(check); err == nil {
		t.Fatal("generation must fail when every candidate name is taken")
	}
}

func TestIdentityValidateRejectsBadNames(t *testing.T) {
	identity := Identity{
		AgentName: "oboard-agent", CoreName: "abcdefghij", RealmName: "abcdefghik",
		ConfigDirName: "abcdefghil", StateDirName: "abcdefghim", AgentLogName: "abcdefghin",
		CoreLogName: "abcdefghio", SocketName: "abcdefghip", SshdName: "abcdefghiq",
		SshName: "abcdefghir", StagingPrefix: "abcdefghis", ConfigFileName: "abcdefghit",
		KeyFileName: "abcdefghiu",
	}
	if err := identity.Validate(); err == nil {
		t.Fatal("oboard marker in identity must be rejected")
	}
	identity.AgentName = "abcdefghiz"
	if err := identity.Validate(); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	identity.CoreName = identity.AgentName
	if err := identity.Validate(); err == nil {
		t.Fatal("duplicate names must be rejected")
	}
	identity.CoreName = "abcdefghij"
	// An empty install_dir_name is a legacy layout and stays valid.
	identity.InstallDirName = ""
	if err := identity.Validate(); err != nil {
		t.Fatalf("legacy identity without install_dir_name rejected: %v", err)
	}
	identity.InstallDirName = "OBOARD"
	if err := identity.Validate(); err == nil {
		t.Fatal("invalid install_dir_name must be rejected")
	}
	identity.InstallDirName = identity.AgentName
	if err := identity.Validate(); err == nil {
		t.Fatal("duplicate install_dir_name must be rejected")
	}
}

func TestResolveLayoutPaths(t *testing.T) {
	identity := Identity{
		AgentName: "aaaaaaaaaa", CoreName: "bbbbbbbbbb", RealmName: "cccccccccc",
		ConfigDirName: "dddddddddd", StateDirName: "eeeeeeeeee", AgentLogName: "ffffffffff",
		CoreLogName: "gggggggggg", SocketName: "hhhhhhhhhh", SshdName: "iiiiiiiiii",
		SshName: "jjjjjjjjjj", StagingPrefix: "kkkkkkkkkk", ConfigFileName: "llllllllll",
		KeyFileName: "mmmmmmmmmm",
	}
	layout := ResolveLayout(identity, "/usr/local/bin", "/etc", "/var/lib")
	if layout.AgentBinary != "/usr/local/bin/aaaaaaaaaa" || layout.AgentService != "aaaaaaaaaa" {
		t.Fatalf("agent layout = %+v", layout)
	}
	if layout.ConfigPath != "/etc/dddddddddd/llllllllll" {
		t.Fatalf("config path = %s", layout.ConfigPath)
	}
	if layout.KeyPath != "/etc/dddddddddd/mmmmmmmmmm" {
		t.Fatalf("key path = %s", layout.KeyPath)
	}
	if layout.CoreSocket != "/run/hhhhhhhhhh.sock" {
		t.Fatalf("socket = %s", layout.CoreSocket)
	}
	if layout.AgentLog != "/var/log/ffffffffff.log" || layout.CoreLog != "/var/log/gggggggggg.log" {
		t.Fatalf("logs = %s / %s", layout.AgentLog, layout.CoreLog)
	}
	if _, err := NormalizeInstallDir("relative"); err == nil {
		t.Fatal("relative install dir must be rejected")
	}
	if clean, err := NormalizeInstallDir("/usr/local/bin/"); err != nil || clean != "/usr/local/bin" {
		t.Fatalf("normalize install dir = %q err=%v", clean, err)
	}
}
