package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStateStoreMigratesAndWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := map[string]any{"schemaVersion": 0, "apps": map[string]any{
		"one": map[string]any{"id": "one", "originalBundleID": "com.example.app"},
	}}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if state.SchemaVersion != currentSchema {
		t.Fatalf("schema = %d", state.SchemaVersion)
	}
	if state.Apps["one"].EffectiveBundleID != "com.example.app" {
		t.Fatal("bundle ID migration failed")
	}
	if state.Apps["one"].Installs == nil {
		t.Fatal("installs migration failed")
	}
	if err := store.Update(func(next *State) error { next.SelectedDeviceID = "device"; return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestStateStoreRejectsFutureSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":99,"apps":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateStore(path); err == nil {
		t.Fatal("expected future schema error")
	}
}
