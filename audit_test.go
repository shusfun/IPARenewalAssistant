package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditEventsAreRedactedAndLimited(t *testing.T) {
	root := t.TempDir()
	service, err := NewService(Paths{StateFile: filepath.Join(root, "state.json"), AuditFile: filepath.Join(root, "audit.jsonl"), Library: filepath.Join(root, "library"), Cache: filepath.Join(root, "cache")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.audit(AuditEvent{Kind: "install", Stage: "finish", Status: "failed", Message: "password=secret verificationCode=123456 token=abc"})
	service.audit(AuditEvent{Kind: "install", Stage: "start", Status: "started", Message: "second"})
	events := service.ListAuditEvents(1)
	if len(events) != 1 || events[0].Message != "second" {
		t.Fatalf("unexpected events: %#v", events)
	}
	data, err := os.ReadFile(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("audit file is empty")
	}
	info, err := os.Stat(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode = %o", info.Mode().Perm())
	}
	if bytes.Contains(data, []byte("secret")) || bytes.Contains(data, []byte("123456")) {
		t.Fatal("sensitive data leaked")
	}
}
