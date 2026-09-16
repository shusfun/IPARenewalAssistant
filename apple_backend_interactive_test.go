package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppleLoginChallengeResendAndCancel(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "fake-signer")
	script := "#!/bin/sh\nread password\necho EVENT:challenge >&2\nwhile read value; do\n  if [ \"$value\" = resend ]; then echo EVENT:resend-result:ok >&2; else exit 1; fi\ndone\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	service, err := NewService(Paths{StateFile: filepath.Join(root, "state.json"), AuditFile: filepath.Join(root, "audit.jsonl"), Library: filepath.Join(root, "library"), Cache: filepath.Join(root, "cache")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.StartAppleLogin("user@example.com", "not-persisted")
	if err != nil {
		t.Fatal(err)
	}
	if !challenge.NeedsTwoFactor || challenge.AuthID == "" {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
	if err := service.ResendTwoFactor(challenge.AuthID); err != nil {
		t.Fatal(err)
	}
	if err := service.CancelAppleLogin(challenge.AuthID); err != nil {
		t.Fatal(err)
	}
	if len(service.apple.pending) != 0 {
		t.Fatal("login process was not cleaned up")
	}
}
