package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestRedactSensitiveValues(t *testing.T) {
	input := "user@example.com 0123456789abcdef0123456789abcdef01234567 123e4567-e89b-12d3-a456-426614174000 00008130-000C48223EF2001C id=00008130-000C48223EF2001C name:私人手机 token=secret Apple Development: Private Name"
	result := redact(input)
	for _, secret := range []string{"user@example.com", "0123456789abcdef", "123e4567", "00008130", "私人手机", "Private Name", "secret"} {
		if strings.Contains(result, secret) {
			t.Fatalf("secret %q remained in %q", secret, result)
		}
	}
}

func TestTeamIDFromCertificateSubjectOU(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Apple Development", OrganizationalUnit: []string{"TEAM123456"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	team, err := teamIDFromCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	if team != "TEAM123456" {
		t.Fatalf("team = %q", team)
	}
}

func TestReplacementBundleIDIsDeterministic(t *testing.T) {
	first := replacementBundleID("ABCDEF123456")
	second := replacementBundleID("abcdef12ffff")
	if first != "com.shus.iparenew.abcdef12" || first != second {
		t.Fatalf("unexpected IDs: %q %q", first, second)
	}
}

func TestUnsignedOriginalAppHasNoEntitlementsToPreserve(t *testing.T) {
	service := &Service{runner: fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{Stderr: []byte("/tmp/iosApp.app: code object is not signed at all\n")}, fmt.Errorf("exit 1")
	}}}
	entitlements, err := service.readOriginalEntitlements(context.Background(), "/tmp/iosApp.app")
	if err != nil {
		t.Fatal(err)
	}
	if len(entitlements) != 0 {
		t.Fatalf("unsigned original should not invent entitlements: %#v", entitlements)
	}
}

func TestOriginalEntitlementsAreParsedWithoutTrailingDiagnostics(t *testing.T) {
	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>diagnostic`)
	service := &Service{runner: fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{Stdout: xml}, nil
	}}}
	entitlements, err := service.readOriginalEntitlements(context.Background(), "/tmp/Test.app")
	if err != nil {
		t.Fatal(err)
	}
	if allowed, ok := entitlements["get-task-allow"].(bool); !ok || !allowed {
		t.Fatalf("unexpected entitlements: %#v", entitlements)
	}
}
