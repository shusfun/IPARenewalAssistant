package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"howett.net/plist"
)

func provisionPlist(team, bundle, device string) []byte {
	now := time.Now()
	data, err := plist.Marshal(map[string]any{
		"UUID":               "profile",
		"TeamIdentifier":     []string{team},
		"CreationDate":       now.Add(-time.Minute),
		"ExpirationDate":     now.Add(7 * 24 * time.Hour),
		"ProvisionedDevices": []string{device},
		"Entitlements": map[string]any{
			"application-identifier":              team + "." + bundle,
			"com.apple.developer.team-identifier": team,
			"get-task-allow":                      true,
		},
	}, plist.XMLFormat)
	if err != nil {
		panic(err)
	}
	return data
}

func readyTestDevice(id, udid string) Device {
	return Device{
		ID: id, Connection: "USB", Transport: "USB", DeveloperMode: "已开启", Pairing: "已配对",
		Available: true, internalUDID: udid,
	}
}

func TestFailedLoginRemembersCredentials(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "fake-signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nread password\necho HTTP 503 from Apple >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	var storedAccount, storedSecret string
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if spec.Name == "/usr/bin/security" && len(spec.Args) > 0 && spec.Args[0] == "add-generic-password" {
			for i, arg := range spec.Args {
				if arg == "-a" && i+1 < len(spec.Args) {
					storedAccount = spec.Args[i+1]
				}
				if arg == "-w" && i+1 < len(spec.Args) {
					storedSecret = spec.Args[i+1]
				}
			}
			return CommandResult{}, nil
		}
		if spec.Name == "/usr/bin/security" && len(spec.Args) > 0 && spec.Args[0] == "find-generic-password" {
			if storedSecret == "" {
				return CommandResult{}, fmt.Errorf("not found")
			}
			return CommandResult{Stdout: []byte(storedSecret)}, nil
		}
		return CommandResult{}, nil
	}}
	service, err := NewService(Paths{StateFile: filepath.Join(root, "state.json"), AuditFile: filepath.Join(root, "audit.jsonl"), Library: filepath.Join(root, "library"), Cache: filepath.Join(root, "cache")}, runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, loginErr := service.StartAppleLogin("user@example.com", "secret-pass")
	if loginErr == nil {
		t.Fatal("expected login failure")
	}
	if storedAccount != "user@example.com" || storedSecret != "secret-pass" {
		t.Fatalf("keychain write missing: account=%q", storedAccount)
	}
	creds := service.RememberedAppleCredentials()
	if creds.AppleID != "user@example.com" || creds.Password != "secret-pass" {
		t.Fatalf("credentials not remembered: %#v", creds)
	}
	if service.store.Snapshot().LastAppleID != "user@example.com" {
		t.Fatal("last Apple ID was not persisted")
	}
}

func TestAppleLoginMapsGatewayUnavailable(t *testing.T) {
	err := appleLoginError(loginResult{
		stderr: []byte("altsign-cli [SRP] Error response (first 512 chars): <html><title>503 Service Temporarily Unavailable</title>\n[Error] Authentication failed: HTTP 503 from Apple"),
		err:    fmt.Errorf("exit 1"),
	})
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "apple_auth_rejected" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if strings.Contains(userErr.Message, "<html>") || strings.Contains(userErr.Message, "altsign-cli") {
		t.Fatalf("raw helper output leaked: %q", userErr.Message)
	}
}

func TestAppleLoginReportsGSAStageFromEvents(t *testing.T) {
	err := appleLoginError(loginResult{
		stderr: []byte("EVENT:gsa stage=probe-get method=GET status=401 duration_ms=90 content=html proxy=system_default\nEVENT:gsa stage=probe-post method=POST status=401 duration_ms=80 content=html proxy=system_default\nEVENT:gsa stage=init method=POST status=503 duration_ms=812 content=html proxy=system_default\n"),
		err:    fmt.Errorf("exit 1"),
	})
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "apple_auth_init_rejected" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(userErr.Message, "init") || !strings.Contains(userErr.Message, "503") || !strings.Contains(userErr.Message, "probe-get") {
		t.Fatalf("missing diagnostic facts: %q", userErr.Message)
	}
	if strings.Contains(userErr.Message, "<html>") {
		t.Fatalf("html leaked: %q", userErr.Message)
	}
}

func TestAppleLoginMapsTwoFactorNotSent(t *testing.T) {
	err := appleLoginError(loginResult{
		stderr: []byte("EVENT:gsa stage=complete method=POST status=200 duration_ms=800 content=plist proxy=system_default\nEVENT:gsa stage=2fa-force au=none\nEVENT:gsa stage=2fa-request status=403 content=empty\nEVENT:gsa stage=2fa-request status=failed fallback=no\n"),
		err:    fmt.Errorf("exit 1"),
	})
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "apple_2fa_not_sent" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if strings.Contains(userErr.Message, "<html>") {
		t.Fatalf("html leaked: %q", userErr.Message)
	}
}

func TestParseSignerJSONReadsTeams(t *testing.T) {
	parsed, err := parseSignerJSON([]byte("log line\n{\"ok\":true,\"teams\":[{\"id\":\"TEAM1\",\"name\":\"One\"},{\"id\":\"TEAM2\",\"name\":\"Two\"}]}\n"))
	if err != nil || !parsed.OK || len(parsed.Teams) != 2 || parsed.Teams[1].ID != "TEAM2" {
		t.Fatalf("parsed = %#v err=%v", parsed, err)
	}
}

func TestSelectDeveloperTeamRejectsUnknownTeam(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{}, nil
	}}, nil)
	if err := service.store.Update(func(state *State) error {
		state.AppleAccount = &AppleAccountState{AccountRef: "apple-abc", Teams: []DeveloperTeam{{ID: "TEAM1", Name: "One"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.SelectDeveloperTeam("OTHER"); err == nil || !strings.Contains(err.Error(), "不在当前账号") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionMismatchIsNotSignedIn(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if len(spec.Args) > 0 && spec.Args[0] == "session" {
			return CommandResult{Stdout: []byte(`{"ok":true,"valid":true,"expired":false,"appleID":"other@example.com"}`)}, nil
		}
		if spec.Name == "/usr/bin/security" {
			return CommandResult{}, nil
		}
		return CommandResult{}, nil
	}}
	service := newWorkflowService(t, runner, nil)
	if err := service.store.Update(func(state *State) error {
		state.AppleAccount = &AppleAccountState{AccountRef: accountRefForEmail("user@example.com"), TeamID: "TEAM1", Teams: []DeveloperTeam{{ID: "TEAM1"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if service.GetAppleAccountStatus().SignedIn {
		t.Fatal("mismatched session should not be signed in")
	}
}

func TestExpiredSessionIsNotSignedIn(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if len(spec.Args) > 0 && spec.Args[0] == "session" {
			return CommandResult{Stdout: []byte(`{"ok":true,"valid":false,"expired":true,"appleID":"user@example.com"}`)}, nil
		}
		if spec.Name == "/usr/bin/security" {
			return CommandResult{}, nil
		}
		return CommandResult{}, nil
	}}
	service := newWorkflowService(t, runner, nil)
	if err := service.store.Update(func(state *State) error {
		state.AppleAccount = &AppleAccountState{AccountRef: accountRefForEmail("user@example.com"), TeamID: "TEAM1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if service.GetAppleAccountStatus().SignedIn {
		t.Fatal("expired session should not be signed in")
	}
}

func TestSignerParsesIdentityFingerprintsCaseInsensitive(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("native", "altsign-cli", "signer.mm"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "create-keychain") {
		t.Fatal("signer still uses a file-based keychain that codesign cannot consume")
	}
	if !strings.Contains(text, "login.keychain") {
		t.Fatal("signer no longer imports the ephemeral identity into the login keychain")
	}
	if !strings.Contains(text, "delete-identity") {
		t.Fatal("signer no longer removes the ephemeral identity after signing")
	}
	if strings.Contains(text, `"-A"`) {
		t.Fatal("signer still allows every application to use the signing identity")
	}
	if !strings.Contains(text, "AppleWWDRCAG3.cer") {
		t.Fatal("signer no longer installs Apple WWDR intermediates before codesign")
	}
	if !strings.Contains(text, `EVENT:sign`) && !strings.Contains(text, `emitSignEvent`) {
		t.Fatal("signer no longer emits structured sign events")
	}
}

func TestP12GenerationChecksKeyMatchesCertificate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("native", "altsign-cli", "apple_api.mm"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "X509_check_private_key") {
		t.Fatal("P12 generation no longer checks that the private key matches the certificate")
	}
}

func TestCertificateSerialMatchingStripsSingleLeadingZero(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("native", "altsign-cli", "apple_api.mm"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, `hasPrefix:@"00"`) {
		t.Fatal("serial matching still only strips paired zeros")
	}
	if !strings.Contains(text, `hasPrefix:@"0"`) {
		t.Fatal("serial matching should strip a single leading zero")
	}
	if !strings.Contains(text, "using the only team certificate after approval") {
		t.Fatal("CSR approval no longer falls back to the only team certificate")
	}
}

func TestNativeSignerDoesNotAutoRevoke(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("native", "altsign-cli", "main.mm"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `emitCertificateEvent(@"skip-create", @"missing-local-key")`) {
		t.Fatal("signing flow no longer skips certificate creation when portal certs already exist")
	}
	if !strings.Contains(text, "reissueCertificate") || !strings.Contains(text, "revokeCertificate") {
		t.Fatal("explicit reissue path should revoke only after user confirmation")
	}
	skipIdx := strings.Index(text, `emitCertificateEvent(@"skip-create", @"missing-local-key")`)
	reissueIdx := strings.Index(text, "reissueCertificate")
	if skipIdx < 0 || reissueIdx < 0 || !strings.Contains(text[reissueIdx:], "revokeCertificate") {
		t.Fatal("revoke is not gated behind the reissue flag")
	}
}

func TestNativeSignerDoesNotAllowAllKeychainApps(t *testing.T) {
	paths := []string{
		filepath.Join("native", "altsign-cli", "srp_auth.mm"),
		filepath.Join("native", "altsign-cli", "keychain.mm"),
		filepath.Join("native", "altsign-cli", "main.mm"),
		"apple_backend.go",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "CreateAnyApplicationAccess") || strings.Contains(text, "SecACLSetContents(acl, NULL") {
			t.Fatalf("%s still widens keychain ACL to every application", path)
		}
	}
	data, err := os.ReadFile("apple_backend.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `add-generic-password", "-U", "-A"`) || strings.Contains(string(data), `"-A", "-a"`) {
		t.Fatal("saveKeychainAccount still allows every application")
	}
}

func TestCertificateRequestDoesNotLogPrivateKeyObject(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("native", "altsign-cli", "certificate_request.mm"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "outputPrivateKey=%@") || strings.Contains(string(data), "outputRequest=%@") {
		t.Fatal("CSR generator still logs key material objects")
	}
}

func TestAppleSignErrorMapsKeychainDenied(t *testing.T) {
	err := appleSignError(CommandResult{
		Stderr: []byte("EVENT:keychain item=certificate-key status=denied\n"),
	}, fmt.Errorf("exit 1"))
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "signing_key_access_denied" {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestCheckEnvironmentDoesNotProbeNativeSession(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	calledSession := false
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if len(spec.Args) > 0 && spec.Args[0] == "session" {
			calledSession = true
		}
		return CommandResult{}, nil
	}}
	service := newWorkflowService(t, runner, nil)
	_ = service.checkEnvironment(context.Background())
	if calledSession {
		t.Fatal("environment check should not launch altsign-cli session")
	}
}

func TestAppleSignErrorMapsCodesignKeychainFailure(t *testing.T) {
	err := appleSignError(CommandResult{
		Stderr: []byte("EVENT:sign step=codesign status=failed reason=keychain\n"),
	}, fmt.Errorf("exit 1"))
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "codesign_failed" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(userErr.Message, "临时钥匙串") {
		t.Fatalf("unexpected message: %q", userErr.Message)
	}
}

func TestAppleSignErrorMapsSignerIdentityMissing(t *testing.T) {
	err := appleSignError(CommandResult{
		Stderr: []byte("EVENT:sign step=identity status=missing reason=find-identity\n"),
	}, fmt.Errorf("exit 1"))
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "signing_identity_unusable" {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestAppleSignErrorHidesKeychainDump(t *testing.T) {
	err := appleSignError(CommandResult{
		Stderr: []byte("    0x00000013 <uint32>=0x00000001\n    0x00000014 <uint32>=0x00000001\n"),
	}, fmt.Errorf("exit 1"))
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "sign_failed" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if strings.Contains(userErr.Message, "0x00000013") {
		t.Fatalf("keychain dump leaked: %q", userErr.Message)
	}
}

func TestAppleSignErrorMapsMissingLocalIdentity(t *testing.T) {
	err := appleSignError(CommandResult{
		Stderr: []byte("EVENT:keychain item=certificate-key status=missing\nEVENT:certificate action=skip-create reason=missing-local-key\n"),
	}, fmt.Errorf("exit 1"))
	userErr, ok := err.(*UserError)
	if !ok || userErr.Code != "signing_identity_missing" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if strings.Contains(userErr.Message, "altsign-cli") {
		t.Fatalf("helper name leaked: %q", userErr.Message)
	}
}

func TestValidateProfileUsesSelectedTeam(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.Local)
	profile := mobileProvision{
		UUID: "profile", TeamIdentifier: []string{"TEAM1"},
		CreationDate: now.Add(-time.Minute), ExpirationDate: now.Add(7 * 24 * time.Hour),
		ProvisionedDevices: []string{"device"}, Entitlements: map[string]any{"application-identifier": "TEAM1.com.example.app"},
	}
	if _, err := validateProfile(profile, "TEAM2", "com.example.app", "device", now); err == nil {
		t.Fatal("expected selected team mismatch")
	}
}

func TestVerifySignedAppRejectsIPAPath(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		t.Fatal("codesign should not run against an IPA")
		return CommandResult{}, nil
	}}, nil)
	if err := service.verifySignedApp(context.Background(), "/tmp/app.ipa"); err == nil {
		t.Fatal("expected IPA verify rejection")
	}
}

func TestSignAppPassesTeamIDAndDoesNotPublishOnVerifyFailure(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	original := writeTestIPA(t, validIPAEntries(t))
	var signArgs []string
	var verifyTargets []string
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		switch {
		case len(spec.Args) > 0 && spec.Args[0] == "session":
			return CommandResult{Stdout: []byte(`{"ok":true,"valid":true,"expired":false,"appleID":"user@example.com"}`)}, nil
		case spec.Name == helper || filepath.Base(spec.Name) == "signer":
			signArgs = append([]string{}, spec.Args...)
			output := ""
			for i, arg := range spec.Args {
				if arg == "--output" && i+1 < len(spec.Args) {
					output = spec.Args[i+1]
				}
			}
			entries := validIPAEntries(t)
			entries["Payload/Test.app/embedded.mobileprovision"] = []byte("provision")
			if err := os.WriteFile(output, mustRead(t, writeTestIPA(t, entries)), 0o600); err != nil {
				t.Fatal(err)
			}
			return CommandResult{}, nil
		case spec.Name == "/usr/bin/codesign" && len(spec.Args) > 0 && spec.Args[0] == "--verify":
			verifyTargets = append(verifyTargets, spec.Args[len(spec.Args)-1])
			return CommandResult{}, nil
		case spec.Name == "/usr/bin/codesign":
			return CommandResult{Stdout: []byte(`<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>`)}, nil
		case (spec.Name == "/usr/bin/security" || spec.Name == "security") && len(spec.Args) > 0 && spec.Args[0] == "cms":
			return CommandResult{Stdout: provisionPlist("TEAM1", "com.example.test", "UDID-1")}, nil
		case spec.Name == "/usr/bin/security" || spec.Name == "security":
			return CommandResult{}, nil
		default:
			return CommandResult{}, nil
		}
	}}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.findDeviceOverride = func(context.Context, string) (Device, error) {
		return readyTestDevice("device-id", "UDID-1"), nil
	}
	if err := service.store.Update(func(state *State) error {
		state.SelectedDeviceID = "device-id"
		state.AppleAccount = &AppleAccountState{AccountRef: accountRefForEmail("user@example.com"), TeamID: "TEAM1", TeamName: "One", Teams: []DeveloperTeam{{ID: "TEAM1", Name: "One"}}}
		state.Apps["app"] = &ManagedApp{ID: "app", OriginalPath: original, OriginalBundleID: "com.example.test", EffectiveBundleID: "com.example.test", Version: "1.0", Installs: map[string]InstallRecord{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignApp("app", "device-id", "preserve"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if !result.Success {
		t.Fatalf("sign failed: %#v", result)
	}
	if !containsAll(signArgs, "--team-id", "TEAM1") {
		t.Fatalf("team id not passed: %v", signArgs)
	}
	for _, arg := range signArgs {
		if arg == "--reissue-certificate" {
			t.Fatal("default sign must not reissue certificates")
		}
	}
	for _, target := range verifyTargets {
		if strings.HasSuffix(strings.ToLower(target), ".ipa") {
			t.Fatalf("verified IPA path %s", target)
		}
	}
	if service.store.Snapshot().Apps["app"].LatestSigned == nil {
		t.Fatal("signed artifact missing")
	}
}

func TestSignAppReissuePassesHelperFlag(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	original := writeTestIPA(t, validIPAEntries(t))
	var signArgs []string
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		switch {
		case len(spec.Args) > 0 && spec.Args[0] == "session":
			return CommandResult{Stdout: []byte(`{"ok":true,"valid":true,"expired":false,"appleID":"user@example.com"}`)}, nil
		case spec.Name == helper || filepath.Base(spec.Name) == "signer":
			signArgs = append([]string{}, spec.Args...)
			output := ""
			for i, arg := range spec.Args {
				if arg == "--output" && i+1 < len(spec.Args) {
					output = spec.Args[i+1]
				}
			}
			entries := validIPAEntries(t)
			entries["Payload/Test.app/embedded.mobileprovision"] = []byte("provision")
			if err := os.WriteFile(output, mustRead(t, writeTestIPA(t, entries)), 0o600); err != nil {
				t.Fatal(err)
			}
			return CommandResult{}, nil
		case spec.Name == "/usr/bin/codesign" && len(spec.Args) > 0 && spec.Args[0] == "--verify":
			return CommandResult{}, nil
		case spec.Name == "/usr/bin/codesign":
			return CommandResult{Stdout: []byte(`<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>`)}, nil
		case (spec.Name == "/usr/bin/security" || spec.Name == "security") && len(spec.Args) > 0 && spec.Args[0] == "cms":
			return CommandResult{Stdout: provisionPlist("TEAM1", "com.example.test", "UDID-1")}, nil
		case spec.Name == "/usr/bin/security" || spec.Name == "security":
			return CommandResult{}, nil
		default:
			return CommandResult{}, nil
		}
	}}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.findDeviceOverride = func(context.Context, string) (Device, error) {
		return readyTestDevice("device-id", "UDID-1"), nil
	}
	if err := service.store.Update(func(state *State) error {
		state.SelectedDeviceID = "device-id"
		state.AppleAccount = &AppleAccountState{AccountRef: accountRefForEmail("user@example.com"), TeamID: "TEAM1", TeamName: "One", Teams: []DeveloperTeam{{ID: "TEAM1", Name: "One"}}}
		state.Apps["app"] = &ManagedApp{ID: "app", OriginalPath: original, OriginalBundleID: "com.example.test", EffectiveBundleID: "com.example.test", Version: "1.0", Installs: map[string]InstallRecord{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignApp("app", "device-id", "preserve", "reissue"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if !result.Success {
		t.Fatalf("sign failed: %#v", result)
	}
	if !containsAll(signArgs, "--reissue-certificate") {
		t.Fatalf("reissue flag not passed: %v", signArgs)
	}
}

func TestSignFailureDoesNotPublishArtifact(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "signer")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPARENEWAL_SIGNER", helper)
	original := writeTestIPA(t, validIPAEntries(t))
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if len(spec.Args) > 0 && spec.Args[0] == "session" {
			return CommandResult{Stdout: []byte(`{"ok":true,"valid":true,"expired":false,"appleID":"user@example.com"}`)}, nil
		}
		if spec.Name == helper || filepath.Base(spec.Name) == "signer" {
			return CommandResult{Stderr: []byte("sign exploded")}, os.ErrPermission
		}
		if spec.Name == "/usr/bin/security" {
			return CommandResult{}, nil
		}
		return CommandResult{}, nil
	}}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.findDeviceOverride = func(context.Context, string) (Device, error) {
		return readyTestDevice("device-id", "UDID-1"), nil
	}
	previous := &SignedArtifact{Path: "previous.ipa", SignedAt: time.Now()}
	if err := service.store.Update(func(state *State) error {
		state.AppleAccount = &AppleAccountState{AccountRef: accountRefForEmail("user@example.com"), TeamID: "TEAM1", Teams: []DeveloperTeam{{ID: "TEAM1"}}}
		state.Apps["app"] = &ManagedApp{ID: "app", OriginalPath: original, OriginalBundleID: "com.example.test", EffectiveBundleID: "com.example.test", LatestSigned: previous, Installs: map[string]InstallRecord{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignApp("app", "device-id", "preserve"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if result.Success {
		t.Fatal("expected failure")
	}
	if service.store.Snapshot().Apps["app"].LatestSigned.Path != "previous.ipa" {
		t.Fatal("previous artifact was replaced")
	}
}

func TestRemoveSupersededSignedIPAsKeepsCurrentAndOtherApps(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{}, nil)
	dir := filepath.Join(service.paths.Library, "signed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "app-9.ipa")
	old := filepath.Join(dir, "app-1.ipa")
	other := filepath.Join(dir, "other-1.ipa")
	for _, path := range []string{keep, old, other} {
		if err := os.WriteFile(path, []byte("ipa"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	service.removeSupersededSignedIPAs("app", keep)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old signed ipa was not removed")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("current signed ipa was removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("other app signed ipa was removed")
	}
}

func writeProvisionedTestIPA(t *testing.T) string {
	t.Helper()
	entries := validIPAEntries(t)
	entries["Payload/Test.app/embedded.mobileprovision"] = []byte("provision")
	return writeTestIPA(t, entries)
}

func TestInstallIdentityConflictPreservesRecord(t *testing.T) {
	signed := writeProvisionedTestIPA(t)
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if (spec.Name == "/usr/bin/security" || spec.Name == "security") && len(spec.Args) > 0 && spec.Args[0] == "cms" {
			return CommandResult{Stdout: provisionPlist("TEAM1", "com.example.app", "UDID-1")}, nil
		}
		return CommandResult{}, nil
	}}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.findDeviceOverride = func(context.Context, string) (Device, error) {
		return readyTestDevice("device-id", "UDID-1"), nil
	}
	service.lookupInstalledOverride = func(context.Context, string, string) (bool, string, string, error) {
		return true, "1.0", "OTHER", nil
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := service.store.Update(func(state *State) error {
		state.Apps["app"] = &ManagedApp{
			ID: "app", EffectiveBundleID: "com.example.app", Version: "1.0",
			LatestSigned: &SignedArtifact{Path: signed, Profile: ProfileMetadata{TeamID: "TEAM1", BundleID: "com.example.app", ExpirationTime: time.Now().Add(time.Hour)}},
			Installs:     map[string]InstallRecord{"device-id": {DeviceID: "device-id", InstalledAt: oldTime, Present: true, Profile: ProfileMetadata{TeamID: "TEAM1"}}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallApp("app", "device-id"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if result.Success || result.Code != "install_identity_conflict" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !service.store.Snapshot().Apps["app"].Installs["device-id"].InstalledAt.Equal(oldTime) {
		t.Fatal("old install record was replaced")
	}
}

func TestLaunchFailureDoesNotRecordInstall(t *testing.T) {
	signed := writeProvisionedTestIPA(t)
	runner := fakeRunner{run: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		if (spec.Name == "/usr/bin/security" || spec.Name == "security") && len(spec.Args) > 0 && spec.Args[0] == "cms" {
			return CommandResult{Stdout: provisionPlist("TEAM1", "com.example.app", "UDID-1")}, nil
		}
		return CommandResult{}, nil
	}}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.findDeviceOverride = func(context.Context, string) (Device, error) {
		return readyTestDevice("device-id", "UDID-1"), nil
	}
	service.lookupInstalledOverride = func(context.Context, string, string) (bool, string, string, error) {
		return false, "", "", nil
	}
	service.installOverride = func(ctx context.Context, tempDir, jobID, kind, appID string) error {
		if err := service.launchInstalledApp(ctx, "device-id", "com.example.app"); err != nil {
			return err
		}
		return nil
	}
	service.launchOverride = func(context.Context, string, string) error {
		return &UserError{Code: "launch_failed", Message: "应用已传输，但未能在设备上启动"}
	}
	if err := service.store.Update(func(state *State) error {
		state.Apps["app"] = &ManagedApp{
			ID: "app", EffectiveBundleID: "com.example.app", Version: "1.0",
			LatestSigned: &SignedArtifact{Path: signed, Profile: ProfileMetadata{TeamID: "TEAM1", ExpirationTime: time.Now().Add(time.Hour)}},
			Installs:     map[string]InstallRecord{},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallApp("app", "device-id"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if result.Success || result.Code != "launch_failed" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if _, ok := service.store.Snapshot().Apps["app"].Installs["device-id"]; ok {
		t.Fatal("install record was written after launch failure")
	}
}

func TestEnsureDeviceReadyRejectsUnknownDeveloperMode(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{}, nil
	}}, nil)
	device := readyTestDevice("device-id", "UDID-1")
	device.DeveloperMode = "未知"
	if err := service.ensureDeviceReady(device); err == nil || !strings.Contains(err.Error(), "无法确认开发者模式") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAppleLoginCancelKillsProcess(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "fake-signer")
	script := "#!/bin/sh\nread password\necho EVENT:challenge >&2\nwhile read value; do sleep 30; done\n"
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
	service.apple.mu.Lock()
	pending := service.apple.pending[challenge.AuthID]
	service.apple.mu.Unlock()
	pid := pending.cmd.Process.Pid
	if err := service.CancelAppleLogin(challenge.AuthID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("login helper still running after cancel")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func containsAll(args []string, want ...string) bool {
	joined := strings.Join(args, "\x00")
	return strings.Contains(joined, strings.Join(want, "\x00"))
}
