package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testIdentity(t *testing.T) (string, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Apple Development: Test", OrganizationalUnit: []string{"TESTTEAM01"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(fingerprint[:])), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newWorkflowService(t *testing.T, runner CommandRunner, events EventSink) *Service {
	t.Helper()
	root := t.TempDir()
	service, err := NewService(Paths{StateFile: filepath.Join(root, "state.json"), Library: filepath.Join(root, "library"), Cache: filepath.Join(root, "cache")}, runner, events)
	if err != nil {
		t.Fatal(err)
	}
	service.storageCheck = func() error { return nil }
	if err := service.ensureExternalStorage(); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestSigningFailurePreservesPreviousArtifact(t *testing.T) {
	runner := fakeRunner{run: func(_ context.Context, _ CommandSpec) (CommandResult, error) { return CommandResult{}, nil }}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.signOverride = func(context.Context, string, string, string, string, string, string) error {
		return &UserError{Code: "profile_build_failed", Message: "Apple ID 签名失败"}
	}
	previous := &SignedArtifact{Path: "previous.ipa", SignedAt: time.Now()}
	if err := service.store.Update(func(state *State) error {
		state.SelectedDeviceID = "device-id"
		state.Apps["app"] = &ManagedApp{ID: "app", SHA256: strings.Repeat("a", 64), OriginalBundleID: "com.example.app", EffectiveBundleID: "com.example.app", LatestSigned: previous, Installs: map[string]InstallRecord{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignApp("app", "preserve"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if result.Success || result.Code != "profile_build_failed" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if service.store.Snapshot().Apps["app"].LatestSigned.Path != "previous.ipa" {
		t.Fatal("previous artifact was replaced")
	}
}

func TestInstallFailurePreservesPreviousRecord(t *testing.T) {
	runner := fakeRunner{run: func(_ context.Context, _ CommandSpec) (CommandResult, error) { return CommandResult{}, nil }}
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service := newWorkflowService(t, runner, events)
	service.findDeviceOverride = func(context.Context, string) (Device, error) {
		return Device{ID: "device-id", Connection: "USB", Available: true}, nil
	}
	service.installOverride = func(context.Context, string, string, string, string) error {
		return &UserError{Code: "install_failed", Message: "设备安装失败，原有安装记录未改变"}
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := service.store.Update(func(state *State) error {
		state.Apps["app"] = &ManagedApp{ID: "app", AppDirectory: "Payload/Test.app", EffectiveBundleID: "com.example.app", Version: "1.0", LatestSigned: &SignedArtifact{Path: "signed.ipa", Profile: ProfileMetadata{ExpirationTime: time.Now().Add(time.Hour)}}, Installs: map[string]InstallRecord{"device-id": {DeviceID: "device-id", InstalledAt: oldTime, Present: true}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallApp("app", "device-id"); err != nil {
		t.Fatal(err)
	}
	result := <-events.finished
	if result.Success || result.Code != "install_failed" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !service.store.Snapshot().Apps["app"].Installs["device-id"].InstalledAt.Equal(oldTime) {
		t.Fatal("old install record was replaced")
	}
}

func TestDeviceDisconnectIsReported(t *testing.T) {
	runner := fakeRunner{run: func(_ context.Context, _ CommandSpec) (CommandResult, error) { return CommandResult{}, nil }}
	service := newWorkflowService(t, runner, nil)
	service.listDevicesOverride = func(context.Context) ([]Device, error) { return []Device{}, nil }
	if _, err := service.findDevice(context.Background(), "gone"); err == nil || !strings.Contains(err.Error(), "不可用") {
		t.Fatalf("unexpected error: %v", err)
	}
}
