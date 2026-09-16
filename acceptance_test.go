package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type acceptanceEvents struct {
	finished chan JobFinished
	log      func(string, ...any)
}

func (a acceptanceEvents) Progress(progress JobProgress) {
	a.log("%s %d%%", progress.Step, progress.Percent)
}

func (a acceptanceEvents) Finished(result JobFinished) { a.finished <- result }

func TestCurrentIPARealAcceptance(t *testing.T) {
	if os.Getenv("IPA_RENEWAL_REAL_ACCEPTANCE") != "1" {
		t.Skip("set IPA_RENEWAL_REAL_ACCEPTANCE=1 to run against the connected iOS device")
	}
	if exec.Command("pgrep", "-x", "Xcode").Run() == nil {
		t.Fatal("Xcode was already running before acceptance")
	}
	paths, err := defaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	events := acceptanceEvents{finished: make(chan JobFinished, 2), log: t.Logf}
	service, err := NewService(paths, RealCommandRunner{}, events)
	if err != nil {
		t.Fatal(err)
	}
	environment := service.CheckEnvironment(context.Background())
	if !environment.Ready {
		t.Fatalf("environment is not ready: %v", environment.Issues)
	}
	ipaPath := strings.TrimSpace(os.Getenv("IPA_RENEWAL_ACCEPTANCE_IPA"))
	if ipaPath == "" {
		t.Fatal("set IPA_RENEWAL_ACCEPTANCE_IPA to the IPA path")
	}
	wantedDevice := strings.TrimSpace(os.Getenv("IPA_RENEWAL_ACCEPTANCE_DEVICE"))
	devices, err := service.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 {
		t.Fatal("no available iOS device")
	}
	device, err := pickAcceptanceDevice(devices, wantedDevice)
	if err != nil {
		t.Fatal(err)
	}
	if wanted := strings.TrimSpace(os.Getenv("IPA_RENEWAL_ACCEPTANCE_TRANSPORT")); wanted != "" {
		if !strings.EqualFold(device.Connection, wanted) && !strings.EqualFold(device.Transport, wanted) {
			t.Fatalf("acceptance required %s but selected %s", wanted, device.Connection)
		}
	}
	app, err := service.ImportIPA(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListManagedApps(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignApp(app.ID, device.ID, "preserve"); err != nil {
		t.Fatal(err)
	}
	waitAcceptanceResult(t, events.finished, "sign", 12*time.Minute)
	state := service.store.Snapshot()
	managed := state.Apps[app.ID]
	if managed == nil || managed.LatestSigned == nil {
		t.Fatal("signed artifact was not recorded")
	}
	if _, err := os.Stat(managed.LatestSigned.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallApp(app.ID, device.ID); err != nil {
		t.Fatal(err)
	}
	waitAcceptanceResult(t, events.finished, "install", 8*time.Minute)
	state = service.store.Snapshot()
	record, ok := state.Apps[app.ID].Installs[device.ID]
	if !ok || !record.Present || !record.Profile.ExpirationTime.After(time.Now()) {
		t.Fatalf("installation/profile state was not committed: %#v", record)
	}
	if exec.Command("pgrep", "-x", "Xcode").Run() == nil {
		t.Fatal("Xcode was launched during acceptance")
	}
}

func TestCurrentIPAImportAcceptance(t *testing.T) {
	if os.Getenv("IPA_RENEWAL_IMPORT_ACCEPTANCE") != "1" {
		t.Skip("set IPA_RENEWAL_IMPORT_ACCEPTANCE=1 to run against the current IPA")
	}
	paths, err := defaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(paths, RealCommandRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ipaPath := strings.TrimSpace(os.Getenv("IPA_RENEWAL_ACCEPTANCE_IPA"))
	if ipaPath == "" {
		t.Fatal("set IPA_RENEWAL_ACCEPTANCE_IPA to the IPA path")
	}
	app, err := service.ImportIPA(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	if app.Name == "" || app.OriginalBundleID == "" || app.IconDataURL == "" {
		t.Fatalf("incomplete imported metadata: name=%t bundle=%t icon=%t", app.Name != "", app.OriginalBundleID != "", app.IconDataURL != "")
	}
}

func pickAcceptanceDevice(devices []Device, wanted string) (Device, error) {
	if wanted == "" {
		return Device{}, fmt.Errorf("set IPA_RENEWAL_ACCEPTANCE_DEVICE to the device ID or UDID")
	}
	for _, device := range devices {
		if device.ID == wanted || device.internalUDID == wanted {
			return device, nil
		}
	}
	return Device{}, fmt.Errorf("requested device %s was not found", wanted)
}

func waitAcceptanceResult(t *testing.T, results <-chan JobFinished, kind string, timeout time.Duration) {
	t.Helper()
	select {
	case result := <-results:
		if !result.Success {
			t.Fatalf("%s failed [%s]: %s", kind, result.Code, result.Message)
		}
	case <-time.After(timeout):
		t.Fatalf("%s timed out", kind)
	}
}
