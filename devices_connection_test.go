package main

import (
	"context"
	"strings"
	"testing"

	ios "github.com/danielpaulus/go-ios/ios"
)

func TestDeviceIDForUDIDNormalizesCaseAndSpace(t *testing.T) {
	want := deviceIDForUDID("00008130-000C48223EF2001C")
	if got := deviceIDForUDID(" 00008130-000c48223ef2001c "); got != want {
		t.Fatalf("normalized id %s, want %s", got, want)
	}
	if want != "device-a6b9d148ade4a844" {
		t.Fatalf("unexpected stable id %s", want)
	}
}

func TestFindDeviceEntryMatchesLowercaseSerialAfterRetry(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{}, nil
	}}, nil)
	udid := "00008130-000C48223EF2001C"
	id := deviceIDForUDID(udid)
	calls := 0
	service.listGoIOSOverride = func() (ios.DeviceList, error) {
		calls++
		if calls == 1 {
			return ios.DeviceList{}, nil
		}
		return ios.DeviceList{DeviceList: []ios.DeviceEntry{
			{DeviceID: 7, Properties: ios.DeviceProperties{SerialNumber: strings.ToLower(udid), ConnectionType: "Network"}},
		}}, nil
	}
	_, entry, err := service.findDeviceEntry(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected a retry after empty list, calls=%d", calls)
	}
	if entry.DeviceID != 7 {
		t.Fatalf("got DeviceID %d", entry.DeviceID)
	}
}

func TestConnectionKindKeepsUnknown(t *testing.T) {
	if connectionKind("unknown", "") != "未知" {
		t.Fatal("unknown connection should stay unknown")
	}
	if connectionKind("", "unknown") != "未知" {
		t.Fatal("unknown transport should stay unknown")
	}
	if connectionKind("Network", "") != "Network" {
		t.Fatal("network should remain a candidate")
	}
	if !connectionSupported("USB") || !connectionSupported("Network") || connectionSupported("未知") {
		t.Fatal("only USB and Network are supported")
	}
}

func TestPreferDeviceEntryUsesUSBBeforeNetwork(t *testing.T) {
	network := ios.DeviceEntry{DeviceID: 2, Properties: ios.DeviceProperties{SerialNumber: "UDID", ConnectionType: "Network"}}
	usb := ios.DeviceEntry{DeviceID: 1, Properties: ios.DeviceProperties{SerialNumber: "UDID", ConnectionType: "USB"}}
	picked := preferDeviceEntry([]ios.DeviceEntry{network, usb})
	if picked.DeviceID != 1 {
		t.Fatalf("expected USB DeviceID 1, got %d", picked.DeviceID)
	}
	if unique := uniqueChannels([]ios.DeviceEntry{network, usb}); strings.Join(unique, ",") != "USB,Network" {
		t.Fatalf("unexpected channels: %v", unique)
	}
}

func TestEnsureDeviceReadyAcceptsNetwork(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{}, nil
	}}, nil)
	device := readyTestDevice("device-id", "UDID-1")
	device.Connection = "Network"
	device.Transport = "Network"
	if err := service.ensureDeviceReady(device); err != nil {
		t.Fatal(err)
	}
	device.Connection = "unknown"
	device.Transport = "unknown"
	if err := service.ensureDeviceReady(device); err == nil || !strings.Contains(err.Error(), "无法确认设备连接方式") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFindDeviceEntryResolvesFreshUSBPreferredConnection(t *testing.T) {
	service := newWorkflowService(t, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) {
		return CommandResult{}, nil
	}}, nil)
	udid := "UDID-DUAL"
	id := deviceIDForUDID(udid)
	service.listGoIOSOverride = func() (ios.DeviceList, error) {
		return ios.DeviceList{DeviceList: []ios.DeviceEntry{
			{DeviceID: 40, Properties: ios.DeviceProperties{SerialNumber: udid, ConnectionType: "Network"}},
			{DeviceID: 41, Properties: ios.DeviceProperties{SerialNumber: udid, ConnectionType: "USB"}},
		}}, nil
	}
	device, entry, err := service.findDeviceEntry(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if entry.DeviceID != 41 {
		t.Fatalf("stale or network DeviceID used: %d", entry.DeviceID)
	}
	if device.Connection != "USB" {
		t.Fatalf("expected USB, got %s", device.Connection)
	}
	service.listGoIOSOverride = func() (ios.DeviceList, error) {
		return ios.DeviceList{DeviceList: []ios.DeviceEntry{
			{DeviceID: 99, Properties: ios.DeviceProperties{SerialNumber: udid, ConnectionType: "Network"}},
		}}, nil
	}
	_, entry, err = service.findDeviceEntry(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if entry.DeviceID != 99 {
		t.Fatalf("did not re-resolve live Network DeviceID, got %d", entry.DeviceID)
	}
}
