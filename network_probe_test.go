package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	ios "github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/imagemounter"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
	"github.com/danielpaulus/go-ios/ios/zipconduit"
)

func TestNetworkInstallChannelProbe(t *testing.T) {
	if os.Getenv("IPA_RENEWAL_NETWORK_PROBE") != "1" {
		t.Skip("set IPA_RENEWAL_NETWORK_PROBE=1 to probe wireless install without sending an IPA")
	}

	list, err := ios.ListDevices()
	if err != nil {
		t.Fatalf("device_scan_failed: %v", err)
	}

	var network []ios.DeviceEntry
	for _, entry := range list.DeviceList {
		if strings.EqualFold(entry.ConnectionTypeLabel(), "Network") && strings.TrimSpace(entry.Properties.SerialNumber) != "" {
			network = append(network, entry)
		}
	}
	if len(network) == 0 {
		t.Fatalf("device_unavailable: usbmuxd 没有返回 Network 设备（共 %d 条）", len(list.DeviceList))
	}

	var last error
	for _, entry := range network {
		t.Logf("probe Network DeviceID=%d UDID=%s", entry.DeviceID, entry.Properties.SerialNumber)
		if err := probeNetworkInstallChannel(t, entry); err != nil {
			last = err
			t.Logf("channel failed [%v]", err)
			continue
		}
		t.Log("zipconduit connected and closed without SendFile")
		return
	}
	t.Fatalf("no Network device passed the install-channel probe: %v", last)
}

func probeNetworkInstallChannel(t *testing.T, entry ios.DeviceEntry) error {
	t.Helper()

	version, versionErr := ios.GetProductVersion(entry)
	if versionErr != nil || version == nil {
		return probeError("device_pairing_unknown", "无法实时读取系统版本，可能只是发现记录", versionErr)
	}
	t.Logf("product version %s", version.String())

	values, valuesErr := ios.GetValuesPlist(entry)
	if valuesErr != nil {
		return probeError("device_pairing_unknown", "无法建立配对会话或读取设备信息", valuesErr)
	}
	name, _ := values["DeviceName"].(string)
	if strings.TrimSpace(name) == "" {
		name = "未命名设备"
	}
	t.Logf("paired device %q", name)

	enabled, modeErr := imagemounter.IsDevModeEnabled(entry)
	if modeErr != nil {
		return probeError("developer_mode_unknown", "无法确认开发者模式", modeErr)
	}
	if !enabled {
		return probeError("developer_mode_required", "开发者模式未开启", nil)
	}
	t.Log("developer mode enabled")

	apps, appsErr := installationproxy.New(entry)
	if appsErr != nil {
		return probeError("device_query_failed", "无法连接安装查询服务", appsErr)
	}
	listed, browseErr := apps.BrowseUserApps()
	apps.Close()
	if browseErr != nil {
		return probeError("device_query_failed", "无法读取已安装应用", browseErr)
	}
	t.Logf("listed %d user apps", len(listed))

	conn, conduitErr := zipconduit.New(entry)
	if conduitErr != nil {
		return probeError("install_service_unavailable", "无法建立 zipconduit 安装服务连接", conduitErr)
	}
	closeErr := conn.Close()
	if closeErr != nil {
		t.Logf("zipconduit close: %v", closeErr)
	}
	return nil
}

func probeError(code, message string, err error) error {
	if err == nil {
		return &UserError{Code: code, Message: message}
	}
	return &UserError{Code: code, Message: message + ": " + err.Error()}
}

func TestProbeErrorKeepsCode(t *testing.T) {
	err := probeError("install_service_unavailable", "无法建立 zipconduit 安装服务连接", errors.New("connection refused"))
	var userErr *UserError
	if !errors.As(err, &userErr) || userErr.Code != "install_service_unavailable" {
		t.Fatalf("unexpected error: %#v", err)
	}
}
