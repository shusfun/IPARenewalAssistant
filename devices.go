package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	ios "github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/imagemounter"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
	"github.com/danielpaulus/go-ios/ios/instruments"
)

func normalizeUDID(udid string) string {
	return strings.ToUpper(strings.TrimSpace(udid))
}

func deviceIDForUDID(udid string) string {
	sum := sha256.Sum256([]byte(normalizeUDID(udid)))
	return "device-" + hex.EncodeToString(sum[:])[:16]
}

func isUSBConnection(label string) bool {
	return strings.EqualFold(label, "USB") || strings.EqualFold(label, "wired")
}

func isNetworkConnection(label string) bool {
	return strings.EqualFold(label, "Network")
}

func connectionKind(connection, transport string) string {
	value := strings.TrimSpace(transport)
	if value == "" {
		value = strings.TrimSpace(connection)
	}
	switch {
	case isUSBConnection(value):
		return "USB"
	case isNetworkConnection(value):
		return "Network"
	case value == "" || strings.EqualFold(value, "unknown") || value == "未知":
		return "未知"
	default:
		return value
	}
}

func connectionSupported(kind string) bool {
	return kind == "USB" || kind == "Network"
}

func channelLabel(entry ios.DeviceEntry) string {
	return connectionKind(entry.ConnectionTypeLabel(), "")
}

func preferDeviceEntry(entries []ios.DeviceEntry) ios.DeviceEntry {
	var network ios.DeviceEntry
	var foundNetwork bool
	for _, entry := range entries {
		kind := channelLabel(entry)
		if kind == "USB" {
			return entry
		}
		if kind == "Network" && !foundNetwork {
			network = entry
			foundNetwork = true
		}
	}
	if foundNetwork {
		return network
	}
	return entries[0]
}

func uniqueChannels(entries []ios.DeviceEntry) []string {
	seen := map[string]bool{}
	channels := make([]string, 0, len(entries))
	for _, kind := range []string{"USB", "Network"} {
		for _, entry := range entries {
			if channelLabel(entry) == kind && !seen[kind] {
				seen[kind] = true
				channels = append(channels, kind)
			}
		}
	}
	for _, entry := range entries {
		kind := channelLabel(entry)
		if kind == "USB" || kind == "Network" || seen[kind] {
			continue
		}
		seen[kind] = true
		channels = append(channels, kind)
	}
	return channels
}

func (s *Service) listGoIOSDevices() (ios.DeviceList, error) {
	if s.listGoIOSOverride != nil {
		return s.listGoIOSOverride()
	}
	devices, err := ios.ListDevices()
	if err != nil {
		return ios.DeviceList{}, &UserError{Code: "device_scan_failed", Message: "无法读取已配对的 iOS 设备", Recovery: "请解锁设备、确认已信任这台 Mac，并通过 USB 连接后重试。"}
	}
	return devices, nil
}

func (s *Service) ListDevices(ctx context.Context) ([]Device, error) {
	if s.listDevicesOverride != nil {
		return s.listDevicesOverride(ctx)
	}
	if err := s.storageCheck(); err != nil {
		return []Device{}, nil
	}
	list, err := s.listGoIOSDevices()
	if err != nil {
		return nil, err
	}
	grouped := map[string][]ios.DeviceEntry{}
	order := make([]string, 0, len(list.DeviceList))
	for _, entry := range list.DeviceList {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		udid := strings.TrimSpace(entry.Properties.SerialNumber)
		if udid == "" {
			continue
		}
		id := deviceIDForUDID(udid)
		if _, ok := grouped[id]; !ok {
			order = append(order, id)
		}
		grouped[id] = append(grouped[id], entry)
	}
	devices := make([]Device, 0, len(order))
	for _, id := range order {
		entries := grouped[id]
		picked := preferDeviceEntry(entries)
		device := s.describeDevice(picked)
		device.Channels = uniqueChannels(entries)
		devices = append(devices, device)
	}
	return devices, nil
}

func (s *Service) describeDevice(entry ios.DeviceEntry) Device {
	udid := strings.TrimSpace(entry.Properties.SerialNumber)
	osVersion := "未知"
	pairing := "未知"
	name := "iOS 设备"
	if version, versionErr := ios.GetProductVersion(entry); versionErr == nil && version != nil {
		osVersion = version.String()
	}
	if values, valuesErr := ios.GetValuesPlist(entry); valuesErr == nil {
		pairing = "已配对"
		if value, ok := values["DeviceName"].(string); ok && strings.TrimSpace(value) != "" {
			name = value
		}
	}
	developerMode := "未知"
	if enabled, modeErr := imagemounter.IsDevModeEnabled(entry); modeErr == nil {
		if enabled {
			developerMode = "已开启"
		} else {
			developerMode = "未开启"
		}
	}
	kind := channelLabel(entry)
	ready := connectionSupported(kind) && pairing == "已配对" && developerMode == "已开启"
	return Device{ID: deviceIDForUDID(udid), Name: name, OSVersion: osVersion,
		Connection: kind, Transport: kind, DeveloperMode: developerMode, Pairing: pairing,
		Available: ready, InstallServiceReady: ready, internalUDID: udid, internalDeviceID: entry.DeviceID}
}

func (s *Service) findDeviceEntry(ctx context.Context, deviceID string) (Device, ios.DeviceEntry, error) {
	if s.findDeviceOverride != nil {
		device, err := s.findDeviceOverride(ctx, deviceID)
		if err != nil {
			return Device{}, ios.DeviceEntry{}, err
		}
		return device, ios.DeviceEntry{DeviceID: device.internalDeviceID, Properties: ios.DeviceProperties{SerialNumber: device.internalUDID, ConnectionType: device.Connection}}, nil
	}
	var seen int
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return Device{}, ios.DeviceEntry{}, ctx.Err()
		}
		list, err := s.listGoIOSDevices()
		if err != nil {
			return Device{}, ios.DeviceEntry{}, err
		}
		seen = len(list.DeviceList)
		matches := make([]ios.DeviceEntry, 0, 2)
		for _, entry := range list.DeviceList {
			if deviceIDForUDID(entry.Properties.SerialNumber) != deviceID {
				continue
			}
			matches = append(matches, entry)
		}
		if len(matches) > 0 {
			entry := preferDeviceEntry(matches)
			device := s.describeDevice(entry)
			device.Channels = uniqueChannels(matches)
			return device, entry, nil
		}
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Device{}, ios.DeviceEntry{}, ctx.Err()
		case <-timer.C:
		}
	}
	recovery := "请解锁设备、保持 USB 或网络连接并点击刷新。"
	if seen > 0 {
		recovery = "设备列表已变化，请刷新后重新选择这台手机。"
	}
	return Device{}, ios.DeviceEntry{}, &UserError{Code: "device_unavailable", Message: "目标 iOS 设备当前不可用", Recovery: recovery}
}

func (s *Service) findDevice(ctx context.Context, deviceID string) (Device, error) {
	if s.findDeviceOverride != nil {
		return s.findDeviceOverride(ctx, deviceID)
	}
	device, _, err := s.findDeviceEntry(ctx, deviceID)
	return device, err
}

func (s *Service) queryInstalledApp(ctx context.Context, deviceID, bundleID, temp string) (bool, string, error) {
	present, version, _, err := s.lookupInstalledApp(ctx, deviceID, bundleID, temp)
	return present, version, err
}

func (s *Service) lookupInstalledPinned(ctx context.Context, deviceID, bundleID, temp string, entry ios.DeviceEntry) (bool, string, string, error) {
	if s.lookupInstalledOverride != nil || s.queryInstalledOverride != nil {
		return s.lookupInstalledApp(ctx, deviceID, bundleID, temp)
	}
	return s.lookupInstalledOnEntry(entry, bundleID)
}

func (s *Service) queryInstalledPinned(ctx context.Context, deviceID, bundleID, temp string, entry ios.DeviceEntry) (bool, string, error) {
	present, version, _, err := s.lookupInstalledPinned(ctx, deviceID, bundleID, temp, entry)
	return present, version, err
}

func (s *Service) launchInstalledPinned(ctx context.Context, deviceID, bundleID string, entry ios.DeviceEntry) error {
	if s.launchOverride != nil {
		return s.launchOverride(ctx, deviceID, bundleID)
	}
	return s.launchInstalledOnEntry(ctx, entry, bundleID)
}

func (s *Service) lookupInstalledApp(ctx context.Context, deviceID, bundleID, temp string) (bool, string, string, error) {
	if s.lookupInstalledOverride != nil {
		return s.lookupInstalledOverride(ctx, deviceID, bundleID)
	}
	if s.queryInstalledOverride != nil {
		present, version, err := s.queryInstalledOverride(ctx, deviceID, bundleID, temp)
		return present, version, "", err
	}
	_, entry, err := s.findDeviceEntry(ctx, deviceID)
	if err != nil {
		return false, "", "", err
	}
	return s.lookupInstalledOnEntry(entry, bundleID)
}

func (s *Service) lookupInstalledOnEntry(entry ios.DeviceEntry, bundleID string) (bool, string, string, error) {
	conn, err := installationproxy.New(entry)
	if err != nil {
		return false, "", "", &UserError{Code: "device_query_failed", Message: "无法读取设备中的 App", Recovery: "请解锁设备并确认已信任这台 Mac。"}
	}
	defer conn.Close()
	apps, err := conn.BrowseUserApps()
	if err != nil {
		return false, "", "", &UserError{Code: "device_query_failed", Message: "无法读取设备中的 App", Recovery: "请保持设备解锁并重新连接。"}
	}
	for _, app := range apps {
		if app.CFBundleIdentifier() == bundleID {
			return true, app.CFBundleShortVersionString(), installedAppTeamID(app), nil
		}
	}
	return false, "", "", nil
}

func installedAppTeamID(app installationproxy.AppInfo) string {
	if entitlements, ok := app[installationproxy.Entitlements].(map[string]any); ok {
		if team, ok := entitlements["com.apple.developer.team-identifier"].(string); ok && strings.TrimSpace(team) != "" {
			return strings.TrimSpace(team)
		}
		if identifier, ok := entitlements["application-identifier"].(string); ok {
			if team, _, found := strings.Cut(identifier, "."); found && team != "" {
				return team
			}
		}
	}
	return ""
}

func (s *Service) launchInstalledApp(ctx context.Context, deviceID, bundleID string) error {
	if s.launchOverride != nil {
		return s.launchOverride(ctx, deviceID, bundleID)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, entry, err := s.findDeviceEntry(ctx, deviceID)
	if err != nil {
		return err
	}
	return s.launchInstalledOnEntry(ctx, entry, bundleID)
}

func (s *Service) launchInstalledOnEntry(ctx context.Context, entry ios.DeviceEntry, bundleID string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	control, err := instruments.NewProcessControl(entry)
	if err != nil {
		return &UserError{Code: "launch_failed", Message: "应用已传输，但无法在设备上启动", Recovery: "请解锁设备并确认开发者模式已开启后重试。安装记录未更新。"}
	}
	defer control.Close()
	if _, err := control.LaunchApp(bundleID, nil); err != nil {
		return &UserError{Code: "launch_failed", Message: "应用已传输，但未能在设备上启动", Recovery: "请在手机上确认应用是否可打开。安装记录未更新。"}
	}
	return nil
}

func (s *Service) deviceEntry(ctx context.Context, deviceID string) (ios.DeviceEntry, error) {
	_, entry, err := s.findDeviceEntry(ctx, deviceID)
	return entry, err
}

func (s *Service) ensureUSBDevice(device Device) error {
	kind := connectionKind(device.Connection, device.Transport)
	if connectionSupported(kind) {
		return nil
	}
	if kind == "未知" {
		return &UserError{Code: "device_connection_unknown", Message: "无法确认设备连接方式", Recovery: "请刷新设备。未知连接不会视为可用。"}
	}
	return &UserError{Code: "device_connection_unsupported", Message: "当前连接方式不可用于签名或安装", Recovery: "请使用 USB 或网络连接后刷新。"}
}

func (s *Service) ensureDeviceReady(device Device) error {
	if err := s.ensureUSBDevice(device); err != nil {
		return err
	}
	switch device.Pairing {
	case "已配对":
	case "未配对":
		return &UserError{Code: "device_not_paired", Message: "设备尚未配对或未信任这台 Mac", Recovery: "请解锁设备并点击“信任”，然后刷新。"}
	default:
		return &UserError{Code: "device_pairing_unknown", Message: "无法确认设备已配对或已信任", Recovery: "请解锁设备、保持 USB 或网络连接后刷新。未知状态不会视为通过。"}
	}
	switch device.DeveloperMode {
	case "已开启":
		return nil
	case "未开启":
		return &UserError{Code: "developer_mode_required", Message: "请在设备上开启开发者模式", Recovery: "打开设置 > 隐私与安全性 > 开发者模式，然后重新连接。"}
	default:
		return &UserError{Code: "developer_mode_unknown", Message: "无法确认开发者模式", Recovery: "请解锁设备并刷新。未知状态不会视为通过。"}
	}
}
