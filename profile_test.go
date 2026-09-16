package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidateProfile(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.Local)
	profile := mobileProvision{
		UUID: "profile", TeamIdentifier: []string{"TEAM"},
		CreationDate: now.Add(-time.Minute), ExpirationDate: now.Add(7 * 24 * time.Hour),
		ProvisionedDevices: []string{"device"}, Entitlements: map[string]any{"application-identifier": "TEAM.com.example.app"},
	}
	metadata, err := validateProfile(profile, "TEAM", "com.example.app", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ExpirationTime != profile.ExpirationDate {
		t.Fatal("expiration mismatch")
	}
	if _, err := validateProfile(profile, "TEAM", "com.example.app", "other", now); err == nil {
		t.Fatal("expected device mismatch")
	}
}

func TestBuildEntitlementsRejectsUnsupportedCapability(t *testing.T) {
	original := map[string]any{"aps-environment": "development"}
	allowed := map[string]any{"application-identifier": "TEAM.com.example.app", "get-task-allow": true}
	_, err := buildEntitlements(original, allowed)
	if err == nil || !strings.Contains(err.Error(), "推送通知") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildEntitlementsKeepsOnlyAllowedValues(t *testing.T) {
	original := map[string]any{"com.apple.developer.networking.wifi-info": true, "application-identifier": "OLD.app"}
	allowed := map[string]any{"application-identifier": "TEAM.app", "com.apple.developer.team-identifier": "TEAM", "get-task-allow": true, "com.apple.developer.networking.wifi-info": true, "unrequested": true}
	data, err := buildEntitlements(original, allowed)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "TEAM.app") || strings.Contains(text, "OLD.app") || strings.Contains(text, "unrequested") {
		t.Fatalf("unexpected entitlements: %s", text)
	}
}

func TestValidityStatusBoundaries(t *testing.T) {
	now := time.Now()
	if validityStatus(now, now.Add(72*time.Hour+time.Second)) != "valid" {
		t.Fatal("expected valid")
	}
	if validityStatus(now, now.Add(72*time.Hour)) != "expiring" {
		t.Fatal("expected expiring")
	}
	if validityStatus(now, now) != "expired" {
		t.Fatal("expected expired")
	}
}
