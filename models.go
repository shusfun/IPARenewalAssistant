package main

import "time"

type EnvironmentStatus struct {
	PlatformSupported   bool     `json:"platformSupported"`
	PlatformIssue       string   `json:"platformIssue,omitempty"`
	VolumeAvailable     bool     `json:"volumeAvailable"`
	VolumeIssue         string   `json:"volumeIssue,omitempty"`
	SigningBackendReady bool     `json:"signingBackendReady"`
	DeviceBackendReady  bool     `json:"deviceBackendReady"`
	AccountReady        bool     `json:"accountReady"`
	CanImport           bool     `json:"canImport"`
	CanSign             bool     `json:"canSign"`
	CanInstall          bool     `json:"canInstall"`
	IdentityReady       bool     `json:"identityReady"`
	IdentityCount       int      `json:"identityCount"`
	ToolsReady          bool     `json:"toolsReady"`
	Ready               bool     `json:"ready"`
	Issues              []string `json:"issues"`
}

type SigningIdentityOption struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Selected bool   `json:"selected"`
}

type Device struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	OSVersion           string   `json:"osVersion"`
	Connection          string   `json:"connection"`
	DeveloperMode       string   `json:"developerMode"`
	Pairing             string   `json:"pairing,omitempty"`
	Available           bool     `json:"available"`
	Transport           string   `json:"transport,omitempty"`
	Channels            []string `json:"channels,omitempty"`
	InstallServiceReady bool     `json:"installServiceReady"`
	internalUDID        string
	internalDeviceID    int
}

type ProfileMetadata struct {
	UUID           string    `json:"uuid"`
	TeamID         string    `json:"teamID"`
	BundleID       string    `json:"bundleID"`
	CreationTime   time.Time `json:"creationTime"`
	ExpirationTime time.Time `json:"expirationTime"`
}

type SignedArtifact struct {
	Path                string          `json:"path"`
	Profile             ProfileMetadata `json:"profile"`
	IdentityFingerprint string          `json:"identityFingerprint"`
	SignedAt            time.Time       `json:"signedAt"`
}

type InstallRecord struct {
	DeviceID      string          `json:"deviceID"`
	BundleID      string          `json:"bundleID"`
	Version       string          `json:"version"`
	Profile       ProfileMetadata `json:"profile"`
	InstalledAt   time.Time       `json:"installedAt"`
	LastConfirmed time.Time       `json:"lastConfirmed"`
	Present       bool            `json:"present"`
}

type ManagedApp struct {
	ID                string                   `json:"id"`
	SHA256            string                   `json:"sha256"`
	OriginalPath      string                   `json:"originalPath"`
	OriginalBundleID  string                   `json:"originalBundleID"`
	EffectiveBundleID string                   `json:"effectiveBundleID"`
	Name              string                   `json:"name"`
	Version           string                   `json:"version"`
	BuildVersion      string                   `json:"buildVersion"`
	MinimumOS         string                   `json:"minimumOS,omitempty"`
	Executable        string                   `json:"executable"`
	AppDirectory      string                   `json:"appDirectory"`
	IconPath          string                   `json:"iconPath,omitempty"`
	SigningObjects    []string                 `json:"signingObjects"`
	ImportedAt        time.Time                `json:"importedAt"`
	LatestSigned      *SignedArtifact          `json:"latestSigned,omitempty"`
	Installs          map[string]InstallRecord `json:"installs"`
}

type State struct {
	SchemaVersion           int                    `json:"schemaVersion"`
	Apps                    map[string]*ManagedApp `json:"apps"`
	LastIdentityFingerprint string                 `json:"lastIdentityFingerprint,omitempty"`
	SelectedDeviceID        string                 `json:"selectedDeviceID,omitempty"`
	LastAppleID             string                 `json:"lastAppleID,omitempty"`
	AppleAccount            *AppleAccountState     `json:"appleAccount,omitempty"`
}

type AppleAccountState struct {
	AccountRef      string          `json:"accountRef"`
	TeamID          string          `json:"teamID,omitempty"`
	TeamName        string          `json:"teamName,omitempty"`
	Teams           []DeveloperTeam `json:"teams,omitempty"`
	AuthenticatedAt time.Time       `json:"authenticatedAt"`
}

type AppleAccountStatus struct {
	SignedIn   bool            `json:"signedIn"`
	AccountRef string          `json:"accountRef,omitempty"`
	TeamID     string          `json:"teamID,omitempty"`
	TeamName   string          `json:"teamName,omitempty"`
	NeedsTeam  bool            `json:"needsTeam"`
	Teams      []DeveloperTeam `json:"teams,omitempty"`
}

type DeveloperTeam struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type LoginChallenge struct {
	AuthID         string `json:"authID"`
	NeedsTwoFactor bool   `json:"needsTwoFactor"`
	Message        string `json:"message"`
}

type RememberedAppleCredentials struct {
	AppleID  string `json:"appleID,omitempty"`
	Password string `json:"password,omitempty"`
}

type AppView struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Version           string     `json:"version"`
	BuildVersion      string     `json:"buildVersion"`
	OriginalBundleID  string     `json:"originalBundleID"`
	EffectiveBundleID string     `json:"effectiveBundleID"`
	MinimumOS         string     `json:"minimumOS,omitempty"`
	IconDataURL       string     `json:"iconDataURL,omitempty"`
	ImportedAt        time.Time  `json:"importedAt"`
	Signed            bool       `json:"signed"`
	SignedAt          *time.Time `json:"signedAt,omitempty"`
	Installed         bool       `json:"installed"`
	InstalledAt       *time.Time `json:"installedAt,omitempty"`
	ExpirationTime    *time.Time `json:"expirationTime,omitempty"`
	ValidityStatus    string     `json:"validityStatus"`
	RemainingSeconds  int64      `json:"remainingSeconds"`
	CanRenew          bool       `json:"canRenew"`
}

type JobHandle struct {
	JobID string `json:"jobID"`
}

type JobProgress struct {
	JobID   string `json:"jobID"`
	Kind    string `json:"kind"`
	Step    string `json:"step"`
	Message string `json:"message"`
	Percent int    `json:"percent"`
}

type JobFinished struct {
	JobID   string `json:"jobID"`
	Kind    string `json:"kind"`
	Success bool   `json:"success"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

type AppNotification struct {
	ID      string `json:"id"`
	Level   string `json:"level"`
	Title   string `json:"title"`
	Message string `json:"message"`
	JobID   string `json:"jobID,omitempty"`
	Code    string `json:"code,omitempty"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	JobID     string    `json:"jobID,omitempty"`
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	Stage     string    `json:"stage"`
	Status    string    `json:"status"`
	AppID     string    `json:"appID,omitempty"`
	BundleID  string    `json:"bundleID,omitempty"`
	DeviceID  string    `json:"deviceID,omitempty"`
	ErrorCode string    `json:"errorCode,omitempty"`
	Message   string    `json:"message,omitempty"`
}

type UserError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Recovery string `json:"recovery,omitempty"`
}

func (e *UserError) Error() string { return e.Message }
