package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	mu      sync.RWMutex
	ctx     context.Context
	service *Service
	initErr error
}

type wailsEventSink struct{ app *App }

func NewApp() *App {
	app := &App{}
	paths, err := defaultPaths()
	if err != nil {
		app.initErr = err
		return app
	}
	service, err := NewService(paths, RealCommandRunner{}, wailsEventSink{app: app})
	app.service = service
	app.initErr = err
	return app
}

func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	_ = runtime.InitializeNotifications(ctx)
	go func() { _, _ = runtime.RequestNotificationAuthorization(ctx) }()
	runtime.OnFileDrop(ctx, func(_, _ int, paths []string) {
		for _, path := range paths {
			if !strings.EqualFold(filepath.Ext(path), ".ipa") {
				continue
			}
			view, err := a.ImportIPA(path)
			if err != nil {
				runtime.EventsEmit(ctx, "ipa:import-failed", publicError(err))
			} else {
				runtime.EventsEmit(ctx, "ipa:imported", view)
			}
			return
		}
	})
}

func (a *App) ready() error {
	if a.initErr != nil {
		return a.initErr
	}
	if a.service == nil {
		return errors.New("服务尚未初始化")
	}
	return nil
}

func (sink wailsEventSink) Progress(progress JobProgress) {
	sink.app.mu.RLock()
	ctx := sink.app.ctx
	sink.app.mu.RUnlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, "job:progress", progress)
	}
}

func (sink wailsEventSink) Finished(finished JobFinished) {
	sink.app.mu.RLock()
	ctx := sink.app.ctx
	sink.app.mu.RUnlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, "job:finished", finished)
		level, title := "success", "任务完成"
		if !finished.Success {
			level, title = "error", "任务失败"
		}
		notice := AppNotification{ID: "job-" + finished.JobID, Level: level, Title: title, Message: finished.Message, JobID: finished.JobID, Code: finished.Code}
		runtime.EventsEmit(ctx, "app:notification", notice)
		if runtime.WindowIsMinimised(ctx) {
			_ = runtime.SendNotification(ctx, runtime.NotificationOptions{ID: notice.ID, Title: notice.Title, Body: redact(finished.Message)})
		}
	}
}

func (a *App) CheckEnvironment() (EnvironmentStatus, error) {
	if err := a.ready(); err != nil {
		return EnvironmentStatus{}, err
	}
	return a.service.CheckEnvironment(context.Background()), nil
}

func (a *App) GetAppleAccountStatus() (AppleAccountStatus, error) {
	if err := a.ready(); err != nil {
		return AppleAccountStatus{}, err
	}
	return a.service.GetAppleAccountStatus(), nil
}

func (a *App) RememberedAppleCredentials() (RememberedAppleCredentials, error) {
	if err := a.ready(); err != nil {
		return RememberedAppleCredentials{}, err
	}
	return a.service.RememberedAppleCredentials(), nil
}

func (a *App) RememberAppleCredentials(appleID, password string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.RememberAppleCredentials(appleID, password)
}

func (a *App) StartAppleLogin(appleID, password string) (LoginChallenge, error) {
	if err := a.ready(); err != nil {
		return LoginChallenge{}, err
	}
	return a.service.StartAppleLogin(appleID, password)
}

func (a *App) SubmitTwoFactor(authID, code string) (AppleAccountStatus, error) {
	if err := a.ready(); err != nil {
		return AppleAccountStatus{}, err
	}
	return a.service.SubmitTwoFactor(authID, code)
}

func (a *App) ResendTwoFactor(authID string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.ResendTwoFactor(authID)
}

func (a *App) CancelAppleLogin(authID string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.CancelAppleLogin(authID)
}

func (a *App) SelectDeveloperTeam(teamID string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.SelectDeveloperTeam(teamID)
}

func (a *App) SignOutAppleAccount() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.SignOutAppleAccount()
}

func (a *App) ListDevices() ([]Device, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.service.ListDevices(context.Background())
}

func (a *App) ListSigningIdentities() ([]SigningIdentityOption, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.service.ListSigningIdentities(context.Background())
}

func (a *App) SelectSigningIdentity(fingerprint string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.SelectSigningIdentity(context.Background(), fingerprint)
}

func (a *App) SelectAndImportIPA() (AppView, error) {
	if err := a.ready(); err != nil {
		return AppView{}, err
	}
	a.mu.RLock()
	ctx := a.ctx
	a.mu.RUnlock()
	if ctx == nil {
		return AppView{}, errors.New("窗口尚未初始化")
	}
	path, err := runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{
		Title: "导入 IPA", Filters: []runtime.FileFilter{{DisplayName: "iOS App (*.ipa)", Pattern: "*.ipa"}},
	})
	if err != nil || path == "" {
		return AppView{}, err
	}
	return a.service.ImportIPA(path)
}

func (a *App) ImportIPA(path string) (AppView, error) {
	if err := a.ready(); err != nil {
		return AppView{}, err
	}
	return a.service.ImportIPA(path)
}

func (a *App) ListManagedApps(deviceID string) ([]AppView, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.service.ListManagedApps(context.Background(), deviceID)
}

func (a *App) ListAuditEvents(limit int) ([]AuditEvent, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.service.ListAuditEvents(limit), nil
}

func (a *App) SignApp(appID, deviceID, bundlePolicy, certificatePolicy string) (JobHandle, error) {
	if err := a.ready(); err != nil {
		return JobHandle{}, err
	}
	return a.service.SignApp(appID, deviceID, bundlePolicy, certificatePolicy)
}

func (a *App) InstallApp(appID, deviceID string) (JobHandle, error) {
	if err := a.ready(); err != nil {
		return JobHandle{}, err
	}
	return a.service.InstallApp(appID, deviceID)
}

func (a *App) RenewApp(appID, deviceID, certificatePolicy string) (JobHandle, error) {
	if err := a.ready(); err != nil {
		return JobHandle{}, err
	}
	return a.service.RenewApp(appID, deviceID, certificatePolicy)
}

func (a *App) CancelJob(jobID string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.CancelJob(jobID)
}

func (a *App) RevealSignedIPA(appID string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.service.RevealSignedIPA(appID)
}

func publicError(err error) UserError {
	var userErr *UserError
	if errors.As(err, &userErr) {
		return *userErr
	}
	return UserError{Code: "operation_failed", Message: redact(err.Error())}
}
