package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ios "github.com/danielpaulus/go-ios/ios"
)

type EventSink interface {
	Progress(JobProgress)
	Finished(JobFinished)
}

type noopEventSink struct{}

func (noopEventSink) Progress(JobProgress) {}
func (noopEventSink) Finished(JobFinished) {}

type runningJob struct {
	id     string
	kind   string
	cancel context.CancelFunc
	temp   string
}

type Service struct {
	paths        Paths
	store        *StateStore
	runner       CommandRunner
	events       EventSink
	now          func() time.Time
	storageCheck func() error
	apple        *AppleBackend
	auditMu      sync.Mutex
	// These hooks are only used by unit tests. Production always uses go-ios
	// and the bundled signer implementation.
	listDevicesOverride     func(context.Context) ([]Device, error)
	listGoIOSOverride       func() (ios.DeviceList, error)
	findDeviceOverride      func(context.Context, string) (Device, error)
	queryInstalledOverride  func(context.Context, string, string, string) (bool, string, error)
	lookupInstalledOverride func(context.Context, string, string) (bool, string, string, error)
	installOverride         func(context.Context, string, string, string, string) error
	signOverride            func(context.Context, string, string, string, string, string, string) error
	launchOverride          func(context.Context, string, string) error

	jobMu sync.Mutex
	job   *runningJob
}

func NewService(paths Paths, runner CommandRunner, events EventSink) (*Service, error) {
	if paths.AuditFile == "" {
		paths.AuditFile = filepath.Join(filepath.Dir(paths.StateFile), "audit.jsonl")
	}
	store, err := NewStateStore(paths.StateFile)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = RealCommandRunner{}
	}
	if events == nil {
		events = noopEventSink{}
	}
	return &Service{paths: paths, store: store, runner: runner, events: events, now: time.Now, storageCheck: checkVolumeIdentity, apple: newAppleBackend()}, nil
}

func (s *Service) ensureExternalStorage() error {
	if err := s.storageCheck(); err != nil {
		return &UserError{Code: "volume_unavailable", Message: err.Error(), Recovery: "请连接正确的 980Pro 后点击刷新。应用不会改用内置磁盘。"}
	}
	for _, dir := range []string{
		filepath.Join(s.paths.Library, "originals"),
		filepath.Join(s.paths.Library, "signed"),
		filepath.Join(s.paths.Library, "icons"),
		s.paths.Cache,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return &UserError{Code: "storage_create_failed", Message: "无法创建 980Pro 上的应用目录", Recovery: "请检查卷的写入权限。"}
		}
	}
	return nil
}

func (s *Service) startJob(kind string, work func(context.Context, string, string) error) (JobHandle, error) {
	if err := s.ensureExternalStorage(); err != nil {
		return JobHandle{}, err
	}
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.job != nil {
		return JobHandle{}, &UserError{Code: "job_busy", Message: "已有任务正在执行", Recovery: "请等待当前任务结束，或先取消当前任务。"}
	}
	jobID := fmt.Sprintf("%d", s.now().UnixNano())
	temp, err := os.MkdirTemp(s.paths.Cache, "job-"+kind+"-")
	if err != nil {
		return JobHandle{}, &UserError{Code: "cache_unavailable", Message: "无法创建本次任务的缓存目录"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.job = &runningJob{id: jobID, kind: kind, cancel: cancel, temp: temp}
	s.audit(AuditEvent{JobID: jobID, Kind: kind, Stage: "start", Status: "started", Message: "任务开始"})
	go func() {
		err := work(ctx, temp, jobID)
		_ = os.RemoveAll(temp)
		s.jobMu.Lock()
		if s.job != nil && s.job.id == jobID {
			s.job = nil
		}
		s.jobMu.Unlock()
		finished := JobFinished{JobID: jobID, Kind: kind, Success: err == nil}
		if err == nil {
			finished.Message = map[string]string{"sign": "签名已完成", "install": "安装已完成", "renew": "续签已完成"}[kind]
		} else if ctx.Err() != nil {
			finished.Code = "cancelled"
			finished.Message = "任务已取消"
		} else if userErr, ok := err.(*UserError); ok {
			finished.Code = userErr.Code
			finished.Message = userErr.Message
			if userErr.Recovery != "" {
				finished.Message += "\n" + userErr.Recovery
			}
		} else {
			finished.Code = "operation_failed"
			finished.Message = redact(err.Error())
		}
		status := "success"
		code := finished.Code
		if !finished.Success {
			status = "failed"
			if ctx.Err() != nil {
				status = "cancelled"
			}
		}
		s.audit(AuditEvent{JobID: jobID, Kind: kind, Stage: "finish", Status: status, ErrorCode: code, Message: finished.Message})
		s.events.Finished(finished)
	}()
	return JobHandle{JobID: jobID}, nil
}

func (s *Service) progress(jobID, kind, step, message string, percent int) {
	s.events.Progress(JobProgress{JobID: jobID, Kind: kind, Step: step, Message: message, Percent: percent})
}

func (s *Service) audit(event AuditEvent) {
	if event.ID == "" {
		event.ID = fmt.Sprintf("audit-%d", s.now().UnixNano())
	}
	if event.At.IsZero() {
		event.At = s.now()
	}
	event.Message = redact(event.Message)
	b, err := json.Marshal(event)
	if err != nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.paths.AuditFile), 0o700); err != nil {
		return
	}
	file, err := os.OpenFile(s.paths.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_ = file.Chmod(0o600)
	_, _ = file.Write(append(b, '\n'))
}

func (s *Service) ListAuditEvents(limit int) []AuditEvent {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.auditMu.Lock()
	b, err := os.ReadFile(s.paths.AuditFile)
	s.auditMu.Unlock()
	if err != nil {
		return []AuditEvent{}
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	result := make([]AuditEvent, 0, min(limit, len(lines)))
	for index := len(lines) - 1; index >= 0 && len(result) < limit; index-- {
		var event AuditEvent
		if json.Unmarshal([]byte(lines[index]), &event) == nil {
			result = append(result, event)
		}
	}
	return result
}

func (s *Service) currentJobID() string {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.job == nil {
		return ""
	}
	return s.job.id
}

func (s *Service) CancelJob(jobID string) error {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.job == nil || s.job.id != jobID {
		return &UserError{Code: "job_not_found", Message: "任务已经结束或不存在"}
	}
	s.job.cancel()
	return nil
}
