package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type recordingEvents struct{ finished chan JobFinished }

func (r recordingEvents) Progress(JobProgress)       {}
func (r recordingEvents) Finished(event JobFinished) { r.finished <- event }

type fakeRunner struct {
	run func(context.Context, CommandSpec) (CommandResult, error)
}

func (f fakeRunner) Run(ctx context.Context, spec CommandSpec) (CommandResult, error) {
	return f.run(ctx, spec)
}

func TestJobCancellationAndSingleFlight(t *testing.T) {
	root := t.TempDir()
	events := recordingEvents{finished: make(chan JobFinished, 1)}
	service, err := NewService(Paths{StateFile: filepath.Join(root, "state.json"), Library: filepath.Join(root, "library"), Cache: filepath.Join(root, "cache")}, fakeRunner{run: func(context.Context, CommandSpec) (CommandResult, error) { return CommandResult{}, nil }}, events)
	if err != nil {
		t.Fatal(err)
	}
	service.storageCheck = func() error { return nil }
	blocker := fakeRunner{run: func(ctx context.Context, _ CommandSpec) (CommandResult, error) {
		<-ctx.Done()
		return CommandResult{}, ctx.Err()
	}}
	handle, err := service.startJob("sign", func(ctx context.Context, _, _ string) error {
		_, runErr := blocker.Run(ctx, CommandSpec{Name: "fake"})
		return runErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.startJob("install", func(context.Context, string, string) error { return nil }); err == nil {
		t.Fatal("expected busy error")
	}
	if err := service.CancelJob(handle.JobID); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-events.finished:
		if result.Code != "cancelled" {
			t.Fatalf("result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("job did not finish")
	}
}

func TestFakeRunnerTimeout(t *testing.T) {
	runner := fakeRunner{run: func(ctx context.Context, _ CommandSpec) (CommandResult, error) {
		<-ctx.Done()
		return CommandResult{}, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := runner.Run(ctx, CommandSpec{Name: "slow"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestDisconnectedStorageStopsJobs(t *testing.T) {
	root := t.TempDir()
	service, err := NewService(Paths{StateFile: filepath.Join(root, "state.json"), Library: filepath.Join(root, "library"), Cache: filepath.Join(root, "cache")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.storageCheck = func() error { return errors.New("missing") }
	if _, err := service.startJob("sign", func(context.Context, string, string) error { return nil }); err == nil {
		t.Fatal("expected storage error")
	}
}
