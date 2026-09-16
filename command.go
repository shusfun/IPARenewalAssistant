package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

type CommandSpec struct {
	Name    string
	Args    []string
	Dir     string
	Env     []string
	Input   []byte
	Timeout time.Duration
}

type CommandResult struct {
	Stdout []byte
	Stderr []byte
}

type CommandRunner interface {
	Run(ctx context.Context, spec CommandSpec) (CommandResult, error)
}

type RealCommandRunner struct{}

func (RealCommandRunner) Run(ctx context.Context, spec CommandSpec) (CommandResult, error) {
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	cmd.Dir = spec.Dir
	if len(spec.Env) > 0 {
		cmd.Env = spec.Env
	}
	if len(spec.Input) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, fmt.Errorf("命令执行失败: %w", err)
}

func commandError(code, message, recovery string, result CommandResult, err error) error {
	detail := redact(strings.TrimSpace(string(append(append([]byte{}, result.Stderr...), result.Stdout...))))
	if detail == "" && err != nil {
		detail = redact(err.Error())
	}
	if detail != "" {
		lines := strings.Split(detail, "\n")
		if len(lines) > 8 {
			lines = lines[len(lines)-8:]
		}
		message += "\n" + strings.Join(lines, "\n")
	}
	return &UserError{Code: code, Message: message, Recovery: recovery}
}

func copyLimited(dst io.Writer, src io.Reader, max int64) error {
	n, err := io.CopyN(dst, src, max+1)
	if err != nil && err != io.EOF {
		return err
	}
	if n > max {
		return fmt.Errorf("内容超过允许大小")
	}
	return nil
}
