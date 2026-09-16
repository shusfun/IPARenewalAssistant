package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type StateStore struct {
	path string
	mu   sync.RWMutex
	data State
}

func NewStateStore(path string) (*StateStore, error) {
	s := &StateStore{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func emptyState() State {
	return State{SchemaVersion: currentSchema, Apps: make(map[string]*ManagedApp)}
}

func (s *StateStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.data = emptyState()
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取状态文件失败: %w", err)
	}
	var state State
	if err := json.Unmarshal(b, &state); err != nil {
		return fmt.Errorf("状态文件已损坏: %w", err)
	}
	if err := migrateState(&state); err != nil {
		return err
	}
	s.data = state
	return nil
}

func migrateState(state *State) error {
	if state.SchemaVersion > currentSchema {
		return fmt.Errorf("状态文件版本 %d 高于本程序支持的版本 %d", state.SchemaVersion, currentSchema)
	}
	if state.SchemaVersion == 0 {
		state.SchemaVersion = 1
	}
	if state.SchemaVersion == 1 {
		state.SchemaVersion = 2
	}
	if state.Apps == nil {
		state.Apps = make(map[string]*ManagedApp)
	}
	for _, app := range state.Apps {
		if app.Installs == nil {
			app.Installs = make(map[string]InstallRecord)
		}
		if app.EffectiveBundleID == "" {
			app.EffectiveBundleID = app.OriginalBundleID
		}
	}
	return nil
}

func (s *StateStore) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.data)
	var clone State
	_ = json.Unmarshal(b, &clone)
	return clone
}

func (s *StateStore) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	var next State
	if err := json.Unmarshal(b, &next); err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	next.SchemaVersion = currentSchema
	if err := writeJSONAtomic(s.path, next); err != nil {
		return err
	}
	s.data = next
	return nil
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建状态目录失败: %w", err)
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		defer dir.Close()
		_ = dir.Sync()
	}
	return nil
}
