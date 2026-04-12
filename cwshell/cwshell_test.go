//go:build cgotest

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/codewiresh/codewire/internal/envshell"
)

func withFakeDial(f func(ctx context.Context, opts envshell.DialOptions) (envshell.Shell, error), fn func()) {
	orig := dialForTest
	dialForTest = f
	defer func() { dialForTest = orig }()
	fn()
}

func TestDoDial_ReturnsHandle(t *testing.T) {
	shell := &stubShell{readCh: make(chan []byte, 1)}
	withFakeDial(
		func(context.Context, envshell.DialOptions) (envshell.Shell, error) {
			return shell, nil
		},
		func() {
			id, err := doDial(`{"server_url":"https://x","token":"t","org_id":"o","env_id":"e","cols":80,"rows":24}`)
			if err != nil {
				t.Fatal(err)
			}
			if id <= 0 {
				t.Fatalf("expected positive id, got %d", id)
			}
			h := lookupHandle(id)
			if h == nil {
				t.Error("handle not registered")
			}
			doClose(id)
		},
	)
}

func TestDoDial_PropagatesError(t *testing.T) {
	withFakeDial(
		func(context.Context, envshell.DialOptions) (envshell.Shell, error) {
			return nil, errors.New("dial failed")
		},
		func() {
			_, err := doDial(`{"server_url":"https://x","token":"t","org_id":"o","env_id":"e","cols":80,"rows":24}`)
			if err == nil || err.Error() != "dial failed" {
				t.Fatalf("wrong error: %v", err)
			}
		},
	)
}

func TestDoDial_InvalidJSON(t *testing.T) {
	_, err := doDial(`{invalid`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDoRead_InvalidHandle(t *testing.T) {
	buf := make([]byte, 10)
	_, err := doRead(999999, buf)
	if err == nil {
		t.Error("expected error for invalid handle")
	}
}

func TestDoClose_RemovesHandle(t *testing.T) {
	shell := &stubShell{readCh: make(chan []byte, 1)}
	_, cancel := context.WithCancel(context.Background())
	id := registerHandle(shell, cancel)
	doClose(id)
	if lookupHandle(id) != nil {
		t.Error("handle not removed")
	}
	shell.mu.Lock()
	closed := shell.closed
	shell.mu.Unlock()
	if !closed {
		t.Error("shell not closed")
	}
}

func TestDoClose_Idempotent(t *testing.T) {
	shell := &stubShell{readCh: make(chan []byte, 1)}
	_, cancel := context.WithCancel(context.Background())
	id := registerHandle(shell, cancel)
	doClose(id)
	doClose(id) // should not panic
}
