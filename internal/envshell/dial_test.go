package envshell

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeShell is a minimal Shell for testing dial logic.
type fakeShell struct {
	closed    bool
	closeCalls int
}

func (s *fakeShell) Read(p []byte) (int, error)     { return 0, nil }
func (s *fakeShell) Write(p []byte) (int, error)    { return len(p), nil }
func (s *fakeShell) Resize(cols, rows uint16) error  { return nil }
func (s *fakeShell) Close() error {
	s.closeCalls++
	s.closed = true
	return nil
}

// fakeDialer records call counts and returns configured results.
type fakeDialer struct {
	wgCalls   int
	wsCalls   int
	wgResult  Shell
	wgErr     error
	wsResult  Shell
	wsErr     error
}

func (d *fakeDialer) DialWireGuard(_ context.Context, _ DialOptions) (Shell, error) {
	d.wgCalls++
	return d.wgResult, d.wgErr
}

func (d *fakeDialer) DialWebSocket(_ context.Context, _ DialOptions) (Shell, error) {
	d.wsCalls++
	return d.wsResult, d.wsErr
}

func TestDial_WireGuardSucceeds(t *testing.T) {
	wgShell := &fakeShell{}
	fd := &fakeDialer{wgResult: wgShell}

	got, err := dialWith(context.Background(), fd, DialOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wgShell {
		t.Error("expected WG shell")
	}
	if fd.wgCalls != 1 {
		t.Errorf("WG should be called once, got %d", fd.wgCalls)
	}
	if fd.wsCalls != 0 {
		t.Errorf("WS should not be called, got %d", fd.wsCalls)
	}
}

func TestDial_WireGuardTimeout_FallsBackToWS(t *testing.T) {
	wsShell := &fakeShell{}
	fd := &fakeDialer{
		wgErr:    errors.New("timeout waiting for agent peer info"),
		wsResult: wsShell,
	}

	got, err := dialWith(context.Background(), fd, DialOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wsShell {
		t.Error("expected WS shell")
	}
	if fd.wgCalls != 1 {
		t.Errorf("WG should be called once, got %d", fd.wgCalls)
	}
	if fd.wsCalls != 1 {
		t.Errorf("WS should be called once, got %d", fd.wsCalls)
	}
}

func TestDial_SSHHandshakeFails_NoFallback(t *testing.T) {
	fd := &fakeDialer{
		wgErr: errors.New("ssh handshake: key mismatch"),
	}

	_, err := dialWith(context.Background(), fd, DialOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ssh handshake") {
		t.Errorf("error should contain 'ssh handshake', got: %v", err)
	}
	if fd.wsCalls != 0 {
		t.Errorf("WS should NOT be called on ssh handshake failure, got %d", fd.wsCalls)
	}
}

func TestDial_BothFail_CombinedError(t *testing.T) {
	fd := &fakeDialer{
		wgErr: errors.New("coordinator connect: refused"),
		wsErr: errors.New("ssh proxy connect: 502"),
	}

	_, err := dialWith(context.Background(), fd, DialOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "coordinator connect") {
		t.Errorf("combined error should contain WG message, got: %s", msg)
	}
	if !strings.Contains(msg, "ssh proxy connect") {
		t.Errorf("combined error should contain WS message, got: %s", msg)
	}
}

func TestDial_PreferWS_SkipsWG(t *testing.T) {
	wsShell := &fakeShell{}
	fd := &fakeDialer{wsResult: wsShell}

	got, err := dialWith(context.Background(), fd, DialOptions{PreferWS: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wsShell {
		t.Error("expected WS shell")
	}
	if fd.wgCalls != 0 {
		t.Errorf("WG should not have been called, got %d", fd.wgCalls)
	}
}

func TestShell_Close_Idempotent(t *testing.T) {
	s := &fakeShell{}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close should not error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close should not error: %v", err)
	}
	if s.closeCalls != 2 {
		t.Errorf("expected 2 close calls, got %d", s.closeCalls)
	}
}

func TestDial_WireGuardCoordinatorFails_FallsBackToWS(t *testing.T) {
	wsShell := &fakeShell{}
	fd := &fakeDialer{
		wgErr:    errors.New("coordinator connect: connection refused"),
		wsResult: wsShell,
	}

	got, err := dialWith(context.Background(), fd, DialOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wsShell {
		t.Error("expected WS shell after coordinator failure")
	}
	if fd.wgCalls != 1 {
		t.Errorf("WG should be called once, got %d", fd.wgCalls)
	}
	if fd.wsCalls != 1 {
		t.Errorf("WS should be called once, got %d", fd.wsCalls)
	}
}
