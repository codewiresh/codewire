package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildEnvStripsClaudeCode(t *testing.T) {
	t.Setenv("CLAUDECODE", "1")
	env := buildEnv(nil)
	for _, e := range env {
		if strings.HasPrefix(e, "CLAUDECODE=") {
			t.Fatalf("CLAUDECODE should be stripped, got: %s", e)
		}
	}
}

func TestBuildEnvPreservesOtherVars(t *testing.T) {
	t.Setenv("CW_TEST_VAR", "keep-me")
	env := buildEnv(nil)
	found := false
	for _, e := range env {
		if e == "CW_TEST_VAR=keep-me" {
			found = true
		}
	}
	if !found {
		t.Fatal("CW_TEST_VAR should be preserved")
	}
}

func TestBuildEnvAppliesOverrides(t *testing.T) {
	env := buildEnv([]string{"MY_VAR=hello"})
	found := false
	for _, e := range env {
		if e == "MY_VAR=hello" {
			found = true
		}
	}
	if !found {
		t.Fatal("MY_VAR=hello should be present")
	}
}

func TestBuildEnvDefaultsTerminalCapabilitiesWhenMissing(t *testing.T) {
	t.Setenv("TERM", "")
	t.Setenv("COLORTERM", "")

	env := buildEnv(nil)

	term, ok := envValue(env, "TERM")
	if !ok || term != "xterm-256color" {
		t.Fatalf("TERM = %q, %v; want xterm-256color", term, ok)
	}

	colorTerm, ok := envValue(env, "COLORTERM")
	if !ok || colorTerm != "truecolor" {
		t.Fatalf("COLORTERM = %q, %v; want truecolor", colorTerm, ok)
	}
}

func TestBuildEnvReplacesDumbTERM(t *testing.T) {
	t.Setenv("TERM", "dumb")
	t.Setenv("COLORTERM", "")

	env := buildEnv(nil)

	term, ok := envValue(env, "TERM")
	if !ok || term != "xterm-256color" {
		t.Fatalf("TERM = %q, %v; want xterm-256color", term, ok)
	}
}

func TestBuildEnvPreservesExplicitTerminalCapabilities(t *testing.T) {
	t.Setenv("TERM", "screen-256color")
	t.Setenv("COLORTERM", "24bit")

	env := buildEnv(nil)

	term, ok := envValue(env, "TERM")
	if !ok || term != "screen-256color" {
		t.Fatalf("TERM = %q, %v; want screen-256color", term, ok)
	}

	colorTerm, ok := envValue(env, "COLORTERM")
	if !ok || colorTerm != "24bit" {
		t.Fatalf("COLORTERM = %q, %v; want 24bit", colorTerm, ok)
	}
}

func TestBuildEnvStripsClaudeCodeEntrypoint(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	env := buildEnv(nil)
	for _, e := range env {
		if strings.HasPrefix(e, "CLAUDE_CODE_ENTRYPOINT=") {
			t.Fatalf("CLAUDE_CODE_ENTRYPOINT should be stripped, got: %s", e)
		}
	}
}

func TestBuildEnvOverridesExisting(t *testing.T) {
	t.Setenv("CW_TEST_VAR", "original")
	env := buildEnv([]string{"CW_TEST_VAR=override"})
	for _, e := range env {
		if e == "CW_TEST_VAR=original" {
			t.Fatal("override not applied")
		}
	}
}

func TestBuildEnvLoadsCodewireWorkspaceEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".codewire")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "environment.json"), []byte(`{"CLAUDE_CODE_OAUTH_TOKEN":"token-123","ANTHROPIC_AUTH_TOKEN":"token-123"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	env := buildEnv(nil)
	foundClaude := false
	foundAnthropic := false
	for _, e := range env {
		if e == "CLAUDE_CODE_OAUTH_TOKEN=token-123" {
			foundClaude = true
		}
		if e == "ANTHROPIC_AUTH_TOKEN=token-123" {
			foundAnthropic = true
		}
	}
	if !foundClaude || !foundAnthropic {
		t.Fatalf("expected codewire env vars to be loaded, got %v", env)
	}
}

func TestCaptureResultStripsOSCQueries(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "output.log")
	content := "prefix\x1b]11;?\x1b\\\x1b[6n\nLogged in using ChatGPT\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := captureResult(logPath, 10)
	if got == nil {
		t.Fatal("captureResult returned nil")
	}
	want := "prefix\nLogged in using ChatGPT"
	if *got != want {
		t.Fatalf("captureResult = %q, want %q", *got, want)
	}
}

func TestStatusPreviewCollapsesWhitespaceAndTruncates(t *testing.T) {
	raw := " first line \n\n second\tline " + strings.Repeat("x", statusPreviewLimit)

	got := statusPreview(raw)
	if !strings.HasPrefix(got, "first line second line ") {
		t.Fatalf("statusPreview prefix = %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("statusPreview should truncate with ellipsis, got %q", got)
	}
	if len([]rune(got)) != statusPreviewLimit+3 {
		t.Fatalf("statusPreview length = %d, want %d", len([]rune(got)), statusPreviewLimit+3)
	}
}

func TestStatusLastEventBlobPrefersCapturedResult(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "output.log")
	if err := os.WriteFile(logPath, []byte("log file content\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result := "\x1b[31mhello\x1b[0m\nworld"

	session := &Session{
		Meta:    SessionMeta{Result: &result},
		logPath: logPath,
	}

	got, err := statusLastEventBlob(session)
	if err != nil {
		t.Fatalf("statusLastEventBlob: %v", err)
	}
	if got != "hello\nworld" {
		t.Fatalf("statusLastEventBlob = %q, want %q", got, "hello\nworld")
	}
}

func TestSessionManagerReportTaskRecordsAndPublishes(t *testing.T) {
	dir := t.TempDir()
	sm, err := NewSessionManager(dir)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	id, err := sm.Launch([]string{"sleep", "60"}, dir, nil, nil, "")
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	defer func() {
		_ = sm.Kill(id)
	}()

	if err := sm.SetName(id, "planner"); err != nil {
		t.Fatalf("SetName: %v", err)
	}

	sub := sm.Subscriptions.Subscribe(&id, nil, []EventType{EventTaskReport})
	defer sm.Subscriptions.Unsubscribe(sub.ID)

	var forwarded struct {
		sessionID   uint32
		sessionName string
		eventID     string
		summary     string
		state       string
		ts          time.Time
	}
	sm.SetTaskReportForward(func(sessionID uint32, sessionName, eventID, summary, state string, ts time.Time) {
		forwarded.sessionID = sessionID
		forwarded.sessionName = sessionName
		forwarded.eventID = eventID
		forwarded.summary = summary
		forwarded.state = state
		forwarded.ts = ts
	})

	if err := sm.ReportTask(id, "   indexing   relay   tests   ", " Working "); err != nil {
		t.Fatalf("ReportTask: %v", err)
	}

	select {
	case se := <-sub.Ch:
		if se.SessionID != id {
			t.Fatalf("SessionID = %d, want %d", se.SessionID, id)
		}
		if se.Event.Type != EventTaskReport {
			t.Fatalf("event type = %s", se.Event.Type)
		}
		var data TaskReportData
		if err := json.Unmarshal(se.Event.Data, &data); err != nil {
			t.Fatalf("unmarshal task report event: %v", err)
		}
		if data.EventID == "" {
			t.Fatal("expected non-empty event id")
		}
		if data.Summary != "indexing relay tests" {
			t.Fatalf("summary = %q", data.Summary)
		}
		if data.State != "working" {
			t.Fatalf("state = %q", data.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for task report subscription event")
	}

	eventsPath := filepath.Join(dir, "sessions", fmt.Sprintf("%d", id), "events.jsonl")
	events, err := ReadEventLog(eventsPath)
	if err != nil {
		t.Fatalf("ReadEventLog: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(events))
	}
	last := events[len(events)-1]
	if last.Type != EventTaskReport {
		t.Fatalf("last event type = %s, want %s", last.Type, EventTaskReport)
	}

	var persisted TaskReportData
	if err := json.Unmarshal(last.Data, &persisted); err != nil {
		t.Fatalf("unmarshal persisted task report: %v", err)
	}
	if persisted.Summary != "indexing relay tests" {
		t.Fatalf("persisted summary = %q", persisted.Summary)
	}
	if persisted.State != "working" {
		t.Fatalf("persisted state = %q", persisted.State)
	}

	if forwarded.sessionID != id {
		t.Fatalf("forwarded session id = %d, want %d", forwarded.sessionID, id)
	}
	if forwarded.sessionName != "planner" {
		t.Fatalf("forwarded session name = %q", forwarded.sessionName)
	}
	if forwarded.eventID == "" {
		t.Fatal("expected forwarded event id")
	}
	if forwarded.summary != "indexing relay tests" {
		t.Fatalf("forwarded summary = %q", forwarded.summary)
	}
	if forwarded.state != "working" {
		t.Fatalf("forwarded state = %q", forwarded.state)
	}
	if forwarded.ts.IsZero() {
		t.Fatal("expected forwarded timestamp")
	}
}

func TestSessionManagerReportTaskValidation(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	if err := sm.ReportTask(42, "hello", "working"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}

	id, err := sm.Launch([]string{"sleep", "60"}, t.TempDir(), nil, nil, "")
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	defer func() {
		_ = sm.Kill(id)
	}()

	tests := []struct {
		name    string
		summary string
		state   string
		wantErr string
	}{
		{name: "empty summary", summary: "   ", state: "working", wantErr: "task summary is required"},
		{name: "invalid state", summary: "building", state: "pending", wantErr: "invalid task state"},
		{name: "too long", summary: strings.Repeat("a", maxTaskSummaryLen+1), state: "working", wantErr: "exceeds"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sm.ReportTask(id, tc.summary, tc.state)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ReportTask error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
