package main

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func TestShortEnvID(t *testing.T) {
	if got := shortEnvID("12345678-1234-1234-1234-123456789abc"); got != "12345678" {
		t.Fatalf("expected short env ID to use the first UUID segment, got %q", got)
	}
	if got := shortEnvID("short"); got != "short" {
		t.Fatalf("expected short non-uuid ID to stay unchanged, got %q", got)
	}
}

func TestFilterEnvCompletionsIncludesNamesShortIDsAndUUIDs(t *testing.T) {
	alpha := "alpha"
	created1 := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	created2 := time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339)
	envs := []platform.Environment{
		{ID: "12345678-1234-1234-1234-123456789abc", Name: &alpha, CreatedAt: created1},
		{ID: "87654321-1234-1234-1234-123456789abc", CreatedAt: created2},
	}

	got := filterEnvCompletions(envs, "")
	want := []string{
		"alpha\t12345678-1234-1234-1234-123456789abc " + timeAgo(created1),
		"12345678\t12345678-1234-1234-1234-123456789abc alpha " + timeAgo(created1),
		"12345678-1234-1234-1234-123456789abc\talpha " + timeAgo(created1),
		"87654321\t87654321-1234-1234-1234-123456789abc " + timeAgo(created2),
		"87654321-1234-1234-1234-123456789abc\t" + timeAgo(created2),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected completions:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestFilterEnvCompletionsMatchesShortIDPrefix(t *testing.T) {
	alpha := "alpha"
	created := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	envs := []platform.Environment{
		{ID: "12345678-1234-1234-1234-123456789abc", Name: &alpha, CreatedAt: created},
	}

	got := filterEnvCompletions(envs, "1234")
	want := []string{
		"12345678\t12345678-1234-1234-1234-123456789abc alpha " + timeAgo(created),
		"12345678-1234-1234-1234-123456789abc\talpha " + timeAgo(created),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected completions for short ID prefix:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestResolveEnvIDFromListPrefersExactNameThenShortID(t *testing.T) {
	alpha := "alpha"
	envs := []platform.Environment{
		{ID: "12345678-1234-1234-1234-123456789abc", Name: &alpha},
	}

	id, err := resolveEnvIDFromList(envs, "alpha")
	if err != nil {
		t.Fatalf("resolve by name failed: %v", err)
	}
	if id != envs[0].ID {
		t.Fatalf("expected %q, got %q", envs[0].ID, id)
	}

	id, err = resolveEnvIDFromList(envs, "12345678")
	if err != nil {
		t.Fatalf("resolve by short ID failed: %v", err)
	}
	if id != envs[0].ID {
		t.Fatalf("expected %q, got %q", envs[0].ID, id)
	}
}

func TestResolveEnvIDFromListRejectsAmbiguousShortID(t *testing.T) {
	envs := []platform.Environment{
		{ID: "12345678-1234-1234-1234-123456789abc"},
		{ID: "12345678-9999-1234-1234-123456789abc"},
	}

	_, err := resolveEnvIDFromList(envs, "12345678")
	if err == nil {
		t.Fatal("expected ambiguous short ID to fail")
	}
	if !strings.Contains(err.Error(), "matched multiple IDs") {
		t.Fatalf("expected ambiguous ID error, got %v", err)
	}
}

func TestEnvCreateDefaultsToWaiting(t *testing.T) {
	cmd := envCreateCmd()

	followFlag := cmd.Flags().Lookup("follow")
	if followFlag == nil {
		t.Fatal("expected create command to expose --follow")
	}
	if followFlag.DefValue != "true" {
		t.Fatalf("expected --follow default true, got %q", followFlag.DefValue)
	}

	noWaitFlag := cmd.Flags().Lookup("no-wait")
	if noWaitFlag == nil {
		t.Fatal("expected create command to expose --no-wait")
	}
	if noWaitFlag.DefValue != "false" {
		t.Fatalf("expected --no-wait default false, got %q", noWaitFlag.DefValue)
	}

	if flag := cmd.Flags().Lookup("write-preset"); flag == nil {
		t.Fatal("expected create command to expose --write-preset")
	}
	if flag := cmd.Flags().Lookup("save-preset"); flag == nil {
		t.Fatal("expected create command to expose --save-preset")
	}
}

func TestShellCmdCompletionUsesEnvironmentRefs(t *testing.T) {
	alpha := "alpha"
	created1 := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	created2 := time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339)
	orig := listEnvironmentsForCompletion
	listEnvironmentsForCompletion = func(cmd *cobra.Command) ([]platform.Environment, error) {
		return []platform.Environment{
			{ID: "f062947a-60e2-405c-b89d-5f48b493d8fb", Name: &alpha, CreatedAt: created1},
			{ID: "f8396bb0-18b4-42a0-8151-2dd2b41cd41f", CreatedAt: created2},
		}, nil
	}
	defer func() { listEnvironmentsForCompletion = orig }()

	cmd := shellCmd()
	got, directive := cmd.ValidArgsFunction(cmd, nil, "f")
	want := []string{
		"f062947a\tf062947a-60e2-405c-b89d-5f48b493d8fb alpha " + timeAgo(created1),
		"f062947a-60e2-405c-b89d-5f48b493d8fb\talpha " + timeAgo(created1),
		"f8396bb0\tf8396bb0-18b4-42a0-8151-2dd2b41cd41f " + timeAgo(created2),
		"f8396bb0-18b4-42a0-8151-2dd2b41cd41f\t" + timeAgo(created2),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ssh completions:\nwant %#v\ngot  %#v", want, got)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("expected no-file completion directive, got %v", directive)
	}
}

func TestPrintEnvListEntriesUsesUnifiedBlockLayout(t *testing.T) {
	alpha := "alpha"
	network := "project-alpha"
	envs := []platform.Environment{
		{
			ID:            "12345678-1234-1234-1234-123456789abc",
			Name:          &alpha,
			State:         "running",
			Type:          "sandbox",
			CPUMillicores: 2000,
			MemoryMB:      4096,
			CreatedAt:     time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
			Network:       &network,
		},
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	printEnvListEntries(envs)

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	got := string(output)
	if !strings.Contains(got, "alpha [12345678]  running") {
		t.Fatalf("expected unified header, got %q", got)
	}
	if !strings.Contains(got, "sandbox  2000m/4096MB  ttl --") {
		t.Fatalf("expected detail line, got %q", got)
	}
	if !strings.Contains(got, "network: project-alpha") {
		t.Fatalf("expected network line, got %q", got)
	}
	if !strings.Contains(got, "connect: cw shell 12345678") {
		t.Fatalf("expected connect hint, got %q", got)
	}
}

func TestPrintEnvListEntriesShowsDeletingStateAndDeadline(t *testing.T) {
	alpha := "alpha"
	deletingAt := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	envs := []platform.Environment{
		{
			ID:                 "12345678-1234-1234-1234-123456789abc",
			Name:               &alpha,
			State:              "running",
			Type:               "sandbox",
			CPUMillicores:      2000,
			MemoryMB:           4096,
			CreatedAt:          time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
			DeletionGraceUntil: &deletingAt,
		},
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	printEnvListEntries(envs)

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	got := string(output)
	if !strings.Contains(got, "alpha [12345678]  deleting") {
		t.Fatalf("expected deleting header, got %q", got)
	}
	if !strings.Contains(got, "deleting at: "+deletingAt) {
		t.Fatalf("expected deleting deadline, got %q", got)
	}
}

func TestEnvironmentStateLabelShowsDeletingDuringGracePeriod(t *testing.T) {
	deletingAt := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	env := platform.Environment{State: "running", DeletionGraceUntil: &deletingAt}
	if got := environmentStateLabel(env); !strings.Contains(got, "deleting") {
		t.Fatalf("expected deleting state label, got %q", got)
	}
}

func TestEnvSSHRefUsesShortIDForRunningSandboxes(t *testing.T) {
	env := platform.Environment{
		ID:    "12345678-1234-1234-1234-123456789abc",
		Type:  "sandbox",
		State: "running",
	}
	if got := envSSHRef(env); got != "12345678" {
		t.Fatalf("expected running sandbox ssh ref to use short ID, got %q", got)
	}

	env.State = "stopped"
	if got := envSSHRef(env); got != "--" {
		t.Fatalf("expected stopped sandbox ssh ref to be unavailable, got %q", got)
	}
}

func TestRequestHasAgentUsesAgentsList(t *testing.T) {
	req := &platform.CreateEnvironmentRequest{
		Agents: []platform.SetupAgent{{Type: "claude-code"}, {Type: "codex"}},
	}
	if !requestHasAgent(req, "claude-code") {
		t.Fatal("expected claude-code to be detected from agents list")
	}
	if !requestHasAgent(req, "codex") {
		t.Fatal("expected codex to be detected from agents list")
	}
	if requestHasAgent(req, "aider") {
		t.Fatal("did not expect aider to be detected")
	}
}

func TestEnvTTLString(t *testing.T) {
	future := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	env := platform.Environment{ShutdownAt: &future}
	if got := envTTLString(env); got == "--" || got == "expired" {
		t.Fatalf("expected future shutdown time to produce a remaining TTL, got %q", got)
	}

	past := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	env.ShutdownAt = &past
	if got := envTTLString(env); got != "expired" {
		t.Fatalf("expected past shutdown time to be expired, got %q", got)
	}
}
