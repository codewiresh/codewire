package main

import (
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
	envs := []platform.Environment{
		{ID: "12345678-1234-1234-1234-123456789abc", Name: &alpha},
		{ID: "87654321-1234-1234-1234-123456789abc"},
	}

	got := filterEnvCompletions(envs, "")
	want := []string{
		"alpha",
		"12345678",
		"12345678-1234-1234-1234-123456789abc",
		"87654321",
		"87654321-1234-1234-1234-123456789abc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected completions:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestFilterEnvCompletionsMatchesShortIDPrefix(t *testing.T) {
	alpha := "alpha"
	envs := []platform.Environment{
		{ID: "12345678-1234-1234-1234-123456789abc", Name: &alpha},
	}

	got := filterEnvCompletions(envs, "1234")
	want := []string{
		"12345678",
		"12345678-1234-1234-1234-123456789abc",
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
}

func TestSSHCmdCompletionUsesEnvironmentRefs(t *testing.T) {
	alpha := "alpha"
	orig := listEnvironmentsForCompletion
	listEnvironmentsForCompletion = func(cmd *cobra.Command) ([]platform.Environment, error) {
		return []platform.Environment{
			{ID: "f062947a-60e2-405c-b89d-5f48b493d8fb", Name: &alpha},
			{ID: "f8396bb0-18b4-42a0-8151-2dd2b41cd41f"},
		}, nil
	}
	defer func() { listEnvironmentsForCompletion = orig }()

	cmd := sshCmd()
	got, directive := cmd.ValidArgsFunction(cmd, nil, "f")
	want := []string{
		"f062947a",
		"f062947a-60e2-405c-b89d-5f48b493d8fb",
		"f8396bb0",
		"f8396bb0-18b4-42a0-8151-2dd2b41cd41f",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ssh completions:\nwant %#v\ngot  %#v", want, got)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("expected no-file completion directive, got %v", directive)
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
