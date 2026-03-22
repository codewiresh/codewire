package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZshCompletionInstallCandidatesPreferSiteFunctionsWithoutOhMyZsh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ZSH", "")

	candidates := zshCompletionInstallCandidates()
	if len(candidates) < 3 {
		t.Fatalf("expected several zsh completion candidates, got %#v", candidates)
	}

	if candidates[0].dir != "/usr/local/share/zsh/site-functions" {
		t.Fatalf("expected /usr/local/share/zsh/site-functions first, got %q", candidates[0].dir)
	}

	last := candidates[len(candidates)-1]
	if last.dir != filepath.Join(home, ".zfunc") {
		t.Fatalf("expected ~/.zfunc fallback last, got %q", last.dir)
	}
	if last.autoload {
		t.Fatalf("expected ~/.zfunc fallback to require shell config")
	}
}

func TestZshCompletionInstallCandidatesUseConfiguredOhMyZsh(t *testing.T) {
	home := t.TempDir()
	omz := filepath.Join(home, ".oh-my-zsh")
	t.Setenv("HOME", home)
	t.Setenv("ZSH", omz)

	candidates := zshCompletionInstallCandidates()
	want := filepath.Join(omz, "completions")
	found := false
	for _, candidate := range candidates {
		if candidate.dir == want {
			found = true
			if !candidate.autoload {
				t.Fatalf("expected configured oh-my-zsh completions to be autoloaded")
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected configured oh-my-zsh completions dir %q in candidates %#v", want, candidates)
	}
}

func TestZshCompletionInstallCandidatesAvoidDuplicateDirs(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("HOME", temp)
	t.Setenv("ZSH", "")
	t.Setenv("PATH", os.Getenv("PATH"))

	candidates := zshCompletionInstallCandidates()
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		if seen[candidate.dir] {
			t.Fatalf("duplicate candidate dir %q in %#v", candidate.dir, candidates)
		}
		seen[candidate.dir] = true
	}
}
