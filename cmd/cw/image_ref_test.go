package main

import "testing"

func TestExpandImageRef(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Fully qualified — pass through.
		{"docker.io/library/alpine:3.19", "docker.io/library/alpine:3.19"},
		{"ghcr.io/foo/bar:v1", "ghcr.io/foo/bar:v1"},
		{"registry.example.com/img", "registry.example.com/img"},

		// Codewire image shorthand.
		{"full", "ghcr.io/codewiresh/full:latest"},
		{"full:v2", "ghcr.io/codewiresh/full:v2"},
		{"base", "ghcr.io/codewiresh/base:latest"},

		// Bare name → Docker Hub official.
		{"alpine", "docker.io/library/alpine:latest"},
		{"alpine:3.19", "docker.io/library/alpine:3.19"},
		{"ubuntu", "docker.io/library/ubuntu:latest"},
		{"python:3.12-slim", "docker.io/library/python:3.12-slim"},

		// user/repo → Docker Hub user image.
		{"myuser/myimage", "docker.io/myuser/myimage:latest"},
		{"myuser/myimage:v1", "docker.io/myuser/myimage:v1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := expandImageRef(tt.input)
			if got != tt.want {
				t.Errorf("expandImageRef(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
