package codewire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LocalService talks to local VMs managed by the `cw` CLI by shelling out to
// its JSON interface (`cw env --local <cmd> --output json`). It mirrors the
// environment surface as closely as possible so callers can swap
// `client.Environments` for `client.Local` with minimal changes.
//
// Requires the `cw` binary on PATH (or $CW_BIN pointing at it). No network
// calls — all operations run against the caller's host.
type LocalService struct {
	cwBin string
}

// LocalSpec is the JSON document accepted by `cw env --local create --spec -`. Its
// fields mirror codewire.yaml.
type LocalSpec struct {
	Preset             string            `json:"preset,omitempty"`
	Image              string            `json:"image,omitempty"`
	Install            string            `json:"install,omitempty"`
	Startup            string            `json:"startup,omitempty"`
	Env                map[string]string `json:"env,omitempty"`
	Ports              []LocalSpecPort   `json:"ports,omitempty"`
	Mounts             []LocalSpecMount  `json:"mounts,omitempty"`
	CPU                int               `json:"cpu,omitempty"`
	Memory             int               `json:"memory,omitempty"`
	Disk               int               `json:"disk,omitempty"`
	Agent              string            `json:"agent,omitempty"`
	SecretProject      string            `json:"secret_project,omitempty"`
	IncludeOrgSecrets  *bool             `json:"include_org_secrets,omitempty"`
	IncludeUserSecrets *bool             `json:"include_user_secrets,omitempty"`
}

// LocalSpecPort describes a single published port in a LocalSpec.
type LocalSpecPort struct {
	HostPort  int    `json:"host_port,omitempty"`
	GuestPort int    `json:"guest_port,omitempty"`
	Port      int    `json:"port,omitempty"`
	Label     string `json:"label,omitempty"`
}

// LocalSpecMount describes a single bind mount in a LocalSpec.
type LocalSpecMount struct {
	Source   string `json:"source"`
	Target   string `json:"target,omitempty"`
	Readonly bool   `json:"readonly,omitempty"`
}

// LocalCreateOptions configures backend selection and lifecycle flags passed
// through to `cw env --local create`.
type LocalCreateOptions struct {
	// Backend selects the runtime: "docker", "lima", etc. Required.
	Backend string
	// Name overrides the auto-derived instance name.
	Name string
	// Path is the project directory associated with the instance; defaults to
	// the caller's working directory.
	Path string
	// Wait blocks until the instance reports status "running".
	Wait bool
}

// LocalInstance represents a persisted local VM instance. Mirrors the JSON
// schema produced by `cw env --local list --output json` /
// `cw env --local info --output json`.
type LocalInstance struct {
	Name        string            `json:"name"`
	Backend     string            `json:"backend"`
	Status      string            `json:"status"`
	RuntimeName string            `json:"runtime_name"`
	RepoPath    string            `json:"repo_path"`
	Workdir     string            `json:"workdir"`
	Image       string            `json:"image,omitempty"`
	Preset      string            `json:"preset,omitempty"`
	Install     string            `json:"install,omitempty"`
	Startup     string            `json:"startup,omitempty"`
	Secrets     string            `json:"secrets,omitempty"`
	Agent       string            `json:"agent,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Ports       []LocalPort       `json:"ports,omitempty"`
	Mounts      []LocalMount      `json:"mounts,omitempty"`
	CPU         int               `json:"cpu,omitempty"`
	Memory      int               `json:"memory,omitempty"`
	Disk        int               `json:"disk,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	LastUsedAt  string            `json:"last_used_at,omitempty"`
	Lima        *LocalLimaInfo    `json:"lima,omitempty"`

	service *LocalService `json:"-"`
}

// LocalPort is a single forwarded port between host and VM.
type LocalPort struct {
	HostPort  int    `json:"host_port"`
	GuestPort int    `json:"guest_port"`
	Label     string `json:"label,omitempty"`
}

// LocalMount is a single bind mount.
type LocalMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Readonly bool   `json:"readonly,omitempty"`
}

// LocalLimaInfo carries Lima-specific metadata; present only when Backend == "lima".
type LocalLimaInfo struct {
	InstanceName string `json:"instance_name,omitempty"`
	MountType    string `json:"mount_type,omitempty"`
	VMType       string `json:"vm_type,omitempty"`
}

// LocalExecResult is the buffered result of a foreground `cw run`.
type LocalExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// LocalExecRequest describes a single exec call against a local instance.
type LocalExecRequest struct {
	Command []string
	// WorkingDir overrides the instance's default workdir.
	WorkingDir string
}

// newLocalService wires the service using the CW binary resolver. Called by
// the Codewire constructor.
func newLocalService() *LocalService {
	return &LocalService{}
}

// Bin returns the resolved path of the `cw` binary the service will invoke.
// Honors $CW_BIN, else the first `cw` on PATH. Returns a descriptive error
// when the binary is absent, so callers can give a good install hint.
func (s *LocalService) Bin() (string, error) {
	if s.cwBin != "" {
		return s.cwBin, nil
	}
	if override := strings.TrimSpace(os.Getenv("CW_BIN")); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("cw binary at CW_BIN=%s: %w", override, err)
		}
		s.cwBin = override
		return s.cwBin, nil
	}
	path, err := exec.LookPath("cw")
	if err != nil {
		return "", errors.New("cw CLI not found on PATH; install it from https://codewire.sh/install or set CW_BIN")
	}
	s.cwBin = path
	return s.cwBin, nil
}

// Create creates a new local instance from the given spec + options. Pipes the
// spec as JSON through `cw env --local create --spec - --output json`.
func (s *LocalService) Create(ctx context.Context, spec LocalSpec, opts LocalCreateOptions) (*LocalInstance, error) {
	if strings.TrimSpace(opts.Backend) == "" {
		return nil, errors.New("LocalCreateOptions.Backend is required")
	}
	bin, err := s.Bin()
	if err != nil {
		return nil, err
	}

	args := []string{"env", "--local", "create", "--output", "json", "--backend", opts.Backend, "--spec", "-"}
	if strings.TrimSpace(opts.Name) != "" {
		args = append(args, "--name", opts.Name)
	}
	if strings.TrimSpace(opts.Path) != "" {
		args = append(args, "--path", opts.Path)
	}

	specBytes, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("marshal spec: %w", err)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(specBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, cwSubprocessErr("cw env --local create", err, stderr.String())
	}

	var inst LocalInstance
	if err := json.Unmarshal(stdout.Bytes(), &inst); err != nil {
		return nil, fmt.Errorf("decode cw env --local create output: %w", err)
	}
	s.attach(&inst)

	if opts.Wait && !strings.EqualFold(inst.Status, "running") {
		if err := inst.WaitReady(ctx); err != nil {
			return &inst, err
		}
	}
	return &inst, nil
}

// Get retrieves a local instance by name.
func (s *LocalService) Get(ctx context.Context, name string) (*LocalInstance, error) {
	out, err := s.runJSON(ctx, "env", "--local", "info", "--output", "json", name)
	if err != nil {
		return nil, err
	}
	var inst LocalInstance
	if err := json.Unmarshal(out, &inst); err != nil {
		return nil, fmt.Errorf("decode cw env --local info: %w", err)
	}
	s.attach(&inst)
	return &inst, nil
}

// List returns all persisted local instances.
func (s *LocalService) List(ctx context.Context) ([]*LocalInstance, error) {
	out, err := s.runJSON(ctx, "env", "--local", "list", "--output", "json")
	if err != nil {
		return nil, err
	}
	var list []LocalInstance
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("decode cw env --local list: %w", err)
	}
	result := make([]*LocalInstance, len(list))
	for i := range list {
		inst := list[i]
		s.attach(&inst)
		result[i] = &inst
	}
	return result, nil
}

// Exec runs a buffered command inside the instance via
// `cw run --no-tty <name> -- ...`. A successful command returns captured
// stdout; a non-zero durable-session exit is returned as a subprocess error.
func (s *LocalService) Exec(ctx context.Context, name string, req LocalExecRequest) (*LocalExecResult, error) {
	if len(req.Command) == 0 {
		return nil, errors.New("exec command is required")
	}
	bin, err := s.Bin()
	if err != nil {
		return nil, err
	}
	args := []string{"run", "--no-tty", name}
	if strings.TrimSpace(req.WorkingDir) != "" {
		args = append(args, "--workdir", req.WorkingDir)
	}
	args = append(args, "--")
	args = append(args, req.Command...)

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, cwSubprocessErr("cw run", err, stderr.String())
	}
	return &LocalExecResult{
		ExitCode: 0,
		Stdout:   stdout.String(),
	}, nil
}

// Start starts a stopped local instance.
func (s *LocalService) Start(ctx context.Context, name string) error {
	_, err := s.runJSON(ctx, "env", "--local", "start", "--output", "json", name)
	return err
}

// Stop stops a running local instance.
func (s *LocalService) Stop(ctx context.Context, name string) error {
	_, err := s.runJSON(ctx, "env", "--local", "stop", "--output", "json", name)
	return err
}

// Remove deletes the local instance and all backend-specific artifacts.
func (s *LocalService) Remove(ctx context.Context, name string) error {
	_, err := s.runJSON(ctx, "env", "--local", "rm", "--output", "json", name)
	return err
}

// runJSON runs `cw <args...>` and returns the captured stdout bytes. Treats
// non-zero exit as an error carrying the subprocess stderr.
func (s *LocalService) runJSON(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := s.Bin()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, cwSubprocessErr("cw "+strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// attach wires service-dependent fields on a decoded instance.
func (s *LocalService) attach(inst *LocalInstance) {
	inst.service = s
}

// Exec runs a buffered command inside the instance. See LocalService.Exec.
func (i *LocalInstance) Exec(ctx context.Context, req LocalExecRequest) (*LocalExecResult, error) {
	return i.service.Exec(ctx, i.Name, req)
}

// Start starts a stopped instance.
func (i *LocalInstance) Start(ctx context.Context) error { return i.service.Start(ctx, i.Name) }

// Stop stops a running instance.
func (i *LocalInstance) Stop(ctx context.Context) error { return i.service.Stop(ctx, i.Name) }

// Remove deletes the instance.
func (i *LocalInstance) Remove(ctx context.Context) error { return i.service.Remove(ctx, i.Name) }

// WaitReady polls `cw env --local info --output json` until Status == "running"
// or context is cancelled. Returns an error if the instance reports a terminal
// failure status.
func (i *LocalInstance) WaitReady(ctx context.Context) error {
	for {
		fresh, err := i.service.Get(ctx, i.Name)
		if err != nil {
			return err
		}
		i.Status = fresh.Status
		switch strings.ToLower(fresh.Status) {
		case "running":
			return nil
		case "error", "missing":
			return fmt.Errorf("local instance %s entered state %s", i.Name, fresh.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

// cwSubprocessErr turns a non-zero cw-subprocess exit into a descriptive error
// that includes the captured stderr.
func cwSubprocessErr(prefix string, runErr error, stderr string) error {
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		return fmt.Errorf("%s: %w", prefix, runErr)
	}
	return fmt.Errorf("%s: %w: %s", prefix, runErr, msg)
}
