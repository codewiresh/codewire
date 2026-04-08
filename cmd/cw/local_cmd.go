package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

const localWorkspacePath = "/workspace"

var (
	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return cwconfig.LoadLocalInstancesConfig(dataDir())
	}
	saveLocalInstancesForCLI = func(cfg *cwconfig.LocalInstancesConfig) error {
		return cwconfig.SaveLocalInstancesConfig(dataDir(), cfg)
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	// localRunCommandStream runs a command with stdout/stderr streamed to os.Stderr.
	localRunCommandStream = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	localLookPath      = exec.LookPath
	localPromptConfirm = promptConfirm
	localNow           = func() time.Time { return time.Now().UTC() }
	localGetwd         = os.Getwd
	localUserHomeDir   = os.UserHomeDir
	localOsStat        = os.Stat
)

type localCreateOptions struct {
	Backend       string
	Name          string
	Path          string
	File          string
	Preset        string
	Image         string
	Install       string
	Startup       string
	Agent         string
	Secrets       string
	EnvVars       []string
	CPU           int
	Memory        int
	Disk          int
	NoOrgSecrets  bool
	NoUserSecrets bool
}

func localParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local",
		Short: "Manage local runtime instances",
	}
	cmd.AddCommand(localCreateCmd())
	cmd.AddCommand(localStartCmd())
	cmd.AddCommand(localStopCmd())
	cmd.AddCommand(localRmCmd())
	cmd.AddCommand(localListCmd())
	cmd.AddCommand(localInfoCmd())
	cmd.AddCommand(localPortsCmd())
	return cmd
}

func localCreateCmd() *cobra.Command {
	var opts localCreateOptions

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a local runtime instance from codewire.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(opts.Backend) == "" {
				return fmt.Errorf("--backend is required")
			}

			instance, err := prepareLocalInstance(opts)
			if err != nil {
				return err
			}

			state, err := loadLocalInstancesForCLI()
			if err != nil {
				return err
			}
			if _, exists := state.Instances[instance.Name]; exists {
				return fmt.Errorf("local instance %q already exists", instance.Name)
			}

			if err := createLocalRuntime(&instance); err != nil {
				return err
			}

			state.Instances[instance.Name] = instance
			if err := saveLocalInstancesForCLI(state); err != nil {
				return fmt.Errorf("save local instance state: %w", err)
			}

			successMsg("Local instance created: %s.", instance.Name)
			fmt.Printf("%-10s %s\n", bold("Backend:"), instance.Backend)
			fmt.Printf("%-10s %s\n", bold("Runtime:"), instance.RuntimeName)
			fmt.Printf("%-10s %s\n", bold("Image:"), instance.Image)
			fmt.Printf("%-10s %s\n", bold("Repo:"), instance.RepoPath)
			fmt.Printf("%-10s %s\n", bold("Mount:"), localWorkspacePath)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Backend, "backend", "", "Local runtime backend (docker, lima, incus, or experimental firecracker)")
	cmd.Flags().StringVar(&opts.Name, "name", "", "Instance name (defaults to the repo directory name)")
	cmd.Flags().StringVar(&opts.Path, "path", ".", "Project directory to associate with the local instance")
	cmd.Flags().StringVar(&opts.File, "file", "codewire.yaml", "Preset file path, relative to --path when not absolute")
	cmd.Flags().StringVar(&opts.Preset, "preset", "", "Preset slug override")
	cmd.Flags().StringVar(&opts.Image, "image", "", "Container image override")
	cmd.Flags().StringVar(&opts.Install, "install", "", "Install command override")
	cmd.Flags().StringVar(&opts.Startup, "startup", "", "Startup script override")
	cmd.Flags().StringVar(&opts.Agent, "agent", "", "AI agent override")
	cmd.Flags().StringVar(&opts.Secrets, "secrets", "", "Secret project override")
	cmd.Flags().StringSliceVar(&opts.EnvVars, "env", nil, "Env vars (KEY=val)")
	cmd.Flags().IntVar(&opts.CPU, "cpu", 0, "CPU in millicores override")
	cmd.Flags().IntVar(&opts.Memory, "memory", 0, "Memory in MB override")
	cmd.Flags().IntVar(&opts.Disk, "disk", 0, "Disk in GB override")
	cmd.Flags().BoolVar(&opts.NoOrgSecrets, "no-org-secrets", false, "Don't inject org-level secrets")
	cmd.Flags().BoolVar(&opts.NoUserSecrets, "no-user-secrets", false, "Don't inject user-level secrets")
	return cmd
}

func localStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [name]",
		Short: "Start an existing local runtime instance",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := resolveLocalInstanceArg(optionalArg(args))
			if err != nil {
				return err
			}
			if err := startLocalRuntime(instance); err != nil {
				return err
			}
			successMsg("Local instance started: %s.", instance.Name)
			return nil
		},
	}
}

func localStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop [name]",
		Short: "Stop an existing local runtime instance",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := resolveLocalInstanceArg(optionalArg(args))
			if err != nil {
				return err
			}
			if err := stopLocalRuntime(instance); err != nil {
				return err
			}
			successMsg("Local instance stopped: %s.", instance.Name)
			return nil
		},
	}
}

func localRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm [name]",
		Aliases: []string{"delete"},
		Short:   "Delete an existing local runtime instance",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := loadLocalInstancesForCLI()
			if err != nil {
				return err
			}

			key, instance, err := resolveLocalInstance(state, optionalArg(args))
			if err != nil {
				return err
			}
			if err := deleteLocalRuntime(instance); err != nil {
				return err
			}
			delete(state.Instances, key)
			if err := saveLocalInstancesForCLI(state); err != nil {
				return fmt.Errorf("save local instance state: %w", err)
			}
			successMsg("Local instance removed: %s.", instance.Name)
			return nil
		},
	}
}

func localListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List local runtime instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := loadLocalInstancesForCLI()
			if err != nil {
				return err
			}
			if len(state.Instances) == 0 {
				fmt.Println("No local instances found.")
				return nil
			}

			names := sortedLocalInstanceNames(state)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "NAME", "BACKEND", "STATE", "PORTS", "IMAGE", "REPO")
			for _, name := range names {
				instance := state.Instances[name]
				status, err := localRuntimeStatus(&instance)
				if err != nil {
					status = "unknown"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					instance.Name,
					instance.Backend,
					stateColor(status),
					localPortSummary(&instance),
					instance.Image,
					instance.RepoPath,
				)
			}
			return w.Flush()
		},
	}
}

func localInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info [name]",
		Short: "Show local runtime instance details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := resolveLocalInstanceArg(optionalArg(args))
			if err != nil {
				return err
			}
			status, statusErr := localRuntimeStatus(instance)
			if statusErr != nil {
				status = "unknown"
			}

			fmt.Printf("%-10s %s\n", bold("Name:"), instance.Name)
			fmt.Printf("%-10s %s\n", bold("Backend:"), instance.Backend)
			fmt.Printf("%-10s %s\n", bold("State:"), stateColor(status))
			fmt.Printf("%-10s %s\n", bold("Runtime:"), instance.RuntimeName)
			fmt.Printf("%-10s %s\n", bold("Image:"), instance.Image)
			fmt.Printf("%-10s %s\n", bold("Repo:"), instance.RepoPath)
			fmt.Printf("%-10s %s\n", bold("Workdir:"), instance.Workdir)
			if ports := localPortSummary(instance); ports != "" {
				fmt.Printf("%-10s %s\n", bold("Ports:"), ports)
			}
			if instance.Backend == "lima" {
				if vmType := strings.TrimSpace(instance.LimaVMType); vmType != "" {
					fmt.Printf("%-10s %s\n", bold("VMType:"), vmType)
				}
				if mountType := strings.TrimSpace(instance.LimaMountType); mountType != "" {
					fmt.Printf("%-10s %s\n", bold("MountType:"), mountType)
				}
			}
			if instance.Preset != "" {
				fmt.Printf("%-10s %s\n", bold("Preset:"), instance.Preset)
			}
			if instance.Install != "" {
				fmt.Printf("%-10s %s\n", bold("Install:"), instance.Install)
			}
			if instance.Startup != "" {
				fmt.Printf("%-10s %s\n", bold("Startup:"), instance.Startup)
			}
			if instance.CreatedAt != "" {
				fmt.Printf("%-10s %s\n", bold("Created:"), instance.CreatedAt)
			}
			return nil
		},
	}
}

func localPortsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ports [name] --publish <host>:<guest>",
		Short: "Forward ports from host to a local runtime when the backend supports it",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := resolveLocalInstanceArg(optionalArg(args))
			if err != nil {
				return err
			}
			if instance.Backend == "lima" {
				return fmt.Errorf("port forwarding for lima instances is managed by Lima configuration; recreate the instance with desired ports in codewire.yaml")
			}
			if instance.Backend != "firecracker" {
				return fmt.Errorf("interactive 'cw local ports' forwarding is only available for the experimental firecracker backend; use backend-native port mapping for docker or configured forwards for lima")
			}

			publish, _ := cmd.Flags().GetStringSlice("publish")
			if len(publish) == 0 {
				if len(instance.Ports) == 0 {
					fmt.Println("No ports configured.")
					return nil
				}
				for _, p := range instance.Ports {
					fmt.Printf("  %d (%s)\n", p.Port, p.Label)
				}
				return nil
			}

			vsockPath := instance.FirecrackerSocket + ".vsock"
			for _, spec := range publish {
				var hostPort, guestPort int
				if _, err := fmt.Sscanf(spec, "%d:%d", &hostPort, &guestPort); err != nil {
					return fmt.Errorf("invalid port spec %q (use host:guest format, e.g. 8080:3000)", spec)
				}
				ln, err := forwardPort(hostPort, guestPort, vsockPath)
				if err != nil {
					return err
				}
				defer ln.Close()
				fmt.Fprintf(os.Stderr, "  Forwarding localhost:%d -> guest:%d\n", hostPort, guestPort)
			}

			fmt.Fprintf(os.Stderr, "\n  Press Ctrl+C to stop forwarding.\n")
			// Block until interrupted
			select {}
		},
	}
	cmd.Flags().StringSliceP("publish", "p", nil, "Port mapping host:guest (e.g. 8080:3000)")
	return cmd
}

func optionalArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func localPortSummary(instance *cwconfig.LocalInstance) string {
	if instance == nil || len(instance.Ports) == 0 {
		return ""
	}

	parts := make([]string, 0, len(instance.Ports))
	for _, port := range instance.Ports {
		if port.Port <= 0 {
			continue
		}

		var part string
		switch instance.Backend {
		case "lima":
			part = fmt.Sprintf("%d -> %d", port.Port, port.Port)
		default:
			part = fmt.Sprintf("%d", port.Port)
		}
		if label := strings.TrimSpace(port.Label); label != "" {
			part += " (" + label + ")"
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, ", ")
}

func prepareLocalInstance(opts localCreateOptions) (cwconfig.LocalInstance, error) {
	projectDir, err := filepath.Abs(opts.Path)
	if err != nil {
		return cwconfig.LocalInstance{}, fmt.Errorf("resolve project path: %w", err)
	}
	info, err := os.Stat(projectDir)
	if err != nil {
		return cwconfig.LocalInstance{}, fmt.Errorf("read project path: %w", err)
	}
	if !info.IsDir() {
		return cwconfig.LocalInstance{}, fmt.Errorf("project path must be a directory")
	}

	cfg, err := loadLocalCodewireConfig(projectDir, opts.File)
	if err != nil {
		return cwconfig.LocalInstance{}, err
	}

	parsedEnv, err := parseEnvVarFlags(opts.EnvVars)
	if err != nil {
		return cwconfig.LocalInstance{}, err
	}
	if cfg.Env == nil {
		cfg.Env = map[string]string{}
	}
	for key, value := range parsedEnv {
		cfg.Env[key] = value
	}

	if opts.Preset != "" {
		cfg.Preset = opts.Preset
	}
	if opts.Image != "" {
		cfg.Image = expandImageRef(opts.Image)
	}
	if opts.Install != "" {
		cfg.Install = opts.Install
	}
	if opts.Startup != "" {
		cfg.Startup = opts.Startup
	}
	if opts.Agent != "" {
		cfg.Agents = &cwconfig.CodewireAgentsConfig{
			Install: cfg.InstallAgents,
			Tools:   []string{cwconfig.DisplayAgentID(opts.Agent)},
		}
		cfg.Agent = ""
	}
	if opts.Secrets != "" {
		if cfg.Secrets == nil {
			cfg.Secrets = &cwconfig.CodewireSecretsConfig{}
		}
		cfg.Secrets.Project = opts.Secrets
	}
	if opts.CPU > 0 {
		cfg.CPU = opts.CPU
	}
	if opts.Memory > 0 {
		cfg.Memory = opts.Memory
	}
	if opts.Disk > 0 {
		cfg.Disk = opts.Disk
	}
	if opts.NoOrgSecrets {
		f := false
		if cfg.Secrets == nil {
			cfg.Secrets = &cwconfig.CodewireSecretsConfig{}
		}
		cfg.Secrets.Org = &f
	}
	if opts.NoUserSecrets {
		f := false
		if cfg.Secrets == nil {
			cfg.Secrets = &cwconfig.CodewireSecretsConfig{}
		}
		cfg.Secrets.User = &f
	}
	if cfg.Image == "" && cfg.Preset != "" {
		cfg.Image = expandImageRef(cfg.Preset)
	}
	if cfg.Image == "" {
		return cwconfig.LocalInstance{}, fmt.Errorf("local create requires an image; set image in codewire.yaml or pass --image")
	}

	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = sanitizeLocalName(filepath.Base(projectDir))
	}
	if name == "" {
		return cwconfig.LocalInstance{}, fmt.Errorf("could not derive a valid local instance name")
	}

	instance := cwconfig.LocalInstance{
		Name:               name,
		Backend:            strings.TrimSpace(opts.Backend),
		RuntimeName:        "cw-" + name,
		RepoPath:           projectDir,
		Workdir:            localWorkspacePath,
		Preset:             cfg.Preset,
		Image:              expandImageRef(cfg.Image),
		Install:            cfg.Install,
		Startup:            cfg.Startup,
		Secrets:            localSecretProject(cfg),
		Env:                cfg.Env,
		Ports:              cfg.Ports,
		CPU:                cfg.CPU,
		Memory:             cfg.Memory,
		Disk:               cfg.Disk,
		Agent:              localPrimaryAgent(cfg),
		IncludeOrgSecrets:  localIncludeOrgSecrets(cfg),
		IncludeUserSecrets: localIncludeUserSecrets(cfg),
		CreatedAt:          localNow().Format(time.RFC3339),
		LastUsedAt:         localNow().Format(time.RFC3339),
	}
	return instance, nil
}

func localPrimaryAgent(cfg *cwconfig.CodewireConfig) string {
	if cfg == nil {
		return ""
	}
	if cfg.Agents != nil && len(cfg.Agents.Tools) > 0 {
		return cwconfig.CanonicalAgentID(cfg.Agents.Tools[0])
	}
	return cwconfig.CanonicalAgentID(cfg.Agent)
}

func localSecretProject(cfg *cwconfig.CodewireConfig) string {
	if cfg == nil || cfg.Secrets == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Secrets.Project)
}

func localIncludeOrgSecrets(cfg *cwconfig.CodewireConfig) *bool {
	if cfg == nil {
		return nil
	}
	if cfg.Secrets != nil && cfg.Secrets.Org != nil {
		return cfg.Secrets.Org
	}
	return cfg.IncludeOrgSecrets
}

func localIncludeUserSecrets(cfg *cwconfig.CodewireConfig) *bool {
	if cfg == nil {
		return nil
	}
	if cfg.Secrets != nil && cfg.Secrets.User != nil {
		return cfg.Secrets.User
	}
	return cfg.IncludeUserSecrets
}

func loadLocalCodewireConfig(projectDir, filePath string) (*cwconfig.CodewireConfig, error) {
	cfg := &cwconfig.CodewireConfig{}

	resolvedPath := filePath
	if resolvedPath == "" {
		resolvedPath = "codewire.yaml"
	}
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(projectDir, resolvedPath)
	}

	loaded, err := loadCodewireYAML(resolvedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		if strings.Contains(err.Error(), "no such file or directory") {
			return cfg, nil
		}
		return nil, err
	}
	return loaded, nil
}

// saveLocalInstanceState persists an in-memory instance change back to TOML.
func saveLocalInstanceState(instance *cwconfig.LocalInstance) error {
	state, err := loadLocalInstancesForCLI()
	if err != nil {
		return err
	}
	state.Instances[instance.Name] = *instance
	return saveLocalInstancesForCLI(state)
}

func createLocalRuntime(instance *cwconfig.LocalInstance) error {
	switch instance.Backend {
	case "incus":
		return createLocalIncusInstance(instance)
	case "docker":
		return createLocalDockerInstance(instance)
	case "lima":
		return createLocalLimaInstance(instance)
	case "firecracker":
		return createLocalFirecrackerInstance(instance)
	default:
		return fmt.Errorf("unsupported local backend %q", instance.Backend)
	}
}

func startLocalRuntime(instance *cwconfig.LocalInstance) error {
	switch instance.Backend {
	case "incus":
		return runIncus("start", instance.RuntimeName)
	case "docker":
		return runDocker("start", instance.RuntimeName)
	case "lima":
		return startLocalLimaInstance(instance)
	case "firecracker":
		if err := startLocalFirecrackerInstance(instance); err != nil {
			return err
		}
		return saveLocalInstanceState(instance)
	default:
		return fmt.Errorf("unsupported local backend %q", instance.Backend)
	}
}

func stopLocalRuntime(instance *cwconfig.LocalInstance) error {
	switch instance.Backend {
	case "incus":
		return runIncus("stop", instance.RuntimeName, "--force")
	case "docker":
		return runDocker("stop", "-t", "0", instance.RuntimeName)
	case "lima":
		return stopLocalLimaInstance(instance)
	case "firecracker":
		if err := stopLocalFirecrackerInstance(instance); err != nil {
			return err
		}
		return saveLocalInstanceState(instance)
	default:
		return fmt.Errorf("unsupported local backend %q", instance.Backend)
	}
}

func deleteLocalRuntime(instance *cwconfig.LocalInstance) error {
	switch instance.Backend {
	case "incus":
		out, err := localRunCommand("incus", "delete", instance.RuntimeName, "--force")
		if err != nil {
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "not found") || strings.Contains(lower, "no such object") {
				return nil
			}
			return fmt.Errorf("incus delete %s: %v\n%s", instance.RuntimeName, err, strings.TrimSpace(string(out)))
		}
		return nil
	case "docker":
		out, err := localRunCommand("docker", "rm", "-f", instance.RuntimeName)
		if err != nil {
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "no such container") || strings.Contains(lower, "not found") {
				return nil
			}
			return fmt.Errorf("docker rm %s: %v\n%s", instance.RuntimeName, err, strings.TrimSpace(string(out)))
		}
		return nil
	case "lima":
		return deleteLocalLimaInstance(instance)
	case "firecracker":
		return deleteLocalFirecrackerInstance(instance)
	default:
		return fmt.Errorf("unsupported local backend %q", instance.Backend)
	}
}

func localRuntimeStatus(instance *cwconfig.LocalInstance) (string, error) {
	switch instance.Backend {
	case "incus":
		return incusInstanceStatus(instance.RuntimeName)
	case "docker":
		return dockerContainerStatus(instance.RuntimeName)
	case "lima":
		return limaInstanceStatus(instance)
	case "firecracker":
		return firecrackerInstanceStatus(instance)
	default:
		return "unknown", fmt.Errorf("unsupported local backend %q", instance.Backend)
	}
}

func createLocalIncusInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("incus"); err != nil {
		return fmt.Errorf("incus is required for the incus backend: %w", err)
	}
	if _, err := localLookPath("skopeo"); err != nil {
		return fmt.Errorf("skopeo is required for the incus backend when using OCI images: %w", err)
	}

	remoteName, remoteURL, remoteImage, err := incusOCIImageRef(instance.Image)
	if err != nil {
		return err
	}
	if err := ensureIncusOCIRemote(remoteName, remoteURL); err != nil {
		return err
	}

	cleanup := false
	if err := runIncus("init", remoteImage, instance.RuntimeName); err != nil {
		return err
	}
	cleanup = true
	defer func() {
		if cleanup {
			_, _ = localRunCommand("incus", "delete", instance.RuntimeName, "--force")
		}
	}()

	if instance.CPU > 0 {
		cpus := (instance.CPU + 999) / 1000
		if cpus < 1 {
			cpus = 1
		}
		if err := runIncus("config", "set", instance.RuntimeName, "limits.cpu", fmt.Sprintf("%d", cpus)); err != nil {
			return err
		}
	}
	if instance.Memory > 0 {
		if err := runIncus("config", "set", instance.RuntimeName, "limits.memory", fmt.Sprintf("%dMiB", instance.Memory)); err != nil {
			return err
		}
	}
	if instance.Disk > 0 {
		if err := runIncus("config", "device", "set", instance.RuntimeName, "root", "size", fmt.Sprintf("%dGiB", instance.Disk)); err != nil {
			return err
		}
	}
	if err := runIncus("config", "device", "add", instance.RuntimeName, "workspace", "disk", "source="+instance.RepoPath, "path="+localWorkspacePath); err != nil {
		return err
	}
	if err := runIncus("start", instance.RuntimeName); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func createLocalDockerInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("docker"); err != nil {
		return fmt.Errorf("docker is required for the docker backend: %w", err)
	}

	args := []string{
		"create",
		"--name", instance.RuntimeName,
		"--hostname", instance.RuntimeName,
		"--workdir", localWorkspacePath,
		"--volume", instance.RepoPath + ":" + localWorkspacePath,
	}
	if homeDir, err := localUserHomeDir(); err == nil {
		claudeDir := filepath.Join(homeDir, ".claude")
		if _, err := localOsStat(claudeDir); err == nil {
			args = append(args, "--volume", claudeDir+":/home/codewire/.claude")
		}
	}
	if instance.CPU > 0 {
		args = append(args, "--cpus", formatDockerCPUs(instance.CPU))
	}
	if instance.Memory > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", instance.Memory))
	}
	if len(instance.Env) > 0 {
		keys := make([]string, 0, len(instance.Env))
		for key := range instance.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			args = append(args, "--env", key+"="+instance.Env[key])
		}
	}
	args = append(args,
		instance.Image,
		"/bin/sh",
		"-lc",
		"trap 'exit 0' TERM INT; while true; do sleep 3600; done",
	)

	if err := runDocker(args...); err != nil {
		return err
	}

	started := false
	defer func() {
		if !started {
			_, _ = localRunCommand("docker", "rm", "-f", instance.RuntimeName)
		}
	}()

	if err := runDocker("start", instance.RuntimeName); err != nil {
		return err
	}
	started = true
	return nil
}

func ensureIncusOCIRemote(remoteName, remoteURL string) error {
	out, err := localRunCommand("incus", "remote", "add", remoteName, remoteURL, "--protocol=oci")
	if err == nil {
		return nil
	}
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "already exists") {
		return nil
	}
	return fmt.Errorf("incus remote add %s: %v\n%s", remoteName, err, strings.TrimSpace(string(out)))
}

func runIncus(args ...string) error {
	out, err := localRunCommand("incus", args...)
	if err != nil {
		return fmt.Errorf("incus %s: %v\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runDocker(args ...string) error {
	out, err := localRunCommand("docker", args...)
	if err != nil {
		return fmt.Errorf("docker %s: %v\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dockerContainerStatus(name string) (string, error) {
	out, err := localRunCommand("docker", "inspect", "--format", "{{.State.Status}}", name)
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "no such object") || strings.Contains(lower, "no such container") || strings.Contains(lower, "not found") {
			return "missing", nil
		}
		return "", fmt.Errorf("docker inspect %s: %v\n%s", name, err, strings.TrimSpace(string(out)))
	}
	return strings.ToLower(strings.TrimSpace(string(out))), nil
}

func formatDockerCPUs(millicores int) string {
	whole := millicores / 1000
	frac := millicores % 1000
	if frac == 0 {
		return fmt.Sprintf("%d", whole)
	}
	return fmt.Sprintf("%d.%03d", whole, frac)
}

func incusInstanceStatus(name string) (string, error) {
	out, err := localRunCommand("incus", "list", name, "--format=json")
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such object") {
			return "missing", nil
		}
		return "", fmt.Errorf("incus list %s: %v\n%s", name, err, strings.TrimSpace(string(out)))
	}

	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err != nil {
		return "", fmt.Errorf("parse incus list json: %w", err)
	}
	if len(rows) == 0 {
		return "missing", nil
	}
	if status, _ := rows[0]["status"].(string); status != "" {
		return strings.ToLower(status), nil
	}
	if state, _ := rows[0]["state"].(map[string]any); state != nil {
		if status, _ := state["status"].(string); status != "" {
			return strings.ToLower(status), nil
		}
	}
	return "unknown", nil
}

func incusOCIImageRef(image string) (string, string, string, error) {
	ref := strings.TrimSpace(image)
	if ref == "" {
		return "", "", "", fmt.Errorf("image is required")
	}

	parts := strings.Split(ref, "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("incus backend requires an OCI image ref with a registry host, got %q", image)
	}

	registry := parts[0]
	remainder := strings.Join(parts[1:], "/")
	if registry == "" || remainder == "" {
		return "", "", "", fmt.Errorf("invalid OCI image ref %q", image)
	}

	remoteName := "cw-" + sanitizeLocalName(strings.ReplaceAll(registry, ".", "-"))
	remoteURL := "https://" + registry
	return remoteName, remoteURL, remoteName + ":" + remainder, nil
}

func resolveLocalInstanceArg(ref string) (*cwconfig.LocalInstance, error) {
	state, err := loadLocalInstancesForCLI()
	if err != nil {
		return nil, err
	}
	_, instance, err := resolveLocalInstance(state, ref)
	return instance, err
}

func resolveLocalInstance(state *cwconfig.LocalInstancesConfig, ref string) (string, *cwconfig.LocalInstance, error) {
	if state == nil || len(state.Instances) == 0 {
		return "", nil, fmt.Errorf("no local instances found")
	}

	if strings.TrimSpace(ref) != "" {
		ref = strings.TrimSpace(ref)
		if instance, ok := state.Instances[ref]; ok {
			return ref, &instance, nil
		}
		for key, instance := range state.Instances {
			if instance.RuntimeName == ref {
				return key, &instance, nil
			}
		}
		return "", nil, fmt.Errorf("local instance not found: %s", ref)
	}

	cwd, err := localGetwd()
	if err == nil {
		cwd, _ = filepath.Abs(cwd)
		var matches []string
		for key, instance := range state.Instances {
			if sameCleanPath(instance.RepoPath, cwd) {
				matches = append(matches, key)
			}
		}
		if len(matches) == 1 {
			instance := state.Instances[matches[0]]
			return matches[0], &instance, nil
		}
		if len(matches) > 1 {
			sort.Strings(matches)
			return "", nil, fmt.Errorf("multiple local instances match this repo: %s", strings.Join(matches, ", "))
		}
	}

	return "", nil, fmt.Errorf("no local instance associated with this directory; pass a name explicitly or run 'cw local create'")
}

func sameCleanPath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func sortedLocalInstanceNames(state *cwconfig.LocalInstancesConfig) []string {
	names := make([]string, 0, len(state.Instances))
	for name := range state.Instances {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sanitizeLocalName(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range raw {
		isAlpha := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if isAlpha || isDigit {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
