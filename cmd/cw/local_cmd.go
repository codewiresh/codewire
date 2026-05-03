package main

import (
	"encoding/json"
	"fmt"
	"io"
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

const (
	localWorkspacePath   = "/workspace"
	localSSHAuthSockPath = "/tmp/codewire-ssh-agent.sock"
)

var (
	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return cwconfig.LoadLocalInstancesConfig(localCLIDataDir())
	}
	saveLocalInstancesForCLI = func(cfg *cwconfig.LocalInstancesConfig) error {
		return cwconfig.SaveLocalInstancesConfig(localCLIDataDir(), cfg)
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
	localLookPath         = exec.LookPath
	localPromptConfirm    = promptConfirm
	localNow              = func() time.Time { return time.Now().UTC() }
	localGetwd            = os.Getwd
	localUserHomeDir      = os.UserHomeDir
	localOsStat           = os.Stat
	localCLIDataDir       = dataDir
	localGitHubToken      = detectLocalGitHubToken
	localGitConfigPath    = detectLocalGitConfigPath
	localSSHAuthSock      = detectLocalSSHAuthSock
	localClaudeOAuthToken = resolveClaudeOAuthToken
	localAnthropicAPIKey  = resolveAnthropicAPIKey
)

// resolveAnthropicAPIKey returns the host's Anthropic API key (sk-ant-api…)
// from $ANTHROPIC_API_KEY, or empty when unset. SDKs and `claude-code` both
// read this env var; forwarding it makes API-billed inference work
// inside local VMs identically to OAuth-token flows.
func resolveAnthropicAPIKey() string {
	return strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
}

func detectLocalGitHubToken() string {
	if token := strings.TrimSpace(os.Getenv("GH_TOKEN")); token != "" {
		return token
	}
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		return token
	}
	ghPath, err := localLookPath("gh")
	if err != nil {
		return ""
	}
	out, err := localRunCommand(ghPath, "auth", "token")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func detectLocalGitConfigPath() string {
	homeDir, err := localUserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(homeDir, ".gitconfig")
	if _, err := localOsStat(path); err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return path
}

func detectLocalSSHAuthSock() string {
	homeDir, err := localUserHomeDir()
	if err == nil {
		onePasswordSock := filepath.Join(homeDir, ".1password", "agent.sock")
		if _, err := localOsStat(onePasswordSock); err == nil {
			return onePasswordSock
		}
	}
	path := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if path == "" {
		return ""
	}
	if _, err := localOsStat(path); err != nil {
		return ""
	}
	return path
}

type localCreateOptions struct {
	Backend       string
	Name          string
	Path          string
	File          string
	Spec          string // JSON spec path or "-" for stdin; takes precedence over File
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
	Network       string
	NoNetwork     bool
	Yes           bool
}

// localSpec is the JSON shape accepted by `cw local create --spec`. It mirrors
// the fields in codewire.yaml but uses snake_case keys. SDK consumers construct
// these objects directly and pipe them via stdin.
type localSpec struct {
	Preset             string            `json:"preset,omitempty"`
	Image              string            `json:"image,omitempty"`
	Install            string            `json:"install,omitempty"`
	Startup            string            `json:"startup,omitempty"`
	Env                map[string]string `json:"env,omitempty"`
	Ports              []localSpecPort   `json:"ports,omitempty"`
	Mounts             []localSpecMount  `json:"mounts,omitempty"`
	CPU                int               `json:"cpu,omitempty"`
	Memory             int               `json:"memory,omitempty"`
	Disk               int               `json:"disk,omitempty"`
	Agent              string            `json:"agent,omitempty"`
	SecretProject      string            `json:"secret_project,omitempty"`
	IncludeOrgSecrets  *bool             `json:"include_org_secrets,omitempty"`
	IncludeUserSecrets *bool             `json:"include_user_secrets,omitempty"`
}

type localSpecPort struct {
	HostPort  int    `json:"host_port,omitempty"`
	GuestPort int    `json:"guest_port,omitempty"`
	Port      int    `json:"port,omitempty"`
	Label     string `json:"label,omitempty"`
}

type localSpecMount struct {
	Source   string `json:"source"`
	Target   string `json:"target,omitempty"`
	Readonly bool   `json:"readonly,omitempty"`
}

func localParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local",
		Short: "Manage local runtime instances",
	}
	cmd.PersistentFlags().StringP("output", "o", outputFormatText, "Output format (text|json)")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{outputFormatText, outputFormatJSON}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.AddCommand(localCreateCmd())
	cmd.AddCommand(localStartCmd())
	cmd.AddCommand(localStopCmd())
	cmd.AddCommand(localRmCmd())
	cmd.AddCommand(localListCmd())
	cmd.AddCommand(localInfoCmd())
	cmd.AddCommand(localPortsCmd())
	cmd.AddCommand(localFilesCmd())
	return cmd
}

// localOutputJSON returns true when the inherited output format for
// `cw local ...` is json. Used by every local subcommand to branch output.
func localOutputJSON(cmd *cobra.Command) (bool, error) {
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		flag = cmd.InheritedFlags().Lookup("output")
	}
	if flag == nil {
		return false, nil
	}
	return wantsJSON(flag.Value.String())
}

func localCreateCmd() *cobra.Command {
	var opts localCreateOptions

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a local runtime instance from codewire.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
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

			// Resolve relay/network selection before creating the runtime, but
			// create the one-use node enrollment only after the runtime is up.
			// That avoids leaking an enrollment token if VM creation fails.
			relayBootstrap, err := resolveRelayNetworkBootstrap(dataDir(), opts.Yes, opts.Network, opts.NoNetwork)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: relay enrollment failed (%v), continuing without network\n", err)
				relayBootstrap = nil
			}

			if err := createLocalRuntime(&instance); err != nil {
				return err
			}

			state.Instances[instance.Name] = instance
			if err := saveLocalInstancesForCLI(state); err != nil {
				return fmt.Errorf("save local instance state: %w", err)
			}

			enrolledOnNetwork := ""
			if relayBootstrap != nil {
				enrollment, err := createLocalRelayNodeEnrollment(dataDir(), relayBootstrap, instance.Name)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: relay enrollment failed (%v), continuing without network\n", err)
					enrollment = nil
				}
				if enrollment != nil {
					if err := redeemRelayEnrollmentInLocalRuntime(&instance, enrollment); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: relay enrollment redemption failed (%v); the runtime is up but not visible on the relay. Redeem manually with: cw exec %s -- cw network enroll redeem %s --node-name %s\n",
							err, instance.Name, enrollment.EnrollmentToken, instance.Name)
					} else {
						enrolledOnNetwork = enrollment.NetworkID
					}
				}
			}

			if jsonOutput {
				status, statusErr := localRuntimeStatus(&instance)
				if statusErr != nil {
					status = "unknown"
				}
				return emitJSON(localInstanceToJSON(&instance, status))
			}

			successMsg("Local instance created: %s.", instance.Name)
			fmt.Printf("%-10s %s\n", bold("Backend:"), instance.Backend)
			fmt.Printf("%-10s %s\n", bold("Runtime:"), instance.RuntimeName)
			fmt.Printf("%-10s %s\n", bold("Image:"), instance.Image)
			fmt.Printf("%-10s %s\n", bold("Repo:"), instance.RepoPath)
			fmt.Printf("%-10s %s\n", bold("Mount:"), instance.Workdir)
			if enrolledOnNetwork != "" {
				fmt.Printf("%-10s %s (node: %s)\n", bold("Network:"), enrolledOnNetwork, instance.Name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Backend, "backend", "", "Local runtime backend (docker, lima, incus, or experimental firecracker)")
	cmd.Flags().StringVar(&opts.Name, "name", "", "Instance name (defaults to the repo directory name)")
	cmd.Flags().StringVar(&opts.Path, "path", ".", "Project directory to associate with the local instance")
	cmd.Flags().StringVar(&opts.File, "file", "codewire.yaml", "Preset file path, relative to --path when not absolute")
	cmd.Flags().StringVar(&opts.Spec, "spec", "", "JSON spec file or '-' for stdin; overrides codewire.yaml (used by SDK shell-out)")
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
	cmd.Flags().StringVar(&opts.Network, "network", "", "Join a specific relay network on boot (requires relay auth in local config)")
	cmd.Flags().BoolVar(&opts.NoNetwork, "no-network", false, "Don't join the selected private relay network")
	cmd.Flags().BoolVarP(&opts.Yes, "yes", "y", false, "Skip interactive prompts (assume yes)")
	return cmd
}

func localStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [name]",
		Short: "Start an existing local runtime instance",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			state, err := loadLocalInstancesForCLI()
			if err != nil {
				return err
			}
			key, instance, err := resolveLocalInstance(state, optionalArg(args))
			if err != nil {
				return err
			}
			changed, err := reconcileLocalInstancePortsFromConfig(instance)
			if err != nil {
				return err
			}
			if changed {
				state.Instances[key] = *instance
				if err := saveLocalInstancesForCLI(state); err != nil {
					return fmt.Errorf("save local instance state: %w", err)
				}
			}
			if err := startLocalRuntime(instance); err != nil {
				return err
			}
			if jsonOutput {
				status, statusErr := localRuntimeStatus(instance)
				if statusErr != nil {
					status = "unknown"
				}
				return emitJSON(localInstanceToJSON(instance, status))
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
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			instance, err := resolveLocalInstanceArg(optionalArg(args))
			if err != nil {
				return err
			}
			if err := stopLocalRuntime(instance); err != nil {
				return err
			}
			if jsonOutput {
				status, statusErr := localRuntimeStatus(instance)
				if statusErr != nil {
					status = "unknown"
				}
				return emitJSON(localInstanceToJSON(instance, status))
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
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
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
			if jsonOutput {
				return emitJSON(map[string]any{
					"name":    instance.Name,
					"removed": true,
				})
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
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			state, err := loadLocalInstancesForCLI()
			if err != nil {
				return err
			}
			names := sortedLocalInstanceNames(state)

			if jsonOutput {
				out := make([]localInstanceJSON, 0, len(names))
				for _, name := range names {
					instance := state.Instances[name]
					status, statusErr := localRuntimeStatus(&instance)
					if statusErr != nil {
						status = "unknown"
					}
					out = append(out, localInstanceToJSON(&instance, status))
				}
				return emitJSON(out)
			}

			if len(state.Instances) == 0 {
				fmt.Println("No local instances found.")
				return nil
			}

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
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			instance, err := resolveLocalInstanceArg(optionalArg(args))
			if err != nil {
				return err
			}
			status, statusErr := localRuntimeStatus(instance)
			if statusErr != nil {
				status = "unknown"
			}

			if jsonOutput {
				return emitJSON(localInstanceToJSON(instance, status))
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
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			state, err := loadLocalInstancesForCLI()
			if err != nil {
				return err
			}
			key, instance, err := resolveLocalInstance(state, optionalArg(args))
			if err != nil {
				return err
			}

			publish, _ := cmd.Flags().GetStringSlice("publish")
			if len(publish) == 0 {
				if jsonOutput {
					status, statusErr := localRuntimeStatus(instance)
					if statusErr != nil {
						status = "unknown"
					}
					return emitJSON(localInstanceToJSON(instance, status).Ports)
				}
				printLocalConfiguredPorts(instance)
				return nil
			}

			switch instance.Backend {
			case "lima":
				updatedPorts, added, err := addLimaPortForwards(instance, publish)
				if err != nil {
					return err
				}
				instance.Ports = updatedPorts
				state.Instances[key] = *instance
				if err := saveLocalInstancesForCLI(state); err != nil {
					return fmt.Errorf("save local instance state: %w", err)
				}
				if jsonOutput {
					status, statusErr := localRuntimeStatus(instance)
					if statusErr != nil {
						status = "unknown"
					}
					return emitJSON(localInstanceToJSON(instance, status))
				}
				if added == 0 {
					fmt.Println("No new ports were added.")
				} else {
					successMsg("Updated Lima port forwards for %s.", instance.Name)
				}
				printLocalConfiguredPorts(instance)
				return nil
			case "firecracker":
				vsockPath := instance.FirecrackerSocket + ".vsock"
				for _, spec := range publish {
					port, err := parsePublishedPortSpec(spec)
					if err != nil {
						return err
					}
					hostPort := port.EffectiveHostPort()
					guestPort := port.EffectiveGuestPort()
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
			default:
				return fmt.Errorf("interactive 'cw local ports' forwarding is only available for Lima and the experimental firecracker backend; use backend-native port mapping for docker")
			}
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

type limaPortForwardEdit struct {
	GuestPort int    `json:"guestPort"`
	HostPort  int    `json:"hostPort"`
	Proto     string `json:"proto"`
}

func parsePublishedPortSpec(spec string) (cwconfig.PortConfig, error) {
	var hostPort, guestPort int
	if _, err := fmt.Sscanf(spec, "%d:%d", &hostPort, &guestPort); err != nil || hostPort <= 0 || guestPort <= 0 {
		return cwconfig.PortConfig{}, fmt.Errorf("invalid port spec %q (use host:guest format, e.g. 8080:3000)", spec)
	}
	return (cwconfig.PortConfig{HostPort: hostPort, GuestPort: guestPort}).Canonical(), nil
}

func printLocalConfiguredPorts(instance *cwconfig.LocalInstance) {
	if instance == nil || len(instance.Ports) == 0 {
		fmt.Println("No ports configured.")
		return
	}

	printed := false
	for _, port := range instance.Ports {
		part := localPortDisplay(instance, port)
		if part == "" {
			continue
		}
		fmt.Printf("  %s\n", part)
		printed = true
	}
	if !printed {
		fmt.Println("No ports configured.")
	}
}

func localPortDisplay(instance *cwconfig.LocalInstance, port cwconfig.PortConfig) string {
	hostPort := port.EffectiveHostPort()
	guestPort := port.EffectiveGuestPort()
	if hostPort <= 0 || guestPort <= 0 {
		return ""
	}

	var part string
	switch {
	case hostPort != guestPort:
		part = fmt.Sprintf("%d -> %d", hostPort, guestPort)
	case instance != nil && instance.Backend == "lima":
		part = fmt.Sprintf("%d -> %d", hostPort, guestPort)
	default:
		part = fmt.Sprintf("%d", guestPort)
	}
	if label := strings.TrimSpace(port.Label); label != "" {
		part += " (" + label + ")"
	}
	return part
}

func canonicalLocalPorts(ports []cwconfig.PortConfig) []cwconfig.PortConfig {
	canonical := make([]cwconfig.PortConfig, 0, len(ports))
	for _, port := range ports {
		normalized := port.Canonical()
		if normalized.EffectiveHostPort() <= 0 || normalized.EffectiveGuestPort() <= 0 {
			continue
		}
		canonical = append(canonical, normalized)
	}
	return canonical
}

func sameLocalPorts(a, b []cwconfig.PortConfig) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func reconcileLocalInstancePortsFromConfig(instance *cwconfig.LocalInstance) (bool, error) {
	if instance == nil || strings.TrimSpace(instance.RepoPath) == "" {
		return false, nil
	}

	cfg, err := loadLocalCodewireConfig(instance.RepoPath, "codewire.yaml")
	if err != nil {
		return false, err
	}
	desiredPorts := canonicalLocalPorts(cfg.Ports)
	currentPorts := canonicalLocalPorts(instance.Ports)
	if sameLocalPorts(currentPorts, desiredPorts) {
		return false, nil
	}

	if instance.Backend == "lima" {
		status, err := localRuntimeStatus(instance)
		if err != nil {
			return false, err
		}
		if status == "running" {
			return false, fmt.Errorf("Lima instance %q is running with stale codewire.yaml port config; stop it and rerun 'cw local start %s' to apply the change", instance.Name, instance.Name)
		}
		if status != "missing" {
			if err := limaSetPortForwards(instance, desiredPorts); err != nil {
				return false, err
			}
		}
	}

	instance.Ports = desiredPorts
	return true, nil
}

func limaSetPortForwards(instance *cwconfig.LocalInstance, ports []cwconfig.PortConfig) error {
	name := limaInstanceName(instance)
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("missing Lima instance name")
	}

	forwards := make([]limaPortForwardEdit, 0, len(ports))
	for _, port := range canonicalLocalPorts(ports) {
		forwards = append(forwards, limaPortForwardEdit{
			GuestPort: port.EffectiveGuestPort(),
			HostPort:  port.EffectiveHostPort(),
			Proto:     "tcp",
		})
	}

	payload, err := json.Marshal(forwards)
	if err != nil {
		return fmt.Errorf("marshal Lima port forwards: %w", err)
	}
	setExpr := fmt.Sprintf(`.portForwards = ((.portForwards // []) | map(select(.guestSocket != null)) + %s)`, payload)
	out, err := localRunCommand("limactl", "edit", "--tty=false", name, "--set", setExpr)
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("limactl edit %s: %v\n%s", name, err, trimmed)
		}
		return fmt.Errorf("limactl edit %s: %w", name, err)
	}
	return nil
}

func addLimaPortForwards(instance *cwconfig.LocalInstance, publish []string) ([]cwconfig.PortConfig, int, error) {
	if instance == nil {
		return nil, 0, fmt.Errorf("missing local instance")
	}

	existingByHost := make(map[int]cwconfig.PortConfig, len(instance.Ports))
	updatedPorts := make([]cwconfig.PortConfig, 0, len(instance.Ports)+len(publish))
	for _, port := range instance.Ports {
		canonical := port.Canonical()
		hostPort := canonical.EffectiveHostPort()
		guestPort := canonical.EffectiveGuestPort()
		if hostPort <= 0 || guestPort <= 0 {
			continue
		}
		if existing, ok := existingByHost[hostPort]; ok && existing.EffectiveGuestPort() != guestPort {
			return nil, 0, fmt.Errorf("Lima instance %q has conflicting host port %d mapped to guest ports %d and %d", instance.Name, hostPort, existing.EffectiveGuestPort(), guestPort)
		}
		existingByHost[hostPort] = canonical
		updatedPorts = append(updatedPorts, canonical)
	}

	forwards := make([]limaPortForwardEdit, 0, len(publish))
	added := 0
	for _, spec := range publish {
		port, err := parsePublishedPortSpec(spec)
		if err != nil {
			return nil, 0, err
		}
		hostPort := port.EffectiveHostPort()
		guestPort := port.EffectiveGuestPort()
		if existing, ok := existingByHost[hostPort]; ok {
			if existing.EffectiveGuestPort() != guestPort {
				return nil, 0, fmt.Errorf("host port %d is already forwarded to guest port %d", hostPort, existing.EffectiveGuestPort())
			}
			continue
		}
		existingByHost[hostPort] = port
		updatedPorts = append(updatedPorts, port)
		forwards = append(forwards, limaPortForwardEdit{GuestPort: guestPort, HostPort: hostPort, Proto: "tcp"})
		added++
	}

	if len(forwards) == 0 {
		return updatedPorts, 0, nil
	}
	if err := limaAddPortForwards(instance, forwards); err != nil {
		return nil, 0, err
	}
	return updatedPorts, added, nil
}

func limaAddPortForwards(instance *cwconfig.LocalInstance, forwards []limaPortForwardEdit) error {
	if len(forwards) == 0 {
		return nil
	}
	name := limaInstanceName(instance)
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("missing Lima instance name")
	}
	payload, err := json.Marshal(forwards)
	if err != nil {
		return fmt.Errorf("marshal Lima port forwards: %w", err)
	}
	setExpr := fmt.Sprintf(".portForwards = (.portForwards // []) + %s", payload)
	out, err := localRunCommand("limactl", "edit", "--tty=false", name, "--set", setExpr)
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("limactl edit %s: %v\n%s", name, err, trimmed)
		}
		return fmt.Errorf("limactl edit %s: %w", name, err)
	}
	return nil
}

func localPortSummary(instance *cwconfig.LocalInstance) string {
	if instance == nil || len(instance.Ports) == 0 {
		return ""
	}

	parts := make([]string, 0, len(instance.Ports))
	for _, port := range instance.Ports {
		part := localPortDisplay(instance, port)
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, ", ")
}

func resolveLocalMounts(projectDir string, mounts []cwconfig.MountConfig) ([]cwconfig.MountConfig, error) {
	if len(mounts) == 0 {
		return nil, nil
	}

	resolved := make([]cwconfig.MountConfig, 0, len(mounts))
	for _, mount := range mounts {
		source := strings.TrimSpace(mount.Source)
		if source == "" {
			return nil, fmt.Errorf("mount source is required")
		}
		if !filepath.IsAbs(source) {
			source = filepath.Join(projectDir, source)
		}
		source = filepath.Clean(source)
		if _, err := os.Stat(source); err != nil {
			return nil, fmt.Errorf("read mount source %s: %w", source, err)
		}

		target := strings.TrimSpace(mount.Target)
		if target == "" {
			target = source
		}
		if !filepath.IsAbs(target) {
			return nil, fmt.Errorf("mount target must be absolute: %s", target)
		}

		resolved = append(resolved, cwconfig.MountConfig{
			Source:   source,
			Target:   filepath.Clean(target),
			Readonly: mount.Readonly,
		})
	}
	return resolved, nil
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

	var cfg *cwconfig.CodewireConfig
	if strings.TrimSpace(opts.Spec) != "" {
		spec, err := loadLocalSpec(opts.Spec)
		if err != nil {
			return cwconfig.LocalInstance{}, err
		}
		cfg = localSpecToCodewireConfig(spec)
	} else {
		cfg, err = loadLocalCodewireConfig(projectDir, opts.File)
		if err != nil {
			return cwconfig.LocalInstance{}, err
		}
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

	resolvedMounts, err := resolveLocalMounts(projectDir, cfg.Mounts)
	if err != nil {
		return cwconfig.LocalInstance{}, err
	}

	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = sanitizeLocalName(filepath.Base(projectDir))
	}
	if name == "" {
		return cwconfig.LocalInstance{}, fmt.Errorf("could not derive a valid local instance name")
	}

	workdir := localWorkspacePath
	if strings.TrimSpace(opts.Backend) == "lima" {
		workdir = projectDir
	}

	instance := cwconfig.LocalInstance{
		Name:               name,
		Backend:            strings.TrimSpace(opts.Backend),
		RuntimeName:        "cw-" + name,
		RepoPath:           projectDir,
		Workdir:            workdir,
		Preset:             cfg.Preset,
		Image:              expandImageRef(cfg.Image),
		Install:            cfg.Install,
		Startup:            cfg.Startup,
		Secrets:            localSecretProject(cfg),
		Env:                cfg.Env,
		Ports:              cfg.Ports,
		Mounts:             resolvedMounts,
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

// relayEnrollmentRedeemCommand builds the argv that redeems an enrollment token
// inside the runtime. Pure function for testability.
func relayEnrollmentRedeemCommand(instance *cwconfig.LocalInstance, enrollment *relayEnrollment) []string {
	if instance == nil || enrollment == nil {
		return nil
	}
	token := strings.TrimSpace(enrollment.EnrollmentToken)
	if token == "" {
		return nil
	}
	command := []string{"cw", "network", "enroll", "redeem", token, "--node-name", instance.Name}
	if strings.TrimSpace(enrollment.RelayURL) != "" {
		command = append(command, "--relay-url", enrollment.RelayURL)
	}
	return command
}

// redeemRelayEnrollmentInLocalRuntime redeems a relay node enrollment from
// inside a freshly-created local runtime. The runtime registers itself as
// a relay node under the instance name, becoming addressable via
// `cw run --on <name>` and the rest of the relay-routed CLI surface.
//
// Local runtimes have no platform-side worker setup phase, so the host
// creates and redeems a node enrollment synchronously after the runtime is up.
var redeemRelayEnrollmentInLocalRuntime = func(instance *cwconfig.LocalInstance, enrollment *relayEnrollment) error {
	command := relayEnrollmentRedeemCommand(instance, enrollment)
	if command == nil {
		return nil
	}
	result, err := execInLocalRuntimeBuffered(instance, "", command)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		stderr := strings.TrimSpace(result.Stderr)
		if stderr == "" {
			stderr = strings.TrimSpace(result.Stdout)
		}
		return fmt.Errorf("redeem exited with code %d: %s", result.ExitCode, stderr)
	}
	return nil
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

// loadLocalSpec reads a localSpec JSON document from either a file path or
// stdin (when source == "-"). SDK callers pipe JSON to `cw local create --spec -`.
func loadLocalSpec(source string) (*localSpec, error) {
	var data []byte
	var err error
	if source == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read spec from stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("read spec %s: %w", source, err)
		}
	}
	var spec localSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse spec json: %w", err)
	}
	return &spec, nil
}

// localSpecToCodewireConfig converts the SDK-facing JSON spec into the internal
// CodewireConfig shape used by prepareLocalInstance. Lives in cmd/ because the
// JSON schema is a CLI contract, not an internal type.
func localSpecToCodewireConfig(spec *localSpec) *cwconfig.CodewireConfig {
	if spec == nil {
		return &cwconfig.CodewireConfig{}
	}
	cfg := &cwconfig.CodewireConfig{
		Preset:             spec.Preset,
		Image:              spec.Image,
		Install:            spec.Install,
		Startup:            spec.Startup,
		Env:                spec.Env,
		CPU:                spec.CPU,
		Memory:             spec.Memory,
		Disk:               spec.Disk,
		Agent:              spec.Agent,
		IncludeOrgSecrets:  spec.IncludeOrgSecrets,
		IncludeUserSecrets: spec.IncludeUserSecrets,
	}
	if strings.TrimSpace(spec.SecretProject) != "" {
		cfg.Secrets = &cwconfig.CodewireSecretsConfig{Project: spec.SecretProject}
	}
	for _, p := range spec.Ports {
		port := cwconfig.PortConfig{
			HostPort:  p.HostPort,
			GuestPort: p.GuestPort,
			Port:      p.Port,
			Label:     p.Label,
		}
		cfg.Ports = append(cfg.Ports, port.Canonical())
	}
	for _, m := range spec.Mounts {
		ro := m.Readonly
		cfg.Mounts = append(cfg.Mounts, cwconfig.MountConfig{
			Source:   m.Source,
			Target:   m.Target,
			Readonly: &ro,
		})
	}
	return cfg
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
	if homeDir, err := localUserHomeDir(); err == nil {
		claudeDir := filepath.Join(homeDir, ".claude")
		if _, statErr := localOsStat(claudeDir); statErr == nil {
			if err := runIncus("config", "device", "add", instance.RuntimeName, "claude-config", "disk",
				"source="+claudeDir, "path=/home/codewire/.claude"); err != nil {
				return err
			}
		}
		claudeJSON := filepath.Join(homeDir, ".claude.json")
		if _, statErr := localOsStat(claudeJSON); statErr == nil {
			if err := runIncus("config", "device", "add", instance.RuntimeName, "claude-json", "disk",
				"source="+claudeJSON, "path=/home/codewire/.claude.json"); err != nil {
				return err
			}
		}
		ghConfigDir := filepath.Join(homeDir, ".config", "gh")
		if _, statErr := localOsStat(ghConfigDir); statErr == nil {
			if err := runIncus("config", "device", "add", instance.RuntimeName, "gh-config", "disk",
				"source="+ghConfigDir, "path=/home/codewire/.config/gh"); err != nil {
				return err
			}
		}
		if token := strings.TrimSpace(localGitHubToken()); token != "" {
			if err := runIncus("config", "set", instance.RuntimeName, "environment.GH_TOKEN", token); err != nil {
				return err
			}
		}
		if token := strings.TrimSpace(localClaudeOAuthToken()); token != "" {
			// Only CLAUDE_CODE_OAUTH_TOKEN — ANTHROPIC_AUTH_TOKEN expects a
			// regular API key ("sk-ant-api…"), not an OAuth token
			// ("sk-ant-oat…"), and setting it here causes claude-code to
			// preferentially use the wrong token and fail with 401.
			if err := runIncus("config", "set", instance.RuntimeName, "environment.CLAUDE_CODE_OAUTH_TOKEN", token); err != nil {
				return err
			}
		}
		if apiKey := localAnthropicAPIKey(); apiKey != "" {
			// Forward ANTHROPIC_API_KEY for SDK / claude-code direct-API use.
			if err := runIncus("config", "set", instance.RuntimeName, "environment.ANTHROPIC_API_KEY", apiKey); err != nil {
				return err
			}
		}
		if gitConfigPath := strings.TrimSpace(localGitConfigPath()); gitConfigPath != "" {
			if err := runIncus("config", "device", "add", instance.RuntimeName, "git-config", "disk",
				"source="+gitConfigPath, "path=/home/codewire/.gitconfig", "readonly=true"); err != nil {
				return err
			}
		}
		sshDir := filepath.Join(homeDir, ".ssh")
		if _, statErr := localOsStat(sshDir); statErr == nil {
			if err := runIncus("config", "device", "add", instance.RuntimeName, "ssh-config", "disk",
				"source="+sshDir, "path=/home/codewire/.ssh", "readonly=true"); err != nil {
				return err
			}
		}
		codexDir := filepath.Join(homeDir, ".codex")
		if _, statErr := localOsStat(codexDir); statErr == nil {
			if err := runIncus("config", "device", "add", instance.RuntimeName, "codex-config", "disk",
				"source="+codexDir, "path=/home/codewire/.codex"); err != nil {
				return err
			}
		}
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
		// Override the image's ENTRYPOINT so the long-running sleep script is
		// what actually runs. Many dev images ship an entrypoint that writes
		// SSH host keys into ~/.ssh at startup — which fails here because we
		// mount ~/.ssh read-only from the host.
		"--entrypoint", "/bin/sh",
		"--workdir", localWorkspacePath,
		"--volume", instance.RepoPath + ":" + localWorkspacePath,
	}
	if homeDir, err := localUserHomeDir(); err == nil {
		claudeDir := filepath.Join(homeDir, ".claude")
		if _, err := localOsStat(claudeDir); err == nil {
			args = append(args, "--volume", claudeDir+":/home/codewire/.claude")
		}
		claudeJSON := filepath.Join(homeDir, ".claude.json")
		if _, err := localOsStat(claudeJSON); err == nil {
			args = append(args, "--volume", claudeJSON+":/home/codewire/.claude.json")
		}
		ghConfigDir := filepath.Join(homeDir, ".config", "gh")
		if _, err := localOsStat(ghConfigDir); err == nil {
			args = append(args, "--volume", ghConfigDir+":/home/codewire/.config/gh")
		}
		if gitConfigPath := strings.TrimSpace(localGitConfigPath()); gitConfigPath != "" {
			args = append(args, "--volume", gitConfigPath+":/home/codewire/.gitconfig:ro")
		}
		if sshAuthSock := strings.TrimSpace(localSSHAuthSock()); sshAuthSock != "" {
			args = append(args, "--volume", sshAuthSock+":"+localSSHAuthSockPath)
		}
		sshDir := filepath.Join(homeDir, ".ssh")
		if _, err := localOsStat(sshDir); err == nil {
			args = append(args, "--volume", sshDir+":/home/codewire/.ssh:ro")
		}
		codexDir := filepath.Join(homeDir, ".codex")
		if _, err := localOsStat(codexDir); err == nil {
			args = append(args, "--volume", codexDir+":/home/codewire/.codex")
		}
	}
	if instance.CPU > 0 {
		args = append(args, "--cpus", formatDockerCPUs(instance.CPU))
	}
	if instance.Memory > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", instance.Memory))
	}
	if token := strings.TrimSpace(localGitHubToken()); token != "" {
		args = append(args, "--env", "GH_TOKEN="+token)
	}
	if sshAuthSock := strings.TrimSpace(localSSHAuthSock()); sshAuthSock != "" {
		args = append(args, "--env", "SSH_AUTH_SOCK="+localSSHAuthSockPath)
	}
	if token := strings.TrimSpace(localClaudeOAuthToken()); token != "" {
		// Only CLAUDE_CODE_OAUTH_TOKEN — ANTHROPIC_AUTH_TOKEN expects a
		// regular API key ("sk-ant-api…"), not an OAuth token
		// ("sk-ant-oat…"), and setting it here causes claude-code to
		// preferentially use the wrong token and fail with 401.
		args = append(args, "--env", "CLAUDE_CODE_OAUTH_TOKEN="+token)
	}
	if apiKey := localAnthropicAPIKey(); apiKey != "" {
		// Forward ANTHROPIC_API_KEY so SDK code and `claude-code` running
		// in the container can hit the API directly (CI / pay-per-token use
		// case). Distinct from the OAuth token above.
		args = append(args, "--env", "ANTHROPIC_API_KEY="+apiKey)
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
		// Entrypoint was overridden to /bin/sh above, so the CMD is the shell's
		// arguments. The `trap` keeps the container responsive to stop signals.
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
