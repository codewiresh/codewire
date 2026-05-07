package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/client"
	"github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/mcp"
	"github.com/codewiresh/codewire/internal/node"
	"github.com/codewiresh/codewire/internal/peer"
	"github.com/codewiresh/codewire/internal/peerclient"
	"github.com/codewiresh/codewire/internal/protocol"
	"github.com/codewiresh/codewire/internal/relay"
	"github.com/codewiresh/codewire/internal/update"
)

var (
	// version is set at build time via -ldflags "-X main.version=..."
	version = "dev"

	serverFlag string
	tokenFlag  string

	runOnTarget           = client.Run
	ensureNodeForRun      = ensureNode
	resolveTargetForRun   = resolveTarget
	currentExecutablePath = os.Executable
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cw",
		Short: "Codewire CLI",
		Long: `  ▸ codewire

  Networks, environments, runs, messages, and agent tooling.

  Mental model:
    Relay network
      |
      +-- Environment
            |
            +-- Shell (` + "`cw shell`" + `)
            |
            +-- Codewire runtime
                  |
                  +-- Run / session (` + "`cw exec --name`" + `)
                        |
                        +-- Terminal (` + "`cw attach`" + `)
                        +-- Output (` + "`cw logs`" + `, ` + "`cw watch`" + `)
                        +-- Messages (` + "`cw msg`" + `, ` + "`cw inbox`" + `, ` + "`cw listen`" + `)

  Example:
    cw env create --image full
    cw use my-env
    cw shell
    cw exec --name claude -- claude
    cw attach claude

  Or run directly in the selected environment:
    cw exec my-env -- claude`,
		Version:      version,
		SilenceUsage: true,
	}
	rootCmd.PersistentFlags().StringVarP(&serverFlag, "server", "s", "", "Connect to a remote Codewire node or relay URL")
	rootCmd.PersistentFlags().StringVar(&tokenFlag, "token", "", "Auth token for remote server")

	// Disable cobra's auto-generated completion command; we supply our own with --install support.
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddGroup(
		&cobra.Group{ID: "network", Title: "Networking:"},
		&cobra.Group{ID: "environment", Title: "Environments:"},
		&cobra.Group{ID: "session", Title: "Sessions:"},
		&cobra.Group{ID: "messaging", Title: "Messaging:"},
		&cobra.Group{ID: "agent", Title: "Agent Interactions:"},
		&cobra.Group{ID: "platform", Title: "Platform:"},
		&cobra.Group{ID: "system", Title: "System:"},
	)

	rootCmd.AddCommand(
		// Networking
		grouped(networkCmd(), "network"),
		grouped(groupCmd(), "network"),
		grouped(nodeCmd(), "network"),
		grouped(relayCmd(), "network"),
		// Environments
		grouped(envParentCmd(), "environment"),
		grouped(localParentCmd(), "environment"),
		grouped(initCmd(), "environment"),
		grouped(presetParentCmd(), "environment"),
		grouped(useCmd(), "environment"),
		grouped(currentCmd(), "environment"),
		grouped(execCmd(), "environment"),
		grouped(shellCmd(), "environment"),
		grouped(vscodeCmd(), "environment"),
		grouped(platformListCmd(), "environment"),
		// Sessions
		grouped(attachCmd(), "session"),
		grouped(killCmd(), "session"),
		grouped(logsCmd(), "session"),
		grouped(sendCmd(), "session"),
		grouped(watchCmd(), "session"),
		grouped(statusCmd(), "session"),
		grouped(tasksCmd(), "session"),
		grouped(subscribeCmd(), "session"),
		grouped(waitSessionCmd(), "session"),
		// Messaging
		grouped(accessCmd(), "messaging"),
		grouped(msgCmd(), "messaging"),
		grouped(inboxCmd(), "messaging"),
		grouped(requestCmd(), "messaging"),
		grouped(replyCmd(), "messaging"),
		grouped(listenCmd(), "messaging"),
		// Agent Integration
		grouped(mcpServerCmd(), "agent"),
		// Platform
		grouped(loginCmd(), "platform"),
		grouped(logoutCmd(), "platform"),
		grouped(whoamiCmd(), "platform"),
		grouped(orgsCmd(), "platform"),
		grouped(resourcesCmd(), "platform"),
		grouped(secretsCmd(), "platform"),
		grouped(apiKeysCmd(), "platform"),
		grouped(costCmd(), "platform"),
		grouped(billingCmd(), "platform"),
		grouped(githubCmd(), "platform"),
		grouped(platformSetupCmd(), "platform"),
		grouped(configSSHCmd(), "platform"),
		// System
		grouped(completionCmd(rootCmd), "system"),
		grouped(updateCmd(), "system"),
		grouped(doctorCmd(), "system"),
	)

	printUpdateNotice := update.BackgroundCheck(version)
	err := rootCmd.Execute()
	if !isUpdateCommand() {
		printUpdateNotice()
	}
	if err != nil {
		os.Exit(1)
	}
}

func wrapLocalRuntimeRunCommand(instance *config.LocalInstance, workDir string, command []string) ([]string, string, error) {
	if instance == nil {
		return nil, "", fmt.Errorf("local instance is required")
	}
	exe, err := currentExecutablePath()
	if err != nil {
		return nil, "", fmt.Errorf("resolve current executable: %w", err)
	}

	guestWorkDir := strings.TrimSpace(workDir)
	if guestWorkDir == "" {
		guestWorkDir = instance.Workdir
	}
	if guestWorkDir == "" {
		guestWorkDir = localWorkspacePath
	}

	hostWorkDir := strings.TrimSpace(instance.RepoPath)
	if hostWorkDir == "" {
		hostWorkDir = "."
	}

	args := []string{exe, "exec", "-it", "--workdir", guestWorkDir, instance.Name, "--"}
	args = append(args, command...)
	return args, hostWorkDir, nil
}

// isUpdateCommand returns true when the user invoked "cw update".
func isUpdateCommand() bool {
	for _, arg := range os.Args[1:] {
		if arg == "update" {
			return true
		}
		if !strings.HasPrefix(arg, "-") {
			return false
		}
	}
	return false
}

// grouped sets GroupID on cmd and returns it, for use in AddCommand chains.
func grouped(cmd *cobra.Command, id string) *cobra.Command {
	cmd.GroupID = id
	return cmd
}

// ---------------------------------------------------------------------------
// nodeCmd — "cw node" starts the node, "cw node stop" stops it
// ---------------------------------------------------------------------------

func nodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Start the codewire node",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := dataDir()
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("creating data dir: %w", err)
			}

			n, err := node.NewNode(dir)
			if err != nil {
				return fmt.Errorf("initializing node: %w", err)
			}
			defer n.Cleanup()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			go func() {
				<-sigCh
				fmt.Fprintln(os.Stderr, "[cw] shutting down...")
				cancel()
			}()

			return n.Run(ctx)
		},
	}
	cmd.AddCommand(nodeStopCmd(), nodeQRCmd(), nodeListCmd())
	return cmd
}

func nodeStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the running node",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath := filepath.Join(dataDir(), "codewire.pid")
			data, err := os.ReadFile(pidPath)
			if err != nil {
				return fmt.Errorf("reading pid file: %w (is the node running?)", err)
			}

			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				return fmt.Errorf("invalid pid file: %w", err)
			}

			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
				if err == syscall.ESRCH {
					// Process already gone — clean up stale files.
					_ = os.Remove(pidPath)
					fmt.Fprintln(os.Stderr, "[cw] node already stopped (stale pid file removed)")
					return nil
				}
				return fmt.Errorf("sending SIGTERM to pid %d: %w", pid, err)
			}

			fmt.Fprintf(os.Stderr, "[cw] sent SIGTERM to node (pid %d)\n", pid)
			return nil
		},
	}
}

func appendGroupTag(tags []string, group string) []string {
	group = strings.TrimSpace(group)
	if group == "" {
		return tags
	}
	groupTag := "group:" + group
	for _, tag := range tags {
		if strings.TrimSpace(tag) == groupTag {
			return tags
		}
	}
	return append(tags, groupTag)
}

func validateLocalGroupedRun(group string) error {
	if _, err := currentNodeName(); err != nil {
		return err
	}
	_, _, _, err := client.LoadRelayAuth(dataDir(), client.RelayAuthOptions{})
	if err != nil {
		return fmt.Errorf("--group requires relay configuration: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// listCmd
// ---------------------------------------------------------------------------
// attachCmd
// ---------------------------------------------------------------------------

func attachCmd() *cobra.Command {
	var noHistory bool

	cmd := &cobra.Command{
		Use:               "attach [session]",
		Short:             "Open the interactive terminal for a run",
		ValidArgsFunction: sessionCompletionFunc,
		Long: `Attach to a running session's PTY for interactive use.

Use this for a specific Codewire run.
Use 'cw shell' for a shell in the environment itself.

Detach without killing: press Ctrl+B d
The session continues running after you detach.

Warning: Ctrl+C sends SIGINT to the session process — use Ctrl+B d to detach safely.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for node:session syntax (remote attach over tailnet).
			if len(args) > 0 {
				loc, err := parseSessionLocator(args[0])
				if err != nil {
					return err
				}
				if loc.isRemote() {
					return attachRemoteSession(cmd.Context(), loc, noHistory)
				}
			}

			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			var id *uint32
			if len(args) > 0 {
				resolved, err := client.ResolveSessionArg(target, args[0])
				if err != nil {
					return err
				}
				id = &resolved
			}

			return client.Attach(target, id, noHistory)
		},
	}

	cmd.Flags().BoolVar(&noHistory, "no-history", false, "Do not replay session history")

	return cmd
}

// ---------------------------------------------------------------------------
// killCmd
// ---------------------------------------------------------------------------

func killCmd() *cobra.Command {
	var (
		all  bool
		tags []string
	)

	cmd := &cobra.Command{
		Use:               "kill [session]",
		Short:             "Kill a session (by ID, name, or tag), or all sessions",
		ValidArgsFunction: sessionCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			if all {
				return client.KillAll(target)
			}

			if len(tags) > 0 {
				return client.KillByTags(target, tags)
			}

			if len(args) == 0 {
				return fmt.Errorf("session id, name, or tag required (or use --all / --tag)")
			}

			id, tagList, err := client.ResolveSessionOrTag(target, args[0])
			if err != nil {
				return err
			}
			if len(tagList) > 0 {
				return client.KillByTags(target, tagList)
			}
			return client.Kill(target, *id)
		},
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Kill all sessions")
	cmd.Flags().StringSliceVarP(&tags, "tag", "t", nil, "Kill sessions matching tag (can be repeated)")
	_ = cmd.RegisterFlagCompletionFunc("tag", tagCompletionFunc)

	return cmd
}

// ---------------------------------------------------------------------------
// logsCmd
// ---------------------------------------------------------------------------

func logsCmd() *cobra.Command {
	var (
		follow bool
		tail   int
		raw    bool
	)

	cmd := &cobra.Command{
		Use:               "logs <session>",
		Short:             "Show saved output for a run",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: sessionCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			resolved, err := client.ResolveSessionArg(target, args[0])
			if err != nil {
				return err
			}

			var tailPtr *int
			if cmd.Flags().Changed("tail") {
				tailPtr = &tail
			}

			return client.Logs(target, resolved, follow, tailPtr, raw)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().IntVarP(&tail, "tail", "t", 0, "Number of lines to show from end")
	cmd.Flags().BoolVar(&raw, "raw", false, "Output raw log data without stripping ANSI escape codes")

	return cmd
}

// ---------------------------------------------------------------------------
// sendCmd
// ---------------------------------------------------------------------------

func sendCmd() *cobra.Command {
	var (
		useStdin  bool
		file      string
		noNewline bool
		paste     bool
		typed     bool
	)

	cmd := &cobra.Command{
		Use:               "send <session> [input]",
		Short:             "Send input to a session (by ID or name)",
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: sessionCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			resolved, err := client.ResolveSessionArg(target, args[0])
			if err != nil {
				return err
			}

			var input *string
			if len(args) > 1 {
				input = &args[1]
			}

			var filePtr *string
			if cmd.Flags().Changed("file") {
				filePtr = &file
			}

			return client.SendInput(target, resolved, input, useStdin, filePtr, noNewline, paste, typed)
		},
	}

	cmd.Flags().BoolVar(&useStdin, "stdin", false, "Read input from stdin")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Read input from file")
	cmd.Flags().BoolVarP(&noNewline, "no-newline", "n", false, "Do not append newline")
	cmd.Flags().BoolVar(&paste, "paste", false, "Wrap input in bracketed paste markers + carriage return (use for TUIs like codex-cli that mis-parse raw typed input). Implies no automatic trailing newline.")
	cmd.Flags().BoolVar(&typed, "type", false, "Send input one byte at a time as live keystrokes (use to fire slash commands and autocomplete in TUIs like Claude Code). Trailing Enter is sent as \\r unless --no-newline. Mutually exclusive with --paste.")

	return cmd
}

// ---------------------------------------------------------------------------
// watchCmd
// ---------------------------------------------------------------------------

func watchCmd() *cobra.Command {
	var (
		tail      int
		noHistory bool
		timeout   uint64
	)

	cmd := &cobra.Command{
		Use:               "watch <session>",
		Short:             "Stream run output until it finishes",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: sessionCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			id, tagList, err := client.ResolveSessionOrTag(target, args[0])
			if err != nil {
				return err
			}

			if len(tagList) > 0 {
				var timeoutPtr *uint64
				if cmd.Flags().Changed("timeout") {
					timeoutPtr = &timeout
				}
				return client.WatchMultiByTag(target, tagList[0], os.Stdout, timeoutPtr)
			}

			var tailPtr *int
			if cmd.Flags().Changed("tail") {
				tailPtr = &tail
			}
			var timeoutPtr *uint64
			if cmd.Flags().Changed("timeout") {
				timeoutPtr = &timeout
			}
			return client.WatchSession(target, *id, tailPtr, noHistory, timeoutPtr)
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "t", 0, "Number of lines to show from end")
	cmd.Flags().BoolVar(&noHistory, "no-history", false, "Do not replay session history")
	cmd.Flags().Uint64Var(&timeout, "timeout", 0, "Timeout in seconds")

	return cmd
}

// ---------------------------------------------------------------------------
// statusCmd
// ---------------------------------------------------------------------------

func statusCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:               "status <session>",
		Short:             "Show detailed status for a run",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: sessionCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			resolved, err := client.ResolveSessionArg(target, args[0])
			if err != nil {
				return err
			}

			return client.GetStatus(target, resolved, jsonOutput)
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")

	return cmd
}

// ---------------------------------------------------------------------------
// mcpServerCmd
// ---------------------------------------------------------------------------

func mcpServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-server",
		Short: "Expose Codewire tools over MCP",
		Long: `Run the Codewire MCP server (communicates over stdio).

Register with Claude Code:
  claude mcp add --scope user codewire -- cw mcp-server

The node must be running before MCP tools work:
  cw node -d

The MCP server does not auto-start a node.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureNode(); err != nil {
				return err
			}
			return mcp.RunMCPServer(dataDir())
		},
	}
}

// ---------------------------------------------------------------------------
// networksCmd — list networks from relay
// ---------------------------------------------------------------------------

func networksCmd() *cobra.Command {
	var (
		relayURL  string
		authToken string
	)
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List relay networks you can use",
		Aliases: []string{"networks"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.Networks(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
			})
		},
	}
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override (useful for local token-auth relays)")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

// ---------------------------------------------------------------------------
// createNetworkCmd — create a relay network
// ---------------------------------------------------------------------------

func createNetworkCmd() *cobra.Command {
	var (
		relayURL  string
		authToken string
		noUse     bool
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a relay network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.CreateNetwork(dataDir(), args[0], client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
			}, !noUse)
		},
	}
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override (useful for local token-auth relays)")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	cmd.Flags().BoolVar(&noUse, "no-use", false, "Create the network without selecting it locally")
	return cmd
}

// ---------------------------------------------------------------------------
// useNetworkCmd — select the local default relay network
// ---------------------------------------------------------------------------

func useNetworkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Select the default relay network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.UseNetwork(dataDir(), args[0])
		},
	}
}

func clearNetworkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Clear the default relay network",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.ClearNetwork(dataDir())
		},
	}
}

func currentNetworkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the default relay network",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig(dataDir())
			if err != nil {
				return err
			}
			if cfg.RelaySelectedNetwork == nil || strings.TrimSpace(*cfg.RelaySelectedNetwork) == "" {
				fmt.Println("none")
				return nil
			}
			fmt.Println(strings.TrimSpace(*cfg.RelaySelectedNetwork))
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// nodeListCmd / nodesCmd — list nodes from relay
// ---------------------------------------------------------------------------

func newNodeListCmd(use, short string) *cobra.Command {
	var (
		networkID string
		all       bool
		relayURL  string
		authToken string
	)
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all && strings.TrimSpace(networkID) != "" {
				return fmt.Errorf("--all and --network cannot be used together")
			}
			return client.Nodes(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
				All:       all,
			})
		},
	}
	cmd.Flags().StringVar(&networkID, "network", "", "Network to list (default: current network)")
	cmd.Flags().BoolVar(&all, "all", false, "List nodes across all networks")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override (useful for local token-auth relays)")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func nodeListCmd() *cobra.Command {
	return newNodeListCmd("list", "List nodes in relay networks")
}

func nodesCmd() *cobra.Command {
	return newNodeListCmd("nodes", "List nodes in the default relay network")
}

// ---------------------------------------------------------------------------
// subscribeCmd — subscribe to session events
// ---------------------------------------------------------------------------

func subscribeCmd() *cobra.Command {
	var (
		tags       []string
		eventTypes []string
	)

	cmd := &cobra.Command{
		Use:   "subscribe [target]",
		Short: "Stream low-level run events",
		Long: `Stream low-level run events such as status changes, output summaries,
and message events.

This is mainly for debugging or automation. For message traffic, use:
  cw listen

For terminal output, use:
  cw watch
  cw logs --follow`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			var sid *uint32
			var resolvedTags []string
			if len(args) > 0 {
				id, tagList, err := client.ResolveSessionOrTag(target, args[0])
				if err != nil {
					return err
				}
				sid = id
				resolvedTags = tagList
			}
			allTags := append(resolvedTags, tags...)

			return client.SubscribeEvents(target, sid, allTags, eventTypes)
		},
	}

	cmd.Flags().StringSliceVarP(&tags, "tag", "t", nil, "Filter by tag (can be repeated)")
	cmd.Flags().StringSliceVarP(&eventTypes, "event", "e", nil, "Filter by event type (can be repeated)")
	_ = cmd.RegisterFlagCompletionFunc("tag", tagCompletionFunc)
	_ = cmd.RegisterFlagCompletionFunc("event", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"session.created",
			"session.status",
			"session.output_summary",
			"message.direct",
			"message.request",
			"message.reply",
		}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

// ---------------------------------------------------------------------------
// waitSessionCmd — wait for session(s) to complete
// ---------------------------------------------------------------------------

func waitSessionCmd() *cobra.Command {
	var (
		tags      []string
		condition string
		timeout   uint64
	)

	cmd := &cobra.Command{
		Use:   "wait [session]",
		Short: "Wait for runs to complete",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			var sid *uint32
			var resolvedTags []string
			if len(args) > 0 {
				id, tagList, err := client.ResolveSessionOrTag(target, args[0])
				if err != nil {
					return err
				}
				sid = id
				resolvedTags = tagList
			}
			allTags := append(resolvedTags, tags...)

			var timeoutPtr *uint64
			if cmd.Flags().Changed("timeout") {
				timeoutPtr = &timeout
			}

			return client.WaitForSession(target, sid, allTags, condition, timeoutPtr)
		},
	}

	cmd.Flags().StringSliceVarP(&tags, "tag", "t", nil, "Wait for sessions matching tag (can be repeated)")
	cmd.Flags().StringVarP(&condition, "condition", "c", "all", "Wait condition: all or any")
	cmd.Flags().Uint64Var(&timeout, "timeout", 0, "Timeout in seconds")
	_ = cmd.RegisterFlagCompletionFunc("tag", tagCompletionFunc)
	_ = cmd.RegisterFlagCompletionFunc("condition", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"all", "any"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

// serverCmd — subcommand group
// ---------------------------------------------------------------------------

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Manage saved server connections",
	}

	cmd.AddCommand(
		serverAddCmd(),
		serverRemoveCmd(),
		serverListCmd(),
	)

	return cmd
}

func serverAddCmd() *cobra.Command {
	var token string

	cmd := &cobra.Command{
		Use:   "add <name> <url>",
		Short: "Add a server connection",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			url := args[1]

			dir := dataDir()
			servers, err := config.LoadServersConfig(dir)
			if err != nil {
				return err
			}

			servers.Servers[name] = config.ServerEntry{
				URL:   url,
				Token: token,
			}

			if err := servers.Save(dir); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Server %q added\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Auth token for the server (optional for relay URLs)")

	return cmd
}

func serverRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a saved server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dir := dataDir()

			servers, err := config.LoadServersConfig(dir)
			if err != nil {
				return err
			}

			if _, ok := servers.Servers[name]; !ok {
				return fmt.Errorf("server %q not found", name)
			}

			delete(servers.Servers, name)

			if err := servers.Save(dir); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Server %q removed\n", name)
			return nil
		},
	}
}

func serverListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List saved servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			servers, err := config.LoadServersConfig(dataDir())
			if err != nil {
				return err
			}

			if len(servers.Servers) == 0 {
				fmt.Println("No saved servers")
				return nil
			}

			fmt.Printf("%-20s %s\n", "NAME", "URL")
			for name, entry := range servers.Servers {
				fmt.Printf("%-20s %s\n", name, entry.URL)
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// qrCmd — show SSH connection QR code
// ---------------------------------------------------------------------------

func nodeQRCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "qr",
		Short: "Show QR code for SSH access to this node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.SSHQRCode(dataDir(), port)
		},
	}

	cmd.Flags().IntVar(&port, "port", 2222, "SSH port on the relay")

	return cmd
}

// ---------------------------------------------------------------------------
// relayServeCmd
// ---------------------------------------------------------------------------

func relayServeCmd() *cobra.Command {
	var (
		baseURL            string
		listen             string
		sshListen          string
		relayDir           string
		authMode           string
		authToken          string
		allowedUsers       []string
		githubClientID     string
		githubClientSecret string
		oidcIssuer         string
		oidcClientID       string
		oidcClientSecret   string
		oidcAllowedGroups  []string
		databaseURL        string
		natsURL            string
		natsCredsFile      string
		natsSubjectRoot    string
		taskEventsStream   string
		taskLatestBucket   string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run a CodeWire relay server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if baseURL == "" {
				return fmt.Errorf("--base-url is required")
			}

			if relayDir == "" {
				relayDir = filepath.Join(dataDir(), "relay")
			}

			if err := os.MkdirAll(relayDir, 0o755); err != nil {
				return fmt.Errorf("creating relay data dir: %w", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			go func() {
				<-sigCh
				fmt.Fprintln(os.Stderr, "[cw] relay shutting down...")
				cancel()
			}()

			return relay.RunRelay(ctx, relay.RelayConfig{
				BaseURL:            baseURL,
				ListenAddr:         listen,
				SSHListenAddr:      sshListen,
				DataDir:            relayDir,
				AuthMode:           authMode,
				AuthToken:          authToken,
				AllowedUsers:       allowedUsers,
				GitHubClientID:     githubClientID,
				GitHubClientSecret: githubClientSecret,
				OIDCIssuer:         oidcIssuer,
				OIDCClientID:       oidcClientID,
				OIDCClientSecret:   oidcClientSecret,
				OIDCAllowedGroups:  oidcAllowedGroups,
				DatabaseURL:        databaseURL,
				NATSURL:            natsURL,
				NATSCredsFile:      natsCredsFile,
				NATSSubjectRoot:    natsSubjectRoot,
				TaskEventsStream:   taskEventsStream,
				TaskLatestBucket:   taskLatestBucket,
			})
		},
	}

	cmd.Flags().StringVar(&baseURL, "base-url", "", "Public base URL of the relay (e.g. https://relay.codewire.sh)")
	cmd.Flags().StringVar(&listen, "listen", ":8080", "HTTP listen address")
	cmd.Flags().StringVar(&sshListen, "ssh-listen", ":2222", "SSH listen address")
	cmd.Flags().StringVar(&relayDir, "data-dir", "", "Data directory for relay (default: ~/.codewire/relay)")
	cmd.Flags().StringVar(&authMode, "auth-mode", "none", "Auth mode: none, token, github, oidc")
	_ = cmd.RegisterFlagCompletionFunc("auth-mode", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"none", "token", "github", "oidc"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.Flags().StringVar(&authToken, "auth-token", "", "Admin auth token (for --auth-mode=token or as fallback for headless/CI)")
	cmd.Flags().StringSliceVar(&allowedUsers, "allowed-users", nil, "GitHub usernames allowed to authenticate (GitHub mode)")
	cmd.Flags().StringVar(&githubClientID, "github-client-id", "", "Manual GitHub OAuth App client ID (for private networks)")
	cmd.Flags().StringVar(&githubClientSecret, "github-client-secret", "", "Manual GitHub OAuth App client secret")
	cmd.Flags().StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC provider issuer URL (for --auth-mode=oidc)")
	cmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID")
	cmd.Flags().StringVar(&oidcClientSecret, "oidc-client-secret", "", "OIDC client secret")
	cmd.Flags().StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "PostgreSQL connection URL (uses SQLite if empty)")
	cmd.Flags().StringSliceVar(&oidcAllowedGroups, "oidc-allowed-groups", nil, "OIDC groups required for access (empty = any authenticated user)")
	cmd.Flags().StringVar(&natsURL, "nats-url", os.Getenv("NATS_URL"), "NATS server URL for JetStream-backed relay task events")
	cmd.Flags().StringVar(&natsCredsFile, "nats-creds", os.Getenv("NATS_CREDS"), "NATS user credentials file")
	cmd.Flags().StringVar(&natsSubjectRoot, "nats-subject-root", "tasks", "NATS subject prefix for task events")
	cmd.Flags().StringVar(&taskEventsStream, "task-events-stream", "TASK_EVENTS", "JetStream stream name for task events")
	cmd.Flags().StringVar(&taskLatestBucket, "task-latest-bucket", "TASK_LATEST", "JetStream KV bucket for latest task state")

	return cmd
}

// ---------------------------------------------------------------------------
// relayCmd
// ---------------------------------------------------------------------------

func relayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Run relay infrastructure",
	}

	cmd.AddCommand(
		relayServeCmd(),
	)

	return cmd
}

// ---------------------------------------------------------------------------
// networkCmd
// ---------------------------------------------------------------------------

func networkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "network",
		Aliases: []string{"networks"},
		Short:   "Manage relay networks for environments and nodes",
	}

	cmd.AddCommand(
		networksCmd(),
		createNetworkCmd(),
		joinNetworkCmd(),
		enrollCmd(),
		currentNetworkCmd(),
		useNetworkCmd(),
		clearNetworkCmd(),
		nodesCmd(),
		inviteCmd(),
		revokeCmd(),
	)

	return cmd
}

func enrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Create or redeem node enrollment grants",
	}

	cmd.AddCommand(
		enrollCreateCmd(),
		enrollRedeemCmd(),
	)

	return cmd
}

func enrollCreateCmd() *cobra.Command {
	var (
		nodeName  string
		uses      int
		ttl       string
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a short-lived node enrollment token",
		RunE: func(cmd *cobra.Command, args []string) error {
			enrollment, err := client.CreateNodeEnrollment(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}, nodeName, uses, ttl)
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Enrollment created\n\n")
			fmt.Fprintf(os.Stderr, "  Token:   %s\n", enrollment.EnrollmentToken)
			fmt.Fprintf(os.Stderr, "  Network: %s\n", enrollment.NetworkID)
			if enrollment.NodeName != "" {
				fmt.Fprintf(os.Stderr, "  Node:    %s\n", enrollment.NodeName)
			}
			fmt.Fprintf(os.Stderr, "  Uses:    %d\n", enrollment.UsesRemaining)
			fmt.Fprintf(os.Stderr, "  Expires: %s\n", enrollment.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&nodeName, "node-name", "", "Optional node name to bind the enrollment to")
	cmd.Flags().IntVar(&uses, "uses", 1, "Number of times the enrollment can be redeemed")
	cmd.Flags().StringVar(&ttl, "ttl", "10m", "Time-to-live for the enrollment (e.g. 5m, 10m, 1h)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to create the enrollment in (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func enrollRedeemCmd() *cobra.Command {
	var (
		nodeName string
		relayURL string
	)

	cmd := &cobra.Command{
		Use:   "redeem <token>",
		Short: "Redeem a node enrollment token and store the resulting node token locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.EnrollNode(dataDir(), client.RelayAuthOptions{
				RelayURL: relayURL,
			}, args[0], nodeName)
		},
	}

	cmd.Flags().StringVar(&nodeName, "node-name", "", "Node name to redeem as (required unless embedded in the enrollment)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	return cmd
}

func joinNetworkCmd() *cobra.Command {
	var relayURL string

	cmd := &cobra.Command{
		Use:   "join <invite>",
		Short: "Join a network from an invite token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(relayURL) == "" {
				resolved, err := resolveRelayURL()
				if err != nil {
					return err
				}
				relayURL = resolved
			}
			return client.JoinNetwork(dataDir(), relayURL, args[0])
		},
	}
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	return cmd
}

// ---------------------------------------------------------------------------
// inviteCmd — create an invite code for device onboarding
// ---------------------------------------------------------------------------

func inviteCmd() *cobra.Command {
	var (
		uses      int
		ttl       string
		qr        bool
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Create an invite for the selected network",
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.Invite(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}, uses, ttl, qr)
		},
	}

	cmd.Flags().IntVar(&uses, "uses", 1, "Number of times the invite can be used")
	cmd.Flags().StringVar(&ttl, "ttl", "1h", "Time-to-live for the invite (e.g. 5m, 1h, 24h)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to create the invite in (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override (useful for local token-auth relays)")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	cmd.Flags().BoolVar(&qr, "qr", false, "Print QR code for the invite URL")

	return cmd
}

// ---------------------------------------------------------------------------
// revokeCmd — revoke a node's access
// ---------------------------------------------------------------------------

func revokeCmd() *cobra.Command {
	var (
		networkID string
		relayURL  string
		authToken string
	)
	cmd := &cobra.Command{
		Use:   "revoke <node-name>",
		Short: "Revoke a node from the selected network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.Revoke(dataDir(), args[0], client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			})
		},
	}
	cmd.Flags().StringVar(&networkID, "network", "", "Network for the target node (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override (useful for local token-auth relays)")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

// ---------------------------------------------------------------------------
// msgCmd — send a direct message to a session
// ---------------------------------------------------------------------------

func msgCmd() *cobra.Command {
	var (
		from     string
		delivery string
	)

	cmd := &cobra.Command{
		Use:   "msg <target> <body>",
		Short: "Send a message to a run",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			toLocator, err := parseSessionLocator(args[0])
			if err != nil {
				return err
			}
			toLocator, err = normalizeSessionLocatorForCurrentNode(toLocator)
			if err != nil {
				return err
			}

			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if toLocator.isRemote() {
				if !target.IsLocal() {
					return fmt.Errorf("remote session locators like %q cannot be combined with --server; use the session ID or name on that server directly", args[0])
				}
				if from == "" {
					if envID := os.Getenv("CW_SESSION_ID"); envID != "" {
						from = envID
					}
				}
				var (
					peerFrom  *peer.SessionLocator
					senderCap string
				)
				if from != "" {
					fromLocator, err := parseSessionLocator(from)
					if err != nil {
						return err
					}
					fromLocator, err = normalizeSessionLocatorForCurrentNode(fromLocator)
					if err != nil {
						return err
					}
					if fromLocator.isRemote() {
						return fmt.Errorf("remote sender locators like %q are not allowed here; the sender session must be owned by the current local node", from)
					}
					if err := ensureNode(); err != nil {
						return err
					}
					peerFrom, senderCap, err = issueRemoteSenderDelegation(target, fromLocator, "msg", toLocator.Node)
					if err != nil {
						return err
					}
				}

				ctx := context.Background()
				peerConn, cleanup, err := dialPeerClientForNode(ctx, toLocator.Node)
				if err != nil {
					return err
				}
				defer cleanup()

				msgID, err := peerclient.Msg(ctx, peerConn, peerFrom, senderCap, toPeerSessionLocator(toLocator), args[1], resolveRemoteDelivery(delivery))
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "Message sent: %s\n", msgID)
				return nil
			}

			if from == "" {
				if envID := os.Getenv("CW_SESSION_ID"); envID != "" {
					from = envID
				}
			}

			if from != "" {
				fromLocator, err := parseSessionLocator(from)
				if err != nil {
					return err
				}
				fromLocator, err = normalizeSessionLocatorForCurrentNode(fromLocator)
				if err != nil {
					return err
				}
				if fromLocator.isRemote() {
					if !target.IsLocal() {
						return fmt.Errorf("remote sender locators like %q cannot be combined with --server; use the sender session ID or name on that server directly", from)
					}
					return fmt.Errorf("remote sender locators like %q are not wired yet; the network peer transport is implemented only as a foundation in this branch", from)
				}
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			toArg := toLocator.Name
			if toLocator.ID != nil {
				toArg = fmt.Sprintf("%d", *toLocator.ID)
			}

			toID, err := client.ResolveSessionArg(target, toArg)
			if err != nil {
				return err
			}

			var fromID *uint32
			if from != "" {
				resolved, err := client.ResolveSessionArg(target, from)
				if err != nil {
					return err
				}
				fromID = &resolved
			}

			resolved := resolveDelivery(delivery, from)
			return client.Msg(target, fromID, toID, args[1], resolved)
		},
	}

	cmd.Flags().StringVarP(&from, "from", "f", "", "Sender session (ID or name)")
	cmd.Flags().StringVar(&delivery, "delivery", "auto", "Delivery mode: auto|inbox|pty|both")

	return cmd
}

// resolveDelivery resolves the "auto" delivery mode: if the sender is another
// session (--from or CW_SESSION_ID), use "both" (inbox + PTY); otherwise "inbox".
func resolveDelivery(delivery, from string) string {
	if delivery != "auto" {
		return delivery
	}
	if from != "" || os.Getenv("CW_SESSION_ID") != "" {
		return "both"
	}
	return "inbox"
}

// ---------------------------------------------------------------------------
// inboxCmd — read messages for a session
// ---------------------------------------------------------------------------

func inboxCmd() *cobra.Command {
	var tail int
	var observerGrant string

	cmd := &cobra.Command{
		Use:               "inbox <session>",
		Short:             "Read messages delivered to a run",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: sessionCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			locator, err := parseSessionLocator(args[0])
			if err != nil {
				return err
			}
			locator, err = normalizeSessionLocatorForCurrentNode(locator)
			if err != nil {
				return err
			}

			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if locator.isRemote() {
				if !target.IsLocal() {
					return fmt.Errorf("remote session locators like %q cannot be combined with --server; use the session ID or name on that server directly", args[0])
				}
				resolvedGrant, err := resolveObserverGrant(locator, "msg.read", observerGrant)
				if err != nil {
					return fmt.Errorf("remote inbox reads require --grant <token> or an accepted matching grant: %w", err)
				}
				ctx := context.Background()
				peerConn, cleanup, err := dialPeerClientForNode(ctx, locator.Node)
				if err != nil {
					return err
				}
				defer cleanup()

				messages, err := peerclient.InboxWithGrant(ctx, peerConn, toPeerSessionLocator(locator), resolvedGrant, tail)
				if err != nil {
					return err
				}
				printMessageResponses(messages)
				return nil
			}

			if strings.TrimSpace(observerGrant) != "" {
				return fmt.Errorf("--grant is only valid with a remote session locator like <node>:<session>")
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			sessionArg := locator.Name
			if locator.ID != nil {
				sessionArg = fmt.Sprintf("%d", *locator.ID)
			}

			sessionID, err := client.ResolveSessionArg(target, sessionArg)
			if err != nil {
				return err
			}

			return client.Inbox(target, sessionID, tail)
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "t", 50, "Number of messages to show")
	cmd.Flags().StringVar(&observerGrant, "grant", "", "Observer grant token for remote inbox reads")

	return cmd
}

// ---------------------------------------------------------------------------
// listenCmd — stream message traffic
// ---------------------------------------------------------------------------

func listenCmd() *cobra.Command {
	var sessionArg string
	var observerGrant string

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Stream message traffic in real time",
		Long: `Stream direct messages, requests, and replies in real time.

Use this to watch message traffic.
Use 'cw inbox' to read stored messages for one run.
Use 'cw subscribe' only if you need lower-level run events.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var locator *sessionLocator
			if sessionArg != "" {
				parsed, err := parseSessionLocator(sessionArg)
				if err != nil {
					return err
				}
				parsed, err = normalizeSessionLocatorForCurrentNode(parsed)
				if err != nil {
					return err
				}
				locator = &parsed
			}

			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if locator != nil && locator.isRemote() {
				if !target.IsLocal() {
					return fmt.Errorf("remote session locators like %q cannot be combined with --server; use the session ID or name on that server directly", sessionArg)
				}
				resolvedGrant, err := resolveObserverGrant(*locator, "msg.listen", observerGrant)
				if err != nil {
					return fmt.Errorf("remote message subscriptions require --grant <token> or an accepted matching grant: %w", err)
				}
				ctx := context.Background()
				peerConn, cleanup, err := dialPeerClientForNode(ctx, locator.Node)
				if err != nil {
					return err
				}
				defer cleanup()
				remoteSession := toPeerSessionLocator(*locator)
				return peerclient.ListenWithGrant(ctx, peerConn, &remoteSession, resolvedGrant, func(event *protocol.SessionEvent) error {
					if event != nil {
						printSessionEvent(event)
					}
					return nil
				})
			}

			if strings.TrimSpace(observerGrant) != "" {
				return fmt.Errorf("--grant is only valid with a remote session locator like <node>:<session>")
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			var sessionID *uint32
			if locator != nil {
				sessionLookup := locator.Name
				if locator.ID != nil {
					sessionLookup = fmt.Sprintf("%d", *locator.ID)
				}
				resolved, err := client.ResolveSessionArg(target, sessionLookup)
				if err != nil {
					return err
				}
				sessionID = &resolved
			}

			return client.Listen(target, sessionID)
		},
	}

	cmd.Flags().StringVar(&sessionArg, "session", "", "Filter by session (ID or name)")
	cmd.Flags().StringVar(&observerGrant, "grant", "", "Observer grant token for remote message subscriptions")

	return cmd
}

// ---------------------------------------------------------------------------
// requestCmd — send a request and block for reply
// ---------------------------------------------------------------------------

func requestCmd() *cobra.Command {
	var (
		from      string
		timeout   uint64
		rawOutput bool
		delivery  string
	)

	cmd := &cobra.Command{
		Use:   "request <target> <body>",
		Short: "Send a request to a run and wait for the reply",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			toLocator, err := parseSessionLocator(args[0])
			if err != nil {
				return err
			}
			toLocator, err = normalizeSessionLocatorForCurrentNode(toLocator)
			if err != nil {
				return err
			}

			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if toLocator.isRemote() {
				if !target.IsLocal() {
					return fmt.Errorf("remote session locators like %q cannot be combined with --server; use the session ID or name on that server directly", args[0])
				}
				if from == "" {
					if envID := os.Getenv("CW_SESSION_ID"); envID != "" {
						from = envID
					}
				}
				var (
					peerFrom  *peer.SessionLocator
					senderCap string
				)
				if from != "" {
					fromLocator, err := parseSessionLocator(from)
					if err != nil {
						return err
					}
					fromLocator, err = normalizeSessionLocatorForCurrentNode(fromLocator)
					if err != nil {
						return err
					}
					if fromLocator.isRemote() {
						return fmt.Errorf("remote sender locators like %q are not allowed here; the sender session must be owned by the current local node", from)
					}
					if err := ensureNode(); err != nil {
						return err
					}
					peerFrom, senderCap, err = issueRemoteSenderDelegation(target, fromLocator, "request", toLocator.Node)
					if err != nil {
						return err
					}
				}

				ctx := context.Background()
				peerConn, cleanup, err := dialPeerClientForNode(ctx, toLocator.Node)
				if err != nil {
					return err
				}
				defer cleanup()

				result, err := peerclient.Request(ctx, peerConn, peerFrom, senderCap, toPeerSessionLocator(toLocator), args[1], timeout, resolveRemoteDelivery(delivery))
				if err != nil {
					return err
				}
				printRequestReplyResult(rawOutput, result)
				return nil
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			toArg := toLocator.Name
			if toLocator.ID != nil {
				toArg = fmt.Sprintf("%d", *toLocator.ID)
			}

			toID, err := client.ResolveSessionArg(target, toArg)
			if err != nil {
				return err
			}

			if from == "" {
				if envID := os.Getenv("CW_SESSION_ID"); envID != "" {
					from = envID
				}
			}

			var fromID *uint32
			if from != "" {
				resolved, err := client.ResolveSessionArg(target, from)
				if err != nil {
					return err
				}
				fromID = &resolved
			}

			resolved := resolveDelivery(delivery, from)
			return client.Request(target, fromID, toID, args[1], timeout, rawOutput, resolved)
		},
	}

	cmd.Flags().StringVarP(&from, "from", "f", "", "Sender session (ID or name)")
	cmd.Flags().Uint64Var(&timeout, "timeout", 60, "Timeout in seconds")
	cmd.Flags().BoolVar(&rawOutput, "raw", false, "Print only the reply body without prefix")
	cmd.Flags().StringVar(&delivery, "delivery", "auto", "Delivery mode: auto|inbox|pty|both")

	return cmd
}

// ---------------------------------------------------------------------------
// replyCmd — reply to a pending request
// ---------------------------------------------------------------------------

func replyCmd() *cobra.Command {
	var from, replyToken string

	cmd := &cobra.Command{
		Use:   "reply <request-id> <body>",
		Short: "Reply to a pending request message",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var fromLocator *sessionLocator
			if from == "" {
				if envID := os.Getenv("CW_SESSION_ID"); envID != "" {
					from = envID
				}
			}
			if from != "" {
				parsed, err := parseSessionLocator(from)
				if err != nil {
					return err
				}
				parsed, err = normalizeSessionLocatorForCurrentNode(parsed)
				if err != nil {
					return err
				}
				fromLocator = &parsed
			}

			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if fromLocator != nil && fromLocator.isRemote() {
				if !target.IsLocal() {
					return fmt.Errorf("remote sender locators like %q cannot be combined with --server; use the sender session ID or name on that server directly", from)
				}
				return fmt.Errorf("remote sender locators like %q are not allowed for reply; reply as a session owned by the current local node", from)
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			var fromID *uint32
			if fromLocator != nil {
				fromValue := fromLocator.Name
				if fromLocator.ID != nil {
					fromValue = fmt.Sprintf("%d", *fromLocator.ID)
				}
				resolved, err := client.ResolveSessionArg(target, fromValue)
				if err != nil {
					return err
				}
				fromID = &resolved
			}

			return client.Reply(target, fromID, args[0], replyToken, args[1])
		},
	}

	cmd.Flags().StringVarP(&from, "from", "f", "", "Sender session (ID or name)")
	cmd.Flags().StringVar(&replyToken, "reply-token", "", "Request-scoped reply capability for system or detached responders")

	return cmd
}

// ---------------------------------------------------------------------------
// gatewayCmd — run an approval gateway for worker sessions
// ---------------------------------------------------------------------------

func gatewayCmd() *cobra.Command {
	var name, execCmd, notify string

	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Run an approval gateway for worker sessions",
		Long: `Start an approval gateway. Workers call 'cw request gateway "<action>"'
and block until the gateway replies.

The gateway creates a stub session (default name: gateway) and subscribes to
approval requests directed at it. Each request body is piped to --exec; its
stdout becomes the reply.

LLM supervisor:
  cw gateway --exec 'claude --dangerously-skip-permissions --print \
    "Policy: approve git/edit/read; deny rm -rf, DROP TABLE. \
     Request: $(cat). Reply: APPROVED or DENIED: <reason>"'

Human notification (macOS):
  cw gateway --notify macos

Combined (LLM first, macOS notification on ESCALATE):
  cw gateway --exec '...' --notify macos`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget()
			if err != nil {
				return err
			}
			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}
			return client.Gateway(target, name, execCmd, notify)
		},
	}
	cmd.Flags().StringVar(&name, "name", "gateway", "Session name to register as")
	cmd.Flags().StringVar(&execCmd, "exec", "", "Shell command to evaluate requests (body on stdin); default auto-approves all")
	cmd.Flags().StringVar(&notify, "notify", "", "Notification method: macos or ntfy:<url>")
	return cmd
}

// ---------------------------------------------------------------------------
// hookCmd — Claude Code PreToolUse hook handler
// ---------------------------------------------------------------------------

func hookCmd() *cobra.Command {
	var install bool

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Claude Code PreToolUse hook — routes tool calls through the gateway",
		Long: `Run as a Claude Code PreToolUse hook. Reads the tool call JSON from stdin,
checks if a gateway session is running, and blocks the call if the gateway
returns a DENIED reply.

Install the hook automatically:
  cw hook --install

Or add manually to ~/.claude/settings.json:
  {
    "hooks": {
      "PreToolUse": [{"hooks": [{"type": "command", "command": "cw hook"}]}]
    }
  }

Exit codes:
  0  — allow the tool call
  2  — block the tool call (decision JSON written to stdout)`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if install {
				return client.HookInstall()
			}
			target, err := resolveTarget()
			if err != nil {
				// Node not running — allow by default (don't block agent work).
				return nil
			}
			blocked, err := client.Hook(target, os.Stdin, os.Stdout)
			if err != nil {
				return err
			}
			if blocked {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "Add PreToolUse hook entry to ~/.claude/settings.json")
	return cmd
}

// ---------------------------------------------------------------------------
// completionCmd — shell completion with --install support
// ---------------------------------------------------------------------------

func completionCmd(rootCmd *cobra.Command) *cobra.Command {
	var install bool

	cmd := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate or install shell completion scripts",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MaximumNArgs(1),
		Long: `Generate shell completion scripts for cw.

Load in current session:
  source <(cw completion zsh)
  source <(cw completion bash)
  cw completion fish | source

Install permanently (no shell config required for fish/zsh+brew):
  cw completion --install`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if install {
				return completionInstall(rootCmd)
			}
			shell := "zsh"
			if len(args) > 0 {
				shell = args[0]
			}
			switch shell {
			case "bash":
				return rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell %q; use bash, zsh, fish, or powershell", shell)
			}
		},
	}

	cmd.Flags().BoolVar(&install, "install", false, "Install completion for the current shell automatically")
	return cmd
}

// completionInstall auto-detects the user's shell and writes the completion
// script to the best location — preferring places that are already on the
// completion path so no shell config changes are needed.
func completionInstall(rootCmd *cobra.Command) error {
	shellBin := os.Getenv("SHELL")
	shell := strings.ToLower(filepath.Base(shellBin))

	switch shell {
	case "zsh":
		return completionInstallZsh(rootCmd)
	case "bash":
		return completionInstallBash(rootCmd)
	case "fish":
		return completionInstallFish(rootCmd)
	default:
		return fmt.Errorf("unsupported shell %q — run 'cw completion zsh|bash|fish' and follow shell-specific instructions", shell)
	}
}

// completionInstallZsh writes _cw to the first auto-loaded zsh completion dir
// it can find: homebrew's site-functions, oh-my-zsh, or ~/.zfunc (with a hint).
func completionInstallZsh(rootCmd *cobra.Command) error {
	candidates := zshCompletionInstallCandidates()

	for _, c := range candidates {
		if c.dir == "" || c.dir == "/share/zsh/site-functions" {
			continue
		}
		if err := os.MkdirAll(c.dir, 0o755); err != nil {
			continue
		}
		dest := filepath.Join(c.dir, "_cw")
		f, err := os.Create(dest)
		if err != nil {
			continue
		}
		if err := rootCmd.GenZshCompletion(f); err != nil {
			f.Close()
			_ = os.Remove(dest)
			continue
		}
		f.Close()
		fmt.Fprintf(os.Stderr, "zsh completion installed: %s\n", dest)
		if !c.autoload {
			fmt.Fprintln(os.Stderr, "\n"+c.hint)
			fmt.Fprintln(os.Stderr, "\nThen start a new shell or run: source ~/.zshrc")
		} else {
			fmt.Fprintln(os.Stderr, "Start a new shell to activate, or run: source ~/.zshrc")
		}
		return nil
	}

	// Nothing writable — print manual instructions.
	fmt.Fprintln(os.Stderr, "Could not find a writable zsh completion directory.")
	fmt.Fprintln(os.Stderr, "Add this to ~/.zshrc:\n  source <(cw completion zsh)")
	return nil
}

type zshCompletionCandidate struct {
	dir      string
	autoload bool
	hint     string
}

func zshCompletionInstallCandidates() []zshCompletionCandidate {
	var candidates []zshCompletionCandidate
	seen := make(map[string]bool)
	add := func(dir string, autoload bool, hint string) {
		if dir == "" || seen[dir] {
			return
		}
		seen[dir] = true
		candidates = append(candidates, zshCompletionCandidate{dir: dir, autoload: autoload, hint: hint})
	}

	// Prefer zsh site-functions paths that are commonly already in $fpath.
	if prefix := brewPrefix(); prefix != "" {
		add(filepath.Join(prefix, "share/zsh/site-functions"), true, "")
	}
	add("/usr/local/share/zsh/site-functions", true, "")
	add("/usr/share/zsh/site-functions", true, "")

	// Only use Oh My Zsh's completions directory when OMZ is actually configured.
	if zshDir := os.Getenv("ZSH"); zshDir != "" {
		add(filepath.Join(zshDir, "completions"), true, "")
	}

	// ~/.zfunc needs one fpath entry in .zshrc.
	add(os.Getenv("HOME")+"/.zfunc", false, "Add these lines to ~/.zshrc (before compinit):\n"+
		"  fpath=(~/.zfunc $fpath)\n"+
		"  autoload -Uz compinit && compinit")

	return candidates
}

// completionInstallBash writes a bash completion script to the first available
// location: homebrew's bash_completion.d, or ~/.bash_completion.d.
func completionInstallBash(rootCmd *cobra.Command) error {
	candidates := []struct {
		dir      string
		autoload bool
		hint     string
	}{
		{dir: brewPrefix() + "/etc/bash_completion.d", autoload: true},
		{
			dir:      os.Getenv("HOME") + "/.bash_completion.d",
			autoload: false,
			hint:     "Add to ~/.bashrc:\n  source ~/.bash_completion.d/cw",
		},
	}

	for _, c := range candidates {
		if c.dir == "" || c.dir == "/etc/bash_completion.d" {
			continue
		}
		if err := os.MkdirAll(c.dir, 0o755); err != nil {
			continue
		}
		dest := filepath.Join(c.dir, "cw")
		f, err := os.Create(dest)
		if err != nil {
			continue
		}
		if err := rootCmd.GenBashCompletion(f); err != nil {
			f.Close()
			_ = os.Remove(dest)
			continue
		}
		f.Close()
		fmt.Fprintf(os.Stderr, "bash completion installed: %s\n", dest)
		if !c.autoload {
			fmt.Fprintln(os.Stderr, "\n"+c.hint)
			fmt.Fprintln(os.Stderr, "\nThen start a new shell or run: source ~/.bashrc")
		} else {
			fmt.Fprintln(os.Stderr, "Start a new shell to activate.")
		}
		return nil
	}

	fmt.Fprintln(os.Stderr, "Could not find a writable bash completion directory.")
	fmt.Fprintln(os.Stderr, "Add to ~/.bashrc:\n  source <(cw completion bash)")
	return nil
}

// completionInstallFish writes to ~/.config/fish/completions/cw.fish — fish
// auto-loads all files from that directory, so no config changes are needed.
func completionInstallFish(rootCmd *cobra.Command) error {
	dir := filepath.Join(os.Getenv("HOME"), ".config", "fish", "completions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	dest := filepath.Join(dir, "cw.fish")
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dest, err)
	}
	defer f.Close()
	if err := rootCmd.GenFishCompletion(f, true); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "fish completion installed: %s\n", dest)
	fmt.Fprintln(os.Stderr, "Start a new shell to activate (fish auto-loads completions).")
	return nil
}

// brewPrefix returns the output of `brew --prefix`, or "" if brew is not found.
func brewPrefix() string {
	out, err := exec.Command("brew", "--prefix").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// Completion helpers
// ---------------------------------------------------------------------------

func sessionCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	target, err := resolveTarget()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return client.ListSessionsForCompletion(target), cobra.ShellCompDirectiveNoFileComp
}

func tagCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	target, err := resolveTarget()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return client.ListTagsForCompletion(target), cobra.ShellCompDirectiveNoFileComp
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func dataDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		fmt.Fprintln(os.Stderr, "[cw] ERROR: $HOME environment variable is not set")
		fmt.Fprintln(os.Stderr, "[cw] WARNING: Using insecure fallback directory /tmp/.codewire")
		return "/tmp/.codewire"
	}
	return filepath.Join(home, ".codewire")
}

func resolveTarget() (*client.Target, error) {
	dir := dataDir()

	if serverFlag == "" {
		return &client.Target{Local: dir}, nil
	}

	url := serverFlag
	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		// Relay URL — token is optional (relay handles auth).
		return &client.Target{URL: url, Token: tokenFlag}, nil
	}

	if tokenFlag == "" {
		return nil, fmt.Errorf("--token required for ad-hoc WebSocket server")
	}

	if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		url = "ws://" + url
	}

	return &client.Target{URL: url, Token: tokenFlag}, nil
}

func ensureNode() error {
	dir := dataDir()
	sock := filepath.Join(dir, "codewire.sock")

	// Check if node is already running.
	if conn, err := net.Dial("unix", sock); err == nil {
		conn.Close()
		return nil
	}

	// Clean stale socket.
	_ = os.Remove(sock)
	_ = os.MkdirAll(dir, 0o755)

	// Spawn `cw node` in background.
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "node")
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// Write node stdout/stderr to a log file for diagnostics.
	logPath := filepath.Join(dir, "node.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
		}
		return fmt.Errorf("spawning node: %w", err)
	}
	// Close our handle; the child inherited the fd.
	if logFile != nil {
		logFile.Close()
	}
	fmt.Fprintf(os.Stderr, "[cw] node started (pid %d)\n", cmd.Process.Pid)

	// Wait for socket to become available.
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if conn, err := net.Dial("unix", sock); err == nil {
			conn.Close()
			return nil
		}
	}

	return fmt.Errorf("node failed to start (socket not available after 5s). Check %s for details", logPath)
}

func resolveRelayURL() (string, error) {
	cfg, err := config.LoadConfig(dataDir())
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}
	if cfg.RelayURL == nil || *cfg.RelayURL == "" {
		return "", fmt.Errorf("relay not configured (run 'cw login' or set CODEWIRE_RELAY_URL)")
	}
	return *cfg.RelayURL, nil
}
