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
	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/relay"
	"github.com/codewiresh/codewire/internal/update"
)

var (
	// version is set at build time via -ldflags "-X main.version=..."
	version = "dev"

	serverFlag        string
	tokenFlag         string
	workspaceOverride string // set by workspace prefix interception (e.g. "cw api run")
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "cw [workspace]",
		Short:   "Persistent process server + agent-first dev environments",
		Version: version,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if platform.HasConfig() {
					return showCurrentWorkspace()
				}
				return cmd.Help()
			}
			// Try workspace switching in platform mode
			if platform.HasConfig() {
				return switchWorkspace(args[0], false)
			}
			return fmt.Errorf("unknown command %q\nRun 'cw --help' for usage.", args[0])
		},
		SilenceUsage: true,
	}
	rootCmd.PersistentFlags().StringVarP(&serverFlag, "server", "s", "", "Connect to a remote server (name from servers.toml or ws://host:port)")
	rootCmd.PersistentFlags().StringVar(&tokenFlag, "token", "", "Auth token for remote server")

	// Disable cobra's auto-generated completion command; we supply our own with --install support.
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(
		// Session management
		nodeCmd(),
		runCmd(),
		platformListCmd(),
		attachCmd(),
		killCmd(),
		logsCmd(),
		sendCmd(),
		watchCmd(),
		statusCmd(),
		subscribeCmd(),
		waitSessionCmd(),
		// Relay
		relayCmd(),
		relaySetupCmd(),
		qrCmd(),
		nodesCmd(),
		serverCmd(),
		inviteCmd(),
		revokeCmd(),
		// Communication
		msgCmd(),
		inboxCmd(),
		requestCmd(),
		replyCmd(),
		listenCmd(),
		// Agent integration
		gatewayCmd(),
		hookCmd(),
		mcpServerCmd(),
		// KV
		kvCmd(),
		// Platform
		platformSetupCmd(),
		loginCmd(),
		logoutCmd(),
		whoamiCmd(),
		orgsCmd(),
		resourcesCmd(),
		secretsCmd(),
		costCmd(),
		billingCmd(),
		githubCmd(),
		envParentCmd(),
		tmplParentCmd(),
		// Workspaces
		launchCmd(),
		openCmd(),
		workspaceStartCmd(),
		workspaceStopCmd(),
		workspacesListCmd(),
		// Shell completion
		completionCmd(rootCmd),
		// Self-update
		updateCmd(),
	)

	// Workspace prefix interception: "cw api run -- cmd" → workspaceOverride="api"
	// Only when: platform mode, >= 3 args, first arg is not a known command or flag.
	if len(os.Args) >= 3 && platform.HasConfig() {
		candidate := os.Args[1]
		if !strings.HasPrefix(candidate, "-") && !isKnownCommand(rootCmd, candidate) {
			workspaceOverride = candidate
			os.Args = append(os.Args[:1], os.Args[2:]...)
		}
	}

	printUpdateNotice := update.BackgroundCheck(version)
	err := rootCmd.Execute()
	if !isUpdateCommand() {
		printUpdateNotice()
	}
	if err != nil {
		os.Exit(1)
	}
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

// isKnownCommand checks if name matches any registered cobra command or alias.
func isKnownCommand(root *cobra.Command, name string) bool {
	// Built-in cobra commands
	if name == "help" || name == "version" || name == "completion" {
		return true
	}
	for _, cmd := range root.Commands() {
		if cmd.Name() == name {
			return true
		}
		for _, alias := range cmd.Aliases {
			if alias == name {
				return true
			}
		}
	}
	return false
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
	cmd.AddCommand(nodeStopCmd())
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

// ---------------------------------------------------------------------------
// runCmd (alias: launch)
// ---------------------------------------------------------------------------

func runCmd() *cobra.Command {
	var (
		workDir     string
		tags        []string
		name        string
		envVars     []string
		autoApprove bool
		promptFile  string
	)

	cmd := &cobra.Command{
		Use:     "run [name] [tag] -- command...",
		Aliases: []string{},
		Short:   "Launch a new session",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Platform mode: route to remote workspace if workspace context exists
			if platform.HasConfig() {
				wsName := workspaceOverride

				if wsName != "" {
					// Remote mode — workspace context is set
					dash := cmd.ArgsLenAtDash()
					if dash == -1 {
						return fmt.Errorf("command required after --\n\nUsage: cw run [name] -- <command> [args...]")
					}

					// Positional arg before -- is session name, not workspace
					sessionName := name
					if sessionName == "" && dash >= 1 {
						sessionName = args[0]
					}

					command := args[dash:]
					if len(command) == 0 {
						return fmt.Errorf("command required after --")
					}

					return runInWorkspace(wsName, sessionName, command)
				}
				// No workspace context — fall through to standalone local mode
			}

			// Standalone mode: existing code below
			target, err := resolveTarget()
			if err != nil {
				return err
			}

			if target.IsLocal() {
				if err := ensureNode(); err != nil {
					return err
				}
			}

			dash := cmd.ArgsLenAtDash()
			if dash == -1 {
				if len(args) > 0 {
					return fmt.Errorf("missing '--' before command\n\nDid you mean: cw run -- %s\n\nUsage: cw run [name] [tag] -- <command> [args...]", strings.Join(args, " "))
				}
				return fmt.Errorf("command required\n\nUsage: cw run [name] [tag] -- <command> [args...]")
			}

			var command []string
			if dash == 2 {
				// cw run planner my-cohort -- claude -p "..."
				if name == "" {
					name = args[0]
				}
				tags = append(tags, args[1])
				command = args[2:]
			} else if dash == 1 {
				// cw launch planner -- claude -p "..."
				if name == "" {
					name = args[0]
				}
				command = args[1:]
			} else if dash == 0 {
				// cw launch -- claude -p "..."
				command = args
			} else {
				return fmt.Errorf("expected at most two positional args (name, tag) before --")
			}

			if len(command) == 0 {
				return fmt.Errorf("command required after --")
			}

			// If --auto-approve, inject --dangerously-skip-permissions after the binary.
			if autoApprove && len(command) > 0 {
				command = append([]string{command[0], "--dangerously-skip-permissions"}, command[1:]...)
			}

			// Default to current working directory if --dir not specified.
			if workDir == "" {
				workDir, _ = os.Getwd()
			}

			var stdinData []byte
			if promptFile != "" {
				var readErr error
				stdinData, readErr = os.ReadFile(promptFile)
				if readErr != nil {
					return fmt.Errorf("reading prompt file: %w", readErr)
				}
			}

			return client.Run(target, command, workDir, name, envVars, stdinData, tags...)
		},
	}

	cmd.Flags().StringVarP(&workDir, "dir", "d", "", "Working directory for the session")
	cmd.Flags().StringSliceVarP(&tags, "tag", "t", nil, "Tags for the session (can be repeated)")
	cmd.Flags().StringVar(&name, "name", "", "Unique name for the session (alphanumeric + hyphens, 1-32 chars)")
	cmd.Flags().StringArrayVarP(&envVars, "env", "e", nil, "Environment variable overrides (KEY=VALUE, can be repeated)")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "Inject --dangerously-skip-permissions after the command binary")
	cmd.Flags().StringVar(&promptFile, "prompt-file", "", "File whose contents are injected as stdin after launch")
	_ = cmd.RegisterFlagCompletionFunc("tag", tagCompletionFunc)

	return cmd
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
		Short:             "Attach to a session's PTY (by ID or name)",
		ValidArgsFunction: sessionCompletionFunc,
		Long: `Attach to a running session's PTY for interactive use.

Detach without killing: press Ctrl+B d
The session continues running after you detach.

Warning: Ctrl+C sends SIGINT to the session process — use Ctrl+B d to detach safely.`,
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
		Short:             "View session output logs (by ID or name)",
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

			return client.SendInput(target, resolved, input, useStdin, filePtr, noNewline)
		},
	}

	cmd.Flags().BoolVar(&useStdin, "stdin", false, "Read input from stdin")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Read input from file")
	cmd.Flags().BoolVarP(&noNewline, "no-newline", "n", false, "Do not append newline")

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
		Short:             "Watch session output in real-time (by ID, name, or tag for multi-session)",
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
		Short:             "Get detailed status for a session (by ID or name)",
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
		Short: "Run the MCP (Model Context Protocol) server",
		Long: `Run the Codewire MCP server (communicates over stdio).

To register with Claude Code:
  claude mcp add --scope user codewire -- cw mcp-server

The node must be running before MCP tools work:
  cw node -d

The MCP server does NOT auto-start a node.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureNode(); err != nil {
				return err
			}
			return mcp.RunMCPServer(dataDir())
		},
	}
}

// ---------------------------------------------------------------------------
// nodesCmd — list nodes from relay
// ---------------------------------------------------------------------------

func nodesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "nodes",
		Short: "List registered nodes from the relay",
		RunE: func(cmd *cobra.Command, args []string) error {
			relayURL, err := resolveRelayURL()
			if err != nil {
				return err
			}
			return client.Nodes(relayURL)
		},
	}
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
		Short: "Subscribe to session events",
		Args:  cobra.MaximumNArgs(1),
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
		Short: "Wait for session(s) to complete (by ID or name)",
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

// ---------------------------------------------------------------------------
// kvCmd — key-value store subcommand group
// ---------------------------------------------------------------------------

func kvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kv",
		Short: "Key-value store for coordination",
	}

	cmd.AddCommand(
		kvSetCmd(),
		kvGetCmd(),
		kvListCmd(),
		kvDeleteCmd(),
	)

	return cmd
}

func kvSetCmd() *cobra.Command {
	var (
		namespace string
		ttl       string
	)

	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a key-value pair",
		Args:  cobra.ExactArgs(2),
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

			return client.KVSet(target, namespace, args[0], args[1], ttl)
		},
	}

	cmd.Flags().StringVar(&namespace, "ns", "default", "Namespace")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Time-to-live (e.g. 60s, 5m)")

	return cmd
}

func kvGetCmd() *cobra.Command {
	var namespace string

	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Get a value by key",
		Args:  cobra.ExactArgs(1),
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

			return client.KVGet(target, namespace, args[0])
		},
	}

	cmd.Flags().StringVar(&namespace, "ns", "default", "Namespace")

	return cmd
}

func kvListCmd() *cobra.Command {
	var namespace string

	cmd := &cobra.Command{
		Use:   "list [prefix]",
		Short: "List keys",
		Args:  cobra.MaximumNArgs(1),
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

			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}

			return client.KVList(target, namespace, prefix)
		},
	}

	cmd.Flags().StringVar(&namespace, "ns", "default", "Namespace")

	return cmd
}

func kvDeleteCmd() *cobra.Command {
	var namespace string

	cmd := &cobra.Command{
		Use:   "delete <key>",
		Short: "Delete a key",
		Args:  cobra.ExactArgs(1),
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

			return client.KVDelete(target, namespace, args[0])
		},
	}

	cmd.Flags().StringVar(&namespace, "ns", "default", "Namespace")

	return cmd
}

// ---------------------------------------------------------------------------
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
// setupCmd
// ---------------------------------------------------------------------------

func relaySetupCmd() *cobra.Command {
	var (
		authToken string
		qr        bool
	)

	cmd := &cobra.Command{
		Use:   "relay-setup <relay-url> [token]",
		Short: "Connect this node to a relay",
		Long:  "Connect this node to a relay. With no token, uses OIDC device flow if the relay supports it.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			relayURL := args[0]
			var token string
			if len(args) > 1 {
				token = args[1]
			}

			dir := dataDir()
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("creating data dir: %w", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			go func() {
				<-sigCh
				cancel()
			}()

			return relay.RunSetup(ctx, relay.SetupOptions{
				RelayURL:  relayURL,
				DataDir:   dir,
				Token:     token,
				AuthToken: authToken,
				ShowQR:    qr,
			})
		},
	}

	cmd.Flags().StringVar(&authToken, "token", "", "Admin auth token (for headless/CI use)")
	cmd.Flags().BoolVar(&qr, "qr", false, "Print QR code with SSH connection URI (for Termius iOS)")

	return cmd
}

// ---------------------------------------------------------------------------
// qrCmd — show SSH connection QR code
// ---------------------------------------------------------------------------

func qrCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "qr",
		Short: "Show QR code for SSH access (scan with Termius)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.SSHQRCode(dataDir(), port)
		},
	}

	cmd.Flags().IntVar(&port, "port", 2222, "SSH port on the relay")

	return cmd
}

// ---------------------------------------------------------------------------
// relayCmd
// ---------------------------------------------------------------------------

func relayCmd() *cobra.Command {
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
	)

	cmd := &cobra.Command{
		Use:   "relay",
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
	cmd.Flags().StringSliceVar(&oidcAllowedGroups, "oidc-allowed-groups", nil, "OIDC groups required for access (empty = any authenticated user)")

	return cmd
}

// ---------------------------------------------------------------------------
// inviteCmd — create an invite code for device onboarding
// ---------------------------------------------------------------------------

func inviteCmd() *cobra.Command {
	var (
		uses int
		ttl  string
		qr   bool
	)

	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Create an invite code for device onboarding",
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.Invite(dataDir(), uses, ttl, qr)
		},
	}

	cmd.Flags().IntVar(&uses, "uses", 1, "Number of times the invite can be used")
	cmd.Flags().StringVar(&ttl, "ttl", "1h", "Time-to-live for the invite (e.g. 5m, 1h, 24h)")
	cmd.Flags().BoolVar(&qr, "qr", false, "Print QR code for the invite URL")

	return cmd
}

// ---------------------------------------------------------------------------
// revokeCmd — revoke a node's access
// ---------------------------------------------------------------------------

func revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <node-name>",
		Short: "Revoke a node's relay access",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.Revoke(dataDir(), args[0])
		},
	}
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
		Short: "Send a message to a session (by ID or name)",
		Args:  cobra.ExactArgs(2),
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

			toID, err := client.ResolveSessionArg(target, args[0])
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

	cmd := &cobra.Command{
		Use:               "inbox <session>",
		Short:             "Read messages for a session (by ID or name)",
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

			sessionID, err := client.ResolveSessionArg(target, args[0])
			if err != nil {
				return err
			}

			return client.Inbox(target, sessionID, tail)
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "t", 50, "Number of messages to show")

	return cmd
}

// ---------------------------------------------------------------------------
// listenCmd — stream message traffic
// ---------------------------------------------------------------------------

func listenCmd() *cobra.Command {
	var sessionArg string

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Stream all message traffic in real-time",
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

			var sessionID *uint32
			if sessionArg != "" {
				resolved, err := client.ResolveSessionArg(target, sessionArg)
				if err != nil {
					return err
				}
				sessionID = &resolved
			}

			return client.Listen(target, sessionID)
		},
	}

	cmd.Flags().StringVar(&sessionArg, "session", "", "Filter by session (ID or name)")

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
		Short: "Send a request to a session and wait for a reply",
		Args:  cobra.ExactArgs(2),
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

			toID, err := client.ResolveSessionArg(target, args[0])
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
	var from string

	cmd := &cobra.Command{
		Use:   "reply <request-id> <body>",
		Short: "Reply to a pending request",
		Args:  cobra.ExactArgs(2),
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

			return client.Reply(target, fromID, args[0], args[1])
		},
	}

	cmd.Flags().StringVarP(&from, "from", "f", "", "Sender session (ID or name)")

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
	candidates := []struct {
		dir      string
		autoload bool // true = no shell config change needed
		hint     string
	}{
		// Homebrew's zsh site-functions are already in $fpath for all brew users.
		{dir: brewPrefix() + "/share/zsh/site-functions", autoload: true},
		// Oh My Zsh custom completions are auto-loaded.
		{dir: os.Getenv("HOME") + "/.oh-my-zsh/completions", autoload: true},
		// ~/.zfunc needs one fpath entry in .zshrc.
		{
			dir:      os.Getenv("HOME") + "/.zfunc",
			autoload: false,
			hint: "Add these lines to ~/.zshrc (before compinit):\n" +
				"  fpath=(~/.zfunc $fpath)\n" +
				"  autoload -Uz compinit && compinit",
		},
	}

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

	// Check servers.toml for a named entry.
	servers, err := config.LoadServersConfig(dir)
	if err == nil {
		if entry, ok := servers.Servers[serverFlag]; ok {
			token := tokenFlag
			if token == "" {
				token = entry.Token
			}
			return &client.Target{URL: entry.URL, Token: token}, nil
		}
	}

	// Treat serverFlag as a direct URL.
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
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawning node: %w", err)
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

	return fmt.Errorf("node failed to start (socket not available after 5s)")
}

func resolveRelayURL() (string, error) {
	cfg, err := config.LoadConfig(dataDir())
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}
	if cfg.RelayURL == nil || *cfg.RelayURL == "" {
		return "", fmt.Errorf("relay not configured (run 'cw setup <relay-url>' or set CODEWIRE_RELAY_URL)")
	}
	return *cfg.RelayURL, nil
}
