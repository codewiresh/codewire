package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"nhooyr.io/websocket"

	"github.com/codewiresh/codewire/internal/envshell"
	"github.com/codewiresh/codewire/internal/peer"
	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/terminal"
)

func shellCmd() *cobra.Command {
	var stdio bool

	cmd := &cobra.Command{
		Use:   "shell [target]",
		Short: "Open a shell in a running environment",
		Long: `Connect to a running sandbox environment shell.

Use this for an interactive target shell.
Use 'cw attach' to re-open the terminal of a specific Codewire run.
Use 'cw exec' to run one command on a target.

Interactive mode (default):
  Connects with PTY, resize support, and Ctrl+B d to detach.

Stdio mode (--stdio):
  For use as SSH ProxyCommand. Pipes stdin/stdout directly to the SSH proxy.
  Used by: ssh cw-<envid> via the managed SSH ProxyCommand

For VS Code Remote-SSH, run 'cw config-ssh' to configure ~/.ssh/config.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := ""
			if len(args) > 0 {
				ref = args[0]
				// Strip "cw-" prefix for ProxyCommand use (Host cw-*)
				if strings.HasPrefix(ref, "cw-") {
					ref = ref[3:]
				}
			}

			target, err := requireEnvironmentTarget(ref)
			if err != nil {
				return err
			}
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID := target.Ref

			if stdio {
				return sshStdio(client, orgID, envID)
			}
			return sshInteractive(client, orgID, envID)
		},
	}

	cmd.Flags().BoolVar(&stdio, "stdio", false, "Stdio mode for ProxyCommand (pipe stdin/stdout to shell proxy)")
	cmd.Flags().String("org", "", "Organization ID or slug (default: current org)")
	return cmd
}

// sshStdio connects via WireGuard (primary) or WebSocket proxy (fallback)
// and pipes stdin/stdout. Used as ProxyCommand for VS Code and ssh clients.
func sshStdio(client *platform.Client, orgID, envID string) error {
	// Try WireGuard first.
	err := sshStdioWireGuard(client, orgID, envID)
	if err == nil {
		return nil
	}

	// Fall back to WebSocket proxy.
	return sshStdioWebSocket(client, orgID, envID)
}

// sshStdioWebSocket connects to the SSH proxy WebSocket and pipes stdin/stdout.
func sshStdioWebSocket(client *platform.Client, orgID, envID string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wsURL := strings.Replace(client.ServerURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += fmt.Sprintf("/api/v1/organizations/%s/environments/%s/ssh-proxy", orgID, envID)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"ssh"},
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + client.SessionToken},
		},
	})
	if err != nil {
		return fmt.Errorf("ssh proxy connect: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Set up signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	done := make(chan error, 2)

	// stdin -> WebSocket
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if wErr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); wErr != nil {
					done <- wErr
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// WebSocket -> stdout
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				done <- err
				return
			}
			if _, err := os.Stdout.Write(data); err != nil {
				done <- err
				return
			}
		}
	}()

	err = <-done
	if err == io.EOF {
		return nil
	}
	return err
}

// sshInteractive connects to the environment via SSH over WireGuard (primary)
// or WebSocket proxy (fallback), then runs an interactive terminal session.
func sshInteractive(client *platform.Client, orgID, envID string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cols, rows, _ := terminal.TerminalSize()
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	shell, err := envshell.Dial(ctx, envshell.DialOptions{
		Client:         client,
		OrgID:          orgID,
		EnvID:          envID,
		InitialCols:    uint16(cols),
		InitialRows:    uint16(rows),
		KnownHostsPath: defaultKnownHostsPath(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "shell dial failed: %v\n", err)
		available, _ := client.CheckSSHProxy(orgID, envID)
		if !available {
			return terminalFallback(client, orgID, envID)
		}
		return err
	}
	defer shell.Close()

	return runInteractiveShell(shell)
}

// sshStdioWireGuard connects via WireGuard and pipes stdin/stdout to the
// raw TCP connection. The calling SSH client handles SSH protocol.
func sshStdioWireGuard(client *platform.Client, orgID, envID string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpConn, wgConn, err := peer.DialEnvironmentPeerTCP(ctx, client, orgID, envID, 22)
	if err != nil {
		return err
	}
	defer wgConn.Close()
	defer tcpConn.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
		tcpConn.Close()
	}()

	done := make(chan error, 2)

	// stdin -> TCP
	go func() {
		_, err := io.Copy(tcpConn, os.Stdin)
		done <- err
	}()

	// TCP -> stdout
	go func() {
		_, err := io.Copy(os.Stdout, tcpConn)
		done <- err
	}()

	err = <-done
	if err == io.EOF {
		return nil
	}
	return err
}

// runInteractiveShell wires a Shell to the local terminal with raw mode,
// resize propagation, and Ctrl+B d detach detection. This is CLI-specific
// and does not belong in the envshell package.
func runInteractiveShell(shell envshell.Shell) error {
	rawGuard, err := terminal.EnableRawMode()
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer rawGuard.Restore()

	resizeCh, resizeCleanup := terminal.ResizeSignal()
	defer resizeCleanup()

	detach := terminal.NewDetachDetector()
	done := make(chan error, 1)

	// stdin -> shell.Write with detach detection
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				detached, fwd := detach.FeedBuf(buf[:n])
				if detached {
					rawGuard.Restore()
					fmt.Fprintln(os.Stderr, "\nDetached.")
					done <- nil
					return
				}
				if len(fwd) > 0 {
					if _, wErr := shell.Write(fwd); wErr != nil {
						done <- wErr
						return
					}
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// shell.Read -> stdout
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := shell.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// resize propagation
	go func() {
		for range resizeCh {
			c, r, err := terminal.TerminalSize()
			if err == nil {
				shell.Resize(uint16(c), uint16(r))
			}
		}
	}()

	err = <-done
	if err == io.EOF {
		rawGuard.Restore()
		return nil
	}
	return err
}

// terminalFallback uses the existing terminal WebSocket for environments without sshd.
func terminalFallback(client *platform.Client, orgID, envID string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wsURL := strings.Replace(client.ServerURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += fmt.Sprintf("/api/v1/organizations/%s/environments/%s/terminal", orgID, envID)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"terminal"},
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + client.SessionToken},
		},
	})
	if err != nil {
		return fmt.Errorf("terminal connect: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Enable raw mode
	rawGuard, err := terminal.EnableRawMode()
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer rawGuard.Restore()

	// Send initial resize
	cols, rows, _ := terminal.TerminalSize()
	if cols > 0 && rows > 0 {
		resizeMsg := make([]byte, 5)
		resizeMsg[0] = 0x01 // msgTypeResize
		resizeMsg[1] = byte(cols >> 8)
		resizeMsg[2] = byte(cols)
		resizeMsg[3] = byte(rows >> 8)
		resizeMsg[4] = byte(rows)
		conn.Write(ctx, websocket.MessageBinary, resizeMsg)
	}

	// Handle SIGWINCH
	resizeCh, resizeCleanup := terminal.ResizeSignal()
	defer resizeCleanup()

	go func() {
		for range resizeCh {
			c, r, err := terminal.TerminalSize()
			if err == nil {
				msg := make([]byte, 5)
				msg[0] = 0x01
				msg[1] = byte(c >> 8)
				msg[2] = byte(c)
				msg[3] = byte(r >> 8)
				msg[4] = byte(r)
				conn.Write(ctx, websocket.MessageBinary, msg)
			}
		}
	}()

	done := make(chan error, 2)
	detach := terminal.NewDetachDetector()

	// stdin -> WebSocket (with terminal framing: 0x00 prefix for stdin)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				detached, fwd := detach.FeedBuf(buf[:n])
				if detached {
					rawGuard.Restore()
					fmt.Fprintln(os.Stderr, "\nDetached.")
					done <- nil
					return
				}
				if len(fwd) > 0 {
					// Prepend stdin message type
					msg := make([]byte, 1+len(fwd))
					msg[0] = 0x00 // msgTypeStdin
					copy(msg[1:], fwd)
					if wErr := conn.Write(ctx, websocket.MessageBinary, msg); wErr != nil {
						done <- wErr
						return
					}
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// WebSocket -> stdout (raw bytes, no framing prefix on output)
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				done <- err
				return
			}
			os.Stdout.Write(data)
		}
	}()

	<-done
	return nil
}
