package envshell

import (
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// sshShell implements Shell over an SSH session with PTY.
type sshShell struct {
	mu        sync.Mutex
	closed    bool
	sshClient *ssh.Client
	session   *ssh.Session
	closers   []io.Closer // transport-layer resources (WG conn, TCP conn, WS conn)
	stdin     io.WriteCloser
	stdout    io.Reader
}

// newShell opens an SSH session with PTY on sshClient and returns a ready Shell.
// The closers are transport-layer resources closed after the SSH layer on Close().
func newShell(sshClient *ssh.Client, opts DialOptions, closers ...io.Closer) (*sshShell, error) {
	session, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		for _, c := range closers {
			c.Close()
		}
		return nil, fmt.Errorf("ssh session: %w", err)
	}

	cols := opts.InitialCols
	rows := opts.InitialRows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	if err := session.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		session.Close()
		sshClient.Close()
		for _, c := range closers {
			c.Close()
		}
		return nil, fmt.Errorf("request pty: %w", err)
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		session.Close()
		sshClient.Close()
		for _, c := range closers {
			c.Close()
		}
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		sshClient.Close()
		for _, c := range closers {
			c.Close()
		}
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		sshClient.Close()
		for _, c := range closers {
			c.Close()
		}
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &sshShell{
		sshClient: sshClient,
		session:   session,
		closers:   closers,
		stdin:     stdinPipe,
		stdout:    stdoutPipe,
	}, nil
}

func (s *sshShell) Read(p []byte) (int, error) {
	return s.stdout.Read(p)
}

func (s *sshShell) Write(p []byte) (int, error) {
	return s.stdin.Write(p)
}

func (s *sshShell) Resize(cols, rows uint16) error {
	return s.session.WindowChange(int(rows), int(cols))
}

// Close tears down the SSH session, client, and transport in order.
// It is idempotent.
func (s *sshShell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	s.session.Close()
	s.sshClient.Close()
	for _, c := range s.closers {
		c.Close()
	}
	return nil
}

// Wait blocks until the remote shell exits and returns its exit status.
func (s *sshShell) Wait() error {
	return s.session.Wait()
}
