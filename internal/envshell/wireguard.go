package envshell

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/codewiresh/codewire/internal/peer"
)

// dialWireGuard establishes an SSH shell session over a WireGuard tunnel.
func dialWireGuard(ctx context.Context, opts DialOptions) (Shell, error) {
	tcpConn, wgConn, err := peer.DialEnvironmentPeerTCP(ctx, opts.Client, opts.OrgID, opts.EnvID, 22)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := hostKeyCallback(opts.KnownHostsPath)
	if err != nil {
		tcpConn.Close()
		wgConn.Close()
		return nil, fmt.Errorf("known_hosts callback: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            "codewire",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: hostKeyCallback,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, "cw-"+opts.EnvID+":22", sshConfig)
	if err != nil {
		tcpConn.Close()
		wgConn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	sshClient := ssh.NewClient(sshConn, chans, reqs)
	return newShell(sshClient, opts, wgConn, tcpConn)
}
