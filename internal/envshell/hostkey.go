package envshell

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyCallback returns an ssh.HostKeyCallback that trusts-on-first-use,
// appending new keys to knownHostsPath. If knownHostsPath is empty,
// ssh.InsecureIgnoreHostKey is returned.
func HostKeyCallback(knownHostsPath string) (ssh.HostKeyCallback, error) {
	return hostKeyCallback(knownHostsPath)
}

func hostKeyCallback(knownHostsPath string) (ssh.HostKeyCallback, error) {
	if knownHostsPath == "" {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		return nil, fmt.Errorf("create known_hosts dir: %w", err)
	}

	baseCallback, err := knownhosts.New(knownHostsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if baseCallback != nil {
			err := baseCallback(hostname, remote, key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
				return err
			}
		}

		f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("append known_hosts: %w", err)
		}
		defer f.Close()
		if _, err := f.WriteString(knownhosts.Line([]string{hostname}, key) + "\n"); err != nil {
			return fmt.Errorf("write known_hosts: %w", err)
		}

		baseCallback, err = knownhosts.New(knownHostsPath)
		if err != nil {
			return fmt.Errorf("reload known_hosts: %w", err)
		}
		return nil
	}, nil
}
