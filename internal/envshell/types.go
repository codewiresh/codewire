package envshell

import "github.com/codewiresh/codewire/internal/platform"

// Shell provides read/write access to a remote PTY session.
// It is the primary interface consumed by both the CLI and the iOS c-archive bridge.
type Shell interface {
	Read(p []byte) (int, error)   // reads PTY output from the remote shell
	Write(p []byte) (int, error)  // writes input to the remote shell
	Resize(cols, rows uint16) error
	Close() error
}

// DialOptions configures how Dial connects to a remote environment shell.
type DialOptions struct {
	Client         *platform.Client
	OrgID          string
	EnvID          string
	InitialCols    uint16
	InitialRows    uint16
	KnownHostsPath string // path to known_hosts file; empty = InsecureIgnoreHostKey
	PreferWS       bool   // skip WireGuard attempt, go straight to WebSocket
}
