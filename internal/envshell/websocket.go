package envshell

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"nhooyr.io/websocket"
)

// dialWebSocket establishes an SSH shell session through the WebSocket proxy.
func dialWebSocket(ctx context.Context, opts DialOptions) (Shell, error) {
	wsURL := strings.Replace(opts.Client.ServerURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += fmt.Sprintf("/api/v1/organizations/%s/environments/%s/ssh-proxy", opts.OrgID, opts.EnvID)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"ssh"},
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + opts.Client.SessionToken},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ssh proxy connect: %w", err)
	}

	wsConn := &wsNetConn{conn: conn, ctx: ctx}

	hostKeyCallback, err := hostKeyCallback(opts.KnownHostsPath)
	if err != nil {
		conn.Close(websocket.StatusNormalClosure, "")
		return nil, fmt.Errorf("known_hosts callback: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            "codewire",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: hostKeyCallback,
	}

	sshClientConn, chans, reqs, err := ssh.NewClientConn(wsConn, "cw-"+opts.EnvID+":22", sshConfig)
	if err != nil {
		conn.Close(websocket.StatusNormalClosure, "")
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	sshClient := ssh.NewClient(sshClientConn, chans, reqs)
	return newShell(sshClient, opts, &wsCloser{conn: conn})
}

// wsCloser wraps a websocket.Conn for io.Closer.
type wsCloser struct {
	conn *websocket.Conn
}

func (c *wsCloser) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "")
}

// wsNetConn wraps a nhooyr.io/websocket.Conn to implement net.Conn
// for use with golang.org/x/crypto/ssh.NewClientConn.
type wsNetConn struct {
	conn   *websocket.Conn
	ctx    context.Context
	reader io.Reader
}

func (w *wsNetConn) Read(p []byte) (int, error) {
	for {
		if w.reader != nil {
			n, err := w.reader.Read(p)
			if n > 0 {
				return n, nil
			}
			if err != io.EOF {
				return 0, err
			}
			w.reader = nil
		}
		_, reader, err := w.conn.Reader(w.ctx)
		if err != nil {
			return 0, err
		}
		w.reader = reader
	}
}

func (w *wsNetConn) Write(p []byte) (int, error) {
	err := w.conn.Write(w.ctx, websocket.MessageBinary, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsNetConn) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "")
}

func (w *wsNetConn) LocalAddr() net.Addr  { return wsAddr{} }
func (w *wsNetConn) RemoteAddr() net.Addr { return wsAddr{} }

func (w *wsNetConn) SetDeadline(t time.Time) error      { return nil }
func (w *wsNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (w *wsNetConn) SetWriteDeadline(t time.Time) error { return nil }

type wsAddr struct{}

func (wsAddr) Network() string { return "websocket" }
func (wsAddr) String() string  { return "websocket:22" }
