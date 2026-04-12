package envshell

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// dialer abstracts the two transport strategies so the fallback logic
// can be tested without real network connections.
type dialer interface {
	DialWireGuard(ctx context.Context, opts DialOptions) (Shell, error)
	DialWebSocket(ctx context.Context, opts DialOptions) (Shell, error)
}

// Dial connects to the environment shell using WireGuard with WebSocket fallback.
//
// Fallback rules:
//  1. If PreferWS is set, skip WireGuard entirely.
//  2. If WireGuard fails with an "ssh handshake" error, do NOT fall through
//     (same sshd would fail over WebSocket too).
//  3. Otherwise, fall through to WebSocket.
//  4. If both fail, return a combined error.
func Dial(ctx context.Context, opts DialOptions) (Shell, error) {
	return dialWith(ctx, &defaultDialer{}, opts)
}

func dialWith(ctx context.Context, d dialer, opts DialOptions) (Shell, error) {
	if opts.PreferWS {
		return d.DialWebSocket(ctx, opts)
	}

	shell, wgErr := d.DialWireGuard(ctx, opts)
	if wgErr == nil {
		return shell, nil
	}

	// SSH handshake failures would recur over WebSocket -- don't fall through.
	if strings.Contains(wgErr.Error(), "ssh handshake") {
		return nil, wgErr
	}

	shell, wsErr := d.DialWebSocket(ctx, opts)
	if wsErr == nil {
		return shell, nil
	}

	return nil, fmt.Errorf("wireguard: %w; websocket: %w",
		wgErr, &wsError{wsErr})
}

// wsError is a distinct error type so errors.As can distinguish WG from WS
// in the combined error.
type wsError struct {
	err error
}

func (e *wsError) Error() string { return e.err.Error() }
func (e *wsError) Unwrap() error { return e.err }

// defaultDialer routes to the real DialWireGuard / DialWebSocket functions.
type defaultDialer struct{}

func (d *defaultDialer) DialWireGuard(ctx context.Context, opts DialOptions) (Shell, error) {
	return dialWireGuard(ctx, opts)
}

func (d *defaultDialer) DialWebSocket(ctx context.Context, opts DialOptions) (Shell, error) {
	return dialWebSocket(ctx, opts)
}

// isMultiError returns true if err wraps both a WG and WS error from Dial.
func isMultiError(err error) bool {
	return err != nil && errors.As(err, new(*wsError))
}
