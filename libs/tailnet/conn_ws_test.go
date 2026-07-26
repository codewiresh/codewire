//go:build ts_debug_websockets

package tailnet

import (
	"testing"
)

// TestTunnelTCP_WebSocketDERP verifies TCP over WireGuard using WebSocket DERP
// transport. Skipped: the upstream tailscale WebSocket DERP client doesn't honor
// InsecureForTests on its TLS config, so it rejects httptest.NewTLSServer's
// self-signed cert. Needs a custom dialer or mkcert CA.
func TestTunnelTCP_WebSocketDERP(t *testing.T) {
	t.Skip("WebSocket DERP client does not honor InsecureForTests for TLS — needs custom CA or dialer override")
}
