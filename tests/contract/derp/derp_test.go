// Package derp_test is the Go/Tailscale interoperability contract for a DERP relay.
//
// It uses Tailscale's real Go DERP-over-HTTP client against the service under
// test, proving the Rust relay supports the clients that speak this external
// protocol.
package derp_test

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func derpURL(t *testing.T) string {
	t.Helper()
	raw := os.Getenv("DERP_BASE_URL")
	if raw == "" {
		t.Skip("DERP_BASE_URL not set; skipping DERP contract suite")
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse DERP_BASE_URL: %v", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/derp"
	}
	return u.String()
}

func TestRawHTTPUpgradeRelaysTailscaleGoClients(t *testing.T) {
	envknob.Setenv("TS_DEBUG_DERP_WS_CLIENT", "")
	relayTwoGoClients(t)
}

func TestWebSocketFallbackRelaysTailscaleGoClients(t *testing.T) {
	if os.Getenv("DERP_WEBSOCKET") != "1" {
		t.Skip("DERP_WEBSOCKET != 1; skipping WebSocket DERP contract")
	}
	envknob.Setenv("TS_DEBUG_DERP_WS_CLIENT", "true")
	relayTwoGoClients(t)
}

func relayTwoGoClients(t *testing.T) {
	t.Helper()
	serverURL := derpURL(t)
	netMon := netmon.NewStatic()

	aKey := key.NewNode()
	bKey := key.NewNode()
	a := connectClient(t, serverURL, aKey, netMon)
	defer a.Close()
	b := connectClient(t, serverURL, bKey, netMon)
	defer b.Close()

	payload := []byte("go-client-to-rust-derp\n")
	if err := a.Send(bKey.Public(), payload); err != nil {
		t.Fatalf("send packet: %v", err)
	}

	got := recvPacket(t, b)
	if !bytes.Equal(got, payload) {
		t.Fatalf("received packet = %q, want %q", got, payload)
	}
}

func connectClient(
	t *testing.T,
	serverURL string,
	priv key.NodePrivate,
	netMon *netmon.Monitor,
) *derphttp.Client {
	t.Helper()
	c, err := derphttp.NewClient(priv, serverURL, t.Logf, netMon)
	if err != nil {
		t.Fatalf("new DERP client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		c.Close()
		t.Fatalf("connect DERP client: %v", err)
	}

	m := recvMessage(t, c)
	if _, ok := m.(derp.ServerInfoMessage); !ok {
		c.Close()
		t.Fatalf("first DERP message = %T, want derp.ServerInfoMessage", m)
	}
	return c
}

func recvPacket(t *testing.T, c *derphttp.Client) []byte {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for DERP packet")
		default:
		}

		switch m := recvMessage(t, c).(type) {
		case derp.ReceivedPacket:
			return bytes.Clone(m.Data)
		case derp.PeerGoneMessage:
			continue
		default:
			t.Fatalf("DERP message = %T, want derp.ReceivedPacket", m)
		}
	}
}

func recvMessage(t *testing.T, c *derphttp.Client) derp.ReceivedMessage {
	t.Helper()
	type result struct {
		msg derp.ReceivedMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := c.Recv()
		ch <- result{msg: msg, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("recv DERP message: %v", res.err)
		}
		return res.msg
	case <-time.After(10 * time.Second):
		c.Close()
		t.Fatal("timed out waiting for DERP message")
	}
	return nil
}
