package tailnet

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"tailscale.com/tailcfg"
)

// testEnv bundles a DERP server + coordinator for integration tests.
type testEnv struct {
	DERPMap     *tailcfg.DERPMap
	Coordinator *Coordinator
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	derpSrv := NewDERPServer()
	handler, derpCleanup := DERPHandler(derpSrv)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("DERP server: %s %s (Upgrade: %s)", r.Method, r.URL.Path, r.Header.Get("Upgrade"))
		switch r.URL.Path {
		case "/derp":
			handler.ServeHTTP(w, r)
		case "/derp/latency-check":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	httpSrv := httptest.NewTLSServer(mux)
	t.Cleanup(func() { httpSrv.Close(); derpCleanup(); derpSrv.Close() })

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := 443
	fmt.Sscanf(u.Port(), "%d", &port)

	coord := NewCoordinator(slog.Default())
	t.Cleanup(func() { coord.Close() })

	return &testEnv{
		DERPMap:     NewDERPMap(u.Hostname(), port, true),
		Coordinator: coord,
	}
}

// wireUp registers both conns with the coordinator, adds a tunnel,
// and starts goroutines to relay peer updates.
func (e *testEnv) wireUp(t *testing.T, clientID, agentID uuid.UUID, client, agent *Conn) {
	t.Helper()

	agentCh := e.Coordinator.Register(agentID, "agent")
	clientCh := e.Coordinator.Register(clientID, "client")
	e.Coordinator.AddTunnel(clientID, agentID)

	agent.SetNodeCallback(func(n *Node) {
		t.Logf("agent node cb: derp=%d endpoints=%v", n.PreferredDERP, n.Endpoints)
		e.Coordinator.UpdateNode(agentID, n)
	})
	client.SetNodeCallback(func(n *Node) {
		t.Logf("client node cb: derp=%d endpoints=%v", n.PreferredDERP, n.Endpoints)
		e.Coordinator.UpdateNode(clientID, n)
	})

	go func() {
		for nodes := range agentCh {
			t.Logf("agent got %d peer(s)", len(nodes))
			_ = agent.UpdatePeers(nodes)
		}
	}()
	go func() {
		for nodes := range clientCh {
			t.Logf("client got %d peer(s)", len(nodes))
			_ = client.UpdatePeers(nodes)
		}
	}()
}

// echoServer accepts connections on ln and echoes data back.
func echoServer(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
}

func TestParseDERPConnectionLogs(t *testing.T) {
	tests := []struct {
		name      string
		msg       string
		connected bool
		recvError bool
		region    int
	}{
		{
			name:      "connected",
			msg:       "magicsock: derp-1 connected; connGen=3",
			connected: true,
			region:    1,
		},
		{
			name:      "recv error",
			msg:       "magicsock: [0xc001] derp.Recv(derp-1): EOF",
			recvError: true,
			region:    1,
		},
		{
			name:      "network down recv error",
			msg:       "[v1] magicsock: derp.Recv(derp-2): network down, closing",
			recvError: true,
			region:    2,
		},
		{
			name: "ignored active log",
			msg:  "magicsock: adding connection to derp-1 for home-keep-alive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, ok := parseDERPConnectedLog(tt.msg)
			if ok != tt.connected {
				t.Fatalf("parseDERPConnectedLog ok=%v, want %v", ok, tt.connected)
			}
			if ok && region != tt.region {
				t.Fatalf("parseDERPConnectedLog region=%d, want %d", region, tt.region)
			}

			region, ok = parseDERPRecvErrorLog(tt.msg)
			if ok != tt.recvError {
				t.Fatalf("parseDERPRecvErrorLog ok=%v, want %v", ok, tt.recvError)
			}
			if ok && region != tt.region {
				t.Fatalf("parseDERPRecvErrorLog region=%d, want %d", region, tt.region)
			}
		})
	}
}

// TestTunnelTCP verifies two Conns can exchange TCP data over the WireGuard
// tunnel. The initial connection bootstraps via DERP relay. On localhost,
// magicsock will discover a direct UDP path after a few seconds and upgrade
// transparently.
func TestTunnelTCP(t *testing.T) {
	env := newTestEnv(t)

	agentID := uuid.New()
	clientID := uuid.New()
	agentAddr := CWServicePrefix.PrefixFromUUID(agentID)
	clientAddr := CWServicePrefix.PrefixFromUUID(clientID)

	agent, err := NewConn(&Options{
		ID:        agentID,
		Addresses: []netip.Prefix{agentAddr},
		DERPMap:   env.DERPMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	client, err := NewConn(&Options{
		ID:        clientID,
		Addresses: []netip.Prefix{clientAddr},
		DERPMap:   env.DERPMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for name, conn := range map[string]*Conn{"agent": agent, "client": client} {
		derpCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := conn.WaitForDERPHome(derpCtx, 1)
		cancel()
		if err != nil {
			t.Fatalf("%s DERP home: %v", name, err)
		}
	}

	ln, err := agent.Listen("tcp", ":9999")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	echoServer(t, ln)
	env.wireUp(t, clientID, agentID, client, agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcpConn, err := client.DialContextTCP(ctx, netip.AddrPortFrom(agentAddr.Addr(), 9999))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tcpConn.Close()

	msg := []byte("hello-wireguard")
	if _, err := tcpConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(tcpConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestCodewireTailnetFilterGrantsPeerRelayCaps(t *testing.T) {
	f := newCodewireTailnetFilter(func(string, ...any) {}, true)

	src := netip.MustParseAddr("fd7a:115c:a1e0:1111:2222:3333:4444:5555")
	dst := netip.MustParseAddr("fd7a:115c:a1e0:aaaa:bbbb:cccc:dddd:eeee")
	caps := f.CapsWithValues(src, dst)

	if _, ok := caps[tailcfg.PeerCapabilityRelay]; !ok {
		t.Fatalf("missing %s cap in %v", tailcfg.PeerCapabilityRelay, caps)
	}
	if _, ok := caps[tailcfg.PeerCapabilityRelayTarget]; !ok {
		t.Fatalf("missing %s cap in %v", tailcfg.PeerCapabilityRelayTarget, caps)
	}
}

func TestCodewireTailnetFilterCanDisablePeerRelayCaps(t *testing.T) {
	f := newCodewireTailnetFilter(func(string, ...any) {}, false)

	src := netip.MustParseAddr("fd7a:115c:a1e0:1111:2222:3333:4444:5555")
	dst := netip.MustParseAddr("fd7a:115c:a1e0:aaaa:bbbb:cccc:dddd:eeee")
	caps := f.CapsWithValues(src, dst)

	if _, ok := caps[tailcfg.PeerCapabilityRelay]; ok {
		t.Fatalf("unexpected %s cap in %v", tailcfg.PeerCapabilityRelay, caps)
	}
	if _, ok := caps[tailcfg.PeerCapabilityRelayTarget]; ok {
		t.Fatalf("unexpected %s cap in %v", tailcfg.PeerCapabilityRelayTarget, caps)
	}
}
