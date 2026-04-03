package peer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"
	"tailscale.com/tailcfg"

	"github.com/codewiresh/codewire/internal/platform"
	tailnetlib "github.com/codewiresh/tailnet"
)

const (
	defaultPeerTimeout = 10 * time.Second
	defaultDialTimeout = 20 * time.Second
)

type coordinateMsg struct {
	Type string           `json:"type"`
	Node *tailnetlib.Node `json:"node,omitempty"`
}

type coordinateResp struct {
	Type    string             `json:"type"`
	Nodes   []*tailnetlib.Node `json:"nodes,omitempty"`
	DERPMap *tailcfg.DERPMap   `json:"derp_map,omitempty"`
}

// DialEnvironmentPeerTCP creates a local tailnet client peer, exchanges peer
// info with the platform coordinator for envID, and dials the target port on
// that environment over the encrypted overlay.
func DialEnvironmentPeerTCP(ctx context.Context, client *platform.Client, orgID, envID string, port uint16) (net.Conn, *tailnetlib.Conn, error) {
	agentID, err := uuid.Parse(envID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid env ID %q: %w", envID, err)
	}
	clientID := uuid.New()
	peerTimeout := timeoutFromEnv("CW_TAILNET_PEER_TIMEOUT", defaultPeerTimeout)
	dialTimeout := timeoutFromEnv("CW_TAILNET_DIAL_TIMEOUT", defaultDialTimeout)

	clientAddr := tailnetlib.CWServicePrefix.PrefixFromUUID(clientID)
	agentAddr := tailnetlib.CWServicePrefix.PrefixFromUUID(agentID)

	serverHost := extractServerHost(client.ServerURL)
	insecure := strings.HasPrefix(client.ServerURL, "http://")
	derpPort := 443
	if insecure {
		if host, p, err := net.SplitHostPort(serverHost); err == nil {
			serverHost = host
			fmt.Sscanf(p, "%d", &derpPort)
		}
	}
	// Build a minimal relay-only DERPMap for bootstrap. The server's
	// coordinator will send the full DERPMap (with STUN regions and the
	// correct DERP hostname) once the WebSocket connects.
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "cw",
				RegionName: "Codewire",
				Nodes: []*tailcfg.DERPNode{{
					Name:             "1a",
					RegionID:         1,
					HostName:         serverHost,
					DERPPort:         derpPort,
					InsecureForTests: insecure,
				}},
			},
		},
	}
	debugf("initial derp target host=%s port=%d insecure=%t", serverHost, derpPort, insecure)

	conn, err := tailnetlib.NewConn(&tailnetlib.Options{
		ID:        clientID,
		Addresses: []netip.Prefix{clientAddr},
		DERPMap:   derpMap,
		Logger:    slog.Default(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("wireguard conn: %w", err)
	}

	wsURL := strings.Replace(client.ServerURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += fmt.Sprintf("/api/v1/organizations/%s/environments/%s/coordinate", orgID, envID)

	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"coordinate"},
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + client.SessionToken},
		},
	})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("coordinator connect: %w", err)
	}

	var wsMu sync.Mutex
	conn.SetNodeCallback(func(node *tailnetlib.Node) {
		msg := coordinateMsg{Type: "node", Node: node}
		data, err := json.Marshal(msg)
		if err != nil {
			return
		}
		wsMu.Lock()
		_ = wsConn.Write(ctx, websocket.MessageText, data)
		wsMu.Unlock()
	})

	peerReady := make(chan struct{}, 1)
	go func() {
		defer wsConn.Close(websocket.StatusNormalClosure, "")
		for {
			_, data, err := wsConn.Read(ctx)
			if err != nil {
				debugf("coordinator read failed: %v", err)
				return
			}
			var resp coordinateResp
			if json.Unmarshal(data, &resp) != nil {
				continue
			}
			if resp.DERPMap != nil {
				node := ""
				port := 0
				insecure := false
				if region, ok := resp.DERPMap.Regions[1]; ok && len(region.Nodes) > 0 {
					node = region.Nodes[0].HostName
					port = region.Nodes[0].DERPPort
					insecure = region.Nodes[0].InsecureForTests
				}
				debugf("received derp map host=%s port=%d insecure=%t", node, port, insecure)
				conn.SetDERPMap(resp.DERPMap)
			}
			if resp.Type == "peer_update" && len(resp.Nodes) > 0 {
				for _, node := range resp.Nodes {
					debugf("peer update id=%s derp=%d endpoints=%v addresses=%v", node.ID, node.PreferredDERP, node.Endpoints, node.Addresses)
				}
				if err := conn.UpdatePeers(resp.Nodes); err == nil {
					select {
					case peerReady <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	peerWaitStarted := time.Now()
	debugf("waiting for peer info (timeout=%s)...", peerTimeout)
	select {
	case <-peerReady:
		debugf("peer exchange complete for env=%s after=%s", envID, time.Since(peerWaitStarted).Round(time.Millisecond))
	case <-time.After(peerTimeout):
		debugf("TIMEOUT: no peer_update received in %s for env=%s", peerTimeout, envID)
		debugf("  check: server logs for 'local_sidecar_node_delivered' and 'KV hit/miss'")
		conn.Close()
		return nil, nil, fmt.Errorf(
			"timeout waiting for agent peer info after %s (env=%s, peer_timeout=%s)",
			time.Since(peerWaitStarted).Round(time.Millisecond),
			envID,
			peerTimeout,
		)
	case <-ctx.Done():
		conn.Close()
		return nil, nil, ctx.Err()
	}

	agentIP := agentAddr.Addr()
	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	defer cancelDial()
	dialStarted := time.Now()
	debugf("dialing agent at %s:%d with timeout=%s", agentIP, port, dialTimeout)
	tcpConn, err := conn.DialContextTCP(dialCtx, netip.AddrPortFrom(agentIP, port))
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf(
			"tailnet TCP dial to agent failed after %s (agent=%s:%d, dial_timeout=%s): %w",
			time.Since(dialStarted).Round(time.Millisecond),
			agentIP,
			port,
			dialTimeout,
			err,
		)
	}

	return tcpConn, conn, nil
}

func debugf(format string, args ...any) {
	if os.Getenv("CW_DEBUG_TAILNET") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "cw tailnet: "+format+"\n", args...)
}

func timeoutFromEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func extractServerHost(serverURL string) string {
	u := serverURL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if idx := strings.IndexByte(u, '/'); idx >= 0 {
		u = u[:idx]
	}
	return u
}
