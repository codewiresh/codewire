package tailnet

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"nhooyr.io/websocket"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// NewDERPServer creates an embedded DERP relay server.
func NewDERPServer() *derpserver.Server {
	logf := func(format string, args ...any) {
		log.Printf("[derp-server] "+format, args...)
	}
	return derpserver.New(key.NewNode(), logf)
}

// DERPHandler returns an HTTP handler for the DERP server with WebSocket support.
// Mount at /derp on the chi router.
func DERPHandler(srv *derpserver.Server) (http.Handler, func()) {
	baseHandler := derpserver.Handler(srv)
	return WithWebsocketSupport(srv, baseHandler)
}

// WithWebsocketSupport upgrades WebSocket connections with the "derp" subprotocol
// and passes them to the DERP server. Falls back to the base handler for non-WS.
// Adapted from the original Go tailnet WebSocket DERP bridge.
func WithWebsocketSupport(s *derpserver.Server, base http.Handler) (http.Handler, func()) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			up := strings.ToLower(r.Header.Get("Upgrade"))
			if up != "websocket" || !strings.Contains(r.Header.Get("Sec-Websocket-Protocol"), "derp") {
				base.ServeHTTP(w, r)
				return
			}

			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				return
			}
			wg.Add(1)
			mu.Unlock()
			defer wg.Done()

			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
				Subprotocols:    []string{"derp"},
				OriginPatterns:  []string{"*"},
				CompressionMode: websocket.CompressionDisabled,
			})
			if err != nil {
				log.Printf("derp websocket accept error: remote=%s err=%v", r.RemoteAddr, err)
				return
			}
			defer c.Close(websocket.StatusInternalError, "closing")

			if c.Subprotocol() != "derp" {
				c.Close(websocket.StatusPolicyViolation, "client must speak the derp subprotocol")
				return
			}

			log.Printf("derp websocket accepted: remote=%s subproto=%s", r.RemoteAddr, c.Subprotocol())
			wc := websocket.NetConn(ctx, c, websocket.MessageBinary)
			brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
			s.Accept(ctx, wc, brw, r.RemoteAddr)
			log.Printf("derp session ended: remote=%s", r.RemoteAddr)
		}), func() {
			cancel()
			mu.Lock()
			wg.Wait()
			mu.Unlock()
		}
}

// NewDERPMap creates a relay-only DERPMap. STUN is disabled on the relay
// node (STUNPort=-1) to prevent STUN latency from competing with the
// DERP relay for preferred_derp selection. Use WithSTUNNode to add a
// co-located STUN node in the same region.
func NewDERPMap(hostname string, port int, insecure bool) *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "cw",
				RegionName: "Codewire Embedded",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "1a",
						RegionID:         1,
						HostName:         hostname,
						DERPPort:         port,
						STUNPort:         -1,
						InsecureForTests: insecure,
					},
				},
			},
		},
	}
}

// WithSTUNNode adds a STUNOnly node to region 1. This keeps STUN and
// DERP in the same region so preferred_derp always stays on the relay.
// The STUN node can be on a different host (e.g. a NodePort IP) from
// the DERP relay (e.g. behind a TCP LB).
func WithSTUNNode(dm *tailcfg.DERPMap, stunHost string, stunPort int) {
	region := dm.Regions[1]
	if region == nil {
		return
	}
	stunCount := 0
	for _, node := range region.Nodes {
		if node.STUNOnly {
			stunCount++
		}
	}
	name := "1s"
	if stunCount > 0 {
		name = fmt.Sprintf("1s%d", stunCount+1)
	}
	region.Nodes = append(region.Nodes, &tailcfg.DERPNode{
		Name:     name,
		RegionID: 1,
		HostName: stunHost,
		STUNOnly: true,
		STUNPort: stunPort,
	})
}
