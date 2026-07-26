package tailnet

import (
	"context"
	"errors"
	"fmt"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// PeerPath is a non-secret snapshot of how magicsock reached a peer.
type PeerPath struct {
	Transport      string
	Endpoint       string
	PeerRelay      string
	DERPRegionID   int
	DERPRegionCode string
	LatencySeconds float64
}

func peerPathFromPing(res *ipnstate.PingResult) PeerPath {
	path := PeerPath{
		Endpoint:       res.Endpoint,
		PeerRelay:      res.PeerRelay,
		DERPRegionID:   res.DERPRegionID,
		DERPRegionCode: res.DERPRegionCode,
		LatencySeconds: res.LatencySeconds,
		Transport:      "unknown",
	}
	switch {
	case res.Endpoint != "":
		path.Transport = "direct_udp"
	case res.PeerRelay != "":
		path.Transport = "peer_relay"
	case res.DERPRegionID != 0:
		path.Transport = "derp_relay"
	}
	return path
}

func tailcfgNodeFromPeer(p *Node) *tailcfg.Node {
	if p == nil {
		return &tailcfg.Node{}
	}
	hostname := fmt.Sprintf("codewire-%s", p.ID)
	return &tailcfg.Node{
		ID:         NodeID(p.ID),
		Cap:        tailcfg.CurrentCapabilityVersion,
		Name:       hostname + ".tailnet.local.",
		Key:        p.Key,
		DiscoKey:   p.DiscoKey,
		Addresses:  p.Addresses,
		AllowedIPs: p.Addresses,
		Endpoints:  p.Endpoints,
		HomeDERP:   p.PreferredDERP,
		Hostinfo: (&tailcfg.Hostinfo{
			Hostname: hostname,
		}).View(),
	}
}

// ProbePeerPath asks magicsock how it currently reaches a peer. A direct UDP
// result means WireGuard packets are bypassing DERP for that peer at the time
// of the probe. DERP results are still valid fallback paths.
func (c *Conn) ProbePeerPath(ctx context.Context, peer *Node) (PeerPath, error) {
	if peer == nil {
		return PeerPath{}, fmt.Errorf("nil peer")
	}

	resultCh := make(chan *ipnstate.PingResult, 1)
	res := &ipnstate.PingResult{}
	c.magicConn.Ping(tailcfgNodeFromPeer(peer).View(), res, 0, func(pr *ipnstate.PingResult) {
		select {
		case resultCh <- pr:
		default:
		}
	})

	select {
	case <-ctx.Done():
		return PeerPath{}, ctx.Err()
	case pr := <-resultCh:
		path := peerPathFromPing(pr)
		if pr.Err != "" {
			return path, errors.New(pr.Err)
		}
		return path, nil
	}
}
