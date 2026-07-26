package tailnet

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

// StartMesh discovers sibling DERP replicas via headless service DNS and
// establishes mesh forwarding between them. Returns a cleanup function.
func StartMesh(ctx context.Context, srv *derpserver.Server, headlessHost string, derpPort int, log *slog.Logger) func() {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		runMeshDiscovery(ctx, srv, headlessHost, derpPort, log)
	}()

	return func() {
		cancel()
		wg.Wait()
	}
}

func runMeshDiscovery(ctx context.Context, srv *derpserver.Server, headlessHost string, derpPort int, log *slog.Logger) {
	selfIP := os.Getenv("MY_POD_IP")

	type peerState struct {
		cancel context.CancelFunc
	}
	peers := map[string]*peerState{}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	discover := func() {
		ips, err := net.DefaultResolver.LookupHost(ctx, headlessHost)
		if err != nil {
			log.Warn("mesh dns lookup failed", "host", headlessHost, "error", err)
			return
		}

		seen := map[string]bool{}
		for _, ip := range ips {
			if ip == selfIP {
				continue
			}
			seen[ip] = true
			if _, ok := peers[ip]; ok {
				continue
			}

			peerCtx, peerCancel := context.WithCancel(ctx)
			peers[ip] = &peerState{cancel: peerCancel}
			log.Info("mesh peer discovered", "ip", ip)

			go runMeshPeer(peerCtx, srv, ip, derpPort, log)
		}

		// Remove stale peers.
		for ip, ps := range peers {
			if !seen[ip] {
				log.Info("mesh peer removed", "ip", ip)
				ps.cancel()
				delete(peers, ip)
			}
		}
	}

	// Initial discovery immediately.
	discover()

	for {
		select {
		case <-ctx.Done():
			for _, ps := range peers {
				ps.cancel()
			}
			return
		case <-ticker.C:
			discover()
		}
	}
}

func runMeshPeer(ctx context.Context, srv *derpserver.Server, peerIP string, derpPort int, log *slog.Logger) {
	peerURL := fmt.Sprintf("http://%s/derp", net.JoinHostPort(peerIP, fmt.Sprintf("%d", derpPort)))
	logf := logger.WithPrefix(slogLogf(log), fmt.Sprintf("mesh(%s): ", peerIP))

	netMon := netmon.NewStatic()
	c, err := derphttp.NewClient(srv.PrivateKey(), peerURL, logf, netMon)
	if err != nil {
		log.Error("mesh client create failed", "peer", peerIP, "error", err)
		return
	}
	c.MeshKey = srv.MeshKey()
	c.WatchConnectionChanges = true

	add := func(m derp.PeerPresentMessage) { srv.AddPacketForwarder(m.Key, c) }
	remove := func(m derp.PeerGoneMessage) { srv.RemovePacketForwarder(m.Peer, c) }

	c.RunWatchConnectionLoop(ctx, srv.PublicKey(), logf, add, remove, nil)
}

// slogLogf returns a logger.Logf that writes to an slog.Logger.
func slogLogf(log *slog.Logger) logger.Logf {
	return func(format string, args ...any) {
		log.Info(fmt.Sprintf(format, args...))
	}
}
