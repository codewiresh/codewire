package tailnet

import (
	"testing"

	"github.com/google/uuid"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestPeerPathFromPingClassifiesTransport(t *testing.T) {
	tests := []struct {
		name string
		res  *ipnstate.PingResult
		want string
	}{
		{
			name: "direct udp endpoint",
			res:  &ipnstate.PingResult{Endpoint: "203.0.113.10:41641"},
			want: "direct_udp",
		},
		{
			name: "peer relay",
			res:  &ipnstate.PingResult{PeerRelay: "203.0.113.10:41641:vni:7"},
			want: "peer_relay",
		},
		{
			name: "derp relay",
			res:  &ipnstate.PingResult{DERPRegionID: 1, DERPRegionCode: "cw"},
			want: "derp_relay",
		},
		{
			name: "unknown",
			res:  &ipnstate.PingResult{},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerPathFromPing(tt.res)
			if got.Transport != tt.want {
				t.Fatalf("Transport = %q, want %q", got.Transport, tt.want)
			}
		})
	}
}

func TestTailcfgNodeFromPeerHasSafeDisplayName(t *testing.T) {
	id := uuid.MustParse("37a96c4c-58ab-460f-9d1e-f8ac43c0e6a1")

	node := tailcfgNodeFromPeer(&Node{ID: id})
	view := node.View()

	if view.Name() == "" {
		t.Fatal("Name is empty")
	}
	if !view.Hostinfo().Valid() {
		t.Fatal("Hostinfo is invalid")
	}
	if view.Hostinfo().Hostname() == "" {
		t.Fatal("Hostinfo hostname is empty")
	}
	if view.Cap() < 121 || view.Cap() != tailcfg.CurrentCapabilityVersion {
		t.Fatalf("Cap = %d, want current relay-capable capability version %d", view.Cap(), tailcfg.CurrentCapabilityVersion)
	}
}
