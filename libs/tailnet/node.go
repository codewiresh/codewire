package tailnet

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"tailscale.com/types/key"
)

// Node contains the WireGuard connectivity information for a single peer.
// Exchanged between clients and agents via the coordinator (JSON over WebSocket).
type Node struct {
	ID            uuid.UUID          `json:"id"`
	AsOf          time.Time          `json:"as_of"`
	Key           key.NodePublic     `json:"key"`
	DiscoKey      key.DiscoPublic    `json:"disco_key"`
	PreferredDERP int                `json:"preferred_derp"`
	DERPLatency   map[string]float64 `json:"derp_latency,omitempty"`
	Endpoints     []netip.AddrPort   `json:"endpoints"`
	Addresses     []netip.Prefix     `json:"addresses"`
}

// ServicePrefix for deterministic IPv6 address generation.
type ServicePrefix [6]byte

var CWServicePrefix = ServicePrefix{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}

// PrefixFromUUID returns a /128 IPv6 prefix for the given UUID.
func (p ServicePrefix) PrefixFromUUID(uid uuid.UUID) netip.Prefix {
	var addr [16]byte
	copy(addr[:6], p[:])
	copy(addr[6:], uid[:10])
	return netip.PrefixFrom(netip.AddrFrom16(addr), 128)
}
