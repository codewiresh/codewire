// Package tailscalegolden_test records the Tailscale wire formats that the Rust
// codewire-tailnet port reimplements, produced by Tailscale's own Go packages.
//
// The golden file tests/fixtures/tailnet/tailscale_golden.json is checked in.
// This test fails when the pinned tailscale.com produces different bytes, so a
// Tailscale upgrade that changes a wire format is visible in review. Run
//
//	UPDATE_TAILSCALE_GOLDEN=1 GOWORK=off go test ./tailscalegolden/
//
// to rewrite it, then make crates/codewire-tailnet's golden test pass.
//
// Sealed values use random nonces, so they cannot be compared byte for byte.
// The golden keeps the sealed bytes it was written with; this test proves
// that the pinned Tailscale still opens them to the recorded plaintext, and
// the Rust test proves the port opens them too.
package tailscalegolden_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const goldenPath = "../../fixtures/tailnet/tailscale_golden.json"

type golden struct {
	Version     int          `json:"version"`
	GeneratedBy string       `json:"generated_by"`
	Tailscale   moduleInfo   `json:"tailscale"`
	Keys        goldenKeys   `json:"keys"`
	DERP        goldenDERP   `json:"derp"`
	Disco       goldenDisco  `json:"disco"`
	STUN        goldenSTUN   `json:"stun"`
	Geneve      []geneveCase `json:"geneve"`
}

type moduleInfo struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

type keyPair struct {
	PrivateHex string `json:"private_hex"`
	PublicHex  string `json:"public_hex"`
	PublicText string `json:"public_text"`
}

type goldenKeys struct {
	NodeA  keyPair `json:"node_a"`
	NodeB  keyPair `json:"node_b"`
	DiscoA keyPair `json:"disco_a"`
	DiscoB keyPair `json:"disco_b"`
}

type frameCase struct {
	Name       string `json:"name"`
	Type       uint8  `json:"type"`
	PayloadHex string `json:"payload_hex"`
	FrameHex   string `json:"frame_hex"`
}

type sealedCase struct {
	Name         string `json:"name"`
	From         string `json:"from"`
	To           string `json:"to"`
	PlaintextHex string `json:"plaintext_hex"`
	SealedHex    string `json:"sealed_hex"`
}

type goldenDERP struct {
	MagicHex        string           `json:"magic_hex"`
	ProtocolVersion int              `json:"protocol_version"`
	FrameHeaderLen  int              `json:"frame_header_len"`
	MaxPacketSize   int              `json:"max_packet_size"`
	MagicIPAddr     string           `json:"magic_ip_addr"`
	FrameTypes      map[string]uint8 `json:"frame_types"`
	Frames          []frameCase      `json:"frames"`
	Sealed          []sealedCase     `json:"sealed"`
}

// discoCase holds a message's inputs and its marshalled payload. Only the
// fields of its kind are set.
type discoCase struct {
	Name        string   `json:"name"`
	Type        uint8    `json:"type"`
	TxIDHex     string   `json:"tx_id_hex,omitempty"`
	NodeKeyHex  string   `json:"node_key_hex,omitempty"`
	Padding     int      `json:"padding,omitempty"`
	Src         string   `json:"src,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
	VNI         uint32   `json:"vni,omitempty"`
	Generation  uint32   `json:"generation,omitempty"`
	RemoteKey   string   `json:"remote_key_hex,omitempty"`
	Challenge   string   `json:"challenge_hex,omitempty"`
	ClientDisco []string `json:"client_disco_hex,omitempty"`
	ServerDisco string   `json:"server_disco_hex,omitempty"`
	LamportID   uint64   `json:"lamport_id,omitempty"`
	BindNanos   int64    `json:"bind_lifetime_ns,omitempty"`
	SteadyNanos int64    `json:"steady_state_lifetime_ns,omitempty"`
	PayloadHex  string   `json:"payload_hex"`
}

type sealedDisco struct {
	Name       string `json:"name"`
	From       string `json:"from"`
	To         string `json:"to"`
	PayloadHex string `json:"payload_hex"`
	PacketHex  string `json:"packet_hex"`
}

type goldenDisco struct {
	MagicHex string        `json:"magic_hex"`
	NonceLen int           `json:"nonce_len"`
	Messages []discoCase   `json:"messages"`
	Sealed   []sealedDisco `json:"sealed"`
}

type stunCase struct {
	TxIDHex   string `json:"tx_id_hex"`
	Addr      string `json:"addr,omitempty"`
	PacketHex string `json:"packet_hex"`
}

type goldenSTUN struct {
	Request   stunCase   `json:"request"`
	Responses []stunCase `json:"responses"`
}

type geneveCase struct {
	Name      string `json:"name"`
	VNI       uint32 `json:"vni"`
	Control   bool   `json:"control"`
	Protocol  uint16 `json:"protocol"`
	HeaderHex string `json:"header_hex"`
}

// seed derives a fixed 32-byte value so every run uses the same keys.
func seed(label string) [32]byte { return sha256.Sum256([]byte("codewire tailscale golden: " + label)) }

func fixed12(label string) [12]byte {
	s := seed(label)
	var b [12]byte
	copy(b[:], s[:])
	return b
}

func h(b []byte) string { return hex.EncodeToString(b) }

func mustText(t *testing.T, m interface{ MarshalText() ([]byte, error) }) string {
	t.Helper()
	b, err := m.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func frame(t *testing.T, name string, ft derp.FrameType, payload []byte) frameCase {
	t.Helper()
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	if err := derp.WriteFrame(bw, ft, payload); err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	return frameCase{Name: name, Type: uint8(ft), PayloadHex: h(payload), FrameHex: h(buf.Bytes())}
}

func tailscaleModule(t *testing.T) moduleInfo {
	t.Helper()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info")
	}
	for _, d := range info.Deps {
		if d.Path == "tailscale.com" {
			if d.Replace != nil {
				d = d.Replace
			}
			return moduleInfo{Module: d.Path, Version: d.Version, Sum: d.Sum}
		}
	}
	t.Fatal("tailscale.com is not in the build")
	return moduleInfo{}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// build returns the golden for the pinned Tailscale. Sealed entries are taken
// from prev when present, because sealing uses a random nonce.
func build(t *testing.T, prev *golden) golden {
	t.Helper()
	nodeA := key.NodePrivateFromRaw32(mem.B(seedSlice("node a")))
	nodeB := key.NodePrivateFromRaw32(mem.B(seedSlice("node b")))
	discoA := key.DiscoPrivateFromRaw32(mem.B(seedSlice("disco a")))
	discoB := key.DiscoPrivateFromRaw32(mem.B(seedSlice("disco b")))
	nodePair := func(k key.NodePrivate) keyPair {
		raw, pub := k.Raw32(), k.Public().Raw32()
		return keyPair{PrivateHex: h(raw[:]), PublicHex: h(pub[:]), PublicText: mustText(t, k.Public())}
	}
	// key.DiscoPrivate has no Raw32, so the private half is the seed it was
	// built from.
	discoPair := func(label string, k key.DiscoPrivate) keyPair {
		raw, pub := seed(label), k.Public().Raw32()
		return keyPair{PrivateHex: h(raw[:]), PublicHex: h(pub[:]), PublicText: mustText(t, k.Public())}
	}

	g := golden{
		Version:     1,
		GeneratedBy: "tests/contract/tailscalegolden/golden_test.go",
		Tailscale:   tailscaleModule(t),
		Keys: goldenKeys{
			NodeA: nodePair(nodeA), NodeB: nodePair(nodeB),
			DiscoA: discoPair("disco a", discoA), DiscoB: discoPair("disco b", discoB),
		},
	}

	// DERP.
	nodeBPub := nodeB.Public().Raw32()
	nodeAPub := nodeA.Public().Raw32()
	g.DERP = goldenDERP{
		MagicHex:        h([]byte(derp.Magic)),
		ProtocolVersion: derp.ProtocolVersion,
		FrameHeaderLen:  derp.FrameHeaderLen,
		MaxPacketSize:   derp.MaxPacketSize,
		MagicIPAddr:     tailcfg.DerpMagicIPAddr.String(),
		FrameTypes: map[string]uint8{
			"server_key": uint8(derp.FrameServerKey), "client_info": uint8(derp.FrameClientInfo),
			"server_info": uint8(derp.FrameServerInfo), "send_packet": uint8(derp.FrameSendPacket),
			"forward_packet": uint8(derp.FrameForwardPacket), "recv_packet": uint8(derp.FrameRecvPacket),
			"keep_alive": uint8(derp.FrameKeepAlive), "note_preferred": uint8(derp.FrameNotePreferred),
			"peer_gone": uint8(derp.FramePeerGone), "peer_present": uint8(derp.FramePeerPresent),
			"watch_conns": uint8(derp.FrameWatchConns), "close_peer": uint8(derp.FrameClosePeer),
			"ping": uint8(derp.FramePing), "pong": uint8(derp.FramePong),
			"health": uint8(derp.FrameHealth), "restarting": uint8(derp.FrameRestarting),
		},
	}
	pingData := fixed12("derp ping")
	g.DERP.Frames = []frameCase{
		frame(t, "server_key", derp.FrameServerKey, append([]byte(derp.Magic), nodeBPub[:]...)),
		frame(t, "send_packet", derp.FrameSendPacket, append(nodeBPub[:], []byte("hello over derp")...)),
		frame(t, "recv_packet", derp.FrameRecvPacket, append(nodeAPub[:], []byte("hello over derp")...)),
		frame(t, "keep_alive", derp.FrameKeepAlive, nil),
		frame(t, "note_preferred", derp.FrameNotePreferred, []byte{0x01}),
		frame(t, "peer_gone", derp.FramePeerGone, append(nodeAPub[:], 0x00)),
		frame(t, "ping", derp.FramePing, pingData[:8]),
		frame(t, "pong", derp.FramePong, pingData[:8]),
	}
	clientInfo := []byte(`{"version":2,"meshKey":"","canAckPings":true,"isProber":false}`)
	g.DERP.Sealed = keepOrSeal(t, prev, "client_info", func() sealedCase {
		return sealedCase{Name: "client_info", From: "node_a", To: "node_b", PlaintextHex: h(clientInfo),
			SealedHex: h(nodeA.SealTo(nodeB.Public(), clientInfo))}
	}, func(c sealedCase) bool {
		sealed, _ := hex.DecodeString(c.SealedHex)
		got, ok := nodeB.OpenFrom(nodeA.Public(), sealed)
		return ok && h(got) == c.PlaintextHex
	})

	// Disco.
	txID := fixed12("disco tx")
	challenge := seed("relay challenge")
	endpoint := disco.UDPRelayEndpoint{
		ServerDisco: discoB.Public(), ClientDisco: [2]key.DiscoPublic{discoA.Public(), discoB.Public()},
		LamportID: 7, VNI: 0x00abcd, BindLifetime: 5 * time.Second, SteadyStateLifetime: 5 * time.Minute,
		AddrPorts: []netip.AddrPort{ap("203.0.113.10:7777"), ap("[2001:db8::10]:7777")},
	}
	common := disco.BindUDPRelayEndpointCommon{VNI: 0x00abcd, Generation: 3, RemoteKey: discoA.Public(), Challenge: challenge}
	discoAPub, discoBPub := discoA.Public().Raw32(), discoB.Public().Raw32()
	relayCase := func(name string, typ disco.MessageType, m disco.Message) discoCase {
		return discoCase{Name: name, Type: uint8(typ), VNI: common.VNI, Generation: common.Generation,
			RemoteKey: h(discoAPub[:]), Challenge: h(challenge[:]), PayloadHex: h(m.AppendMarshal(nil))}
	}
	endpointCase := func(name string, typ disco.MessageType, generation uint32, m disco.Message) discoCase {
		var eps []string
		for _, a := range endpoint.AddrPorts {
			eps = append(eps, a.String())
		}
		return discoCase{Name: name, Type: uint8(typ), Generation: generation,
			ServerDisco: h(discoBPub[:]), ClientDisco: []string{h(discoAPub[:]), h(discoBPub[:])},
			LamportID: endpoint.LamportID, VNI: endpoint.VNI,
			BindNanos: int64(endpoint.BindLifetime), SteadyNanos: int64(endpoint.SteadyStateLifetime),
			Endpoints: eps, PayloadHex: h(m.AppendMarshal(nil))}
	}
	g.Disco = goldenDisco{
		MagicHex: h([]byte(disco.Magic)),
		NonceLen: disco.NonceLen,
		Messages: []discoCase{
			{Name: "ping", Type: uint8(disco.TypePing), TxIDHex: h(txID[:]),
				PayloadHex: h((&disco.Ping{TxID: txID}).AppendMarshal(nil))},
			{Name: "ping_with_node_key", Type: uint8(disco.TypePing), TxIDHex: h(txID[:]), NodeKeyHex: h(nodeAPub[:]),
				PayloadHex: h((&disco.Ping{TxID: txID, NodeKey: nodeA.Public()}).AppendMarshal(nil))},
			{Name: "ping_padded", Type: uint8(disco.TypePing), TxIDHex: h(txID[:]), NodeKeyHex: h(nodeAPub[:]), Padding: 16,
				PayloadHex: h((&disco.Ping{TxID: txID, NodeKey: nodeA.Public(), Padding: 16}).AppendMarshal(nil))},
			{Name: "pong_v4", Type: uint8(disco.TypePong), TxIDHex: h(txID[:]), Src: "198.51.100.7:41641",
				PayloadHex: h((&disco.Pong{TxID: txID, Src: ap("198.51.100.7:41641")}).AppendMarshal(nil))},
			{Name: "pong_v6", Type: uint8(disco.TypePong), TxIDHex: h(txID[:]), Src: "[2001:db8::7]:41641",
				PayloadHex: h((&disco.Pong{TxID: txID, Src: ap("[2001:db8::7]:41641")}).AppendMarshal(nil))},
			{Name: "call_me_maybe", Type: uint8(disco.TypeCallMeMaybe),
				Endpoints:  []string{"198.51.100.7:41641", "[2001:db8::7]:41641"},
				PayloadHex: h((&disco.CallMeMaybe{MyNumber: []netip.AddrPort{ap("198.51.100.7:41641"), ap("[2001:db8::7]:41641")}}).AppendMarshal(nil))},
			relayCase("bind_udp_relay_endpoint", disco.TypeBindUDPRelayEndpoint, &disco.BindUDPRelayEndpoint{BindUDPRelayEndpointCommon: common}),
			relayCase("bind_udp_relay_endpoint_challenge", disco.TypeBindUDPRelayEndpointChallenge, &disco.BindUDPRelayEndpointChallenge{BindUDPRelayEndpointCommon: common}),
			relayCase("bind_udp_relay_endpoint_answer", disco.TypeBindUDPRelayEndpointAnswer, &disco.BindUDPRelayEndpointAnswer{BindUDPRelayEndpointCommon: common}),
			{Name: "allocate_udp_relay_endpoint_request", Type: uint8(disco.TypeAllocateUDPRelayEndpointRequest),
				ClientDisco: []string{h(discoAPub[:]), h(discoBPub[:])}, Generation: 9,
				PayloadHex: h((&disco.AllocateUDPRelayEndpointRequest{ClientDisco: endpoint.ClientDisco, Generation: 9}).AppendMarshal(nil))},
			endpointCase("allocate_udp_relay_endpoint_response", disco.TypeAllocateUDPRelayEndpointResponse, 9,
				&disco.AllocateUDPRelayEndpointResponse{Generation: 9, UDPRelayEndpoint: endpoint}),
			endpointCase("call_me_maybe_via", disco.TypeCallMeMaybeVia, 0, &disco.CallMeMaybeVia{UDPRelayEndpoint: endpoint}),
		},
	}
	pingPayload := (&disco.Ping{TxID: txID, NodeKey: nodeA.Public()}).AppendMarshal(nil)
	g.Disco.Sealed = keepOrSealDisco(t, prev, "ping", func() sealedDisco {
		return sealedDisco{Name: "ping", From: "disco_a", To: "disco_b", PayloadHex: h(pingPayload),
			PacketHex: h(sealDisco(discoA, discoB.Public(), pingPayload))}
	}, func(c sealedDisco) bool {
		packetBytes, _ := hex.DecodeString(c.PacketHex)
		got, ok := openDisco(discoB, packetBytes)
		return ok && h(got) == c.PayloadHex
	})

	// STUN.
	stunTx := stun.TxID(fixed12("stun tx"))
	g.STUN = goldenSTUN{
		Request: stunCase{TxIDHex: h(stunTx[:]), PacketHex: h(stun.Request(stunTx))},
		Responses: []stunCase{
			{TxIDHex: h(stunTx[:]), Addr: "203.0.113.7:41641", PacketHex: h(stun.Response(stunTx, ap("203.0.113.7:41641")))},
			{TxIDHex: h(stunTx[:]), Addr: "[2001:db8::7]:41641", PacketHex: h(stun.Response(stunTx, ap("[2001:db8::7]:41641")))},
		},
	}

	// Geneve headers used by the UDP peer relay.
	geneve := func(name string, vni uint32, control bool, protocol uint16) geneveCase {
		hdr := packet.GeneveHeader{Protocol: protocol, Control: control}
		hdr.VNI.Set(vni)
		b := make([]byte, packet.GeneveFixedHeaderLength)
		if err := hdr.Encode(b); err != nil {
			t.Fatal(err)
		}
		return geneveCase{Name: name, VNI: vni, Control: control, Protocol: protocol, HeaderHex: h(b)}
	}
	g.Geneve = []geneveCase{
		geneve("control_disco", 0x00abcd, true, packet.GeneveProtocolDisco),
		geneve("relay_disco", 0x00abcd, false, packet.GeneveProtocolDisco),
		geneve("relay_wireguard", 0x00abcd, false, packet.GeneveProtocolWireGuard),
	}
	return g
}

func seedSlice(label string) []byte { s := seed(label); return s[:] }

// sealDisco builds a disco packet the way magicsock does: magic, the
// sender's disco public key, then the sealed payload.
func sealDisco(from key.DiscoPrivate, to key.DiscoPublic, payload []byte) []byte {
	pub := from.Public().Raw32()
	out := append([]byte(disco.Magic), pub[:]...)
	return append(out, from.Shared(to).Seal(payload)...)
}

func openDisco(to key.DiscoPrivate, p []byte) ([]byte, bool) {
	src, ok := disco.Source(p)
	if !ok {
		return nil, false
	}
	from := key.DiscoPublicFromRaw32(mem.B(src))
	return to.Shared(from).Open(p[len(disco.Magic)+len(src):])
}

func keepOrSeal(t *testing.T, prev *golden, name string, fresh func() sealedCase, valid func(sealedCase) bool) []sealedCase {
	t.Helper()
	if prev != nil {
		for _, c := range prev.DERP.Sealed {
			if c.Name == name && valid(c) {
				return []sealedCase{c}
			}
		}
	}
	return []sealedCase{fresh()}
}

func keepOrSealDisco(t *testing.T, prev *golden, name string, fresh func() sealedDisco, valid func(sealedDisco) bool) []sealedDisco {
	t.Helper()
	if prev != nil {
		for _, c := range prev.Disco.Sealed {
			if c.Name == name && valid(c) {
				return []sealedDisco{c}
			}
		}
	}
	return []sealedDisco{fresh()}
}

func encode(t *testing.T, g golden) []byte {
	t.Helper()
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestTailscaleGolden(t *testing.T) {
	var prev *golden
	if b, err := os.ReadFile(goldenPath); err == nil {
		var g golden
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatalf("decode %s: %v", goldenPath, err)
		}
		prev = &g
	}
	want := encode(t, build(t, prev))

	if os.Getenv("UPDATE_TAILSCALE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read %s: %v (run UPDATE_TAILSCALE_GOLDEN=1)", goldenPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not match tailscale.com %s; a Tailscale wire format or constant changed. "+
			"Run UPDATE_TAILSCALE_GOLDEN=1 GOWORK=off go test ./tailscalegolden/ in tests/contract, review the diff, "+
			"and update crates/codewire-tailnet until its golden test passes", goldenPath, tailscaleModule(t).Version)
	}
}
