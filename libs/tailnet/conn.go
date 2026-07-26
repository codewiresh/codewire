package tailnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go4.org/netipx"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	tslogger "tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func init() {
	netns.SetEnabled(false)
}

// Options configures a WireGuard connection.
type Options struct {
	ID               uuid.UUID
	Addresses        []netip.Prefix
	DERPMap          *tailcfg.DERPMap
	Logger           *slog.Logger
	ListenPort       uint16
	StaticEndpoints  []netip.AddrPort
	DisablePeerRelay bool
}

// Conn wraps a Tailscale WireGuard engine + netstack to provide net.Listener
// and DialContextTCP over WireGuard.
type Conn struct {
	mu           sync.Mutex
	closed       chan struct{}
	stateChanged chan struct{}

	id       uuid.UUID
	nodeKey  key.NodePrivate
	discoKey key.DiscoPublic
	addrs    []netip.Prefix
	logger   *slog.Logger

	sys       *tsd.System
	lb        *ipnlocal.LocalBackend
	engine    wgengine.Engine
	magicConn *magicsock.Conn
	netStack  *netstack.Impl
	netMon    *netmon.Monitor
	dialer    *tsdial.Dialer
	listeners map[listenKey]*listener

	// Node tracking
	preferredDERP int
	activeDERPs   int
	derpConnected map[int]bool
	endpoints     []netip.AddrPort
	derpLatency   map[string]float64
	nodeCb        func(*Node)
	derpMap       *tailcfg.DERPMap
	filter        *filter.Filter
}

// NodeID creates a tailcfg.NodeID from a UUID.
func NodeID(uid uuid.UUID) tailcfg.NodeID {
	id := int64(binary.BigEndian.Uint64(uid[8:]))
	y := id >> 63
	id = (id ^ y) - y
	return tailcfg.NodeID(id)
}

func newCodewireTailnetFilter(logf tslogger.Logf, peerRelayEnabled bool) *filter.Filter {
	any4 := netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0)
	any6 := netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)
	allPorts := filter.PortRange{First: 0, Last: 65535}
	caps := []filter.CapMatch{}
	if peerRelayEnabled {
		caps = []filter.CapMatch{
			{Dst: any4, Cap: tailcfg.PeerCapabilityRelay},
			{Dst: any6, Cap: tailcfg.PeerCapabilityRelay},
			{Dst: any4, Cap: tailcfg.PeerCapabilityRelayTarget},
			{Dst: any6, Cap: tailcfg.PeerCapabilityRelayTarget},
		}
	}
	matches := []filter.Match{
		{
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv4}),
			Srcs:    []netip.Prefix{any4},
			Dsts: []filter.NetPortRange{{
				Net:   any4,
				Ports: allPorts,
			}},
			Caps: caps,
		},
		{
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv6}),
			Srcs:    []netip.Prefix{any6},
			Dsts: []filter.NetPortRange{{
				Net:   any6,
				Ports: allPorts,
			}},
			Caps: caps,
		},
	}
	var builder netipx.IPSetBuilder
	builder.AddPrefix(any4)
	builder.AddPrefix(any6)
	ipSet, _ := builder.IPSet()
	return filter.New(matches, nil, ipSet, ipSet, nil, logf)
}

// NewConn creates a new WireGuard connection.
func NewConn(opts *Options) (*Conn, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	var logConn atomic.Pointer[Conn]
	nodePrivKey := key.NewNode()

	logf := tslogger.Logf(func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if c := logConn.Load(); c != nil {
			c.observeMagicsockLog(msg)
		}
		opts.Logger.Debug(msg)
	})

	sys := tsd.NewSystem()

	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, fmt.Errorf("netmon: %w", err)
	}

	dialer := &tsdial.Dialer{Logf: logf}

	engine, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		NetMon:        netMon,
		Dialer:        dialer,
		ListenPort:    opts.ListenPort,
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
	})
	if err != nil {
		netMon.Close()
		return nil, fmt.Errorf("wgengine: %w", err)
	}

	engine = wgengine.NewWatchdog(engine)
	sys.Set(engine)
	sys.Set(new(mem.Store))

	mc := sys.MagicSock.Get()

	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := engine.PeerForIP(ip)
		return ok
	}

	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("local backend: %w", err)
	}

	ns, err := netstack.Create(
		logf,
		sys.Tun.Get(),
		engine,
		mc,
		dialer,
		sys.DNSManager.Get(),
		sys.ProxyMapper(),
	)
	if err != nil {
		lb.Shutdown()
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("netstack: %w", err)
	}

	sys.Tun.Get().Start()
	tailnetFilter := newCodewireTailnetFilter(logf, !opts.DisablePeerRelay)
	sys.Tun.Get().SetFilter(tailnetFilter)

	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}
	ns.ProcessLocalIPs = true

	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("netstack start: %w", err)
	}

	c := &Conn{
		closed:        make(chan struct{}),
		stateChanged:  make(chan struct{}),
		id:            opts.ID,
		nodeKey:       nodePrivKey,
		discoKey:      mc.DiscoPublicKey(),
		addrs:         opts.Addresses,
		logger:        opts.Logger,
		sys:           sys,
		lb:            lb,
		engine:        engine,
		magicConn:     mc,
		netStack:      ns,
		netMon:        netMon,
		dialer:        dialer,
		listeners:     make(map[listenKey]*listener),
		derpConnected: make(map[int]bool),
		filter:        tailnetFilter,
	}
	logConn.Store(c)

	// Track endpoint and DERP changes via magicsock callbacks.
	mc.SetNetInfoCallback(func(ni *tailcfg.NetInfo) {
		c.mu.Lock()
		prevDERP := c.preferredDERP
		c.preferredDERP = ni.PreferredDERP
		c.derpLatency = ni.DERPLatency
		cb := c.nodeCb
		c.notifyStateChangedLocked()
		c.mu.Unlock()
		opts.Logger.Debug("tailnet: netinfo update",
			"preferred_derp", ni.PreferredDERP,
			"prev_derp", prevDERP,
			"derp_latency", ni.DERPLatency,
		)
		if cb != nil {
			cb(c.Node())
		}
	})
	engine.SetStatusCallback(func(s *wgengine.Status, err error) {
		if err != nil {
			return
		}
		eps := make([]netip.AddrPort, len(s.LocalAddrs))
		for i, ep := range s.LocalAddrs {
			eps[i] = ep.Addr
		}
		c.mu.Lock()
		c.endpoints = eps
		c.activeDERPs = s.DERPs
		cb := c.nodeCb
		c.notifyStateChangedLocked()
		c.mu.Unlock()
		opts.Logger.Debug("tailnet: endpoints updated", "count", len(eps), "endpoints", eps, "active_derps", s.DERPs)
		if cb != nil {
			cb(c.Node())
		}
	})

	if opts.DERPMap != nil {
		c.derpMap = opts.DERPMap
		mc.SetDERPMap(opts.DERPMap)
	}
	if len(opts.StaticEndpoints) > 0 {
		mc.SetStaticEndpoints(views.SliceOf(append([]netip.AddrPort(nil), opts.StaticEndpoints...)))
	}
	c.applyNetworkMap(nil)

	return c, nil
}

func (c *Conn) observeMagicsockLog(msg string) {
	// DERPs() only reports allocated DERP clients. The server-acknowledged
	// registration signal is logged when magicsock receives ServerInfoMessage.
	if regionID, ok := parseDERPConnectedLog(msg); ok {
		c.setDERPConnected(regionID, true)
		return
	}
	if regionID, ok := parseDERPRecvErrorLog(msg); ok {
		c.setDERPConnected(regionID, false)
	}
}

func (c *Conn) setDERPConnected(regionID int, connected bool) {
	if regionID <= 0 {
		return
	}

	c.mu.Lock()
	wasConnected := c.derpConnected[regionID]
	if connected {
		c.derpConnected[regionID] = true
	} else {
		delete(c.derpConnected, regionID)
	}
	changed := wasConnected != connected
	if changed {
		c.notifyStateChangedLocked()
	}
	c.mu.Unlock()

	if changed {
		c.logger.Debug("tailnet: derp connection state", "region_id", regionID, "connected", connected)
	}
}

func parseDERPConnectedLog(msg string) (int, bool) {
	const prefix = "magicsock: derp-"
	if !strings.HasPrefix(msg, prefix) {
		return 0, false
	}
	rest := strings.TrimPrefix(msg, prefix)
	region, suffix, ok := parseLeadingPositiveInt(rest)
	if !ok || !strings.HasPrefix(suffix, " connected;") {
		return 0, false
	}
	return region, true
}

func parseDERPRecvErrorLog(msg string) (int, bool) {
	const marker = "derp.Recv(derp-"
	idx := strings.Index(msg, marker)
	if idx < 0 {
		return 0, false
	}
	rest := msg[idx+len(marker):]
	region, suffix, ok := parseLeadingPositiveInt(rest)
	if !ok || !strings.HasPrefix(suffix, ")") {
		return 0, false
	}
	return region, true
}

func parseLeadingPositiveInt(s string) (int, string, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, s, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil || n <= 0 {
		return 0, s[end:], false
	}
	return n, s[end:], true
}

// SetNodeCallback sets a callback invoked when local node info changes.
func (c *Conn) SetNodeCallback(cb func(*Node)) {
	c.mu.Lock()
	c.nodeCb = cb
	c.mu.Unlock()
	if cb != nil {
		cb(c.Node())
	}
}

// SetDERPMap updates the DERP map and re-applies the NetworkMap so that
// magicsock's netcheck can discover public endpoints via STUN.
func (c *Conn) SetDERPMap(dm *tailcfg.DERPMap) {
	if dm != nil {
		for id, region := range dm.Regions {
			for _, node := range region.Nodes {
				c.logger.Debug("tailnet: SetDERPMap",
					"region_id", id,
					"node", node.Name,
					"host", node.HostName,
					"derp_port", node.DERPPort,
					"stun_port", node.STUNPort,
					"stun_only", node.STUNOnly,
					"insecure", node.InsecureForTests,
				)
			}
		}
	}
	c.mu.Lock()
	c.derpMap = dm
	c.mu.Unlock()
	c.magicConn.SetDERPMap(dm)
	c.magicConn.ReSTUN("derpmap-update")
}

// WaitForDERPHome forces and waits for an active home DERP connection. This is
// required before advertising listener nodes that must be reachable from
// clients without a direct UDP path, such as VM sandbox gateways.
func (c *Conn) WaitForDERPHome(ctx context.Context, regionID int) error {
	if regionID <= 0 {
		return fmt.Errorf("invalid derp region %d", regionID)
	}

	c.magicConn.DebugForcePreferDERP(regionID)
	c.magicConn.SetNetworkUp(true)
	c.magicConn.ReSTUN("wait-for-derp-home")

	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return fmt.Errorf("conn closed")
		default:
		}
		derpConnected := c.derpConnected[regionID]
		ready := c.preferredDERP == regionID && c.activeDERPs > 0 && derpConnected
		ch := c.stateChanged
		preferredDERP := c.preferredDERP
		activeDERPs := c.activeDERPs
		c.mu.Unlock()

		if ready {
			return nil
		}

		c.logger.Debug("tailnet: waiting for derp home",
			"wanted_derp", regionID,
			"preferred_derp", preferredDERP,
			"active_derps", activeDERPs,
			"derp_connected", derpConnected,
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for derp home %d: %w", regionID, ctx.Err())
		case <-ch:
		}
	}
}

// UpdatePeers configures the WireGuard engine with the given peer nodes.
func (c *Conn) UpdatePeers(peers []*Node) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return fmt.Errorf("conn closed")
	default:
	}
	c.applyNetworkMap(peers)
	return nil
}

func (c *Conn) applyNetworkMap(peers []*Node) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        NodeID(c.id),
			Cap:       tailcfg.CurrentCapabilityVersion,
			Key:       c.nodeKey.Public(),
			Addresses: c.addrs,
		}).View(),
		NodeKey: c.nodeKey.Public(),
		DERPMap: c.derpMap,
	}

	for _, p := range peers {
		nm.Peers = append(nm.Peers, tailcfgNodeFromPeer(p).View())
	}

	c.engine.SetFilter(c.filter)
	c.magicConn.SetFilter(c.filter)
	c.engine.SetNetworkMap(nm)
	c.magicConn.SetNetworkMap(nm.SelfNode, nm.Peers)
	c.netStack.UpdateNetstackIPs(nm)
	if err := c.engine.Reconfig(nmToCfg(nm, c.nodeKey), &router.Config{LocalAddrs: c.addrs}, &dns.Config{}); err != nil {
		c.logger.Warn("reconfig failed", "error", err)
	}
}

// Listen returns a net.Listener on the tailnet address.
func (c *Conn) Listen(network, addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	lk := listenKey{network, host, port}
	ln := &listener{
		s:      c,
		key:    lk,
		addr:   addr,
		closed: make(chan struct{}),
		conn:   make(chan net.Conn),
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, fmt.Errorf("conn closed")
	default:
	}
	if _, ok := c.listeners[lk]; ok {
		c.mu.Unlock()
		return nil, fmt.Errorf("listener already open for %s %s", network, addr)
	}
	c.listeners[lk] = ln
	c.mu.Unlock()

	// Register TCP forwarding for this listener.
	c.netStack.GetTCPHandlerForFlow = c.forwardTCP
	return ln, nil
}

// DialContextTCP dials a TCP connection over the WireGuard tunnel.
func (c *Conn) DialContextTCP(ctx context.Context, dst netip.AddrPort) (*gonet.TCPConn, error) {
	return c.netStack.DialContextTCP(ctx, dst)
}

// Node returns the current node info for coordination.
func (c *Conn) Node() *Node {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &Node{
		ID:            c.id,
		AsOf:          time.Now(),
		Key:           c.nodeKey.Public(),
		DiscoKey:      c.discoKey,
		PreferredDERP: c.preferredDERP,
		Endpoints:     append([]netip.AddrPort(nil), c.endpoints...),
		Addresses:     append([]netip.Prefix(nil), c.addrs...),
	}
}

// Close shuts down the WireGuard engine.
func (c *Conn) Close() error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
	}
	close(c.closed)
	c.notifyStateChangedLocked()
	for _, l := range c.listeners {
		_ = l.closeNoLock()
	}
	c.listeners = nil
	c.mu.Unlock()

	_ = c.netStack.Close()
	c.lb.Shutdown()
	_ = c.netMon.Close()
	_ = c.dialer.Close()
	c.engine.Close()
	return nil
}

func (c *Conn) notifyStateChangedLocked() {
	close(c.stateChanged)
	c.stateChanged = make(chan struct{})
}

func (c *Conn) forwardTCP(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
	c.mu.Lock()
	ln, ok := c.listeners[listenKey{"tcp", "", fmt.Sprint(dst.Port())}]
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	return func(conn net.Conn) {
		t := time.NewTimer(time.Second)
		defer t.Stop()
		select {
		case ln.conn <- conn:
		case <-ln.closed:
			conn.Close()
		case <-c.closed:
			conn.Close()
		case <-t.C:
			conn.Close()
		}
	}, true
}

func nmToCfg(nm *netmap.NetworkMap, privateKey key.NodePrivate) *wgcfg.Config {
	cfg := &wgcfg.Config{
		PrivateKey: privateKey,
		Addresses:  nm.SelfNode.Addresses().AsSlice(),
	}
	for _, pv := range nm.Peers {
		pcfg := wgcfg.Peer{
			PublicKey: pv.Key(),
			DiscoKey:  pv.DiscoKey(),
		}
		for _, a := range pv.AllowedIPs().All() {
			pcfg.AllowedIPs = append(pcfg.AllowedIPs, a)
		}
		cfg.Peers = append(cfg.Peers, pcfg)
	}
	return cfg
}

// listenKey + listener: stable keying for tailnet TCP listeners.
type listenKey struct {
	network string
	host    string
	port    string
}

type listener struct {
	s      *Conn
	key    listenKey
	addr   string
	conn   chan net.Conn
	closed chan struct{}
}

func (ln *listener) Accept() (net.Conn, error) {
	select {
	case c := <-ln.conn:
		return c, nil
	case <-ln.closed:
		return nil, net.ErrClosed
	}
}

func (ln *listener) Addr() net.Addr { return lnAddr{ln.addr} }

func (ln *listener) Close() error {
	ln.s.mu.Lock()
	defer ln.s.mu.Unlock()
	return ln.closeNoLock()
}

func (ln *listener) closeNoLock() error {
	if v, ok := ln.s.listeners[ln.key]; ok && v == ln {
		delete(ln.s.listeners, ln.key)
		close(ln.closed)
	}
	return nil
}

type lnAddr struct{ s string }

func (a lnAddr) Network() string { return "tcp" }
func (a lnAddr) String() string  { return a.s }
