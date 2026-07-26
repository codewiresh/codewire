package tailnet

import (
	"log/slog"
	"sync"

	"github.com/google/uuid"
)

// Coordinator brokers WireGuard key exchange between clients and agents.
// Single-process, in-memory — no HA needed for v1.
type Coordinator struct {
	mu     sync.RWMutex
	closed bool
	peers  map[uuid.UUID]*coordPeer
	// tunnels tracks src→dst relationships (client→agent).
	tunnels map[uuid.UUID]uuid.UUID
	logger  *slog.Logger
}

type coordPeer struct {
	id   uuid.UUID
	name string
	node *Node
	// respCh receives peer updates to be forwarded over WebSocket.
	respCh chan []*Node
}

// NewCoordinator creates a new in-memory coordinator.
func NewCoordinator(logger *slog.Logger) *Coordinator {
	return &Coordinator{
		peers:   make(map[uuid.UUID]*coordPeer),
		tunnels: make(map[uuid.UUID]uuid.UUID),
		logger:  logger,
	}
}

// UpdateNode is called when a peer (agent or client) sends a new Node.
func (c *Coordinator) UpdateNode(id uuid.UUID, node *Node) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	p, ok := c.peers[id]
	if !ok {
		return
	}
	p.node = node

	// Notify all tunnel partners.
	for src, dst := range c.tunnels {
		if src == id {
			// I'm the source (client), notify the destination (agent).
			// Send ALL client peers so the agent keeps its full peer list.
			if agent, ok := c.peers[dst]; ok {
				c.sendAllPeers(agent, dst)
			}
		}
		if dst == id {
			// I'm the destination (agent), notify the source (client).
			if client, ok := c.peers[src]; ok {
				c.sendUpdate(client, id, node)
			}
		}
	}
}

// AddTunnel registers a client→agent tunnel and exchanges existing nodes.
// Returns true if the agent's node was delivered to the client immediately
// (same-replica fast path).
func (c *Coordinator) AddTunnel(clientID, agentID uuid.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.tunnels[clientID] = agentID

	client := c.peers[clientID]
	agent := c.peers[agentID]

	delivered := false
	// Send agent node to the new client.
	if client != nil && agent != nil && agent.node != nil {
		c.sendUpdate(client, agentID, agent.node)
		delivered = true
	}
	// Send ALL client peers to the agent (not just the new one).
	if agent != nil {
		c.sendAllPeers(agent, agentID)
	}
	return delivered
}

// Register adds a peer. Returns a channel that receives peer updates.
func (c *Coordinator) Register(id uuid.UUID, name string) <-chan []*Node {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close old peer if it exists (reconnection).
	if old, ok := c.peers[id]; ok {
		close(old.respCh)
	}

	ch := make(chan []*Node, 64)
	c.peers[id] = &coordPeer{
		id:     id,
		name:   name,
		respCh: ch,
	}
	return ch
}

// Deregister removes a peer and its tunnels.
func (c *Coordinator) Deregister(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if p, ok := c.peers[id]; ok {
		close(p.respCh)
		delete(c.peers, id)
	}

	// Remove any tunnels involving this peer.
	for src, dst := range c.tunnels {
		if src == id || dst == id {
			delete(c.tunnels, src)
		}
	}
}

// Close shuts down the coordinator.
func (c *Coordinator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	for _, p := range c.peers {
		close(p.respCh)
	}
	c.peers = nil
	c.tunnels = nil
	return nil
}

// sendAllPeers sends the full set of client nodes to an agent.
func (c *Coordinator) sendAllPeers(agent *coordPeer, agentID uuid.UUID) {
	var nodes []*Node
	for src, dst := range c.tunnels {
		if dst == agentID {
			if client, ok := c.peers[src]; ok && client.node != nil {
				nodes = append(nodes, client.node)
			}
		}
	}
	if len(nodes) == 0 {
		return
	}
	select {
	case agent.respCh <- nodes:
	default:
		c.logger.Warn("coordinator: dropped peer update (slow consumer)",
			"target", agent.id)
	}
}

func (c *Coordinator) sendUpdate(target *coordPeer, peerID uuid.UUID, node *Node) {
	select {
	case target.respCh <- []*Node{node}:
	default:
		c.logger.Warn("coordinator: dropped peer update (slow consumer)",
			"target", target.id, "peer", peerID)
	}
}
