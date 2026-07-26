package tailnet

import (
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"tailscale.com/types/key"
)

func makeNode(id uuid.UUID) *Node {
	return &Node{
		ID:            id,
		AsOf:          time.Now(),
		Key:           key.NewNode().Public(),
		DiscoKey:      key.NewDisco().Public(),
		PreferredDERP: 1,
	}
}

func TestRegisterAndDeregister(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	id := uuid.New()
	ch := coord.Register(id, "test-peer")

	// Channel should be open and empty.
	select {
	case <-ch:
		t.Fatal("expected empty channel")
	default:
	}

	coord.Deregister(id)

	// Channel should be closed after deregister.
	_, ok := <-ch
	if ok {
		t.Fatal("expected channel to be closed after deregister")
	}
}

func TestRegisterReconnect(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	id := uuid.New()
	ch1 := coord.Register(id, "peer-v1")
	ch2 := coord.Register(id, "peer-v2")

	// Old channel should be closed.
	_, ok := <-ch1
	if ok {
		t.Fatal("expected old channel to be closed on re-register")
	}

	// New channel should be open.
	select {
	case <-ch2:
		t.Fatal("expected new channel to be open and empty")
	default:
	}
}

func TestUpdateNodeNotifiesTunnelPeers(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	clientID := uuid.New()
	agentID := uuid.New()

	clientCh := coord.Register(clientID, "client")
	agentCh := coord.Register(agentID, "agent")

	coord.AddTunnel(clientID, agentID)

	// Agent sends a node update — client should receive it.
	agentNode := makeNode(agentID)
	coord.UpdateNode(agentID, agentNode)

	select {
	case nodes := <-clientCh:
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].ID != agentID {
			t.Fatalf("expected agent ID %s, got %s", agentID, nodes[0].ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for client to receive agent node")
	}

	// Client sends a node update — agent should receive it.
	clientNode := makeNode(clientID)
	coord.UpdateNode(clientID, clientNode)

	select {
	case nodes := <-agentCh:
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].ID != clientID {
			t.Fatalf("expected client ID %s, got %s", clientID, nodes[0].ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for agent to receive client node")
	}
}

func TestAddTunnelExchangesExistingNodes(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	clientID := uuid.New()
	agentID := uuid.New()

	clientCh := coord.Register(clientID, "client")
	agentCh := coord.Register(agentID, "agent")

	// Both peers send nodes before the tunnel is created.
	agentNode := makeNode(agentID)
	clientNode := makeNode(clientID)
	coord.UpdateNode(agentID, agentNode)
	coord.UpdateNode(clientID, clientNode)

	// No updates yet — no tunnel exists.
	select {
	case <-clientCh:
		t.Fatal("should not receive update without tunnel")
	case <-agentCh:
		t.Fatal("should not receive update without tunnel")
	default:
	}

	// Add tunnel — should exchange existing nodes immediately.
	coord.AddTunnel(clientID, agentID)

	select {
	case nodes := <-clientCh:
		if len(nodes) != 1 || nodes[0].ID != agentID {
			t.Fatalf("expected agent node, got %v", nodes)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: client should receive agent node on AddTunnel")
	}

	select {
	case nodes := <-agentCh:
		if len(nodes) != 1 || nodes[0].ID != clientID {
			t.Fatalf("expected client node, got %v", nodes)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: agent should receive client node on AddTunnel")
	}
}

func TestUpdateNodeNoUpdateWithoutTunnel(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	id1 := uuid.New()
	id2 := uuid.New()

	ch1 := coord.Register(id1, "peer1")
	_ = coord.Register(id2, "peer2")

	// Update node without any tunnel — no cross-notification.
	coord.UpdateNode(id2, makeNode(id2))

	select {
	case <-ch1:
		t.Fatal("should not receive update without tunnel")
	default:
	}
}

func TestDeregisterRemovesTunnels(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	clientID := uuid.New()
	agentID := uuid.New()

	coord.Register(clientID, "client")
	agentCh := coord.Register(agentID, "agent")

	coord.AddTunnel(clientID, agentID)
	coord.Deregister(clientID)

	// Agent should not panic or receive updates for deregistered client.
	coord.UpdateNode(agentID, makeNode(agentID))

	select {
	case <-agentCh:
		t.Fatal("should not receive update after tunnel peer deregistered")
	default:
	}
}

func TestCloseClosesAllChannels(t *testing.T) {
	coord := NewCoordinator(slog.Default())

	ch1 := coord.Register(uuid.New(), "a")
	ch2 := coord.Register(uuid.New(), "b")

	coord.Close()

	_, ok1 := <-ch1
	_, ok2 := <-ch2
	if ok1 || ok2 {
		t.Fatal("expected all channels to be closed after Close")
	}

	// Double close should not panic.
	coord.Close()
}

func TestUpdateNodeUnregisteredPeer(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	defer coord.Close()

	// Should not panic on unknown peer.
	coord.UpdateNode(uuid.New(), makeNode(uuid.New()))
}

func TestUpdateNodeAfterClose(t *testing.T) {
	coord := NewCoordinator(slog.Default())
	coord.Close()

	// Should not panic on closed coordinator.
	coord.UpdateNode(uuid.New(), makeNode(uuid.New()))
}
