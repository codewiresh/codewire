package tailnet

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestNewDERPMap_RelayOnly(t *testing.T) {
	dm := NewDERPMap("derp.example.com", 443, false)
	if len(dm.Regions) != 1 {
		t.Fatalf("expected 1 region, got %d", len(dm.Regions))
	}
	relay := dm.Regions[1]
	if relay == nil {
		t.Fatal("missing region 1")
	}
	if relay.Nodes[0].STUNPort != -1 {
		t.Fatalf("relay STUNPort = %d, want -1", relay.Nodes[0].STUNPort)
	}
	if relay.Nodes[0].HostName != "derp.example.com" {
		t.Fatalf("hostname = %q, want derp.example.com", relay.Nodes[0].HostName)
	}
}

func TestNewDERPMap_RelayPreservesConfig(t *testing.T) {
	dm := NewDERPMap("test.example.com", 8443, true)
	node := dm.Regions[1].Nodes[0]
	if node.DERPPort != 8443 {
		t.Fatalf("DERPPort = %d, want 8443", node.DERPPort)
	}
	if !node.InsecureForTests {
		t.Fatal("InsecureForTests should be true")
	}
}

func TestWithSTUNNode(t *testing.T) {
	dm := NewDERPMap("derp.example.com", 443, false)
	WithSTUNNode(dm, "stun.example.com", 3478)

	nodes := dm.Regions[1].Nodes
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	stun := nodes[1]
	if !stun.STUNOnly {
		t.Fatal("second node should be STUNOnly")
	}
	if stun.HostName != "stun.example.com" {
		t.Fatalf("STUN host = %q, want stun.example.com", stun.HostName)
	}
	if stun.STUNPort != 3478 {
		t.Fatalf("STUN port = %d, want 3478", stun.STUNPort)
	}
	if stun.RegionID != 1 {
		t.Fatalf("STUN regionID = %d, want 1 (same as relay)", stun.RegionID)
	}
}

func TestWithSTUNNode_NilRegion(t *testing.T) {
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{}}
	WithSTUNNode(dm, "stun.example.com", 3478) // should not panic
}

func TestWithSTUNNode_MultipleNodesUseStableNames(t *testing.T) {
	dm := NewDERPMap("derp.example.com", 443, false)
	WithSTUNNode(dm, "stun.codewire-dev.sh", 3478)
	WithSTUNNode(dm, "stun.l.google.com", 19302)

	nodes := dm.Regions[1].Nodes
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}
	if nodes[1].Name != "1s" {
		t.Fatalf("first STUN node name = %q, want 1s", nodes[1].Name)
	}
	if nodes[2].Name != "1s2" {
		t.Fatalf("second STUN node name = %q, want 1s2", nodes[2].Name)
	}
}
