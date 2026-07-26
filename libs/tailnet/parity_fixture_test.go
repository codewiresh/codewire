package tailnet

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"go4.org/mem"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const parityFixturePath = "../../tests/fixtures/tailnet/go_tailnet_parity.json"

type parityFixture struct {
	Version     int                  `json:"version"`
	GeneratedBy string               `json:"generated_by"`
	Oracle      parityOracleMetadata `json:"oracle"`
	PathCases   []parityPathCase     `json:"path_cases"`
	DERPMagic   []derpMagicCase      `json:"derp_magic_cases"`
	PrefixCases []prefixCase         `json:"prefix_cases"`
	NodeJSON    string               `json:"node_json"`
}

type parityPathCase struct {
	Name     string           `json:"name"`
	Ping     parityPingInput  `json:"ping"`
	Expected parityPathOutput `json:"expected"`
	Note     string           `json:"note,omitempty"`
}

type parityPingInput struct {
	Endpoint       string  `json:"endpoint,omitempty"`
	PeerRelay      string  `json:"peer_relay,omitempty"`
	DERPRegionID   int     `json:"derp_region_id,omitempty"`
	DERPRegionCode string  `json:"derp_region_code,omitempty"`
	LatencySeconds float64 `json:"latency_seconds,omitempty"`
}

type parityPathOutput struct {
	Transport      string  `json:"transport"`
	Endpoint       string  `json:"endpoint,omitempty"`
	PeerRelay      string  `json:"peer_relay,omitempty"`
	DERPRegionID   int     `json:"derp_region_id,omitempty"`
	DERPRegionCode string  `json:"derp_region_code,omitempty"`
	LatencySeconds float64 `json:"latency_seconds,omitempty"`
}

type prefixCase struct {
	UUID   string `json:"uuid"`
	Prefix string `json:"prefix"`
}

type derpMagicCase struct {
	RegionID int    `json:"region_id"`
	AddrPort string `json:"addr_port"`
	Note     string `json:"note,omitempty"`
}

type parityOracleMetadata struct {
	Modules     []parityOracleModule `json:"modules"`
	SourceFiles []parityOracleSource `json:"source_files"`
}

type parityOracleModule struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum,omitempty"`
	Replace string `json:"replace,omitempty"`
}

type parityOracleSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func TestTailnetParityFixture(t *testing.T) {
	fixture := buildParityFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	if os.Getenv("UPDATE_TAILNET_PARITY_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(parityFixturePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(parityFixturePath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(parityFixturePath)
	if err != nil {
		t.Fatalf("read parity fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("tailnet parity fixture drifted; run UPDATE_TAILNET_PARITY_FIXTURES=1 go test ./... in libs/tailnet and update Rust consumers")
	}
}

func buildParityFixture(t *testing.T) parityFixture {
	t.Helper()

	pathInputs := []struct {
		name string
		ping parityPingInput
		note string
	}{
		{
			name: "direct udp endpoint",
			ping: parityPingInput{Endpoint: "203.0.113.10:41641"},
		},
		{
			name: "peer relay",
			ping: parityPingInput{PeerRelay: "203.0.113.10:41641:vni:7"},
		},
		{
			name: "derp relay",
			ping: parityPingInput{
				DERPRegionID:   1,
				DERPRegionCode: "cw",
				LatencySeconds: 0.004,
			},
		},
		{
			name: "unknown",
			ping: parityPingInput{},
		},
		{
			name: "endpoint wins over derp",
			ping: parityPingInput{
				Endpoint:       "203.0.113.20:41641",
				DERPRegionID:   3,
				DERPRegionCode: "cw",
			},
			note: "Go magicsock reports a direct endpoint as the preferred transport even when DERP fields are populated.",
		},
		{
			name: "peer relay wins over derp",
			ping: parityPingInput{
				PeerRelay:      "203.0.113.30:41641:vni:9",
				DERPRegionID:   4,
				DERPRegionCode: "cw",
			},
			note: "DERP is still the control/fallback channel; a populated PeerRelay means the selected path is peer_relay.",
		},
	}

	pathCases := make([]parityPathCase, 0, len(pathInputs))
	for _, input := range pathInputs {
		got := peerPathFromPing(&ipnstate.PingResult{
			Endpoint:       input.ping.Endpoint,
			PeerRelay:      input.ping.PeerRelay,
			DERPRegionID:   input.ping.DERPRegionID,
			DERPRegionCode: input.ping.DERPRegionCode,
			LatencySeconds: input.ping.LatencySeconds,
		})
		pathCases = append(pathCases, parityPathCase{
			Name:     input.name,
			Ping:     input.ping,
			Expected: parityPathOutput(got),
			Note:     input.note,
		})
	}

	prefixInputs := []string{
		"12345678-1234-5678-1234-567812345678",
		"00112233-4455-6677-8899-aabbccddeeff",
	}
	prefixCases := make([]prefixCase, 0, len(prefixInputs))
	for _, raw := range prefixInputs {
		id := uuid.MustParse(raw)
		prefixCases = append(prefixCases, prefixCase{
			UUID:   raw,
			Prefix: CWServicePrefix.PrefixFromUUID(id).String(),
		})
	}

	nodeJSON, err := json.Marshal(parityNode(t))
	if err != nil {
		t.Fatal(err)
	}

	return parityFixture{
		Version:     3,
		GeneratedBy: "libs/tailnet/parity_fixture_test.go",
		Oracle:      buildParityOracleMetadata(t),
		PathCases:   pathCases,
		DERPMagic: []derpMagicCase{
			{
				RegionID: 1,
				AddrPort: netip.AddrPortFrom(
					tailcfg.DerpMagicIPAddr,
					1,
				).String(),
				Note: "Tailscale magicsock represents DERP receive paths as 127.3.3.40:<region>; DERP disco Pong.Src echoes this tuple.",
			},
		},
		PrefixCases: prefixCases,
		NodeJSON:    string(nodeJSON),
	}
}

func buildParityOracleMetadata(t *testing.T) parityOracleMetadata {
	t.Helper()

	modulePaths := map[string]bool{
		"tailscale.com": true,
	}
	modules := parityOracleModules(t, modulePaths)

	sourcePaths := []string{
		"conn.go",
		"coordinator.go",
		"derp.go",
		"node.go",
		"path.go",
	}
	sourceFiles := make([]parityOracleSource, 0, len(sourcePaths))
	for _, path := range sourcePaths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read Go oracle source %s: %v", path, err)
		}
		sum := sha256.Sum256(body)
		sourceFiles = append(sourceFiles, parityOracleSource{
			Path:   filepath.ToSlash(filepath.Join("libs/tailnet", path)),
			SHA256: fmt.Sprintf("%x", sum[:]),
		})
	}

	return parityOracleMetadata{
		Modules:     modules,
		SourceFiles: sourceFiles,
	}
}

func parityOracleModules(t *testing.T, wanted map[string]bool) []parityOracleModule {
	t.Helper()

	modules := make([]parityOracleModule, 0, len(wanted))
	paths := make([]string, 0, len(wanted))
	for path := range wanted {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		var dep struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Sum     string `json:"Sum"`
			Replace *struct {
				Path    string `json:"Path"`
				Version string `json:"Version"`
			} `json:"Replace"`
		}
		out, err := exec.Command("go", "list", "-m", "-json", path).CombinedOutput()
		if err != nil {
			t.Fatalf("go list oracle module %s: %v\n%s", path, err, out)
		}
		if err := json.Unmarshal(out, &dep); err != nil {
			t.Fatalf("parse go list oracle module %s: %v", path, err)
		}

		module := parityOracleModule{
			Path:    dep.Path,
			Version: dep.Version,
			Sum:     dep.Sum,
		}
		if dep.Replace != nil {
			module.Replace = dep.Replace.Path
			if dep.Replace.Version != "" {
				module.Replace += "@" + dep.Replace.Version
			}
		}
		if module.Path == "" || module.Version == "" {
			t.Fatalf("go list oracle module %s returned incomplete module: %+v", path, module)
		}
		modules = append(modules, module)
	}

	return modules
}

func parityNode(t *testing.T) *Node {
	t.Helper()

	id := uuid.MustParse("12345678-1234-5678-1234-567812345678")
	asOf, err := time.Parse(time.RFC3339, "2026-06-19T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}

	nodeRaw := [32]byte{}
	discoRaw := [32]byte{}
	nodeRaw[31] = 0x01
	discoRaw[31] = 0x02

	return &Node{
		ID:            id,
		AsOf:          asOf,
		Key:           key.NodePublicFromRaw32(mem.B(nodeRaw[:])),
		DiscoKey:      key.DiscoPublicFromRaw32(mem.B(discoRaw[:])),
		PreferredDERP: 3,
		DERPLatency:   map[string]float64{"1": 0.05},
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("1.2.3.4:41641"),
			netip.MustParseAddrPort("[2001:db8::1]:41641"),
		},
		Addresses: []netip.Prefix{
			CWServicePrefix.PrefixFromUUID(id),
		},
	}
}
