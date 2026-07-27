package codewire_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	codewire "codewire.sh/sdk-go"
)

func TestMeshNetworksRequireAndTransmitExactOrganization(t *testing.T) {
	t.Helper()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer cw_mesh_test" {
			t.Errorf("Authorization = %q, want exact mesh credential", got)
		}
		switch requests {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/networks" {
				t.Errorf("create = %s %s, want POST /api/v1/networks", r.Method, r.URL.Path)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["org_id"] != "org space/one" || body["network_id"] != "network-one" {
				t.Errorf("create body = %#v, want exact org and network", body)
			}
			w.WriteHeader(http.StatusOK)
		case 2:
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/networks" {
				t.Errorf("list = %s %s, want GET /api/v1/networks", r.Method, r.URL.Path)
			}
			if got := r.URL.Query().Get("org_id"); got != "org space/one" {
				t.Errorf("list org_id = %q, want exact organization", got)
			}
			_, _ = w.Write([]byte(`[{"id":"network-one","org_id":"org space/one","created_at":"2026-01-01T00:00:00Z","node_count":0,"invite_count":0}]`))
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	client := codewire.NewMeshClient(server.URL, "cw_mesh_test")
	if err := client.Networks.Create(context.Background(), "org space/one", "network-one"); err != nil {
		t.Fatal(err)
	}
	networks, err := client.Networks.List(context.Background(), "org space/one")
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 || networks[0].OrgID != "org space/one" {
		t.Fatalf("networks = %#v, want exact owned network", networks)
	}
}
