package codewire

import (
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
)

// MeshClient is the client for the Codewire mesh API.
// Separate from the platform Client -- the mesh uses its own URL and auth.
type MeshClient struct {
	Networks *MeshNetworkService
	Nodes    *MeshNodeService
	KV       *MeshKVService
	Groups   *MeshGroupService

	baseURL       string
	httpClient    *http.Client
	networkClient codewirev1connect.MeshNetworkServiceClient
	nodeClient    codewirev1connect.MeshNodeServiceClient
	kvClient      codewirev1connect.MeshKeyValueServiceClient
	groupClient   codewirev1connect.MeshGroupServiceClient
}

// MeshOption configures a MeshClient.
type MeshOption func(*MeshClient)

// WithMeshHTTPClient sets a custom HTTP client.
func WithMeshHTTPClient(hc *http.Client) MeshOption {
	return func(c *MeshClient) { c.httpClient = hc }
}

// NewMeshClient creates a client for the Codewire mesh API.
func NewMeshClient(meshURL, authToken string, opts ...MeshOption) *MeshClient {
	c := &MeshClient{
		baseURL:    strings.TrimRight(meshURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	connectOptions := connect.WithInterceptors(bearerInterceptor{apiKey: authToken})
	c.networkClient = codewirev1connect.NewMeshNetworkServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.nodeClient = codewirev1connect.NewMeshNodeServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.kvClient = codewirev1connect.NewMeshKeyValueServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.groupClient = codewirev1connect.NewMeshGroupServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.Networks = &MeshNetworkService{client: c}
	c.Nodes = &MeshNodeService{client: c}
	c.KV = &MeshKVService{client: c}
	c.Groups = &MeshGroupService{client: c}
	return c
}
