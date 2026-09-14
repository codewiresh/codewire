// Package codewire is the Go SDK for the Codewire API. It layers ergonomic
// service handles and a fluent Environment object over generated transport
// clients.
package codewire

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
)

// DefaultBaseURL is the production API base. Generated clients append their
// exact Connect RPC procedure paths.
const DefaultBaseURL = "https://codewire.sh"

// Client is the SDK entry point.
type Client struct {
	Environments   *EnvironmentService
	Presets        *PresetService
	APIKeys        *APIKeyService
	Secrets        *SecretService
	SecretProjects *SecretProjectService
	AccessProfiles *AccessProfileService
	Credentials    *CredentialService

	baseURL               string
	apiKey                string
	orgID                 string
	httpClient            *http.Client
	environments          codewirev1connect.EnvironmentServiceClient
	exec                  codewirev1connect.ExecServiceClient
	files                 codewirev1connect.FileServiceClient
	ports                 codewirev1connect.PortServiceClient
	apiKeys               codewirev1connect.ApiKeyServiceClient
	presets               codewirev1connect.PresetServiceClient
	secrets               codewirev1connect.SecretServiceClient
	accessProfiles        codewirev1connect.AccessProfileServiceClient
	credentials           codewirev1connect.CredentialServiceClient
	credentialMutations   codewirev1connect.CredentialMutationServiceClient
	githubRepositories    codewirev1connect.GithubRepositoryServiceClient
	credentialEnrollments codewirev1connect.CredentialMutationServiceClient
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides DefaultBaseURL.
func WithBaseURL(u string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(u, "/")
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.httpClient = hc } }

// WithOrgID sets the organization ID for org-scoped requests.
func WithOrgID(orgID string) Option { return func(c *Client) { c.orgID = orgID } }

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient = &http.Client{Timeout: d} }
}

// New creates a Codewire SDK client. apiKey falls back to CODEWIRE_API_KEY;
// the base URL falls back to CODEWIRE_API_URL, then the production API; the
// organization ID falls back to CODEWIRE_ORG_ID.
func New(apiKey string, opts ...Option) *Client {
	if apiKey == "" {
		apiKey = os.Getenv("CODEWIRE_API_KEY")
	}
	baseURL := DefaultBaseURL
	if envBaseURL := os.Getenv("CODEWIRE_API_URL"); envBaseURL != "" {
		baseURL = strings.TrimRight(envBaseURL, "/")
	}
	c := &Client{baseURL: baseURL, apiKey: apiKey, httpClient: http.DefaultClient}
	for _, o := range opts {
		o(c)
	}
	if c.orgID == "" {
		c.orgID = os.Getenv("CODEWIRE_ORG_ID")
	}
	connectOptions := connect.WithInterceptors(bearerInterceptor{apiKey: c.apiKey})
	c.environments = codewirev1connect.NewEnvironmentServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.exec = codewirev1connect.NewExecServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.files = codewirev1connect.NewFileServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.ports = codewirev1connect.NewPortServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.apiKeys = codewirev1connect.NewApiKeyServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.presets = codewirev1connect.NewPresetServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.secrets = codewirev1connect.NewSecretServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.accessProfiles = codewirev1connect.NewAccessProfileServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.credentials = codewirev1connect.NewCredentialServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.credentialMutations = codewirev1connect.NewCredentialMutationServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.githubRepositories = codewirev1connect.NewGithubRepositoryServiceClient(c.httpClient, c.baseURL, connectOptions)
	// Enrollment owns its explicit per-call context deadline. Preserve the caller's
	// transport, redirect policy and cookie jar without mutating their HTTP client
	// or letting an ordinary short client timeout truncate device authorization.
	enrollmentHTTP := *c.httpClient
	enrollmentHTTP.Timeout = 0
	c.credentialEnrollments = codewirev1connect.NewCredentialMutationServiceClient(&enrollmentHTTP, c.baseURL, connectOptions)
	c.Environments = &EnvironmentService{c}
	c.Presets = &PresetService{c}
	c.APIKeys = &APIKeyService{c}
	c.Secrets = &SecretService{c}
	c.SecretProjects = &SecretProjectService{c}
	c.AccessProfiles = &AccessProfileService{c}
	c.Credentials = &CredentialService{c}
	return c
}

func (c *Client) resolveOrgID() (string, error) {
	if c.orgID != "" {
		return c.orgID, nil
	}
	return "", fmt.Errorf("codewire: orgID is required — use WithOrgID or set CODEWIRE_ORG_ID")
}

// Error is the typed error returned for any 4xx/5xx response.
type Error struct {
	StatusCode int
	Detail     string
	RequestID  string
	violations []FieldViolation
}

func (e *Error) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("codewire: %d %s (request_id: %s)", e.StatusCode, e.Detail, e.RequestID)
	}
	return fmt.Sprintf("codewire: %d %s", e.StatusCode, e.Detail)
}

// FieldViolation identifies an invalid request field returned by the API.
type FieldViolation struct {
	Field   string
	Message string
}

// Violations returns the structured field-validation failures, if any.
func (e *Error) Violations() []FieldViolation {
	return append([]FieldViolation(nil), e.violations...)
}

type bearerInterceptor struct{ apiKey string }

func (i bearerInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		i.setAuthorization(req.Header())
		return next(ctx, req)
	}
}

func (i bearerInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		i.setAuthorization(conn.RequestHeader())
		return conn
	}
}

func (bearerInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

func (i bearerInterceptor) setAuthorization(header http.Header) {
	if i.apiKey != "" {
		header.Set("Authorization", "Bearer "+i.apiKey)
	}
}
