// Package codewire is the Go SDK for the Codewire API. It layers ergonomic
// service handles and a fluent Environment object over generated transport
// clients.
package codewire

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
)

// DefaultBaseURL is the production API base. Generated clients append their
// exact Connect RPC procedure paths.
const DefaultBaseURL = "https://codewire.sh"

// Client is the SDK entry point.
type Client struct {
	Environments    *EnvironmentService
	Presets         *PresetService
	APIKeys         *APIKeyService
	Secrets         *SecretService
	SecretProjects  *SecretProjectService
	AccessProfiles  *AccessProfileService
	NetworkPolicies *NetworkPolicyService
	SandboxIdentity *SandboxIdentityService
	Credentials     *CredentialService

	baseURL    string
	orgID      string
	httpClient *http.Client
	// auth holds the bearer behind a pointer, so printing a Client never
	// shows it.
	auth bearerInterceptor
	// pending collects the options while New runs; nil afterwards.
	pending *codeSettings
	// settingsErr is returned by every call, before any request, when New
	// found no usable credential.
	settingsErr           error
	environments          codewirev1connect.EnvironmentServiceClient
	exec                  codewirev1connect.ExecServiceClient
	files                 codewirev1connect.FileServiceClient
	ports                 codewirev1connect.PortServiceClient
	apiKeys               codewirev1connect.ApiKeyServiceClient
	presets               codewirev1connect.PresetServiceClient
	secrets               codewirev1connect.SecretServiceClient
	accessProfiles        codewirev1connect.AccessProfileServiceClient
	networkPolicies       codewirev1connect.NetworkPolicyServiceClient
	sandboxIdentity       codewirev1connect.SandboxIdentityServiceClient
	credentials           codewirev1connect.CredentialServiceClient
	credentialMutations   codewirev1connect.CredentialMutationServiceClient
	githubRepositories    codewirev1connect.GithubRepositoryServiceClient
	credentialEnrollments codewirev1connect.CredentialMutationServiceClient
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key. A key or token set in code replaces any in the
// environment; given both, the key is used.
func WithAPIKey(key string) Option { return func(c *Client) { c.pending.apiKey = key } }

// WithJWTToken sets the user token. A key or token set in code replaces any
// in the environment. A user token needs an organization.
func WithJWTToken(token string) Option { return func(c *Client) { c.pending.jwtToken = token } }

// WithOrganizationID sets the organization for organization-scoped requests,
// instead of CODEWIRE_ORGANIZATION_ID or CODEWIRE_ORG_ID.
func WithOrganizationID(id string) Option {
	return func(c *Client) { c.pending.organizationID = id }
}

// WithAPIURL sets the server, instead of CODEWIRE_API_URL or
// CODEWIRE_SERVER_URL; the default is DefaultBaseURL.
func WithAPIURL(u string) Option { return func(c *Client) { c.pending.apiURL = u } }

// WithBaseURL sets the server.
//
// Deprecated: use WithAPIURL.
func WithBaseURL(u string) Option { return WithAPIURL(u) }

// WithOrgID sets the organization.
//
// Deprecated: use WithOrganizationID.
func WithOrgID(orgID string) Option { return WithOrganizationID(orgID) }

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.httpClient = hc } }

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient = &http.Client{Timeout: d} }
}

// New creates a Codewire SDK client. Its settings come from New's arguments,
// then the environment, then the default, as follows:
//   - the API key: apiKey or WithAPIKey, then CODEWIRE_API_KEY;
//   - the user token: WithJWTToken, then CODEWIRE_JWT_TOKEN;
//   - the organization: WithOrganizationID, then CODEWIRE_ORGANIZATION_ID,
//     then CODEWIRE_ORG_ID;
//   - the server: WithAPIURL, then CODEWIRE_API_URL, then
//     CODEWIRE_SERVER_URL, then DefaultBaseURL.
//
// The key or user token comes as a unit from code when code sets either,
// otherwise from the environment; within that source the key wins. A key or
// token in the environment under one in code is ignored and reported once
// through the standard log package. The organization comes from code, then
// from the environment; when the credential is in code and code sets no
// organization, the environment's is used and that is logged once too. With no credential, every call returns ErrNoCredentials;
// with a user token and no organization, ErrUserTokenWithoutOrganization.
// Either comes before any request is sent.
func New(apiKey string, opts ...Option) *Client {
	c := &Client{httpClient: http.DefaultClient, pending: &codeSettings{apiKey: apiKey}}
	for _, o := range opts {
		o(c)
	}
	resolved, err := resolveSettings(*c.pending, os.Getenv)
	reportOnce(resolved.warnings)
	c.pending = nil
	c.baseURL = resolved.apiURL
	c.orgID = resolved.organizationID
	c.auth = bearerInterceptor{bearer: &resolved.bearer}
	if err != nil {
		c.settingsErr = err
		c.httpClient = &http.Client{Transport: refusingTransport{err: err}}
	}
	connectOptions := connect.WithInterceptors(c.auth)
	c.environments = codewirev1connect.NewEnvironmentServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.exec = codewirev1connect.NewExecServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.files = codewirev1connect.NewFileServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.ports = codewirev1connect.NewPortServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.apiKeys = codewirev1connect.NewApiKeyServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.presets = codewirev1connect.NewPresetServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.secrets = codewirev1connect.NewSecretServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.accessProfiles = codewirev1connect.NewAccessProfileServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.networkPolicies = codewirev1connect.NewNetworkPolicyServiceClient(c.httpClient, c.baseURL, connectOptions)
	c.sandboxIdentity = codewirev1connect.NewSandboxIdentityServiceClient(c.httpClient, c.baseURL, connectOptions)
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
	c.NetworkPolicies = &NetworkPolicyService{c}
	c.SandboxIdentity = &SandboxIdentityService{c}
	c.Credentials = &CredentialService{c}
	return c
}

func (c *Client) resolveOrgID() (string, error) {
	if c.settingsErr != nil {
		return "", c.settingsErr
	}
	if c.orgID != "" {
		return c.orgID, nil
	}
	return "", fmt.Errorf("codewire: organization ID is required — use WithOrganizationID or set CODEWIRE_ORGANIZATION_ID")
}

// Error is the typed error returned for any 4xx/5xx response.
type Error struct {
	StatusCode int
	Detail     string
	RequestID  string
	// Reason is the google.rpc.ErrorInfo reason the server named, such as
	// FILE_NOT_FOUND; empty when it named none.
	Reason     string
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

// bearerInterceptor sends the API key or user token. The pointer keeps the
// value out of anything that prints a Client.
type bearerInterceptor struct{ bearer *string }

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
	if i.bearer != nil && *i.bearer != "" {
		header.Set("Authorization", "Bearer "+*i.bearer)
	}
}
