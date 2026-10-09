package codewire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
)

const platformAgentRecordBytes = 5 * 1024 * 1024

var platformAgentRequestID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PlatformAgentOutcomeUnknownError preserves the UUID for Observe. It never
// authorizes replay or a new mutation UUID after a transport failure.
type PlatformAgentOutcomeUnknownError struct {
	RequestID string
	Cause     error
}

func (e *PlatformAgentOutcomeUnknownError) Error() string {
	return fmt.Sprintf("codewire: agent outcome is uncertain; observe the original request %s", e.RequestID)
}
func (e *PlatformAgentOutcomeUnknownError) Unwrap() error { return e.Cause }

// PlatformAgents uses the caller's original Pod identity and launch generation.
// All generated uint64 fields retain their exact values.
type PlatformAgents struct {
	client       codewirev1connect.EnvironmentAgentServiceClient
	orgID, envID string
}

func newPlatformAgents(client *Client, orgID, envID string) *PlatformAgents {
	httpClient := *client.httpClient
	httpClient.Timeout = 0
	return &PlatformAgents{client: codewirev1connect.NewEnvironmentAgentServiceClient(&httpClient, client.baseURL,
		connect.WithInterceptors(bearerInterceptor{apiKey: client.apiKey}),
		connect.WithReadMaxBytes(platformAgentRecordBytes+32*1024), connect.WithSendMaxBytes(256*1024)), orgID: orgID, envID: envID}
}

func (s *EnvironmentService) Agents(envID string) (*PlatformAgents, error) {
	org, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	return newPlatformAgents(s.client, org, envID), nil
}

func (a *PlatformAgents) scope(s *codewirev1.EnvironmentAgentScope) error {
	if s == nil || s.Incarnation == nil || s.Incarnation.OrgId != a.orgID || s.Incarnation.EnvironmentId != a.envID || len(s.SupportImageSha256) != 32 || s.SupportImageSize == 0 {
		return fmt.Errorf("codewire: agent scope differs from this environment or omits support identity")
	}
	return nil
}

func (a *PlatformAgents) requestScope(org, env string, s *codewirev1.EnvironmentAgentScope) error {
	if org != a.orgID || env != a.envID {
		return fmt.Errorf("codewire: agent request scope differs from this environment")
	}
	return a.scope(s)
}

func (a *PlatformAgents) Info(ctx context.Context) (*codewirev1.GetEnvironmentAgentInfoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r, err := a.client.GetEnvironmentAgentInfo(ctx, connect.NewRequest(&codewirev1.GetEnvironmentAgentInfoRequest{OrgId: a.orgID, EnvironmentId: a.envID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if err := a.scope(r.Msg.Scope); err != nil {
		return nil, err
	}
	return r.Msg, nil
}

func (a *PlatformAgents) Mutate(ctx context.Context, request *codewirev1.MutateEnvironmentAgentRequest) (*codewirev1.EnvironmentAgentOperation, error) {
	if request == nil {
		return nil, fmt.Errorf("codewire: agent mutation is required")
	}
	if err := a.requestScope(request.OrgId, request.EnvironmentId, request.ExpectedScope); err != nil {
		return nil, err
	}
	if !platformAgentRequestID.MatchString(request.RequestId) || request.Operation == nil || proto.Size(request) > 256*1024 {
		return nil, fmt.Errorf("codewire: agent mutation is invalid or exceeds its bound")
	}
	owned := proto.Clone(request).(*codewirev1.MutateEnvironmentAgentRequest)
	ctx, cancel := context.WithTimeout(ctx, 240*time.Second)
	defer cancel()
	r, err := a.client.MutateEnvironmentAgent(ctx, connect.NewRequest(owned))
	if err != nil {
		return nil, &PlatformAgentOutcomeUnknownError{RequestID: owned.RequestId, Cause: connectSDKError(err)}
	}
	if r.Msg.Operation == nil || r.Msg.Operation.RequestId != owned.RequestId || !proto.Equal(r.Msg.Operation.Scope, owned.ExpectedScope) {
		return nil, &PlatformAgentOutcomeUnknownError{RequestID: owned.RequestId, Cause: fmt.Errorf("agent response changed its original request or scope")}
	}
	return r.Msg.Operation, nil
}

func (a *PlatformAgents) Observe(ctx context.Context, requestID string) (*codewirev1.EnvironmentAgentOperation, error) {
	if !platformAgentRequestID.MatchString(requestID) {
		return nil, fmt.Errorf("codewire: agent request_id must be a canonical UUID")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r, err := a.client.ObserveEnvironmentAgent(ctx, connect.NewRequest(&codewirev1.ObserveEnvironmentAgentRequest{OrgId: a.orgID, EnvironmentId: a.envID, RequestId: requestID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if r.Msg.Operation == nil || r.Msg.Operation.RequestId != requestID {
		return nil, fmt.Errorf("codewire: agent observation changed its original request")
	}
	if err := a.scope(r.Msg.Operation.Scope); err != nil {
		return nil, err
	}
	return r.Msg.Operation, nil
}

func (a *PlatformAgents) List(ctx context.Context, request *codewirev1.ListEnvironmentAgentsRequest) (*codewirev1.ListEnvironmentAgentsResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("codewire: agent list request is required")
	}
	if err := a.requestScope(request.OrgId, request.EnvironmentId, request.ExpectedScope); err != nil {
		return nil, err
	}
	if proto.Size(request) > 32*1024 {
		return nil, fmt.Errorf("codewire: agent list request exceeds its bound")
	}
	owned := proto.Clone(request).(*codewirev1.ListEnvironmentAgentsRequest)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r, err := a.client.ListEnvironmentAgents(ctx, connect.NewRequest(owned))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if !proto.Equal(r.Msg.Scope, owned.ExpectedScope) || len(r.Msg.Sessions) > 8 {
		return nil, fmt.Errorf("codewire: agent list changed its original scope or exceeded its page bound")
	}
	return r.Msg, nil
}

func (a *PlatformAgents) Read(ctx context.Context, request *codewirev1.ReadEnvironmentAgentRequest) (*codewirev1.ReadEnvironmentAgentResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("codewire: agent read request is required")
	}
	if err := a.requestScope(request.OrgId, request.EnvironmentId, request.ExpectedScope); err != nil {
		return nil, err
	}
	if proto.Size(request) > 32*1024 {
		return nil, fmt.Errorf("codewire: agent read request exceeds its bound")
	}
	owned := proto.Clone(request).(*codewirev1.ReadEnvironmentAgentRequest)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r, err := a.client.ReadEnvironmentAgent(ctx, connect.NewRequest(owned))
	if err != nil {
		return nil, connectSDKError(err)
	}
	m := r.Msg
	digest := sha256.Sum256(m.RecordJson)
	if !proto.Equal(m.Scope, owned.ExpectedScope) || m.SessionId != owned.SessionId || m.DriverId != owned.DriverId || m.LaunchGeneration != owned.ExpectedLaunchGeneration || m.Kind != owned.Kind || m.MessageId != owned.MessageId || len(m.RecordJson) > platformAgentRecordBytes || !bytes.Equal(m.RecordSha256, digest[:]) {
		return nil, fmt.Errorf("codewire: agent record changed its original scope, generation or digest")
	}
	return m, nil
}
