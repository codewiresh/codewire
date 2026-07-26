package codewire

import (
	"context"
	"fmt"
	"io"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const defaultEnvironmentPollInterval = 2 * time.Second

// EnvironmentService is the entry point for environment CRUD and lifecycle
// operations.
type EnvironmentService struct {
	client *Client
}

// CreateOptions configures optional behavior for Create.
type CreateOptions struct {
	// Wait blocks until the environment reaches "running" state.
	Wait bool
}

// Create provisions a new environment. If opts.Wait is set the call blocks
// until the environment reaches "running".
func (s *EnvironmentService) Create(ctx context.Context, body CreateEnvironmentBody, opts ...CreateOptions) (*Environment, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req, err := createEnvironmentRequest(orgID, body)
	if err != nil {
		return nil, err
	}
	response, err := s.client.environments.CreateEnvironment(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, connectSDKError(err)
	}
	data, err := fromProtoEnvironment(response.Msg.GetEnvironment())
	if err != nil {
		return nil, err
	}
	env := s.wrap(orgID, data, defaultEnvironmentPollInterval)
	if len(opts) > 0 && opts[0].Wait {
		if err := env.WaitReady(ctx); err != nil {
			return env, err
		}
	}
	return env, nil
}

// List returns environments for the configured organization, optionally
// filtered by state/type.
func (s *EnvironmentService) List(ctx context.Context, params *ListEnvironmentsParams) ([]*Environment, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req := &codewirev1.ListEnvironmentsRequest{OrgId: orgID}
	if params != nil {
		req.Type = valueOrEmpty(params.Type)
		req.State = toProtoEnvironmentState(params.State)
		if params.IncludeDestroyed != nil {
			req.IncludeDestroyed = *params.IncludeDestroyed
		}
	}
	var environments []*Environment
	for {
		response, err := s.client.environments.ListEnvironments(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, connectSDKError(err)
		}
		pollInterval := environmentPollInterval(response.Msg.GetPollInterval())
		for _, environment := range response.Msg.GetEnvironments() {
			data, err := fromProtoEnvironment(environment)
			if err != nil {
				return nil, err
			}
			environments = append(environments, s.wrap(orgID, data, pollInterval))
		}
		req.PageToken = response.Msg.GetNextPageToken()
		if req.PageToken == "" {
			return environments, nil
		}
	}
}

// Get retrieves an environment by ID.
func (s *EnvironmentService) Get(ctx context.Context, envID string) (*Environment, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.environments.GetEnvironment(ctx, connect.NewRequest(&codewirev1.GetEnvironmentRequest{
		OrgId: orgID, EnvironmentId: envID,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	data, err := fromProtoEnvironment(response.Msg.GetEnvironment())
	if err != nil {
		return nil, err
	}
	return s.wrap(orgID, data, environmentPollInterval(response.Msg.GetPollInterval())), nil
}

// Delete destroys an environment by ID.
func (s *EnvironmentService) Delete(ctx context.Context, envID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.environments.DeleteEnvironment(ctx, connect.NewRequest(&codewirev1.DeleteEnvironmentRequest{
		OrgId: orgID, EnvironmentId: envID,
	}))
	return connectSDKError(err)
}

// Stop stops a running environment.
func (s *EnvironmentService) Stop(ctx context.Context, envID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.environments.StopEnvironment(ctx, connect.NewRequest(&codewirev1.StopEnvironmentRequest{
		OrgId: orgID, EnvironmentId: envID,
	}))
	return connectSDKError(err)
}

// Start starts a stopped environment.
func (s *EnvironmentService) Start(ctx context.Context, envID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.environments.StartEnvironment(ctx, connect.NewRequest(&codewirev1.StartEnvironmentRequest{
		OrgId: orgID, EnvironmentId: envID,
	}))
	return connectSDKError(err)
}

// Exec runs a command in the environment and returns the result.
func (s *EnvironmentService) Exec(ctx context.Context, envID string, body ExecBody) (*ExecResult, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req, err := execEnvironmentRequest(orgID, envID, body)
	if err != nil {
		return nil, err
	}
	response, err := s.client.exec.Exec(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, connectSDKError(err)
	}
	result := fromProtoExecResult(response.Msg)
	return &result, nil
}

// ListFiles delegates to a [Files] handle.
func (s *EnvironmentService) ListFiles(ctx context.Context, envID string, dirPath *string) ([]FileEntry, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	return newFiles(s.client, orgID, envID).List(ctx, dirPath)
}

// UploadFile delegates to a [Files] handle.
func (s *EnvironmentService) UploadFile(ctx context.Context, envID string, src io.Reader, remotePath string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	return newFiles(s.client, orgID, envID).Upload(ctx, src, remotePath)
}

// DownloadFile delegates to a [Files] handle.
func (s *EnvironmentService) DownloadFile(ctx context.Context, envID string, remotePath string) (io.ReadCloser, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	return newFiles(s.client, orgID, envID).Download(ctx, remotePath)
}

// ListPorts returns all forwarded ports for the environment.
func (s *EnvironmentService) ListPorts(ctx context.Context, envID string) ([]EnvironmentPort, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req := &codewirev1.ListPortsRequest{OrgId: orgID, EnvironmentId: envID}
	var ports []EnvironmentPort
	for {
		response, err := s.client.ports.ListPorts(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, port := range response.Msg.GetPorts() {
			converted, err := fromProtoEnvironmentPort(port)
			if err != nil {
				return nil, err
			}
			ports = append(ports, converted)
		}
		req.PageToken = response.Msg.GetNextPageToken()
		if req.PageToken == "" {
			return ports, nil
		}
	}
}

// CreatePort creates a new port forward for the environment.
func (s *EnvironmentService) CreatePort(ctx context.Context, envID string, body CreatePortBody) (*EnvironmentPort, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	port, err := int32FromInt64("port", &body.Port)
	if err != nil {
		return nil, err
	}
	response, err := s.client.ports.CreatePort(ctx, connect.NewRequest(&codewirev1.CreatePortRequest{
		OrgId: orgID, EnvironmentId: envID, Port: valueOrZero(port), Label: body.Label, Access: toProtoPortAccess(body.Access),
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	converted, err := fromProtoEnvironmentPort(response.Msg.GetPort())
	if err != nil {
		return nil, err
	}
	return &converted, nil
}

// DeletePort removes a port forward from the environment.
func (s *EnvironmentService) DeletePort(ctx context.Context, envID, portID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.ports.DeletePort(ctx, connect.NewRequest(&codewirev1.DeletePortRequest{
		OrgId: orgID, EnvironmentId: envID, PortId: portID,
	}))
	return connectSDKError(err)
}

func (s *EnvironmentService) wrap(orgID string, data EnvironmentData, pollInterval time.Duration) *Environment {
	return &Environment{
		EnvironmentData: data,
		Files:           newFiles(s.client, orgID, data.Id),
		client:          s.client,
		orgID:           orgID,
		pollInterval:    pollInterval,
	}
}

func execEnvironmentRequest(orgID, envID string, body ExecBody) (*codewirev1.ExecRequest, error) {
	req := &codewirev1.ExecRequest{
		OrgId: orgID, EnvironmentId: envID, WorkingDir: valueOrEmpty(body.WorkingDir),
		Env: copyStringMapPointer(body.Env),
	}
	if body.Command != nil {
		req.Command = append([]string(nil), (*body.Command)...)
	}
	if body.Timeout != nil {
		timeout := &durationpb.Duration{Seconds: *body.Timeout}
		if err := timeout.CheckValid(); err != nil {
			return nil, fmt.Errorf("codewire: timeout is outside the API duration range: %w", err)
		}
		req.Timeout = timeout
	}
	return req, nil
}

func environmentPollInterval(interval *durationpb.Duration) time.Duration {
	if interval == nil || interval.CheckValid() != nil {
		return defaultEnvironmentPollInterval
	}
	duration := interval.AsDuration()
	if duration <= 0 {
		return defaultEnvironmentPollInterval
	}
	return duration
}

func valueOrZero(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}
