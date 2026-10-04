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

// Resize starts an idempotent platform resize for an environment.
func (s *EnvironmentService) Resize(ctx context.Context, envID string, body ResizeEnvironmentRequest) (*EnvironmentResizeOperation, error) {
	if err := ensureResizeRequestConverterCoverage(); err != nil {
		return nil, err
	}
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	resources, err := toProtoEnvironmentResources(body.EnvironmentResources)
	if err != nil {
		return nil, err
	}
	disruptionPolicy := codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY
	if body.AllowRestart {
		disruptionPolicy = codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART
	}
	response, err := s.client.environments.ResizeEnvironment(ctx, connect.NewRequest(&codewirev1.ResizeEnvironmentRequest{
		OrgId:            orgID,
		EnvironmentId:    envID,
		CpuMillicores:    resources.GetCpuMillicores(),
		MemoryMb:         resources.GetMemoryMb(),
		DiskGb:           resources.GetDiskGb(),
		RequestId:        body.RequestId,
		Force:            body.Force,
		DisruptionPolicy: disruptionPolicy,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if response.Msg.GetOperation() == nil {
		return nil, fmt.Errorf("codewire: resize response omitted operation")
	}
	operation, err := fromProtoEnvironmentResizeOperation(response.Msg.GetOperation())
	if err != nil {
		return nil, err
	}
	return &operation, nil
}

// PlanResize asks whether a desired allocation is live, deferred, or disruptive.
func (s *EnvironmentService) PlanResize(ctx context.Context, envID string, desired EnvironmentResources) (*EnvironmentResizePlan, error) {
	if err := ensureResizeRequestConverterCoverage(); err != nil {
		return nil, err
	}
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	resources, err := toProtoEnvironmentResources(desired)
	if err != nil {
		return nil, err
	}
	response, err := s.client.environments.PlanEnvironmentResize(ctx, connect.NewRequest(&codewirev1.PlanEnvironmentResizeRequest{
		OrgId:         orgID,
		EnvironmentId: envID,
		CpuMillicores: resources.GetCpuMillicores(),
		MemoryMb:      resources.GetMemoryMb(),
		DiskGb:        resources.GetDiskGb(),
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if response.Msg.GetPlan() == nil {
		return nil, fmt.Errorf("codewire: resize plan response omitted plan")
	}
	plan, err := fromProtoEnvironmentResizePlan(response.Msg.GetPlan())
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

// GetResizeOperation reads a durable platform resize operation.
func (s *EnvironmentService) GetResizeOperation(ctx context.Context, envID, operationID string) (*EnvironmentResizeOperation, error) {
	if err := ensureResizeRequestConverterCoverage(); err != nil {
		return nil, err
	}
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.environments.GetEnvironmentResizeOperation(ctx, connect.NewRequest(&codewirev1.GetEnvironmentResizeOperationRequest{
		OrgId:         orgID,
		EnvironmentId: envID,
		OperationId:   operationID,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if response.Msg.GetOperation() == nil {
		return nil, fmt.Errorf("codewire: resize response omitted operation")
	}
	operation, err := fromProtoEnvironmentResizeOperation(response.Msg.GetOperation())
	if err != nil {
		return nil, err
	}
	return &operation, nil
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

// UpdateEnvironmentSources replaces only application-secret sources and the
// provider-profile selection. The caller supplies the exact current selection
// and operation generation; running environments restart only when explicitly
// allowed, and personal source confirmations are never inferred.
func (s *EnvironmentService) UpdateEnvironmentSources(ctx context.Context, envID string, body UpdateEnvironmentSourcesRequest) (*EnvironmentSourcesUpdate, error) {
	if err := ensureEnvironmentConverterCoverage(); err != nil {
		return nil, err
	}
	if body.ExpectedOperationGeneration == 0 {
		return nil, fmt.Errorf("codewire: expected operation generation must be a positive uint64")
	}
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	expected, err := toProtoEnvironmentSourceSelection(body.Expected)
	if err != nil {
		return nil, err
	}
	replacement, err := toProtoEnvironmentSourceSelection(body.Replacement)
	if err != nil {
		return nil, err
	}
	response, err := s.client.environments.UpdateEnvironmentSources(ctx, connect.NewRequest(&codewirev1.UpdateEnvironmentSourcesRequest{
		OrgId: orgID, EnvironmentId: envID, ExpectedOperationGeneration: body.ExpectedOperationGeneration,
		Expected: expected, Replacement: replacement, AllowRestart: body.AllowRestart,
		ConfirmPersonalCredentials: body.ConfirmPersonalCredentials, ConfirmPersonalSecrets: body.ConfirmPersonalSecrets,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if response.Msg.GetSelection() == nil {
		return nil, fmt.Errorf("codewire: environment sources response omitted selection")
	}
	if response.Msg.GetEnvironmentId() != envID {
		return nil, fmt.Errorf("codewire: environment sources response changed environment identity")
	}
	if response.Msg.GetOperationGeneration() == 0 {
		return nil, fmt.Errorf("codewire: environment sources response omitted operation generation")
	}
	selection, err := fromProtoEnvironmentSourceSelection(response.Msg.GetSelection())
	if err != nil {
		return nil, err
	}
	outcome, err := environmentSourcesUpdateOutcome(response.Msg.GetOutcome())
	if err != nil {
		return nil, err
	}
	return &EnvironmentSourcesUpdate{
		EnvironmentID: response.Msg.GetEnvironmentId(), OperationGeneration: response.Msg.GetOperationGeneration(),
		Selection: *selection, Outcome: outcome,
	}, nil
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
		Runtime:         newCwRuntime(s.client, orgID, data.Id),
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
