package codewire_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	codewire "codewire.sh/sdk-go"
)

type environmentServiceHandler struct {
	codewirev1connect.UnimplementedEnvironmentServiceHandler
	list       func(context.Context, *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error)
	create     func(context.Context, *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error)
	get        func(context.Context, *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error)
	planResize func(context.Context, *connect.Request[codewirev1.PlanEnvironmentResizeRequest]) (*connect.Response[codewirev1.PlanEnvironmentResizeResponse], error)
	resize     func(context.Context, *connect.Request[codewirev1.ResizeEnvironmentRequest]) (*connect.Response[codewirev1.ResizeEnvironmentResponse], error)
	getResize  func(context.Context, *connect.Request[codewirev1.GetEnvironmentResizeOperationRequest]) (*connect.Response[codewirev1.GetEnvironmentResizeOperationResponse], error)
	delete     func(context.Context, *connect.Request[codewirev1.DeleteEnvironmentRequest]) (*connect.Response[codewirev1.DeleteEnvironmentResponse], error)
	stop       func(context.Context, *connect.Request[codewirev1.StopEnvironmentRequest]) (*connect.Response[codewirev1.StopEnvironmentResponse], error)
	start      func(context.Context, *connect.Request[codewirev1.StartEnvironmentRequest]) (*connect.Response[codewirev1.StartEnvironmentResponse], error)
}

func (h environmentServiceHandler) ListEnvironments(ctx context.Context, req *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
	if h.list != nil {
		return h.list(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.ListEnvironments(ctx, req)
}
func (h environmentServiceHandler) CreateEnvironment(ctx context.Context, req *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error) {
	if h.create != nil {
		return h.create(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.CreateEnvironment(ctx, req)
}
func (h environmentServiceHandler) GetEnvironment(ctx context.Context, req *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
	if h.get != nil {
		return h.get(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.GetEnvironment(ctx, req)
}
func (h environmentServiceHandler) PlanEnvironmentResize(ctx context.Context, req *connect.Request[codewirev1.PlanEnvironmentResizeRequest]) (*connect.Response[codewirev1.PlanEnvironmentResizeResponse], error) {
	if h.planResize != nil {
		return h.planResize(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.PlanEnvironmentResize(ctx, req)
}
func (h environmentServiceHandler) ResizeEnvironment(ctx context.Context, req *connect.Request[codewirev1.ResizeEnvironmentRequest]) (*connect.Response[codewirev1.ResizeEnvironmentResponse], error) {
	if h.resize != nil {
		return h.resize(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.ResizeEnvironment(ctx, req)
}
func (h environmentServiceHandler) GetEnvironmentResizeOperation(ctx context.Context, req *connect.Request[codewirev1.GetEnvironmentResizeOperationRequest]) (*connect.Response[codewirev1.GetEnvironmentResizeOperationResponse], error) {
	if h.getResize != nil {
		return h.getResize(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.GetEnvironmentResizeOperation(ctx, req)
}
func (h environmentServiceHandler) DeleteEnvironment(ctx context.Context, req *connect.Request[codewirev1.DeleteEnvironmentRequest]) (*connect.Response[codewirev1.DeleteEnvironmentResponse], error) {
	if h.delete != nil {
		return h.delete(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.DeleteEnvironment(ctx, req)
}
func (h environmentServiceHandler) StopEnvironment(ctx context.Context, req *connect.Request[codewirev1.StopEnvironmentRequest]) (*connect.Response[codewirev1.StopEnvironmentResponse], error) {
	if h.stop != nil {
		return h.stop(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.StopEnvironment(ctx, req)
}
func (h environmentServiceHandler) StartEnvironment(ctx context.Context, req *connect.Request[codewirev1.StartEnvironmentRequest]) (*connect.Response[codewirev1.StartEnvironmentResponse], error) {
	if h.start != nil {
		return h.start(ctx, req)
	}
	return h.UnimplementedEnvironmentServiceHandler.StartEnvironment(ctx, req)
}

type execServiceHandler struct {
	codewirev1connect.UnimplementedExecServiceHandler
	exec func(context.Context, *connect.Request[codewirev1.ExecRequest]) (*connect.Response[codewirev1.ExecResponse], error)
}

func (h execServiceHandler) Exec(ctx context.Context, req *connect.Request[codewirev1.ExecRequest]) (*connect.Response[codewirev1.ExecResponse], error) {
	if h.exec != nil {
		return h.exec(ctx, req)
	}
	return h.UnimplementedExecServiceHandler.Exec(ctx, req)
}

type fileServiceHandler struct {
	codewirev1connect.UnimplementedFileServiceHandler
	list     func(context.Context, *connect.Request[codewirev1.ListFilesRequest]) (*connect.Response[codewirev1.ListFilesResponse], error)
	download func(context.Context, *connect.Request[codewirev1.DownloadFileRequest], *connect.ServerStream[codewirev1.DownloadFileResponse]) error
	upload   func(context.Context, *connect.ClientStream[codewirev1.UploadFileRequest]) (*connect.Response[codewirev1.UploadFileResponse], error)
}

func (h fileServiceHandler) ListFiles(ctx context.Context, req *connect.Request[codewirev1.ListFilesRequest]) (*connect.Response[codewirev1.ListFilesResponse], error) {
	if h.list != nil {
		return h.list(ctx, req)
	}
	return h.UnimplementedFileServiceHandler.ListFiles(ctx, req)
}
func (h fileServiceHandler) DownloadFile(ctx context.Context, req *connect.Request[codewirev1.DownloadFileRequest], stream *connect.ServerStream[codewirev1.DownloadFileResponse]) error {
	if h.download != nil {
		return h.download(ctx, req, stream)
	}
	return h.UnimplementedFileServiceHandler.DownloadFile(ctx, req, stream)
}
func (h fileServiceHandler) UploadFile(ctx context.Context, stream *connect.ClientStream[codewirev1.UploadFileRequest]) (*connect.Response[codewirev1.UploadFileResponse], error) {
	if h.upload != nil {
		return h.upload(ctx, stream)
	}
	return h.UnimplementedFileServiceHandler.UploadFile(ctx, stream)
}

type portServiceHandler struct {
	codewirev1connect.UnimplementedPortServiceHandler
	list   func(context.Context, *connect.Request[codewirev1.ListPortsRequest]) (*connect.Response[codewirev1.ListPortsResponse], error)
	create func(context.Context, *connect.Request[codewirev1.CreatePortRequest]) (*connect.Response[codewirev1.CreatePortResponse], error)
	delete func(context.Context, *connect.Request[codewirev1.DeletePortRequest]) (*connect.Response[codewirev1.DeletePortResponse], error)
}

func (h portServiceHandler) ListPorts(ctx context.Context, req *connect.Request[codewirev1.ListPortsRequest]) (*connect.Response[codewirev1.ListPortsResponse], error) {
	if h.list != nil {
		return h.list(ctx, req)
	}
	return h.UnimplementedPortServiceHandler.ListPorts(ctx, req)
}
func (h portServiceHandler) CreatePort(ctx context.Context, req *connect.Request[codewirev1.CreatePortRequest]) (*connect.Response[codewirev1.CreatePortResponse], error) {
	if h.create != nil {
		return h.create(ctx, req)
	}
	return h.UnimplementedPortServiceHandler.CreatePort(ctx, req)
}
func (h portServiceHandler) DeletePort(ctx context.Context, req *connect.Request[codewirev1.DeletePortRequest]) (*connect.Response[codewirev1.DeletePortResponse], error) {
	if h.delete != nil {
		return h.delete(ctx, req)
	}
	return h.UnimplementedPortServiceHandler.DeletePort(ctx, req)
}

func testRuntimeServer(t *testing.T, environments environmentServiceHandler, exec execServiceHandler, files fileServiceHandler, ports portServiceHandler) (*codewire.Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	environmentPath, environmentHandler := codewirev1connect.NewEnvironmentServiceHandler(environments)
	execPath, execHandler := codewirev1connect.NewExecServiceHandler(exec)
	filePath, fileHandler := codewirev1connect.NewFileServiceHandler(files)
	portPath, portHandler := codewirev1connect.NewPortServiceHandler(ports)
	mux.Handle(environmentPath, environmentHandler)
	mux.Handle(execPath, execHandler)
	mux.Handle(filePath, fileHandler)
	mux.Handle(portPath, portHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return codewire.New("test-key", codewire.WithBaseURL(srv.URL), codewire.WithOrgID("org_test")), srv
}

type apiKeyServiceHandler struct {
	codewirev1connect.UnimplementedApiKeyServiceHandler

	list   func(context.Context, *connect.Request[codewirev1.ListApiKeysRequest]) (*connect.Response[codewirev1.ListApiKeysResponse], error)
	create func(context.Context, *connect.Request[codewirev1.CreateApiKeyRequest]) (*connect.Response[codewirev1.CreateApiKeyResponse], error)
	update func(context.Context, *connect.Request[codewirev1.UpdateApiKeyRequest]) (*connect.Response[codewirev1.UpdateApiKeyResponse], error)
	delete func(context.Context, *connect.Request[codewirev1.DeleteApiKeyRequest]) (*connect.Response[codewirev1.DeleteApiKeyResponse], error)
}

func (h apiKeyServiceHandler) ListApiKeys(ctx context.Context, req *connect.Request[codewirev1.ListApiKeysRequest]) (*connect.Response[codewirev1.ListApiKeysResponse], error) {
	if h.list != nil {
		return h.list(ctx, req)
	}
	return h.UnimplementedApiKeyServiceHandler.ListApiKeys(ctx, req)
}

func (h apiKeyServiceHandler) CreateApiKey(ctx context.Context, req *connect.Request[codewirev1.CreateApiKeyRequest]) (*connect.Response[codewirev1.CreateApiKeyResponse], error) {
	if h.create != nil {
		return h.create(ctx, req)
	}
	return h.UnimplementedApiKeyServiceHandler.CreateApiKey(ctx, req)
}

func (h apiKeyServiceHandler) UpdateApiKey(ctx context.Context, req *connect.Request[codewirev1.UpdateApiKeyRequest]) (*connect.Response[codewirev1.UpdateApiKeyResponse], error) {
	if h.update != nil {
		return h.update(ctx, req)
	}
	return h.UnimplementedApiKeyServiceHandler.UpdateApiKey(ctx, req)
}

func (h apiKeyServiceHandler) DeleteApiKey(ctx context.Context, req *connect.Request[codewirev1.DeleteApiKeyRequest]) (*connect.Response[codewirev1.DeleteApiKeyResponse], error) {
	if h.delete != nil {
		return h.delete(ctx, req)
	}
	return h.UnimplementedApiKeyServiceHandler.DeleteApiKey(ctx, req)
}

func testAPIKeyServer(t *testing.T, handler apiKeyServiceHandler) (*codewire.Client, *httptest.Server) {
	t.Helper()
	_, connectHandler := codewirev1connect.NewApiKeyServiceHandler(handler)
	srv := httptest.NewServer(connectHandler)
	t.Cleanup(srv.Close)
	client := codewire.New("test-key",
		codewire.WithBaseURL(srv.URL),
		codewire.WithOrgID("org_test"),
	)
	return client, srv
}

type presetServiceHandler struct {
	codewirev1connect.UnimplementedPresetServiceHandler
	list   func(context.Context, *connect.Request[codewirev1.ListPresetsRequest]) (*connect.Response[codewirev1.ListPresetsResponse], error)
	create func(context.Context, *connect.Request[codewirev1.CreatePresetRequest]) (*connect.Response[codewirev1.CreatePresetResponse], error)
	get    func(context.Context, *connect.Request[codewirev1.GetPresetRequest]) (*connect.Response[codewirev1.GetPresetResponse], error)
	update func(context.Context, *connect.Request[codewirev1.UpdatePresetRequest]) (*connect.Response[codewirev1.UpdatePresetResponse], error)
	delete func(context.Context, *connect.Request[codewirev1.DeletePresetRequest]) (*connect.Response[codewirev1.DeletePresetResponse], error)
}

func (h presetServiceHandler) ListPresets(ctx context.Context, req *connect.Request[codewirev1.ListPresetsRequest]) (*connect.Response[codewirev1.ListPresetsResponse], error) {
	if h.list != nil {
		return h.list(ctx, req)
	}
	return h.UnimplementedPresetServiceHandler.ListPresets(ctx, req)
}
func (h presetServiceHandler) CreatePreset(ctx context.Context, req *connect.Request[codewirev1.CreatePresetRequest]) (*connect.Response[codewirev1.CreatePresetResponse], error) {
	if h.create != nil {
		return h.create(ctx, req)
	}
	return h.UnimplementedPresetServiceHandler.CreatePreset(ctx, req)
}
func (h presetServiceHandler) GetPreset(ctx context.Context, req *connect.Request[codewirev1.GetPresetRequest]) (*connect.Response[codewirev1.GetPresetResponse], error) {
	if h.get != nil {
		return h.get(ctx, req)
	}
	return h.UnimplementedPresetServiceHandler.GetPreset(ctx, req)
}
func (h presetServiceHandler) UpdatePreset(ctx context.Context, req *connect.Request[codewirev1.UpdatePresetRequest]) (*connect.Response[codewirev1.UpdatePresetResponse], error) {
	if h.update != nil {
		return h.update(ctx, req)
	}
	return h.UnimplementedPresetServiceHandler.UpdatePreset(ctx, req)
}
func (h presetServiceHandler) DeletePreset(ctx context.Context, req *connect.Request[codewirev1.DeletePresetRequest]) (*connect.Response[codewirev1.DeletePresetResponse], error) {
	if h.delete != nil {
		return h.delete(ctx, req)
	}
	return h.UnimplementedPresetServiceHandler.DeletePreset(ctx, req)
}

func testPresetServer(t *testing.T, handler presetServiceHandler) (*codewire.Client, *httptest.Server) {
	t.Helper()
	_, connectHandler := codewirev1connect.NewPresetServiceHandler(handler)
	srv := httptest.NewServer(connectHandler)
	t.Cleanup(srv.Close)
	return codewire.New("test-key", codewire.WithBaseURL(srv.URL), codewire.WithOrgID("org_test")), srv
}

type secretServiceHandler struct {
	codewirev1connect.UnimplementedSecretServiceHandler
	listSecrets         func(context.Context, *connect.Request[codewirev1.ListSecretsRequest]) (*connect.Response[codewirev1.ListSecretsResponse], error)
	setSecret           func(context.Context, *connect.Request[codewirev1.SetSecretRequest]) (*connect.Response[codewirev1.SetSecretResponse], error)
	deleteSecret        func(context.Context, *connect.Request[codewirev1.DeleteSecretRequest]) (*connect.Response[codewirev1.DeleteSecretResponse], error)
	renameSecret        func(context.Context, *connect.Request[codewirev1.RenameSecretRequest]) (*connect.Response[codewirev1.RenameSecretResponse], error)
	listUserSecrets     func(context.Context, *connect.Request[codewirev1.ListUserSecretsRequest]) (*connect.Response[codewirev1.ListUserSecretsResponse], error)
	setUserSecret       func(context.Context, *connect.Request[codewirev1.SetUserSecretRequest]) (*connect.Response[codewirev1.SetUserSecretResponse], error)
	deleteUserSecret    func(context.Context, *connect.Request[codewirev1.DeleteUserSecretRequest]) (*connect.Response[codewirev1.DeleteUserSecretResponse], error)
	renameUserSecret    func(context.Context, *connect.Request[codewirev1.RenameUserSecretRequest]) (*connect.Response[codewirev1.RenameUserSecretResponse], error)
	listProjects        func(context.Context, *connect.Request[codewirev1.ListSecretProjectsRequest]) (*connect.Response[codewirev1.ListSecretProjectsResponse], error)
	createProject       func(context.Context, *connect.Request[codewirev1.CreateSecretProjectRequest]) (*connect.Response[codewirev1.CreateSecretProjectResponse], error)
	deleteProject       func(context.Context, *connect.Request[codewirev1.DeleteSecretProjectRequest]) (*connect.Response[codewirev1.DeleteSecretProjectResponse], error)
	listProjectSecrets  func(context.Context, *connect.Request[codewirev1.ListProjectSecretsRequest]) (*connect.Response[codewirev1.ListProjectSecretsResponse], error)
	setProjectSecret    func(context.Context, *connect.Request[codewirev1.SetProjectSecretRequest]) (*connect.Response[codewirev1.SetProjectSecretResponse], error)
	deleteProjectSecret func(context.Context, *connect.Request[codewirev1.DeleteProjectSecretRequest]) (*connect.Response[codewirev1.DeleteProjectSecretResponse], error)
	renameProjectSecret func(context.Context, *connect.Request[codewirev1.RenameProjectSecretRequest]) (*connect.Response[codewirev1.RenameProjectSecretResponse], error)
	previewSecrets      func(context.Context, *connect.Request[codewirev1.PreviewWorkloadSecretResolutionRequest]) (*connect.Response[codewirev1.PreviewWorkloadSecretResolutionResponse], error)
}

func (h secretServiceHandler) ListSecrets(ctx context.Context, req *connect.Request[codewirev1.ListSecretsRequest]) (*connect.Response[codewirev1.ListSecretsResponse], error) {
	if h.listSecrets != nil {
		return h.listSecrets(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.ListSecrets(ctx, req)
}
func (h secretServiceHandler) SetSecret(ctx context.Context, req *connect.Request[codewirev1.SetSecretRequest]) (*connect.Response[codewirev1.SetSecretResponse], error) {
	if h.setSecret != nil {
		return h.setSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.SetSecret(ctx, req)
}
func (h secretServiceHandler) DeleteSecret(ctx context.Context, req *connect.Request[codewirev1.DeleteSecretRequest]) (*connect.Response[codewirev1.DeleteSecretResponse], error) {
	if h.deleteSecret != nil {
		return h.deleteSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.DeleteSecret(ctx, req)
}
func (h secretServiceHandler) RenameSecret(ctx context.Context, req *connect.Request[codewirev1.RenameSecretRequest]) (*connect.Response[codewirev1.RenameSecretResponse], error) {
	if h.renameSecret != nil {
		return h.renameSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.RenameSecret(ctx, req)
}
func (h secretServiceHandler) ListUserSecrets(ctx context.Context, req *connect.Request[codewirev1.ListUserSecretsRequest]) (*connect.Response[codewirev1.ListUserSecretsResponse], error) {
	if h.listUserSecrets != nil {
		return h.listUserSecrets(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.ListUserSecrets(ctx, req)
}
func (h secretServiceHandler) SetUserSecret(ctx context.Context, req *connect.Request[codewirev1.SetUserSecretRequest]) (*connect.Response[codewirev1.SetUserSecretResponse], error) {
	if h.setUserSecret != nil {
		return h.setUserSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.SetUserSecret(ctx, req)
}
func (h secretServiceHandler) DeleteUserSecret(ctx context.Context, req *connect.Request[codewirev1.DeleteUserSecretRequest]) (*connect.Response[codewirev1.DeleteUserSecretResponse], error) {
	if h.deleteUserSecret != nil {
		return h.deleteUserSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.DeleteUserSecret(ctx, req)
}
func (h secretServiceHandler) RenameUserSecret(ctx context.Context, req *connect.Request[codewirev1.RenameUserSecretRequest]) (*connect.Response[codewirev1.RenameUserSecretResponse], error) {
	if h.renameUserSecret != nil {
		return h.renameUserSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.RenameUserSecret(ctx, req)
}
func (h secretServiceHandler) ListSecretProjects(ctx context.Context, req *connect.Request[codewirev1.ListSecretProjectsRequest]) (*connect.Response[codewirev1.ListSecretProjectsResponse], error) {
	if h.listProjects != nil {
		return h.listProjects(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.ListSecretProjects(ctx, req)
}
func (h secretServiceHandler) CreateSecretProject(ctx context.Context, req *connect.Request[codewirev1.CreateSecretProjectRequest]) (*connect.Response[codewirev1.CreateSecretProjectResponse], error) {
	if h.createProject != nil {
		return h.createProject(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.CreateSecretProject(ctx, req)
}
func (h secretServiceHandler) DeleteSecretProject(ctx context.Context, req *connect.Request[codewirev1.DeleteSecretProjectRequest]) (*connect.Response[codewirev1.DeleteSecretProjectResponse], error) {
	if h.deleteProject != nil {
		return h.deleteProject(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.DeleteSecretProject(ctx, req)
}
func (h secretServiceHandler) ListProjectSecrets(ctx context.Context, req *connect.Request[codewirev1.ListProjectSecretsRequest]) (*connect.Response[codewirev1.ListProjectSecretsResponse], error) {
	if h.listProjectSecrets != nil {
		return h.listProjectSecrets(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.ListProjectSecrets(ctx, req)
}
func (h secretServiceHandler) SetProjectSecret(ctx context.Context, req *connect.Request[codewirev1.SetProjectSecretRequest]) (*connect.Response[codewirev1.SetProjectSecretResponse], error) {
	if h.setProjectSecret != nil {
		return h.setProjectSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.SetProjectSecret(ctx, req)
}
func (h secretServiceHandler) DeleteProjectSecret(ctx context.Context, req *connect.Request[codewirev1.DeleteProjectSecretRequest]) (*connect.Response[codewirev1.DeleteProjectSecretResponse], error) {
	if h.deleteProjectSecret != nil {
		return h.deleteProjectSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.DeleteProjectSecret(ctx, req)
}
func (h secretServiceHandler) RenameProjectSecret(ctx context.Context, req *connect.Request[codewirev1.RenameProjectSecretRequest]) (*connect.Response[codewirev1.RenameProjectSecretResponse], error) {
	if h.renameProjectSecret != nil {
		return h.renameProjectSecret(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.RenameProjectSecret(ctx, req)
}
func (h secretServiceHandler) PreviewWorkloadSecretResolution(ctx context.Context, req *connect.Request[codewirev1.PreviewWorkloadSecretResolutionRequest]) (*connect.Response[codewirev1.PreviewWorkloadSecretResolutionResponse], error) {
	if h.previewSecrets != nil {
		return h.previewSecrets(ctx, req)
	}
	return h.UnimplementedSecretServiceHandler.PreviewWorkloadSecretResolution(ctx, req)
}

func testSecretServer(t *testing.T, handler secretServiceHandler) (*codewire.Client, *httptest.Server) {
	t.Helper()
	_, connectHandler := codewirev1connect.NewSecretServiceHandler(handler)
	srv := httptest.NewServer(connectHandler)
	t.Cleanup(srv.Close)
	return codewire.New("test-key", codewire.WithBaseURL(srv.URL), codewire.WithOrgID("org_test")), srv
}

func apiKeyProto(disabled bool) *codewirev1.ApiKey {
	key := &codewirev1.ApiKey{
		Id:             "key_1",
		UserId:         "user_1",
		OrgId:          "org_test",
		Name:           "test",
		KeyPrefix:      "cw_abc",
		Scopes:         []string{"read", "write"},
		LastUsedAt:     timestamppb.New(time.Date(2026, 1, 1, 1, 2, 3, 0, time.UTC)),
		ExpiresAt:      timestamppb.New(time.Date(2027, 1, 1, 1, 2, 3, 0, time.UTC)),
		CreatedAt:      timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		CreatedByName:  "Test User",
		CreatedByEmail: "test@example.com",
	}
	if disabled {
		key.DisabledAt = timestamppb.New(time.Date(2026, 1, 2, 1, 2, 3, 0, time.UTC))
	}
	return key
}

func TestNewUsesCodewireAPIURLEnv(t *testing.T) {
	_, srv := testRuntimeServer(t, environmentServiceHandler{
		list: func(_ context.Context, req *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" {
				t.Errorf("unexpected list request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListEnvironmentsResponse{}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	t.Setenv("CODEWIRE_API_URL", srv.URL+"/api/v1")
	t.Setenv("CODEWIRE_ORG_ID", "org_test")

	client := codewire.New("test-key")
	if _, err := client.Environments.List(context.Background(), nil); err != nil {
		t.Fatalf("list environments: %v", err)
	}
}

func TestEnvironmentsCRUD(t *testing.T) {
	envJSON := codewire.EnvironmentData{
		Id: "env_123", OrgId: "org_test", State: "running",
		DesiredState: "running", Type: "sandbox", CreatedBy: "user_1",
		PresetId: strPtr("tmpl_1"), Recoverable: true, StateChangedAt: "2026-01-01T00:00:00Z",
		CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 20,
		TotalRunningSeconds: 0, CreatedAt: "2026-01-01T00:00:00Z",
	}

	client, _ := testRuntimeServer(t, environmentServiceHandler{
		create: func(_ context.Context, req *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetPresetSlug() != "python" {
				t.Errorf("unexpected create request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.CreateEnvironmentResponse{Environment: environmentProto(envJSON)}), nil
		},
		get: func(_ context.Context, req *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
			if req.Msg.GetEnvironmentId() != "env_123" {
				t.Errorf("unexpected get request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(envJSON)}), nil
		},
		list: func(_ context.Context, req *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" {
				t.Errorf("unexpected list request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListEnvironmentsResponse{Environments: []*codewirev1.Environment{environmentProto(envJSON)}}), nil
		},
		stop: func(_ context.Context, req *connect.Request[codewirev1.StopEnvironmentRequest]) (*connect.Response[codewirev1.StopEnvironmentResponse], error) {
			if req.Msg.GetEnvironmentId() != "env_123" {
				t.Errorf("unexpected stop request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.StopEnvironmentResponse{}), nil
		},
		start: func(_ context.Context, req *connect.Request[codewirev1.StartEnvironmentRequest]) (*connect.Response[codewirev1.StartEnvironmentResponse], error) {
			if req.Msg.GetEnvironmentId() != "env_123" {
				t.Errorf("unexpected start request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.StartEnvironmentResponse{}), nil
		},
		delete: func(_ context.Context, req *connect.Request[codewirev1.DeleteEnvironmentRequest]) (*connect.Response[codewirev1.DeleteEnvironmentResponse], error) {
			if req.Msg.GetEnvironmentId() != "env_123" {
				t.Errorf("unexpected delete request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeleteEnvironmentResponse{}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()

	// Create
	slug := "python"
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{
		PresetSlug: &slug,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if env.Id != "env_123" {
		t.Errorf("expected env_123, got %s", env.Id)
	}
	if env.State != "running" {
		t.Errorf("expected running, got %s", env.State)
	}

	// Get
	env2, err := client.Environments.Get(ctx, "env_123")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if env2.Id != "env_123" {
		t.Errorf("expected env_123, got %s", env2.Id)
	}

	// List
	envs, err := client.Environments.List(ctx, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(envs) != 1 {
		t.Errorf("expected 1 env, got %d", len(envs))
	}

	// Stop/Start
	if err := client.Environments.Stop(ctx, "env_123"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := client.Environments.Start(ctx, "env_123"); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Delete
	if err := client.Environments.Delete(ctx, "env_123"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestEnvironmentExec(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{}, execServiceHandler{
		exec: func(_ context.Context, req *connect.Request[codewirev1.ExecRequest]) (*connect.Response[codewirev1.ExecResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetEnvironmentId() != "env_123" || len(req.Msg.GetCommand()) == 0 {
				t.Errorf("unexpected exec request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ExecResponse{ExitCode: 0, Stdout: []byte("hello\n")}), nil
		},
	}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	cmd := []string{"echo", "hello"}
	result, err := client.Environments.Exec(ctx, "env_123", codewire.ExecBody{
		Command: &cmd,
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", result.ExitCode)
	}
	if result.Stdout != "hello\n" {
		t.Errorf("unexpected stdout: %q", result.Stdout)
	}
}

func TestEnvironmentFileUploadDownload(t *testing.T) {
	content := "file contents here"
	client, _ := testRuntimeServer(t, environmentServiceHandler{}, execServiceHandler{}, fileServiceHandler{
		upload: func(_ context.Context, stream *connect.ClientStream[codewirev1.UploadFileRequest]) (*connect.Response[codewirev1.UploadFileResponse], error) {
			var body strings.Builder
			for stream.Receive() {
				if header := stream.Msg().GetHeader(); header != nil {
					if header.GetOrgId() != "org_test" || header.GetEnvironmentId() != "env_123" || header.GetPath() != "/workspace/test.txt" {
						t.Errorf("unexpected upload header: %#v", header)
					}
					continue
				}
				body.Write(stream.Msg().GetChunk())
			}
			if err := stream.Err(); err != nil {
				return nil, err
			}
			if body.String() != content {
				t.Errorf("expected %q, got %q", content, body.String())
			}
			return connect.NewResponse(&codewirev1.UploadFileResponse{Path: "/workspace/test.txt", Size: int64(len(content))}), nil
		},
		download: func(_ context.Context, req *connect.Request[codewirev1.DownloadFileRequest], stream *connect.ServerStream[codewirev1.DownloadFileResponse]) error {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetPath() != "/workspace/test.txt" {
				t.Errorf("unexpected download request: %#v", req.Msg)
			}
			return stream.Send(&codewirev1.DownloadFileResponse{Payload: &codewirev1.DownloadFileResponse_Chunk{Chunk: []byte(content)}})
		},
	}, portServiceHandler{})

	ctx := context.Background()

	// Upload
	err := client.Environments.UploadFile(ctx, "env_123", strings.NewReader(content), "/workspace/test.txt")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	// Download
	rc, err := client.Environments.DownloadFile(ctx, "env_123", "/workspace/test.txt")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != content {
		t.Errorf("expected %q, got %q", content, string(got))
	}
}

func TestDownloadStreamsWithoutBufferingTheWholeFile(t *testing.T) {
	firstChunkSent := make(chan struct{})
	releaseSecondChunk := make(chan struct{})
	client, _ := testRuntimeServer(t, environmentServiceHandler{}, execServiceHandler{}, fileServiceHandler{
		download: func(_ context.Context, _ *connect.Request[codewirev1.DownloadFileRequest], stream *connect.ServerStream[codewirev1.DownloadFileResponse]) error {
			if err := stream.Send(&codewirev1.DownloadFileResponse{Payload: &codewirev1.DownloadFileResponse_Chunk{Chunk: []byte("first")}}); err != nil {
				return err
			}
			close(firstChunkSent)
			<-releaseSecondChunk
			return stream.Send(&codewirev1.DownloadFileResponse{Payload: &codewirev1.DownloadFileResponse_Chunk{Chunk: []byte("second")}})
		},
	}, portServiceHandler{})

	type downloadResult struct {
		reader io.ReadCloser
		err    error
	}
	result := make(chan downloadResult, 1)
	go func() {
		reader, err := client.Environments.DownloadFile(context.Background(), "env_123", "/workspace/test.txt")
		result <- downloadResult{reader: reader, err: err}
	}()

	select {
	case <-firstChunkSent:
	case <-time.After(time.Second):
		t.Fatal("server did not send the first download chunk")
	}

	var download downloadResult
	select {
	case download = <-result:
	case <-time.After(time.Second):
		t.Fatal("Download waited for the entire server stream")
	}
	if download.err != nil {
		t.Fatalf("download: %v", download.err)
	}
	defer download.reader.Close()

	first := make([]byte, len("first"))
	if _, err := io.ReadFull(download.reader, first); err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	if string(first) != "first" {
		t.Fatalf("first chunk = %q", first)
	}
	close(releaseSecondChunk)
	second, err := io.ReadAll(download.reader)
	if err != nil {
		t.Fatalf("read second chunk: %v", err)
	}
	if string(second) != "second" {
		t.Fatalf("second chunk = %q", second)
	}
}

func TestEnvironmentWrapper(t *testing.T) {
	envJSON := codewire.EnvironmentData{
		Id: "env_w", OrgId: "org_test", State: "running",
		DesiredState: "running", Type: "sandbox", CreatedBy: "user_1",
		PresetId: strPtr("tmpl_1"), Recoverable: true, StateChangedAt: "2026-01-01T00:00:00Z",
		CpuMillicores: 1000, MemoryMb: 2048, DiskGb: 10,
		TotalRunningSeconds: 0, CreatedAt: "2026-01-01T00:00:00Z",
	}

	client, _ := testRuntimeServer(t, environmentServiceHandler{
		create: func(_ context.Context, _ *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.CreateEnvironmentResponse{Environment: environmentProto(envJSON)}), nil
		},
		stop: func(_ context.Context, _ *connect.Request[codewirev1.StopEnvironmentRequest]) (*connect.Response[codewirev1.StopEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.StopEnvironmentResponse{}), nil
		},
		delete: func(_ context.Context, _ *connect.Request[codewirev1.DeleteEnvironmentRequest]) (*connect.Response[codewirev1.DeleteEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.DeleteEnvironmentResponse{}), nil
		},
	}, execServiceHandler{
		exec: func(_ context.Context, _ *connect.Request[codewirev1.ExecRequest]) (*connect.Response[codewirev1.ExecResponse], error) {
			return connect.NewResponse(&codewirev1.ExecResponse{Stdout: []byte("ok")}), nil
		},
	}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	slug := "go"
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{PresetSlug: &slug})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Use wrapper methods
	cmd := []string{"go", "version"}
	result, err := env.Exec(ctx, codewire.ExecBody{Command: &cmd})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.Stdout != "ok" {
		t.Errorf("expected ok, got %s", result.Stdout)
	}

	if err := env.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := env.Remove(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
}

func TestTemplatesCRUD(t *testing.T) {
	tmplProto := &codewirev1.Preset{
		Id: "tmpl_1", Name: "Go",
		BuildStatus: "ready", DefaultCpuMillicores: 2000,
		DefaultMemoryMb: 4096, DefaultDiskGb: 20, Official: false,
		CreatedAt: timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}

	client, _ := testPresetServer(t, presetServiceHandler{
		create: func(_ context.Context, req *connect.Request[codewirev1.CreatePresetRequest]) (*connect.Response[codewirev1.CreatePresetResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetName() != "Go" {
				t.Errorf("unexpected create request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.CreatePresetResponse{Preset: tmplProto}), nil
		},
		get: func(_ context.Context, req *connect.Request[codewirev1.GetPresetRequest]) (*connect.Response[codewirev1.GetPresetResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetPresetId() != "tmpl_1" {
				t.Errorf("unexpected get request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.GetPresetResponse{Preset: tmplProto}), nil
		},
		update: func(_ context.Context, req *connect.Request[codewirev1.UpdatePresetRequest]) (*connect.Response[codewirev1.UpdatePresetResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetPresetId() != "tmpl_1" || req.Msg.GetName() != "Golang" {
				t.Errorf("unexpected update request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.UpdatePresetResponse{Preset: tmplProto}), nil
		},
		list: func(_ context.Context, req *connect.Request[codewirev1.ListPresetsRequest]) (*connect.Response[codewirev1.ListPresetsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" {
				t.Errorf("unexpected list request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListPresetsResponse{Presets: []*codewirev1.Preset{tmplProto}}), nil
		},
		delete: func(_ context.Context, req *connect.Request[codewirev1.DeletePresetRequest]) (*connect.Response[codewirev1.DeletePresetResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetPresetId() != "tmpl_1" {
				t.Errorf("unexpected delete request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeletePresetResponse{}), nil
		},
	})

	ctx := context.Background()

	tmpl, err := client.Templates.Create(ctx, codewire.CreatePresetBody{
		Name: "Go",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tmpl.Name != "Go" {
		t.Errorf("expected Go, got %s", tmpl.Name)
	}

	_, err = client.Templates.Get(ctx, "tmpl_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	newName := "Golang"
	_, err = client.Templates.Update(ctx, "tmpl_1", codewire.UpdatePresetBody{Name: &newName})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	list, err := client.Templates.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 template, got %d", len(list))
	}

	if err := client.Templates.Delete(ctx, "tmpl_1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestAPIKeys(t *testing.T) {
	client, _ := testAPIKeyServer(t, apiKeyServiceHandler{
		create: func(_ context.Context, req *connect.Request[codewirev1.CreateApiKeyRequest]) (*connect.Response[codewirev1.CreateApiKeyResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" {
				t.Error("missing auth header")
			}
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetName() != "test" {
				t.Errorf("unexpected create request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.CreateApiKeyResponse{ApiKey: apiKeyProto(false), Key: "cw_abc123"}), nil
		},
		list: func(_ context.Context, req *connect.Request[codewirev1.ListApiKeysRequest]) (*connect.Response[codewirev1.ListApiKeysResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" {
				t.Error("missing auth header")
			}
			if req.Msg.GetOrgId() != "org_test" {
				t.Errorf("unexpected list org: %s", req.Msg.GetOrgId())
			}
			return connect.NewResponse(&codewirev1.ListApiKeysResponse{ApiKeys: []*codewirev1.ApiKey{apiKeyProto(false)}}), nil
		},
		delete: func(_ context.Context, req *connect.Request[codewirev1.DeleteApiKeyRequest]) (*connect.Response[codewirev1.DeleteApiKeyResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" {
				t.Error("missing auth header")
			}
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetKeyId() != "key_1" {
				t.Errorf("unexpected delete request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeleteApiKeyResponse{}), nil
		},
	})

	ctx := context.Background()

	resp, err := client.APIKeys.Create(ctx, codewire.CreateAPIKeyBody{Name: "test"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.Key != "cw_abc123" {
		t.Errorf("expected cw_abc123, got %s", resp.Key)
	}

	keys, err := client.APIKeys.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}

	if err := client.APIKeys.Delete(ctx, "key_1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestSecrets(t *testing.T) {
	client, _ := testSecretServer(t, secretServiceHandler{
		listSecrets: func(_ context.Context, req *connect.Request[codewirev1.ListSecretsRequest]) (*connect.Response[codewirev1.ListSecretsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" {
				t.Errorf("unexpected list request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListSecretsResponse{Secrets: []*codewirev1.SecretMetadata{{Key: "DB_URL"}}}), nil
		},
		setSecret: func(_ context.Context, req *connect.Request[codewirev1.SetSecretRequest]) (*connect.Response[codewirev1.SetSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetKey() != "DB_URL" {
				t.Errorf("unexpected set request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.SetSecretResponse{}), nil
		},
		deleteSecret: func(_ context.Context, req *connect.Request[codewirev1.DeleteSecretRequest]) (*connect.Response[codewirev1.DeleteSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetKey() != "DB_URL" {
				t.Errorf("unexpected delete request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeleteSecretResponse{}), nil
		},
		listUserSecrets: func(_ context.Context, req *connect.Request[codewirev1.ListUserSecretsRequest]) (*connect.Response[codewirev1.ListUserSecretsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" {
				t.Error("missing auth header")
			}
			return connect.NewResponse(&codewirev1.ListUserSecretsResponse{Secrets: []*codewirev1.SecretMetadata{{Key: "TOKEN"}}}), nil
		},
		setUserSecret: func(_ context.Context, req *connect.Request[codewirev1.SetUserSecretRequest]) (*connect.Response[codewirev1.SetUserSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetKey() != "TOKEN" {
				t.Errorf("unexpected set user request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.SetUserSecretResponse{}), nil
		},
		deleteUserSecret: func(_ context.Context, req *connect.Request[codewirev1.DeleteUserSecretRequest]) (*connect.Response[codewirev1.DeleteUserSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetKey() != "TOKEN" {
				t.Errorf("unexpected delete user request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeleteUserSecretResponse{}), nil
		},
		previewSecrets: func(_ context.Context, req *connect.Request[codewirev1.PreviewWorkloadSecretResolutionRequest]) (*connect.Response[codewirev1.PreviewWorkloadSecretResolutionResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || !req.Msg.GetOrganization() || !req.Msg.GetUser() || req.Msg.GetSecretProjectId() != "proj_1" || len(req.Msg.GetExplicitEnvironmentKeys()) != 1 || req.Msg.GetExplicitEnvironmentKeys()[0] != "EXPLICIT" {
				t.Errorf("unexpected preview request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.PreviewWorkloadSecretResolutionResponse{Secrets: []*codewirev1.ResolvedWorkloadSecretMetadata{{
				Key:               "TOKEN",
				Source:            codewirev1.WorkloadSecretSource_WORKLOAD_SECRET_SOURCE_USER,
				OverriddenSources: []codewirev1.WorkloadSecretSource{codewirev1.WorkloadSecretSource_WORKLOAD_SECRET_SOURCE_ORGANIZATION},
			}}}), nil
		},
	})

	ctx := context.Background()

	secrets, err := client.Secrets.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Key != "DB_URL" {
		t.Errorf("unexpected secrets: %v", secrets)
	}

	if err := client.Secrets.Set(ctx, "DB_URL", "postgres://..."); err != nil {
		t.Fatalf("set: %v", err)
	}

	if err := client.Secrets.Delete(ctx, "DB_URL"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	userSecrets, err := client.Secrets.ListUser(ctx)
	if err != nil {
		t.Fatalf("list user: %v", err)
	}
	if len(userSecrets) != 1 {
		t.Errorf("expected 1 user secret, got %d", len(userSecrets))
	}

	if err := client.Secrets.SetUser(ctx, "TOKEN", "abc"); err != nil {
		t.Fatalf("set user: %v", err)
	}

	if err := client.Secrets.DeleteUser(ctx, "TOKEN"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	preview, err := client.Secrets.Preview(ctx, codewire.WorkloadSecretPreviewInput{
		Organization:            true,
		SecretProjectID:         "proj_1",
		User:                    true,
		ExplicitEnvironmentKeys: []string{"EXPLICIT"},
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(preview) != 1 || preview[0].Key != "TOKEN" || preview[0].Source != codewire.WorkloadSecretSourceUser || len(preview[0].OverriddenSources) != 1 || preview[0].OverriddenSources[0] != codewire.WorkloadSecretSourceOrganization {
		t.Errorf("unexpected preview: %#v", preview)
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		t.Fatalf("marshal preview: %v", err)
	}
	if strings.Contains(string(encoded), "value") {
		t.Fatalf("preview exposed a value field: %s", encoded)
	}
}

func TestSecretProjects(t *testing.T) {
	projProto := &codewirev1.SecretProject{
		Id: "proj_1", OrgId: "org_test", Name: "myapp",
		CreatedAt: timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}

	client, _ := testSecretServer(t, secretServiceHandler{
		createProject: func(_ context.Context, req *connect.Request[codewirev1.CreateSecretProjectRequest]) (*connect.Response[codewirev1.CreateSecretProjectResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetName() != "myapp" {
				t.Errorf("unexpected create project request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.CreateSecretProjectResponse{SecretProject: projProto}), nil
		},
		listProjects: func(_ context.Context, req *connect.Request[codewirev1.ListSecretProjectsRequest]) (*connect.Response[codewirev1.ListSecretProjectsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" {
				t.Errorf("unexpected list projects request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListSecretProjectsResponse{SecretProjects: []*codewirev1.SecretProject{projProto}}), nil
		},
		deleteProject: func(_ context.Context, req *connect.Request[codewirev1.DeleteSecretProjectRequest]) (*connect.Response[codewirev1.DeleteSecretProjectResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetSecretProjectId() != "proj_1" {
				t.Errorf("unexpected delete project request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeleteSecretProjectResponse{}), nil
		},
		listProjectSecrets: func(_ context.Context, req *connect.Request[codewirev1.ListProjectSecretsRequest]) (*connect.Response[codewirev1.ListProjectSecretsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetSecretProjectId() != "proj_1" {
				t.Errorf("unexpected list project secrets request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListProjectSecretsResponse{Secrets: []*codewirev1.SecretMetadata{{Key: "API_KEY"}}}), nil
		},
		setProjectSecret: func(_ context.Context, req *connect.Request[codewirev1.SetProjectSecretRequest]) (*connect.Response[codewirev1.SetProjectSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetSecretProjectId() != "proj_1" || req.Msg.GetKey() != "API_KEY" {
				t.Errorf("unexpected set project secret request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.SetProjectSecretResponse{}), nil
		},
		deleteProjectSecret: func(_ context.Context, req *connect.Request[codewirev1.DeleteProjectSecretRequest]) (*connect.Response[codewirev1.DeleteProjectSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetSecretProjectId() != "proj_1" || req.Msg.GetKey() != "API_KEY" {
				t.Errorf("unexpected delete project secret request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeleteProjectSecretResponse{}), nil
		},
	})

	ctx := context.Background()

	proj, err := client.SecretProjects.Create(ctx, codewire.CreateSecretProjectInputBody{Name: "myapp"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if proj.Name != "myapp" {
		t.Errorf("expected myapp, got %s", proj.Name)
	}

	list, err := client.SecretProjects.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 project, got %d", len(list))
	}

	secrets, err := client.SecretProjects.ListSecrets(ctx, "proj_1")
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(secrets))
	}

	if err := client.SecretProjects.SetSecret(ctx, "proj_1", "API_KEY", "sk_123"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	if err := client.SecretProjects.DeleteSecret(ctx, "proj_1", "API_KEY"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}

	if err := client.SecretProjects.Delete(ctx, "proj_1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestSecretRenames(t *testing.T) {
	client, _ := testSecretServer(t, secretServiceHandler{
		renameSecret: func(_ context.Context, req *connect.Request[codewirev1.RenameSecretRequest]) (*connect.Response[codewirev1.RenameSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetKey() != "OLD" || req.Msg.GetNewKey() != "NEW" {
				t.Errorf("unexpected rename secret request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.RenameSecretResponse{}), nil
		},
		renameUserSecret: func(_ context.Context, req *connect.Request[codewirev1.RenameUserSecretRequest]) (*connect.Response[codewirev1.RenameUserSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetKey() != "OLD" || req.Msg.GetNewKey() != "NEW" {
				t.Errorf("unexpected rename user secret request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.RenameUserSecretResponse{}), nil
		},
		renameProjectSecret: func(_ context.Context, req *connect.Request[codewirev1.RenameProjectSecretRequest]) (*connect.Response[codewirev1.RenameProjectSecretResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetOrgId() != "org_test" || req.Msg.GetSecretProjectId() != "project_1" || req.Msg.GetKey() != "OLD" || req.Msg.GetNewKey() != "NEW" {
				t.Errorf("unexpected rename project secret request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.RenameProjectSecretResponse{}), nil
		},
	})

	ctx := context.Background()
	if err := client.Secrets.RenameSecret(ctx, "OLD", "NEW"); err != nil {
		t.Fatalf("rename secret: %v", err)
	}
	if err := client.Secrets.RenameUserSecret(ctx, "OLD", "NEW"); err != nil {
		t.Fatalf("rename user secret: %v", err)
	}
	if err := client.SecretProjects.RenameProjectSecret(ctx, "project_1", "OLD", "NEW"); err != nil {
		t.Fatalf("rename project secret: %v", err)
	}
}

func TestErrorHandling(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		get: func(context.Context, *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("environment not found"))
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	_, err := client.Environments.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *codewire.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *codewire.Error, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 404 {
		t.Errorf("expected 404, got %d", apiErr.StatusCode)
	}
	if apiErr.Detail != "environment not found" {
		t.Errorf("expected 'environment not found', got %q", apiErr.Detail)
	}
}

func TestErrorFieldHandling(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		list: func(context.Context, *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("workspace file upload failed: no such file"))
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	_, err := client.Environments.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *codewire.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *codewire.Error, got %T: %v", err, err)
	}
	if apiErr.Detail != "workspace file upload failed: no such file" {
		t.Errorf("expected raw error detail, got %q", apiErr.Detail)
	}
}

func TestRawFileErrorFieldHandling(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{}, execServiceHandler{}, fileServiceHandler{
		upload: func(context.Context, *connect.ClientStream[codewirev1.UploadFileRequest]) (*connect.Response[codewirev1.UploadFileResponse], error) {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("workspace file upload failed: no such file"))
		},
	}, portServiceHandler{})

	err := client.Environments.UploadFile(context.Background(), "env_123", strings.NewReader("hello"), "/workspace/test.txt")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *codewire.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *codewire.Error, got %T: %v", err, err)
	}
	if apiErr.Detail != "workspace file upload failed: no such file" {
		t.Errorf("expected raw error detail, got %q", apiErr.Detail)
	}
}

func TestMissingOrgID(t *testing.T) {
	client := codewire.New("test-key")
	_, err := client.Environments.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for missing orgID")
	}
	if !strings.Contains(err.Error(), "orgID is required") {
		t.Errorf("expected orgID error, got: %v", err)
	}
}

func TestPorts(t *testing.T) {
	portJSON := codewire.EnvironmentPort{
		Id: "port_1", EnvironmentId: "env_123", Port: 8080,
		Label: "web", Access: "public", CreatedAt: "2026-01-01T00:00:00Z",
	}

	client, _ := testRuntimeServer(t, environmentServiceHandler{}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{
		list: func(_ context.Context, req *connect.Request[codewirev1.ListPortsRequest]) (*connect.Response[codewirev1.ListPortsResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" || req.Msg.GetEnvironmentId() != "env_123" {
				t.Errorf("unexpected list request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ListPortsResponse{Ports: []*codewirev1.Port{portProto(portJSON)}}), nil
		},
		create: func(_ context.Context, req *connect.Request[codewirev1.CreatePortRequest]) (*connect.Response[codewirev1.CreatePortResponse], error) {
			if req.Msg.GetPort() != 8080 || req.Msg.GetLabel() != "web" || req.Msg.GetAccess() != codewirev1.PortAccess_PORT_ACCESS_PUBLIC {
				t.Errorf("unexpected create request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.CreatePortResponse{Port: portProto(portJSON)}), nil
		},
		delete: func(_ context.Context, req *connect.Request[codewirev1.DeletePortRequest]) (*connect.Response[codewirev1.DeletePortResponse], error) {
			if req.Msg.GetPortId() != "port_1" {
				t.Errorf("unexpected delete request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.DeletePortResponse{}), nil
		},
	})

	ctx := context.Background()

	ports, err := client.Environments.ListPorts(ctx, "env_123")
	if err != nil {
		t.Fatalf("list ports: %v", err)
	}
	if len(ports) != 1 || ports[0].Port != 8080 {
		t.Errorf("unexpected ports: %v", ports)
	}

	access := "public"
	port, err := client.Environments.CreatePort(ctx, "env_123", codewire.CreatePortBody{
		Port: 8080, Label: "web", Access: &access,
	})
	if err != nil {
		t.Fatalf("create port: %v", err)
	}
	if port.Label != "web" {
		t.Errorf("expected web, got %s", port.Label)
	}

	if err := client.Environments.DeletePort(ctx, "env_123", "port_1"); err != nil {
		t.Fatalf("delete port: %v", err)
	}
}

func TestError401(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		list: func(context.Context, *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	_, err := client.Environments.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *codewire.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *codewire.Error, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("expected 401, got %d", apiErr.StatusCode)
	}
	if apiErr.Detail != "unauthorized" {
		t.Errorf("expected 'unauthorized', got %q", apiErr.Detail)
	}
}

func TestError500(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		list: func(context.Context, *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			return nil, connect.NewError(connect.CodeInternal, errors.New("internal server error"))
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	_, err := client.Environments.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *codewire.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *codewire.Error, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected 500, got %d", apiErr.StatusCode)
	}
	if apiErr.Detail != "internal server error" {
		t.Errorf("expected 'internal server error', got %q", apiErr.Detail)
	}
}

func TestEmptyList(t *testing.T) {
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		list: func(context.Context, *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			return connect.NewResponse(&codewirev1.ListEnvironmentsResponse{}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	envs, err := client.Environments.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(envs) != 0 {
		t.Errorf("expected 0 environments, got %d", len(envs))
	}
}

func TestWaitReady(t *testing.T) {
	var calls atomic.Int32

	envProvisioning := codewire.EnvironmentData{
		Id: "env1", OrgId: "org_test", State: "provisioning",
		DesiredState: "running", Type: "sandbox", CreatedBy: "user-1",
		PresetId: strPtr("tmpl-1"), Recoverable: false, StateChangedAt: "2024-01-01T00:00:00Z",
		CpuMillicores: 1000, MemoryMb: 512, DiskGb: 10,
		TotalRunningSeconds: 0, CreatedAt: "2024-01-01T00:00:00Z",
	}
	envRunning := envProvisioning
	envRunning.State = "running"

	client, _ := testRuntimeServer(t, environmentServiceHandler{
		create: func(context.Context, *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.CreateEnvironmentResponse{Environment: environmentProto(envProvisioning)}), nil
		},
		get: func(_ context.Context, req *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
			if req.Msg.GetEnvironmentId() != "env1" {
				t.Errorf("unexpected get request: %#v", req.Msg)
			}
			if calls.Add(1) == 1 {
				return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(envProvisioning)}), nil
			}
			return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(envRunning)}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	slug := "test"
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{PresetSlug: &slug})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := env.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if env.State != "running" {
		t.Errorf("expected running, got %s", env.State)
	}
}

func TestWaitReadyError(t *testing.T) {
	reason := "out of resources"
	envProvisioning := codewire.EnvironmentData{
		Id: "env1", OrgId: "org_test", State: "provisioning",
		DesiredState: "running", Type: "sandbox", CreatedBy: "user-1",
		PresetId: strPtr("tmpl-1"), Recoverable: false, StateChangedAt: "2024-01-01T00:00:00Z",
		CpuMillicores: 1000, MemoryMb: 512, DiskGb: 10,
		TotalRunningSeconds: 0, CreatedAt: "2024-01-01T00:00:00Z",
	}
	envError := envProvisioning
	envError.State = "error"
	envError.ErrorReason = &reason

	client, _ := testRuntimeServer(t, environmentServiceHandler{
		create: func(context.Context, *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.CreateEnvironmentResponse{Environment: environmentProto(envProvisioning)}), nil
		},
		get: func(context.Context, *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(envError)}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	slug := "test"
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{PresetSlug: &slug})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	err = env.WaitReady(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *codewire.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *codewire.Error, got %T: %v", err, err)
	}
	if !strings.Contains(apiErr.Detail, "out of resources") {
		t.Errorf("expected detail containing 'out of resources', got %q", apiErr.Detail)
	}
}

func TestCreateWithWait(t *testing.T) {
	var getCalls atomic.Int32

	envProvisioning := codewire.EnvironmentData{
		Id: "env_cw", OrgId: "org_test", State: "provisioning",
		DesiredState: "running", Type: "sandbox", CreatedBy: "user-1",
		PresetId: strPtr("tmpl-1"), Recoverable: false, StateChangedAt: "2024-01-01T00:00:00Z",
		CpuMillicores: 1000, MemoryMb: 512, DiskGb: 10,
		TotalRunningSeconds: 0, CreatedAt: "2024-01-01T00:00:00Z",
	}
	envRunning := envProvisioning
	envRunning.State = "running"

	client, _ := testRuntimeServer(t, environmentServiceHandler{
		create: func(context.Context, *connect.Request[codewirev1.CreateEnvironmentRequest]) (*connect.Response[codewirev1.CreateEnvironmentResponse], error) {
			return connect.NewResponse(&codewirev1.CreateEnvironmentResponse{Environment: environmentProto(envProvisioning)}), nil
		},
		get: func(_ context.Context, req *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
			if req.Msg.GetEnvironmentId() != "env_cw" {
				t.Errorf("unexpected get request: %#v", req.Msg)
			}
			if getCalls.Add(1) >= 2 {
				return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(envRunning)}), nil
			}
			return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(envProvisioning)}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	slug := "test"
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{PresetSlug: &slug}, codewire.CreateOptions{Wait: true})
	if err != nil {
		t.Fatalf("create with wait: %v", err)
	}
	if env.State != "running" {
		t.Errorf("expected running, got %s", env.State)
	}
}

func TestAPIKeyUpdate(t *testing.T) {
	client, _ := testAPIKeyServer(t, apiKeyServiceHandler{
		update: func(_ context.Context, req *connect.Request[codewirev1.UpdateApiKeyRequest]) (*connect.Response[codewirev1.UpdateApiKeyResponse], error) {
			if req.Header().Get("Authorization") != "Bearer test-key" {
				t.Error("missing auth header")
			}
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetKeyId() != "key_1" || req.Msg.Disabled == nil || !req.Msg.GetDisabled() {
				t.Errorf("unexpected update request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.UpdateApiKeyResponse{ApiKey: apiKeyProto(true)}), nil
		},
	})

	ctx := context.Background()
	key, err := client.APIKeys.Update(ctx, "key_1", map[string]any{"disabled": true})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if key.DisabledAt == nil {
		t.Error("expected disabled API key")
	}
	if key.Id != "key_1" {
		t.Errorf("expected key_1, got %s", key.Id)
	}
}

func TestWithTimeout(t *testing.T) {
	// Verify WithTimeout doesn't panic.
	client := codewire.New("test-key",
		codewire.WithTimeout(5*time.Second),
		codewire.WithOrgID("org_test"),
	)
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Verify a slow Connect server triggers a timeout.
	_, srv := testRuntimeServer(t, environmentServiceHandler{
		list: func(context.Context, *connect.Request[codewirev1.ListEnvironmentsRequest]) (*connect.Response[codewirev1.ListEnvironmentsResponse], error) {
			time.Sleep(500 * time.Millisecond)
			return connect.NewResponse(&codewirev1.ListEnvironmentsResponse{}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	slowClient := codewire.New("test-key",
		codewire.WithBaseURL(srv.URL),
		codewire.WithOrgID("org_test"),
		codewire.WithTimeout(50*time.Millisecond),
	)

	_, err := slowClient.Environments.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func environmentProto(data codewire.EnvironmentData) *codewirev1.Environment {
	return &codewirev1.Environment{
		Id: data.Id, OrgId: data.OrgId, CreatedBy: data.CreatedBy, PresetId: valueOrEmpty(data.PresetId),
		Type: data.Type, Name: valueOrEmpty(data.Name), State: testEnvironmentState(data.State),
		DesiredState: testDesiredState(data.DesiredState), ErrorReason: valueOrEmpty(data.ErrorReason),
		Recoverable: data.Recoverable, StateChangedAt: testTimestamp(data.StateChangedAt),
		RetryCount: int32(data.RetryCount), SetupPhase: int32(data.SetupPhase), SetupComplete: data.SetupComplete,
		SetupError: valueOrEmpty(data.SetupError), CpuMillicores: int32(data.CpuMillicores), MemoryMb: int32(data.MemoryMb),
		DiskGb: int32(data.DiskGb), TotalRunningSeconds: int32(data.TotalRunningSeconds), CreatedAt: testTimestamp(data.CreatedAt),
		ShutdownAt: testTimestampPointer(data.ShutdownAt), StartedAt: testTimestampPointer(data.StartedAt),
		StoppedAt: testTimestampPointer(data.StoppedAt), DestroyedAt: testTimestampPointer(data.DestroyedAt), Protected: data.Protected,
		DeletionRequestedAt: testTimestampPointer(data.DeletionRequestedAt), DeletionGraceUntil: testTimestampPointer(data.DeletionGraceUntil),
		PresetName: valueOrEmpty(data.PresetName), Network: valueOrEmpty(data.Network),
	}
}

func portProto(data codewire.EnvironmentPort) *codewirev1.Port {
	return &codewirev1.Port{
		Id: data.Id, EnvironmentId: data.EnvironmentId, Port: int32(data.Port), Label: data.Label,
		Access: testPortAccess(data.Access), PreviewUrl: data.PreviewUrl, CreatedAt: testTimestamp(data.CreatedAt),
	}
}

func testEnvironmentState(value string) codewirev1.EnvironmentState {
	switch value {
	case "provisioning", "pending":
		return codewirev1.EnvironmentState_ENVIRONMENT_STATE_PENDING
	case "running":
		return codewirev1.EnvironmentState_ENVIRONMENT_STATE_RUNNING
	case "error":
		return codewirev1.EnvironmentState_ENVIRONMENT_STATE_ERROR
	default:
		return codewirev1.EnvironmentState_ENVIRONMENT_STATE_UNSPECIFIED
	}
}

func testDesiredState(value string) codewirev1.DesiredState {
	switch value {
	case "running", "started":
		return codewirev1.DesiredState_DESIRED_STATE_STARTED
	case "stopped":
		return codewirev1.DesiredState_DESIRED_STATE_STOPPED
	case "destroyed":
		return codewirev1.DesiredState_DESIRED_STATE_DESTROYED
	default:
		return codewirev1.DesiredState_DESIRED_STATE_UNSPECIFIED
	}
}

func testPortAccess(value string) codewirev1.PortAccess {
	switch value {
	case "public":
		return codewirev1.PortAccess_PORT_ACCESS_PUBLIC
	case "org_members":
		return codewirev1.PortAccess_PORT_ACCESS_ORG_MEMBERS
	case "creator":
		return codewirev1.PortAccess_PORT_ACCESS_CREATOR
	default:
		return codewirev1.PortAccess_PORT_ACCESS_UNSPECIFIED
	}
}

func testTimestamp(value string) *timestamppb.Timestamp {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return timestamppb.New(parsed)
}

func testTimestampPointer(value *string) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return testTimestamp(*value)
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func strPtr(s string) *string { return &s }
