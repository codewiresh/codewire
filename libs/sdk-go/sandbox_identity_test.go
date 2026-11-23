package codewire_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sandboxIdentityFixture struct {
	codewirev1connect.UnimplementedSandboxIdentityServiceHandler
	mu       sync.Mutex
	requests []proto.Message
}

func (f *sandboxIdentityFixture) record(message proto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, proto.Clone(message))
}

func (f *sandboxIdentityFixture) last() proto.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

var identityTime = time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)

func identityAudienceProto() *codewirev1.IdentityAudience {
	file := "vault"
	return &codewirev1.IdentityAudience{OrgId: "org-one", Audience: "https://vault.example.com/v1/auth/jwt",
		VisibleGroups: &codewirev1.IdentityAudienceGroups{Names: []string{"readers"}},
		Lifetime:      durationpb.New(5 * time.Minute), ClaimCreatedBy: true, FileName: &file,
		Version: 1794600000000000, CreatedBy: "user-one", CreatedAt: timestamppb.New(identityTime)}
}

func (f *sandboxIdentityFixture) GetEnvironmentIdentityGroups(_ context.Context, request *connect.Request[codewirev1.GetEnvironmentIdentityGroupsRequest]) (*connect.Response[codewirev1.GetEnvironmentIdentityGroupsResponse], error) {
	f.record(request.Msg)
	if request.Msg.GetEnvironmentId() == "never" {
		return connect.NewResponse(&codewirev1.GetEnvironmentIdentityGroupsResponse{Groups: &codewirev1.EnvironmentIdentityGroups{EnvironmentId: "never"}}), nil
	}
	return connect.NewResponse(&codewirev1.GetEnvironmentIdentityGroupsResponse{Groups: &codewirev1.EnvironmentIdentityGroups{
		EnvironmentId: request.Msg.GetEnvironmentId(), Groups: []string{"builders"}, Version: 2, UpdatedAt: timestamppb.New(identityTime)}}), nil
}

func (f *sandboxIdentityFixture) SetEnvironmentIdentityGroups(_ context.Context, request *connect.Request[codewirev1.SetEnvironmentIdentityGroupsRequest]) (*connect.Response[codewirev1.SetEnvironmentIdentityGroupsResponse], error) {
	f.record(request.Msg)
	if slices.Contains(request.Msg.GetGroups(), "all") {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("group name `all` is reserved: every token carries it"))
	}
	return connect.NewResponse(&codewirev1.SetEnvironmentIdentityGroupsResponse{
		Groups:         &codewirev1.EnvironmentIdentityGroups{EnvironmentId: request.Msg.GetEnvironmentId(), Groups: request.Msg.GetGroups(), Version: 3},
		PreviousGroups: []string{"builders"}, Changed: true,
		CanRunCode: []*codewirev1.IdentityGroupUser{
			{UserId: "user-one", Email: "one@example.com", Reason: codewirev1.IdentityGroupUserReason_IDENTITY_GROUP_USER_REASON_CREATOR},
			{UserId: "user-two", Email: "two@example.com", Reason: codewirev1.IdentityGroupUserReason(99)},
		}}), nil
}

func (f *sandboxIdentityFixture) RegisterIdentityAudience(_ context.Context, request *connect.Request[codewirev1.RegisterIdentityAudienceRequest]) (*connect.Response[codewirev1.RegisterIdentityAudienceResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.RegisterIdentityAudienceResponse{Audience: identityAudienceProto()}), nil
}

func (f *sandboxIdentityFixture) ListIdentityAudiences(_ context.Context, request *connect.Request[codewirev1.ListIdentityAudiencesRequest]) (*connect.Response[codewirev1.ListIdentityAudiencesResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.ListIdentityAudiencesResponse{Audiences: []*codewirev1.IdentityAudience{
		identityAudienceProto(), {OrgId: "org-one", Audience: "https://k8s.example", Version: 2}}}), nil
}

func (f *sandboxIdentityFixture) RemoveIdentityAudience(_ context.Context, request *connect.Request[codewirev1.RemoveIdentityAudienceRequest]) (*connect.Response[codewirev1.RemoveIdentityAudienceResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.RemoveIdentityAudienceResponse{Audience: "https://k8s.example"}), nil
}

func (f *sandboxIdentityFixture) StopIdentityMinting(_ context.Context, request *connect.Request[codewirev1.StopIdentityMintingRequest]) (*connect.Response[codewirev1.StopIdentityMintingResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.StopIdentityMintingResponse{Changed: true}), nil
}

func (f *sandboxIdentityFixture) ResumeIdentityMinting(_ context.Context, request *connect.Request[codewirev1.ResumeIdentityMintingRequest]) (*connect.Response[codewirev1.ResumeIdentityMintingResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.ResumeIdentityMintingResponse{Changed: false}), nil
}

func sandboxIdentityClient(t *testing.T) (*codewire.Client, *sandboxIdentityFixture) {
	t.Helper()
	fixture := &sandboxIdentityFixture{}
	_, handler := codewirev1connect.NewSandboxIdentityServiceHandler(fixture)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/codewire.v1.SandboxIdentityService/") {
			t.Error("unexpected generated procedure path")
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return codewire.New("synthetic", codewire.WithBaseURL(server.URL), codewire.WithOrgID("org-one")), fixture
}

func TestSandboxIdentityGroupsAreReadAndReplacedWithWhoCanUseThem(t *testing.T) {
	client, fixture := sandboxIdentityClient(t)
	ctx := context.Background()

	read, err := client.SandboxIdentity.GetGroups(ctx, "env-one")
	if err != nil || !reflect.DeepEqual(read.Groups, []string{"builders"}) || read.Version != 2 || read.UpdatedAt == nil || *read.UpdatedAt != "2026-11-21T18:00:00Z" {
		t.Fatalf("get: %+v %v", read, err)
	}
	if get := fixture.last().(*codewirev1.GetEnvironmentIdentityGroupsRequest); get.GetOrgId() != "org-one" || get.GetEnvironmentId() != "env-one" {
		t.Fatalf("get request: %v", get)
	}
	never, err := client.SandboxIdentity.GetGroups(ctx, "never")
	if err != nil || len(never.Groups) != 0 || never.Version != 0 || never.UpdatedAt != nil {
		t.Fatalf("never set: %+v %v", never, err)
	}

	set, err := client.SandboxIdentity.SetGroups(ctx, "env-one", []string{"data-readers"})
	if err != nil || !set.Changed || !reflect.DeepEqual(set.PreviousGroups, []string{"builders"}) {
		t.Fatalf("set: %+v %v", set, err)
	}
	// A reason this SDK does not know yet never fails the call.
	reasons := []string{set.CanRunCode[0].Reason, set.CanRunCode[1].Reason}
	if !reflect.DeepEqual(reasons, []string{"creator", "unknown"}) || set.CanRunCode[0].Email != "one@example.com" {
		t.Fatalf("can run code: %+v", set.CanRunCode)
	}
	if _, err := client.SandboxIdentity.SetGroups(ctx, "env-one", []string{"all"}); err == nil {
		t.Fatal("a refused set returned no error")
	} else if sdkError := (*codewire.Error)(nil); !errors.As(err, &sdkError) {
		t.Fatalf("not the SDK's error: %T %v", err, err)
	}
}

func TestSandboxIdentityAudiencesAreRegisteredListedAndRemoved(t *testing.T) {
	client, fixture := sandboxIdentityClient(t)
	ctx := context.Background()

	registered, err := client.SandboxIdentity.RegisterAudience(ctx, "https://vault.example.com/v1/auth/jwt", codewire.RegisterIdentityAudienceOptions{
		VisibleGroups: []string{"readers"}, Lifetime: 5 * time.Minute, ClaimCreatedBy: true, FileName: "vault"})
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.last().(*codewirev1.RegisterIdentityAudienceRequest)
	if !reflect.DeepEqual(request.GetVisibleGroups().GetNames(), []string{"readers"}) || request.GetLifetime().GetSeconds() != 300 ||
		!request.GetClaimCreatedBy() || request.GetClaimEnvironmentName() || request.GetFileName() != "vault" {
		t.Fatalf("register request: %v", request)
	}
	if registered.LifetimeSeconds != 300 || !reflect.DeepEqual(registered.VisibleGroups, []string{"readers"}) ||
		registered.FileName == nil || *registered.FileName != "vault" || registered.Version != 1794600000000000 ||
		registered.CreatedAt == nil || *registered.CreatedAt != "2026-11-21T18:00:00Z" {
		t.Fatalf("registered: %+v", registered)
	}
	if _, err := client.SandboxIdentity.RegisterAudience(ctx, "https://k8s.example", codewire.RegisterIdentityAudienceOptions{}); err != nil {
		t.Fatal(err)
	}
	if plain := fixture.last().(*codewirev1.RegisterIdentityAudienceRequest); plain.VisibleGroups != nil || plain.Lifetime != nil || plain.FileName != nil {
		t.Fatalf("every group, ten minutes and no file unless named: %v", plain)
	}
	if _, err := client.SandboxIdentity.RegisterAudience(ctx, "https://none.example", codewire.RegisterIdentityAudienceOptions{VisibleGroups: []string{}}); err != nil {
		t.Fatal(err)
	}
	if none := fixture.last().(*codewirev1.RegisterIdentityAudienceRequest); none.VisibleGroups == nil {
		t.Fatal("an empty list sees none but all, so it is sent")
	}

	listed, err := client.SandboxIdentity.ListAudiences(ctx)
	if err != nil || len(listed) != 2 || listed[1].VisibleGroups != nil || listed[1].LifetimeSeconds != 600 || listed[1].FileName != nil {
		t.Fatalf("list: %+v %v", listed, err)
	}
	removed, err := client.SandboxIdentity.RemoveAudience(ctx, "HTTPS://K8S.EXAMPLE:443")
	if err != nil || removed != "https://k8s.example" {
		t.Fatalf("remove: %q %v", removed, err)
	}
}

func TestSandboxIdentityMintingStopsForASandboxOrTheOrganization(t *testing.T) {
	client, fixture := sandboxIdentityClient(t)
	ctx := context.Background()
	if changed, err := client.SandboxIdentity.StopMinting(ctx, "env-one"); err != nil || !changed {
		t.Fatalf("stop: %v %v", changed, err)
	}
	if stop := fixture.last().(*codewirev1.StopIdentityMintingRequest); stop.GetEnvironmentId() != "env-one" || stop.GetOrgId() != "org-one" {
		t.Fatalf("stop request: %v", stop)
	}
	if _, err := client.SandboxIdentity.StopMinting(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if stop := fixture.last().(*codewirev1.StopIdentityMintingRequest); stop.GetEnvironmentId() != "" {
		t.Fatalf("no Sandbox stops the organization: %v", stop)
	}
	if changed, err := client.SandboxIdentity.ResumeMinting(ctx, "env-one"); err != nil || changed {
		t.Fatalf("resume: %v %v", changed, err)
	}
}
