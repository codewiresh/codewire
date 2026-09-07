package codewire_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
)

const accessExact uint64 = 9_007_199_254_741_009

type accessProfileFixture struct {
	codewirev1connect.UnimplementedAccessProfileServiceHandler
	t        *testing.T
	mu       sync.Mutex
	methods  []string
	requests []proto.Message
	paths    []string
}

func (f *accessProfileFixture) record(method string, message proto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if message.ProtoReflect().Descriptor().Fields().ByName("org_id") != nil {
		f.t.Error("personal profiles must not inherit organization scope")
	}
	f.methods = append(f.methods, method)
	f.requests = append(f.requests, proto.Clone(message))
}

func (f *accessProfileFixture) last() proto.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return proto.Clone(f.requests[len(f.requests)-1])
}

func (f *accessProfileFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.requests) }

func accessProfileProto() *codewirev1.AccessProfile {
	return &codewirev1.AccessProfile{Id: "profile-one", Name: "personal", Revision: accessExact,
		Entries: []*codewirev1.AccessProfileEntry{{CapabilitySlot: "codex", CredentialId: "credential-one"}}}
}

func accessBinding() codewire.EnvironmentAccessProfileBinding {
	return codewire.EnvironmentAccessProfileBinding{EnvironmentID: "environment-one", AccessProfileID: "profile-one", AccessProfileRevision: accessExact}
}

func (f *accessProfileFixture) ListAccessProfiles(_ context.Context, request *connect.Request[codewirev1.ListAccessProfilesRequest]) (*connect.Response[codewirev1.ListAccessProfilesResponse], error) {
	f.record("ListAccessProfiles", request.Msg)
	next := ""
	if request.Msg.PageToken == "" {
		next = "page-two"
	}
	return connect.NewResponse(&codewirev1.ListAccessProfilesResponse{AccessProfiles: []*codewirev1.AccessProfile{accessProfileProto()}, NextPageToken: next}), nil
}
func (f *accessProfileFixture) GetAccessProfile(_ context.Context, request *connect.Request[codewirev1.GetAccessProfileRequest]) (*connect.Response[codewirev1.GetAccessProfileResponse], error) {
	f.record("GetAccessProfile", request.Msg)
	if request.Msg.GetAccessProfileId() == "missing" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
	}
	if request.Msg.GetAccessProfileId() == "missing-response" {
		return connect.NewResponse(&codewirev1.GetAccessProfileResponse{}), nil
	}
	return connect.NewResponse(&codewirev1.GetAccessProfileResponse{AccessProfile: accessProfileProto()}), nil
}
func (f *accessProfileFixture) CreateAccessProfile(_ context.Context, request *connect.Request[codewirev1.CreateAccessProfileRequest]) (*connect.Response[codewirev1.CreateAccessProfileResponse], error) {
	f.record("CreateAccessProfile", request.Msg)
	return connect.NewResponse(&codewirev1.CreateAccessProfileResponse{AccessProfile: accessProfileProto()}), nil
}
func (f *accessProfileFixture) UpdateAccessProfile(_ context.Context, request *connect.Request[codewirev1.UpdateAccessProfileRequest]) (*connect.Response[codewirev1.UpdateAccessProfileResponse], error) {
	f.record("UpdateAccessProfile", request.Msg)
	if request.Msg.AccessProfileId == "stale" {
		return nil, connect.NewError(connect.CodeAborted, errors.New("stale revision"))
	}
	return connect.NewResponse(&codewirev1.UpdateAccessProfileResponse{AccessProfile: accessProfileProto()}), nil
}
func (f *accessProfileFixture) DeleteAccessProfile(_ context.Context, request *connect.Request[codewirev1.DeleteAccessProfileRequest]) (*connect.Response[codewirev1.DeleteAccessProfileResponse], error) {
	f.record("DeleteAccessProfile", request.Msg)
	return connect.NewResponse(&codewirev1.DeleteAccessProfileResponse{}), nil
}
func (f *accessProfileFixture) GetEnvironmentAccessProfile(_ context.Context, request *connect.Request[codewirev1.GetEnvironmentAccessProfileRequest]) (*connect.Response[codewirev1.GetEnvironmentAccessProfileResponse], error) {
	f.record("GetEnvironmentAccessProfile", request.Msg)
	if request.Msg.EnvironmentId == "unbound" {
		return connect.NewResponse(&codewirev1.GetEnvironmentAccessProfileResponse{}), nil
	}
	return connect.NewResponse(&codewirev1.GetEnvironmentAccessProfileResponse{Binding: &codewirev1.EnvironmentAccessProfileBinding{
		EnvironmentId: "environment-one", AccessProfileId: "profile-one", AccessProfileRevision: accessExact}, PersonalCredentialsConfirmed: true}), nil
}
func (f *accessProfileFixture) SetEnvironmentAccessProfile(_ context.Context, request *connect.Request[codewirev1.SetEnvironmentAccessProfileRequest]) (*connect.Response[codewirev1.SetEnvironmentAccessProfileResponse], error) {
	f.record("SetEnvironmentAccessProfile", request.Msg)
	if !request.Msg.ConfirmPersonalCredentials {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("explicit consent required"))
	}
	return connect.NewResponse(&codewirev1.SetEnvironmentAccessProfileResponse{Binding: request.Msg.Binding}), nil
}
func (f *accessProfileFixture) ClearEnvironmentAccessProfile(_ context.Context, request *connect.Request[codewirev1.ClearEnvironmentAccessProfileRequest]) (*connect.Response[codewirev1.ClearEnvironmentAccessProfileResponse], error) {
	f.record("ClearEnvironmentAccessProfile", request.Msg)
	return connect.NewResponse(&codewirev1.ClearEnvironmentAccessProfileResponse{}), nil
}

func testAccessProfileServer(t *testing.T) (*codewire.Client, *accessProfileFixture) {
	t.Helper()
	f := &accessProfileFixture{t: t}
	_, handler := codewirev1connect.NewAccessProfileServiceHandler(f)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-opaque-oauth" {
			t.Error("missing exact user bearer")
		}
		if !strings.HasPrefix(r.URL.Path, "/codewire.v1.AccessProfileService/") {
			t.Error("unexpected generated procedure path")
		}
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		want := make([]string, len(f.methods))
		for index, method := range f.methods {
			want[index] = "/codewire.v1.AccessProfileService/" + method
		}
		if !reflect.DeepEqual(f.paths, want) && len(want) != 0 {
			t.Errorf("unexpected method paths: %v", f.paths)
		}
	})
	return codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL)), f
}

func TestAccessProfilesListAndExactSelectors(t *testing.T) {
	client, fixture := testAccessProfileServer(t)
	ctx := context.Background()
	profiles, err := client.AccessProfiles.List(ctx)
	if err != nil || len(profiles) != 2 || profiles[0].Revision != accessExact {
		t.Fatalf("lossless paginated profiles: %v %v", profiles, err)
	}
	if len(profiles[0].Entries) != 1 || profiles[0].Entries[0].CredentialID != "credential-one" {
		t.Fatal("profile entry output changed")
	}
	fixture.mu.Lock()
	first := fixture.requests[0].(*codewirev1.ListAccessProfilesRequest)
	second := fixture.requests[1].(*codewirev1.ListAccessProfilesRequest)
	fixture.mu.Unlock()
	if first.PageSize != 0 || first.PageToken != "" || second.PageToken != "page-two" {
		t.Fatal("pagination/default page size changed")
	}
	if _, err := client.AccessProfiles.Get(ctx, "profile-one", nil); err != nil {
		t.Fatal(err)
	}
	request := fixture.last().(*codewirev1.GetAccessProfileRequest)
	if _, ok := request.Selector.(*codewirev1.GetAccessProfileRequest_AccessProfileId); !ok || request.GetAccessProfileId() != "profile-one" || request.Revision != nil {
		t.Fatal("ID selector/current presence changed")
	}
	exact := accessExact
	if _, err := client.AccessProfiles.GetByName(ctx, "personal", &exact); err != nil {
		t.Fatal(err)
	}
	request = fixture.last().(*codewirev1.GetAccessProfileRequest)
	if _, ok := request.Selector.(*codewirev1.GetAccessProfileRequest_Name); !ok || request.GetName() != "personal" || request.GetRevision() != exact {
		t.Fatal("name selector/exact revision changed")
	}
}

func TestAccessProfilesMutationAndBindingCAS(t *testing.T) {
	client, fixture := testAccessProfileServer(t)
	ctx := context.Background()
	entry := codewire.AccessProfileEntry{CapabilitySlot: "codex", CredentialID: "credential-one"}
	if _, err := client.AccessProfiles.Create(ctx, "personal", []codewire.AccessProfileEntry{entry}); err != nil {
		t.Fatal(err)
	}
	create := fixture.last().(*codewirev1.CreateAccessProfileRequest)
	if create.Name != "personal" || len(create.Entries) != 1 || create.Entries[0].CredentialId != entry.CredentialID {
		t.Fatal("credential metadata reference changed")
	}
	if _, err := client.AccessProfiles.Update(ctx, "profile-one", accessExact, nil); err != nil {
		t.Fatal(err)
	}
	update := fixture.last().(*codewirev1.UpdateAccessProfileRequest)
	if update.ExpectedRevision != accessExact || len(update.Entries) != 0 {
		t.Fatal("exact CAS/empty replacement changed")
	}
	if err := client.AccessProfiles.Delete(ctx, "profile-one", ^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if fixture.last().(*codewirev1.DeleteAccessProfileRequest).ExpectedRevision != ^uint64(0) {
		t.Fatal("uint64 revision was narrowed")
	}
	unbound, err := client.AccessProfiles.GetEnvironmentBinding(ctx, "unbound")
	if err != nil || unbound.Binding != nil || unbound.PersonalCredentialsConfirmed {
		t.Fatalf("unbound default: %v %v", unbound, err)
	}
	bound, err := client.AccessProfiles.GetEnvironmentBinding(ctx, "environment-one")
	if err != nil || !bound.PersonalCredentialsConfirmed || *bound.Binding != accessBinding() {
		t.Fatalf("bound metadata: %v %v", bound, err)
	}
	binding := accessBinding()
	if _, err := client.AccessProfiles.SetEnvironmentBinding(ctx, binding, nil, false); err == nil {
		t.Fatal("false consent was not sent to server")
	}
	set := fixture.last().(*codewirev1.SetEnvironmentAccessProfileRequest)
	if set.ConfirmPersonalCredentials || set.ExpectedBinding != nil {
		t.Fatal("SDK inferred consent or existing binding")
	}
	expected := binding
	expected.AccessProfileID = "previous-profile"
	expected.AccessProfileRevision = accessExact - 3
	result, err := client.AccessProfiles.SetEnvironmentBinding(ctx, binding, &expected, true)
	if err != nil || *result != binding {
		t.Fatalf("binding result: %v %v", result, err)
	}
	set = fixture.last().(*codewirev1.SetEnvironmentAccessProfileRequest)
	if !set.ConfirmPersonalCredentials || set.ExpectedBinding.AccessProfileId != expected.AccessProfileID || set.ExpectedBinding.AccessProfileRevision != expected.AccessProfileRevision {
		t.Fatal("exact caller-provided binding CAS was replaced")
	}
	if err := client.AccessProfiles.ClearEnvironmentBinding(ctx, expected); err != nil {
		t.Fatal(err)
	}
	clear := fixture.last().(*codewirev1.ClearEnvironmentAccessProfileRequest)
	if !proto.Equal(clear.ExpectedBinding, set.ExpectedBinding) {
		t.Fatal("clear did not preserve exact expected binding")
	}
}

func TestAccessProfilesRejectDuplicateSlotsAndZeroRevisionWithoutTransport(t *testing.T) {
	client, fixture := testAccessProfileServer(t)
	ctx := context.Background()
	entries := []codewire.AccessProfileEntry{{CapabilitySlot: "codex", CredentialID: "one"}, {CapabilitySlot: "codex", CredentialID: "two"}}
	if _, err := client.AccessProfiles.Create(ctx, "personal", entries); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("duplicate create was not rejected")
	}
	if _, err := client.AccessProfiles.Update(ctx, "profile-one", accessExact, entries); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("duplicate update was not rejected")
	}
	zero := uint64(0)
	if _, err := client.AccessProfiles.Get(ctx, "profile-one", &zero); err == nil {
		t.Fatal("zero revision accepted")
	}
	if err := client.AccessProfiles.Delete(ctx, "profile-one", 0); err == nil {
		t.Fatal("zero CAS accepted")
	}
	binding := accessBinding()
	binding.AccessProfileRevision = 0
	if _, err := client.AccessProfiles.SetEnvironmentBinding(ctx, binding, nil, true); err == nil {
		t.Fatal("zero binding revision accepted")
	}
	if fixture.count() != 0 {
		t.Fatal("invalid local input reached transport")
	}
}

func TestAccessProfilesErrorMappingAndNoStaleCASRetry(t *testing.T) {
	client, fixture := testAccessProfileServer(t)
	ctx := context.Background()
	_, err := client.AccessProfiles.Update(ctx, "stale", accessExact, nil)
	var sdkError *codewire.Error
	if !errors.As(err, &sdkError) || sdkError.StatusCode != 409 || fixture.count() != 1 {
		t.Fatalf("stale CAS retried or wrong error: %v", err)
	}
	_, err = client.AccessProfiles.Get(ctx, "missing", nil)
	if !errors.As(err, &sdkError) || sdkError.StatusCode != 404 || fixture.count() != 2 {
		t.Fatalf("not-found mapping: %v", err)
	}
	_, err = client.AccessProfiles.Get(ctx, "missing-response", nil)
	if err == nil || !strings.Contains(err.Error(), "omitted access_profile") {
		t.Fatalf("missing profile accepted: %v", err)
	}
}
