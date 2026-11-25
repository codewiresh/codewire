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
	"time"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type auditFixture struct {
	codewirev1connect.UnimplementedAuditServiceHandler
	mu       sync.Mutex
	requests []*codewirev1.ListAuditEventsRequest
}

func (f *auditFixture) last() *codewirev1.ListAuditEventsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

var auditTime = time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)

func auditEventsProto() []*codewirev1.AuditEvent {
	user := &codewirev1.AuditActor{Actor: &codewirev1.AuditActor_User{User: &codewirev1.AuditUser{
		Id: "user-one", Email: "one@example.com", Role: codewirev1.AuditRole_AUDIT_ROLE_ADMIN}}}
	key := &codewirev1.AuditActor{Actor: &codewirev1.AuditActor_ApiKey{ApiKey: &codewirev1.AuditApiKey{Id: "key-one", Name: "ci"}}}
	platform := &codewirev1.AuditActor{Actor: &codewirev1.AuditActor_Platform{Platform: &codewirev1.AuditPlatform{}}}
	sandbox := &codewirev1.AuditActor{Actor: &codewirev1.AuditActor_Sandbox{Sandbox: &codewirev1.AuditSandbox{}}}
	return []*codewirev1.AuditEvent{
		{Id: "event-access", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_ACCESS, First: timestamppb.New(auditTime),
			Count: 1, Actor: user, Detail: &codewirev1.AuditEvent_Access{Access: &codewirev1.AuditAccess{
				Surface: codewirev1.AuditSurface_AUDIT_SURFACE_SSH, ClientIp: "203.0.113.7"}}},
		{Id: "event-lifecycle", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_LIFECYCLE, First: timestamppb.New(auditTime),
			Last: timestamppb.New(auditTime.Add(time.Second)), Count: 1, Actor: platform,
			Detail: &codewirev1.AuditEvent_Lifecycle{Lifecycle: &codewirev1.AuditLifecycle{
				Action: codewirev1.AuditLifecycle_ACTION_STOPPED, Reason: codewirev1.AuditPlatformReason_AUDIT_PLATFORM_REASON_IDLE,
				Preset: "go", FromSnapshot: "snap-one", From: &codewirev1.AuditSize{Vcpu: 2, MemoryMib: 4096},
				To: &codewirev1.AuditSize{Vcpu: 4, MemoryMib: 8192}, Snapshot: "snap-two", IdleStopSeconds: 1800}}},
		{Id: "event-policy", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_POLICY, Count: 1, Actor: key,
			Detail: &codewirev1.AuditEvent_Policy{Policy: &codewirev1.AuditPolicyChange{
				Action: codewirev1.AuditPolicyChange_ACTION_EDITED, From: "open", To: "web", Policy: "web",
				FromRevision: 2, ToRevision: 3, Added: []string{"github.com:443"}, Removed: []string{"example.com:80"},
				Revision: 3, FailureCode: "self_check_failed"}}},
		{Id: "event-refused", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_REFUSED, Count: 7, Actor: sandbox,
			Detail: &codewirev1.AuditEvent_Refused{Refused: &codewirev1.AuditRefusal{
				Destination: "evil.example", Address: "198.51.100.9", Port: proto.Uint32(443),
				Protocol: codewirev1.AuditProtocol_AUDIT_PROTOCOL_TCP, Reason: "name_not_allowed", Source: "egress",
				Policy: "web", Revision: 3, AllowedSinceRevision: proto.Uint32(4)}}},
		{Id: "event-dns", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_REFUSED, Count: 1, Actor: sandbox,
			Detail: &codewirev1.AuditEvent_Refused{Refused: &codewirev1.AuditRefusal{
				Withheld: true, Protocol: codewirev1.AuditProtocol_AUDIT_PROTOCOL_DNS, Reason: "host_check_failed"}}},
		{Id: "event-credentials", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_CREDENTIALS, Count: 2, Actor: sandbox,
			Detail: &codewirev1.AuditEvent_Credentials{Credentials: &codewirev1.AuditCredentials{
				Action: codewirev1.AuditCredentials_ACTION_USED, Provider: "github", Name: "work", Host: "api.github.com", Withheld: true}}},
		{Id: "event-overflow", Kind: codewirev1.AuditEventKind_AUDIT_EVENT_KIND_REFUSED, Count: 4200, Actor: sandbox,
			Detail: &codewirev1.AuditEvent_RefusedOverflow{RefusedOverflow: &codewirev1.AuditRefusalOverflow{Subjects: 1000, AtLeast: true}}},
		{Id: "event-future", Kind: codewirev1.AuditEventKind(99), Actor: &codewirev1.AuditActor{}},
	}
}

func (f *auditFixture) ListAuditEvents(_ context.Context, request *connect.Request[codewirev1.ListAuditEventsRequest]) (*connect.Response[codewirev1.ListAuditEventsResponse], error) {
	f.mu.Lock()
	f.requests = append(f.requests, proto.Clone(request.Msg).(*codewirev1.ListAuditEventsRequest))
	f.mu.Unlock()
	if request.Msg.GetEnvironmentName() == "missing" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("environment not found"))
	}
	if request.Msg.GetEnvironmentName() == "unselected" {
		return connect.NewResponse(&codewirev1.ListAuditEventsResponse{Environment: &codewirev1.AuditEnvironment{Id: "env-two", Name: "unselected"}}), nil
	}
	return connect.NewResponse(&codewirev1.ListAuditEventsResponse{
		Environment: &codewirev1.AuditEnvironment{Id: "env-one", Name: "web", Deleted: true},
		Policy:      &codewirev1.AuditPolicyRevision{Name: "web", Revision: 3},
		Events:      auditEventsProto(), NextCursor: "cursor-two", LeftOut: 5}), nil
}

func auditClient(t *testing.T) (*codewire.Client, *auditFixture) {
	t.Helper()
	fixture := &auditFixture{}
	_, handler := codewirev1connect.NewAuditServiceHandler(fixture)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/codewire.v1.AuditService/") {
			t.Error("unexpected generated procedure path")
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return codewire.New("synthetic", codewire.WithBaseURL(server.URL), codewire.WithOrgID("org-one")), fixture
}

func TestAuditEventsSendEveryFilterAndConvertEveryKind(t *testing.T) {
	client, fixture := auditClient(t)
	ctx := context.Background()

	page, err := client.Audit.ListAuditEvents(ctx, codewire.ListAuditEventsOptions{EnvironmentID: "env-one",
		Kinds: []string{"refused", "credentials"}, Since: auditTime.Add(-time.Hour), Until: auditTime,
		Limit: 50, Cursor: "cursor-one", GroupBySubject: true})
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.last()
	if request.GetOrgId() != "org-one" || request.GetEnvironmentId() != "env-one" ||
		!reflect.DeepEqual(request.GetKinds(), []codewirev1.AuditEventKind{codewirev1.AuditEventKind_AUDIT_EVENT_KIND_REFUSED, codewirev1.AuditEventKind_AUDIT_EVENT_KIND_CREDENTIALS}) ||
		!request.GetSince().AsTime().Equal(auditTime.Add(-time.Hour)) || !request.GetUntil().AsTime().Equal(auditTime) ||
		request.GetLimit() != 50 || request.GetCursor() != "cursor-one" || !request.GetGroupBySubject() {
		t.Fatalf("request: %v", request)
	}
	if page.Environment != (codewire.AuditEnvironment{ID: "env-one", Name: "web", Deleted: true}) ||
		page.Policy == nil || *page.Policy != (codewire.AuditPolicyRevision{Name: "web", Revision: 3}) ||
		page.NextCursor != "cursor-two" || page.LeftOut != 5 || len(page.Events) != 8 {
		t.Fatalf("page: %+v", page)
	}
	first := "2026-11-24T09:00:00Z"
	last := "2026-11-24T09:00:01Z"
	port, allowedSince := uint32(443), uint32(4)
	want := []codewire.AuditEvent{
		{ID: "event-access", Kind: "access", First: &first, Count: 1,
			Actor:  codewire.AuditActor{User: &codewire.AuditUser{ID: "user-one", Email: "one@example.com", Role: "admin"}},
			Access: &codewire.AuditAccess{Surface: "ssh", ClientIP: "203.0.113.7"}},
		{ID: "event-lifecycle", Kind: "lifecycle", First: &first, Last: &last, Count: 1,
			Actor: codewire.AuditActor{Platform: &codewire.AuditPlatform{}},
			Lifecycle: &codewire.AuditLifecycle{Action: "stopped", Reason: "idle", Preset: "go", FromSnapshot: "snap-one",
				From: &codewire.AuditSize{VCPU: 2, MemoryMiB: 4096}, To: &codewire.AuditSize{VCPU: 4, MemoryMiB: 8192},
				Snapshot: "snap-two", IdleStopSeconds: 1800}},
		{ID: "event-policy", Kind: "policy", Count: 1,
			Actor: codewire.AuditActor{APIKey: &codewire.AuditAPIKey{ID: "key-one", Name: "ci"}},
			Policy: &codewire.AuditPolicyChange{Action: "edited", From: "open", To: "web", Policy: "web", FromRevision: 2,
				ToRevision: 3, Added: []string{"github.com:443"}, Removed: []string{"example.com:80"}, Revision: 3,
				FailureCode: "self_check_failed"}},
		{ID: "event-refused", Kind: "refused", Count: 7, Actor: codewire.AuditActor{Sandbox: &codewire.AuditSandbox{}},
			Refused: &codewire.AuditRefusal{Destination: "evil.example", Address: "198.51.100.9", Port: &port,
				Protocol: "tcp", Reason: "name_not_allowed", Source: "egress", Policy: "web", Revision: 3,
				AllowedSinceRevision: &allowedSince}},
		{ID: "event-dns", Kind: "refused", Count: 1, Actor: codewire.AuditActor{Sandbox: &codewire.AuditSandbox{}},
			Refused: &codewire.AuditRefusal{Withheld: true, Protocol: "dns", Reason: "host_check_failed"}},
		{ID: "event-credentials", Kind: "credentials", Count: 2, Actor: codewire.AuditActor{Sandbox: &codewire.AuditSandbox{}},
			Credentials: &codewire.AuditCredentials{Action: "used", Provider: "github", Name: "work", Host: "api.github.com", Withheld: true}},
		{ID: "event-overflow", Kind: "refused", Count: 4200, Actor: codewire.AuditActor{Sandbox: &codewire.AuditSandbox{}},
			RefusedOverflow: &codewire.AuditRefusalOverflow{Subjects: 1000, AtLeast: true}},
		// A kind or actor this SDK does not know yet never fails the read.
		{ID: "event-future", Kind: "unknown"},
	}
	for i := range want {
		if !reflect.DeepEqual(page.Events[i], want[i]) {
			t.Fatalf("event %d:\n got %+v\nwant %+v", i, page.Events[i], want[i])
		}
	}
}

func TestAuditEventsNameTheEnvironmentOnceAndDefaultTheRest(t *testing.T) {
	client, fixture := auditClient(t)
	ctx := context.Background()

	page, err := client.Audit.ListAuditEvents(ctx, codewire.ListAuditEventsOptions{EnvironmentName: "unselected"})
	if err != nil || page.Policy != nil || len(page.Events) != 0 || page.NextCursor != "" {
		t.Fatalf("unselected: %+v %v", page, err)
	}
	if request := fixture.last(); request.GetEnvironmentName() != "unselected" || request.Since != nil || request.Until != nil ||
		len(request.GetKinds()) != 0 || request.GetLimit() != 0 || request.GetGroupBySubject() {
		t.Fatalf("defaults are left to the server: %v", request)
	}
	for _, options := range []codewire.ListAuditEventsOptions{{}, {EnvironmentID: "env-one", EnvironmentName: "web"}} {
		if _, err := client.Audit.ListAuditEvents(ctx, options); err == nil {
			t.Fatalf("%+v: an environment named by neither or both was accepted", options)
		}
	}
	for _, kinds := range [][]string{{"unspecified"}, {""}, {"logins"}} {
		if _, err := client.Audit.ListAuditEvents(ctx, codewire.ListAuditEventsOptions{EnvironmentID: "env-one", Kinds: kinds}); err == nil {
			t.Fatalf("kind %q was accepted", kinds)
		}
	}
	if len(fixture.requests) != 1 {
		t.Fatalf("a refused option reached the server: %d requests", len(fixture.requests))
	}
	if _, err := client.Audit.ListAuditEvents(ctx, codewire.ListAuditEventsOptions{EnvironmentName: "missing"}); err == nil {
		t.Fatal("a missing environment returned no error")
	} else if sdkError := (*codewire.Error)(nil); !errors.As(err, &sdkError) {
		t.Fatalf("not the SDK's error: %T %v", err, err)
	}
}
