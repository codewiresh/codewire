package codewire_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
)

type networkPolicyFixture struct {
	codewirev1connect.UnimplementedNetworkPolicyServiceHandler
	mu       sync.Mutex
	requests []proto.Message
}

func (f *networkPolicyFixture) record(message proto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, proto.Clone(message))
}

func (f *networkPolicyFixture) last() proto.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

func networkPolicyProto() *codewirev1.NetworkPolicy {
	return &codewirev1.NetworkPolicy{Id: "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b6a", OrgId: "org-one", Name: "web",
		Revision: 2, CurrentRevision: 2, Digest: strings.Repeat("ab", 32), CreatedBy: "user-one",
		Rules: []*codewirev1.NetworkPolicyRule{{Target: "github.com", Ports: []uint32{22, 443}}}}
}

func (f *networkPolicyFixture) CreateNetworkPolicy(_ context.Context, request *connect.Request[codewirev1.CreateNetworkPolicyRequest]) (*connect.Response[codewirev1.CreateNetworkPolicyResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.CreateNetworkPolicyResponse{Policy: networkPolicyProto()}), nil
}

func (f *networkPolicyFixture) ListNetworkPolicies(_ context.Context, request *connect.Request[codewirev1.ListNetworkPoliciesRequest]) (*connect.Response[codewirev1.ListNetworkPoliciesResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.ListNetworkPoliciesResponse{Policies: []*codewirev1.NetworkPolicy{networkPolicyProto()}}), nil
}

func (f *networkPolicyFixture) GetNetworkPolicy(_ context.Context, request *connect.Request[codewirev1.GetNetworkPolicyRequest]) (*connect.Response[codewirev1.GetNetworkPolicyResponse], error) {
	f.record(request.Msg)
	if request.Msg.GetPolicy().GetName() == "off" {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("platform network policies are not enabled"))
	}
	return connect.NewResponse(&codewirev1.GetNetworkPolicyResponse{Policy: networkPolicyProto()}), nil
}

func (f *networkPolicyFixture) UpdateNetworkPolicy(_ context.Context, request *connect.Request[codewirev1.UpdateNetworkPolicyRequest]) (*connect.Response[codewirev1.UpdateNetworkPolicyResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.UpdateNetworkPolicyResponse{Policy: networkPolicyProto()}), nil
}

func (f *networkPolicyFixture) DeleteNetworkPolicy(_ context.Context, request *connect.Request[codewirev1.DeleteNetworkPolicyRequest]) (*connect.Response[codewirev1.DeleteNetworkPolicyResponse], error) {
	f.record(request.Msg)
	return connect.NewResponse(&codewirev1.DeleteNetworkPolicyResponse{Policy: networkPolicyProto()}), nil
}

func (f *networkPolicyFixture) UpdateEnvironmentNetworkPolicy(_ context.Context, request *connect.Request[codewirev1.UpdateEnvironmentNetworkPolicyRequest]) (*connect.Response[codewirev1.UpdateEnvironmentNetworkPolicyResponse], error) {
	f.record(request.Msg)
	if request.Msg.GetEnvironmentId() == "future" {
		return connect.NewResponse(&codewirev1.UpdateEnvironmentNetworkPolicyResponse{NetworkPolicy: &codewirev1.EnvironmentNetworkPolicy{
			Reference: "hosted-default", Name: "hosted-default", Digest: strings.Repeat("cd", 32),
			Enforcement: codewirev1.NetworkPolicyEnforcement(99)}}), nil
	}
	return connect.NewResponse(&codewirev1.UpdateEnvironmentNetworkPolicyResponse{NetworkPolicy: &codewirev1.EnvironmentNetworkPolicy{
		Reference: "hosted-default", Name: "hosted-default", Digest: strings.Repeat("cd", 32),
		Enforcement: codewirev1.NetworkPolicyEnforcement_NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED}}), nil
}

func TestNetworkPoliciesNameTheOrganizationAndPolicy(t *testing.T) {
	fixture := &networkPolicyFixture{}
	_, handler := codewirev1connect.NewNetworkPolicyServiceHandler(fixture)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/codewire.v1.NetworkPolicyService/") {
			t.Error("unexpected generated procedure path")
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := codewire.New("synthetic", codewire.WithBaseURL(server.URL), codewire.WithOrgID("org-one"))
	ctx := context.Background()

	policies, err := client.NetworkPolicies.List(ctx)
	if err != nil || len(policies) != 1 || policies[0].CurrentRevision != 2 || len(policies[0].Rules[0].Ports) != 2 {
		t.Fatalf("list: %v %v", policies, err)
	}
	if _, err := client.NetworkPolicies.Create(ctx, "web", []codewire.NetworkPolicyRule{{Target: "github.com", Ports: []uint32{443}}}, &codewire.NetworkPolicySelector{Name: "base"}); err != nil {
		t.Fatal(err)
	}
	if create := fixture.last().(*codewirev1.CreateNetworkPolicyRequest); create.GetFrom().GetName() != "base" || create.GetOrgId() != "org-one" {
		t.Fatalf("create request: %v", create)
	}
	if _, err := client.NetworkPolicies.Get(ctx, codewire.NetworkPolicySelector{ID: "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b6a"}, 1); err != nil {
		t.Fatal(err)
	}
	if get := fixture.last().(*codewirev1.GetNetworkPolicyRequest); get.GetPolicy().GetId() == "" || get.GetRevision() != 1 {
		t.Fatalf("get request: %v", get)
	}
	if _, err := client.NetworkPolicies.Update(ctx, codewire.NetworkPolicySelector{Name: "web"}, nil, []string{"pypi.org"}, 2); err != nil {
		t.Fatal(err)
	}
	if update := fixture.last().(*codewirev1.UpdateNetworkPolicyRequest); update.GetExpectedRevision() != 2 || update.GetRemove()[0] != "pypi.org" {
		t.Fatalf("update request: %v", update)
	}
	if _, err := client.NetworkPolicies.Delete(ctx, codewire.NetworkPolicySelector{Name: "web"}); err != nil {
		t.Fatal(err)
	}
	selected, err := client.NetworkPolicies.Select(ctx, "environment-one", "hosted-default")
	if err != nil || selected.Enforcement != "not_enforced" || selected.Revision != 0 {
		t.Fatalf("select: %v %v", selected, err)
	}
	// A state this SDK does not know yet never fails the read.
	future, err := client.NetworkPolicies.Select(ctx, "future", "hosted-default")
	if err != nil || future.Enforcement != "unknown" || future.EnforcedAt != nil {
		t.Fatalf("unknown enforcement: %v %v", future, err)
	}
	if _, err := client.NetworkPolicies.Get(ctx, codewire.NetworkPolicySelector{Name: "off"}, 0); err == nil {
		t.Fatal("a deployment with policies off must fail")
	}
	if _, err := client.NetworkPolicies.Get(ctx, codewire.NetworkPolicySelector{Name: "web", ID: "x"}, 0); err == nil {
		t.Fatal("a selector naming both must be refused before any request")
	}
}
