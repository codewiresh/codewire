package codewire_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	meshTestOrg     = "org-exact"
	meshTestNetwork = "network-exact"
)

func TestMeshGeneratedClientsCoverMountedOperations(t *testing.T) {
	handler := newMeshCapabilityHandler(t)
	mux := http.NewServeMux()
	registerMeshCapabilityHandlers(mux, handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := codewire.NewMeshClient(server.URL, "cw_mesh_test")
	ctx := context.Background()

	createdNetwork, err := client.Networks.Create(ctx, meshTestOrg, meshTestNetwork)
	if err != nil {
		t.Fatal(err)
	}
	assertMeshNetwork(t, createdNetwork)
	networks, err := client.Networks.List(ctx, meshTestOrg)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 {
		t.Fatalf("networks = %#v, want two paginated results", networks)
	}
	assertMeshNetwork(t, &networks[0])

	nodes, err := client.Nodes.List(ctx, meshTestOrg, meshTestNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %#v, want two paginated results", nodes)
	}
	if got := nodes[0]; got.OrgID != meshTestOrg || got.NetworkID != meshTestNetwork ||
		got.Name != "node-one" || got.PeerURL != "https://peer.example/node-one" || !got.Connected {
		t.Fatalf("node = %#v, want every MeshNode field", got)
	}
	if err := client.Nodes.Revoke(ctx, meshTestOrg, meshTestNetwork, "node-one"); err != nil {
		t.Fatal(err)
	}
	enrollment, err := client.Nodes.CreateEnrollment(ctx, meshTestOrg, meshTestNetwork, "node-one", 17*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.ID != "enrollment-one" || enrollment.OrgID != meshTestOrg ||
		enrollment.NetworkID != meshTestNetwork || enrollment.NodeName != "node-one" ||
		enrollment.OwnerUserID != "owner-user" || enrollment.IssuedByUserID != "issuer-user" ||
		enrollment.EnrollmentCode != "secret-one-use-code" ||
		!enrollment.ExpiresAt.Equal(handler.expiresAt) ||
		!enrollment.CreatedAt.Equal(handler.createdAt) ||
		enrollment.RedeemedAt == nil || !enrollment.RedeemedAt.Equal(handler.redeemedAt) {
		t.Fatalf("enrollment = %#v, want every MeshNodeEnrollment field and one-use code", enrollment)
	}

	createdGroup, err := client.Groups.Create(ctx, meshTestOrg, meshTestNetwork, "group-one")
	if err != nil {
		t.Fatal(err)
	}
	assertMeshGroup(t, createdGroup, codewire.MeshGroupMessagesPolicyOpen, codewire.MeshGroupDebugPolicyFull)
	groups, err := client.Groups.List(ctx, meshTestOrg, meshTestNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("groups = %#v, want four paginated enum fixtures", groups)
	}
	assertMeshGroup(t, &groups[0], codewire.MeshGroupMessagesPolicyOpen, codewire.MeshGroupDebugPolicyFull)
	gotPolicies := [][2]string{
		{string(groups[0].Policy.MessagesPolicy), string(groups[0].Policy.DebugPolicy)},
		{string(groups[1].Policy.MessagesPolicy), string(groups[1].Policy.DebugPolicy)},
		{string(groups[2].Policy.MessagesPolicy), string(groups[2].Policy.DebugPolicy)},
		{string(groups[3].Policy.MessagesPolicy), string(groups[3].Policy.DebugPolicy)},
	}
	wantPolicies := [][2]string{
		{"open", "full"},
		{"internal-only", "none"},
		{"", "observe-only"},
		{"open", ""},
	}
	if !reflect.DeepEqual(gotPolicies, wantPolicies) {
		t.Fatalf("group enum conversions = %#v, want %#v", gotPolicies, wantPolicies)
	}
	gotGroup, err := client.Groups.Get(ctx, meshTestOrg, meshTestNetwork, "group-one")
	if err != nil {
		t.Fatal(err)
	}
	assertMeshGroup(t, gotGroup, codewire.MeshGroupMessagesPolicyOpen, codewire.MeshGroupDebugPolicyFull)
	if err := client.Groups.Delete(ctx, meshTestOrg, meshTestNetwork, "group-one"); err != nil {
		t.Fatal(err)
	}
	member, err := client.Groups.AddMember(ctx, meshTestOrg, meshTestNetwork, "group-one", "node-one", "session-one")
	if err != nil {
		t.Fatal(err)
	}
	assertMeshGroupMember(t, member)
	if err := client.Groups.RemoveMember(ctx, meshTestOrg, meshTestNetwork, "group-one", "node-one", "session-one"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		messages codewire.MeshGroupMessagesPolicy
		debug    codewire.MeshGroupDebugPolicy
	}{
		{codewire.MeshGroupMessagesPolicyUnspecified, codewire.MeshGroupDebugPolicyUnspecified},
		{codewire.MeshGroupMessagesPolicyInternalOnly, codewire.MeshGroupDebugPolicyNone},
		{codewire.MeshGroupMessagesPolicyOpen, codewire.MeshGroupDebugPolicyObserveOnly},
		{codewire.MeshGroupMessagesPolicyOpen, codewire.MeshGroupDebugPolicyFull},
	} {
		policy, err := client.Groups.SetPolicy(
			ctx, meshTestOrg, meshTestNetwork, "group-one", test.messages, test.debug,
		)
		if err != nil {
			t.Fatal(err)
		}
		if policy.MessagesPolicy != test.messages || policy.DebugPolicy != test.debug {
			t.Fatalf("policy = %#v, want %q/%q", policy, test.messages, test.debug)
		}
	}
	if _, err := client.Groups.SetPolicy(
		ctx, meshTestOrg, meshTestNetwork, "group-one",
		codewire.MeshGroupMessagesPolicy("invalid"), codewire.MeshGroupDebugPolicyNone,
	); err == nil {
		t.Fatal("invalid messages policy unexpectedly succeeded")
	}

	setEntry, err := client.KV.Set(
		ctx, meshTestOrg, meshTestNetwork, "namespace-one", "key-one", []byte{0, 1, 2, 255}, 23*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertMeshKVEntry(t, setEntry, handler.expiresAt)
	gotEntry, err := client.KV.Get(ctx, meshTestOrg, meshTestNetwork, "namespace-one", "key-one")
	if err != nil {
		t.Fatal(err)
	}
	assertMeshKVEntry(t, gotEntry, handler.expiresAt)
	entries, err := client.KV.List(ctx, meshTestOrg, meshTestNetwork, "namespace-one", "key")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %#v, want two paginated results", entries)
	}
	assertMeshKVEntry(t, &entries[0], handler.expiresAt)
	if err := client.KV.Delete(ctx, meshTestOrg, meshTestNetwork, "namespace-one", "key-one"); err != nil {
		t.Fatal(err)
	}

	wantOperations := []string{
		"AddMeshGroupMember",
		"CreateMeshGroup",
		"CreateMeshNetwork",
		"CreateMeshNodeEnrollment",
		"DeleteMeshGroup",
		"DeleteMeshKeyValue",
		"GetMeshGroup",
		"GetMeshKeyValue",
		"ListMeshGroups",
		"ListMeshKeyValues",
		"ListMeshNetworks",
		"ListMeshNodes",
		"RemoveMeshGroupMember",
		"RevokeMeshNode",
		"SetMeshGroupPolicy",
		"SetMeshKeyValue",
	}
	if got := handler.calledOperations(); !reflect.DeepEqual(got, wantOperations) {
		t.Fatalf("mounted operation coverage = %#v, want %#v", got, wantOperations)
	}
}

func TestMeshConnectErrorUsesCanonicalSDKError(t *testing.T) {
	handler := newMeshCapabilityHandler(t)
	mux := http.NewServeMux()
	path, networkHandler := codewirev1connect.NewMeshNetworkServiceHandler(handler)
	mux.Handle(path, networkHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := codewire.NewMeshClient(server.URL, "cw_mesh_test")
	_, err := client.Networks.Create(context.Background(), meshTestOrg, "reject-me")
	var sdkError *codewire.Error
	if !errors.As(err, &sdkError) {
		t.Fatalf("error = %T %v, want *codewire.Error", err, err)
	}
	if sdkError.StatusCode != http.StatusBadRequest || sdkError.Detail != "invalid network" {
		t.Fatalf("error = %#v, want canonical invalid_argument mapping", sdkError)
	}
}

func TestMeshRedeemEnrollmentIsTheOnlyRawMeshCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/node-enrollments/redeem" {
			t.Fatalf("request = %s %s, want exact raw redemption route", r.Method, r.URL.Path)
		}
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Fatalf("Authorization = %q, want public redemption", authorization)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request["enrollment_token"] != "one-use-token" || request["node_name"] != "node-one" {
			t.Fatalf("request = %#v, want exact redemption payload", request)
		}
		_ = json.NewEncoder(w).Encode(codewire.MeshNodeCredentials{
			NodeToken: "node-token-one", NodeName: "node-one",
			NetworkID: meshTestNetwork, EnrollmentID: "enrollment-one",
		})
	}))
	defer server.Close()

	client := codewire.NewMeshClient(server.URL, "unused-bearer")
	credentials, err := client.Nodes.RedeemEnrollment(context.Background(), "one-use-token", "node-one")
	if err != nil {
		t.Fatal(err)
	}
	if credentials.NodeToken != "node-token-one" || credentials.NodeName != "node-one" ||
		credentials.NetworkID != meshTestNetwork || credentials.EnrollmentID != "enrollment-one" {
		t.Fatalf("credentials = %#v, want exact raw response", credentials)
	}
}

type meshCapabilityHandler struct {
	codewirev1connect.UnimplementedMeshNetworkServiceHandler
	codewirev1connect.UnimplementedMeshNodeServiceHandler
	codewirev1connect.UnimplementedMeshGroupServiceHandler
	codewirev1connect.UnimplementedMeshKeyValueServiceHandler

	t          *testing.T
	createdAt  time.Time
	updatedAt  time.Time
	expiresAt  time.Time
	redeemedAt time.Time
	mu         sync.Mutex
	calls      map[string]int
}

func newMeshCapabilityHandler(t *testing.T) *meshCapabilityHandler {
	return &meshCapabilityHandler{
		t:          t,
		createdAt:  time.Date(2026, 7, 28, 10, 11, 12, 13, time.UTC),
		updatedAt:  time.Date(2026, 7, 28, 11, 12, 13, 14, time.UTC),
		expiresAt:  time.Date(2026, 7, 29, 10, 11, 12, 15, time.UTC),
		redeemedAt: time.Date(2026, 7, 28, 12, 13, 14, 16, time.UTC),
		calls:      make(map[string]int),
	}
}

func (h *meshCapabilityHandler) ListMeshNetworks(_ context.Context, request *connect.Request[codewirev1.ListMeshNetworksRequest]) (*connect.Response[codewirev1.ListMeshNetworksResponse], error) {
	h.record("ListMeshNetworks", request.Header(), request.Msg.GetOrgId())
	switch request.Msg.GetPageToken() {
	case "":
		return connect.NewResponse(&codewirev1.ListMeshNetworksResponse{
			Networks:      []*codewirev1.MeshNetwork{h.network("network-one")},
			NextPageToken: "network-page-two",
		}), nil
	case "network-page-two":
		return connect.NewResponse(&codewirev1.ListMeshNetworksResponse{
			Networks: []*codewirev1.MeshNetwork{h.network("network-two")},
		}), nil
	default:
		h.t.Fatalf("network page token = %q", request.Msg.GetPageToken())
		return nil, nil
	}
}

func (h *meshCapabilityHandler) CreateMeshNetwork(_ context.Context, request *connect.Request[codewirev1.CreateMeshNetworkRequest]) (*connect.Response[codewirev1.CreateMeshNetworkResponse], error) {
	h.record("CreateMeshNetwork", request.Header(), request.Msg.GetOrgId())
	if request.Msg.GetNetworkId() == "reject-me" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid network"))
	}
	if request.Msg.GetNetworkId() != meshTestNetwork {
		h.t.Fatalf("network_id = %q, want %q", request.Msg.GetNetworkId(), meshTestNetwork)
	}
	return connect.NewResponse(&codewirev1.CreateMeshNetworkResponse{Network: h.network(meshTestNetwork)}), nil
}

func (h *meshCapabilityHandler) ListMeshNodes(_ context.Context, request *connect.Request[codewirev1.ListMeshNodesRequest]) (*connect.Response[codewirev1.ListMeshNodesResponse], error) {
	h.recordNetwork("ListMeshNodes", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId())
	switch request.Msg.GetPageToken() {
	case "":
		return connect.NewResponse(&codewirev1.ListMeshNodesResponse{
			Nodes:         []*codewirev1.MeshNode{h.node("node-one")},
			NextPageToken: "node-page-two",
		}), nil
	case "node-page-two":
		return connect.NewResponse(&codewirev1.ListMeshNodesResponse{
			Nodes: []*codewirev1.MeshNode{h.node("node-two")},
		}), nil
	default:
		h.t.Fatalf("node page token = %q", request.Msg.GetPageToken())
		return nil, nil
	}
}

func (h *meshCapabilityHandler) RevokeMeshNode(_ context.Context, request *connect.Request[codewirev1.RevokeMeshNodeRequest]) (*connect.Response[codewirev1.RevokeMeshNodeResponse], error) {
	h.recordNetwork("RevokeMeshNode", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId())
	if request.Msg.GetNodeName() != "node-one" {
		h.t.Fatalf("node_name = %q, want node-one", request.Msg.GetNodeName())
	}
	return connect.NewResponse(&codewirev1.RevokeMeshNodeResponse{}), nil
}

func (h *meshCapabilityHandler) CreateMeshNodeEnrollment(_ context.Context, request *connect.Request[codewirev1.CreateMeshNodeEnrollmentRequest]) (*connect.Response[codewirev1.CreateMeshNodeEnrollmentResponse], error) {
	h.recordNetwork("CreateMeshNodeEnrollment", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId())
	if request.Msg.GetNodeName() != "node-one" || request.Msg.GetTtl().AsDuration() != 17*time.Minute {
		h.t.Fatalf("enrollment request = %#v, want node-one and 17m", request.Msg)
	}
	return connect.NewResponse(&codewirev1.CreateMeshNodeEnrollmentResponse{
		Enrollment: &codewirev1.MeshNodeEnrollment{
			Id: "enrollment-one", OrgId: meshTestOrg, NetworkId: meshTestNetwork,
			NodeName: "node-one", OwnerUserId: "owner-user", IssuedByUserId: "issuer-user",
			ExpiresAt: timestamppb.New(h.expiresAt), CreatedAt: timestamppb.New(h.createdAt),
			RedeemedAt: timestamppb.New(h.redeemedAt),
		},
		EnrollmentCode: "secret-one-use-code",
	}), nil
}

func (h *meshCapabilityHandler) ListMeshGroups(_ context.Context, request *connect.Request[codewirev1.ListMeshGroupsRequest]) (*connect.Response[codewirev1.ListMeshGroupsResponse], error) {
	h.recordNetwork("ListMeshGroups", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId())
	switch request.Msg.GetPageToken() {
	case "":
		return connect.NewResponse(&codewirev1.ListMeshGroupsResponse{
			Groups: []*codewirev1.MeshGroup{h.group(
				"group-one",
				codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_OPEN,
				codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_FULL,
			)},
			NextPageToken: "group-page-two",
		}), nil
	case "group-page-two":
		return connect.NewResponse(&codewirev1.ListMeshGroupsResponse{Groups: []*codewirev1.MeshGroup{
			h.group(
				"group-two",
				codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY,
				codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_NONE,
			),
			h.group(
				"group-three",
				codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED,
				codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY,
			),
			h.group(
				"group-four",
				codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_OPEN,
				codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_UNSPECIFIED,
			),
		}}), nil
	default:
		h.t.Fatalf("group page token = %q", request.Msg.GetPageToken())
		return nil, nil
	}
}

func (h *meshCapabilityHandler) CreateMeshGroup(_ context.Context, request *connect.Request[codewirev1.CreateMeshGroupRequest]) (*connect.Response[codewirev1.CreateMeshGroupResponse], error) {
	h.recordGroup("CreateMeshGroup", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetName())
	return connect.NewResponse(&codewirev1.CreateMeshGroupResponse{Group: h.group(
		request.Msg.GetName(),
		codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_OPEN,
		codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_FULL,
	)}), nil
}

func (h *meshCapabilityHandler) GetMeshGroup(_ context.Context, request *connect.Request[codewirev1.GetMeshGroupRequest]) (*connect.Response[codewirev1.GetMeshGroupResponse], error) {
	h.recordGroup("GetMeshGroup", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetGroupName())
	return connect.NewResponse(&codewirev1.GetMeshGroupResponse{Group: h.group(
		request.Msg.GetGroupName(),
		codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_OPEN,
		codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_FULL,
	)}), nil
}

func (h *meshCapabilityHandler) DeleteMeshGroup(_ context.Context, request *connect.Request[codewirev1.DeleteMeshGroupRequest]) (*connect.Response[codewirev1.DeleteMeshGroupResponse], error) {
	h.recordGroup("DeleteMeshGroup", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetGroupName())
	return connect.NewResponse(&codewirev1.DeleteMeshGroupResponse{}), nil
}

func (h *meshCapabilityHandler) SetMeshGroupPolicy(_ context.Context, request *connect.Request[codewirev1.SetMeshGroupPolicyRequest]) (*connect.Response[codewirev1.SetMeshGroupPolicyResponse], error) {
	h.recordGroup("SetMeshGroupPolicy", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetGroupName())
	return connect.NewResponse(&codewirev1.SetMeshGroupPolicyResponse{Policy: h.policy(
		request.Msg.GetMessagesPolicy(), request.Msg.GetDebugPolicy(),
	)}), nil
}

func (h *meshCapabilityHandler) AddMeshGroupMember(_ context.Context, request *connect.Request[codewirev1.AddMeshGroupMemberRequest]) (*connect.Response[codewirev1.AddMeshGroupMemberResponse], error) {
	h.recordGroup("AddMeshGroupMember", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetGroupName())
	if request.Msg.GetNodeName() != "node-one" || request.Msg.GetSessionName() != "session-one" {
		h.t.Fatalf("member request = %#v, want exact node/session", request.Msg)
	}
	return connect.NewResponse(&codewirev1.AddMeshGroupMemberResponse{Member: h.member()}), nil
}

func (h *meshCapabilityHandler) RemoveMeshGroupMember(_ context.Context, request *connect.Request[codewirev1.RemoveMeshGroupMemberRequest]) (*connect.Response[codewirev1.RemoveMeshGroupMemberResponse], error) {
	h.recordGroup("RemoveMeshGroupMember", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetGroupName())
	if request.Msg.GetNodeName() != "node-one" || request.Msg.GetSessionName() != "session-one" {
		h.t.Fatalf("member request = %#v, want exact node/session", request.Msg)
	}
	return connect.NewResponse(&codewirev1.RemoveMeshGroupMemberResponse{}), nil
}

func (h *meshCapabilityHandler) ListMeshKeyValues(_ context.Context, request *connect.Request[codewirev1.ListMeshKeyValuesRequest]) (*connect.Response[codewirev1.ListMeshKeyValuesResponse], error) {
	h.recordKV("ListMeshKeyValues", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetNamespace())
	if request.Msg.GetPrefix() != "key" {
		h.t.Fatalf("prefix = %q, want key", request.Msg.GetPrefix())
	}
	switch request.Msg.GetPageToken() {
	case "":
		return connect.NewResponse(&codewirev1.ListMeshKeyValuesResponse{
			Entries:       []*codewirev1.MeshKeyValue{h.kv("key-one")},
			NextPageToken: "kv-page-two",
		}), nil
	case "kv-page-two":
		return connect.NewResponse(&codewirev1.ListMeshKeyValuesResponse{
			Entries: []*codewirev1.MeshKeyValue{h.kv("key-two")},
		}), nil
	default:
		h.t.Fatalf("KV page token = %q", request.Msg.GetPageToken())
		return nil, nil
	}
}

func (h *meshCapabilityHandler) GetMeshKeyValue(_ context.Context, request *connect.Request[codewirev1.GetMeshKeyValueRequest]) (*connect.Response[codewirev1.GetMeshKeyValueResponse], error) {
	h.recordKV("GetMeshKeyValue", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetNamespace())
	if request.Msg.GetKey() != "key-one" {
		h.t.Fatalf("key = %q, want key-one", request.Msg.GetKey())
	}
	return connect.NewResponse(&codewirev1.GetMeshKeyValueResponse{Entry: h.kv(request.Msg.GetKey())}), nil
}

func (h *meshCapabilityHandler) SetMeshKeyValue(_ context.Context, request *connect.Request[codewirev1.SetMeshKeyValueRequest]) (*connect.Response[codewirev1.SetMeshKeyValueResponse], error) {
	h.recordKV("SetMeshKeyValue", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetNamespace())
	if request.Msg.GetKey() != "key-one" ||
		!reflect.DeepEqual(request.Msg.GetValue(), []byte{0, 1, 2, 255}) ||
		request.Msg.GetTtl().AsDuration() != 23*time.Second {
		h.t.Fatalf("set request = %#v, want exact key/value/TTL", request.Msg)
	}
	return connect.NewResponse(&codewirev1.SetMeshKeyValueResponse{Entry: h.kv(request.Msg.GetKey())}), nil
}

func (h *meshCapabilityHandler) DeleteMeshKeyValue(_ context.Context, request *connect.Request[codewirev1.DeleteMeshKeyValueRequest]) (*connect.Response[codewirev1.DeleteMeshKeyValueResponse], error) {
	h.recordKV("DeleteMeshKeyValue", request.Header(), request.Msg.GetOrgId(), request.Msg.GetNetworkId(), request.Msg.GetNamespace())
	if request.Msg.GetKey() != "key-one" {
		h.t.Fatalf("key = %q, want key-one", request.Msg.GetKey())
	}
	return connect.NewResponse(&codewirev1.DeleteMeshKeyValueResponse{}), nil
}

func (h *meshCapabilityHandler) record(operation string, header http.Header, orgID string) {
	if got := header.Get("Authorization"); got != "Bearer cw_mesh_test" {
		h.t.Fatalf("%s Authorization = %q, want canonical bearer", operation, got)
	}
	if orgID != meshTestOrg {
		h.t.Fatalf("%s org_id = %q, want %q", operation, orgID, meshTestOrg)
	}
	h.mu.Lock()
	h.calls[operation]++
	h.mu.Unlock()
}

func (h *meshCapabilityHandler) recordNetwork(operation string, header http.Header, orgID, networkID string) {
	h.record(operation, header, orgID)
	if networkID != meshTestNetwork {
		h.t.Fatalf("%s network_id = %q, want %q", operation, networkID, meshTestNetwork)
	}
}

func (h *meshCapabilityHandler) recordGroup(operation string, header http.Header, orgID, networkID, groupName string) {
	h.recordNetwork(operation, header, orgID, networkID)
	if groupName != "group-one" {
		h.t.Fatalf("%s group_name = %q, want group-one", operation, groupName)
	}
}

func (h *meshCapabilityHandler) recordKV(operation string, header http.Header, orgID, networkID, namespace string) {
	h.recordNetwork(operation, header, orgID, networkID)
	if namespace != "namespace-one" {
		h.t.Fatalf("%s namespace = %q, want namespace-one", operation, namespace)
	}
}

func (h *meshCapabilityHandler) calledOperations() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	operations := make([]string, 0, len(h.calls))
	for _, operation := range []string{
		"AddMeshGroupMember",
		"CreateMeshGroup",
		"CreateMeshNetwork",
		"CreateMeshNodeEnrollment",
		"DeleteMeshGroup",
		"DeleteMeshKeyValue",
		"GetMeshGroup",
		"GetMeshKeyValue",
		"ListMeshGroups",
		"ListMeshKeyValues",
		"ListMeshNetworks",
		"ListMeshNodes",
		"RemoveMeshGroupMember",
		"RevokeMeshNode",
		"SetMeshGroupPolicy",
		"SetMeshKeyValue",
	} {
		if h.calls[operation] > 0 {
			operations = append(operations, operation)
		}
	}
	return operations
}

func (h *meshCapabilityHandler) network(id string) *codewirev1.MeshNetwork {
	return &codewirev1.MeshNetwork{
		Id: id, OrgId: meshTestOrg, CreatedAt: timestamppb.New(h.createdAt),
		NodeCount: 7, InviteCount: 11,
	}
}

func (h *meshCapabilityHandler) node(name string) *codewirev1.MeshNode {
	return &codewirev1.MeshNode{
		OrgId: meshTestOrg, NetworkId: meshTestNetwork, Name: name,
		PeerUrl: "https://peer.example/" + name, Connected: true,
	}
}

func (h *meshCapabilityHandler) member() *codewirev1.MeshGroupMember {
	return &codewirev1.MeshGroupMember{
		OrgId: meshTestOrg, NetworkId: meshTestNetwork, GroupName: "group-one",
		NodeName: "node-one", SessionName: "session-one", CreatedAt: timestamppb.New(h.createdAt),
	}
}

func (h *meshCapabilityHandler) policy(messages codewirev1.MeshGroupMessagesPolicy, debug codewirev1.MeshGroupDebugPolicy) *codewirev1.MeshGroupPolicy {
	return &codewirev1.MeshGroupPolicy{
		OrgId: meshTestOrg, NetworkId: meshTestNetwork, GroupName: "group-one",
		MessagesPolicy: messages, DebugPolicy: debug, UpdatedAt: timestamppb.New(h.updatedAt),
	}
}

func (h *meshCapabilityHandler) group(name string, messages codewirev1.MeshGroupMessagesPolicy, debug codewirev1.MeshGroupDebugPolicy) *codewirev1.MeshGroup {
	return &codewirev1.MeshGroup{
		OrgId: meshTestOrg, NetworkId: meshTestNetwork, Name: name,
		CreatedAt: timestamppb.New(h.createdAt), CreatedByUserId: "creator-user",
		Members: []*codewirev1.MeshGroupMember{h.member()}, Policy: h.policy(messages, debug),
	}
}

func (h *meshCapabilityHandler) kv(key string) *codewirev1.MeshKeyValue {
	return &codewirev1.MeshKeyValue{
		OrgId: meshTestOrg, NetworkId: meshTestNetwork, Namespace: "namespace-one",
		Key: key, Value: []byte{0, 1, 2, 255}, ExpiresAt: timestamppb.New(h.expiresAt),
	}
}

func registerMeshCapabilityHandlers(mux *http.ServeMux, handler *meshCapabilityHandler) {
	networkPath, networkHandler := codewirev1connect.NewMeshNetworkServiceHandler(handler)
	mux.Handle(networkPath, networkHandler)
	nodePath, nodeHandler := codewirev1connect.NewMeshNodeServiceHandler(handler)
	mux.Handle(nodePath, nodeHandler)
	groupPath, groupHandler := codewirev1connect.NewMeshGroupServiceHandler(handler)
	mux.Handle(groupPath, groupHandler)
	kvPath, kvHandler := codewirev1connect.NewMeshKeyValueServiceHandler(handler)
	mux.Handle(kvPath, kvHandler)
}

func assertMeshNetwork(t *testing.T, network *codewire.MeshNetwork) {
	t.Helper()
	if network.ID == "" || network.OrgID != meshTestOrg ||
		!network.CreatedAt.Equal(time.Date(2026, 7, 28, 10, 11, 12, 13, time.UTC)) ||
		network.NodeCount != 7 || network.InviteCount != 11 {
		t.Fatalf("network = %#v, want every MeshNetwork field", network)
	}
}

func assertMeshGroup(t *testing.T, group *codewire.MeshGroup, messages codewire.MeshGroupMessagesPolicy, debug codewire.MeshGroupDebugPolicy) {
	t.Helper()
	if group.OrgID != meshTestOrg || group.NetworkID != meshTestNetwork || group.Name == "" ||
		!group.CreatedAt.Equal(time.Date(2026, 7, 28, 10, 11, 12, 13, time.UTC)) ||
		group.CreatedByUserID != "creator-user" || len(group.Members) != 1 || group.Policy == nil {
		t.Fatalf("group = %#v, want every MeshGroup field", group)
	}
	assertMeshGroupMember(t, &group.Members[0])
	if group.Policy.MessagesPolicy != messages || group.Policy.DebugPolicy != debug ||
		group.Policy.OrgID != meshTestOrg || group.Policy.NetworkID != meshTestNetwork ||
		group.Policy.GroupName != "group-one" ||
		!group.Policy.UpdatedAt.Equal(time.Date(2026, 7, 28, 11, 12, 13, 14, time.UTC)) {
		t.Fatalf("policy = %#v, want every MeshGroupPolicy field", group.Policy)
	}
}

func assertMeshGroupMember(t *testing.T, member *codewire.MeshGroupMember) {
	t.Helper()
	if member.OrgID != meshTestOrg || member.NetworkID != meshTestNetwork ||
		member.GroupName != "group-one" || member.NodeName != "node-one" ||
		member.SessionName != "session-one" ||
		!member.CreatedAt.Equal(time.Date(2026, 7, 28, 10, 11, 12, 13, time.UTC)) {
		t.Fatalf("member = %#v, want every MeshGroupMember field", member)
	}
}

func assertMeshKVEntry(t *testing.T, entry *codewire.MeshKVEntry, expiresAt time.Time) {
	t.Helper()
	if entry.OrgID != meshTestOrg || entry.NetworkID != meshTestNetwork ||
		entry.Namespace != "namespace-one" || entry.Key != "key-one" ||
		!reflect.DeepEqual(entry.Value, []byte{0, 1, 2, 255}) ||
		entry.ExpiresAt == nil || !entry.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("entry = %#v, want every MeshKeyValue field", entry)
	}
}
