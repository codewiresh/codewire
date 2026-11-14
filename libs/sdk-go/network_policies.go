package codewire

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// NetworkPolicyRule is one allow rule: an exact name, a `*.` pattern or a
// public CIDR, and the TCP ports it may be dialed on.
type NetworkPolicyRule struct {
	Target string   `json:"target"`
	Ports  []uint32 `json:"ports"`
}

// NetworkPolicy is one immutable revision of an organization's network policy
// (#4000). A local VM's policy with the same rules has the same digest.
type NetworkPolicy struct {
	ID              string              `json:"id"`
	OrgID           string              `json:"org_id"`
	Name            string              `json:"name"`
	Revision        uint32              `json:"revision"`
	CurrentRevision uint32              `json:"current_revision"`
	Rules           []NetworkPolicyRule `json:"rules"`
	Digest          string              `json:"digest"`
	CreatedBy       string              `json:"created_by"`
}

// EnvironmentNetworkPolicy is what an environment selects and what its runtime
// enforces. Enforcement is "not_enforced", "enforced", "enforcing",
// "failed_closed", or "unknown" for a state this SDK does not know yet.
type EnvironmentNetworkPolicy struct {
	Reference        string `json:"reference"`
	Name             string `json:"name"`
	Revision         uint32 `json:"revision"`
	Digest           string `json:"digest"`
	Enforcement      string `json:"enforcement"`
	EnforcedRevision uint32 `json:"enforced_revision"`
	EnforcedDigest   string `json:"enforced_digest"`
	// EnforcedAt is RFC 3339, or nil while nothing enforces the selection.
	EnforcedAt *string `json:"enforced_at,omitempty"`
}

// NetworkPolicySelector names a policy by Name or by ID; set exactly one.
type NetworkPolicySelector struct {
	Name string
	ID   string
}

// NetworkPolicyService manages an organization's network policies. Owners and
// admins create, change and delete them; members read and select them. While
// the deployment's platform network policies are off, every method fails as
// unavailable.
type NetworkPolicyService struct{ client *Client }

func networkPolicySelector(selector NetworkPolicySelector) (*codewirev1.NetworkPolicySelector, error) {
	switch {
	case selector.Name != "" && selector.ID == "":
		return &codewirev1.NetworkPolicySelector{Selector: &codewirev1.NetworkPolicySelector_Name{Name: selector.Name}}, nil
	case selector.ID != "" && selector.Name == "":
		return &codewirev1.NetworkPolicySelector{Selector: &codewirev1.NetworkPolicySelector_Id{Id: selector.ID}}, nil
	}
	return nil, fmt.Errorf("codewire: a network policy selector names a policy by exactly one of Name or ID")
}

func networkPolicyRules(rules []NetworkPolicyRule) []*codewirev1.NetworkPolicyRule {
	result := make([]*codewirev1.NetworkPolicyRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, &codewirev1.NetworkPolicyRule{Target: rule.Target, Ports: rule.Ports})
	}
	return result
}

func fromProtoNetworkPolicy(policy *codewirev1.NetworkPolicy) (*NetworkPolicy, error) {
	if policy == nil {
		return nil, fmt.Errorf("codewire: network policy response omitted policy")
	}
	result := &NetworkPolicy{ID: policy.GetId(), OrgID: policy.GetOrgId(), Name: policy.GetName(),
		Revision: policy.GetRevision(), CurrentRevision: policy.GetCurrentRevision(),
		Digest: policy.GetDigest(), CreatedBy: policy.GetCreatedBy(),
		Rules: make([]NetworkPolicyRule, 0, len(policy.GetRules()))}
	for _, rule := range policy.GetRules() {
		result.Rules = append(result.Rules, NetworkPolicyRule{Target: rule.GetTarget(), Ports: append([]uint32(nil), rule.GetPorts()...)})
	}
	return result, nil
}

func fromProtoEnvironmentNetworkPolicy(policy *codewirev1.EnvironmentNetworkPolicy) (*EnvironmentNetworkPolicy, error) {
	if policy == nil {
		return nil, fmt.Errorf("codewire: network policy response omitted network_policy")
	}
	enforcement, ok := map[codewirev1.NetworkPolicyEnforcement]string{
		codewirev1.NetworkPolicyEnforcement_NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED:  "not_enforced",
		codewirev1.NetworkPolicyEnforcement_NETWORK_POLICY_ENFORCEMENT_ENFORCED:      "enforced",
		codewirev1.NetworkPolicyEnforcement_NETWORK_POLICY_ENFORCEMENT_ENFORCING:     "enforcing",
		codewirev1.NetworkPolicyEnforcement_NETWORK_POLICY_ENFORCEMENT_FAILED_CLOSED: "failed_closed",
	}[policy.GetEnforcement()]
	if !ok {
		enforcement = "unknown"
	}
	var enforcedAt *string
	if policy.GetEnforcedAt() != nil {
		value := policy.GetEnforcedAt().AsTime().UTC().Format(time.RFC3339Nano)
		enforcedAt = &value
	}
	return &EnvironmentNetworkPolicy{Reference: policy.GetReference(), Name: policy.GetName(),
		Revision: policy.GetRevision(), Digest: policy.GetDigest(), Enforcement: enforcement,
		EnforcedRevision: policy.GetEnforcedRevision(), EnforcedDigest: policy.GetEnforcedDigest(),
		EnforcedAt: enforcedAt}, nil
}

// Create stores a policy at revision 1: from's current rules, or none, plus allow.
func (s *NetworkPolicyService) Create(ctx context.Context, name string, allow []NetworkPolicyRule, from *NetworkPolicySelector) (*NetworkPolicy, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	request := &codewirev1.CreateNetworkPolicyRequest{OrgId: orgID, Name: name, Allow: networkPolicyRules(allow)}
	if from != nil {
		if request.From, err = networkPolicySelector(*from); err != nil {
			return nil, err
		}
	}
	response, err := s.client.networkPolicies.CreateNetworkPolicy(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoNetworkPolicy(response.Msg.GetPolicy())
}

// List returns the organization's policies at their current revisions, by name.
func (s *NetworkPolicyService) List(ctx context.Context) ([]NetworkPolicy, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.networkPolicies.ListNetworkPolicies(ctx, connect.NewRequest(&codewirev1.ListNetworkPoliciesRequest{OrgId: orgID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	policies := make([]NetworkPolicy, 0, len(response.Msg.GetPolicies()))
	for _, policy := range response.Msg.GetPolicies() {
		value, err := fromProtoNetworkPolicy(policy)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *value)
	}
	return policies, nil
}

// Get returns a policy at revision, or at its current revision when revision is 0.
func (s *NetworkPolicyService) Get(ctx context.Context, policy NetworkPolicySelector, revision uint32) (*NetworkPolicy, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	selector, err := networkPolicySelector(policy)
	if err != nil {
		return nil, err
	}
	response, err := s.client.networkPolicies.GetNetworkPolicy(ctx, connect.NewRequest(&codewirev1.GetNetworkPolicyRequest{OrgId: orgID, Policy: selector, Revision: revision}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoNetworkPolicy(response.Msg.GetPolicy())
}

// Update makes a new revision: the current rules plus allow, minus the rules
// for remove. A nonzero expectedRevision refuses a concurrent change.
func (s *NetworkPolicyService) Update(ctx context.Context, policy NetworkPolicySelector, allow []NetworkPolicyRule, remove []string, expectedRevision uint32) (*NetworkPolicy, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	selector, err := networkPolicySelector(policy)
	if err != nil {
		return nil, err
	}
	response, err := s.client.networkPolicies.UpdateNetworkPolicy(ctx, connect.NewRequest(&codewirev1.UpdateNetworkPolicyRequest{
		OrgId: orgID, Policy: selector, Allow: networkPolicyRules(allow), Remove: remove, ExpectedRevision: expectedRevision}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoNetworkPolicy(response.Msg.GetPolicy())
}

// Delete removes a policy no environment selects and returns it as it was.
func (s *NetworkPolicyService) Delete(ctx context.Context, policy NetworkPolicySelector) (*NetworkPolicy, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	selector, err := networkPolicySelector(policy)
	if err != nil {
		return nil, err
	}
	response, err := s.client.networkPolicies.DeleteNetworkPolicy(ctx, connect.NewRequest(&codewirev1.DeleteNetworkPolicyRequest{OrgId: orgID, Policy: selector}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoNetworkPolicy(response.Msg.GetPolicy())
}

// Select sets an environment's policy; "hosted-default" removes the selection.
func (s *NetworkPolicyService) Select(ctx context.Context, environmentID, reference string) (*EnvironmentNetworkPolicy, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.networkPolicies.UpdateEnvironmentNetworkPolicy(ctx, connect.NewRequest(&codewirev1.UpdateEnvironmentNetworkPolicyRequest{
		OrgId: orgID, EnvironmentId: environmentID, NetworkPolicy: reference}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoEnvironmentNetworkPolicy(response.Msg.GetNetworkPolicy())
}
