package codewire

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EnvironmentIdentityGroups is a Sandbox's identity groups, sorted; a token
// names each as "<org id>:<group>" (#4663).
type EnvironmentIdentityGroups struct {
	EnvironmentID string   `json:"environment_id"`
	Groups        []string `json:"groups"`
	// Version is bumped on every change; 0 for a Sandbox whose groups were
	// never set.
	Version int64 `json:"version"`
	// UpdatedAt is RFC 3339, or nil for a Sandbox whose groups were never set.
	UpdatedAt *string `json:"updated_at,omitempty"`
}

// IdentityGroupUser is a member who can run code in a Sandbox, and so use its
// groups. Reason is "creator", "owner_grant", "operator_grant",
// "organization_admin", or "unknown" for a reason this SDK does not know yet.
type IdentityGroupUser struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// SetEnvironmentIdentityGroupsResult is a change of groups, with everyone who
// can run code in the Sandbox. Every process in it can use its groups too.
type SetEnvironmentIdentityGroupsResult struct {
	Groups         EnvironmentIdentityGroups `json:"groups"`
	PreviousGroups []string                  `json:"previous_groups"`
	// Changed is false when the new set equals the old one.
	Changed    bool                `json:"changed"`
	CanRunCode []IdentityGroupUser `json:"can_run_code"`
}

// IdentityAudience is a verifier the organization registered, in its
// canonical form.
type IdentityAudience struct {
	OrgID    string `json:"org_id"`
	Audience string `json:"audience"`
	// VisibleGroups is nil for every group; otherwise only these, and an
	// empty list sees none but "all".
	VisibleGroups        []string `json:"visible_groups"`
	LifetimeSeconds      int64    `json:"lifetime_seconds"`
	ClaimCreatedBy       bool     `json:"claim_created_by"`
	ClaimEnvironmentName bool     `json:"claim_environment_name"`
	FileName             *string  `json:"file_name,omitempty"`
	Version              int64    `json:"version"`
	CreatedBy            string   `json:"created_by"`
	CreatedAt            *string  `json:"created_at,omitempty"`
}

// RegisterIdentityAudienceOptions are a registration's choices. A nil
// VisibleGroups sees every group; a zero Lifetime is ten minutes.
type RegisterIdentityAudienceOptions struct {
	VisibleGroups        []string
	Lifetime             time.Duration
	ClaimCreatedBy       bool
	ClaimEnvironmentName bool
	FileName             string
}

// SandboxIdentityService manages sandbox identity's records: each Sandbox's
// groups, the organization's registered audiences, and the switches that stop
// minting. Changing any of them is for organization owners and admins.
type SandboxIdentityService struct{ client *Client }

func rfc3339(value *timestamppb.Timestamp) *string {
	if value == nil {
		return nil
	}
	formatted := value.AsTime().UTC().Format(time.RFC3339Nano)
	return &formatted
}

func fromProtoIdentityGroups(groups *codewirev1.EnvironmentIdentityGroups) (*EnvironmentIdentityGroups, error) {
	if groups == nil {
		return nil, fmt.Errorf("codewire: sandbox identity response omitted groups")
	}
	return &EnvironmentIdentityGroups{EnvironmentID: groups.GetEnvironmentId(),
		Groups: append([]string{}, groups.GetGroups()...), Version: groups.GetVersion(),
		UpdatedAt: rfc3339(groups.GetUpdatedAt())}, nil
}

func fromProtoIdentityAudience(audience *codewirev1.IdentityAudience) (*IdentityAudience, error) {
	if audience == nil {
		return nil, fmt.Errorf("codewire: sandbox identity response omitted audience")
	}
	result := &IdentityAudience{OrgID: audience.GetOrgId(), Audience: audience.GetAudience(),
		LifetimeSeconds: 600, ClaimCreatedBy: audience.GetClaimCreatedBy(),
		ClaimEnvironmentName: audience.GetClaimEnvironmentName(), FileName: audience.FileName,
		Version: audience.GetVersion(), CreatedBy: audience.GetCreatedBy(),
		CreatedAt: rfc3339(audience.GetCreatedAt())}
	if audience.GetVisibleGroups() != nil {
		result.VisibleGroups = append([]string{}, audience.GetVisibleGroups().GetNames()...)
	}
	if audience.GetLifetime() != nil {
		result.LifetimeSeconds = audience.GetLifetime().GetSeconds()
	}
	return result, nil
}

var identityGroupUserReasons = map[codewirev1.IdentityGroupUserReason]string{
	codewirev1.IdentityGroupUserReason_IDENTITY_GROUP_USER_REASON_CREATOR:            "creator",
	codewirev1.IdentityGroupUserReason_IDENTITY_GROUP_USER_REASON_OWNER_GRANT:        "owner_grant",
	codewirev1.IdentityGroupUserReason_IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT:     "operator_grant",
	codewirev1.IdentityGroupUserReason_IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN: "organization_admin",
}

// GetGroups returns a Sandbox's groups.
func (s *SandboxIdentityService) GetGroups(ctx context.Context, environmentID string) (*EnvironmentIdentityGroups, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.sandboxIdentity.GetEnvironmentIdentityGroups(ctx, connect.NewRequest(&codewirev1.GetEnvironmentIdentityGroupsRequest{
		OrgId: orgID, EnvironmentId: environmentID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoIdentityGroups(response.Msg.GetGroups())
}

// SetGroups replaces a Sandbox's groups; an empty list removes them all.
func (s *SandboxIdentityService) SetGroups(ctx context.Context, environmentID string, groups []string) (*SetEnvironmentIdentityGroupsResult, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.sandboxIdentity.SetEnvironmentIdentityGroups(ctx, connect.NewRequest(&codewirev1.SetEnvironmentIdentityGroupsRequest{
		OrgId: orgID, EnvironmentId: environmentID, Groups: groups}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	stored, err := fromProtoIdentityGroups(response.Msg.GetGroups())
	if err != nil {
		return nil, err
	}
	result := &SetEnvironmentIdentityGroupsResult{Groups: *stored,
		PreviousGroups: append([]string{}, response.Msg.GetPreviousGroups()...),
		Changed:        response.Msg.GetChanged(), CanRunCode: []IdentityGroupUser{}}
	for _, user := range response.Msg.GetCanRunCode() {
		reason, ok := identityGroupUserReasons[user.GetReason()]
		if !ok {
			reason = "unknown"
		}
		result.CanRunCode = append(result.CanRunCode, IdentityGroupUser{UserID: user.GetUserId(), Email: user.GetEmail(), Reason: reason})
	}
	return result, nil
}

// RegisterAudience registers a verifier. The server stores it in its
// canonical form, and refuses one its rules don't admit, naming the rule.
func (s *SandboxIdentityService) RegisterAudience(ctx context.Context, audience string, options RegisterIdentityAudienceOptions) (*IdentityAudience, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	request := &codewirev1.RegisterIdentityAudienceRequest{OrgId: orgID, Audience: audience,
		ClaimCreatedBy: options.ClaimCreatedBy, ClaimEnvironmentName: options.ClaimEnvironmentName}
	if options.VisibleGroups != nil {
		request.VisibleGroups = &codewirev1.IdentityAudienceGroups{Names: options.VisibleGroups}
	}
	if options.Lifetime != 0 {
		request.Lifetime = durationpb.New(options.Lifetime)
	}
	if options.FileName != "" {
		request.FileName = &options.FileName
	}
	response, err := s.client.sandboxIdentity.RegisterIdentityAudience(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoIdentityAudience(response.Msg.GetAudience())
}

// ListAudiences returns the organization's registrations, by audience.
func (s *SandboxIdentityService) ListAudiences(ctx context.Context) ([]IdentityAudience, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.sandboxIdentity.ListIdentityAudiences(ctx, connect.NewRequest(&codewirev1.ListIdentityAudiencesRequest{OrgId: orgID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	audiences := make([]IdentityAudience, 0, len(response.Msg.GetAudiences()))
	for _, audience := range response.Msg.GetAudiences() {
		value, err := fromProtoIdentityAudience(audience)
		if err != nil {
			return nil, err
		}
		audiences = append(audiences, *value)
	}
	return audiences, nil
}

// RemoveAudience removes a registration and returns the canonical audience
// removed.
func (s *SandboxIdentityService) RemoveAudience(ctx context.Context, audience string) (string, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return "", err
	}
	response, err := s.client.sandboxIdentity.RemoveIdentityAudience(ctx, connect.NewRequest(&codewirev1.RemoveIdentityAudienceRequest{
		OrgId: orgID, Audience: audience}))
	if err != nil {
		return "", connectSDKError(err)
	}
	return response.Msg.GetAudience(), nil
}

// StopMinting stops minting for one Sandbox, or the whole organization when
// environmentID is empty. It returns false when it was already stopped.
func (s *SandboxIdentityService) StopMinting(ctx context.Context, environmentID string) (bool, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return false, err
	}
	response, err := s.client.sandboxIdentity.StopIdentityMinting(ctx, connect.NewRequest(&codewirev1.StopIdentityMintingRequest{
		OrgId: orgID, EnvironmentId: environmentID}))
	if err != nil {
		return false, connectSDKError(err)
	}
	return response.Msg.GetChanged(), nil
}

// ResumeMinting resumes minting for one Sandbox, or the organization when
// environmentID is empty. It returns false when it was not stopped.
func (s *SandboxIdentityService) ResumeMinting(ctx context.Context, environmentID string) (bool, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return false, err
	}
	response, err := s.client.sandboxIdentity.ResumeIdentityMinting(ctx, connect.NewRequest(&codewirev1.ResumeIdentityMintingRequest{
		OrgId: orgID, EnvironmentId: environmentID}))
	if err != nil {
		return false, connectSDKError(err)
	}
	return response.Msg.GetChanged(), nil
}
