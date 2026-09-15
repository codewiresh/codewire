package codewire

import (
	"context"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	credentialConverterCoverageOnce sync.Once
	credentialConverterCoverageErr  error
)

// SSHPublicKey is public registration metadata; private key bytes never have a
// credential metadata representation.
type SSHPublicKey struct {
	OpenSSH     string `json:"openssh"`
	Fingerprint string `json:"fingerprint"`
}

// Credential is personal platform metadata, without a provider token or store reference.
type Credential struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	Provider             string        `json:"provider"`
	AuthenticationKind   string        `json:"authentication_kind"`
	AccountHint          *string       `json:"account_hint,omitempty"`
	Status               string        `json:"status"`
	ExpiresAtUnix        *uint64       `json:"expires_at_unix,omitempty"`
	RevocationGeneration uint64        `json:"revocation_generation"`
	SSHPublicKey         *SSHPublicKey `json:"ssh_public_key,omitempty"`
}

// CodexDeviceChallenge contains a one-time code for the requesting user, never routine logs.
type CodexDeviceChallenge struct {
	VerificationURL string `json:"verification_url"`
	UserCode        string `json:"user_code"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
}

// EnrollmentOutcomeUnknownError means that storage may have occurred. Reconcile
// by name before retrying; this error never triggers provider logout/revocation.
type EnrollmentOutcomeUnknownError struct{}

func (*EnrollmentOutcomeUnknownError) Error() string {
	return "codewire: Codex enrollment acknowledgement is unknown; reconcile the credential by name before retrying"
}

// CredentialService manages the authenticated personal account's credentials.
// Supply a user OAuth bearer, not an organization API key. Enrollment and
// lifecycle require OAuth even when metadata permits an account session.
// No method chooses a delivery mode or fetches and retries a stale mutation.
type CredentialService struct{ client *Client }

// GithubRepository is allowlisted metadata, never provider JSON or a checkout grant.
type GithubRepository struct {
	RepositoryID  string `json:"repository_id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	CloneURL      string `json:"clone_url"`
	IsPrivate     bool   `json:"is_private"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
}

type GithubRepositoryPage struct {
	Repositories  []GithubRepository `json:"repositories"`
	NextPageToken string             `json:"next_page_token"`
}

// ListGithubRepositories fetches one page for the exact selected personal profile.
// It never advances the profile revision or attaches credentials to an environment.
func (s *CredentialService) ListGithubRepositories(ctx context.Context, profileID string, profileRevision uint64, pageSize int32, pageToken string) (*GithubRepositoryPage, error) {
	if err := ensureCredentialConverterCoverage(); err != nil {
		return nil, err
	}
	if profileID == "" || profileRevision == 0 || pageSize < 0 || pageSize > 100 || len(pageToken) > 128 {
		return nil, fmt.Errorf("codewire: invalid GitHub repository selection or page")
	}
	response, err := s.client.githubRepositories.ListGithubRepositories(ctx, connect.NewRequest(&codewirev1.ListGithubRepositoriesRequest{
		ProfileId: profileID, ProfileRevision: profileRevision, PageSize: pageSize, PageToken: pageToken,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	page := &GithubRepositoryPage{Repositories: make([]GithubRepository, 0, len(response.Msg.Repositories)), NextPageToken: response.Msg.NextPageToken}
	for _, value := range response.Msg.Repositories {
		if value == nil {
			return nil, fmt.Errorf("codewire: missing GitHub repository metadata")
		}
		page.Repositories = append(page.Repositories, GithubRepository{
			RepositoryID: value.RepositoryId, FullName: value.FullName, DefaultBranch: value.DefaultBranch,
			CloneURL: value.CloneUrl, IsPrivate: value.IsPrivate, Archived: value.Archived, Disabled: value.Disabled,
		})
	}
	return page, nil
}

// Bounded admission/cleanup room around the server's original 15-minute limit.
// This does not change the timeout of any ordinary SDK request.
const credentialEnrollmentTimeout = 16 * time.Minute

func credentialGeneration(value uint64) error {
	if value == 0 {
		return fmt.Errorf("codewire: credential revision must be a positive uint64")
	}
	return nil
}

func fromProtoCredential(value *codewirev1.Credential) (*Credential, error) {
	if err := ensureCredentialConverterCoverage(); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("codewire: credential response omitted credential")
	}
	if err := credentialGeneration(value.GetRevocationGeneration()); err != nil {
		return nil, err
	}
	kinds := map[codewirev1.CredentialAuthenticationKind]string{
		codewirev1.CredentialAuthenticationKind_CREDENTIAL_AUTHENTICATION_KIND_OAUTH:        "oauth",
		codewirev1.CredentialAuthenticationKind_CREDENTIAL_AUTHENTICATION_KIND_API_KEY:      "api_key",
		codewirev1.CredentialAuthenticationKind_CREDENTIAL_AUTHENTICATION_KIND_ACCESS_TOKEN: "access_token",
		codewirev1.CredentialAuthenticationKind_CREDENTIAL_AUTHENTICATION_KIND_GITHUB_APP:   "github_app",
		codewirev1.CredentialAuthenticationKind_CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY:      "ssh_key",
	}
	statuses := map[codewirev1.CredentialStatus]string{
		codewirev1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE:         "active",
		codewirev1.CredentialStatus_CREDENTIAL_STATUS_REVOKED:        "revoked",
		codewirev1.CredentialStatus_CREDENTIAL_STATUS_EXPIRED:        "expired",
		codewirev1.CredentialStatus_CREDENTIAL_STATUS_REFRESH_FAILED: "refresh_failed",
	}
	kind, status := kinds[value.GetAuthenticationKind()], statuses[value.GetStatus()]
	if kind == "" || status == "" {
		return nil, fmt.Errorf("codewire: credential response contains unsupported metadata")
	}
	if (kind == "ssh_key") != (value.GetSshPublicKey() != nil) {
		return nil, fmt.Errorf("codewire: credential response contains inconsistent SSH metadata")
	}
	var sshPublicKey *SSHPublicKey
	if value.GetSshPublicKey() != nil {
		sshPublicKey = &SSHPublicKey{OpenSSH: value.GetSshPublicKey().GetOpenssh(), Fingerprint: value.GetSshPublicKey().GetFingerprint()}
	}
	return &Credential{ID: value.GetId(), Name: value.GetName(), Provider: value.GetProvider(),
		AuthenticationKind: kind, AccountHint: value.AccountHint, Status: status,
		ExpiresAtUnix: value.ExpiresAtUnix, RevocationGeneration: value.GetRevocationGeneration(), SSHPublicKey: sshPublicKey}, nil
}

func ensureCredentialConverterCoverage() error {
	credentialConverterCoverageOnce.Do(func() {
		messages := codewirev1.File_codewire_v1_credential_proto.Messages()
		credentialConverterCoverageErr = ensureDescriptorCoverage("credential metadata", messages.ByName("Credential"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "name", 3: "provider", 4: "authentication_kind", 5: "account_hint", 6: "status", 7: "expires_at_unix", 8: "revocation_generation", 9: "ssh_public_key",
		})
		if credentialConverterCoverageErr != nil {
			return
		}
		credentialConverterCoverageErr = ensureDescriptorCoverage("SSH public key", messages.ByName("SshPublicKey"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "openssh", 2: "fingerprint",
		})
		if credentialConverterCoverageErr != nil {
			return
		}
		credentialConverterCoverageErr = ensureDescriptorCoverage("GitHub repository", messages.ByName("GithubRepository"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "repository_id", 2: "full_name", 3: "default_branch", 4: "clone_url", 5: "is_private", 6: "archived", 7: "disabled",
		})
	})
	return credentialConverterCoverageErr
}

// List consumes every page with the server's default page size.
func (s *CredentialService) List(ctx context.Context) ([]Credential, error) {
	result := make([]Credential, 0)
	seen := make(map[string]bool)
	for pageToken := ""; ; {
		if seen[pageToken] {
			return nil, fmt.Errorf("codewire: credential pagination repeated a cursor")
		}
		seen[pageToken] = true
		response, err := s.client.credentials.ListCredentials(ctx, connect.NewRequest(&codewirev1.ListCredentialsRequest{PageToken: pageToken}))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, value := range response.Msg.GetCredentials() {
			credential, err := fromProtoCredential(value)
			if err != nil {
				return nil, err
			}
			result = append(result, *credential)
		}
		pageToken = response.Msg.GetNextPageToken()
		if pageToken == "" {
			return result, nil
		}
	}
}

// Get selects an exact credential ID, never guessing whether it is a name.
func (s *CredentialService) Get(ctx context.Context, id string) (*Credential, error) {
	return s.get(ctx, &codewirev1.GetCredentialRequest{Selector: &codewirev1.GetCredentialRequest_CredentialId{CredentialId: id}})
}

// GetByName selects an exact case-insensitive personal name.
func (s *CredentialService) GetByName(ctx context.Context, name string) (*Credential, error) {
	return s.get(ctx, &codewirev1.GetCredentialRequest{Selector: &codewirev1.GetCredentialRequest_Name{Name: name}})
}

func (s *CredentialService) get(ctx context.Context, request *codewirev1.GetCredentialRequest) (*Credential, error) {
	response, err := s.client.credentials.GetCredential(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoCredential(response.Msg.GetCredential())
}

// EnrollCodex delivers the challenge to onChallenge immediately, before waiting
// for committed metadata. The callback must return promptly and must not log the
// one-time code. A callback error or context cancellation closes this original
// stream, never starts another enrollment, and returns an uncertain outcome.
// Use a shorter parent context deadline to bound this call further.
func (s *CredentialService) EnrollCodex(ctx context.Context, name string, onChallenge func(CodexDeviceChallenge) error) (*Credential, error) {
	if onChallenge == nil {
		return nil, fmt.Errorf("codewire: a Codex device challenge callback is required")
	}
	ctx, cancel := context.WithTimeout(ctx, credentialEnrollmentTimeout)
	defer cancel()
	stream, err := s.client.credentialEnrollments.EnrollCodex(ctx, connect.NewRequest(&codewirev1.EnrollCodexRequest{Name: name}))
	if err != nil {
		return nil, &EnrollmentOutcomeUnknownError{}
	}
	defer stream.Close()
	challenged := false
	for stream.Receive() {
		switch event := stream.Msg().Event.(type) {
		case *codewirev1.EnrollCodexResponse_Challenge:
			value := event.Challenge
			if challenged || value == nil || value.GetVerificationUrl() == "" || value.GetUserCode() == "" || value.GetExpiresAtUnix() == 0 {
				return nil, &EnrollmentOutcomeUnknownError{}
			}
			challenged = true
			if err := onChallenge(CodexDeviceChallenge{VerificationURL: value.GetVerificationUrl(), UserCode: value.GetUserCode(), ExpiresAtUnix: value.GetExpiresAtUnix()}); err != nil {
				return nil, &EnrollmentOutcomeUnknownError{}
			}
		case *codewirev1.EnrollCodexResponse_Credential:
			if !challenged {
				return nil, &EnrollmentOutcomeUnknownError{}
			}
			credential, err := fromProtoCredential(event.Credential)
			if err != nil {
				return nil, &EnrollmentOutcomeUnknownError{}
			}
			return credential, nil
		default:
			return nil, &EnrollmentOutcomeUnknownError{}
		}
	}
	// Clean EOF, transport errors and cancellation all lack a storage ACK.
	return nil, &EnrollmentOutcomeUnknownError{}
}

// Revoke compares the caller's exact observed revision; conflicts are not retried.
func (s *CredentialService) Revoke(ctx context.Context, id string, expectedGeneration uint64) (*Credential, error) {
	if err := credentialGeneration(expectedGeneration); err != nil {
		return nil, err
	}
	response, err := s.client.credentialMutations.RevokeCredential(ctx, connect.NewRequest(&codewirev1.RevokeCredentialRequest{
		CredentialId: id, ExpectedRevocationGeneration: expectedGeneration}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoCredential(response.Msg.GetCredential())
}

// Delete forgets an already-revoked, unreferenced record; it is not provider logout.
func (s *CredentialService) Delete(ctx context.Context, id string, expectedGeneration uint64) error {
	if err := credentialGeneration(expectedGeneration); err != nil {
		return err
	}
	_, err := s.client.credentialMutations.DeleteCredential(ctx, connect.NewRequest(&codewirev1.DeleteCredentialRequest{
		CredentialId: id, ExpectedRevocationGeneration: expectedGeneration}))
	return connectSDKError(err)
}
