package codewire

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
)

// The resolution order and the variables are specified in
// docs/dev/AUTH-POLICY.md, "Signing in from the environment". The Go SDK
// reads no .env file.

var (
	// ErrNoCredentials is returned, before any request, by every call of a
	// client that has neither an API key nor a user token.
	ErrNoCredentials = errors.New("codewire: no credentials: set CODEWIRE_API_KEY or CODEWIRE_JWT_TOKEN, or use WithAPIKey or WithJWTToken")
	// ErrUserTokenWithoutOrganization is returned, before any request, by
	// every call of a client with a user token and no organization.
	ErrUserTokenWithoutOrganization = errors.New("codewire: a user token needs an organization: set CODEWIRE_ORGANIZATION_ID or use WithOrganizationID")
)

var (
	organizationVariables = [2]string{"CODEWIRE_ORGANIZATION_ID", "CODEWIRE_ORG_ID"}
	serverVariables       = [2]string{"CODEWIRE_API_URL", "CODEWIRE_SERVER_URL"}
)

// codeSettings holds what the program passed to New and its options.
type codeSettings struct {
	apiKey, jwtToken, organizationID, apiURL string
}

type settings struct {
	bearer         string
	credential     string
	organizationID string
	apiURL         string
	// warnings are reported once each; they never contain a key or a token.
	warnings []string
}

// source is what one place sets; an empty value counts as unset.
type source struct {
	name                           string
	apiKey, jwtToken, organization string
	// organizationVariable set organization, for a source other than code.
	organizationVariable string
}

// resolveSettings reads code, then the environment through getenv. The
// credential comes as a unit from the first of them that sets a key or a
// token, the key winning within it; a key or token in the environment under
// a credential in code is ignored and reported. The organization comes from
// the highest source at or above the credential's that sets one; failing
// that, from the environment, which is reported. The error never contains a
// key or a token.
func resolveSettings(code codeSettings, getenv func(string) string) (settings, error) {
	firstOf := func(values ...string) string {
		for _, value := range values {
			if value != "" {
				return value
			}
		}
		return ""
	}
	ordered := []source{
		{name: "code", apiKey: code.apiKey, jwtToken: code.jwtToken, organization: code.organizationID},
		{
			name: "the environment", apiKey: getenv("CODEWIRE_API_KEY"), jwtToken: getenv("CODEWIRE_JWT_TOKEN"),
			organization: firstOf(getenv(organizationVariables[0]), getenv(organizationVariables[1])),
		},
	}
	for _, variable := range organizationVariables {
		if getenv(variable) != "" {
			ordered[1].organizationVariable = variable
			break
		}
	}
	resolved := settings{
		apiURL: strings.TrimRight(firstOf(code.apiURL, getenv(serverVariables[0]), getenv(serverVariables[1])), "/"),
	}
	if resolved.apiURL == "" {
		resolved.apiURL = DefaultBaseURL
	}
	chosen := -1
	for index, each := range ordered {
		if each.apiKey != "" || each.jwtToken != "" {
			chosen = index
			break
		}
	}
	if chosen < 0 {
		return resolved, ErrNoCredentials
	}
	credential := ordered[chosen]
	for _, lower := range ordered[chosen+1:] {
		for _, set := range []struct{ variable, value string }{
			{"CODEWIRE_API_KEY", lower.apiKey}, {"CODEWIRE_JWT_TOKEN", lower.jwtToken},
		} {
			if set.value != "" {
				resolved.warnings = append(resolved.warnings,
					"codewire: ignored "+set.variable+" in "+lower.name+": the credential comes from "+credential.name)
			}
		}
	}
	for _, each := range ordered[:chosen+1] {
		if resolved.organizationID = each.organization; resolved.organizationID != "" {
			break
		}
	}
	if resolved.organizationID == "" {
		for _, lower := range ordered[chosen+1:] {
			if lower.organization != "" {
				resolved.organizationID = lower.organization
				resolved.warnings = append(resolved.warnings, "codewire: used "+lower.organizationVariable+" in "+
					lower.name+": the credential in "+credential.name+" sets no organization")
				break
			}
		}
	}
	if credential.apiKey != "" {
		resolved.bearer, resolved.credential = credential.apiKey, "api key"
		return resolved, nil
	}
	if resolved.organizationID == "" {
		return resolved, ErrUserTokenWithoutOrganization
	}
	resolved.bearer, resolved.credential = credential.jwtToken, "user token"
	return resolved, nil
}

var (
	reportedMu sync.Mutex
	reported   = map[string]bool{}
)

// reportOnce writes each warning once per process through the standard log
// package, which writes to stderr unless the program redirected it.
func reportOnce(warnings []string) {
	reportedMu.Lock()
	defer reportedMu.Unlock()
	for _, warning := range warnings {
		if !reported[warning] {
			reported[warning] = true
			log.Print(warning)
		}
	}
}

// refusingTransport answers every request with the client's settings error
// without sending anything.
type refusingTransport struct{ err error }

func (t refusingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		_ = request.Body.Close() // RoundTrip owns the body; nothing is sent.
	}
	return nil, t.err
}

// settingsError returns the settings error err carries, if any.
func settingsError(err error) error {
	for _, refusal := range []error{ErrNoCredentials, ErrUserTokenWithoutOrganization} {
		if errors.Is(err, refusal) {
			return refusal
		}
	}
	return nil
}
