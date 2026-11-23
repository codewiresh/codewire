package codewire

import (
	"bytes"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"
)

const (
	settingsKey   = "cw_synthetic_key"
	settingsToken = "synthetic-user-token"
)

// The sdk-config states the Go SDK has, from an explicit environment. Go
// reads no .env file, so the file states belong to Python and TypeScript.
func TestResolveSettings(t *testing.T) {
	everything := map[string]string{
		"CODEWIRE_API_KEY":         "cw_from_environment",
		"CODEWIRE_ORGANIZATION_ID": "org-environment",
		"CODEWIRE_API_URL":         "https://environment.example.test",
	}
	cases := []struct {
		name        string
		code        codeSettings
		environment map[string]string
		want        settings
		err         error
	}{
		{
			name:        "key only",
			environment: map[string]string{"CODEWIRE_API_KEY": settingsKey},
			want:        settings{bearer: settingsKey, credential: "api key", apiURL: DefaultBaseURL},
		},
		{
			name:        "token and organization",
			environment: map[string]string{"CODEWIRE_JWT_TOKEN": settingsToken, "CODEWIRE_ORGANIZATION_ID": "org-one"},
			want:        settings{bearer: settingsToken, credential: "user token", organizationID: "org-one", apiURL: DefaultBaseURL},
		},
		{
			name:        "CODEWIRE_ORG_ID alias",
			environment: map[string]string{"CODEWIRE_JWT_TOKEN": settingsToken, "CODEWIRE_ORG_ID": "org-alias"},
			want:        settings{bearer: settingsToken, credential: "user token", organizationID: "org-alias", apiURL: DefaultBaseURL},
		},
		{
			name: "the preferred organization name beats the alias",
			environment: map[string]string{
				"CODEWIRE_API_KEY": settingsKey, "CODEWIRE_ORGANIZATION_ID": "org-new", "CODEWIRE_ORG_ID": "org-old",
			},
			want: settings{bearer: settingsKey, credential: "api key", organizationID: "org-new", apiURL: DefaultBaseURL},
		},
		{
			name:        "both set uses the key",
			environment: map[string]string{"CODEWIRE_API_KEY": settingsKey, "CODEWIRE_JWT_TOKEN": settingsToken},
			want:        settings{bearer: settingsKey, credential: "api key", apiURL: DefaultBaseURL},
		},
		{
			name:        "neither is refused",
			environment: map[string]string{"CODEWIRE_ORGANIZATION_ID": "org-one", "CODEWIRE_API_KEY": ""},
			err:         ErrNoCredentials,
		},
		{
			name:        "a token without an organization is refused",
			environment: map[string]string{"CODEWIRE_JWT_TOKEN": settingsToken},
			err:         ErrUserTokenWithoutOrganization,
		},
		{
			name: "server aliases",
			environment: map[string]string{
				"CODEWIRE_API_KEY": settingsKey, "CODEWIRE_SERVER_URL": "https://server.example.test/",
			},
			want: settings{bearer: settingsKey, credential: "api key", apiURL: "https://server.example.test"},
		},
		{
			name: "CODEWIRE_API_URL beats CODEWIRE_SERVER_URL",
			environment: map[string]string{
				"CODEWIRE_API_KEY": settingsKey, "CODEWIRE_API_URL": "https://api.example.test",
				"CODEWIRE_SERVER_URL": "https://server.example.test",
			},
			want: settings{bearer: settingsKey, credential: "api key", apiURL: "https://api.example.test"},
		},
		{
			name:        "an organization in code always wins, even over the credential's source",
			code:        codeSettings{organizationID: "org-code"},
			environment: everything,
			want: settings{
				bearer: "cw_from_environment", credential: "api key", organizationID: "org-code",
				apiURL: "https://environment.example.test",
			},
		},
		{
			name: "either alias counts in the credential's source, with no report",
			environment: map[string]string{
				"CODEWIRE_JWT_TOKEN": settingsToken, "CODEWIRE_ORG_ID": "org-alias",
			},
			want: settings{bearer: settingsToken, credential: "user token", organizationID: "org-alias", apiURL: DefaultBaseURL},
		},
		{
			name:        "a key and server in code beat the environment, whose key is reported",
			code:        codeSettings{apiKey: "cw_from_code", apiURL: "https://code.example.test/"},
			environment: everything,
			want: settings{
				bearer: "cw_from_code", credential: "api key", organizationID: "org-environment",
				apiURL: "https://code.example.test",
				warnings: []string{
					"codewire: ignored CODEWIRE_API_KEY in the environment: the credential comes from code",
					"codewire: used CODEWIRE_ORGANIZATION_ID in the environment: the credential in code sets no organization",
				},
			},
		},
		{
			name:        "a token in code beats a key in the environment, which is reported",
			code:        codeSettings{jwtToken: settingsToken, organizationID: "org-code"},
			environment: everything,
			want: settings{
				bearer: settingsToken, credential: "user token", organizationID: "org-code",
				apiURL:   "https://environment.example.test",
				warnings: []string{"codewire: ignored CODEWIRE_API_KEY in the environment: the credential comes from code"},
			},
		},
		{
			name:        "a code credential without an organization uses the environment's, reported",
			code:        codeSettings{jwtToken: settingsToken},
			environment: map[string]string{"CODEWIRE_ORG_ID": "org-environment"},
			want: settings{
				bearer: settingsToken, credential: "user token", organizationID: "org-environment", apiURL: DefaultBaseURL,
				warnings: []string{"codewire: used CODEWIRE_ORG_ID in the environment: the credential in code sets no organization"},
			},
		},
		{
			name: "a token in code",
			code: codeSettings{jwtToken: settingsToken, organizationID: "org-code"},
			want: settings{bearer: settingsToken, credential: "user token", organizationID: "org-code", apiURL: DefaultBaseURL},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSettings(tc.code, func(name string) string { return tc.environment[name] })
			if !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
			if tc.err != nil {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("settings differ:\n got %+v\nwant %+v", got, tc.want)
			}
			for _, warning := range got.warnings {
				for _, value := range tc.environment {
					if strings.Contains(warning, value) && strings.HasPrefix(value, "cw_") {
						t.Fatalf("a report holds a value: %q", warning)
					}
				}
				if strings.Contains(warning, settingsToken) || strings.Contains(warning, "org-") {
					t.Fatalf("a report holds the token: %q", warning)
				}
			}
		})
	}
}

func TestSettingsRefusalsNameTheVariables(t *testing.T) {
	for _, want := range []string{"CODEWIRE_API_KEY", "CODEWIRE_JWT_TOKEN"} {
		if !strings.Contains(ErrNoCredentials.Error(), want) {
			t.Errorf("ErrNoCredentials does not name %s", want)
		}
	}
	if !strings.Contains(ErrUserTokenWithoutOrganization.Error(), "CODEWIRE_ORGANIZATION_ID") {
		t.Error("ErrUserTokenWithoutOrganization does not name CODEWIRE_ORGANIZATION_ID")
	}
}

func TestReportOnceWritesEachWarningOnceThroughLog(t *testing.T) {
	var written bytes.Buffer
	output, flags := log.Writer(), log.Flags()
	log.SetOutput(&written)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(output)
		log.SetFlags(flags)
	})
	warning := "codewire: ignored CODEWIRE_API_KEY in the environment: the credential comes from code (" + t.Name() + ")"
	reportOnce([]string{warning})
	reportOnce([]string{warning})
	if written.String() != warning+"\n" {
		t.Fatalf("log output = %q", written.String())
	}
}
