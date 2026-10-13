package codewire_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
)

type githubRepositoryFixture struct {
	codewirev1connect.UnimplementedGithubRepositoryServiceHandler
	calls []*codewirev1.ListGithubRepositoriesRequest
}

func (f *githubRepositoryFixture) ListGithubRepositories(_ context.Context, request *connect.Request[codewirev1.ListGithubRepositoriesRequest]) (*connect.Response[codewirev1.ListGithubRepositoriesResponse], error) {
	f.calls = append(f.calls, request.Msg)
	return connect.NewResponse(&codewirev1.ListGithubRepositoriesResponse{Repositories: []*codewirev1.GithubRepository{{
		RepositoryId: "42", FullName: "owner/private", DefaultBranch: "main", CloneUrl: "https://github.com/owner/private.git", IsPrivate: true,
	}}, NextPageToken: "opaque-next"}), nil
}

func TestGithubRepositoriesExactCredentialAndAllowlistedMetadata(t *testing.T) {
	fixture := &githubRepositoryFixture{}
	path, handler := codewirev1connect.NewGithubRepositoryServiceHandler(fixture)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-opaque-oauth" || r.URL.Path != path+"ListGithubRepositories" {
			t.Error("wrong exact generated service path or account authorization")
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL))
	page, err := client.Credentials.ListGithubRepositories(context.Background(), 50, "opaque-page")
	if err != nil {
		t.Fatal(err)
	}
	want := &codewire.GithubRepositoryPage{Repositories: []codewire.GithubRepository{{RepositoryID: "42", FullName: "owner/private",
		DefaultBranch: "main", CloneURL: "https://github.com/owner/private.git", IsPrivate: true}}, NextPageToken: "opaque-next"}
	if !reflect.DeepEqual(page, want) {
		t.Fatalf("wrong allowlisted metadata: %#v", page)
	}
	request := fixture.calls[0]
	if request.PageSize != 50 || request.PageToken != "opaque-page" {
		t.Fatal("selected owner/page changed")
	}
	for _, invalid := range []struct {
		size  int32
		token string
	}{{101, ""}, {50, strings.Repeat("x", 129)}} {
		if _, err := client.Credentials.ListGithubRepositories(context.Background(), invalid.size, invalid.token); err == nil {
			t.Fatal("invalid page accepted")
		}
	}
	if len(fixture.calls) != 1 {
		t.Fatal("invalid selection called the provider or advanced the profile")
	}
}

func (f *githubRepositoryFixture) ListGithubPendingPermissions(_ context.Context, _ *connect.Request[codewirev1.ListGithubPendingPermissionsRequest]) (*connect.Response[codewirev1.ListGithubPendingPermissionsResponse], error) {
	return connect.NewResponse(&codewirev1.ListGithubPendingPermissionsResponse{PendingPermissions: []*codewirev1.GithubAppPendingPermissions{
		{Account: "octo-org", InstallationId: 43, AccountKind: codewirev1.GithubAppAccountKind_GITHUB_APP_ACCOUNT_KIND_ORGANIZATION},
		{Account: "octo-ent", InstallationId: 1<<64 - 1, AccountKind: codewirev1.GithubAppAccountKind_GITHUB_APP_ACCOUNT_KIND_ENTERPRISE},
		{Account: "unknown", InstallationId: 1},
	}}), nil
}

func TestGithubPendingPermissionsKeepLoginIDAndKindOnly(t *testing.T) {
	path, handler := codewirev1connect.NewGithubRepositoryServiceHandler(&githubRepositoryFixture{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-opaque-oauth" || r.URL.Path != path+"ListGithubPendingPermissions" {
			t.Error("wrong exact generated service path or account authorization")
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL))
	pending, err := client.Credentials.ListGithubPendingPermissions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []codewire.GithubPendingPermissions{
		{Account: "octo-org", InstallationID: 43, AccountKind: "organization"},
		{Account: "octo-ent", InstallationID: 1<<64 - 1, AccountKind: "enterprise"},
	}
	if !reflect.DeepEqual(pending, want) {
		t.Fatalf("wrong pending installations: %#v", pending)
	}
}
