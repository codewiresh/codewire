package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestJoinPageEscapesInvite guards against reflected XSS via the `invite`
// query parameter. Prior to the fix, an attacker-controlled `?invite=<script>`
// was interpolated directly into the HTML response.
func TestJoinPageEscapesInvite(t *testing.T) {
	handler := joinPageHandler("https://relay.example.com")

	req := httptest.NewRequest(http.MethodGet, `/?invite=<script>alert(1)</script>`, nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("join page reflected raw script tag: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("join page did not HTML-escape invite value: %s", body)
	}
}

// TestJoinPageEscapesBaseURL covers the defensive escaping of the
// server-configured BaseURL — even though it's not user-controlled, an
// operator typo that included an ampersand or angle bracket should not
// produce broken HTML.
func TestJoinPageEscapesBaseURL(t *testing.T) {
	handler := joinPageHandler("https://relay.example.com/?x=<y>&z")

	req := httptest.NewRequest(http.MethodGet, "/?invite=abc", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "x=<y>&z") {
		t.Fatalf("join page did not escape baseURL: %s", body)
	}
	if !strings.Contains(body, "x=&lt;y&gt;&amp;z") {
		t.Fatalf("expected escaped baseURL in output: %s", body)
	}
}
