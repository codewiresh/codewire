use axum::http::{HeaderValue, header};

use super::*;

const ID: &str = "00000000-0000-4000-8000-000000000021";
const HTTPS: &str = "https://codewire.example.test";

#[test]
fn a_submission_is_a_new_sign_in_or_an_exact_reconnect() {
    assert_eq!(target("", None), Some((NEW_DIALOG.to_owned(), None)));
    assert_eq!(
        target(ID, Some(3)),
        Some((
            format!("credential-{ID}-reconnect"),
            Some((ID.to_owned(), 3))
        ))
    );
    for (id, generation) in [
        (ID, None),
        ("", Some(3)),
        (ID, Some(0)),
        (ID, Some(i64::MAX as u64)),
        ("not-an-id", Some(3)),
    ] {
        assert_eq!(target(id, generation), None, "{id} {generation:?}");
    }
}

#[test]
fn the_handle_cookie_is_strict_http_only_secure_and_scoped_to_the_two_actions() {
    let cookie = claude_sign_in_cookie(HTTPS, "cwcs2.1800000000.0a1b", 900).unwrap();
    assert_eq!(
        cookie,
        "__Secure-codewire_claude_sign_in=cwcs2.1800000000.0a1b; \
         Path=/settings/credentials/_actions/credentials/claude-sign-in/; \
         HttpOnly; SameSite=Strict; Max-Age=900; Secure"
    );
    assert_eq!(
        clear_claude_sign_in_cookie(HTTPS),
        "__Secure-codewire_claude_sign_in=; \
         Path=/settings/credentials/_actions/credentials/claude-sign-in/; \
         HttpOnly; SameSite=Strict; Max-Age=0; Secure"
    );
    // A local http origin cannot set a __Secure- cookie, so it uses the plain name.
    assert!(
        claude_sign_in_cookie("http://localhost:4174", "cwcs2.1.ab", 900)
            .unwrap()
            .starts_with("codewire_claude_sign_in=cwcs2.1.ab; ")
    );
    assert!(claude_sign_in_cookie(HTTPS, "cwcs2.1; Path=/", 900).is_none());
}

#[test]
fn only_the_one_handle_for_this_origin_is_read_back() {
    let mut headers = HeaderMap::new();
    let read = |headers: &HeaderMap| claude_sign_in_handle(headers, HTTPS).map(str::to_owned);
    assert_eq!(read(&headers), None);
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("a=b; __Secure-codewire_claude_sign_in=cwcs2.1.ab"),
    );
    assert_eq!(read(&headers).as_deref(), Some("cwcs2.1.ab"));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("codewire_claude_sign_in=cwcs2.1.ab"),
    );
    assert_eq!(read(&headers), None);
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static(
            "__Secure-codewire_claude_sign_in=cwcs2.1.ab; __Secure-codewire_claude_sign_in=cwcs2.2.cd",
        ),
    );
    assert_eq!(read(&headers), None);
}

#[test]
fn the_sign_ins_messages_and_errors_are_closed_and_static() {
    for code in ["claude-sign-in-added", "claude-sign-in-reconnected"] {
        assert!(!approved_message(code).is_empty(), "{code}");
        assert!(approved_error(code).is_empty(), "{code}");
    }
    for code in [
        "claude-code-invalid",
        "claude-code-refused",
        "claude-sign-in-expired",
    ] {
        assert!(!approved_error(code).is_empty(), "{code}");
    }
    assert!(approved_error("anything-else").is_empty());
    assert!(approved_message("anything-else").is_empty());
}

mod rendered {
    use super::super::super::tests::{page_view, render_view};
    use super::*;
    use crate::credentials_connect::CredentialSettingsData;
    use crate::view::{CredentialChoicesView, CredentialRowView};

    const URL: &str = "https://claude.com/cai/oauth/authorize?code=true&state=synthetic";

    fn sign_in_row() -> CredentialRowView {
        CredentialRowView {
            id: ID.into(),
            name: "Work Claude".into(),
            kind: "Claude",
            account_hint: "person@example.test".into(),
            status: "Active",
            status_tone: "success",
            expires: String::new(),
            generation: 3,
            ssh_public_key: String::new(),
            ssh_fingerprint: String::new(),
            public_key_id: "public-key-1".into(),
            api_key: false,
            oauth: false,
            subscription_token: false,
            claude_sign_in: true,
            reconnect_needed: false,
            revoked: false,
            oauth_provider: "",
        }
    }

    fn data() -> CredentialSettingsData {
        CredentialSettingsData {
            credentials: vec![sign_in_row()],
            profiles: Vec::new(),
            choices: CredentialChoicesView::default(),
        }
    }

    /// One dialog's markup, from its opening tag to its close.
    fn dialog(html: &str, id: &str) -> String {
        let start = html
            .find(&format!(
                "<dialog class=\"cw-dialog cw-credential-dialog\" data-dialog id=\"{id}\""
            ))
            .unwrap_or_else(|| panic!("no dialog {id}"));
        let end = start + html[start..].find("</dialog>").unwrap();
        html[start..end].to_owned()
    }

    fn rendered(dialog_id: &str, error: &str, step: Option<&str>) -> String {
        let mut page = page_view(dialog_id, error, data(), "?org=sample-org", "Work Claude");
        page.claude_sign_in_code = step.is_some();
        page.claude_sign_in_url = step.unwrap_or_default().into();
        render_view(&page)
    }

    #[test]
    fn the_sign_in_is_offered_before_the_subscription_token() {
        let html = rendered("", "", None);
        let sign_in = html
            .find("id=\"add-claude-sign-in-choice-name\">Connect Claude<")
            .unwrap();
        let token = html
            .find("id=\"add-claude-subscription-token-choice-name\">Claude (token)<")
            .unwrap();
        assert!(sign_in < token);
        assert!(html.contains("Your subscription; lasts a year, for automation."));
    }

    #[test]
    fn the_name_step_starts_the_sign_in_and_asks_for_no_code() {
        let add = dialog(&rendered(NEW_DIALOG, "", None), NEW_DIALOG);
        assert!(add.contains("data-dialog-auto-open"));
        assert!(add.contains(
            "action=\"/settings/credentials/_actions/credentials/claude-sign-in/start?org=sample-org\""
        ));
        assert!(add.contains("name=\"name\" autofocus maxlength=\"256\" value=\"Work Claude\""));
        assert!(add.contains(">Continue</button>"));
        assert!(!add.contains("name=\"code\""));
        assert!(!add.contains("name=\"credential_id\""));
    }

    #[test]
    fn a_started_sign_in_links_claude_in_a_new_tab_and_takes_the_code_unechoed() {
        let add = dialog(&rendered(NEW_DIALOG, "", Some(URL)), NEW_DIALOG);
        assert!(add.contains(
            "<a class=\"cw-link-button\" href=\"https://claude.com/cai/oauth/authorize?code=true&#38;state=synthetic\" target=\"_blank\" rel=\"noopener noreferrer\">Open Claude to sign in</a>"
        ));
        assert!(add.contains(
            "action=\"/settings/credentials/_actions/credentials/claude-sign-in/complete?org=sample-org\""
        ));
        assert!(add.contains("<input type=\"hidden\" name=\"name\" value=\"Work Claude\">"));
        assert!(add.contains(
            "name=\"code\" type=\"password\" data-dialog-private maxlength=\"8200\" autocomplete=\"off\""
        ));
        assert!(!add.contains("value=\"cwcs"));
        assert!(add.contains(">Connect Claude</button>"));
        assert!(!add.contains("role=\"alert\""));
    }

    #[test]
    fn a_misshapen_paste_reopens_the_code_step_without_the_link() {
        let html = rendered(NEW_DIALOG, approved_error("claude-code-invalid"), Some(""));
        let add = dialog(&html, NEW_DIALOG);
        assert!(add.contains("role=\"alert\">That isn&#39;t the code Claude shows;"));
        assert!(!add.contains("Open Claude to sign in"));
        assert!(add.contains("name=\"code\""));
    }

    #[test]
    fn a_sign_in_row_reconnects_its_exact_identity() {
        let id = format!("credential-{ID}-reconnect");
        let html = rendered(&id, "", None);
        assert!(html.contains(&format!("data-dialog-open=\"{id}\" aria-haspopup=\"dialog\" aria-controls=\"{id}\">Reconnect</button>")));
        let reconnect = dialog(&html, &id);
        assert!(reconnect.contains("data-dialog-auto-open"));
        assert!(reconnect.contains("Reconnect Work Claude</h2>"));
        assert!(reconnect.contains(&format!(
            "<input type=\"hidden\" name=\"credential_id\" value=\"{ID}\">"
        )));
        assert!(reconnect.contains(
            "<input type=\"hidden\" name=\"expected_revocation_generation\" value=\"3\">"
        ));
        assert!(!reconnect.contains("name=\"confirm_reconnect\""));
        let mut page = page_view(&id, "", data(), "", "");
        page.claude_sign_in_code = true;
        let step = dialog(&render_view(&page), &id);
        assert!(step.contains(&format!(
            "<input type=\"hidden\" name=\"credential_id\" value=\"{ID}\">"
        )));
        assert!(step.contains("name=\"code\""));
    }
}
