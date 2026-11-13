//! `cw org` membership and invitation commands against a synthetic platform
//! (#3840, #3847): accepting by invitation id, never a token; listing and
//! removing members; and the inviter's report of the invitation email.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use codewire_client::{self as rpc, InvitationEmailStatus};
use wiremock::matchers::{body_bytes, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::*;

const LIST_MINE: &str = "/codewire.v1.OrganizationService/ListMyInvitations";
const ACCEPT: &str = "/codewire.v1.OrganizationService/AcceptInvitation";
const LIST_MEMBERS: &str = "/codewire.v1.OrganizationService/ListMembers";
const REMOVE: &str = "/codewire.v1.OrganizationService/RemoveMember";
const LIST_INVITATIONS: &str = "/codewire.v1.OrganizationService/ListInvitations";
const CREATE_INVITATION: &str = "/codewire.v1.OrganizationService/CreateInvitation";

fn client(server: &MockServer) -> OrganizationClient {
    OrganizationClient::new(&config::ResolvedPlatformConfig::static_token(
        server.uri(),
        "synthetic-org-token",
        true,
        None,
    ))
    .unwrap()
}

fn proto(body: impl buffa::Message) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/proto")
        .set_body_bytes(body.encode_to_vec())
}

fn refusal(code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(400)
        .insert_header("content-type", "application/json")
        .set_body_json(serde_json::json!({ "code": code, "message": message }))
}

fn invitation(id: &str, slug: &str, name: &str) -> rpc::OrgInvitation {
    rpc::OrgInvitation {
        id: id.into(),
        org_id: format!("org_{slug}"),
        org_name: name.into(),
        org_slug: slug.into(),
        email: "invitee@example.test".into(),
        role: rpc::OrgRole::Admin.into(),
        status: rpc::InvitationStatus::Pending.into(),
        expires_at: Some(rpc::Timestamp {
            seconds: 1_795_000_000,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

async fn mine(server: &MockServer, invitations: Vec<rpc::OrgInvitation>) {
    Mock::given(method("POST"))
        .and(path(LIST_MINE))
        .respond_with(proto(rpc::ListMyInvitationsResponse {
            invitations,
            ..Default::default()
        }))
        .mount(server)
        .await;
}

fn accept_request(invitation_id: &str) -> Vec<u8> {
    buffa::Message::encode_to_vec(&rpc::AcceptInvitationRequest {
        invitation_id: invitation_id.into(),
        ..Default::default()
    })
}

/// `cw org accept` names the organization by slug, ID or name (ignoring
/// case) and accepts by invitation id alone: the request carries no token.
#[tokio::test]
async fn accepting_resolves_the_organization_and_sends_only_the_invitation_id() {
    let server = MockServer::start().await;
    mine(
        &server,
        vec![
            invitation("inv_acme", "acme", "Acme Labs"),
            invitation("inv_beta", "beta", "Beta"),
        ],
    )
    .await;
    Mock::given(method("POST"))
        .and(path(ACCEPT))
        .and(body_bytes(accept_request("inv_acme")))
        .respond_with(proto(rpc::AcceptInvitationResponse {
            org_id: "org_acme".into(),
            ..Default::default()
        }))
        .expect(3)
        .mount(&server)
        .await;

    for org in ["acme", "org_acme", "acme labs"] {
        assert_eq!(
            accept(&client(&server), org).await.unwrap(),
            "Joined Acme Labs (acme) as admin.",
            "{org}"
        );
    }
}

/// An unverified address is told plainly to verify it, then run the same
/// command again.
#[tokio::test]
async fn an_unverified_address_is_told_to_verify_and_retry() {
    let server = MockServer::start().await;
    mine(&server, vec![invitation("inv_acme", "acme", "Acme Labs")]).await;
    Mock::given(method("POST"))
        .and(path(ACCEPT))
        .respond_with(refusal(
            "failed_precondition",
            "verify your email address, then accept the invitation again",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let error = accept(&client(&server), "acme").await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "your email address is not verified; verify it first (follow the link in Codewire's verification email), then run `cw org accept acme` again"
    );
}

/// With nothing pending, or nothing that matches, the command says so and
/// lists what is pending; it never calls AcceptInvitation.
#[tokio::test]
async fn nothing_pending_or_no_match_is_said_and_accepts_nothing() {
    let server = MockServer::start().await;
    mine(&server, Vec::new()).await;
    Mock::given(method("POST"))
        .and(path(ACCEPT))
        .respond_with(proto(rpc::AcceptInvitationResponse::default()))
        .expect(0)
        .mount(&server)
        .await;
    let none = accept(&client(&server), "acme").await.unwrap_err();
    assert!(
        none.to_string()
            .starts_with("no pending invitation to \"acme\": you have no pending invitations."),
        "{none}"
    );
    assert!(none.to_string().contains("verified email address"));

    let pending = [
        PendingInvitation {
            id: "inv_beta".into(),
            org_name: "Beta".into(),
            org_slug: "beta".into(),
            role: "member".into(),
            expires_at: "2026-11-19T10:00:00Z".into(),
            ..Default::default()
        },
        PendingInvitation {
            id: "inv_gamma".into(),
            org_name: "Beta".into(),
            org_slug: "beta-two".into(),
            role: "admin".into(),
            ..Default::default()
        },
    ];
    let unmatched = select_invitation(&pending, "acme").unwrap_err().to_string();
    assert!(
        unmatched.starts_with("no pending invitation to \"acme\". Your pending invitations:\n"),
        "{unmatched}"
    );
    assert!(unmatched.contains("beta-two"), "{unmatched}");
    let ambiguous = select_invitation(&pending, "beta ").unwrap();
    assert_eq!(ambiguous.id, "inv_beta", "an exact slug wins over names");
    let several = select_invitation(&pending, "BETA")
        .err()
        .unwrap()
        .to_string();
    assert_eq!(
        several,
        "\"BETA\" names 2 pending invitations; name one by slug: beta, beta-two"
    );
}

fn member(user: &str, email: &str, role: rpc::OrgRole) -> rpc::OrgMember {
    rpc::OrgMember {
        id: format!("member_{user}"),
        org_id: "org_acme".into(),
        user_id: user.into(),
        email: email.into(),
        role: role.into(),
        assignments: vec!["viewer".into()],
        ..Default::default()
    }
}

async fn members(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(LIST_MEMBERS))
        .respond_with(proto(rpc::ListMembersResponse {
            members: vec![
                member("user_owner", "owner@example.test", rpc::OrgRole::Owner),
                member("user_ada", "Ada@Example.test", rpc::OrgRole::Member),
            ],
            ..Default::default()
        }))
        .mount(server)
        .await;
}

fn remove_request(user: &str) -> Vec<u8> {
    buffa::Message::encode_to_vec(&rpc::RemoveMemberRequest {
        org_id: "org_acme".into(),
        user_id: user.into(),
        ..Default::default()
    })
}

/// `cw org member rm` names the member by user ID or by email ignoring case,
/// asks first, and removes nothing when declined.
#[tokio::test]
async fn removal_resolves_the_member_and_asks_first() {
    let server = MockServer::start().await;
    members(&server).await;
    Mock::given(method("POST"))
        .and(path(REMOVE))
        .and(body_bytes(remove_request("user_ada")))
        .respond_with(proto(rpc::RemoveMemberResponse::default()))
        .expect(2)
        .mount(&server)
        .await;
    let client = client(&server);

    let mut asked = Vec::new();
    let declined = remove_member(&client, "org_acme", "ada@example.test", |member| {
        asked.push((member.email.clone(), member.role.clone()));
        Ok(false)
    })
    .await
    .unwrap();
    assert_eq!(declined, None);
    assert_eq!(
        asked,
        [("Ada@Example.test".to_owned(), "member".to_owned())]
    );

    for user in ["ADA@example.test", "user_ada"] {
        let removed = remove_member(&client, "org_acme", user, |_| Ok(true))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(removed.user_id, "user_ada");
    }

    let unknown = remove_member(&client, "org_acme", "nobody@example.test", |_| {
        panic!("nobody to confirm")
    })
    .await
    .unwrap_err();
    assert_eq!(
        unknown.to_string(),
        "no member \"nobody@example.test\" in this organization; `cw org members` lists them"
    );
}

/// The server, not the CLI, refuses to remove an owner, and its reason is
/// what the user reads.
#[tokio::test]
async fn the_servers_refusal_to_remove_an_owner_is_shown() {
    let server = MockServer::start().await;
    members(&server).await;
    Mock::given(method("POST"))
        .and(path(REMOVE))
        .and(body_bytes(remove_request("user_owner")))
        .respond_with(refusal("invalid_argument", "cannot remove the owner"))
        .expect(1)
        .mount(&server)
        .await;

    let error = remove_member(&client(&server), "org_acme", "owner@example.test", |_| {
        Ok(true)
    })
    .await
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "remove member: cannot remove the owner"
    );
}

#[test]
fn members_and_invitations_read_as_tables_and_json() {
    let listed = [Member {
        user_id: "user_ada".into(),
        email: "ada@example.test".into(),
        name: Some("Ada".into()),
        role: "admin".into(),
        assignments: vec!["viewer".into()],
        joined_at: "2026-11-01T10:00:00Z".into(),
    }];
    assert_eq!(
        format_members_text(&listed),
        format!(
            "{:<32} {:<24} {:<8} USER ID\n{:<32} {:<24} {:<8} user_ada\n",
            "EMAIL", "NAME", "ROLE", "ada@example.test", "Ada", "admin"
        )
    );
    let json = serde_json::to_value(&listed).unwrap();
    assert_eq!(json[0]["user_id"], "user_ada");
    assert_eq!(json[0]["joined_at"], "2026-11-01T10:00:00Z");

    let pending = [PendingInvitation {
        id: "inv_acme".into(),
        org_id: "org_acme".into(),
        org_name: "Acme Labs".into(),
        org_slug: "acme".into(),
        role: "admin".into(),
        inviter_name: None,
        expires_at: "2026-11-19T10:00:00Z".into(),
    }];
    assert_eq!(
        format_pending_invitations_text(&pending),
        format!(
            "{:<24} {:<24} {:<8} EXPIRES\n{:<24} {:<24} {:<8} 2026-11-19T10:00:00Z\n",
            "ORGANIZATION", "SLUG", "ROLE", "Acme Labs", "acme", "admin"
        )
    );
    assert_eq!(
        format_pending_invitations_text(&[]),
        "No pending invitations. Invitations are listed only for a verified email address.\n"
    );
    let json = serde_json::to_value(&pending).unwrap();
    assert_eq!(json[0]["org_slug"], "acme");
    assert!(json[0].get("inviter_name").is_none());
}

/// Answers each request with the next response, then repeats the last.
struct Sequence(Mutex<VecDeque<ResponseTemplate>>);

impl Respond for Sequence {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let mut responses = self.0.lock().unwrap();
        if responses.len() > 1 {
            responses.pop_front().unwrap()
        } else {
            responses.front().cloned().unwrap()
        }
    }
}

fn listed(status: InvitationEmailStatus, error: &str) -> ResponseTemplate {
    proto(rpc::ListInvitationsResponse {
        invitations: vec![
            invitation("inv_other", "acme", "Acme Labs"),
            rpc::OrgInvitation {
                email_status: status.into(),
                email_error: error.into(),
                ..invitation("inv_new", "acme", "Acme Labs")
            },
        ],
        ..Default::default()
    })
}

async fn observe(responses: Vec<ResponseTemplate>, window: Duration) -> InvitationEmail {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LIST_INVITATIONS))
        .respond_with(Sequence(Mutex::new(responses.into())))
        .mount(&server)
        .await;
    client(&server)
        .invitation_email_with_policy("org_acme", "inv_new", Duration::from_millis(5), window)
        .await
}

/// The inviter's report follows the email's observed outcome: it waits while
/// the email is pending, stops at sent or failed, and after the bounded
/// wait says whether an attempt already failed.
#[tokio::test]
async fn the_invitation_email_outcome_is_observed() {
    let hang_guard = Duration::from_secs(30);
    assert_eq!(
        observe(
            vec![
                listed(InvitationEmailStatus::Pending, ""),
                listed(InvitationEmailStatus::Pending, ""),
                listed(InvitationEmailStatus::Sent, "")
            ],
            hang_guard
        )
        .await,
        InvitationEmail::Sent
    );
    assert_eq!(
        observe(
            vec![
                listed(InvitationEmailStatus::Pending, ""),
                listed(
                    InvitationEmailStatus::Failed,
                    "email delivery is not configured on this server"
                )
            ],
            hang_guard
        )
        .await,
        InvitationEmail::NotSent {
            reason: "email delivery is not configured on this server".into()
        }
    );
    assert_eq!(
        observe(
            vec![listed(
                InvitationEmailStatus::Skipped,
                "the invitation was revoked before its email was sent"
            )],
            hang_guard
        )
        .await,
        InvitationEmail::NotSent {
            reason: "the invitation was revoked before its email was sent".into()
        }
    );
    let short = Duration::from_millis(50);
    assert_eq!(
        observe(
            vec![listed(
                InvitationEmailStatus::Pending,
                "SES email request failed"
            )],
            short
        )
        .await,
        InvitationEmail::Retrying {
            reason: "SES email request failed".into()
        }
    );
    assert_eq!(
        observe(vec![listed(InvitationEmailStatus::Pending, "")], short).await,
        InvitationEmail::Queued
    );
    assert_eq!(
        observe(
            vec![listed(InvitationEmailStatus::Unspecified, "")],
            hang_guard
        )
        .await,
        InvitationEmail::NotOffered
    );
    assert_eq!(
        observe(
            vec![refusal(
                "permission_denied",
                "only owner or admin can view invitations"
            )],
            hang_guard
        )
        .await,
        InvitationEmail::Unknown {
            reason: "only owner or admin can view invitations".into()
        }
    );
}

/// A server that queues the email says so when the invitation is created,
/// and only then does the CLI wait for it; an older server is not asked.
#[tokio::test]
async fn the_cli_waits_only_when_the_server_queued_an_email() {
    for (status, queued) in [
        (InvitationEmailStatus::Pending, true),
        (InvitationEmailStatus::Unspecified, false),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_INVITATION))
            .respond_with(proto(rpc::CreateInvitationResponse {
                invitation: Some(rpc::OrgInvitation {
                    email_status: status.into(),
                    ..invitation("inv_new", "acme", "Acme Labs")
                })
                .into(),
                token: "synthetic-invitation-capability".into(),
                ..Default::default()
            }))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(LIST_INVITATIONS))
            .respond_with(listed(InvitationEmailStatus::Sent, ""))
            .expect(u64::from(queued))
            .mount(&server)
            .await;
        let client = client(&server);
        let created = client
            .create_invitation(
                "org_acme",
                &CreateInvitationRequest {
                    email: "invitee@example.test".into(),
                    role: "admin".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(created.email_queued, queued);
        let report = report_invitation_email(&client, "org_acme", &created).await;
        let expected = if queued {
            "Invitation email sent to invitee@example.test. The link also works; the link is shown only once."
        } else {
            "Share the link; the link is shown only once."
        };
        assert_eq!(report, expected);
    }
}

#[test]
fn each_email_outcome_reads_as_one_plain_line() {
    let email = "invitee@example.test";
    for (outcome, expected) in [
        (
            InvitationEmail::NotSent {
                reason: "email delivery is not configured on this server".into(),
            },
            "Email not sent: email delivery is not configured on this server; share the link instead. The link is shown only once.",
        ),
        (
            InvitationEmail::Retrying {
                reason: "SES email request failed with HTTP 503 (Throttling)".into(),
            },
            "Email not sent yet: SES email request failed with HTTP 503 (Throttling); it will be retried. Share the link if it does not arrive; the link is shown only once.",
        ),
        (
            InvitationEmail::Queued,
            "The invitation email to invitee@example.test is not sent yet; share the link if it does not arrive. The link is shown only once.",
        ),
        (
            InvitationEmail::Unknown {
                reason: "session expired or invalid".into(),
            },
            "Could not check the invitation email (session expired or invalid); share the link if it does not arrive. The link is shown only once.",
        ),
    ] {
        assert_eq!(invitation_email_message(email, &outcome), expected);
    }
}

#[test]
fn the_membership_commands_parse() {
    let parse = |argv: &[&str]| match crate::Cli::try_parse_from(argv).unwrap().command {
        crate::Command::Org { command } => command.unwrap(),
        _ => panic!("not an org command"),
    };
    assert!(matches!(
        parse(&["cw", "org", "invitations", "--output", "json"]),
        OrgCommand::Invitations(OrgInvitationsArgs {
            output: OutputFormat::Json
        })
    ));
    assert!(matches!(
        parse(&["cw", "org", "accept", "acme"]),
        OrgCommand::Accept(OrgAcceptArgs { org }) if org == "acme"
    ));
    assert!(matches!(
        parse(&["cw", "org", "members", "--org", "acme"]),
        OrgCommand::Members(OrgMembersArgs { org: Some(org), output: OutputFormat::Text }) if org == "acme"
    ));
    for verb in ["rm", "remove"] {
        assert!(matches!(
            parse(&["cw", "org", "member", verb, "ada@example.test", "--yes"]),
            OrgCommand::Member {
                command: OrgMemberCommand::Rm(OrgMemberRmArgs { user, org: None, yes: true })
            } if user == "ada@example.test"
        ));
    }
    assert!(crate::Cli::try_parse_from(["cw", "org", "accept"]).is_err());
}
