//! Every field marked `debug_redact` is kept out of `Debug` output (#4950).
//!
//! The generated `Debug` redacts a field only if the descriptor set the code
//! was generated from still carries the field's `debug_redact` option. A
//! protobuf compiler that drops the option produces code that compiles,
//! passes every test that prints no secret, and logs the secret. So this
//! reads the marked fields from the descriptor set, puts a marker in each
//! one, and looks for it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use buffa::{HasMessageView, Message};
use buffa_descriptor::generated::descriptor::field_descriptor_proto::{Label, Type};
use buffa_descriptor::generated::descriptor::{DescriptorProto, FileDescriptorSet};
use codewire_proto::codewire::{bridge, internal, v1};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const MARKER: &str = "synthetic-debug-redact-canary";
/// `MARKER` as proto3 JSON carries a `bytes` field. `check` proves the two
/// agree: the marker must be in the message's wire bytes.
const MARKER_BASE64: &str = "c3ludGhldGljLWRlYnVnLXJlZGFjdC1jYW5hcnk=";

/// One marked field, and a proto3 JSON message that holds the marker in it.
struct Marked {
    message: String,
    field: String,
    json: Value,
}

fn descriptor_set() -> FileDescriptorSet {
    FileDescriptorSet::decode_from_slice(codewire_proto::FILE_DESCRIPTOR_SET)
        .expect("decode the built descriptor set")
}

/// Every message of the set by its full name, nested ones included.
fn messages(set: &FileDescriptorSet) -> BTreeMap<String, &DescriptorProto> {
    fn add<'a>(
        prefix: &str,
        message: &'a DescriptorProto,
        all: &mut BTreeMap<String, &'a DescriptorProto>,
    ) {
        let name = format!("{prefix}.{}", message.name.as_deref().unwrap_or_default());
        for nested in &message.nested_type {
            add(&name, nested, all);
        }
        all.insert(name, message);
    }
    let mut all = BTreeMap::new();
    for file in &set.file {
        let package = file.package.as_deref().unwrap_or_default();
        for message in &file.message_type {
            add(package, message, &mut all);
        }
    }
    all
}

fn marked_fields(set: &FileDescriptorSet) -> Vec<Marked> {
    let messages = messages(set);
    let mut marked = Vec::new();
    for (name, message) in &messages {
        for field in &message.field {
            if field.options.debug_redact != Some(true) {
                continue;
            }
            let repeated = field.label == Some(Label::LABEL_REPEATED);
            let value = match field.r#type {
                Some(Type::TYPE_STRING) => json!(MARKER),
                Some(Type::TYPE_BYTES) => json!(MARKER_BASE64),
                Some(Type::TYPE_MESSAGE) => {
                    let nested = field.type_name.as_deref().unwrap_or_default();
                    let nested = messages
                        .get(nested.trim_start_matches('.'))
                        .unwrap_or_else(|| panic!("{name}: no message {nested}"));
                    // A map is a repeated entry message on the wire and one
                    // object in JSON; the only marked one maps strings.
                    assert!(
                        nested.options.map_entry == Some(true),
                        "{name}: a marked message field that is not a map has no case here"
                    );
                    marked.push(Marked {
                        message: name.clone(),
                        field: field.name.clone().unwrap_or_default(),
                        json: json!({
                            field.json_name.as_deref().unwrap_or_default(): { "KEY": MARKER }
                        }),
                    });
                    continue;
                }
                other => panic!("{name}: a marked field of type {other:?} has no case here"),
            };
            let value = if repeated { json!([value]) } else { value };
            marked.push(Marked {
                message: name.clone(),
                field: field.name.clone().unwrap_or_default(),
                json: json!({ field.json_name.as_deref().unwrap_or_default(): value }),
            });
        }
    }
    marked
}

fn assert_redacted(rendered: &str, what: &str) {
    assert!(
        rendered.contains("[REDACTED]"),
        "{what}: `Debug` shows no redaction: {rendered}"
    );
    assert!(
        !rendered.contains(MARKER),
        "{what}: `Debug` prints the value"
    );
    assert!(
        !rendered.contains(&format!("{:?}", MARKER.as_bytes())),
        "{what}: `Debug` prints the value's bytes"
    );
}

fn check<T>(marked: &Marked)
where
    T: Default + Debug + DeserializeOwned + Message + HasMessageView,
    for<'a> T::View<'a>: Debug,
{
    let what = format!("{}.{}", marked.message, marked.field);
    let message: T = serde_json::from_value(marked.json.clone())
        .unwrap_or_else(|error| panic!("{what}: {} is not that message: {error}", marked.json));
    let wire = message.encode_to_vec();
    assert!(
        wire.windows(MARKER.len())
            .any(|window| window == MARKER.as_bytes()),
        "{what}: the marker did not reach the message"
    );
    assert_redacted(&format!("{message:?}"), &what);
    let view = T::decode_view(&wire).expect("decode the message's view");
    assert_redacted(&format!("{view:?}"), &format!("{what} (view)"));
}

type Check = fn(&Marked);

macro_rules! cases {
    ($($name:literal => $message:ty,)*) => {
        BTreeMap::from([$(($name, check::<$message> as Check),)*])
    };
}

/// A message type for every message that has a marked field.
#[rustfmt::skip]
fn cases() -> BTreeMap<&'static str, Check> {
    cases! {
        "codewire.bridge.v1.ClaudeLoginResponse" => bridge::v1::ClaudeLoginResponse,
        "codewire.bridge.v1.CodexLoginResponse" => bridge::v1::CodexLoginResponse,
        "codewire.bridge.v1.CredentialSshSignRequest" => bridge::v1::CredentialSshSignRequest,
        "codewire.bridge.v1.CredentialSshSignature" => bridge::v1::CredentialSshSignature,
        "codewire.internal.v1.BindWorkspaceResponse" => internal::v1::BindWorkspaceResponse,
        "codewire.internal.v1.CoordinateProof" => internal::v1::CoordinateProof,
        "codewire.internal.v1.GitIdentity" => internal::v1::GitIdentity,
        "codewire.internal.v1.IssueMeshEnrollmentResponse" => internal::v1::IssueMeshEnrollmentResponse,
        "codewire.internal.v1.RedeemEnvironmentEnrollmentRequest" => internal::v1::RedeemEnvironmentEnrollmentRequest,
        "codewire.internal.v1.WorkspaceAccess" => internal::v1::WorkspaceAccess,
        "codewire.internal.v1.WorkspaceDefaults" => internal::v1::WorkspaceDefaults,
        "codewire.v1.AcceptInvitationRequest" => v1::AcceptInvitationRequest,
        "codewire.v1.AddApiKeyCredentialRequest" => v1::AddApiKeyCredentialRequest,
        "codewire.v1.AddClaudeSubscriptionTokenCredentialRequest" => v1::AddClaudeSubscriptionTokenCredentialRequest,
        "codewire.v1.AddSshCredentialRequest" => v1::AddSshCredentialRequest,
        "codewire.v1.CodexDeviceChallenge" => v1::CodexDeviceChallenge,
        "codewire.v1.CompleteClaudeSignInRequest" => v1::CompleteClaudeSignInRequest,
        "codewire.v1.CompleteGithubAppAuthorizationRequest" => v1::CompleteGithubAppAuthorizationRequest,
        "codewire.v1.CreateApiKeyResponse" => v1::CreateApiKeyResponse,
        "codewire.v1.CreateInvitationResponse" => v1::CreateInvitationResponse,
        "codewire.v1.CreateMeshInviteResponse" => v1::CreateMeshInviteResponse,
        "codewire.v1.DelegateCredentialsResponse" => v1::DelegateCredentialsResponse,
        "codewire.v1.CreateMeshNodeEnrollmentResponse" => v1::CreateMeshNodeEnrollmentResponse,
        "codewire.v1.GetInvitationByTokenRequest" => v1::GetInvitationByTokenRequest,
        "codewire.v1.GithubDeviceChallenge" => v1::GithubDeviceChallenge,
        "codewire.v1.HostTunnelReady" => v1::HostTunnelReady,
        "codewire.v1.JoinMeshNetworkRequest" => v1::JoinMeshNetworkRequest,
        "codewire.v1.MeshKeyValue" => v1::MeshKeyValue,
        "codewire.v1.OpenHostTunnelRequest" => v1::OpenHostTunnelRequest,
        "codewire.v1.OpenHostTunnelResponse" => v1::OpenHostTunnelResponse,
        "codewire.v1.RedeemMeshNodeEnrollmentRequest" => v1::RedeemMeshNodeEnrollmentRequest,
        "codewire.v1.RotateApiKeyCredentialRequest" => v1::RotateApiKeyCredentialRequest,
        "codewire.v1.SetMeshKeyValueRequest" => v1::SetMeshKeyValueRequest,
        "codewire.v1.SetProjectSecretRequest" => v1::SetProjectSecretRequest,
        "codewire.v1.SetSecretRequest" => v1::SetSecretRequest,
        "codewire.v1.SetUserSecretRequest" => v1::SetUserSecretRequest,
        "codewire.v1.StartClaudeSignInResponse" => v1::StartClaudeSignInResponse,
        "codewire.v1.SubmitFeedbackRequest" => v1::SubmitFeedbackRequest,
    }
}

#[test]
fn the_descriptor_set_keeps_every_redaction_mark_the_protos_carry() {
    let in_the_protos: usize = env!("CODEWIRE_PROTO_DEBUG_REDACT_MARKS")
        .parse()
        .expect("a count from the build script");
    let in_the_set = marked_fields(&descriptor_set()).len();
    assert!(in_the_protos > 0, "the protos mark no field");
    assert!(
        in_the_set >= in_the_protos,
        "the protos mark {in_the_protos} fields and the descriptor set {in_the_set}"
    );
}

#[test]
fn every_marked_field_is_redacted_in_debug_output() {
    let set = descriptor_set();
    let marked = marked_fields(&set);
    let cases = cases();
    let with_marks: BTreeSet<&str> = marked.iter().map(|field| field.message.as_str()).collect();
    assert_eq!(
        with_marks,
        cases.keys().copied().collect::<BTreeSet<_>>(),
        "the messages with a marked field, against the cases here"
    );
    for field in &marked {
        cases[field.message.as_str()](field);
    }
}
