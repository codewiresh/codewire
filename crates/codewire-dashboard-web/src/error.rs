use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message as _;
use connectrpc::ConnectError;

#[derive(Debug)]
pub(crate) enum WebError {
    Unauthorized,
    TwoFactorRequired,
    NotFound,
    Forbidden,
    CsrfRejected,
    IdentityUnavailable,
    BrowserConfigurationUnavailable,
    Connect(ConnectError),
}

/// The Codewire reason a service attached to `error` as its one
/// `google.rpc.ErrorInfo` detail (`docs/dev/CONNECT-ERROR-MODEL.md`, D4), in
/// SCREAMING_SNAKE. `Ok(None)` when there is none; `Err` when the detail is
/// repeated, undecodable or not Codewire's, so a caller never trusts it.
pub(crate) fn codewire_reason(error: &ConnectError) -> Result<Option<String>, ()> {
    let mut details = error.details.iter().filter(|detail| {
        matches!(
            detail.type_url.as_str(),
            "google.rpc.ErrorInfo" | "type.googleapis.com/google.rpc.ErrorInfo"
        )
    });
    let Some(detail) = details.next() else {
        return Ok(None);
    };
    if details.next().is_some() {
        return Err(());
    }
    let encoded = detail.value.as_deref().ok_or(())?;
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| STANDARD.decode(encoded))
        .map_err(|_| ())?;
    let info = codewire_proto::google::rpc::ErrorInfo::decode_from_slice(&bytes).map_err(|_| ())?;
    if info.domain != "codewire.sh" || info.reason.is_empty() {
        return Err(());
    }
    Ok(Some(info.reason))
}
