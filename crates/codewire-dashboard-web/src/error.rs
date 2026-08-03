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
