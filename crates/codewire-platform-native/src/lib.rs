#[cfg(feature = "legacy-core")]
pub mod async_storage;
#[cfg(feature = "legacy-core")]
pub mod http;
#[cfg(feature = "legacy-core")]
pub mod oauth;
#[cfg(feature = "legacy-core")]
pub mod secure_storage;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "legacy-core")]
pub mod storage;

#[cfg(feature = "legacy-core")]
pub use async_storage::TokioAsyncStorage;
#[cfg(feature = "legacy-core")]
pub use http::ReqwestHttpClient;
#[cfg(feature = "legacy-core")]
pub use oauth::NativeOAuthHandler;
#[cfg(feature = "legacy-core")]
pub use secure_storage::KeyringSecureStorage;
#[cfg(feature = "ssh")]
pub use ssh::{RusshClient, RusshSession, parse_ssh_config, parse_ssh_config_content};
#[cfg(feature = "legacy-core")]
pub use storage::FsPersistentStorage;
