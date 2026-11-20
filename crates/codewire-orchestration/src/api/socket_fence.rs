//! The dashboard's terminal and the SSH proxy's WebSocket on the revocation
//! fence (#3586; `docs/dev/AUTH-POLICY.md`, "Account access revocation"): a
//! socket is admitted by the credential its handshake carried, and closes
//! with 1008, "access revoked", when that credential is lost.

use std::future::Future;
use std::pin::Pin;

use axum::extract::ws::{CloseFrame, Message};
use axum::http::{HeaderMap, StatusCode};
use codewire_server_core::AppError;
use codewire_server_core::auth::{AuthState, AuthUser, authenticate_headers_with_context};
use codewire_server_core::revocation::{Admitted, Fence, Refused, StreamSite, record_revoked};
use sqlx::PgPool;

/// The close a revoked socket sends.
pub(crate) fn access_revoked_close() -> Message {
    Message::Close(Some(CloseFrame {
        code: 1008,
        reason: "access revoked".into(),
    }))
}

/// The user a socket's handshake admitted, the credential that admitted it,
/// and the check it re-reads once when it registers.
pub(crate) struct SocketAdmission {
    pub(crate) user: AuthUser,
    admitted: Admitted,
    recheck: Recheck,
}

enum Recheck {
    /// The handshake's headers, held only until the socket registers.
    Headers(HeaderMap),
    /// A ticket can be redeemed once; its session and user are read again.
    Ticket { session_id: String },
}

impl SocketAdmission {
    /// A socket admitted by a terminal ticket, which names the browser
    /// session that minted it.
    pub(crate) fn ticket(user: AuthUser, session_id: String) -> Self {
        Self {
            admitted: Admitted::session(&user.user_id, &session_id),
            user,
            recheck: Recheck::Ticket { session_id },
        }
    }

    /// A socket admitted by its handshake's session cookie, API key or OAuth
    /// bearer.
    pub(crate) async fn headers(auth: &AuthState, headers: &HeaderMap) -> Result<Self, AppError> {
        let authentication = authenticate_headers_with_context(auth, headers).await?;
        let admitted = Admitted::from_request(
            &authentication.user,
            &authentication.credential,
            authentication.oauth_bearer_authority(),
        )
        .ok_or(AppError::Unauthorized)?;
        Ok(Self {
            user: authentication.user,
            admitted,
            recheck: Recheck::Headers(headers.clone()),
        })
    }

    /// Registers the socket on the fence before it is upgraded, then re-reads
    /// its admission. After this only the credential's id or hash is held.
    pub(crate) async fn fence(
        self,
        auth: &AuthState,
        pool: &PgPool,
        fence: &Fence,
        site: StreamSite,
    ) -> Result<(AuthUser, SocketRevoked), StatusCode> {
        let Self {
            user,
            admitted,
            recheck,
        } = self;
        let recheck = async {
            match recheck {
                Recheck::Headers(headers) => {
                    match authenticate_headers_with_context(auth, &headers).await {
                        Ok(again)
                            if Admitted::from_request(
                                &again.user,
                                &again.credential,
                                again.oauth_bearer_authority(),
                            )
                            .as_ref()
                                == Some(&admitted) =>
                        {
                            Ok(())
                        }
                        Ok(_) | Err(AppError::Unauthorized | AppError::Forbidden) => {
                            Err(Refused::Revoked)
                        }
                        Err(_) => Err(Refused::Unavailable),
                    }
                }
                Recheck::Ticket { session_id } => {
                    ticket_session_live(pool, &session_id, admitted.user_id()).await
                }
            }
        };
        let watch =
            fence
                .admit(pool, &admitted, recheck)
                .await
                .map_err(|refused| match refused {
                    Refused::Revoked => StatusCode::UNAUTHORIZED,
                    Refused::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                })?;
        let pool = pool.clone();
        let revoked = Box::pin(async move {
            let mut watch = watch;
            let revocation = watch.revoked().await;
            record_revoked(&pool, &admitted, revocation, &site).await;
        });
        Ok((user, SocketRevoked(revoked)))
    }
}

/// Completes when the socket's credential is lost, after recording it. The
/// registration ends when this is dropped with the socket.
pub(crate) struct SocketRevoked(Pin<Box<dyn Future<Output = ()> + Send>>);

impl SocketRevoked {
    pub(crate) fn into_future(self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.0
    }
}

/// What redeeming the ticket required, read again after registering: its
/// session still live and its user still enabled.
async fn ticket_session_live(
    pool: &PgPool,
    session_id: &str,
    user_id: &str,
) -> Result<(), Refused> {
    let live: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM sessions AS session \
         JOIN users AS user_account ON user_account.id = session.user_id \
         WHERE session.id = $1 AND session.user_id = $2 \
           AND session.expires_at > NOW() AND user_account.enabled",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        tracing::warn!(%error, "terminal ticket session re-read failed");
        Refused::Unavailable
    })?;
    live.map(|_| ()).ok_or(Refused::Revoked)
}

/// Where a socket on `surface` into `environment_id` ran.
pub(crate) fn site(surface: &'static str, environment_id: &str) -> StreamSite {
    StreamSite {
        surface,
        environment_id: Some(environment_id.to_owned()),
    }
}

#[cfg(test)]
mod database_tests;
