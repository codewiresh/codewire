//! Startup client provisioning.
//!
//! The idp ensures the built-in **desktop** client exists on boot (matching
//! the Go `EnsureDesktopClient`). The relay client is provisioned by its own
//! registration path — not the idp's responsibility.

use sqlx::PgPool;

/// Upsert the `codewire-desktop` public client (idempotent; refreshes the
/// redirect URIs + grant types on conflict, exactly as the Go provider does).
/// Lifetimes match Go: 720h access (= the desktop session), 2160h refresh,
/// 1h id_token.
pub async fn ensure_desktop_client(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO oidc_clients
            (id, name, application_type, auth_method, redirect_uris,
             grant_types, response_types, scopes, skip_consent,
             access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
        VALUES (
            'codewire-desktop', 'Codewire Desktop', 'native', 'none',
            ARRAY['http://localhost:9876/callback'],
            ARRAY['authorization_code', 'refresh_token'],
            ARRAY['code'],
            ARRAY['openid', 'profile', 'email', 'offline_access'],
            true,
            interval '720 hours', interval '2160 hours', interval '1 hour'
        )
        ON CONFLICT (id) DO UPDATE SET
            redirect_uris = EXCLUDED.redirect_uris,
            grant_types = EXCLUDED.grant_types,
            updated_at = NOW()
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Upsert the public CLI OAuth client used by the RFC 8628 device grant.
///
/// Conflict updates are deliberate: an older registration must converge its
/// grant and scope allowlists rather than silently retaining a capability that
/// cannot complete the CLI's flavor-2 login.
pub async fn ensure_cli_client(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO oidc_clients
            (id, name, application_type, auth_method, redirect_uris,
             grant_types, response_types, scopes, skip_consent,
             access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
        VALUES (
            'codewire-cli', 'Codewire CLI', 'native', 'none', ARRAY[]::text[],
            ARRAY['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
            ARRAY['code'],
            ARRAY['openid', 'profile', 'email', 'offline_access', 'codewire.api'],
            true,
            interval '720 hours', interval '2160 hours', interval '1 hour'
        )
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            application_type = EXCLUDED.application_type,
            auth_method = EXCLUDED.auth_method,
            redirect_uris = EXCLUDED.redirect_uris,
            grant_types = EXCLUDED.grant_types,
            response_types = EXCLUDED.response_types,
            scopes = EXCLUDED.scopes,
            skip_consent = EXCLUDED.skip_consent,
            access_token_lifetime = EXCLUDED.access_token_lifetime,
            refresh_token_lifetime = EXCLUDED.refresh_token_lifetime,
            id_token_lifetime = EXCLUDED.id_token_lifetime,
            updated_at = NOW()
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}
