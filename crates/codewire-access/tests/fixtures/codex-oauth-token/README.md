# Codex OAuth token endpoint fixtures

The exchange between Codex inside an environment and the front door's answer
at `POST https://auth.openai.com/oauth/token` when the refresh token is
Codewire's managed marker (#6197). Tests in more than one crate, and
`scripts/ci/verify/codex-login-compat.py`, read these files; change them
only together with the behaviour they describe.

- `refresh-request.json`: the body Codex 0.160.0 sends to refresh its
  ChatGPT sign-in, with `content-type: application/json` and no
  `authorization` header: exactly these three members. Its `refresh_token`
  is the marker Codewire writes into `auth.json`,
  `codewire-managed-no-refresh-token`. Codex refreshes when the login's
  `last_refresh` is more than eight days old, and after its provider answers
  401.
- `refresh-response.json`: the shape of the 200 `application/json` answer,
  exactly the three members Codex reads. The values in angle brackets are
  shapes, not literals:
  - `id_token` is the unsigned placeholder ID token the login file holds,
    with the same allow-listed claims;
  - `access_token` is this environment's credential placeholder for its
    Codex slot: `cwp1_` and 43 base64url characters.

  `refresh_token` is literal: the marker again, never a nonce form, since
  the daemon knows the file as Codewire's by it.
