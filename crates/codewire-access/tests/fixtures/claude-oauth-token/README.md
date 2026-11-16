# Claude OAuth token endpoint fixtures

The exchange between Claude Code inside an environment and the front door's
answer at `POST https://platform.claude.com/v1/oauth/token` when the refresh
token is Codewire's managed marker (#3999, change 7a). Tests in more than one
crate read these files; change them only together with the behaviour they
describe.

- `refresh-request.json`: the body Claude Code 2.1.308 sends to refresh its
  sign-in, with `content-type: application/json` and no `authorization`
  header. Its `refresh_token` is a managed marker:
  `codewire-managed-no-refresh-token-` followed by exactly 32 lowercase
  hexadecimal characters. Any marker of that form is answered; the requested
  `scope` is accepted whatever it says and never copied into the answer.
- `refresh-response.json`: the shape of the 200 `application/json` answer.
  The values in angle brackets are shapes, not literals:
  - `access_token` is this environment's credential placeholder for its
    Anthropic slot: `cwp1_` and 43 base64url characters;
  - `refresh_token` is a new managed marker with a fresh random nonce;
  - `scope` is the stored sign-in's granted scopes joined with single
    spaces, never more than were granted.

  `expires_in` (315360000) and `token_type` (`Bearer`) are literal. The
  answer has exactly these five members.
