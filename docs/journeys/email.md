# Email

Every email Codewire sends, in one plain layout with a plain-text part, from
`Codewire <hello@codewire.sh>` (#4553). The layout's rules are in
[`docs/CONFIGURATION.md`](../CONFIGURATION.md), "Transactional email". The
journeys that send each email hold its own steps; this one checks how each
looks when it arrives.

Updated 2026-11-23.

| Email (preview name) | Sent when | Dev | Production |
| --- | --- | --- | --- |
| `idp-verification` | an email sign-up, or Resend verification email | not yet observed | not yet observed |
| `idp-access-request-received` | an access request's address is verified | not yet observed | not yet observed |
| `idp-access-enabled` | an admin enables an access request | not yet observed | not yet observed |
| `idp-password-reset` | Forgot password, for an account with a password | not yet observed | not yet observed |
| `idp-provider-sign-in` | Forgot password, for an account that signs in only with GitHub or Google | not yet observed | not yet observed |
| `idp-provider-linked` | GitHub or Google is linked at sign-in | not yet observed | not yet observed |
| `idp-provider-connected` | GitHub or Google is connected in Settings | not yet observed | not yet observed |
| `idp-provider-disconnected` | GitHub or Google is disconnected in Settings | not yet observed | not yet observed |
| `idp-provider-link-confirmation` | a provider sign-in matches an existing address | not yet observed | not yet observed |
| `idp-password-added` | a password is added to a provider-only account | not yet observed | not yet observed |
| `idp-two-factor-replaced`, `idp-two-factor-regenerated` | an authenticator is replaced, or recovery codes are made again | not yet observed | not yet observed |
| `idp-organization-invitation` | someone is invited to an organization | not yet observed | not yet observed |
| `idp-operator-access-request`, `idp-operator-more-waiting` | a sign-up, to the operator address (#5358) | not yet observed | a GitHub access request's notice observed 2026-11-21 at v0.4.26 (#5358); layout and text part not checked |
| `billing-receipt`, `billing-receipt-top-up` | a paid invoice, when billing sends receipts rather than Stripe (#4816) | not yet observed | Stripe sends Production's receipts |
| `billing-payment-failed` | a charge fails | not yet observed | not yet observed |
| `billing-credit-low`, `billing-credit-low-top-up` | the balance runs low | not yet observed | not yet observed |
| `billing-credit-exhausted`, `billing-credit-exhausted-unnamed` | the balance reaches €0 | not yet observed | not yet observed |
| `billing-account-deleted` | an account deletion completes | not yet observed | not yet observed |
| `billing-operator-credit-bought`, `billing-operator-more-purchases` | a paid credit purchase, to the operator address (#5358) | not yet observed | not yet observed |

## `email-look`: an email as it arrives

Issue: #4553.

- **Entry points:** the inbox the email was sent to. Each email is sent by
  the journey that owns its feature.
- **States to exercise:** one email of each kind in the table, in a desktop
  mail client and on a phone.
- **Driving it:** walk the journey that sends the email, then open it.
- **Proof:**
  - the From line reads `Codewire <hello@codewire.sh>` (on Dev,
    `Codewire <hello@codewire-dev.sh>`);
  - the body is a column no wider than 640 px, left-aligned, with at most one
    dark pill button, a thin rule and the grey footer saying why it was sent;
  - no images load, and there is no tracking pixel;
  - "Show original" has a `text/plain` part with the same words and every
    link written out, and the button's link works.
- **Gotchas:**
  - Feedback to the operator (#5466) is plain text only, by design.
  - To see every email without sending one:
    `EMAIL_PREVIEW_DIR=<dir> cargo test -p codewire-idp -p codewire-billing --lib write_email_previews -- --ignored`.
- **Observed:** see the table.
