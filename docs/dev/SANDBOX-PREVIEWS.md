# Sandbox previews

A preview is an HTTPS URL that forwards HTTP requests to an application's
internal Sandbox port. It is not a public TCP port mapping, and there is no
separate external port number to choose.

The creation page reads the deployment's public `preview_base_domain` from
`GetEnvironmentCreateOptions`. Before creation it shows a non-clickable pattern:
`https://{label}-{sandbox-id-prefix}-{organization-slug}.{preview_base_domain}`.
The five-character Sandbox ID prefix is assigned during creation. The Ports
dialog uses the exact URL returned by the API; Open and Copy share the same
validated HTTPS root address. Missing or malformed public configuration is
shown as unavailable, never replaced with a guessed deployment domain.

Preview access can be the Sandbox creator, organization members with Sandbox
access, or anyone with the URL. Creator-only access still exposes an
authenticated preview URL. Confidential policy can require authentication even
for a public preview. These settings do not determine whether an application
is listening inside the Sandbox.

The creation page explicitly submits its preview choice. Removing every row
sends `omit_application_previews: true` on `CreateEnvironmentRequest`, suppressing
preview defaults from both presets and repository configuration. That flag
requires an empty `project_spec.application_ports` list. Prepare preserves it
in returned drafts. Older clients omit the flag and retain default inheritance.
The flag controls creation-time defaults, not generic local-VM port bindings.

Internal ports must be distinct, in `1..65535`, and not runtime-reserved ports
`2222` or `2223`. Labels must be distinct and contain 2–22 lowercase letters,
digits or hyphens, with a letter or digit at either end. Empty access retains
the platform's creator-only default. Effective inherited previews are checked
before platform setup; database uniqueness remains the concurrency safeguard.

An empty preview list, or removing an existing entry, disables this HTTPS
preview mechanism only. It is not complete network isolation. Clipboard denial
does not report success: the dialog leaves the URL available for manual copying.
