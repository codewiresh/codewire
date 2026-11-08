---
title: OpenSSF security posture
description: Codewire's OpenSSF Scorecard and Best Practices status, with links to the authoritative results.
updated: 2026-11-08
weight: 5
---

This page reports the security posture of the
[`codewiresh/codewire`](https://github.com/codewiresh/codewire) source
repository. For the boundaries that protect Codewire environments and
credentials, see the [security model](@/reference/security.md).

## What is OpenSSF?

The [Open Source Security Foundation](https://openssf.org/) (OpenSSF) runs two
complementary assessments of open-source projects:

- **Scorecard** automatically checks repository supply-chain practices such as
  branch protection, dependency pinning, signed releases, static analysis and
  vulnerability handling.
- The **Best Practices badge** is a maintainer self-certification, assisted by
  automated checks, against a broader set of security and quality criteria.

Neither assessment is a security audit or a guarantee. The links beside each
result let you inspect the evidence and verify it at the authoritative source.

## OpenSSF Scorecard report

{{ security_posture() }}

## Actively hardening

Security posture is ongoing work, not a one-time score. We track gaps against
these checks and address them through the normal development process. A low
score is a prompt to inspect the check's evidence and remediation guidance, not
a verdict on the whole project.

Found a vulnerability? Follow the
[security policy](https://github.com/codewiresh/codewire/security/policy) to
report it privately. Disclosed issues are published as
[security advisories](https://github.com/codewiresh/codewire/security/advisories).
