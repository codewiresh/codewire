---
title: Isolation evidence
description: See how a hosted sandbox is isolated with cw report - its runtime, VM boundary, images by digest, and whether it makes a confidential computing claim.
updated: 2026-10-26
weight: 7
---

Every hosted sandbox runs in its own VM. `cw report` shows the evidence
behind that for one sandbox: the runtime it was placed on, the exact images
it runs by digest, and what it does and does not claim. Local VMs and trusted
hosts have no report; what each placement protects is in the
[security model](@/reference/security.md).

The output below is from a real run on a Codewire platform, with the
platform's internal names replaced. Your IDs will differ.

```sh
cw report ana-web
```

```text
Environment report: cae6f2ba-d240-49bf-bb97-434c697bd848
  Trust level: not_confidential
  Production verified: no
  Environment: sandbox (running)
  Isolation: standard
  Runtime: commodity / RuntimeClass commodity / handler kata-clh
  Confidential: no
  Placement:
    Namespace: {namespace}
    Workspace pod: sandbox-cae6f2ba-d240-49bf-bb97-434c697bd848
    Pod IP: {pod address}
    Node: {node}
    Zone: --
    Region: --
  Images:
    Workspace: ghcr.io/codewiresh/workspace@sha256:{digest}
    Workspace image ID: ghcr.io/codewiresh/workspace@sha256:{digest}
    DinD: docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c
    DinD image ID: docker.io/library/docker@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c
    Daemon init: {daemon image}@sha256:a312aeb01ff220b004de7d9a562d0984524c6315cea245ee30df5e3c14d2c9f9
    Daemon init image ID: --
  Provenance: not_available
    Guest kernel: --
    Guest initrd: --
    Guest image: --
    Firmware: --
    Source: --
    Notes:
      - Guest kernel, initrd/image, and firmware provenance are not persisted by the runtime API yet.
  Attestation: not_applicable (none)
    Report available: no
    Source: --
  Trustee: not_applicable
    Resource: --
    Reference values: --
    Policy: --
  Warnings:
    - Commodity runtime has a Kata VM boundary but does not make a TEE attestation claim.
```

## Reading it

| Line | Means |
| --- | --- |
| `Runtime` | Where the sandbox runs. `kata-clh` is a Kata Containers VM on Cloud Hypervisor: the sandbox has its own kernel, and the VM is the boundary |
| `Isolation` | `standard` for every sandbox today |
| `Trust level`, `Confidential` | Whether the sandbox claims confidential computing, where even the host cannot read its memory. A standard sandbox does not |
| `Images` | Each image the sandbox runs, pinned by digest, so you can check exactly what code it runs |
| `Provenance` | The guest kernel, initrd and firmware the VM booted. Not recorded yet |
| `Attestation`, `Trustee` | Hardware evidence for a confidential sandbox. Not applicable to a standard one |
| `Warnings` | What the sandbox does not claim, in plain words |

`cw report ENV --output json` gives the same fields for a script.

## Related

- [Security model](@/reference/security.md): what each placement protects,
  and what it does not.
- [Environments](@/environments/_index.md#where-it-runs)
