+++
title = "Concepts"
description = "The objects cw works with and how they fit together."
weight = 20
sort_by = "weight"
+++

An **environment** is the product object: an isolated development machine. It
runs in one of three **placements**, owns durable **sessions** (shells,
commands and managed agent conversations), receives **application secrets**
and uses **provider credentials** through a credential profile, and is reached
over the Codewire tailnet, preview URLs or Codewire Mesh. Hosted environments
belong to an **organization**.

{{ card_grid(
  titles=["Environments", "Placements", "Sessions and agents", "Secrets and credentials", "Networking and previews", "Organizations"],
  hrefs=["/docs/concepts/environments", "/docs/concepts/placements", "/docs/concepts/sessions-and-agents", "/docs/concepts/secrets-and-credentials", "/docs/concepts/networking", "/docs/concepts/organizations"],
  descriptions=["What an environment contains, its lifecycle, and the daemon inside it.", "Hosted sandbox, local VM and trusted host: what each one gives you.", "Durable sessions, managed Codex and Claude conversations, leads and workers.", "Two different things with two different boundaries.", "How cw reaches an environment, preview URLs, ports and Codewire Mesh.", "Members, roles, sharing and billing for hosted sandboxes."]
) }}

## Vocabulary

| Term | Meaning |
| --- | --- |
| Environment | An isolated development machine for agents and developers. The dashboard calls a hosted one a *Sandbox*. |
| Placement | Where an environment runs: hosted sandbox, local VM or trusted host session. |
| Session | A process inside an environment: a shell, a command or a managed agent conversation. Sessions outlive the client that launched them. |
| Daemon | The in-environment control plane (the `cw` binary) that serves sessions, files, SSH and the tailnet peer. |
| Workspace storage | The live, mutable files an environment owns. They survive a stop; they are not a snapshot. |
| Application secret | A named value such as `DATABASE_URL`, delivered to processes under its own name. |
| Provider credential | A named identity for Codex and OpenAI, Anthropic, GitHub or SSH whose private material stays outside the environment. |
| Credential profile | A named selection of provider identities that an environment uses. |
| Environment projection | The child-visible values assembled for one process launch. |
| Preset | Creation defaults: image, resources, commands, ports. |
| Codewire Mesh | The network control plane that lets local environments and nodes reach each other. |
