---
title: Environment statuses
description: Status values shown for Codewire environments
---

Environment statuses describe the lifecycle state of a sandbox.

| Status | Meaning |
| --- | --- |
| Creating | Codewire is preparing runtime state, repository configuration, and sandbox resources. |
| Running | The environment is ready for terminal, SSH, file, preview, and agent access. |
| Stopping | Codewire is shutting down compute while preserving retained state. |
| Stopped | Compute is released. Start the environment again to reconnect. |
| Deleting | Codewire is tearing down the environment and related access records. |
| Failed | Creation, startup, or lifecycle action failed. Check lifecycle events and logs. |
| Suspended | Access is blocked by billing, policy, or administrative action. |
