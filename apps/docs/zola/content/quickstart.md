---
title: Quickstart
description: Get your first environment running in 5 minutes
---


Two paths to get started — web dashboard or CLI.

## Prerequisites

- An **invite code** (Codewire is in private beta)
- After account creation, **2FA setup is mandatory** — you'll be redirected to configure it before accessing the dashboard

## Web quickstart

### 1. Create your account

1. Go to [codewire.sh/signup](https://codewire.sh/signup)
2. Enter your invite code, name, email, and a password (minimum 12 characters)
3. Verify your email, then set up 2FA with an authenticator app

{% aside(kind="note") %}
  Save your backup codes — they're shown only once and are your fallback if you lose access to your authenticator app.
{% end %}

### 2. Create an organization

1. From the [dashboard](https://codewire.sh/dashboard), click **New Organization**
2. Enter a **name** and **slug** for your organization
3. Click **Create**

After creating your org, connect GitHub and create your first environment.

### 3. Connect GitHub

1. Go to **Secrets** in the sidebar
2. Set a **GitHub Token** for private repository access
3. Return to the organization dashboard

{% aside(kind="note") %}
  Public repositories do not require a token, but connecting GitHub gives the environment creator access to private repos.
{% end %}

### 4. Create an environment

1. Choose **New Environment**
2. Enter a repo URL and click **Analyze** — AI detects your language, framework, and services
3. Review the detection results and adjust options if needed
4. Click **Create Environment**

### 5. Connect

Once your environment shows **Running**, open a terminal, SSH, file browser, preview port, or persistent agent session.

### 6. Invite your team (optional)

1. Go to your organization's **Settings** page
2. Click **Members**, enter an email and click **Invite**

## CLI quickstart

### 1. Install

During the private preview, install from the root of an authorized Codewire
source checkout:

```bash
make cli-install
```

### 2. Set up

```bash
cw setup
```

The interactive wizard walks you through: server URL, login, org selection, and GitHub connection.

### 3. Create a sandbox environment

```bash
cw env create github.com/your-org/your-repo
```

AI analyzes the repo and creates a sandbox environment with the right tools and dependencies.

### 4. Run an agent

```bash
cw run -- claude "fix the tests"
```

This starts a persistent session after you connect to the environment.

## What's next?

{{ card_grid(
  titles=["Create environments", "CLI platform commands", "Connect to environments", "Connect GitHub"],
  hrefs=["/docs/getting-started/create-your-first-environment", "/docs/cli/platform", "/docs/environments/connect", "/docs/settings/github-integration"],
  descriptions=["Learn about AI-assisted environment creation.", "Full reference for platform-mode CLI commands.", "Terminal, SSH, files, previews, and sessions.", "Use private repositories in environments."]
) }}
