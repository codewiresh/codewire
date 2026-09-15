import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, type Page } from "@playwright/test";
import postgres from "postgres";
import { waitForEnvironmentState } from "./environment";

const sql = postgres(process.env.DATABASE_URL!);
const execFileAsync = promisify(execFile);
const serverUrl = process.env.SERVER_URL || "http://127.0.0.1:8080";
export const githubCheckoutName = "github-repository-draft";
export const githubCheckoutUrl = "https://github.com/synthetic-user/repository-01.git";
// The same pinned workspace contract used by ssr-dashboard.environments.ssr.ts.
export const githubCheckoutImage = process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE
  || "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff";
// Public deterministic fixture identity; not a credential. The install marker
// proves setup checked out the repository BEFORE running the user's command.
const checkoutCommit = "78e440926ea15ee9644a69199694e39f6f06e3ce";
// Install Command is a single-line input: newlines would become spaces and
// silently turn these checks into arguments to `set`, skipping the marker.
export const githubCheckoutInstall = [
  "set -eu",
  "cd /workspace/repository-01",
  `test "$(git rev-parse HEAD)" = '${checkoutCommit}'`,
  "test \"$(cat proof.txt)\" = 'initial-private-checkout-synthetic-v1'",
  "test \"$(wc -c < proof.txt)\" -eq 38",
  "printf 'checkout-before-install-ok\\n' > /workspace/github-checkout-proof",
].join("; ");

type GitCounters = { advertisement: number; uploadPack: number };

async function waitForGithubCheckoutSetup(environmentId: string) {
  // Running makes Exec available, but setup continues asynchronously. Read
  // only status metadata; setup errors may contain child output, so never
  // return their contents to browser reports.
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const [row] = await sql`
      SELECT e.state, b.setup_complete,
             COALESCE(b.setup_error, '') <> '' AS setup_failed
      FROM environments e
      LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
      WHERE e.id = ${environmentId}
    `;
    if (!row || row.state !== "running") {
      throw new Error("GitHub checkout environment is no longer running");
    }
    if (row.setup_failed) throw new Error("GitHub checkout setup failed");
    if (row.setup_complete) return;
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error("GitHub checkout setup did not complete within 180000ms");
}

export async function githubGitCounters(): Promise<GitCounters> {
  const context = process.env.PLAYWRIGHT_KUBE_CONTEXT;
  if (process.env.PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1" || !context?.startsWith("kind-")) {
    throw new Error("Git checkout counters require the explicit managed Kind fixture context");
  }
  // Existing fixture's credential-free structured diagnostics; no new provider
  // introspection endpoint, cluster forwarding or unrestricted log collection.
  const { stdout } = await execFileAsync("kubectl", [
    "--context", context, "-n", "codewire-e2e", "logs",
    "deployment/codewire-credential-service", "-c", "credential-service", "--tail=1000",
  ], { timeout: 15_000, maxBuffer: 1024 * 1024 });
  const counters: GitCounters = { advertisement: 0, uploadPack: 0 };
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    const event = JSON.parse(line);
    if (event.target !== "codewire_kind_credential_fixture"
      || event.fields?.event !== "github_git_response") continue;
    const { github_advertisement_calls: advertisement, github_upload_pack_calls: uploadPack } = event.fields;
    if (!Number.isSafeInteger(advertisement) || advertisement < 0
      || !Number.isSafeInteger(uploadPack) || uploadPack < 0) {
      throw new Error("Invalid synthetic Git response counters");
    }
    counters.advertisement = Math.max(counters.advertisement, advertisement);
    counters.uploadPack = Math.max(counters.uploadPack, uploadPack);
  }
  return counters;
}

export async function verifyGithubCheckout(page: Page, orgId: string, profileId: string, before: GitCounters) {
  const [created] = await sql`
    SELECT e.id, e.project_spec, b.profile_id, b.profile_revision
    FROM environments e
    JOIN platform_environment_access_bindings b ON b.environment_id = e.id
    WHERE e.org_id = ${orgId} AND e.name = ${githubCheckoutName}
  `;
  expect(created?.id).toBeTruthy();
  expect(created.profile_id).toBe(profileId);
  expect(Number(created.profile_revision)).toBe(1);
  expect(created.project_spec.install_command).toBe(githubCheckoutInstall);
  expect(created.project_spec.repositories).toEqual([{
    source: githubCheckoutUrl, branch: "main", destination: "/workspace/repository-01",
  }]);
  await waitForEnvironmentState(created.id, ["running"], 300_000);
  await waitForGithubCheckoutSetup(created.id);
  const after = await githubGitCounters();
  expect(after.advertisement).toBeGreaterThan(before.advertisement);
  expect(after.uploadPack).toBeGreaterThan(before.uploadPack);

  const response = await page.request.post(`${serverUrl}/codewire.v1.ExecService/Exec`, {
    timeout: 45_000,
    data: {
      orgId, environmentId: created.id, timeout: "30s",
      command: ["sh", "-c", [
        "set -eu",
        "cd /workspace/repository-01",
        "test \"$(cat /workspace/github-checkout-proof)\" = 'checkout-before-install-ok'",
        `test "$(git rev-parse HEAD)" = '${checkoutCommit}'`,
        `test "$(git remote get-url origin)" = '${githubCheckoutUrl}'`,
        "test -z \"$(git status --porcelain)\"",
        // Only fixed, bounded relevant configuration is examined. Never echo
        // environment/configuration bytes into test output or artifacts.
        "test \"$HOME\" = /home/codewire",
        "test \"${XDG_CONFIG_HOME:-/home/codewire/.config}\" = /home/codewire/.config",
        "test \"${GH_CONFIG_DIR:-/home/codewire/.config/gh}\" = /home/codewire/.config/gh",
        "for directory in .git /home/codewire /home/codewire/.config /home/codewire/.config/git /home/codewire/.config/gh; do",
        "  test ! -L \"$directory\"",
        "  if [ -e \"$directory\" ]; then",
        "    test -d \"$directory\"",
        "    test -r \"$directory\"",
        "    test -x \"$directory\"",
        "  fi",
        "done",
        "for file in .git/config /home/codewire/.gitconfig /home/codewire/.config/git/config /home/codewire/.config/gh/hosts.yml /home/codewire/.git-credentials /home/codewire/.netrc; do",
        "  test ! -L \"$file\"",
        "  if [ -e \"$file\" ]; then",
        "    test -f \"$file\"",
        "    test -r \"$file\"",
        "    test \"$(wc -c < \"$file\")\" -le 65536",
        "    if grep -Eiq 'gh[o_pusr]_|github_pat_|oauth_token|extraheader|insteadof|credential.*helper' \"$file\"; then exit 41; fi",
        "  fi",
        "done",
        "git_environment=\"$(env | grep -E '^(GH_|GITHUB_|GIT_)' || true)\"",
        "test \"${#git_environment}\" -le 65536",
        "if printf '%s' \"$git_environment\" | grep -Eiq 'gh[o_pusr]_|github_pat_|oauth_token|authorization'; then exit 42; fi",
        "printf 'github-checkout-verified\\n'",
      ].join("\n")],
    },
  });
  expect(response.status()).toBe(200);
  const result = await response.json();
  expect(result.exitCode ?? 0).toBe(0);
  expect(Buffer.from(result.stderr || "", "base64").length).toBe(0);
  expect(Buffer.from(result.stdout || "", "base64").toString()).toBe("github-checkout-verified\n");
}

export async function destroyGithubCheckout(page: Page, orgId: string) {
  // Normal lifecycle even after a failed assertion; never remove finalizers,
  // forge runtime state or delete a bound profile before its sandbox is gone.
  const rows = await sql`
    SELECT id, state FROM environments
    WHERE org_id = ${orgId} AND name = ${githubCheckoutName}
  `;
  for (const row of rows) {
    if (row.state === "destroyed") continue;
    if (row.state !== "destroying") {
      const response = await page.request.post(`${serverUrl}/codewire.v1.EnvironmentService/DeleteEnvironment`, {
        timeout: 30_000, data: { orgId, environmentId: row.id },
      });
      expect(response.status()).toBe(200);
    }
    await waitForEnvironmentState(row.id, ["destroyed"], 120_000);
  }
}
