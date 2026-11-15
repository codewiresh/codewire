import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, type Page } from "@playwright/test";
import postgres from "postgres";
import { waitForEnvironmentState } from "./environment";
import { defaultWorkspaceImage } from "./runtime-images";

const sql = postgres(process.env.DATABASE_URL!);
const execFileAsync = promisify(execFile);
const serverUrl = process.env.SERVER_URL || "http://127.0.0.1:8080";
export const githubCheckoutName = "github-repository-draft";
export const githubCheckoutUrl = "https://github.com/synthetic-user/repository-01.git";
// Git in the Sandbox reaches github.com through the managed GitHub route, set
// as Git's own insteadOf configuration in the session environment. The stored
// origin stays canonical; `git remote get-url` reports the rewritten URL.
const githubManagedRoute = githubCheckoutUrl.replace(
  "https://github.com/",
  "http://127.0.0.1:38081/_codewire/github/",
);
// The same pinned workspace contract used by ssr-dashboard.environments.ssr.ts.
export const githubCheckoutImage = process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE || defaultWorkspaceImage;
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

type GitCounters = {
  advertisement: number;
  uploadPack: number;
  appRefresh: number;
  refreshedAdvertisement: number;
  refreshedUploadPack: number;
};

export async function githubConnectionMetadata(userId: string) {
  if (process.env.PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1") {
    throw new Error("GitHub connection metadata requires the managed synthetic Kind fixture");
  }
  // Inspect only this test owner's metadata and envelope-validity booleans.
  // Neither plaintext nor encrypted provider material enters browser reports.
  return sql`
    SELECT c.id, c.user_id, c.organization_id, c.provider, c.authentication_kind,
           c.status, c.revocation_generation::text, c.material_generation::text,
           (m.credential_id IS NOT NULL AND m.material_generation = c.material_generation
            AND m.kek_provider = 'openbao-transit' AND m.key_version > 0
            AND octet_length(m.wrapped_dek) BETWEEN 1 AND 65536
            AND octet_length(m.ciphertext) BETWEEN 16 AND 1048592
            AND octet_length(m.nonce) = 12 AND m.format = 1 AND m.wrapped_format = 1)
             AS protected_material_present
    FROM platform_credentials c
    LEFT JOIN platform_credential_material m ON m.credential_id = c.id
    WHERE c.user_id = ${userId}
    ORDER BY c.id
  `;
}

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

/** A profile's current revision; connecting or deleting GitHub never changes it. */
export async function profileCurrentRevision(profileId: string): Promise<number> {
  const [profile] = await sql`
    SELECT current_revision FROM platform_access_profiles WHERE id = ${profileId}
  `;
  expect(profile).toBeTruthy();
  return Number(profile.current_revision);
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
  const counters: GitCounters = {
    advertisement: 0, uploadPack: 0, appRefresh: 0,
    refreshedAdvertisement: 0, refreshedUploadPack: 0,
  };
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    const event = JSON.parse(line);
    if (event.target !== "codewire_kind_credential_fixture") continue;
    if (event.fields?.event === "github_app_refresh") {
      const { github_app_refresh_calls: appRefresh } = event.fields;
      if (!Number.isSafeInteger(appRefresh) || appRefresh < 0) {
        throw new Error("Invalid synthetic GitHub App refresh counter");
      }
      counters.appRefresh = Math.max(counters.appRefresh, appRefresh);
      continue;
    }
    if (event.fields?.event !== "github_git_response") continue;
    const {
      github_advertisement_calls: advertisement,
      github_upload_pack_calls: uploadPack,
      github_refreshed_advertisement_calls: refreshedAdvertisement,
      github_refreshed_upload_pack_calls: refreshedUploadPack,
    } = event.fields;
    if (!Number.isSafeInteger(advertisement) || advertisement < 0
      || !Number.isSafeInteger(uploadPack) || uploadPack < 0
      || !Number.isSafeInteger(refreshedAdvertisement) || refreshedAdvertisement < 0
      || !Number.isSafeInteger(refreshedUploadPack) || refreshedUploadPack < 0) {
      throw new Error("Invalid synthetic Git response counters");
    }
    counters.advertisement = Math.max(counters.advertisement, advertisement);
    counters.uploadPack = Math.max(counters.uploadPack, uploadPack);
    counters.refreshedAdvertisement = Math.max(counters.refreshedAdvertisement, refreshedAdvertisement);
    counters.refreshedUploadPack = Math.max(counters.refreshedUploadPack, refreshedUploadPack);
  }
  return counters;
}

export async function verifyGithubCheckout(page: Page, orgId: string, before: GitCounters) {
  // The checkout uses the account's GitHub connection; no profile is bound.
  const [created] = await sql`
    SELECT e.id, e.project_spec, b.profile_id
    FROM environments e
    LEFT JOIN platform_environment_access_bindings b ON b.environment_id = e.id
    WHERE e.org_id = ${orgId} AND e.name = ${githubCheckoutName}
  `;
  expect(created?.id).toBeTruthy();
  expect(created.profile_id).toBeNull();
  expect(created.project_spec.install_command).toBe(githubCheckoutInstall);
  expect(created.project_spec.repositories).toEqual([{
    source: githubCheckoutUrl, branch: "main", destination: "/workspace/repository-01",
  }]);
  await waitForEnvironmentState(created.id, ["running"], 300_000);
  await waitForGithubCheckoutSetup(created.id);
  const after = await githubGitCounters();
  expect(after.advertisement).toBeGreaterThan(before.advertisement);
  expect(after.uploadPack).toBeGreaterThan(before.uploadPack);
  expect(after.appRefresh).toBe(before.appRefresh);
  expect(after.refreshedAdvertisement).toBeGreaterThan(before.refreshedAdvertisement);
  expect(after.refreshedUploadPack).toBeGreaterThan(before.refreshedUploadPack);

  const response = await page.request.post(`${serverUrl}/codewire.v1.ExecService/Exec`, {
    timeout: 45_000,
    data: {
      orgId, environmentId: created.id, timeout: "30s",
      command: ["sh", "-c", [
        "set -eu",
        "cd /workspace/repository-01",
        "test \"$(cat /workspace/github-checkout-proof)\" = 'checkout-before-install-ok'",
        `test "$(git rev-parse HEAD)" = '${checkoutCommit}'`,
        `test "$(git config --get remote.origin.url)" = '${githubCheckoutUrl}'`,
        `test "$(git remote get-url origin)" = '${githubManagedRoute}'`,
        "test -z \"$(git status --porcelain)\"",
        // Only fixed, bounded relevant configuration is examined. Never echo
        // environment/configuration bytes into test output or artifacts.
        "test \"$HOME\" = /home/codewire",
        "test \"${XDG_CONFIG_HOME:-/home/codewire/.config}\" = /home/codewire/.config",
        // Stock gh is configured by Codewire while GitHub is selected: its own
        // directory with one file naming the ingress socket, and a public
        // placeholder token. The user's ~/.config/gh is not read.
        "test \"$GH_CONFIG_DIR\" = /codewire/run/gh",
        "test \"$GH_TOKEN\" = codewire-managed",
        "test \"$(cat \"$GH_CONFIG_DIR/config.yml\")\" = \"$(printf 'version: 1\\nhttp_unix_socket: /codewire/run/credentials.sock')\"",
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

type LargeTransfer = { operation: string; streamed: boolean; requestBytes: number; success: boolean };

/** The fixture's large repository (#4280) and its streamed transfers so far. */
async function githubLargeFixture() {
  const context = process.env.PLAYWRIGHT_KUBE_CONTEXT;
  if (process.env.PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1" || !context?.startsWith("kind-")) {
    throw new Error("Large Git transfers require the explicit managed Kind fixture context");
  }
  // The ready line is logged once at start; read the whole bounded log.
  const { stdout } = await execFileAsync("kubectl", [
    "--context", context, "-n", "codewire-e2e", "logs",
    "deployment/codewire-credential-service", "-c", "credential-service", "--limit-bytes=8388608",
  ], { timeout: 15_000, maxBuffer: 16 * 1024 * 1024 });
  let ready: { commit: string; mebibytes: number } | undefined;
  const transfers: LargeTransfer[] = [];
  for (const line of stdout.split("\n")) {
    // The fixture's first event shares its line with the test harness's
    // "test runtime::kind::serve_kind_credential_fixture ... " prefix.
    const start = line.indexOf("{\"timestamp\"");
    if (start < 0) continue;
    const event = JSON.parse(line.slice(start));
    if (event.target !== "codewire_kind_credential_fixture") continue;
    const fields = event.fields ?? {};
    if (fields.event === "github_git_large_ready") {
      if (!/^[0-9a-f]{40}$/.test(fields.commit) || !Number.isSafeInteger(fields.mebibytes)) {
        throw new Error("Invalid large Git fixture ready line");
      }
      ready = { commit: fields.commit, mebibytes: fields.mebibytes };
    } else if (fields.event === "github_git_large_transfer") {
      transfers.push({
        operation: String(fields.operation), streamed: fields.streamed_body === true,
        requestBytes: Number(fields.request_bytes), success: fields.success === true,
      });
    }
  }
  if (!ready) throw new Error("The Kind credential fixture has no large Git repository");
  return { ...ready, transfers };
}

/**
 * Stock Git in the checkout's Sandbox, through the managed GitHub route and
 * the credential bridge (#4280): clones the large repository, whose pack is
 * over the old 256 MiB response limit, verifies every blob against the
 * fixture's commit, then pushes 20 MiB of incompressible bytes, over the old
 * 4 MiB request limit. Both POSTs must have streamed their bodies.
 */
export async function verifyGithubLargeTransfers(page: Page, orgId: string) {
  const [created] = await sql`
    SELECT id FROM environments WHERE org_id = ${orgId} AND name = ${githubCheckoutName}
  `;
  expect(created?.id).toBeTruthy();
  const before = await githubLargeFixture();
  const branch = `large-push-${Date.now()}`;
  const response = await page.request.post(`${serverUrl}/codewire.v1.ExecService/Exec`, {
    timeout: 600_000,
    data: {
      orgId, environmentId: created.id, timeout: "570s",
      command: ["sh", "-c", [
        "set -eu",
        "work=\"$(mktemp -d /workspace/large-transfer.XXXXXX)\"",
        "cd \"$work\"",
        "git clone --quiet https://github.com/synthetic-user/repository-large.git large",
        "cd large",
        `test "$(git rev-parse HEAD)" = '${before.commit}'`,
        "git fsck --full --strict --no-dangling",
        "for file in blob-*.bin; do test \"$(git hash-object \"$file\")\" = \"$(git rev-parse \"HEAD:$file\")\"; done",
        `test "$(cat blob-*.bin | wc -c)" -eq ${before.mebibytes * 1024 * 1024}`,
        "head -c 20971520 /dev/urandom > pushed.bin",
        "git add pushed.bin",
        "git -c user.name=E2E -c user.email=e2e@example.invalid commit --quiet --no-gpg-sign -m pushed",
        `git push --quiet origin HEAD:refs/heads/${branch}`,
        `test "$(git ls-remote origin refs/heads/${branch} | cut -f1)" = "$(git rev-parse HEAD)"`,
        "cd /workspace",
        "rm -rf \"$work\"",
        "printf 'github-large-transfers-verified\\n'",
      ].join("\n")],
    },
  });
  expect(response.status()).toBe(200);
  const result = await response.json();
  const stderr = Buffer.from(result.stderr || "", "base64").toString();
  expect(result.exitCode ?? 0, stderr).toBe(0);
  expect(Buffer.from(result.stdout || "", "base64").toString()).toBe("github-large-transfers-verified\n");
  const after = (await githubLargeFixture()).transfers.slice(before.transfers.length);
  // The clone's and the push's POSTs streamed (not the 4 MiB whole-body
  // fallback, which the guest would have refused with 413).
  expect(after.filter((t) => t.operation === "large_upload_pack" && t.streamed && t.success).length)
    .toBeGreaterThan(0);
  expect(after.some((t) => t.operation === "large_receive_pack" && t.streamed && t.success
    && t.requestBytes > 20 * 1024 * 1024)).toBe(true);
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
