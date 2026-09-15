import assert from "node:assert/strict";
import { AsyncLocalStorage, createHook } from "node:async_hooks";
import { Codewire, CodewireError, EnrollmentOutcomeUnknownError } from "./index.js";
import { assertCredentialConverterCoverage } from "./credentials.js";

function frame(value: object, flags = 0): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  const result = new Uint8Array(5 + payload.length);
  result[0] = flags;
  new DataView(result.buffer).setUint32(1, payload.length);
  result.set(payload, 5);
  return result;
}

/** Actual generated Connect codecs over a synthetic, incremental HTTP body. */
export async function runCredentialTests(): Promise<void> {
  const pendingTimers = new Set<number>();
  const scope = new AsyncLocalStorage<symbol>();
  const fixture = Symbol("credential transport fixture");
  const ownership = createHook({
    init(id, type) {
      // Earlier tests can still schedule HTTP keepalive work while this hook
      // is active. Observe only timers descended from this fixture's calls.
      if (type === "Timeout" && scope.getStore() === fixture) pendingTimers.add(id);
    },
    destroy(id) { pendingTimers.delete(id); },
  }).enable();
  const assertTimers = async (expected: number) => {
    // clearTimeout emits destroy on the next event-loop turn. Observe real
    // timer ownership without changing timers, unref'ing, or forcing exit.
    await new Promise<void>((resolve) => setImmediate(resolve));
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(pendingTimers.size, expected, "only an active enrollment may retain its deadline timer");
  };
  try {
    await scope.run(fixture, async () => {
      await checkCredentialTransport(assertTimers);
      await checkGithubRepositoryTransport();
      await assertTimers(0);
      console.log("Credentials: generated metadata/CAS, incremental enrollment, cancellation, uncertain acknowledgement and deadline cleanup passed");
    });
  } finally {
    ownership.disable();
    scope.disable();
  }
}

async function checkGithubRepositoryTransport(): Promise<void> {
  const calls: Record<string, unknown>[] = [];
  const revision = 9_007_199_254_741_009n;
  const cw = new Codewire({ apiKey: "synthetic-opaque-oauth", baseUrl: "https://sdk.example.test",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      assert.equal(request.headers.get("authorization"), "Bearer synthetic-opaque-oauth");
      const url = new URL(request.url);
      assert.equal(url.pathname, "/codewire.v1.GithubRepositoryService/ListGithubRepositories");
      const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}") : await request.json();
      calls.push(body);
      return new Response(JSON.stringify({ repositories: [{repositoryId:"42",fullName:"owner/private",defaultBranch:"main",
        cloneUrl:"https://github.com/owner/private.git",isPrivate:true,archived:false,disabled:false}],nextPageToken:"opaque-next" }),
        {headers:{"Content-Type":"application/json"}});
    },
  });
  const page = await cw.credentials.listGithubRepositories("profile-one", revision, 50, "opaque-page");
  assert.deepEqual(calls, [{profileId:"profile-one",profileRevision:revision.toString(),pageSize:50,pageToken:"opaque-page"}]);
  assert.deepEqual(page, { repositories: [{repository_id:"42",full_name:"owner/private",default_branch:"main",
    clone_url:"https://github.com/owner/private.git",is_private:true,archived:false,disabled:false}],next_page_token:"opaque-next" });
  await assert.rejects(cw.credentials.listGithubRepositories("profile-one", 0n));
  await assert.rejects(cw.credentials.listGithubRepositories("profile-one", revision, 101));
  await assert.rejects(cw.credentials.listGithubRepositories("profile-one", revision, 50, "x".repeat(129)));
  assert.equal(calls.length,1,"invalid selections must not call the provider or advance the profile");
}

async function checkCredentialTransport(assertTimers: (expected: number) => Promise<void>): Promise<void> {
  assertCredentialConverterCoverage();
  const exact = 9_007_199_254_741_009n;
  const maximum = 0xffff_ffff_ffff_ffffn;
  const credential = { id: "credential-one", name: "personal", provider: "openai",
    authenticationKind: "CREDENTIAL_AUTHENTICATION_KIND_OAUTH", status: "CREDENTIAL_STATUS_ACTIVE",
    expiresAtUnix: maximum.toString(), revocationGeneration: exact.toString() };
  const sshCredential = {
    ...credential,
    id: "credential-ssh",
    name: "ssh",
    provider: "ssh",
    authenticationKind: "CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY",
    sshPublicKey: {
      openssh: "ssh-ed25519 AAAASynthetic sdk-fixture",
      fingerprint: "SHA256:synthetic-fingerprint",
    },
  };
  const challenge = { verificationUrl: "https://auth.openai.com/codex/device",
    userCode: "SYNTHETIC-CODE", expiresAtUnix: maximum.toString() };
  const calls: { method: string; body: Record<string, any> }[] = [];
  let releaseCommit: (() => void) | undefined;
  let enrollmentAborted = false;
  const cw = new Codewire({ apiKey: "synthetic-opaque-oauth", baseUrl: "https://sdk.example.test",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      assert.equal(request.headers.get("authorization"), "Bearer synthetic-opaque-oauth");
      const url = new URL(request.url);
      const method = url.pathname.split("/").at(-1)!;
      const bytes = new Uint8Array(await request.arrayBuffer());
      const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}")
        : JSON.parse(new TextDecoder().decode(method === "EnrollCodex" ? bytes.subarray(5) : bytes));
      assert.ok(!("orgId" in body));
      calls.push({ method, body });
      const unary = (value: object, status = 200) => new Response(JSON.stringify(value), {
        status, headers: { "Content-Type": "application/json" },
      });
      if (method === "ListCredentials") return unary({ credentials: [credential], nextPageToken: body.pageToken ? "" : "page-two" });
      if (method === "GetCredential") {
        if (body.credentialId === "missing") return unary({});
        const statuses: Record<string, string> = { expired: "CREDENTIAL_STATUS_EXPIRED", refresh_failed: "CREDENTIAL_STATUS_REFRESH_FAILED", revoked: "CREDENTIAL_STATUS_REVOKED" };
        return unary({ credential: body.name === "ssh"
          ? sshCredential
          : body.name === "ssh-missing-public"
            ? { ...sshCredential, sshPublicKey: undefined }
            : body.name === "oauth-with-public"
              ? { ...credential, sshPublicKey: sshCredential.sshPublicKey }
              : { ...credential, status: statuses[body.name] ?? credential.status } });
      }
      if (method === "RevokeCredential") {
        if (body.credentialId === "stale") return unary({ code: "aborted", message: "stale revision" }, 409);
        return unary({ credential: { ...credential, status: "CREDENTIAL_STATUS_REVOKED" } });
      }
      if (method === "DeleteCredential") return unary({});
      assert.equal(method, "EnrollCodex");
      assert.equal(url.pathname, "/codewire.v1.CredentialMutationService/EnrollCodex");
      assert.deepEqual(
        Object.keys(body),
        body.name === "reconnect"
          ? ["name", "credentialId", "expectedRevocationGeneration"]
          : ["name"],
      );
      const timeout = Number(request.headers.get("connect-timeout-ms"));
      assert.ok(timeout > 900_000 && timeout <= 960_000, "enrollment must override only this call's 30-second default");
      enrollmentAborted = false;
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          request.signal.addEventListener("abort", () => {
            enrollmentAborted = true;
            try { controller.error(new DOMException("Aborted", "AbortError")); } catch { /* already closed */ }
          }, { once: true });
          controller.enqueue(frame({ challenge }));
          if (body.name === "success") {
            releaseCommit = () => {
              controller.enqueue(frame({ credential }));
              controller.enqueue(frame({}, 2));
              controller.close();
            };
          } else if (body.name === "eof") {
            controller.enqueue(frame({}, 2)); controller.close();
          } else if (body.name === "error") {
            controller.enqueue(frame({ error: { code: "unavailable", message: "synthetic unavailable" } }, 2)); controller.close();
          } else if (body.name === "duplicate") {
            controller.enqueue(frame({ challenge })); controller.enqueue(frame({}, 2)); controller.close();
          }
        },
      }), { headers: { "Content-Type": "application/connect+json" } });
    },
  });
  assert.equal((await cw.credentials.list()).length, 2);
  assert.equal(calls[1].body.pageToken, "page-two");
  const metadata = await cw.credentials.get("credential-one");
  assert.equal(metadata.revocation_generation, exact);
  assert.equal(metadata.expires_at_unix, maximum);
  assert.equal(metadata.account_hint, undefined);
  assert.equal(calls.at(-1)!.body.credentialId, "credential-one");
  assert.ok(!("name" in calls.at(-1)!.body));
  for (const status of ["expired", "refresh_failed", "revoked"] as const) {
    assert.equal((await cw.credentials.getByName(status)).status, status);
    assert.equal(calls.at(-1)!.body.name, status);
    assert.ok(!("credentialId" in calls.at(-1)!.body));
  }
  const ssh = await cw.credentials.getByName("ssh");
  assert.equal(ssh.authentication_kind, "ssh_key");
  assert.deepEqual(ssh.ssh_public_key, {
    openssh: "ssh-ed25519 AAAASynthetic sdk-fixture",
    fingerprint: "SHA256:synthetic-fingerprint",
  });
  await assert.rejects(
    cw.credentials.getByName("ssh-missing-public"),
    /SSH public metadata exactly for SSH credentials/,
  );
  await assert.rejects(
    cw.credentials.getByName("oauth-with-public"),
    /SSH public metadata exactly for SSH credentials/,
  );
  assert.equal((await cw.credentials.revoke("credential-one", exact)).status, "revoked");
  assert.equal(calls.at(-1)!.body.expectedRevocationGeneration, exact.toString());
  await cw.credentials.delete("credential-one", maximum);
  assert.equal(calls.at(-1)!.body.expectedRevocationGeneration, maximum.toString());
  const before = calls.length;
  await assert.rejects(cw.credentials.revoke("stale", exact), (error: unknown) => error instanceof CodewireError && error.status === 409);
  assert.equal(calls.length, before + 1);
  const beforeInvalid = calls.length;
  for (const invalid of [0n, maximum + 1n, 42 as unknown as bigint]) {
    await assert.rejects(cw.credentials.delete("credential-one", invalid), /positive uint64 bigint/);
  }
  assert.equal(calls.length, beforeInvalid);
  await assert.rejects(cw.credentials.get("missing"), /omitted credential/);

  const enrollment = cw.credentials.enrollCodex("success");
  const first = await enrollment.next();
  assert.equal(first.value?.type, "challenge", "challenge must arrive before publication is released");
  if (first.value?.type === "challenge") assert.equal(first.value.challenge.expires_at_unix, maximum);
  await assertTimers(1); // Prove the observer detects the real active deadline.
  assert.ok(releaseCommit);
  releaseCommit();
  const second = await enrollment.next();
  assert.equal(second.value?.type, "credential");
  if (second.value?.type === "credential") assert.equal(second.value.credential.revocation_generation, exact);
  // Cleanup must precede exposing terminal metadata, not depend on another read.
  await assertTimers(0);
  assert.equal((await enrollment.next()).done, true);

  const reconnect = cw.credentials.enrollCodex("reconnect", {
    credential_id: "credential-one",
    expected_revocation_generation: exact,
  });
  assert.equal((await reconnect.next()).value?.type, "challenge");
  assert.equal(calls.at(-1)!.body.credentialId, "credential-one");
  assert.equal(calls.at(-1)!.body.expectedRevocationGeneration, exact.toString());
  await reconnect.return(undefined);
  await assertTimers(0);
  const beforeInvalidReconnect = calls.length;
  await assert.rejects(
    cw.credentials.enrollCodex("invalid", { credential_id: "credential-one" }).next(),
    /requires credential_id and expected_revocation_generation together/,
  );
  await assert.rejects(
    cw.credentials.enrollCodex("invalid", {
      credential_id: "credential-one",
      expected_revocation_generation: 0n,
    }).next(),
    /positive uint64 bigint/,
  );
  assert.equal(calls.length, beforeInvalidReconnect);

  for (const name of ["eof", "error", "duplicate"]) {
    const start = calls.length;
    const stream = cw.credentials.enrollCodex(name);
    assert.equal((await stream.next()).value?.type, "challenge");
    await assert.rejects(stream.next(), EnrollmentOutcomeUnknownError);
    assert.equal(calls.length, start + 1, "uncertainty must not trigger fetch/retry/revoke");
  }
  const dropped = cw.credentials.enrollCodex("drop");
  await dropped.next();
  await dropped.return(undefined);
  assert.equal(enrollmentAborted, true, "early iteration exit cancels the same HTTP request");
  const pausedCancellation = new AbortController();
  const paused = cw.credentials.enrollCodex("abort", { signal: pausedCancellation.signal });
  await paused.next();
  pausedCancellation.abort();
  // An aborted caller need not pull again for request/deadline cleanup.
  await assertTimers(0);
  assert.equal(enrollmentAborted, true);
  await paused.return(undefined);
  const cancellation = new AbortController();
  const aborted = cw.credentials.enrollCodex("abort", { signal: cancellation.signal });
  await aborted.next();
  const pending = aborted.next();
  cancellation.abort();
  await assert.rejects(pending, EnrollmentOutcomeUnknownError);
  assert.equal(enrollmentAborted, true);
}
