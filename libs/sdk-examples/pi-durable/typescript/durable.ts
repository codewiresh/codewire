// A durable pi agent whose tools run in a Codewire environment, and a turn
// that survives its host process being killed.
//
//   npm start
//
// `demo` creates the environment with the Codewire SDK and starts the turn
// in a child process. The agent's bash call writes /workspace/notes.txt and
// sleeps; the demo kills the child mid-call. A new process reopens the same
// SQLite storage and resumes the turn, which reads the file back from the same
// environment. Last, the demo deletes the environment.
//
// The tools reach the environment over SSH through `cw --cloud shell --stdio`,
// with the environment's host key from `cw --cloud ssh known-hosts`, the same
// route `cw setup ssh` writes; here it lives in a config file of its own, so
// your ~/.ssh/config is untouched. Reads CODEWIRE_API_KEY, CODEWIRE_ORG_ID
// and, for a server other than the hosted one, CODEWIRE_API_URL. With
// ANTHROPIC_API_KEY set the agent is Claude (PI_DURABLE_MODEL, default
// claude-sonnet-5-5); without it, a scripted model plays the same turn.

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { accessSync, constants } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Codewire, type Environment } from "@codewire/sdk";
import { BACKGROUND_CONTEXT } from "@earendil-works/chord/context";
import { createModels } from "@earendil-works/pi-ai/models";
import { anthropicProvider } from "@earendil-works/pi-ai/providers/anthropic";
import { fauxAssistantMessage, fauxProvider, fauxText, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { AssistantEntry, createRegistry, Harness } from "@earendil-works/pi-durable";
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node";
import { CodingTools } from "@earendil-works/pi-durable/tools";
import { RemoteExecutionEnv, sshConnection } from "@earendil-works/pi-env";

const context = BACKGROUND_CONTEXT;
const cw = findCw();
const requestId = "write-and-read-notes";
const prompt =
  "Write the line 'written before the restart' to /workspace/notes.txt, touch /workspace/started, " +
  "then sleep 120 seconds, all in one bash command. Then read /workspace/notes.txt and tell me what it says.";

// The managed directives `cw setup ssh` writes, for this one host.
// OpenSSH runs a KnownHostsCommand only from an absolute path, so the config
// names cw by its full path: CW_BIN, or the first cw on PATH.
function findCw(): string {
  const named = process.env.CW_BIN?.trim();
  if (named) {
    if (!isAbsolute(named)) throw new Error("CW_BIN must be an absolute path");
    return named;
  }
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!isAbsolute(directory)) continue;
    const candidate = join(directory, "cw");
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Not here; try the next directory.
    }
  }
  throw new Error("cw is not on PATH; install it, or set CW_BIN to its absolute path");
}

function sshConfig(host: string): string {
  return [
    `Host ${host}`,
    `  ProxyCommand ${cw} --cloud shell --stdio %n`,
    "  User codewire",
    "  StrictHostKeyChecking yes",
    "  UserKnownHostsFile /dev/null",
    "  GlobalKnownHostsFile /dev/null",
    `  KnownHostsCommand ${cw} --cloud ssh known-hosts %H`,
    "  HostKeyAlgorithms ssh-ed25519",
    "  UpdateHostKeys no",
    "  ForwardAgent no",
    "  ForwardX11 no",
    "  PasswordAuthentication no",
    "  KbdInteractiveAuthentication no",
    "  PubkeyAuthentication no",
    "  GSSAPIAuthentication no",
    "  ServerAliveInterval 30",
    "  ServerAliveCountMax 4",
    "",
  ].join("\n");
}

// Without a model key, a scripted model plays the turn, deciding each step
// from the transcript so a resumed process carries on where the last stopped.
function models() {
  const models = createModels();
  if (process.env.ANTHROPIC_API_KEY) {
    models.setProvider(anthropicProvider());
    return { models, model: { provider: "anthropic", modelId: process.env.PI_DURABLE_MODEL ?? "claude-sonnet-5-5" } };
  }
  const faux = fauxProvider();
  const script = (transcript: { messages: { role: string; toolName?: string; content?: unknown }[] }) => {
    const results = transcript.messages.filter((message) => message.role === "toolResult");
    if (results.length === 0) {
      return fauxAssistantMessage(
        fauxToolCall("bash", {
          command:
            "echo 'written before the restart' > /workspace/notes.txt && touch /workspace/started && sleep 120",
        }),
        { stopReason: "toolUse" },
      );
    }
    const last = results[results.length - 1];
    if (last.toolName === "bash") {
      return fauxAssistantMessage(fauxToolCall("read", { path: "/workspace/notes.txt" }), { stopReason: "toolUse" });
    }
    const text = JSON.stringify(last.content ?? "");
    return fauxAssistantMessage(fauxText(`notes.txt says: ${text.includes("written before the restart") ? "written before the restart" : text}`));
  };
  faux.setResponses(Array.from({ length: 8 }, () => script));
  models.setProvider(faux.provider);
  return { models, model: { provider: faux.provider.id, modelId: faux.getModel().id } };
}

async function openHarness(name: string, directory: string) {
  const host = `cw-cloud-${name}`;
  const configFile = join(directory, "ssh_config");
  const { connection } = sshConnection({
    host,
    // The config's KnownHostsCommand trusts the environment's recorded key by
    // this name; pi-env's own known-hosts file stays empty.
    hostKeyAlias: host,
    knownHostsFile: join(directory, "known_hosts"),
    configFile,
  });
  const { models: hostModels, model } = models();
  const registry = createRegistry();
  registry.install(CodingTools);
  const harness = await Harness.open(
    await openNodeSqliteStorage(join(directory, "session.sqlite")),
    {
      models: hostModels,
      registry,
      env: () => new RemoteExecutionEnv({ connection, id: `pi-env:${name}`, cwd: "/workspace" }),
    },
    context,
  );
  const root = await harness.root(context, { agent: { model, extensions: [CodingTools], cwd: "/workspace" } });
  return { harness, root, connection };
}

// One process's part of the turn: submit it (or find it again by its request
// ID after a restart), resume what the last process left, and print the answer.
async function turn(name: string, directory: string) {
  const { harness, root, connection } = await openHarness(name, directory);
  harness.resume();
  const submission = await root.submit({ type: "input", content: prompt, requestId }, context);
  const settled = await submission.wait(context);
  if (settled.status !== "done" || settled.type !== "input") {
    throw new Error(`the turn ended ${settled.status}`);
  }
  const answer = await root.commit((tx) => tx.entry(AssistantEntry, settled.answer), context);
  const message = (answer?.model?.[0] ?? settled.answer) as { content?: { type: string; text?: string }[] };
  const text = (message.content ?? []).filter((block) => block.type === "text").map((block) => block.text).join("");
  console.log("answer:", text);
  await harness.close(context);
  // The SSH session to the environment would otherwise keep this process alive.
  connection.close();
}

function child(mode: string, name: string, directory: string): ChildProcess {
  return spawn(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url), mode, name, directory], {
    stdio: "inherit",
  });
}

// Waits for a turn process to exit, killing it after timeoutMs, so the demo
// always reaches its cleanup.
function exited(turn: ChildProcess, timeoutMs: number): Promise<number | null> {
  if (turn.exitCode !== null || turn.signalCode !== null) return Promise.resolve(turn.exitCode);
  return new Promise((resolve) => {
    const timer = setTimeout(() => turn.kill("SIGKILL"), timeoutMs);
    turn.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

// Waits until path exists in the environment; fails at once if the turn
// process ends first, since then nothing will create it.
async function waitForFile(env: Environment, path: string, turn: ChildProcess, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (turn.exitCode !== null || turn.signalCode !== null) {
      throw new Error(`the turn ended (${turn.exitCode ?? turn.signalCode}) before ${path} appeared`);
    }
    const output = await env.exec({ command: ["test", "-e", path] });
    if (output.exit_code === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`${path} did not appear within ${timeoutMs / 1000} s`);
}

async function demo() {
  const codewire = new Codewire({ timeout: 300_000 });
  const name = `pi-durable-${randomUUID().slice(0, 8)}`;
  const env = await codewire.environments.create(
    { name, project_spec: { schema_version: 1, image: "python:3.12-slim", working_directory: "/workspace" } },
  );
  console.log("created", env.id, `(${name})`);
  const directory = await mkdtemp(join(tmpdir(), "pi-durable-"));
  const turns: ChildProcess[] = [];
  // From here on, delete the environment and the local storage whether or
  // not anything fails.
  try {
    await env.waitReady({ timeout: 300_000 });
    await writeFile(join(directory, "ssh_config"), sshConfig(`cw-cloud-${name}`), { mode: 0o600 });
    await writeFile(join(directory, "known_hosts"), "", { mode: 0o600 });

    const first = child("turn", name, directory);
    turns.push(first);
    await waitForFile(env, "/workspace/started", first, 300_000);
    first.kill("SIGKILL");
    await exited(first, 30_000);
    console.log("killed the host process in the middle of the turn");

    const second = child("turn", name, directory);
    turns.push(second);
    const code = await exited(second, 600_000);
    if (code !== 0) throw new Error(`the resumed turn exited ${code}`);

    const notes = new TextDecoder().decode(await env.files.download("/workspace/notes.txt"));
    if (notes.trim() !== "written before the restart") throw new Error("notes.txt came back different");
    console.log("resumed against the same environment: /workspace/notes.txt is still there");
  } finally {
    for (const turn of turns) if (turn.exitCode === null && turn.signalCode === null) turn.kill("SIGKILL");
    await env.remove();
    console.log("deleted", env.id);
    await rm(directory, { recursive: true, force: true });
  }
}

const [mode, name, directory] = process.argv.slice(2);
const run = mode === "turn" && name && directory ? turn(name, directory) : mode === "demo" ? demo() : undefined;
if (!run) {
  console.error("usage: tsx durable.ts demo");
  process.exit(2);
}
run.catch((error: unknown) => {
  console.error("pi-durable example failed:", error instanceof Error ? error.message : error);
  process.exit(1);
});
