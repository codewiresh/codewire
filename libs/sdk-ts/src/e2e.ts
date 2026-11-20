import { Codewire, CodewireError, type Environment } from "./index.js";

const baseUrl = process.env.CODEWIRE_SERVER_URL?.trim();
if (!baseUrl) {
  throw new Error("CODEWIRE_SERVER_URL is required for the SDK e2e suite");
}

// Presets belong to an organization, so the suite makes its own and deletes
// it after: the account it runs as has none to begin with.
async function testPresetEnv() {
  const cw = new Codewire({ baseUrl, timeout: 300_000 });
  const slug = `sdk-e2e-${crypto.randomUUID().slice(0, 8)}`;
  const preset = await cw.presets.create({
    name: slug,
    slug,
    project_spec: { schema_version: 1, image: "python:3.12-slim", working_directory: "/workspace" },
  });
  try {
    await usePresetEnv(cw, slug);
  } finally {
    await cw.presets.delete(preset.id);
  }
}

// Deleting an environment returns before it is destroyed, and a preset an
// environment still uses cannot be deleted, so wait until it is gone.
async function removeAndWait(cw: Codewire, env: Environment) {
  await env.remove();
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    try {
      if ((await cw.environments.get(env.id)).state === "destroyed") return;
    } catch (error) {
      if (error instanceof CodewireError && error.status === 404) return;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`environment ${env.id} was not destroyed within 300 s`);
}

async function usePresetEnv(cw: Codewire, slug: string) {
  const env = await cw.environments.create(
    { project_spec: { schema_version: 1, preset: slug, working_directory: "/workspace" } },
    { wait: true, waitTimeout: 300_000 },
  );
  try {
    const result = await env.exec({ command: ["python3", "--version"] });
    if (result.exit_code !== 0) throw new Error(`exit_code=${result.exit_code}`);
    if (!result.stdout.includes("Python")) throw new Error(`stdout=${result.stdout}`);

    await env.files.upload(new TextEncoder().encode("hello"), "/workspace/test.txt");
    const files = await env.files.list("/workspace");
    if (!files.some((f) => f.name === "test.txt")) throw new Error("test.txt not found");
    const buf = await env.files.download("/workspace/test.txt");
    const content = new TextDecoder().decode(buf);
    if (content !== "hello") throw new Error(`content=${content}`);

    console.log("PASS: preset env");
  } finally {
    await removeAndWait(cw, env);
  }
}

async function testArbitraryImage() {
  const cw = new Codewire({ baseUrl, timeout: 300_000 });
  const env = await cw.environments.create(
    { project_spec: { schema_version: 1, image: "python:3.12-slim", working_directory: "/workspace" } },
    { wait: true, waitTimeout: 300_000 },
  );
  try {
    const result = await env.exec({ command: ["python3", "-c", "print(1+1)"] });
    if (result.exit_code !== 0) throw new Error(`exit_code=${result.exit_code}`);
    if (result.stdout.trim() !== "2") throw new Error(`stdout=${result.stdout}`);
    console.log("PASS: arbitrary image");
  } finally {
    await env.remove();
  }
}

testPresetEnv()
  .then(() => testArbitraryImage())
  .then(() => console.log("\nAll e2e tests passed"))
  .catch((e) => {
    console.error("FAIL:", e);
    process.exit(1);
  });
