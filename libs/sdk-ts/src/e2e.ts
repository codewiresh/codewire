import { Codewire } from "./index.js";

const baseUrl = process.env.CODEWIRE_SERVER_URL?.trim();
if (!baseUrl) {
  throw new Error("CODEWIRE_SERVER_URL is required for the SDK e2e suite");
}

async function testFirstPartyEnv() {
  const cw = new Codewire({ baseUrl, timeout: 300_000 });
  const env = await cw.environments.create(
    { project_spec: { schema_version: 1, preset: "python", working_directory: "/workspace" } },
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

    console.log("PASS: first-party env");
  } finally {
    await env.remove();
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

testFirstPartyEnv()
  .then(() => testArbitraryImage())
  .then(() => console.log("\nAll e2e tests passed"))
  .catch((e) => {
    console.error("FAIL:", e);
    process.exit(1);
  });
