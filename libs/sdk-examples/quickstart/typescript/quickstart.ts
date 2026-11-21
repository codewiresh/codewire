// Creates an environment, runs a command in it, writes and reads back a
// file, and deletes it. Reads CODEWIRE_API_KEY, CODEWIRE_ORG_ID and, for a
// server other than the hosted one, CODEWIRE_API_URL.
//
//   npm start

import { Codewire, type Environment } from "@codewire/sdk";

async function useEnvironment(env: Environment): Promise<void> {
  const output = await env.exec({ command: ["python3", "--version"] });
  process.stdout.write(output.stdout);
  if (output.exit_code !== 0) {
    throw new Error(`python3 exited ${output.exit_code}`);
  }

  await env.files.upload(new TextEncoder().encode("hello from TypeScript"), "/workspace/hello.txt");
  const entries = await env.files.list("/workspace");
  if (!entries.some((entry) => entry.name === "hello.txt")) {
    throw new Error("hello.txt is missing from /workspace");
  }
  const contents = new TextDecoder().decode(await env.files.download("/workspace/hello.txt"));
  if (contents !== "hello from TypeScript") {
    throw new Error("hello.txt came back different");
  }
  console.log("wrote and read back /workspace/hello.txt");
}

async function quickstart(): Promise<void> {
  const baseUrl = process.env.CODEWIRE_API_URL?.trim();
  const codewire = new Codewire({ ...(baseUrl ? { baseUrl } : {}), timeout: 300_000 });
  const env = await codewire.environments.create(
    {
      name: "typescript-sdk-quickstart",
      project_spec: { schema_version: 1, image: "python:3.12-slim", working_directory: "/workspace" },
    },
  );
  console.log("created", env.id);
  // From here on, delete the environment whether or not anything fails.
  try {
    await env.waitReady({ timeout: 300_000 });
    console.log("ready");
    await useEnvironment(env);
  } finally {
    await env.remove();
    console.log("deleted", env.id);
  }
}

quickstart().catch((error: unknown) => {
  console.error("quickstart failed:", error instanceof Error ? error.message : error);
  process.exit(1);
});
