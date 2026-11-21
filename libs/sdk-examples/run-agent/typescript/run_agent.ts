// Runs a coding agent in an environment on a small project, without a
// terminal, and prints the change it made. Reads CODEWIRE_API_KEY,
// CODEWIRE_ORG_ID and, for a server other than the hosted one,
// CODEWIRE_API_URL.
//
//   npm start
//
// RUN_AGENT_COMMAND replaces the agent command, which by default is Claude
// Code without a terminal. Claude Code needs a Claude credential in the
// environment; a program signed in with an API key can't bind a profile
// yet (#5687).

import { Codewire, type Environment } from "@codewire/sdk";

const project = "/workspace/project";
const task =
  "The test in test_greeting.py fails. Fix greeting.py so that it passes, without changing the test.";
const files: Record<string, string> = {
  "greeting.py": 'def greet(name):\n    return "Hello " + name\n',
  "test_greeting.py":
    "import unittest\n\nfrom greeting import greet\n\n\n" +
    "class GreetingTest(unittest.TestCase):\n" +
    "    def test_greets_by_name(self):\n" +
    '        self.assertEqual(greet("Codewire"), "Hello, Codewire!")\n\n\n' +
    'if __name__ == "__main__":\n    unittest.main()\n',
};

async function run(env: Environment, command: string, timeout = 300) {
  const output = await env.exec({ command: ["sh", "-c", command], working_dir: project, timeout });
  return output;
}

async function useEnvironment(env: Environment): Promise<void> {
  const created = await env.exec({ command: ["mkdir", "-p", project] });
  if (created.exit_code !== 0) throw new Error(`mkdir exited ${created.exit_code}`);
  for (const [name, contents] of Object.entries(files)) {
    await env.files.upload(new TextEncoder().encode(contents), `${project}/${name}`);
  }
  const baseline = await run(
    env,
    "git init -q && git add -A && git -c user.name=example -c user.email=example@example.com commit -qm baseline",
  );
  if (baseline.exit_code !== 0) throw new Error(`git baseline exited ${baseline.exit_code}: ${baseline.stderr}`);
  const before = await run(env, "python3 -m unittest -q test_greeting");
  if (before.exit_code === 0) throw new Error("the test should fail before the agent runs");
  console.log("uploaded the project; its test fails");

  const agent =
    process.env.RUN_AGENT_COMMAND?.trim() ||
    `claude -p ${JSON.stringify(task)} --permission-mode acceptEdits`;
  const result = await run(env, agent, 900);
  if (result.exit_code !== 0) throw new Error(`the agent exited ${result.exit_code}: ${result.stderr}`);
  console.log("the agent finished");

  const diff = await run(env, "git diff");
  process.stdout.write(diff.stdout);
  const tests = await run(env, "python3 -m unittest -q test_greeting");
  if (tests.exit_code !== 0) throw new Error(`the test still fails: ${tests.stderr}`);
  console.log("the test passes");
}

async function runAgent(): Promise<void> {
  const baseUrl = process.env.CODEWIRE_API_URL?.trim();
  const codewire = new Codewire({ ...(baseUrl ? { baseUrl } : {}), timeout: 300_000 });
  const env = await codewire.environments.create(
    {
      name: "typescript-sdk-run-agent",
      project_spec: {
        schema_version: 1,
        image: "workspace",
        working_directory: "/workspace",
      },
    },
  );
  console.log("created", env.id);
  // From here on, delete the environment whether or not anything fails.
  try {
    await env.waitReady({ timeout: 300_000 });
    await useEnvironment(env);
  } finally {
    await env.remove();
    console.log("deleted", env.id);
  }
}

runAgent().catch((error: unknown) => {
  console.error("run-agent failed:", error instanceof Error ? error.message : error);
  process.exit(1);
});
