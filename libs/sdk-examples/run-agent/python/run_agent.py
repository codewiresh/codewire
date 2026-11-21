"""Runs a coding agent in an environment on a small project, without a
terminal, and prints the change it made. Reads CODEWIRE_API_KEY,
CODEWIRE_ORG_ID and, for a server other than the hosted one,
CODEWIRE_BASE_URL.

    python run_agent.py

RUN_AGENT_COMMAND replaces the agent command, which by default is Claude
Code without a terminal. Claude Code needs a Claude credential in the
environment; a program signed in with an API key can't bind a profile
yet (#5687).
"""

import json
import os
import sys

from codewire import Codewire

PROJECT = "/workspace/project"
TASK = "The test in test_greeting.py fails. Fix greeting.py so that it passes, without changing the test."
FILES = {
    "greeting.py": 'def greet(name):\n    return "Hello " + name\n',
    "test_greeting.py": (
        "import unittest\n\nfrom greeting import greet\n\n\n"
        "class GreetingTest(unittest.TestCase):\n"
        "    def test_greets_by_name(self):\n"
        '        self.assertEqual(greet("Codewire"), "Hello, Codewire!")\n\n\n'
        'if __name__ == "__main__":\n    unittest.main()\n'
    ),
}


def run(env, command: str, timeout: int = 300) -> dict:
    return env.exec(command=["sh", "-c", command], working_dir=PROJECT, timeout=timeout)


def succeeded(what: str, result: dict) -> None:
    if result["exit_code"] != 0:
        raise RuntimeError(f"{what} exited {result['exit_code']}: {result['stderr']}")


def use_environment(env) -> None:
    succeeded("mkdir", env.exec(command=["mkdir", "-p", PROJECT]))
    for name, contents in FILES.items():
        env.files.upload(contents.encode(), f"{PROJECT}/{name}")
    succeeded(
        "git baseline",
        run(env, "git init -q && git add -A && git -c user.name=example -c user.email=example@example.com commit -qm baseline"),
    )
    if run(env, "python3 -m unittest -q test_greeting")["exit_code"] == 0:
        raise RuntimeError("the test should fail before the agent runs")
    print("uploaded the project; its test fails")

    agent = os.environ.get("RUN_AGENT_COMMAND", "").strip() or (
        f"claude -p {json.dumps(TASK)} --permission-mode acceptEdits"
    )
    succeeded("the agent", run(env, agent, 900))
    print("the agent finished")

    diff = run(env, "git diff")
    succeeded("git diff", diff)
    print(diff["stdout"], end="")
    succeeded("the test", run(env, "python3 -m unittest -q test_greeting"))
    print("the test passes")


def run_agent() -> None:
    spec = {"schema_version": 1, "image": "workspace", "working_directory": "/workspace"}
    with Codewire(timeout=300) as codewire:
        env = codewire.environments.create(name="python-sdk-run-agent", project_spec=spec)
        print("created", env.id)
        # From here on, delete the environment whether or not anything fails.
        try:
            env.wait_ready(timeout=300)
            use_environment(env)
        finally:
            env.remove()
            print("deleted", env.id)


if __name__ == "__main__":
    try:
        run_agent()
    except Exception as error:  # noqa: BLE001 - report any failure and exit non-zero
        print(f"run-agent failed: {error}", file=sys.stderr)
        sys.exit(1)
