"""Creates an environment, runs a command in it, writes and reads back a file,
and deletes it. Reads CODEWIRE_API_KEY, CODEWIRE_ORG_ID and, for a server
other than the hosted one, CODEWIRE_API_URL.

    python quickstart.py
"""

import sys

from codewire import Codewire


def use_environment(env) -> None:
    output = env.exec(command=["python3", "--version"])
    print(output["stdout"], end="")
    if output["exit_code"] != 0:
        raise RuntimeError(f"python3 exited {output['exit_code']}")

    env.files.upload(b"hello from Python", "/workspace/hello.txt")
    names = [entry["name"] for entry in env.files.list("/workspace")]
    if "hello.txt" not in names:
        raise RuntimeError("hello.txt is missing from /workspace")
    if env.files.download("/workspace/hello.txt") != b"hello from Python":
        raise RuntimeError("hello.txt came back different")
    print("wrote and read back /workspace/hello.txt")


def quickstart() -> None:
    with Codewire(timeout=300) as codewire:
        env = codewire.environments.create(
            name="python-sdk-quickstart",
            project_spec={
                "schema_version": 1,
                "image": "python:3.12-slim",
                "working_directory": "/workspace",
            },
        )
        print("created", env.id)
        # From here on, delete the environment whether or not anything fails.
        try:
            env.wait_ready(timeout=300)
            print("ready")
            use_environment(env)
        finally:
            env.remove()
            print("deleted", env.id)


if __name__ == "__main__":
    try:
        quickstart()
    except Exception as error:  # noqa: BLE001 - report any failure and exit non-zero
        print(f"quickstart failed: {error}", file=sys.stderr)
        sys.exit(1)
