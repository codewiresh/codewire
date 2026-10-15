"""Committed agent tooling runs the reviewed Playwright MCP launch, unchanged.

.mcp.json starts one Playwright MCP server through Docker with exactly the
reviewed arguments: the multi-architecture image digest instead of a mutable
tag, host networking so the browser reaches loopback dev servers on Linux, and
the headless mode and shared memory the browser needs. Any other change, such
as a new image, a mount, an added capability, an environment value,
--privileged or --no-sandbox, alters that review and fails here until
REVIEWED_MCP is updated with it (#1382).

.claude/settings.json keeps the attribution preferences and sets no
environment, so every clone commits with its own Git identity.
"""

from .shared import *

PLAYWRIGHT_MCP_IMAGE = (
    "mcr.microsoft.com/playwright/mcp@sha256:"
    "3d871c22ea2d4cca0966e2cfb1860e1cb03eb7353725a3d6cffd133296fb04eb"
)
REVIEWED_MCP = {
    "mcpServers": {
        "playwright": {
            "type": "stdio",
            "command": "docker",
            "args": [
                "run",
                "-i",
                "--rm",
                "--init",
                "--network",
                "host",
                "--shm-size=2gb",
                PLAYWRIGHT_MCP_IMAGE,
                "--headless",
            ],
            "env": {},
        }
    }
}
ATTRIBUTION = {"attribution": {"commit": "", "pr": ""}, "includeCoAuthoredBy": False}


def violations_from(mcp_text: str, claude_text: str) -> list[str]:
    """Every way the committed agent tooling departs from the reviewed shape."""
    failures: list[str] = []
    try:
        mcp = json.loads(mcp_text)
    except json.JSONDecodeError as error:
        failures.append(f".mcp.json does not parse: {error}")
    else:
        if mcp != REVIEWED_MCP:
            failures.append(
                ".mcp.json differs from the reviewed Playwright MCP launch; a new image, "
                "argument, mount or environment value needs review and an update to "
                "REVIEWED_MCP in scripts/checks/repo_policy/mcp_settings.py (#1382)")
    try:
        claude = json.loads(claude_text)
    except json.JSONDecodeError as error:
        failures.append(f".claude/settings.json does not parse: {error}")
    else:
        if not isinstance(claude, dict):
            failures.append(".claude/settings.json must be an object")
        else:
            if claude.get("env"):
                failures.append(
                    ".claude/settings.json sets env; each clone commits with its own Git "
                    "identity, so committed settings override no environment")
            for key, value in ATTRIBUTION.items():
                if claude.get(key) != value:
                    failures.append(f".claude/settings.json must keep {key} = {json.dumps(value)}")
    return failures


def self_test() -> None:
    """Prove the guard accepts the reviewed shape and refuses each regression."""
    reviewed_claude = json.dumps(ATTRIBUTION)
    if failures := violations_from(json.dumps(REVIEWED_MCP), reviewed_claude):
        raise RuntimeError(f"self-test: the reviewed shape was refused: {failures}")

    def with_server(change: Callable[[dict], None]) -> str:
        mcp = copy.deepcopy(REVIEWED_MCP)
        change(mcp["mcpServers"]["playwright"])
        return json.dumps(mcp)

    def run_flags(*flags: str) -> str:
        def change(server: dict) -> None:
            server["args"][1:1] = flags
        return with_server(change)

    def image(value: str) -> str:
        def change(server: dict) -> None:
            args = server["args"]
            args[args.index(PLAYWRIGHT_MCP_IMAGE)] = value
        return with_server(change)

    reviewed_mcp = json.dumps(REVIEWED_MCP)
    cases = {
        "mutable latest tag": (image("mcr.microsoft.com/playwright/mcp:latest"), reviewed_claude),
        "other digest": (image("mcr.microsoft.com/playwright/mcp@sha256:" + "0" * 64), reviewed_claude),
        "--no-sandbox": (with_server(lambda server: server["args"].append("--no-sandbox")), reviewed_claude),
        "--privileged": (run_flags("--privileged"), reviewed_claude),
        "host mount": (run_flags("-v", "/:/host"), reviewed_claude),
        "added capability": (run_flags("--cap-add", "SYS_ADMIN"), reviewed_claude),
        "docker env credential": (run_flags("-e", "API_TOKEN"), reviewed_claude),
        "server env credential": (
            with_server(lambda server: server.__setitem__("env", {"API_TOKEN": "x"})), reviewed_claude),
        "unparsable .mcp.json": ("{not json", reviewed_claude),
        "Git identity override": (
            reviewed_mcp, json.dumps({**ATTRIBUTION, "env": {"GIT_AUTHOR_NAME": "Someone"}})),
        "dropped attribution preference": (
            reviewed_mcp, json.dumps({"attribution": ATTRIBUTION["attribution"]})),
    }
    for name, (mcp_text, claude_text) in cases.items():
        if not violations_from(mcp_text, claude_text):
            raise RuntimeError(f"self-test: {name} was accepted")


def check_mcp_settings(args: argparse.Namespace) -> int:
    failures = violations_from(read_text(".mcp.json"), read_text(".claude/settings.json"))
    if args.self_test:
        try:
            self_test()
        except RuntimeError as error:
            failures.append(str(error))
    for failure in failures:
        print(f"::error::mcp settings: {failure}", file=sys.stderr)
    if failures:
        return 1
    suffix = " and self-test" if args.self_test else ""
    print(f"mcp settings: OK (reviewed Playwright MCP launch, no committed environment{suffix})")
    return 0
