"""Committed agent tooling runs the reviewed Playwright MCP launch, unchanged.

.mcp.json starts one Playwright MCP server through Docker with exactly the
reviewed command. Any other change, such as a new image, a mount, an added
capability, an environment value or --privileged, alters that review and fails
here until REVIEWED_MCP is updated with it (#1382). What the command means:

- The image is pinned by its multi-architecture digest, not a mutable tag.
- The Chromium sandbox is on. The image's own entrypoint passes --no-sandbox, and
  Playwright adds that flag itself unless told otherwise, so an unchanged image
  would run unsandboxed whatever these arguments said. The command replaces the
  entrypoint and passes --sandbox.
- Docker's default seccomp profile refuses the namespaces the sandbox needs
  unless the container holds CAP_SYS_ADMIN. The sandbox needs no capability, only
  those two syscalls, so scripts/dev/playwright-mcp-seccomp.json is Docker's
  default (moby/profiles 6fe7deb1b9fb, Apache-2.0) plus one rule allowing clone
  and unshare. The container's user can already create user namespaces on the
  host; inside the container it now can too, and that is the extra kernel
  surface this accepts. setns and clone3 stay refused.
- The profile path comes from git because .mcp.json has no project-directory
  variable, and a relative path fails for a session started in a subdirectory.
- Host networking stays: a bridge network cannot reach a dev server bound to
  loopback on the host, and dev origins expect localhost. The browser can
  therefore reach every loopback service on the workstation.

.claude/settings.json keeps the attribution preferences and sets no
environment, so every clone commits with its own Git identity.
"""

from .shared import *

PLAYWRIGHT_MCP_IMAGE = (
    "mcr.microsoft.com/playwright/mcp@sha256:"
    "690763cbb437ee7233f538a953bb5390bf03791eb5c965b471e59d17a6132fcb"
)
PLAYWRIGHT_SECCOMP_PROFILE = "scripts/dev/playwright-mcp-seccomp.json"
PLAYWRIGHT_MCP_LAUNCH = (
    "exec docker run -i --rm --init --network host --shm-size=2gb "
    f'--security-opt seccomp="$(git rev-parse --show-toplevel)/{PLAYWRIGHT_SECCOMP_PROFILE}" '
    f"--entrypoint node {PLAYWRIGHT_MCP_IMAGE} /app/cli.js --headless --browser chromium --sandbox"
)
REVIEWED_MCP = {
    "mcpServers": {
        "playwright": {
            "type": "stdio",
            "command": "sh",
            "args": ["-c", PLAYWRIGHT_MCP_LAUNCH],
            "env": {},
        }
    }
}
# The one rule the profile adds to Docker's default, and that default's digest.
SANDBOX_SECCOMP_RULE = {"names": ["clone", "unshare"], "action": "SCMP_ACT_ALLOW"}
DOCKER_DEFAULT_SECCOMP_SHA256 = "2ebf3bdba229d3d972cfc3721001306de96cc5113a14b29cb510c2edd91ca84a"
ATTRIBUTION = {"attribution": {"commit": "", "pr": ""}, "includeCoAuthoredBy": False}


def seccomp_violations(seccomp_text: str) -> list[str]:
    """The profile must be Docker's default plus the sandbox rule, and nothing else."""
    refused = (
        f"{PLAYWRIGHT_SECCOMP_PROFILE} must be Docker's default seccomp profile plus only "
        "the rule allowing clone and unshare; a wider profile needs review and an update "
        "in scripts/checks/repo_policy/mcp_settings.py")
    try:
        profile = json.loads(seccomp_text)
        rules = profile["syscalls"]
        default = {**profile, "syscalls": rules[:-1]}
    except (json.JSONDecodeError, KeyError, TypeError):
        return [refused]
    digest = hashlib.sha256(json.dumps(default, sort_keys=True).encode()).hexdigest()
    return [] if rules[-1:] == [SANDBOX_SECCOMP_RULE] and digest == DOCKER_DEFAULT_SECCOMP_SHA256 else [refused]


def violations_from(mcp_text: str, claude_text: str, seccomp_text: str) -> list[str]:
    """Every way the committed agent tooling departs from the reviewed shape."""
    failures = seccomp_violations(seccomp_text)
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
    reviewed_seccomp = read_text(PLAYWRIGHT_SECCOMP_PROFILE)
    if failures := violations_from(json.dumps(REVIEWED_MCP), reviewed_claude, reviewed_seccomp):
        raise RuntimeError(f"self-test: the reviewed shape was refused: {failures}")

    def with_server(change: Callable[[dict], None]) -> str:
        mcp = copy.deepcopy(REVIEWED_MCP)
        change(mcp["mcpServers"]["playwright"])
        return json.dumps(mcp)

    def launch(old: str, new: str) -> str:
        if old not in PLAYWRIGHT_MCP_LAUNCH:
            raise RuntimeError(f"self-test: {old} is not in the launch")
        def change(server: dict) -> None:
            server["args"][1] = PLAYWRIGHT_MCP_LAUNCH.replace(old, new)
        return with_server(change)

    def run_flags(*flags: str) -> str:
        return launch("docker run ", f"docker run {' '.join(flags)} ")

    def seccomp(change: Callable[[dict], None]) -> str:
        profile = json.loads(reviewed_seccomp)
        change(profile)
        return json.dumps(profile)

    reviewed_mcp = json.dumps(REVIEWED_MCP)
    wider_rule = {"names": ["clone", "unshare", "setns"], "action": "SCMP_ACT_ALLOW"}
    cases = {
        "mutable latest tag": (launch(PLAYWRIGHT_MCP_IMAGE, "mcr.microsoft.com/playwright/mcp:latest"), reviewed_claude, reviewed_seccomp),
        "other digest": (launch(PLAYWRIGHT_MCP_IMAGE, "mcr.microsoft.com/playwright/mcp@sha256:" + "0" * 64), reviewed_claude, reviewed_seccomp),
        "--no-sandbox": (launch("--sandbox", "--no-sandbox"), reviewed_claude, reviewed_seccomp),
        "no --sandbox, so Playwright adds --no-sandbox": (launch(" --sandbox", ""), reviewed_claude, reviewed_seccomp),
        "the image's entrypoint, which passes --no-sandbox": (
            launch("--entrypoint node ", "").replace("/app/cli.js ", ""), reviewed_claude, reviewed_seccomp),
        "seccomp off": (launch('seccomp="$(git rev-parse --show-toplevel)/' + PLAYWRIGHT_SECCOMP_PROFILE + '"', "seccomp=unconfined"), reviewed_claude, reviewed_seccomp),
        "--privileged": (run_flags("--privileged"), reviewed_claude, reviewed_seccomp),
        "host mount": (run_flags("-v", "/:/host"), reviewed_claude, reviewed_seccomp),
        "added capability": (run_flags("--cap-add", "SYS_ADMIN"), reviewed_claude, reviewed_seccomp),
        "docker env credential": (run_flags("-e", "API_TOKEN"), reviewed_claude, reviewed_seccomp),
        "server env credential": (
            with_server(lambda server: server.__setitem__("env", {"API_TOKEN": "x"})), reviewed_claude, reviewed_seccomp),
        "unparsable .mcp.json": ("{not json", reviewed_claude, reviewed_seccomp),
        "seccomp default allows everything": (
            reviewed_mcp, reviewed_claude, seccomp(lambda profile: profile.__setitem__("defaultAction", "SCMP_ACT_ALLOW"))),
        "seccomp rule widened": (
            reviewed_mcp, reviewed_claude, seccomp(lambda profile: profile["syscalls"].__setitem__(-1, wider_rule))),
        "seccomp rule added": (
            reviewed_mcp, reviewed_claude, seccomp(lambda profile: profile["syscalls"].insert(0, wider_rule))),
        "seccomp sandbox rule missing": (
            reviewed_mcp, reviewed_claude, seccomp(lambda profile: profile["syscalls"].pop())),
        "unparsable seccomp profile": (reviewed_mcp, reviewed_claude, "{not json"),
        "Git identity override": (
            reviewed_mcp, json.dumps({**ATTRIBUTION, "env": {"GIT_AUTHOR_NAME": "Someone"}}), reviewed_seccomp),
        "dropped attribution preference": (
            reviewed_mcp, json.dumps({"attribution": ATTRIBUTION["attribution"]}), reviewed_seccomp),
    }
    for name, (mcp_text, claude_text, seccomp_text) in cases.items():
        if not violations_from(mcp_text, claude_text, seccomp_text):
            raise RuntimeError(f"self-test: {name} was accepted")


def check_mcp_settings(args: argparse.Namespace) -> int:
    failures = violations_from(
        read_text(".mcp.json"), read_text(".claude/settings.json"), read_text(PLAYWRIGHT_SECCOMP_PROFILE))
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
    print(f"mcp settings: OK (reviewed Playwright MCP launch and seccomp profile, no committed environment{suffix})")
    return 0
