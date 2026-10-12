#!/usr/bin/env python3
"""Read, render and check the published workspace image pin.

The pin is crates/codewire-workspace-image/src/pin.rs. Rust consumers read its
constants; scripts read them through `show`. Only `render` writes it: the
post-publish proposal in support-images.yaml, or a person refreshing the pin
from a digest that workflow published.

`inputs_sha256` identifies the image definition: SHA-256 over the exact output
of `git ls-tree -r <commit> -- images/base images/workspace` (mode, type,
object ID, a tab and the path, one entry per line, in Git's order). The cw the
image carries is refreshed through its own runtime asset and is not part of it.

`platforms` records which platforms the published image index serves; the
proposal reads them from the index itself (`index-platforms`). Every pin serves
linux/amd64 (Dev and Production Sandboxes). A pin without linux/arm64 cannot
serve an Apple silicon Mac's local VMs: `check` and the policy core warn, and
`check --release` refuses it. The checks trust the pin's own `platforms`: only
the proposal, which read them from the published index, or `render` writes
the pin, and policy refuses any other edit.

Commands:
  show [--commit REV] [FIELD]      print the pin as JSON, or one field
  inputs-sha256 [--commit REV]     the image-definition identity at REV
  agents [--commit REV]            agent CLI versions the definition pins at REV
  index-platforms                  image platforms of the OCI index on stdin
  render --digest D --source-sha S --platforms P,...
                                   rewrite the pin for a published image
  check [--commit REV] [--release] canonical form, platforms and freshness
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PIN = "crates/codewire-workspace-image/src/pin.rs"
HARBOR_REPOSITORY = "registry.example.invalid/codewire/workspace"
PUBLIC_REPOSITORY = "ghcr.io/codewiresh/workspace"
INPUT_PATHS = ("images/base", "images/workspace")
# Agent name -> the npm package the workspace image installs it from.
AGENT_PACKAGES = {
    "claude": "@anthropic-ai/claude-code",
    "codex": "@openai/codex",
    "gemini": "@google/gemini-cli",
    "kimi": "@moonshot-ai/kimi-code",
    "pi": "@earendil-works/pi-coding-agent",
}
# Older cw releases send earlier canonical digests; keep this many.
MAX_PREVIOUS = 32
FIELDS = ("digest", "harbor-image", "public-image", "platforms", "source-sha",
          "inputs-sha256", "agents", "previous-digests")
# Platforms a workspace image may serve, in the pin's order.
PLATFORMS = ("linux/amd64", "linux/arm64")
REQUIRED_PLATFORM = "linux/amd64"
RELEASE_PLATFORMS = PLATFORMS
INDEX_MEDIA_TYPES = ("application/vnd.oci.image.index.v1+json",
                     "application/vnd.docker.distribution.manifest.list.v2+json")

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class PinError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PinError(message)


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    require(result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def show_file(root: Path, commit: str, path: str) -> str | None:
    result = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{path}"],
                            capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def inputs_sha256(root: Path, commit: str) -> str:
    listing = git(root, "ls-tree", "-r", commit, "--", *INPUT_PATHS)
    require(listing.strip() != "", f"{commit} has no workspace image definition")
    return hashlib.sha256(listing.encode()).hexdigest()


def agent_versions(root: Path, commit: str) -> dict[str, str]:
    """Versions the image definition at `commit` installs, by agent name."""
    lock = show_file(root, commit, "images/workspace/agents/package-lock.json")
    versions: dict[str, str] = {}
    if lock is not None:
        packages = json.loads(lock).get("packages", {})
        for agent, package in AGENT_PACKAGES.items():
            entry = packages.get(f"node_modules/{package}")
            require(isinstance(entry, dict), f"agent lockfile does not install {package}")
            versions[agent] = entry.get("version", "")
    else:
        dockerfile = show_file(root, commit, "images/workspace/Dockerfile")
        require(dockerfile is not None, f"{commit} has no workspace Dockerfile")
        for agent, package in AGENT_PACKAGES.items():
            found = set(re.findall(re.escape(package) + r"@([0-9][0-9A-Za-z.+-]*)", dockerfile))
            require(len(found) == 1, f"workspace Dockerfile pins {package} {len(found)} times")
            versions[agent] = found.pop()
    for agent, version in versions.items():
        require(bool(VERSION_RE.match(version)), f"{agent} version {version!r} is not exact")
    return versions


def index_platforms(index) -> list[str]:
    """The image platforms of an OCI image index, in the pin's order.

    BuildKit's attestation manifests (provenance and SBOM) are not images:
    each must say unknown/unknown and reference an image entry of the same
    index, and is skipped. Anything else malformed is refused.
    """
    require(isinstance(index, dict) and index.get("mediaType") in INDEX_MEDIA_TYPES,
            "the published image is not an image index")
    manifests = index.get("manifests")
    require(isinstance(manifests, list) and manifests, "the image index lists no manifests")
    require(all(isinstance(manifest, dict) for manifest in manifests),
            "the image index has a malformed entry")
    images: dict[str, str] = {}
    attestations: list[str] = []
    for manifest in manifests:
        digest = manifest.get("digest")
        platform = manifest.get("platform")
        annotations = manifest.get("annotations") or {}
        require(isinstance(digest, str) and DIGEST_RE.match(digest) is not None
                and isinstance(platform, dict) and isinstance(annotations, dict),
                "the image index has a malformed entry")
        os_name, architecture = platform.get("os"), platform.get("architecture")
        variant = platform.get("variant")
        require(all(isinstance(value, str) for value in (os_name, architecture))
                and variant in (None, *(("v8",) if architecture == "arm64" else ())),
                f"the image index has a malformed platform {platform!r}")
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            require((os_name, architecture) == ("unknown", "unknown"),
                    "an attestation manifest names a real platform")
            reference = annotations.get("vnd.docker.reference.digest")
            require(isinstance(reference, str), "an attestation manifest references no image")
            attestations.append(reference)
            continue
        name = f"{os_name}/{architecture}"
        require(name in PLATFORMS, f"the image index serves an unexpected platform {name}")
        require(name not in images.values(), f"the image index serves {name} twice")
        images[digest] = name
    for reference in attestations:
        require(reference in images, "an attestation manifest references no image of this index")
    return [name for name in PLATFORMS if name in images.values()]


def render(pin: dict) -> str:
    digest = pin["digest"]
    # One line, as rustfmt writes a short array.
    platforms = ", ".join(f'"{item}"' for item in pin["platforms"])
    agents = "".join(f'    ("{name}", "{version}"),\n' for name, version in pin["agents"].items())
    previous = "".join(f'    "{item}",\n' for item in pin["previous_digests"])
    return (
        "// Generated by scripts/ci/images/workspace-image-pin.py. Do not edit by hand:\n"
        "// the post-publish proposal rewrites this file and policy refuses other edits.\n"
        "\n"
        "/// Content digest of the published workspace image.\n"
        f'pub const DIGEST: &str = "{digest}";\n'
        "/// The image at the Harbor repository every deployment pulls.\n"
        f'pub const HARBOR_IMAGE: &str = "{HARBOR_REPOSITORY}@{digest}";\n'
        "/// The same digest at the public GHCR mirror, pulled anonymously by local\n"
        "/// environments.\n"
        f'pub const PUBLIC_IMAGE: &str = "{PUBLIC_REPOSITORY}@{digest}";\n'
        "/// Platforms the published image index serves.\n"
        f"pub const PLATFORMS: &[&str] = &[{platforms}];\n"
        "/// Commit the image was built from.\n"
        f'pub const SOURCE_SHA: &str = "{pin["source_sha"]}";\n'
        "/// Identity of the image definition at `SOURCE_SHA`; see the generator.\n"
        f'pub const INPUTS_SHA256: &str = "{pin["inputs_sha256"]}";\n'
        "/// Agent CLI versions the image definition at `SOURCE_SHA` installs.\n"
        "pub const AGENT_VERSIONS: &[(&str, &str)] = &[\n"
        f"{agents}"
        "];\n"
        "/// Earlier published digests, newest first, that older clients may send.\n"
        + (f"pub const PREVIOUS_DIGESTS: &[&str] = &[\n{previous}];\n" if previous
           else "pub const PREVIOUS_DIGESTS: &[&str] = &[];\n")
    )


def validate(pin: dict) -> dict:
    require(bool(DIGEST_RE.match(pin["digest"])), "pin digest is not an exact sha256 digest")
    require(bool(SHA_RE.match(pin["source_sha"])), "pin source commit is not a full object ID")
    platforms = pin["platforms"]
    require(platforms == [name for name in PLATFORMS if name in platforms]
            and len(set(platforms)) == len(platforms) and set(platforms) <= set(PLATFORMS),
            "pin platforms are not a known, ordered set")
    require(REQUIRED_PLATFORM in platforms, f"pin does not serve {REQUIRED_PLATFORM}")
    require(bool(HEX64_RE.match(pin["inputs_sha256"])), "pin inputs_sha256 is not 64 hex")
    require(list(pin["agents"]) == sorted(AGENT_PACKAGES), "pin agents are not exactly the shipped agents")
    for agent, version in pin["agents"].items():
        require(bool(VERSION_RE.match(version)), f"pin {agent} version is not exact")
    previous = pin["previous_digests"]
    require(len(previous) <= MAX_PREVIOUS, "pin keeps too many previous digests")
    require(len(set(previous)) == len(previous), "pin previous digests repeat")
    require(pin["digest"] not in previous, "pin current digest is also listed as previous")
    for item in previous:
        require(bool(DIGEST_RE.match(item)), "pin previous digest is not an exact sha256 digest")
    return pin


def parse(text: str) -> dict:
    def one(name: str) -> str:
        found = re.findall(rf'^pub const {name}: &str = "([^"]*)";$', text, re.MULTILINE)
        require(len(found) == 1, f"pin does not define {name} exactly once")
        return found[0]

    def block(name: str, kind: str) -> str:
        if re.search(rf"^pub const {name}: &\[{kind}\] = &\[\];$", text, re.MULTILINE):
            return ""
        found = re.findall(rf"^pub const {name}: &\[{kind}\] = &\[\n(.*?)^\];$", text,
                           re.MULTILINE | re.DOTALL)
        require(len(found) == 1, f"pin does not define {name} exactly once")
        return found[0]

    agents = dict(re.findall(r'^    \("([a-z]+)", "([^"]*)"\),$', block("AGENT_VERSIONS", r"\(&str, &str\)"),
                             re.MULTILINE))
    previous = re.findall(r'^    "([^"]*)",$', block("PREVIOUS_DIGESTS", "&str"), re.MULTILINE)
    found = re.findall(r'^pub const PLATFORMS: &\[&str\] = &\[(.*)\];$', text, re.MULTILINE)
    require(len(found) == 1, "pin does not define PLATFORMS exactly once")
    platforms = re.findall(r'"([^"]*)"', found[0])
    pin = validate({
        "digest": one("DIGEST"),
        "platforms": platforms,
        "source_sha": one("SOURCE_SHA"),
        "inputs_sha256": one("INPUTS_SHA256"),
        "agents": agents,
        "previous_digests": previous,
    })
    require(one("HARBOR_IMAGE") == f"{HARBOR_REPOSITORY}@{pin['digest']}", "pin Harbor image is not the digest")
    require(one("PUBLIC_IMAGE") == f"{PUBLIC_REPOSITORY}@{pin['digest']}", "pin public image is not the digest")
    require(render(pin) == text, "pin is not in the generator's exact form; regenerate it with `render`")
    return pin


def read_pin(root: Path, commit: str | None) -> dict:
    if commit is None:
        path = root / PIN
        require(path.is_file() and not path.is_symlink(), f"{PIN} is missing")
        text = path.read_text(encoding="utf-8")
    else:
        text = show_file(root, commit, PIN)
        require(text is not None, f"{commit} has no {PIN}")
    return parse(text)


def field(pin: dict, name: str):
    return {
        "digest": pin["digest"],
        "harbor-image": f"{HARBOR_REPOSITORY}@{pin['digest']}",
        "public-image": f"{PUBLIC_REPOSITORY}@{pin['digest']}",
        "platforms": pin["platforms"],
        "source-sha": pin["source_sha"],
        "inputs-sha256": pin["inputs_sha256"],
        "agents": pin["agents"],
        "previous-digests": pin["previous_digests"],
    }[name]


def freshness(root: Path, pin: dict, commit: str) -> str | None:
    """None when the pin was built from the definition at `commit`."""
    current = inputs_sha256(root, commit)
    if current == pin["inputs_sha256"]:
        return None
    return (f"the workspace image definition at {commit} differs from the published pin "
            f"(built from {pin['source_sha'][:12]}); support-images publishes the image "
            "after merge and proposes the new pin")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=os.environ.get("CODEWIRE_WORKSPACE_PIN_ROOT", str(ROOT)))
    commands = parser.add_subparsers(dest="command", required=True)
    show_parser = commands.add_parser("show")
    show_parser.add_argument("--commit")
    show_parser.add_argument("field", nargs="?", choices=FIELDS)
    for name in ("inputs-sha256", "agents"):
        commands.add_parser(name).add_argument("--commit", default="HEAD")
    commands.add_parser("index-platforms")
    render_parser = commands.add_parser("render")
    render_parser.add_argument("--digest", required=True)
    render_parser.add_argument("--source-sha", required=True)
    render_parser.add_argument("--platforms", required=True,
                               help="comma-separated platforms the published index serves")
    check_parser = commands.add_parser("check")
    check_parser.add_argument("--commit")
    check_parser.add_argument("--release", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command == "show":
            pin = read_pin(root, args.commit)
            value = field(pin, args.field) if args.field else {name: field(pin, name) for name in FIELDS}
            print(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
        elif args.command == "inputs-sha256":
            print(inputs_sha256(root, args.commit))
        elif args.command == "agents":
            print(json.dumps(agent_versions(root, args.commit), sort_keys=True))
        elif args.command == "index-platforms":
            try:
                index = json.load(sys.stdin)
            except json.JSONDecodeError as error:
                raise PinError(f"the image index is not JSON: {error}") from None
            print(",".join(index_platforms(index)))
        elif args.command == "render":
            require(bool(DIGEST_RE.match(args.digest)), "--digest must be an exact sha256 digest")
            require(bool(SHA_RE.match(args.source_sha)), "--source-sha must be a full object ID")
            old = read_pin(root, None)
            previous = [old["digest"], *old["previous_digests"]] if old["digest"] != args.digest \
                else list(old["previous_digests"])
            previous = [item for item in dict.fromkeys(previous) if item != args.digest][:MAX_PREVIOUS]
            pin = validate({
                "digest": args.digest,
                "platforms": args.platforms.split(","),
                "source_sha": args.source_sha,
                "inputs_sha256": inputs_sha256(root, args.source_sha),
                "agents": dict(sorted(agent_versions(root, args.source_sha).items())),
                "previous_digests": previous,
            })
            text = render(pin)
            (root / PIN).write_text(text, encoding="utf-8")
            parse(text)
            print(f"workspace image pin: {args.digest} from {args.source_sha}")
        elif args.command == "check":
            commit = args.commit or "HEAD"
            pin = read_pin(root, args.commit)
            missing = [name for name in RELEASE_PLATFORMS if name not in pin["platforms"]]
            if missing:
                message = (f"the pinned image does not serve {', '.join(missing)}; local VMs on "
                           "Apple silicon need a multi-platform workspace image")
                if args.release:
                    print(f"workspace image pin: {message}", file=sys.stderr)
                    return 1
                print(f"::warning::workspace image pin: {message}")
            stale = freshness(root, pin, commit)
            if stale is None:
                print(f"workspace image pin: fresh ({pin['digest']} from {pin['source_sha'][:12]})")
            elif args.release:
                print(f"workspace image pin: {stale}; land the proposed pin before releasing",
                      file=sys.stderr)
                return 1
            else:
                print(f"::warning::workspace image pin: {stale}")
    except PinError as error:
        print(f"workspace image pin: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
