"""The published workspace image pin is the only place its digest is written.

crates/codewire-workspace-image/src/pin.rs holds the current digest and the
earlier ones older clients still send. Every consumer imports it; a copy goes
stale the moment support-images.yaml publishes a new image. This check refuses
any copy of a pin digest, and any workspace digest that is neither synthetic
nor a recorded fixture or historical reference. It also reports a pin whose
image was built from a different image definition than the tree's: a warning
here, and a refusal for a release (`workspace-image-pin.py check --release`).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile

from .shared import *

PIN_TOOL = ROOT / "scripts/ci/images/workspace-image-pin.py"
WORKSPACE_DIGEST = re.compile(r"workspace@sha256:([0-9a-f]{64})")
HEX64 = re.compile(r"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
# Obviously synthetic digests: one repeated hex digit, or a counting pattern.
SYNTHETIC = re.compile(r"^(?:([0-9a-f])\1{63}|(?:0123456789abcdef){4})$")
# Real workspace digests that are deliberately not the pin, and where each may
# appear. Each is a fixture or a record, never a default a consumer pulls.
RECORDED_DIGESTS: dict[str, tuple[tuple[str, ...], str]] = {
    "2058b7f1fd76f6f77b1dba596a9b54c698c049380e5ace6a0493f10a9d41e1b4": (
        ("crates/codewire-orchestration/src/",),
        "a non-canonical public workspace image in orchestration tests",
    ),
    "cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510": (
        (".gitea/workflows/ci.yaml", "scripts/ci/verify/kind/common.sh",
         "scripts/ci/tests/test-kind-e2e-suites.sh"),
        "the reviewed oci-approved Kind copy, updated by its own approval",
    ),
    "7645bc90934a603724751a2363657933f673eaf469857e64e3462c7042fd1808": (
        ("scripts/runtime/tests/test-resolve-coco-support-lock.sh",),
        "a registry reply fixture in the CoCo support lock test",
    ),
    "d864f5f3afec8f7e56e38ee8f6aaba2af33ed2d984316a90c68f3dd5fcdb2d9a": (
        ("docs/",),
        "the historical confidential product proof",
    ),
}


def load_pin_tool():
    spec = importlib.util.spec_from_file_location("workspace_image_pin_tool", PIN_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scan(files: dict[str, str], pin_path: str, pin: dict) -> list[str]:
    """Policy failures for these repository files, by path."""
    pinned = {pin["digest"].removeprefix("sha256:")}
    pinned.update(item.removeprefix("sha256:") for item in pin["previous_digests"])
    failures: list[str] = []
    for path, text in sorted(files.items()):
        if path == pin_path:
            continue
        for match in HEX64.finditer(text):
            if match.group(1) in pinned:
                failures.append(
                    f"workspace image pin: {path}:{line_number(text, match.start())} copies a "
                    "published pin digest; import codewire-workspace-image or run "
                    "scripts/ci/images/workspace-image-pin.py show")
        for match in WORKSPACE_DIGEST.finditer(text):
            digest = match.group(1)
            if digest in pinned or SYNTHETIC.match(digest):
                continue
            recorded = RECORDED_DIGESTS.get(digest)
            if recorded and path.startswith(recorded[0]):
                continue
            failures.append(
                f"workspace image pin: {path}:{line_number(text, match.start())} names workspace "
                f"digest {digest[:12]}, which is neither the published pin nor a recorded "
                "fixture or historical reference")
    return failures


def tracked_text_files() -> dict[str, str]:
    files: dict[str, str] = {}
    for rel in run(["git", "ls-files", "-z"], check=True).stdout.split("\0"):
        if not rel:
            continue
        path = ROOT / rel
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            continue
        try:
            files[rel] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return files


def self_test(tool) -> list[str]:
    failures: list[str] = []
    digest = "sha256:" + "8" * 63 + "9"
    previous = "sha256:" + "7" * 63 + "6"
    pin = {"digest": digest, "previous_digests": [previous]}
    hexd, hexp = digest[7:], previous[7:]
    cases = {
        "the pin file itself": ({"crates/codewire-workspace-image/src/pin.rs": hexd}, 0),
        "a copied current digest": ({"crates/codewire-cli/src/x.rs": f"ghcr.io/codewiresh/workspace@sha256:{hexd}"}, 1),
        "a URL-encoded copy": ({"crates/x.rs": f"workspace%40sha256%3A{hexp}"}, 1),
        "a synthetic fixture": ({"crates/x.rs": "registry.example/workspace@sha256:" + "a" * 64}, 0),
        "an unknown real digest": ({"scripts/x.sh": "ghcr.io/codewiresh/workspace@sha256:" + "1234abcd" * 8}, 1),
        "a recorded digest in place": ({"scripts/ci/verify/kind/common.sh":
                                        "registry.example.invalid/oci-approved/codewire/workspace@sha256:"
                                        "cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510"}, 0),
        "a recorded digest elsewhere": ({"crates/x.rs":
                                         "registry.example.invalid/oci-approved/codewire/workspace@sha256:"
                                         "cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510"}, 1),
        "a short-name copy": ({"docs/x.md": f"workspace@sha256:{hexp}"}, 1),
    }
    for name, (files, expected) in cases.items():
        found = len(scan(files, "crates/codewire-workspace-image/src/pin.rs", pin))
        if found != expected:
            failures.append(f"workspace image pin self-test: {name}: {found} failures, expected {expected}")

    # Freshness: a pin built from the tree's definition is fresh; a changed
    # definition warns on a branch and refuses a release.
    with tempfile.TemporaryDirectory(prefix="workspace-image-pin-") as directory:
        repo = Path(directory)
        def git(*args: str) -> str:
            return run(["git", "-C", str(repo), *args], check=True).stdout.strip()
        git("init", "-q")
        (repo / "images/workspace").mkdir(parents=True)
        (repo / "images/base").mkdir(parents=True)
        (repo / "images/base/apt").write_text("base\n")
        (repo / "images/workspace/Dockerfile").write_text(
            "".join(f"RUN npm install -g {package}@1.0.0\n" for package in tool.AGENT_PACKAGES.values()))
        git("add", "-A")
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-q", "-m", "definition")
        source = git("rev-parse", "HEAD")
        pin_text = tool.render(tool.validate({
            "digest": digest, "platforms": list(tool.PLATFORMS), "source_sha": source,
            "inputs_sha256": tool.inputs_sha256(repo, source),
            "agents": dict(sorted(tool.agent_versions(repo, source).items())),
            "previous_digests": [previous],
        }))
        target = repo / tool.PIN
        target.parent.mkdir(parents=True)
        target.write_text(pin_text)
        root = ["--root", str(repo)]

        def check(*args: str) -> int:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return tool.main([*root, "check", *args])
        if check("--release") != 0:
            failures.append("workspace image pin self-test: a fresh pin was refused for release")
        # Platforms: every pin serves linux/amd64; one without linux/arm64
        # warns on a branch and refuses a release.
        amd64_only = pin_text.replace('"linux/amd64", "linux/arm64"', '"linux/amd64"')
        target.write_text(amd64_only)
        if check() != 0:
            failures.append("workspace image pin self-test: an amd64-only pin failed a branch check")
        if check("--release") == 0:
            failures.append("workspace image pin self-test: an amd64-only pin was accepted for release")
        target.write_text(pin_text.replace('"linux/amd64", "linux/arm64"', '"linux/arm64"'))
        if check() == 0:
            failures.append("workspace image pin self-test: a pin without linux/amd64 was accepted")
        target.write_text(pin_text)
        (repo / "images/workspace/Dockerfile").write_text("RUN npm install -g @openai/codex@2.0.0\n")
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-qam", "change the definition")
        if check() != 0:
            failures.append("workspace image pin self-test: a stale pin failed a branch check")
        if check("--release") == 0:
            failures.append("workspace image pin self-test: a stale pin was accepted for release")
        target.write_text(pin_text.replace("pub const DIGEST", "pub const  DIGEST"))
        if check() == 0:
            failures.append("workspace image pin self-test: a hand-edited pin was accepted")

    # The proposal reads platforms from the published index; attestation
    # manifests are not images, and anything but an index is refused.
    def entry(seed: str, os_name: str, architecture: str, references: str | None = None,
              variant: str | None = None) -> dict:
        platform = {"os": os_name, "architecture": architecture}
        if variant:
            platform["variant"] = variant
        item = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": f"sha256:{seed * 64}",
                "size": 1, "platform": platform}
        if references:
            item["annotations"] = {"vnd.docker.reference.type": "attestation-manifest",
                                   "vnd.docker.reference.digest": f"sha256:{references * 64}"}
        return item
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [entry("b", "linux", "arm64", variant="v8"), entry("a", "linux", "amd64"),
                           entry("c", "unknown", "unknown", references="a")]}
    if tool.index_platforms(index) != ["linux/amd64", "linux/arm64"]:
        failures.append("workspace image pin self-test: index platforms were not read in pin order")
    for name, bad in {
        "a plain manifest": {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
        "an unexpected platform": {**index, "manifests": [*index["manifests"], entry("d", "linux", "s390x")]},
        "a repeated platform": {**index, "manifests": [*index["manifests"], entry("d", "linux", "amd64")]},
        "a v8 variant on amd64": {**index, "manifests": [entry("d", "linux", "amd64", variant="v8")]},
        "an attestation with a real platform": {
            **index, "manifests": [*index["manifests"], entry("d", "linux", "arm64", references="a")]},
        "an attestation of another index's image": {
            **index, "manifests": [*index["manifests"], entry("d", "unknown", "unknown", references="e")]},
        "a malformed entry": {**index, "manifests": [*index["manifests"], "linux/amd64"]},
    }.items():
        try:
            tool.index_platforms(bad)
        except tool.PinError:
            continue
        failures.append(f"workspace image pin self-test: {name} was read as an image index")
    return failures


def check_workspace_image_pin(args: argparse.Namespace) -> int:
    tool = load_pin_tool()
    if args.self_test:
        failures = self_test(tool)
        if failures:
            for failure in failures:
                print(failure, file=sys.stderr)
            return 1
        print("workspace image pin: OK (self-test)")
        return 0
    try:
        pin = tool.read_pin(ROOT, None)
    except tool.PinError as error:
        print(f"workspace image pin: {error}", file=sys.stderr)
        return 1
    failures = scan(tracked_text_files(), tool.PIN, pin)
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    missing = [name for name in tool.RELEASE_PLATFORMS if name not in pin["platforms"]]
    if missing:
        print(f"::warning::workspace image pin: the pinned image does not serve {', '.join(missing)}; "
              "a release refuses it until support-images publishes a multi-platform index")
    stale = tool.freshness(ROOT, pin, "HEAD")
    if stale:
        print(f"::warning::workspace image pin: {stale}")
    print(f"workspace image pin: OK ({pin['digest']})")
    return 0
