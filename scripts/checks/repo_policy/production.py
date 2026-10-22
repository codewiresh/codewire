from .shared import *

def check_production_source_ownership(args: argparse.Namespace) -> int:
    try:
        files = load_production_source_files(Path(args.root).resolve())
        tag = validate_production_source(files)
        if args.self_test:
            production_source_self_test(files)
        print(f"production source ownership: OK ({tag})")
        return 0
    except Exception as error:  # noqa: BLE001 - repo check script
        print(f"production source ownership: {error}", file=sys.stderr)
        return 1


def collect_files(root: Path, directory: Path, files: dict[str, str]) -> None:
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.stat().st_size > 0:
            files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")


def one_match(text: str, pattern: str, label: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(f"{label}: expected exactly one immutable source pin, found {len(matches)}")
    return matches[0]


def load_production_source_files(root: Path) -> dict[str, Any]:
    def read(path: str) -> str:
        return (root / path).read_text(encoding="utf-8")

    retired_control_paths = [
        ".gitea/workflows/observe-prod-release.yaml",
        "scripts/ci/codewire-prod-observer-authz.tsv",
        "scripts/ci/codewire-prod-observer-minter-authz.tsv",
        "scripts/ci/deploy-prod-observer.sh",
        "scripts/ci/observe-deploy-dev.py",
        "scripts/ci/test-deploy-prod-observer.sh",
        "scripts/ci/test-observe-deploy-dev.py",
        "scripts/ci/test-observe-prod-release.sh",
        "scripts/ci/verify-prod-observer-receipt.sh",
        "scripts/ci/promote-image-bundle.sh",
        "scripts/ci/promotion-receipt.py",
        "scripts/ci/test-promote-image-bundle.sh",
        "scripts/ci/test-promotion-receipt.py",
        # The legacy source render. Production renders only in codewire/deploy
        # promote-prod, which dispatch-deploy-prod.sh starts.
        "scripts/ci/deploy/deploy-prod.sh",
        "scripts/ci/tests/test-deploy-prod-render.sh",
    ]
    production_files: dict[str, str] = {}
    for directory in [
        "deployments/k8s/overlays/production",
        "deployments/k8s/flux/production",
        "deployments/k8s/flux/temporal-production",
        "deployments/k8s/mesh-production",
    ]:
        collect_files(root, root / directory, production_files)

    return {
        "kustomization": read("deployments/k8s/overlays/production/kustomization.yaml"),
        "daemon_patch": read("deployments/k8s/overlays/production/config-images.yaml"),
        "mesh_release": read("deployments/k8s/flux/production/mesh-helmrelease.yaml"),
        "ci_workflow": read(".gitea/workflows/ci.yaml"),
        "production_workflow": read(".gitea/workflows/deploy-prod.yaml"),
        "production_dispatch": read("scripts/ci/deploy/dispatch-deploy-prod.sh"),
        "production_oidc_fetcher": read(
            "scripts/ci/setup/fetch-forgejo-deploy-prod-token.sh"
        ),
        "production_files": production_files,
        "retired_control_paths_present": [
            path for path in retired_control_paths if (root / path).exists()
        ],
        "retired_temporal_preflight_present": (root / ".gitea/workflows/prod-temporal-preflight.yaml").exists(),
    }


def validate_production_source(files: dict[str, Any]) -> str:
    if files["retired_temporal_preflight_present"]:
        raise RuntimeError("retired manual production Temporal preflight workflow remains")
    if files["retired_control_paths_present"]:
        raise RuntimeError(
            "retired source deployment control remains: "
            + ", ".join(files["retired_control_paths_present"])
        )
    if re.search(r"promotion-receipt-(?:publish|consume):", files["ci_workflow"]):
        raise RuntimeError("synthetic promotion receipt CI transport remains")

    for path, text in files["production_files"].items():
        if "$imagepolicy" in text:
            raise RuntimeError(f"retired Flux image setter marker remains in {path}")

    if not re.search(r"^\s*- path: config-images\.yaml\s*$", files["kustomization"], re.MULTILINE):
        raise RuntimeError("production Kustomization must apply config-images.yaml")

    tags: dict[str, str] = {}
    digests: dict[str, str] = {}
    # The production overlay names its image registry host; this source check
    # binds the repository path, tag and digest, never one registry host.
    registry = r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d+)?"
    for name in ["services", "derp", "dashboard"]:
        pin = one_match(
            files["kustomization"],
            rf"^\s*- name: git\.example\.com/codewire/{name}\s*\n"
            rf"\s+newName: {registry}/codewire/{name}\s*\n"
            r"\s+newTag: (v\d+\.\d+\.\d+)\s*\n"
            r"\s+digest: (sha256:[0-9a-f]{64})\s*$",
            f"{name} image",
        )
        tags[name] = pin.group(1)
        digests[name] = pin.group(2)

    daemon = one_match(
        files["daemon_patch"],
        rf"^\s*SANDBOX_DAEMON_IMAGE:\s*{registry}/codewire/daemon:(v\d+\.\d+\.\d+)@(sha256:[0-9a-f]{{64}})\s*$",
        "daemon image",
    )
    tags["daemon"] = daemon.group(1)
    digests["daemon"] = daemon.group(2)

    mesh = one_match(
        files["mesh_release"],
        rf"^\s*image:\s*\n\s+repository:\s*{registry}/codewire/mesh\s*\n"
        r"\s+tag:\s*(v\d+\.\d+\.\d+)\s*\n"
        r"\s+digest:\s*(sha256:[0-9a-f]{64})\s*$",
        "mesh image",
    )
    tags["mesh"] = mesh.group(1)
    digests["mesh"] = mesh.group(2)

    unique_tags = set(tags.values())
    if len(unique_tags) != 1:
        raise RuntimeError(
            "mixed credential-free source tags: "
            + ", ".join(f"{name}={tag}" for name, tag in tags.items())
        )
    if len(digests) != 5:
        raise RuntimeError(f"expected five immutable source digests, found {len(digests)}")

    for required in [
        "publish-runtime-images:",
        "image-bundle.py create",
        "publish-image-to-harbor.sh",
        "publish-image-to-ghcr.sh",
        "dispatch-deploy-prod.sh",
        "enable-openid-connect: true",
    ]:
        if required not in files["production_workflow"]:
            raise RuntimeError(f"source production workflow lost required boundary: {required}")
    for retired in [
        "aggregate-image-promotion:",
        "CODEWIRE_DEPLOY_PROMOTION_TOKEN",
        "CODEWIRE_DEPLOY_PROMOTION_USERNAME",
        "promote-image-bundle.sh",
        "promotion-receipt",
        "observe-production:",
        "deploy-prod-observer.sh",
    ]:
        if retired in files["production_workflow"]:
            raise RuntimeError(f"source production workflow retains retired control plane: {retired}")
    if "scripts/ci/deploy/deploy-prod.sh" in files["production_workflow"]:
        raise RuntimeError("production workflow reintroduced the retired direct deploy script")
    if "fetch-forgejo-deploy-prod-token.sh" not in files["production_dispatch"]:
        raise RuntimeError("production dispatch lost its short-lived Forgejo credential fetcher")
    for required in [
        "u:36:743b0975-b91c-4323-be37-a55707687c78",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ]:
        if required not in files["production_oidc_fetcher"]:
            raise RuntimeError(
                f"production OIDC fetcher lost required identity binding: {required}"
            )
    if "CODEWIRE_DEPLOY_PROMOTION_TOKEN" in files["production_dispatch"]:
        raise RuntimeError("production dispatch retained the static deploy token")

    return next(iter(unique_tags))


def production_source_self_test(files: dict[str, Any]) -> None:
    def expect_rejected(label: str, fixture: dict[str, Any], expected: str) -> None:
        try:
            validate_production_source(fixture)
        except Exception as error:  # noqa: BLE001 - negative fixture
            if expected in str(error):
                return
            raise
        raise RuntimeError(f"self-test accepted {label}")

    fixture = dict(files)
    fixture["daemon_patch"] = re.sub(
        r"daemon:v\d+\.\d+\.\d+@",
        "daemon:v999.999.999@",
        files["daemon_patch"],
    )
    expect_rejected("mixed image tags", fixture, "mixed credential-free source tags")

    fixture = dict(files)
    fixture["production_files"] = {**files["production_files"], "fixture.yaml": '# {"$imagepolicy": "flux-system:retired"}'}
    expect_rejected("retired image setter", fixture, "retired Flux image setter marker")

    fixture = dict(files)
    fixture["production_workflow"] = (
        files["production_workflow"] + "\n        run: scripts/ci/deploy/deploy-prod.sh v0.0.0\n"
    )
    expect_rejected(
        "retired direct deploy script",
        fixture,
        "production workflow reintroduced the retired direct deploy script",
    )

    fixture = dict(files)
    fixture["retired_control_paths_present"] = ["scripts/ci/retired-observer.sh"]
    expect_rejected("retired source deployment control", fixture, "retired source deployment control remains")

    fixture = dict(files)
    fixture["ci_workflow"] = files["ci_workflow"] + "\npromotion-receipt-publish:\n"
    expect_rejected("synthetic promotion receipt CI transport", fixture, "synthetic promotion receipt CI transport remains")

    fixture = dict(files)
    fixture["retired_temporal_preflight_present"] = True
    expect_rejected("retired Temporal preflight workflow", fixture, "retired manual production Temporal preflight workflow")

    fixture = dict(files)
    fixture["production_workflow"] = (
        files["production_workflow"] + "\nCODEWIRE_DEPLOY_PROMOTION_TOKEN: retired\n"
    )
    expect_rejected(
        "static production deploy token",
        fixture,
        "source production workflow retains retired control plane",
    )
