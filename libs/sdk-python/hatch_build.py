"""Make the public generated API packages available to every build target."""

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


GENERATED_SDIST_ROOT = "_codewire_generated"
PUBLIC_GENERATED_TREES = (
    (Path("codewire") / "v1", Path("codewire") / "v1"),
    (Path("google") / "rpc", Path("google") / "rpc"),
)
REQUIRED_GENERATED_FILES = (
    Path("codewire/v1/api_key_connect.py"),
    Path("codewire/v1/environment_pb2.py"),
    Path("google/rpc/status_pb2.py"),
)


class CustomBuildHook(BuildHookInterface):
    """Carry generated inputs into the sdist, then consume them in its wheel."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        del version
        project_root = Path(self.root)
        repository_generated = project_root.parent / "gen-python"
        packaged_generated = project_root / GENERATED_SDIST_ROOT

        repository_layout = repository_generated.is_dir()
        packaged_layout = packaged_generated.is_dir()
        if repository_layout == packaged_layout:
            raise RuntimeError(
                "expected exactly one generated SDK layout: repository sibling "
                "or self-contained sdist"
            )

        generated_root = (
            repository_generated if repository_layout else packaged_generated
        )
        self._validate_generated_root(generated_root)

        force_include = build_data["force_include"]
        for source_tree, installed_tree in PUBLIC_GENERATED_TREES:
            for source_file in self._public_files(generated_root / source_tree):
                relative_file = source_file.relative_to(generated_root)
                if self.target_name == "sdist":
                    destination = Path(GENERATED_SDIST_ROOT) / relative_file
                elif self.target_name == "wheel":
                    destination = installed_tree / source_file.relative_to(
                        generated_root / source_tree
                    )
                else:
                    raise RuntimeError(
                        f"unsupported Python SDK build target: {self.target_name}"
                    )
                force_include[str(source_file)] = destination.as_posix()

    @staticmethod
    def _public_files(source_tree: Path) -> list[Path]:
        if not source_tree.is_dir():
            raise RuntimeError(f"generated SDK tree is missing: {source_tree}")

        files: list[Path] = []
        for entry in sorted(source_tree.rglob("*")):
            if entry.is_symlink():
                raise RuntimeError(f"generated SDK tree contains a symlink: {entry}")
            if entry.is_dir():
                continue
            if "__pycache__" in entry.parts or entry.suffix == ".pyc":
                continue
            if entry.suffix not in {".py", ".pyi"}:
                raise RuntimeError(
                    f"generated SDK tree contains an unexpected file: {entry}"
                )
            files.append(entry)

        if not files:
            raise RuntimeError(f"generated SDK tree is empty: {source_tree}")
        return files

    @staticmethod
    def _validate_generated_root(generated_root: Path) -> None:
        missing = [
            path.as_posix()
            for path in REQUIRED_GENERATED_FILES
            if not (generated_root / path).is_file()
        ]
        if missing:
            raise RuntimeError(
                "generated SDK input is incomplete; missing: " + ", ".join(missing)
            )
