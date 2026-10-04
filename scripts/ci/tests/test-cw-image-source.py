#!/usr/bin/env python3
"""Credential-free custody/policy tests; no Docker or compiler is invoked."""

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("cw_image_source_under_test", ROOT / "scripts/ci/images/cw-image-source.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
REFUSALS = (source.Refused, OSError)
PROTECTED = (".git", ".tmp", "target", "node_modules", "__pycache__", ".cache", ".cargo", ".sccache",
             ".ssh", ".gnupg", ".aws", ".codex", ".claude", ".docker", ".kube", ".netrc", ".npmrc", ".pypirc")
IGNORE = "".join("**/" + name + "\n" for name in PROTECTED) + "**/.env*\n**/*.pyc\n**/*.pyo\n"


def write(path, raw=b"source\n", mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw if type(raw) is bytes else raw.encode("utf-8"))
    path.chmod(mode)


class Inventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-image-source-")
        self.base = Path(self.temporary.name)
        self.checkout = self.base / "checkout"
        self.checkout.mkdir(mode=0o700)
        self.policy = self.checkout / ".dockerignore"
        write(self.policy, IGNORE)
        write(self.checkout / "Dockerfile", "FROM scratch\nCOPY src /src\n")
        write(self.checkout / "src/main.rs")

    def tearDown(self):
        source.STOP = None
        self.temporary.cleanup()

    def admit(self, recipes=None):
        return source.ImageSource(self.checkout, recipes or ["Dockerfile"])

    def members(self, admitted):
        return {entry["path"]: entry for entry in admitted.summary["inventory"]}

    def test_unicode_separators_cannot_create_an_extra_ignore_rule(self):
        write(self.checkout / "public", b"must remain admitted\n")
        write(self.policy, IGNORE + "unmatched\u0085public\n")
        with self.assertRaises(source.Refused):
            self.admit()
        write(self.policy, IGNORE + "unmatched\u2028public\n")
        with self.admit() as admitted:
            self.assertIn("public", self.members(admitted))

    def test_checked_in_root_policy_omits_claude_without_opening_it(self):
        # The real image context contains this project directory. Its bytes
        # are outside the image/credential contract, including when cached.
        write(self.policy, (ROOT / ".dockerignore").read_bytes())
        write(self.checkout / ".claude/synthetic-fixture", b"synthetic-unread-bytes\n")
        real_open, real_stat = os.open, os.stat
        with mock.patch.object(source.os, "open", wraps=real_open) as opened, \
                mock.patch.object(source.os, "stat", wraps=real_stat) as inspected:
            with self.admit() as admitted:
                self.assertIn("src/main.rs", self.members(admitted))
                self.assertFalse(any(".claude" in Path(name).parts for name in self.members(admitted)))
                admitted.revalidate()
            for calls in (opened.call_args_list, inspected.call_args_list):
                self.assertFalse(any(".claude" in Path(os.fspath(call.args[0])).parts
                                     for call in calls
                                     if isinstance(call.args[0], (str, os.PathLike))))
        write(self.policy, (ROOT / ".dockerignore").read_bytes() + b"!.claude\n")
        with self.assertRaises(source.Refused):
            self.admit()

    def test_checked_in_root_policy_omits_proto_environment_without_inspection(self):
        root_policy = (ROOT / ".dockerignore").read_bytes()
        write(self.policy, root_policy)
        outside = self.base / "owned-proto-environment"
        write(outside / "synthetic-fixture", b"synthetic-unread-tool-bytes\n")
        (self.checkout / ".venv-proto").symlink_to(outside, target_is_directory=True)
        real_open, real_stat, real_readlink = os.open, os.stat, os.readlink
        with mock.patch.object(source.os, "open", wraps=real_open) as opened, \
                mock.patch.object(source.os, "stat", wraps=real_stat) as inspected, \
                mock.patch.object(source.os, "readlink", wraps=real_readlink) as links:
            with self.admit() as admitted:
                self.assertIn("src/main.rs", self.members(admitted))
                self.assertNotIn(".venv-proto", self.members(admitted))
                admitted.revalidate()
            for calls in (opened.call_args_list, inspected.call_args_list, links.call_args_list):
                self.assertFalse(any(".venv-proto" in Path(os.fspath(call.args[0])).parts
                                     or Path(os.fspath(call.args[0])).is_relative_to(outside)
                                     for call in calls
                                     if isinstance(call.args[0], (str, os.PathLike))))
        # Explicitly exposing the absolute link retains the original refusal;
        # its target is an owned synthetic directory and is never followed.
        write(self.policy, root_policy + b"!.venv-proto\n")
        with mock.patch.object(source.os, "open", wraps=real_open) as opened, \
                self.assertRaisesRegex(source.Refused, "symlink points outside the context"):
            self.admit()
        self.assertFalse(any(".venv-proto" in Path(os.fspath(call.args[0])).parts
                             or Path(os.fspath(call.args[0])).is_relative_to(outside)
                             for call in opened.call_args_list
                             if isinstance(call.args[0], (str, os.PathLike))))

    def test_checked_in_root_policy_omits_nested_npmrc_without_inspection(self):
        root_policy = (ROOT / ".dockerignore").read_bytes()
        write(self.policy, root_policy)
        write(self.checkout / "libs/sdk-ts/.npmrc", b"synthetic-unread-client-config\n")
        real_open, real_stat, real_readlink = os.open, os.stat, os.readlink
        with mock.patch.object(source.os, "open", wraps=real_open) as opened, \
                mock.patch.object(source.os, "stat", wraps=real_stat) as inspected, \
                mock.patch.object(source.os, "readlink", wraps=real_readlink) as links:
            with self.admit() as admitted:
                self.assertIn("src/main.rs", self.members(admitted))
                self.assertNotIn("libs/sdk-ts/.npmrc", self.members(admitted))
                admitted.revalidate()
            for calls in (opened.call_args_list, inspected.call_args_list, links.call_args_list):
                self.assertFalse(any(".npmrc" in Path(os.fspath(call.args[0])).parts
                                     for call in calls
                                     if isinstance(call.args[0], (str, os.PathLike))))
        write(self.policy, root_policy + b"!libs/sdk-ts/.npmrc\n")
        with mock.patch.object(source.os, "open", wraps=real_open) as opened, \
                mock.patch.object(source.os, "stat", wraps=real_stat) as inspected, \
                mock.patch.object(source.os, "readlink", wraps=real_readlink) as links:
            with self.assertRaisesRegex(source.Refused, "protected credential/cache tree"):
                self.admit()
            for calls in (opened.call_args_list, inspected.call_args_list, links.call_args_list):
                self.assertFalse(any(".npmrc" in Path(os.fspath(call.args[0])).parts
                                     for call in calls
                                     if isinstance(call.args[0], (str, os.PathLike))))

    def test_complete_context_not_only_recipe_copy_paths_and_repeat_enumeration(self):
        write(self.checkout / "unreferenced/public.txt", b"readonly context mounts can consume this\n")
        with self.admit() as admitted:
            before = admitted.summary
            self.assertIn("unreferenced/public.txt", self.members(admitted))
            for _ in range(3):
                admitted.revalidate()
                self.assertEqual(before, admitted.summary)
            self.assertIsNone(admitted.deadline)
            self.assertEqual(before["claim"], "current-local-image-source-admission-only")
            self.assertNotIn("compiled_cw", before)
            altered = admitted.summary
            altered["inventory"].clear()
            self.assertEqual(before, admitted.summary)
        with self.assertRaises(source.Refused):
            admitted.revalidate()

    def test_empty_regular_files_and_executable_modes_are_intentional(self):
        write(self.checkout / "empty", b"")
        write(self.checkout / "run.sh", b"#!/bin/sh\n", 0o755)
        with self.admit() as admitted:
            members = self.members(admitted)
            self.assertEqual(members["empty"]["size"], 0)
            self.assertEqual(members["empty"]["sha256"], hashlib.sha256(b"").hexdigest())
            self.assertEqual(members["run.sh"]["mode"], 0o755)
            admitted.revalidate()

    def test_selected_recipe_graph_and_override_held_even_when_context_excludes_them(self):
        write(self.checkout / "docker-bake.hcl", 'target "sample" {}\n')
        write(self.checkout / "Dockerfile.dockerignore", "*\n!src\n!src/**\n" + IGNORE)
        with self.admit(["docker-bake.hcl", "Dockerfile"]) as admitted:
            members = self.members(admitted)
            self.assertTrue({"Dockerfile", "docker-bake.hcl", ".dockerignore", "Dockerfile.dockerignore"} <= members.keys())
            self.assertEqual(admitted.summary["policies"][0]["ignore"], "Dockerfile.dockerignore")
            write(self.checkout / "docker-bake.hcl", 'target "replaced" {}\n')
            with self.assertRaises(REFUSALS):
                admitted.revalidate()

    def test_dockerfile_specific_policy_replaces_root_and_multiple_contexts_union(self):
        write(self.checkout / "Dockerfile.dockerignore", "*\n!src\n!src/**\n" + IGNORE)
        write(self.checkout / "Other.Dockerfile", "FROM scratch\nCOPY other /other\n")
        write(self.checkout / "Other.Dockerfile.dockerignore", "*\n!other\n!other/**\n" + IGNORE)
        write(self.checkout / "other/public")
        write(self.checkout / "unselected/public")
        with self.admit() as admitted:
            self.assertNotIn("other/public", self.members(admitted))
        with self.admit(["Dockerfile", "Other.Dockerfile"]) as admitted:
            members = self.members(admitted)
            self.assertIn("src/main.rs", members)
            self.assertIn("other/public", members)
            self.assertNotIn("unselected/public", members)
            admitted.revalidate()

    def test_checked_in_ignore_patterns_and_parent_negations(self):
        # These are the exact syntax families in root and per-recipe policies,
        # including services' !crates (without an added /** rule).
        policy = source.IgnorePolicy(b"*\n!Cargo.toml\n!crates\n!proto\n!proto/**\ncrates/**/target\n**/.tmp\n")
        for path in ("Cargo.toml", "crates", "crates/a/src/lib.rs", "proto/a.proto"):
            self.assertTrue(policy.includes(path), path)
        for path in ("other", "crates/a/target/output", "crates/.tmp/private", ".tmp/private"):
            self.assertFalse(policy.includes(path), path)
        self.assertFalse(policy.traverses("crates/a/target"))
        policy = source.IgnorePolicy(b"scripts\n!scripts/\n!scripts/ci/\n!scripts/ci/images/\n!scripts/ci/images/run-rust-build.sh\n")
        self.assertTrue(policy.includes("scripts/ci/images/run-rust-build.sh"))
        # A negated parent makes descendants visible. We deliberately cover
        # those extra bytes rather than guessing the comment's intent.
        self.assertTrue(policy.includes("scripts/ci/images/other.py"))
        later = source.IgnorePolicy(b"*\n!one/two/file\n")
        self.assertTrue(later.traverses("one"))
        self.assertFalse(later.includes("one"))
        self.assertFalse(later.traverses("unrelated"))

    def test_terminal_recursive_glob_keeps_same_named_regular_file(self):
        # Moby's terminal foo/** is a foo/ prefix, not an exclusion of foo.
        # Dropping this regular file would omit bytes BuildKit can consume.
        write(self.policy, IGNORE + "public/**\n")
        write(self.checkout / "public", b"actual consumed fixture bytes\n")
        with self.admit() as admitted:
            self.assertIn("public", self.members(admitted))
        policy = source.IgnorePolicy(b"public/**\n")
        self.assertTrue(policy.includes("public"))
        self.assertFalse(policy.includes("public/child"))
        self.assertFalse(policy.includes("public/a/child"))

    def test_negation_whitespace_after_bang_is_trimmed(self):
        write(self.policy, "*\n! src \n!Dockerfile\n" + IGNORE)
        with self.admit() as admitted:
            self.assertIn("src/main.rs", self.members(admitted))
            admitted.revalidate()

    def test_ignored_credentials_and_caches_are_not_opened_or_read(self):
        for name in (*PROTECTED, ".env.secret"):
            write(self.checkout / name / "forbidden-bytes", b"not a credential; test sentinel only\n")
        write(self.checkout / "src/.env.secret", b"test sentinel\n")
        real_open, real_stat = os.open, os.stat

        def context_entry(path, kwargs):
            fd = kwargs.get("dir_fd")
            return fd is not None and os.readlink("/proc/self/fd/" + str(fd)).startswith(str(self.checkout))

        def guarded_open(path, *args, **kwargs):
            if context_entry(path, kwargs):
                self.assertFalse(source.forbidden(os.fspath(path)), "attempted protected entry open")
            return real_open(path, *args, **kwargs)

        def guarded_stat(path, *args, **kwargs):
            if context_entry(path, kwargs):
                self.assertFalse(source.forbidden(os.fspath(path)), "attempted protected entry stat")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(source.os, "open", side_effect=guarded_open), mock.patch.object(source.os, "stat", side_effect=guarded_stat):
            with self.admit() as admitted:
                admitted.revalidate()
                self.assertNotIn("src/.env.secret", self.members(admitted))

    def test_unsafe_policy_refuses_before_protected_file_open(self):
        write(self.checkout / ".env.private", b"synthetic private sentinel\n")
        real_open = os.open

        def guarded(path, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), ".env.private", "must refuse before opening private bytes")
            return real_open(path, *args, **kwargs)

        for rules in (b"", b"**/.env*\n!.env.private\n", b"**/.env*\n!.env.private/kept\n"):
            with self.subTest(rules=rules):
                write(self.policy, rules)
                with mock.patch.object(source.os, "open", side_effect=guarded), self.assertRaises(source.Refused):
                    self.admit()

    def test_ignored_foreign_symlink_not_followed_but_consumed_symlink_refuses(self):
        outside = self.base / "outside"
        write(outside, b"synthetic foreign bytes\n")
        (self.checkout / ".env.link").symlink_to(outside)
        with self.admit() as admitted:
            self.assertNotIn(".env.link", self.members(admitted))
        (self.checkout / "public-link").symlink_to(outside)
        with self.assertRaises(source.Refused):
            self.admit()

    def test_safe_relative_file_and_directory_symlinks_are_metadata_only(self):
        (self.checkout / "file-link").symlink_to("src/main.rs")
        (self.checkout / "dir-link").symlink_to("src", target_is_directory=True)
        (self.checkout / "src/relative-link").symlink_to("../Dockerfile")
        real_open = os.open

        def guarded(path, *args, **kwargs):
            self.assertNotIn(os.fspath(path), ("file-link", "dir-link", "relative-link"), "symlink was opened")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(source.os, "open", side_effect=guarded):
            with self.admit() as admitted:
                members = self.members(admitted)
                self.assertEqual(members["file-link"], {"path": "file-link", "kind": "symlink", "target": "src/main.rs"})
                self.assertEqual(admitted.summary["symlinks"], 3)
                admitted.revalidate()

    def test_symlink_unknown_ignored_credential_traversal_and_cycles_refuse(self):
        link = self.checkout / "link"
        write(self.checkout / ".env.private", b"synthetic private sentinel\n")
        for target in ("missing", ".env.private", "../outside", ".", "link", "src/main.rs/child"):
            with self.subTest(target=target):
                link.symlink_to(target)
                try:
                    with self.assertRaises(source.Refused):
                        self.admit()
                finally:
                    link.unlink()
        (self.checkout / "src/root-link").symlink_to("..")
        with self.assertRaises(source.Refused):
            self.admit()

    def test_symlink_alias_cannot_reach_context_excluded_target(self):
        write(self.policy, IGNORE + "hidden\n")
        write(self.checkout / "hidden/data", b"synthetic ignored sentinel\n")
        (self.checkout / "link").symlink_to("hidden/data")
        with self.assertRaises(source.Refused):
            self.admit()

    def test_file_mutation_replacement_and_mode_changes_refuse(self):
        path = self.checkout / "src/main.rs"
        for change in ("bytes", "replacement", "mode", "removed"):
            with self.subTest(change=change):
                write(path)
                with self.admit() as admitted:
                    if change == "bytes":
                        write(path, b"mutated\n")
                    elif change == "replacement":
                        replacement = path.with_name("owned-new")
                        write(replacement, path.read_bytes())
                        os.replace(replacement, path)
                    elif change == "mode":
                        path.chmod(0o600)
                    else:
                        path.unlink()
                    with self.assertRaises(REFUSALS):
                        admitted.revalidate()

    def test_transient_create_delete_refuses_even_with_same_final_inventory(self):
        with self.admit() as admitted:
            directory = self.checkout / "src"
            before = set(os.listdir(directory))
            temporary = directory / "transient"
            write(temporary)
            temporary.unlink()
            self.assertEqual(set(os.listdir(directory)), before)
            with self.assertRaises(source.Refused):
                admitted.revalidate()

    def test_transient_in_place_restore_and_directory_replacement_refuse(self):
        path = self.checkout / "src/main.rs"
        with self.admit() as admitted:
            prior = path.stat()
            raw = path.read_bytes()
            write(path, b"changed\n")
            write(path, raw)
            os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
            self.assertEqual(path.read_bytes(), raw)
            with self.assertRaises(source.Refused):
                admitted.revalidate()
        with self.admit() as admitted:
            # Every replacement destination is an explicitly owned fresh name.
            old = self.base / "original-src"
            (self.checkout / "src").rename(old)
            write(self.checkout / "src/main.rs")
            with self.assertRaises(source.Refused):
                admitted.revalidate()

    def test_policy_replacement_and_absent_override_creation_refuse(self):
        with self.admit() as admitted:
            write(self.checkout / "Dockerfile.dockerignore", IGNORE)
            with self.assertRaises(source.Refused):
                admitted.revalidate()
        (self.checkout / "Dockerfile.dockerignore").unlink()
        with self.admit() as admitted:
            replacement = self.checkout / "owned-new-policy"
            write(replacement, self.policy.read_bytes())
            os.replace(replacement, self.policy)
            with self.assertRaises(source.Refused):
                admitted.revalidate()

    def test_regular_hardlink_fifo_and_foreign_writable_modes_refuse(self):
        path = self.checkout / "bad"
        os.link(self.checkout / "src/main.rs", path)
        with self.assertRaises(source.Refused):
            self.admit()
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(source.Refused):
            self.admit()
        path.unlink()
        for mode in (0o666, 0o664):
            with self.subTest(mode=mode):
                write(path, mode=mode)
                with self.assertRaises(source.Refused):
                    self.admit()
        path.unlink()
        (self.checkout / "src").chmod(0o777)
        with self.assertRaises(source.Refused):
            self.admit()

    def test_foreign_file_and_directory_ownership_policy_refuses(self):
        path = self.checkout / "src/main.rs"
        real_fstat, real_stat = os.fstat, os.stat

        def changed_owner(info):
            values = {"st_" + key: getattr(info, "st_" + key) for key in source.STAMP_FIELDS}
            values["st_uid"] = os.geteuid() + 1
            return SimpleNamespace(**values)

        def observed(fd):
            info = real_fstat(fd)
            return changed_owner(info) if os.readlink("/proc/self/fd/" + str(fd)) == str(path) else info

        def named(name, *args, **kwargs):
            info = real_stat(name, *args, **kwargs)
            fd = kwargs.get("dir_fd")
            matches = name == path.name and fd is not None and os.readlink("/proc/self/fd/" + str(fd)) == str(path.parent)
            return changed_owner(info) if matches else info

        with mock.patch.object(source.os, "fstat", side_effect=observed), mock.patch.object(source.os, "stat", side_effect=named):
            with self.assertRaisesRegex(source.Refused, "regular file ownership"):
                self.admit()
        # No chown or other UID's filesystem is involved in this policy case.
        with self.assertRaisesRegex(source.Refused, "directory ownership"):
            source.directory_policy(changed_owner(self.checkout.stat()))

    def test_source_ancestry_and_recipe_symlinks_refuse(self):
        alias = self.base / "alias"
        alias.symlink_to(self.checkout, target_is_directory=True)
        with self.assertRaises(REFUSALS):
            source.ImageSource(alias, ["Dockerfile"])
        file = self.checkout / "Dockerfile"
        file.unlink()
        file.symlink_to("src/main.rs")
        with self.assertRaises(source.Refused):
            self.admit()

    def test_closed_recipe_paths_policy_syntax_and_resource_bounds(self):
        for recipes in ([], ["Dockerfile", "Dockerfile"], ["../Dockerfile"], ["src/main.rs"],
                        [str(self.base / "outside.Dockerfile")], ["docker-bake.hcl"], [".env/Dockerfile"]):
            with self.subTest(recipes=recipes), self.assertRaises(REFUSALS):
                source.ImageSource(self.checkout, recipes)
        for raw in (b"!\n", b"a/**b\n", b"../outside\n", b"a/[0-9]\n", b"a\\b\n", b"a\x00b\n", b"\xff\n"):
            with self.subTest(raw=raw), self.assertRaises(source.Refused):
                source.IgnorePolicy(raw)
        for field, limit in (("MAX_FILE", 2), ("MAX_TOTAL", 2), ("MAX_FILES", 2),
                             ("MAX_DIRECTORIES", 1), ("MAX_ENTRIES", 1), ("MAX_DOCUMENT", 1)):
            with self.subTest(field=field), mock.patch.object(source, field, limit), self.assertRaises(source.Refused):
                self.admit()

    def test_phase_cancellation_deadline_and_no_compiler_clock(self):
        with self.admit() as admitted:
            source.STOP = "test cancellation"
            with self.assertRaises(source.Refused):
                admitted.revalidate()
            source.STOP = None
            # An arbitrarily long solve does not expire metadata admission.
            future = time.monotonic() + source.PHASE_SECONDS * 10
            with mock.patch.object(source.time, "monotonic", return_value=future):
                admitted.revalidate()
            with mock.patch.object(source, "PHASE_SECONDS", 0), self.assertRaises(source.Refused):
                admitted.revalidate()
            self.assertIsNone(admitted.deadline)

    def test_identity_is_logical_and_changes_for_image_only_source_edits(self):
        with self.admit() as admitted:
            before = admitted.summary["sha256"]
        duplicate = self.base / "duplicate"
        duplicate.mkdir(mode=0o700)
        for name in (".dockerignore", "Dockerfile", "src/main.rs"):
            write(duplicate / name, (self.checkout / name).read_bytes())
        with source.ImageSource(duplicate, ["Dockerfile"]) as admitted:
            self.assertEqual(before, admitted.summary["sha256"])
        write(self.checkout / "image-only-public.txt", b"image input, not compiled CW\n")
        with self.admit() as admitted:
            self.assertNotEqual(before, admitted.summary["sha256"])


if __name__ == "__main__":
    unittest.main()
