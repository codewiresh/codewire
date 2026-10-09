#!/usr/bin/env python3
"""Hold the selected local image context across an owning BuildKit solve.

The caller supplies every selected/dependency Dockerfile and any Bake graph.
Their effective .dockerignore policies are combined, since each selected
recipe can consume a different view of the same context. Recipe and policy
files remain inputs even when excluded from COPY. This is current image-source
admission, independent of the compiled CW executable's original provenance.

No Git, compiler, Docker or executable is invoked. Excluded file bytes and
protected trees are not read;
an effective policy that exposes a known credential/cache tree is refused.
Symlinks are metadata only, never followed, and must resolve within the admitted
context without cycles. The owning wrapper must hold this context manager and
call revalidate() immediately before and after the solve. Same-UID/root writers
remain trusted; this is a bounded change detector, not filesystem isolation.
"""

from contextlib import contextmanager
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import stat
import time


SCHEMA = "codewire.cw.image-source/v1"
CLAIM = "current-local-image-source-admission-only"
MAX_PATH = 4096
MAX_DEPTH = 64
MAX_RECIPES = 64
MAX_RULES = 256
MAX_RULE_LENGTH = 256
MAX_POLICY = 64 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILES = 32768
MAX_DIRECTORIES = 8192
MAX_ENTRIES = 131072
MAX_DOCUMENT = 32 * 1024 * 1024
PHASE_SECONDS = 600
STAMP_FIELDS = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
ANCESTRY_FIELDS = STAMP_FIELDS[:5]
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
FORBIDDEN_NAMES = frozenset({".git", ".tmp", "target", "node_modules", "__pycache__", ".cache",
                             ".cargo", ".sccache", ".ssh", ".gnupg", ".aws", ".codex", ".claude",
                             ".docker", ".kube", ".netrc", ".npmrc", ".pypirc"})
STOP = None


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def text(value, maximum=MAX_PATH):
    require(type(value) is str and value and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            "image-source text refused")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError:
        raise Refused("image-source text encoding refused") from None
    require(len(raw) <= maximum, "image-source text exceeds its bound")
    return value


def path_arg(value):
    value = text(os.fspath(value))
    require(value.startswith("/") and value != "/" and len(value.split("/")) <= MAX_DEPTH
            and all(part not in ("", ".", "..") for part in value.split("/")[1:]),
            "image-source path is not absolute bounded canonical spelling")
    return Path(value)


def relative(value):
    value = text(value)
    require(not value.startswith("/") and len(value.split("/")) <= MAX_DEPTH
            and all(part not in ("", ".", "..") for part in value.split("/")),
            "image-source relative path refused")
    return value


def forbidden(value):
    return any(part in FORBIDDEN_NAMES or part.startswith(".env")
               or part.endswith((".pyc", ".pyo")) for part in value.split("/"))


def stamp(info, fields=STAMP_FIELDS):
    values = dict(zip(STAMP_FIELDS, (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)))
    return {key: values[key] for key in fields}


def directory_policy(info, ancestry=False):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()),
            "image-source directory ownership refused")
    sticky_temporary = ancestry and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777
    require(not info.st_mode & 0o022 or sticky_temporary, "image-source directory permits foreign writes")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


class Ancestry:
    """Held root-to-context names; directory content is separately inventoried."""

    def __init__(self, path):
        self.fds, self.names, self.stamps = [], [], []
        try:
            for name in ("/", *path.parts[1:]):
                before = os.stat(name, dir_fd=self.fds[-1] if self.fds else None, follow_symlinks=False)
                fd = os.open(name, DIR_FLAGS, dir_fd=self.fds[-1] if self.fds else None)
                self.fds.append(fd)
                current = os.fstat(fd)
                directory_policy(current, ancestry=True)
                expected = stamp(current, ANCESTRY_FIELDS)
                require(stamp(before, ANCESTRY_FIELDS) == expected, "image-source ancestry changed during open")
                self.names.append(name)
                self.stamps.append(expected)
            self.revalidate()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def revalidate(self):
        require(STOP is None, "image-source operation cancelled")
        for index, (name, fd, expected) in enumerate(zip(self.names, self.fds, self.stamps)):
            current = os.stat(name, dir_fd=self.fds[index - 1] if index else None, follow_symlinks=False)
            directory_policy(current, ancestry=True)
            require(stamp(current, ANCESTRY_FIELDS) == expected == stamp(os.fstat(fd), ANCESTRY_FIELDS),
                    "held image-source ancestry changed")

    def close(self):
        while self.fds:
            os.close(self.fds.pop())


class Rule:
    def __init__(self, pattern, include):
        self.pattern, self.include = pattern, include
        self.parts = pattern.split("/")

    def direct(self, parts, prefix=False):
        # Component matching keeps * from crossing a slash. ** is the closed
        # zero-or-more component spelling, with bounded dynamic-programming
        # work rather than an unbounded caller-generated regular expression.
        pending, seen = [(0, 0)], set()
        while pending:
            i, j = pending.pop()
            if (i, j) in seen:
                continue
            seen.add((i, j))
            if j == len(parts) and (prefix or i == len(self.parts)):
                return True
            if i == len(self.parts):
                continue
            if self.parts[i] == "**":
                if i and i == len(self.parts) - 1:
                    # Moby's terminal foo/** matches the foo/ prefix, not a
                    # regular file (or the directory itself) named foo.
                    if j < len(parts):
                        return True
                    continue
                pending.append((i + 1, j))
                if j < len(parts):
                    pending.append((i, j + 1))
            elif j < len(parts) and fnmatch.fnmatchcase(parts[j], self.parts[i]):
                pending.append((i + 1, j + 1))
        return False

    def matches(self, parts):
        return any(self.direct(parts[:length]) for length in range(1, len(parts) + 1))


class IgnorePolicy:
    """Closed Docker ignore syntax used by the checked-in image recipes.

    Leading/trailing slashes are insignificant. A rule matches a path or its
    parents; the last matching rule wins. Directory traversal only prunes when
    no later negation can expose a descendant. Unsupported glob/escape syntax
    refuses instead of weakening the admitted context.
    """

    def __init__(self, raw):
        require(type(raw) is bytes and len(raw) <= MAX_POLICY, "image ignore file exceeds its bound")
        try:
            decoded = raw.decode("utf-8-sig", "strict")
        except UnicodeError:
            raise Refused("image ignore encoding refused") from None
        self.rules = []
        for original in decoded.split("\n"):
            original = original.removesuffix("\r")
            require(not any((ord(c) < 32 and c != "\t") or 0x7f <= ord(c) <= 0x9f for c in original),
                    "image ignore control syntax refused")
            if original.startswith("#"):
                continue
            pattern = original.strip()
            if not pattern or pattern == ".":
                continue
            include = pattern.startswith("!")
            pattern = pattern[1:].strip() if include else pattern
            pattern = pattern.strip("/")
            require(pattern and len(pattern.encode("utf-8")) <= MAX_RULE_LENGTH
                    and "\\" not in pattern and len(self.rules) < MAX_RULES,
                    "image ignore rule syntax/bound refused")
            text(pattern, MAX_RULE_LENGTH)
            parts = pattern.split("/")
            require(len(parts) <= MAX_DEPTH and all(part not in ("", ".", "..") for part in parts),
                    "image ignore traversal syntax refused")
            for part in parts:
                require("**" not in part or part == "**", "image ignore recursive glob spelling refused")
                # Current checked-in policies need * and ** only. Reject
                # character classes/escapes whose Go/Python meanings differ.
                require(not any(c in part for c in "[]"), "image ignore character classes unsupported")
            self.rules.append(Rule(pattern, include))

    def state(self, path):
        parts, included, last = path.split("/"), True, -1
        for index, rule in enumerate(self.rules):
            if rule.matches(parts):
                included, last = rule.include, index
        return included, last

    def includes(self, path):
        return self.state(path)[0]

    def traverses(self, path):
        included, last = self.state(path)
        return included or any(rule.include and rule.direct(path.split("/"), prefix=True)
                               for rule in self.rules[last + 1:])


class ImageSource:
    """A held input inventory; no successful image/build claim is produced."""

    def __init__(self, source_dir, recipe_paths):
        self.path = path_arg(source_dir)
        self.ancestry, self.deadline = None, None
        self.directories, self.files, self.links = {}, {}, {}
        self.nodes, self.selections, self.absent_policies = {}, set(), []
        self.policies, self.policy_selection = [], []
        self.total_bytes, self.total_entries = 0, 0
        self.closed = False
        require(isinstance(recipe_paths, (list, tuple)) and 0 < len(recipe_paths) <= MAX_RECIPES,
                "image-source recipe selection bound refused")
        self.recipes = []
        for value in recipe_paths:
            value = os.fspath(value)
            if value.startswith("/"):
                try:
                    value = str(path_arg(value).relative_to(self.path))
                except ValueError:
                    raise Refused("image recipe lies outside the selected context") from None
            value = relative(value)
            require(not forbidden(value) and (Path(value).name == "Dockerfile"
                    or value.endswith(".Dockerfile") or value == "docker-bake.hcl"),
                    "image recipe/graph selection refused")
            self.recipes.append(value)
        require(len(set(self.recipes)) == len(self.recipes), "image recipe selection repeats")
        self.recipes.sort()
        dockerfiles = [name for name in self.recipes if name != "docker-bake.hcl"]
        require(dockerfiles, "actual selected Dockerfiles are required with the Bake graph")
        try:
            with self.phase():
                self.ancestry = Ancestry(self.path)
                self._directory("", self.ancestry.fd, ".")
                root_ignore = self._selected_file(".dockerignore", MAX_POLICY)
                for name in self.recipes:
                    self._selected_file(name, MAX_FILE)
                policy_by_name = {".dockerignore": IgnorePolicy(self._bytes(root_ignore, MAX_POLICY))}
                for name in dockerfiles:
                    override = name + ".dockerignore"
                    parent, leaf = self._parent(override)
                    try:
                        os.stat(leaf, dir_fd=parent["fd"], follow_symlinks=False)
                    except FileNotFoundError:
                        self.absent_policies.append((parent, leaf))
                        selected = ".dockerignore"
                    else:
                        held = self._selected_file(override, MAX_POLICY)
                        policy_by_name.setdefault(override, IgnorePolicy(self._bytes(held, MAX_POLICY)))
                        selected = override
                    if policy_by_name[selected] not in self.policies:
                        self.policies.append(policy_by_name[selected])
                    self.policy_selection.append({"recipe": name, "ignore": selected,
                                                  "sha256": self.files[selected]["sha256"]})
                self._walk("")
                self._symlink_closure()
                self._revalidate()
                self._summary = self._make_summary()
        except BaseException:
            self.close()
            raise

    @contextmanager
    def phase(self):
        require(not self.closed and self.deadline is None, "image-source phase is closed or nested")
        self.deadline = time.monotonic() + PHASE_SECONDS
        try:
            self.active()
            yield
            self.active()
        finally:
            # The metadata-phase bound never becomes a compiler deadline.
            self.deadline = None

    def active(self):
        require(STOP is None, "image-source operation cancelled")
        require(self.deadline is not None and time.monotonic() < self.deadline,
                "image-source metadata phase exceeded its bound")

    def _directory(self, name, parent_fd, leaf):
        self.active()
        if name in self.directories:
            return self.directories[name]
        require(len(self.directories) < MAX_DIRECTORIES, "image-source directory bound exceeded")
        before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        fd = os.open(leaf, DIR_FLAGS, dir_fd=parent_fd)
        try:
            current = os.fstat(fd)
            directory_policy(current)
            require(stamp(before) == stamp(current), "image-source directory changed during open")
            record = {"fd": fd, "parent_fd": parent_fd, "leaf": leaf,
                      "metadata": stamp(current), "names": None}
            self.directories[name] = record
            self.nodes[name] = "directory"
            return record
        except BaseException:
            os.close(fd)
            raise

    def _parent(self, name):
        parts, parent = name.split("/"), self.directories[""]
        for index, leaf in enumerate(parts[:-1]):
            self.active()
            parent = self._directory("/".join(parts[:index + 1]), parent["fd"], leaf)
        return parent, parts[-1]

    def _file(self, name, parent, leaf, maximum=MAX_FILE):
        self.active()
        if name in self.files:
            require(self.files[name]["metadata"]["size"] <= maximum, "image-source selected file exceeds its bound")
            return self.files[name]
        require(len(self.files) + len(self.links) < MAX_FILES, "image-source file bound exceeded")
        before = os.stat(leaf, dir_fd=parent["fd"], follow_symlinks=False)
        # Refuse types before opening; O_NONBLOCK also prevents a racing FIFO
        # replacement from blocking the metadata phase.
        require(stat.S_ISREG(before.st_mode), "image-source entry is not regular")
        fd = os.open(leaf, FILE_FLAGS, dir_fd=parent["fd"])
        try:
            current = os.fstat(fd)
            require(stamp(current) == stamp(before) and stat.S_ISREG(current.st_mode)
                    and current.st_nlink == 1 and current.st_uid in (0, os.geteuid())
                    and not current.st_mode & 0o022 and 0 <= current.st_size <= maximum,
                    "image-source regular file ownership/type/mode/bound refused")
            require(self.total_bytes + current.st_size <= MAX_TOTAL, "image-source total byte bound exceeded")
            record = {"fd": fd, "parent": parent, "leaf": leaf, "metadata": stamp(current)}
            record["sha256"] = self._hash(record)
            self.files[name] = record
            self.nodes[name] = "file"
            self.total_bytes += current.st_size
            return record
        except BaseException:
            os.close(fd)
            raise

    def _selected_file(self, name, maximum):
        require(not forbidden(name), "image-source selection exposes a protected tree")
        parent, leaf = self._parent(name)
        held = self._file(name, parent, leaf, maximum)
        self.selections.add(name)
        return held

    def _hash(self, record):
        self.active()
        os.lseek(record["fd"], 0, os.SEEK_SET)
        digest, size = hashlib.sha256(), 0
        expected = record["metadata"]
        while True:
            self.active()
            block = os.read(record["fd"], min(1024 * 1024, expected["size"] + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= expected["size"], "image-source held file grew")
            digest.update(block)
        require(size == expected["size"] and stamp(os.fstat(record["fd"])) == expected
                == stamp(os.stat(record["leaf"], dir_fd=record["parent"]["fd"], follow_symlinks=False)),
                "image-source held file changed during read")
        return digest.hexdigest()

    def _bytes(self, record, maximum):
        require(record["metadata"]["size"] <= maximum, "image-source policy exceeds its bound")
        os.lseek(record["fd"], 0, os.SEEK_SET)
        result = bytearray()
        while True:
            self.active()
            block = os.read(record["fd"], min(65536, maximum + 1 - len(result)))
            if not block:
                break
            result.extend(block)
            require(len(result) <= maximum, "image-source policy grew beyond its bound")
        require(len(result) == record["metadata"]["size"]
                and hashlib.sha256(result).hexdigest() == record["sha256"]
                and stamp(os.fstat(record["fd"])) == record["metadata"],
                "image-source policy changed during parse")
        return bytes(result)

    def _names(self, record, count=False):
        self.active()
        require(stamp(os.fstat(record["fd"])) == record["metadata"], "image-source directory changed")
        names = []
        # dup() shares directory offsets. A fresh anchored '.' open provides
        # an independent enumeration, including on repeated revalidation.
        scan_fd = os.open(".", DIR_FLAGS, dir_fd=record["fd"])
        try:
            require(stamp(os.fstat(scan_fd)) == record["metadata"], "image-source enumeration changed directory")
            with os.scandir(scan_fd) as entries:
                for entry in entries:
                    self.active()
                    leaf = text(entry.name)
                    require("/" not in leaf and leaf not in (".", ".."), "image-source entry name refused")
                    names.append(leaf)
                    require(len(names) <= MAX_ENTRIES, "image-source directory entry bound exceeded")
                    if count:
                        self.total_entries += 1
                        require(self.total_entries <= MAX_ENTRIES, "image-source total entry bound exceeded")
            require(stamp(os.fstat(scan_fd)) == record["metadata"], "image-source directory changed during enumeration")
        finally:
            os.close(scan_fd)
        require(stamp(os.fstat(record["fd"])) == record["metadata"], "image-source directory changed during enumeration")
        return tuple(sorted(names))

    def _walk(self, name):
        self.active()
        record = self.directories[name]
        names = self._names(record, count=True)
        require(record["names"] in (None, names), "image-source directory inventory changed")
        record["names"] = names
        for leaf in names:
            path = relative(name + "/" + leaf if name else leaf)
            included = any(policy.includes(path) for policy in self.policies)
            traversed = included or any(policy.traverses(path) for policy in self.policies)
            if forbidden(path):
                require(not traversed, "effective image context exposes a protected credential/cache tree")
                continue  # Never stat/open an excluded protected entry.
            if not traversed and path not in self.selections and path not in self.directories:
                continue
            current = os.stat(leaf, dir_fd=record["fd"], follow_symlinks=False)
            if stat.S_ISDIR(current.st_mode):
                self._directory(path, record["fd"], leaf)
                self._walk(path)
            elif included or path in self.selections:
                if stat.S_ISREG(current.st_mode):
                    self._file(path, record, leaf)
                elif stat.S_ISLNK(current.st_mode):
                    self._link(path, record, leaf, current)
                else:
                    raise Refused("effective image context has unsupported entry topology")

    def _link(self, name, parent, leaf, expected):
        self.active()
        require(len(self.files) + len(self.links) < MAX_FILES and expected.st_uid in (0, os.geteuid())
                and expected.st_nlink == 1 and expected.st_size <= MAX_PATH,
                "image-source symlink ownership/bound refused")
        target = text(os.readlink(leaf, dir_fd=parent["fd"]))
        require(stamp(expected) == stamp(os.stat(leaf, dir_fd=parent["fd"], follow_symlinks=False)),
                "image-source symlink changed during admission")
        require(not target.startswith("/"), "image-source symlink points outside the context")
        self.links[name] = {"parent": parent, "leaf": leaf, "metadata": stamp(expected), "target": target}
        self.nodes[name] = "symlink"

    def _resolve(self, link):
        components = link.split("/")[:-1]
        pending = self.links[link]["target"].split("/")
        steps = 0
        while pending:
            self.active()
            steps += 1
            require(steps <= MAX_DEPTH * 2, "image-source symlink resolution cycle/depth refused")
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                require(components, "image-source symlink traverses outside the context")
                components.pop()
                continue
            components.append(part)
            name = "/".join(components)
            require(not forbidden(name) and name in self.nodes, "image-source symlink exposes unadmitted data")
            if self.nodes[name] == "symlink":
                pending = self.links[name]["target"].split("/") + pending
                components.pop()
            elif pending:
                require(self.nodes[name] == "directory", "image-source symlink target traversal refused")
        name = "/".join(components)
        require(name in self.nodes, "image-source symlink target is absent")
        return name

    def _symlink_closure(self):
        for name, record in self.links.items():
            record["resolved"] = self._resolve(name)
        # Directory aliases may not make traversal cyclic. This includes a
        # link to its own ancestor and mutually linked otherwise-real trees.
        edges = {name: [] for name, kind in self.nodes.items() if kind in ("directory", "symlink")}
        for name in self.nodes:
            if name:
                parent = name.rpartition("/")[0]
                if parent in edges:
                    edges[parent].append(name)
        for name, record in self.links.items():
            edges[name] = [record["resolved"]]
        colors = {}
        for start in edges:
            if colors.get(start) == 2:
                continue
            pending = [(start, False)]
            while pending:
                self.active()
                name, leaving = pending.pop()
                if leaving:
                    colors[name] = 2
                elif name not in edges or colors.get(name) == 2:
                    continue
                else:
                    require(colors.get(name) != 1, "image-source directory symlink cycle refused")
                    colors[name] = 1
                    pending.append((name, True))
                    pending.extend((child, False) for child in reversed(edges[name]))

    def _revalidate(self):
        self.active()
        self.ancestry.revalidate()
        for record in self.directories.values():
            require(stamp(os.stat(record["leaf"], dir_fd=record["parent_fd"], follow_symlinks=False))
                    == record["metadata"] == stamp(os.fstat(record["fd"])),
                    "held image-source directory name/identity changed")
            names = self._names(record)
            if record["names"] is None:
                record["names"] = names
            else:
                require(names == record["names"], "held image-source directory inventory changed")
        for parent, leaf in self.absent_policies:
            try:
                os.stat(leaf, dir_fd=parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("previously absent Dockerfile ignore policy appeared")
        for record in self.files.values():
            require(stamp(os.stat(record["leaf"], dir_fd=record["parent"]["fd"], follow_symlinks=False))
                    == record["metadata"] == stamp(os.fstat(record["fd"])), "held image-source file changed")
            require(self._hash(record) == record["sha256"], "held image-source file hash changed")
        for record in self.links.values():
            require(stamp(os.stat(record["leaf"], dir_fd=record["parent"]["fd"], follow_symlinks=False))
                    == record["metadata"] and os.readlink(record["leaf"], dir_fd=record["parent"]["fd"])
                    == record["target"], "held image-source symlink changed")
        # Hashing can span enough time for namespace changes; close the phase
        # with the held directory and ancestry identities again.
        for record in self.directories.values():
            require(stamp(os.fstat(record["fd"])) == record["metadata"]
                    == stamp(os.stat(record["leaf"], dir_fd=record["parent_fd"], follow_symlinks=False)),
                    "image-source directory changed during revalidation")
        self.ancestry.revalidate()

    def _make_summary(self):
        inventory = []
        encoded_size = len(canonical({"recipes": self.recipes, "policies": self.policy_selection, "inventory": []}))
        for name, kind in sorted(self.nodes.items()):
            if kind == "directory":
                metadata = self.directories[name]["metadata"]
                entry = {"path": name or ".", "kind": kind, "mode": stat.S_IMODE(metadata["mode"])}
            elif kind == "file":
                record = self.files[name]
                entry = {"path": name, "kind": kind, "mode": stat.S_IMODE(record["metadata"]["mode"]),
                         "size": record["metadata"]["size"], "sha256": record["sha256"]}
            else:
                record = self.links[name]
                entry = {"path": name, "kind": kind, "target": record["target"]}
            encoded_size += len(canonical(entry))
            require(encoded_size <= MAX_DOCUMENT, "image-source summary document exceeds its bound")
            inventory.append(entry)
        logical = {"recipes": self.recipes, "policies": self.policy_selection, "inventory": inventory}
        raw = canonical(logical)
        require(len(raw) <= MAX_DOCUMENT, "image-source summary document exceeds its bound")
        return {"schema": SCHEMA, "claim": CLAIM, "source_dir": str(self.path),
                "sha256": hashlib.sha256(raw).hexdigest(), "recipes": self.recipes,
                "policies": self.policy_selection, "files": len(self.files),
                "directories": len(self.directories), "symlinks": len(self.links),
                "total_bytes": self.total_bytes, "inventory": inventory}

    @property
    def summary(self):
        require(not self.closed, "image-source context is closed")
        # Do not let a caller alter the retained logical identity.
        return json.loads(canonical(self._summary))

    def revalidate(self):
        with self.phase():
            self._revalidate()

    def __enter__(self):
        require(not self.closed, "image-source context is closed")
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        self.closed = True
        for record in self.files.values():
            os.close(record["fd"])
        self.files.clear()
        for record in reversed(list(self.directories.values())):
            os.close(record["fd"])
        self.directories.clear()
        if self.ancestry is not None:
            self.ancestry.close()
