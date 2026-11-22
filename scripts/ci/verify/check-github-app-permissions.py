#!/usr/bin/env python3
"""Read the permissions GitHub lists for Codewire's GitHub App and compare them.

The credential broker's GitHub route is written for an App that holds exactly
`contents: write`, `pull_requests: write` and `metadata: read`, which every
installation needs (`REQUIRED_PERMISSIONS` in
crates/codewire-credential-broker/src/github_app.rs), and `actions: read`,
which it requests for Actions reads but doesn't need (#5737). A wider App, with `administration` for example, would let a sandbox do more
through the managed credential than the route was reviewed for (#4926). The
App's settings live at GitHub, outside this repository, so a scheduled run
reads its public record once a day, with no credential.

Three results:

- read, and the set is the expected one: success;
- read, and the set differs, or GitHub's answer is one this check cannot
  interpret: failure, naming each difference;
- could not read (rate limited, a timeout, a 5xx): a warning and success,
  after a few tries inside the run. The run prints `app-permissions: unread`
  in its log and step summary. The job keeps no state between runs; whoever
  sweeps scheduled runs counts consecutive unread days. A caller that does
  know the count passes --earlier-unread-days, and the third unread day in a
  row fails.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO

APP_SLUG = "codewire-sh"
APP_URL = f"https://api.github.com/apps/{APP_SLUG}"
# What every installation needs: the broker's REQUIRED_PERMISSIONS.
REQUIRED = {"contents": "write", "metadata": "read", "pull_requests": "write"}
# Requested, not needed: an installation without it keeps everything else and
# gets GitHub's own 403 for Actions reads (#5737).
REQUESTED = {"actions": "read"}
EXPECTED = {**REQUIRED, **REQUESTED}
LEVELS = {"read": 1, "write": 2, "admin": 3}
ATTEMPTS = 4
RETRY_WAIT_SECONDS = 150
# An unread run on a day after this many unread days fails.
UNREAD_DAYS_ALLOWED = 2


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class Unread(Exception):
    """GitHub could not be read this time; nothing is known about the App."""


class Changed(Exception):
    """GitHub answered, and the answer is not the expected permission set."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


Fetch = Callable[[], Response]


def curl_fetch() -> Response:
    """GET the App's public record with no credential and no redirect."""
    with tempfile.TemporaryDirectory(prefix="codewire-app-permissions-") as temporary:
        headers_path = Path(temporary) / "headers"
        body_path = Path(temporary) / "body"
        try:
            completed = subprocess.run(
                [
                    "curl", "--silent", "--show-error", "--max-time", "30",
                    "--proto", "=https", "--tlsv1.2",
                    "--header", "Accept: application/vnd.github+json",
                    "--header", "X-GitHub-Api-Version: 2022-11-28",
                    "--dump-header", str(headers_path), "--output", str(body_path),
                    "--write-out", "%{http_code}", APP_URL,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Unread("the request did not complete") from exc
        if completed.returncode != 0 or not completed.stdout.strip().isdigit():
            raise Unread(f"the request did not complete (curl exit {completed.returncode})")
        try:
            return Response(
                int(completed.stdout.strip()),
                parse_headers(headers_path.read_text(errors="replace")),
                body_path.read_bytes(),
            )
        except OSError as exc:
            raise Unread("the response could not be read back") from exc


def parse_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return headers


def permissions_from(response: Response) -> dict[str, str]:
    """The App's permission set, or Unread, or Changed for any other answer."""
    status = response.status
    rate_limited = status == 429 or (
        status == 403
        and (response.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in response.headers)
    )
    if rate_limited:
        raise Unread(f"GitHub rate limited the request ({status})")
    if 500 <= status <= 599:
        raise Unread(f"GitHub answered {status}")
    if status != 200:
        raise Changed([f"GitHub answered {status} for {APP_URL}; the App's permissions cannot be confirmed"])
    try:
        record = json.loads(response.body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Changed(["GitHub's answer is not JSON"]) from exc
    if not isinstance(record, dict) or record.get("slug") != APP_SLUG:
        raise Changed([f"GitHub's answer is not the record of {APP_SLUG}"])
    permissions = record.get("permissions")
    if not isinstance(permissions, dict) or not all(
        isinstance(name, str) and isinstance(level, str) for name, level in permissions.items()
    ):
        raise Changed(["GitHub's answer has no readable permissions"])
    return permissions


def differences(permissions: dict[str, str]) -> list[str]:
    """Each way the App's set differs from the expected one, widenings first."""
    wider: list[str] = []
    narrower: list[str] = []
    for name in sorted(set(permissions) | set(EXPECTED)):
        have, want = permissions.get(name), EXPECTED.get(name)
        if have == want:
            continue
        if want is None:
            wider.append(f"wider: the App holds {name}: {have}, which the GitHub route does not expect")
        elif have is None:
            narrower.append(f"narrower: the App no longer holds {name}: {want}")
        # A level this check does not know counts as wider.
        elif LEVELS.get(have, len(LEVELS) + 1) > LEVELS[want]:
            wider.append(f"wider: the App holds {name}: {have}, expected {name}: {want}")
        else:
            narrower.append(f"narrower: the App holds {name}: {have}, expected {name}: {want}")
    return wider + narrower


def read_permissions(fetch: Fetch, sleep: Callable[[float], None], out: TextIO) -> dict[str, str]:
    """Try a few times; only a could-not-read answer is tried again."""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            response = fetch()
            limit = response.headers.get("x-ratelimit-limit", "unknown")
            remaining = response.headers.get("x-ratelimit-remaining", "unknown")
            print(f"rate limit: {remaining} of {limit} requests remain", file=out)
            return permissions_from(response)
        except Unread as unread:
            print(f"attempt {attempt} of {ATTEMPTS}: {unread}", file=out)
            if attempt == ATTEMPTS:
                raise
            sleep(RETRY_WAIT_SECONDS)
    raise AssertionError("unreachable")


def report(result: str, lines: list[str], environ: dict[str, str], out: TextIO) -> None:
    """The fixed result line and its details, in the log and the step summary."""
    marker = f"app-permissions: {result}"
    print(marker, file=out)
    summary = environ.get("GITHUB_STEP_SUMMARY", "")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"## GitHub App permissions\n\n`{marker}`\n\n")
            handle.writelines(f"- {line}\n" for line in lines)


def main(
    argv: list[str],
    fetch: Fetch = curl_fetch,
    sleep: Callable[[float], None] = time.sleep,
    environ: dict[str, str] | None = None,
    out: TextIO = sys.stdout,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--earlier-unread-days",
        type=int,
        default=0,
        help="consecutive days before this run that ended unread (default 0)",
    )
    arguments = parser.parse_args(argv)
    if arguments.earlier_unread_days < 0:
        parser.error("--earlier-unread-days must not be negative")
    environ = dict(os.environ) if environ is None else environ

    try:
        permissions = read_permissions(fetch, sleep, out)
    except Unread as unread:
        lines = [f"GitHub could not be read: {unread}. Nothing is known about the App from this run."]
        if arguments.earlier_unread_days >= UNREAD_DAYS_ALLOWED:
            days = arguments.earlier_unread_days + 1
            print(f"::error::the GitHub App's permissions have not been read for {days} days: {unread}", file=out)
            report("unread", lines, environ, out)
            return 1
        print(f"::warning::the GitHub App's permissions were not read today: {unread}", file=out)
        report("unread", lines, environ, out)
        return 0
    except Changed as changed:
        problems = changed.problems
    else:
        problems = differences(permissions)
        held = ", ".join(f"{name}: {level}" for name, level in sorted(permissions.items()))
        print(f"{APP_SLUG} holds {held or 'no permissions'}", file=out)
        if not problems:
            report("read", [f"{APP_SLUG} holds the expected set: {held}"], environ, out)
            return 0
    for problem in problems:
        print(f"::error::GitHub App {APP_SLUG}: {problem}", file=out)
    report("changed", problems, environ, out)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
