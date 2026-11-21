#!/usr/bin/env python3
"""Keep Codewire's public GitHub repositories protected as declared below.

  github-repository-protection.py --check       compare, change nothing
  github-repository-protection.py --reconcile   create or replace the
                                                rulesets and environments
                                                that differ, then check

For codewiresh/homebrew-codewire (the Homebrew tap) and codewiresh/codewire
(the public mirror) it checks, each against its declaration:

- every repository ruleset, whole: target, enforcement, conditions, every rule
  with its parameters, and every bypass actor's type, id and mode. Anything
  extra or missing fails, and so does an undeclared ruleset;
- every deployment environment: it admits exactly the declared branches and
  has no other protection rule. An undeclared environment fails;
- who can write the repository: a collaborator or team with push, maintain
  or admin (affiliation all, so an organization owner counts), a deploy key
  that isn't read-only, or a GitHub App installation that covers the
  repository with contents or administration write, outside the declared
  writers, fails. An installation on selected repositories whose list can't
  be read covers what the owner's dated record says (ACCEPTED_UNREAD), and
  without a record it is unverified and fails. Reconcile cannot fix this;
  the owner narrows the installation or access;
- immutable releases, read and reported. It stays off on the mirror until
  publish-cw-release.sh uploads to a draft before publishing, since GitHub
  refuses an asset added to a published immutable release.

Why every ref, and why a write-access check: docs/dev/CLI-HOMEBREW-INSTALL.md,
"The tap's protection" (cw-security, 2026-11-19, on #5407). Runs through
`gh api` as whoever `gh` is signed in as, an organization owner; the token
stays inside gh and is never printed.
"""
import argparse
import json
import subprocess
import sys
import tempfile

ORGANIZATION = "codewiresh"
TAP = "codewiresh/homebrew-codewire"
MIRROR = "codewiresh/codewire"
# GitHub's fixed id for the repository admin role, and the codewire-releases
# App, which pushes the mirror's main and signed tags (mirror-github.sh).
ADMIN = {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}
CODEWIRE_RELEASES = {"actor_type": "Integration", "actor_id": 4118373, "bypass_mode": "always"}


def ruleset(name, target, include, exclude, rules, bypass):
    return {"name": name, "target": target, "enforcement": "active",
            "conditions": {"ref_name": {"include": include, "exclude": exclude}},
            "rules": [{"type": rule} for rule in rules], "bypass_actors": bypass}


# The tap's workflow commits to main with its own token, and GitHub refuses
# the Actions App as a bypass actor, so main's updates stay open and the
# write-access check stands in for that restriction.
REPOSITORIES = {
    TAP: {
        "rulesets": [
            ruleset("lock-all-tags", "tag", ["~ALL"], [], ["creation", "update", "deletion"], [ADMIN]),
            ruleset("lock-side-branches", "branch", ["~ALL"], ["refs/heads/main"],
                    ["creation", "update", "deletion", "non_fast_forward"], [ADMIN]),
            ruleset("protect-main", "branch", ["refs/heads/main"], [], ["deletion", "non_fast_forward"], [ADMIN]),
        ],
        "environments": {},
        "writers": {"user:noeljackson"},
    },
    MIRROR: {
        "rulesets": [
            ruleset("main", "branch", ["~DEFAULT_BRANCH"], [], ["update", "deletion", "non_fast_forward"],
                    [CODEWIRE_RELEASES]),
            ruleset("lock-all-tags", "tag", ["~ALL"], [], ["creation", "update", "deletion"],
                    [ADMIN, CODEWIRE_RELEASES]),
        ],
        # sdk-release.yml publishes each SDK from main only, by trusted
        # publishing in its registry's environment.
        "environments": {"crates-io": ["main"], "npm": ["main"], "pypi": ["main"]},
        # The two installed Apps in ACCEPTED_UNREAD cover the mirror and fail
        # here until the owner decides they keep contents write on it.
        "writers": {"user:noeljackson", "app:codewire-releases"},
    },
}
# An installation on selected repositories whose list gh can't read (the
# owner's user token can't) covers exactly the repositories the owner's dated
# record names: app slug -> (those repositories, the record). Without a
# record it is unverified and fails the check.
OWNER_SELECTED_MIRROR = 'owner, 2026-11-19, on #5407: "yes just codewire repo was selected"'
ACCEPTED_UNREAD = {
    "codewire-sh": ((MIRROR,), OWNER_SELECTED_MIRROR),
    "claude": ((MIRROR,), OWNER_SELECTED_MIRROR),
}
RULESET_FIELDS = ("name", "target", "enforcement", "conditions", "rules", "bypass_actors")
BRANCH_POLICY = {"protected_branches": False, "custom_branch_policies": True}
WRITE = ("admin", "maintain", "push")
# Installation permissions that let an App write the repository or remove its
# rulesets.
APP_WRITE = ("contents", "administration")
PAGE = 100


class ProtectionError(Exception):
    pass


def gh(*args, body=None):
    """One `gh api` call; its JSON answer, or ProtectionError without gh's output."""
    command = ["gh", "api", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
    with tempfile.NamedTemporaryFile("w", suffix=".json") as payload:
        if body is not None:
            json.dump(body, payload)
            payload.flush()
            command += ["--input", payload.name]
        result = subprocess.run([*command, *args], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise ProtectionError(f"gh api {' '.join(args)} failed (exit {result.returncode})")
    return json.loads(result.stdout) if result.stdout.strip() else None


def one_page(values, what):
    """A list answer that fits one page; a full page may hide more, so it fails."""
    values = values or []
    if len(values) >= PAGE:
        raise ProtectionError(f"{what} filled a page of {PAGE}; refusing to judge a partial list")
    return values


def sort_list(values):
    return sorted(values, key=lambda value: json.dumps(value, sort_keys=True))


def normal_ruleset(value):
    missing = [field for field in RULESET_FIELDS if field not in value]
    if missing:
        raise ProtectionError(f"ruleset {value.get('name')!r} has no {', '.join(missing)}")
    value = {field: value[field] for field in RULESET_FIELDS}
    value["rules"] = sort_list(value["rules"])
    value["bypass_actors"] = sort_list(value["bypass_actors"] or [])
    return value


def live_rulesets(repository):
    """{name: (id, full ruleset)} for the repository's own rulesets."""
    found = {}
    for summary in one_page(gh(f"repos/{repository}/rulesets?includes_parents=false&per_page={PAGE}"),
                            f"{repository} rulesets"):
        if summary.get("source_type", "Repository") != "Repository":
            continue
        if summary["name"] in found:
            raise ProtectionError(f"{repository}: two rulesets are named {summary['name']!r}")
        found[summary["name"]] = (summary["id"], gh(f"repos/{repository}/rulesets/{summary['id']}"))
    return found


def ruleset_problems(repository, declared, found):
    names = {value["name"] for value in declared}
    problems = [f"{repository}: undeclared ruleset {name!r}" for name in sorted(set(found) - names)]
    for value in declared:
        if value["name"] not in found:
            problems.append(f"{repository}: missing ruleset {value['name']!r}")
            continue
        want, have = normal_ruleset(value), normal_ruleset(found[value["name"]][1])
        for field in RULESET_FIELDS:
            if want[field] != have[field]:
                problems.append(f"{repository}: ruleset {value['name']!r} {field}: want "
                                f"{json.dumps(want[field], sort_keys=True)}, have {json.dumps(have[field], sort_keys=True)}")
    return problems


def live_environments(repository):
    """{name: (environment, [(policy name, type)], {policy name: id})}."""
    found = {}
    listed_environments = (gh(f"repos/{repository}/environments?per_page={PAGE}") or {}).get("environments")
    for environment in one_page(listed_environments, f"{repository} environments"):
        name = environment["name"]
        policies = gh(f"repos/{repository}/environments/{name}/deployment-branch-policies?per_page={PAGE}") or {}
        listed = one_page(policies.get("branch_policies"), f"{repository} {name} branch policies")
        found[name] = (environment, sorted((p["name"], p.get("type", "branch")) for p in listed),
                       {p["name"]: p["id"] for p in listed})
    return found


def environment_problems(repository, declared, found):
    problems = [f"{repository}: undeclared environment {name!r}" for name in sorted(set(found) - set(declared))]
    for name, branches in sorted(declared.items()):
        if name not in found:
            problems.append(f"{repository}: missing environment {name!r}")
            continue
        environment, policies, _ = found[name]
        if environment.get("deployment_branch_policy") != BRANCH_POLICY:
            problems.append(f"{repository}: environment {name!r} does not admit only its custom branch policies")
        rules = sorted(rule.get("type") for rule in environment.get("protection_rules") or [])
        if rules != ["branch_policy"]:
            problems.append(f"{repository}: environment {name!r} protection rules are {rules}, not ['branch_policy']")
        if policies != sorted((branch, "branch") for branch in branches):
            problems.append(f"{repository}: environment {name!r} admits {policies}, not {sorted(branches)}")
    return problems


def writers(repository):
    """Everyone who can write the repository, as user:, team:, key: and app:
    names; the installations whose coverage rests on the owner's record; and
    those whose selected repositories can't be read and have no record."""
    found, recorded, unread = set(), set(), set()
    for user in one_page(gh(f"repos/{repository}/collaborators?affiliation=all&per_page={PAGE}"),
                         f"{repository} collaborators"):
        if any((user.get("permissions") or {}).get(level) for level in WRITE):
            found.add(f"user:{user['login']}")
    for team in one_page(gh(f"repos/{repository}/teams?per_page={PAGE}"), f"{repository} teams"):
        if team.get("permission") in WRITE:
            found.add(f"team:{team['slug']}")
    for key in one_page(gh(f"repos/{repository}/keys?per_page={PAGE}"), f"{repository} deploy keys"):
        if key.get("read_only") is not True:
            found.add(f"key:{key['id']}")
    installations = (gh(f"orgs/{ORGANIZATION}/installations?per_page={PAGE}") or {}).get("installations")
    for installation in one_page(installations, f"{ORGANIZATION} installations"):
        permissions = installation.get("permissions") or {}
        if not any(permissions.get(name) == "write" for name in APP_WRITE):
            continue
        slug = installation["app_slug"]
        if installation.get("repository_selection") == "all":
            found.add(f"app:{slug}")
            continue
        try:
            covered = gh(f"user/installations/{installation['id']}/repositories?per_page={PAGE}") or {}
        except ProtectionError:
            if slug not in ACCEPTED_UNREAD:
                unread.add(slug)
            elif repository in ACCEPTED_UNREAD[slug][0]:
                found.add(f"app:{slug}")
            else:
                recorded.add(slug)
            continue
        if repository in {r["full_name"] for r in one_page(covered.get("repositories"), f"{slug} repositories")}:
            found.add(f"app:{slug}")
    return found, recorded, unread


def check():
    problems = []
    for repository, declared in REPOSITORIES.items():
        problems += ruleset_problems(repository, declared["rulesets"], live_rulesets(repository))
        problems += environment_problems(repository, declared["environments"], live_environments(repository))
        found, recorded, unread = writers(repository)
        problems += [f"{repository}: {writer} can write it and is not a declared writer"
                     for writer in sorted(found - declared["writers"])]
        for slug in sorted(recorded):
            print(f"github-repository-protection: {repository}: app:{slug}'s repositories can't be read; it doesn't "
                  f"cover this one, accepted on the owner's record: {ACCEPTED_UNREAD[slug][1]}")
        problems += [f"{repository}: app:{slug} has write on repositories that can't be read; unverified"
                     for slug in sorted(unread)]
        immutable = gh(f"repos/{repository}/immutable-releases") or {}
        print(f"github-repository-protection: {repository}: immutable releases "
              f"{'on' if immutable.get('enabled') else 'off'}")
    for problem in problems:
        print(f"github-repository-protection: {problem}", file=sys.stderr)
    return not problems


def reconcile_rulesets(repository, declared):
    found = live_rulesets(repository)
    for name in sorted(set(found) - {value["name"] for value in declared}):
        raise ProtectionError(f"{repository}: undeclared ruleset {name!r}; read it and remove it by hand")
    for value in declared:
        if value["name"] not in found:
            gh("-X", "POST", f"repos/{repository}/rulesets", body=value)
            print(f"github-repository-protection: {repository}: created ruleset {value['name']!r}")
        elif normal_ruleset(value) != normal_ruleset(found[value["name"]][1]):
            # The record shows what a replacement loosens or tightens.
            for problem in ruleset_problems(repository, [value], {value["name"]: found[value["name"]]}):
                print(f"github-repository-protection: replacing: {problem}")
            gh("-X", "PUT", f"repos/{repository}/rulesets/{found[value['name']][0]}", body=value)
            print(f"github-repository-protection: {repository}: replaced ruleset {value['name']!r}")


def reconcile_environments(repository, declared):
    found = live_environments(repository)
    for name in sorted(set(found) - set(declared)):
        raise ProtectionError(f"{repository}: undeclared environment {name!r}; read it and remove it by hand")
    for name, branches in sorted(declared.items()):
        drift = ([f"{repository}: missing environment {name!r}"] if name not in found
                 else environment_problems(repository, {name: branches}, {name: found[name]}))
        if drift:
            for problem in drift:
                print(f"github-repository-protection: setting: {problem}")
            gh("-X", "PUT", f"repos/{repository}/environments/{name}",
               body={"deployment_branch_policy": BRANCH_POLICY, "reviewers": [], "wait_timer": 0})
            print(f"github-repository-protection: {repository}: set environment {name!r}")
            ids = found[name][2] if name in found else {}
            for branch, policy in ids.items():
                if branch not in branches:
                    gh("-X", "DELETE", f"repos/{repository}/environments/{name}/deployment-branch-policies/{policy}")
            for branch in branches:
                if branch not in ids:
                    gh("-X", "POST", f"repos/{repository}/environments/{name}/deployment-branch-policies",
                       body={"name": branch, "type": "branch"})


def reconcile():
    for repository, declared in REPOSITORIES.items():
        reconcile_rulesets(repository, declared["rulesets"])
        reconcile_environments(repository, declared["environments"])
    return check()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args(argv)
    try:
        ok = reconcile() if args.reconcile else check()
    except ProtectionError as error:
        print(f"github-repository-protection: {error}", file=sys.stderr)
        return 1
    print(f"github-repository-protection: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
