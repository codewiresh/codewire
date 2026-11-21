#!/usr/bin/env python3
"""Synthetic proof for github-repository-protection.py against a fake `gh api`
that keeps both repositories' rulesets, environments, access and App
installations in a file and answers as GitHub does."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/dev/orchestrator/github-repository-protection.py"
TAP, MIRROR = "codewiresh/homebrew-codewire", "codewiresh/codewire"

FAKE_GH = r'''import json, os, re, sys
state_path = os.environ["FAKE_STATE"]
state = json.load(open(state_path))
args, method, body = sys.argv[2:], "GET", None
while args and args[0].startswith("-"):
    flag, value, args = args[0], args[1], args[2:]
    if flag == "-X":
        method = value
    elif flag == "--input":
        body = json.load(open(value))
path = args[0].split("?")[0]
with open(os.environ["FAKE_CALLS"], "a") as calls:
    calls.write(f"{method} {args[0]}\n")
answer = None
match = re.fullmatch(r"repos/(codewiresh/[^/]+)/(.*)", path)
if match:
    repo, rest = state["repos"][match.group(1)], match.group(2)
    if rest == "rulesets" and method == "GET":
        answer = [{"id": r["id"], "name": r["name"], "source_type": "Repository"} for r in repo["rulesets"]]
    elif rest == "rulesets" and method == "POST":
        state["next"] += 1
        repo["rulesets"].append({**body, "id": state["next"]})
        answer = {"id": state["next"]}
    elif rest.startswith("rulesets/"):
        wanted = int(rest.split("/")[1])
        if method == "PUT":
            repo["rulesets"] = [{**body, "id": wanted} if r["id"] == wanted else r for r in repo["rulesets"]]
        answer = {**next(r for r in repo["rulesets"] if r["id"] == wanted), "source_type": "Repository",
                  "node_id": "RRS_x", "_links": {}, "current_user_can_bypass": "always"}
    elif rest == "environments":
        answer = {"total_count": len(repo["environments"]),
                  "environments": [{"name": n, **{k: v for k, v in e.items() if k != "branches"}}
                                   for n, e in repo["environments"].items()]}
    elif re.fullmatch(r"environments/[^/]+", rest) and method == "PUT":
        name = rest.split("/")[1]
        env = repo["environments"].setdefault(name, {"branches": {}})
        env["deployment_branch_policy"] = body["deployment_branch_policy"]
        env["protection_rules"] = [{"id": 1, "type": "branch_policy"}]
        answer = {"name": name}
    elif re.fullmatch(r"environments/[^/]+/deployment-branch-policies", rest):
        env = repo["environments"][rest.split("/")[1]]
        if method == "POST":
            state["next"] += 1
            env["branches"][body["name"]] = state["next"]
        answer = {"branch_policies": [{"id": i, "name": n, "type": "branch"} for n, i in env["branches"].items()]}
    elif re.fullmatch(r"environments/[^/]+/deployment-branch-policies/\d+", rest) and method == "DELETE":
        env = repo["environments"][rest.split("/")[1]]
        env["branches"] = {n: i for n, i in env["branches"].items() if i != int(rest.split("/")[3])}
    elif rest == "collaborators":
        answer = repo["collaborators"]
    elif rest == "teams":
        answer = repo["teams"]
    elif rest == "keys":
        answer = repo["keys"]
    elif rest == "immutable-releases":
        answer = {"enabled": repo["immutable"], "enforced_by_owner": False}
elif path == "orgs/codewiresh/installations":
    answer = {"installations": state["installations"]}
elif re.fullmatch(r"user/installations/\d+/repositories", path):
    wanted = int(path.split("/")[2])
    covered = next(i for i in state["installations"] if i["id"] == wanted)["covers"]
    if covered is None:
        print("fake gh: HTTP 403", file=sys.stderr)
        sys.exit(1)
    answer = {"repositories": [{"full_name": name} for name in covered]}
if answer is None and method == "GET":
    print("fake gh: unexpected", method, args[0], file=sys.stderr)
    sys.exit(9)
json.dump(state, open(state_path, "w"))
if answer is not None:
    print(json.dumps(answer))
'''


def declared():
    spec = {"__name__": "declared"}
    exec(compile(HELPER.read_text(), str(HELPER), "exec"), spec)
    return spec


SPEC = declared()


def good_state():
    """Both repositories exactly as declared: the live state the owner made."""
    repos = {}
    for name, repository in SPEC["REPOSITORIES"].items():
        repos[name] = {
            "rulesets": [{**json.loads(json.dumps(r)), "id": 10 + i} for i, r in enumerate(repository["rulesets"])],
            "environments": {env: {"deployment_branch_policy": SPEC["BRANCH_POLICY"],
                                   "protection_rules": [{"id": 1, "type": "branch_policy"}],
                                   "branches": {branch: 50 + n for n, branch in enumerate(branches)}}
                             for env, branches in repository["environments"].items()},
            "collaborators": [{"login": "noeljackson", "permissions": {"admin": True, "push": True}},
                              {"login": "reader", "permissions": {"pull": True, "push": False}}],
            "teams": [{"slug": "readers", "permission": "pull"}],
            "keys": [{"id": 31, "title": "read-only mirror key", "read_only": True}],
            "immutable": False,
        }
    installations = [
        {"id": 1, "app_slug": "codewire-releases", "repository_selection": "selected",
         "permissions": {"contents": "write"}, "covers": [MIRROR]},
        {"id": 2, "app_slug": "codewire-release-homebrew", "repository_selection": "selected",
         "permissions": {"actions": "write"}, "covers": [TAP]},
        {"id": 3, "app_slug": "linear", "repository_selection": "all", "permissions": {"issues": "write"}, "covers": []},
    ]
    return {"repos": repos, "installations": installations, "next": 100}


class RepositoryProtection(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        (self.tmp / "bin").mkdir()
        gh = self.tmp / "bin/gh"
        # Only the fake is on PATH, with an absolute interpreter: the real gh,
        # signed in as a person, is never reachable from this test.
        gh.write_text(f"#!{sys.executable}\n" + FAKE_GH)
        gh.chmod(0o755)
        self.state_file = self.tmp / "state.json"
        self.calls = self.tmp / "calls"
        self.save(good_state())

    def save(self, state):
        self.state_file.write_text(json.dumps(state))

    def state(self):
        return json.loads(self.state_file.read_text())

    def run_helper(self, mode):
        self.calls.write_text("")
        env = {"PATH": str(self.tmp / "bin"), "FAKE_STATE": str(self.state_file), "FAKE_CALLS": str(self.calls),
               "HOME": str(self.tmp), "LC_ALL": "C"}
        result = subprocess.run([sys.executable, "-I", "-B", str(HELPER), mode], env=env,
                                capture_output=True, text=True, timeout=60)
        writes = [line for line in self.calls.read_text().splitlines() if not line.startswith("GET ")]
        return result, writes

    def drift(self, change):
        state = self.state()
        change(state)
        self.save(state)
        return self.run_helper("--check")

    def test_the_declared_state_passes_and_reports_immutable_releases(self):
        result, writes = self.run_helper("--check")
        self.assertEqual((result.returncode, writes), (0, []), result.stderr)
        self.assertIn(f"{MIRROR}: immutable releases off", result.stdout)
        # Collaborators are read with affiliation=all, so an organization owner counts.
        self.assertIn("affiliation=all", self.calls.read_text())
        result, writes = self.run_helper("--reconcile")
        self.assertEqual((result.returncode, writes), (0, []), result.stderr)

    def test_a_recorded_app_is_a_writer_only_of_the_repositories_its_record_names(self):
        # The owner's record: the two installed Apps in ACCEPTED_UNREAD cover
        # the mirror only, and neither is a declared writer of it.
        state = good_state()
        state["installations"] += [
            {"id": 7, "app_slug": "codewire-sh", "repository_selection": "selected",
             "permissions": {"contents": "write"}, "covers": None},
            {"id": 8, "app_slug": "claude", "repository_selection": "selected",
             "permissions": {"contents": "write", "workflows": "write"}, "covers": None}]
        self.save(state)
        result, writes = self.run_helper("--check")
        self.assertEqual((result.returncode, writes), (1, []))
        for slug in ("claude", "codewire-sh"):
            self.assertIn(f"{MIRROR}: app:{slug} can write it and is not a declared writer", result.stderr)
            self.assertIn(f"{TAP}: app:{slug}'s repositories can't be read; it doesn't cover this one, accepted on "
                          "the owner's record", result.stdout)
            self.assertNotIn(f"{TAP}: app:{slug} can write it", result.stderr)
        # Reconcile can't change who writes: it fails the same way and writes nothing.
        result, writes = self.run_helper("--reconcile")
        self.assertEqual((result.returncode, writes), (1, []))

    def test_the_declarations_match_the_owner_s_settings(self):
        tap = {r["name"]: r for r in SPEC["REPOSITORIES"][TAP]["rulesets"]}
        self.assertEqual(sorted(tap), ["lock-all-tags", "lock-side-branches", "protect-main"])
        self.assertEqual(tap["lock-side-branches"]["conditions"]["ref_name"],
                         {"include": ["~ALL"], "exclude": ["refs/heads/main"]})
        for value in tap.values():
            self.assertEqual(value["bypass_actors"], [SPEC["ADMIN"]])
            self.assertEqual(value["enforcement"], "active")
        self.assertEqual(SPEC["REPOSITORIES"][TAP]["writers"], {"user:noeljackson"})
        self.assertEqual({slug: covers for slug, (covers, _) in SPEC["ACCEPTED_UNREAD"].items()},
                         {"codewire-sh": (MIRROR,), "claude": (MIRROR,)})
        mirror = SPEC["REPOSITORIES"][MIRROR]
        self.assertEqual(mirror["environments"], {"crates-io": ["main"], "npm": ["main"], "pypi": ["main"]})
        self.assertEqual(mirror["writers"], {"user:noeljackson", "app:codewire-releases"})

    def test_check_fails_on_ruleset_drift_and_writes_nothing(self):
        def first(state):
            return state["repos"][TAP]["rulesets"][1]
        changes = {
            "evaluate": lambda s: first(s).update(enforcement="evaluate"),
            "extra bypass": lambda s: first(s)["bypass_actors"].append(
                {"actor_type": "Team", "actor_id": 7, "bypass_mode": "always"}),
            "bypass mode": lambda s: first(s)["bypass_actors"][0].update(bypass_mode="pull_request"),
            "missing rule": lambda s: first(s).update(rules=first(s)["rules"][:-1]),
            "extra rule": lambda s: first(s)["rules"].append({"type": "required_signatures"}),
            "main no longer excluded": lambda s: first(s)["conditions"]["ref_name"].update(exclude=[]),
            "missing ruleset": lambda s: s["repos"][TAP]["rulesets"].pop(0),
            "undeclared ruleset": lambda s: s["repos"][MIRROR]["rulesets"].append(
                {**s["repos"][MIRROR]["rulesets"][0], "id": 99, "name": "someone's"}),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                self.save(good_state())
                result, writes = self.drift(change)
                self.assertEqual((result.returncode, writes), (1, []), name)
                self.assertIn("ruleset", result.stderr)

    def test_check_fails_on_environment_drift(self):
        def crates(state):
            return state["repos"][MIRROR]["environments"]["crates-io"]
        changes = {
            "missing crates-io": lambda s: s["repos"][MIRROR]["environments"].pop("crates-io"),
            "any branch": lambda s: crates(s).update(deployment_branch_policy=None),
            "protected branches": lambda s: crates(s).update(
                deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False}),
            "a second branch": lambda s: crates(s)["branches"].update({"release": 77}),
            "no branch": lambda s: crates(s).update(branches={}),
            "a reviewer rule": lambda s: crates(s)["protection_rules"].append({"id": 2, "type": "required_reviewers"}),
            "undeclared environment": lambda s: s["repos"][MIRROR]["environments"].update(
                {"github-pages": {"deployment_branch_policy": None, "protection_rules": [], "branches": {}}}),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                self.save(good_state())
                result, writes = self.drift(change)
                self.assertEqual((result.returncode, writes), (1, []), name)
                self.assertIn("environment", result.stderr)

    def test_check_fails_on_an_undeclared_writer(self):
        changes = {
            "app on all repositories": (lambda s: s["installations"].append(
                {"id": 4, "app_slug": "codewire-sh", "repository_selection": "all",
                 "permissions": {"contents": "write"}, "covers": []}), "app:codewire-sh", TAP),
            "selected app on the tap": (lambda s: s["installations"].append(
                {"id": 5, "app_slug": "claude", "repository_selection": "selected",
                 "permissions": {"contents": "write"}, "covers": [TAP]}), "app:claude", TAP),
            "mirror App on the tap": (lambda s: s["installations"][0]["covers"].append(TAP),
                                      "app:codewire-releases", TAP),
            "collaborator": (lambda s: s["repos"][TAP]["collaborators"].append(
                {"login": "someone", "permissions": {"push": True}}), "user:someone", TAP),
            "write deploy key": (lambda s: s["repos"][TAP]["keys"].append(
                {"id": 32, "title": "writer", "read_only": False}), "key:32", TAP),
            "deploy key without read_only": (lambda s: s["repos"][MIRROR]["keys"].append(
                {"id": 33, "title": "unknown"}), "key:33", MIRROR),
            "administration write": (lambda s: s["installations"].append(
                {"id": 9, "app_slug": "settings-bot", "repository_selection": "selected",
                 "permissions": {"administration": "write"}, "covers": [TAP]}), "app:settings-bot", TAP),
            "recorded App reaching the tap": (lambda s: s["installations"].append(
                {"id": 10, "app_slug": "unrecorded-app", "repository_selection": "selected",
                 "permissions": {"contents": "write"}, "covers": [TAP]}), "app:unrecorded-app", TAP),
            "team": (lambda s: s["repos"][MIRROR]["teams"].append({"slug": "devs", "permission": "maintain"}),
                     "team:devs", MIRROR),
        }
        for name, (change, writer, repository) in changes.items():
            with self.subTest(change=name):
                self.save(good_state())
                result, writes = self.drift(change)
                self.assertEqual((result.returncode, writes), (1, []), name)
                self.assertIn(f"{repository}: {writer} can write it", result.stderr)

    def test_reconcile_creates_the_crates_io_environment_and_missing_rulesets(self):
        state = good_state()
        state["repos"][MIRROR]["environments"].pop("crates-io")
        state["repos"][MIRROR]["rulesets"] = [r for r in state["repos"][MIRROR]["rulesets"]
                                              if r["name"] != "lock-all-tags"]
        self.save(state)
        result, writes = self.run_helper("--reconcile")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(writes, [f"POST repos/{MIRROR}/rulesets", f"PUT repos/{MIRROR}/environments/crates-io",
                                  f"POST repos/{MIRROR}/environments/crates-io/deployment-branch-policies"])
        crates = self.state()["repos"][MIRROR]["environments"]["crates-io"]
        self.assertEqual(sorted(crates["branches"]), ["main"])
        result, writes = self.run_helper("--reconcile")
        self.assertEqual((result.returncode, writes), (0, []), "a second reconcile wrote")

    def test_reconcile_narrows_an_environment_and_replaces_a_drifted_ruleset(self):
        state = good_state()
        state["repos"][MIRROR]["environments"]["npm"]["branches"]["release"] = 77
        state["repos"][TAP]["rulesets"][0]["enforcement"] = "disabled"
        self.save(state)
        result, writes = self.run_helper("--reconcile")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"PUT repos/{TAP}/rulesets/10", writes)
        self.assertIn("replacing: codewiresh/homebrew-codewire: ruleset 'lock-all-tags' enforcement: want \"active\", "
                      "have \"disabled\"", result.stdout)
        self.assertIn("setting: codewiresh/codewire: environment 'npm' admits", result.stdout)
        self.assertIn(f"DELETE repos/{MIRROR}/environments/npm/deployment-branch-policies/77", writes)
        self.assertEqual(sorted(self.state()["repos"][MIRROR]["environments"]["npm"]["branches"]), ["main"])

    def test_reconcile_refuses_what_it_does_not_declare(self):
        for change in (lambda s: s["repos"][TAP]["rulesets"].append({**s["repos"][TAP]["rulesets"][0], "id": 99,
                                                                     "name": "someone's"}),
                       lambda s: s["repos"][MIRROR]["environments"].update(
                           {"github-pages": {"deployment_branch_policy": None, "protection_rules": [], "branches": {}}})):
            with self.subTest():
                state = good_state()
                change(state)
                self.save(state)
                result, writes = self.run_helper("--reconcile")
                self.assertEqual((result.returncode, writes), (1, []))
                self.assertIn("remove it by hand", result.stderr)

    def test_an_installation_whose_repositories_cannot_be_read_needs_the_owner_s_record(self):
        state = good_state()
        state["installations"].append({"id": 6, "app_slug": "unrecorded-app", "repository_selection": "selected",
                                       "permissions": {"contents": "write"}, "covers": None})
        self.save(state)
        result, writes = self.run_helper("--check")
        self.assertEqual((result.returncode, writes), (1, []))
        for repository in (TAP, MIRROR):
            self.assertIn(f"{repository}: app:unrecorded-app has write on repositories that can't be read; "
                          "unverified", result.stderr)
        self.assertNotIn("app:codewire-releases has write", result.stderr)

    def test_a_full_page_fails_closed(self):
        state = good_state()
        state["repos"][TAP]["collaborators"] = [{"login": f"r{n}", "permissions": {"pull": True}} for n in range(100)]
        self.save(state)
        result, writes = self.run_helper("--check")
        self.assertEqual((result.returncode, writes), (1, []))
        self.assertIn("filled a page of 100", result.stderr)

    def test_a_writer_is_never_reconciled(self):
        state = good_state()
        state["repos"][TAP]["collaborators"].append({"login": "someone", "permissions": {"admin": True}})
        self.save(state)
        result, writes = self.run_helper("--reconcile")
        self.assertEqual((result.returncode, writes), (1, []))
        self.assertIn("user:someone can write it", result.stderr)


if __name__ == "__main__":
    unittest.main()
