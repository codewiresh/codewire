#!/usr/bin/env python3
"""Static guard for the fixed App Sandbox canary experiment topology."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = (ROOT / "Package.swift").read_text()
OWNER = (ROOT / "Sources/SandboxExperimentOwner/main.swift").read_text()
CANDIDATE = (ROOT / "Sources/SandboxCandidate/main.swift").read_text()
DEPUTY = (ROOT / "Sources/CanaryDeputy/main.swift").read_text()
PROTOCOL = (ROOT / "Sources/SandboxCanaryProtocol/Protocol.swift").read_text()
SUPPORT = (ROOT / "Sources/CCanarySupport/CCanarySupport.c").read_text()
HEADER = (ROOT / "Sources/CCanarySupport/include/CCanarySupport.h").read_text()
RUN_LOOP = (ROOT / "Tests/test_run_loop.swift").read_text()
LIFECYCLE = (ROOT / "Sources/CanaryDeputy/ApplicationLifecycle.swift").read_text()
LIFECYCLE_TEST = (ROOT / "Tests/test_application_lifecycle.swift").read_text()


products = re.findall(r'\.executable\(name: "([^"]+)"', PACKAGE)
expected = ["sandbox-experiment-owner", "sandbox-candidate", "canary-deputy"]
if products != expected:
    raise SystemExit(f"unexpected executable product topology: {products}")

if "CommandLine.arguments.count == 1" not in CANDIDATE:
    raise SystemExit("candidate must be argument-free")
if "CommandLine.arguments.count == 1" not in DEPUTY:
    raise SystemExit("deputy must be argument-free")
for required in (
    "createsNewApplicationInstance = true",
    "allowsRunningApplicationSubstitution = false",
    "addsToRecentItems = false",
    "promptsUserIfNeeded = false",
    "observe(\\.isTerminated",
    "CFRunLoopMode.defaultMode",
    'kind: "instance-live"',
):
    if required not in CANDIDATE:
        raise SystemExit(f"candidate lacks fixed launch observation: {required}")

for forbidden in (
    "configuration.arguments",
    "configuration.environment",
    "forceTerminate",
    ".terminate()",
    "NSAppleScript",
    "LSSetDefault",
    "SMAppService",
    "URLSession",
):
    if forbidden in CANDIDATE + DEPUTY + OWNER:
        raise SystemExit(f"forbidden experiment authority: {forbidden}")

for source in (CANDIDATE, DEPUTY, LIFECYCLE, OWNER, PROTOCOL, SUPPORT, HEADER):
    for forbidden in ("AF_INET", "PF_INET", "SOCK_DGRAM", "getaddrinfo", "http://", "https://"):
        if forbidden in source:
            raise SystemExit(f"IP network path present in canary experiment: {forbidden}")

if (
    'WireMessage(kind: "arm"' not in OWNER
    or 'WireMessage(kind: "reassert-instance"' not in OWNER
    or "observeCanary" not in DEPUTY
):
    raise SystemExit("deputy action must remain owner-armed and fixed to the canary read")
if "cw_canary_verify_connected_peer" not in OWNER:
    raise SystemExit("owner must dynamically bind the accepted deputy peer")
if "cw_canary_verify_direct_child" not in OWNER:
    raise SystemExit("owner must bind each exclusively unreaped direct child to pinned code")
if "mutable most-recent-accessor" not in HEADER:
    raise SystemExit("inherited socketpair identity limitation must remain explicit")
if SUPPORT.count("LOCAL_PEERTOKEN") != 1 or SUPPORT.count("LOCAL_PEERPID") != 1:
    raise SystemExit("peer identity must be read only by the connected-deputy verifier")
if "POSIX_SPAWN_CLOEXEC_DEFAULT" not in SUPPORT or "posix_spawn" not in SUPPORT:
    raise SystemExit("direct child FD inheritance must stay closed and exact")
if "cw_canary_normalize_sigchld()" not in OWNER:
    raise SystemExit("owner must restore the exclusive-reaper SIGCHLD premise before spawning")
if "cw_canary_cleanup_child(childPID)" not in OWNER:
    raise SystemExit("owner cleanup must use the ownership-checking signal helper")
if SUPPORT.count("signal_owned_group(pid, SIGTERM)") != 1:
    raise SystemExit("TERM must occur only inside the ownership-checking cleanup helper")
if SUPPORT.count("signal_owned_group(pid, SIGKILL)") != 1:
    raise SystemExit("KILL must occur only inside the ownership-checking cleanup helper")
if "cw_canary_replace_checkpoint" not in OWNER or "recordPositive" not in OWNER:
    raise SystemExit("authenticated positive evidence must be durably checkpointed")
if "expectedSHA256" in CANDIDATE + PROTOCOL:
    raise SystemExit("expected canary hash must remain owner-only")
if "kCFRunLoopCommonModes" in CANDIDATE:
    raise SystemExit("common-modes set is not itself a runnable run-loop mode")
if 'WireMessage(kind: "continue-delegation"' not in OWNER:
    raise SystemExit("owner must explicitly authorize each deputy launch")
if 'WireMessage(kind: "finish"' not in OWNER:
    raise SystemExit("owner must stop before delegation when direct observations disallow it")
direct_positive = OWNER.index('if directObservation == "succeeded" {')
direct_checkpoint = OWNER.index("try onPositive(progress)", direct_positive)
direct_gate = OWNER.index("let delegationAllowed", direct_checkpoint)
if not direct_positive < direct_checkpoint < direct_gate:
    raise SystemExit("a direct positive must be checkpointed before delegation or finish")
deputy_positive = OWNER.index('if deputyObservation == "succeeded" {')
deputy_checkpoint = OWNER.index("try onPositive(progress)", deputy_positive)
deputy_eof = OWNER.index("guard readEOF", deputy_checkpoint)
if not deputy_positive < deputy_checkpoint < deputy_eof:
    raise SystemExit("a deputy positive must be checkpointed before EOF/termination waits")
if '.linkedLibrary("bsm"' not in PACKAGE:
    raise SystemExit("audit_token_to_pid must retain its explicit libbsm link")
for required in (
    "Thread.isMainThread",
    "NSLock()",
    "DispatchQueue.global().async",
    "DispatchQueue.main.async",
    "CFRunLoopMode.defaultMode",
    "Date().addingTimeInterval(2)",
    "Darwin.exit(1)",
):
    if required not in RUN_LOOP:
        raise SystemExit(f"standalone default-mode run-loop fixture lacks: {required}")
for forbidden in ("@main", "@MainActor", "Task {", "kCFRunLoopCommonModes"):
    if forbidden in RUN_LOOP:
        raise SystemExit(f"standalone run-loop fixture must remain synchronous: {forbidden}")

for required in (
    "NSApplication.shared", "activationPolicy() == .prohibited", "application.run()",
    "withExtendedLifetime(lifecycle)", "applicationDidFinishLaunching",
    "finishCount == 1", "Thread.isMainThread", "DispatchQueue.global",
):
    if required not in LIFECYCLE:
        raise SystemExit(f"deputy AppKit bootstrap lacks: {required}")
if "runApplicationLifecycle" not in DEPUTY or "alarm(20)" not in DEPUTY:
    raise SystemExit("deputy must use the tested bootstrap within its original bound")
for required in (
    "runApplicationLifecycle", "signal(SIGALRM, SIG_DFL)", "alarm(2)",
    "finish.count == 1", "observation.workerWasOffMainThread",
    "observation.callbackObservedWaitingWorker", "DispatchQueue.main.async",
    "callback.wait(timeout: deadline)", ".applicationDefined", "alarm(0)",
):
    if required not in LIFECYCLE_TEST:
        raise SystemExit(f"same-bootstrap lifecycle fixture lacks: {required}")
for forbidden in ("Task {", "post(name:", "NSWorkspace"):
    if forbidden in LIFECYCLE + LIFECYCLE_TEST:
        raise SystemExit(f"unsupported or delegated lifecycle fixture path: {forbidden}")

if OWNER.count("readFrame(from: ownerDescriptor, deadline: launchDeadline)") != 2:
    raise SystemExit("completion diagnostic and launch must share one absolute phase deadline")
if "validateLaunchCompletion(completion, followedBy: launch" not in OWNER:
    raise SystemExit("launch diagnostics must not bypass cross-frame consistency")
if OWNER.index("validateLaunchCompletion(completion") > OWNER.index("cw_canary_accept(listener"):
    raise SystemExit("launch sequence must be validated before accepting the deputy")
if CANDIDATE.index('kind: "launch-completion"') > CANDIDATE.index("guard application.bundleIdentifier"):
    raise SystemExit("completion diagnostic must precede launch identity admission")
if "ContinuousClock.now >= deadline" not in PROTOCOL:
    raise SystemExit("partial-frame polling must enforce the absolute deadline")

print("macOS App Sandbox canary static contract: ok")
