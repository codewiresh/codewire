# shellcheck shell=bash disable=SC2034 # release_* are read by the sourcing fetcher.
# Sourced by the release credential fetchers. A release credential is read
# only by a run of main's own workflow code, started one of two ways:
#
#   - the owner's dispatch: event workflow_dispatch, actor noel;
#   - Forgejo's schedule picking up a pushed release tag (#2892): event
#     schedule, actor forgejo-actions, Forgejo's Actions user.
#
# Each way has its own OpenBao role, bound to exactly its claims (infra), so a
# dispatch by the Actions user, which any same-repository branch's job token
# can make, matches neither. A scheduled run reads only in its first attempt:
# any branch's job token can rerun its jobs, which keeps its identity but
# raises the attempt, so a failed scheduled release is recovered only by the
# owner's dispatch.
#
# release_run_identity ROLE AUDIENCE sets release_role and release_audience
# for this run, and the event, actor and (for the schedule) attempt its OIDC
# token must carry (release_event, release_actor, release_attempt; an empty
# release_attempt accepts any), or fails for any other run. The runner reports
# the attempt as GITHUB_RUN_ATTEMPT, from the run_attempt Forgejo sends it.
release_run_identity() {
  case "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}|${GITHUB_ACTOR:-}|${GITHUB_REPOSITORY:-}" in
    'workflow_dispatch|refs/heads/main|noel|codewire/codewire')
      release_role="$1"
      release_audience="$2"
      release_event=workflow_dispatch
      release_actor=noel
      release_attempt=''
      ;;
    'schedule|refs/heads/main|forgejo-actions|codewire/codewire')
      [[ "${GITHUB_RUN_ATTEMPT:-}" == 1 ]] || return 1
      release_role="$1-schedule"
      release_audience="$2-schedule"
      release_event=schedule
      release_actor=forgejo-actions
      release_attempt=1
      ;;
    *) return 1 ;;
  esac
}

# release_schedule_guard ROLE: a schedule role ("-schedule") is used only by
# the schedule's own first attempt; any other role passes. For fetchers whose
# roles are shared with other workflows and only allowlisted.
release_schedule_guard() {
  case "$1" in
    *-schedule) release_run_identity "${1%-schedule}" "${1%-schedule}" && [[ "$release_event" == schedule ]] ;;
    *) return 0 ;;
  esac
}
