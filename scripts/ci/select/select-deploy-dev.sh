#!/usr/bin/env bash
# Select whether a main push needs dev image builds and rollout.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: select-deploy-dev.sh [changed-files]

changed-files may be a file containing one path per line, or "-" for stdin.
Without an argument the script discovers push changes from HEAD^..HEAD.

Writes deploy_dev=true|false to stdout and to $GITHUB_OUTPUT when running
inside Actions.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if [ $# -gt 0 ]; then
  if [ "$1" = "-" ]; then
    cat > "$tmp"
  else
    cp "$1" "$tmp"
  fi
elif git rev-parse --verify HEAD^ >/dev/null 2>&1; then
  git diff --name-only HEAD^ HEAD > "$tmp"
else
  echo "warning: no parent commit available; selecting deploy-dev" >&2
  printf '__unknown__\n' > "$tmp"
fi

if [ "${GITHUB_EVENT_NAME:-}" = "workflow_dispatch" ]; then
  deploy_dev=true
else
  deploy_dev=false

  script_reference_only_diff() {
    local path="$1"
    local range=()

    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      return 1
    fi

    if ! git diff --quiet -- "$path" 2>/dev/null; then
      range=()
    elif git rev-parse --verify HEAD^ >/dev/null 2>&1 \
        && ! git diff --quiet HEAD^ HEAD -- "$path" 2>/dev/null; then
      range=(HEAD^ HEAD)
    else
      return 1
    fi

    git diff --unified=0 "${range[@]}" -- "$path" | awk '
      /^(diff --git|index |--- |\+\+\+ |@@ )/ { next }
      /^[+-]/ {
        line = substr($0, 2)
        if (line ~ /^[[:space:]]*$/) { next }
        if (line ~ /scripts\//) { next }
        if (line ~ /repo_checks\.py/) { next }
        if (line ~ /[[:alnum:]_-]+:check-source/) { next }
        if (line ~ /(openapi|rest:freeze|validation:check-source|go:check-source|hooks:install|preflight)/) { next }
        bad = 1
      }
      END { exit bad }
    '
  }

  while IFS= read -r path; do
    [ -n "$path" ] || continue

    case "$path" in
      .gitea/workflows/*.yaml|package.json|\
      Caddyfile|Caddyfile.docker|deployments/k8s/*ingress*.yaml|tests/e2e/kind/ingress.yaml|\
      tests/e2e/flip-state.env)
        if script_reference_only_diff "$path"; then
          continue
        fi
        ;;
    esac

    case "$path" in
      docs/*|\
      .agents/*|\
      .claude/*|\
      .github/*|\
      images/*|\
      .githooks/pre-push|\
      .gitea/workflows/ci.yaml|\
      .gitea/workflows/cli-release.yaml|\
      .gitea/workflows/manual-diagnostics.yaml|\
      .gitea/workflows/mirror-github.yaml|\
      .gitea/workflows/observe-*.yaml|\
      .gitea/workflows/support-images.yaml|\
      Makefile|\
      libs/sdk-python/*|\
      libs/sdk-scripts/*|\
      libs/sdk-ts/*|\
      libs/sdk-examples/*|\
      crates/codewire-cli/*|\
      crates/codewire-cli-bin/*|\
      scripts/runtime/dev/run-sdk-python-e2e.sh|\
      scripts/runtime/tests/test-run-sdk-python-e2e.sh|\
      crates/codewire-server-core/tests/org_deletion_lifecycle.rs|\
      apps/cli/GPG_PUBLIC_KEY.asc|\
      keys/production-release.asc|\
      apps/cli/README.md|\
      apps/cli/install.sh|\
      scripts/dev/install-hooks.sh|\
      scripts/dev/preflight.sh|\
      scripts/ci/release/mirror-canonical-release-tag.sh|\
      scripts/ci/release/mirror-git-tags.sh|\
      scripts/ci/images/copy-image-to-ghcr.sh|\
      scripts/ci/deploy/dispatch-deploy-dev.sh|\
      scripts/ci/deploy/dispatch-deploy-prod.sh|\
      scripts/ci/images/publish-image-to-ghcr.sh|\
      scripts/ci/images/run-skopeo-container.sh|\
      scripts/ci/tests/test-deploy-dev.sh|\
      scripts/ci/tests/test-mirror-git-tags.sh|\
      scripts/ci/tests/test-copy-image-to-ghcr.sh|\
      scripts/ci/tests/test-dispatch-deploy-dev.sh|\
      scripts/ci/tests/test-dispatch-deploy-prod.sh|\
      scripts/ci/tests/test-publish-image-to-ghcr.sh|\
      scripts/ci/tests/test-deploy-prod-workflow.sh|\
      scripts/ci/tests/test-run-skopeo-container.sh|\
      scripts/ci/tests/test-support-images-workflow.sh|\
      scripts/ci/*observe*.sh|\
      scripts/ci/*observe*.py|\
      scripts/ci/*observer*.tsv|\
      scripts/ci/tests/test-verify-cw-release-signing-key.sh|\
      scripts/ci/tests/test-verify-release-tag-ref.sh|\
      scripts/ci/tests/test-pre-push-worktree.sh|\
      scripts/ci/release/package-cw-release.sh|\
      scripts/ci/tests/test-cw-install-signature.sh|\
      scripts/ci/tests/test-publish-cw-release.sh|\
      scripts/ci/release/publish-cw-release.sh|\
      scripts/ci/verify/integration-postgres.sh|\
      scripts/ci/verify/run-integration-verification.sh|\
      scripts/ci/verify/run-product-verification.sh|\
      scripts/ci/tests/test-integration-postgres.sh|\
      scripts/ci/tests/test-base-image-source.sh|\
      scripts/ci/verify/rust-stack-rehearsal.sh|\
      scripts/ci/select/select-verification.sh|\
      scripts/ci/tests/test-select-verification.sh|\
      scripts/ci/release/verify-cw-release-signing-key.sh|\
      scripts/ci/release/verify-release-tag-ref.sh|\
      scripts/*|\
      *.md)
        ;;
      *)
        deploy_dev=true
        ;;
    esac
  done < "$tmp"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'deploy_dev=%s\n' "$deploy_dev" | tee -a "$GITHUB_OUTPUT"
else
  printf 'deploy_dev=%s\n' "$deploy_dev"
fi

printf 'changed_files<<EOF\n'
cat "$tmp"
printf 'EOF\n'
