# shellcheck shell=bash disable=SC2154 # release_* are set by the sourcing script.
# Sourced by find-pending-release.sh and require-current-release.sh: the
# release tags on origin, and whether Forgejo verifies one as signed by the
# release tagger (#2892).
#
# Callers set release_api (the repository's API base), release_token (the
# job token), release_tagger (CODEWIRE_RELEASE_TAGGER) and release_tmp (a
# private directory).

# release_tag_list: origin's canonical release tags, newest version first, as
# "name object commit". Read with ls-remote, which lists every tag.
release_tag_list() {
  git ls-remote --tags origin 'refs/tags/v*' >"$release_tmp/ls-remote" || return 1
  python3 -I - "$release_tmp/ls-remote" <<'PY'
import re
import sys

objects, commits = {}, {}
for line in open(sys.argv[1]):
    sha, ref = line.split()
    peeled = ref.endswith("^{}")
    name = ref.removeprefix("refs/tags/").removesuffix("^{}")
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", name):
        continue
    (commits if peeled else objects)[name] = sha
# Only annotated tags peel; a lightweight tag is never a release.
names = [name for name in objects if name in commits]
names.sort(key=lambda name: tuple(int(part) for part in name[1:].split(".")), reverse=True)
for name in names:
    print(name, objects[name], commits[name])
PY
}

# release_tag_signed NAME OBJECT COMMIT: Forgejo verifies the tag object's own
# signature as made by a key on the release tagger's account. A tag without a
# signature of its own reports its commit's verification, whose payload is a
# commit, not this tag. Sets release_tag_date (the signed tagger time, epoch
# seconds) on success.
release_tag_signed() {
  local name="$1" object="$2" commit="$3" status
  status="$(printf 'header = "Authorization: token %s"\n' "$release_token" |
    curl --disable --config - --silent --show-error \
      --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
      --output "$release_tmp/tag.json" --write-out '%{http_code}' \
      "$release_api/git/tags/$object" 2>/dev/null)" || return 2
  [[ "$status" == 200 ]] || return 2
  local date
  date="$(jq -er --arg name "$name" --arg object "$object" --arg commit "$commit" \
      --arg tagger "$release_tagger" '
      select(.tag == $name and .sha == $object and .object.sha == $commit
        and .verification.verified == true
        and (.verification.signer.name // "") == $tagger
        and ((.verification.payload // "")
          | startswith("object \($commit)\ntype commit\ntag \($name)\n")))
      | .tagger.date | strings
    ' "$release_tmp/tag.json" 2>/dev/null)" || return 1
  release_tag_date="$(python3 -I -c '
import datetime, sys
print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")).timestamp()))
' "$date" 2>/dev/null)" || return 1
  [[ "$release_tag_date" =~ ^[0-9]+$ ]] || return 1
}
