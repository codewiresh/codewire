#!/bin/sh
set -eu
umask 077
# The daemon projection owns this selection. Never accept an inherited alternate
# agent, ambient private key, global/user Git configuration, or SSH configuration.
test "${SSH_AUTH_SOCK-}" = /codewire/run/ssh-agent.sock
test -S /codewire/run/ssh-agent.sock
test "$#" -ge 6
cw_source=$1
cw_destination=$2
cw_host=$3
cw_port=$4
cw_alias=$5
shift 5
cw_hosts=''
cw_hosts_identity=''
cw_errors=''
cw_errors_identity=''
# Remove one owned temporary file, or report that it is no longer the file this
# script created.
cw_remove() {
    if test -z "$1" || { test ! -e "$1" && test ! -L "$1"; }; then
        return 0
    elif test -f "$1" && test ! -L "$1" &&
        test "$(/usr/bin/stat -c '%d:%i:%u' -- "$1")" = "$2"; then
        /bin/rm -f -- "$1"
    else
        return 1
    fi
}
cleanup() {
    cw_status=$?
    trap - EXIT HUP INT TERM
    # Existing hosted-exec ambiguity status requires exact-Pod recovery.
    cw_remove "$cw_hosts" "$cw_hosts_identity" || cw_status=125
    cw_remove "$cw_errors" "$cw_errors_identity" || cw_status=125
    exit "$cw_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cw_hosts=$(/usr/bin/mktemp /codewire/run/.ssh-known-hosts.XXXXXXXX)
cw_hosts_identity=$(/usr/bin/stat -c '%d:%i:%u' -- "$cw_hosts")
cw_errors=$(/usr/bin/mktemp /codewire/run/.ssh-errors.XXXXXXXX)
cw_errors_identity=$(/usr/bin/stat -c '%d:%i:%u' -- "$cw_errors")
printf '%s\n' "$@" >"$cw_hosts"

# Append the pins this clone verified to the workspace user's known_hosts, so a
# later fetch or push from this checkout trusts the same host without a prompt.
# Existing lines are never rewritten.
cw_record_trust() {
    cw_known=/home/codewire/.ssh/known_hosts
    # A concurrent checkout may create the directory first.
    test -d /home/codewire/.ssh ||
        /bin/mkdir -m 700 -- /home/codewire/.ssh 2>/dev/null ||
        test -d /home/codewire/.ssh || return 1
    if test -s "$cw_known" && test -n "$(/usr/bin/tail -c 1 -- "$cw_known")"; then
        printf '\n' >>"$cw_known" || return 1
    fi
    for cw_line do
        /usr/bin/grep -qxF -e "$cw_line" -- "$cw_known" 2>/dev/null ||
            printf '%s\n' "$cw_line" >>"$cw_known" || return 1
    done
}

# Canonical host/port contain no quotes or whitespace; the temporary filenames
# come only from the fixed patterns above. Quote them inside Git's SSH command.
# OpenSSH's and the server's own messages go to the owned error file, so this
# script can tell a refused key from a network or host-key failure.
cw_ssh="/usr/bin/ssh -F /dev/null -o 'HostName=$cw_host' -p '$cw_port' -o 'HostKeyAlias=$cw_alias' -o 'UserKnownHostsFile=$cw_hosts' -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentityAgent=/codewire/run/ssh-agent.sock -o IdentityFile=none -o CertificateFile=none -o IdentitiesOnly=no -o BatchMode=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no -o HostbasedAuthentication=no -o PKCS11Provider=none -o SecurityKeyProvider=none -o ForwardAgent=no -o ClearAllForwardings=yes -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no -o AddKeysToAgent=no -o ControlMaster=no -o ControlPath=none -o ControlPersist=no 2>>'$cw_errors'"
cw_status=0
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    SSH_AUTH_SOCK=/codewire/run/ssh-agent.sock \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 GIT_SSH_VARIANT=ssh GIT_SSH_COMMAND="$cw_ssh" \
    /usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    clone --progress -- "$cw_source" "$cw_destination" || cw_status=$?
/bin/cat -- "$cw_errors" >&2 || :

# The script's status, returned as its last command so the EXIT trap sees it.
cw_finish() {
    if test "$cw_status" -eq 0; then
        cw_record_trust "$@" ||
            printf '%s\n' 'codewire: the checkout succeeded, but its SSH host keys were not recorded in ~/.ssh/known_hosts' >&2
        return 0
    fi
    # The server refused the key or the repository: only then may the caller
    # fall back to HTTPS. A host-key failure ends the connection before
    # authentication, and a network failure never reaches it; both keep Git's
    # own status.
    if ! /usr/bin/grep -q -e 'Host key verification failed' -e 'IDENTIFICATION HAS CHANGED' -- "$cw_errors" &&
        /usr/bin/grep -q -e 'Permission denied (publickey' -e '^ERROR: Repository not found' -e '^ERROR: Permission to ' -- "$cw_errors"; then
        return 77
    fi
    return "$cw_status"
}
cw_finish "$@"
