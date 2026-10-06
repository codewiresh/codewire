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
cw_hosts=$(/usr/bin/mktemp /codewire/run/.ssh-known-hosts.XXXXXXXX)
cw_hosts_identity=''
cleanup() {
    cw_status=$?
    trap - EXIT HUP INT TERM
    if test ! -e "$cw_hosts" && test ! -L "$cw_hosts"; then
        :
    elif test -f "$cw_hosts" && test ! -L "$cw_hosts" &&
        test "$(/usr/bin/stat -c '%d:%i:%u' -- "$cw_hosts")" = "$cw_hosts_identity"; then
        /bin/rm -f -- "$cw_hosts" || cw_status=125
    else
        # Existing hosted-exec ambiguity status requires exact-Pod recovery.
        cw_status=125
    fi
    exit "$cw_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cw_hosts_identity=$(/usr/bin/stat -c '%d:%i:%u' -- "$cw_hosts")
printf '%s\n' "$@" >"$cw_hosts"

# Canonical host/port contain no quotes or whitespace; the temporary filename
# comes only from the fixed pattern above. Quote them inside Git's SSH command.
cw_ssh="/usr/bin/ssh -F /dev/null -o 'HostName=$cw_host' -p '$cw_port' -o 'HostKeyAlias=$cw_alias' -o 'UserKnownHostsFile=$cw_hosts' -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentityAgent=/codewire/run/ssh-agent.sock -o IdentityFile=none -o CertificateFile=none -o IdentitiesOnly=no -o BatchMode=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no -o HostbasedAuthentication=no -o PKCS11Provider=none -o SecurityKeyProvider=none -o ForwardAgent=no -o ClearAllForwardings=yes -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no -o AddKeysToAgent=no -o ControlMaster=no -o ControlPath=none -o ControlPersist=no"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    SSH_AUTH_SOCK=/codewire/run/ssh-agent.sock \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 GIT_SSH_VARIANT=ssh GIT_SSH_COMMAND="$cw_ssh" \
    /usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    clone --progress -- "$cw_source" "$cw_destination"
