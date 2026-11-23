# The `standard` profile's runtime image (#5602): the one container of a
# standard sandbox Pod, which boots the sandbox's VM. Its context comes from
# scripts/ci/images/pod-runtime-context.py: a cw and the local VM runtime of
# the same source, each checked against its digest. Admission pins this
# image by digest, its entrypoint and its user; the Pod sets no command.
FROM ubuntu:noble@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

COPY --chown=0:0 cw /usr/local/bin/cw
# The runtime keeps the modes the context gives it (0700 directories, 0500
# executables, 0400 data) and belongs to the user the runtime runs as, as the
# local runtime's artifact admission requires.
COPY --chown=1000:1000 runtime /opt/codewire/runtime
# uid 1000 is the Pod's user, so the base image's own user of that id goes.
# /codewire/run carries the readiness file, /state the claim and /image the
# workspace disk.
RUN userdel --remove ubuntu && \
    chmod 0700 /opt/codewire/runtime && \
    mkdir -p /codewire/run /state /image && \
    chown 1000:1000 /codewire/run /state

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/cw", "__pod-runtime"]
