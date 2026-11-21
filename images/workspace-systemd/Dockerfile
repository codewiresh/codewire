# A workspace in which sessions see systemd as PID 1, with the environment daemon as a
# unit (docs/dev/SYSTEMD-WORKSPACE.md). It is the published workspace image
# plus an init system, so the builder supplies that exact image by digest.
ARG BASE_IMAGE_REF
FROM ${BASE_IMAGE_REF}
# OCI image configs do not carry the base SHELL; never inherit it.
SHELL ["/bin/bash", "-c"]
USER root

# The same dated archive snapshot as the workspace, through its apt wrapper.
RUN --mount=type=secret,id=codewire-apt-mirror,required=false \
    apt-get-with-retry update && apt-get-with-retry install -y --no-install-recommends \
      systemd systemd-sysv dbus dbus-user-session libpam-systemd && \
    rm -rf /var/lib/apt/lists/*

# A container has no console, hardware, package timers or network to manage,
# and no initctl pipe. An empty machine-id makes each boot generate its own.
# /etc and /var are marked up to date with /usr, so a boot does not first
# rebuild the linker cache, the journal catalog and the system users.
RUN systemctl mask \
      console-getty.service getty.target systemd-firstboot.service systemd-initctl.socket \
      apt-daily.timer apt-daily-upgrade.timer dpkg-db-backup.timer \
      e2scrub_all.timer fstrim.timer motd-news.timer \
      systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service && \
    : > /etc/machine-id && \
    systemctl set-default multi-user.target && \
    ldconfig && touch /etc/.updated /var/.updated

# The workspace user's manager runs from boot: nothing in a sandbox logs in
# through PAM, and without polkit a user cannot turn lingering on for itself.
# The drop-in directories exist first: a directory COPY creates would take the
# files' mode and be closed to the workspace user's manager.
RUN install -d -m 0755 /var/lib/systemd/linger /etc/systemd/system.conf.d /etc/systemd/user.conf.d && \
    : > /var/lib/systemd/linger/codewire

COPY --chown=0:0 --chmod=0644 stop-timeout.conf /etc/systemd/system.conf.d/10-codewire-stop-timeout.conf
COPY --chown=0:0 --chmod=0644 stop-timeout.conf /etc/systemd/user.conf.d/10-codewire-stop-timeout.conf
COPY --chown=0:0 --chmod=0755 codewire-daemon-run /usr/local/libexec/codewire/codewire-daemon-run
COPY --chown=0:0 --chmod=0644 codewire-daemon.service /etc/systemd/system/codewire-daemon.service
RUN systemctl enable codewire-daemon.service && \
    systemd-analyze verify /etc/systemd/system/codewire-daemon.service

# systemd reads `container` to know it is not on hardware, and shuts down on
# SIGRTMIN+3; a plain SIGTERM only makes it re-execute itself.
ENV container=oci
STOPSIGNAL SIGRTMIN+3
# Orchestration renders the first process ("The first process" in the spec),
# which starts systemd in namespaces of its own. Run on its own, the image
# boots systemd directly as root.
ENTRYPOINT []
CMD ["/sbin/init"]
