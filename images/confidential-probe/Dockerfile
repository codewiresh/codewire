# syntax=docker/dockerfile:1.7
FROM registry.k8s.io/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb

USER 0

# The attestation binary is a static PIE from the reviewed upstream v0.10.0
# release. BuildKit verifies its content before it enters the image.
ADD --checksum=sha256:70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0 \
    --chmod=0755 \
    https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest \
    /usr/local/bin/snpguest

RUN test -x /usr/local/bin/snpguest && /usr/local/bin/snpguest --version

USER 65532:65532
