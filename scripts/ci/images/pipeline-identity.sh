# shellcheck shell=bash
# shellcheck disable=SC2034  # variables are consumed by the scripts that source this file
# Identity of the protected delivery pipeline: the one place the image build
# and the signer take it from. Checked in and reviewed on protected main, so a
# build job cannot choose its own; the scripts still reject any other value.
#
# A fork replaces these values and the cosign public key together; images are
# then verified against the fork's values, never this project's.
#
# PIPELINE_BUILDER_ID is the SLSA provenance runDetails.builder.id stamped at
# build and required before signing. It is an identifier, not a URL anything
# fetches. Changing it invalidates verification of every image built under the
# old value, so change it only in a release that rebuilds the whole set.
readonly PIPELINE_BUILDER_ID='https://codewire.sh/ci/builders/protected-delivery/v1'
# The repository URL provenance must name as its source.
readonly PIPELINE_SOURCE_URL='https://git.example.invalid/codewire/codewire.git'
# OpenBao serving the Transit signing key and publisher credentials. Every
# CI and smoke script reads the same CODEWIRE_OPENBAO_ADDR; set it (workflow
# env or repository variable) to point this tooling at another OpenBao.
readonly PIPELINE_OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
