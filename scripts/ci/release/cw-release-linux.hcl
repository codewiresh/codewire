# The two Linux cw release builds on the trusted BuildKit builder (#3119).
# build-cw-linux.sh runs this from the workflow checkout's root with the
# variables below and one target, exported with --output type=local.

variable "CW_RELEASE_CONTEXT" {
  # A credential-free clone of exactly the selected source commit.
  default = ""
}

variable "CW_RELEASE_DOCKERFILE" {
  # Absolute, so its per-Dockerfile ignore applies to the context above.
  default = ""
}

variable "CW_RELEASE_SCRIPTS" {
  # The workflow ref's scripts/ tree.
  default = ""
}

variable "CW_RELEASE_RUNTIME" {
  # The packed local runtime, or an empty directory.
  default = ""
}

variable "CW_RELEASE_HAS_RUNTIME" {
  default = ""
}

variable "CW_RELEASE_VERSION" {
  default = ""
}

variable "CW_RELEASE_SOURCE_SHA" {
  default = ""
}

variable "CW_RELEASE_TAG_OBJECT_SHA" {
  default = ""
}

variable "CW_RELEASE_TARGET_CACHE" {
  default = "warm"
}

variable "CODEWIRE_CARGO_BUILD_JOBS" {
  default = ""
}

variable "CW_RELEASE_CARGO_BUILD_JOBS" {
  # The cw compile's own bound, 16 from build-cw-linux.sh; at 8 jobs both
  # compiles together peaked at 8.47 GiB (dry run 18591).
  default = ""
}

variable "ZIG_VERSION" {
  default = ""
}

variable "ZIG_X86_64_LINUX_SHA256" {
  default = ""
}

variable "CARGO_ZIGBUILD_VERSION" {
  default = ""
}

target "cw-release-rust-base" {
  context    = "."
  dockerfile = "deployments/docker/rust-base.Dockerfile"
  platforms  = ["linux/amd64"]
}

target "_cw-release-linux" {
  context    = CW_RELEASE_CONTEXT
  dockerfile = CW_RELEASE_DOCKERFILE
  # The builder is linux/amd64 only and the release cross-compiles; nothing
  # here runs under emulation.
  platforms = ["linux/amd64"]
  contexts = {
    codewire-rust-base = "target:cw-release-rust-base"
    workflow-scripts   = CW_RELEASE_SCRIPTS
    local-runtime      = CW_RELEASE_RUNTIME
  }
  args = {
    ZIG_VERSION               = ZIG_VERSION
    ZIG_X86_64_LINUX_SHA256   = ZIG_X86_64_LINUX_SHA256
    CARGO_ZIGBUILD_VERSION    = CARGO_ZIGBUILD_VERSION
    TOOLS_CARGO_BUILD_JOBS    = CODEWIRE_CARGO_BUILD_JOBS
    CW_RELEASE_VERSION        = CW_RELEASE_VERSION
    CW_RELEASE_SOURCE_SHA     = CW_RELEASE_SOURCE_SHA
    CW_RELEASE_TAG_OBJECT_SHA = CW_RELEASE_TAG_OBJECT_SHA
    CW_RELEASE_HAS_RUNTIME    = CW_RELEASE_HAS_RUNTIME
    CW_RELEASE_TARGET_CACHE   = CW_RELEASE_TARGET_CACHE
    CARGO_BUILD_JOBS          = CW_RELEASE_CARGO_BUILD_JOBS
  }
  # The export is the executable and its two records only.
  attest = ["type=provenance,disabled=true", "type=sbom,disabled=true"]
}

target "cw-release-x86_64-unknown-linux-musl" {
  inherits = ["_cw-release-linux"]
  target   = "cw-x86_64-unknown-linux-musl"
}

target "cw-release-aarch64-unknown-linux-gnu" {
  inherits = ["_cw-release-linux"]
  target   = "cw-aarch64-unknown-linux-gnu"
}

group "cw-release-linux" {
  targets = ["cw-release-x86_64-unknown-linux-musl", "cw-release-aarch64-unknown-linux-gnu"]
}
