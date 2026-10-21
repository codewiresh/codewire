variable "IMAGE_PREFIX" {
  default = "codewire"
}

variable "IMAGE_TAG" {
  default = "e2e"
}

variable "CODEWIRE_IMAGE_SOURCE_SHA" {
  default = ""
}

variable "CODEWIRE_IMAGE_SOURCE_URL" {
  default = "https://github.com/codewiresh/codewire"
}

variable "CODEWIRE_SCCACHE_MODE" {
  default = "disabled"
}

variable "SCCACHE_BUCKET" {
  default = ""
}

variable "SCCACHE_ENDPOINT" {
  default = ""
}

variable "CODEWIRE_SCCACHE_PREFIX" {
  default = ""
}

# Cargo's job count on the trusted BuildKit builder (trusted-buildkit.sh);
# empty keeps Cargo's default of one job per CPU.
variable "CODEWIRE_CARGO_BUILD_JOBS" {
  default = ""
}

group "default" {
  targets = ["dashboard", "services", "mesh", "daemon", "derp"]
}

group "kind" {
  targets = ["dashboard-ci", "services-ci", "mesh-ci", "daemon-ci"]
}

target "rust-base" {
  context    = "."
  dockerfile = "deployments/docker/rust-base.Dockerfile"
}

# Every image builds the one runtime profile ([profile.runtime] in Cargo.toml),
# the Kind targets included. It is fixed here, not a variable, so no caller's
# environment can select another. The Kind targets differ from the promotable
# images only in their promotable=false label and services-ci's kind-e2e
# features.
target "_rust-product" {
  context = "."
  contexts = {
    codewire-rust-base = "target:rust-base"
  }
  labels = {
    "org.opencontainers.image.revision" = CODEWIRE_IMAGE_SOURCE_SHA
    "org.opencontainers.image.source"   = CODEWIRE_IMAGE_SOURCE_URL
    "dev.codewire.build.profile"        = "runtime"
    "dev.codewire.promotable"           = "true"
  }
  args = {
    CODEWIRE_SCCACHE_MODE = CODEWIRE_SCCACHE_MODE
    SCCACHE_BUCKET        = SCCACHE_BUCKET
    SCCACHE_ENDPOINT      = SCCACHE_ENDPOINT
    CODEWIRE_SCCACHE_PREFIX = CODEWIRE_SCCACHE_PREFIX
    CODEWIRE_RUST_PROFILE = "runtime"
    CARGO_BUILD_JOBS      = CODEWIRE_CARGO_BUILD_JOBS
  }
  pull = true
}

target "dashboard" {
  inherits   = ["_rust-product"]
  dockerfile = "apps/dashboard/Dockerfile"
  tags       = ["${IMAGE_PREFIX}-dashboard:${IMAGE_TAG}"]
  labels = {
    "org.opencontainers.image.title" = "codewire-dashboard"
  }
}

target "services" {
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/services.Dockerfile"
  tags       = ["${IMAGE_PREFIX}-services:${IMAGE_TAG}"]
  labels = {
    "org.opencontainers.image.title" = "codewire-services"
  }
  args = {
    CODEWIRE_ORCHESTRATION_FEATURES = ""
  }
}

target "mesh" {
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/mesh.Dockerfile"
  tags       = ["${IMAGE_PREFIX}-mesh:${IMAGE_TAG}"]
  labels = {
    "org.opencontainers.image.title" = "codewire-mesh"
  }
}

target "daemon" {
  # Build through scripts/ci/images/build-product-images.sh (or the owning
  # Kind/protected wrapper). It admits and binds codewire-verified-cw before
  # this target runs; an unbound recipe has only an empty local scratch stage.
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/daemon.Dockerfile"
  tags       = ["${IMAGE_PREFIX}-daemon:${IMAGE_TAG}"]
  labels = {
    "org.opencontainers.image.title" = "codewire-daemon"
  }
}

target "derp" {
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/derp.Dockerfile"
  tags       = ["${IMAGE_PREFIX}-derp:${IMAGE_TAG}"]
  labels = {
    "org.opencontainers.image.title" = "codewire-derp"
  }
}

target "dashboard-ci" {
  inherits = ["dashboard"]
  labels = {
    "dev.codewire.promotable" = "false"
  }
}

# Local Kind development only: one incrementally compiled service binary,
# exported to the host by scripts/dev/kind/deploy-service.sh.
variable "KIND_DEV_CRATE" {
  default = ""
}

variable "KIND_DEV_FEATURES" {
  default = ""
}

variable "KIND_DEV_BIN" {
  default = ""
}

# The gate's static CW toolchain (Rust, musl target, zig, cargo-zigbuild),
# reused by the kind-dev daemon build.
target "cw-toolchain" {
  context    = "."
  dockerfile = "images/cw-runtime/Dockerfile"
  target     = "cw-toolchain"
}

target "kind-dev-binary" {
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/kind-dev-binary.Dockerfile"
  contexts = {
    codewire-rust-base    = "target:rust-base"
    codewire-cw-toolchain = "target:cw-toolchain"
  }
  labels = {
    "dev.codewire.promotable" = "false"
  }
  args = {
    KIND_DEV_CRATE    = KIND_DEV_CRATE
    KIND_DEV_FEATURES = KIND_DEV_FEATURES
    KIND_DEV_BIN      = KIND_DEV_BIN
  }
}

target "services-ci" {
  inherits = ["services"]
  args = {
    CODEWIRE_ORCHESTRATION_FEATURES = "kind-e2e"
  }
  labels = {
    "dev.codewire.promotable" = "false"
  }
}

target "mesh-ci" {
  inherits = ["mesh"]
  labels = {
    "dev.codewire.promotable" = "false"
  }
}

target "daemon-ci" {
  inherits = ["daemon"]
  labels = {
    "dev.codewire.promotable" = "false"
  }
}
