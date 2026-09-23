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

variable "CODEWIRE_RUST_PROFILE" {
  default = "release"
}

group "default" {
  targets = ["dashboard", "services", "mesh", "gateway", "derp"]
}

group "kind" {
  targets = ["dashboard-ci", "services-ci", "mesh-ci", "gateway-ci"]
}

target "rust-base" {
  context    = "."
  dockerfile = "deployments/docker/rust-base.Dockerfile"
}

target "_rust-product" {
  context = "."
  contexts = {
    codewire-rust-base = "target:rust-base"
  }
  labels = {
    "org.opencontainers.image.revision" = CODEWIRE_IMAGE_SOURCE_SHA
    "org.opencontainers.image.source"   = CODEWIRE_IMAGE_SOURCE_URL
    "dev.codewire.build.profile"        = CODEWIRE_RUST_PROFILE
    "dev.codewire.promotable"           = "true"
  }
  args = {
    CODEWIRE_SCCACHE_MODE = CODEWIRE_SCCACHE_MODE
    SCCACHE_BUCKET        = SCCACHE_BUCKET
    SCCACHE_ENDPOINT      = SCCACHE_ENDPOINT
    CODEWIRE_SCCACHE_PREFIX = CODEWIRE_SCCACHE_PREFIX
    CODEWIRE_RUST_PROFILE = CODEWIRE_RUST_PROFILE
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

target "gateway" {
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/gateway.Dockerfile"
  tags       = ["${IMAGE_PREFIX}-gateway:${IMAGE_TAG}"]
  labels = {
    "org.opencontainers.image.title" = "codewire-gateway"
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
  args = {
    CODEWIRE_RUST_PROFILE = "ci"
  }
  labels = {
    "dev.codewire.build.profile" = "ci"
    "dev.codewire.promotable"    = "false"
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

target "kind-dev-binary" {
  inherits   = ["_rust-product"]
  dockerfile = "deployments/docker/kind-dev-binary.Dockerfile"
  labels = {
    "dev.codewire.promotable" = "false"
  }
  args = {
    KIND_DEV_CRATE    = KIND_DEV_CRATE
    KIND_DEV_FEATURES = KIND_DEV_FEATURES
  }
}

target "services-ci" {
  inherits = ["services"]
  args = {
    CODEWIRE_RUST_PROFILE           = "ci"
    CODEWIRE_ORCHESTRATION_FEATURES = "kind-e2e"
  }
  labels = {
    "dev.codewire.build.profile" = "ci"
    "dev.codewire.promotable"    = "false"
  }
}

target "mesh-ci" {
  inherits = ["mesh"]
  args = {
    CODEWIRE_RUST_PROFILE = "ci"
  }
  labels = {
    "dev.codewire.build.profile" = "ci"
    "dev.codewire.promotable"    = "false"
  }
}

target "gateway-ci" {
  inherits = ["gateway"]
  args = {
    CODEWIRE_RUST_PROFILE = "ci"
  }
  labels = {
    "dev.codewire.build.profile" = "ci"
    "dev.codewire.promotable"    = "false"
  }
}
