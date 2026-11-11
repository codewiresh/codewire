#!/usr/bin/env python3
"""Stable command-line dispatcher for Codewire repository policy checks."""

from __future__ import annotations

from repo_policy.shared import ROOT, argparse
from repo_policy.design_tokens import check_design_tokens
from repo_policy.edge_routing import check_connect_edge_routing
from repo_policy.hosted_overlay_contract import check_hosted_overlay_contract
from repo_policy.idp_security import check_idp_signing_kek_isolation
from repo_policy.kind_suite_rows import check_kind_suite_rows
from repo_policy.ses_security import check_ses_sender_isolation
from repo_policy.turnstile_security import check_turnstile_access_projection
from repo_policy.licensing import check_license_map
from repo_policy.material_cache import check_epoch_material_cache_owner
from repo_policy.database_pools import check_database_pools
from repo_policy.mcp_settings import check_mcp_settings
from repo_policy.mesh import check_mesh_surface_freeze
from repo_policy.orchestration_security import check_orchestration_authz
from repo_policy.os_splits import check_os_splits
from repo_policy.permanent_raw import check_permanent_raw_surface
from repo_policy.production import check_production_source_ownership
from repo_policy.public_addresses import check_public_address_literals
from repo_policy.private_hosts import check_private_host_literals
from repo_policy.proto import check_proto_package_boundaries
from repo_policy.workspace_identity import check_identity_free_workspace
from repo_policy.webpki_roots_floor import check_webpki_roots_floor
from repo_policy.sqlx_sqlite_unused import check_sqlx_sqlite_unused
from repo_policy.workspace_image_pin import check_workspace_image_pin
from repo_policy.source_classification import (
    check_go_source_classification,
    check_retired_reference_source,
    check_rust_validation_source,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Codewire repository policy checks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    edge_parser = subparsers.add_parser("connect-edge-routing")
    edge_parser.add_argument("--self-test", action="store_true")
    edge_parser.set_defaults(func=check_connect_edge_routing)
    permanent_raw_parser = subparsers.add_parser("permanent-raw-surface")
    permanent_raw_parser.add_argument("--self-test", action="store_true")
    permanent_raw_parser.set_defaults(func=check_permanent_raw_surface)
    mesh_parser = subparsers.add_parser("mesh-surface-freeze")
    mesh_parser.add_argument("--self-test", action="store_true")
    mesh_parser.set_defaults(func=check_mesh_surface_freeze)
    proto_package_parser = subparsers.add_parser("proto-package-boundaries")
    proto_package_parser.add_argument("--self-test", action="store_true")
    proto_package_parser.set_defaults(func=check_proto_package_boundaries)
    subparsers.add_parser("license-map").set_defaults(func=check_license_map)
    subparsers.add_parser("rust-validation-source").set_defaults(func=check_rust_validation_source)
    subparsers.add_parser("retired-reference-source").set_defaults(func=check_retired_reference_source)
    subparsers.add_parser("go-source-classification").set_defaults(func=check_go_source_classification)
    prod_parser = subparsers.add_parser("production-source-ownership")
    prod_parser.add_argument("--self-test", action="store_true")
    prod_parser.add_argument("--root", default=str(ROOT))
    prod_parser.set_defaults(func=check_production_source_ownership)
    identity_free_parser = subparsers.add_parser("identity-free-workspace")
    identity_free_parser.add_argument("--self-test", action="store_true")
    identity_free_parser.set_defaults(func=check_identity_free_workspace)
    database_pools_parser = subparsers.add_parser("database-pools")
    database_pools_parser.add_argument("--self-test", action="store_true")
    database_pools_parser.set_defaults(func=check_database_pools)
    mcp_parser = subparsers.add_parser("mcp-settings")
    mcp_parser.add_argument("--self-test", action="store_true")
    mcp_parser.set_defaults(func=check_mcp_settings)
    orchestration_authz_parser = subparsers.add_parser("orchestration-authz")
    orchestration_authz_parser.add_argument("--self-test", action="store_true")
    orchestration_authz_parser.set_defaults(func=check_orchestration_authz)
    idp_parser = subparsers.add_parser("idp-signing-kek-isolation")
    idp_parser.add_argument("--live", action="store_true")
    idp_parser.add_argument("--context", default="kind-codewire")
    idp_parser.add_argument("--namespace", default="default")
    idp_parser.set_defaults(func=check_idp_signing_kek_isolation)
    ses_parser = subparsers.add_parser("ses-email-isolation")
    ses_parser.set_defaults(func=check_ses_sender_isolation)
    turnstile_parser = subparsers.add_parser("turnstile-access-projection")
    turnstile_parser.add_argument("--self-test", action="store_true")
    turnstile_parser.set_defaults(func=check_turnstile_access_projection)
    hosted_overlay_parser = subparsers.add_parser("hosted-overlay-contract")
    hosted_overlay_parser.add_argument("--self-test", action="store_true")
    hosted_overlay_parser.set_defaults(func=check_hosted_overlay_contract)
    design_parser = subparsers.add_parser("design-tokens")
    design_parser.add_argument("--self-test", action="store_true")
    design_parser.add_argument("--root", default=str(ROOT))
    design_parser.set_defaults(func=check_design_tokens)
    workspace_pin_parser = subparsers.add_parser("workspace-image-pin")
    workspace_pin_parser.add_argument("--self-test", action="store_true")
    workspace_pin_parser.set_defaults(func=check_workspace_image_pin)
    kind_suite_rows_parser = subparsers.add_parser("kind-suite-rows")
    kind_suite_rows_parser.add_argument("--self-test", action="store_true")
    kind_suite_rows_parser.set_defaults(func=check_kind_suite_rows)
    os_splits_parser = subparsers.add_parser("os-splits")
    os_splits_parser.add_argument("--self-test", action="store_true")
    os_splits_parser.set_defaults(func=check_os_splits)

    webpki_roots_parser = subparsers.add_parser("webpki-roots-floor")
    webpki_roots_parser.add_argument("--self-test", action="store_true")
    webpki_roots_parser.set_defaults(func=check_webpki_roots_floor)
    sqlx_sqlite_parser = subparsers.add_parser("sqlx-sqlite-unused")
    sqlx_sqlite_parser.add_argument("--self-test", action="store_true")
    sqlx_sqlite_parser.set_defaults(func=check_sqlx_sqlite_unused)
    material_cache_parser = subparsers.add_parser("epoch-material-cache-owner")
    material_cache_parser.add_argument("--self-test", action="store_true")
    material_cache_parser.set_defaults(func=check_epoch_material_cache_owner)
    public_address_parser = subparsers.add_parser("public-address-literals")
    public_address_parser.add_argument("--self-test", action="store_true")
    public_address_parser.set_defaults(func=check_public_address_literals)
    private_host_parser = subparsers.add_parser("private-host-literals")
    private_host_parser.add_argument("--self-test", action="store_true")
    private_host_parser.set_defaults(func=check_private_host_literals)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
