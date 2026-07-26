import { createConnectQueryKey } from "@connectrpc/connect-query";
import {
  OrgRole,
  OrganizationService,
  type OrganizationMembership,
} from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { connectTransport } from "./connect";

export const organizationServiceQueryKey = createConnectQueryKey({
  schema: OrganizationService,
  transport: connectTransport,
  cardinality: undefined,
});

export const organizationListQueryKey = createConnectQueryKey({
  schema: OrganizationService.method.listOrganizations,
  transport: connectTransport,
  cardinality: undefined,
});

export function findOrganizationBySlug(
  organizations: OrganizationMembership[] | undefined,
  slug: string,
) {
  return organizations?.find((membership) => membership.organization?.slug === slug);
}

export function orgRoleName(role: OrgRole): "owner" | "admin" | "member" | "unknown" {
  switch (role) {
    case OrgRole.OWNER:
      return "owner";
    case OrgRole.ADMIN:
      return "admin";
    case OrgRole.MEMBER:
      return "member";
    default:
      return "unknown";
  }
}
