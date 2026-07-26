import { createFileRoute, Link, Outlet, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@connectrpc/connect-query";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { Badge } from "@/components/ui/badge";
import { connectTransport } from "@/lib/connect";
import { findOrganizationBySlug, orgRoleName } from "@/lib/organizations";
import { ArrowLeft, Loader2 } from "lucide-react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const Route = createFileRoute("/dashboard/orgs/$slug")({
  component: OrgLayout,
});

function OrgLayout() {
  const { slug } = Route.useParams();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  const { data: orgsResponse, isLoading } = useQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );

  const membership = findOrganizationBySlug(orgsResponse?.organizations, slug);
  const organization = membership?.organization;

  if (isLoading) {
    return (
      <div className="animate-page-enter py-6 md:py-8">
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-tertiary)]" />
        </div>
      </div>
    );
  }

  if (!membership || !organization) {
    return (
      <div className="animate-page-enter py-6 md:py-8 max-w-4xl mx-auto">
        <Card className="border-[var(--destructive)]/50">
          <CardHeader>
            <CardTitle className="text-[color:var(--destructive)]">Not Found</CardTitle>
            <CardDescription>Organization not found or access denied.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const basePath = `/dashboard/orgs/${slug}`;
  const tabs = [
    { label: "Environments", href: `${basePath}/environments` },
    { label: "Presets", href: `${basePath}/presets` },
    { label: "Secrets", href: `${basePath}/secrets` },
    { label: "API Keys", href: `${basePath}/api-keys` },
    { label: "Members", href: `${basePath}/members` },
    { label: "Billing", href: `${basePath}/billing` },
  ];

  function isTabActive(tabHref: string) {
    return pathname.startsWith(tabHref);
  }

  return (
    <div className="animate-page-enter py-6 md:py-8 max-w-4xl mx-auto">
      {/* Back link */}
      <Link
        to="/dashboard"
        className="inline-flex items-center gap-2 text-sm text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] mb-4"
      >
        <ArrowLeft className="h-4 w-4" />
        Dashboard
      </Link>

      {/* Org header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-[color:var(--fg-primary)]">{organization.name}</h1>
          <Badge variant="outline" className="text-xs">
            {orgRoleName(membership.role)}
          </Badge>
        </div>
      </div>

      {/* Nav tabs */}
      <div className="flex gap-1 border-b border-[var(--border-subtle)] mb-6">
        {tabs.map((tab) => {
          const active = isTabActive(tab.href);
          return (
            <Link
              key={tab.href}
              to={tab.href}
              className={`px-4 py-2 text-sm font-medium transition-colors relative no-underline ${
                active
                  ? "text-[color:var(--fg-primary)]"
                  : "text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)]"
              }`}
            >
              {tab.label}
              {active && (
                <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--accent)]" />
              )}
            </Link>
          );
        })}
      </div>

      {/* Child route content */}
      <Outlet />
    </div>
  );
}
