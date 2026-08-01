import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery as useConnectQuery } from "@connectrpc/connect-query";
import { GitHubService } from "@codewire/proto-ts/gen/codewire/console/v1/github_pb";
import {
  OrganizationService,
  type OrganizationMembership,
} from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { connectTransport } from "@/lib/connect";
import { orgRoleName } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Plus,
  Loader2,
  Building2,
  ChevronRight,
  CheckCircle2,
  Circle,
  Github,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/")({
  component: DashboardPage,
});

function DashboardPage() {
  const { data: orgsResponse, isLoading } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );

  const { data: ghStatus } = useConnectQuery(
    GitHubService.method.getGitHubStatus,
    undefined,
    { transport: connectTransport },
  );

  if (isLoading) {
    return (
      <div className="animate-page-enter py-8">
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-tertiary)]" />
        </div>
      </div>
    );
  }

  const orgs = orgsResponse?.organizations ?? [];

  return (
    <div className="cw-page animate-page-enter py-6 md:py-8 max-w-4xl mx-auto">
      <div className="cw-page-header flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 md:mb-8">
        <div>
          <h1 className="cw-page-title text-2xl md:text-3xl font-bold text-[color:var(--fg-primary)]">Dashboard</h1>
          <p className="cw-page-description text-[color:var(--fg-secondary)] mt-1 text-sm md:text-base">
            Manage your organizations and environments
          </p>
        </div>
        <div className="flex gap-2 self-start sm:self-auto">
          <Link to="/dashboard/orgs/new">
            <Button variant="outline" className="gap-2">
              <Building2 className="h-4 w-4" />
              New Organization
            </Button>
          </Link>
        </div>
      </div>

      {/* Setup checklist — show when setup is incomplete */}
      {orgs.length === 0 || (orgs.length > 0 && !ghStatus?.connected) ? (
        <SetupChecklist orgs={orgs} ghStatus={ghStatus} />
      ) : null}

      {orgs.length === 0 ? (
        <Card className="text-center py-16">
          <CardContent className="pt-6">
            <div className="h-12 w-12 rounded-lg bg-[var(--bg-surface-hover)] flex items-center justify-center mx-auto mb-4">
              <Building2 className="h-6 w-6 text-[color:var(--fg-tertiary)]" />
            </div>
            <h3 className="text-lg font-semibold mb-2 text-[color:var(--fg-primary)]">
              No organizations yet
            </h3>
            <p className="text-[color:var(--fg-secondary)] mb-6 max-w-sm mx-auto">
              Create your first organization to start creating environments
            </p>
            <Link to="/dashboard/orgs/new">
              <Button className="gap-2">
                <Plus className="h-4 w-4" />
                Create Your First Organization
              </Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {orgs.map((membership) => (
            membership.organization && <OrgCard key={membership.organization.id} membership={membership} />
          ))}
        </div>
      )}
    </div>
  );
}

function SetupChecklist({
  orgs,
  ghStatus,
}: {
  orgs: OrganizationMembership[];
  ghStatus?: { connected: boolean; username?: string } | null;
}) {
  const hasOrg = orgs.length > 0;
  const hasGitHub = !!ghStatus?.connected;

  // Don't show if everything is done
  if (hasOrg && hasGitHub) return null;

  return (
    <Card className="mb-6">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Get started</CardTitle>
        <CardDescription>Complete these steps to start creating environments</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <ChecklistItem done={hasOrg} label="Create an organization">
          {!hasOrg && (
            <Link to="/dashboard/orgs/new">
              <Button variant="outline" size="sm" className="mt-1">
                <Plus className="h-3 w-3 mr-1" />
                Create
              </Button>
            </Link>
          )}
        </ChecklistItem>
        <ChecklistItem done={hasGitHub} label="Connect GitHub">
          {!hasGitHub && (
            <div className="mt-1">
              <p className="text-xs text-[color:var(--fg-tertiary)] mb-1">
                Connect your GitHub account to create environments from private repos
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  window.location.href = `/api/v1/github/oauth/authorize?return_url=${encodeURIComponent(window.location.href)}`;
                }}
              >
                <Github className="h-3 w-3 mr-1" />
                Connect
              </Button>
            </div>
          )}
        </ChecklistItem>
      </CardContent>
    </Card>
  );
}

function ChecklistItem({
  done,
  label,
  children,
}: {
  done: boolean;
  label: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2">
      {done ? (
        <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
      ) : (
        <Circle className="h-4 w-4 text-[color:var(--fg-tertiary)] mt-0.5 shrink-0" />
      )}
      <div>
        <span className={`text-sm ${done ? "text-[color:var(--fg-secondary)] line-through" : "text-[color:var(--fg-primary)]"}`}>
          {label}
        </span>
        {!done && children}
      </div>
    </div>
  );
}

function OrgCard({ membership }: { membership: OrganizationMembership }) {
  const organization = membership.organization;
  if (!organization) return null;

  return (
    <Link to="/dashboard/orgs/$slug" params={{ slug: organization.slug }}>
      <Card className="hover:border-[var(--accent)]/50 transition-all duration-150 cursor-pointer">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-md bg-[var(--bg-surface)] flex items-center justify-center">
                <Building2 className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
              </div>
              <div>
                <CardTitle className="text-base flex items-center gap-2">
                  {organization.name}
                  <Badge variant="outline" className="text-xs">
                    {orgRoleName(membership.role)}
                  </Badge>
                </CardTitle>
                <CardDescription className="text-xs mt-0.5">
                  Plan: {membership.billingPlan}
                </CardDescription>
              </div>
            </div>
            <ChevronRight className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
          </div>
        </CardHeader>
      </Card>
    </Link>
  );
}
