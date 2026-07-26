import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { useQuery as useConnectQuery } from "@connectrpc/connect-query";
import {
  EnvironmentService,
  EnvironmentState,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import {
  OrganizationService,
  type OrganizationMembership,
} from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { signOut } from "@/lib/auth";
import { connectTransport } from "@/lib/connect";
import {
  ChevronDown,
  ChevronRight,
  Settings,
  Plus,
  LogOut,
  LayoutDashboard,
  FileText,
  CreditCard,
  BookOpen,
  Terminal,
} from "lucide-react";
import { useState } from "react";

function StatusDot({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    running: "bg-[var(--success)]",
    starting: "bg-[var(--info)] animate-pulse-dot",
    creating: "bg-[var(--info)] animate-pulse-dot",
    pending: "bg-[var(--warning)] animate-pulse-dot",
    stopping: "bg-[var(--warning)] animate-pulse-dot",
    stopped: "bg-[var(--fg-tertiary)]",
    error: "bg-[var(--destructive)]",
  };
  return (
    <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${colorMap[status] || "bg-[var(--fg-tertiary)]"}`} />
  );
}

function environmentStateName(state: EnvironmentState): string {
  const enumName = EnvironmentState[state];
  return enumName && enumName !== "UNSPECIFIED" ? enumName.toLowerCase() : "unknown";
}

function OrgGroup({ membership, onClose }: { membership: OrganizationMembership; onClose?: () => void }) {
  const organization = membership.organization;
  const [expanded, setExpanded] = useState(true);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();

  // Fetch active environments for this org
  const { data: environmentsResponse } = useConnectQuery(
    EnvironmentService.method.listEnvironments,
    organization ? { orgId: organization.id } : undefined,
    { enabled: !!organization, transport: connectTransport, refetchInterval: 10000 },
  );

  // Only show active envs (not destroyed/destroying)
  const activeEnvs = (environmentsResponse?.environments ?? []).filter(
    (env) => ![EnvironmentState.DESTROYED, EnvironmentState.DESTROYING].includes(env.state),
  );

  const handleOrgClick = () => {
    if (!organization) return;
    navigate({ to: "/dashboard/orgs/$slug", params: { slug: organization.slug } });
    setExpanded(!expanded);
    onClose?.();
  };

  if (!organization) return null;

  return (
    <div>
      <button
        onClick={handleOrgClick}
        className="flex items-center gap-2 w-full px-3 py-1.5 text-sm text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] hover:bg-[var(--bg-surface)] rounded-md transition-colors cursor-pointer group"
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-[color:var(--fg-tertiary)]" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-[color:var(--fg-tertiary)]" />
        )}
        <span className="truncate flex-1 text-left font-medium">{organization.name}</span>
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <Link
            to="/dashboard/orgs/$slug/billing"
            params={{ slug: organization.slug }}
            onClick={(e) => e.stopPropagation()}
          >
            <CreditCard className="h-3.5 w-3.5 text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-primary)]" />
          </Link>
          <Link
            to="/dashboard/orgs/$slug"
            params={{ slug: organization.slug }}
            onClick={(e) => e.stopPropagation()}
          >
            <Settings className="h-3.5 w-3.5 text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-primary)]" />
          </Link>
        </div>
      </button>

      {expanded && (
        <div className="ml-3 mt-0.5 space-y-0.5">
          {activeEnvs.length > 0 && (
            activeEnvs.map((env) => (
              <Link
                key={env.id}
                to="/terminal/$orgId/$envId"
                params={{ orgId: organization.id, envId: env.id }}
                onClick={onClose}
                className={`flex items-center gap-2 px-3 py-1.5 text-sm rounded-md transition-colors ${
                  pathname.includes(env.id)
                    ? "bg-[var(--bg-surface)] text-[color:var(--fg-primary)] border-l-[3px] border-[var(--accent)] -ml-[3px] pl-[15px]"
                    : "text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] hover:bg-[var(--bg-surface)]"
                }`}
              >
                <Terminal className="h-3.5 w-3.5 text-[color:var(--fg-tertiary)]" />
                <StatusDot status={environmentStateName(env.state)} />
                <span className="truncate flex-1">{env.name}</span>
              </Link>
            ))
          )}

          <Link
            to="/dashboard/orgs/$slug/environments"
            params={{ slug: organization.slug }}
            search={{ create: true }}
            onClick={onClose}
            className="flex items-center gap-2 px-3 py-2 mt-1 text-xs font-medium text-white bg-[var(--accent)] hover:bg-[var(--accent)]/90 rounded-md transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Create Env
          </Link>
        </div>
      )}
    </div>
  );
}

export function Sidebar({
  isAdmin,
  userName,
  onClose,
}: {
  isAdmin: boolean;
  userName?: string;
  onClose?: () => void;
}) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const orgs = orgsResponse?.organizations ?? [];

  const handleNavigate = () => {
    onClose?.();
  };

  return (
    <nav
      className="flex flex-col h-full"
      style={{ background: "var(--bg-primary)", fontFamily: "var(--font-sans)" }}
      aria-label="Main navigation"
    >
      {/* Logo + User */}
      <div className="px-4 py-4 border-b border-[var(--border-subtle)]">
        <Link to="/dashboard" className="flex items-center gap-2 no-underline" onClick={handleNavigate}>
          <svg width="20" height="20" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="32" height="32" rx="8" fill="#0EA5E9" />
            <path d="M8 10l6 6-6 6" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            <line x1="17" y1="22" x2="24" y2="22" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
          </svg>
          <span
            className="text-sm text-[color:var(--fg-primary)]"
            style={{ fontWeight: 510 }}
          >
            Codewire
          </span>
        </Link>
        {userName && (
          <p className="text-xs text-[color:var(--fg-tertiary)] mt-1.5 truncate">{userName}</p>
        )}
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
        {/* Environments section */}
        <div>
          <div className="section-label px-3 mb-2">ENVIRONMENTS</div>
          {orgs && orgs.length > 0 ? (
            <div className="space-y-1">
              {orgs.map((membership) => (
                membership.organization && (
                  <OrgGroup key={membership.organization.id} membership={membership} onClose={onClose} />
                )
              ))}
            </div>
          ) : (
            <p className="px-3 text-xs text-[color:var(--fg-tertiary)]">No organizations</p>
          )}
        </div>

        <div className="px-3">
          <Link to="/dashboard/orgs/new" onClick={handleNavigate}>
            <span className="flex items-center gap-2 text-xs text-[color:var(--fg-tertiary)] hover:text-[color:var(--accent)] transition-colors cursor-pointer">
              <Plus className="h-3.5 w-3.5" />
              New Organization
            </span>
          </Link>
        </div>

        {/* Admin section */}
        {isAdmin && (
          <>
            <div className="h-px bg-[var(--border-subtle)] mx-3" />
            <div>
              <div className="section-label px-3 mb-2">ADMIN</div>
              <div className="space-y-0.5">
                {[
                  { to: "/admin", label: "Overview", icon: LayoutDashboard },
                  { to: "/admin/billing", label: "Billing Catalog", icon: CreditCard },
                  { to: "/admin/audit", label: "Audit Log", icon: FileText },
                ].map((item) => {
                  const Icon = item.icon;
                  const isActive = pathname === item.to;
                  return (
                    <Link
                      key={item.to}
                      to={item.to}
                      onClick={handleNavigate}
                      className={`flex items-center gap-2 px-3 py-1.5 text-sm rounded-md transition-colors ${
                        isActive
                          ? "bg-[var(--bg-surface)] text-[color:var(--fg-primary)] border-l-[3px] border-[var(--accent)] -ml-[3px] pl-[15px]"
                          : "text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] hover:bg-[var(--bg-surface)]"
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                      {item.label}
                    </Link>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Bottom links */}
      <div className="border-t border-[var(--border-subtle)] px-2 py-3 space-y-0.5">
        <Link
          to="/dashboard/settings"
          onClick={handleNavigate}
          className={`flex items-center gap-2 px-3 py-1.5 text-sm rounded-md transition-colors ${
            pathname === "/dashboard/settings"
              ? "bg-[var(--bg-surface)] text-[color:var(--fg-primary)] border-l-[3px] border-[var(--accent)] -ml-[3px] pl-[15px]"
              : "text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] hover:bg-[var(--bg-surface)]"
          }`}
        >
          <Settings className="h-4 w-4" />
          Settings
        </Link>
        <a
          href="https://codewire.sh/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-1.5 text-sm text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] hover:bg-[var(--bg-surface)] rounded-md transition-colors no-underline"
        >
          <BookOpen className="h-4 w-4" />
          Docs
        </a>
        <button
          onClick={() => signOut().then(() => (window.location.href = "/"))}
          className="flex items-center gap-2 px-3 py-1.5 text-sm text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] hover:bg-[var(--bg-surface)] rounded-md transition-colors w-full cursor-pointer"
        >
          <LogOut className="h-4 w-4" />
          Sign Out
        </button>
      </div>
    </nav>
  );
}
