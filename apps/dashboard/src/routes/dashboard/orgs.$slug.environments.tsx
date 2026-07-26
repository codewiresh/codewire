import React from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  createConnectQueryKey,
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import {
  EnvironmentService,
  EnvironmentState,
  type Environment,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { PortAccess, PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { connectTransport } from "@/lib/connect";
import { findOrganizationBySlug } from "@/lib/organizations";
import { TerminalPanel } from "@/components/terminal";
import { PortsDialog } from "@/components/ports-dialog";
import { EnvCreateForm } from "@/components/env-create-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Loader2,
  Plus,
  Trash2,
  Square,
  Play,
  MoreHorizontal,
  Terminal,
  Code2,
  Network,
  ArrowUpDown,
  X,
  Globe,
  Building,
  User,
  Settings2,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/orgs/$slug/environments")({
  component: EnvironmentsPage,
  validateSearch: (search: Record<string, unknown>) => ({
    create: search.create === "true" || search.create === true,
  }),
});

const STATE_COLORS: Record<string, string> = {
  running: "bg-green-500/10 text-green-700 border-green-500/20",
  starting: "bg-yellow-500/10 text-yellow-700 border-yellow-500/20",
  creating: "bg-yellow-500/10 text-yellow-700 border-yellow-500/20",
  stopping: "bg-yellow-500/10 text-yellow-700 border-yellow-500/20",
  pending: "bg-yellow-500/10 text-yellow-700 border-yellow-500/20",
  stopped: "bg-gray-500/10 text-gray-600 border-gray-500/20",
  destroyed: "bg-gray-500/10 text-gray-500 border-gray-500/20",
  destroying: "bg-gray-500/10 text-gray-500 border-gray-500/20",
  error: "bg-red-500/10 text-red-700 border-red-500/20",
  build_failed: "bg-red-500/10 text-red-700 border-red-500/20",
};

const STATE_ICONS: Record<string, string> = {
  running: "\u2713",
  stopped: "\u25CB",
  pending: "\u25CC",
  creating: "\u25CC",
  starting: "\u25CC",
  stopping: "\u25CC",
  destroying: "\u25CC",
  error: "\u2715",
  build_failed: "\u2715",
  destroyed: "\u2015",
};

const SANDBOX_RATES = {
  cpuPerSecond: 0.000014,   // per vCPU
  memPerSecond: 0.0000045,  // per GiB
};

const environmentServiceQueryKey = createConnectQueryKey({
  schema: EnvironmentService,
  transport: connectTransport,
  cardinality: undefined,
});

function environmentStateName(state: EnvironmentState): string {
  switch (state) {
    case EnvironmentState.PENDING:
      return "pending";
    case EnvironmentState.PENDING_BUILD:
      return "pending_build";
    case EnvironmentState.BUILDING:
      return "building";
    case EnvironmentState.BUILD_FAILED:
      return "build_failed";
    case EnvironmentState.PULLING_SNAPSHOT:
      return "pulling_snapshot";
    case EnvironmentState.CREATING:
      return "creating";
    case EnvironmentState.STARTING:
      return "starting";
    case EnvironmentState.RUNNING:
      return "running";
    case EnvironmentState.STOPPING:
      return "stopping";
    case EnvironmentState.STOPPED:
      return "stopped";
    case EnvironmentState.ARCHIVING:
      return "archiving";
    case EnvironmentState.ARCHIVED:
      return "archived";
    case EnvironmentState.RESTORING:
      return "restoring";
    case EnvironmentState.RESIZING:
      return "resizing";
    case EnvironmentState.DESTROYING:
      return "destroying";
    case EnvironmentState.DESTROYED:
      return "destroyed";
    case EnvironmentState.ERROR:
      return "error";
    case EnvironmentState.UNKNOWN:
    case EnvironmentState.UNSPECIFIED:
      return "unknown";
  }
  return "unknown";
}

function formatDuration(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatEnvCost(env: Environment): string {
  const cpuVCPU = env.cpuMillicores / 1000;
  const memGiB = env.memoryMb / 1024;
  const costPerSec = cpuVCPU * SANDBOX_RATES.cpuPerSecond + memGiB * SANDBOX_RATES.memPerSecond;
  const totalCost = env.totalRunningSeconds * costPerSec;
  return `$${totalCost.toFixed(2)}`;
}

function formatHourlyRate(env: Environment): string {
  const cpuVCPU = env.cpuMillicores / 1000;
  const memGiB = env.memoryMb / 1024;
  const hourlyRate = (cpuVCPU * SANDBOX_RATES.cpuPerSecond + memGiB * SANDBOX_RATES.memPerSecond) * 3600;
  return `$${hourlyRate.toFixed(2)}/h`;
}

function timeAgo(timestamp: Timestamp | undefined): string {
  if (!timestamp) return "-";
  const d = Date.now() - timestampDate(timestamp).getTime();
  const secs = Math.floor(d / 1000);
  if (secs < 10) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

type SortField = "id" | "state" | "created_at";
type SortDir = "asc" | "desc";

function EnvironmentsPage() {
  const { slug } = Route.useParams();
  const { create } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [showCreate, setShowCreate] = useState(create ?? false);

  // Clear the search param once we've consumed it
  useEffect(() => {
    if (create) {
      navigate({ to: ".", search: { create: false }, replace: true } as any);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [sortField, setSortField] = useState<SortField>("created_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [perPage, setPerPage] = useState(25);

  const [terminalEnv, setTerminalEnv] = useState<Environment | null>(null);
  const [portsEnvId, setPortsEnvId] = useState<string | null>(null);

  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const membership = findOrganizationBySlug(orgsResponse?.organizations, slug);
  const org = membership?.organization;

  const includeDestroyed = stateFilter === "destroyed";
  const { data: environmentsResponse, isLoading } = useConnectQuery(
    EnvironmentService.method.listEnvironments,
    org?.id ? { orgId: org.id, includeDestroyed } : undefined,
    {
      enabled: !!org?.id,
      transport: connectTransport,
      refetchInterval: 5000,
    },
  );

  const stopMutation = useConnectMutation(EnvironmentService.method.stopEnvironment, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: environmentServiceQueryKey }),
  });

  const startMutation = useConnectMutation(EnvironmentService.method.startEnvironment, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: environmentServiceQueryKey }),
  });

  const destroyMutation = useConnectMutation(EnvironmentService.method.deleteEnvironment, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: environmentServiceQueryKey }),
  });

  const envs = environmentsResponse?.environments ?? [];
  // Filter
  const filtered = useMemo(() => {
    let result = envs;
    if (stateFilter !== "all") {
      result = result.filter((e) => environmentStateName(e.state) === stateFilter);
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.id.toLowerCase().includes(q) ||
          (e.name && e.name.toLowerCase().includes(q)) ||
          (e.presetName && e.presetName.toLowerCase().includes(q)),
      );
    }
    return result;
  }, [envs, stateFilter, search]);

  // Sort
  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortField === "id") cmp = a.id.localeCompare(b.id);
      else if (sortField === "state") cmp = environmentStateName(a.state).localeCompare(environmentStateName(b.state));
      else {
        const aCreatedAt = a.createdAt ? timestampDate(a.createdAt).getTime() : 0;
        const bCreatedAt = b.createdAt ? timestampDate(b.createdAt).getTime() : 0;
        cmp = aCreatedAt - bCreatedAt;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [filtered, sortField, sortDir]);

  // Paginate
  const totalPages = Math.max(1, Math.ceil(sorted.length / perPage));
  const pageEnvs = sorted.slice(page * perPage, (page + 1) * perPage);

  // Reset page when filters change
  useEffect(() => { setPage(0); }, [search, stateFilter, perPage]);

  // Clear selection of envs no longer in view
  useEffect(() => {
    const pageIds = new Set(pageEnvs.map((e) => e.id));
    setSelectedIds((prev) => {
      const next = new Set<string>();
      prev.forEach((id) => { if (pageIds.has(id)) next.add(id); });
      return next.size === prev.size ? prev : next;
    });
  }, [pageEnvs]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  };

  const allPageSelected = pageEnvs.length > 0 && pageEnvs.every((e) => selectedIds.has(e.id));

  const toggleAll = () => {
    if (allPageSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(pageEnvs.map((e) => e.id)));
    }
  };

  const toggleOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleMassDestroy = () => {
    if (selectedIds.size === 0) return;
    if (!confirm(`Destroy ${selectedIds.size} environment(s)? This cannot be undone.`)) return;
    selectedIds.forEach((id) => {
      destroyMutation.mutate({ orgId: org!.id, environmentId: id });
    });
    setSelectedIds(new Set());
  };

  if (!org) return null;

  const stateOptions = ["all", "running", "stopped", "pending", "creating", "starting", "stopping", "error", "destroyed"];
  const terminalState = terminalEnv ? environmentStateName(terminalEnv.state) : undefined;

  return (
    <div className="w-full">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2 flex-1">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search..."
            className="max-w-xs h-8 text-sm"
          />
          <Select value={stateFilter} onValueChange={setStateFilter}>
            <SelectTrigger className="w-[130px] h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {stateOptions.map((s) => (
                <SelectItem key={s} value={s}>
                  {s === "all" ? "All states" : s.charAt(0).toUpperCase() + s.slice(1)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/dashboard/orgs/$slug/presets"
            params={{ slug }}
            className="no-underline"
          >
            <Button variant="outline" className="gap-1.5 h-8" size="sm">
              <Settings2 className="h-3.5 w-3.5" />
              Presets
            </Button>
          </Link>
          <Button className="gap-2 h-8" size="sm" onClick={() => setShowCreate(!showCreate)}>
            <Plus className="h-3.5 w-3.5" />
            Create
          </Button>
        </div>
      </div>

      {/* Create Form */}
      {showCreate && (
        <EnvCreateForm orgId={org.id} onCreated={() => setShowCreate(false)} />
      )}

      {/* Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-secondary)]" />
        </div>
      ) : envs.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-[color:var(--fg-secondary)] text-sm">
              No environments found. Create one to get started.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="rounded-md border border-[var(--border)]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    <input
                      type="checkbox"
                      role="checkbox"
                      checked={allPageSelected}
                      onChange={toggleAll}
                      className="rounded border-[var(--border)]"
                    />
                  </TableHead>
                  <TableHead>
                    <button onClick={() => toggleSort("id")} className="inline-flex items-center gap-1 hover:text-[color:var(--fg-primary)]">
                      ID <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </TableHead>
                  <TableHead>
                    <button onClick={() => toggleSort("state")} className="inline-flex items-center gap-1 hover:text-[color:var(--fg-primary)]">
                      State <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </TableHead>
                  <TableHead>Region</TableHead>
                  <TableHead>Labels</TableHead>
                  <TableHead>Last Event</TableHead>
                  <TableHead>
                    <button onClick={() => toggleSort("created_at")} className="inline-flex items-center gap-1 hover:text-[color:var(--fg-primary)]">
                      Created <ArrowUpDown className="h-3 w-3" />
                    </button>
                  </TableHead>
                  <TableHead className="w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageEnvs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-[color:var(--fg-secondary)] text-sm">
                      No environments match your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  pageEnvs.map((env) => {
                    const state = environmentStateName(env.state);
                    return (
                      <React.Fragment key={env.id}>
                        <TableRow className={state === "running" ? "border-0" : ""} data-state={selectedIds.has(env.id) ? "selected" : undefined}>
                          <TableCell>
                            <input
                              type="checkbox"
                              role="checkbox"
                              checked={selectedIds.has(env.id)}
                              onChange={() => toggleOne(env.id)}
                              className="rounded border-[var(--border)]"
                            />
                          </TableCell>
                          <TableCell className="font-mono text-xs" title={env.id}>
                            {env.name || env.id.slice(0, 8)}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`text-[10px] px-1.5 py-0 ${STATE_COLORS[state] || ""}`}
                            >
                              <span className="mr-1">{STATE_ICONS[state] || ""}</span>
                              {state}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-[color:var(--fg-secondary)]">--</TableCell>
                          <TableCell className="text-xs text-[color:var(--fg-secondary)]">--</TableCell>
                          <TableCell className="text-xs text-[color:var(--fg-secondary)]">
                            {timeAgo(env.stateChangedAt)}
                          </TableCell>
                          <TableCell className="text-xs text-[color:var(--fg-secondary)]">
                            {timeAgo(env.createdAt)}
                          </TableCell>
                          <TableCell>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                {state === "running" && (
                                  <DropdownMenuItem
                                    onClick={() => stopMutation.mutate({ orgId: org.id, environmentId: env.id })}
                                  >
                                    <Square className="h-3.5 w-3.5 mr-2" />
                                    Stop
                                  </DropdownMenuItem>
                                )}
                                {state === "stopped" && (
                                  <DropdownMenuItem
                                    onClick={() => startMutation.mutate({ orgId: org.id, environmentId: env.id })}
                                  >
                                    <Play className="h-3.5 w-3.5 mr-2" />
                                    Start
                                  </DropdownMenuItem>
                                )}
                                {state === "running" && (
                                  <DropdownMenuItem asChild>
                                    <a href={`vscode://vscode-remote/ssh-remote+cw-${env.id}/workspace`}>
                                      <Code2 className="h-3.5 w-3.5 mr-2" />
                                      Open in VS Code
                                    </a>
                                  </DropdownMenuItem>
                                )}
                                <DropdownMenuItem onClick={() => setPortsEnvId(env.id)}>
                                  <Network className="h-3.5 w-3.5 mr-2" />
                                  Ports
                                </DropdownMenuItem>
                                {state !== "destroyed" && state !== "destroying" && (
                                  <>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem
                                      className="text-[color:var(--destructive)] focus:text-[color:var(--destructive)]"
                                      onClick={() => {
                                        if (confirm("Destroy this environment? This cannot be undone.")) {
                                          destroyMutation.mutate({ orgId: org.id, environmentId: env.id });
                                        }
                                      }}
                                    >
                                      <Trash2 className="h-3.5 w-3.5 mr-2" />
                                      Destroy
                                    </DropdownMenuItem>
                                  </>
                                )}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                        {state === "running" && (
                          <TableRow className="hover:bg-transparent">
                            <TableCell className="pt-0" />
                            <TableCell colSpan={7} className="pt-0 pb-2">
                              <div className="flex items-center gap-1.5">
                                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-[var(--fg-secondary)]">
                                  <span className="font-medium text-[var(--fg)]">{formatEnvCost(env)}</span>
                                  <span>&middot;</span>
                                  <span>{formatDuration(env.totalRunningSeconds)}</span>
                                  <span>&middot;</span>
                                  <span>{env.cpuMillicores / 1000} vCPU / {(env.memoryMb / 1024).toFixed(0)} GiB</span>
                                  <span>&middot;</span>
                                  <span>{formatHourlyRate(env)}</span>
                                </span>
                                <a
                                  href={`/terminal/${org.id}/${env.id}`}
                                  onClick={(e) => {
                                    if (e.ctrlKey || e.metaKey) return;
                                    e.preventDefault();
                                    setTerminalEnv(env);
                                  }}
                                  className="inline-flex items-center gap-1 rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] hover:bg-[var(--bg-hover)] text-[var(--fg-secondary)] hover:text-[var(--fg)]"
                                  title="Terminal (Ctrl+click for fullscreen)"
                                >
                                  <Terminal className="h-2.5 w-2.5" />
                                  terminal
                                </a>
                                <a
                                  href={`vscode://vscode-remote/ssh-remote+cw-${env.id}/workspace`}
                                  className="inline-flex items-center gap-1 rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] hover:bg-[var(--bg-hover)] text-[var(--fg-secondary)] hover:text-[var(--fg)]"
                                  title="Open in VS Code (requires cw config-ssh)"
                                >
                                  <Code2 className="h-2.5 w-2.5" />
                                  vscode
                                </a>
                                <PortBadges orgId={org.id} envId={env.id} />
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between mt-3 text-xs text-[color:var(--fg-secondary)]">
            <div className="flex items-center gap-3">
              <span>{selectedIds.size} of {sorted.length} row(s) selected</span>
              {selectedIds.size > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs text-[color:var(--destructive)] hover:text-[color:var(--destructive)]"
                  onClick={handleMassDestroy}
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Delete selected
                </Button>
              )}
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1">
                <span>Per page</span>
                <select
                  value={perPage}
                  onChange={(e) => setPerPage(Number(e.target.value))}
                  className="rounded border border-[var(--border)] bg-[var(--bg-base)] px-1.5 py-0.5 text-xs"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
              <span>Page {page + 1} of {totalPages}</span>
              <div className="flex gap-1">
                <Button variant="outline" size="sm" className="h-7 w-7 p-0" disabled={page === 0} onClick={() => setPage(0)}>&laquo;</Button>
                <Button variant="outline" size="sm" className="h-7 w-7 p-0" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>&lsaquo;</Button>
                <Button variant="outline" size="sm" className="h-7 w-7 p-0" disabled={page >= totalPages - 1} onClick={() => setPage((p) => p + 1)}>&rsaquo;</Button>
                <Button variant="outline" size="sm" className="h-7 w-7 p-0" disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>&raquo;</Button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Terminal Drawer */}
      {terminalEnv && (
        <div className="fixed bottom-0 left-0 right-0 z-40 bg-[var(--bg-surface)] border-t border-[var(--border)] shadow-2xl animate-in slide-in-from-bottom duration-200"
          style={{ height: "40vh" }}
        >
          <div className="flex items-center justify-between px-4 py-2 border-b border-[var(--border)]">
            <div className="flex items-center gap-2 text-sm">
              <Terminal className="h-4 w-4" />
              <span className="font-medium">{terminalEnv.name || terminalEnv.id.slice(0, 8)}</span>
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${STATE_COLORS[terminalState ?? ""] || ""}`}>
                {terminalState}
              </Badge>
            </div>
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setTerminalEnv(null)}>
              <X className="h-4 w-4" />
            </Button>
          </div>
          <div className="h-[calc(100%-41px)]">
            <TerminalPanel
              orgId={org.id}
              envId={terminalEnv.id}
              isRunning={terminalState === "running"}
              className="h-full overflow-hidden"
            />
          </div>
        </div>
      )}

      {/* Close terminal on Escape */}
      {terminalEnv && <EscapeHandler onEscape={() => setTerminalEnv(null)} />}

      {/* Port Management Dialog */}
      <PortsDialog
        orgId={org.id}
        envId={portsEnvId}
        open={!!portsEnvId}
        onClose={() => setPortsEnvId(null)}
      />
    </div>
  );
}

const ACCESS_ICONS: Record<string, typeof Globe> = {
  public: Globe,
  org_members: Building,
  creator: User,
};

function portAccessName(access: PortAccess): "public" | "org_members" | "creator" {
  switch (access) {
    case PortAccess.PUBLIC:
      return "public";
    case PortAccess.ORG_MEMBERS:
      return "org_members";
    default:
      return "creator";
  }
}

function PortBadges({ orgId, envId }: { orgId: string; envId: string }) {
  const { data: portsResponse } = useConnectQuery(
    PortService.method.listPorts,
    { orgId, environmentId: envId },
    { refetchInterval: 10000, transport: connectTransport },
  );
  const ports = portsResponse?.ports ?? [];

  if (ports.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1">
      {ports.map((p) => {
        const access = portAccessName(p.access);
        const Icon = ACCESS_ICONS[access] || Globe;
        return (
          <a
            key={p.id}
            href={p.previewUrl || "#"}
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center gap-1 rounded border px-1.5 py-0 text-[10px] font-mono border-[var(--border)] hover:bg-[var(--bg-hover)] ${p.previewUrl ? "text-[var(--fg)]" : "text-[var(--fg-secondary)] pointer-events-none"}`}
            title={`${p.label} (${access})`}
          >
            <Icon className="h-2.5 w-2.5" />
            {p.label || p.port}
          </a>
        );
      })}
    </div>
  );
}

function EscapeHandler({ onEscape }: { onEscape: () => void }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onEscape();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onEscape]);
  return null;
}
