import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery as useConnectQuery } from "@connectrpc/connect-query";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import {
  AdminService,
  type AuditLogEntry,
} from "@codewire/proto-ts/gen/codewire/admin/v1/admin_pb";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { connectTransport } from "@/lib/connect";
import { Loader2, ChevronDown, ChevronRight } from "lucide-react";

export const Route = createFileRoute("/admin/audit")({
  component: AdminAuditPage,
});

function getSeverityVariant(
  severity: string,
): "default" | "secondary" | "destructive" | "warning" {
  switch (severity) {
    case "error":
      return "destructive";
    case "warn":
      return "warning";
    default:
      return "secondary";
  }
}

const PAGE_SIZE = 50;

function AdminAuditPage() {
  const [actionFilter, setActionFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [offset, setOffset] = useState(0);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const { data: auditLogsResponse, isLoading } = useConnectQuery(
    AdminService.method.listAuditLogs,
    {
      limit: PAGE_SIZE,
      offset,
      action: actionFilter,
      severity: severityFilter === "all" ? "" : severityFilter,
    },
    { transport: connectTransport, refetchInterval: 15000 },
  );
  const logs = auditLogsResponse?.auditLogs;

  return (
    <div className="space-y-6 animate-page-enter">
      <h2 className="text-lg font-semibold text-[color:var(--fg-primary)]">Audit Log</h2>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <Input
          placeholder="Filter by action (e.g. user.signin)"
          value={actionFilter}
          onChange={(e) => {
            setActionFilter(e.target.value);
            setOffset(0);
          }}
          className="sm:w-[280px]"
        />
        <Select
          value={severityFilter}
          onValueChange={(v) => {
            setSeverityFilter(v);
            setOffset(0);
          }}
        >
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="All" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="info">Info</SelectItem>
            <SelectItem value="warn">Warn</SelectItem>
            <SelectItem value="error">Error</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-[color:var(--fg-secondary)]" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs && logs.length > 0 ? (
                  logs.map((entry: AuditLogEntry) => {
                    const isExpanded = expandedRow === entry.id;
                    const meta = entry.metadata as Record<string, unknown> | null;
                    const hasMetadata =
                      meta != null &&
                      Object.keys(meta).length > 0;
                    return (
                      <>
                        <TableRow
                          key={entry.id}
                          className={hasMetadata ? "cursor-pointer" : ""}
                          onClick={() =>
                            hasMetadata &&
                            setExpandedRow(isExpanded ? null : entry.id)
                          }
                        >
                          <TableCell className="w-8 px-2">
                            {hasMetadata &&
                              (isExpanded ? (
                                <ChevronDown className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
                              ) : (
                                <ChevronRight className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
                              ))}
                          </TableCell>
                          <TableCell className="text-sm text-[color:var(--fg-tertiary)] whitespace-nowrap">
                            {entry.timestamp
                              ? timestampDate(entry.timestamp).toLocaleString()
                              : "—"}
                          </TableCell>
                          <TableCell>
                            <code className="text-xs bg-[var(--bg-surface)] px-1.5 py-0.5 rounded">
                              {entry.action}
                            </code>
                          </TableCell>
                          <TableCell className="text-sm text-[color:var(--fg-primary)]">
                            {entry.userEmail || "—"}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-[color:var(--fg-primary)]">
                            {entry.ipAddress || "—"}
                          </TableCell>
                          <TableCell>
                            <Badge variant={getSeverityVariant(entry.severity)}>
                              {entry.severity}
                            </Badge>
                          </TableCell>
                        </TableRow>
                        {isExpanded && hasMetadata && (
                          <TableRow key={`${entry.id}-meta`}>
                            <TableCell colSpan={6} className="bg-[var(--bg-surface)] px-6 py-3">
                              <pre className="text-xs font-mono whitespace-pre-wrap">
                                {JSON.stringify(entry.metadata, null, 2)}
                              </pre>
                            </TableCell>
                          </TableRow>
                        )}
                      </>
                    );
                  })
                ) : (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="text-center text-[color:var(--fg-secondary)] py-8"
                    >
                      No audit log entries found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <Button
          variant="outline"
          size="sm"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </Button>
        <span className="text-sm text-[color:var(--fg-secondary)]">
          Showing {offset + 1}–{offset + (logs?.length ?? 0)}
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={!logs || logs.length < PAGE_SIZE}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Load More
        </Button>
      </div>
    </div>
  );
}
