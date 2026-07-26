import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { PortAccess, PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { connectTransport, portServiceQueryKey } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Loader2, Trash2, ExternalLink } from "lucide-react";

function portAccessValue(access: string): PortAccess {
  switch (access) {
    case "public":
      return PortAccess.PUBLIC;
    case "org_members":
      return PortAccess.ORG_MEMBERS;
    default:
      return PortAccess.CREATOR;
  }
}

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

export function PortsDialog({
  orgId,
  envId,
  open,
  onClose,
}: {
  orgId: string;
  envId: string | null;
  open: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [portNum, setPortNum] = useState("");
  const [label, setLabel] = useState("");
  const [access, setAccess] = useState("creator");
  const [addError, setAddError] = useState("");

  const { data: portsResponse } = useConnectQuery(
    PortService.method.listPorts,
    envId ? { orgId, environmentId: envId } : undefined,
    { enabled: open && !!envId, refetchInterval: 15000, transport: connectTransport },
  );

  const createMutation = useConnectMutation(PortService.method.createPort, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: portServiceQueryKey });
      setPortNum("");
      setLabel("");
      setAccess("creator");
      setAddError("");
    },
    onError: (error) => setAddError(errorMessage(error)),
  });

  const deleteMutation = useConnectMutation(PortService.method.deletePort, {
    transport: connectTransport,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: portServiceQueryKey }),
  });

  const portList = portsResponse?.ports ?? [];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const num = parseInt(portNum, 10);
    if (!num || num < 1 || num > 65535) {
      setAddError("Port must be 1-65535");
      return;
    }
    if (!label.match(/^[a-z0-9][a-z0-9-]{0,20}[a-z0-9]$/)) {
      setAddError("Label must be 2-22 chars: lowercase alphanumeric + hyphens");
      return;
    }
    createMutation.mutate({
      orgId,
      environmentId: envId!,
      port: num,
      label,
      access: portAccessValue(access),
    });
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Port Management</DialogTitle>
          <DialogDescription>
            Expose ports from this environment with preview URLs
          </DialogDescription>
        </DialogHeader>

        {portList.length === 0 ? (
          <p className="text-sm text-[color:var(--fg-secondary)] text-center py-4">
            No ports registered
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Access</TableHead>
                <TableHead>Preview</TableHead>
                <TableHead className="w-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {portList.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="font-medium font-mono text-xs">{p.label}</TableCell>
                  <TableCell className="font-mono text-xs">{p.port}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[10px]">
                      {portAccessName(p.access) === "org_members"
                        ? "Org"
                        : portAccessName(p.access) === "public"
                          ? "Public"
                          : "Creator"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {p.previewUrl ? (
                      <a
                        href={p.previewUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-[color:var(--accent)] hover:underline"
                      >
                        {new URL(p.previewUrl).hostname}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <span className="text-xs text-[color:var(--fg-secondary)]">--</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0 text-[color:var(--destructive)]"
                      onClick={() =>
                        deleteMutation.mutate({
                          orgId,
                          environmentId: envId!,
                          portId: p.id,
                        })
                      }
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <div className="border-t border-[var(--border)] pt-3">
          {addError && (
            <p className="text-xs text-[color:var(--destructive)] mb-2">{addError}</p>
          )}
          {(createMutation.error || deleteMutation.error) && (
            <p role="alert" className="text-xs text-[color:var(--destructive)] mb-2">
              {errorMessage(createMutation.error ?? deleteMutation.error)}
            </p>
          )}
          <form onSubmit={handleSubmit} className="flex items-end gap-2">
            <div className="w-20">
              <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">Port</label>
              <Input
                value={portNum}
                onChange={(e) => setPortNum(e.target.value)}
                placeholder="3000"
                type="number"
              />
            </div>
            <div className="flex-1">
              <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">Label</label>
              <Input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="web"
              />
            </div>
            <div className="w-28">
              <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">Access</label>
              <select
                value={access}
                onChange={(e) => setAccess(e.target.value)}
                className="w-full rounded-md border border-[var(--border)] bg-[var(--bg-base)] px-2 py-2 text-sm"
              >
                <option value="creator">Creator</option>
                <option value="org_members">Org</option>
                <option value="public">Public</option>
              </select>
            </div>
            <Button type="submit" size="sm" disabled={createMutation.isPending}>
              {createMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                "Add"
              )}
            </Button>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
}
