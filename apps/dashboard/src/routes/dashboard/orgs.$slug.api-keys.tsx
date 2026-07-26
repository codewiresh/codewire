import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  createConnectQueryKey,
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { ApiKeyService, type ApiKey } from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { connectTransport } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { findOrganizationBySlug } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { Copy, Key, Loader2, Plus, Power, PowerOff, Trash2 } from "lucide-react";

export const Route = createFileRoute("/dashboard/orgs/$slug/api-keys")({
  component: APIKeysPage,
});

const apiKeyListQueryKey = createConnectQueryKey({
  schema: ApiKeyService.method.listApiKeys,
  transport: connectTransport,
  cardinality: undefined,
});

function keyStatus(key: ApiKey): "active" | "disabled" | "expired" {
  if (key.disabledAt) return "disabled";
  if (key.expiresAt && timestampDate(key.expiresAt) < new Date()) return "expired";
  return "active";
}

function statusBadge(status: "active" | "disabled" | "expired") {
  switch (status) {
    case "active":
      return <Badge variant="outline" className="text-green-600 border-green-600/30">Active</Badge>;
    case "disabled":
      return <Badge variant="outline" className="text-yellow-600 border-yellow-600/30">Disabled</Badge>;
    case "expired":
      return <Badge variant="outline" className="text-[var(--destructive)] border-[var(--destructive)]/30">Expired</Badge>;
  }
}

function relativeTime(timestamp: Timestamp) {
  const d = timestampDate(timestamp);
  const now = new Date();
  const diff = now.getTime() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

function APIKeysPage() {
  const { slug } = Route.useParams();
  const queryClient = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [expiry, setExpiry] = useState("never");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<ApiKey | null>(null);

  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const membership = findOrganizationBySlug(orgsResponse?.organizations, slug);
  const org = membership?.organization;

  const { data: keysResponse, isLoading } = useConnectQuery(
    ApiKeyService.method.listApiKeys,
    org?.id ? { orgId: org.id } : undefined,
    {
      enabled: !!org?.id,
      transport: connectTransport,
    },
  );
  const keys = keysResponse?.apiKeys;

  const createMut = useConnectMutation(ApiKeyService.method.createApiKey, {
    transport: connectTransport,
    onSuccess: (data) => {
      setCreatedKey(data.key);
      setNewName("");
      setExpiry("never");
      setShowCreate(false);
      queryClient.invalidateQueries({ queryKey: apiKeyListQueryKey });
    },
  });

  const toggleMut = useConnectMutation(ApiKeyService.method.updateApiKey, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: apiKeyListQueryKey }),
  });

  const deleteMut = useConnectMutation(ApiKeyService.method.deleteApiKey, {
    transport: connectTransport,
    onSuccess: () => {
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: apiKeyListQueryKey });
    },
  });

  if (!org || isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-[color:var(--fg-tertiary)]" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[color:var(--fg-primary)]">API Keys</h2>
          <p className="text-sm text-[color:var(--fg-tertiary)]">
            Manage API keys for programmatic access
          </p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)} className="gap-1.5">
          <Plus className="h-4 w-4" />
          Create Key
        </Button>
      </div>

      {(keys ?? []).length === 0 ? (
        <div className="text-center py-12">
          <Key className="h-8 w-8 mx-auto mb-3 text-[color:var(--fg-tertiary)]" />
          <p className="text-sm text-[color:var(--fg-tertiary)]">
            No API keys yet. Create one for programmatic access.
          </p>
        </div>
      ) : (
        <div className="border border-[var(--border)] rounded-lg overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Created By</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(keys ?? []).map((k) => {
                const status = keyStatus(k);
                return (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell>
                      <code className="text-xs bg-[var(--bg-surface-hover)] px-1.5 py-0.5 rounded">
                        cw_{k.keyPrefix}...
                      </code>
                    </TableCell>
                    <TableCell className="text-sm text-[color:var(--fg-secondary)]">
                      {k.createdByName || k.createdByEmail || "-"}
                    </TableCell>
                    <TableCell className="text-sm text-[color:var(--fg-secondary)]">
                      {k.createdAt ? relativeTime(k.createdAt) : "-"}
                    </TableCell>
                    <TableCell className="text-sm text-[color:var(--fg-secondary)]">
                      {k.lastUsedAt ? relativeTime(k.lastUsedAt) : "Never"}
                    </TableCell>
                    <TableCell>{statusBadge(status)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        {status !== "expired" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              toggleMut.mutate({
                                orgId: org.id,
                                keyId: k.id,
                                disabled: status === "active",
                              })
                            }
                            disabled={toggleMut.isPending}
                            aria-label={status === "active" ? "Disable API key" : "Enable API key"}
                            title={status === "active" ? "Disable" : "Enable"}
                          >
                            {status === "active" ? (
                              <PowerOff className="h-3.5 w-3.5" />
                            ) : (
                              <Power className="h-3.5 w-3.5" />
                            )}
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(k)}
                          aria-label="Delete API key"
                          className="text-[var(--destructive)]"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      {toggleMut.isError && (
        <p className="text-sm text-[var(--destructive)]">{errorMessage(toggleMut.error)}</p>
      )}

      {/* Create dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>
              Generate a new API key for programmatic access to this organization.
            </DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (newName.trim()) {
                createMut.mutate({
                  orgId: org.id,
                  name: newName,
                  scopes: [],
                  expiresInDays: expiry === "never" ? undefined : parseInt(expiry, 10),
                });
              }
            }}
            className="space-y-4"
          >
            <div className="space-y-2">
              <Label htmlFor="key-name">Name</Label>
              <Input
                id="key-name"
                placeholder="e.g. CI/CD Pipeline"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label>Expiration</Label>
              <Select value={expiry} onValueChange={setExpiry}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="never">Never</SelectItem>
                  <SelectItem value="30">30 days</SelectItem>
                  <SelectItem value="60">60 days</SelectItem>
                  <SelectItem value="90">90 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <DialogFooter>
              <Button
                type="submit"
                disabled={!newName.trim() || createMut.isPending}
              >
                {createMut.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : null}
                Create
              </Button>
            </DialogFooter>
            {createMut.isError && (
              <p className="text-sm text-[var(--destructive)]">
                {errorMessage(createMut.error)}
              </p>
            )}
          </form>
        </DialogContent>
      </Dialog>

      {/* Key reveal dialog */}
      <Dialog open={!!createdKey} onOpenChange={() => setCreatedKey(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
            <DialogDescription>
              Copy your key now. It won't be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="relative">
            <code className="block w-full p-3 bg-[var(--bg-surface-hover)] rounded text-xs break-all font-mono">
              {createdKey}
            </code>
            <Button
              variant="ghost"
              size="sm"
              className="absolute top-1 right-1"
              onClick={() => {
                if (createdKey) {
                  navigator.clipboard.writeText(createdKey);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }
              }}
            >
              {copied ? (
                <span className="text-xs text-green-600">Copied</span>
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </Button>
          </div>
          <DialogFooter>
            <Button onClick={() => setCreatedKey(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete API Key</DialogTitle>
            <DialogDescription>
              Permanently revoke <strong>{deleteTarget?.name}</strong>? Any integrations using this key will stop working immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteTarget && deleteMut.mutate({ orgId: org.id, keyId: deleteTarget.id })
              }
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : null}
              Delete
            </Button>
          </DialogFooter>
          {deleteMut.isError && (
            <p className="text-sm text-[var(--destructive)]">
              {errorMessage(deleteMut.error)}
            </p>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
