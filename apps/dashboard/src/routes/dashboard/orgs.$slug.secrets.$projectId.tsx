import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useQuery as useConnectQuery } from "@connectrpc/connect-query";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import {
  connectTransport,
  secretClient,
  secretServiceQueryKey,
} from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { findOrganizationBySlug } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  ArrowLeft,
  Check,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  TextCursorInput,
  Trash2,
  X,
} from "lucide-react";

export const Route = createFileRoute(
  "/dashboard/orgs/$slug/secrets/$projectId",
)({
  component: ProjectSecrets,
});

function ProjectSecrets() {
  const { slug, projectId } = Route.useParams();
  const isOrg = projectId === "organization";
  const isUser = projectId === "user";
  const queryClient = useQueryClient();
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [renamingKey, setRenamingKey] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const org = findOrganizationBySlug(orgsResponse?.organizations, slug)?.organization;

  const { data: projectsResponse } = useConnectQuery(
    SecretService.method.listSecretProjects,
    org?.id ? { orgId: org.id } : undefined,
    {
      enabled: !!org?.id && !isOrg && !isUser,
      transport: connectTransport,
    },
  );
  const project = projectsResponse?.secretProjects.find((p) => p.id === projectId);

  const { data: organizationSecretsResponse, isLoading: organizationSecretsLoading } =
    useConnectQuery(
      SecretService.method.listSecrets,
      org?.id ? { orgId: org.id } : undefined,
      { enabled: !!org?.id && isOrg, transport: connectTransport },
    );
  const { data: userSecretsResponse, isLoading: userSecretsLoading } = useConnectQuery(
    SecretService.method.listUserSecrets,
    undefined,
    { enabled: isUser, transport: connectTransport },
  );
  const { data: projectSecretsResponse, isLoading: projectSecretsLoading } =
    useConnectQuery(
      SecretService.method.listProjectSecrets,
      org?.id ? { orgId: org.id, secretProjectId: projectId } : undefined,
      {
        enabled: !!org?.id && !isOrg && !isUser,
        transport: connectTransport,
      },
    );

  const secrets = isUser
    ? userSecretsResponse?.secrets ?? []
    : isOrg
      ? organizationSecretsResponse?.secrets ?? []
      : projectSecretsResponse?.secrets ?? [];
  const isLoading = isUser
    ? userSecretsLoading
    : isOrg
      ? organizationSecretsLoading
      : projectSecretsLoading;

  const invalidateSecretQueries = () =>
    queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });

  const addMutation = useMutation({
    mutationFn: async ({ key, value }: { key: string; value: string }) => {
      if (isUser) {
        await secretClient.setUserSecret({ key, value });
      } else if (isOrg) {
        await secretClient.setSecret({ orgId: org!.id, key, value });
      } else {
        await secretClient.setProjectSecret({
          orgId: org!.id,
          secretProjectId: projectId,
          key,
          value,
        });
      }
    },
    onSuccess: () => {
      setNewKey("");
      setNewValue("");
      invalidateSecretQueries();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (key: string) => {
      if (isUser) {
        await secretClient.deleteUserSecret({ key });
      } else if (isOrg) {
        await secretClient.deleteSecret({ orgId: org!.id, key });
      } else {
        await secretClient.deleteProjectSecret({
          orgId: org!.id,
          secretProjectId: projectId,
          key,
        });
      }
    },
    onSuccess: invalidateSecretQueries,
  });

  const editMutation = useMutation({
    mutationFn: async ({ key, value }: { key: string; value: string }) => {
      if (isUser) {
        await secretClient.setUserSecret({ key, value });
      } else if (isOrg) {
        await secretClient.setSecret({ orgId: org!.id, key, value });
      } else {
        await secretClient.setProjectSecret({
          orgId: org!.id,
          secretProjectId: projectId,
          key,
          value,
        });
      }
    },
    onSuccess: () => {
      setEditingKey(null);
      setEditValue("");
      invalidateSecretQueries();
    },
  });

  const renameMutation = useMutation({
    mutationFn: async ({ oldKey, newKey }: { oldKey: string; newKey: string }) => {
      if (isUser) {
        await secretClient.renameUserSecret({ key: oldKey, newKey });
      } else if (isOrg) {
        await secretClient.renameSecret({ orgId: org!.id, key: oldKey, newKey });
      } else {
        await secretClient.renameProjectSecret({
          orgId: org!.id,
          secretProjectId: projectId,
          key: oldKey,
          newKey,
        });
      }
    },
    onSuccess: () => {
      setRenamingKey(null);
      setRenameValue("");
      invalidateSecretQueries();
    },
  });

  const mutationError =
    addMutation.error ??
    deleteMutation.error ??
    editMutation.error ??
    renameMutation.error;

  if (!org) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-[color:var(--fg-tertiary)]" />
      </div>
    );
  }

  const title = isUser ? "User Secrets" : isOrg ? "Organization Secrets" : (project?.name ?? projectId);

  return (
    <div className="space-y-3">
      <Link
        to="/dashboard/orgs/$slug/secrets"
        params={{ slug }}
        className="flex items-center gap-1 text-sm text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] no-underline"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to secrets
      </Link>

      <h3 className="text-base font-medium text-[color:var(--fg-primary)]">
        {title}
      </h3>

      {mutationError && (
        <p role="alert" className="text-sm text-[color:var(--destructive)]">
          {errorMessage(mutationError)}
        </p>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-[color:var(--fg-tertiary)]" />
        </div>
      ) : (
        <>
          {secrets.map((s) => (
            <Card key={s.key}>
              <CardContent className="py-3">
                {renamingKey === s.key ? (
                  <form
                    className="flex items-center gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (renameValue && renameValue !== s.key)
                        renameMutation.mutate({ oldKey: s.key, newKey: renameValue });
                    }}
                  >
                    <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                    <Input
                      placeholder="NEW_KEY_NAME"
                      value={renameValue}
                      onChange={(e) =>
                        setRenameValue(
                          e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""),
                        )
                      }
                      className="flex-1 h-8 text-sm font-mono"
                      autoFocus
                    />
                    <Button
                      size="sm"
                      type="submit"
                      disabled={!renameValue || renameValue === s.key || renameMutation.isPending}
                    >
                      {renameMutation.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        "Rename"
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      type="button"
                      onClick={() => { setRenamingKey(null); setRenameValue(""); }}
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  </form>
                ) : editingKey === s.key ? (
                  <form
                    className="flex items-center gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (editValue) editMutation.mutate({ key: s.key, value: editValue });
                    }}
                  >
                    <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                    <span className="text-sm font-mono font-medium text-[color:var(--fg-primary)] truncate">
                      {s.key}
                    </span>
                    <Input
                      type="password"
                      placeholder="new value"
                      value={editValue}
                      onChange={(e) => setEditValue(e.target.value)}
                      className="flex-1 h-8 text-sm"
                      autoFocus
                    />
                    <Button
                      size="sm"
                      type="submit"
                      disabled={!editValue || editMutation.isPending}
                    >
                      {editMutation.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        "Save"
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      type="button"
                      onClick={() => { setEditingKey(null); setEditValue(""); }}
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  </form>
                ) : (
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                      <span className="text-sm font-mono font-medium text-[color:var(--fg-primary)] truncate">
                        {s.key}
                      </span>
                      <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-[var(--success)]/10 text-[var(--success)]">
                        <Check className="h-3 w-3" />
                        Set
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => { setRenamingKey(s.key); setRenameValue(s.key); setEditingKey(null); }}
                        title="Rename key"
                        aria-label={`Rename secret ${s.key}`}
                      >
                        <TextCursorInput className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => { setEditingKey(s.key); setEditValue(""); setRenamingKey(null); }}
                        title="Edit value"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteMutation.mutate(s.key)}
                        disabled={deleteMutation.isPending}
                        className="text-[var(--destructive)]"
                        title="Delete"
                        aria-label={`Delete secret ${s.key}`}
                      >
                        {deleteMutation.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Trash2 className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}

          <Card>
            <CardContent className="py-3">
              <form
                className="flex items-center gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (newKey && newValue) addMutation.mutate({ key: newKey, value: newValue });
                }}
              >
                <Input
                  placeholder="KEY_NAME"
                  value={newKey}
                  onChange={(e) =>
                    setNewKey(
                      e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""),
                    )
                  }
                  className="flex-1 h-8 text-sm font-mono"
                />
                <Input
                  type="password"
                  placeholder="value"
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  className="flex-1 h-8 text-sm"
                />
                <Button
                  size="sm"
                  type="submit"
                  disabled={!newKey || !newValue || addMutation.isPending}
                >
                  {addMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <>
                      <Plus className="h-3.5 w-3.5 mr-1" />
                      Add
                    </>
                  )}
                </Button>
              </form>
            </CardContent>
          </Card>

          {secrets.length === 0 && (
            <p className="text-sm text-[color:var(--fg-tertiary)] text-center py-4">
              No secrets configured. Add one above.
            </p>
          )}
        </>
      )}
    </div>
  );
}
