import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { connectTransport, secretServiceQueryKey } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { findOrganizationBySlug } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { FolderKey, KeyRound, Loader2, Plus, Trash2, User } from "lucide-react";

export const Route = createFileRoute("/dashboard/orgs/$slug/secrets/")({
  component: SecretsIndex,
});

function SecretsIndex() {
  const { slug } = Route.useParams();
  const queryClient = useQueryClient();
  const [newName, setNewName] = useState("");

  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const org = findOrganizationBySlug(orgsResponse?.organizations, slug)?.organization;

  const { data: projectsResponse, isLoading } = useConnectQuery(
    SecretService.method.listSecretProjects,
    org?.id ? { orgId: org.id } : undefined,
    { enabled: !!org?.id, transport: connectTransport },
  );
  const projects = projectsResponse?.secretProjects ?? [];

  const createMutation = useConnectMutation(SecretService.method.createSecretProject, {
    transport: connectTransport,
    onSuccess: () => {
      setNewName("");
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });
    },
  });

  const deleteMutation = useConnectMutation(SecretService.method.deleteSecretProject, {
    transport: connectTransport,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey }),
  });

  if (!org || isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-[color:var(--fg-tertiary)]" />
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Organization secrets card */}
      <Link
        to="/dashboard/orgs/$slug/secrets/$projectId"
        params={{ slug, projectId: "organization" }}
        className="block no-underline"
      >
        <Card className="hover:border-[var(--accent)] transition-colors cursor-pointer">
          <CardContent className="py-3">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
              <span className="text-sm font-medium text-[color:var(--fg-primary)]">
                Organization
              </span>
            </div>
          </CardContent>
        </Card>
      </Link>

      {/* User secrets card */}
      <Link
        to="/dashboard/orgs/$slug/secrets/$projectId"
        params={{ slug, projectId: "user" }}
        className="block no-underline"
      >
        <Card className="hover:border-[var(--accent)] transition-colors cursor-pointer">
          <CardContent className="py-3">
            <div className="flex items-center gap-2">
              <User className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
              <span className="text-sm font-medium text-[color:var(--fg-primary)]">
                User
              </span>
              <span className="text-xs text-[color:var(--fg-tertiary)]">
                Your personal credentials, injected into all environments
              </span>
            </div>
          </CardContent>
        </Card>
      </Link>

      {/* Project cards */}
      {projects.map((p) => (
        <Card key={p.id}>
          <CardContent className="py-3">
            <div className="flex items-center justify-between">
              <Link
                to="/dashboard/orgs/$slug/secrets/$projectId"
                params={{ slug, projectId: p.id }}
                className="flex items-center gap-2 min-w-0 flex-1 no-underline"
              >
                <FolderKey className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                <span className="text-sm font-medium text-[color:var(--fg-primary)] truncate">
                  {p.name}
                </span>
                {p.secretCount != null && (
                  <span className="text-xs text-[color:var(--fg-tertiary)]">
                    {p.secretCount.toString()} secret{p.secretCount !== 1n ? "s" : ""}
                  </span>
                )}
              </Link>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  deleteMutation.mutate({
                    orgId: org.id,
                    secretProjectId: p.id,
                  })
                }
                disabled={deleteMutation.isPending}
                className="text-[var(--destructive)]"
              >
                {deleteMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5" />
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}

      {/* Create new project */}
      <Card>
        <CardContent className="py-3">
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (newName.trim()) {
                createMutation.mutate({ orgId: org.id, name: newName.trim() });
              }
            }}
          >
            <Input
              placeholder="New project name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="flex-1 h-8 text-sm"
            />
            <Button
              size="sm"
              type="submit"
              disabled={!newName.trim() || createMutation.isPending}
            >
              {createMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <>
                  <Plus className="h-3.5 w-3.5 mr-1" />
                  Create
                </>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {createMutation.isError && (
        <p role="alert" className="text-sm text-[color:var(--destructive)]">
          {errorMessage(createMutation.error)}
        </p>
      )}

      {projects.length === 0 && (
        <p className="text-sm text-[color:var(--fg-tertiary)] text-center py-4">
          No secret projects yet. Create one above.
        </p>
      )}
    </div>
  );
}
