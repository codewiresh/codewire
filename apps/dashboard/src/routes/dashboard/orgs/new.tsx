import { createFileRoute, useNavigate, redirect, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useMutation } from "@connectrpc/connect-query";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { getSession } from "@/lib/auth";
import { connectTransport } from "@/lib/connect";
import { errorMessage, fieldViolations } from "@/lib/errors";
import { organizationListQueryKey } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ArrowLeft, Loader2, Building2 } from "lucide-react";

export const Route = createFileRoute("/dashboard/orgs/new")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (!session.user.two_factor_enabled && !session.skip_2fa_setup) {
      throw redirect({ to: "/setup-2fa" });
    }
  },
  component: NewOrgPage,
});

function NewOrgPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const mutation = useMutation(OrganizationService.method.createOrganization, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: organizationListQueryKey });
      navigate({ to: "/dashboard" });
    },
    onError: (err) => {
      const violations = fieldViolations(err);
      setFieldErrors(
        Object.fromEntries(violations.map(({ field, description }) => [field, description])),
      );
      setError(violations.length > 0 ? "" : errorMessage(err));
    },
  });

  // Auto-generate slug from name
  const handleNameChange = (value: string) => {
    setName(value);
    if (!slug || slug === nameToSlug(name)) {
      setSlug(nameToSlug(value));
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setFieldErrors({});

    if (!slug.match(/^[a-z0-9]+(-[a-z0-9]+)*$/)) {
      setError(
        "Slug must contain only lowercase letters, numbers, and hyphens (no leading/trailing hyphens)"
      );
      return;
    }

    if (slug.length < 3 || slug.length > 48) {
      setError("Slug must be between 3 and 48 characters");
      return;
    }

    mutation.mutate({ name, slug });
  };

  return (
    <div className="py-8">
      <div className="max-w-lg mx-auto">
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-2 text-sm text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] mb-6"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Link>

        <Card>
          <CardHeader>
            <div className="h-10 w-10 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center mb-2">
              <Building2 className="h-5 w-5 text-[color:var(--accent)]" />
            </div>
            <CardTitle>Create Organization</CardTitle>
            <CardDescription>
              Organizations group your environments and team members together
            </CardDescription>
          </CardHeader>
          <form onSubmit={handleSubmit}>
            <CardContent className="space-y-6">
              {error && (
                <div className="p-3 rounded-md bg-[var(--destructive)]/10 text-[color:var(--destructive)] text-sm">
                  {error}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="name">Organization Name</Label>
                <Input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => handleNameChange(e.target.value)}
                  placeholder="Acme Corp"
                  required
                />
                {fieldErrors.name && (
                  <p className="text-sm text-[color:var(--destructive)]" role="alert">
                    {fieldErrors.name}
                  </p>
                )}
                <p className="text-sm text-[color:var(--fg-secondary)]">
                  A display name for your organization
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="slug">Slug</Label>
                <Input
                  id="slug"
                  type="text"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value.toLowerCase())}
                  placeholder="acme-corp"
                  pattern="[a-z0-9]+(-[a-z0-9]+)*"
                  required
                />
                {fieldErrors.slug && (
                  <p className="text-sm text-[color:var(--destructive)]" role="alert">
                    {fieldErrors.slug}
                  </p>
                )}
                <p className="text-sm text-[color:var(--fg-secondary)]">
                  URL-safe identifier. Used in organization URLs and API calls.
                </p>
              </div>

              <div className="flex gap-3 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => navigate({ to: "/dashboard" })}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="flex-1"
                  disabled={mutation.isPending}
                >
                  {mutation.isPending && (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  )}
                  {mutation.isPending ? "Creating..." : "Create Organization"}
                </Button>
              </div>
            </CardContent>
          </form>
        </Card>
      </div>
    </div>
  );
}

function nameToSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}
