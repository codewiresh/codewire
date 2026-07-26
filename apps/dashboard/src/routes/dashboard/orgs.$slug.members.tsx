import {
  createFileRoute,
} from "@tanstack/react-router";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import {
  InvitationStatus,
  OrgRole,
  OrganizationService,
} from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { connectTransport } from "@/lib/connect";
import { errorMessage, fieldViolations } from "@/lib/errors";
import {
  findOrganizationBySlug,
  organizationServiceQueryKey,
  orgRoleName,
} from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import {
  Loader2,
  UserPlus,
  Trash2,
  Mail,
  X,
} from "lucide-react";

const ASSIGNMENT_COLORS: Record<string, string> = {
  viewer: "bg-gray-100 text-gray-700 border-gray-300",
  developer: "bg-blue-100 text-blue-700 border-blue-300",
  environments_admin: "bg-green-100 text-green-700 border-green-300",
  sandboxes_admin: "bg-purple-100 text-purple-700 border-purple-300",
  billing_admin: "bg-yellow-100 text-yellow-700 border-yellow-300",
  auditor: "bg-orange-100 text-orange-700 border-orange-300",
  super_admin: "bg-red-100 text-red-700 border-red-300",
};

const ASSIGNMENT_LABELS: Record<string, string> = {
  viewer: "Viewer",
  developer: "Developer",
  environments_admin: "Environments Admin",
  sandboxes_admin: "Sandboxes Admin",
  billing_admin: "Billing Admin",
  auditor: "Auditor",
  super_admin: "Super Admin",
};

const VALID_ASSIGNMENTS = [
  "viewer",
  "developer",
  "environments_admin",
  "sandboxes_admin",
  "billing_admin",
  "auditor",
  "super_admin",
] as const;

export const Route = createFileRoute("/dashboard/orgs/$slug/members")({
  component: OrgMembersPage,
});

function OrgMembersPage() {
  const { slug } = Route.useParams();
  const queryClient = useQueryClient();
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "member">("member");
  const [inviteAssignments, setInviteAssignments] = useState<string[]>(["viewer"]);
  const [inviteError, setInviteError] = useState("");
  const [inviteFieldErrors, setInviteFieldErrors] = useState<Record<string, string>>({});
  const [showInviteForm, setShowInviteForm] = useState(false);

  const { data: orgsResponse, isLoading: orgLoading } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const membership = findOrganizationBySlug(orgsResponse?.organizations, slug);
  const organization = membership?.organization;

  const { data: membersResponse, isLoading: membersLoading } = useConnectQuery(
    OrganizationService.method.listMembers,
    organization ? { orgId: organization.id } : undefined,
    { enabled: !!organization, transport: connectTransport },
  );

  const { data: invitationsResponse } = useConnectQuery(
    OrganizationService.method.listInvitations,
    organization ? { orgId: organization.id } : undefined,
    { enabled: !!organization, transport: connectTransport },
  );

  const inviteMutation = useConnectMutation(OrganizationService.method.createInvitation, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: organizationServiceQueryKey });
      setInviteEmail("");
      setInviteRole("member");
      setInviteAssignments(["viewer"]);
      setShowInviteForm(false);
      setInviteError("");
      setInviteFieldErrors({});
    },
    onError: (err) => {
      const violations = fieldViolations(err);
      setInviteFieldErrors(
        Object.fromEntries(violations.map(({ field, description }) => [field, description])),
      );
      setInviteError(violations.length > 0 ? "" : errorMessage(err));
    },
  });

  const assignmentMutation = useConnectMutation(OrganizationService.method.updateMemberAssignments, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: organizationServiceQueryKey }),
  });

  const removeMutation = useConnectMutation(OrganizationService.method.removeMember, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: organizationServiceQueryKey }),
  });

  const roleChangeMutation = useConnectMutation(OrganizationService.method.updateMemberRole, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: organizationServiceQueryKey }),
  });

  const revokeMutation = useConnectMutation(OrganizationService.method.revokeInvitation, {
    transport: connectTransport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: organizationServiceQueryKey }),
  });

  if (orgLoading || membersLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-secondary)]" />
      </div>
    );
  }

  if (!membership || !organization) {
    return null;
  }

  const members = membersResponse?.members ?? [];
  const invitations = (invitationsResponse?.invitations ?? []).filter(
    (inv) => inv.status === InvitationStatus.PENDING,
  );
  const isOwner = membership.role === OrgRole.OWNER;

  return (
    <div>
      <div className="max-w-2xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <p className="text-[color:var(--fg-secondary)] text-sm">
            Manage members and invitations
          </p>
          <Button
            className="gap-2"
            onClick={() => setShowInviteForm(!showInviteForm)}
          >
            <UserPlus className="h-4 w-4" />
            Invite Member
          </Button>
        </div>

        {/* Invite Form */}
        {showInviteForm && (
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="text-base">Invite Member</CardTitle>
              <CardDescription>
                Send an invitation to join this organization
              </CardDescription>
            </CardHeader>
            <CardContent>
              {inviteError && (
                <div className="p-3 rounded-md bg-[var(--destructive)]/10 text-[color:var(--destructive)] text-sm mb-4">
                  {inviteError}
                </div>
              )}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  inviteMutation.mutate({
                    orgId: organization.id,
                    email: inviteEmail,
                    role: inviteRole === "admin" ? OrgRole.ADMIN : OrgRole.MEMBER,
                    assignments: inviteAssignments,
                  });
                }}
                className="flex flex-col gap-3"
              >
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1">
                    <Input
                      type="email"
                      value={inviteEmail}
                      onChange={(e) => {
                        setInviteEmail(e.target.value);
                        setInviteFieldErrors((current) => ({ ...current, email: "" }));
                      }}
                      placeholder="colleague@example.com"
                      required
                    />
                    {inviteFieldErrors.email && (
                      <p className="mt-1 text-sm text-[color:var(--destructive)]" role="alert">
                        {inviteFieldErrors.email}
                      </p>
                    )}
                  </div>
                  <select
                    value={inviteRole}
                    onChange={(e) =>
                      setInviteRole(e.target.value as "admin" | "member")
                    }
                    className="rounded-md border border-[var(--border)] bg-[var(--bg-base)] px-3 py-2 text-sm"
                  >
                    <option value="member">Member</option>
                    <option value="admin">Admin</option>
                  </select>
                  <Button type="submit" disabled={inviteMutation.isPending}>
                    {inviteMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      "Send Invite"
                    )}
                  </Button>
                </div>
                <div>
                  <p className="text-xs text-[color:var(--fg-secondary)] mb-1.5">Assignments</p>
                  <div className="flex flex-wrap gap-1.5">
                    {VALID_ASSIGNMENTS.map((a) => (
                      <label
                        key={a}
                        className="flex items-center gap-1.5 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={inviteAssignments.includes(a)}
                          disabled={a === "viewer"}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setInviteAssignments((prev) => [...prev, a]);
                            } else {
                              setInviteAssignments((prev) => prev.filter((x) => x !== a));
                            }
                          }}
                          className="h-3.5 w-3.5 rounded border-[var(--border)]"
                        />
                        <Badge variant="outline" className={`text-xs ${ASSIGNMENT_COLORS[a] || ""}`}>
                          {ASSIGNMENT_LABELS[a] || a}
                        </Badge>
                      </label>
                    ))}
                  </div>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Members List */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-base">
              Members ({members.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y">
              {members.map((member) => {
                const memberAssignments = member.assignments;
                return (
                  <div
                    key={member.id}
                    className="flex items-center justify-between px-6 py-3"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      {member.image ? (
                        <img
                          src={member.image}
                          alt=""
                          className="h-8 w-8 rounded-full shrink-0"
                        />
                      ) : (
                        <div className="h-8 w-8 rounded-full bg-[var(--bg-surface-hover)] flex items-center justify-center text-xs font-medium shrink-0">
                          {(member.name || member.email || "?")
                            .charAt(0)
                            .toUpperCase()}
                        </div>
                      )}
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-[color:var(--fg-primary)]">
                          {member.name || member.email}
                        </div>
                        {member.name && (
                          <div className="text-xs text-[color:var(--fg-secondary)]">
                            {member.email}
                          </div>
                        )}
                        {memberAssignments.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {memberAssignments.map((a) => (
                              <Badge
                                key={a}
                                variant="outline"
                                className={`text-[10px] px-1.5 py-0 leading-4 ${ASSIGNMENT_COLORS[a] || ""}`}
                              >
                                {ASSIGNMENT_LABELS[a] || a}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {isOwner && member.role !== OrgRole.OWNER ? (
                        <>
                          <select
                            value={orgRoleName(member.role)}
                            onChange={(e) =>
                              roleChangeMutation.mutate({
                                orgId: organization.id,
                                userId: member.userId,
                                role: e.target.value === "admin" ? OrgRole.ADMIN : OrgRole.MEMBER,
                              })
                            }
                            className="rounded-md border border-[var(--border)] bg-[var(--bg-base)] px-2 py-1 text-xs"
                          >
                            <option value="member">Member</option>
                            <option value="admin">Admin</option>
                          </select>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="outline" size="sm" className="text-xs h-7 px-2">
                                Assignments
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-52">
                              <DropdownMenuLabel className="text-xs">Assignments</DropdownMenuLabel>
                              <DropdownMenuSeparator />
                              {VALID_ASSIGNMENTS.map((a) => (
                                <DropdownMenuCheckboxItem
                                  key={a}
                                  checked={memberAssignments.includes(a)}
                                  disabled={a === "viewer"}
                                  onCheckedChange={(checked) => {
                                    const next = checked
                                      ? [...memberAssignments, a]
                                      : memberAssignments.filter((x) => x !== a);
                                    assignmentMutation.mutate({
                                      orgId: organization.id,
                                      memberId: member.id,
                                      assignments: next,
                                    });
                                  }}
                                  onSelect={(e) => e.preventDefault()}
                                >
                                  <span className={`text-xs ${ASSIGNMENT_COLORS[a] || ""} rounded px-1`}>
                                    {ASSIGNMENT_LABELS[a] || a}
                                  </span>
                                </DropdownMenuCheckboxItem>
                              ))}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </>
                      ) : (
                        <Badge
                          variant={
                            member.role === OrgRole.OWNER ? "default" : "outline"
                          }
                          className="text-xs"
                        >
                          {orgRoleName(member.role)}
                        </Badge>
                      )}
                      {member.role !== OrgRole.OWNER && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            removeMutation.mutate({
                              orgId: organization.id,
                              userId: member.userId,
                            })
                          }
                          disabled={removeMutation.isPending}
                          className="text-[color:var(--destructive)] hover:text-[color:var(--destructive)]"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Pending Invitations */}
        {invitations.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                Pending Invitations ({invitations.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y">
                {invitations.map((inv) => (
                  <div
                    key={inv.id}
                    className="flex items-center justify-between px-6 py-3"
                  >
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded-full bg-[var(--bg-surface-hover)] flex items-center justify-center">
                        <Mail className="h-4 w-4 text-[color:var(--fg-secondary)]" />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-[color:var(--fg-primary)]">{inv.email}</div>
                        <div className="text-xs text-[color:var(--fg-secondary)]">
                          Invited by {inv.inviterName} &middot; Expires{" "}
                          {inv.expiresAt
                            ? timestampDate(inv.expiresAt).toLocaleDateString()
                            : ""}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">
                        {orgRoleName(inv.role)}
                      </Badge>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          revokeMutation.mutate({ invitationId: inv.id, orgId: organization.id })
                        }
                        disabled={revokeMutation.isPending}
                        className="text-[color:var(--destructive)] hover:text-[color:var(--destructive)]"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
