import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { type OrgInvitation } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { getSession } from "@/lib/auth";
import { organizationClient } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { orgRoleName } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Code2, Loader2, CheckCircle2, XCircle, Mail, Users } from "lucide-react";

export const Route = createFileRoute("/accept-invite")({
  validateSearch: (search: Record<string, unknown>) => ({
    token: (search.token as string) || "",
  }),
  beforeLoad: async () => {
    const session = await getSession();
    return { session };
  },
  component: AcceptInvitePage,
});

function AcceptInvitePage() {
  const { token } = Route.useSearch();
  const { session } = Route.useRouteContext();
  const navigate = useNavigate();

  const [invitation, setInvitation] = useState<OrgInvitation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [accepting, setAccepting] = useState(false);
  const [accepted, setAccepted] = useState(false);

  // Fetch invitation details
  useEffect(() => {
    async function fetchInvitation() {
      if (!token) {
        setError("No invitation token provided");
        setLoading(false);
        return;
      }

      try {
        const result = await organizationClient.getInvitationByToken({ token });
        setInvitation(result.invitation ?? null);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    }

    fetchInvitation();
  }, [token]);

  const handleAccept = async () => {
    if (!token) return;

    setAccepting(true);
    setError(null);

    try {
      await organizationClient.acceptInvitation({ token });
      setAccepted(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setAccepting(false);
    }
  };

  // Show loading state
  if (loading) {
    return (
      <Card className="w-full max-w-md">
        <CardContent className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-secondary)]" />
        </CardContent>
      </Card>
    );
  }

  // Show error state
  if (error && !invitation) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <div className="h-12 w-12 rounded-lg bg-destructive/10 flex items-center justify-center">
              <XCircle className="h-6 w-6 text-destructive" />
            </div>
          </div>
          <CardTitle className="text-2xl">Invalid Invitation</CardTitle>
          <CardDescription>{error}</CardDescription>
        </CardHeader>
        <CardFooter className="flex justify-center">
          <Link to="/">
            <Button variant="outline">Go to Homepage</Button>
          </Link>
        </CardFooter>
      </Card>
    );
  }

  // Show success state
  if (accepted) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <div className="h-12 w-12 rounded-lg bg-[var(--success)]/10 flex items-center justify-center">
              <CheckCircle2 className="h-6 w-6 text-[color:var(--success)]" />
            </div>
          </div>
          <CardTitle className="text-2xl">Welcome to the Team!</CardTitle>
          <CardDescription>
            You've successfully joined{" "}
            <span className="font-medium">{invitation?.orgName}</span>
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex justify-center">
          <Button onClick={() => navigate({ to: "/dashboard" })}>
            Go to Dashboard
          </Button>
        </CardFooter>
      </Card>
    );
  }

  // Show login prompt if not authenticated
  if (!session?.user) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
              <Mail className="h-6 w-6 text-primary" />
            </div>
          </div>
          <CardTitle className="text-2xl">You've Been Invited!</CardTitle>
          <CardDescription>
            {invitation?.inviterName} has invited you to join{" "}
            <span className="font-medium">{invitation?.orgName}</span> as a{" "}
            <span className="font-medium">{invitation ? orgRoleName(invitation.role) : "member"}</span>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)]/50 p-4 space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <Users className="h-4 w-4 text-[color:var(--fg-secondary)]" />
              <span className="text-[color:var(--fg-secondary)]">Team:</span>
              <span className="font-medium">{invitation?.orgName}</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Mail className="h-4 w-4 text-[color:var(--fg-secondary)]" />
              <span className="text-[color:var(--fg-secondary)]">Invited email:</span>
              <span className="font-medium">{invitation?.email}</span>
            </div>
          </div>
          <p className="text-sm text-[color:var(--fg-secondary)] text-center">
            Please sign in or create an account with{" "}
            <span className="font-medium">{invitation?.email}</span> to accept this
            invitation.
          </p>
        </CardContent>
        <CardFooter className="flex flex-col gap-3">
          <Link to="/login" className="w-full">
            <Button className="w-full">Sign In</Button>
          </Link>
          <Link to="/signup" className="w-full">
            <Button variant="outline" className="w-full">
              Create Account
            </Button>
          </Link>
        </CardFooter>
      </Card>
    );
  }

  // Check if user's email matches invitation
  const emailMatches =
    session.user.email?.toLowerCase() === invitation?.email.toLowerCase();

  // Show invitation details and accept button
  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
            <Code2 className="h-6 w-6 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl">Join {invitation?.orgName}</CardTitle>
        <CardDescription>
          {invitation?.inviterName} has invited you to join as a{" "}
          <span className="font-medium">{invitation ? orgRoleName(invitation.role) : "member"}</span>.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
            {error}
          </div>
        )}

        {!emailMatches && (
          <div className="p-3 rounded-md bg-yellow-500/10 text-yellow-400 text-sm">
            <p className="font-medium">Email mismatch</p>
            <p className="mt-1">
              This invitation was sent to{" "}
              <span className="font-medium">{invitation?.email}</span>, but you're
              signed in as <span className="font-medium">{session.user.email}</span>.
            </p>
            <p className="mt-1">
              Please sign in with the correct email address to accept this invitation.
            </p>
          </div>
        )}

        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)]/50 p-4 space-y-2">
          <div className="flex items-center gap-2 text-sm">
            <Users className="h-4 w-4 text-[color:var(--fg-secondary)]" />
            <span className="text-[color:var(--fg-secondary)]">Team:</span>
            <span className="font-medium">{invitation?.orgName}</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Mail className="h-4 w-4 text-[color:var(--fg-secondary)]" />
            <span className="text-[color:var(--fg-secondary)]">Your role:</span>
            <span className="font-medium capitalize">
              {invitation ? orgRoleName(invitation.role) : "member"}
            </span>
          </div>
        </div>
      </CardContent>
      <CardFooter className="flex flex-col gap-3">
        <Button
          className="w-full"
          onClick={handleAccept}
          disabled={accepting || !emailMatches}
        >
          {accepting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {accepting ? "Joining..." : "Accept Invitation"}
        </Button>
        <Link to="/dashboard" className="w-full">
          <Button variant="outline" className="w-full">
            Cancel
          </Button>
        </Link>
      </CardFooter>
    </Card>
  );
}
