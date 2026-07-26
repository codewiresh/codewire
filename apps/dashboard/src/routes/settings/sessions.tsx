import { createFileRoute, redirect } from "@tanstack/react-router";
import { getSession } from "@/lib/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const Route = createFileRoute("/settings/sessions")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (!session.user.two_factor_enabled && !session.skip_2fa_setup) {
      throw redirect({ to: "/setup-2fa" });
    }
  },
  component: SessionsPage,
});

function SessionsPage() {
  return (
    <div className="container mx-auto px-4 py-8 max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Active Sessions</h1>
      <Card>
        <CardHeader>
          <CardTitle>Sessions</CardTitle>
          <CardDescription>
            Session management is being migrated to the Go backend.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            View and revoke active sessions once the Go session management endpoints are complete.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
