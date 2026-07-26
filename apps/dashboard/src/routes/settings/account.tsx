import { createFileRoute, redirect } from "@tanstack/react-router";
import { getSession } from "@/lib/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const Route = createFileRoute("/settings/account")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (!session.user.two_factor_enabled && !session.skip_2fa_setup) {
      throw redirect({ to: "/setup-2fa" });
    }
    return { session };
  },
  component: AccountPage,
});

function AccountPage() {
  const { session } = Route.useRouteContext();

  return (
    <div className="container mx-auto px-4 py-8 max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Account Settings</h1>
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>
            Account management is being migrated to the Go backend.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            <p><span className="text-muted-foreground">Name:</span> {session?.user?.name || "N/A"}</p>
            <p><span className="text-muted-foreground">Email:</span> {session?.user?.email || "N/A"}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
