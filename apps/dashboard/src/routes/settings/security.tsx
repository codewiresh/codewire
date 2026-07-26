import { createFileRoute, redirect } from "@tanstack/react-router";
import { getSession } from "@/lib/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const Route = createFileRoute("/settings/security")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (!session.user.two_factor_enabled && !session.skip_2fa_setup) {
      throw redirect({ to: "/setup-2fa" });
    }
  },
  component: SecurityPage,
});

function SecurityPage() {
  return (
    <div className="container mx-auto px-4 py-8 max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Security Settings</h1>
      <Card>
        <CardHeader>
          <CardTitle>Two-Factor Authentication</CardTitle>
          <CardDescription>
            Security settings are being migrated to the Go backend.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Password changes, 2FA setup, and other security features will be available once the Go auth endpoints are complete.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
