import { createFileRoute, redirect } from "@tanstack/react-router";
import { getSession } from "@/lib/auth";
import { DashboardLayout } from "@/components/dashboard-layout";

export const Route = createFileRoute("/dashboard")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (!session.user.two_factor_enabled && !session.skip_2fa_setup) {
      throw redirect({ to: "/setup-2fa" });
    }
    return {
      session,
      isAdmin: !!session.user.is_admin,
      userName: session.user.name || session.user.email,
    };
  },
  component: DashboardRoute,
});

function DashboardRoute() {
  const { isAdmin, userName } = Route.useRouteContext();
  return <DashboardLayout isAdmin={isAdmin} userName={userName} />;
}
