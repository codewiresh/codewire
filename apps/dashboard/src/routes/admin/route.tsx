import { createFileRoute, redirect } from "@tanstack/react-router";
import { getSession } from "@/lib/auth";
import { DashboardLayout } from "@/components/dashboard-layout";

export const Route = createFileRoute("/admin")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (!session.user.two_factor_enabled && !session.skip_2fa_setup) {
      throw redirect({ to: "/setup-2fa" });
    }
    if (!session.user.is_admin) {
      throw redirect({ to: "/dashboard" });
    }
    return {
      session,
      isAdmin: true,
      userName: session.user.name || session.user.email,
    };
  },
  component: AdminRoute,
});

function AdminRoute() {
  const { userName } = Route.useRouteContext();
  return <DashboardLayout isAdmin={true} userName={userName} />;
}
