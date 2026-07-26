import { createFileRoute, Outlet } from "@tanstack/react-router";

export const Route = createFileRoute("/dashboard/orgs/$slug/secrets")({
  component: () => <Outlet />,
});
