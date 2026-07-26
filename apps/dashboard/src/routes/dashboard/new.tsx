import { createFileRoute, redirect } from "@tanstack/react-router";

// Legacy tenant creation — redirect to dashboard
export const Route = createFileRoute("/dashboard/new")({
  beforeLoad: () => {
    throw redirect({ to: "/dashboard" });
  },
  component: () => null,
});
