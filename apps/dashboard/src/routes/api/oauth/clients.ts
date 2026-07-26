import { createFileRoute } from "@tanstack/react-router";

// OAuth client management is handled by the Go server directly
export const Route = createFileRoute("/api/oauth/clients")({
  component: () => null,
});
