import { createFileRoute } from "@tanstack/react-router";

// GitHub App callback is handled by the Go server directly
export const Route = createFileRoute("/api/github-app/callback")({
  component: () => null,
});
