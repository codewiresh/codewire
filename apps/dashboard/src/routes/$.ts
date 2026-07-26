import { createFileRoute } from "@tanstack/react-router";

// SPA catch-all — show 404 for unmatched routes
export const Route = createFileRoute("/$")({
  component: () => null,
  notFoundComponent: () => null,
});
