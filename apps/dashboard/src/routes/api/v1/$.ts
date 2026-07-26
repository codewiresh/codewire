import { createFileRoute } from "@tanstack/react-router";

// API v1 is handled by the platform edge services directly; no SPA route.
export const Route = createFileRoute("/api/v1/$")({
  component: () => null,
});
