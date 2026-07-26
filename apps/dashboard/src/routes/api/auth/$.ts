import { createFileRoute } from "@tanstack/react-router";

// Auth API is handled by the Rust IdP service directly; no SPA route.
export const Route = createFileRoute("/api/auth/$")({
  component: () => null,
});
