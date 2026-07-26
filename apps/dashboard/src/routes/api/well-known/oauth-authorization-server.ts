import { createFileRoute } from "@tanstack/react-router";

// OAuth Authorization Server metadata is served by the Rust IdP service directly.
export const Route = createFileRoute("/api/well-known/oauth-authorization-server")({
  component: () => null,
});
