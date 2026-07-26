import { createFileRoute } from "@tanstack/react-router";

// OpenID Configuration is served by the Rust IdP service directly.
export const Route = createFileRoute("/api/well-known/openid-configuration")({
  component: () => null,
});
