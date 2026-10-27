// Browser specs whose every test runs against the editable design fixtures
// served by scripts/dev/design-system-server.py, never the dashboard itself.
// scripts/ci/verify/run-design-fixtures.sh runs exactly these through the
// design-fixtures projects; the dashboard projects ignore them.
export const designFixtureSpecs = [
  "ssr-dashboard.account-dialogs.ssr.ts",
  "ssr-dashboard.create-help.ssr.ts",
  "ssr-dashboard.creation-disclosure.ssr.ts",
  "ssr-dashboard.credential-dialogs.ssr.ts",
  "ssr-dashboard.date-picker.ssr.ts",
  "ssr-dashboard.design-system.ssr.ts",
  "ssr-dashboard.durable-terminal.ssr.ts",
  "ssr-dashboard.organization-layout.ssr.ts",
  "ssr-dashboard.personal-api-keys.ssr.ts",
  "ssr-dashboard.personal-secrets.ssr.ts",
  "ssr-dashboard.preview-ports.ssr.ts",
  "ssr-dashboard.repository-picker.ssr.ts",
  "ssr-dashboard.resize.ssr.ts",
  "ssr-dashboard.sandbox-inventory.ssr.ts",
  "ssr-dashboard.sandbox-rail.ssr.ts",
  "ssr-dashboard.setup-progress.ssr.ts",
  "ssr-dashboard.source-recovery.ssr.ts",
  "ssr-dashboard.terminal-renderer.ssr.ts",
] as const;

// Application specs that read the design origin only to stand aside when it is
// set. They are not fixture specs and never run in the design-fixtures projects.
export const designOriginAwareApplicationSpecs = [
  "ssr-dashboard.personal-api-keys-live.ssr.ts",
] as const;

const escaped = (name: string) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const designFixtureSpecPattern = new RegExp(
  `apps/dashboard/e2e/(?:${designFixtureSpecs.map(escaped).join("|")})$`,
);
