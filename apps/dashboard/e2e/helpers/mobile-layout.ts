// Dashboard specs with a test that checks the mobile layout: a mobile-only
// test, a branch on `isMobile`, or a layout check that runs in both viewports.
// Only these run in the dashboard-ssr-mobile project. Every other dashboard
// spec skips all of its tests on mobile, so running it there only started
// browsers to skip them (#2974). mobile-layout.test.ts keeps this list honest.
export const mobileLayoutSpecs = [
  "ssr-dashboard.billing-admin.ssr.ts",
  "ssr-dashboard.environments.ssr.ts",
  "ssr-dashboard.governance.ssr.ts",
  "ssr-dashboard.management-visual.ssr.ts",
  "ssr-dashboard.organization.ssr.ts",
  "ssr-dashboard.personal-api-keys-live.ssr.ts",
  "ssr-dashboard.read.ssr.ts",
  "ssr-dashboard.routes.ssr.ts",
  "ssr-dashboard.secrets-presets.ssr.ts",
] as const;

const escaped = (name: string) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const mobileLayoutSpecPattern = new RegExp(
  `apps/dashboard/e2e/(?:${mobileLayoutSpecs.map(escaped).join("|")})$`,
);
