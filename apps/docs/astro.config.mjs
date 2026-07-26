import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  base: "/docs",
  trailingSlash: "never",
  server: { host: "0.0.0.0", allowedHosts: ["docs", "localhost"] },
  integrations: [
    starlight({
      title: "Codewire",
      favicon: "/favicon.svg",
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
      },
      customCss: ["./src/styles/custom.css"],
      disable404Route: true,
      sidebar: [
        {
          label: "Documentation",
          items: [
            {
              label: "Overview",
              items: [
                { label: "What is Codewire?", slug: "" },
                { label: "Quickstart", slug: "quickstart" },
              ],
            },
            {
              label: "Getting Started",
              items: [
                { label: "Create Account", slug: "getting-started/create-account" },
                { label: "Sign In", slug: "getting-started/sign-in" },
                { label: "Create Organization", slug: "getting-started/create-organization" },
                { label: "Create Your First Environment", slug: "getting-started/create-your-first-environment" },
                { label: "Navigate the Dashboard", slug: "getting-started/navigate-the-dashboard" },
                { label: "Connect to an Environment", slug: "getting-started/connect-to-an-environment" },
              ],
            },
            {
              label: "Organizations",
              items: [
                { label: "Overview", slug: "organizations/overview" },
                { label: "Manage Members", slug: "organizations/manage-members" },
                { label: "Invite Members", slug: "organizations/invite-members" },
                { label: "Accept Invitation", slug: "organizations/accept-invitation" },
                { label: "Billing", slug: "organizations/billing" },
                { label: "Secrets", slug: "organizations/secrets" },
              ],
            },
            {
              label: "Environments",
              items: [
                { label: "Overview", slug: "environments/overview" },
                { label: "Create Environment", slug: "environments/create-environment" },
                { label: "Manage Environments", slug: "environments/manage-environments" },
                { label: "Connect", slug: "environments/connect" },
              ],
            },
            {
              label: "Settings",
              items: [
                { label: "GitHub Integration", slug: "settings/github-integration" },
                { label: "Security", slug: "settings/security" },
              ],
            },
            {
              label: "Reference",
              items: [
                { label: "Environment Statuses", slug: "reference/environment-statuses" },
                { label: "Provisioning Events", slug: "reference/provisioning-events" },
                { label: "Subscription Plans", slug: "reference/subscription-plans" },
                { label: "FAQ", slug: "reference/faq" },
              ],
            },
          ],
        },
        {
          label: "CLI",
          items: [
            { label: "Overview", slug: "cli/overview" },
            { label: "Platform", slug: "cli/platform" },
            { label: "Sessions", slug: "cli/sessions" },
            { label: "Mesh", slug: "cli/mesh" },
            { label: "Configuration", slug: "cli/configuration" },
          ],
        },
      ],
    }),
  ],
});
