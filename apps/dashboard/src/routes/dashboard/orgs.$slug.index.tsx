import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/dashboard/orgs/$slug/")({
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/dashboard/orgs/$slug/environments",
      params: { slug: params.slug },
      search: { create: false },
    });
  },
});
