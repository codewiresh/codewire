import { createFileRoute } from "@tanstack/react-router";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import {
  BillingService,
  type BillingEvent,
} from "@codewire/proto-ts/gen/codewire/console/v1/billing_pb";
import { OrgRole, OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { connectTransport } from "@/lib/connect";
import { findOrganizationBySlug } from "@/lib/organizations";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  AlertCircle,
  CreditCard,
  Download,
  ExternalLink,
  Loader2,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/orgs/$slug/billing")({
  component: BillingPage,
});

function formatCents(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
  }).format(cents / 100);
}

function formatDate(timestamp: Timestamp | undefined): string {
  if (!timestamp) return "—";
  return timestampDate(timestamp).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function statusVariant(status: string): "default" | "secondary" | "success" | "warning" | "destructive" {
  switch (status) {
    case "active":
      return "success";
    case "trialing":
      return "warning";
    case "past_due":
    case "unpaid":
    case "incomplete":
      return "destructive";
    default:
      return "secondary";
  }
}

function BillingPage() {
  const { slug } = Route.useParams();
  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const membership = findOrganizationBySlug(orgsResponse?.organizations, slug);
  const org = membership?.organization;
  const orgId = org?.id ?? "";

  const { data: billing, isLoading: billingLoading } = useConnectQuery(
    BillingService.method.getBillingOverview,
    orgId ? { orgId } : undefined,
    {
      enabled: !!orgId,
      transport: connectTransport,
    },
  );
  const { data: envUsage } = useConnectQuery(
    BillingService.method.getEnvironmentUsage,
    orgId ? { orgId } : undefined,
    {
      enabled: !!orgId,
      transport: connectTransport,
    },
  );
  const { data: invoicesResponse } = useConnectQuery(
    BillingService.method.listInvoices,
    orgId ? { orgId } : undefined,
    {
      enabled: !!orgId,
      transport: connectTransport,
    },
  );
  const { data: billingEventsResponse } = useConnectQuery(
    BillingService.method.listBillingEvents,
    orgId ? { orgId } : undefined,
    {
      enabled: !!orgId,
      transport: connectTransport,
    },
  );
  const invoices = invoicesResponse?.invoices;
  const billingEvents = billingEventsResponse?.events;

  const portalMutation = useConnectMutation(BillingService.method.createPortalSession, {
    transport: connectTransport,
    onSuccess: ({ portalUrl }) => {
      if (portalUrl) window.location.href = portalUrl;
    },
  });

  const setupMutation = useConnectMutation(BillingService.method.createSetupSession, {
    transport: connectTransport,
    onSuccess: ({ checkoutUrl }) => {
      if (checkoutUrl) window.location.href = checkoutUrl;
    },
  });

  if (!org || billingLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-secondary)]" />
      </div>
    );
  }

  const isAdmin = membership?.role === OrgRole.OWNER || membership?.role === OrgRole.ADMIN;

  return (
    <div className="space-y-6">
      {!billing?.billingEnabled && (
        <Card className="border-dashed">
          <CardContent className="py-6 text-center">
            <p className="text-sm text-[color:var(--fg-secondary)]">
              Billing is not configured. Environments run freely in dev mode.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Plan */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Plan</CardTitle>
          <CardDescription>Organization-level billing.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{billing?.planDisplayName || "No plan"}</Badge>
                {billing?.status && (
                  <Badge variant={statusVariant(billing.status)}>{billing.status}</Badge>
                )}
              </div>
              {billing?.trialEnd && billing.status === "trialing" && (
                <p className="text-sm text-[color:var(--fg-secondary)]">
                  Trial ends {formatDate(billing.trialEnd)}
                </p>
              )}
              {billing?.currentPeriodEnd && (
                <p className="text-sm text-[color:var(--fg-secondary)]">
                  Current period ends {formatDate(billing.currentPeriodEnd)}
                </p>
              )}
            </div>
            {isAdmin && billing?.billingEnabled && (
              <div className="flex flex-col gap-2 md:items-end">
                {billing.hasPaymentMethod ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      portalMutation.mutate({ orgId, returnUrl: window.location.href })
                    }
                    disabled={portalMutation.isPending}
                  >
                    <CreditCard className="h-4 w-4 mr-1.5" />
                    Manage in Stripe
                    <ExternalLink className="h-3 w-3 ml-1.5" />
                  </Button>
                ) : (
                  <Button
                    type="button"
                    size="sm"
                    onClick={() =>
                      setupMutation.mutate({
                        orgId,
                        successUrl: window.location.href,
                        cancelUrl: window.location.href,
                      })
                    }
                    disabled={setupMutation.isPending}
                  >
                    <AlertCircle className="h-4 w-4 mr-1.5" />
                    Add payment method
                  </Button>
                )}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Environment Usage */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Environment Usage</CardTitle>
          <CardDescription>Per-second compute billing for this month.</CardDescription>
        </CardHeader>
        <CardContent>
          {envUsage?.currentMonth ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="rounded-lg border p-3">
                  <div className="text-xs text-[color:var(--fg-secondary)]">Current Month</div>
                  <div className="text-lg font-semibold">{formatCents(envUsage.currentMonth.costCents)}</div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-xs text-[color:var(--fg-secondary)]">CPU Hours</div>
                  <div className="text-lg font-semibold">
                    {envUsage.currentMonth.cpuHours.toFixed(1)}
                    {envUsage.currentMonth.includedCpuHours > 0 && (
                      <span className="text-xs text-[color:var(--fg-secondary)] ml-1">
                        / {envUsage.currentMonth.includedCpuHours}
                      </span>
                    )}
                  </div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-xs text-[color:var(--fg-secondary)]">Memory GiB-Hours</div>
                  <div className="text-lg font-semibold">
                    {envUsage.currentMonth.memGbHours.toFixed(1)}
                    {envUsage.currentMonth.includedMemGbHours > 0 && (
                      <span className="text-xs text-[color:var(--fg-secondary)] ml-1">
                        / {envUsage.currentMonth.includedMemGbHours}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              {envUsage.perEnvironment.length > 0 && (
                <div className="space-y-1.5 pt-2 border-t border-[var(--border-subtle)]">
                  <div className="text-xs text-[color:var(--fg-secondary)] mb-2">By environment</div>
                  {envUsage.perEnvironment.map((env) => (
                    <div
                      key={env.id}
                      className="flex items-center justify-between text-sm py-1"
                    >
                      <span className="text-[color:var(--fg-primary)]">{env.name}</span>
                      <span className="text-[color:var(--fg-secondary)]">
                        {formatCents(env.costCents)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-[color:var(--fg-secondary)]">No usage yet this month.</p>
          )}
        </CardContent>
      </Card>

      {/* Invoices */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Invoices</CardTitle>
          <CardDescription>Past billing periods.</CardDescription>
        </CardHeader>
        <CardContent>
          {invoices && invoices.length > 0 ? (
            <div className="space-y-1.5">
              {invoices.map((invoice) => (
                <div
                  key={invoice.id}
                  className="flex items-center justify-between rounded-md border px-3 py-2"
                >
                  <div className="text-sm">
                    <div className="text-[color:var(--fg-primary)]">
                      {formatDate(invoice.periodStart)} – {formatDate(invoice.periodEnd)}
                    </div>
                    <div className="text-xs text-[color:var(--fg-secondary)]">
                      {formatCents(invoice.amountPaid, invoice.currency)} · {invoice.status}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {invoice.hostedInvoiceUrl && (
                      <a
                        href={invoice.hostedInvoiceUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)]"
                      >
                        <ExternalLink className="h-4 w-4" />
                      </a>
                    )}
                    {invoice.invoicePdf && (
                      <a
                        href={invoice.invoicePdf}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)]"
                      >
                        <Download className="h-4 w-4" />
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[color:var(--fg-secondary)]">No invoices yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Recent billing events */}
      {billingEvents && billingEvents.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5">
              {billingEvents.slice(0, 10).map((event: BillingEvent) => (
                <div
                  key={event.id}
                  className="flex items-center justify-between text-sm py-1"
                >
                  <div>
                    <div className="text-[color:var(--fg-primary)]">{event.eventType}</div>
                    <div className="text-xs text-[color:var(--fg-secondary)]">
                      {formatDate(event.createdAt)}
                    </div>
                  </div>
                  {event.amountCents != null && (
                    <span className="text-[color:var(--fg-secondary)]">
                      {formatCents(event.amountCents)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
