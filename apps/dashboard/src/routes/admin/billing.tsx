import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  createConnectQueryKey,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import {
  BillingCatalogService,
  type CatalogPlan,
  type CatalogPrice,
  type CatalogSetting,
  type MigrationRun,
  type PreviewSubscriptionMigrationResponse,
} from "@codewire/proto-ts/gen/codewire/admin/v1/billing_catalog_pb";
import { billingCatalogClient, connectTransport } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Loader2, Save } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/admin/billing")({
  component: AdminBillingCatalogPage,
});

type AdminBillingCatalogPlan = {
  resource_type: string;
  plan_key: string;
  display_name: string;
  price_cents: number;
  included_devs: number;
  max_concurrent_ws: number;
  max_team_members: number;
  storage_gb: number;
  is_contact_us: boolean;
  is_admin_only: boolean;
  included_cpu_hours: number;
  included_mem_gb_hours: number;
  included_disk_gb_hours: number;
  cpu_overage_cents: number;
  mem_overage_cents: number;
  disk_overage_cents: number;
  archived: boolean;
};

type AdminBillingCatalogPrice = {
  resource_type: string;
  plan_key: string;
  stripe_mode: string;
  price_kind: string;
  stripe_price_id: string;
  archived: boolean;
};

type AdminBillingCatalogSetting = {
  setting_key: string;
  int_value: number;
};

type AdminBillingCatalogMigrationPreview = {
  resource_type: string;
  source_plan_key: string;
  target_plan_key: string;
  target_stripe_price_id: string;
  matching_count: number;
  candidate_count: number;
  already_on_target: number;
  samples: {
    scope: string;
    org_slug: string;
    stripe_subscription_id: string;
    status: string;
    current_plan_key: string;
    current_stripe_price_id?: string;
  }[];
};

type AdminBillingCatalogMigrationRun = {
  id: string;
  resource_type: string;
  source_plan_key: string;
  target_plan_key: string;
  proration_behavior: string;
  migrated_count: number;
  skipped_count: number;
  failed_count: number;
  created_by?: string;
  created_at: string;
};

const billingCatalogQueryKey = createConnectQueryKey({
  schema: BillingCatalogService.method.getCatalog,
  transport: connectTransport,
  cardinality: undefined,
});

const billingCatalogMigrationsQueryKey = createConnectQueryKey({
  schema: BillingCatalogService.method.listSubscriptionMigrations,
  transport: connectTransport,
  cardinality: undefined,
});

function planFromProto({
  resourceType,
  planKey,
  plan,
  archived,
}: CatalogPlan): AdminBillingCatalogPlan {
  return {
    resource_type: resourceType,
    plan_key: planKey,
    display_name: plan?.displayName ?? "",
    price_cents: plan?.priceCents ?? 0,
    included_devs: plan?.includedDevs ?? 0,
    max_concurrent_ws: plan?.maxConcurrentWs ?? 0,
    max_team_members: plan?.maxTeamMembers ?? 0,
    storage_gb: plan?.storageGb ?? 0,
    is_contact_us: plan?.isContactUs ?? false,
    is_admin_only: plan?.isAdminOnly ?? false,
    included_cpu_hours: plan?.includedCpuHours ?? 0,
    included_mem_gb_hours: plan?.includedMemGbHours ?? 0,
    included_disk_gb_hours: plan?.includedDiskGbHours ?? 0,
    cpu_overage_cents: plan?.cpuOverageCents ?? 0,
    mem_overage_cents: plan?.memOverageCents ?? 0,
    disk_overage_cents: plan?.diskOverageCents ?? 0,
    archived,
  };
}

function priceFromProto({
  resourceType,
  planKey,
  stripeMode,
  priceKind,
  stripePriceId,
  archived,
}: CatalogPrice): AdminBillingCatalogPrice {
  return {
    resource_type: resourceType,
    plan_key: planKey,
    stripe_mode: stripeMode,
    price_kind: priceKind,
    stripe_price_id: stripePriceId,
    archived,
  };
}

function settingFromProto({ settingKey, intValue }: CatalogSetting): AdminBillingCatalogSetting {
  return { setting_key: settingKey, int_value: intValue };
}

function planSpecFromDraft(plan: AdminBillingCatalogPlan) {
  return {
    displayName: plan.display_name,
    priceCents: plan.price_cents,
    includedDevs: plan.included_devs,
    maxConcurrentWs: plan.max_concurrent_ws,
    maxTeamMembers: plan.max_team_members,
    storageGb: plan.storage_gb,
    isContactUs: plan.is_contact_us,
    isAdminOnly: plan.is_admin_only,
    includedCpuHours: plan.included_cpu_hours,
    includedMemGbHours: plan.included_mem_gb_hours,
    includedDiskGbHours: plan.included_disk_gb_hours,
    cpuOverageCents: plan.cpu_overage_cents,
    memOverageCents: plan.mem_overage_cents,
    diskOverageCents: plan.disk_overage_cents,
  };
}

function migrationPreviewFromProto(
  preview: PreviewSubscriptionMigrationResponse,
): AdminBillingCatalogMigrationPreview {
  return {
    resource_type: preview.resourceType,
    source_plan_key: preview.sourcePlanKey,
    target_plan_key: preview.targetPlanKey,
    target_stripe_price_id: preview.targetStripePriceId,
    matching_count: preview.matchingCount,
    candidate_count: preview.candidateCount,
    already_on_target: preview.alreadyOnTarget,
    samples: preview.samples.map((sample) => ({
      scope: sample.scope,
      org_slug: sample.orgSlug,
      stripe_subscription_id: sample.stripeSubscriptionId,
      status: sample.status,
      current_plan_key: sample.currentPlanKey,
      current_stripe_price_id: sample.currentStripePriceId,
    })),
  };
}

function migrationRunFromProto(run: MigrationRun): AdminBillingCatalogMigrationRun {
  return {
    id: run.id,
    resource_type: run.resourceType,
    source_plan_key: run.sourcePlanKey,
    target_plan_key: run.targetPlanKey,
    proration_behavior: run.prorationBehavior,
    migrated_count: run.migratedCount,
    skipped_count: run.skippedCount,
    failed_count: run.failedCount,
    created_by: run.createdBy,
    created_at: run.createdAt ? timestampDate(run.createdAt).toISOString() : "",
  };
}

function planKey(plan: Pick<AdminBillingCatalogPlan, "resource_type" | "plan_key">) {
  return `${plan.resource_type}:${plan.plan_key}`;
}

function priceKey(
  price: Pick<
    AdminBillingCatalogPrice,
    "resource_type" | "plan_key" | "stripe_mode" | "price_kind"
  >,
) {
  return `${price.resource_type}:${price.plan_key}:${price.stripe_mode}:${price.price_kind}`;
}

function settingKey(setting: Pick<AdminBillingCatalogSetting, "setting_key">) {
  return setting.setting_key;
}

function toNumber(value: string): number {
  if (value.trim() === "") return 0;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function BooleanSelect({
  value,
  onValueChange,
}: {
  value: boolean;
  onValueChange: (value: boolean) => void;
}) {
  return (
    <Select
      value={value ? "true" : "false"}
      onValueChange={(next) => onValueChange(next === "true")}
    >
      <SelectTrigger className="w-[110px]">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="false">False</SelectItem>
        <SelectItem value="true">True</SelectItem>
      </SelectContent>
    </Select>
  );
}

function emptyPlanDraft(): AdminBillingCatalogPlan {
  return {
    resource_type: "sandbox",
    plan_key: "",
    display_name: "",
    price_cents: 0,
    included_devs: 0,
    max_concurrent_ws: 0,
    max_team_members: 0,
    storage_gb: 0,
    is_contact_us: false,
    is_admin_only: false,
    included_cpu_hours: 0,
    included_mem_gb_hours: 0,
    included_disk_gb_hours: 0,
    cpu_overage_cents: 0,
    mem_overage_cents: 0,
    disk_overage_cents: 0,
    archived: false,
  };
}

function emptyPriceDraft(): AdminBillingCatalogPrice {
  return {
    resource_type: "sandbox",
    plan_key: "",
    stripe_mode: "test",
    price_kind: "subscription",
    stripe_price_id: "",
    archived: false,
  };
}

type BillingMigrationDraft = {
  resource_type: string;
  source_plan_key: string;
  target_plan_key: string;
  proration_behavior: "none" | "create_prorations" | "always_invoice";
};

function emptyMigrationDraft(): BillingMigrationDraft {
  return {
    resource_type: "org",
    source_plan_key: "",
    target_plan_key: "",
    proration_behavior: "none",
  };
}

function AdminBillingCatalogPage() {
  const queryClient = useQueryClient();
  const [planDrafts, setPlanDrafts] = useState<Record<string, AdminBillingCatalogPlan>>({});
  const [priceDrafts, setPriceDrafts] = useState<Record<string, AdminBillingCatalogPrice>>({});
  const [settingDrafts, setSettingDrafts] = useState<Record<string, AdminBillingCatalogSetting>>({});
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [newPlan, setNewPlan] = useState<AdminBillingCatalogPlan>(emptyPlanDraft);
  const [newPrice, setNewPrice] = useState<AdminBillingCatalogPrice>(emptyPriceDraft);
  const [migrationDraft, setMigrationDraft] = useState<BillingMigrationDraft>(emptyMigrationDraft);
  const [migrationPreview, setMigrationPreview] = useState<AdminBillingCatalogMigrationPreview | null>(null);

  const { data: catalogResponse, isLoading } = useConnectQuery(
    BillingCatalogService.method.getCatalog,
    undefined,
    { transport: connectTransport },
  );
  const { data: migrationRunsResponse } = useConnectQuery(
    BillingCatalogService.method.listSubscriptionMigrations,
    { limit: 25 },
    { transport: connectTransport },
  );
  const catalog = useMemo(
    () =>
      catalogResponse && {
        plans: catalogResponse.plans.map(planFromProto),
        prices: catalogResponse.prices.map(priceFromProto),
        settings: catalogResponse.settings.map(settingFromProto),
      },
    [catalogResponse],
  );
  const migrationRuns = useMemo(
    () => migrationRunsResponse?.migrations.map(migrationRunFromProto),
    [migrationRunsResponse],
  );

  const plans = catalog?.plans ?? [];
  const prices = catalog?.prices ?? [];
  const settings = catalog?.settings ?? [];

  useEffect(() => {
    if (!catalog) return;
    setPlanDrafts(
      Object.fromEntries(plans.map((plan) => [planKey(plan), { ...plan }])),
    );
    setPriceDrafts(
      Object.fromEntries(prices.map((price) => [priceKey(price), { ...price }])),
    );
    setSettingDrafts(
      Object.fromEntries(settings.map((setting) => [settingKey(setting), { ...setting }])),
    );
    setMigrationDraft((current) => {
      const nextResourceType = current.resource_type || plans[0]?.resource_type || "org";
      const nextPlans = plans.filter((plan) => plan.resource_type === nextResourceType);
      const firstPlan = nextPlans[0]?.plan_key ?? "";
      return {
        ...current,
        resource_type: nextResourceType,
        source_plan_key: current.source_plan_key || firstPlan,
        target_plan_key: current.target_plan_key || firstPlan,
      };
    });
  }, [catalog, plans, prices, settings]);

  const groupedPlans = useMemo(() => {
    const groups = new Map<string, AdminBillingCatalogPlan[]>();
    for (const plan of plans) {
      const key = plan.resource_type;
      const next = groups.get(key) ?? [];
      next.push(plan);
      groups.set(key, next);
    }
    return Array.from(groups.entries());
  }, [plans]);

  const resourceTypes = useMemo(() => Array.from(new Set(plans.map((plan) => plan.resource_type))), [plans]);
  const migrationPlanOptions = useMemo(
    () => plans.filter((plan) => plan.resource_type === migrationDraft.resource_type),
    [migrationDraft.resource_type, plans],
  );

  const planMutation = useMutation({
    mutationFn: (plan: AdminBillingCatalogPlan) =>
      billingCatalogClient.updatePlan({
        resourceType: plan.resource_type,
        planKey: plan.plan_key,
        plan: planSpecFromDraft(plan),
      }),
    onSuccess: () => {
      toast.success("Billing plan saved");
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const createPlanMutation = useMutation({
    mutationFn: (plan: AdminBillingCatalogPlan) =>
      billingCatalogClient.createPlan({
        resourceType: plan.resource_type,
        planKey: plan.plan_key,
        plan: planSpecFromDraft(plan),
      }),
    onSuccess: () => {
      toast.success("Billing plan created");
      setNewPlan(emptyPlanDraft());
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const archivePlanMutation = useMutation({
    mutationFn: (plan: AdminBillingCatalogPlan) =>
      billingCatalogClient.setPlanArchived({
        resourceType: plan.resource_type,
        planKey: plan.plan_key,
        archived: !plan.archived,
      }),
    onSuccess: () => {
      toast.success("Billing plan archive state updated");
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const priceMutation = useMutation({
    mutationFn: (price: AdminBillingCatalogPrice) =>
      billingCatalogClient.updatePrice({
        resourceType: price.resource_type,
        planKey: price.plan_key,
        stripeMode: price.stripe_mode,
        priceKind: price.price_kind,
        stripePriceId: price.stripe_price_id,
      }),
    onSuccess: () => {
      toast.success("Stripe price saved");
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const createPriceMutation = useMutation({
    mutationFn: (price: AdminBillingCatalogPrice) =>
      billingCatalogClient.createPrice({
        resourceType: price.resource_type,
        planKey: price.plan_key,
        stripeMode: price.stripe_mode,
        priceKind: price.price_kind,
        stripePriceId: price.stripe_price_id,
      }),
    onSuccess: () => {
      toast.success("Stripe price created");
      setNewPrice(emptyPriceDraft());
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const archivePriceMutation = useMutation({
    mutationFn: (price: AdminBillingCatalogPrice) =>
      billingCatalogClient.setPriceArchived({
        resourceType: price.resource_type,
        planKey: price.plan_key,
        stripeMode: price.stripe_mode,
        priceKind: price.price_kind,
        archived: !price.archived,
      }),
    onSuccess: () => {
      toast.success("Stripe price archive state updated");
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const settingMutation = useMutation({
    mutationFn: (setting: AdminBillingCatalogSetting) =>
      billingCatalogClient.updateSetting({
        settingKey: setting.setting_key,
        intValue: setting.int_value,
      }),
    onSuccess: () => {
      toast.success("Billing setting saved");
      queryClient.invalidateQueries({ queryKey: billingCatalogQueryKey });
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const previewMigrationMutation = useMutation({
    mutationFn: (input: BillingMigrationDraft) =>
      billingCatalogClient.previewSubscriptionMigration({
        resourceType: input.resource_type,
        sourcePlanKey: input.source_plan_key,
        targetPlanKey: input.target_plan_key,
        sampleLimit: 8,
      }),
    onSuccess: (data) => {
      setMigrationPreview(migrationPreviewFromProto(data));
      toast.success("Subscription migration preview updated");
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  const runMigrationMutation = useMutation({
    mutationFn: (input: BillingMigrationDraft) =>
      billingCatalogClient.runSubscriptionMigration({
        resourceType: input.resource_type,
        sourcePlanKey: input.source_plan_key,
        targetPlanKey: input.target_plan_key,
        prorationBehavior: input.proration_behavior,
      }),
    onSuccess: (data) => {
      setMigrationPreview(null);
      queryClient.invalidateQueries({
        queryKey: billingCatalogMigrationsQueryKey,
      });
      if (!data.migration) {
        toast.error("Subscription migration did not return a result");
        return;
      }
      const migration = migrationRunFromProto(data.migration);
      const failedCount = migration.failed_count;
      if (failedCount > 0) {
        toast.warning(
          `Migration ran with ${migration.migrated_count} migrated, ${migration.skipped_count} skipped, ${failedCount} failed`,
        );
      } else {
        toast.success(
          `Migrated ${migration.migrated_count} subscriptions to ${migration.target_plan_key}`,
        );
      }
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
    onSettled: () => {
      setSavingKey(null);
    },
  });

  if (isLoading || !catalog) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-secondary)]" />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-page-enter">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-[color:var(--fg-primary)]">
            Billing Catalog
          </h2>
          <p className="text-sm text-[color:var(--fg-secondary)]">
            Edit plan limits, billing settings, and Stripe price IDs from Codewire instead of
            treating Stripe as the product catalog.
          </p>
        </div>
        <Badge variant="outline">
          {plans.length} plans · {prices.length} prices · {settings.length} settings
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Subscription Migrations</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border p-4">
            <div className="mb-2 text-sm font-medium text-[color:var(--fg-primary)]">
              Move active subscriptions to the current catalog price
            </div>
            <p className="mb-4 text-sm text-[color:var(--fg-secondary)]">
              Use this after changing a plan target or replacing a Stripe price. Same-plan
              migrations refresh existing subscriptions onto the current price ID for that plan.
            </p>
            <div className="grid gap-3 md:grid-cols-4">
              <Select
                value={migrationDraft.resource_type}
                onValueChange={(value) => {
                  const nextPlans = plans.filter((plan) => plan.resource_type === value);
                  const firstPlan = nextPlans[0]?.plan_key ?? "";
                  setMigrationPreview(null);
                  setMigrationDraft((current) => ({
                    ...current,
                    resource_type: value,
                    source_plan_key: firstPlan,
                    target_plan_key: firstPlan,
                  }));
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Plan scope" />
                </SelectTrigger>
                <SelectContent>
                  {resourceTypes.map((resourceType) => (
                    <SelectItem key={resourceType} value={resourceType}>
                      {resourceType}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select
                value={migrationDraft.source_plan_key || "__none__"}
                onValueChange={(value) => {
                  setMigrationPreview(null);
                  setMigrationDraft((current) => ({
                    ...current,
                    source_plan_key: value === "__none__" ? "" : value,
                  }));
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Source plan" />
                </SelectTrigger>
                <SelectContent>
                  {migrationPlanOptions.map((plan) => (
                    <SelectItem key={`source-${planKey(plan)}`} value={plan.plan_key}>
                      {plan.display_name} ({plan.plan_key}){plan.archived ? " · archived" : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select
                value={migrationDraft.target_plan_key || "__none__"}
                onValueChange={(value) => {
                  setMigrationPreview(null);
                  setMigrationDraft((current) => ({
                    ...current,
                    target_plan_key: value === "__none__" ? "" : value,
                  }));
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Target plan" />
                </SelectTrigger>
                <SelectContent>
                  {migrationPlanOptions
                    .filter((plan) => !plan.archived)
                    .map((plan) => (
                      <SelectItem key={`target-${planKey(plan)}`} value={plan.plan_key}>
                        {plan.display_name} ({plan.plan_key})
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>

              <Select
                value={migrationDraft.proration_behavior}
                onValueChange={(value: "none" | "create_prorations" | "always_invoice") =>
                  setMigrationDraft((current) => ({ ...current, proration_behavior: value }))
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Proration" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No proration</SelectItem>
                  <SelectItem value="create_prorations">Create prorations</SelectItem>
                  <SelectItem value="always_invoice">Invoice immediately</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={
                  !migrationDraft.source_plan_key ||
                  !migrationDraft.target_plan_key ||
                  (savingKey === "migration:preview" && previewMigrationMutation.isPending)
                }
                onClick={() => {
                  setSavingKey("migration:preview");
                  previewMigrationMutation.mutate(migrationDraft);
                }}
                className="gap-2"
              >
                {savingKey === "migration:preview" && previewMigrationMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Preview
              </Button>
              <Button
                disabled={
                  !migrationDraft.source_plan_key ||
                  !migrationDraft.target_plan_key ||
                  (savingKey === "migration:run" && runMigrationMutation.isPending)
                }
                onClick={() => {
                  setSavingKey("migration:run");
                  runMigrationMutation.mutate(migrationDraft);
                }}
                className="gap-2"
              >
                {savingKey === "migration:run" && runMigrationMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Run Migration
              </Button>
            </div>
          </div>

          {migrationPreview && (
            <div className="rounded-lg border p-4">
              <div className="grid gap-3 md:grid-cols-4">
                <div>
                  <div className="text-xs uppercase tracking-wide text-[color:var(--fg-tertiary)]">
                    Matching
                  </div>
                  <div className="text-lg font-semibold text-[color:var(--fg-primary)]">
                    {migrationPreview.matching_count}
                  </div>
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wide text-[color:var(--fg-tertiary)]">
                    Need Update
                  </div>
                  <div className="text-lg font-semibold text-[color:var(--fg-primary)]">
                    {migrationPreview.candidate_count}
                  </div>
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wide text-[color:var(--fg-tertiary)]">
                    Already On Target
                  </div>
                  <div className="text-lg font-semibold text-[color:var(--fg-primary)]">
                    {migrationPreview.already_on_target}
                  </div>
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wide text-[color:var(--fg-tertiary)]">
                    Target Price
                  </div>
                  <div className="font-mono text-xs text-[color:var(--fg-primary)]">
                    {migrationPreview.target_stripe_price_id}
                  </div>
                </div>
              </div>

              <div className="mt-4 overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Scope</TableHead>
                      <TableHead>Org</TableHead>
                      <TableHead>Subscription</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Current Plan</TableHead>
                      <TableHead>Current Price</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(migrationPreview.samples ?? []).length > 0 ? (
                      (migrationPreview.samples ?? []).map((sample) => (
                        <TableRow key={`${sample.scope}:${sample.stripe_subscription_id}`}>
                          <TableCell>{sample.scope}</TableCell>
                          <TableCell className="font-mono text-xs">{sample.org_slug}</TableCell>
                          <TableCell className="font-mono text-xs">{sample.stripe_subscription_id}</TableCell>
                          <TableCell>{sample.status}</TableCell>
                          <TableCell className="font-mono text-xs">{sample.current_plan_key}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {sample.current_stripe_price_id || "—"}
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center text-[color:var(--fg-secondary)]">
                          No subscriptions currently need migration.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Plan Scope</TableHead>
                  <TableHead>From</TableHead>
                  <TableHead>To</TableHead>
                  <TableHead>Proration</TableHead>
                  <TableHead>Migrated</TableHead>
                  <TableHead>Skipped</TableHead>
                  <TableHead>Failed</TableHead>
                  <TableHead>Actor</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(migrationRuns ?? []).length > 0 ? (
                  (migrationRuns ?? []).map((run: AdminBillingCatalogMigrationRun) => (
                    <TableRow key={run.id}>
                      <TableCell className="text-sm text-[color:var(--fg-secondary)]">
                        {new Date(run.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell>{run.resource_type}</TableCell>
                      <TableCell className="font-mono text-xs">{run.source_plan_key}</TableCell>
                      <TableCell className="font-mono text-xs">{run.target_plan_key}</TableCell>
                      <TableCell>{run.proration_behavior}</TableCell>
                      <TableCell>{run.migrated_count}</TableCell>
                      <TableCell>{run.skipped_count}</TableCell>
                      <TableCell>{run.failed_count}</TableCell>
                      <TableCell>{run.created_by || "—"}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-[color:var(--fg-secondary)]">
                      No subscription migrations have been run yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Billing Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {settings.map((setting) => {
            const draft = settingDrafts[settingKey(setting)] ?? setting;
            const key = `setting:${setting.setting_key}`;
            const isSaving = savingKey === key && settingMutation.isPending;
            return (
              <div
                key={setting.setting_key}
                className="flex flex-col gap-3 rounded-lg border p-4 md:flex-row md:items-center md:justify-between"
              >
                <div>
                  <div className="font-medium text-[color:var(--fg-primary)]">
                    {setting.setting_key}
                  </div>
                  <div className="text-xs text-[color:var(--fg-secondary)]">
                    Integer catalog setting used by billing flows and UI.
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Input
                    type="number"
                    className="w-[140px]"
                    value={draft.int_value}
                    onChange={(e) =>
                      setSettingDrafts((current) => ({
                        ...current,
                        [setting.setting_key]: {
                          ...draft,
                          int_value: toNumber(e.target.value),
                        },
                      }))
                    }
                  />
                  <Button
                    size="sm"
                    onClick={() => {
                      setSavingKey(key);
                      settingMutation.mutate(draft);
                    }}
                    disabled={isSaving}
                    className="gap-2"
                  >
                    {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                    Save
                  </Button>
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Stripe Price IDs</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <div className="mb-4 rounded-lg border border-dashed p-4">
            <div className="mb-3 text-sm font-medium text-[color:var(--fg-primary)]">
              Add Stripe price
            </div>
            <div className="grid gap-3 md:grid-cols-6">
              <Input
                placeholder="plan_scope"
                value={newPrice.resource_type}
                onChange={(e) => setNewPrice((current) => ({ ...current, resource_type: e.target.value }))}
              />
              <Input
                placeholder="plan_key"
                value={newPrice.plan_key}
                onChange={(e) => setNewPrice((current) => ({ ...current, plan_key: e.target.value }))}
              />
              <Input
                placeholder="stripe_mode"
                value={newPrice.stripe_mode}
                onChange={(e) => setNewPrice((current) => ({ ...current, stripe_mode: e.target.value }))}
              />
              <Input
                placeholder="price_kind"
                value={newPrice.price_kind}
                onChange={(e) => setNewPrice((current) => ({ ...current, price_kind: e.target.value }))}
              />
              <Input
                placeholder="stripe_price_id"
                value={newPrice.stripe_price_id}
                onChange={(e) => setNewPrice((current) => ({ ...current, stripe_price_id: e.target.value }))}
              />
              <Button
                onClick={() => {
                  setSavingKey("price:new");
                  createPriceMutation.mutate(newPrice);
                }}
                disabled={savingKey === "price:new" && createPriceMutation.isPending}
                className="gap-2"
              >
                {savingKey === "price:new" && createPriceMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Create
              </Button>
            </div>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Plan Scope</TableHead>
                <TableHead>Plan</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Stripe Price ID</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {prices.map((price) => {
                const draft = priceDrafts[priceKey(price)] ?? price;
                const key = `price:${priceKey(price)}`;
                const isSaving = savingKey === key && priceMutation.isPending;
                const archiveKey = `price-archive:${priceKey(price)}`;
                const isArchiving = savingKey === archiveKey && archivePriceMutation.isPending;
                return (
                  <TableRow key={priceKey(price)}>
                    <TableCell className="font-mono text-xs">{price.resource_type}</TableCell>
                    <TableCell className="font-mono text-xs">{price.plan_key}</TableCell>
                    <TableCell>{price.stripe_mode}</TableCell>
                    <TableCell>{price.price_kind}</TableCell>
                    <TableCell className="min-w-[280px]">
                      <Input
                        value={draft.stripe_price_id}
                        onChange={(e) =>
                          setPriceDrafts((current) => ({
                            ...current,
                            [priceKey(price)]: {
                              ...draft,
                              stripe_price_id: e.target.value,
                            },
                          }))
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Badge variant={price.archived ? "secondary" : "outline"}>
                        {price.archived ? "Archived" : "Active"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setSavingKey(key);
                            priceMutation.mutate(draft);
                          }}
                          disabled={isSaving}
                          className="gap-2"
                        >
                          {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                          Save
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setSavingKey(archiveKey);
                            archivePriceMutation.mutate(price);
                          }}
                          disabled={isArchiving}
                        >
                          {isArchiving ? <Loader2 className="h-4 w-4 animate-spin" /> : price.archived ? "Unarchive" : "Archive"}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {groupedPlans.map(([resourceType, plans]) => (
        <Card key={resourceType}>
          <CardHeader>
            <CardTitle className="text-base">
              {resourceType} plans
            </CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <div className="mb-4 rounded-lg border border-dashed p-4">
              <div className="mb-3 text-sm font-medium text-[color:var(--fg-primary)]">
                Add {resourceType} plan
              </div>
              <div className="grid gap-3 md:grid-cols-5">
                <Input
                  placeholder="plan_key"
                  value={newPlan.resource_type === resourceType ? newPlan.plan_key : ""}
                  onChange={(e) =>
                    setNewPlan((current) => ({
                      ...current,
                      resource_type: resourceType,
                      plan_key: e.target.value,
                    }))
                  }
                />
                <Input
                  placeholder="display_name"
                  value={newPlan.resource_type === resourceType ? newPlan.display_name : ""}
                  onChange={(e) =>
                    setNewPlan((current) => ({
                      ...current,
                      resource_type: resourceType,
                      display_name: e.target.value,
                    }))
                  }
                />
                <Input
                  type="number"
                  placeholder="price_cents"
                  value={newPlan.resource_type === resourceType ? newPlan.price_cents : 0}
                  onChange={(e) =>
                    setNewPlan((current) => ({
                      ...current,
                      resource_type: resourceType,
                      price_cents: toNumber(e.target.value),
                    }))
                  }
                />
                <Input
                  type="number"
                  placeholder="included_devs"
                  value={newPlan.resource_type === resourceType ? newPlan.included_devs : 0}
                  onChange={(e) =>
                    setNewPlan((current) => ({
                      ...current,
                      resource_type: resourceType,
                      included_devs: toNumber(e.target.value),
                    }))
                  }
                />
                <Button
                  onClick={() => {
                    setSavingKey(`plan:new:${resourceType}`);
                    createPlanMutation.mutate({ ...newPlan, resource_type: resourceType });
                  }}
                  disabled={savingKey === `plan:new:${resourceType}` && createPlanMutation.isPending}
                  className="gap-2"
                >
                  {savingKey === `plan:new:${resourceType}` && createPlanMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="h-4 w-4" />
                  )}
                  Create
                </Button>
              </div>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Plan</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Price</TableHead>
                  <TableHead>Included Devs</TableHead>
                  <TableHead>Concurrent WS</TableHead>
                  <TableHead>Team Members</TableHead>
                  <TableHead>Storage GB</TableHead>
                  <TableHead>Contact</TableHead>
                  <TableHead>Admin Only</TableHead>
                  <TableHead>CPU Hours</TableHead>
                  <TableHead>Mem GB-Hours</TableHead>
                  <TableHead>Disk GB-Hours</TableHead>
                  <TableHead>CPU Overage</TableHead>
                  <TableHead>Mem Overage</TableHead>
                  <TableHead>Disk Overage</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {plans.map((plan) => {
                  const draft = planDrafts[planKey(plan)] ?? plan;
                  const key = `plan:${planKey(plan)}`;
                  const isSaving = savingKey === key && planMutation.isPending;
                  const archiveKey = `plan-archive:${planKey(plan)}`;
                  const isArchiving = savingKey === archiveKey && archivePlanMutation.isPending;
                  return (
                    <TableRow key={planKey(plan)}>
                      <TableCell className="font-mono text-xs">{plan.plan_key}</TableCell>
                      <TableCell className="min-w-[160px]">
                        <Input
                          value={draft.display_name}
                          onChange={(e) =>
                            setPlanDrafts((current) => ({
                              ...current,
                              [planKey(plan)]: { ...draft, display_name: e.target.value },
                            }))
                          }
                        />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input
                          type="number"
                          value={draft.price_cents}
                          onChange={(e) =>
                            setPlanDrafts((current) => ({
                              ...current,
                              [planKey(plan)]: { ...draft, price_cents: toNumber(e.target.value) },
                            }))
                          }
                        />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.included_devs} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, included_devs: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.max_concurrent_ws} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, max_concurrent_ws: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.max_team_members} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, max_team_members: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.storage_gb} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, storage_gb: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell>
                        <BooleanSelect value={draft.is_contact_us} onValueChange={(value) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, is_contact_us: value } }))} />
                      </TableCell>
                      <TableCell>
                        <BooleanSelect value={draft.is_admin_only} onValueChange={(value) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, is_admin_only: value } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.included_cpu_hours} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, included_cpu_hours: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.included_mem_gb_hours} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, included_mem_gb_hours: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" value={draft.included_disk_gb_hours} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, included_disk_gb_hours: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" step="0.01" value={draft.cpu_overage_cents} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, cpu_overage_cents: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" step="0.01" value={draft.mem_overage_cents} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, mem_overage_cents: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell className="w-[110px]">
                        <Input type="number" step="0.01" value={draft.disk_overage_cents} onChange={(e) => setPlanDrafts((current) => ({ ...current, [planKey(plan)]: { ...draft, disk_overage_cents: toNumber(e.target.value) } }))} />
                      </TableCell>
                      <TableCell>
                        <Badge variant={plan.archived ? "secondary" : "outline"}>
                          {plan.archived ? "Archived" : "Active"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setSavingKey(key);
                              planMutation.mutate(draft);
                            }}
                            disabled={isSaving}
                            className="gap-2"
                          >
                            {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                            Save
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setSavingKey(archiveKey);
                              archivePlanMutation.mutate(plan);
                            }}
                            disabled={isArchiving}
                          >
                            {isArchiving ? <Loader2 className="h-4 w-4 animate-spin" /> : plan.archived ? "Unarchive" : "Archive"}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
