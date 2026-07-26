import { createFileRoute } from "@tanstack/react-router";
import { useQuery as useConnectQuery } from "@connectrpc/connect-query";
import { AdminService } from "@codewire/proto-ts/gen/codewire/admin/v1/admin_pb";
import { connectTransport } from "@/lib/connect";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Boxes, Cpu, DollarSign, HardDrive, Loader2 } from "lucide-react";

export const Route = createFileRoute("/admin/")({
  component: AdminOverviewPage,
});

function AdminOverviewPage() {
  const { data: stats, isLoading } = useConnectQuery(
    AdminService.method.getStats,
    undefined,
    { transport: connectTransport, refetchInterval: 30000 },
  );

  if (isLoading || !stats) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-[color:var(--fg-secondary)]" />
      </div>
    );
  }

  const cards = [
    {
      title: "Total Environments",
      value: stats.totalEnvironments.toString(),
      subtitle: `${stats.activeEnvironments.toString()} active`,
      icon: Boxes,
    },
    {
      title: "Monthly Cost",
      value: `$${(Number(stats.monthlyCostCents) / 100).toFixed(2)}`,
      subtitle: "This month",
      icon: DollarSign,
    },
    {
      title: "CPU Hours",
      value: stats.monthlyCpuHours.toFixed(1),
      subtitle: "This month",
      icon: Cpu,
    },
    {
      title: "Memory GB-Hours",
      value: stats.monthlyMemoryGbHours.toFixed(1),
      subtitle: "This month",
      icon: HardDrive,
    },
  ];

  return (
    <div className="space-y-6 animate-page-enter">
      <h2 className="text-lg font-semibold text-[color:var(--fg-primary)]">Overview</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <Card key={card.title}>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-[color:var(--fg-secondary)]">
                  {card.title}
                </CardTitle>
                <Icon className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-[color:var(--fg-primary)]">{card.value}</div>
                <p className="text-xs text-[color:var(--fg-tertiary)]">{card.subtitle}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
