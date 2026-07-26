import type { LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <div
        className="w-12 h-12 rounded-xl flex items-center justify-center mb-4"
        style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
      >
        <Icon className="h-6 w-6 text-[color:var(--fg-tertiary)]" />
      </div>
      <h3 className="font-semibold text-[color:var(--fg-primary)] mb-1">{title}</h3>
      <p className="text-sm text-[color:var(--fg-secondary)] max-w-[320px] mb-4">{description}</p>
      {action && (
        <Button size="sm" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
}
