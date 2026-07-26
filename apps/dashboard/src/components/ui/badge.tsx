import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--accent)] focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-[var(--accent)]/15 text-[color:var(--accent)]",
        secondary:
          "border-transparent bg-[var(--bg-surface)] text-[color:var(--fg-secondary)]",
        destructive:
          "border-transparent bg-[var(--destructive)]/15 text-[color:var(--destructive)]",
        outline: "text-[color:var(--fg-primary)] border-[var(--border)]",
        success:
          "border-transparent bg-[var(--success)]/15 text-[color:var(--success)]",
        warning:
          "border-transparent bg-[var(--warning)]/15 text-[color:var(--warning)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
