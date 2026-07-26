import { cn } from "@/lib/utils";

export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-[var(--bg-surface-hover)]", className)}
      {...props}
    />
  );
}

export function SidebarSkeleton() {
  return (
    <div className="px-4 py-3 space-y-4">
      <Skeleton className="h-4 w-24" />
      <div className="space-y-2">
        <Skeleton className="h-7 w-full" />
        <Skeleton className="h-6 w-3/4 ml-4" />
        <Skeleton className="h-6 w-2/3 ml-4" />
      </div>
      <Skeleton className="h-4 w-20" />
      <div className="space-y-2">
        <Skeleton className="h-7 w-full" />
        <Skeleton className="h-6 w-3/4 ml-4" />
      </div>
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-surface)] p-6 space-y-4">
      <Skeleton className="h-5 w-1/3" />
      <Skeleton className="h-4 w-2/3" />
      <div className="space-y-2">
        <Skeleton className="h-3 w-full" />
        <Skeleton className="h-3 w-4/5" />
      </div>
    </div>
  );
}

export function WorkspaceCardSkeleton() {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-surface)] p-5 space-y-3">
      <div className="flex items-center gap-3">
        <Skeleton className="h-8 w-8 rounded-lg" />
        <div className="space-y-1.5 flex-1">
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-3 w-1/3" />
        </div>
        <Skeleton className="h-2 w-2 rounded-full" />
      </div>
      <Skeleton className="h-8 w-24" />
    </div>
  );
}
