interface ProvisioningEvent {
  id: number;
  tenant_id: string;
  event_type: string;
  status: "success" | "failed" | "in_progress" | "info";
  message?: string;
  created_at: string;
}

interface EventTimelineProps {
  events: ProvisioningEvent[];
}

const statusIcon: Record<string, { icon: string; color: string }> = {
  success: { icon: '✓', color: 'text-green-400 bg-green-500/10' },
  failed: { icon: '✕', color: 'text-red-400 bg-red-500/10' },
  in_progress: { icon: '●', color: 'text-blue-400 bg-blue-500/10 animate-pulse' },
  info: { icon: 'ℹ', color: 'text-neutral-400 bg-neutral-500/10' },
}

export function EventTimeline({ events }: EventTimelineProps) {
  // Filter out drift detection noise - these are routine reconciliation events
  const visibleEvents = events.filter(e => e.event_type !== 'drift_detected')

  if (visibleEvents.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">No events yet</p>
    )
  }

  return (
    <div className="space-y-4">
      {visibleEvents.map((event) => {
        const { icon, color } = statusIcon[event.status] || statusIcon.info

        return (
          <div key={event.id} className="flex gap-3">
            <div
              className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs ${color}`}
            >
              {icon}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium">
                {formatEventType(event.event_type)}
              </p>
              {event.message && (
                <p className="text-sm text-muted-foreground mt-0.5 break-words">
                  {event.message}
                </p>
              )}
              <p className="text-xs text-muted-foreground mt-1">
                {new Date(event.created_at).toLocaleString()}
              </p>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function formatEventType(type: string): string {
  const typeMap: Record<string, string> = {
    provision_start: 'Provisioning Started',
    terraform_init: 'Terraform Initialized',
    terraform_apply: 'Terraform Applied',
    provision_complete: 'Provisioning Complete',
    provision_failed: 'Provisioning Failed',
    upgrade_start: 'Upgrade Started',
    upgrade_complete: 'Upgrade Complete',
    upgrade_failed: 'Upgrade Failed',
    delete_start: 'Deletion Started',
    delete_complete: 'Deletion Complete',
    delete_failed: 'Deletion Failed',
    drift_detected: 'Configuration Drift Detected',
  }

  return typeMap[type] || type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}
