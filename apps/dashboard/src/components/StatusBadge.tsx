interface StatusBadgeProps {
  status: string
}

const statusConfig: Record<string, { label: string; className: string }> = {
  pending: {
    label: 'Pending',
    className: 'bg-yellow-500/10 text-yellow-400',
  },
  provisioning: {
    label: 'Provisioning',
    className: 'bg-blue-500/10 text-blue-400',
  },
  running: {
    label: 'Running',
    className: 'bg-green-500/10 text-green-400',
  },
  failed: {
    label: 'Failed',
    className: 'bg-red-500/10 text-red-400',
  },
  deleting: {
    label: 'Deleting',
    className: 'bg-orange-500/10 text-orange-400',
  },
  deleted: {
    label: 'Deleted',
    className: 'bg-neutral-500/10 text-neutral-400',
  },
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status] || {
    label: status,
    className: 'bg-neutral-500/10 text-neutral-400',
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.className}`}
    >
      {config.label}
    </span>
  )
}
