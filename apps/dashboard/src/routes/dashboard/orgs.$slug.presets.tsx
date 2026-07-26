import { useState } from "react";
import { toast } from "sonner";
import { createFileRoute } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { OrgRole, OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { PresetService, type Preset } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import { connectTransport, presetServiceQueryKey } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { findOrganizationBySlug } from "@/lib/organizations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Loader2,
  Pencil,
  Trash2,
  X,
  Check,
  Box,
  Cpu,
  HardDrive,
  MemoryStick,
  Clock,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/orgs/$slug/presets")({
  component: PresetsPage,
});

function PresetsPage() {
  const { slug } = Route.useParams();
  const queryClient = useQueryClient();
  const [editingId, setEditingId] = useState<string | null>(null);

  const { data: orgsResponse } = useConnectQuery(
    OrganizationService.method.listOrganizations,
    undefined,
    { transport: connectTransport },
  );
  const membership = findOrganizationBySlug(orgsResponse?.organizations, slug);
  const org = membership?.organization;

  const { data: presetsResponse, isLoading } = useConnectQuery(
    PresetService.method.listPresets,
    org?.id ? { orgId: org.id } : undefined,
    { enabled: !!org?.id, transport: connectTransport },
  );
  const presets = presetsResponse?.presets ?? [];

  const deleteMutation = useConnectMutation(PresetService.method.deletePreset, {
    transport: connectTransport,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: presetServiceQueryKey }),
    onError: (error) => toast.error(errorMessage(error)),
  });

  if (!org || isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-[color:var(--fg-tertiary)]" />
      </div>
    );
  }

  const isAdmin =
    membership?.role === OrgRole.OWNER ||
    membership?.role === OrgRole.ADMIN ||
    membership?.assignments.includes("super_admin");

  const items = presets;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-[color:var(--fg-primary)]">
          Presets
        </h2>
      </div>

      {items.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-[color:var(--fg-secondary)] text-sm">
              No presets yet. Presets are created automatically when you
              create environments.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((t) => (
            <PresetCard
              key={t.id}
              preset={t}
              orgId={org.id}
              isAdmin={isAdmin}
              isEditing={editingId === t.id}
              onEdit={() => setEditingId(t.id)}
              onCancel={() => setEditingId(null)}
              onSaved={() => {
                setEditingId(null);
                queryClient.invalidateQueries({
                  queryKey: presetServiceQueryKey,
                });
              }}
              onDelete={() => {
                if (
                  confirm(
                    `Delete preset "${t.name}"? This cannot be undone.`,
                  )
                ) {
                  deleteMutation.mutate({ orgId: org.id, presetId: t.id });
                }
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function PresetCard({
  preset: t,
  orgId,
  isAdmin,
  isEditing,
  onEdit,
  onCancel,
  onSaved,
  onDelete,
}: {
  preset: Preset;
  orgId: string;
  isAdmin: boolean;
  isEditing: boolean;
  onEdit: () => void;
  onCancel: () => void;
  onSaved: () => void;
  onDelete: () => void;
}) {
  if (isEditing) {
    return (
      <PresetEditForm
        preset={t}
        orgId={orgId}
        onCancel={onCancel}
        onSaved={onSaved}
      />
    );
  }

  const isOrgPreset = !!t.orgId;

  return (
    <Card>
      <CardContent className="py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-[color:var(--fg-primary)] truncate">
                {t.name}
              </span>
              <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                sandbox
              </Badge>
              {t.official && (
                <Badge
                  variant="outline"
                  className="text-[10px] px-1.5 py-0 bg-blue-500/10 text-blue-700 border-blue-500/20"
                >
                  official
                </Badge>
              )}
              {t.slug && (
                <span className="text-[10px] font-mono text-[color:var(--fg-tertiary)]">
                  {t.slug}
                </span>
              )}
            </div>

            {t.description && (
              <p className="text-xs text-[color:var(--fg-secondary)] line-clamp-1">
                {t.description}
              </p>
            )}

            <div className="flex flex-wrap items-center gap-3 text-[11px] text-[color:var(--fg-tertiary)]">
              {t.image && (
                <span className="inline-flex items-center gap-1">
                  <Box className="h-3 w-3" />
                  <span className="font-mono">{t.image}</span>
                </span>
              )}
              <span className="inline-flex items-center gap-1">
                <Cpu className="h-3 w-3" />
                {t.defaultCpuMillicores / 1000} vCPU
              </span>
              <span className="inline-flex items-center gap-1">
                <MemoryStick className="h-3 w-3" />
                {(t.defaultMemoryMb / 1024).toFixed(0)} GiB
              </span>
              <span className="inline-flex items-center gap-1">
                <HardDrive className="h-3 w-3" />
                {t.defaultDiskGb} GB
              </span>
              {t.defaultTtlSeconds && (
                <span className="inline-flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {Math.round(t.defaultTtlSeconds / 60)}m TTL
                </span>
              )}
            </div>
          </div>

          {isAdmin && isOrgPreset && (
            <div className="flex items-center gap-1 shrink-0">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                onClick={onEdit}
              >
                <Pencil className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0 text-[var(--destructive)]"
                onClick={onDelete}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function PresetEditForm({
  preset: t,
  orgId,
  onCancel,
  onSaved,
}: {
  preset: Preset;
  orgId: string;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(t.name);
  const [description, setDescription] = useState(t.description ?? "");
  const [slug, setSlug] = useState(t.slug ?? "");
  const [image, setImage] = useState(t.image ?? "");
  const [cpu, setCpu] = useState(String(t.defaultCpuMillicores));
  const [mem, setMem] = useState(String(t.defaultMemoryMb));
  const [disk, setDisk] = useState(String(t.defaultDiskGb));
  const [ttl, setTtl] = useState(
    t.defaultTtlSeconds ? String(t.defaultTtlSeconds) : "",
  );
  const [installCmd, setInstallCmd] = useState(
    t.defaultSetupConfig?.installCommand ?? "",
  );
  const [startupScript, setStartupScript] = useState(
    t.defaultSetupConfig?.startupScript ?? "",
  );

  const mutation = useConnectMutation(PresetService.method.updatePreset, {
    transport: connectTransport,
    onSuccess: onSaved,
    onError: (error) => toast.error(errorMessage(error)),
  });

  function save() {
    const request: {
      orgId: string;
      presetId: string;
      name?: string;
      description?: string;
      slug?: string;
      image?: string;
      defaultCpuMillicores?: number;
      defaultMemoryMb?: number;
      defaultDiskGb?: number;
      defaultTtlSeconds?: number;
      installCommand?: string;
      startupScript?: string;
    } = { orgId, presetId: t.id };
    if (name !== t.name) request.name = name;
    if (description !== (t.description ?? "")) request.description = description;
    if (slug !== (t.slug ?? "")) request.slug = slug;
    if (image !== (t.image ?? "")) request.image = image;
    const cpuNum = parseInt(cpu);
    if (!isNaN(cpuNum) && cpuNum !== t.defaultCpuMillicores)
      request.defaultCpuMillicores = cpuNum;
    const memNum = parseInt(mem);
    if (!isNaN(memNum) && memNum !== t.defaultMemoryMb)
      request.defaultMemoryMb = memNum;
    const diskNum = parseInt(disk);
    if (!isNaN(diskNum) && diskNum !== t.defaultDiskGb)
      request.defaultDiskGb = diskNum;
    const ttlNum = ttl ? parseInt(ttl) : undefined;
    if (ttlNum !== t.defaultTtlSeconds) request.defaultTtlSeconds = ttlNum;
    if (installCmd !== (t.defaultSetupConfig?.installCommand ?? ""))
      request.installCommand = installCmd;
    if (startupScript !== (t.defaultSetupConfig?.startupScript ?? ""))
      request.startupScript = startupScript;

    mutation.mutate(request);
  }

  return (
    <Card className="border-[var(--accent)]">
      <CardContent className="py-3 space-y-3">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
              Name
            </label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="h-8 text-sm"
            />
          </div>
          <div>
            <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
              Slug
            </label>
            <Input
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              className="h-8 text-sm font-mono"
              placeholder="optional"
            />
          </div>
        </div>

        <div>
          <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
            Description
          </label>
          <Input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="h-8 text-sm"
            placeholder="optional"
          />
        </div>

        <div>
          <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
            Image
          </label>
          <Input
            value={image}
            onChange={(e) => setImage(e.target.value)}
            className="h-8 text-sm font-mono"
            placeholder="e.g. ghcr.io/codewiresh/workspace:latest"
          />
        </div>

        <div className="grid grid-cols-4 gap-2">
          <div>
            <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
              CPU (millicores)
            </label>
            <Input
              type="number"
              value={cpu}
              onChange={(e) => setCpu(e.target.value)}
              className="h-8 text-sm"
            />
          </div>
          <div>
            <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
              Memory (MB)
            </label>
            <Input
              type="number"
              value={mem}
              onChange={(e) => setMem(e.target.value)}
              className="h-8 text-sm"
            />
          </div>
          <div>
            <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
              Disk (GB)
            </label>
            <Input
              type="number"
              value={disk}
              onChange={(e) => setDisk(e.target.value)}
              className="h-8 text-sm"
            />
          </div>
          <div>
            <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
              TTL (seconds)
            </label>
            <Input
              type="number"
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              className="h-8 text-sm"
              placeholder="none"
            />
          </div>
        </div>

        <div>
          <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
            Install command
          </label>
          <Input
            value={installCmd}
            onChange={(e) => setInstallCmd(e.target.value)}
            className="h-8 text-sm font-mono"
            placeholder="e.g. npm install"
          />
        </div>

        <div>
          <label className="text-xs text-[color:var(--fg-secondary)] mb-1 block">
            Startup script
          </label>
          <Input
            value={startupScript}
            onChange={(e) => setStartupScript(e.target.value)}
            className="h-8 text-sm font-mono"
            placeholder="e.g. npm run dev"
          />
        </div>

        <div className="flex items-center gap-2 justify-end">
          {mutation.isError && (
            <span className="text-xs text-[color:var(--destructive)]">
              {errorMessage(mutation.error)}
            </span>
          )}
          <Button variant="ghost" size="sm" onClick={onCancel}>
            <X className="h-3.5 w-3.5 mr-1" />
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={save}
            disabled={mutation.isPending || !name.trim()}
          >
            {mutation.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
            ) : (
              <Check className="h-3.5 w-3.5 mr-1" />
            )}
            Save
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
