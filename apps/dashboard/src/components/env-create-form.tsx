import { useState, useMemo, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  createConnectQueryKey,
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import {
  EnvironmentService,
  type CreateEnvironmentRequest,
  type DetectionResult,
  type WatchEnvironmentCreateResponse,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { PresetService, type Preset } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { EnvironmentSetupService } from "@codewire/proto-ts/gen/codewire/console/v1/environment_setup_pb";
import { GitHubService, type GitHubRepo } from "@codewire/proto-ts/gen/codewire/console/v1/github_pb";
import {
  connectTransport,
  environmentClient,
  secretClient,
  secretServiceQueryKey,
} from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { useServerStream } from "@/lib/use-server-stream";
import { AGENT_CATALOG, AGENT_CATALOG_BY_ID } from "@/lib/agents";
import { SecretProjectDialog } from "@/components/secret-project-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Bot,
  Box,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  GitBranch,
  Github,
  KeyRound,
  Lock,
  Loader2,
  Pencil,
  Plus,
  Search,
  Sparkles,
  AlertCircle,
  X,
} from "lucide-react";

const CANONICAL_WORKSPACE_IMAGE = "ghcr.io/codewiresh/workspace:latest";
const DEFAULT_FULL_CPU = "1000";
const DEFAULT_FULL_MEMORY = "2048";
const DEFAULT_FULL_DISK = "10";
const UNIVERSAL_IMAGE_LABEL = "Universal environment image";

const environmentServiceQueryKey = createConnectQueryKey({
  schema: EnvironmentService,
  transport: connectTransport,
  cardinality: undefined,
});

export function EnvCreateForm({
  orgId,
  onCreated,
}: {
  orgId: string;
  onCreated: () => void;
}) {
  const queryClient = useQueryClient();
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"repo" | "image">("repo");
  const [customImage, setCustomImage] = useState("");
  const [imageReady, setImageReady] = useState(false);

  // ── GitHub ──────────────────────────────────────────────────────────
  const { data: environmentCreateOptions } = useConnectQuery(
    EnvironmentSetupService.method.getEnvironmentCreateOptions,
    { orgId },
    { transport: connectTransport },
  );
  const ghStatus = environmentCreateOptions?.githubStatus;
  const ghConnected = ghStatus?.connected ?? false;
  const { data: presetsResponse } = useConnectQuery(
    PresetService.method.listPresets,
    { orgId },
    { transport: connectTransport },
  );
  const allPresets = presetsResponse?.presets ?? [];
  const systemPresets = useMemo(() => allPresets.filter((p) => p.official), [allPresets]);
  const userPresets = useMemo(() => allPresets.filter((p) => !p.official), [allPresets]);

  const { data: ghReposResponse, isLoading: reposLoading } = useConnectQuery(
    GitHubService.method.listGitHubRepos,
    { perPage: 100 },
    { enabled: ghConnected, transport: connectTransport },
  );
  const ghRepos = ghReposResponse?.repos ?? [];
  const { data: userSecretsData } = useConnectQuery(
    SecretService.method.listUserSecrets,
    undefined,
    { transport: connectTransport },
  );

  // ── Repo state ─────────────────────────────────────────────────────
  const [repos, setRepos] = useState<{ url: string; branch: string }[]>([]);
  const [repoSearch, setRepoSearch] = useState("");
  const [showUrlInput, setShowUrlInput] = useState(false);
  const [detection, setDetection] = useState<DetectionResult | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [preparedPresetId, setPreparedPresetId] = useState("");

  // Streaming progress state
  const [preparePhase, setPreparePhase] = useState<string | null>(null);
  const [prepareMessage, setPrepareMessage] = useState("");
  const [repoFetchStatus, setRepoFetchStatus] = useState<Map<number, { repo: string; ok: boolean }>>(new Map());
  const [repoFetchTotal, setRepoFetchTotal] = useState(0);
  const { abort: abortDetect, run: runServerStream } = useServerStream<WatchEnvironmentCreateResponse>();

  // Convenience accessors for primary repo (backward compat).
  const repoUrl = repos[0]?.url ?? "";
  const branch = repos[0]?.branch ?? "";

  // Overrides from detection / preset selection
  const [selectedPresetName, setSelectedPresetName] = useState("");
  const [image, setImage] = useState("");
  const [installCommand, setInstallCommand] = useState("");
  const [startupScript, setStartupScript] = useState("");
  const [cpu, setCpu] = useState(DEFAULT_FULL_CPU);
  const [memory, setMemory] = useState(DEFAULT_FULL_MEMORY);
  const [disk, setDisk] = useState(DEFAULT_FULL_DISK);
  const [ttl, setTTL] = useState("");
  const [name, setName] = useState("");
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [agentSecretValues, setAgentSecretValues] = useState<Record<string, string>>({});
  const [secretProject, setSecretProject] = useState("");
  const [secretProjectDialogOpen, setSecretProjectDialogOpen] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const [showProjectPicker, setShowProjectPicker] = useState(false);
  const [includeOrgSecrets, setIncludeOrgSecrets] = useState(true);
  const [includeUserSecrets, setIncludeUserSecrets] = useState(true);
  const [appPorts, setAppPorts] = useState<{ port: string; label: string; access: string }[]>([]);

  // ── Queries ────────────────────────────────────────────────────────
  const { data: secretProjectsResponse } = useConnectQuery(
    SecretService.method.listSecretProjects,
    { orgId },
    { transport: connectTransport },
  );
  const secretProjects = secretProjectsResponse?.secretProjects ?? [];

  const createProjectMutation = useConnectMutation(SecretService.method.createSecretProject, {
    transport: connectTransport,
    onSuccess: ({ secretProject }) => {
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });
      if (secretProject) setSecretProject(secretProject.name);
      setNewProjectName("");
      setShowProjectPicker(false);
    },
  });

  const filteredRepos = useMemo(() => {
    if (!ghRepos) return [];
    if (!repoSearch) return ghRepos;
    const q = repoSearch.toLowerCase();
    return ghRepos.filter(
      (r) =>
        r.fullName.toLowerCase().includes(q) ||
        (r.description?.toLowerCase().includes(q) ?? false),
    );
  }, [ghRepos, repoSearch]);
  const userSecretKeys = useMemo(
    () => new Set((userSecretsData?.secrets ?? []).map((secret) => secret.key)),
    [userSecretsData],
  );
  const selectedAgentDefs = useMemo(
    () => selectedAgents
      .map((id) => AGENT_CATALOG_BY_ID[id])
      .filter((agent): agent is NonNullable<typeof agent> => Boolean(agent)),
    [selectedAgents],
  );

  // ── Detection (streaming) ───────────────────────────────────────────
  const detectIsPending = preparePhase !== null;

  const applyDraftResult = useCallback((draft: CreateEnvironmentRequest, detection?: DetectionResult) => {
    setDetection(detection ?? null);
    setPreparedPresetId(draft.presetId ?? "");
    if (draft.image) setImage(draft.image);
    if (draft.installCommand) setInstallCommand(draft.installCommand);
    if (draft.startupScript) setStartupScript(draft.startupScript);
    if (draft.cpuMillicores) setCpu(String(draft.cpuMillicores));
    if (draft.memoryMb) setMemory(String(draft.memoryMb));
    if (draft.diskGb) setDisk(String(draft.diskGb));
    if (draft.ttlSeconds) setTTL(`${draft.ttlSeconds}s`);
    if (draft.name) setName(draft.name);
    setSelectedAgents(draft.agents?.map((agent: { type: string }) => agent.type) ?? []);
    setSecretProject(draft.secretProject ?? "");
    setIncludeOrgSecrets(draft.includeOrgSecrets !== false);
    setIncludeUserSecrets(draft.includeUserSecrets !== false);
    setAppPorts(
      draft.appPorts.map((port) => ({ port: String(port.port), label: port.label, access: port.access || "creator" })),
    );
    setShowAdvanced(false);
    setError("");
  }, []);

  function toggleAgent(agentId: string) {
    setSelectedAgents((current) =>
      current.includes(agentId)
        ? current.filter((id) => id !== agentId)
        : [...current, agentId],
    );
  }

  const runDetect = useCallback((analyze: boolean) => {
    const draft = {
      orgId,
      presetSlug: "",
      repoUrl,
      branch,
      repos: repos.length > 1 ? repos.map((repo) => ({ url: repo.url, branch: repo.branch })) : [],
      image: mode === "image" ? image : "",
      installCommand,
      startupScript,
      name: name || undefined,
      envVars: {},
      agents: selectedAgents.map((type) => ({ type })),
      agent: "",
      agentEnv: {},
      secretProject,
      appPorts: appPorts.length > 0
        ? appPorts
            .filter((port) => port.port && port.label)
            .map((port) => ({ port: parseInt(port.port), label: port.label, access: port.access || "creator" }))
        : [],
      includeOrgSecrets: includeOrgSecrets ? undefined : false,
      includeUserSecrets: includeUserSecrets ? undefined : false,
      cpuMillicores: parseInt(cpu) || undefined,
      memoryMb: parseInt(memory) || undefined,
      diskGb: parseInt(disk) || undefined,
      ttlSeconds: parseTTL(ttl),
    };

    setPreparePhase("starting");
    setPrepareMessage("Preparing...");
    setRepoFetchStatus(new Map());
    setRepoFetchTotal(0);
    setError("");

    runServerStream({
      stream: (signal) => environmentClient.watchEnvironmentCreate({ orgId, draft, analyze }, { signal }),
      onMessage: ({ event }) => {
        switch (event.case) {
          case "progress":
            setPreparePhase(event.value.phase);
            if (event.value.message) setPrepareMessage(event.value.message);
            if (event.value.total) setRepoFetchTotal(event.value.total);
            break;
          case "repoFetched":
            setRepoFetchStatus((previous) => {
              const next = new Map(previous);
              next.set(event.value.index, { repo: event.value.repo, ok: event.value.ok });
              return next;
            });
            break;
          case "complete":
            setPreparePhase(null);
            setPrepareMessage("");
            if (!event.value.draft) {
              setError("Environment preparation completed without a draft");
              return;
            }
            applyDraftResult(event.value.draft, event.value.detection);
            break;
        }
      },
      onError: (error) => {
        setPreparePhase(null);
        setPrepareMessage("");
        setError(errorMessage(error));
      },
    });
  }, [orgId, repoUrl, branch, repos, mode, image, installCommand, startupScript, name, cpu, memory, ttl, selectedAgents, secretProject, includeOrgSecrets, includeUserSecrets, appPorts, applyDraftResult, runServerStream]);

  const resetDetect = useCallback(() => {
    abortDetect();
    setPreparePhase(null);
    setPrepareMessage("");
    setRepoFetchStatus(new Map());
    setRepoFetchTotal(0);
  }, [abortDetect]);

  function selectPreset(preset: Preset) {
    setImage(preset.image ?? "");
    setSelectedPresetName(preset.name);
    setPreparedPresetId(preset.id);
    if (preset.defaultCpuMillicores) setCpu(String(preset.defaultCpuMillicores));
    if (preset.defaultMemoryMb) setMemory(String(preset.defaultMemoryMb));
    if (preset.defaultDiskGb) setDisk(String(preset.defaultDiskGb));
    if (preset.defaultTtlSeconds) setTTL(`${preset.defaultTtlSeconds}s`);
    if (preset.defaultSetupConfig?.installCommand) setInstallCommand(preset.defaultSetupConfig.installCommand);
    if (preset.defaultSetupConfig?.startupScript) setStartupScript(preset.defaultSetupConfig.startupScript);
    setSelectedAgents(preset.defaultSetupConfig?.agents?.map((agent) => agent.type) ?? []);
    setImageReady(true);
    setError("");
  }

  function selectUniversalImage() {
    setImage(CANONICAL_WORKSPACE_IMAGE);
    setSelectedPresetName(UNIVERSAL_IMAGE_LABEL);
    setPreparedPresetId("");
    setCpu(DEFAULT_FULL_CPU);
    setMemory(DEFAULT_FULL_MEMORY);
    setDisk(DEFAULT_FULL_DISK);
    setTTL("");
    setInstallCommand("");
    setStartupScript("");
    setSelectedAgents([]);
    setImageReady(true);
    setError("");
  }

  function selectCustomImage() {
    if (!customImage.trim()) return;
    setImage(customImage.trim());
    setSelectedPresetName("");
    setName("");
    setPreparedPresetId("");
    setImageReady(true);
    setError("");
  }

  function toggleRepo(repo: GitHubRepo) {
    const exists = repos.find((r) => r.url === repo.htmlUrl);
    if (exists) {
      setRepos(repos.filter((r) => r.url !== repo.htmlUrl));
    } else {
      setRepos([...repos, { url: repo.htmlUrl, branch: "" }]);
    }
    setDetection(null);
    setPreparedPresetId("");
    setError("");
  }

  function confirmRepoSelection() {
    if (repos.length > 0) {
      runDetect(true);
    }
  }

  // ── Create (smart) ─────────────────────────────────────────────────
  const createMutation = useConnectMutation(EnvironmentService.method.createEnvironment, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: environmentServiceQueryKey });
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });
      resetState();
      onCreated();
    },
  });

  async function submitEnvironment() {
    setError("");
    try {
      for (const key of Object.keys(agentSecretValues)) {
        const value = agentSecretValues[key]?.trim();
        if (value && !userSecretKeys.has(key)) {
          await secretClient.setUserSecret({ key, value });
        }
      }

      await createMutation.mutateAsync({
        orgId,
        presetId: preparedPresetId || undefined,
        presetSlug: "",
        repoUrl,
        branch,
        repos: repos.length > 1 ? repos.map((r) => ({ url: r.url, branch: r.branch })) : [],
        image,
        installCommand,
        startupScript,
        name: name || undefined,
        envVars: {},
        agents: selectedAgents.map((type) => ({ type })),
        agent: "",
        agentEnv: {},
        secretProject,
        appPorts: appPorts.length > 0
          ? appPorts
              .filter((p) => p.port && p.label)
              .map((p) => ({ port: parseInt(p.port), label: p.label, access: p.access || "creator" }))
          : [],
        includeOrgSecrets: includeOrgSecrets ? undefined : false,
        includeUserSecrets: includeUserSecrets ? undefined : false,
        cpuMillicores: parseInt(cpu) || undefined,
        memoryMb: parseInt(memory) || undefined,
        diskGb: parseInt(disk) || undefined,
        ttlSeconds: parseTTL(ttl),
      });
    } catch (error) {
      setError(errorMessage(error));
    }
  }

  function resetState() {
    setMode("repo");
    setCustomImage(""); setImageReady(false);
    setSelectedPresetName("");
    setRepos([]); setRepoSearch("");
    setShowUrlInput(false); setDetection(null);
    setPreparedPresetId("");
    setImage(""); setInstallCommand(""); setStartupScript("");
    setCpu(DEFAULT_FULL_CPU); setMemory(DEFAULT_FULL_MEMORY); setDisk(DEFAULT_FULL_DISK); setTTL("");
    setName(""); setSelectedAgents([]); setAgentSecretValues({}); setSecretProject("");
    setSecretProjectDialogOpen(false); setNewProjectName(""); setShowProjectPicker(false);
    setIncludeOrgSecrets(true); setIncludeUserSecrets(true); setAppPorts([]);
    setShowAdvanced(false);
    setError("");
  }

  const isPending = createMutation.isPending;

  return (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Create Environment</CardTitle>
        {/* GitHub status */}
        <GitHubBanner connected={ghConnected} username={ghStatus?.username} />
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="p-3 rounded-md bg-[var(--destructive)]/10 border border-[var(--destructive)]/20 flex items-start gap-2">
            <AlertCircle className="h-4 w-4 text-[var(--destructive)] mt-0.5 shrink-0" />
            <p className="text-sm text-[var(--destructive)]">{error}</p>
          </div>
        )}

        {/* ── Mode tabs ──────────────────────────────────────────── */}
        <div className="flex rounded-md border border-[var(--border-subtle)] overflow-hidden">
          <button
            onClick={() => { setMode("repo"); setImageReady(false); setImage(""); setCustomImage(""); setSelectedPresetName(""); if (showUrlInput && repos.length === 0) setRepos([{ url: "", branch: "" }]); }}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium transition-colors cursor-pointer ${
              mode === "repo"
                ? "bg-[var(--bg-surface)] text-[color:var(--fg-primary)]"
                : "text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)]"
            }`}
          >
            <GitBranch className="h-3.5 w-3.5" />
            From Repository
          </button>
          <button
            onClick={() => { setMode("image"); setRepos([]); setDetection(null); setPreparedPresetId(""); }}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium transition-colors cursor-pointer ${
              mode === "image"
                ? "bg-[var(--bg-surface)] text-[color:var(--fg-primary)]"
                : "text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)]"
            }`}
          >
            <Box className="h-3.5 w-3.5" />
            From Image
          </button>
        </div>

        {/* ── Image mode: preset selector ────────────────────── */}
        {mode === "image" && !imageReady && (
          <div className="space-y-3">
            <button
              type="button"
              onClick={selectUniversalImage}
              className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-3 text-left cursor-pointer hover:border-[var(--border)] transition-colors"
            >
              <div className="flex items-start gap-3">
                <Box className="h-4 w-4 mt-0.5 text-[color:var(--fg-tertiary)] shrink-0" />
                <div className="min-w-0">
                  <div className="text-sm font-medium text-[color:var(--fg-primary)]">
                    {UNIVERSAL_IMAGE_LABEL}
                  </div>
                  <div className="text-xs text-[color:var(--fg-tertiary)] font-mono mt-0.5 break-all">
                    {CANONICAL_WORKSPACE_IMAGE}
                  </div>
                </div>
              </div>
            </button>
            <Select onValueChange={(val) => {
              const preset = allPresets?.find((p) => p.id === val);
              if (preset) selectPreset(preset);
            }}>
              <SelectTrigger>
                <SelectValue placeholder="Select a preset (optional)..." />
              </SelectTrigger>
              <SelectContent>
                {systemPresets.length > 0 && (
                  <SelectGroup>
                    <SelectLabel>System</SelectLabel>
                    {systemPresets.map((p) => (
                      <SelectItem key={p.id} value={p.id} textValue={p.name}>
                        <div className="flex min-w-0 flex-col">
                          <span>{p.name}</span>
                          {p.description && (
                            <span className="text-[color:var(--fg-tertiary)] text-xs truncate">
                              {p.description}
                            </span>
                          )}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectGroup>
                )}
                {userPresets.length > 0 && (
                  <>
                    {systemPresets.length > 0 && <SelectSeparator />}
                    <SelectGroup>
                      <SelectLabel>Your Presets</SelectLabel>
                      {userPresets.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          {p.name}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </>
                )}
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2">
              <Input
                placeholder="Custom image (e.g. ghcr.io/org/image:tag)"
                value={customImage}
                onChange={(e) => setCustomImage(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && selectCustomImage()}
                className="flex-1"
              />
              <Button
                onClick={selectCustomImage}
                disabled={!customImage.trim()}
                variant="outline"
                size="sm"
              >
                Use
              </Button>
            </div>
          </div>
        )}

        {/* ── Image mode: selected preset/image bar ───────────── */}
        {mode === "image" && imageReady && (
          <div className="flex items-center gap-2 rounded-md border border-[var(--border-subtle)] px-3 py-2 bg-[var(--bg-surface)]">
            <Box className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-[color:var(--fg-primary)] truncate">
                {selectedPresetName || image}
              </div>
              {selectedPresetName && (
                <div className="text-xs text-[color:var(--fg-tertiary)] font-mono truncate">
                  {image}
                </div>
              )}
            </div>
            <button
              onClick={() => { setImageReady(false); setImage(""); setCustomImage(""); setSelectedPresetName(""); setPreparedPresetId(""); }}
              className="text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* ── Repo mode: source selection ────────────────────────── */}
        {mode === "repo" && !detection && !detectIsPending && (
          <>
            {ghConnected && !showUrlInput ? (
              <div className="space-y-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[color:var(--fg-tertiary)]" />
                  <Input
                    placeholder="Search your repositories..."
                    value={repoSearch}
                    onChange={(e) => setRepoSearch(e.target.value)}
                    className="pl-9"
                  />
                </div>
                <div className="max-h-56 overflow-y-auto rounded-md border border-[var(--border-subtle)]">
                  {reposLoading ? (
                    <div className="flex items-center justify-center py-8 text-sm text-[color:var(--fg-tertiary)]">
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Loading...
                    </div>
                  ) : filteredRepos.length === 0 ? (
                    <div className="py-6 text-center text-sm text-[color:var(--fg-tertiary)]">
                      {repoSearch ? "No matching repos" : "No repos found"}
                    </div>
                  ) : (
                    filteredRepos.map((repo) => {
                      const isSelected = repos.some((r) => r.url === repo.htmlUrl);
                      return (
                        <button
                          key={repo.fullName}
                          onClick={() => toggleRepo(repo)}
                          className={`w-full text-left px-3 py-2 hover:bg-[var(--bg-surface)] transition-colors border-b border-[var(--border-subtle)] last:border-b-0 cursor-pointer ${isSelected ? "bg-[var(--bg-surface)]" : ""}`}
                        >
                          <div className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              checked={isSelected}
                              readOnly
                              className="rounded border-[var(--border)] shrink-0"
                            />
                            <Github className="h-3.5 w-3.5 text-[color:var(--fg-tertiary)] shrink-0" />
                            <span className="text-sm font-medium text-[color:var(--fg-primary)] truncate">
                              {repo.fullName}
                            </span>
                            {repo.private && <Lock className="h-3 w-3 text-[color:var(--fg-tertiary)] shrink-0" />}
                            {repo.language && (
                              <span className="text-xs text-[color:var(--fg-tertiary)] ml-auto shrink-0">{repo.language}</span>
                            )}
                          </div>
                          {repo.description && (
                            <p className="text-xs text-[color:var(--fg-tertiary)] mt-0.5 truncate pl-7">{repo.description}</p>
                          )}
                        </button>
                      );
                    })
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <button
                    onClick={() => { setShowUrlInput(true); if (repos.length === 0) setRepos([{ url: "", branch: "" }]); }}
                    className="text-xs text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                  >
                    Paste a URL instead
                  </button>
                  {repos.length > 0 && (
                    <Button
                      onClick={confirmRepoSelection}
                      disabled={detectIsPending}
                      size="sm"
                    >
                      {detectIsPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                      ) : (
                        <Sparkles className="h-3.5 w-3.5 mr-1" />
                      )}
                      Continue with {repos.length} repo{repos.length > 1 ? "s" : ""}
                    </Button>
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label>Repository URLs</Label>
                  {ghConnected && (
                    <button
                      onClick={() => setShowUrlInput(false)}
                      className="text-xs text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                    >
                      Pick from list
                    </button>
                  )}
                </div>
                {repos.map((repo, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <div className="flex-1 space-y-1">
                      <Input
                        placeholder="https://github.com/owner/repo"
                        value={repo.url}
                        onChange={(e) => {
                          const next = [...repos];
                          next[i] = { ...next[i], url: e.target.value };
                          setRepos(next);
                        }}
                        autoFocus={i === 0}
                      />
                      <Input
                        placeholder="Branch (optional)"
                        value={repo.branch}
                        onChange={(e) => {
                          const next = [...repos];
                          next[i] = { ...next[i], branch: e.target.value };
                          setRepos(next);
                        }}
                        className="h-7 text-xs"
                      />
                    </div>
                    {repos.length > 1 && (
                      <button
                        type="button"
                        onClick={() => {
                          setRepos(repos.filter((_, j) => j !== i));
                          setDetection(null);
                          setPreparedPresetId("");
                        }}
                        className="mt-2 text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ))}
                <button
                  type="button"
                  onClick={() => setRepos([...repos, { url: "", branch: "" }])}
                  className="flex items-center gap-1 text-xs text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                >
                  <Plus className="h-3 w-3" />Add another repo
                </button>
                <Button
                  onClick={() => {
                    const valid = repos.filter((r) => r.url.trim());
                    if (valid.length > 0) {
                      setRepos(valid);
                      runDetect(true);
                    }
                  }}
                  disabled={!repos.some((r) => r.url.trim()) || detectIsPending}
                  className="w-full"
                >
                  {detectIsPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Analyzing...</>
                  ) : (
                    <><Sparkles className="h-4 w-4 mr-2" />Analyze</>
                  )}
                </Button>
              </div>
            )}
          </>
        )}

        {/* ── Repo mode: selected repo bar(s) ──────────────────────── */}
        {mode === "repo" && repoUrl && (detection || detectIsPending) && (
          <>
            <div className="space-y-1">
              {repos.map((repo, i) => (
                <div key={i} className="flex items-center gap-2 rounded-md border border-[var(--border-subtle)] px-3 py-2 bg-[var(--bg-surface)]">
                  {repo.url.includes("github.com") ? (
                    <Github className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                  ) : (
                    <GitBranch className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                  )}
                  <span className="text-sm font-medium text-[color:var(--fg-primary)] truncate flex-1">
                    {repo.url.replace(/^https?:\/\/[^/]+\//, "")}
                    {repo.branch && <span className="text-[color:var(--fg-tertiary)]"> @ {repo.branch}</span>}
                  </span>
                  {repos.length > 1 && (
                    <button
                      onClick={() => {
                        const next = repos.filter((_, j) => j !== i);
                        setRepos(next);
                        setPreparedPresetId("");
                        if (next.length === 0) { setDetection(null); setError(""); resetDetect(); }
                      }}
                      className="text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
            <button
              onClick={() => { setRepos([]); setDetection(null); setPreparedPresetId(""); setError(""); resetDetect(); }}
              className="text-xs text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
            >
              Clear all
            </button>

            {detectIsPending && (
              <div className="rounded-md border border-[var(--border-subtle)] px-3 py-3 bg-[var(--bg-surface)] space-y-2">
                <div className="flex items-center gap-3">
                  <Loader2 className="h-4 w-4 animate-spin text-[color:var(--fg-tertiary)] shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-[color:var(--fg-primary)]">{prepareMessage || "Analyzing repository..."}</p>
                    {preparePhase === "repo_fetch" && repoFetchTotal === 0 && (
                      <p className="text-xs text-[color:var(--fg-tertiary)]">Detecting language, framework, and configuration</p>
                    )}
                  </div>
                </div>
                {repoFetchTotal > 0 && (
                  <div className="pl-7 space-y-1">
                    {repos.map((repo, i) => {
                      const status = repoFetchStatus.get(i);
                      return (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          {status == null ? (
                            <Loader2 className="h-3 w-3 animate-spin text-[color:var(--fg-tertiary)]" />
                          ) : status.ok ? (
                            <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                          ) : (
                            <AlertCircle className="h-3 w-3 text-amber-500" />
                          )}
                          <span className="text-[color:var(--fg-secondary)] truncate">
                            {repo.url.replace(/^https?:\/\/[^/]+\//, "")}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {!detection && !detectIsPending && (
              <Button
                onClick={() => runDetect(true)}
                disabled={detectIsPending}
                className="w-full"
              >
                <Sparkles className="h-4 w-4 mr-2" />Analyze
              </Button>
            )}
          </>
        )}

        {/* ── Repo mode: detection summary ───────────────────────── */}
        {mode === "repo" && detection && (
          <div className="rounded-md border border-[var(--border-subtle)] p-3 space-y-2">
            <p className="text-xs text-[color:var(--fg-tertiary)]">{detection.setupNotes}</p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
              <Detail label="Image" value={detection.presetImage.split("/").pop() || detection.presetImage} />
              <Detail label="Type" value={detection.projectType} />
              <Detail label="Docker" value={detection.needsDocker ? "Yes" : "No"} />
              <Detail label="Compose" value={detection.hasCompose ? "Yes" : "No"} />
            </div>
          </div>
        )}

        {/* ── Shared config (both modes) ─────────────────────────── */}
        {((mode === "repo" && detection) || (mode === "image" && imageReady)) && (
          <>
            {/* ── Ports ───────────────────────────────────────── */}
            <div className="rounded-md border border-[var(--border-subtle)] p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Ports</span>
                <button
                  type="button"
                  onClick={() => setAppPorts([...appPorts, { port: "", label: "", access: "creator" }])}
                  className="flex items-center gap-1 text-xs text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                >
                  <Plus className="h-3 w-3" />Add
                </button>
              </div>
              {appPorts.length === 0 && (
                <p className="text-xs text-[color:var(--fg-tertiary)]">No ports configured</p>
              )}
              {appPorts.map((p, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    type="number"
                    placeholder="Port"
                    value={p.port}
                    onChange={(e) => {
                      const next = [...appPorts];
                      next[i] = { ...next[i], port: e.target.value };
                      setAppPorts(next);
                    }}
                    className="h-7 text-sm w-20"
                  />
                  <Input
                    placeholder="Label (e.g. web)"
                    value={p.label}
                    onChange={(e) => {
                      const next = [...appPorts];
                      next[i] = { ...next[i], label: e.target.value };
                      setAppPorts(next);
                    }}
                    className="h-7 text-sm flex-1"
                  />
                  <Select
                    value={p.access}
                    onValueChange={(v) => {
                      const next = [...appPorts];
                      next[i] = { ...next[i], access: v };
                      setAppPorts(next);
                    }}
                  >
                    <SelectTrigger className="h-7 w-24 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="creator">Creator</SelectItem>
                      <SelectItem value="org_members">Org</SelectItem>
                      <SelectItem value="public">Public</SelectItem>
                    </SelectContent>
                  </Select>
                  <button
                    type="button"
                    onClick={() => setAppPorts(appPorts.filter((_, j) => j !== i))}
                    className="text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>

            {/* ── Agents ─────────────────────────────────────────── */}
            <div className="rounded-md border border-[var(--border-subtle)] p-3 space-y-3">
              <div className="flex items-center gap-2">
                <Bot className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
                <span className="text-sm font-medium">Agents</span>
              </div>
              <p className="text-xs text-[color:var(--fg-tertiary)]">
                Pick the tools this environment should have. Selected agent credentials are read from user secrets by default.
              </p>
              <div className="flex flex-wrap gap-2">
                {AGENT_CATALOG.map((agent) => {
                  const selected = selectedAgents.includes(agent.id);
                  return (
                    <button
                      key={agent.id}
                      type="button"
                      onClick={() => toggleAgent(agent.id)}
                      className={`rounded-md border px-3 py-1.5 text-sm transition-colors cursor-pointer ${
                        selected
                          ? "border-[var(--accent)] bg-[var(--accent)]/10 text-[color:var(--fg-primary)]"
                          : "border-[var(--border-subtle)] text-[color:var(--fg-secondary)] hover:bg-[var(--bg-surface)]"
                      }`}
                    >
                      {agent.label}
                    </button>
                  );
                })}
              </div>

              {selectedAgentDefs.length > 0 && (
                <div className="space-y-3 pt-1 border-t border-[var(--border-subtle)]">
                  {selectedAgentDefs.map((agent) => (
                    <div key={agent.id} className="rounded-md border border-[var(--border-subtle)] p-3 space-y-2">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-sm font-medium text-[color:var(--fg-primary)]">{agent.label}</div>
                          <div className="text-xs text-[color:var(--fg-tertiary)]">
                            Included in the canonical workspace image. Custom images must provide it.
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => toggleAgent(agent.id)}
                          className="text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>

                      {agent.envVars.map((envVar) => {
                        const isSaved = userSecretKeys.has(envVar.key);
                        return (
                          <div key={`${agent.id}-${envVar.key}`} className="rounded-md border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-2 space-y-2">
                            <div className="flex items-start justify-between gap-3">
                              <div>
                                <div className="text-xs font-mono text-[color:var(--fg-primary)]">{envVar.key}</div>
                                <div className="text-xs text-[color:var(--fg-tertiary)]">{envVar.label}</div>
                              </div>
                              <span className={`text-[11px] ${
                                isSaved
                                  ? "text-[color:var(--success)]"
                                  : "text-[color:var(--fg-tertiary)]"
                              }`}>
                                {isSaved ? "Saved in user secrets" : "Missing from user secrets"}
                              </span>
                            </div>

                            {!isSaved && (
                              <div className="space-y-1">
                                <Input
                                  type="password"
                                  placeholder={envVar.placeholder || envVar.key}
                                  value={agentSecretValues[envVar.key] ?? ""}
                                  onChange={(e) => setAgentSecretValues((current) => ({
                                    ...current,
                                    [envVar.key]: e.target.value,
                                  }))}
                                  className="h-8 text-sm font-mono"
                                />
                                <div className="text-[11px] text-[color:var(--fg-tertiary)]">
                                  Saved to your user secrets when you create the environment.
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex flex-col gap-2 pt-1 border-t border-[var(--border-subtle)]">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeUserSecrets}
                    onChange={(e) => setIncludeUserSecrets(e.target.checked)}
                    className="rounded border-[var(--border)]"
                  />
                  <span className="text-[color:var(--fg-secondary)]">Include user secrets</span>
                  <span className="text-xs text-[color:var(--fg-tertiary)]">
                    Injects saved agent credentials and other personal secrets.
                  </span>
                </label>
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeOrgSecrets}
                    onChange={(e) => setIncludeOrgSecrets(e.target.checked)}
                    className="rounded border-[var(--border)]"
                  />
                  <span className="text-[color:var(--fg-secondary)]">Include org secrets</span>
                </label>
              </div>
            </div>

            {/* ── Secrets selector ──────────────────────────────── */}
            {(() => {
              const selectedProject = secretProjects.find((p) => p.name === secretProject);
              return (
                <div className="space-y-2">
                  <Label>Secret Project</Label>
                  {selectedProject ? (
                    <div className="flex items-center gap-2 rounded-md border border-[var(--border-subtle)] px-3 py-2 bg-[var(--bg-surface)]">
                      <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                      <span className="text-sm font-medium text-[color:var(--fg-primary)] truncate flex-1">
                        {selectedProject.name}
                      </span>
                      <span className="text-xs text-[color:var(--fg-tertiary)]">
                        {selectedProject.secretCount.toString()} secret{selectedProject.secretCount === 1n ? "" : "s"}
                      </span>
                      <button
                        type="button"
                        onClick={() => setSecretProjectDialogOpen(true)}
                        className="text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => { setSecretProject(""); setShowProjectPicker(false); }}
                        className="text-[color:var(--fg-tertiary)] hover:text-[color:var(--fg-secondary)] cursor-pointer"
                      >
                        <X className="h-4 w-4" />
                      </button>
                      <SecretProjectDialog
                        orgId={orgId}
                        projectId={selectedProject.id}
                        projectName={selectedProject.name}
                        open={secretProjectDialogOpen}
                        onClose={() => setSecretProjectDialogOpen(false)}
                      />
                    </div>
                  ) : (
                    <>
                      <button
                        type="button"
                        onClick={() => setShowProjectPicker(!showProjectPicker)}
                        className="w-full flex items-center justify-between rounded-md border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[color:var(--fg-tertiary)] cursor-pointer"
                      >
                        <span>Select a secret project...</span>
                        <ChevronDown className="h-4 w-4" />
                      </button>
                      {showProjectPicker && (
                        <div className="rounded-md border border-[var(--border-subtle)] overflow-hidden">
                          {secretProjects.map((p) => (
                            <button
                              key={p.id}
                              type="button"
                              onClick={() => { setSecretProject(p.name); setShowProjectPicker(false); }}
                              className="w-full text-left px-3 py-2 hover:bg-[var(--bg-surface)] transition-colors border-b border-[var(--border-subtle)] last:border-b-0 cursor-pointer flex items-center justify-between"
                            >
                              <div className="flex items-center gap-2">
                                <KeyRound className="h-3.5 w-3.5 text-[color:var(--fg-tertiary)]" />
                                <span className="text-sm font-medium text-[color:var(--fg-primary)]">{p.name}</span>
                              </div>
                              <span className="text-xs text-[color:var(--fg-tertiary)]">
                                {p.secretCount.toString()} secret{p.secretCount === 1n ? "" : "s"}
                              </span>
                            </button>
                          ))}
                          <div className="border-t border-[var(--border-subtle)] px-3 py-2 bg-[var(--bg-surface)]">
                            <form
                              className="flex items-center gap-2"
                              onSubmit={(e) => {
                                e.preventDefault();
                                if (newProjectName.trim()) {
                                  createProjectMutation.mutate({
                                    orgId,
                                    name: newProjectName.trim(),
                                  });
                                }
                              }}
                            >
                              <Plus className="h-3.5 w-3.5 text-[color:var(--fg-tertiary)] shrink-0" />
                              <Input
                                placeholder="New project name"
                                value={newProjectName}
                                onChange={(e) => setNewProjectName(e.target.value)}
                                className="h-7 text-sm flex-1"
                              />
                              <Button
                                type="submit"
                                size="sm"
                                variant="outline"
                                disabled={!newProjectName.trim() || createProjectMutation.isPending}
                                className="h-7 text-xs"
                              >
                                {createProjectMutation.isPending ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  "Create"
                                )}
                              </Button>
                            </form>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              );
            })()}

            {/* ── Advanced ──────────────────────────────────────── */}
            <div className="rounded-md border border-[var(--border-subtle)]">
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center gap-2 w-full text-left p-3 cursor-pointer"
              >
                {showAdvanced ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                <span className="text-sm font-medium">Advanced</span>
              </button>
              {showAdvanced && (
                <div className="px-3 pb-3 space-y-3 border-t border-[var(--border-subtle)] pt-3">
                  <Field id="env-name" label="Name" value={name} onChange={setName} placeholder="Environment name" />
                  <Field id="env-image" label="Image" value={image} onChange={(v) => { setImage(v); setPreparedPresetId(""); }} placeholder="Container image" />
                  <Field id="env-install" label="Install Command" value={installCommand} onChange={setInstallCommand} placeholder="e.g. bun install" />
                  <div>
                    <Label htmlFor="env-startup">Startup Script</Label>
                    <textarea
                      id="env-startup"
                      value={startupScript}
                      onChange={(e) => setStartupScript(e.target.value)}
                      rows={3}
                      className="w-full rounded-md border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm font-mono resize-y"
                      placeholder="Post-install commands..."
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <SelectField id="env-cpu" label="CPU" value={cpu} onChange={setCpu}
                      options={[["1000","1 Core"],["2000","2 Cores"],["4000","4 Cores"],["8000","8 Cores"]]} />
                    <SelectField id="env-memory" label="Memory" value={memory} onChange={setMemory}
                      options={[["2048","2 GB"],["4096","4 GB"],["8192","8 GB"],["16384","16 GB"]]} />
                  </div>
                  <Field id="env-disk" label="Disk (GB)" value={disk} onChange={setDisk} placeholder="e.g. 10" />
                  <Field id="env-ttl" label="TTL" value={ttl} onChange={setTTL} placeholder="e.g. 1h, 30m" />
                </div>
              )}
            </div>

            <Button onClick={() => void submitEnvironment()} disabled={isPending} className="w-full">
              {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create Environment"}
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ── Small components ────────────────────────────────────────────────────

function GitHubBanner({ connected, username }: { connected: boolean; username?: string }) {
  if (connected) {
    return (
      <div className="flex items-center gap-2 mt-2 text-xs text-[color:var(--fg-secondary)]">
        <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
        GitHub connected as <span className="font-medium">@{username}</span>
      </div>
    );
  }
  return (
    <div className="flex items-center justify-between mt-2 px-3 py-2 rounded-md bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
      <div className="flex items-center gap-2 text-xs text-[color:var(--fg-secondary)]">
        <Github className="h-3.5 w-3.5" />
        Connect GitHub for private repos
      </div>
      <a
        href={`/api/v1/github/oauth/authorize?return_url=${encodeURIComponent(window.location.href)}`}
        className="text-xs font-medium text-[color:var(--fg-primary)] hover:underline"
      >
        Connect
      </a>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-[color:var(--fg-tertiary)]">{label}:</span>{" "}
      <span className="font-medium">{value}</span>
    </div>
  );
}

function Field({ id, label, value, onChange, placeholder }: {
  id: string; label: string; value: string; onChange: (v: string) => void; placeholder: string;
}) {
  return (
    <div>
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}

function SelectField({ label, value, onChange, options }: {
  id?: string; label: string; value: string; onChange: (v: string) => void; options: string[][];
}) {
  return (
    <div>
      <Label>{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([v, l]) => <SelectItem key={v} value={v}>{l}</SelectItem>)}
        </SelectContent>
      </Select>
    </div>
  );
}

function parseTTL(ttl: string): number | undefined {
  if (!ttl) return undefined;
  const match = ttl.match(/^(\d+)(h|m|s)?$/);
  if (!match) return undefined;
  const val = parseInt(match[1]);
  const unit = match[2] || "m";
  return unit === "h" ? val * 3600 : unit === "m" ? val * 60 : val;
}
