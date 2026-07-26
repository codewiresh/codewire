import { createFileRoute, redirect } from "@tanstack/react-router";
import { useQuery as useConnectQuery } from "@connectrpc/connect-query";
import {
  EnvironmentService,
  EnvironmentState,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { getSession } from "@/lib/auth";
import { connectTransport } from "@/lib/connect";
import { TerminalPanel } from "@/components/terminal";
import { ArrowLeft, Cpu, HardDrive, MemoryStick } from "lucide-react";

export const Route = createFileRoute("/terminal/$orgId/$envId")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
  },
  component: TerminalPage,
});

function environmentStateName(state: EnvironmentState): string {
  const enumName = EnvironmentState[state];
  return enumName && enumName !== "UNSPECIFIED" ? enumName.toLowerCase() : "unknown";
}

function TerminalPage() {
  const { orgId, envId } = Route.useParams();

  const { data: environmentResponse } = useConnectQuery(
    EnvironmentService.method.getEnvironment,
    { orgId, environmentId: envId },
    { transport: connectTransport },
  );
  const env = environmentResponse?.environment;
  const state = env ? environmentStateName(env.state) : undefined;

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0a]">
      <div className="flex items-center gap-3 px-4 py-2 border-b border-zinc-800 shrink-0">
        <button
          onClick={() => window.history.back()}
          className="text-zinc-400 hover:text-zinc-200"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <span className="text-sm font-medium text-zinc-200">
          {env?.name || envId.slice(0, 8)}
        </span>
        {env && (
          <span
            className={`text-[10px] px-1.5 py-0.5 rounded-full border ${
              state === "running"
                ? "text-emerald-400 border-emerald-400/30"
                : "text-zinc-500 border-zinc-700"
            }`}
          >
            {state}
          </span>
        )}
      </div>
      <div className="flex-1 min-h-0">
        <TerminalPanel
          orgId={orgId}
          envId={envId}
          isRunning={state === "running"}
          className="h-full overflow-hidden"
        />
      </div>
      {env && (
        <div className="flex items-center gap-6 px-4 py-1.5 border-t border-zinc-800 shrink-0 text-[11px] text-zinc-500 font-mono">
          <div className="flex items-center gap-1.5">
            <Cpu className="h-3 w-3" />
            <span>{(env.cpuMillicores / 1000).toFixed(1)} CPU</span>
          </div>
          <div className="flex items-center gap-1.5">
            <MemoryStick className="h-3 w-3" />
            <span>{(env.memoryMb / 1024).toFixed(1)} GB RAM</span>
          </div>
          <div className="flex items-center gap-1.5">
            <HardDrive className="h-3 w-3" />
            <span>{env.diskGb} GB Disk</span>
          </div>
        </div>
      )}
    </div>
  );
}
