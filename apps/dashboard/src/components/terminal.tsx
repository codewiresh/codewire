import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { environmentSetupClient } from "@/lib/connect";
import "@xterm/xterm/css/xterm.css";

const MSG_STDIN = 0x00;
const MSG_RESIZE = 0x01;
const DEFAULT_COLS = 120;
const DEFAULT_ROWS = 32;

function encodeResize(cols: number, rows: number): Uint8Array {
  const buf = new Uint8Array(5);
  buf[0] = MSG_RESIZE;
  buf[1] = (cols >> 8) & 0xff;
  buf[2] = cols & 0xff;
  buf[3] = (rows >> 8) & 0xff;
  buf[4] = rows & 0xff;
  return buf;
}

async function getTerminalTicket(): Promise<string> {
  const { ticket } = await environmentSetupClient.issueTerminalTicket({});
  if (!ticket) throw new Error("Failed to get terminal ticket");
  return ticket;
}

export function TerminalPanel({
  orgId,
  envId,
  isRunning,
  className,
}: {
  orgId: string;
  envId: string;
  isRunning: boolean;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "closed">("connecting");

  useEffect(() => {
    if (!isRunning || !containerRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      theme: {
        background: "#0a0a0a",
        foreground: "#e4e4e7",
        cursor: "#e4e4e7",
        selectionBackground: "#3f3f46",
      },
    });
    termRef.current = term;

    const fit = new FitAddon();
    fitRef.current = fit;
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(containerRef.current);

    // Fit after a frame so the container has dimensions
    requestAnimationFrame(() => fit.fit());

    let cancelled = false;
    setStatus("connecting");

    const sendResize = (cols: number, rows: number) => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      ws.send(encodeResize(
        cols > 0 ? cols : DEFAULT_COLS,
        rows > 0 ? rows : DEFAULT_ROWS,
      ));
    };

    const fitAndSendResize = () => {
      fit.fit();
      sendResize(term.cols, term.rows);
    };

    // In dev, use ticket auth (WS connects cross-port to :8080, no cookies).
    // In prod, use cookie auth directly (same-origin, cookies sent on upgrade).
    const connect = async () => {
      if (cancelled) return;
      try {
        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        let wsUrl: string;
        if (import.meta.env.DEV) {
          const ticket = await getTerminalTicket();
          const host = `${window.location.hostname}:8080`;
          wsUrl = `${proto}//${host}/api/v1/organizations/${orgId}/environments/${envId}/terminal?ticket=${ticket}`;
        } else {
          wsUrl = `${proto}//${window.location.host}/api/v1/organizations/${orgId}/environments/${envId}/terminal`;
        }
        if (cancelled) return;

        const ws = new WebSocket(wsUrl);
        ws.binaryType = "arraybuffer";
        wsRef.current = ws;

        ws.onopen = () => {
          setStatus("connected");
          fitAndSendResize();
          requestAnimationFrame(() => fitAndSendResize());
        };

        ws.onmessage = (ev) => {
          term.write(new Uint8Array(ev.data));
        };

        ws.onclose = () => setStatus("closed");
        ws.onerror = () => setStatus("closed");
      } catch {
        if (!cancelled) setStatus("closed");
      }
    };
    connect();

    // stdin
    const dataDisposable = term.onData((data) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        const encoded = new TextEncoder().encode(data);
        const buf = new Uint8Array(1 + encoded.length);
        buf[0] = MSG_STDIN;
        buf.set(encoded, 1);
        ws.send(buf);
      }
    });

    // resize
    const resizeDisposable = term.onResize(({ cols, rows }) => {
      sendResize(cols, rows);
    });

    // Auto-fit on container resize
    const observer = new ResizeObserver(() => {
      requestAnimationFrame(() => fitAndSendResize());
    });
    observer.observe(containerRef.current);

    return () => {
      cancelled = true;
      observer.disconnect();
      dataDisposable.dispose();
      resizeDisposable.dispose();
      wsRef.current?.close();
      term.dispose();
      termRef.current = null;
      wsRef.current = null;
      fitRef.current = null;
    };
  }, [orgId, envId, isRunning]);

  if (!isRunning) {
    return (
      <div className="flex items-center justify-center h-48 bg-[#0a0a0a] rounded-md border border-[var(--border)]">
        <p className="text-sm text-zinc-500">Environment is not running</p>
      </div>
    );
  }

  return (
    <div className="relative">
      {status === "connecting" && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-[#0a0a0a]/80 rounded-md">
          <p className="text-sm text-zinc-400">Connecting...</p>
        </div>
      )}
      {status === "closed" && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-[#0a0a0a]/80 rounded-md">
          <p className="text-sm text-zinc-500">Connection closed</p>
        </div>
      )}
      <div
        ref={containerRef}
        className={className || "h-80 rounded-md border border-[var(--border)] overflow-hidden"}
      />
    </div>
  );
}
