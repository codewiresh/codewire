import { createFileRoute, Link, redirect } from "@tanstack/react-router";
import { ArrowRight } from "lucide-react";
import { useEffect, useState } from "react";

export const Route = createFileRoute("/")({
  beforeLoad: async ({ context }) => {
    if (context.session?.user) {
      throw redirect({ to: "/dashboard" });
    }
  },
  component: HomePage,
});

const colors = ["#EF4444", "#0EA5E9", "#3B82F6", "#8B5CF6", "#EAB308"];

function HomePage() {
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % 5);
    }, 2500);
    return () => clearInterval(interval);
  }, []);

  return (
    <>
      {/* ── 1. Hero ── */}
      <section className="relative overflow-hidden dot-bg" style={{ padding: "120px 24px 100px" }}>
        <div
          className="absolute pointer-events-none"
          style={{
            top: "-50%",
            left: "50%",
            transform: "translateX(-50%)",
            width: "800px",
            height: "800px",
            background: "radial-gradient(circle, rgba(14,165,233,0.06) 0%, transparent 70%)",
          }}
        />
        <div className="max-w-[900px] mx-auto text-center relative">
          <h1
            className="mb-7"
            style={{
              fontWeight: 510,
              fontSize: "clamp(2rem, 6vw, 3.5rem)",
              lineHeight: 1.1,
              letterSpacing: "-0.022em",
            }}
          >
            <span style={{ display: "block" }}>Give every AI agent</span>
            <span style={{ display: "block", color: "var(--accent)" }}>its own machine.</span>
          </h1>
          <p
            className="mx-auto mb-12"
            style={{
              fontSize: "1.25rem",
              color: "var(--fg-secondary)",
              maxWidth: "640px",
              lineHeight: 1.7,
            }}
          >
            Run Claude Code, Codex, or any AI tool on dedicated cloud environments. Run them in parallel. Check in tomorrow.
          </p>
          <div className="flex gap-4 justify-center flex-wrap">
            <a
              href="#cta"
              className="inline-flex items-center gap-2 rounded-lg transition-all duration-150 no-underline"
              style={{
                fontSize: "13px",
                fontWeight: 510,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                padding: "12px 28px",
                background: "var(--accent)",
                color: "#000",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "var(--accent-hover)";
                e.currentTarget.style.transform = "translateY(-1px)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "var(--accent)";
                e.currentTarget.style.transform = "translateY(0)";
              }}
            >
              Get Early Access <ArrowRight className="w-4 h-4" />
            </a>
          </div>

          {/* Terminal mockup — simplified */}
          <div
            className="max-w-[700px] mx-auto mt-16 text-left overflow-hidden rounded-xl"
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border)",
            }}
          >
            <div
              className="flex items-center gap-2 px-4 py-3"
              style={{
                background: "rgba(255,255,255,0.02)",
                borderBottom: "1px solid var(--border-subtle)",
              }}
            >
              <span className="w-3 h-3 rounded-full" style={{ background: "#EF4444" }} />
              <span className="w-3 h-3 rounded-full" style={{ background: "#EAB308" }} />
              <span className="w-3 h-3 rounded-full" style={{ background: "#22C55E" }} />
            </div>
            <div
              className="p-5 leading-[1.85]"
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "13px",
                color: "var(--fg-secondary)",
              }}
            >
              <div>
                <span style={{ color: "var(--accent)" }}>$</span>{" "}
                <span style={{ color: "var(--fg-primary)" }}>cw env create github.com/acme/api</span>
              </div>
              <div style={{ color: "var(--fg-tertiary)" }}>
                Environment "api" running (4 vCPU, 16GB RAM)
              </div>
              <br />
              <div>
                <span style={{ color: "var(--accent)" }}>$</span>{" "}
                <span style={{ color: "var(--fg-primary)" }}>cw run api -- claude "fix the auth bug in src/middleware"</span>
              </div>
              <div style={{ color: "var(--fg-tertiary)" }}>
                Session 1 started
              </div>
              <br />
              <div>
                <span style={{ color: "var(--accent)" }}>$</span>{" "}
                <span style={{ color: "var(--fg-primary)" }}>cw run api -- claude "add pagination to /api/users"</span>
              </div>
              <div style={{ color: "var(--fg-tertiary)" }}>
                Session 2 started
              </div>
              <br />
              <div>
                <span style={{ color: "var(--accent)" }}>$</span>{" "}
                <span style={{ color: "var(--fg-primary)" }}>cw list api</span>
              </div>
              <div
                className="mt-1"
                style={{
                  display: "grid",
                  gridTemplateColumns: "8rem 7rem 5rem",
                  color: "var(--fg-tertiary)",
                  fontSize: "12px",
                }}
              >
                <span>WORKSPACE</span><span>SESSIONS</span><span>STATUS</span>
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "8rem 7rem 5rem",
                  fontSize: "12px",
                }}
              >
                <span>api</span>
                <span>2 active</span>
                <span style={{ color: "var(--success)" }}>running</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 2. The Problem — merged comparison ── */}
      <section className="py-24 px-6" style={{ background: "var(--bg-base)" }}>
        <div className="max-w-[1200px] mx-auto">
          <div className="section-label mb-4">The Problem</div>
          <h2
            className="mb-5 max-w-[700px]"
            style={{
              fontWeight: 510,
              fontSize: "clamp(2rem, 5vw, 3rem)",
              lineHeight: 1.15,
              letterSpacing: "-0.022em",
            }}
          >
            Your AI tools are stuck on one machine.
          </h2>
          <p className="mb-14 max-w-[640px]" style={{ fontSize: "1.25rem", color: "var(--fg-secondary)", lineHeight: 1.7 }}>
            Claude, Cursor, Copilot — they could work in parallel. But your laptop can't run them all at once.
          </p>

          <div className="grid md:grid-cols-2 gap-6">
            {/* Before Card */}
            <div
              className="rounded-xl p-8 relative overflow-hidden"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
            >
              <h3
                className="mb-1"
                style={{
                  fontSize: "11px",
                  fontWeight: 450,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "var(--fg-tertiary)",
                }}
              >
                Monday morning
              </h3>
              <p className="mb-8 text-[15px]" style={{ color: "var(--fg-secondary)" }}>
                5 tasks, 1 machine.
              </p>
              <div
                className="h-[280px] relative rounded-xl overflow-hidden"
                style={{ background: "var(--bg-surface-hover)", border: "1px solid var(--border)" }}
              >
                <div className="h-full flex flex-col items-center p-6">
                  <div className="flex gap-2 mb-5">
                    {[0, 1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className="w-9 h-9 rounded-[10px] flex items-center justify-center text-xs font-semibold text-white transition-all duration-500"
                        style={{
                          backgroundColor: colors[i],
                          opacity: activeIndex === i ? 1 : 0.4,
                          transform: activeIndex === i ? "scale(1.1)" : "scale(1)",
                        }}
                      >
                        {i + 1}
                      </div>
                    ))}
                  </div>
                  <div className="w-0.5 h-10 relative" style={{ background: "var(--border)" }}>
                    <div
                      className="absolute -bottom-1.5 left-1/2 -translate-x-1/2"
                      style={{
                        borderLeft: "5px solid transparent",
                        borderRight: "5px solid transparent",
                        borderTop: "6px solid var(--border)",
                      }}
                    />
                  </div>
                  <div
                    className="flex items-center gap-3 mt-5 px-8 py-4 rounded-xl"
                    style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
                  >
                    <div className="w-10 h-7 rounded relative" style={{ background: "var(--fg-tertiary)" }}>
                      <div
                        className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-[50px] h-1 rounded"
                        style={{ background: "var(--fg-tertiary)" }}
                      />
                    </div>
                    <span className="text-xs" style={{ color: "var(--fg-tertiary)" }}>Your laptop</span>
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center text-[10px] font-semibold text-white animate-pulse-glow"
                      style={{ backgroundColor: colors[activeIndex] }}
                    >
                      {activeIndex + 1}
                    </div>
                  </div>
                </div>
                <div
                  className="absolute bottom-4 right-4 rounded-lg px-3.5 py-2 text-xs"
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border)",
                    color: "var(--fg-tertiary)",
                  }}
                >
                  Total: <strong style={{ color: "var(--destructive)", fontWeight: 510 }}>5 days</strong>
                </div>
              </div>
            </div>

            {/* After Card */}
            <div
              className="rounded-xl p-8 relative overflow-hidden"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
            >
              <h3
                className="mb-1"
                style={{
                  fontSize: "11px",
                  fontWeight: 450,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "var(--accent)",
                }}
              >
                Monday morning
              </h3>
              <p className="mb-8 text-[15px]" style={{ color: "var(--fg-secondary)" }}>
                5 tasks, 5 machines. Done by lunch.
              </p>
              <div
                className="h-[280px] relative rounded-xl overflow-hidden"
                style={{ background: "var(--bg-surface-hover)", border: "1px solid var(--border)" }}
              >
                <div className="h-full flex flex-col p-6">
                  <div className="flex gap-2.5 flex-1">
                    {[0, 1, 2, 3, 4].map((i) => (
                      <div key={i} className="flex-1 flex flex-col items-center gap-2.5">
                        <div
                          className="w-8 h-8 rounded-lg flex items-center justify-center text-[11px] font-semibold text-white"
                          style={{ backgroundColor: colors[i] }}
                        >
                          {i + 1}
                        </div>
                        <div className="w-px h-5" style={{ background: "var(--border)" }} />
                        <div
                          className="flex-1 w-full rounded-lg relative overflow-hidden flex flex-col justify-end p-2"
                          style={{
                            background: "var(--bg-surface)",
                            border: "1px solid var(--border)",
                            borderTopColor: colors[i],
                            borderTopWidth: "3px",
                          }}
                        >
                          <div className="h-1 rounded overflow-hidden" style={{ background: "var(--border)" }}>
                            <div
                              className={`h-full rounded ws-progress-fill-${i + 1}`}
                              style={{ backgroundColor: colors[i] }}
                            />
                          </div>
                        </div>
                        <span
                          className="text-[10px]"
                          style={{ fontFamily: "var(--font-mono)", color: "var(--fg-tertiary)" }}
                        >
                          ws-{i + 1}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
                <div
                  className="absolute bottom-4 right-4 rounded-lg px-3.5 py-2 text-xs"
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border)",
                    color: "var(--fg-tertiary)",
                  }}
                >
                  Total: <strong style={{ color: "var(--accent)", fontWeight: 510 }}>1 day</strong>
                </div>
              </div>
            </div>
          </div>

          {/* Mid-page CTA */}
          <div className="mt-12 text-center">
            <a
              href="#cta"
              className="inline-flex items-center gap-2 rounded-lg transition-all duration-150 no-underline"
              style={{
                fontSize: "13px",
                fontWeight: 510,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                padding: "12px 28px",
                background: "var(--accent)",
                color: "#000",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "var(--accent-hover)";
                e.currentTarget.style.transform = "translateY(-1px)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "var(--accent)";
                e.currentTarget.style.transform = "translateY(0)";
              }}
            >
              Get Early Access <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      </section>

      {/* ── 3. Isolation — elevated as core differentiator ── */}
      <section
        className="py-24 px-6"
        style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg-base)" }}
      >
        <div className="max-w-[1200px] mx-auto">
          <div className="section-label mb-4">Security</div>
          <h2
            className="mb-5 max-w-[800px]"
            style={{
              fontWeight: 510,
              fontSize: "clamp(2rem, 5vw, 3rem)",
              lineHeight: 1.15,
            }}
          >
            AI agents write and run code you haven't reviewed. They need real isolation.
          </h2>
          <p className="mb-12" style={{ fontSize: "18px", color: "var(--fg-secondary)", maxWidth: "640px", lineHeight: 1.7 }}>
            Every competitor runs shared-kernel containers. One escape compromises every tenant. Codewire runs each environment in its own Xen VM with a dedicated kernel.
          </p>

          <div className="grid md:grid-cols-2 gap-6 mb-12">
            {/* Standard Containers Card */}
            <div
              className="rounded-xl p-8 relative overflow-hidden"
              style={{ background: "var(--bg-surface)", border: "1.5px solid var(--destructive)" }}
            >
              <h3
                className="mb-1"
                style={{
                  fontSize: "11px",
                  fontWeight: 450,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "var(--destructive)",
                }}
              >
                Standard Containers
              </h3>
              <p className="mb-8 text-[15px]" style={{ color: "var(--fg-secondary)" }}>
                Shared kernel. One escape compromises all.
              </p>
              <div
                className="rounded-xl overflow-hidden p-6 flex items-center justify-center"
                style={{ background: "var(--bg-surface-hover)", border: "1px solid var(--border)" }}
              >
                <svg viewBox="0 0 320 220" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full max-w-[320px]">
                  {[60, 140, 220].map((x, i) => (
                    <g key={i}>
                      <rect x={x - 25} y={20} width={50} height={40} rx={6} fill="var(--bg-surface)" stroke="var(--destructive)" strokeWidth={1.5} />
                      <text x={x} y={45} textAnchor="middle" fontSize={11} fontFamily="var(--font-mono)" fill="var(--fg-secondary)">Pod</text>
                    </g>
                  ))}
                  {[60, 140, 220].map((x, i) => (
                    <line key={i} x1={x} y1={60} x2={160} y2={110} stroke="var(--destructive)" strokeWidth={1} strokeOpacity={0.5} strokeDasharray="4 3" />
                  ))}
                  <rect x={40} y={110} width={240} height={36} rx={6} fill="var(--bg-surface)" stroke="var(--destructive)" strokeWidth={1.5} />
                  <text x={160} y={133} textAnchor="middle" fontSize={11} fontFamily="var(--font-mono)" fill="var(--destructive)">Shared Kernel</text>
                  <rect x={80} y={170} width={160} height={28} rx={14} fill="var(--destructive)" fillOpacity={0.15} stroke="var(--destructive)" strokeWidth={1} />
                  <text x={160} y={189} textAnchor="middle" fontSize={11} fontFamily="var(--font-mono)" fontWeight={510} fill="var(--destructive)">container escape</text>
                </svg>
              </div>
            </div>

            {/* CodeWire Card */}
            <div
              className="rounded-xl p-8 relative overflow-hidden"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--accent)", borderWidth: "1.5px" }}
            >
              <h3
                className="mb-1"
                style={{
                  fontSize: "11px",
                  fontWeight: 450,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "var(--accent)",
                }}
              >
                Codewire
              </h3>
              <p className="mb-8 text-[15px]" style={{ color: "var(--fg-secondary)" }}>
                Dedicated kernel per environment. Hypervisor enforced.
              </p>
              <div
                className="rounded-xl overflow-hidden p-6 flex items-center justify-center"
                style={{ background: "var(--bg-surface-hover)", border: "1px solid var(--border)" }}
              >
                <svg viewBox="0 0 320 220" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full max-w-[320px]">
                  {[60, 160, 260].map((x, i) => (
                    <g key={i}>
                      <rect x={x - 30} y={20} width={60} height={36} rx={6} fill="var(--bg-surface)" stroke="var(--accent)" strokeWidth={1.5} />
                      <text x={x} y={43} textAnchor="middle" fontSize={11} fontFamily="var(--font-mono)" fill="var(--fg-secondary)">Pod</text>
                      <rect x={x - 30} y={72} width={60} height={28} rx={4} fill="var(--bg-surface)" stroke="var(--accent)" strokeWidth={1} strokeOpacity={0.5} />
                      <text x={x} y={91} textAnchor="middle" fontSize={9} fontFamily="var(--font-mono)" fill="var(--accent)">Kernel</text>
                      <line x1={x} y1={56} x2={x} y2={72} stroke="var(--accent)" strokeWidth={1} strokeOpacity={0.4} />
                    </g>
                  ))}
                  {[60, 160, 260].map((x, i) => (
                    <line key={i} x1={x} y1={100} x2={x} y2={140} stroke="var(--accent)" strokeWidth={1} strokeOpacity={0.3} strokeDasharray="4 3" />
                  ))}
                  <rect x={20} y={140} width={280} height={36} rx={6} fill="var(--bg-surface)" stroke="var(--accent)" strokeWidth={1.5} />
                  <text x={160} y={163} textAnchor="middle" fontSize={11} fontFamily="var(--font-mono)" fontWeight={510} fill="var(--accent)">Xen Hypervisor</text>
                  <rect x={20} y={190} width={280} height={24} rx={4} fill="var(--bg-surface-hover)" stroke="var(--border)" strokeWidth={1} />
                  <text x={160} y={207} textAnchor="middle" fontSize={10} fontFamily="var(--font-mono)" fill="var(--fg-tertiary)">Hardware</text>
                </svg>
              </div>
            </div>
          </div>

          {/* Competitive comparison table */}
          <div
            className="rounded-xl p-8 overflow-x-auto"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
          >
            <table className="w-full text-[15px]">
              <thead>
                <tr>
                  {["Platform", "Isolation Model"].map((header) => (
                    <th
                      key={header}
                      className="text-left px-4 py-3"
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontWeight: 450,
                        fontSize: "11px",
                        textTransform: "uppercase",
                        letterSpacing: "0.1em",
                        color: "var(--fg-tertiary)",
                        borderBottom: "1px solid var(--border)",
                      }}
                    >
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[
                  { platform: "GitHub Codespaces", model: "Shared kernel (containers)" },
                  { platform: "Gitpod", model: "Shared kernel (containers)" },
                  { platform: "DevPod", model: "Shared kernel (containers)" },
                  { platform: "vCluster", model: "Shared kernel (virtual K8s)" },
                ].map((row) => (
                  <tr key={row.platform}>
                    <td
                      className="px-4 py-3.5"
                      style={{
                        fontWeight: 450,
                        borderBottom: "1px solid var(--border-subtle)",
                        color: "var(--fg-secondary)",
                      }}
                    >
                      {row.platform}
                    </td>
                    <td
                      className="px-4 py-3.5"
                      style={{
                        fontWeight: 450,
                        borderBottom: "1px solid var(--border-subtle)",
                        color: "var(--fg-tertiary)",
                      }}
                    >
                      {row.model}
                    </td>
                  </tr>
                ))}
                <tr style={{ background: "rgba(14,165,233,0.08)" }}>
                  <td
                    className="px-4 py-3.5"
                    style={{ fontWeight: 510, color: "var(--accent)" }}
                  >
                    Codewire
                  </td>
                  <td
                    className="px-4 py-3.5"
                    style={{ fontWeight: 510, color: "var(--accent)" }}
                  >
                    Dedicated kernel (Xen VM)
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ── 4. What You Get — 4-card bento grid ── */}
      <section
        id="features"
        className="py-24 px-6 dot-bg-subtle"
        style={{ background: "var(--bg-primary)" }}
      >
        <div className="max-w-[1200px] mx-auto">
          <div className="section-label mb-4">Platform</div>
          <h2
            className="mb-5"
            style={{
              fontWeight: 510,
              fontSize: "clamp(2rem, 5vw, 3rem)",
              lineHeight: 1.15,
            }}
          >
            What you get
          </h2>
          <p className="mb-12" style={{ fontSize: "18px", color: "var(--fg-secondary)", maxWidth: "640px", lineHeight: 1.7 }}>
            Dev environments, AI sessions, multi-agent coordination, and remote access. One control plane.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <BentoCard
              icon="&#9889;"
              title="Cloud Environments"
              description="Full dev environments in the cloud. Your repo, your deps, your tools, on dedicated compute."
              visual={
                <div className="flex items-center gap-2" style={{ fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--fg-tertiary)" }}>
                  <span style={{ color: "var(--success)" }}>&#10003;</span>
                  Environment "api" provisioned in 45s
                </div>
              }
            />
            <BentoCard
              icon="&#128279;"
              title="Persistent AI Sessions"
              description="AI agents run in persistent sessions that survive disconnects. Start, detach, check back later."
              visual={
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--fg-tertiary)", lineHeight: 1.6 }}>
                  <div><span style={{ color: "var(--accent)" }}>$</span> cw run api -- claude "fix the bug"</div>
                  <div><span style={{ color: "var(--accent)" }}>$</span> cw attach api</div>
                </div>
              }
            />
            <BentoCard
              icon="&#9881;"
              title="Durable Agent Sessions"
              description="Run multiple agents in one environment. Their supervised sessions retain output and survive CLI disconnects."
              visual={
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--fg-tertiary)", lineHeight: 1.6 }}>
                  <span style={{ color: "var(--accent)" }}>$</span> cw run --detach api -- codex
                </div>
              }
            />
            <BentoCard
              icon="&#127760;"
              title="SSH Access"
              description="Connect to any environment over SSH. No VPN, no port forwarding. Works behind NAT."
              visual={
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--fg-tertiary)", lineHeight: 1.6 }}>
                  <span style={{ color: "var(--accent)" }}>$</span> cw shell api
                </div>
              }
            />
          </div>

          {/* Mid-page CTA */}
          <div className="mt-12 text-center">
            <a
              href="#cta"
              className="inline-flex items-center gap-2 rounded-lg transition-all duration-150 no-underline"
              style={{
                fontSize: "13px",
                fontWeight: 510,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                padding: "12px 28px",
                background: "transparent",
                color: "var(--fg-secondary)",
                border: "1px solid var(--border)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = "var(--fg-primary)";
                e.currentTarget.style.borderColor = "var(--fg-tertiary)";
                e.currentTarget.style.background = "var(--bg-surface)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = "var(--fg-secondary)";
                e.currentTarget.style.borderColor = "var(--border)";
                e.currentTarget.style.background = "transparent";
              }}
            >
              Get Early Access <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      </section>

      {/* ── 5. Get Started — 3-step CLI walkthrough ── */}
      <section className="py-24 px-6" style={{ background: "var(--bg-base)" }}>
        <div className="max-w-[1200px] mx-auto">
          <div className="section-label mb-4">How it works</div>
          <h2
            className="mb-12"
            style={{
              fontWeight: 510,
              fontSize: "clamp(2rem, 5vw, 3rem)",
              lineHeight: 1.15,
            }}
          >
            Up and running in 3 commands
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <StepCard
              step={1}
              title="Install the CLI"
              description="From an authorized private source checkout."
              code={<><span style={{ color: "var(--accent)" }}>$</span> make cli-install</>}
            />
            <StepCard
              step={2}
              title="Create an environment"
              description="Cloud dev environment, ready in seconds."
              code={<><span style={{ color: "var(--accent)" }}>$</span> cw env create github.com/acme/api</>}
            />
            <StepCard
              step={3}
              title="Run an AI agent"
              description="Runs in the background. Attach anytime."
              code={<><span style={{ color: "var(--accent)" }}>$</span> cw run -- claude "fix the tests"</>}
            />
          </div>
        </div>
      </section>

      {/* ── 6. Pricing ── */}
      <section id="pricing" className="py-24 px-6" style={{ background: "var(--bg-primary)" }}>
        <div className="max-w-[1200px] mx-auto text-center">
          <h2
            className="mb-5"
            style={{ fontWeight: 510, fontSize: "clamp(2rem, 5vw, 3rem)", lineHeight: 1.15 }}
          >
            No seat tax on AI agents
          </h2>
          <p className="mx-auto mb-12" style={{ fontSize: "18px", color: "var(--fg-secondary)", maxWidth: "600px", lineHeight: 1.7 }}>
            Pay for machines, not for how many agents use them. Half the cost of Codespaces.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-14 text-left">
            <PricingCard tier="Starter" price="$49" period="/month" features={["1 developer included", "500 compute hours/mo", "5 concurrent environments", "2 vCPU / 8 GB default", "AI agents don't count as seats"]} />
            <PricingCard tier="Pro" price="$199" period="/month" featured features={["10 developers included", "2,000 compute hours/mo", "25 concurrent environments", "4 vCPU / 16 GB default", "AI agents don't count as seats"]} />
            <PricingCard tier="Team" price="$499" period="/month" features={["30 developers included", "6,000 compute hours/mo", "100 concurrent environments", "8 vCPU / 32 GB default", "AI agents don't count as seats"]} />
            <PricingCard tier="Enterprise" price="Contact" period="us" features={["Unlimited developers", "Unlimited compute hours", "Unlimited environments", "Custom machine sizes", "Dedicated support + SLA"]} />
          </div>
          <p className="text-sm mb-10 text-center" style={{ color: "var(--fg-tertiary)" }}>
            Additional developer seats: $18/dev/month across all tiers. All plans include a 14-day free trial.
          </p>

          {/* Compute Pricing Table */}
          <div className="rounded-xl p-10 text-left" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            <h3 className="mb-2" style={{ fontWeight: 510, fontSize: "20px" }}>
              Compute pricing
            </h3>
            <p className="mb-7" style={{ fontSize: "15px", color: "var(--fg-secondary)" }}>
              Uniform usage rates by machine type across all plans.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-[15px]">
                <thead>
                  <tr>
                    {["Machine", "vCPU", "RAM", "Rate"].map((header) => (
                      <th
                        key={header}
                        className="text-left px-4 py-3"
                        style={{
                          fontFamily: "var(--font-mono)",
                          fontWeight: 450,
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.1em",
                          color: "var(--fg-tertiary)",
                          borderBottom: "1px solid var(--border)",
                        }}
                      >
                        {header}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    { name: "Small", vcpu: "2", ram: "8 GB", rate: "$0.10/hr" },
                    { name: "Medium", vcpu: "4", ram: "16 GB", rate: "$0.18/hr", highlighted: true },
                    { name: "Large", vcpu: "8", ram: "32 GB", rate: "$0.32/hr" },
                    { name: "XL", vcpu: "16", ram: "64 GB", rate: "$0.60/hr" },
                  ].map((row, idx, arr) => (
                    <tr key={row.name} style={{ background: row.highlighted ? "rgba(14,165,233,0.08)" : "transparent" }}>
                      {[row.name, row.vcpu, row.ram, row.rate].map((cell, i) => (
                        <td
                          key={i}
                          className="px-4 py-4"
                          style={{
                            fontWeight: i === 0 ? 510 : 450,
                            borderBottom: idx === arr.length - 1 ? "none" : `1px solid ${row.highlighted ? "rgba(14,165,233,0.2)" : "var(--border-subtle)"}`,
                            color: "var(--fg-secondary)",
                          }}
                        >
                          {cell}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-sm mt-6 text-center" style={{ color: "var(--fg-tertiary)" }}>
              GitHub Codespaces charges $0.36/hr for 4-core. You're saving 50%+.
            </p>
          </div>

          {/* Custom Setup */}
          <div
            className="rounded-xl p-9 flex flex-wrap justify-between items-center gap-6 text-left mt-10"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
          >
            <div>
              <h3 className="mb-2" style={{ fontWeight: 510, fontSize: "20px" }}>Custom setup</h3>
              <p className="max-w-[500px]" style={{ fontSize: "15px", color: "var(--fg-secondary)" }}>
                Complex stack? Legacy services? We'll make it boot perfectly. Every dependency, every weird thing.
              </p>
            </div>
            <a
              href="mailto:hello@codewire.sh"
              className="inline-flex items-center gap-2 rounded-lg transition-all duration-150 no-underline"
              style={{
                fontSize: "13px",
                fontWeight: 510,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                padding: "12px 28px",
                background: "transparent",
                color: "var(--fg-secondary)",
                border: "1px solid var(--border)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = "var(--fg-primary)";
                e.currentTarget.style.borderColor = "var(--fg-tertiary)";
                e.currentTarget.style.background = "var(--bg-surface-hover)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = "var(--fg-secondary)";
                e.currentTarget.style.borderColor = "var(--border)";
                e.currentTarget.style.background = "transparent";
              }}
            >
              Contact Us <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      </section>

      {/* ── 7. CTA ── */}
      <section id="cta" className="relative overflow-hidden py-28 px-6 text-center dot-bg" style={{ background: "var(--bg-primary)" }}>
        <div className="relative max-w-[700px] mx-auto">
          <h2
            className="mb-4"
            style={{ fontWeight: 510, fontSize: "clamp(1.8rem, 4vw, 2.8rem)", lineHeight: 1.2 }}
          >
            Ready to multiply your stack?
          </h2>
          <p className="mb-10" style={{ color: "var(--fg-secondary)", fontSize: "1.25rem" }}>
            Create an account to start building with your team.
          </p>

          <Link
            to="/login"
            className="inline-flex items-center justify-center gap-2 rounded-lg transition-all duration-150 no-underline"
            style={{
              fontSize: "13px",
              fontWeight: 510,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              padding: "12px 28px",
              background: "var(--accent)",
              color: "#000",
            }}
          >
            Get started <ArrowRight className="w-4 h-4" />
          </Link>

          <div className="mt-8">
            <Link to="/login" className="text-sm transition-colors no-underline" style={{ color: "var(--fg-tertiary)" }}>
              Already have an invite? Sign in
            </Link>
          </div>
        </div>
      </section>

      {/* ── 8. Footer ── */}
      <footer className="py-16 px-6" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg-base)" }}>
        <div className="max-w-[1200px] mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-[2fr_1fr_1fr_1fr] gap-8 md:gap-12 mb-12">
            <div className="col-span-2 md:col-span-1">
              <div className="flex items-center gap-2 mb-4">
                <svg width="24" height="24" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <rect width="32" height="32" rx="8" fill="#0EA5E9" />
                  <path d="M8 10l6 6-6 6" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                  <line x1="17" y1="22" x2="24" y2="22" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
                </svg>
                <span style={{ fontWeight: 510, fontSize: "16px", color: "var(--fg-primary)" }}>Codewire</span>
              </div>
              <p className="max-w-[280px] leading-relaxed" style={{ fontSize: "14px", color: "var(--fg-tertiary)" }}>
                Cloud machines for AI coding agents. Isolated environments, persistent sessions, and multi-agent coordination.
              </p>
            </div>
            <FooterCol title="Product" links={[{ label: "Features", href: "#features" }, { label: "Pricing", href: "#pricing" }]} />
            <FooterCol title="Developers" links={[{ label: "Documentation", href: "https://docs.codewire.sh" }, { label: "CLI Docs", href: "https://docs.codewire.sh/cli/overview" }]} />
            <FooterCol title="Company" links={[{ label: "Contact", href: "mailto:hello@codewire.sh" }]} />
          </div>

          <div
            className="flex flex-wrap justify-between items-center pt-8 gap-4"
            style={{ borderTop: "1px solid var(--border-subtle)", fontSize: "13px", color: "var(--fg-tertiary)" }}
          >
            <span>&copy; 2026 Codewire</span>
            <div className="flex items-center gap-5">
              <a href="#" className="no-underline transition-colors" style={{ color: "var(--fg-tertiary)" }}>Terms</a>
              <a href="#" className="no-underline transition-colors" style={{ color: "var(--fg-tertiary)" }}>Privacy</a>
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}

/* ── Component helpers ── */

function BentoCard({ icon, title, description, visual }: {
  icon?: string; title: string; description: string; visual?: React.ReactNode;
}) {
  return (
    <div
      className="rounded-xl p-8 transition-colors duration-200"
      style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = "#333"; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
    >
      {icon && (
        <div
          className="w-10 h-10 rounded-[10px] flex items-center justify-center text-lg mb-5"
          style={{ background: "var(--accent-muted)", border: "1px solid rgba(14,165,233,0.2)" }}
        >
          <span dangerouslySetInnerHTML={{ __html: icon }} />
        </div>
      )}
      <h3 className="mb-2.5" style={{ fontSize: "16px", fontWeight: 510, color: "var(--fg-primary)" }}>
        {title}
      </h3>
      <p style={{ fontSize: "14px", color: "var(--fg-secondary)", lineHeight: 1.6 }}>{description}</p>
      {visual && (
        <div
          className="mt-6 rounded-lg flex items-center justify-center"
          style={{ height: "120px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}
        >
          {visual}
        </div>
      )}
    </div>
  );
}

function StepCard({ step, title, description, code }: { step: number; title: string; description: string; code: React.ReactNode }) {
  return (
    <div>
      <div className="mb-3" style={{ fontSize: "11px", fontWeight: 450, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--accent)" }}>
        Step {step}
      </div>
      <h3 className="mb-3" style={{ fontSize: "20px", fontWeight: 510, color: "var(--fg-primary)" }}>{title}</h3>
      <p className="mb-5" style={{ fontSize: "15px", color: "var(--fg-secondary)", lineHeight: 1.6 }}>{description}</p>
      <div className="rounded-lg px-4 py-3.5 overflow-x-auto" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--fg-secondary)" }}>
        {code}
      </div>
    </div>
  );
}

function PricingCard({ tier, price, period, features, featured }: { tier: string; price: string; period: string; features: string[]; featured?: boolean }) {
  return (
    <div
      className="rounded-xl p-8 flex flex-col"
      style={{
        background: "var(--bg-surface)",
        border: featured ? "1px solid var(--accent)" : "1px solid var(--border)",
        boxShadow: featured ? "0 0 40px rgba(14,165,233,0.08)" : "none",
      }}
    >
      <div className="mb-2 flex items-center gap-2" style={{ fontSize: "11px", fontWeight: 450, textTransform: "uppercase", letterSpacing: "0.1em", color: featured ? "var(--accent)" : "var(--fg-tertiary)" }}>
        <span className="w-2 h-2 rounded-full" style={{ background: featured ? "var(--accent)" : "var(--fg-tertiary)" }} />
        {tier}
      </div>
      <div className="mb-1" style={{ fontSize: "36px", fontWeight: 510, color: "var(--fg-primary)" }}>{price}</div>
      <div className="mb-6" style={{ fontSize: "14px", color: "var(--fg-tertiary)" }}>{period}</div>
      <ul className="flex-1 mb-8" style={{ listStyle: "none", padding: 0 }}>
        {features.map((feature) => (
          <li key={feature} className="flex items-center gap-2.5 py-2" style={{ fontSize: "14px", color: "var(--fg-secondary)", borderBottom: "1px solid var(--border-subtle)" }}>
            <span style={{ color: "var(--fg-tertiary)", fontFamily: "var(--font-mono)" }}>~</span>
            {feature}
          </li>
        ))}
      </ul>
      <a
        href="#cta"
        className="w-full inline-flex items-center justify-center gap-2 rounded-lg transition-all duration-150 no-underline"
        style={{
          fontSize: "13px", fontWeight: 510, textTransform: "uppercase", letterSpacing: "0.06em", padding: "12px 28px",
          background: featured ? "var(--accent)" : "transparent",
          color: featured ? "#000" : "var(--fg-secondary)",
          border: featured ? "none" : "1px solid var(--border)",
        }}
        onMouseEnter={(e) => {
          if (featured) { e.currentTarget.style.background = "var(--accent-hover)"; }
          else { e.currentTarget.style.color = "var(--fg-primary)"; e.currentTarget.style.borderColor = "var(--fg-tertiary)"; e.currentTarget.style.background = "var(--bg-surface-hover)"; }
        }}
        onMouseLeave={(e) => {
          if (featured) { e.currentTarget.style.background = "var(--accent)"; }
          else { e.currentTarget.style.color = "var(--fg-secondary)"; e.currentTarget.style.borderColor = "var(--border)"; e.currentTarget.style.background = "transparent"; }
        }}
      >
        {featured ? (<>Get Started <ArrowRight className="w-4 h-4" /></>) : "Get Started"}
      </a>
    </div>
  );
}

function FooterCol({ title, links }: { title: string; links: { label: string; href: string }[] }) {
  return (
    <div>
      <h4 className="mb-4" style={{ fontSize: "11px", fontWeight: 450, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--fg-tertiary)" }}>{title}</h4>
      {links.map((link) => (
        <a
          key={link.label}
          href={link.href}
          className="block py-1.5 no-underline transition-colors duration-150"
          style={{ fontSize: "14px", color: "var(--fg-secondary)" }}
          onMouseEnter={(e) => { e.currentTarget.style.color = "var(--fg-primary)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = "var(--fg-secondary)"; }}
        >
          {link.label}
        </a>
      ))}
    </div>
  );
}
