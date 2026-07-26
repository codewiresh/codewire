/// <reference types="vite/client" />
import { useState } from "react";
import {
  createRootRoute,
  Outlet,
  Link,
  useRouterState,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TransportProvider } from "@connectrpc/connect-query";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/theme-provider";
import { Menu, X } from "lucide-react";
import { getSession } from "@/lib/auth";
import { connectTransport } from "@/lib/connect";
import "@/index.css";

function CodewireLogo({ className, mono }: { className?: string; mono?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 ${className ?? ""}`}>
      <svg width="24" height="24" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="32" height="32" rx="8" fill="#0EA5E9" />
        <path d="M8 10l6 6-6 6" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        <line x1="17" y1="22" x2="24" y2="22" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
      </svg>
      <span style={mono ? { fontFamily: "var(--font-mono)", fontWeight: 600, fontSize: "16px", color: "var(--fg-primary)" } : undefined}>
        Codewire
      </span>
    </span>
  );
}

export { CodewireLogo };

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60,
      retry: 1,
    },
  },
});

export const Route = createRootRoute({
  beforeLoad: async () => {
    const session = await getSession();
    const isAdmin = !!session?.user?.is_admin;
    return { session, isAdmin };
  },
  component: RootComponent,
  errorComponent: () => (
    <div style={{ padding: "2rem", textAlign: "center", color: "#999", fontFamily: "var(--font-sans)" }}>
      <p>Something went wrong.</p>
      <a
        href={window.location.href}
        style={{ color: "var(--accent, #f97316)", textDecoration: "underline", marginTop: "0.5rem", display: "inline-block" }}
      >
        Refresh the page
      </a>
    </div>
  ),
});

function RootComponent() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const isLandingPage = pathname === "/" || pathname === "";
  const isDashboard = pathname.startsWith("/dashboard") || pathname.startsWith("/admin");
  const isFullscreen = pathname.startsWith("/terminal");
  const isAuth = !isLandingPage && !isDashboard && !isFullscreen;

  return (
    <ThemeProvider>
      <TransportProvider transport={connectTransport}>
        <QueryClientProvider client={queryClient}>
          <Toaster position="bottom-right" theme="dark" />
          {isLandingPage ? (
            <LandingLayout mobileMenuOpen={mobileMenuOpen} setMobileMenuOpen={setMobileMenuOpen}>
              <Outlet />
            </LandingLayout>
          ) : isDashboard ? (
            <Outlet />
          ) : isFullscreen ? (
            <Outlet />
          ) : isAuth ? (
            <AuthLayout>
              <Outlet />
            </AuthLayout>
          ) : (
            <Outlet />
          )}
        </QueryClientProvider>
      </TransportProvider>
    </ThemeProvider>
  );
}

/* ── Auth layout (minimal dark wrapper, no nav) ── */

function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="min-h-screen flex items-center justify-center antialiased px-4"
      style={{ background: "var(--bg-base)", color: "var(--fg-primary)" }}
    >
      {children}
    </div>
  );
}

/* ── Landing page layout (dark, monospace nav) ── */

function LandingLayout({
  mobileMenuOpen,
  setMobileMenuOpen,
  children,
}: {
  mobileMenuOpen: boolean;
  setMobileMenuOpen: (v: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className="min-h-screen max-w-[100vw] overflow-x-hidden antialiased"
      style={{
        background: "var(--bg-base)",
        color: "var(--fg-primary)",
        fontFamily: "var(--font-sans)",
      }}
    >
      {/* Announcement Bar */}
      <div
        className="text-center text-[13px] px-6 py-2.5"
        style={{
          background: "var(--accent-muted)",
          borderBottom: "1px solid rgba(14,165,233,0.2)",
          fontFamily: "var(--font-mono)",
          color: "var(--fg-secondary)",
        }}
      >
        <span style={{ color: "var(--accent)", fontWeight: 600 }}>BETA:</span>{" "}
        Cloud machines for AI coding agents — now accepting teams{" "}
        <a
          href="#cta"
          style={{ color: "var(--accent)", textDecoration: "underline", textUnderlineOffset: "3px" }}
        >
          Get early access
        </a>
      </div>

      {/* Navigation */}
      <nav
        className="sticky top-0 z-50 px-6"
        style={{
          background: "rgba(13,13,13,0.85)",
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div className="max-w-[1200px] mx-auto flex items-center justify-between h-16">
          <a href="/" className="flex items-center no-underline" style={{ color: "var(--fg-primary)" }}>
            <CodewireLogo mono />
          </a>

          {/* Desktop nav links */}
          <div className="hidden md:flex items-center gap-2">
            {[
              { label: "Features", href: "#features" },
              { label: "Pricing", href: "#pricing" },
              { label: "Docs", href: "https://docs.codewire.sh" },
            ].map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="px-3.5 py-2 rounded-md transition-all duration-150 no-underline"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "12px",
                  fontWeight: 500,
                  textTransform: "uppercase" as const,
                  letterSpacing: "0.08em",
                  color: "var(--fg-secondary)",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "var(--fg-primary)";
                  e.currentTarget.style.background = "var(--bg-surface)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = "var(--fg-secondary)";
                  e.currentTarget.style.background = "transparent";
                }}
              >
                {link.label}
              </a>
            ))}
            <Link
              to="/login"
              className="px-3.5 py-2 rounded-md transition-all duration-150 no-underline"
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                fontWeight: 500,
                textTransform: "uppercase" as const,
                letterSpacing: "0.08em",
                color: "var(--fg-secondary)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = "var(--fg-primary)";
                e.currentTarget.style.background = "var(--bg-surface)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = "var(--fg-secondary)";
                e.currentTarget.style.background = "transparent";
              }}
            >
              Sign In
            </Link>
            <a
              href="#cta"
              className="px-3.5 py-2 rounded-md transition-all duration-150 no-underline ml-1"
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                fontWeight: 600,
                textTransform: "uppercase" as const,
                letterSpacing: "0.08em",
                background: "var(--accent)",
                color: "#000",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--accent-hover)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "var(--accent)"; }}
            >
              Get Started
            </a>
          </div>

          {/* Mobile hamburger */}
          <button
            className="md:hidden p-2 -m-2 cursor-pointer"
            style={{ color: "var(--fg-secondary)", background: "none", border: "none" }}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div
            className="md:hidden py-4 flex flex-col gap-2"
            style={{ borderTop: "1px solid var(--border-subtle)" }}
          >
            {[
              { label: "Features", href: "#features" },
              { label: "Pricing", href: "#pricing" },
              { label: "Docs", href: "https://docs.codewire.sh" },
            ].map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="py-2 no-underline"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "13px",
                  fontWeight: 500,
                  textTransform: "uppercase" as const,
                  letterSpacing: "0.08em",
                  color: "var(--fg-secondary)",
                }}
                onClick={() => setMobileMenuOpen(false)}
              >
                {link.label}
              </a>
            ))}
            <div className="h-px my-1" style={{ background: "var(--border-subtle)" }} />
            <Link
              to="/login"
              className="py-2 no-underline"
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "13px",
                fontWeight: 500,
                textTransform: "uppercase" as const,
                letterSpacing: "0.08em",
                color: "var(--fg-secondary)",
              }}
              onClick={() => setMobileMenuOpen(false)}
            >
              Sign In
            </Link>
            <a
              href="#cta"
              className="inline-flex justify-center py-2.5 rounded-md no-underline mt-1"
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "13px",
                fontWeight: 600,
                textTransform: "uppercase" as const,
                letterSpacing: "0.08em",
                background: "var(--accent)",
                color: "#000",
              }}
              onClick={() => setMobileMenuOpen(false)}
            >
              Get Started
            </a>
          </div>
        )}
      </nav>

      {children}
    </div>
  );
}
