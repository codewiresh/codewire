import { useState } from "react";
import { Outlet } from "@tanstack/react-router";
import { Sidebar } from "@/components/sidebar";
import { Menu, X } from "lucide-react";

export function DashboardLayout({
  isAdmin,
  userName,
}: {
  isAdmin: boolean;
  userName?: string;
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="cw-app flex min-h-screen" style={{ background: "var(--bg-base)", color: "var(--fg-primary)" }}>
      {/* Desktop sidebar */}
      <div className="cw-sidebar-slot hidden lg:block w-60 shrink-0 fixed top-0 left-0 bottom-0 z-40 border-r border-[var(--border-subtle)]">
        <Sidebar isAdmin={isAdmin} userName={userName} />
      </div>

      {/* Mobile top bar */}
      <div className="cw-mobile-bar lg:hidden fixed top-0 left-0 right-0 z-40 h-14 flex items-center px-4 border-b border-[var(--border-subtle)]" style={{ background: "var(--bg-primary)" }}>
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="p-2 -ml-2 text-[color:var(--fg-secondary)] hover:text-[color:var(--fg-primary)] cursor-pointer"
          aria-label="Toggle sidebar"
        >
          {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
        <div className="flex items-center gap-2 ml-2">
          <svg width="20" height="20" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="32" height="32" rx="8" fill="#0EA5E9" />
            <path d="M8 10l6 6-6 6" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            <line x1="17" y1="22" x2="24" y2="22" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
          </svg>
          <span className="text-sm text-[color:var(--fg-primary)]" style={{ fontWeight: 510 }}>
            Codewire
          </span>
        </div>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <>
          <div
            className="lg:hidden fixed inset-0 z-40 bg-black/60"
            onClick={() => setSidebarOpen(false)}
          />
          <div className="lg:hidden fixed top-0 left-0 bottom-0 z-50 w-60 border-r border-[var(--border-subtle)]">
            <Sidebar isAdmin={isAdmin} userName={userName} onClose={() => setSidebarOpen(false)} />
          </div>
        </>
      )}

      {/* Main content */}
      <main className="cw-main flex-1 lg:ml-60 min-w-0 pt-14 lg:pt-0">
        <div className="cw-main-inner px-4 md:px-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
