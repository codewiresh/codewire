import { createFileRoute, redirect } from "@tanstack/react-router";
import { useState } from "react";
import { getSession } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Monitor, CheckCircle2, Loader2 } from "lucide-react";

export const Route = createFileRoute("/device")({
  component: DevicePage,
  validateSearch: (
    search: Record<string, unknown>,
  ): { user_code?: string } => ({
    user_code: (search.user_code as string) || undefined,
  }),
  beforeLoad: async ({ search }) => {
    const session = await getSession();
    if (!session?.user) {
      const returnTo = `/device${search.user_code ? `?user_code=${encodeURIComponent(search.user_code)}` : ""}`;
      throw redirect({
        to: "/login",
        search: { return_to: returnTo },
      });
    }
  },
});

function DevicePage() {
  const search = Route.useSearch();
  const [code, setCode] = useState(search.user_code ?? "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [approved, setApproved] = useState(false);

  const handleApprove = async () => {
    if (!code.trim()) {
      setError("Please enter a device code.");
      return;
    }

    setError("");
    setLoading(true);

    try {
      const resp = await fetch("/api/oauth/device_verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ user_code: code.trim().toUpperCase() }),
      });

      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(
          data.detail || data.title || data.message || `Request failed (${resp.status})`,
        );
      }

      setApproved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to approve device");
    } finally {
      setLoading(false);
    }
  };

  if (approved) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <div className="h-12 w-12 rounded-lg bg-green-500/10 flex items-center justify-center">
              <CheckCircle2 className="h-6 w-6 text-green-500" />
            </div>
          </div>
          <CardTitle className="text-2xl">CLI Authorized</CardTitle>
          <CardDescription>
            Your CLI has been authorized. You can close this tab.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
            <Monitor className="h-6 w-6 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl">Authorize CLI</CardTitle>
        <CardDescription>
          Confirm the code shown in your terminal to authorize CLI access.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
            {error}
          </div>
        )}

        <div className="space-y-2">
          <Input
            type="text"
            placeholder="ABCD-1234"
            value={code}
            onChange={(e) => setCode(e.target.value.toUpperCase())}
            className="text-center text-lg tracking-widest font-mono"
            maxLength={9}
            autoFocus={!search.user_code}
          />
        </div>

        <Button
          className="w-full"
          onClick={handleApprove}
          disabled={loading || !code.trim()}
        >
          {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {loading ? "Authorizing..." : "Authorize CLI Access"}
        </Button>
      </CardContent>
    </Card>
  );
}
