import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { safeAuthContinuation } from "@/lib/auth-continuation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Loader2, Shield } from "lucide-react";

export const Route = createFileRoute("/two-factor")({
  component: TwoFactorPage,
  validateSearch: (search: Record<string, unknown>): {
    token?: string;
    authRequestID?: string;
    return_to?: string;
  } => ({
    token: (search.token as string) || undefined,
    authRequestID: (search.authRequestID as string) || undefined,
    return_to: safeAuthContinuation(search.return_to),
  }),
});

function TwoFactorPage() {
  const [code, setCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const search = Route.useSearch();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (!search.token) {
        setError("Missing 2FA token. Please sign in again.");
        return;
      }

      const res = await fetch("/api/auth/two-factor/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ code, token: search.token }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || data.message || "Invalid verification code");
        return;
      }

      // Session cookie is now set — redirect appropriately
      if (search.authRequestID) {
        // Complete the OIDC auth request via the callback
        window.location.href = `/api/oidc/callback?id=${search.authRequestID}`;
        return;
      }

      if (search.return_to) {
        window.location.href = search.return_to;
        return;
      }

      // Regular login flow - redirect to dashboard
      window.location.href = "/dashboard";
    } catch {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
            <Shield className="h-6 w-6 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl">Two-Factor Authentication</CardTitle>
        <CardDescription>
          {useBackupCode
            ? "Enter one of your backup codes"
            : "Enter the 6-digit code from your authenticator app"}
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {error && (
            <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
              {error}
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="code">
              {useBackupCode ? "Backup Code" : "Verification Code"}
            </Label>
            <Input
              id="code"
              type="text"
              placeholder={useBackupCode ? "XXXXXXXXXX" : "000000"}
              value={code}
              onChange={(e) => {
                if (useBackupCode) {
                  setCode(e.target.value.replace(/[^a-f0-9]/gi, "").toLowerCase());
                } else {
                  const value = e.target.value.replace(/\D/g, "");
                  if (value.length <= 6) setCode(value);
                }
              }}
              className="text-center text-2xl tracking-widest font-mono"
              autoComplete="one-time-code"
              maxLength={useBackupCode ? 10 : 6}
              required
              autoFocus
            />
          </div>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              setUseBackupCode(!useBackupCode);
              setCode("");
              setError("");
            }}
            className="w-full"
          >
            {useBackupCode
              ? "Use authenticator app instead"
              : "Use backup code instead"}
          </Button>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button
            type="submit"
            className="w-full"
            disabled={loading || code.length < (useBackupCode ? 10 : 6)}
          >
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {loading ? "Verifying..." : "Verify"}
          </Button>
          <p className="text-xs text-[color:var(--fg-secondary)] text-center">
            Having trouble? Contact support for assistance.
          </p>
        </CardFooter>
      </form>
    </Card>
  );
}
