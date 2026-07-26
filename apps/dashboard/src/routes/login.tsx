import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { signIn } from "@/lib/auth";
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
import { Code2, Loader2 } from "lucide-react";

export const Route = createFileRoute("/login")({
  component: LoginPage,
  validateSearch: (search: Record<string, unknown>): {
    authRequestID?: string;
    return_to?: string;
  } => ({
    authRequestID: (search.authRequestID as string) || undefined,
    return_to: safeAuthContinuation(search.return_to),
  }),
});

function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const search = Route.useSearch();
  const isOIDCFlow = !!search.authRequestID;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const result = await signIn(email, password);

      // 2FA challenge — redirect to verification page with token
      if (result?.twoFactorRequired) {
        const tfParams = new URLSearchParams({ token: result.twoFactorToken ?? "" });
        if (search.authRequestID) {
          tfParams.set("authRequestID", search.authRequestID);
        }
        if (search.return_to) {
          tfParams.set("return_to", search.return_to);
        }
        window.location.href = `/two-factor?${tfParams.toString()}`;
        return;
      }

      if (isOIDCFlow) {
        // Redirect to the OIDC callback which will complete the auth request
        // and redirect back to ZITADEL's authorize callback with the code.
        window.location.href = `/api/oidc/callback?id=${search.authRequestID}`;
        return;
      }

      if (search.return_to) {
        window.location.href = search.return_to;
        return;
      }

      // Full page navigation so the dashboard runs with the new session cookie.
      window.location.href = "/dashboard";
    } catch (err) {
      const msg = err instanceof Error ? err.message : "An unexpected error occurred";
      if (msg.includes("locked")) {
        setError("Account is temporarily locked due to too many failed attempts. Please try again later.");
      } else if (msg.includes("429") || msg.includes("Too many")) {
        setError("Too many login attempts. Please wait before trying again.");
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
            <Code2 className="h-6 w-6 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl">Welcome back</CardTitle>
        <CardDescription>
          Sign in to your account to continue
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
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password">Password</Label>
              <Link
                to="/forgot-password"
                className="text-sm text-[color:var(--fg-secondary)] hover:text-primary"
              >
                Forgot password?
              </Link>
            </div>
            <Input
              id="password"
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {loading ? "Signing in..." : "Sign In"}
          </Button>
          <p className="text-sm text-[color:var(--fg-secondary)] text-center">
            Don't have an account?{" "}
            <Link to="/signup" className="text-primary hover:underline">
              Sign up
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  );
}
