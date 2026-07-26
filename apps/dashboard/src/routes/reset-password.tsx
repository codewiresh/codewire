import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { authClient } from "@/lib/auth-client";
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
import { Code2, Loader2, CheckCircle, XCircle, ArrowLeft } from "lucide-react";

export const Route = createFileRoute("/reset-password")({
  component: ResetPasswordPage,
  validateSearch: (search: Record<string, unknown>) => ({
    token: (search.token as string) || "",
    error: (search.error as string) || "",
  }),
});

function PasswordStrength({ password }: { password: string }) {
  const checks = [
    { label: "12+ characters", met: password.length >= 12 },
    { label: "Uppercase letter", met: /[A-Z]/.test(password) },
    { label: "Lowercase letter", met: /[a-z]/.test(password) },
    { label: "Number", met: /[0-9]/.test(password) },
    { label: "Special character", met: /[^A-Za-z0-9]/.test(password) },
  ];
  const metCount = checks.filter((c) => c.met).length;
  const barColor =
    metCount <= 2
      ? "bg-destructive"
      : metCount <= 4
        ? "bg-yellow-400"
        : "bg-green-400";

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full ${i < metCount ? barColor : "bg-muted"}`}
          />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-1">
        {checks.map((check) => (
          <span
            key={check.label}
            className={`text-xs ${check.met ? "text-[color:var(--success)]" : "text-muted-foreground"}`}
          >
            {check.met ? "\u2713" : "\u2022"} {check.label}
          </span>
        ))}
      </div>
    </div>
  );
}

function ResetPasswordPage() {
  const { token, error: urlError } = Route.useSearch();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState(urlError || "");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (password.length < 12) {
      setError("Password must be at least 12 characters");
      return;
    }

    setLoading(true);

    try {
      const result = await authClient.resetPassword({
        newPassword: password,
        token,
      });

      if (result.error) {
        setError(result.error.message || "Failed to reset password");
        return;
      }

      setSuccess(true);
    } catch {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  if (urlError === "INVALID_TOKEN" || (!token && !success)) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <div className="h-12 w-12 rounded-lg bg-destructive/10 flex items-center justify-center">
              <XCircle className="h-6 w-6 text-destructive" />
            </div>
          </div>
          <CardTitle className="text-2xl">Invalid or expired link</CardTitle>
          <CardDescription>
            This password reset link is invalid or has expired. Please request
            a new one.
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col gap-4">
          <Link to="/forgot-password" className="w-full">
            <Button className="w-full">Request new reset link</Button>
          </Link>
          <Link
            to="/login"
            className="text-sm text-[color:var(--fg-secondary)] hover:text-primary"
          >
            <ArrowLeft className="inline mr-1 h-3 w-3" />
            Back to login
          </Link>
        </CardFooter>
      </Card>
    );
  }

  if (success) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <div className="h-12 w-12 rounded-lg bg-[var(--success)]/10 flex items-center justify-center">
              <CheckCircle className="h-6 w-6 text-[color:var(--success)]" />
            </div>
          </div>
          <CardTitle className="text-2xl">Password reset!</CardTitle>
          <CardDescription>
            Your password has been successfully reset. You can now sign in
            with your new password.
          </CardDescription>
        </CardHeader>
        <CardFooter>
          <Link to="/login" className="w-full">
            <Button className="w-full">Sign in</Button>
          </Link>
        </CardFooter>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
            <Code2 className="h-6 w-6 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl">Reset your password</CardTitle>
        <CardDescription>Enter your new password below</CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {error && (
            <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
              {error}
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="password">New Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="Enter your new password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
            />
            {password && <PasswordStrength password={password} />}
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirmPassword">Confirm Password</Label>
            <Input
              id="confirmPassword"
              type="password"
              placeholder="Confirm your new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              minLength={12}
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {loading ? "Resetting..." : "Reset password"}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
