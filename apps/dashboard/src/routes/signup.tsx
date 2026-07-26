import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { signUp } from "@/lib/auth";
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

export const Route = createFileRoute("/signup")({
  component: SignupPage,
});

function SignupPage() {
  const [inviteCode, setInviteCode] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await signUp(email, password, name, inviteCode);
      // Signup creates a session and sets the cookie — go straight to dashboard
      window.location.href = "/dashboard";
    } catch (err) {
      const msg = err instanceof Error ? err.message : "An unexpected error occurred";
      setError(msg === "Invalid invite code" ? "Invalid invite code. Please check your code and try again." : msg);
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
        <CardTitle className="text-2xl">Create your account</CardTitle>
        <CardDescription>
          Get started with Codewire
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
            <Label htmlFor="invite-code">Invite Code</Label>
            <Input
              id="invite-code"
              type="text"
              placeholder="Enter your invite code"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              type="text"
              placeholder="John Doe"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

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
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="At least 12 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={12}
              required
            />
            {password && <PasswordStrength password={password} />}
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {loading ? "Creating account..." : "Create Account"}
          </Button>
          <p className="text-sm text-[color:var(--fg-secondary)] text-center">
            Already have an account?{" "}
            <Link to="/login" className="text-primary hover:underline">
              Sign in
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  );
}
