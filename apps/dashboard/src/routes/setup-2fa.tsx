import { createFileRoute, redirect } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { getSession } from "@/lib/auth";
import { authClient } from "@/lib/auth-client";
import QRCode from "qrcode";
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
import { Loader2, Shield, Copy, Check } from "lucide-react";

export const Route = createFileRoute("/setup-2fa")({
  beforeLoad: async () => {
    const session = await getSession();
    if (!session?.user) {
      throw redirect({ to: "/login" });
    }
    if (session.user.two_factor_enabled) {
      throw redirect({ to: "/dashboard" });
    }
    return { session };
  },
  component: Setup2FAPage,
});

type SetupStep = "generate" | "verify" | "backup";

function Setup2FAPage() {
  const generatedOnMountRef = useRef(false);
  const [step, setStep] = useState<SetupStep>("generate");
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (generatedOnMountRef.current) return;
    generatedOnMountRef.current = true;
    generateSetup();
  }, []);

  const generateSetup = async () => {
    setGenerating(true);
    setError("");
    try {
      const result = await authClient.twoFactor.enable();
      if (result.error) {
        setError(result.error.message || "Failed to generate 2FA setup");
        return;
      }
      const data = result.data as { totpUri: string; secret: string; backupCodes: string[] } | undefined;
      if (data) {
        const dataUrl = await QRCode.toDataURL(data.totpUri, {
          width: 256,
          margin: 2,
        });
        setQrDataUrl(dataUrl);
        setSecret(data.secret);
        setBackupCodes(data.backupCodes);
        setStep("verify");
      }
    } catch {
      setError("Failed to generate 2FA setup");
    } finally {
      setGenerating(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await authClient.twoFactor.verify({ code });
      if (result.error) {
        setError(result.error.message || "Invalid verification code");
        return;
      }
      setStep("backup");
    } catch {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  const copyBackupCodes = async () => {
    await navigator.clipboard.writeText(backupCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (generating) {
    return (
      <div className="flex items-center gap-3">
        <Loader2 className="h-6 w-6 animate-spin text-[color:var(--fg-secondary)]" />
        <span className="text-[color:var(--fg-secondary)]">Setting up two-factor authentication...</span>
      </div>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <div className="h-12 w-12 rounded-lg bg-[var(--accent)]/10 flex items-center justify-center">
            <Shield className="h-6 w-6 text-primary" />
          </div>
        </div>
        <CardTitle className="text-2xl">
          {step === "backup" ? "Save Backup Codes" : "Set Up Two-Factor Authentication"}
        </CardTitle>
        <CardDescription>
          {step === "verify" &&
            "Scan the QR code with your authenticator app, then enter the 6-digit code to verify."}
          {step === "backup" &&
            "Save these backup codes in a safe place. You can use them to sign in if you lose access to your authenticator app."}
          {step === "generate" && error &&
            "There was an issue setting up 2FA."}
        </CardDescription>
      </CardHeader>

      {step === "verify" && (
        <form onSubmit={handleVerify}>
          <CardContent className="space-y-4">
            {error && (
              <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
                {error}
              </div>
            )}

            {qrDataUrl && (
              <div className="flex justify-center">
                <img
                  src={qrDataUrl}
                  alt="Scan this QR code with your authenticator app"
                  className="rounded-lg"
                  width={256}
                  height={256}
                />
              </div>
            )}

            <div className="space-y-1">
              <p className="text-xs text-[color:var(--fg-secondary)] text-center">
                Can't scan? Enter this key manually:
              </p>
              <p className="text-center font-mono text-sm bg-[var(--bg-surface)] px-3 py-2 rounded-md select-all break-all">
                {secret}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="code">Verification Code</Label>
              <Input
                id="code"
                type="text"
                placeholder="000000"
                value={code}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, "");
                  if (value.length <= 6) setCode(value);
                }}
                className="text-center text-2xl tracking-widest font-mono"
                autoComplete="one-time-code"
                maxLength={6}
                required
                autoFocus
              />
            </div>
          </CardContent>
          <CardFooter>
            <Button
              type="submit"
              className="w-full"
              disabled={loading || code.length < 6}
            >
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Verifying..." : "Verify & Enable"}
            </Button>
          </CardFooter>
        </form>
      )}

      {step === "backup" && (
        <>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-2 bg-[var(--bg-surface)] p-4 rounded-lg font-mono text-sm">
              {backupCodes.map((bc, i) => (
                <div key={i} className="text-center py-1">
                  {bc}
                </div>
              ))}
            </div>

            <Button
              variant="outline"
              className="w-full gap-2"
              onClick={copyBackupCodes}
            >
              {copied ? (
                <Check className="h-4 w-4" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
              {copied ? "Copied!" : "Copy Backup Codes"}
            </Button>
          </CardContent>
          <CardFooter>
            <Button
              className="w-full"
              onClick={() => {
                window.location.href = "/dashboard";
              }}
            >
              Continue to Dashboard
            </Button>
          </CardFooter>
        </>
      )}

      {step === "generate" && error && (
        <>
          <CardContent>
            <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
              {error}
            </div>
          </CardContent>
          <CardFooter>
            <Button className="w-full" onClick={generateSetup}>
              Try Again
            </Button>
          </CardFooter>
        </>
      )}
    </Card>
  );
}
