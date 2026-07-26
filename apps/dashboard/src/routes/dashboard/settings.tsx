import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { AccountService, type GitCredential } from "@codewire/proto-ts/gen/codewire/console/v1/account_pb";
import { GitHubService } from "@codewire/proto-ts/gen/codewire/console/v1/github_pb";
import {
  accountServiceQueryKey,
  connectTransport,
  githubServiceQueryKey,
} from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Github, GitBranch, CheckCircle2, XCircle, Loader2, Key, User, Copy, RefreshCw, Plus, Trash2 } from "lucide-react";

export const Route = createFileRoute("/dashboard/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  const queryClient = useQueryClient();

  const { data: ghStatus, isLoading: ghLoading } = useConnectQuery(
    GitHubService.method.getGitHubStatus,
    undefined,
    { transport: connectTransport },
  );

  const disconnectMutation = useConnectMutation(GitHubService.method.deleteGitHubToken, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: githubServiceQueryKey });
    },
  });

  return (
    <div className="max-w-2xl mx-auto py-8 px-4">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-[color:var(--fg-primary)]">
          Settings
        </h1>
        <p className="text-sm text-[color:var(--fg-secondary)] mt-1">
          Manage your account settings and integrations
        </p>
      </div>

      {/* GitHub Section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Github className="h-5 w-5" />
            GitHub
          </CardTitle>
          <CardDescription>
            Connect your GitHub account to create environments from private repositories.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {ghLoading ? (
            <div className="flex items-center gap-2 text-sm text-[color:var(--fg-tertiary)]">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading...
            </div>
          ) : ghStatus?.connected ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                <span className="text-[color:var(--fg-primary)]">
                  Connected as <span className="font-medium">@{ghStatus.username}</span>
                </span>
              </div>
              {ghStatus.connectedAt && (
                <p className="text-xs text-[color:var(--fg-tertiary)]">
                  Connected {timestampDate(ghStatus.connectedAt).toLocaleDateString()}
                </p>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => disconnectMutation.mutate({})}
                disabled={disconnectMutation.isPending}
              >
                {disconnectMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <XCircle className="h-4 w-4 mr-2" />
                )}
                Disconnect
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-[color:var(--fg-tertiary)]">
                Not connected
              </p>
              <Button
                onClick={() => {
                  window.location.href = `/api/v1/github/oauth/authorize?return_url=${encodeURIComponent(window.location.href)}`;
                }}
              >
                <Github className="h-4 w-4 mr-2" />
                Connect GitHub
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Git Authentication Section */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <GitBranch className="h-5 w-5" />
            Git Authentication
          </CardTitle>
          <CardDescription>
            Add credentials for Gitea, GitLab, Bitbucket, or any git host. Credentials auto-match by host when cloning.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <GitCredentialsSection />
        </CardContent>
      </Card>

      {/* Git Identity Section */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <User className="h-5 w-5" />
            Git Identity
          </CardTitle>
          <CardDescription>
            Used for git commits in environments. Defaults to your account name and email if unset.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <GitIdentityForm />
        </CardContent>
      </Card>

      {/* SSH Key Section */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Key className="h-5 w-5" />
            SSH Key
          </CardTitle>
          <CardDescription>
            Added to every environment. Add this key to GitHub, GitLab, or any server.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SSHKeyCard />
        </CardContent>
      </Card>
    </div>
  );
}

function GitCredentialsSection() {
  const queryClient = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const { data: credentialsResponse, isLoading } = useConnectQuery(
    AccountService.method.listGitCredentials,
    undefined,
    { transport: connectTransport },
  );
  const credentials = credentialsResponse?.gitCredentials ?? [];

  const addMutation = useConnectMutation(AccountService.method.createGitCredential, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: accountServiceQueryKey });
      setShowAdd(false);
      setName("");
      setHost("");
      setUsername("");
      setPassword("");
      setError("");
    },
    onError: (error) => {
      setError(errorMessage(error));
    },
  });

  const deleteMutation = useConnectMutation(AccountService.method.deleteGitCredential, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: accountServiceQueryKey });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-[color:var(--fg-tertiary)]">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading...
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {credentials.length > 0 && (
        <div className="border border-[color:var(--border-primary)] rounded-md divide-y divide-[color:var(--border-primary)]">
          {credentials.map((cred: GitCredential) => (
            <div key={cred.id} className="flex items-center justify-between px-3 py-2">
              <div>
                <span className="text-sm font-medium text-[color:var(--fg-primary)]">
                  {cred.name}
                </span>
                <span className="text-xs text-[color:var(--fg-tertiary)] ml-2">
                  {cred.host}
                </span>
                {cred.username && (
                  <span className="text-xs text-[color:var(--fg-tertiary)] ml-2">
                    ({cred.username})
                  </span>
                )}
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => deleteMutation.mutate({ credentialId: cred.id })}
                disabled={deleteMutation.isPending}
              >
                <Trash2 className="h-4 w-4 text-[color:var(--fg-tertiary)]" />
              </Button>
            </div>
          ))}
        </div>
      )}

      {showAdd ? (
        <div className="space-y-3 border border-[color:var(--border-primary)] rounded-md p-3">
          <div>
            <Label htmlFor="cred-name">Name</Label>
            <Input
              id="cred-name"
              placeholder="my gitea"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="cred-host">Host</Label>
            <Input
              id="cred-host"
              placeholder="git.example.com"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="cred-username">Username (optional)</Label>
            <Input
              id="cred-username"
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="cred-password">Token / Password</Label>
            <Input
              id="cred-password"
              type="password"
              placeholder="access token or password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && (
            <p className="text-xs text-red-500">{error}</p>
          )}
          <div className="flex gap-2">
            <Button
              onClick={() => addMutation.mutate({
                name,
                host,
                authType: "basic",
                username,
                password,
              })}
              disabled={!name || !host || !password || addMutation.isPending}
            >
              {addMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : null}
              Save
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setShowAdd(false);
                setError("");
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="outline" size="sm" onClick={() => setShowAdd(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Credential
        </Button>
      )}
    </div>
  );
}

function GitIdentityForm() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [loaded, setLoaded] = useState(false);

  const { data: identityResponse, isLoading } = useConnectQuery(
    AccountService.method.getGitIdentity,
    undefined,
    { transport: connectTransport },
  );
  const identity = identityResponse?.gitIdentity;

  // Populate form fields once loaded.
  if (identity && !loaded) {
    setName(identity.gitName ?? "");
    setEmail(identity.gitEmail ?? "");
    setLoaded(true);
  }

  const saveMutation = useConnectMutation(AccountService.method.updateGitIdentity, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: accountServiceQueryKey });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-[color:var(--fg-tertiary)]">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading...
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div>
        <Label htmlFor="git-name">Name</Label>
        <Input
          id="git-name"
          placeholder={identity?.gitName || "Your name"}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div>
        <Label htmlFor="git-email">Email</Label>
        <Input
          id="git-email"
          type="email"
          placeholder={identity?.gitEmail || "you@example.com"}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>
      <Button
        onClick={() => saveMutation.mutate({
          gitName: name || undefined,
          gitEmail: email || undefined,
        })}
        disabled={saveMutation.isPending}
      >
        {saveMutation.isPending ? (
          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
        ) : null}
        Save
      </Button>
    </div>
  );
}

function SSHKeyCard() {
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [confirmRegen, setConfirmRegen] = useState(false);

  const { data: sshKeyResponse, isLoading } = useConnectQuery(
    AccountService.method.ensureSshKey,
    undefined,
    { transport: connectTransport },
  );
  const sshKey = sshKeyResponse?.sshKey;

  const regenMutation = useConnectMutation(AccountService.method.regenerateSshKey, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: accountServiceQueryKey });
      setConfirmRegen(false);
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-[color:var(--fg-tertiary)]">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading...
      </div>
    );
  }

  if (!sshKey) return null;

  return (
    <div className="space-y-3">
      <code className="block text-xs bg-[color:var(--bg-tertiary)] text-[color:var(--fg-primary)] p-3 rounded-md break-all whitespace-pre-wrap font-mono">
        {sshKey.publicKey.trim()}
      </code>
      <p className="text-xs text-[color:var(--fg-tertiary)]">
        {sshKey.fingerprint}
      </p>
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            navigator.clipboard.writeText(sshKey.publicKey.trim());
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
        >
          <Copy className="h-4 w-4 mr-2" />
          {copied ? "Copied" : "Copy"}
        </Button>
        {confirmRegen ? (
          <div className="flex items-center gap-2">
            <span className="text-xs text-[color:var(--fg-tertiary)]">
              Old key will stop working.
            </span>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => regenMutation.mutate({})}
              disabled={regenMutation.isPending}
            >
              {regenMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : null}
              Confirm
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmRegen(false)}
            >
              Cancel
            </Button>
          </div>
        ) : (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setConfirmRegen(true)}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Regenerate
          </Button>
        )}
      </div>
    </div>
  );
}
