import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useMutation as useConnectMutation,
  useQuery as useConnectQuery,
} from "@connectrpc/connect-query";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { connectTransport, secretServiceQueryKey } from "@/lib/connect";
import { errorMessage } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Check, KeyRound, Loader2, Pencil, Plus, Trash2, X } from "lucide-react";

export function SecretProjectDialog({
  orgId,
  projectId,
  projectName,
  open,
  onClose,
}: {
  orgId: string;
  projectId: string;
  projectName: string;
  open: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");

  const { data: secretsData, isLoading } = useConnectQuery(
    SecretService.method.listProjectSecrets,
    { orgId, secretProjectId: projectId },
    { enabled: open, transport: connectTransport },
  );

  const secrets = secretsData?.secrets ?? [];

  const addMutation = useConnectMutation(SecretService.method.setProjectSecret, {
    transport: connectTransport,
    onSuccess: () => {
      setNewKey("");
      setNewValue("");
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });
    },
  });

  const deleteMutation = useConnectMutation(SecretService.method.deleteProjectSecret, {
    transport: connectTransport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });
    },
  });

  const editMutation = useConnectMutation(SecretService.method.setProjectSecret, {
    transport: connectTransport,
    onSuccess: () => {
      setEditingKey(null);
      setEditValue("");
      queryClient.invalidateQueries({ queryKey: secretServiceQueryKey });
    },
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{projectName}</DialogTitle>
          <DialogDescription>Manage secrets for this project</DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-[color:var(--fg-tertiary)]" />
          </div>
        ) : secrets.length === 0 ? (
          <p className="text-sm text-[color:var(--fg-secondary)] text-center py-4">
            No secrets configured
          </p>
        ) : (
          <div className="space-y-2">
            {secrets.map((s) => (
              <div key={s.key} className="rounded-md border border-[var(--border-subtle)] px-3 py-2">
                {editingKey === s.key ? (
                  <form
                    className="flex items-center gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (editValue) {
                        editMutation.mutate({
                          orgId,
                          secretProjectId: projectId,
                          key: s.key,
                          value: editValue,
                        });
                      }
                    }}
                  >
                    <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                    <span className="text-sm font-mono font-medium text-[color:var(--fg-primary)] truncate">
                      {s.key}
                    </span>
                    <Input
                      type="password"
                      placeholder="new value"
                      value={editValue}
                      onChange={(e) => setEditValue(e.target.value)}
                      className="flex-1 h-8 text-sm"
                      autoFocus
                    />
                    <Button
                      size="sm"
                      type="submit"
                      disabled={!editValue || editMutation.isPending}
                    >
                      {editMutation.isPending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        "Save"
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      type="button"
                      onClick={() => { setEditingKey(null); setEditValue(""); }}
                      className="h-6 w-6 p-0"
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </form>
                ) : (
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <KeyRound className="h-4 w-4 text-[color:var(--fg-tertiary)] shrink-0" />
                      <span className="text-sm font-mono font-medium text-[color:var(--fg-primary)] truncate">
                        {s.key}
                      </span>
                      <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-[var(--success)]/10 text-[var(--success)]">
                        <Check className="h-3 w-3" />
                        Set
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => { setEditingKey(s.key); setEditValue(""); }}
                        className="h-6 w-6 p-0"
                      >
                        <Pencil className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          deleteMutation.mutate({
                            orgId,
                            secretProjectId: projectId,
                            key: s.key,
                          })
                        }
                        disabled={deleteMutation.isPending}
                        className="h-6 w-6 p-0 text-[color:var(--destructive)]"
                      >
                        {deleteMutation.isPending ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Trash2 className="h-3 w-3" />
                        )}
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="border-t border-[var(--border)] pt-3">
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (newKey && newValue) {
                addMutation.mutate({
                  orgId,
                  secretProjectId: projectId,
                  key: newKey,
                  value: newValue,
                });
              }
            }}
          >
            <Input
              placeholder="KEY_NAME"
              value={newKey}
              onChange={(e) =>
                setNewKey(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))
              }
              className="flex-1 h-8 text-sm font-mono"
            />
            <Input
              type="password"
              placeholder="value"
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              className="flex-1 h-8 text-sm"
            />
            <Button
              size="sm"
              type="submit"
              disabled={!newKey || !newValue || addMutation.isPending}
            >
              {addMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <>
                  <Plus className="h-3.5 w-3.5 mr-1" />
                  Add
                </>
              )}
            </Button>
          </form>
        </div>

        {(addMutation.error || editMutation.error || deleteMutation.error) && (
          <p role="alert" className="text-sm text-[color:var(--destructive)]">
            {errorMessage(addMutation.error ?? editMutation.error ?? deleteMutation.error)}
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
