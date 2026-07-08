import { env } from "@flycockpit/env/web";
import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@flycockpit/ui/components/dialog";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import type { TFunction } from "i18next";
import { Copy, KeyRound, Plus, Trash } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { authClient } from "@/lib/auth-client";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

type ApiKeySummary = {
  id: string;
  name: string | null;
  start: string | null;
  prefix: string | null;
  enabled: boolean;
  expiresAt: Date | string | null;
  createdAt: Date | string;
  lastRequest: Date | string | null;
  permissions: { mcp?: string[] } | null;
};

const API_KEYS_QUERY = ["api-keys"] as const;

export const Route = createFileRoute("/$lang/admin/api-keys")({
  component: AdminApiKeys,
});

function AdminApiKeys() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<{ key: string; name: string } | null>(null);
  const { t } = useTranslation(["admin", "common"]);

  const list = useQuery({
    queryKey: API_KEYS_QUERY,
    queryFn: async (): Promise<ApiKeySummary[]> => {
      const result = await authClient.apiKey.list();
      if (result.error) {
        console.error("[api-keys.list]", result.error);
        throw new Error(t("admin:apiKeys.loadFailed"));
      }
      // The list endpoint returns `{ apiKeys, total, limit, offset }`. We only
      // surface the rows here and let the user paginate by deleting old keys.
      return (result.data?.apiKeys ?? []) as unknown as ApiKeySummary[];
    },
  });

  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const result = await authClient.apiKey.delete({ keyId: id });
      if (result.error) {
        console.error("[api-keys.revoke]", result.error);
        throw new Error(t("admin:apiKeys.revokeFailed"));
      }
      return result.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: API_KEYS_QUERY });
      toast.success(t("admin:apiKeys.revoked"));
      setRevokeId(null);
    },
    onError: (err) => {
      toast.error(friendly(err, t("admin:apiKeys.revokeFailedRetry")));
    },
    meta: { skipGlobalErrorToast: true },
  });

  const revokeTarget = list.data?.find((k) => k.id === revokeId) ?? null;
  const revokeToken = revokeTarget ? (revokeTarget.name ?? revokeTarget.id) : "";

  return (
    <div className="container mx-auto max-w-3xl px-4 py-8 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("admin:apiKeys.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("admin:apiKeys.description")}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)} className="min-h-[44px]">
          <Plus className="size-4" /> {t("admin:apiKeys.newKey")}
        </Button>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="size-4" /> {t("admin:apiKeys.yourKeys")}
          </CardTitle>
          <CardDescription>{t("admin:apiKeys.yourKeysDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          {list.isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : list.isError ? (
            <InlineRetry
              variant="destructive"
              onRetry={() => list.refetch()}
              message={friendly(list.error, t("admin:apiKeys.loadFailed"))}
            />
          ) : (list.data ?? []).length === 0 ? (
            <div className="rounded-md border border-dashed py-10 text-center">
              <p className="text-sm font-medium">{t("admin:apiKeys.noKeys")}</p>
              <p className="mt-1 text-sm text-muted-foreground">{t("admin:apiKeys.noKeysHint")}</p>
            </div>
          ) : (
            <ul className="divide-y">
              {(list.data ?? []).map((key) => (
                <li key={key.id} className="flex items-center justify-between gap-4 py-3">
                  <div className="min-w-0 space-y-0.5">
                    <p className="truncate font-medium">
                      {key.name ?? t("admin:apiKeys.untitled")}
                    </p>
                    <p className="font-mono text-xs text-muted-foreground">
                      {key.start ? `${key.start}…` : t("admin:apiKeys.hidden")}
                      {key.expiresAt
                        ? ` · ${t("admin:apiKeys.expires", { date: formatDate(key.expiresAt) })}`
                        : ` · ${t("admin:apiKeys.noExpiry")}`}
                      {" · "}
                      {formatMcpScope(key.permissions, t)}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    aria-label={t("admin:apiKeys.revokeAriaLabel", {
                      name: key.name ?? t("admin:apiKeys.revokeFallbackName"),
                    })}
                    onClick={() => setRevokeId(key.id)}
                    className="min-h-[44px]"
                  >
                    <Trash className="size-4" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <CreateKeyDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(key) => {
          setCreateOpen(false);
          setRevealedKey(key);
        }}
      />

      <RevealKeyDialog revealed={revealedKey} onClose={() => setRevealedKey(null)} />

      <ConfirmDeleteDialog
        open={!!revokeId}
        onOpenChange={(open) => {
          if (!open) setRevokeId(null);
        }}
        title={t("admin:apiKeys.revokeKeyTitle")}
        description={
          revokeTarget?.name
            ? t("admin:apiKeys.revokeKeyDescriptionNamed", { name: revokeTarget.name })
            : t("admin:apiKeys.revokeKeyDescriptionUnnamed")
        }
        confirmToken={revokeToken}
        typePrompt={
          revokeTarget?.name
            ? t("admin:apiKeys.typeNameToConfirm")
            : t("admin:apiKeys.typeIdToConfirm")
        }
        copyAriaLabel={t("admin:apiKeys.copyIdAriaLabel")}
        confirmLabel={t("admin:apiKeys.revoke")}
        pendingLabel={t("admin:apiKeys.revoking")}
        isPending={revoke.isPending}
        onConfirm={() => revokeId && revoke.mutate(revokeId)}
      />
    </div>
  );
}

function CreateKeyDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (next: boolean) => void;
  onCreated: (revealed: { key: string; name: string }) => void;
}) {
  const [name, setName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState<string>("90");
  const [scope, setScope] = useState<"read" | "write">("read");
  const queryClient = useQueryClient();
  const { t } = useTranslation(["admin", "common"]);

  const create = useMutation({
    mutationFn: async () => {
      const trimmed = name.trim();
      if (!trimmed) throw new Error(t("admin:apiKeys.nameRequired"));
      const expiresIn = expiresInDays === "" ? null : Number(expiresInDays) * 24 * 60 * 60;
      if (expiresIn !== null && (!Number.isFinite(expiresIn) || expiresIn <= 0)) {
        throw new Error(t("admin:apiKeys.expiryPositive"));
      }
      const result = await authClient.apiKey.create({
        name: trimmed,
        ...(expiresIn != null ? { expiresIn } : {}),
      });
      if (result.error) {
        console.error("[api-keys.create]", result.error);
        throw new Error(t("admin:apiKeys.createFailed"));
      }
      // The plaintext key is in result.data.key — only available on this
      // single response. The /admin/api-keys list never returns it again.
      const created = result.data as unknown as { id: string; key: string };
      // Better-Auth's create endpoint treats `permissions` as server-only, so
      // the MCP scope is applied in a second call. If that fails, delete the
      // just-created key — an unscoped key is rejected by the MCP gate and its
      // plaintext is already lost, so leaving it orphaned only adds confusion.
      try {
        const scoped = await orpc.apiKeys.setMcpScope.call({ keyId: created.id, scope });
        if (!scoped.success) throw new Error(t("admin:apiKeys.createFailed"));
      } catch (err) {
        await authClient.apiKey.delete({ keyId: created.id }).catch(() => {});
        throw err;
      }
      return { key: created.key, name: trimmed };
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: API_KEYS_QUERY });
      setName("");
      setExpiresInDays("90");
      setScope("read");
      onCreated(data);
    },
    onError: (err) => {
      toast.error(friendly(err, t("admin:apiKeys.createFailedRetry")));
    },
    meta: { skipGlobalErrorToast: true },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!create.isPending) onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("admin:apiKeys.createTitle")}</DialogTitle>
          <DialogDescription>
            <Trans i18nKey="apiKeys.createDescription" t={t} components={[<strong key="0" />]} />
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="api-key-name">{t("admin:apiKeys.nameLabel")}</Label>
            <Input
              id="api-key-name"
              autoComplete="off"
              placeholder={t("admin:apiKeys.namePlaceholder")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={32}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="api-key-expiry">{t("admin:apiKeys.expiresInLabel")}</Label>
            <Input
              id="api-key-expiry"
              type="number"
              inputMode="numeric"
              min={1}
              max={365}
              placeholder={t("admin:apiKeys.expiresInPlaceholder")}
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="api-key-scope">{t("admin:apiKeys.scopeLabel")}</Label>
            <select
              id="api-key-scope"
              value={scope}
              onChange={(e) => setScope(e.target.value === "write" ? "write" : "read")}
              className="min-h-[44px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            >
              <option value="read">{t("admin:apiKeys.scopeRead")}</option>
              <option value="write">{t("admin:apiKeys.scopeWrite")}</option>
            </select>
            <p className="text-xs text-muted-foreground">{t("admin:apiKeys.scopeDescription")}</p>
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            onClick={() => onOpenChange(false)}
            disabled={create.isPending}
            className="min-h-[44px]"
          >
            {t("common:actions.cancel")}
          </Button>
          <Button
            onClick={() => create.mutate()}
            disabled={create.isPending}
            className="min-h-[44px]"
          >
            {create.isPending ? t("admin:apiKeys.creating") : t("admin:apiKeys.createKey")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RevealKeyDialog({
  revealed,
  onClose,
}: {
  revealed: { key: string; name: string } | null;
  onClose: () => void;
}) {
  const { t } = useTranslation("admin");
  const appName = env.VITE_APP_NAME.toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
  const mcpUrl = `${env.VITE_SERVER_URL.replace(/\/$/, "")}/mcp`;
  const mcpConfig = revealed
    ? JSON.stringify(
        {
          mcpServers: {
            [`${appName || "app"}-admin`]: {
              transport: "http",
              url: mcpUrl,
              headers: { Authorization: `Bearer ${revealed.key}` },
            },
          },
        },
        null,
        2,
      )
    : "";

  return (
    <Dialog
      open={!!revealed}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("apiKeys.revealTitle")}</DialogTitle>
          <DialogDescription>{t("apiKeys.revealDescription")}</DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label>{t("apiKeys.apiKeyLabel")}</Label>
            <CopyableBlock value={revealed?.key ?? ""} label={t("apiKeys.apiKeyLabel")} mono />
          </div>

          <div className="space-y-1.5">
            <Label>{t("apiKeys.mcpClientLabel")}</Label>
            <CopyableBlock value={mcpConfig} label={t("apiKeys.mcpConfigLabel")} />
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onClose} className="min-h-[44px]">
            {t("apiKeys.savedIt")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function CopyableBlock({ value, label, mono }: { value: string; label: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  const { t } = useTranslation(["admin", "common", "errors"]);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success(t("admin:apiKeys.copied", { label }));
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error(t("errors:couldNotCopy"));
    }
  };
  return (
    <div className="relative">
      <pre
        className={
          "max-h-72 overflow-auto rounded-md border bg-muted/40 p-3 pr-12 text-xs " +
          (mono ? "font-mono break-all whitespace-pre-wrap" : "whitespace-pre")
        }
      >
        {value}
      </pre>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="absolute right-1 top-1 min-h-[44px] min-w-[44px]"
        aria-label={t("admin:apiKeys.copyAriaLabel", { label })}
        onClick={onCopy}
      >
        <Copy className="size-4" />{" "}
        <span className="sr-only">
          {copied ? t("common:actions.copied") : t("common:actions.copy")}
        </span>
      </Button>
    </div>
  );
}

function formatDate(value: Date | string): string {
  const d = typeof value === "string" ? new Date(value) : value;
  return d.toLocaleDateString();
}

function formatMcpScope(permissions: ApiKeySummary["permissions"], t: TFunction<"admin">): string {
  const mcp = permissions?.mcp ?? [];
  if (mcp.includes("write")) return t("apiKeys.scopeWriteShort");
  if (mcp.includes("read")) return t("apiKeys.scopeReadShort");
  return t("apiKeys.scopeLegacy");
}
