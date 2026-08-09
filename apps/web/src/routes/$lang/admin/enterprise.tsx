import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { Download, FileJson, FileText, RefreshCcw, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { useHaptics } from "@/hooks/use-haptics";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/enterprise")({
  component: EnterpriseAdmin,
});

type EnterpriseOverview = Awaited<ReturnType<typeof orpc.enterprise.overview.call>>;

const fromBase64Url = (value: string) => {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
};
const toBase64Url = (value: ArrayBuffer) => {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

function EnterpriseAdmin() {
  const queryClient = useQueryClient();
  const { trigger } = useHaptics();
  const { t } = useTranslation(["admin", "common"]);
  const overview = useQuery(orpc.enterprise.overview.queryOptions());

  const invalidate = () => queryClient.invalidateQueries({ queryKey: orpc.enterprise.key() });
  const bootstrap = useMutation({
    mutationFn: async ({ name }: { name: string }) => {
      const ceremony = await orpc.enterprise.bootstrap.call({ name });
      if (!window.PublicKeyCredential) throw new Error("WebAuthn is required.");
      const created = (await navigator.credentials.create({
        publicKey: {
          challenge: fromBase64Url(ceremony.challenge),
          rp: { id: ceremony.rpId, name: "FlyCockpit" },
          user: {
            id: new TextEncoder().encode(crypto.randomUUID()),
            name: "enterprise-owner",
            displayName: "Enterprise owner",
          },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 300_000,
          authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
          attestation: "none",
        },
      })) as PublicKeyCredential | null;
      if (!created || !(created.response instanceof AuthenticatorAttestationResponse))
        throw new Error("Passkey registration was cancelled.");
      const publicKey = created.response.getPublicKey();
      if (!publicKey || created.response.getPublicKeyAlgorithm() !== -7)
        throw new Error("An ES256 passkey is required.");
      const credentialIdHash = await crypto.subtle.digest("SHA-256", created.rawId);
      const asserted = (await navigator.credentials.get({
        publicKey: {
          challenge: fromBase64Url(ceremony.challenge),
          rpId: ceremony.rpId,
          allowCredentials: [{ type: "public-key", id: created.rawId }],
          timeout: 300_000,
          userVerification: "required",
        },
      })) as PublicKeyCredential | null;
      if (!asserted || !(asserted.response instanceof AuthenticatorAssertionResponse))
        throw new Error("Passkey verification was cancelled.");
      return orpc.enterprise.completeOwnerBootstrap.call({
        challengeId: ceremony.challengeId,
        credentialIdHash: toBase64Url(credentialIdHash),
        publicKeySpki: toBase64Url(publicKey),
        declaredCustody: "UNKNOWN",
        authenticatorData: toBase64Url(asserted.response.authenticatorData),
        clientDataJson: toBase64Url(asserted.response.clientDataJSON),
        signatureDer: toBase64Url(asserted.response.signature),
      });
    },
    ...{
      onSuccess: () => {
        invalidate();
        trigger("success");
        toast.success(t("admin:enterprise.bootstrapSuccess"));
      },
      onError: () => trigger("error"),
    },
    meta: { errorFallbackKey: "admin:enterprise.bootstrapFailed" },
  });
  const updatePolicy = useMutation({
    ...orpc.enterprise.updatePolicy.mutationOptions({
      onSuccess: () => {
        invalidate();
        trigger("success");
        toast.success(t("admin:enterprise.policyUpdated"));
      },
      onError: () => trigger("error"),
    }),
    meta: { errorFallbackKey: "admin:enterprise.policyUpdateFailed" },
  });
  const createExport = useMutation({
    ...orpc.enterprise.createExport.mutationOptions({
      onSuccess: () => {
        invalidate();
        trigger("success");
        toast.success(t("admin:enterprise.exportQueued"));
      },
      onError: () => trigger("error"),
    }),
    meta: { errorFallbackKey: "admin:enterprise.exportFailed" },
  });
  const downloadExport = useMutation({
    ...orpc.enterprise.downloadExport.mutationOptions({
      onSuccess: (result) => {
        trigger("success");
        window.location.assign(result.url);
      },
      onError: () => trigger("error"),
    }),
    meta: { errorFallbackKey: "admin:enterprise.downloadFailed" },
  });

  if (overview.isPending) return <EnterpriseSkeleton />;
  if (overview.isError) {
    return (
      <div className="container mx-auto max-w-6xl px-4 py-8">
        <InlineRetry
          message={t("admin:enterprise.loadFailed")}
          onRetry={() => overview.refetch()}
        />
      </div>
    );
  }

  const data = overview.data;
  return (
    <div className="container mx-auto max-w-6xl px-4 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("admin:enterprise.title")}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{t("admin:enterprise.description")}</p>
      </div>

      {!data.org || !data.policy ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("admin:enterprise.bootstrapTitle")}</CardTitle>
            <CardDescription>{t("admin:enterprise.bootstrapDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              className="min-h-[44px]"
              disabled={bootstrap.isPending}
              onClick={() => bootstrap.mutate({ name: t("admin:enterprise.defaultOrgName") })}
            >
              <ShieldCheck className="size-4" />
              {t("admin:enterprise.bootstrapAction")}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <MetricCard label={t("admin:enterprise.members")} value={String(data.members.length)} />
            <MetricCard
              label={t("admin:enterprise.instances")}
              value={String(data.instances.length)}
            />
            <MetricCard label={t("admin:enterprise.events")} value={String(data.eventCount)} />
          </div>
          <PolicyCard
            data={data}
            isPending={updatePolicy.isPending}
            onToggleMandated={() => {
              if (!data.org || !data.policy) return;
              updatePolicy.mutate({
                orgId: data.org.id,
                logSyncMandated: !data.policy.logSync.mandated,
                syncSessionEvents: data.policy.logSync.eventKindPolicy.SESSION,
                syncMessageEvents: data.policy.logSync.eventKindPolicy.MESSAGE,
                syncToolCallEvents: data.policy.logSync.eventKindPolicy.TOOL_CALL,
                syncInferenceEvents: data.policy.logSync.eventKindPolicy.INFERENCE,
                syncTruncationEvents: data.policy.logSync.eventKindPolicy.TRUNCATION,
                includeLocalModels: data.policy.logSync.includeLocalModels,
                backfill: data.policy.logSync.backfill,
                backlogPolicy: data.policy.logSync.backlogPolicy as
                  | "since_join"
                  | "since_policy"
                  | "all_available",
                retentionDays: data.policy.logSync.retentionDays,
              });
            }}
          />
          <ExportsCard
            data={data}
            createPending={createExport.isPending}
            downloadPending={downloadExport.isPending}
            onCreate={(format) => {
              if (!data.org) return;
              createExport.mutate({ format, filters: { orgId: data.org.id } });
            }}
            onDownload={(exportId) => downloadExport.mutate({ exportId })}
          />
        </>
      )}
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
      </CardContent>
    </Card>
  );
}

function PolicyCard({
  data,
  isPending,
  onToggleMandated,
}: {
  data: EnterpriseOverview;
  isPending: boolean;
  onToggleMandated: () => void;
}) {
  const { t } = useTranslation("admin");
  if (!data.policy) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("enterprise.policyTitle")}</CardTitle>
        <CardDescription>
          {t("enterprise.policyVersion", { version: data.policy.policyVersion })}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(data.policy.logSync.eventKindPolicy).map(([kind, enabled]) => (
            <div key={kind} className="rounded-lg border p-3">
              <p className="text-xs font-medium uppercase text-muted-foreground">{kind}</p>
              <p className="mt-1 text-sm font-medium">
                {enabled ? t("enterprise.enabled") : t("enterprise.disabled")}
              </p>
            </div>
          ))}
        </div>
        <Button className="min-h-[44px]" disabled={isPending} onClick={onToggleMandated}>
          <RefreshCcw className="size-4" />
          {data.policy.logSync.mandated
            ? t("enterprise.disableCollection")
            : t("enterprise.enableCollection")}
        </Button>
      </CardContent>
    </Card>
  );
}

function ExportsCard({
  data,
  createPending,
  downloadPending,
  onCreate,
  onDownload,
}: {
  data: EnterpriseOverview;
  createPending: boolean;
  downloadPending: boolean;
  onCreate: (format: "RAW_NDJSON" | "CHAT_JSONL") => void;
  onDownload: (exportId: string) => void;
}) {
  const { t } = useTranslation("admin");
  const exports = data.exports ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("enterprise.exportsTitle")}</CardTitle>
        <CardDescription>{t("enterprise.exportsDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Button
            className="min-h-[44px]"
            disabled={createPending}
            onClick={() => onCreate("RAW_NDJSON")}
          >
            <FileText className="size-4" />
            {t("enterprise.createRawExport")}
          </Button>
          <Button
            className="min-h-[44px]"
            disabled={createPending}
            onClick={() => onCreate("CHAT_JSONL")}
          >
            <FileJson className="size-4" />
            {t("enterprise.createChatExport")}
          </Button>
        </div>
        <ul className="divide-y rounded-lg border">
          {exports.length === 0 ? (
            <li className="p-4 text-sm text-muted-foreground">{t("enterprise.noExports")}</li>
          ) : (
            exports.map((item) => (
              <li
                key={item.id}
                className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div>
                  <p className="font-medium">{item.format}</p>
                  <p className="text-sm text-muted-foreground">
                    {item.status} · {new Date(item.createdAt).toLocaleString()}
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="min-h-[44px]"
                  disabled={item.status !== "READY" || downloadPending}
                  onClick={() => onDownload(item.id)}
                >
                  <Download className="size-4" />
                  {t("enterprise.download")}
                </Button>
              </li>
            ))
          )}
        </ul>
      </CardContent>
    </Card>
  );
}

function EnterpriseSkeleton() {
  return (
    <div className="container mx-auto max-w-6xl px-4 py-8 space-y-6">
      <Skeleton className="h-8 w-64" />
      <div className="grid gap-4 md:grid-cols-3">
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}
