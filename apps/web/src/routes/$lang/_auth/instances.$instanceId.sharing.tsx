import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { Checkbox } from "@flycockpit/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@flycockpit/ui/components/dialog";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Clock, RefreshCw, Trash2, UserPlus } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/instances/$instanceId/sharing")({
  component: InstanceSharingPage,
});

type SharingScope = "terminal" | "agent" | "agent_readonly" | "project_files";
type ExpiryPreset = "24h" | "7d" | "30d" | "never";
type Grant = {
  id: string;
  granteeEmail: string;
  scope: string;
  projectRoot: string | null;
  status: string;
  expiresAt: Date | string | null;
};

type AuditEvent = { id: string; kind: string; metadataJson: string; createdAt: Date | string };

const scopes: SharingScope[] = ["agent", "agent_readonly", "project_files", "terminal"];

function InstanceSharingPage() {
  const { lang, instanceId } = Route.useParams();
  const { t } = useTranslation("instances");
  const queryClient = useQueryClient();
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteTwoFactorRequired, setInviteTwoFactorRequired] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<Grant | null>(null);
  const instances = useQuery(orpc.instances.listMine.queryOptions());
  const sharing = useQuery(
    orpc.instanceSharing.listForInstance.queryOptions({ input: { instanceId } }),
  );
  const instance = instances.data?.instances.find((item) => item.id === instanceId);
  const invite = useMutation(
    orpc.instanceSharing.invite.mutationOptions({
      onSuccess: async (result) => {
        await queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.success(result.emailSent ? t("sharing.inviteSent") : t("sharing.inviteSaved"));
        setInviteTwoFactorRequired(false);
        setInviteOpen(false);
      },
      onError: (err) => {
        if (isTwoFactorInviteError(err)) {
          setInviteTwoFactorRequired(true);
          return;
        }
        toast.error(friendly(err, t("sharing.inviteError")));
      },
    }),
  );
  const revoke = useMutation(
    orpc.instanceSharing.revoke.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.success(t("sharing.revoked"));
        setRevokeTarget(null);
      },
      onError: (err) => toast.error(friendly(err, t("sharing.revokeError"))),
    }),
  );
  const renew = useMutation(
    orpc.instanceSharing.renew.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.success(t("sharing.renewed"));
      },
      onError: (err) => toast.error(friendly(err, t("sharing.renewError"))),
    }),
  );

  if (instances.isPending || sharing.isPending) return <SharingSkeleton />;
  if (instances.isError || sharing.isError) {
    return (
      <InlineRetry
        className="container mx-auto max-w-5xl px-4 py-12"
        message={friendly(instances.error ?? sharing.error, t("sharing.loadFailed"))}
        onRetry={() => {
          instances.refetch();
          sharing.refetch();
        }}
      />
    );
  }
  if (!instance) {
    return (
      <div className="container mx-auto max-w-5xl px-4 py-8">
        <Card>
          <CardHeader>
            <CardTitle>{t("terminal.notFoundTitle")}</CardTitle>
            <CardDescription>{t("terminal.notFoundDescription")}</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-5xl px-4 py-8">
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <Link
            to="/$lang/instances"
            params={{ lang }}
            className="mb-3 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            {t("remote.backToInstances")}
          </Link>
          <h1 className="truncate text-2xl font-semibold tracking-tight">
            {t("sharing.title", { name: instance.displayName })}
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">{t("sharing.description")}</p>
        </div>
        <InviteGrantDialog
          open={inviteOpen}
          onOpenChange={(open) => {
            setInviteOpen(open);
            if (!open) setInviteTwoFactorRequired(false);
          }}
          lang={lang}
          isPending={invite.isPending}
          showTwoFactorRequired={inviteTwoFactorRequired}
          onInvite={(value) => {
            setInviteTwoFactorRequired(false);
            invite.mutate({ instanceId, ...value });
          }}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("sharing.grantsTitle")}</CardTitle>
          <CardDescription>{t("sharing.grantsDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {sharing.data.grants.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              {t("sharing.noGrants")}
            </div>
          ) : (
            <div className="divide-y">
              {sharing.data.grants.map((grant) => (
                <GrantRow
                  key={grant.id}
                  grant={grant}
                  onRevoke={() => setRevokeTarget(grant)}
                  onRenew={() => renew.mutate({ grantId: grant.id, expiresIn: "7d" })}
                  renewPending={renew.isPending}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>{t("sharing.auditTitle")}</CardTitle>
          <CardDescription>{t("sharing.auditDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {sharing.data.auditEvents.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              {t("sharing.noAuditEvents")}
            </div>
          ) : (
            <div className="divide-y">
              {sharing.data.auditEvents.map((event) => (
                <AuditRow key={event.id} event={event} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <ConfirmDeleteDialog
        open={Boolean(revokeTarget)}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
        title={t("sharing.revokeTitle")}
        description={t("sharing.revokeDescription", { email: revokeTarget?.granteeEmail ?? "" })}
        confirmToken={revokeTarget?.granteeEmail ?? ""}
        typePrompt={t("sharing.revokeTypePrompt")}
        copyAriaLabel={t("sharing.copyEmail")}
        confirmLabel={t("sharing.revoke")}
        pendingLabel={t("sharing.revoking")}
        isPending={revoke.isPending}
        onConfirm={() => {
          if (revokeTarget) revoke.mutate({ grantId: revokeTarget.id });
        }}
      />
    </div>
  );
}

function isTwoFactorInviteError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /two-factor|two factor/i.test(message);
}

function InviteGrantDialog({
  open,
  onOpenChange,
  lang,
  isPending,
  showTwoFactorRequired,
  onInvite,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  lang: string;
  isPending: boolean;
  showTwoFactorRequired: boolean;
  onInvite: (value: {
    email: string;
    scopes: SharingScope[];
    projectRoot?: string;
    expiresIn: ExpiryPreset;
  }) => void;
}) {
  const { t } = useTranslation("instances");
  const [email, setEmail] = useState("");
  const [projectRoot, setProjectRoot] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<SharingScope[]>(["agent"]);
  const [expiresIn, setExpiresIn] = useState<ExpiryPreset>("never");
  const [terminalConfirmEmail, setTerminalConfirmEmail] = useState("");
  const terminalSelected = selectedScopes.includes("terminal");
  const normalizedEmail = email.trim().toLowerCase();
  const terminalConfirmed =
    !terminalSelected || terminalConfirmEmail.trim().toLowerCase() === normalizedEmail;
  const canSubmit =
    normalizedEmail.length > 0 && selectedScopes.length > 0 && terminalConfirmed && !isPending;

  useEffect(() => {
    if (!terminalSelected) setTerminalConfirmEmail("");
  }, [terminalSelected]);

  function toggleScope(scope: SharingScope, checked: boolean) {
    setSelectedScopes((current) => {
      if (checked) return current.includes(scope) ? current : [...current, scope];
      return current.filter((item) => item !== scope);
    });
    if (scope === "terminal" && checked && expiresIn === "never") setExpiresIn("7d");
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger
        render={
          <Button className="min-h-[44px]">
            <UserPlus className="size-4" />
            {t("sharing.addGrant")}
          </Button>
        }
      />
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("sharing.addGrantTitle")}</DialogTitle>
          <DialogDescription>{t("sharing.addGrantDescription")}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4 px-4 sm:px-6"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            if (!canSubmit) return;
            onInvite({
              email: email.trim(),
              scopes: selectedScopes,
              projectRoot: projectRoot.trim() || undefined,
              expiresIn,
            });
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="share-email">{t("sharing.emailLabel")}</Label>
            <Input
              id="share-email"
              type="email"
              inputMode="email"
              autoComplete="email"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
                setTerminalConfirmEmail("");
              }}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="share-project-root">{t("sharing.projectRootLabel")}</Label>
            <Input
              id="share-project-root"
              value={projectRoot}
              onChange={(event) => setProjectRoot(event.target.value)}
              placeholder={t("sharing.projectRootPlaceholder")}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">{t("sharing.projectRootHint")}</p>
          </div>
          <fieldset className="space-y-2">
            <legend className="font-medium text-sm">{t("sharing.scopesLabel")}</legend>
            <div className="grid gap-2">
              {scopes.map((scope) => (
                <label key={scope} className="flex items-start gap-3 rounded-md border p-3 text-sm">
                  <Checkbox
                    checked={selectedScopes.includes(scope)}
                    onCheckedChange={(checked) => toggleScope(scope, checked === true)}
                  />
                  <span>
                    <span className="block font-medium">{t("sharing.scopes." + scope)}</span>
                    <span className="block text-muted-foreground">
                      {t("sharing.scopeDescriptions." + scope)}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
          {terminalSelected ? (
            <div className="space-y-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm">
              <p className="text-destructive">{t("sharing.terminalWarning")}</p>
              <div className="space-y-2">
                <Label htmlFor="share-terminal-confirm">{t("sharing.terminalConfirmLabel")}</Label>
                <Input
                  id="share-terminal-confirm"
                  type="email"
                  inputMode="email"
                  autoComplete="off"
                  value={terminalConfirmEmail}
                  onChange={(event) => setTerminalConfirmEmail(event.target.value)}
                />
                <p className="text-muted-foreground text-xs">
                  {t("sharing.terminalConfirmHint", { email: normalizedEmail || "-" })}
                </p>
              </div>
            </div>
          ) : null}
          {showTwoFactorRequired ? (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm">
              <p className="text-destructive">{t("sharing.twoFactorRequired")}</p>
              <Link
                to="/$lang/settings/security"
                params={{ lang }}
                className="mt-2 inline-flex text-primary underline-offset-4 hover:underline"
              >
                {t("sharing.enableTwoFactorLink")}
              </Link>
            </div>
          ) : null}
          <div className="space-y-2">
            <Label htmlFor="share-expiry">{t("sharing.expiryLabel")}</Label>
            <select
              id="share-expiry"
              className="h-11 w-full rounded-md border bg-background px-3 text-sm"
              value={expiresIn}
              onChange={(event) => setExpiresIn(event.target.value as ExpiryPreset)}
            >
              <option value="24h">{t("sharing.expiry.24h")}</option>
              <option value="7d">{t("sharing.expiry.7d")}</option>
              <option value="30d">{t("sharing.expiry.30d")}</option>
              <option value="never">{t("sharing.expiry.never")}</option>
            </select>
          </div>
          <DialogFooter>
            <Button type="submit" className="min-h-[44px]" disabled={!canSubmit}>
              {isPending ? t("sharing.inviting") : t("sharing.sendInvite")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function GrantRow({
  grant,
  onRevoke,
  onRenew,
  renewPending,
}: {
  grant: Grant;
  onRevoke: () => void;
  onRenew: () => void;
  renewPending: boolean;
}) {
  const { t } = useTranslation("instances");
  return (
    <div className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <p className="font-medium text-sm">{grant.granteeEmail}</p>
          <StatusPill status={grant.status} />
        </div>
        <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
          <span className="rounded-full border bg-muted px-2 py-1">
            {t("sharing.scopes." + grant.scope)}
          </span>
          <span className="rounded-full border bg-muted px-2 py-1">
            {grant.projectRoot ?? t("sharing.allProjects")}
          </span>
          <span className="inline-flex items-center gap-1 rounded-full border bg-muted px-2 py-1">
            <Clock className="size-3" />
            {grant.expiresAt ? formatDate(grant.expiresAt) : t("sharing.expiry.never")}
          </span>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        {grant.status === "expired" ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="min-h-[44px]"
            onClick={onRenew}
            disabled={renewPending}
          >
            <RefreshCw className="size-4" />
            {t("sharing.renew")}
          </Button>
        ) : null}
        <Button
          type="button"
          variant="destructive"
          size="sm"
          className="min-h-[44px]"
          onClick={onRevoke}
          disabled={grant.status === "revoked"}
        >
          <Trash2 className="size-4" />
          {t("sharing.revoke")}
        </Button>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const { t } = useTranslation("instances");
  return (
    <span className="inline-flex items-center rounded-full border bg-muted px-2 py-0.5 text-xs text-muted-foreground">
      {t("sharing.status." + status)}
    </span>
  );
}

function AuditRow({ event }: { event: AuditEvent }) {
  const { t } = useTranslation("instances");
  return (
    <div className="flex flex-col gap-1 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between">
      <span className="font-medium">
        {t("sharing.auditKinds." + event.kind, { defaultValue: event.kind })}
      </span>
      <span className="text-muted-foreground text-xs tabular-nums">
        {formatDate(event.createdAt)}
      </span>
    </div>
  );
}

function SharingSkeleton() {
  return (
    <div className="container mx-auto max-w-5xl px-4 py-8">
      <Skeleton className="mb-6 h-20 w-full rounded-lg" />
      <Skeleton className="h-72 w-full rounded-lg" />
    </div>
  );
}

function formatDate(value: Date | string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}
