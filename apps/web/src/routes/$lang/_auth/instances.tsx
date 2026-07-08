import { Button, buttonVariants } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@flycockpit/ui/components/sheet";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Check,
  FolderOpen,
  Monitor,
  Pencil,
  RefreshCw,
  Share2,
  TerminalSquare,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import PullToRefresh from "@/components/pull-to-refresh";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/instances")({
  component: InstancesPage,
});

type InstanceSummary = {
  id: string;
  displayName: string;
  hostname: string;
  os: string;
  arch: string;
  cliVersion: string;
  status: string;
  createdAt: Date | string;
  updatedAt: Date | string;
  lastSeenAt: Date | string | null;
  revokedAt: Date | string | null;
  presence: string;
};

const instanceDateFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

function InstancesPage() {
  const {
    data: instancesData,
    error: instancesError,
    isError: instancesIsError,
    isFetching: instancesIsFetching,
    isPending: instancesIsPending,
    refetch: refetchInstances,
  } = useQuery({
    ...orpc.instances.listMine.queryOptions(),
    refetchInterval: 10_000,
  });
  const pendingInvites = useQuery(orpc.instanceSharing.listPendingForMe.queryOptions());
  const sharedInstances = useQuery(orpc.instanceSharing.listSharedWithMe.queryOptions());
  const queryClient = useQueryClient();
  const { lang } = Route.useParams();
  const { t } = useTranslation("instances");
  const [renameTarget, setRenameTarget] = useState<InstanceSummary | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<InstanceSummary | null>(null);
  const acceptInvite = useMutation(
    orpc.instanceSharing.accept.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.success(t("sharing.accepted"));
      },
      onError: (err) => toast.error(friendly(err, t("sharing.acceptError"))),
    }),
  );
  const declineInvite = useMutation(
    orpc.instanceSharing.decline.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() });
        toast.success(t("sharing.declined"));
      },
      onError: (err) => toast.error(friendly(err, t("sharing.declineError"))),
    }),
  );

  const handleRefresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: orpc.instances.key() }),
      queryClient.invalidateQueries({ queryKey: orpc.instanceSharing.key() }),
    ]);
  };

  return (
    <PullToRefresh onRefresh={handleRefresh}>
      <div className="container mx-auto max-w-5xl px-4 py-8">
        <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{t("title")}</h1>
            <p className="mt-2 text-sm text-muted-foreground">{t("description")}</p>
          </div>
          <Button
            type="button"
            variant="outline"
            className="min-h-[44px] w-full sm:w-auto"
            onClick={() => refetchInstances()}
            disabled={instancesIsFetching}
          >
            <RefreshCw className="size-4" /> {t("refresh")}
          </Button>
        </div>

        {instancesIsPending ? (
          <InstancesSkeleton />
        ) : instancesIsError ? (
          <InlineRetry
            className="py-12"
            message={friendly(instancesError, t("loadFailed"))}
            onRetry={() => refetchInstances()}
          />
        ) : instancesData.instances.length === 0 ? (
          <Card>
            <CardHeader>
              <CardTitle>{t("empty.title")}</CardTitle>
              <CardDescription>{t("empty.description")}</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          <div className="grid gap-4">
            {instancesData.instances.map((instance) => (
              <InstanceCard
                key={instance.id}
                instance={instance}
                lang={lang}
                onRename={() => setRenameTarget(instance)}
                onRevoke={() => setRevokeTarget(instance)}
              />
            ))}
          </div>
        )}

        <PendingInvitations
          invitations={pendingInvites.data?.invitations ?? []}
          isPending={pendingInvites.isPending}
          lang={lang}
          onAccept={(grantId) => acceptInvite.mutate({ grantId })}
          onDecline={(grantId) => declineInvite.mutate({ grantId })}
          accepting={acceptInvite.isPending}
          declining={declineInvite.isPending}
        />

        <SharedInstances
          sharedInstances={sharedInstances.data?.sharedInstances ?? []}
          isPending={sharedInstances.isPending}
          lang={lang}
        />

        <RenameInstanceSheet
          instance={renameTarget}
          open={Boolean(renameTarget)}
          onOpenChange={(open) => {
            if (!open) setRenameTarget(null);
          }}
        />
        <RevokeInstanceDialog
          instance={revokeTarget}
          open={Boolean(revokeTarget)}
          onOpenChange={(open) => {
            if (!open) setRevokeTarget(null);
          }}
        />
      </div>
    </PullToRefresh>
  );
}

function InstanceCard({
  instance,
  lang,
  onRename,
  onRevoke,
}: {
  instance: InstanceSummary;
  lang: string;
  onRename: () => void;
  onRevoke: () => void;
}) {
  const { t } = useTranslation("instances");
  const revoked = instance.status === "REVOKED" || Boolean(instance.revokedAt);

  return (
    <Card>
      <CardHeader className="gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Monitor className="size-5 text-muted-foreground" />
            <CardTitle className="truncate text-base">{instance.displayName}</CardTitle>
            <PresencePill presence={instance.presence} />
          </div>
          <CardDescription>
            {t("machineLine", {
              hostname: instance.hostname,
              os: instance.os,
              arch: instance.arch,
            })}
          </CardDescription>
        </div>
        <div className="flex shrink-0 gap-2">
          {revoked ? (
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="min-h-[44px] min-w-[44px]"
              aria-label={t("remote.openProjectsAriaLabel", { name: instance.displayName })}
              disabled
            >
              <FolderOpen className="size-4" />
            </Button>
          ) : (
            <Link
              to="/$lang/instances/$instanceId"
              params={{ lang, instanceId: instance.id }}
              className={buttonVariants({
                variant: "outline",
                size: "icon",
                className: "min-h-[44px] min-w-[44px]",
              })}
              aria-label={t("remote.openProjectsAriaLabel", { name: instance.displayName })}
            >
              <FolderOpen className="size-4" />
            </Link>
          )}
          {revoked ? (
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="min-h-[44px] min-w-[44px]"
              aria-label={t("terminal.openAriaLabel", { name: instance.displayName })}
              disabled
            >
              <TerminalSquare className="size-4" />
            </Button>
          ) : (
            <Link
              to="/$lang/instances/$instanceId/terminal"
              params={{ lang, instanceId: instance.id }}
              className={buttonVariants({
                variant: "outline",
                size: "icon",
                className: "min-h-[44px] min-w-[44px]",
              })}
              aria-label={t("terminal.openAriaLabel", { name: instance.displayName })}
            >
              <TerminalSquare className="size-4" />
            </Link>
          )}
          {revoked ? (
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="min-h-[44px] min-w-[44px]"
              aria-label={t("sharing.openAriaLabel", { name: instance.displayName })}
              disabled
            >
              <Share2 className="size-4" />
            </Button>
          ) : (
            <Link
              to="/$lang/instances/$instanceId/sharing"
              params={{ lang, instanceId: instance.id }}
              className={buttonVariants({
                variant: "outline",
                size: "icon",
                className: "min-h-[44px] min-w-[44px]",
              })}
              aria-label={t("sharing.openAriaLabel", { name: instance.displayName })}
            >
              <Share2 className="size-4" />
            </Link>
          )}
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="min-h-[44px] min-w-[44px]"
            aria-label={t("rename.ariaLabel", { name: instance.displayName })}
            onClick={onRename}
            disabled={revoked}
          >
            <Pencil className="size-4" />
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="icon"
            className="min-h-[44px] min-w-[44px]"
            aria-label={t("revoke.ariaLabel", { name: instance.displayName })}
            onClick={onRevoke}
            disabled={revoked}
          >
            <Trash2 className="size-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-3 text-sm sm:grid-cols-3">
          <InfoItem label={t("cliVersion")} value={instance.cliVersion} />
          <InfoItem label={t("createdAt")} value={formatDate(instance.createdAt)} />
          <InfoItem
            label={t("lastSeenAt")}
            value={formatNullableDate(instance.lastSeenAt, t("neverSeen"))}
          />
        </dl>
      </CardContent>
    </Card>
  );
}

type PendingInvitation = {
  id: string;
  scope: string;
  projectRoot: string | null;
  expiresAt: Date | string | null;
  instance: { id: string; displayName: string; hostname: string };
};

type SharedInstance = {
  instance: { id: string; displayName: string; hostname: string; presence: string };
  grants: Array<{ id: string; scope: string; projectRoot: string | null }>;
};

function PendingInvitations({
  invitations,
  isPending,
  lang,
  onAccept,
  onDecline,
  accepting,
  declining,
}: {
  invitations: PendingInvitation[];
  isPending: boolean;
  lang: string;
  onAccept: (grantId: string) => void;
  onDecline: (grantId: string) => void;
  accepting: boolean;
  declining: boolean;
}) {
  const { t } = useTranslation("instances");
  if (isPending) return null;
  if (invitations.length === 0) return null;
  return (
    <section className="mt-8 space-y-3">
      <div>
        <h2 className="font-semibold text-lg">{t("sharing.pendingTitle")}</h2>
        <p className="text-sm text-muted-foreground">{t("sharing.pendingDescription")}</p>
      </div>
      <div className="grid gap-3">
        {invitations.map((invite) => (
          <Card key={invite.id}>
            <CardHeader className="gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <CardTitle className="truncate text-base">{invite.instance.displayName}</CardTitle>
                <CardDescription className="truncate">{invite.instance.hostname}</CardDescription>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  className="min-h-[44px]"
                  onClick={() => onAccept(invite.id)}
                  disabled={accepting}
                >
                  <Check className="size-4" />
                  {t("sharing.accept")}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="min-h-[44px]"
                  onClick={() => onDecline(invite.id)}
                  disabled={declining}
                >
                  <X className="size-4" />
                  {t("sharing.decline")}
                </Button>
                <Link
                  to="/$lang/instances/$instanceId"
                  params={{ lang, instanceId: invite.instance.id }}
                  className={buttonVariants({
                    variant: "outline",
                    size: "sm",
                    className: "min-h-[44px]",
                  })}
                >
                  <FolderOpen className="size-4" />
                  {t("sharing.preview")}
                </Link>
              </div>
            </CardHeader>
            <CardContent>
              <GrantPills grants={[invite]} />
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}

function SharedInstances({
  sharedInstances,
  isPending,
  lang,
}: {
  sharedInstances: SharedInstance[];
  isPending: boolean;
  lang: string;
}) {
  const { t } = useTranslation("instances");
  if (isPending) return null;
  if (sharedInstances.length === 0) return null;
  return (
    <section className="mt-8 space-y-3">
      <div>
        <h2 className="font-semibold text-lg">{t("sharing.sharedWithMeTitle")}</h2>
        <p className="text-sm text-muted-foreground">{t("sharing.sharedWithMeDescription")}</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        {sharedInstances.map((shared) => (
          <Link
            key={shared.instance.id}
            to="/$lang/instances/$instanceId"
            params={{ lang, instanceId: shared.instance.id }}
            className="block"
          >
            <Card className="h-full transition-[border-color,box-shadow] hover:border-foreground/30 hover:shadow-sm">
              <CardHeader>
                <div className="flex items-start gap-3">
                  <FolderOpen className="mt-0.5 size-5 text-muted-foreground" />
                  <div className="min-w-0">
                    <CardTitle className="truncate text-base">
                      {shared.instance.displayName}
                    </CardTitle>
                    <CardDescription className="truncate">
                      {shared.instance.hostname}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <PresencePill presence={shared.instance.presence} />
                <GrantPills grants={shared.grants} />
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </section>
  );
}

function GrantPills({ grants }: { grants: Array<{ scope: string; projectRoot: string | null }> }) {
  const { t } = useTranslation("instances");
  return (
    <div className="flex flex-wrap gap-2">
      {grants.map((grant) => (
        <span
          key={grant.scope + (grant.projectRoot ?? "*")}
          className="inline-flex items-center rounded-full border bg-muted px-2 py-1 text-xs text-muted-foreground"
        >
          {t("sharing.scopes." + grant.scope)}
          {grant.projectRoot ? " · " + grant.projectRoot : ""}
        </span>
      ))}
    </div>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-words tabular-nums">{value}</dd>
    </div>
  );
}

function PresencePill({ presence }: { presence: string }) {
  const { t } = useTranslation("instances");
  const className =
    presence === "online"
      ? "border-emerald-600/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
      : presence === "revoked"
        ? "border-destructive/30 bg-destructive/10 text-destructive"
        : "border-muted-foreground/30 bg-muted text-muted-foreground";
  return (
    <span
      className={
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium " + className
      }
    >
      {t("presence." + presence)}
    </span>
  );
}

function RenameInstanceSheet({
  instance,
  open,
  onOpenChange,
}: {
  instance: InstanceSummary | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  if (!instance) return null;
  return (
    <RenameInstanceSheetInner
      key={instance.id}
      instance={instance}
      open={open}
      onOpenChange={onOpenChange}
    />
  );
}

function RenameInstanceSheetInner({
  instance,
  open,
  onOpenChange,
}: {
  instance: InstanceSummary;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const { t } = useTranslation("instances");
  const rename = useMutation(
    orpc.instances.rename.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: orpc.instances.key() });
        toast.success(t("rename.success"));
        onOpenChange(false);
      },
      onError: (err) => {
        toast.error(friendly(err, t("rename.error")));
      },
    }),
  );

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{t("rename.title")}</SheetTitle>
          <SheetDescription>{t("rename.description")}</SheetDescription>
        </SheetHeader>
        <form
          className="flex flex-1 flex-col"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            const formData = new FormData(event.currentTarget);
            const displayName = String(formData.get("displayName") ?? "").trim();
            if (displayName) rename.mutate({ instanceId: instance.id, displayName });
          }}
        >
          <div className="space-y-2 px-4">
            <Label htmlFor="instance-display-name">{t("rename.label")}</Label>
            <Input
              id="instance-display-name"
              name="displayName"
              defaultValue={instance.displayName}
              autoComplete="off"
            />
          </div>
          <SheetFooter>
            <Button type="submit" className="min-h-[44px]" disabled={rename.isPending}>
              {rename.isPending ? t("rename.saving") : t("rename.save")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

function RevokeInstanceDialog({
  instance,
  open,
  onOpenChange,
}: {
  instance: InstanceSummary | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const { t } = useTranslation("instances");
  const revoke = useMutation(
    orpc.instances.revoke.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: orpc.instances.key() });
        toast.success(t("revoke.success"));
        onOpenChange(false);
      },
      onError: (err) => {
        toast.error(friendly(err, t("revoke.error")));
      },
    }),
  );

  if (!instance) return null;

  return (
    <ConfirmDeleteDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("revoke.title")}
      description={t("revoke.description", { name: instance.displayName })}
      confirmToken={instance.displayName}
      typePrompt={t("revoke.typePrompt")}
      copyAriaLabel={t("revoke.copyAriaLabel")}
      confirmLabel={t("revoke.confirm")}
      pendingLabel={t("revoke.revoking")}
      isPending={revoke.isPending}
      onConfirm={() => revoke.mutate({ instanceId: instance.id })}
    />
  );
}

function InstancesSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-36 w-full rounded-lg" />
      <Skeleton className="h-36 w-full rounded-lg" />
    </div>
  );
}

function formatDate(value: Date | string) {
  return instanceDateFormatter.format(new Date(value));
}

function formatNullableDate(value: Date | string | null, fallback: string) {
  return value ? formatDate(value) : fallback;
}
