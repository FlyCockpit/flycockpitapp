import { hasRole } from "@flycockpit/auth/roles";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@flycockpit/ui/components/dropdown-menu";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@flycockpit/ui/components/select";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useDebounce } from "@flycockpit/ui/hooks/use-async-search";
import { cn } from "@flycockpit/ui/lib/utils";
import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import type { TFunction } from "i18next";
import { Archive, ArchiveRestore, Copy, MoreVertical, Plus, Shield, Trash } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { SegmentedControl } from "@/components/segmented-control";
import { useHaptics } from "@/hooks/use-haptics";
import { useNamespaceT } from "@/i18n/use-namespace-t";
import { orpc } from "@/utils/orpc";

type StatusFilter = "all" | "active" | "archived";

type UserRow = {
  id: string;
  email: string;
  name: string;
  role: string;
  plan: "FREE" | "PRO";
  emailVerified: boolean;
  banned: boolean | null;
  banReason: string | null;
  createdAt: Date | string;
};

function buildInviteSchema(t: TFunction<"admin">) {
  return z.object({
    email: z.string().email(t("users.inviteEmailRequired")),
    name: z.string().trim().min(1, t("users.inviteNameRequired")).max(100),
    role: z.enum(["user", "admin"]),
  });
}

export const Route = createFileRoute("/$lang/admin/users")({
  component: AdminUsers,
});

function AdminUsers() {
  const { session } = Route.useRouteContext();
  const queryClient = useQueryClient();
  const { trigger } = useHaptics();
  const { t } = useTranslation(["admin", "common"]);

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [reveal, setReveal] = useState<{
    email: string;
    tempPassword: string;
    emailSent: boolean;
  } | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const debouncedSearch = useDebounce(search.trim(), 300);

  const list = useQuery(
    orpc.users.list.queryOptions({
      input: { limit: 100, search: debouncedSearch || undefined },
    }),
  );

  const setRole = useMutation({
    ...orpc.users.setRole.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.users.key() });
        trigger("success");
        toast.success(t("admin:users.roleUpdated"));
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:users.roleUpdateFailed" },
  });

  const setPlan = useMutation({
    ...orpc.users.setPlan.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.users.key() });
        trigger("success");
        toast.success(t("admin:users.planUpdated"));
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:users.planUpdateFailed" },
  });

  const archive = useMutation({
    ...orpc.users.archive.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.users.key() });
        trigger("success");
        toast.success(t("admin:users.userArchived"));
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:users.archiveFailed" },
  });

  const unarchive = useMutation({
    ...orpc.users.unarchive.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.users.key() });
        trigger("success");
        toast.success(t("admin:users.userRestored"));
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:users.restoreFailed" },
  });

  const remove = useMutation({
    ...orpc.users.remove.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.users.key() });
        trigger("success");
        toast.success(t("admin:users.userDeleted"));
        setDeleteId(null);
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:users.deleteFailed" },
  });

  const allUsers = (list.data?.users ?? []) as UserRow[];
  const filtered = allUsers.filter((u) => {
    if (statusFilter === "active") return !u.banned;
    if (statusFilter === "archived") return !!u.banned;
    return true;
  });
  const deleteTarget = allUsers.find((u) => u.id === deleteId) ?? null;

  return (
    <div className="container mx-auto max-w-7xl px-4 py-8 space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("admin:users.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("admin:users.description")}</p>
        </div>
        <Button
          onClick={() => {
            trigger("light");
            setInviteOpen(true);
          }}
          className="min-h-[44px]"
        >
          <Plus className="size-4" /> {t("admin:users.invite")}
        </Button>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SegmentedControl
          value={statusFilter}
          onChange={setStatusFilter}
          items={[
            { value: "all", label: t("admin:users.tabAll") },
            { value: "active", label: t("admin:users.tabActive") },
            { value: "archived", label: t("admin:users.tabArchived") },
          ]}
        />
        <Input
          type="search"
          inputMode="search"
          autoComplete="off"
          placeholder={t("admin:users.searchPlaceholder")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="sm:max-w-xs"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("admin:users.allUsers")}</CardTitle>
          <CardDescription>
            {list.isPending
              ? t("admin:users.loading")
              : list.isError
                ? t("admin:users.loadFailedShort")
                : t("admin:users.totalCount", {
                    count: list.data.total,
                    shown: filtered.length,
                    total: list.data.total,
                  })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {list.isPending ? (
            <ListSkeleton />
          ) : list.isError ? (
            <InlineRetry
              className="py-12"
              message={t("admin:users.loadFailed")}
              onRetry={() => list.refetch()}
            />
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <p className="text-sm font-medium">
                {search.trim()
                  ? t("admin:users.noMatch")
                  : statusFilter === "archived"
                    ? t("admin:users.noArchived")
                    : statusFilter === "active"
                      ? t("admin:users.noActive")
                      : t("admin:users.noUsersYet")}
              </p>
              <p className="text-sm text-muted-foreground">
                {search.trim() ? t("admin:users.tryDifferentQuery") : t("admin:users.inviteFirst")}
              </p>
            </div>
          ) : (
            <ul className="divide-y">
              {filtered.map((user) => {
                const isSelf = user.id === session.user.id;
                const isAdmin = hasRole(user.role, "admin");
                const isArchived = !!user.banned;
                return (
                  <li
                    key={user.id}
                    className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="flex flex-wrap items-center gap-2 font-medium">
                        <span className="truncate">{user.name || user.email}</span>
                        {isSelf && (
                          <span className="rounded-full border bg-muted px-1.5 py-0.5 text-[10px] font-medium uppercase text-muted-foreground">
                            {t("admin:users.youBadge")}
                          </span>
                        )}
                        <RolePill isAdmin={isAdmin} />
                        <PlanPill plan={user.plan} />
                        {isArchived && <ArchivedPill />}
                        {!user.emailVerified && <UnverifiedPill />}
                      </p>
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">
                        {user.email} · {t("admin:users.joined")}{" "}
                        <time dateTime={new Date(user.createdAt).toISOString()}>
                          {new Date(user.createdAt).toLocaleDateString()}
                        </time>
                        {user.banReason ? ` · ${user.banReason}` : ""}
                      </p>
                    </div>
                    <UserActions
                      user={user}
                      isSelf={isSelf}
                      isAdmin={isAdmin}
                      isArchived={isArchived}
                      onSetRole={(role) => {
                        trigger("light");
                        setRole.mutate({ userId: user.id, role });
                      }}
                      onSetPlan={(plan) => {
                        trigger("light");
                        setPlan.mutate({ userId: user.id, plan });
                      }}
                      onArchive={() => {
                        trigger("warning");
                        archive.mutate({ userId: user.id });
                      }}
                      onUnarchive={() => {
                        trigger("light");
                        unarchive.mutate({ userId: user.id });
                      }}
                      onDelete={() => {
                        trigger("warning");
                        setDeleteId(user.id);
                      }}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      <InviteUserDialog
        open={inviteOpen}
        onOpenChange={setInviteOpen}
        onInvited={(payload) => {
          setInviteOpen(false);
          setReveal(payload);
          queryClient.invalidateQueries({ queryKey: orpc.users.key() });
        }}
      />

      <RevealInviteDialog reveal={reveal} onClose={() => setReveal(null)} />

      <ConfirmDeleteDialog
        open={!!deleteId}
        onOpenChange={(open) => {
          if (!open) setDeleteId(null);
        }}
        title={t("admin:users.deleteTitle")}
        description={t("admin:users.deleteDescription")}
        confirmToken={deleteTarget?.email ?? ""}
        typePrompt={t("admin:users.typeEmailToConfirm")}
        copyAriaLabel={t("admin:users.copyEmailAriaLabel")}
        inputMode="email"
        isPending={remove.isPending}
        onConfirm={() => {
          if (!deleteTarget) return;
          remove.mutate({ userId: deleteTarget.id });
        }}
      />
    </div>
  );
}

function UserActions({
  user,
  isSelf,
  isAdmin,
  isArchived,
  onSetRole,
  onArchive,
  onSetPlan,
  onUnarchive,
  onDelete,
}: {
  user: UserRow;
  isSelf: boolean;
  isAdmin: boolean;
  isArchived: boolean;
  onSetRole: (role: "user" | "admin") => void;
  onArchive: () => void;
  onSetPlan: (plan: "FREE" | "PRO") => void;
  onUnarchive: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation("admin");
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="outline"
            size="sm"
            className="min-h-[44px] self-end sm:self-auto"
            aria-label={t("users.actionsAriaLabel", { name: user.name || user.email })}
          />
        }
      >
        <MoreVertical aria-hidden className="size-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        {isAdmin ? (
          <DropdownMenuItem disabled={isSelf} onClick={() => onSetRole("user")}>
            <Shield className="size-4" />
            {t("users.demoteToUser")}
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem onClick={() => onSetRole("admin")}>
            <Shield className="size-4" />
            {t("users.promoteToAdmin")}
          </DropdownMenuItem>
        )}
        {user.plan === "PRO" ? (
          <DropdownMenuItem onClick={() => onSetPlan("FREE")}>
            {t("users.setFreePlan")}
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem onClick={() => onSetPlan("PRO")}>
            {t("users.setProPlan")}
          </DropdownMenuItem>
        )}
        {isArchived ? (
          <DropdownMenuItem onClick={onUnarchive}>
            <ArchiveRestore className="size-4" />
            {t("users.restoreUser")}
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem disabled={isSelf} onClick={onArchive}>
            <Archive className="size-4" />
            {t("users.archiveUser")}
          </DropdownMenuItem>
        )}
        <DropdownMenuItem disabled={isSelf} onClick={onDelete}>
          <Trash className="size-4" />
          {t("users.deleteAction")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function RolePill({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation("admin");
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium uppercase",
        isAdmin
          ? "bg-violet-500/10 text-violet-700 dark:text-violet-400"
          : "bg-muted text-muted-foreground",
      )}
    >
      {isAdmin ? t("users.adminBadge") : t("users.userBadge")}
    </span>
  );
}

function PlanPill({ plan }: { plan: "FREE" | "PRO" }) {
  const { t } = useTranslation("admin");
  return (
    <span className="inline-flex items-center rounded-md bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-primary">
      {plan === "PRO" ? t("users.proPlanBadge") : t("users.freePlanBadge")}
    </span>
  );
}

function ArchivedPill() {
  const { t } = useTranslation("admin");
  return (
    <span className="inline-flex items-center rounded-md bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-amber-700 dark:text-amber-400">
      {t("users.archivedBadge")}
    </span>
  );
}

function UnverifiedPill() {
  const { t } = useTranslation("admin");
  return (
    <span className="inline-flex items-center rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-medium uppercase text-muted-foreground">
      {t("users.unverifiedBadge")}
    </span>
  );
}

function ListSkeleton() {
  return (
    <ul className="divide-y">
      {Array.from({ length: 6 }).map((_, i) => (
        <li key={`user-skel-${i}`} className="flex items-center justify-between gap-3 px-4 py-3">
          <div className="min-w-0 flex-1 space-y-2">
            <Skeleton className="h-5 w-1/3" />
            <Skeleton className="h-3 w-1/2" />
          </div>
          <Skeleton className="size-9" />
        </li>
      ))}
    </ul>
  );
}

function InviteUserDialog({
  open,
  onOpenChange,
  onInvited,
}: {
  open: boolean;
  onOpenChange: (next: boolean) => void;
  onInvited: (reveal: { email: string; tempPassword: string; emailSent: boolean }) => void;
}) {
  const { t } = useTranslation(["admin", "common"]);
  const tAdmin = useNamespaceT("admin");
  const invite = useMutation(orpc.users.invite.mutationOptions());

  const form = useForm({
    defaultValues: { email: "", name: "", role: "user" as "user" | "admin" },
    validators: { onChange: buildInviteSchema(tAdmin) },
    onSubmit: async ({ value }) => {
      const result = await invite.mutateAsync(value);
      onInvited({
        email: value.email,
        tempPassword: result.tempPassword,
        emailSent: result.emailSent,
      });
      form.reset();
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!invite.isPending) {
          if (!next) form.reset();
          onOpenChange(next);
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("admin:users.inviteTitle")}</DialogTitle>
          <DialogDescription>{t("admin:users.inviteDescription")}</DialogDescription>
        </DialogHeader>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-3"
        >
          <form.Field name="name">
            {(field) => (
              <div className="space-y-1.5">
                <Label htmlFor={field.name}>{t("admin:users.nameLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  autoComplete="name"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                <FieldErrors field={field} />
              </div>
            )}
          </form.Field>

          <form.Field name="email">
            {(field) => (
              <div className="space-y-1.5">
                <Label htmlFor={field.name}>{t("admin:users.emailLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="email"
                  inputMode="email"
                  autoComplete="email"
                  placeholder={t("admin:users.emailPlaceholder")}
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                <FieldErrors field={field} />
              </div>
            )}
          </form.Field>

          <form.Field name="role">
            {(field) => (
              <div className="space-y-1.5">
                <Label htmlFor={field.name}>{t("admin:users.roleLabel")}</Label>
                <Select
                  value={field.state.value}
                  onValueChange={(v) => field.handleChange(v as "user" | "admin")}
                >
                  <SelectTrigger id={field.name} className="w-full min-h-[44px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">{t("admin:users.roleUser")}</SelectItem>
                    <SelectItem value="admin">{t("admin:users.roleAdmin")}</SelectItem>
                  </SelectContent>
                </Select>
                <FieldErrors field={field} />
              </div>
            )}
          </form.Field>

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              className="min-h-[44px]"
              onClick={() => onOpenChange(false)}
              disabled={invite.isPending}
            >
              {t("common:actions.cancel")}
            </Button>
            <form.Subscribe selector={(s) => [s.canSubmit, s.isSubmitting] as const}>
              {([canSubmit, isSubmitting]) => (
                <Button
                  type="submit"
                  className="min-h-[44px]"
                  disabled={!canSubmit || isSubmitting || invite.isPending}
                >
                  {isSubmitting || invite.isPending
                    ? t("admin:users.inviting")
                    : t("admin:users.sendInvite")}
                </Button>
              )}
            </form.Subscribe>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function FieldErrors({
  field,
}: {
  field: { state: { meta: { errors: Array<{ message?: string } | string | undefined> } } };
}) {
  const firstMessage = field.state.meta.errors.reduce<string | null>((acc, e) => {
    if (acc) return acc;
    const msg = typeof e === "string" ? e : e?.message;
    return msg ?? null;
  }, null);
  if (!firstMessage) return null;
  return <p className="text-sm text-destructive">{firstMessage}</p>;
}

function RevealInviteDialog({
  reveal,
  onClose,
}: {
  reveal: { email: string; tempPassword: string; emailSent: boolean } | null;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const { t } = useTranslation(["admin", "common", "errors"]);
  const onCopy = async () => {
    if (!reveal) return;
    try {
      await navigator.clipboard.writeText(reveal.tempPassword);
      setCopied(true);
      toast.success(t("admin:users.passwordCopied"));
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error(t("errors:couldNotCopy"));
    }
  };
  return (
    <Dialog
      open={!!reveal}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("admin:users.revealTitle")}</DialogTitle>
          <DialogDescription>
            {reveal?.emailSent
              ? t("admin:users.revealEmailedDescription", { email: reveal.email })
              : t("admin:users.revealNotEmailedDescription", { email: reveal?.email ?? "" })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-1.5">
          <Label>{t("admin:users.tempPasswordLabel")}</Label>
          <div className="flex items-center gap-2">
            <code className="flex-1 truncate rounded-md border bg-muted px-2 py-1 font-mono text-sm">
              {reveal?.tempPassword}
            </code>
            <Button
              type="button"
              variant="outline"
              size="icon-sm"
              className="min-h-[44px] min-w-[44px]"
              onClick={onCopy}
              aria-label={t("admin:users.copyTempPasswordAriaLabel")}
            >
              <Copy className="size-4" />{" "}
              <span className="sr-only">
                {copied ? t("common:actions.copied") : t("common:actions.copy")}
              </span>
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">{t("admin:users.tempPasswordHint")}</p>
        </div>

        <DialogFooter>
          <Button onClick={onClose} className="min-h-[44px]">
            {t("admin:users.savedPassword")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
