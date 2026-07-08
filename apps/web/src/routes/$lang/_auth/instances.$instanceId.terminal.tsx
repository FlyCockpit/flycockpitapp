import "@xterm/xterm/css/xterm.css";

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
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Clipboard, Keyboard, PlugZap, TerminalSquare, WifiOff, X } from "lucide-react";
import { type ReactNode, useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { useBrowserTerminal } from "@/hooks/use-browser-terminal";
import { authClient } from "@/lib/auth-client";
import { friendly, isRateLimit } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/instances/$instanceId/terminal")({
  component: InstanceTerminalPage,
});

type TokenInfo = {
  token: string;
  relayUrl: string;
  expiresAt: Date | string;
  stepUpExpiresAt: Date | string | null;
};

function InstanceTerminalPage() {
  const { lang, instanceId } = Route.useParams();
  const { session } = Route.useRouteContext();
  const { t } = useTranslation(["instances", "auth", "common"]);
  const [tokenInfo, setTokenInfo] = useState<TokenInfo | null>(null);
  const [needsStepUp, setNeedsStepUp] = useState(false);
  const instances = useQuery({
    ...orpc.instances.listMine.queryOptions(),
    refetchInterval: 10_000,
  });
  const instance = useMemo(
    () => instances.data?.instances.find((item) => item.id === instanceId) ?? null,
    [instanceId, instances.data?.instances],
  );
  const mintTerminalToken = useMutation(
    orpc.instances.mintTerminalClientToken.mutationOptions({
      onSuccess: (result) => {
        setTokenInfo(result);
        setNeedsStepUp(false);
      },
      onError: (error) => {
        if (session.user.twoFactorEnabled === true) {
          setNeedsStepUp(true);
          return;
        }
        toast.error(friendly(error, t("instances:terminal.openFailed")));
      },
    }),
  );

  const handleOpen = useCallback(() => {
    mintTerminalToken.mutate({ instanceId });
  }, [instanceId, mintTerminalToken]);

  if (instances.isPending) return <TerminalPageSkeleton />;

  if (instances.isError) {
    return (
      <TerminalShell lang={lang}>
        <InlineRetry
          className="py-12"
          message={friendly(instances.error, t("instances:loadFailed"))}
          onRetry={() => instances.refetch()}
        />
      </TerminalShell>
    );
  }

  if (!instance) {
    return (
      <TerminalShell lang={lang} title={t("instances:terminal.title")}>
        {tokenInfo ? (
          <TerminalSession
            instanceId={instanceId}
            instanceName={t("instances:terminal.title")}
            tokenInfo={tokenInfo}
          />
        ) : needsStepUp ? (
          <TerminalStepUpPanel
            email={session.user.email}
            onAuthenticated={handleOpen}
            onCancel={() => setNeedsStepUp(false)}
          />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TerminalSquare className="size-5" />
                {t("instances:terminal.readyTitle")}
              </CardTitle>
              <CardDescription>{t("instances:terminal.readyDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                className="min-h-[44px]"
                onClick={handleOpen}
                disabled={mintTerminalToken.isPending}
              >
                <PlugZap className="size-4" />
                {mintTerminalToken.isPending
                  ? t("instances:terminal.opening")
                  : t("instances:terminal.open")}
              </Button>
            </CardContent>
          </Card>
        )}
      </TerminalShell>
    );
  }

  const revoked = instance.status === "REVOKED" || Boolean(instance.revokedAt);
  const offline = instance.presence !== "online";

  return (
    <TerminalShell lang={lang} title={instance.displayName}>
      {revoked ? (
        <TerminalStateCard
          icon={<X className="size-5" />}
          title={t("instances:terminal.revokedTitle")}
          description={t("instances:terminal.revokedDescription")}
        />
      ) : offline ? (
        <TerminalStateCard
          icon={<WifiOff className="size-5" />}
          title={t("instances:terminal.offlineTitle")}
          description={t("instances:terminal.offlineDescription")}
        />
      ) : tokenInfo ? (
        <TerminalSession
          instanceId={instance.id}
          instanceName={instance.displayName}
          tokenInfo={tokenInfo}
        />
      ) : needsStepUp ? (
        <TerminalStepUpPanel
          email={session.user.email}
          onAuthenticated={handleOpen}
          onCancel={() => setNeedsStepUp(false)}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TerminalSquare className="size-5" />
              {t("instances:terminal.readyTitle")}
            </CardTitle>
            <CardDescription>{t("instances:terminal.readyDescription")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {session.user.twoFactorEnabled === true && (
              <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-950 dark:text-amber-100">
                {t("instances:terminal.stepUpNotice")}
              </div>
            )}
            <Button
              className="min-h-[44px]"
              onClick={handleOpen}
              disabled={mintTerminalToken.isPending}
            >
              <PlugZap className="size-4" />
              {mintTerminalToken.isPending
                ? t("instances:terminal.opening")
                : t("instances:terminal.open")}
            </Button>
          </CardContent>
        </Card>
      )}
    </TerminalShell>
  );
}

function TerminalShell({
  lang,
  title,
  children,
}: {
  lang: string;
  title?: string;
  children: ReactNode;
}) {
  const { t } = useTranslation("instances");
  return (
    <div className="container mx-auto flex min-h-full max-w-6xl flex-col px-4 py-6">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <Link
            to="/$lang/instances"
            params={{ lang }}
            className={buttonVariants({
              variant: "ghost",
              className: "mb-2 min-h-[44px] px-0",
            })}
          >
            <ArrowLeft className="size-4" /> {t("terminal.backToInstances")}
          </Link>
          <h1 className="truncate text-2xl font-semibold tracking-tight">
            {title ? t("terminal.titleWithName", { name: title }) : t("terminal.title")}
          </h1>
        </div>
      </div>
      {children}
    </div>
  );
}

function TerminalSession({
  instanceId,
  instanceName,
  tokenInfo,
}: {
  instanceId: string;
  instanceName: string;
  tokenInfo: TokenInfo;
}) {
  const { t } = useTranslation("instances");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const handleError = useCallback(
    (code: string) => {
      setErrorCode(code);
      toast.error(t(`terminal.errors.${code}`, { defaultValue: t("terminal.errors.host_error") }));
    },
    [t],
  );
  const terminal = useBrowserTerminal({
    tokenInfo,
    instanceId,
    instanceName,
    onError: handleError,
  });

  return (
    <div className="flex min-h-[70svh] flex-1 flex-col overflow-hidden rounded-lg border bg-background">
      <div className="flex min-h-[44px] flex-wrap items-center justify-between gap-2 border-b px-3 py-2">
        <div className="flex min-w-0 items-center gap-2 text-sm">
          <span className="inline-flex items-center gap-1 rounded-md border px-2 py-1 font-medium">
            <TerminalSquare className="size-4" /> {t(`terminal.status.${terminal.status}`)}
          </span>
          {terminal.viewerCount !== null && (
            <span className="text-muted-foreground">
              {t("terminal.viewers", { count: terminal.viewerCount })}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {terminal.pendingClipboardText && (
            <Button
              size="sm"
              variant="outline"
              className="min-h-[36px]"
              onClick={terminal.confirmClipboardWrite}
            >
              <Clipboard className="size-4" /> {t("terminal.confirmClipboard")}
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            className="min-h-[36px]"
            onClick={terminal.disconnect}
          >
            <X className="size-4" /> {t("terminal.disconnect")}
          </Button>
        </div>
      </div>
      {terminal.recording && (
        <div className="border-b border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-950 dark:text-amber-100">
          {t("terminal.recordingNotice")}
        </div>
      )}
      {errorCode && (
        <div className="border-b border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t(`terminal.errors.${errorCode}`, { defaultValue: t("terminal.errors.host_error") })}
        </div>
      )}
      {terminal.uploadProgress && (
        <div className="border-b px-3 py-2 text-sm text-muted-foreground">
          {t("terminal.uploading", {
            sent: Math.round(terminal.uploadProgress.sentBytes / 1024),
            total: Math.round(terminal.uploadProgress.totalBytes / 1024),
          })}
        </div>
      )}
      <div
        ref={terminal.containerRef}
        className="min-h-0 flex-1 overflow-hidden bg-black p-2"
        onPaste={terminal.handlePaste}
        onDrop={terminal.handleDrop}
        onDragOver={(event) => event.preventDefault()}
      />
      <div className="flex min-w-0 gap-1 overflow-x-auto border-t p-2 md:hidden">
        {[
          ["Esc", "\u001b"],
          ["Tab", "\t"],
          ["Ctrl-C", "\u0003"],
          ["Ctrl-D", "\u0004"],
          ["↑", "\u001b[A"],
          ["↓", "\u001b[B"],
          ["←", "\u001b[D"],
          ["→", "\u001b[C"],
        ].map(([label, value]) => (
          <Button
            key={label}
            type="button"
            variant="outline"
            size="sm"
            className="min-h-[44px] shrink-0"
            onClick={() => terminal.sendInput(value)}
          >
            <Keyboard className="size-3" /> {label}
          </Button>
        ))}
      </div>
    </div>
  );
}

function TerminalStepUpPanel({
  email,
  onAuthenticated,
  onCancel,
}: {
  email: string;
  onAuthenticated: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation(["instances", "auth", "common"]);
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needs2FA, setNeeds2FA] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handlePassword = async () => {
    setIsSubmitting(true);
    try {
      const result = await authClient.signIn.email({ email, password });
      if (result.error) {
        toast.error(
          isRateLimit(result.error) ? friendly(result.error) : t("auth:errors.invalidCredentials"),
        );
        return;
      }
      if ((result.data as Record<string, unknown>)?.twoFactorRedirect) {
        setNeeds2FA(true);
        return;
      }
      onAuthenticated();
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTotp = async () => {
    setIsSubmitting(true);
    try {
      const result = await authClient.twoFactor.verifyTotp({ code: totpCode });
      if (result.error) {
        toast.error(t("auth:errors.invalidTotp"));
        return;
      }
      onAuthenticated();
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("instances:terminal.stepUpTitle")}</CardTitle>
        <CardDescription>{t("instances:terminal.stepUpDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="max-w-sm space-y-4">
        {!needs2FA ? (
          <>
            <div className="space-y-2">
              <Label htmlFor="terminal-password">{t("auth:fields.password")}</Label>
              <Input
                id="terminal-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button
                className="min-h-[44px]"
                disabled={!password || isSubmitting}
                onClick={handlePassword}
              >
                {isSubmitting ? t("auth:login.signingIn") : t("auth:twoFactor.continue")}
              </Button>
              <Button className="min-h-[44px]" variant="ghost" onClick={onCancel}>
                {t("common:actions.cancel")}
              </Button>
            </div>
          </>
        ) : (
          <>
            <div className="space-y-2">
              <Label htmlFor="terminal-totp">{t("auth:fields.verificationCode")}</Label>
              <Input
                id="terminal-totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="000000"
                value={totpCode}
                onChange={(event) => setTotpCode(event.target.value)}
                className="text-center text-lg tracking-widest"
              />
            </div>
            <Button
              className="min-h-[44px]"
              disabled={totpCode.length !== 6 || isSubmitting}
              onClick={handleTotp}
            >
              {isSubmitting ? t("auth:twoFactor.verifying") : t("auth:twoFactor.verify")}
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function TerminalStateCard({
  icon,
  title,
  description,
}: {
  icon: ReactNode;
  title: string;
  description: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {icon}
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
    </Card>
  );
}

function TerminalPageSkeleton() {
  return (
    <div className="container mx-auto max-w-6xl px-4 py-6">
      <Skeleton className="mb-4 h-12 w-56" />
      <Skeleton className="h-[70svh] w-full rounded-lg" />
    </div>
  );
}
