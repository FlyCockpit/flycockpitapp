import { Button } from "@flycockpit/ui/components/button";
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
import { Switch } from "@flycockpit/ui/components/switch";
import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRound, ShieldCheck, ShieldOff, TerminalSquare } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import z from "zod";

import { TwoFactorSetupDetails } from "@/components/two-factor-setup-details";
import { authClient } from "@/lib/auth-client";
import { friendly, isRateLimit } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/settings/security")({
  component: SecuritySettings,
});

function SecuritySettings() {
  const { session } = Route.useRouteContext();
  const has2FA = session.user.twoFactorEnabled === true;
  const { t } = useTranslation("settings");

  return (
    <div className="space-y-6">
      <PasswordSection />
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {has2FA ? (
              <ShieldCheck className="size-5 text-green-500" />
            ) : (
              <ShieldOff className="size-5 text-muted-foreground" />
            )}
            {t("security.twoFactorTitle")}
          </CardTitle>
          <CardDescription>
            {has2FA ? t("security.enabledDescription") : t("security.disabledDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent>{has2FA ? <Disable2FASection /> : <Enable2FASection />}</CardContent>
      </Card>
      <TerminalSecuritySection has2FA={has2FA} />
    </div>
  );
}

function PasswordSection() {
  const {
    data: capabilities,
    isPending,
    isError,
    refetch,
  } = useQuery(orpc.auth.passwordCapabilities.queryOptions());
  const { t } = useTranslation(["settings", "common"]);

  if (isPending) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="size-5 text-muted-foreground" />
            {t("settings:security.passwordTitle")}
          </CardTitle>
          <CardDescription>{t("settings:security.passwordDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-10 w-full max-w-sm" />
          <Skeleton className="h-10 w-full max-w-sm" />
          <Skeleton className="h-10 w-full max-w-sm" />
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="size-5 text-muted-foreground" />
            {t("settings:security.passwordTitle")}
          </CardTitle>
          <CardDescription>{t("settings:security.passwordDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-destructive">{t("settings:security.passwordLoadError")}</p>
          <Button className="min-h-[44px]" variant="outline" onClick={() => refetch()}>
            {t("common:actions.retry")}
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!capabilities?.canChangePassword) return null;

  return <ChangePasswordCard />;
}

function ChangePasswordCard() {
  const { t } = useTranslation(["settings", "common"]);
  const [formError, setFormError] = useState<string | null>(null);
  const passwordSchema = useMemo(
    () =>
      z
        .object({
          currentPassword: z.string().min(1),
          newPassword: z.string().min(12).max(128),
          confirmPassword: z.string().min(1),
        })
        .refine((value) => value.newPassword === value.confirmPassword, {
          message: t("settings:security.passwordsMustMatch"),
          path: ["confirmPassword"],
        }),
    [t],
  );

  const form = useForm({
    defaultValues: { currentPassword: "", newPassword: "", confirmPassword: "" },
    validators: { onSubmit: passwordSchema },
    onSubmit: async ({ value, formApi }) => {
      setFormError(null);
      const result = await authClient.changePassword({
        currentPassword: value.currentPassword,
        newPassword: value.newPassword,
        revokeOtherSessions: true,
      });

      if (result.error) {
        const message = isRateLimit(result.error)
          ? friendly(result.error)
          : result.error.status === 400
            ? t("settings:security.currentPasswordMismatch")
            : t("settings:security.passwordChangeError");
        setFormError(message);
        return;
      }

      formApi.reset();
      toast.success(t("settings:security.passwordChangedSuccess"));
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="size-5 text-muted-foreground" />
          {t("settings:security.passwordTitle")}
        </CardTitle>
        <CardDescription>{t("settings:security.passwordDescription")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="max-w-sm space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
        >
          {formError ? <p className="text-sm text-destructive">{formError}</p> : null}
          <form.Field name="currentPassword">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("settings:security.currentPasswordLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="password"
                  autoComplete="current-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>
          <form.Field name="newPassword">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("settings:security.newPasswordLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="password"
                  autoComplete="new-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>
          <form.Field name="confirmPassword">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("settings:security.confirmPasswordLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="password"
                  autoComplete="new-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>
          <p className="text-sm text-muted-foreground">
            {t("settings:security.passwordSessionRevocation")}
          </p>
          <form.Subscribe selector={(state) => state.isSubmitting}>
            {(isSubmitting) => (
              <Button className="min-h-[44px]" type="submit" disabled={isSubmitting}>
                {isSubmitting
                  ? t("settings:security.changingPassword")
                  : t("settings:security.changePassword")}
              </Button>
            )}
          </form.Subscribe>
        </form>
      </CardContent>
    </Card>
  );
}

function Enable2FASection() {
  const [step, setStep] = useState<"idle" | "password" | "setup" | "verify">("idle");
  const [password, setPassword] = useState("");
  const [totpURI, setTotpURI] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { t } = useTranslation(["settings", "auth", "common"]);

  const handleEnable = async () => {
    setIsLoading(true);
    try {
      const result = await authClient.twoFactor.enable({
        password,
      });
      if (result.error) {
        console.error("[settings.security.twoFactor.enable]", result.error);
        toast.error(t("settings:security.couldNotStartSetup"));
        return;
      }
      setTotpURI(result.data?.totpURI || "");
      setBackupCodes(result.data?.backupCodes || []);
      setStep("setup");
    } catch (err) {
      console.error("[settings.security.twoFactor.enable]", err);
      toast.error(t("settings:security.couldNotStartSetup"));
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerify = async () => {
    setIsLoading(true);
    try {
      const result = await authClient.twoFactor.verifyTotp({
        code: verifyCode,
      });
      if (result.error) {
        console.error("[settings.security.twoFactor.verifyTotp]", result.error);
        toast.error(t("auth:errors.invalidTotp"));
        return;
      }
      toast.success(t("settings:security.enabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[settings.security.twoFactor.verifyTotp]", err);
      toast.error(t("auth:errors.invalidTotp"));
    } finally {
      setIsLoading(false);
    }
  };

  if (step === "idle") {
    return (
      <Button className="min-h-[44px]" onClick={() => setStep("password")}>
        {t("settings:security.enable2FA")}
      </Button>
    );
  }

  if (step === "password") {
    return (
      <div className="space-y-4 max-w-sm">
        <p className="text-sm text-muted-foreground">
          {t("settings:security.confirmPasswordPrompt")}
        </p>
        <div className="space-y-2">
          <Label htmlFor="confirm-password">{t("auth:fields.password")}</Label>
          <Input
            id="confirm-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleEnable();
            }}
          />
        </div>
        <div className="flex gap-2">
          <Button className="min-h-[44px]" onClick={handleEnable} disabled={!password || isLoading}>
            {isLoading ? t("auth:twoFactor.settingUp") : t("auth:twoFactor.continue")}
          </Button>
          <Button className="min-h-[44px]" variant="ghost" onClick={() => setStep("idle")}>
            {t("common:actions.cancel")}
          </Button>
        </div>
      </div>
    );
  }

  if (step === "setup") {
    return (
      <div className="space-y-4 max-w-sm">
        <TwoFactorSetupDetails
          backupCodes={backupCodes}
          backupCodesLabel={t("settings:security.saveBackupCodes")}
          manualPrompt={t("settings:security.addKeyToApp")}
          qrPrompt={t("settings:security.scanQrPrompt")}
          totpURI={totpURI}
        />

        <Button className="min-h-[44px]" onClick={() => setStep("verify")}>
          {t("settings:security.savedBackupCodes")}
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-sm">
      <p className="text-sm text-muted-foreground">{t("settings:security.verifyPrompt")}</p>
      <div className="space-y-2">
        <Label htmlFor="setup-verify-code">{t("auth:fields.verificationCode")}</Label>
        <Input
          id="setup-verify-code"
          placeholder="000000"
          value={verifyCode}
          onChange={(e) => setVerifyCode(e.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          className="text-center text-lg tracking-widest"
          onKeyDown={(e) => {
            if (e.key === "Enter" && verifyCode.length === 6) handleVerify();
          }}
        />
      </div>
      <Button
        className="min-h-[44px]"
        onClick={handleVerify}
        disabled={verifyCode.length !== 6 || isLoading}
      >
        {isLoading ? t("auth:twoFactor.verifying") : t("settings:security.verifyAndEnable")}
      </Button>
    </div>
  );
}

function Disable2FASection() {
  const [showConfirm, setShowConfirm] = useState(false);
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { t } = useTranslation(["settings", "auth", "common"]);

  const handleDisable = async () => {
    setIsLoading(true);
    try {
      const result = await authClient.twoFactor.disable({
        password,
      });
      if (result.error) {
        console.error("[settings.security.twoFactor.disable]", result.error);
        toast.error(t("settings:security.couldNotDisable"));
        return;
      }
      toast.success(t("settings:security.disabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[settings.security.twoFactor.disable]", err);
      toast.error(t("settings:security.couldNotDisable"));
    } finally {
      setIsLoading(false);
    }
  };

  if (!showConfirm) {
    return (
      <Button className="min-h-[44px]" variant="outline" onClick={() => setShowConfirm(true)}>
        {t("settings:security.disable2FA")}
      </Button>
    );
  }

  return (
    <div className="space-y-4 max-w-sm">
      <p className="text-sm text-muted-foreground">{t("settings:security.disablePrompt")}</p>
      <div className="space-y-2">
        <Label htmlFor="disable-password">{t("auth:fields.password")}</Label>
        <Input
          id="disable-password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleDisable();
          }}
        />
      </div>
      <div className="flex gap-2">
        <Button
          className="min-h-[44px]"
          variant="destructive"
          onClick={handleDisable}
          disabled={!password || isLoading}
        >
          {isLoading ? t("settings:security.disabling") : t("settings:security.disable")}
        </Button>
        <Button className="min-h-[44px]" variant="ghost" onClick={() => setShowConfirm(false)}>
          {t("common:actions.cancel")}
        </Button>
      </div>
    </div>
  );
}

function TerminalSecuritySection({ has2FA }: { has2FA: boolean }) {
  const { t } = useTranslation("settings");
  const queryClient = useQueryClient();
  const preferences = useQuery(orpc.settings.myTerminalSecurityPreferences.queryOptions());
  const update = useMutation(
    orpc.settings.updateMyTerminalSecurityPreferences.mutationOptions({
      onSuccess: async () => {
        await queryClient.invalidateQueries({
          queryKey: orpc.settings.myTerminalSecurityPreferences.queryKey(),
        });
        toast.success(t("security.terminalStepUpSaved"));
      },
      onError: () => toast.error(t("security.terminalStepUpSaveFailed")),
    }),
  );

  const relaxed = preferences.data?.terminalStepUpRelaxed === true;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TerminalSquare className="size-5 text-muted-foreground" />
          {t("security.terminalTitle")}
        </CardTitle>
        <CardDescription>{t("security.terminalDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!has2FA && (
          <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-950 dark:text-amber-100">
            {t("security.terminalRequires2FA")}
          </div>
        )}
        <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
          <div className="space-y-1">
            <Label htmlFor="terminal-step-up-relaxed">{t("security.terminalRelaxLabel")}</Label>
            <p className="text-sm text-muted-foreground">
              {t("security.terminalRelaxDescription")}
            </p>
          </div>
          <Switch
            id="terminal-step-up-relaxed"
            checked={relaxed}
            disabled={!has2FA || preferences.isPending || update.isPending}
            onCheckedChange={(terminalStepUpRelaxed) => {
              update.mutate({ terminalStepUpRelaxed });
            }}
          />
        </div>
      </CardContent>
    </Card>
  );
}
