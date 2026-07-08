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
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { TwoFactorSetupDetails } from "@/components/two-factor-setup-details";
import { authClient } from "@/lib/auth-client";
import { orpc } from "@/utils/orpc";
import { isForcedTwoFactorEnabledForRole } from "@/utils/two-factor-policy";

export const Route = createFileRoute("/$lang/_auth")({
  beforeLoad: async ({ location, params }) => {
    const session = await authClient.getSession();
    if (!session.data) {
      throw redirect({
        to: "/$lang/login",
        params: { lang: params.lang },
        search: { redirectTo: location.href },
      });
    }
    return { session: session.data };
  },
  component: AuthLayout,
});

function AuthLayout() {
  const { session } = Route.useRouteContext();
  const appSettings = useQuery(orpc.settings.getAll.queryOptions());
  const { t } = useTranslation(["common", "dashboard"]);

  if (appSettings.isPending) {
    return (
      <div className="container mx-auto max-w-4xl px-4 py-8 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-5 w-64" />
        <div className="mt-8 space-y-3">
          <Skeleton className="h-32 w-full rounded-lg" />
          <Skeleton className="h-32 w-full rounded-lg" />
        </div>
      </div>
    );
  }

  if (appSettings.isError) {
    return (
      <div className="container mx-auto max-w-4xl px-4">
        <InlineRetry
          className="py-12"
          message={t("dashboard:appSettingsLoadFailed")}
          onRetry={() => appSettings.refetch()}
        />
      </div>
    );
  }

  const force2FA = isForcedTwoFactorEnabledForRole(appSettings.data, session.user.role);
  const has2FA = session.user.twoFactorEnabled === true;

  if (force2FA && !has2FA) {
    return <TwoFactorSetupRequired />;
  }

  return <Outlet />;
}

function TwoFactorSetupRequired() {
  const [step, setStep] = useState<"intro" | "setup" | "verify">("intro");
  const [totpURI, setTotpURI] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { t } = useTranslation("auth");

  const handleEnable = async () => {
    setIsLoading(true);
    try {
      const result = await authClient.twoFactor.enable({
        password,
      });
      if (result.error) {
        console.error("[_auth.twoFactor.enable]", result.error);
        toast.error(t("twoFactor.couldNotStartSetup"));
        return;
      }
      setTotpURI(result.data?.totpURI || "");
      setBackupCodes(result.data?.backupCodes || []);
      setStep("verify");
    } catch (err) {
      console.error("[_auth.twoFactor.enable]", err);
      toast.error(t("twoFactor.couldNotStartSetup"));
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
        console.error("[_auth.twoFactor.verifyTotp]", result.error);
        toast.error(t("errors.invalidTotp"));
        return;
      }
      toast.success(t("twoFactor.enabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[_auth.twoFactor.verifyTotp]", err);
      toast.error(t("errors.invalidTotp"));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-[80vh] items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">{t("twoFactor.requiredTitle")}</CardTitle>
          <CardDescription>{t("twoFactor.requiredDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {step === "intro" && (
            <>
              <p className="text-sm text-muted-foreground">{t("twoFactor.introText")}</p>
              <Button className="min-h-[44px] w-full" onClick={() => setStep("setup")}>
                {t("twoFactor.setUp")}
              </Button>
            </>
          )}

          {step === "setup" && (
            <>
              <p className="text-sm text-muted-foreground">{t("twoFactor.passwordPrompt")}</p>
              <div className="space-y-2">
                <Label htmlFor="2fa-password">{t("fields.password")}</Label>
                <Input
                  id="2fa-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleEnable();
                  }}
                />
              </div>
              <Button
                className="min-h-[44px] w-full"
                onClick={handleEnable}
                disabled={!password || isLoading}
              >
                {isLoading ? t("twoFactor.settingUp") : t("twoFactor.continue")}
              </Button>
            </>
          )}

          {step === "verify" && (
            <>
              <TwoFactorSetupDetails
                backupCodes={backupCodes}
                backupCodesLabel={t("twoFactor.backupCodesLabel")}
                manualPrompt={t("twoFactor.addKeyToApp")}
                qrPrompt={t("twoFactor.scanQrPrompt")}
                totpURI={totpURI}
              />

              <div className="space-y-2">
                <Label htmlFor="verify-code">{t("fields.verificationCode")}</Label>
                <Input
                  id="verify-code"
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
                className="min-h-[44px] w-full"
                onClick={handleVerify}
                disabled={verifyCode.length !== 6 || isLoading}
              >
                {isLoading ? t("twoFactor.verifying") : t("twoFactor.verifyAndEnable")}
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
