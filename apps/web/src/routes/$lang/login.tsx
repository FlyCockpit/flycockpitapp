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
import { cn } from "@flycockpit/ui/lib/utils";
import { useForm } from "@tanstack/react-form";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, redirect, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import z from "zod";

import { authClient } from "@/lib/auth-client";
import { friendly, isRateLimit } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";
import { safeRedirectTo } from "@/utils/safe-redirect";

export const Route = createFileRoute("/$lang/login")({
  validateSearch: (search: Record<string, unknown>) => ({
    redirectTo: typeof search.redirectTo === "string" ? search.redirectTo : undefined,
  }),
  beforeLoad: async ({ params, search }) => {
    const session = await authClient.getSession();
    if (session.data) {
      throw redirect({ href: safeRedirectTo(search.redirectTo, params.lang) });
    }
  },
  component: LoginPage,
});

function LoginPage() {
  const { lang } = Route.useParams();
  const { redirectTo } = Route.useSearch();
  const [needs2FA, setNeeds2FA] = useState(false);
  const [totpCode, setTotpCode] = useState("");
  const [isVerifying2FA, setIsVerifying2FA] = useState(false);
  // Email-OTP challenge: once the user requests a code by email we switch the
  // verification path from verifyTotp to verifyOtp.
  const [otpSent, setOtpSent] = useState(false);
  const [isSendingOtp, setIsSendingOtp] = useState(false);
  const { isPending } = authClient.useSession();
  const config = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation(["auth", "common"]);

  const ssoEnabled = config.data?.ssoEnabled ?? false;
  const forceSso = config.data?.forceSso === true;
  const ssoProviderName = config.data?.ssoProviderName ?? "SSO";
  const signupEnabled =
    !forceSso &&
    ((config.data?.signupEnabled ?? true) || config.data?.adminBootstrapSignupEnabled === true);
  const emailEnabled = config.data?.emailEnabled ?? false;
  const postAuthRedirect = safeRedirectTo(redirectTo, lang);

  if (isPending || config.isPending) {
    return (
      <div className="flex min-h-[80vh] items-center justify-center px-4">
        <div className="w-full max-w-md space-y-6">
          <div className="space-y-2 text-center">
            <Skeleton className="mx-auto h-8 w-40" />
            <Skeleton className="mx-auto h-4 w-56" />
          </div>
          <div className="space-y-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        </div>
      </div>
    );
  }

  if (config.isError) {
    return (
      <div className="flex min-h-[80vh] items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl">{t("auth:login.unableToConnect")}</CardTitle>
            <CardDescription>{t("auth:login.unableToConnectDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="min-h-[44px] w-full" onClick={() => config.refetch()}>
              {t("common:actions.retry")}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const handleSsoLogin = async () => {
    const result = await authClient.signIn.social({
      provider: "sso",
      callbackURL: postAuthRedirect,
    });
    if (result.error) {
      console.error("[login.sso]", result.error);
      toast.error(t("auth:login.ssoFailed"));
    }
  };

  const handle2FAVerify = async () => {
    setIsVerifying2FA(true);
    try {
      // When the user requested an emailed code we verify against the OTP
      // endpoint; otherwise the code is a TOTP from their authenticator app.
      const result = otpSent
        ? await authClient.twoFactor.verifyOtp({ code: totpCode })
        : await authClient.twoFactor.verifyTotp({ code: totpCode });
      if (result.error) {
        console.error("[login.twoFactor.verify]", result.error);
        toast.error(t("auth:errors.invalidTotp"));
      } else {
        toast.success(t("auth:signedInSuccess"));
        window.location.assign(postAuthRedirect);
      }
    } finally {
      setIsVerifying2FA(false);
    }
  };

  const handleSendEmailOtp = async () => {
    setIsSendingOtp(true);
    try {
      // Delivery-aware preflight: Better-Auth's send-otp endpoint reports
      // success even when SMTP delivery fails, so verify the transport is
      // actually reachable before telling the user a code is on the way.
      const preflight = await orpc.auth.verifyEmailTransport.call().catch((err) => {
        console.error("[login.twoFactor.verifyEmailTransport]", err);
        return { ok: false };
      });
      if (!preflight.ok) {
        toast.error(t("auth:twoFactor.couldNotSendCode"));
        return;
      }
      const result = await authClient.twoFactor.sendOtp();
      if (result.error) {
        console.error("[login.twoFactor.sendOtp]", result.error);
        toast.error(
          isRateLimit(result.error) ? friendly(result.error) : t("auth:twoFactor.couldNotSendCode"),
        );
        return;
      }
      setOtpSent(true);
      setTotpCode("");
      toast.success(t("auth:twoFactor.codeSent"));
    } finally {
      setIsSendingOtp(false);
    }
  };

  if (needs2FA) {
    return (
      <div className="flex min-h-[80vh] items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl">{t("auth:twoFactor.title")}</CardTitle>
            <CardDescription>
              {otpSent ? t("auth:twoFactor.emailCodeDescription") : t("auth:twoFactor.description")}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="totp-code">{t("auth:fields.verificationCode")}</Label>
              <Input
                id="totp-code"
                placeholder="000000"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                className="text-center text-lg tracking-widest"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && totpCode.length === 6) {
                    handle2FAVerify();
                  }
                }}
              />
            </div>
            <Button
              className="min-h-[44px] w-full"
              onClick={handle2FAVerify}
              disabled={totpCode.length !== 6 || isVerifying2FA}
            >
              {isVerifying2FA ? t("auth:twoFactor.verifying") : t("auth:twoFactor.verify")}
            </Button>
            {emailEnabled && (
              <Button
                variant="outline"
                className="min-h-[44px] w-full"
                onClick={handleSendEmailOtp}
                disabled={isSendingOtp}
              >
                {isSendingOtp
                  ? t("auth:twoFactor.sendingCode")
                  : otpSent
                    ? t("auth:twoFactor.resendEmailCode")
                    : t("auth:twoFactor.emailMeCode")}
              </Button>
            )}
            <Button
              variant="ghost"
              className="min-h-[44px] w-full"
              onClick={() => {
                setNeeds2FA(false);
                setTotpCode("");
                setOtpSent(false);
              }}
            >
              {t("auth:twoFactor.back")}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-[80vh] items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">{t("auth:login.signinTitle")}</CardTitle>
          <CardDescription>
            {forceSso
              ? t("auth:login.ssoOnlyDescription", { provider: ssoProviderName })
              : t("auth:login.signinDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {ssoEnabled && (
            <>
              <Button variant="outline" className="min-h-[44px] w-full" onClick={handleSsoLogin}>
                {t("auth:login.ssoContinue", { provider: ssoProviderName })}
              </Button>
              {!forceSso && (
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">{t("auth:login.or")}</span>
                  </div>
                </div>
              )}
            </>
          )}
          {!forceSso && (
            <SignInForm
              lang={lang}
              redirectTo={postAuthRedirect}
              onNeeds2FA={() => setNeeds2FA(true)}
            />
          )}
          {forceSso && !ssoEnabled && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {t("auth:login.ssoUnavailable")}
            </div>
          )}
          {signupEnabled && (
            <div className="text-center">
              <Link
                to="/$lang/signup"
                params={{ lang }}
                search={{ redirectTo }}
                className={cn(buttonVariants({ variant: "link" }), "min-h-[44px]")}
              >
                {t("auth:login.signupHint")}
              </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SignInForm({
  lang,
  redirectTo,
  onNeeds2FA,
}: {
  lang: string;
  redirectTo: string;
  onNeeds2FA: () => void;
}) {
  const navigate = useNavigate();
  const { t } = useTranslation(["auth"]);

  const form = useForm({
    defaultValues: { email: "", password: "" },
    onSubmit: async ({ value }) => {
      const result = await authClient.signIn.email({
        email: value.email,
        password: value.password,
      });
      if (result.error) {
        toast.error(
          isRateLimit(result.error) ? friendly(result.error) : t("auth:errors.invalidCredentials"),
        );
        return;
      }
      if ((result.data as Record<string, unknown>)?.twoFactorRedirect) {
        onNeeds2FA();
        return;
      }
      toast.success(t("auth:signedInSuccess"));
      if (redirectTo === `/${lang}/dashboard`) {
        navigate({ to: "/$lang/dashboard", params: { lang } });
      } else {
        window.location.assign(redirectTo);
      }
    },
    validators: {
      // Validation messages come from the locale-aware Zod error map installed
      // in `@/i18n/zod`. Don't pass inline strings here — that would override
      // the global map and leak hardcoded English copy into es-MX UIs.
      onSubmit: z.object({
        email: z.email(),
        password: z.string().min(8),
      }),
    },
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
      className="space-y-4"
    >
      <form.Field name="email">
        {(field) => (
          <div className="space-y-2">
            <Label htmlFor={field.name}>{t("auth:fields.email")}</Label>
            <Input
              id={field.name}
              name={field.name}
              type="email"
              inputMode="email"
              autoComplete="email"
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

      <form.Field name="password">
        {(field) => (
          <div className="space-y-2">
            <Label htmlFor={field.name}>{t("auth:fields.password")}</Label>
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

      <form.Subscribe
        selector={(state) => ({ canSubmit: state.canSubmit, isSubmitting: state.isSubmitting })}
      >
        {({ canSubmit, isSubmitting }) => (
          <Button
            type="submit"
            className="min-h-[44px] w-full"
            disabled={!canSubmit || isSubmitting}
          >
            {isSubmitting ? t("auth:login.signingIn") : t("auth:login.signIn")}
          </Button>
        )}
      </form.Subscribe>
    </form>
  );
}
