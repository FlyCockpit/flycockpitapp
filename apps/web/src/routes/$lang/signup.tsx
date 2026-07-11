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
import { useTranslation } from "react-i18next";
import z from "zod";

import { useAuthSessionSnapshot } from "@/hooks/use-auth-session";
import { authClient } from "@/lib/auth-client";
import { decideAnonymousOnlyRouteAccess } from "@/lib/route-session-access";
import { getRouteSession } from "@/server/auth-session";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";
import { safeRedirectTo } from "@/utils/safe-redirect";

export const Route = createFileRoute("/$lang/signup")({
  validateSearch: (search: Record<string, unknown>) => ({
    redirectTo: typeof search.redirectTo === "string" ? search.redirectTo : undefined,
  }),
  beforeLoad: async ({ context, params, search }) => {
    const decision = decideAnonymousOnlyRouteAccess(await getRouteSession());
    if (decision.kind === "error") throw new Error("Could not verify session");
    if (decision.kind === "redirect-authenticated") {
      throw redirect({ href: safeRedirectTo(search.redirectTo, params.lang) });
    }
    const cfg = await context.queryClient.ensureQueryData(orpc.appConfig.queryOptions());
    if (cfg.forceSso || (!cfg.signupEnabled && !cfg.adminBootstrapSignupEnabled)) {
      throw redirect({ to: "/$lang/login", params: { lang: params.lang }, search });
    }
  },
  component: SignupPage,
});

function SignupPage() {
  const { lang } = Route.useParams();
  const { redirectTo } = Route.useSearch();
  const { isPending } = useAuthSessionSnapshot();
  const config = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation(["auth", "common"]);

  const postAuthRedirect = safeRedirectTo(redirectTo, lang);
  const forceSso = config.data?.forceSso === true;

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

  if (forceSso) {
    return (
      <div className="flex min-h-[80vh] items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl">{t("auth:login.ssoRequiredTitle")}</CardTitle>
            <CardDescription>{t("auth:login.ssoRequiredDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Link
              to="/$lang/login"
              params={{ lang }}
              search={{ redirectTo }}
              className={cn(buttonVariants(), "min-h-[44px] w-full")}
            >
              {t("auth:login.signIn")}
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-[80vh] items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">{t("auth:login.createAccount")}</CardTitle>
          <CardDescription>{t("auth:login.createDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <SignUpForm lang={lang} redirectTo={postAuthRedirect} />
          <div className="text-center">
            <Link
              to="/$lang/login"
              params={{ lang }}
              search={{ redirectTo }}
              className={cn(buttonVariants({ variant: "link" }), "min-h-[44px]")}
            >
              {t("auth:login.signinHint")}
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function SignUpForm({ lang, redirectTo }: { lang: string; redirectTo: string }) {
  const navigate = useNavigate();
  const { t } = useTranslation(["auth"]);

  const form = useForm({
    defaultValues: { name: "", email: "", password: "" },
    onSubmit: async ({ value }) => {
      const result = await authClient.signUp.email({
        email: value.email,
        password: value.password,
        name: value.name,
      });
      if (result.error) {
        console.error("[signup.signUp]", result.error);
        toast.error(
          result.error?.status === 409
            ? t("auth:errors.accountAlreadyRegistered")
            : friendly(result.error, t("auth:errors.couldNotCreateAccount")),
        );
        return;
      }
      toast.success(t("auth:accountCreatedSuccess"));
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
        name: z.string().min(2),
        email: z.email(),
        password: z.string().min(12),
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
      <form.Field name="name">
        {(field) => (
          <div className="space-y-2">
            <Label htmlFor={field.name}>{t("auth:fields.name")}</Label>
            <Input
              id={field.name}
              name={field.name}
              autoComplete="name"
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

      <form.Subscribe
        selector={(state) => ({ canSubmit: state.canSubmit, isSubmitting: state.isSubmitting })}
      >
        {({ canSubmit, isSubmitting }) => (
          <Button
            type="submit"
            className="min-h-[44px] w-full"
            disabled={!canSubmit || isSubmitting}
          >
            {isSubmitting ? t("auth:login.creatingAccount") : t("auth:login.signUp")}
          </Button>
        )}
      </form.Subscribe>
    </form>
  );
}
