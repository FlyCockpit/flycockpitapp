import { buttonVariants } from "@flycockpit/ui/components/button";
import { cn } from "@flycockpit/ui/lib/utils";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

export const Route = createFileRoute("/$lang/")({
  component: HomePage,
});

function HomePage() {
  const { lang } = Route.useParams();
  const { t } = useTranslation("marketing");

  return (
    <section className="container mx-auto flex min-h-[calc(100vh-8rem)] max-w-3xl flex-col justify-center px-4 py-16">
      <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
        {t("home.title")}
      </h1>
      <p className="mt-4 text-balance text-lg text-muted-foreground">{t("home.subtitle")}</p>
      <div className="mt-8 flex flex-wrap gap-3">
        <Link
          to="/$lang/login"
          params={{ lang }}
          search={{ redirectTo: undefined }}
          className={cn(buttonVariants({ size: "touch" }), "min-h-[44px]")}
        >
          {t("home.signIn")}
        </Link>
        <Link
          to="/$lang/device"
          params={{ lang }}
          search={{ user_code: undefined }}
          className={cn(buttonVariants({ variant: "outline", size: "touch" }), "min-h-[44px]")}
        >
          {t("home.device")}
        </Link>
      </div>
    </section>
  );
}
