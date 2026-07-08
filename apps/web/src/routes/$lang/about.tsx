import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

export const Route = createFileRoute("/$lang/about")({
  ssr: true,
  component: AboutPage,
});

function AboutPage() {
  const { t } = useTranslation("marketing");
  return (
    <article className="container mx-auto max-w-3xl px-4 py-12">
      <h1 className="text-balance text-3xl font-semibold tracking-tight sm:text-4xl">
        {t("about.title")}
      </h1>
      <p className="mt-6 whitespace-pre-line text-base leading-7 text-foreground/90">
        {t("about.body")}
      </p>
    </article>
  );
}
