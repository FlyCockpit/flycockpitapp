import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import Loader from "@/components/loader";

export function I18nReady({ children }: { children: ReactNode }) {
  const { ready } = useTranslation();
  if (!ready) return <Loader />;
  return <>{children}</>;
}
