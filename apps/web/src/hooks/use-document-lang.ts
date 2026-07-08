import { useSyncExternalStore } from "react";

import i18n from "@/i18n";

function subscribe(onStoreChange: () => void): () => void {
  const handler = () => {
    if (typeof document !== "undefined") {
      document.documentElement.lang = i18n.language;
    }
    onStoreChange();
  };
  i18n.on("languageChanged", handler);
  return () => {
    i18n.off("languageChanged", handler);
  };
}

function getSnapshot(): string {
  return i18n.language;
}

function getServerSnapshot(): string {
  return i18n.language;
}

export function useDocumentLang(): string {
  const lang = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  if (typeof document !== "undefined" && document.documentElement.lang !== lang) {
    document.documentElement.lang = lang;
  }
  return lang;
}
