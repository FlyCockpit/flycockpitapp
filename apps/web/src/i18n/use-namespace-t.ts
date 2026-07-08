import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";

/**
 * Returns a TFunction strongly typed to a single namespace, so call sites can
 * pass it to helpers (form schema builders, etc.) that expect `TFunction<NS>`
 * without the `t as unknown as TFunction<NS>` double-cast.
 *
 * Use the regular `useTranslation` for in-component string lookups across
 * multiple namespaces; use this only when handing `t` to a function that
 * requires a strongly-typed single-namespace TFunction.
 */
export function useNamespaceT<NS extends string>(ns: NS): TFunction<NS> {
  const { t } = useTranslation(ns);
  return t as TFunction<NS>;
}
