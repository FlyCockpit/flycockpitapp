import { create } from "zustand";

/**
 * Tiny UI-only store: is the cookie-preferences panel open? Lives in a store
 * (not local state) so the persistent "Cookie preferences" link can re-open
 * it from anywhere in the tree — a footer, a CMS page, the settings route —
 * without prop-drilling. The actual decision lives in the consent cookie, not
 * here; this is purely "is the modal visible".
 */
interface ConsentUiState {
  preferencesOpen: boolean;
  openPreferences: () => void;
  closePreferences: () => void;
  setPreferencesOpen: (open: boolean) => void;
}

export const useConsentUi = create<ConsentUiState>()((set) => ({
  preferencesOpen: false,
  openPreferences: () => set({ preferencesOpen: true }),
  closePreferences: () => set({ preferencesOpen: false }),
  setPreferencesOpen: (open) => set({ preferencesOpen: open }),
}));
