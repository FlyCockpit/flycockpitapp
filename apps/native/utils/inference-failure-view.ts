export type AuthFailureKind =
  | { kind: "credentials_rejected"; status?: number | null }
  | { kind: "missing_entitlement"; feature?: string | null }
  | { kind: "oauth_expired"; provider?: string | null }
  | { kind: "provider_not_configured" };

export type InferenceFailureInput = {
  provider?: string | null;
  model?: string | null;
  error_class?: string | null;
  detail?: string | null;
  auth_failure?: AuthFailureKind | null;
};

export type InferenceRecovery =
  | { kind: "reauthenticate"; label: string; action: "reauthenticate"; guidance: string }
  | { kind: "upgrade"; label: string; guidance: string }
  | {
      kind: "reconnect";
      label: string;
      action: "reconnect_provider";
      provider: string;
      guidance: string;
    }
  | { kind: "configure"; label: string; guidance: string }
  | { kind: "none"; label: null };

export type InferenceFailureView = {
  headline: string;
  detail: string;
  provider: string;
  model: string;
  errorClass: string;
  recovery: InferenceRecovery;
};

export type ActiveModelInput = {
  provider?: string | null;
  model?: string | null;
  config_provider?: string | null;
  config_model?: string | null;
  diverged?: boolean | null;
  generation?: number | null;
};

export type ActiveModelState = {
  provider: string;
  model: string;
  configProvider: string | null;
  configModel: string | null;
  diverged: boolean;
  generation: number;
};

export type ActiveModelView = {
  label: string;
  divergence: string | null;
};

function displayValue(value: string | null | undefined, fallback: string) {
  return value?.trim() ? value : fallback;
}

export function inferenceFailureView(input: InferenceFailureInput): InferenceFailureView {
  const provider = displayValue(input.provider, "Unknown provider");
  const model = displayValue(input.model, "Unknown model");
  const errorClass = displayValue(input.error_class, "Inference failed");
  const detail = displayValue(input.detail, errorClass);
  const authFailure = input.auth_failure;
  let recovery: InferenceRecovery = { kind: "none", label: null };

  if (authFailure?.kind === "credentials_rejected") {
    const status = typeof authFailure.status === "number" ? ` (HTTP ${authFailure.status})` : "";
    recovery = {
      kind: "reauthenticate",
      label: `Credentials rejected${status}`,
      action: "reauthenticate",
      guidance: "Re-authenticate this provider from an available provider entry point.",
    };
  } else if (authFailure?.kind === "missing_entitlement") {
    const feature = displayValue(authFailure.feature, "the required feature");
    recovery = {
      kind: "upgrade",
      label: `This needs ${feature}`,
      guidance: "Open your account plan or provider portal to upgrade access.",
    };
  } else if (authFailure?.kind === "oauth_expired") {
    const expiredProvider = displayValue(authFailure.provider, provider);
    recovery = {
      kind: "reconnect",
      label: `${expiredProvider} sign-in expired`,
      action: "reconnect_provider",
      provider: expiredProvider,
      guidance: "Reconnect this provider from an available provider entry point.",
    };
  } else if (authFailure?.kind === "provider_not_configured") {
    recovery = {
      kind: "configure",
      label: "Provider not configured",
      guidance: "Configure this provider before retrying the session.",
    };
  }

  return {
    headline: `${provider} ${model} failed`,
    detail,
    provider,
    model,
    errorClass,
    recovery,
  };
}

export function activeModelReducer(
  current: ActiveModelState | null,
  input: ActiveModelInput,
): ActiveModelState {
  const generation = typeof input.generation === "number" ? input.generation : 0;
  if (current && generation < current.generation) return current;
  return {
    provider: displayValue(input.provider, "Unknown provider"),
    model: displayValue(input.model, "Unknown model"),
    configProvider: input.config_provider ?? null,
    configModel: input.config_model ?? null,
    diverged: input.diverged === true,
    generation,
  };
}

export function activeModelView(
  state: ActiveModelState | null,
  mode: string | null,
): ActiveModelView {
  if (!state) {
    return {
      label: mode ? `Mode: ${mode}` : "Model pending",
      divergence: null,
    };
  }
  return {
    label: mode ? `${state.provider}/${state.model} · ${mode}` : `${state.provider}/${state.model}`,
    divergence: state.diverged
      ? `Configured ${displayValue(state.configProvider, "unknown provider")}/${displayValue(
          state.configModel,
          "unknown model",
        )} is not active`
      : null,
  };
}
