//! AC4 on the **real** model-construction paths.
//!
//! The typed custody API is only worth anything if the paths that actually
//! build models go through it. The API-level half of AC4 lives in
//! `cockpit-config` (`model_policy_custody_requirements_are_type_enforced`);
//! this module pins the consequences on the two production entry points that
//! turn configuration into a live outbound sink:
//!
//! - [`Model::from_config_with_env`] — the active model.
//! - [`Model::for_provider_with_env`] — configured utility/background targets.
//!
//! Both obtain their redaction posture from a
//! [`ResolvedSensitiveModelPolicy`], and raw provider bytes are released only
//! by a `TrustedCustodyGrant` minted for that exact `(provider, model)`. There
//! is no trust-by-name lookup left on these paths, so a caller that never
//! routed custody cannot reach the raw table at all — it falls closed.

use std::sync::Arc;

use crate::config::providers::{
    ActiveModelRef, ModelCustody, ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig,
};
use crate::engine::model::Model;
use crate::redact::RedactionTable;

use crate::config::extended::LlmMode;

const SECRET: &str = "sk-live-custody-boundary-secret";
const PLACEHOLDER: &str = "[custody-redacted]";

fn secret_table() -> Arc<RedactionTable> {
    Arc::new(
        RedactionTable::empty()
            .with_forced_literal(SECRET.to_string(), PLACEHOLDER.to_string())
            .expect("forced literal"),
    )
}

/// A keyless OpenAI-compatible provider carrying an explicit trust *and* an
/// explicit mode, so every assertion below is made with both dimensions set.
fn provider(trust: ModelTrust, mode: LlmMode) -> ProviderEntry {
    ProviderEntry {
        url: "http://127.0.0.1:1/v1".into(),
        trust: Some(trust),
        mode: Some(mode),
        models: vec![ModelEntry {
            id: "m".into(),
            subagent_invokable: Some(true),
            ..ModelEntry::default()
        }],
        ..ProviderEntry::default()
    }
}

fn config(mode: LlmMode) -> ProvidersConfig {
    let mut cfg = ProvidersConfig::default();
    cfg.providers
        .insert("selfhosted".into(), provider(ModelTrust::Trusted, mode));
    cfg.providers
        .insert("cloud".into(), provider(ModelTrust::Untrusted, mode));
    cfg
}

fn active(provider: &str) -> ActiveModelRef {
    ActiveModelRef {
        provider: provider.to_string(),
        model: "m".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }
}

/// AC4, active-model path. The normal `/model` selection is a potentially
/// sensitive caller: it builds the sink every foreground turn sends through.
/// It therefore declares custody through the typed request API, and the model
/// it produces carries exactly the table that custody released.
///
/// Trusted (self-hosted / no-log) keeps raw content — that is the supported
/// outcome, not a leak. Untrusted (cloud, may retain logs) is always redacted.
/// Both hold for every harness posture: custody never reads mode.
#[test]
fn model_policy_custody_requirements_are_type_enforced_on_the_active_model_path() {
    for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
        let mut cfg = config(mode);

        cfg.active_model = Some(active("cloud"));
        let untrusted = Model::from_config_with_env(&cfg, secret_table(), |_| Some("k".into()))
            .expect("keyless openai-compat build");
        assert!(
            !untrusted.redact_table().scrub(SECRET).contains(SECRET),
            "{mode:?}: an untrusted active model must always receive a redacted rendering"
        );

        cfg.active_model = Some(active("selfhosted"));
        let trusted = Model::from_config_with_env(&cfg, secret_table(), |_| Some("k".into()))
            .expect("keyless openai-compat build");
        assert_eq!(
            trusted.redact_table().scrub(SECRET),
            SECRET,
            "{mode:?}: a trusted active model's raw custody must survive the custody route"
        );
    }
}

/// AC4, configured utility/background path. `for_provider` bypasses active-model
/// selection but is not thereby exempt: it routes custody the same way.
#[test]
fn model_policy_custody_requirements_are_type_enforced_on_the_utility_model_path() {
    for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
        let cfg = config(mode);

        let untrusted =
            Model::for_provider_with_env(&cfg, "cloud", "m", secret_table(), |_| Some("k".into()))
                .expect("keyless openai-compat build");
        assert!(
            !untrusted.redact_table().scrub(SECRET).contains(SECRET),
            "{mode:?}: an untrusted utility target must always receive a redacted rendering"
        );

        let trusted = Model::for_provider_with_env(&cfg, "selfhosted", "m", secret_table(), |_| {
            Some("k".into())
        })
        .expect("keyless openai-compat build");
        assert_eq!(
            trusted.redact_table().scrub(SECRET),
            SECRET,
            "{mode:?}: a trusted utility target keeps raw custody"
        );
    }
}

/// The grant is destination-bound. A completed trusted selection for one target
/// is not a licence to send raw bytes to a *different* one, so a route may not
/// be carried sideways onto another model build. Without this binding the raw
/// table would be reachable by resolving custody once for any trusted model and
/// reusing the result.
#[test]
fn raw_custody_requires_a_grant_minted_for_this_exact_target() {
    let mut cfg = config(LlmMode::Normal);
    // A second trusted model on the same provider: the provider class matches,
    // only the model id differs.
    cfg.providers
        .get_mut("selfhosted")
        .unwrap()
        .models
        .push(ModelEntry {
            id: "other".into(),
            subagent_invokable: Some(true),
            ..ModelEntry::default()
        });

    let table = secret_table();
    let route = Model::configured_custody_route(&cfg, "selfhosted", "m", &table)
        .expect("a configured trusted target routes");
    assert_eq!(route.custody, ModelCustody::Trusted);
    assert!(route.trusted_custody_grant().is_some());

    assert_eq!(
        Model::effective_redact_table_for(&route, "selfhosted", "m", table.clone()).scrub(SECRET),
        SECRET,
        "the grant releases raw bytes for the target it was minted for"
    );
    assert!(
        !Model::effective_redact_table_for(&route, "selfhosted", "other", table.clone())
            .scrub(SECRET)
            .contains(SECRET),
        "a grant minted for `selfhosted:m` must not release raw bytes to `selfhosted:other`"
    );
    assert!(
        !Model::effective_redact_table_for(&route, "cloud", "m", table)
            .scrub(SECRET)
            .contains(SECRET),
        "a grant minted for one provider must not release raw bytes to another"
    );
}

/// An untrusted route carries no grant at all, so it can never release raw
/// bytes — the invariant is one-directional and this is the direction that is
/// enforced.
#[test]
fn an_untrusted_route_never_releases_raw_bytes() {
    let cfg = config(LlmMode::Frontier);
    let table = secret_table();
    let route = Model::configured_custody_route(&cfg, "cloud", "m", &table)
        .expect("a configured untrusted target routes");
    assert_eq!(route.custody, ModelCustody::Untrusted);
    assert!(
        route.trusted_custody_grant().is_none(),
        "an untrusted selection mints no grant"
    );
    assert!(
        !Model::effective_redact_table_for(&route, "cloud", "m", table)
            .scrub(SECRET)
            .contains(SECRET)
    );
}

/// A target whose custody cannot be routed at all falls **closed**. The
/// dangerous failure mode for a missing custody decision is "assume raw"; this
/// pins the opposite.
#[test]
fn an_unroutable_configured_target_falls_closed_to_redacted() {
    let cfg = config(LlmMode::Normal);
    let table = secret_table();

    assert!(
        Model::configured_custody_route(&cfg, "never-configured", "m", &table).is_err(),
        "an unknown provider is a custody-routing error, not a silent guess"
    );
    assert!(
        !Model::effective_redact_table_for_configured(&cfg, "never-configured", "m", table)
            .scrub(SECRET)
            .contains(SECRET),
        "no custody route means redacted, never raw"
    );
}

/// A session table built from a real `redact.enabled = false` config, with
/// [`SECRET`] present in a `.env` under the returned temp dir.
///
/// This is the production build path, not a hand-made table: the point of the
/// assertions below is that the *configured* opt-out cannot empty out what an
/// untrusted route scrubs against.
fn disabled_config_table() -> (tempfile::TempDir, Arc<RedactionTable>) {
    use crate::config::extended::RedactConfig;
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join(".env"), format!("API_KEY={SECRET}\n")).unwrap();
    let cfg = RedactConfig {
        enabled: false,
        scan_environment: false,
        scan_dotenv: true,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        placeholder: PLACEHOLDER.into(),
        min_secret_length: 8,
        ..RedactConfig::default()
    };
    let table = RedactionTable::build(&cfg, tmp.path()).expect("table builds with the opt-out set");
    (tmp, Arc::new(table))
}

/// `redact.enabled = false` must still produce a *populated* table.
///
/// This is the shape the fix depends on: the opt-out is a scrub-time flag, not
/// a reason to skip collection. If the builder returned an empty table here,
/// an untrusted route would have nothing to enforce and the two tests below
/// could not be satisfied at all.
#[test]
fn the_redaction_opt_out_still_collects_a_real_table() {
    let (_tmp, table) = disabled_config_table();
    assert!(
        table.disabled(),
        "the configured opt-out must be recorded on the table"
    );
    let origins = table.entries_for_debug();
    assert!(
        origins.iter().any(|origin| origin.contains("API_KEY")),
        "the opt-out must not skip collection: the dotenv secret must be in the table; \
         origins: {origins:?}"
    );
    assert_eq!(
        table.scrub(SECRET),
        SECRET,
        "on its own the table honors the opt-out and passes through"
    );
    assert!(
        !table.enforced().scrub(SECRET).contains(SECRET),
        "the enforced view of the same table substitutes"
    );
}

/// **The security fix.** `redact.enabled = false` is a trusted-route opt-out.
/// An untrusted target is a cloud provider that may retain logs, so it is
/// redacted regardless of that setting — otherwise the one-directional
/// invariant (unredacted content never reaches an untrusted sink) has an
/// exception, and a global config flag is enough to open it.
#[test]
fn an_untrusted_route_redacts_even_when_redaction_is_disabled_in_config() {
    for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
        let mut cfg = config(mode);
        let (_tmp, table) = disabled_config_table();

        let route = Model::configured_custody_route(&cfg, "cloud", "m", &table)
            .expect("a configured untrusted target routes");
        assert!(
            !Model::effective_redact_table_for(&route, "cloud", "m", table.clone())
                .scrub(SECRET)
                .contains(SECRET),
            "{mode:?}: the config opt-out must not reach an untrusted route"
        );

        // ...and on the two real construction paths, not just the chokepoint.
        cfg.active_model = Some(active("cloud"));
        let untrusted = Model::from_config_with_env(&cfg, table.clone(), |_| Some("k".into()))
            .expect("keyless openai-compat build");
        assert!(
            !untrusted.redact_table().scrub(SECRET).contains(SECRET),
            "{mode:?}: untrusted active model leaked the secret with redaction disabled"
        );

        let utility = Model::for_provider_with_env(&cfg, "cloud", "m", table, |_| Some("k".into()))
            .expect("keyless openai-compat build");
        assert!(
            !utility.redact_table().scrub(SECRET).contains(SECRET),
            "{mode:?}: untrusted utility target leaked the secret with redaction disabled"
        );
    }
}

/// The other direction of the same decision: the opt-out is still honored where
/// the user is entitled to it. A trusted target is a sink the user vouched for,
/// so `redact.enabled = false` means raw there — that is the supported way to
/// send raw content to a model, and it must keep working. Without this, the fix
/// above would have silently removed the opt-out entirely.
#[test]
fn a_trusted_route_still_receives_raw_when_redaction_is_disabled_in_config() {
    for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
        let mut cfg = config(mode);
        let (_tmp, table) = disabled_config_table();

        let route = Model::configured_custody_route(&cfg, "selfhosted", "m", &table)
            .expect("a configured trusted target routes");
        assert_eq!(
            Model::effective_redact_table_for(&route, "selfhosted", "m", table.clone())
                .scrub(SECRET),
            SECRET,
            "{mode:?}: a trusted route must still honor the redaction opt-out"
        );

        cfg.active_model = Some(active("selfhosted"));
        let trusted = Model::from_config_with_env(&cfg, table.clone(), |_| Some("k".into()))
            .expect("keyless openai-compat build");
        assert_eq!(
            trusted.redact_table().scrub(SECRET),
            SECRET,
            "{mode:?}: trusted active model must receive raw content"
        );

        let utility =
            Model::for_provider_with_env(&cfg, "selfhosted", "m", table, |_| Some("k".into()))
                .expect("keyless openai-compat build");
        assert_eq!(
            utility.redact_table().scrub(SECRET),
            SECRET,
            "{mode:?}: trusted utility target must receive raw content"
        );
    }
}

/// Custody is orthogonal to posture on the construction path too: the same
/// target resolves the same custody class under every harness mode, and mode
/// alone never moves a model between raw and redacted.
#[test]
fn configured_custody_is_identical_across_every_harness_mode() {
    let table = secret_table();
    for target in ["selfhosted", "cloud"] {
        let mut classes = Vec::new();
        for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
            let cfg = config(mode);
            let route = Model::configured_custody_route(&cfg, target, "m", &table).unwrap();
            classes.push((
                route.custody,
                route.trusted_custody_grant().is_some(),
                Model::effective_redact_table_for(&route, target, "m", table.clone()).scrub(SECRET),
            ));
        }
        assert!(
            classes.windows(2).all(|w| w[0] == w[1]),
            "{target}: harness posture must not change custody or redaction: {classes:?}"
        );
    }
}
