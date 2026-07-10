use super::*;
use crate::skills::{Skill, SkillFrontmatter};
use std::path::PathBuf;

fn skill(name: &str) -> Skill {
    Skill {
        frontmatter: SkillFrontmatter {
            name: name.into(),
            description: "d".into(),
            ..Default::default()
        },
        source: PathBuf::from(format!("/x/{name}/SKILL.md")),
    }
}

/// Write a skill on disk (frontmatter + `body`) and return a `Skill`
/// pointing at it, so `load_body`/`render_body` can read a real file.
fn write_skill(dir: &Path, name: &str, body: &str) -> Skill {
    let sub = dir.join(name);
    std::fs::create_dir_all(&sub).unwrap();
    let path = sub.join("SKILL.md");
    std::fs::write(
        &path,
        format!("---\nname: {name}\ndescription: d\n---\n{body}"),
    )
    .unwrap();
    Skill {
        frontmatter: SkillFrontmatter {
            name: name.into(),
            description: "d".into(),
            ..Default::default()
        },
        source: path,
    }
}

/// Build a `Skill` with a real description (and optional `when_to_use`
/// trigger prose) so the relevance backstop has keywords to match
/// against. No on-disk file is needed — the backstop reads frontmatter
/// only.
fn skill_desc(name: &str, description: &str) -> Skill {
    Skill {
        frontmatter: SkillFrontmatter {
            name: name.into(),
            description: description.into(),
            ..Default::default()
        },
        source: PathBuf::from(format!("/x/{name}/SKILL.md")),
    }
}

fn skill_strict(name: &str, description: &str, triggers: &[&str]) -> Skill {
    let mut skill = skill_desc(name, description);
    skill.frontmatter.extra.insert(
        "strict_current_turn_triggers".into(),
        serde_yaml::Value::Sequence(
            triggers
                .iter()
                .map(|trigger| serde_yaml::Value::String((*trigger).to_string()))
                .collect(),
        ),
    );
    skill
}

fn folded_skill(name: &str, body: &str, user: &str) -> String {
    format!("Skill `{name}` (auto-selected):\n\n{body}\n\n---\n\n{user}")
}

/// The real `firecrawl` skill description (verbatim subject prose) — the
/// catalog entry that was wrongly injected in session `v9h213`.
const FIRECRAWL_DESC: &str = "Search, scrape, and interact with the web \
        via the Firecrawl CLI. Use this skill whenever the user wants to \
        search the web, find articles, research a topic, look something up \
        online, scrape a webpage, grab content from a URL, get data from a \
        website, crawl documentation, download a site, or interact with \
        pages that need clicks or logins.";

fn no_redact(cwd: &Path) -> crate::redact::RedactionTable {
    crate::redact::RedactionTable::build(&Default::default(), cwd).unwrap()
}

fn names(injected: &[InjectedSkill]) -> Vec<String> {
    injected.iter().map(|i| i.name.clone()).collect()
}

// ---- robust parser ----

#[test]
fn parse_choices_single_exact_match() {
    let skills = vec![skill("deploy"), skill("review")];
    let got = parse_choices("deploy", &skills);
    assert_eq!(choice_names(&got), vec!["deploy"]);
    // Bare name → no reason.
    assert_eq!(got[0].reason, None);
}

#[test]
fn parse_choices_case_insensitive_and_trimmed() {
    let skills = vec![skill("Deploy")];
    let got = parse_choices("  deploy\n", &skills);
    assert_eq!(choice_names(&got), vec!["Deploy"]);
    assert_eq!(got[0].reason, None);
}

#[test]
fn parse_choices_none_keyword_and_empty() {
    let skills = vec![skill("deploy")];
    assert!(parse_choices("NONE", &skills).is_empty());
    assert!(parse_choices("none", &skills).is_empty());
    assert!(parse_choices("", &skills).is_empty());
}

#[test]
fn parse_choices_ignores_unknown_names() {
    let skills = vec![skill("deploy")];
    assert!(parse_choices("ship-it", &skills).is_empty());
    // Known + unknown interleaved: only the known survives.
    let got = parse_choices("ship-it deploy nope", &skills);
    assert_eq!(choice_names(&got), vec!["deploy"]);
    // `nope` is a trailing word, not a separator-introduced reason.
    assert_eq!(got[0].reason, None);
}

#[test]
fn parse_choices_multiple_relevance_order_across_separators() {
    let skills = vec![skill("deploy"), skill("review"), skill("test")];
    // Mixed separators, bullets, numbering, casing, stray punctuation.
    let resp = "1. Review,\n- DEPLOY\n* test!";
    let got = parse_choices(resp, &skills);
    assert_eq!(choice_names(&got), vec!["review", "deploy", "test"]);
}

#[test]
fn parse_choices_dedupes_preserving_first_seen_order() {
    let skills = vec![skill("deploy"), skill("review")];
    let got = parse_choices("review\ndeploy\nReview\nREVIEW\ndeploy", &skills);
    assert_eq!(choice_names(&got), vec!["review", "deploy"]);
}

// ---- reason parsing (name — reason) ----

#[test]
fn parse_choices_extracts_reason_after_em_dash() {
    let skills = vec![skill("firecrawl")];
    let got = parse_choices("firecrawl — because you asked to scrape a URL", &skills);
    assert_eq!(choice_names(&got), vec!["firecrawl"]);
    assert_eq!(
        got[0].reason.as_deref(),
        Some("because you asked to scrape a URL")
    );
}

#[test]
fn parse_choices_reason_mixed_separators_and_bare() {
    let skills = vec![skill("deploy"), skill("review"), skill("test")];
    // ` - ` hyphen reason, `:` reason, and a bare name (no reason).
    let resp = "deploy - ship the release\nreview: look it over\ntest";
    let got = parse_choices(resp, &skills);
    assert_eq!(choice_names(&got), vec!["deploy", "review", "test"]);
    assert_eq!(got[0].reason.as_deref(), Some("ship the release"));
    assert_eq!(got[1].reason.as_deref(), Some("look it over"));
    assert_eq!(got[2].reason, None);
}

#[test]
fn parse_choices_collapses_multiline_and_caps_reason() {
    let skills = vec![skill("deploy")];
    // A weak model that ran the reason long: it must collapse to one
    // line and cap at the char limit with a trailing `…`.
    let long = "word ".repeat(60);
    let got = parse_choices(&format!("deploy — {long}"), &skills);
    let reason = got[0].reason.as_ref().expect("a reason");
    assert!(
        reason.chars().count() <= SELECT_REASON_MAX_CHARS,
        "reason capped, got {} chars: {reason:?}",
        reason.chars().count()
    );
    assert!(
        reason.ends_with('…'),
        "over-long reason truncated: {reason:?}"
    );
    assert!(!reason.contains('\n'), "single-lined: {reason:?}");
}

#[test]
fn parse_choices_bare_name_never_drops_or_fails() {
    // Bare-name list (old format / model omitted reasons) still parses,
    // each with reason = None.
    let skills = vec![skill("deploy"), skill("review")];
    let got = parse_choices("deploy\nreview", &skills);
    assert_eq!(choice_names(&got), vec!["deploy", "review"]);
    assert!(got.iter().all(|c| c.reason.is_none()));
}

fn choice_names(chosen: &[ParsedChoice<'_>]) -> Vec<String> {
    chosen
        .iter()
        .map(|c| c.skill.frontmatter.name.clone())
        .collect()
}

fn names_of(chosen: &[Survivor<'_>]) -> Vec<String> {
    chosen
        .iter()
        .map(|s| s.skill.frontmatter.name.clone())
        .collect()
}

// ---- deterministic relevance backstop ----

/// Regression for the v9h213 defect: an agent-identity question must
/// yield NONE even when the (stubbed) utility model names `firecrawl`.
/// `parse_choices` accepts the model's pick; the backstop rejects it
/// because the request shares no content word with the firecrawl
/// keyword set.
#[test]
fn backstop_rejects_firecrawl_on_identity_question() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let skills = vec![firecrawl];
    // What the weak utility model returned in the export.
    let chosen = parse_choices("firecrawl", &skills);
    assert_eq!(
        choice_names(&chosen),
        vec!["firecrawl"],
        "model named firecrawl"
    );

    let turns = vec![PredictionTurn {
        user: "Are you sure? I switched you. What are you now?".into(),
        agent: String::new(),
    }];
    let kept = relevance_filter(&chosen, &turns);
    assert!(
        kept.is_empty(),
        "off-topic identity question must reject firecrawl, got {:?}",
        names_of(&kept)
    );
}

/// A clearly on-topic request must still pass the backstop: a scrape
/// request shares `scrape`/`content` with the firecrawl keywords.
#[test]
fn backstop_passes_genuine_scrape_request() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let skills = vec![firecrawl];
    let chosen = parse_choices("firecrawl", &skills);
    let turns = vec![PredictionTurn {
        user: "Please scrape the content from https://example.com".into(),
        agent: String::new(),
    }];
    let kept = relevance_filter(&chosen, &turns);
    assert_eq!(
        names_of(&kept),
        vec!["firecrawl"],
        "a genuine scrape request must pass the backstop"
    );
}

/// Regression for session `ncs82d`: ordinary local-repo investigation
/// work must not auto-inject web skills even when the utility model votes
/// for `firecrawl`.
#[test]
fn backstop_rejects_firecrawl_on_ncs82d_local_repo_request() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let skills = vec![firecrawl];
    let chosen = parse_choices("firecrawl", &skills);
    assert_eq!(
        choice_names(&chosen),
        vec!["firecrawl"],
        "model named firecrawl"
    );

    let turns = vec![PredictionTurn {
        user: "Can you investigate the state of this repo, and then write a test-plan.md...".into(),
        agent: String::new(),
    }];
    let kept = relevance_filter(&chosen, &turns);
    assert!(
        kept.is_empty(),
        "local repo investigation must inject nothing, got {:?}",
        names_of(&kept)
    );
}

/// Local codebase prompts contain many words that weak models associate
/// with broad research/tooling skills. They are not external-web
/// triggers.
#[test]
fn backstop_rejects_web_skills_on_local_repo_plan_request() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let search = skill_desc(
        "web-search",
        "Search the web for online articles and current documentation.",
    );
    let scrape = skill_desc("web-scrape", "Scrape webpages and URLs from websites.");
    let skills = vec![firecrawl, search, scrape];
    let chosen = parse_choices("firecrawl\nweb-search\nweb-scrape", &skills);
    let turns = vec![PredictionTurn {
            user: "investigate this repo and write a plan for the test harness, agent model, and token handling"
                .into(),
            agent: String::new(),
        }];
    assert!(
        relevance_filter(&chosen, &turns).is_empty(),
        "local repo plan prompt must not inject web/search/scrape skills"
    );
}

#[test]
fn backstop_passes_web_skill_for_explicit_search_web_request() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let skills = vec![firecrawl];
    let chosen = parse_choices("firecrawl", &skills);
    let turns = vec![PredictionTurn {
        user: "search the web for recent OpenAI API docs".into(),
        agent: String::new(),
    }];
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["firecrawl"],
        "explicit web search with recent docs must pass"
    );
}

/// The backstop also matches on the skill *name* (and hyphen parts),
/// not just the description.
#[test]
fn backstop_matches_on_skill_name_parts() {
    let s = skill_desc("docker-deploy", "ship containers");
    let skills = vec![s];
    let chosen = parse_choices("docker-deploy", &skills);
    let turns = vec![PredictionTurn {
        user: "help me deploy this".into(),
        agent: String::new(),
    }];
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["docker-deploy"]
    );
}

/// Multiple model-named skills are filtered independently: the relevant
/// one survives, the off-topic one is dropped.
#[test]
fn backstop_filters_each_skill_independently() {
    let scrape = skill_desc("firecrawl", FIRECRAWL_DESC);
    let deploy = skill_desc("deploy", "deploy and release the application to production");
    let skills = vec![scrape, deploy];
    // One skill per line (the new parser takes the first catalog name
    // per line as the pick).
    let chosen = parse_choices("firecrawl\ndeploy", &skills);
    assert_eq!(choice_names(&chosen), vec!["firecrawl", "deploy"]);
    let turns = vec![PredictionTurn {
        user: "scrape the webpage content for me".into(),
        agent: String::new(),
    }];
    // Only firecrawl shares words ("scrape"/"webpage"/"content"); deploy
    // shares none and is rejected.
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["firecrawl"]
    );
}

/// Declared trigger prose in `when_to_use` frontmatter contributes to
/// the keyword set even when the description itself is terse.
#[test]
fn backstop_uses_when_to_use_triggers() {
    let mut s = skill_desc("k8s", "cluster helper");
    s.frontmatter.extra.insert(
        "when_to_use".into(),
        serde_yaml::Value::String("use when deploying to kubernetes".into()),
    );
    let skills = vec![s];
    let chosen = parse_choices("k8s", &skills);
    let turns = vec![PredictionTurn {
        user: "get this onto kubernetes".into(),
        agent: String::new(),
    }];
    assert_eq!(names_of(&relevance_filter(&chosen, &turns)), vec!["k8s"]);
}

#[test]
fn selector_window_strips_leading_folded_skill_blocks_only() {
    let folded = folded_skill(
        "generate-benchmark",
        "release notes deployment runbook body words",
        "actual user request",
    );
    assert_eq!(
        strip_leading_folded_auto_skills(&folded),
        "actual user request"
    );
    let mentioned_later =
        "please inspect this\n\nSkill `release-notes` (auto-selected):\n\nbody\n\n---\n\nx";
    assert_eq!(
        strip_leading_folded_auto_skills(mentioned_later),
        mentioned_later
    );
}

#[test]
fn selector_window_low_information_current_turn_injects_nothing() {
    let turns = vec![
        PredictionTurn {
            user: folded_skill(
                "generate-benchmark",
                "release notes deployment workflow terms",
                "draft release notes for benchmark generation",
            ),
            agent: "done".into(),
        },
        PredictionTurn {
            user: "Hi!".into(),
            agent: String::new(),
        },
    ];
    let mut diagnostics = SelectionDiagnostics::default();
    assert!(selector_window(&turns, &mut diagnostics).is_empty());
    assert_eq!(diagnostics.rejections[0].reason, "current_turn_gate");
}

#[test]
fn selector_window_uhh_and_what_now_ignore_prior_skill_context() {
    for current in ["Uhh", "what now?"] {
        let turns = vec![
            PredictionTurn {
                user: folded_skill(
                    "release-notes",
                    "release notes deployment runbook",
                    "draft release notes",
                ),
                agent: "done".into(),
            },
            PredictionTurn {
                user: current.into(),
                agent: String::new(),
            },
        ];
        let mut diagnostics = SelectionDiagnostics::default();
        assert!(
            selector_window(&turns, &mut diagnostics).is_empty(),
            "{current:?} must be a hard NONE gate"
        );
    }
}

#[test]
fn strict_current_turn_triggers_gate_unrelated_skills() {
    let release = skill_strict(
        "release-notes",
        RELEASE_NOTES_DESC,
        &["draft release notes", "write changelog"],
    );
    let deploy = skill_strict(
        "deploy-runbook",
        DEPLOY_RUNBOOK_DESC,
        &["prepare deployment runbook", "deploy production"],
    );
    let skills = vec![release, deploy];

    let chosen = parse_choices("release-notes\ndeploy-runbook", &skills);
    let turns = vec![PredictionTurn {
        user: "workflow task helper skill".into(),
        agent: String::new(),
    }];
    let mut diagnostics = SelectionDiagnostics::default();
    assert!(relevance_filter_with_diagnostics(&chosen, &turns, &mut diagnostics).is_empty());
    assert!(
        diagnostics
            .rejections
            .iter()
            .all(|r| r.reason == "strict_current_turn_trigger_mismatch"),
        "strict mismatch reasons recorded: {:?}",
        diagnostics.rejections
    );

    let chosen = parse_choices("release-notes\ndeploy-runbook", &skills);
    let turns = vec![PredictionTurn {
        user: "draft release notes for the new OAuth flow".into(),
        agent: String::new(),
    }];
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["release-notes"]
    );
}

#[test]
fn explicit_continuation_uses_sanitized_prior_context_not_folded_bodies() {
    let release = skill_strict(
        "release-notes",
        RELEASE_NOTES_DESC,
        &["draft release notes"],
    );
    let deploy = skill_strict(
        "deploy-runbook",
        DEPLOY_RUNBOOK_DESC,
        &["prepare deployment runbook"],
    );
    let skills = vec![release, deploy];
    let turns = vec![
        PredictionTurn {
            user: folded_skill(
                "generate-benchmark",
                "prepare deployment runbook and other body-only terms",
                "draft release notes for benchmark generation",
            ),
            agent: "started".into(),
        },
        PredictionTurn {
            user: "continue".into(),
            agent: String::new(),
        },
    ];
    let mut diagnostics = SelectionDiagnostics::default();
    let window = selector_window(&turns, &mut diagnostics);
    assert_eq!(
        window.len(),
        2,
        "continuation keeps sanitized prior context"
    );
    assert!(!window[0].user.contains("body-only terms"));

    let chosen = parse_choices("release-notes\ndeploy-runbook", &skills);
    assert_eq!(
        names_of(&relevance_filter(&chosen, &window)),
        vec!["release-notes"],
        "prior user text can continue; stripped skill body cannot trigger deploy-runbook"
    );
}

// ---- hardened relevance backstop (curated keywords + stoplist) ----

/// Real-ish release-notes description prose (no curated triggers): the
/// trigger-less fallback path uses this, pruned of generic terms.
const RELEASE_NOTES_DESC: &str = "Turn a rough change description into \
        clear release notes for users. Use when the user wants to draft, \
        clean up, or publish release notes.";

/// Real-ish deploy-runbook description prose (no curated triggers).
const DEPLOY_RUNBOOK_DESC: &str = "Prepare a production deployment \
        runbook: verify readiness, list commands, capture rollback steps, \
        and call out operator checks.";

/// Negative: a plain bug-audit request must reject every off-topic skill
/// the weak model nominated. The expanded generic-term stoplist strips
/// `analysis`/`repo`/`bug`/`change`/`prompt`/… from the keyword side, so
/// the incidental description overlap that used to pass the backstop no
/// longer does — all three are rejected, nothing injects.
#[test]
fn backstop_rejects_all_on_bug_audit_request() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let release = skill_desc("release-notes", RELEASE_NOTES_DESC);
    let deploy = skill_desc("deploy-runbook", DEPLOY_RUNBOOK_DESC);
    let skills = vec![firecrawl, release, deploy];
    // What the over-nominating utility model returned.
    let chosen = parse_choices("release-notes\ndeploy-runbook\nfirecrawl", &skills);
    assert_eq!(
        choice_names(&chosen),
        vec!["release-notes", "deploy-runbook", "firecrawl"],
        "model nominated all three"
    );
    let turns = vec![PredictionTurn {
        user: "Can you do a deep dive analysis of this repo? I want to \
                   make sure there are no bugs before I ship it. Don't make \
                   any changes."
            .into(),
        agent: String::new(),
    }];
    assert!(
        relevance_filter(&chosen, &turns).is_empty(),
        "a plain bug-audit request must inject nothing, got {:?}",
        names_of(&relevance_filter(&chosen, &turns))
    );
}

/// Positive: the bar didn't over-prune — a genuine scrape request still
/// keeps `firecrawl`, and a genuine release-notes request still keeps
/// `release-notes`. The discriminating words (`scrape`, `release`) survive
/// the stoplist.
#[test]
fn backstop_keeps_genuine_matches() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let release = skill_desc("release-notes", RELEASE_NOTES_DESC);

    // "scrape the pricing page" → firecrawl (shares `scrape`).
    let fc = [firecrawl];
    let chosen = parse_choices("firecrawl", &fc);
    let turns = vec![PredictionTurn {
        user: "scrape the pricing page".into(),
        agent: String::new(),
    }];
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["firecrawl"],
        "genuine scrape request keeps firecrawl"
    );

    // "draft release notes" -> release-notes (shares `release`,
    // a discriminating description word in the trigger-less fallback).
    let rn = [release];
    let chosen = parse_choices("release-notes", &rn);
    let turns = vec![PredictionTurn {
        user: "draft release notes for the new login flow".into(),
        agent: String::new(),
    }];
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["release-notes"],
        "genuine release-notes request keeps release-notes"
    );
}

/// Trigger-less fallback: a skill with only a `description` (no curated
/// triggers) still matches on a *discriminating* description word, but a
/// generic-stoplist word in that same request matches nothing.
#[test]
fn trigger_less_fallback_matches_discriminating_word_only() {
    // No triggers → keywords come from the pruned description.
    let s = skill_desc(
        "rebrander",
        "Rebrand a product: rename every occurrence across the codebase.",
    );
    let skills = vec![s];

    // A discriminating word (`rebrand`) matches.
    let chosen = parse_choices("rebrander", &skills);
    let turns = vec![PredictionTurn {
        user: "please rebrand the product".into(),
        agent: String::new(),
    }];
    assert_eq!(
        names_of(&relevance_filter(&chosen, &turns)),
        vec!["rebrander"],
        "discriminating description word matches in the trigger-less fallback"
    );

    // A request sharing only generic-stoplist words (`codebase`,
    // `application`) with the description matches nothing — those were
    // pruned from the keyword side.
    let chosen = parse_choices("rebrander", &skills);
    let turns = vec![PredictionTurn {
        user: "look at the codebase for this application".into(),
        agent: String::new(),
    }];
    assert!(
        relevance_filter(&chosen, &turns).is_empty(),
        "a generic-stoplist-only overlap must not pass the backstop"
    );
}

// ---- once-per-session suppression (change 4) ----

/// The already-injected exclusion is applied at the same discover-then-
/// filter step `select_inner` uses (before the catalog): a skill in the
/// exclusion set drops out, the rest stay.
fn select_catalog_excluding(
    cwd: &Path,
    cfg: &crate::config::extended::SkillsConfig,
    already_injected: &std::collections::HashSet<String>,
) -> Vec<crate::skills::Skill> {
    crate::skills::discover(cwd, cfg)
        .unwrap()
        .into_iter()
        .filter(|s| !s.frontmatter.disable_model_invocation)
        .filter(|s| !already_injected.contains(&s.frontmatter.name))
        .collect()
}

#[test]
fn already_injected_skill_excluded_before_catalog() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("scan");
    std::fs::create_dir_all(&scan).unwrap();
    write_fm_skill(&scan, "firecrawl", "");
    write_fm_skill(&scan, "release-notes", "");
    let cfg = crate::config::extended::SkillsConfig {
        scan_dirs: vec![scan.to_string_lossy().into_owned()],
        auto_bang_commands: false,
        ancestor_walk: false,
    };

    // With firecrawl already injected this session, it is gone from the
    // candidate set; a different still-relevant skill is unaffected.
    let mut injected = std::collections::HashSet::new();
    injected.insert("firecrawl".to_string());
    let candidates = select_catalog_excluding(tmp.path(), &cfg, &injected);
    let names: Vec<&str> = candidates
        .iter()
        .map(|s| s.frontmatter.name.as_str())
        .collect();
    assert!(
        !names.contains(&"firecrawl"),
        "already-injected firecrawl excluded from the catalog; got {names:?}"
    );
    assert!(
        names.contains(&"release-notes"),
        "a different skill is unaffected; got {names:?}"
    );

    // Excluding the only candidate empties the set → `select_inner`
    // returns `Selection::None` (its `skills.is_empty()` path), never an
    // error.
    let mut both = std::collections::HashSet::new();
    both.insert("firecrawl".to_string());
    both.insert("release-notes".to_string());
    let candidates = select_catalog_excluding(tmp.path(), &cfg, &both);
    assert!(
        candidates.is_empty(),
        "excluding every candidate yields an empty set (→ Selection::None)"
    );
}

/// End-to-end through `select`: the once-per-session set short-circuits to
/// `Selection::None` when it empties the candidates — no utility model is
/// ever consulted, no error. (A genuine match on `firecrawl` — proven by
/// `backstop_keeps_genuine_matches` — would otherwise inject; suppression
/// is the gate that stops the repeat.)
#[tokio::test]
async fn select_returns_none_when_exclusion_empties_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("scan");
    std::fs::create_dir_all(scan.join("firecrawl")).unwrap();
    std::fs::write(
        scan.join("firecrawl").join("SKILL.md"),
        "---\nname: firecrawl\ndescription: scrape the web\n---\nBODY",
    )
    .unwrap();

    let mut extended = ExtendedConfig::default();
    extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];
    // A utility model IS configured (so the unset-model short-circuit is
    // not what we're testing) — but exclusion empties the candidates
    // before any call is made.
    extended.utility_model = Some("nope/nope".into());
    let providers = ProvidersConfig::default();
    let redact = std::sync::Arc::new(
        crate::redact::RedactionTable::build(&Default::default(), tmp.path()).unwrap(),
    );
    let turns = vec![PredictionTurn {
        user: "scrape the pricing page".into(),
        agent: String::new(),
    }];
    let mut injected = std::collections::HashSet::new();
    injected.insert("firecrawl".to_string());

    let sel = select(tmp.path(), &extended, &providers, redact, &turns, &injected).await;
    assert!(
        matches!(sel, Selection::None),
        "exclusion empties the candidates → Selection::None, no error, no model call"
    );
}

// ---- prompt window ----

#[test]
fn prompt_carries_last_turn_transcript_not_a_single_message() {
    let turns = vec![
        PredictionTurn {
            user: "set up CI".into(),
            agent: "Added a workflow.".into(),
        },
        PredictionTurn {
            user: "now deploy it".into(),
            agent: String::new(),
        },
    ];
    let p = build_select_prompt("- deploy: d\n", &turns);
    assert!(p.contains("USER: set up CI"), "{p}");
    assert!(p.contains("AGENT: Added a workflow."), "{p}");
    assert!(p.contains("USER: now deploy it"), "{p}");
    // Open turn (no agent reply) omits the AGENT marker for that turn.
    assert!(!p.contains("AGENT: \n"), "{p}");
    // Catalog present; no body content leaks in.
    assert!(p.contains("- deploy: d"), "{p}");
}

// ---- relevance-filter matched words + fallback reason ----

/// The backstop returns the matched content words per survivor (sorted),
/// and the keyword fallback synthesizes `matches: a, b, c` from them.
#[test]
fn relevance_filter_returns_matched_words_and_fallback() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let skills = vec![firecrawl];
    let chosen = parse_choices("firecrawl", &skills); // bare name → no model reason
    let turns = vec![PredictionTurn {
        user: "please scrape the webpage content".into(),
        agent: String::new(),
    }];
    let kept = relevance_filter(&chosen, &turns);
    assert_eq!(names_of(&kept), vec!["firecrawl"]);
    // The matched set is the request ∩ keyword intersection, sorted.
    // `content` is a generic skill-keyword stopword now, so it does not
    // contribute; the discriminating `scrape`/`webpage` do.
    let m = &kept[0].matched;
    assert!(m.contains(&"scrape".to_string()), "matched: {m:?}");
    assert!(m.contains(&"webpage".to_string()), "matched: {m:?}");
    assert!(
        !m.contains(&"content".to_string()),
        "generic stopword pruned from keyword side: {m:?}"
    );
    assert!(m.windows(2).all(|w| w[0] <= w[1]), "sorted: {m:?}");
    // No model reason → keyword fallback is synthesized.
    assert_eq!(kept[0].reason, None);
    let fb = fallback_reason(&kept[0].matched).expect("a fallback reason");
    assert!(fb.starts_with("matches: "), "fallback shape: {fb:?}");
    // Capped to the first few words.
    let listed = fb.trim_start_matches("matches: ").split(", ").count();
    assert!(listed <= FALLBACK_KEYWORD_COUNT, "fallback capped: {fb:?}");
}

/// A model reason on the line survives the backstop and takes precedence
/// over the keyword fallback in `render_capped_and_budgeted`.
#[test]
fn relevance_filter_preserves_model_reason() {
    let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
    let skills = vec![firecrawl];
    let chosen = parse_choices("firecrawl — to scrape the page you named", &skills);
    let turns = vec![PredictionTurn {
        user: "scrape the content".into(),
        agent: String::new(),
    }];
    let kept = relevance_filter(&chosen, &turns);
    assert_eq!(
        kept[0].reason.as_deref(),
        Some("to scrape the page you named")
    );
}

// ---- cap + budget rendering ----

/// Build a `Survivor` for the render tests: no model reason, no matched
/// words (the render path's reason population is exercised separately).
fn survivor(skill: &Skill) -> Survivor<'_> {
    Survivor {
        skill,
        reason: None,
        matched: Vec::new(),
    }
}

#[test]
fn render_multi_match_injects_all_in_relevance_order() {
    let tmp = tempfile::tempdir().unwrap();
    let a = write_skill(tmp.path(), "deploy", "deploy body");
    let b = write_skill(tmp.path(), "review", "review body");
    let chosen = vec![survivor(&a), survivor(&b)];
    let extended = ExtendedConfig::default();
    let injected =
        render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
    assert_eq!(names(&injected), vec!["deploy", "review"]);
    assert_eq!(injected[0].body.trim(), "deploy body");
    assert_eq!(injected[1].body.trim(), "review body");
}

#[test]
fn render_single_match_injects_one() {
    let tmp = tempfile::tempdir().unwrap();
    let a = write_skill(tmp.path(), "deploy", "deploy body");
    let chosen = vec![survivor(&a)];
    let extended = ExtendedConfig::default();
    let injected =
        render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
    assert_eq!(names(&injected), vec!["deploy"]);
}

/// `render_capped_and_budgeted` populates the reason: the model reason
/// when present, else the keyword fallback from the matched words.
#[test]
fn render_populates_reason_model_then_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let a = write_skill(tmp.path(), "deploy", "deploy body");
    let b = write_skill(tmp.path(), "review", "review body");
    let extended = ExtendedConfig::default();
    let chosen = vec![
        Survivor {
            skill: &a,
            reason: Some("because you asked to ship".into()),
            matched: vec!["ship".into()],
        },
        Survivor {
            skill: &b,
            reason: None,
            matched: vec!["review".into(), "diff".into()],
        },
    ];
    let injected =
        render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
    assert_eq!(
        injected[0].reason.as_deref(),
        Some("because you asked to ship"),
        "model reason wins"
    );
    assert_eq!(
        injected[1].reason.as_deref(),
        Some("matches: review, diff"),
        "keyword fallback when no model reason"
    );
}

#[test]
fn render_cap_keeps_top_n_by_order() {
    let tmp = tempfile::tempdir().unwrap();
    // More skills than the cap; all tiny so the budget never bites.
    let s: Vec<Skill> = (0..MAX_SELECTED_SKILLS + 2)
        .map(|i| write_skill(tmp.path(), &format!("s{i}"), "x"))
        .collect();
    let chosen: Vec<Survivor> = s.iter().map(survivor).collect();
    let extended = ExtendedConfig::default();
    let injected =
        render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
    assert_eq!(injected.len(), MAX_SELECTED_SKILLS);
    // The kept set is the top-N by relevance order (s0..s{N-1}).
    let expected: Vec<String> = (0..MAX_SELECTED_SKILLS).map(|i| format!("s{i}")).collect();
    assert_eq!(names(&injected), expected);
}

#[test]
fn render_budget_drops_lowest_priority_whole_bodies() {
    let tmp = tempfile::tempdir().unwrap();
    // First body nearly fills the budget; the second is non-trivial and
    // cannot fit, so it is dropped whole (never truncated). Both within
    // the count cap so only the budget is under test.
    let near_full = "word ".repeat(SELECTED_BODY_TOKEN_BUDGET - 50);
    let second = "word ".repeat(200);
    assert!(
        crate::tokens::count(&near_full) <= SELECTED_BODY_TOKEN_BUDGET,
        "first body must fit alone"
    );
    assert!(
        crate::tokens::count(&near_full) + crate::tokens::count(&second)
            > SELECTED_BODY_TOKEN_BUDGET,
        "combined must exceed budget"
    );
    let a = write_skill(tmp.path(), "deploy", &near_full);
    let b = write_skill(tmp.path(), "review", &second);
    let chosen = vec![survivor(&a), survivor(&b)];
    let extended = ExtendedConfig::default();
    let injected =
        render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
    // Only the high-priority body survives; the lower one is dropped
    // whole. The survivor is byte-for-byte the full body (no truncation).
    assert_eq!(names(&injected), vec!["deploy"]);
    assert_eq!(injected[0].body.trim(), near_full.trim());
}

// ---- auto-select invocation filter ----

/// Mirror of the discover-then-filter step in `select_inner`: a skill
/// enters the utility-model catalog iff `disable-model-invocation` is not
/// true. `user-invocable` does not affect catalog membership.
fn auto_select_catalog(cwd: &Path, cfg: &crate::config::extended::SkillsConfig) -> String {
    let skills: Vec<crate::skills::Skill> = crate::skills::discover(cwd, cfg)
        .unwrap()
        .into_iter()
        .filter(|s| !s.frontmatter.disable_model_invocation)
        .collect();
    crate::skills::catalog_lines(&skills)
}

fn write_fm_skill(dir: &Path, name: &str, frontmatter_extra: &str) {
    let sub = dir.join(name);
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(
        sub.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: d-{name}\n{frontmatter_extra}---\nB"),
    )
    .unwrap();
}

#[test]
fn disable_model_invocation_excluded_from_catalog() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("scan");
    std::fs::create_dir_all(&scan).unwrap();
    write_fm_skill(&scan, "plain", "");
    write_fm_skill(&scan, "useronly", "disable-model-invocation: true\n");
    let cfg = crate::config::extended::SkillsConfig {
        scan_dirs: vec![scan.to_string_lossy().into_owned()],
        auto_bang_commands: false,
        ancestor_walk: false,
    };
    let catalog = auto_select_catalog(tmp.path(), &cfg);
    assert!(catalog.contains("plain"), "got {catalog:?}");
    assert!(
        !catalog.contains("useronly") && !catalog.contains("d-useronly"),
        "a disable-model-invocation skill must not enter the catalog; got {catalog:?}"
    );
}

#[test]
fn user_invocable_false_stays_in_catalog() {
    // A model-only skill (hidden from the slash menu) is still
    // auto-injectable, so its description stays in the catalog.
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("scan");
    std::fs::create_dir_all(&scan).unwrap();
    write_fm_skill(&scan, "modelonly", "user-invocable: false\n");
    let cfg = crate::config::extended::SkillsConfig {
        scan_dirs: vec![scan.to_string_lossy().into_owned()],
        auto_bang_commands: false,
        ancestor_walk: false,
    };
    let catalog = auto_select_catalog(tmp.path(), &cfg);
    assert!(
        catalog.contains("modelonly"),
        "a user-invocable:false skill must remain in the auto-select catalog; got {catalog:?}"
    );
}

// ---- graceful degradation ----

#[tokio::test]
async fn select_skips_when_utility_model_unset() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("scan");
    std::fs::create_dir_all(scan.join("deploy")).unwrap();
    std::fs::write(
        scan.join("deploy").join("SKILL.md"),
        "---\nname: deploy\ndescription: d\n---\nBODY",
    )
    .unwrap();

    let mut extended = ExtendedConfig::default();
    extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];
    // utility_model deliberately unset.
    let providers = ProvidersConfig::default();
    let redact = std::sync::Arc::new(
        crate::redact::RedactionTable::build(&Default::default(), tmp.path()).unwrap(),
    );

    let turns = vec![PredictionTurn {
        user: "deploy please".into(),
        agent: String::new(),
    }];
    let sel = select(
        tmp.path(),
        &extended,
        &providers,
        redact,
        &turns,
        &std::collections::HashSet::new(),
    )
    .await;
    assert!(
        matches!(sel, Selection::None),
        "unset utility_model must skip auto-selection without error"
    );
}

#[tokio::test]
async fn select_low_information_turn_skips_before_model_lookup_with_diagnostics() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("scan");
    std::fs::create_dir_all(scan.join("release-notes")).unwrap();
    std::fs::write(
        scan.join("release-notes").join("SKILL.md"),
        "---\nname: release-notes\ndescription: draft release notes\n---\nBODY",
    )
    .unwrap();

    let mut extended = ExtendedConfig::default();
    extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];
    extended.utility_model = Some("missing-provider/missing-model".into());
    let providers = ProvidersConfig::default();
    let redact = std::sync::Arc::new(
        crate::redact::RedactionTable::build(&Default::default(), tmp.path()).unwrap(),
    );
    let turns = vec![PredictionTurn {
        user: "thanks".into(),
        agent: String::new(),
    }];

    let (sel, diagnostics) = select_with_diagnostics(
        tmp.path(),
        &extended,
        &providers,
        redact,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        &turns,
        &std::collections::HashSet::new(),
    )
    .await;

    assert!(matches!(sel, Selection::None));
    assert_eq!(diagnostics.rejections.len(), 1);
    assert_eq!(diagnostics.rejections[0].skill, None);
    assert_eq!(diagnostics.rejections[0].reason, "current_turn_gate");
}
