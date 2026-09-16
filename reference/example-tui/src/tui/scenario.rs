//! Seed sessions and their scripts. The responses are canned — no model is
//! called — but they're written to exercise the UX the demo is about: a
//! streaming answer with a reasoning pass, a run that parks on your decision
//! (so the sidebar dot goes red), and turns long enough that queuing a message
//! mid-run actually has somewhere to land.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use super::model::{
    AgentNode, FileDiff, Hunk, Message, Role, Segment, Session, SkillInfo, Status, Step, TaskInfo,
    TimerInfo, ToolInfo, ToolTier, Turn, TurnStats,
};

/* --------------------------- seeded file changes -------------------------- */

/// The new token-verification module, shown as a completed write in session 1.
const VERIFY_TOKEN_BODY: &[&str] = &[
    "import jwt from \"jsonwebtoken\";",
    "import type { Claims } from \"./claims\";",
    "",
    "export type TokenError = \"expired\" | \"malformed\";",
    "",
    "export function verifyToken(raw: string): Result<Claims, TokenError> {",
    "  try {",
    "    return ok(jwt.verify(raw, env.JWT_SECRET) as Claims);",
    "  } catch (err) {",
    "    return err instanceof TokenExpiredError ? fail(\"expired\") : fail(\"malformed\");",
    "  }",
    "}",
];

/// The middleware edit that delegates to the new module, shown in session 1.
const AUTH_MIDDLEWARE_EDIT: &[Hunk] = &[
    Hunk::Context("import { RequestHandler } from \"express\";"),
    Hunk::Added("import { verifyToken } from \"../auth/verify-token\";"),
    Hunk::Context(""),
    Hunk::Context("export const requireAuth: RequestHandler = (req, res, next) => {"),
    Hunk::Context("  const raw = readBearer(req.headers.authorization);"),
    Hunk::Removed("  let claims: Claims;"),
    Hunk::Removed("  try {"),
    Hunk::Removed("    claims = jwt.verify(raw, env.JWT_SECRET) as Claims;"),
    Hunk::Removed("  } catch {"),
    Hunk::Removed("    return res.sendStatus(401);"),
    Hunk::Removed("  }"),
    Hunk::Added("  const result = verifyToken(raw);"),
    Hunk::Added("  if (!result.ok) {"),
    Hunk::Added("    return res.sendStatus(result.error === \"expired\" ? 401 : 403);"),
    Hunk::Added("  }"),
    Hunk::Context("  req.user = loadUser(result.claims.sub);"),
    Hunk::Context("  next();"),
    Hunk::Context("};"),
];

/// A focused test file the agent writes *live* when you accept the follow-up in
/// session 1 — the streaming counterpart to the seeded diffs above.
const VERIFY_TOKEN_TEST: &[&str] = &[
    "import { verifyToken } from \"./verify-token\";",
    "",
    "test(\"accepts a freshly signed token\", () => {",
    "  const token = sign({ sub: \"u_1\" });",
    "  expect(verifyToken(token)).toEqual(ok({ sub: \"u_1\" }));",
    "});",
    "",
    "test(\"reports an expired token as 401, not 403\", () => {",
    "  expect(verifyToken(expired())).toEqual(fail(\"expired\"));",
    "});",
];

/// Handshake still called `jwt.verify` inline; the parent migrates it after
/// the interactive explorer hands back.
const HANDSHAKE_EDIT: &[Hunk] = &[
    Hunk::Context(
        "export function verifyUpgrade(req: IncomingMessage): Result<Claims, TokenError> {",
    ),
    Hunk::Context("  const raw = readBearer(req.headers.authorization);"),
    Hunk::Removed("  try {"),
    Hunk::Removed("    return ok(jwt.verify(raw, env.JWT_SECRET) as Claims);"),
    Hunk::Removed("  } catch {"),
    Hunk::Removed("    return fail(\"malformed\");"),
    Hunk::Removed("  }"),
    Hunk::Added("  return verifyToken(raw);"),
    Hunk::Context("}"),
];

/// A small live edit the storefront session applies when you accept the
/// rounding fix.
const COUPON_ROUNDING_EDIT: &[Hunk] = &[
    Hunk::Context("export function applyCoupon(total: Money, coupon: Coupon): Money {"),
    Hunk::Context("  const off = total.amount * coupon.rate;"),
    Hunk::Removed("  return money(total.amount - off, total.currency);"),
    Hunk::Added("  return money(toMinorUnits(total.amount - off), total.currency);"),
    Hunk::Context("}"),
];

/// A seeded (historical) message with a wall-clock stamp `mins_ago` in the
/// past, so opened sessions read like a real conversation with timestamps.
fn seeded(role: Role, segments: Vec<Segment>, mins_ago: u64) -> Message {
    Message {
        role,
        segments,
        interrupted: false,
        streaming: false,
        at: SystemTime::now() - Duration::from_secs(mins_ago * 60),
        pinned: false,
        thinking_open: None,
        stats: matches!(role, Role::Agent)
            .then(|| TurnStats::demo("OpenAI", "GPT-5 Codex", mins_ago)),
        stats_open: false,
        summary_open: false,
    }
}

/// Push a user + agent exchange onto a seeded transcript so sessions open with
/// history to scroll through. `mins_ago` stamps the user message; the reply
/// lands a minute later.
fn seed_exchange(messages: &mut Vec<Message>, user: &str, agent: &str, mins_ago: u64) {
    messages.push(seeded(
        Role::User,
        vec![Segment::Prose(user.to_string())],
        mins_ago,
    ));
    messages.push(seeded(
        Role::Agent,
        vec![Segment::Prose(agent.to_string())],
        mins_ago.saturating_sub(1),
    ));
}

fn session(
    title: &str,
    subtitle: &str,
    repo: &str,
    resting: Status,
    messages: Vec<Message>,
    script: Vec<Turn>,
    suggestions: &[&str],
) -> Session {
    let last_active = messages
        .iter()
        .map(|message| message.at)
        .max()
        .unwrap_or_else(SystemTime::now);
    Session {
        title: title.to_string(),
        subtitle: subtitle.to_string(),
        repo: repo.to_string(),
        messages,
        script: VecDeque::from(script),
        suggestions: suggestions.iter().map(|s| s.to_string()).collect(),
        queue: Vec::new(),
        run: None,
        resting,
        scroll: 0,
        pinned: true,
        last_active,
        archived: false,
        starred: false,
        show_thinking: false,
        focus: Vec::new(),
        subagents: Vec::new(),
        tools: root_tools(),
        skills: root_skills(),
        tasks: Vec::new(),
        timers: Vec::new(),
    }
}

fn tool(name: &str, hint: &str) -> ToolInfo {
    tool_with(name, hint, ToolTier::Enabled)
}

fn tool_with(name: &str, hint: &str, tier: ToolTier) -> ToolInfo {
    ToolInfo {
        name: name.to_string(),
        hint: hint.to_string(),
        tier,
    }
}

fn skill(name: &str, hint: &str) -> SkillInfo {
    SkillInfo {
        name: name.to_string(),
        hint: hint.to_string(),
    }
}

/// The root agent's tool catalog — twelve, matching the activity-bar demo count.
fn root_tools() -> Vec<ToolInfo> {
    vec![
        tool("read_file", "Read a file from the workspace"),
        tool("write_file", "Create or overwrite a file"),
        tool("edit_file", "Apply a targeted patch"),
        tool("grep", "Search file contents"),
        tool("glob", "Find files by name pattern"),
        tool("shell", "Run a command in the sandbox"),
        tool("git_status", "Read the working tree"),
        tool("git_diff", "Show unstaged and staged diffs"),
        tool_with(
            "web_search",
            "Search the public web",
            ToolTier::Discoverable,
        ),
        tool_with("fetch_url", "Fetch a URL as text", ToolTier::Discoverable),
        tool_with("list_dir", "List a directory", ToolTier::Disabled),
        tool_with(
            "diagnostics",
            "Read compiler and linter output",
            ToolTier::Disabled,
        ),
    ]
}

/// The root agent's skill catalog — twenty-four, matching the activity-bar demo count.
fn root_skills() -> Vec<SkillInfo> {
    vec![
        skill("code-review", "Review a diff for bugs and style"),
        skill("refactor", "Restructure without changing behaviour"),
        skill("test-author", "Write focused unit tests"),
        skill("debug", "Narrow a failing test or log"),
        skill("docs", "Write or update documentation"),
        skill("commit", "Draft a commit message"),
        skill("pr-summary", "Summarise a pull request"),
        skill("api-design", "Propose an API shape"),
        skill("sql", "Read and write SQL"),
        skill("auth", "Review authentication flows"),
        skill("perf", "Spot hot paths"),
        skill("security", "Look for common vulns"),
        skill("i18n", "Check copy and locale keys"),
        skill("a11y", "Flag accessibility issues"),
        skill("css", "Layout and styling help"),
        skill("rust", "Idiomatic Rust"),
        skill("typescript", "Idiomatic TypeScript"),
        skill("python", "Idiomatic Python"),
        skill("shell", "Shell scripting"),
        skill("docker", "Containers and Compose"),
        skill("ci", "GitHub Actions and pipelines"),
        skill("release", "Versioning and changelog"),
        skill("migrate", "Schema and data migrations"),
        skill("oncall", "Incident notes and rollback"),
    ]
}

fn pick_tools(names: &[&str]) -> Vec<ToolInfo> {
    let mut all = root_tools();
    all.push(tool(
        "done",
        "Hand the result back and return the user to the parent agent",
    ));
    names
        .iter()
        .filter_map(|name| all.iter().find(|tool| tool.name == *name).cloned())
        .collect()
}

fn pick_skills(names: &[&str]) -> Vec<SkillInfo> {
    let all = root_skills();
    names
        .iter()
        .filter_map(|name| all.iter().find(|skill| skill.name == *name).cloned())
        .collect()
}

/// The initial set of sessions. Between them the sidebar shows all three status
/// colours at rest: green (done), red (waiting on you), and grey (idle).
pub fn initial_sessions() -> Vec<Session> {
    let mut sessions = Vec::new();

    // 1. Done (green) — an extraction that already landed, so the transcript
    //    opens on a file write and a file edit you can eyeball straight away.
    let refactor = vec![
        seeded(
            Role::User,
            vec![Segment::Prose(
                "Can you take a look at how requireAuth is structured in the API gateway?".into(),
            )],
            12,
        ),
        seeded(
            Role::Agent,
            vec![
                Segment::Reasoning(
                    "The middleware and handshake both call jwt.verify inline. Extracting that keeps the two sites from drifting."
                        .into(),
                ),
                Segment::Prose(
                    "I read through src/middleware/auth.ts. It's a single 40-line function that reads the bearer token, verifies it inline with jwt.verify, then loads the user. That verification half is copy-pasted into src/ws/handshake.ts, which is the main thing I'd change. Want me to extract it into its own module?".into(),
                ),
            ],
            11,
        ),
        seeded(
            Role::User,
            vec![Segment::Prose(
                "Yes — extract the verification into its own module.".to_string(),
            )],
            9,
        ),
        seeded(
            Role::Agent,
            vec![
                Segment::Prose(
                    "Done. I moved the verification into its own module and pointed the middleware at it — same behaviour, minus the duplication.".to_string(),
                ),
                Segment::Diff(FileDiff::write("src/auth/verify-token.ts", VERIFY_TOKEN_BODY)),
                Segment::Diff(FileDiff::edit("src/middleware/auth.ts", AUTH_MIDDLEWARE_EDIT)),
                Segment::Prose(
                    "The auth suite is green, and ws/handshake.ts now imports the same helper, so the two call sites can't drift apart again.".to_string(),
                ),
                Segment::Subagent {
                    name: "Explore call sites".into(),
                    interactive: true,
                    summary: "Checking every jwt.verify use so the extract does not miss a caller."
                        .into(),
                    path: vec![0],
                },
                Segment::Subagent {
                    name: "Scan changelog".into(),
                    interactive: false,
                    summary: "Looked at CHANGELOG.md — no auth notes to update. Done.".into(),
                    path: vec![1],
                },
            ],
            8,
        ),
    ];
    // The interactive explorer already has a short conversation of its own.
    // It is inlined in the parent transcript (teal); focus is routing only.
    let mut explore = Vec::new();
    seed_exchange(
        &mut explore,
        "Look at every jwt.verify call site.",
        "Found three: middleware (now using verifyToken), handshake.ts, and the expired-token helper in tests.",
        8,
    );
    seed_exchange(
        &mut explore,
        "Is handshake.ts the same extract we just did?",
        "Almost. Handshake still calls jwt.verify inline and maps every error to 401, so an expired token never becomes 403 — that's the drift.",
        6,
    );
    explore.push(seeded(
        Role::User,
        vec![Segment::Prose("What about the tests?".into())],
        4,
    ));
    explore.push(seeded(
        Role::Agent,
        vec![
            Segment::Prose(
                "The expired-token helper still uses jwt.verify directly, so it never goes through verifyToken. I kicked off a background writer for a focused test file — I'll keep scanning while that runs.".into(),
            ),
            Segment::Subagent {
                name: "Write regression test".into(),
                interactive: false,
                summary: "Drafting verify-token.test.ts in the background.".into(),
                path: vec![0, 0],
            },
        ],
        3,
    ));
    for (i, message) in explore.iter_mut().enumerate() {
        if let Some(stats) = &mut message.stats {
            *stats = TurnStats::demo("xAI", "Grok Code", 8 + i as u64);
        }
    }
    let mut refactor_session = session(
        "Refactor auth middleware",
        "Extracted token verification",
        "acme/api-gateway",
        Status::Working,
        refactor,
        vec![
            // Played after the explorer runs `done` and the user talks to
            // the main agent again.
            Turn {
                steps: vec![
                    Step::Think(
                        "The module has two branches worth locking down: a valid token and an expired one, which is exactly the 401-vs-403 split I introduced. I'll drop a focused test beside it.",
                    ),
                    Step::Say(
                        "Adding a test file next to the module, covering the happy path and the expired-token branch.",
                    ),
                    Step::Wait(1400),
                    Step::Write {
                        path: "src/auth/verify-token.test.ts",
                        body: VERIFY_TOKEN_TEST,
                    },
                    Step::Say(
                        "Both cases pass, so the 401-vs-403 behaviour is pinned and a future change can't quietly regress it.",
                    ),
                ],
                follow_ups: vec![
                    "Also cover the malformed-token case",
                    "Migrate handshake.ts next",
                ],
            },
            Turn {
                steps: vec![
                    Step::Say(
                        "Migrating handshake.ts onto verifyToken so expired tokens become 401 and malformed become 403 — same split as the middleware.",
                    ),
                    Step::Wait(1200),
                    Step::Edit {
                        path: "src/ws/handshake.ts",
                        hunk: HANDSHAKE_EDIT,
                    },
                    Step::Say(
                        "Handshake now shares the helper. The expired-token test helper is the last jwt.verify; I left it because it's asserting the library error, not the app path.",
                    ),
                ],
                follow_ups: vec!["Draft a commit message", "Leave the helper as-is"],
            },
            Turn {
                steps: vec![Step::Say(
                    "Commit message: extract verifyToken, point middleware and handshake at it, and pin the 401-vs-403 split with a test.",
                )],
                follow_ups: vec!["Open the PR", "Run the full auth suite"],
            },
        ],
        &[
            "Walk me through handshake.ts",
            "Hand the remaining sites back",
        ],
    );
    refactor_session.tasks = vec![TaskInfo {
        name: "pnpm test --filter auth".into(),
        status: Status::Working,
    }];
    refactor_session.timers = vec![TimerInfo {
        name: "re-run auth suite".into(),
        remaining: "2m".into(),
    }];
    refactor_session.subagents = vec![
        AgentNode {
            messages: explore,
            children: vec![AgentNode {
                tools: pick_tools(&["read_file", "write_file", "edit_file"]),
                skills: pick_skills(&["test-author", "typescript"]),
                tasks: vec![TaskInfo {
                    name: "draft verify-token.test.ts".into(),
                    status: Status::Working,
                }],
                report: Some(
                    "Drafted verify-token.test.ts covering the happy path and the expired-token branch.".into(),
                ),
                // Long enough that a user can `done` first; tests override this.
                ready_at: Some(Instant::now() + Duration::from_secs(8)),
                ..AgentNode::new("Write regression test", false, Status::Working)
            }],
            tools: pick_tools(&["read_file", "grep", "glob", "list_dir", "done"]),
            skills: pick_skills(&["debug", "auth", "typescript"]),
            tasks: vec![TaskInfo {
                name: "scan jwt.verify".into(),
                status: Status::Working,
            }],
            timers: vec![TimerInfo {
                name: "re-check handshake".into(),
                remaining: "1m".into(),
            }],
            model: Some("Grok Code".into()),
            script: VecDeque::from([
                Turn {
                    steps: vec![
                        Step::Think(
                            "They want the handshake walkthrough. I'll read the error mapping and show how it disagrees with verifyToken.",
                        ),
                        Step::Tool {
                            name: "grep",
                            hint: "jwt.verify in src/ws/handshake.ts",
                        },
                        Step::Say(
                            "handshake.ts still does jwt.verify in a try/catch and returns fail(\"malformed\") for every throw — expired tokens included. verifyToken distinguishes TokenExpiredError, which is why the middleware now sends 401 vs 403. Same extract, different error map.",
                        ),
                    ],
                    follow_ups: vec![
                        "Check the expired-token helper too",
                        "That's enough — hand back",
                    ],
                },
                Turn {
                    steps: vec![
                        Step::Think(
                            "Three sites, and the test writer is still going in the background. I'll hand back so the parent keeps a lean context.",
                        ),
                        Step::Tool {
                            name: "grep",
                            hint: "jwt.verify across the workspace",
                        },
                        Step::Say(
                            "That's the set: middleware (migrated), handshake.ts (still inline), and the expired-token helper. The test writer is finishing in the background — I'll return the remaining sites and leave that running.",
                        ),
                        Step::Wait(500),
                        Step::Done {
                            summary: "Three jwt.verify sites: middleware (migrated), handshake.ts, and the expired-token test helper.",
                        },
                    ],
                    follow_ups: vec![
                        "Add tests for the new module",
                        "Migrate handshake.ts next",
                    ],
                },
            ]),
            ..AgentNode::new("Explore call sites", true, Status::Working)
        },
        // Finished — inlined in the parent transcript, omitted from the live picker.
        AgentNode {
            tools: pick_tools(&["read_file"]),
            skills: pick_skills(&["docs", "release"]),
            ..AgentNode::new("Scan changelog", false, Status::Done)
        },
    ];
    // Routing starts on the live explorer; the document is still the parent thread.
    refactor_session.focus = vec![0];
    sessions.push(refactor_session);

    // 2. Waiting (red) — the agent asked a question and is parked on the answer.
    let mut onboarding = Vec::new();
    seed_exchange(
        &mut onboarding,
        "We need an onboarding flow for new users. Can you build it?",
        "\"Onboarding\" could mean a product tour, a dismissible checklist, or a full multi-step wizard, and the persistence story differs a lot between them. Before I write any code: should this be a wizard, a tour, or a checklist — and should progress live in localStorage or on the user record?",
        6,
    );
    sessions.push(session(
        "Build the onboarding flow",
        "Waiting on the shape decision",
        "acme/dashboard",
        Status::Waiting,
        onboarding,
        vec![
            Turn {
                steps: vec![
                    Step::Think(
                        "They've picked a direction, so I can commit to the routing and persistence and lay out the step machine.",
                    ),
                    Step::Say(
                        "Good — that settles the two decisions that drive everything else. I'll scaffold a dedicated /onboarding/:step route so each step is linkable and the back button behaves.",
                    ),
                    Step::Wait(1600),
                    Step::Say(
                        "Progress writes to the user record on each step transition, so a refresh or a different device resumes exactly where you left off. Starting on the route shell and the step machine now; I'll come back before touching the schema.",
                    ),
                ],
                follow_ups: vec![
                    "Start with the route shell",
                    "Add a progress indicator per step",
                ],
            },
        ],
        &[
            "Make it a multi-step wizard, stored on the user record",
            "A dismissible checklist in localStorage",
        ],
    ));

    // 3. Done (green) — a long orchestration-flavoured turn, good for queuing
    //    a message mid-run and watching where it lands.
    let mut release = Vec::new();
    seed_exchange(
        &mut release,
        "I want to ship the checkout rewrite this afternoon. Seven tests are failing and I haven't written the changelog.",
        "None of that has to happen in sequence. I can triage the failing tests, draft the changelog from the commit log, and keep a dev server up — say the word and I'll fan the release prep out.",
        7,
    );
    sessions.push(session(
        "Ship the checkout rewrite",
        "Triage, changelog, and a dev server",
        "acme/storefront",
        Status::Done,
        release,
        vec![
            Turn {
                steps: vec![
                    Step::Think(
                        "The test triage is on the critical path — I can't summarise the branch without it — so I'll do that first. The changelog can run from the commit log alone, and the dev server just needs to stay up.",
                    ),
                    Step::Say("Starting the test triage — re-running the seven failing specs to separate real breaks from flakes."),
                    Step::Wait(2200),
                    Step::Say(
                        "Five of the seven are timing flakes in the tax suite. The two real failures both bisect to a91f2c0 — the currency refactor dropped minor-unit rounding, so coupon and address fail on any non-integer total.",
                    ),
                    Step::Wait(1800),
                    Step::Say(
                        "Changelog drafted from v1.9.4..HEAD: 214 commits grouped into six sections, with eleven breaking changes flagged in the checkout API. Dev server is up on http://localhost:5173.",
                    ),
                    Step::Wait(1500),
                    Step::Say(
                        "So the release is one fix away: restore toMinorUnits() in the coupon path, re-run the two deterministic specs, and ship. Want me to make that change?",
                    ),
                    // Park on the user: the sidebar dot goes red until you reply.
                    Step::AwaitUser,
                ],
                follow_ups: vec![
                    "Make the rounding fix",
                    "Keep watching the flaky tax test",
                ],
            },
            // Accepting the fix applies the edit live.
            Turn {
                steps: vec![
                    Step::Say("Restoring the rounding helper in the coupon path."),
                    Step::Wait(1500),
                    Step::Edit {
                        path: "src/checkout/coupon.ts",
                        hunk: COUPON_ROUNDING_EDIT,
                    },
                    Step::Say(
                        "Re-ran the two deterministic specs — both green. The checkout suite is clean, so you're clear to ship.",
                    ),
                ],
                follow_ups: vec!["Open the release PR", "Draft the ship note"],
            },
        ],
        &[
            "Start the release prep",
            "Just tell me which tests are failing",
        ],
    ));

    // 4. Idle (grey) — a fresh session with nothing said yet.
    sessions.push(new_session());

    sessions
}

/// A blank session, as created by the "new session" action.
pub fn new_session() -> Session {
    session(
        "New session",
        "No messages yet",
        "acme/dashboard",
        Status::Idle,
        Vec::new(),
        vec![Turn {
            steps: vec![
                Step::Think(
                    "A fresh session with no prior context — I should say what I can help with before committing to a plan.",
                ),
                Step::Say(
                    "This is a UI demo, so I'm working from a script rather than a live model.\n\nThe sidebar sessions each show a different resting state — one done, one waiting on a decision, one finished a long run. Try typing while a turn is working: your message queues above the composer, and Enter escalates it from \"send when the turn finishes\" to \"cut in at the next step\" to \"stop the agent and send now\".",
                ),
                Step::Wait(900),
                Step::Say(
                    "Pick a model and effort from the controls under the input. Higher effort visibly takes longer and shows a reasoning pass; the lowest answers directly.",
                ),
            ],
            follow_ups: vec!["Show me how queuing works", "What can this demo do?"],
        }],
        &[
            "What does this repository do?",
            "Show me how message queuing works",
            "Find the slowest test in the suite",
        ],
    )
}

/// The turn played when a session's script is exhausted: a short reminder that
/// the responses are simulated.
pub fn fallback_turn() -> Turn {
    Turn {
        steps: vec![
            Step::Wait(500),
            Step::Say(
                "This is a UI demo, so I'm replying from a script rather than a live model.\n\nEverything you're seeing is the interaction design: streaming output, the sidebar status dots, model and effort selection, sticky user messages, and the message queue with its three release points.",
            ),
        ],
        follow_ups: vec![],
    }
}
