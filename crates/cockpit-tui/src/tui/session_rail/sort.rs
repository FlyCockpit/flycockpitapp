//! Display comparator owned by the rail: favorite first, then live TUI
//! tier, then activity/recency descending, then UUID ascending.

use cockpit_proto::SessionSummary;

/// Tier a session sorts into, top (lowest discriminant) to bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Has active background/loop/timer jobs (daemon-reported).
    ActiveSchedules,
    /// Currently executing a tool call.
    ToolRunning,
    /// Currently waiting on model inference.
    InferenceInProgress,
    /// Durable mid-turn interruption marker.
    Interrupted,
    /// Currently processing a turn (daemon-reported).
    Processing,
    /// Unread: the most recent agent event is newer than the marker.
    Unread,
    /// Read, with a pending question (`open_interrupts > 0`).
    PendingQuestion,
    /// A viewed session with durable activity and no pending work.
    Done,
    /// Read, idle, no pending question.
    Idle,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::ActiveSchedules => "● jobs running",
            Tier::ToolRunning => "● tool running",
            Tier::InferenceInProgress => "● inference",
            Tier::Interrupted => "● interrupted",
            Tier::Processing => "● working",
            Tier::Unread => "● unread",
            Tier::PendingQuestion => "● question pending",
            Tier::Done => "● done",
            Tier::Idle => "idle",
        }
    }

    pub fn label_for(self, summary: &SessionSummary) -> String {
        match self {
            Tier::PendingQuestion if summary.open_interrupts > 0 => {
                format!("● {} pending", summary.open_interrupts)
            }
            _ => self.label().to_string(),
        }
    }

    pub fn color(self) -> ratatui::style::Color {
        use crate::tui::theme::{DISABLED, GOOD, RED, YELLOW};
        match self {
            Tier::ActiveSchedules
            | Tier::ToolRunning
            | Tier::InferenceInProgress
            | Tier::Processing => YELLOW,
            Tier::Interrupted | Tier::Unread | Tier::PendingQuestion => RED,
            Tier::Done => GOOD,
            Tier::Idle => DISABLED,
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Tier::ActiveSchedules
                | Tier::ToolRunning
                | Tier::InferenceInProgress
                | Tier::Processing
        )
    }
}

/// Classify one session into its tier given its live daemon status.
/// `live = (has_active_schedules, processing)`; `None` when the daemon has no
/// live worker — then only the DB-derived tiers apply.
pub fn classify(summary: &SessionSummary, live: Option<(bool, bool)>) -> Tier {
    if let Some((has_schedules, _processing)) = live
        && has_schedules
    {
        return Tier::ActiveSchedules;
    }
    match summary.activity_state {
        Some(cockpit_proto::SessionActivityState::ToolRunning) => {
            return Tier::ToolRunning;
        }
        Some(cockpit_proto::SessionActivityState::InferenceInProgress) => {
            return Tier::InferenceInProgress;
        }
        Some(cockpit_proto::SessionActivityState::Interrupted) => {
            return Tier::Interrupted;
        }
        Some(cockpit_proto::SessionActivityState::PendingQuestion) => {
            return Tier::PendingQuestion;
        }
        Some(cockpit_proto::SessionActivityState::Parked) | None => {}
    }
    if let Some((_has_schedules, processing)) = live
        && processing
    {
        return Tier::Processing;
    }
    if is_unread(summary) {
        return Tier::Unread;
    }
    if summary.open_interrupts > 0 {
        return Tier::PendingQuestion;
    }
    if summary.latest_activity_at_unix_ms.is_some() {
        Tier::Done
    } else {
        Tier::Idle
    }
}

fn is_unread(summary: &SessionSummary) -> bool {
    match summary.latest_activity_at_unix_ms {
        None => false,
        Some(activity) => match summary.last_viewed_at_unix_ms {
            None => true,
            Some(viewed) => activity > viewed,
        },
    }
}

/// Sort `(summary, live)` pairs into display order: favorite first, then
/// live tier, then durable activity/recency descending, then UUID
/// ascending. The database never supplies a live tier.
pub fn tier_sort(
    mut items: Vec<(SessionSummary, Option<(bool, bool)>)>,
) -> Vec<(SessionSummary, Tier)> {
    let mut classified: Vec<(SessionSummary, Tier)> = items
        .drain(..)
        .map(|(s, live)| {
            let tier = classify(&s, live);
            (s, tier)
        })
        .collect();
    classified.sort_by(|a, b| {
        b.0.favorite
            .cmp(&a.0.favorite)
            .then(a.1.cmp(&b.1))
            .then(b.0.last_active_at_unix_ms.cmp(&a.0.last_active_at_unix_ms))
            .then(a.0.session_id.cmp(&b.0.session_id))
    });
    classified
}

pub fn canonical_root(summary: &SessionSummary) -> uuid::Uuid {
    summary
        .compaction_lineage_root_id
        .unwrap_or(summary.session_id)
}
