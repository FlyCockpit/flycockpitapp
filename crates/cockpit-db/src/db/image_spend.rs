#![allow(clippy::items_after_test_module)]
//! Durable, exactly-once image-generation monetary reservations.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};

use super::Db;

fn sqlite_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| BudgetBlockReason::ArithmeticOverflow.into())
}

fn read_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetPolicy {
    Unconfigured,
    Finite { usd_micros: u64 },
    Unlimited,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finite(limit: u64) -> ImageSpendSettings {
        ImageSpendSettings {
            request: BudgetPolicy::Finite { usd_micros: limit },
            session: BudgetPolicy::Finite { usd_micros: limit },
            project: BudgetPolicy::Finite { usd_micros: limit },
            project_epoch: Some(ProjectEpochPolicy::CalendarMonth {
                time_zone: "UTC".into(),
            }),
        }
    }

    fn keys(plan: &str) -> SpendScopeKeys {
        SpendScopeKeys {
            plan_digest: plan.into(),
            session_id: "session".into(),
            project_key: "project".into(),
            project_epoch_sequence: 1,
        }
    }

    #[tokio::test]
    async fn image_spend_requires_explicit_policy() {
        let db = Db::open_in_memory().unwrap();
        assert!(
            db.reserve_image_spend(
                "r".into(),
                keys("p"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: Some(1)
                }],
                1,
                0
            )
            .await
            .is_err()
        );
        let invalid = ImageSpendSettings::default();
        assert!(
            db.save_image_spend_policy("project".into(), invalid, None, 0)
                .await
                .is_err()
        );
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.resolve_image_spend_epoch("project".into(), 1, "2026-08".into(), 0, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "r".into(),
            keys("p"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(1),
            }],
            1,
            0,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn image_spend_budget_atomic() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.resolve_image_spend_epoch("project".into(), 1, "2026-08".into(), 0, 0)
            .await
            .unwrap();
        let first = db.reserve_image_spend(
            "r1".into(),
            keys("p1"),
            vec![AttemptMaximum {
                attempt_id: "a1".into(),
                usd_micros: Some(6),
            }],
            1,
            0,
        );
        let second = db.reserve_image_spend(
            "r2".into(),
            keys("p2"),
            vec![AttemptMaximum {
                attempt_id: "a2".into(),
                usd_micros: Some(6),
            }],
            1,
            0,
        );
        let (first, second) = tokio::join!(first, second);
        assert_ne!(first.is_ok(), second.is_ok());
        assert!(
            db.reserve_image_spend(
                "overflow".into(),
                keys("p3"),
                vec![
                    AttemptMaximum {
                        attempt_id: "x".into(),
                        usd_micros: Some(u64::MAX)
                    },
                    AttemptMaximum {
                        attempt_id: "y".into(),
                        usd_micros: Some(1)
                    }
                ],
                1,
                0
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn unknown_requires_all_unlimited_and_late_cost_charges_once() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.resolve_image_spend_epoch("project".into(), 1, "2026-08".into(), 0, 0)
            .await
            .unwrap();
        assert!(
            db.reserve_image_spend(
                "unknown".into(),
                keys("p"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: None
                }],
                1,
                0
            )
            .await
            .is_err()
        );
        let unlimited = ImageSpendSettings {
            request: BudgetPolicy::Unlimited,
            session: BudgetPolicy::Unlimited,
            project: BudgetPolicy::Unlimited,
            project_epoch: None,
        };
        db.save_image_spend_policy("project".into(), unlimited, Some(1), 1)
            .await
            .unwrap();
        let reservation = db
            .reserve_image_spend(
                "unknown".into(),
                keys("p"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: None,
                }],
                2,
                0,
            )
            .await
            .unwrap();
        assert!(reservation.cost_unknown);
        assert!(
            db.release_image_spend_before_acceptance("unknown".into(), "proof".into(), 2)
                .await
                .unwrap()
        );
        assert!(
            db.reconcile_image_spend(
                "unknown".into(),
                "a".into(),
                "bill".into(),
                5,
                "evidence".into(),
                3
            )
            .await
            .unwrap()
        );
        assert!(
            !db.reconcile_image_spend(
                "unknown".into(),
                "a".into(),
                "bill".into(),
                5,
                "evidence".into(),
                3
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn policy_versions_preserve_original_epoch_attribution() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.resolve_image_spend_epoch("project".into(), 1, "2026-08".into(), 0, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "old".into(),
            keys("old-plan"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(5),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        let mut changed = finite(10);
        changed.project_epoch = Some(ProjectEpochPolicy::Rolling {
            duration_seconds: 86_400,
            anchor: SavedInstant {
                unix_ms: 1,
                monotonic_sequence: 1,
            },
        });
        db.save_image_spend_policy("project".into(), changed, Some(1), 1)
            .await
            .unwrap();
        assert!(
            db.reserve_image_spend(
                "stale".into(),
                keys("stale"),
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(1)
                }],
                1,
                1
            )
            .await
            .is_err()
        );
        let old = db
            .image_spend_diagnostic("old".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                old.policy_version,
                old.epoch_policy_version,
                old.epoch_sequence
            ),
            (1, 1, 1)
        );
    }

    #[tokio::test]
    async fn overage_creates_debt_and_release_late_cost_does_not_resurrect() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(20), None, 0)
            .await
            .unwrap();
        db.resolve_image_spend_epoch("project".into(), 1, "2026-08".into(), 0, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "over".into(),
            keys("over-plan"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(5),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        db.reconcile_image_spend(
            "over".into(),
            "a".into(),
            "cost".into(),
            7,
            "normalized".into(),
            1,
        )
        .await
        .unwrap();
        let over = db
            .image_spend_diagnostic("over".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                over.state.as_str(),
                over.charged_usd_micros,
                over.debt_usd_micros
            ),
            ("budget_violation", 7, 2)
        );
        assert!(
            db.reserve_image_spend(
                "blocked".into(),
                keys("other"),
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(1)
                }],
                1,
                2
            )
            .await
            .is_err()
        );
        assert!(
            db.resolve_image_spend_debt("over".into(), "reviewed".into(), 3)
                .await
                .unwrap()
        );

        db.reserve_image_spend(
            "released".into(),
            keys("release-plan"),
            vec![
                AttemptMaximum {
                    attempt_id: "c".into(),
                    usd_micros: Some(4),
                },
                AttemptMaximum {
                    attempt_id: "d".into(),
                    usd_micros: Some(4),
                },
            ],
            1,
            4,
        )
        .await
        .unwrap();
        db.release_image_spend_before_acceptance("released".into(), "not-accepted".into(), 5)
            .await
            .unwrap();
        db.reconcile_image_spend(
            "released".into(),
            "c".into(),
            "late".into(),
            3,
            "normalized-late".into(),
            6,
        )
        .await
        .unwrap();
        let released = db
            .image_spend_diagnostic("released".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (released.state.as_str(), released.charged_usd_micros),
            ("reconciled", 3)
        );
    }

    #[test]
    fn calendar_epoch_rejects_non_iana_zone_and_derives_membership() {
        let invalid = ProjectEpochPolicy::CalendarMonth {
            time_zone: "Not/AZone".into(),
        };
        assert_eq!(
            invalid.validate(),
            Err(BudgetBlockReason::InvalidProjectEpoch)
        );
        let valid = ProjectEpochPolicy::CalendarMonth {
            time_zone: "America/Chicago".into(),
        };
        let epoch = valid.resolve_epoch(1_775_000_000_000).unwrap();
        assert_eq!(epoch.membership_key, "2026-04@America/Chicago");
    }

    #[tokio::test]
    async fn finite_policy_preserves_full_u64_micros() {
        let db = Db::open_in_memory().unwrap();
        let settings = finite(u64::MAX);
        db.save_image_spend_policy("project".into(), settings, None, 0)
            .await
            .unwrap();
        db.resolve_image_spend_epoch("project".into(), 1, "epoch".into(), 0, 0)
            .await
            .unwrap();
        let reserved = db
            .reserve_image_spend(
                "u64".into(),
                keys("u64-plan"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: Some(u64::MAX),
                }],
                1,
                0,
            )
            .await
            .unwrap();
        assert_eq!(reserved.reserved_usd_micros, Some(u64::MAX));
    }
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self::Unconfigured
    }
}

impl<'de> Deserialize<'de> for BudgetPolicy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Raw {
            Unconfigured,
            Finite { usd_micros: u64 },
            Unlimited,
        }
        match Raw::deserialize(d)? {
            Raw::Unconfigured => Ok(Self::Unconfigured),
            Raw::Finite { usd_micros: 0 } => Err(serde::de::Error::custom(
                "finite image spend budget must be positive",
            )),
            Raw::Finite { usd_micros } => Ok(Self::Finite { usd_micros }),
            Raw::Unlimited => Ok(Self::Unlimited),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedInstant {
    pub unix_ms: i64,
    pub monotonic_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectEpochPolicy {
    CalendarMonth {
        time_zone: String,
    },
    Rolling {
        duration_seconds: u64,
        anchor: SavedInstant,
    },
}

impl ProjectEpochPolicy {
    pub fn validate(&self) -> std::result::Result<(), BudgetBlockReason> {
        match self {
            Self::CalendarMonth { time_zone }
                if time_zone.trim().is_empty()
                    || time_zone.bytes().any(|b| {
                        !(b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'+'))
                    }) =>
            {
                Err(BudgetBlockReason::InvalidProjectEpoch)
            }
            Self::Rolling {
                duration_seconds, ..
            } if !(86_400..=31_622_400).contains(duration_seconds) => {
                Err(BudgetBlockReason::InvalidProjectEpoch)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSpendSettings {
    #[serde(default)]
    pub request: BudgetPolicy,
    #[serde(default)]
    pub session: BudgetPolicy,
    #[serde(default)]
    pub project: BudgetPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_epoch: Option<ProjectEpochPolicy>,
}

impl ImageSpendSettings {
    pub fn validate(&self) -> std::result::Result<(), BudgetBlockReason> {
        if self.request == BudgetPolicy::Unconfigured {
            return Err(BudgetBlockReason::RequestUnconfigured);
        }
        if self.session == BudgetPolicy::Unconfigured {
            return Err(BudgetBlockReason::SessionUnconfigured);
        }
        if self.project == BudgetPolicy::Unconfigured {
            return Err(BudgetBlockReason::ProjectUnconfigured);
        }
        if let Some(epoch) = &self.project_epoch {
            epoch.validate()?;
        }
        if matches!(self.project, BudgetPolicy::Finite { .. }) {
            self.project_epoch
                .as_ref()
                .ok_or(BudgetBlockReason::ProjectEpochUnconfigured)?
                .validate()?;
        }
        Ok(())
    }
    pub fn all_unlimited(&self) -> bool {
        self.request == BudgetPolicy::Unlimited
            && self.session == BudgetPolicy::Unlimited
            && self.project == BudgetPolicy::Unlimited
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetBlockReason {
    RequestUnconfigured,
    SessionUnconfigured,
    ProjectUnconfigured,
    ProjectEpochUnconfigured,
    InvalidProjectEpoch,
    UnknownMaximumWithFinitePolicy,
    ArithmeticOverflow,
    RequestExhausted,
    SessionExhausted,
    ProjectExhausted,
    RequestDebt,
    SessionDebt,
    ProjectDebt,
    PolicyVersionChanged,
    ReservationTerminal,
    EmptyPlan,
}

impl std::fmt::Display for BudgetBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BudgetBlockReason {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendScopeKeys {
    /// Unique immutable request-plan identity, including the request nonce.
    /// Replays retain this digest; a distinct rerun must mint a new digest.
    pub plan_digest: String,
    pub session_id: String,
    pub project_key: String,
    pub project_epoch_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptMaximum {
    pub attempt_id: String,
    pub usd_micros: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendReservation {
    pub reservation_id: String,
    pub reserved_usd_micros: Option<u64>,
    pub cost_unknown: bool,
    pub policy_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendLedgerDiagnostic {
    pub reservation_id: String,
    pub policy_version: u64,
    pub epoch_policy_version: u64,
    pub epoch_sequence: u64,
    pub state: String,
    pub reserved_usd_micros: Option<u64>,
    pub charged_usd_micros: u64,
    pub debt_usd_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentImageSpendPolicy {
    pub settings: ImageSpendSettings,
    pub policy_version: u64,
    pub epoch_policy_version: u64,
    pub epoch_sequence: Option<u64>,
}

impl Db {
    pub async fn current_image_spend_policy(
        &self,
        project_key: String,
    ) -> Result<Option<CurrentImageSpendPolicy>> {
        self.read(move |conn| conn.query_row("SELECT p.settings_json,p.version,p.epoch_policy_version,(SELECT epoch_sequence FROM image_spend_epoch_heads h WHERE h.project_key=p.project_key AND h.epoch_policy_version=p.epoch_policy_version) FROM image_spend_policy_versions p WHERE p.project_key=?1 ORDER BY p.version DESC LIMIT 1",[project_key],|row|Ok(CurrentImageSpendPolicy{settings:serde_json::from_str::<ImageSpendSettings>(&row.get::<_,String>(0)?).map_err(|e|rusqlite::Error::FromSqlConversionFailure(0,rusqlite::types::Type::Text,Box::new(e)))?,policy_version:read_u64(row.get(1)?)?,epoch_policy_version:read_u64(row.get(2)?)?,epoch_sequence:row.get::<_,Option<i64>>(3)?.map(read_u64).transpose()?})).optional().map_err(Into::into)).await
    }
    pub async fn image_spend_diagnostic(
        &self,
        reservation_id: String,
    ) -> Result<Option<SpendLedgerDiagnostic>> {
        self.read(move |conn| conn.query_row("SELECT r.policy_version,r.epoch_policy_version,r.epoch_sequence,r.state,r.reserved_usd_micros,COALESCE((SELECT SUM(e.actual_usd_micros) FROM image_spend_cost_events e WHERE e.reservation_id=r.reservation_id),0),COALESCE(MAX(u.debt_usd_micros),0) FROM image_spend_reservations r LEFT JOIN image_spend_scope_usage u ON u.reservation_id=r.reservation_id WHERE r.reservation_id=?1 GROUP BY r.reservation_id",[&reservation_id],|row| {
            let convert=|v:i64| u64::try_from(v).map_err(|e|rusqlite::Error::FromSqlConversionFailure(0,rusqlite::types::Type::Integer,Box::new(e)));
            Ok(SpendLedgerDiagnostic { reservation_id:reservation_id.clone(),policy_version:convert(row.get(0)?)?,epoch_policy_version:convert(row.get(1)?)?,epoch_sequence:convert(row.get(2)?)?,state:row.get(3)?,reserved_usd_micros:row.get::<_,Option<i64>>(4)?.map(convert).transpose()?,charged_usd_micros:convert(row.get(5)?)?,debt_usd_micros:convert(row.get(6)?)? })
        }).optional().map_err(Into::into)).await
    }
    /// Resolve a caller-derived calendar/rolling membership to a durable,
    /// monotonic sequence. A changed wall-clock label can only advance; it can
    /// never select an older sequence after clock rollback.
    pub async fn resolve_image_spend_epoch(
        &self,
        project_key: String,
        epoch_policy_version: u64,
        membership_key: String,
        interval_start_ms: i64,
        resolved_at_ms: i64,
    ) -> Result<u64> {
        let epoch_policy_version_sql = sqlite_u64(epoch_policy_version)?;
        self.transaction(move |conn| {
            let current: Option<(i64,String,i64)> = conn.query_row("SELECT epoch_sequence,membership_key,interval_start_ms FROM image_spend_epoch_heads WHERE project_key=?1 AND epoch_policy_version=?2",params![project_key,epoch_policy_version_sql],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((sequence,current_key,current_start))=current {
                if current_key == membership_key { return u64::try_from(sequence).context("negative epoch sequence"); }
                if interval_start_ms <= current_start { bail!("clock rollback cannot reopen an image spend epoch"); }
                let next=sequence.checked_add(1).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
                conn.execute("UPDATE image_spend_epoch_heads SET epoch_sequence=?3,membership_key=?4,interval_start_ms=?5,resolved_at_ms=?6 WHERE project_key=?1 AND epoch_policy_version=?2 AND epoch_sequence=?7",params![project_key,epoch_policy_version_sql,next,membership_key,interval_start_ms,resolved_at_ms,sequence])?;
                return u64::try_from(next).context("negative epoch sequence");
            }
            conn.execute("INSERT INTO image_spend_epoch_heads(project_key,epoch_policy_version,epoch_sequence,membership_key,interval_start_ms,resolved_at_ms) VALUES(?1,?2,1,?3,?4,?5)",params![project_key,epoch_policy_version_sql,membership_key,interval_start_ms,resolved_at_ms])?;
            Ok(1)
        }).await
    }
    /// Save a reviewed policy. Every save creates a new immutable version;
    /// ledger rows retain their original version and resolved epoch.
    pub async fn save_image_spend_policy(
        &self,
        project_key: String,
        settings: ImageSpendSettings,
        expected_current_version: Option<u64>,
        saved_at_ms: i64,
    ) -> Result<u64> {
        settings.validate().map_err(anyhow::Error::new)?;
        let json = serde_json::to_string(&settings)?;
        self.transaction(move |conn| {
            let current: Option<(u64,String,u64)> = conn.query_row("SELECT version,settings_json,epoch_policy_version FROM image_spend_policy_versions WHERE project_key=?1 ORDER BY version DESC LIMIT 1", [&project_key], |r| Ok((read_u64(r.get(0)?)?,r.get(1)?,read_u64(r.get(2)?)?))).optional()?;
            if current.as_ref().map(|v|v.0) != expected_current_version { return Err(BudgetBlockReason::PolicyVersionChanged.into()); }
            let version = current.as_ref().map_or(1, |v| v.0.checked_add(1).expect("policy version overflow"));
            let previous_epoch = current.as_ref().and_then(|v| serde_json::from_str::<ImageSpendSettings>(&v.1).ok()).and_then(|s|s.project_epoch);
            let epoch_policy_version = current.as_ref().map_or(1, |v| if previous_epoch == settings.project_epoch { v.2 } else { v.2.checked_add(1).expect("epoch policy version overflow") });
            conn.execute("INSERT INTO image_spend_policy_versions(project_key,version,epoch_policy_version,settings_json,saved_at_ms) VALUES(?1,?2,?3,?4,?5)", params![project_key, sqlite_u64(version)?, sqlite_u64(epoch_policy_version)?, json, saved_at_ms])?;
            Ok(version)
        }).await
    }

    /// Atomically reserve the checked conservative sum at request, session,
    /// and resolved project-epoch scope before any provider contact.
    pub async fn reserve_image_spend(
        &self,
        reservation_id: String,
        keys: SpendScopeKeys,
        attempts: Vec<AttemptMaximum>,
        expected_policy_version: u64,
        created_at_ms: i64,
    ) -> Result<SpendReservation> {
        self.transaction(move |conn| {
            if let Some((existing,state,plan,session,project)) = conn.query_row("SELECT reserved_usd_micros,cost_unknown,policy_version,state,plan_digest,session_id,project_key FROM image_spend_reservations WHERE reservation_id=?1", [&reservation_id], |r| Ok((SpendReservation { reservation_id: reservation_id.clone(), reserved_usd_micros: r.get::<_,Option<i64>>(0)?.map(read_u64).transpose()?, cost_unknown: r.get::<_,i64>(1)? != 0, policy_version: read_u64(r.get(2)?)? },r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?))).optional()? {
                if state != "reserved" { return Err(BudgetBlockReason::ReservationTerminal.into()); }
                if plan != keys.plan_digest || session != keys.session_id || project != keys.project_key || existing.policy_version != expected_policy_version { bail!("reservation replay does not match active immutable plan"); }
                let stored: Vec<(String,Option<i64>)> = { let mut statement=conn.prepare("SELECT attempt_id,maximum_usd_micros FROM image_spend_attempts WHERE reservation_id=?1 ORDER BY attempt_id")?; statement.query_map([&reservation_id],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<rusqlite::Result<_>>()? };
                let mut requested: Vec<_> = attempts.iter().map(|a|(a.attempt_id.clone(),a.usd_micros)).collect(); requested.sort();
                let stored: Vec<_> = stored.into_iter().map(|(id,v)|(id,v.map(u64::try_from).transpose())).map(|(id,v)|Ok((id,v?))).collect::<std::result::Result<_,std::num::TryFromIntError>>()?;
                if stored != requested { bail!("reservation replay attempts do not match immutable plan"); }
                return Ok(existing);
            }
            let current: Option<(u64,String,u64)> = conn.query_row("SELECT version,settings_json,epoch_policy_version FROM image_spend_policy_versions WHERE project_key=?1 ORDER BY version DESC LIMIT 1", [&keys.project_key], |r| Ok((read_u64(r.get(0)?)?,r.get(1)?,read_u64(r.get(2)?)?))).optional()?;
            let (current_version,json,epoch_policy_version)=current.ok_or(BudgetBlockReason::ProjectUnconfigured)?;
            if current_version != expected_policy_version { return Err(BudgetBlockReason::PolicyVersionChanged.into()); }
            let settings: ImageSpendSettings = serde_json::from_str(&json)?;
            settings.validate().map_err(|r| anyhow::anyhow!("{r:?}"))?;
            if attempts.is_empty() {
                return Err(BudgetBlockReason::EmptyPlan.into());
            }
            let unknown = attempts.iter().any(|a| a.usd_micros.is_none());
            if unknown && !settings.all_unlimited() {
                return Err(BudgetBlockReason::UnknownMaximumWithFinitePolicy.into());
            }
            let total = attempts.iter().try_fold(0u64, |sum,a| a.usd_micros.map_or(Ok(sum), |v| sum.checked_add(v).ok_or(BudgetBlockReason::ArithmeticOverflow)))?;
            let total_sql = sqlite_u64(total)?;
            let expected_policy_version_sql = sqlite_u64(expected_policy_version)?;
            let epoch_policy_version_sql = sqlite_u64(epoch_policy_version)?;
            let epoch_sequence_sql = sqlite_u64(keys.project_epoch_sequence)?;
            if matches!(settings.project, BudgetPolicy::Finite { .. }) {
                let head: Option<i64> = conn.query_row("SELECT epoch_sequence FROM image_spend_epoch_heads WHERE project_key=?1 AND epoch_policy_version=?2",params![keys.project_key,epoch_policy_version_sql],|r|r.get(0)).optional()?;
                if head != Some(epoch_sequence_sql) { return Err(BudgetBlockReason::InvalidProjectEpoch.into()); }
            }
            conn.execute("INSERT INTO image_spend_reservations(reservation_id,plan_digest,session_id,project_key,policy_version,epoch_policy_version,epoch_sequence,reserved_usd_micros,cost_unknown,state,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'reserved',?10)", params![reservation_id,keys.plan_digest,keys.session_id,keys.project_key,expected_policy_version_sql,epoch_policy_version_sql,epoch_sequence_sql,if unknown { None } else { Some(total_sql) },unknown,created_at_ms])?;
            for (kind, scope_key, policy) in [("request", keys.plan_digest.as_str(), settings.request), ("session", keys.session_id.as_str(), settings.session), ("project", keys.project_key.as_str(), settings.project)] {
                if let BudgetPolicy::Finite { usd_micros: limit } = policy {
                    let epoch = if kind == "project" { keys.project_epoch_sequence } else { 0 };
                    let epoch_policy = if kind == "project" { epoch_policy_version } else { 0 };
                    let used: i64 = conn.query_row("SELECT COALESCE(SUM(reserved_usd_micros),0) FROM image_spend_scope_usage WHERE scope_kind=?1 AND scope_key=?2 AND (?3!='project' OR (epoch_policy_version=?4 AND epoch_sequence=?5))", params![kind,scope_key,kind,sqlite_u64(epoch_policy)?,sqlite_u64(epoch)?], |r| r.get(0))?;
                    let debt: i64 = conn.query_row("SELECT COALESCE(SUM(debt_usd_micros),0) FROM image_spend_scope_usage WHERE scope_kind=?1 AND scope_key=?2", params![kind,scope_key], |r| r.get(0))?;
                    let reason = match kind { "request" => if debt > 0 { BudgetBlockReason::RequestDebt } else { BudgetBlockReason::RequestExhausted }, "session" => if debt > 0 { BudgetBlockReason::SessionDebt } else { BudgetBlockReason::SessionExhausted }, _ => if debt > 0 { BudgetBlockReason::ProjectDebt } else { BudgetBlockReason::ProjectExhausted } };
                    let used = u64::try_from(used).map_err(|_| BudgetBlockReason::ArithmeticOverflow)?;
                    let projected=used.checked_add(total).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
                    if debt > 0 || projected > limit { return Err(reason.into()); }
                    conn.execute("INSERT INTO image_spend_scope_usage(reservation_id,scope_kind,scope_key,policy_version,epoch_policy_version,epoch_sequence,reserved_usd_micros,charged_usd_micros,debt_usd_micros) VALUES(?1,?2,?3,?4,?5,?6,?7,0,0)", params![reservation_id,kind,scope_key,expected_policy_version_sql,sqlite_u64(epoch_policy)?,sqlite_u64(epoch)?,total_sql])?;
                }
            }
            for attempt in attempts { conn.execute("INSERT INTO image_spend_attempts(reservation_id,attempt_id,maximum_usd_micros) VALUES(?1,?2,?3)",params![reservation_id,attempt.attempt_id,attempt.usd_micros.map(sqlite_u64).transpose()?])?; }
            Ok(SpendReservation { reservation_id, reserved_usd_micros: (!unknown).then_some(total), cost_unknown: unknown, policy_version: expected_policy_version })
        }).await
    }

    /// Apply one authoritative billing identity exactly once. Actual cost is
    /// never capped; overage becomes debt on every affected finite scope.
    pub async fn reconcile_image_spend(
        &self,
        reservation_id: String,
        attempt_id: String,
        cost_identity: String,
        actual_usd_micros: u64,
        evidence_ref: String,
        at_ms: i64,
    ) -> Result<bool> {
        let actual_usd_micros_sql = sqlite_u64(actual_usd_micros)?;
        self.transaction(move |conn| {
            if conn.query_row("SELECT 1 FROM image_spend_cost_events WHERE cost_identity=?1",[&cost_identity],|r|r.get::<_,i64>(0)).optional()?.is_some() { return Ok(false); }
            conn.execute("INSERT INTO image_spend_cost_events(cost_identity,reservation_id,attempt_id,actual_usd_micros,evidence_ref,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![cost_identity,reservation_id,attempt_id,actual_usd_micros_sql,evidence_ref,at_ms])?;
            let (reserved, unknown, prior_state): (Option<i64>,i64,String) = conn.query_row("SELECT reserved_usd_micros,cost_unknown,state FROM image_spend_reservations WHERE reservation_id=?1",[&reservation_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            let charged: i64 = conn.query_row("SELECT COALESCE(SUM(actual_usd_micros),0) FROM image_spend_cost_events WHERE reservation_id=?1",[&reservation_id],|r|r.get(0))?;
            let charged = u64::try_from(charged).context("negative image spend charge")?;
            let resolved: i64=conn.query_row("SELECT COALESCE(SUM(resolved_debt_usd_micros),0) FROM image_spend_debt_resolutions WHERE reservation_id=?1",[&reservation_id],|r|r.get(0))?;
            let debt = if unknown != 0 { 0 } else { charged.saturating_sub(reserved.map(read_u64).transpose()?.unwrap_or(0)).saturating_sub(u64::try_from(resolved).context("negative resolved debt")?) };
            let remaining: i64 = if prior_state == "released" { 0 } else { conn.query_row("SELECT COALESCE(SUM(maximum_usd_micros),0) FROM image_spend_attempts a WHERE reservation_id=?1 AND NOT EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=a.reservation_id AND e.attempt_id=a.attempt_id)",[&reservation_id],|r|r.get(0))? };
            let held = charged.checked_add(u64::try_from(remaining).context("negative remaining maximum")?).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
            conn.execute("UPDATE image_spend_scope_usage SET charged_usd_micros=?2,reserved_usd_micros=?3,debt_usd_micros=?4 WHERE reservation_id=?1",params![reservation_id,sqlite_u64(charged)?,sqlite_u64(held)?,sqlite_u64(debt)?])?;
            conn.execute("UPDATE image_spend_reservations SET state=CASE WHEN ?4='released' AND ?3=0 THEN 'released' WHEN ?2=1 THEN 'reconciled' WHEN ?3>0 THEN 'budget_violation' WHEN EXISTS(SELECT 1 FROM image_spend_attempts a WHERE a.reservation_id=?1 AND NOT EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=a.reservation_id AND e.attempt_id=a.attempt_id)) THEN 'reserved' ELSE 'reconciled' END WHERE reservation_id=?1",params![reservation_id,unknown,sqlite_u64(debt)?,prior_state])?;
            Ok(true)
        }).await
    }

    /// Release only when non-acceptance is proven. Ambiguous acceptance must
    /// retain the reservation for recovery or a late cost event.
    pub async fn release_image_spend_before_acceptance(
        &self,
        reservation_id: String,
        proof_identity: String,
        at_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let changed=conn.execute("UPDATE image_spend_reservations SET state='released',release_proof_identity=?2,released_at_ms=?3 WHERE reservation_id=?1 AND state='reserved'",params![reservation_id,proof_identity,at_ms])?;
            if changed != 0 { conn.execute("UPDATE image_spend_scope_usage SET reserved_usd_micros=charged_usd_micros WHERE reservation_id=?1",[reservation_id])?; }
            Ok(changed != 0)
        }).await
    }

    /// Explicitly acknowledge and clear recorded debt after external billing
    /// reconciliation. This never changes the authoritative charge.
    pub async fn resolve_image_spend_debt(
        &self,
        reservation_id: String,
        resolution_ref: String,
        at_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let amount: i64=conn.query_row("SELECT COALESCE(MAX(debt_usd_micros),0) FROM image_spend_scope_usage WHERE reservation_id=?1",[&reservation_id],|r|r.get(0))?;
            let changed=conn.execute("UPDATE image_spend_scope_usage SET debt_usd_micros=0 WHERE reservation_id=?1 AND debt_usd_micros>0",[&reservation_id])?;
            if changed > 0 { conn.execute("INSERT INTO image_spend_debt_resolutions(reservation_id,resolution_ref,resolved_debt_usd_micros,resolved_at_ms) VALUES(?1,?2,?3,?4)",params![reservation_id,resolution_ref,amount,at_ms])?; }
            Ok(changed > 0)
        }).await
    }
}
