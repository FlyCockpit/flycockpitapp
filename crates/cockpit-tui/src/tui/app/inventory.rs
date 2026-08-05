//! Daemon-backed inventory snapshot consumption for the TUI.
//!
//! One GetInventoryBundle RPC supplies agents, models, and selected-agent
//! skills. Generation floors, invalidation epochs, and in-flight refresh
//! coalescing are pure reducers so the event loop never blocks on discovery.

#![allow(dead_code)] // public reducer API exercised by inventory_tests and App wiring

use cockpit_core::daemon::proto::{AgentSummary, ModelSummary, SkillSummary};
use uuid::Uuid;

/// Authoritative inventory projection for one selected session/agent.
#[derive(Debug, Clone)]
pub struct InventorySnapshot {
    pub selected_agent: String,
    pub agents: Vec<AgentSummary>,
    pub models: Vec<ModelSummary>,
    pub skills: Vec<SkillSummary>,
    pub session_generation: u64,
    pub config_generation: u64,
    pub inventory_generation: u64,
}

/// Local monotonic knowledge of accepted generations for one attached session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GenerationFloor {
    pub session_generation: u64,
    pub config_generation: Option<u64>,
    pub inventory_generation: Option<u64>,
}

/// Identity tuple that must remain current for a response to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryIdentity {
    pub client_instance_id: Uuid,
    pub connection_epoch: u64,
    pub session_id: Uuid,
    pub selected_agent: String,
    pub refresh_generation: u64,
    pub invalidation_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdvanceRequirements {
    pub must_advance_config: bool,
    pub must_advance_inventory: bool,
}

/// Captured at request start; compared against the live state on completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryRequestTicket {
    pub identity: InventoryIdentity,
    pub floors: GenerationFloor,
    pub advance: AdvanceRequirements,
    /// True when this refresh is explicit user refresh or selected-agent change
    /// (equal config/inventory triple is allowed when no MustAdvance is pending).
    pub allow_equal_generations: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryAvailability {
    /// Not yet attached or floors not bootstrapped.
    Unavailable,
    /// Authoritative empty collections from a successful bundle.
    Empty,
    /// Authoritative non-empty snapshot.
    Ready,
}

#[derive(Debug, Clone, Default)]
pub struct InventoryState {
    pub identity: Option<InventoryIdentity>,
    pub floors: GenerationFloor,
    pub advance: AdvanceRequirements,
    pub invalidation_epoch: u64,
    pub refresh_generation: u64,
    pub snapshot: Option<InventorySnapshot>,
    pub in_flight: Option<InventoryRequestTicket>,
    pub dirty: bool,
    pub last_notice: Option<String>,
}

impl InventoryState {
    pub fn availability(&self) -> InventoryAvailability {
        match &self.snapshot {
            None => InventoryAvailability::Unavailable,
            Some(snap)
                if snap.agents.is_empty() && snap.models.is_empty() && snap.skills.is_empty() =>
            {
                InventoryAvailability::Empty
            }
            Some(_) => InventoryAvailability::Ready,
        }
    }

    /// Clear floors/snapshot/dirty/in-flight on detach or session switch.
    pub fn clear_for_session_switch(&mut self) {
        self.floors = GenerationFloor::default();
        self.advance = AdvanceRequirements::default();
        self.snapshot = None;
        self.in_flight = None;
        self.dirty = false;
        self.identity = None;
        self.last_notice = None;
        // refresh_generation and invalidation_epoch keep advancing so late
        // responses from the old session cannot apply.
        self.refresh_generation = self.refresh_generation.saturating_add(1);
        self.invalidation_epoch = self.invalidation_epoch.saturating_add(1);
    }

    /// Begin attach for a session; floors remain unset until first accepted bundle.
    pub fn begin_attach(
        &mut self,
        client_instance_id: Uuid,
        connection_epoch: u64,
        session_id: Uuid,
        selected_agent: String,
        session_generation: u64,
    ) {
        self.clear_for_session_switch();
        self.floors.session_generation = session_generation;
        self.identity = Some(InventoryIdentity {
            client_instance_id,
            connection_epoch,
            session_id,
            selected_agent,
            refresh_generation: self.refresh_generation,
            invalidation_epoch: self.invalidation_epoch,
        });
    }

    /// Capture a new in-flight refresh ticket. Replaces any previous in-flight
    /// ticket (coalesce) without clearing dirty.
    pub fn start_refresh(
        &mut self,
        selected_agent: String,
        allow_equal_generations: bool,
    ) -> Option<InventoryRequestTicket> {
        let mut identity = self.identity.clone()?;
        self.refresh_generation = self.refresh_generation.saturating_add(1);
        identity.selected_agent = selected_agent;
        identity.refresh_generation = self.refresh_generation;
        identity.invalidation_epoch = self.invalidation_epoch;
        if let Some(current) = self.identity.as_mut() {
            current.selected_agent = identity.selected_agent.clone();
            current.refresh_generation = identity.refresh_generation;
            current.invalidation_epoch = identity.invalidation_epoch;
        }
        let ticket = InventoryRequestTicket {
            identity,
            floors: self.floors,
            advance: self.advance,
            allow_equal_generations,
        };
        self.in_flight = Some(ticket.clone());
        Some(ticket)
    }

    /// Config/inventory invalidation from a daemon event.
    pub fn on_invalidation(
        &mut self,
        config_generation: Option<u64>,
        inventory_generation: Option<u64>,
    ) {
        self.invalidation_epoch = self.invalidation_epoch.saturating_add(1);
        self.refresh_generation = self.refresh_generation.saturating_add(1);
        if let Some(generation) = config_generation {
            self.floors.config_generation = Some(match self.floors.config_generation {
                Some(floor) => floor.max(generation),
                None => generation,
            });
        } else if self.floors.config_generation.is_some() {
            self.advance.must_advance_config = true;
        }
        if let Some(generation) = inventory_generation {
            self.floors.inventory_generation = Some(match self.floors.inventory_generation {
                Some(floor) => floor.max(generation),
                None => generation,
            });
        } else if self.floors.inventory_generation.is_some() {
            self.advance.must_advance_inventory = true;
        }
        if self.in_flight.is_some() {
            self.dirty = true;
            // Invalidate the in-flight ticket's epoch so its completion is inert.
            self.in_flight = None;
        } else {
            self.dirty = true;
        }
        if let Some(identity) = self.identity.as_mut() {
            identity.invalidation_epoch = self.invalidation_epoch;
            identity.refresh_generation = self.refresh_generation;
        }
    }

    /// Apply a successful bundle response. Returns true when applied.
    pub fn apply_success(
        &mut self,
        ticket: &InventoryRequestTicket,
        bundle: InventorySnapshot,
    ) -> bool {
        if !self.ticket_is_current(ticket) {
            return false;
        }
        if bundle.selected_agent != ticket.identity.selected_agent {
            return false;
        }
        if bundle.session_generation != self.floors.session_generation {
            // Session generation mismatch is always rejected.
            return false;
        }
        if !Self::generations_acceptable(ticket, &bundle) {
            // Stale relative to floors/MustAdvance — keep one replacement pending.
            self.dirty = true;
            self.in_flight = None;
            return false;
        }

        // Bootstrap or raise floors.
        self.floors.config_generation = Some(match self.floors.config_generation {
            None => bundle.config_generation,
            Some(floor) => floor.max(bundle.config_generation),
        });
        self.floors.inventory_generation = Some(match self.floors.inventory_generation {
            None => bundle.inventory_generation,
            Some(floor) => floor.max(bundle.inventory_generation),
        });

        if ticket.advance.must_advance_config
            && bundle.config_generation > ticket.floors.config_generation.unwrap_or(0)
        {
            self.advance.must_advance_config = false;
        } else if !ticket.advance.must_advance_config {
            // no-op
        }
        if ticket.advance.must_advance_inventory
            && bundle.inventory_generation > ticket.floors.inventory_generation.unwrap_or(0)
        {
            self.advance.must_advance_inventory = false;
        }

        // Clear satisfied advance requirements when equal-allow or advanced.
        if !ticket.advance.must_advance_config
            || bundle.config_generation > ticket.floors.config_generation.unwrap_or(0)
        {
            self.advance.must_advance_config = false;
        }
        if !ticket.advance.must_advance_inventory
            || bundle.inventory_generation > ticket.floors.inventory_generation.unwrap_or(0)
        {
            self.advance.must_advance_inventory = false;
        }

        self.snapshot = Some(bundle);
        self.in_flight = None;
        let need_replacement = self.dirty;
        self.dirty = false;
        if need_replacement {
            // Caller schedules exactly one replacement with newest floors.
            self.dirty = true;
        }
        true
    }

    /// Apply a failure. Retains last complete snapshot; surfaces one notice.
    pub fn apply_failure(&mut self, ticket: &InventoryRequestTicket, notice: String) -> bool {
        if !self.ticket_is_current(ticket) {
            return false;
        }
        self.in_flight = None;
        self.last_notice = Some(notice);
        if self.dirty {
            // Keep dirty so one replacement still runs.
        }
        true
    }

    pub fn ticket_is_current(&self, ticket: &InventoryRequestTicket) -> bool {
        let Some(identity) = self.identity.as_ref() else {
            return false;
        };
        ticket.identity.client_instance_id == identity.client_instance_id
            && ticket.identity.connection_epoch == identity.connection_epoch
            && ticket.identity.session_id == identity.session_id
            && ticket.identity.refresh_generation == identity.refresh_generation
            && ticket.identity.invalidation_epoch == self.invalidation_epoch
    }

    fn generations_acceptable(ticket: &InventoryRequestTicket, bundle: &InventorySnapshot) -> bool {
        // Bootstrap: None floors accept any identity-current bundle for config/inventory.
        if let Some(floor) = ticket.floors.config_generation {
            if bundle.config_generation < floor {
                return false;
            }
            if ticket.advance.must_advance_config && bundle.config_generation <= floor {
                return false;
            }
            if !ticket.allow_equal_generations
                && !ticket.advance.must_advance_config
                && bundle.config_generation < floor
            {
                return false;
            }
        }
        if let Some(floor) = ticket.floors.inventory_generation {
            if bundle.inventory_generation < floor {
                return false;
            }
            if ticket.advance.must_advance_inventory && bundle.inventory_generation <= floor {
                return false;
            }
        }
        true
    }

    /// Take dirty replacement flag if a new refresh should be scheduled.
    pub fn take_dirty_replacement(&mut self) -> bool {
        if self.dirty && self.in_flight.is_none() {
            self.dirty = false;
            true
        } else {
            false
        }
    }
}

/// Preserve picker focus by stable item identity after a refresh.
pub fn preserve_focus_by_identity(
    previous_selected: Option<&str>,
    ordered_ids: &[String],
) -> Option<usize> {
    if ordered_ids.is_empty() {
        return None;
    }
    if let Some(id) = previous_selected
        && let Some(idx) = ordered_ids.iter().position(|entry| entry == id)
    {
        return Some(idx);
    }
    Some(0)
}
