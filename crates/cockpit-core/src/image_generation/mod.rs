//! Dedicated image-generation adapters.
//!
//! Each adapter owns the exact wire contract, discovery, routing, pricing, and
//! response parsing for one provider's direct Image API. The per-provider
//! `adapters` modules are UI-free pure request/response logic: they produce
//! bounded read-only request descriptions and parse already-bounded responses.
//! Credentials, pinned-connector egress, and redirect handling live in the
//! production transports (see [`transport`] for the shared outcome/error
//! vocabulary those transports report); the job/artifact foundation
//! (`crate::image_generation_job`) owns immutable plans, attempts, artifacts,
//! spend, and effect recovery.

pub mod adapters;
pub mod transport;
