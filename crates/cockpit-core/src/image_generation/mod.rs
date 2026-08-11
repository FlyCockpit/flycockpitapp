//! Dedicated image-generation adapters.
//!
//! Each adapter owns the exact wire contract, discovery, routing, pricing, and
//! response parsing for one provider's direct Image API. The modules here are
//! UI-free and transport-free: they produce bounded read-only request
//! descriptions and parse already-bounded responses. The runtime registry
//! (`crate::image_generation_runtime`) owns transport, credentials, and
//! redirect handling; the job/artifact foundation (`crate::image_generation_job`)
//! owns immutable plans, attempts, artifacts, spend, and effect recovery.

pub mod adapters;
