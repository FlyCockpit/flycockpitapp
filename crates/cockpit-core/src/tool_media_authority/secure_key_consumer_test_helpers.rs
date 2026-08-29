//! Test helpers for the composite consumer reconciler — minimal fakes
//! that mirror the production routing without a real DB.

#![cfg(test)]

use crate::secure_key::{ConsumerReconciler, FailClosedReconciler, SecureKeyError};

/// A probe that always fails closed (delegates to `FailClosedReconciler`).
pub struct FailClosedProbe;

impl ConsumerReconciler for FailClosedProbe {
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError> {
        FailClosedReconciler.consumer_exists(kind, id)
    }
}

/// A map-based probe that returns a canned answer for the
/// `tool_media_subject_binding` kind.
pub struct MapReconcilerProbe {
    tool_media_exists: bool,
}

impl MapReconcilerProbe {
    pub fn with_tool_media_kind(exists: bool) -> Self {
        Self {
            tool_media_exists: exists,
        }
    }
}

impl ConsumerReconciler for MapReconcilerProbe {
    fn consumer_exists(&self, kind: &str, _id: &str) -> Result<bool, SecureKeyError> {
        if kind == crate::tool_media_authority::TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND {
            Ok(self.tool_media_exists)
        } else {
            FailClosedReconciler.consumer_exists(kind, _id)
        }
    }
}

/// A two-arm composite probe mirroring `CompositeConsumerReconciler`.
pub struct CompositeProbe<A: ConsumerReconciler, B: ConsumerReconciler> {
    external: A,
    tool_media: B,
}

impl<A: ConsumerReconciler, B: ConsumerReconciler> CompositeProbe<A, B> {
    pub fn new(external: A, tool_media: B) -> Self {
        Self {
            external,
            tool_media,
        }
    }
}

impl<A: ConsumerReconciler, B: ConsumerReconciler> ConsumerReconciler for CompositeProbe<A, B> {
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError> {
        match kind {
            crate::tool_media_authority::TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND => {
                self.tool_media.consumer_exists(kind, id)
            }
            _ => self.external.consumer_exists(kind, id),
        }
    }
}
