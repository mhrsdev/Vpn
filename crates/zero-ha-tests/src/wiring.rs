//! Engine wiring point.
//!
//! [`connect`] returns the real dual always-on engine: [`crate::rig::RigEngine`],
//! a loopback-pair rig driving the REAL [`zero_observatory::TransportTable`]
//! selection/failover machinery over real TCP/UDP loopback sockets. See
//! [`crate::rig`] for the architecture and the documented simulations.
//!
//! The handle is `Arc`-backed and cheaply cloneable: scenarios that need two
//! handles to the same engine (e.g. `long_download`'s transfer task) clone
//! the `Arc`. Each `connect()` call builds a FRESH, isolated rig (ephemeral
//! ports), so parallel scenarios never interfere.

use crate::engine::HaEngine;
use crate::rig::RigEngine;
use std::fmt;
use std::sync::Arc;

/// Why the harness could not obtain an engine.
#[derive(Debug)]
pub enum HarnessError {
    /// The rig failed to build (no runtime context, loopback bind failure…).
    Engine(String),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarnessError::Engine(m) => write!(f, "engine error: {m}"),
        }
    }
}

impl std::error::Error for HarnessError {}

/// Obtain the engine under test: a fresh isolated loopback-pair rig.
///
/// Must be called from within a Tokio runtime (the rig spawns its exit-side
/// and heartbeat tasks). Every scenario test satisfies this.
pub fn connect() -> Result<Arc<dyn HaEngine>, HarnessError> {
    let rig = RigEngine::new().map_err(|e| HarnessError::Engine(e.to_string()))?;
    Ok(Arc::new(rig))
}

/// Test-body helper: returns the engine or panics loudly.
pub fn require_engine(scenario: &'static str) -> Arc<dyn HaEngine> {
    match connect() {
        Ok(e) => e,
        Err(e) => panic!("scenario '{scenario}': {e}"),
    }
}
