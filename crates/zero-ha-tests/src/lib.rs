//! `zero-ha-tests`: integration-test scaffolding for the dual always-on
//! Iran→USA failover leg.
//!
//! Status: **SCAFFOLD**. The scenario tests compile against the [`engine::HaEngine`]
//! trait, but no engine implements it yet — every scenario fails loudly with a
//! `SCAFFOLD` panic until the routing agent wires the real engine via
//! [`wiring::connect`]. No test here fakes a pass against a mock.
//!
//! Runnable today: the unit tests in [`metrics`] (`cargo test --lib`).

pub mod engine;
pub mod metrics;
pub mod rig;
pub mod wiring;
