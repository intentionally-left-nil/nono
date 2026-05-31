//! AWS SigV4 support for nono-proxy.
//!
//! This module provides:
//! - `endpoints`: host-to-service mapping table and region extraction.
//! - `route`: the `AwsRoute` per-route state struct.
//! - `provider`: credential provider construction and caching.
//! - `resolve`: region and service resolution logic.
//! - `sign`: SigV4 request signing.

pub mod endpoints;
pub mod provider;
pub mod resolve;
pub mod route;
pub mod sign;
