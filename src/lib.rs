//! redoxide — an on-demand Minecraft reverse proxy that keeps the server
//! container stopped until a player actually connects.
//!
//! The binary in `src/main.rs` wires these modules together; the library
//! target exists so integration tests (see `tests/`) can reuse the wire
//! protocol helpers instead of re-implementing them.

pub mod config;
pub mod docker;
pub mod protocol;
pub mod proxy;
pub mod state;
pub mod status;
pub mod version_cache;
