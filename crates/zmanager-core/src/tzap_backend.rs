//! TZAP backend facade.
//!
//! The implementation lives in the `tzap` module tree under `src/tzap/`.
//! This module re-exports it so historical `zmanager_core::tzap_backend::...`
//! paths keep working without caller changes.

pub use crate::tzap::*;
