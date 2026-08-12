//! Online identity and sharing surface (gated behind the `auth` feature).
//!
//! Everything that talks to hosted TZAP services, manages local identity
//! material, or signs/verifies TZAP documents lives here. The crate root
//! re-exports the public modules (so existing `zmanager_core::auth_client`
//! style paths keep working) and privately re-exports the helpers that the
//! modules share. With `--no-default-features` this whole subtree is absent,
//! leaving the offline core.

pub mod auth_client;
pub mod certificate_lifecycle;
pub mod contact_card;
pub mod crl;
pub mod device_identity;
pub mod document_envelope;
pub mod document_signing;
pub mod document_verification;
pub mod enrollment_client;
pub mod identity_catalog;
pub mod jcs;
pub mod local_identity_store;
pub mod local_tzap_service;
pub mod p256_signature;
pub mod status_client;
pub mod tzap_service;
pub mod tzap_service_auth;

// Crate-visible helpers (the crate root re-exports them privately so the
// historical `crate::http_client`-style paths inside auth keep working).
pub(crate) mod http_client;
pub(crate) mod identity_migration;
pub(crate) mod json_util;
