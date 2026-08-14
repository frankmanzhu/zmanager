//! Shared hosted-service wire profile.
//!
//! The enrollment and certificate-lifecycle clients historically shipped two
//! identical profile enums (CR-128). Both clients talk to the same hosted
//! service, so the profile is shared; the per-profile request-body shapes
//! remain per-operation in each client, and the `LocalStagingServer` profile
//! is deliberately not refactored further — CR-076 defers standardizing its
//! wire format until the staging service runs the production code.

/// Which hosted-service wire profile a client speaks.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TzapWireProfile {
    /// The specification wire format.
    Spec,
    /// The local staging server's wire format.
    LocalStagingServer,
}
