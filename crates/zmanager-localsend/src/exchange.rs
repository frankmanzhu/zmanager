//! Application-level "send, receiver processes, receiver pushes a
//! correlated response back" workflows, built entirely from the ordinary
//! push primitives in [`crate::registry`] — no new wire protocol, no pull
//! primitive. See `zmanager/implementation-docs/tzap-contact-sync-design.md`
//! for the server-anchored sync design this complements (that one matters
//! when devices aren't co-located; this one is for "both devices are here,
//! right now").

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A recognized exchange payload, sent as an ordinary file in a LocalSend
/// push. `session_correlation_id` lets the original sender auto-accept the
/// matching reply from the same peer without a second manual confirmation —
/// see the module-level exchange flow this backs, described in the crate's
/// implementation plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeEnvelope {
    pub exchange_type: ExchangeType,
    pub session_correlation_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeType {
    ContactSyncRequest,
    ContactSyncResponse,
}

pub const EXCHANGE_FILE_SUFFIX: &str = ".tzap-exchange.json";

/// One contact record as carried in a sync exchange. Mirrors the shape of
/// `TzapContactRecord` in `zmanager-core`'s local identity store, plus the
/// two fields a peer-to-peer merge needs that the local-only record doesn't:
/// an explicit `deleted` tombstone, and `updated_at_unix_seconds` as the
/// single "which copy is newer" signal for merge, distinct from
/// `accepted_at_unix_seconds` which never changes once a contact is first
/// accepted.
///
/// **Known limitation, accepted deliberately**: `updated_at_unix_seconds` is
/// client wall-clock time. Two-device, in-person sync has no third party to
/// assign an authoritative ordering the way the server-anchored design does
/// (see the doc referenced above) — clock skew between the two devices can
/// in principle make a genuinely later edit lose to an earlier one. Fine for
/// a first version of a low-stakes contact-list merge; not fine to silently
/// forget as an oversight later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncableContact {
    pub contact_id: String,
    pub payload: Value,
    pub updated_at_unix_seconds: u64,
    #[serde(default)]
    pub deleted: bool,
}

/// Merges two contact lists (typically "my local list" and "the list I just
/// received from my other device") into one, per `contact_id`: the record
/// with the later `updated_at_unix_seconds` wins outright, including a
/// tombstone (`deleted: true`) winning over an active record if it's newer.
/// A contact present on only one side is kept as-is (a pure union for
/// disjoint additions — the common case when two devices each independently
/// added different people since they last synced).
#[must_use]
pub fn merge_contact_lists(local: &[SyncableContact], remote: &[SyncableContact]) -> Vec<SyncableContact> {
    use std::collections::HashMap;

    let mut merged: HashMap<String, SyncableContact> = HashMap::with_capacity(local.len().max(remote.len()));
    for contact in local.iter().chain(remote.iter()) {
        merged
            .entry(contact.contact_id.clone())
            .and_modify(|existing| {
                if contact.updated_at_unix_seconds >= existing.updated_at_unix_seconds {
                    *existing = contact.clone();
                }
            })
            .or_insert_with(|| contact.clone());
    }
    let mut result: Vec<SyncableContact> = merged.into_values().collect();
    result.sort_by(|a, b| a.contact_id.cmp(&b.contact_id));
    result
}

/// Drops tombstones from a merged list — the shape a UI should actually
/// render, once the merge itself is done and the deletion has been recorded.
#[must_use]
pub fn active_contacts(merged: &[SyncableContact]) -> Vec<&SyncableContact> {
    merged.iter().filter(|contact| !contact.deleted).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(id: &str, updated_at: u64, deleted: bool) -> SyncableContact {
        SyncableContact { contact_id: id.to_owned(), payload: serde_json::json!({"display_name": id}), updated_at_unix_seconds: updated_at, deleted }
    }

    #[test]
    fn disjoint_lists_union_to_the_sum_of_both() {
        // Desktop added A, B. Mobile independently added C, D, E. This is
        // the exact scenario from the design discussion: end state is 5.
        let desktop = vec![contact("a", 1, false), contact("b", 2, false)];
        let mobile = vec![contact("c", 3, false), contact("d", 4, false), contact("e", 5, false)];

        let merged = merge_contact_lists(&desktop, &mobile);

        assert_eq!(merged.len(), 5);
        let ids: Vec<&str> = merged.iter().map(|c| c.contact_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn a_newer_edit_wins_the_conflict() {
        let local = vec![contact("a", 10, false)];
        let remote = vec![contact("a", 20, false)];

        let merged = merge_contact_lists(&local, &remote);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].updated_at_unix_seconds, 20);
    }

    #[test]
    fn an_older_edit_does_not_overwrite_a_newer_one() {
        let local = vec![contact("a", 20, false)];
        let remote = vec![contact("a", 10, false)];

        let merged = merge_contact_lists(&local, &remote);

        assert_eq!(merged[0].updated_at_unix_seconds, 20);
    }

    #[test]
    fn deletion_after_add_propagates_as_a_tombstone() {
        // Add contact A, then later delete it. A device that only saw the
        // add would otherwise resurrect it on merge if the tombstone lost.
        let added = vec![contact("a", 1, false)];
        let deleted = vec![contact("a", 2, true)];

        let merged = merge_contact_lists(&added, &deleted);

        assert_eq!(merged.len(), 1);
        assert!(merged[0].deleted);
        assert!(active_contacts(&merged).is_empty());
    }

    #[test]
    fn a_stale_add_cannot_resurrect_a_newer_deletion() {
        // Order shouldn't matter, only timestamps: pass the newer tombstone
        // as `local` this time.
        let deleted = vec![contact("a", 5, true)];
        let stale_add = vec![contact("a", 3, false)];

        let merged = merge_contact_lists(&deleted, &stale_add);

        assert!(merged[0].deleted);
    }

    #[test]
    fn merge_is_symmetric() {
        let left = vec![contact("a", 1, false), contact("b", 5, false)];
        let right = vec![contact("a", 2, false), contact("c", 1, false)];

        let forward = merge_contact_lists(&left, &right);
        let backward = merge_contact_lists(&right, &left);

        assert_eq!(forward, backward);
    }
}
