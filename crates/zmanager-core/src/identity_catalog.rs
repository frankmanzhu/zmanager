//! Public TZAP identity catalog and purpose-specific secret-store seams.
//!
//! The legacy [`crate::local_identity_store`] remains available for migration
//! and compatibility. New readers should use this module so public metadata
//! never requires hydrating private key bytes.

use crate::local_identity_store::{
    TzapCertificateStatusCacheRecord, TzapContactRecord, TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState,
    TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore,
    TzapLocalIdentityStoreError, TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
};
use crate::secrets::SecretBytes;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const PUBLIC_CATALOG_SCHEMA_VERSION: u64 = 1;
pub const PUBLIC_CATALOG_FILE_SUFFIX: &str = ".identity-catalog.json";

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TzapSecretRef(String);

impl TzapSecretRef {
    /// Creates a new non-discoverable reference for secure-store material.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 24];
        rand::rng().fill_bytes(&mut bytes);
        Self(format!("secret_{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, TzapSecretStoreError> {
        let value = value.into();
        if value.starts_with("secret_") && value.len() > "secret_".len() {
            Ok(Self(value))
        } else {
            Err(TzapSecretStoreError::InvalidReference)
        }
    }
}

impl fmt::Display for TzapSecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzapSecretPurpose {
    SigningKey,
    RecipientKey,
    Session,
}

impl TzapSecretPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SigningKey => "signing_key",
            Self::RecipientKey => "recipient_key",
            Self::Session => "session",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapSecretStoreError {
    Unavailable,
    Locked,
    Denied,
    Corrupt,
    Missing { reference: TzapSecretRef },
    InvalidReference,
}

impl fmt::Display for TzapSecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("secure secret store is unavailable"),
            Self::Locked => f.write_str("secure secret store is locked"),
            Self::Denied => f.write_str("secure secret store access was denied"),
            Self::Corrupt => f.write_str("secure secret store data is corrupt"),
            Self::Missing { reference } => write!(f, "secure secret is missing: {reference}"),
            Self::InvalidReference => f.write_str("secure secret reference is invalid"),
        }
    }
}

impl std::error::Error for TzapSecretStoreError {}

/// Purpose-specific secure material interface. Implementations must not fall
/// back to a plaintext file when the native store is unavailable or locked.
pub trait TzapSecretMaterialStore {
    fn put(&mut self, purpose: TzapSecretPurpose, material: SecretBytes)
    -> Result<TzapSecretRef, TzapSecretStoreError>;

    /// Stores material under a caller-generated reference. This is used by
    /// crash-recoverable catalog transactions: the public catalog can record
    /// the opaque reference before the secret is written, then retry the same
    /// write after an interrupted startup.
    fn put_at(
        &mut self,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
        material: SecretBytes,
    ) -> Result<(), TzapSecretStoreError>;

    fn resolve(
        &self,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
    ) -> Result<SecretBytes, TzapSecretStoreError>;

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError>;
}

#[derive(Debug, Default)]
pub struct InMemoryTzapSecretMaterialStore {
    values: HashMap<(TzapSecretPurpose, TzapSecretRef), SecretBytes>,
}

impl InMemoryTzapSecretMaterialStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TzapSecretMaterialStore for InMemoryTzapSecretMaterialStore {
    fn put(
        &mut self,
        purpose: TzapSecretPurpose,
        material: SecretBytes,
    ) -> Result<TzapSecretRef, TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let reference = TzapSecretRef::generate();
        self.values.insert((purpose, reference.clone()), material);
        Ok(reference)
    }

    fn put_at(
        &mut self,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
        material: SecretBytes,
    ) -> Result<(), TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        self.values.insert((purpose, reference.clone()), material);
        Ok(())
    }

    fn resolve(
        &self,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
    ) -> Result<SecretBytes, TzapSecretStoreError> {
        self.values
            .get(&(purpose, reference.clone()))
            .cloned()
            .ok_or_else(|| TzapSecretStoreError::Missing { reference: reference.clone() })
    }

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError> {
        self.values
            .remove(&(purpose, reference.clone()))
            .map(|_| ())
            .ok_or_else(|| TzapSecretStoreError::Missing { reference: reference.clone() })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicSigningIdentityRecord {
    pub id: String,
    pub local_alias: Option<String>,
    pub certificate_id: Option<String>,
    pub certificate_sha256: Option<String>,
    pub issuer_certificate_sha256: Option<String>,
    pub issuer_key_identifier: Option<String>,
    pub serial_number: Option<String>,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub not_before_unix_seconds: Option<u64>,
    pub not_after_unix_seconds: Option<u64>,
    pub public_signer_id: Option<String>,
    pub public_org_id: Option<String>,
    pub public_device_id: Option<String>,
    pub assurance_level: Option<String>,
    pub sign_device_id: Option<String>,
    /// Sign-device routing carried through from the legacy inventory so the
    /// legacy facade can round-trip it losslessly. Absent on catalogs written
    /// before this field existed.
    #[serde(default)]
    pub sign_device_routing: Option<TzapSignDeviceRouting>,
    /// Creation time of the underlying signing key, carried from the legacy
    /// inventory for the same reason.
    #[serde(default)]
    pub signing_key_created_at_unix_seconds: Option<u64>,
    /// Legacy inventory key id backing this identity, when it came from the
    /// legacy store. Lets the legacy facade reuse the same secret reference
    /// across saves instead of churning refs. Absent on catalogs written
    /// before this field existed.
    #[serde(default)]
    pub legacy_key_id: Option<String>,
    /// Public-metadata fields the legacy inventory carries that the catalog
    /// does not otherwise model; carried for lossless facade round-trips.
    #[serde(default)]
    pub metadata_version: Option<u64>,
    #[serde(default)]
    pub policy_oid: Option<String>,
    pub signing_key_ref: TzapSecretRef,
    pub lifecycle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicRecipientKeyRecord {
    pub id: String,
    pub local_label: Option<String>,
    pub algorithm: String,
    pub public_key_der: Vec<u8>,
    pub fingerprint: String,
    pub private_key_ref: TzapSecretRef,
    pub lifecycle: String,
    pub created_at_unix_seconds: u64,
    pub retired_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicContactRecord {
    pub contact_id: String,
    pub display_name: String,
    pub signing_certificate_sha256: String,
    pub recipient_public_key_fingerprint: String,
    pub recipient_public_key_der: Vec<u8>,
    pub trust_source: String,
    pub verification_state: String,
    pub missing_status_caveat: bool,
    pub contact_card_payload: Value,
    pub accepted_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicStatusCacheRecord {
    pub lookup_id: String,
    pub status: String,
    pub this_update: String,
    pub next_update: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicEmergencyBlocklist {
    pub blocked_root_sha256: Vec<String>,
    pub blocked_issuer_sha256: Vec<String>,
    pub updated_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapIdentityCatalog {
    pub schema_version: u64,
    pub catalog_id: String,
    pub revision: u64,
    pub default_signing_identity_id: Option<String>,
    pub signing_identities: Vec<TzapPublicSigningIdentityRecord>,
    pub recipient_keys: Vec<TzapPublicRecipientKeyRecord>,
    pub contacts: Vec<TzapPublicContactRecord>,
    pub status_cache: Vec<TzapPublicStatusCacheRecord>,
    pub emergency_blocklist: TzapPublicEmergencyBlocklist,
    pub pending_mutations: Vec<PendingMutation>,
}

/// One crash-recoverable catalog transaction that was recorded before its
/// side effects completed.
///
/// The wire format deliberately matches the historical string marker
/// (`legacy-migration-<unix seconds>`), so catalogs written by older versions
/// keep loading after an upgrade.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PendingMutation {
    /// A legacy inventory migration wrote its public catalog first and is
    /// expected to finish copying secret material into the secure store.
    LegacyMigration { started_at_unix_seconds: u64 },
}

impl PendingMutation {
    fn wire_value(&self) -> String {
        match self {
            Self::LegacyMigration { started_at_unix_seconds } => {
                format!("legacy-migration-{started_at_unix_seconds}")
            }
        }
    }
}

impl Serialize for PendingMutation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.wire_value())
    }
}

impl<'de> Deserialize<'de> for PendingMutation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if let Some(started_at) = value.strip_prefix("legacy-migration-") {
            let started_at_unix_seconds =
                started_at.parse().map_err(|_| serde::de::Error::custom("invalid legacy migration marker"))?;
            Ok(Self::LegacyMigration { started_at_unix_seconds })
        } else {
            Err(serde::de::Error::custom(format!("unknown pending mutation marker: {value}")))
        }
    }
}

impl TzapIdentityCatalog {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: PUBLIC_CATALOG_SCHEMA_VERSION,
            catalog_id: format!("catalog_{}", random_identifier()),
            revision: 0,
            default_signing_identity_id: None,
            signing_identities: Vec::new(),
            recipient_keys: Vec::new(),
            contacts: Vec::new(),
            status_cache: Vec::new(),
            emergency_blocklist: TzapPublicEmergencyBlocklist::default(),
            pending_mutations: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), TzapIdentityCatalogError> {
        if self.schema_version != PUBLIC_CATALOG_SCHEMA_VERSION {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field: "schema_version" });
        }
        if self.catalog_id.is_empty() {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field: "catalog_id" });
        }
        validate_unique("signing_identities.id", self.signing_identities.iter().map(|v| v.id.as_str()))?;
        validate_unique("recipient_keys.id", self.recipient_keys.iter().map(|v| v.id.as_str()))?;
        validate_unique("contacts.contact_id", self.contacts.iter().map(|v| v.contact_id.as_str()))?;
        if let Some(default_id) = &self.default_signing_identity_id
            && !self.signing_identities.iter().any(|record| &record.id == default_id)
        {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field: "default_signing_identity_id" });
        }
        for record in &self.signing_identities {
            validate_non_empty("signing_identities.id", &record.id)?;
            validate_non_empty("signing_identities.signing_key_ref", record.signing_key_ref.as_str())?;
            validate_non_empty("signing_identities.lifecycle", &record.lifecycle)?;
        }
        for record in &self.recipient_keys {
            validate_non_empty("recipient_keys.id", &record.id)?;
            validate_non_empty("recipient_keys.algorithm", &record.algorithm)?;
            validate_non_empty("recipient_keys.fingerprint", &record.fingerprint)?;
            validate_non_empty("recipient_keys.private_key_ref", record.private_key_ref.as_str())?;
            if record.public_key_der.is_empty() {
                return Err(TzapIdentityCatalogError::InvalidCatalog { field: "recipient_keys.public_key_der" });
            }
        }
        Ok(())
    }
}

pub trait TzapIdentityCatalogStore {
    fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError>;
    fn save_catalog(
        &mut self,
        account_key: &str,
        expected_revision: Option<u64>,
        catalog: TzapIdentityCatalog,
    ) -> Result<(), TzapIdentityCatalogError>;
    fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError>;
}

#[derive(Debug, Default)]
pub struct InMemoryTzapIdentityCatalogStore {
    catalogs: HashMap<String, TzapIdentityCatalog>,
}

impl InMemoryTzapIdentityCatalogStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TzapIdentityCatalogStore for InMemoryTzapIdentityCatalogStore {
    fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError> {
        Ok(self.catalogs.get(account_key).cloned())
    }

    fn save_catalog(
        &mut self,
        account_key: &str,
        expected_revision: Option<u64>,
        catalog: TzapIdentityCatalog,
    ) -> Result<(), TzapIdentityCatalogError> {
        catalog.validate()?;
        let actual = self.catalogs.get(account_key).map(|value| value.revision);
        if expected_revision != actual {
            return Err(TzapIdentityCatalogError::RevisionConflict { expected: expected_revision, actual });
        }
        self.catalogs.insert(account_key.to_owned(), catalog);
        Ok(())
    }

    fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError> {
        self.catalogs.remove(account_key);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileTzapIdentityCatalogStore {
    root: PathBuf,
}

impl FileTzapIdentityCatalogStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn catalog_path(&self, account_key: &str) -> Result<PathBuf, TzapIdentityCatalogError> {
        if !validate_account_key(account_key) {
            return Err(TzapIdentityCatalogError::InvalidAccountKey);
        }
        Ok(self.root.join(format!("{account_key}{PUBLIC_CATALOG_FILE_SUFFIX}")))
    }
}

/// A catalog lock older than this is assumed to have been abandoned by a
/// crashed writer and is stolen instead of blocking all future saves.
const LOCK_STALE_AFTER_SECONDS: u64 = 30;
/// Maximum stale-lock steal attempts before reporting a concurrent write.
const MAX_LOCK_STEAL_ATTEMPTS: u32 = 3;

/// Acquires the exclusive catalog lock, returning the held file handle.
///
/// A lock left behind by a crashed writer (which never removed it) would
/// otherwise fail every future save with [`TzapIdentityCatalogError::ConcurrentWrite`]
/// forever. When the existing lock is older than [`LOCK_STALE_AFTER_SECONDS`]
/// it is stolen and the acquisition retried; a lock that young is assumed to
/// belong to a live writer, and the write is refused.
fn acquire_catalog_lock(lock_path: &Path) -> Result<fs::File, TzapIdentityCatalogError> {
    let mut steal_attempts = 0u32;
    loop {
        match fs::OpenOptions::new().write(true).create_new(true).open(lock_path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if steal_attempts >= MAX_LOCK_STEAL_ATTEMPTS || !lock_is_stale(lock_path) {
                    return Err(TzapIdentityCatalogError::ConcurrentWrite);
                }
                let _ = fs::remove_file(lock_path);
                steal_attempts += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn lock_is_stale(lock_path: &Path) -> bool {
    fs::metadata(lock_path).is_ok_and(|metadata| {
        metadata.modified().is_ok_and(|modified| {
            SystemTime::now().duration_since(modified).is_ok_and(|age| age.as_secs() >= LOCK_STALE_AFTER_SECONDS)
        })
    })
}

impl TzapIdentityCatalogStore for FileTzapIdentityCatalogStore {
    fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError> {
        let path = self.catalog_path(account_key)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let catalog: TzapIdentityCatalog = serde_json::from_slice(&bytes)?;
        catalog.validate()?;
        Ok(Some(catalog))
    }

    fn save_catalog(
        &mut self,
        account_key: &str,
        expected_revision: Option<u64>,
        catalog: TzapIdentityCatalog,
    ) -> Result<(), TzapIdentityCatalogError> {
        let path = self.catalog_path(account_key)?;
        catalog.validate()?;
        fs::create_dir_all(&self.root)?;
        let lock_path = path.with_extension("lock");
        let _lock = acquire_catalog_lock(&lock_path)?;
        // Check the revision while the lock is held so no writer can commit
        // between validation and the atomic replacement below.
        let actual = self.load_catalog(account_key)?.map(|value| value.revision);
        if expected_revision != actual {
            let _ = fs::remove_file(&lock_path);
            return Err(TzapIdentityCatalogError::RevisionConflict { expected: expected_revision, actual });
        }
        let result = write_catalog_atomically(&path, &catalog);
        let _ = fs::remove_file(lock_path);
        result
    }

    fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError> {
        let path = self.catalog_path(account_key)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Debug)]
pub enum TzapIdentityCatalogError {
    InvalidAccountKey,
    InvalidCatalog { field: &'static str },
    RevisionConflict { expected: Option<u64>, actual: Option<u64> },
    ConcurrentWrite,
    Io(io::ErrorKind),
    Json(String),
    Legacy(TzapLocalIdentityStoreError),
    Secret(TzapSecretStoreError),
}

impl fmt::Display for TzapIdentityCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccountKey => f.write_str("identity catalog account key is invalid"),
            Self::InvalidCatalog { field } => {
                write!(f, "identity catalog field is invalid: {field}")
            }
            Self::RevisionConflict { expected, actual } => {
                write!(f, "identity catalog revision conflict (expected {expected:?}, actual {actual:?})")
            }
            Self::ConcurrentWrite => f.write_str("identity catalog is already being updated"),
            Self::Io(kind) => write!(f, "identity catalog I/O failed: {kind:?}"),
            Self::Json(message) => write!(f, "identity catalog JSON is invalid: {message}"),
            Self::Legacy(error) => write!(f, "legacy identity migration failed: {error}"),
            Self::Secret(error) => write!(f, "secure secret migration failed: {error}"),
        }
    }
}

impl std::error::Error for TzapIdentityCatalogError {}

impl From<io::Error> for TzapIdentityCatalogError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<serde_json::Error> for TzapIdentityCatalogError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<TzapLocalIdentityStoreError> for TzapIdentityCatalogError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Legacy(error)
    }
}

impl From<TzapSecretStoreError> for TzapIdentityCatalogError {
    fn from(error: TzapSecretStoreError) -> Self {
        Self::Secret(error)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TzapLegacyMigrationReport {
    pub migrated: bool,
    pub signing_identity_count: usize,
    pub recipient_key_count: usize,
}

/// Moves legacy private bytes into the injected secure store and writes only
/// public metadata plus opaque references to the new catalog. A completed
/// pre-existing catalog makes the operation a no-op; a catalog marked with a
/// pending migration is resumed from the intact legacy inventory.
pub fn migrate_legacy_inventory(
    legacy_store: &impl TzapLocalIdentityStore,
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    now_unix_seconds: u64,
) -> Result<TzapLegacyMigrationReport, TzapIdentityCatalogError> {
    if let Some(catalog) = catalog_store.load_catalog(account_key)? {
        if has_pending_legacy_migration(&catalog) {
            return resume_pending_migration(legacy_store, catalog_store, secret_store, account_key, catalog);
        }
        return Ok(TzapLegacyMigrationReport {
            migrated: false,
            signing_identity_count: catalog.signing_identities.len(),
            recipient_key_count: catalog.recipient_keys.len(),
        });
    }

    let inventory = legacy_store.load_inventory(account_key)?;
    let (catalog, signing_refs, recipient_refs) = build_catalog_from_legacy(&inventory, now_unix_seconds)?;
    commit_migration(catalog_store, secret_store, account_key, catalog, &inventory, &signing_refs, &recipient_refs)?;

    let catalog = catalog_store
        .load_catalog(account_key)?
        .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.catalog" })?;
    Ok(TzapLegacyMigrationReport {
        migrated: true,
        signing_identity_count: catalog.signing_identities.len(),
        recipient_key_count: catalog.recipient_keys.len(),
    })
}

fn has_pending_legacy_migration(catalog: &TzapIdentityCatalog) -> bool {
    catalog.pending_mutations.iter().any(|mutation| matches!(mutation, PendingMutation::LegacyMigration { .. }))
}

/// Resumes a migration whose public catalog was committed but whose secret
/// store writes did not finish before a crash.
///
/// A catalog is written before its secrets during migration. On a restart,
/// retry the same references from the intact legacy file instead of creating
/// a second set of orphaned keychain entries.
fn resume_pending_migration(
    legacy_store: &impl TzapLocalIdentityStore,
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    mut catalog: TzapIdentityCatalog,
) -> Result<TzapLegacyMigrationReport, TzapIdentityCatalogError> {
    let inventory = legacy_store.load_inventory(account_key)?;
    let signing_by_id = inventory
        .device_signing_keys
        .iter()
        .map(|record| (record.key_id.as_str(), &record.private_key_der))
        .collect::<HashMap<_, _>>();
    let signing_by_certificate = inventory
        .enrolled_certificates
        .iter()
        .map(|record| (record.certificate_id.as_str(), record.signing_key_id.as_str()))
        .collect::<HashMap<_, _>>();
    for identity in &catalog.signing_identities {
        if matches!(
            secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref),
            Err(TzapSecretStoreError::Missing { .. })
        ) {
            let key_id = signing_by_certificate.get(identity.id.as_str()).copied().unwrap_or(identity.id.as_str());
            let material = signing_by_id
                .get(key_id)
                .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "legacy_migration.signing_key_ref" })?;
            secret_store.put_at(TzapSecretPurpose::SigningKey, &identity.signing_key_ref, (*material).clone())?;
        }
    }
    let recipient_by_id = inventory
        .recipient_encryption_keys
        .iter()
        .map(|record| (record.key_id.as_str(), &record.private_key_der))
        .collect::<HashMap<_, _>>();
    for key in &catalog.recipient_keys {
        if matches!(
            secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref),
            Err(TzapSecretStoreError::Missing { .. })
        ) {
            let material = recipient_by_id
                .get(key.id.as_str())
                .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "legacy_migration.recipient_key_ref" })?;
            secret_store.put_at(TzapSecretPurpose::RecipientKey, &key.private_key_ref, (*material).clone())?;
        }
    }
    for identity in &catalog.signing_identities {
        secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
    }
    for key in &catalog.recipient_keys {
        secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
    }
    catalog.pending_mutations.retain(|mutation| !matches!(mutation, PendingMutation::LegacyMigration { .. }));
    let expected_revision = catalog.revision;
    catalog.revision = catalog.revision.saturating_add(1);
    catalog_store.save_catalog(account_key, Some(expected_revision), catalog.clone())?;
    Ok(TzapLegacyMigrationReport {
        migrated: true,
        signing_identity_count: catalog.signing_identities.len(),
        recipient_key_count: catalog.recipient_keys.len(),
    })
}

/// Secret references produced while building a catalog, keyed by legacy
/// record id.
type SecretRefMap = HashMap<String, TzapSecretRef>;

/// Builds the public catalog (and its secret references) from a legacy
/// inventory without writing anything to either store.
///
/// Returns the catalog, the signing-key references, and the recipient-key
/// references, all keyed by legacy record id.
fn build_catalog_from_legacy(
    inventory: &TzapLocalIdentityInventory,
    now_unix_seconds: u64,
) -> Result<(TzapIdentityCatalog, SecretRefMap, SecretRefMap), TzapIdentityCatalogError> {
    let mut signing_refs = HashMap::new();
    let mut recipient_refs = HashMap::new();
    for record in &inventory.device_signing_keys {
        verify_private_matches_fingerprint(&record.private_key_der, &record.public_key_fingerprint)?;
        signing_refs.insert(record.key_id.clone(), TzapSecretRef::generate());
    }
    for record in &inventory.recipient_encryption_keys {
        verify_private_matches_public_key(&record.private_key_der, &record.public_key_der)?;
        recipient_refs.insert(record.key_id.clone(), TzapSecretRef::generate());
    }

    let mut signing_identities = Vec::new();
    let mut certificate_key_ids = HashSet::new();
    for certificate in &inventory.enrolled_certificates {
        let signing_key_ref = signing_refs
            .get(&certificate.signing_key_id)
            .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "enrolled_certificates.signing_key_id" })?
            .clone();
        let backing_key = inventory.device_signing_keys.iter().find(|key| key.key_id == certificate.signing_key_id);
        let signing_key_created_at = backing_key.map(|key| key.created_at_unix_seconds);
        let signing_key_label = backing_key.and_then(|key| key.label.clone());
        certificate_key_ids.insert(certificate.signing_key_id.clone());
        signing_identities.push(TzapPublicSigningIdentityRecord {
            id: certificate.certificate_id.clone(),
            local_alias: signing_key_label,
            certificate_id: Some(certificate.certificate_id.clone()),
            certificate_sha256: Some(certificate.certificate_sha256.clone()),
            issuer_certificate_sha256: Some(certificate.issuer_certificate_sha256.clone()),
            issuer_key_identifier: Some(certificate.issuer_key_identifier.clone()),
            serial_number: Some(certificate.serial_number.clone()),
            certificate_chain_der: std::iter::once(certificate.leaf_certificate_der.clone())
                .chain(certificate.intermediate_chain_der.clone())
                .collect(),
            not_before_unix_seconds: Some(certificate.not_before_unix_seconds),
            not_after_unix_seconds: Some(certificate.not_after_unix_seconds),
            public_signer_id: Some(certificate.public_metadata.public_signer_id.clone()),
            public_org_id: certificate.public_metadata.public_org_id.clone(),
            public_device_id: Some(certificate.public_metadata.public_device_id.clone()),
            assurance_level: Some(certificate.public_metadata.assurance_level.as_str().to_owned()),
            sign_device_id: Some(certificate.sign_device_id.clone()),
            sign_device_routing: Some(certificate.sign_device_routing.clone()),
            signing_key_created_at_unix_seconds: signing_key_created_at,
            legacy_key_id: Some(certificate.signing_key_id.clone()),
            metadata_version: Some(certificate.public_metadata.version),
            policy_oid: Some(certificate.public_metadata.policy_oid.clone()),
            signing_key_ref,
            lifecycle: certificate.state.as_str().to_owned(),
        });
    }
    for key in &inventory.device_signing_keys {
        if !certificate_key_ids.contains(&key.key_id) {
            signing_identities.push(TzapPublicSigningIdentityRecord {
                id: key.key_id.clone(),
                local_alias: key.label.clone(),
                certificate_id: None,
                certificate_sha256: None,
                issuer_certificate_sha256: None,
                issuer_key_identifier: None,
                serial_number: None,
                certificate_chain_der: Vec::new(),
                not_before_unix_seconds: None,
                not_after_unix_seconds: None,
                public_signer_id: None,
                public_org_id: None,
                public_device_id: None,
                assurance_level: None,
                sign_device_id: None,
                sign_device_routing: None,
                signing_key_created_at_unix_seconds: Some(key.created_at_unix_seconds),
                legacy_key_id: None,
                metadata_version: None,
                policy_oid: None,
                signing_key_ref: signing_refs
                    .get(&key.key_id)
                    .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.signing_refs" })?
                    .clone(),
                lifecycle: "pending".to_owned(),
            });
        }
    }

    let recipient_keys = inventory
        .recipient_encryption_keys
        .iter()
        .map(|key| {
            Ok::<_, TzapIdentityCatalogError>(TzapPublicRecipientKeyRecord {
                id: key.key_id.clone(),
                local_label: key.label.clone(),
                algorithm: key.algorithm.clone(),
                public_key_der: key.public_key_der.clone(),
                fingerprint: key.public_key_fingerprint.clone(),
                private_key_ref: recipient_refs
                    .get(&key.key_id)
                    .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.recipient_refs" })?
                    .clone(),
                lifecycle: "active".to_owned(),
                created_at_unix_seconds: key.created_at_unix_seconds,
                retired_at_unix_seconds: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut catalog = TzapIdentityCatalog::empty();
    catalog.revision = 1;
    catalog.signing_identities = signing_identities;
    catalog.recipient_keys = recipient_keys;
    catalog.contacts = inventory
        .contacts
        .iter()
        .map(|contact| {
            let recipient_public_key_der = contact
                .contact_card_payload
                .get("recipient_public_key")
                .and_then(Value::as_str)
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "contacts.recipient_public_key" })?;
            Ok::<_, TzapIdentityCatalogError>(TzapPublicContactRecord {
                contact_id: contact.contact_id.clone(),
                display_name: contact.display_name.clone(),
                signing_certificate_sha256: contact.signing_certificate_sha256.clone(),
                recipient_public_key_fingerprint: contact.recipient_public_key_fingerprint.clone(),
                recipient_public_key_der,
                trust_source: contact.trust_anchor_type.as_str().to_owned(),
                verification_state: contact.verification_state.as_str().to_owned(),
                missing_status_caveat: contact.missing_status_caveat,
                contact_card_payload: contact.contact_card_payload.clone(),
                accepted_at_unix_seconds: contact.accepted_at_unix_seconds,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    catalog.status_cache = inventory
        .certificate_status_cache
        .iter()
        .map(|record| TzapPublicStatusCacheRecord {
            lookup_id: record.certificate_sha256.clone(),
            status: record.status.as_str().to_owned(),
            this_update: record.this_update_unix_seconds.to_string(),
            next_update: record.next_update_unix_seconds.to_string(),
        })
        .collect();
    catalog.emergency_blocklist = TzapPublicEmergencyBlocklist {
        blocked_root_sha256: inventory.emergency_blocklist.blocked_root_sha256.clone(),
        blocked_issuer_sha256: inventory.emergency_blocklist.blocked_issuer_sha256.clone(),
        updated_at_unix_seconds: inventory.emergency_blocklist.updated_at_unix_seconds,
    };
    catalog.pending_mutations.push(PendingMutation::LegacyMigration { started_at_unix_seconds: now_unix_seconds });
    catalog.validate()?;
    Ok((catalog, signing_refs, recipient_refs))
}

/// Commits a built catalog: writes the public intent first, copies every
/// secret into the secure store under the recorded references, verifies the
/// result, then clears the pending-migration marker.
fn commit_migration(
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    catalog: TzapIdentityCatalog,
    inventory: &TzapLocalIdentityInventory,
    signing_refs: &HashMap<String, TzapSecretRef>,
    recipient_refs: &HashMap<String, TzapSecretRef>,
) -> Result<(), TzapIdentityCatalogError> {
    // Commit the public intent first. The secret store writes below use
    // these exact references, so startup can resume this transaction.
    catalog_store.save_catalog(account_key, None, catalog)?;
    for record in &inventory.device_signing_keys {
        secret_store.put_at(
            TzapSecretPurpose::SigningKey,
            signing_refs
                .get(&record.key_id)
                .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.signing_refs" })?,
            record.private_key_der.clone(),
        )?;
    }
    for record in &inventory.recipient_encryption_keys {
        secret_store.put_at(
            TzapSecretPurpose::RecipientKey,
            recipient_refs
                .get(&record.key_id)
                .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.recipient_refs" })?,
            record.private_key_der.clone(),
        )?;
    }
    let mut committed = catalog_store
        .load_catalog(account_key)?
        .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.catalog" })?;
    for identity in &committed.signing_identities {
        secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
    }
    for key in &committed.recipient_keys {
        secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
    }
    committed.pending_mutations.retain(|mutation| !matches!(mutation, PendingMutation::LegacyMigration { .. }));
    let expected_revision = committed.revision;
    committed.revision = committed.revision.saturating_add(1);
    catalog_store.save_catalog(account_key, Some(expected_revision), committed)?;
    Ok(())
}

/// Computes the `sha256:` public-key fingerprint of a private key, in the
/// same form the legacy inventory stores on its key records.
pub(crate) fn public_key_fingerprint_from_private_key(
    private_key: &SecretBytes,
) -> Result<String, TzapIdentityCatalogError> {
    let key = openssl::pkey::PKey::private_key_from_der(private_key.expose_secret())
        .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    let public_der =
        key.public_key_to_der().map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    let digest: [u8; 32] = Sha256::digest(public_der).into();
    Ok(crate::trust::format_certificate_sha256(&digest))
}

fn verify_private_matches_fingerprint(
    private_key: &SecretBytes,
    expected_fingerprint: &str,
) -> Result<(), TzapIdentityCatalogError> {
    if public_key_fingerprint_from_private_key(private_key)? != expected_fingerprint {
        return Err(TzapIdentityCatalogError::InvalidCatalog { field: "private_key_public_key_match" });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy facade
//
// The legacy `TzapLocalIdentityStore` API persists through the catalog and a
// file-backed secret store, so the catalog is the only on-disk identity
// format. The legacy JSON inventory file is read once for migration and
// removed; the legacy record types remain the in-memory/wire model.

/// File-backed secret store used by the legacy facade: one 0o600 file per
/// secret under `{root}/secrets/{account_key}/{purpose}/{reference}`.
pub(crate) struct FileTzapSecretMaterialStore {
    root: PathBuf,
    account_key: String,
}

impl FileTzapSecretMaterialStore {
    #[must_use]
    pub(crate) fn new(root: impl Into<PathBuf>, account_key: &str) -> Self {
        Self { root: root.into(), account_key: account_key.to_owned() }
    }

    fn secret_path(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> PathBuf {
        self.root.join("secrets").join(&self.account_key).join(purpose.as_str()).join(reference.as_str())
    }
}

impl TzapSecretMaterialStore for FileTzapSecretMaterialStore {
    fn put(
        &mut self,
        purpose: TzapSecretPurpose,
        material: SecretBytes,
    ) -> Result<TzapSecretRef, TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let reference = TzapSecretRef::generate();
        self.put_at(purpose, &reference, material)?;
        Ok(reference)
    }

    fn put_at(
        &mut self,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
        material: SecretBytes,
    ) -> Result<(), TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let path = self.secret_path(purpose, reference);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| TzapSecretStoreError::Denied)?;
        }
        crate::atomic_file::write_atomic_secret_file(&path, material.expose_secret())
            .map_err(|_| TzapSecretStoreError::Denied)
    }

    fn resolve(
        &self,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
    ) -> Result<SecretBytes, TzapSecretStoreError> {
        let path = self.secret_path(purpose, reference);
        match fs::read(&path) {
            Ok(bytes) => Ok(SecretBytes::from(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(TzapSecretStoreError::Missing { reference: reference.clone() })
            }
            Err(_) => Err(TzapSecretStoreError::Corrupt),
        }
    }

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError> {
        let path = self.secret_path(purpose, reference);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(TzapSecretStoreError::Denied),
        }
    }
}

/// Persists a legacy inventory through the catalog, reusing existing secret
/// references for keys that persist so refs stay stable across saves and no
/// secrets are orphaned.
pub(crate) fn store_inventory_as_catalog(
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    inventory: &TzapLocalIdentityInventory,
    now_unix_seconds: u64,
) -> Result<(), TzapIdentityCatalogError> {
    let (mut catalog, mut signing_refs, mut recipient_refs) = build_catalog_from_legacy(inventory, now_unix_seconds)?;
    // The facade's normal writes are not migration transactions.
    catalog.pending_mutations.retain(|mutation| !matches!(mutation, PendingMutation::LegacyMigration { .. }));

    let existing = catalog_store.load_catalog(account_key)?;
    if let Some(existing) = &existing {
        for identity in &existing.signing_identities {
            let Some(key_id) = identity.legacy_key_id.clone() else { continue };
            let Some(fresh) = signing_refs.get(&key_id) else { continue };
            let existing_ref = identity.signing_key_ref.clone();
            for record in &mut catalog.signing_identities {
                if &record.signing_key_ref == fresh {
                    record.signing_key_ref = existing_ref.clone();
                }
            }
            signing_refs.insert(key_id, existing_ref);
        }
        for key in &existing.recipient_keys {
            let Some(fresh) = recipient_refs.get(&key.id) else { continue };
            let existing_ref = key.private_key_ref.clone();
            for record in &mut catalog.recipient_keys {
                if &record.private_key_ref == fresh {
                    record.private_key_ref = existing_ref.clone();
                }
            }
            recipient_refs.insert(key.id.clone(), existing_ref);
        }
        // Secrets whose refs disappeared from the inventory are dropped.
        let current_signing: HashSet<&str> =
            catalog.signing_identities.iter().map(|identity| identity.signing_key_ref.as_str()).collect();
        let current_recipient: HashSet<&str> =
            catalog.recipient_keys.iter().map(|key| key.private_key_ref.as_str()).collect();
        for identity in &existing.signing_identities {
            if !current_signing.contains(identity.signing_key_ref.as_str()) {
                let _ = secret_store.delete(TzapSecretPurpose::SigningKey, &identity.signing_key_ref);
            }
        }
        for key in &existing.recipient_keys {
            if !current_recipient.contains(key.private_key_ref.as_str()) {
                let _ = secret_store.delete(TzapSecretPurpose::RecipientKey, &key.private_key_ref);
            }
        }
    }

    for record in &inventory.device_signing_keys {
        let reference = signing_refs
            .get(&record.key_id)
            .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "facade.signing_refs" })?;
        secret_store.put_at(TzapSecretPurpose::SigningKey, reference, record.private_key_der.clone())?;
    }
    for record in &inventory.recipient_encryption_keys {
        let reference = recipient_refs
            .get(&record.key_id)
            .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "facade.recipient_refs" })?;
        secret_store.put_at(TzapSecretPurpose::RecipientKey, reference, record.private_key_der.clone())?;
    }

    let expected_revision = existing.as_ref().map(|catalog| catalog.revision);
    catalog.revision = expected_revision.map_or(1, |revision| revision.saturating_add(1));
    catalog_store.save_catalog(account_key, expected_revision, catalog)?;
    Ok(())
}

/// Loads a legacy-shaped inventory from the catalog, hydrating private key
/// material from the secret store.
pub(crate) fn load_inventory_from_catalog(
    catalog_store: &impl TzapIdentityCatalogStore,
    secret_store: &impl TzapSecretMaterialStore,
    account_key: &str,
) -> Result<Option<TzapLocalIdentityInventory>, TzapIdentityCatalogError> {
    let Some(catalog) = catalog_store.load_catalog(account_key)? else { return Ok(None) };
    let mut inventory = TzapLocalIdentityInventory::empty();

    for identity in &catalog.signing_identities {
        let private_key_der = secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
        let key_id = identity.legacy_key_id.clone().unwrap_or_else(|| identity.id.clone());
        inventory.device_signing_keys.push(TzapDeviceSigningKeyRecord {
            key_id: key_id.clone(),
            public_key_fingerprint: public_key_fingerprint_from_private_key(&private_key_der)?,
            private_key_der: private_key_der.clone(),
            created_at_unix_seconds: identity.signing_key_created_at_unix_seconds.unwrap_or(0),
            label: identity.local_alias.clone(),
        });
        if let Some(certificate_id) = &identity.certificate_id {
            let mut chain = identity.certificate_chain_der.clone();
            let leaf = chain.drain(..1).next().unwrap_or_default();
            inventory.enrolled_certificates.push(TzapEnrolledCertificateRecord {
                certificate_id: certificate_id.clone(),
                certificate_sha256: identity.certificate_sha256.clone().unwrap_or_default(),
                issuer_certificate_sha256: identity.issuer_certificate_sha256.clone().unwrap_or_default(),
                issuer_key_identifier: identity.issuer_key_identifier.clone().unwrap_or_default(),
                serial_number: identity.serial_number.clone().unwrap_or_default(),
                leaf_certificate_der: leaf,
                intermediate_chain_der: chain,
                not_before_unix_seconds: identity.not_before_unix_seconds.unwrap_or(0),
                not_after_unix_seconds: identity.not_after_unix_seconds.unwrap_or(0),
                public_metadata: crate::trust::TzapCertificatePublicMetadata {
                    version: identity.metadata_version.unwrap_or(u64::from(crate::trust::TZAP_ENVELOPE_VERSION)),
                    public_signer_id: identity.public_signer_id.clone().unwrap_or_default(),
                    public_org_id: identity.public_org_id.clone(),
                    public_device_id: identity.public_device_id.clone().unwrap_or_default(),
                    assurance_level: identity
                        .assurance_level
                        .as_deref()
                        .map(str::parse)
                        .transpose()
                        .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "assurance_level" })?
                        .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "assurance_level" })?,
                    policy_oid: identity
                        .policy_oid
                        .clone()
                        .unwrap_or_else(|| crate::trust::TZAP_OID_LEAF_POLICY.to_owned()),
                },
                sign_device_id: identity.sign_device_id.clone().unwrap_or_default(),
                sign_device_routing: identity.sign_device_routing.clone().unwrap_or(TzapSignDeviceRouting::Personal),
                signing_key_id: key_id,
                state: TzapLocalCertificateState::from_wire_value(&identity.lifecycle)
                    .unwrap_or(TzapLocalCertificateState::Active),
            });
        }
    }

    for key in &catalog.recipient_keys {
        let private_key_der = secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
        inventory.recipient_encryption_keys.push(TzapRecipientEncryptionKeyRecord {
            key_id: key.id.clone(),
            algorithm: key.algorithm.clone(),
            public_key_fingerprint: key.fingerprint.clone(),
            public_key_der: key.public_key_der.clone(),
            private_key_der,
            created_at_unix_seconds: key.created_at_unix_seconds,
            label: key.local_label.clone(),
        });
    }

    for contact in &catalog.contacts {
        inventory.contacts.push(TzapContactRecord {
            contact_id: contact.contact_id.clone(),
            display_name: contact.display_name.clone(),
            signing_certificate_sha256: contact.signing_certificate_sha256.clone(),
            recipient_public_key_fingerprint: contact.recipient_public_key_fingerprint.clone(),
            trust_anchor_type: contact
                .trust_source
                .parse()
                .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "contacts.trust_source" })?,
            verification_state: contact
                .verification_state
                .parse()
                .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "contacts.verification_state" })?,
            missing_status_caveat: contact.missing_status_caveat,
            contact_card_payload: contact.contact_card_payload.clone(),
            accepted_at_unix_seconds: contact.accepted_at_unix_seconds,
        });
    }

    for record in &catalog.status_cache {
        inventory.certificate_status_cache.push(TzapCertificateStatusCacheRecord {
            certificate_sha256: record.lookup_id.clone(),
            status: record
                .status
                .parse()
                .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "status_cache.status" })?,
            this_update_unix_seconds: record
                .this_update
                .parse()
                .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "status_cache.this_update" })?,
            next_update_unix_seconds: record
                .next_update
                .parse()
                .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "status_cache.next_update" })?,
        });
    }

    inventory.emergency_blocklist = TzapEmergencyBlocklistState {
        blocked_root_sha256: catalog.emergency_blocklist.blocked_root_sha256.clone(),
        blocked_issuer_sha256: catalog.emergency_blocklist.blocked_issuer_sha256.clone(),
        updated_at_unix_seconds: catalog.emergency_blocklist.updated_at_unix_seconds,
    };
    Ok(Some(inventory))
}

fn verify_private_matches_public_key(
    private_key: &SecretBytes,
    public_key_der: &[u8],
) -> Result<(), TzapIdentityCatalogError> {
    let key = openssl::pkey::PKey::private_key_from_der(private_key.expose_secret())
        .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    let derived =
        key.public_key_to_der().map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    if derived != public_key_der {
        return Err(TzapIdentityCatalogError::InvalidCatalog { field: "private_key_public_key_match" });
    }
    Ok(())
}

fn write_catalog_atomically(path: &Path, catalog: &TzapIdentityCatalog) -> Result<(), TzapIdentityCatalogError> {
    let bytes = serde_json::to_vec_pretty(catalog)?;
    let mut temporary = path.to_path_buf();
    temporary.set_extension(format!("tmp-{}", std::process::id()));
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&temporary, permissions)?;
    }
    drop(file);
    replace_catalog_file(&temporary, path)?;
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(path.parent().unwrap_or_else(|| Path::new("."))) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_catalog_file(temporary: &Path, path: &Path) -> Result<(), TzapIdentityCatalogError> {
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_catalog_file(temporary: &Path, path: &Path) -> Result<(), TzapIdentityCatalogError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // MoveFileExW with REPLACE_EXISTING is the Windows equivalent of an
    // atomic rename-over-existing-file. WRITE_THROUGH ensures the rename is
    // flushed before the call returns.
    let result = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn random_identifier() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validates an identity account key under the shared catalog rule.
///
/// Account keys are used as file names, so path separators and parent
/// traversal markers are rejected. This is deliberately conservative:
/// accepting a wider alphabet (spaces, dots) is fine as long as the key
/// cannot escape its directory. [`crate::local_identity_store`] uses the
/// same rule so both stores accept the same account keys.
#[must_use]
pub(crate) fn validate_account_key(value: &str) -> bool {
    !value.is_empty() && !value.contains('/') && !value.contains('\\') && !value.contains("..")
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), TzapIdentityCatalogError> {
    if value.is_empty() { Err(TzapIdentityCatalogError::InvalidCatalog { field }) } else { Ok(()) }
}

fn validate_unique<'a>(
    field: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), TzapIdentityCatalogError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_identity::{
        TzapDeviceCsrOptions, generate_device_signing_key_and_csr, generate_recipient_encryption_key,
    };
    use crate::local_identity_store::{
        InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord, TzapLocalIdentityInventory,
        TzapRecipientEncryptionKeyRecord,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn empty_catalog_is_public_and_has_no_secret_fields() {
        let catalog = TzapIdentityCatalog::empty();
        let json = serde_json::to_string(&catalog).unwrap();
        assert!(!json.contains("private_key_der"));
        assert!(!json.contains("session_token"));
        catalog.validate().unwrap();
    }

    #[test]
    fn catalog_store_enforces_revision_and_writes_owner_only_file() {
        let root = std::env::temp_dir().join(format!("tzap-catalog-{}", std::process::id()));
        let mut store = FileTzapIdentityCatalogStore::new(&root);
        let mut catalog = TzapIdentityCatalog::empty();
        catalog.revision = 1;
        store.save_catalog("default", None, catalog.clone()).unwrap();
        assert!(matches!(
            store.save_catalog("default", None, catalog.clone()),
            Err(TzapIdentityCatalogError::RevisionConflict { .. })
        ));
        let mut next = catalog.clone();
        next.revision = 2;
        store
            .save_catalog("default", Some(1), next.clone())
            .expect("an existing catalog can be replaced under its locked revision");
        assert_eq!(store.load_catalog("default").unwrap(), Some(next));
        #[cfg(unix)]
        {
            let path = root.join(format!("default{PUBLIC_CATALOG_FILE_SUFFIX}"));
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn catalog_store_refuses_concurrent_writes_but_steals_stale_locks() {
        let root = std::env::temp_dir().join(format!("tzap-catalog-lock-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut store = FileTzapIdentityCatalogStore::new(&root);
        let mut catalog = TzapIdentityCatalog::empty();
        catalog.revision = 1;
        let lock_path = root.join(format!("default{PUBLIC_CATALOG_FILE_SUFFIX}")).with_extension("lock");

        // A fresh lock belongs to a live writer: the save must be refused.
        fs::write(&lock_path, b"").unwrap();
        assert!(matches!(
            store.save_catalog("default", None, catalog.clone()),
            Err(TzapIdentityCatalogError::ConcurrentWrite)
        ));

        // A lock abandoned by a crashed writer must not block saves forever:
        // once it is old enough it is stolen and the save succeeds.
        let lock = fs::File::options().write(true).open(&lock_path).unwrap();
        let age = std::time::Duration::from_secs(LOCK_STALE_AFTER_SECONDS + 60);
        lock.set_modified(SystemTime::now() - age).unwrap();
        drop(lock);
        store
            .save_catalog("default", None, catalog.clone())
            .expect("a stale lock should be stolen instead of blocking the save");
        assert!(!lock_path.exists(), "the stolen lock should have been removed");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migration_moves_private_material_and_is_idempotent() {
        let signing = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient = generate_recipient_encryption_key().unwrap();
        let mut legacy = InMemoryTzapLocalIdentityStore::new();
        legacy
            .save_inventory(
                "default",
                TzapLocalIdentityInventory {
                    device_signing_keys: vec![TzapDeviceSigningKeyRecord {
                        key_id: "signing-1".to_owned(),
                        public_key_fingerprint: signing.public_key_fingerprint.clone(),
                        private_key_der: signing.private_key_der.clone(),
                        created_at_unix_seconds: 1,
                        label: Some("Laptop".to_owned()),
                    }],
                    recipient_encryption_keys: vec![TzapRecipientEncryptionKeyRecord {
                        key_id: "recipient-1".to_owned(),
                        algorithm: recipient.algorithm.to_owned(),
                        public_key_fingerprint: recipient.public_key_fingerprint.clone(),
                        public_key_der: recipient.public_key_spki_der.clone(),
                        private_key_der: recipient.private_key_der.clone(),
                        created_at_unix_seconds: 2,
                        label: None,
                    }],
                    ..TzapLocalIdentityInventory::empty()
                },
            )
            .unwrap();
        let mut catalogs = InMemoryTzapIdentityCatalogStore::new();
        let mut secrets = InMemoryTzapSecretMaterialStore::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let report = migrate_legacy_inventory(&legacy, &mut catalogs, &mut secrets, "default", now).unwrap();
        assert!(report.migrated);
        assert_eq!(report.signing_identity_count, 1);
        assert_eq!(report.recipient_key_count, 1);
        let second = migrate_legacy_inventory(&legacy, &mut catalogs, &mut secrets, "default", now).unwrap();
        assert!(!second.migrated);
        let catalog = catalogs.load_catalog("default").unwrap().unwrap();
        assert!(!serde_json::to_string(&catalog).unwrap().contains("private_key_der"));
        let signing_ref = catalog.signing_identities[0].signing_key_ref.clone();
        let recipient_ref = catalog.recipient_keys[0].private_key_ref.clone();
        secrets.delete(TzapSecretPurpose::SigningKey, &signing_ref).unwrap();
        secrets.delete(TzapSecretPurpose::RecipientKey, &recipient_ref).unwrap();
        let mut interrupted = catalog.clone();
        interrupted.pending_mutations.push(PendingMutation::LegacyMigration { started_at_unix_seconds: 1 });
        let expected_revision = interrupted.revision;
        interrupted.revision += 1;
        catalogs.save_catalog("default", Some(expected_revision), interrupted).unwrap();
        let recovered = migrate_legacy_inventory(&legacy, &mut catalogs, &mut secrets, "default", now).unwrap();
        assert!(recovered.migrated);
        assert!(secrets.resolve(TzapSecretPurpose::SigningKey, &signing_ref).is_ok());
        assert!(secrets.resolve(TzapSecretPurpose::RecipientKey, &recipient_ref).is_ok());
        assert!(catalogs.load_catalog("default").unwrap().unwrap().pending_mutations.is_empty());
    }
}
