use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialPostQuantumAccountNonceVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_POST_QUANTUM_ACCOUNT_NONCE_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-post-quantum-account-nonce-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_POST_QUANTUM_ACCOUNT_NONCE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_NONCE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-account-nonce-attestation-v1";
pub const SEALED_NONCE_BUCKET_SUITE: &str =
    "ML-KEM-1024+sealed-confidential-account-nonce-bucket-v1";
pub const REPLAY_FENCE_SCHEME: &str = "private-l2-pq-account-nonce-nullifier-fence-v1";
pub const LOW_FEE_LEASE_SCHEME: &str = "low-fee-batch-account-nonce-lease-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "operator-safe-account-nonce-redaction-budget-v1";
pub const DEVNET_HEIGHT: u64 = 1_444_000;
pub const DEVNET_EPOCH: u64 = 2_049;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIGRATION_EPOCH_BLOCKS: u64 = 43_200;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 16_384;
pub const DEFAULT_LOW_FEE_MICRONERO: u64 = 750;
pub const DEFAULT_MAX_LEASE_FEE_MICRONERO: u64 = 4_000;
pub const DEFAULT_MAX_BUCKETS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 16_777_216;
pub const DEFAULT_MAX_REPLAY_FENCES: usize = 33_554_432;
pub const DEFAULT_MAX_SESSION_KEYS: usize = 4_194_304;
pub const DEFAULT_MAX_LEASES: usize = 4_194_304;
pub const DEFAULT_MAX_MIGRATION_EPOCHS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 33_554_432;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceDomain {
    SmartAccount,
    SessionKey,
    Paymaster,
    Recovery,
    ContractCall,
    BridgeIntent,
    Governance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Sealed,
    Attested,
    Leasing,
    PartiallySpent,
    Draining,
    Exhausted,
    Migrating,
    Expired,
    Quarantined,
}

impl BucketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::Attested
                | Self::Leasing
                | Self::PartiallySpent
                | Self::Draining
                | Self::Migrating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BucketOpening,
    SessionBinding,
    ReplayFence,
    LeaseSettlement,
    MigrationCarry,
    RedactionSpend,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Linked,
    Consumed,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Offered,
    Reserved,
    BoundToBucket,
    Settled,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationEpochStatus {
    Proposed,
    PrivacyPrimed,
    Active,
    DrainingLegacy,
    Enforced,
    Superseded,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub monero_network: String,
    pub l2_network: String,
    pub activation_height: u64,
    pub epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set: u64,
    pub bucket_ttl_blocks: u64,
    pub session_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub migration_epoch_blocks: u64,
    pub redaction_budget_units: u64,
    pub low_fee_micronero: u64,
    pub max_lease_fee_micronero: u64,
    pub max_buckets: usize,
    pub max_attestations: usize,
    pub max_replay_fences: usize,
    pub max_session_keys: usize,
    pub max_leases: usize,
    pub max_migration_epochs: usize,
    pub max_public_records: usize,
    pub enabled_domains: BTreeSet<NonceDomain>,
    pub require_pq_attestations: bool,
    pub require_replay_fences: bool,
    pub allow_low_fee_batch_leasing: bool,
    pub operator_safe_public_records: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            activation_height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            migration_epoch_blocks: DEFAULT_MIGRATION_EPOCH_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            low_fee_micronero: DEFAULT_LOW_FEE_MICRONERO,
            max_lease_fee_micronero: DEFAULT_MAX_LEASE_FEE_MICRONERO,
            max_buckets: DEFAULT_MAX_BUCKETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_replay_fences: DEFAULT_MAX_REPLAY_FENCES,
            max_session_keys: DEFAULT_MAX_SESSION_KEYS,
            max_leases: DEFAULT_MAX_LEASES,
            max_migration_epochs: DEFAULT_MAX_MIGRATION_EPOCHS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            enabled_domains: BTreeSet::from([
                NonceDomain::SmartAccount,
                NonceDomain::SessionKey,
                NonceDomain::Paymaster,
                NonceDomain::Recovery,
                NonceDomain::ContractCall,
                NonceDomain::BridgeIntent,
            ]),
            require_pq_attestations: true,
            require_replay_fences: true,
            allow_low_fee_batch_leasing: true,
            operator_safe_public_records: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_nonce_attestation_suite": PQ_NONCE_ATTESTATION_SUITE,
            "sealed_nonce_bucket_suite": SEALED_NONCE_BUCKET_SUITE,
            "replay_fence_scheme": REPLAY_FENCE_SCHEME,
            "low_fee_lease_scheme": LOW_FEE_LEASE_SCHEME,
            "redaction_budget_scheme": REDACTION_BUDGET_SCHEME,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "activation_height": self.activation_height,
            "epoch": self.epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set": self.min_privacy_set,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "session_ttl_blocks": self.session_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "lease_ttl_blocks": self.lease_ttl_blocks,
            "migration_epoch_blocks": self.migration_epoch_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "low_fee_micronero": self.low_fee_micronero,
            "max_lease_fee_micronero": self.max_lease_fee_micronero,
            "enabled_domains": self.enabled_domains,
            "require_pq_attestations": self.require_pq_attestations,
            "require_replay_fences": self.require_replay_fences,
            "allow_low_fee_batch_leasing": self.allow_low_fee_batch_leasing,
            "operator_safe_public_records": self.operator_safe_public_records
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sealed_buckets: u64,
    pub live_buckets: u64,
    pub nonce_slots_committed: u64,
    pub nonce_slots_spent: u64,
    pub pq_attestations: u64,
    pub replay_fences: u64,
    pub session_keys: u64,
    pub low_fee_leases: u64,
    pub migration_epochs: u64,
    pub redaction_units_reserved: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub bucket_root: String,
    pub attestation_root: String,
    pub replay_fence_root: String,
    pub session_key_root: String,
    pub lease_root: String,
    pub migration_epoch_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedNonceBucket {
    pub bucket_id: String,
    pub account_commitment: String,
    pub domain: NonceDomain,
    pub status: BucketStatus,
    pub sealed_nonce_root: String,
    pub replay_window_root: String,
    pub deterministic_root: String,
    pub nonce_slots: u64,
    pub spent_slots: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub redaction_budget_id: String,
}

impl SealedNonceBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "account_commitment": self.account_commitment,
            "domain": self.domain,
            "status": self.status,
            "sealed_nonce_root": self.sealed_nonce_root,
            "replay_window_root": self.replay_window_root,
            "deterministic_root": self.deterministic_root,
            "nonce_slots": self.nonce_slots,
            "spent_slots": self.spent_slots,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "redaction_budget_id": self.redaction_budget_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqNonceAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub statement_root: String,
    pub bound_session_key_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqNonceAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub bucket_id: String,
    pub nullifier_root: String,
    pub consumed_nonce_root: String,
    pub epoch: u64,
    pub first_height: u64,
    pub last_height: u64,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionKeyLease {
    pub session_key_id: String,
    pub account_commitment: String,
    pub bucket_id: String,
    pub authorization_root: String,
    pub spend_limit_commitment: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SessionKeyLease {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeNonceLease {
    pub lease_id: String,
    pub bucket_id: String,
    pub status: LeaseStatus,
    pub lessee_commitment: String,
    pub nonce_slot_count: u64,
    pub fee_micronero: u64,
    pub batch_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeNonceLease {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationEpoch {
    pub migration_epoch_id: String,
    pub status: MigrationEpochStatus,
    pub legacy_root: String,
    pub pq_vault_root: String,
    pub carry_proof_root: String,
    pub starts_at_height: u64,
    pub enforced_at_height: u64,
}

impl MigrationEpoch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub disclosure_policy_root: String,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub buckets: BTreeMap<String, SealedNonceBucket>,
    pub attestations: BTreeMap<String, PqNonceAttestation>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub session_keys: BTreeMap<String, SessionKeyLease>,
    pub low_fee_leases: BTreeMap<String, LowFeeNonceLease>,
    pub migration_epochs: BTreeMap<String, MigrationEpoch>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        let mut state = Self {
            config,
            height,
            counters: Counters::default(),
            roots: Roots::default(),
            buckets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            session_keys: BTreeMap::new(),
            low_fee_leases: BTreeMap::new(),
            migration_epochs: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let account = sample_commitment("smart-account", 1);
        let budget_id = deterministic_id("redaction-budget", &["devnet", "account-1"]);
        let bucket_id = deterministic_id("nonce-bucket", &["devnet", "account-1", "epoch-2049"]);
        let session_key_id = deterministic_id("session-key", &["devnet", "session-1"]);

        state
            .insert_redaction_budget(RedactionBudget {
                budget_id: budget_id.clone(),
                owner_commitment: account.clone(),
                reserved_units: DEFAULT_REDACTION_BUDGET_UNITS,
                spent_units: 192,
                disclosure_policy_root: sample_root("redaction-policy", 1),
                expires_at_height: DEVNET_HEIGHT + DEFAULT_BUCKET_TTL_BLOCKS,
            })
            .expect("devnet redaction budget");
        state
            .insert_bucket(SealedNonceBucket {
                bucket_id: bucket_id.clone(),
                account_commitment: account.clone(),
                domain: NonceDomain::SmartAccount,
                status: BucketStatus::Leasing,
                sealed_nonce_root: sample_root("sealed-nonces", 1),
                replay_window_root: sample_root("replay-window", 1),
                deterministic_root: deterministic_root("bucket", &[&account, &bucket_id]),
                nonce_slots: 4_096,
                spent_slots: 384,
                privacy_set_size: 262_144,
                opened_at_height: DEVNET_HEIGHT,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_BUCKET_TTL_BLOCKS,
                redaction_budget_id: budget_id,
            })
            .expect("devnet bucket");
        state
            .insert_session_key(SessionKeyLease {
                session_key_id: session_key_id.clone(),
                account_commitment: account.clone(),
                bucket_id: bucket_id.clone(),
                authorization_root: sample_root("session-authorization", 1),
                spend_limit_commitment: sample_commitment("spend-limit", 1),
                issued_at_height: DEVNET_HEIGHT + 1,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_SESSION_TTL_BLOCKS,
            })
            .expect("devnet session key");
        state
            .insert_attestation(PqNonceAttestation {
                attestation_id: deterministic_id("nonce-attestation", &["devnet", "bucket-1"]),
                bucket_id: bucket_id.clone(),
                kind: AttestationKind::BucketOpening,
                status: AttestationStatus::Linked,
                attester_commitment: sample_commitment("attester", 1),
                pq_signature_root: sample_root("pq-signature", 1),
                statement_root: sample_root("nonce-statement", 1),
                bound_session_key_id: Some(session_key_id),
                submitted_at_height: DEVNET_HEIGHT + 1,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
            })
            .expect("devnet attestation");
        state
            .insert_replay_fence(ReplayFence {
                fence_id: deterministic_id("replay-fence", &["devnet", "bucket-1"]),
                bucket_id: bucket_id.clone(),
                nullifier_root: sample_root("nullifiers", 1),
                consumed_nonce_root: sample_root("consumed-nonces", 1),
                epoch: DEVNET_EPOCH,
                first_height: DEVNET_HEIGHT,
                last_height: DEVNET_HEIGHT + DEFAULT_BUCKET_TTL_BLOCKS,
            })
            .expect("devnet replay fence");
        state
            .insert_low_fee_lease(LowFeeNonceLease {
                lease_id: deterministic_id("nonce-lease", &["devnet", "batch-1"]),
                bucket_id: bucket_id.clone(),
                status: LeaseStatus::BoundToBucket,
                lessee_commitment: sample_commitment("lessee", 1),
                nonce_slot_count: 256,
                fee_micronero: DEFAULT_LOW_FEE_MICRONERO,
                batch_root: sample_root("low-fee-batch", 1),
                issued_at_height: DEVNET_HEIGHT + 2,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_LEASE_TTL_BLOCKS,
            })
            .expect("devnet low-fee lease");
        state
            .insert_migration_epoch(MigrationEpoch {
                migration_epoch_id: deterministic_id("migration-epoch", &["devnet", "2049"]),
                status: MigrationEpochStatus::Active,
                legacy_root: sample_root("legacy-nonce-root", 1),
                pq_vault_root: deterministic_root("pq-vault", &[&bucket_id]),
                carry_proof_root: sample_root("migration-carry-proof", 1),
                starts_at_height: DEVNET_HEIGHT,
                enforced_at_height: DEVNET_HEIGHT + DEFAULT_MIGRATION_EPOCH_BLOCKS,
            })
            .expect("devnet migration epoch");
        state.record_public_summary("devnet-account-nonce-vault");
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn insert_bucket(&mut self, bucket: SealedNonceBucket) -> Result<()> {
        ensure(
            self.buckets.len() < self.config.max_buckets,
            "bucket capacity exhausted",
        )?;
        ensure(
            self.config.enabled_domains.contains(&bucket.domain),
            "nonce domain is not enabled",
        )?;
        ensure(
            bucket.privacy_set_size >= self.config.min_privacy_set,
            "bucket privacy set below configured minimum",
        )?;
        self.counters.sealed_buckets = self.counters.sealed_buckets.saturating_add(1);
        if bucket.status.live() {
            self.counters.live_buckets = self.counters.live_buckets.saturating_add(1);
        }
        self.counters.nonce_slots_committed = self
            .counters
            .nonce_slots_committed
            .saturating_add(bucket.nonce_slots);
        self.counters.nonce_slots_spent = self
            .counters
            .nonce_slots_spent
            .saturating_add(bucket.spent_slots);
        self.buckets.insert(bucket.bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_attestation(&mut self, attestation: PqNonceAttestation) -> Result<()> {
        ensure(
            self.attestations.len() < self.config.max_attestations,
            "attestation capacity exhausted",
        )?;
        ensure(
            self.buckets.contains_key(&attestation.bucket_id),
            "attestation references unknown bucket",
        )?;
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_replay_fence(&mut self, fence: ReplayFence) -> Result<()> {
        ensure(
            self.replay_fences.len() < self.config.max_replay_fences,
            "replay fence capacity exhausted",
        )?;
        self.counters.replay_fences = self.counters.replay_fences.saturating_add(1);
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_session_key(&mut self, session_key: SessionKeyLease) -> Result<()> {
        ensure(
            self.session_keys.len() < self.config.max_session_keys,
            "session key capacity exhausted",
        )?;
        self.counters.session_keys = self.counters.session_keys.saturating_add(1);
        self.session_keys
            .insert(session_key.session_key_id.clone(), session_key);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_lease(&mut self, lease: LowFeeNonceLease) -> Result<()> {
        ensure(
            self.config.allow_low_fee_batch_leasing,
            "low-fee batch leasing is disabled",
        )?;
        ensure(
            self.low_fee_leases.len() < self.config.max_leases,
            "lease capacity exhausted",
        )?;
        ensure(
            lease.fee_micronero <= self.config.max_lease_fee_micronero,
            "lease fee exceeds configured maximum",
        )?;
        self.counters.low_fee_leases = self.counters.low_fee_leases.saturating_add(1);
        self.low_fee_leases.insert(lease.lease_id.clone(), lease);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_migration_epoch(&mut self, epoch: MigrationEpoch) -> Result<()> {
        ensure(
            self.migration_epochs.len() < self.config.max_migration_epochs,
            "migration epoch capacity exhausted",
        )?;
        self.counters.migration_epochs = self.counters.migration_epochs.saturating_add(1);
        self.migration_epochs
            .insert(epoch.migration_epoch_id.clone(), epoch);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        self.counters.redaction_units_reserved = self
            .counters
            .redaction_units_reserved
            .saturating_add(budget.reserved_units);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_public_summary(&mut self, label: &str) {
        let record = json!({
            "label": label,
            "height": self.height,
            "bucket_root": self.roots.bucket_root,
            "attestation_root": self.roots.attestation_root,
            "replay_fence_root": self.roots.replay_fence_root,
            "lease_root": self.roots.lease_root,
            "state_hint": deterministic_root(label, &[&self.roots.bucket_root, &self.roots.lease_root])
        });
        self.public_records.insert(label.to_string(), record);
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            bucket_root: map_root("ACCOUNT-NONCE-BUCKETS", &self.buckets, |bucket| {
                bucket.public_record()
            }),
            attestation_root: map_root(
                "PQ-NONCE-ATTESTATIONS",
                &self.attestations,
                |attestation| attestation.public_record(),
            ),
            replay_fence_root: map_root(
                "ACCOUNT-NONCE-REPLAY-FENCES",
                &self.replay_fences,
                |fence| fence.public_record(),
            ),
            session_key_root: map_root("ACCOUNT-NONCE-SESSION-KEYS", &self.session_keys, |key| {
                key.public_record()
            }),
            lease_root: map_root("LOW-FEE-NONCE-LEASES", &self.low_fee_leases, |lease| {
                lease.public_record()
            }),
            migration_epoch_root: map_root(
                "NONCE-VAULT-MIGRATION-EPOCHS",
                &self.migration_epochs,
                |epoch| epoch.public_record(),
            ),
            redaction_budget_root: map_root(
                "NONCE-VAULT-REDACTION-BUDGETS",
                &self.redaction_budgets,
                |budget| budget.public_record(),
            ),
            public_record_root: value_map_root("NONCE-VAULT-PUBLIC-RECORDS", &self.public_records),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "module": "private_l2_pq_confidential_post_quantum_account_nonce_vault_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record()
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-POST-QUANTUM-ACCOUNT-NONCE-VAULT-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, parts: &[&str]) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-NONCE-VAULT-DETERMINISTIC-ROOT",
        &[HashPart::Str(label), HashPart::Json(&json!(parts))],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let root = domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-NONCE-VAULT-ID",
        &[HashPart::Str(prefix), HashPart::Json(&json!(parts))],
        16,
    );
    format!("{prefix}-{root}")
}

pub fn sample_root(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-NONCE-VAULT-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sample_commitment(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-NONCE-VAULT-SAMPLE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value)
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn value_map_root(domain: &str, values: &BTreeMap<String, Value>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": value
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
