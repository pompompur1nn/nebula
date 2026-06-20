use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialPqKeyRotationMigrationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_PQ_KEY_ROTATION_MIGRATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-pq-key-rotation-migration-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_PQ_KEY_ROTATION_MIGRATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-rotation-migration-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024+hybrid-x25519-confidential-migration-envelope-v1";
pub const PRIVACY_PROOF_SCHEME: &str = "confidential-pq-key-rotation-privacy-proof-root-v1";
pub const REPLAY_FENCE_SCHEME: &str = "confidential-pq-key-rotation-nullifier-fence-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-confidential-pq-key-migration-batch-v1";
pub const RELEASE_GATE_SCHEME: &str = "operator-pq-release-gate-migration-readiness-v1";
pub const REMEDIATION_SCHEME: &str = "confidential-pq-key-rotation-remediation-queue-v1";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_EPOCH_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_ROTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_BRIDGE_WATCHER_TTL_BLOCKS: u64 = 960;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 1_440;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_MAX_FEE_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_COVERAGE_BPS: u64 = 9_200;
pub const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 256;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const DEFAULT_RELEASE_GATE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const MAX_ACCOUNT_KEYS: usize = 1_048_576;
pub const MAX_SESSION_KEYS: usize = 2_097_152;
pub const MAX_BRIDGE_WATCHERS: usize = 524_288;
pub const MAX_CONTRACT_KEYS: usize = 1_048_576;
pub const MAX_WALLET_API_KEYS: usize = 1_048_576;
pub const MAX_MIGRATION_EPOCHS: usize = 2_097_152;
pub const MAX_ROTATION_REQUESTS: usize = 4_194_304;
pub const MAX_PRIVACY_PROOFS: usize = 4_194_304;
pub const MAX_REPLAY_FENCES: usize = 8_388_608;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_RELEASE_GATES: usize = 262_144;
pub const MAX_REMEDIATION_ITEMS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDomain {
    Account,
    Session,
    BridgeWatcher,
    Contract,
    WalletApi,
    Operator,
}

impl KeyDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Session => "session",
            Self::BridgeWatcher => "bridge_watcher",
            Self::Contract => "contract",
            Self::WalletApi => "wallet_api",
            Self::Operator => "operator",
        }
    }

    pub fn default_ttl_blocks(self, config: &Config) -> u64 {
        match self {
            Self::Session => config.session_ttl_blocks,
            Self::BridgeWatcher => config.bridge_watcher_ttl_blocks,
            Self::Operator => config.release_delay_blocks,
            _ => config.rotation_ttl_blocks,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    MlDsa65,
    MlDsa87,
    SlhDsaShake192f,
    SlhDsaShake256f,
    HybridEd25519MlDsa87,
    HybridSpendKeyMlDsa87,
    HybridSecp256k1MlDsa87,
    HybridBlsMlDsa87,
}

impl KeyAlgorithm {
    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::SlhDsaShake192f => 192,
            Self::MlDsa87
            | Self::SlhDsaShake256f
            | Self::HybridEd25519MlDsa87
            | Self::HybridSpendKeyMlDsa87
            | Self::HybridSecp256k1MlDsa87
            | Self::HybridBlsMlDsa87 => 256,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake192f => "slh_dsa_shake_192f",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridEd25519MlDsa87 => "hybrid_ed25519_ml_dsa_87",
            Self::HybridSpendKeyMlDsa87 => "hybrid_spend_key_ml_dsa_87",
            Self::HybridSecp256k1MlDsa87 => "hybrid_secp256k1_ml_dsa_87",
            Self::HybridBlsMlDsa87 => "hybrid_bls_ml_dsa_87",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Registered,
    Active,
    RotationPending,
    MigrationPending,
    GracePeriod,
    Retired,
    Frozen,
    Compromised,
    Slashed,
}

impl KeyStatus {
    pub fn accepts_rotation(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Active | Self::RotationPending | Self::MigrationPending
        )
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::RotationPending | Self::MigrationPending | Self::GracePeriod
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::RotationPending => "rotation_pending",
            Self::MigrationPending => "migration_pending",
            Self::GracePeriod => "grace_period",
            Self::Retired => "retired",
            Self::Frozen => "frozen",
            Self::Compromised => "compromised",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Proposed,
    PrivacyPrimed,
    SponsorReserved,
    AdmissionOpen,
    Active,
    DrainingLegacy,
    Enforced,
    Superseded,
    Revoked,
    EmergencyOnly,
}

impl EpochStatus {
    pub fn accepts_requests(self) -> bool {
        matches!(
            self,
            Self::PrivacyPrimed | Self::SponsorReserved | Self::AdmissionOpen | Self::Active
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PrivacyPrimed => "privacy_primed",
            Self::SponsorReserved => "sponsor_reserved",
            Self::AdmissionOpen => "admission_open",
            Self::Active => "active",
            Self::DrainingLegacy => "draining_legacy",
            Self::Enforced => "enforced",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationKind {
    AccountSpendKey,
    AccountViewKey,
    SessionAuthorization,
    BridgeWatcherAttestation,
    ContractAdminKey,
    ContractExecutionKey,
    WalletApiCredential,
    OperatorReleaseKey,
    EmergencyRemediation,
}

impl RotationKind {
    pub fn domain(self) -> KeyDomain {
        match self {
            Self::AccountSpendKey | Self::AccountViewKey => KeyDomain::Account,
            Self::SessionAuthorization => KeyDomain::Session,
            Self::BridgeWatcherAttestation => KeyDomain::BridgeWatcher,
            Self::ContractAdminKey | Self::ContractExecutionKey => KeyDomain::Contract,
            Self::WalletApiCredential => KeyDomain::WalletApi,
            Self::OperatorReleaseKey => KeyDomain::Operator,
            Self::EmergencyRemediation => KeyDomain::Account,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountSpendKey => "account_spend_key",
            Self::AccountViewKey => "account_view_key",
            Self::SessionAuthorization => "session_authorization",
            Self::BridgeWatcherAttestation => "bridge_watcher_attestation",
            Self::ContractAdminKey => "contract_admin_key",
            Self::ContractExecutionKey => "contract_execution_key",
            Self::WalletApiCredential => "wallet_api_credential",
            Self::OperatorReleaseKey => "operator_release_key",
            Self::EmergencyRemediation => "emergency_remediation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Drafted,
    PrivacyProved,
    ReplayFenced,
    SponsorMatched,
    BatchQueued,
    Settled,
    Rejected,
    Expired,
    RemediationQueued,
}

impl RequestStatus {
    pub fn batchable(self) -> bool {
        matches!(self, Self::ReplayFenced | Self::SponsorMatched)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rejected | Self::Expired | Self::RemediationQueued
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::PrivacyProved => "privacy_proved",
            Self::ReplayFenced => "replay_fenced",
            Self::SponsorMatched => "sponsor_matched",
            Self::BatchQueued => "batch_queued",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::RemediationQueued => "remediation_queued",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Posted,
    Settled,
    PartiallySettled,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Draft,
    CollectingEvidence,
    QuorumMet,
    Ready,
    Blocked,
    Released,
    RolledBack,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::CollectingEvidence => "collecting_evidence",
            Self::QuorumMet => "quorum_met",
            Self::Ready => "ready",
            Self::Blocked => "blocked",
            Self::Released => "released",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    WeakPqBits,
    PrivacySetTooSmall,
    ReplayFenceCollision,
    MissingWatcherQuorum,
    ContractPolicyMismatch,
    WalletApiCredentialStale,
    ReleaseGateBlocked,
    SponsorExhausted,
    EvidenceMalformed,
}

impl RemediationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeakPqBits => "weak_pq_bits",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::ReplayFenceCollision => "replay_fence_collision",
            Self::MissingWatcherQuorum => "missing_watcher_quorum",
            Self::ContractPolicyMismatch => "contract_policy_mismatch",
            Self::WalletApiCredentialStale => "wallet_api_credential_stale",
            Self::ReleaseGateBlocked => "release_gate_blocked",
            Self::SponsorExhausted => "sponsor_exhausted",
            Self::EvidenceMalformed => "evidence_malformed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Queued,
    Assigned,
    InProgress,
    ProofSubmitted,
    Cleared,
    Escalated,
    Slashed,
}

impl RemediationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::InProgress => "in_progress",
            Self::ProofSubmitted => "proof_submitted",
            Self::Cleared => "cleared",
            Self::Escalated => "escalated",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub pq_kem_suite: String,
    pub privacy_proof_scheme: String,
    pub replay_fence_scheme: String,
    pub low_fee_batch_scheme: String,
    pub release_gate_scheme: String,
    pub remediation_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub epoch_ttl_blocks: u64,
    pub rotation_ttl_blocks: u64,
    pub session_ttl_blocks: u64,
    pub bridge_watcher_ttl_blocks: u64,
    pub release_delay_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub max_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub low_fee_batch_target: usize,
    pub low_fee_batch_limit: usize,
    pub release_gate_quorum_bps: u64,
    pub watcher_quorum_bps: u64,
    pub require_privacy_proof: bool,
    pub require_replay_fence: bool,
    pub require_release_gate: bool,
    pub allow_sponsored_batches: bool,
    pub allow_emergency_remediation: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            privacy_proof_scheme: PRIVACY_PROOF_SCHEME.to_string(),
            replay_fence_scheme: REPLAY_FENCE_SCHEME.to_string(),
            low_fee_batch_scheme: LOW_FEE_BATCH_SCHEME.to_string(),
            release_gate_scheme: RELEASE_GATE_SCHEME.to_string(),
            remediation_scheme: REMEDIATION_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            epoch_ttl_blocks: DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_ttl_blocks: DEFAULT_ROTATION_TTL_BLOCKS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            bridge_watcher_ttl_blocks: DEFAULT_BRIDGE_WATCHER_TTL_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            sponsor_coverage_bps: DEFAULT_SPONSOR_COVERAGE_BPS,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            release_gate_quorum_bps: DEFAULT_RELEASE_GATE_QUORUM_BPS,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            require_privacy_proof: true,
            require_replay_fence: true,
            require_release_gate: true,
            allow_sponsored_batches: true,
            allow_emergency_remediation: true,
        }
    }

    pub fn demo() -> Self {
        let mut config = Self::devnet();
        config.low_fee_batch_target = 8;
        config.low_fee_batch_limit = 64;
        config.min_privacy_set_size = 1_024;
        config.batch_privacy_set_size = 4_096;
        config
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "privacy_proof_scheme": self.privacy_proof_scheme,
            "replay_fence_scheme": self.replay_fence_scheme,
            "low_fee_batch_scheme": self.low_fee_batch_scheme,
            "release_gate_scheme": self.release_gate_scheme,
            "remediation_scheme": self.remediation_scheme,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "epoch_ttl_blocks": self.epoch_ttl_blocks,
            "rotation_ttl_blocks": self.rotation_ttl_blocks,
            "session_ttl_blocks": self.session_ttl_blocks,
            "bridge_watcher_ttl_blocks": self.bridge_watcher_ttl_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "low_fee_batch_target": self.low_fee_batch_target,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "release_gate_quorum_bps": self.release_gate_quorum_bps,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "require_privacy_proof": self.require_privacy_proof,
            "require_replay_fence": self.require_replay_fence,
            "require_release_gate": self.require_release_gate,
            "allow_sponsored_batches": self.allow_sponsored_batches,
            "allow_emergency_remediation": self.allow_emergency_remediation
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub account_keys: u64,
    pub session_keys: u64,
    pub bridge_watchers: u64,
    pub contract_keys: u64,
    pub wallet_api_keys: u64,
    pub operator_keys: u64,
    pub migration_epochs: u64,
    pub rotation_requests: u64,
    pub privacy_proofs: u64,
    pub replay_fences: u64,
    pub batches: u64,
    pub receipts: u64,
    pub release_gates: u64,
    pub remediations: u64,
    pub rejected_requests: u64,
    pub settled_requests: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "account_keys": self.account_keys,
            "session_keys": self.session_keys,
            "bridge_watchers": self.bridge_watchers,
            "contract_keys": self.contract_keys,
            "wallet_api_keys": self.wallet_api_keys,
            "operator_keys": self.operator_keys,
            "migration_epochs": self.migration_epochs,
            "rotation_requests": self.rotation_requests,
            "privacy_proofs": self.privacy_proofs,
            "replay_fences": self.replay_fences,
            "batches": self.batches,
            "receipts": self.receipts,
            "release_gates": self.release_gates,
            "remediations": self.remediations,
            "rejected_requests": self.rejected_requests,
            "settled_requests": self.settled_requests
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRecord {
    pub key_id: String,
    pub domain: KeyDomain,
    pub owner_commitment: String,
    pub key_commitment: String,
    pub policy_root: String,
    pub algorithm: KeyAlgorithm,
    pub status: KeyStatus,
    pub epoch_id: String,
    pub generation: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub rotation_nonce: u64,
    pub privacy_set_size: u64,
    pub last_request_id: Option<String>,
}

impl KeyRecord {
    pub fn pq_security_bits(&self) -> u16 {
        self.algorithm.pq_security_bits()
    }

    pub fn expired_at(&self, height: u64) -> bool {
        self.valid_until_height > 0 && height > self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "key_id": self.key_id,
            "domain": self.domain.as_str(),
            "owner_commitment": self.owner_commitment,
            "key_commitment": self.key_commitment,
            "policy_root": self.policy_root,
            "algorithm": self.algorithm.as_str(),
            "pq_security_bits": self.pq_security_bits(),
            "status": self.status.as_str(),
            "epoch_id": self.epoch_id,
            "generation": self.generation,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "rotation_nonce": self.rotation_nonce,
            "privacy_set_size": self.privacy_set_size,
            "last_request_id": self.last_request_id
        })
    }

    pub fn root(&self) -> String {
        value_root("KEY-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationEpoch {
    pub epoch_id: String,
    pub status: EpochStatus,
    pub start_height: u64,
    pub admission_height: u64,
    pub enforce_height: u64,
    pub expires_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_domains: BTreeSet<KeyDomain>,
    pub sponsor_pool_commitment: String,
    pub release_gate_id: String,
    pub previous_epoch_root: String,
    pub notes_commitment: String,
}

impl MigrationEpoch {
    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts_requests()
            && height >= self.admission_height
            && height <= self.expires_height
    }

    pub fn public_record(&self) -> Value {
        let domains = self
            .target_domains
            .iter()
            .map(|domain| json!(domain.as_str()))
            .collect::<Vec<_>>();
        json!({
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "admission_height": self.admission_height,
            "enforce_height": self.enforce_height,
            "expires_height": self.expires_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_domains": domains,
            "sponsor_pool_commitment": self.sponsor_pool_commitment,
            "release_gate_id": self.release_gate_id,
            "previous_epoch_root": self.previous_epoch_root,
            "notes_commitment": self.notes_commitment
        })
    }

    pub fn root(&self) -> String {
        value_root("MIGRATION-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyProof {
    pub proof_id: String,
    pub request_id: String,
    pub domain: KeyDomain,
    pub nullifier: String,
    pub old_key_commitment: String,
    pub new_key_commitment: String,
    pub membership_root: String,
    pub disclosure_root: String,
    pub statement_root: String,
    pub pq_proof_bits: u16,
    pub privacy_set_size: u64,
    pub proves_no_linkable_secret: bool,
    pub proves_policy_continuity: bool,
    pub proves_owner_authorization: bool,
}

impl PrivacyProof {
    pub fn valid_for(&self, config: &Config) -> bool {
        self.pq_proof_bits >= config.min_pq_security_bits
            && self.privacy_set_size >= config.min_privacy_set_size
            && self.proves_no_linkable_secret
            && self.proves_policy_continuity
            && self.proves_owner_authorization
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "request_id": self.request_id,
            "domain": self.domain.as_str(),
            "nullifier": self.nullifier,
            "old_key_commitment": self.old_key_commitment,
            "new_key_commitment": self.new_key_commitment,
            "membership_root": self.membership_root,
            "disclosure_root": self.disclosure_root,
            "statement_root": self.statement_root,
            "pq_proof_bits": self.pq_proof_bits,
            "privacy_set_size": self.privacy_set_size,
            "proves_no_linkable_secret": self.proves_no_linkable_secret,
            "proves_policy_continuity": self.proves_policy_continuity,
            "proves_owner_authorization": self.proves_owner_authorization
        })
    }

    pub fn root(&self) -> String {
        value_root("PRIVACY-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub request_id: String,
    pub nullifier: String,
    pub domain: KeyDomain,
    pub epoch_id: String,
    pub first_seen_height: u64,
    pub expires_height: u64,
    pub consumed: bool,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "request_id": self.request_id,
            "nullifier": self.nullifier,
            "domain": self.domain.as_str(),
            "epoch_id": self.epoch_id,
            "first_seen_height": self.first_seen_height,
            "expires_height": self.expires_height,
            "consumed": self.consumed
        })
    }

    pub fn root(&self) -> String {
        value_root("REPLAY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationRequest {
    pub request_id: String,
    pub kind: RotationKind,
    pub domain: KeyDomain,
    pub owner_commitment: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub epoch_id: String,
    pub privacy_proof_id: String,
    pub replay_fence_id: String,
    pub fee_asset_id: String,
    pub fee_limit: u64,
    pub max_fee_bps: u64,
    pub sponsor_commitment: Option<String>,
    pub status: RequestStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub batch_id: Option<String>,
    pub remediation_id: Option<String>,
}

impl RotationRequest {
    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_height && !self.status.terminal()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "kind": self.kind.as_str(),
            "domain": self.domain.as_str(),
            "owner_commitment": self.owner_commitment,
            "old_key_id": self.old_key_id,
            "new_key_id": self.new_key_id,
            "epoch_id": self.epoch_id,
            "privacy_proof_id": self.privacy_proof_id,
            "replay_fence_id": self.replay_fence_id,
            "fee_asset_id": self.fee_asset_id,
            "fee_limit": self.fee_limit,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "batch_id": self.batch_id,
            "remediation_id": self.remediation_id
        })
    }

    pub fn root(&self) -> String {
        value_root("ROTATION-REQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeWatcherEvidence {
    pub evidence_id: String,
    pub watcher_key_id: String,
    pub epoch_id: String,
    pub observed_bridge_root: String,
    pub observed_state_root: String,
    pub attestation_root: String,
    pub weight: u64,
    pub pq_security_bits: u16,
    pub height: u64,
    pub accepted: bool,
}

impl BridgeWatcherEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "watcher_key_id": self.watcher_key_id,
            "epoch_id": self.epoch_id,
            "observed_bridge_root": self.observed_bridge_root,
            "observed_state_root": self.observed_state_root,
            "attestation_root": self.attestation_root,
            "weight": self.weight,
            "pq_security_bits": self.pq_security_bits,
            "height": self.height,
            "accepted": self.accepted
        })
    }

    pub fn root(&self) -> String {
        value_root("BRIDGE-WATCHER-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractKeyPolicy {
    pub policy_id: String,
    pub contract_key_id: String,
    pub admin_threshold: u64,
    pub execution_threshold: u64,
    pub upgrade_delay_blocks: u64,
    pub allowed_call_root: String,
    pub dependency_root: String,
    pub privacy_budget_root: String,
    pub requires_release_gate: bool,
}

impl ContractKeyPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "contract_key_id": self.contract_key_id,
            "admin_threshold": self.admin_threshold,
            "execution_threshold": self.execution_threshold,
            "upgrade_delay_blocks": self.upgrade_delay_blocks,
            "allowed_call_root": self.allowed_call_root,
            "dependency_root": self.dependency_root,
            "privacy_budget_root": self.privacy_budget_root,
            "requires_release_gate": self.requires_release_gate
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletApiKey {
    pub api_key_id: String,
    pub wallet_commitment: String,
    pub key_id: String,
    pub capability_root: String,
    pub rate_limit_root: String,
    pub disclosure_policy_root: String,
    pub session_binding_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub pq_security_bits: u16,
    pub revoked: bool,
}

impl WalletApiKey {
    pub fn public_record(&self) -> Value {
        json!({
            "api_key_id": self.api_key_id,
            "wallet_commitment": self.wallet_commitment,
            "key_id": self.key_id,
            "capability_root": self.capability_root,
            "rate_limit_root": self.rate_limit_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "session_binding_root": self.session_binding_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "pq_security_bits": self.pq_security_bits,
            "revoked": self.revoked
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub epoch_id: String,
    pub coordinator_commitment: String,
    pub request_ids: Vec<String>,
    pub request_root: String,
    pub privacy_set_size: u64,
    pub total_fee_limit: u64,
    pub sponsor_coverage_bps: u64,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub posted_height: u64,
    pub settlement_root: String,
}

impl LowFeeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "coordinator_commitment": self.coordinator_commitment,
            "request_ids": self.request_ids,
            "request_root": self.request_root,
            "privacy_set_size": self.privacy_set_size,
            "total_fee_limit": self.total_fee_limit,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "posted_height": self.posted_height,
            "settlement_root": self.settlement_root
        })
    }

    pub fn root(&self) -> String {
        value_root("LOW-FEE-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub batch_id: Option<String>,
    pub old_key_id: String,
    pub new_key_id: String,
    pub epoch_id: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_charged: u64,
    pub sponsor_paid: u64,
    pub settled_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "batch_id": self.batch_id,
            "old_key_id": self.old_key_id,
            "new_key_id": self.new_key_id,
            "epoch_id": self.epoch_id,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "fee_charged": self.fee_charged,
            "sponsor_paid": self.sponsor_paid,
            "settled_height": self.settled_height
        })
    }

    pub fn root(&self) -> String {
        value_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseGate {
    pub gate_id: String,
    pub release_id: String,
    pub target_epoch_id: String,
    pub operator_commitment: String,
    pub required_quorum_bps: u64,
    pub observed_quorum_bps: u64,
    pub readiness_root: String,
    pub regression_root: String,
    pub rollback_root: String,
    pub status: GateStatus,
    pub created_height: u64,
    pub ready_height: u64,
    pub released_height: u64,
    pub blockers: BTreeSet<String>,
}

impl ReleaseGate {
    pub fn public_record(&self) -> Value {
        let blockers = self
            .blockers
            .iter()
            .map(|item| json!(item))
            .collect::<Vec<_>>();
        json!({
            "gate_id": self.gate_id,
            "release_id": self.release_id,
            "target_epoch_id": self.target_epoch_id,
            "operator_commitment": self.operator_commitment,
            "required_quorum_bps": self.required_quorum_bps,
            "observed_quorum_bps": self.observed_quorum_bps,
            "readiness_root": self.readiness_root,
            "regression_root": self.regression_root,
            "rollback_root": self.rollback_root,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "ready_height": self.ready_height,
            "released_height": self.released_height,
            "blockers": blockers
        })
    }

    pub fn root(&self) -> String {
        value_root("RELEASE-GATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemediationItem {
    pub remediation_id: String,
    pub kind: RemediationKind,
    pub status: RemediationStatus,
    pub affected_domain: KeyDomain,
    pub subject_id: String,
    pub request_id: Option<String>,
    pub epoch_id: String,
    pub severity: u8,
    pub opened_height: u64,
    pub due_height: u64,
    pub evidence_root: String,
    pub assigned_operator_commitment: Option<String>,
    pub resolution_root: Option<String>,
}

impl RemediationItem {
    pub fn public_record(&self) -> Value {
        json!({
            "remediation_id": self.remediation_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "affected_domain": self.affected_domain.as_str(),
            "subject_id": self.subject_id,
            "request_id": self.request_id,
            "epoch_id": self.epoch_id,
            "severity": self.severity,
            "opened_height": self.opened_height,
            "due_height": self.due_height,
            "evidence_root": self.evidence_root,
            "assigned_operator_commitment": self.assigned_operator_commitment,
            "resolution_root": self.resolution_root
        })
    }

    pub fn root(&self) -> String {
        value_root("REMEDIATION-ITEM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationRequestDraft {
    pub request_id: String,
    pub kind: RotationKind,
    pub owner_commitment: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub epoch_id: String,
    pub privacy_proof_id: String,
    pub replay_fence_id: String,
    pub fee_asset_id: String,
    pub fee_limit: u64,
    pub max_fee_bps: u64,
    pub sponsor_commitment: Option<String>,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub account_key_root: String,
    pub session_key_root: String,
    pub bridge_watcher_root: String,
    pub contract_key_root: String,
    pub wallet_api_root: String,
    pub operator_key_root: String,
    pub epoch_root: String,
    pub request_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub watcher_evidence_root: String,
    pub contract_policy_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub release_gate_root: String,
    pub remediation_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "account_key_root": self.account_key_root,
            "session_key_root": self.session_key_root,
            "bridge_watcher_root": self.bridge_watcher_root,
            "contract_key_root": self.contract_key_root,
            "wallet_api_root": self.wallet_api_root,
            "operator_key_root": self.operator_key_root,
            "epoch_root": self.epoch_root,
            "request_root": self.request_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "watcher_evidence_root": self.watcher_evidence_root,
            "contract_policy_root": self.contract_policy_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "release_gate_root": self.release_gate_root,
            "remediation_root": self.remediation_root
        })
    }

    pub fn root(&self) -> String {
        value_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub account_keys: BTreeMap<String, KeyRecord>,
    pub session_keys: BTreeMap<String, KeyRecord>,
    pub bridge_watchers: BTreeMap<String, KeyRecord>,
    pub contract_keys: BTreeMap<String, KeyRecord>,
    pub wallet_api_key_records: BTreeMap<String, KeyRecord>,
    pub operator_keys: BTreeMap<String, KeyRecord>,
    pub wallet_api_keys: BTreeMap<String, WalletApiKey>,
    pub contract_policies: BTreeMap<String, ContractKeyPolicy>,
    pub migration_epochs: BTreeMap<String, MigrationEpoch>,
    pub rotation_requests: BTreeMap<String, RotationRequest>,
    pub privacy_proofs: BTreeMap<String, PrivacyProof>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub replay_nullifiers: BTreeSet<String>,
    pub bridge_watcher_evidence: BTreeMap<String, BridgeWatcherEvidence>,
    pub batches: BTreeMap<String, LowFeeBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub release_gates: BTreeMap<String, ReleaseGate>,
    pub remediation_queue: BTreeMap<String, RemediationItem>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            height,
            counters: Counters::default(),
            account_keys: BTreeMap::new(),
            session_keys: BTreeMap::new(),
            bridge_watchers: BTreeMap::new(),
            contract_keys: BTreeMap::new(),
            wallet_api_key_records: BTreeMap::new(),
            operator_keys: BTreeMap::new(),
            wallet_api_keys: BTreeMap::new(),
            contract_policies: BTreeMap::new(),
            migration_epochs: BTreeMap::new(),
            rotation_requests: BTreeMap::new(),
            privacy_proofs: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            bridge_watcher_evidence: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            release_gates: BTreeMap::new(),
            remediation_queue: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let domains = BTreeSet::from([
            KeyDomain::Account,
            KeyDomain::Session,
            KeyDomain::BridgeWatcher,
            KeyDomain::Contract,
            KeyDomain::WalletApi,
            KeyDomain::Operator,
        ]);
        let gate = ReleaseGate {
            gate_id: "release-gate-devnet-pq-001".to_string(),
            release_id: "pq-rotation-migration-devnet".to_string(),
            target_epoch_id: "pq-migration-epoch-devnet-001".to_string(),
            operator_commitment: "operator:devnet:pq-release".to_string(),
            required_quorum_bps: DEFAULT_RELEASE_GATE_QUORUM_BPS,
            observed_quorum_bps: 7_200,
            readiness_root: fixed_root("devnet-readiness"),
            regression_root: fixed_root("devnet-regression-clean"),
            rollback_root: fixed_root("devnet-rollback-plan"),
            status: GateStatus::Ready,
            created_height: DEVNET_HEIGHT,
            ready_height: DEVNET_HEIGHT + 8,
            released_height: 0,
            blockers: BTreeSet::new(),
        };
        let epoch = MigrationEpoch {
            epoch_id: "pq-migration-epoch-devnet-001".to_string(),
            status: EpochStatus::AdmissionOpen,
            start_height: DEVNET_HEIGHT,
            admission_height: DEVNET_HEIGHT + 10,
            enforce_height: DEVNET_HEIGHT + 2_880,
            expires_height: DEVNET_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_domains: domains,
            sponsor_pool_commitment: "sponsor-pool:devnet:pq-migration".to_string(),
            release_gate_id: gate.gate_id.clone(),
            previous_epoch_root: fixed_root("legacy-key-epoch"),
            notes_commitment: fixed_root("devnet-epoch-notes"),
        };
        let account_key = KeyRecord {
            key_id: "account-key-devnet-alice-v1".to_string(),
            domain: KeyDomain::Account,
            owner_commitment: "owner:alice:stealth".to_string(),
            key_commitment: "key:alice:legacy-hybrid".to_string(),
            policy_root: fixed_root("alice-policy"),
            algorithm: KeyAlgorithm::HybridSpendKeyMlDsa87,
            status: KeyStatus::Active,
            epoch_id: epoch.epoch_id.clone(),
            generation: 1,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_nonce: 1,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            last_request_id: None,
        };
        let session_key = KeyRecord {
            key_id: "session-key-devnet-alice-fast-001".to_string(),
            domain: KeyDomain::Session,
            owner_commitment: account_key.owner_commitment.clone(),
            key_commitment: "session:alice:fast-path".to_string(),
            policy_root: fixed_root("session-policy"),
            algorithm: KeyAlgorithm::MlDsa87,
            status: KeyStatus::Active,
            epoch_id: epoch.epoch_id.clone(),
            generation: 1,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_SESSION_TTL_BLOCKS,
            rotation_nonce: 7,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            last_request_id: None,
        };
        let watcher_key = KeyRecord {
            key_id: "bridge-watcher-devnet-001".to_string(),
            domain: KeyDomain::BridgeWatcher,
            owner_commitment: "watcher:committee:devnet:001".to_string(),
            key_commitment: "watcher-key:devnet:001".to_string(),
            policy_root: fixed_root("watcher-policy"),
            algorithm: KeyAlgorithm::HybridBlsMlDsa87,
            status: KeyStatus::Active,
            epoch_id: epoch.epoch_id.clone(),
            generation: 1,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_BRIDGE_WATCHER_TTL_BLOCKS,
            rotation_nonce: 2,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            last_request_id: None,
        };
        let contract_key = KeyRecord {
            key_id: "contract-key-devnet-vault-001".to_string(),
            domain: KeyDomain::Contract,
            owner_commitment: "contract:vault:devnet".to_string(),
            key_commitment: "contract-key:vault:admin".to_string(),
            policy_root: fixed_root("vault-contract-policy"),
            algorithm: KeyAlgorithm::HybridSecp256k1MlDsa87,
            status: KeyStatus::Active,
            epoch_id: epoch.epoch_id.clone(),
            generation: 3,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_nonce: 3,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            last_request_id: None,
        };
        let wallet_key_record = KeyRecord {
            key_id: "wallet-api-key-record-devnet-001".to_string(),
            domain: KeyDomain::WalletApi,
            owner_commitment: "wallet:alice:api".to_string(),
            key_commitment: "wallet-api-key:alice".to_string(),
            policy_root: fixed_root("wallet-api-policy"),
            algorithm: KeyAlgorithm::MlDsa87,
            status: KeyStatus::Active,
            epoch_id: epoch.epoch_id.clone(),
            generation: 1,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_nonce: 5,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            last_request_id: None,
        };
        let wallet_api = WalletApiKey {
            api_key_id: "wallet-api-devnet-alice-001".to_string(),
            wallet_commitment: "wallet:alice:api".to_string(),
            key_id: wallet_key_record.key_id.clone(),
            capability_root: fixed_root("wallet-capabilities"),
            rate_limit_root: fixed_root("wallet-rate-limits"),
            disclosure_policy_root: fixed_root("wallet-disclosure"),
            session_binding_root: session_key.root(),
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            pq_security_bits: 256,
            revoked: false,
        };
        let operator_key = KeyRecord {
            key_id: "operator-release-key-devnet-001".to_string(),
            domain: KeyDomain::Operator,
            owner_commitment: "operator:devnet:pq-release".to_string(),
            key_commitment: "operator-key:pq-release".to_string(),
            policy_root: fixed_root("operator-release-policy"),
            algorithm: KeyAlgorithm::SlhDsaShake256f,
            status: KeyStatus::Active,
            epoch_id: epoch.epoch_id.clone(),
            generation: 1,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_nonce: 9,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            last_request_id: None,
        };
        let policy = ContractKeyPolicy {
            policy_id: "contract-policy-vault-devnet-001".to_string(),
            contract_key_id: contract_key.key_id.clone(),
            admin_threshold: 2,
            execution_threshold: 1,
            upgrade_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            allowed_call_root: fixed_root("vault-allowed-calls"),
            dependency_root: fixed_root("vault-dependencies"),
            privacy_budget_root: fixed_root("vault-privacy-budget"),
            requires_release_gate: true,
        };
        let evidence = BridgeWatcherEvidence {
            evidence_id: "watcher-evidence-devnet-001".to_string(),
            watcher_key_id: watcher_key.key_id.clone(),
            epoch_id: epoch.epoch_id.clone(),
            observed_bridge_root: fixed_root("bridge-root-devnet"),
            observed_state_root: fixed_root("state-root-devnet"),
            attestation_root: fixed_root("watcher-attestation-devnet"),
            weight: 7_200,
            pq_security_bits: 256,
            height: DEVNET_HEIGHT + 12,
            accepted: true,
        };
        let _ = state.insert_key(account_key);
        let _ = state.insert_key(session_key);
        let _ = state.insert_key(watcher_key);
        let _ = state.insert_key(contract_key);
        let _ = state.insert_key(wallet_key_record);
        let _ = state.insert_key(operator_key);
        let _ = state.register_wallet_api_key(wallet_api);
        let _ = state.register_contract_policy(policy);
        let _ = state.register_release_gate(gate);
        let _ = state.register_epoch(epoch);
        let _ = state.register_bridge_watcher_evidence(evidence);
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::new(Config::demo(), DEVNET_HEIGHT + 100);
        let mut demo = Self::devnet();
        demo.config = Config::demo();
        demo.height = DEVNET_HEIGHT + 100;
        state = demo;
        let proof = PrivacyProof {
            proof_id: "privacy-proof-demo-001".to_string(),
            request_id: "rotation-request-demo-001".to_string(),
            domain: KeyDomain::Account,
            nullifier: "nullifier:demo:001".to_string(),
            old_key_commitment: "key:alice:legacy-hybrid".to_string(),
            new_key_commitment: "key:alice:pq-v2".to_string(),
            membership_root: fixed_root("demo-membership"),
            disclosure_root: fixed_root("demo-disclosure"),
            statement_root: fixed_root("demo-statement"),
            pq_proof_bits: 256,
            privacy_set_size: 4_096,
            proves_no_linkable_secret: true,
            proves_policy_continuity: true,
            proves_owner_authorization: true,
        };
        let new_key = KeyRecord {
            key_id: "account-key-devnet-alice-v2".to_string(),
            domain: KeyDomain::Account,
            owner_commitment: "owner:alice:stealth".to_string(),
            key_commitment: proof.new_key_commitment.clone(),
            policy_root: fixed_root("alice-policy-v2"),
            algorithm: KeyAlgorithm::MlDsa87,
            status: KeyStatus::Registered,
            epoch_id: "pq-migration-epoch-devnet-001".to_string(),
            generation: 2,
            valid_from_height: state.height,
            valid_until_height: state.height + DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_nonce: 10,
            privacy_set_size: 4_096,
            last_request_id: None,
        };
        let _ = state.insert_key(new_key);
        let _ = state.register_privacy_proof(proof);
        let draft = RotationRequestDraft {
            request_id: "rotation-request-demo-001".to_string(),
            kind: RotationKind::AccountSpendKey,
            owner_commitment: "owner:alice:stealth".to_string(),
            old_key_id: "account-key-devnet-alice-v1".to_string(),
            new_key_id: "account-key-devnet-alice-v2".to_string(),
            epoch_id: "pq-migration-epoch-devnet-001".to_string(),
            privacy_proof_id: "privacy-proof-demo-001".to_string(),
            replay_fence_id: "replay-fence-demo-001".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            fee_limit: 10_000,
            max_fee_bps: 8,
            sponsor_commitment: Some("sponsor-pool:devnet:pq-migration".to_string()),
            submitted_height: state.height,
        };
        let _ = state.submit_rotation_request(draft);
        let _ = state.open_or_update_batch(
            "low-fee-batch-demo-001",
            "pq-migration-epoch-devnet-001",
            "coordinator:devnet:batcher",
            vec!["rotation-request-demo-001".to_string()],
            state.height + 1,
        );
        state
    }

    pub fn insert_key(&mut self, key: KeyRecord) -> Result<()> {
        self.validate_capacity_for_domain(key.domain)?;
        if key.pq_security_bits() < self.config.min_pq_security_bits {
            return Err("key pq security bits below configured floor".to_string());
        }
        if key.privacy_set_size < self.config.min_privacy_set_size {
            return Err("key privacy set size below configured floor".to_string());
        }
        match key.domain {
            KeyDomain::Account => {
                self.account_keys.insert(key.key_id.clone(), key);
                self.counters.account_keys = self.account_keys.len() as u64;
            }
            KeyDomain::Session => {
                self.session_keys.insert(key.key_id.clone(), key);
                self.counters.session_keys = self.session_keys.len() as u64;
            }
            KeyDomain::BridgeWatcher => {
                self.bridge_watchers.insert(key.key_id.clone(), key);
                self.counters.bridge_watchers = self.bridge_watchers.len() as u64;
            }
            KeyDomain::Contract => {
                self.contract_keys.insert(key.key_id.clone(), key);
                self.counters.contract_keys = self.contract_keys.len() as u64;
            }
            KeyDomain::WalletApi => {
                self.wallet_api_key_records.insert(key.key_id.clone(), key);
                self.counters.wallet_api_keys = self.wallet_api_key_records.len() as u64;
            }
            KeyDomain::Operator => {
                self.operator_keys.insert(key.key_id.clone(), key);
                self.counters.operator_keys = self.operator_keys.len() as u64;
            }
        }
        Ok(())
    }

    pub fn register_epoch(&mut self, epoch: MigrationEpoch) -> Result<()> {
        if self.migration_epochs.len() >= MAX_MIGRATION_EPOCHS
            && !self.migration_epochs.contains_key(&epoch.epoch_id)
        {
            return Err("migration epoch capacity exhausted".to_string());
        }
        if epoch.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("epoch pq security bits below configured floor".to_string());
        }
        if epoch.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("epoch privacy set size below configured floor".to_string());
        }
        if epoch.expires_height <= epoch.admission_height {
            return Err("epoch expiry must be after admission height".to_string());
        }
        self.migration_epochs.insert(epoch.epoch_id.clone(), epoch);
        self.counters.migration_epochs = self.migration_epochs.len() as u64;
        Ok(())
    }

    pub fn register_privacy_proof(&mut self, proof: PrivacyProof) -> Result<()> {
        if self.privacy_proofs.len() >= MAX_PRIVACY_PROOFS
            && !self.privacy_proofs.contains_key(&proof.proof_id)
        {
            return Err("privacy proof capacity exhausted".to_string());
        }
        if !proof.valid_for(&self.config) {
            return Err("privacy proof does not satisfy configured policy".to_string());
        }
        self.privacy_proofs.insert(proof.proof_id.clone(), proof);
        self.counters.privacy_proofs = self.privacy_proofs.len() as u64;
        Ok(())
    }

    pub fn register_replay_fence(&mut self, fence: ReplayFence) -> Result<()> {
        if self.replay_fences.len() >= MAX_REPLAY_FENCES
            && !self.replay_fences.contains_key(&fence.fence_id)
        {
            return Err("replay fence capacity exhausted".to_string());
        }
        if self.replay_nullifiers.contains(&fence.nullifier) {
            return Err("replay nullifier already used".to_string());
        }
        self.replay_nullifiers.insert(fence.nullifier.clone());
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        self.counters.replay_fences = self.replay_fences.len() as u64;
        Ok(())
    }

    pub fn submit_rotation_request(&mut self, draft: RotationRequestDraft) -> Result<String> {
        if self.rotation_requests.len() >= MAX_ROTATION_REQUESTS
            && !self.rotation_requests.contains_key(&draft.request_id)
        {
            return Err("rotation request capacity exhausted".to_string());
        }
        if draft.max_fee_bps > self.config.max_fee_bps || draft.max_fee_bps > MAX_BPS {
            return Err("request fee bps exceeds configured limit".to_string());
        }
        let domain = draft.kind.domain();
        let epoch = match self.migration_epochs.get(&draft.epoch_id) {
            Some(epoch) => epoch,
            None => return Err("missing migration epoch".to_string()),
        };
        if !epoch.active_at(draft.submitted_height) {
            return Err(
                "migration epoch is not accepting requests at submitted height".to_string(),
            );
        }
        if !epoch.target_domains.contains(&domain) {
            return Err("migration epoch does not target request domain".to_string());
        }
        let old_key = match self.key_by_domain(domain, &draft.old_key_id) {
            Some(key) => key,
            None => return Err("old key not registered for request domain".to_string()),
        };
        let new_key = match self.key_by_domain(domain, &draft.new_key_id) {
            Some(key) => key,
            None => return Err("new key not registered for request domain".to_string()),
        };
        if !old_key.status.accepts_rotation() {
            return Err("old key status does not accept rotation".to_string());
        }
        if new_key.pq_security_bits() < epoch.min_pq_security_bits {
            return Err("new key pq security bits below epoch floor".to_string());
        }
        if new_key.privacy_set_size < epoch.min_privacy_set_size {
            return Err("new key privacy set size below epoch floor".to_string());
        }
        let proof = match self.privacy_proofs.get(&draft.privacy_proof_id) {
            Some(proof) => proof,
            None => return Err("missing privacy proof".to_string()),
        };
        if proof.request_id != draft.request_id || proof.domain != domain {
            return Err("privacy proof does not bind to request and domain".to_string());
        }
        let fence = ReplayFence {
            fence_id: draft.replay_fence_id.clone(),
            request_id: draft.request_id.clone(),
            nullifier: proof.nullifier.clone(),
            domain,
            epoch_id: draft.epoch_id.clone(),
            first_seen_height: draft.submitted_height,
            expires_height: draft.submitted_height + domain.default_ttl_blocks(&self.config),
            consumed: false,
        };
        self.register_replay_fence(fence)?;
        let request = RotationRequest {
            request_id: draft.request_id.clone(),
            kind: draft.kind,
            domain,
            owner_commitment: draft.owner_commitment,
            old_key_id: draft.old_key_id,
            new_key_id: draft.new_key_id,
            epoch_id: draft.epoch_id,
            privacy_proof_id: draft.privacy_proof_id,
            replay_fence_id: draft.replay_fence_id,
            fee_asset_id: draft.fee_asset_id,
            fee_limit: draft.fee_limit,
            max_fee_bps: draft.max_fee_bps,
            sponsor_commitment: draft.sponsor_commitment,
            status: RequestStatus::ReplayFenced,
            submitted_height: draft.submitted_height,
            expires_height: draft.submitted_height + domain.default_ttl_blocks(&self.config),
            batch_id: None,
            remediation_id: None,
        };
        self.rotation_requests
            .insert(request.request_id.clone(), request);
        self.counters.rotation_requests = self.rotation_requests.len() as u64;
        Ok(draft.request_id)
    }

    pub fn register_bridge_watcher_evidence(
        &mut self,
        evidence: BridgeWatcherEvidence,
    ) -> Result<()> {
        if self.bridge_watcher_evidence.len() >= MAX_BRIDGE_WATCHERS
            && !self
                .bridge_watcher_evidence
                .contains_key(&evidence.evidence_id)
        {
            return Err("bridge watcher evidence capacity exhausted".to_string());
        }
        if evidence.pq_security_bits < self.config.min_pq_security_bits {
            return Err("bridge watcher evidence pq bits below configured floor".to_string());
        }
        self.bridge_watcher_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn register_contract_policy(&mut self, policy: ContractKeyPolicy) -> Result<()> {
        if self.contract_policies.len() >= MAX_CONTRACT_KEYS
            && !self.contract_policies.contains_key(&policy.policy_id)
        {
            return Err("contract policy capacity exhausted".to_string());
        }
        self.contract_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn register_wallet_api_key(&mut self, key: WalletApiKey) -> Result<()> {
        if self.wallet_api_keys.len() >= MAX_WALLET_API_KEYS
            && !self.wallet_api_keys.contains_key(&key.api_key_id)
        {
            return Err("wallet api key capacity exhausted".to_string());
        }
        if key.pq_security_bits < self.config.min_pq_security_bits {
            return Err("wallet api key pq bits below configured floor".to_string());
        }
        self.wallet_api_keys.insert(key.api_key_id.clone(), key);
        Ok(())
    }

    pub fn register_release_gate(&mut self, gate: ReleaseGate) -> Result<()> {
        if self.release_gates.len() >= MAX_RELEASE_GATES
            && !self.release_gates.contains_key(&gate.gate_id)
        {
            return Err("release gate capacity exhausted".to_string());
        }
        if gate.required_quorum_bps > MAX_BPS || gate.observed_quorum_bps > MAX_BPS {
            return Err("release gate quorum bps exceeds maximum".to_string());
        }
        self.release_gates.insert(gate.gate_id.clone(), gate);
        self.counters.release_gates = self.release_gates.len() as u64;
        Ok(())
    }

    pub fn open_or_update_batch(
        &mut self,
        batch_id: &str,
        epoch_id: &str,
        coordinator_commitment: &str,
        request_ids: Vec<String>,
        height: u64,
    ) -> Result<String> {
        if self.batches.len() >= MAX_BATCHES && !self.batches.contains_key(batch_id) {
            return Err("batch capacity exhausted".to_string());
        }
        if request_ids.len() > self.config.low_fee_batch_limit {
            return Err("batch exceeds configured item limit".to_string());
        }
        if request_ids.is_empty() {
            return Err("batch must contain at least one request".to_string());
        }
        let mut total_fee_limit = 0_u64;
        let mut request_records = Vec::new();
        for request_id in &request_ids {
            let request = match self.rotation_requests.get(request_id) {
                Some(request) => request,
                None => return Err("batch contains missing request".to_string()),
            };
            if request.epoch_id != epoch_id {
                return Err("batch request epoch mismatch".to_string());
            }
            if !request.status.batchable() {
                return Err("batch request is not batchable".to_string());
            }
            total_fee_limit = total_fee_limit.saturating_add(request.fee_limit);
            request_records.push(request.public_record());
        }
        let request_root = merkle_root("PQ-ROTATION-BATCH-REQUESTS", &request_records);
        for request_id in &request_ids {
            if let Some(request) = self.rotation_requests.get_mut(request_id) {
                request.status = RequestStatus::BatchQueued;
                request.batch_id = Some(batch_id.to_string());
            }
        }
        let batch = LowFeeBatch {
            batch_id: batch_id.to_string(),
            epoch_id: epoch_id.to_string(),
            coordinator_commitment: coordinator_commitment.to_string(),
            request_ids,
            request_root,
            privacy_set_size: self.config.batch_privacy_set_size,
            total_fee_limit,
            sponsor_coverage_bps: self.config.sponsor_coverage_bps,
            status: BatchStatus::Open,
            opened_height: height,
            sealed_height: 0,
            posted_height: 0,
            settlement_root: fixed_root("unsettled-batch"),
        };
        self.batches.insert(batch_id.to_string(), batch);
        self.counters.batches = self.batches.len() as u64;
        Ok(batch_id.to_string())
    }

    pub fn settle_request(&mut self, request_id: &str, settled_height: u64) -> Result<String> {
        let request = match self.rotation_requests.get(request_id) {
            Some(request) => request.clone(),
            None => return Err("missing rotation request".to_string()),
        };
        if request.expired_at(settled_height) {
            return Err("rotation request expired before settlement".to_string());
        }
        if !(request.status == RequestStatus::ReplayFenced
            || request.status == RequestStatus::SponsorMatched
            || request.status == RequestStatus::BatchQueued)
        {
            return Err("rotation request status cannot settle".to_string());
        }
        let before = self.state_root();
        self.apply_key_transition(&request)?;
        if let Some(fence) = self.replay_fences.get_mut(&request.replay_fence_id) {
            fence.consumed = true;
        }
        if let Some(stored) = self.rotation_requests.get_mut(request_id) {
            stored.status = RequestStatus::Settled;
        }
        let after = self.state_root();
        let sponsor_paid = request
            .fee_limit
            .saturating_mul(self.config.sponsor_coverage_bps)
            .saturating_div(MAX_BPS);
        let fee_charged = request.fee_limit.saturating_sub(sponsor_paid);
        let receipt_id = deterministic_id("receipt", &[request_id, &after]);
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            request_id: request.request_id,
            batch_id: request.batch_id,
            old_key_id: request.old_key_id,
            new_key_id: request.new_key_id,
            epoch_id: request.epoch_id,
            state_root_before: before,
            state_root_after: after,
            fee_charged,
            sponsor_paid,
            settled_height,
        };
        self.receipts.insert(receipt_id.clone(), receipt);
        self.counters.receipts = self.receipts.len() as u64;
        self.counters.settled_requests = self
            .rotation_requests
            .values()
            .filter(|request| request.status == RequestStatus::Settled)
            .count() as u64;
        Ok(receipt_id)
    }

    pub fn settle_batch(&mut self, batch_id: &str, height: u64) -> Result<Vec<String>> {
        let request_ids = match self.batches.get(batch_id) {
            Some(batch) => batch.request_ids.clone(),
            None => return Err("missing low-fee batch".to_string()),
        };
        let mut receipt_ids = Vec::new();
        for request_id in request_ids {
            match self.settle_request(&request_id, height) {
                Ok(receipt_id) => receipt_ids.push(receipt_id),
                Err(error) => {
                    let remediation_id = self.queue_remediation(
                        RemediationKind::EvidenceMalformed,
                        KeyDomain::Account,
                        &request_id,
                        Some(request_id.clone()),
                        "batch-settlement-failed",
                        2,
                        height,
                    )?;
                    if let Some(request) = self.rotation_requests.get_mut(&request_id) {
                        request.status = RequestStatus::RemediationQueued;
                        request.remediation_id = Some(remediation_id);
                    }
                    let _ = error;
                }
            }
        }
        let settlement_root = {
            let records = receipt_ids
                .iter()
                .filter_map(|receipt_id| self.receipts.get(receipt_id))
                .map(|receipt| receipt.public_record())
                .collect::<Vec<_>>();
            merkle_root("PQ-BATCH-SETTLEMENT-RECEIPTS", &records)
        };
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = if receipt_ids.len() == batch.request_ids.len() {
                BatchStatus::Settled
            } else {
                BatchStatus::PartiallySettled
            };
            batch.sealed_height = height;
            batch.posted_height = height;
            batch.settlement_root = settlement_root;
        }
        Ok(receipt_ids)
    }

    pub fn queue_remediation(
        &mut self,
        kind: RemediationKind,
        affected_domain: KeyDomain,
        subject_id: &str,
        request_id: Option<String>,
        evidence_label: &str,
        severity: u8,
        height: u64,
    ) -> Result<String> {
        if self.remediation_queue.len() >= MAX_REMEDIATION_ITEMS {
            return Err("remediation queue capacity exhausted".to_string());
        }
        let remediation_id =
            deterministic_id("remediation", &[kind.as_str(), subject_id, evidence_label]);
        let epoch_id = request_id
            .as_ref()
            .and_then(|id| self.rotation_requests.get(id))
            .map(|request| request.epoch_id.clone())
            .fallback_string("unknown-epoch");
        let item = RemediationItem {
            remediation_id: remediation_id.clone(),
            kind,
            status: RemediationStatus::Queued,
            affected_domain,
            subject_id: subject_id.to_string(),
            request_id,
            epoch_id,
            severity,
            opened_height: height,
            due_height: height + self.config.rotation_ttl_blocks,
            evidence_root: fixed_root(evidence_label),
            assigned_operator_commitment: None,
            resolution_root: None,
        };
        self.remediation_queue.insert(remediation_id.clone(), item);
        self.counters.remediations = self.remediation_queue.len() as u64;
        Ok(remediation_id)
    }

    pub fn mark_release_gate_ready(
        &mut self,
        gate_id: &str,
        quorum_bps: u64,
        height: u64,
    ) -> Result<()> {
        let gate = match self.release_gates.get_mut(gate_id) {
            Some(gate) => gate,
            None => return Err("missing release gate".to_string()),
        };
        if quorum_bps < gate.required_quorum_bps {
            gate.status = GateStatus::Blocked;
            gate.blockers.insert("quorum_below_required".to_string());
            return Err("release gate quorum below required threshold".to_string());
        }
        gate.observed_quorum_bps = quorum_bps;
        gate.ready_height = height;
        gate.status = GateStatus::Ready;
        gate.blockers.remove("quorum_below_required");
        Ok(())
    }

    pub fn release_gate(&mut self, gate_id: &str, height: u64) -> Result<()> {
        let gate = match self.release_gates.get_mut(gate_id) {
            Some(gate) => gate,
            None => return Err("missing release gate".to_string()),
        };
        if gate.status != GateStatus::Ready && gate.status != GateStatus::QuorumMet {
            return Err("release gate is not ready".to_string());
        }
        if !gate.blockers.is_empty() {
            return Err("release gate has blockers".to_string());
        }
        if height
            < gate
                .ready_height
                .saturating_add(self.config.release_delay_blocks)
        {
            return Err("release delay has not elapsed".to_string());
        }
        gate.status = GateStatus::Released;
        gate.released_height = height;
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: value_root("CONFIG", &self.config.public_record()),
            counters_root: value_root("COUNTERS", &self.counters.public_record()),
            account_key_root: map_root("ACCOUNT-KEYS", &self.account_keys, |key| {
                key.public_record()
            }),
            session_key_root: map_root("SESSION-KEYS", &self.session_keys, |key| {
                key.public_record()
            }),
            bridge_watcher_root: map_root("BRIDGE-WATCHERS", &self.bridge_watchers, |key| {
                key.public_record()
            }),
            contract_key_root: map_root("CONTRACT-KEYS", &self.contract_keys, |key| {
                key.public_record()
            }),
            wallet_api_root: value_root(
                "WALLET-API-ROOT",
                &json!({
                    "key_records": map_records(&self.wallet_api_key_records, |key| key.public_record()),
                    "api_keys": map_records(&self.wallet_api_keys, |key| key.public_record())
                }),
            ),
            operator_key_root: map_root("OPERATOR-KEYS", &self.operator_keys, |key| {
                key.public_record()
            }),
            epoch_root: map_root("MIGRATION-EPOCHS", &self.migration_epochs, |epoch| {
                epoch.public_record()
            }),
            request_root: map_root("ROTATION-REQUESTS", &self.rotation_requests, |request| {
                request.public_record()
            }),
            privacy_proof_root: map_root("PRIVACY-PROOFS", &self.privacy_proofs, |proof| {
                proof.public_record()
            }),
            replay_fence_root: map_root("REPLAY-FENCES", &self.replay_fences, |fence| {
                fence.public_record()
            }),
            watcher_evidence_root: map_root(
                "BRIDGE-WATCHER-EVIDENCE",
                &self.bridge_watcher_evidence,
                |evidence| evidence.public_record(),
            ),
            contract_policy_root: map_root(
                "CONTRACT-POLICIES",
                &self.contract_policies,
                |policy| policy.public_record(),
            ),
            batch_root: map_root("LOW-FEE-BATCHES", &self.batches, |batch| {
                batch.public_record()
            }),
            receipt_root: map_root("SETTLEMENT-RECEIPTS", &self.receipts, |receipt| {
                receipt.public_record()
            }),
            release_gate_root: map_root("RELEASE-GATES", &self.release_gates, |gate| {
                gate.public_record()
            }),
            remediation_root: map_root("REMEDIATION-QUEUE", &self.remediation_queue, |item| {
                item.public_record()
            }),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "module": "private_l2_pq_confidential_pq_key_rotation_migration_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record()
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

    fn validate_capacity_for_domain(&self, domain: KeyDomain) -> Result<()> {
        let ok = match domain {
            KeyDomain::Account => self.account_keys.len() < MAX_ACCOUNT_KEYS,
            KeyDomain::Session => self.session_keys.len() < MAX_SESSION_KEYS,
            KeyDomain::BridgeWatcher => self.bridge_watchers.len() < MAX_BRIDGE_WATCHERS,
            KeyDomain::Contract => self.contract_keys.len() < MAX_CONTRACT_KEYS,
            KeyDomain::WalletApi => self.wallet_api_key_records.len() < MAX_WALLET_API_KEYS,
            KeyDomain::Operator => self.operator_keys.len() < MAX_RELEASE_GATES,
        };
        if ok {
            Ok(())
        } else {
            Err("key domain capacity exhausted".to_string())
        }
    }

    fn key_by_domain(&self, domain: KeyDomain, key_id: &str) -> Option<&KeyRecord> {
        match domain {
            KeyDomain::Account => self.account_keys.get(key_id),
            KeyDomain::Session => self.session_keys.get(key_id),
            KeyDomain::BridgeWatcher => self.bridge_watchers.get(key_id),
            KeyDomain::Contract => self.contract_keys.get(key_id),
            KeyDomain::WalletApi => self.wallet_api_key_records.get(key_id),
            KeyDomain::Operator => self.operator_keys.get(key_id),
        }
    }

    fn key_by_domain_mut(&mut self, domain: KeyDomain, key_id: &str) -> Option<&mut KeyRecord> {
        match domain {
            KeyDomain::Account => self.account_keys.get_mut(key_id),
            KeyDomain::Session => self.session_keys.get_mut(key_id),
            KeyDomain::BridgeWatcher => self.bridge_watchers.get_mut(key_id),
            KeyDomain::Contract => self.contract_keys.get_mut(key_id),
            KeyDomain::WalletApi => self.wallet_api_key_records.get_mut(key_id),
            KeyDomain::Operator => self.operator_keys.get_mut(key_id),
        }
    }

    fn apply_key_transition(&mut self, request: &RotationRequest) -> Result<()> {
        let old_generation = match self.key_by_domain(request.domain, &request.old_key_id) {
            Some(old_key) => old_key.generation,
            None => return Err("old key missing during transition".to_string()),
        };
        if let Some(old_key) = self.key_by_domain_mut(request.domain, &request.old_key_id) {
            old_key.status = KeyStatus::GracePeriod;
            old_key.last_request_id = Some(request.request_id.clone());
        }
        if let Some(new_key) = self.key_by_domain_mut(request.domain, &request.new_key_id) {
            new_key.status = KeyStatus::Active;
            new_key.generation = old_generation.saturating_add(1).max(new_key.generation);
            new_key.last_request_id = Some(request.request_id.clone());
            Ok(())
        } else {
            Err("new key missing during transition".to_string())
        }
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

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PQ-KEY-ROTATION-MIGRATION-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-KEY-ROTATION-MIGRATION-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-KEY-ROTATION-MIGRATION-FIXED",
        &[HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let root = domain_hash(
        "PRIVATE-L2-PQ-KEY-ROTATION-MIGRATION-ID",
        &[HashPart::Str(prefix), HashPart::Json(&json!(parts))],
        16,
    );
    format!("{prefix}-{root}")
}

pub fn map_records<T, F>(values: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    let mut object = serde_json::Map::new();
    for (key, value) in values {
        object.insert(key.clone(), public_record(value));
    }
    Value::Object(object)
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

trait OptionStringFallback {
    fn fallback_string(self, fallback: &str) -> String;
}

impl OptionStringFallback for Option<String> {
    fn fallback_string(self, fallback: &str) -> String {
        match self {
            Some(value) => value,
            None => fallback.to_string(),
        }
    }
}
