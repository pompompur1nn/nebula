use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalSettlementExitVectorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_SETTLEMENT_EXIT_VECTOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-settlement-exit-vector-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_SETTLEMENT_EXIT_VECTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VECTOR_SUITE: &str = "forced-exit-heavy-gate-canonical-settlement-exit-vector-v1";
pub const SETTLEMENT_RECEIPT_ROOT_SUITE: &str =
    "canonical-settlement-receipt-roots-public-and-encrypted-v1";
pub const EXIT_CLAIM_ROOT_SUITE: &str = "canonical-exit-claim-roots-for-forced-exit-gate-v1";
pub const RELEASE_AUTHORIZATION_LINKAGE_SUITE: &str =
    "canonical-release-authorization-linkage-settlement-exit-v1";
pub const WATCHER_PQ_ROOT_SUITE: &str = "pq-watcher-root-quorum-for-canonical-exit-vector-v1";
pub const RESERVE_LIQUIDITY_SUITE: &str = "reserve-liquidity-envelope-for-canonical-exit-vector-v1";
pub const LOW_FEE_LIMIT_SUITE: &str = "low-fee-settlement-limit-for-canonical-exit-vector-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_260_384;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_LOW_FEE_BATCH_CAP_ATOMIC: u128 = 140_000_000;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MAX_VECTOR_ITEMS: usize = 512;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementExitLane {
    PrivateTransfer,
    ForcedExit,
    LiquidityBackstop,
    EmergencyEscape,
}

impl SettlementExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ForcedExit => "forced_exit",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    Public,
    Encrypted,
    Hybrid,
}

impl ReceiptVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Encrypted => "encrypted",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorCheckKind {
    SettlementReceiptRootBound,
    ExitClaimRootBound,
    ReleaseAuthorizationLinked,
    ReserveCoverageMet,
    LiquidityUnlocked,
    PublicReceiptMaterialPresent,
    EncryptedReceiptMaterialPresent,
    WatcherPqRootQuorumMet,
    LowFeeSettlementLimitMet,
    PrivacyFloorMet,
    MetadataLeakageWithinLimit,
    DisputeWindowElapsed,
}

impl VectorCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementReceiptRootBound => "settlement_receipt_root_bound",
            Self::ExitClaimRootBound => "exit_claim_root_bound",
            Self::ReleaseAuthorizationLinked => "release_authorization_linked",
            Self::ReserveCoverageMet => "reserve_coverage_met",
            Self::LiquidityUnlocked => "liquidity_unlocked",
            Self::PublicReceiptMaterialPresent => "public_receipt_material_present",
            Self::EncryptedReceiptMaterialPresent => "encrypted_receipt_material_present",
            Self::WatcherPqRootQuorumMet => "watcher_pq_root_quorum_met",
            Self::LowFeeSettlementLimitMet => "low_fee_settlement_limit_met",
            Self::PrivacyFloorMet => "privacy_floor_met",
            Self::MetadataLeakageWithinLimit => "metadata_leakage_within_limit",
            Self::DisputeWindowElapsed => "dispute_window_elapsed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Accepted,
    Watch,
    Rejected,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorOutcome {
    Accepted,
    Watch,
    Rejected,
}

impl VectorOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    SettlementReceiptRootMissing,
    ExitClaimRootMissing,
    ReleaseAuthorizationMismatch,
    ReserveCoverageBelowFloor,
    LiquidityLocked,
    PublicReceiptMaterialMissing,
    EncryptedReceiptMaterialMissing,
    WatcherPqRootQuorumMissing,
    LowFeeLimitExceeded,
    PrivacyFloorNotMet,
    MetadataLeakageExceeded,
    DisputeWindowOpen,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SettlementReceiptRootMissing => "settlement_receipt_root_missing",
            Self::ExitClaimRootMissing => "exit_claim_root_missing",
            Self::ReleaseAuthorizationMismatch => "release_authorization_mismatch",
            Self::ReserveCoverageBelowFloor => "reserve_coverage_below_floor",
            Self::LiquidityLocked => "liquidity_locked",
            Self::PublicReceiptMaterialMissing => "public_receipt_material_missing",
            Self::EncryptedReceiptMaterialMissing => "encrypted_receipt_material_missing",
            Self::WatcherPqRootQuorumMissing => "watcher_pq_root_quorum_missing",
            Self::LowFeeLimitExceeded => "low_fee_limit_exceeded",
            Self::PrivacyFloorNotMet => "privacy_floor_not_met",
            Self::MetadataLeakageExceeded => "metadata_leakage_exceeded",
            Self::DisputeWindowOpen => "dispute_window_open",
        }
    }

    pub fn rejects(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub vector_suite: String,
    pub settlement_receipt_root_suite: String,
    pub exit_claim_root_suite: String,
    pub release_authorization_linkage_suite: String,
    pub watcher_pq_root_suite: String,
    pub reserve_liquidity_suite: String,
    pub low_fee_limit_suite: String,
    pub current_height: u64,
    pub dispute_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub min_watcher_quorum: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_metadata_leakage_units: u64,
    pub low_fee_cap_atomic: u128,
    pub low_fee_batch_cap_atomic: u128,
    pub min_reserve_coverage_bps: u64,
    pub require_public_receipt_material: bool,
    pub require_encrypted_receipt_material: bool,
    pub require_release_authorization_linkage: bool,
    pub production_release_allowed: bool,
    pub max_vector_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            vector_suite: VECTOR_SUITE.to_string(),
            settlement_receipt_root_suite: SETTLEMENT_RECEIPT_ROOT_SUITE.to_string(),
            exit_claim_root_suite: EXIT_CLAIM_ROOT_SUITE.to_string(),
            release_authorization_linkage_suite: RELEASE_AUTHORIZATION_LINKAGE_SUITE.to_string(),
            watcher_pq_root_suite: WATCHER_PQ_ROOT_SUITE.to_string(),
            reserve_liquidity_suite: RESERVE_LIQUIDITY_SUITE.to_string(),
            low_fee_limit_suite: LOW_FEE_LIMIT_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            low_fee_batch_cap_atomic: DEFAULT_LOW_FEE_BATCH_CAP_ATOMIC,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            require_public_receipt_material: true,
            require_encrypted_receipt_material: true,
            require_release_authorization_linkage: true,
            production_release_allowed: false,
            max_vector_items: DEFAULT_MAX_VECTOR_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "vector_suite": self.vector_suite,
            "settlement_receipt_root_suite": self.settlement_receipt_root_suite,
            "exit_claim_root_suite": self.exit_claim_root_suite,
            "release_authorization_linkage_suite": self.release_authorization_linkage_suite,
            "watcher_pq_root_suite": self.watcher_pq_root_suite,
            "reserve_liquidity_suite": self.reserve_liquidity_suite,
            "low_fee_limit_suite": self.low_fee_limit_suite,
            "current_height": self.current_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "low_fee_batch_cap_atomic": self.low_fee_batch_cap_atomic.to_string(),
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "require_public_receipt_material": self.require_public_receipt_material,
            "require_encrypted_receipt_material": self.require_encrypted_receipt_material,
            "require_release_authorization_linkage": self.require_release_authorization_linkage,
            "production_release_allowed": self.production_release_allowed,
            "max_vector_items": self.max_vector_items,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptRoot {
    pub receipt_id: String,
    pub lane: SettlementExitLane,
    pub visibility: ReceiptVisibility,
    pub settlement_batch_id: String,
    pub settlement_receipt_root: String,
    pub public_material_root: String,
    pub encrypted_material_root: String,
    pub nullifier_root: String,
    pub amount_atomic: u128,
    pub fee_atomic: u128,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub settled_at_height: u64,
}

impl SettlementReceiptRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "visibility": self.visibility.as_str(),
            "settlement_batch_id": self.settlement_batch_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "public_material_root": self.public_material_root,
            "encrypted_material_root": self.encrypted_material_root,
            "nullifier_root": self.nullifier_root,
            "amount_atomic": self.amount_atomic.to_string(),
            "fee_atomic": self.fee_atomic.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-SETTLEMENT-RECEIPT-ROOT",
            &[
                HashPart::Str(&self.receipt_id),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(self.visibility.as_str()),
                HashPart::Str(&self.settlement_batch_id),
                HashPart::Str(&self.settlement_receipt_root),
                HashPart::Str(&self.public_material_root),
                HashPart::Str(&self.encrypted_material_root),
                HashPart::Str(&self.nullifier_root),
                HashPart::U64(self.settled_at_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimRoot {
    pub claim_id: String,
    pub receipt_id: String,
    pub exit_claim_root: String,
    pub recipient_commitment_root: String,
    pub forced_exit_gate_root: String,
    pub claim_amount_atomic: u128,
    pub claim_fee_atomic: u128,
    pub claim_created_at_height: u64,
    pub release_not_before_height: u64,
}

impl ExitClaimRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "receipt_id": self.receipt_id,
            "exit_claim_root": self.exit_claim_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "forced_exit_gate_root": self.forced_exit_gate_root,
            "claim_amount_atomic": self.claim_amount_atomic.to_string(),
            "claim_fee_atomic": self.claim_fee_atomic.to_string(),
            "claim_created_at_height": self.claim_created_at_height,
            "release_not_before_height": self.release_not_before_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-EXIT-CLAIM-ROOT",
            &[
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.exit_claim_root),
                HashPart::Str(&self.recipient_commitment_root),
                HashPart::Str(&self.forced_exit_gate_root),
                HashPart::U64(self.claim_created_at_height),
                HashPart::U64(self.release_not_before_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAuthorizationLinkage {
    pub linkage_id: String,
    pub claim_id: String,
    pub receipt_id: String,
    pub release_authorization_root: String,
    pub pq_authority_root: String,
    pub dispute_window_root: String,
    pub withdrawal_authorization_root: String,
    pub linked_at_height: u64,
}

impl ReleaseAuthorizationLinkage {
    pub fn public_record(&self) -> Value {
        json!({
            "linkage_id": self.linkage_id,
            "claim_id": self.claim_id,
            "receipt_id": self.receipt_id,
            "release_authorization_root": self.release_authorization_root,
            "pq_authority_root": self.pq_authority_root,
            "dispute_window_root": self.dispute_window_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
            "linked_at_height": self.linked_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-RELEASE-AUTHORIZATION-LINKAGE",
            &[
                HashPart::Str(&self.linkage_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.release_authorization_root),
                HashPart::Str(&self.pq_authority_root),
                HashPart::Str(&self.dispute_window_root),
                HashPart::Str(&self.withdrawal_authorization_root),
                HashPart::U64(self.linked_at_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveLiquidityCheck {
    pub check_id: String,
    pub claim_id: String,
    pub reserve_root: String,
    pub liquidity_bucket_root: String,
    pub reserve_atomic: u128,
    pub pending_liability_atomic: u128,
    pub unlocked_liquidity_atomic: u128,
    pub reserve_coverage_bps: u64,
    pub liquidity_unlocked: bool,
    pub measured_at_height: u64,
}

impl ReserveLiquidityCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "claim_id": self.claim_id,
            "reserve_root": self.reserve_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "reserve_atomic": self.reserve_atomic.to_string(),
            "pending_liability_atomic": self.pending_liability_atomic.to_string(),
            "unlocked_liquidity_atomic": self.unlocked_liquidity_atomic.to_string(),
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "liquidity_unlocked": self.liquidity_unlocked,
            "measured_at_height": self.measured_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-RESERVE-LIQUIDITY-CHECK",
            &[
                HashPart::Str(&self.check_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.reserve_root),
                HashPart::Str(&self.liquidity_bucket_root),
                HashPart::U64(self.reserve_coverage_bps),
                HashPart::Str(bool_str(self.liquidity_unlocked)),
                HashPart::U64(self.measured_at_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherPqRoot {
    pub watcher_root_id: String,
    pub claim_id: String,
    pub watcher_set_root: String,
    pub pq_signature_root: String,
    pub finality_observation_root: String,
    pub signer_count: u64,
    pub quorum_count: u64,
    pub pq_security_bits: u16,
    pub observed_at_height: u64,
}

impl WatcherPqRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_root_id": self.watcher_root_id,
            "claim_id": self.claim_id,
            "watcher_set_root": self.watcher_set_root,
            "pq_signature_root": self.pq_signature_root,
            "finality_observation_root": self.finality_observation_root,
            "signer_count": self.signer_count,
            "quorum_count": self.quorum_count,
            "pq_security_bits": self.pq_security_bits,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-WATCHER-PQ-ROOT",
            &[
                HashPart::Str(&self.watcher_root_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.watcher_set_root),
                HashPart::Str(&self.pq_signature_root),
                HashPart::Str(&self.finality_observation_root),
                HashPart::U64(self.signer_count),
                HashPart::U64(self.quorum_count),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::U64(self.observed_at_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementLimit {
    pub limit_id: String,
    pub claim_id: String,
    pub fee_asset_id: String,
    pub fee_atomic: u128,
    pub cap_atomic: u128,
    pub batch_fee_atomic: u128,
    pub batch_cap_atomic: u128,
    pub sponsor_root: String,
    pub within_limit: bool,
}

impl LowFeeSettlementLimit {
    pub fn public_record(&self) -> Value {
        json!({
            "limit_id": self.limit_id,
            "claim_id": self.claim_id,
            "fee_asset_id": self.fee_asset_id,
            "fee_atomic": self.fee_atomic.to_string(),
            "cap_atomic": self.cap_atomic.to_string(),
            "batch_fee_atomic": self.batch_fee_atomic.to_string(),
            "batch_cap_atomic": self.batch_cap_atomic.to_string(),
            "sponsor_root": self.sponsor_root,
            "within_limit": self.within_limit,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-LOW-FEE-SETTLEMENT-LIMIT",
            &[
                HashPart::Str(&self.limit_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.fee_asset_id),
                HashPart::Str(&self.sponsor_root),
                HashPart::Str(bool_str(self.within_limit)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VectorCheck {
    pub check_id: String,
    pub claim_id: String,
    pub kind: VectorCheckKind,
    pub status: CheckStatus,
    pub evidence_root: String,
    pub rejection_reason: RejectionReason,
    pub observed: String,
}

impl VectorCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "claim_id": self.claim_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "rejection_reason": self.rejection_reason.as_str(),
            "observed": self.observed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-SETTLEMENT-EXIT-VECTOR-CHECK",
            &[
                HashPart::Str(&self.check_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(self.kind.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(self.rejection_reason.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceDecision {
    pub decision_id: String,
    pub claim_id: String,
    pub outcome: VectorOutcome,
    pub reason: RejectionReason,
    pub accepted_check_count: u64,
    pub watch_check_count: u64,
    pub rejected_check_count: u64,
    pub canonical_vector_root: String,
    pub decided_at_height: u64,
}

impl AcceptanceDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "claim_id": self.claim_id,
            "outcome": self.outcome.as_str(),
            "reason": self.reason.as_str(),
            "accepted_check_count": self.accepted_check_count,
            "watch_check_count": self.watch_check_count,
            "rejected_check_count": self.rejected_check_count,
            "canonical_vector_root": self.canonical_vector_root,
            "decided_at_height": self.decided_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-SETTLEMENT-EXIT-VECTOR-DECISION",
            &[
                HashPart::Str(&self.decision_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(self.outcome.as_str()),
                HashPart::Str(self.reason.as_str()),
                HashPart::U64(self.accepted_check_count),
                HashPart::U64(self.watch_check_count),
                HashPart::U64(self.rejected_check_count),
                HashPart::Str(&self.canonical_vector_root),
                HashPart::U64(self.decided_at_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub settlement_receipts: Vec<SettlementReceiptRoot>,
    pub exit_claims: Vec<ExitClaimRoot>,
    pub release_authorizations: Vec<ReleaseAuthorizationLinkage>,
    pub reserve_liquidity_checks: Vec<ReserveLiquidityCheck>,
    pub watcher_pq_roots: Vec<WatcherPqRoot>,
    pub low_fee_limits: Vec<LowFeeSettlementLimit>,
    pub checks: Vec<VectorCheck>,
    pub decisions: Vec<AcceptanceDecision>,
    pub metadata: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            settlement_receipts: Vec::new(),
            exit_claims: Vec::new(),
            release_authorizations: Vec::new(),
            reserve_liquidity_checks: Vec::new(),
            watcher_pq_roots: Vec::new(),
            low_fee_limits: Vec::new(),
            checks: Vec::new(),
            decisions: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn add_vector(
        &mut self,
        receipt: SettlementReceiptRoot,
        claim: ExitClaimRoot,
        authorization: ReleaseAuthorizationLinkage,
        reserve: ReserveLiquidityCheck,
        watcher: WatcherPqRoot,
        low_fee: LowFeeSettlementLimit,
    ) -> Result<AcceptanceDecision> {
        if self.exit_claims.len() >= self.config.max_vector_items {
            return Err("canonical settlement-exit vector capacity exceeded".to_string());
        }
        if receipt.receipt_id != claim.receipt_id {
            return Err("exit claim does not reference settlement receipt".to_string());
        }
        if authorization.claim_id != claim.claim_id
            || authorization.receipt_id != receipt.receipt_id
        {
            return Err(
                "release authorization linkage does not bind receipt and claim".to_string(),
            );
        }
        if reserve.claim_id != claim.claim_id
            || watcher.claim_id != claim.claim_id
            || low_fee.claim_id != claim.claim_id
        {
            return Err(
                "reserve, watcher, or low-fee record is bound to another claim".to_string(),
            );
        }

        let checks = self.evaluate_vector(
            &receipt,
            &claim,
            &authorization,
            &reserve,
            &watcher,
            &low_fee,
        );
        let decision = self.decision_for_claim(&claim.claim_id, &checks);
        self.settlement_receipts.push(receipt);
        self.exit_claims.push(claim);
        self.release_authorizations.push(authorization);
        self.reserve_liquidity_checks.push(reserve);
        self.watcher_pq_roots.push(watcher);
        self.low_fee_limits.push(low_fee);
        self.checks.extend(checks);
        self.decisions.push(decision.clone());
        Ok(decision)
    }

    pub fn evaluate_vector(
        &self,
        receipt: &SettlementReceiptRoot,
        claim: &ExitClaimRoot,
        authorization: &ReleaseAuthorizationLinkage,
        reserve: &ReserveLiquidityCheck,
        watcher: &WatcherPqRoot,
        low_fee: &LowFeeSettlementLimit,
    ) -> Vec<VectorCheck> {
        let mut checks = Vec::new();
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::SettlementReceiptRootBound,
            !receipt.settlement_receipt_root.is_empty(),
            receipt.state_root(),
            RejectionReason::SettlementReceiptRootMissing,
            "settlement receipt root is present",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::ExitClaimRootBound,
            !claim.exit_claim_root.is_empty(),
            claim.state_root(),
            RejectionReason::ExitClaimRootMissing,
            "exit claim root is present",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::ReleaseAuthorizationLinked,
            !self.config.require_release_authorization_linkage
                || authorization.claim_id == claim.claim_id,
            authorization.state_root(),
            RejectionReason::ReleaseAuthorizationMismatch,
            "release authorization binds claim and receipt",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::ReserveCoverageMet,
            reserve.reserve_coverage_bps >= self.config.min_reserve_coverage_bps,
            reserve.state_root(),
            RejectionReason::ReserveCoverageBelowFloor,
            "reserve coverage is at or above configured floor",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::LiquidityUnlocked,
            reserve.liquidity_unlocked
                && reserve.unlocked_liquidity_atomic >= claim.claim_amount_atomic,
            reserve.state_root(),
            RejectionReason::LiquidityLocked,
            "unlocked liquidity covers the claim amount",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::PublicReceiptMaterialPresent,
            !self.config.require_public_receipt_material
                || !receipt.public_material_root.is_empty(),
            receipt.public_material_root.clone(),
            RejectionReason::PublicReceiptMaterialMissing,
            "public receipt material root is present",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::EncryptedReceiptMaterialPresent,
            !self.config.require_encrypted_receipt_material
                || !receipt.encrypted_material_root.is_empty(),
            receipt.encrypted_material_root.clone(),
            RejectionReason::EncryptedReceiptMaterialMissing,
            "encrypted receipt material root is present",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::WatcherPqRootQuorumMet,
            watcher.quorum_count >= self.config.min_watcher_quorum
                && watcher.pq_security_bits >= self.config.min_pq_security_bits,
            watcher.state_root(),
            RejectionReason::WatcherPqRootQuorumMissing,
            "watcher PQ quorum and security bits satisfy the floor",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::LowFeeSettlementLimitMet,
            low_fee.within_limit
                && low_fee.fee_atomic <= self.config.low_fee_cap_atomic
                && low_fee.batch_fee_atomic <= self.config.low_fee_batch_cap_atomic,
            low_fee.state_root(),
            RejectionReason::LowFeeLimitExceeded,
            "low-fee settlement limits are within caps",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::PrivacyFloorMet,
            receipt.privacy_set_size >= self.config.min_privacy_set_size,
            receipt.state_root(),
            RejectionReason::PrivacyFloorNotMet,
            "receipt privacy set meets the floor",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::MetadataLeakageWithinLimit,
            receipt.metadata_leakage_units <= self.config.max_metadata_leakage_units,
            receipt.state_root(),
            RejectionReason::MetadataLeakageExceeded,
            "receipt metadata leakage stays within limit",
        ));
        checks.push(make_check(
            &claim.claim_id,
            VectorCheckKind::DisputeWindowElapsed,
            self.config.current_height >= claim.release_not_before_height,
            authorization.dispute_window_root.clone(),
            RejectionReason::DisputeWindowOpen,
            "release height is reachable under the configured dispute window",
        ));
        checks
    }

    pub fn decision_for_claim(&self, claim_id: &str, checks: &[VectorCheck]) -> AcceptanceDecision {
        let accepted_check_count = checks
            .iter()
            .filter(|check| check.status == CheckStatus::Accepted)
            .count() as u64;
        let watch_check_count = checks
            .iter()
            .filter(|check| check.status == CheckStatus::Watch)
            .count() as u64;
        let rejected_check_count = checks
            .iter()
            .filter(|check| check.status == CheckStatus::Rejected)
            .count() as u64;
        let reason = checks
            .iter()
            .find(|check| check.rejection_reason.rejects())
            .map(|check| check.rejection_reason)
            .unwrap_or(RejectionReason::None);
        let outcome = if rejected_check_count > 0 {
            VectorOutcome::Rejected
        } else if watch_check_count > 0 || !self.config.production_release_allowed {
            VectorOutcome::Watch
        } else {
            VectorOutcome::Accepted
        };
        let canonical_vector_root = merkle_root(
            "CANONICAL-SETTLEMENT-EXIT-VECTOR-CHECKS",
            &checks
                .iter()
                .map(|check| json!(check.state_root()))
                .collect::<Vec<_>>(),
        );
        AcceptanceDecision {
            decision_id: stable_id("canonical-vector-decision", claim_id),
            claim_id: claim_id.to_string(),
            outcome,
            reason,
            accepted_check_count,
            watch_check_count,
            rejected_check_count,
            canonical_vector_root,
            decided_at_height: self.config.current_height,
        }
    }

    pub fn settlement_receipt_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-ROOTS",
            &self
                .settlement_receipts
                .iter()
                .map(|receipt| json!(receipt.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn exit_claim_root(&self) -> String {
        merkle_root(
            "CANONICAL-EXIT-CLAIM-ROOTS",
            &self
                .exit_claims
                .iter()
                .map(|claim| json!(claim.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn release_authorization_root(&self) -> String {
        merkle_root(
            "CANONICAL-RELEASE-AUTHORIZATION-LINKAGE-ROOTS",
            &self
                .release_authorizations
                .iter()
                .map(|authorization| json!(authorization.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn reserve_liquidity_root(&self) -> String {
        merkle_root(
            "CANONICAL-RESERVE-LIQUIDITY-ROOTS",
            &self
                .reserve_liquidity_checks
                .iter()
                .map(|reserve| json!(reserve.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn watcher_pq_root(&self) -> String {
        merkle_root(
            "CANONICAL-WATCHER-PQ-ROOTS",
            &self
                .watcher_pq_roots
                .iter()
                .map(|watcher| json!(watcher.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_limit_root(&self) -> String {
        merkle_root(
            "CANONICAL-LOW-FEE-LIMIT-ROOTS",
            &self
                .low_fee_limits
                .iter()
                .map(|limit| json!(limit.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn check_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-EXIT-CHECK-ROOTS",
            &self
                .checks
                .iter()
                .map(|check| json!(check.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn decision_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-EXIT-DECISION-ROOTS",
            &self
                .decisions
                .iter()
                .map(|decision| json!(decision.state_root()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "settlement_receipt_root": self.settlement_receipt_root(),
            "exit_claim_root": self.exit_claim_root(),
            "release_authorization_root": self.release_authorization_root(),
            "reserve_liquidity_root": self.reserve_liquidity_root(),
            "watcher_pq_root": self.watcher_pq_root(),
            "low_fee_limit_root": self.low_fee_limit_root(),
            "check_root": self.check_root(),
            "decision_root": self.decision_root(),
            "settlement_receipts": self.settlement_receipts.iter().map(SettlementReceiptRoot::public_record).collect::<Vec<_>>(),
            "exit_claims": self.exit_claims.iter().map(ExitClaimRoot::public_record).collect::<Vec<_>>(),
            "release_authorizations": self.release_authorizations.iter().map(ReleaseAuthorizationLinkage::public_record).collect::<Vec<_>>(),
            "reserve_liquidity_checks": self.reserve_liquidity_checks.iter().map(ReserveLiquidityCheck::public_record).collect::<Vec<_>>(),
            "watcher_pq_roots": self.watcher_pq_roots.iter().map(WatcherPqRoot::public_record).collect::<Vec<_>>(),
            "low_fee_limits": self.low_fee_limits.iter().map(LowFeeSettlementLimit::public_record).collect::<Vec<_>>(),
            "checks": self.checks.iter().map(VectorCheck::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.iter().map(AcceptanceDecision::public_record).collect::<Vec<_>>(),
            "metadata": &self.metadata,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-SETTLEMENT-EXIT-VECTOR-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.settlement_receipt_root()),
                HashPart::Str(&self.exit_claim_root()),
                HashPart::Str(&self.release_authorization_root()),
                HashPart::Str(&self.reserve_liquidity_root()),
                HashPart::Str(&self.watcher_pq_root()),
                HashPart::Str(&self.low_fee_limit_root()),
                HashPart::Str(&self.check_root()),
                HashPart::Str(&self.decision_root()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet());
    state.metadata.insert(
        "fixture".to_string(),
        "canonical settlement-to-exit vector for forced-exit heavy-gate proof".to_string(),
    );
    let receipt_a = devnet_receipt(
        "receipt-a",
        SettlementExitLane::ForcedExit,
        ReceiptVisibility::Hybrid,
        40_000_000_000,
        24_000_000,
        DEFAULT_CURRENT_HEIGHT - 900,
    );
    let claim_a = devnet_claim(
        "claim-a",
        &receipt_a.receipt_id,
        receipt_a.amount_atomic - receipt_a.fee_atomic,
        receipt_a.fee_atomic,
        DEFAULT_CURRENT_HEIGHT - 840,
        DEFAULT_CURRENT_HEIGHT - 120,
    );
    let authorization_a = devnet_authorization("auth-a", &claim_a.claim_id, &receipt_a.receipt_id);
    let reserve_a = devnet_reserve(
        "reserve-a",
        &claim_a.claim_id,
        claim_a.claim_amount_atomic,
        true,
    );
    let watcher_a = devnet_watcher("watcher-a", &claim_a.claim_id, 7, 5, 256);
    let low_fee_a = devnet_low_fee(
        "low-fee-a",
        &claim_a.claim_id,
        claim_a.claim_fee_atomic,
        true,
    );
    let _ = state.add_vector(
        receipt_a,
        claim_a,
        authorization_a,
        reserve_a,
        watcher_a,
        low_fee_a,
    );

    let receipt_b = devnet_receipt(
        "receipt-b",
        SettlementExitLane::PrivateTransfer,
        ReceiptVisibility::Encrypted,
        12_500_000_000,
        42_000_000,
        DEFAULT_CURRENT_HEIGHT - 180,
    );
    let claim_b = devnet_claim(
        "claim-b",
        &receipt_b.receipt_id,
        receipt_b.amount_atomic - receipt_b.fee_atomic,
        receipt_b.fee_atomic,
        DEFAULT_CURRENT_HEIGHT - 160,
        DEFAULT_CURRENT_HEIGHT + 560,
    );
    let authorization_b = devnet_authorization("auth-b", &claim_b.claim_id, &receipt_b.receipt_id);
    let reserve_b = devnet_reserve(
        "reserve-b",
        &claim_b.claim_id,
        claim_b.claim_amount_atomic,
        true,
    );
    let watcher_b = devnet_watcher("watcher-b", &claim_b.claim_id, 5, 5, 256);
    let low_fee_b = devnet_low_fee(
        "low-fee-b",
        &claim_b.claim_id,
        claim_b.claim_fee_atomic,
        false,
    );
    let _ = state.add_vector(
        receipt_b,
        claim_b,
        authorization_b,
        reserve_b,
        watcher_b,
        low_fee_b,
    );
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn root_for_public_record(kind: &str, record: &Value) -> String {
    record_root(kind, record)
}

pub fn canonical_vector_root(state: &State) -> String {
    state.state_root()
}

fn make_check(
    claim_id: &str,
    kind: VectorCheckKind,
    accepted: bool,
    evidence_root: String,
    rejection_reason: RejectionReason,
    observed: &str,
) -> VectorCheck {
    let status = if accepted {
        CheckStatus::Accepted
    } else {
        CheckStatus::Rejected
    };
    let reason = if accepted {
        RejectionReason::None
    } else {
        rejection_reason
    };
    VectorCheck {
        check_id: stable_id(kind.as_str(), claim_id),
        claim_id: claim_id.to_string(),
        kind,
        status,
        evidence_root,
        rejection_reason: reason,
        observed: observed.to_string(),
    }
}

fn devnet_receipt(
    suffix: &str,
    lane: SettlementExitLane,
    visibility: ReceiptVisibility,
    amount_atomic: u128,
    fee_atomic: u128,
    settled_at_height: u64,
) -> SettlementReceiptRoot {
    let receipt_id = stable_id("devnet-receipt", suffix);
    SettlementReceiptRoot {
        settlement_receipt_root: stable_id("settlement-receipt-root", &receipt_id),
        public_material_root: stable_id("public-receipt-material", &receipt_id),
        encrypted_material_root: stable_id("encrypted-receipt-material", &receipt_id),
        nullifier_root: stable_id("receipt-nullifier", &receipt_id),
        receipt_id,
        lane,
        visibility,
        settlement_batch_id: stable_id("settlement-batch", suffix),
        amount_atomic,
        fee_atomic,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        metadata_leakage_units: 1,
        settled_at_height,
    }
}

fn devnet_claim(
    suffix: &str,
    receipt_id: &str,
    claim_amount_atomic: u128,
    claim_fee_atomic: u128,
    claim_created_at_height: u64,
    release_not_before_height: u64,
) -> ExitClaimRoot {
    let claim_id = stable_id("devnet-claim", suffix);
    ExitClaimRoot {
        exit_claim_root: stable_id("exit-claim-root", &claim_id),
        recipient_commitment_root: stable_id("recipient-commitment", &claim_id),
        forced_exit_gate_root: stable_id("forced-exit-heavy-gate", &claim_id),
        claim_id,
        receipt_id: receipt_id.to_string(),
        claim_amount_atomic,
        claim_fee_atomic,
        claim_created_at_height,
        release_not_before_height,
    }
}

fn devnet_authorization(
    suffix: &str,
    claim_id: &str,
    receipt_id: &str,
) -> ReleaseAuthorizationLinkage {
    ReleaseAuthorizationLinkage {
        linkage_id: stable_id("release-linkage", suffix),
        claim_id: claim_id.to_string(),
        receipt_id: receipt_id.to_string(),
        release_authorization_root: stable_id("release-authorization", claim_id),
        pq_authority_root: stable_id("pq-authority", claim_id),
        dispute_window_root: stable_id("dispute-window", claim_id),
        withdrawal_authorization_root: stable_id("withdrawal-authorization", claim_id),
        linked_at_height: DEFAULT_CURRENT_HEIGHT - DEFAULT_RELEASE_DELAY_BLOCKS,
    }
}

fn devnet_reserve(
    suffix: &str,
    claim_id: &str,
    claim_amount_atomic: u128,
    liquidity_unlocked: bool,
) -> ReserveLiquidityCheck {
    ReserveLiquidityCheck {
        check_id: stable_id("reserve-liquidity", suffix),
        claim_id: claim_id.to_string(),
        reserve_root: stable_id("reserve-root", claim_id),
        liquidity_bucket_root: stable_id("liquidity-bucket", claim_id),
        reserve_atomic: claim_amount_atomic * 2,
        pending_liability_atomic: claim_amount_atomic,
        unlocked_liquidity_atomic: claim_amount_atomic + DEFAULT_LOW_FEE_CAP_ATOMIC,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS + 500,
        liquidity_unlocked,
        measured_at_height: DEFAULT_CURRENT_HEIGHT,
    }
}

fn devnet_watcher(
    suffix: &str,
    claim_id: &str,
    signer_count: u64,
    quorum_count: u64,
    pq_security_bits: u16,
) -> WatcherPqRoot {
    WatcherPqRoot {
        watcher_root_id: stable_id("watcher-pq", suffix),
        claim_id: claim_id.to_string(),
        watcher_set_root: stable_id("watcher-set", claim_id),
        pq_signature_root: stable_id("pq-signature", claim_id),
        finality_observation_root: stable_id("finality-observation", claim_id),
        signer_count,
        quorum_count,
        pq_security_bits,
        observed_at_height: DEFAULT_CURRENT_HEIGHT,
    }
}

fn devnet_low_fee(
    suffix: &str,
    claim_id: &str,
    fee_atomic: u128,
    within_limit: bool,
) -> LowFeeSettlementLimit {
    LowFeeSettlementLimit {
        limit_id: stable_id("low-fee-limit", suffix),
        claim_id: claim_id.to_string(),
        fee_asset_id: "xmr-atomic".to_string(),
        fee_atomic,
        cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
        batch_fee_atomic: fee_atomic * 3,
        batch_cap_atomic: DEFAULT_LOW_FEE_BATCH_CAP_ATOMIC,
        sponsor_root: stable_id("low-fee-sponsor", claim_id),
        within_limit,
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-EXIT-VECTOR-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(domain: &str, value: &str) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-EXIT-VECTOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
