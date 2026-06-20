use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_INTENT_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-intent-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_INTENT_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_HEIGHT: u64 = 1_884_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_644_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_EXECUTION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_PRECONFIRMATION_TTL_MS: u64 = 1_250;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 28;
pub const DEFAULT_MIN_SURPLUS_REBATE_BPS: u64 = 6;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_MIN_WITNESS_ESCROW_MICRO_UNITS: u64 = 8_000_000;
pub const DEFAULT_SOLVER_BOND_MICRO_UNITS: u64 = 12_000_000;
pub const DEFAULT_SLASHING_ESCROW_MICRO_UNITS: u64 = 120_000_000;
pub const DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 = 500_000_000;
pub const DEFAULT_MAX_CALLDATA_BYTES: u64 = 131_072;
pub const DEFAULT_MAX_BUNDLE_ITEMS: usize = 256;
pub const DEFAULT_MAX_PARALLEL_EXECUTION_SHARDS: u16 = 64;
pub const MAX_SEALED_INTENTS: usize = 524_288;
pub const MAX_CALLDATA_BUNDLES: usize = 524_288;
pub const MAX_SOLVER_BIDS: usize = 1_048_576;
pub const MAX_EXECUTION_COMMITMENTS: usize = 1_048_576;
pub const MAX_WITNESS_ESCROWS: usize = 524_288;
pub const MAX_FEE_REBATES: usize = 1_048_576;
pub const MAX_PRECONFIRMATION_RECEIPTS: usize = 1_048_576;
pub const MAX_PRIVACY_FENCES: usize = 1_048_576;
pub const MAX_NULLIFIER_FENCES: usize = 1_048_576;
pub const MAX_SLASHING_EVIDENCE: usize = 262_144;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-contract-intent-auction-v1";
pub const PQ_ENCRYPTION_SUITE: &str = "ML-KEM-1024+hybrid-forward-secret-calldata-bundle-v1";
pub const CONTRACT_INTENT_SUITE: &str = "confidential-contract-intent-sealed-orderflow-v1";
pub const AUCTION_CLEARING_SUITE: &str = "surplus-maximizing-private-batch-auction-v1";
pub const EXECUTION_COMMITMENT_SUITE: &str = "zk-confidential-contract-execution-commitment-v1";
pub const WITNESS_ESCROW_SUITE: &str = "post-quantum-witness-escrow-and-release-v1";
pub const PRECONFIRMATION_SUITE: &str = "low-latency-private-preconfirmation-receipt-v1";
pub const PRIVACY_FENCE_SUITE: &str = "nullifier-and-linkability-fence-v1";
pub const SLASHING_EVIDENCE_SUITE: &str = "pq-signed-auction-misbehavior-evidence-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-record-v1";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractIntentKind {
    Call,
    Create,
    DefiSwap,
    VaultDeposit,
    VaultWithdraw,
    LendingBorrow,
    LendingRepay,
    PerpsOpen,
    PerpsClose,
    BridgeMessage,
    BatchNetting,
    LiquidationProtection,
}
impl ContractIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Create => "create",
            Self::DefiSwap => "defi_swap",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::PerpsOpen => "perps_open",
            Self::PerpsClose => "perps_close",
            Self::BridgeMessage => "bridge_message",
            Self::BatchNetting => "batch_netting",
            Self::LiquidationProtection => "liquidation_protection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    Bundled,
    Bidding,
    BidSelected,
    ExecutionCommitted,
    Preconfirmed,
    Settled,
    Rebated,
    Slashed,
    Rejected,
    Expired,
}
impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Bundled => "bundled",
            Self::Bidding => "bidding",
            Self::BidSelected => "bid_selected",
            Self::ExecutionCommitted => "execution_committed",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataBundleStatus {
    Encrypted,
    AvailabilityLocked,
    WitnessAssigned,
    Ready,
    Executed,
    Expired,
    Slashed,
}
impl CalldataBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::AvailabilityLocked => "availability_locked",
            Self::WitnessAssigned => "witness_assigned",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBidStatus {
    Committed,
    Revealed,
    Eligible,
    Selected,
    Preconfirmed,
    Settled,
    Rejected,
    Expired,
    Slashed,
}
impl SolverBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Committed,
    WitnessEscrowed,
    Proving,
    Preconfirmed,
    Finalized,
    Disputed,
    Reverted,
    Slashed,
}
impl ExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::WitnessEscrowed => "witness_escrowed",
            Self::Proving => "proving",
            Self::Preconfirmed => "preconfirmed",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Open,
    Locked,
    Released,
    PartiallyReleased,
    Forfeited,
    Disputed,
    Expired,
}
impl EscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::PartiallyReleased => "partially_released",
            Self::Forfeited => "forfeited",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Accrued,
    Claimable,
    Claimed,
    Expired,
    ClawedBack,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Issued,
    Aggregated,
    Honored,
    Challenged,
    Finalized,
    Expired,
    Slashed,
}
impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Aggregated => "aggregated",
            Self::Honored => "honored",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Armed,
    Satisfied,
    Violated,
    Released,
    Expired,
}
impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Armed => "armed",
            Self::Satisfied => "satisfied",
            Self::Violated => "violated",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Submitted,
    Accepted,
    Rejected,
    UnderReview,
    Executed,
    Appealed,
}
impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::UnderReview => "under_review",
            Self::Executed => "executed",
            Self::Appealed => "appealed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Equivocation,
    InvalidReveal,
    LateExecution,
    CalldataWithholding,
    WitnessWithholding,
    FenceViolation,
    NullifierReuse,
    FeeOvercharge,
    PreconfirmationDefault,
    InvalidProof,
    Censorship,
}
impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidReveal => "invalid_reveal",
            Self::LateExecution => "late_execution",
            Self::CalldataWithholding => "calldata_withholding",
            Self::WitnessWithholding => "witness_withholding",
            Self::FenceViolation => "fence_violation",
            Self::NullifierReuse => "nullifier_reuse",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PreconfirmationDefault => "preconfirmation_default",
            Self::InvalidProof => "invalid_proof",
            Self::Censorship => "censorship",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub pq_encryption_suite: String,
    pub contract_intent_suite: String,
    pub auction_clearing_suite: String,
    pub execution_commitment_suite: String,
    pub witness_escrow_suite: String,
    pub preconfirmation_suite: String,
    pub privacy_fence_suite: String,
    pub slashing_evidence_suite: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub execution_ttl_blocks: u64,
    pub preconfirmation_ttl_ms: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_witness_escrow_micro_units: u64,
    pub solver_bond_micro_units: u64,
    pub slashing_escrow_micro_units: u64,
    pub rebate_budget_micro_units: u64,
    pub max_calldata_bytes: u64,
    pub max_bundle_items: usize,
    pub max_parallel_execution_shards: u16,
    pub require_pq_authorization: bool,
    pub require_encrypted_calldata: bool,
    pub allow_low_fee_sponsorship: bool,
    pub enable_private_preconfirmations: bool,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub sealed_intents: u64,
    pub calldata_bundles: u64,
    pub solver_bids: u64,
    pub execution_commitments: u64,
    pub witness_escrows: u64,
    pub fee_rebates: u64,
    pub preconfirmation_receipts: u64,
    pub privacy_fences: u64,
    pub nullifier_fences: u64,
    pub slashing_evidence: u64,
    pub public_records: u64,
    pub settled_intents: u64,
    pub rejected_intents: u64,
    pub slashed_solvers: u64,
    pub total_fees_reserved_micro_units: u64,
    pub total_rebates_claimable_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub sealed_intent_root: String,
    pub calldata_bundle_root: String,
    pub solver_bid_root: String,
    pub execution_commitment_root: String,
    pub witness_escrow_root: String,
    pub fee_rebate_root: String,
    pub preconfirmation_receipt_root: String,
    pub privacy_fence_root: String,
    pub nullifier_fence_root: String,
    pub slashing_evidence_root: String,
    pub public_event_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedContractIntent {
    pub intent_id: String,
    pub kind: ContractIntentKind,
    pub status: IntentStatus,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub sealed_payload_root: String,
    pub calldata_bundle_id: String,
    pub policy_root: String,
    pub max_fee_micro_units: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub authorization_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub pq_signature_root: String,
    pub public_metadata_root: String,
}

impl SealedContractIntent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("SEALED-CONTRACT-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCalldataBundle {
    pub bundle_id: String,
    pub intent_id: String,
    pub status: CalldataBundleStatus,
    pub encryption_suite: String,
    pub ciphertext_root: String,
    pub recipient_key_commitment_root: String,
    pub availability_root: String,
    pub size_bytes: u64,
    pub item_count: u64,
    pub witness_policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedCalldataBundle {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("ENCRYPTED-CALLDATA-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBid {
    pub bid_id: String,
    pub intent_id: String,
    pub solver_commitment: String,
    pub status: SolverBidStatus,
    pub bid_commitment_root: String,
    pub reveal_root: String,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_bps: u64,
    pub bond_micro_units: u64,
    pub latency_budget_ms: u64,
    pub execution_shard: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub pq_signature_root: String,
}

impl SolverBid {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("SOLVER-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCommitment {
    pub execution_id: String,
    pub intent_id: String,
    pub bid_id: String,
    pub status: ExecutionStatus,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub trace_commitment_root: String,
    pub proof_commitment_root: String,
    pub gas_commitment_root: String,
    pub fee_charged_micro_units: u64,
    pub created_at_height: u64,
    pub finality_height: u64,
    pub executor_signature_root: String,
}

impl ExecutionCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("EXECUTION-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEscrow {
    pub escrow_id: String,
    pub intent_id: String,
    pub execution_id: String,
    pub solver_commitment: String,
    pub status: EscrowStatus,
    pub witness_root: String,
    pub encrypted_witness_root: String,
    pub escrow_amount_micro_units: u64,
    pub release_condition_root: String,
    pub opened_at_height: u64,
    pub release_height: u64,
    pub arbiter_set_root: String,
}

impl WitnessEscrow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("WITNESS-ESCROW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub execution_id: String,
    pub recipient_commitment: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub gross_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub surplus_micro_units: u64,
    pub claim_nullifier: String,
    pub reserved_at_height: u64,
    pub claimable_at_height: u64,
    pub sponsor_root: String,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub bid_id: String,
    pub execution_id: String,
    pub status: PreconfirmationStatus,
    pub sequencer_commitment: String,
    pub deadline_ms: u64,
    pub preconfirmation_root: String,
    pub availability_root: String,
    pub fee_lock_micro_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub aggregate_signature_root: String,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("PRECONFIRMATION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub intent_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub status: FenceStatus,
    pub privacy_set_root: String,
    pub min_privacy_set_size: u64,
    pub linkability_tag_root: String,
    pub opened_at_height: u64,
    pub release_height: u64,
    pub auditor_hint_root: String,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub intent_id: String,
    pub nullifier_root: String,
    pub status: FenceStatus,
    pub scope_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub dedupe_proof_root: String,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("NULLIFIER-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub status: SlashingStatus,
    pub subject_id: String,
    pub subject_commitment: String,
    pub intent_id: String,
    pub evidence_root: String,
    pub penalty_micro_units: u64,
    pub reporter_commitment: String,
    pub opened_at_height: u64,
    pub resolved_at_height: u64,
    pub pq_signature_root: String,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub publisher_commitment: String,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("PUBLIC-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub sealed_intents: BTreeMap<String, SealedContractIntent>,
    pub calldata_bundles: BTreeMap<String, EncryptedCalldataBundle>,
    pub solver_bids: BTreeMap<String, SolverBid>,
    pub execution_commitments: BTreeMap<String, ExecutionCommitment>,
    pub witness_escrows: BTreeMap<String, WitnessEscrow>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_events: BTreeMap<String, PublicEvent>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub active_linkability_tags: BTreeSet<String>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            pq_encryption_suite: PQ_ENCRYPTION_SUITE.to_string(),
            contract_intent_suite: CONTRACT_INTENT_SUITE.to_string(),
            auction_clearing_suite: AUCTION_CLEARING_SUITE.to_string(),
            execution_commitment_suite: EXECUTION_COMMITMENT_SUITE.to_string(),
            witness_escrow_suite: WITNESS_ESCROW_SUITE.to_string(),
            preconfirmation_suite: PRECONFIRMATION_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            slashing_evidence_suite: SLASHING_EVIDENCE_SUITE.to_string(),
            fee_asset_id: DEVNET_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            execution_ttl_blocks: DEFAULT_EXECUTION_TTL_BLOCKS,
            preconfirmation_ttl_ms: DEFAULT_PRECONFIRMATION_TTL_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            min_surplus_rebate_bps: DEFAULT_MIN_SURPLUS_REBATE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_witness_escrow_micro_units: DEFAULT_MIN_WITNESS_ESCROW_MICRO_UNITS,
            solver_bond_micro_units: DEFAULT_SOLVER_BOND_MICRO_UNITS,
            slashing_escrow_micro_units: DEFAULT_SLASHING_ESCROW_MICRO_UNITS,
            rebate_budget_micro_units: DEFAULT_REBATE_BUDGET_MICRO_UNITS,
            max_calldata_bytes: DEFAULT_MAX_CALLDATA_BYTES,
            max_bundle_items: DEFAULT_MAX_BUNDLE_ITEMS,
            max_parallel_execution_shards: DEFAULT_MAX_PARALLEL_EXECUTION_SHARDS,
            require_pq_authorization: true,
            require_encrypted_calldata: true,
            allow_low_fee_sponsorship: true,
            enable_private_preconfirmations: true,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("wrong chain id".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security floor too low".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS || self.max_solver_fee_bps > MAX_BPS {
            return Err("fee bps out of range".to_string());
        }
        if self.min_surplus_rebate_bps > self.max_user_fee_bps {
            return Err("rebate floor exceeds user fee cap".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set configuration is invalid".to_string());
        }
        Ok(())
    }
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            sealed_intents: 0,
            calldata_bundles: 0,
            solver_bids: 0,
            execution_commitments: 0,
            witness_escrows: 0,
            fee_rebates: 0,
            preconfirmation_receipts: 0,
            privacy_fences: 0,
            nullifier_fences: 0,
            slashing_evidence: 0,
            public_records: 0,
            settled_intents: 0,
            rejected_intents: 0,
            slashed_solvers: 0,
            total_fees_reserved_micro_units: 0,
            total_rebates_claimable_micro_units: 0,
        }
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::empty(),
            sealed_intents: BTreeMap::new(),
            calldata_bundles: BTreeMap::new(),
            solver_bids: BTreeMap::new(),
            execution_commitments: BTreeMap::new(),
            witness_escrows: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_events: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            active_linkability_tags: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        let owner = commitment_id("account", "devnet-alice-contract-wallet");
        let contract = commitment_id("contract", "devnet-private-defi-router");
        let nullifier = payload_root(
            "DEVNET-NULLIFIER",
            &json!({"note":"alice-0","scope":"contract-intent"}),
        );
        let bundle = state
            .register_encrypted_calldata_bundle(
                "devnet-bundle",
                "pending",
                "devnet-ciphertext-root",
                "devnet-recipient-root",
                4096,
                3,
                DEVNET_L2_HEIGHT,
            )
            .expect("devnet bundle");
        let intent = state
            .seal_contract_intent(
                ContractIntentKind::DefiSwap,
                &owner,
                &contract,
                "devnet-sealed-payload",
                &bundle.bundle_id,
                "devnet-policy-root",
                42_000,
                16,
                8,
                DEFAULT_BATCH_PRIVACY_SET_SIZE,
                &nullifier,
                "devnet-auth-root",
                DEVNET_L2_HEIGHT,
            )
            .expect("devnet intent");
        let bid = state
            .submit_solver_bid(
                &intent.intent_id,
                "devnet-solver-alpha",
                "devnet-bid-commitment",
                "devnet-reveal-root",
                250_000,
                10,
                DEFAULT_SOLVER_BOND_MICRO_UNITS,
                900,
                7,
                DEVNET_L2_HEIGHT + 1,
            )
            .expect("devnet bid");
        let exec = state
            .commit_execution(
                &intent.intent_id,
                &bid.bid_id,
                "devnet-pre-state",
                "devnet-post-state",
                "devnet-trace",
                "devnet-proof",
                "devnet-gas",
                31_000,
                DEVNET_L2_HEIGHT + 2,
            )
            .expect("devnet execution");
        state
            .open_witness_escrow(
                &intent.intent_id,
                &exec.execution_id,
                "devnet-solver-alpha",
                "devnet-witness",
                "devnet-encrypted-witness",
                DEFAULT_MIN_WITNESS_ESCROW_MICRO_UNITS,
                "devnet-release-condition",
                DEVNET_L2_HEIGHT + 2,
            )
            .expect("devnet escrow");
        state
            .issue_preconfirmation(
                &intent.intent_id,
                &bid.bid_id,
                &exec.execution_id,
                "devnet-sequencer",
                "devnet-preconf",
                "devnet-availability",
                31_000,
                DEVNET_L2_HEIGHT + 2,
            )
            .expect("devnet preconfirmation");
        state
            .arm_privacy_fence(
                &intent.intent_id,
                "intent",
                &intent.intent_id,
                "devnet-privacy-set",
                DEFAULT_BATCH_PRIVACY_SET_SIZE,
                "devnet-linkability-tag",
                DEVNET_L2_HEIGHT + 2,
            )
            .expect("devnet privacy fence");
        state
            .arm_nullifier_fence(
                &intent.intent_id,
                &nullifier,
                "devnet-nullifier-scope",
                DEVNET_L2_HEIGHT + 2,
            )
            .expect("devnet nullifier fence");
        state
            .reserve_fee_rebate(
                &intent.intent_id,
                &exec.execution_id,
                &owner,
                31_000,
                3_100,
                250_000,
                "devnet-claim-nullifier",
                DEVNET_L2_HEIGHT + 3,
                "devnet-sponsor-root",
            )
            .expect("devnet rebate");
        state
            .publish_public_event(
                "devnet_runtime_ready",
                &intent.intent_id,
                &intent.record_root(),
                &json!({"lane":"pq-confidential-contract-intent-auction"}),
                DEVNET_L2_HEIGHT + 3,
                "devnet-operator",
            )
            .expect("devnet public event");
        state
    }

    pub fn seal_contract_intent(
        &mut self,
        kind: ContractIntentKind,
        owner_commitment: &str,
        contract_commitment: &str,
        sealed_payload_root: &str,
        calldata_bundle_id: &str,
        policy_root: &str,
        max_fee_micro_units: u64,
        max_solver_fee_bps: u64,
        min_rebate_bps: u64,
        privacy_set_size: u64,
        nullifier_root: &str,
        authorization_root: &str,
        created_at_height: u64,
    ) -> Result<SealedContractIntent> {
        self.ensure_capacity(
            self.sealed_intents.len(),
            MAX_SEALED_INTENTS,
            "sealed intents",
        )?;
        if max_solver_fee_bps > self.config.max_solver_fee_bps {
            return Err("solver fee exceeds runtime cap".to_string());
        }
        if min_rebate_bps < self.config.min_surplus_rebate_bps {
            return Err("rebate below configured floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured floor".to_string());
        }
        self.ensure_new_nullifier(nullifier_root)?;
        let intent_id = intent_id(
            kind,
            owner_commitment,
            contract_commitment,
            sealed_payload_root,
            nullifier_root,
            created_at_height,
        );
        let rec = SealedContractIntent {
            intent_id: intent_id.clone(),
            kind,
            status: IntentStatus::Sealed,
            owner_commitment: owner_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            sealed_payload_root: sealed_payload_root.to_string(),
            calldata_bundle_id: calldata_bundle_id.to_string(),
            policy_root: policy_root.to_string(),
            max_fee_micro_units,
            max_solver_fee_bps,
            min_rebate_bps,
            privacy_set_size,
            nullifier_root: nullifier_root.to_string(),
            authorization_root: authorization_root.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(self.config.intent_ttl_blocks),
            pq_signature_root: payload_root(
                "INTENT-PQ-SIGNATURE",
                &json!({"intent_id":intent_id,"authorization_root":authorization_root}),
            ),
            public_metadata_root: payload_root(
                "INTENT-PUBLIC-METADATA",
                &json!({"kind":kind.as_str(),"privacy_set_size":privacy_set_size}),
            ),
        };
        self.consumed_nullifiers.insert(nullifier_root.to_string());
        self.counters.sealed_intents += 1;
        self.sealed_intents.insert(intent_id, rec.clone());
        Ok(rec)
    }

    pub fn register_encrypted_calldata_bundle(
        &mut self,
        label: &str,
        intent_id: &str,
        ciphertext_root: &str,
        recipient_key_commitment_root: &str,
        size_bytes: u64,
        item_count: u64,
        created_at_height: u64,
    ) -> Result<EncryptedCalldataBundle> {
        self.ensure_capacity(
            self.calldata_bundles.len(),
            MAX_CALLDATA_BUNDLES,
            "calldata bundles",
        )?;
        if size_bytes > self.config.max_calldata_bytes {
            return Err("calldata bundle too large".to_string());
        }
        if item_count as usize > self.config.max_bundle_items {
            return Err("calldata bundle has too many items".to_string());
        }
        let bundle_id = calldata_bundle_id(label, intent_id, ciphertext_root, created_at_height);
        let rec = EncryptedCalldataBundle {
            bundle_id: bundle_id.clone(),
            intent_id: intent_id.to_string(),
            status: CalldataBundleStatus::Encrypted,
            encryption_suite: self.config.pq_encryption_suite.clone(),
            ciphertext_root: ciphertext_root.to_string(),
            recipient_key_commitment_root: recipient_key_commitment_root.to_string(),
            availability_root: payload_root(
                "CALLDATA-AVAILABILITY",
                &json!({"bundle_id":bundle_id,"recipient_key_commitment_root":recipient_key_commitment_root}),
            ),
            size_bytes,
            item_count,
            witness_policy_root: payload_root(
                "CALLDATA-WITNESS-POLICY",
                &json!({"bundle_id":bundle_id,"max_items":self.config.max_bundle_items}),
            ),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(self.config.intent_ttl_blocks),
        };
        self.counters.calldata_bundles += 1;
        self.calldata_bundles.insert(bundle_id, rec.clone());
        Ok(rec)
    }

    pub fn submit_solver_bid(
        &mut self,
        intent_id: &str,
        solver_commitment: &str,
        bid_commitment_root: &str,
        reveal_root: &str,
        expected_surplus_micro_units: u64,
        solver_fee_bps: u64,
        bond_micro_units: u64,
        latency_budget_ms: u64,
        execution_shard: u16,
        created_at_height: u64,
    ) -> Result<SolverBid> {
        self.ensure_capacity(self.solver_bids.len(), MAX_SOLVER_BIDS, "solver bids")?;
        if !self.sealed_intents.contains_key(intent_id) {
            return Err("unknown intent".to_string());
        }
        if solver_fee_bps > self.config.max_solver_fee_bps {
            return Err("solver fee exceeds cap".to_string());
        }
        if bond_micro_units < self.config.solver_bond_micro_units {
            return Err("solver bond below floor".to_string());
        }
        if execution_shard >= self.config.max_parallel_execution_shards {
            return Err("execution shard out of range".to_string());
        }
        let bid_id = solver_bid_id(
            intent_id,
            solver_commitment,
            bid_commitment_root,
            created_at_height,
        );
        let rec = SolverBid {
            bid_id: bid_id.clone(),
            intent_id: intent_id.to_string(),
            solver_commitment: solver_commitment.to_string(),
            status: SolverBidStatus::Committed,
            bid_commitment_root: bid_commitment_root.to_string(),
            reveal_root: reveal_root.to_string(),
            expected_surplus_micro_units,
            solver_fee_bps,
            bond_micro_units,
            latency_budget_ms,
            execution_shard,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(self.config.bid_ttl_blocks),
            pq_signature_root: payload_root(
                "SOLVER-BID-PQ-SIGNATURE",
                &json!({"bid_id":bid_id,"solver_commitment":solver_commitment}),
            ),
        };
        self.counters.solver_bids += 1;
        self.solver_bids.insert(bid_id, rec.clone());
        Ok(rec)
    }

    pub fn commit_execution(
        &mut self,
        intent_id: &str,
        bid_id: &str,
        pre_state_root: &str,
        post_state_root: &str,
        trace_commitment_root: &str,
        proof_commitment_root: &str,
        gas_commitment_root: &str,
        fee_charged_micro_units: u64,
        created_at_height: u64,
    ) -> Result<ExecutionCommitment> {
        self.ensure_capacity(
            self.execution_commitments.len(),
            MAX_EXECUTION_COMMITMENTS,
            "execution commitments",
        )?;
        let intent = self
            .sealed_intents
            .get(intent_id)
            .ok_or_else(|| "unknown intent".to_string())?;
        if !self.solver_bids.contains_key(bid_id) {
            return Err("unknown bid".to_string());
        }
        if fee_charged_micro_units > intent.max_fee_micro_units {
            return Err("execution fee exceeds intent cap".to_string());
        }
        let execution_id =
            execution_commitment_id(intent_id, bid_id, post_state_root, created_at_height);
        let rec = ExecutionCommitment {
            execution_id: execution_id.clone(),
            intent_id: intent_id.to_string(),
            bid_id: bid_id.to_string(),
            status: ExecutionStatus::Committed,
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            trace_commitment_root: trace_commitment_root.to_string(),
            proof_commitment_root: proof_commitment_root.to_string(),
            gas_commitment_root: gas_commitment_root.to_string(),
            fee_charged_micro_units,
            created_at_height,
            finality_height: created_at_height.saturating_add(self.config.execution_ttl_blocks),
            executor_signature_root: payload_root(
                "EXECUTION-PQ-SIGNATURE",
                &json!({"execution_id":execution_id,"bid_id":bid_id}),
            ),
        };
        self.counters.execution_commitments += 1;
        self.counters.total_fees_reserved_micro_units = self
            .counters
            .total_fees_reserved_micro_units
            .saturating_add(fee_charged_micro_units);
        self.execution_commitments.insert(execution_id, rec.clone());
        Ok(rec)
    }

    pub fn open_witness_escrow(
        &mut self,
        intent_id: &str,
        execution_id: &str,
        solver_commitment: &str,
        witness_root: &str,
        encrypted_witness_root: &str,
        escrow_amount_micro_units: u64,
        release_condition_root: &str,
        opened_at_height: u64,
    ) -> Result<WitnessEscrow> {
        self.ensure_capacity(
            self.witness_escrows.len(),
            MAX_WITNESS_ESCROWS,
            "witness escrows",
        )?;
        if escrow_amount_micro_units < self.config.min_witness_escrow_micro_units {
            return Err("witness escrow below floor".to_string());
        }
        if !self.execution_commitments.contains_key(execution_id) {
            return Err("unknown execution".to_string());
        }
        let escrow_id =
            witness_escrow_id(intent_id, execution_id, solver_commitment, opened_at_height);
        let rec = WitnessEscrow {
            escrow_id: escrow_id.clone(),
            intent_id: intent_id.to_string(),
            execution_id: execution_id.to_string(),
            solver_commitment: solver_commitment.to_string(),
            status: EscrowStatus::Open,
            witness_root: witness_root.to_string(),
            encrypted_witness_root: encrypted_witness_root.to_string(),
            escrow_amount_micro_units,
            release_condition_root: release_condition_root.to_string(),
            opened_at_height,
            release_height: opened_at_height.saturating_add(self.config.execution_ttl_blocks),
            arbiter_set_root: payload_root(
                "WITNESS-ARBITER-SET",
                &json!({"intent_id":intent_id,"solver_commitment":solver_commitment}),
            ),
        };
        self.counters.witness_escrows += 1;
        self.witness_escrows.insert(escrow_id, rec.clone());
        Ok(rec)
    }

    pub fn reserve_fee_rebate(
        &mut self,
        intent_id: &str,
        execution_id: &str,
        recipient_commitment: &str,
        gross_fee_micro_units: u64,
        rebate_micro_units: u64,
        surplus_micro_units: u64,
        claim_nullifier: &str,
        reserved_at_height: u64,
        sponsor_root: &str,
    ) -> Result<FeeRebate> {
        self.ensure_capacity(self.fee_rebates.len(), MAX_FEE_REBATES, "fee rebates")?;
        if rebate_micro_units > gross_fee_micro_units {
            return Err("rebate exceeds gross fee".to_string());
        }
        self.ensure_new_nullifier(claim_nullifier)?;
        let rebate_id = fee_rebate_id(
            intent_id,
            execution_id,
            recipient_commitment,
            claim_nullifier,
        );
        let rec = FeeRebate {
            rebate_id: rebate_id.clone(),
            intent_id: intent_id.to_string(),
            execution_id: execution_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            status: RebateStatus::Reserved,
            fee_asset_id: self.config.fee_asset_id.clone(),
            gross_fee_micro_units,
            rebate_micro_units,
            surplus_micro_units,
            claim_nullifier: claim_nullifier.to_string(),
            reserved_at_height,
            claimable_at_height: reserved_at_height.saturating_add(1),
            sponsor_root: sponsor_root.to_string(),
        };
        self.consumed_nullifiers.insert(claim_nullifier.to_string());
        self.counters.fee_rebates += 1;
        self.counters.total_rebates_claimable_micro_units = self
            .counters
            .total_rebates_claimable_micro_units
            .saturating_add(rebate_micro_units);
        self.fee_rebates.insert(rebate_id, rec.clone());
        Ok(rec)
    }

    pub fn issue_preconfirmation(
        &mut self,
        intent_id: &str,
        bid_id: &str,
        execution_id: &str,
        sequencer_commitment: &str,
        preconfirmation_root: &str,
        availability_root: &str,
        fee_lock_micro_units: u64,
        issued_at_height: u64,
    ) -> Result<PreconfirmationReceipt> {
        self.ensure_capacity(
            self.preconfirmation_receipts.len(),
            MAX_PRECONFIRMATION_RECEIPTS,
            "preconfirmation receipts",
        )?;
        if !self.config.enable_private_preconfirmations {
            return Err("private preconfirmations disabled".to_string());
        }
        let receipt_id = preconfirmation_receipt_id(
            intent_id,
            bid_id,
            execution_id,
            sequencer_commitment,
            issued_at_height,
        );
        let rec = PreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            intent_id: intent_id.to_string(),
            bid_id: bid_id.to_string(),
            execution_id: execution_id.to_string(),
            status: PreconfirmationStatus::Issued,
            sequencer_commitment: sequencer_commitment.to_string(),
            deadline_ms: self.config.preconfirmation_ttl_ms,
            preconfirmation_root: preconfirmation_root.to_string(),
            availability_root: availability_root.to_string(),
            fee_lock_micro_units,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(1),
            aggregate_signature_root: payload_root(
                "PRECONFIRMATION-AGGREGATE-SIGNATURE",
                &json!({"receipt_id":receipt_id,"sequencer_commitment":sequencer_commitment}),
            ),
        };
        self.counters.preconfirmation_receipts += 1;
        self.preconfirmation_receipts
            .insert(receipt_id, rec.clone());
        Ok(rec)
    }

    pub fn arm_privacy_fence(
        &mut self,
        intent_id: &str,
        subject_kind: &str,
        subject_id: &str,
        privacy_set_root: &str,
        min_privacy_set_size: u64,
        linkability_tag_root: &str,
        opened_at_height: u64,
    ) -> Result<PrivacyFence> {
        self.ensure_capacity(
            self.privacy_fences.len(),
            MAX_PRIVACY_FENCES,
            "privacy fences",
        )?;
        if min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy fence below set floor".to_string());
        }
        if self.active_linkability_tags.contains(linkability_tag_root) {
            return Err("linkability tag already active".to_string());
        }
        let fence_id = privacy_fence_id(intent_id, subject_kind, subject_id, linkability_tag_root);
        let rec = PrivacyFence {
            fence_id: fence_id.clone(),
            intent_id: intent_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            status: FenceStatus::Armed,
            privacy_set_root: privacy_set_root.to_string(),
            min_privacy_set_size,
            linkability_tag_root: linkability_tag_root.to_string(),
            opened_at_height,
            release_height: opened_at_height.saturating_add(self.config.intent_ttl_blocks),
            auditor_hint_root: payload_root(
                "PRIVACY-FENCE-AUDITOR-HINT",
                &json!({"fence_id":fence_id,"subject_kind":subject_kind}),
            ),
        };
        self.active_linkability_tags
            .insert(linkability_tag_root.to_string());
        self.counters.privacy_fences += 1;
        self.privacy_fences.insert(fence_id, rec.clone());
        Ok(rec)
    }

    pub fn arm_nullifier_fence(
        &mut self,
        intent_id: &str,
        nullifier_root: &str,
        scope_root: &str,
        first_seen_height: u64,
    ) -> Result<NullifierFence> {
        self.ensure_capacity(
            self.nullifier_fences.len(),
            MAX_NULLIFIER_FENCES,
            "nullifier fences",
        )?;
        let fence_id = nullifier_fence_id(intent_id, nullifier_root, scope_root);
        let rec = NullifierFence {
            fence_id: fence_id.clone(),
            intent_id: intent_id.to_string(),
            nullifier_root: nullifier_root.to_string(),
            status: FenceStatus::Armed,
            scope_root: scope_root.to_string(),
            first_seen_height,
            expires_at_height: first_seen_height.saturating_add(self.config.intent_ttl_blocks),
            dedupe_proof_root: payload_root(
                "NULLIFIER-DEDUPE-PROOF",
                &json!({"fence_id":fence_id,"nullifier_root":nullifier_root}),
            ),
        };
        self.counters.nullifier_fences += 1;
        self.nullifier_fences.insert(fence_id, rec.clone());
        Ok(rec)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: EvidenceKind,
        subject_id: &str,
        subject_commitment: &str,
        intent_id: &str,
        evidence_root: &str,
        penalty_micro_units: u64,
        reporter_commitment: &str,
        opened_at_height: u64,
    ) -> Result<SlashingEvidence> {
        self.ensure_capacity(
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
            "slashing evidence",
        )?;
        let evidence_id =
            slashing_evidence_id(kind, subject_id, intent_id, evidence_root, opened_at_height);
        let rec = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            kind,
            status: SlashingStatus::Submitted,
            subject_id: subject_id.to_string(),
            subject_commitment: subject_commitment.to_string(),
            intent_id: intent_id.to_string(),
            evidence_root: evidence_root.to_string(),
            penalty_micro_units,
            reporter_commitment: reporter_commitment.to_string(),
            opened_at_height,
            resolved_at_height: 0,
            pq_signature_root: payload_root(
                "SLASHING-EVIDENCE-PQ-SIGNATURE",
                &json!({"evidence_id":evidence_id,"reporter_commitment":reporter_commitment}),
            ),
        };
        self.counters.slashing_evidence += 1;
        self.slashing_evidence.insert(evidence_id, rec.clone());
        Ok(rec)
    }

    pub fn publish_public_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        emitted_at_height: u64,
        publisher_commitment: &str,
    ) -> Result<PublicEvent> {
        self.ensure_capacity(
            self.public_events.len(),
            MAX_PUBLIC_RECORDS,
            "public events",
        )?;
        let payload_root = payload_root("PUBLIC-EVENT-PAYLOAD", payload);
        let event_id = public_event_id(
            event_kind,
            subject_id,
            subject_root,
            &payload_root,
            emitted_at_height,
        );
        let rec = PublicEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_at_height,
            publisher_commitment: publisher_commitment.to_string(),
        };
        self.counters.public_records += 1;
        self.public_events.insert(event_id, rec.clone());
        Ok(rec)
    }

    fn ensure_capacity(&self, len: usize, max: usize, label: &str) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exhausted"))
        } else {
            Ok(())
        }
    }
    fn ensure_new_nullifier(&self, nullifier: &str) -> Result<()> {
        if self.consumed_nullifiers.contains(nullifier) {
            Err("nullifier already consumed".to_string())
        } else {
            Ok(())
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.record_root(),
            sealed_intent_root: records_root(
                "SEALED-INTENT",
                self.sealed_intents
                    .values()
                    .map(SealedContractIntent::public_record)
                    .collect(),
            ),
            calldata_bundle_root: records_root(
                "CALLDATA-BUNDLE",
                self.calldata_bundles
                    .values()
                    .map(EncryptedCalldataBundle::public_record)
                    .collect(),
            ),
            solver_bid_root: records_root(
                "SOLVER-BID",
                self.solver_bids
                    .values()
                    .map(SolverBid::public_record)
                    .collect(),
            ),
            execution_commitment_root: records_root(
                "EXECUTION-COMMITMENT",
                self.execution_commitments
                    .values()
                    .map(ExecutionCommitment::public_record)
                    .collect(),
            ),
            witness_escrow_root: records_root(
                "WITNESS-ESCROW",
                self.witness_escrows
                    .values()
                    .map(WitnessEscrow::public_record)
                    .collect(),
            ),
            fee_rebate_root: records_root(
                "FEE-REBATE",
                self.fee_rebates
                    .values()
                    .map(FeeRebate::public_record)
                    .collect(),
            ),
            preconfirmation_receipt_root: records_root(
                "PRECONFIRMATION-RECEIPT",
                self.preconfirmation_receipts
                    .values()
                    .map(PreconfirmationReceipt::public_record)
                    .collect(),
            ),
            privacy_fence_root: records_root(
                "PRIVACY-FENCE",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record)
                    .collect(),
            ),
            nullifier_fence_root: records_root(
                "NULLIFIER-FENCE",
                self.nullifier_fences
                    .values()
                    .map(NullifierFence::public_record)
                    .collect(),
            ),
            slashing_evidence_root: records_root(
                "SLASHING-EVIDENCE",
                self.slashing_evidence
                    .values()
                    .map(SlashingEvidence::public_record)
                    .collect(),
            ),
            public_event_root: records_root(
                "PUBLIC-EVENT",
                self.public_events
                    .values()
                    .map(PublicEvent::public_record)
                    .collect(),
            ),
            counter_root: self.counters.record_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({"protocol_version": PROTOCOL_VERSION, "chain_id": CHAIN_ID, "schema_version": SCHEMA_VERSION, "public_record_suite": PUBLIC_RECORD_SUITE, "roots": roots.public_record(), "counters": self.counters.public_record(), "state_root": self.state_root()})
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-INTENT-AUCTION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&self.counters.public_record()),
            ],
            32,
        )
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-INTENT-AUCTION-PUBLIC-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}
pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}
pub fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}
pub fn commitment_id(kind: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn intent_id(
    kind: ContractIntentKind,
    owner_commitment: &str,
    contract_commitment: &str,
    sealed_payload_root: &str,
    nullifier_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_payload_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(created_at_height),
        ],
        32,
    )
}
pub fn calldata_bundle_id(
    label: &str,
    intent_id: &str,
    ciphertext_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-CALLDATA-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(intent_id),
            HashPart::Str(ciphertext_root),
            HashPart::U64(created_at_height),
        ],
        32,
    )
}
pub fn solver_bid_id(
    intent_id: &str,
    solver_commitment: &str,
    bid_commitment_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-SOLVER-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(bid_commitment_root),
            HashPart::U64(created_at_height),
        ],
        32,
    )
}
pub fn execution_commitment_id(
    intent_id: &str,
    bid_id: &str,
    post_state_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-EXECUTION-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(bid_id),
            HashPart::Str(post_state_root),
            HashPart::U64(created_at_height),
        ],
        32,
    )
}
pub fn witness_escrow_id(
    intent_id: &str,
    execution_id: &str,
    solver_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-WITNESS-ESCROW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(execution_id),
            HashPart::Str(solver_commitment),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn fee_rebate_id(
    intent_id: &str,
    execution_id: &str,
    recipient_commitment: &str,
    claim_nullifier: &str,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(execution_id),
            HashPart::Str(recipient_commitment),
            HashPart::Str(claim_nullifier),
        ],
        32,
    )
}
pub fn preconfirmation_receipt_id(
    intent_id: &str,
    bid_id: &str,
    execution_id: &str,
    sequencer_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-PRECONFIRMATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(bid_id),
            HashPart::Str(execution_id),
            HashPart::Str(sequencer_commitment),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}
pub fn privacy_fence_id(
    intent_id: &str,
    subject_kind: &str,
    subject_id: &str,
    linkability_tag_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(linkability_tag_root),
        ],
        32,
    )
}
pub fn nullifier_fence_id(intent_id: &str, nullifier_root: &str, scope_root: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(scope_root),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    kind: EvidenceKind,
    subject_id: &str,
    intent_id: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(intent_id),
            HashPart::Str(evidence_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn public_event_id(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-AUCTION-PUBLIC-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::U64(emitted_at_height),
        ],
        32,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicyCapability {
    pub capability_id: String,
    pub lane: String,
    pub objective: String,
    pub privacy_boundary: String,
    pub pq_control: String,
    pub fee_control: String,
    pub public_signal_root: String,
}
impl RuntimePolicyCapability {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root("RUNTIME-POLICY-CAPABILITY", &self.public_record())
    }
}
pub fn runtime_policy_catalog() -> Vec<RuntimePolicyCapability> {
    vec![
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-000".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 0, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-001".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 1, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-002".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 2, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-003".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 3, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-004".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 4, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-005".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 5, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-006".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 6, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-007".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 7, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-008".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 8, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-009".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 9, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-010".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 10, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-011".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 11, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-012".to_string(),
            lane: "solver_bid".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 12, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-013".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 13, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-014".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 14, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-015".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 15, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-016".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 16, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-017".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 17, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-018".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 18, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-019".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 19, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-020".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 20, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-021".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 21, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-022".to_string(),
            lane: "solver_bid".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 22, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-023".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 23, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-024".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 24, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-025".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 25, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-026".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 26, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-027".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 27, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-028".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 28, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-029".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 29, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-030".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 30, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-031".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 31, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-032".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 32, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-033".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 33, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-034".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 34, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-035".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 35, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-036".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 36, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-037".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 37, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-038".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 38, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-039".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 39, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-040".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 40, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-041".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 41, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-042".to_string(),
            lane: "solver_bid".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 42, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-043".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 43, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-044".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 44, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-045".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 45, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-046".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 46, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-047".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 47, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-048".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 48, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-049".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 49, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-050".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 50, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-051".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 51, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-052".to_string(),
            lane: "solver_bid".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 52, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-053".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 53, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-054".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 54, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-055".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 55, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-056".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 56, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-057".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 57, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-058".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 58, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-059".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 59, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-060".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 60, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-061".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 61, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-062".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 62, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-063".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 63, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-064".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 64, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-065".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 65, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-066".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 66, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-067".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 67, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-068".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 68, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-069".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 69, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-070".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 70, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-071".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 71, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-072".to_string(),
            lane: "solver_bid".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 72, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-073".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 73, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-074".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 74, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-075".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 75, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-076".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 76, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-077".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 77, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-078".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 78, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-079".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 79, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-080".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 80, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-081".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 81, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-082".to_string(),
            lane: "solver_bid".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 82, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-083".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 83, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-084".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 84, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-085".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 85, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-086".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 86, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-087".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 87, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-088".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 88, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-089".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 89, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-090".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 90, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-091".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 91, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-092".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 92, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-093".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 93, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-094".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 94, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-095".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 95, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-096".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 96, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-097".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 97, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-098".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 98, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-099".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 99, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-100".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 100, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-101".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 101, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-102".to_string(),
            lane: "solver_bid".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 102, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-103".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 103, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-104".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 104, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-105".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 105, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-106".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 106, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-107".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 107, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-108".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 108, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-109".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 109, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-110".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 110, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-111".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 111, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-112".to_string(),
            lane: "solver_bid".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 112, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-113".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 113, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-114".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 114, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-115".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 115, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-116".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 116, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-117".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 117, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-118".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 118, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-119".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 119, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-120".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 120, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-121".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 121, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-122".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 122, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-123".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 123, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-124".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 124, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-125".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 125, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-126".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 126, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-127".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 127, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-128".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 128, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-129".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 129, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-130".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 130, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-131".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 131, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-132".to_string(),
            lane: "solver_bid".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 132, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-133".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 133, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-134".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 134, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-135".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 135, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-136".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 136, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-137".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 137, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-138".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 138, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-139".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 139, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-140".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 140, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-141".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 141, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-142".to_string(),
            lane: "solver_bid".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 142, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-143".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 143, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-144".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 144, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-145".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 145, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-146".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 146, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-147".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 147, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-148".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 148, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-149".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 149, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-150".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 150, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-151".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 151, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-152".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 152, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-153".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 153, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-154".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 154, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-155".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 155, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-156".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 156, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-157".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 157, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-158".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 158, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-159".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 159, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-160".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 160, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-161".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 161, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-162".to_string(),
            lane: "solver_bid".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 162, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-163".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 163, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-164".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 164, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-165".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 165, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-166".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 166, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-167".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 167, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-168".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 168, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-169".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 169, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-170".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 170, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-171".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 171, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-172".to_string(),
            lane: "solver_bid".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 172, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-173".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 173, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-174".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 174, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-175".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 175, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-176".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 176, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-177".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 177, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-178".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 178, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-179".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 179, "lane": "slashing_evidence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-180".to_string(),
            lane: "sealed_intent".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 180, "lane": "sealed_intent"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-181".to_string(),
            lane: "encrypted_calldata".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 181, "lane": "encrypted_calldata"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-182".to_string(),
            lane: "solver_bid".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 182, "lane": "solver_bid"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-183".to_string(),
            lane: "execution_commitment".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 183, "lane": "execution_commitment"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-184".to_string(),
            lane: "witness_escrow".to_string(),
            objective: "fast_preconfirmation".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 184, "lane": "witness_escrow"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-185".to_string(),
            lane: "fee_rebate".to_string(),
            objective: "witness_accountability".to_string(),
            privacy_boundary: "roots_only_publication".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "surplus_rebate".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 185, "lane": "fee_rebate"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-186".to_string(),
            lane: "preconfirmation".to_string(),
            objective: "quantum_resistance".to_string(),
            privacy_boundary: "nullifier_deduplication".to_string(),
            pq_control: "hybrid_signature_quorum".to_string(),
            fee_control: "solver_fee_cap".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 186, "lane": "preconfirmation"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-187".to_string(),
            lane: "privacy_fence".to_string(),
            objective: "low_fee_execution".to_string(),
            privacy_boundary: "linkability_delay".to_string(),
            pq_control: "shake_domain_separation".to_string(),
            fee_control: "sponsor_budget".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 187, "lane": "privacy_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-188".to_string(),
            lane: "nullifier_fence".to_string(),
            objective: "confidential_contracts".to_string(),
            privacy_boundary: "encrypted_witness".to_string(),
            pq_control: "ml_dsa_authorization".to_string(),
            fee_control: "escrow_slashing".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 188, "lane": "nullifier_fence"}),
            ),
        },
        RuntimePolicyCapability {
            capability_id: "private-auction-capability-189".to_string(),
            lane: "slashing_evidence".to_string(),
            objective: "defi_intent_clearing".to_string(),
            privacy_boundary: "solver_blindness".to_string(),
            pq_control: "ml_kem_calldata".to_string(),
            fee_control: "batch_amortization".to_string(),
            public_signal_root: payload_root(
                "RUNTIME-POLICY-SIGNAL",
                &json!({"index": 189, "lane": "slashing_evidence"}),
            ),
        },
    ]
}
pub fn runtime_policy_catalog_root() -> String {
    merkle_root(
        "RUNTIME-POLICY-CATALOG",
        &runtime_policy_catalog()
            .iter()
            .map(RuntimePolicyCapability::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn deterministic_runtime_probe_000(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-000",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(0),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_001(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-001",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(1),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_002(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-002",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(2),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_003(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-003",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(3),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_004(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-004",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(4),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_005(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-005",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(5),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_006(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-006",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(6),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_007(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-007",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(7),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_008(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-008",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(8),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_009(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-009",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(9),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_010(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-010",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(10),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_011(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-011",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(11),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_012(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-012",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(12),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_013(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-013",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(13),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_014(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-014",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(14),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_015(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-015",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(15),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_016(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-016",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(16),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_017(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-017",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(17),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_018(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-018",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(18),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_019(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-019",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(19),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_020(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-020",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(20),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_021(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-021",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(21),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_022(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-022",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(22),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_023(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-023",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(23),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_024(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-024",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(24),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_025(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-025",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(25),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_026(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-026",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(26),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_027(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-027",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(27),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_028(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-028",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(28),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_029(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-029",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(29),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_030(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-030",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(30),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_031(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-031",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(31),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_032(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-032",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(32),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_033(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-033",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(33),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_034(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-034",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(34),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_035(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-035",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(35),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_036(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-036",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(36),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_037(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-037",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(37),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_038(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-038",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(38),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_039(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-039",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(39),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_040(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-040",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(40),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_041(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-041",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(41),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_042(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-042",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(42),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_043(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-043",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(43),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_044(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-044",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(44),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_045(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-045",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(45),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_046(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-046",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(46),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_047(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-047",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(47),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_048(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-048",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(48),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_049(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-049",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(49),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_050(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-050",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(50),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_051(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-051",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(51),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_052(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-052",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(52),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_053(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-053",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(53),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_054(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-054",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(54),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_055(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-055",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(55),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_056(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-056",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(56),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_057(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-057",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(57),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_058(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-058",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(58),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_059(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-059",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(59),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_060(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-060",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(60),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_061(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-061",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(61),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_062(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-062",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(62),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_063(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-063",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(63),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_064(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-064",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(64),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_065(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-065",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(65),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_066(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-066",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(66),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_067(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-067",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(67),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_068(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-068",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(68),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_069(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-069",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(69),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_070(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-070",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(70),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_071(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-071",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(71),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_072(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-072",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(72),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_073(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-073",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(73),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_074(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-074",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(74),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_075(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-075",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(75),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_076(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-076",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(76),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_077(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-077",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(77),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_078(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-078",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(78),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_079(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-079",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(79),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_080(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-080",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(80),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_081(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-081",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(81),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_082(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-082",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(82),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_083(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-083",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(83),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_084(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-084",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(84),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_085(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-085",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(85),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_086(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-086",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(86),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_087(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-087",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(87),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_088(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-088",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(88),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_089(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-089",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(89),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_090(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-090",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(90),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_091(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-091",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(91),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_092(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-092",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(92),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_093(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-093",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(93),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_094(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-094",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(94),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_095(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-095",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(95),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_096(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-096",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(96),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_097(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-097",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(97),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_098(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-098",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(98),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_099(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-099",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(99),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_100(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-100",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(100),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_101(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-101",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(101),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_102(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-102",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(102),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_103(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-103",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(103),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_104(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-104",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(104),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_105(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-105",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(105),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_106(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-106",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(106),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_107(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-107",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(107),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_108(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-108",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(108),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_109(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-109",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(109),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_110(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-110",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(110),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_111(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-111",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(111),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_112(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-112",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(112),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_113(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-113",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(113),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_114(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-114",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(114),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_115(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-115",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(115),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_116(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-116",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(116),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_117(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-117",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(117),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_118(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-118",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(118),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_119(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-119",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(119),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_120(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-120",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(120),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_121(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-121",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(121),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_122(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-122",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(122),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_123(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-123",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(123),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_124(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-124",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(124),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_125(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-125",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(125),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_126(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-126",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(126),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_127(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-127",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(127),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_128(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-128",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(128),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_129(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-129",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(129),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_130(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-130",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(130),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_131(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-131",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(131),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_132(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-132",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(132),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_133(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-133",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(133),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_134(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-134",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(134),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_135(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-135",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(135),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_136(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-136",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(136),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_137(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-137",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(137),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_138(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-138",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(138),
        ],
        32,
    )
}

pub fn deterministic_runtime_probe_139(subject: &str) -> String {
    domain_hash(
        "PRIVATE-AUCTION-DETERMINISTIC-PROBE-139",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::U64(139),
        ],
        32,
    )
}
