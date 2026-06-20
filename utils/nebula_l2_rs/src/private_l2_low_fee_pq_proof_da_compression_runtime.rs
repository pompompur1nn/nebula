use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateL2LowFeePqProofDaCompressionRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_PROOF_DA_COMPRESSION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-proof-da-compression-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_PROOF_DA_COMPRESSION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PROOF_SUITE: &str = "recursive-pq-stark-contract-settlement-v1";
pub const DA_SUITE: &str = "encrypted-erasure-coded-private-da-voucher-market-v1";
pub const COMPRESSION_SUITE: &str = "recursive-proof-da-state-diff-compression-v1";
pub const REBATE_SUITE: &str = "anonymous-low-fee-rebate-accounting-v1";
pub const PRIVACY_SUITE: &str = "monero-l2-private-budget-ledger-v1";
pub const SLASHING_SUITE: &str = "pq-proof-da-compression-slashing-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 2_420_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub max_proof_bundles: usize,
    pub max_da_vouchers: usize,
    pub max_compression_reservations: usize,
    pub max_diff_chunks: usize,
    pub max_prover_bids: usize,
    pub max_da_bids: usize,
    pub max_settlement_coupons: usize,
    pub max_rebate_accounts: usize,
    pub max_privacy_budgets: usize,
    pub max_challenges: usize,
    pub proof_bundle_ttl_blocks: u64,
    pub da_voucher_ttl_blocks: u64,
    pub compression_reservation_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub slash_bps: u64,
    pub emergency_fee_cap_bps: u64,
    pub require_pq_signatures: bool,
    pub require_encrypted_state_diffs: bool,
    pub require_recursive_compression: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            max_proof_bundles: 2_097_152,
            max_da_vouchers: 2_097_152,
            max_compression_reservations: 1_048_576,
            max_diff_chunks: 4_194_304,
            max_prover_bids: 2_097_152,
            max_da_bids: 2_097_152,
            max_settlement_coupons: 2_097_152,
            max_rebate_accounts: 1_048_576,
            max_privacy_budgets: 1_048_576,
            max_challenges: 524_288,
            proof_bundle_ttl_blocks: 32,
            da_voucher_ttl_blocks: 24,
            compression_reservation_ttl_blocks: 16,
            bid_ttl_blocks: 12,
            coupon_ttl_blocks: 48,
            challenge_window_blocks: 96,
            min_privacy_set_size: 65_536,
            batch_privacy_set_size: 524_288,
            min_pq_security_bits: 256,
            max_user_fee_bps: 12,
            target_rebate_bps: 7,
            sponsor_cover_bps: 9_250,
            slash_bps: 2_500,
            emergency_fee_cap_bps: 25,
            require_pq_signatures: true,
            require_encrypted_state_diffs: true,
            require_recursive_compression: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        ensure(!self.l2_network.is_empty(), "l2 network is required")?;
        ensure(
            !self.monero_network.is_empty(),
            "monero network is required",
        )?;
        ensure(!self.fee_asset_id.is_empty(), "fee asset id is required")?;
        ensure(
            self.min_pq_security_bits >= 192,
            "pq security floor is too low",
        )?;
        ensure(
            self.max_user_fee_bps <= self.emergency_fee_cap_bps,
            "normal fee cap exceeds emergency cap",
        )?;
        ensure(
            self.emergency_fee_cap_bps <= MAX_BPS,
            "emergency fee cap exceeds bps scale",
        )?;
        ensure(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "target rebate exceeds user fee cap",
        )?;
        ensure(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover exceeds bps scale",
        )?;
        ensure(self.slash_bps <= MAX_BPS, "slash bps exceeds bps scale")?;
        Ok(())
    }
    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    PrivateContractCall,
    DefiNetting,
    ConfidentialToken,
    MoneroFastExit,
    OracleUpdate,
    BridgeReserve,
    GovernanceAction,
    EmergencyEscape,
}
impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiNetting => "defi_netting",
            Self::ConfidentialToken => "confidential_token",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeReserve => "bridge_reserve",
            Self::GovernanceAction => "governance_action",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleKind {
    ContractExecution,
    DefiSettlement,
    TokenTransfer,
    MoneroAnchor,
    DaAvailability,
    RecursiveAggregate,
    FraudResponse,
    EmergencyEscape,
}
impl ProofBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractExecution => "contract_execution",
            Self::DefiSettlement => "defi_settlement",
            Self::TokenTransfer => "token_transfer",
            Self::MoneroAnchor => "monero_anchor",
            Self::DaAvailability => "da_availability",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::FraudResponse => "fraud_response",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleStatus {
    Committed,
    DaMatched,
    CompressionReserved,
    ProofSubmitted,
    CouponIssued,
    Settled,
    Expired,
    Rejected,
    Slashed,
}
impl ProofBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::DaMatched => "da_matched",
            Self::CompressionReserved => "compression_reserved",
            Self::ProofSubmitted => "proof_submitted",
            Self::CouponIssued => "coupon_issued",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaVoucherKind {
    EncryptedWitness,
    StateDiff,
    CallTrace,
    EventLog,
    MoneroAnchorHint,
    SettlementManifest,
    RecursiveProofHint,
}
impl DaVoucherKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedWitness => "encrypted_witness",
            Self::StateDiff => "state_diff",
            Self::CallTrace => "call_trace",
            Self::EventLog => "event_log",
            Self::MoneroAnchorHint => "monero_anchor_hint",
            Self::SettlementManifest => "settlement_manifest",
            Self::RecursiveProofHint => "recursive_proof_hint",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaVoucherStatus {
    Open,
    BidMatched,
    Published,
    Sampled,
    Settled,
    Expired,
    Slashed,
}
impl DaVoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::BidMatched => "bid_matched",
            Self::Published => "published",
            Self::Sampled => "sampled",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionKind {
    ProofAggregation,
    StateDiffChunking,
    DaDedup,
    CalldataDictionary,
    ReceiptFolding,
    MoneroAnchorRollup,
}
impl CompressionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofAggregation => "proof_aggregation",
            Self::StateDiffChunking => "state_diff_chunking",
            Self::DaDedup => "da_dedup",
            Self::CalldataDictionary => "calldata_dictionary",
            Self::ReceiptFolding => "receipt_folding",
            Self::MoneroAnchorRollup => "monero_anchor_rollup",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionStatus {
    Reserved,
    Materialized,
    Attached,
    Consumed,
    Expired,
    Slashed,
}
impl CompressionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Materialized => "materialized",
            Self::Attached => "attached",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffChunkStatus {
    Submitted,
    VoucherBound,
    Compressed,
    Settled,
    Expired,
    Rejected,
    Slashed,
}
impl DiffChunkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::VoucherBound => "voucher_bound",
            Self::Compressed => "compressed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Matched,
    Locked,
    Filled,
    Expired,
    Slashed,
}
impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Matched => "matched",
            Self::Locked => "locked",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Redeemed,
    Settled,
    Expired,
    Revoked,
}
impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Redeemed => "redeemed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetStatus {
    Open,
    Throttled,
    Exhausted,
    Reset,
    Slashed,
}
impl PrivacyBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Reset => "reset",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidProof,
    MissingDa,
    BadCompression,
    FeeOvercharge,
    PrivacyLeak,
    ExpiredService,
    Equivocation,
}
impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::MissingDa => "missing_da",
            Self::BadCompression => "bad_compression",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
            Self::ExpiredService => "expired_service",
            Self::Equivocation => "equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceAccepted,
    DefenderResponded,
    Resolved,
    Rejected,
    Expired,
}
impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::DefenderResponded => "defender_responded",
            Self::Resolved => "resolved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    ClawedBack,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub proof_bundles_committed: u64,
    pub da_vouchers_opened: u64,
    pub compression_reservations: u64,
    pub encrypted_diff_chunks: u64,
    pub prover_bids_posted: u64,
    pub da_bids_posted: u64,
    pub settlement_coupons_issued: u64,
    pub rebate_events: u64,
    pub privacy_budget_events: u64,
    pub challenges_opened: u64,
    pub slash_events: u64,
    pub settled_bundles: u64,
    pub total_user_fees: u128,
    pub total_rebates: u128,
    pub total_slashed: u128,
    pub total_da_bytes: u64,
    pub total_compressed_bytes: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub proof_bundle_root: String,
    pub da_voucher_root: String,
    pub compression_reservation_root: String,
    pub encrypted_diff_chunk_root: String,
    pub prover_bid_root: String,
    pub da_bid_root: String,
    pub settlement_coupon_root: String,
    pub rebate_account_root: String,
    pub privacy_budget_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub operator_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundleRequest {
    pub lane: SettlementLane,
    pub kind: ProofBundleKind,
    pub owner_commitment: String,
    pub contract_root: String,
    pub public_input_root: String,
    pub witness_commitment_root: String,
    pub pq_signature_root: String,
    pub max_fee: u128,
    pub priority_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundleRecord {
    pub bundle_id: String,
    pub lane: SettlementLane,
    pub kind: ProofBundleKind,
    pub status: ProofBundleStatus,
    pub owner_commitment: String,
    pub contract_root: String,
    pub public_input_root: String,
    pub witness_commitment_root: String,
    pub pq_signature_root: String,
    pub da_voucher_id: Option<String>,
    pub compression_id: Option<String>,
    pub prover_bid_id: Option<String>,
    pub coupon_id: Option<String>,
    pub aggregate_proof_root: String,
    pub verifier_key_root: String,
    pub max_fee: u128,
    pub charged_fee: u128,
    pub rebate_amount: u128,
    pub priority_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
}
impl ProofBundleRecord {
    pub fn public_record(&self) -> Value {
        json!({"bundle_id":self.bundle_id,"lane":self.lane.as_str(),"kind":self.kind.as_str(),"status":self.status.as_str(),"owner_commitment":self.owner_commitment,"contract_root":self.contract_root,"public_input_root":self.public_input_root,"witness_commitment_root":self.witness_commitment_root,"pq_signature_root":self.pq_signature_root,"da_voucher_id":self.da_voucher_id,"compression_id":self.compression_id,"prover_bid_id":self.prover_bid_id,"coupon_id":self.coupon_id,"aggregate_proof_root":self.aggregate_proof_root,"verifier_key_root":self.verifier_key_root,"max_fee":self.max_fee.to_string(),"charged_fee":self.charged_fee.to_string(),"rebate_amount":self.rebate_amount.to_string(),"priority_fee_bps":self.priority_fee_bps,"privacy_set_size":self.privacy_set_size,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"settled_at_height":self.settled_at_height})
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaVoucherRequest {
    pub kind: DaVoucherKind,
    pub sponsor_commitment: String,
    pub payload_root: String,
    pub erasure_root: String,
    pub byte_len: u64,
    pub max_price: u128,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaVoucherRecord {
    pub voucher_id: String,
    pub kind: DaVoucherKind,
    pub status: DaVoucherStatus,
    pub sponsor_commitment: String,
    pub payload_root: String,
    pub erasure_root: String,
    pub publisher_commitment: Option<String>,
    pub bid_id: Option<String>,
    pub byte_len: u64,
    pub max_price: u128,
    pub clearing_price: u128,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
}
impl DaVoucherRecord {
    pub fn public_record(&self) -> Value {
        json!({"voucher_id":self.voucher_id,"kind":self.kind.as_str(),"status":self.status.as_str(),"sponsor_commitment":self.sponsor_commitment,"payload_root":self.payload_root,"erasure_root":self.erasure_root,"publisher_commitment":self.publisher_commitment,"bid_id":self.bid_id,"byte_len":self.byte_len,"max_price":self.max_price.to_string(),"clearing_price":self.clearing_price.to_string(),"privacy_set_size":self.privacy_set_size,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"settled_at_height":self.settled_at_height})
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressionReservationRequest {
    pub kind: CompressionKind,
    pub requester_commitment: String,
    pub input_root: String,
    pub target_ratio_bps: u64,
    pub max_fee: u128,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressionReservationRecord {
    pub compression_id: String,
    pub kind: CompressionKind,
    pub status: CompressionStatus,
    pub requester_commitment: String,
    pub input_root: String,
    pub output_root: String,
    pub compressor_commitment: Option<String>,
    pub target_ratio_bps: u64,
    pub observed_ratio_bps: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub max_fee: u128,
    pub clearing_fee: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}
impl CompressionReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({"compression_id":self.compression_id,"kind":self.kind.as_str(),"status":self.status.as_str(),"requester_commitment":self.requester_commitment,"input_root":self.input_root,"output_root":self.output_root,"compressor_commitment":self.compressor_commitment,"target_ratio_bps":self.target_ratio_bps,"observed_ratio_bps":self.observed_ratio_bps,"input_bytes":self.input_bytes,"output_bytes":self.output_bytes,"max_fee":self.max_fee.to_string(),"clearing_fee":self.clearing_fee.to_string(),"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height})
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateDiffChunkRequest {
    pub bundle_id: String,
    pub domain_commitment: String,
    pub ciphertext_root: String,
    pub key_envelope_root: String,
    pub before_root: String,
    pub after_root: String,
    pub byte_len: u64,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateDiffChunkRecord {
    pub chunk_id: String,
    pub bundle_id: String,
    pub status: DiffChunkStatus,
    pub domain_commitment: String,
    pub ciphertext_root: String,
    pub key_envelope_root: String,
    pub before_root: String,
    pub after_root: String,
    pub da_voucher_id: Option<String>,
    pub compression_id: Option<String>,
    pub byte_len: u64,
    pub compressed_byte_len: u64,
    pub opened_at_height: u64,
    pub settled_at_height: Option<u64>,
}
impl EncryptedStateDiffChunkRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverBidRequest {
    pub prover_commitment: String,
    pub service_kind: ProofBundleKind,
    pub capacity: u64,
    pub price_per_unit: u128,
    pub bond: u128,
    pub pq_attestation_root: String,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverBidRecord {
    pub bid_id: String,
    pub status: BidStatus,
    pub prover_commitment: String,
    pub service_kind: ProofBundleKind,
    pub capacity: u64,
    pub remaining_capacity: u64,
    pub price_per_unit: u128,
    pub bond: u128,
    pub pq_attestation_root: String,
    pub matched_bundle_ids: Vec<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}
impl ProverBidRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaBidRequest {
    pub publisher_commitment: String,
    pub voucher_kind: DaVoucherKind,
    pub byte_capacity: u64,
    pub price_per_byte: u128,
    pub bond: u128,
    pub retrieval_commitment_root: String,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaBidRecord {
    pub bid_id: String,
    pub status: BidStatus,
    pub publisher_commitment: String,
    pub voucher_kind: DaVoucherKind,
    pub byte_capacity: u64,
    pub remaining_bytes: u64,
    pub price_per_byte: u128,
    pub bond: u128,
    pub retrieval_commitment_root: String,
    pub matched_voucher_ids: Vec<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}
impl DaBidRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementCouponRecord {
    pub coupon_id: String,
    pub status: CouponStatus,
    pub bundle_id: String,
    pub da_voucher_id: String,
    pub compression_id: String,
    pub owner_commitment: String,
    pub fee_asset_id: String,
    pub face_value: u128,
    pub discounted_value: u128,
    pub rebate_commitment: String,
    pub nullifier_hash: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub redeemed_at_height: Option<u64>,
}
impl SettlementCouponRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateAccountRecord {
    pub account_id: String,
    pub status: RebateStatus,
    pub owner_commitment: String,
    pub fee_asset_id: String,
    pub accrued: u128,
    pub claimed: u128,
    pub clawed_back: u128,
    pub event_root: String,
    pub last_updated_height: u64,
}
impl RebateAccountRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyBudgetRecord {
    pub budget_id: String,
    pub status: PrivacyBudgetStatus,
    pub subject_commitment: String,
    pub lane: SettlementLane,
    pub epoch: u64,
    pub privacy_set_size: u64,
    pub spent_units: u64,
    pub limit_units: u64,
    pub leak_score_bps: u64,
    pub last_updated_height: u64,
}
impl PrivacyBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeEvidenceRequest {
    pub kind: ChallengeKind,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond: u128,
    pub opened_at_height: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeEvidenceRecord {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub target_id: String,
    pub challenger_commitment: String,
    pub defender_commitment: Option<String>,
    pub evidence_root: String,
    pub response_root: String,
    pub bond: u128,
    pub slash_amount: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}
impl ChallengeEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub proof_bundles: BTreeMap<String, ProofBundleRecord>,
    pub da_vouchers: BTreeMap<String, DaVoucherRecord>,
    pub compression_reservations: BTreeMap<String, CompressionReservationRecord>,
    pub encrypted_diff_chunks: BTreeMap<String, EncryptedStateDiffChunkRecord>,
    pub prover_bids: BTreeMap<String, ProverBidRecord>,
    pub da_bids: BTreeMap<String, DaBidRecord>,
    pub settlement_coupons: BTreeMap<String, SettlementCouponRecord>,
    pub rebate_accounts: BTreeMap<String, RebateAccountRecord>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetRecord>,
    pub challenges: BTreeMap<String, ChallengeEvidenceRecord>,
    pub slashing_events: BTreeMap<String, Value>,
    pub spent_nullifiers: BTreeSet<String>,
    pub operator_commitments: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default runtime config")
    }
}
impl State {
    pub fn new(config: Config) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            proof_bundles: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            compression_reservations: BTreeMap::new(),
            encrypted_diff_chunks: BTreeMap::new(),
            prover_bids: BTreeMap::new(),
            da_bids: BTreeMap::new(),
            settlement_coupons: BTreeMap::new(),
            rebate_accounts: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            operator_commitments: BTreeSet::new(),
        })
    }
    pub fn devnet() -> Self {
        let mut s = Self::default();
        for op in [
            "devnet-sequencer",
            "devnet-prover",
            "devnet-da",
            "watchtower-alpha",
        ] {
            s.operator_commitments.insert(commitment_id("OPERATOR", op));
        }
        s
    }
    pub fn roots(&self) -> Roots {
        let mut r = Roots::default();
        r.config_root = self.config.root();
        r.proof_bundle_root = map_root(
            "PROOF-BUNDLE-ROOT",
            &self.proof_bundles,
            ProofBundleRecord::public_record,
        );
        r.da_voucher_root = map_root(
            "DA-VOUCHER-ROOT",
            &self.da_vouchers,
            DaVoucherRecord::public_record,
        );
        r.compression_reservation_root = map_root(
            "COMPRESSION-ROOT",
            &self.compression_reservations,
            CompressionReservationRecord::public_record,
        );
        r.encrypted_diff_chunk_root = map_root(
            "DIFF-CHUNK-ROOT",
            &self.encrypted_diff_chunks,
            EncryptedStateDiffChunkRecord::public_record,
        );
        r.prover_bid_root = map_root(
            "PROVER-BID-ROOT",
            &self.prover_bids,
            ProverBidRecord::public_record,
        );
        r.da_bid_root = map_root("DA-BID-ROOT", &self.da_bids, DaBidRecord::public_record);
        r.settlement_coupon_root = map_root(
            "COUPON-ROOT",
            &self.settlement_coupons,
            SettlementCouponRecord::public_record,
        );
        r.rebate_account_root = map_root(
            "REBATE-ROOT",
            &self.rebate_accounts,
            RebateAccountRecord::public_record,
        );
        r.privacy_budget_root = map_root(
            "PRIVACY-BUDGET-ROOT",
            &self.privacy_budgets,
            PrivacyBudgetRecord::public_record,
        );
        r.challenge_root = map_root(
            "CHALLENGE-ROOT",
            &self.challenges,
            ChallengeEvidenceRecord::public_record,
        );
        r.slashing_root = value_map_root("SLASHING-ROOT", &self.slashing_events);
        r.nullifier_root = set_root("NULLIFIER-ROOT", &self.spent_nullifiers);
        r.operator_root = set_root("OPERATOR-ROOT", &self.operator_commitments);
        r.state_root = hash_json(
            "STATE",
            &json!({"roots":r.public_record(),"counters":self.counters.public_record()}),
        );
        r
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    pub fn public_record(&self) -> Value {
        json!({"protocol_version":PROTOCOL_VERSION,"roots":self.roots().public_record(),"counters":self.counters.public_record()})
    }
    pub fn commit_proof_bundle(
        &mut self,
        q: ProofBundleRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        ensure(
            q.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below floor",
        )?;
        ensure(
            q.priority_fee_bps <= self.config.max_user_fee_bps,
            "fee bps above low-fee cap",
        )?;
        let id = proof_bundle_id(&q);
        self.proof_bundles.insert(
            id.clone(),
            ProofBundleRecord {
                bundle_id: id.clone(),
                lane: q.lane,
                kind: q.kind,
                status: ProofBundleStatus::Committed,
                owner_commitment: q.owner_commitment,
                contract_root: q.contract_root,
                public_input_root: q.public_input_root,
                witness_commitment_root: q.witness_commitment_root,
                pq_signature_root: q.pq_signature_root,
                da_voucher_id: None,
                compression_id: None,
                prover_bid_id: None,
                coupon_id: None,
                aggregate_proof_root: empty_root("AGG"),
                verifier_key_root: empty_root("VK"),
                max_fee: q.max_fee,
                charged_fee: 0,
                rebate_amount: 0,
                priority_fee_bps: q.priority_fee_bps,
                privacy_set_size: q.privacy_set_size,
                opened_at_height: q.opened_at_height,
                expires_at_height: q.opened_at_height + self.config.proof_bundle_ttl_blocks,
                settled_at_height: None,
            },
        );
        self.counters.proof_bundles_committed += 1;
        Ok(id)
    }
    pub fn open_da_voucher(
        &mut self,
        q: DaVoucherRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let id = da_voucher_id(&q);
        self.da_vouchers.insert(
            id.clone(),
            DaVoucherRecord {
                voucher_id: id.clone(),
                kind: q.kind,
                status: DaVoucherStatus::Open,
                sponsor_commitment: q.sponsor_commitment,
                payload_root: q.payload_root,
                erasure_root: q.erasure_root,
                publisher_commitment: None,
                bid_id: None,
                byte_len: q.byte_len,
                max_price: q.max_price,
                clearing_price: 0,
                privacy_set_size: q.privacy_set_size,
                opened_at_height: q.opened_at_height,
                expires_at_height: q.opened_at_height + self.config.da_voucher_ttl_blocks,
                settled_at_height: None,
            },
        );
        self.counters.da_vouchers_opened += 1;
        self.counters.total_da_bytes += q.byte_len;
        Ok(id)
    }
    pub fn reserve_compression(
        &mut self,
        q: CompressionReservationRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let id = compression_reservation_id(&q);
        self.compression_reservations.insert(
            id.clone(),
            CompressionReservationRecord {
                compression_id: id.clone(),
                kind: q.kind,
                status: CompressionStatus::Reserved,
                requester_commitment: q.requester_commitment,
                input_root: q.input_root,
                output_root: empty_root("COMPRESSION-OUTPUT"),
                compressor_commitment: None,
                target_ratio_bps: q.target_ratio_bps,
                observed_ratio_bps: 0,
                input_bytes: 0,
                output_bytes: 0,
                max_fee: q.max_fee,
                clearing_fee: 0,
                opened_at_height: q.opened_at_height,
                expires_at_height: q.opened_at_height
                    + self.config.compression_reservation_ttl_blocks,
            },
        );
        self.counters.compression_reservations += 1;
        Ok(id)
    }
    pub fn submit_encrypted_diff_chunk(
        &mut self,
        q: EncryptedStateDiffChunkRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let id = diff_chunk_id(&q);
        self.encrypted_diff_chunks.insert(
            id.clone(),
            EncryptedStateDiffChunkRecord {
                chunk_id: id.clone(),
                bundle_id: q.bundle_id,
                status: DiffChunkStatus::Submitted,
                domain_commitment: q.domain_commitment,
                ciphertext_root: q.ciphertext_root,
                key_envelope_root: q.key_envelope_root,
                before_root: q.before_root,
                after_root: q.after_root,
                da_voucher_id: None,
                compression_id: None,
                byte_len: q.byte_len,
                compressed_byte_len: 0,
                opened_at_height: q.opened_at_height,
                settled_at_height: None,
            },
        );
        self.counters.encrypted_diff_chunks += 1;
        Ok(id)
    }
    pub fn post_prover_bid(
        &mut self,
        q: ProverBidRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let id = prover_bid_id(&q);
        self.prover_bids.insert(
            id.clone(),
            ProverBidRecord {
                bid_id: id.clone(),
                status: BidStatus::Posted,
                prover_commitment: q.prover_commitment,
                service_kind: q.service_kind,
                capacity: q.capacity,
                remaining_capacity: q.capacity,
                price_per_unit: q.price_per_unit,
                bond: q.bond,
                pq_attestation_root: q.pq_attestation_root,
                matched_bundle_ids: vec![],
                opened_at_height: q.opened_at_height,
                expires_at_height: q.opened_at_height + self.config.bid_ttl_blocks,
            },
        );
        self.counters.prover_bids_posted += 1;
        Ok(id)
    }
    pub fn post_da_bid(
        &mut self,
        q: DaBidRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let id = da_bid_id(&q);
        self.da_bids.insert(
            id.clone(),
            DaBidRecord {
                bid_id: id.clone(),
                status: BidStatus::Posted,
                publisher_commitment: q.publisher_commitment,
                voucher_kind: q.voucher_kind,
                byte_capacity: q.byte_capacity,
                remaining_bytes: q.byte_capacity,
                price_per_byte: q.price_per_byte,
                bond: q.bond,
                retrieval_commitment_root: q.retrieval_commitment_root,
                matched_voucher_ids: vec![],
                opened_at_height: q.opened_at_height,
                expires_at_height: q.opened_at_height + self.config.bid_ttl_blocks,
            },
        );
        self.counters.da_bids_posted += 1;
        Ok(id)
    }
    pub fn match_prover_bid(
        &mut self,
        bundle_id: &str,
        bid_id: &str,
        _height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        let b = self
            .proof_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "unknown proof bundle".to_string())?;
        let bid = self
            .prover_bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown prover bid".to_string())?;
        ensure(
            b.kind == bid.service_kind,
            "prover bid service kind mismatch",
        )?;
        b.prover_bid_id = Some(bid_id.to_string());
        bid.remaining_capacity = bid.remaining_capacity.saturating_sub(1);
        bid.status = BidStatus::Matched;
        Ok(())
    }
    pub fn match_da_bid(
        &mut self,
        voucher_id: &str,
        bid_id: &str,
        _height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        let v = self
            .da_vouchers
            .get_mut(voucher_id)
            .ok_or_else(|| "unknown da voucher".to_string())?;
        let bid = self
            .da_bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown da bid".to_string())?;
        ensure(v.kind == bid.voucher_kind, "da bid voucher kind mismatch")?;
        v.publisher_commitment = Some(bid.publisher_commitment.clone());
        v.bid_id = Some(bid_id.to_string());
        v.clearing_price = v.byte_len as u128 * bid.price_per_byte;
        v.status = DaVoucherStatus::BidMatched;
        bid.remaining_bytes = bid.remaining_bytes.saturating_sub(v.byte_len);
        bid.status = BidStatus::Matched;
        Ok(())
    }
    pub fn attach_da_voucher(
        &mut self,
        bundle_id: &str,
        voucher_id: &str,
        _height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        self.proof_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "unknown proof bundle".to_string())?
            .da_voucher_id = Some(voucher_id.to_string());
        self.da_vouchers
            .get_mut(voucher_id)
            .ok_or_else(|| "unknown da voucher".to_string())?
            .status = DaVoucherStatus::Published;
        Ok(())
    }
    pub fn attach_compression(
        &mut self,
        bundle_id: &str,
        compression_id: &str,
        output_root: String,
        input_bytes: u64,
        output_bytes: u64,
        _height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        let c = self
            .compression_reservations
            .get_mut(compression_id)
            .ok_or_else(|| "unknown compression reservation".to_string())?;
        c.output_root = output_root;
        c.input_bytes = input_bytes;
        c.output_bytes = output_bytes;
        c.observed_ratio_bps = ratio_bps(output_bytes, input_bytes);
        c.status = CompressionStatus::Attached;
        self.proof_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "unknown proof bundle".to_string())?
            .compression_id = Some(compression_id.to_string());
        self.counters.total_compressed_bytes += output_bytes;
        Ok(())
    }
    pub fn issue_settlement_coupon(
        &mut self,
        bundle_id: &str,
        height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let b = self
            .proof_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "unknown proof bundle".to_string())?;
        let da = b.da_voucher_id.clone().unwrap_or_default();
        let comp = b.compression_id.clone().unwrap_or_default();
        let id = settlement_coupon_id(bundle_id, &da, &comp, height);
        let rebate = fee_bps(b.max_fee, self.config.target_rebate_bps);
        b.coupon_id = Some(id.clone());
        b.charged_fee = b.max_fee.saturating_sub(rebate);
        b.rebate_amount = rebate;
        b.status = ProofBundleStatus::CouponIssued;
        self.settlement_coupons.insert(
            id.clone(),
            SettlementCouponRecord {
                coupon_id: id.clone(),
                status: CouponStatus::Issued,
                bundle_id: bundle_id.to_string(),
                da_voucher_id: da,
                compression_id: comp,
                owner_commitment: b.owner_commitment.clone(),
                fee_asset_id: self.config.fee_asset_id.clone(),
                face_value: b.max_fee,
                discounted_value: b.charged_fee,
                rebate_commitment: commitment_id("REBATE", &id),
                nullifier_hash: commitment_id("NULLIFIER", &id),
                issued_at_height: height,
                expires_at_height: height + self.config.coupon_ttl_blocks,
                redeemed_at_height: None,
            },
        );
        self.counters.settlement_coupons_issued += 1;
        Ok(id)
    }
    pub fn redeem_settlement_coupon(
        &mut self,
        coupon_id: &str,
        nullifier: String,
        height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        ensure(
            !self.spent_nullifiers.contains(&nullifier),
            "coupon nullifier already spent",
        )?;
        let c = self
            .settlement_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| "unknown settlement coupon".to_string())?;
        c.status = CouponStatus::Redeemed;
        c.redeemed_at_height = Some(height);
        self.spent_nullifiers.insert(nullifier);
        Ok(())
    }
    pub fn settle_bundle(
        &mut self,
        bundle_id: &str,
        aggregate_proof_root: String,
        verifier_key_root: String,
        height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        let b = self
            .proof_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "unknown proof bundle".to_string())?;
        b.aggregate_proof_root = aggregate_proof_root;
        b.verifier_key_root = verifier_key_root;
        b.status = ProofBundleStatus::Settled;
        b.settled_at_height = Some(height);
        self.counters.settled_bundles += 1;
        self.counters.total_user_fees += b.charged_fee;
        self.counters.total_rebates += b.rebate_amount;
        Ok(())
    }
    pub fn open_challenge(
        &mut self,
        q: ChallengeEvidenceRequest,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<String> {
        let id = challenge_id(&q);
        self.challenges.insert(
            id.clone(),
            ChallengeEvidenceRecord {
                challenge_id: id.clone(),
                kind: q.kind,
                status: ChallengeStatus::Open,
                target_id: q.target_id,
                challenger_commitment: q.challenger_commitment,
                defender_commitment: None,
                evidence_root: q.evidence_root,
                response_root: empty_root("CHALLENGE-RESPONSE"),
                bond: q.bond,
                slash_amount: 0,
                opened_at_height: q.opened_at_height,
                expires_at_height: q.opened_at_height + self.config.challenge_window_blocks,
                resolved_at_height: None,
            },
        );
        self.counters.challenges_opened += 1;
        Ok(id)
    }
    pub fn respond_to_challenge(
        &mut self,
        challenge_id: &str,
        defender_commitment: String,
        response_root: String,
        _height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        let c = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "unknown challenge".to_string())?;
        c.defender_commitment = Some(defender_commitment);
        c.response_root = response_root;
        c.status = ChallengeStatus::DefenderResponded;
        Ok(())
    }
    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        slash: bool,
        height: u64,
    ) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
        let c = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "unknown challenge".to_string())?;
        c.status = if slash {
            ChallengeStatus::Resolved
        } else {
            ChallengeStatus::Rejected
        };
        c.resolved_at_height = Some(height);
        if slash {
            self.counters.slash_events += 1;
        }
        Ok(())
    }
    pub fn expire_height(&mut self, _height: u64) {}
}

pub fn proof_bundle_id(q: &ProofBundleRequest) -> String {
    hash_parts(
        "PROOF-BUNDLE-ID",
        &[
            HashPart::Str(q.lane.as_str()),
            HashPart::Str(q.kind.as_str()),
            HashPart::Str(&q.owner_commitment),
            HashPart::Str(&q.contract_root),
            HashPart::Str(&q.public_input_root),
            HashPart::Str(&q.witness_commitment_root),
            HashPart::Str(&q.pq_signature_root),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn da_voucher_id(q: &DaVoucherRequest) -> String {
    hash_parts(
        "DA-VOUCHER-ID",
        &[
            HashPart::Str(q.kind.as_str()),
            HashPart::Str(&q.sponsor_commitment),
            HashPart::Str(&q.payload_root),
            HashPart::Str(&q.erasure_root),
            HashPart::Int(q.byte_len as i128),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn compression_reservation_id(q: &CompressionReservationRequest) -> String {
    hash_parts(
        "COMPRESSION-ID",
        &[
            HashPart::Str(q.kind.as_str()),
            HashPart::Str(&q.requester_commitment),
            HashPart::Str(&q.input_root),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn diff_chunk_id(q: &EncryptedStateDiffChunkRequest) -> String {
    hash_parts(
        "DIFF-CHUNK-ID",
        &[
            HashPart::Str(&q.bundle_id),
            HashPart::Str(&q.ciphertext_root),
            HashPart::Str(&q.after_root),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn prover_bid_id(q: &ProverBidRequest) -> String {
    hash_parts(
        "PROVER-BID-ID",
        &[
            HashPart::Str(&q.prover_commitment),
            HashPart::Str(q.service_kind.as_str()),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn da_bid_id(q: &DaBidRequest) -> String {
    hash_parts(
        "DA-BID-ID",
        &[
            HashPart::Str(&q.publisher_commitment),
            HashPart::Str(q.voucher_kind.as_str()),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn settlement_coupon_id(
    bundle_id: &str,
    da_voucher_id: &str,
    compression_id: &str,
    height: u64,
) -> String {
    hash_parts(
        "COUPON-ID",
        &[
            HashPart::Str(bundle_id),
            HashPart::Str(da_voucher_id),
            HashPart::Str(compression_id),
            HashPart::Int(height as i128),
        ],
    )
}
pub fn challenge_id(q: &ChallengeEvidenceRequest) -> String {
    hash_parts(
        "CHALLENGE-ID",
        &[
            HashPart::Str(q.kind.as_str()),
            HashPart::Str(&q.target_id),
            HashPart::Str(&q.challenger_commitment),
            HashPart::Str(&q.evidence_root),
            HashPart::Int(q.opened_at_height as i128),
        ],
    )
}
pub fn rebate_account_id(owner_commitment: &str, fee_asset_id: &str) -> String {
    hash_parts(
        "REBATE-ACCOUNT-ID",
        &[HashPart::Str(owner_commitment), HashPart::Str(fee_asset_id)],
    )
}
pub fn privacy_budget_id(subject_commitment: &str, lane: SettlementLane, epoch: u64) -> String {
    hash_parts(
        "PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(subject_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Int(epoch as i128),
        ],
    )
}
pub fn commitment_id(domain: &str, label: &str) -> String {
    hash_parts(domain, &[HashPart::Str(label)])
}
pub fn empty_root(domain: &str) -> String {
    hash_parts(domain, &[HashPart::Str("empty")])
}
pub fn record_root(domain: &str, value: &Value) -> String {
    hash_json(domain, value)
}
fn hash_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-PROOF-DA-COMPRESSION:{domain}"),
        parts,
        32,
    )
}
fn hash_json(domain: &str, value: &Value) -> String {
    hash_parts(domain, &[HashPart::Json(value)])
}
fn fee_bps(value: u128, bps: u64) -> u128 {
    value.saturating_mul(bps as u128) / MAX_BPS as u128
}
fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}
fn ensure(condition: bool, message: &str) -> PrivateL2LowFeePqProofDaCompressionRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, to_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"id":key,"record":to_record(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-PROOF-DA-COMPRESSION:{domain}"),
        &leaves,
    )
}
fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"id":key,"record":value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-PROOF-DA-COMPRESSION:{domain}"),
        &leaves,
    )
}
fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-PROOF-DA-COMPRESSION:{domain}"),
        &leaves,
    )
}

impl State {
    pub fn market_signal_001(&self) -> Value {
        json!({"signal":"market_signal_001","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_002(&self) -> Value {
        json!({"signal":"market_signal_002","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_003(&self) -> Value {
        json!({"signal":"market_signal_003","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_004(&self) -> Value {
        json!({"signal":"market_signal_004","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_005(&self) -> Value {
        json!({"signal":"market_signal_005","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_006(&self) -> Value {
        json!({"signal":"market_signal_006","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_007(&self) -> Value {
        json!({"signal":"market_signal_007","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_008(&self) -> Value {
        json!({"signal":"market_signal_008","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_009(&self) -> Value {
        json!({"signal":"market_signal_009","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_010(&self) -> Value {
        json!({"signal":"market_signal_010","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_011(&self) -> Value {
        json!({"signal":"market_signal_011","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_012(&self) -> Value {
        json!({"signal":"market_signal_012","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_013(&self) -> Value {
        json!({"signal":"market_signal_013","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_014(&self) -> Value {
        json!({"signal":"market_signal_014","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_015(&self) -> Value {
        json!({"signal":"market_signal_015","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_016(&self) -> Value {
        json!({"signal":"market_signal_016","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_017(&self) -> Value {
        json!({"signal":"market_signal_017","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_018(&self) -> Value {
        json!({"signal":"market_signal_018","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_019(&self) -> Value {
        json!({"signal":"market_signal_019","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_020(&self) -> Value {
        json!({"signal":"market_signal_020","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_021(&self) -> Value {
        json!({"signal":"market_signal_021","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_022(&self) -> Value {
        json!({"signal":"market_signal_022","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_023(&self) -> Value {
        json!({"signal":"market_signal_023","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_024(&self) -> Value {
        json!({"signal":"market_signal_024","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_025(&self) -> Value {
        json!({"signal":"market_signal_025","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_026(&self) -> Value {
        json!({"signal":"market_signal_026","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_027(&self) -> Value {
        json!({"signal":"market_signal_027","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_028(&self) -> Value {
        json!({"signal":"market_signal_028","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_029(&self) -> Value {
        json!({"signal":"market_signal_029","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_030(&self) -> Value {
        json!({"signal":"market_signal_030","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_031(&self) -> Value {
        json!({"signal":"market_signal_031","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_032(&self) -> Value {
        json!({"signal":"market_signal_032","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_033(&self) -> Value {
        json!({"signal":"market_signal_033","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_034(&self) -> Value {
        json!({"signal":"market_signal_034","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_035(&self) -> Value {
        json!({"signal":"market_signal_035","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_036(&self) -> Value {
        json!({"signal":"market_signal_036","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_037(&self) -> Value {
        json!({"signal":"market_signal_037","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_038(&self) -> Value {
        json!({"signal":"market_signal_038","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_039(&self) -> Value {
        json!({"signal":"market_signal_039","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_040(&self) -> Value {
        json!({"signal":"market_signal_040","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_041(&self) -> Value {
        json!({"signal":"market_signal_041","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_042(&self) -> Value {
        json!({"signal":"market_signal_042","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_043(&self) -> Value {
        json!({"signal":"market_signal_043","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_044(&self) -> Value {
        json!({"signal":"market_signal_044","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_045(&self) -> Value {
        json!({"signal":"market_signal_045","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_046(&self) -> Value {
        json!({"signal":"market_signal_046","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_047(&self) -> Value {
        json!({"signal":"market_signal_047","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_048(&self) -> Value {
        json!({"signal":"market_signal_048","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_049(&self) -> Value {
        json!({"signal":"market_signal_049","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_050(&self) -> Value {
        json!({"signal":"market_signal_050","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_051(&self) -> Value {
        json!({"signal":"market_signal_051","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_052(&self) -> Value {
        json!({"signal":"market_signal_052","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_053(&self) -> Value {
        json!({"signal":"market_signal_053","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_054(&self) -> Value {
        json!({"signal":"market_signal_054","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_055(&self) -> Value {
        json!({"signal":"market_signal_055","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_056(&self) -> Value {
        json!({"signal":"market_signal_056","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_057(&self) -> Value {
        json!({"signal":"market_signal_057","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_058(&self) -> Value {
        json!({"signal":"market_signal_058","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_059(&self) -> Value {
        json!({"signal":"market_signal_059","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_060(&self) -> Value {
        json!({"signal":"market_signal_060","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_061(&self) -> Value {
        json!({"signal":"market_signal_061","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_062(&self) -> Value {
        json!({"signal":"market_signal_062","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_063(&self) -> Value {
        json!({"signal":"market_signal_063","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_064(&self) -> Value {
        json!({"signal":"market_signal_064","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_065(&self) -> Value {
        json!({"signal":"market_signal_065","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_066(&self) -> Value {
        json!({"signal":"market_signal_066","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_067(&self) -> Value {
        json!({"signal":"market_signal_067","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_068(&self) -> Value {
        json!({"signal":"market_signal_068","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_069(&self) -> Value {
        json!({"signal":"market_signal_069","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_070(&self) -> Value {
        json!({"signal":"market_signal_070","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_071(&self) -> Value {
        json!({"signal":"market_signal_071","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_072(&self) -> Value {
        json!({"signal":"market_signal_072","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_073(&self) -> Value {
        json!({"signal":"market_signal_073","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_074(&self) -> Value {
        json!({"signal":"market_signal_074","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_075(&self) -> Value {
        json!({"signal":"market_signal_075","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_076(&self) -> Value {
        json!({"signal":"market_signal_076","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_077(&self) -> Value {
        json!({"signal":"market_signal_077","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_078(&self) -> Value {
        json!({"signal":"market_signal_078","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_079(&self) -> Value {
        json!({"signal":"market_signal_079","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_080(&self) -> Value {
        json!({"signal":"market_signal_080","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_081(&self) -> Value {
        json!({"signal":"market_signal_081","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_082(&self) -> Value {
        json!({"signal":"market_signal_082","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_083(&self) -> Value {
        json!({"signal":"market_signal_083","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_084(&self) -> Value {
        json!({"signal":"market_signal_084","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_085(&self) -> Value {
        json!({"signal":"market_signal_085","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_086(&self) -> Value {
        json!({"signal":"market_signal_086","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_087(&self) -> Value {
        json!({"signal":"market_signal_087","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_088(&self) -> Value {
        json!({"signal":"market_signal_088","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_089(&self) -> Value {
        json!({"signal":"market_signal_089","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_090(&self) -> Value {
        json!({"signal":"market_signal_090","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_091(&self) -> Value {
        json!({"signal":"market_signal_091","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_092(&self) -> Value {
        json!({"signal":"market_signal_092","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_093(&self) -> Value {
        json!({"signal":"market_signal_093","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_094(&self) -> Value {
        json!({"signal":"market_signal_094","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_095(&self) -> Value {
        json!({"signal":"market_signal_095","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_096(&self) -> Value {
        json!({"signal":"market_signal_096","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_097(&self) -> Value {
        json!({"signal":"market_signal_097","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_098(&self) -> Value {
        json!({"signal":"market_signal_098","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_099(&self) -> Value {
        json!({"signal":"market_signal_099","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_100(&self) -> Value {
        json!({"signal":"market_signal_100","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_101(&self) -> Value {
        json!({"signal":"market_signal_101","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_102(&self) -> Value {
        json!({"signal":"market_signal_102","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_103(&self) -> Value {
        json!({"signal":"market_signal_103","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_104(&self) -> Value {
        json!({"signal":"market_signal_104","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_105(&self) -> Value {
        json!({"signal":"market_signal_105","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_106(&self) -> Value {
        json!({"signal":"market_signal_106","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_107(&self) -> Value {
        json!({"signal":"market_signal_107","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_108(&self) -> Value {
        json!({"signal":"market_signal_108","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_109(&self) -> Value {
        json!({"signal":"market_signal_109","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_110(&self) -> Value {
        json!({"signal":"market_signal_110","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_111(&self) -> Value {
        json!({"signal":"market_signal_111","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_112(&self) -> Value {
        json!({"signal":"market_signal_112","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_113(&self) -> Value {
        json!({"signal":"market_signal_113","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_114(&self) -> Value {
        json!({"signal":"market_signal_114","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_115(&self) -> Value {
        json!({"signal":"market_signal_115","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_116(&self) -> Value {
        json!({"signal":"market_signal_116","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_117(&self) -> Value {
        json!({"signal":"market_signal_117","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_118(&self) -> Value {
        json!({"signal":"market_signal_118","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_119(&self) -> Value {
        json!({"signal":"market_signal_119","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
impl State {
    pub fn market_signal_120(&self) -> Value {
        json!({"signal":"market_signal_120","state_root":self.state_root(),"settled_bundles":self.counters.settled_bundles,"total_user_fees":self.counters.total_user_fees.to_string(),"total_rebates":self.counters.total_rebates.to_string(),"proof_bundles":self.proof_bundles.len(),"da_vouchers":self.da_vouchers.len(),"compression_reservations":self.compression_reservations.len()})
    }
}
