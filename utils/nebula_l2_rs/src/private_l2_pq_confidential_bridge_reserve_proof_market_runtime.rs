use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeReserveProofMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-bridge-reserve-proof-market-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_RESERVE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RESERVE_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const RESERVE_PROOF_SUITE: &str = "monero-bridge-confidential-reserve-proof-root-v1";
pub const MARKET_SUITE: &str = "private-bridge-reserve-proof-market-root-v1";
pub const REBATE_SUITE: &str = "bridge-reserve-proof-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-bridge-reserve-proof-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_RESERVE_ASSET_ID: &str = "xmr-bridge-reserve-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_PROOF_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_SETTLEMENT_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_MAX_PROOF_FEE_BPS: u64 = 22;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS: u64 = 30_000_000;
pub const DEFAULT_MIN_RESERVE_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_RESERVE_DRIFT_BPS: u64 = 120;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_MARKETS: usize = 524_288;
pub const MAX_PROVIDERS: usize = 524_288;
pub const MAX_BIDS: usize = 2_097_152;
pub const MAX_PROOF_RECEIPTS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 7_424;
pub const DEVNET_SLOT: u64 = 113;
pub const DEVNET_L2_HEIGHT: u64 = 2_921_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveScope {
    HotBridgeReserve,
    ColdBridgeReserve,
    WatchtowerReserve,
    FastExitLiquidity,
    AtomicSwapEscrow,
    WithdrawalQueue,
    FeeSponsorReserve,
    EmergencyExitReserve,
}

impl ReserveScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotBridgeReserve => "hot_bridge_reserve",
            Self::ColdBridgeReserve => "cold_bridge_reserve",
            Self::WatchtowerReserve => "watchtower_reserve",
            Self::FastExitLiquidity => "fast_exit_liquidity",
            Self::AtomicSwapEscrow => "atomic_swap_escrow",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::FeeSponsorReserve => "fee_sponsor_reserve",
            Self::EmergencyExitReserve => "emergency_exit_reserve",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::ColdBridgeReserve => 9,
            Self::HotBridgeReserve => 8,
            Self::EmergencyExitReserve => 7,
            Self::FastExitLiquidity => 6,
            Self::AtomicSwapEscrow => 6,
            Self::WithdrawalQueue => 5,
            Self::WatchtowerReserve => 4,
            Self::FeeSponsorReserve => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Planned,
    Open,
    Clearing,
    Settled,
    Paused,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Candidate,
    Active,
    Throttled,
    Exhausted,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Submitted,
    Sponsored,
    ProofPublished,
    Attested,
    Settled,
    RebateIssued,
    Stale,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Attested,
    Accepted,
    Stale,
    Quarantined,
    Settled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqProviderSignatureVerified,
    ReserveCommitmentOpened,
    MoneroOutputSetChecked,
    WatchtowerQuorumChecked,
    DriftBoundObserved,
    FeeCapObserved,
    PrivacyBoundaryObserved,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqProviderSignatureVerified => "pq_provider_signature_verified",
            Self::ReserveCommitmentOpened => "reserve_commitment_opened",
            Self::MoneroOutputSetChecked => "monero_output_set_checked",
            Self::WatchtowerQuorumChecked => "watchtower_quorum_checked",
            Self::DriftBoundObserved => "drift_bound_observed",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::SettlementSafe => "settlement_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    Approve,
    ApproveWithRebate,
    PartialReserveCredit,
    Retry,
    Reject,
    Quarantine,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveWithRebate => "approve_with_rebate",
            Self::PartialReserveCredit => "partial_reserve_credit",
            Self::Retry => "retry",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Expire => "expire",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_reserve_suite: String,
    pub reserve_proof_suite: String,
    pub market_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub reserve_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub proof_window_slots: u64,
    pub settlement_window_slots: u64,
    pub max_proof_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_provider_bond_micro_units: u64,
    pub min_reserve_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_reserve_drift_bps: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_reserve_suite: PQ_RESERVE_SUITE.to_string(),
            reserve_proof_suite: RESERVE_PROOF_SUITE.to_string(),
            market_suite: MARKET_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            reserve_asset_id: DEFAULT_RESERVE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            proof_window_slots: DEFAULT_PROOF_WINDOW_SLOTS,
            settlement_window_slots: DEFAULT_SETTLEMENT_WINDOW_SLOTS,
            max_proof_fee_bps: DEFAULT_MAX_PROOF_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_provider_bond_micro_units: DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS,
            min_reserve_micro_units: DEFAULT_MIN_RESERVE_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_reserve_drift_bps: DEFAULT_MAX_RESERVE_DRIFT_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_reserve_suite, "pq_reserve_suite")?;
        ensure_non_empty(&self.reserve_proof_suite, "reserve_proof_suite")?;
        ensure_non_empty(&self.market_suite, "market_suite")?;
        ensure_non_empty(&self.rebate_suite, "rebate_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.reserve_asset_id, "reserve_asset_id")?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must be >= minimum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security bits below configured floor".to_string());
        }
        if self.proof_window_slots == 0 || self.settlement_window_slots == 0 {
            return Err("proof and settlement windows must be non-zero".to_string());
        }
        ensure_bps(self.max_proof_fee_bps, "max_proof_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.max_reserve_drift_bps, "max_reserve_drift_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err("strong attestation quorum below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub providers: u64,
    pub bids: u64,
    pub proof_receipts: u64,
    pub attestations: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_bids: u64,
    pub quarantined_bids: u64,
    pub stale_proofs: u64,
    pub reserve_micro_units: u64,
    pub proven_reserve_micro_units: u64,
    pub rebated_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "providers": self.providers,
            "bids": self.bids,
            "proof_receipts": self.proof_receipts,
            "attestations": self.attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_bids": self.settled_bids,
            "quarantined_bids": self.quarantined_bids,
            "stale_proofs": self.stale_proofs,
            "reserve_micro_units": self.reserve_micro_units,
            "proven_reserve_micro_units": self.proven_reserve_micro_units,
            "rebated_micro_units": self.rebated_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub provider_root: String,
    pub bid_root: String,
    pub proof_receipt_root: String,
    pub attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "provider_root": self.provider_root,
            "bid_root": self.bid_root,
            "proof_receipt_root": self.proof_receipt_root,
            "attestation_root": self.attestation_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveMarket {
    pub market_id: String,
    pub scope: ReserveScope,
    pub sealed_market_root: String,
    pub public_hint_root: String,
    pub target_reserve_micro_units: u64,
    pub min_proof_slot: u64,
    pub max_proof_slot: u64,
    pub fee_cap_bps: u64,
    pub status: MarketStatus,
    pub opened_slot: u64,
    pub expires_slot: u64,
}

impl ReserveMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "scope": self.scope.as_str(),
            "public_hint_root": self.public_hint_root,
            "target_reserve_micro_units": self.target_reserve_micro_units,
            "min_proof_slot": self.min_proof_slot,
            "max_proof_slot": self.max_proof_slot,
            "fee_cap_bps": self.fee_cap_bps,
            "status": self.status,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProvider {
    pub provider_id: String,
    pub provider_commitment: String,
    pub pq_verifying_key_root: String,
    pub reserve_commitment_root: String,
    pub bond_micro_units: u64,
    pub reserve_micro_units: u64,
    pub privacy_set_size: u64,
    pub status: ProviderStatus,
    pub joined_slot: u64,
}

impl ReserveProvider {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "pq_verifying_key_root": self.pq_verifying_key_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "bond_micro_units": self.bond_micro_units,
            "reserve_micro_units": self.reserve_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "joined_slot": self.joined_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProofBid {
    pub bid_id: String,
    pub market_id: String,
    pub provider_id: String,
    pub sealed_bid_root: String,
    pub redacted_bid_root: String,
    pub requested_reserve_micro_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub status: BidStatus,
}

impl ReserveProofBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "market_id": self.market_id,
            "provider_id": self.provider_id,
            "redacted_bid_root": self.redacted_bid_root,
            "requested_reserve_micro_units": self.requested_reserve_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProofReceipt {
    pub receipt_id: String,
    pub bid_id: String,
    pub proof_root: String,
    pub reserve_commitment_root: String,
    pub monero_output_set_root: String,
    pub pq_signature_root: String,
    pub proven_reserve_micro_units: u64,
    pub reserve_drift_bps: u64,
    pub published_slot: u64,
    pub status: ProofStatus,
}

impl ReserveProofReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bid_id": self.bid_id,
            "proof_root": self.proof_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "monero_output_set_root": self.monero_output_set_root,
            "pq_signature_root": self.pq_signature_root,
            "proven_reserve_micro_units": self.proven_reserve_micro_units,
            "reserve_drift_bps": self.reserve_drift_bps,
            "published_slot": self.published_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub bid_id: String,
    pub receipt_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub bid_id: String,
    pub receipt_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_reserve_micro_units: u64,
    pub fee_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub bid_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub markets: u64,
    pub providers: u64,
    pub open_bids: u64,
    pub settled_bids: u64,
    pub quarantined_bids: u64,
    pub stale_proofs: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub proven_reserve_micro_units: u64,
    pub rebated_micro_units: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenMarketRequest {
    pub scope: ReserveScope,
    pub sealed_market_root: String,
    pub public_hint_root: String,
    pub target_reserve_micro_units: u64,
    pub min_proof_slot: u64,
    pub max_proof_slot: u64,
    pub fee_cap_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterProviderRequest {
    pub provider_commitment: String,
    pub pq_verifying_key_root: String,
    pub reserve_commitment_root: String,
    pub bond_micro_units: u64,
    pub reserve_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitBidRequest {
    pub market_id: String,
    pub provider_id: String,
    pub sealed_bid_root: String,
    pub redacted_bid_root: String,
    pub requested_reserve_micro_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishProofReceiptRequest {
    pub bid_id: String,
    pub proof_root: String,
    pub reserve_commitment_root: String,
    pub monero_output_set_root: String,
    pub pq_signature_root: String,
    pub proven_reserve_micro_units: u64,
    pub reserve_drift_bps: u64,
    pub published_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub bid_id: String,
    pub receipt_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleBidRequest {
    pub bid_id: String,
    pub receipt_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub bid_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub markets: BTreeMap<String, ReserveMarket>,
    pub providers: BTreeMap<String, ReserveProvider>,
    pub bids: BTreeMap<String, ReserveProofBid>,
    pub proof_receipts: BTreeMap<String, ReserveProofReceipt>,
    pub attestations: BTreeMap<String, ReserveAttestation>,
    pub settlements: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default bridge reserve proof market config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            markets: BTreeMap::new(),
            providers: BTreeMap::new(),
            bids: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn open_market(&mut self, request: OpenMarketRequest) -> Result<ReserveMarket> {
        ensure_capacity(self.markets.len(), MAX_MARKETS, "markets")?;
        ensure_non_empty(&request.sealed_market_root, "sealed_market_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_bps(request.fee_cap_bps, "fee_cap_bps")?;
        if request.fee_cap_bps > self.config.max_proof_fee_bps {
            return Err("market fee cap exceeds configured maximum".to_string());
        }
        if request.target_reserve_micro_units < self.config.min_reserve_micro_units {
            return Err("target reserve below configured minimum".to_string());
        }
        if request.max_proof_slot <= request.min_proof_slot {
            return Err("max_proof_slot must be greater than min_proof_slot".to_string());
        }
        let market_id = stable_id(
            "market",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.sealed_market_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let market = ReserveMarket {
            market_id: market_id.clone(),
            scope: request.scope,
            sealed_market_root: request.sealed_market_root,
            public_hint_root: request.public_hint_root,
            target_reserve_micro_units: request.target_reserve_micro_units,
            min_proof_slot: request.min_proof_slot,
            max_proof_slot: request.max_proof_slot,
            fee_cap_bps: request.fee_cap_bps,
            status: MarketStatus::Open,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.proof_window_slots,
        };
        self.markets.insert(market_id, market.clone());
        self.refresh_roots();
        Ok(market)
    }

    pub fn register_provider(
        &mut self,
        request: RegisterProviderRequest,
    ) -> Result<ReserveProvider> {
        ensure_capacity(self.providers.len(), MAX_PROVIDERS, "providers")?;
        ensure_non_empty(&request.provider_commitment, "provider_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(&request.reserve_commitment_root, "reserve_commitment_root")?;
        if request.bond_micro_units < self.config.min_provider_bond_micro_units {
            return Err("provider bond below configured minimum".to_string());
        }
        if request.reserve_micro_units < self.config.min_reserve_micro_units {
            return Err("provider reserve below configured minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("provider privacy set below configured minimum".to_string());
        }
        let provider_id = stable_id(
            "provider",
            &[
                HashPart::Str(&request.provider_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::Str(&request.reserve_commitment_root),
            ],
        );
        let provider = ReserveProvider {
            provider_id: provider_id.clone(),
            provider_commitment: request.provider_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            reserve_commitment_root: request.reserve_commitment_root,
            bond_micro_units: request.bond_micro_units,
            reserve_micro_units: request.reserve_micro_units,
            privacy_set_size: request.privacy_set_size,
            status: ProviderStatus::Active,
            joined_slot: request.joined_slot,
        };
        self.providers.insert(provider_id, provider.clone());
        self.refresh_roots();
        Ok(provider)
    }

    pub fn submit_bid(&mut self, request: SubmitBidRequest) -> Result<ReserveProofBid> {
        ensure_capacity(self.bids.len(), MAX_BIDS, "bids")?;
        ensure_non_empty(&request.sealed_bid_root, "sealed_bid_root")?;
        ensure_non_empty(&request.redacted_bid_root, "redacted_bid_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("bid rebate exceeds configured target".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "market not found".to_string())?;
        if market.status != MarketStatus::Open {
            return Err("market is not open".to_string());
        }
        if request.submitted_slot < market.min_proof_slot
            || request.submitted_slot > market.max_proof_slot
        {
            return Err("bid submitted outside market proof window".to_string());
        }
        if request.max_fee_bps > market.fee_cap_bps {
            return Err("bid fee exceeds market cap".to_string());
        }
        if request.requested_reserve_micro_units < self.config.min_reserve_micro_units {
            return Err("bid reserve below configured minimum".to_string());
        }
        let provider = self
            .providers
            .get(&request.provider_id)
            .ok_or_else(|| "provider not found".to_string())?;
        if provider.status != ProviderStatus::Active {
            return Err("provider is not active".to_string());
        }
        if provider.reserve_micro_units < request.requested_reserve_micro_units {
            return Err("provider reserve is below requested amount".to_string());
        }
        let bid_id = stable_id(
            "bid",
            &[
                HashPart::Str(&request.market_id),
                HashPart::Str(&request.provider_id),
                HashPart::Str(&request.redacted_bid_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let bid = ReserveProofBid {
            bid_id: bid_id.clone(),
            market_id: request.market_id,
            provider_id: request.provider_id,
            sealed_bid_root: request.sealed_bid_root,
            redacted_bid_root: request.redacted_bid_root,
            requested_reserve_micro_units: request.requested_reserve_micro_units,
            max_fee_bps: request.max_fee_bps,
            rebate_bps: request.rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.proof_window_slots,
            status: BidStatus::Sponsored,
        };
        self.bids.insert(bid_id, bid.clone());
        self.refresh_roots();
        Ok(bid)
    }

    pub fn publish_proof_receipt(
        &mut self,
        request: PublishProofReceiptRequest,
    ) -> Result<ReserveProofReceipt> {
        ensure_capacity(
            self.proof_receipts.len(),
            MAX_PROOF_RECEIPTS,
            "proof_receipts",
        )?;
        ensure_non_empty(&request.proof_root, "proof_root")?;
        ensure_non_empty(&request.reserve_commitment_root, "reserve_commitment_root")?;
        ensure_non_empty(&request.monero_output_set_root, "monero_output_set_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.reserve_drift_bps, "reserve_drift_bps")?;
        let bid = self
            .bids
            .get(&request.bid_id)
            .ok_or_else(|| "bid not found".to_string())?
            .clone();
        if request.published_slot < bid.submitted_slot {
            return Err("proof published before bid submission".to_string());
        }
        let stale = request.published_slot > bid.expires_slot
            || request.reserve_drift_bps > self.config.max_reserve_drift_bps;
        if stale {
            self.counters.stale_proofs = self.counters.stale_proofs.saturating_add(1);
        }
        let receipt_id = stable_id(
            "proof-receipt",
            &[
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.proof_root),
                HashPart::U64(request.published_slot),
            ],
        );
        let receipt = ReserveProofReceipt {
            receipt_id: receipt_id.clone(),
            bid_id: request.bid_id.clone(),
            proof_root: request.proof_root,
            reserve_commitment_root: request.reserve_commitment_root,
            monero_output_set_root: request.monero_output_set_root,
            pq_signature_root: request.pq_signature_root,
            proven_reserve_micro_units: request.proven_reserve_micro_units,
            reserve_drift_bps: request.reserve_drift_bps,
            published_slot: request.published_slot,
            status: if stale {
                ProofStatus::Stale
            } else {
                ProofStatus::Submitted
            },
        };
        self.proof_receipts.insert(receipt_id, receipt.clone());
        if let Some(bid) = self.bids.get_mut(&request.bid_id) {
            bid.status = if stale {
                BidStatus::Stale
            } else {
                BidStatus::ProofPublished
            };
        }
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn record_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<ReserveAttestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        self.ensure_bid_exists(&request.bid_id)?;
        let receipt = self
            .proof_receipts
            .get_mut(&request.receipt_id)
            .ok_or_else(|| "proof receipt not found".to_string())?;
        if receipt.bid_id != request.bid_id {
            return Err("proof receipt does not match bid".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.receipt_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = ReserveAttestation {
            attestation_id: attestation_id.clone(),
            bid_id: request.bid_id.clone(),
            receipt_id: request.receipt_id.clone(),
            kind: request.kind,
            committee_root: request.committee_root,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if request.kind == AttestationKind::SettlementSafe && receipt.status != ProofStatus::Stale {
            receipt.status = ProofStatus::Attested;
            if let Some(bid) = self.bids.get_mut(&request.bid_id) {
                bid.status = BidStatus::Attested;
            }
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_bid(&mut self, request: SettleBidRequest) -> Result<SettlementReceipt> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let bid = self
            .bids
            .get(&request.bid_id)
            .ok_or_else(|| "bid not found".to_string())?
            .clone();
        let receipt = self
            .proof_receipts
            .get(&request.receipt_id)
            .ok_or_else(|| "proof receipt not found".to_string())?
            .clone();
        if receipt.bid_id != bid.bid_id {
            return Err("receipt does not match bid".to_string());
        }
        if request.settled_slot < receipt.published_slot {
            return Err("settlement slot precedes proof receipt".to_string());
        }
        let settled_reserve_micro_units = match request.decision {
            SettlementDecision::Approve | SettlementDecision::ApproveWithRebate => {
                receipt.proven_reserve_micro_units
            }
            SettlementDecision::PartialReserveCredit => receipt.proven_reserve_micro_units / 2,
            _ => 0,
        };
        let fee_micro_units = settled_reserve_micro_units.saturating_mul(bid.max_fee_bps) / MAX_BPS;
        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.receipt_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::U64(request.settled_slot),
            ],
        );
        let settlement = SettlementReceipt {
            settlement_id: settlement_id.clone(),
            bid_id: request.bid_id.clone(),
            receipt_id: request.receipt_id.clone(),
            settlement_root: request.settlement_root,
            decision: request.decision,
            settled_reserve_micro_units,
            fee_micro_units,
            settled_slot: request.settled_slot,
        };
        self.settlements.insert(settlement_id, settlement.clone());
        self.apply_settlement(
            &bid,
            &receipt,
            request.decision,
            settled_reserve_micro_units,
        )?;
        self.refresh_roots();
        Ok(settlement)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate bps exceeds configured target".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        let bid = self
            .bids
            .get_mut(&request.bid_id)
            .ok_or_else(|| "bid not found".to_string())?;
        if bid.status != BidStatus::Settled {
            return Err("rebate requires a settled bid".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let rebate = RebateReceipt {
            rebate_id: rebate_id.clone(),
            bid_id: request.bid_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, rebate.clone());
        self.counters.rebated_micro_units = self
            .counters
            .rebated_micro_units
            .saturating_add(request.amount_micro_units);
        bid.status = BidStatus::RebateIssued;
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction_budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.public_fields.is_empty() {
            return Err("redaction budget requires public fields".to_string());
        }
        if request.redacted_fields.is_empty() {
            return Err("redaction budget requires redacted fields".to_string());
        }
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("redaction budget exceeds configured public byte cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below configured minimum".to_string());
        }
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::U64(request.max_public_bytes),
                HashPart::U64(request.actual_public_bytes),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let open_bids = self
            .bids
            .values()
            .filter(|bid| {
                matches!(
                    bid.status,
                    BidStatus::Submitted
                        | BidStatus::Sponsored
                        | BidStatus::ProofPublished
                        | BidStatus::Attested
                )
            })
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[HashPart::U64(self.operator_summaries.len() as u64)],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            markets: self.markets.len() as u64,
            providers: self.providers.len() as u64,
            open_bids,
            settled_bids: self.counters.settled_bids,
            quarantined_bids: self.counters.quarantined_bids,
            stale_proofs: self.counters.stale_proofs,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            proven_reserve_micro_units: self.counters.proven_reserve_micro_units,
            rebated_micro_units: self.counters.rebated_micro_units,
            state_root: self.state_root(),
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.markets = self.markets.len() as u64;
        self.counters.providers = self.providers.len() as u64;
        self.counters.bids = self.bids.len() as u64;
        self.counters.proof_receipts = self.proof_receipts.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.reserve_micro_units = self
            .providers
            .values()
            .map(|provider| provider.reserve_micro_units)
            .sum();
        self.roots.market_root = map_root("bridge-reserve-proof-market:markets", &self.markets);
        self.roots.provider_root =
            map_root("bridge-reserve-proof-market:providers", &self.providers);
        self.roots.bid_root = map_root("bridge-reserve-proof-market:bids", &self.bids);
        self.roots.proof_receipt_root = map_root(
            "bridge-reserve-proof-market:proof-receipts",
            &self.proof_receipts,
        );
        self.roots.attestation_root = map_root(
            "bridge-reserve-proof-market:attestations",
            &self.attestations,
        );
        self.roots.settlement_root =
            map_root("bridge-reserve-proof-market:settlements", &self.settlements);
        self.roots.rebate_root = map_root("bridge-reserve-proof-market:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "bridge-reserve-proof-market:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "bridge-reserve-proof-market:operator-summaries",
            &self.operator_summaries,
        );
        self.roots.state_root = self.compute_state_root();
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_reserve_suite": self.config.pq_reserve_suite,
            "reserve_proof_suite": self.config.reserve_proof_suite,
            "market_suite": self.config.market_suite,
            "rebate_suite": self.config.rebate_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "markets": self.markets,
            "providers": self.providers,
            "bids": self.bids,
            "proof_receipts": self.proof_receipts,
            "attestations": self.attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
        })
    }

    fn compute_state_root(&self) -> String {
        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "market_root": self.roots.market_root,
            "provider_root": self.roots.provider_root,
            "bid_root": self.roots.bid_root,
            "proof_receipt_root": self.roots.proof_receipt_root,
            "attestation_root": self.roots.attestation_root,
            "settlement_root": self.roots.settlement_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "bridge-reserve-proof-market:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn apply_settlement(
        &mut self,
        bid: &ReserveProofBid,
        receipt: &ReserveProofReceipt,
        decision: SettlementDecision,
        settled_reserve_micro_units: u64,
    ) -> Result<()> {
        match decision {
            SettlementDecision::Approve
            | SettlementDecision::ApproveWithRebate
            | SettlementDecision::PartialReserveCredit => {
                if receipt.status != ProofStatus::Attested
                    && receipt.status != ProofStatus::Submitted
                    && receipt.status != ProofStatus::Accepted
                {
                    return Err("proof receipt is not eligible for settlement".to_string());
                }
                if let Some(proof) = self.proof_receipts.get_mut(&receipt.receipt_id) {
                    proof.status = ProofStatus::Settled;
                }
                if let Some(stored_bid) = self.bids.get_mut(&bid.bid_id) {
                    stored_bid.status = BidStatus::Settled;
                }
                self.counters.settled_bids = self.counters.settled_bids.saturating_add(1);
                self.counters.proven_reserve_micro_units = self
                    .counters
                    .proven_reserve_micro_units
                    .saturating_add(settled_reserve_micro_units);
            }
            SettlementDecision::Retry => {
                if let Some(stored_bid) = self.bids.get_mut(&bid.bid_id) {
                    stored_bid.status = BidStatus::ProofPublished;
                }
            }
            SettlementDecision::Reject | SettlementDecision::Quarantine => {
                if let Some(proof) = self.proof_receipts.get_mut(&receipt.receipt_id) {
                    proof.status = ProofStatus::Quarantined;
                }
                if let Some(stored_bid) = self.bids.get_mut(&bid.bid_id) {
                    stored_bid.status = BidStatus::Quarantined;
                }
                self.counters.quarantined_bids = self.counters.quarantined_bids.saturating_add(1);
            }
            SettlementDecision::Expire => {
                if let Some(stored_bid) = self.bids.get_mut(&bid.bid_id) {
                    stored_bid.status = BidStatus::Expired;
                }
            }
        }
        Ok(())
    }

    fn ensure_bid_exists(&self, bid_id: &str) -> Result<()> {
        ensure_non_empty(bid_id, "bid_id")?;
        if !self.bids.contains_key(bid_id) {
            return Err(format!("bid not found: {bid_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let market = state
        .open_market(OpenMarketRequest {
            scope: ReserveScope::HotBridgeReserve,
            sealed_market_root: sample_hash("sealed-market", 1),
            public_hint_root: sample_hash("public-hint", 1),
            target_reserve_micro_units: 240_000_000,
            min_proof_slot: DEVNET_SLOT,
            max_proof_slot: DEVNET_SLOT + 512,
            fee_cap_bps: 12,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet reserve market opened");
    let provider = state
        .register_provider(RegisterProviderRequest {
            provider_commitment: sample_hash("provider", 1),
            pq_verifying_key_root: sample_hash("provider-pq-key", 1),
            reserve_commitment_root: sample_hash("reserve", 1),
            bond_micro_units: DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS * 3,
            reserve_micro_units: 280_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet provider registered");
    let bid = state
        .submit_bid(SubmitBidRequest {
            market_id: market.market_id.clone(),
            provider_id: provider.provider_id,
            sealed_bid_root: sample_hash("sealed-bid", 1),
            redacted_bid_root: sample_hash("redacted-bid", 1),
            requested_reserve_micro_units: 120_000_000,
            max_fee_bps: 10,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet reserve bid submitted");
    let receipt = state
        .publish_proof_receipt(PublishProofReceiptRequest {
            bid_id: bid.bid_id.clone(),
            proof_root: sample_hash("proof", 1),
            reserve_commitment_root: sample_hash("reserve", 2),
            monero_output_set_root: sample_hash("monero-output-set", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            proven_reserve_micro_units: 118_000_000,
            reserve_drift_bps: 60,
            published_slot: DEVNET_SLOT + 16,
        })
        .expect("devnet proof receipt published");
    state
        .record_attestation(RecordAttestationRequest {
            bid_id: bid.bid_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            kind: AttestationKind::SettlementSafe,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("committee-signature", 1),
            observed_slot: DEVNET_SLOT + 18,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet attestation recorded");
    state
        .settle_bid(SettleBidRequest {
            bid_id: bid.bid_id.clone(),
            receipt_id: receipt.receipt_id,
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::ApproveWithRebate,
            settled_slot: DEVNET_SLOT + 20,
        })
        .expect("devnet bid settled");
    state
        .issue_rebate(IssueRebateRequest {
            bid_id: bid.bid_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 900,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 21,
            expires_slot: DEVNET_SLOT + DEFAULT_PROOF_WINDOW_SLOTS,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: bid.bid_id,
            public_fields: [
                "bid_id",
                "market_id",
                "scope",
                "proven_reserve_micro_units",
                "reserve_drift_bps",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "provider_commitment",
                "sealed_bid_root",
                "reserve_commitment_root",
                "monero_output_set_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 816,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 10,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let market = state
        .open_market(OpenMarketRequest {
            scope: ReserveScope::EmergencyExitReserve,
            sealed_market_root: sample_hash("sealed-market", 2),
            public_hint_root: sample_hash("public-hint", 2),
            target_reserve_micro_units: 80_000_000,
            min_proof_slot: DEVNET_SLOT + 64,
            max_proof_slot: DEVNET_SLOT + 640,
            fee_cap_bps: 8,
            opened_slot: DEVNET_SLOT + 64,
        })
        .expect("demo reserve market opened");
    state
        .register_provider(RegisterProviderRequest {
            provider_commitment: sample_hash("provider", 2),
            pq_verifying_key_root: sample_hash("provider-pq-key", 2),
            reserve_commitment_root: sample_hash("reserve", 3),
            bond_micro_units: DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS * 2,
            reserve_micro_units: market.target_reserve_micro_units + 20_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 65,
        })
        .expect("demo reserve provider registered");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!(state.public_record())
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("bridge-reserve-proof-market:{domain}:id"),
        parts,
        24,
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "bridge-reserve-proof-market:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
