use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialLatticeStateCheckpointMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialLatticeStateCheckpointMarketRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_STATE_CHECKPOINT_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-lattice-state-checkpoint-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_STATE_CHECKPOINT_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 2_420_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LATTICE_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+module-lattice-checkpoint-attestation-v1";
pub const SEALED_BID_SUITE: &str = "sealed-confidential-checkpoint-market-bid-v1";
pub const FINALITY_RECEIPT_SUITE: &str =
    "monero-private-l2-lattice-state-checkpoint-finality-receipt-v1";
pub const QUARANTINE_SUITE: &str = "stale-checkpoint-quarantine-and-evidence-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "privacy-redaction-budget-commitment-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MARKET_ID: &str = "devnet-lattice-checkpoint-market";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ATTESTORS: u16 = 5;
pub const DEFAULT_TARGET_ATTESTORS: u16 = 11;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8;
pub const DEFAULT_CHECKPOINT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 12;
pub const DEFAULT_STALE_AFTER_BLOCKS: u64 = 144;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 128;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_MARKETS: usize = 65_536;
pub const MAX_CHECKPOINTS: usize = 1_048_576;
pub const MAX_ATTESTORS: usize = 262_144;
pub const MAX_BIDS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_FINALITY_RECEIPTS: usize = 2_097_152;
pub const MAX_QUARANTINES: usize = 1_048_576;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    MoneroPrivateL2,
    RollupState,
    BridgeState,
    LiquidityState,
    DevnetFixture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    FinalityOnly,
    QuarantineOnly,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::FinalityOnly => "finality_only",
            Self::QuarantineOnly => "quarantine_only",
        }
    }

    pub fn accepts_checkpoints(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_finality(self) -> bool {
        matches!(self, Self::Open | Self::FinalityOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    SequencerState,
    BridgeExitState,
    LiquidityNettingState,
    NullifierSetState,
    FeeMarketState,
    EmergencyRecoveryState,
}

impl CheckpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerState => "sequencer_state",
            Self::BridgeExitState => "bridge_exit_state",
            Self::LiquidityNettingState => "liquidity_netting_state",
            Self::NullifierSetState => "nullifier_set_state",
            Self::FeeMarketState => "fee_market_state",
            Self::EmergencyRecoveryState => "emergency_recovery_state",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    Bidding,
    Attesting,
    Finalized,
    Quarantined,
}

impl CheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bidding => "bidding",
            Self::Attesting => "attesting",
            Self::Finalized => "finalized",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Proposed | Self::Bidding | Self::Attesting)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestorKind {
    LatticeCommittee,
    Watchtower,
    BridgeOperator,
    DevnetOracle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestorStatus {
    Active,
    Probation,
    Retired,
}

impl AttestorStatus {
    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Revealed,
    Selected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithRedactions,
    NeedsMoreWitnesses,
    Stale,
    Invalid,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ValidWithRedactions => "valid_with_redactions",
            Self::NeedsMoreWitnesses => "needs_more_witnesses",
            Self::Stale => "stale",
            Self::Invalid => "invalid",
        }
    }

    pub fn positive(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithRedactions)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Confirmed,
    Challenged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleHeight,
    ConflictingRoot,
    InsufficientQuorum,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleHeight => "stale_height",
            Self::ConflictingRoot => "conflicting_root",
            Self::InsufficientQuorum => "insufficient_quorum",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    LowFeeLane,
    DenseCommittee,
    FastFinality,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeLane => "low_fee_lane",
            Self::DenseCommittee => "dense_committee",
            Self::FastFinality => "fast_finality",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub lattice_attestation_suite: String,
    pub sealed_bid_suite: String,
    pub finality_receipt_suite: String,
    pub quarantine_suite: String,
    pub privacy_redaction_suite: String,
    pub min_pq_security_bits: u16,
    pub min_attestors: u16,
    pub target_attestors: u16,
    pub quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub checkpoint_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub finality_delay_blocks: u64,
    pub stale_after_blocks: u64,
    pub privacy_redaction_budget: u64,
    pub devnet_fixtures_enabled: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            lattice_attestation_suite: LATTICE_ATTESTATION_SUITE.to_string(),
            sealed_bid_suite: SEALED_BID_SUITE.to_string(),
            finality_receipt_suite: FINALITY_RECEIPT_SUITE.to_string(),
            quarantine_suite: QUARANTINE_SUITE.to_string(),
            privacy_redaction_suite: PRIVACY_REDACTION_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attestors: DEFAULT_MIN_ATTESTORS,
            target_attestors: DEFAULT_TARGET_ATTESTORS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            checkpoint_ttl_blocks: DEFAULT_CHECKPOINT_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            finality_delay_blocks: DEFAULT_FINALITY_DELAY_BLOCKS,
            stale_after_blocks: DEFAULT_STALE_AFTER_BLOCKS,
            privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
            devnet_fixtures_enabled: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_lattice_state_checkpoint_market_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "lattice_attestation_suite": self.lattice_attestation_suite,
            "sealed_bid_suite": self.sealed_bid_suite,
            "finality_receipt_suite": self.finality_receipt_suite,
            "quarantine_suite": self.quarantine_suite,
            "privacy_redaction_suite": self.privacy_redaction_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_attestors": self.min_attestors,
            "target_attestors": self.target_attestors,
            "quorum_bps": self.quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "checkpoint_ttl_blocks": self.checkpoint_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "finality_delay_blocks": self.finality_delay_blocks,
            "stale_after_blocks": self.stale_after_blocks,
            "privacy_redaction_budget": self.privacy_redaction_budget,
            "devnet_fixtures_enabled": self.devnet_fixtures_enabled,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub checkpoints: u64,
    pub attestors: u64,
    pub sealed_bids: u64,
    pub lattice_attestations: u64,
    pub finality_receipts: u64,
    pub quarantines: u64,
    pub low_fee_rebates: u64,
    pub privacy_redaction_budgets: u64,
    pub public_records: u64,
    pub nullifier_roots: u64,
    pub deterministic_roots: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_lattice_state_checkpoint_market_counters",
            "markets": self.markets,
            "checkpoints": self.checkpoints,
            "attestors": self.attestors,
            "sealed_bids": self.sealed_bids,
            "lattice_attestations": self.lattice_attestations,
            "finality_receipts": self.finality_receipts,
            "quarantines": self.quarantines,
            "low_fee_rebates": self.low_fee_rebates,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "public_records": self.public_records,
            "nullifier_roots": self.nullifier_roots,
            "deterministic_roots": self.deterministic_roots,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub checkpoint_root: String,
    pub attestor_root: String,
    pub sealed_bid_root: String,
    pub lattice_attestation_root: String,
    pub finality_receipt_root: String,
    pub quarantine_root: String,
    pub low_fee_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
    pub deterministic_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_lattice_state_checkpoint_market_roots",
            "market_root": self.market_root,
            "checkpoint_root": self.checkpoint_root,
            "attestor_root": self.attestor_root,
            "sealed_bid_root": self.sealed_bid_root,
            "lattice_attestation_root": self.lattice_attestation_root,
            "finality_receipt_root": self.finality_receipt_root,
            "quarantine_root": self.quarantine_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "public_record_root": self.public_record_root,
            "nullifier_root": self.nullifier_root,
            "deterministic_root": self.deterministic_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CheckpointMarket {
    pub market_id: String,
    pub market_kind: MarketKind,
    pub status: MarketStatus,
    pub sponsor_id: String,
    pub base_fee_commitment: String,
    pub market_policy_root: String,
    pub attestor_set_root: String,
    pub accepted_checkpoint_kinds: BTreeSet<CheckpointKind>,
    pub min_attestors: u16,
    pub target_attestors: u16,
    pub quorum_bps: u64,
    pub low_fee_lane: bool,
    pub opened_height: u64,
    pub expires_height: u64,
    pub notes: Vec<String>,
}

impl CheckpointMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_market",
            "market_id": self.market_id,
            "market_kind": self.market_kind,
            "status": self.status.as_str(),
            "sponsor_id": self.sponsor_id,
            "base_fee_commitment": self.base_fee_commitment,
            "market_policy_root": self.market_policy_root,
            "attestor_set_root": self.attestor_set_root,
            "accepted_checkpoint_kinds": self.accepted_checkpoint_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>(),
            "min_attestors": self.min_attestors,
            "target_attestors": self.target_attestors,
            "quorum_bps": self.quorum_bps,
            "low_fee_lane": self.low_fee_lane,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "notes": self.notes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StateCheckpoint {
    pub checkpoint_id: String,
    pub market_id: String,
    pub checkpoint_kind: CheckpointKind,
    pub status: CheckpointStatus,
    pub l2_height: u64,
    pub monero_height: u64,
    pub proposer_id: String,
    pub state_root_commitment: String,
    pub previous_state_root: String,
    pub deterministic_root: String,
    pub nullifier_root: String,
    pub redacted_payload_root: String,
    pub bid_window_end: u64,
    pub attestation_window_end: u64,
    pub finality_eligible_height: u64,
    pub privacy_redaction_budget_id: String,
    pub selected_bid_id: Option<String>,
    pub finality_receipt_id: Option<String>,
}

impl StateCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "checkpoint_kind": self.checkpoint_kind.as_str(),
            "status": self.status.as_str(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "proposer_id": self.proposer_id,
            "state_root_commitment": self.state_root_commitment,
            "previous_state_root": self.previous_state_root,
            "deterministic_root": self.deterministic_root,
            "nullifier_root": self.nullifier_root,
            "redacted_payload_root": self.redacted_payload_root,
            "bid_window_end": self.bid_window_end,
            "attestation_window_end": self.attestation_window_end,
            "finality_eligible_height": self.finality_eligible_height,
            "privacy_redaction_budget_id": self.privacy_redaction_budget_id,
            "selected_bid_id": self.selected_bid_id,
            "finality_receipt_id": self.finality_receipt_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqLatticeAttestor {
    pub attestor_id: String,
    pub attestor_kind: AttestorKind,
    pub status: AttestorStatus,
    pub operator_commitment: String,
    pub lattice_public_key_commitment: String,
    pub stake_commitment: String,
    pub reputation_score: u64,
    pub pq_security_bits: u16,
    pub supported_markets: BTreeSet<String>,
    pub accepted_checkpoint_kinds: BTreeSet<CheckpointKind>,
    pub last_attested_height: u64,
    pub registered_height: u64,
}

impl PqLatticeAttestor {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_lattice_attestor",
            "attestor_id": self.attestor_id,
            "attestor_kind": self.attestor_kind,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "lattice_public_key_commitment": self.lattice_public_key_commitment,
            "stake_commitment": self.stake_commitment,
            "reputation_score": self.reputation_score,
            "pq_security_bits": self.pq_security_bits,
            "supported_markets": self.supported_markets.iter().cloned().collect::<Vec<_>>(),
            "accepted_checkpoint_kinds": self.accepted_checkpoint_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>(),
            "last_attested_height": self.last_attested_height,
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCheckpointBid {
    pub bid_id: String,
    pub checkpoint_id: String,
    pub market_id: String,
    pub bidder_id: String,
    pub status: BidStatus,
    pub sealed_price_commitment: String,
    pub sealed_latency_commitment: String,
    pub sealed_witness_bundle_root: String,
    pub collateral_commitment: String,
    pub max_fee_bps: u64,
    pub low_fee_lane: bool,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl SealedCheckpointBid {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_checkpoint_bid",
            "bid_id": self.bid_id,
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "bidder_id": self.bidder_id,
            "status": self.status,
            "sealed_price_commitment": self.sealed_price_commitment,
            "sealed_latency_commitment": self.sealed_latency_commitment,
            "sealed_witness_bundle_root": self.sealed_witness_bundle_root,
            "collateral_commitment": self.collateral_commitment,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_lane": self.low_fee_lane,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LatticeAttestation {
    pub attestation_id: String,
    pub checkpoint_id: String,
    pub market_id: String,
    pub attestor_id: String,
    pub verdict: AttestationVerdict,
    pub lattice_signature_root: String,
    pub witness_commitment_root: String,
    pub redaction_transcript_root: String,
    pub deterministic_root: String,
    pub attested_height: u64,
    pub expires_height: u64,
    pub pq_security_bits: u16,
    pub weight_bps: u64,
}

impl LatticeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lattice_attestation",
            "attestation_id": self.attestation_id,
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "attestor_id": self.attestor_id,
            "verdict": self.verdict.as_str(),
            "lattice_signature_root": self.lattice_signature_root,
            "witness_commitment_root": self.witness_commitment_root,
            "redaction_transcript_root": self.redaction_transcript_root,
            "deterministic_root": self.deterministic_root,
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
            "pq_security_bits": self.pq_security_bits,
            "weight_bps": self.weight_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FinalityReceipt {
    pub receipt_id: String,
    pub checkpoint_id: String,
    pub market_id: String,
    pub status: ReceiptStatus,
    pub finalized_state_root: String,
    pub finality_root: String,
    pub attestation_bundle_root: String,
    pub selected_bid_id: String,
    pub quorum_weight_bps: u64,
    pub finalized_height: u64,
    pub monero_anchor_height: u64,
    pub receipt_memo_root: String,
}

impl FinalityReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_receipt",
            "receipt_id": self.receipt_id,
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "status": self.status,
            "finalized_state_root": self.finalized_state_root,
            "finality_root": self.finality_root,
            "attestation_bundle_root": self.attestation_bundle_root,
            "selected_bid_id": self.selected_bid_id,
            "quorum_weight_bps": self.quorum_weight_bps,
            "finalized_height": self.finalized_height,
            "monero_anchor_height": self.monero_anchor_height,
            "receipt_memo_root": self.receipt_memo_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StaleCheckpointQuarantine {
    pub quarantine_id: String,
    pub checkpoint_id: String,
    pub market_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub conflicting_root: Option<String>,
    pub reporter_id: String,
    pub quarantined_height: u64,
    pub review_after_height: u64,
    pub released: bool,
}

impl StaleCheckpointQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stale_checkpoint_quarantine",
            "quarantine_id": self.quarantine_id,
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "conflicting_root": self.conflicting_root,
            "reporter_id": self.reporter_id,
            "quarantined_height": self.quarantined_height,
            "review_after_height": self.review_after_height,
            "released": self.released,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeAttestationRebate {
    pub rebate_id: String,
    pub checkpoint_id: String,
    pub market_id: String,
    pub attestor_id: String,
    pub recipient_commitment: String,
    pub reason: RebateReason,
    pub fee_asset_id: String,
    pub gross_fee_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub issued_height: u64,
}

impl LowFeeAttestationRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_attestation_rebate",
            "rebate_id": self.rebate_id,
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "attestor_id": self.attestor_id,
            "recipient_commitment": self.recipient_commitment,
            "reason": self.reason.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_commitment": self.gross_fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub checkpoint_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub budget_limit: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub redaction_policy_root: String,
    pub redaction_nullifier_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_redaction_budget",
            "budget_id": self.budget_id,
            "checkpoint_id": self.checkpoint_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "budget_limit": self.budget_limit,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units,
            "redaction_policy_root": self.redaction_policy_root,
            "redaction_nullifier_root": self.redaction_nullifier_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicRuntimeRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload: Value,
}

impl PublicRuntimeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_lattice_state_checkpoint_market_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub markets: BTreeMap<String, CheckpointMarket>,
    pub checkpoints: BTreeMap<String, StateCheckpoint>,
    pub attestors: BTreeMap<String, PqLatticeAttestor>,
    pub sealed_bids: BTreeMap<String, SealedCheckpointBid>,
    pub lattice_attestations: BTreeMap<String, LatticeAttestation>,
    pub finality_receipts: BTreeMap<String, FinalityReceipt>,
    pub quarantines: BTreeMap<String, StaleCheckpointQuarantine>,
    pub low_fee_rebates: BTreeMap<String, LowFeeAttestationRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_records: BTreeMap<String, PublicRuntimeRecord>,
    pub nullifier_roots: BTreeSet<String>,
    pub deterministic_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        ensure_nonempty("protocol_version", &config.protocol_version)?;
        ensure_nonempty("chain_id", &config.chain_id)?;
        ensure_bps("quorum_bps", config.quorum_bps)?;
        ensure_bps("max_user_fee_bps", config.max_user_fee_bps)?;
        ensure_bps("target_user_fee_bps", config.target_user_fee_bps)?;
        ensure_bps("low_fee_rebate_bps", config.low_fee_rebate_bps)?;
        if config.min_attestors == 0 {
            return Err("min_attestors must be nonzero".to_string());
        }
        if config.target_attestors < config.min_attestors {
            return Err("target_attestors must be >= min_attestors".to_string());
        }
        if config.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be >= 128".to_string());
        }
        Ok(Self {
            config,
            height,
            markets: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            attestors: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            lattice_attestations: BTreeMap::new(),
            finality_receipts: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifier_roots: BTreeSet::new(),
            deterministic_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT).expect("valid devnet config");
        state
            .install_devnet_fixtures()
            .expect("valid devnet fixtures");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let checkpoint_id = state
            .submit_checkpoint(
                DEFAULT_MARKET_ID,
                CheckpointKind::BridgeExitState,
                "demo-sequencer",
                sample_hash("demo-state-root"),
                sample_hash("devnet-state-root"),
                sample_hash("demo-redacted-payload"),
            )
            .expect("demo checkpoint");
        let bid_id = state
            .submit_sealed_bid(
                &checkpoint_id,
                "demo-bidder",
                sample_hash("demo-price"),
                sample_hash("demo-latency"),
                sample_hash("demo-witness-bundle"),
                true,
            )
            .expect("demo sealed bid");
        state
            .select_bid(&checkpoint_id, &bid_id)
            .expect("select bid");
        for index in 0..DEFAULT_MIN_ATTESTORS {
            let attestor_id = format!("demo-attestor-{index}");
            state
                .register_attestor(
                    &attestor_id,
                    AttestorKind::LatticeCommittee,
                    sample_hash(&format!("{attestor_id}-pk")),
                    sample_hash(&format!("{attestor_id}-stake")),
                )
                .expect("demo attestor");
            state
                .record_lattice_attestation(
                    &checkpoint_id,
                    &attestor_id,
                    AttestationVerdict::Valid,
                    sample_hash(&format!("{attestor_id}-sig")),
                    sample_hash(&format!("{attestor_id}-witness")),
                )
                .expect("demo attestation");
        }
        state
            .issue_finality_receipt(&checkpoint_id, state.height + DEFAULT_FINALITY_DELAY_BLOCKS)
            .expect("demo finality receipt");
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            markets: self.markets.len() as u64,
            checkpoints: self.checkpoints.len() as u64,
            attestors: self.attestors.len() as u64,
            sealed_bids: self.sealed_bids.len() as u64,
            lattice_attestations: self.lattice_attestations.len() as u64,
            finality_receipts: self.finality_receipts.len() as u64,
            quarantines: self.quarantines.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            privacy_redaction_budgets: self.privacy_redaction_budgets.len() as u64,
            public_records: self.public_records.len() as u64,
            nullifier_roots: self.nullifier_roots.len() as u64,
            deterministic_roots: self.deterministic_roots.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            market_root: map_root(
                "private_l2_pq_lattice_checkpoint:markets",
                &self.markets,
                CheckpointMarket::public_record,
            ),
            checkpoint_root: map_root(
                "private_l2_pq_lattice_checkpoint:checkpoints",
                &self.checkpoints,
                StateCheckpoint::public_record,
            ),
            attestor_root: map_root(
                "private_l2_pq_lattice_checkpoint:attestors",
                &self.attestors,
                PqLatticeAttestor::public_record,
            ),
            sealed_bid_root: map_root(
                "private_l2_pq_lattice_checkpoint:sealed_bids",
                &self.sealed_bids,
                SealedCheckpointBid::public_record,
            ),
            lattice_attestation_root: map_root(
                "private_l2_pq_lattice_checkpoint:lattice_attestations",
                &self.lattice_attestations,
                LatticeAttestation::public_record,
            ),
            finality_receipt_root: map_root(
                "private_l2_pq_lattice_checkpoint:finality_receipts",
                &self.finality_receipts,
                FinalityReceipt::public_record,
            ),
            quarantine_root: map_root(
                "private_l2_pq_lattice_checkpoint:quarantines",
                &self.quarantines,
                StaleCheckpointQuarantine::public_record,
            ),
            low_fee_rebate_root: map_root(
                "private_l2_pq_lattice_checkpoint:rebates",
                &self.low_fee_rebates,
                LowFeeAttestationRebate::public_record,
            ),
            privacy_redaction_budget_root: map_root(
                "private_l2_pq_lattice_checkpoint:redaction_budgets",
                &self.privacy_redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            public_record_root: map_root(
                "private_l2_pq_lattice_checkpoint:public_records",
                &self.public_records,
                PublicRuntimeRecord::public_record,
            ),
            nullifier_root: set_root(
                "private_l2_pq_lattice_checkpoint:nullifier_roots",
                &self.nullifier_roots,
            ),
            deterministic_root: set_root(
                "private_l2_pq_lattice_checkpoint:deterministic_roots",
                &self.deterministic_roots,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_lattice_state_checkpoint_market_state",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn open_market(
        &mut self,
        market_id: impl Into<String>,
        market_kind: MarketKind,
        sponsor_id: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity("markets", self.markets.len(), MAX_MARKETS)?;
        let market_id = market_id.into();
        let sponsor_id = sponsor_id.into();
        ensure_nonempty("market_id", &market_id)?;
        ensure_nonempty("sponsor_id", &sponsor_id)?;
        if self.markets.contains_key(&market_id) {
            return Err(format!("market already exists: {market_id}"));
        }
        let accepted_checkpoint_kinds = [
            CheckpointKind::SequencerState,
            CheckpointKind::BridgeExitState,
            CheckpointKind::LiquidityNettingState,
            CheckpointKind::NullifierSetState,
            CheckpointKind::FeeMarketState,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let market = CheckpointMarket {
            market_id: market_id.clone(),
            market_kind,
            status: MarketStatus::Open,
            sponsor_id,
            base_fee_commitment: sample_hash(&format!("{market_id}:base-fee")),
            market_policy_root: sample_hash(&format!("{market_id}:policy")),
            attestor_set_root: sample_hash(&format!("{market_id}:attestor-set")),
            accepted_checkpoint_kinds,
            min_attestors: self.config.min_attestors,
            target_attestors: self.config.target_attestors,
            quorum_bps: self.config.quorum_bps,
            low_fee_lane: true,
            opened_height: self.height,
            expires_height: self.height + self.config.checkpoint_ttl_blocks * 1_024,
            notes: vec!["devnet-compatible confidential checkpoint market".to_string()],
        };
        self.publish("market", &market_id, market.public_record())?;
        self.markets.insert(market_id.clone(), market);
        Ok(market_id)
    }

    pub fn register_attestor(
        &mut self,
        attestor_id: impl Into<String>,
        attestor_kind: AttestorKind,
        lattice_public_key_commitment: impl Into<String>,
        stake_commitment: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity("attestors", self.attestors.len(), MAX_ATTESTORS)?;
        let attestor_id = attestor_id.into();
        let lattice_public_key_commitment = lattice_public_key_commitment.into();
        let stake_commitment = stake_commitment.into();
        ensure_nonempty("attestor_id", &attestor_id)?;
        ensure_hash_like(
            "lattice_public_key_commitment",
            &lattice_public_key_commitment,
        )?;
        ensure_hash_like("stake_commitment", &stake_commitment)?;
        if self.attestors.contains_key(&attestor_id) {
            return Err(format!("attestor already exists: {attestor_id}"));
        }
        let supported_markets = self.markets.keys().cloned().collect::<BTreeSet<_>>();
        let accepted_checkpoint_kinds = [
            CheckpointKind::SequencerState,
            CheckpointKind::BridgeExitState,
            CheckpointKind::LiquidityNettingState,
            CheckpointKind::NullifierSetState,
            CheckpointKind::FeeMarketState,
            CheckpointKind::EmergencyRecoveryState,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let attestor = PqLatticeAttestor {
            attestor_id: attestor_id.clone(),
            attestor_kind,
            status: AttestorStatus::Active,
            operator_commitment: sample_hash(&format!("{attestor_id}:operator")),
            lattice_public_key_commitment,
            stake_commitment,
            reputation_score: 1_000,
            pq_security_bits: self.config.min_pq_security_bits,
            supported_markets,
            accepted_checkpoint_kinds,
            last_attested_height: 0,
            registered_height: self.height,
        };
        self.publish("attestor", &attestor_id, attestor.public_record())?;
        self.attestors.insert(attestor_id.clone(), attestor);
        Ok(attestor_id)
    }

    pub fn submit_checkpoint(
        &mut self,
        market_id: &str,
        checkpoint_kind: CheckpointKind,
        proposer_id: impl Into<String>,
        state_root_commitment: impl Into<String>,
        previous_state_root: impl Into<String>,
        redacted_payload_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity("checkpoints", self.checkpoints.len(), MAX_CHECKPOINTS)?;
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| format!("unknown market: {market_id}"))?;
        if !market.status.accepts_checkpoints() {
            return Err(format!("market does not accept checkpoints: {market_id}"));
        }
        if !market.accepted_checkpoint_kinds.contains(&checkpoint_kind) {
            return Err(format!(
                "checkpoint kind not accepted by market: {}",
                checkpoint_kind.as_str()
            ));
        }
        let proposer_id = proposer_id.into();
        let state_root_commitment = state_root_commitment.into();
        let previous_state_root = previous_state_root.into();
        let redacted_payload_root = redacted_payload_root.into();
        ensure_nonempty("proposer_id", &proposer_id)?;
        ensure_hash_like("state_root_commitment", &state_root_commitment)?;
        ensure_hash_like("previous_state_root", &previous_state_root)?;
        ensure_hash_like("redacted_payload_root", &redacted_payload_root)?;
        let deterministic_root = checkpoint_deterministic_root(
            market_id,
            checkpoint_kind,
            self.height,
            &state_root_commitment,
            &previous_state_root,
            &redacted_payload_root,
        );
        let nullifier_root = checkpoint_nullifier_root(market_id, self.height, &deterministic_root);
        if !self.deterministic_roots.insert(deterministic_root.clone()) {
            return Err("duplicate deterministic checkpoint root".to_string());
        }
        self.nullifier_roots.insert(nullifier_root.clone());
        let checkpoint_id = checkpoint_id(
            market_id,
            checkpoint_kind,
            self.height,
            &state_root_commitment,
            &deterministic_root,
        );
        let budget_id = redaction_budget_id(&checkpoint_id, market_id, &proposer_id);
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            checkpoint_id: checkpoint_id.clone(),
            market_id: market_id.to_string(),
            owner_commitment: sample_hash(&format!("{checkpoint_id}:redaction-owner")),
            budget_limit: self.config.privacy_redaction_budget,
            spent_units: 0,
            remaining_units: self.config.privacy_redaction_budget,
            redaction_policy_root: sample_hash(&format!("{checkpoint_id}:redaction-policy")),
            redaction_nullifier_root: sample_hash(&format!("{checkpoint_id}:redaction-nullifier")),
            opened_height: self.height,
            expires_height: self.height + self.config.checkpoint_ttl_blocks,
        };
        let checkpoint = StateCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            market_id: market_id.to_string(),
            checkpoint_kind,
            status: CheckpointStatus::Bidding,
            l2_height: self.height,
            monero_height: self.height / 2,
            proposer_id,
            state_root_commitment,
            previous_state_root,
            deterministic_root,
            nullifier_root,
            redacted_payload_root,
            bid_window_end: self.height + self.config.bid_ttl_blocks,
            attestation_window_end: self.height + self.config.attestation_ttl_blocks,
            finality_eligible_height: self.height + self.config.finality_delay_blocks,
            privacy_redaction_budget_id: budget_id.clone(),
            selected_bid_id: None,
            finality_receipt_id: None,
        };
        self.publish(
            "privacy_redaction_budget",
            &budget_id,
            budget.public_record(),
        )?;
        self.publish("checkpoint", &checkpoint_id, checkpoint.public_record())?;
        self.privacy_redaction_budgets.insert(budget_id, budget);
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        Ok(checkpoint_id)
    }

    pub fn submit_sealed_bid(
        &mut self,
        checkpoint_id: &str,
        bidder_id: impl Into<String>,
        sealed_price_commitment: impl Into<String>,
        sealed_latency_commitment: impl Into<String>,
        sealed_witness_bundle_root: impl Into<String>,
        low_fee_lane: bool,
    ) -> Result<String> {
        ensure_capacity("sealed_bids", self.sealed_bids.len(), MAX_BIDS)?;
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint: {checkpoint_id}"))?;
        if !checkpoint.status.is_live() {
            return Err(format!("checkpoint does not accept bids: {checkpoint_id}"));
        }
        let bidder_id = bidder_id.into();
        let sealed_price_commitment = sealed_price_commitment.into();
        let sealed_latency_commitment = sealed_latency_commitment.into();
        let sealed_witness_bundle_root = sealed_witness_bundle_root.into();
        ensure_nonempty("bidder_id", &bidder_id)?;
        ensure_hash_like("sealed_price_commitment", &sealed_price_commitment)?;
        ensure_hash_like("sealed_latency_commitment", &sealed_latency_commitment)?;
        ensure_hash_like("sealed_witness_bundle_root", &sealed_witness_bundle_root)?;
        let bid_id = sealed_bid_id(
            checkpoint_id,
            &checkpoint.market_id,
            &bidder_id,
            &sealed_price_commitment,
            &sealed_witness_bundle_root,
        );
        if self.sealed_bids.contains_key(&bid_id) {
            return Err(format!("sealed bid already exists: {bid_id}"));
        }
        let bid = SealedCheckpointBid {
            bid_id: bid_id.clone(),
            checkpoint_id: checkpoint_id.to_string(),
            market_id: checkpoint.market_id.clone(),
            bidder_id,
            status: BidStatus::Sealed,
            sealed_price_commitment,
            sealed_latency_commitment,
            sealed_witness_bundle_root,
            collateral_commitment: sample_hash(&format!("{bid_id}:collateral")),
            max_fee_bps: if low_fee_lane {
                self.config.target_user_fee_bps
            } else {
                self.config.max_user_fee_bps
            },
            low_fee_lane,
            submitted_height: self.height,
            expires_height: self.height + self.config.bid_ttl_blocks,
        };
        self.publish("sealed_bid", &bid_id, bid.public_record())?;
        self.sealed_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn select_bid(&mut self, checkpoint_id: &str, bid_id: &str) -> Result<()> {
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint: {checkpoint_id}"))?;
        let bid = self
            .sealed_bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown sealed bid: {bid_id}"))?;
        if bid.checkpoint_id != checkpoint_id {
            return Err("sealed bid belongs to a different checkpoint".to_string());
        }
        bid.status = BidStatus::Selected;
        checkpoint.status = CheckpointStatus::Attesting;
        checkpoint.selected_bid_id = Some(bid_id.to_string());
        Ok(())
    }

    pub fn record_lattice_attestation(
        &mut self,
        checkpoint_id: &str,
        attestor_id: &str,
        verdict: AttestationVerdict,
        lattice_signature_root: impl Into<String>,
        witness_commitment_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(
            "lattice_attestations",
            self.lattice_attestations.len(),
            MAX_ATTESTATIONS,
        )?;
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint: {checkpoint_id}"))?;
        let attestor = self
            .attestors
            .get_mut(attestor_id)
            .ok_or_else(|| format!("unknown attestor: {attestor_id}"))?;
        if !attestor.status.can_attest() {
            return Err(format!("attestor cannot attest: {attestor_id}"));
        }
        if attestor.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestor pq security below configured minimum".to_string());
        }
        let lattice_signature_root = lattice_signature_root.into();
        let witness_commitment_root = witness_commitment_root.into();
        ensure_hash_like("lattice_signature_root", &lattice_signature_root)?;
        ensure_hash_like("witness_commitment_root", &witness_commitment_root)?;
        let deterministic_root = attestation_deterministic_root(
            checkpoint_id,
            attestor_id,
            verdict,
            &lattice_signature_root,
            &witness_commitment_root,
        );
        let attestation_id = attestation_id(checkpoint_id, attestor_id, &deterministic_root);
        if self.lattice_attestations.contains_key(&attestation_id) {
            return Err(format!("attestation already exists: {attestation_id}"));
        }
        let attestation = LatticeAttestation {
            attestation_id: attestation_id.clone(),
            checkpoint_id: checkpoint_id.to_string(),
            market_id: checkpoint.market_id.clone(),
            attestor_id: attestor_id.to_string(),
            verdict,
            lattice_signature_root,
            witness_commitment_root,
            redaction_transcript_root: sample_hash(&format!("{attestation_id}:redactions")),
            deterministic_root,
            attested_height: self.height,
            expires_height: self.height + self.config.attestation_ttl_blocks,
            pq_security_bits: attestor.pq_security_bits,
            weight_bps: if verdict.positive() { 2_000 } else { 0 },
        };
        attestor.last_attested_height = self.height;
        self.publish(
            "lattice_attestation",
            &attestation_id,
            attestation.public_record(),
        )?;
        self.lattice_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn issue_finality_receipt(
        &mut self,
        checkpoint_id: &str,
        finalized_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "finality_receipts",
            self.finality_receipts.len(),
            MAX_FINALITY_RECEIPTS,
        )?;
        let checkpoint_view = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint: {checkpoint_id}"))?;
        let market = self
            .markets
            .get(&checkpoint_view.market_id)
            .ok_or_else(|| format!("unknown market: {}", checkpoint_view.market_id))?;
        if !market.status.accepts_finality() {
            return Err(format!(
                "market does not accept finality: {}",
                market.market_id
            ));
        }
        if checkpoint_view.selected_bid_id.is_none() {
            return Err("checkpoint has no selected sealed bid".to_string());
        }
        let quorum_weight_bps = self.quorum_weight_bps(checkpoint_id);
        if quorum_weight_bps < market.quorum_bps {
            return Err(format!(
                "quorum below threshold: {quorum_weight_bps} < {}",
                market.quorum_bps
            ));
        }
        let selected_bid_id = checkpoint_view
            .selected_bid_id
            .clone()
            .expect("checked selected bid");
        let receipt_id = finality_receipt_id(
            checkpoint_id,
            &checkpoint_view.market_id,
            &checkpoint_view.state_root_commitment,
            finalized_height,
        );
        if self.finality_receipts.contains_key(&receipt_id) {
            return Err(format!("finality receipt already exists: {receipt_id}"));
        }
        let attestation_bundle_root = self.attestation_bundle_root(checkpoint_id);
        let receipt = FinalityReceipt {
            receipt_id: receipt_id.clone(),
            checkpoint_id: checkpoint_id.to_string(),
            market_id: checkpoint_view.market_id.clone(),
            status: ReceiptStatus::Confirmed,
            finalized_state_root: checkpoint_view.state_root_commitment.clone(),
            finality_root: sample_hash(&format!("{receipt_id}:finality")),
            attestation_bundle_root,
            selected_bid_id,
            quorum_weight_bps,
            finalized_height,
            monero_anchor_height: finalized_height / 2,
            receipt_memo_root: sample_hash(&format!("{receipt_id}:memo")),
        };
        self.publish("finality_receipt", &receipt_id, receipt.public_record())?;
        self.finality_receipts
            .insert(receipt_id.clone(), receipt.clone());
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .expect("checkpoint exists");
        checkpoint.status = CheckpointStatus::Finalized;
        checkpoint.finality_receipt_id = Some(receipt_id.clone());
        self.issue_low_fee_rebates(checkpoint_id)?;
        Ok(receipt_id)
    }

    pub fn quarantine_stale_checkpoint(
        &mut self,
        checkpoint_id: &str,
        reason: QuarantineReason,
        reporter_id: impl Into<String>,
        evidence_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity("quarantines", self.quarantines.len(), MAX_QUARANTINES)?;
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint: {checkpoint_id}"))?;
        let reporter_id = reporter_id.into();
        let evidence_root = evidence_root.into();
        ensure_nonempty("reporter_id", &reporter_id)?;
        ensure_hash_like("evidence_root", &evidence_root)?;
        let quarantine_id =
            quarantine_id(checkpoint_id, &checkpoint.market_id, reason, &evidence_root);
        let quarantine = StaleCheckpointQuarantine {
            quarantine_id: quarantine_id.clone(),
            checkpoint_id: checkpoint_id.to_string(),
            market_id: checkpoint.market_id.clone(),
            reason,
            evidence_root,
            conflicting_root: Some(checkpoint.state_root_commitment.clone()),
            reporter_id,
            quarantined_height: self.height,
            review_after_height: self.height + self.config.stale_after_blocks,
            released: false,
        };
        checkpoint.status = CheckpointStatus::Quarantined;
        self.publish(
            "stale_checkpoint_quarantine",
            &quarantine_id,
            quarantine.public_record(),
        )?;
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        Ok(quarantine_id)
    }

    fn issue_low_fee_rebates(&mut self, checkpoint_id: &str) -> Result<()> {
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint: {checkpoint_id}"))?;
        let selected_bid_id = checkpoint
            .selected_bid_id
            .clone()
            .ok_or_else(|| "checkpoint has no selected bid".to_string())?;
        let bid = self
            .sealed_bids
            .get(&selected_bid_id)
            .ok_or_else(|| format!("unknown selected bid: {selected_bid_id}"))?;
        if !bid.low_fee_lane {
            return Ok(());
        }
        let attestor_ids = self
            .lattice_attestations
            .values()
            .filter(|attestation| {
                attestation.checkpoint_id == checkpoint_id && attestation.verdict.positive()
            })
            .map(|attestation| attestation.attestor_id.clone())
            .collect::<Vec<_>>();
        for attestor_id in attestor_ids {
            ensure_capacity("low_fee_rebates", self.low_fee_rebates.len(), MAX_REBATES)?;
            let rebate_id = low_fee_rebate_id(
                checkpoint_id,
                &checkpoint.market_id,
                &attestor_id,
                RebateReason::LowFeeLane,
            );
            if self.low_fee_rebates.contains_key(&rebate_id) {
                continue;
            }
            let rebate = LowFeeAttestationRebate {
                rebate_id: rebate_id.clone(),
                checkpoint_id: checkpoint_id.to_string(),
                market_id: checkpoint.market_id.clone(),
                attestor_id: attestor_id.clone(),
                recipient_commitment: sample_hash(&format!("{attestor_id}:rebate-recipient")),
                reason: RebateReason::LowFeeLane,
                fee_asset_id: self.config.fee_asset_id.clone(),
                gross_fee_commitment: sample_hash(&format!("{checkpoint_id}:gross-fee")),
                rebate_commitment: sample_hash(&format!("{rebate_id}:rebate")),
                rebate_bps: self.config.low_fee_rebate_bps,
                issued_height: self.height,
            };
            self.publish(
                "low_fee_attestation_rebate",
                &rebate_id,
                rebate.public_record(),
            )?;
            self.low_fee_rebates.insert(rebate_id, rebate);
        }
        Ok(())
    }

    fn quorum_weight_bps(&self, checkpoint_id: &str) -> u64 {
        self.lattice_attestations
            .values()
            .filter(|attestation| {
                attestation.checkpoint_id == checkpoint_id && attestation.verdict.positive()
            })
            .map(|attestation| attestation.weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    fn attestation_bundle_root(&self, checkpoint_id: &str) -> String {
        let leaves = self
            .lattice_attestations
            .values()
            .filter(|attestation| attestation.checkpoint_id == checkpoint_id)
            .map(LatticeAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "private_l2_pq_lattice_checkpoint:attestation_bundle",
            &leaves,
        )
    }

    fn install_devnet_fixtures(&mut self) -> Result<()> {
        self.open_market(
            DEFAULT_MARKET_ID,
            MarketKind::MoneroPrivateL2,
            "devnet-market-sponsor",
        )?;
        for index in 0..self.config.min_attestors {
            let attestor_id = format!("devnet-lattice-attestor-{index}");
            self.register_attestor(
                &attestor_id,
                AttestorKind::DevnetOracle,
                sample_hash(&format!("{attestor_id}:pk")),
                sample_hash(&format!("{attestor_id}:stake")),
            )?;
        }
        let checkpoint_id = self.submit_checkpoint(
            DEFAULT_MARKET_ID,
            CheckpointKind::SequencerState,
            "devnet-sequencer",
            sample_hash("devnet-state-root"),
            sample_hash("genesis-state-root"),
            sample_hash("devnet-redacted-payload"),
        )?;
        let bid_id = self.submit_sealed_bid(
            &checkpoint_id,
            "devnet-bidder",
            sample_hash("devnet-sealed-price"),
            sample_hash("devnet-sealed-latency"),
            sample_hash("devnet-sealed-witness"),
            true,
        )?;
        self.select_bid(&checkpoint_id, &bid_id)?;
        for index in 0..self.config.min_attestors {
            let attestor_id = format!("devnet-lattice-attestor-{index}");
            self.record_lattice_attestation(
                &checkpoint_id,
                &attestor_id,
                AttestationVerdict::ValidWithRedactions,
                sample_hash(&format!("{attestor_id}:signature")),
                sample_hash(&format!("{attestor_id}:witness")),
            )?;
        }
        self.issue_finality_receipt(
            &checkpoint_id,
            self.height + self.config.finality_delay_blocks,
        )?;
        let stale_checkpoint_id = self.submit_checkpoint(
            DEFAULT_MARKET_ID,
            CheckpointKind::FeeMarketState,
            "devnet-fee-sequencer",
            sample_hash("stale-state-root"),
            sample_hash("devnet-state-root"),
            sample_hash("stale-redacted-payload"),
        )?;
        self.quarantine_stale_checkpoint(
            &stale_checkpoint_id,
            QuarantineReason::StaleHeight,
            "devnet-watchtower",
            sample_hash("stale-evidence-root"),
        )?;
        Ok(())
    }

    fn publish(&mut self, record_kind: &str, subject_id: &str, payload: Value) -> Result<()> {
        ensure_capacity(
            "public_records",
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
        )?;
        let record_id = public_record_id(record_kind, subject_id, self.height, &payload);
        if self.public_records.contains_key(&record_id) {
            return Err(format!("public record already exists: {record_id}"));
        }
        let record = PublicRuntimeRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            payload,
        };
        self.public_records.insert(record_id, record);
        Ok(())
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:state_root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn checkpoint_id(
    market_id: &str,
    checkpoint_kind: CheckpointKind,
    height: u64,
    state_root_commitment: &str,
    deterministic_root: &str,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:checkpoint_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(checkpoint_kind.as_str()),
            HashPart::U64(height),
            HashPart::Str(state_root_commitment),
            HashPart::Str(deterministic_root),
        ],
        32,
    )
}

pub fn checkpoint_deterministic_root(
    market_id: &str,
    checkpoint_kind: CheckpointKind,
    height: u64,
    state_root_commitment: &str,
    previous_state_root: &str,
    redacted_payload_root: &str,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:deterministic_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(checkpoint_kind.as_str()),
            HashPart::U64(height),
            HashPart::Str(state_root_commitment),
            HashPart::Str(previous_state_root),
            HashPart::Str(redacted_payload_root),
        ],
        32,
    )
}

pub fn checkpoint_nullifier_root(market_id: &str, height: u64, deterministic_root: &str) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:nullifier_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::U64(height),
            HashPart::Str(deterministic_root),
        ],
        32,
    )
}

pub fn sealed_bid_id(
    checkpoint_id: &str,
    market_id: &str,
    bidder_id: &str,
    sealed_price_commitment: &str,
    sealed_witness_bundle_root: &str,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:sealed_bid_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(market_id),
            HashPart::Str(bidder_id),
            HashPart::Str(sealed_price_commitment),
            HashPart::Str(sealed_witness_bundle_root),
        ],
        32,
    )
}

pub fn attestation_id(checkpoint_id: &str, attestor_id: &str, deterministic_root: &str) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:attestation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(attestor_id),
            HashPart::Str(deterministic_root),
        ],
        32,
    )
}

pub fn attestation_deterministic_root(
    checkpoint_id: &str,
    attestor_id: &str,
    verdict: AttestationVerdict,
    lattice_signature_root: &str,
    witness_commitment_root: &str,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:attestation_deterministic_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(attestor_id),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(lattice_signature_root),
            HashPart::Str(witness_commitment_root),
        ],
        32,
    )
}

pub fn finality_receipt_id(
    checkpoint_id: &str,
    market_id: &str,
    finalized_state_root: &str,
    finalized_height: u64,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:finality_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(market_id),
            HashPart::Str(finalized_state_root),
            HashPart::U64(finalized_height),
        ],
        32,
    )
}

pub fn quarantine_id(
    checkpoint_id: &str,
    market_id: &str,
    reason: QuarantineReason,
    evidence_root: &str,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:quarantine_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(market_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(
    checkpoint_id: &str,
    market_id: &str,
    attestor_id: &str,
    reason: RebateReason,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:low_fee_rebate_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(market_id),
            HashPart::Str(attestor_id),
            HashPart::Str(reason.as_str()),
        ],
        32,
    )
}

pub fn redaction_budget_id(checkpoint_id: &str, market_id: &str, owner_id: &str) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:redaction_budget_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(market_id),
            HashPart::Str(owner_id),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    height: u64,
    payload: &Value,
) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:public_record_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        Err(format!("{field} must be at least 16 characters"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(field: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn sample_hash(label: &str) -> String {
    domain_hash(
        "private_l2_pq_lattice_checkpoint:devnet_sample",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}
