use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialStatePruningRebateMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-state-pruning-rebate-market-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_STATE_PRUNING_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const PRUNING_MARKET_SUITE: &str = "confidential-state-pruning-rebate-market-root-v1";
pub const REBATE_SUITE: &str = "state-pruning-low-fee-rebate-receipt-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-state-pruning-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_PRUNING_WINDOW_SLOTS: u64 = 2_048;
pub const DEFAULT_MAX_PRUNING_LAG_SLOTS: u64 = 320;
pub const DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MAX_PRUNING_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const DEFAULT_STALE_PROOF_QUARANTINE_SLOTS: u64 = 960;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_MARKETS: usize = 524_288;
pub const MAX_SPONSORS: usize = 524_288;
pub const MAX_TICKETS: usize = 2_097_152;
pub const MAX_PROOF_RECEIPTS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MIN_PRUNED_BYTES: u64 = 4_096;
pub const DEVNET_EPOCH: u64 = 7_424;
pub const DEVNET_SLOT: u64 = 113;
pub const DEVNET_L2_HEIGHT: u64 = 2_921_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PruningScope {
    AccountNullifierSet,
    ContractStorageShard,
    OutputWitnessCache,
    BridgeReceiptArchive,
    FeeQuoteHistory,
    MempoolSnapshotArchive,
    OracleSampleWindow,
    LiquidityProofCache,
}

impl PruningScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountNullifierSet => "account_nullifier_set",
            Self::ContractStorageShard => "contract_storage_shard",
            Self::OutputWitnessCache => "output_witness_cache",
            Self::BridgeReceiptArchive => "bridge_receipt_archive",
            Self::FeeQuoteHistory => "fee_quote_history",
            Self::MempoolSnapshotArchive => "mempool_snapshot_archive",
            Self::OracleSampleWindow => "oracle_sample_window",
            Self::LiquidityProofCache => "liquidity_proof_cache",
        }
    }

    pub fn fee_weight(self) -> u64 {
        match self {
            Self::ContractStorageShard => 6,
            Self::AccountNullifierSet => 5,
            Self::BridgeReceiptArchive => 5,
            Self::LiquidityProofCache => 4,
            Self::OutputWitnessCache => 3,
            Self::OracleSampleWindow => 3,
            Self::MempoolSnapshotArchive => 2,
            Self::FeeQuoteHistory => 1,
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pending,
    Active,
    Throttled,
    Exhausted,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Submitted,
    Sponsored,
    ProofPublished,
    Attested,
    Settled,
    RebateIssued,
    StaleProof,
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
    PqSignatureVerified,
    PrunedStateRootChecked,
    ArchiveAvailabilityChecked,
    PrivacyBoundaryObserved,
    SponsorBondEscrowed,
    RebateCapObserved,
    StaleProofQuarantined,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerified => "pq_signature_verified",
            Self::PrunedStateRootChecked => "pruned_state_root_checked",
            Self::ArchiveAvailabilityChecked => "archive_availability_checked",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::SponsorBondEscrowed => "sponsor_bond_escrowed",
            Self::RebateCapObserved => "rebate_cap_observed",
            Self::StaleProofQuarantined => "stale_proof_quarantined",
            Self::SettlementSafe => "settlement_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    Approve,
    ApproveWithRebate,
    PartialRebate,
    QuarantineProof,
    Reject,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveWithRebate => "approve_with_rebate",
            Self::PartialRebate => "partial_rebate",
            Self::QuarantineProof => "quarantine_proof",
            Self::Reject => "reject",
            Self::Expire => "expire",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub pruning_market_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub pruning_window_slots: u64,
    pub max_pruning_lag_slots: u64,
    pub min_sponsor_bond_micro_units: u64,
    pub max_pruning_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_public_redaction_bytes: u64,
    pub stale_proof_quarantine_slots: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            pruning_market_suite: PRUNING_MARKET_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pruning_window_slots: DEFAULT_PRUNING_WINDOW_SLOTS,
            max_pruning_lag_slots: DEFAULT_MAX_PRUNING_LAG_SLOTS,
            min_sponsor_bond_micro_units: DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS,
            max_pruning_fee_bps: DEFAULT_MAX_PRUNING_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            stale_proof_quarantine_slots: DEFAULT_STALE_PROOF_QUARANTINE_SLOTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_attestation_suite, "pq_attestation_suite")?;
        ensure_non_empty(&self.pruning_market_suite, "pruning_market_suite")?;
        ensure_non_empty(&self.rebate_suite, "rebate_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must be >= minimum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security bits below configured floor".to_string());
        }
        if self.pruning_window_slots == 0 {
            return Err("pruning_window_slots must be non-zero".to_string());
        }
        if self.max_pruning_lag_slots == 0 {
            return Err("max_pruning_lag_slots must be non-zero".to_string());
        }
        if self.min_sponsor_bond_micro_units == 0 {
            return Err("min_sponsor_bond_micro_units must be non-zero".to_string());
        }
        ensure_bps(self.max_pruning_fee_bps, "max_pruning_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err("strong attestation quorum below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub sponsors: u64,
    pub tickets: u64,
    pub proof_receipts: u64,
    pub attestations: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_tickets: u64,
    pub quarantined_tickets: u64,
    pub stale_proofs: u64,
    pub sponsored_micro_units: u64,
    pub rebated_micro_units: u64,
    pub pruned_bytes: u64,
    pub archived_nodes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "sponsors": self.sponsors,
            "tickets": self.tickets,
            "proof_receipts": self.proof_receipts,
            "attestations": self.attestations,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_tickets": self.settled_tickets,
            "quarantined_tickets": self.quarantined_tickets,
            "stale_proofs": self.stale_proofs,
            "sponsored_micro_units": self.sponsored_micro_units,
            "rebated_micro_units": self.rebated_micro_units,
            "pruned_bytes": self.pruned_bytes,
            "archived_nodes": self.archived_nodes,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub sponsor_root: String,
    pub ticket_root: String,
    pub proof_receipt_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "sponsor_root": self.sponsor_root,
            "ticket_root": self.ticket_root,
            "proof_receipt_root": self.proof_receipt_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PruningMarket {
    pub market_id: String,
    pub scope: PruningScope,
    pub sealed_market_root: String,
    pub public_hint_root: String,
    pub min_pruning_slot: u64,
    pub max_pruning_slot: u64,
    pub target_pruned_bytes: u64,
    pub fee_cap_bps: u64,
    pub sponsor_pool_root: String,
    pub status: MarketStatus,
    pub created_slot: u64,
    pub expires_slot: u64,
}

impl PruningMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "scope": self.scope.as_str(),
            "public_hint_root": self.public_hint_root,
            "min_pruning_slot": self.min_pruning_slot,
            "max_pruning_slot": self.max_pruning_slot,
            "target_pruned_bytes": self.target_pruned_bytes,
            "fee_cap_bps": self.fee_cap_bps,
            "sponsor_pool_root": self.sponsor_pool_root,
            "status": self.status,
            "created_slot": self.created_slot,
            "expires_slot": self.expires_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Sponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_micro_units: u64,
    pub available_micro_units: u64,
    pub fee_asset_id: String,
    pub privacy_set_size: u64,
    pub status: SponsorStatus,
    pub joined_slot: u64,
}

impl Sponsor {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "pq_verifying_key_root": self.pq_verifying_key_root,
            "bond_micro_units": self.bond_micro_units,
            "available_micro_units": self.available_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "joined_slot": self.joined_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PruningTicket {
    pub ticket_id: String,
    pub market_id: String,
    pub sponsor_id: String,
    pub scope: PruningScope,
    pub sealed_state_root: String,
    pub redacted_state_root: String,
    pub witness_commitment_root: String,
    pub requested_pruned_bytes: u64,
    pub reserved_fee_micro_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub status: TicketStatus,
}

impl PruningTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "market_id": self.market_id,
            "sponsor_id": self.sponsor_id,
            "scope": self.scope.as_str(),
            "redacted_state_root": self.redacted_state_root,
            "witness_commitment_root": self.witness_commitment_root,
            "requested_pruned_bytes": self.requested_pruned_bytes,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PruningProofReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub prover_commitment: String,
    pub proof_root: String,
    pub pruned_state_root: String,
    pub archived_node_root: String,
    pub pq_signature_root: String,
    pub pruned_bytes: u64,
    pub archived_nodes: u64,
    pub published_slot: u64,
    pub lag_slots: u64,
    pub status: ProofStatus,
}

impl PruningProofReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "proof_root": self.proof_root,
            "pruned_state_root": self.pruned_state_root,
            "archived_node_root": self.archived_node_root,
            "pq_signature_root": self.pq_signature_root,
            "pruned_bytes": self.pruned_bytes,
            "archived_nodes": self.archived_nodes,
            "published_slot": self.published_slot,
            "lag_slots": self.lag_slots,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Attestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub receipt_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub ticket_id: String,
    pub sponsor_id: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
    pub settlement_decision: SettlementDecision,
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
    pub tickets: u64,
    pub open_tickets: u64,
    pub settled_tickets: u64,
    pub quarantined_tickets: u64,
    pub stale_proofs: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub pruned_bytes: u64,
    pub rebated_micro_units: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenMarketRequest {
    pub scope: PruningScope,
    pub sealed_market_root: String,
    pub public_hint_root: String,
    pub min_pruning_slot: u64,
    pub max_pruning_slot: u64,
    pub target_pruned_bytes: u64,
    pub fee_cap_bps: u64,
    pub sponsor_pool_root: String,
    pub created_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSponsorRequest {
    pub sponsor_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_micro_units: u64,
    pub available_micro_units: u64,
    pub fee_asset_id: String,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPruningTicketRequest {
    pub market_id: String,
    pub sponsor_id: String,
    pub sealed_state_root: String,
    pub redacted_state_root: String,
    pub witness_commitment_root: String,
    pub requested_pruned_bytes: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishProofReceiptRequest {
    pub ticket_id: String,
    pub prover_commitment: String,
    pub proof_root: String,
    pub pruned_state_root: String,
    pub archived_node_root: String,
    pub pq_signature_root: String,
    pub pruned_bytes: u64,
    pub archived_nodes: u64,
    pub published_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub ticket_id: String,
    pub receipt_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleTicketRequest {
    pub ticket_id: String,
    pub receipt_id: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub ticket_id: String,
    pub sponsor_id: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
    pub settlement_decision: SettlementDecision,
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
    pub markets: BTreeMap<String, PruningMarket>,
    pub sponsors: BTreeMap<String, Sponsor>,
    pub tickets: BTreeMap<String, PruningTicket>,
    pub proof_receipts: BTreeMap<String, PruningProofReceipt>,
    pub attestations: BTreeMap<String, Attestation>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default state pruning rebate market config")
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
            sponsors: BTreeMap::new(),
            tickets: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn open_market(&mut self, request: OpenMarketRequest) -> Result<PruningMarket> {
        ensure_capacity(self.markets.len(), MAX_MARKETS, "markets")?;
        ensure_non_empty(&request.sealed_market_root, "sealed_market_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_bps(request.fee_cap_bps, "fee_cap_bps")?;
        if request.fee_cap_bps > self.config.max_pruning_fee_bps {
            return Err("market fee cap exceeds configured maximum".to_string());
        }
        if request.target_pruned_bytes < MIN_PRUNED_BYTES {
            return Err("market target_pruned_bytes below minimum".to_string());
        }
        if request.max_pruning_slot <= request.min_pruning_slot {
            return Err("max_pruning_slot must be greater than min_pruning_slot".to_string());
        }
        let market_id = stable_id(
            "market",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.sealed_market_root),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.created_slot),
            ],
        );
        let expires_slot = request.created_slot + self.config.pruning_window_slots;
        let market = PruningMarket {
            market_id: market_id.clone(),
            scope: request.scope,
            sealed_market_root: request.sealed_market_root,
            public_hint_root: request.public_hint_root,
            min_pruning_slot: request.min_pruning_slot,
            max_pruning_slot: request.max_pruning_slot,
            target_pruned_bytes: request.target_pruned_bytes,
            fee_cap_bps: request.fee_cap_bps,
            sponsor_pool_root: request.sponsor_pool_root,
            status: MarketStatus::Open,
            created_slot: request.created_slot,
            expires_slot,
        };
        self.markets.insert(market_id, market.clone());
        self.refresh_roots();
        Ok(market)
    }

    pub fn register_sponsor(&mut self, request: RegisterSponsorRequest) -> Result<Sponsor> {
        ensure_capacity(self.sponsors.len(), MAX_SPONSORS, "sponsors")?;
        ensure_non_empty(&request.sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(&request.fee_asset_id, "fee_asset_id")?;
        if request.bond_micro_units < self.config.min_sponsor_bond_micro_units {
            return Err("sponsor bond below configured minimum".to_string());
        }
        if request.available_micro_units == 0 {
            return Err("sponsor liquidity must be non-zero".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsor privacy set below configured minimum".to_string());
        }
        let sponsor_id = stable_id(
            "sponsor",
            &[
                HashPart::Str(&request.sponsor_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.bond_micro_units),
            ],
        );
        let sponsor = Sponsor {
            sponsor_id: sponsor_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            bond_micro_units: request.bond_micro_units,
            available_micro_units: request.available_micro_units,
            fee_asset_id: request.fee_asset_id,
            privacy_set_size: request.privacy_set_size,
            status: SponsorStatus::Active,
            joined_slot: request.joined_slot,
        };
        self.sponsors.insert(sponsor_id, sponsor.clone());
        self.refresh_roots();
        Ok(sponsor)
    }

    pub fn submit_pruning_ticket(
        &mut self,
        request: SubmitPruningTicketRequest,
    ) -> Result<PruningTicket> {
        ensure_capacity(self.tickets.len(), MAX_TICKETS, "tickets")?;
        ensure_non_empty(&request.sealed_state_root, "sealed_state_root")?;
        ensure_non_empty(&request.redacted_state_root, "redacted_state_root")?;
        ensure_non_empty(&request.witness_commitment_root, "witness_commitment_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("ticket rebate exceeds configured target".to_string());
        }
        if request.requested_pruned_bytes < MIN_PRUNED_BYTES {
            return Err("requested_pruned_bytes below minimum".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "market not found".to_string())?
            .clone();
        if market.status != MarketStatus::Open {
            return Err("market is not open".to_string());
        }
        if request.submitted_slot < market.min_pruning_slot
            || request.submitted_slot > market.max_pruning_slot
        {
            return Err("ticket submitted outside market pruning slot range".to_string());
        }
        if request.max_fee_bps > market.fee_cap_bps
            || request.max_fee_bps > self.config.max_pruning_fee_bps
        {
            return Err("ticket fee exceeds market or config cap".to_string());
        }
        let reserved_fee_micro_units = estimate_pruning_fee_micro_units(
            market.scope,
            request.requested_pruned_bytes,
            request.max_fee_bps,
        );
        let sponsor = self
            .sponsors
            .get_mut(&request.sponsor_id)
            .ok_or_else(|| "sponsor not found".to_string())?;
        if sponsor.status != SponsorStatus::Active {
            return Err("sponsor is not active".to_string());
        }
        if sponsor.available_micro_units < reserved_fee_micro_units {
            sponsor.status = SponsorStatus::Exhausted;
            return Err("sponsor liquidity below ticket reserve".to_string());
        }
        sponsor.available_micro_units -= reserved_fee_micro_units;
        let ticket_id = stable_id(
            "ticket",
            &[
                HashPart::Str(&request.market_id),
                HashPart::Str(&request.sponsor_id),
                HashPart::Str(&request.redacted_state_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let ticket = PruningTicket {
            ticket_id: ticket_id.clone(),
            market_id: request.market_id,
            sponsor_id: request.sponsor_id,
            scope: market.scope,
            sealed_state_root: request.sealed_state_root,
            redacted_state_root: request.redacted_state_root,
            witness_commitment_root: request.witness_commitment_root,
            requested_pruned_bytes: request.requested_pruned_bytes,
            reserved_fee_micro_units,
            max_fee_bps: request.max_fee_bps,
            rebate_bps: request.rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.pruning_window_slots,
            status: TicketStatus::Sponsored,
        };
        self.counters.sponsored_micro_units = self
            .counters
            .sponsored_micro_units
            .saturating_add(reserved_fee_micro_units);
        self.tickets.insert(ticket_id, ticket.clone());
        self.refresh_roots();
        Ok(ticket)
    }

    pub fn publish_proof_receipt(
        &mut self,
        request: PublishProofReceiptRequest,
    ) -> Result<PruningProofReceipt> {
        ensure_capacity(
            self.proof_receipts.len(),
            MAX_PROOF_RECEIPTS,
            "proof_receipts",
        )?;
        ensure_non_empty(&request.prover_commitment, "prover_commitment")?;
        ensure_non_empty(&request.proof_root, "proof_root")?;
        ensure_non_empty(&request.pruned_state_root, "pruned_state_root")?;
        ensure_non_empty(&request.archived_node_root, "archived_node_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        if request.pruned_bytes < MIN_PRUNED_BYTES {
            return Err("pruned_bytes below minimum".to_string());
        }
        let ticket = self
            .tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?
            .clone();
        if request.published_slot < ticket.submitted_slot {
            return Err("proof published before ticket submission".to_string());
        }
        let lag_slots = request.published_slot.saturating_sub(ticket.submitted_slot);
        let status = if lag_slots > self.config.max_pruning_lag_slots {
            self.counters.stale_proofs = self.counters.stale_proofs.saturating_add(1);
            ProofStatus::Stale
        } else {
            ProofStatus::Submitted
        };
        let receipt_id = stable_id(
            "proof-receipt",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.proof_root),
                HashPart::U64(request.published_slot),
            ],
        );
        let receipt = PruningProofReceipt {
            receipt_id: receipt_id.clone(),
            ticket_id: request.ticket_id.clone(),
            prover_commitment: request.prover_commitment,
            proof_root: request.proof_root,
            pruned_state_root: request.pruned_state_root,
            archived_node_root: request.archived_node_root,
            pq_signature_root: request.pq_signature_root,
            pruned_bytes: request.pruned_bytes,
            archived_nodes: request.archived_nodes,
            published_slot: request.published_slot,
            lag_slots,
            status,
        };
        self.proof_receipts.insert(receipt_id, receipt.clone());
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.status = if status == ProofStatus::Stale {
                TicketStatus::StaleProof
            } else {
                TicketStatus::ProofPublished
            };
        }
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn record_attestation(&mut self, request: RecordAttestationRequest) -> Result<Attestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        self.ensure_ticket_exists(&request.ticket_id)?;
        let receipt = self
            .proof_receipts
            .get_mut(&request.receipt_id)
            .ok_or_else(|| "proof receipt not found".to_string())?;
        if receipt.ticket_id != request.ticket_id {
            return Err("receipt does not match ticket".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.receipt_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = Attestation {
            attestation_id: attestation_id.clone(),
            ticket_id: request.ticket_id.clone(),
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
        match request.kind {
            AttestationKind::StaleProofQuarantined => {
                receipt.status = ProofStatus::Quarantined;
                if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
                    ticket.status = TicketStatus::Quarantined;
                }
                self.counters.quarantined_tickets =
                    self.counters.quarantined_tickets.saturating_add(1);
            }
            _ => {
                receipt.status = ProofStatus::Attested;
                if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
                    ticket.status = TicketStatus::Attested;
                }
            }
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_ticket(&mut self, request: SettleTicketRequest) -> Result<PruningTicket> {
        self.ensure_ticket_exists(&request.ticket_id)?;
        let receipt = self
            .proof_receipts
            .get_mut(&request.receipt_id)
            .ok_or_else(|| "proof receipt not found".to_string())?;
        if receipt.ticket_id != request.ticket_id {
            return Err("receipt does not match ticket".to_string());
        }
        if request.settled_slot < receipt.published_slot {
            return Err("settlement slot precedes receipt publication".to_string());
        }
        let ticket = self
            .tickets
            .get_mut(&request.ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?;
        match request.decision {
            SettlementDecision::Approve
            | SettlementDecision::ApproveWithRebate
            | SettlementDecision::PartialRebate => {
                if receipt.status != ProofStatus::Attested
                    && receipt.status != ProofStatus::Accepted
                    && receipt.status != ProofStatus::Submitted
                {
                    return Err("proof receipt is not eligible for settlement".to_string());
                }
                receipt.status = ProofStatus::Settled;
                ticket.status = TicketStatus::Settled;
                self.counters.settled_tickets = self.counters.settled_tickets.saturating_add(1);
                self.counters.pruned_bytes = self
                    .counters
                    .pruned_bytes
                    .saturating_add(receipt.pruned_bytes);
                self.counters.archived_nodes = self
                    .counters
                    .archived_nodes
                    .saturating_add(receipt.archived_nodes);
            }
            SettlementDecision::QuarantineProof => {
                receipt.status = ProofStatus::Quarantined;
                ticket.status = TicketStatus::Quarantined;
                self.counters.quarantined_tickets =
                    self.counters.quarantined_tickets.saturating_add(1);
            }
            SettlementDecision::Reject => {
                receipt.status = ProofStatus::Quarantined;
                ticket.status = TicketStatus::Quarantined;
                self.counters.quarantined_tickets =
                    self.counters.quarantined_tickets.saturating_add(1);
            }
            SettlementDecision::Expire => {
                ticket.status = TicketStatus::Expired;
            }
        }
        let settled_ticket = ticket.clone();
        self.refresh_roots();
        Ok(settled_ticket)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate bps exceeds configured target".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        self.ensure_sponsor_exists(&request.sponsor_id)?;
        let ticket = self
            .tickets
            .get_mut(&request.ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?;
        if ticket.sponsor_id != request.sponsor_id {
            return Err("ticket sponsor does not match rebate sponsor".to_string());
        }
        if ticket.status != TicketStatus::Settled {
            return Err("rebate requires a settled ticket".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.beneficiary_group_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let receipt = RebateReceipt {
            rebate_id: rebate_id.clone(),
            ticket_id: request.ticket_id.clone(),
            sponsor_id: request.sponsor_id,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
            settlement_decision: request.settlement_decision,
        };
        self.rebates.insert(rebate_id, receipt.clone());
        self.counters.rebated_micro_units = self
            .counters
            .rebated_micro_units
            .saturating_add(request.amount_micro_units);
        ticket.status = TicketStatus::RebateIssued;
        self.refresh_roots();
        Ok(receipt)
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
        let open_tickets = self
            .tickets
            .values()
            .filter(|ticket| {
                matches!(
                    ticket.status,
                    TicketStatus::Submitted
                        | TicketStatus::Sponsored
                        | TicketStatus::ProofPublished
                        | TicketStatus::Attested
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
            tickets: self.tickets.len() as u64,
            open_tickets,
            settled_tickets: self.counters.settled_tickets,
            quarantined_tickets: self.counters.quarantined_tickets,
            stale_proofs: self.counters.stale_proofs,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            pruned_bytes: self.counters.pruned_bytes,
            rebated_micro_units: self.counters.rebated_micro_units,
            state_root: self.state_root(),
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.markets = self.markets.len() as u64;
        self.counters.sponsors = self.sponsors.len() as u64;
        self.counters.tickets = self.tickets.len() as u64;
        self.counters.proof_receipts = self.proof_receipts.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots.market_root = map_root("state-pruning-rebate-market:markets", &self.markets);
        self.roots.sponsor_root = map_root("state-pruning-rebate-market:sponsors", &self.sponsors);
        self.roots.ticket_root = map_root("state-pruning-rebate-market:tickets", &self.tickets);
        self.roots.proof_receipt_root = map_root(
            "state-pruning-rebate-market:proof-receipts",
            &self.proof_receipts,
        );
        self.roots.attestation_root = map_root(
            "state-pruning-rebate-market:attestations",
            &self.attestations,
        );
        self.roots.rebate_root = map_root("state-pruning-rebate-market:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "state-pruning-rebate-market:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "state-pruning-rebate-market:operator-summaries",
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
            "pq_attestation_suite": self.config.pq_attestation_suite,
            "pruning_market_suite": self.config.pruning_market_suite,
            "rebate_suite": self.config.rebate_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "markets": self.markets,
            "sponsors": self.sponsors,
            "tickets": self.tickets,
            "proof_receipts": self.proof_receipts,
            "attestations": self.attestations,
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
            "sponsor_root": self.roots.sponsor_root,
            "ticket_root": self.roots.ticket_root,
            "proof_receipt_root": self.roots.proof_receipt_root,
            "attestation_root": self.roots.attestation_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "state-pruning-rebate-market:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn ensure_ticket_exists(&self, ticket_id: &str) -> Result<()> {
        ensure_non_empty(ticket_id, "ticket_id")?;
        if !self.tickets.contains_key(ticket_id) {
            return Err(format!("ticket not found: {ticket_id}"));
        }
        Ok(())
    }

    fn ensure_sponsor_exists(&self, sponsor_id: &str) -> Result<()> {
        ensure_non_empty(sponsor_id, "sponsor_id")?;
        if !self.sponsors.contains_key(sponsor_id) {
            return Err(format!("sponsor not found: {sponsor_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let market = state
        .open_market(OpenMarketRequest {
            scope: PruningScope::ContractStorageShard,
            sealed_market_root: sample_hash("sealed-market", 1),
            public_hint_root: sample_hash("public-hint", 1),
            min_pruning_slot: DEVNET_SLOT,
            max_pruning_slot: DEVNET_SLOT + 512,
            target_pruned_bytes: 64 * 1024 * 1024,
            fee_cap_bps: 12,
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            created_slot: DEVNET_SLOT,
        })
        .expect("devnet pruning market opened");
    let sponsor = state
        .register_sponsor(RegisterSponsorRequest {
            sponsor_commitment: sample_hash("sponsor", 1),
            pq_verifying_key_root: sample_hash("sponsor-pq-key", 1),
            bond_micro_units: DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS * 3,
            available_micro_units: 18_000_000,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT,
        })
        .expect("devnet sponsor registered");
    let ticket = state
        .submit_pruning_ticket(SubmitPruningTicketRequest {
            market_id: market.market_id.clone(),
            sponsor_id: sponsor.sponsor_id.clone(),
            sealed_state_root: sample_hash("sealed-state", 1),
            redacted_state_root: sample_hash("redacted-state", 1),
            witness_commitment_root: sample_hash("witness", 1),
            requested_pruned_bytes: 12 * 1024 * 1024,
            max_fee_bps: 10,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet pruning ticket submitted");
    let receipt = state
        .publish_proof_receipt(PublishProofReceiptRequest {
            ticket_id: ticket.ticket_id.clone(),
            prover_commitment: sample_hash("prover", 1),
            proof_root: sample_hash("proof", 1),
            pruned_state_root: sample_hash("pruned-state", 1),
            archived_node_root: sample_hash("archive", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            pruned_bytes: 12 * 1024 * 1024,
            archived_nodes: 8_192,
            published_slot: DEVNET_SLOT + 12,
        })
        .expect("devnet proof receipt published");
    state
        .record_attestation(RecordAttestationRequest {
            ticket_id: ticket.ticket_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            kind: AttestationKind::PrunedStateRootChecked,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("committee-signature", 1),
            observed_slot: DEVNET_SLOT + 13,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet attestation recorded");
    state
        .settle_ticket(SettleTicketRequest {
            ticket_id: ticket.ticket_id.clone(),
            receipt_id: receipt.receipt_id,
            decision: SettlementDecision::ApproveWithRebate,
            settled_slot: DEVNET_SLOT + 16,
        })
        .expect("devnet ticket settled");
    state
        .issue_rebate(IssueRebateRequest {
            ticket_id: ticket.ticket_id.clone(),
            sponsor_id: sponsor.sponsor_id,
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 1_200,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 17,
            expires_slot: DEVNET_SLOT + 512,
            settlement_decision: SettlementDecision::ApproveWithRebate,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: ticket.ticket_id,
            public_fields: [
                "ticket_id",
                "scope",
                "redacted_state_root",
                "pruned_bytes",
                "rebate_bps",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "sealed_state_root",
                "sponsor_commitment",
                "prover_commitment",
                "witness_commitment_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 864,
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
            scope: PruningScope::OutputWitnessCache,
            sealed_market_root: sample_hash("sealed-market", 2),
            public_hint_root: sample_hash("public-hint", 2),
            min_pruning_slot: DEVNET_SLOT + 32,
            max_pruning_slot: DEVNET_SLOT + 640,
            target_pruned_bytes: 32 * 1024 * 1024,
            fee_cap_bps: 8,
            sponsor_pool_root: sample_hash("sponsor-pool", 2),
            created_slot: DEVNET_SLOT + 32,
        })
        .expect("demo pruning market opened");
    let sponsor = state
        .register_sponsor(RegisterSponsorRequest {
            sponsor_commitment: sample_hash("sponsor", 2),
            pq_verifying_key_root: sample_hash("sponsor-pq-key", 2),
            bond_micro_units: DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS * 2,
            available_micro_units: 9_000_000,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 33,
        })
        .expect("demo sponsor registered");
    state
        .submit_pruning_ticket(SubmitPruningTicketRequest {
            market_id: market.market_id,
            sponsor_id: sponsor.sponsor_id,
            sealed_state_root: sample_hash("sealed-state", 2),
            redacted_state_root: sample_hash("redacted-state", 2),
            witness_commitment_root: sample_hash("witness", 2),
            requested_pruned_bytes: 8 * 1024 * 1024,
            max_fee_bps: 7,
            rebate_bps: 6,
            submitted_slot: DEVNET_SLOT + 40,
        })
        .expect("demo pruning ticket submitted");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!(state.public_record())
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn estimate_pruning_fee_micro_units(scope: PruningScope, pruned_bytes: u64, fee_bps: u64) -> u64 {
    let kib = pruned_bytes.div_ceil(1024).max(1);
    let weighted = kib
        .saturating_mul(scope.fee_weight())
        .saturating_mul(fee_bps.max(1));
    weighted.div_ceil(16).max(1)
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("state-pruning-rebate-market:{domain}:id"),
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
        "state-pruning-rebate-market:devnet-sample",
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
