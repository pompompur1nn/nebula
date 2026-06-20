use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialEmergencyExitBondedRelayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-emergency-exit-bonded-relay-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_EMERGENCY_EXIT_BONDED_RELAY_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RELAY_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const EXIT_NOTE_SUITE: &str = "ringct-confidential-emergency-exit-note-root-v1";
pub const BONDED_RELAY_SUITE: &str = "pq-confidential-bonded-exit-relay-market-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-emergency-exit-redaction-budget-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_EXIT_ASSET_ID: &str = "wxmr-emergency-exit-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_EXIT_WINDOW_SLOTS: u64 = 144;
pub const DEFAULT_RELAY_QUARANTINE_SLOTS: u64 = 720;
pub const DEFAULT_MAX_EXIT_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_MIN_RELAY_BOND_MICRO_UNITS: u64 = 40_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_EXIT_RISK_BPS: u64 = 2_600;
pub const DEFAULT_SLASHING_PENALTY_BPS: u64 = 3_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_EXIT_MARKETS: usize = 262_144;
pub const MAX_RELAYS: usize = 524_288;
pub const MAX_EXIT_TICKETS: usize = 2_097_152;
pub const MAX_EXIT_QUOTES: usize = 2_097_152;
pub const MAX_EXIT_BATCHES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_TICKETS_PER_BATCH: usize = 1024;
pub const DEVNET_EPOCH: u64 = 7_360;
pub const DEVNET_SLOT: u64 = 89;
pub const DEVNET_L2_HEIGHT: u64 = 2_884_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitKind {
    StandardExit,
    EmergencyLiquidityExit,
    SequencerCensorshipExit,
    BridgePauseExit,
    WatchtowerTriggeredExit,
    ContractEscapeExit,
    GuardianRecoveryExit,
    DustSweepExit,
}

impl ExitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardExit => "standard_exit",
            Self::EmergencyLiquidityExit => "emergency_liquidity_exit",
            Self::SequencerCensorshipExit => "sequencer_censorship_exit",
            Self::BridgePauseExit => "bridge_pause_exit",
            Self::WatchtowerTriggeredExit => "watchtower_triggered_exit",
            Self::ContractEscapeExit => "contract_escape_exit",
            Self::GuardianRecoveryExit => "guardian_recovery_exit",
            Self::DustSweepExit => "dust_sweep_exit",
        }
    }

    pub fn base_priority_bps(self) -> u64 {
        match self {
            Self::BridgePauseExit => 10_000,
            Self::SequencerCensorshipExit => 9_800,
            Self::EmergencyLiquidityExit => 9_500,
            Self::WatchtowerTriggeredExit => 9_200,
            Self::ContractEscapeExit => 8_800,
            Self::GuardianRecoveryExit => 8_200,
            Self::StandardExit => 7_200,
            Self::DustSweepExit => 6_300,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Open,
    Congested,
    Paused,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStatus {
    Candidate,
    Active,
    Throttled,
    Quarantined,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitTicketStatus {
    Sealed,
    Quoted,
    Batched,
    Attested,
    Settled,
    Rebated,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Locked,
    Attested,
    Settled,
    Delayed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureVerified,
    ExitNoteLocked,
    NullifierSetChecked,
    RelayBondEscrowed,
    FeeCapObserved,
    PrivacyFloorSatisfied,
    WatchtowerEvidenceAccepted,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerified => "pq_signature_verified",
            Self::ExitNoteLocked => "exit_note_locked",
            Self::NullifierSetChecked => "nullifier_set_checked",
            Self::RelayBondEscrowed => "relay_bond_escrowed",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyFloorSatisfied => "privacy_floor_satisfied",
            Self::WatchtowerEvidenceAccepted => "watchtower_evidence_accepted",
            Self::SettlementSafe => "settlement_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    ReleaseExit,
    ReleaseWithDelay,
    RequireMoreAttestations,
    QuarantineRelay,
    SlashRelay,
    RejectExit,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseExit => "release_exit",
            Self::ReleaseWithDelay => "release_with_delay",
            Self::RequireMoreAttestations => "require_more_attestations",
            Self::QuarantineRelay => "quarantine_relay",
            Self::SlashRelay => "slash_relay",
            Self::RejectExit => "reject_exit",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_relay_suite: String,
    pub exit_note_suite: String,
    pub bonded_relay_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub exit_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub exit_window_slots: u64,
    pub relay_quarantine_slots: u64,
    pub max_exit_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_relay_bond_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_exit_risk_bps: u64,
    pub slashing_penalty_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_relay_suite: PQ_RELAY_SUITE.to_string(),
            exit_note_suite: EXIT_NOTE_SUITE.to_string(),
            bonded_relay_suite: BONDED_RELAY_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            exit_asset_id: DEFAULT_EXIT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            exit_window_slots: DEFAULT_EXIT_WINDOW_SLOTS,
            relay_quarantine_slots: DEFAULT_RELAY_QUARANTINE_SLOTS,
            max_exit_fee_bps: DEFAULT_MAX_EXIT_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_relay_bond_micro_units: DEFAULT_MIN_RELAY_BOND_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_exit_risk_bps: DEFAULT_MAX_EXIT_RISK_BPS,
            slashing_penalty_bps: DEFAULT_SLASHING_PENALTY_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_relay_suite, "pq_relay_suite")?;
        ensure_non_empty(&self.exit_note_suite, "exit_note_suite")?;
        ensure_non_empty(&self.bonded_relay_suite, "bonded_relay_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.exit_asset_id, "exit_asset_id")?;
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target_privacy_set_size must be >= min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below configured target".to_string());
        }
        if self.exit_window_slots == 0 {
            return Err("exit_window_slots must be non-zero".to_string());
        }
        if self.relay_quarantine_slots < self.exit_window_slots {
            return Err("relay_quarantine_slots must cover at least one exit window".to_string());
        }
        if self.min_relay_bond_micro_units == 0 {
            return Err("min_relay_bond_micro_units must be non-zero".to_string());
        }
        ensure_bps(self.max_exit_fee_bps, "max_exit_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.max_exit_risk_bps, "max_exit_risk_bps")?;
        ensure_bps(self.slashing_penalty_bps, "slashing_penalty_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err(
                "strong_attestation_quorum_bps must be >= min_attestation_quorum_bps".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub relays: u64,
    pub exit_tickets: u64,
    pub exit_quotes: u64,
    pub exit_batches: u64,
    pub attestations: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_tickets: u64,
    pub delayed_tickets: u64,
    pub rejected_tickets: u64,
    pub quarantined_relays: u64,
    pub slashed_relays: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "relays": self.relays,
            "exit_tickets": self.exit_tickets,
            "exit_quotes": self.exit_quotes,
            "exit_batches": self.exit_batches,
            "attestations": self.attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_tickets": self.settled_tickets,
            "delayed_tickets": self.delayed_tickets,
            "rejected_tickets": self.rejected_tickets,
            "quarantined_relays": self.quarantined_relays,
            "slashed_relays": self.slashed_relays,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub relay_root: String,
    pub exit_ticket_root: String,
    pub exit_quote_root: String,
    pub exit_batch_root: String,
    pub attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash("emergency-exit-bonded-relay:empty-root", &[], 32);
        Self {
            market_root: empty.clone(),
            relay_root: empty.clone(),
            exit_ticket_root: empty.clone(),
            exit_quote_root: empty.clone(),
            exit_batch_root: empty.clone(),
            attestation_root: empty.clone(),
            settlement_root: empty.clone(),
            rebate_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            operator_summary_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "relay_root": self.relay_root,
            "exit_ticket_root": self.exit_ticket_root,
            "exit_quote_root": self.exit_quote_root,
            "exit_batch_root": self.exit_batch_root,
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
pub struct ExitMarket {
    pub market_id: String,
    pub monero_network: String,
    pub l2_rollup_root: String,
    pub bridge_reserve_root: String,
    pub supported_exit_kinds: BTreeSet<ExitKind>,
    pub min_relay_bond_micro_units: u64,
    pub max_exit_fee_bps: u64,
    pub exit_window_slots: u64,
    pub privacy_set_size: u64,
    pub status: MarketStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BondedRelay {
    pub relay_id: String,
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_micro_units: u64,
    pub supported_exit_kinds: BTreeSet<ExitKind>,
    pub status: RelayStatus,
    pub successful_exits: u64,
    pub failed_exits: u64,
    pub quarantine_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitTicket {
    pub ticket_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub exit_kind: ExitKind,
    pub sealed_exit_note_root: String,
    pub nullifier_root: String,
    pub monero_destination_commitment: String,
    pub amount_commitment: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub risk_bps: u64,
    pub status: ExitTicketStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitQuote {
    pub quote_id: String,
    pub ticket_id: String,
    pub relay_id: String,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
    pub relay_bond_micro_units: u64,
    pub sponsor_pool_root: String,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitBatch {
    pub batch_id: String,
    pub market_id: String,
    pub relay_id: String,
    pub ticket_ids: Vec<String>,
    pub aggregate_exit_note_root: String,
    pub aggregate_nullifier_root: String,
    pub reserve_release_root: String,
    pub total_fee_micro_units: u64,
    pub opened_slot: u64,
    pub status: BatchStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayAttestation {
    pub attestation_id: String,
    pub ticket_id: Option<String>,
    pub batch_id: Option<String>,
    pub relay_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitSettlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub quote_id: String,
    pub decision: SettlementDecision,
    pub settlement_root: String,
    pub released_micro_units: u64,
    pub slashed_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub ticket_id: String,
    pub quote_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
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
    pub market_id: String,
    pub settled_tickets: u64,
    pub delayed_tickets: u64,
    pub rejected_tickets: u64,
    pub slashed_relays: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenMarketRequest {
    pub monero_network: String,
    pub l2_rollup_root: String,
    pub bridge_reserve_root: String,
    pub supported_exit_kinds: BTreeSet<ExitKind>,
    pub min_relay_bond_micro_units: u64,
    pub max_exit_fee_bps: u64,
    pub exit_window_slots: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterRelayRequest {
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_micro_units: u64,
    pub supported_exit_kinds: BTreeSet<ExitKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitExitTicketRequest {
    pub market_id: String,
    pub owner_commitment: String,
    pub exit_kind: ExitKind,
    pub sealed_exit_note_root: String,
    pub nullifier_root: String,
    pub monero_destination_commitment: String,
    pub amount_commitment: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
    pub risk_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteExitRequest {
    pub ticket_id: String,
    pub relay_id: String,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
    pub relay_bond_micro_units: u64,
    pub sponsor_pool_root: String,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildExitBatchRequest {
    pub market_id: String,
    pub relay_id: String,
    pub ticket_ids: Vec<String>,
    pub aggregate_exit_note_root: String,
    pub aggregate_nullifier_root: String,
    pub reserve_release_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub ticket_id: Option<String>,
    pub batch_id: Option<String>,
    pub relay_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub quote_id: String,
    pub decision: SettlementDecision,
    pub settlement_root: String,
    pub released_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub ticket_id: String,
    pub quote_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
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
    pub market_id: String,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub markets: BTreeMap<String, ExitMarket>,
    pub relays: BTreeMap<String, BondedRelay>,
    pub exit_tickets: BTreeMap<String, ExitTicket>,
    pub exit_quotes: BTreeMap<String, ExitQuote>,
    pub exit_batches: BTreeMap<String, ExitBatch>,
    pub attestations: BTreeMap<String, RelayAttestation>,
    pub settlements: BTreeMap<String, ExitSettlement>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default emergency exit bonded relay config")
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
            relays: BTreeMap::new(),
            exit_tickets: BTreeMap::new(),
            exit_quotes: BTreeMap::new(),
            exit_batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn open_market(&mut self, request: OpenMarketRequest) -> Result<ExitMarket> {
        ensure_capacity(self.markets.len(), MAX_EXIT_MARKETS, "markets")?;
        ensure_non_empty(&request.monero_network, "monero_network")?;
        ensure_non_empty(&request.l2_rollup_root, "l2_rollup_root")?;
        ensure_non_empty(&request.bridge_reserve_root, "bridge_reserve_root")?;
        if request.supported_exit_kinds.is_empty() {
            return Err("market requires at least one exit kind".to_string());
        }
        if request.min_relay_bond_micro_units < self.config.min_relay_bond_micro_units {
            return Err("market relay bond below configured minimum".to_string());
        }
        ensure_bps(request.max_exit_fee_bps, "max_exit_fee_bps")?;
        if request.max_exit_fee_bps > self.config.max_exit_fee_bps {
            return Err("market fee cap exceeds configured cap".to_string());
        }
        if request.exit_window_slots == 0 {
            return Err("exit window must be non-zero".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("market privacy set below configured minimum".to_string());
        }
        let market_id = stable_id(
            "market",
            &[
                HashPart::Str(&request.monero_network),
                HashPart::Str(&request.l2_rollup_root),
                HashPart::Str(&request.bridge_reserve_root),
            ],
        );
        let market = ExitMarket {
            market_id: market_id.clone(),
            monero_network: request.monero_network,
            l2_rollup_root: request.l2_rollup_root,
            bridge_reserve_root: request.bridge_reserve_root,
            supported_exit_kinds: request.supported_exit_kinds,
            min_relay_bond_micro_units: request.min_relay_bond_micro_units,
            max_exit_fee_bps: request.max_exit_fee_bps,
            exit_window_slots: request.exit_window_slots,
            privacy_set_size: request.privacy_set_size,
            status: MarketStatus::Open,
        };
        self.markets.insert(market_id, market.clone());
        self.refresh_roots();
        Ok(market)
    }

    pub fn register_relay(&mut self, request: RegisterRelayRequest) -> Result<BondedRelay> {
        ensure_capacity(self.relays.len(), MAX_RELAYS, "relays")?;
        ensure_non_empty(&request.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        if request.stake_bond_micro_units < self.config.min_relay_bond_micro_units {
            return Err("relay stake below configured minimum".to_string());
        }
        if request.supported_exit_kinds.is_empty() {
            return Err("relay requires at least one supported exit kind".to_string());
        }
        let relay_id = stable_id(
            "relay",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.stake_bond_micro_units),
            ],
        );
        let relay = BondedRelay {
            relay_id: relay_id.clone(),
            operator_commitment: request.operator_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            stake_bond_micro_units: request.stake_bond_micro_units,
            supported_exit_kinds: request.supported_exit_kinds,
            status: RelayStatus::Active,
            successful_exits: 0,
            failed_exits: 0,
            quarantine_until_slot: 0,
        };
        self.relays.insert(relay_id, relay.clone());
        self.refresh_roots();
        Ok(relay)
    }

    pub fn submit_exit_ticket(&mut self, request: SubmitExitTicketRequest) -> Result<ExitTicket> {
        ensure_capacity(self.exit_tickets.len(), MAX_EXIT_TICKETS, "exit_tickets")?;
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "market not found".to_string())?;
        if market.status != MarketStatus::Open && market.status != MarketStatus::Congested {
            return Err("market is not accepting exits".to_string());
        }
        if !market.supported_exit_kinds.contains(&request.exit_kind) {
            return Err("market does not support exit kind".to_string());
        }
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.sealed_exit_note_root, "sealed_exit_note_root")?;
        ensure_non_empty(&request.nullifier_root, "nullifier_root")?;
        ensure_non_empty(
            &request.monero_destination_commitment,
            "monero_destination_commitment",
        )?;
        ensure_non_empty(&request.amount_commitment, "amount_commitment")?;
        if request.max_fee_micro_units == 0 {
            return Err("max_fee_micro_units must be non-zero".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("exit ticket privacy set below configured minimum".to_string());
        }
        ensure_bps(request.risk_bps, "risk_bps")?;
        let risk_bps = request
            .risk_bps
            .max(MAX_BPS.saturating_sub(request.exit_kind.base_priority_bps()));
        if risk_bps > self.config.max_exit_risk_bps {
            return Err("exit ticket risk exceeds configured bound".to_string());
        }
        let ticket_id = stable_id(
            "ticket",
            &[
                HashPart::Str(&request.market_id),
                HashPart::Str(request.exit_kind.as_str()),
                HashPart::Str(&request.nullifier_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let ticket = ExitTicket {
            ticket_id: ticket_id.clone(),
            market_id: request.market_id,
            owner_commitment: request.owner_commitment,
            exit_kind: request.exit_kind,
            sealed_exit_note_root: request.sealed_exit_note_root,
            nullifier_root: request.nullifier_root,
            monero_destination_commitment: request.monero_destination_commitment,
            amount_commitment: request.amount_commitment,
            max_fee_micro_units: request.max_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + market.exit_window_slots,
            risk_bps,
            status: ExitTicketStatus::Sealed,
        };
        self.exit_tickets.insert(ticket_id, ticket.clone());
        self.refresh_roots();
        Ok(ticket)
    }

    pub fn quote_exit(&mut self, request: QuoteExitRequest) -> Result<ExitQuote> {
        ensure_capacity(self.exit_quotes.len(), MAX_EXIT_QUOTES, "exit_quotes")?;
        let ticket = self
            .exit_tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "exit ticket not found".to_string())?;
        let market = self
            .markets
            .get(&ticket.market_id)
            .ok_or_else(|| "market not found".to_string())?;
        let relay = self
            .relays
            .get(&request.relay_id)
            .ok_or_else(|| "relay not found".to_string())?;
        if relay.status != RelayStatus::Active {
            return Err("relay is not active".to_string());
        }
        if !relay.supported_exit_kinds.contains(&ticket.exit_kind) {
            return Err("relay does not support ticket exit kind".to_string());
        }
        ensure_non_empty(&request.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        if request.fee_micro_units == 0 {
            return Err("fee_micro_units must be non-zero".to_string());
        }
        if request.fee_micro_units > ticket.max_fee_micro_units {
            return Err("fee exceeds ticket cap".to_string());
        }
        ensure_bps(request.fee_bps, "fee_bps")?;
        if request.fee_bps > market.max_exit_fee_bps {
            return Err("fee bps exceeds market cap".to_string());
        }
        if request.relay_bond_micro_units < market.min_relay_bond_micro_units {
            return Err("relay bond below market minimum".to_string());
        }
        if request.valid_until_slot <= ticket.submitted_slot {
            return Err("quote validity must extend beyond ticket submission".to_string());
        }
        let quote_id = stable_id(
            "quote",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.relay_id),
                HashPart::U64(request.fee_micro_units),
                HashPart::U64(request.valid_until_slot),
            ],
        );
        let quote = ExitQuote {
            quote_id: quote_id.clone(),
            ticket_id: request.ticket_id.clone(),
            relay_id: request.relay_id,
            fee_asset_id: request.fee_asset_id,
            fee_micro_units: request.fee_micro_units,
            fee_bps: request.fee_bps,
            relay_bond_micro_units: request.relay_bond_micro_units,
            sponsor_pool_root: request.sponsor_pool_root,
            valid_until_slot: request.valid_until_slot,
        };
        self.exit_quotes.insert(quote_id, quote.clone());
        if let Some(ticket) = self.exit_tickets.get_mut(&request.ticket_id) {
            ticket.status = ExitTicketStatus::Quoted;
        }
        self.refresh_roots();
        Ok(quote)
    }

    pub fn build_exit_batch(&mut self, request: BuildExitBatchRequest) -> Result<ExitBatch> {
        ensure_capacity(self.exit_batches.len(), MAX_EXIT_BATCHES, "exit_batches")?;
        self.ensure_market_exists(&request.market_id)?;
        self.ensure_relay_exists(&request.relay_id)?;
        if request.ticket_ids.is_empty() {
            return Err("exit batch requires at least one ticket".to_string());
        }
        if request.ticket_ids.len() > MAX_TICKETS_PER_BATCH {
            return Err("exit batch has too many tickets".to_string());
        }
        ensure_non_empty(
            &request.aggregate_exit_note_root,
            "aggregate_exit_note_root",
        )?;
        ensure_non_empty(
            &request.aggregate_nullifier_root,
            "aggregate_nullifier_root",
        )?;
        ensure_non_empty(&request.reserve_release_root, "reserve_release_root")?;
        let mut total_fee_micro_units = 0_u64;
        for ticket_id in &request.ticket_ids {
            let ticket = self
                .exit_tickets
                .get(ticket_id)
                .ok_or_else(|| format!("ticket not found: {ticket_id}"))?;
            if ticket.market_id != request.market_id {
                return Err("ticket market does not match batch market".to_string());
            }
            if ticket.status != ExitTicketStatus::Quoted {
                return Err("ticket is not quoted".to_string());
            }
            let quote_fee = self
                .exit_quotes
                .values()
                .filter(|quote| quote.ticket_id == *ticket_id && quote.relay_id == request.relay_id)
                .map(|quote| quote.fee_micro_units)
                .min()
                .ok_or_else(|| "ticket has no relay quote".to_string())?;
            total_fee_micro_units = total_fee_micro_units.saturating_add(quote_fee);
        }
        let batch_id = stable_id(
            "batch",
            &[
                HashPart::Str(&request.market_id),
                HashPart::Str(&request.relay_id),
                HashPart::Str(&request.aggregate_nullifier_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let batch = ExitBatch {
            batch_id: batch_id.clone(),
            market_id: request.market_id,
            relay_id: request.relay_id,
            ticket_ids: request.ticket_ids.clone(),
            aggregate_exit_note_root: request.aggregate_exit_note_root,
            aggregate_nullifier_root: request.aggregate_nullifier_root,
            reserve_release_root: request.reserve_release_root,
            total_fee_micro_units,
            opened_slot: request.opened_slot,
            status: BatchStatus::Locked,
        };
        self.exit_batches.insert(batch_id, batch.clone());
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.exit_tickets.get_mut(ticket_id) {
                ticket.status = ExitTicketStatus::Batched;
            }
        }
        self.refresh_roots();
        Ok(batch)
    }

    pub fn record_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<RelayAttestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        self.ensure_relay_exists(&request.relay_id)?;
        if let Some(ticket_id) = &request.ticket_id {
            self.ensure_ticket_exists(ticket_id)?;
        }
        if let Some(batch_id) = &request.batch_id {
            self.ensure_batch_exists(batch_id)?;
        }
        if request.ticket_id.is_none() && request.batch_id.is_none() {
            return Err("attestation must target a ticket or batch".to_string());
        }
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(request.ticket_id.as_deref().unwrap_or("none")),
                HashPart::Str(request.batch_id.as_deref().unwrap_or("none")),
                HashPart::Str(&request.relay_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = RelayAttestation {
            attestation_id: attestation_id.clone(),
            ticket_id: request.ticket_id.clone(),
            batch_id: request.batch_id.clone(),
            relay_id: request.relay_id,
            kind: request.kind,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if let Some(ticket_id) = request.ticket_id {
            if let Some(ticket) = self.exit_tickets.get_mut(&ticket_id) {
                ticket.status = ExitTicketStatus::Attested;
            }
        }
        if let Some(batch_id) = request.batch_id {
            if let Some(batch) = self.exit_batches.get_mut(&batch_id) {
                batch.status = BatchStatus::Attested;
            }
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<ExitSettlement> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        let batch = self
            .exit_batches
            .get(&request.batch_id)
            .ok_or_else(|| "batch not found".to_string())?;
        let quote = self
            .exit_quotes
            .get(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?;
        if !batch
            .ticket_ids
            .iter()
            .any(|ticket_id| ticket_id == &quote.ticket_id)
        {
            return Err("quote ticket is not in batch".to_string());
        }
        if quote.relay_id != batch.relay_id {
            return Err("quote relay does not match batch relay".to_string());
        }
        if request.settled_slot < batch.opened_slot {
            return Err("settled_slot must be >= batch opened slot".to_string());
        }
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let slashed_micro_units = match request.decision {
            SettlementDecision::SlashRelay => {
                quote.relay_bond_micro_units * self.config.slashing_penalty_bps / MAX_BPS
            }
            _ => 0,
        };
        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.quote_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::U64(request.settled_slot),
            ],
        );
        let settlement = ExitSettlement {
            settlement_id: settlement_id.clone(),
            batch_id: request.batch_id.clone(),
            quote_id: request.quote_id.clone(),
            decision: request.decision,
            settlement_root: request.settlement_root,
            released_micro_units: request.released_micro_units,
            slashed_micro_units,
            settled_slot: request.settled_slot,
        };
        self.settlements.insert(settlement_id, settlement.clone());
        self.apply_settlement(&request.batch_id, &quote.relay_id, request.decision)?;
        self.refresh_roots();
        Ok(settlement)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        let quote = self
            .exit_quotes
            .get(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?;
        if quote.ticket_id != request.ticket_id {
            return Err("rebate quote does not match ticket".to_string());
        }
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate exceeds configured target".to_string());
        }
        if request.amount_micro_units > quote.fee_micro_units {
            return Err("rebate amount exceeds quoted fee".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.quote_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let receipt = RebateReceipt {
            rebate_id: rebate_id.clone(),
            ticket_id: request.ticket_id.clone(),
            quote_id: request.quote_id,
            asset_id: request.asset_id,
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, receipt.clone());
        if let Some(ticket) = self.exit_tickets.get_mut(&request.ticket_id) {
            ticket.status = ExitTicketStatus::Rebated;
        }
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
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction budget privacy set below configured minimum".to_string());
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
        self.ensure_market_exists(&request.market_id)?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::Str(&request.market_id),
                HashPart::U64(self.operator_summaries.len() as u64),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            market_id: request.market_id,
            settled_tickets: self.counters.settled_tickets,
            delayed_tickets: self.counters.delayed_tickets,
            rejected_tickets: self.counters.rejected_tickets,
            slashed_relays: self.counters.slashed_relays,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.markets = self.markets.len() as u64;
        self.counters.relays = self.relays.len() as u64;
        self.counters.exit_tickets = self.exit_tickets.len() as u64;
        self.counters.exit_quotes = self.exit_quotes.len() as u64;
        self.counters.exit_batches = self.exit_batches.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots.market_root = map_root("emergency-exit-bonded-relay:markets", &self.markets);
        self.roots.relay_root = map_root("emergency-exit-bonded-relay:relays", &self.relays);
        self.roots.exit_ticket_root = map_root(
            "emergency-exit-bonded-relay:exit-tickets",
            &self.exit_tickets,
        );
        self.roots.exit_quote_root =
            map_root("emergency-exit-bonded-relay:exit-quotes", &self.exit_quotes);
        self.roots.exit_batch_root = map_root(
            "emergency-exit-bonded-relay:exit-batches",
            &self.exit_batches,
        );
        self.roots.attestation_root = map_root(
            "emergency-exit-bonded-relay:attestations",
            &self.attestations,
        );
        self.roots.settlement_root =
            map_root("emergency-exit-bonded-relay:settlements", &self.settlements);
        self.roots.rebate_root = map_root("emergency-exit-bonded-relay:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "emergency-exit-bonded-relay:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "emergency-exit-bonded-relay:operator-summaries",
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
            "pq_relay_suite": self.config.pq_relay_suite,
            "exit_note_suite": self.config.exit_note_suite,
            "bonded_relay_suite": self.config.bonded_relay_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "markets": self.markets,
            "relays": self.relays,
            "exit_tickets": self.exit_tickets,
            "exit_quotes": self.exit_quotes,
            "exit_batches": self.exit_batches,
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
            "relay_root": self.roots.relay_root,
            "exit_ticket_root": self.roots.exit_ticket_root,
            "exit_quote_root": self.roots.exit_quote_root,
            "exit_batch_root": self.roots.exit_batch_root,
            "attestation_root": self.roots.attestation_root,
            "settlement_root": self.roots.settlement_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "emergency-exit-bonded-relay:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn apply_settlement(
        &mut self,
        batch_id: &str,
        relay_id: &str,
        decision: SettlementDecision,
    ) -> Result<()> {
        let ticket_ids = self
            .exit_batches
            .get(batch_id)
            .ok_or_else(|| "batch not found".to_string())?
            .ticket_ids
            .clone();
        if let Some(batch) = self.exit_batches.get_mut(batch_id) {
            batch.status = match decision {
                SettlementDecision::ReleaseExit => BatchStatus::Settled,
                SettlementDecision::ReleaseWithDelay
                | SettlementDecision::RequireMoreAttestations => BatchStatus::Delayed,
                SettlementDecision::QuarantineRelay
                | SettlementDecision::SlashRelay
                | SettlementDecision::RejectExit => BatchStatus::Quarantined,
            };
        }
        for ticket_id in ticket_ids {
            if let Some(ticket) = self.exit_tickets.get_mut(&ticket_id) {
                ticket.status = match decision {
                    SettlementDecision::ReleaseExit => {
                        self.counters.settled_tickets =
                            self.counters.settled_tickets.saturating_add(1);
                        ExitTicketStatus::Settled
                    }
                    SettlementDecision::ReleaseWithDelay
                    | SettlementDecision::RequireMoreAttestations => {
                        self.counters.delayed_tickets =
                            self.counters.delayed_tickets.saturating_add(1);
                        ExitTicketStatus::Attested
                    }
                    SettlementDecision::RejectExit
                    | SettlementDecision::QuarantineRelay
                    | SettlementDecision::SlashRelay => {
                        self.counters.rejected_tickets =
                            self.counters.rejected_tickets.saturating_add(1);
                        ExitTicketStatus::Rejected
                    }
                };
            }
        }
        if let Some(relay) = self.relays.get_mut(relay_id) {
            match decision {
                SettlementDecision::ReleaseExit | SettlementDecision::ReleaseWithDelay => {
                    relay.successful_exits = relay.successful_exits.saturating_add(1);
                }
                SettlementDecision::QuarantineRelay => {
                    relay.status = RelayStatus::Quarantined;
                    relay.failed_exits = relay.failed_exits.saturating_add(1);
                    relay.quarantine_until_slot = DEVNET_SLOT + self.config.relay_quarantine_slots;
                    self.counters.quarantined_relays =
                        self.counters.quarantined_relays.saturating_add(1);
                }
                SettlementDecision::SlashRelay => {
                    relay.status = RelayStatus::Slashed;
                    relay.failed_exits = relay.failed_exits.saturating_add(1);
                    self.counters.slashed_relays = self.counters.slashed_relays.saturating_add(1);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn ensure_market_exists(&self, market_id: &str) -> Result<()> {
        ensure_non_empty(market_id, "market_id")?;
        if !self.markets.contains_key(market_id) {
            return Err(format!("market not found: {market_id}"));
        }
        Ok(())
    }

    fn ensure_relay_exists(&self, relay_id: &str) -> Result<()> {
        ensure_non_empty(relay_id, "relay_id")?;
        if !self.relays.contains_key(relay_id) {
            return Err(format!("relay not found: {relay_id}"));
        }
        Ok(())
    }

    fn ensure_ticket_exists(&self, ticket_id: &str) -> Result<()> {
        ensure_non_empty(ticket_id, "ticket_id")?;
        if !self.exit_tickets.contains_key(ticket_id) {
            return Err(format!("ticket not found: {ticket_id}"));
        }
        Ok(())
    }

    fn ensure_batch_exists(&self, batch_id: &str) -> Result<()> {
        ensure_non_empty(batch_id, "batch_id")?;
        if !self.exit_batches.contains_key(batch_id) {
            return Err(format!("batch not found: {batch_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let market = state
        .open_market(OpenMarketRequest {
            monero_network: "monero-devnet".to_string(),
            l2_rollup_root: sample_hash("l2-rollup", 1),
            bridge_reserve_root: sample_hash("bridge-reserve", 1),
            supported_exit_kinds: [
                ExitKind::StandardExit,
                ExitKind::EmergencyLiquidityExit,
                ExitKind::SequencerCensorshipExit,
                ExitKind::BridgePauseExit,
            ]
            .into_iter()
            .collect(),
            min_relay_bond_micro_units: DEFAULT_MIN_RELAY_BOND_MICRO_UNITS,
            max_exit_fee_bps: DEFAULT_MAX_EXIT_FEE_BPS,
            exit_window_slots: DEFAULT_EXIT_WINDOW_SLOTS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet exit market opened");
    let relay = state
        .register_relay(RegisterRelayRequest {
            operator_commitment: sample_hash("relay-operator", 1),
            pq_verifying_key_root: sample_hash("pq-key", 1),
            stake_bond_micro_units: DEFAULT_MIN_RELAY_BOND_MICRO_UNITS * 3,
            supported_exit_kinds: [
                ExitKind::StandardExit,
                ExitKind::EmergencyLiquidityExit,
                ExitKind::SequencerCensorshipExit,
                ExitKind::BridgePauseExit,
            ]
            .into_iter()
            .collect(),
        })
        .expect("devnet bonded relay registered");
    let ticket = state
        .submit_exit_ticket(SubmitExitTicketRequest {
            market_id: market.market_id.clone(),
            owner_commitment: sample_hash("owner", 1),
            exit_kind: ExitKind::EmergencyLiquidityExit,
            sealed_exit_note_root: sample_hash("exit-note", 1),
            nullifier_root: sample_hash("nullifier", 1),
            monero_destination_commitment: sample_hash("destination", 1),
            amount_commitment: sample_hash("amount", 1),
            max_fee_micro_units: 25_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT,
            risk_bps: 900,
        })
        .expect("devnet exit ticket submitted");
    let quote = state
        .quote_exit(QuoteExitRequest {
            ticket_id: ticket.ticket_id.clone(),
            relay_id: relay.relay_id.clone(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            fee_micro_units: 5_800,
            fee_bps: 8,
            relay_bond_micro_units: DEFAULT_MIN_RELAY_BOND_MICRO_UNITS * 2,
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            valid_until_slot: DEVNET_SLOT + 48,
        })
        .expect("devnet exit quoted");
    let batch = state
        .build_exit_batch(BuildExitBatchRequest {
            market_id: market.market_id.clone(),
            relay_id: relay.relay_id.clone(),
            ticket_ids: vec![ticket.ticket_id.clone()],
            aggregate_exit_note_root: sample_hash("aggregate-exit-note", 1),
            aggregate_nullifier_root: sample_hash("aggregate-nullifier", 1),
            reserve_release_root: sample_hash("reserve-release", 1),
            opened_slot: DEVNET_SLOT + 2,
        })
        .expect("devnet exit batch built");
    state
        .record_attestation(RecordAttestationRequest {
            ticket_id: Some(ticket.ticket_id.clone()),
            batch_id: Some(batch.batch_id.clone()),
            relay_id: relay.relay_id,
            kind: AttestationKind::SettlementSafe,
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 4,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet relay attestation recorded");
    state
        .settle_batch(SettleBatchRequest {
            batch_id: batch.batch_id.clone(),
            quote_id: quote.quote_id.clone(),
            decision: SettlementDecision::ReleaseExit,
            settlement_root: sample_hash("settlement", 1),
            released_micro_units: 1_000_000,
            settled_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet exit settled");
    state
        .issue_rebate(IssueRebateRequest {
            ticket_id: ticket.ticket_id.clone(),
            quote_id: quote.quote_id,
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            amount_micro_units: 1_250,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 9,
            expires_slot: DEVNET_SLOT + 512,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: batch.batch_id,
            public_fields: ["batch_id", "ticket_count", "decision"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            redacted_fields: [
                "owner_commitment",
                "sealed_exit_note_root",
                "monero_destination_commitment",
                "amount_commitment",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: 2_048,
            actual_public_bytes: 736,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            market_id: market.market_id,
            median_fee_bps: 8,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let market_id = state
        .markets
        .keys()
        .next()
        .cloned()
        .expect("devnet has an exit market");
    state
        .submit_exit_ticket(SubmitExitTicketRequest {
            market_id,
            owner_commitment: sample_hash("owner", 2),
            exit_kind: ExitKind::SequencerCensorshipExit,
            sealed_exit_note_root: sample_hash("exit-note", 2),
            nullifier_root: sample_hash("nullifier", 2),
            monero_destination_commitment: sample_hash("destination", 2),
            amount_commitment: sample_hash("amount", 2),
            max_fee_micro_units: 30_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT + 32,
            risk_bps: 600,
        })
        .expect("demo censorship exit submitted");
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
        &format!("emergency-exit-bonded-relay:{domain}:id"),
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
        "emergency-exit-bonded-relay:devnet-sample",
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
