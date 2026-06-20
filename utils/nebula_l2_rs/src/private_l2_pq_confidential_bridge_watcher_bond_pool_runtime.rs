use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeWatcherBondPoolRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-bridge-watcher-bond-pool-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_WATCHER_BOND_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_WATCHER_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const BOND_POOL_SUITE: &str = "confidential-monero-bridge-watcher-bond-pool-root-v1";
pub const EVIDENCE_SUITE: &str = "confidential-bridge-watcher-evidence-root-v1";
pub const REBATE_SUITE: &str = "bridge-watcher-bond-pool-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-bridge-watcher-bond-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BOND_ASSET_ID: &str = "xmr-bridge-watcher-bond-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 288;
pub const DEFAULT_SLASH_SETTLEMENT_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_MAX_WATCHER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MIN_WATCHER_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MIN_POOL_BOND_MICRO_UNITS: u64 = 100_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 524_288;
pub const MAX_WATCHERS: usize = 1_048_576;
pub const MAX_CHALLENGES: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SLASH_RECEIPTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 7_520;
pub const DEVNET_SLOT: u64 = 151;
pub const DEVNET_L2_HEIGHT: u64 = 3_008_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondPoolScope {
    DepositFinalityWatch,
    WithdrawalProofWatch,
    ReorgRescueWatch,
    ReserveDriftWatch,
    FastExitRelayWatch,
    AtomicSwapEscrowWatch,
    EmergencyExitWatch,
    FeeSponsorWatch,
}

impl BondPoolScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositFinalityWatch => "deposit_finality_watch",
            Self::WithdrawalProofWatch => "withdrawal_proof_watch",
            Self::ReorgRescueWatch => "reorg_rescue_watch",
            Self::ReserveDriftWatch => "reserve_drift_watch",
            Self::FastExitRelayWatch => "fast_exit_relay_watch",
            Self::AtomicSwapEscrowWatch => "atomic_swap_escrow_watch",
            Self::EmergencyExitWatch => "emergency_exit_watch",
            Self::FeeSponsorWatch => "fee_sponsor_watch",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::EmergencyExitWatch => 10,
            Self::ReorgRescueWatch => 9,
            Self::WithdrawalProofWatch => 8,
            Self::DepositFinalityWatch => 7,
            Self::ReserveDriftWatch => 6,
            Self::FastExitRelayWatch => 5,
            Self::AtomicSwapEscrowWatch => 5,
            Self::FeeSponsorWatch => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondPoolStatus {
    Planned,
    Open,
    Throttled,
    Challenged,
    Draining,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherStatus {
    Candidate,
    Active,
    Probation,
    Challenged,
    Slashed,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Submitted,
    EvidenceLocked,
    Attested,
    Settled,
    RebateIssued,
    Rejected,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MissingDepositFinality,
    InvalidWithdrawalProof,
    ReorgRescueTimeout,
    ReserveDriftExceeded,
    FastExitRelayMismatch,
    AtomicSwapEscrowFault,
    FeeSponsorMisrouting,
    PrivacyBoundaryLeak,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingDepositFinality => "missing_deposit_finality",
            Self::InvalidWithdrawalProof => "invalid_withdrawal_proof",
            Self::ReorgRescueTimeout => "reorg_rescue_timeout",
            Self::ReserveDriftExceeded => "reserve_drift_exceeded",
            Self::FastExitRelayMismatch => "fast_exit_relay_mismatch",
            Self::AtomicSwapEscrowFault => "atomic_swap_escrow_fault",
            Self::FeeSponsorMisrouting => "fee_sponsor_misrouting",
            Self::PrivacyBoundaryLeak => "privacy_boundary_leak",
        }
    }

    pub fn severity_weight(self) -> u64 {
        match self {
            Self::PrivacyBoundaryLeak => 10,
            Self::InvalidWithdrawalProof => 9,
            Self::MissingDepositFinality => 8,
            Self::ReserveDriftExceeded => 8,
            Self::ReorgRescueTimeout => 7,
            Self::FastExitRelayMismatch => 6,
            Self::AtomicSwapEscrowFault => 6,
            Self::FeeSponsorMisrouting => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqWatcherSignatureVerified,
    EvidenceCommitmentOpened,
    MoneroFinalityChecked,
    ReserveWindowChecked,
    ReorgDepthBounded,
    FeeCapObserved,
    PrivacyBoundaryObserved,
    SlashSettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqWatcherSignatureVerified => "pq_watcher_signature_verified",
            Self::EvidenceCommitmentOpened => "evidence_commitment_opened",
            Self::MoneroFinalityChecked => "monero_finality_checked",
            Self::ReserveWindowChecked => "reserve_window_checked",
            Self::ReorgDepthBounded => "reorg_depth_bounded",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::SlashSettlementSafe => "slash_settlement_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    ApproveSlash,
    ApproveSlashWithRebate,
    PartialSlash,
    Reject,
    Retry,
    Quarantine,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApproveSlash => "approve_slash",
            Self::ApproveSlashWithRebate => "approve_slash_with_rebate",
            Self::PartialSlash => "partial_slash",
            Self::Reject => "reject",
            Self::Retry => "retry",
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
    pub pq_watcher_suite: String,
    pub bond_pool_suite: String,
    pub evidence_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub bond_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub challenge_window_slots: u64,
    pub slash_settlement_window_slots: u64,
    pub max_watcher_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_watcher_bond_micro_units: u64,
    pub min_pool_bond_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_slash_bps: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_watcher_suite: PQ_WATCHER_SUITE.to_string(),
            bond_pool_suite: BOND_POOL_SUITE.to_string(),
            evidence_suite: EVIDENCE_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bond_asset_id: DEFAULT_BOND_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            slash_settlement_window_slots: DEFAULT_SLASH_SETTLEMENT_WINDOW_SLOTS,
            max_watcher_fee_bps: DEFAULT_MAX_WATCHER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_watcher_bond_micro_units: DEFAULT_MIN_WATCHER_BOND_MICRO_UNITS,
            min_pool_bond_micro_units: DEFAULT_MIN_POOL_BOND_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools_opened: u64,
    pub watchers_registered: u64,
    pub challenges_submitted: u64,
    pub attestations_recorded: u64,
    pub slash_receipts_recorded: u64,
    pub rebates_issued: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub quarantines: u64,
    pub total_bonded_micro_units: u64,
    pub total_reserved_micro_units: u64,
    pub total_slashed_micro_units: u64,
    pub total_rebated_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pool_root: String,
    pub watcher_root: String,
    pub challenge_root: String,
    pub attestation_root: String,
    pub slash_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            pool_root: empty_root("pools"),
            watcher_root: empty_root("watchers"),
            challenge_root: empty_root("challenges"),
            attestation_root: empty_root("attestations"),
            slash_root: empty_root("slashes"),
            rebate_root: empty_root("rebates"),
            redaction_root: empty_root("redactions"),
            operator_summary_root: empty_root("operator-summaries"),
            counters_root: empty_root("counters"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BondPool {
    pub pool_id: String,
    pub scope: BondPoolScope,
    pub status: BondPoolStatus,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub watcher_set_root: String,
    pub target_bond_micro_units: u64,
    pub fee_cap_bps: u64,
    pub slash_cap_bps: u64,
    pub opened_slot: u64,
    pub last_updated_slot: u64,
    pub registered_watchers: u64,
    pub challenged_watchers: u64,
    pub available_bond_micro_units: u64,
    pub reserved_bond_micro_units: u64,
    pub slashed_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherBond {
    pub watcher_id: String,
    pub pool_id: String,
    pub status: WatcherStatus,
    pub watcher_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_commitment_root: String,
    pub bond_micro_units: u64,
    pub reserved_micro_units: u64,
    pub slashed_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
    pub last_attested_slot: u64,
    pub challenge_count: u64,
    pub successful_challenge_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeWatcherChallenge {
    pub challenge_id: String,
    pub pool_id: String,
    pub watcher_id: String,
    pub kind: EvidenceKind,
    pub status: ChallengeStatus,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub claimant_commitment: String,
    pub affected_bridge_root: String,
    pub requested_slash_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub attestation_count: u64,
    pub quorum_weight_bps: u64,
    pub settled_slot: Option<u64>,
    pub settlement_decision: Option<SettlementDecision>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub challenge_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashReceipt {
    pub slash_id: String,
    pub challenge_id: String,
    pub pool_id: String,
    pub watcher_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub slash_bps: u64,
    pub slashed_micro_units: u64,
    pub claimant_award_micro_units: u64,
    pub pool_replenish_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub challenge_id: String,
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
    pub epoch: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub active_pools: u64,
    pub active_watchers: u64,
    pub challenged_watchers: u64,
    pub slashed_watchers: u64,
    pub quarantined_watchers: u64,
    pub total_bonded_micro_units: u64,
    pub total_slashed_micro_units: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenBondPoolRequest {
    pub scope: BondPoolScope,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub watcher_set_root: String,
    pub target_bond_micro_units: u64,
    pub fee_cap_bps: u64,
    pub slash_cap_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenBondPoolReceipt {
    pub pool_id: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterWatcherRequest {
    pub pool_id: String,
    pub watcher_commitment: String,
    pub pq_verifying_key_root: String,
    pub bond_commitment_root: String,
    pub bond_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterWatcherReceipt {
    pub watcher_id: String,
    pub pool_id: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitChallengeRequest {
    pub pool_id: String,
    pub watcher_id: String,
    pub kind: EvidenceKind,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub claimant_commitment: String,
    pub affected_bridge_root: String,
    pub requested_slash_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitChallengeReceipt {
    pub challenge_id: String,
    pub expires_slot: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub challenge_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationReceipt {
    pub attestation_id: String,
    pub challenge_id: String,
    pub accepted: bool,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleChallengeRequest {
    pub challenge_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleChallengeReceipt {
    pub slash_id: String,
    pub challenge_id: String,
    pub slashed_micro_units: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub challenge_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateReceipt {
    pub rebate_id: String,
    pub challenge_id: String,
    pub state_root: String,
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
    pub pools: BTreeMap<String, BondPool>,
    pub watchers: BTreeMap<String, WatcherBond>,
    pub challenges: BTreeMap<String, BridgeWatcherChallenge>,
    pub attestations: BTreeMap<String, WatcherAttestation>,
    pub slash_receipts: BTreeMap<String, SlashReceipt>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            watchers: BTreeMap::new(),
            challenges: BTreeMap::new(),
            attestations: BTreeMap::new(),
            slash_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn open_bond_pool(&mut self, request: OpenBondPoolRequest) -> Result<OpenBondPoolReceipt> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "bond pools")?;
        ensure_non_empty(&request.sealed_pool_root, "sealed_pool_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_non_empty(&request.watcher_set_root, "watcher_set_root")?;
        ensure_bps(request.fee_cap_bps, "fee_cap_bps")?;
        ensure_bps(request.slash_cap_bps, "slash_cap_bps")?;
        if request.fee_cap_bps > self.config.max_watcher_fee_bps {
            return Err("fee_cap_bps exceeds configured maximum".to_string());
        }
        if request.slash_cap_bps > self.config.max_slash_bps {
            return Err("slash_cap_bps exceeds configured maximum".to_string());
        }
        if request.target_bond_micro_units < self.config.min_pool_bond_micro_units {
            return Err("target_bond_micro_units below minimum pool bond".to_string());
        }

        let pool_id = stable_id(
            "pool",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.sealed_pool_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        if self.pools.contains_key(&pool_id) {
            return Err(format!("bond pool {pool_id} already exists"));
        }

        let pool = BondPool {
            pool_id: pool_id.clone(),
            scope: request.scope,
            status: BondPoolStatus::Open,
            sealed_pool_root: request.sealed_pool_root,
            public_hint_root: request.public_hint_root,
            watcher_set_root: request.watcher_set_root,
            target_bond_micro_units: request.target_bond_micro_units,
            fee_cap_bps: request.fee_cap_bps,
            slash_cap_bps: request.slash_cap_bps,
            opened_slot: request.opened_slot,
            last_updated_slot: request.opened_slot,
            registered_watchers: 0,
            challenged_watchers: 0,
            available_bond_micro_units: 0,
            reserved_bond_micro_units: 0,
            slashed_micro_units: 0,
        };
        self.pools.insert(pool_id.clone(), pool);
        self.counters.pools_opened = self.counters.pools_opened.saturating_add(1);
        self.refresh_roots();

        Ok(OpenBondPoolReceipt {
            pool_id,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn register_watcher(
        &mut self,
        request: RegisterWatcherRequest,
    ) -> Result<RegisterWatcherReceipt> {
        ensure_capacity(self.watchers.len(), MAX_WATCHERS, "watchers")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.watcher_commitment, "watcher_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(&request.bond_commitment_root, "bond_commitment_root")?;
        if request.bond_micro_units < self.config.min_watcher_bond_micro_units {
            return Err("bond_micro_units below minimum watcher bond".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }

        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        if !matches!(
            pool.status,
            BondPoolStatus::Open | BondPoolStatus::Throttled
        ) {
            return Err("bond pool is not accepting watchers".to_string());
        }

        let watcher_id = stable_id(
            "watcher",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.watcher_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.joined_slot),
            ],
        );
        if self.watchers.contains_key(&watcher_id) {
            return Err(format!("watcher {watcher_id} already exists"));
        }

        let watcher = WatcherBond {
            watcher_id: watcher_id.clone(),
            pool_id: request.pool_id.clone(),
            status: WatcherStatus::Active,
            watcher_commitment: request.watcher_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            bond_commitment_root: request.bond_commitment_root,
            bond_micro_units: request.bond_micro_units,
            reserved_micro_units: 0,
            slashed_micro_units: 0,
            privacy_set_size: request.privacy_set_size,
            joined_slot: request.joined_slot,
            last_attested_slot: request.joined_slot,
            challenge_count: 0,
            successful_challenge_count: 0,
        };
        pool.registered_watchers = pool.registered_watchers.saturating_add(1);
        pool.available_bond_micro_units = pool
            .available_bond_micro_units
            .saturating_add(request.bond_micro_units);
        pool.last_updated_slot = request.joined_slot;
        self.counters.watchers_registered = self.counters.watchers_registered.saturating_add(1);
        self.counters.total_bonded_micro_units = self
            .counters
            .total_bonded_micro_units
            .saturating_add(request.bond_micro_units);
        self.watchers.insert(watcher_id.clone(), watcher);
        self.refresh_roots();

        Ok(RegisterWatcherReceipt {
            watcher_id,
            pool_id: request.pool_id,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn submit_challenge(
        &mut self,
        request: SubmitChallengeRequest,
    ) -> Result<SubmitChallengeReceipt> {
        ensure_capacity(self.challenges.len(), MAX_CHALLENGES, "challenges")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.watcher_id, "watcher_id")?;
        ensure_non_empty(&request.sealed_evidence_root, "sealed_evidence_root")?;
        ensure_non_empty(&request.redacted_evidence_root, "redacted_evidence_root")?;
        ensure_non_empty(&request.claimant_commitment, "claimant_commitment")?;
        ensure_non_empty(&request.affected_bridge_root, "affected_bridge_root")?;
        ensure_bps(request.requested_slash_bps, "requested_slash_bps")?;
        ensure_bps(request.requested_rebate_bps, "requested_rebate_bps")?;
        if request.requested_slash_bps > self.config.max_slash_bps {
            return Err("requested_slash_bps exceeds configured maximum".to_string());
        }

        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        let watcher = self
            .watchers
            .get_mut(&request.watcher_id)
            .ok_or_else(|| format!("unknown watcher {}", request.watcher_id))?;
        if watcher.pool_id != request.pool_id {
            return Err("watcher does not belong to requested pool".to_string());
        }
        if !matches!(
            watcher.status,
            WatcherStatus::Active | WatcherStatus::Probation
        ) {
            return Err("watcher is not challengeable".to_string());
        }

        let reserve_micro_units = watcher
            .bond_micro_units
            .saturating_mul(request.requested_slash_bps)
            / MAX_BPS;
        if reserve_micro_units == 0 {
            return Err("requested slash reserves zero bond units".to_string());
        }
        if reserve_micro_units
            > watcher
                .bond_micro_units
                .saturating_sub(watcher.slashed_micro_units)
        {
            return Err("requested slash exceeds remaining watcher bond".to_string());
        }

        let challenge_id = stable_id(
            "challenge",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.watcher_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.sealed_evidence_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        if self.challenges.contains_key(&challenge_id) {
            return Err(format!("challenge {challenge_id} already exists"));
        }

        let expires_slot = request
            .submitted_slot
            .saturating_add(self.config.challenge_window_slots);
        let challenge = BridgeWatcherChallenge {
            challenge_id: challenge_id.clone(),
            pool_id: request.pool_id.clone(),
            watcher_id: request.watcher_id.clone(),
            kind: request.kind,
            status: ChallengeStatus::Submitted,
            sealed_evidence_root: request.sealed_evidence_root,
            redacted_evidence_root: request.redacted_evidence_root,
            claimant_commitment: request.claimant_commitment,
            affected_bridge_root: request.affected_bridge_root,
            requested_slash_bps: request.requested_slash_bps,
            requested_rebate_bps: request.requested_rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot,
            attestation_count: 0,
            quorum_weight_bps: 0,
            settled_slot: None,
            settlement_decision: None,
        };

        watcher.status = WatcherStatus::Challenged;
        watcher.challenge_count = watcher.challenge_count.saturating_add(1);
        watcher.reserved_micro_units = watcher
            .reserved_micro_units
            .saturating_add(reserve_micro_units);
        pool.status = BondPoolStatus::Challenged;
        pool.challenged_watchers = pool.challenged_watchers.saturating_add(1);
        pool.reserved_bond_micro_units = pool
            .reserved_bond_micro_units
            .saturating_add(reserve_micro_units);
        pool.available_bond_micro_units = pool
            .available_bond_micro_units
            .saturating_sub(reserve_micro_units);
        pool.last_updated_slot = request.submitted_slot;
        self.counters.challenges_submitted = self.counters.challenges_submitted.saturating_add(1);
        self.counters.total_reserved_micro_units = self
            .counters
            .total_reserved_micro_units
            .saturating_add(reserve_micro_units);
        self.challenges.insert(challenge_id.clone(), challenge);
        self.refresh_roots();

        Ok(SubmitChallengeReceipt {
            challenge_id,
            expires_slot,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn record_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<RecordAttestationReceipt> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.challenge_id, "challenge_id")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;

        let challenge = self
            .challenges
            .get_mut(&request.challenge_id)
            .ok_or_else(|| format!("unknown challenge {}", request.challenge_id))?;
        if !matches!(
            challenge.status,
            ChallengeStatus::Submitted | ChallengeStatus::EvidenceLocked
        ) {
            return Err("challenge is not accepting attestations".to_string());
        }

        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.committee_root),
                HashPart::Str(&request.statement_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }

        let accepted = request.quorum_weight_bps >= self.config.min_attestation_quorum_bps;
        let attestation = WatcherAttestation {
            attestation_id: attestation_id.clone(),
            challenge_id: request.challenge_id.clone(),
            kind: request.kind,
            committee_root: request.committee_root,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
            accepted,
        };
        challenge.attestation_count = challenge.attestation_count.saturating_add(1);
        challenge.quorum_weight_bps = challenge.quorum_weight_bps.max(request.quorum_weight_bps);
        if accepted {
            challenge.status = ChallengeStatus::Attested;
        } else {
            challenge.status = ChallengeStatus::EvidenceLocked;
        }
        if let Some(watcher) = self.watchers.get_mut(&challenge.watcher_id) {
            watcher.last_attested_slot = request.observed_slot;
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();

        Ok(RecordAttestationReceipt {
            attestation_id,
            challenge_id: request.challenge_id,
            accepted,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn settle_challenge(
        &mut self,
        request: SettleChallengeRequest,
    ) -> Result<SettleChallengeReceipt> {
        ensure_capacity(
            self.slash_receipts.len(),
            MAX_SLASH_RECEIPTS,
            "slash receipts",
        )?;
        ensure_non_empty(&request.challenge_id, "challenge_id")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;

        let challenge = self
            .challenges
            .get_mut(&request.challenge_id)
            .ok_or_else(|| format!("unknown challenge {}", request.challenge_id))?;
        if !matches!(
            challenge.status,
            ChallengeStatus::Attested | ChallengeStatus::EvidenceLocked
        ) {
            return Err("challenge is not settleable".to_string());
        }
        if request.settled_slot > challenge.expires_slot {
            return Err("settled_slot exceeds challenge expiry".to_string());
        }

        let pool = self
            .pools
            .get_mut(&challenge.pool_id)
            .ok_or_else(|| format!("unknown pool {}", challenge.pool_id))?;
        let watcher = self
            .watchers
            .get_mut(&challenge.watcher_id)
            .ok_or_else(|| format!("unknown watcher {}", challenge.watcher_id))?;
        let requested_slash = watcher
            .bond_micro_units
            .saturating_mul(challenge.requested_slash_bps)
            / MAX_BPS;
        let slashed_micro_units = match request.decision {
            SettlementDecision::ApproveSlash | SettlementDecision::ApproveSlashWithRebate => {
                requested_slash
            }
            SettlementDecision::PartialSlash => requested_slash / 2,
            SettlementDecision::Reject | SettlementDecision::Retry | SettlementDecision::Expire => {
                0
            }
            SettlementDecision::Quarantine => requested_slash,
        };
        let slash_id = stable_id(
            "slash",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::Str(&request.settlement_root),
                HashPart::U64(request.settled_slot),
            ],
        );
        if self.slash_receipts.contains_key(&slash_id) {
            return Err(format!("slash receipt {slash_id} already exists"));
        }

        let claimant_award_micro_units = slashed_micro_units / 2;
        let pool_replenish_micro_units =
            slashed_micro_units.saturating_sub(claimant_award_micro_units);
        watcher.reserved_micro_units = watcher.reserved_micro_units.saturating_sub(requested_slash);
        watcher.slashed_micro_units = watcher
            .slashed_micro_units
            .saturating_add(slashed_micro_units);
        if slashed_micro_units > 0 {
            watcher.successful_challenge_count =
                watcher.successful_challenge_count.saturating_add(1);
        }
        watcher.status = match request.decision {
            SettlementDecision::ApproveSlash | SettlementDecision::ApproveSlashWithRebate => {
                WatcherStatus::Slashed
            }
            SettlementDecision::PartialSlash => WatcherStatus::Probation,
            SettlementDecision::Quarantine => {
                self.counters.quarantines = self.counters.quarantines.saturating_add(1);
                WatcherStatus::Quarantined
            }
            SettlementDecision::Reject | SettlementDecision::Retry => WatcherStatus::Active,
            SettlementDecision::Expire => WatcherStatus::Probation,
        };

        pool.reserved_bond_micro_units = pool
            .reserved_bond_micro_units
            .saturating_sub(requested_slash);
        pool.slashed_micro_units = pool.slashed_micro_units.saturating_add(slashed_micro_units);
        pool.available_bond_micro_units = pool
            .available_bond_micro_units
            .saturating_add(requested_slash.saturating_sub(slashed_micro_units));
        pool.status = if matches!(request.decision, SettlementDecision::Quarantine) {
            BondPoolStatus::Quarantined
        } else {
            BondPoolStatus::Open
        };
        pool.last_updated_slot = request.settled_slot;

        challenge.status = match request.decision {
            SettlementDecision::Reject => ChallengeStatus::Rejected,
            SettlementDecision::Expire => ChallengeStatus::Expired,
            SettlementDecision::Quarantine => ChallengeStatus::Quarantined,
            _ => ChallengeStatus::Settled,
        };
        challenge.settled_slot = Some(request.settled_slot);
        challenge.settlement_decision = Some(request.decision);

        let slash = SlashReceipt {
            slash_id: slash_id.clone(),
            challenge_id: request.challenge_id.clone(),
            pool_id: challenge.pool_id.clone(),
            watcher_id: challenge.watcher_id.clone(),
            settlement_root: request.settlement_root,
            decision: request.decision,
            slash_bps: challenge.requested_slash_bps,
            slashed_micro_units,
            claimant_award_micro_units,
            pool_replenish_micro_units,
            settled_slot: request.settled_slot,
        };
        self.counters.slash_receipts_recorded =
            self.counters.slash_receipts_recorded.saturating_add(1);
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(slashed_micro_units);
        self.slash_receipts.insert(slash_id.clone(), slash);
        self.refresh_roots();

        Ok(SettleChallengeReceipt {
            slash_id,
            challenge_id: request.challenge_id,
            slashed_micro_units,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<IssueRebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.challenge_id, "challenge_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.max_watcher_fee_bps {
            return Err("fee_rebate_bps exceeds configured fee cap".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("expires_slot must be greater than issued_slot".to_string());
        }

        let challenge = self
            .challenges
            .get_mut(&request.challenge_id)
            .ok_or_else(|| format!("unknown challenge {}", request.challenge_id))?;
        if !matches!(challenge.status, ChallengeStatus::Settled) {
            return Err("challenge must be settled before rebate".to_string());
        }

        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::Str(&request.beneficiary_group_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("rebate {rebate_id} already exists"));
        }

        let rebate = RebateReceipt {
            rebate_id: rebate_id.clone(),
            challenge_id: request.challenge_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        challenge.status = ChallengeStatus::RebateIssued;
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.total_rebated_micro_units = self
            .counters
            .total_rebated_micro_units
            .saturating_add(request.amount_micro_units);
        self.rebates.insert(rebate_id.clone(), rebate);
        self.refresh_roots();

        Ok(IssueRebateReceipt {
            rebate_id,
            challenge_id: request.challenge_id,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn publish_redaction_budget(&mut self, request: RedactionBudgetRequest) -> Result<()> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("max_public_bytes exceeds configured maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }

        let budget = RedactionBudget {
            target_id: request.target_id.clone(),
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
        };
        self.redaction_budgets
            .insert(request.target_id.clone(), budget);
        self.counters.redaction_budgets_published =
            self.counters.redaction_budgets_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<()> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;

        let active_pools = self
            .pools
            .values()
            .filter(|pool| {
                matches!(
                    pool.status,
                    BondPoolStatus::Open | BondPoolStatus::Challenged
                )
            })
            .count() as u64;
        let active_watchers = self
            .watchers
            .values()
            .filter(|watcher| matches!(watcher.status, WatcherStatus::Active))
            .count() as u64;
        let challenged_watchers = self
            .watchers
            .values()
            .filter(|watcher| matches!(watcher.status, WatcherStatus::Challenged))
            .count() as u64;
        let slashed_watchers = self
            .watchers
            .values()
            .filter(|watcher| matches!(watcher.status, WatcherStatus::Slashed))
            .count() as u64;
        let quarantined_watchers = self
            .watchers
            .values()
            .filter(|watcher| matches!(watcher.status, WatcherStatus::Quarantined))
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::U64(DEVNET_EPOCH),
                HashPart::U64(DEVNET_SLOT),
                HashPart::Str(&self.roots.state_root),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            l2_height: DEVNET_L2_HEIGHT,
            active_pools,
            active_watchers,
            challenged_watchers,
            slashed_watchers,
            quarantined_watchers,
            total_bonded_micro_units: self.counters.total_bonded_micro_units,
            total_slashed_micro_units: self.counters.total_slashed_micro_units,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            state_root: self.roots.state_root.clone(),
        };
        self.operator_summaries.insert(summary_id, summary);
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = object_root("config", &self.config);
        self.roots.pool_root = map_root("pools", &self.pools);
        self.roots.watcher_root = map_root("watchers", &self.watchers);
        self.roots.challenge_root = map_root("challenges", &self.challenges);
        self.roots.attestation_root = map_root("attestations", &self.attestations);
        self.roots.slash_root = map_root("slashes", &self.slash_receipts);
        self.roots.rebate_root = map_root("rebates", &self.rebates);
        self.roots.redaction_root = map_root("redactions", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("operator-summaries", &self.operator_summaries);
        self.roots.counters_root = object_root("counters", &self.counters);
        self.roots.state_root = merkle_root(
            "bridge-watcher-bond-pool:state",
            &[
                json!({ "config_root": self.roots.config_root }),
                json!({ "pool_root": self.roots.pool_root }),
                json!({ "watcher_root": self.roots.watcher_root }),
                json!({ "challenge_root": self.roots.challenge_root }),
                json!({ "attestation_root": self.roots.attestation_root }),
                json!({ "slash_root": self.roots.slash_root }),
                json!({ "rebate_root": self.roots.rebate_root }),
                json!({ "redaction_root": self.roots.redaction_root }),
                json!({ "operator_summary_root": self.roots.operator_summary_root }),
                json!({ "counters_root": self.roots.counters_root }),
            ],
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": self.config.hash_suite,
            "pq_watcher_suite": self.config.pq_watcher_suite,
            "bond_pool_suite": self.config.bond_pool_suite,
            "evidence_suite": self.config.evidence_suite,
            "fee_asset_id": self.config.fee_asset_id,
            "bond_asset_id": self.config.bond_asset_id,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "challenge_window_slots": self.config.challenge_window_slots,
            "slash_settlement_window_slots": self.config.slash_settlement_window_slots,
            "max_watcher_fee_bps": self.config.max_watcher_fee_bps,
            "target_rebate_bps": self.config.target_rebate_bps,
            "max_slash_bps": self.config.max_slash_bps,
            "counters": self.counters,
            "roots": self.roots,
            "pool_count": self.pools.len(),
            "watcher_count": self.watchers.len(),
            "challenge_count": self.challenges.len(),
            "attestation_count": self.attestations.len(),
            "slash_receipt_count": self.slash_receipts.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "pools": self.pools.values().map(|pool| {
                json!({
                    "pool_id": pool.pool_id,
                    "scope": pool.scope,
                    "status": pool.status,
                    "public_hint_root": pool.public_hint_root,
                    "target_bond_micro_units": pool.target_bond_micro_units,
                    "fee_cap_bps": pool.fee_cap_bps,
                    "slash_cap_bps": pool.slash_cap_bps,
                    "opened_slot": pool.opened_slot,
                    "registered_watchers": pool.registered_watchers,
                    "challenged_watchers": pool.challenged_watchers,
                    "available_bond_micro_units": pool.available_bond_micro_units,
                    "reserved_bond_micro_units": pool.reserved_bond_micro_units,
                    "slashed_micro_units": pool.slashed_micro_units,
                })
            }).collect::<Vec<_>>(),
            "watchers": self.watchers.values().map(|watcher| {
                json!({
                    "watcher_id": watcher.watcher_id,
                    "pool_id": watcher.pool_id,
                    "status": watcher.status,
                    "bond_micro_units": watcher.bond_micro_units,
                    "reserved_micro_units": watcher.reserved_micro_units,
                    "slashed_micro_units": watcher.slashed_micro_units,
                    "privacy_set_size": watcher.privacy_set_size,
                    "joined_slot": watcher.joined_slot,
                    "last_attested_slot": watcher.last_attested_slot,
                    "challenge_count": watcher.challenge_count,
                    "successful_challenge_count": watcher.successful_challenge_count,
                })
            }).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(|challenge| {
                json!({
                    "challenge_id": challenge.challenge_id,
                    "pool_id": challenge.pool_id,
                    "watcher_id": challenge.watcher_id,
                    "kind": challenge.kind,
                    "status": challenge.status,
                    "redacted_evidence_root": challenge.redacted_evidence_root,
                    "affected_bridge_root": challenge.affected_bridge_root,
                    "requested_slash_bps": challenge.requested_slash_bps,
                    "requested_rebate_bps": challenge.requested_rebate_bps,
                    "submitted_slot": challenge.submitted_slot,
                    "expires_slot": challenge.expires_slot,
                    "attestation_count": challenge.attestation_count,
                    "quorum_weight_bps": challenge.quorum_weight_bps,
                    "settled_slot": challenge.settled_slot,
                    "settlement_decision": challenge.settlement_decision,
                })
            }).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(|attestation| {
                json!({
                    "attestation_id": attestation.attestation_id,
                    "challenge_id": attestation.challenge_id,
                    "kind": attestation.kind,
                    "statement_root": attestation.statement_root,
                    "observed_slot": attestation.observed_slot,
                    "quorum_weight_bps": attestation.quorum_weight_bps,
                    "accepted": attestation.accepted,
                })
            }).collect::<Vec<_>>(),
            "slash_receipts": self.slash_receipts.values().map(|slash| {
                json!({
                    "slash_id": slash.slash_id,
                    "challenge_id": slash.challenge_id,
                    "pool_id": slash.pool_id,
                    "watcher_id": slash.watcher_id,
                    "decision": slash.decision,
                    "slash_bps": slash.slash_bps,
                    "slashed_micro_units": slash.slashed_micro_units,
                    "claimant_award_micro_units": slash.claimant_award_micro_units,
                    "pool_replenish_micro_units": slash.pool_replenish_micro_units,
                    "settled_slot": slash.settled_slot,
                })
            }).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(|rebate| {
                json!({
                    "rebate_id": rebate.rebate_id,
                    "challenge_id": rebate.challenge_id,
                    "asset_id": rebate.asset_id,
                    "amount_micro_units": rebate.amount_micro_units,
                    "fee_rebate_bps": rebate.fee_rebate_bps,
                    "issued_slot": rebate.issued_slot,
                    "expires_slot": rebate.expires_slot,
                })
            }).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool = state
        .open_bond_pool(OpenBondPoolRequest {
            scope: BondPoolScope::WithdrawalProofWatch,
            sealed_pool_root: sample_hash("sealed-pool", 1),
            public_hint_root: sample_hash("public-hint", 1),
            watcher_set_root: sample_hash("watcher-set", 1),
            target_bond_micro_units: 240_000_000,
            fee_cap_bps: 11,
            slash_cap_bps: 2_500,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet bridge watcher bond pool opened");
    let watcher = state
        .register_watcher(RegisterWatcherRequest {
            pool_id: pool.pool_id.clone(),
            watcher_commitment: sample_hash("watcher", 1),
            pq_verifying_key_root: sample_hash("watcher-pq-key", 1),
            bond_commitment_root: sample_hash("watcher-bond", 1),
            bond_micro_units: DEFAULT_MIN_WATCHER_BOND_MICRO_UNITS * 3,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet watcher registered");
    let challenge = state
        .submit_challenge(SubmitChallengeRequest {
            pool_id: pool.pool_id.clone(),
            watcher_id: watcher.watcher_id.clone(),
            kind: EvidenceKind::InvalidWithdrawalProof,
            sealed_evidence_root: sample_hash("sealed-evidence", 1),
            redacted_evidence_root: sample_hash("redacted-evidence", 1),
            claimant_commitment: sample_hash("claimant", 1),
            affected_bridge_root: sample_hash("bridge-root", 1),
            requested_slash_bps: 1_500,
            requested_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 5,
        })
        .expect("devnet challenge submitted");
    state
        .record_attestation(RecordAttestationRequest {
            challenge_id: challenge.challenge_id.clone(),
            kind: AttestationKind::SlashSettlementSafe,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 9,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet attestation recorded");
    state
        .settle_challenge(SettleChallengeRequest {
            challenge_id: challenge.challenge_id.clone(),
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::ApproveSlashWithRebate,
            settled_slot: DEVNET_SLOT + 15,
        })
        .expect("devnet challenge settled");
    state
        .issue_rebate(IssueRebateRequest {
            challenge_id: challenge.challenge_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 1_250,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 16,
            expires_slot: DEVNET_SLOT + DEFAULT_CHALLENGE_WINDOW_SLOTS,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: challenge.challenge_id,
            public_fields: [
                "challenge_id",
                "pool_id",
                "watcher_id",
                "kind",
                "requested_slash_bps",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "watcher_commitment",
                "sealed_evidence_root",
                "claimant_commitment",
                "committee_root",
                "pq_signature_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 896,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 9,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .open_bond_pool(OpenBondPoolRequest {
            scope: BondPoolScope::ReorgRescueWatch,
            sealed_pool_root: sample_hash("sealed-pool", 2),
            public_hint_root: sample_hash("public-hint", 2),
            watcher_set_root: sample_hash("watcher-set", 2),
            target_bond_micro_units: 180_000_000,
            fee_cap_bps: 10,
            slash_cap_bps: 1_800,
            opened_slot: DEVNET_SLOT + 40,
        })
        .expect("demo bridge watcher bond pool opened");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("bridge-watcher-bond-pool:{domain}:id"), parts, 24)
}

fn empty_root(domain: &str) -> String {
    merkle_root(&format!("bridge-watcher-bond-pool:{domain}"), &[])
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    let value = json!(value);
    merkle_root(&format!("bridge-watcher-bond-pool:{domain}"), &[value])
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("bridge-watcher-bond-pool:{domain}"), &leaves)
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "bridge-watcher-bond-pool:devnet-sample",
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
