use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialExitAcceptanceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-exit-acceptance-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-19.vertical-slice.adversarial-exit-acceptance.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const ACCEPTANCE_SUITE: &str =
    "monero-l2-pq-bridge-private-exit-adversarial-acceptance-negative-fixtures-v1";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-exit-acceptance-runtime";
const DEFAULT_L2_TIP_HEIGHT: u64 = 6_180_400;
const DEFAULT_MONERO_TIP_HEIGHT: u64 = 3_465_920;
const DEFAULT_ACCEPTANCE_EPOCH: u64 = 84;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceCaseKind {
    StaleWalletRecovery,
    BadObservedReceiptRoot,
    WithheldLiveFeedRoot,
    WatcherCollusion,
    ReorgSensitiveDepositEvidence,
    ReplayedClaim,
    LiquidityShortfall,
    PqAuthorityMismatch,
    PrivacyBudgetBreach,
}

impl AcceptanceCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleWalletRecovery => "stale_wallet_recovery",
            Self::BadObservedReceiptRoot => "bad_observed_receipt_root",
            Self::WithheldLiveFeedRoot => "withheld_live_feed_root",
            Self::WatcherCollusion => "watcher_collusion",
            Self::ReorgSensitiveDepositEvidence => "reorg_sensitive_deposit_evidence",
            Self::ReplayedClaim => "replayed_claim",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::PqAuthorityMismatch => "pq_authority_mismatch",
            Self::PrivacyBudgetBreach => "privacy_budget_breach",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceStatus {
    Accepted,
    Deferred,
    Rejected,
}

impl AcceptanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedReason {
    None,
    StaleRecoveryTranscript,
    ReceiptRootMismatch,
    LiveFeedRootMissing,
    WatcherEquivocation,
    DepositEvidenceBelowReorgHold,
    ClaimReplayDetected,
    ReserveFloorViolated,
    PqAuthorityEpochMismatch,
    PrivacyBudgetExceeded,
}

impl FailClosedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StaleRecoveryTranscript => "stale_recovery_transcript",
            Self::ReceiptRootMismatch => "receipt_root_mismatch",
            Self::LiveFeedRootMissing => "live_feed_root_missing",
            Self::WatcherEquivocation => "watcher_equivocation",
            Self::DepositEvidenceBelowReorgHold => "deposit_evidence_below_reorg_hold",
            Self::ClaimReplayDetected => "claim_replay_detected",
            Self::ReserveFloorViolated => "reserve_floor_violated",
            Self::PqAuthorityEpochMismatch => "pq_authority_epoch_mismatch",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub acceptance_suite: String,
    pub l2_finality_lag_blocks: u64,
    pub monero_reorg_hold_blocks: u64,
    pub wallet_recovery_max_age_blocks: u64,
    pub live_feed_grace_ms: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub pq_authority_epoch: u64,
    pub pq_authority_ttl_blocks: u64,
    pub reserve_floor_piconero: u64,
    pub privacy_budget_bits: u64,
    pub max_claim_age_blocks: u64,
    pub reject_on_any_blocker: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            acceptance_suite: ACCEPTANCE_SUITE.to_string(),
            l2_finality_lag_blocks: 12,
            monero_reorg_hold_blocks: 24,
            wallet_recovery_max_age_blocks: 48,
            live_feed_grace_ms: 45_000,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            pq_authority_epoch: 37,
            pq_authority_ttl_blocks: 720,
            reserve_floor_piconero: 16_000_000_000_000,
            privacy_budget_bits: 6,
            max_claim_age_blocks: 576,
            reject_on_any_blocker: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "acceptance_suite": self.acceptance_suite,
            "l2_finality_lag_blocks": self.l2_finality_lag_blocks,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "wallet_recovery_max_age_blocks": self.wallet_recovery_max_age_blocks,
            "live_feed_grace_ms": self.live_feed_grace_ms,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "pq_authority_epoch": self.pq_authority_epoch,
            "pq_authority_ttl_blocks": self.pq_authority_ttl_blocks,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "privacy_budget_bits": self.privacy_budget_bits,
            "max_claim_age_blocks": self.max_claim_age_blocks,
            "reject_on_any_blocker": self.reject_on_any_blocker,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletRecoveryEvidence {
    pub recovery_id: String,
    pub wallet_view_tag: String,
    pub transcript_root: String,
    pub recovery_height: u64,
    pub observed_l2_height: u64,
    pub signer_epoch: u64,
    pub recovery_nonce: u64,
}

impl WalletRecoveryEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "recovery_id": self.recovery_id,
            "wallet_view_tag": self.wallet_view_tag,
            "transcript_root": self.transcript_root,
            "recovery_height": self.recovery_height,
            "observed_l2_height": self.observed_l2_height,
            "signer_epoch": self.signer_epoch,
            "recovery_nonce": self.recovery_nonce,
        })
    }

    pub fn age_blocks(&self) -> u64 {
        self.observed_l2_height.saturating_sub(self.recovery_height)
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_recovery_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptEvidence {
    pub receipt_id: String,
    pub claimed_receipt_root: String,
    pub observed_receipt_root: String,
    pub receipt_leaf_root: String,
    pub receipt_count: u64,
    pub observed_batch_height: u64,
}

impl ReceiptEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "claimed_receipt_root": self.claimed_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "receipt_leaf_root": self.receipt_leaf_root,
            "receipt_count": self.receipt_count,
            "observed_batch_height": self.observed_batch_height,
        })
    }

    pub fn roots_match(&self) -> bool {
        self.claimed_receipt_root == self.observed_receipt_root
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveFeedEvidence {
    pub feed_id: String,
    pub expected_live_root: String,
    pub supplied_live_root: String,
    pub root_withheld_ms: u64,
    pub adapter_sequence: u64,
    pub feed_height: u64,
}

impl LiveFeedEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "expected_live_root": self.expected_live_root,
            "supplied_live_root": self.supplied_live_root,
            "root_withheld_ms": self.root_withheld_ms,
            "adapter_sequence": self.adapter_sequence,
            "feed_height": self.feed_height,
        })
    }

    pub fn supplied(&self) -> bool {
        !self.supplied_live_root.is_empty()
    }

    pub fn state_root(&self) -> String {
        record_root("live_feed_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub watcher_id: String,
    pub public_key_tag: String,
    pub signed_view_root: String,
    pub release_bitmap: u64,
    pub observed_height: u64,
    pub signature_root: String,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "public_key_tag": self.public_key_tag,
            "signed_view_root": self.signed_view_root,
            "release_bitmap": self.release_bitmap,
            "observed_height": self.observed_height,
            "signature_root": self.signature_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositEvidence {
    pub deposit_id: String,
    pub monero_txid_root: String,
    pub lock_output_root: String,
    pub deposit_height: u64,
    pub monero_tip_height: u64,
    pub confirmations: u64,
    pub anchor_root: String,
}

impl DepositEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "monero_txid_root": self.monero_txid_root,
            "lock_output_root": self.lock_output_root,
            "deposit_height": self.deposit_height,
            "monero_tip_height": self.monero_tip_height,
            "confirmations": self.confirmations,
            "anchor_root": self.anchor_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayEvidence {
    pub replay_set_id: String,
    pub claim_hash: String,
    pub first_seen_height: u64,
    pub attempted_height: u64,
    pub previous_claim_id: String,
    pub nullifier_root: String,
}

impl ReplayEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_set_id": self.replay_set_id,
            "claim_hash": self.claim_hash,
            "first_seen_height": self.first_seen_height,
            "attempted_height": self.attempted_height,
            "previous_claim_id": self.previous_claim_id,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn is_replay(&self) -> bool {
        !self.previous_claim_id.is_empty()
    }

    pub fn state_root(&self) -> String {
        record_root("replay_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityEvidence {
    pub reserve_id: String,
    pub available_piconero: u64,
    pub pending_exit_piconero: u64,
    pub reserve_floor_piconero: u64,
    pub reserve_root: String,
    pub queue_root: String,
}

impl LiquidityEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "available_piconero": self.available_piconero,
            "pending_exit_piconero": self.pending_exit_piconero,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "reserve_root": self.reserve_root,
            "queue_root": self.queue_root,
        })
    }

    pub fn projected_balance(&self) -> i128 {
        self.available_piconero as i128 - self.pending_exit_piconero as i128
    }

    pub fn state_root(&self) -> String {
        record_root("liquidity_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorityEvidence {
    pub authority_id: String,
    pub expected_epoch: u64,
    pub supplied_epoch: u64,
    pub expected_authority_root: String,
    pub supplied_authority_root: String,
    pub key_registry_root: String,
    pub signature_root: String,
}

impl PqAuthorityEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "expected_epoch": self.expected_epoch,
            "supplied_epoch": self.supplied_epoch,
            "expected_authority_root": self.expected_authority_root,
            "supplied_authority_root": self.supplied_authority_root,
            "key_registry_root": self.key_registry_root,
            "signature_root": self.signature_root,
        })
    }

    pub fn authority_matches(&self) -> bool {
        self.expected_epoch == self.supplied_epoch
            && self.expected_authority_root == self.supplied_authority_root
    }

    pub fn state_root(&self) -> String {
        record_root("pq_authority_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyEvidence {
    pub privacy_id: String,
    pub disclosed_bits: u64,
    pub budget_bits: u64,
    pub linkability_set_size: u64,
    pub metadata_root: String,
    pub note_commitment_root: String,
}

impl PrivacyEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_id": self.privacy_id,
            "disclosed_bits": self.disclosed_bits,
            "budget_bits": self.budget_bits,
            "linkability_set_size": self.linkability_set_size,
            "metadata_root": self.metadata_root,
            "note_commitment_root": self.note_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("privacy_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaim {
    pub claim_id: String,
    pub case_kind: AcceptanceCaseKind,
    pub account_tag: String,
    pub destination_tag: String,
    pub claim_amount_piconero: u64,
    pub fee_piconero: u64,
    pub l2_claim_height: u64,
    pub monero_claim_height: u64,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub release_request_root: String,
    pub wallet_recovery: WalletRecoveryEvidence,
    pub receipt: ReceiptEvidence,
    pub live_feed: LiveFeedEvidence,
    pub watchers: Vec<WatcherAttestation>,
    pub deposit: DepositEvidence,
    pub replay: ReplayEvidence,
    pub liquidity: LiquidityEvidence,
    pub pq_authority: PqAuthorityEvidence,
    pub privacy: PrivacyEvidence,
}

impl ExitClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "case_kind": self.case_kind.as_str(),
            "account_tag": self.account_tag,
            "destination_tag": self.destination_tag,
            "claim_amount_piconero": self.claim_amount_piconero,
            "fee_piconero": self.fee_piconero,
            "l2_claim_height": self.l2_claim_height,
            "monero_claim_height": self.monero_claim_height,
            "note_commitment_root": self.note_commitment_root,
            "nullifier_root": self.nullifier_root,
            "release_request_root": self.release_request_root,
            "wallet_recovery": self.wallet_recovery.public_record(),
            "receipt": self.receipt.public_record(),
            "live_feed": self.live_feed.public_record(),
            "watchers": self.watchers.iter().map(WatcherAttestation::public_record).collect::<Vec<_>>(),
            "deposit": self.deposit.public_record(),
            "replay": self.replay.public_record(),
            "liquidity": self.liquidity.public_record(),
            "pq_authority": self.pq_authority.public_record(),
            "privacy": self.privacy.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("exit_claim", &self.public_record())
    }

    pub fn watcher_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:claim-watchers"),
            &self
                .watchers
                .iter()
                .map(WatcherAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn evidence_roots(&self) -> BTreeMap<String, String> {
        let mut roots = BTreeMap::new();
        roots.insert(
            "wallet_recovery".to_string(),
            self.wallet_recovery.state_root(),
        );
        roots.insert("receipt".to_string(), self.receipt.state_root());
        roots.insert("live_feed".to_string(), self.live_feed.state_root());
        roots.insert("watchers".to_string(), self.watcher_root());
        roots.insert("deposit".to_string(), self.deposit.state_root());
        roots.insert("replay".to_string(), self.replay.state_root());
        roots.insert("liquidity".to_string(), self.liquidity.state_root());
        roots.insert("pq_authority".to_string(), self.pq_authority.state_root());
        roots.insert("privacy".to_string(), self.privacy.state_root());
        roots
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceDecision {
    pub claim_id: String,
    pub case_kind: AcceptanceCaseKind,
    pub status: AcceptanceStatus,
    pub fail_closed_reason: FailClosedReason,
    pub fail_closed: bool,
    pub deterministic_negative: bool,
    pub blocker_count: u64,
    pub stale_wallet_recovery: bool,
    pub bad_observed_receipt_root: bool,
    pub withheld_live_feed_root: bool,
    pub watcher_collusion: bool,
    pub reorg_sensitive_deposit_evidence: bool,
    pub replayed_claim: bool,
    pub liquidity_shortfall: bool,
    pub pq_authority_mismatch: bool,
    pub privacy_budget_breach: bool,
    pub evidence_root: String,
    pub blocker_root: String,
    pub decision_root: String,
    pub remediation: String,
}

impl AcceptanceDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "case_kind": self.case_kind.as_str(),
            "status": self.status.as_str(),
            "fail_closed_reason": self.fail_closed_reason.as_str(),
            "fail_closed": self.fail_closed,
            "deterministic_negative": self.deterministic_negative,
            "blocker_count": self.blocker_count,
            "stale_wallet_recovery": self.stale_wallet_recovery,
            "bad_observed_receipt_root": self.bad_observed_receipt_root,
            "withheld_live_feed_root": self.withheld_live_feed_root,
            "watcher_collusion": self.watcher_collusion,
            "reorg_sensitive_deposit_evidence": self.reorg_sensitive_deposit_evidence,
            "replayed_claim": self.replayed_claim,
            "liquidity_shortfall": self.liquidity_shortfall,
            "pq_authority_mismatch": self.pq_authority_mismatch,
            "privacy_budget_breach": self.privacy_budget_breach,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "decision_root": self.decision_root,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        self.decision_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceCounters {
    pub total_claims: u64,
    pub accepted: u64,
    pub deferred: u64,
    pub rejected: u64,
    pub deterministic_negative_cases: u64,
    pub fail_closed_cases: u64,
    pub stale_wallet_recovery: u64,
    pub bad_observed_receipt_root: u64,
    pub withheld_live_feed_root: u64,
    pub watcher_collusion: u64,
    pub reorg_sensitive_deposit_evidence: u64,
    pub replayed_claim: u64,
    pub liquidity_shortfall: u64,
    pub pq_authority_mismatch: u64,
    pub privacy_budget_breach: u64,
}

impl AcceptanceCounters {
    pub fn from_decisions(decisions: &[AcceptanceDecision]) -> Self {
        let mut counters = Self {
            total_claims: decisions.len() as u64,
            accepted: 0,
            deferred: 0,
            rejected: 0,
            deterministic_negative_cases: 0,
            fail_closed_cases: 0,
            stale_wallet_recovery: 0,
            bad_observed_receipt_root: 0,
            withheld_live_feed_root: 0,
            watcher_collusion: 0,
            reorg_sensitive_deposit_evidence: 0,
            replayed_claim: 0,
            liquidity_shortfall: 0,
            pq_authority_mismatch: 0,
            privacy_budget_breach: 0,
        };
        for decision in decisions {
            match decision.status {
                AcceptanceStatus::Accepted => counters.accepted += 1,
                AcceptanceStatus::Deferred => counters.deferred += 1,
                AcceptanceStatus::Rejected => counters.rejected += 1,
            }
            if decision.deterministic_negative {
                counters.deterministic_negative_cases += 1;
            }
            if decision.fail_closed {
                counters.fail_closed_cases += 1;
            }
            if decision.stale_wallet_recovery {
                counters.stale_wallet_recovery += 1;
            }
            if decision.bad_observed_receipt_root {
                counters.bad_observed_receipt_root += 1;
            }
            if decision.withheld_live_feed_root {
                counters.withheld_live_feed_root += 1;
            }
            if decision.watcher_collusion {
                counters.watcher_collusion += 1;
            }
            if decision.reorg_sensitive_deposit_evidence {
                counters.reorg_sensitive_deposit_evidence += 1;
            }
            if decision.replayed_claim {
                counters.replayed_claim += 1;
            }
            if decision.liquidity_shortfall {
                counters.liquidity_shortfall += 1;
            }
            if decision.pq_authority_mismatch {
                counters.pq_authority_mismatch += 1;
            }
            if decision.privacy_budget_breach {
                counters.privacy_budget_breach += 1;
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_claims": self.total_claims,
            "accepted": self.accepted,
            "deferred": self.deferred,
            "rejected": self.rejected,
            "deterministic_negative_cases": self.deterministic_negative_cases,
            "fail_closed_cases": self.fail_closed_cases,
            "stale_wallet_recovery": self.stale_wallet_recovery,
            "bad_observed_receipt_root": self.bad_observed_receipt_root,
            "withheld_live_feed_root": self.withheld_live_feed_root,
            "watcher_collusion": self.watcher_collusion,
            "reorg_sensitive_deposit_evidence": self.reorg_sensitive_deposit_evidence,
            "replayed_claim": self.replayed_claim,
            "liquidity_shortfall": self.liquidity_shortfall,
            "pq_authority_mismatch": self.pq_authority_mismatch,
            "privacy_budget_breach": self.privacy_budget_breach,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("acceptance_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeRoots {
    pub config_root: String,
    pub claim_root: String,
    pub decision_root: String,
    pub counter_root: String,
    pub case_index_root: String,
    pub state_root: String,
}

impl RuntimeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "claim_root": self.claim_root,
            "decision_root": self.decision_root,
            "counter_root": self.counter_root,
            "case_index_root": self.case_index_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:roots"),
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.claim_root),
                HashPart::Str(&self.decision_root),
                HashPart::Str(&self.counter_root),
                HashPart::Str(&self.case_index_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub acceptance_epoch: u64,
    pub claims: Vec<ExitClaim>,
    pub decisions: Vec<AcceptanceDecision>,
    pub counters: AcceptanceCounters,
    pub case_index: BTreeMap<String, String>,
    pub roots: RuntimeRoots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let claims = devnet_claims(&config);
        let decisions = evaluate_claims(&config, &claims);
        let counters = AcceptanceCounters::from_decisions(&decisions);
        let case_index = build_case_index(&decisions);
        let roots = build_roots(&config, &claims, &decisions, &counters, &case_index);
        Self {
            config,
            runtime_id: runtime_id(),
            l2_tip_height: DEFAULT_L2_TIP_HEIGHT,
            monero_tip_height: DEFAULT_MONERO_TIP_HEIGHT,
            acceptance_epoch: DEFAULT_ACCEPTANCE_EPOCH,
            claims,
            decisions,
            counters,
            case_index,
            roots,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_exit_acceptance_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "acceptance_suite": ACCEPTANCE_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "acceptance_epoch": self.acceptance_epoch,
            "config": self.config.public_record(),
            "claims": self.claims.iter().map(ExitClaim::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.iter().map(AcceptanceDecision::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "case_index": self.case_index,
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.l2_tip_height),
                HashPart::U64(self.monero_tip_height),
                HashPart::U64(self.acceptance_epoch),
                HashPart::Str(&self.roots.state_root),
            ],
            32,
        )
    }

    pub fn decision_for(&self, claim_id: &str) -> Option<&AcceptanceDecision> {
        self.decisions
            .iter()
            .find(|decision| decision.claim_id == claim_id)
    }

    pub fn acceptance_report(&self) -> Value {
        json!({
            "runtime_id": self.runtime_id,
            "state_root": self.state_root(),
            "fail_closed_cases": self.counters.fail_closed_cases,
            "deterministic_negative_cases": self.counters.deterministic_negative_cases,
            "case_index_root": self.roots.case_index_root,
            "decision_root": self.roots.decision_root,
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn evaluate_claims(config: &Config, claims: &[ExitClaim]) -> Vec<AcceptanceDecision> {
    claims
        .iter()
        .map(|claim| evaluate_claim(config, claim))
        .collect::<Vec<_>>()
}

pub fn evaluate_claim(config: &Config, claim: &ExitClaim) -> AcceptanceDecision {
    let stale_wallet_recovery =
        claim.wallet_recovery.age_blocks() > config.wallet_recovery_max_age_blocks;
    let bad_observed_receipt_root = !claim.receipt.roots_match();
    let withheld_live_feed_root =
        !claim.live_feed.supplied() || claim.live_feed.root_withheld_ms > config.live_feed_grace_ms;
    let watcher_collusion = has_watcher_collusion(config, &claim.watchers);
    let reorg_sensitive_deposit_evidence =
        claim.deposit.confirmations < config.monero_reorg_hold_blocks;
    let replayed_claim = claim.replay.is_replay();
    let liquidity_shortfall =
        claim.liquidity.projected_balance() < claim.liquidity.reserve_floor_piconero as i128;
    let pq_authority_mismatch = !claim.pq_authority.authority_matches();
    let privacy_budget_breach = claim.privacy.disclosed_bits > claim.privacy.budget_bits;
    let blocker_count = [
        stale_wallet_recovery,
        bad_observed_receipt_root,
        withheld_live_feed_root,
        watcher_collusion,
        reorg_sensitive_deposit_evidence,
        replayed_claim,
        liquidity_shortfall,
        pq_authority_mismatch,
        privacy_budget_breach,
    ]
    .iter()
    .filter(|flag| **flag)
    .count() as u64;
    let fail_closed_reason = primary_reason(
        stale_wallet_recovery,
        bad_observed_receipt_root,
        withheld_live_feed_root,
        watcher_collusion,
        reorg_sensitive_deposit_evidence,
        replayed_claim,
        liquidity_shortfall,
        pq_authority_mismatch,
        privacy_budget_breach,
    );
    let status = if blocker_count == 0 {
        AcceptanceStatus::Accepted
    } else if reorg_sensitive_deposit_evidence && blocker_count == 1 {
        AcceptanceStatus::Deferred
    } else {
        AcceptanceStatus::Rejected
    };
    let fail_closed = config.reject_on_any_blocker && blocker_count > 0;
    let evidence_root = evidence_root(claim);
    let blocker_root = blocker_root(
        claim,
        stale_wallet_recovery,
        bad_observed_receipt_root,
        withheld_live_feed_root,
        watcher_collusion,
        reorg_sensitive_deposit_evidence,
        replayed_claim,
        liquidity_shortfall,
        pq_authority_mismatch,
        privacy_budget_breach,
    );
    let decision_root = decision_root(
        claim,
        status,
        fail_closed_reason,
        fail_closed,
        blocker_count,
        &evidence_root,
        &blocker_root,
    );
    AcceptanceDecision {
        claim_id: claim.claim_id.clone(),
        case_kind: claim.case_kind,
        status,
        fail_closed_reason,
        fail_closed,
        deterministic_negative: blocker_count > 0,
        blocker_count,
        stale_wallet_recovery,
        bad_observed_receipt_root,
        withheld_live_feed_root,
        watcher_collusion,
        reorg_sensitive_deposit_evidence,
        replayed_claim,
        liquidity_shortfall,
        pq_authority_mismatch,
        privacy_budget_breach,
        evidence_root,
        blocker_root,
        decision_root,
        remediation: remediation_for(fail_closed_reason).to_string(),
    }
}

fn primary_reason(
    stale_wallet_recovery: bool,
    bad_observed_receipt_root: bool,
    withheld_live_feed_root: bool,
    watcher_collusion: bool,
    reorg_sensitive_deposit_evidence: bool,
    replayed_claim: bool,
    liquidity_shortfall: bool,
    pq_authority_mismatch: bool,
    privacy_budget_breach: bool,
) -> FailClosedReason {
    if stale_wallet_recovery {
        FailClosedReason::StaleRecoveryTranscript
    } else if bad_observed_receipt_root {
        FailClosedReason::ReceiptRootMismatch
    } else if withheld_live_feed_root {
        FailClosedReason::LiveFeedRootMissing
    } else if watcher_collusion {
        FailClosedReason::WatcherEquivocation
    } else if reorg_sensitive_deposit_evidence {
        FailClosedReason::DepositEvidenceBelowReorgHold
    } else if replayed_claim {
        FailClosedReason::ClaimReplayDetected
    } else if liquidity_shortfall {
        FailClosedReason::ReserveFloorViolated
    } else if pq_authority_mismatch {
        FailClosedReason::PqAuthorityEpochMismatch
    } else if privacy_budget_breach {
        FailClosedReason::PrivacyBudgetExceeded
    } else {
        FailClosedReason::None
    }
}

fn remediation_for(reason: FailClosedReason) -> &'static str {
    match reason {
        FailClosedReason::None => "release_claim_can_enter_canonical_exit_queue",
        FailClosedReason::StaleRecoveryTranscript => {
            "refresh_wallet_recovery_transcript_before_acceptance"
        }
        FailClosedReason::ReceiptRootMismatch => {
            "reject_until_observed_receipt_root_matches_canonical_batch"
        }
        FailClosedReason::LiveFeedRootMissing => "require_live_feed_root_before_claim_admission",
        FailClosedReason::WatcherEquivocation => {
            "slash_or_exclude_equivocating_watchers_and_rebuild_quorum"
        }
        FailClosedReason::DepositEvidenceBelowReorgHold => {
            "defer_until_monero_reorg_hold_is_satisfied"
        }
        FailClosedReason::ClaimReplayDetected => {
            "reject_duplicate_nullifier_and_preserve_first_seen_claim"
        }
        FailClosedReason::ReserveFloorViolated => {
            "queue_after_reserve_replenishment_or_reduce_release_amount"
        }
        FailClosedReason::PqAuthorityEpochMismatch => {
            "refresh_pq_authority_signature_for_expected_epoch"
        }
        FailClosedReason::PrivacyBudgetExceeded => {
            "reject_claim_and_request_lower_metadata_disclosure"
        }
    }
}

fn has_watcher_collusion(config: &Config, watchers: &[WatcherAttestation]) -> bool {
    let mut by_key: BTreeMap<String, String> = BTreeMap::new();
    let mut equivocations = 0_u64;
    for watcher in watchers {
        if let Some(previous) = by_key.get(&watcher.public_key_tag) {
            if previous != &watcher.signed_view_root {
                equivocations += 1;
            }
        } else {
            by_key.insert(
                watcher.public_key_tag.clone(),
                watcher.signed_view_root.clone(),
            );
        }
    }
    equivocations > config.watcher_fault_limit
        || by_key.len() as u64 >= config.watcher_quorum && equivocations > 0
}

fn build_case_index(decisions: &[AcceptanceDecision]) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for decision in decisions {
        index.insert(
            decision.case_kind.as_str().to_string(),
            decision.decision_root.clone(),
        );
    }
    index
}

fn build_roots(
    config: &Config,
    claims: &[ExitClaim],
    decisions: &[AcceptanceDecision],
    counters: &AcceptanceCounters,
    case_index: &BTreeMap<String, String>,
) -> RuntimeRoots {
    let claim_root = merkle_root(
        &format!("{DOMAIN}:claims"),
        &claims
            .iter()
            .map(ExitClaim::public_record)
            .collect::<Vec<_>>(),
    );
    let decision_root = merkle_root(
        &format!("{DOMAIN}:decisions"),
        &decisions
            .iter()
            .map(AcceptanceDecision::public_record)
            .collect::<Vec<_>>(),
    );
    let case_index_root = record_root("case_index", &json!(case_index));
    let mut roots = RuntimeRoots {
        config_root: config.state_root(),
        claim_root,
        decision_root,
        counter_root: counters.state_root(),
        case_index_root,
        state_root: String::new(),
    };
    roots.state_root = roots.compute_state_root();
    roots
}

fn evidence_root(claim: &ExitClaim) -> String {
    record_root("evidence_bundle", &json!(claim.evidence_roots()))
}

fn blocker_root(
    claim: &ExitClaim,
    stale_wallet_recovery: bool,
    bad_observed_receipt_root: bool,
    withheld_live_feed_root: bool,
    watcher_collusion: bool,
    reorg_sensitive_deposit_evidence: bool,
    replayed_claim: bool,
    liquidity_shortfall: bool,
    pq_authority_mismatch: bool,
    privacy_budget_breach: bool,
) -> String {
    record_root(
        "acceptance_blockers",
        &json!({
            "claim_id": claim.claim_id,
            "case_kind": claim.case_kind.as_str(),
            "stale_wallet_recovery": stale_wallet_recovery,
            "bad_observed_receipt_root": bad_observed_receipt_root,
            "withheld_live_feed_root": withheld_live_feed_root,
            "watcher_collusion": watcher_collusion,
            "reorg_sensitive_deposit_evidence": reorg_sensitive_deposit_evidence,
            "replayed_claim": replayed_claim,
            "liquidity_shortfall": liquidity_shortfall,
            "pq_authority_mismatch": pq_authority_mismatch,
            "privacy_budget_breach": privacy_budget_breach,
        }),
    )
}

fn decision_root(
    claim: &ExitClaim,
    status: AcceptanceStatus,
    fail_closed_reason: FailClosedReason,
    fail_closed: bool,
    blocker_count: u64,
    evidence_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:decision"),
        &[
            HashPart::Str(&claim.claim_id),
            HashPart::Str(claim.case_kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(fail_closed_reason.as_str()),
            HashPart::U64(if fail_closed { 1 } else { 0 }),
            HashPart::U64(blocker_count),
            HashPart::Str(evidence_root),
            HashPart::Str(blocker_root),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&format!("{DOMAIN}:{label}"), &[HashPart::Json(record)], 32)
}

fn runtime_id() -> String {
    domain_hash(
        &format!("{DOMAIN}:runtime-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
            HashPart::Str(ACCEPTANCE_SUITE),
        ],
        16,
    )
}

fn devnet_claims(config: &Config) -> Vec<ExitClaim> {
    vec![
        devnet_claim(config, AcceptanceCaseKind::StaleWalletRecovery, 0),
        devnet_claim(config, AcceptanceCaseKind::BadObservedReceiptRoot, 1),
        devnet_claim(config, AcceptanceCaseKind::WithheldLiveFeedRoot, 2),
        devnet_claim(config, AcceptanceCaseKind::WatcherCollusion, 3),
        devnet_claim(config, AcceptanceCaseKind::ReorgSensitiveDepositEvidence, 4),
        devnet_claim(config, AcceptanceCaseKind::ReplayedClaim, 5),
        devnet_claim(config, AcceptanceCaseKind::LiquidityShortfall, 6),
        devnet_claim(config, AcceptanceCaseKind::PqAuthorityMismatch, 7),
        devnet_claim(config, AcceptanceCaseKind::PrivacyBudgetBreach, 8),
    ]
}

fn devnet_claim(config: &Config, case_kind: AcceptanceCaseKind, ordinal: u64) -> ExitClaim {
    let claim_id = format!("adversarial-exit-claim-{ordinal:02}");
    let base_root = fixture_root("claim-base", &claim_id, ordinal);
    let expected_receipt_root = fixture_root("receipt-root", &claim_id, ordinal);
    let expected_live_root = fixture_root("live-root", &claim_id, ordinal);
    let expected_authority_root = fixture_root("pq-authority-root", &claim_id, ordinal);
    let mut wallet_recovery = WalletRecoveryEvidence {
        recovery_id: format!("recovery-{ordinal:02}"),
        wallet_view_tag: format!("wallet-view-tag-{ordinal:02}"),
        transcript_root: fixture_root("wallet-transcript", &claim_id, ordinal),
        recovery_height: DEFAULT_L2_TIP_HEIGHT - 16,
        observed_l2_height: DEFAULT_L2_TIP_HEIGHT,
        signer_epoch: config.pq_authority_epoch,
        recovery_nonce: 10_000 + ordinal,
    };
    let mut receipt = ReceiptEvidence {
        receipt_id: format!("receipt-{ordinal:02}"),
        claimed_receipt_root: expected_receipt_root.clone(),
        observed_receipt_root: expected_receipt_root.clone(),
        receipt_leaf_root: fixture_root("receipt-leaves", &claim_id, ordinal),
        receipt_count: 4 + ordinal,
        observed_batch_height: DEFAULT_L2_TIP_HEIGHT - config.l2_finality_lag_blocks,
    };
    let mut live_feed = LiveFeedEvidence {
        feed_id: format!("live-feed-{ordinal:02}"),
        expected_live_root: expected_live_root.clone(),
        supplied_live_root: expected_live_root,
        root_withheld_ms: 4_000,
        adapter_sequence: 90_000 + ordinal,
        feed_height: DEFAULT_L2_TIP_HEIGHT,
    };
    let mut watchers = honest_watchers(&claim_id, ordinal);
    let mut deposit = DepositEvidence {
        deposit_id: format!("deposit-{ordinal:02}"),
        monero_txid_root: fixture_root("monero-txid", &claim_id, ordinal),
        lock_output_root: fixture_root("lock-output", &claim_id, ordinal),
        deposit_height: DEFAULT_MONERO_TIP_HEIGHT - 80,
        monero_tip_height: DEFAULT_MONERO_TIP_HEIGHT,
        confirmations: 80,
        anchor_root: fixture_root("monero-anchor", &claim_id, ordinal),
    };
    let mut replay = ReplayEvidence {
        replay_set_id: format!("replay-set-{ordinal:02}"),
        claim_hash: fixture_root("claim-hash", &claim_id, ordinal),
        first_seen_height: DEFAULT_L2_TIP_HEIGHT - 1,
        attempted_height: DEFAULT_L2_TIP_HEIGHT,
        previous_claim_id: String::new(),
        nullifier_root: fixture_root("nullifier", &claim_id, ordinal),
    };
    let mut liquidity = LiquidityEvidence {
        reserve_id: format!("reserve-{ordinal:02}"),
        available_piconero: config.reserve_floor_piconero + 5_000_000_000_000,
        pending_exit_piconero: 1_000_000_000_000,
        reserve_floor_piconero: config.reserve_floor_piconero,
        reserve_root: fixture_root("reserve", &claim_id, ordinal),
        queue_root: fixture_root("liquidity-queue", &claim_id, ordinal),
    };
    let mut pq_authority = PqAuthorityEvidence {
        authority_id: format!("pq-authority-{ordinal:02}"),
        expected_epoch: config.pq_authority_epoch,
        supplied_epoch: config.pq_authority_epoch,
        expected_authority_root: expected_authority_root.clone(),
        supplied_authority_root: expected_authority_root,
        key_registry_root: fixture_root("pq-key-registry", &claim_id, ordinal),
        signature_root: fixture_root("pq-signature", &claim_id, ordinal),
    };
    let mut privacy = PrivacyEvidence {
        privacy_id: format!("privacy-{ordinal:02}"),
        disclosed_bits: 3,
        budget_bits: config.privacy_budget_bits,
        linkability_set_size: 4_096,
        metadata_root: fixture_root("metadata", &claim_id, ordinal),
        note_commitment_root: fixture_root("note-privacy", &claim_id, ordinal),
    };

    match case_kind {
        AcceptanceCaseKind::StaleWalletRecovery => {
            wallet_recovery.recovery_height =
                DEFAULT_L2_TIP_HEIGHT - config.wallet_recovery_max_age_blocks - 9;
        }
        AcceptanceCaseKind::BadObservedReceiptRoot => {
            receipt.observed_receipt_root =
                fixture_root("mutated-receipt-root", &claim_id, ordinal);
        }
        AcceptanceCaseKind::WithheldLiveFeedRoot => {
            live_feed.supplied_live_root = String::new();
            live_feed.root_withheld_ms = config.live_feed_grace_ms + 7_500;
        }
        AcceptanceCaseKind::WatcherCollusion => {
            watchers = colluding_watchers(&claim_id, ordinal);
        }
        AcceptanceCaseKind::ReorgSensitiveDepositEvidence => {
            deposit.deposit_height = DEFAULT_MONERO_TIP_HEIGHT - 3;
            deposit.confirmations = 3;
        }
        AcceptanceCaseKind::ReplayedClaim => {
            replay.first_seen_height = DEFAULT_L2_TIP_HEIGHT - 128;
            replay.previous_claim_id = "adversarial-exit-claim-first-seen-05".to_string();
        }
        AcceptanceCaseKind::LiquidityShortfall => {
            liquidity.available_piconero = config.reserve_floor_piconero + 500_000_000_000;
            liquidity.pending_exit_piconero = 2_000_000_000_000;
        }
        AcceptanceCaseKind::PqAuthorityMismatch => {
            pq_authority.supplied_epoch = config.pq_authority_epoch + 1;
            pq_authority.supplied_authority_root =
                fixture_root("foreign-pq-authority-root", &claim_id, ordinal);
        }
        AcceptanceCaseKind::PrivacyBudgetBreach => {
            privacy.disclosed_bits = config.privacy_budget_bits + 5;
            privacy.linkability_set_size = 64;
        }
    }

    ExitClaim {
        claim_id,
        case_kind,
        account_tag: format!("account-tag-{ordinal:02}"),
        destination_tag: format!("monero-destination-tag-{ordinal:02}"),
        claim_amount_piconero: 1_250_000_000_000 + ordinal * 10_000_000_000,
        fee_piconero: 20_000_000 + ordinal * 1_000,
        l2_claim_height: DEFAULT_L2_TIP_HEIGHT - ordinal,
        monero_claim_height: DEFAULT_MONERO_TIP_HEIGHT - ordinal,
        note_commitment_root: base_root,
        nullifier_root: replay.nullifier_root.clone(),
        release_request_root: fixture_root(
            "release-request",
            &format!("release-{ordinal:02}"),
            ordinal,
        ),
        wallet_recovery,
        receipt,
        live_feed,
        watchers,
        deposit,
        replay,
        liquidity,
        pq_authority,
        privacy,
    }
}

fn honest_watchers(claim_id: &str, ordinal: u64) -> Vec<WatcherAttestation> {
    (0..5)
        .map(|watcher| WatcherAttestation {
            watcher_id: format!("watcher-{watcher:02}"),
            public_key_tag: format!("watcher-key-{watcher:02}"),
            signed_view_root: fixture_root("watcher-view", claim_id, ordinal),
            release_bitmap: 0b11111,
            observed_height: DEFAULT_L2_TIP_HEIGHT,
            signature_root: fixture_root("watcher-signature", claim_id, ordinal + watcher),
        })
        .collect::<Vec<_>>()
}

fn colluding_watchers(claim_id: &str, ordinal: u64) -> Vec<WatcherAttestation> {
    let mut watchers = honest_watchers(claim_id, ordinal);
    if let Some(first) = watchers.get_mut(1) {
        first.public_key_tag = "watcher-key-equivocation-a".to_string();
        first.signed_view_root = fixture_root("colluding-view-a", claim_id, ordinal);
    }
    if let Some(second) = watchers.get_mut(3) {
        second.public_key_tag = "watcher-key-equivocation-a".to_string();
        second.signed_view_root = fixture_root("colluding-view-b", claim_id, ordinal);
        second.release_bitmap = 0b00111;
    }
    watchers
}

fn fixture_root(label: &str, seed: &str, ordinal: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:fixture:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
            HashPart::U64(ordinal),
        ],
        32,
    )
}
