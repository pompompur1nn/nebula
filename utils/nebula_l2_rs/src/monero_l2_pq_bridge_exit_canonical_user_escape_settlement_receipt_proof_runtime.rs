use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptProofRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-settlement-receipt-proof-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_PROOF_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROOF_SUITE: &str =
    "canonical-user-escape-settlement-receipt-continuity-proof-fail-closed-v1";
pub const DEFAULT_CURRENT_L2_HEIGHT: u64 = 9_216;
pub const DEFAULT_CURRENT_MONERO_HEIGHT: u64 = 3_521_040;
pub const DEFAULT_ESCAPE_SEQUENCE: u64 = 42;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_DISPUTE_OPENED_AT_HEIGHT: u64 = 8_400;
pub const DEFAULT_LOW_COST_FEE_BOUND_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MIN_WATCHER_ATTESTATIONS: u64 = 5;
pub const DEFAULT_MIN_SEQUENCER_RECEIPTS: u64 = 1;
pub const DEFAULT_MIN_PRIVATE_ACTION_RECEIPTS: u64 = 1;
pub const DEFAULT_MAX_FAIL_CLOSED_GAPS: usize = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityField {
    SettlementReceiptRoot,
    PrivateActionReceiptRoot,
    WithdrawalClaimRoot,
    ChallengeWindowRoot,
    DisputeClock,
    SequencerReceiptRoot,
    WatcherAttestationRoot,
    FeeLowCostBound,
}

impl ContinuityField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementReceiptRoot => "settlement_receipt_root",
            Self::PrivateActionReceiptRoot => "private_action_receipt_root",
            Self::WithdrawalClaimRoot => "withdrawal_claim_root",
            Self::ChallengeWindowRoot => "challenge_window_root",
            Self::DisputeClock => "dispute_clock",
            Self::SequencerReceiptRoot => "sequencer_receipt_root",
            Self::WatcherAttestationRoot => "watcher_attestation_root",
            Self::FeeLowCostBound => "fee_low_cost_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapSeverity {
    None,
    Hold,
    Reject,
}

impl GapSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Hold | Self::Reject)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub proof_suite: String,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub dispute_window_blocks: u64,
    pub dispute_opened_at_height: u64,
    pub low_cost_fee_bound_atomic: u128,
    pub min_watcher_attestations: u64,
    pub min_sequencer_receipts: u64,
    pub min_private_action_receipts: u64,
    pub max_fail_closed_gaps: usize,
    pub require_all_roots_bound: bool,
    pub require_dispute_window_elapsed: bool,
    pub fail_closed_on_any_gap: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            proof_suite: PROOF_SUITE.to_string(),
            current_l2_height: DEFAULT_CURRENT_L2_HEIGHT,
            current_monero_height: DEFAULT_CURRENT_MONERO_HEIGHT,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            dispute_opened_at_height: DEFAULT_DISPUTE_OPENED_AT_HEIGHT,
            low_cost_fee_bound_atomic: DEFAULT_LOW_COST_FEE_BOUND_ATOMIC,
            min_watcher_attestations: DEFAULT_MIN_WATCHER_ATTESTATIONS,
            min_sequencer_receipts: DEFAULT_MIN_SEQUENCER_RECEIPTS,
            min_private_action_receipts: DEFAULT_MIN_PRIVATE_ACTION_RECEIPTS,
            max_fail_closed_gaps: DEFAULT_MAX_FAIL_CLOSED_GAPS,
            require_all_roots_bound: true,
            require_dispute_window_elapsed: true,
            fail_closed_on_any_gap: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "proof_suite": self.proof_suite,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "dispute_opened_at_height": self.dispute_opened_at_height,
            "low_cost_fee_bound_atomic": self.low_cost_fee_bound_atomic.to_string(),
            "min_watcher_attestations": self.min_watcher_attestations,
            "min_sequencer_receipts": self.min_sequencer_receipts,
            "min_private_action_receipts": self.min_private_action_receipts,
            "max_fail_closed_gaps": self.max_fail_closed_gaps,
            "require_all_roots_bound": self.require_all_roots_bound,
            "require_dispute_window_elapsed": self.require_dispute_window_elapsed,
            "fail_closed_on_any_gap": self.fail_closed_on_any_gap,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContinuityRoot {
    pub field: ContinuityField,
    pub root: String,
    pub source_receipt_id: String,
    pub sequence: u64,
}

impl ContinuityRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "field": self.field.as_str(),
            "root": self.root,
            "source_receipt_id": self.source_receipt_id,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DisputeClock {
    pub opened_at_l2_height: u64,
    pub window_blocks: u64,
    pub current_l2_height: u64,
}

impl DisputeClock {
    pub fn elapsed_blocks(&self) -> u64 {
        self.current_l2_height
            .saturating_sub(self.opened_at_l2_height)
    }

    pub fn is_elapsed(&self) -> bool {
        self.elapsed_blocks() >= self.window_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "opened_at_l2_height": self.opened_at_l2_height,
            "window_blocks": self.window_blocks,
            "current_l2_height": self.current_l2_height,
            "elapsed_blocks": self.elapsed_blocks(),
            "elapsed": self.is_elapsed(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedGap {
    pub gap_id: String,
    pub field: ContinuityField,
    pub expected_root: String,
    pub observed_root: String,
    pub severity: GapSeverity,
}

impl FailClosedGap {
    pub fn public_record(&self) -> Value {
        json!({
            "gap_id": self.gap_id,
            "field": self.field.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "severity": self.severity.as_str(),
            "blocks_release": self.severity.blocks_release(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserEscapePackage {
    pub escape_package_id: String,
    pub user_commitment: String,
    pub settlement_receipt_root: String,
    pub private_action_receipt_root: String,
    pub withdrawal_claim_root: String,
    pub challenge_window_root: String,
    pub dispute_clock: DisputeClock,
    pub sequencer_receipt_root: String,
    pub watcher_attestation_root: String,
    pub fee_low_cost_bound_atomic: u128,
    pub watcher_attestation_count: u64,
    pub sequencer_receipt_count: u64,
    pub private_action_receipt_count: u64,
    pub continuity_roots: Vec<ContinuityRoot>,
    pub fail_closed_gaps: Vec<FailClosedGap>,
}

impl UserEscapePackage {
    pub fn devnet(config: &Config) -> Self {
        let escape_package_id = receipt_hash("escape-package", DEFAULT_ESCAPE_SEQUENCE);
        let user_commitment = receipt_hash("user-commitment", DEFAULT_ESCAPE_SEQUENCE);
        let settlement_receipt_root =
            receipt_hash("settlement-receipt-root", DEFAULT_ESCAPE_SEQUENCE);
        let private_action_receipt_root =
            receipt_hash("private-action-receipt-root", DEFAULT_ESCAPE_SEQUENCE);
        let withdrawal_claim_root = receipt_hash("withdrawal-claim-root", DEFAULT_ESCAPE_SEQUENCE);
        let challenge_window_root = receipt_hash("challenge-window-root", DEFAULT_ESCAPE_SEQUENCE);
        let sequencer_receipt_root =
            receipt_hash("sequencer-receipt-root", DEFAULT_ESCAPE_SEQUENCE);
        let watcher_attestation_root =
            receipt_hash("watcher-attestation-root", DEFAULT_ESCAPE_SEQUENCE);
        let continuity_roots = vec![
            continuity_root(
                ContinuityField::SettlementReceiptRoot,
                &settlement_receipt_root,
                DEFAULT_ESCAPE_SEQUENCE,
            ),
            continuity_root(
                ContinuityField::PrivateActionReceiptRoot,
                &private_action_receipt_root,
                DEFAULT_ESCAPE_SEQUENCE,
            ),
            continuity_root(
                ContinuityField::WithdrawalClaimRoot,
                &withdrawal_claim_root,
                DEFAULT_ESCAPE_SEQUENCE,
            ),
            continuity_root(
                ContinuityField::ChallengeWindowRoot,
                &challenge_window_root,
                DEFAULT_ESCAPE_SEQUENCE,
            ),
            continuity_root(
                ContinuityField::SequencerReceiptRoot,
                &sequencer_receipt_root,
                DEFAULT_ESCAPE_SEQUENCE,
            ),
            continuity_root(
                ContinuityField::WatcherAttestationRoot,
                &watcher_attestation_root,
                DEFAULT_ESCAPE_SEQUENCE,
            ),
            continuity_root(
                ContinuityField::FeeLowCostBound,
                &receipt_hash("fee-low-cost-bound", DEFAULT_ESCAPE_SEQUENCE),
                DEFAULT_ESCAPE_SEQUENCE,
            ),
        ];

        Self {
            escape_package_id,
            user_commitment,
            settlement_receipt_root,
            private_action_receipt_root,
            withdrawal_claim_root,
            challenge_window_root,
            dispute_clock: DisputeClock {
                opened_at_l2_height: config.dispute_opened_at_height,
                window_blocks: config.dispute_window_blocks,
                current_l2_height: config.current_l2_height,
            },
            sequencer_receipt_root,
            watcher_attestation_root,
            fee_low_cost_bound_atomic: config.low_cost_fee_bound_atomic,
            watcher_attestation_count: config.min_watcher_attestations,
            sequencer_receipt_count: config.min_sequencer_receipts,
            private_action_receipt_count: config.min_private_action_receipts,
            continuity_roots,
            fail_closed_gaps: Vec::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        let continuity_roots = self
            .continuity_roots
            .iter()
            .map(ContinuityRoot::public_record)
            .collect::<Vec<_>>();
        let fail_closed_gaps = self
            .fail_closed_gaps
            .iter()
            .map(FailClosedGap::public_record)
            .collect::<Vec<_>>();

        json!({
            "escape_package_id": self.escape_package_id,
            "user_commitment": self.user_commitment,
            "settlement_receipt_root": self.settlement_receipt_root,
            "private_action_receipt_root": self.private_action_receipt_root,
            "withdrawal_claim_root": self.withdrawal_claim_root,
            "challenge_window_root": self.challenge_window_root,
            "dispute_clock": self.dispute_clock.public_record(),
            "sequencer_receipt_root": self.sequencer_receipt_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "fee_low_cost_bound_atomic": self.fee_low_cost_bound_atomic.to_string(),
            "watcher_attestation_count": self.watcher_attestation_count,
            "sequencer_receipt_count": self.sequencer_receipt_count,
            "private_action_receipt_count": self.private_action_receipt_count,
            "continuity_roots": continuity_roots,
            "continuity_root": merkle_root(
                "USER-ESCAPE-SETTLEMENT-RECEIPT-CONTINUITY",
                &continuity_roots,
            ),
            "fail_closed_gaps": fail_closed_gaps,
            "fail_closed_gap_root": merkle_root(
                "USER-ESCAPE-SETTLEMENT-RECEIPT-FAIL-CLOSED-GAPS",
                &fail_closed_gaps,
            ),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub escape_package: UserEscapePackage,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let escape_package = UserEscapePackage::devnet(&config);
        Self {
            config,
            escape_package,
        }
    }

    pub fn fail_closed_gap_count(&self) -> usize {
        self.escape_package
            .fail_closed_gaps
            .iter()
            .filter(|gap| gap.severity.blocks_release())
            .count()
    }

    pub fn proves_receipt_continuity(&self) -> bool {
        let package = &self.escape_package;
        let roots_bound = !package.settlement_receipt_root.is_empty()
            && !package.private_action_receipt_root.is_empty()
            && !package.withdrawal_claim_root.is_empty()
            && !package.challenge_window_root.is_empty()
            && !package.sequencer_receipt_root.is_empty()
            && !package.watcher_attestation_root.is_empty();
        let dispute_ready =
            !self.config.require_dispute_window_elapsed || package.dispute_clock.is_elapsed();
        let receipt_counts_ready = package.watcher_attestation_count
            >= self.config.min_watcher_attestations
            && package.sequencer_receipt_count >= self.config.min_sequencer_receipts
            && package.private_action_receipt_count >= self.config.min_private_action_receipts;
        let fee_ready = package.fee_low_cost_bound_atomic <= self.config.low_cost_fee_bound_atomic;
        let gap_count = self.fail_closed_gap_count();
        let gaps_ready = gap_count <= self.config.max_fail_closed_gaps
            && !(self.config.fail_closed_on_any_gap && gap_count > 0);

        (!self.config.require_all_roots_bound || roots_bound)
            && dispute_ready
            && receipt_counts_ready
            && fee_ready
            && gaps_ready
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "escape_package": self.escape_package.public_record(),
            "fail_closed_gap_count": self.fail_closed_gap_count(),
            "proves_settlement_receipt_continuity": self.proves_receipt_continuity(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-PROOF-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
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

fn continuity_root(field: ContinuityField, root: &str, sequence: u64) -> ContinuityRoot {
    ContinuityRoot {
        field,
        root: root.to_string(),
        source_receipt_id: receipt_hash(field.as_str(), sequence),
        sequence,
    }
}

fn receipt_hash(label: &str, sequence: u64) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-PROOF-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}
