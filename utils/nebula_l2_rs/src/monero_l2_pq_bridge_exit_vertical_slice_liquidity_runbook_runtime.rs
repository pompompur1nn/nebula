use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceLiquidityRunbookRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_LIQUIDITY_RUNBOOK_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-vertical-slice-liquidity-runbook-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_LIQUIDITY_RUNBOOK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_SUITE: &str =
    "monero-private-l2-bridge-exit-liquidity-exhaustion-reserve-recovery-v1";
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MIN_BACKSTOP_COVERAGE_BPS: u64 = 2_500;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 35;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const DEFAULT_AUCTION_OPEN_BLOCKS: u64 = 12;
pub const DEFAULT_ESCAPE_WINDOW_BLOCKS: u64 = 240;
pub const DEFAULT_MAX_REPORTS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookPhase {
    IntakeFreeze,
    PartialSettlement,
    BackstopActivation,
    AuctionFallback,
    ReserveRecovery,
    UserEscape,
}

impl RunbookPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntakeFreeze => "intake_freeze",
            Self::PartialSettlement => "partial_settlement",
            Self::BackstopActivation => "backstop_activation",
            Self::AuctionFallback => "auction_fallback",
            Self::ReserveRecovery => "reserve_recovery",
            Self::UserEscape => "user_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimPriority {
    UserEscape,
    MaturedExit,
    LiquidityProviderRefund,
    BackstopReimbursement,
    ProtocolTreasuryRecovery,
}

impl ClaimPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserEscape => "user_escape",
            Self::MaturedExit => "matured_exit",
            Self::LiquidityProviderRefund => "liquidity_provider_refund",
            Self::BackstopReimbursement => "backstop_reimbursement",
            Self::ProtocolTreasuryRecovery => "protocol_treasury_recovery",
        }
    }

    pub fn rank(self) -> u64 {
        match self {
            Self::UserEscape => 0,
            Self::MaturedExit => 1,
            Self::LiquidityProviderRefund => 2,
            Self::BackstopReimbursement => 3,
            Self::ProtocolTreasuryRecovery => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Weak,
    CommitteeAttested,
    ZkReserveProven,
    Finalized,
}

impl EvidenceStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::CommitteeAttested => "committee_attested",
            Self::ZkReserveProven => "zk_reserve_proven",
            Self::Finalized => "finalized",
        }
    }

    pub fn production_blocking(self) -> bool {
        matches!(self, Self::Weak | Self::CommitteeAttested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookStatus {
    Proven,
    Watch,
    Blocked,
}

impl RunbookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_suite: String,
    pub min_reserve_coverage_bps: u64,
    pub min_backstop_coverage_bps: u64,
    pub low_fee_cap_bps: u64,
    pub min_privacy_set_size: u64,
    pub auction_open_blocks: u64,
    pub escape_window_blocks: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_suite: RUNBOOK_SUITE.to_string(),
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_backstop_coverage_bps: DEFAULT_MIN_BACKSTOP_COVERAGE_BPS,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            auction_open_blocks: DEFAULT_AUCTION_OPEN_BLOCKS,
            escape_window_blocks: DEFAULT_ESCAPE_WINDOW_BLOCKS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "runbook_suite": self.runbook_suite,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_backstop_coverage_bps": self.min_backstop_coverage_bps,
            "low_fee_cap_bps": self.low_fee_cap_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "auction_open_blocks": self.auction_open_blocks,
            "escape_window_blocks": self.escape_window_blocks,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityEvidence {
    pub evidence_id: String,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub range_proof_root: String,
    pub nullifier_set_root: String,
    pub privacy_set_size: u64,
    pub reserve_coverage_bps: u64,
    pub strength: EvidenceStrength,
    pub hides_account_graph: bool,
    pub production_blocker: bool,
    pub evidence_root: String,
}

impl LiquidityEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reserve_commitment_root: impl Into<String>,
        liability_commitment_root: impl Into<String>,
        range_proof_root: impl Into<String>,
        nullifier_set_root: impl Into<String>,
        privacy_set_size: u64,
        reserve_coverage_bps: u64,
        strength: EvidenceStrength,
        hides_account_graph: bool,
    ) -> Self {
        let reserve_commitment_root = reserve_commitment_root.into();
        let liability_commitment_root = liability_commitment_root.into();
        let range_proof_root = range_proof_root.into();
        let nullifier_set_root = nullifier_set_root.into();
        let evidence_id = liquidity_id(
            "evidence",
            &reserve_commitment_root,
            &liability_commitment_root,
            privacy_set_size,
        );
        let production_blocker = strength.production_blocking() || !hides_account_graph;
        let evidence_root = domain_hash(
            "MONERO-L2-LIQUIDITY-EVIDENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence_id),
                HashPart::Str(&reserve_commitment_root),
                HashPart::Str(&liability_commitment_root),
                HashPart::Str(&range_proof_root),
                HashPart::Str(&nullifier_set_root),
                HashPart::Int(privacy_set_size as i128),
                HashPart::Int(reserve_coverage_bps as i128),
                HashPart::Str(strength.as_str()),
                HashPart::Str(if hides_account_graph {
                    "hidden"
                } else {
                    "exposed"
                }),
            ],
            32,
        );
        Self {
            evidence_id,
            reserve_commitment_root,
            liability_commitment_root,
            range_proof_root,
            nullifier_set_root,
            privacy_set_size,
            reserve_coverage_bps,
            strength,
            hides_account_graph,
            production_blocker,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liability_commitment_root": self.liability_commitment_root,
            "range_proof_root": self.range_proof_root,
            "nullifier_set_root": self.nullifier_set_root,
            "privacy_set_size": self.privacy_set_size,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "strength": self.strength.as_str(),
            "hides_account_graph": self.hides_account_graph,
            "production_blocker": self.production_blocker,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementStep {
    pub step_id: String,
    pub claim_commitment: String,
    pub priority: ClaimPriority,
    pub requested_amount: u64,
    pub settled_amount: u64,
    pub deferred_amount: u64,
    pub fee_bps: u64,
    pub ordering_index: u64,
    pub preserves_escape: bool,
    pub low_fee_cap_enforced: bool,
    pub step_root: String,
}

impl SettlementStep {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim_commitment: impl Into<String>,
        priority: ClaimPriority,
        requested_amount: u64,
        settled_amount: u64,
        fee_bps: u64,
        ordering_index: u64,
        preserves_escape: bool,
        low_fee_cap_bps: u64,
    ) -> Self {
        let claim_commitment = claim_commitment.into();
        let deferred_amount = requested_amount.saturating_sub(settled_amount);
        let low_fee_cap_enforced = fee_bps <= low_fee_cap_bps;
        let step_id = liquidity_id(
            "settlement",
            &claim_commitment,
            priority.as_str(),
            ordering_index,
        );
        let step_root = domain_hash(
            "MONERO-L2-LIQUIDITY-SETTLEMENT-STEP",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&step_id),
                HashPart::Str(&claim_commitment),
                HashPart::Str(priority.as_str()),
                HashPart::Int(priority.rank() as i128),
                HashPart::Int(requested_amount as i128),
                HashPart::Int(settled_amount as i128),
                HashPart::Int(deferred_amount as i128),
                HashPart::Int(fee_bps as i128),
                HashPart::Int(ordering_index as i128),
                HashPart::Str(if preserves_escape {
                    "escape-preserved"
                } else {
                    "escape-risk"
                }),
                HashPart::Str(if low_fee_cap_enforced {
                    "fee-capped"
                } else {
                    "fee-cap-breach"
                }),
            ],
            32,
        );
        Self {
            step_id,
            claim_commitment,
            priority,
            requested_amount,
            settled_amount,
            deferred_amount,
            fee_bps,
            ordering_index,
            preserves_escape,
            low_fee_cap_enforced,
            step_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "claim_commitment": self.claim_commitment,
            "priority": self.priority.as_str(),
            "requested_amount": self.requested_amount,
            "settled_amount": self.settled_amount,
            "deferred_amount": self.deferred_amount,
            "fee_bps": self.fee_bps,
            "ordering_index": self.ordering_index,
            "preserves_escape": self.preserves_escape,
            "low_fee_cap_enforced": self.low_fee_cap_enforced,
            "step_root": self.step_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackstopActivation {
    pub activation_id: String,
    pub sponsor_commitment: String,
    pub reserve_gap_amount: u64,
    pub committed_amount: u64,
    pub coverage_bps: u64,
    pub activation_height: u64,
    pub reimbursement_priority: ClaimPriority,
    pub activated: bool,
    pub activation_root: String,
}

impl BackstopActivation {
    pub fn new(
        sponsor_commitment: impl Into<String>,
        reserve_gap_amount: u64,
        committed_amount: u64,
        activation_height: u64,
        min_backstop_coverage_bps: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let coverage_bps = coverage_bps(committed_amount, reserve_gap_amount);
        let activated = coverage_bps >= min_backstop_coverage_bps;
        let activation_id = liquidity_id(
            "backstop",
            &sponsor_commitment,
            reserve_gap_amount,
            activation_height,
        );
        let activation_root = record_root(
            "backstop-activation",
            &json!({
                "activation_id": activation_id,
                "sponsor_commitment": sponsor_commitment,
                "reserve_gap_amount": reserve_gap_amount,
                "committed_amount": committed_amount,
                "coverage_bps": coverage_bps,
                "activation_height": activation_height,
                "reimbursement_priority": ClaimPriority::BackstopReimbursement.as_str(),
                "activated": activated,
            }),
        );
        Self {
            activation_id,
            sponsor_commitment,
            reserve_gap_amount,
            committed_amount,
            coverage_bps,
            activation_height,
            reimbursement_priority: ClaimPriority::BackstopReimbursement,
            activated,
            activation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "activation_id": self.activation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_gap_amount": self.reserve_gap_amount,
            "committed_amount": self.committed_amount,
            "coverage_bps": self.coverage_bps,
            "activation_height": self.activation_height,
            "reimbursement_priority": self.reimbursement_priority.as_str(),
            "activated": self.activated,
            "activation_root": self.activation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuctionFallback {
    pub auction_id: String,
    pub lot_commitment_root: String,
    pub sealed_bid_root: String,
    pub clearing_price_commitment: String,
    pub start_height: u64,
    pub close_height: u64,
    pub low_fee_cap_bps: u64,
    pub fallback_open: bool,
    pub privacy_preserving: bool,
    pub auction_root: String,
}

impl AuctionFallback {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lot_commitment_root: impl Into<String>,
        sealed_bid_root: impl Into<String>,
        clearing_price_commitment: impl Into<String>,
        start_height: u64,
        auction_open_blocks: u64,
        low_fee_cap_bps: u64,
        fallback_open: bool,
        privacy_preserving: bool,
    ) -> Self {
        let lot_commitment_root = lot_commitment_root.into();
        let sealed_bid_root = sealed_bid_root.into();
        let clearing_price_commitment = clearing_price_commitment.into();
        let close_height = start_height.saturating_add(auction_open_blocks);
        let auction_id = liquidity_id(
            "auction",
            &lot_commitment_root,
            &sealed_bid_root,
            start_height,
        );
        let auction_root = record_root(
            "auction-fallback",
            &json!({
                "auction_id": auction_id,
                "lot_commitment_root": lot_commitment_root,
                "sealed_bid_root": sealed_bid_root,
                "clearing_price_commitment": clearing_price_commitment,
                "start_height": start_height,
                "close_height": close_height,
                "low_fee_cap_bps": low_fee_cap_bps,
                "fallback_open": fallback_open,
                "privacy_preserving": privacy_preserving,
            }),
        );
        Self {
            auction_id,
            lot_commitment_root,
            sealed_bid_root,
            clearing_price_commitment,
            start_height,
            close_height,
            low_fee_cap_bps,
            fallback_open,
            privacy_preserving,
            auction_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lot_commitment_root": self.lot_commitment_root,
            "sealed_bid_root": self.sealed_bid_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "start_height": self.start_height,
            "close_height": self.close_height,
            "low_fee_cap_bps": self.low_fee_cap_bps,
            "fallback_open": self.fallback_open,
            "privacy_preserving": self.privacy_preserving,
            "auction_root": self.auction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EscapeContinuity {
    pub escape_id: String,
    pub wallet_recovery_root: String,
    pub forced_exit_queue_root: String,
    pub proof_carryover_root: String,
    pub available_window_blocks: u64,
    pub escape_lane_open: bool,
    pub user_funds_senior: bool,
    pub continuity_root: String,
}

impl EscapeContinuity {
    pub fn new(
        wallet_recovery_root: impl Into<String>,
        forced_exit_queue_root: impl Into<String>,
        proof_carryover_root: impl Into<String>,
        available_window_blocks: u64,
        escape_window_blocks: u64,
        escape_lane_open: bool,
    ) -> Self {
        let wallet_recovery_root = wallet_recovery_root.into();
        let forced_exit_queue_root = forced_exit_queue_root.into();
        let proof_carryover_root = proof_carryover_root.into();
        let user_funds_senior = available_window_blocks >= escape_window_blocks && escape_lane_open;
        let escape_id = liquidity_id(
            "escape",
            &wallet_recovery_root,
            &forced_exit_queue_root,
            available_window_blocks,
        );
        let continuity_root = record_root(
            "escape-continuity",
            &json!({
                "escape_id": escape_id,
                "wallet_recovery_root": wallet_recovery_root,
                "forced_exit_queue_root": forced_exit_queue_root,
                "proof_carryover_root": proof_carryover_root,
                "available_window_blocks": available_window_blocks,
                "escape_lane_open": escape_lane_open,
                "user_funds_senior": user_funds_senior,
            }),
        );
        Self {
            escape_id,
            wallet_recovery_root,
            forced_exit_queue_root,
            proof_carryover_root,
            available_window_blocks,
            escape_lane_open,
            user_funds_senior,
            continuity_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "wallet_recovery_root": self.wallet_recovery_root,
            "forced_exit_queue_root": self.forced_exit_queue_root,
            "proof_carryover_root": self.proof_carryover_root,
            "available_window_blocks": self.available_window_blocks,
            "escape_lane_open": self.escape_lane_open,
            "user_funds_senior": self.user_funds_senior,
            "continuity_root": self.continuity_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunbookCheckpoint {
    pub checkpoint_id: String,
    pub phase: RunbookPhase,
    pub status: RunbookStatus,
    pub assertion: String,
    pub evidence_root: String,
    pub blocks_production: bool,
    pub checkpoint_root: String,
}

impl RunbookCheckpoint {
    pub fn new(
        phase: RunbookPhase,
        status: RunbookStatus,
        assertion: impl Into<String>,
        evidence_root: impl Into<String>,
        blocks_production: bool,
    ) -> Self {
        let assertion = assertion.into();
        let evidence_root = evidence_root.into();
        let checkpoint_id = liquidity_id(
            "checkpoint",
            phase.as_str(),
            &evidence_root,
            status.as_str(),
        );
        let checkpoint_root = domain_hash(
            "MONERO-L2-LIQUIDITY-CHECKPOINT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&checkpoint_id),
                HashPart::Str(phase.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(&assertion),
                HashPart::Str(&evidence_root),
                HashPart::Str(if blocks_production { "blocks" } else { "clear" }),
            ],
            32,
        );
        Self {
            checkpoint_id,
            phase,
            status,
            assertion,
            evidence_root,
            blocks_production,
            checkpoint_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "phase": self.phase.as_str(),
            "status": self.status.as_str(),
            "assertion": self.assertion,
            "evidence_root": self.evidence_root,
            "blocks_production": self.blocks_production,
            "checkpoint_root": self.checkpoint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateRoots {
    pub config_root: String,
    pub liquidity_evidence_root: String,
    pub settlement_order_root: String,
    pub backstop_root: String,
    pub auction_root: String,
    pub escape_root: String,
    pub checkpoint_root: String,
    pub blocker_root: String,
}

impl StateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "liquidity_evidence_root": self.liquidity_evidence_root,
            "settlement_order_root": self.settlement_order_root,
            "backstop_root": self.backstop_root,
            "auction_root": self.auction_root,
            "escape_root": self.escape_root,
            "checkpoint_root": self.checkpoint_root,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub liquidity_evidence: Vec<LiquidityEvidence>,
    pub settlement_steps: Vec<SettlementStep>,
    pub backstop_activations: Vec<BackstopActivation>,
    pub auction_fallbacks: Vec<AuctionFallback>,
    pub escape_continuity: Vec<EscapeContinuity>,
    pub checkpoints: Vec<RunbookCheckpoint>,
    pub production_blockers: Vec<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            liquidity_evidence: Vec::new(),
            settlement_steps: Vec::new(),
            backstop_activations: Vec::new(),
            auction_fallbacks: Vec::new(),
            escape_continuity: Vec::new(),
            checkpoints: Vec::new(),
            production_blockers: Vec::new(),
        }
    }

    pub fn add_liquidity_evidence(&mut self, evidence: LiquidityEvidence) -> Result<String> {
        if self.liquidity_evidence.len() >= self.config.max_reports {
            return Err("liquidity evidence report cap exceeded".to_string());
        }
        if evidence.privacy_set_size < self.config.min_privacy_set_size {
            self.production_blockers.push(format!(
                "liquidity evidence {} privacy set below threshold",
                evidence.evidence_id
            ));
        }
        if evidence.reserve_coverage_bps < self.config.min_reserve_coverage_bps {
            self.production_blockers.push(format!(
                "liquidity evidence {} reserve coverage below threshold",
                evidence.evidence_id
            ));
        }
        if evidence.production_blocker {
            self.production_blockers.push(format!(
                "liquidity evidence {} is not production strong",
                evidence.evidence_id
            ));
        }
        let root = evidence.evidence_root.clone();
        self.liquidity_evidence.push(evidence);
        Ok(root)
    }

    pub fn add_settlement_step(&mut self, step: SettlementStep) -> Result<String> {
        if !step.low_fee_cap_enforced {
            self.production_blockers.push(format!(
                "settlement step {} exceeds low-fee cap",
                step.step_id
            ));
        }
        if !step.preserves_escape || step.priority.rank() > ClaimPriority::MaturedExit.rank() {
            self.production_blockers.push(format!(
                "settlement step {} must not outrank user escape continuity",
                step.step_id
            ));
        }
        let root = step.step_root.clone();
        self.settlement_steps.push(step);
        self.settlement_steps.sort_by(|left, right| {
            (
                left.priority.rank(),
                left.ordering_index,
                left.step_id.as_str(),
            )
                .cmp(&(
                    right.priority.rank(),
                    right.ordering_index,
                    right.step_id.as_str(),
                ))
        });
        Ok(root)
    }

    pub fn add_backstop_activation(&mut self, activation: BackstopActivation) -> Result<String> {
        if !activation.activated {
            self.production_blockers.push(format!(
                "backstop activation {} below coverage threshold",
                activation.activation_id
            ));
        }
        let root = activation.activation_root.clone();
        self.backstop_activations.push(activation);
        Ok(root)
    }

    pub fn add_auction_fallback(&mut self, auction: AuctionFallback) -> Result<String> {
        if !auction.fallback_open || !auction.privacy_preserving {
            self.production_blockers.push(format!(
                "auction fallback {} is not release ready",
                auction.auction_id
            ));
        }
        if auction.low_fee_cap_bps > self.config.low_fee_cap_bps {
            self.production_blockers.push(format!(
                "auction fallback {} exceeds low-fee cap",
                auction.auction_id
            ));
        }
        let root = auction.auction_root.clone();
        self.auction_fallbacks.push(auction);
        Ok(root)
    }

    pub fn add_escape_continuity(&mut self, escape: EscapeContinuity) -> Result<String> {
        if !escape.escape_lane_open || !escape.user_funds_senior {
            self.production_blockers.push(format!(
                "escape continuity {} does not keep user exits senior",
                escape.escape_id
            ));
        }
        let root = escape.continuity_root.clone();
        self.escape_continuity.push(escape);
        Ok(root)
    }

    pub fn add_checkpoint(&mut self, checkpoint: RunbookCheckpoint) -> Result<String> {
        if checkpoint.blocks_production || checkpoint.status == RunbookStatus::Blocked {
            self.production_blockers.push(format!(
                "checkpoint {} blocks production",
                checkpoint.checkpoint_id
            ));
        }
        let root = checkpoint.checkpoint_root.clone();
        self.checkpoints.push(checkpoint);
        Ok(root)
    }

    pub fn status(&self) -> RunbookStatus {
        if !self.production_blockers.is_empty() || !self.config.production_release_allowed {
            RunbookStatus::Blocked
        } else if self
            .checkpoints
            .iter()
            .any(|checkpoint| checkpoint.status == RunbookStatus::Watch)
        {
            RunbookStatus::Watch
        } else {
            RunbookStatus::Proven
        }
    }

    pub fn roots(&self) -> StateRoots {
        StateRoots {
            config_root: self.config.state_root(),
            liquidity_evidence_root: merkle_from_records(
                "liquidity-evidence",
                self.liquidity_evidence
                    .iter()
                    .map(LiquidityEvidence::public_record)
                    .collect(),
            ),
            settlement_order_root: merkle_from_records(
                "settlement-order",
                self.settlement_steps
                    .iter()
                    .map(SettlementStep::public_record)
                    .collect(),
            ),
            backstop_root: merkle_from_records(
                "backstops",
                self.backstop_activations
                    .iter()
                    .map(BackstopActivation::public_record)
                    .collect(),
            ),
            auction_root: merkle_from_records(
                "auctions",
                self.auction_fallbacks
                    .iter()
                    .map(AuctionFallback::public_record)
                    .collect(),
            ),
            escape_root: merkle_from_records(
                "escape-continuity",
                self.escape_continuity
                    .iter()
                    .map(EscapeContinuity::public_record)
                    .collect(),
            ),
            checkpoint_root: merkle_from_records(
                "checkpoints",
                self.checkpoints
                    .iter()
                    .map(RunbookCheckpoint::public_record)
                    .collect(),
            ),
            blocker_root: merkle_from_strings("blockers", self.production_blockers.clone()),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "epoch": self.epoch,
            "status": self.status().as_str(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
            "counters": {
                "liquidity_evidence": self.liquidity_evidence.len(),
                "settlement_steps": self.settlement_steps.len(),
                "backstop_activations": self.backstop_activations.len(),
                "auction_fallbacks": self.auction_fallbacks.len(),
                "escape_continuity": self.escape_continuity.len(),
                "checkpoints": self.checkpoints.len(),
                "production_blockers": self.production_blockers.len(),
            },
            "roots": roots.public_record(),
            "production_blockers": self.production_blockers,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "MONERO-L2-LIQUIDITY-RUNBOOK-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch as i128),
                HashPart::Str(self.status().as_str()),
                HashPart::Json(&roots.public_record()),
                HashPart::Int(self.production_blockers.len() as i128),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let mut state = State::new(config.clone(), 42_000, 7);

    let weak_evidence = LiquidityEvidence::new(
        sample_root("reserve-commitment-weak"),
        sample_root("liability-commitment-devnet"),
        sample_root("range-proof-batch-a"),
        sample_root("exit-nullifier-set-a"),
        48,
        8_750,
        EvidenceStrength::Weak,
        true,
    );
    let strong_evidence = LiquidityEvidence::new(
        sample_root("reserve-commitment-zk"),
        sample_root("liability-commitment-devnet"),
        sample_root("range-proof-batch-b"),
        sample_root("exit-nullifier-set-b"),
        128,
        10_250,
        EvidenceStrength::ZkReserveProven,
        true,
    );
    let weak_evidence_root = weak_evidence.evidence_root.clone();
    let strong_evidence_root = strong_evidence.evidence_root.clone();
    let _weak_root = state.add_liquidity_evidence(weak_evidence);
    let _strong_root = state.add_liquidity_evidence(strong_evidence);

    let _escape_settlement = state.add_settlement_step(SettlementStep::new(
        sample_root("claim-user-escape-0"),
        ClaimPriority::UserEscape,
        4_000,
        4_000,
        10,
        0,
        true,
        config.low_fee_cap_bps,
    ));
    let _matured_settlement = state.add_settlement_step(SettlementStep::new(
        sample_root("claim-matured-exit-1"),
        ClaimPriority::MaturedExit,
        8_000,
        5_250,
        25,
        1,
        true,
        config.low_fee_cap_bps,
    ));

    let backstop = BackstopActivation::new(
        sample_root("backstop-sponsor-a"),
        2_750,
        900,
        state.height + 1,
        config.min_backstop_coverage_bps,
    );
    let backstop_root = backstop.activation_root.clone();
    let _backstop_root = state.add_backstop_activation(backstop);

    let auction = AuctionFallback::new(
        sample_root("auction-lot-root"),
        sample_root("sealed-bid-root"),
        sample_root("clearing-price-commitment"),
        state.height + 2,
        config.auction_open_blocks,
        config.low_fee_cap_bps,
        true,
        true,
    );
    let auction_root = auction.auction_root.clone();
    let _auction_root = state.add_auction_fallback(auction);

    let escape = EscapeContinuity::new(
        sample_root("wallet-recovery-root"),
        sample_root("forced-exit-queue-root"),
        sample_root("proof-carryover-root"),
        config.escape_window_blocks,
        config.escape_window_blocks,
        true,
    );
    let escape_root = escape.continuity_root.clone();
    let _escape_root = state.add_escape_continuity(escape);

    let checkpoints = [
        RunbookCheckpoint::new(
            RunbookPhase::PartialSettlement,
            RunbookStatus::Proven,
            "partial settlement orders user escape and matured exits before reimbursements",
            strong_evidence_root,
            false,
        ),
        RunbookCheckpoint::new(
            RunbookPhase::BackstopActivation,
            RunbookStatus::Proven,
            "backstop activation covers the measured reserve gap before auction fallback",
            backstop_root,
            false,
        ),
        RunbookCheckpoint::new(
            RunbookPhase::AuctionFallback,
            RunbookStatus::Proven,
            "sealed auction fallback preserves low-fee caps and bid privacy",
            auction_root,
            false,
        ),
        RunbookCheckpoint::new(
            RunbookPhase::UserEscape,
            RunbookStatus::Proven,
            "user escape lane remains senior through reserve recovery",
            escape_root,
            false,
        ),
        RunbookCheckpoint::new(
            RunbookPhase::ReserveRecovery,
            RunbookStatus::Blocked,
            "weak reserve evidence remains a production blocker until replaced by finalized proof",
            weak_evidence_root,
            true,
        ),
    ];
    for checkpoint in checkpoints {
        let _checkpoint_root = state.add_checkpoint(checkpoint);
    }

    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn config_root(config: &Config) -> String {
    config.state_root()
}

pub fn liquidity_evidence_root(evidence: &[LiquidityEvidence]) -> String {
    merkle_from_records(
        "liquidity-evidence",
        evidence
            .iter()
            .map(LiquidityEvidence::public_record)
            .collect(),
    )
}

pub fn settlement_order_root(steps: &[SettlementStep]) -> String {
    let mut ordered = steps.to_vec();
    ordered.sort_by(|left, right| {
        (
            left.priority.rank(),
            left.ordering_index,
            left.step_id.as_str(),
        )
            .cmp(&(
                right.priority.rank(),
                right.ordering_index,
                right.step_id.as_str(),
            ))
    });
    merkle_from_records(
        "settlement-order",
        ordered.iter().map(SettlementStep::public_record).collect(),
    )
}

pub fn reserve_recovery_root(state: &State) -> String {
    let roots = state.roots();
    domain_hash(
        "MONERO-L2-RESERVE-RECOVERY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&roots.liquidity_evidence_root),
            HashPart::Str(&roots.backstop_root),
            HashPart::Str(&roots.auction_root),
            HashPart::Str(&roots.escape_root),
            HashPart::Str(&roots.blocker_root),
        ],
        32,
    )
}

pub fn runbook_root(checkpoints: &[RunbookCheckpoint]) -> String {
    merkle_from_records(
        "runbook-checkpoints",
        checkpoints
            .iter()
            .map(RunbookCheckpoint::public_record)
            .collect(),
    )
}

pub fn production_blocker_root(blockers: &[String]) -> String {
    merkle_from_strings("production-blockers", blockers.to_vec())
}

fn coverage_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        10_000
    } else {
        numerator.saturating_mul(10_000) / denominator
    }
}

fn liquidity_id(
    kind: impl Into<String>,
    left: impl ToString,
    right: impl ToString,
    nonce: impl ToString,
) -> String {
    let kind = kind.into();
    domain_hash(
        "MONERO-L2-LIQUIDITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&kind),
            HashPart::Str(&left.to_string()),
            HashPart::Str(&right.to_string()),
            HashPart::Str(&nonce.to_string()),
        ],
        16,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-LIQUIDITY-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn merkle_from_records(label: &str, records: Vec<Value>) -> String {
    let leaves = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| json!({ "index": index, "record": record }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-LIQUIDITY-MERKLE-{label}"),
        leaves.as_slice(),
    )
}

fn merkle_from_strings(label: &str, values: Vec<String>) -> String {
    let mut map = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        map.insert(index.to_string(), json!({ "value": value }));
    }
    merkle_from_records(label, map.into_values().collect())
}

fn sample_root(label: &str) -> String {
    record_root("devnet-sample", &json!({ "label": label }))
}
