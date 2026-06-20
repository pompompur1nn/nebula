use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitLiquidityExhaustionRecoveryContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_LIQUIDITY_EXHAUSTION_RECOVERY_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-liquidity-exhaustion-recovery-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_LIQUIDITY_EXHAUSTION_RECOVERY_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECOVERY_CONTRACT_SUITE: &str =
    "monero-l2-pq-bridge-exit-liquidity-exhaustion-recovery-contract-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_EVIDENCE_SHARES: u64 = 9;
pub const DEFAULT_MIN_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_BACKSTOP_TRIGGER_BPS: u64 = 9_500;
pub const DEFAULT_AUCTION_TRIGGER_BPS: u64 = 8_500;
pub const DEFAULT_MAX_LOW_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_PARTIAL_SETTLEMENTS: u64 = 4;
pub const DEFAULT_MAX_REPORTS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    ReserveRelease,
    BackstopDraw,
    AuctionFill,
    FallbackEscrow,
    PartialSettlement,
    UserReleaseBlocker,
    ProductionBlocker,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveRelease => "reserve_release",
            Self::BackstopDraw => "backstop_draw",
            Self::AuctionFill => "auction_fill",
            Self::FallbackEscrow => "fallback_escrow",
            Self::PartialSettlement => "partial_settlement",
            Self::UserReleaseBlocker => "user_release_blocker",
            Self::ProductionBlocker => "production_blocker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionStatus {
    Ready,
    Partial,
    Held,
    Blocked,
}

impl RecoveryActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Partial => "partial",
            Self::Held => "held",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityEvidenceStatus {
    Sufficient,
    Degraded,
    Insufficient,
}

impl LiquidityEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sufficient => "sufficient",
            Self::Degraded => "degraded",
            Self::Insufficient => "insufficient",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReportStatus {
    Ready,
    Watch,
    Blocked,
}

impl RecoveryReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
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
    pub contract_suite: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_evidence_shares: u64,
    pub min_coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub backstop_trigger_bps: u64,
    pub auction_trigger_bps: u64,
    pub max_low_fee_bps: u64,
    pub max_partial_settlements: u64,
    pub reserve_release_adapter_live: bool,
    pub bridge_liquidity_live: bool,
    pub claim_queue_handler_live: bool,
    pub settlement_execution_live: bool,
    pub fail_closed_on_evidence_gap: bool,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub security_audit_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            contract_suite: RECOVERY_CONTRACT_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_evidence_shares: DEFAULT_MIN_EVIDENCE_SHARES,
            min_coverage_bps: DEFAULT_MIN_COVERAGE_BPS,
            target_coverage_bps: DEFAULT_TARGET_COVERAGE_BPS,
            backstop_trigger_bps: DEFAULT_BACKSTOP_TRIGGER_BPS,
            auction_trigger_bps: DEFAULT_AUCTION_TRIGGER_BPS,
            max_low_fee_bps: DEFAULT_MAX_LOW_FEE_BPS,
            max_partial_settlements: DEFAULT_MAX_PARTIAL_SETTLEMENTS,
            reserve_release_adapter_live: false,
            bridge_liquidity_live: false,
            claim_queue_handler_live: false,
            settlement_execution_live: false,
            fail_closed_on_evidence_gap: true,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            security_audit_deferred: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "contract_suite": self.contract_suite,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_evidence_shares": self.min_evidence_shares,
            "min_coverage_bps": self.min_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "backstop_trigger_bps": self.backstop_trigger_bps,
            "auction_trigger_bps": self.auction_trigger_bps,
            "max_low_fee_bps": self.max_low_fee_bps,
            "max_partial_settlements": self.max_partial_settlements,
            "reserve_release_adapter_live": self.reserve_release_adapter_live,
            "bridge_liquidity_live": self.bridge_liquidity_live,
            "claim_queue_handler_live": self.claim_queue_handler_live,
            "settlement_execution_live": self.settlement_execution_live,
            "fail_closed_on_evidence_gap": self.fail_closed_on_evidence_gap,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyPreservingLiquidityEvidence {
    pub evidence_id: String,
    pub status: LiquidityEvidenceStatus,
    pub reserve_account_root: String,
    pub bridge_liquidity_root: String,
    pub claim_queue_root: String,
    pub live_settlement_root: String,
    pub blinded_liquidity_bucket_root: String,
    pub encrypted_provider_set_root: String,
    pub range_proof_root: String,
    pub nullifier_set_root: String,
    pub evidence_shares: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub coverage_bps: u64,
    pub low_fee_bps: u64,
    pub evidence_root: String,
}

impl PrivacyPreservingLiquidityEvidence {
    pub fn new(
        config: &Config,
        evidence_id: impl Into<String>,
        reserve_account_root: impl Into<String>,
        bridge_liquidity_root: impl Into<String>,
        claim_queue_root: impl Into<String>,
        live_settlement_root: impl Into<String>,
        requested_amount: u128,
        available_amount: u128,
        ordinal: u64,
    ) -> Self {
        let evidence_id = evidence_id.into();
        let reserve_account_root = reserve_account_root.into();
        let bridge_liquidity_root = bridge_liquidity_root.into();
        let claim_queue_root = claim_queue_root.into();
        let live_settlement_root = live_settlement_root.into();
        let coverage_bps = bps(available_amount, requested_amount.max(1));
        let privacy_set_size = config.min_privacy_set_size.saturating_add(ordinal * 257);
        let evidence_shares = config.min_evidence_shares.saturating_add(ordinal % 3);
        let low_fee_bps = ordinal.min(config.max_low_fee_bps);
        let blinded_liquidity_bucket_root = liquidity_bucket_root(
            &evidence_id,
            &reserve_account_root,
            &bridge_liquidity_root,
            coverage_bps,
        );
        let encrypted_provider_set_root = provider_set_root(
            &evidence_id,
            &claim_queue_root,
            privacy_set_size,
            evidence_shares,
        );
        let range_proof_root = range_proof_root(
            &evidence_id,
            requested_amount,
            available_amount,
            coverage_bps,
            low_fee_bps,
        );
        let nullifier_set_root = nullifier_set_root(
            &evidence_id,
            &live_settlement_root,
            ordinal,
            evidence_shares,
        );
        let status = evidence_status(
            config,
            evidence_shares,
            privacy_set_size,
            config.min_pq_security_bits,
            coverage_bps,
            low_fee_bps,
        );
        let evidence_root = record_root(
            "privacy_preserving_liquidity_evidence",
            &json!({
                "evidence_id": evidence_id,
                "status": status.as_str(),
                "reserve_account_root": reserve_account_root,
                "bridge_liquidity_root": bridge_liquidity_root,
                "claim_queue_root": claim_queue_root,
                "live_settlement_root": live_settlement_root,
                "blinded_liquidity_bucket_root": blinded_liquidity_bucket_root,
                "encrypted_provider_set_root": encrypted_provider_set_root,
                "range_proof_root": range_proof_root,
                "nullifier_set_root": nullifier_set_root,
                "evidence_shares": evidence_shares,
                "privacy_set_size": privacy_set_size,
                "pq_security_bits": config.min_pq_security_bits,
                "coverage_bps": coverage_bps,
                "low_fee_bps": low_fee_bps,
            }),
        );

        Self {
            evidence_id,
            status,
            reserve_account_root,
            bridge_liquidity_root,
            claim_queue_root,
            live_settlement_root,
            blinded_liquidity_bucket_root,
            encrypted_provider_set_root,
            range_proof_root,
            nullifier_set_root,
            evidence_shares,
            privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            coverage_bps,
            low_fee_bps,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "status": self.status.as_str(),
            "reserve_account_root": self.reserve_account_root,
            "bridge_liquidity_root": self.bridge_liquidity_root,
            "claim_queue_root": self.claim_queue_root,
            "live_settlement_root": self.live_settlement_root,
            "blinded_liquidity_bucket_root": self.blinded_liquidity_bucket_root,
            "encrypted_provider_set_root": self.encrypted_provider_set_root,
            "range_proof_root": self.range_proof_root,
            "nullifier_set_root": self.nullifier_set_root,
            "evidence_shares": self.evidence_shares,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "coverage_bps": self.coverage_bps,
            "low_fee_bps": self.low_fee_bps,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("liquidity_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityExhaustionRecoveryContract {
    pub contract_id: String,
    pub status: RecoveryActionStatus,
    pub primary_lane: RecoveryLane,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub scenario_id: String,
    pub queue_position: u64,
    pub claim_order_root: String,
    pub requested_amount: u128,
    pub reserve_release_amount: u128,
    pub backstop_amount: u128,
    pub auction_amount: u128,
    pub fallback_amount: u128,
    pub settled_amount: u128,
    pub residual_amount: u128,
    pub partial_settlement_index: u64,
    pub partial_settlement_count: u64,
    pub low_fee_cap_bps: u64,
    pub coverage_bps: u64,
    pub reserve_release_root: String,
    pub backstop_root: String,
    pub auction_root: String,
    pub fallback_root: String,
    pub partial_settlement_root: String,
    pub evidence_root: String,
    pub live_execution_payload_root: String,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub blocker_root: String,
    pub contract_root: String,
    pub hold_reason: String,
}

impl LiquidityExhaustionRecoveryContract {
    pub fn from_evidence(
        config: &Config,
        claim: RecoveryClaimInput,
        evidence: &PrivacyPreservingLiquidityEvidence,
        ordinal: u64,
    ) -> Self {
        let reserve_release_amount = claim.reserve_available.min(claim.requested_amount);
        let reserve_gap = claim
            .requested_amount
            .saturating_sub(reserve_release_amount);
        let backstop_amount = if evidence.coverage_bps < config.backstop_trigger_bps {
            claim.backstop_available.min(reserve_gap)
        } else {
            0
        };
        let backstop_gap = reserve_gap.saturating_sub(backstop_amount);
        let auction_amount = if evidence.coverage_bps < config.auction_trigger_bps {
            claim.auction_available.min(backstop_gap)
        } else {
            0
        };
        let fallback_amount = claim
            .fallback_available
            .min(backstop_gap.saturating_sub(auction_amount));
        let settled_amount = reserve_release_amount
            .saturating_add(backstop_amount)
            .saturating_add(auction_amount)
            .saturating_add(fallback_amount);
        let residual_amount = claim.requested_amount.saturating_sub(settled_amount);
        let partial_settlement_count =
            partial_count(config, claim.requested_amount, settled_amount);
        let partial_settlement_index = if partial_settlement_count == 0 {
            0
        } else {
            ordinal % partial_settlement_count
        };
        let low_fee_cap_bps = evidence.low_fee_bps.min(config.max_low_fee_bps);
        let claim_order_root = claim_order_root(
            &claim.release_claim_id,
            claim.queue_position,
            claim.challenge_window_end,
            ordinal,
        );
        let reserve_release_root = reserve_release_root(
            &claim.release_claim_id,
            reserve_release_amount,
            claim.reserve_available,
            &evidence.reserve_account_root,
        );
        let backstop_root = backstop_root(
            &claim.release_claim_id,
            backstop_amount,
            claim.backstop_available,
            &evidence.blinded_liquidity_bucket_root,
        );
        let auction_root = auction_root(
            &claim.release_claim_id,
            auction_amount,
            claim.auction_available,
            evidence.coverage_bps,
        );
        let fallback_root = fallback_root(
            &claim.release_claim_id,
            fallback_amount,
            claim.fallback_available,
            residual_amount,
        );
        let partial_settlement_root = partial_settlement_root(
            &claim.release_claim_id,
            partial_settlement_index,
            partial_settlement_count,
            settled_amount,
            residual_amount,
        );
        let live_execution_payload_root = live_execution_payload_root(
            &claim.release_claim_id,
            &claim_order_root,
            &reserve_release_root,
            &partial_settlement_root,
            low_fee_cap_bps,
        );
        let user_release_blockers = user_release_blockers(config, evidence, residual_amount);
        let production_blockers = production_blockers(config, evidence);
        let blocker_root = blocker_root(
            &claim.release_claim_id,
            user_release_blockers,
            production_blockers,
            &evidence.evidence_root,
        );
        let status = contract_status(
            evidence.status,
            settled_amount,
            claim.requested_amount,
            user_release_blockers,
            production_blockers,
        );
        let primary_lane = primary_lane(
            status,
            reserve_release_amount,
            backstop_amount,
            auction_amount,
            fallback_amount,
            user_release_blockers,
            production_blockers,
        );
        let hold_reason = hold_reason(
            status,
            user_release_blockers,
            production_blockers,
            residual_amount,
        );
        let contract_root = record_root(
            "liquidity_exhaustion_recovery_contract",
            &json!({
                "contract_id": claim.contract_id,
                "status": status.as_str(),
                "primary_lane": primary_lane.as_str(),
                "release_claim_id": claim.release_claim_id,
                "transfer_id": claim.transfer_id,
                "scenario_id": claim.scenario_id,
                "queue_position": claim.queue_position,
                "claim_order_root": claim_order_root,
                "requested_amount": claim.requested_amount,
                "reserve_release_amount": reserve_release_amount,
                "backstop_amount": backstop_amount,
                "auction_amount": auction_amount,
                "fallback_amount": fallback_amount,
                "settled_amount": settled_amount,
                "residual_amount": residual_amount,
                "partial_settlement_index": partial_settlement_index,
                "partial_settlement_count": partial_settlement_count,
                "low_fee_cap_bps": low_fee_cap_bps,
                "coverage_bps": evidence.coverage_bps,
                "reserve_release_root": reserve_release_root,
                "backstop_root": backstop_root,
                "auction_root": auction_root,
                "fallback_root": fallback_root,
                "partial_settlement_root": partial_settlement_root,
                "evidence_root": evidence.evidence_root,
                "live_execution_payload_root": live_execution_payload_root,
                "user_release_blockers": user_release_blockers,
                "production_blockers": production_blockers,
                "blocker_root": blocker_root,
                "hold_reason": hold_reason,
            }),
        );

        Self {
            contract_id: claim.contract_id,
            status,
            primary_lane,
            release_claim_id: claim.release_claim_id,
            transfer_id: claim.transfer_id,
            scenario_id: claim.scenario_id,
            queue_position: claim.queue_position,
            claim_order_root,
            requested_amount: claim.requested_amount,
            reserve_release_amount,
            backstop_amount,
            auction_amount,
            fallback_amount,
            settled_amount,
            residual_amount,
            partial_settlement_index,
            partial_settlement_count,
            low_fee_cap_bps,
            coverage_bps: evidence.coverage_bps,
            reserve_release_root,
            backstop_root,
            auction_root,
            fallback_root,
            partial_settlement_root,
            evidence_root: evidence.evidence_root.clone(),
            live_execution_payload_root,
            user_release_blockers,
            production_blockers,
            blocker_root,
            contract_root,
            hold_reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "primary_lane": self.primary_lane.as_str(),
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "scenario_id": self.scenario_id,
            "queue_position": self.queue_position,
            "claim_order_root": self.claim_order_root,
            "requested_amount": self.requested_amount,
            "reserve_release_amount": self.reserve_release_amount,
            "backstop_amount": self.backstop_amount,
            "auction_amount": self.auction_amount,
            "fallback_amount": self.fallback_amount,
            "settled_amount": self.settled_amount,
            "residual_amount": self.residual_amount,
            "partial_settlement_index": self.partial_settlement_index,
            "partial_settlement_count": self.partial_settlement_count,
            "low_fee_cap_bps": self.low_fee_cap_bps,
            "coverage_bps": self.coverage_bps,
            "reserve_release_root": self.reserve_release_root,
            "backstop_root": self.backstop_root,
            "auction_root": self.auction_root,
            "fallback_root": self.fallback_root,
            "partial_settlement_root": self.partial_settlement_root,
            "evidence_root": self.evidence_root,
            "live_execution_payload_root": self.live_execution_payload_root,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "blocker_root": self.blocker_root,
            "contract_root": self.contract_root,
            "hold_reason": self.hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("recovery_contract", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryClaimInput {
    pub contract_id: String,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub scenario_id: String,
    pub queue_position: u64,
    pub challenge_window_end: u64,
    pub requested_amount: u128,
    pub reserve_available: u128,
    pub backstop_available: u128,
    pub auction_available: u128,
    pub fallback_available: u128,
}

impl RecoveryClaimInput {
    pub fn devnet(ordinal: u64) -> Self {
        let requested_amount = 1_000_000_000_000u128.saturating_add(ordinal as u128 * 10_000_000);
        Self {
            contract_id: format!("liquidity-exhaustion-recovery-contract-{ordinal:04}"),
            release_claim_id: format!("release-claim-{ordinal:04}"),
            transfer_id: format!("transfer-{ordinal:04}"),
            scenario_id: format!("always-available-exit-{ordinal:04}"),
            queue_position: ordinal,
            challenge_window_end: 4_200_192u64.saturating_add(ordinal),
            requested_amount,
            reserve_available: requested_amount.saturating_mul(68).saturating_div(100),
            backstop_available: requested_amount.saturating_mul(16).saturating_div(100),
            auction_available: requested_amount.saturating_mul(10).saturating_div(100),
            fallback_available: requested_amount.saturating_mul(8).saturating_div(100),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "scenario_id": self.scenario_id,
            "queue_position": self.queue_position,
            "challenge_window_end": self.challenge_window_end,
            "requested_amount": self.requested_amount,
            "reserve_available": self.reserve_available,
            "backstop_available": self.backstop_available,
            "auction_available": self.auction_available,
            "fallback_available": self.fallback_available,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("recovery_claim_input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityExhaustionRecoveryReport {
    pub report_id: String,
    pub status: RecoveryReportStatus,
    pub config_root: String,
    pub evidence_root: String,
    pub contract_root: String,
    pub claim_input_root: String,
    pub recovery_sequence_root: String,
    pub reserve_release_adapter_root: String,
    pub bridge_liquidity_root: String,
    pub claim_queue_handler_root: String,
    pub live_settlement_execution_root: String,
    pub total_requested_amount: u128,
    pub total_settled_amount: u128,
    pub total_residual_amount: u128,
    pub ready_contracts: u64,
    pub partial_contracts: u64,
    pub held_contracts: u64,
    pub blocked_contracts: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub report_root: String,
}

impl LiquidityExhaustionRecoveryReport {
    pub fn from_contracts(
        config: &Config,
        report_id: impl Into<String>,
        evidence: &[PrivacyPreservingLiquidityEvidence],
        claims: &[RecoveryClaimInput],
        contracts: &[LiquidityExhaustionRecoveryContract],
    ) -> Self {
        let report_id = report_id.into();
        let total_requested_amount = contracts
            .iter()
            .map(|contract| contract.requested_amount)
            .sum();
        let total_settled_amount = contracts
            .iter()
            .map(|contract| contract.settled_amount)
            .sum();
        let total_residual_amount = contracts
            .iter()
            .map(|contract| contract.residual_amount)
            .sum();
        let ready_contracts = count_status(contracts, RecoveryActionStatus::Ready);
        let partial_contracts = count_status(contracts, RecoveryActionStatus::Partial);
        let held_contracts = count_status(contracts, RecoveryActionStatus::Held);
        let blocked_contracts = count_status(contracts, RecoveryActionStatus::Blocked);
        let user_release_blockers = contracts
            .iter()
            .map(|contract| contract.user_release_blockers)
            .sum();
        let production_blockers = contracts
            .iter()
            .map(|contract| contract.production_blockers)
            .sum();
        let config_root = config.state_root();
        let evidence_leaves = evidence
            .iter()
            .map(|record| Value::String(record.state_root()))
            .collect::<Vec<_>>();
        let contract_leaves = contracts
            .iter()
            .map(|record| Value::String(record.state_root()))
            .collect::<Vec<_>>();
        let claim_input_leaves = claims
            .iter()
            .map(|record| Value::String(record.state_root()))
            .collect::<Vec<_>>();
        let evidence_root = merkle_root(
            "liquidity-exhaustion-recovery-evidence-root",
            &evidence_leaves,
        );
        let contract_root = merkle_root(
            "liquidity-exhaustion-recovery-contract-root",
            &contract_leaves,
        );
        let claim_input_root = merkle_root(
            "liquidity-exhaustion-recovery-claim-input-root",
            &claim_input_leaves,
        );
        let recovery_sequence_root = recovery_sequence_root(
            &report_id,
            &config_root,
            &evidence_root,
            &contract_root,
            &claim_input_root,
        );
        let reserve_release_adapter_root =
            adapter_alignment_root("reserve_release_adapter", &contract_root, ready_contracts);
        let bridge_liquidity_root =
            adapter_alignment_root("bridge_liquidity", &evidence_root, partial_contracts);
        let claim_queue_handler_root =
            adapter_alignment_root("claim_queue_handler", &claim_input_root, held_contracts);
        let live_settlement_execution_root = adapter_alignment_root(
            "live_settlement_execution",
            &recovery_sequence_root,
            blocked_contracts,
        );
        let status = report_status(
            blocked_contracts,
            held_contracts,
            partial_contracts,
            production_blockers,
        );
        let report_root = record_root(
            "liquidity_exhaustion_recovery_report",
            &json!({
                "report_id": report_id,
                "status": status.as_str(),
                "config_root": config_root,
                "evidence_root": evidence_root,
                "contract_root": contract_root,
                "claim_input_root": claim_input_root,
                "recovery_sequence_root": recovery_sequence_root,
                "reserve_release_adapter_root": reserve_release_adapter_root,
                "bridge_liquidity_root": bridge_liquidity_root,
                "claim_queue_handler_root": claim_queue_handler_root,
                "live_settlement_execution_root": live_settlement_execution_root,
                "total_requested_amount": total_requested_amount,
                "total_settled_amount": total_settled_amount,
                "total_residual_amount": total_residual_amount,
                "ready_contracts": ready_contracts,
                "partial_contracts": partial_contracts,
                "held_contracts": held_contracts,
                "blocked_contracts": blocked_contracts,
                "user_release_blockers": user_release_blockers,
                "production_blockers": production_blockers,
            }),
        );

        Self {
            report_id,
            status,
            config_root,
            evidence_root,
            contract_root,
            claim_input_root,
            recovery_sequence_root,
            reserve_release_adapter_root,
            bridge_liquidity_root,
            claim_queue_handler_root,
            live_settlement_execution_root,
            total_requested_amount,
            total_settled_amount,
            total_residual_amount,
            ready_contracts,
            partial_contracts,
            held_contracts,
            blocked_contracts,
            user_release_blockers,
            production_blockers,
            report_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "config_root": self.config_root,
            "evidence_root": self.evidence_root,
            "contract_root": self.contract_root,
            "claim_input_root": self.claim_input_root,
            "recovery_sequence_root": self.recovery_sequence_root,
            "reserve_release_adapter_root": self.reserve_release_adapter_root,
            "bridge_liquidity_root": self.bridge_liquidity_root,
            "claim_queue_handler_root": self.claim_queue_handler_root,
            "live_settlement_execution_root": self.live_settlement_execution_root,
            "total_requested_amount": self.total_requested_amount,
            "total_settled_amount": self.total_settled_amount,
            "total_residual_amount": self.total_residual_amount,
            "ready_contracts": self.ready_contracts,
            "partial_contracts": self.partial_contracts,
            "held_contracts": self.held_contracts,
            "blocked_contracts": self.blocked_contracts,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "report_root": self.report_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("recovery_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub claims: BTreeMap<String, RecoveryClaimInput>,
    pub evidence: BTreeMap<String, PrivacyPreservingLiquidityEvidence>,
    pub contracts: BTreeMap<String, LiquidityExhaustionRecoveryContract>,
    pub reports: Vec<LiquidityExhaustionRecoveryReport>,
    pub counters: BTreeMap<String, u64>,
    pub roots: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            claims: BTreeMap::new(),
            evidence: BTreeMap::new(),
            contracts: BTreeMap::new(),
            reports: Vec::new(),
            counters: BTreeMap::new(),
            roots: BTreeMap::new(),
        };
        state.refresh_indexes();
        state
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone());
        for ordinal in 0..6 {
            let claim = RecoveryClaimInput::devnet(ordinal);
            let claim_root = claim.state_root();
            let evidence = PrivacyPreservingLiquidityEvidence::new(
                &config,
                format!("liquidity-evidence-{ordinal:04}"),
                reserve_release_root(
                    &claim.release_claim_id,
                    claim.reserve_available,
                    claim.reserve_available,
                    &claim_root,
                ),
                bridge_liquidity_position_root(
                    &claim.release_claim_id,
                    claim.requested_amount,
                    ordinal,
                ),
                claim_order_root(
                    &claim.release_claim_id,
                    claim.queue_position,
                    claim.challenge_window_end,
                    ordinal,
                ),
                live_settlement_payload_hint_root(&claim.release_claim_id, ordinal),
                claim.requested_amount,
                claim
                    .reserve_available
                    .saturating_add(claim.backstop_available)
                    .saturating_add(claim.auction_available)
                    .saturating_add(claim.fallback_available),
                ordinal,
            );
            let contract = LiquidityExhaustionRecoveryContract::from_evidence(
                &config,
                claim.clone(),
                &evidence,
                ordinal,
            );
            state.claims.insert(claim.release_claim_id.clone(), claim);
            state
                .evidence
                .insert(evidence.evidence_id.clone(), evidence);
            state
                .contracts
                .insert(contract.contract_id.clone(), contract);
        }
        state.generate_report("devnet-liquidity-exhaustion-recovery-report");
        state
    }

    pub fn insert_claim(
        &mut self,
        claim: RecoveryClaimInput,
        reserve_account_root: impl Into<String>,
        bridge_liquidity_root: impl Into<String>,
        live_settlement_root: impl Into<String>,
    ) -> Result<LiquidityExhaustionRecoveryContract> {
        let ordinal = self.contracts.len() as u64;
        let evidence = PrivacyPreservingLiquidityEvidence::new(
            &self.config,
            format!("liquidity-evidence-{ordinal:04}"),
            reserve_account_root,
            bridge_liquidity_root,
            claim.state_root(),
            live_settlement_root,
            claim.requested_amount,
            claim
                .reserve_available
                .saturating_add(claim.backstop_available)
                .saturating_add(claim.auction_available)
                .saturating_add(claim.fallback_available),
            ordinal,
        );
        let contract = LiquidityExhaustionRecoveryContract::from_evidence(
            &self.config,
            claim.clone(),
            &evidence,
            ordinal,
        );
        self.claims.insert(claim.release_claim_id.clone(), claim);
        self.evidence.insert(evidence.evidence_id.clone(), evidence);
        self.contracts
            .insert(contract.contract_id.clone(), contract.clone());
        self.refresh_indexes();
        Ok(contract)
    }

    pub fn generate_report(
        &mut self,
        report_id: impl Into<String>,
    ) -> LiquidityExhaustionRecoveryReport {
        let evidence: Vec<_> = self.evidence.values().cloned().collect();
        let claims: Vec<_> = self.claims.values().cloned().collect();
        let contracts: Vec<_> = self.contracts.values().cloned().collect();
        let report = LiquidityExhaustionRecoveryReport::from_contracts(
            &self.config,
            report_id,
            &evidence,
            &claims,
            &contracts,
        );
        self.reports.push(report.clone());
        if self.reports.len() > self.config.max_reports {
            let overflow = self.reports.len().saturating_sub(self.config.max_reports);
            self.reports.drain(0..overflow);
        }
        self.refresh_indexes();
        report
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "claims": self.claims.values().map(RecoveryClaimInput::public_record).collect::<Vec<_>>(),
            "evidence": self.evidence.values().map(PrivacyPreservingLiquidityEvidence::public_record).collect::<Vec<_>>(),
            "contracts": self.contracts.values().map(LiquidityExhaustionRecoveryContract::public_record).collect::<Vec<_>>(),
            "reports": self.reports.iter().map(LiquidityExhaustionRecoveryReport::public_record).collect::<Vec<_>>(),
            "counters": self.counters,
            "roots": self.roots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn refresh_indexes(&mut self) {
        self.counters = counters(self);
        self.roots = roots(self);
    }
}

fn counters(state: &State) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    counters.insert("claims".to_string(), state.claims.len() as u64);
    counters.insert("evidence".to_string(), state.evidence.len() as u64);
    counters.insert("contracts".to_string(), state.contracts.len() as u64);
    counters.insert("reports".to_string(), state.reports.len() as u64);
    counters.insert(
        "ready_contracts".to_string(),
        count_status_values(state.contracts.values(), RecoveryActionStatus::Ready),
    );
    counters.insert(
        "partial_contracts".to_string(),
        count_status_values(state.contracts.values(), RecoveryActionStatus::Partial),
    );
    counters.insert(
        "held_contracts".to_string(),
        count_status_values(state.contracts.values(), RecoveryActionStatus::Held),
    );
    counters.insert(
        "blocked_contracts".to_string(),
        count_status_values(state.contracts.values(), RecoveryActionStatus::Blocked),
    );
    counters.insert(
        "user_release_blockers".to_string(),
        state
            .contracts
            .values()
            .map(|contract| contract.user_release_blockers)
            .sum(),
    );
    counters.insert(
        "production_blockers".to_string(),
        state
            .contracts
            .values()
            .map(|contract| contract.production_blockers)
            .sum(),
    );
    counters
}

fn roots(state: &State) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    let claim_leaves = state
        .claims
        .values()
        .map(|record| Value::String(record.state_root()))
        .collect::<Vec<_>>();
    let evidence_leaves = state
        .evidence
        .values()
        .map(|record| Value::String(record.state_root()))
        .collect::<Vec<_>>();
    let contract_leaves = state
        .contracts
        .values()
        .map(|record| Value::String(record.state_root()))
        .collect::<Vec<_>>();
    let report_leaves = state
        .reports
        .iter()
        .map(|record| Value::String(record.state_root()))
        .collect::<Vec<_>>();
    roots.insert("config_root".to_string(), state.config.state_root());
    roots.insert(
        "claim_root".to_string(),
        merkle_root(
            "liquidity-exhaustion-recovery-state-claim-root",
            &claim_leaves,
        ),
    );
    roots.insert(
        "evidence_root".to_string(),
        merkle_root(
            "liquidity-exhaustion-recovery-state-evidence-root",
            &evidence_leaves,
        ),
    );
    roots.insert(
        "contract_root".to_string(),
        merkle_root(
            "liquidity-exhaustion-recovery-state-contract-root",
            &contract_leaves,
        ),
    );
    roots.insert(
        "report_root".to_string(),
        merkle_root(
            "liquidity-exhaustion-recovery-state-report-root",
            &report_leaves,
        ),
    );
    roots
}

fn evidence_status(
    config: &Config,
    evidence_shares: u64,
    privacy_set_size: u64,
    pq_security_bits: u16,
    coverage_bps: u64,
    low_fee_bps: u64,
) -> LiquidityEvidenceStatus {
    if evidence_shares < config.min_evidence_shares
        || privacy_set_size < config.min_privacy_set_size
        || pq_security_bits < config.min_pq_security_bits
        || low_fee_bps > config.max_low_fee_bps
    {
        LiquidityEvidenceStatus::Insufficient
    } else if coverage_bps < config.min_coverage_bps {
        LiquidityEvidenceStatus::Degraded
    } else {
        LiquidityEvidenceStatus::Sufficient
    }
}

fn contract_status(
    evidence_status: LiquidityEvidenceStatus,
    settled_amount: u128,
    requested_amount: u128,
    user_release_blockers: u64,
    production_blockers: u64,
) -> RecoveryActionStatus {
    if production_blockers > 0 || evidence_status == LiquidityEvidenceStatus::Insufficient {
        RecoveryActionStatus::Blocked
    } else if user_release_blockers > 0 {
        RecoveryActionStatus::Held
    } else if settled_amount < requested_amount {
        RecoveryActionStatus::Partial
    } else {
        RecoveryActionStatus::Ready
    }
}

fn primary_lane(
    status: RecoveryActionStatus,
    reserve_release_amount: u128,
    backstop_amount: u128,
    auction_amount: u128,
    fallback_amount: u128,
    user_release_blockers: u64,
    production_blockers: u64,
) -> RecoveryLane {
    if production_blockers > 0 {
        RecoveryLane::ProductionBlocker
    } else if user_release_blockers > 0 || status == RecoveryActionStatus::Held {
        RecoveryLane::UserReleaseBlocker
    } else if fallback_amount > 0 {
        RecoveryLane::FallbackEscrow
    } else if auction_amount > 0 {
        RecoveryLane::AuctionFill
    } else if backstop_amount > 0 {
        RecoveryLane::BackstopDraw
    } else if reserve_release_amount > 0 {
        RecoveryLane::ReserveRelease
    } else {
        RecoveryLane::PartialSettlement
    }
}

fn report_status(
    blocked_contracts: u64,
    held_contracts: u64,
    partial_contracts: u64,
    production_blockers: u64,
) -> RecoveryReportStatus {
    if blocked_contracts > 0 || production_blockers > 0 {
        RecoveryReportStatus::Blocked
    } else if held_contracts > 0 || partial_contracts > 0 {
        RecoveryReportStatus::Watch
    } else {
        RecoveryReportStatus::Ready
    }
}

fn user_release_blockers(
    config: &Config,
    evidence: &PrivacyPreservingLiquidityEvidence,
    residual_amount: u128,
) -> u64 {
    let residual_blocker = u64::from(residual_amount > 0);
    let coverage_blocker = u64::from(evidence.coverage_bps < config.min_coverage_bps);
    residual_blocker.saturating_add(coverage_blocker)
}

fn production_blockers(config: &Config, evidence: &PrivacyPreservingLiquidityEvidence) -> u64 {
    let adapter_live_blockers = [
        config.reserve_release_adapter_live,
        config.bridge_liquidity_live,
        config.claim_queue_handler_live,
        config.settlement_execution_live,
    ]
    .iter()
    .filter(|live| !**live)
    .count() as u64;
    let evidence_blocker = u64::from(
        config.fail_closed_on_evidence_gap
            && evidence.status == LiquidityEvidenceStatus::Insufficient,
    );
    let deferred_blockers = [
        config.cargo_checks_deferred,
        config.runtime_tests_deferred,
        config.security_audit_deferred,
    ]
    .iter()
    .filter(|deferred| **deferred)
    .count() as u64;
    adapter_live_blockers
        .saturating_add(evidence_blocker)
        .saturating_add(deferred_blockers)
}

fn partial_count(config: &Config, requested_amount: u128, settled_amount: u128) -> u64 {
    if settled_amount == 0 || settled_amount >= requested_amount {
        0
    } else {
        let remaining = requested_amount.saturating_sub(settled_amount);
        let nominal_slice = requested_amount
            .saturating_div(config.max_partial_settlements.max(1) as u128)
            .max(1);
        let count = remaining
            .saturating_add(nominal_slice.saturating_sub(1))
            .saturating_div(nominal_slice) as u64;
        count.clamp(1, config.max_partial_settlements.max(1))
    }
}

fn hold_reason(
    status: RecoveryActionStatus,
    user_release_blockers: u64,
    production_blockers: u64,
    residual_amount: u128,
) -> String {
    match status {
        RecoveryActionStatus::Ready => "none".to_string(),
        RecoveryActionStatus::Partial => format!("partial_settlement_residual_{residual_amount}"),
        RecoveryActionStatus::Held => format!("user_release_blockers_{user_release_blockers}"),
        RecoveryActionStatus::Blocked => format!("production_blockers_{production_blockers}"),
    }
}

fn count_status(
    contracts: &[LiquidityExhaustionRecoveryContract],
    status: RecoveryActionStatus,
) -> u64 {
    contracts
        .iter()
        .filter(|contract| contract.status == status)
        .count() as u64
}

fn count_status_values<'a>(
    contracts: impl Iterator<Item = &'a LiquidityExhaustionRecoveryContract>,
    status: RecoveryActionStatus,
) -> u64 {
    contracts
        .filter(|contract| contract.status == status)
        .count() as u64
}

fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator
            .saturating_mul(MAX_BPS as u128)
            .saturating_div(denominator)
            .min(u64::MAX as u128) as u64
    }
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn liquidity_bucket_root(
    evidence_id: &str,
    reserve_account_root: &str,
    bridge_liquidity_root: &str,
    coverage_bps: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-liquidity-bucket",
        &[
            HashPart::Str(evidence_id),
            HashPart::Str(reserve_account_root),
            HashPart::Str(bridge_liquidity_root),
            HashPart::U64(coverage_bps),
        ],
    )
}

fn provider_set_root(
    evidence_id: &str,
    claim_queue_root: &str,
    privacy_set_size: u64,
    evidence_shares: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-provider-set",
        &[
            HashPart::Str(evidence_id),
            HashPart::Str(claim_queue_root),
            HashPart::U64(privacy_set_size),
            HashPart::U64(evidence_shares),
        ],
    )
}

fn range_proof_root(
    evidence_id: &str,
    requested_amount: u128,
    available_amount: u128,
    coverage_bps: u64,
    low_fee_bps: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-range-proof",
        &[
            HashPart::Str(evidence_id),
            HashPart::Int(requested_amount as i128),
            HashPart::Int(available_amount as i128),
            HashPart::U64(coverage_bps),
            HashPart::U64(low_fee_bps),
        ],
    )
}

fn nullifier_set_root(
    evidence_id: &str,
    live_settlement_root: &str,
    ordinal: u64,
    evidence_shares: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-nullifier-set",
        &[
            HashPart::Str(evidence_id),
            HashPart::Str(live_settlement_root),
            HashPart::U64(ordinal),
            HashPart::U64(evidence_shares),
        ],
    )
}

fn claim_order_root(
    release_claim_id: &str,
    queue_position: u64,
    challenge_window_end: u64,
    ordinal: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-claim-order",
        &[
            HashPart::Str(release_claim_id),
            HashPart::U64(queue_position),
            HashPart::U64(challenge_window_end),
            HashPart::U64(ordinal),
        ],
    )
}

fn reserve_release_root(
    release_claim_id: &str,
    reserve_release_amount: u128,
    reserve_available: u128,
    reserve_account_root: &str,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-reserve-release",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Int(reserve_release_amount as i128),
            HashPart::Int(reserve_available as i128),
            HashPart::Str(reserve_account_root),
        ],
    )
}

fn backstop_root(
    release_claim_id: &str,
    backstop_amount: u128,
    backstop_available: u128,
    blinded_liquidity_bucket_root: &str,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-backstop",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Int(backstop_amount as i128),
            HashPart::Int(backstop_available as i128),
            HashPart::Str(blinded_liquidity_bucket_root),
        ],
    )
}

fn auction_root(
    release_claim_id: &str,
    auction_amount: u128,
    auction_available: u128,
    coverage_bps: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-auction",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Int(auction_amount as i128),
            HashPart::Int(auction_available as i128),
            HashPart::U64(coverage_bps),
        ],
    )
}

fn fallback_root(
    release_claim_id: &str,
    fallback_amount: u128,
    fallback_available: u128,
    residual_amount: u128,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-fallback",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Int(fallback_amount as i128),
            HashPart::Int(fallback_available as i128),
            HashPart::Int(residual_amount as i128),
        ],
    )
}

fn partial_settlement_root(
    release_claim_id: &str,
    partial_settlement_index: u64,
    partial_settlement_count: u64,
    settled_amount: u128,
    residual_amount: u128,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-partial-settlement",
        &[
            HashPart::Str(release_claim_id),
            HashPart::U64(partial_settlement_index),
            HashPart::U64(partial_settlement_count),
            HashPart::Int(settled_amount as i128),
            HashPart::Int(residual_amount as i128),
        ],
    )
}

fn live_execution_payload_root(
    release_claim_id: &str,
    claim_order_root: &str,
    reserve_release_root: &str,
    partial_settlement_root: &str,
    low_fee_cap_bps: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-live-execution-payload",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(claim_order_root),
            HashPart::Str(reserve_release_root),
            HashPart::Str(partial_settlement_root),
            HashPart::U64(low_fee_cap_bps),
        ],
    )
}

fn blocker_root(
    release_claim_id: &str,
    user_release_blockers: u64,
    production_blockers: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-blocker",
        &[
            HashPart::Str(release_claim_id),
            HashPart::U64(user_release_blockers),
            HashPart::U64(production_blockers),
            HashPart::Str(evidence_root),
        ],
    )
}

fn recovery_sequence_root(
    report_id: &str,
    config_root: &str,
    evidence_root: &str,
    contract_root: &str,
    claim_input_root: &str,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-sequence",
        &[
            HashPart::Str(report_id),
            HashPart::Str(config_root),
            HashPart::Str(evidence_root),
            HashPart::Str(contract_root),
            HashPart::Str(claim_input_root),
        ],
    )
}

fn adapter_alignment_root(adapter_name: &str, root: &str, count: u64) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-adapter-alignment",
        &[
            HashPart::Str(adapter_name),
            HashPart::Str(root),
            HashPart::U64(count),
        ],
    )
}

fn bridge_liquidity_position_root(
    release_claim_id: &str,
    requested_amount: u128,
    ordinal: u64,
) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-bridge-liquidity-position",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Int(requested_amount as i128),
            HashPart::U64(ordinal),
        ],
    )
}

fn live_settlement_payload_hint_root(release_claim_id: &str, ordinal: u64) -> String {
    domain_hash(
        "liquidity-exhaustion-recovery-live-settlement-payload-hint",
        &[HashPart::Str(release_claim_id), HashPart::U64(ordinal)],
    )
}
