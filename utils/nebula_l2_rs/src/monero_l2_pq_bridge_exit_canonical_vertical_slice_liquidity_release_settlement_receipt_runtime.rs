use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceLiquidityReleaseSettlementReceiptRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_LIQUIDITY_RELEASE_SETTLEMENT_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-liquidity-release-settlement-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_LIQUIDITY_RELEASE_SETTLEMENT_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str =
    "canonical-liquidity-release-settlement-receipt-private-l2-spine-v1";
pub const RESERVE_BUCKET_ROOT_SCHEME: &str =
    "monero-private-l2-reserve-bucket-root-release-settlement-v1";
pub const AMOUNT_COMMITMENT_SCHEME: &str = "monero-private-l2-release-amount-commitment-receipt-v1";
pub const COVERAGE_RECEIPT_SCHEME: &str = "monero-private-l2-release-coverage-receipt-root-v1";
pub const BACKSTOP_SETTLEMENT_SCHEME: &str =
    "monero-private-l2-release-backstop-settlement-root-v1";
pub const FEE_CAP_RECEIPT_SCHEME: &str = "monero-private-l2-release-fee-cap-receipt-root-v1";
pub const QUEUE_PRIORITY_RECEIPT_SCHEME: &str =
    "monero-private-l2-release-queue-priority-receipt-root-v1";
pub const PARTIAL_FILL_RECEIPT_SCHEME: &str =
    "monero-private-l2-release-partial-fill-receipt-root-v1";
pub const SHORTFALL_HOLD_SCHEME: &str = "monero-private-l2-release-shortfall-hold-root-v1";
pub const SETTLEMENT_ROOT_SCHEME: &str = "monero-private-l2-release-settlement-root-v1";
pub const DEFAULT_CURRENT_L2_HEIGHT: u64 = 8_960;
pub const DEFAULT_CURRENT_MONERO_HEIGHT: u64 = 3_514_480;
pub const DEFAULT_RELEASE_FINALITY_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_BACKSTOP_TRIGGER_BPS: u64 = 9_500;
pub const DEFAULT_PARTIAL_FILL_TRIGGER_BPS: u64 = 7_500;
pub const DEFAULT_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_EMERGENCY_FEE_CAP_BPS: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_RECEIPTS: usize = 512;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveBucketKind {
    ForcedExitHot,
    ForcedExitWarm,
    DelayedCold,
    MakerCredit,
    InsuranceBackstop,
    GovernanceBuffer,
}

impl ReserveBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedExitHot => "forced_exit_hot",
            Self::ForcedExitWarm => "forced_exit_warm",
            Self::DelayedCold => "delayed_cold",
            Self::MakerCredit => "maker_credit",
            Self::InsuranceBackstop => "insurance_backstop",
            Self::GovernanceBuffer => "governance_buffer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseIntentKind {
    ForcedExitUserClaim,
    BatchNetting,
    ChallengeResolution,
    WatchtowerEscalation,
    EmergencyWithdrawal,
}

impl ReleaseIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedExitUserClaim => "forced_exit_user_claim",
            Self::BatchNetting => "batch_netting",
            Self::ChallengeResolution => "challenge_resolution",
            Self::WatchtowerEscalation => "watchtower_escalation",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyWithdrawal => 10,
            Self::WatchtowerEscalation => 20,
            Self::ChallengeResolution => 30,
            Self::ForcedExitUserClaim => 40,
            Self::BatchNetting => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Watch,
    Held,
    Rejected,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Held | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopLaneKind {
    None,
    MakerBond,
    InsuranceVault,
    WatchtowerEscrow,
    GovernanceBuffer,
    EmergencyCredit,
}

impl BackstopLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MakerBond => "maker_bond",
            Self::InsuranceVault => "insurance_vault",
            Self::WatchtowerEscrow => "watchtower_escrow",
            Self::GovernanceBuffer => "governance_buffer",
            Self::EmergencyCredit => "emergency_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReasonKind {
    None,
    CoverageBelowMinimum,
    BackstopPending,
    FeeCapExceeded,
    QueuePriorityDeferred,
    PartialFillBelowThreshold,
    ShortfallUnfunded,
    WatcherQuorumMissing,
    PrivacyFloorNotMet,
    FinalityPending,
}

impl HoldReasonKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CoverageBelowMinimum => "coverage_below_minimum",
            Self::BackstopPending => "backstop_pending",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::QueuePriorityDeferred => "queue_priority_deferred",
            Self::PartialFillBelowThreshold => "partial_fill_below_threshold",
            Self::ShortfallUnfunded => "shortfall_unfunded",
            Self::WatcherQuorumMissing => "watcher_quorum_missing",
            Self::PrivacyFloorNotMet => "privacy_floor_not_met",
            Self::FinalityPending => "finality_pending",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_suite: String,
    pub reserve_bucket_root_scheme: String,
    pub amount_commitment_scheme: String,
    pub coverage_receipt_scheme: String,
    pub backstop_settlement_scheme: String,
    pub fee_cap_receipt_scheme: String,
    pub queue_priority_receipt_scheme: String,
    pub partial_fill_receipt_scheme: String,
    pub shortfall_hold_scheme: String,
    pub settlement_root_scheme: String,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub release_finality_blocks: u64,
    pub min_coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub backstop_trigger_bps: u64,
    pub partial_fill_trigger_bps: u64,
    pub fee_cap_bps: u64,
    pub emergency_fee_cap_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_watcher_quorum: u64,
    pub max_receipts: usize,
    pub require_backstop_when_below_minimum: bool,
    pub fail_closed_on_shortfall: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            reserve_bucket_root_scheme: RESERVE_BUCKET_ROOT_SCHEME.to_string(),
            amount_commitment_scheme: AMOUNT_COMMITMENT_SCHEME.to_string(),
            coverage_receipt_scheme: COVERAGE_RECEIPT_SCHEME.to_string(),
            backstop_settlement_scheme: BACKSTOP_SETTLEMENT_SCHEME.to_string(),
            fee_cap_receipt_scheme: FEE_CAP_RECEIPT_SCHEME.to_string(),
            queue_priority_receipt_scheme: QUEUE_PRIORITY_RECEIPT_SCHEME.to_string(),
            partial_fill_receipt_scheme: PARTIAL_FILL_RECEIPT_SCHEME.to_string(),
            shortfall_hold_scheme: SHORTFALL_HOLD_SCHEME.to_string(),
            settlement_root_scheme: SETTLEMENT_ROOT_SCHEME.to_string(),
            current_l2_height: DEFAULT_CURRENT_L2_HEIGHT,
            current_monero_height: DEFAULT_CURRENT_MONERO_HEIGHT,
            release_finality_blocks: DEFAULT_RELEASE_FINALITY_BLOCKS,
            min_coverage_bps: DEFAULT_MIN_COVERAGE_BPS,
            target_coverage_bps: DEFAULT_TARGET_COVERAGE_BPS,
            backstop_trigger_bps: DEFAULT_BACKSTOP_TRIGGER_BPS,
            partial_fill_trigger_bps: DEFAULT_PARTIAL_FILL_TRIGGER_BPS,
            fee_cap_bps: DEFAULT_FEE_CAP_BPS,
            emergency_fee_cap_bps: DEFAULT_EMERGENCY_FEE_CAP_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            require_backstop_when_below_minimum: true,
            fail_closed_on_shortfall: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_suite": self.receipt_suite,
            "reserve_bucket_root_scheme": self.reserve_bucket_root_scheme,
            "amount_commitment_scheme": self.amount_commitment_scheme,
            "coverage_receipt_scheme": self.coverage_receipt_scheme,
            "backstop_settlement_scheme": self.backstop_settlement_scheme,
            "fee_cap_receipt_scheme": self.fee_cap_receipt_scheme,
            "queue_priority_receipt_scheme": self.queue_priority_receipt_scheme,
            "partial_fill_receipt_scheme": self.partial_fill_receipt_scheme,
            "shortfall_hold_scheme": self.shortfall_hold_scheme,
            "settlement_root_scheme": self.settlement_root_scheme,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "release_finality_blocks": self.release_finality_blocks,
            "min_coverage_bps": self.min_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "backstop_trigger_bps": self.backstop_trigger_bps,
            "partial_fill_trigger_bps": self.partial_fill_trigger_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "emergency_fee_cap_bps": self.emergency_fee_cap_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_receipts": self.max_receipts,
            "require_backstop_when_below_minimum": self.require_backstop_when_below_minimum,
            "fail_closed_on_shortfall": self.fail_closed_on_shortfall
        })
    }

    pub fn state_root(&self) -> String {
        digest_record("LIQUIDITY-RELEASE-SETTLEMENT-CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveBucketReceipt {
    pub bucket_id: String,
    pub bucket_kind: ReserveBucketKind,
    pub reserve_asset_id: String,
    pub reserve_bucket_root_before: String,
    pub reserve_bucket_root_after: String,
    pub available_before_atomic: u128,
    pub available_after_atomic: u128,
    pub reserved_for_release_atomic: u128,
    pub bucket_epoch: u64,
}

impl ReserveBucketReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_bucket_root_before": self.reserve_bucket_root_before,
            "reserve_bucket_root_after": self.reserve_bucket_root_after,
            "available_before_atomic": self.available_before_atomic,
            "available_after_atomic": self.available_after_atomic,
            "reserved_for_release_atomic": self.reserved_for_release_atomic,
            "bucket_epoch": self.bucket_epoch
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-RESERVE-BUCKET-ROOT",
            &[
                HashPart::Str(RESERVE_BUCKET_ROOT_SCHEME),
                HashPart::Str(&self.bucket_id),
                HashPart::Str(self.bucket_kind.as_str()),
                HashPart::Str(&self.reserve_asset_id),
                HashPart::Str(&self.reserve_bucket_root_before),
                HashPart::Str(&self.reserve_bucket_root_after),
                HashPart::U128(self.available_before_atomic),
                HashPart::U128(self.available_after_atomic),
                HashPart::U128(self.reserved_for_release_atomic),
                HashPart::U64(self.bucket_epoch),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AmountCommitmentReceipt {
    pub release_id: String,
    pub claim_id: String,
    pub claimant_commitment: String,
    pub amount_commitment_root: String,
    pub amount_range_proof_root: String,
    pub requested_atomic: u128,
    pub committed_atomic: u128,
    pub asset_id: String,
    pub blinding_root: String,
}

impl AmountCommitmentReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "claim_id": self.claim_id,
            "claimant_commitment": self.claimant_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "amount_range_proof_root": self.amount_range_proof_root,
            "requested_atomic": self.requested_atomic,
            "committed_atomic": self.committed_atomic,
            "asset_id": self.asset_id,
            "blinding_root": self.blinding_root
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-AMOUNT-COMMITMENT-ROOT",
            &[
                HashPart::Str(AMOUNT_COMMITMENT_SCHEME),
                HashPart::Str(&self.release_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.claimant_commitment),
                HashPart::Str(&self.amount_commitment_root),
                HashPart::Str(&self.amount_range_proof_root),
                HashPart::U128(self.requested_atomic),
                HashPart::U128(self.committed_atomic),
                HashPart::Str(&self.asset_id),
                HashPart::Str(&self.blinding_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverageReceipt {
    pub coverage_receipt_id: String,
    pub reserve_bucket_root: String,
    pub amount_commitment_root: String,
    pub coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub watcher_quorum: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: ReceiptStatus,
}

impl CoverageReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "coverage_receipt_id": self.coverage_receipt_id,
            "reserve_bucket_root": self.reserve_bucket_root,
            "amount_commitment_root": self.amount_commitment_root,
            "coverage_bps": self.coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "watcher_quorum": self.watcher_quorum,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-COVERAGE-RECEIPT-ROOT",
            &[
                HashPart::Str(COVERAGE_RECEIPT_SCHEME),
                HashPart::Str(&self.coverage_receipt_id),
                HashPart::Str(&self.reserve_bucket_root),
                HashPart::Str(&self.amount_commitment_root),
                HashPart::U64(self.coverage_bps),
                HashPart::U64(self.target_coverage_bps),
                HashPart::U64(self.watcher_quorum),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackstopSettlementReceipt {
    pub backstop_id: String,
    pub lane: BackstopLaneKind,
    pub lane_root_before: String,
    pub lane_root_after: String,
    pub trigger_bps: u64,
    pub provided_atomic: u128,
    pub settlement_credit_root: String,
    pub sponsor_commitment: String,
    pub status: ReceiptStatus,
}

impl BackstopSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "backstop_id": self.backstop_id,
            "lane": self.lane.as_str(),
            "lane_root_before": self.lane_root_before,
            "lane_root_after": self.lane_root_after,
            "trigger_bps": self.trigger_bps,
            "provided_atomic": self.provided_atomic,
            "settlement_credit_root": self.settlement_credit_root,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-BACKSTOP-SETTLEMENT-ROOT",
            &[
                HashPart::Str(BACKSTOP_SETTLEMENT_SCHEME),
                HashPart::Str(&self.backstop_id),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.lane_root_before),
                HashPart::Str(&self.lane_root_after),
                HashPart::U64(self.trigger_bps),
                HashPart::U128(self.provided_atomic),
                HashPart::Str(&self.settlement_credit_root),
                HashPart::Str(&self.sponsor_commitment),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCapReceipt {
    pub fee_receipt_id: String,
    pub fee_asset_id: String,
    pub estimated_fee_atomic: u128,
    pub charged_fee_atomic: u128,
    pub fee_cap_bps: u64,
    pub fee_cap_atomic: u128,
    pub low_fee_lane_root: String,
    pub status: ReceiptStatus,
}

impl FeeCapReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_receipt_id": self.fee_receipt_id,
            "fee_asset_id": self.fee_asset_id,
            "estimated_fee_atomic": self.estimated_fee_atomic,
            "charged_fee_atomic": self.charged_fee_atomic,
            "fee_cap_bps": self.fee_cap_bps,
            "fee_cap_atomic": self.fee_cap_atomic,
            "low_fee_lane_root": self.low_fee_lane_root,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-FEE-CAP-RECEIPT-ROOT",
            &[
                HashPart::Str(FEE_CAP_RECEIPT_SCHEME),
                HashPart::Str(&self.fee_receipt_id),
                HashPart::Str(&self.fee_asset_id),
                HashPart::U128(self.estimated_fee_atomic),
                HashPart::U128(self.charged_fee_atomic),
                HashPart::U64(self.fee_cap_bps),
                HashPart::U128(self.fee_cap_atomic),
                HashPart::Str(&self.low_fee_lane_root),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QueuePriorityReceipt {
    pub queue_receipt_id: String,
    pub intent_kind: ReleaseIntentKind,
    pub queue_root_before: String,
    pub queue_root_after: String,
    pub sequence: u64,
    pub priority_score: u64,
    pub expires_at_l2_height: u64,
    pub anti_starvation_root: String,
    pub status: ReceiptStatus,
}

impl QueuePriorityReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_receipt_id": self.queue_receipt_id,
            "intent_kind": self.intent_kind.as_str(),
            "queue_root_before": self.queue_root_before,
            "queue_root_after": self.queue_root_after,
            "sequence": self.sequence,
            "priority_score": self.priority_score,
            "expires_at_l2_height": self.expires_at_l2_height,
            "anti_starvation_root": self.anti_starvation_root,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-QUEUE-PRIORITY-RECEIPT-ROOT",
            &[
                HashPart::Str(QUEUE_PRIORITY_RECEIPT_SCHEME),
                HashPart::Str(&self.queue_receipt_id),
                HashPart::Str(self.intent_kind.as_str()),
                HashPart::Str(&self.queue_root_before),
                HashPart::Str(&self.queue_root_after),
                HashPart::U64(self.sequence),
                HashPart::U64(self.priority_score),
                HashPart::U64(self.expires_at_l2_height),
                HashPart::Str(&self.anti_starvation_root),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PartialFillReceipt {
    pub partial_fill_id: String,
    pub requested_atomic: u128,
    pub filled_atomic: u128,
    pub remaining_atomic: u128,
    pub fill_ratio_bps: u64,
    pub tranche_root: String,
    pub next_attempt_l2_height: u64,
    pub status: ReceiptStatus,
}

impl PartialFillReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "partial_fill_id": self.partial_fill_id,
            "requested_atomic": self.requested_atomic,
            "filled_atomic": self.filled_atomic,
            "remaining_atomic": self.remaining_atomic,
            "fill_ratio_bps": self.fill_ratio_bps,
            "tranche_root": self.tranche_root,
            "next_attempt_l2_height": self.next_attempt_l2_height,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-PARTIAL-FILL-RECEIPT-ROOT",
            &[
                HashPart::Str(PARTIAL_FILL_RECEIPT_SCHEME),
                HashPart::Str(&self.partial_fill_id),
                HashPart::U128(self.requested_atomic),
                HashPart::U128(self.filled_atomic),
                HashPart::U128(self.remaining_atomic),
                HashPart::U64(self.fill_ratio_bps),
                HashPart::Str(&self.tranche_root),
                HashPart::U64(self.next_attempt_l2_height),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShortfallHoldReceipt {
    pub hold_id: String,
    pub reason: HoldReasonKind,
    pub hold_root_before: String,
    pub hold_root_after: String,
    pub shortfall_atomic: u128,
    pub held_until_l2_height: u64,
    pub release_blocked: bool,
    pub remediation_root: String,
    pub status: ReceiptStatus,
}

impl ShortfallHoldReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "reason": self.reason.as_str(),
            "hold_root_before": self.hold_root_before,
            "hold_root_after": self.hold_root_after,
            "shortfall_atomic": self.shortfall_atomic,
            "held_until_l2_height": self.held_until_l2_height,
            "release_blocked": self.release_blocked,
            "remediation_root": self.remediation_root,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-SHORTFALL-HOLD-ROOT",
            &[
                HashPart::Str(SHORTFALL_HOLD_SCHEME),
                HashPart::Str(&self.hold_id),
                HashPart::Str(self.reason.as_str()),
                HashPart::Str(&self.hold_root_before),
                HashPart::Str(&self.hold_root_after),
                HashPart::U128(self.shortfall_atomic),
                HashPart::U64(self.held_until_l2_height),
                HashPart::Str(bool_str(self.release_blocked)),
                HashPart::Str(&self.remediation_root),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub release_id: String,
    pub reserve_bucket: ReserveBucketReceipt,
    pub amount_commitment: AmountCommitmentReceipt,
    pub coverage_receipt: CoverageReceipt,
    pub backstop_settlement: BackstopSettlementReceipt,
    pub fee_cap_receipt: FeeCapReceipt,
    pub queue_priority_receipt: QueuePriorityReceipt,
    pub partial_fill_receipt: PartialFillReceipt,
    pub shortfall_hold: ShortfallHoldReceipt,
    pub settlement_l2_height: u64,
    pub settlement_monero_height: u64,
    pub finality_target_l2_height: u64,
    pub settlement_status: ReceiptStatus,
    pub memo_root: String,
}

impl SettlementReceipt {
    pub fn component_roots(&self) -> BTreeMap<String, String> {
        let mut roots = BTreeMap::new();
        roots.insert(
            "reserve_bucket_root".to_string(),
            self.reserve_bucket.root(),
        );
        roots.insert(
            "amount_commitment_root".to_string(),
            self.amount_commitment.root(),
        );
        roots.insert(
            "coverage_receipt_root".to_string(),
            self.coverage_receipt.root(),
        );
        roots.insert(
            "backstop_settlement_root".to_string(),
            self.backstop_settlement.root(),
        );
        roots.insert(
            "fee_cap_receipt_root".to_string(),
            self.fee_cap_receipt.root(),
        );
        roots.insert(
            "queue_priority_receipt_root".to_string(),
            self.queue_priority_receipt.root(),
        );
        roots.insert(
            "partial_fill_receipt_root".to_string(),
            self.partial_fill_receipt.root(),
        );
        roots.insert(
            "shortfall_hold_root".to_string(),
            self.shortfall_hold.root(),
        );
        roots
    }

    pub fn component_root(&self) -> String {
        let leaves = self
            .component_roots()
            .into_iter()
            .map(|(label, root)| {
                domain_hash(
                    "LIQUIDITY-RELEASE-SETTLEMENT-COMPONENT-LEAF",
                    &[HashPart::Str(&label), HashPart::Str(&root)],
                    32,
                )
            })
            .collect::<Vec<_>>();
        merkle_root(&leaves)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "release_id": self.release_id,
            "reserve_bucket": self.reserve_bucket.public_record(),
            "amount_commitment": self.amount_commitment.public_record(),
            "coverage_receipt": self.coverage_receipt.public_record(),
            "backstop_settlement": self.backstop_settlement.public_record(),
            "fee_cap_receipt": self.fee_cap_receipt.public_record(),
            "queue_priority_receipt": self.queue_priority_receipt.public_record(),
            "partial_fill_receipt": self.partial_fill_receipt.public_record(),
            "shortfall_hold": self.shortfall_hold.public_record(),
            "settlement_l2_height": self.settlement_l2_height,
            "settlement_monero_height": self.settlement_monero_height,
            "finality_target_l2_height": self.finality_target_l2_height,
            "settlement_status": self.settlement_status.as_str(),
            "component_root": self.component_root(),
            "memo_root": self.memo_root
        })
    }

    pub fn settlement_root(&self, config_root: &str) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-SETTLEMENT-ROOT",
            &[
                HashPart::Str(SETTLEMENT_ROOT_SCHEME),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(config_root),
                HashPart::Str(&self.settlement_id),
                HashPart::Str(&self.release_id),
                HashPart::Str(&self.component_root()),
                HashPart::U64(self.settlement_l2_height),
                HashPart::U64(self.settlement_monero_height),
                HashPart::U64(self.finality_target_l2_height),
                HashPart::Str(self.settlement_status.as_str()),
                HashPart::Str(&self.memo_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationFinding {
    pub finding_id: String,
    pub reason: HoldReasonKind,
    pub status: ReceiptStatus,
    pub evidence_root: String,
    pub blocks_release: bool,
}

impl ValidationFinding {
    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "reason": self.reason.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "blocks_release": self.blocks_release
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "LIQUIDITY-RELEASE-SETTLEMENT-FINDING-ROOT",
            &[
                HashPart::Str(&self.finding_id),
                HashPart::Str(self.reason.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(bool_str(self.blocks_release)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReport {
    pub config_root: String,
    pub receipt_count: u64,
    pub accepted_count: u64,
    pub watch_count: u64,
    pub held_count: u64,
    pub rejected_count: u64,
    pub release_blocked_count: u64,
    pub total_requested_atomic: u128,
    pub total_filled_atomic: u128,
    pub total_shortfall_atomic: u128,
    pub settlement_receipt_root: String,
    pub finding_root: String,
    pub report_root: String,
}

impl SettlementReport {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "receipt_count": self.receipt_count,
            "accepted_count": self.accepted_count,
            "watch_count": self.watch_count,
            "held_count": self.held_count,
            "rejected_count": self.rejected_count,
            "release_blocked_count": self.release_blocked_count,
            "total_requested_atomic": self.total_requested_atomic,
            "total_filled_atomic": self.total_filled_atomic,
            "total_shortfall_atomic": self.total_shortfall_atomic,
            "settlement_receipt_root": self.settlement_receipt_root,
            "finding_root": self.finding_root,
            "report_root": self.report_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub receipts: Vec<SettlementReceipt>,
    pub findings: Vec<ValidationFinding>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            receipts: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn add_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> MoneroL2PqBridgeExitCanonicalVerticalSliceLiquidityReleaseSettlementReceiptRuntimeResult<
        String,
    >{
        if self.receipts.len() >= self.config.max_receipts {
            return Err("max receipt count exceeded".to_string());
        }
        let config = self.config.clone();
        let findings = validate_receipt(&config, &receipt);
        let root = receipt.settlement_root(&config.state_root());
        self.findings.extend(findings);
        self.receipts.push(receipt);
        Ok(root)
    }

    pub fn receipt_roots(&self) -> Vec<String> {
        let config_root = self.config.state_root();
        self.receipts
            .iter()
            .map(|receipt| receipt.settlement_root(&config_root))
            .collect()
    }

    pub fn settlement_receipt_root(&self) -> String {
        merkle_root(&self.receipt_roots())
    }

    pub fn finding_root(&self) -> String {
        let roots = self
            .findings
            .iter()
            .map(ValidationFinding::root)
            .collect::<Vec<_>>();
        merkle_root(&roots)
    }

    pub fn report(&self) -> SettlementReport {
        let mut accepted_count = 0_u64;
        let mut watch_count = 0_u64;
        let mut held_count = 0_u64;
        let mut rejected_count = 0_u64;
        let mut release_blocked_count = 0_u64;
        let mut total_requested_atomic = 0_u128;
        let mut total_filled_atomic = 0_u128;
        let mut total_shortfall_atomic = 0_u128;

        for receipt in &self.receipts {
            match receipt.settlement_status {
                ReceiptStatus::Accepted => accepted_count += 1,
                ReceiptStatus::Watch => watch_count += 1,
                ReceiptStatus::Held => held_count += 1,
                ReceiptStatus::Rejected => rejected_count += 1,
            }
            if receipt.settlement_status.blocks_release() || receipt.shortfall_hold.release_blocked
            {
                release_blocked_count += 1;
            }
            total_requested_atomic += receipt.amount_commitment.requested_atomic;
            total_filled_atomic += receipt.partial_fill_receipt.filled_atomic;
            total_shortfall_atomic += receipt.shortfall_hold.shortfall_atomic;
        }

        let config_root = self.config.state_root();
        let settlement_receipt_root = self.settlement_receipt_root();
        let finding_root = self.finding_root();
        let report_root = domain_hash(
            "LIQUIDITY-RELEASE-SETTLEMENT-REPORT-ROOT",
            &[
                HashPart::Str(&config_root),
                HashPart::U64(self.receipts.len() as u64),
                HashPart::U64(accepted_count),
                HashPart::U64(watch_count),
                HashPart::U64(held_count),
                HashPart::U64(rejected_count),
                HashPart::U64(release_blocked_count),
                HashPart::U128(total_requested_atomic),
                HashPart::U128(total_filled_atomic),
                HashPart::U128(total_shortfall_atomic),
                HashPart::Str(&settlement_receipt_root),
                HashPart::Str(&finding_root),
            ],
            32,
        );

        SettlementReport {
            config_root,
            receipt_count: self.receipts.len() as u64,
            accepted_count,
            watch_count,
            held_count,
            rejected_count,
            release_blocked_count,
            total_requested_atomic,
            total_filled_atomic,
            total_shortfall_atomic,
            settlement_receipt_root,
            finding_root,
            report_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let receipts = self
            .receipts
            .iter()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let findings = self
            .findings
            .iter()
            .map(ValidationFinding::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "receipts": receipts,
            "findings": findings,
            "report": self.report().public_record()
        })
    }

    pub fn state_root(&self) -> String {
        digest_record("LIQUIDITY-RELEASE-SETTLEMENT-STATE", &self.public_record())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn validate_receipt(config: &Config, receipt: &SettlementReceipt) -> Vec<ValidationFinding> {
    let mut findings = Vec::new();
    push_threshold_finding(
        &mut findings,
        "coverage-minimum",
        HoldReasonKind::CoverageBelowMinimum,
        receipt.coverage_receipt.coverage_bps >= config.min_coverage_bps,
        receipt.coverage_receipt.root(),
        true,
    );
    push_threshold_finding(
        &mut findings,
        "watcher-quorum",
        HoldReasonKind::WatcherQuorumMissing,
        receipt.coverage_receipt.watcher_quorum >= config.min_watcher_quorum,
        receipt.coverage_receipt.root(),
        true,
    );
    push_threshold_finding(
        &mut findings,
        "privacy-floor",
        HoldReasonKind::PrivacyFloorNotMet,
        receipt.coverage_receipt.privacy_set_size >= config.min_privacy_set_size,
        receipt.coverage_receipt.root(),
        true,
    );
    push_threshold_finding(
        &mut findings,
        "pq-security",
        HoldReasonKind::PrivacyFloorNotMet,
        receipt.coverage_receipt.pq_security_bits >= config.min_pq_security_bits,
        receipt.coverage_receipt.root(),
        true,
    );
    push_threshold_finding(
        &mut findings,
        "fee-cap",
        HoldReasonKind::FeeCapExceeded,
        receipt.fee_cap_receipt.charged_fee_atomic <= receipt.fee_cap_receipt.fee_cap_atomic
            && receipt.fee_cap_receipt.fee_cap_bps <= config.fee_cap_bps,
        receipt.fee_cap_receipt.root(),
        true,
    );
    push_threshold_finding(
        &mut findings,
        "partial-fill",
        HoldReasonKind::PartialFillBelowThreshold,
        receipt.partial_fill_receipt.fill_ratio_bps >= config.partial_fill_trigger_bps
            || receipt.partial_fill_receipt.remaining_atomic == 0,
        receipt.partial_fill_receipt.root(),
        false,
    );
    push_threshold_finding(
        &mut findings,
        "shortfall-hold",
        HoldReasonKind::ShortfallUnfunded,
        receipt.shortfall_hold.shortfall_atomic == 0 || !config.fail_closed_on_shortfall,
        receipt.shortfall_hold.root(),
        config.fail_closed_on_shortfall,
    );
    push_threshold_finding(
        &mut findings,
        "finality",
        HoldReasonKind::FinalityPending,
        receipt.finality_target_l2_height <= config.current_l2_height,
        receipt.component_root(),
        false,
    );

    if config.require_backstop_when_below_minimum
        && receipt.coverage_receipt.coverage_bps < config.min_coverage_bps
    {
        push_threshold_finding(
            &mut findings,
            "backstop-required",
            HoldReasonKind::BackstopPending,
            receipt.backstop_settlement.provided_atomic >= receipt.shortfall_hold.shortfall_atomic
                && receipt.backstop_settlement.status != ReceiptStatus::Rejected,
            receipt.backstop_settlement.root(),
            true,
        );
    }

    findings
}

pub fn build_settlement_receipt(
    config: &Config,
    release_id: &str,
    claim_id: &str,
    claimant_commitment: &str,
    requested_atomic: u128,
    available_before_atomic: u128,
    charged_fee_atomic: u128,
    intent_kind: ReleaseIntentKind,
) -> SettlementReceipt {
    let reserve_after = available_before_atomic.saturating_sub(requested_atomic);
    let filled_atomic = requested_atomic.min(available_before_atomic);
    let remaining_atomic = requested_atomic.saturating_sub(filled_atomic);
    let fill_ratio_bps = ratio_bps(filled_atomic, requested_atomic);
    let coverage_bps = ratio_bps(available_before_atomic, requested_atomic);
    let fee_cap_atomic =
        requested_atomic.saturating_mul(config.fee_cap_bps as u128) / MAX_BPS as u128;
    let shortfall_status = if remaining_atomic == 0 {
        ReceiptStatus::Accepted
    } else {
        ReceiptStatus::Held
    };
    let coverage_status = if coverage_bps >= config.min_coverage_bps {
        ReceiptStatus::Accepted
    } else if coverage_bps >= config.backstop_trigger_bps {
        ReceiptStatus::Watch
    } else {
        ReceiptStatus::Held
    };
    let fee_status = if charged_fee_atomic <= fee_cap_atomic {
        ReceiptStatus::Accepted
    } else {
        ReceiptStatus::Rejected
    };
    let settlement_status = derive_settlement_status(
        coverage_status,
        fee_status,
        shortfall_status,
        fill_ratio_bps,
        config.partial_fill_trigger_bps,
    );
    let settlement_l2_height = config.current_l2_height;

    let reserve_bucket = ReserveBucketReceipt {
        bucket_id: stable_id("reserve-bucket", release_id, claim_id),
        bucket_kind: ReserveBucketKind::ForcedExitHot,
        reserve_asset_id: "xmr-atomic".to_string(),
        reserve_bucket_root_before: stable_root(
            "reserve-before",
            release_id,
            available_before_atomic,
        ),
        reserve_bucket_root_after: stable_root("reserve-after", release_id, reserve_after),
        available_before_atomic,
        available_after_atomic: reserve_after,
        reserved_for_release_atomic: filled_atomic,
        bucket_epoch: config.current_l2_height / 720,
    };
    let amount_commitment = AmountCommitmentReceipt {
        release_id: release_id.to_string(),
        claim_id: claim_id.to_string(),
        claimant_commitment: claimant_commitment.to_string(),
        amount_commitment_root: stable_root("amount-commitment", release_id, requested_atomic),
        amount_range_proof_root: stable_id("amount-range-proof", release_id, claim_id),
        requested_atomic,
        committed_atomic: requested_atomic,
        asset_id: "xmr-atomic".to_string(),
        blinding_root: stable_id("amount-blinding", release_id, claimant_commitment),
    };
    let reserve_bucket_root = reserve_bucket.root();
    let amount_commitment_root = amount_commitment.root();
    let coverage_receipt = CoverageReceipt {
        coverage_receipt_id: stable_id("coverage", release_id, claim_id),
        reserve_bucket_root,
        amount_commitment_root,
        coverage_bps,
        target_coverage_bps: config.target_coverage_bps,
        watcher_quorum: config.min_watcher_quorum,
        privacy_set_size: config.min_privacy_set_size,
        pq_security_bits: config.min_pq_security_bits,
        status: coverage_status,
    };
    let backstop_settlement = BackstopSettlementReceipt {
        backstop_id: stable_id("backstop", release_id, claim_id),
        lane: if remaining_atomic > 0 {
            BackstopLaneKind::InsuranceVault
        } else {
            BackstopLaneKind::None
        },
        lane_root_before: stable_id("backstop-before", release_id, claim_id),
        lane_root_after: stable_id("backstop-after", release_id, claim_id),
        trigger_bps: config.backstop_trigger_bps,
        provided_atomic: remaining_atomic,
        settlement_credit_root: stable_root("backstop-credit", release_id, remaining_atomic),
        sponsor_commitment: stable_id("backstop-sponsor", release_id, "insurance"),
        status: if remaining_atomic > 0 {
            ReceiptStatus::Watch
        } else {
            ReceiptStatus::Accepted
        },
    };
    let fee_cap_receipt = FeeCapReceipt {
        fee_receipt_id: stable_id("fee", release_id, claim_id),
        fee_asset_id: "xmr-atomic".to_string(),
        estimated_fee_atomic: charged_fee_atomic,
        charged_fee_atomic,
        fee_cap_bps: config.fee_cap_bps,
        fee_cap_atomic,
        low_fee_lane_root: stable_id("low-fee-lane", release_id, claim_id),
        status: fee_status,
    };
    let queue_priority_receipt = QueuePriorityReceipt {
        queue_receipt_id: stable_id("queue", release_id, claim_id),
        intent_kind,
        queue_root_before: stable_id("queue-before", release_id, claim_id),
        queue_root_after: stable_id("queue-after", release_id, claim_id),
        sequence: config.current_l2_height,
        priority_score: intent_kind.base_priority(),
        expires_at_l2_height: config.current_l2_height + config.release_finality_blocks * 4,
        anti_starvation_root: stable_id("anti-starvation", release_id, claim_id),
        status: ReceiptStatus::Accepted,
    };
    let partial_fill_receipt = PartialFillReceipt {
        partial_fill_id: stable_id("partial-fill", release_id, claim_id),
        requested_atomic,
        filled_atomic,
        remaining_atomic,
        fill_ratio_bps,
        tranche_root: stable_root("fill-tranche", release_id, filled_atomic),
        next_attempt_l2_height: config.current_l2_height + config.release_finality_blocks,
        status: if remaining_atomic == 0 {
            ReceiptStatus::Accepted
        } else {
            ReceiptStatus::Watch
        },
    };
    let shortfall_hold = ShortfallHoldReceipt {
        hold_id: stable_id("shortfall-hold", release_id, claim_id),
        reason: if remaining_atomic == 0 {
            HoldReasonKind::None
        } else {
            HoldReasonKind::ShortfallUnfunded
        },
        hold_root_before: stable_id("hold-before", release_id, claim_id),
        hold_root_after: stable_id("hold-after", release_id, claim_id),
        shortfall_atomic: remaining_atomic,
        held_until_l2_height: config.current_l2_height + config.release_finality_blocks,
        release_blocked: remaining_atomic > 0 && config.fail_closed_on_shortfall,
        remediation_root: stable_root("remediation", release_id, remaining_atomic),
        status: shortfall_status,
    };

    SettlementReceipt {
        settlement_id: stable_id("settlement", release_id, claim_id),
        release_id: release_id.to_string(),
        reserve_bucket,
        amount_commitment,
        coverage_receipt,
        backstop_settlement,
        fee_cap_receipt,
        queue_priority_receipt,
        partial_fill_receipt,
        shortfall_hold,
        settlement_l2_height,
        settlement_monero_height: config.current_monero_height,
        finality_target_l2_height: settlement_l2_height + config.release_finality_blocks,
        settlement_status,
        memo_root: stable_id("settlement-memo", release_id, claim_id),
    }
}

pub fn fixture_state(
) -> MoneroL2PqBridgeExitCanonicalVerticalSliceLiquidityReleaseSettlementReceiptRuntimeResult<State>
{
    let config = Config::devnet();
    let mut state = State::new(config.clone());
    let receipt = build_settlement_receipt(
        &config,
        "release-fixture-001",
        "claim-fixture-001",
        "claimant-commitment-fixture-001",
        2_500_000_000_000,
        3_100_000_000_000,
        2_500_000,
        ReleaseIntentKind::ForcedExitUserClaim,
    );
    state.add_receipt(receipt)?;
    Ok(state)
}

fn derive_settlement_status(
    coverage_status: ReceiptStatus,
    fee_status: ReceiptStatus,
    shortfall_status: ReceiptStatus,
    fill_ratio_bps: u64,
    partial_fill_trigger_bps: u64,
) -> ReceiptStatus {
    if fee_status == ReceiptStatus::Rejected {
        ReceiptStatus::Rejected
    } else if shortfall_status == ReceiptStatus::Held {
        ReceiptStatus::Held
    } else if coverage_status == ReceiptStatus::Held || fill_ratio_bps < partial_fill_trigger_bps {
        ReceiptStatus::Watch
    } else {
        ReceiptStatus::Accepted
    }
}

fn push_threshold_finding(
    findings: &mut Vec<ValidationFinding>,
    finding_id: &str,
    reason: HoldReasonKind,
    passed: bool,
    evidence_root: String,
    blocks_release_on_failure: bool,
) {
    let status = if passed {
        ReceiptStatus::Accepted
    } else if blocks_release_on_failure {
        ReceiptStatus::Held
    } else {
        ReceiptStatus::Watch
    };
    findings.push(ValidationFinding {
        finding_id: finding_id.to_string(),
        reason: if passed { HoldReasonKind::None } else { reason },
        status,
        evidence_root,
        blocks_release: !passed && blocks_release_on_failure,
    });
}

fn ratio_bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return MAX_BPS;
    }
    let ratio = numerator.saturating_mul(MAX_BPS as u128) / denominator;
    if ratio > u64::MAX as u128 {
        u64::MAX
    } else {
        ratio as u64
    }
}

fn stable_id(label: &str, left: &str, right: &str) -> String {
    domain_hash(
        "LIQUIDITY-RELEASE-STABLE-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(left),
            HashPart::Str(right),
        ],
        32,
    )
}

fn stable_root(label: &str, id: &str, value: u128) -> String {
    domain_hash(
        "LIQUIDITY-RELEASE-STABLE-ROOT",
        &[
            HashPart::Str(label),
            HashPart::Str(id),
            HashPart::U128(value),
        ],
        32,
    )
}

fn digest_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
