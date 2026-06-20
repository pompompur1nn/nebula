use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceLiquidityReleaseExecutionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_LIQUIDITY_RELEASE_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-liquidity-release-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_LIQUIDITY_RELEASE_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RESERVE_BUCKET_SCHEME: &str = "forced-exit-reserve-bucket-root-v1";
pub const RELEASE_COMMITMENT_SCHEME: &str = "forced-exit-release-amount-commitment-root-v1";
pub const COVERAGE_SCHEME: &str = "forced-exit-liquidity-coverage-root-v1";
pub const BACKSTOP_SCHEME: &str = "forced-exit-backstop-lane-root-v1";
pub const FEE_CAP_SCHEME: &str = "forced-exit-fee-cap-root-v1";
pub const PRIORITY_SCHEME: &str = "forced-exit-release-queue-priority-root-v1";
pub const HOLD_SCHEME: &str = "forced-exit-liquidity-hold-root-v1";
pub const RECEIPT_SCHEME: &str = "forced-exit-settlement-receipt-root-v1";
pub const DEFAULT_EXECUTION_HEIGHT: u64 = 440_000;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 24;
pub const DEFAULT_RELEASE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_BACKSTOP_TRIGGER_BPS: u64 = 9_500;
pub const DEFAULT_PARTIAL_FILL_TRIGGER_BPS: u64 = 7_500;
pub const DEFAULT_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_EMERGENCY_FEE_CAP_BPS: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_EXECUTION_RECORDS: usize = 512;
pub const DEFAULT_MAX_HOLD_RECORDS: usize = 512;
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

    pub fn default_lane(self) -> BackstopLaneKind {
        match self {
            Self::ForcedExitHot | Self::ForcedExitWarm => BackstopLaneKind::None,
            Self::DelayedCold => BackstopLaneKind::GovernanceBuffer,
            Self::MakerCredit => BackstopLaneKind::MakerBond,
            Self::InsuranceBackstop => BackstopLaneKind::InsuranceVault,
            Self::GovernanceBuffer => BackstopLaneKind::EmergencyCredit,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseIntentKind {
    ForcedExitUserClaim,
    ForcedExitBatchNetting,
    ChallengeResolution,
    WatchtowerEscalation,
    PrivacySetDrain,
    EmergencyWithdrawal,
}

impl ReleaseIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedExitUserClaim => "forced_exit_user_claim",
            Self::ForcedExitBatchNetting => "forced_exit_batch_netting",
            Self::ChallengeResolution => "challenge_resolution",
            Self::WatchtowerEscalation => "watchtower_escalation",
            Self::PrivacySetDrain => "privacy_set_drain",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyWithdrawal => 10,
            Self::WatchtowerEscalation => 20,
            Self::ChallengeResolution => 30,
            Self::ForcedExitUserClaim => 40,
            Self::ForcedExitBatchNetting => 50,
            Self::PrivacySetDrain => 60,
        }
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

    pub fn consumes_external_credit(self) -> bool {
        matches!(
            self,
            Self::MakerBond | Self::InsuranceVault | Self::EmergencyCredit
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuePriorityClass {
    Emergency,
    Watchtower,
    Challenge,
    Standard,
    Deferred,
}

impl QueuePriorityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Watchtower => "watchtower",
            Self::Challenge => "challenge",
            Self::Standard => "standard",
            Self::Deferred => "deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Queued,
    Covered,
    PartialHeld,
    ShortfallHeld,
    Backstopped,
    Executed,
    Settled,
    Rejected,
}

impl ExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Covered => "covered",
            Self::PartialHeld => "partial_held",
            Self::ShortfallHeld => "shortfall_held",
            Self::Backstopped => "backstopped",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldKind {
    PartialFill,
    LiquidityShortfall,
    FeeCapExceeded,
    CoverageBelowMinimum,
    ReceiptFinalityPending,
}

impl HoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PartialFill => "partial_fill",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::CoverageBelowMinimum => "coverage_below_minimum",
            Self::ReceiptFinalityPending => "receipt_finality_pending",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldStatus {
    Open,
    Reducible,
    Cleared,
}

impl HoldStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reducible => "reducible",
            Self::Cleared => "cleared",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Anchored,
    Final,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Anchored => "anchored",
            Self::Final => "final",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub reserve_bucket_scheme: String,
    pub release_commitment_scheme: String,
    pub coverage_scheme: String,
    pub backstop_scheme: String,
    pub fee_cap_scheme: String,
    pub priority_scheme: String,
    pub hold_scheme: String,
    pub receipt_scheme: String,
    pub reserve_asset_id: String,
    pub liability_asset_id: String,
    pub execution_height: u64,
    pub settlement_finality_blocks: u64,
    pub release_ttl_blocks: u64,
    pub min_coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub backstop_trigger_bps: u64,
    pub partial_fill_trigger_bps: u64,
    pub fee_cap_bps: u64,
    pub emergency_fee_cap_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_execution_records: usize,
    pub max_hold_records: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            reserve_bucket_scheme: RESERVE_BUCKET_SCHEME.to_string(),
            release_commitment_scheme: RELEASE_COMMITMENT_SCHEME.to_string(),
            coverage_scheme: COVERAGE_SCHEME.to_string(),
            backstop_scheme: BACKSTOP_SCHEME.to_string(),
            fee_cap_scheme: FEE_CAP_SCHEME.to_string(),
            priority_scheme: PRIORITY_SCHEME.to_string(),
            hold_scheme: HOLD_SCHEME.to_string(),
            receipt_scheme: RECEIPT_SCHEME.to_string(),
            reserve_asset_id: "xmr-forced-exit-reserve-devnet".to_string(),
            liability_asset_id: "wxmr-private-l2-liability-devnet".to_string(),
            execution_height: DEFAULT_EXECUTION_HEIGHT,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            release_ttl_blocks: DEFAULT_RELEASE_TTL_BLOCKS,
            min_coverage_bps: DEFAULT_MIN_COVERAGE_BPS,
            target_coverage_bps: DEFAULT_TARGET_COVERAGE_BPS,
            backstop_trigger_bps: DEFAULT_BACKSTOP_TRIGGER_BPS,
            partial_fill_trigger_bps: DEFAULT_PARTIAL_FILL_TRIGGER_BPS,
            fee_cap_bps: DEFAULT_FEE_CAP_BPS,
            emergency_fee_cap_bps: DEFAULT_EMERGENCY_FEE_CAP_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_execution_records: DEFAULT_MAX_EXECUTION_RECORDS,
            max_hold_records: DEFAULT_MAX_HOLD_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reserve_bucket_scheme": self.reserve_bucket_scheme,
            "release_commitment_scheme": self.release_commitment_scheme,
            "coverage_scheme": self.coverage_scheme,
            "backstop_scheme": self.backstop_scheme,
            "fee_cap_scheme": self.fee_cap_scheme,
            "priority_scheme": self.priority_scheme,
            "hold_scheme": self.hold_scheme,
            "receipt_scheme": self.receipt_scheme,
            "reserve_asset_id": self.reserve_asset_id,
            "liability_asset_id": self.liability_asset_id,
            "execution_height": self.execution_height,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "release_ttl_blocks": self.release_ttl_blocks,
            "min_coverage_bps": self.min_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "backstop_trigger_bps": self.backstop_trigger_bps,
            "partial_fill_trigger_bps": self.partial_fill_trigger_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "emergency_fee_cap_bps": self.emergency_fee_cap_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_execution_records": self.max_execution_records,
            "max_hold_records": self.max_hold_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveBucket {
    pub bucket_id: String,
    pub kind: ReserveBucketKind,
    pub custodian_commitment_root: String,
    pub reserve_units: u128,
    pub reserved_units: u128,
    pub released_units: u128,
    pub pending_units: u128,
    pub liability_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
}

impl ReserveBucket {
    pub fn new(
        kind: ReserveBucketKind,
        seed: &str,
        reserve_units: u128,
        reserved_units: u128,
        released_units: u128,
        pending_units: u128,
        liability_units: u128,
    ) -> Self {
        let custodian_commitment_root = digest_str("BUCKET-CUSTODIAN", seed);
        let attestation_root = digest_json(
            "BUCKET-ATTESTATION",
            &json!({
                "seed": seed,
                "kind": kind.as_str(),
                "reserve_units": u128_json(reserve_units),
                "liability_units": u128_json(liability_units),
            }),
        );
        let bucket_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-BUCKET-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&custodian_commitment_root),
                HashPart::Int(saturating_i128(reserve_units)),
                HashPart::Int(saturating_i128(liability_units)),
            ],
            32,
        );
        Self {
            bucket_id,
            kind,
            custodian_commitment_root,
            reserve_units,
            reserved_units,
            released_units,
            pending_units,
            liability_units,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attestation_root,
        }
    }

    pub fn available_units(&self) -> u128 {
        self.reserve_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.released_units)
            .saturating_sub(self.pending_units)
    }

    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(
            self.reserve_units,
            self.liability_units.saturating_add(self.pending_units),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "custodian_commitment_root": self.custodian_commitment_root,
            "reserve_units": u128_json(self.reserve_units),
            "reserved_units": u128_json(self.reserved_units),
            "released_units": u128_json(self.released_units),
            "pending_units": u128_json(self.pending_units),
            "liability_units": u128_json(self.liability_units),
            "available_units": u128_json(self.available_units()),
            "coverage_bps": self.coverage_bps(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attestation_root": self.attestation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RESERVE-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseAmountCommitment {
    pub commitment_id: String,
    pub intent: ReleaseIntentKind,
    pub exit_claim_root: String,
    pub amount_commitment_root: String,
    pub release_units: u128,
    pub min_fill_units: u128,
    pub fee_cap_bps: u64,
    pub receiver_view_root: String,
    pub nullifier_set_root: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
}

impl ReleaseAmountCommitment {
    pub fn new(
        intent: ReleaseIntentKind,
        seed: &str,
        release_units: u128,
        min_fill_units: u128,
        fee_cap_bps: u64,
        requested_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let exit_claim_root = digest_str("EXIT-CLAIM", seed);
        let receiver_view_root = digest_str("RECEIVER-VIEW", seed);
        let nullifier_set_root = digest_str("NULLIFIER-SET", seed);
        let amount_commitment_root = digest_json(
            "RELEASE-AMOUNT",
            &json!({
                "intent": intent.as_str(),
                "seed": seed,
                "release_units": u128_json(release_units),
                "min_fill_units": u128_json(min_fill_units),
                "fee_cap_bps": fee_cap_bps,
            }),
        );
        let commitment_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RELEASE-COMMITMENT-ID",
            &[
                HashPart::Str(intent.as_str()),
                HashPart::Str(&exit_claim_root),
                HashPart::Str(&amount_commitment_root),
                HashPart::U64(requested_at_height),
            ],
            32,
        );
        Self {
            commitment_id,
            intent,
            exit_claim_root,
            amount_commitment_root,
            release_units,
            min_fill_units,
            fee_cap_bps,
            receiver_view_root,
            nullifier_set_root,
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(ttl_blocks),
        }
    }

    pub fn priority_class(&self) -> QueuePriorityClass {
        match self.intent {
            ReleaseIntentKind::EmergencyWithdrawal => QueuePriorityClass::Emergency,
            ReleaseIntentKind::WatchtowerEscalation => QueuePriorityClass::Watchtower,
            ReleaseIntentKind::ChallengeResolution => QueuePriorityClass::Challenge,
            ReleaseIntentKind::ForcedExitUserClaim | ReleaseIntentKind::ForcedExitBatchNetting => {
                QueuePriorityClass::Standard
            }
            ReleaseIntentKind::PrivacySetDrain => QueuePriorityClass::Deferred,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "intent": self.intent.as_str(),
            "priority_class": self.priority_class().as_str(),
            "exit_claim_root": self.exit_claim_root,
            "amount_commitment_root": self.amount_commitment_root,
            "release_units": u128_json(self.release_units),
            "min_fill_units": u128_json(self.min_fill_units),
            "fee_cap_bps": self.fee_cap_bps,
            "receiver_view_root": self.receiver_view_root,
            "nullifier_set_root": self.nullifier_set_root,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RELEASE-AMOUNT-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityCoverage {
    pub coverage_id: String,
    pub bucket_id: String,
    pub commitment_id: String,
    pub available_units: u128,
    pub requested_units: u128,
    pub covered_units: u128,
    pub shortfall_units: u128,
    pub coverage_bps: u64,
    pub reserve_coverage_bps: u64,
    pub coverage_root: String,
}

impl LiquidityCoverage {
    pub fn from_bucket_and_commitment(
        bucket: &ReserveBucket,
        commitment: &ReleaseAmountCommitment,
    ) -> Self {
        let available_units = bucket.available_units();
        let covered_units = available_units.min(commitment.release_units);
        let shortfall_units = commitment.release_units.saturating_sub(covered_units);
        let coverage_bps = ratio_bps(covered_units, commitment.release_units);
        let reserve_coverage_bps = bucket.coverage_bps();
        let coverage_root = digest_json(
            "LIQUIDITY-COVERAGE",
            &json!({
                "bucket_id": bucket.bucket_id,
                "commitment_id": commitment.commitment_id,
                "available_units": u128_json(available_units),
                "requested_units": u128_json(commitment.release_units),
                "covered_units": u128_json(covered_units),
                "shortfall_units": u128_json(shortfall_units),
                "coverage_bps": coverage_bps,
                "reserve_coverage_bps": reserve_coverage_bps,
            }),
        );
        let coverage_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-COVERAGE-ID",
            &[
                HashPart::Str(&bucket.bucket_id),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Int(saturating_i128(covered_units)),
                HashPart::Int(saturating_i128(shortfall_units)),
            ],
            32,
        );
        Self {
            coverage_id,
            bucket_id: bucket.bucket_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            available_units,
            requested_units: commitment.release_units,
            covered_units,
            shortfall_units,
            coverage_bps,
            reserve_coverage_bps,
            coverage_root,
        }
    }

    pub fn fully_covered(&self) -> bool {
        self.shortfall_units == 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coverage_id": self.coverage_id,
            "bucket_id": self.bucket_id,
            "commitment_id": self.commitment_id,
            "available_units": u128_json(self.available_units),
            "requested_units": u128_json(self.requested_units),
            "covered_units": u128_json(self.covered_units),
            "shortfall_units": u128_json(self.shortfall_units),
            "coverage_bps": self.coverage_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "coverage_root": self.coverage_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackstopLane {
    pub lane_id: String,
    pub kind: BackstopLaneKind,
    pub bucket_id: String,
    pub commitment_id: String,
    pub backstop_capacity_units: u128,
    pub allocated_units: u128,
    pub trigger_bps: u64,
    pub lane_commitment_root: String,
}

impl BackstopLane {
    pub fn from_coverage(
        kind: BackstopLaneKind,
        coverage: &LiquidityCoverage,
        capacity_units: u128,
        trigger_bps: u64,
    ) -> Self {
        let allocated_units = if coverage.coverage_bps < trigger_bps {
            coverage.shortfall_units.min(capacity_units)
        } else {
            0
        };
        let lane_commitment_root = digest_json(
            "BACKSTOP-LANE",
            &json!({
                "kind": kind.as_str(),
                "bucket_id": coverage.bucket_id,
                "commitment_id": coverage.commitment_id,
                "capacity_units": u128_json(capacity_units),
                "allocated_units": u128_json(allocated_units),
                "trigger_bps": trigger_bps,
            }),
        );
        let lane_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-BACKSTOP-LANE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&coverage.coverage_id),
                HashPart::Str(&lane_commitment_root),
            ],
            32,
        );
        Self {
            lane_id,
            kind,
            bucket_id: coverage.bucket_id.clone(),
            commitment_id: coverage.commitment_id.clone(),
            backstop_capacity_units: capacity_units,
            allocated_units,
            trigger_bps,
            lane_commitment_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "bucket_id": self.bucket_id,
            "commitment_id": self.commitment_id,
            "backstop_capacity_units": u128_json(self.backstop_capacity_units),
            "allocated_units": u128_json(self.allocated_units),
            "trigger_bps": self.trigger_bps,
            "consumes_external_credit": self.kind.consumes_external_credit(),
            "lane_commitment_root": self.lane_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCap {
    pub fee_cap_id: String,
    pub commitment_id: String,
    pub max_fee_bps: u64,
    pub quoted_fee_bps: u64,
    pub fee_units: u128,
    pub fee_cap_root: String,
}

impl FeeCap {
    pub fn new(commitment: &ReleaseAmountCommitment, quoted_fee_bps: u64, config: &Config) -> Self {
        let max_fee_bps = match commitment.intent {
            ReleaseIntentKind::EmergencyWithdrawal | ReleaseIntentKind::WatchtowerEscalation => {
                config.emergency_fee_cap_bps
            }
            _ => config.fee_cap_bps,
        };
        let bounded_fee_bps = quoted_fee_bps.min(max_fee_bps);
        let fee_units = mul_bps(commitment.release_units, bounded_fee_bps);
        let fee_cap_root = digest_json(
            "FEE-CAP",
            &json!({
                "commitment_id": commitment.commitment_id,
                "max_fee_bps": max_fee_bps,
                "quoted_fee_bps": quoted_fee_bps,
                "bounded_fee_bps": bounded_fee_bps,
                "fee_units": u128_json(fee_units),
            }),
        );
        let fee_cap_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-FEE-CAP-ID",
            &[
                HashPart::Str(&commitment.commitment_id),
                HashPart::U64(max_fee_bps),
                HashPart::U64(quoted_fee_bps),
            ],
            32,
        );
        Self {
            fee_cap_id,
            commitment_id: commitment.commitment_id.clone(),
            max_fee_bps,
            quoted_fee_bps,
            fee_units,
            fee_cap_root,
        }
    }

    pub fn accepted(&self) -> bool {
        self.quoted_fee_bps <= self.max_fee_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "commitment_id": self.commitment_id,
            "max_fee_bps": self.max_fee_bps,
            "quoted_fee_bps": self.quoted_fee_bps,
            "accepted": self.accepted(),
            "fee_units": u128_json(self.fee_units),
            "fee_cap_root": self.fee_cap_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueuePriority {
    pub priority_id: String,
    pub commitment_id: String,
    pub class: QueuePriorityClass,
    pub effective_rank: u64,
    pub requested_at_height: u64,
    pub tie_breaker_root: String,
}

impl QueuePriority {
    pub fn from_commitment(commitment: &ReleaseAmountCommitment, sequence: u64) -> Self {
        let class = commitment.priority_class();
        let effective_rank = commitment
            .intent
            .base_priority()
            .saturating_mul(1_000_000)
            .saturating_add(commitment.requested_at_height)
            .saturating_add(sequence);
        let tie_breaker_root = digest_json(
            "QUEUE-PRIORITY-TIE-BREAKER",
            &json!({
                "commitment_id": commitment.commitment_id,
                "class": class.as_str(),
                "sequence": sequence,
            }),
        );
        let priority_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-QUEUE-PRIORITY-ID",
            &[
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(class.as_str()),
                HashPart::U64(effective_rank),
                HashPart::Str(&tie_breaker_root),
            ],
            32,
        );
        Self {
            priority_id,
            commitment_id: commitment.commitment_id.clone(),
            class,
            effective_rank,
            requested_at_height: commitment.requested_at_height,
            tie_breaker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "priority_id": self.priority_id,
            "commitment_id": self.commitment_id,
            "class": self.class.as_str(),
            "effective_rank": self.effective_rank,
            "requested_at_height": self.requested_at_height,
            "tie_breaker_root": self.tie_breaker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityHold {
    pub hold_id: String,
    pub kind: HoldKind,
    pub status: HoldStatus,
    pub commitment_id: String,
    pub bucket_id: String,
    pub held_units: u128,
    pub releaseable_units: u128,
    pub opened_at_height: u64,
    pub clears_after_height: u64,
    pub evidence_root: String,
}

impl LiquidityHold {
    pub fn partial_fill(
        commitment: &ReleaseAmountCommitment,
        coverage: &LiquidityCoverage,
        height: u64,
        finality_blocks: u64,
    ) -> Self {
        Self::new(
            HoldKind::PartialFill,
            HoldStatus::Reducible,
            commitment,
            coverage,
            coverage.shortfall_units,
            coverage.covered_units,
            height,
            height.saturating_add(finality_blocks),
        )
    }

    pub fn shortfall(
        commitment: &ReleaseAmountCommitment,
        coverage: &LiquidityCoverage,
        height: u64,
        finality_blocks: u64,
    ) -> Self {
        Self::new(
            HoldKind::LiquidityShortfall,
            HoldStatus::Open,
            commitment,
            coverage,
            coverage.shortfall_units,
            coverage.covered_units,
            height,
            height.saturating_add(finality_blocks),
        )
    }

    pub fn fee_cap(
        commitment: &ReleaseAmountCommitment,
        coverage: &LiquidityCoverage,
        height: u64,
        finality_blocks: u64,
    ) -> Self {
        Self::new(
            HoldKind::FeeCapExceeded,
            HoldStatus::Open,
            commitment,
            coverage,
            commitment.release_units,
            0,
            height,
            height.saturating_add(finality_blocks),
        )
    }

    fn new(
        kind: HoldKind,
        status: HoldStatus,
        commitment: &ReleaseAmountCommitment,
        coverage: &LiquidityCoverage,
        held_units: u128,
        releaseable_units: u128,
        opened_at_height: u64,
        clears_after_height: u64,
    ) -> Self {
        let evidence_root = digest_json(
            "LIQUIDITY-HOLD-EVIDENCE",
            &json!({
                "kind": kind.as_str(),
                "status": status.as_str(),
                "commitment_id": commitment.commitment_id,
                "bucket_id": coverage.bucket_id,
                "held_units": u128_json(held_units),
                "releaseable_units": u128_json(releaseable_units),
                "opened_at_height": opened_at_height,
                "clears_after_height": clears_after_height,
            }),
        );
        let hold_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-HOLD-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&coverage.bucket_id),
                HashPart::Str(&evidence_root),
            ],
            32,
        );
        Self {
            hold_id,
            kind,
            status,
            commitment_id: commitment.commitment_id.clone(),
            bucket_id: coverage.bucket_id.clone(),
            held_units,
            releaseable_units,
            opened_at_height,
            clears_after_height,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "commitment_id": self.commitment_id,
            "bucket_id": self.bucket_id,
            "held_units": u128_json(self.held_units),
            "releaseable_units": u128_json(self.releaseable_units),
            "opened_at_height": self.opened_at_height,
            "clears_after_height": self.clears_after_height,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseExecutionRecord {
    pub execution_id: String,
    pub bucket_id: String,
    pub commitment_id: String,
    pub coverage_id: String,
    pub backstop_lane_id: String,
    pub fee_cap_id: String,
    pub priority_id: String,
    pub status: ExecutionStatus,
    pub gross_release_units: u128,
    pub reserve_fill_units: u128,
    pub backstop_fill_units: u128,
    pub fee_units: u128,
    pub net_release_units: u128,
    pub shortfall_units: u128,
    pub executed_at_height: u64,
    pub execution_root: String,
}

impl ReleaseExecutionRecord {
    pub fn compose(
        bucket: &ReserveBucket,
        commitment: &ReleaseAmountCommitment,
        coverage: &LiquidityCoverage,
        backstop: &BackstopLane,
        fee_cap: &FeeCap,
        priority: &QueuePriority,
        config: &Config,
    ) -> Self {
        let gross_release_units = commitment.release_units;
        let reserve_fill_units = coverage.covered_units;
        let backstop_fill_units = backstop.allocated_units;
        let filled_units = reserve_fill_units.saturating_add(backstop_fill_units);
        let fee_units = fee_cap.fee_units.min(filled_units);
        let net_release_units = filled_units.saturating_sub(fee_units);
        let shortfall_units = gross_release_units.saturating_sub(filled_units);
        let status = execution_status(coverage, backstop, fee_cap, config);
        let execution_root = digest_json(
            "RELEASE-EXECUTION",
            &json!({
                "bucket_id": bucket.bucket_id,
                "commitment_id": commitment.commitment_id,
                "coverage_id": coverage.coverage_id,
                "backstop_lane_id": backstop.lane_id,
                "fee_cap_id": fee_cap.fee_cap_id,
                "priority_id": priority.priority_id,
                "status": status.as_str(),
                "gross_release_units": u128_json(gross_release_units),
                "reserve_fill_units": u128_json(reserve_fill_units),
                "backstop_fill_units": u128_json(backstop_fill_units),
                "fee_units": u128_json(fee_units),
                "net_release_units": u128_json(net_release_units),
                "shortfall_units": u128_json(shortfall_units),
                "executed_at_height": config.execution_height,
            }),
        );
        let execution_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-EXECUTION-ID",
            &[
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&coverage.coverage_id),
                HashPart::Str(&execution_root),
            ],
            32,
        );
        Self {
            execution_id,
            bucket_id: bucket.bucket_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            coverage_id: coverage.coverage_id.clone(),
            backstop_lane_id: backstop.lane_id.clone(),
            fee_cap_id: fee_cap.fee_cap_id.clone(),
            priority_id: priority.priority_id.clone(),
            status,
            gross_release_units,
            reserve_fill_units,
            backstop_fill_units,
            fee_units,
            net_release_units,
            shortfall_units,
            executed_at_height: config.execution_height,
            execution_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_id": self.execution_id,
            "bucket_id": self.bucket_id,
            "commitment_id": self.commitment_id,
            "coverage_id": self.coverage_id,
            "backstop_lane_id": self.backstop_lane_id,
            "fee_cap_id": self.fee_cap_id,
            "priority_id": self.priority_id,
            "status": self.status.as_str(),
            "terminal": self.status.terminal(),
            "gross_release_units": u128_json(self.gross_release_units),
            "reserve_fill_units": u128_json(self.reserve_fill_units),
            "backstop_fill_units": u128_json(self.backstop_fill_units),
            "fee_units": u128_json(self.fee_units),
            "net_release_units": u128_json(self.net_release_units),
            "shortfall_units": u128_json(self.shortfall_units),
            "executed_at_height": self.executed_at_height,
            "execution_root": self.execution_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub execution_id: String,
    pub commitment_id: String,
    pub settlement_status: ReceiptStatus,
    pub settlement_amount_root: String,
    pub receiver_output_root: String,
    pub fee_output_root: String,
    pub anchor_height: u64,
    pub final_height: u64,
    pub receipt_root: String,
}

impl SettlementReceipt {
    pub fn from_execution(execution: &ReleaseExecutionRecord, config: &Config) -> Self {
        let settlement_status =
            if execution.shortfall_units == 0 && execution.status != ExecutionStatus::Rejected {
                ReceiptStatus::Final
            } else if execution.net_release_units > 0 {
                ReceiptStatus::Anchored
            } else {
                ReceiptStatus::Pending
            };
        let settlement_amount_root = digest_json(
            "SETTLEMENT-AMOUNT",
            &json!({
                "execution_id": execution.execution_id,
                "net_release_units": u128_json(execution.net_release_units),
                "fee_units": u128_json(execution.fee_units),
                "shortfall_units": u128_json(execution.shortfall_units),
            }),
        );
        let receiver_output_root = digest_str("RECEIVER-OUTPUT", &execution.execution_id);
        let fee_output_root = digest_str("FEE-OUTPUT", &settlement_amount_root);
        let anchor_height = execution.executed_at_height.saturating_add(1);
        let final_height = anchor_height.saturating_add(config.settlement_finality_blocks);
        let receipt_root = digest_json(
            "SETTLEMENT-RECEIPT",
            &json!({
                "execution_id": execution.execution_id,
                "commitment_id": execution.commitment_id,
                "settlement_status": settlement_status.as_str(),
                "settlement_amount_root": settlement_amount_root,
                "receiver_output_root": receiver_output_root,
                "fee_output_root": fee_output_root,
                "anchor_height": anchor_height,
                "final_height": final_height,
            }),
        );
        let receipt_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-SETTLEMENT-RECEIPT-ID",
            &[
                HashPart::Str(&execution.execution_id),
                HashPart::Str(&settlement_amount_root),
                HashPart::U64(final_height),
            ],
            32,
        );
        Self {
            receipt_id,
            execution_id: execution.execution_id.clone(),
            commitment_id: execution.commitment_id.clone(),
            settlement_status,
            settlement_amount_root,
            receiver_output_root,
            fee_output_root,
            anchor_height,
            final_height,
            receipt_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "execution_id": self.execution_id,
            "commitment_id": self.commitment_id,
            "settlement_status": self.settlement_status.as_str(),
            "settlement_amount_root": self.settlement_amount_root,
            "receiver_output_root": self.receiver_output_root,
            "fee_output_root": self.fee_output_root,
            "anchor_height": self.anchor_height,
            "final_height": self.final_height,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeCounters {
    pub reserve_bucket_count: u64,
    pub commitment_count: u64,
    pub execution_count: u64,
    pub partial_fill_hold_count: u64,
    pub shortfall_hold_count: u64,
    pub backstopped_execution_count: u64,
    pub settled_receipt_count: u64,
    pub total_requested_units: u128,
    pub total_net_released_units: u128,
    pub total_shortfall_units: u128,
}

impl RuntimeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_bucket_count": self.reserve_bucket_count,
            "commitment_count": self.commitment_count,
            "execution_count": self.execution_count,
            "partial_fill_hold_count": self.partial_fill_hold_count,
            "shortfall_hold_count": self.shortfall_hold_count,
            "backstopped_execution_count": self.backstopped_execution_count,
            "settled_receipt_count": self.settled_receipt_count,
            "total_requested_units": u128_json(self.total_requested_units),
            "total_net_released_units": u128_json(self.total_net_released_units),
            "total_shortfall_units": u128_json(self.total_shortfall_units),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeRoots {
    pub config_root: String,
    pub reserve_bucket_root: String,
    pub release_commitment_root: String,
    pub liquidity_coverage_root: String,
    pub backstop_lane_root: String,
    pub fee_cap_root: String,
    pub queue_priority_root: String,
    pub hold_root: String,
    pub execution_record_root: String,
    pub settlement_receipt_root: String,
    pub state_root: String,
}

impl RuntimeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "reserve_bucket_root": self.reserve_bucket_root,
            "release_commitment_root": self.release_commitment_root,
            "liquidity_coverage_root": self.liquidity_coverage_root,
            "backstop_lane_root": self.backstop_lane_root,
            "fee_cap_root": self.fee_cap_root,
            "queue_priority_root": self.queue_priority_root,
            "hold_root": self.hold_root,
            "execution_record_root": self.execution_record_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub reserve_buckets: BTreeMap<String, ReserveBucket>,
    pub release_commitments: BTreeMap<String, ReleaseAmountCommitment>,
    pub liquidity_coverages: BTreeMap<String, LiquidityCoverage>,
    pub backstop_lanes: BTreeMap<String, BackstopLane>,
    pub fee_caps: BTreeMap<String, FeeCap>,
    pub queue_priorities: BTreeMap<String, QueuePriority>,
    pub holds: BTreeMap<String, LiquidityHold>,
    pub execution_records: BTreeMap<String, ReleaseExecutionRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            reserve_buckets: BTreeMap::new(),
            release_commitments: BTreeMap::new(),
            liquidity_coverages: BTreeMap::new(),
            backstop_lanes: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            queue_priorities: BTreeMap::new(),
            holds: BTreeMap::new(),
            execution_records: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config);
        let seeds = [
            (
                ReserveBucketKind::ForcedExitHot,
                "devnet-hot-forced-exit",
                9_500_000_000_000_u128,
                500_000_000_000_u128,
                120_000_000_000_u128,
                300_000_000_000_u128,
                7_200_000_000_000_u128,
            ),
            (
                ReserveBucketKind::ForcedExitWarm,
                "devnet-warm-forced-exit",
                5_000_000_000_000_u128,
                700_000_000_000_u128,
                80_000_000_000_u128,
                220_000_000_000_u128,
                4_400_000_000_000_u128,
            ),
            (
                ReserveBucketKind::InsuranceBackstop,
                "devnet-insurance-backstop",
                2_250_000_000_000_u128,
                150_000_000_000_u128,
                50_000_000_000_u128,
                70_000_000_000_u128,
                1_900_000_000_000_u128,
            ),
            (
                ReserveBucketKind::MakerCredit,
                "devnet-maker-credit",
                1_200_000_000_000_u128,
                400_000_000_000_u128,
                40_000_000_000_u128,
                150_000_000_000_u128,
                1_450_000_000_000_u128,
            ),
        ];
        for (kind, seed, reserve, reserved, released, pending, liability) in seeds {
            let bucket =
                ReserveBucket::new(kind, seed, reserve, reserved, released, pending, liability);
            state
                .reserve_buckets
                .insert(bucket.bucket_id.clone(), bucket);
        }

        let commitments = [
            (
                ReleaseIntentKind::EmergencyWithdrawal,
                "devnet-emergency-release-0",
                650_000_000_000_u128,
                650_000_000_000_u128,
                4,
                0_u64,
            ),
            (
                ReleaseIntentKind::ForcedExitUserClaim,
                "devnet-user-forced-exit-1",
                1_100_000_000_000_u128,
                850_000_000_000_u128,
                10,
                1_u64,
            ),
            (
                ReleaseIntentKind::ChallengeResolution,
                "devnet-challenge-resolution-2",
                900_000_000_000_u128,
                600_000_000_000_u128,
                9,
                2_u64,
            ),
            (
                ReleaseIntentKind::WatchtowerEscalation,
                "devnet-watchtower-escalation-3",
                1_600_000_000_000_u128,
                1_100_000_000_000_u128,
                6,
                3_u64,
            ),
            (
                ReleaseIntentKind::PrivacySetDrain,
                "devnet-privacy-set-drain-4",
                2_200_000_000_000_u128,
                1_500_000_000_000_u128,
                12,
                4_u64,
            ),
        ];
        for (intent, seed, release, min_fill, fee_bps, offset) in commitments {
            let commitment = ReleaseAmountCommitment::new(
                intent,
                seed,
                release,
                min_fill,
                fee_bps,
                state
                    .config
                    .execution_height
                    .saturating_sub(8)
                    .saturating_add(offset),
                state.config.release_ttl_blocks,
            );
            state
                .release_commitments
                .insert(commitment.commitment_id.clone(), commitment);
        }
        state.rebuild_execution_index();
        state
    }

    pub fn rebuild_execution_index(&mut self) {
        self.liquidity_coverages.clear();
        self.backstop_lanes.clear();
        self.fee_caps.clear();
        self.queue_priorities.clear();
        self.holds.clear();
        self.execution_records.clear();
        self.settlement_receipts.clear();

        let buckets = self
            .reserve_buckets
            .values()
            .cloned()
            .collect::<Vec<ReserveBucket>>();
        let commitments = self
            .release_commitments
            .values()
            .cloned()
            .collect::<Vec<ReleaseAmountCommitment>>();

        for (index, commitment) in commitments.iter().enumerate() {
            let bucket = select_bucket(&buckets, commitment);
            if let Some(bucket) = bucket {
                let coverage = LiquidityCoverage::from_bucket_and_commitment(bucket, commitment);
                let lane_kind = select_backstop_lane(bucket, &coverage, &self.config);
                let backstop_capacity = backstop_capacity_for_lane(lane_kind, &buckets);
                let backstop = BackstopLane::from_coverage(
                    lane_kind,
                    &coverage,
                    backstop_capacity,
                    self.config.backstop_trigger_bps,
                );
                let fee_cap = FeeCap::new(commitment, commitment.fee_cap_bps, &self.config);
                let sequence = match u64::try_from(index) {
                    Ok(value) => value,
                    Err(_) => u64::MAX,
                };
                let priority = QueuePriority::from_commitment(commitment, sequence);
                let execution = ReleaseExecutionRecord::compose(
                    bucket,
                    commitment,
                    &coverage,
                    &backstop,
                    &fee_cap,
                    &priority,
                    &self.config,
                );
                self.install_holds(commitment, &coverage, &fee_cap);
                let receipt = SettlementReceipt::from_execution(&execution, &self.config);
                self.liquidity_coverages
                    .insert(coverage.coverage_id.clone(), coverage);
                self.backstop_lanes
                    .insert(backstop.lane_id.clone(), backstop);
                self.fee_caps.insert(fee_cap.fee_cap_id.clone(), fee_cap);
                self.queue_priorities
                    .insert(priority.priority_id.clone(), priority);
                self.execution_records
                    .insert(execution.execution_id.clone(), execution);
                self.settlement_receipts
                    .insert(receipt.receipt_id.clone(), receipt);
            }
        }
    }

    fn install_holds(
        &mut self,
        commitment: &ReleaseAmountCommitment,
        coverage: &LiquidityCoverage,
        fee_cap: &FeeCap,
    ) {
        if !fee_cap.accepted() {
            let hold = LiquidityHold::fee_cap(
                commitment,
                coverage,
                self.config.execution_height,
                self.config.settlement_finality_blocks,
            );
            self.holds.insert(hold.hold_id.clone(), hold);
        }
        if coverage.shortfall_units > 0
            && coverage.coverage_bps >= self.config.partial_fill_trigger_bps
        {
            let hold = LiquidityHold::partial_fill(
                commitment,
                coverage,
                self.config.execution_height,
                self.config.settlement_finality_blocks,
            );
            self.holds.insert(hold.hold_id.clone(), hold);
        }
        if coverage.shortfall_units > 0
            && coverage.coverage_bps < self.config.partial_fill_trigger_bps
        {
            let hold = LiquidityHold::shortfall(
                commitment,
                coverage,
                self.config.execution_height,
                self.config.settlement_finality_blocks,
            );
            self.holds.insert(hold.hold_id.clone(), hold);
        }
    }

    pub fn counters(&self) -> RuntimeCounters {
        RuntimeCounters {
            reserve_bucket_count: len_u64(self.reserve_buckets.len()),
            commitment_count: len_u64(self.release_commitments.len()),
            execution_count: len_u64(self.execution_records.len()),
            partial_fill_hold_count: len_u64(
                self.holds
                    .values()
                    .filter(|hold| hold.kind == HoldKind::PartialFill)
                    .count(),
            ),
            shortfall_hold_count: len_u64(
                self.holds
                    .values()
                    .filter(|hold| hold.kind == HoldKind::LiquidityShortfall)
                    .count(),
            ),
            backstopped_execution_count: len_u64(
                self.execution_records
                    .values()
                    .filter(|record| record.backstop_fill_units > 0)
                    .count(),
            ),
            settled_receipt_count: len_u64(
                self.settlement_receipts
                    .values()
                    .filter(|receipt| receipt.settlement_status == ReceiptStatus::Final)
                    .count(),
            ),
            total_requested_units: self
                .release_commitments
                .values()
                .fold(0_u128, |sum, item| sum.saturating_add(item.release_units)),
            total_net_released_units: self.execution_records.values().fold(0_u128, |sum, item| {
                sum.saturating_add(item.net_release_units)
            }),
            total_shortfall_units: self
                .execution_records
                .values()
                .fold(0_u128, |sum, item| sum.saturating_add(item.shortfall_units)),
        }
    }

    pub fn roots(&self) -> RuntimeRoots {
        let config_root = self.config.state_root();
        let reserve_bucket_root = collection_root(
            "RESERVE-BUCKETS",
            self.reserve_buckets
                .values()
                .map(ReserveBucket::public_record)
                .collect(),
        );
        let release_commitment_root = collection_root(
            "RELEASE-COMMITMENTS",
            self.release_commitments
                .values()
                .map(ReleaseAmountCommitment::public_record)
                .collect(),
        );
        let liquidity_coverage_root = collection_root(
            "LIQUIDITY-COVERAGES",
            self.liquidity_coverages
                .values()
                .map(LiquidityCoverage::public_record)
                .collect(),
        );
        let backstop_lane_root = collection_root(
            "BACKSTOP-LANES",
            self.backstop_lanes
                .values()
                .map(BackstopLane::public_record)
                .collect(),
        );
        let fee_cap_root = collection_root(
            "FEE-CAPS",
            self.fee_caps.values().map(FeeCap::public_record).collect(),
        );
        let queue_priority_root = collection_root(
            "QUEUE-PRIORITIES",
            self.queue_priorities
                .values()
                .map(QueuePriority::public_record)
                .collect(),
        );
        let hold_root = collection_root(
            "LIQUIDITY-HOLDS",
            self.holds
                .values()
                .map(LiquidityHold::public_record)
                .collect(),
        );
        let execution_record_root = collection_root(
            "EXECUTION-RECORDS",
            self.execution_records
                .values()
                .map(ReleaseExecutionRecord::public_record)
                .collect(),
        );
        let settlement_receipt_root = collection_root(
            "SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        let state_record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "config_root": config_root,
            "reserve_bucket_root": reserve_bucket_root,
            "release_commitment_root": release_commitment_root,
            "liquidity_coverage_root": liquidity_coverage_root,
            "backstop_lane_root": backstop_lane_root,
            "fee_cap_root": fee_cap_root,
            "queue_priority_root": queue_priority_root,
            "hold_root": hold_root,
            "execution_record_root": execution_record_root,
            "settlement_receipt_root": settlement_receipt_root,
            "counters": self.counters().public_record(),
        });
        let state_root = record_root("STATE", &state_record);
        RuntimeRoots {
            config_root,
            reserve_bucket_root,
            release_commitment_root,
            liquidity_coverage_root,
            backstop_lane_root,
            fee_cap_root,
            queue_priority_root,
            hold_root,
            execution_record_root,
            settlement_receipt_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_liquidity_release_execution_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "reserve_buckets": map_records(&self.reserve_buckets, ReserveBucket::public_record),
            "release_commitments": map_records(&self.release_commitments, ReleaseAmountCommitment::public_record),
            "liquidity_coverages": map_records(&self.liquidity_coverages, LiquidityCoverage::public_record),
            "backstop_lanes": map_records(&self.backstop_lanes, BackstopLane::public_record),
            "fee_caps": map_records(&self.fee_caps, FeeCap::public_record),
            "queue_priorities": map_records(&self.queue_priorities, QueuePriority::public_record),
            "holds": map_records(&self.holds, LiquidityHold::public_record),
            "execution_records": map_records(&self.execution_records, ReleaseExecutionRecord::public_record),
            "settlement_receipts": map_records(&self.settlement_receipts, SettlementReceipt::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
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

fn execution_status(
    coverage: &LiquidityCoverage,
    backstop: &BackstopLane,
    fee_cap: &FeeCap,
    config: &Config,
) -> ExecutionStatus {
    if !fee_cap.accepted() {
        ExecutionStatus::Rejected
    } else if coverage.fully_covered() {
        ExecutionStatus::Executed
    } else if backstop.allocated_units >= coverage.shortfall_units && backstop.allocated_units > 0 {
        ExecutionStatus::Backstopped
    } else if coverage.coverage_bps >= config.partial_fill_trigger_bps {
        ExecutionStatus::PartialHeld
    } else if coverage.coverage_bps < config.min_coverage_bps {
        ExecutionStatus::ShortfallHeld
    } else {
        ExecutionStatus::Covered
    }
}

fn select_bucket<'a>(
    buckets: &'a [ReserveBucket],
    commitment: &ReleaseAmountCommitment,
) -> Option<&'a ReserveBucket> {
    let preferred = match commitment.intent {
        ReleaseIntentKind::EmergencyWithdrawal => ReserveBucketKind::ForcedExitHot,
        ReleaseIntentKind::WatchtowerEscalation => ReserveBucketKind::InsuranceBackstop,
        ReleaseIntentKind::ChallengeResolution => ReserveBucketKind::ForcedExitWarm,
        ReleaseIntentKind::ForcedExitUserClaim | ReleaseIntentKind::ForcedExitBatchNetting => {
            ReserveBucketKind::ForcedExitHot
        }
        ReleaseIntentKind::PrivacySetDrain => ReserveBucketKind::DelayedCold,
    };
    buckets
        .iter()
        .filter(|bucket| bucket.kind == preferred)
        .max_by_key(|bucket| bucket.available_units())
        .or_else(|| buckets.iter().max_by_key(|bucket| bucket.available_units()))
}

fn select_backstop_lane(
    bucket: &ReserveBucket,
    coverage: &LiquidityCoverage,
    config: &Config,
) -> BackstopLaneKind {
    if coverage.shortfall_units == 0 || coverage.coverage_bps >= config.backstop_trigger_bps {
        BackstopLaneKind::None
    } else {
        bucket.kind.default_lane()
    }
}

fn backstop_capacity_for_lane(kind: BackstopLaneKind, buckets: &[ReserveBucket]) -> u128 {
    match kind {
        BackstopLaneKind::None => 0,
        BackstopLaneKind::MakerBond => capacity_by_kind(buckets, ReserveBucketKind::MakerCredit),
        BackstopLaneKind::InsuranceVault => {
            capacity_by_kind(buckets, ReserveBucketKind::InsuranceBackstop)
        }
        BackstopLaneKind::WatchtowerEscrow => {
            capacity_by_kind(buckets, ReserveBucketKind::ForcedExitWarm) / 2
        }
        BackstopLaneKind::GovernanceBuffer => {
            capacity_by_kind(buckets, ReserveBucketKind::GovernanceBuffer)
        }
        BackstopLaneKind::EmergencyCredit => {
            capacity_by_kind(buckets, ReserveBucketKind::InsuranceBackstop) / 2
        }
    }
}

fn capacity_by_kind(buckets: &[ReserveBucket], kind: ReserveBucketKind) -> u128 {
    buckets
        .iter()
        .filter(|bucket| bucket.kind == kind)
        .fold(0_u128, |sum, bucket| {
            sum.saturating_add(bucket.available_units())
        })
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RELEASE-{domain}"),
        &records,
    )
}

fn map_records<T, F>(items: &BTreeMap<String, T>, mut record: F) -> Value
where
    F: FnMut(&T) -> Value,
{
    let mut map = serde_json::Map::new();
    for (key, item) in items {
        map.insert(key.clone(), record(item));
    }
    Value::Object(map)
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RELEASE-EXECUTION-RECORD",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

fn digest_str(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RELEASE-EXECUTION-DIGEST",
        &[HashPart::Str(label), HashPart::Str(value)],
        32,
    )
}

fn digest_json(label: &str, value: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RELEASE-EXECUTION-DIGEST",
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn ratio_bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return MAX_BPS;
    }
    let scaled = numerator.saturating_mul(MAX_BPS as u128) / denominator;
    match u64::try_from(scaled) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn mul_bps(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn u128_json(value: u128) -> Value {
    Value::String(value.to_string())
}

fn saturating_i128(value: u128) -> i128 {
    match i128::try_from(value) {
        Ok(value) => value,
        Err(_) => i128::MAX,
    }
}

fn len_u64(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}
