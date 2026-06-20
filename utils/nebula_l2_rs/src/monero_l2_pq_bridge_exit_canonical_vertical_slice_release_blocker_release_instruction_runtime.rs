use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerReleaseInstructionRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_RELEASE_INSTRUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-release-instruction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_RELEASE_INSTRUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_BLOCKER_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-release-instruction-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-release-instruction-devnet-v1";
pub const DEFAULT_RELEASE_BATCH_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-instruction-batch-devnet-v1";
pub const DEFAULT_L2_ACCEPTANCE_HEIGHT: u64 = 101_728;
pub const DEFAULT_MONERO_ANCHOR_HEIGHT: u64 = 3_505_920;
pub const DEFAULT_OBSERVATION_HEIGHT: u64 = 3_505_932;
pub const DEFAULT_RELEASE_NOT_BEFORE_HEIGHT: u64 = 3_506_064;
pub const DEFAULT_CHALLENGE_CLOSE_HEIGHT: u64 = 3_506_136;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_ALLOWED_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_MAX_METADATA_FIELDS: u64 = 5;
pub const DEFAULT_REQUIRED_BLOCKERS: usize = 14;
pub const DEFAULT_RELEASEABLE_THRESHOLD_SCORE: u64 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerLane {
    ExitAcceptance,
    WalletPayload,
    MoneroTransactionPlan,
    PqCustodyAuthorization,
    LiquidityExecution,
    ChallengeWindow,
    DisputeResolution,
    LiveFeedObservation,
    PrivacyBounds,
    InstructionAssembly,
}

impl BlockerLane {
    pub fn all() -> [Self; 10] {
        [
            Self::ExitAcceptance,
            Self::WalletPayload,
            Self::MoneroTransactionPlan,
            Self::PqCustodyAuthorization,
            Self::LiquidityExecution,
            Self::ChallengeWindow,
            Self::DisputeResolution,
            Self::LiveFeedObservation,
            Self::PrivacyBounds,
            Self::InstructionAssembly,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExitAcceptance => "exit_acceptance",
            Self::WalletPayload => "wallet_payload",
            Self::MoneroTransactionPlan => "monero_transaction_plan",
            Self::PqCustodyAuthorization => "pq_custody_authorization",
            Self::LiquidityExecution => "liquidity_execution",
            Self::ChallengeWindow => "challenge_window",
            Self::DisputeResolution => "dispute_resolution",
            Self::LiveFeedObservation => "live_feed_observation",
            Self::PrivacyBounds => "privacy_bounds",
            Self::InstructionAssembly => "instruction_assembly",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    ExitAcceptanceMissing,
    ExitAcceptanceRootMismatch,
    WalletPayloadMissing,
    WalletPayloadQuarantined,
    WalletDestinationMismatch,
    MoneroPlanMissing,
    MoneroFeePlanExpired,
    MoneroInputSetInsufficient,
    PqAuthorizationMissing,
    PqQuorumBelowPolicy,
    PqAuthorizationExpired,
    LiquidityReservationMissing,
    LiquiditySlippageExceeded,
    ChallengeWindowOpen,
    ChallengeEvidencePending,
    DisputeOpen,
    DisputeResolvedBlocked,
    LiveFeedMissing,
    LiveFeedStale,
    LiveFeedRootMismatch,
    PrivacySetTooSmall,
    MetadataBudgetExceeded,
    LinkageRiskExceeded,
    InstructionDigestMismatch,
    ReleaseBatchCapacityExceeded,
    OperatorHold,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExitAcceptanceMissing => "exit_acceptance_missing",
            Self::ExitAcceptanceRootMismatch => "exit_acceptance_root_mismatch",
            Self::WalletPayloadMissing => "wallet_payload_missing",
            Self::WalletPayloadQuarantined => "wallet_payload_quarantined",
            Self::WalletDestinationMismatch => "wallet_destination_mismatch",
            Self::MoneroPlanMissing => "monero_plan_missing",
            Self::MoneroFeePlanExpired => "monero_fee_plan_expired",
            Self::MoneroInputSetInsufficient => "monero_input_set_insufficient",
            Self::PqAuthorizationMissing => "pq_authorization_missing",
            Self::PqQuorumBelowPolicy => "pq_quorum_below_policy",
            Self::PqAuthorizationExpired => "pq_authorization_expired",
            Self::LiquidityReservationMissing => "liquidity_reservation_missing",
            Self::LiquiditySlippageExceeded => "liquidity_slippage_exceeded",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ChallengeEvidencePending => "challenge_evidence_pending",
            Self::DisputeOpen => "dispute_open",
            Self::DisputeResolvedBlocked => "dispute_resolved_blocked",
            Self::LiveFeedMissing => "live_feed_missing",
            Self::LiveFeedStale => "live_feed_stale",
            Self::LiveFeedRootMismatch => "live_feed_root_mismatch",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::LinkageRiskExceeded => "linkage_risk_exceeded",
            Self::InstructionDigestMismatch => "instruction_digest_mismatch",
            Self::ReleaseBatchCapacityExceeded => "release_batch_capacity_exceeded",
            Self::OperatorHold => "operator_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerStatus {
    Clear,
    Missing,
    Mismatched,
    Stale,
    Quarantined,
    Open,
    Pending,
    Expired,
    Exceeded,
    Held,
    Blocked,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Open => "open",
            Self::Pending => "pending",
            Self::Expired => "expired",
            Self::Exceeded => "exceeded",
            Self::Held => "held",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        match self {
            Self::Clear => false,
            Self::Missing
            | Self::Mismatched
            | Self::Stale
            | Self::Quarantined
            | Self::Open
            | Self::Pending
            | Self::Expired
            | Self::Exceeded
            | Self::Held
            | Self::Blocked => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Informational,
    Watch,
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Informational => 1,
            Self::Watch => 2,
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRequirement {
    RequiredRoot,
    RequiredReceipt,
    RequiredQuorum,
    RequiredFreshness,
    RequiredWindowClosure,
    RequiredBudget,
    RequiredOperatorRelease,
}

impl EvidenceRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequiredRoot => "required_root",
            Self::RequiredReceipt => "required_receipt",
            Self::RequiredQuorum => "required_quorum",
            Self::RequiredFreshness => "required_freshness",
            Self::RequiredWindowClosure => "required_window_closure",
            Self::RequiredBudget => "required_budget",
            Self::RequiredOperatorRelease => "required_operator_release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseInstructionDecision {
    Issue,
    Defer,
    Hold,
    Reject,
}

impl ReleaseInstructionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Defer => "defer",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_blocker_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub release_batch_id: String,
    pub min_privacy_set_size: u64,
    pub min_watcher_quorum: u64,
    pub max_allowed_leakage_units: u64,
    pub max_metadata_fields: u64,
    pub required_blockers: usize,
    pub releaseable_threshold_score: u64,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_blocker_suite: RELEASE_BLOCKER_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            release_batch_id: DEFAULT_RELEASE_BATCH_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_allowed_leakage_units: DEFAULT_MAX_ALLOWED_LEAKAGE_UNITS,
            max_metadata_fields: DEFAULT_MAX_METADATA_FIELDS,
            required_blockers: DEFAULT_REQUIRED_BLOCKERS,
            releaseable_threshold_score: DEFAULT_RELEASEABLE_THRESHOLD_SCORE,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_blocker_suite": self.release_blocker_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "release_batch_id": self.release_batch_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_allowed_leakage_units": self.max_allowed_leakage_units,
            "max_metadata_fields": self.max_metadata_fields,
            "required_blockers": self.required_blockers,
            "releaseable_threshold_score": self.releaseable_threshold_score,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitAcceptanceSnapshot {
    pub acceptance_id: String,
    pub exit_nullifier: String,
    pub acceptance_root: String,
    pub l2_acceptance_height: u64,
    pub accepted_amount_piconero: u64,
    pub accepted: bool,
    pub canonical: bool,
}

impl ExitAcceptanceSnapshot {
    pub fn devnet() -> Self {
        let acceptance_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-EXIT-ACCEPTANCE-ROOT",
            &[
                HashPart::Str(DEFAULT_RELEASE_CANDIDATE_ID),
                HashPart::U64(DEFAULT_L2_ACCEPTANCE_HEIGHT),
                HashPart::U64(24_000_000_000),
            ],
            32,
        );
        let acceptance_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-EXIT-ACCEPTANCE-ID",
            &[
                HashPart::Str(DEFAULT_VERTICAL_SLICE_ID),
                HashPart::Str(&acceptance_root),
            ],
            32,
        );
        Self {
            acceptance_id,
            exit_nullifier: "exit-nullifier-devnet-release-instruction-0001".to_string(),
            acceptance_root,
            l2_acceptance_height: DEFAULT_L2_ACCEPTANCE_HEIGHT,
            accepted_amount_piconero: 24_000_000_000,
            accepted: true,
            canonical: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acceptance_id": self.acceptance_id,
            "exit_nullifier": self.exit_nullifier,
            "acceptance_root": self.acceptance_root,
            "l2_acceptance_height": self.l2_acceptance_height,
            "accepted_amount_piconero": self.accepted_amount_piconero,
            "accepted": self.accepted,
            "canonical": self.canonical,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("EXIT-ACCEPTANCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletPayloadSnapshot {
    pub payload_id: String,
    pub wallet_bundle_root: String,
    pub destination_commitment: String,
    pub encrypted_notice_commitment: String,
    pub claim_receipt_root: String,
    pub metadata_field_count: u64,
    pub quarantined: bool,
    pub destination_matches_acceptance: bool,
}

impl WalletPayloadSnapshot {
    pub fn devnet(acceptance: &ExitAcceptanceSnapshot) -> Self {
        let wallet_bundle_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-WALLET-BUNDLE-ROOT",
            &[
                HashPart::Str(&acceptance.acceptance_id),
                HashPart::Str(&acceptance.exit_nullifier),
            ],
            32,
        );
        let destination_commitment = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-WALLET-DESTINATION",
            &[
                HashPart::Str(&wallet_bundle_root),
                HashPart::Str("view-and-spend-release-destination-devnet"),
            ],
            32,
        );
        let encrypted_notice_commitment = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-WALLET-NOTICE",
            &[
                HashPart::Str(&destination_commitment),
                HashPart::U64(DEFAULT_MONERO_ANCHOR_HEIGHT),
            ],
            32,
        );
        let claim_receipt_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-WALLET-CLAIM-ROOT",
            &[
                HashPart::Str(&wallet_bundle_root),
                HashPart::Str(&encrypted_notice_commitment),
            ],
            32,
        );
        let payload_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-WALLET-PAYLOAD-ID",
            &[
                HashPart::Str(&wallet_bundle_root),
                HashPart::Str(&claim_receipt_root),
            ],
            32,
        );
        Self {
            payload_id,
            wallet_bundle_root,
            destination_commitment,
            encrypted_notice_commitment,
            claim_receipt_root,
            metadata_field_count: 4,
            quarantined: false,
            destination_matches_acceptance: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "payload_id": self.payload_id,
            "wallet_bundle_root": self.wallet_bundle_root,
            "destination_commitment": self.destination_commitment,
            "encrypted_notice_commitment": self.encrypted_notice_commitment,
            "claim_receipt_root": self.claim_receipt_root,
            "metadata_field_count": self.metadata_field_count,
            "quarantined": self.quarantined,
            "destination_matches_acceptance": self.destination_matches_acceptance,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WALLET-PAYLOAD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroTransactionPlanSnapshot {
    pub plan_id: String,
    pub plan_root: String,
    pub input_set_root: String,
    pub fee_plan_root: String,
    pub change_policy_root: String,
    pub monero_anchor_height: u64,
    pub planned_output_count: u64,
    pub ring_member_count: u64,
    pub fee_valid_until_height: u64,
    pub plan_ready: bool,
}

impl MoneroTransactionPlanSnapshot {
    pub fn devnet(wallet: &WalletPayloadSnapshot) -> Self {
        let input_set_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-TX-INPUT-SET",
            &[
                HashPart::Str(&wallet.destination_commitment),
                HashPart::U64(DEFAULT_MONERO_ANCHOR_HEIGHT),
                HashPart::U64(16),
            ],
            32,
        );
        let fee_plan_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-TX-FEE-PLAN",
            &[
                HashPart::Str(&wallet.claim_receipt_root),
                HashPart::U64(DEFAULT_RELEASE_NOT_BEFORE_HEIGHT),
            ],
            32,
        );
        let change_policy_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-TX-CHANGE-POLICY",
            &[
                HashPart::Str(&input_set_root),
                HashPart::Str("return-to-custody-change-vault"),
            ],
            32,
        );
        let plan_root = merkle_root(&[
            input_set_root.clone(),
            fee_plan_root.clone(),
            change_policy_root.clone(),
        ]);
        let plan_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-TX-PLAN-ID",
            &[
                HashPart::Str(&wallet.payload_id),
                HashPart::Str(&plan_root),
                HashPart::U64(DEFAULT_MONERO_ANCHOR_HEIGHT),
            ],
            32,
        );
        Self {
            plan_id,
            plan_root,
            input_set_root,
            fee_plan_root,
            change_policy_root,
            monero_anchor_height: DEFAULT_MONERO_ANCHOR_HEIGHT,
            planned_output_count: 2,
            ring_member_count: 16,
            fee_valid_until_height: DEFAULT_RELEASE_NOT_BEFORE_HEIGHT + 180,
            plan_ready: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "plan_root": self.plan_root,
            "input_set_root": self.input_set_root,
            "fee_plan_root": self.fee_plan_root,
            "change_policy_root": self.change_policy_root,
            "monero_anchor_height": self.monero_anchor_height,
            "planned_output_count": self.planned_output_count,
            "ring_member_count": self.ring_member_count,
            "fee_valid_until_height": self.fee_valid_until_height,
            "plan_ready": self.plan_ready,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MONERO-TX-PLAN", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCustodyAuthorizationSnapshot {
    pub authorization_id: String,
    pub authorization_root: String,
    pub authority_set_root: String,
    pub signature_bundle_root: String,
    pub quorum_signed: u64,
    pub quorum_required: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub authorization_ready: bool,
}

impl PqCustodyAuthorizationSnapshot {
    pub fn devnet(plan: &MoneroTransactionPlanSnapshot) -> Self {
        let authority_set_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-PQ-AUTHORITY-SET",
            &[
                HashPart::Str(DEFAULT_RELEASE_CANDIDATE_ID),
                HashPart::U64(DEFAULT_MIN_WATCHER_QUORUM),
            ],
            32,
        );
        let signature_bundle_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-PQ-SIGNATURE-BUNDLE",
            &[
                HashPart::Str(&authority_set_root),
                HashPart::Str(&plan.plan_root),
            ],
            32,
        );
        let authorization_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-PQ-AUTHORIZATION-ROOT",
            &[
                HashPart::Str(&signature_bundle_root),
                HashPart::U64(DEFAULT_RELEASE_NOT_BEFORE_HEIGHT),
            ],
            32,
        );
        let authorization_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-PQ-AUTHORIZATION-ID",
            &[
                HashPart::Str(&plan.plan_id),
                HashPart::Str(&authorization_root),
            ],
            32,
        );
        Self {
            authorization_id,
            authorization_root,
            authority_set_root,
            signature_bundle_root,
            quorum_signed: 5,
            quorum_required: DEFAULT_MIN_WATCHER_QUORUM,
            valid_from_height: DEFAULT_MONERO_ANCHOR_HEIGHT,
            valid_until_height: DEFAULT_RELEASE_NOT_BEFORE_HEIGHT + 240,
            authorization_ready: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "authorization_root": self.authorization_root,
            "authority_set_root": self.authority_set_root,
            "signature_bundle_root": self.signature_bundle_root,
            "quorum_signed": self.quorum_signed,
            "quorum_required": self.quorum_required,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "authorization_ready": self.authorization_ready,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PQ-CUSTODY-AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityExecutionSnapshot {
    pub reservation_id: String,
    pub reservation_root: String,
    pub route_root: String,
    pub reserve_proof_root: String,
    pub reserved_amount_piconero: u64,
    pub minimum_release_amount_piconero: u64,
    pub max_slippage_bps: u64,
    pub observed_slippage_bps: u64,
    pub executable: bool,
}

impl LiquidityExecutionSnapshot {
    pub fn devnet(acceptance: &ExitAcceptanceSnapshot) -> Self {
        let reserve_proof_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIQUIDITY-RESERVE-PROOF",
            &[
                HashPart::Str(&acceptance.acceptance_root),
                HashPart::U64(24_200_000_000),
            ],
            32,
        );
        let route_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIQUIDITY-ROUTE",
            &[
                HashPart::Str(&reserve_proof_root),
                HashPart::Str("custody-vault-to-monero-release-planner"),
            ],
            32,
        );
        let reservation_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIQUIDITY-RESERVATION",
            &[
                HashPart::Str(&route_root),
                HashPart::U64(acceptance.accepted_amount_piconero),
            ],
            32,
        );
        let reservation_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIQUIDITY-RESERVATION-ID",
            &[
                HashPart::Str(&acceptance.acceptance_id),
                HashPart::Str(&reservation_root),
            ],
            32,
        );
        Self {
            reservation_id,
            reservation_root,
            route_root,
            reserve_proof_root,
            reserved_amount_piconero: 24_200_000_000,
            minimum_release_amount_piconero: 23_980_000_000,
            max_slippage_bps: 40,
            observed_slippage_bps: 12,
            executable: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "reservation_root": self.reservation_root,
            "route_root": self.route_root,
            "reserve_proof_root": self.reserve_proof_root,
            "reserved_amount_piconero": self.reserved_amount_piconero,
            "minimum_release_amount_piconero": self.minimum_release_amount_piconero,
            "max_slippage_bps": self.max_slippage_bps,
            "observed_slippage_bps": self.observed_slippage_bps,
            "executable": self.executable,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("LIQUIDITY-EXECUTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeDisputeSnapshot {
    pub challenge_root: String,
    pub dispute_root: String,
    pub challenge_opened_height: u64,
    pub challenge_close_height: u64,
    pub dispute_count: u64,
    pub pending_evidence_count: u64,
    pub resolved_blocked_count: u64,
    pub window_open: bool,
}

impl ChallengeDisputeSnapshot {
    pub fn devnet(acceptance: &ExitAcceptanceSnapshot) -> Self {
        let challenge_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-CHALLENGE-ROOT",
            &[
                HashPart::Str(&acceptance.exit_nullifier),
                HashPart::U64(DEFAULT_CHALLENGE_CLOSE_HEIGHT),
            ],
            32,
        );
        let dispute_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-DISPUTE-ROOT",
            &[
                HashPart::Str(&challenge_root),
                HashPart::U64(0),
                HashPart::U64(0),
            ],
            32,
        );
        Self {
            challenge_root,
            dispute_root,
            challenge_opened_height: DEFAULT_L2_ACCEPTANCE_HEIGHT,
            challenge_close_height: DEFAULT_CHALLENGE_CLOSE_HEIGHT,
            dispute_count: 0,
            pending_evidence_count: 0,
            resolved_blocked_count: 0,
            window_open: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_root": self.challenge_root,
            "dispute_root": self.dispute_root,
            "challenge_opened_height": self.challenge_opened_height,
            "challenge_close_height": self.challenge_close_height,
            "dispute_count": self.dispute_count,
            "pending_evidence_count": self.pending_evidence_count,
            "resolved_blocked_count": self.resolved_blocked_count,
            "window_open": self.window_open,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CHALLENGE-DISPUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveFeedObservationSnapshot {
    pub feed_root: String,
    pub header_root: String,
    pub watcher_root: String,
    pub reserve_observation_root: String,
    pub observation_height: u64,
    pub observed_watcher_quorum: u64,
    pub max_feed_age_blocks: u64,
    pub observed_feed_age_blocks: u64,
    pub root_matches_candidate: bool,
}

impl LiveFeedObservationSnapshot {
    pub fn devnet(plan: &MoneroTransactionPlanSnapshot) -> Self {
        let header_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIVE-FEED-HEADER-ROOT",
            &[
                HashPart::Str(&plan.plan_root),
                HashPart::U64(DEFAULT_OBSERVATION_HEIGHT),
            ],
            32,
        );
        let watcher_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIVE-FEED-WATCHER-ROOT",
            &[
                HashPart::Str(&header_root),
                HashPart::U64(DEFAULT_MIN_WATCHER_QUORUM),
            ],
            32,
        );
        let reserve_observation_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-LIVE-FEED-RESERVE-ROOT",
            &[
                HashPart::Str(&watcher_root),
                HashPart::Str("reserve-observed-above-release-floor"),
            ],
            32,
        );
        let feed_root = merkle_root(&[
            header_root.clone(),
            watcher_root.clone(),
            reserve_observation_root.clone(),
        ]);
        Self {
            feed_root,
            header_root,
            watcher_root,
            reserve_observation_root,
            observation_height: DEFAULT_OBSERVATION_HEIGHT,
            observed_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_feed_age_blocks: 48,
            observed_feed_age_blocks: 4,
            root_matches_candidate: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feed_root": self.feed_root,
            "header_root": self.header_root,
            "watcher_root": self.watcher_root,
            "reserve_observation_root": self.reserve_observation_root,
            "observation_height": self.observation_height,
            "observed_watcher_quorum": self.observed_watcher_quorum,
            "max_feed_age_blocks": self.max_feed_age_blocks,
            "observed_feed_age_blocks": self.observed_feed_age_blocks,
            "root_matches_candidate": self.root_matches_candidate,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("LIVE-FEED-OBSERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBoundsSnapshot {
    pub privacy_root: String,
    pub anonymity_set_size: u64,
    pub min_anonymity_set_size: u64,
    pub metadata_field_count: u64,
    pub max_metadata_fields: u64,
    pub linkage_risk_units: u64,
    pub max_linkage_risk_units: u64,
    pub bounds_satisfied: bool,
}

impl PrivacyBoundsSnapshot {
    pub fn devnet(wallet: &WalletPayloadSnapshot) -> Self {
        let privacy_root = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-PRIVACY-BOUNDS",
            &[
                HashPart::Str(&wallet.wallet_bundle_root),
                HashPart::U64(256),
                HashPart::U64(wallet.metadata_field_count),
                HashPart::U64(1),
            ],
            32,
        );
        Self {
            privacy_root,
            anonymity_set_size: 256,
            min_anonymity_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            metadata_field_count: wallet.metadata_field_count,
            max_metadata_fields: DEFAULT_MAX_METADATA_FIELDS,
            linkage_risk_units: 1,
            max_linkage_risk_units: DEFAULT_MAX_ALLOWED_LEAKAGE_UNITS,
            bounds_satisfied: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "privacy_root": self.privacy_root,
            "anonymity_set_size": self.anonymity_set_size,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "metadata_field_count": self.metadata_field_count,
            "max_metadata_fields": self.max_metadata_fields,
            "linkage_risk_units": self.linkage_risk_units,
            "max_linkage_risk_units": self.max_linkage_risk_units,
            "bounds_satisfied": self.bounds_satisfied,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRIVACY-BOUNDS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInstructionDraft {
    pub instruction_id: String,
    pub instruction_root: String,
    pub release_batch_id: String,
    pub release_candidate_id: String,
    pub release_not_before_height: u64,
    pub custody_authorization_root: String,
    pub monero_plan_root: String,
    pub wallet_payload_root: String,
    pub liquidity_reservation_root: String,
    pub assembled: bool,
}

impl ReleaseInstructionDraft {
    pub fn from_snapshots(
        config: &Config,
        wallet: &WalletPayloadSnapshot,
        plan: &MoneroTransactionPlanSnapshot,
        authorization: &PqCustodyAuthorizationSnapshot,
        liquidity: &LiquidityExecutionSnapshot,
    ) -> Self {
        let wallet_payload_root = wallet.state_root();
        let instruction_root = merkle_root(&[
            wallet_payload_root.clone(),
            plan.plan_root.clone(),
            authorization.authorization_root.clone(),
            liquidity.reservation_root.clone(),
        ]);
        let instruction_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-RELEASE-INSTRUCTION-ID",
            &[
                HashPart::Str(&config.release_batch_id),
                HashPart::Str(&config.release_candidate_id),
                HashPart::Str(&instruction_root),
            ],
            32,
        );
        Self {
            instruction_id,
            instruction_root,
            release_batch_id: config.release_batch_id.clone(),
            release_candidate_id: config.release_candidate_id.clone(),
            release_not_before_height: DEFAULT_RELEASE_NOT_BEFORE_HEIGHT,
            custody_authorization_root: authorization.authorization_root.clone(),
            monero_plan_root: plan.plan_root.clone(),
            wallet_payload_root,
            liquidity_reservation_root: liquidity.reservation_root.clone(),
            assembled: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "instruction_id": self.instruction_id,
            "instruction_root": self.instruction_root,
            "release_batch_id": self.release_batch_id,
            "release_candidate_id": self.release_candidate_id,
            "release_not_before_height": self.release_not_before_height,
            "custody_authorization_root": self.custody_authorization_root,
            "monero_plan_root": self.monero_plan_root,
            "wallet_payload_root": self.wallet_payload_root,
            "liquidity_reservation_root": self.liquidity_reservation_root,
            "assembled": self.assembled,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RELEASE-INSTRUCTION-DRAFT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBlocker {
    pub blocker_id: String,
    pub lane: BlockerLane,
    pub kind: BlockerKind,
    pub status: BlockerStatus,
    pub severity: BlockerSeverity,
    pub requirement: EvidenceRequirement,
    pub subject_root: String,
    pub observed_value: String,
    pub required_value: String,
    pub release_condition: String,
    pub blocks_instruction: bool,
}

impl ReleaseBlocker {
    pub fn new(
        lane: BlockerLane,
        kind: BlockerKind,
        status: BlockerStatus,
        severity: BlockerSeverity,
        requirement: EvidenceRequirement,
        subject_root: String,
        observed_value: String,
        required_value: String,
        release_condition: String,
    ) -> Self {
        let blocks_instruction = status.blocks_release() && severity.score() >= 3;
        let blocker_id = domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-RELEASE-INSTRUCTION-BLOCKER-ID",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(kind.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(&subject_root),
                HashPart::Str(&observed_value),
                HashPart::Str(&required_value),
            ],
            32,
        );
        Self {
            blocker_id,
            lane,
            kind,
            status,
            severity,
            requirement,
            subject_root,
            observed_value,
            required_value,
            release_condition,
            blocks_instruction,
        }
    }

    pub fn clear(
        lane: BlockerLane,
        kind: BlockerKind,
        requirement: EvidenceRequirement,
        subject_root: String,
        observed_value: String,
        release_condition: String,
    ) -> Self {
        Self::new(
            lane,
            kind,
            BlockerStatus::Clear,
            BlockerSeverity::Informational,
            requirement,
            subject_root,
            observed_value.clone(),
            observed_value,
            release_condition,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "requirement": self.requirement.as_str(),
            "subject_root": self.subject_root,
            "observed_value": self.observed_value,
            "required_value": self.required_value,
            "release_condition": self.release_condition,
            "blocks_instruction": self.blocks_instruction,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RELEASE-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBlockerSummary {
    pub blocker_count: u64,
    pub blocking_count: u64,
    pub clear_count: u64,
    pub release_stop_count: u64,
    pub max_severity_score: u64,
    pub aggregate_blocking_score: u64,
    pub decision: ReleaseInstructionDecision,
    pub release_instruction_issuable: bool,
}

impl ReleaseBlockerSummary {
    pub fn from_blockers(blockers: &BTreeMap<String, ReleaseBlocker>) -> Self {
        let mut blocking_count = 0;
        let mut clear_count = 0;
        let mut release_stop_count = 0;
        let mut max_severity_score = 0;
        let mut aggregate_blocking_score = 0;
        for blocker in blockers.values() {
            let score = blocker.severity.score();
            if blocker.status == BlockerStatus::Clear {
                clear_count += 1;
            }
            if blocker.blocks_instruction {
                blocking_count += 1;
                aggregate_blocking_score += score;
            }
            if blocker.severity == BlockerSeverity::ReleaseStop && blocker.blocks_instruction {
                release_stop_count += 1;
            }
            if score > max_severity_score {
                max_severity_score = score;
            }
        }
        let decision = if release_stop_count > 0 {
            ReleaseInstructionDecision::Reject
        } else if blocking_count > 0 {
            ReleaseInstructionDecision::Hold
        } else {
            ReleaseInstructionDecision::Issue
        };
        Self {
            blocker_count: blockers.len() as u64,
            blocking_count,
            clear_count,
            release_stop_count,
            max_severity_score,
            aggregate_blocking_score,
            decision,
            release_instruction_issuable: decision == ReleaseInstructionDecision::Issue,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_count": self.blocker_count,
            "blocking_count": self.blocking_count,
            "clear_count": self.clear_count,
            "release_stop_count": self.release_stop_count,
            "max_severity_score": self.max_severity_score,
            "aggregate_blocking_score": self.aggregate_blocking_score,
            "decision": self.decision.as_str(),
            "release_instruction_issuable": self.release_instruction_issuable,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RELEASE-BLOCKER-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub exit_acceptance: ExitAcceptanceSnapshot,
    pub wallet_payload: WalletPayloadSnapshot,
    pub monero_plan: MoneroTransactionPlanSnapshot,
    pub pq_authorization: PqCustodyAuthorizationSnapshot,
    pub liquidity_execution: LiquidityExecutionSnapshot,
    pub challenge_dispute: ChallengeDisputeSnapshot,
    pub live_feed_observation: LiveFeedObservationSnapshot,
    pub privacy_bounds: PrivacyBoundsSnapshot,
    pub release_instruction: ReleaseInstructionDraft,
    pub blockers: BTreeMap<String, ReleaseBlocker>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let exit_acceptance = ExitAcceptanceSnapshot::devnet();
        let wallet_payload = WalletPayloadSnapshot::devnet(&exit_acceptance);
        let monero_plan = MoneroTransactionPlanSnapshot::devnet(&wallet_payload);
        let pq_authorization = PqCustodyAuthorizationSnapshot::devnet(&monero_plan);
        let liquidity_execution = LiquidityExecutionSnapshot::devnet(&exit_acceptance);
        let challenge_dispute = ChallengeDisputeSnapshot::devnet(&exit_acceptance);
        let live_feed_observation = LiveFeedObservationSnapshot::devnet(&monero_plan);
        let privacy_bounds = PrivacyBoundsSnapshot::devnet(&wallet_payload);
        let release_instruction = ReleaseInstructionDraft::from_snapshots(
            &config,
            &wallet_payload,
            &monero_plan,
            &pq_authorization,
            &liquidity_execution,
        );
        let mut state = Self {
            config,
            exit_acceptance,
            wallet_payload,
            monero_plan,
            pq_authorization,
            liquidity_execution,
            challenge_dispute,
            live_feed_observation,
            privacy_bounds,
            release_instruction,
            blockers: BTreeMap::new(),
        };
        state.recompute_blockers();
        state
    }

    pub fn recompute_blockers(&mut self) {
        self.blockers = build_blockers(
            &self.config,
            &self.exit_acceptance,
            &self.wallet_payload,
            &self.monero_plan,
            &self.pq_authorization,
            &self.liquidity_execution,
            &self.challenge_dispute,
            &self.live_feed_observation,
            &self.privacy_bounds,
            &self.release_instruction,
        );
    }

    pub fn summary(&self) -> ReleaseBlockerSummary {
        ReleaseBlockerSummary::from_blockers(&self.blockers)
    }

    pub fn roots(&self) -> BTreeMap<String, String> {
        let mut roots = BTreeMap::new();
        roots.insert("config".to_string(), self.config.state_root());
        roots.insert(
            "exit_acceptance".to_string(),
            self.exit_acceptance.state_root(),
        );
        roots.insert(
            "wallet_payload".to_string(),
            self.wallet_payload.state_root(),
        );
        roots.insert("monero_plan".to_string(), self.monero_plan.state_root());
        roots.insert(
            "pq_authorization".to_string(),
            self.pq_authorization.state_root(),
        );
        roots.insert(
            "liquidity_execution".to_string(),
            self.liquidity_execution.state_root(),
        );
        roots.insert(
            "challenge_dispute".to_string(),
            self.challenge_dispute.state_root(),
        );
        roots.insert(
            "live_feed_observation".to_string(),
            self.live_feed_observation.state_root(),
        );
        roots.insert(
            "privacy_bounds".to_string(),
            self.privacy_bounds.state_root(),
        );
        roots.insert(
            "release_instruction".to_string(),
            self.release_instruction.state_root(),
        );
        roots.insert("blockers".to_string(), self.blocker_root());
        roots.insert("summary".to_string(), self.summary().state_root());
        roots
    }

    pub fn blocker_root(&self) -> String {
        merkle_root(
            &self
                .blockers
                .values()
                .map(ReleaseBlocker::state_root)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lane_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::new();
        for lane in BlockerLane::all() {
            counts.insert(lane.as_str().to_string(), 0);
        }
        for blocker in self.blockers.values() {
            let lane = blocker.lane.as_str().to_string();
            let count = counts.get(&lane).copied().unwrap_or(0);
            counts.insert(lane, count + 1);
        }
        counts
    }

    pub fn blocking_blockers(&self) -> Vec<Value> {
        self.blockers
            .values()
            .filter(|blocker| blocker.blocks_instruction)
            .map(ReleaseBlocker::public_record)
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_release_instruction_runtime",
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "exit_acceptance": self.exit_acceptance.public_record(),
            "wallet_payload": self.wallet_payload.public_record(),
            "monero_plan": self.monero_plan.public_record(),
            "pq_authorization": self.pq_authorization.public_record(),
            "liquidity_execution": self.liquidity_execution.public_record(),
            "challenge_dispute": self.challenge_dispute.public_record(),
            "live_feed_observation": self.live_feed_observation.public_record(),
            "privacy_bounds": self.privacy_bounds.public_record(),
            "release_instruction": self.release_instruction.public_record(),
            "blockers": self.blockers.values().map(ReleaseBlocker::public_record).collect::<Vec<_>>(),
            "blocking_blockers": self.blocking_blockers(),
            "lane_counts": self.lane_counts(),
            "summary": self.summary().public_record(),
            "roots": self.roots(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "MONERO-L2-RELEASE-BLOCKER-RELEASE-INSTRUCTION-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&json!(roots)),
                HashPart::Json(&self.summary().public_record()),
            ],
            32,
        )
    }

    pub fn validate(&self) -> Result<String> {
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.config.chain_id != CHAIN_ID {
            return Err("chain id mismatch".to_string());
        }
        if self.blockers.len() < self.config.required_blockers {
            return Err("release blocker inventory below configured minimum".to_string());
        }
        if self.release_instruction.release_candidate_id != self.config.release_candidate_id {
            return Err("release candidate binding mismatch".to_string());
        }
        Ok(self.state_root())
    }
}

fn build_blockers(
    config: &Config,
    exit_acceptance: &ExitAcceptanceSnapshot,
    wallet_payload: &WalletPayloadSnapshot,
    monero_plan: &MoneroTransactionPlanSnapshot,
    pq_authorization: &PqCustodyAuthorizationSnapshot,
    liquidity_execution: &LiquidityExecutionSnapshot,
    challenge_dispute: &ChallengeDisputeSnapshot,
    live_feed_observation: &LiveFeedObservationSnapshot,
    privacy_bounds: &PrivacyBoundsSnapshot,
    release_instruction: &ReleaseInstructionDraft,
) -> BTreeMap<String, ReleaseBlocker> {
    let mut blockers = BTreeMap::new();
    insert_blocker(
        &mut blockers,
        blocker_for_exit_acceptance_present(exit_acceptance),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_exit_acceptance_canonical(exit_acceptance),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_wallet_payload_present(wallet_payload),
    );
    insert_blocker(&mut blockers, blocker_for_wallet_quarantine(wallet_payload));
    insert_blocker(
        &mut blockers,
        blocker_for_wallet_destination(wallet_payload),
    );
    insert_blocker(&mut blockers, blocker_for_monero_plan_present(monero_plan));
    insert_blocker(&mut blockers, blocker_for_monero_fee_freshness(monero_plan));
    insert_blocker(&mut blockers, blocker_for_monero_input_set(monero_plan));
    insert_blocker(
        &mut blockers,
        blocker_for_pq_authorization_present(pq_authorization),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_pq_quorum(config, pq_authorization),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_pq_authorization_freshness(pq_authorization),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_liquidity_reservation(liquidity_execution),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_liquidity_slippage(liquidity_execution),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_challenge_window(challenge_dispute),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_challenge_evidence(challenge_dispute),
    );
    insert_blocker(&mut blockers, blocker_for_dispute_open(challenge_dispute));
    insert_blocker(
        &mut blockers,
        blocker_for_dispute_resolved_blocked(challenge_dispute),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_live_feed_present(live_feed_observation),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_live_feed_freshness(live_feed_observation),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_live_feed_root_match(live_feed_observation),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_privacy_set(config, privacy_bounds),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_metadata_budget(config, privacy_bounds),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_linkage_risk(config, privacy_bounds),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_instruction_assembly(release_instruction),
    );
    insert_blocker(
        &mut blockers,
        blocker_for_instruction_digest(
            release_instruction,
            wallet_payload,
            monero_plan,
            pq_authorization,
            liquidity_execution,
        ),
    );
    insert_blocker(&mut blockers, blocker_for_operator_hold(config));
    blockers
}

fn insert_blocker(blockers: &mut BTreeMap<String, ReleaseBlocker>, blocker: ReleaseBlocker) {
    blockers.insert(blocker.blocker_id.clone(), blocker);
}

fn blocker_for_exit_acceptance_present(exit_acceptance: &ExitAcceptanceSnapshot) -> ReleaseBlocker {
    if exit_acceptance.accepted {
        ReleaseBlocker::clear(
            BlockerLane::ExitAcceptance,
            BlockerKind::ExitAcceptanceMissing,
            EvidenceRequirement::RequiredReceipt,
            exit_acceptance.state_root(),
            "accepted".to_string(),
            "exit acceptance receipt is present".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::ExitAcceptance,
            BlockerKind::ExitAcceptanceMissing,
            BlockerStatus::Missing,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredReceipt,
            exit_acceptance.state_root(),
            "missing".to_string(),
            "accepted".to_string(),
            "record canonical exit acceptance receipt before instruction issuance".to_string(),
        )
    }
}

fn blocker_for_exit_acceptance_canonical(
    exit_acceptance: &ExitAcceptanceSnapshot,
) -> ReleaseBlocker {
    if exit_acceptance.canonical {
        ReleaseBlocker::clear(
            BlockerLane::ExitAcceptance,
            BlockerKind::ExitAcceptanceRootMismatch,
            EvidenceRequirement::RequiredRoot,
            exit_acceptance.acceptance_root.clone(),
            "canonical".to_string(),
            "acceptance root matches canonical exit spine".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::ExitAcceptance,
            BlockerKind::ExitAcceptanceRootMismatch,
            BlockerStatus::Mismatched,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            exit_acceptance.acceptance_root.clone(),
            "non_canonical".to_string(),
            "canonical".to_string(),
            "reconcile acceptance root with canonical forced-exit spine".to_string(),
        )
    }
}

fn blocker_for_wallet_payload_present(wallet_payload: &WalletPayloadSnapshot) -> ReleaseBlocker {
    if wallet_payload.wallet_bundle_root.is_empty() {
        ReleaseBlocker::new(
            BlockerLane::WalletPayload,
            BlockerKind::WalletPayloadMissing,
            BlockerStatus::Missing,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            wallet_payload.state_root(),
            "missing".to_string(),
            "wallet_bundle_root".to_string(),
            "attach wallet recovery payload root before release instruction issuance".to_string(),
        )
    } else {
        ReleaseBlocker::clear(
            BlockerLane::WalletPayload,
            BlockerKind::WalletPayloadMissing,
            EvidenceRequirement::RequiredRoot,
            wallet_payload.wallet_bundle_root.clone(),
            "wallet_bundle_root".to_string(),
            "wallet payload root is available".to_string(),
        )
    }
}

fn blocker_for_wallet_quarantine(wallet_payload: &WalletPayloadSnapshot) -> ReleaseBlocker {
    if wallet_payload.quarantined {
        ReleaseBlocker::new(
            BlockerLane::WalletPayload,
            BlockerKind::WalletPayloadQuarantined,
            BlockerStatus::Quarantined,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredOperatorRelease,
            wallet_payload.wallet_bundle_root.clone(),
            "quarantined".to_string(),
            "released".to_string(),
            "clear wallet payload quarantine marker".to_string(),
        )
    } else {
        ReleaseBlocker::clear(
            BlockerLane::WalletPayload,
            BlockerKind::WalletPayloadQuarantined,
            EvidenceRequirement::RequiredOperatorRelease,
            wallet_payload.wallet_bundle_root.clone(),
            "released".to_string(),
            "wallet payload is not quarantined".to_string(),
        )
    }
}

fn blocker_for_wallet_destination(wallet_payload: &WalletPayloadSnapshot) -> ReleaseBlocker {
    if wallet_payload.destination_matches_acceptance {
        ReleaseBlocker::clear(
            BlockerLane::WalletPayload,
            BlockerKind::WalletDestinationMismatch,
            EvidenceRequirement::RequiredRoot,
            wallet_payload.destination_commitment.clone(),
            "matched".to_string(),
            "wallet destination commitment matches accepted exit".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::WalletPayload,
            BlockerKind::WalletDestinationMismatch,
            BlockerStatus::Mismatched,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            wallet_payload.destination_commitment.clone(),
            "mismatched".to_string(),
            "matched".to_string(),
            "replace destination commitment with accepted wallet release commitment".to_string(),
        )
    }
}

fn blocker_for_monero_plan_present(monero_plan: &MoneroTransactionPlanSnapshot) -> ReleaseBlocker {
    if monero_plan.plan_ready {
        ReleaseBlocker::clear(
            BlockerLane::MoneroTransactionPlan,
            BlockerKind::MoneroPlanMissing,
            EvidenceRequirement::RequiredRoot,
            monero_plan.plan_root.clone(),
            "ready".to_string(),
            "Monero release transaction plan is present".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::MoneroTransactionPlan,
            BlockerKind::MoneroPlanMissing,
            BlockerStatus::Missing,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            monero_plan.state_root(),
            "missing".to_string(),
            "ready".to_string(),
            "construct deterministic Monero transaction plan".to_string(),
        )
    }
}

fn blocker_for_monero_fee_freshness(monero_plan: &MoneroTransactionPlanSnapshot) -> ReleaseBlocker {
    if monero_plan.fee_valid_until_height >= DEFAULT_RELEASE_NOT_BEFORE_HEIGHT {
        ReleaseBlocker::clear(
            BlockerLane::MoneroTransactionPlan,
            BlockerKind::MoneroFeePlanExpired,
            EvidenceRequirement::RequiredFreshness,
            monero_plan.fee_plan_root.clone(),
            monero_plan.fee_valid_until_height.to_string(),
            "fee plan remains valid through release-not-before height".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::MoneroTransactionPlan,
            BlockerKind::MoneroFeePlanExpired,
            BlockerStatus::Expired,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredFreshness,
            monero_plan.fee_plan_root.clone(),
            monero_plan.fee_valid_until_height.to_string(),
            DEFAULT_RELEASE_NOT_BEFORE_HEIGHT.to_string(),
            "refresh Monero fee plan before release instruction issuance".to_string(),
        )
    }
}

fn blocker_for_monero_input_set(monero_plan: &MoneroTransactionPlanSnapshot) -> ReleaseBlocker {
    if monero_plan.ring_member_count >= 16 {
        ReleaseBlocker::clear(
            BlockerLane::MoneroTransactionPlan,
            BlockerKind::MoneroInputSetInsufficient,
            EvidenceRequirement::RequiredBudget,
            monero_plan.input_set_root.clone(),
            monero_plan.ring_member_count.to_string(),
            "Monero input set satisfies ring member floor".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::MoneroTransactionPlan,
            BlockerKind::MoneroInputSetInsufficient,
            BlockerStatus::Pending,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredBudget,
            monero_plan.input_set_root.clone(),
            monero_plan.ring_member_count.to_string(),
            "16".to_string(),
            "expand Monero input set before custody release instruction".to_string(),
        )
    }
}

fn blocker_for_pq_authorization_present(
    pq_authorization: &PqCustodyAuthorizationSnapshot,
) -> ReleaseBlocker {
    if pq_authorization.authorization_ready {
        ReleaseBlocker::clear(
            BlockerLane::PqCustodyAuthorization,
            BlockerKind::PqAuthorizationMissing,
            EvidenceRequirement::RequiredRoot,
            pq_authorization.authorization_root.clone(),
            "ready".to_string(),
            "PQ custody authorization root is available".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::PqCustodyAuthorization,
            BlockerKind::PqAuthorizationMissing,
            BlockerStatus::Missing,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            pq_authorization.state_root(),
            "missing".to_string(),
            "ready".to_string(),
            "collect PQ custody authorization before instruction issuance".to_string(),
        )
    }
}

fn blocker_for_pq_quorum(
    config: &Config,
    pq_authorization: &PqCustodyAuthorizationSnapshot,
) -> ReleaseBlocker {
    let required = config
        .min_watcher_quorum
        .max(pq_authorization.quorum_required);
    if pq_authorization.quorum_signed >= required {
        ReleaseBlocker::clear(
            BlockerLane::PqCustodyAuthorization,
            BlockerKind::PqQuorumBelowPolicy,
            EvidenceRequirement::RequiredQuorum,
            pq_authorization.signature_bundle_root.clone(),
            pq_authorization.quorum_signed.to_string(),
            "PQ custody quorum satisfies policy".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::PqCustodyAuthorization,
            BlockerKind::PqQuorumBelowPolicy,
            BlockerStatus::Pending,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredQuorum,
            pq_authorization.signature_bundle_root.clone(),
            pq_authorization.quorum_signed.to_string(),
            required.to_string(),
            "collect additional PQ custody signatures".to_string(),
        )
    }
}

fn blocker_for_pq_authorization_freshness(
    pq_authorization: &PqCustodyAuthorizationSnapshot,
) -> ReleaseBlocker {
    if pq_authorization.valid_until_height >= DEFAULT_RELEASE_NOT_BEFORE_HEIGHT {
        ReleaseBlocker::clear(
            BlockerLane::PqCustodyAuthorization,
            BlockerKind::PqAuthorizationExpired,
            EvidenceRequirement::RequiredFreshness,
            pq_authorization.authorization_root.clone(),
            pq_authorization.valid_until_height.to_string(),
            "PQ authorization is fresh for release height".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::PqCustodyAuthorization,
            BlockerKind::PqAuthorizationExpired,
            BlockerStatus::Expired,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredFreshness,
            pq_authorization.authorization_root.clone(),
            pq_authorization.valid_until_height.to_string(),
            DEFAULT_RELEASE_NOT_BEFORE_HEIGHT.to_string(),
            "refresh PQ custody authorization window".to_string(),
        )
    }
}

fn blocker_for_liquidity_reservation(
    liquidity_execution: &LiquidityExecutionSnapshot,
) -> ReleaseBlocker {
    if liquidity_execution.executable {
        ReleaseBlocker::clear(
            BlockerLane::LiquidityExecution,
            BlockerKind::LiquidityReservationMissing,
            EvidenceRequirement::RequiredReceipt,
            liquidity_execution.reservation_root.clone(),
            "reserved".to_string(),
            "liquidity route has executable reservation".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::LiquidityExecution,
            BlockerKind::LiquidityReservationMissing,
            BlockerStatus::Missing,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredReceipt,
            liquidity_execution.state_root(),
            "missing".to_string(),
            "reserved".to_string(),
            "reserve liquidity for release route".to_string(),
        )
    }
}

fn blocker_for_liquidity_slippage(
    liquidity_execution: &LiquidityExecutionSnapshot,
) -> ReleaseBlocker {
    if liquidity_execution.observed_slippage_bps <= liquidity_execution.max_slippage_bps {
        ReleaseBlocker::clear(
            BlockerLane::LiquidityExecution,
            BlockerKind::LiquiditySlippageExceeded,
            EvidenceRequirement::RequiredBudget,
            liquidity_execution.route_root.clone(),
            liquidity_execution.observed_slippage_bps.to_string(),
            "liquidity slippage remains within policy".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::LiquidityExecution,
            BlockerKind::LiquiditySlippageExceeded,
            BlockerStatus::Exceeded,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredBudget,
            liquidity_execution.route_root.clone(),
            liquidity_execution.observed_slippage_bps.to_string(),
            liquidity_execution.max_slippage_bps.to_string(),
            "refresh route or liquidity reservation before release".to_string(),
        )
    }
}

fn blocker_for_challenge_window(challenge_dispute: &ChallengeDisputeSnapshot) -> ReleaseBlocker {
    if challenge_dispute.window_open {
        ReleaseBlocker::new(
            BlockerLane::ChallengeWindow,
            BlockerKind::ChallengeWindowOpen,
            BlockerStatus::Open,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredWindowClosure,
            challenge_dispute.challenge_root.clone(),
            "open".to_string(),
            "closed".to_string(),
            "wait for challenge window closure".to_string(),
        )
    } else {
        ReleaseBlocker::clear(
            BlockerLane::ChallengeWindow,
            BlockerKind::ChallengeWindowOpen,
            EvidenceRequirement::RequiredWindowClosure,
            challenge_dispute.challenge_root.clone(),
            "closed".to_string(),
            "challenge window is closed".to_string(),
        )
    }
}

fn blocker_for_challenge_evidence(challenge_dispute: &ChallengeDisputeSnapshot) -> ReleaseBlocker {
    if challenge_dispute.pending_evidence_count == 0 {
        ReleaseBlocker::clear(
            BlockerLane::ChallengeWindow,
            BlockerKind::ChallengeEvidencePending,
            EvidenceRequirement::RequiredReceipt,
            challenge_dispute.challenge_root.clone(),
            "0".to_string(),
            "no pending challenge evidence remains".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::ChallengeWindow,
            BlockerKind::ChallengeEvidencePending,
            BlockerStatus::Pending,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredReceipt,
            challenge_dispute.challenge_root.clone(),
            challenge_dispute.pending_evidence_count.to_string(),
            "0".to_string(),
            "resolve pending challenge evidence".to_string(),
        )
    }
}

fn blocker_for_dispute_open(challenge_dispute: &ChallengeDisputeSnapshot) -> ReleaseBlocker {
    if challenge_dispute.dispute_count == 0 {
        ReleaseBlocker::clear(
            BlockerLane::DisputeResolution,
            BlockerKind::DisputeOpen,
            EvidenceRequirement::RequiredReceipt,
            challenge_dispute.dispute_root.clone(),
            "0".to_string(),
            "no open disputes remain".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::DisputeResolution,
            BlockerKind::DisputeOpen,
            BlockerStatus::Open,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredReceipt,
            challenge_dispute.dispute_root.clone(),
            challenge_dispute.dispute_count.to_string(),
            "0".to_string(),
            "close all release disputes before issuance".to_string(),
        )
    }
}

fn blocker_for_dispute_resolved_blocked(
    challenge_dispute: &ChallengeDisputeSnapshot,
) -> ReleaseBlocker {
    if challenge_dispute.resolved_blocked_count == 0 {
        ReleaseBlocker::clear(
            BlockerLane::DisputeResolution,
            BlockerKind::DisputeResolvedBlocked,
            EvidenceRequirement::RequiredReceipt,
            challenge_dispute.dispute_root.clone(),
            "0".to_string(),
            "no dispute resolved against release".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::DisputeResolution,
            BlockerKind::DisputeResolvedBlocked,
            BlockerStatus::Blocked,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredReceipt,
            challenge_dispute.dispute_root.clone(),
            challenge_dispute.resolved_blocked_count.to_string(),
            "0".to_string(),
            "remove release candidate or replace with cleared dispute outcome".to_string(),
        )
    }
}

fn blocker_for_live_feed_present(
    live_feed_observation: &LiveFeedObservationSnapshot,
) -> ReleaseBlocker {
    if live_feed_observation.feed_root.is_empty() {
        ReleaseBlocker::new(
            BlockerLane::LiveFeedObservation,
            BlockerKind::LiveFeedMissing,
            BlockerStatus::Missing,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredRoot,
            live_feed_observation.state_root(),
            "missing".to_string(),
            "feed_root".to_string(),
            "ingest live-feed observation root".to_string(),
        )
    } else {
        ReleaseBlocker::clear(
            BlockerLane::LiveFeedObservation,
            BlockerKind::LiveFeedMissing,
            EvidenceRequirement::RequiredRoot,
            live_feed_observation.feed_root.clone(),
            "feed_root".to_string(),
            "live-feed observation root is present".to_string(),
        )
    }
}

fn blocker_for_live_feed_freshness(
    live_feed_observation: &LiveFeedObservationSnapshot,
) -> ReleaseBlocker {
    if live_feed_observation.observed_feed_age_blocks <= live_feed_observation.max_feed_age_blocks {
        ReleaseBlocker::clear(
            BlockerLane::LiveFeedObservation,
            BlockerKind::LiveFeedStale,
            EvidenceRequirement::RequiredFreshness,
            live_feed_observation.feed_root.clone(),
            live_feed_observation.observed_feed_age_blocks.to_string(),
            "live-feed observation age remains within policy".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::LiveFeedObservation,
            BlockerKind::LiveFeedStale,
            BlockerStatus::Stale,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredFreshness,
            live_feed_observation.feed_root.clone(),
            live_feed_observation.observed_feed_age_blocks.to_string(),
            live_feed_observation.max_feed_age_blocks.to_string(),
            "refresh live-feed observation before release issuance".to_string(),
        )
    }
}

fn blocker_for_live_feed_root_match(
    live_feed_observation: &LiveFeedObservationSnapshot,
) -> ReleaseBlocker {
    if live_feed_observation.root_matches_candidate {
        ReleaseBlocker::clear(
            BlockerLane::LiveFeedObservation,
            BlockerKind::LiveFeedRootMismatch,
            EvidenceRequirement::RequiredRoot,
            live_feed_observation.feed_root.clone(),
            "matched".to_string(),
            "live-feed root matches release candidate".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::LiveFeedObservation,
            BlockerKind::LiveFeedRootMismatch,
            BlockerStatus::Mismatched,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            live_feed_observation.feed_root.clone(),
            "mismatched".to_string(),
            "matched".to_string(),
            "reconcile live-feed root with candidate evidence root".to_string(),
        )
    }
}

fn blocker_for_privacy_set(
    config: &Config,
    privacy_bounds: &PrivacyBoundsSnapshot,
) -> ReleaseBlocker {
    if privacy_bounds.anonymity_set_size >= config.min_privacy_set_size {
        ReleaseBlocker::clear(
            BlockerLane::PrivacyBounds,
            BlockerKind::PrivacySetTooSmall,
            EvidenceRequirement::RequiredBudget,
            privacy_bounds.privacy_root.clone(),
            privacy_bounds.anonymity_set_size.to_string(),
            "privacy set satisfies configured floor".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::PrivacyBounds,
            BlockerKind::PrivacySetTooSmall,
            BlockerStatus::Exceeded,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredBudget,
            privacy_bounds.privacy_root.clone(),
            privacy_bounds.anonymity_set_size.to_string(),
            config.min_privacy_set_size.to_string(),
            "increase release anonymity set before instruction issuance".to_string(),
        )
    }
}

fn blocker_for_metadata_budget(
    config: &Config,
    privacy_bounds: &PrivacyBoundsSnapshot,
) -> ReleaseBlocker {
    if privacy_bounds.metadata_field_count <= config.max_metadata_fields {
        ReleaseBlocker::clear(
            BlockerLane::PrivacyBounds,
            BlockerKind::MetadataBudgetExceeded,
            EvidenceRequirement::RequiredBudget,
            privacy_bounds.privacy_root.clone(),
            privacy_bounds.metadata_field_count.to_string(),
            "metadata field count remains within privacy budget".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::PrivacyBounds,
            BlockerKind::MetadataBudgetExceeded,
            BlockerStatus::Exceeded,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredBudget,
            privacy_bounds.privacy_root.clone(),
            privacy_bounds.metadata_field_count.to_string(),
            config.max_metadata_fields.to_string(),
            "redact release metadata fields before issuance".to_string(),
        )
    }
}

fn blocker_for_linkage_risk(
    config: &Config,
    privacy_bounds: &PrivacyBoundsSnapshot,
) -> ReleaseBlocker {
    if privacy_bounds.linkage_risk_units <= config.max_allowed_leakage_units {
        ReleaseBlocker::clear(
            BlockerLane::PrivacyBounds,
            BlockerKind::LinkageRiskExceeded,
            EvidenceRequirement::RequiredBudget,
            privacy_bounds.privacy_root.clone(),
            privacy_bounds.linkage_risk_units.to_string(),
            "linkage risk remains within privacy budget".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::PrivacyBounds,
            BlockerKind::LinkageRiskExceeded,
            BlockerStatus::Exceeded,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredBudget,
            privacy_bounds.privacy_root.clone(),
            privacy_bounds.linkage_risk_units.to_string(),
            config.max_allowed_leakage_units.to_string(),
            "rebuild release set with lower linkage risk".to_string(),
        )
    }
}

fn blocker_for_instruction_assembly(
    release_instruction: &ReleaseInstructionDraft,
) -> ReleaseBlocker {
    if release_instruction.assembled {
        ReleaseBlocker::clear(
            BlockerLane::InstructionAssembly,
            BlockerKind::ReleaseBatchCapacityExceeded,
            EvidenceRequirement::RequiredRoot,
            release_instruction.instruction_root.clone(),
            "assembled".to_string(),
            "release instruction draft is assembled".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::InstructionAssembly,
            BlockerKind::ReleaseBatchCapacityExceeded,
            BlockerStatus::Pending,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredRoot,
            release_instruction.state_root(),
            "not_assembled".to_string(),
            "assembled".to_string(),
            "assemble release instruction draft from canonical roots".to_string(),
        )
    }
}

fn blocker_for_instruction_digest(
    release_instruction: &ReleaseInstructionDraft,
    wallet_payload: &WalletPayloadSnapshot,
    monero_plan: &MoneroTransactionPlanSnapshot,
    pq_authorization: &PqCustodyAuthorizationSnapshot,
    liquidity_execution: &LiquidityExecutionSnapshot,
) -> ReleaseBlocker {
    let expected_root = merkle_root(&[
        wallet_payload.state_root(),
        monero_plan.plan_root.clone(),
        pq_authorization.authorization_root.clone(),
        liquidity_execution.reservation_root.clone(),
    ]);
    if release_instruction.instruction_root == expected_root {
        ReleaseBlocker::clear(
            BlockerLane::InstructionAssembly,
            BlockerKind::InstructionDigestMismatch,
            EvidenceRequirement::RequiredRoot,
            release_instruction.instruction_root.clone(),
            "matched".to_string(),
            "release instruction digest matches source roots".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::InstructionAssembly,
            BlockerKind::InstructionDigestMismatch,
            BlockerStatus::Mismatched,
            BlockerSeverity::ReleaseStop,
            EvidenceRequirement::RequiredRoot,
            release_instruction.instruction_root.clone(),
            "mismatched".to_string(),
            expected_root,
            "rebuild release instruction digest from canonical source roots".to_string(),
        )
    }
}

fn blocker_for_operator_hold(config: &Config) -> ReleaseBlocker {
    if config.production_release_allowed {
        ReleaseBlocker::clear(
            BlockerLane::InstructionAssembly,
            BlockerKind::OperatorHold,
            EvidenceRequirement::RequiredOperatorRelease,
            config.state_root(),
            "released".to_string(),
            "operator release gate allows production issuance".to_string(),
        )
    } else {
        ReleaseBlocker::new(
            BlockerLane::InstructionAssembly,
            BlockerKind::OperatorHold,
            BlockerStatus::Held,
            BlockerSeverity::Critical,
            EvidenceRequirement::RequiredOperatorRelease,
            config.state_root(),
            "held".to_string(),
            "released".to_string(),
            "set production release gate after review signoff".to_string(),
        )
    }
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-RELEASE-INSTRUCTION-RECORD",
        &[HashPart::Str(domain), HashPart::Json(record)],
        32,
    )
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
