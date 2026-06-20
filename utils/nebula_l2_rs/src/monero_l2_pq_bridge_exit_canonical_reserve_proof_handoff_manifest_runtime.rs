use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalReserveProofHandoffManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RESERVE_PROOF_HANDOFF_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-reserve-proof-handoff-manifest-runtime-v1-release-candidate-heavy-gate-bound";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RESERVE_PROOF_HANDOFF_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HANDOFF_SUITE: &str =
    "canonical-forced-exit-reserve-proof-handoff-heavy-gate-release-path-v1";
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MIN_RELEASE_TRANCHE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MIN_CHALLENGE_HOLDBACK_BPS: u64 = 1_200;
pub const DEFAULT_MAX_FEE_CAP_BPS: u64 = 8;
pub const DEFAULT_MAX_RESERVE_STALENESS_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_EMERGENCY_PATHS: u64 = 2;
pub const DEFAULT_MIN_LIQUIDITY_HEADROOM_BPS: u64 = 1_500;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffTarget {
    HeavyGate,
    ReleasePath,
    ChallengeWindow,
    EmergencyReservePath,
}

impl HandoffTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeavyGate => "heavy_gate",
            Self::ReleasePath => "release_path",
            Self::ChallengeWindow => "challenge_window",
            Self::EmergencyReservePath => "emergency_reserve_path",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ReserveAccountRoot,
    PendingExitLiabilityRoot,
    ChallengeHoldbackRoot,
    ReleaseTrancheRoot,
    EmergencyReservePathRoot,
    FeeCapCommitment,
    StaleReserveRejectionRoot,
    LiquidityExhaustionEvidenceRoot,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveAccountRoot => "reserve_account_root",
            Self::PendingExitLiabilityRoot => "pending_exit_liability_root",
            Self::ChallengeHoldbackRoot => "challenge_holdback_root",
            Self::ReleaseTrancheRoot => "release_tranche_root",
            Self::EmergencyReservePathRoot => "emergency_reserve_path_root",
            Self::FeeCapCommitment => "fee_cap_commitment",
            Self::StaleReserveRejectionRoot => "stale_reserve_rejection_root",
            Self::LiquidityExhaustionEvidenceRoot => "liquidity_exhaustion_evidence_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Required,
    Present,
    DeferredLiveExecution,
    Rejected,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Present => "present",
            Self::DeferredLiveExecution => "deferred_live_execution",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SufficiencyAnswer {
    SufficientForForcedExitHandoff,
    SufficientWithLiveProofExecutionDeferred,
    Insufficient,
}

impl SufficiencyAnswer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SufficientForForcedExitHandoff => "sufficient_for_forced_exit_handoff",
            Self::SufficientWithLiveProofExecutionDeferred => {
                "sufficient_with_live_proof_execution_deferred"
            }
            Self::Insufficient => "insufficient",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub handoff_suite: String,
    pub min_reserve_coverage_bps: u64,
    pub min_release_tranche_coverage_bps: u64,
    pub min_challenge_holdback_bps: u64,
    pub max_fee_cap_bps: u64,
    pub max_reserve_staleness_blocks: u64,
    pub min_emergency_paths: u64,
    pub min_liquidity_headroom_bps: u64,
    pub heavy_gate_requires_all_roots: bool,
    pub release_path_requires_liquidity_evidence: bool,
    pub live_proof_execution_deferred: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            handoff_suite: HANDOFF_SUITE.to_string(),
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_release_tranche_coverage_bps: DEFAULT_MIN_RELEASE_TRANCHE_COVERAGE_BPS,
            min_challenge_holdback_bps: DEFAULT_MIN_CHALLENGE_HOLDBACK_BPS,
            max_fee_cap_bps: DEFAULT_MAX_FEE_CAP_BPS,
            max_reserve_staleness_blocks: DEFAULT_MAX_RESERVE_STALENESS_BLOCKS,
            min_emergency_paths: DEFAULT_MIN_EMERGENCY_PATHS,
            min_liquidity_headroom_bps: DEFAULT_MIN_LIQUIDITY_HEADROOM_BPS,
            heavy_gate_requires_all_roots: true,
            release_path_requires_liquidity_evidence: true,
            live_proof_execution_deferred: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "handoff_suite": self.handoff_suite,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_release_tranche_coverage_bps": self.min_release_tranche_coverage_bps,
            "min_challenge_holdback_bps": self.min_challenge_holdback_bps,
            "max_fee_cap_bps": self.max_fee_cap_bps,
            "max_reserve_staleness_blocks": self.max_reserve_staleness_blocks,
            "min_emergency_paths": self.min_emergency_paths,
            "min_liquidity_headroom_bps": self.min_liquidity_headroom_bps,
            "heavy_gate_requires_all_roots": self.heavy_gate_requires_all_roots,
            "release_path_requires_liquidity_evidence": self.release_path_requires_liquidity_evidence,
            "live_proof_execution_deferred": self.live_proof_execution_deferred,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveAccountRoot {
    pub lane: String,
    pub account_root: String,
    pub attestation_root: String,
    pub spend_authority_root: String,
    pub available_atomic: u128,
    pub reserved_atomic: u128,
    pub observed_at_height: u64,
}

impl ReserveAccountRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "account_root": self.account_root,
            "attestation_root": self.attestation_root,
            "spend_authority_root": self.spend_authority_root,
            "available_atomic": self.available_atomic,
            "reserved_atomic": self.reserved_atomic,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingExitLiability {
    pub exit_id: String,
    pub claimant_commitment: String,
    pub liability_atomic: u128,
    pub challenge_holdback_atomic: u128,
    pub release_tranche_id: String,
    pub evidence_root: String,
}

impl PendingExitLiability {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "claimant_commitment": self.claimant_commitment,
            "liability_atomic": self.liability_atomic,
            "challenge_holdback_atomic": self.challenge_holdback_atomic,
            "release_tranche_id": self.release_tranche_id,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseTranche {
    pub tranche_id: String,
    pub reserve_lane: String,
    pub max_release_atomic: u128,
    pub fee_cap_bps: u64,
    pub tranche_root: String,
    pub heavy_gate_release_root: String,
}

impl ReleaseTranche {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "reserve_lane": self.reserve_lane,
            "max_release_atomic": self.max_release_atomic,
            "fee_cap_bps": self.fee_cap_bps,
            "tranche_root": self.tranche_root,
            "heavy_gate_release_root": self.heavy_gate_release_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyReservePath {
    pub path_id: String,
    pub reserve_lane: String,
    pub activation_condition: String,
    pub route_root: String,
    pub capacity_atomic: u128,
    pub priority: u64,
}

impl EmergencyReservePath {
    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "reserve_lane": self.reserve_lane,
            "activation_condition": self.activation_condition,
            "route_root": self.route_root,
            "capacity_atomic": self.capacity_atomic,
            "priority": self.priority,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RejectionEvidence {
    pub rejection_id: String,
    pub rejected_root: String,
    pub observed_at_height: u64,
    pub max_accepted_height: u64,
    pub reason: String,
}

impl RejectionEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "rejection_id": self.rejection_id,
            "rejected_root": self.rejected_root,
            "observed_at_height": self.observed_at_height,
            "max_accepted_height": self.max_accepted_height,
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityExhaustionEvidence {
    pub evidence_id: String,
    pub reserve_lane: String,
    pub claimed_exhausted_atomic: u128,
    pub queued_liability_atomic: u128,
    pub headroom_bps: u64,
    pub fail_closed_release_root: String,
}

impl LiquidityExhaustionEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reserve_lane": self.reserve_lane,
            "claimed_exhausted_atomic": self.claimed_exhausted_atomic,
            "queued_liability_atomic": self.queued_liability_atomic,
            "headroom_bps": self.headroom_bps,
            "fail_closed_release_root": self.fail_closed_release_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub target: HandoffTarget,
    pub status: EvidenceStatus,
    pub payload_root: String,
    pub verifier_hint: String,
}

impl HandoffEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "target": self.target.as_str(),
            "status": self.status.as_str(),
            "payload_root": self.payload_root,
            "verifier_hint": self.verifier_hint,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub reserve_account_roots: Vec<ReserveAccountRoot>,
    pub pending_exit_liabilities: Vec<PendingExitLiability>,
    pub release_tranches: Vec<ReleaseTranche>,
    pub emergency_reserve_paths: Vec<EmergencyReservePath>,
    pub stale_reserve_rejections: Vec<RejectionEvidence>,
    pub liquidity_exhaustion_evidence: Vec<LiquidityExhaustionEvidence>,
    pub handoff_evidence: Vec<HandoffEvidence>,
    pub sufficiency_answer: SufficiencyAnswer,
    pub live_proof_execution_note: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let reserve_account_roots = vec![
            reserve_account_root(
                "primary_forced_exit",
                8_400_000_000_000,
                2_100_000_000_000,
                1_772_160,
            ),
            reserve_account_root(
                "challenge_holdback",
                1_200_000_000_000,
                320_000_000_000,
                1_772_160,
            ),
            reserve_account_root(
                "emergency_backstop",
                2_800_000_000_000,
                240_000_000_000,
                1_772_160,
            ),
        ];
        let pending_exit_liabilities = vec![
            pending_liability(
                "forced-exit-devnet-0001",
                1_250_000_000_000,
                150_000_000_000,
                "tranche-a",
            ),
            pending_liability(
                "forced-exit-devnet-0002",
                920_000_000_000,
                110_400_000_000,
                "tranche-a",
            ),
            pending_liability(
                "forced-exit-devnet-0003",
                640_000_000_000,
                76_800_000_000,
                "tranche-b",
            ),
        ];
        let release_tranches = vec![
            release_tranche("tranche-a", "primary_forced_exit", 2_300_000_000_000, 6),
            release_tranche("tranche-b", "emergency_backstop", 900_000_000_000, 8),
        ];
        let emergency_reserve_paths = vec![
            emergency_path(
                "emergency-path-01",
                "emergency_backstop",
                "primary reserve utilization above policy ceiling",
                1_600_000_000_000,
                1,
            ),
            emergency_path(
                "emergency-path-02",
                "challenge_holdback",
                "challenge window release requires protected holdback draw",
                540_000_000_000,
                2,
            ),
        ];
        let stale_reserve_rejections = vec![stale_rejection(
            "stale-reserve-devnet-0001",
            "primary_forced_exit",
            1_772_120,
            1_772_148,
        )];
        let liquidity_exhaustion_evidence = vec![liquidity_evidence(
            "liquidity-exhaustion-devnet-0001",
            "primary_forced_exit",
            0,
            2_810_000_000_000,
            2_180,
        )];

        let reserve_account_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-RESERVE-ACCOUNT",
            reserve_account_roots
                .iter()
                .map(ReserveAccountRoot::public_record)
                .collect(),
        );
        let pending_liability_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-PENDING-LIABILITY",
            pending_exit_liabilities
                .iter()
                .map(PendingExitLiability::public_record)
                .collect(),
        );
        let challenge_holdback_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-CHALLENGE-HOLDBACK",
            pending_exit_liabilities
                .iter()
                .map(|liability| {
                    json!({
                        "exit_id": liability.exit_id,
                        "challenge_holdback_atomic": liability.challenge_holdback_atomic,
                    })
                })
                .collect(),
        );
        let release_tranche_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-RELEASE-TRANCHE",
            release_tranches
                .iter()
                .map(ReleaseTranche::public_record)
                .collect(),
        );
        let emergency_path_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-EMERGENCY-PATH",
            emergency_reserve_paths
                .iter()
                .map(EmergencyReservePath::public_record)
                .collect(),
        );
        let stale_rejection_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-STALE-REJECTION",
            stale_reserve_rejections
                .iter()
                .map(RejectionEvidence::public_record)
                .collect(),
        );
        let liquidity_root = merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-LIQUIDITY-EXHAUSTION",
            liquidity_exhaustion_evidence
                .iter()
                .map(LiquidityExhaustionEvidence::public_record)
                .collect(),
        );
        let fee_cap_root = record_root(
            "fee-cap",
            &json!({
                "max_fee_cap_bps": config.max_fee_cap_bps,
                "observed_tranche_fee_cap_bps": 8_u64,
                "release_path_fee_capped": true,
            }),
        );

        let handoff_evidence = vec![
            handoff_evidence(
                EvidenceKind::ReserveAccountRoot,
                HandoffTarget::HeavyGate,
                reserve_account_root,
                "bind reserve accounts before forced-exit release eligibility",
            ),
            handoff_evidence(
                EvidenceKind::PendingExitLiabilityRoot,
                HandoffTarget::HeavyGate,
                pending_liability_root,
                "sum pending canonical forced-exit liabilities",
            ),
            handoff_evidence(
                EvidenceKind::ChallengeHoldbackRoot,
                HandoffTarget::ChallengeWindow,
                challenge_holdback_root,
                "prove challenge liquidity remains withheld",
            ),
            handoff_evidence(
                EvidenceKind::ReleaseTrancheRoot,
                HandoffTarget::ReleasePath,
                release_tranche_root,
                "cap release by tranche root and fee ceiling",
            ),
            handoff_evidence(
                EvidenceKind::EmergencyReservePathRoot,
                HandoffTarget::EmergencyReservePath,
                emergency_path_root,
                "route forced exits when primary lane is exhausted",
            ),
            handoff_evidence(
                EvidenceKind::FeeCapCommitment,
                HandoffTarget::ReleasePath,
                fee_cap_root,
                "reject releases above canonical fee cap",
            ),
            handoff_evidence(
                EvidenceKind::StaleReserveRejectionRoot,
                HandoffTarget::HeavyGate,
                stale_rejection_root,
                "reject reserve roots outside freshness window",
            ),
            handoff_evidence(
                EvidenceKind::LiquidityExhaustionEvidenceRoot,
                HandoffTarget::ReleasePath,
                liquidity_root,
                "show fail-closed behavior and emergency path availability",
            ),
        ];

        Self {
            config,
            reserve_account_roots,
            pending_exit_liabilities,
            release_tranches,
            emergency_reserve_paths,
            stale_reserve_rejections,
            liquidity_exhaustion_evidence,
            handoff_evidence,
            sufficiency_answer: SufficiencyAnswer::SufficientWithLiveProofExecutionDeferred,
            live_proof_execution_note:
                "deterministic devnet manifest proves handoff completeness; live reserve proof execution remains deferred to the heavy gate runtime"
                    .to_string(),
        }
    }

    pub fn reserve_account_root(&self) -> String {
        merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-RESERVE-ACCOUNT",
            self.reserve_account_roots
                .iter()
                .map(ReserveAccountRoot::public_record)
                .collect(),
        )
    }

    pub fn pending_exit_liability_root(&self) -> String {
        merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-PENDING-LIABILITY",
            self.pending_exit_liabilities
                .iter()
                .map(PendingExitLiability::public_record)
                .collect(),
        )
    }

    pub fn handoff_evidence_root(&self) -> String {
        merkle_root_from_records(
            "RESERVE-PROOF-HANDOFF-EVIDENCE",
            self.handoff_evidence
                .iter()
                .map(HandoffEvidence::public_record)
                .collect(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "config": self.config.public_record(),
            "reserve_account_root": self.reserve_account_root(),
            "pending_exit_liability_root": self.pending_exit_liability_root(),
            "release_tranche_root": merkle_root_from_records(
                "RESERVE-PROOF-HANDOFF-RELEASE-TRANCHE",
                self.release_tranches.iter().map(ReleaseTranche::public_record).collect(),
            ),
            "emergency_reserve_path_root": merkle_root_from_records(
                "RESERVE-PROOF-HANDOFF-EMERGENCY-PATH",
                self.emergency_reserve_paths.iter().map(EmergencyReservePath::public_record).collect(),
            ),
            "stale_reserve_rejection_root": merkle_root_from_records(
                "RESERVE-PROOF-HANDOFF-STALE-REJECTION",
                self.stale_reserve_rejections.iter().map(RejectionEvidence::public_record).collect(),
            ),
            "liquidity_exhaustion_evidence_root": merkle_root_from_records(
                "RESERVE-PROOF-HANDOFF-LIQUIDITY-EXHAUSTION",
                self.liquidity_exhaustion_evidence.iter().map(LiquidityExhaustionEvidence::public_record).collect(),
            ),
            "handoff_evidence_root": self.handoff_evidence_root(),
            "reserve_account_roots": self.reserve_account_roots.iter().map(ReserveAccountRoot::public_record).collect::<Vec<_>>(),
            "pending_exit_liabilities": self.pending_exit_liabilities.iter().map(PendingExitLiability::public_record).collect::<Vec<_>>(),
            "release_tranches": self.release_tranches.iter().map(ReleaseTranche::public_record).collect::<Vec<_>>(),
            "emergency_reserve_paths": self.emergency_reserve_paths.iter().map(EmergencyReservePath::public_record).collect::<Vec<_>>(),
            "stale_reserve_rejections": self.stale_reserve_rejections.iter().map(RejectionEvidence::public_record).collect::<Vec<_>>(),
            "liquidity_exhaustion_evidence": self.liquidity_exhaustion_evidence.iter().map(LiquidityExhaustionEvidence::public_record).collect::<Vec<_>>(),
            "handoff_evidence": self.handoff_evidence.iter().map(HandoffEvidence::public_record).collect::<Vec<_>>(),
            "forced_exit_reserve_proof_handoff_sufficient": self.is_sufficient_for_forced_exits(),
            "sufficiency_answer": self.sufficiency_answer.as_str(),
            "live_proof_execution_deferred": self.config.live_proof_execution_deferred,
            "live_proof_execution_note": self.live_proof_execution_note,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "RESERVE-PROOF-HANDOFF-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn is_sufficient_for_forced_exits(&self) -> bool {
        let total_available = self
            .reserve_account_roots
            .iter()
            .map(|reserve| reserve.available_atomic)
            .sum::<u128>();
        let total_liability = self
            .pending_exit_liabilities
            .iter()
            .map(|liability| liability.liability_atomic + liability.challenge_holdback_atomic)
            .sum::<u128>();
        let max_fee_cap = self
            .release_tranches
            .iter()
            .map(|tranche| tranche.fee_cap_bps)
            .max()
            .unwrap_or(0);

        total_available >= total_liability
            && max_fee_cap <= self.config.max_fee_cap_bps
            && self.emergency_reserve_paths.len() as u64 >= self.config.min_emergency_paths
            && self
                .handoff_evidence
                .iter()
                .all(|evidence| evidence.status == EvidenceStatus::Present)
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

fn reserve_account_root(
    lane: &str,
    available_atomic: u128,
    reserved_atomic: u128,
    observed_at_height: u64,
) -> ReserveAccountRoot {
    let attestation_root = labeled_root("reserve-attestation", lane);
    let spend_authority_root = labeled_root("reserve-spend-authority", lane);
    let account_root = domain_hash(
        "RESERVE-PROOF-HANDOFF-ACCOUNT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane),
            HashPart::Str(&attestation_root),
            HashPart::Str(&spend_authority_root),
            HashPart::Int(available_atomic as i128),
            HashPart::Int(reserved_atomic as i128),
            HashPart::U64(observed_at_height),
        ],
        32,
    );
    ReserveAccountRoot {
        lane: lane.to_string(),
        account_root,
        attestation_root,
        spend_authority_root,
        available_atomic,
        reserved_atomic,
        observed_at_height,
    }
}

fn pending_liability(
    exit_id: &str,
    liability_atomic: u128,
    challenge_holdback_atomic: u128,
    release_tranche_id: &str,
) -> PendingExitLiability {
    let claimant_commitment = labeled_root("claimant", exit_id);
    let evidence_root = domain_hash(
        "RESERVE-PROOF-HANDOFF-PENDING-EXIT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(exit_id),
            HashPart::Str(&claimant_commitment),
            HashPart::Int(liability_atomic as i128),
            HashPart::Int(challenge_holdback_atomic as i128),
            HashPart::Str(release_tranche_id),
        ],
        32,
    );
    PendingExitLiability {
        exit_id: exit_id.to_string(),
        claimant_commitment,
        liability_atomic,
        challenge_holdback_atomic,
        release_tranche_id: release_tranche_id.to_string(),
        evidence_root,
    }
}

fn release_tranche(
    tranche_id: &str,
    reserve_lane: &str,
    max_release_atomic: u128,
    fee_cap_bps: u64,
) -> ReleaseTranche {
    let tranche_root = domain_hash(
        "RESERVE-PROOF-HANDOFF-TRANCHE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tranche_id),
            HashPart::Str(reserve_lane),
            HashPart::Int(max_release_atomic as i128),
            HashPart::U64(fee_cap_bps),
        ],
        32,
    );
    let heavy_gate_release_root = domain_hash(
        "RESERVE-PROOF-HANDOFF-HEAVY-GATE-RELEASE",
        &[HashPart::Str(&tranche_root), HashPart::Str(reserve_lane)],
        32,
    );
    ReleaseTranche {
        tranche_id: tranche_id.to_string(),
        reserve_lane: reserve_lane.to_string(),
        max_release_atomic,
        fee_cap_bps,
        tranche_root,
        heavy_gate_release_root,
    }
}

fn emergency_path(
    path_id: &str,
    reserve_lane: &str,
    activation_condition: &str,
    capacity_atomic: u128,
    priority: u64,
) -> EmergencyReservePath {
    let route_root = domain_hash(
        "RESERVE-PROOF-HANDOFF-EMERGENCY-ROUTE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(path_id),
            HashPart::Str(reserve_lane),
            HashPart::Str(activation_condition),
            HashPart::Int(capacity_atomic as i128),
            HashPart::U64(priority),
        ],
        32,
    );
    EmergencyReservePath {
        path_id: path_id.to_string(),
        reserve_lane: reserve_lane.to_string(),
        activation_condition: activation_condition.to_string(),
        route_root,
        capacity_atomic,
        priority,
    }
}

fn stale_rejection(
    rejection_id: &str,
    reserve_lane: &str,
    observed_at_height: u64,
    max_accepted_height: u64,
) -> RejectionEvidence {
    let rejected_root = labeled_root("stale-reserve", reserve_lane);
    RejectionEvidence {
        rejection_id: rejection_id.to_string(),
        rejected_root,
        observed_at_height,
        max_accepted_height,
        reason: "reserve root older than canonical freshness window".to_string(),
    }
}

fn liquidity_evidence(
    evidence_id: &str,
    reserve_lane: &str,
    claimed_exhausted_atomic: u128,
    queued_liability_atomic: u128,
    headroom_bps: u64,
) -> LiquidityExhaustionEvidence {
    let fail_closed_release_root = domain_hash(
        "RESERVE-PROOF-HANDOFF-FAIL-CLOSED-LIQUIDITY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_id),
            HashPart::Str(reserve_lane),
            HashPart::Int(claimed_exhausted_atomic as i128),
            HashPart::Int(queued_liability_atomic as i128),
            HashPart::U64(headroom_bps),
        ],
        32,
    );
    LiquidityExhaustionEvidence {
        evidence_id: evidence_id.to_string(),
        reserve_lane: reserve_lane.to_string(),
        claimed_exhausted_atomic,
        queued_liability_atomic,
        headroom_bps,
        fail_closed_release_root,
    }
}

fn handoff_evidence(
    kind: EvidenceKind,
    target: HandoffTarget,
    payload_root: String,
    verifier_hint: &str,
) -> HandoffEvidence {
    let evidence_id = domain_hash(
        "RESERVE-PROOF-HANDOFF-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(target.as_str()),
            HashPart::Str(&payload_root),
        ],
        32,
    );
    HandoffEvidence {
        evidence_id,
        kind,
        target,
        status: EvidenceStatus::Present,
        payload_root,
        verifier_hint: verifier_hint.to_string(),
    }
}

fn labeled_root(label: &str, value: &str) -> String {
    domain_hash(
        "RESERVE-PROOF-HANDOFF-LABELED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "RESERVE-PROOF-HANDOFF-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn merkle_root_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}
