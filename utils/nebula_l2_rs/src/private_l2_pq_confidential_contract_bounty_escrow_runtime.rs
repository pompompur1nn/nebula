use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractBountyEscrowRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractBountyEscrowRuntimeResult<T>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-bounty-escrow-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEVNET_HEIGHT: u64 = 1_318_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bounty-escrow-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+Poseidon2-transcript+AEAD-confidential-bounty-spec-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_MONERO_PRIVACY_SUITE: &str =
    "Monero-RingCT-viewtag-nullifier-fence-bounty-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_RECURSIVE_PROOF_SUITE: &str =
    "Nova+FRI-recursive-bounty-milestone-proof-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: u64 =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_ESCROW_FEE_BPS:
    u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    5;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MIN_CHALLENGE_BOND_BPS: u64 = 50;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_CHALLENGE_BOND_BPS: u64 = 2_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_BOUNTY_TTL_BLOCKS: u64 =
    86_400;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 1_440;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MILESTONE_TTL_BLOCKS:
    u64 = 7_200;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_APPROVAL_TTL_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 2_880;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_RELEASE_DELAY_BLOCKS:
    u64 = 64;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize =
    4_096;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_BOUNTIES: usize =
    8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_COMMITMENTS: usize =
    67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_APPROVALS: usize =
    33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_MILESTONES: usize =
    67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_RELEASES: usize =
    67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_DISPUTES: usize =
    16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_BONDS: usize =
    33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_PROOF_RECEIPTS:
    usize = 67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_REBATES: usize =
    33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES:
    usize = 134_217_728;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_SLASHING_RECORDS:
    usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_NULLIFIERS: usize =
    268_435_456;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_EVENTS: usize =
    134_217_728;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BountyAssetKind {
    ConfidentialToken,
    GovernanceToken,
    StablePrivateToken,
    LpShare,
    VaultShare,
    FeeCredit,
    BridgeReceipt,
    CustomToken,
}
impl BountyAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialToken => "confidential_token",
            Self::GovernanceToken => "governance_token",
            Self::StablePrivateToken => "stable_private_token",
            Self::LpShare => "lp_share",
            Self::VaultShare => "vault_share",
            Self::FeeCredit => "fee_credit",
            Self::BridgeReceipt => "bridge_receipt",
            Self::CustomToken => "custom_token",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BountyVisibility {
    Sealed,
    SponsorRevealed,
    SolverRevealed,
    CommitteeRevealed,
    PublicSummary,
}
impl BountyVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::SponsorRevealed => "sponsor_revealed",
            Self::SolverRevealed => "solver_revealed",
            Self::CommitteeRevealed => "committee_revealed",
            Self::PublicSummary => "public_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BountyStatus {
    Draft,
    Funded,
    Open,
    Solving,
    Review,
    PartiallyReleased,
    Settled,
    Disputed,
    Cancelled,
    Expired,
    Slashed,
}
impl BountyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Funded => "funded",
            Self::Open => "open",
            Self::Solving => "solving",
            Self::Review => "review",
            Self::PartiallyReleased => "partially_released",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Funded | Self::Open | Self::Solving)
    }
    pub fn accepts_review(self) -> bool {
        matches!(self, Self::Solving | Self::Review | Self::PartiallyReleased)
    }
    pub fn anchors_state(self) -> bool {
        !matches!(self, Self::Draft)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    PrivateCommitted,
    SponsorApproved,
    MilestoneProving,
    Selected,
    Rejected,
    Withdrawn,
    Expired,
    Slashed,
}
impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCommitted => "private_committed",
            Self::SponsorApproved => "sponsor_approved",
            Self::MilestoneProving => "milestone_proving",
            Self::Selected => "selected",
            Self::Rejected => "rejected",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::PrivateCommitted
                | Self::SponsorApproved
                | Self::MilestoneProving
                | Self::Selected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Requested,
    Granted,
    Denied,
    Expired,
    Revoked,
    Quarantined,
}
impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MilestoneStatus {
    Encrypted,
    Committed,
    Proving,
    Accepted,
    Released,
    Disputed,
    Rejected,
    Expired,
    Slashed,
}
impl MilestoneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Committed => "committed",
            Self::Proving => "proving",
            Self::Accepted => "accepted",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn can_release(self) -> bool {
        matches!(self, Self::Accepted | Self::Released)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Queued,
    Timelocked,
    Settled,
    Rebated,
    Disputed,
    Cancelled,
    Slashed,
}
impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Timelocked => "timelocked",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
    pub fn is_open(self) -> bool {
        matches!(self, Self::Queued | Self::Timelocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Opened,
    EvidenceSubmitted,
    Challenged,
    Voting,
    ResolvedSponsor,
    ResolvedSolver,
    ResolvedSplit,
    Expired,
    Slashed,
}
impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Challenged => "challenged",
            Self::Voting => "voting",
            Self::ResolvedSponsor => "resolved_sponsor",
            Self::ResolvedSolver => "resolved_solver",
            Self::ResolvedSplit => "resolved_split",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Opened | Self::EvidenceSubmitted | Self::Challenged | Self::Voting
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Locked,
    Released,
    PartiallySlashed,
    Slashed,
    Expired,
}
impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Released => "released",
            Self::PartiallySlashed => "partially_slashed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofReceiptKind {
    BountySpec,
    SolverCommitment,
    SponsorApproval,
    MilestoneProof,
    ReleaseProof,
    DisputeProof,
    RecursiveAggregate,
    PrivacyFence,
    SlashingEvidence,
}
impl ProofReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BountySpec => "bounty_spec",
            Self::SolverCommitment => "solver_commitment",
            Self::SponsorApproval => "sponsor_approval",
            Self::MilestoneProof => "milestone_proof",
            Self::ReleaseProof => "release_proof",
            Self::DisputeProof => "dispute_proof",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::PrivacyFence => "privacy_fence",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWitnesses,
    Invalid,
    Revoked,
}
impl ProofVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ValidWithWarning => "valid_with_warning",
            Self::NeedsMoreWitnesses => "needs_more_witnesses",
            Self::Invalid => "invalid",
            Self::Revoked => "revoked",
        }
    }
    pub fn accepts_state(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Claimed,
    Expired,
    ClawedBack,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    NullifierSet,
    SolverAnonymitySet,
    SponsorApprovalSet,
    MilestoneWitnessSet,
    DisputeEvidenceSet,
    ReleaseBatchSet,
    CrossContractLinkageSet,
}
impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierSet => "nullifier_set",
            Self::SolverAnonymitySet => "solver_anonymity_set",
            Self::SponsorApprovalSet => "sponsor_approval_set",
            Self::MilestoneWitnessSet => "milestone_witness_set",
            Self::DisputeEvidenceSet => "dispute_evidence_set",
            Self::ReleaseBatchSet => "release_batch_set",
            Self::CrossContractLinkageSet => "cross_contract_linkage_set",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    ReplayNullifier,
    InvalidProof,
    PrematureRelease,
    BondUnderfunded,
    PrivacyFenceBreach,
    SponsorDoubleApproval,
    SolverEquivocation,
    ChallengeFraud,
    RecursiveReceiptMismatch,
}
impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayNullifier => "replay_nullifier",
            Self::InvalidProof => "invalid_proof",
            Self::PrematureRelease => "premature_release",
            Self::BondUnderfunded => "bond_underfunded",
            Self::PrivacyFenceBreach => "privacy_fence_breach",
            Self::SponsorDoubleApproval => "sponsor_double_approval",
            Self::SolverEquivocation => "solver_equivocation",
            Self::ChallengeFraud => "challenge_fraud",
            Self::RecursiveReceiptMismatch => "recursive_receipt_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    BountyOpened,
    SolverCommitted,
    SponsorApproved,
    MilestoneAccepted,
    ReleaseQueued,
    ReleaseSettled,
    DisputeOpened,
    BondSlashed,
    RebateCredited,
    PrivacyFenceAnchored,
}
impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BountyOpened => "bounty_opened",
            Self::SolverCommitted => "solver_committed",
            Self::SponsorApproved => "sponsor_approved",
            Self::MilestoneAccepted => "milestone_accepted",
            Self::ReleaseQueued => "release_queued",
            Self::ReleaseSettled => "release_settled",
            Self::DisputeOpened => "dispute_opened",
            Self::BondSlashed => "bond_slashed",
            Self::RebateCredited => "rebate_credited",
            Self::PrivacyFenceAnchored => "privacy_fence_anchored",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub encryption_suite: String,
    pub monero_privacy_suite: String,
    pub recursive_proof_suite: String,
    pub min_privacy_set: u64,
    pub batch_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_escrow_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_challenge_bond_bps: u64,
    pub max_challenge_bond_bps: u64,
    pub bounty_ttl_blocks: u64,
    pub commitment_ttl_blocks: u64,
    pub milestone_ttl_blocks: u64,
    pub approval_ttl_blocks: u64,
    pub dispute_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub max_batch_items: usize,
    pub max_bounties: usize,
    pub max_commitments: usize,
    pub max_approvals: usize,
    pub max_milestones: usize,
    pub max_releases: usize,
    pub max_disputes: usize,
    pub max_bonds: usize,
    pub max_proof_receipts: usize,
    pub max_rebates: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_records: usize,
    pub max_nullifiers: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_PQ_SUITE.to_string(),
            encryption_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_ENCRYPTION_SUITE.to_string(),
            monero_privacy_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_MONERO_PRIVACY_SUITE.to_string(),
            recursive_proof_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_RECURSIVE_PROOF_SUITE.to_string(),
            min_privacy_set: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_escrow_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_ESCROW_FEE_BPS,
            target_rebate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            min_challenge_bond_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MIN_CHALLENGE_BOND_BPS,
            max_challenge_bond_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_CHALLENGE_BOND_BPS,
            bounty_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_BOUNTY_TTL_BLOCKS,
            commitment_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_COMMITMENT_TTL_BLOCKS,
            milestone_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MILESTONE_TTL_BLOCKS,
            approval_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_APPROVAL_TTL_BLOCKS,
            dispute_window_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            release_delay_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_RELEASE_DELAY_BLOCKS,
            max_batch_items: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_bounties: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_BOUNTIES,
            max_commitments: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_COMMITMENTS,
            max_approvals: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_APPROVALS,
            max_milestones: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_MILESTONES,
            max_releases: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_RELEASES,
            max_disputes: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_DISPUTES,
            max_bonds: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_BONDS,
            max_proof_receipts: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_PROOF_RECEIPTS,
            max_rebates: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_REBATES,
            max_privacy_fences: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_records: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_SLASHING_RECORDS,
            max_nullifiers: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_events: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_DEFAULT_MAX_EVENTS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bounties: u64,
    pub active_bounties: u64,
    pub solver_commitments: u64,
    pub open_commitments: u64,
    pub sponsor_approvals: u64,
    pub milestone_proofs: u64,
    pub accepted_milestones: u64,
    pub token_releases: u64,
    pub open_releases: u64,
    pub disputes: u64,
    pub open_disputes: u64,
    pub challenge_bonds: u64,
    pub proof_receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub slashing_records: u64,
    pub spent_nullifiers: u64,
    pub events: u64,
    pub total_escrowed_piconero: u128,
    pub total_released_piconero: u128,
    pub total_bonded_piconero: u128,
    pub total_slashed_piconero: u128,
    pub total_rebated_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bounty_root: String,
    pub active_bounty_root: String,
    pub commitment_root: String,
    pub open_commitment_root: String,
    pub approval_root: String,
    pub milestone_root: String,
    pub accepted_milestone_root: String,
    pub release_root: String,
    pub open_release_root: String,
    pub dispute_root: String,
    pub open_dispute_root: String,
    pub bond_root: String,
    pub proof_receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub slashing_record_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        let empty = json!({"empty": true});
        Self {
            config_root: root_from_record("PRIVATE-L2-PQ-BOUNTY-CONFIG", &config.public_record()),
            bounty_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-BOUNTY", &[]),
            active_bounty_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-ACTIVE-BOUNTY", &[]),
            commitment_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-COMMITMENT", &[]),
            open_commitment_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-OPEN-COMMITMENT", &[]),
            approval_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-APPROVAL", &[]),
            milestone_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-MILESTONE", &[]),
            accepted_milestone_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-ACCEPTED-MILESTONE", &[]),
            release_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-RELEASE", &[]),
            open_release_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-OPEN-RELEASE", &[]),
            dispute_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-DISPUTE", &[]),
            open_dispute_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-OPEN-DISPUTE", &[]),
            bond_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-BOND", &[]),
            proof_receipt_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-PROOF-RECEIPT", &[]),
            rebate_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-REBATE", &[]),
            privacy_fence_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-PRIVACY-FENCE", &[]),
            slashing_record_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-SLASHING-RECORD", &[]),
            nullifier_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-NULLIFIER", &[]),
            event_root: merkle_root("PRIVATE-L2-PQ-BOUNTY-EVENT", &[]),
            counters_root: root_from_record(
                "PRIVATE-L2-PQ-BOUNTY-COUNTERS",
                &Counters::default().public_record(),
            ),
            public_record_root: root_from_record("PRIVATE-L2-PQ-BOUNTY-PUBLIC-RECORD", &empty),
            state_root: root_from_record("PRIVATE-L2-PQ-BOUNTY-STATE", &empty),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBountySpec {
    pub bounty_id: String,
    pub asset_kind: BountyAssetKind,
    pub visibility: BountyVisibility,
    pub status: BountyStatus,
    pub sponsor_commitment: String,
    pub contract_commitment: String,
    pub asset_commitment: String,
    pub encrypted_spec_root: String,
    pub encrypted_acceptance_root: String,
    pub milestone_schema_root: String,
    pub solver_policy_root: String,
    pub release_policy_root: String,
    pub dispute_policy_root: String,
    pub total_amount_commitment: String,
    pub remaining_amount_commitment: String,
    pub sponsor_pq_key_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub max_solver_commitments: u64,
    pub max_milestones: u64,
    pub escrow_fee_bps: u64,
    pub sequence: u64,
}

impl EncryptedBountySpec {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSolverCommitment {
    pub commitment_id: String,
    pub bounty_id: String,
    pub status: SolverCommitmentStatus,
    pub solver_commitment: String,
    pub solver_nullifier: String,
    pub encrypted_solution_plan_root: String,
    pub work_sample_commitment: String,
    pub capability_proof_root: String,
    pub bond_commitment: String,
    pub pq_auth_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub selected_at_height: u64,
    pub sequence: u64,
}

impl PrivateSolverCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorApproval {
    pub approval_id: String,
    pub bounty_id: String,
    pub commitment_id: String,
    pub status: ApprovalStatus,
    pub sponsor_commitment: String,
    pub approval_policy_root: String,
    pub pq_signature_root: String,
    pub approval_nullifier: String,
    pub limits_commitment: String,
    pub approved_milestone_count: u64,
    pub approved_release_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub requested_at_height: u64,
    pub approved_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSponsorApproval {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialMilestoneProof {
    pub milestone_id: String,
    pub bounty_id: String,
    pub commitment_id: String,
    pub status: MilestoneStatus,
    pub milestone_commitment: String,
    pub encrypted_evidence_root: String,
    pub recursive_proof_root: String,
    pub witness_set_root: String,
    pub review_committee_root: String,
    pub release_amount_commitment: String,
    pub milestone_nullifier: String,
    pub milestone_index: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialMilestoneProof {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenEscrowRelease {
    pub release_id: String,
    pub bounty_id: String,
    pub commitment_id: String,
    pub milestone_id: String,
    pub status: ReleaseStatus,
    pub recipient_commitment: String,
    pub token_commitment: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub release_proof_root: String,
    pub settlement_tx_root: String,
    pub amount_piconero: u128,
    pub fee_piconero: u128,
    pub queued_at_height: u64,
    pub unlock_height: u64,
    pub settled_at_height: u64,
}

impl TokenEscrowRelease {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub release_id: String,
    pub status: RebateStatus,
    pub sponsor_commitment: String,
    pub solver_commitment: String,
    pub fee_receipt_root: String,
    pub rebate_note_commitment: String,
    pub charged_fee_piconero: u128,
    pub rebate_piconero: u128,
    pub rebate_bps: u64,
    pub queued_at_height: u64,
    pub claimed_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeChallengeBond {
    pub bond_id: String,
    pub dispute_id: String,
    pub bounty_id: String,
    pub status: BondStatus,
    pub bonder_commitment: String,
    pub bond_note_commitment: String,
    pub bond_policy_root: String,
    pub bond_amount_piconero: u128,
    pub slashed_amount_piconero: u128,
    pub bond_bps: u64,
    pub locked_at_height: u64,
    pub unlock_height: u64,
}

impl DisputeChallengeBond {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BountyDispute {
    pub dispute_id: String,
    pub bounty_id: String,
    pub commitment_id: String,
    pub milestone_id: String,
    pub status: DisputeStatus,
    pub claimant_commitment: String,
    pub encrypted_claim_root: String,
    pub evidence_root: String,
    pub challenge_set_root: String,
    pub resolution_root: String,
    pub opened_at_height: u64,
    pub evidence_deadline_height: u64,
    pub resolved_at_height: u64,
}

impl BountyDispute {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofReceipt {
    pub receipt_id: String,
    pub kind: ProofReceiptKind,
    pub verdict: ProofVerdict,
    pub subject_id: String,
    pub bounty_id: String,
    pub proof_root: String,
    pub recursive_parent_root: String,
    pub aggregated_state_root: String,
    pub verifier_committee_root: String,
    pub verified_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl RecursiveProofReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: PrivacyFenceKind,
    pub subject_id: String,
    pub bounty_id: String,
    pub fence_root: String,
    pub nullifier_root: String,
    pub anonymity_set_root: String,
    pub privacy_set_size: u64,
    pub anchored_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub slashing_id: String,
    pub reason: SlashingReason,
    pub subject_id: String,
    pub bounty_id: String,
    pub evidence_root: String,
    pub slash_authority_root: String,
    pub related_bond_id: String,
    pub slash_amount_piconero: u128,
    pub detected_at_height: u64,
    pub finalized: bool,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub bounty_id: Option<String>,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub bounties: BTreeMap<String, EncryptedBountySpec>,
    pub commitments: BTreeMap<String, PrivateSolverCommitment>,
    pub approvals: BTreeMap<String, PqSponsorApproval>,
    pub milestones: BTreeMap<String, ConfidentialMilestoneProof>,
    pub releases: BTreeMap<String, TokenEscrowRelease>,
    pub disputes: BTreeMap<String, BountyDispute>,
    pub bonds: BTreeMap<String, DisputeChallengeBond>,
    pub proof_receipts: BTreeMap<String, RecursiveProofReceipt>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_records: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let roots = Roots::empty(&config);
        Self {
            config,
            counters: Counters::default(),
            roots,
            bounties: BTreeMap::new(),
            commitments: BTreeMap::new(),
            approvals: BTreeMap::new(),
            milestones: BTreeMap::new(),
            releases: BTreeMap::new(),
            disputes: BTreeMap::new(),
            bonds: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let h = state.config.devnet_height;
        let sponsor = payload_root(
            "bounty:sponsor",
            &json!({"sponsor":"devnet-foundation","lane":"pq-confidential-defi"}),
        );
        let contract = payload_root(
            "bounty:contract",
            &json!({"vm":"private-l2","contract":"bounty-escrow"}),
        );
        let asset = payload_root(
            "bounty:asset",
            &json!({"symbol":"pXMR","kind":"confidential_token"}),
        );
        let bounty_id = bounty_id(BountyAssetKind::ConfidentialToken, &sponsor, &asset, 0);
        let commitment_id = solver_commitment_id(&bounty_id, "solver-alpha", h);
        let milestone_id = milestone_id(&bounty_id, &commitment_id, 0);
        let release_id = release_id(&bounty_id, &milestone_id, 0);
        let dispute_id = dispute_id(&bounty_id, &milestone_id, 0);
        let bond_id = bond_id(&dispute_id, "challenger-alpha", 0);
        state
            .register_bounty(EncryptedBountySpec {
                bounty_id: bounty_id.clone(),
                asset_kind: BountyAssetKind::ConfidentialToken,
                visibility: BountyVisibility::Sealed,
                status: BountyStatus::Open,
                sponsor_commitment: sponsor.clone(),
                contract_commitment: contract,
                asset_commitment: asset,
                encrypted_spec_root: payload_root(
                    "bounty:encrypted-spec",
                    &json!({"ciphertext":"devnet-bounty-spec","suite":"ml-kem-1024"}),
                ),
                encrypted_acceptance_root: payload_root(
                    "bounty:acceptance",
                    &json!({"tests":"hidden","review":"committee"}),
                ),
                milestone_schema_root: root_from_values(
                    "bounty:milestone-schema",
                    &["design", "implementation", "audit"],
                ),
                solver_policy_root: root_from_values(
                    "bounty:solver-policy",
                    &["private-commit", "pq-auth", "bonded"],
                ),
                release_policy_root: root_from_values(
                    "bounty:release-policy",
                    &["accepted-proof", "timelock", "rebate"],
                ),
                dispute_policy_root: root_from_values(
                    "bounty:dispute-policy",
                    &["challenge-bond", "recursive-proof", "slash"],
                ),
                total_amount_commitment: commitment("amount", "total-devnet-bounty"),
                remaining_amount_commitment: commitment("amount", "remaining-devnet-bounty"),
                sponsor_pq_key_commitment: commitment("pq-key", "sponsor-devnet"),
                privacy_set_size: state.config.batch_privacy_set,
                pq_security_bits: state.config.min_pq_security_bits,
                created_at_height: h,
                opened_at_height: h,
                expires_at_height: h + state.config.bounty_ttl_blocks,
                max_solver_commitments: 4096,
                max_milestones: 8,
                escrow_fee_bps: state.config.max_escrow_fee_bps,
                sequence: 0,
            })
            .expect("devnet bounty");
        state
            .submit_solver_commitment(PrivateSolverCommitment {
                commitment_id: commitment_id.clone(),
                bounty_id: bounty_id.clone(),
                status: SolverCommitmentStatus::PrivateCommitted,
                solver_commitment: commitment("solver", "alpha"),
                solver_nullifier: nullifier("solver-alpha", 0),
                encrypted_solution_plan_root: payload_root(
                    "bounty:solution-plan",
                    &json!({"ciphertext":"sealed-plan-alpha"}),
                ),
                work_sample_commitment: commitment("work", "alpha-sample"),
                capability_proof_root: payload_root(
                    "bounty:capability",
                    &json!({"pq":"valid","zk":"valid"}),
                ),
                bond_commitment: commitment("bond", "alpha-bond"),
                pq_auth_root: payload_root("bounty:pq-auth", &json!({"ml-dsa":"sig-alpha"})),
                privacy_set_size: state.config.min_privacy_set,
                pq_security_bits: state.config.min_pq_security_bits,
                submitted_at_height: h + 1,
                expires_at_height: h + state.config.commitment_ttl_blocks,
                selected_at_height: 0,
                sequence: 0,
            })
            .expect("devnet commitment");
        state
            .record_sponsor_approval(PqSponsorApproval {
                approval_id: approval_id(&bounty_id, &commitment_id, 0),
                bounty_id: bounty_id.clone(),
                commitment_id: commitment_id.clone(),
                status: ApprovalStatus::Granted,
                sponsor_commitment: sponsor,
                approval_policy_root: root_from_values(
                    "bounty:approval-policy",
                    &["milestone-0", "release-2500bps"],
                ),
                pq_signature_root: payload_root(
                    "bounty:approval-sig",
                    &json!({"ml-dsa":"approval-alpha"}),
                ),
                approval_nullifier: nullifier("approval-alpha", 0),
                limits_commitment: commitment("limits", "alpha-release-limits"),
                approved_milestone_count: 1,
                approved_release_bps: 2_500,
                privacy_set_size: state.config.min_privacy_set,
                pq_security_bits: state.config.min_pq_security_bits,
                requested_at_height: h + 2,
                approved_at_height: h + 3,
                expires_at_height: h + state.config.approval_ttl_blocks,
            })
            .expect("devnet approval");
        state
            .submit_milestone_proof(ConfidentialMilestoneProof {
                milestone_id: milestone_id.clone(),
                bounty_id: bounty_id.clone(),
                commitment_id: commitment_id.clone(),
                status: MilestoneStatus::Accepted,
                milestone_commitment: commitment("milestone", "alpha-0"),
                encrypted_evidence_root: payload_root(
                    "bounty:evidence",
                    &json!({"ciphertext":"sealed-evidence-alpha"}),
                ),
                recursive_proof_root: payload_root(
                    "bounty:recursive-proof",
                    &json!({"folds":8,"verdict":"valid"}),
                ),
                witness_set_root: root_from_values(
                    "bounty:witnesses",
                    &["witness-a", "witness-b", "witness-c"],
                ),
                review_committee_root: root_from_values(
                    "bounty:reviewers",
                    &["reviewer-a", "reviewer-b"],
                ),
                release_amount_commitment: commitment("release", "alpha-0-amount"),
                milestone_nullifier: nullifier("milestone-alpha", 0),
                milestone_index: 0,
                privacy_set_size: state.config.min_privacy_set,
                pq_security_bits: state.config.min_pq_security_bits,
                submitted_at_height: h + 10,
                accepted_at_height: h + 12,
                expires_at_height: h + state.config.milestone_ttl_blocks,
            })
            .expect("devnet milestone");
        state
            .queue_release(TokenEscrowRelease {
                release_id: release_id.clone(),
                bounty_id: bounty_id.clone(),
                commitment_id: commitment_id.clone(),
                milestone_id: milestone_id.clone(),
                status: ReleaseStatus::Queued,
                recipient_commitment: commitment("recipient", "solver-alpha"),
                token_commitment: commitment("token", "pxmr-note"),
                amount_commitment: commitment("amount", "release-alpha-0"),
                fee_commitment: commitment("fee", "release-alpha-0"),
                release_proof_root: payload_root(
                    "bounty:release-proof",
                    &json!({"milestone":"accepted"}),
                ),
                settlement_tx_root: String::new(),
                amount_piconero: 25_000_000_000,
                fee_piconero: 25_000,
                queued_at_height: h + 13,
                unlock_height: h + 13 + state.config.release_delay_blocks,
                settled_at_height: 0,
            })
            .expect("devnet release");
        state
            .open_dispute(BountyDispute {
                dispute_id: dispute_id.clone(),
                bounty_id: bounty_id.clone(),
                commitment_id: commitment_id.clone(),
                milestone_id: milestone_id.clone(),
                status: DisputeStatus::Opened,
                claimant_commitment: commitment("claimant", "reviewer-alpha"),
                encrypted_claim_root: payload_root(
                    "bounty:dispute-claim",
                    &json!({"ciphertext":"sealed-claim"}),
                ),
                evidence_root: payload_root("bounty:dispute-evidence", &json!({"root":"pending"})),
                challenge_set_root: root_from_values("bounty:challenge-set", &["challenge-alpha"]),
                resolution_root: String::new(),
                opened_at_height: h + 14,
                evidence_deadline_height: h + 14 + state.config.dispute_window_blocks,
                resolved_at_height: 0,
            })
            .expect("devnet dispute");
        state
            .lock_challenge_bond(DisputeChallengeBond {
                bond_id,
                dispute_id,
                bounty_id: bounty_id.clone(),
                status: BondStatus::Locked,
                bonder_commitment: commitment("bonder", "challenger-alpha"),
                bond_note_commitment: commitment("bond-note", "challenge-alpha"),
                bond_policy_root: root_from_values(
                    "bounty:bond-policy",
                    &["slash-invalid", "release-valid"],
                ),
                bond_amount_piconero: 1_000_000_000,
                slashed_amount_piconero: 0,
                bond_bps: state.config.min_challenge_bond_bps,
                locked_at_height: h + 15,
                unlock_height: h + 15 + state.config.dispute_window_blocks,
            })
            .expect("devnet bond");
        state
            .anchor_privacy_fence(PrivacyFence {
                fence_id: privacy_fence_id(&bounty_id, PrivacyFenceKind::SolverAnonymitySet, 0),
                kind: PrivacyFenceKind::SolverAnonymitySet,
                subject_id: commitment_id.clone(),
                bounty_id: bounty_id.clone(),
                fence_root: root_from_values(
                    "bounty:solver-fence",
                    &["solver-alpha", "solver-beta", "solver-gamma"],
                ),
                nullifier_root: root_from_values("bounty:nullifier-fence", &["n0", "n1", "n2"]),
                anonymity_set_root: root_from_values("bounty:anon-set", &["a", "b", "c", "d"]),
                privacy_set_size: state.config.batch_privacy_set,
                anchored_at_height: h + 16,
                expires_at_height: h + state.config.bounty_ttl_blocks,
            })
            .expect("devnet fence");
        state
            .record_proof_receipt(RecursiveProofReceipt {
                receipt_id: proof_receipt_id(&bounty_id, ProofReceiptKind::RecursiveAggregate, 0),
                kind: ProofReceiptKind::RecursiveAggregate,
                verdict: ProofVerdict::Valid,
                subject_id: milestone_id,
                bounty_id,
                proof_root: payload_root("bounty:receipt-proof", &json!({"aggregate":"valid"})),
                recursive_parent_root: String::new(),
                aggregated_state_root: state.state_root(),
                verifier_committee_root: root_from_values(
                    "bounty:verifiers",
                    &["verifier-a", "verifier-b"],
                ),
                verified_at_height: h + 17,
                privacy_set_size: state.config.min_privacy_set,
                pq_security_bits: state.config.min_pq_security_bits,
            })
            .expect("devnet receipt");
        state
    }
    pub fn validate_config(&self) -> Result<()> {
        ensure(self.config.chain_id == CHAIN_ID, "chain id mismatch")?;
        ensure(
            self.config.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.config.min_pq_security_bits >= 256,
            "pq security below 256 bits",
        )?;
        ensure(
            self.config.min_privacy_set > 0,
            "privacy set must be non-zero",
        )?;
        ensure(
            self.config.max_escrow_fee_bps
                <= PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_MAX_BPS,
            "fee bps too high",
        )?;
        ensure(
            self.config.target_rebate_bps <= self.config.max_escrow_fee_bps,
            "rebate exceeds fee",
        )?;
        ensure(
            self.config.min_challenge_bond_bps <= self.config.max_challenge_bond_bps,
            "bond bounds inverted",
        )?;
        Ok(())
    }
    pub fn register_bounty(&mut self, item: EncryptedBountySpec) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.bounties.len() < self.config.max_bounties,
            "too many bounties",
        )?;
        self.validate_bounty(&item)?;
        ensure(
            !self.bounties.contains_key(&item.bounty_id),
            "duplicate bounties id",
        )?;
        self.bounties.insert(item.bounty_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn submit_solver_commitment(&mut self, item: PrivateSolverCommitment) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.commitments.len() < self.config.max_commitments,
            "too many solver commitments",
        )?;
        self.validate_commitment(&item)?;
        ensure(
            !self.commitments.contains_key(&item.commitment_id),
            "duplicate solver commitments id",
        )?;
        self.commitments.insert(item.commitment_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn record_sponsor_approval(&mut self, item: PqSponsorApproval) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.approvals.len() < self.config.max_approvals,
            "too many approvals",
        )?;
        self.validate_approval(&item)?;
        ensure(
            !self.approvals.contains_key(&item.approval_id),
            "duplicate approvals id",
        )?;
        self.approvals.insert(item.approval_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn submit_milestone_proof(&mut self, item: ConfidentialMilestoneProof) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.milestones.len() < self.config.max_milestones,
            "too many milestones",
        )?;
        self.validate_milestone(&item)?;
        ensure(
            !self.milestones.contains_key(&item.milestone_id),
            "duplicate milestones id",
        )?;
        self.milestones.insert(item.milestone_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn queue_release(&mut self, item: TokenEscrowRelease) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.releases.len() < self.config.max_releases,
            "too many releases",
        )?;
        self.validate_release(&item)?;
        ensure(
            !self.releases.contains_key(&item.release_id),
            "duplicate releases id",
        )?;
        self.releases.insert(item.release_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn open_dispute(&mut self, item: BountyDispute) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.disputes.len() < self.config.max_disputes,
            "too many disputes",
        )?;
        self.validate_dispute(&item)?;
        ensure(
            !self.disputes.contains_key(&item.dispute_id),
            "duplicate disputes id",
        )?;
        self.disputes.insert(item.dispute_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn lock_challenge_bond(&mut self, item: DisputeChallengeBond) -> Result<()> {
        self.validate_config()?;
        ensure(self.bonds.len() < self.config.max_bonds, "too many bonds")?;
        self.validate_bond(&item)?;
        ensure(
            !self.bonds.contains_key(&item.bond_id),
            "duplicate bonds id",
        )?;
        self.bonds.insert(item.bond_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn record_proof_receipt(&mut self, item: RecursiveProofReceipt) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.proof_receipts.len() < self.config.max_proof_receipts,
            "too many proof receipts",
        )?;
        self.validate_receipt(&item)?;
        ensure(
            !self.proof_receipts.contains_key(&item.receipt_id),
            "duplicate proof receipts id",
        )?;
        self.proof_receipts.insert(item.receipt_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn credit_rebate(&mut self, item: LowFeeRebate) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.rebates.len() < self.config.max_rebates,
            "too many rebates",
        )?;
        self.validate_rebate(&item)?;
        ensure(
            !self.rebates.contains_key(&item.rebate_id),
            "duplicate rebates id",
        )?;
        self.rebates.insert(item.rebate_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn anchor_privacy_fence(&mut self, item: PrivacyFence) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.privacy_fences.len() < self.config.max_privacy_fences,
            "too many privacy fences",
        )?;
        self.validate_fence(&item)?;
        ensure(
            !self.privacy_fences.contains_key(&item.fence_id),
            "duplicate privacy fences id",
        )?;
        self.privacy_fences.insert(item.fence_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn record_slashing_evidence(&mut self, item: SlashingEvidence) -> Result<()> {
        self.validate_config()?;
        ensure(
            self.slashing_records.len() < self.config.max_slashing_records,
            "too many slashing records",
        )?;
        self.validate_slashing(&item)?;
        ensure(
            !self.slashing_records.contains_key(&item.slashing_id),
            "duplicate slashing records id",
        )?;
        self.slashing_records.insert(item.slashing_id.clone(), item);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn settle_release(
        &mut self,
        release_id: &str,
        settlement_tx_root: String,
        height: u64,
    ) -> Result<()> {
        let release = self
            .releases
            .get_mut(release_id)
            .ok_or_else(|| format!("unknown release: {release_id}"))?;
        ensure(release.status.is_open(), "release is not open")?;
        ensure(
            height >= release.unlock_height,
            "release timelock still active",
        )?;
        release.status = ReleaseStatus::Settled;
        release.settlement_tx_root = settlement_tx_root;
        release.settled_at_height = height;
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn resolve_dispute(
        &mut self,
        dispute_id: &str,
        status: DisputeStatus,
        resolution_root: String,
        height: u64,
    ) -> Result<()> {
        ensure(
            matches!(
                status,
                DisputeStatus::ResolvedSponsor
                    | DisputeStatus::ResolvedSolver
                    | DisputeStatus::ResolvedSplit
                    | DisputeStatus::Expired
                    | DisputeStatus::Slashed
            ),
            "invalid terminal dispute status",
        )?;
        let dispute = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| format!("unknown dispute: {dispute_id}"))?;
        ensure(dispute.status.is_open(), "dispute is not open")?;
        dispute.status = status;
        dispute.resolution_root = resolution_root;
        dispute.resolved_at_height = height;
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn slash_bond(&mut self, bond_id: &str, amount_piconero: u128, height: u64) -> Result<()> {
        let bond = self
            .bonds
            .get_mut(bond_id)
            .ok_or_else(|| format!("unknown bond: {bond_id}"))?;
        ensure(
            matches!(
                bond.status,
                BondStatus::Locked | BondStatus::PartiallySlashed
            ),
            "bond cannot be slashed",
        )?;
        ensure(amount_piconero > 0, "slash amount must be non-zero")?;
        ensure(
            bond.slashed_amount_piconero + amount_piconero <= bond.bond_amount_piconero,
            "slash exceeds bond",
        )?;
        bond.slashed_amount_piconero += amount_piconero;
        bond.status = if bond.slashed_amount_piconero == bond.bond_amount_piconero {
            BondStatus::Slashed
        } else {
            BondStatus::PartiallySlashed
        };
        bond.unlock_height = height;
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn consume_nullifier(&mut self, nullifier: String) -> Result<()> {
        ensure(
            !self.spent_nullifiers.contains(&nullifier),
            "nullifier already spent",
        )?;
        ensure(
            self.spent_nullifiers.len() < self.config.max_nullifiers,
            "too many nullifiers",
        )?;
        self.spent_nullifiers.insert(nullifier);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }
    pub fn record_event(
        &mut self,
        kind: EventKind,
        subject_id: &str,
        bounty_id: Option<String>,
        payload: &Value,
        height: u64,
    ) -> Result<String> {
        ensure(
            self.events.len() < self.config.max_events,
            "too many events",
        )?;
        let sequence = self.events.len() as u64;
        let event_id = event_id(kind, subject_id, sequence);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            bounty_id,
            payload_root: payload_root("bounty:event-payload", payload),
            height,
            sequence,
        };
        self.events.push(event);
        self.recompute_counters();
        self.recompute_roots();
        Ok(event_id)
    }
    fn validate_bounty(&self, item: &EncryptedBountySpec) -> Result<()> {
        ensure(!item.bounty_id.is_empty(), "bounty id is required")?;
        ensure(
            item.privacy_set_size >= self.config.min_privacy_set,
            "bounty privacy set too small",
        )?;
        ensure(
            item.pq_security_bits >= self.config.min_pq_security_bits,
            "bounty pq security too low",
        )?;
        ensure(
            item.escrow_fee_bps <= self.config.max_escrow_fee_bps,
            "escrow fee too high",
        )?;
        ensure(
            item.expires_at_height > item.opened_at_height,
            "bounty expiry must be after opening",
        )?;
        Ok(())
    }
    fn validate_commitment(&self, item: &PrivateSolverCommitment) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "commitment references unknown bounty",
        )?;
        ensure(
            !self.spent_nullifiers.contains(&item.solver_nullifier),
            "solver nullifier already spent",
        )?;
        ensure(
            item.privacy_set_size >= self.config.min_privacy_set,
            "commitment privacy set too small",
        )?;
        ensure(
            item.pq_security_bits >= self.config.min_pq_security_bits,
            "commitment pq security too low",
        )?;
        Ok(())
    }
    fn validate_approval(&self, item: &PqSponsorApproval) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "approval references unknown bounty",
        )?;
        ensure(
            self.commitments.contains_key(&item.commitment_id),
            "approval references unknown commitment",
        )?;
        ensure(
            !self.spent_nullifiers.contains(&item.approval_nullifier),
            "approval nullifier already spent",
        )?;
        ensure(
            item.approved_release_bps
                <= PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_BOUNTY_ESCROW_RUNTIME_MAX_BPS,
            "approval release bps too high",
        )?;
        Ok(())
    }
    fn validate_milestone(&self, item: &ConfidentialMilestoneProof) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "milestone references unknown bounty",
        )?;
        ensure(
            self.commitments.contains_key(&item.commitment_id),
            "milestone references unknown commitment",
        )?;
        ensure(
            !self.spent_nullifiers.contains(&item.milestone_nullifier),
            "milestone nullifier already spent",
        )?;
        ensure(
            item.privacy_set_size >= self.config.min_privacy_set,
            "milestone privacy set too small",
        )?;
        Ok(())
    }
    fn validate_release(&self, item: &TokenEscrowRelease) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "release references unknown bounty",
        )?;
        ensure(
            self.milestones.contains_key(&item.milestone_id),
            "release references unknown milestone",
        )?;
        ensure(item.amount_piconero > 0, "release amount must be non-zero")?;
        ensure(
            item.unlock_height >= item.queued_at_height,
            "release unlock before queue",
        )?;
        Ok(())
    }
    fn validate_dispute(&self, item: &BountyDispute) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "dispute references unknown bounty",
        )?;
        ensure(
            self.commitments.contains_key(&item.commitment_id),
            "dispute references unknown commitment",
        )?;
        ensure(
            item.evidence_deadline_height > item.opened_at_height,
            "dispute evidence deadline invalid",
        )?;
        Ok(())
    }
    fn validate_bond(&self, item: &DisputeChallengeBond) -> Result<()> {
        ensure(
            self.disputes.contains_key(&item.dispute_id),
            "bond references unknown dispute",
        )?;
        ensure(
            item.bond_amount_piconero > 0,
            "bond amount must be non-zero",
        )?;
        ensure(
            item.bond_bps >= self.config.min_challenge_bond_bps,
            "bond below minimum",
        )?;
        ensure(
            item.bond_bps <= self.config.max_challenge_bond_bps,
            "bond above maximum",
        )?;
        Ok(())
    }
    fn validate_receipt(&self, item: &RecursiveProofReceipt) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "receipt references unknown bounty",
        )?;
        ensure(
            item.verdict.accepts_state(),
            "receipt verdict does not accept state",
        )?;
        ensure(
            item.privacy_set_size >= self.config.min_privacy_set,
            "receipt privacy set too small",
        )?;
        ensure(
            item.pq_security_bits >= self.config.min_pq_security_bits,
            "receipt pq security too low",
        )?;
        Ok(())
    }
    fn validate_rebate(&self, item: &LowFeeRebate) -> Result<()> {
        ensure(
            self.releases.contains_key(&item.release_id),
            "rebate references unknown release",
        )?;
        ensure(
            item.rebate_bps <= self.config.max_escrow_fee_bps,
            "rebate bps above fee cap",
        )?;
        ensure(
            item.rebate_piconero <= item.charged_fee_piconero,
            "rebate exceeds charged fee",
        )?;
        Ok(())
    }
    fn validate_fence(&self, item: &PrivacyFence) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "fence references unknown bounty",
        )?;
        ensure(
            item.privacy_set_size >= self.config.min_privacy_set,
            "fence privacy set too small",
        )?;
        ensure(
            item.expires_at_height > item.anchored_at_height,
            "fence expiry invalid",
        )?;
        Ok(())
    }
    fn validate_slashing(&self, item: &SlashingEvidence) -> Result<()> {
        ensure(
            self.bounties.contains_key(&item.bounty_id),
            "slashing references unknown bounty",
        )?;
        ensure(
            item.slash_amount_piconero > 0,
            "slash amount must be non-zero",
        )?;
        ensure(
            !item.evidence_root.is_empty(),
            "slashing evidence root required",
        )?;
        Ok(())
    }
    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            bounties: self.bounties.len() as u64,
            active_bounties: self
                .bounties
                .values()
                .filter(|b| b.status.accepts_commitments())
                .count() as u64,
            solver_commitments: self.commitments.len() as u64,
            open_commitments: self
                .commitments
                .values()
                .filter(|c| c.status.is_open())
                .count() as u64,
            sponsor_approvals: self.approvals.len() as u64,
            milestone_proofs: self.milestones.len() as u64,
            accepted_milestones: self
                .milestones
                .values()
                .filter(|m| m.status.can_release())
                .count() as u64,
            token_releases: self.releases.len() as u64,
            open_releases: self
                .releases
                .values()
                .filter(|r| r.status.is_open())
                .count() as u64,
            disputes: self.disputes.len() as u64,
            open_disputes: self
                .disputes
                .values()
                .filter(|d| d.status.is_open())
                .count() as u64,
            challenge_bonds: self.bonds.len() as u64,
            proof_receipts: self.proof_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            slashing_records: self.slashing_records.len() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            events: self.events.len() as u64,
            total_escrowed_piconero: self.bounties.values().map(|_| 0u128).sum(),
            total_released_piconero: self
                .releases
                .values()
                .filter(|r| matches!(r.status, ReleaseStatus::Settled | ReleaseStatus::Rebated))
                .map(|r| r.amount_piconero)
                .sum(),
            total_bonded_piconero: self.bonds.values().map(|b| b.bond_amount_piconero).sum(),
            total_slashed_piconero: self
                .bonds
                .values()
                .map(|b| b.slashed_amount_piconero)
                .sum::<u128>()
                + self
                    .slashing_records
                    .values()
                    .map(|s| s.slash_amount_piconero)
                    .sum::<u128>(),
            total_rebated_piconero: self.rebates.values().map(|r| r.rebate_piconero).sum(),
        };
    }
    pub fn recompute_roots(&mut self) {
        self.roots.bounty_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-BOUNTY",
            &self
                .bounties
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.active_bounty_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-ACTIVE-BOUNTY",
            &self
                .bounties
                .values()
                .filter(|v| v.status.accepts_commitments())
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.commitment_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-COMMITMENT",
            &self
                .commitments
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.open_commitment_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-OPEN-COMMITMENT",
            &self
                .commitments
                .values()
                .filter(|v| v.status.is_open())
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.approval_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-APPROVAL",
            &self
                .approvals
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.milestone_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-MILESTONE",
            &self
                .milestones
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.accepted_milestone_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-ACCEPTED-MILESTONE",
            &self
                .milestones
                .values()
                .filter(|v| v.status.can_release())
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.release_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-RELEASE",
            &self
                .releases
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.open_release_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-OPEN-RELEASE",
            &self
                .releases
                .values()
                .filter(|v| v.status.is_open())
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.dispute_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-DISPUTE",
            &self
                .disputes
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.open_dispute_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-OPEN-DISPUTE",
            &self
                .disputes
                .values()
                .filter(|v| v.status.is_open())
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.bond_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-BOND",
            &self
                .bonds
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.proof_receipt_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-PROOF-RECEIPT",
            &self
                .proof_receipts
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.rebate_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-REBATE",
            &self
                .rebates
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.privacy_fence_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-PRIVACY-FENCE",
            &self
                .privacy_fences
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.slashing_record_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-SLASHING-RECORD",
            &self
                .slashing_records
                .values()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-NULLIFIERS",
            &self
                .spent_nullifiers
                .iter()
                .map(|v| Value::String(v.clone()))
                .collect::<Vec<_>>(),
        );
        self.roots.event_root = merkle_root(
            "PRIVATE-L2-PQ-BOUNTY-EVENTS",
            &self
                .events
                .iter()
                .map(|v| v.public_record())
                .collect::<Vec<_>>(),
        );
        self.roots.config_root =
            root_from_record("PRIVATE-L2-PQ-BOUNTY-CONFIG", &self.config.public_record());
        self.roots.counters_root = root_from_record(
            "PRIVATE-L2-PQ-BOUNTY-COUNTERS",
            &self.counters.public_record(),
        );
        let record = self.public_record_without_roots();
        self.roots.public_record_root = public_record_root(&record);
        self.roots.state_root = state_root_from_record(&record);
    }
    fn public_record_without_roots(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": self.config.protocol_version, "schema_version": self.config.schema_version, "counters": self.counters, "limits": { "max_bounties": self.config.max_bounties, "max_commitments": self.config.max_commitments, "max_milestones": self.config.max_milestones, "max_releases": self.config.max_releases, "min_privacy_set": self.config.min_privacy_set, "min_pq_security_bits": self.config.min_pq_security_bits, "max_escrow_fee_bps": self.config.max_escrow_fee_bps, "target_rebate_bps": self.config.target_rebate_bps }, "feature_flags": { "encrypted_bounty_specs": true, "private_solver_commitments": true, "pq_sponsor_approvals": true, "confidential_milestone_proofs": true, "token_escrow_releases": true, "fee_rebates": true, "challenge_bonds": true, "recursive_proof_receipts": true, "privacy_fences": true, "slashing_evidence": true } })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_roots();
        if let Value::Object(ref mut map) = record {
            map.insert("roots".to_string(), self.roots.public_record());
        }
        record
    }
    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub type Runtime = State;
pub fn devnet() -> State {
    State::devnet()
}
pub fn private_l2_pq_confidential_contract_bounty_escrow_runtime_public_record() -> Value {
    State::devnet().public_record()
}
pub fn private_l2_pq_confidential_contract_bounty_escrow_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-BOUNTY-PUBLIC-RECORD", record)
}
pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-BOUNTY-STATE-ROOT", record)
}
pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}
pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}
pub fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn nullifier(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn bounty_id(
    asset_kind: BountyAssetKind,
    sponsor_commitment: &str,
    asset_commitment: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_kind.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(asset_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn solver_commitment_id(bounty_id: &str, solver_nonce: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(solver_nonce),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn approval_id(bounty_id: &str, commitment_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(commitment_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn milestone_id(bounty_id: &str, commitment_id: &str, milestone_index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-MILESTONE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(commitment_id),
            HashPart::U64(milestone_index),
        ],
        32,
    )
}
pub fn release_id(bounty_id: &str, milestone_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-RELEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(milestone_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn dispute_id(bounty_id: &str, milestone_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(milestone_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn bond_id(dispute_id: &str, bonder_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Str(bonder_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn proof_receipt_id(bounty_id: &str, kind: ProofReceiptKind, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-PROOF-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn rebate_id(release_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(release_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn privacy_fence_id(bounty_id: &str, kind: PrivacyFenceKind, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn slashing_id(
    bounty_id: &str,
    subject_id: &str,
    reason: SlashingReason,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bounty_id),
            HashPart::Str(subject_id),
            HashPart::Str(reason.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn event_id(kind: EventKind, subject_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BOUNTY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}
fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
pub trait PublicRecord {
    fn as_public_record(&self) -> Value;
}
impl PublicRecord for EncryptedBountySpec {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for PrivateSolverCommitment {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for PqSponsorApproval {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for ConfidentialMilestoneProof {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for TokenEscrowRelease {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for LowFeeRebate {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for DisputeChallengeBond {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for BountyDispute {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for RecursiveProofReceipt {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for PrivacyFence {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for SlashingEvidence {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for RuntimeEvent {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}
