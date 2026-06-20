use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaBridgeWithdrawalQuorumBondRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_BRIDGE_WITHDRAWAL_QUORUM_BOND_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-dsa-bridge-withdrawal-quorum-bond-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_BRIDGE_WITHDRAWAL_QUORUM_BOND_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-withdrawal-quorum-bond-v1";
pub const BOND_COMMITMENT_SCHEME: &str = "private-l2-ml-dsa-signer-bond-commitment-root-v1";
pub const QUORUM_POLICY_SCHEME: &str = "private-l2-confidential-withdrawal-quorum-policy-root-v1";
pub const ATTESTATION_SCHEME: &str = "ml-dsa-confidential-withdrawal-quorum-attestation-root-v1";
pub const WITHDRAWAL_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-withdrawal-batch-commitment-root-v1";
pub const CHALLENGE_WINDOW_SCHEME: &str = "monero-private-l2-withdrawal-challenge-window-root-v1";
pub const SLASHING_CLAIM_SCHEME: &str = "ml-dsa-withdrawal-quorum-bond-slashing-claim-root-v1";
pub const FEE_REBATE_SCHEME: &str = "private-l2-low-fee-withdrawal-fee-credit-rebate-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str = "private-l2-withdrawal-quorum-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "private-l2-withdrawal-quorum-operator-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_720_800;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_SIGNERS: u16 = 5;
pub const DEFAULT_MIN_WEIGHT: u64 = 13;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 6_700;
pub const DEFAULT_MIN_BOND_ATOMIC_UNITS: u64 = 5_000_000_000;
pub const DEFAULT_MAX_USER_FEE_ATOMIC_UNITS: u64 = 20_000;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_REORG_GUARD_BLOCKS: u64 = 32;
pub const DEFAULT_SLASHING_EVIDENCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_BUDGET_FIELDS: u16 = 6;
pub const DEFAULT_MAX_POLICIES: usize = 262_144;
pub const DEFAULT_MAX_SIGNER_BONDS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_WITHDRAWAL_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_CHALLENGE_WINDOWS: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHING_CLAIMS: usize = 524_288;
pub const DEFAULT_MAX_FEE_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalLane {
    LowFee,
    Standard,
    Fast,
    EmergencyReorg,
    LiquidityBackstop,
}

impl WithdrawalLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::EmergencyReorg => "emergency_reorg",
            Self::LiquidityBackstop => "liquidity_backstop",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyReorg => 1_000,
            Self::LiquidityBackstop => 920,
            Self::Fast => 860,
            Self::Standard => 720,
            Self::LowFee => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    Paused,
    ChallengeOnly,
    Retired,
}

impl PolicyStatus {
    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Pending,
    Active,
    CoolingDown,
    LockedForChallenge,
    Slashed,
    Released,
}

impl BondStatus {
    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::LockedForChallenge)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    ApproveWithdrawal,
    RejectWithdrawal,
    ChallengeRequired,
    FeeOverLimit,
    PrivacyFloorBreached,
    ReorgRisk,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    QuorumPending,
    QuorumReached,
    ChallengeOpen,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::QuorumPending | Self::QuorumReached | Self::ChallengeOpen
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceCommitted,
    Sustained,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    Equivocation,
    InvalidWithdrawalRoot,
    FeeOvercharge,
    PrivacyDisclosure,
    ReorgConcealment,
    Timeout,
    QuorumForgery,
}

impl SlashingReason {
    pub fn severity_bps(self) -> u64 {
        match self {
            Self::QuorumForgery => 10_000,
            Self::Equivocation => 8_000,
            Self::InvalidWithdrawalRoot => 7_000,
            Self::PrivacyDisclosure => 6_500,
            Self::ReorgConcealment => 5_000,
            Self::FeeOvercharge => 2_500,
            Self::Timeout => 1_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToLowFeeLane,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionField {
    SenderCommitment,
    ReceiverCommitment,
    AmountCommitment,
    DecoySetRoot,
    FeeQuote,
    SignerSet,
    TimingMetadata,
    ChallengeEvidence,
}

impl RedactionField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SenderCommitment => "sender_commitment",
            Self::ReceiverCommitment => "receiver_commitment",
            Self::AmountCommitment => "amount_commitment",
            Self::DecoySetRoot => "decoy_set_root",
            Self::FeeQuote => "fee_quote",
            Self::SignerSet => "signer_set",
            Self::TimingMetadata => "timing_metadata",
            Self::ChallengeEvidence => "challenge_evidence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub bond_commitment_scheme: String,
    pub quorum_policy_scheme: String,
    pub attestation_scheme: String,
    pub withdrawal_batch_scheme: String,
    pub challenge_window_scheme: String,
    pub slashing_claim_scheme: String,
    pub fee_rebate_scheme: String,
    pub privacy_redaction_scheme: String,
    pub operator_summary_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_signers: u16,
    pub min_weight: u64,
    pub supermajority_bps: u64,
    pub min_bond_atomic_units: u64,
    pub max_user_fee_atomic_units: u64,
    pub target_rebate_bps: u64,
    pub batch_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub reorg_guard_blocks: u64,
    pub slashing_evidence_ttl_blocks: u64,
    pub redaction_budget_fields: u16,
    pub max_policies: usize,
    pub max_signer_bonds: usize,
    pub max_attestations: usize,
    pub max_withdrawal_batches: usize,
    pub max_challenge_windows: usize,
    pub max_slashing_claims: usize,
    pub max_fee_rebates: usize,
    pub max_redaction_budgets: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            bond_commitment_scheme: BOND_COMMITMENT_SCHEME.to_string(),
            quorum_policy_scheme: QUORUM_POLICY_SCHEME.to_string(),
            attestation_scheme: ATTESTATION_SCHEME.to_string(),
            withdrawal_batch_scheme: WITHDRAWAL_BATCH_SCHEME.to_string(),
            challenge_window_scheme: CHALLENGE_WINDOW_SCHEME.to_string(),
            slashing_claim_scheme: SLASHING_CLAIM_SCHEME.to_string(),
            fee_rebate_scheme: FEE_REBATE_SCHEME.to_string(),
            privacy_redaction_scheme: PRIVACY_REDACTION_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_signers: DEFAULT_MIN_SIGNERS,
            min_weight: DEFAULT_MIN_WEIGHT,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
            min_bond_atomic_units: DEFAULT_MIN_BOND_ATOMIC_UNITS,
            max_user_fee_atomic_units: DEFAULT_MAX_USER_FEE_ATOMIC_UNITS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            reorg_guard_blocks: DEFAULT_REORG_GUARD_BLOCKS,
            slashing_evidence_ttl_blocks: DEFAULT_SLASHING_EVIDENCE_TTL_BLOCKS,
            redaction_budget_fields: DEFAULT_REDACTION_BUDGET_FIELDS,
            max_policies: DEFAULT_MAX_POLICIES,
            max_signer_bonds: DEFAULT_MAX_SIGNER_BONDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_withdrawal_batches: DEFAULT_MAX_WITHDRAWAL_BATCHES,
            max_challenge_windows: DEFAULT_MAX_CHALLENGE_WINDOWS,
            max_slashing_claims: DEFAULT_MAX_SLASHING_CLAIMS,
            max_fee_rebates: DEFAULT_MAX_FEE_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_positive("min_pq_security_bits", self.min_pq_security_bits as u64)?;
        require(
            self.min_pq_security_bits >= 256,
            "pq security floor below 256 bits",
        )?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum privacy set",
        )?;
        require_positive("min_signers", self.min_signers as u64)?;
        require_positive("min_weight", self.min_weight)?;
        require_bps("supermajority_bps", self.supermajority_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_positive("min_bond_atomic_units", self.min_bond_atomic_units)?;
        require_positive("challenge_window_blocks", self.challenge_window_blocks)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_policy: u64,
    pub next_signer_bond: u64,
    pub next_attestation: u64,
    pub next_withdrawal_batch: u64,
    pub next_challenge_window: u64,
    pub next_slashing_claim: u64,
    pub next_fee_rebate: u64,
    pub next_redaction_budget: u64,
    pub consumed_nullifiers: u64,
    pub accepted_batches: u64,
    pub rejected_batches: u64,
    pub sustained_challenges: u64,
    pub total_rebate_atomic_units: u64,
    pub total_slashed_atomic_units: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_policy: 1,
            next_signer_bond: 1,
            next_attestation: 1,
            next_withdrawal_batch: 1,
            next_challenge_window: 1,
            next_slashing_claim: 1,
            next_fee_rebate: 1,
            next_redaction_budget: 1,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorization {
    pub suite: String,
    pub signer_commitment: String,
    pub public_key_commitment: String,
    pub transcript_root: String,
    pub signature_commitment: String,
    pub pq_security_bits: u16,
}

impl PqAuthorization {
    pub fn devnet(signer: &str, transcript_root: &str) -> Self {
        Self {
            suite: PQ_SIGNATURE_SUITE.to_string(),
            signer_commitment: signer.to_string(),
            public_key_commitment: payload_id(
                "PRIVATE-L2-PQ-WITHDRAWAL-AUTH-KEY",
                &[HashPart::Str(signer)],
            ),
            transcript_root: transcript_root.to_string(),
            signature_commitment: payload_id(
                "PRIVATE-L2-PQ-WITHDRAWAL-AUTH-SIG",
                &[HashPart::Str(signer), HashPart::Str(transcript_root)],
            ),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            self.suite == config.pq_signature_suite,
            "unsupported pq signature suite",
        )?;
        require_non_empty("signer_commitment", &self.signer_commitment)?;
        require_root("public_key_commitment", &self.public_key_commitment)?;
        require_root("transcript_root", &self.transcript_root)?;
        require_root("signature_commitment", &self.signature_commitment)?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pq authorization below configured security floor",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalQuorumPolicy {
    pub policy_id: String,
    pub lane: WithdrawalLane,
    pub operator_set_root: String,
    pub signer_registry_root: String,
    pub fee_policy_root: String,
    pub privacy_policy_root: String,
    pub min_signers: u16,
    pub min_weight: u64,
    pub supermajority_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_user_fee_atomic_units: u64,
    pub challenge_window_blocks: u64,
    pub reorg_guard_blocks: u64,
    pub status: PolicyStatus,
    pub created_height: u64,
}

impl WithdrawalQuorumPolicy {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-WITHDRAWAL-QUORUM-POLICY",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("policy_id", &self.policy_id)?;
        require_root("operator_set_root", &self.operator_set_root)?;
        require_root("signer_registry_root", &self.signer_registry_root)?;
        require_positive("min_signers", self.min_signers as u64)?;
        require_positive("min_weight", self.min_weight)?;
        require(
            self.min_signers >= config.min_signers,
            "policy signer floor too low",
        )?;
        require(
            self.min_weight >= config.min_weight,
            "policy weight floor too low",
        )?;
        require_bps("supermajority_bps", self.supermajority_bps)?;
        require(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "policy privacy set below config floor",
        )?;
        require(
            self.max_user_fee_atomic_units <= config.max_user_fee_atomic_units,
            "policy fee cap above config cap",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlDsaSignerBond {
    pub bond_id: String,
    pub signer_commitment: String,
    pub operator_commitment: String,
    pub policy_id: String,
    pub bond_commitment: String,
    pub collateral_asset_id: String,
    pub locked_amount_atomic_units: u64,
    pub effective_weight: u64,
    pub pq_authorization: PqAuthorization,
    pub status: BondStatus,
    pub locked_at_height: u64,
    pub cooldown_height: Option<u64>,
}

impl MlDsaSignerBond {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-WITHDRAWAL-SIGNER-BOND",
            &self.public_record(),
        )
    }

    pub fn slashable_amount(&self, reason: SlashingReason) -> u64 {
        self.locked_amount_atomic_units
            .saturating_mul(reason.severity_bps())
            / MAX_BPS
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("bond_id", &self.bond_id)?;
        require_non_empty("signer_commitment", &self.signer_commitment)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_non_empty("policy_id", &self.policy_id)?;
        require_root("bond_commitment", &self.bond_commitment)?;
        require(
            self.locked_amount_atomic_units >= config.min_bond_atomic_units,
            "bond amount below configured minimum",
        )?;
        require_positive("effective_weight", self.effective_weight)?;
        self.pq_authorization.validate(config)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuorumAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub policy_id: String,
    pub bond_id: String,
    pub signer_commitment: String,
    pub verdict: AttestationVerdict,
    pub statement_root: String,
    pub fee_quote_root: String,
    pub privacy_proof_root: String,
    pub reorg_guard_root: String,
    pub weight: u64,
    pub pq_authorization: PqAuthorization,
    pub attested_height: u64,
}

impl QuorumAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-WITHDRAWAL-QUORUM-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn approves(&self) -> bool {
        self.verdict == AttestationVerdict::ApproveWithdrawal
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("policy_id", &self.policy_id)?;
        require_non_empty("bond_id", &self.bond_id)?;
        require_root("statement_root", &self.statement_root)?;
        require_root("privacy_proof_root", &self.privacy_proof_root)?;
        require_positive("weight", self.weight)?;
        self.pq_authorization.validate(config)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalBatchCommitment {
    pub batch_id: String,
    pub policy_id: String,
    pub lane: WithdrawalLane,
    pub withdrawal_note_root: String,
    pub destination_commitment_root: String,
    pub amount_commitment_root: String,
    pub decoy_set_root: String,
    pub nullifier_root: String,
    pub fee_quote_root: String,
    pub batch_proof_root: String,
    pub requested_fee_atomic_units: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: BatchStatus,
    pub attestation_ids: BTreeSet<String>,
}

impl WithdrawalBatchCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-WITHDRAWAL-BATCH", &self.public_record())
    }

    pub fn validate(&self, config: &Config, policy: &WithdrawalQuorumPolicy) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("withdrawal_note_root", &self.withdrawal_note_root)?;
        require_root(
            "destination_commitment_root",
            &self.destination_commitment_root,
        )?;
        require_root("amount_commitment_root", &self.amount_commitment_root)?;
        require_root("decoy_set_root", &self.decoy_set_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("batch_proof_root", &self.batch_proof_root)?;
        require(
            self.requested_fee_atomic_units <= policy.max_user_fee_atomic_units,
            "batch fee exceeds policy cap",
        )?;
        require(
            self.requested_fee_atomic_units <= config.max_user_fee_atomic_units,
            "batch fee exceeds config cap",
        )?;
        require(
            self.privacy_set_size >= policy.min_privacy_set_size,
            "batch privacy set below policy floor",
        )?;
        require(
            self.expires_height > self.opened_height,
            "batch expiry must be after open height",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindow {
    pub challenge_id: String,
    pub batch_id: String,
    pub policy_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub disclosed_fields: BTreeSet<RedactionField>,
    pub opened_height: u64,
    pub expires_height: u64,
    pub bond_lock_root: String,
    pub status: ChallengeStatus,
}

impl ChallengeWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-WITHDRAWAL-CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingClaim {
    pub claim_id: String,
    pub challenge_id: String,
    pub batch_id: String,
    pub bond_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slash_amount_atomic_units: u64,
    pub claimant_reward_atomic_units: u64,
    pub treasury_credit_atomic_units: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub sustained: bool,
}

impl SlashingClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-WITHDRAWAL-SLASHING-CLAIM",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub fee_paid_atomic_units: u64,
    pub rebate_atomic_units: u64,
    pub rebate_nullifier: String,
    pub claimable_height: u64,
    pub expires_height: u64,
    pub status: RebateStatus,
}

impl FeeCreditRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-WITHDRAWAL-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub allowed_fields: BTreeSet<RedactionField>,
    pub spent_fields: BTreeSet<RedactionField>,
    pub privacy_set_size: u64,
    pub minimum_remaining_set_size: u64,
    pub budget_nullifier: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-WITHDRAWAL-REDACTION-BUDGET",
            &self.public_record(),
        )
    }

    pub fn remaining_fields(&self) -> BTreeSet<RedactionField> {
        self.allowed_fields
            .difference(&self.spent_fields)
            .copied()
            .collect()
    }

    pub fn spend(&mut self, fields: &BTreeSet<RedactionField>) -> Result<()> {
        require(
            fields.is_subset(&self.allowed_fields),
            "redaction spend contains a disallowed field",
        )?;
        require(
            fields.is_disjoint(&self.spent_fields),
            "redaction field already spent",
        )?;
        self.spent_fields.extend(fields.iter().copied());
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_commitment: String,
    pub active_bonds: u64,
    pub total_weight: u64,
    pub locked_bond_atomic_units: u64,
    pub attestation_count: u64,
    pub approved_weight: u64,
    pub challenged_batches: u64,
    pub slashed_atomic_units: u64,
    pub rebate_contributed_atomic_units: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-L2-PQ-WITHDRAWAL-OPERATOR-SUMMARY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub quorum_policy_root: String,
    pub signer_bond_root: String,
    pub quorum_attestation_root: String,
    pub withdrawal_batch_root: String,
    pub challenge_window_root: String,
    pub slashing_claim_root: String,
    pub fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub quorum_policies: BTreeMap<String, WithdrawalQuorumPolicy>,
    pub signer_bonds: BTreeMap<String, MlDsaSignerBond>,
    pub quorum_attestations: BTreeMap<String, QuorumAttestation>,
    pub withdrawal_batches: BTreeMap<String, WithdrawalBatchCommitment>,
    pub challenge_windows: BTreeMap<String, ChallengeWindow>,
    pub slashing_claims: BTreeMap<String, SlashingClaim>,
    pub fee_rebates: BTreeMap<String, FeeCreditRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifier_index: BTreeSet<String>,
    pub attestations_by_batch: BTreeMap<String, BTreeSet<String>>,
    pub bonds_by_policy: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::devnet(),
            height: DEVNET_HEIGHT,
            quorum_policies: BTreeMap::new(),
            signer_bonds: BTreeMap::new(),
            quorum_attestations: BTreeMap::new(),
            withdrawal_batches: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            slashing_claims: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            attestations_by_batch: BTreeMap::new(),
            bonds_by_policy: BTreeMap::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots_without_state_root();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "quorum_policy_count": self.quorum_policies.len(),
            "signer_bond_count": self.signer_bonds.len(),
            "quorum_attestation_count": self.quorum_attestations.len(),
            "withdrawal_batch_count": self.withdrawal_batches.len(),
            "challenge_window_count": self.challenge_windows.len(),
            "slashing_claim_count": self.slashing_claims.len(),
            "fee_rebate_count": self.fee_rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
        })
    }

    pub fn roots(&self) -> Roots {
        let mut roots = self.roots_without_state_root();
        roots.state_root = state_root_from_record(&self.public_record_without_state_root());
        roots
    }

    fn roots_without_state_root(&self) -> Roots {
        Roots {
            quorum_policy_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-POLICY-ROOT",
                &self.quorum_policies,
            ),
            signer_bond_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-SIGNER-BOND-ROOT",
                &self.signer_bonds,
            ),
            quorum_attestation_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-ATTESTATION-ROOT",
                &self.quorum_attestations,
            ),
            withdrawal_batch_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-BATCH-ROOT",
                &self.withdrawal_batches,
            ),
            challenge_window_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-CHALLENGE-ROOT",
                &self.challenge_windows,
            ),
            slashing_claim_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-SLASHING-ROOT",
                &self.slashing_claims,
            ),
            fee_rebate_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-FEE-REBATE-ROOT",
                &self.fee_rebates,
            ),
            redaction_budget_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-REDACTION-ROOT",
                &self.redaction_budgets,
            ),
            operator_summary_root: map_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-OPERATOR-SUMMARY-ROOT",
                &self.operator_summaries,
            ),
            nullifier_root: set_root(
                "PRIVATE-L2-PQ-WITHDRAWAL-NULLIFIER-ROOT",
                &self.nullifier_index,
            ),
            state_root: String::new(),
        }
    }

    pub fn install_quorum_policy(&mut self, mut policy: WithdrawalQuorumPolicy) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            self.quorum_policies.len(),
            self.config.max_policies,
            "quorum policy capacity exceeded",
        )?;
        if policy.policy_id.is_empty() {
            policy.policy_id = next_id("withdrawal-policy", self.counters.next_policy);
        }
        policy.validate(&self.config)?;
        require(
            !self.quorum_policies.contains_key(&policy.policy_id),
            "duplicate quorum policy",
        )?;
        let policy_id = policy.policy_id.clone();
        self.quorum_policies.insert(policy_id.clone(), policy);
        self.counters.next_policy += 1;
        Ok(policy_id)
    }

    pub fn lock_signer_bond(&mut self, mut bond: MlDsaSignerBond) -> Result<String> {
        require_capacity(
            self.signer_bonds.len(),
            self.config.max_signer_bonds,
            "signer bond capacity exceeded",
        )?;
        require(
            self.quorum_policies.contains_key(&bond.policy_id),
            "unknown policy for signer bond",
        )?;
        if bond.bond_id.is_empty() {
            bond.bond_id = next_id("ml-dsa-bond", self.counters.next_signer_bond);
        }
        bond.validate(&self.config)?;
        require(
            !self.signer_bonds.contains_key(&bond.bond_id),
            "duplicate signer bond",
        )?;
        self.consume_nullifier(&bond.bond_commitment)?;
        let bond_id = bond.bond_id.clone();
        self.bump_operator_bond(&bond);
        self.bonds_by_policy
            .entry(bond.policy_id.clone())
            .or_default()
            .insert(bond_id.clone());
        self.signer_bonds.insert(bond_id.clone(), bond);
        self.counters.next_signer_bond += 1;
        Ok(bond_id)
    }

    pub fn submit_withdrawal_batch(
        &mut self,
        mut batch: WithdrawalBatchCommitment,
    ) -> Result<String> {
        require_capacity(
            self.withdrawal_batches.len(),
            self.config.max_withdrawal_batches,
            "withdrawal batch capacity exceeded",
        )?;
        let policy = self
            .quorum_policies
            .get(&batch.policy_id)
            .ok_or_else(|| "unknown withdrawal policy".to_string())?;
        require(
            policy.status.accepts_batches(),
            "policy does not accept batches",
        )?;
        if batch.batch_id.is_empty() {
            batch.batch_id = next_id("withdrawal-batch", self.counters.next_withdrawal_batch);
        }
        batch.validate(&self.config, policy)?;
        self.consume_nullifier(&batch.nullifier_root)?;
        let batch_id = batch.batch_id.clone();
        self.withdrawal_batches.insert(batch_id.clone(), batch);
        self.counters.next_withdrawal_batch += 1;
        Ok(batch_id)
    }

    pub fn record_quorum_attestation(
        &mut self,
        mut attestation: QuorumAttestation,
    ) -> Result<String> {
        require_capacity(
            self.quorum_attestations.len(),
            self.config.max_attestations,
            "quorum attestation capacity exceeded",
        )?;
        let bond = self
            .signer_bonds
            .get(&attestation.bond_id)
            .ok_or_else(|| "unknown signer bond".to_string())?
            .clone();
        require(bond.status.can_attest(), "signer bond cannot attest")?;
        require(
            bond.signer_commitment == attestation.signer_commitment,
            "attestation signer mismatch",
        )?;
        require(
            bond.policy_id == attestation.policy_id,
            "attestation policy mismatch",
        )?;
        require(
            self.withdrawal_batches.contains_key(&attestation.batch_id),
            "unknown withdrawal batch",
        )?;
        if attestation.attestation_id.is_empty() {
            attestation.attestation_id =
                next_id("quorum-attestation", self.counters.next_attestation);
        }
        attestation.validate(&self.config)?;
        let attestation_id = attestation.attestation_id.clone();
        let batch_id = attestation.batch_id.clone();
        self.bump_operator_attestation(bond, &attestation);
        self.quorum_attestations
            .insert(attestation_id.clone(), attestation);
        self.attestations_by_batch
            .entry(batch_id.clone())
            .or_default()
            .insert(attestation_id.clone());
        self.refresh_batch_quorum(&batch_id)?;
        self.counters.next_attestation += 1;
        Ok(attestation_id)
    }

    pub fn open_challenge_window(&mut self, mut challenge: ChallengeWindow) -> Result<String> {
        require_capacity(
            self.challenge_windows.len(),
            self.config.max_challenge_windows,
            "challenge window capacity exceeded",
        )?;
        require(
            self.withdrawal_batches.contains_key(&challenge.batch_id),
            "unknown batch for challenge",
        )?;
        if challenge.challenge_id.is_empty() {
            challenge.challenge_id =
                next_id("withdrawal-challenge", self.counters.next_challenge_window);
        }
        require_root("evidence_root", &challenge.evidence_root)?;
        require(
            challenge.expires_height > challenge.opened_height,
            "challenge expiry must be after open height",
        )?;
        let challenge_id = challenge.challenge_id.clone();
        if let Some(batch) = self.withdrawal_batches.get_mut(&challenge.batch_id) {
            batch.status = BatchStatus::ChallengeOpen;
        }
        self.challenge_windows
            .insert(challenge_id.clone(), challenge);
        self.counters.next_challenge_window += 1;
        Ok(challenge_id)
    }

    pub fn sustain_challenge_with_slashing(
        &mut self,
        challenge_id: &str,
        bond_id: &str,
        reason: SlashingReason,
        evidence_root: String,
    ) -> Result<String> {
        require_capacity(
            self.slashing_claims.len(),
            self.config.max_slashing_claims,
            "slashing claim capacity exceeded",
        )?;
        require_root("evidence_root", &evidence_root)?;
        let challenge = self
            .challenge_windows
            .get_mut(challenge_id)
            .ok_or_else(|| "unknown challenge".to_string())?;
        let bond = self
            .signer_bonds
            .get_mut(bond_id)
            .ok_or_else(|| "unknown signer bond".to_string())?;
        let slash_amount = bond.slashable_amount(reason);
        bond.locked_amount_atomic_units =
            bond.locked_amount_atomic_units.saturating_sub(slash_amount);
        bond.status = BondStatus::Slashed;
        challenge.status = ChallengeStatus::Sustained;
        let claimant_reward = slash_amount / 5;
        let claim = SlashingClaim {
            claim_id: next_id("slashing-claim", self.counters.next_slashing_claim),
            challenge_id: challenge_id.to_string(),
            batch_id: challenge.batch_id.clone(),
            bond_id: bond_id.to_string(),
            reason,
            evidence_root,
            slash_amount_atomic_units: slash_amount,
            claimant_reward_atomic_units: claimant_reward,
            treasury_credit_atomic_units: slash_amount.saturating_sub(claimant_reward),
            created_height: self.height,
            expires_height: self.height + self.config.slashing_evidence_ttl_blocks,
            sustained: true,
        };
        let claim_id = claim.claim_id.clone();
        self.counters.total_slashed_atomic_units = self
            .counters
            .total_slashed_atomic_units
            .saturating_add(slash_amount);
        self.counters.sustained_challenges += 1;
        self.slashing_claims.insert(claim_id.clone(), claim);
        self.counters.next_slashing_claim += 1;
        Ok(claim_id)
    }

    pub fn queue_fee_credit_rebate(&mut self, mut rebate: FeeCreditRebate) -> Result<String> {
        require_capacity(
            self.fee_rebates.len(),
            self.config.max_fee_rebates,
            "fee rebate capacity exceeded",
        )?;
        require(
            self.withdrawal_batches.contains_key(&rebate.batch_id),
            "unknown batch for rebate",
        )?;
        if rebate.rebate_id.is_empty() {
            rebate.rebate_id = next_id("fee-rebate", self.counters.next_fee_rebate);
        }
        require_non_empty("recipient_commitment", &rebate.recipient_commitment)?;
        require_non_empty("sponsor_commitment", &rebate.sponsor_commitment)?;
        require_positive("fee_paid_atomic_units", rebate.fee_paid_atomic_units)?;
        require(
            rebate.rebate_atomic_units <= rebate.fee_paid_atomic_units,
            "rebate cannot exceed fee paid",
        )?;
        self.consume_nullifier(&rebate.rebate_nullifier)?;
        let rebate_id = rebate.rebate_id.clone();
        self.counters.total_rebate_atomic_units = self
            .counters
            .total_rebate_atomic_units
            .saturating_add(rebate.rebate_atomic_units);
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.next_fee_rebate += 1;
        Ok(rebate_id)
    }

    pub fn install_redaction_budget(
        &mut self,
        mut budget: PrivacyRedactionBudget,
    ) -> Result<String> {
        require_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction budget capacity exceeded",
        )?;
        if budget.budget_id.is_empty() {
            budget.budget_id = next_id("redaction-budget", self.counters.next_redaction_budget);
        }
        require_non_empty("subject_id", &budget.subject_id)?;
        require(
            !budget.allowed_fields.is_empty(),
            "redaction budget has no allowed fields",
        )?;
        require(
            budget.allowed_fields.len() <= self.config.redaction_budget_fields as usize,
            "redaction budget exceeds configured field count",
        )?;
        require(
            budget.privacy_set_size >= self.config.min_privacy_set_size,
            "redaction budget privacy set below floor",
        )?;
        self.consume_nullifier(&budget.budget_nullifier)?;
        let budget_id = budget.budget_id.clone();
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.next_redaction_budget += 1;
        Ok(budget_id)
    }

    pub fn settle_batch_if_quorum_reached(&mut self, batch_id: &str) -> Result<()> {
        self.refresh_batch_quorum(batch_id)?;
        let batch = self
            .withdrawal_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown withdrawal batch".to_string())?;
        require(
            batch.status == BatchStatus::QuorumReached,
            "batch quorum not reached",
        )?;
        batch.status = BatchStatus::Settled;
        self.counters.accepted_batches += 1;
        Ok(())
    }

    pub fn refresh_expirations(&mut self) {
        for batch in self.withdrawal_batches.values_mut() {
            if batch.status.is_live() && self.height > batch.expires_height {
                batch.status = BatchStatus::Expired;
                self.counters.rejected_batches += 1;
            }
        }
        for challenge in self.challenge_windows.values_mut() {
            if challenge.status == ChallengeStatus::Open && self.height > challenge.expires_height {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        for rebate in self.fee_rebates.values_mut() {
            if matches!(
                rebate.status,
                RebateStatus::Pending | RebateStatus::Claimable
            ) && self.height > rebate.expires_height
            {
                rebate.status = RebateStatus::Expired;
            } else if rebate.status == RebateStatus::Pending
                && self.height >= rebate.claimable_height
            {
                rebate.status = RebateStatus::Claimable;
            }
        }
    }

    fn refresh_batch_quorum(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .withdrawal_batches
            .get(batch_id)
            .ok_or_else(|| "unknown withdrawal batch".to_string())?;
        let policy = self
            .quorum_policies
            .get(&batch.policy_id)
            .ok_or_else(|| "unknown policy".to_string())?;
        let attestation_ids = self
            .attestations_by_batch
            .get(batch_id)
            .cloned()
            .unwrap_or_default();
        let mut signer_count = 0_u16;
        let mut approved_weight = 0_u64;
        let mut distinct_signers = BTreeSet::new();
        for attestation_id in attestation_ids {
            if let Some(attestation) = self.quorum_attestations.get(&attestation_id) {
                if attestation.approves()
                    && distinct_signers.insert(attestation.signer_commitment.clone())
                {
                    signer_count += 1;
                    approved_weight = approved_weight.saturating_add(attestation.weight);
                }
            }
        }
        let reached = signer_count >= policy.min_signers && approved_weight >= policy.min_weight;
        if let Some(batch) = self.withdrawal_batches.get_mut(batch_id) {
            batch.status = if reached {
                BatchStatus::QuorumReached
            } else {
                BatchStatus::QuorumPending
            };
        }
        Ok(())
    }

    fn consume_nullifier(&mut self, value: &str) -> Result<()> {
        require_non_empty("nullifier", value)?;
        let nullifier = payload_id(
            "PRIVATE-L2-PQ-WITHDRAWAL-NULLIFIER",
            &[HashPart::Str(value)],
        );
        require(
            self.nullifier_index.insert(nullifier),
            "duplicate nullifier",
        )?;
        self.counters.consumed_nullifiers += 1;
        Ok(())
    }

    fn bump_operator_bond(&mut self, bond: &MlDsaSignerBond) {
        let summary = self
            .operator_summaries
            .entry(bond.operator_commitment.clone())
            .or_insert_with(|| OperatorSummary {
                operator_commitment: bond.operator_commitment.clone(),
                ..OperatorSummary::default()
            });
        summary.active_bonds += 1;
        summary.total_weight = summary.total_weight.saturating_add(bond.effective_weight);
        summary.locked_bond_atomic_units = summary
            .locked_bond_atomic_units
            .saturating_add(bond.locked_amount_atomic_units);
    }

    fn bump_operator_attestation(
        &mut self,
        bond: &MlDsaSignerBond,
        attestation: &QuorumAttestation,
    ) {
        let summary = self
            .operator_summaries
            .entry(bond.operator_commitment.clone())
            .or_insert_with(|| OperatorSummary {
                operator_commitment: bond.operator_commitment.clone(),
                ..OperatorSummary::default()
            });
        summary.attestation_count += 1;
        if attestation.approves() {
            summary.approved_weight = summary.approved_weight.saturating_add(attestation.weight);
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let policy = WithdrawalQuorumPolicy {
        policy_id: "devnet-withdrawal-policy-1".to_string(),
        lane: WithdrawalLane::LowFee,
        operator_set_root: payload_id("DEVNET-OPERATOR-SET", &[HashPart::Int(1)]),
        signer_registry_root: payload_id("DEVNET-SIGNER-REGISTRY", &[HashPart::Int(1)]),
        fee_policy_root: payload_id("DEVNET-FEE-POLICY", &[HashPart::Int(1)]),
        privacy_policy_root: payload_id("DEVNET-PRIVACY-POLICY", &[HashPart::Int(1)]),
        min_signers: DEFAULT_MIN_SIGNERS,
        min_weight: DEFAULT_MIN_WEIGHT,
        supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        max_user_fee_atomic_units: DEFAULT_MAX_USER_FEE_ATOMIC_UNITS,
        challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        reorg_guard_blocks: DEFAULT_REORG_GUARD_BLOCKS,
        status: PolicyStatus::Active,
        created_height: DEVNET_HEIGHT,
    };
    state.install_quorum_policy(policy).expect("devnet policy");

    for index in 0..DEFAULT_MIN_SIGNERS {
        let signer = format!("devnet-ml-dsa-signer-{}", index + 1);
        let transcript = payload_id("DEVNET-BOND-TRANSCRIPT", &[HashPart::Str(&signer)]);
        let bond = MlDsaSignerBond {
            bond_id: format!("devnet-bond-{}", index + 1),
            signer_commitment: signer.clone(),
            operator_commitment: format!("devnet-operator-{}", (index % 2) + 1),
            policy_id: "devnet-withdrawal-policy-1".to_string(),
            bond_commitment: payload_id("DEVNET-BOND-COMMITMENT", &[HashPart::Str(&signer)]),
            collateral_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            locked_amount_atomic_units: DEFAULT_MIN_BOND_ATOMIC_UNITS + (index as u64 * 10_000),
            effective_weight: 3,
            pq_authorization: PqAuthorization::devnet(&signer, &transcript),
            status: BondStatus::Active,
            locked_at_height: DEVNET_HEIGHT,
            cooldown_height: None,
        };
        state.lock_signer_bond(bond).expect("devnet bond");
    }

    let batch_root = payload_id("DEVNET-WITHDRAWAL-BATCH-ROOT", &[HashPart::Int(1)]);
    let batch = WithdrawalBatchCommitment {
        batch_id: "devnet-withdrawal-batch-1".to_string(),
        policy_id: "devnet-withdrawal-policy-1".to_string(),
        lane: WithdrawalLane::LowFee,
        withdrawal_note_root: payload_id("DEVNET-WITHDRAWAL-NOTES", &[HashPart::Int(1)]),
        destination_commitment_root: payload_id(
            "DEVNET-WITHDRAWAL-DESTINATIONS",
            &[HashPart::Int(1)],
        ),
        amount_commitment_root: payload_id("DEVNET-WITHDRAWAL-AMOUNTS", &[HashPart::Int(1)]),
        decoy_set_root: payload_id("DEVNET-WITHDRAWAL-DECOYS", &[HashPart::Int(1)]),
        nullifier_root: payload_id("DEVNET-WITHDRAWAL-NULLIFIERS", &[HashPart::Int(1)]),
        fee_quote_root: payload_id("DEVNET-WITHDRAWAL-FEE-QUOTE", &[HashPart::Int(1)]),
        batch_proof_root: batch_root.clone(),
        requested_fee_atomic_units: DEFAULT_MAX_USER_FEE_ATOMIC_UNITS / 2,
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        opened_height: DEVNET_HEIGHT,
        expires_height: DEVNET_HEIGHT + DEFAULT_BATCH_TTL_BLOCKS,
        status: BatchStatus::Open,
        attestation_ids: BTreeSet::new(),
    };
    state.submit_withdrawal_batch(batch).expect("devnet batch");

    for index in 0..DEFAULT_MIN_SIGNERS {
        let signer = format!("devnet-ml-dsa-signer-{}", index + 1);
        let statement = payload_id(
            "DEVNET-WITHDRAWAL-ATTESTATION-STATEMENT",
            &[HashPart::Str(&batch_root), HashPart::Str(&signer)],
        );
        let attestation = QuorumAttestation {
            attestation_id: format!("devnet-attestation-{}", index + 1),
            batch_id: "devnet-withdrawal-batch-1".to_string(),
            policy_id: "devnet-withdrawal-policy-1".to_string(),
            bond_id: format!("devnet-bond-{}", index + 1),
            signer_commitment: signer.clone(),
            verdict: AttestationVerdict::ApproveWithdrawal,
            statement_root: statement.clone(),
            fee_quote_root: payload_id("DEVNET-ATTESTATION-FEE", &[HashPart::Str(&signer)]),
            privacy_proof_root: payload_id("DEVNET-ATTESTATION-PRIVACY", &[HashPart::Str(&signer)]),
            reorg_guard_root: payload_id("DEVNET-ATTESTATION-REORG", &[HashPart::Str(&signer)]),
            weight: 3,
            pq_authorization: PqAuthorization::devnet(&signer, &statement),
            attested_height: DEVNET_HEIGHT + 1,
        };
        state
            .record_quorum_attestation(attestation)
            .expect("devnet attestation");
    }

    let rebate = FeeCreditRebate {
        rebate_id: "devnet-fee-rebate-1".to_string(),
        batch_id: "devnet-withdrawal-batch-1".to_string(),
        sponsor_commitment: "devnet-low-fee-sponsor".to_string(),
        recipient_commitment: "devnet-withdrawer-rebate-recipient".to_string(),
        fee_paid_atomic_units: DEFAULT_MAX_USER_FEE_ATOMIC_UNITS / 2,
        rebate_atomic_units: DEFAULT_MAX_USER_FEE_ATOMIC_UNITS / 10,
        rebate_nullifier: "devnet-rebate-nullifier-1".to_string(),
        claimable_height: DEVNET_HEIGHT + 2,
        expires_height: DEVNET_HEIGHT + 720,
        status: RebateStatus::Pending,
    };
    state
        .queue_fee_credit_rebate(rebate)
        .expect("devnet rebate");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
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

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| json!(payload_root(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("PRIVATE-L2-PQ-WITHDRAWAL-QUORUM-BOND-STATE", record)
}

fn map_root<T>(domain: &str, records: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = records
        .iter()
        .map(|(key, value)| json!({"id": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records
        .iter()
        .map(|record| json!(record))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn next_id(prefix: &str, sequence: u64) -> String {
    format!("{}-{:016}", prefix, sequence)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{} must not be empty", label),
    )
}

fn require_positive(label: &str, value: u64) -> Result<()> {
    require(value > 0, &format!("{} must be positive", label))
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(
        value <= MAX_BPS,
        &format!("{} exceeds basis point maximum", label),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{} is too short to be a root", label),
    )
}

fn require_capacity(current: usize, max: usize, message: &str) -> Result<()> {
    require(current < max, message)
}
