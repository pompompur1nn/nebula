use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub type PrivateOracleExecutionInsuranceResult<T> = Result<T, String>;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_ID: &str =
    "nebula-private-oracle-execution-insurance-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEVNET_HEIGHT: u64 = 1_728;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_POLICY_SEALING_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-shielded-oracle-execution-policy-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_CLAIM_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-encrypted-oracle-incident-claim-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_VAULT_SCHEME: &str =
    "confidential-oracle-execution-payout-vault-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_ATTESTATION_SCHEME: &str =
    "pq-oracle-committee-execution-attestation-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_THROTTLE_SCHEME: &str =
    "delayed-confidential-payout-throttle-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_CHALLENGE_SCHEME: &str =
    "encrypted-claim-challenge-evidence-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_SLASHING_HANDOFF_SCHEME: &str =
    "oracle-insurance-slashing-handoff-receipt-v1";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_FEE_ASSET_ID: &str = "asset:dxmr";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_POLICY_TTL_BLOCKS: u64 = 28_800;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_PAYOUT_DELAY_BLOCKS: u64 = 72;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SPONSOR_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_HANDOFF_TTL_BLOCKS: u64 = 240;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SUPERMAJORITY_BPS: u64 = 7_500;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MAX_POLICY_EXPOSURE_BPS: u64 = 1_250;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MAX_VAULT_UTILIZATION_BPS: u64 = 6_000;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_SOLVENCY_BPS: u64 = 11_500;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MAX_EPOCH_PAYOUT_BPS: u64 = 900;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_LOW_FEE_CAP_UNITS: u64 = 4;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 125_000;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CLAIM_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_REPORTER_REWARD_BPS: u64 = 1_000;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_VAULTS: usize = 16_384;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_POLICIES: usize = 262_144;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_COMMITTEE_MEMBERS: usize = 16_384;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_ATTESTATIONS: usize = 524_288;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_CLAIMS: usize = 262_144;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_SPONSORS: usize = 65_536;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_THROTTLES: usize = 262_144;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_HANDOFFS: usize = 131_072;
pub const PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_EVENTS: usize = 524_288;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleExecutionDomain {
    SpotPrice,
    PrivateTwap,
    PerpFunding,
    LendingIndex,
    StablecoinPeg,
    VaultShare,
    MoneroReserve,
    ProofFee,
    SequencerLatency,
    EmergencyFallback,
}
impl OracleExecutionDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpotPrice => "spot_price",
            Self::PrivateTwap => "private_twap",
            Self::PerpFunding => "perp_funding",
            Self::LendingIndex => "lending_index",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::VaultShare => "vault_share",
            Self::MoneroReserve => "monero_reserve",
            Self::ProofFee => "proof_fee",
            Self::SequencerLatency => "sequencer_latency",
            Self::EmergencyFallback => "emergency_fallback",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionFailureKind {
    MissingOracleUpdate,
    BadPriceOpening,
    StaleCommitteeAttestation,
    ThresholdNotMet,
    IncorrectTwapWindow,
    SequencerWithheldUpdate,
    BridgeReserveMismatch,
    SponsorCensorship,
    FeeSpikeExecutionMiss,
    EmergencyFallbackMisfire,
}
impl ExecutionFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingOracleUpdate => "missing_oracle_update",
            Self::BadPriceOpening => "bad_price_opening",
            Self::StaleCommitteeAttestation => "stale_committee_attestation",
            Self::ThresholdNotMet => "threshold_not_met",
            Self::IncorrectTwapWindow => "incorrect_twap_window",
            Self::SequencerWithheldUpdate => "sequencer_withheld_update",
            Self::BridgeReserveMismatch => "bridge_reserve_mismatch",
            Self::SponsorCensorship => "sponsor_censorship",
            Self::FeeSpikeExecutionMiss => "fee_spike_execution_miss",
            Self::EmergencyFallbackMisfire => "emergency_fallback_misfire",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutVaultStatus {
    Bootstrapping,
    Active,
    ExposureCapped,
    PayoutOnly,
    Frozen,
    Slashed,
    Retired,
}
impl PayoutVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::ExposureCapped => "exposure_capped",
            Self::PayoutOnly => "payout_only",
            Self::Frozen => "frozen",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
    pub fn can_underwrite(self) -> bool {
        matches!(
            self,
            Self::Bootstrapping | Self::Active | Self::ExposureCapped
        )
    }
    pub fn can_pay_claims(self) -> bool {
        matches!(self, Self::Active | Self::ExposureCapped | Self::PayoutOnly)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPolicyStatus {
    Quoted,
    Active,
    GracePeriod,
    ClaimPending,
    Settled,
    Expired,
    Cancelled,
    Challenged,
}
impl ExecutionPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::ClaimPending => "claim_pending",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod | Self::ClaimPending)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeMemberStatus {
    Active,
    Suspended,
    RotatingOut,
    Slashed,
    Retired,
}
impl CommitteeMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::RotatingOut => "rotating_out",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
    pub fn attesting(self) -> bool {
        matches!(self, Self::Active | Self::RotatingOut)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAttestationStatus {
    Submitted,
    RangeChecked,
    Counted,
    Superseded,
    Rejected,
    Expired,
    Challenged,
}
impl ExecutionAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::RangeChecked => "range_checked",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentClaimStatus {
    Queued,
    CommitteeReview,
    Challenged,
    Approved,
    PayoutScheduled,
    Paid,
    Rejected,
    Expired,
}
impl IncidentClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::CommitteeReview => "committee_review",
            Self::Challenged => "challenged",
            Self::Approved => "approved",
            Self::PayoutScheduled => "payout_scheduled",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::CommitteeReview
                | Self::Challenged
                | Self::Approved
                | Self::PayoutScheduled
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSponsorStatus {
    Active,
    Exhausted,
    Suspended,
    Retired,
}
impl ClaimSponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutThrottleStatus {
    Scheduled,
    CoolingDown,
    Releasable,
    Released,
    Cancelled,
    Challenged,
}
impl PayoutThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::CoolingDown => "cooling_down",
            Self::Releasable => "releasable",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimChallengeStatus {
    Open,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    SlashingQueued,
    Expired,
}
impl ClaimChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::SlashingQueued => "slashing_queued",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatus {
    Prepared,
    Delivered,
    Acknowledged,
    Challenged,
    Expired,
}
impl HandoffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceEventKind {
    VaultRegistered,
    PolicyIssued,
    CommitteeMemberRegistered,
    AttestationRecorded,
    ClaimQueued,
    SponsorDebited,
    PayoutScheduled,
    ChallengeFiled,
    HandoffPrepared,
    StateValidated,
}
impl InsuranceEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultRegistered => "vault_registered",
            Self::PolicyIssued => "policy_issued",
            Self::CommitteeMemberRegistered => "committee_member_registered",
            Self::AttestationRecorded => "attestation_recorded",
            Self::ClaimQueued => "claim_queued",
            Self::SponsorDebited => "sponsor_debited",
            Self::PayoutScheduled => "payout_scheduled",
            Self::ChallengeFiled => "challenge_filed",
            Self::HandoffPrepared => "handoff_prepared",
            Self::StateValidated => "state_validated",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleExecutionInsuranceConfig {
    pub epoch_blocks: u64,
    pub policy_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub payout_delay_blocks: u64,
    pub sponsor_window_blocks: u64,
    pub handoff_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub committee_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub max_policy_exposure_bps: u64,
    pub max_vault_utilization_bps: u64,
    pub min_solvency_bps: u64,
    pub max_epoch_payout_bps: u64,
    pub low_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub claim_slash_bps: u64,
    pub reporter_reward_bps: u64,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
    pub pq_kem_scheme: String,
    pub policy_sealing_scheme: String,
    pub claim_encryption_scheme: String,
    pub vault_scheme: String,
    pub attestation_scheme: String,
    pub throttle_scheme: String,
    pub challenge_scheme: String,
    pub slashing_handoff_scheme: String,
}
impl PrivateOracleExecutionInsuranceConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_EPOCH_BLOCKS,
            policy_ttl_blocks: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_POLICY_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_window_blocks: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CLAIM_WINDOW_BLOCKS,
            challenge_window_blocks:
                PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            payout_delay_blocks: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_PAYOUT_DELAY_BLOCKS,
            sponsor_window_blocks: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SPONSOR_WINDOW_BLOCKS,
            handoff_ttl_blocks: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_HANDOFF_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_quorum_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_COMMITTEE_QUORUM_BPS,
            supermajority_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SUPERMAJORITY_BPS,
            max_policy_exposure_bps:
                PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MAX_POLICY_EXPOSURE_BPS,
            max_vault_utilization_bps:
                PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MAX_VAULT_UTILIZATION_BPS,
            min_solvency_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_SOLVENCY_BPS,
            max_epoch_payout_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MAX_EPOCH_PAYOUT_BPS,
            low_fee_cap_units: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_LOW_FEE_CAP_UNITS,
            sponsor_budget_units: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SPONSOR_BUDGET_UNITS,
            claim_slash_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CLAIM_SLASH_BPS,
            reporter_reward_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_REPORTER_REWARD_BPS,
            fee_asset_id: PRIVATE_ORACLE_EXECUTION_INSURANCE_FEE_ASSET_ID.to_string(),
            monero_network: PRIVATE_ORACLE_EXECUTION_INSURANCE_MONERO_NETWORK.to_string(),
            hash_suite: PRIVATE_ORACLE_EXECUTION_INSURANCE_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_PQ_SIGNATURE_SCHEME.to_string(),
            pq_backup_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_PQ_BACKUP_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_PQ_KEM_SCHEME.to_string(),
            policy_sealing_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_POLICY_SEALING_SCHEME
                .to_string(),
            claim_encryption_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_CLAIM_ENCRYPTION_SCHEME
                .to_string(),
            vault_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_VAULT_SCHEME.to_string(),
            attestation_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_ATTESTATION_SCHEME.to_string(),
            throttle_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_THROTTLE_SCHEME.to_string(),
            challenge_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_CHALLENGE_SCHEME.to_string(),
            slashing_handoff_scheme: PRIVATE_ORACLE_EXECUTION_INSURANCE_SLASHING_HANDOFF_SCHEME
                .to_string(),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"chain_id": CHAIN_ID, "protocol_id": PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_ID, "protocol_version": PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_VERSION, "epoch_blocks": self.epoch_blocks, "policy_ttl_blocks": self.policy_ttl_blocks, "attestation_ttl_blocks": self.attestation_ttl_blocks, "claim_window_blocks": self.claim_window_blocks, "challenge_window_blocks": self.challenge_window_blocks, "payout_delay_blocks": self.payout_delay_blocks, "sponsor_window_blocks": self.sponsor_window_blocks, "handoff_ttl_blocks": self.handoff_ttl_blocks, "min_privacy_set_size": self.min_privacy_set_size, "min_pq_security_bits": self.min_pq_security_bits, "committee_quorum_bps": self.committee_quorum_bps, "supermajority_bps": self.supermajority_bps, "max_policy_exposure_bps": self.max_policy_exposure_bps, "max_vault_utilization_bps": self.max_vault_utilization_bps, "min_solvency_bps": self.min_solvency_bps, "max_epoch_payout_bps": self.max_epoch_payout_bps, "low_fee_cap_units": self.low_fee_cap_units, "sponsor_budget_units": self.sponsor_budget_units, "claim_slash_bps": self.claim_slash_bps, "reporter_reward_bps": self.reporter_reward_bps, "fee_asset_id": self.fee_asset_id, "monero_network": self.monero_network, "hash_suite": self.hash_suite, "pq_signature_scheme": self.pq_signature_scheme, "pq_backup_scheme": self.pq_backup_scheme, "pq_kem_scheme": self.pq_kem_scheme, "policy_sealing_scheme": self.policy_sealing_scheme, "claim_encryption_scheme": self.claim_encryption_scheme, "vault_scheme": self.vault_scheme, "attestation_scheme": self.attestation_scheme, "throttle_scheme": self.throttle_scheme, "challenge_scheme": self.challenge_scheme, "slashing_handoff_scheme": self.slashing_handoff_scheme})
    }
    pub fn config_root(&self) -> String {
        oracle_execution_insurance_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        if self.epoch_blocks == 0
            || self.policy_ttl_blocks == 0
            || self.attestation_ttl_blocks == 0
            || self.claim_window_blocks == 0
            || self.challenge_window_blocks == 0
            || self.payout_delay_blocks == 0
            || self.sponsor_window_blocks == 0
            || self.handoff_ttl_blocks == 0
        {
            return Err("oracle execution insurance windows must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 || self.min_pq_security_bits < 128 {
            return Err("oracle execution insurance privacy and pq floors are too low".to_string());
        }
        if self.committee_quorum_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.supermajority_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.max_policy_exposure_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.max_vault_utilization_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.max_epoch_payout_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.claim_slash_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.reporter_reward_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
        {
            return Err("oracle execution insurance bps value exceeds max".to_string());
        }
        if self.committee_quorum_bps > self.supermajority_bps {
            return Err("oracle execution insurance quorum exceeds supermajority".to_string());
        }
        if self.min_solvency_bps < PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS {
            return Err(
                "oracle execution insurance solvency floor must exceed full coverage".to_string(),
            );
        }
        for (field, value) in [
            ("fee_asset_id", self.fee_asset_id.as_str()),
            ("monero_network", self.monero_network.as_str()),
            ("hash_suite", self.hash_suite.as_str()),
            ("pq_signature_scheme", self.pq_signature_scheme.as_str()),
            ("pq_backup_scheme", self.pq_backup_scheme.as_str()),
            ("pq_kem_scheme", self.pq_kem_scheme.as_str()),
            ("policy_sealing_scheme", self.policy_sealing_scheme.as_str()),
            (
                "claim_encryption_scheme",
                self.claim_encryption_scheme.as_str(),
            ),
            ("vault_scheme", self.vault_scheme.as_str()),
            ("attestation_scheme", self.attestation_scheme.as_str()),
            ("throttle_scheme", self.throttle_scheme.as_str()),
            ("challenge_scheme", self.challenge_scheme.as_str()),
            (
                "slashing_handoff_scheme",
                self.slashing_handoff_scheme.as_str(),
            ),
        ] {
            ensure_non_empty(field, value)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPayoutVault {
    pub vault_id: String,
    pub operator_commitment: String,
    pub reserve_commitment: String,
    pub payout_asset_id: String,
    pub total_capacity_units: u64,
    pub active_exposure_units: u64,
    pub reserved_claim_units: u64,
    pub released_payout_units: u64,
    pub solvency_bps: u64,
    pub privacy_set_size: u64,
    pub status: PayoutVaultStatus,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}
impl ConfidentialPayoutVault {
    pub fn available_capacity_units(&self) -> u64 {
        self.total_capacity_units
            .saturating_sub(self.active_exposure_units)
            .saturating_sub(self.reserved_claim_units)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "operator_commitment": self.operator_commitment,
            "reserve_commitment": self.reserve_commitment,
            "payout_asset_id": self.payout_asset_id,
            "total_capacity_units": self.total_capacity_units,
            "active_exposure_units": self.active_exposure_units,
            "reserved_claim_units": self.reserved_claim_units,
            "released_payout_units": self.released_payout_units,
            "solvency_bps": self.solvency_bps,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("vault_id", &self.vault_id)?;
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        ensure_non_empty("reserve_commitment", &self.reserve_commitment)?;
        ensure_non_empty("payout_asset_id", &self.payout_asset_id)?;
        if self.total_capacity_units == 0 || self.privacy_set_size == 0 {
            return Err(format!(
                "vault {} capacity and privacy set must be positive",
                self.vault_id
            ));
        }
        if self
            .active_exposure_units
            .saturating_add(self.reserved_claim_units)
            > self.total_capacity_units
        {
            return Err(format!("vault {} exceeds capacity", self.vault_id));
        }
        if self.updated_at_height < self.created_at_height {
            return Err(format!(
                "vault {} update height precedes creation",
                self.vault_id
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedOracleExecutionPolicy {
    pub policy_id: String,
    pub vault_id: String,
    pub owner_commitment: String,
    pub market_id: String,
    pub domain: OracleExecutionDomain,
    pub failure_kind: ExecutionFailureKind,
    pub sealed_terms_root: String,
    pub premium_nullifier: String,
    pub coverage_units: u64,
    pub premium_units: u64,
    pub deductible_units: u64,
    pub max_latency_blocks: u64,
    pub min_committee_weight_bps: u64,
    pub privacy_set_size: u64,
    pub status: ExecutionPolicyStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
}
impl ShieldedOracleExecutionPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "market_id": self.market_id,
            "domain": self.domain,
            "failure_kind": self.failure_kind,
            "sealed_terms_root": self.sealed_terms_root,
            "premium_nullifier": self.premium_nullifier,
            "coverage_units": self.coverage_units,
            "premium_units": self.premium_units,
            "deductible_units": self.deductible_units,
            "max_latency_blocks": self.max_latency_blocks,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("policy_id", &self.policy_id)?;
        ensure_non_empty("vault_id", &self.vault_id)?;
        ensure_non_empty("owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("sealed_terms_root", &self.sealed_terms_root)?;
        ensure_non_empty("premium_nullifier", &self.premium_nullifier)?;
        if self.coverage_units == 0 || self.premium_units == 0 || self.max_latency_blocks == 0 {
            return Err(format!(
                "policy {} positive units and latency required",
                self.policy_id
            ));
        }
        if self.deductible_units > self.coverage_units {
            return Err(format!(
                "policy {} deductible exceeds coverage",
                self.policy_id
            ));
        }
        if self.min_committee_weight_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS {
            return Err(format!(
                "policy {} committee weight exceeds max",
                self.policy_id
            ));
        }
        if self.issued_at_height >= self.expires_at_height
            || self.updated_at_height < self.issued_at_height
        {
            return Err(format!("policy {} has invalid heights", self.policy_id));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOracleCommitteeMember {
    pub member_id: String,
    pub committee_id: String,
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub backup_public_key_root: String,
    pub kem_public_key_root: String,
    pub weight_bps: u64,
    pub bond_units: u64,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub status: CommitteeMemberStatus,
    pub joined_at_height: u64,
    pub updated_at_height: u64,
}
impl PqOracleCommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "backup_public_key_root": self.backup_public_key_root,
            "kem_public_key_root": self.kem_public_key_root,
            "weight_bps": self.weight_bps,
            "bond_units": self.bond_units,
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "joined_at_height": self.joined_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("member_id", &self.member_id)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("backup_public_key_root", &self.backup_public_key_root)?;
        ensure_non_empty("kem_public_key_root", &self.kem_public_key_root)?;
        if self.weight_bps == 0 || self.weight_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS {
            return Err(format!("member {} invalid weight", self.member_id));
        }
        if self.bond_units == 0 || self.security_bits < 128 || self.privacy_set_size == 0 {
            return Err(format!(
                "member {} bond, security, and privacy set required",
                self.member_id
            ));
        }
        if self.updated_at_height < self.joined_at_height {
            return Err(format!(
                "member {} update height precedes join",
                self.member_id
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOracleExecutionAttestation {
    pub attestation_id: String,
    pub policy_id: String,
    pub market_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub incident_claim_id: Option<String>,
    pub execution_root: String,
    pub encrypted_observation_root: String,
    pub pq_signature_root: String,
    pub observed_height: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub committee_weight_bps: u64,
    pub status: ExecutionAttestationStatus,
}
impl PqOracleExecutionAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "policy_id": self.policy_id,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "incident_claim_id": self.incident_claim_id,
            "execution_root": self.execution_root,
            "encrypted_observation_root": self.encrypted_observation_root,
            "pq_signature_root": self.pq_signature_root,
            "observed_height": self.observed_height,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "committee_weight_bps": self.committee_weight_bps,
            "status": self.status,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("attestation_id", &self.attestation_id)?;
        ensure_non_empty("policy_id", &self.policy_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("member_id", &self.member_id)?;
        ensure_non_empty("execution_root", &self.execution_root)?;
        ensure_non_empty(
            "encrypted_observation_root",
            &self.encrypted_observation_root,
        )?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        if self.submitted_at_height > self.expires_at_height {
            return Err(format!(
                "attestation {} expires before submission",
                self.attestation_id
            ));
        }
        if self.committee_weight_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS {
            return Err(format!(
                "attestation {} weight exceeds max",
                self.attestation_id
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIncidentClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub claimant_commitment: String,
    pub claim_ciphertext_root: String,
    pub incident_evidence_root: String,
    pub payout_address_commitment: String,
    pub sponsor_id: Option<String>,
    pub requested_payout_units: u64,
    pub approved_payout_units: u64,
    pub claim_nullifier: String,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub expires_at_height: u64,
    pub status: IncidentClaimStatus,
}
impl EncryptedIncidentClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "claimant_commitment": self.claimant_commitment,
            "claim_ciphertext_root": self.claim_ciphertext_root,
            "incident_evidence_root": self.incident_evidence_root,
            "payout_address_commitment": self.payout_address_commitment,
            "sponsor_id": self.sponsor_id,
            "requested_payout_units": self.requested_payout_units,
            "approved_payout_units": self.approved_payout_units,
            "claim_nullifier": self.claim_nullifier,
            "opened_at_height": self.opened_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("claim_id", &self.claim_id)?;
        ensure_non_empty("policy_id", &self.policy_id)?;
        ensure_non_empty("vault_id", &self.vault_id)?;
        ensure_non_empty("claimant_commitment", &self.claimant_commitment)?;
        ensure_non_empty("claim_ciphertext_root", &self.claim_ciphertext_root)?;
        ensure_non_empty("incident_evidence_root", &self.incident_evidence_root)?;
        ensure_non_empty("payout_address_commitment", &self.payout_address_commitment)?;
        ensure_non_empty("claim_nullifier", &self.claim_nullifier)?;
        if self.requested_payout_units == 0 {
            return Err(format!(
                "claim {} requested payout must be positive",
                self.claim_id
            ));
        }
        if self.approved_payout_units > self.requested_payout_units {
            return Err(format!("claim {} approval exceeds request", self.claim_id));
        }
        if self.opened_at_height > self.challenge_deadline_height
            || self.challenge_deadline_height > self.expires_at_height
        {
            return Err(format!("claim {} has invalid deadlines", self.claim_id));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeClaimSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub fee_cap_units: u64,
    pub sponsored_claims: u64,
    pub privacy_set_size: u64,
    pub status: ClaimSponsorStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
}
impl LowFeeClaimSponsor {
    pub fn remaining_budget_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "fee_cap_units": self.fee_cap_units,
            "sponsored_claims": self.sponsored_claims,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.budget_units == 0 || self.fee_cap_units == 0 || self.privacy_set_size == 0 {
            return Err(format!(
                "sponsor {} budget, cap, and privacy set must be positive",
                self.sponsor_id
            ));
        }
        if self.spent_units > self.budget_units {
            return Err(format!("sponsor {} overspent", self.sponsor_id));
        }
        if self.window_start_height >= self.window_end_height {
            return Err(format!("sponsor {} has invalid window", self.sponsor_id));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedPayoutThrottle {
    pub throttle_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub payout_commitment: String,
    pub payout_units: u64,
    pub epoch_index: u64,
    pub scheduled_at_height: u64,
    pub release_after_height: u64,
    pub released_at_height: Option<u64>,
    pub status: PayoutThrottleStatus,
}
impl DelayedPayoutThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "throttle_id": self.throttle_id,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "payout_commitment": self.payout_commitment,
            "payout_units": self.payout_units,
            "epoch_index": self.epoch_index,
            "scheduled_at_height": self.scheduled_at_height,
            "release_after_height": self.release_after_height,
            "released_at_height": self.released_at_height,
            "status": self.status,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("throttle_id", &self.throttle_id)?;
        ensure_non_empty("claim_id", &self.claim_id)?;
        ensure_non_empty("policy_id", &self.policy_id)?;
        ensure_non_empty("vault_id", &self.vault_id)?;
        ensure_non_empty("payout_commitment", &self.payout_commitment)?;
        if self.payout_units == 0 {
            return Err(format!(
                "throttle {} payout must be positive",
                self.throttle_id
            ));
        }
        if self.scheduled_at_height > self.release_after_height {
            return Err(format!(
                "throttle {} release precedes schedule",
                self.throttle_id
            ));
        }
        if let Some(released_at_height) = self.released_at_height {
            if released_at_height < self.release_after_height {
                return Err(format!(
                    "throttle {} released before delay",
                    self.throttle_id
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimChallengeEvidence {
    pub challenge_id: String,
    pub claim_id: String,
    pub challenger_commitment: String,
    pub accused_member_id: Option<String>,
    pub evidence_ciphertext_root: String,
    pub evidence_merkle_root: String,
    pub bond_nullifier: String,
    pub slash_bps: u64,
    pub reporter_reward_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ClaimChallengeStatus,
}
impl ClaimChallengeEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "challenger_commitment": self.challenger_commitment,
            "accused_member_id": self.accused_member_id,
            "evidence_ciphertext_root": self.evidence_ciphertext_root,
            "evidence_merkle_root": self.evidence_merkle_root,
            "bond_nullifier": self.bond_nullifier,
            "slash_bps": self.slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("challenge_id", &self.challenge_id)?;
        ensure_non_empty("claim_id", &self.claim_id)?;
        ensure_non_empty("challenger_commitment", &self.challenger_commitment)?;
        ensure_non_empty("evidence_ciphertext_root", &self.evidence_ciphertext_root)?;
        ensure_non_empty("evidence_merkle_root", &self.evidence_merkle_root)?;
        ensure_non_empty("bond_nullifier", &self.bond_nullifier)?;
        if self.slash_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
            || self.reporter_reward_bps > PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
        {
            return Err(format!("challenge {} bps exceeds max", self.challenge_id));
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err(format!(
                "challenge {} has invalid window",
                self.challenge_id
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingHandoffReceipt {
    pub handoff_id: String,
    pub challenge_id: String,
    pub claim_id: String,
    pub target_member_id: String,
    pub destination_module: String,
    pub slashing_evidence_root: String,
    pub handoff_receipt_root: String,
    pub slash_units: u64,
    pub reporter_reward_units: u64,
    pub prepared_at_height: u64,
    pub expires_at_height: u64,
    pub status: HandoffStatus,
}
impl SlashingHandoffReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "handoff_id": self.handoff_id,
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "target_member_id": self.target_member_id,
            "destination_module": self.destination_module,
            "slashing_evidence_root": self.slashing_evidence_root,
            "handoff_receipt_root": self.handoff_receipt_root,
            "slash_units": self.slash_units,
            "reporter_reward_units": self.reporter_reward_units,
            "prepared_at_height": self.prepared_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("handoff_id", &self.handoff_id)?;
        ensure_non_empty("challenge_id", &self.challenge_id)?;
        ensure_non_empty("claim_id", &self.claim_id)?;
        ensure_non_empty("target_member_id", &self.target_member_id)?;
        ensure_non_empty("destination_module", &self.destination_module)?;
        ensure_non_empty("slashing_evidence_root", &self.slashing_evidence_root)?;
        ensure_non_empty("handoff_receipt_root", &self.handoff_receipt_root)?;
        if self.slash_units == 0 {
            return Err(format!(
                "handoff {} slash units must be positive",
                self.handoff_id
            ));
        }
        if self.prepared_at_height >= self.expires_at_height {
            return Err(format!("handoff {} has invalid ttl", self.handoff_id));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleExecutionInsuranceEvent {
    pub event_id: String,
    pub event_kind: InsuranceEventKind,
    pub subject_id: String,
    pub state_root_after: String,
    pub payload_root: String,
    pub height: u64,
}
impl OracleExecutionInsuranceEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "state_root_after": self.state_root_after,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_non_empty("event_id", &self.event_id)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("state_root_after", &self.state_root_after)?;
        ensure_non_empty("payload_root", &self.payload_root)?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleExecutionInsuranceRoots {
    pub config_root: String,
    pub vault_root: String,
    pub policy_root: String,
    pub committee_member_root: String,
    pub attestation_root: String,
    pub claim_root: String,
    pub sponsor_root: String,
    pub payout_throttle_root: String,
    pub challenge_root: String,
    pub handoff_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub state_root: String,
}
impl PrivateOracleExecutionInsuranceRoots {
    pub fn public_record(&self) -> Value {
        json!({"chain_id": CHAIN_ID, "config_root": self.config_root, "vault_root": self.vault_root, "policy_root": self.policy_root, "committee_member_root": self.committee_member_root, "attestation_root": self.attestation_root, "claim_root": self.claim_root, "sponsor_root": self.sponsor_root, "payout_throttle_root": self.payout_throttle_root, "challenge_root": self.challenge_root, "handoff_root": self.handoff_root, "nullifier_root": self.nullifier_root, "event_root": self.event_root, "state_root": self.state_root})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleExecutionInsuranceCounters {
    pub height: u64,
    pub vaults: usize,
    pub policies: usize,
    pub active_policies: usize,
    pub committee_members: usize,
    pub active_committee_members: usize,
    pub attestations: usize,
    pub counted_attestations: usize,
    pub claims: usize,
    pub open_claims: usize,
    pub sponsors: usize,
    pub active_sponsors: usize,
    pub payout_throttles: usize,
    pub pending_payout_throttles: usize,
    pub challenges: usize,
    pub open_challenges: usize,
    pub handoffs: usize,
    pub nullifiers: usize,
    pub events: usize,
    pub total_capacity_units: u64,
    pub active_exposure_units: u64,
    pub reserved_claim_units: u64,
    pub released_payout_units: u64,
    pub sponsor_budget_units: u64,
    pub sponsor_spent_units: u64,
}
impl PrivateOracleExecutionInsuranceCounters {
    pub fn public_record(&self) -> Value {
        json!({"chain_id": CHAIN_ID, "height": self.height, "vaults": self.vaults, "policies": self.policies, "active_policies": self.active_policies, "committee_members": self.committee_members, "active_committee_members": self.active_committee_members, "attestations": self.attestations, "counted_attestations": self.counted_attestations, "claims": self.claims, "open_claims": self.open_claims, "sponsors": self.sponsors, "active_sponsors": self.active_sponsors, "payout_throttles": self.payout_throttles, "pending_payout_throttles": self.pending_payout_throttles, "challenges": self.challenges, "open_challenges": self.open_challenges, "handoffs": self.handoffs, "nullifiers": self.nullifiers, "events": self.events, "total_capacity_units": self.total_capacity_units, "active_exposure_units": self.active_exposure_units, "reserved_claim_units": self.reserved_claim_units, "released_payout_units": self.released_payout_units, "sponsor_budget_units": self.sponsor_budget_units, "sponsor_spent_units": self.sponsor_spent_units})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOracleExecutionInsuranceState {
    pub height: u64,
    pub config: PrivateOracleExecutionInsuranceConfig,
    pub vaults: BTreeMap<String, ConfidentialPayoutVault>,
    pub policies: BTreeMap<String, ShieldedOracleExecutionPolicy>,
    pub committee_members: BTreeMap<String, PqOracleCommitteeMember>,
    pub attestations: BTreeMap<String, PqOracleExecutionAttestation>,
    pub claims: BTreeMap<String, EncryptedIncidentClaim>,
    pub sponsors: BTreeMap<String, LowFeeClaimSponsor>,
    pub payout_throttles: BTreeMap<String, DelayedPayoutThrottle>,
    pub challenges: BTreeMap<String, ClaimChallengeEvidence>,
    pub handoffs: BTreeMap<String, SlashingHandoffReceipt>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, OracleExecutionInsuranceEvent>,
}
impl PrivateOracleExecutionInsuranceState {
    pub fn new(
        config: PrivateOracleExecutionInsuranceConfig,
        height: u64,
    ) -> PrivateOracleExecutionInsuranceResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            config,
            vaults: BTreeMap::new(),
            policies: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            attestations: BTreeMap::new(),
            claims: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            payout_throttles: BTreeMap::new(),
            challenges: BTreeMap::new(),
            handoffs: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        })
    }
    pub fn devnet() -> PrivateOracleExecutionInsuranceResult<Self> {
        let mut state = Self::new(
            PrivateOracleExecutionInsuranceConfig::devnet(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_DEVNET_HEIGHT,
        )?;
        for index in 0..4_u64 {
            state.register_vault(make_devnet_vault(index, state.height))?;
        }
        for index in 0..8_u64 {
            state.register_committee_member(make_devnet_member(index, state.height))?;
        }
        state.register_sponsor(make_devnet_sponsor(
            0,
            state.height,
            state.config.sponsor_window_blocks,
        ))?;
        for index in 0..12_u64 {
            state.issue_policy(make_devnet_policy(
                index,
                state.height,
                state.config.policy_ttl_blocks,
            ))?;
        }
        for index in 0..12_u64 {
            state.record_attestation(make_devnet_attestation(
                index,
                state.height,
                state.config.attestation_ttl_blocks,
            ))?;
        }
        for index in 0..5_u64 {
            state.queue_claim(make_devnet_claim(
                index,
                state.height,
                state.config.claim_window_blocks,
                state.config.challenge_window_blocks,
            ))?;
        }
        for index in 0..3_u64 {
            state.schedule_payout(make_devnet_throttle(
                index,
                state.height,
                state.config.payout_delay_blocks,
            ))?;
        }
        state.file_challenge(make_devnet_challenge(
            0,
            state.height,
            state.config.challenge_window_blocks,
        ))?;
        state.prepare_handoff(make_devnet_handoff(
            0,
            state.height,
            state.config.handoff_ttl_blocks,
        ))?;
        state.validate()?;
        Ok(state)
    }
    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        if next_height < self.height {
            return Err(format!(
                "height regression from {} to {}",
                self.height, next_height
            ));
        }
        self.height = next_height;
        self.expire_stale_records();
        self.record_event(
            InsuranceEventKind::StateValidated,
            "height",
            &json!({"height": next_height}),
        )?;
        Ok(self.state_root())
    }
    pub fn validate(&self) -> PrivateOracleExecutionInsuranceResult<()> {
        self.config.validate()?;
        ensure_capacity(
            "vault",
            self.vaults.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_VAULTS,
        )?;
        ensure_capacity(
            "policy",
            self.policies.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_POLICIES,
        )?;
        ensure_capacity(
            "member",
            self.committee_members.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_COMMITTEE_MEMBERS,
        )?;
        ensure_capacity(
            "attestation",
            self.attestations.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_ATTESTATIONS,
        )?;
        ensure_capacity(
            "claim",
            self.claims.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_CLAIMS,
        )?;
        ensure_capacity(
            "sponsor",
            self.sponsors.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_SPONSORS,
        )?;
        ensure_capacity(
            "throttle",
            self.payout_throttles.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_THROTTLES,
        )?;
        ensure_capacity(
            "challenge",
            self.challenges.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_CHALLENGES,
        )?;
        ensure_capacity(
            "handoff",
            self.handoffs.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_HANDOFFS,
        )?;
        ensure_capacity(
            "event",
            self.events.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_EVENTS,
        )?;
        for vault in self.vaults.values() {
            vault.validate()?;
            if vault.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!("vault {} privacy set below floor", vault.vault_id));
            }
        }
        for policy in self.policies.values() {
            policy.validate()?;
            if !self.vaults.contains_key(&policy.vault_id) {
                return Err(format!("policy {} missing vault", policy.policy_id));
            }
        }
        for member in self.committee_members.values() {
            member.validate()?;
            if member.security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "member {} pq security below floor",
                    member.member_id
                ));
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.policies.contains_key(&attestation.policy_id) {
                return Err(format!(
                    "attestation {} missing policy",
                    attestation.attestation_id
                ));
            }
            if !self.committee_members.contains_key(&attestation.member_id) {
                return Err(format!(
                    "attestation {} missing member",
                    attestation.attestation_id
                ));
            }
        }
        for claim in self.claims.values() {
            claim.validate()?;
            if !self.policies.contains_key(&claim.policy_id)
                || !self.vaults.contains_key(&claim.vault_id)
            {
                return Err(format!(
                    "claim {} references missing policy or vault",
                    claim.claim_id
                ));
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for throttle in self.payout_throttles.values() {
            throttle.validate()?;
            if !self.claims.contains_key(&throttle.claim_id) {
                return Err(format!("throttle {} missing claim", throttle.throttle_id));
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.claims.contains_key(&challenge.claim_id) {
                return Err(format!(
                    "challenge {} missing claim",
                    challenge.challenge_id
                ));
            }
        }
        for handoff in self.handoffs.values() {
            handoff.validate()?;
            if !self.challenges.contains_key(&handoff.challenge_id) {
                return Err(format!("handoff {} missing challenge", handoff.handoff_id));
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }
    pub fn register_vault(
        &mut self,
        mut vault: ConfidentialPayoutVault,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "vault",
            self.vaults.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_VAULTS,
        )?;
        vault.updated_at_height = self.height.max(vault.updated_at_height);
        vault.validate()?;
        if vault.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!("vault {} privacy set below floor", vault.vault_id));
        }
        if vault.solvency_bps < self.config.min_solvency_bps && vault.status.can_underwrite() {
            return Err(format!("vault {} below solvency floor", vault.vault_id));
        }
        if self.vaults.contains_key(&vault.vault_id) {
            return Err(format!("vault {} already exists", vault.vault_id));
        }
        let id = vault.vault_id.clone();
        self.vaults.insert(id.clone(), vault);
        self.record_event(
            InsuranceEventKind::VaultRegistered,
            &id,
            &json!({"vault_id": id}),
        )?;
        Ok(id)
    }
    pub fn issue_policy(
        &mut self,
        mut policy: ShieldedOracleExecutionPolicy,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "policy",
            self.policies.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_POLICIES,
        )?;
        policy.updated_at_height = self.height.max(policy.updated_at_height);
        policy.validate()?;
        if policy
            .expires_at_height
            .saturating_sub(policy.issued_at_height)
            > self.config.policy_ttl_blocks
        {
            return Err(format!("policy {} exceeds ttl", policy.policy_id));
        }
        if policy.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "policy {} privacy set below floor",
                policy.policy_id
            ));
        }
        if self.spent_nullifiers.contains(&policy.premium_nullifier) {
            return Err(format!(
                "premium nullifier {} already spent",
                policy.premium_nullifier
            ));
        }
        let vault = self
            .vaults
            .get(&policy.vault_id)
            .ok_or_else(|| format!("missing vault {}", policy.vault_id))?;
        if !vault.status.can_underwrite() {
            return Err(format!("vault {} cannot underwrite", policy.vault_id));
        }
        let max_policy_units = bps_mul(
            vault.total_capacity_units,
            self.config.max_policy_exposure_bps,
        );
        if policy.coverage_units > max_policy_units
            || policy.coverage_units > vault.available_capacity_units()
        {
            return Err(format!(
                "policy {} exceeds vault capacity",
                policy.policy_id
            ));
        }
        let id = policy.policy_id.clone();
        self.spent_nullifiers
            .insert(policy.premium_nullifier.clone());
        self.policies.insert(id.clone(), policy);
        self.recompute_vault_exposure_for_policy(&id)?;
        self.record_event(
            InsuranceEventKind::PolicyIssued,
            &id,
            &json!({"policy_id": id}),
        )?;
        Ok(id)
    }
    pub fn register_committee_member(
        &mut self,
        member: PqOracleCommitteeMember,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "member",
            self.committee_members.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_COMMITTEE_MEMBERS,
        )?;
        member.validate()?;
        if member.security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "member {} pq security below floor",
                member.member_id
            ));
        }
        if member.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "member {} privacy set below floor",
                member.member_id
            ));
        }
        if self.committee_members.contains_key(&member.member_id) {
            return Err(format!("member {} already exists", member.member_id));
        }
        let id = member.member_id.clone();
        self.committee_members.insert(id.clone(), member);
        self.record_event(
            InsuranceEventKind::CommitteeMemberRegistered,
            &id,
            &json!({"member_id": id}),
        )?;
        Ok(id)
    }
    pub fn record_attestation(
        &mut self,
        attestation: PqOracleExecutionAttestation,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "attestation",
            self.attestations.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_ATTESTATIONS,
        )?;
        attestation.validate()?;
        let policy = self
            .policies
            .get(&attestation.policy_id)
            .ok_or_else(|| format!("missing policy {}", attestation.policy_id))?;
        let member = self
            .committee_members
            .get(&attestation.member_id)
            .ok_or_else(|| format!("missing member {}", attestation.member_id))?;
        if !member.status.attesting() {
            return Err(format!("member {} cannot attest", attestation.member_id));
        }
        if policy.market_id != attestation.market_id {
            return Err(format!(
                "attestation {} market mismatch",
                attestation.attestation_id
            ));
        }
        if attestation
            .expires_at_height
            .saturating_sub(attestation.submitted_at_height)
            > self.config.attestation_ttl_blocks
        {
            return Err(format!(
                "attestation {} exceeds ttl",
                attestation.attestation_id
            ));
        }
        let id = attestation.attestation_id.clone();
        self.attestations.insert(id.clone(), attestation);
        self.record_event(
            InsuranceEventKind::AttestationRecorded,
            &id,
            &json!({"attestation_id": id}),
        )?;
        Ok(id)
    }
    pub fn queue_claim(
        &mut self,
        mut claim: EncryptedIncidentClaim,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "claim",
            self.claims.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_CLAIMS,
        )?;
        claim.validate()?;
        if self.spent_nullifiers.contains(&claim.claim_nullifier) {
            return Err(format!(
                "claim nullifier {} already spent",
                claim.claim_nullifier
            ));
        }
        let policy = self
            .policies
            .get(&claim.policy_id)
            .ok_or_else(|| format!("missing policy {}", claim.policy_id))?;
        if !policy.status.accepts_claims() {
            return Err(format!("policy {} does not accept claims", claim.policy_id));
        }
        if policy.vault_id != claim.vault_id {
            return Err(format!("claim {} vault mismatch", claim.claim_id));
        }
        if claim.requested_payout_units
            > policy
                .coverage_units
                .saturating_sub(policy.deductible_units)
        {
            return Err(format!("claim {} exceeds policy coverage", claim.claim_id));
        }
        if let Some(sponsor_id) = claim.sponsor_id.clone() {
            self.debit_sponsor(&sponsor_id, self.config.low_fee_cap_units)?;
        }
        claim.approved_payout_units = claim
            .approved_payout_units
            .min(claim.requested_payout_units);
        let id = claim.claim_id.clone();
        self.spent_nullifiers.insert(claim.claim_nullifier.clone());
        self.claims.insert(id.clone(), claim);
        self.reserve_claim_capacity(&id)?;
        self.record_event(
            InsuranceEventKind::ClaimQueued,
            &id,
            &json!({"claim_id": id}),
        )?;
        Ok(id)
    }
    pub fn register_sponsor(
        &mut self,
        sponsor: LowFeeClaimSponsor,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "sponsor",
            self.sponsors.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_SPONSORS,
        )?;
        sponsor.validate()?;
        if sponsor.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "sponsor {} privacy set below floor",
                sponsor.sponsor_id
            ));
        }
        if self.sponsors.contains_key(&sponsor.sponsor_id) {
            return Err(format!("sponsor {} already exists", sponsor.sponsor_id));
        }
        let id = sponsor.sponsor_id.clone();
        self.sponsors.insert(id.clone(), sponsor);
        Ok(id)
    }
    pub fn schedule_payout(
        &mut self,
        throttle: DelayedPayoutThrottle,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "throttle",
            self.payout_throttles.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_THROTTLES,
        )?;
        throttle.validate()?;
        let claim = self
            .claims
            .get(&throttle.claim_id)
            .ok_or_else(|| format!("missing claim {}", throttle.claim_id))?;
        let vault = self
            .vaults
            .get(&throttle.vault_id)
            .ok_or_else(|| format!("missing vault {}", throttle.vault_id))?;
        if !vault.status.can_pay_claims() {
            return Err(format!("vault {} cannot pay claims", throttle.vault_id));
        }
        if claim.policy_id != throttle.policy_id || claim.vault_id != throttle.vault_id {
            return Err(format!(
                "throttle {} claim linkage mismatch",
                throttle.throttle_id
            ));
        }
        if throttle
            .release_after_height
            .saturating_sub(throttle.scheduled_at_height)
            < self.config.payout_delay_blocks
        {
            return Err(format!(
                "throttle {} delay below floor",
                throttle.throttle_id
            ));
        }
        let epoch_payout = self
            .epoch_payout_units(throttle.epoch_index)
            .saturating_add(throttle.payout_units);
        let max_epoch = bps_mul(vault.total_capacity_units, self.config.max_epoch_payout_bps);
        if epoch_payout > max_epoch {
            return Err(format!(
                "throttle {} exceeds epoch payout cap",
                throttle.throttle_id
            ));
        }
        let id = throttle.throttle_id.clone();
        self.payout_throttles.insert(id.clone(), throttle);
        self.record_event(
            InsuranceEventKind::PayoutScheduled,
            &id,
            &json!({"throttle_id": id}),
        )?;
        Ok(id)
    }
    pub fn file_challenge(
        &mut self,
        challenge: ClaimChallengeEvidence,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "challenge",
            self.challenges.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_CHALLENGES,
        )?;
        challenge.validate()?;
        if self.spent_nullifiers.contains(&challenge.bond_nullifier) {
            return Err(format!(
                "challenge bond nullifier {} already spent",
                challenge.bond_nullifier
            ));
        }
        if !self.claims.contains_key(&challenge.claim_id) {
            return Err(format!("missing claim {}", challenge.claim_id));
        }
        if challenge
            .expires_at_height
            .saturating_sub(challenge.opened_at_height)
            > self.config.challenge_window_blocks
        {
            return Err(format!(
                "challenge {} exceeds window",
                challenge.challenge_id
            ));
        }
        let id = challenge.challenge_id.clone();
        self.spent_nullifiers
            .insert(challenge.bond_nullifier.clone());
        self.challenges.insert(id.clone(), challenge);
        self.record_event(
            InsuranceEventKind::ChallengeFiled,
            &id,
            &json!({"challenge_id": id}),
        )?;
        Ok(id)
    }
    pub fn prepare_handoff(
        &mut self,
        handoff: SlashingHandoffReceipt,
    ) -> PrivateOracleExecutionInsuranceResult<String> {
        ensure_capacity(
            "handoff",
            self.handoffs.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_HANDOFFS,
        )?;
        handoff.validate()?;
        if !self.challenges.contains_key(&handoff.challenge_id) {
            return Err(format!("missing challenge {}", handoff.challenge_id));
        }
        if !self.claims.contains_key(&handoff.claim_id) {
            return Err(format!("missing claim {}", handoff.claim_id));
        }
        if !self
            .committee_members
            .contains_key(&handoff.target_member_id)
        {
            return Err(format!("missing member {}", handoff.target_member_id));
        }
        if handoff
            .expires_at_height
            .saturating_sub(handoff.prepared_at_height)
            > self.config.handoff_ttl_blocks
        {
            return Err(format!("handoff {} exceeds ttl", handoff.handoff_id));
        }
        let id = handoff.handoff_id.clone();
        self.handoffs.insert(id.clone(), handoff);
        self.record_event(
            InsuranceEventKind::HandoffPrepared,
            &id,
            &json!({"handoff_id": id}),
        )?;
        Ok(id)
    }
    pub fn public_record(&self) -> Value {
        json!({"chain_id": CHAIN_ID, "protocol_id": PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_ID, "protocol_version": PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_VERSION, "height": self.height, "roots": self.roots().public_record(), "counters": self.counters().public_record()})
    }
    pub fn roots(&self) -> PrivateOracleExecutionInsuranceRoots {
        let config_root = self.config.config_root();
        let vault_root = record_merkle_root(
            "VAULTS",
            self.vaults
                .values()
                .map(ConfidentialPayoutVault::public_record)
                .collect(),
        );
        let policy_root = record_merkle_root(
            "POLICIES",
            self.policies
                .values()
                .map(ShieldedOracleExecutionPolicy::public_record)
                .collect(),
        );
        let committee_member_root = record_merkle_root(
            "MEMBERS",
            self.committee_members
                .values()
                .map(PqOracleCommitteeMember::public_record)
                .collect(),
        );
        let attestation_root = record_merkle_root(
            "ATTESTATIONS",
            self.attestations
                .values()
                .map(PqOracleExecutionAttestation::public_record)
                .collect(),
        );
        let claim_root = record_merkle_root(
            "CLAIMS",
            self.claims
                .values()
                .map(EncryptedIncidentClaim::public_record)
                .collect(),
        );
        let sponsor_root = record_merkle_root(
            "SPONSORS",
            self.sponsors
                .values()
                .map(LowFeeClaimSponsor::public_record)
                .collect(),
        );
        let payout_throttle_root = record_merkle_root(
            "THROTTLES",
            self.payout_throttles
                .values()
                .map(DelayedPayoutThrottle::public_record)
                .collect(),
        );
        let challenge_root = record_merkle_root(
            "CHALLENGES",
            self.challenges
                .values()
                .map(ClaimChallengeEvidence::public_record)
                .collect(),
        );
        let handoff_root = record_merkle_root(
            "HANDOFFS",
            self.handoffs
                .values()
                .map(SlashingHandoffReceipt::public_record)
                .collect(),
        );
        let nullifier_root = record_merkle_root(
            "NULLIFIERS",
            self.spent_nullifiers
                .iter()
                .map(|value| json!({"nullifier": value}))
                .collect(),
        );
        let event_root = record_merkle_root(
            "EVENTS",
            self.events
                .values()
                .map(OracleExecutionInsuranceEvent::public_record)
                .collect(),
        );
        let state_root = oracle_execution_insurance_hash(
            "STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&vault_root),
                HashPart::Str(&policy_root),
                HashPart::Str(&committee_member_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&claim_root),
                HashPart::Str(&sponsor_root),
                HashPart::Str(&payout_throttle_root),
                HashPart::Str(&challenge_root),
                HashPart::Str(&handoff_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&event_root),
                HashPart::Int(self.height as i128),
            ],
        );
        PrivateOracleExecutionInsuranceRoots {
            config_root,
            vault_root,
            policy_root,
            committee_member_root,
            attestation_root,
            claim_root,
            sponsor_root,
            payout_throttle_root,
            challenge_root,
            handoff_root,
            nullifier_root,
            event_root,
            state_root,
        }
    }
    pub fn counters(&self) -> PrivateOracleExecutionInsuranceCounters {
        PrivateOracleExecutionInsuranceCounters {
            height: self.height,
            vaults: self.vaults.len(),
            policies: self.policies.len(),
            active_policies: self
                .policies
                .values()
                .filter(|policy| policy.status.accepts_claims())
                .count(),
            committee_members: self.committee_members.len(),
            active_committee_members: self
                .committee_members
                .values()
                .filter(|member| member.status.attesting())
                .count(),
            attestations: self.attestations.len(),
            counted_attestations: self
                .attestations
                .values()
                .filter(|attestation| attestation.status == ExecutionAttestationStatus::Counted)
                .count(),
            claims: self.claims.len(),
            open_claims: self
                .claims
                .values()
                .filter(|claim| claim.status.is_open())
                .count(),
            sponsors: self.sponsors.len(),
            active_sponsors: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.can_sponsor())
                .count(),
            payout_throttles: self.payout_throttles.len(),
            pending_payout_throttles: self
                .payout_throttles
                .values()
                .filter(|throttle| {
                    matches!(
                        throttle.status,
                        PayoutThrottleStatus::Scheduled
                            | PayoutThrottleStatus::CoolingDown
                            | PayoutThrottleStatus::Releasable
                    )
                })
                .count(),
            challenges: self.challenges.len(),
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| {
                    matches!(
                        challenge.status,
                        ClaimChallengeStatus::Open | ClaimChallengeStatus::EvidenceSubmitted
                    )
                })
                .count(),
            handoffs: self.handoffs.len(),
            nullifiers: self.spent_nullifiers.len(),
            events: self.events.len(),
            total_capacity_units: self
                .vaults
                .values()
                .map(|vault| vault.total_capacity_units)
                .sum(),
            active_exposure_units: self
                .vaults
                .values()
                .map(|vault| vault.active_exposure_units)
                .sum(),
            reserved_claim_units: self
                .vaults
                .values()
                .map(|vault| vault.reserved_claim_units)
                .sum(),
            released_payout_units: self
                .vaults
                .values()
                .map(|vault| vault.released_payout_units)
                .sum(),
            sponsor_budget_units: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.budget_units)
                .sum(),
            sponsor_spent_units: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.spent_units)
                .sum(),
        }
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    fn debit_sponsor(
        &mut self,
        sponsor_id: &str,
        fee_units: u64,
    ) -> PrivateOracleExecutionInsuranceResult<()> {
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| format!("missing sponsor {}", sponsor_id))?;
        if !sponsor.status.can_sponsor() {
            return Err(format!("sponsor {} cannot sponsor", sponsor_id));
        }
        if fee_units > sponsor.fee_cap_units || fee_units > sponsor.remaining_budget_units() {
            return Err(format!("sponsor {} cannot cover fee", sponsor_id));
        }
        sponsor.spent_units = sponsor.spent_units.saturating_add(fee_units);
        sponsor.sponsored_claims = sponsor.sponsored_claims.saturating_add(1);
        if sponsor.spent_units >= sponsor.budget_units {
            sponsor.status = ClaimSponsorStatus::Exhausted;
        }
        self.record_event(
            InsuranceEventKind::SponsorDebited,
            sponsor_id,
            &json!({"sponsor_id": sponsor_id, "fee_units": fee_units}),
        )?;
        Ok(())
    }
    fn reserve_claim_capacity(
        &mut self,
        claim_id: &str,
    ) -> PrivateOracleExecutionInsuranceResult<()> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| format!("missing claim {}", claim_id))?;
        let vault = self
            .vaults
            .get_mut(&claim.vault_id)
            .ok_or_else(|| format!("missing vault {}", claim.vault_id))?;
        if claim.requested_payout_units
            > vault
                .available_capacity_units()
                .saturating_add(vault.reserved_claim_units)
        {
            return Err(format!("claim {} exceeds vault claim capacity", claim_id));
        }
        vault.reserved_claim_units = vault
            .reserved_claim_units
            .saturating_add(claim.requested_payout_units);
        vault.updated_at_height = self.height;
        Ok(())
    }
    fn recompute_vault_exposure_for_policy(
        &mut self,
        policy_id: &str,
    ) -> PrivateOracleExecutionInsuranceResult<()> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| format!("missing policy {}", policy_id))?;
        let vault_id = policy.vault_id.clone();
        let exposure = self
            .policies
            .values()
            .filter(|candidate| candidate.vault_id == vault_id && candidate.status.accepts_claims())
            .map(|candidate| candidate.coverage_units)
            .sum::<u64>();
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or_else(|| format!("missing vault {}", vault_id))?;
        let utilization_bps = if vault.total_capacity_units == 0 {
            0
        } else {
            exposure.saturating_mul(PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS)
                / vault.total_capacity_units
        };
        if utilization_bps > self.config.max_vault_utilization_bps {
            return Err(format!("vault {} utilization exceeds cap", vault_id));
        }
        vault.active_exposure_units = exposure;
        vault.updated_at_height = self.height;
        Ok(())
    }
    fn epoch_payout_units(&self, epoch_index: u64) -> u64 {
        self.payout_throttles
            .values()
            .filter(|throttle| throttle.epoch_index == epoch_index)
            .map(|throttle| throttle.payout_units)
            .sum()
    }
    fn expire_stale_records(&mut self) {
        for policy in self.policies.values_mut() {
            if policy.status.accepts_claims() && policy.expires_at_height < self.height {
                policy.status = ExecutionPolicyStatus::Expired;
                policy.updated_at_height = self.height;
            }
        }
        for attestation in self.attestations.values_mut() {
            if matches!(
                attestation.status,
                ExecutionAttestationStatus::Submitted | ExecutionAttestationStatus::RangeChecked
            ) && attestation.expires_at_height < self.height
            {
                attestation.status = ExecutionAttestationStatus::Expired;
            }
        }
        for claim in self.claims.values_mut() {
            if claim.status.is_open() && claim.expires_at_height < self.height {
                claim.status = IncidentClaimStatus::Expired;
            }
        }
        for sponsor in self.sponsors.values_mut() {
            if sponsor.status == ClaimSponsorStatus::Active
                && sponsor.window_end_height < self.height
            {
                sponsor.status = ClaimSponsorStatus::Retired;
            }
        }
        for throttle in self.payout_throttles.values_mut() {
            if matches!(
                throttle.status,
                PayoutThrottleStatus::Scheduled | PayoutThrottleStatus::CoolingDown
            ) && throttle.release_after_height <= self.height
            {
                throttle.status = PayoutThrottleStatus::Releasable;
            }
        }
        for challenge in self.challenges.values_mut() {
            if matches!(
                challenge.status,
                ClaimChallengeStatus::Open | ClaimChallengeStatus::EvidenceSubmitted
            ) && challenge.expires_at_height < self.height
            {
                challenge.status = ClaimChallengeStatus::Expired;
            }
        }
        for handoff in self.handoffs.values_mut() {
            if matches!(
                handoff.status,
                HandoffStatus::Prepared | HandoffStatus::Delivered
            ) && handoff.expires_at_height < self.height
            {
                handoff.status = HandoffStatus::Expired;
            }
        }
    }
    fn record_event(
        &mut self,
        kind: InsuranceEventKind,
        subject_id: &str,
        payload: &Value,
    ) -> PrivateOracleExecutionInsuranceResult<()> {
        ensure_capacity(
            "event",
            self.events.len(),
            PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_EVENTS,
        )?;
        let payload_root =
            oracle_execution_insurance_hash("EVENTPAYLOAD", &[HashPart::Json(payload)]);
        let event_id = oracle_execution_insurance_hash(
            "EVENTID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.events.len() as i128),
            ],
        );
        let event = OracleExecutionInsuranceEvent {
            event_id: event_id.clone(),
            event_kind: kind,
            subject_id: subject_id.to_string(),
            state_root_after: self.state_root_without_events(),
            payload_root,
            height: self.height,
        };
        event.validate()?;
        self.events.insert(event_id, event);
        Ok(())
    }
    fn state_root_without_events(&self) -> String {
        let config_root = self.config.config_root();
        oracle_execution_insurance_hash(
            "STATEWITHOUTEVENTS",
            &[
                HashPart::Str(&config_root),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.vaults.len() as i128),
                HashPart::Int(self.policies.len() as i128),
                HashPart::Int(self.claims.len() as i128),
                HashPart::Int(self.payout_throttles.len() as i128),
            ],
        )
    }
}
fn ensure_non_empty(field: &str, value: &str) -> PrivateOracleExecutionInsuranceResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    Ok(())
}
fn ensure_capacity(
    name: &str,
    len: usize,
    max: usize,
) -> PrivateOracleExecutionInsuranceResult<()> {
    if len >= max {
        return Err(format!(
            "oracle execution insurance {} capacity exceeded",
            name
        ));
    }
    Ok(())
}
fn bps_mul(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / PRIVATE_ORACLE_EXECUTION_INSURANCE_MAX_BPS
}
fn oracle_execution_insurance_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}",
            PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_ID, domain
        ),
        parts,
        32,
    )
}
fn record_merkle_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!(
            "{}:{}",
            PRIVATE_ORACLE_EXECUTION_INSURANCE_PROTOCOL_ID, domain
        ),
        &records,
    )
}
fn make_devnet_vault(index: u64, height: u64) -> ConfidentialPayoutVault {
    ConfidentialPayoutVault {
        vault_id: format!("oracle-exec-vault-{:02}", index),
        operator_commitment: format!("oracle-exec-vault-operator-commitment-{:02}", index),
        reserve_commitment: format!("oracle-exec-reserve-commitment-{:02}", index),
        payout_asset_id: PRIVATE_ORACLE_EXECUTION_INSURANCE_FEE_ASSET_ID.to_string(),
        total_capacity_units: 20_000_000 + index.saturating_mul(1_000_000),
        active_exposure_units: 0,
        reserved_claim_units: 0,
        released_payout_units: 0,
        solvency_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_SOLVENCY_BPS + 500,
        privacy_set_size: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE
            + index.saturating_mul(128),
        status: PayoutVaultStatus::Active,
        created_at_height: height,
        updated_at_height: height,
    }
}
fn make_devnet_policy(index: u64, height: u64, ttl: u64) -> ShieldedOracleExecutionPolicy {
    let domain = match index % 5 {
        0 => OracleExecutionDomain::SpotPrice,
        1 => OracleExecutionDomain::PrivateTwap,
        2 => OracleExecutionDomain::PerpFunding,
        3 => OracleExecutionDomain::StablecoinPeg,
        _ => OracleExecutionDomain::MoneroReserve,
    };
    ShieldedOracleExecutionPolicy {
        policy_id: format!("oracle-exec-policy-{:03}", index),
        vault_id: format!("oracle-exec-vault-{:02}", index % 4),
        owner_commitment: format!("oracle-exec-policy-owner-commitment-{:03}", index),
        market_id: format!("oracle-market-{:02}", index % 6),
        domain,
        failure_kind: ExecutionFailureKind::MissingOracleUpdate,
        sealed_terms_root: format!("oracle-exec-policy-sealed-terms-root-{:03}", index),
        premium_nullifier: format!("oracle-exec-premium-nullifier-{:03}", index),
        coverage_units: 120_000 + index.saturating_mul(2_500),
        premium_units: 1_200 + index.saturating_mul(25),
        deductible_units: 5_000,
        max_latency_blocks: 8 + index % 4,
        min_committee_weight_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_COMMITTEE_QUORUM_BPS,
        privacy_set_size: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE + 64,
        status: ExecutionPolicyStatus::Active,
        issued_at_height: height,
        expires_at_height: height.saturating_add(ttl),
        updated_at_height: height,
    }
}
fn make_devnet_member(index: u64, height: u64) -> PqOracleCommitteeMember {
    PqOracleCommitteeMember {
        member_id: format!("oracle-exec-member-{:02}", index),
        committee_id: "oracle-exec-committee-devnet-0".to_string(),
        operator_commitment: format!("oracle-exec-member-operator-commitment-{:02}", index),
        pq_public_key_root: format!("oracle-exec-member-pq-root-{:02}", index),
        backup_public_key_root: format!("oracle-exec-member-backup-root-{:02}", index),
        kem_public_key_root: format!("oracle-exec-member-kem-root-{:02}", index),
        weight_bps: 1_250,
        bond_units: 250_000 + index.saturating_mul(5_000),
        security_bits: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PQ_SECURITY_BITS,
        privacy_set_size: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE + 128,
        status: CommitteeMemberStatus::Active,
        joined_at_height: height,
        updated_at_height: height,
    }
}
fn make_devnet_attestation(index: u64, height: u64, ttl: u64) -> PqOracleExecutionAttestation {
    PqOracleExecutionAttestation {
        attestation_id: format!("oracle-exec-attestation-{:03}", index),
        policy_id: format!("oracle-exec-policy-{:03}", index),
        market_id: format!("oracle-market-{:02}", index % 6),
        committee_id: "oracle-exec-committee-devnet-0".to_string(),
        member_id: format!("oracle-exec-member-{:02}", index % 8),
        incident_claim_id: None,
        execution_root: format!("oracle-exec-execution-root-{:03}", index),
        encrypted_observation_root: format!("oracle-exec-observation-root-{:03}", index),
        pq_signature_root: format!("oracle-exec-signature-root-{:03}", index),
        observed_height: height.saturating_sub(index % 4),
        submitted_at_height: height,
        expires_at_height: height.saturating_add(ttl),
        committee_weight_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_COMMITTEE_QUORUM_BPS,
        status: ExecutionAttestationStatus::Counted,
    }
}
fn make_devnet_claim(
    index: u64,
    height: u64,
    claim_window: u64,
    challenge_window: u64,
) -> EncryptedIncidentClaim {
    EncryptedIncidentClaim {
        claim_id: format!("oracle-exec-claim-{:03}", index),
        policy_id: format!("oracle-exec-policy-{:03}", index),
        vault_id: format!("oracle-exec-vault-{:02}", index % 4),
        claimant_commitment: format!("oracle-exec-claimant-commitment-{:03}", index),
        claim_ciphertext_root: format!("oracle-exec-claim-ciphertext-root-{:03}", index),
        incident_evidence_root: format!("oracle-exec-incident-evidence-root-{:03}", index),
        payout_address_commitment: format!("oracle-exec-payout-address-commitment-{:03}", index),
        sponsor_id: Some("oracle-exec-sponsor-00".to_string()),
        requested_payout_units: 35_000 + index.saturating_mul(1_000),
        approved_payout_units: 0,
        claim_nullifier: format!("oracle-exec-claim-nullifier-{:03}", index),
        opened_at_height: height,
        challenge_deadline_height: height.saturating_add(challenge_window),
        expires_at_height: height.saturating_add(claim_window),
        status: IncidentClaimStatus::CommitteeReview,
    }
}
fn make_devnet_sponsor(index: u64, height: u64, window: u64) -> LowFeeClaimSponsor {
    LowFeeClaimSponsor {
        sponsor_id: format!("oracle-exec-sponsor-{:02}", index),
        sponsor_commitment: format!("oracle-exec-sponsor-commitment-{:02}", index),
        fee_asset_id: PRIVATE_ORACLE_EXECUTION_INSURANCE_FEE_ASSET_ID.to_string(),
        budget_units: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_SPONSOR_BUDGET_UNITS,
        spent_units: 0,
        fee_cap_units: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_LOW_FEE_CAP_UNITS,
        sponsored_claims: 0,
        privacy_set_size: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE + 256,
        status: ClaimSponsorStatus::Active,
        window_start_height: height,
        window_end_height: height.saturating_add(window),
    }
}
fn make_devnet_throttle(index: u64, height: u64, delay: u64) -> DelayedPayoutThrottle {
    DelayedPayoutThrottle {
        throttle_id: format!("oracle-exec-throttle-{:03}", index),
        claim_id: format!("oracle-exec-claim-{:03}", index),
        policy_id: format!("oracle-exec-policy-{:03}", index),
        vault_id: format!("oracle-exec-vault-{:02}", index % 4),
        payout_commitment: format!("oracle-exec-payout-commitment-{:03}", index),
        payout_units: 20_000 + index.saturating_mul(500),
        epoch_index: height / PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_EPOCH_BLOCKS,
        scheduled_at_height: height,
        release_after_height: height.saturating_add(delay),
        released_at_height: None,
        status: PayoutThrottleStatus::Scheduled,
    }
}
fn make_devnet_challenge(index: u64, height: u64, window: u64) -> ClaimChallengeEvidence {
    ClaimChallengeEvidence {
        challenge_id: format!("oracle-exec-challenge-{:03}", index),
        claim_id: format!("oracle-exec-claim-{:03}", index),
        challenger_commitment: format!("oracle-exec-challenger-commitment-{:03}", index),
        accused_member_id: Some("oracle-exec-member-00".to_string()),
        evidence_ciphertext_root: format!("oracle-exec-challenge-ciphertext-root-{:03}", index),
        evidence_merkle_root: format!("oracle-exec-challenge-merkle-root-{:03}", index),
        bond_nullifier: format!("oracle-exec-challenge-bond-nullifier-{:03}", index),
        slash_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_CLAIM_SLASH_BPS,
        reporter_reward_bps: PRIVATE_ORACLE_EXECUTION_INSURANCE_DEFAULT_REPORTER_REWARD_BPS,
        opened_at_height: height,
        expires_at_height: height.saturating_add(window),
        status: ClaimChallengeStatus::EvidenceSubmitted,
    }
}
fn make_devnet_handoff(index: u64, height: u64, ttl: u64) -> SlashingHandoffReceipt {
    SlashingHandoffReceipt {
        handoff_id: format!("oracle-exec-handoff-{:03}", index),
        challenge_id: format!("oracle-exec-challenge-{:03}", index),
        claim_id: format!("oracle-exec-claim-{:03}", index),
        target_member_id: "oracle-exec-member-00".to_string(),
        destination_module: "private_oracle_risk_committee".to_string(),
        slashing_evidence_root: format!("oracle-exec-handoff-evidence-root-{:03}", index),
        handoff_receipt_root: format!("oracle-exec-handoff-receipt-root-{:03}", index),
        slash_units: 25_000,
        reporter_reward_units: 2_500,
        prepared_at_height: height,
        expires_at_height: height.saturating_add(ttl),
        status: HandoffStatus::Prepared,
    }
}
