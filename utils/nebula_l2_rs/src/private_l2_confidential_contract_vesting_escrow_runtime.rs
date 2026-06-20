use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractVestingEscrowRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-vesting-escrow-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-vesting-escrow-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEVNET_HEIGHT: u64 = 1_046_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_SCHEDULES: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_BENEFICIARIES: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_MILESTONES: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_CLAIMS: usize =
    134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_REBATES: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_NULLIFIERS: usize =
    268_435_456;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_BATCH_CLAIMS: usize =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    65_536;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 =
    5;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    4;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_CLAIM_TTL_BLOCKS: u64 =
    96;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 =
    72;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VestingAssetKind {
    ConfidentialToken,
    GovernanceToken,
    LpShare,
    VaultShare,
    OptionToken,
    FeeCredit,
    BridgeReceipt,
}

impl VestingAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialToken => "confidential_token",
            Self::GovernanceToken => "governance_token",
            Self::LpShare => "lp_share",
            Self::VaultShare => "vault_share",
            Self::OptionToken => "option_token",
            Self::FeeCredit => "fee_credit",
            Self::BridgeReceipt => "bridge_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCurveKind {
    Cliff,
    Linear,
    Milestone,
    Streaming,
    Hybrid,
}

impl ReleaseCurveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cliff => "cliff",
            Self::Linear => "linear",
            Self::Milestone => "milestone",
            Self::Streaming => "streaming",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Draft,
    Active,
    Paused,
    Matured,
    Cancelled,
    Settled,
}

impl ScheduleStatus {
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::Matured)
    }

    pub fn anchors_state(self) -> bool {
        !matches!(self, Self::Draft)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BeneficiaryStatus {
    Pending,
    Active,
    Paused,
    Revoked,
    FullyVested,
}

impl BeneficiaryStatus {
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::FullyVested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MilestoneStatus {
    Pending,
    Eligible,
    Attested,
    Released,
    Cancelled,
}

impl MilestoneStatus {
    pub fn contributes_release(self) -> bool {
        matches!(self, Self::Eligible | Self::Attested | Self::Released)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Encrypted,
    Sponsored,
    Queued,
    Settled,
    Disputed,
    Expired,
    Cancelled,
}

impl ClaimStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Encrypted | Self::Sponsored | Self::Queued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Proving,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn anchors_state(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Proving | Self::Settled | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ScheduleActivated,
    MilestoneReleased,
    PrivateClaimSettled,
    SponsorCharged,
    RebateCredited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Claimed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ScheduleIntegrity,
    BeneficiarySet,
    MilestoneEligibility,
    ReleaseComputation,
    ContractHook,
    PqAuthorization,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    Warning,
    Invalid,
}

impl AttestationVerdict {
    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Valid | Self::Warning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Released,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFenceStatus {
    Locked,
    Consumed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub devnet_height: u64,
    pub max_schedules: usize,
    pub max_beneficiaries: usize,
    pub max_milestones: usize,
    pub max_claims: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_attestations: usize,
    pub max_nullifiers: usize,
    pub max_batch_claims: usize,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub claim_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            devnet_height: PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEVNET_HEIGHT,
            max_schedules:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_SCHEDULES,
            max_beneficiaries:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_BENEFICIARIES,
            max_milestones:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_MILESTONES,
            max_claims: PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_CLAIMS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_REBATES,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_nullifiers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_batch_claims:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_BATCH_CLAIMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            claim_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_CLAIM_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub schedule_count: u64,
    pub active_schedule_count: u64,
    pub beneficiary_count: u64,
    pub active_beneficiary_count: u64,
    pub milestone_count: u64,
    pub releasable_milestone_count: u64,
    pub claim_count: u64,
    pub open_claim_count: u64,
    pub reservation_count: u64,
    pub batch_count: u64,
    pub settled_batch_count: u64,
    pub receipt_count: u64,
    pub rebate_count: u64,
    pub attestation_count: u64,
    pub locked_nullifier_count: u64,
    pub event_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub schedule_root: String,
    pub active_schedule_root: String,
    pub beneficiary_root: String,
    pub active_beneficiary_root: String,
    pub milestone_root: String,
    pub releasable_milestone_root: String,
    pub claim_root: String,
    pub open_claim_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub attestation_root: String,
    pub nullifier_fence_root: String,
    pub consumed_nullifier_root: String,
    pub sponsor_credit_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = json!({"empty": true});
        Self {
            schedule_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-SCHEDULES", &[]),
            active_schedule_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-ACTIVE-SCHEDULES",
                &[],
            ),
            beneficiary_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-BENEFICIARIES", &[]),
            active_beneficiary_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-ACTIVE-BENEFICIARIES",
                &[],
            ),
            milestone_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-MILESTONES", &[]),
            releasable_milestone_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-RELEASABLE-MILESTONES",
                &[],
            ),
            claim_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-CLAIMS", &[]),
            open_claim_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-OPEN-CLAIMS", &[]),
            reservation_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-RESERVATIONS", &[]),
            batch_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-BATCHES", &[]),
            receipt_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-RECEIPTS", &[]),
            rebate_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-REBATES", &[]),
            attestation_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-ATTESTATIONS", &[]),
            nullifier_fence_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-NULLIFIER-FENCES",
                &[],
            ),
            consumed_nullifier_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-CONSUMED-NULLIFIERS",
                &[],
            ),
            sponsor_credit_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-SPONSOR-CREDITS",
                &[],
            ),
            event_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-EVENTS", &[]),
            public_record_root: domain_hash(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-PUBLIC-RECORD",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(
                        PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PROTOCOL_VERSION,
                    ),
                    HashPart::Json(&empty),
                ],
                32,
            ),
            state_root: domain_hash(
                "PRIVATE-L2-CONFIDENTIAL-VESTING-STATE",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(
                        PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PROTOCOL_VERSION,
                    ),
                    HashPart::Json(&empty),
                ],
                32,
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VestingSchedule {
    pub schedule_id: String,
    pub asset_kind: VestingAssetKind,
    pub curve_kind: ReleaseCurveKind,
    pub issuer_commitment: String,
    pub contract_commitment: String,
    pub asset_commitment: String,
    pub encrypted_terms_root: String,
    pub beneficiary_set_root: String,
    pub milestone_root: String,
    pub hook_root: String,
    pub total_amount_commitment: String,
    pub vested_amount_commitment: String,
    pub claimable_amount_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: ScheduleStatus,
    pub created_at_height: u64,
    pub cliff_height: u64,
    pub start_height: u64,
    pub end_height: u64,
}

impl VestingSchedule {
    pub fn record(&self) -> Value {
        json!({
            "schedule_id": self.schedule_id,
            "asset_kind": self.asset_kind,
            "curve_kind": self.curve_kind,
            "issuer_commitment": self.issuer_commitment,
            "contract_commitment": self.contract_commitment,
            "asset_commitment": self.asset_commitment,
            "encrypted_terms_root": self.encrypted_terms_root,
            "beneficiary_set_root": self.beneficiary_set_root,
            "milestone_root": self.milestone_root,
            "hook_root": self.hook_root,
            "total_amount_commitment": self.total_amount_commitment,
            "vested_amount_commitment": self.vested_amount_commitment,
            "claimable_amount_commitment": self.claimable_amount_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "cliff_height": self.cliff_height,
            "start_height": self.start_height,
            "end_height": self.end_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BeneficiaryCommitment {
    pub beneficiary_id: String,
    pub schedule_id: String,
    pub encrypted_account_commitment: String,
    pub allocation_commitment: String,
    pub claimed_amount_commitment: String,
    pub delegate_hook_commitment: String,
    pub release_nullifier_root: String,
    pub status: BeneficiaryStatus,
    pub privacy_set_size: u64,
    pub added_at_height: u64,
    pub last_claim_height: u64,
}

impl BeneficiaryCommitment {
    pub fn record(&self) -> Value {
        json!({
            "beneficiary_id": self.beneficiary_id,
            "schedule_id": self.schedule_id,
            "encrypted_account_commitment": self.encrypted_account_commitment,
            "allocation_commitment": self.allocation_commitment,
            "claimed_amount_commitment": self.claimed_amount_commitment,
            "delegate_hook_commitment": self.delegate_hook_commitment,
            "release_nullifier_root": self.release_nullifier_root,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "added_at_height": self.added_at_height,
            "last_claim_height": self.last_claim_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseMilestone {
    pub milestone_id: String,
    pub schedule_id: String,
    pub milestone_index: u64,
    pub encrypted_condition_root: String,
    pub attestation_root: String,
    pub releasable_amount_commitment: String,
    pub release_height: u64,
    pub status: MilestoneStatus,
}

impl ReleaseMilestone {
    pub fn record(&self) -> Value {
        json!({
            "milestone_id": self.milestone_id,
            "schedule_id": self.schedule_id,
            "milestone_index": self.milestone_index,
            "encrypted_condition_root": self.encrypted_condition_root,
            "attestation_root": self.attestation_root,
            "releasable_amount_commitment": self.releasable_amount_commitment,
            "release_height": self.release_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimIntent {
    pub claim_id: String,
    pub schedule_id: String,
    pub beneficiary_id: String,
    pub milestone_id: String,
    pub encrypted_claim_payload: String,
    pub requested_amount_commitment: String,
    pub claim_nullifier: String,
    pub witness_root: String,
    pub fee_quote_commitment: String,
    pub status: ClaimStatus,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ClaimIntent {
    pub fn record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "schedule_id": self.schedule_id,
            "beneficiary_id": self.beneficiary_id,
            "milestone_id": self.milestone_id,
            "encrypted_claim_payload": self.encrypted_claim_payload,
            "requested_amount_commitment": self.requested_amount_commitment,
            "claim_nullifier": self.claim_nullifier,
            "witness_root": self.witness_root,
            "fee_quote_commitment": self.fee_quote_commitment,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub claim_id: String,
    pub sponsor_commitment: String,
    pub credit_root: String,
    pub max_fee_amount: u64,
    pub consumed_fee_amount: u64,
    pub sponsor_fee_bps: u64,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "claim_id": self.claim_id,
            "sponsor_commitment": self.sponsor_commitment,
            "credit_root": self.credit_root,
            "max_fee_amount": self.max_fee_amount,
            "consumed_fee_amount": self.consumed_fee_amount,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseBatch {
    pub batch_id: String,
    pub schedule_root: String,
    pub claim_root: String,
    pub milestone_root: String,
    pub reservation_root: String,
    pub attestation_root: String,
    pub proof_commitment: String,
    pub status: BatchStatus,
    pub claim_count: u64,
    pub gross_release_commitment: String,
    pub sponsor_fee_amount: u64,
    pub rebate_amount: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
}

impl ReleaseBatch {
    pub fn record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "schedule_root": self.schedule_root,
            "claim_root": self.claim_root,
            "milestone_root": self.milestone_root,
            "reservation_root": self.reservation_root,
            "attestation_root": self.attestation_root,
            "proof_commitment": self.proof_commitment,
            "status": self.status,
            "claim_count": self.claim_count,
            "gross_release_commitment": self.gross_release_commitment,
            "sponsor_fee_amount": self.sponsor_fee_amount,
            "rebate_amount": self.rebate_amount,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub claim_id: String,
    pub reservation_id: String,
    pub kind: ReceiptKind,
    pub release_commitment: String,
    pub fee_amount: u64,
    pub rebate_amount: u64,
    pub settlement_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "claim_id": self.claim_id,
            "reservation_id": self.reservation_id,
            "kind": self.kind,
            "release_commitment": self.release_commitment,
            "fee_amount": self.fee_amount,
            "rebate_amount": self.rebate_amount,
            "settlement_root": self.settlement_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_id: String,
    pub sponsor_commitment: String,
    pub rebate_amount: u64,
    pub status: RebateStatus,
    pub claim_after_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_id": self.beneficiary_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_amount": self.rebate_amount,
            "status": self.status,
            "claim_after_height": self.claim_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EscrowAttestation {
    pub attestation_id: String,
    pub schedule_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub committee_root: String,
    pub transcript_root: String,
    pub pq_signature_commitment: String,
    pub observed_at_height: u64,
}

impl EscrowAttestation {
    pub fn record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "schedule_id": self.schedule_id,
            "subject_id": self.subject_id,
            "kind": self.kind,
            "verdict": self.verdict,
            "committee_root": self.committee_root,
            "transcript_root": self.transcript_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub subject_id: String,
    pub fence_root: String,
    pub status: NullifierFenceStatus,
    pub locked_at_height: u64,
    pub released_at_height: u64,
}

impl NullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "subject_id": self.subject_id,
            "fence_root": self.fence_root,
            "status": self.status,
            "locked_at_height": self.locked_at_height,
            "released_at_height": self.released_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub schedules: BTreeMap<String, VestingSchedule>,
    pub beneficiaries: BTreeMap<String, BeneficiaryCommitment>,
    pub milestones: BTreeMap<String, ReleaseMilestone>,
    pub claims: BTreeMap<String, ClaimIntent>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub batches: BTreeMap<String, ReleaseBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub attestations: BTreeMap<String, EscrowAttestation>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub sponsor_credit_roots: BTreeMap<String, String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            schedules: BTreeMap::new(),
            beneficiaries: BTreeMap::new(),
            milestones: BTreeMap::new(),
            claims: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            sponsor_credit_roots: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let height = state.config.devnet_height;
        let issuer_commitment = payload_root(
            "vesting-escrow:issuer",
            &json!({"issuer": "devnet-token-launchpad", "scope": "private-team-vesting"}),
        );
        let contract_commitment = payload_root(
            "vesting-escrow:contract",
            &json!({"contract": "confidential-vesting-escrow", "vm": "private-l2"}),
        );
        let asset_commitment = payload_root(
            "vesting-escrow:asset",
            &json!({"symbol": "dXMR-TEAM", "asset_kind": "confidential_token"}),
        );
        let schedule_id = schedule_id(
            VestingAssetKind::ConfidentialToken,
            &issuer_commitment,
            &asset_commitment,
            0,
        );
        let beneficiary_id = beneficiary_id(&schedule_id, "beneficiary-alpha", 0);
        let milestone_id = milestone_id(&schedule_id, 0, height + 720);
        let schedule = VestingSchedule {
            schedule_id: schedule_id.clone(),
            asset_kind: VestingAssetKind::ConfidentialToken,
            curve_kind: ReleaseCurveKind::Hybrid,
            issuer_commitment: issuer_commitment.clone(),
            contract_commitment: contract_commitment.clone(),
            asset_commitment: asset_commitment.clone(),
            encrypted_terms_root: payload_root(
                "vesting-escrow:encrypted-terms",
                &json!({"ciphertext": "devnet-vesting-terms-alpha", "suite": "ml-kem-1024"}),
            ),
            beneficiary_set_root: root_from_values(
                "vesting-escrow:beneficiary-set",
                &["beneficiary-alpha", "beneficiary-beta", "beneficiary-gamma"],
            ),
            milestone_root: root_from_values(
                "vesting-escrow:milestones",
                &["cliff", "linear-release", "liquidity-unlock"],
            ),
            hook_root: payload_root(
                "vesting-escrow:hooks",
                &json!({"hooks": ["compliance-proof", "governance-delay"], "mode": "private"}),
            ),
            total_amount_commitment: payload_root(
                "vesting-escrow:total-amount",
                &json!({"commitment": "team-vesting-total", "amount_hint": "hidden"}),
            ),
            vested_amount_commitment: payload_root(
                "vesting-escrow:vested-amount",
                &json!({"commitment": "vested-at-devnet-height"}),
            ),
            claimable_amount_commitment: payload_root(
                "vesting-escrow:claimable-amount",
                &json!({"commitment": "claimable-first-release"}),
            ),
            privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            status: ScheduleStatus::Active,
            created_at_height: height - 20_000,
            cliff_height: height - 1_024,
            start_height: height - 20_000,
            end_height: height + 262_800,
        };
        state
            .register_schedule(schedule.clone())
            .expect("devnet schedule");

        let beneficiary = BeneficiaryCommitment {
            beneficiary_id: beneficiary_id.clone(),
            schedule_id: schedule_id.clone(),
            encrypted_account_commitment: payload_root(
                "vesting-escrow:beneficiary-account",
                &json!({"account": "beneficiary-alpha-stealth", "suite": "ml-kem-1024"}),
            ),
            allocation_commitment: payload_root(
                "vesting-escrow:allocation",
                &json!({"beneficiary": "alpha", "allocation": "hidden"}),
            ),
            claimed_amount_commitment: payload_root(
                "vesting-escrow:claimed",
                &json!({"beneficiary": "alpha", "claimed": "first-release-pending"}),
            ),
            delegate_hook_commitment: payload_root(
                "vesting-escrow:delegate-hook",
                &json!({"delegate": "beneficiary-alpha-safe", "policy": "pq-session"}),
            ),
            release_nullifier_root: root_from_values(
                "vesting-escrow:beneficiary-nullifiers",
                &["release-nullifier-alpha-0"],
            ),
            status: BeneficiaryStatus::Active,
            privacy_set_size: state.config.min_privacy_set_size,
            added_at_height: height - 19_900,
            last_claim_height: height - 2_000,
        };
        state
            .register_beneficiary(beneficiary.clone())
            .expect("devnet beneficiary");

        let milestone = ReleaseMilestone {
            milestone_id: milestone_id.clone(),
            schedule_id: schedule_id.clone(),
            milestone_index: 0,
            encrypted_condition_root: payload_root(
                "vesting-escrow:milestone-condition",
                &json!({"condition": "cliff-complete", "payload": "hidden"}),
            ),
            attestation_root: payload_root(
                "vesting-escrow:milestone-attestation-root",
                &json!({"committee": "vesting-release-committee", "quorum": 5}),
            ),
            releasable_amount_commitment: payload_root(
                "vesting-escrow:milestone-release",
                &json!({"release": "first-slice", "amount": "hidden"}),
            ),
            release_height: height - 64,
            status: MilestoneStatus::Attested,
        };
        state
            .register_milestone(milestone.clone())
            .expect("devnet milestone");

        let claim_nullifier = nullifier_id(&schedule_id, &beneficiary_id, "claim-alpha-0");
        let claim_id = claim_id(&schedule_id, &beneficiary_id, &claim_nullifier, 0);
        let claim = ClaimIntent {
            claim_id: claim_id.clone(),
            schedule_id: schedule_id.clone(),
            beneficiary_id: beneficiary_id.clone(),
            milestone_id: milestone_id.clone(),
            encrypted_claim_payload: payload_root(
                "vesting-escrow:claim-payload",
                &json!({"ciphertext": "devnet-claim-alpha", "suite": "ml-kem-1024"}),
            ),
            requested_amount_commitment: payload_root(
                "vesting-escrow:requested-amount",
                &json!({"request": "first-release", "amount": "hidden"}),
            ),
            claim_nullifier: claim_nullifier.clone(),
            witness_root: payload_root(
                "vesting-escrow:claim-witness",
                &json!({"schedule": schedule_id.clone(), "milestone": milestone_id.clone()}),
            ),
            fee_quote_commitment: payload_root(
                "vesting-escrow:fee-quote",
                &json!({"sponsor": "vesting-fee-vault", "fee_bps": 3}),
            ),
            status: ClaimStatus::Sponsored,
            privacy_set_size: state.config.min_privacy_set_size,
            created_at_height: height - 12,
            expires_at_height: height + state.config.claim_ttl_blocks,
        };
        state.submit_claim(claim.clone()).expect("devnet claim");

        let reservation_id = sponsor_reservation_id(&claim_id, "vesting-fee-vault", 0);
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            claim_id: claim_id.clone(),
            sponsor_commitment: payload_root(
                "vesting-escrow:sponsor",
                &json!({"vault": "vesting-fee-vault", "strategy": "low-fee-release"}),
            ),
            credit_root: payload_root(
                "vesting-escrow:sponsor-credit",
                &json!({"credit": "devnet-vesting-credit-root", "nonce": 17}),
            ),
            max_fee_amount: 640_000,
            consumed_fee_amount: 420_000,
            sponsor_fee_bps: 3,
            rebate_bps: state.config.target_rebate_bps,
            status: ReservationStatus::RebateQueued,
            created_at_height: height - 10,
            expires_at_height: height + state.config.claim_ttl_blocks,
        };
        state
            .reserve_sponsor(reservation.clone())
            .expect("devnet sponsor");

        let attestation = EscrowAttestation {
            attestation_id: attestation_id(
                &schedule_id,
                &milestone_id,
                AttestationKind::MilestoneEligibility,
                0,
            ),
            schedule_id: schedule_id.clone(),
            subject_id: milestone_id.clone(),
            kind: AttestationKind::MilestoneEligibility,
            verdict: AttestationVerdict::Valid,
            committee_root: payload_root(
                "vesting-escrow:committee",
                &json!({"committee": "vesting-release-committee", "scheme": "ml-dsa-87"}),
            ),
            transcript_root: payload_root(
                "vesting-escrow:attestation-transcript",
                &json!({"height": height - 8, "milestone": milestone_id.clone()}),
            ),
            pq_signature_commitment: payload_root(
                "vesting-escrow:pq-signature",
                &json!({"signature": "devnet-vesting-attestation", "suite": "ml-dsa-87"}),
            ),
            observed_at_height: height - 8,
        };
        state
            .record_attestation(attestation.clone())
            .expect("devnet attestation");

        let batch_id = release_batch_id(&schedule_id, height - 2, 0);
        let batch = ReleaseBatch {
            batch_id: batch_id.clone(),
            schedule_root: root_from_record("vesting-escrow:schedule", &schedule.record()),
            claim_root: root_from_record("vesting-escrow:claim", &claim.record()),
            milestone_root: root_from_record("vesting-escrow:milestone", &milestone.record()),
            reservation_root: root_from_record("vesting-escrow:reservation", &reservation.record()),
            attestation_root: root_from_record("vesting-escrow:attestation", &attestation.record()),
            proof_commitment: payload_root(
                "vesting-escrow:release-proof",
                &json!({"proof": "devnet-private-release-proof", "backend": "recursive-pq"}),
            ),
            status: BatchStatus::Settled,
            claim_count: 1,
            gross_release_commitment: payload_root(
                "vesting-escrow:gross-release",
                &json!({"batch": batch_id.clone(), "amount": "hidden"}),
            ),
            sponsor_fee_amount: reservation.consumed_fee_amount,
            rebate_amount: 210,
            opened_at_height: height - 6,
            sealed_at_height: height - 2,
            expires_at_height: height + state.config.batch_ttl_blocks,
        };
        state.record_batch(batch.clone()).expect("devnet batch");

        let receipt = SettlementReceipt {
            receipt_id: settlement_receipt_id(&batch_id, &claim_id, 0),
            batch_id: batch_id.clone(),
            claim_id: claim_id.clone(),
            reservation_id: reservation_id.clone(),
            kind: ReceiptKind::PrivateClaimSettled,
            release_commitment: payload_root(
                "vesting-escrow:receipt-release",
                &json!({"claim": claim_id.clone(), "release": "hidden"}),
            ),
            fee_amount: reservation.consumed_fee_amount,
            rebate_amount: batch.rebate_amount,
            settlement_root: payload_root(
                "vesting-escrow:settlement",
                &json!({"batch": batch_id.clone(), "claim": claim_id.clone(), "receipt": "settled"}),
            ),
            settled_at_height: height - 1,
        };
        state
            .record_receipt(receipt.clone())
            .expect("devnet receipt");

        let rebate = FeeRebate {
            rebate_id: rebate_id(&receipt.receipt_id, &beneficiary_id, 0),
            receipt_id: receipt.receipt_id.clone(),
            beneficiary_id,
            sponsor_commitment: reservation.sponsor_commitment,
            rebate_amount: receipt.rebate_amount,
            status: RebateStatus::Claimable,
            claim_after_height: height + 1,
            expires_at_height: height + 7_200,
        };
        state.record_rebate(rebate).expect("devnet rebate");
        state.events.push(
            json!({"kind": "devnet_vesting_release", "batch_id": batch_id, "claim_id": claim_id}),
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn register_schedule(
        &mut self,
        schedule: VestingSchedule,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.schedules.len() >= self.config.max_schedules {
            return Err("schedule capacity exceeded".to_string());
        }
        if schedule.privacy_set_size < self.config.min_privacy_set_size {
            return Err("schedule privacy set below runtime floor".to_string());
        }
        if schedule.pq_security_bits < self.config.min_pq_security_bits {
            return Err("schedule pq security below runtime floor".to_string());
        }
        if schedule.end_height <= schedule.start_height {
            return Err("schedule end height must be after start height".to_string());
        }
        self.schedules
            .insert(schedule.schedule_id.clone(), schedule);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn register_beneficiary(
        &mut self,
        beneficiary: BeneficiaryCommitment,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.beneficiaries.len() >= self.config.max_beneficiaries {
            return Err("beneficiary capacity exceeded".to_string());
        }
        let Some(schedule) = self.schedules.get(&beneficiary.schedule_id) else {
            return Err("beneficiary references unknown schedule".to_string());
        };
        if !schedule.status.anchors_state() {
            return Err("beneficiary cannot attach to draft schedule".to_string());
        }
        if beneficiary.privacy_set_size < self.config.min_privacy_set_size {
            return Err("beneficiary privacy set below runtime floor".to_string());
        }
        self.beneficiaries
            .insert(beneficiary.beneficiary_id.clone(), beneficiary);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn register_milestone(
        &mut self,
        milestone: ReleaseMilestone,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.milestones.len() >= self.config.max_milestones {
            return Err("milestone capacity exceeded".to_string());
        }
        if !self.schedules.contains_key(&milestone.schedule_id) {
            return Err("milestone references unknown schedule".to_string());
        }
        self.milestones
            .insert(milestone.milestone_id.clone(), milestone);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn submit_claim(
        &mut self,
        claim: ClaimIntent,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.claims.len() >= self.config.max_claims {
            return Err("claim capacity exceeded".to_string());
        }
        let Some(schedule) = self.schedules.get(&claim.schedule_id) else {
            return Err("claim references unknown schedule".to_string());
        };
        if !schedule.status.accepts_claims() {
            return Err("schedule does not accept claims".to_string());
        }
        let Some(beneficiary) = self.beneficiaries.get(&claim.beneficiary_id) else {
            return Err("claim references unknown beneficiary".to_string());
        };
        if !beneficiary.status.accepts_claims() {
            return Err("beneficiary does not accept claims".to_string());
        }
        if !self.milestones.contains_key(&claim.milestone_id) {
            return Err("claim references unknown milestone".to_string());
        }
        if self.consumed_nullifiers.contains(&claim.claim_nullifier) {
            return Err("claim nullifier already consumed".to_string());
        }
        if claim.privacy_set_size < self.config.min_privacy_set_size {
            return Err("claim privacy set below runtime floor".to_string());
        }
        let fence = NullifierFence {
            nullifier: claim.claim_nullifier.clone(),
            subject_id: claim.claim_id.clone(),
            fence_root: nullifier_fence_leaf(&claim.schedule_id, &claim.claim_nullifier),
            status: NullifierFenceStatus::Locked,
            locked_at_height: claim.created_at_height,
            released_at_height: 0,
        };
        self.consumed_nullifiers
            .insert(claim.claim_nullifier.clone());
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        self.claims.insert(claim.claim_id.clone(), claim);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_sponsor(
        &mut self,
        reservation: SponsorReservation,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation capacity exceeded".to_string());
        }
        if !self.claims.contains_key(&reservation.claim_id) {
            return Err("reservation references unknown claim".to_string());
        }
        if reservation.sponsor_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("reservation sponsor fee above runtime ceiling".to_string());
        }
        if reservation.consumed_fee_amount > reservation.max_fee_amount {
            return Err("reservation consumed fee exceeds max fee".to_string());
        }
        self.sponsor_credit_roots.insert(
            reservation.sponsor_commitment.clone(),
            reservation.credit_root.clone(),
        );
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        attestation: EscrowAttestation,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exceeded".to_string());
        }
        if !self.schedules.contains_key(&attestation.schedule_id) {
            return Err("attestation references unknown schedule".to_string());
        }
        if !attestation.verdict.contributes_to_quorum() {
            return Err("attestation verdict does not contribute to quorum".to_string());
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_batch(
        &mut self,
        batch: ReleaseBatch,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.batches.len() >= self.config.max_batches {
            return Err("batch capacity exceeded".to_string());
        }
        if batch.claim_count as usize > self.config.max_batch_claims {
            return Err("batch claim count exceeds runtime limit".to_string());
        }
        if !batch.status.anchors_state() && batch.status != BatchStatus::Open {
            return Err("batch status is not recordable".to_string());
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err("receipt references unknown batch".to_string());
        }
        if !self.claims.contains_key(&receipt.claim_id) {
            return Err("receipt references unknown claim".to_string());
        }
        if !self.reservations.contains_key(&receipt.reservation_id) {
            return Err("receipt references unknown reservation".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_rebate(
        &mut self,
        rebate: FeeRebate,
    ) -> PrivateL2ConfidentialContractVestingEscrowRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            schedule_count: self.schedules.len() as u64,
            active_schedule_count: self
                .schedules
                .values()
                .filter(|schedule| schedule.status.accepts_claims())
                .count() as u64,
            beneficiary_count: self.beneficiaries.len() as u64,
            active_beneficiary_count: self
                .beneficiaries
                .values()
                .filter(|beneficiary| beneficiary.status.accepts_claims())
                .count() as u64,
            milestone_count: self.milestones.len() as u64,
            releasable_milestone_count: self
                .milestones
                .values()
                .filter(|milestone| milestone.status.contributes_release())
                .count() as u64,
            claim_count: self.claims.len() as u64,
            open_claim_count: self
                .claims
                .values()
                .filter(|claim| claim.status.is_open())
                .count() as u64,
            reservation_count: self.reservations.len() as u64,
            batch_count: self.batches.len() as u64,
            settled_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Settled)
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            rebate_count: self.rebates.len() as u64,
            attestation_count: self.attestations.len() as u64,
            locked_nullifier_count: self
                .nullifier_fences
                .values()
                .filter(|fence| fence.status == NullifierFenceStatus::Locked)
                .count() as u64,
            event_count: self.events.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        let schedule_records = self
            .schedules
            .values()
            .map(VestingSchedule::record)
            .collect::<Vec<_>>();
        let active_schedule_records = self
            .schedules
            .values()
            .filter(|schedule| schedule.status.accepts_claims())
            .map(VestingSchedule::record)
            .collect::<Vec<_>>();
        let beneficiary_records = self
            .beneficiaries
            .values()
            .map(BeneficiaryCommitment::record)
            .collect::<Vec<_>>();
        let active_beneficiary_records = self
            .beneficiaries
            .values()
            .filter(|beneficiary| beneficiary.status.accepts_claims())
            .map(BeneficiaryCommitment::record)
            .collect::<Vec<_>>();
        let milestone_records = self
            .milestones
            .values()
            .map(ReleaseMilestone::record)
            .collect::<Vec<_>>();
        let releasable_milestone_records = self
            .milestones
            .values()
            .filter(|milestone| milestone.status.contributes_release())
            .map(ReleaseMilestone::record)
            .collect::<Vec<_>>();
        let claim_records = self
            .claims
            .values()
            .map(ClaimIntent::record)
            .collect::<Vec<_>>();
        let open_claim_records = self
            .claims
            .values()
            .filter(|claim| claim.status.is_open())
            .map(ClaimIntent::record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .reservations
            .values()
            .map(SponsorReservation::record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(ReleaseBatch::record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(SettlementReceipt::record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(FeeRebate::record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(EscrowAttestation::record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .nullifier_fences
            .values()
            .map(NullifierFence::record)
            .collect::<Vec<_>>();
        let consumed_nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({"nullifier": nullifier}))
            .collect::<Vec<_>>();
        let sponsor_credit_records = self
            .sponsor_credit_roots
            .iter()
            .map(|(sponsor, root)| json!({"sponsor": sponsor, "credit_root": root}))
            .collect::<Vec<_>>();

        self.roots.schedule_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-SCHEDULES",
            &schedule_records,
        );
        self.roots.active_schedule_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-ACTIVE-SCHEDULES",
            &active_schedule_records,
        );
        self.roots.beneficiary_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-BENEFICIARIES",
            &beneficiary_records,
        );
        self.roots.active_beneficiary_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-ACTIVE-BENEFICIARIES",
            &active_beneficiary_records,
        );
        self.roots.milestone_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-MILESTONES",
            &milestone_records,
        );
        self.roots.releasable_milestone_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-RELEASABLE-MILESTONES",
            &releasable_milestone_records,
        );
        self.roots.claim_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-CLAIMS", &claim_records);
        self.roots.open_claim_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-OPEN-CLAIMS",
            &open_claim_records,
        );
        self.roots.reservation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-RESERVATIONS",
            &reservation_records,
        );
        self.roots.batch_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-BATCHES", &batch_records);
        self.roots.receipt_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-RECEIPTS", &receipt_records);
        self.roots.rebate_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-REBATES", &rebate_records);
        self.roots.attestation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-ATTESTATIONS",
            &attestation_records,
        );
        self.roots.nullifier_fence_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-NULLIFIER-FENCES",
            &nullifier_records,
        );
        self.roots.consumed_nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-CONSUMED-NULLIFIERS",
            &consumed_nullifier_records,
        );
        self.roots.sponsor_credit_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-VESTING-SPONSOR-CREDITS",
            &sponsor_credit_records,
        );
        self.roots.event_root = merkle_root("PRIVATE-L2-CONFIDENTIAL-VESTING-EVENTS", &self.events);
        let record = self.public_record();
        self.roots.public_record_root =
            root_from_record("PRIVATE-L2-CONFIDENTIAL-VESTING-PUBLIC-RECORD", &record);
        self.roots.state_root = state_root_from_record(&record);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "counters": self.counters,
            "roots": self.roots,
            "limits": {
                "max_schedules": self.config.max_schedules,
                "max_beneficiaries": self.config.max_beneficiaries,
                "max_claims": self.config.max_claims,
                "max_batch_claims": self.config.max_batch_claims,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "max_sponsor_fee_bps": self.config.max_sponsor_fee_bps,
                "target_rebate_bps": self.config.target_rebate_bps,
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_confidential_contract_vesting_escrow_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_confidential_contract_vesting_escrow_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn schedule_id(
    asset_kind: VestingAssetKind,
    issuer_commitment: &str,
    asset_commitment: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-SCHEDULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_kind.as_str()),
            HashPart::Str(issuer_commitment),
            HashPart::Str(asset_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn beneficiary_id(schedule_id: &str, beneficiary_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-BENEFICIARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(beneficiary_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn milestone_id(schedule_id: &str, milestone_index: u64, release_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-MILESTONE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::U64(milestone_index),
            HashPart::U64(release_height),
        ],
        32,
    )
}

pub fn claim_id(
    schedule_id: &str,
    beneficiary_id: &str,
    claim_nullifier: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(beneficiary_id),
            HashPart::Str(claim_nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(claim_id: &str, sponsor_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(sponsor_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn release_batch_id(schedule_id: &str, sealed_at_height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-RELEASE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::U64(sealed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, claim_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(claim_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn attestation_id(
    schedule_id: &str,
    subject_id: &str,
    kind: AttestationKind,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(subject_id),
            HashPart::Str(match kind {
                AttestationKind::ScheduleIntegrity => "schedule_integrity",
                AttestationKind::BeneficiarySet => "beneficiary_set",
                AttestationKind::MilestoneEligibility => "milestone_eligibility",
                AttestationKind::ReleaseComputation => "release_computation",
                AttestationKind::ContractHook => "contract_hook",
                AttestationKind::PqAuthorization => "pq_authorization",
            }),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_id(schedule_id: &str, beneficiary_id: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(beneficiary_id),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn nullifier_fence_leaf(schedule_id: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-NULLIFIER-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn escrow_account_id(schedule_id: &str, role_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-VESTING-ESCROW-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(role_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_CONTRACT_VESTING_ESCROW_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-VESTING-STATE-ROOT", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}
