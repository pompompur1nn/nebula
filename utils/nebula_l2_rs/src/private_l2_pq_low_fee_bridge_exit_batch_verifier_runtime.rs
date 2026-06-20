use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqLowFeeBridgeExitBatchVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_LOW_FEE_BRIDGE_EXIT_BATCH_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-pq-low-fee-bridge-exit-batch-verifier-runtime-v1";
const CHAIN_ID: &str = "nebula-l2-devnet";
const MAX_BPS: u64 = 10_000;
const MAX_EXIT_NOTES_PER_BATCH: usize = 128;
const MAX_COMMITTEE_MEMBERS: usize = 96;
const MAX_EVENTS: usize = 8192;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitLane {
    FastRetail,
    DefiLiquidity,
    BridgeMarketMaker,
    EmergencyEscape,
}

impl ExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            ExitLane::FastRetail => "fast_retail",
            ExitLane::DefiLiquidity => "defi_liquidity",
            ExitLane::BridgeMarketMaker => "bridge_market_maker",
            ExitLane::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn target_latency_ms(self) -> u64 {
        match self {
            ExitLane::FastRetail => 350,
            ExitLane::DefiLiquidity => 500,
            ExitLane::BridgeMarketMaker => 450,
            ExitLane::EmergencyEscape => 175,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitNoteKind {
    MoneroPayout,
    LiquidityProviderRedeem,
    AtomicSwapRefund,
    EmergencyWithdrawal,
}

impl ExitNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ExitNoteKind::MoneroPayout => "monero_payout",
            ExitNoteKind::LiquidityProviderRedeem => "liquidity_provider_redeem",
            ExitNoteKind::AtomicSwapRefund => "atomic_swap_refund",
            ExitNoteKind::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitNoteStatus {
    Submitted,
    Batched,
    Rejected,
    Settled,
}

impl ExitNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ExitNoteStatus::Submitted => "submitted",
            ExitNoteStatus::Batched => "batched",
            ExitNoteStatus::Rejected => "rejected",
            ExitNoteStatus::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchStatus {
    Open,
    Verified,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            BatchStatus::Open => "open",
            BatchStatus::Verified => "verified",
            BatchStatus::Settled => "settled",
            BatchStatus::Disputed => "disputed",
            BatchStatus::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitteeStatus {
    Active,
    Retiring,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CommitteeStatus::Active => "active",
            CommitteeStatus::Retiring => "retiring",
            CommitteeStatus::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationVerdict {
    Valid,
    InvalidSpendProof,
    InvalidMoneroAddress,
    StaleAnchor,
    InsufficientCommitteeWeight,
}

impl VerificationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationVerdict::Valid => "valid",
            VerificationVerdict::InvalidSpendProof => "invalid_spend_proof",
            VerificationVerdict::InvalidMoneroAddress => "invalid_monero_address",
            VerificationVerdict::StaleAnchor => "stale_anchor",
            VerificationVerdict::InsufficientCommitteeWeight => "insufficient_committee_weight",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SponsorStatus {
    Reserved,
    Applied,
    Refunded,
    Slashed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SponsorStatus::Reserved => "reserved",
            SponsorStatus::Applied => "applied",
            SponsorStatus::Refunded => "refunded",
            SponsorStatus::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptKind {
    FastExit,
    MoneroAnchor,
    LiquidityProviderFill,
    EmergencyExit,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptKind::FastExit => "fast_exit",
            ReceiptKind::MoneroAnchor => "monero_anchor",
            ReceiptKind::LiquidityProviderFill => "liquidity_provider_fill",
            ReceiptKind::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RebateStatus {
    Queued,
    Paid,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RebateStatus::Queued => "queued",
            RebateStatus::Paid => "paid",
            RebateStatus::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FenceKind {
    ExitNullifier,
    AddressReplay,
    CommitteeReplay,
    EmergencyEscape,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FenceKind::ExitNullifier => "exit_nullifier",
            FenceKind::AddressReplay => "address_replay",
            FenceKind::CommitteeReplay => "committee_replay",
            FenceKind::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlashingReason {
    FalseAttestation,
    DoubleExit,
    WithheldBatch,
    InvalidMoneroAnchor,
    FeeOvercharge,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SlashingReason::FalseAttestation => "false_attestation",
            SlashingReason::DoubleExit => "double_exit",
            SlashingReason::WithheldBatch => "withheld_batch",
            SlashingReason::InvalidMoneroAnchor => "invalid_monero_anchor",
            SlashingReason::FeeOvercharge => "fee_overcharge",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub runtime_version: String,
    pub min_committee_weight: u64,
    pub quorum_bps: u64,
    pub max_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_exit_notes_per_batch: usize,
    pub max_committee_members: usize,
    pub max_anchor_age_blocks: u64,
    pub emergency_lane_enabled: bool,
    pub pq_scheme_root: String,
    pub monero_anchor_domain: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_version:
                PRIVATE_L2_PQ_LOW_FEE_BRIDGE_EXIT_BATCH_VERIFIER_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            min_committee_weight: 5,
            quorum_bps: 6700,
            max_fee_bps: 70,
            low_fee_rebate_bps: 2200,
            max_exit_notes_per_batch: 64,
            max_committee_members: 48,
            max_anchor_age_blocks: 20,
            emergency_lane_enabled: true,
            pq_scheme_root: commitment("bridge-exit ML-DSA-87 quorum"),
            monero_anchor_domain: "monero-devnet-exit-anchor".to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        require_non_empty("runtime_version", &self.runtime_version)?;
        require_bps("quorum_bps", self.quorum_bps)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.min_committee_weight == 0 {
            return Err("min_committee_weight must be non-zero".to_string());
        }
        if self.quorum_bps < 5000 {
            return Err("quorum_bps must be at least a majority".to_string());
        }
        if self.max_exit_notes_per_batch == 0
            || self.max_exit_notes_per_batch > MAX_EXIT_NOTES_PER_BATCH
        {
            return Err(format!(
                "max_exit_notes_per_batch must be between 1 and {MAX_EXIT_NOTES_PER_BATCH}"
            ));
        }
        if self.max_committee_members == 0 || self.max_committee_members > MAX_COMMITTEE_MEMBERS {
            return Err(format!(
                "max_committee_members must be between 1 and {MAX_COMMITTEE_MEMBERS}"
            ));
        }
        require_root("pq_scheme_root", &self.pq_scheme_root)?;
        require_non_empty("monero_anchor_domain", &self.monero_anchor_domain)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "runtime_version": self.runtime_version,
            "min_committee_weight": self.min_committee_weight,
            "quorum_bps": self.quorum_bps,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_exit_notes_per_batch": self.max_exit_notes_per_batch,
            "max_committee_members": self.max_committee_members,
            "max_anchor_age_blocks": self.max_anchor_age_blocks,
            "emergency_lane_enabled": self.emergency_lane_enabled,
            "pq_scheme_root": self.pq_scheme_root,
            "monero_anchor_domain": self.monero_anchor_domain,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub committees: u64,
    pub exit_notes: u64,
    pub batches: u64,
    pub verifications: u64,
    pub sponsor_reservations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub slashing_events: u64,
    pub runtime_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committees": self.committees,
            "exit_notes": self.exit_notes,
            "batches": self.batches,
            "verifications": self.verifications,
            "sponsor_reservations": self.sponsor_reservations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "slashing_events": self.slashing_events,
            "runtime_events": self.runtime_events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub committees_root: String,
    pub exit_notes_root: String,
    pub batches_root: String,
    pub verifications_root: String,
    pub sponsor_reservations_root: String,
    pub receipts_root: String,
    pub rebates_root: String,
    pub privacy_fences_root: String,
    pub slashing_events_root: String,
    pub spent_nullifiers_root: String,
    pub runtime_events_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            committees_root: empty_root("COMMITTEES"),
            exit_notes_root: empty_root("EXIT-NOTES"),
            batches_root: empty_root("BATCHES"),
            verifications_root: empty_root("VERIFICATIONS"),
            sponsor_reservations_root: empty_root("SPONSOR-RESERVATIONS"),
            receipts_root: empty_root("RECEIPTS"),
            rebates_root: empty_root("REBATES"),
            privacy_fences_root: empty_root("PRIVACY-FENCES"),
            slashing_events_root: empty_root("SLASHING-EVENTS"),
            spent_nullifiers_root: empty_root("SPENT-NULLIFIERS"),
            runtime_events_root: empty_root("RUNTIME-EVENTS"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committees_root": self.committees_root,
            "exit_notes_root": self.exit_notes_root,
            "batches_root": self.batches_root,
            "verifications_root": self.verifications_root,
            "sponsor_reservations_root": self.sponsor_reservations_root,
            "receipts_root": self.receipts_root,
            "rebates_root": self.rebates_root,
            "privacy_fences_root": self.privacy_fences_root,
            "slashing_events_root": self.slashing_events_root,
            "spent_nullifiers_root": self.spent_nullifiers_root,
            "runtime_events_root": self.runtime_events_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterCommitteeRequest {
    pub committee_label: String,
    pub epoch: u64,
    pub pq_public_key_root: String,
    pub member_set_root: String,
    pub aggregate_weight: u64,
    pub activated_at_height: u64,
}

impl RegisterCommitteeRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("committee_label", &self.committee_label)?;
        require_root("pq_public_key_root", &self.pq_public_key_root)?;
        require_root("member_set_root", &self.member_set_root)?;
        if self.aggregate_weight < config.min_committee_weight {
            return Err("aggregate_weight below min committee weight".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeRecord {
    pub committee_id: String,
    pub committee_label: String,
    pub epoch: u64,
    pub pq_public_key_root: String,
    pub member_set_root: String,
    pub aggregate_weight: u64,
    pub activated_at_height: u64,
    pub status: CommitteeStatus,
}

impl CommitteeRecord {
    pub fn from_request(request: RegisterCommitteeRequest, config: &Config) -> Result<Self> {
        request.validate(config)?;
        let committee_id = committee_id(&request);
        Ok(Self {
            committee_id,
            committee_label: request.committee_label,
            epoch: request.epoch,
            pq_public_key_root: request.pq_public_key_root,
            member_set_root: request.member_set_root,
            aggregate_weight: request.aggregate_weight,
            activated_at_height: request.activated_at_height,
            status: CommitteeStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "committee_label": self.committee_label,
            "epoch": self.epoch,
            "pq_public_key_root": self.pq_public_key_root,
            "member_set_root": self.member_set_root,
            "aggregate_weight": self.aggregate_weight,
            "activated_at_height": self.activated_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitExitNoteRequest {
    pub lane: ExitLane,
    pub note_kind: ExitNoteKind,
    pub owner_commitment: String,
    pub encrypted_monero_address_root: String,
    pub amount_commitment: String,
    pub spend_authorization_root: String,
    pub source_note_root: String,
    pub monero_anchor_root: String,
    pub submitted_at_height: u64,
    pub max_fee_bps: u64,
    pub nullifier_root: String,
}

impl SubmitExitNoteRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("owner_commitment", &self.owner_commitment)?;
        require_root(
            "encrypted_monero_address_root",
            &self.encrypted_monero_address_root,
        )?;
        require_root("amount_commitment", &self.amount_commitment)?;
        require_root("spend_authorization_root", &self.spend_authorization_root)?;
        require_root("source_note_root", &self.source_note_root)?;
        require_root("monero_anchor_root", &self.monero_anchor_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("exit max_fee_bps exceeds runtime fee cap".to_string());
        }
        if self.lane == ExitLane::EmergencyEscape && !config.emergency_lane_enabled {
            return Err("emergency exit lane disabled".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitNote {
    pub exit_note_id: String,
    pub lane: ExitLane,
    pub note_kind: ExitNoteKind,
    pub owner_commitment: String,
    pub encrypted_monero_address_root: String,
    pub amount_commitment: String,
    pub spend_authorization_root: String,
    pub source_note_root: String,
    pub monero_anchor_root: String,
    pub submitted_at_height: u64,
    pub max_fee_bps: u64,
    pub nullifier_root: String,
    pub status: ExitNoteStatus,
}

impl ExitNote {
    pub fn from_request(
        request: SubmitExitNoteRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let exit_note_id = exit_note_id(&request, sequence);
        Ok(Self {
            exit_note_id,
            lane: request.lane,
            note_kind: request.note_kind,
            owner_commitment: request.owner_commitment,
            encrypted_monero_address_root: request.encrypted_monero_address_root,
            amount_commitment: request.amount_commitment,
            spend_authorization_root: request.spend_authorization_root,
            source_note_root: request.source_note_root,
            monero_anchor_root: request.monero_anchor_root,
            submitted_at_height: request.submitted_at_height,
            max_fee_bps: request.max_fee_bps,
            nullifier_root: request.nullifier_root,
            status: ExitNoteStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_note_id": self.exit_note_id,
            "lane": self.lane.as_str(),
            "note_kind": self.note_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "encrypted_monero_address_root": self.encrypted_monero_address_root,
            "amount_commitment": self.amount_commitment,
            "spend_authorization_root": self.spend_authorization_root,
            "source_note_root": self.source_note_root,
            "monero_anchor_root": self.monero_anchor_root,
            "submitted_at_height": self.submitted_at_height,
            "max_fee_bps": self.max_fee_bps,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildExitBatchRequest {
    pub lane: ExitLane,
    pub committee_id: String,
    pub exit_note_ids: Vec<String>,
    pub batch_policy_root: String,
    pub monero_anchor_root: String,
    pub expires_at_height: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildExitBatchRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("committee_id", &self.committee_id)?;
        if self.exit_note_ids.is_empty() {
            return Err("exit_note_ids must not be empty".to_string());
        }
        if self.exit_note_ids.len() > config.max_exit_notes_per_batch {
            return Err("exit_note_ids exceeds configured batch cap".to_string());
        }
        require_root("batch_policy_root", &self.batch_policy_root)?;
        require_root("monero_anchor_root", &self.monero_anchor_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("batch max_fee_bps exceeds runtime fee cap".to_string());
        }
        if self.expires_at_height <= self.built_at_height {
            return Err("expires_at_height must be after built_at_height".to_string());
        }
        if self.lane == ExitLane::EmergencyEscape && !config.emergency_lane_enabled {
            return Err("emergency exit lane disabled".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitBatch {
    pub batch_id: String,
    pub lane: ExitLane,
    pub committee_id: String,
    pub exit_note_ids: Vec<String>,
    pub exit_note_set_root: String,
    pub batch_policy_root: String,
    pub monero_anchor_root: String,
    pub expires_at_height: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
    pub verification_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub status: BatchStatus,
}

impl ExitBatch {
    pub fn from_request(
        request: BuildExitBatchRequest,
        exit_note_set_root: String,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let batch_id = exit_batch_id(&request, &exit_note_set_root, sequence);
        Ok(Self {
            batch_id,
            lane: request.lane,
            committee_id: request.committee_id,
            exit_note_ids: request.exit_note_ids,
            exit_note_set_root,
            batch_policy_root: request.batch_policy_root,
            monero_anchor_root: request.monero_anchor_root,
            expires_at_height: request.expires_at_height,
            max_fee_bps: request.max_fee_bps,
            built_at_height: request.built_at_height,
            verification_ids: Vec::new(),
            sponsor_reservation_ids: Vec::new(),
            receipt_ids: Vec::new(),
            status: BatchStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "committee_id": self.committee_id,
            "exit_note_ids": self.exit_note_ids,
            "exit_note_set_root": self.exit_note_set_root,
            "batch_policy_root": self.batch_policy_root,
            "monero_anchor_root": self.monero_anchor_root,
            "expires_at_height": self.expires_at_height,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
            "verification_ids": self.verification_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "receipt_ids": self.receipt_ids,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyExitBatchRequest {
    pub batch_id: String,
    pub committee_id: String,
    pub attester_commitment_root: String,
    pub pq_signature_root: String,
    pub verified_exit_set_root: String,
    pub monero_anchor_height: u64,
    pub signer_weight: u64,
    pub verdict: VerificationVerdict,
    pub verified_at_height: u64,
    pub nullifier_root: String,
}

impl VerifyExitBatchRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_root("attester_commitment_root", &self.attester_commitment_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_root("verified_exit_set_root", &self.verified_exit_set_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        if self.signer_weight == 0 {
            return Err("signer_weight must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchVerification {
    pub verification_id: String,
    pub batch_id: String,
    pub committee_id: String,
    pub attester_commitment_root: String,
    pub pq_signature_root: String,
    pub verified_exit_set_root: String,
    pub monero_anchor_height: u64,
    pub signer_weight: u64,
    pub verdict: VerificationVerdict,
    pub verified_at_height: u64,
    pub nullifier_root: String,
}

impl BatchVerification {
    pub fn from_request(request: VerifyExitBatchRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let verification_id = batch_verification_id(&request, sequence);
        Ok(Self {
            verification_id,
            batch_id: request.batch_id,
            committee_id: request.committee_id,
            attester_commitment_root: request.attester_commitment_root,
            pq_signature_root: request.pq_signature_root,
            verified_exit_set_root: request.verified_exit_set_root,
            monero_anchor_height: request.monero_anchor_height,
            signer_weight: request.signer_weight,
            verdict: request.verdict,
            verified_at_height: request.verified_at_height,
            nullifier_root: request.nullifier_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verification_id": self.verification_id,
            "batch_id": self.batch_id,
            "committee_id": self.committee_id,
            "attester_commitment_root": self.attester_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "verified_exit_set_root": self.verified_exit_set_root,
            "monero_anchor_height": self.monero_anchor_height,
            "signer_weight": self.signer_weight,
            "verdict": self.verdict.as_str(),
            "verified_at_height": self.verified_at_height,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReserveSponsorRequest {
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
}

impl ReserveSponsorRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("fee_note_root", &self.fee_note_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("sponsor max_fee_bps exceeds runtime fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
    pub status: SponsorStatus,
}

impl SponsorReservation {
    pub fn from_request(
        request: ReserveSponsorRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        Ok(Self {
            reservation_id,
            batch_id: request.batch_id,
            sponsor_commitment: request.sponsor_commitment,
            fee_note_root: request.fee_note_root,
            max_fee_bps: request.max_fee_bps,
            expires_at_height: request.expires_at_height,
            nullifier_root: request.nullifier_root,
            status: SponsorStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_note_root": self.fee_note_root,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishReceiptRequest {
    pub batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub monero_tx_set_root: String,
    pub verified_exit_set_root: String,
    pub fee_charged_bps: u64,
    pub settled_at_height: u64,
}

impl PublishReceiptRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("monero_tx_set_root", &self.monero_tx_set_root)?;
        require_root("verified_exit_set_root", &self.verified_exit_set_root)?;
        require_bps("fee_charged_bps", self.fee_charged_bps)?;
        if self.fee_charged_bps > config.max_fee_bps {
            return Err("fee_charged_bps exceeds runtime cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub monero_tx_set_root: String,
    pub verified_exit_set_root: String,
    pub fee_charged_bps: u64,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn from_request(
        request: PublishReceiptRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let receipt_id = settlement_receipt_id(&request, sequence);
        Ok(Self {
            receipt_id,
            batch_id: request.batch_id,
            receipt_kind: request.receipt_kind,
            monero_tx_set_root: request.monero_tx_set_root,
            verified_exit_set_root: request.verified_exit_set_root,
            fee_charged_bps: request.fee_charged_bps,
            settled_at_height: request.settled_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "monero_tx_set_root": self.monero_tx_set_root,
            "verified_exit_set_root": self.verified_exit_set_root,
            "fee_charged_bps": self.fee_charged_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueRebateRequest {
    pub batch_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
}

impl IssueRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_root("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_root("rebate_note_root", &self.rebate_note_root)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.low_fee_rebate_bps {
            return Err("rebate_bps exceeds configured rebate cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub status: RebateStatus,
}

impl FeeRebate {
    pub fn from_request(
        request: IssueRebateRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let rebate_id = fee_rebate_id(&request, sequence);
        Ok(Self {
            rebate_id,
            batch_id: request.batch_id,
            receipt_id: request.receipt_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_note_root: request.rebate_note_root,
            rebate_bps: request.rebate_bps,
            status: RebateStatus::Queued,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenPrivacyFenceRequest {
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub nullifier_root: String,
    pub effective_height: u64,
}

impl OpenPrivacyFenceRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("commitment_root", &self.commitment_root)?;
        require_non_empty("replay_domain", &self.replay_domain)?;
        require_root("nullifier_root", &self.nullifier_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub nullifier_root: String,
    pub effective_height: u64,
}

impl PrivacyFence {
    pub fn from_request(request: OpenPrivacyFenceRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let fence_id = privacy_fence_id(&request, sequence);
        Ok(Self {
            fence_id,
            fence_kind: request.fence_kind,
            subject_id: request.subject_id,
            commitment_root: request.commitment_root,
            replay_domain: request.replay_domain,
            nullifier_root: request.nullifier_root,
            effective_height: request.effective_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "replay_domain": self.replay_domain,
            "nullifier_root": self.nullifier_root,
            "effective_height": self.effective_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordSlashingRequest {
    pub batch_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_note_root: String,
    pub recorded_at_height: u64,
}

impl RecordSlashingRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("offender_commitment", &self.offender_commitment)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_root("penalty_note_root", &self.penalty_note_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvent {
    pub slashing_id: String,
    pub batch_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_note_root: String,
    pub recorded_at_height: u64,
}

impl SlashingEvent {
    pub fn from_request(request: RecordSlashingRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let slashing_id = slashing_id(&request, sequence);
        Ok(Self {
            slashing_id,
            batch_id: request.batch_id,
            offender_commitment: request.offender_commitment,
            reason: request.reason,
            evidence_root: request.evidence_root,
            penalty_note_root: request.penalty_note_root,
            recorded_at_height: request.recorded_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "batch_id": self.batch_id,
            "offender_commitment": self.offender_commitment,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "penalty_note_root": self.penalty_note_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = payload_root("RUNTIME-EVENT", payload);
        Self {
            event_id: runtime_event_id(event_kind, subject_id, &payload_root, height, sequence),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub committees: BTreeMap<String, CommitteeRecord>,
    pub exit_notes: BTreeMap<String, ExitNote>,
    pub batches: BTreeMap<String, ExitBatch>,
    pub verifications: BTreeMap<String, BatchVerification>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_events: BTreeMap<String, SlashingEvent>,
    pub spent_nullifiers: BTreeSet<String>,
    pub runtime_events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            committees: BTreeMap::new(),
            exit_notes: BTreeMap::new(),
            batches: BTreeMap::new(),
            verifications: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            runtime_events: Vec::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config must validate");
        let committee = state
            .register_committee(RegisterCommitteeRequest {
                committee_label: "devnet-fast-exit-committee".to_string(),
                epoch: 1,
                pq_public_key_root: commitment("devnet bridge exit pq key"),
                member_set_root: commitment("devnet bridge exit members"),
                aggregate_weight: 9,
                activated_at_height: 1,
            })
            .expect("devnet committee must register");
        let note_a = state
            .submit_exit_note(SubmitExitNoteRequest {
                lane: ExitLane::FastRetail,
                note_kind: ExitNoteKind::MoneroPayout,
                owner_commitment: commitment("owner a"),
                encrypted_monero_address_root: commitment("encrypted monero address a"),
                amount_commitment: commitment("amount a"),
                spend_authorization_root: commitment("spend authorization a"),
                source_note_root: commitment("source note a"),
                monero_anchor_root: commitment("monero anchor a"),
                submitted_at_height: 10,
                max_fee_bps: 10,
                nullifier_root: commitment("exit note a nullifier"),
            })
            .expect("devnet exit note a must submit");
        let note_b = state
            .submit_exit_note(SubmitExitNoteRequest {
                lane: ExitLane::FastRetail,
                note_kind: ExitNoteKind::LiquidityProviderRedeem,
                owner_commitment: commitment("owner b"),
                encrypted_monero_address_root: commitment("encrypted monero address b"),
                amount_commitment: commitment("amount b"),
                spend_authorization_root: commitment("spend authorization b"),
                source_note_root: commitment("source note b"),
                monero_anchor_root: commitment("monero anchor b"),
                submitted_at_height: 11,
                max_fee_bps: 10,
                nullifier_root: commitment("exit note b nullifier"),
            })
            .expect("devnet exit note b must submit");
        let batch = state
            .build_exit_batch(BuildExitBatchRequest {
                lane: ExitLane::FastRetail,
                committee_id: committee.committee_id.clone(),
                exit_note_ids: vec![note_a.exit_note_id.clone(), note_b.exit_note_id.clone()],
                batch_policy_root: commitment("fast exit batch policy"),
                monero_anchor_root: commitment("batched monero anchor"),
                expires_at_height: 24,
                max_fee_bps: 10,
                built_at_height: 12,
            })
            .expect("devnet batch must build");
        let verification = state
            .verify_exit_batch(VerifyExitBatchRequest {
                batch_id: batch.batch_id.clone(),
                committee_id: committee.committee_id.clone(),
                attester_commitment_root: commitment("bridge verifier"),
                pq_signature_root: commitment("bridge verifier pq signature"),
                verified_exit_set_root: batch.exit_note_set_root.clone(),
                monero_anchor_height: 128,
                signer_weight: 7,
                verdict: VerificationVerdict::Valid,
                verified_at_height: 13,
                nullifier_root: commitment("verification nullifier"),
            })
            .expect("devnet verification must record");
        let reservation = state
            .reserve_sponsor(ReserveSponsorRequest {
                batch_id: batch.batch_id.clone(),
                sponsor_commitment: commitment("fast exit sponsor"),
                fee_note_root: commitment("fast exit sponsor fee"),
                max_fee_bps: 10,
                expires_at_height: 28,
                nullifier_root: commitment("sponsor nullifier"),
            })
            .expect("devnet sponsor must reserve");
        let receipt = state
            .publish_receipt(PublishReceiptRequest {
                batch_id: batch.batch_id.clone(),
                receipt_kind: ReceiptKind::FastExit,
                monero_tx_set_root: commitment("monero tx set"),
                verified_exit_set_root: verification.verified_exit_set_root.clone(),
                fee_charged_bps: 8,
                settled_at_height: 15,
            })
            .expect("devnet receipt must publish");
        let _rebate = state
            .issue_rebate(IssueRebateRequest {
                batch_id: batch.batch_id.clone(),
                receipt_id: receipt.receipt_id.clone(),
                beneficiary_commitment: reservation.sponsor_commitment.clone(),
                rebate_note_root: commitment("fast exit rebate"),
                rebate_bps: 600,
            })
            .expect("devnet rebate must queue");
        let _fence = state
            .open_privacy_fence(OpenPrivacyFenceRequest {
                fence_kind: FenceKind::ExitNullifier,
                subject_id: batch.batch_id.clone(),
                commitment_root: commitment("fast exit replay fence"),
                replay_domain: "bridge-exit-devnet".to_string(),
                nullifier_root: commitment("privacy fence nullifier"),
                effective_height: 15,
            })
            .expect("devnet fence must open");
        state
    }

    pub fn register_committee(
        &mut self,
        request: RegisterCommitteeRequest,
    ) -> Result<CommitteeRecord> {
        let committee = CommitteeRecord::from_request(request, &self.config)?;
        if self.committees.contains_key(&committee.committee_id) {
            return Err("committee already registered".to_string());
        }
        self.counters.committees = self.counters.committees.saturating_add(1);
        self.emit_event(
            "committee_registered",
            &committee.committee_id,
            &committee.public_record(),
            committee.activated_at_height,
        );
        self.committees
            .insert(committee.committee_id.clone(), committee.clone());
        self.recompute_roots();
        Ok(committee)
    }

    pub fn submit_exit_note(&mut self, request: SubmitExitNoteRequest) -> Result<ExitNote> {
        request.validate(&self.config)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let note = ExitNote::from_request(
            request,
            self.counters.exit_notes.saturating_add(1),
            &self.config,
        )?;
        self.counters.exit_notes = self.counters.exit_notes.saturating_add(1);
        self.emit_event(
            "exit_note_submitted",
            &note.exit_note_id,
            &note.public_record(),
            note.submitted_at_height,
        );
        self.exit_notes
            .insert(note.exit_note_id.clone(), note.clone());
        self.recompute_roots();
        Ok(note)
    }

    pub fn build_exit_batch(&mut self, request: BuildExitBatchRequest) -> Result<ExitBatch> {
        request.validate(&self.config)?;
        self.ensure_committee_active(&request.committee_id)?;
        for note_id in &request.exit_note_ids {
            let note = self
                .exit_notes
                .get(note_id)
                .ok_or_else(|| format!("exit note {note_id} missing"))?;
            if note.status != ExitNoteStatus::Submitted {
                return Err(format!("exit note {note_id} is not submitted"));
            }
        }
        let note_records = request
            .exit_note_ids
            .iter()
            .filter_map(|id| self.exit_notes.get(id))
            .map(ExitNote::public_record)
            .collect::<Vec<_>>();
        let exit_note_set_root = public_record_root("EXIT-NOTE-SET", &note_records);
        let batch = ExitBatch::from_request(
            request,
            exit_note_set_root,
            self.counters.batches.saturating_add(1),
            &self.config,
        )?;
        for note_id in &batch.exit_note_ids {
            if let Some(note) = self.exit_notes.get_mut(note_id) {
                note.status = ExitNoteStatus::Batched;
            }
        }
        self.counters.batches = self.counters.batches.saturating_add(1);
        self.emit_event(
            "exit_batch_built",
            &batch.batch_id,
            &batch.public_record(),
            batch.built_at_height,
        );
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        self.recompute_roots();
        Ok(batch)
    }

    pub fn verify_exit_batch(
        &mut self,
        request: VerifyExitBatchRequest,
    ) -> Result<BatchVerification> {
        request.validate()?;
        self.ensure_committee_active(&request.committee_id)?;
        self.ensure_batch_open(&request.batch_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "committee missing".to_string())?;
        let required = required_quorum_weight(committee.aggregate_weight, self.config.quorum_bps);
        if request.signer_weight < required {
            return Err("verification signer_weight below quorum".to_string());
        }
        let verification = BatchVerification::from_request(
            request,
            self.counters.verifications.saturating_add(1),
        )?;
        let batch = self
            .batches
            .get_mut(&verification.batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        batch
            .verification_ids
            .push(verification.verification_id.clone());
        batch.status = if verification.verdict == VerificationVerdict::Valid {
            BatchStatus::Verified
        } else {
            BatchStatus::Disputed
        };
        self.counters.verifications = self.counters.verifications.saturating_add(1);
        self.emit_event(
            "exit_batch_verified",
            &verification.verification_id,
            &verification.public_record(),
            verification.verified_at_height,
        );
        self.verifications
            .insert(verification.verification_id.clone(), verification.clone());
        self.recompute_roots();
        Ok(verification)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> Result<SponsorReservation> {
        request.validate(&self.config)?;
        self.ensure_batch_exists(&request.batch_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let reservation = SponsorReservation::from_request(
            request,
            self.counters.sponsor_reservations.saturating_add(1),
            &self.config,
        )?;
        if let Some(batch) = self.batches.get_mut(&reservation.batch_id) {
            batch
                .sponsor_reservation_ids
                .push(reservation.reservation_id.clone());
        }
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        self.emit_event(
            "sponsor_reserved",
            &reservation.reservation_id,
            &reservation.public_record(),
            reservation.expires_at_height,
        );
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.recompute_roots();
        Ok(reservation)
    }

    pub fn publish_receipt(&mut self, request: PublishReceiptRequest) -> Result<SettlementReceipt> {
        request.validate(&self.config)?;
        self.ensure_batch_exists(&request.batch_id)?;
        let receipt = SettlementReceipt::from_request(
            request,
            self.counters.receipts.saturating_add(1),
            &self.config,
        )?;
        let batch = self
            .batches
            .get_mut(&receipt.batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if batch.status != BatchStatus::Verified {
            return Err("batch must be verified before receipt".to_string());
        }
        batch.status = BatchStatus::Settled;
        batch.receipt_ids.push(receipt.receipt_id.clone());
        for note_id in &batch.exit_note_ids {
            if let Some(note) = self.exit_notes.get_mut(note_id) {
                note.status = ExitNoteStatus::Settled;
            }
        }
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        self.emit_event(
            "settlement_receipt_published",
            &receipt.receipt_id,
            &receipt.public_record(),
            receipt.settled_at_height,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        request.validate(&self.config)?;
        self.ensure_batch_exists(&request.batch_id)?;
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("receipt missing for rebate".to_string());
        }
        let rebate = FeeRebate::from_request(
            request,
            self.counters.rebates.saturating_add(1),
            &self.config,
        )?;
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.emit_event(
            "fee_rebate_queued",
            &rebate.rebate_id,
            &rebate.public_record(),
            0,
        );
        self.rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.recompute_roots();
        Ok(rebate)
    }

    pub fn open_privacy_fence(&mut self, request: OpenPrivacyFenceRequest) -> Result<PrivacyFence> {
        request.validate()?;
        self.spend_nullifier(&request.nullifier_root)?;
        let fence =
            PrivacyFence::from_request(request, self.counters.privacy_fences.saturating_add(1))?;
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.emit_event(
            "privacy_fence_opened",
            &fence.fence_id,
            &fence.public_record(),
            fence.effective_height,
        );
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn record_slashing(&mut self, request: RecordSlashingRequest) -> Result<SlashingEvent> {
        request.validate()?;
        self.ensure_batch_exists(&request.batch_id)?;
        let event =
            SlashingEvent::from_request(request, self.counters.slashing_events.saturating_add(1))?;
        if let Some(batch) = self.batches.get_mut(&event.batch_id) {
            batch.status = BatchStatus::Disputed;
        }
        self.counters.slashing_events = self.counters.slashing_events.saturating_add(1);
        self.emit_event(
            "slashing_recorded",
            &event.slashing_id,
            &event.public_record(),
            event.recorded_at_height,
        );
        self.slashing_events
            .insert(event.slashing_id.clone(), event.clone());
        self.recompute_roots();
        Ok(event)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PQ_LOW_FEE_BRIDGE_EXIT_BATCH_VERIFIER_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PQ_LOW_FEE_BRIDGE_EXIT_BATCH_VERIFIER_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    fn ensure_committee_active(&self, committee_id: &str) -> Result<()> {
        let committee = self
            .committees
            .get(committee_id)
            .ok_or_else(|| "committee missing".to_string())?;
        if committee.status == CommitteeStatus::Active {
            Ok(())
        } else {
            Err("committee not active".to_string())
        }
    }

    fn ensure_batch_exists(&self, batch_id: &str) -> Result<()> {
        if self.batches.contains_key(batch_id) {
            Ok(())
        } else {
            Err("batch missing".to_string())
        }
    }

    fn ensure_batch_open(&self, batch_id: &str) -> Result<()> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if batch.status == BatchStatus::Open {
            Ok(())
        } else {
            Err("batch is not open".to_string())
        }
    }

    fn spend_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        require_root("nullifier_root", nullifier_root)?;
        if self.spent_nullifiers.contains(nullifier_root) {
            Err("nullifier already spent".to_string())
        } else {
            self.spent_nullifiers.insert(nullifier_root.to_string());
            Ok(())
        }
    }

    fn emit_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value, height: u64) {
        let sequence = self.counters.runtime_events.saturating_add(1);
        let event = RuntimeEvent::new(event_kind, subject_id, payload, height, sequence);
        self.runtime_events.push(event);
        self.counters.runtime_events = sequence;
        if self.runtime_events.len() > MAX_EVENTS {
            let drain = self.runtime_events.len().saturating_sub(MAX_EVENTS);
            self.runtime_events.drain(0..drain);
        }
    }

    fn recompute_roots(&mut self) {
        self.roots = Roots {
            committees_root: map_root(
                "COMMITTEES",
                self.committees.values().map(CommitteeRecord::public_record),
            ),
            exit_notes_root: map_root(
                "EXIT-NOTES",
                self.exit_notes.values().map(ExitNote::public_record),
            ),
            batches_root: map_root(
                "BATCHES",
                self.batches.values().map(ExitBatch::public_record),
            ),
            verifications_root: map_root(
                "VERIFICATIONS",
                self.verifications
                    .values()
                    .map(BatchVerification::public_record),
            ),
            sponsor_reservations_root: map_root(
                "SPONSOR-RESERVATIONS",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            receipts_root: map_root(
                "RECEIPTS",
                self.receipts.values().map(SettlementReceipt::public_record),
            ),
            rebates_root: map_root(
                "REBATES",
                self.rebates.values().map(FeeRebate::public_record),
            ),
            privacy_fences_root: map_root(
                "PRIVACY-FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            slashing_events_root: map_root(
                "SLASHING-EVENTS",
                self.slashing_events
                    .values()
                    .map(SlashingEvent::public_record),
            ),
            spent_nullifiers_root: id_list_root(
                "SPENT-NULLIFIERS",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            runtime_events_root: map_root(
                "RUNTIME-EVENTS",
                self.runtime_events.iter().map(RuntimeEvent::public_record),
            ),
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_low_fee_bridge_exit_batch_verifier_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_pq_low_fee_bridge_exit_batch_verifier_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn committee_id(request: &RegisterCommitteeRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.committee_label),
            HashPart::U64(request.epoch),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.member_set_root),
        ],
        32,
    )
}

pub fn exit_note_id(request: &SubmitExitNoteRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(request.note_kind.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.source_note_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn exit_batch_id(
    request: &BuildExitBatchRequest,
    note_set_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.committee_id),
            HashPart::Str(note_set_root),
            HashPart::Str(&request.batch_policy_root),
            HashPart::Str(&request.monero_anchor_root),
            HashPart::U64(request.built_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn batch_verification_id(request: &VerifyExitBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-VERIFICATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.attester_commitment_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(request.verdict.as_str()),
            HashPart::U64(request.verified_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_note_root),
            HashPart::U64(request.max_fee_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.monero_tx_set_root),
            HashPart::Str(&request.verified_exit_set_root),
            HashPart::U64(request.settled_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_rebate_id(request: &IssueRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_note_root),
            HashPart::U64(request.rebate_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &OpenPrivacyFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.commitment_root),
            HashPart::Str(&request.replay_domain),
            HashPart::Str(&request.nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_id(request: &RecordSlashingRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.offender_commitment),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.recorded_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(&format!("{domain}-ROOT"), record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-LOW-FEE-BRIDGE-EXIT-{domain}"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

pub fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn required_quorum_weight(total_weight: u64, quorum_bps: u64) -> u64 {
    total_weight
        .saturating_mul(quorum_bps)
        .saturating_add(MAX_BPS.saturating_sub(1))
        .checked_div(MAX_BPS)
        .unwrap_or(total_weight)
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must equal {expected}"))
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        Err(format!("{field} must be a commitment root"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}
