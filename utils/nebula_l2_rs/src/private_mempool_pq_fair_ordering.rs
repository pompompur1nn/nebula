use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateMempoolPqFairOrderingResult<T> = Result<T, String>;

pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_PROTOCOL_VERSION: &str =
    "nebula-private-mempool-pq-fair-ordering-v1";
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-fair-ordering";
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_BATCH_BLOCKS: u64 = 3;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_CHALLENGE_BLOCKS: u64 = 12;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_MIN_PRIVACY_SET: u64 = 16;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_MAX_DELAY_BLOCKS: u64 = 8;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS: u64 = 10_000;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_LANES: usize = 64;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_COMMITTEE: usize = 128;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_ENVELOPES: usize = 4_096;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BATCHES: usize = 512;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_ATTESTATIONS: usize = 4_096;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_CHALLENGES: usize = 1_024;
pub const PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_RECEIPTS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairOrderingLaneClass {
    WalletTransfer,
    MoneroExit,
    ContractCall,
    PrivateSwap,
    OracleUpdate,
    ProofJob,
    Emergency,
}

impl FairOrderingLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MoneroExit => "monero_exit",
            Self::ContractCall => "contract_call",
            Self::PrivateSwap => "private_swap",
            Self::OracleUpdate => "oracle_update",
            Self::ProofJob => "proof_job",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 128,
            Self::MoneroExit => 104,
            Self::ContractCall => 96,
            Self::PrivateSwap => 88,
            Self::WalletTransfer => 80,
            Self::ProofJob => 64,
            Self::OracleUpdate => 56,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Pending,
    Batched,
    Included,
    Expired,
    Challenged,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Batched => "batched",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Included,
    Challenged,
    Finalized,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Included => "included",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingLane {
    pub lane_id: String,
    pub label: String,
    pub class: FairOrderingLaneClass,
    pub max_envelopes_per_batch: u64,
    pub max_delay_blocks: u64,
    pub sponsor_budget_units: u64,
    pub min_committee_weight_bps: u64,
    pub active: bool,
}

impl FairOrderingLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        class: FairOrderingLaneClass,
        max_envelopes_per_batch: u64,
        max_delay_blocks: u64,
        sponsor_budget_units: u64,
        min_committee_weight_bps: u64,
        active: bool,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if label.is_empty() {
            return Err("fair ordering lane label cannot be empty".to_string());
        }
        if max_envelopes_per_batch == 0 {
            return Err("fair ordering lane batch capacity must be positive".to_string());
        }
        if max_delay_blocks == 0 {
            return Err("fair ordering lane delay must be positive".to_string());
        }
        if min_committee_weight_bps > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS {
            return Err("fair ordering lane quorum exceeds max bps".to_string());
        }
        let lane_id = private_mempool_pq_fair_ordering_id(
            "LANE",
            &[label, class.as_str(), &max_delay_blocks.to_string()],
        );
        Ok(Self {
            lane_id,
            label: label.to_string(),
            class,
            max_envelopes_per_batch,
            max_delay_blocks,
            sponsor_budget_units,
            min_committee_weight_bps,
            active,
        })
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.lane_id.is_empty() || self.label.is_empty() {
            return Err("fair ordering lane identifiers cannot be empty".to_string());
        }
        if self.max_envelopes_per_batch == 0 || self.max_delay_blocks == 0 {
            return Err("fair ordering lane limits must be positive".to_string());
        }
        if self.min_committee_weight_bps > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS {
            return Err("fair ordering lane quorum exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_lane",
            "lane_id": self.lane_id,
            "label": self.label,
            "class": self.class.as_str(),
            "priority_weight": self.class.priority_weight(),
            "max_envelopes_per_batch": self.max_envelopes_per_batch,
            "max_delay_blocks": self.max_delay_blocks,
            "sponsor_budget_units": self.sponsor_budget_units,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingCommitteeMember {
    pub member_id: String,
    pub label: String,
    pub pq_identity_commitment: String,
    pub ordering_weight_bps: u64,
    pub stake_commitment: String,
    pub active: bool,
}

impl FairOrderingCommitteeMember {
    pub fn new(
        label: &str,
        pq_identity_commitment: &str,
        ordering_weight_bps: u64,
        stake_commitment: &str,
        active: bool,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if label.is_empty() || pq_identity_commitment.is_empty() || stake_commitment.is_empty() {
            return Err("fair ordering committee member fields cannot be empty".to_string());
        }
        if ordering_weight_bps == 0
            || ordering_weight_bps > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS
        {
            return Err("fair ordering committee weight is invalid".to_string());
        }
        let member_id = private_mempool_pq_fair_ordering_id(
            "MEMBER",
            &[label, pq_identity_commitment, stake_commitment],
        );
        Ok(Self {
            member_id,
            label: label.to_string(),
            pq_identity_commitment: pq_identity_commitment.to_string(),
            ordering_weight_bps,
            stake_commitment: stake_commitment.to_string(),
            active,
        })
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.member_id.is_empty()
            || self.label.is_empty()
            || self.pq_identity_commitment.is_empty()
            || self.stake_commitment.is_empty()
        {
            return Err("fair ordering committee member identifiers cannot be empty".to_string());
        }
        if self.ordering_weight_bps == 0
            || self.ordering_weight_bps > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS
        {
            return Err("fair ordering committee member weight is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_committee_member",
            "member_id": self.member_id,
            "label": self.label,
            "pq_identity_commitment": self.pq_identity_commitment,
            "ordering_weight_bps": self.ordering_weight_bps,
            "stake_commitment": self.stake_commitment,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("MEMBER", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMempoolEnvelope {
    pub envelope_id: String,
    pub lane_id: String,
    pub sender_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier_commitment: String,
    pub fee_credit_commitment: String,
    pub arrival_height: u64,
    pub expiry_height: u64,
    pub max_delay_blocks: u64,
    pub weight_units: u64,
    pub status: EnvelopeStatus,
}

impl EncryptedMempoolEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        sender_commitment: &str,
        encrypted_payload_root: &str,
        nullifier_commitment: &str,
        fee_credit_commitment: &str,
        arrival_height: u64,
        max_delay_blocks: u64,
        weight_units: u64,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if lane_id.is_empty()
            || sender_commitment.is_empty()
            || encrypted_payload_root.is_empty()
            || nullifier_commitment.is_empty()
            || fee_credit_commitment.is_empty()
        {
            return Err("fair ordering envelope commitments cannot be empty".to_string());
        }
        if max_delay_blocks == 0 || weight_units == 0 {
            return Err("fair ordering envelope limits must be positive".to_string());
        }
        let envelope_id = private_mempool_pq_fair_ordering_id(
            "ENVELOPE",
            &[
                lane_id,
                sender_commitment,
                encrypted_payload_root,
                nullifier_commitment,
                &arrival_height.to_string(),
            ],
        );
        Ok(Self {
            envelope_id,
            lane_id: lane_id.to_string(),
            sender_commitment: sender_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            nullifier_commitment: nullifier_commitment.to_string(),
            fee_credit_commitment: fee_credit_commitment.to_string(),
            arrival_height,
            expiry_height: arrival_height.saturating_add(max_delay_blocks),
            max_delay_blocks,
            weight_units,
            status: EnvelopeStatus::Pending,
        })
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.envelope_id.is_empty()
            || self.lane_id.is_empty()
            || self.sender_commitment.is_empty()
            || self.encrypted_payload_root.is_empty()
            || self.nullifier_commitment.is_empty()
            || self.fee_credit_commitment.is_empty()
        {
            return Err("fair ordering envelope identifiers cannot be empty".to_string());
        }
        if self.expiry_height < self.arrival_height || self.weight_units == 0 {
            return Err("fair ordering envelope timing or weight is invalid".to_string());
        }
        Ok(())
    }

    pub fn is_live(&self, height: u64) -> bool {
        matches!(
            self.status,
            EnvelopeStatus::Pending | EnvelopeStatus::Batched
        ) && height <= self.expiry_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_mempool_envelope",
            "envelope_id": self.envelope_id,
            "lane_id": self.lane_id,
            "sender_commitment": self.sender_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier_commitment": self.nullifier_commitment,
            "fee_credit_commitment": self.fee_credit_commitment,
            "arrival_height": self.arrival_height,
            "expiry_height": self.expiry_height,
            "max_delay_blocks": self.max_delay_blocks,
            "weight_units": self.weight_units,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("ENVELOPE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub open_height: u64,
    pub seal_height: u64,
    pub envelope_ids: BTreeSet<String>,
    pub ordering_commitment_root: String,
    pub committee_signature_root: String,
    pub status: BatchStatus,
}

impl FairOrderingBatch {
    pub fn new(
        lane_id: &str,
        open_height: u64,
        batch_blocks: u64,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if lane_id.is_empty() {
            return Err("fair ordering batch lane cannot be empty".to_string());
        }
        if batch_blocks == 0 {
            return Err("fair ordering batch blocks must be positive".to_string());
        }
        let batch_id = private_mempool_pq_fair_ordering_id(
            "BATCH",
            &[lane_id, &open_height.to_string(), &batch_blocks.to_string()],
        );
        Ok(Self {
            batch_id,
            lane_id: lane_id.to_string(),
            open_height,
            seal_height: open_height.saturating_add(batch_blocks),
            envelope_ids: BTreeSet::new(),
            ordering_commitment_root: private_mempool_pq_fair_ordering_empty_root("BATCH-ORDERING"),
            committee_signature_root: private_mempool_pq_fair_ordering_empty_root(
                "BATCH-COMMITTEE",
            ),
            status: BatchStatus::Open,
        })
    }

    pub fn refresh_roots(&mut self) {
        self.ordering_commitment_root = private_mempool_pq_fair_ordering_string_set_root(
            "BATCH-ENVELOPE-IDS",
            &self.envelope_ids.iter().cloned().collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.batch_id.is_empty()
            || self.lane_id.is_empty()
            || self.ordering_commitment_root.is_empty()
            || self.committee_signature_root.is_empty()
        {
            return Err("fair ordering batch identifiers cannot be empty".to_string());
        }
        if self.seal_height < self.open_height {
            return Err("fair ordering batch timing is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_batch",
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "open_height": self.open_height,
            "seal_height": self.seal_height,
            "envelope_ids": self.envelope_ids.iter().cloned().collect::<Vec<_>>(),
            "ordering_commitment_root": self.ordering_commitment_root,
            "committee_signature_root": self.committee_signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub member_id: String,
    pub pq_signature_commitment: String,
    pub fairness_witness_root: String,
    pub weight_bps: u64,
    pub height: u64,
}

impl FairOrderingAttestation {
    pub fn new(
        batch_id: &str,
        member_id: &str,
        pq_signature_commitment: &str,
        fairness_witness_root: &str,
        weight_bps: u64,
        height: u64,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if batch_id.is_empty()
            || member_id.is_empty()
            || pq_signature_commitment.is_empty()
            || fairness_witness_root.is_empty()
        {
            return Err("fair ordering attestation fields cannot be empty".to_string());
        }
        if weight_bps == 0 || weight_bps > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS {
            return Err("fair ordering attestation weight is invalid".to_string());
        }
        let attestation_id = private_mempool_pq_fair_ordering_id(
            "ATTESTATION",
            &[
                batch_id,
                member_id,
                pq_signature_commitment,
                &height.to_string(),
            ],
        );
        Ok(Self {
            attestation_id,
            batch_id: batch_id.to_string(),
            member_id: member_id.to_string(),
            pq_signature_commitment: pq_signature_commitment.to_string(),
            fairness_witness_root: fairness_witness_root.to_string(),
            weight_bps,
            height,
        })
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.attestation_id.is_empty()
            || self.batch_id.is_empty()
            || self.member_id.is_empty()
            || self.pq_signature_commitment.is_empty()
            || self.fairness_witness_root.is_empty()
        {
            return Err("fair ordering attestation identifiers cannot be empty".to_string());
        }
        if self.weight_bps == 0 || self.weight_bps > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS {
            return Err("fair ordering attestation weight is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_attestation",
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "member_id": self.member_id,
            "pq_signature_commitment": self.pq_signature_commitment,
            "fairness_witness_root": self.fairness_witness_root,
            "weight_bps": self.weight_bps,
            "height": self.height,
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingChallenge {
    pub challenge_id: String,
    pub batch_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub status: ChallengeStatus,
}

impl FairOrderingChallenge {
    pub fn new(
        batch_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        opened_height: u64,
        challenge_blocks: u64,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if batch_id.is_empty() || challenger_commitment.is_empty() || evidence_root.is_empty() {
            return Err("fair ordering challenge fields cannot be empty".to_string());
        }
        if challenge_blocks == 0 {
            return Err("fair ordering challenge blocks must be positive".to_string());
        }
        let challenge_id = private_mempool_pq_fair_ordering_id(
            "CHALLENGE",
            &[
                batch_id,
                challenger_commitment,
                evidence_root,
                &opened_height.to_string(),
            ],
        );
        Ok(Self {
            challenge_id,
            batch_id: batch_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_height,
            expiry_height: opened_height.saturating_add(challenge_blocks),
            status: ChallengeStatus::Open,
        })
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.challenge_id.is_empty()
            || self.batch_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("fair ordering challenge identifiers cannot be empty".to_string());
        }
        if self.expiry_height < self.opened_height {
            return Err("fair ordering challenge timing is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_challenge",
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingInclusionReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub block_commitment: String,
    pub included_envelope_root: String,
    pub rebate_commitment: String,
    pub height: u64,
}

impl FairOrderingInclusionReceipt {
    pub fn new(
        batch_id: &str,
        block_commitment: &str,
        included_envelope_root: &str,
        rebate_commitment: &str,
        height: u64,
    ) -> PrivateMempoolPqFairOrderingResult<Self> {
        if batch_id.is_empty()
            || block_commitment.is_empty()
            || included_envelope_root.is_empty()
            || rebate_commitment.is_empty()
        {
            return Err("fair ordering inclusion receipt fields cannot be empty".to_string());
        }
        let receipt_id = private_mempool_pq_fair_ordering_id(
            "RECEIPT",
            &[
                batch_id,
                block_commitment,
                included_envelope_root,
                &height.to_string(),
            ],
        );
        Ok(Self {
            receipt_id,
            batch_id: batch_id.to_string(),
            block_commitment: block_commitment.to_string(),
            included_envelope_root: included_envelope_root.to_string(),
            rebate_commitment: rebate_commitment.to_string(),
            height,
        })
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.receipt_id.is_empty()
            || self.batch_id.is_empty()
            || self.block_commitment.is_empty()
            || self.included_envelope_root.is_empty()
            || self.rebate_commitment.is_empty()
        {
            return Err("fair ordering inclusion receipt identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_inclusion_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "block_commitment": self.block_commitment,
            "included_envelope_root": self.included_envelope_root,
            "rebate_commitment": self.rebate_commitment,
            "height": self.height,
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub batch_blocks: u64,
    pub challenge_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_delay_blocks: u64,
    pub require_pq_dual_signatures: bool,
    pub enable_low_fee_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            batch_blocks: PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_BATCH_BLOCKS,
            challenge_blocks: PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_CHALLENGE_BLOCKS,
            min_privacy_set_size: PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_MIN_PRIVACY_SET,
            max_delay_blocks: PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_DEFAULT_MAX_DELAY_BLOCKS,
            require_pq_dual_signatures: true,
            enable_low_fee_rebates: true,
        }
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.batch_blocks == 0
            || self.challenge_blocks == 0
            || self.min_privacy_set_size == 0
            || self.max_delay_blocks == 0
        {
            return Err("fair ordering config windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_pq_fair_ordering_config",
            "batch_blocks": self.batch_blocks,
            "challenge_blocks": self.challenge_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_delay_blocks": self.max_delay_blocks,
            "require_pq_dual_signatures": self.require_pq_dual_signatures,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub committee_root: String,
    pub envelope_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_pq_fair_ordering_roots",
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "committee_root": self.committee_root,
            "envelope_root": self.envelope_root,
            "batch_root": self.batch_root,
            "attestation_root": self.attestation_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn root(&self) -> String {
        private_mempool_pq_fair_ordering_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub committee_member_count: u64,
    pub active_committee_weight_bps: u64,
    pub envelope_count: u64,
    pub pending_envelope_count: u64,
    pub live_batch_count: u64,
    pub attestation_count: u64,
    pub open_challenge_count: u64,
    pub receipt_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_pq_fair_ordering_counters",
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "committee_member_count": self.committee_member_count,
            "active_committee_weight_bps": self.active_committee_weight_bps,
            "envelope_count": self.envelope_count,
            "pending_envelope_count": self.pending_envelope_count,
            "live_batch_count": self.live_batch_count,
            "attestation_count": self.attestation_count,
            "open_challenge_count": self.open_challenge_count,
            "receipt_count": self.receipt_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub lanes: BTreeMap<String, FairOrderingLane>,
    pub committee: BTreeMap<String, FairOrderingCommitteeMember>,
    pub envelopes: BTreeMap<String, EncryptedMempoolEnvelope>,
    pub batches: BTreeMap<String, FairOrderingBatch>,
    pub attestations: BTreeMap<String, FairOrderingAttestation>,
    pub challenges: BTreeMap<String, FairOrderingChallenge>,
    pub receipts: BTreeMap<String, FairOrderingInclusionReceipt>,
}

impl State {
    pub fn new(config: Config) -> PrivateMempoolPqFairOrderingResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            epoch: 0,
            lanes: BTreeMap::new(),
            committee: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PrivateMempoolPqFairOrderingResult<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.height = 2_048;
        state.epoch = 5;

        let lanes = [
            FairOrderingLane::new(
                "wallet-low-fee",
                FairOrderingLaneClass::WalletTransfer,
                192,
                5,
                12_000_000,
                6_700,
                true,
            )?,
            FairOrderingLane::new(
                "monero-exit-fast",
                FairOrderingLaneClass::MoneroExit,
                128,
                4,
                25_000_000,
                7_000,
                true,
            )?,
            FairOrderingLane::new(
                "private-contract-call",
                FairOrderingLaneClass::ContractCall,
                160,
                6,
                18_000_000,
                6_700,
                true,
            )?,
        ];
        for lane in lanes {
            state.insert_lane(lane)?;
        }

        let members = [
            FairOrderingCommitteeMember::new(
                "sequencer-alpha",
                "pqid:sequencer-alpha:ml-dsa",
                3_400,
                "stake:sequencer-alpha",
                true,
            )?,
            FairOrderingCommitteeMember::new(
                "sequencer-beta",
                "pqid:sequencer-beta:slh-dsa",
                3_300,
                "stake:sequencer-beta",
                true,
            )?,
            FairOrderingCommitteeMember::new(
                "watchtower-gamma",
                "pqid:watchtower-gamma:hybrid",
                3_300,
                "stake:watchtower-gamma",
                true,
            )?,
        ];
        for member in members {
            state.insert_committee_member(member)?;
        }

        let lane_ids = state.lanes.keys().cloned().collect::<Vec<_>>();
        for (index, lane_id) in lane_ids.iter().enumerate() {
            let envelope = EncryptedMempoolEnvelope::new(
                lane_id,
                &format!("sender:commitment:{index}"),
                &private_mempool_pq_fair_ordering_payload_root(
                    "DEVNET-PAYLOAD",
                    &json!({ "lane_id": lane_id, "index": index as u64 }),
                ),
                &format!("nullifier:commitment:{index}"),
                &format!("fee-credit:commitment:{index}"),
                state.height,
                state.config.max_delay_blocks,
                1 + index as u64,
            )?;
            state.queue_envelope(envelope)?;
        }

        if let Some(lane_id) = lane_ids.first() {
            let batch_id = state.open_batch(lane_id)?;
            let envelope_ids = state
                .envelopes
                .values()
                .filter(|envelope| envelope.lane_id == *lane_id)
                .map(|envelope| envelope.envelope_id.clone())
                .collect::<Vec<_>>();
            for envelope_id in &envelope_ids {
                state.add_envelope_to_batch(&batch_id, envelope_id)?;
            }
            state.seal_batch(&batch_id, "committee:signature:root:devnet")?;
            let member_ids = state.committee.keys().cloned().collect::<Vec<_>>();
            for member_id in member_ids {
                state.record_attestation(
                    &batch_id,
                    &member_id,
                    &format!("pq-signature:{member_id}:{batch_id}"),
                    &private_mempool_pq_fair_ordering_payload_root(
                        "DEVNET-FAIRNESS-WITNESS",
                        &json!({ "member_id": member_id, "batch_id": batch_id }),
                    ),
                )?;
            }
        }

        state.validate()?;
        Ok(state)
    }

    pub fn insert_lane(
        &mut self,
        lane: FairOrderingLane,
    ) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.lanes.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_LANES
            && !self.lanes.contains_key(&lane.lane_id)
        {
            return Err("fair ordering lane capacity reached".to_string());
        }
        lane.validate()?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_committee_member(
        &mut self,
        member: FairOrderingCommitteeMember,
    ) -> PrivateMempoolPqFairOrderingResult<()> {
        if self.committee.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_COMMITTEE
            && !self.committee.contains_key(&member.member_id)
        {
            return Err("fair ordering committee capacity reached".to_string());
        }
        member.validate()?;
        self.committee.insert(member.member_id.clone(), member);
        Ok(())
    }

    pub fn queue_envelope(
        &mut self,
        envelope: EncryptedMempoolEnvelope,
    ) -> PrivateMempoolPqFairOrderingResult<String> {
        if self.envelopes.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_ENVELOPES
            && !self.envelopes.contains_key(&envelope.envelope_id)
        {
            return Err("fair ordering envelope capacity reached".to_string());
        }
        envelope.validate()?;
        let lane = self
            .lanes
            .get(&envelope.lane_id)
            .ok_or_else(|| "fair ordering envelope lane missing".to_string())?;
        if !lane.active {
            return Err("fair ordering envelope lane is inactive".to_string());
        }
        if envelope.max_delay_blocks > lane.max_delay_blocks.max(self.config.max_delay_blocks) {
            return Err("fair ordering envelope delay exceeds lane policy".to_string());
        }
        let envelope_id = envelope.envelope_id.clone();
        self.envelopes.insert(envelope_id.clone(), envelope);
        Ok(envelope_id)
    }

    pub fn open_batch(&mut self, lane_id: &str) -> PrivateMempoolPqFairOrderingResult<String> {
        if self.batches.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BATCHES {
            return Err("fair ordering batch capacity reached".to_string());
        }
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "fair ordering batch lane missing".to_string())?;
        if !lane.active {
            return Err("fair ordering batch lane is inactive".to_string());
        }
        let batch = FairOrderingBatch::new(lane_id, self.height, self.config.batch_blocks)?;
        let batch_id = batch.batch_id.clone();
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn add_envelope_to_batch(
        &mut self,
        batch_id: &str,
        envelope_id: &str,
    ) -> PrivateMempoolPqFairOrderingResult<()> {
        let lane_id = self
            .batches
            .get(batch_id)
            .map(|batch| batch.lane_id.clone())
            .ok_or_else(|| "fair ordering batch missing".to_string())?;
        let lane = self
            .lanes
            .get(&lane_id)
            .ok_or_else(|| "fair ordering batch lane missing".to_string())?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "fair ordering batch missing".to_string())?;
        if batch.status != BatchStatus::Open {
            return Err("fair ordering batch is not open".to_string());
        }
        if batch.envelope_ids.len() as u64 >= lane.max_envelopes_per_batch {
            return Err("fair ordering batch capacity reached".to_string());
        }
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| "fair ordering envelope missing".to_string())?;
        if envelope.lane_id != lane_id {
            return Err("fair ordering envelope lane mismatch".to_string());
        }
        if !envelope.is_live(self.height) {
            return Err("fair ordering envelope is not live".to_string());
        }
        envelope.status = EnvelopeStatus::Batched;
        batch.envelope_ids.insert(envelope_id.to_string());
        batch.refresh_roots();
        Ok(())
    }

    pub fn seal_batch(
        &mut self,
        batch_id: &str,
        committee_signature_root: &str,
    ) -> PrivateMempoolPqFairOrderingResult<()> {
        if committee_signature_root.is_empty() {
            return Err("fair ordering batch signature root cannot be empty".to_string());
        }
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "fair ordering batch missing".to_string())?;
        if batch.envelope_ids.len() < self.config.min_privacy_set_size as usize
            && batch.envelope_ids.is_empty()
        {
            return Err("fair ordering batch privacy set is empty".to_string());
        }
        if self.height > batch.seal_height {
            return Err("fair ordering batch seal window elapsed".to_string());
        }
        batch.status = BatchStatus::Sealed;
        batch.committee_signature_root = committee_signature_root.to_string();
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        batch_id: &str,
        member_id: &str,
        pq_signature_commitment: &str,
        fairness_witness_root: &str,
    ) -> PrivateMempoolPqFairOrderingResult<String> {
        if self.attestations.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_ATTESTATIONS {
            return Err("fair ordering attestation capacity reached".to_string());
        }
        let member = self
            .committee
            .get(member_id)
            .ok_or_else(|| "fair ordering committee member missing".to_string())?;
        if !member.active {
            return Err("fair ordering committee member inactive".to_string());
        }
        if !self.batches.contains_key(batch_id) {
            return Err("fair ordering attestation batch missing".to_string());
        }
        let attestation = FairOrderingAttestation::new(
            batch_id,
            member_id,
            pq_signature_commitment,
            fairness_witness_root,
            member.ordering_weight_bps,
            self.height,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn open_challenge(
        &mut self,
        batch_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
    ) -> PrivateMempoolPqFairOrderingResult<String> {
        if self.challenges.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_CHALLENGES {
            return Err("fair ordering challenge capacity reached".to_string());
        }
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "fair ordering challenge batch missing".to_string())?;
        batch.status = BatchStatus::Challenged;
        let challenge = FairOrderingChallenge::new(
            batch_id,
            challenger_commitment,
            evidence_root,
            self.height,
            self.config.challenge_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        accepted: bool,
    ) -> PrivateMempoolPqFairOrderingResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "fair ordering challenge missing".to_string())?;
        if challenge.status != ChallengeStatus::Open {
            return Err("fair ordering challenge already resolved".to_string());
        }
        challenge.status = if accepted {
            ChallengeStatus::Accepted
        } else {
            ChallengeStatus::Rejected
        };
        if let Some(batch) = self.batches.get_mut(&challenge.batch_id) {
            batch.status = if accepted {
                BatchStatus::Challenged
            } else {
                BatchStatus::Finalized
            };
        }
        Ok(())
    }

    pub fn record_inclusion_receipt(
        &mut self,
        batch_id: &str,
        block_commitment: &str,
        rebate_commitment: &str,
    ) -> PrivateMempoolPqFairOrderingResult<String> {
        if self.receipts.len() >= PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_RECEIPTS {
            return Err("fair ordering receipt capacity reached".to_string());
        }
        let envelope_ids = {
            let batch = self
                .batches
                .get_mut(batch_id)
                .ok_or_else(|| "fair ordering receipt batch missing".to_string())?;
            if !matches!(batch.status, BatchStatus::Sealed | BatchStatus::Finalized) {
                return Err("fair ordering batch is not includable".to_string());
            }
            batch.status = BatchStatus::Included;
            batch.envelope_ids.iter().cloned().collect::<Vec<_>>()
        };
        for envelope_id in &envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Included;
            }
        }
        let included_envelope_root =
            private_mempool_pq_fair_ordering_string_set_root("INCLUDED-ENVELOPES", &envelope_ids);
        let receipt = FairOrderingInclusionReceipt::new(
            batch_id,
            block_commitment,
            &included_envelope_root,
            rebate_commitment,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateMempoolPqFairOrderingResult<()> {
        if height < self.height {
            return Err("fair ordering height cannot go backwards".to_string());
        }
        self.height = height;
        self.epoch = height / self.config.batch_blocks.max(1);
        for envelope in self.envelopes.values_mut() {
            if matches!(
                envelope.status,
                EnvelopeStatus::Pending | EnvelopeStatus::Batched
            ) && height > envelope.expiry_height
            {
                envelope.status = EnvelopeStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open && height > challenge.expiry_height {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> PrivateMempoolPqFairOrderingResult<()> {
        self.set_height(height)
    }

    pub fn validate(&self) -> PrivateMempoolPqFairOrderingResult<()> {
        self.config.validate()?;
        if self.lanes.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_LANES
            || self.committee.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_COMMITTEE
            || self.envelopes.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_ENVELOPES
            || self.batches.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BATCHES
            || self.attestations.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_ATTESTATIONS
            || self.challenges.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_CHALLENGES
            || self.receipts.len() > PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_RECEIPTS
        {
            return Err("fair ordering state capacity exceeded".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for member in self.committee.values() {
            member.validate()?;
        }
        for envelope in self.envelopes.values() {
            envelope.validate()?;
            if !self.lanes.contains_key(&envelope.lane_id) {
                return Err("fair ordering envelope references missing lane".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate()?;
            if !self.lanes.contains_key(&batch.lane_id) {
                return Err("fair ordering batch references missing lane".to_string());
            }
            for envelope_id in &batch.envelope_ids {
                if !self.envelopes.contains_key(envelope_id) {
                    return Err("fair ordering batch references missing envelope".to_string());
                }
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.batches.contains_key(&attestation.batch_id)
                || !self.committee.contains_key(&attestation.member_id)
            {
                return Err("fair ordering attestation references missing state".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.batches.contains_key(&challenge.batch_id) {
                return Err("fair ordering challenge references missing batch".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err("fair ordering receipt references missing batch".to_string());
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_mempool_pq_fair_ordering_payload_root(
                "CONFIG",
                &self.config.public_record(),
            ),
            lane_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-LANES",
                &self
                    .lanes
                    .values()
                    .map(FairOrderingLane::public_record)
                    .collect::<Vec<_>>(),
            ),
            committee_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-COMMITTEE",
                &self
                    .committee
                    .values()
                    .map(FairOrderingCommitteeMember::public_record)
                    .collect::<Vec<_>>(),
            ),
            envelope_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-ENVELOPES",
                &self
                    .envelopes
                    .values()
                    .map(EncryptedMempoolEnvelope::public_record)
                    .collect::<Vec<_>>(),
            ),
            batch_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-BATCHES",
                &self
                    .batches
                    .values()
                    .map(FairOrderingBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            attestation_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-ATTESTATIONS",
                &self
                    .attestations
                    .values()
                    .map(FairOrderingAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-CHALLENGES",
                &self
                    .challenges
                    .values()
                    .map(FairOrderingChallenge::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: merkle_root(
                "PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(FairOrderingInclusionReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lane_count: self.lanes.len() as u64,
            active_lane_count: self.lanes.values().filter(|lane| lane.active).count() as u64,
            committee_member_count: self.committee.len() as u64,
            active_committee_weight_bps: self
                .committee
                .values()
                .filter(|member| member.active)
                .map(|member| member.ordering_weight_bps)
                .sum::<u64>(),
            envelope_count: self.envelopes.len() as u64,
            pending_envelope_count: self
                .envelopes
                .values()
                .filter(|envelope| envelope.status == EnvelopeStatus::Pending)
                .count() as u64,
            live_batch_count: self
                .batches
                .values()
                .filter(|batch| matches!(batch.status, BatchStatus::Open | BatchStatus::Sealed))
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
        }
    }

    pub fn live_batch_ids(&self) -> Vec<String> {
        self.batches
            .values()
            .filter(|batch| matches!(batch.status, BatchStatus::Open | BatchStatus::Sealed))
            .map(|batch| batch.batch_id.clone())
            .collect()
    }

    pub fn pending_envelope_ids(&self) -> Vec<String> {
        self.envelopes
            .values()
            .filter(|envelope| envelope.status == EnvelopeStatus::Pending)
            .map(|envelope| envelope.envelope_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Open)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn lane_pressure_map(&self) -> BTreeMap<String, Value> {
        let mut pressure = BTreeMap::new();
        for lane in self.lanes.values() {
            let pending_weight = self
                .envelopes
                .values()
                .filter(|envelope| {
                    envelope.lane_id == lane.lane_id && envelope.status == EnvelopeStatus::Pending
                })
                .map(|envelope| envelope.weight_units)
                .sum::<u64>();
            let capacity = lane.max_envelopes_per_batch.max(1);
            pressure.insert(
                lane.lane_id.clone(),
                json!({
                    "label": lane.label,
                    "class": lane.class.as_str(),
                    "pending_weight_units": pending_weight,
                    "capacity": capacity,
                    "pressure_bps": pending_weight
                        .saturating_mul(PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_MAX_BPS)
                        / capacity,
                    "sponsor_budget_units": lane.sponsor_budget_units,
                }),
            );
        }
        pressure
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_pq_fair_ordering_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_HASH_SUITE,
            "auth_suite": PRIVATE_MEMPOOL_PQ_FAIR_ORDERING_AUTH_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_batch_ids": self.live_batch_ids(),
            "pending_envelope_ids": self.pending_envelope_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
            "lane_pressure_map": self.lane_pressure_map(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

pub fn root_from_record(record: &Value) -> String {
    private_mempool_pq_fair_ordering_payload_root("STATE", record)
}

pub fn private_mempool_pq_fair_ordering_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_mempool_pq_fair_ordering_empty_root(domain: &str) -> String {
    domain_hash(
        &format!("PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-{domain}-EMPTY"),
        &[],
        32,
    )
}

pub fn private_mempool_pq_fair_ordering_string_set_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        &format!("PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-{domain}"),
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn private_mempool_pq_fair_ordering_id(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-MEMPOOL-PQ-FAIR-ORDERING-ID-{domain}"),
        &[HashPart::Json(&json!({ "parts": parts }))],
        32,
    )
}

pub fn devnet() -> PrivateMempoolPqFairOrderingResult<State> {
    State::devnet()
}
