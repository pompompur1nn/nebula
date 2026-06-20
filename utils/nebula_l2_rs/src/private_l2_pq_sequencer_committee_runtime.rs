use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqSequencerCommitteeRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-sequencer-committee-runtime-v1";
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_ENCRYPTED_MEMPOOL_SUITE: &str =
    "threshold-ml-kem-encrypted-private-mempool-v1";
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEVNET_HEIGHT: u64 = 300_000;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_EPOCH_BLOCKS: u64 = 16;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_SLOT_MS: u64 = 300;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_COMMITTEES: usize = 65_536;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_MEMBERS: usize = 262_144;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_WINDOWS: usize = 262_144;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_ORDER_INTENTS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS: u64 = 6_700;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_FAST_QUORUM_BPS: u64 = 7_500;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_SLASH_BPS: u64 = 750;
pub const PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeKind {
    FastPrivateDefi,
    ContractExecution,
    MoneroBridge,
    ProofDa,
    EmergencyEscape,
}

impl CommitteeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPrivateDefi => "fast_private_defi",
            Self::ContractExecution => "contract_execution",
            Self::MoneroBridge => "monero_bridge",
            Self::ProofDa => "proof_da",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::FastPrivateDefi => 9_400,
            Self::MoneroBridge => 9_000,
            Self::ContractExecution => 8_300,
            Self::ProofDa => 7_400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Paused,
    Slashed,
    Retired,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_sequence(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Candidate,
    Active,
    Standby,
    Jailed,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Jailed => "jailed",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn voting(self) -> bool {
        matches!(self, Self::Active | Self::Standby)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderLane {
    PrivateSwap,
    PrivateLending,
    ConfidentialToken,
    SmartContractCall,
    MoneroFastExit,
    ProofDataAvailability,
}

impl OrderLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::ConfidentialToken => "confidential_token",
            Self::SmartContractCall => "smart_contract_call",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::ProofDataAvailability => "proof_data_availability",
        }
    }

    pub fn latency_score(self) -> u64 {
        match self {
            Self::MoneroFastExit => 10_000,
            Self::PrivateSwap => 9_000,
            Self::PrivateLending => 8_700,
            Self::SmartContractCall => 8_400,
            Self::ConfidentialToken => 8_000,
            Self::ProofDataAvailability => 7_300,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Encrypted,
    Scheduled,
    Preconfirmed,
    Settled,
    Rejected,
    Expired,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Scheduled => "scheduled",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn schedulable(self) -> bool {
        matches!(self, Self::Encrypted | Self::Scheduled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Locked,
    Preconfirmed,
    Settled,
    Expired,
    Slashed,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Locked | Self::Preconfirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Built,
    QuorumReady,
    Published,
    Settled,
    Rejected,
}

impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::QuorumReady => "quorum_ready",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    Equivocation,
    LateReveal,
    InvalidPqSignature,
    DaWithholding,
    FeeOvercharge,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::LateReveal => "late_reveal",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::DaWithholding => "da_withholding",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub encrypted_mempool_suite: String,
    pub epoch_blocks: u64,
    pub slot_ms: u64,
    pub max_committees: usize,
    pub max_members: usize,
    pub max_windows: usize,
    pub max_order_intents: usize,
    pub max_receipts: usize,
    pub min_committee_weight_bps: u64,
    pub fast_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub slash_bps: u64,
    pub roots_only: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_PQ_SUITE.to_string(),
            encrypted_mempool_suite:
                PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_ENCRYPTED_MEMPOOL_SUITE.to_string(),
            epoch_blocks: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_EPOCH_BLOCKS,
            slot_ms: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_SLOT_MS,
            max_committees: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_COMMITTEES,
            max_members: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_MEMBERS,
            max_windows: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_WINDOWS,
            max_order_intents: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_ORDER_INTENTS,
            max_receipts: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_committee_weight_bps:
                PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS,
            fast_quorum_bps: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_FAST_QUORUM_BPS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            slash_bps: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEFAULT_SLASH_BPS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("protocol_version", &self.protocol_version)?;
        required("chain_id", &self.chain_id)?;
        required("hash_suite", &self.hash_suite)?;
        required("pq_suite", &self.pq_suite)?;
        required("encrypted_mempool_suite", &self.encrypted_mempool_suite)?;
        if self.chain_id != CHAIN_ID {
            return Err("PQ sequencer committee chain id mismatch".to_string());
        }
        if !self.roots_only {
            return Err("PQ sequencer committee requires roots-only privacy".to_string());
        }
        if self.epoch_blocks == 0
            || self.slot_ms == 0
            || self.max_committees == 0
            || self.max_members == 0
            || self.max_windows == 0
            || self.max_order_intents == 0
            || self.max_receipts == 0
        {
            return Err("PQ sequencer committee capacities must be positive".to_string());
        }
        if self.min_committee_weight_bps == 0
            || self.min_committee_weight_bps > PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS
            || self.fast_quorum_bps < self.min_committee_weight_bps
            || self.fast_quorum_bps > PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS
        {
            return Err("PQ sequencer committee quorum policy is invalid".to_string());
        }
        if self.min_privacy_set_size == 0 || self.min_pq_security_bits < 192 {
            return Err("PQ sequencer committee privacy/PQ policy is invalid".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS
            || self.slash_bps > PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS
        {
            return Err("PQ sequencer committee bps policy is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "encrypted_mempool_suite": self.encrypted_mempool_suite,
            "epoch_blocks": self.epoch_blocks,
            "slot_ms": self.slot_ms,
            "max_committees": self.max_committees,
            "max_members": self.max_members,
            "max_windows": self.max_windows,
            "max_order_intents": self.max_order_intents,
            "max_receipts": self.max_receipts,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "slash_bps": self.slash_bps,
            "roots_only": self.roots_only,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub committee_counter: u64,
    pub member_counter: u64,
    pub window_counter: u64,
    pub order_counter: u64,
    pub preconfirmation_counter: u64,
    pub receipt_counter: u64,
    pub slash_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_counter": self.committee_counter,
            "member_counter": self.member_counter,
            "window_counter": self.window_counter,
            "order_counter": self.order_counter,
            "preconfirmation_counter": self.preconfirmation_counter,
            "receipt_counter": self.receipt_counter,
            "slash_counter": self.slash_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterCommitteeRequest {
    pub committee_kind: CommitteeKind,
    pub operator_set_root: String,
    pub epoch: u64,
    pub stake_root: String,
    pub threshold_key_root: String,
    pub encrypted_mempool_root: String,
    pub low_fee_policy_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub member_set_size: u64,
    pub committee_weight_bps: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
}

impl RegisterCommitteeRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("operator_set_root", &self.operator_set_root)?;
        required("stake_root", &self.stake_root)?;
        required("threshold_key_root", &self.threshold_key_root)?;
        required("encrypted_mempool_root", &self.encrypted_mempool_root)?;
        required("low_fee_policy_root", &self.low_fee_policy_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        if self.member_set_size < config.min_privacy_set_size {
            return Err("PQ sequencer committee member set below privacy floor".to_string());
        }
        if self.committee_weight_bps < config.min_committee_weight_bps {
            return Err("PQ sequencer committee weight below quorum floor".to_string());
        }
        if self.committee_weight_bps > PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS {
            return Err("PQ sequencer committee weight exceeds BPS range".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("PQ sequencer committee security bits below floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_kind": self.committee_kind.as_str(),
            "operator_set_root": self.operator_set_root,
            "epoch": self.epoch,
            "stake_root": self.stake_root,
            "threshold_key_root": self.threshold_key_root,
            "encrypted_mempool_root": self.encrypted_mempool_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "member_set_size": self.member_set_size,
            "committee_weight_bps": self.committee_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterMemberRequest {
    pub committee_id: String,
    pub member_commitment: String,
    pub stake_commitment_root: String,
    pub pq_public_key_root: String,
    pub vrf_key_root: String,
    pub network_address_root: String,
    pub admission_proof_root: String,
    pub privacy_proof_root: String,
    pub member_weight_bps: u64,
    pub pq_security_bits: u16,
    pub joined_at_height: u64,
    pub member_nonce: String,
}

impl RegisterMemberRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("committee_id", &self.committee_id)?;
        required("member_commitment", &self.member_commitment)?;
        required("stake_commitment_root", &self.stake_commitment_root)?;
        required("pq_public_key_root", &self.pq_public_key_root)?;
        required("vrf_key_root", &self.vrf_key_root)?;
        required("network_address_root", &self.network_address_root)?;
        required("admission_proof_root", &self.admission_proof_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("member_nonce", &self.member_nonce)?;
        if self.member_weight_bps == 0
            || self.member_weight_bps > PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_MAX_BPS
        {
            return Err("PQ sequencer member weight is invalid".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("PQ sequencer member security bits below floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "member_commitment": self.member_commitment,
            "stake_commitment_root": self.stake_commitment_root,
            "pq_public_key_root": self.pq_public_key_root,
            "vrf_key_root": self.vrf_key_root,
            "network_address_root": self.network_address_root,
            "admission_proof_root": self.admission_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "member_weight_bps": self.member_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "joined_at_height": self.joined_at_height,
            "member_nonce": self.member_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenScheduleWindowRequest {
    pub committee_id: String,
    pub lane: OrderLane,
    pub epoch: u64,
    pub slot: u64,
    pub encrypted_order_root: String,
    pub fair_ordering_seed_root: String,
    pub da_hint_root: String,
    pub low_fee_policy_root: String,
    pub pq_window_signature_root: String,
    pub privacy_proof_root: String,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl OpenScheduleWindowRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("committee_id", &self.committee_id)?;
        required("encrypted_order_root", &self.encrypted_order_root)?;
        required("fair_ordering_seed_root", &self.fair_ordering_seed_root)?;
        required("da_hint_root", &self.da_hint_root)?;
        required("low_fee_policy_root", &self.low_fee_policy_root)?;
        required("pq_window_signature_root", &self.pq_window_signature_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("PQ sequencer window fee exceeds low-fee policy".to_string());
        }
        if self.closes_at_height <= self.opened_at_height {
            return Err("PQ sequencer window closes before it opens".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "slot": self.slot,
            "encrypted_order_root": self.encrypted_order_root,
            "fair_ordering_seed_root": self.fair_ordering_seed_root,
            "da_hint_root": self.da_hint_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "pq_window_signature_root": self.pq_window_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedOrderRequest {
    pub schedule_window_id: String,
    pub lane: OrderLane,
    pub account_commitment: String,
    pub encrypted_payload_root: String,
    pub state_read_root: String,
    pub state_write_hint_root: String,
    pub fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub order_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitEncryptedOrderRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("schedule_window_id", &self.schedule_window_id)?;
        required("account_commitment", &self.account_commitment)?;
        required("encrypted_payload_root", &self.encrypted_payload_root)?;
        required("state_read_root", &self.state_read_root)?;
        required("state_write_hint_root", &self.state_write_hint_root)?;
        required("fee_sponsor_root", &self.fee_sponsor_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("replay_fence_root", &self.replay_fence_root)?;
        required("order_nullifier", &self.order_nullifier)?;
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("PQ sequencer order fee exceeds low-fee policy".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("PQ sequencer order expires before it can be scheduled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schedule_window_id": self.schedule_window_id,
            "lane": self.lane.as_str(),
            "account_commitment": self.account_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "state_read_root": self.state_read_root,
            "state_write_hint_root": self.state_write_hint_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "order_nullifier": self.order_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPreconfirmationRequest {
    pub schedule_window_id: String,
    pub order_ids: Vec<String>,
    pub builder_commitment: String,
    pub ordered_intent_root: String,
    pub aggregate_pq_signature_root: String,
    pub aggregate_privacy_proof_root: String,
    pub low_fee_receipt_root: String,
    pub da_publication_root: String,
    pub quorum_weight_bps: u64,
    pub built_at_height: u64,
}

impl BuildPreconfirmationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("schedule_window_id", &self.schedule_window_id)?;
        required("builder_commitment", &self.builder_commitment)?;
        required("ordered_intent_root", &self.ordered_intent_root)?;
        required(
            "aggregate_pq_signature_root",
            &self.aggregate_pq_signature_root,
        )?;
        required(
            "aggregate_privacy_proof_root",
            &self.aggregate_privacy_proof_root,
        )?;
        required("low_fee_receipt_root", &self.low_fee_receipt_root)?;
        required("da_publication_root", &self.da_publication_root)?;
        if self.order_ids.is_empty() {
            return Err("PQ sequencer preconfirmation requires orders".to_string());
        }
        if self.quorum_weight_bps < config.fast_quorum_bps {
            return Err("PQ sequencer preconfirmation quorum below fast quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schedule_window_id": self.schedule_window_id,
            "order_ids": self.order_ids,
            "builder_commitment": self.builder_commitment,
            "ordered_intent_root": self.ordered_intent_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "da_publication_root": self.da_publication_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishFastReceiptRequest {
    pub preconfirmation_id: String,
    pub fast_block_root: String,
    pub settlement_hint_root: String,
    pub fee_receipt_root: String,
    pub pq_receipt_signature_root: String,
    pub published_at_height: u64,
}

impl PublishFastReceiptRequest {
    pub fn validate(&self) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("preconfirmation_id", &self.preconfirmation_id)?;
        required("fast_block_root", &self.fast_block_root)?;
        required("settlement_hint_root", &self.settlement_hint_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_receipt_signature_root", &self.pq_receipt_signature_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "fast_block_root": self.fast_block_root,
            "settlement_hint_root": self.settlement_hint_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_receipt_signature_root": self.pq_receipt_signature_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashMemberRequest {
    pub committee_id: String,
    pub member_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slashing_proof_root: String,
    pub reporter_commitment: String,
    pub pq_report_signature_root: String,
    pub slash_bps: u64,
    pub reported_at_height: u64,
}

impl SlashMemberRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        required("committee_id", &self.committee_id)?;
        required("member_id", &self.member_id)?;
        required("evidence_root", &self.evidence_root)?;
        required("slashing_proof_root", &self.slashing_proof_root)?;
        required("reporter_commitment", &self.reporter_commitment)?;
        required("pq_report_signature_root", &self.pq_report_signature_root)?;
        if self.slash_bps == 0 || self.slash_bps > config.slash_bps {
            return Err("PQ sequencer slash bps exceeds policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slashing_proof_root": self.slashing_proof_root,
            "reporter_commitment": self.reporter_commitment,
            "pq_report_signature_root": self.pq_report_signature_root,
            "slash_bps": self.slash_bps,
            "reported_at_height": self.reported_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeRecord {
    pub committee_id: String,
    pub committee_kind: CommitteeKind,
    pub status: CommitteeStatus,
    pub operator_set_root: String,
    pub epoch: u64,
    pub stake_root: String,
    pub threshold_key_root: String,
    pub encrypted_mempool_root: String,
    pub low_fee_policy_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub member_set_size: u64,
    pub committee_weight_bps: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub member_ids: Vec<String>,
    pub window_ids: Vec<String>,
}

impl CommitteeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "committee_kind": self.committee_kind.as_str(),
            "status": self.status.as_str(),
            "operator_set_root": self.operator_set_root,
            "epoch": self.epoch,
            "stake_root": self.stake_root,
            "threshold_key_root": self.threshold_key_root,
            "encrypted_mempool_root": self.encrypted_mempool_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "member_set_size": self.member_set_size,
            "committee_weight_bps": self.committee_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
            "member_ids": self.member_ids,
            "window_ids": self.window_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    pub member_id: String,
    pub committee_id: String,
    pub member_commitment: String,
    pub stake_commitment_root: String,
    pub pq_public_key_root: String,
    pub vrf_key_root: String,
    pub network_address_root: String,
    pub admission_proof_root: String,
    pub privacy_proof_root: String,
    pub member_weight_bps: u64,
    pub pq_security_bits: u16,
    pub status: MemberStatus,
    pub joined_at_height: u64,
    pub member_nonce: String,
}

impl MemberRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "member_commitment": self.member_commitment,
            "stake_commitment_root": self.stake_commitment_root,
            "pq_public_key_root": self.pq_public_key_root,
            "vrf_key_root": self.vrf_key_root,
            "network_address_root": self.network_address_root,
            "admission_proof_root": self.admission_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "member_weight_bps": self.member_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "joined_at_height": self.joined_at_height,
            "member_nonce": self.member_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleWindowRecord {
    pub schedule_window_id: String,
    pub committee_id: String,
    pub lane: OrderLane,
    pub status: WindowStatus,
    pub epoch: u64,
    pub slot: u64,
    pub encrypted_order_root: String,
    pub fair_ordering_seed_root: String,
    pub da_hint_root: String,
    pub low_fee_policy_root: String,
    pub pq_window_signature_root: String,
    pub privacy_proof_root: String,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub order_ids: Vec<String>,
    pub preconfirmation_ids: Vec<String>,
}

impl ScheduleWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "schedule_window_id": self.schedule_window_id,
            "committee_id": self.committee_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "slot": self.slot,
            "encrypted_order_root": self.encrypted_order_root,
            "fair_ordering_seed_root": self.fair_ordering_seed_root,
            "da_hint_root": self.da_hint_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "pq_window_signature_root": self.pq_window_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "order_ids": self.order_ids,
            "preconfirmation_ids": self.preconfirmation_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOrderRecord {
    pub order_id: String,
    pub schedule_window_id: String,
    pub lane: OrderLane,
    pub account_commitment: String,
    pub encrypted_payload_root: String,
    pub state_read_root: String,
    pub state_write_hint_root: String,
    pub fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub order_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub priority_score: u64,
    pub status: OrderStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedOrderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "schedule_window_id": self.schedule_window_id,
            "lane": self.lane.as_str(),
            "account_commitment": self.account_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "state_read_root": self.state_read_root,
            "state_write_hint_root": self.state_write_hint_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "order_nullifier": self.order_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "priority_score": self.priority_score,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationRecord {
    pub preconfirmation_id: String,
    pub schedule_window_id: String,
    pub order_ids: Vec<String>,
    pub builder_commitment: String,
    pub ordered_intent_root: String,
    pub aggregate_pq_signature_root: String,
    pub aggregate_privacy_proof_root: String,
    pub low_fee_receipt_root: String,
    pub da_publication_root: String,
    pub quorum_weight_bps: u64,
    pub status: PreconfirmationStatus,
    pub built_at_height: u64,
    pub receipt_ids: Vec<String>,
}

impl PreconfirmationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "schedule_window_id": self.schedule_window_id,
            "order_ids": self.order_ids,
            "builder_commitment": self.builder_commitment,
            "ordered_intent_root": self.ordered_intent_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "da_publication_root": self.da_publication_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "receipt_ids": self.receipt_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastReceiptRecord {
    pub receipt_id: String,
    pub preconfirmation_id: String,
    pub fast_block_root: String,
    pub settlement_hint_root: String,
    pub fee_receipt_root: String,
    pub pq_receipt_signature_root: String,
    pub published_at_height: u64,
}

impl FastReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "preconfirmation_id": self.preconfirmation_id,
            "fast_block_root": self.fast_block_root,
            "settlement_hint_root": self.settlement_hint_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_receipt_signature_root": self.pq_receipt_signature_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashRecord {
    pub slash_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slashing_proof_root: String,
    pub reporter_commitment: String,
    pub pq_report_signature_root: String,
    pub slash_bps: u64,
    pub reported_at_height: u64,
}

impl SlashRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slashing_proof_root": self.slashing_proof_root,
            "reporter_commitment": self.reporter_commitment,
            "pq_report_signature_root": self.pq_report_signature_root,
            "slash_bps": self.slash_bps,
            "reported_at_height": self.reported_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub committee_root: String,
    pub member_root: String,
    pub schedule_window_root: String,
    pub order_root: String,
    pub preconfirmation_root: String,
    pub receipt_root: String,
    pub slash_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_root": self.committee_root,
            "member_root": self.member_root,
            "schedule_window_root": self.schedule_window_root,
            "order_root": self.order_root,
            "preconfirmation_root": self.preconfirmation_root,
            "receipt_root": self.receipt_root,
            "slash_root": self.slash_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub counters: Counters,
    pub committees: BTreeMap<String, CommitteeRecord>,
    pub members: BTreeMap<String, MemberRecord>,
    pub schedule_windows: BTreeMap<String, ScheduleWindowRecord>,
    pub orders: BTreeMap<String, EncryptedOrderRecord>,
    pub preconfirmations: BTreeMap<String, PreconfirmationRecord>,
    pub receipts: BTreeMap<String, FastReceiptRecord>,
    pub slashes: BTreeMap<String, SlashRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqSequencerCommitteeRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            config,
            current_height: PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_DEVNET_HEIGHT,
            counters: Counters::default(),
            committees: BTreeMap::new(),
            members: BTreeMap::new(),
            schedule_windows: BTreeMap::new(),
            orders: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            slashes: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_committee(
        &mut self,
        request: RegisterCommitteeRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<CommitteeRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.committees.len() >= self.config.max_committees {
            return Err("PQ sequencer committee capacity exhausted".to_string());
        }
        self.counters.committee_counter = self.counters.committee_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let committee_id = committee_id(&request, self.counters.committee_counter);
        let committee = CommitteeRecord {
            committee_id: committee_id.clone(),
            committee_kind: request.committee_kind,
            status: CommitteeStatus::Active,
            operator_set_root: request.operator_set_root,
            epoch: request.epoch,
            stake_root: request.stake_root,
            threshold_key_root: request.threshold_key_root,
            encrypted_mempool_root: request.encrypted_mempool_root,
            low_fee_policy_root: request.low_fee_policy_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            member_set_size: request.member_set_size,
            committee_weight_bps: request.committee_weight_bps,
            pq_security_bits: request.pq_security_bits,
            registered_at_height: request.registered_at_height,
            member_ids: Vec::new(),
            window_ids: Vec::new(),
        };
        self.committees.insert(committee_id, committee.clone());
        Ok(committee)
    }

    pub fn register_member(
        &mut self,
        request: RegisterMemberRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<MemberRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.members.len() >= self.config.max_members {
            return Err("PQ sequencer member capacity exhausted".to_string());
        }
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "PQ sequencer committee not found for member".to_string())?;
        if !committee.status.can_sequence() {
            return Err("PQ sequencer committee is not active".to_string());
        }
        self.counters.member_counter = self.counters.member_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.joined_at_height);
        let member_id = member_id(&request, self.counters.member_counter);
        let member = MemberRecord {
            member_id: member_id.clone(),
            committee_id: request.committee_id.clone(),
            member_commitment: request.member_commitment,
            stake_commitment_root: request.stake_commitment_root,
            pq_public_key_root: request.pq_public_key_root,
            vrf_key_root: request.vrf_key_root,
            network_address_root: request.network_address_root,
            admission_proof_root: request.admission_proof_root,
            privacy_proof_root: request.privacy_proof_root,
            member_weight_bps: request.member_weight_bps,
            pq_security_bits: request.pq_security_bits,
            status: MemberStatus::Active,
            joined_at_height: request.joined_at_height,
            member_nonce: request.member_nonce,
        };
        if let Some(committee) = self.committees.get_mut(&request.committee_id) {
            committee.member_ids.push(member_id.clone());
        }
        self.members.insert(member_id, member.clone());
        Ok(member)
    }

    pub fn open_schedule_window(
        &mut self,
        request: OpenScheduleWindowRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<ScheduleWindowRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.schedule_windows.len() >= self.config.max_windows {
            return Err("PQ sequencer schedule window capacity exhausted".to_string());
        }
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "PQ sequencer committee not found for schedule window".to_string())?;
        if !committee.status.can_sequence() {
            return Err("PQ sequencer committee cannot open schedule windows".to_string());
        }
        self.counters.window_counter = self.counters.window_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let schedule_window_id = schedule_window_id(&request, self.counters.window_counter);
        let window = ScheduleWindowRecord {
            schedule_window_id: schedule_window_id.clone(),
            committee_id: request.committee_id.clone(),
            lane: request.lane,
            status: WindowStatus::Open,
            epoch: request.epoch,
            slot: request.slot,
            encrypted_order_root: request.encrypted_order_root,
            fair_ordering_seed_root: request.fair_ordering_seed_root,
            da_hint_root: request.da_hint_root,
            low_fee_policy_root: request.low_fee_policy_root,
            pq_window_signature_root: request.pq_window_signature_root,
            privacy_proof_root: request.privacy_proof_root,
            max_fee_bps: request.max_fee_bps,
            opened_at_height: request.opened_at_height,
            closes_at_height: request.closes_at_height,
            order_ids: Vec::new(),
            preconfirmation_ids: Vec::new(),
        };
        if let Some(committee) = self.committees.get_mut(&request.committee_id) {
            committee.window_ids.push(schedule_window_id.clone());
        }
        self.schedule_windows
            .insert(schedule_window_id, window.clone());
        Ok(window)
    }

    pub fn submit_encrypted_order(
        &mut self,
        request: SubmitEncryptedOrderRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<EncryptedOrderRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.orders.len() >= self.config.max_order_intents {
            return Err("PQ sequencer order capacity exhausted".to_string());
        }
        {
            let window = self
                .schedule_windows
                .get(&request.schedule_window_id)
                .ok_or_else(|| "PQ sequencer schedule window not found".to_string())?;
            if !window.status.live() {
                return Err("PQ sequencer schedule window is not live".to_string());
            }
            if window.lane != request.lane {
                return Err("PQ sequencer order lane does not match window".to_string());
            }
            if request.submitted_at_height >= window.closes_at_height {
                return Err("PQ sequencer order submitted after window close".to_string());
            }
            if request.max_fee_bps > window.max_fee_bps {
                return Err("PQ sequencer order exceeds window fee cap".to_string());
            }
        }
        self.consume_nullifier(&request.order_nullifier)?;
        self.counters.order_counter = self.counters.order_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let order_id = order_id(&request, self.counters.order_counter);
        let order = EncryptedOrderRecord {
            order_id: order_id.clone(),
            schedule_window_id: request.schedule_window_id.clone(),
            lane: request.lane,
            account_commitment: request.account_commitment,
            encrypted_payload_root: request.encrypted_payload_root,
            state_read_root: request.state_read_root,
            state_write_hint_root: request.state_write_hint_root,
            fee_sponsor_root: request.fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            replay_fence_root: request.replay_fence_root,
            order_nullifier: request.order_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            priority_score: request.lane.latency_score(),
            status: OrderStatus::Encrypted,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(window) = self.schedule_windows.get_mut(&request.schedule_window_id) {
            window.status = WindowStatus::Locked;
            window.order_ids.push(order_id.clone());
        }
        self.orders.insert(order_id, order.clone());
        Ok(order)
    }

    pub fn build_preconfirmation(
        &mut self,
        request: BuildPreconfirmationRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<PreconfirmationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let mut seen = BTreeSet::new();
        {
            let window = self
                .schedule_windows
                .get(&request.schedule_window_id)
                .ok_or_else(|| {
                    "PQ sequencer schedule window not found for preconfirmation".to_string()
                })?;
            if !window.status.live() {
                return Err("PQ sequencer schedule window is not live".to_string());
            }
            if request.built_at_height >= window.closes_at_height {
                return Err("PQ sequencer preconfirmation built after window close".to_string());
            }
            for order_id in &request.order_ids {
                if !seen.insert(order_id.clone()) {
                    return Err("PQ sequencer preconfirmation has duplicate order".to_string());
                }
                let order = self
                    .orders
                    .get(order_id)
                    .ok_or_else(|| format!("PQ sequencer order {order_id} missing"))?;
                if order.schedule_window_id != request.schedule_window_id {
                    return Err("PQ sequencer preconfirmation mixes windows".to_string());
                }
                if !order.status.schedulable() {
                    return Err("PQ sequencer order is not schedulable".to_string());
                }
                if request.built_at_height >= order.expires_at_height {
                    return Err("PQ sequencer order expired before preconfirmation".to_string());
                }
            }
        }
        self.counters.preconfirmation_counter =
            self.counters.preconfirmation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let preconfirmation_id =
            preconfirmation_id(&request, self.counters.preconfirmation_counter);
        for order_id in &request.order_ids {
            if let Some(order) = self.orders.get_mut(order_id) {
                order.status = OrderStatus::Preconfirmed;
            }
        }
        if let Some(window) = self.schedule_windows.get_mut(&request.schedule_window_id) {
            window.status = WindowStatus::Preconfirmed;
            window.preconfirmation_ids.push(preconfirmation_id.clone());
        }
        let preconfirmation = PreconfirmationRecord {
            preconfirmation_id: preconfirmation_id.clone(),
            schedule_window_id: request.schedule_window_id,
            order_ids: request.order_ids,
            builder_commitment: request.builder_commitment,
            ordered_intent_root: request.ordered_intent_root,
            aggregate_pq_signature_root: request.aggregate_pq_signature_root,
            aggregate_privacy_proof_root: request.aggregate_privacy_proof_root,
            low_fee_receipt_root: request.low_fee_receipt_root,
            da_publication_root: request.da_publication_root,
            quorum_weight_bps: request.quorum_weight_bps,
            status: PreconfirmationStatus::QuorumReady,
            built_at_height: request.built_at_height,
            receipt_ids: Vec::new(),
        };
        self.preconfirmations
            .insert(preconfirmation_id, preconfirmation.clone());
        Ok(preconfirmation)
    }

    pub fn publish_fast_receipt(
        &mut self,
        request: PublishFastReceiptRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<FastReceiptRecord> {
        self.config.validate()?;
        request.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("PQ sequencer receipt capacity exhausted".to_string());
        }
        let preconfirmation = self
            .preconfirmations
            .get(&request.preconfirmation_id)
            .ok_or_else(|| "PQ sequencer preconfirmation not found for receipt".to_string())?;
        if preconfirmation.status == PreconfirmationStatus::Rejected {
            return Err("PQ sequencer rejected preconfirmation cannot receive receipt".to_string());
        }
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.published_at_height);
        let receipt_id = receipt_id(&request, self.counters.receipt_counter);
        let receipt = FastReceiptRecord {
            receipt_id: receipt_id.clone(),
            preconfirmation_id: request.preconfirmation_id.clone(),
            fast_block_root: request.fast_block_root,
            settlement_hint_root: request.settlement_hint_root,
            fee_receipt_root: request.fee_receipt_root,
            pq_receipt_signature_root: request.pq_receipt_signature_root,
            published_at_height: request.published_at_height,
        };
        if let Some(preconfirmation) = self.preconfirmations.get_mut(&request.preconfirmation_id) {
            preconfirmation.status = PreconfirmationStatus::Published;
            preconfirmation.receipt_ids.push(receipt_id.clone());
        }
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn slash_member(
        &mut self,
        request: SlashMemberRequest,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<SlashRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let member = self
            .members
            .get(&request.member_id)
            .ok_or_else(|| "PQ sequencer member not found for slashing".to_string())?;
        if member.committee_id != request.committee_id {
            return Err("PQ sequencer slash member belongs to a different committee".to_string());
        }
        self.counters.slash_counter = self.counters.slash_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.reported_at_height);
        let slash_id = slash_id(&request, self.counters.slash_counter);
        let slash = SlashRecord {
            slash_id: slash_id.clone(),
            committee_id: request.committee_id.clone(),
            member_id: request.member_id.clone(),
            reason: request.reason,
            evidence_root: request.evidence_root,
            slashing_proof_root: request.slashing_proof_root,
            reporter_commitment: request.reporter_commitment,
            pq_report_signature_root: request.pq_report_signature_root,
            slash_bps: request.slash_bps,
            reported_at_height: request.reported_at_height,
        };
        if let Some(member) = self.members.get_mut(&request.member_id) {
            member.status = MemberStatus::Slashed;
        }
        if let Some(committee) = self.committees.get_mut(&request.committee_id) {
            committee.status = CommitteeStatus::Slashed;
        }
        self.slashes.insert(slash_id, slash.clone());
        Ok(slash)
    }

    pub fn roots(&self) -> Roots {
        let committee_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-COMMITTEES",
            &self
                .committees
                .values()
                .map(CommitteeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let member_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-MEMBERS",
            &self
                .members
                .values()
                .map(MemberRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let schedule_window_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-WINDOWS",
            &self
                .schedule_windows
                .values()
                .map(ScheduleWindowRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let order_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-ORDERS",
            &self
                .orders
                .values()
                .map(EncryptedOrderRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let preconfirmation_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-PRECONFIRMATIONS",
            &self
                .preconfirmations
                .values()
                .map(PreconfirmationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-RECEIPTS",
            &self
                .receipts
                .values()
                .map(FastReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let slash_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-SLASHES",
            &self
                .slashes
                .values()
                .map(SlashRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-SEQUENCER-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-SEQUENCER-STATE",
            &json!({
                "protocol_version": self.config.protocol_version,
                "chain_id": self.config.chain_id,
                "current_height": self.current_height,
                "committee_root": committee_root,
                "member_root": member_root,
                "schedule_window_root": schedule_window_root,
                "order_root": order_root,
                "preconfirmation_root": preconfirmation_root,
                "receipt_root": receipt_root,
                "slash_root": slash_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            committee_root,
            member_root,
            schedule_window_root,
            order_root,
            preconfirmation_root,
            receipt_root,
            slash_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_suite": self.config.pq_suite,
            "encrypted_mempool_suite": self.config.encrypted_mempool_suite,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "committee_ids": self.committees.keys().cloned().collect::<Vec<_>>(),
            "member_ids": self.members.keys().cloned().collect::<Vec<_>>(),
            "schedule_window_ids": self.schedule_windows.keys().cloned().collect::<Vec<_>>(),
            "order_ids": self.orders.keys().cloned().collect::<Vec<_>>(),
            "preconfirmation_ids": self.preconfirmations.keys().cloned().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().cloned().collect::<Vec<_>>(),
            "slash_ids": self.slashes.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
        let nullifier_root = root_from_record(
            "PRIVATE-L2-PQ-SEQUENCER-NULLIFIER",
            &json!({ "nullifier": nullifier }),
        );
        if !self.consumed_nullifiers.insert(nullifier_root) {
            return Err("PQ sequencer committee nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn committee_id(request: &RegisterCommitteeRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-COMMITTEE-ID",
        &json!({
            "counter": counter,
            "committee_kind": request.committee_kind.as_str(),
            "operator_set_root": request.operator_set_root,
            "epoch": request.epoch,
            "threshold_key_root": request.threshold_key_root,
        }),
    )
}

pub fn member_id(request: &RegisterMemberRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-MEMBER-ID",
        &json!({
            "counter": counter,
            "committee_id": request.committee_id,
            "member_commitment": request.member_commitment,
            "pq_public_key_root": request.pq_public_key_root,
            "member_nonce": request.member_nonce,
        }),
    )
}

pub fn schedule_window_id(request: &OpenScheduleWindowRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-WINDOW-ID",
        &json!({
            "counter": counter,
            "committee_id": request.committee_id,
            "lane": request.lane.as_str(),
            "epoch": request.epoch,
            "slot": request.slot,
            "fair_ordering_seed_root": request.fair_ordering_seed_root,
        }),
    )
}

pub fn order_id(request: &SubmitEncryptedOrderRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-ORDER-ID",
        &json!({
            "counter": counter,
            "schedule_window_id": request.schedule_window_id,
            "lane": request.lane.as_str(),
            "account_commitment": request.account_commitment,
            "encrypted_payload_root": request.encrypted_payload_root,
            "order_nullifier": request.order_nullifier,
        }),
    )
}

pub fn preconfirmation_id(request: &BuildPreconfirmationRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-PRECONFIRMATION-ID",
        &json!({
            "counter": counter,
            "schedule_window_id": request.schedule_window_id,
            "order_ids": request.order_ids,
            "ordered_intent_root": request.ordered_intent_root,
            "quorum_weight_bps": request.quorum_weight_bps,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn receipt_id(request: &PublishFastReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-FAST-RECEIPT-ID",
        &json!({
            "counter": counter,
            "preconfirmation_id": request.preconfirmation_id,
            "fast_block_root": request.fast_block_root,
            "settlement_hint_root": request.settlement_hint_root,
            "published_at_height": request.published_at_height,
        }),
    )
}

pub fn slash_id(request: &SlashMemberRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-SEQUENCER-SLASH-ID",
        &json!({
            "counter": counter,
            "committee_id": request.committee_id,
            "member_id": request.member_id,
            "reason": request.reason.as_str(),
            "evidence_root": request.evidence_root,
            "reported_at_height": request.reported_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_SEQUENCER_COMMITTEE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-PQ-SEQUENCER-PAYLOAD-{domain}"),
        payload,
    )
}

fn required(field: &str, value: &str) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("PQ sequencer committee field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqSequencerCommitteeRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("PQ sequencer privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("PQ sequencer PQ security bits below minimum".to_string());
    }
    Ok(())
}
