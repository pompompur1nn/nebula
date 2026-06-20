use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type QuantumSafePrivateOrderflowBatcherResult<T> = Result<T, String>;

pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION: &str =
    "nebula-quantum-safe-private-orderflow-batcher-v1";
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+Kyber-compatible-threshold-reveal-devnet";
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-128f-builder-accountability";
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_FAIRNESS_PROOF_SYSTEM: &str =
    "devnet-fair-order-transcript-v1";
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEVNET_HEIGHT: u64 = 7_240;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_EPOCH_BLOCKS: u64 = 6;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_COMMIT_BLOCKS: u64 = 3;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_REVEAL_BLOCKS: u64 = 4;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_SETTLEMENT_BLOCKS: u64 = 18;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_MIN_PRIVACY_SET: u64 = 32;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_MAX_INTENTS_PER_BATCH: usize = 512;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_MAX_INTENT_BYTES: u64 = 64_000;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 75_000_000;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_BUILDER_BOND_UNITS: u64 = 2_500_000_000;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BPS: u64 = 10_000;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_LANES: usize = 64;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BUILDERS: usize = 512;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_INTENTS: usize = 65_536;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BATCHES: usize = 8_192;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_COMMITMENTS: usize = 65_536;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_REVEAL_WINDOWS: usize = 8_192;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_FAIRNESS_PROOFS: usize = 8_192;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_RECEIPTS: usize = 65_536;
pub const QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_ACCOUNTABILITY_EVENTS: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentClass {
    PrivateSwap,
    MoneroExit,
    AccountOperation,
    LiquidationShield,
    LowFeePayment,
    ContractCall,
    EmergencyUnwind,
}

impl IntentClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::MoneroExit => "monero_exit",
            Self::AccountOperation => "account_operation",
            Self::LiquidationShield => "liquidation_shield",
            Self::LowFeePayment => "low_fee_payment",
            Self::ContractCall => "contract_call",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 180,
            Self::MoneroExit => 150,
            Self::LiquidationShield => 132,
            Self::ContractCall => 116,
            Self::PrivateSwap => 104,
            Self::AccountOperation => 92,
            Self::LowFeePayment => 76,
        }
    }

    pub fn default_lane(self) -> LaneKind {
        match self {
            Self::PrivateSwap => LaneKind::Swap,
            Self::MoneroExit => LaneKind::Exit,
            Self::AccountOperation => LaneKind::Account,
            Self::LiquidationShield => LaneKind::Risk,
            Self::LowFeePayment => LaneKind::Sponsored,
            Self::ContractCall => LaneKind::Contract,
            Self::EmergencyUnwind => LaneKind::Emergency,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Sponsored,
    Swap,
    Exit,
    Account,
    Risk,
    Contract,
    Emergency,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sponsored => "sponsored",
            Self::Swap => "swap",
            Self::Exit => "exit",
            Self::Account => "account",
            Self::Risk => "risk",
            Self::Contract => "contract",
            Self::Emergency => "emergency",
        }
    }

    pub fn ordering_rank(self) -> u64 {
        match self {
            Self::Emergency => 0,
            Self::Exit => 1,
            Self::Risk => 2,
            Self::Swap => 3,
            Self::Contract => 4,
            Self::Account => 5,
            Self::Sponsored => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatus {
    Pending,
    Accepted,
    Throttled,
    Rejected,
    Expired,
}

impl AdmissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Throttled => "throttled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Sealed,
    Revealing,
    Solved,
    Settled,
    Challenged,
    Slashed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Revealing => "revealing",
            Self::Solved => "solved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevealWindowStatus {
    Scheduled,
    Open,
    Closed,
    Finalized,
    Disputed,
}

impl RevealWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairnessProofStatus {
    Draft,
    Submitted,
    Verified,
    Rejected,
    Challenged,
}

impl FairnessProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityEventKind {
    LateReveal,
    InvalidFairnessProof,
    OrderingDeviation,
    CensorshipSuspect,
    BundleLeak,
    SponsorOvercharge,
}

impl AccountabilityEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LateReveal => "late_reveal",
            Self::InvalidFairnessProof => "invalid_fairness_proof",
            Self::OrderingDeviation => "ordering_deviation",
            Self::CensorshipSuspect => "censorship_suspect",
            Self::BundleLeak => "bundle_leak",
            Self::SponsorOvercharge => "sponsor_overcharge",
        }
    }

    pub fn severity_weight(self) -> u64 {
        match self {
            Self::BundleLeak => 100,
            Self::OrderingDeviation => 88,
            Self::InvalidFairnessProof => 80,
            Self::CensorshipSuspect => 66,
            Self::LateReveal => 50,
            Self::SponsorOvercharge => 42,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_encryption_suite: String,
    pub pq_signature_suite: String,
    pub fairness_proof_system: String,
    pub epoch_blocks: u64,
    pub commit_window_blocks: u64,
    pub reveal_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_intents_per_batch: usize,
    pub max_intent_ciphertext_bytes: u64,
    pub default_sponsor_budget_units: u64,
    pub default_builder_bond_units: u64,
    pub max_lane_fee_bps: u64,
    pub sponsor_discount_bps: u64,
    pub slash_fraction_bps: u64,
    pub anti_mev_delay_jitter_blocks: u64,
    pub builder_accountability_enabled: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_HASH_SUITE.to_string(),
            pq_encryption_suite: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_ENCRYPTION_SUITE
                .to_string(),
            pq_signature_suite: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_SIGNATURE_SUITE
                .to_string(),
            fairness_proof_system: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_FAIRNESS_PROOF_SYSTEM
                .to_string(),
            epoch_blocks: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_EPOCH_BLOCKS,
            commit_window_blocks: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_COMMIT_BLOCKS,
            reveal_window_blocks: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_REVEAL_BLOCKS,
            settlement_window_blocks:
                QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_SETTLEMENT_BLOCKS,
            min_privacy_set_size: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_MIN_PRIVACY_SET,
            max_intents_per_batch:
                QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_intent_ciphertext_bytes:
                QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_MAX_INTENT_BYTES,
            default_sponsor_budget_units:
                QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_SPONSOR_BUDGET_UNITS,
            default_builder_bond_units:
                QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEFAULT_BUILDER_BOND_UNITS,
            max_lane_fee_bps: 35,
            sponsor_discount_bps: 7_500,
            slash_fraction_bps: 2_500,
            anti_mev_delay_jitter_blocks: 2,
            builder_accountability_enabled: true,
        }
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        if self.protocol_version != QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION {
            return Err("quantum safe private orderflow protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("quantum safe private orderflow chain id mismatch".to_string());
        }
        if self.epoch_blocks == 0
            || self.commit_window_blocks == 0
            || self.reveal_window_blocks == 0
            || self.settlement_window_blocks == 0
        {
            return Err("quantum safe private orderflow windows must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("quantum safe private orderflow privacy set must be positive".to_string());
        }
        if self.max_intents_per_batch == 0 {
            return Err(
                "quantum safe private orderflow batch capacity must be positive".to_string(),
            );
        }
        if self.max_lane_fee_bps > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BPS
            || self.sponsor_discount_bps > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BPS
            || self.slash_fraction_bps > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BPS
        {
            return Err("quantum safe private orderflow bps value exceeds maximum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_private_orderflow_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_encryption_suite": self.pq_encryption_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "fairness_proof_system": self.fairness_proof_system,
            "epoch_blocks": self.epoch_blocks,
            "commit_window_blocks": self.commit_window_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_intent_ciphertext_bytes": self.max_intent_ciphertext_bytes,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "default_builder_bond_units": self.default_builder_bond_units,
            "max_lane_fee_bps": self.max_lane_fee_bps,
            "sponsor_discount_bps": self.sponsor_discount_bps,
            "slash_fraction_bps": self.slash_fraction_bps,
            "anti_mev_delay_jitter_blocks": self.anti_mev_delay_jitter_blocks,
            "builder_accountability_enabled": self.builder_accountability_enabled,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatcherLane {
    pub lane_id: String,
    pub label: String,
    pub kind: LaneKind,
    pub max_batch_intents: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub sponsor_enabled: bool,
    pub active: bool,
}

impl BatcherLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        kind: LaneKind,
        max_batch_intents: u64,
        max_fee_bps: u64,
        min_privacy_set_size: u64,
        sponsor_enabled: bool,
        active: bool,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        if label.is_empty() {
            return Err("quantum safe private orderflow lane label cannot be empty".to_string());
        }
        if max_batch_intents == 0 || min_privacy_set_size == 0 {
            return Err("quantum safe private orderflow lane limits must be positive".to_string());
        }
        if max_fee_bps > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BPS {
            return Err("quantum safe private orderflow lane fee exceeds max bps".to_string());
        }
        let lane_id = deterministic_id("LANE", &[label, kind.as_str()]);
        Ok(Self {
            lane_id,
            label: label.to_string(),
            kind,
            max_batch_intents,
            max_fee_bps,
            min_privacy_set_size,
            sponsor_enabled,
            active,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("lane_label", &self.label)?;
        if self.max_batch_intents == 0 || self.min_privacy_set_size == 0 {
            return Err("quantum safe private orderflow lane limits must be positive".to_string());
        }
        if self.max_fee_bps > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BPS {
            return Err("quantum safe private orderflow lane fee exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batcher_lane",
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_kind": self.kind.as_str(),
            "ordering_rank": self.kind.ordering_rank(),
            "max_batch_intents": self.max_batch_intents,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "sponsor_enabled": self.sponsor_enabled,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        payload_root("LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderProfile {
    pub builder_id: String,
    pub label: String,
    pub pq_identity_root: String,
    pub bond_units: u64,
    pub reputation_score: u64,
    pub allowed_lane_ids: BTreeSet<String>,
    pub accountability_strikes: u64,
    pub active: bool,
}

impl BuilderProfile {
    pub fn new(
        label: &str,
        bond_units: u64,
        reputation_score: u64,
        allowed_lane_ids: BTreeSet<String>,
        accountability_strikes: u64,
        active: bool,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        if label.is_empty() {
            return Err("quantum safe private orderflow builder label cannot be empty".to_string());
        }
        if bond_units == 0 {
            return Err("quantum safe private orderflow builder bond must be positive".to_string());
        }
        let pq_identity_root = payload_root(
            "BUILDER-PQ-IDENTITY",
            &json!({
                "label": label,
                "signature_suite": QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_SIGNATURE_SUITE,
                "bond_units": bond_units,
            }),
        );
        let builder_id = deterministic_id("BUILDER", &[label, &pq_identity_root]);
        Ok(Self {
            builder_id,
            label: label.to_string(),
            pq_identity_root,
            bond_units,
            reputation_score,
            allowed_lane_ids,
            accountability_strikes,
            active,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("builder_id", &self.builder_id)?;
        require_non_empty("builder_label", &self.label)?;
        require_non_empty("builder_pq_identity_root", &self.pq_identity_root)?;
        if self.bond_units == 0 {
            return Err("quantum safe private orderflow builder bond must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "builder_profile",
            "builder_id": self.builder_id,
            "label": self.label,
            "pq_identity_root": self.pq_identity_root,
            "bond_units": self.bond_units,
            "reputation_score": self.reputation_score,
            "allowed_lane_ids": self.allowed_lane_ids.iter().cloned().collect::<Vec<_>>(),
            "accountability_strikes": self.accountability_strikes,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        payload_root("BUILDER", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub account_commitment: String,
    pub intent_class: IntentClass,
    pub lane_id: String,
    pub ciphertext_root: String,
    pub pq_ephemeral_key_root: String,
    pub nullifier_commitment: String,
    pub admission_policy_root: String,
    pub max_fee_units: u64,
    pub notional_hint_units: u64,
    pub received_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_requested: bool,
    pub builder_hint_root: String,
}

impl EncryptedIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        intent_class: IntentClass,
        lane_id: &str,
        max_fee_units: u64,
        notional_hint_units: u64,
        received_at_height: u64,
        expires_at_height: u64,
        sponsor_requested: bool,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        require_non_empty("account_label", account_label)?;
        require_non_empty("lane_id", lane_id)?;
        if expires_at_height <= received_at_height {
            return Err(
                "quantum safe private orderflow intent expiry must be after receipt".to_string(),
            );
        }
        let account_commitment = deterministic_id("ACCOUNT", &[account_label]);
        let ciphertext_root = payload_root(
            "INTENT-CIPHERTEXT",
            &json!({
                "account_commitment": account_commitment,
                "intent_class": intent_class.as_str(),
                "lane_id": lane_id,
                "notional_hint_units": notional_hint_units,
                "received_at_height": received_at_height,
            }),
        );
        let pq_ephemeral_key_root = payload_root(
            "INTENT-PQ-KEY",
            &json!({
                "account_label": account_label,
                "encryption_suite": QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_ENCRYPTION_SUITE,
                "received_at_height": received_at_height,
            }),
        );
        let nullifier_commitment =
            deterministic_id("INTENT-NULLIFIER", &[account_label, intent_class.as_str()]);
        let admission_policy_root = payload_root(
            "ADMISSION-POLICY",
            &json!({
                "lane_id": lane_id,
                "sponsor_requested": sponsor_requested,
                "max_fee_units": max_fee_units,
            }),
        );
        let builder_hint_root = payload_root(
            "BUILDER-HINT",
            &json!({
                "lane_id": lane_id,
                "priority_weight": intent_class.priority_weight(),
                "notional_hint_units": notional_hint_units,
            }),
        );
        let intent_id = deterministic_id(
            "INTENT",
            &[&account_commitment, &ciphertext_root, &nullifier_commitment],
        );
        Ok(Self {
            intent_id,
            account_commitment,
            intent_class,
            lane_id: lane_id.to_string(),
            ciphertext_root,
            pq_ephemeral_key_root,
            nullifier_commitment,
            admission_policy_root,
            max_fee_units,
            notional_hint_units,
            received_at_height,
            expires_at_height,
            sponsor_requested,
            builder_hint_root,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("ciphertext_root", &self.ciphertext_root)?;
        require_non_empty("pq_ephemeral_key_root", &self.pq_ephemeral_key_root)?;
        require_non_empty("nullifier_commitment", &self.nullifier_commitment)?;
        if self.expires_at_height <= self.received_at_height {
            return Err(
                "quantum safe private orderflow intent expiry must be after receipt".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_intent",
            "intent_id": self.intent_id,
            "account_commitment": self.account_commitment,
            "intent_class": self.intent_class.as_str(),
            "lane_id": self.lane_id,
            "ciphertext_root": self.ciphertext_root,
            "pq_ephemeral_key_root": self.pq_ephemeral_key_root,
            "nullifier_commitment": self.nullifier_commitment,
            "admission_policy_root": self.admission_policy_root,
            "max_fee_units": self.max_fee_units,
            "notional_hint_units": self.notional_hint_units,
            "received_at_height": self.received_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_requested": self.sponsor_requested,
            "builder_hint_root": self.builder_hint_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMempoolAdmission {
    pub admission_id: String,
    pub intent_id: String,
    pub lane_id: String,
    pub status: AdmissionStatus,
    pub received_by_builder_id: String,
    pub privacy_set_size: u64,
    pub fee_cap_units: u64,
    pub anti_spam_score: u64,
    pub admission_root: String,
    pub admitted_at_height: u64,
}

impl PrivateMempoolAdmission {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: &EncryptedIntent,
        status: AdmissionStatus,
        received_by_builder_id: &str,
        privacy_set_size: u64,
        anti_spam_score: u64,
        admitted_at_height: u64,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        intent.validate()?;
        require_non_empty("received_by_builder_id", received_by_builder_id)?;
        if privacy_set_size == 0 {
            return Err(
                "quantum safe private orderflow admission privacy set must be positive".to_string(),
            );
        }
        let admission_root = payload_root(
            "MEMPOOL-ADMISSION",
            &json!({
                "intent_id": intent.intent_id,
                "lane_id": intent.lane_id,
                "status": status.as_str(),
                "privacy_set_size": privacy_set_size,
                "anti_spam_score": anti_spam_score,
                "admitted_at_height": admitted_at_height,
            }),
        );
        let admission_id = deterministic_id("ADMISSION", &[&intent.intent_id, &admission_root]);
        Ok(Self {
            admission_id,
            intent_id: intent.intent_id.clone(),
            lane_id: intent.lane_id.clone(),
            status,
            received_by_builder_id: received_by_builder_id.to_string(),
            privacy_set_size,
            fee_cap_units: intent.max_fee_units,
            anti_spam_score,
            admission_root,
            admitted_at_height,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("admission_id", &self.admission_id)?;
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("received_by_builder_id", &self.received_by_builder_id)?;
        require_non_empty("admission_root", &self.admission_root)?;
        if self.privacy_set_size == 0 {
            return Err(
                "quantum safe private orderflow admission privacy set must be positive".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_admission",
            "admission_id": self.admission_id,
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "received_by_builder_id": self.received_by_builder_id,
            "privacy_set_size": self.privacy_set_size,
            "fee_cap_units": self.fee_cap_units,
            "anti_spam_score": self.anti_spam_score,
            "admission_root": self.admission_root,
            "admitted_at_height": self.admitted_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ADMISSION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingCommitment {
    pub commitment_id: String,
    pub lane_id: String,
    pub builder_id: String,
    pub epoch: u64,
    pub intent_ids: Vec<String>,
    pub entropy_commitment: String,
    pub anti_mev_order_root: String,
    pub previous_commitment_root: String,
    pub committed_at_height: u64,
}

impl OrderingCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        builder_id: &str,
        epoch: u64,
        intent_ids: Vec<String>,
        previous_commitment_root: &str,
        committed_at_height: u64,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        require_non_empty("lane_id", lane_id)?;
        require_non_empty("builder_id", builder_id)?;
        require_non_empty("previous_commitment_root", previous_commitment_root)?;
        if intent_ids.is_empty() {
            return Err(
                "quantum safe private orderflow ordering commitment requires intents".to_string(),
            );
        }
        require_unique_strings("ordering_intent_ids", &intent_ids)?;
        let entropy_commitment = payload_root(
            "ORDERING-ENTROPY",
            &json!({
                "lane_id": lane_id,
                "builder_id": builder_id,
                "epoch": epoch,
                "previous_commitment_root": previous_commitment_root,
            }),
        );
        let anti_mev_order_root = merkle_root(
            "QUANTUM-SAFE-PRIVATE-ORDERFLOW-ANTI-MEV-ORDER",
            &intent_ids
                .iter()
                .enumerate()
                .map(|(position, intent_id)| {
                    json!({
                        "position": position,
                        "intent_id": intent_id,
                        "lane_id": lane_id,
                        "entropy_commitment": entropy_commitment,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let commitment_id = deterministic_id(
            "ORDERING-COMMITMENT",
            &[
                lane_id,
                builder_id,
                &epoch.to_string(),
                &anti_mev_order_root,
            ],
        );
        Ok(Self {
            commitment_id,
            lane_id: lane_id.to_string(),
            builder_id: builder_id.to_string(),
            epoch,
            intent_ids,
            entropy_commitment,
            anti_mev_order_root,
            previous_commitment_root: previous_commitment_root.to_string(),
            committed_at_height,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("commitment_id", &self.commitment_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("builder_id", &self.builder_id)?;
        require_non_empty("entropy_commitment", &self.entropy_commitment)?;
        require_non_empty("anti_mev_order_root", &self.anti_mev_order_root)?;
        require_non_empty("previous_commitment_root", &self.previous_commitment_root)?;
        if self.intent_ids.is_empty() {
            return Err(
                "quantum safe private orderflow ordering commitment requires intents".to_string(),
            );
        }
        require_unique_strings("ordering_intent_ids", &self.intent_ids)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "ordering_commitment",
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "builder_id": self.builder_id,
            "epoch": self.epoch,
            "intent_ids": self.intent_ids,
            "entropy_commitment": self.entropy_commitment,
            "anti_mev_order_root": self.anti_mev_order_root,
            "previous_commitment_root": self.previous_commitment_root,
            "committed_at_height": self.committed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ORDERING-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBatchAuction {
    pub batch_id: String,
    pub lane_id: String,
    pub builder_id: String,
    pub ordering_commitment_id: String,
    pub epoch: u64,
    pub intent_ids: Vec<String>,
    pub sealed_bid_root: String,
    pub encrypted_bundle_root: String,
    pub clearing_policy_root: String,
    pub expected_surplus_units: u64,
    pub sealed_at_height: u64,
    pub status: BatchStatus,
}

impl SealedBatchAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        builder_id: &str,
        ordering_commitment: &OrderingCommitment,
        expected_surplus_units: u64,
        sealed_at_height: u64,
        status: BatchStatus,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        ordering_commitment.validate()?;
        if ordering_commitment.lane_id != lane_id || ordering_commitment.builder_id != builder_id {
            return Err(
                "quantum safe private orderflow batch does not match ordering commitment"
                    .to_string(),
            );
        }
        let sealed_bid_root = payload_root(
            "SEALED-BID",
            &json!({
                "lane_id": lane_id,
                "builder_id": builder_id,
                "ordering_commitment_id": ordering_commitment.commitment_id,
                "expected_surplus_units": expected_surplus_units,
            }),
        );
        let encrypted_bundle_root = merkle_root(
            "QUANTUM-SAFE-PRIVATE-ORDERFLOW-ENCRYPTED-BUNDLE",
            &ordering_commitment
                .intent_ids
                .iter()
                .map(|intent_id| {
                    json!({
                        "intent_id": intent_id,
                        "sealed_bid_root": sealed_bid_root,
                        "bundle_encryption": QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_ENCRYPTION_SUITE,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let clearing_policy_root = payload_root(
            "CLEARING-POLICY",
            &json!({
                "lane_id": lane_id,
                "epoch": ordering_commitment.epoch,
                "anti_mev_order_root": ordering_commitment.anti_mev_order_root,
                "status": status.as_str(),
            }),
        );
        let batch_id = deterministic_id(
            "SEALED-BATCH",
            &[
                lane_id,
                builder_id,
                &ordering_commitment.commitment_id,
                &sealed_bid_root,
            ],
        );
        Ok(Self {
            batch_id,
            lane_id: lane_id.to_string(),
            builder_id: builder_id.to_string(),
            ordering_commitment_id: ordering_commitment.commitment_id.clone(),
            epoch: ordering_commitment.epoch,
            intent_ids: ordering_commitment.intent_ids.clone(),
            sealed_bid_root,
            encrypted_bundle_root,
            clearing_policy_root,
            expected_surplus_units,
            sealed_at_height,
            status,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("builder_id", &self.builder_id)?;
        require_non_empty("ordering_commitment_id", &self.ordering_commitment_id)?;
        require_non_empty("sealed_bid_root", &self.sealed_bid_root)?;
        require_non_empty("encrypted_bundle_root", &self.encrypted_bundle_root)?;
        require_non_empty("clearing_policy_root", &self.clearing_policy_root)?;
        if self.intent_ids.is_empty() {
            return Err("quantum safe private orderflow batch requires intents".to_string());
        }
        require_unique_strings("batch_intent_ids", &self.intent_ids)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_batch_auction",
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "builder_id": self.builder_id,
            "ordering_commitment_id": self.ordering_commitment_id,
            "epoch": self.epoch,
            "intent_ids": self.intent_ids,
            "sealed_bid_root": self.sealed_bid_root,
            "encrypted_bundle_root": self.encrypted_bundle_root,
            "clearing_policy_root": self.clearing_policy_root,
            "expected_surplus_units": self.expected_surplus_units,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEALED-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealWindow {
    pub window_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub builder_id: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub threshold_key_share_root: String,
    pub revealed_intent_root: String,
    pub missing_share_count: u64,
    pub status: RevealWindowStatus,
}

impl RevealWindow {
    pub fn new(
        batch: &SealedBatchAuction,
        opens_at_height: u64,
        closes_at_height: u64,
        missing_share_count: u64,
        status: RevealWindowStatus,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        batch.validate()?;
        if closes_at_height <= opens_at_height {
            return Err(
                "quantum safe private orderflow reveal window closes before it opens".to_string(),
            );
        }
        let threshold_key_share_root = payload_root(
            "THRESHOLD-KEY-SHARES",
            &json!({
                "batch_id": batch.batch_id,
                "builder_id": batch.builder_id,
                "opens_at_height": opens_at_height,
                "pq_encryption_suite": QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PQ_ENCRYPTION_SUITE,
            }),
        );
        let revealed_intent_root = merkle_root(
            "QUANTUM-SAFE-PRIVATE-ORDERFLOW-REVEALED-INTENT",
            &batch
                .intent_ids
                .iter()
                .map(|intent_id| {
                    json!({
                        "batch_id": batch.batch_id,
                        "intent_id": intent_id,
                        "reveal_window_status": status.as_str(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let window_id = deterministic_id(
            "REVEAL-WINDOW",
            &[
                &batch.batch_id,
                &opens_at_height.to_string(),
                &closes_at_height.to_string(),
            ],
        );
        Ok(Self {
            window_id,
            batch_id: batch.batch_id.clone(),
            lane_id: batch.lane_id.clone(),
            builder_id: batch.builder_id.clone(),
            opens_at_height,
            closes_at_height,
            threshold_key_share_root,
            revealed_intent_root,
            missing_share_count,
            status,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("window_id", &self.window_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("builder_id", &self.builder_id)?;
        require_non_empty("threshold_key_share_root", &self.threshold_key_share_root)?;
        require_non_empty("revealed_intent_root", &self.revealed_intent_root)?;
        if self.closes_at_height <= self.opens_at_height {
            return Err(
                "quantum safe private orderflow reveal window closes before it opens".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reveal_window",
            "window_id": self.window_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "builder_id": self.builder_id,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "threshold_key_share_root": self.threshold_key_share_root,
            "revealed_intent_root": self.revealed_intent_root,
            "missing_share_count": self.missing_share_count,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("REVEAL-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessProof {
    pub proof_id: String,
    pub batch_id: String,
    pub ordering_commitment_id: String,
    pub proof_system: String,
    pub input_root: String,
    pub transcript_root: String,
    pub claimed_order_root: String,
    pub excluded_intent_root: String,
    pub privacy_set_size: u64,
    pub verifier_count: u64,
    pub status: FairnessProofStatus,
    pub submitted_at_height: u64,
}

impl FairnessProof {
    pub fn new(
        batch: &SealedBatchAuction,
        ordering_commitment: &OrderingCommitment,
        excluded_intent_ids: &[String],
        privacy_set_size: u64,
        verifier_count: u64,
        status: FairnessProofStatus,
        submitted_at_height: u64,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        batch.validate()?;
        ordering_commitment.validate()?;
        if batch.ordering_commitment_id != ordering_commitment.commitment_id {
            return Err(
                "quantum safe private orderflow fairness proof batch commitment mismatch"
                    .to_string(),
            );
        }
        if privacy_set_size == 0 || verifier_count == 0 {
            return Err(
                "quantum safe private orderflow fairness proof counters must be positive"
                    .to_string(),
            );
        }
        let input_root = payload_root(
            "FAIRNESS-PROOF-INPUT",
            &json!({
                "batch_id": batch.batch_id,
                "ordering_commitment_id": ordering_commitment.commitment_id,
                "anti_mev_order_root": ordering_commitment.anti_mev_order_root,
                "privacy_set_size": privacy_set_size,
            }),
        );
        let transcript_root = payload_root(
            "FAIRNESS-PROOF-TRANSCRIPT",
            &json!({
                "batch_id": batch.batch_id,
                "input_root": input_root,
                "verifier_count": verifier_count,
                "status": status.as_str(),
            }),
        );
        let excluded_intent_root = merkle_root(
            "QUANTUM-SAFE-PRIVATE-ORDERFLOW-EXCLUDED-INTENT",
            &excluded_intent_ids
                .iter()
                .map(|intent_id| json!({ "intent_id": intent_id, "batch_id": batch.batch_id }))
                .collect::<Vec<_>>(),
        );
        let proof_id = deterministic_id(
            "FAIRNESS-PROOF",
            &[&batch.batch_id, &transcript_root, status.as_str()],
        );
        Ok(Self {
            proof_id,
            batch_id: batch.batch_id.clone(),
            ordering_commitment_id: ordering_commitment.commitment_id.clone(),
            proof_system: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_FAIRNESS_PROOF_SYSTEM.to_string(),
            input_root,
            transcript_root,
            claimed_order_root: ordering_commitment.anti_mev_order_root.clone(),
            excluded_intent_root,
            privacy_set_size,
            verifier_count,
            status,
            submitted_at_height,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("proof_id", &self.proof_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("ordering_commitment_id", &self.ordering_commitment_id)?;
        require_non_empty("input_root", &self.input_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        require_non_empty("claimed_order_root", &self.claimed_order_root)?;
        require_non_empty("excluded_intent_root", &self.excluded_intent_root)?;
        if self.privacy_set_size == 0 || self.verifier_count == 0 {
            return Err(
                "quantum safe private orderflow fairness proof counters must be positive"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fairness_proof",
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "ordering_commitment_id": self.ordering_commitment_id,
            "proof_system": self.proof_system,
            "input_root": self.input_root,
            "transcript_root": self.transcript_root,
            "claimed_order_root": self.claimed_order_root,
            "excluded_intent_root": self.excluded_intent_root,
            "privacy_set_size": self.privacy_set_size,
            "verifier_count": self.verifier_count,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAIRNESS-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReceipt {
    pub receipt_id: String,
    pub sponsor_id: String,
    pub intent_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub user_paid_fee_units: u64,
    pub receipt_root: String,
    pub issued_at_height: u64,
}

impl SponsorReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        intent_id: &str,
        batch_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        issued_at_height: u64,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        require_non_empty("sponsor_id", sponsor_id)?;
        require_non_empty("intent_id", intent_id)?;
        require_non_empty("batch_id", batch_id)?;
        require_non_empty("lane_id", lane_id)?;
        require_non_empty("fee_asset_id", fee_asset_id)?;
        if sponsored_fee_units > gross_fee_units {
            return Err(
                "quantum safe private orderflow sponsored fee exceeds gross fee".to_string(),
            );
        }
        let user_paid_fee_units = gross_fee_units.saturating_sub(sponsored_fee_units);
        let receipt_root = payload_root(
            "SPONSOR-RECEIPT",
            &json!({
                "sponsor_id": sponsor_id,
                "intent_id": intent_id,
                "batch_id": batch_id,
                "gross_fee_units": gross_fee_units,
                "sponsored_fee_units": sponsored_fee_units,
                "user_paid_fee_units": user_paid_fee_units,
            }),
        );
        let receipt_id = deterministic_id("SPONSOR-RECEIPT", &[sponsor_id, intent_id, batch_id]);
        Ok(Self {
            receipt_id,
            sponsor_id: sponsor_id.to_string(),
            intent_id: intent_id.to_string(),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            sponsored_fee_units,
            user_paid_fee_units,
            receipt_root,
            issued_at_height,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("sponsor_id", &self.sponsor_id)?;
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("receipt_root", &self.receipt_root)?;
        if self.sponsored_fee_units > self.gross_fee_units {
            return Err(
                "quantum safe private orderflow sponsored fee exceeds gross fee".to_string(),
            );
        }
        if self.user_paid_fee_units
            != self
                .gross_fee_units
                .saturating_sub(self.sponsored_fee_units)
        {
            return Err(
                "quantum safe private orderflow sponsor receipt fee arithmetic mismatch"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_receipt",
            "receipt_id": self.receipt_id,
            "sponsor_id": self.sponsor_id,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "user_paid_fee_units": self.user_paid_fee_units,
            "receipt_root": self.receipt_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SPONSOR-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderAccountabilityEvent {
    pub event_id: String,
    pub builder_id: String,
    pub batch_id: String,
    pub kind: AccountabilityEventKind,
    pub evidence_root: String,
    pub slash_units: u64,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub resolved: bool,
}

impl BuilderAccountabilityEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        builder_id: &str,
        batch_id: &str,
        kind: AccountabilityEventKind,
        evidence_label: &str,
        slash_units: u64,
        opened_at_height: u64,
        resolved_at_height: Option<u64>,
        resolved: bool,
    ) -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        require_non_empty("builder_id", builder_id)?;
        require_non_empty("batch_id", batch_id)?;
        require_non_empty("evidence_label", evidence_label)?;
        let evidence_root = payload_root(
            "ACCOUNTABILITY-EVIDENCE",
            &json!({
                "builder_id": builder_id,
                "batch_id": batch_id,
                "event_kind": kind.as_str(),
                "evidence_label": evidence_label,
                "severity_weight": kind.severity_weight(),
            }),
        );
        let event_id = deterministic_id(
            "ACCOUNTABILITY-EVENT",
            &[builder_id, batch_id, kind.as_str(), &evidence_root],
        );
        Ok(Self {
            event_id,
            builder_id: builder_id.to_string(),
            batch_id: batch_id.to_string(),
            kind,
            evidence_root,
            slash_units,
            opened_at_height,
            resolved_at_height,
            resolved,
        })
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        require_non_empty("event_id", &self.event_id)?;
        require_non_empty("builder_id", &self.builder_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err(
                    "quantum safe private orderflow accountability resolution precedes opening"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "builder_accountability_event",
            "event_id": self.event_id,
            "builder_id": self.builder_id,
            "batch_id": self.batch_id,
            "event_kind": self.kind.as_str(),
            "severity_weight": self.kind.severity_weight(),
            "evidence_root": self.evidence_root,
            "slash_units": self.slash_units,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "resolved": self.resolved,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ACCOUNTABILITY-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub builder_root: String,
    pub encrypted_intent_root: String,
    pub admission_root: String,
    pub ordering_commitment_root: String,
    pub sealed_batch_root: String,
    pub reveal_window_root: String,
    pub fairness_proof_root: String,
    pub sponsor_receipt_root: String,
    pub accountability_event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_private_orderflow_roots",
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "builder_root": self.builder_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "admission_root": self.admission_root,
            "ordering_commitment_root": self.ordering_commitment_root,
            "sealed_batch_root": self.sealed_batch_root,
            "reveal_window_root": self.reveal_window_root,
            "fairness_proof_root": self.fairness_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "accountability_event_root": self.accountability_event_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lane_count: u64,
    pub builder_count: u64,
    pub active_builder_count: u64,
    pub encrypted_intent_count: u64,
    pub admitted_intent_count: u64,
    pub sponsored_intent_count: u64,
    pub ordering_commitment_count: u64,
    pub sealed_batch_count: u64,
    pub open_reveal_window_count: u64,
    pub verified_fairness_proof_count: u64,
    pub sponsor_receipt_count: u64,
    pub accountability_event_count: u64,
    pub unresolved_accountability_event_count: u64,
    pub total_sponsored_fee_units: u64,
    pub total_expected_surplus_units: u64,
    pub total_builder_bond_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_private_orderflow_counters",
            "lane_count": self.lane_count,
            "builder_count": self.builder_count,
            "active_builder_count": self.active_builder_count,
            "encrypted_intent_count": self.encrypted_intent_count,
            "admitted_intent_count": self.admitted_intent_count,
            "sponsored_intent_count": self.sponsored_intent_count,
            "ordering_commitment_count": self.ordering_commitment_count,
            "sealed_batch_count": self.sealed_batch_count,
            "open_reveal_window_count": self.open_reveal_window_count,
            "verified_fairness_proof_count": self.verified_fairness_proof_count,
            "sponsor_receipt_count": self.sponsor_receipt_count,
            "accountability_event_count": self.accountability_event_count,
            "unresolved_accountability_event_count": self.unresolved_accountability_event_count,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_expected_surplus_units": self.total_expected_surplus_units,
            "total_builder_bond_units": self.total_builder_bond_units,
        })
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub lanes: BTreeMap<String, BatcherLane>,
    pub builders: BTreeMap<String, BuilderProfile>,
    pub encrypted_intents: BTreeMap<String, EncryptedIntent>,
    pub private_mempool_admissions: BTreeMap<String, PrivateMempoolAdmission>,
    pub ordering_commitments: BTreeMap<String, OrderingCommitment>,
    pub sealed_batch_auctions: BTreeMap<String, SealedBatchAuction>,
    pub reveal_windows: BTreeMap<String, RevealWindow>,
    pub fairness_proofs: BTreeMap<String, FairnessProof>,
    pub sponsor_receipts: BTreeMap<String, SponsorReceipt>,
    pub builder_accountability_events: BTreeMap<String, BuilderAccountabilityEvent>,
    pub observed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> QuantumSafePrivateOrderflowBatcherResult<Self> {
        let config = Config::devnet();
        let mut lanes = BTreeMap::new();
        let lane_specs = [
            (
                "sponsored-wallet-lane",
                LaneKind::Sponsored,
                256,
                8,
                48,
                true,
                true,
            ),
            (
                "shielded-swap-lane",
                LaneKind::Swap,
                384,
                24,
                96,
                false,
                true,
            ),
            ("monero-exit-lane", LaneKind::Exit, 192, 18, 80, true, true),
            (
                "private-contract-lane",
                LaneKind::Contract,
                224,
                28,
                64,
                false,
                true,
            ),
            ("risk-unwind-lane", LaneKind::Risk, 128, 20, 64, false, true),
            (
                "emergency-unwind-lane",
                LaneKind::Emergency,
                64,
                5,
                16,
                true,
                true,
            ),
        ];
        for (
            label,
            kind,
            max_batch_intents,
            max_fee_bps,
            min_privacy_set_size,
            sponsor_enabled,
            active,
        ) in lane_specs
        {
            let lane = BatcherLane::new(
                label,
                kind,
                max_batch_intents,
                max_fee_bps,
                min_privacy_set_size,
                sponsor_enabled,
                active,
            )?;
            lanes.insert(lane.lane_id.clone(), lane);
        }

        let sponsored_lane_id = find_lane_id(&lanes, LaneKind::Sponsored)?;
        let swap_lane_id = find_lane_id(&lanes, LaneKind::Swap)?;
        let exit_lane_id = find_lane_id(&lanes, LaneKind::Exit)?;
        let contract_lane_id = find_lane_id(&lanes, LaneKind::Contract)?;
        let risk_lane_id = find_lane_id(&lanes, LaneKind::Risk)?;
        let emergency_lane_id = find_lane_id(&lanes, LaneKind::Emergency)?;

        let mut builder_lanes_a = BTreeSet::new();
        builder_lanes_a.insert(sponsored_lane_id.clone());
        builder_lanes_a.insert(swap_lane_id.clone());
        builder_lanes_a.insert(contract_lane_id.clone());
        let mut builder_lanes_b = BTreeSet::new();
        builder_lanes_b.insert(exit_lane_id.clone());
        builder_lanes_b.insert(risk_lane_id.clone());
        builder_lanes_b.insert(emergency_lane_id.clone());
        let mut builder_lanes_c = BTreeSet::new();
        builder_lanes_c.insert(sponsored_lane_id.clone());
        builder_lanes_c.insert(swap_lane_id.clone());
        builder_lanes_c.insert(exit_lane_id.clone());
        builder_lanes_c.insert(contract_lane_id.clone());

        let mut builders = BTreeMap::new();
        for builder in [
            BuilderProfile::new(
                "builder-cobalt",
                3_400_000_000,
                9_240,
                builder_lanes_a,
                0,
                true,
            )?,
            BuilderProfile::new(
                "builder-umbra",
                4_100_000_000,
                8_870,
                builder_lanes_b,
                1,
                true,
            )?,
            BuilderProfile::new(
                "builder-saffron",
                2_950_000_000,
                9_010,
                builder_lanes_c,
                0,
                true,
            )?,
        ] {
            builders.insert(builder.builder_id.clone(), builder);
        }
        let builder_ids = builders.keys().cloned().collect::<Vec<_>>();
        let builder_a = require_index("builder", &builder_ids, 0)?;
        let builder_b = require_index("builder", &builder_ids, 1)?;
        let builder_c = require_index("builder", &builder_ids, 2)?;

        let intent_specs = [
            (
                "alice",
                IntentClass::LowFeePayment,
                sponsored_lane_id.as_str(),
                1_200,
                35_000,
                7_232,
                true,
            ),
            (
                "bravo",
                IntentClass::PrivateSwap,
                swap_lane_id.as_str(),
                4_500,
                120_000,
                7_233,
                false,
            ),
            (
                "carol",
                IntentClass::PrivateSwap,
                swap_lane_id.as_str(),
                4_800,
                130_000,
                7_233,
                false,
            ),
            (
                "dorian",
                IntentClass::MoneroExit,
                exit_lane_id.as_str(),
                3_700,
                98_000,
                7_234,
                true,
            ),
            (
                "elena",
                IntentClass::ContractCall,
                contract_lane_id.as_str(),
                5_200,
                140_000,
                7_234,
                false,
            ),
            (
                "farah",
                IntentClass::LiquidationShield,
                risk_lane_id.as_str(),
                6_000,
                210_000,
                7_235,
                false,
            ),
            (
                "gideon",
                IntentClass::EmergencyUnwind,
                emergency_lane_id.as_str(),
                900,
                260_000,
                7_235,
                true,
            ),
            (
                "hana",
                IntentClass::AccountOperation,
                sponsored_lane_id.as_str(),
                1_600,
                45_000,
                7_236,
                true,
            ),
        ];

        let mut encrypted_intents = BTreeMap::new();
        for (account, class, lane_id, max_fee, notional, received, sponsor) in intent_specs {
            let intent = EncryptedIntent::new(
                account,
                class,
                lane_id,
                max_fee,
                notional,
                received,
                received + 36,
                sponsor,
            )?;
            encrypted_intents.insert(intent.intent_id.clone(), intent);
        }

        let mut private_mempool_admissions = BTreeMap::new();
        for (position, intent) in encrypted_intents.values().enumerate() {
            let builder_id = match intent.intent_class.default_lane() {
                LaneKind::Exit | LaneKind::Risk | LaneKind::Emergency => builder_b,
                LaneKind::Sponsored if position % 2 == 0 => builder_c,
                LaneKind::Sponsored => builder_a,
                _ => builder_a,
            };
            let admission = PrivateMempoolAdmission::new(
                intent,
                AdmissionStatus::Accepted,
                builder_id,
                64 + position as u64 * 8,
                9_500_u64.saturating_sub(position as u64 * 110),
                intent.received_at_height + 1,
            )?;
            private_mempool_admissions.insert(admission.admission_id.clone(), admission);
        }

        let swap_intent_ids = ids_for_lane(&encrypted_intents, &swap_lane_id);
        let sponsored_intent_ids = ids_for_lane(&encrypted_intents, &sponsored_lane_id);
        let exit_intent_ids = ids_for_lane(&encrypted_intents, &exit_lane_id);
        let risk_intent_ids = ids_for_lane(&encrypted_intents, &risk_lane_id);
        let emergency_intent_ids = ids_for_lane(&encrypted_intents, &emergency_lane_id);
        let mut protected_exit_ids = exit_intent_ids.clone();
        protected_exit_ids.extend(risk_intent_ids);
        protected_exit_ids.extend(emergency_intent_ids);

        let empty_commitment_root =
            merkle_root("QUANTUM-SAFE-PRIVATE-ORDERFLOW-GENESIS-COMMITMENT", &[]);
        let commitment_a = OrderingCommitment::new(
            &swap_lane_id,
            builder_a,
            1_206,
            swap_intent_ids,
            &empty_commitment_root,
            7_237,
        )?;
        let commitment_b = OrderingCommitment::new(
            &exit_lane_id,
            builder_b,
            1_206,
            protected_exit_ids,
            &commitment_a.root(),
            7_238,
        )?;
        let commitment_c = OrderingCommitment::new(
            &sponsored_lane_id,
            builder_c,
            1_206,
            sponsored_intent_ids,
            &commitment_b.root(),
            7_238,
        )?;

        let mut ordering_commitments = BTreeMap::new();
        for commitment in [commitment_a, commitment_b, commitment_c] {
            ordering_commitments.insert(commitment.commitment_id.clone(), commitment);
        }

        let mut sealed_batch_auctions = BTreeMap::new();
        for commitment in ordering_commitments.values() {
            let expected_surplus_units = match commitment.lane_id.as_str() {
                lane if lane == swap_lane_id => 18_400,
                lane if lane == exit_lane_id => 11_200,
                _ => 3_900,
            };
            let batch = SealedBatchAuction::new(
                &commitment.lane_id,
                &commitment.builder_id,
                commitment,
                expected_surplus_units,
                commitment.committed_at_height + 1,
                BatchStatus::Sealed,
            )?;
            sealed_batch_auctions.insert(batch.batch_id.clone(), batch);
        }

        let mut reveal_windows = BTreeMap::new();
        for batch in sealed_batch_auctions.values() {
            let window = RevealWindow::new(
                batch,
                batch.sealed_at_height + 1,
                batch.sealed_at_height + config.reveal_window_blocks + 1,
                if batch.lane_id == exit_lane_id { 1 } else { 0 },
                if batch.lane_id == exit_lane_id {
                    RevealWindowStatus::Open
                } else {
                    RevealWindowStatus::Closed
                },
            )?;
            reveal_windows.insert(window.window_id.clone(), window);
        }

        let mut fairness_proofs = BTreeMap::new();
        for batch in sealed_batch_auctions.values() {
            let commitment = ordering_commitments
                .get(&batch.ordering_commitment_id)
                .ok_or_else(|| {
                    "quantum safe private orderflow missing commitment for fairness proof"
                        .to_string()
                })?;
            let proof = FairnessProof::new(
                batch,
                commitment,
                &Vec::new(),
                config.min_privacy_set_size + batch.intent_ids.len() as u64 * 8,
                5,
                FairnessProofStatus::Verified,
                batch.sealed_at_height + config.reveal_window_blocks + 2,
            )?;
            fairness_proofs.insert(proof.proof_id.clone(), proof);
        }

        let mut sponsor_receipts = BTreeMap::new();
        for intent in encrypted_intents
            .values()
            .filter(|intent| intent.sponsor_requested)
        {
            let batch = sealed_batch_auctions
                .values()
                .find(|batch| batch.intent_ids.contains(&intent.intent_id))
                .ok_or_else(|| {
                    "quantum safe private orderflow sponsored intent missing batch".to_string()
                })?;
            let sponsored_fee_units = intent.max_fee_units.saturating_mul(75) / 100;
            let receipt = SponsorReceipt::new(
                "devnet-low-fee-sponsor-vault",
                &intent.intent_id,
                &batch.batch_id,
                &intent.lane_id,
                "pnebula",
                intent.max_fee_units,
                sponsored_fee_units,
                batch.sealed_at_height + 2,
            )?;
            sponsor_receipts.insert(receipt.receipt_id.clone(), receipt);
        }

        let mut builder_accountability_events = BTreeMap::new();
        for event in [
            BuilderAccountabilityEvent::new(
                builder_b,
                sealed_batch_auctions
                    .values()
                    .find(|batch| batch.builder_id == builder_b)
                    .map(|batch| batch.batch_id.as_str())
                    .ok_or_else(|| {
                        "quantum safe private orderflow missing builder batch".to_string()
                    })?,
                AccountabilityEventKind::LateReveal,
                "missing-one-threshold-share-in-open-window",
                45_000_000,
                7_243,
                None,
                false,
            )?,
            BuilderAccountabilityEvent::new(
                builder_c,
                sealed_batch_auctions
                    .values()
                    .find(|batch| batch.builder_id == builder_c)
                    .map(|batch| batch.batch_id.as_str())
                    .ok_or_else(|| {
                        "quantum safe private orderflow missing sponsored batch".to_string()
                    })?,
                AccountabilityEventKind::SponsorOvercharge,
                "devnet-rebate-auditor-cleared-with-warning",
                0,
                7_242,
                Some(7_244),
                true,
            )?,
        ] {
            builder_accountability_events.insert(event.event_id.clone(), event);
        }

        let observed_nullifiers = encrypted_intents
            .values()
            .map(|intent| intent.nullifier_commitment.clone())
            .collect::<BTreeSet<_>>();

        let state = Self {
            height: QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_DEVNET_HEIGHT,
            config,
            lanes,
            builders,
            encrypted_intents,
            private_mempool_admissions,
            ordering_commitments,
            sealed_batch_auctions,
            reveal_windows,
            fairness_proofs,
            sponsor_receipts,
            builder_accountability_events,
            observed_nullifiers,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        self.config.validate()?;
        if self.lanes.len() > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_LANES
            || self.builders.len() > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BUILDERS
            || self.encrypted_intents.len() > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_INTENTS
            || self.sealed_batch_auctions.len() > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_BATCHES
            || self.ordering_commitments.len()
                > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_COMMITMENTS
            || self.reveal_windows.len() > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_REVEAL_WINDOWS
            || self.fairness_proofs.len()
                > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_FAIRNESS_PROOFS
            || self.sponsor_receipts.len() > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_RECEIPTS
            || self.builder_accountability_events.len()
                > QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_MAX_ACCOUNTABILITY_EVENTS
        {
            return Err("quantum safe private orderflow state exceeds devnet bounds".to_string());
        }

        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for builder in self.builders.values() {
            builder.validate()?;
            for lane_id in &builder.allowed_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err(
                        "quantum safe private orderflow builder references unknown lane"
                            .to_string(),
                    );
                }
            }
        }
        for intent in self.encrypted_intents.values() {
            intent.validate()?;
            if !self.lanes.contains_key(&intent.lane_id) {
                return Err(
                    "quantum safe private orderflow intent references unknown lane".to_string(),
                );
            }
            if intent.expires_at_height <= self.height && intent.received_at_height > self.height {
                return Err(
                    "quantum safe private orderflow intent has inconsistent height".to_string(),
                );
            }
        }
        for admission in self.private_mempool_admissions.values() {
            admission.validate()?;
            if !self.encrypted_intents.contains_key(&admission.intent_id) {
                return Err(
                    "quantum safe private orderflow admission references unknown intent"
                        .to_string(),
                );
            }
            if !self
                .builders
                .contains_key(&admission.received_by_builder_id)
            {
                return Err(
                    "quantum safe private orderflow admission references unknown builder"
                        .to_string(),
                );
            }
        }
        for commitment in self.ordering_commitments.values() {
            commitment.validate()?;
            if !self.lanes.contains_key(&commitment.lane_id) {
                return Err(
                    "quantum safe private orderflow commitment references unknown lane".to_string(),
                );
            }
            if !self.builders.contains_key(&commitment.builder_id) {
                return Err(
                    "quantum safe private orderflow commitment references unknown builder"
                        .to_string(),
                );
            }
            for intent_id in &commitment.intent_ids {
                if !self.encrypted_intents.contains_key(intent_id) {
                    return Err(
                        "quantum safe private orderflow commitment references unknown intent"
                            .to_string(),
                    );
                }
            }
        }
        for batch in self.sealed_batch_auctions.values() {
            batch.validate()?;
            if !self
                .ordering_commitments
                .contains_key(&batch.ordering_commitment_id)
            {
                return Err(
                    "quantum safe private orderflow batch references unknown commitment"
                        .to_string(),
                );
            }
            if !self.builders.contains_key(&batch.builder_id) {
                return Err(
                    "quantum safe private orderflow batch references unknown builder".to_string(),
                );
            }
        }
        for window in self.reveal_windows.values() {
            window.validate()?;
            if !self.sealed_batch_auctions.contains_key(&window.batch_id) {
                return Err(
                    "quantum safe private orderflow reveal window references unknown batch"
                        .to_string(),
                );
            }
        }
        for proof in self.fairness_proofs.values() {
            proof.validate()?;
            if !self.sealed_batch_auctions.contains_key(&proof.batch_id) {
                return Err(
                    "quantum safe private orderflow proof references unknown batch".to_string(),
                );
            }
        }
        for receipt in self.sponsor_receipts.values() {
            receipt.validate()?;
            if !self.encrypted_intents.contains_key(&receipt.intent_id) {
                return Err(
                    "quantum safe private orderflow sponsor receipt references unknown intent"
                        .to_string(),
                );
            }
            if !self.sealed_batch_auctions.contains_key(&receipt.batch_id) {
                return Err(
                    "quantum safe private orderflow sponsor receipt references unknown batch"
                        .to_string(),
                );
            }
        }
        for event in self.builder_accountability_events.values() {
            event.validate()?;
            if !self.builders.contains_key(&event.builder_id) {
                return Err("quantum safe private orderflow accountability event references unknown builder".to_string());
            }
            if !self.sealed_batch_auctions.contains_key(&event.batch_id) {
                return Err(
                    "quantum safe private orderflow accountability event references unknown batch"
                        .to_string(),
                );
            }
        }
        for nullifier in &self.observed_nullifiers {
            if nullifier.is_empty() {
                return Err("quantum safe private orderflow nullifier cannot be empty".to_string());
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, delta: u64) -> QuantumSafePrivateOrderflowBatcherResult<()> {
        self.height = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "quantum safe private orderflow height overflow".to_string())?;
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            lane_root: collection_root(
                "LANES",
                self.lanes
                    .values()
                    .map(BatcherLane::public_record)
                    .collect(),
            ),
            builder_root: collection_root(
                "BUILDERS",
                self.builders
                    .values()
                    .map(BuilderProfile::public_record)
                    .collect(),
            ),
            encrypted_intent_root: collection_root(
                "ENCRYPTED-INTENTS",
                self.encrypted_intents
                    .values()
                    .map(EncryptedIntent::public_record)
                    .collect(),
            ),
            admission_root: collection_root(
                "PRIVATE-MEMPOOL-ADMISSIONS",
                self.private_mempool_admissions
                    .values()
                    .map(PrivateMempoolAdmission::public_record)
                    .collect(),
            ),
            ordering_commitment_root: collection_root(
                "ORDERING-COMMITMENTS",
                self.ordering_commitments
                    .values()
                    .map(OrderingCommitment::public_record)
                    .collect(),
            ),
            sealed_batch_root: collection_root(
                "SEALED-BATCH-AUCTIONS",
                self.sealed_batch_auctions
                    .values()
                    .map(SealedBatchAuction::public_record)
                    .collect(),
            ),
            reveal_window_root: collection_root(
                "REVEAL-WINDOWS",
                self.reveal_windows
                    .values()
                    .map(RevealWindow::public_record)
                    .collect(),
            ),
            fairness_proof_root: collection_root(
                "FAIRNESS-PROOFS",
                self.fairness_proofs
                    .values()
                    .map(FairnessProof::public_record)
                    .collect(),
            ),
            sponsor_receipt_root: collection_root(
                "SPONSOR-RECEIPTS",
                self.sponsor_receipts
                    .values()
                    .map(SponsorReceipt::public_record)
                    .collect(),
            ),
            accountability_event_root: collection_root(
                "ACCOUNTABILITY-EVENTS",
                self.builder_accountability_events
                    .values()
                    .map(BuilderAccountabilityEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lane_count: self.lanes.len() as u64,
            builder_count: self.builders.len() as u64,
            active_builder_count: self
                .builders
                .values()
                .filter(|builder| builder.active)
                .count() as u64,
            encrypted_intent_count: self.encrypted_intents.len() as u64,
            admitted_intent_count: self
                .private_mempool_admissions
                .values()
                .filter(|admission| admission.status == AdmissionStatus::Accepted)
                .count() as u64,
            sponsored_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.sponsor_requested)
                .count() as u64,
            ordering_commitment_count: self.ordering_commitments.len() as u64,
            sealed_batch_count: self.sealed_batch_auctions.len() as u64,
            open_reveal_window_count: self
                .reveal_windows
                .values()
                .filter(|window| window.status == RevealWindowStatus::Open)
                .count() as u64,
            verified_fairness_proof_count: self
                .fairness_proofs
                .values()
                .filter(|proof| proof.status == FairnessProofStatus::Verified)
                .count() as u64,
            sponsor_receipt_count: self.sponsor_receipts.len() as u64,
            accountability_event_count: self.builder_accountability_events.len() as u64,
            unresolved_accountability_event_count: self
                .builder_accountability_events
                .values()
                .filter(|event| !event.resolved)
                .count() as u64,
            total_sponsored_fee_units: self
                .sponsor_receipts
                .values()
                .map(|receipt| receipt.sponsored_fee_units)
                .sum(),
            total_expected_surplus_units: self
                .sealed_batch_auctions
                .values()
                .map(|batch| batch.expected_surplus_units)
                .sum(),
            total_builder_bond_units: self
                .builders
                .values()
                .map(|builder| builder.bond_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        with_field(
            record,
            "quantum_safe_private_orderflow_state_root",
            self.state_root(),
        )
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "quantum_safe_private_orderflow_batcher_state",
            "height": self.height,
            "protocol_version": QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": counters.public_record(),
            "counters_root": counters.root(),
            "lanes": self.lanes.values().map(BatcherLane::public_record).collect::<Vec<_>>(),
            "builders": self.builders.values().map(BuilderProfile::public_record).collect::<Vec<_>>(),
            "encrypted_intents": self.encrypted_intents.values().map(EncryptedIntent::public_record).collect::<Vec<_>>(),
            "private_mempool_admissions": self.private_mempool_admissions.values().map(PrivateMempoolAdmission::public_record).collect::<Vec<_>>(),
            "ordering_commitments": self.ordering_commitments.values().map(OrderingCommitment::public_record).collect::<Vec<_>>(),
            "sealed_batch_auctions": self.sealed_batch_auctions.values().map(SealedBatchAuction::public_record).collect::<Vec<_>>(),
            "reveal_windows": self.reveal_windows.values().map(RevealWindow::public_record).collect::<Vec<_>>(),
            "fairness_proofs": self.fairness_proofs.values().map(FairnessProof::public_record).collect::<Vec<_>>(),
            "sponsor_receipts": self.sponsor_receipts.values().map(SponsorReceipt::public_record).collect::<Vec<_>>(),
            "builder_accountability_events": self.builder_accountability_events.values().map(BuilderAccountabilityEvent::public_record).collect::<Vec<_>>(),
            "observed_nullifier_root": merkle_root(
                "QUANTUM-SAFE-PRIVATE-ORDERFLOW-OBSERVED-NULLIFIER",
                &self.observed_nullifiers.iter().map(|value| json!(value)).collect::<Vec<_>>(),
            ),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "QUANTUM-SAFE-PRIVATE-ORDERFLOW-BATCHER-STATE",
        &[
            HashPart::Str(QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> QuantumSafePrivateOrderflowBatcherResult<State> {
    State::devnet()
}

fn require_non_empty(field: &str, value: &str) -> QuantumSafePrivateOrderflowBatcherResult<()> {
    if value.is_empty() {
        return Err(format!(
            "quantum safe private orderflow {field} cannot be empty"
        ));
    }
    Ok(())
}

fn require_unique_strings(
    field: &str,
    values: &[String],
) -> QuantumSafePrivateOrderflowBatcherResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!(
                "quantum safe private orderflow {field} contains empty value"
            ));
        }
        if !seen.insert(value) {
            return Err(format!(
                "quantum safe private orderflow {field} contains duplicate value"
            ));
        }
    }
    Ok(())
}

fn require_index<'a>(
    label: &str,
    values: &'a [String],
    index: usize,
) -> QuantumSafePrivateOrderflowBatcherResult<&'a str> {
    values.get(index).map(String::as_str).ok_or_else(|| {
        format!("quantum safe private orderflow missing deterministic {label} fixture")
    })
}

fn find_lane_id(
    lanes: &BTreeMap<String, BatcherLane>,
    kind: LaneKind,
) -> QuantumSafePrivateOrderflowBatcherResult<String> {
    lanes
        .values()
        .find(|lane| lane.kind == kind)
        .map(|lane| lane.lane_id.clone())
        .ok_or_else(|| "quantum safe private orderflow missing deterministic lane".to_string())
}

fn ids_for_lane(intents: &BTreeMap<String, EncryptedIntent>, lane_id: &str) -> Vec<String> {
    intents
        .values()
        .filter(|intent| intent.lane_id == lane_id)
        .map(|intent| intent.intent_id.clone())
        .collect::<Vec<_>>()
}

fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, part)| json!({ "index": index, "value": part }))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("QUANTUM-SAFE-PRIVATE-ORDERFLOW-{domain}-ID"),
        &[
            HashPart::Str(QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&merkle_root(
                "QUANTUM-SAFE-PRIVATE-ORDERFLOW-ID-PART",
                &leaves,
            )),
        ],
        24,
    )
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("QUANTUM-SAFE-PRIVATE-ORDERFLOW-{domain}"),
        &[
            HashPart::Str(QUANTUM_SAFE_PRIVATE_ORDERFLOW_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("QUANTUM-SAFE-PRIVATE-ORDERFLOW-{domain}"),
        &records,
    )
}

fn with_field(mut record: Value, field: &str, value: String) -> Value {
    if let Value::Object(fields) = &mut record {
        fields.insert(field.to_string(), json!(value));
    }
    record
}
