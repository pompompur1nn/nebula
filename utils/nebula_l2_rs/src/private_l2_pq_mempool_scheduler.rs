use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqMempoolSchedulerResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-mempool-scheduler-v1";
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_SEALING_SUITE: &str =
    "ML-KEM-1024+threshold-sealed-intent-v1";
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PRIVACY_PROOF_SYSTEM: &str = "zk-private-l2-admission-v1";
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEVNET_HEIGHT: u64 = 100_000;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 4_000;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MAX_BATCH_ENVELOPES: usize = 64;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MAX_FEE_MICRO_UNITS: u64 = 2_500;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_MAX_ENVELOPES: usize = 32_768;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_MAX_BATCHES: usize = 2_048;
pub const PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_MAX_RECEIPTS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentClass {
    PrivateTransfer,
    ConfidentialToken,
    PrivateContract,
    PrivateDefiSwap,
    LiquidityProvision,
    ProofAggregation,
    MoneroExit,
    Emergency,
}

impl IntentClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialToken => "confidential_token",
            Self::PrivateContract => "private_contract",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::LiquidityProvision => "liquidity_provision",
            Self::ProofAggregation => "proof_aggregation",
            Self::MoneroExit => "monero_exit",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_weight_units(self) -> u64 {
        match self {
            Self::PrivateTransfer => 8,
            Self::ConfidentialToken => 18,
            Self::PrivateContract => 32,
            Self::PrivateDefiSwap => 36,
            Self::LiquidityProvision => 34,
            Self::ProofAggregation => 42,
            Self::MoneroExit => 40,
            Self::Emergency => 24,
        }
    }

    pub fn lane_floor_bps(self) -> u64 {
        match self {
            Self::PrivateTransfer => 1_700,
            Self::ConfidentialToken => 1_100,
            Self::PrivateContract => 1_700,
            Self::PrivateDefiSwap => 1_700,
            Self::LiquidityProvision => 900,
            Self::ProofAggregation => 700,
            Self::MoneroExit => 1_500,
            Self::Emergency => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    Flash,
    Fast,
    Standard,
    Background,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flash => "flash",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Background => "background",
        }
    }

    pub fn target_blocks(self) -> u64 {
        match self {
            Self::Flash => 1,
            Self::Fast => 2,
            Self::Standard => 5,
            Self::Background => 12,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Flash => 128,
            Self::Fast => 96,
            Self::Standard => 64,
            Self::Background => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Pending,
    Deferred,
    Batched,
    Executed,
    Expired,
    Rejected,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Deferred => "deferred",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Scheduled,
    Executed,
    Failed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Executed => "executed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub sealing_suite: String,
    pub privacy_proof_system: String,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_batch_weight_units: u64,
    pub max_batch_envelopes: usize,
    pub default_max_fee_micro_units: u64,
    pub default_ttl_blocks: u64,
    pub fair_age_boost_per_block: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PQ_AUTH_SUITE.to_string(),
            sealing_suite: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_SEALING_SUITE.to_string(),
            privacy_proof_system: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PRIVACY_PROOF_SYSTEM.to_string(),
            min_privacy_set: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_batch_weight_units: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MAX_BATCH_WEIGHT,
            max_batch_envelopes: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MAX_BATCH_ENVELOPES,
            default_max_fee_micro_units:
                PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_MAX_FEE_MICRO_UNITS,
            default_ttl_blocks: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEFAULT_TTL_BLOCKS,
            fair_age_boost_per_block: 3,
        }
    }
}

impl Config {
    pub fn validate(&self) -> PrivateL2PqMempoolSchedulerResult<()> {
        if self.protocol_version != PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PROTOCOL_VERSION {
            return Err("private l2 pq mempool scheduler protocol mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("private l2 pq mempool scheduler chain id mismatch".to_string());
        }
        if self.min_privacy_set == 0 || self.min_pq_security_bits == 0 {
            return Err("privacy and pq security floors must be positive".to_string());
        }
        if self.max_batch_weight_units == 0 || self.max_batch_envelopes == 0 {
            return Err("batch limits must be positive".to_string());
        }
        if self.default_max_fee_micro_units == 0 || self.default_ttl_blocks == 0 {
            return Err("fee cap and ttl defaults must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_mempool_scheduler_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "sealing_suite": self.sealing_suite,
            "privacy_proof_system": self.privacy_proof_system,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_batch_weight_units": self.max_batch_weight_units,
            "max_batch_envelopes": self.max_batch_envelopes,
            "default_max_fee_micro_units": self.default_max_fee_micro_units,
            "default_ttl_blocks": self.default_ttl_blocks,
            "fair_age_boost_per_block": self.fair_age_boost_per_block,
        })
    }

    pub fn root(&self) -> String {
        private_l2_pq_mempool_scheduler_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub submitted_envelopes: u64,
    pub accepted_envelopes: u64,
    pub rejected_envelopes: u64,
    pub deferred_envelopes: u64,
    pub expired_envelopes: u64,
    pub scheduled_batches: u64,
    pub executed_batches: u64,
    pub failed_batches: u64,
    pub executed_envelopes: u64,
    pub fee_cap_rejections: u64,
    pub privacy_floor_rejections: u64,
    pub pq_floor_rejections: u64,
    pub nullifier_rejections: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_mempool_scheduler_counters",
            "submitted_envelopes": self.submitted_envelopes,
            "accepted_envelopes": self.accepted_envelopes,
            "rejected_envelopes": self.rejected_envelopes,
            "deferred_envelopes": self.deferred_envelopes,
            "expired_envelopes": self.expired_envelopes,
            "scheduled_batches": self.scheduled_batches,
            "executed_batches": self.executed_batches,
            "failed_batches": self.failed_batches,
            "executed_envelopes": self.executed_envelopes,
            "fee_cap_rejections": self.fee_cap_rejections,
            "privacy_floor_rejections": self.privacy_floor_rejections,
            "pq_floor_rejections": self.pq_floor_rejections,
            "nullifier_rejections": self.nullifier_rejections,
        })
    }

    pub fn root(&self) -> String {
        private_l2_pq_mempool_scheduler_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIntentEnvelope {
    pub envelope_id: String,
    pub intake_height: u64,
    pub expires_at_height: u64,
    pub class: IntentClass,
    pub latency_class: LatencyClass,
    pub sealed_payload_root: String,
    pub pq_authorization_root: String,
    pub nullifier_root: String,
    pub privacy_proof_root: String,
    pub fee_asset_root: String,
    pub max_fee_micro_units: u64,
    pub min_privacy_set: u64,
    pub pq_security_bits: u64,
    pub weight_units: u64,
    pub ordering_salt_root: String,
    pub status: EnvelopeStatus,
}

impl SealedIntentEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intake_height: u64,
        class: IntentClass,
        latency_class: LatencyClass,
        sealed_payload_root: &str,
        pq_authorization_root: &str,
        nullifier_root: &str,
        privacy_proof_root: &str,
        fee_asset_root: &str,
        max_fee_micro_units: u64,
        min_privacy_set: u64,
        pq_security_bits: u64,
        weight_units: u64,
        ordering_salt_root: &str,
        ttl_blocks: u64,
    ) -> PrivateL2PqMempoolSchedulerResult<Self> {
        if sealed_payload_root.is_empty()
            || pq_authorization_root.is_empty()
            || nullifier_root.is_empty()
            || privacy_proof_root.is_empty()
            || fee_asset_root.is_empty()
            || ordering_salt_root.is_empty()
        {
            return Err("sealed envelope roots cannot be empty".to_string());
        }
        if max_fee_micro_units == 0 || min_privacy_set == 0 || pq_security_bits == 0 {
            return Err("sealed envelope fee, privacy, and pq floors must be positive".to_string());
        }
        if weight_units == 0 || ttl_blocks == 0 {
            return Err("sealed envelope weight and ttl must be positive".to_string());
        }
        let expires_at_height = intake_height.saturating_add(ttl_blocks);
        let envelope_id = private_l2_pq_mempool_scheduler_id(
            "ENVELOPE",
            &[
                sealed_payload_root,
                pq_authorization_root,
                nullifier_root,
                ordering_salt_root,
                &intake_height.to_string(),
            ],
        );
        Ok(Self {
            envelope_id,
            intake_height,
            expires_at_height,
            class,
            latency_class,
            sealed_payload_root: sealed_payload_root.to_string(),
            pq_authorization_root: pq_authorization_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            privacy_proof_root: privacy_proof_root.to_string(),
            fee_asset_root: fee_asset_root.to_string(),
            max_fee_micro_units,
            min_privacy_set,
            pq_security_bits,
            weight_units,
            ordering_salt_root: ordering_salt_root.to_string(),
            status: EnvelopeStatus::Pending,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_intent_envelope",
            "envelope_id": self.envelope_id,
            "intake_height": self.intake_height,
            "expires_at_height": self.expires_at_height,
            "class": self.class.as_str(),
            "latency_class": self.latency_class.as_str(),
            "sealed_payload_root": self.sealed_payload_root,
            "pq_authorization_root": self.pq_authorization_root,
            "nullifier_root": self.nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "fee_asset_root": self.fee_asset_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "min_privacy_set": self.min_privacy_set,
            "pq_security_bits": self.pq_security_bits,
            "weight_units": self.weight_units,
            "ordering_salt_root": self.ordering_salt_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_l2_pq_mempool_scheduler_payload_root("ENVELOPE", &self.public_record())
    }

    pub fn fair_score(&self, height: u64, age_boost: u64) -> u128 {
        let age = height.saturating_sub(self.intake_height);
        let deadline_pressure = self.expires_at_height.saturating_sub(height).max(1);
        let latency = self.latency_class.priority_weight();
        let class_floor = self.class.lane_floor_bps();
        let age_component = age.saturating_mul(age_boost);
        (latency as u128)
            .saturating_mul(1_000_000)
            .saturating_add((class_floor as u128).saturating_mul(100))
            .saturating_add((age_component as u128).saturating_mul(10_000))
            .saturating_add((1_000_000_u128).saturating_div(deadline_pressure as u128))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledBatch {
    pub batch_id: String,
    pub scheduled_height: u64,
    pub target_execute_height: u64,
    pub status: BatchStatus,
    pub envelope_ids: Vec<String>,
    pub envelope_root: String,
    pub pq_authorization_root: String,
    pub nullifier_root: String,
    pub fee_cap_root: String,
    pub privacy_floor_root: String,
    pub fair_ordering_root: String,
    pub total_weight_units: u64,
    pub max_fee_micro_units: u64,
    pub min_privacy_set: u64,
}

impl ScheduledBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_scheduled_batch",
            "batch_id": self.batch_id,
            "scheduled_height": self.scheduled_height,
            "target_execute_height": self.target_execute_height,
            "status": self.status.as_str(),
            "envelope_ids": self.envelope_ids,
            "envelope_root": self.envelope_root,
            "pq_authorization_root": self.pq_authorization_root,
            "nullifier_root": self.nullifier_root,
            "fee_cap_root": self.fee_cap_root,
            "privacy_floor_root": self.privacy_floor_root,
            "fair_ordering_root": self.fair_ordering_root,
            "total_weight_units": self.total_weight_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "min_privacy_set": self.min_privacy_set,
        })
    }

    pub fn root(&self) -> String {
        private_l2_pq_mempool_scheduler_payload_root("BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledBatchReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub scheduled_height: u64,
    pub executed_height: Option<u64>,
    pub status: BatchStatus,
    pub batch_root: String,
    pub execution_root: Option<String>,
    pub included_envelope_count: u64,
    pub executed_envelope_count: u64,
}

impl ScheduledBatchReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_scheduled_batch_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "scheduled_height": self.scheduled_height,
            "executed_height": self.executed_height,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "execution_root": self.execution_root,
            "included_envelope_count": self.included_envelope_count,
            "executed_envelope_count": self.executed_envelope_count,
        })
    }

    pub fn root(&self) -> String {
        private_l2_pq_mempool_scheduler_payload_root("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub envelope_root: String,
    pub pending_envelope_root: String,
    pub pq_authorization_root: String,
    pub nullifier_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_mempool_scheduler_roots",
            "config_root": self.config_root,
            "envelope_root": self.envelope_root,
            "pending_envelope_root": self.pending_envelope_root,
            "pq_authorization_root": self.pq_authorization_root,
            "nullifier_root": self.nullifier_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub envelopes: BTreeMap<String, SealedIntentEnvelope>,
    pub batches: BTreeMap<String, ScheduledBatch>,
    pub receipts: BTreeMap<String, ScheduledBatchReceipt>,
    pub seen_nullifier_roots: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            height: PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_DEVNET_HEIGHT,
            epoch: 0,
            config: Config::default(),
            counters: Counters::default(),
            envelopes: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            seen_nullifier_roots: BTreeSet::new(),
        }
    }
}

impl State {
    pub fn devnet() -> PrivateL2PqMempoolSchedulerResult<Self> {
        let mut state = Self::default();
        state.config.validate()?;
        let seeds = [
            (
                "wallet-transfer",
                IntentClass::PrivateTransfer,
                LatencyClass::Fast,
                1_200,
                320,
            ),
            (
                "contract-swap",
                IntentClass::PrivateDefiSwap,
                LatencyClass::Flash,
                1_850,
                384,
            ),
            (
                "confidential-token-mint",
                IntentClass::ConfidentialToken,
                LatencyClass::Standard,
                900,
                512,
            ),
            (
                "monero-fast-exit",
                IntentClass::MoneroExit,
                LatencyClass::Fast,
                2_100,
                512,
            ),
            (
                "proof-aggregation",
                IntentClass::ProofAggregation,
                LatencyClass::Background,
                700,
                256,
            ),
        ];
        for (label, class, latency_class, fee_cap, privacy_set) in seeds {
            let sealed = private_l2_pq_mempool_scheduler_seed_root("SEALED-PAYLOAD", label);
            let auth = private_l2_pq_mempool_scheduler_seed_root("PQ-AUTH", label);
            let nullifier = private_l2_pq_mempool_scheduler_seed_root("NULLIFIER", label);
            let proof = private_l2_pq_mempool_scheduler_seed_root("PRIVACY-PROOF", label);
            let fee_asset = private_l2_pq_mempool_scheduler_seed_root("FEE-ASSET", "xmr");
            let salt = private_l2_pq_mempool_scheduler_seed_root("ORDERING-SALT", label);
            state.submit_envelope(
                class,
                latency_class,
                &sealed,
                &auth,
                &nullifier,
                &proof,
                &fee_asset,
                fee_cap,
                privacy_set,
                state.config.min_pq_security_bits,
                class.default_weight_units(),
                &salt,
                Some(state.config.default_ttl_blocks),
            )?;
        }
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_envelope(
        &mut self,
        class: IntentClass,
        latency_class: LatencyClass,
        sealed_payload_root: &str,
        pq_authorization_root: &str,
        nullifier_root: &str,
        privacy_proof_root: &str,
        fee_asset_root: &str,
        max_fee_micro_units: u64,
        min_privacy_set: u64,
        pq_security_bits: u64,
        weight_units: u64,
        ordering_salt_root: &str,
        ttl_blocks: Option<u64>,
    ) -> PrivateL2PqMempoolSchedulerResult<SealedIntentEnvelope> {
        self.config.validate()?;
        self.counters.submitted_envelopes = self.counters.submitted_envelopes.saturating_add(1);
        if self.envelopes.len() >= PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_MAX_ENVELOPES {
            self.counters.rejected_envelopes = self.counters.rejected_envelopes.saturating_add(1);
            return Err("private l2 pq mempool scheduler envelope limit reached".to_string());
        }
        if max_fee_micro_units > self.config.default_max_fee_micro_units {
            self.counters.fee_cap_rejections = self.counters.fee_cap_rejections.saturating_add(1);
            self.counters.rejected_envelopes = self.counters.rejected_envelopes.saturating_add(1);
            return Err("sealed envelope fee cap exceeds scheduler policy".to_string());
        }
        if min_privacy_set < self.config.min_privacy_set {
            self.counters.privacy_floor_rejections =
                self.counters.privacy_floor_rejections.saturating_add(1);
            self.counters.rejected_envelopes = self.counters.rejected_envelopes.saturating_add(1);
            return Err("sealed envelope privacy set below scheduler floor".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            self.counters.pq_floor_rejections = self.counters.pq_floor_rejections.saturating_add(1);
            self.counters.rejected_envelopes = self.counters.rejected_envelopes.saturating_add(1);
            return Err("sealed envelope pq security below scheduler floor".to_string());
        }
        if self.seen_nullifier_roots.contains(nullifier_root) {
            self.counters.nullifier_rejections =
                self.counters.nullifier_rejections.saturating_add(1);
            self.counters.rejected_envelopes = self.counters.rejected_envelopes.saturating_add(1);
            return Err("sealed envelope nullifier root already admitted".to_string());
        }
        let envelope = SealedIntentEnvelope::new(
            self.height,
            class,
            latency_class,
            sealed_payload_root,
            pq_authorization_root,
            nullifier_root,
            privacy_proof_root,
            fee_asset_root,
            max_fee_micro_units,
            min_privacy_set,
            pq_security_bits,
            weight_units,
            ordering_salt_root,
            ttl_blocks.unwrap_or(self.config.default_ttl_blocks),
        )?;
        self.seen_nullifier_roots
            .insert(envelope.nullifier_root.clone());
        self.counters.accepted_envelopes = self.counters.accepted_envelopes.saturating_add(1);
        self.envelopes
            .insert(envelope.envelope_id.clone(), envelope.clone());
        Ok(envelope)
    }

    pub fn select_batch(
        &mut self,
        height: u64,
        max_weight_units: Option<u64>,
        max_envelopes: Option<usize>,
    ) -> PrivateL2PqMempoolSchedulerResult<ScheduledBatchReceipt> {
        self.height = self.height.max(height);
        self.expire_pending();
        if self.batches.len() >= PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_MAX_BATCHES {
            return Err("private l2 pq mempool scheduler batch limit reached".to_string());
        }
        let max_weight = max_weight_units.unwrap_or(self.config.max_batch_weight_units);
        let max_count = max_envelopes
            .unwrap_or(self.config.max_batch_envelopes)
            .min(self.config.max_batch_envelopes);
        if max_weight == 0 || max_count == 0 {
            return Err("batch selection limits must be positive".to_string());
        }
        let mut candidates = self
            .envelopes
            .values()
            .filter(|envelope| envelope.status == EnvelopeStatus::Pending)
            .map(|envelope| {
                (
                    envelope.fair_score(self.height, self.config.fair_age_boost_per_block),
                    envelope.intake_height,
                    envelope.envelope_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });

        let mut selected_ids = Vec::new();
        let mut total_weight = 0_u64;
        let mut class_counts = BTreeMap::<IntentClass, usize>::new();
        for (_, _, envelope_id) in candidates {
            let envelope = self
                .envelopes
                .get(&envelope_id)
                .ok_or_else(|| "batch candidate disappeared".to_string())?;
            if selected_ids.len() >= max_count {
                break;
            }
            if total_weight.saturating_add(envelope.weight_units) > max_weight {
                continue;
            }
            let class_count = class_counts.entry(envelope.class).or_insert(0);
            if *class_count >= max_count.saturating_div(2).max(1)
                && selected_ids.len() + 1 < max_count
            {
                continue;
            }
            *class_count += 1;
            total_weight = total_weight.saturating_add(envelope.weight_units);
            selected_ids.push(envelope_id);
        }
        if selected_ids.is_empty() {
            self.counters.deferred_envelopes = self.counters.deferred_envelopes.saturating_add(1);
            return Err("no eligible sealed envelopes for batch selection".to_string());
        }
        for envelope_id in &selected_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Batched;
            }
        }
        let selected = selected_ids
            .iter()
            .filter_map(|envelope_id| self.envelopes.get(envelope_id))
            .cloned()
            .collect::<Vec<_>>();
        let envelope_records = selected
            .iter()
            .map(SealedIntentEnvelope::public_record)
            .collect::<Vec<_>>();
        let pq_records = selected
            .iter()
            .map(|envelope| json!({ "pq_authorization_root": envelope.pq_authorization_root }))
            .collect::<Vec<_>>();
        let nullifier_records = selected
            .iter()
            .map(|envelope| json!({ "nullifier_root": envelope.nullifier_root }))
            .collect::<Vec<_>>();
        let fee_records = selected
            .iter()
            .map(|envelope| {
                json!({
                    "envelope_id": envelope.envelope_id,
                    "fee_asset_root": envelope.fee_asset_root,
                    "max_fee_micro_units": envelope.max_fee_micro_units,
                })
            })
            .collect::<Vec<_>>();
        let privacy_records = selected
            .iter()
            .map(|envelope| {
                json!({
                    "envelope_id": envelope.envelope_id,
                    "min_privacy_set": envelope.min_privacy_set,
                    "privacy_proof_root": envelope.privacy_proof_root,
                })
            })
            .collect::<Vec<_>>();
        let fair_records = selected
            .iter()
            .enumerate()
            .map(|(index, envelope)| {
                json!({
                    "rank": index,
                    "envelope_id": envelope.envelope_id,
                    "class": envelope.class.as_str(),
                    "latency_class": envelope.latency_class.as_str(),
                    "intake_height": envelope.intake_height,
                    "ordering_salt_root": envelope.ordering_salt_root,
                })
            })
            .collect::<Vec<_>>();
        let envelope_root = merkle_root(
            "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-SELECTED-ENVELOPE",
            &envelope_records,
        );
        let pq_authorization_root =
            merkle_root("PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-PQ-AUTH", &pq_records);
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-NULLIFIER",
            &nullifier_records,
        );
        let fee_cap_root = merkle_root("PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-FEE-CAP", &fee_records);
        let privacy_floor_root = merkle_root(
            "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-PRIVACY-FLOOR",
            &privacy_records,
        );
        let fair_ordering_root = merkle_root(
            "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-FAIR-ORDERING",
            &fair_records,
        );
        let min_privacy_set = selected
            .iter()
            .map(|envelope| envelope.min_privacy_set)
            .min()
            .unwrap_or(self.config.min_privacy_set);
        let max_fee_micro_units = selected
            .iter()
            .map(|envelope| envelope.max_fee_micro_units)
            .max()
            .unwrap_or(0);
        let batch_id = private_l2_pq_mempool_scheduler_id(
            "BATCH",
            &[
                &self.height.to_string(),
                &envelope_root,
                &pq_authorization_root,
                &nullifier_root,
                &fair_ordering_root,
            ],
        );
        let batch = ScheduledBatch {
            batch_id: batch_id.clone(),
            scheduled_height: self.height,
            target_execute_height: self.height.saturating_add(1),
            status: BatchStatus::Scheduled,
            envelope_ids: selected_ids,
            envelope_root,
            pq_authorization_root,
            nullifier_root,
            fee_cap_root,
            privacy_floor_root,
            fair_ordering_root,
            total_weight_units: total_weight,
            max_fee_micro_units,
            min_privacy_set,
        };
        let receipt_id = private_l2_pq_mempool_scheduler_id(
            "RECEIPT",
            &[
                &batch.batch_id,
                &batch.root(),
                &self.counters.scheduled_batches.to_string(),
            ],
        );
        let receipt = ScheduledBatchReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: batch.batch_id.clone(),
            scheduled_height: batch.scheduled_height,
            executed_height: None,
            status: BatchStatus::Scheduled,
            batch_root: batch.root(),
            execution_root: None,
            included_envelope_count: batch.envelope_ids.len() as u64,
            executed_envelope_count: 0,
        };
        self.counters.scheduled_batches = self.counters.scheduled_batches.saturating_add(1);
        self.batches.insert(batch.batch_id.clone(), batch);
        self.receipts.insert(receipt_id, receipt.clone());
        self.prune_history();
        Ok(receipt)
    }

    pub fn mark_executed(
        &mut self,
        batch_id: &str,
        executed_height: u64,
        execution_root: &str,
        success: bool,
    ) -> PrivateL2PqMempoolSchedulerResult<ScheduledBatchReceipt> {
        if batch_id.is_empty() || execution_root.is_empty() {
            return Err("batch id and execution root cannot be empty".to_string());
        }
        self.height = self.height.max(executed_height);
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "scheduled batch not found".to_string())?;
        if batch.status != BatchStatus::Scheduled {
            return Err("scheduled batch already marked".to_string());
        }
        batch.status = if success {
            BatchStatus::Executed
        } else {
            BatchStatus::Failed
        };
        let mut executed_count = 0_u64;
        for envelope_id in &batch.envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = if success {
                    executed_count = executed_count.saturating_add(1);
                    EnvelopeStatus::Executed
                } else {
                    EnvelopeStatus::Deferred
                };
            }
        }
        if success {
            self.counters.executed_batches = self.counters.executed_batches.saturating_add(1);
            self.counters.executed_envelopes = self
                .counters
                .executed_envelopes
                .saturating_add(executed_count);
        } else {
            self.counters.failed_batches = self.counters.failed_batches.saturating_add(1);
            self.counters.deferred_envelopes = self
                .counters
                .deferred_envelopes
                .saturating_add(batch.envelope_ids.len() as u64);
        }
        let receipt = self
            .receipts
            .values_mut()
            .find(|receipt| receipt.batch_id == batch_id)
            .ok_or_else(|| "scheduled batch receipt not found".to_string())?;
        receipt.status = batch.status;
        receipt.executed_height = Some(executed_height);
        receipt.execution_root = Some(execution_root.to_string());
        receipt.executed_envelope_count = executed_count;
        Ok(receipt.clone())
    }

    pub fn roots(&self) -> Roots {
        let envelope_records = self
            .envelopes
            .values()
            .map(SealedIntentEnvelope::public_record)
            .collect::<Vec<_>>();
        let pending_records = self
            .envelopes
            .values()
            .filter(|envelope| envelope.status == EnvelopeStatus::Pending)
            .map(|envelope| json!({ "envelope_id": envelope.envelope_id, "root": envelope.root() }))
            .collect::<Vec<_>>();
        let pq_records = self
            .envelopes
            .values()
            .map(|envelope| json!({ "pq_authorization_root": envelope.pq_authorization_root }))
            .collect::<Vec<_>>();
        let nullifier_records = self
            .seen_nullifier_roots
            .iter()
            .map(|nullifier_root| json!({ "nullifier_root": nullifier_root }))
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(ScheduledBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(ScheduledBatchReceipt::public_record)
            .collect::<Vec<_>>();
        Roots {
            config_root: self.config.root(),
            envelope_root: merkle_root(
                "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-ENVELOPE-SET",
                &envelope_records,
            ),
            pending_envelope_root: merkle_root(
                "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-PENDING-SET",
                &pending_records,
            ),
            pq_authorization_root: merkle_root(
                "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-PQ-AUTH-SET",
                &pq_records,
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-NULLIFIER-SET",
                &nullifier_records,
            ),
            batch_root: merkle_root("PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-BATCH-SET", &batch_records),
            receipt_root: merkle_root(
                "PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-RECEIPT-SET",
                &receipt_records,
            ),
            counter_root: self.counters.root(),
        }
    }

    pub fn pending_envelope_ids(&self) -> Vec<String> {
        self.envelopes
            .values()
            .filter(|envelope| envelope.status == EnvelopeStatus::Pending)
            .map(|envelope| envelope.envelope_id.clone())
            .collect()
    }

    pub fn live_batch_ids(&self) -> Vec<String> {
        self.batches
            .values()
            .filter(|batch| batch.status == BatchStatus::Scheduled)
            .map(|batch| batch.batch_id.clone())
            .collect()
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_mempool_scheduler_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PQ_AUTH_SUITE,
            "sealing_suite": PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_SEALING_SUITE,
            "privacy_proof_system": PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_PRIVACY_PROOF_SYSTEM,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
            "pending_envelope_ids": self.pending_envelope_ids(),
            "live_batch_ids": self.live_batch_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_pq_mempool_scheduler_payload_root("STATE", &self.public_record())
    }

    fn expire_pending(&mut self) {
        for envelope in self.envelopes.values_mut() {
            if envelope.status == EnvelopeStatus::Pending
                && envelope.expires_at_height <= self.height
            {
                envelope.status = EnvelopeStatus::Expired;
                self.counters.expired_envelopes = self.counters.expired_envelopes.saturating_add(1);
            }
        }
    }

    fn prune_history(&mut self) {
        while self.receipts.len() > PRIVATE_L2_PQ_MEMPOOL_SCHEDULER_MAX_RECEIPTS {
            if let Some(first_key) = self.receipts.keys().next().cloned() {
                self.receipts.remove(&first_key);
            } else {
                break;
            }
        }
    }
}

pub fn private_l2_pq_mempool_scheduler_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_pq_mempool_scheduler_id(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-ID-{domain}"),
        &[HashPart::Json(&json!({ "parts": parts }))],
        32,
    )
}

pub fn private_l2_pq_mempool_scheduler_seed_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-MEMPOOL-SCHEDULER-SEED-{domain}"),
        &[HashPart::Str(label)],
        32,
    )
}

pub fn devnet() -> PrivateL2PqMempoolSchedulerResult<State> {
    State::devnet()
}
