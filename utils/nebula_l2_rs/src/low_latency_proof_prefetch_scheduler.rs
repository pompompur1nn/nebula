use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowLatencyProofPrefetchSchedulerResult<T> = Result<T, String>;

pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PROTOCOL_VERSION: &str =
    "nebula-l2-low-latency-proof-prefetch-scheduler-v1";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_SCHEMA_VERSION: u64 = 1;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_HASH_SUITE: &str = "SHAKE256";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_HINT_ENCRYPTION_SCHEME: &str =
    "ml-kem-768+xchacha20-poly1305-witness-hint-v1";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_RECEIPT_SCHEME: &str =
    "shake256-prefetch-completion-receipt-v1";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PREDICTION_MODEL: &str =
    "deterministic-devnet-proof-request-predictor-v1";
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_PREDICTIONS: usize = 512;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_HINTS: usize = 768;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_RESERVATIONS: usize = 384;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_LANES: usize = 16;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_QUEUE_ITEMS: usize = 768;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_AUTHORIZATIONS: usize = 768;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_RECEIPTS: usize = 768;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_LOOKAHEAD_BLOCKS: u64 = 16;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HINT_TTL_BLOCKS: u64 = 32;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HOT_QUEUE_TARGET_MS: u64 = 750;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_COLD_QUEUE_TARGET_MS: u64 = 4_000;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MIN_CONFIDENCE_BPS: u64 = 2_500;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HOT_CONFIDENCE_BPS: u64 = 7_500;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MIN_FEE_MICRO_UNITS: u64 = 25;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_PROTOCOL_FEE_BPS: u64 = 250;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_REBATE_BPS: u64 = 1_000;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRequestKind {
    RollupStateTransition,
    MoneroBridgeExit,
    MoneroBridgeReserve,
    PrivateContractCall,
    PrivateIntentSettlement,
    FeeRebateClearing,
    RecursiveAggregate,
    FraudEvidence,
    WatchtowerRefresh,
    WalletSyncWitness,
}

impl ProofRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupStateTransition => "rollup_state_transition",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::MoneroBridgeReserve => "monero_bridge_reserve",
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateIntentSettlement => "private_intent_settlement",
            Self::FeeRebateClearing => "fee_rebate_clearing",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::FraudEvidence => "fraud_evidence",
            Self::WatchtowerRefresh => "watchtower_refresh",
            Self::WalletSyncWitness => "wallet_sync_witness",
        }
    }

    pub fn default_lane(self) -> PrefetchLaneKind {
        match self {
            Self::MoneroBridgeExit | Self::MoneroBridgeReserve => PrefetchLaneKind::Bridge,
            Self::PrivateContractCall => PrefetchLaneKind::PrivateContracts,
            Self::PrivateIntentSettlement => PrefetchLaneKind::Intents,
            Self::FeeRebateClearing => PrefetchLaneKind::FeeRebates,
            Self::FraudEvidence => PrefetchLaneKind::Emergency,
            Self::RollupStateTransition | Self::RecursiveAggregate => PrefetchLaneKind::Rollup,
            Self::WatchtowerRefresh | Self::WalletSyncWitness => PrefetchLaneKind::Maintenance,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridgeExit
                | Self::MoneroBridgeReserve
                | Self::PrivateContractCall
                | Self::PrivateIntentSettlement
                | Self::WalletSyncWitness
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionStatus {
    Candidate,
    Scored,
    Promoted,
    Reserved,
    Queued,
    Completed,
    Expired,
    Rejected,
}

impl PredictionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Scored => "scored",
            Self::Promoted => "promoted",
            Self::Reserved => "reserved",
            Self::Queued => "queued",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Candidate | Self::Scored | Self::Promoted | Self::Reserved | Self::Queued
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessHintStatus {
    Sealed,
    Advertised,
    Pinned,
    Consumed,
    Expired,
    Revoked,
}

impl WitnessHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Advertised => "advertised",
            Self::Pinned => "pinned",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Sealed | Self::Advertised | Self::Pinned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Offered,
    Accepted,
    Bound,
    Released,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Bound => "bound",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Offered | Self::Accepted | Self::Bound)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchLaneKind {
    Emergency,
    Bridge,
    PrivateContracts,
    Intents,
    Rollup,
    FeeRebates,
    Maintenance,
}

impl PrefetchLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Bridge => "bridge",
            Self::PrivateContracts => "private_contracts",
            Self::Intents => "intents",
            Self::Rollup => "rollup",
            Self::FeeRebates => "fee_rebates",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Bridge => 9_400,
            Self::PrivateContracts => 8_400,
            Self::Intents => 7_800,
            Self::Rollup => 6_600,
            Self::FeeRebates => 5_500,
            Self::Maintenance => 2_000,
        }
    }

    pub fn default_fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Emergency => 2_000,
            Self::Bridge => 1_500,
            Self::PrivateContracts => 1_250,
            Self::Intents => 1_150,
            Self::Rollup => 1_000,
            Self::FeeRebates => 900,
            Self::Maintenance => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueTemperature {
    Hot,
    Cold,
}

impl QueueTemperature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Cold => "cold",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueItemStatus {
    Pending,
    Leased,
    Proving,
    Completed,
    Dropped,
    Expired,
}

impl QueueItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Proving => "proving",
            Self::Completed => "completed",
            Self::Dropped => "dropped",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Pending | Self::Leased | Self::Proving)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Committed,
    Revealed,
    Bound,
    Spent,
    Revoked,
    Expired,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Bound => "bound",
            Self::Spent => "spent",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Committed | Self::Revealed | Self::Bound)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Claimed,
    Verified,
    Settled,
    Disputed,
    Rejected,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Verified => "verified",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u64,
    pub prediction_model: String,
    pub hint_encryption_scheme: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub completion_receipt_scheme: String,
    pub max_predictions: usize,
    pub max_hints: usize,
    pub max_reservations: usize,
    pub max_lanes: usize,
    pub max_queue_items: usize,
    pub max_authorizations: usize,
    pub max_receipts: usize,
    pub lookahead_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub hot_queue_target_ms: u64,
    pub cold_queue_target_ms: u64,
    pub min_confidence_bps: u64,
    pub hot_confidence_bps: u64,
    pub min_fee_micro_units: u64,
    pub protocol_fee_bps: u64,
    pub completion_rebate_bps: u64,
    pub slashing_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_SCHEMA_VERSION,
            prediction_model: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PREDICTION_MODEL.to_string(),
            hint_encryption_scheme: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_HINT_ENCRYPTION_SCHEME
                .to_string(),
            pq_signature_scheme: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PQ_SIGNATURE_SCHEME
                .to_string(),
            pq_kem_scheme: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PQ_KEM_SCHEME.to_string(),
            completion_receipt_scheme: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_RECEIPT_SCHEME
                .to_string(),
            max_predictions: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_PREDICTIONS,
            max_hints: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_HINTS,
            max_reservations: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_RESERVATIONS,
            max_lanes: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_LANES,
            max_queue_items: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_QUEUE_ITEMS,
            max_authorizations: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_AUTHORIZATIONS,
            max_receipts: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MAX_RECEIPTS,
            lookahead_blocks: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_LOOKAHEAD_BLOCKS,
            hint_ttl_blocks: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HINT_TTL_BLOCKS,
            reservation_ttl_blocks:
                LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_RESERVATION_TTL_BLOCKS,
            hot_queue_target_ms: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HOT_QUEUE_TARGET_MS,
            cold_queue_target_ms: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_COLD_QUEUE_TARGET_MS,
            min_confidence_bps: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MIN_CONFIDENCE_BPS,
            hot_confidence_bps: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HOT_CONFIDENCE_BPS,
            min_fee_micro_units: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_MIN_FEE_MICRO_UNITS,
            protocol_fee_bps: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_PROTOCOL_FEE_BPS,
            completion_rebate_bps: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_REBATE_BPS,
            slashing_bps: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_SLASHING_BPS,
        }
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_positive("schema_version", self.schema_version)?;
        ensure_nonempty("prediction_model", &self.prediction_model)?;
        ensure_nonempty("hint_encryption_scheme", &self.hint_encryption_scheme)?;
        ensure_nonempty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_nonempty("pq_kem_scheme", &self.pq_kem_scheme)?;
        ensure_nonempty("completion_receipt_scheme", &self.completion_receipt_scheme)?;
        ensure_usize_positive("max_predictions", self.max_predictions)?;
        ensure_usize_positive("max_hints", self.max_hints)?;
        ensure_usize_positive("max_reservations", self.max_reservations)?;
        ensure_usize_positive("max_lanes", self.max_lanes)?;
        ensure_usize_positive("max_queue_items", self.max_queue_items)?;
        ensure_usize_positive("max_authorizations", self.max_authorizations)?;
        ensure_usize_positive("max_receipts", self.max_receipts)?;
        ensure_positive("lookahead_blocks", self.lookahead_blocks)?;
        ensure_positive("hint_ttl_blocks", self.hint_ttl_blocks)?;
        ensure_positive("reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        ensure_positive("hot_queue_target_ms", self.hot_queue_target_ms)?;
        ensure_positive("cold_queue_target_ms", self.cold_queue_target_ms)?;
        ensure_bps("min_confidence_bps", self.min_confidence_bps)?;
        ensure_bps("hot_confidence_bps", self.hot_confidence_bps)?;
        ensure_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        ensure_bps("completion_rebate_bps", self.completion_rebate_bps)?;
        ensure_bps("slashing_bps", self.slashing_bps)?;
        ensure_positive("min_fee_micro_units", self.min_fee_micro_units)?;
        if self.hot_confidence_bps < self.min_confidence_bps {
            return Err("hot confidence must be at least minimum confidence".to_string());
        }
        if self.hot_queue_target_ms > self.cold_queue_target_ms {
            return Err("hot queue target must be no slower than cold queue target".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "prediction_model": self.prediction_model,
            "hint_encryption_scheme": self.hint_encryption_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "completion_receipt_scheme": self.completion_receipt_scheme,
            "max_predictions": self.max_predictions,
            "max_hints": self.max_hints,
            "max_reservations": self.max_reservations,
            "max_lanes": self.max_lanes,
            "max_queue_items": self.max_queue_items,
            "max_authorizations": self.max_authorizations,
            "max_receipts": self.max_receipts,
            "lookahead_blocks": self.lookahead_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "hot_queue_target_ms": self.hot_queue_target_ms,
            "cold_queue_target_ms": self.cold_queue_target_ms,
            "min_confidence_bps": self.min_confidence_bps,
            "hot_confidence_bps": self.hot_confidence_bps,
            "min_fee_micro_units": self.min_fee_micro_units,
            "protocol_fee_bps": self.protocol_fee_bps,
            "completion_rebate_bps": self.completion_rebate_bps,
            "slashing_bps": self.slashing_bps,
        })
    }

    pub fn config_root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestPrediction {
    pub prediction_id: String,
    pub request_kind: ProofRequestKind,
    pub lane: PrefetchLaneKind,
    pub account_commitment: String,
    pub source_commitment: String,
    pub circuit_id: String,
    pub witness_shape_root: String,
    pub public_input_root: String,
    pub dependency_root: String,
    pub predicted_at_height: u64,
    pub target_height: u64,
    pub expires_at_height: u64,
    pub confidence_bps: u64,
    pub expected_cycles: u64,
    pub expected_bytes: u64,
    pub privacy_sensitive: bool,
    pub status: PredictionStatus,
}

impl ProofRequestPrediction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_kind: ProofRequestKind,
        account_commitment: &str,
        source_commitment: &str,
        circuit_id: &str,
        witness_shape_root: &str,
        public_input_root: &str,
        dependency_root: &str,
        predicted_at_height: u64,
        target_height: u64,
        expires_at_height: u64,
        confidence_bps: u64,
        expected_cycles: u64,
        expected_bytes: u64,
    ) -> Self {
        let lane = request_kind.default_lane();
        let prediction_id = prediction_id(
            request_kind,
            account_commitment,
            source_commitment,
            circuit_id,
            witness_shape_root,
            public_input_root,
            target_height,
        );
        Self {
            prediction_id,
            request_kind,
            lane,
            account_commitment: account_commitment.to_string(),
            source_commitment: source_commitment.to_string(),
            circuit_id: circuit_id.to_string(),
            witness_shape_root: witness_shape_root.to_string(),
            public_input_root: public_input_root.to_string(),
            dependency_root: dependency_root.to_string(),
            predicted_at_height,
            target_height,
            expires_at_height,
            confidence_bps,
            expected_cycles,
            expected_bytes,
            privacy_sensitive: request_kind.privacy_sensitive(),
            status: PredictionStatus::Candidate,
        }
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("prediction_id", &self.prediction_id)?;
        ensure_nonempty("account_commitment", &self.account_commitment)?;
        ensure_nonempty("source_commitment", &self.source_commitment)?;
        ensure_nonempty("circuit_id", &self.circuit_id)?;
        ensure_nonempty("witness_shape_root", &self.witness_shape_root)?;
        ensure_nonempty("public_input_root", &self.public_input_root)?;
        ensure_nonempty("dependency_root", &self.dependency_root)?;
        ensure_bps("confidence_bps", self.confidence_bps)?;
        ensure_positive("expected_cycles", self.expected_cycles)?;
        ensure_positive("expected_bytes", self.expected_bytes)?;
        if self.target_height < self.predicted_at_height {
            return Err(format!(
                "prediction {} target height precedes prediction height",
                self.prediction_id
            ));
        }
        if self.expires_at_height < self.target_height {
            return Err(format!(
                "prediction {} expires before target height",
                self.prediction_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "prediction_id": self.prediction_id,
            "request_kind": self.request_kind.as_str(),
            "lane": self.lane.as_str(),
            "account_commitment": self.account_commitment,
            "source_commitment": self.source_commitment,
            "circuit_id": self.circuit_id,
            "witness_shape_root": self.witness_shape_root,
            "public_input_root": self.public_input_root,
            "dependency_root": self.dependency_root,
            "predicted_at_height": self.predicted_at_height,
            "target_height": self.target_height,
            "expires_at_height": self.expires_at_height,
            "confidence_bps": self.confidence_bps,
            "expected_cycles": self.expected_cycles,
            "expected_bytes": self.expected_bytes,
            "privacy_sensitive": self.privacy_sensitive,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PREDICTION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWitnessCacheHint {
    pub hint_id: String,
    pub prediction_id: String,
    pub cache_key_commitment: String,
    pub sealed_hint_root: String,
    pub encrypted_metadata_root: String,
    pub recipient_pq_key_commitment: String,
    pub hint_nonce_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub estimated_witness_bytes: u64,
    pub reuse_score_bps: u64,
    pub status: WitnessHintStatus,
}

impl EncryptedWitnessCacheHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prediction_id: &str,
        cache_key_commitment: &str,
        sealed_hint_root: &str,
        encrypted_metadata_root: &str,
        recipient_pq_key_commitment: &str,
        hint_nonce_commitment: &str,
        created_at_height: u64,
        expires_at_height: u64,
        estimated_witness_bytes: u64,
        reuse_score_bps: u64,
    ) -> Self {
        let hint_id = hint_id(
            prediction_id,
            cache_key_commitment,
            sealed_hint_root,
            recipient_pq_key_commitment,
            created_at_height,
        );
        Self {
            hint_id,
            prediction_id: prediction_id.to_string(),
            cache_key_commitment: cache_key_commitment.to_string(),
            sealed_hint_root: sealed_hint_root.to_string(),
            encrypted_metadata_root: encrypted_metadata_root.to_string(),
            recipient_pq_key_commitment: recipient_pq_key_commitment.to_string(),
            hint_nonce_commitment: hint_nonce_commitment.to_string(),
            created_at_height,
            expires_at_height,
            estimated_witness_bytes,
            reuse_score_bps,
            status: WitnessHintStatus::Sealed,
        }
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("hint_id", &self.hint_id)?;
        ensure_nonempty("prediction_id", &self.prediction_id)?;
        ensure_nonempty("cache_key_commitment", &self.cache_key_commitment)?;
        ensure_nonempty("sealed_hint_root", &self.sealed_hint_root)?;
        ensure_nonempty("encrypted_metadata_root", &self.encrypted_metadata_root)?;
        ensure_nonempty(
            "recipient_pq_key_commitment",
            &self.recipient_pq_key_commitment,
        )?;
        ensure_nonempty("hint_nonce_commitment", &self.hint_nonce_commitment)?;
        ensure_positive("estimated_witness_bytes", self.estimated_witness_bytes)?;
        ensure_bps("reuse_score_bps", self.reuse_score_bps)?;
        if self.expires_at_height < self.created_at_height {
            return Err(format!(
                "hint {} expires before it is created",
                self.hint_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "prediction_id": self.prediction_id,
            "cache_key_commitment": self.cache_key_commitment,
            "sealed_hint_root": self.sealed_hint_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "recipient_pq_key_commitment": self.recipient_pq_key_commitment,
            "hint_nonce_commitment": self.hint_nonce_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "estimated_witness_bytes": self.estimated_witness_bytes,
            "reuse_score_bps": self.reuse_score_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("WITNESS-HINT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverReservation {
    pub reservation_id: String,
    pub prover_id: String,
    pub operator_commitment: String,
    pub pq_key_commitment: String,
    pub lane: PrefetchLaneKind,
    pub capacity_cycles: u64,
    pub reserved_cycles: u64,
    pub fee_floor_micro_units: u64,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl ProverReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_label: &str,
        operator_commitment: &str,
        pq_key_commitment: &str,
        lane: PrefetchLaneKind,
        capacity_cycles: u64,
        fee_floor_micro_units: u64,
        bond_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let prover_id = string_root("PROVER-ID", prover_label);
        let reservation_id = reservation_id(
            &prover_id,
            operator_commitment,
            pq_key_commitment,
            lane,
            opened_at_height,
        );
        Self {
            reservation_id,
            prover_id,
            operator_commitment: operator_commitment.to_string(),
            pq_key_commitment: pq_key_commitment.to_string(),
            lane,
            capacity_cycles,
            reserved_cycles: 0,
            fee_floor_micro_units,
            bond_units,
            opened_at_height,
            expires_at_height,
            status: ReservationStatus::Offered,
        }
    }

    pub fn available_cycles(&self) -> u64 {
        self.capacity_cycles.saturating_sub(self.reserved_cycles)
    }

    pub fn reserve_cycles(&mut self, cycles: u64) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_positive("cycles", cycles)?;
        if cycles > self.available_cycles() {
            return Err(format!(
                "reservation {} lacks available cycles",
                self.reservation_id
            ));
        }
        self.reserved_cycles = self.reserved_cycles.saturating_add(cycles);
        self.status = ReservationStatus::Bound;
        Ok(())
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("reservation_id", &self.reservation_id)?;
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("pq_key_commitment", &self.pq_key_commitment)?;
        ensure_positive("capacity_cycles", self.capacity_cycles)?;
        ensure_positive("fee_floor_micro_units", self.fee_floor_micro_units)?;
        ensure_positive("bond_units", self.bond_units)?;
        if self.reserved_cycles > self.capacity_cycles {
            return Err(format!(
                "reservation {} over-reserved cycles",
                self.reservation_id
            ));
        }
        if self.expires_at_height < self.opened_at_height {
            return Err(format!(
                "reservation {} expires before it opens",
                self.reservation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "prover_id": self.prover_id,
            "operator_commitment": self.operator_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "lane": self.lane.as_str(),
            "capacity_cycles": self.capacity_cycles,
            "reserved_cycles": self.reserved_cycles,
            "available_cycles": self.available_cycles(),
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PROVER-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAwarePrefetchLane {
    pub lane_id: String,
    pub kind: PrefetchLaneKind,
    pub weight: u64,
    pub fee_multiplier_bps: u64,
    pub min_fee_micro_units: u64,
    pub budget_micro_units: u64,
    pub spent_micro_units: u64,
    pub hot_target_ms: u64,
    pub cold_target_ms: u64,
    pub admission_open: bool,
}

impl FeeAwarePrefetchLane {
    pub fn devnet(kind: PrefetchLaneKind, min_fee_micro_units: u64) -> Self {
        let lane_id = string_root("LANE-ID", kind.as_str());
        Self {
            lane_id,
            kind,
            weight: kind.default_weight(),
            fee_multiplier_bps: kind.default_fee_multiplier_bps(),
            min_fee_micro_units,
            budget_micro_units: min_fee_micro_units.saturating_mul(20_000),
            spent_micro_units: 0,
            hot_target_ms: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_HOT_QUEUE_TARGET_MS,
            cold_target_ms: LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_DEFAULT_COLD_QUEUE_TARGET_MS,
            admission_open: true,
        }
    }

    pub fn effective_min_fee(&self) -> u64 {
        self.min_fee_micro_units
            .saturating_mul(self.fee_multiplier_bps)
            .saturating_div(LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_MAX_BPS)
    }

    pub fn remaining_budget(&self) -> u64 {
        self.budget_micro_units
            .saturating_sub(self.spent_micro_units)
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_positive("weight", self.weight)?;
        ensure_bps("fee_multiplier_bps", self.fee_multiplier_bps)?;
        ensure_positive("min_fee_micro_units", self.min_fee_micro_units)?;
        ensure_positive("budget_micro_units", self.budget_micro_units)?;
        ensure_positive("hot_target_ms", self.hot_target_ms)?;
        ensure_positive("cold_target_ms", self.cold_target_ms)?;
        if self.hot_target_ms > self.cold_target_ms {
            return Err(format!(
                "lane {} hot target exceeds cold target",
                self.lane_id
            ));
        }
        if self.spent_micro_units > self.budget_micro_units {
            return Err(format!("lane {} spent beyond budget", self.lane_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "weight": self.weight,
            "fee_multiplier_bps": self.fee_multiplier_bps,
            "min_fee_micro_units": self.min_fee_micro_units,
            "effective_min_fee": self.effective_min_fee(),
            "budget_micro_units": self.budget_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "remaining_budget": self.remaining_budget(),
            "hot_target_ms": self.hot_target_ms,
            "cold_target_ms": self.cold_target_ms,
            "admission_open": self.admission_open,
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("FEE-AWARE-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofQueueItem {
    pub queue_id: String,
    pub prediction_id: String,
    pub hint_id: String,
    pub reservation_id: String,
    pub lane: PrefetchLaneKind,
    pub temperature: QueueTemperature,
    pub priority_score: u64,
    pub fee_bid_micro_units: u64,
    pub expected_cycles: u64,
    pub inserted_at_height: u64,
    pub deadline_height: u64,
    pub status: QueueItemStatus,
}

impl ProofQueueItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prediction_id: &str,
        hint_id: &str,
        reservation_id: &str,
        lane: PrefetchLaneKind,
        temperature: QueueTemperature,
        priority_score: u64,
        fee_bid_micro_units: u64,
        expected_cycles: u64,
        inserted_at_height: u64,
        deadline_height: u64,
    ) -> Self {
        let queue_id = queue_id(
            prediction_id,
            hint_id,
            reservation_id,
            lane,
            temperature,
            inserted_at_height,
        );
        Self {
            queue_id,
            prediction_id: prediction_id.to_string(),
            hint_id: hint_id.to_string(),
            reservation_id: reservation_id.to_string(),
            lane,
            temperature,
            priority_score,
            fee_bid_micro_units,
            expected_cycles,
            inserted_at_height,
            deadline_height,
            status: QueueItemStatus::Pending,
        }
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("queue_id", &self.queue_id)?;
        ensure_nonempty("prediction_id", &self.prediction_id)?;
        ensure_nonempty("hint_id", &self.hint_id)?;
        ensure_nonempty("reservation_id", &self.reservation_id)?;
        ensure_positive("priority_score", self.priority_score)?;
        ensure_positive("fee_bid_micro_units", self.fee_bid_micro_units)?;
        ensure_positive("expected_cycles", self.expected_cycles)?;
        if self.deadline_height < self.inserted_at_height {
            return Err(format!(
                "queue item {} deadline is in the past",
                self.queue_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "prediction_id": self.prediction_id,
            "hint_id": self.hint_id,
            "reservation_id": self.reservation_id,
            "lane": self.lane.as_str(),
            "temperature": self.temperature.as_str(),
            "priority_score": self.priority_score,
            "fee_bid_micro_units": self.fee_bid_micro_units,
            "expected_cycles": self.expected_cycles,
            "inserted_at_height": self.inserted_at_height,
            "deadline_height": self.deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PROOF-QUEUE-ITEM", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorizationCommitment {
    pub authorization_id: String,
    pub prediction_id: String,
    pub queue_id: String,
    pub authorizer_commitment: String,
    pub pq_key_commitment: String,
    pub authorization_commitment_root: String,
    pub transcript_root: String,
    pub nonce_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: AuthorizationStatus,
}

impl PqAuthorizationCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prediction_id: &str,
        queue_id: &str,
        authorizer_commitment: &str,
        pq_key_commitment: &str,
        authorization_commitment_root: &str,
        transcript_root: &str,
        nonce_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let authorization_id = authorization_id(
            prediction_id,
            queue_id,
            authorizer_commitment,
            pq_key_commitment,
            authorization_commitment_root,
        );
        Self {
            authorization_id,
            prediction_id: prediction_id.to_string(),
            queue_id: queue_id.to_string(),
            authorizer_commitment: authorizer_commitment.to_string(),
            pq_key_commitment: pq_key_commitment.to_string(),
            authorization_commitment_root: authorization_commitment_root.to_string(),
            transcript_root: transcript_root.to_string(),
            nonce_root: nonce_root.to_string(),
            created_at_height,
            expires_at_height,
            status: AuthorizationStatus::Committed,
        }
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("authorization_id", &self.authorization_id)?;
        ensure_nonempty("prediction_id", &self.prediction_id)?;
        ensure_nonempty("queue_id", &self.queue_id)?;
        ensure_nonempty("authorizer_commitment", &self.authorizer_commitment)?;
        ensure_nonempty("pq_key_commitment", &self.pq_key_commitment)?;
        ensure_nonempty(
            "authorization_commitment_root",
            &self.authorization_commitment_root,
        )?;
        ensure_nonempty("transcript_root", &self.transcript_root)?;
        ensure_nonempty("nonce_root", &self.nonce_root)?;
        if self.expires_at_height < self.created_at_height {
            return Err(format!(
                "authorization {} expires before it is created",
                self.authorization_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "prediction_id": self.prediction_id,
            "queue_id": self.queue_id,
            "authorizer_commitment": self.authorizer_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "authorization_commitment_root": self.authorization_commitment_root,
            "transcript_root": self.transcript_root,
            "nonce_root": self.nonce_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("PQ-AUTHORIZATION-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionReceipt {
    pub receipt_id: String,
    pub queue_id: String,
    pub prediction_id: String,
    pub prover_id: String,
    pub proof_commitment_root: String,
    pub public_output_root: String,
    pub witness_hint_root: String,
    pub latency_ms: u64,
    pub cycles_used: u64,
    pub fee_charged_micro_units: u64,
    pub rebate_micro_units: u64,
    pub completed_at_height: u64,
    pub status: ReceiptStatus,
}

impl CompletionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue_id: &str,
        prediction_id: &str,
        prover_id: &str,
        proof_commitment_root: &str,
        public_output_root: &str,
        witness_hint_root: &str,
        latency_ms: u64,
        cycles_used: u64,
        fee_charged_micro_units: u64,
        rebate_micro_units: u64,
        completed_at_height: u64,
    ) -> Self {
        let receipt_id = receipt_id(
            queue_id,
            prediction_id,
            prover_id,
            proof_commitment_root,
            completed_at_height,
        );
        Self {
            receipt_id,
            queue_id: queue_id.to_string(),
            prediction_id: prediction_id.to_string(),
            prover_id: prover_id.to_string(),
            proof_commitment_root: proof_commitment_root.to_string(),
            public_output_root: public_output_root.to_string(),
            witness_hint_root: witness_hint_root.to_string(),
            latency_ms,
            cycles_used,
            fee_charged_micro_units,
            rebate_micro_units,
            completed_at_height,
            status: ReceiptStatus::Claimed,
        }
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("receipt_id", &self.receipt_id)?;
        ensure_nonempty("queue_id", &self.queue_id)?;
        ensure_nonempty("prediction_id", &self.prediction_id)?;
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("proof_commitment_root", &self.proof_commitment_root)?;
        ensure_nonempty("public_output_root", &self.public_output_root)?;
        ensure_nonempty("witness_hint_root", &self.witness_hint_root)?;
        ensure_positive("latency_ms", self.latency_ms)?;
        ensure_positive("cycles_used", self.cycles_used)?;
        ensure_positive("fee_charged_micro_units", self.fee_charged_micro_units)?;
        if self.rebate_micro_units > self.fee_charged_micro_units {
            return Err(format!(
                "receipt {} rebate exceeds charged fee",
                self.receipt_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "queue_id": self.queue_id,
            "prediction_id": self.prediction_id,
            "prover_id": self.prover_id,
            "proof_commitment_root": self.proof_commitment_root,
            "public_output_root": self.public_output_root,
            "witness_hint_root": self.witness_hint_root,
            "latency_ms": self.latency_ms,
            "cycles_used": self.cycles_used,
            "fee_charged_micro_units": self.fee_charged_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "completed_at_height": self.completed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        payload_root("COMPLETION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub prediction_root: String,
    pub witness_hint_root: String,
    pub reservation_root: String,
    pub lane_root: String,
    pub hot_queue_root: String,
    pub cold_queue_root: String,
    pub authorization_root: String,
    pub completion_receipt_root: String,
    pub index_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "prediction_root": self.prediction_root,
            "witness_hint_root": self.witness_hint_root,
            "reservation_root": self.reservation_root,
            "lane_root": self.lane_root,
            "hot_queue_root": self.hot_queue_root,
            "cold_queue_root": self.cold_queue_root,
            "authorization_root": self.authorization_root,
            "completion_receipt_root": self.completion_receipt_root,
            "index_root": self.index_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub predictions_total: u64,
    pub predictions_live: u64,
    pub hints_total: u64,
    pub hints_usable: u64,
    pub reservations_total: u64,
    pub reservations_active: u64,
    pub lanes_total: u64,
    pub lanes_open: u64,
    pub hot_queue_total: u64,
    pub hot_queue_live: u64,
    pub cold_queue_total: u64,
    pub cold_queue_live: u64,
    pub authorizations_total: u64,
    pub authorizations_live: u64,
    pub receipts_total: u64,
    pub receipts_verified: u64,
    pub total_predicted_cycles: u64,
    pub total_reserved_cycles: u64,
    pub total_fees_micro_units: u64,
    pub total_rebates_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "predictions_total": self.predictions_total,
            "predictions_live": self.predictions_live,
            "hints_total": self.hints_total,
            "hints_usable": self.hints_usable,
            "reservations_total": self.reservations_total,
            "reservations_active": self.reservations_active,
            "lanes_total": self.lanes_total,
            "lanes_open": self.lanes_open,
            "hot_queue_total": self.hot_queue_total,
            "hot_queue_live": self.hot_queue_live,
            "cold_queue_total": self.cold_queue_total,
            "cold_queue_live": self.cold_queue_live,
            "authorizations_total": self.authorizations_total,
            "authorizations_live": self.authorizations_live,
            "receipts_total": self.receipts_total,
            "receipts_verified": self.receipts_verified,
            "total_predicted_cycles": self.total_predicted_cycles,
            "total_reserved_cycles": self.total_reserved_cycles,
            "total_fees_micro_units": self.total_fees_micro_units,
            "total_rebates_micro_units": self.total_rebates_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub height: u64,
    pub config: Config,
    pub predictions: BTreeMap<String, ProofRequestPrediction>,
    pub witness_hints: BTreeMap<String, EncryptedWitnessCacheHint>,
    pub prover_reservations: BTreeMap<String, ProverReservation>,
    pub lanes: BTreeMap<String, FeeAwarePrefetchLane>,
    pub hot_queue: BTreeMap<String, ProofQueueItem>,
    pub cold_queue: BTreeMap<String, ProofQueueItem>,
    pub pq_authorizations: BTreeMap<String, PqAuthorizationCommitment>,
    pub completion_receipts: BTreeMap<String, CompletionReceipt>,
    pub prediction_to_hints: BTreeMap<String, BTreeSet<String>>,
    pub prediction_to_queue_items: BTreeMap<String, BTreeSet<String>>,
    pub queue_to_authorizations: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> LowLatencyProofPrefetchSchedulerResult<State> {
        let config = Config::devnet();
        let height = 1_u64;
        let mut state = State {
            chain_id: CHAIN_ID.to_string(),
            height,
            config,
            predictions: BTreeMap::new(),
            witness_hints: BTreeMap::new(),
            prover_reservations: BTreeMap::new(),
            lanes: BTreeMap::new(),
            hot_queue: BTreeMap::new(),
            cold_queue: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            completion_receipts: BTreeMap::new(),
            prediction_to_hints: BTreeMap::new(),
            prediction_to_queue_items: BTreeMap::new(),
            queue_to_authorizations: BTreeMap::new(),
        };

        state.seed_devnet_lanes();
        state.seed_devnet_predictions()?;
        state.seed_devnet_reservations()?;
        state.seed_devnet_hints()?;
        state.seed_devnet_queues()?;
        state.seed_devnet_authorizations()?;
        state.seed_devnet_receipts()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("state chain id does not match crate chain id".to_string());
        }
        self.config.validate()?;
        ensure_len(
            "predictions",
            self.predictions.len(),
            self.config.max_predictions,
        )?;
        ensure_len(
            "witness_hints",
            self.witness_hints.len(),
            self.config.max_hints,
        )?;
        ensure_len(
            "prover_reservations",
            self.prover_reservations.len(),
            self.config.max_reservations,
        )?;
        ensure_len("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_len(
            "hot_queue",
            self.hot_queue.len(),
            self.config.max_queue_items,
        )?;
        ensure_len(
            "cold_queue",
            self.cold_queue.len(),
            self.config.max_queue_items,
        )?;
        ensure_len(
            "pq_authorizations",
            self.pq_authorizations.len(),
            self.config.max_authorizations,
        )?;
        ensure_len(
            "completion_receipts",
            self.completion_receipts.len(),
            self.config.max_receipts,
        )?;

        for (id, prediction) in &self.predictions {
            if id != &prediction.prediction_id {
                return Err(format!("prediction key mismatch for {id}"));
            }
            prediction.validate()?;
            if !self.lane_exists(prediction.lane) {
                return Err(format!(
                    "prediction {} references missing lane {}",
                    id,
                    prediction.lane.as_str()
                ));
            }
        }

        for (id, hint) in &self.witness_hints {
            if id != &hint.hint_id {
                return Err(format!("witness hint key mismatch for {id}"));
            }
            hint.validate()?;
            if !self.predictions.contains_key(&hint.prediction_id) {
                return Err(format!(
                    "hint {} references missing prediction {}",
                    id, hint.prediction_id
                ));
            }
        }

        for (id, reservation) in &self.prover_reservations {
            if id != &reservation.reservation_id {
                return Err(format!("reservation key mismatch for {id}"));
            }
            reservation.validate()?;
            if !self.lane_exists(reservation.lane) {
                return Err(format!(
                    "reservation {} references missing lane {}",
                    id,
                    reservation.lane.as_str()
                ));
            }
        }

        for (id, lane) in &self.lanes {
            if id != &lane.lane_id {
                return Err(format!("lane key mismatch for {id}"));
            }
            lane.validate()?;
        }

        for (id, item) in &self.hot_queue {
            if id != &item.queue_id {
                return Err(format!("hot queue key mismatch for {id}"));
            }
            item.validate()?;
            if item.temperature != QueueTemperature::Hot {
                return Err(format!("hot queue item {} has non-hot temperature", id));
            }
            self.validate_queue_references(item)?;
        }

        for (id, item) in &self.cold_queue {
            if id != &item.queue_id {
                return Err(format!("cold queue key mismatch for {id}"));
            }
            item.validate()?;
            if item.temperature != QueueTemperature::Cold {
                return Err(format!("cold queue item {} has non-cold temperature", id));
            }
            self.validate_queue_references(item)?;
        }

        for (id, authorization) in &self.pq_authorizations {
            if id != &authorization.authorization_id {
                return Err(format!("authorization key mismatch for {id}"));
            }
            authorization.validate()?;
            if !self.predictions.contains_key(&authorization.prediction_id) {
                return Err(format!(
                    "authorization {} references missing prediction {}",
                    id, authorization.prediction_id
                ));
            }
            if !self.queue_contains(&authorization.queue_id) {
                return Err(format!(
                    "authorization {} references missing queue item {}",
                    id, authorization.queue_id
                ));
            }
        }

        for (id, receipt) in &self.completion_receipts {
            if id != &receipt.receipt_id {
                return Err(format!("receipt key mismatch for {id}"));
            }
            receipt.validate()?;
            if !self.predictions.contains_key(&receipt.prediction_id) {
                return Err(format!(
                    "receipt {} references missing prediction {}",
                    id, receipt.prediction_id
                ));
            }
        }

        self.validate_indexes()?;
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowLatencyProofPrefetchSchedulerResult<()> {
        self.height = height;
        self.expire_stale_records();
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> LowLatencyProofPrefetchSchedulerResult<()> {
        if height < self.height {
            return Err(format!(
                "cannot update scheduler height from {} down to {}",
                self.height, height
            ));
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let prediction_records = self
            .predictions
            .values()
            .map(ProofRequestPrediction::public_record)
            .collect::<Vec<_>>();
        let hint_records = self
            .witness_hints
            .values()
            .map(EncryptedWitnessCacheHint::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .prover_reservations
            .values()
            .map(ProverReservation::public_record)
            .collect::<Vec<_>>();
        let lane_records = self
            .lanes
            .values()
            .map(FeeAwarePrefetchLane::public_record)
            .collect::<Vec<_>>();
        let hot_records = self
            .hot_queue
            .values()
            .map(ProofQueueItem::public_record)
            .collect::<Vec<_>>();
        let cold_records = self
            .cold_queue
            .values()
            .map(ProofQueueItem::public_record)
            .collect::<Vec<_>>();
        let authorization_records = self
            .pq_authorizations
            .values()
            .map(PqAuthorizationCommitment::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .completion_receipts
            .values()
            .map(CompletionReceipt::public_record)
            .collect::<Vec<_>>();
        let index_records = self.index_records();

        Roots {
            config_root: self.config.config_root(),
            prediction_root: merkle_root(
                "LOW-LATENCY-PROOF-PREFETCH-PREDICTIONS",
                &prediction_records,
            ),
            witness_hint_root: merkle_root(
                "LOW-LATENCY-PROOF-PREFETCH-WITNESS-HINTS",
                &hint_records,
            ),
            reservation_root: merkle_root(
                "LOW-LATENCY-PROOF-PREFETCH-RESERVATIONS",
                &reservation_records,
            ),
            lane_root: merkle_root("LOW-LATENCY-PROOF-PREFETCH-LANES", &lane_records),
            hot_queue_root: merkle_root("LOW-LATENCY-PROOF-PREFETCH-HOT-QUEUE", &hot_records),
            cold_queue_root: merkle_root("LOW-LATENCY-PROOF-PREFETCH-COLD-QUEUE", &cold_records),
            authorization_root: merkle_root(
                "LOW-LATENCY-PROOF-PREFETCH-AUTHORIZATIONS",
                &authorization_records,
            ),
            completion_receipt_root: merkle_root(
                "LOW-LATENCY-PROOF-PREFETCH-COMPLETION-RECEIPTS",
                &receipt_records,
            ),
            index_root: merkle_root("LOW-LATENCY-PROOF-PREFETCH-INDEXES", &index_records),
        }
    }

    pub fn counters(&self) -> Counters {
        let hot_queue_live = self
            .hot_queue
            .values()
            .filter(|item| item.status.live())
            .count() as u64;
        let cold_queue_live = self
            .cold_queue
            .values()
            .filter(|item| item.status.live())
            .count() as u64;
        Counters {
            predictions_total: self.predictions.len() as u64,
            predictions_live: self
                .predictions
                .values()
                .filter(|prediction| prediction.status.live())
                .count() as u64,
            hints_total: self.witness_hints.len() as u64,
            hints_usable: self
                .witness_hints
                .values()
                .filter(|hint| hint.status.usable())
                .count() as u64,
            reservations_total: self.prover_reservations.len() as u64,
            reservations_active: self
                .prover_reservations
                .values()
                .filter(|reservation| reservation.status.active())
                .count() as u64,
            lanes_total: self.lanes.len() as u64,
            lanes_open: self
                .lanes
                .values()
                .filter(|lane| lane.admission_open)
                .count() as u64,
            hot_queue_total: self.hot_queue.len() as u64,
            hot_queue_live,
            cold_queue_total: self.cold_queue.len() as u64,
            cold_queue_live,
            authorizations_total: self.pq_authorizations.len() as u64,
            authorizations_live: self
                .pq_authorizations
                .values()
                .filter(|authorization| authorization.status.live())
                .count() as u64,
            receipts_total: self.completion_receipts.len() as u64,
            receipts_verified: self
                .completion_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ReceiptStatus::Verified | ReceiptStatus::Settled
                    )
                })
                .count() as u64,
            total_predicted_cycles: self
                .predictions
                .values()
                .map(|prediction| prediction.expected_cycles)
                .sum(),
            total_reserved_cycles: self
                .prover_reservations
                .values()
                .map(|reservation| reservation.reserved_cycles)
                .sum(),
            total_fees_micro_units: self
                .completion_receipts
                .values()
                .map(|receipt| receipt.fee_charged_micro_units)
                .sum(),
            total_rebates_micro_units: self
                .completion_receipts
                .values()
                .map(|receipt| receipt.rebate_micro_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_root())
    }

    pub fn schedule_prediction(
        &mut self,
        prediction: ProofRequestPrediction,
    ) -> LowLatencyProofPrefetchSchedulerResult<String> {
        prediction.validate()?;
        if self.predictions.len() >= self.config.max_predictions {
            return Err("prediction capacity exhausted".to_string());
        }
        let prediction_id = prediction.prediction_id.clone();
        self.predictions.insert(prediction_id.clone(), prediction);
        self.prediction_to_hints
            .entry(prediction_id.clone())
            .or_default();
        self.prediction_to_queue_items
            .entry(prediction_id.clone())
            .or_default();
        self.validate()?;
        Ok(prediction_id)
    }

    pub fn add_witness_hint(
        &mut self,
        hint: EncryptedWitnessCacheHint,
    ) -> LowLatencyProofPrefetchSchedulerResult<String> {
        hint.validate()?;
        if self.witness_hints.len() >= self.config.max_hints {
            return Err("witness hint capacity exhausted".to_string());
        }
        if !self.predictions.contains_key(&hint.prediction_id) {
            return Err(format!(
                "cannot add hint {} for missing prediction {}",
                hint.hint_id, hint.prediction_id
            ));
        }
        let hint_id = hint.hint_id.clone();
        let prediction_id = hint.prediction_id.clone();
        self.witness_hints.insert(hint_id.clone(), hint);
        self.prediction_to_hints
            .entry(prediction_id)
            .or_default()
            .insert(hint_id.clone());
        self.validate()?;
        Ok(hint_id)
    }

    pub fn add_reservation(
        &mut self,
        reservation: ProverReservation,
    ) -> LowLatencyProofPrefetchSchedulerResult<String> {
        reservation.validate()?;
        if self.prover_reservations.len() >= self.config.max_reservations {
            return Err("reservation capacity exhausted".to_string());
        }
        let reservation_id = reservation.reservation_id.clone();
        self.prover_reservations
            .insert(reservation_id.clone(), reservation);
        self.validate()?;
        Ok(reservation_id)
    }

    pub fn enqueue(
        &mut self,
        item: ProofQueueItem,
    ) -> LowLatencyProofPrefetchSchedulerResult<String> {
        item.validate()?;
        self.validate_queue_references(&item)?;
        let queue_id = item.queue_id.clone();
        let prediction_id = item.prediction_id.clone();
        match item.temperature {
            QueueTemperature::Hot => {
                if self.hot_queue.len() >= self.config.max_queue_items {
                    return Err("hot queue capacity exhausted".to_string());
                }
                self.hot_queue.insert(queue_id.clone(), item);
            }
            QueueTemperature::Cold => {
                if self.cold_queue.len() >= self.config.max_queue_items {
                    return Err("cold queue capacity exhausted".to_string());
                }
                self.cold_queue.insert(queue_id.clone(), item);
            }
        }
        self.prediction_to_queue_items
            .entry(prediction_id)
            .or_default()
            .insert(queue_id.clone());
        self.queue_to_authorizations
            .entry(queue_id.clone())
            .or_default();
        self.validate()?;
        Ok(queue_id)
    }

    pub fn add_authorization(
        &mut self,
        authorization: PqAuthorizationCommitment,
    ) -> LowLatencyProofPrefetchSchedulerResult<String> {
        authorization.validate()?;
        if self.pq_authorizations.len() >= self.config.max_authorizations {
            return Err("authorization capacity exhausted".to_string());
        }
        if !self.queue_contains(&authorization.queue_id) {
            return Err(format!(
                "cannot authorize missing queue item {}",
                authorization.queue_id
            ));
        }
        let authorization_id = authorization.authorization_id.clone();
        let queue_id = authorization.queue_id.clone();
        self.pq_authorizations
            .insert(authorization_id.clone(), authorization);
        self.queue_to_authorizations
            .entry(queue_id)
            .or_default()
            .insert(authorization_id.clone());
        self.validate()?;
        Ok(authorization_id)
    }

    pub fn add_completion_receipt(
        &mut self,
        receipt: CompletionReceipt,
    ) -> LowLatencyProofPrefetchSchedulerResult<String> {
        receipt.validate()?;
        if self.completion_receipts.len() >= self.config.max_receipts {
            return Err("completion receipt capacity exhausted".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        if let Some(item) = self.hot_queue.get_mut(&receipt.queue_id) {
            item.status = QueueItemStatus::Completed;
        }
        if let Some(item) = self.cold_queue.get_mut(&receipt.queue_id) {
            item.status = QueueItemStatus::Completed;
        }
        if let Some(prediction) = self.predictions.get_mut(&receipt.prediction_id) {
            prediction.status = PredictionStatus::Completed;
        }
        self.completion_receipts.insert(receipt_id.clone(), receipt);
        self.validate()?;
        Ok(receipt_id)
    }

    fn public_record_without_root(&self) -> Value {
        let prediction_records = self
            .predictions
            .values()
            .map(ProofRequestPrediction::public_record)
            .collect::<Vec<_>>();
        let hint_records = self
            .witness_hints
            .values()
            .map(EncryptedWitnessCacheHint::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .prover_reservations
            .values()
            .map(ProverReservation::public_record)
            .collect::<Vec<_>>();
        let lane_records = self
            .lanes
            .values()
            .map(FeeAwarePrefetchLane::public_record)
            .collect::<Vec<_>>();
        let hot_records = self
            .hot_queue
            .values()
            .map(ProofQueueItem::public_record)
            .collect::<Vec<_>>();
        let cold_records = self
            .cold_queue
            .values()
            .map(ProofQueueItem::public_record)
            .collect::<Vec<_>>();
        let authorization_records = self
            .pq_authorizations
            .values()
            .map(PqAuthorizationCommitment::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .completion_receipts
            .values()
            .map(CompletionReceipt::public_record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PROTOCOL_VERSION,
            "chain_id": self.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "predictions": prediction_records,
            "witness_hints": hint_records,
            "prover_reservations": reservation_records,
            "lanes": lane_records,
            "hot_queue": hot_records,
            "cold_queue": cold_records,
            "pq_authorizations": authorization_records,
            "completion_receipts": receipt_records,
            "indexes": self.index_records(),
        })
    }

    fn lane_exists(&self, lane: PrefetchLaneKind) -> bool {
        self.lanes.values().any(|candidate| candidate.kind == lane)
    }

    fn queue_contains(&self, queue_id: &str) -> bool {
        self.hot_queue.contains_key(queue_id) || self.cold_queue.contains_key(queue_id)
    }

    fn validate_queue_references(
        &self,
        item: &ProofQueueItem,
    ) -> LowLatencyProofPrefetchSchedulerResult<()> {
        if !self.predictions.contains_key(&item.prediction_id) {
            return Err(format!(
                "queue item {} references missing prediction {}",
                item.queue_id, item.prediction_id
            ));
        }
        if !self.witness_hints.contains_key(&item.hint_id) {
            return Err(format!(
                "queue item {} references missing hint {}",
                item.queue_id, item.hint_id
            ));
        }
        if !self.prover_reservations.contains_key(&item.reservation_id) {
            return Err(format!(
                "queue item {} references missing reservation {}",
                item.queue_id, item.reservation_id
            ));
        }
        if !self.lane_exists(item.lane) {
            return Err(format!(
                "queue item {} references missing lane {}",
                item.queue_id,
                item.lane.as_str()
            ));
        }
        Ok(())
    }

    fn validate_indexes(&self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        for (prediction_id, hint_ids) in &self.prediction_to_hints {
            if !self.predictions.contains_key(prediction_id) {
                return Err(format!(
                    "hint index references missing prediction {prediction_id}"
                ));
            }
            for hint_id in hint_ids {
                let hint = self
                    .witness_hints
                    .get(hint_id)
                    .ok_or_else(|| format!("hint index references missing hint {hint_id}"))?;
                if &hint.prediction_id != prediction_id {
                    return Err(format!("hint index mismatch for hint {hint_id}"));
                }
            }
        }
        for (prediction_id, queue_ids) in &self.prediction_to_queue_items {
            if !self.predictions.contains_key(prediction_id) {
                return Err(format!(
                    "queue index references missing prediction {prediction_id}"
                ));
            }
            for queue_id in queue_ids {
                let item = self
                    .hot_queue
                    .get(queue_id)
                    .or_else(|| self.cold_queue.get(queue_id))
                    .ok_or_else(|| format!("queue index references missing item {queue_id}"))?;
                if &item.prediction_id != prediction_id {
                    return Err(format!("queue index mismatch for item {queue_id}"));
                }
            }
        }
        for (queue_id, authorization_ids) in &self.queue_to_authorizations {
            if !self.queue_contains(queue_id) {
                return Err(format!(
                    "authorization index references missing queue item {queue_id}"
                ));
            }
            for authorization_id in authorization_ids {
                let authorization = self.pq_authorizations.get(authorization_id).ok_or_else(|| {
                    format!("authorization index references missing authorization {authorization_id}")
                })?;
                if &authorization.queue_id != queue_id {
                    return Err(format!(
                        "authorization index mismatch for authorization {authorization_id}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn index_records(&self) -> Vec<Value> {
        let mut records = Vec::new();
        for (prediction_id, hint_ids) in &self.prediction_to_hints {
            records.push(json!({
                "index": "prediction_to_hints",
                "prediction_id": prediction_id,
                "hint_ids": hint_ids.iter().cloned().collect::<Vec<_>>(),
            }));
        }
        for (prediction_id, queue_ids) in &self.prediction_to_queue_items {
            records.push(json!({
                "index": "prediction_to_queue_items",
                "prediction_id": prediction_id,
                "queue_ids": queue_ids.iter().cloned().collect::<Vec<_>>(),
            }));
        }
        for (queue_id, authorization_ids) in &self.queue_to_authorizations {
            records.push(json!({
                "index": "queue_to_authorizations",
                "queue_id": queue_id,
                "authorization_ids": authorization_ids.iter().cloned().collect::<Vec<_>>(),
            }));
        }
        records
    }

    fn expire_stale_records(&mut self) {
        for prediction in self.predictions.values_mut() {
            if prediction.status.live() && prediction.expires_at_height < self.height {
                prediction.status = PredictionStatus::Expired;
            }
        }
        for hint in self.witness_hints.values_mut() {
            if hint.status.usable() && hint.expires_at_height < self.height {
                hint.status = WitnessHintStatus::Expired;
            }
        }
        for reservation in self.prover_reservations.values_mut() {
            if reservation.status.active() && reservation.expires_at_height < self.height {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for item in self.hot_queue.values_mut() {
            if item.status.live() && item.deadline_height < self.height {
                item.status = QueueItemStatus::Expired;
            }
        }
        for item in self.cold_queue.values_mut() {
            if item.status.live() && item.deadline_height < self.height {
                item.status = QueueItemStatus::Expired;
            }
        }
        for authorization in self.pq_authorizations.values_mut() {
            if authorization.status.live() && authorization.expires_at_height < self.height {
                authorization.status = AuthorizationStatus::Expired;
            }
        }
    }

    fn seed_devnet_lanes(&mut self) {
        let kinds = [
            PrefetchLaneKind::Emergency,
            PrefetchLaneKind::Bridge,
            PrefetchLaneKind::PrivateContracts,
            PrefetchLaneKind::Intents,
            PrefetchLaneKind::Rollup,
            PrefetchLaneKind::FeeRebates,
            PrefetchLaneKind::Maintenance,
        ];
        for kind in kinds {
            let lane = FeeAwarePrefetchLane::devnet(kind, self.config.min_fee_micro_units);
            self.lanes.insert(lane.lane_id.clone(), lane);
        }
    }

    fn seed_devnet_predictions(&mut self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        let seeds = [
            (
                ProofRequestKind::MoneroBridgeExit,
                "devnet-bridge-exit-account",
                "devnet-monero-exit-watch",
                "monero_bridge_exit_fast_path",
                8_500,
                24_000_000,
                196_608,
            ),
            (
                ProofRequestKind::PrivateContractCall,
                "devnet-private-contract-account",
                "devnet-private-contract-mempool",
                "private_contract_call_prefetch",
                7_900,
                18_000_000,
                131_072,
            ),
            (
                ProofRequestKind::RollupStateTransition,
                "devnet-rollup-batcher",
                "devnet-sequencer-block-template",
                "rollup_state_transition_batch",
                6_800,
                32_000_000,
                262_144,
            ),
            (
                ProofRequestKind::PrivateIntentSettlement,
                "devnet-intent-solver",
                "devnet-private-intent-pool",
                "private_intent_settlement_prefetch",
                7_600,
                15_000_000,
                98_304,
            ),
            (
                ProofRequestKind::FeeRebateClearing,
                "devnet-fee-rebate-clearing",
                "devnet-fee-ledger",
                "fee_rebate_clearing_prefetch",
                5_900,
                7_000_000,
                65_536,
            ),
        ];

        for (offset, seed) in seeds.iter().enumerate() {
            let offset_height = offset as u64;
            let account_commitment = string_root("DEVNET-ACCOUNT", seed.1);
            let source_commitment = string_root("DEVNET-SOURCE", seed.2);
            let witness_shape_root = string_root("DEVNET-WITNESS-SHAPE", seed.3);
            let public_input_root = string_root("DEVNET-PUBLIC-INPUT", seed.3);
            let dependency_root = string_root("DEVNET-DEPENDENCY", seed.3);
            let mut prediction = ProofRequestPrediction::new(
                seed.0,
                &account_commitment,
                &source_commitment,
                seed.3,
                &witness_shape_root,
                &public_input_root,
                &dependency_root,
                self.height,
                self.height + 2 + offset_height,
                self.height + self.config.lookahead_blocks + offset_height,
                seed.4,
                seed.5,
                seed.6,
            );
            prediction.status = if prediction.confidence_bps >= self.config.hot_confidence_bps {
                PredictionStatus::Promoted
            } else {
                PredictionStatus::Scored
            };
            self.schedule_prediction(prediction)?;
        }
        Ok(())
    }

    fn seed_devnet_reservations(&mut self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        let reservations = [
            (
                "devnet-prover-bridge-a",
                PrefetchLaneKind::Bridge,
                80_000_000,
            ),
            (
                "devnet-prover-private-contract-a",
                PrefetchLaneKind::PrivateContracts,
                64_000_000,
            ),
            (
                "devnet-prover-rollup-a",
                PrefetchLaneKind::Rollup,
                96_000_000,
            ),
            (
                "devnet-prover-intents-a",
                PrefetchLaneKind::Intents,
                48_000_000,
            ),
            (
                "devnet-prover-fee-rebates-a",
                PrefetchLaneKind::FeeRebates,
                24_000_000,
            ),
        ];
        for (label, lane, capacity) in reservations {
            let operator_commitment = string_root("DEVNET-PROVER-OPERATOR", label);
            let pq_key_commitment = string_root("DEVNET-PROVER-PQ-KEY", label);
            let reservation = ProverReservation::new(
                label,
                &operator_commitment,
                &pq_key_commitment,
                lane,
                capacity,
                self.config.min_fee_micro_units,
                capacity / 64,
                self.height,
                self.height + self.config.reservation_ttl_blocks,
            );
            self.add_reservation(reservation)?;
        }
        Ok(())
    }

    fn seed_devnet_hints(&mut self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        let predictions = self
            .predictions
            .values()
            .cloned()
            .collect::<Vec<ProofRequestPrediction>>();
        for prediction in predictions {
            let cache_key_commitment = string_root("DEVNET-CACHE-KEY", &prediction.prediction_id);
            let sealed_hint_root = payload_root(
                "DEVNET-SEALED-HINT",
                &json!({
                    "prediction_id": prediction.prediction_id,
                    "witness_shape_root": prediction.witness_shape_root,
                    "privacy_sensitive": prediction.privacy_sensitive,
                }),
            );
            let encrypted_metadata_root = string_root(
                "DEVNET-ENCRYPTED-HINT-METADATA",
                &prediction.public_input_root,
            );
            let recipient_pq_key_commitment =
                string_root("DEVNET-HINT-RECIPIENT", prediction.lane.as_str());
            let hint_nonce_commitment = string_root("DEVNET-HINT-NONCE", &prediction.prediction_id);
            let mut hint = EncryptedWitnessCacheHint::new(
                &prediction.prediction_id,
                &cache_key_commitment,
                &sealed_hint_root,
                &encrypted_metadata_root,
                &recipient_pq_key_commitment,
                &hint_nonce_commitment,
                self.height,
                self.height + self.config.hint_ttl_blocks,
                prediction.expected_bytes,
                prediction.confidence_bps,
            );
            hint.status = WitnessHintStatus::Advertised;
            self.add_witness_hint(hint)?;
        }
        Ok(())
    }

    fn seed_devnet_queues(&mut self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        let predictions = self
            .predictions
            .values()
            .cloned()
            .collect::<Vec<ProofRequestPrediction>>();
        for prediction in predictions {
            let hint_id = self
                .prediction_to_hints
                .get(&prediction.prediction_id)
                .and_then(|hints| hints.iter().next().cloned())
                .ok_or_else(|| {
                    format!(
                        "missing devnet hint for prediction {}",
                        prediction.prediction_id
                    )
                })?;
            let reservation_id = self
                .prover_reservations
                .values()
                .find(|reservation| reservation.lane == prediction.lane)
                .map(|reservation| reservation.reservation_id.clone())
                .ok_or_else(|| {
                    format!(
                        "missing devnet reservation for lane {}",
                        prediction.lane.as_str()
                    )
                })?;
            let temperature = if prediction.confidence_bps >= self.config.hot_confidence_bps {
                QueueTemperature::Hot
            } else {
                QueueTemperature::Cold
            };
            let fee_bid = self.fee_bid_for_prediction(&prediction);
            let item = ProofQueueItem::new(
                &prediction.prediction_id,
                &hint_id,
                &reservation_id,
                prediction.lane,
                temperature,
                self.priority_score(&prediction),
                fee_bid,
                prediction.expected_cycles,
                self.height,
                prediction.expires_at_height,
            );
            if let Some(reservation) = self.prover_reservations.get_mut(&reservation_id) {
                reservation.reserve_cycles(prediction.expected_cycles)?;
            }
            self.enqueue(item)?;
        }
        Ok(())
    }

    fn seed_devnet_authorizations(&mut self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        let queue_items = self
            .hot_queue
            .values()
            .chain(self.cold_queue.values())
            .cloned()
            .collect::<Vec<ProofQueueItem>>();
        for item in queue_items {
            let authorizer_commitment = string_root("DEVNET-AUTHORIZER", &item.prediction_id);
            let pq_key_commitment = string_root("DEVNET-AUTHORIZER-PQ-KEY", &item.queue_id);
            let authorization_commitment_root =
                string_root("DEVNET-AUTHORIZATION-COMMITMENT", &item.queue_id);
            let transcript_root = string_root("DEVNET-AUTHORIZATION-TRANSCRIPT", &item.queue_id);
            let nonce_root = string_root("DEVNET-AUTHORIZATION-NONCE", &item.queue_id);
            let authorization = PqAuthorizationCommitment::new(
                &item.prediction_id,
                &item.queue_id,
                &authorizer_commitment,
                &pq_key_commitment,
                &authorization_commitment_root,
                &transcript_root,
                &nonce_root,
                self.height,
                item.deadline_height,
            );
            self.add_authorization(authorization)?;
        }
        Ok(())
    }

    fn seed_devnet_receipts(&mut self) -> LowLatencyProofPrefetchSchedulerResult<()> {
        let first_hot = self.hot_queue.values().next().cloned();
        if let Some(item) = first_hot {
            let prover_id = self
                .prover_reservations
                .get(&item.reservation_id)
                .map(|reservation| reservation.prover_id.clone())
                .ok_or_else(|| {
                    format!(
                        "missing reservation {} for devnet receipt",
                        item.reservation_id
                    )
                })?;
            let proof_commitment_root = string_root("DEVNET-PROOF-COMMITMENT", &item.queue_id);
            let public_output_root = string_root("DEVNET-PUBLIC-OUTPUT", &item.prediction_id);
            let witness_hint_root = self
                .witness_hints
                .get(&item.hint_id)
                .map(EncryptedWitnessCacheHint::record_root)
                .ok_or_else(|| format!("missing hint {} for devnet receipt", item.hint_id))?;
            let rebate = item
                .fee_bid_micro_units
                .saturating_mul(self.config.completion_rebate_bps)
                .saturating_div(LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_MAX_BPS);
            let mut receipt = CompletionReceipt::new(
                &item.queue_id,
                &item.prediction_id,
                &prover_id,
                &proof_commitment_root,
                &public_output_root,
                &witness_hint_root,
                self.config.hot_queue_target_ms,
                item.expected_cycles,
                item.fee_bid_micro_units,
                rebate,
                self.height + 1,
            );
            receipt.status = ReceiptStatus::Verified;
            self.add_completion_receipt(receipt)?;
        }
        Ok(())
    }

    fn fee_bid_for_prediction(&self, prediction: &ProofRequestPrediction) -> u64 {
        let base = match self
            .lanes
            .values()
            .find(|lane| lane.kind == prediction.lane)
            .map(FeeAwarePrefetchLane::effective_min_fee)
        {
            Some(value) => value,
            None => self.config.min_fee_micro_units,
        };
        let cycle_component = prediction.expected_cycles.saturating_div(1_000_000);
        let confidence_component = prediction
            .confidence_bps
            .saturating_mul(base)
            .saturating_div(LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_MAX_BPS);
        base.saturating_add(cycle_component)
            .saturating_add(confidence_component)
    }

    fn priority_score(&self, prediction: &ProofRequestPrediction) -> u64 {
        let lane_weight = match self
            .lanes
            .values()
            .find(|lane| lane.kind == prediction.lane)
            .map(|lane| lane.weight)
        {
            Some(value) => value,
            None => prediction.lane.default_weight(),
        };
        lane_weight
            .saturating_mul(2)
            .saturating_add(prediction.confidence_bps)
            .saturating_add(prediction.expected_cycles.saturating_div(1_000_000))
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-SCHEDULER-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> LowLatencyProofPrefetchSchedulerResult<State> {
    State::devnet()
}

pub fn prediction_id(
    request_kind: ProofRequestKind,
    account_commitment: &str,
    source_commitment: &str,
    circuit_id: &str,
    witness_shape_root: &str,
    public_input_root: &str,
    target_height: u64,
) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-PREDICTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_kind.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(source_commitment),
            HashPart::Str(circuit_id),
            HashPart::Str(witness_shape_root),
            HashPart::Str(public_input_root),
            HashPart::Int(target_height as i128),
        ],
        32,
    )
}

pub fn hint_id(
    prediction_id: &str,
    cache_key_commitment: &str,
    sealed_hint_root: &str,
    recipient_pq_key_commitment: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prediction_id),
            HashPart::Str(cache_key_commitment),
            HashPart::Str(sealed_hint_root),
            HashPart::Str(recipient_pq_key_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn reservation_id(
    prover_id: &str,
    operator_commitment: &str,
    pq_key_commitment: &str,
    lane: PrefetchLaneKind,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prover_id),
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_key_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn queue_id(
    prediction_id: &str,
    hint_id: &str,
    reservation_id: &str,
    lane: PrefetchLaneKind,
    temperature: QueueTemperature,
    inserted_at_height: u64,
) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prediction_id),
            HashPart::Str(hint_id),
            HashPart::Str(reservation_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(temperature.as_str()),
            HashPart::Int(inserted_at_height as i128),
        ],
        32,
    )
}

pub fn authorization_id(
    prediction_id: &str,
    queue_id: &str,
    authorizer_commitment: &str,
    pq_key_commitment: &str,
    authorization_commitment_root: &str,
) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prediction_id),
            HashPart::Str(queue_id),
            HashPart::Str(authorizer_commitment),
            HashPart::Str(pq_key_commitment),
            HashPart::Str(authorization_commitment_root),
        ],
        32,
    )
}

pub fn receipt_id(
    queue_id: &str,
    prediction_id: &str,
    prover_id: &str,
    proof_commitment_root: &str,
    completed_at_height: u64,
) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(queue_id),
            HashPart::Str(prediction_id),
            HashPart::Str(prover_id),
            HashPart::Str(proof_commitment_root),
            HashPart::Int(completed_at_height as i128),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "LOW-LATENCY-PROOF-PREFETCH-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

fn ensure_nonempty(name: &str, value: &str) -> LowLatencyProofPrefetchSchedulerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(name: &str, value: u64) -> LowLatencyProofPrefetchSchedulerResult<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_usize_positive(name: &str, value: usize) -> LowLatencyProofPrefetchSchedulerResult<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> LowLatencyProofPrefetchSchedulerResult<()> {
    if value > LOW_LATENCY_PROOF_PREFETCH_SCHEDULER_MAX_BPS {
        return Err(format!("{name} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_len(name: &str, len: usize, max: usize) -> LowLatencyProofPrefetchSchedulerResult<()> {
    if len > max {
        return Err(format!("{name} length {len} exceeds max {max}"));
    }
    Ok(())
}
