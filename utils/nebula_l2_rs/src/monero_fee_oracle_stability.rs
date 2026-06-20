use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroFeeOracleStabilityResult<T> = Result<T, String>;

pub const MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION: &str =
    "nebula-monero-fee-oracle-stability-v1";
pub const MONERO_FEE_ORACLE_STABILITY_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_SMOOTHING_BLOCKS: u64 = 24;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_MIN_PUBLISHERS: u64 = 2;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_MAX_DEVIATION_BPS: u64 = 1_500;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_PRESSURE_ALERT_BPS: u64 = 7_500;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_WITHDRAWAL_FORECAST_BLOCKS: u64 = 18;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 90;
pub const MONERO_FEE_ORACLE_STABILITY_DEFAULT_SUBSIDY_TTL_BLOCKS: u64 = 720;
pub const MONERO_FEE_ORACLE_STABILITY_MAX_BPS: u64 = 10_000;
pub const MONERO_FEE_ORACLE_STABILITY_MIN_WEIGHT_BPS: u64 = 1;
pub const MONERO_FEE_ORACLE_STABILITY_MAX_HISTORY: usize = 512;
pub const MONERO_FEE_ORACLE_STABILITY_FEE_ASSET: &str = "wxmr-devnet";
pub const MONERO_FEE_ORACLE_STABILITY_PQ_SCHEME: &str = "ML-DSA-65";
pub const MONERO_FEE_ORACLE_STABILITY_FALLBACK_PQ_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const MONERO_FEE_ORACLE_STABILITY_PROOF_SYSTEM: &str = "zk-monero-fee-oracle-attestation-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeObservationKind {
    MempoolSnapshot,
    DaemonEstimate,
    BlockInclusion,
    BridgeWithdrawal,
    PrivateDefiSample,
    WatchtowerReport,
}

impl MoneroFeeObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MempoolSnapshot => "mempool_snapshot",
            Self::DaemonEstimate => "daemon_estimate",
            Self::BlockInclusion => "block_inclusion",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::PrivateDefiSample => "private_defi_sample",
            Self::WatchtowerReport => "watchtower_report",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroMempoolPressureKind {
    Calm,
    Elevated,
    Congested,
    Spike,
    Quarantined,
}

impl MoneroMempoolPressureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calm => "calm",
            Self::Elevated => "elevated",
            Self::Congested => "congested",
            Self::Spike => "spike",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeLane {
    BridgeWithdrawal,
    PrivateTransfer,
    PrivateDefi,
    ProofSubmission,
    WalletRecovery,
    EmergencyExit,
}

impl MoneroFeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::ProofSubmission => "proof_submission",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::BridgeWithdrawal,
            Self::PrivateTransfer,
            Self::PrivateDefi,
            Self::ProofSubmission,
            Self::WalletRecovery,
            Self::EmergencyExit,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeForecastStatus {
    Draft,
    Active,
    Settled,
    Superseded,
    Disputed,
    Expired,
}

impl MoneroFeeForecastStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Settled => "settled",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Active | Self::Draft)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeCapStatus {
    Active,
    Throttled,
    Paused,
    Exhausted,
    Retired,
}

impl MoneroFeeCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeSubsidyStatus {
    Scheduled,
    Active,
    Exhausted,
    Expired,
    Revoked,
}

impl MoneroFeeSubsidyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeAttestationStatus {
    Submitted,
    Counted,
    Duplicate,
    Invalid,
    Expired,
}

impl MoneroFeeAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Duplicate => "duplicate",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeManipulationKind {
    PublisherDeviation,
    MempoolSpike,
    WithheldSample,
    BridgeQueueAmplification,
    DefiCapAbuse,
    SubsidyDrain,
    StaleAttestation,
}

impl MoneroFeeManipulationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublisherDeviation => "publisher_deviation",
            Self::MempoolSpike => "mempool_spike",
            Self::WithheldSample => "withheld_sample",
            Self::BridgeQueueAmplification => "bridge_queue_amplification",
            Self::DefiCapAbuse => "defi_cap_abuse",
            Self::SubsidyDrain => "subsidy_drain",
            Self::StaleAttestation => "stale_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeAlertSeverity {
    Info,
    Watch,
    Warn,
    Critical,
}

impl MoneroFeeAlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroFeeReceiptStatus {
    Pending,
    Settled,
    Rebated,
    Disputed,
    Expired,
}

impl MoneroFeeReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeOracleStabilityConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub network: String,
    pub operator_label: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub smoothing_window_blocks: u64,
    pub min_publisher_count: u64,
    pub max_deviation_bps: u64,
    pub pressure_alert_bps: u64,
    pub withdrawal_forecast_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub subsidy_ttl_blocks: u64,
}

impl MoneroFeeOracleStabilityConfig {
    pub fn devnet(operator_label: impl Into<String>) -> Self {
        Self {
            protocol_version: MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            network: MONERO_FEE_ORACLE_STABILITY_DEVNET_NETWORK.to_string(),
            operator_label: operator_label.into(),
            fee_asset_id: MONERO_FEE_ORACLE_STABILITY_FEE_ASSET.to_string(),
            epoch_blocks: MONERO_FEE_ORACLE_STABILITY_DEFAULT_EPOCH_BLOCKS,
            smoothing_window_blocks: MONERO_FEE_ORACLE_STABILITY_DEFAULT_SMOOTHING_BLOCKS,
            min_publisher_count: MONERO_FEE_ORACLE_STABILITY_DEFAULT_MIN_PUBLISHERS,
            max_deviation_bps: MONERO_FEE_ORACLE_STABILITY_DEFAULT_MAX_DEVIATION_BPS,
            pressure_alert_bps: MONERO_FEE_ORACLE_STABILITY_DEFAULT_PRESSURE_ALERT_BPS,
            withdrawal_forecast_blocks:
                MONERO_FEE_ORACLE_STABILITY_DEFAULT_WITHDRAWAL_FORECAST_BLOCKS,
            attestation_ttl_blocks: MONERO_FEE_ORACLE_STABILITY_DEFAULT_ATTESTATION_TTL_BLOCKS,
            subsidy_ttl_blocks: MONERO_FEE_ORACLE_STABILITY_DEFAULT_SUBSIDY_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_oracle_stability_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "network": self.network,
            "operator_label": self.operator_label,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "smoothing_window_blocks": self.smoothing_window_blocks,
            "min_publisher_count": self.min_publisher_count,
            "max_deviation_bps": self.max_deviation_bps,
            "pressure_alert_bps": self.pressure_alert_bps,
            "withdrawal_forecast_blocks": self.withdrawal_forecast_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "subsidy_ttl_blocks": self.subsidy_ttl_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-ORACLE-STABILITY-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        if self.protocol_version != MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION {
            return Err("monero fee oracle stability protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("monero fee oracle stability chain id mismatch".to_string());
        }
        require_non_empty("network", &self.network)?;
        require_non_empty("operator label", &self.operator_label)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_positive("epoch blocks", self.epoch_blocks)?;
        require_positive("smoothing window blocks", self.smoothing_window_blocks)?;
        require_positive("min publisher count", self.min_publisher_count)?;
        require_bps("max deviation bps", self.max_deviation_bps)?;
        require_bps("pressure alert bps", self.pressure_alert_bps)?;
        require_positive(
            "withdrawal forecast blocks",
            self.withdrawal_forecast_blocks,
        )?;
        require_positive("attestation ttl blocks", self.attestation_ttl_blocks)?;
        require_positive("subsidy ttl blocks", self.subsidy_ttl_blocks)?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeOraclePublisher {
    pub publisher_id: String,
    pub label: String,
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub fallback_public_key_root: String,
    pub weight_bps: u64,
    pub max_lag_blocks: u64,
    pub registered_at_height: u64,
    pub active: bool,
    pub metadata_root: String,
}

impl MoneroFeeOraclePublisher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        operator_label: &str,
        pq_public_key_root: &str,
        fallback_public_key_root: &str,
        weight_bps: u64,
        max_lag_blocks: u64,
        registered_at_height: u64,
        metadata: &Value,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("publisher label", label)?;
        require_non_empty("publisher operator label", operator_label)?;
        require_non_empty("publisher pq public key root", pq_public_key_root)?;
        require_non_empty(
            "publisher fallback public key root",
            fallback_public_key_root,
        )?;
        require_bps("publisher weight bps", weight_bps)?;
        if weight_bps < MONERO_FEE_ORACLE_STABILITY_MIN_WEIGHT_BPS {
            return Err("publisher weight bps must be positive".to_string());
        }
        require_positive("publisher max lag blocks", max_lag_blocks)?;
        let operator_commitment = monero_fee_oracle_stability_string_root(
            "MONERO-FEE-PUBLISHER-OPERATOR",
            operator_label,
        );
        let metadata_root =
            monero_fee_oracle_stability_payload_root("MONERO-FEE-PUBLISHER-METADATA", metadata);
        let publisher_id = monero_fee_publisher_id(
            label,
            &operator_commitment,
            pq_public_key_root,
            fallback_public_key_root,
            weight_bps,
        );
        Ok(Self {
            publisher_id,
            label: label.to_string(),
            operator_commitment,
            pq_public_key_root: pq_public_key_root.to_string(),
            fallback_public_key_root: fallback_public_key_root.to_string(),
            weight_bps,
            max_lag_blocks,
            registered_at_height,
            active: true,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_oracle_publisher",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "publisher_id": self.publisher_id,
            "label": self.label,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "fallback_public_key_root": self.fallback_public_key_root,
            "pq_signature_scheme": MONERO_FEE_ORACLE_STABILITY_PQ_SCHEME,
            "fallback_pq_signature_scheme": MONERO_FEE_ORACLE_STABILITY_FALLBACK_PQ_SCHEME,
            "weight_bps": self.weight_bps,
            "max_lag_blocks": self.max_lag_blocks,
            "registered_at_height": self.registered_at_height,
            "active": self.active,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn publisher_root(&self) -> String {
        monero_fee_oracle_stability_payload_root("MONERO-FEE-PUBLISHER", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("publisher id", &self.publisher_id)?;
        require_non_empty("publisher label", &self.label)?;
        require_non_empty("publisher operator commitment", &self.operator_commitment)?;
        require_non_empty("publisher pq public key root", &self.pq_public_key_root)?;
        require_non_empty(
            "publisher fallback public key root",
            &self.fallback_public_key_root,
        )?;
        require_bps("publisher weight bps", self.weight_bps)?;
        require_positive("publisher max lag blocks", self.max_lag_blocks)?;
        let expected = monero_fee_publisher_id(
            &self.label,
            &self.operator_commitment,
            &self.pq_public_key_root,
            &self.fallback_public_key_root,
            self.weight_bps,
        );
        if self.publisher_id != expected {
            return Err("monero fee publisher id mismatch".to_string());
        }
        Ok(self.publisher_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeObservation {
    pub observation_id: String,
    pub publisher_id: String,
    pub kind: MoneroFeeObservationKind,
    pub monero_height: u64,
    pub l2_height: u64,
    pub fee_per_kb_atomic: u64,
    pub priority_fee_atomic: u64,
    pub tx_count: u64,
    pub bytes_in_mempool: u64,
    pub median_wait_blocks: u64,
    pub pressure_bps: u64,
    pub sample_root: String,
    pub endpoint_root: String,
    pub status: String,
}

impl MoneroFeeObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher_id: &str,
        kind: MoneroFeeObservationKind,
        monero_height: u64,
        l2_height: u64,
        fee_per_kb_atomic: u64,
        priority_fee_atomic: u64,
        tx_count: u64,
        bytes_in_mempool: u64,
        median_wait_blocks: u64,
        endpoint_label: &str,
        sample: &Value,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("fee observation publisher id", publisher_id)?;
        require_positive("fee observation monero height", monero_height)?;
        require_positive("fee observation l2 height", l2_height)?;
        require_positive("fee per kb atomic", fee_per_kb_atomic)?;
        require_non_empty("fee observation endpoint label", endpoint_label)?;
        let sample_root =
            monero_fee_oracle_stability_payload_root("MONERO-FEE-OBSERVATION-SAMPLE", sample);
        let endpoint_root = monero_fee_oracle_stability_string_root(
            "MONERO-FEE-OBSERVATION-ENDPOINT",
            endpoint_label,
        );
        let pressure_bps =
            monero_mempool_pressure_bps(tx_count, bytes_in_mempool, median_wait_blocks);
        let observation_id = monero_fee_observation_id(
            publisher_id,
            kind,
            monero_height,
            l2_height,
            fee_per_kb_atomic,
            &sample_root,
        );
        Ok(Self {
            observation_id,
            publisher_id: publisher_id.to_string(),
            kind,
            monero_height,
            l2_height,
            fee_per_kb_atomic,
            priority_fee_atomic,
            tx_count,
            bytes_in_mempool,
            median_wait_blocks,
            pressure_bps,
            sample_root,
            endpoint_root,
            status: "observed".to_string(),
        })
    }

    pub fn effective_fee_atomic(&self) -> u64 {
        self.fee_per_kb_atomic
            .saturating_add(self.priority_fee_atomic)
    }

    pub fn pressure_kind(&self) -> MoneroMempoolPressureKind {
        pressure_kind(self.pressure_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_observation",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "publisher_id": self.publisher_id,
            "observation_kind": self.kind.as_str(),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "fee_per_kb_atomic": self.fee_per_kb_atomic,
            "priority_fee_atomic": self.priority_fee_atomic,
            "effective_fee_atomic": self.effective_fee_atomic(),
            "tx_count": self.tx_count,
            "bytes_in_mempool": self.bytes_in_mempool,
            "median_wait_blocks": self.median_wait_blocks,
            "pressure_bps": self.pressure_bps,
            "pressure_kind": self.pressure_kind().as_str(),
            "sample_root": self.sample_root,
            "endpoint_root": self.endpoint_root,
            "status": self.status,
        })
    }

    pub fn observation_root(&self) -> String {
        monero_fee_oracle_stability_payload_root("MONERO-FEE-OBSERVATION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("fee observation id", &self.observation_id)?;
        require_non_empty("fee observation publisher id", &self.publisher_id)?;
        require_positive("fee observation monero height", self.monero_height)?;
        require_positive("fee observation l2 height", self.l2_height)?;
        require_positive("fee per kb atomic", self.fee_per_kb_atomic)?;
        require_bps("fee observation pressure bps", self.pressure_bps)?;
        require_non_empty("fee observation sample root", &self.sample_root)?;
        require_non_empty("fee observation endpoint root", &self.endpoint_root)?;
        let expected = monero_fee_observation_id(
            &self.publisher_id,
            self.kind,
            self.monero_height,
            self.l2_height,
            self.fee_per_kb_atomic,
            &self.sample_root,
        );
        if self.observation_id != expected {
            return Err("monero fee observation id mismatch".to_string());
        }
        Ok(self.observation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroMempoolPressureSnapshot {
    pub pressure_id: String,
    pub height: u64,
    pub observation_root: String,
    pub publisher_root: String,
    pub sample_count: u64,
    pub active_publisher_count: u64,
    pub median_fee_per_kb_atomic: u64,
    pub p90_fee_per_kb_atomic: u64,
    pub weighted_fee_per_kb_atomic: u64,
    pub median_wait_blocks: u64,
    pub total_tx_count: u64,
    pub total_bytes_in_mempool: u64,
    pub pressure_bps: u64,
    pub pressure_kind: MoneroMempoolPressureKind,
    pub valid_until_height: u64,
}

impl MoneroMempoolPressureSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        observation_root: &str,
        publisher_root: &str,
        sample_count: u64,
        active_publisher_count: u64,
        median_fee_per_kb_atomic: u64,
        p90_fee_per_kb_atomic: u64,
        weighted_fee_per_kb_atomic: u64,
        median_wait_blocks: u64,
        total_tx_count: u64,
        total_bytes_in_mempool: u64,
        pressure_bps: u64,
        valid_until_height: u64,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_positive("mempool pressure height", height)?;
        require_non_empty("mempool pressure observation root", observation_root)?;
        require_non_empty("mempool pressure publisher root", publisher_root)?;
        require_positive("mempool pressure sample count", sample_count)?;
        require_bps("mempool pressure bps", pressure_bps)?;
        if valid_until_height < height {
            return Err("mempool pressure validity must not end before height".to_string());
        }
        let pressure_kind = pressure_kind(pressure_bps);
        let pressure_id = monero_mempool_pressure_id(
            height,
            observation_root,
            sample_count,
            weighted_fee_per_kb_atomic,
            pressure_bps,
        );
        Ok(Self {
            pressure_id,
            height,
            observation_root: observation_root.to_string(),
            publisher_root: publisher_root.to_string(),
            sample_count,
            active_publisher_count,
            median_fee_per_kb_atomic,
            p90_fee_per_kb_atomic,
            weighted_fee_per_kb_atomic,
            median_wait_blocks,
            total_tx_count,
            total_bytes_in_mempool,
            pressure_bps,
            pressure_kind,
            valid_until_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.height && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_mempool_pressure_snapshot",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "pressure_id": self.pressure_id,
            "height": self.height,
            "observation_root": self.observation_root,
            "publisher_root": self.publisher_root,
            "sample_count": self.sample_count,
            "active_publisher_count": self.active_publisher_count,
            "median_fee_per_kb_atomic": self.median_fee_per_kb_atomic,
            "p90_fee_per_kb_atomic": self.p90_fee_per_kb_atomic,
            "weighted_fee_per_kb_atomic": self.weighted_fee_per_kb_atomic,
            "median_wait_blocks": self.median_wait_blocks,
            "total_tx_count": self.total_tx_count,
            "total_bytes_in_mempool": self.total_bytes_in_mempool,
            "pressure_bps": self.pressure_bps,
            "pressure_kind": self.pressure_kind.as_str(),
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn pressure_root(&self) -> String {
        monero_fee_oracle_stability_payload_root("MONERO-MEMPOOL-PRESSURE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("mempool pressure id", &self.pressure_id)?;
        require_positive("mempool pressure height", self.height)?;
        require_non_empty("mempool pressure observation root", &self.observation_root)?;
        require_non_empty("mempool pressure publisher root", &self.publisher_root)?;
        require_positive("mempool pressure sample count", self.sample_count)?;
        require_bps("mempool pressure bps", self.pressure_bps)?;
        if self.valid_until_height < self.height {
            return Err("mempool pressure validity must not end before height".to_string());
        }
        let expected = monero_mempool_pressure_id(
            self.height,
            &self.observation_root,
            self.sample_count,
            self.weighted_fee_per_kb_atomic,
            self.pressure_bps,
        );
        if self.pressure_id != expected {
            return Err("mempool pressure id mismatch".to_string());
        }
        Ok(self.pressure_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeSmoothingWindow {
    pub window_id: String,
    pub lane: MoneroFeeLane,
    pub start_height: u64,
    pub end_height: u64,
    pub observation_root: String,
    pub pressure_root: String,
    pub sample_count: u64,
    pub smoothed_fee_per_kb_atomic: u64,
    pub smoothed_pressure_bps: u64,
    pub max_delta_bps: u64,
    pub stability_score_bps: u64,
}

impl MoneroFeeSmoothingWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: MoneroFeeLane,
        start_height: u64,
        end_height: u64,
        observation_root: &str,
        pressure_root: &str,
        sample_count: u64,
        smoothed_fee_per_kb_atomic: u64,
        smoothed_pressure_bps: u64,
        max_delta_bps: u64,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        if end_height < start_height {
            return Err("smoothing window ends before it starts".to_string());
        }
        require_non_empty("smoothing observation root", observation_root)?;
        require_non_empty("smoothing pressure root", pressure_root)?;
        require_positive("smoothing sample count", sample_count)?;
        require_positive("smoothing fee per kb", smoothed_fee_per_kb_atomic)?;
        require_bps("smoothing pressure bps", smoothed_pressure_bps)?;
        require_bps("smoothing max delta bps", max_delta_bps)?;
        let stability_score_bps = MONERO_FEE_ORACLE_STABILITY_MAX_BPS.saturating_sub(max_delta_bps);
        let window_id = monero_fee_smoothing_window_id(
            lane,
            start_height,
            end_height,
            observation_root,
            smoothed_fee_per_kb_atomic,
        );
        Ok(Self {
            window_id,
            lane,
            start_height,
            end_height,
            observation_root: observation_root.to_string(),
            pressure_root: pressure_root.to_string(),
            sample_count,
            smoothed_fee_per_kb_atomic,
            smoothed_pressure_bps,
            max_delta_bps,
            stability_score_bps,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_smoothing_window",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "observation_root": self.observation_root,
            "pressure_root": self.pressure_root,
            "sample_count": self.sample_count,
            "smoothed_fee_per_kb_atomic": self.smoothed_fee_per_kb_atomic,
            "smoothed_pressure_bps": self.smoothed_pressure_bps,
            "max_delta_bps": self.max_delta_bps,
            "stability_score_bps": self.stability_score_bps,
        })
    }

    pub fn window_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-SMOOTHING-WINDOW",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("smoothing window id", &self.window_id)?;
        if self.end_height < self.start_height {
            return Err("smoothing window ends before it starts".to_string());
        }
        require_non_empty("smoothing observation root", &self.observation_root)?;
        require_non_empty("smoothing pressure root", &self.pressure_root)?;
        require_positive("smoothing sample count", self.sample_count)?;
        require_positive("smoothing fee per kb", self.smoothed_fee_per_kb_atomic)?;
        require_bps("smoothing pressure bps", self.smoothed_pressure_bps)?;
        require_bps("smoothing max delta bps", self.max_delta_bps)?;
        let expected = monero_fee_smoothing_window_id(
            self.lane,
            self.start_height,
            self.end_height,
            &self.observation_root,
            self.smoothed_fee_per_kb_atomic,
        );
        if self.window_id != expected {
            return Err("smoothing window id mismatch".to_string());
        }
        Ok(self.window_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalFeeForecast {
    pub forecast_id: String,
    pub lane: MoneroFeeLane,
    pub pressure_id: String,
    pub window_id: String,
    pub forecast_height: u64,
    pub valid_until_height: u64,
    pub withdrawal_batch_id: String,
    pub queued_withdrawal_count: u64,
    pub estimated_vbytes: u64,
    pub base_fee_per_kb_atomic: u64,
    pub priority_fee_atomic: u64,
    pub forecast_fee_atomic: u64,
    pub max_fee_atomic: u64,
    pub confidence_bps: u64,
    pub status: MoneroFeeForecastStatus,
}

impl BridgeWithdrawalFeeForecast {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pressure_id: &str,
        window_id: &str,
        forecast_height: u64,
        valid_until_height: u64,
        withdrawal_batch_label: &str,
        queued_withdrawal_count: u64,
        estimated_vbytes: u64,
        base_fee_per_kb_atomic: u64,
        priority_fee_atomic: u64,
        pressure_bps: u64,
        confidence_bps: u64,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("forecast pressure id", pressure_id)?;
        require_non_empty("forecast window id", window_id)?;
        require_positive("forecast height", forecast_height)?;
        if valid_until_height < forecast_height {
            return Err("forecast validity must not end before forecast height".to_string());
        }
        require_non_empty("withdrawal batch label", withdrawal_batch_label)?;
        require_positive("forecast estimated vbytes", estimated_vbytes)?;
        require_positive("forecast base fee per kb", base_fee_per_kb_atomic)?;
        require_bps("forecast pressure bps", pressure_bps)?;
        require_bps("forecast confidence bps", confidence_bps)?;
        let withdrawal_batch_id = monero_fee_oracle_stability_string_root(
            "MONERO-FEE-WITHDRAWAL-BATCH",
            withdrawal_batch_label,
        );
        let pressure_surge = mul_bps(base_fee_per_kb_atomic, pressure_bps);
        let adjusted_per_kb = base_fee_per_kb_atomic.saturating_add(pressure_surge);
        let forecast_fee_atomic = adjusted_per_kb
            .saturating_mul(estimated_vbytes)
            .saturating_div(1_000)
            .saturating_add(priority_fee_atomic);
        let max_fee_atomic =
            forecast_fee_atomic.saturating_add(mul_bps(forecast_fee_atomic, 2_500));
        let forecast_id = bridge_withdrawal_fee_forecast_id(
            pressure_id,
            window_id,
            &withdrawal_batch_id,
            forecast_height,
            forecast_fee_atomic,
        );
        Ok(Self {
            forecast_id,
            lane: MoneroFeeLane::BridgeWithdrawal,
            pressure_id: pressure_id.to_string(),
            window_id: window_id.to_string(),
            forecast_height,
            valid_until_height,
            withdrawal_batch_id,
            queued_withdrawal_count,
            estimated_vbytes,
            base_fee_per_kb_atomic,
            priority_fee_atomic,
            forecast_fee_atomic,
            max_fee_atomic,
            confidence_bps,
            status: MoneroFeeForecastStatus::Active,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.can_settle()
            && height >= self.forecast_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_withdrawal_fee_forecast",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "forecast_id": self.forecast_id,
            "lane": self.lane.as_str(),
            "pressure_id": self.pressure_id,
            "window_id": self.window_id,
            "forecast_height": self.forecast_height,
            "valid_until_height": self.valid_until_height,
            "withdrawal_batch_id": self.withdrawal_batch_id,
            "queued_withdrawal_count": self.queued_withdrawal_count,
            "estimated_vbytes": self.estimated_vbytes,
            "base_fee_per_kb_atomic": self.base_fee_per_kb_atomic,
            "priority_fee_atomic": self.priority_fee_atomic,
            "forecast_fee_atomic": self.forecast_fee_atomic,
            "max_fee_atomic": self.max_fee_atomic,
            "confidence_bps": self.confidence_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn forecast_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-BRIDGE-WITHDRAWAL-FEE-FORECAST",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("bridge withdrawal forecast id", &self.forecast_id)?;
        require_non_empty("bridge withdrawal forecast pressure id", &self.pressure_id)?;
        require_non_empty("bridge withdrawal forecast window id", &self.window_id)?;
        require_non_empty(
            "bridge withdrawal forecast batch id",
            &self.withdrawal_batch_id,
        )?;
        require_positive("bridge withdrawal forecast height", self.forecast_height)?;
        if self.valid_until_height < self.forecast_height {
            return Err("forecast validity must not end before forecast height".to_string());
        }
        require_positive("bridge withdrawal forecast vbytes", self.estimated_vbytes)?;
        require_positive("bridge withdrawal forecast fee", self.forecast_fee_atomic)?;
        require_bps("bridge withdrawal forecast confidence", self.confidence_bps)?;
        if self.max_fee_atomic < self.forecast_fee_atomic {
            return Err("bridge withdrawal forecast max fee below forecast".to_string());
        }
        let expected = bridge_withdrawal_fee_forecast_id(
            &self.pressure_id,
            &self.window_id,
            &self.withdrawal_batch_id,
            self.forecast_height,
            self.forecast_fee_atomic,
        );
        if self.forecast_id != expected {
            return Err("bridge withdrawal forecast id mismatch".to_string());
        }
        Ok(self.forecast_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiLaneFeeCap {
    pub cap_id: String,
    pub lane: MoneroFeeLane,
    pub market_label: String,
    pub market_commitment: String,
    pub cap_fee_atomic: u64,
    pub target_fee_atomic: u64,
    pub max_priority_fee_atomic: u64,
    pub max_surge_bps: u64,
    pub per_epoch_tx_limit: u64,
    pub used_tx_count: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub policy_root: String,
    pub status: MoneroFeeCapStatus,
}

impl PrivateDefiLaneFeeCap {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_label: &str,
        cap_fee_atomic: u64,
        target_fee_atomic: u64,
        max_priority_fee_atomic: u64,
        max_surge_bps: u64,
        per_epoch_tx_limit: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        policy: &Value,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("private defi market label", market_label)?;
        require_positive("private defi cap fee", cap_fee_atomic)?;
        require_positive("private defi target fee", target_fee_atomic)?;
        require_bps("private defi max surge bps", max_surge_bps)?;
        require_positive("private defi per epoch tx limit", per_epoch_tx_limit)?;
        if cap_fee_atomic < target_fee_atomic {
            return Err("private defi cap must be at least target fee".to_string());
        }
        if valid_until_height <= valid_from_height {
            return Err("private defi cap expiry must follow start".to_string());
        }
        let market_commitment =
            monero_fee_oracle_stability_string_root("MONERO-FEE-DEFI-MARKET", market_label);
        let policy_root =
            monero_fee_oracle_stability_payload_root("MONERO-FEE-DEFI-CAP-POLICY", policy);
        let cap_id = private_defi_lane_fee_cap_id(
            &market_commitment,
            cap_fee_atomic,
            target_fee_atomic,
            valid_from_height,
            &policy_root,
        );
        Ok(Self {
            cap_id,
            lane: MoneroFeeLane::PrivateDefi,
            market_label: market_label.to_string(),
            market_commitment,
            cap_fee_atomic,
            target_fee_atomic,
            max_priority_fee_atomic,
            max_surge_bps,
            per_epoch_tx_limit,
            used_tx_count: 0,
            valid_from_height,
            valid_until_height,
            policy_root,
            status: MoneroFeeCapStatus::Active,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable()
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn remaining_tx_count(&self) -> u64 {
        self.per_epoch_tx_limit.saturating_sub(self.used_tx_count)
    }

    pub fn quote_fee_atomic(&self, pressure_bps: u64) -> u64 {
        let bounded_pressure = pressure_bps.min(self.max_surge_bps);
        self.target_fee_atomic
            .saturating_add(mul_bps(self.target_fee_atomic, bounded_pressure))
            .saturating_add(self.max_priority_fee_atomic)
            .min(self.cap_fee_atomic)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_defi_lane_fee_cap",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "cap_id": self.cap_id,
            "lane": self.lane.as_str(),
            "market_label": self.market_label,
            "market_commitment": self.market_commitment,
            "cap_fee_atomic": self.cap_fee_atomic,
            "target_fee_atomic": self.target_fee_atomic,
            "max_priority_fee_atomic": self.max_priority_fee_atomic,
            "max_surge_bps": self.max_surge_bps,
            "per_epoch_tx_limit": self.per_epoch_tx_limit,
            "used_tx_count": self.used_tx_count,
            "remaining_tx_count": self.remaining_tx_count(),
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "policy_root": self.policy_root,
            "status": self.status.as_str(),
        })
    }

    pub fn cap_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-PRIVATE-DEFI-LANE-FEE-CAP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("private defi cap id", &self.cap_id)?;
        require_non_empty("private defi market label", &self.market_label)?;
        require_non_empty("private defi market commitment", &self.market_commitment)?;
        require_positive("private defi cap fee", self.cap_fee_atomic)?;
        require_positive("private defi target fee", self.target_fee_atomic)?;
        require_bps("private defi max surge bps", self.max_surge_bps)?;
        require_positive("private defi per epoch tx limit", self.per_epoch_tx_limit)?;
        if self.cap_fee_atomic < self.target_fee_atomic {
            return Err("private defi cap must be at least target fee".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("private defi cap expiry must follow start".to_string());
        }
        let expected = private_defi_lane_fee_cap_id(
            &self.market_commitment,
            self.cap_fee_atomic,
            self.target_fee_atomic,
            self.valid_from_height,
            &self.policy_root,
        );
        if self.cap_id != expected {
            return Err("private defi cap id mismatch".to_string());
        }
        Ok(self.cap_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSubsidyEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub fee_asset_id: String,
    pub budget_atomic: u64,
    pub reserved_atomic: u64,
    pub spent_atomic: u64,
    pub bridge_reserved_atomic: u64,
    pub private_defi_reserved_atomic: u64,
    pub sponsor_commitment_root: String,
    pub status: MoneroFeeSubsidyStatus,
}

impl LowFeeSubsidyEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        fee_asset_id: &str,
        budget_atomic: u64,
        sponsor_label: &str,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        if end_height < start_height {
            return Err("subsidy epoch ends before it starts".to_string());
        }
        require_non_empty("subsidy fee asset id", fee_asset_id)?;
        require_positive("subsidy budget atomic", budget_atomic)?;
        require_non_empty("subsidy sponsor label", sponsor_label)?;
        let sponsor_commitment_root =
            monero_fee_oracle_stability_string_root("MONERO-FEE-SUBSIDY-SPONSOR", sponsor_label);
        let epoch_id = low_fee_subsidy_epoch_id(
            epoch_index,
            start_height,
            end_height,
            fee_asset_id,
            budget_atomic,
            &sponsor_commitment_root,
        );
        Ok(Self {
            epoch_id,
            epoch_index,
            start_height,
            end_height,
            fee_asset_id: fee_asset_id.to_string(),
            budget_atomic,
            reserved_atomic: 0,
            spent_atomic: 0,
            bridge_reserved_atomic: 0,
            private_defi_reserved_atomic: 0,
            sponsor_commitment_root,
            status: MoneroFeeSubsidyStatus::Scheduled,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.spendable() && height >= self.start_height && height <= self.end_height
    }

    pub fn available_atomic(&self) -> u64 {
        self.budget_atomic
            .saturating_sub(self.reserved_atomic)
            .saturating_sub(self.spent_atomic)
    }

    pub fn reserve(
        &mut self,
        amount_atomic: u64,
        lane: MoneroFeeLane,
    ) -> MoneroFeeOracleStabilityResult<()> {
        if amount_atomic == 0 {
            return Err("subsidy reservation amount must be positive".to_string());
        }
        if self.available_atomic() < amount_atomic {
            self.status = MoneroFeeSubsidyStatus::Exhausted;
            return Err("subsidy epoch budget exhausted".to_string());
        }
        self.reserved_atomic = self.reserved_atomic.saturating_add(amount_atomic);
        match lane {
            MoneroFeeLane::BridgeWithdrawal => {
                self.bridge_reserved_atomic =
                    self.bridge_reserved_atomic.saturating_add(amount_atomic);
            }
            MoneroFeeLane::PrivateDefi => {
                self.private_defi_reserved_atomic = self
                    .private_defi_reserved_atomic
                    .saturating_add(amount_atomic);
            }
            _ => {}
        }
        if self.status == MoneroFeeSubsidyStatus::Scheduled {
            self.status = MoneroFeeSubsidyStatus::Active;
        }
        Ok(())
    }

    pub fn settle(&mut self, amount_atomic: u64) -> MoneroFeeOracleStabilityResult<()> {
        if amount_atomic == 0 {
            return Err("subsidy settlement amount must be positive".to_string());
        }
        let bounded = amount_atomic.min(self.reserved_atomic);
        self.reserved_atomic = self.reserved_atomic.saturating_sub(bounded);
        self.spent_atomic = self.spent_atomic.saturating_add(bounded);
        if self.available_atomic() == 0 {
            self.status = MoneroFeeSubsidyStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_low_fee_subsidy_epoch",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "fee_asset_id": self.fee_asset_id,
            "budget_atomic": self.budget_atomic,
            "reserved_atomic": self.reserved_atomic,
            "spent_atomic": self.spent_atomic,
            "available_atomic": self.available_atomic(),
            "bridge_reserved_atomic": self.bridge_reserved_atomic,
            "private_defi_reserved_atomic": self.private_defi_reserved_atomic,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "status": self.status.as_str(),
        })
    }

    pub fn epoch_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-LOW-FEE-SUBSIDY-EPOCH",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("subsidy epoch id", &self.epoch_id)?;
        if self.end_height < self.start_height {
            return Err("subsidy epoch ends before it starts".to_string());
        }
        require_non_empty("subsidy fee asset id", &self.fee_asset_id)?;
        require_positive("subsidy budget atomic", self.budget_atomic)?;
        require_non_empty("subsidy sponsor root", &self.sponsor_commitment_root)?;
        if self.reserved_atomic.saturating_add(self.spent_atomic) > self.budget_atomic {
            return Err("subsidy epoch accounting exceeds budget".to_string());
        }
        let expected = low_fee_subsidy_epoch_id(
            self.epoch_index,
            self.start_height,
            self.end_height,
            &self.fee_asset_id,
            self.budget_atomic,
            &self.sponsor_commitment_root,
        );
        if self.epoch_id != expected {
            return Err("subsidy epoch id mismatch".to_string());
        }
        Ok(self.epoch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOraclePublisherAttestation {
    pub attestation_id: String,
    pub publisher_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub l2_height: u64,
    pub expires_at_height: u64,
    pub pq_signature_root: String,
    pub fallback_signature_root: String,
    pub proof_root: String,
    pub status: MoneroFeeAttestationStatus,
}

impl PqOraclePublisherAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher_id: &str,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        l2_height: u64,
        expires_at_height: u64,
        pq_signature_label: &str,
        fallback_signature_label: &str,
        proof: &Value,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("attestation publisher id", publisher_id)?;
        require_non_empty("attestation subject kind", subject_kind)?;
        require_non_empty("attestation subject id", subject_id)?;
        require_non_empty("attestation subject root", subject_root)?;
        require_positive("attestation l2 height", l2_height)?;
        if expires_at_height <= l2_height {
            return Err("attestation expiry must follow l2 height".to_string());
        }
        require_non_empty("attestation pq signature label", pq_signature_label)?;
        let pq_signature_root =
            monero_fee_oracle_stability_string_root("MONERO-FEE-PQ-SIGNATURE", pq_signature_label);
        let fallback_signature_root = monero_fee_oracle_stability_string_root(
            "MONERO-FEE-FALLBACK-PQ-SIGNATURE",
            fallback_signature_label,
        );
        let proof_root = monero_fee_oracle_stability_payload_root("MONERO-FEE-PQ-PROOF", proof);
        let attestation_id = pq_oracle_publisher_attestation_id(
            publisher_id,
            subject_kind,
            subject_id,
            subject_root,
            l2_height,
            &pq_signature_root,
        );
        Ok(Self {
            attestation_id,
            publisher_id: publisher_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            l2_height,
            expires_at_height,
            pq_signature_root,
            fallback_signature_root,
            proof_root,
            status: MoneroFeeAttestationStatus::Submitted,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            MoneroFeeAttestationStatus::Submitted | MoneroFeeAttestationStatus::Counted
        ) && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_publisher_attestation",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "publisher_id": self.publisher_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "l2_height": self.l2_height,
            "expires_at_height": self.expires_at_height,
            "pq_signature_scheme": MONERO_FEE_ORACLE_STABILITY_PQ_SCHEME,
            "fallback_pq_signature_scheme": MONERO_FEE_ORACLE_STABILITY_FALLBACK_PQ_SCHEME,
            "proof_system": MONERO_FEE_ORACLE_STABILITY_PROOF_SYSTEM,
            "pq_signature_root": self.pq_signature_root,
            "fallback_signature_root": self.fallback_signature_root,
            "proof_root": self.proof_root,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_fee_oracle_stability_payload_root("MONERO-FEE-PQ-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("attestation id", &self.attestation_id)?;
        require_non_empty("attestation publisher id", &self.publisher_id)?;
        require_non_empty("attestation subject kind", &self.subject_kind)?;
        require_non_empty("attestation subject id", &self.subject_id)?;
        require_non_empty("attestation subject root", &self.subject_root)?;
        require_positive("attestation l2 height", self.l2_height)?;
        if self.expires_at_height <= self.l2_height {
            return Err("attestation expiry must follow l2 height".to_string());
        }
        require_non_empty("attestation pq signature root", &self.pq_signature_root)?;
        require_non_empty("attestation proof root", &self.proof_root)?;
        let expected = pq_oracle_publisher_attestation_id(
            &self.publisher_id,
            &self.subject_kind,
            &self.subject_id,
            &self.subject_root,
            self.l2_height,
            &self.pq_signature_root,
        );
        if self.attestation_id != expected {
            return Err("attestation id mismatch".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeManipulationAlert {
    pub alert_id: String,
    pub kind: MoneroFeeManipulationKind,
    pub severity: MoneroFeeAlertSeverity,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub observed_height: u64,
    pub measured_bps: u64,
    pub threshold_bps: u64,
    pub evidence_root: String,
    pub status: String,
}

impl MoneroFeeManipulationAlert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: MoneroFeeManipulationKind,
        severity: MoneroFeeAlertSeverity,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        observed_height: u64,
        measured_bps: u64,
        threshold_bps: u64,
        evidence: &Value,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("manipulation subject kind", subject_kind)?;
        require_non_empty("manipulation subject id", subject_id)?;
        require_non_empty("manipulation subject root", subject_root)?;
        require_positive("manipulation observed height", observed_height)?;
        require_bps("manipulation measured bps", measured_bps)?;
        require_bps("manipulation threshold bps", threshold_bps)?;
        let evidence_root =
            monero_fee_oracle_stability_payload_root("MONERO-FEE-MANIPULATION-EVIDENCE", evidence);
        let alert_id = monero_fee_manipulation_alert_id(
            kind,
            severity,
            subject_kind,
            subject_id,
            observed_height,
            &evidence_root,
        );
        Ok(Self {
            alert_id,
            kind,
            severity,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            observed_height,
            measured_bps,
            threshold_bps,
            evidence_root,
            status: "open".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_manipulation_alert",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "alert_id": self.alert_id,
            "alert_kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
            "measured_bps": self.measured_bps,
            "threshold_bps": self.threshold_bps,
            "evidence_root": self.evidence_root,
            "status": self.status,
        })
    }

    pub fn alert_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-MANIPULATION-ALERT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("manipulation alert id", &self.alert_id)?;
        require_non_empty("manipulation subject kind", &self.subject_kind)?;
        require_non_empty("manipulation subject id", &self.subject_id)?;
        require_non_empty("manipulation subject root", &self.subject_root)?;
        require_positive("manipulation observed height", self.observed_height)?;
        require_bps("manipulation measured bps", self.measured_bps)?;
        require_bps("manipulation threshold bps", self.threshold_bps)?;
        require_non_empty("manipulation evidence root", &self.evidence_root)?;
        let expected = monero_fee_manipulation_alert_id(
            self.kind,
            self.severity,
            &self.subject_kind,
            &self.subject_id,
            self.observed_height,
            &self.evidence_root,
        );
        if self.alert_id != expected {
            return Err("manipulation alert id mismatch".to_string());
        }
        Ok(self.alert_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeSettlementReceipt {
    pub receipt_id: String,
    pub lane: MoneroFeeLane,
    pub tx_reference: String,
    pub payer_commitment: String,
    pub forecast_id: String,
    pub cap_id: String,
    pub subsidy_epoch_id: String,
    pub gross_fee_atomic: u64,
    pub capped_fee_atomic: u64,
    pub subsidy_atomic: u64,
    pub settled_fee_atomic: u64,
    pub settled_at_height: u64,
    pub settlement_proof_root: String,
    pub status: MoneroFeeReceiptStatus,
}

impl MoneroFeeSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: MoneroFeeLane,
        tx_reference: &str,
        payer_label: &str,
        forecast_id: Option<&str>,
        cap_id: Option<&str>,
        subsidy_epoch_id: Option<&str>,
        gross_fee_atomic: u64,
        capped_fee_atomic: u64,
        subsidy_atomic: u64,
        settled_at_height: u64,
        settlement_proof: &Value,
    ) -> MoneroFeeOracleStabilityResult<Self> {
        require_non_empty("settlement tx reference", tx_reference)?;
        require_non_empty("settlement payer label", payer_label)?;
        require_positive("settlement gross fee", gross_fee_atomic)?;
        require_positive("settlement height", settled_at_height)?;
        if capped_fee_atomic > gross_fee_atomic {
            return Err("settlement capped fee cannot exceed gross fee".to_string());
        }
        if subsidy_atomic > capped_fee_atomic {
            return Err("settlement subsidy cannot exceed capped fee".to_string());
        }
        let payer_commitment =
            monero_fee_oracle_stability_string_root("MONERO-FEE-SETTLEMENT-PAYER", payer_label);
        let settlement_proof_root = monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-SETTLEMENT-PROOF",
            settlement_proof,
        );
        let forecast_id = optional_id(forecast_id);
        let cap_id = optional_id(cap_id);
        let subsidy_epoch_id = optional_id(subsidy_epoch_id);
        let settled_fee_atomic = capped_fee_atomic.saturating_sub(subsidy_atomic);
        let receipt_id = monero_fee_settlement_receipt_id(
            lane,
            tx_reference,
            &payer_commitment,
            &forecast_id,
            &cap_id,
            settled_at_height,
        );
        Ok(Self {
            receipt_id,
            lane,
            tx_reference: tx_reference.to_string(),
            payer_commitment,
            forecast_id,
            cap_id,
            subsidy_epoch_id,
            gross_fee_atomic,
            capped_fee_atomic,
            subsidy_atomic,
            settled_fee_atomic,
            settled_at_height,
            settlement_proof_root,
            status: MoneroFeeReceiptStatus::Settled,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_settlement_receipt",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "tx_reference": self.tx_reference,
            "payer_commitment": self.payer_commitment,
            "forecast_id": self.forecast_id,
            "cap_id": self.cap_id,
            "subsidy_epoch_id": self.subsidy_epoch_id,
            "gross_fee_atomic": self.gross_fee_atomic,
            "capped_fee_atomic": self.capped_fee_atomic,
            "subsidy_atomic": self.subsidy_atomic,
            "settled_fee_atomic": self.settled_fee_atomic,
            "settled_at_height": self.settled_at_height,
            "settlement_proof_root": self.settlement_proof_root,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        require_non_empty("settlement receipt id", &self.receipt_id)?;
        require_non_empty("settlement tx reference", &self.tx_reference)?;
        require_non_empty("settlement payer commitment", &self.payer_commitment)?;
        require_positive("settlement gross fee", self.gross_fee_atomic)?;
        require_positive("settlement height", self.settled_at_height)?;
        require_non_empty("settlement proof root", &self.settlement_proof_root)?;
        if self.capped_fee_atomic > self.gross_fee_atomic {
            return Err("settlement capped fee cannot exceed gross fee".to_string());
        }
        if self.subsidy_atomic > self.capped_fee_atomic {
            return Err("settlement subsidy cannot exceed capped fee".to_string());
        }
        if self.settled_fee_atomic != self.capped_fee_atomic.saturating_sub(self.subsidy_atomic) {
            return Err("settlement fee accounting mismatch".to_string());
        }
        let expected = monero_fee_settlement_receipt_id(
            self.lane,
            &self.tx_reference,
            &self.payer_commitment,
            &self.forecast_id,
            &self.cap_id,
            self.settled_at_height,
        );
        if self.receipt_id != expected {
            return Err("settlement receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeOracleStabilityRoots {
    pub config_root: String,
    pub publisher_root: String,
    pub observation_root: String,
    pub pressure_root: String,
    pub smoothing_root: String,
    pub withdrawal_forecast_root: String,
    pub private_defi_cap_root: String,
    pub subsidy_epoch_root: String,
    pub pq_attestation_root: String,
    pub manipulation_alert_root: String,
    pub settlement_receipt_root: String,
    pub lane_quote_root: String,
}

impl MoneroFeeOracleStabilityRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_oracle_stability_roots",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "publisher_root": self.publisher_root,
            "observation_root": self.observation_root,
            "pressure_root": self.pressure_root,
            "smoothing_root": self.smoothing_root,
            "withdrawal_forecast_root": self.withdrawal_forecast_root,
            "private_defi_cap_root": self.private_defi_cap_root,
            "subsidy_epoch_root": self.subsidy_epoch_root,
            "pq_attestation_root": self.pq_attestation_root,
            "manipulation_alert_root": self.manipulation_alert_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "lane_quote_root": self.lane_quote_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-ORACLE-STABILITY-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeOracleStabilityCounters {
    pub publisher_count: u64,
    pub active_publisher_count: u64,
    pub observation_count: u64,
    pub pressure_snapshot_count: u64,
    pub smoothing_window_count: u64,
    pub withdrawal_forecast_count: u64,
    pub active_withdrawal_forecast_count: u64,
    pub private_defi_cap_count: u64,
    pub active_private_defi_cap_count: u64,
    pub subsidy_epoch_count: u64,
    pub active_subsidy_epoch_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub manipulation_alert_count: u64,
    pub open_manipulation_alert_count: u64,
    pub settlement_receipt_count: u64,
    pub total_observed_fee_atomic: u64,
    pub total_subsidy_available_atomic: u64,
    pub total_subsidy_spent_atomic: u64,
    pub latest_pressure_bps: u64,
}

impl MoneroFeeOracleStabilityCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_oracle_stability_counters",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "publisher_count": self.publisher_count,
            "active_publisher_count": self.active_publisher_count,
            "observation_count": self.observation_count,
            "pressure_snapshot_count": self.pressure_snapshot_count,
            "smoothing_window_count": self.smoothing_window_count,
            "withdrawal_forecast_count": self.withdrawal_forecast_count,
            "active_withdrawal_forecast_count": self.active_withdrawal_forecast_count,
            "private_defi_cap_count": self.private_defi_cap_count,
            "active_private_defi_cap_count": self.active_private_defi_cap_count,
            "subsidy_epoch_count": self.subsidy_epoch_count,
            "active_subsidy_epoch_count": self.active_subsidy_epoch_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "manipulation_alert_count": self.manipulation_alert_count,
            "open_manipulation_alert_count": self.open_manipulation_alert_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "total_observed_fee_atomic": self.total_observed_fee_atomic,
            "total_subsidy_available_atomic": self.total_subsidy_available_atomic,
            "total_subsidy_spent_atomic": self.total_subsidy_spent_atomic,
            "latest_pressure_bps": self.latest_pressure_bps,
        })
    }

    pub fn counters_root(&self) -> String {
        monero_fee_oracle_stability_payload_root(
            "MONERO-FEE-ORACLE-STABILITY-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeOracleStabilityState {
    pub config: MoneroFeeOracleStabilityConfig,
    pub height: u64,
    pub publishers: BTreeMap<String, MoneroFeeOraclePublisher>,
    pub observations: BTreeMap<String, MoneroFeeObservation>,
    pub pressure_snapshots: BTreeMap<String, MoneroMempoolPressureSnapshot>,
    pub smoothing_windows: BTreeMap<String, MoneroFeeSmoothingWindow>,
    pub withdrawal_forecasts: BTreeMap<String, BridgeWithdrawalFeeForecast>,
    pub private_defi_caps: BTreeMap<String, PrivateDefiLaneFeeCap>,
    pub subsidy_epochs: BTreeMap<String, LowFeeSubsidyEpoch>,
    pub pq_attestations: BTreeMap<String, PqOraclePublisherAttestation>,
    pub manipulation_alerts: BTreeMap<String, MoneroFeeManipulationAlert>,
    pub settlement_receipts: BTreeMap<String, MoneroFeeSettlementReceipt>,
}

impl MoneroFeeOracleStabilityState {
    pub fn new(config: MoneroFeeOracleStabilityConfig) -> MoneroFeeOracleStabilityResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            publishers: BTreeMap::new(),
            observations: BTreeMap::new(),
            pressure_snapshots: BTreeMap::new(),
            smoothing_windows: BTreeMap::new(),
            withdrawal_forecasts: BTreeMap::new(),
            private_defi_caps: BTreeMap::new(),
            subsidy_epochs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            manipulation_alerts: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
        })
    }

    pub fn devnet(operator_label: &str) -> MoneroFeeOracleStabilityResult<Self> {
        let mut state = Self::new(MoneroFeeOracleStabilityConfig::devnet(operator_label))?;
        state.set_height(24)?;

        let publisher_a = state.register_publisher(
            "devnet-fee-publisher-a",
            operator_label,
            "devnet-pq-fee-key-a",
            "devnet-fallback-fee-key-a",
            5_000,
            6,
            &json!({"role": "primary", "region": "local"}),
        )?;
        let publisher_b = state.register_publisher(
            "devnet-fee-publisher-b",
            operator_label,
            "devnet-pq-fee-key-b",
            "devnet-fallback-fee-key-b",
            3_000,
            6,
            &json!({"role": "watchtower", "region": "local"}),
        )?;
        let publisher_c = state.register_publisher(
            "devnet-fee-publisher-c",
            operator_label,
            "devnet-pq-fee-key-c",
            "devnet-fallback-fee-key-c",
            2_000,
            8,
            &json!({"role": "bridge", "region": "local"}),
        )?;

        state.record_observation(
            &publisher_a.publisher_id,
            MoneroFeeObservationKind::MempoolSnapshot,
            1_000,
            22,
            1_900,
            150,
            42,
            175_000,
            2,
            "devnet-rpc-a",
            &json!({"fee_bins": [1500, 1900, 2300], "privacy": "bucketed"}),
        )?;
        state.record_observation(
            &publisher_b.publisher_id,
            MoneroFeeObservationKind::DaemonEstimate,
            1_000,
            23,
            2_100,
            125,
            46,
            182_000,
            3,
            "devnet-rpc-b",
            &json!({"estimate": "fast", "source": "daemon"}),
        )?;
        state.record_observation(
            &publisher_c.publisher_id,
            MoneroFeeObservationKind::BridgeWithdrawal,
            1_001,
            24,
            2_050,
            200,
            49,
            188_000,
            3,
            "devnet-rpc-c",
            &json!({"bridge_queue": 12, "withdrawal_batches": 2}),
        )?;

        let pressure = state.recompute_mempool_pressure()?;
        let window = state.record_smoothing_window(MoneroFeeLane::BridgeWithdrawal)?;
        let forecast = state.forecast_bridge_withdrawal_fee(
            &pressure.pressure_id,
            &window.window_id,
            "devnet-withdrawal-batch-0",
            12,
            2_450,
            pressure.weighted_fee_per_kb_atomic,
            220,
            8_500,
        )?;
        let defi_cap = state.register_private_defi_cap(
            "devnet-sealed-swap",
            8_000,
            3_500,
            400,
            2_000,
            2_000,
            &json!({"market": "sealed-swap", "cap_scope": "per-epoch"}),
        )?;
        let epoch = state.open_subsidy_epoch(
            0,
            1,
            state.config.subsidy_ttl_blocks,
            500_000,
            "devnet-low-fee-foundation",
        )?;
        state.reserve_subsidy(&epoch.epoch_id, 9_500, MoneroFeeLane::BridgeWithdrawal)?;
        state.attest_subject(
            &publisher_a.publisher_id,
            "mempool_pressure_snapshot",
            &pressure.pressure_id,
            &pressure.pressure_root(),
            "devnet-pq-signature-a-pressure",
            "devnet-fallback-signature-a-pressure",
            &json!({"quorum": "devnet", "weighted": true}),
        )?;
        state.attest_subject(
            &publisher_b.publisher_id,
            "bridge_withdrawal_fee_forecast",
            &forecast.forecast_id,
            &forecast.forecast_root(),
            "devnet-pq-signature-b-forecast",
            "devnet-fallback-signature-b-forecast",
            &json!({"quorum": "devnet", "batch": "withdrawal"}),
        )?;
        state.record_manipulation_alert(
            MoneroFeeManipulationKind::MempoolSpike,
            MoneroFeeAlertSeverity::Watch,
            "mempool_pressure_snapshot",
            &pressure.pressure_id,
            &pressure.pressure_root(),
            pressure.pressure_bps,
            state.config.pressure_alert_bps,
            &json!({"reason": "devnet pressure near watch threshold"}),
        )?;
        state.record_settlement_receipt(
            MoneroFeeLane::BridgeWithdrawal,
            "devnet-withdrawal-tx-0",
            "devnet-withdrawer-0",
            Some(&forecast.forecast_id),
            None,
            Some(&epoch.epoch_id),
            9_500,
            9_500,
            2_500,
            &json!({"settlement": "devnet", "forecast_id": forecast.forecast_id}),
        )?;
        state.record_settlement_receipt(
            MoneroFeeLane::PrivateDefi,
            "devnet-private-defi-tx-0",
            "devnet-solver-0",
            None,
            Some(&defi_cap.cap_id),
            Some(&epoch.epoch_id),
            defi_cap.quote_fee_atomic(pressure.pressure_bps),
            defi_cap.quote_fee_atomic(pressure.pressure_bps),
            800,
            &json!({"settlement": "devnet", "cap_id": defi_cap.cap_id}),
        )?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroFeeOracleStabilityResult<String> {
        self.height = height;
        for forecast in self.withdrawal_forecasts.values_mut() {
            if forecast.status.can_settle() && height > forecast.valid_until_height {
                forecast.status = MoneroFeeForecastStatus::Expired;
            }
        }
        for cap in self.private_defi_caps.values_mut() {
            if cap.status.usable() && height > cap.valid_until_height {
                cap.status = MoneroFeeCapStatus::Retired;
            }
            if cap.status.usable() && cap.remaining_tx_count() == 0 {
                cap.status = MoneroFeeCapStatus::Exhausted;
            }
        }
        for epoch in self.subsidy_epochs.values_mut() {
            if epoch.status.spendable() && height > epoch.end_height {
                epoch.status = MoneroFeeSubsidyStatus::Expired;
            } else if epoch.status == MoneroFeeSubsidyStatus::Scheduled && epoch.active_at(height) {
                epoch.status = MoneroFeeSubsidyStatus::Active;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if attestation.active_at(height) {
                continue;
            }
            if matches!(
                attestation.status,
                MoneroFeeAttestationStatus::Submitted | MoneroFeeAttestationStatus::Counted
            ) {
                attestation.status = MoneroFeeAttestationStatus::Expired;
            }
        }
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn register_publisher(
        &mut self,
        label: &str,
        operator_label: &str,
        pq_public_key_root: &str,
        fallback_public_key_root: &str,
        weight_bps: u64,
        max_lag_blocks: u64,
        metadata: &Value,
    ) -> MoneroFeeOracleStabilityResult<MoneroFeeOraclePublisher> {
        let publisher = MoneroFeeOraclePublisher::new(
            label,
            operator_label,
            pq_public_key_root,
            fallback_public_key_root,
            weight_bps,
            max_lag_blocks,
            self.height,
            metadata,
        )?;
        publisher.validate()?;
        self.publishers
            .insert(publisher.publisher_id.clone(), publisher.clone());
        Ok(publisher)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_observation(
        &mut self,
        publisher_id: &str,
        kind: MoneroFeeObservationKind,
        monero_height: u64,
        l2_height: u64,
        fee_per_kb_atomic: u64,
        priority_fee_atomic: u64,
        tx_count: u64,
        bytes_in_mempool: u64,
        median_wait_blocks: u64,
        endpoint_label: &str,
        sample: &Value,
    ) -> MoneroFeeOracleStabilityResult<MoneroFeeObservation> {
        let publisher = self
            .publishers
            .get(publisher_id)
            .ok_or_else(|| "unknown monero fee oracle publisher".to_string())?;
        if !publisher.active {
            return Err("monero fee oracle publisher is inactive".to_string());
        }
        let observation = MoneroFeeObservation::new(
            publisher_id,
            kind,
            monero_height,
            l2_height,
            fee_per_kb_atomic,
            priority_fee_atomic,
            tx_count,
            bytes_in_mempool,
            median_wait_blocks,
            endpoint_label,
            sample,
        )?;
        let observation_id = observation.validate()?;
        self.observations
            .insert(observation_id, observation.clone());
        prune_oldest(
            &mut self.observations,
            MONERO_FEE_ORACLE_STABILITY_MAX_HISTORY,
        );
        Ok(observation)
    }

    pub fn recompute_mempool_pressure(
        &mut self,
    ) -> MoneroFeeOracleStabilityResult<MoneroMempoolPressureSnapshot> {
        let observations = self.recent_observations(self.config.smoothing_window_blocks);
        if observations.len() < self.config.min_publisher_count as usize {
            return Err("not enough monero fee observations for pressure snapshot".to_string());
        }
        let mut fees = observations
            .iter()
            .map(|observation| observation.effective_fee_atomic())
            .collect::<Vec<_>>();
        fees.sort_unstable();
        let median_fee = percentile_sorted(&fees, 5_000);
        let p90_fee = percentile_sorted(&fees, 9_000);
        let weighted_fee = weighted_fee(&observations, &self.publishers);
        let median_wait_blocks = median_u64(
            observations
                .iter()
                .map(|observation| observation.median_wait_blocks)
                .collect(),
        );
        let total_tx_count = observations.iter().fold(0_u64, |total, observation| {
            total.saturating_add(observation.tx_count)
        });
        let total_bytes = observations.iter().fold(0_u64, |total, observation| {
            total.saturating_add(observation.bytes_in_mempool)
        });
        let pressure_bps = bounded_average(
            observations
                .iter()
                .map(|observation| observation.pressure_bps)
                .collect(),
        );
        let active_publisher_count = observations
            .iter()
            .map(|observation| observation.publisher_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let snapshot = MoneroMempoolPressureSnapshot::new(
            self.height,
            &self.observation_root(),
            &self.publisher_root(),
            observations.len() as u64,
            active_publisher_count,
            median_fee,
            p90_fee,
            weighted_fee,
            median_wait_blocks,
            total_tx_count,
            total_bytes,
            pressure_bps,
            self.height
                .saturating_add(self.config.withdrawal_forecast_blocks),
        )?;
        let pressure_id = snapshot.validate()?;
        self.pressure_snapshots
            .insert(pressure_id, snapshot.clone());
        prune_oldest(
            &mut self.pressure_snapshots,
            MONERO_FEE_ORACLE_STABILITY_MAX_HISTORY,
        );
        if pressure_bps >= self.config.pressure_alert_bps {
            self.record_manipulation_alert(
                MoneroFeeManipulationKind::MempoolSpike,
                MoneroFeeAlertSeverity::Warn,
                "mempool_pressure_snapshot",
                &snapshot.pressure_id,
                &snapshot.pressure_root(),
                pressure_bps,
                self.config.pressure_alert_bps,
                &json!({"pressure_bps": pressure_bps, "threshold": self.config.pressure_alert_bps}),
            )?;
        }
        Ok(snapshot)
    }

    pub fn record_smoothing_window(
        &mut self,
        lane: MoneroFeeLane,
    ) -> MoneroFeeOracleStabilityResult<MoneroFeeSmoothingWindow> {
        let observations = self.recent_observations(self.config.smoothing_window_blocks);
        if observations.is_empty() {
            return Err("cannot smooth monero fee oracle without observations".to_string());
        }
        let start_height = self
            .height
            .saturating_sub(self.config.smoothing_window_blocks.saturating_sub(1));
        let fees = observations
            .iter()
            .map(|observation| observation.effective_fee_atomic())
            .collect::<Vec<_>>();
        let smoothed_fee = bounded_average(fees.clone());
        let pressure = bounded_average(
            observations
                .iter()
                .map(|observation| observation.pressure_bps)
                .collect(),
        );
        let max_delta_bps = max_delta_bps(&fees, smoothed_fee);
        let window = MoneroFeeSmoothingWindow::new(
            lane,
            start_height,
            self.height,
            &self.observation_root(),
            &self.pressure_root(),
            observations.len() as u64,
            smoothed_fee,
            pressure,
            max_delta_bps,
        )?;
        let window_id = window.validate()?;
        self.smoothing_windows.insert(window_id, window.clone());
        prune_oldest(
            &mut self.smoothing_windows,
            MONERO_FEE_ORACLE_STABILITY_MAX_HISTORY,
        );
        Ok(window)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn forecast_bridge_withdrawal_fee(
        &mut self,
        pressure_id: &str,
        window_id: &str,
        withdrawal_batch_label: &str,
        queued_withdrawal_count: u64,
        estimated_vbytes: u64,
        base_fee_per_kb_atomic: u64,
        priority_fee_atomic: u64,
        confidence_bps: u64,
    ) -> MoneroFeeOracleStabilityResult<BridgeWithdrawalFeeForecast> {
        let pressure = self
            .pressure_snapshots
            .get(pressure_id)
            .ok_or_else(|| "unknown mempool pressure snapshot".to_string())?;
        if !self.smoothing_windows.contains_key(window_id) {
            return Err("unknown smoothing window".to_string());
        }
        let forecast = BridgeWithdrawalFeeForecast::new(
            pressure_id,
            window_id,
            self.height,
            self.height
                .saturating_add(self.config.withdrawal_forecast_blocks),
            withdrawal_batch_label,
            queued_withdrawal_count,
            estimated_vbytes,
            base_fee_per_kb_atomic,
            priority_fee_atomic,
            pressure.pressure_bps,
            confidence_bps,
        )?;
        let forecast_id = forecast.validate()?;
        self.withdrawal_forecasts
            .insert(forecast_id, forecast.clone());
        Ok(forecast)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_private_defi_cap(
        &mut self,
        market_label: &str,
        cap_fee_atomic: u64,
        target_fee_atomic: u64,
        max_priority_fee_atomic: u64,
        max_surge_bps: u64,
        per_epoch_tx_limit: u64,
        policy: &Value,
    ) -> MoneroFeeOracleStabilityResult<PrivateDefiLaneFeeCap> {
        let cap = PrivateDefiLaneFeeCap::new(
            market_label,
            cap_fee_atomic,
            target_fee_atomic,
            max_priority_fee_atomic,
            max_surge_bps,
            per_epoch_tx_limit,
            self.height,
            self.height.saturating_add(self.config.epoch_blocks),
            policy,
        )?;
        let cap_id = cap.validate()?;
        self.private_defi_caps.insert(cap_id, cap.clone());
        Ok(cap)
    }

    pub fn open_subsidy_epoch(
        &mut self,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        budget_atomic: u64,
        sponsor_label: &str,
    ) -> MoneroFeeOracleStabilityResult<LowFeeSubsidyEpoch> {
        let epoch = LowFeeSubsidyEpoch::new(
            epoch_index,
            start_height,
            end_height,
            &self.config.fee_asset_id,
            budget_atomic,
            sponsor_label,
        )?;
        let epoch_id = epoch.validate()?;
        self.subsidy_epochs.insert(epoch_id, epoch.clone());
        Ok(epoch)
    }

    pub fn reserve_subsidy(
        &mut self,
        epoch_id: &str,
        amount_atomic: u64,
        lane: MoneroFeeLane,
    ) -> MoneroFeeOracleStabilityResult<()> {
        let epoch = self
            .subsidy_epochs
            .get_mut(epoch_id)
            .ok_or_else(|| "unknown subsidy epoch".to_string())?;
        if !epoch.active_at(self.height) {
            return Err("subsidy epoch is not active at current height".to_string());
        }
        epoch.reserve(amount_atomic, lane)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attest_subject(
        &mut self,
        publisher_id: &str,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        pq_signature_label: &str,
        fallback_signature_label: &str,
        proof: &Value,
    ) -> MoneroFeeOracleStabilityResult<PqOraclePublisherAttestation> {
        if !self.publishers.contains_key(publisher_id) {
            return Err("unknown attestation publisher".to_string());
        }
        let mut attestation = PqOraclePublisherAttestation::new(
            publisher_id,
            subject_kind,
            subject_id,
            subject_root,
            self.height,
            self.height
                .saturating_add(self.config.attestation_ttl_blocks),
            pq_signature_label,
            fallback_signature_label,
            proof,
        )?;
        let already_counted = self.pq_attestations.values().any(|existing| {
            existing.publisher_id == publisher_id
                && existing.subject_kind == subject_kind
                && existing.subject_id == subject_id
                && existing.status == MoneroFeeAttestationStatus::Counted
        });
        attestation.status = if already_counted {
            MoneroFeeAttestationStatus::Duplicate
        } else {
            MoneroFeeAttestationStatus::Counted
        };
        let attestation_id = attestation.validate()?;
        self.pq_attestations
            .insert(attestation_id, attestation.clone());
        Ok(attestation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_manipulation_alert(
        &mut self,
        kind: MoneroFeeManipulationKind,
        severity: MoneroFeeAlertSeverity,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        measured_bps: u64,
        threshold_bps: u64,
        evidence: &Value,
    ) -> MoneroFeeOracleStabilityResult<MoneroFeeManipulationAlert> {
        let alert = MoneroFeeManipulationAlert::new(
            kind,
            severity,
            subject_kind,
            subject_id,
            subject_root,
            self.height,
            measured_bps,
            threshold_bps,
            evidence,
        )?;
        let alert_id = alert.validate()?;
        self.manipulation_alerts.insert(alert_id, alert.clone());
        Ok(alert)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_settlement_receipt(
        &mut self,
        lane: MoneroFeeLane,
        tx_reference: &str,
        payer_label: &str,
        forecast_id: Option<&str>,
        cap_id: Option<&str>,
        subsidy_epoch_id: Option<&str>,
        gross_fee_atomic: u64,
        capped_fee_atomic: u64,
        subsidy_atomic: u64,
        settlement_proof: &Value,
    ) -> MoneroFeeOracleStabilityResult<MoneroFeeSettlementReceipt> {
        if let Some(forecast_id) = forecast_id {
            let forecast = self
                .withdrawal_forecasts
                .get_mut(forecast_id)
                .ok_or_else(|| "settlement references unknown forecast".to_string())?;
            if !forecast.active_at(self.height) {
                return Err("settlement forecast is not active".to_string());
            }
            forecast.status = MoneroFeeForecastStatus::Settled;
        }
        if let Some(cap_id) = cap_id {
            let cap = self
                .private_defi_caps
                .get_mut(cap_id)
                .ok_or_else(|| "settlement references unknown private defi cap".to_string())?;
            if !cap.active_at(self.height) {
                return Err("settlement private defi cap is not active".to_string());
            }
            if capped_fee_atomic > cap.cap_fee_atomic {
                return Err("settlement exceeds private defi fee cap".to_string());
            }
            cap.used_tx_count = cap.used_tx_count.saturating_add(1);
        }
        if let Some(epoch_id) = subsidy_epoch_id {
            let epoch = self
                .subsidy_epochs
                .get_mut(epoch_id)
                .ok_or_else(|| "settlement references unknown subsidy epoch".to_string())?;
            epoch.settle(subsidy_atomic)?;
        }
        let receipt = MoneroFeeSettlementReceipt::new(
            lane,
            tx_reference,
            payer_label,
            forecast_id,
            cap_id,
            subsidy_epoch_id,
            gross_fee_atomic,
            capped_fee_atomic,
            subsidy_atomic,
            self.height,
            settlement_proof,
        )?;
        let receipt_id = receipt.validate()?;
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn recent_observations(&self, window_blocks: u64) -> Vec<&MoneroFeeObservation> {
        let start = self.height.saturating_sub(window_blocks.saturating_sub(1));
        self.observations
            .values()
            .filter(|observation| {
                observation.l2_height >= start && observation.l2_height <= self.height
            })
            .collect()
    }

    pub fn latest_pressure(&self) -> Option<&MoneroMempoolPressureSnapshot> {
        self.pressure_snapshots.values().max_by(|left, right| {
            left.height
                .cmp(&right.height)
                .then_with(|| left.pressure_id.cmp(&right.pressure_id))
        })
    }

    pub fn quote_for_lane(&self, lane: MoneroFeeLane) -> Value {
        let pressure_bps = match self.latest_pressure() {
            Some(pressure) => pressure.pressure_bps,
            None => 0,
        };
        match lane {
            MoneroFeeLane::BridgeWithdrawal => {
                let active = self
                    .withdrawal_forecasts
                    .values()
                    .filter(|forecast| forecast.active_at(self.height))
                    .max_by(|left, right| left.forecast_height.cmp(&right.forecast_height));
                match active {
                    Some(forecast) => json!({
                        "lane": lane.as_str(),
                        "fee_atomic": forecast.forecast_fee_atomic,
                        "max_fee_atomic": forecast.max_fee_atomic,
                        "pressure_bps": pressure_bps,
                        "source_id": forecast.forecast_id,
                    }),
                    None => json!({
                        "lane": lane.as_str(),
                        "fee_atomic": 0,
                        "max_fee_atomic": 0,
                        "pressure_bps": pressure_bps,
                        "source_id": "",
                    }),
                }
            }
            MoneroFeeLane::PrivateDefi => {
                let active = self
                    .private_defi_caps
                    .values()
                    .filter(|cap| cap.active_at(self.height))
                    .max_by(|left, right| left.valid_from_height.cmp(&right.valid_from_height));
                match active {
                    Some(cap) => json!({
                        "lane": lane.as_str(),
                        "fee_atomic": cap.quote_fee_atomic(pressure_bps),
                        "max_fee_atomic": cap.cap_fee_atomic,
                        "pressure_bps": pressure_bps,
                        "source_id": cap.cap_id,
                    }),
                    None => json!({
                        "lane": lane.as_str(),
                        "fee_atomic": 0,
                        "max_fee_atomic": 0,
                        "pressure_bps": pressure_bps,
                        "source_id": "",
                    }),
                }
            }
            _ => {
                let base = match self.latest_pressure() {
                    Some(pressure) => pressure.weighted_fee_per_kb_atomic,
                    None => 0,
                };
                json!({
                    "lane": lane.as_str(),
                    "fee_atomic": base.saturating_add(mul_bps(base, pressure_bps)),
                    "max_fee_atomic": base.saturating_mul(4),
                    "pressure_bps": pressure_bps,
                    "source_id": "mempool_pressure",
                })
            }
        }
    }

    pub fn lane_quote_root(&self) -> String {
        let quotes = MoneroFeeLane::all()
            .into_iter()
            .map(|lane| {
                json!({
                    "key": lane.as_str(),
                    "value": self.quote_for_lane(lane),
                })
            })
            .collect::<Vec<_>>();
        merkle_root("MONERO-FEE-LANE-QUOTES", &quotes)
    }

    pub fn publisher_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-PUBLISHERS",
            self.publishers
                .values()
                .map(|publisher| (publisher.publisher_id.clone(), publisher.public_record()))
                .collect(),
        )
    }

    pub fn observation_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-OBSERVATIONS",
            self.observations
                .values()
                .map(|observation| {
                    (
                        observation.observation_id.clone(),
                        observation.public_record(),
                    )
                })
                .collect(),
        )
    }

    pub fn pressure_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-PRESSURE",
            self.pressure_snapshots
                .values()
                .map(|pressure| (pressure.pressure_id.clone(), pressure.public_record()))
                .collect(),
        )
    }

    pub fn smoothing_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-SMOOTHING",
            self.smoothing_windows
                .values()
                .map(|window| (window.window_id.clone(), window.public_record()))
                .collect(),
        )
    }

    pub fn withdrawal_forecast_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-WITHDRAWAL-FORECASTS",
            self.withdrawal_forecasts
                .values()
                .map(|forecast| (forecast.forecast_id.clone(), forecast.public_record()))
                .collect(),
        )
    }

    pub fn private_defi_cap_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-DEFI-CAPS",
            self.private_defi_caps
                .values()
                .map(|cap| (cap.cap_id.clone(), cap.public_record()))
                .collect(),
        )
    }

    pub fn subsidy_epoch_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-SUBSIDY-EPOCHS",
            self.subsidy_epochs
                .values()
                .map(|epoch| (epoch.epoch_id.clone(), epoch.public_record()))
                .collect(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-PQ-ATTESTATIONS",
            self.pq_attestations
                .values()
                .map(|attestation| {
                    (
                        attestation.attestation_id.clone(),
                        attestation.public_record(),
                    )
                })
                .collect(),
        )
    }

    pub fn manipulation_alert_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-MANIPULATION-ALERTS",
            self.manipulation_alerts
                .values()
                .map(|alert| (alert.alert_id.clone(), alert.public_record()))
                .collect(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        keyed_value_root(
            "MONERO-FEE-SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
                .collect(),
        )
    }

    pub fn roots(&self) -> MoneroFeeOracleStabilityRoots {
        MoneroFeeOracleStabilityRoots {
            config_root: self.config.config_root(),
            publisher_root: self.publisher_root(),
            observation_root: self.observation_root(),
            pressure_root: self.pressure_root(),
            smoothing_root: self.smoothing_root(),
            withdrawal_forecast_root: self.withdrawal_forecast_root(),
            private_defi_cap_root: self.private_defi_cap_root(),
            subsidy_epoch_root: self.subsidy_epoch_root(),
            pq_attestation_root: self.pq_attestation_root(),
            manipulation_alert_root: self.manipulation_alert_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            lane_quote_root: self.lane_quote_root(),
        }
    }

    pub fn counters(&self) -> MoneroFeeOracleStabilityCounters {
        let latest_pressure_bps = match self.latest_pressure() {
            Some(pressure) => pressure.pressure_bps,
            None => 0,
        };
        MoneroFeeOracleStabilityCounters {
            publisher_count: self.publishers.len() as u64,
            active_publisher_count: self
                .publishers
                .values()
                .filter(|publisher| publisher.active)
                .count() as u64,
            observation_count: self.observations.len() as u64,
            pressure_snapshot_count: self.pressure_snapshots.len() as u64,
            smoothing_window_count: self.smoothing_windows.len() as u64,
            withdrawal_forecast_count: self.withdrawal_forecasts.len() as u64,
            active_withdrawal_forecast_count: self
                .withdrawal_forecasts
                .values()
                .filter(|forecast| forecast.active_at(self.height))
                .count() as u64,
            private_defi_cap_count: self.private_defi_caps.len() as u64,
            active_private_defi_cap_count: self
                .private_defi_caps
                .values()
                .filter(|cap| cap.active_at(self.height))
                .count() as u64,
            subsidy_epoch_count: self.subsidy_epochs.len() as u64,
            active_subsidy_epoch_count: self
                .subsidy_epochs
                .values()
                .filter(|epoch| epoch.active_at(self.height))
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.active_at(self.height))
                .count() as u64,
            manipulation_alert_count: self.manipulation_alerts.len() as u64,
            open_manipulation_alert_count: self
                .manipulation_alerts
                .values()
                .filter(|alert| alert.status == "open")
                .count() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            total_observed_fee_atomic: self
                .observations
                .values()
                .fold(0_u64, |total, observation| {
                    total.saturating_add(observation.effective_fee_atomic())
                }),
            total_subsidy_available_atomic: self
                .subsidy_epochs
                .values()
                .fold(0_u64, |total, epoch| {
                    total.saturating_add(epoch.available_atomic())
                }),
            total_subsidy_spent_atomic: self.subsidy_epochs.values().fold(0_u64, |total, epoch| {
                total.saturating_add(epoch.spent_atomic)
            }),
            latest_pressure_bps,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_fee_oracle_stability_state",
            "protocol_version": MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "sample_quotes": {
                "bridge_withdrawal": self.quote_for_lane(MoneroFeeLane::BridgeWithdrawal),
                "private_defi": self.quote_for_lane(MoneroFeeLane::PrivateDefi),
                "proof_submission": self.quote_for_lane(MoneroFeeLane::ProofSubmission),
            },
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "monero_fee_oracle_stability_state_root",
            self.state_root(),
        )
    }

    pub fn state_root(&self) -> String {
        monero_fee_oracle_stability_state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> MoneroFeeOracleStabilityResult<String> {
        self.config.validate()?;
        let publisher_ids = self
            .publishers
            .values()
            .map(MoneroFeeOraclePublisher::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&publisher_ids, "publisher id")?;
        let publisher_set = publisher_ids.iter().cloned().collect::<BTreeSet<_>>();
        let observation_ids = self
            .observations
            .values()
            .map(MoneroFeeObservation::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&observation_ids, "observation id")?;
        for observation in self.observations.values() {
            if !publisher_set.contains(&observation.publisher_id) {
                return Err("fee observation references unknown publisher".to_string());
            }
        }
        let pressure_ids = self
            .pressure_snapshots
            .values()
            .map(MoneroMempoolPressureSnapshot::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&pressure_ids, "pressure snapshot id")?;
        let pressure_set = pressure_ids.iter().cloned().collect::<BTreeSet<_>>();
        let window_ids = self
            .smoothing_windows
            .values()
            .map(MoneroFeeSmoothingWindow::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&window_ids, "smoothing window id")?;
        let window_set = window_ids.iter().cloned().collect::<BTreeSet<_>>();
        let forecast_ids = self
            .withdrawal_forecasts
            .values()
            .map(BridgeWithdrawalFeeForecast::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&forecast_ids, "withdrawal forecast id")?;
        for forecast in self.withdrawal_forecasts.values() {
            if !pressure_set.contains(&forecast.pressure_id) {
                return Err("withdrawal forecast references unknown pressure".to_string());
            }
            if !window_set.contains(&forecast.window_id) {
                return Err("withdrawal forecast references unknown smoothing window".to_string());
            }
        }
        let cap_ids = self
            .private_defi_caps
            .values()
            .map(PrivateDefiLaneFeeCap::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&cap_ids, "private defi cap id")?;
        let epoch_ids = self
            .subsidy_epochs
            .values()
            .map(LowFeeSubsidyEpoch::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&epoch_ids, "subsidy epoch id")?;
        let attestation_ids = self
            .pq_attestations
            .values()
            .map(PqOraclePublisherAttestation::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&attestation_ids, "attestation id")?;
        for attestation in self.pq_attestations.values() {
            if !publisher_set.contains(&attestation.publisher_id) {
                return Err("attestation references unknown publisher".to_string());
            }
        }
        let alert_ids = self
            .manipulation_alerts
            .values()
            .map(MoneroFeeManipulationAlert::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&alert_ids, "manipulation alert id")?;
        let receipt_ids = self
            .settlement_receipts
            .values()
            .map(MoneroFeeSettlementReceipt::validate)
            .collect::<MoneroFeeOracleStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&receipt_ids, "settlement receipt id")?;
        Ok(self.state_root())
    }
}

pub fn monero_fee_oracle_stability_state_root_from_record(record: &Value) -> String {
    monero_fee_oracle_stability_payload_root("MONERO-FEE-ORACLE-STABILITY-STATE", record)
}

pub fn monero_fee_oracle_stability_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_fee_oracle_stability_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

fn monero_fee_publisher_id(
    label: &str,
    operator_commitment: &str,
    pq_public_key_root: &str,
    fallback_public_key_root: &str,
    weight_bps: u64,
) -> String {
    domain_hash(
        "MONERO-FEE-PUBLISHER-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(fallback_public_key_root),
            HashPart::Int(weight_bps as i128),
        ],
        32,
    )
}

fn monero_fee_observation_id(
    publisher_id: &str,
    kind: MoneroFeeObservationKind,
    monero_height: u64,
    l2_height: u64,
    fee_per_kb_atomic: u64,
    sample_root: &str,
) -> String {
    domain_hash(
        "MONERO-FEE-OBSERVATION-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(publisher_id),
            HashPart::Str(kind.as_str()),
            HashPart::Int(monero_height as i128),
            HashPart::Int(l2_height as i128),
            HashPart::Int(fee_per_kb_atomic as i128),
            HashPart::Str(sample_root),
        ],
        32,
    )
}

fn monero_mempool_pressure_id(
    height: u64,
    observation_root: &str,
    sample_count: u64,
    weighted_fee_per_kb_atomic: u64,
    pressure_bps: u64,
) -> String {
    domain_hash(
        "MONERO-MEMPOOL-PRESSURE-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(observation_root),
            HashPart::Int(sample_count as i128),
            HashPart::Int(weighted_fee_per_kb_atomic as i128),
            HashPart::Int(pressure_bps as i128),
        ],
        32,
    )
}

fn monero_fee_smoothing_window_id(
    lane: MoneroFeeLane,
    start_height: u64,
    end_height: u64,
    observation_root: &str,
    smoothed_fee_per_kb_atomic: u64,
) -> String {
    domain_hash(
        "MONERO-FEE-SMOOTHING-WINDOW-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(observation_root),
            HashPart::Int(smoothed_fee_per_kb_atomic as i128),
        ],
        32,
    )
}

fn bridge_withdrawal_fee_forecast_id(
    pressure_id: &str,
    window_id: &str,
    withdrawal_batch_id: &str,
    forecast_height: u64,
    forecast_fee_atomic: u64,
) -> String {
    domain_hash(
        "MONERO-BRIDGE-WITHDRAWAL-FEE-FORECAST-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pressure_id),
            HashPart::Str(window_id),
            HashPart::Str(withdrawal_batch_id),
            HashPart::Int(forecast_height as i128),
            HashPart::Int(forecast_fee_atomic as i128),
        ],
        32,
    )
}

fn private_defi_lane_fee_cap_id(
    market_commitment: &str,
    cap_fee_atomic: u64,
    target_fee_atomic: u64,
    valid_from_height: u64,
    policy_root: &str,
) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEFI-LANE-FEE-CAP-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_commitment),
            HashPart::Int(cap_fee_atomic as i128),
            HashPart::Int(target_fee_atomic as i128),
            HashPart::Int(valid_from_height as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

fn low_fee_subsidy_epoch_id(
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    fee_asset_id: &str,
    budget_atomic: u64,
    sponsor_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-LOW-FEE-SUBSIDY-EPOCH-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(fee_asset_id),
            HashPart::Int(budget_atomic as i128),
            HashPart::Str(sponsor_commitment_root),
        ],
        32,
    )
}

fn pq_oracle_publisher_attestation_id(
    publisher_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    l2_height: u64,
    pq_signature_root: &str,
) -> String {
    domain_hash(
        "MONERO-FEE-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(publisher_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(l2_height as i128),
            HashPart::Str(pq_signature_root),
        ],
        32,
    )
}

fn monero_fee_manipulation_alert_id(
    kind: MoneroFeeManipulationKind,
    severity: MoneroFeeAlertSeverity,
    subject_kind: &str,
    subject_id: &str,
    observed_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-FEE-MANIPULATION-ALERT-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Int(observed_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn monero_fee_settlement_receipt_id(
    lane: MoneroFeeLane,
    tx_reference: &str,
    payer_commitment: &str,
    forecast_id: &str,
    cap_id: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-FEE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(MONERO_FEE_ORACLE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(tx_reference),
            HashPart::Str(payer_commitment),
            HashPart::Str(forecast_id),
            HashPart::Str(cap_id),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

fn keyed_value_root(domain: &str, entries: Vec<(String, Value)>) -> String {
    let leaves = entries
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(ref mut object) = record {
        object.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(label: &str, value: &str) -> MoneroFeeOracleStabilityResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "monero fee oracle stability {label} cannot be empty"
        ));
    }
    Ok(())
}

fn require_positive(label: &str, value: u64) -> MoneroFeeOracleStabilityResult<()> {
    if value == 0 {
        return Err(format!(
            "monero fee oracle stability {label} must be positive"
        ));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> MoneroFeeOracleStabilityResult<()> {
    if value > MONERO_FEE_ORACLE_STABILITY_MAX_BPS {
        return Err(format!(
            "monero fee oracle stability {label} exceeds 10000 bps"
        ));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> MoneroFeeOracleStabilityResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("duplicate monero fee oracle stability {label}"));
        }
    }
    Ok(())
}

fn optional_id(value: Option<&str>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn monero_mempool_pressure_bps(
    tx_count: u64,
    bytes_in_mempool: u64,
    median_wait_blocks: u64,
) -> u64 {
    let tx_pressure = tx_count.saturating_mul(100).min(4_000);
    let byte_pressure = bytes_in_mempool.saturating_div(64).min(3_000);
    let wait_pressure = median_wait_blocks.saturating_mul(600).min(3_000);
    tx_pressure
        .saturating_add(byte_pressure)
        .saturating_add(wait_pressure)
        .min(MONERO_FEE_ORACLE_STABILITY_MAX_BPS)
}

fn pressure_kind(pressure_bps: u64) -> MoneroMempoolPressureKind {
    if pressure_bps >= 9_000 {
        MoneroMempoolPressureKind::Spike
    } else if pressure_bps >= 7_000 {
        MoneroMempoolPressureKind::Congested
    } else if pressure_bps >= 3_500 {
        MoneroMempoolPressureKind::Elevated
    } else {
        MoneroMempoolPressureKind::Calm
    }
}

fn mul_bps(value: u64, bps: u64) -> u64 {
    value
        .saturating_mul(bps.min(MONERO_FEE_ORACLE_STABILITY_MAX_BPS))
        .saturating_div(MONERO_FEE_ORACLE_STABILITY_MAX_BPS)
}

fn bounded_average(values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let total = values
        .iter()
        .fold(0_u64, |sum, value| sum.saturating_add(*value));
    total.saturating_div(values.len() as u64)
}

fn median_u64(mut values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let index = values.len().saturating_sub(1) / 2;
    values[index]
}

fn percentile_sorted(values: &[u64], percentile_bps: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let bounded = percentile_bps.min(MONERO_FEE_ORACLE_STABILITY_MAX_BPS);
    let last = values.len().saturating_sub(1) as u64;
    let index = last
        .saturating_mul(bounded)
        .saturating_add(MONERO_FEE_ORACLE_STABILITY_MAX_BPS - 1)
        .saturating_div(MONERO_FEE_ORACLE_STABILITY_MAX_BPS) as usize;
    values[index]
}

fn weighted_fee(
    observations: &[&MoneroFeeObservation],
    publishers: &BTreeMap<String, MoneroFeeOraclePublisher>,
) -> u64 {
    let mut weighted_sum = 0_u64;
    let mut total_weight = 0_u64;
    for observation in observations {
        let weight = match publishers.get(&observation.publisher_id) {
            Some(publisher) => publisher.weight_bps,
            None => 1,
        };
        weighted_sum =
            weighted_sum.saturating_add(observation.effective_fee_atomic().saturating_mul(weight));
        total_weight = total_weight.saturating_add(weight);
    }
    if total_weight == 0 {
        return bounded_average(
            observations
                .iter()
                .map(|observation| observation.effective_fee_atomic())
                .collect(),
        );
    }
    weighted_sum.saturating_div(total_weight)
}

fn max_delta_bps(values: &[u64], baseline: u64) -> u64 {
    if values.is_empty() || baseline == 0 {
        return 0;
    }
    values
        .iter()
        .map(|value| {
            let delta = if *value >= baseline {
                value.saturating_sub(baseline)
            } else {
                baseline.saturating_sub(*value)
            };
            delta
                .saturating_mul(MONERO_FEE_ORACLE_STABILITY_MAX_BPS)
                .saturating_div(baseline)
                .min(MONERO_FEE_ORACLE_STABILITY_MAX_BPS)
        })
        .max()
        .map_or(0, |value| value)
}

fn prune_oldest<T>(items: &mut BTreeMap<String, T>, max_len: usize) {
    while items.len() > max_len {
        let key = match items.keys().next().cloned() {
            Some(key) => key,
            None => return,
        };
        items.remove(&key);
    }
}
