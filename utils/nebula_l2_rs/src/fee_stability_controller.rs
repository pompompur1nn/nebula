use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FeeStabilityResult<T> = Result<T, String>;

pub const FEE_STABILITY_PROTOCOL_VERSION: &str = "nebula-fee-stability-v1";
pub const FEE_STABILITY_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const FEE_STABILITY_DEFAULT_CONTROL_WINDOW_BLOCKS: u64 = 12;
pub const FEE_STABILITY_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 2_000;
pub const FEE_STABILITY_DEFAULT_MAX_SURGE_BPS: u64 = 2_500;
pub const FEE_STABILITY_DEFAULT_MIN_REBATE_BPS: u64 = 6_000;
pub const FEE_STABILITY_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 720;
pub const FEE_STABILITY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeStabilityLane {
    MoneroBridge,
    PrivateTransfer,
    PrivateDefi,
    ProofSubmission,
    WalletRecovery,
    EmergencyExit,
    Maintenance,
}

impl FeeStabilityLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::ProofSubmission => "proof_submission",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
            Self::Maintenance => "maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeStabilityMode {
    Target,
    Subsidized,
    Congested,
    Protected,
    Paused,
}

impl FeeStabilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Subsidized => "subsidized",
            Self::Congested => "congested",
            Self::Protected => "protected",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionSignalKind {
    QueueDepth,
    Latency,
    ProofBacklog,
    BridgeBacklog,
    DaPressure,
    SponsorDrawdown,
}

impl CongestionSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueueDepth => "queue_depth",
            Self::Latency => "latency",
            Self::ProofBacklog => "proof_backlog",
            Self::BridgeBacklog => "bridge_backlog",
            Self::DaPressure => "da_pressure",
            Self::SponsorDrawdown => "sponsor_drawdown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorBudgetStatus {
    Active,
    Reserved,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSettlementStatus {
    Pending,
    Settled,
    Disputed,
    Expired,
}

impl FeeSettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStabilityConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_label: String,
    pub epoch_blocks: u64,
    pub control_window_blocks: u64,
    pub default_low_fee_target_micro_units: u64,
    pub max_surge_bps: u64,
    pub min_rebate_bps: u64,
    pub sponsor_ttl_blocks: u64,
}

impl FeeStabilityConfig {
    pub fn devnet(operator_label: impl Into<String>) -> Self {
        Self {
            protocol_version: FEE_STABILITY_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_label: operator_label.into(),
            epoch_blocks: FEE_STABILITY_DEFAULT_EPOCH_BLOCKS,
            control_window_blocks: FEE_STABILITY_DEFAULT_CONTROL_WINDOW_BLOCKS,
            default_low_fee_target_micro_units: FEE_STABILITY_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            max_surge_bps: FEE_STABILITY_DEFAULT_MAX_SURGE_BPS,
            min_rebate_bps: FEE_STABILITY_DEFAULT_MIN_REBATE_BPS,
            sponsor_ttl_blocks: FEE_STABILITY_DEFAULT_SPONSOR_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_stability_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "epoch_blocks": self.epoch_blocks,
            "control_window_blocks": self.control_window_blocks,
            "default_low_fee_target_micro_units": self.default_low_fee_target_micro_units,
            "max_surge_bps": self.max_surge_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        fee_stability_payload_root("FEE-STABILITY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> FeeStabilityResult<String> {
        if self.protocol_version != FEE_STABILITY_PROTOCOL_VERSION {
            return Err("fee stability protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("fee stability chain id mismatch".to_string());
        }
        require_non_empty("operator label", &self.operator_label)?;
        require_positive("epoch blocks", self.epoch_blocks)?;
        require_positive("control window blocks", self.control_window_blocks)?;
        require_positive(
            "default low fee target",
            self.default_low_fee_target_micro_units,
        )?;
        require_bps("max surge bps", self.max_surge_bps)?;
        require_bps("min rebate bps", self.min_rebate_bps)?;
        require_positive("sponsor ttl blocks", self.sponsor_ttl_blocks)?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeLaneTarget {
    pub target_id: String,
    pub lane: FeeStabilityLane,
    pub mode: FeeStabilityMode,
    pub target_micro_units: u64,
    pub max_micro_units: u64,
    pub rebate_bps: u64,
    pub priority_weight: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl FeeLaneTarget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: FeeStabilityLane,
        mode: FeeStabilityMode,
        target_micro_units: u64,
        max_micro_units: u64,
        rebate_bps: u64,
        priority_weight: u64,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> FeeStabilityResult<Self> {
        require_positive("target fee", target_micro_units)?;
        if max_micro_units < target_micro_units {
            return Err("max fee must be at least target fee".to_string());
        }
        require_bps("rebate bps", rebate_bps)?;
        require_positive("priority weight", priority_weight)?;
        if valid_until_height <= valid_from_height {
            return Err("fee target expiry must follow start".to_string());
        }
        let target_id = fee_stability_lane_target_id(
            lane,
            mode,
            target_micro_units,
            max_micro_units,
            valid_from_height,
        );
        Ok(Self {
            target_id,
            lane,
            mode,
            target_micro_units,
            max_micro_units,
            rebate_bps,
            priority_weight,
            valid_from_height,
            valid_until_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height < self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_lane_target",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "target_id": self.target_id,
            "lane": self.lane.as_str(),
            "mode": self.mode.as_str(),
            "target_micro_units": self.target_micro_units,
            "max_micro_units": self.max_micro_units,
            "rebate_bps": self.rebate_bps,
            "priority_weight": self.priority_weight,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn validate(&self) -> FeeStabilityResult<String> {
        require_non_empty("target id", &self.target_id)?;
        require_positive("target fee", self.target_micro_units)?;
        if self.max_micro_units < self.target_micro_units {
            return Err("max fee must be at least target fee".to_string());
        }
        require_bps("rebate bps", self.rebate_bps)?;
        require_positive("priority weight", self.priority_weight)?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("fee target expiry must follow start".to_string());
        }
        let expected = fee_stability_lane_target_id(
            self.lane,
            self.mode,
            self.target_micro_units,
            self.max_micro_units,
            self.valid_from_height,
        );
        if self.target_id != expected {
            return Err("fee lane target id mismatch".to_string());
        }
        Ok(self.target_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CongestionSignal {
    pub signal_id: String,
    pub lane: FeeStabilityLane,
    pub signal_kind: CongestionSignalKind,
    pub observed_value: u64,
    pub threshold_value: u64,
    pub pressure_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub evidence_root: String,
}

impl CongestionSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: FeeStabilityLane,
        signal_kind: CongestionSignalKind,
        observed_value: u64,
        threshold_value: u64,
        pressure_bps: u64,
        observed_at_height: u64,
        expires_at_height: u64,
        evidence: &Value,
    ) -> FeeStabilityResult<Self> {
        require_positive("signal threshold", threshold_value)?;
        require_bps("pressure bps", pressure_bps)?;
        if expires_at_height <= observed_at_height {
            return Err("signal expiry must follow observation".to_string());
        }
        let evidence_root = fee_stability_payload_root("FEE-STABILITY-SIGNAL-EVIDENCE", evidence);
        let signal_id = fee_stability_congestion_signal_id(
            lane,
            signal_kind,
            observed_value,
            threshold_value,
            observed_at_height,
        );
        Ok(Self {
            signal_id,
            lane,
            signal_kind,
            observed_value,
            threshold_value,
            pressure_bps,
            observed_at_height,
            expires_at_height,
            evidence_root,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "congestion_signal",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "signal_id": self.signal_id,
            "lane": self.lane.as_str(),
            "signal_kind": self.signal_kind.as_str(),
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "pressure_bps": self.pressure_bps,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn validate(&self) -> FeeStabilityResult<String> {
        require_non_empty("signal id", &self.signal_id)?;
        require_positive("signal threshold", self.threshold_value)?;
        require_bps("pressure bps", self.pressure_bps)?;
        require_non_empty("signal evidence root", &self.evidence_root)?;
        if self.expires_at_height <= self.observed_at_height {
            return Err("signal expiry must follow observation".to_string());
        }
        let expected = fee_stability_congestion_signal_id(
            self.lane,
            self.signal_kind,
            self.observed_value,
            self.threshold_value,
            self.observed_at_height,
        );
        if self.signal_id != expected {
            return Err("congestion signal id mismatch".to_string());
        }
        Ok(self.signal_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorBudget {
    pub budget_id: String,
    pub sponsor_label: String,
    pub lane: FeeStabilityLane,
    pub available_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorBudgetStatus,
}

impl SponsorBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        lane: FeeStabilityLane,
        available_units: u64,
        max_rebate_bps: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        status: SponsorBudgetStatus,
    ) -> FeeStabilityResult<Self> {
        require_non_empty("sponsor label", sponsor_label)?;
        require_positive("available units", available_units)?;
        require_bps("max rebate bps", max_rebate_bps)?;
        if expires_at_height <= opened_at_height {
            return Err("budget expiry must follow open height".to_string());
        }
        let budget_id =
            fee_stability_sponsor_budget_id(sponsor_label, lane, available_units, opened_at_height);
        Ok(Self {
            budget_id,
            sponsor_label: sponsor_label.to_string(),
            lane,
            available_units,
            reserved_units: 0,
            spent_units: 0,
            max_rebate_bps,
            opened_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.spendable() && height < self.expires_at_height && self.available_units > 0
    }

    pub fn reserve(&mut self, units: u64) -> FeeStabilityResult<()> {
        require_positive("reserve units", units)?;
        if units > self.available_units {
            return Err("insufficient sponsor budget".to_string());
        }
        self.available_units = self.available_units.saturating_sub(units);
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.status = SponsorBudgetStatus::Reserved;
        Ok(())
    }

    pub fn settle_reserved(&mut self, units: u64) -> FeeStabilityResult<()> {
        require_positive("settle units", units)?;
        if units > self.reserved_units {
            return Err("settle units exceed reserved budget".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units == 0 && self.reserved_units == 0 {
            self.status = SponsorBudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_budget",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "sponsor_label": self.sponsor_label,
            "lane": self.lane.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "max_rebate_bps": self.max_rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> FeeStabilityResult<String> {
        require_non_empty("budget id", &self.budget_id)?;
        require_non_empty("sponsor label", &self.sponsor_label)?;
        require_bps("max rebate bps", self.max_rebate_bps)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("budget expiry must follow open height".to_string());
        }
        let expected = fee_stability_sponsor_budget_id(
            &self.sponsor_label,
            self.lane,
            self.available_units
                .saturating_add(self.reserved_units)
                .saturating_add(self.spent_units),
            self.opened_at_height,
        );
        if self.budget_id != expected {
            return Err("sponsor budget id mismatch".to_string());
        }
        Ok(self.budget_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateSettlement {
    pub settlement_id: String,
    pub budget_id: String,
    pub lane: FeeStabilityLane,
    pub gross_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub rebate_units: u64,
    pub recipient_commitment: String,
    pub settled_at_height: u64,
    pub status: FeeSettlementStatus,
}

impl RebateSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        budget_id: &str,
        lane: FeeStabilityLane,
        gross_fee_micro_units: u64,
        target_fee_micro_units: u64,
        rebate_units: u64,
        recipient_commitment: &str,
        settled_at_height: u64,
        status: FeeSettlementStatus,
    ) -> FeeStabilityResult<Self> {
        require_non_empty("rebate budget id", budget_id)?;
        require_positive("gross fee", gross_fee_micro_units)?;
        require_positive("target fee", target_fee_micro_units)?;
        require_non_empty("recipient commitment", recipient_commitment)?;
        if rebate_units > gross_fee_micro_units {
            return Err("rebate cannot exceed gross fee".to_string());
        }
        let settlement_id = fee_stability_rebate_settlement_id(
            budget_id,
            lane,
            gross_fee_micro_units,
            target_fee_micro_units,
            recipient_commitment,
            settled_at_height,
        );
        Ok(Self {
            settlement_id,
            budget_id: budget_id.to_string(),
            lane,
            gross_fee_micro_units,
            target_fee_micro_units,
            rebate_units,
            recipient_commitment: recipient_commitment.to_string(),
            settled_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_settlement",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "settlement_id": self.settlement_id,
            "budget_id": self.budget_id,
            "lane": self.lane.as_str(),
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "target_fee_micro_units": self.target_fee_micro_units,
            "rebate_units": self.rebate_units,
            "recipient_commitment": self.recipient_commitment,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> FeeStabilityResult<String> {
        require_non_empty("settlement id", &self.settlement_id)?;
        require_non_empty("budget id", &self.budget_id)?;
        require_positive("gross fee", self.gross_fee_micro_units)?;
        require_positive("target fee", self.target_fee_micro_units)?;
        require_non_empty("recipient commitment", &self.recipient_commitment)?;
        if self.rebate_units > self.gross_fee_micro_units {
            return Err("rebate cannot exceed gross fee".to_string());
        }
        let expected = fee_stability_rebate_settlement_id(
            &self.budget_id,
            self.lane,
            self.gross_fee_micro_units,
            self.target_fee_micro_units,
            &self.recipient_commitment,
            self.settled_at_height,
        );
        if self.settlement_id != expected {
            return Err("rebate settlement id mismatch".to_string());
        }
        Ok(self.settlement_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStabilityRoots {
    pub config_root: String,
    pub target_root: String,
    pub signal_root: String,
    pub budget_root: String,
    pub settlement_root: String,
    pub lane_quote_root: String,
}

impl FeeStabilityRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_stability_roots",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "target_root": self.target_root,
            "signal_root": self.signal_root,
            "budget_root": self.budget_root,
            "settlement_root": self.settlement_root,
            "lane_quote_root": self.lane_quote_root,
        })
    }

    pub fn roots_root(&self) -> String {
        fee_stability_payload_root("FEE-STABILITY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStabilityCounters {
    pub target_count: u64,
    pub active_target_count: u64,
    pub signal_count: u64,
    pub active_signal_count: u64,
    pub sponsor_budget_count: u64,
    pub active_sponsor_budget_count: u64,
    pub settlement_count: u64,
    pub total_available_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub aggregate_pressure_bps: u64,
}

impl FeeStabilityCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_stability_counters",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "target_count": self.target_count,
            "active_target_count": self.active_target_count,
            "signal_count": self.signal_count,
            "active_signal_count": self.active_signal_count,
            "sponsor_budget_count": self.sponsor_budget_count,
            "active_sponsor_budget_count": self.active_sponsor_budget_count,
            "settlement_count": self.settlement_count,
            "total_available_units": self.total_available_units,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "aggregate_pressure_bps": self.aggregate_pressure_bps,
        })
    }

    pub fn counters_root(&self) -> String {
        fee_stability_payload_root("FEE-STABILITY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStabilityControllerState {
    pub config: FeeStabilityConfig,
    pub height: u64,
    pub targets: BTreeMap<String, FeeLaneTarget>,
    pub signals: BTreeMap<String, CongestionSignal>,
    pub sponsor_budgets: BTreeMap<String, SponsorBudget>,
    pub settlements: BTreeMap<String, RebateSettlement>,
}

impl FeeStabilityControllerState {
    pub fn devnet(operator_label: &str) -> FeeStabilityResult<Self> {
        let config = FeeStabilityConfig::devnet(operator_label);
        let height = 1;
        let mut state = Self {
            config,
            height,
            targets: BTreeMap::new(),
            signals: BTreeMap::new(),
            sponsor_budgets: BTreeMap::new(),
            settlements: BTreeMap::new(),
        };
        for (lane, weight, target) in [
            (FeeStabilityLane::MoneroBridge, 40_u64, 1_500_u64),
            (FeeStabilityLane::PrivateTransfer, 30_u64, 1_200_u64),
            (FeeStabilityLane::PrivateDefi, 25_u64, 2_000_u64),
            (FeeStabilityLane::ProofSubmission, 20_u64, 2_500_u64),
            (FeeStabilityLane::WalletRecovery, 50_u64, 800_u64),
            (FeeStabilityLane::EmergencyExit, 100_u64, 500_u64),
        ] {
            state.insert_target(FeeLaneTarget::new(
                lane,
                FeeStabilityMode::Subsidized,
                target,
                target.saturating_mul(3),
                state.config.min_rebate_bps,
                weight,
                height,
                height.saturating_add(state.config.epoch_blocks),
            )?)?;
        }
        state.insert_signal(CongestionSignal::new(
            FeeStabilityLane::PrivateDefi,
            CongestionSignalKind::QueueDepth,
            74,
            100,
            2_800,
            height,
            height.saturating_add(state.config.control_window_blocks),
            &json!({"queue": "private-defi", "samples": [68, 74, 71]}),
        )?)?;
        state.insert_signal(CongestionSignal::new(
            FeeStabilityLane::ProofSubmission,
            CongestionSignalKind::ProofBacklog,
            18,
            32,
            3_250,
            height,
            height.saturating_add(state.config.control_window_blocks),
            &json!({"proof_backlog": 18, "recursive_batches": 4}),
        )?)?;
        let mut bridge_budget = SponsorBudget::new(
            "devnet-low-fee-foundation",
            FeeStabilityLane::MoneroBridge,
            1_500_000,
            state.config.min_rebate_bps,
            height,
            height.saturating_add(state.config.sponsor_ttl_blocks),
            SponsorBudgetStatus::Active,
        )?;
        bridge_budget.reserve(25_000)?;
        let budget_id = bridge_budget.budget_id.clone();
        state.insert_budget(bridge_budget)?;
        state.insert_budget(SponsorBudget::new(
            "devnet-wallet-recovery-sponsor",
            FeeStabilityLane::WalletRecovery,
            750_000,
            9_000,
            height,
            height.saturating_add(state.config.sponsor_ttl_blocks),
            SponsorBudgetStatus::Active,
        )?)?;
        state.insert_settlement(RebateSettlement::new(
            &budget_id,
            FeeStabilityLane::MoneroBridge,
            9_000,
            1_500,
            7_500,
            &fee_stability_string_root("FEE-STABILITY-DEVNET-RECIPIENT", "bridge-user-0"),
            height,
            FeeSettlementStatus::Settled,
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_target(&mut self, target: FeeLaneTarget) -> FeeStabilityResult<String> {
        let target_id = target.validate()?;
        self.targets.insert(target_id.clone(), target);
        Ok(target_id)
    }

    pub fn insert_signal(&mut self, signal: CongestionSignal) -> FeeStabilityResult<String> {
        let signal_id = signal.validate()?;
        self.signals.insert(signal_id.clone(), signal);
        Ok(signal_id)
    }

    pub fn insert_budget(&mut self, budget: SponsorBudget) -> FeeStabilityResult<String> {
        let budget_id = budget.validate()?;
        self.sponsor_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_settlement(
        &mut self,
        settlement: RebateSettlement,
    ) -> FeeStabilityResult<String> {
        let settlement_id = settlement.validate()?;
        if !self.sponsor_budgets.contains_key(&settlement.budget_id) {
            return Err("rebate settlement references missing budget".to_string());
        }
        self.settlements.insert(settlement_id.clone(), settlement);
        Ok(settlement_id)
    }

    pub fn set_height(&mut self, height: u64) -> FeeStabilityResult<String> {
        self.height = height;
        for budget in self.sponsor_budgets.values_mut() {
            if budget.status.spendable() && height >= budget.expires_at_height {
                budget.status = SponsorBudgetStatus::Expired;
            }
        }
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn active_targets(&self) -> Vec<&FeeLaneTarget> {
        self.targets
            .values()
            .filter(|target| target.active_at(self.height))
            .collect()
    }

    pub fn active_signals(&self) -> Vec<&CongestionSignal> {
        self.signals
            .values()
            .filter(|signal| signal.active_at(self.height))
            .collect()
    }

    pub fn quote_for_lane(&self, lane: FeeStabilityLane) -> Value {
        let active_targets = self.active_targets();
        let target = active_targets
            .iter()
            .find(|target| target.lane == lane)
            .copied();
        let pressure_bps = self
            .active_signals()
            .into_iter()
            .filter(|signal| signal.lane == lane)
            .map(|signal| signal.pressure_bps)
            .max()
            .unwrap_or(0);
        let target_micro_units = target
            .map(|target| target.target_micro_units)
            .unwrap_or(self.config.default_low_fee_target_micro_units);
        let max_micro_units = target
            .map(|target| target.max_micro_units)
            .unwrap_or(target_micro_units.saturating_mul(4));
        let surge_micro_units = target_micro_units
            .saturating_mul(pressure_bps.min(self.config.max_surge_bps))
            .saturating_div(FEE_STABILITY_MAX_BPS);
        let quoted_micro_units = target_micro_units
            .saturating_add(surge_micro_units)
            .min(max_micro_units);
        json!({
            "lane": lane.as_str(),
            "target_micro_units": target_micro_units,
            "quoted_micro_units": quoted_micro_units,
            "max_micro_units": max_micro_units,
            "pressure_bps": pressure_bps,
            "rebate_bps": target.map(|target| target.rebate_bps).unwrap_or(0),
        })
    }

    pub fn lane_quote_root(&self) -> String {
        let quotes = [
            FeeStabilityLane::MoneroBridge,
            FeeStabilityLane::PrivateTransfer,
            FeeStabilityLane::PrivateDefi,
            FeeStabilityLane::ProofSubmission,
            FeeStabilityLane::WalletRecovery,
            FeeStabilityLane::EmergencyExit,
            FeeStabilityLane::Maintenance,
        ]
        .into_iter()
        .map(|lane| json!({"key": lane.as_str(), "value": self.quote_for_lane(lane)}))
        .collect::<Vec<_>>();
        merkle_root("FEE-STABILITY-LANE-QUOTES", &quotes)
    }

    pub fn aggregate_pressure_bps(&self) -> u64 {
        let signals = self.active_signals();
        if signals.is_empty() {
            return 0;
        }
        signals
            .iter()
            .map(|signal| signal.pressure_bps)
            .sum::<u64>()
            / signals.len() as u64
    }

    pub fn roots(&self) -> FeeStabilityRoots {
        FeeStabilityRoots {
            config_root: self.config.config_root(),
            target_root: keyed_value_root(
                "FEE-STABILITY-TARGETS",
                self.targets
                    .values()
                    .map(|target| (target.target_id.clone(), target.public_record()))
                    .collect(),
            ),
            signal_root: keyed_value_root(
                "FEE-STABILITY-SIGNALS",
                self.signals
                    .values()
                    .map(|signal| (signal.signal_id.clone(), signal.public_record()))
                    .collect(),
            ),
            budget_root: keyed_value_root(
                "FEE-STABILITY-BUDGETS",
                self.sponsor_budgets
                    .values()
                    .map(|budget| (budget.budget_id.clone(), budget.public_record()))
                    .collect(),
            ),
            settlement_root: keyed_value_root(
                "FEE-STABILITY-SETTLEMENTS",
                self.settlements
                    .values()
                    .map(|settlement| {
                        (settlement.settlement_id.clone(), settlement.public_record())
                    })
                    .collect(),
            ),
            lane_quote_root: self.lane_quote_root(),
        }
    }

    pub fn counters(&self) -> FeeStabilityCounters {
        FeeStabilityCounters {
            target_count: self.targets.len() as u64,
            active_target_count: self.active_targets().len() as u64,
            signal_count: self.signals.len() as u64,
            active_signal_count: self.active_signals().len() as u64,
            sponsor_budget_count: self.sponsor_budgets.len() as u64,
            active_sponsor_budget_count: self
                .sponsor_budgets
                .values()
                .filter(|budget| budget.active_at(self.height))
                .count() as u64,
            settlement_count: self.settlements.len() as u64,
            total_available_units: self
                .sponsor_budgets
                .values()
                .map(|budget| budget.available_units)
                .sum(),
            total_reserved_units: self
                .sponsor_budgets
                .values()
                .map(|budget| budget.reserved_units)
                .sum(),
            total_spent_units: self
                .sponsor_budgets
                .values()
                .map(|budget| budget.spent_units)
                .sum(),
            aggregate_pressure_bps: self.aggregate_pressure_bps(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "fee_stability_controller_state",
            "protocol_version": FEE_STABILITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "sample_quotes": {
                "monero_bridge": self.quote_for_lane(FeeStabilityLane::MoneroBridge),
                "private_defi": self.quote_for_lane(FeeStabilityLane::PrivateDefi),
                "wallet_recovery": self.quote_for_lane(FeeStabilityLane::WalletRecovery),
            },
        })
    }

    pub fn state_root(&self) -> String {
        fee_stability_controller_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "fee_stability_controller_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> FeeStabilityResult<String> {
        self.config.validate()?;
        let target_ids = self
            .targets
            .values()
            .map(FeeLaneTarget::validate)
            .collect::<FeeStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&target_ids, "target id")?;
        let signal_ids = self
            .signals
            .values()
            .map(CongestionSignal::validate)
            .collect::<FeeStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&signal_ids, "signal id")?;
        let budget_ids = self
            .sponsor_budgets
            .values()
            .map(SponsorBudget::validate)
            .collect::<FeeStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&budget_ids, "budget id")?;
        let budget_set = budget_ids.iter().cloned().collect::<BTreeSet<_>>();
        let settlement_ids = self
            .settlements
            .values()
            .map(RebateSettlement::validate)
            .collect::<FeeStabilityResult<Vec<_>>>()?;
        ensure_unique_strings(&settlement_ids, "settlement id")?;
        for settlement in self.settlements.values() {
            if !budget_set.contains(&settlement.budget_id) {
                return Err("rebate settlement references missing budget".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn fee_stability_controller_state_root_from_record(record: &Value) -> String {
    fee_stability_payload_root("FEE-STABILITY-STATE", record)
}

pub fn fee_stability_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(FEE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn fee_stability_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(FEE_STABILITY_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn fee_stability_lane_target_id(
    lane: FeeStabilityLane,
    mode: FeeStabilityMode,
    target_micro_units: u64,
    max_micro_units: u64,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "FEE-STABILITY-LANE-TARGET-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(mode.as_str()),
            HashPart::Int(target_micro_units as i128),
            HashPart::Int(max_micro_units as i128),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn fee_stability_congestion_signal_id(
    lane: FeeStabilityLane,
    signal_kind: CongestionSignalKind,
    observed_value: u64,
    threshold_value: u64,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "FEE-STABILITY-CONGESTION-SIGNAL-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(signal_kind.as_str()),
            HashPart::Int(observed_value as i128),
            HashPart::Int(threshold_value as i128),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn fee_stability_sponsor_budget_id(
    sponsor_label: &str,
    lane: FeeStabilityLane,
    original_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "FEE-STABILITY-SPONSOR-BUDGET-ID",
        &[
            HashPart::Str(sponsor_label),
            HashPart::Str(lane.as_str()),
            HashPart::Int(original_units as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn fee_stability_rebate_settlement_id(
    budget_id: &str,
    lane: FeeStabilityLane,
    gross_fee_micro_units: u64,
    target_fee_micro_units: u64,
    recipient_commitment: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "FEE-STABILITY-REBATE-SETTLEMENT-ID",
        &[
            HashPart::Str(budget_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(gross_fee_micro_units as i128),
            HashPart::Int(target_fee_micro_units as i128),
            HashPart::Str(recipient_commitment),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(label: &str, value: &str) -> FeeStabilityResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> FeeStabilityResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> FeeStabilityResult<()> {
    if value > FEE_STABILITY_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> FeeStabilityResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
