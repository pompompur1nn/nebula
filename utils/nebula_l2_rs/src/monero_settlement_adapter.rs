use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroSettlementAdapterResult<T> = Result<T, String>;

pub const MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION: &str = "nebula-monero-settlement-adapter-v1";
pub const MONERO_SETTLEMENT_ADAPTER_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_SETTLEMENT_ADAPTER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_SETTLEMENT_ADAPTER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_L2_FINALITY_DEPTH: u64 = 12;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_REORG_HOLD_BLOCKS: u64 = 36;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_BATCH_TTL_BLOCKS: u64 = 144;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_RELEASE_TTL_BLOCKS: u64 = 96;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_FEE_BUMP_TTL_BLOCKS: u64 = 48;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 192;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_MAX_BATCH_WITHDRAWALS: u64 = 256;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_PQ_APPROVAL_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_SETTLEMENT_ADAPTER_DEFAULT_MAX_FEE_BUMP_MULTIPLIER_BPS: u64 = 30_000;
pub const MONERO_SETTLEMENT_ADAPTER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    Standard,
    LowFee,
    PrivateExit,
    LiquidityProvider,
    Emergency,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::PrivateExit => "private_exit",
            Self::LiquidityProvider => "liquidity_provider",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 0,
            Self::PrivateExit => 1,
            Self::LowFee => 2,
            Self::LiquidityProvider => 3,
            Self::Standard => 4,
        }
    }

    pub fn sponsor_eligible(self) -> bool {
        matches!(self, Self::LowFee | Self::PrivateExit | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Draft,
    Anchored,
    Approved,
    Submitted,
    Confirming,
    Settled,
    ReorgHold,
    Reorged,
    Failed,
    Expired,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Anchored => "anchored",
            Self::Approved => "approved",
            Self::Submitted => "submitted",
            Self::Confirming => "confirming",
            Self::Settled => "settled",
            Self::ReorgHold => "reorg_hold",
            Self::Reorged => "reorged",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::Anchored
                | Self::Approved
                | Self::Submitted
                | Self::Confirming
                | Self::ReorgHold
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Reorged | Self::Failed | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorManifestStatus {
    Prepared,
    Published,
    Confirmed,
    Reorged,
    Expired,
}

impl AnchorManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Published => "published",
            Self::Confirmed => "confirmed",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Prepared | Self::Published)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    BatchCommitment,
    WithdrawalRoot,
    NullifierRoot,
    ReserveSpendRoot,
    FeePlanRoot,
    SponsorLaneRoot,
    PqApprovalRoot,
}

impl AnchorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchCommitment => "batch_commitment",
            Self::WithdrawalRoot => "withdrawal_root",
            Self::NullifierRoot => "nullifier_root",
            Self::ReserveSpendRoot => "reserve_spend_root",
            Self::FeePlanRoot => "fee_plan_root",
            Self::SponsorLaneRoot => "sponsor_lane_root",
            Self::PqApprovalRoot => "pq_approval_root",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalReleaseStatus {
    Planned,
    Authorized,
    Submitted,
    Confirming,
    Released,
    HeldForReorg,
    Cancelled,
    Expired,
}

impl WithdrawalReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Authorized => "authorized",
            Self::Submitted => "submitted",
            Self::Confirming => "confirming",
            Self::Released => "released",
            Self::HeldForReorg => "held_for_reorg",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Planned
                | Self::Authorized
                | Self::Submitted
                | Self::Confirming
                | Self::HeldForReorg
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBumpStatus {
    Planned,
    Broadcast,
    Superseded,
    Settled,
    Rejected,
    Expired,
}

impl FeeBumpStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Broadcast => "broadcast",
            Self::Superseded => "superseded",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Planned | Self::Broadcast)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonSubmissionStatus {
    Prepared,
    Submitted,
    Accepted,
    InMempool,
    Confirmed,
    Rejected,
    Reorged,
    Expired,
}

impl DaemonSubmissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::InMempool => "in_mempool",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Accepted | Self::InMempool | Self::Confirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSpendStatus {
    Requested,
    Authorized,
    Consumed,
    Revoked,
    Expired,
}

impl ReserveSpendStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Requested | Self::Authorized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayProtectionScope {
    Withdrawal,
    ReserveSpend,
    FeeBump,
    AnchorManifest,
    SponsorLane,
}

impl ReplayProtectionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Withdrawal => "withdrawal",
            Self::ReserveSpend => "reserve_spend",
            Self::FeeBump => "fee_bump",
            Self::AnchorManifest => "anchor_manifest",
            Self::SponsorLane => "sponsor_lane",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayProtectionStatus {
    Reserved,
    Consumed,
    Reorged,
    Revoked,
}

impl ReplayProtectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Reorged => "reorged",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Reserved | Self::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorLaneStatus {
    Open,
    Reserved,
    Consumed,
    Settled,
    Exhausted,
    Expired,
}

impl SponsorLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSettlementSubjectKind {
    SettlementBatch,
    AnchorManifest,
    WithdrawalRelease,
    ReserveSpend,
    FeeBump,
    SponsorLane,
}

impl PqSettlementSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementBatch => "settlement_batch",
            Self::AnchorManifest => "anchor_manifest",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::ReserveSpend => "reserve_spend",
            Self::FeeBump => "fee_bump",
            Self::SponsorLane => "sponsor_lane",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalStatus {
    Pending,
    Accepted,
    ThresholdMet,
    Rejected,
    Superseded,
    Expired,
}

impl PqApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::ThresholdMet => "threshold_met",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Accepted | Self::ThresholdMet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgSignalKind {
    BlockHashConflict,
    ConfirmationDrop,
    DaemonQuorumConflict,
    AnchorMissing,
    TxDropped,
    KeyImageReappeared,
}

impl ReorgSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockHashConflict => "block_hash_conflict",
            Self::ConfirmationDrop => "confirmation_drop",
            Self::DaemonQuorumConflict => "daemon_quorum_conflict",
            Self::AnchorMissing => "anchor_missing",
            Self::TxDropped => "tx_dropped",
            Self::KeyImageReappeared => "key_image_reappeared",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgSignalStatus {
    Open,
    Quarantined,
    Resolved,
    Expired,
}

impl ReorgSignalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quarantined => "quarantined",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Open | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAdapterEventKind {
    BatchPlanned,
    AnchorManifest,
    WithdrawalRelease,
    FeeBumpPlan,
    DaemonReceipt,
    ReserveSpendAuthorization,
    ReplayProtection,
    SponsorLane,
    PqApproval,
    ReorgSignal,
}

impl SettlementAdapterEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchPlanned => "batch_planned",
            Self::AnchorManifest => "anchor_manifest",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::FeeBumpPlan => "fee_bump_plan",
            Self::DaemonReceipt => "daemon_receipt",
            Self::ReserveSpendAuthorization => "reserve_spend_authorization",
            Self::ReplayProtection => "replay_protection",
            Self::SponsorLane => "sponsor_lane",
            Self::PqApproval => "pq_approval",
            Self::ReorgSignal => "reorg_signal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementAdapterConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub monero_finality_depth: u64,
    pub l2_finality_depth: u64,
    pub reorg_hold_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub release_ttl_blocks: u64,
    pub fee_bump_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub max_batch_withdrawals: u64,
    pub pq_approval_quorum_weight: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_rebate_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_fee_bump_multiplier_bps: u64,
    pub require_pq_approval: bool,
}

impl Default for MoneroSettlementAdapterConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION.to_string(),
            network: MONERO_SETTLEMENT_ADAPTER_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_SETTLEMENT_ADAPTER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_SETTLEMENT_ADAPTER_DEVNET_FEE_ASSET_ID.to_string(),
            monero_finality_depth: MONERO_SETTLEMENT_ADAPTER_DEFAULT_MONERO_FINALITY_DEPTH,
            l2_finality_depth: MONERO_SETTLEMENT_ADAPTER_DEFAULT_L2_FINALITY_DEPTH,
            reorg_hold_blocks: MONERO_SETTLEMENT_ADAPTER_DEFAULT_REORG_HOLD_BLOCKS,
            batch_ttl_blocks: MONERO_SETTLEMENT_ADAPTER_DEFAULT_BATCH_TTL_BLOCKS,
            release_ttl_blocks: MONERO_SETTLEMENT_ADAPTER_DEFAULT_RELEASE_TTL_BLOCKS,
            fee_bump_ttl_blocks: MONERO_SETTLEMENT_ADAPTER_DEFAULT_FEE_BUMP_TTL_BLOCKS,
            sponsorship_ttl_blocks: MONERO_SETTLEMENT_ADAPTER_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            max_batch_withdrawals: MONERO_SETTLEMENT_ADAPTER_DEFAULT_MAX_BATCH_WITHDRAWALS,
            pq_approval_quorum_weight: MONERO_SETTLEMENT_ADAPTER_DEFAULT_PQ_APPROVAL_QUORUM_WEIGHT,
            min_pq_security_bits: MONERO_SETTLEMENT_ADAPTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_rebate_bps: MONERO_SETTLEMENT_ADAPTER_DEFAULT_LOW_FEE_REBATE_BPS,
            min_reserve_coverage_bps: MONERO_SETTLEMENT_ADAPTER_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_fee_bump_multiplier_bps:
                MONERO_SETTLEMENT_ADAPTER_DEFAULT_MAX_FEE_BUMP_MULTIPLIER_BPS,
            require_pq_approval: true,
        };
        config.config_id = monero_settlement_adapter_config_id(&config.identity_record());
        config
    }
}

impl MoneroSettlementAdapterConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_adapter_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "monero_finality_depth": self.monero_finality_depth,
            "l2_finality_depth": self.l2_finality_depth,
            "reorg_hold_blocks": self.reorg_hold_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "release_ttl_blocks": self.release_ttl_blocks,
            "fee_bump_ttl_blocks": self.fee_bump_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "max_batch_withdrawals": self.max_batch_withdrawals,
            "pq_approval_quorum_weight": self.pq_approval_quorum_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_fee_bump_multiplier_bps": self.max_fee_bump_multiplier_bps,
            "require_pq_approval": self.require_pq_approval,
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            with_string_field(
                with_string_field(
                    self.identity_record(),
                    "kind",
                    "monero_settlement_adapter_config".to_string(),
                ),
                "config_id",
                self.config_id.clone(),
            ),
            "config_root",
            self.config_root(),
        )
    }

    pub fn config_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-ADAPTER-CONFIG",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.config_id, "monero settlement config id")?;
        ensure_non_empty(&self.protocol_version, "monero settlement protocol version")?;
        ensure_non_empty(&self.network, "monero settlement network")?;
        ensure_non_empty(&self.asset_id, "monero settlement asset id")?;
        ensure_non_empty(&self.fee_asset_id, "monero settlement fee asset id")?;
        if self.protocol_version != MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION {
            return Err("monero settlement protocol version mismatch".to_string());
        }
        ensure_positive(
            self.monero_finality_depth,
            "monero settlement finality depth",
        )?;
        ensure_positive(self.l2_finality_depth, "monero settlement l2 finality")?;
        ensure_positive(self.reorg_hold_blocks, "monero settlement reorg hold")?;
        ensure_positive(self.batch_ttl_blocks, "monero settlement batch ttl")?;
        ensure_positive(self.release_ttl_blocks, "monero settlement release ttl")?;
        ensure_positive(self.fee_bump_ttl_blocks, "monero settlement fee bump ttl")?;
        ensure_positive(
            self.sponsorship_ttl_blocks,
            "monero settlement sponsorship ttl",
        )?;
        ensure_positive(
            self.max_batch_withdrawals,
            "monero settlement max batch withdrawals",
        )?;
        ensure_positive(
            self.pq_approval_quorum_weight,
            "monero settlement pq quorum",
        )?;
        if self.min_pq_security_bits < 128 {
            return Err("monero settlement pq security floor is too low".to_string());
        }
        ensure_bps(self.low_fee_rebate_bps, "monero settlement low fee rebate")?;
        if self.min_reserve_coverage_bps < MONERO_SETTLEMENT_ADAPTER_MAX_BPS {
            return Err("monero settlement reserve coverage must cover liabilities".to_string());
        }
        ensure_positive(
            self.max_fee_bump_multiplier_bps,
            "monero settlement max fee bump multiplier",
        )?;
        let computed = monero_settlement_adapter_config_id(&self.identity_record());
        if self.config_id != computed {
            return Err("monero settlement config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementBatch {
    pub batch_id: String,
    pub settlement_epoch: u64,
    pub lane: SettlementLane,
    pub network: String,
    pub asset_id: String,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub planned_at_height: u64,
    pub expires_at_height: u64,
    pub monero_anchor_height: u64,
    pub monero_anchor_block_hash: String,
    pub monero_safe_height: u64,
    pub reorg_hold_until_height: u64,
    pub withdrawal_root: String,
    pub nullifier_root: String,
    pub reserve_spend_root: String,
    pub sponsor_lane_root: String,
    pub fee_plan_root: String,
    pub pq_approval_root: String,
    pub withdrawal_count: u64,
    pub total_amount_piconero: u64,
    pub target_fee_piconero: u64,
    pub min_confirmations: u64,
    pub status: SettlementBatchStatus,
}

impl MoneroSettlementBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settlement_epoch: u64,
        lane: SettlementLane,
        network: impl Into<String>,
        asset_id: impl Into<String>,
        l2_start_height: u64,
        l2_end_height: u64,
        monero_anchor_height: u64,
        monero_anchor_block_hash: impl Into<String>,
        planned_at_height: u64,
        batch_ttl_blocks: u64,
        reorg_hold_blocks: u64,
        withdrawal_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        reserve_spend_root: impl Into<String>,
        sponsor_lane_root: impl Into<String>,
        fee_plan_root: impl Into<String>,
        pq_approval_root: impl Into<String>,
        withdrawal_count: u64,
        total_amount_piconero: u64,
        target_fee_piconero: u64,
        min_confirmations: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let network = network.into();
        let asset_id = asset_id.into();
        let monero_anchor_block_hash = monero_anchor_block_hash.into();
        let withdrawal_root = withdrawal_root.into();
        let nullifier_root = nullifier_root.into();
        let reserve_spend_root = reserve_spend_root.into();
        let sponsor_lane_root = sponsor_lane_root.into();
        let fee_plan_root = fee_plan_root.into();
        let pq_approval_root = pq_approval_root.into();
        ensure_non_empty(&network, "settlement batch network")?;
        ensure_non_empty(&asset_id, "settlement batch asset id")?;
        ensure_non_empty(
            &monero_anchor_block_hash,
            "settlement batch monero anchor block hash",
        )?;
        ensure_non_empty(&withdrawal_root, "settlement batch withdrawal root")?;
        ensure_non_empty(&nullifier_root, "settlement batch nullifier root")?;
        ensure_non_empty(&reserve_spend_root, "settlement batch reserve root")?;
        ensure_non_empty(&sponsor_lane_root, "settlement batch sponsor root")?;
        ensure_non_empty(&fee_plan_root, "settlement batch fee root")?;
        ensure_non_empty(&pq_approval_root, "settlement batch pq approval root")?;
        ensure_height_range(l2_start_height, l2_end_height, "settlement batch l2 range")?;
        ensure_positive(withdrawal_count, "settlement batch withdrawal count")?;
        ensure_positive(total_amount_piconero, "settlement batch total amount")?;
        ensure_positive(target_fee_piconero, "settlement batch target fee")?;
        ensure_positive(min_confirmations, "settlement batch confirmations")?;
        ensure_positive(batch_ttl_blocks, "settlement batch ttl")?;
        ensure_positive(reorg_hold_blocks, "settlement batch reorg hold")?;
        let mut batch = Self {
            batch_id: String::new(),
            settlement_epoch,
            lane,
            network,
            asset_id,
            l2_start_height,
            l2_end_height,
            planned_at_height,
            expires_at_height: planned_at_height.saturating_add(batch_ttl_blocks),
            monero_anchor_height,
            monero_anchor_block_hash,
            monero_safe_height: monero_anchor_height.saturating_add(min_confirmations),
            reorg_hold_until_height: planned_at_height.saturating_add(reorg_hold_blocks),
            withdrawal_root,
            nullifier_root,
            reserve_spend_root,
            sponsor_lane_root,
            fee_plan_root,
            pq_approval_root,
            withdrawal_count,
            total_amount_piconero,
            target_fee_piconero,
            min_confirmations,
            status: SettlementBatchStatus::Draft,
        };
        batch.batch_id = monero_settlement_adapter_batch_id(&batch.identity_record());
        batch.validate()?;
        Ok(batch)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_batch_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "settlement_epoch": self.settlement_epoch,
            "lane": self.lane.as_str(),
            "network": self.network,
            "asset_id": self.asset_id,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "planned_at_height": self.planned_at_height,
            "monero_anchor_height": self.monero_anchor_height,
            "monero_anchor_block_hash": self.monero_anchor_block_hash,
            "withdrawal_root": self.withdrawal_root,
            "nullifier_root": self.nullifier_root,
            "withdrawal_count": self.withdrawal_count,
            "total_amount_piconero": self.total_amount_piconero,
            "target_fee_piconero": self.target_fee_piconero,
            "min_confirmations": self.min_confirmations,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "settlement_epoch": self.settlement_epoch,
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "network": self.network,
            "asset_id": self.asset_id,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "planned_at_height": self.planned_at_height,
            "expires_at_height": self.expires_at_height,
            "monero_anchor_height": self.monero_anchor_height,
            "monero_anchor_block_hash": self.monero_anchor_block_hash,
            "monero_safe_height": self.monero_safe_height,
            "reorg_hold_until_height": self.reorg_hold_until_height,
            "withdrawal_root": self.withdrawal_root,
            "nullifier_root": self.nullifier_root,
            "reserve_spend_root": self.reserve_spend_root,
            "sponsor_lane_root": self.sponsor_lane_root,
            "fee_plan_root": self.fee_plan_root,
            "pq_approval_root": self.pq_approval_root,
            "withdrawal_count": self.withdrawal_count,
            "total_amount_piconero": self.total_amount_piconero,
            "target_fee_piconero": self.target_fee_piconero,
            "min_confirmations": self.min_confirmations,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-BATCH",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "batch_root",
            self.batch_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.batch_id, "settlement batch id")?;
        ensure_non_empty(&self.network, "settlement batch network")?;
        ensure_non_empty(&self.asset_id, "settlement batch asset id")?;
        ensure_non_empty(
            &self.monero_anchor_block_hash,
            "settlement batch monero anchor block hash",
        )?;
        ensure_non_empty(&self.withdrawal_root, "settlement batch withdrawal root")?;
        ensure_non_empty(&self.nullifier_root, "settlement batch nullifier root")?;
        ensure_non_empty(
            &self.reserve_spend_root,
            "settlement batch reserve spend root",
        )?;
        ensure_non_empty(
            &self.sponsor_lane_root,
            "settlement batch sponsor lane root",
        )?;
        ensure_non_empty(&self.fee_plan_root, "settlement batch fee plan root")?;
        ensure_non_empty(&self.pq_approval_root, "settlement batch pq approval root")?;
        ensure_height_range(
            self.l2_start_height,
            self.l2_end_height,
            "settlement batch l2 range",
        )?;
        ensure_positive(self.withdrawal_count, "settlement batch withdrawal count")?;
        ensure_positive(self.total_amount_piconero, "settlement batch total amount")?;
        ensure_positive(self.target_fee_piconero, "settlement batch target fee")?;
        ensure_positive(self.min_confirmations, "settlement batch confirmations")?;
        if self.expires_at_height <= self.planned_at_height {
            return Err("settlement batch expiry must be after planning height".to_string());
        }
        if self.monero_safe_height < self.monero_anchor_height {
            return Err("settlement batch safe height precedes anchor height".to_string());
        }
        let computed = monero_settlement_adapter_batch_id(&self.identity_record());
        if self.batch_id != computed {
            return Err("settlement batch id mismatch".to_string());
        }
        Ok(self.batch_root())
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_open() {
            self.status = SettlementBatchStatus::Expired;
        }
        if self.status == SettlementBatchStatus::ReorgHold && height >= self.reorg_hold_until_height
        {
            self.status = SettlementBatchStatus::Confirming;
        }
    }

    pub fn mark_anchored(&mut self) -> MoneroSettlementAdapterResult<String> {
        if self.status != SettlementBatchStatus::Draft {
            return Err("settlement batch can only anchor from draft".to_string());
        }
        self.status = SettlementBatchStatus::Anchored;
        self.validate()
    }

    pub fn mark_approved(
        &mut self,
        approval_root: impl Into<String>,
    ) -> MoneroSettlementAdapterResult<String> {
        let approval_root = approval_root.into();
        ensure_non_empty(&approval_root, "settlement batch approval root")?;
        if !matches!(
            self.status,
            SettlementBatchStatus::Draft | SettlementBatchStatus::Anchored
        ) {
            return Err("settlement batch cannot be approved from current status".to_string());
        }
        self.pq_approval_root = approval_root;
        self.status = SettlementBatchStatus::Approved;
        self.validate()
    }

    pub fn mark_submitted(&mut self) -> MoneroSettlementAdapterResult<String> {
        if !matches!(
            self.status,
            SettlementBatchStatus::Approved | SettlementBatchStatus::Anchored
        ) {
            return Err("settlement batch cannot be submitted from current status".to_string());
        }
        self.status = SettlementBatchStatus::Submitted;
        self.validate()
    }

    pub fn hold_for_reorg(&mut self, until_height: u64) -> MoneroSettlementAdapterResult<String> {
        if self.status.is_terminal() {
            return Err("terminal settlement batch cannot enter reorg hold".to_string());
        }
        self.reorg_hold_until_height = self.reorg_hold_until_height.max(until_height);
        self.status = SettlementBatchStatus::ReorgHold;
        self.validate()
    }

    pub fn mark_settled(&mut self) -> MoneroSettlementAdapterResult<String> {
        if !matches!(
            self.status,
            SettlementBatchStatus::Submitted
                | SettlementBatchStatus::Confirming
                | SettlementBatchStatus::Approved
        ) {
            return Err("settlement batch cannot settle from current status".to_string());
        }
        self.status = SettlementBatchStatus::Settled;
        self.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAnchorManifest {
    pub manifest_id: String,
    pub batch_id: String,
    pub anchor_kind: AnchorKind,
    pub manifest_index: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub monero_block_hash: String,
    pub anchor_payload_root: String,
    pub published_at_height: u64,
    pub confirmed_at_height: Option<u64>,
    pub expires_at_height: u64,
    pub status: AnchorManifestStatus,
}

impl SettlementAnchorManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        anchor_kind: AnchorKind,
        manifest_index: u64,
        l2_height: u64,
        monero_height: u64,
        monero_block_hash: impl Into<String>,
        anchor_payload_root: impl Into<String>,
        published_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let monero_block_hash = monero_block_hash.into();
        let anchor_payload_root = anchor_payload_root.into();
        ensure_non_empty(&batch_id, "settlement manifest batch id")?;
        ensure_non_empty(&monero_block_hash, "settlement manifest block hash")?;
        ensure_non_empty(&anchor_payload_root, "settlement manifest payload root")?;
        ensure_expiry(
            published_at_height,
            expires_at_height,
            "settlement manifest",
        )?;
        let mut manifest = Self {
            manifest_id: String::new(),
            batch_id,
            anchor_kind,
            manifest_index,
            l2_height,
            monero_height,
            monero_block_hash,
            anchor_payload_root,
            published_at_height,
            confirmed_at_height: None,
            expires_at_height,
            status: AnchorManifestStatus::Prepared,
        };
        manifest.manifest_id =
            monero_settlement_adapter_anchor_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_anchor_manifest_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "anchor_kind": self.anchor_kind.as_str(),
            "manifest_index": self.manifest_index,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "monero_block_hash": self.monero_block_hash,
            "anchor_payload_root": self.anchor_payload_root,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_anchor_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "batch_id": self.batch_id,
            "anchor_kind": self.anchor_kind.as_str(),
            "manifest_index": self.manifest_index,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "monero_block_hash": self.monero_block_hash,
            "anchor_payload_root": self.anchor_payload_root,
            "published_at_height": self.published_at_height,
            "confirmed_at_height": self.confirmed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-ANCHOR-MANIFEST",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "manifest_root",
            self.manifest_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.manifest_id, "settlement manifest id")?;
        ensure_non_empty(&self.batch_id, "settlement manifest batch id")?;
        ensure_non_empty(&self.monero_block_hash, "settlement manifest block hash")?;
        ensure_non_empty(
            &self.anchor_payload_root,
            "settlement manifest payload root",
        )?;
        ensure_expiry(
            self.published_at_height,
            self.expires_at_height,
            "settlement manifest",
        )?;
        if let Some(height) = self.confirmed_at_height {
            if height < self.published_at_height {
                return Err("settlement manifest confirmation precedes publish".to_string());
            }
        }
        let computed = monero_settlement_adapter_anchor_manifest_id(&self.identity_record());
        if self.manifest_id != computed {
            return Err("settlement manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }

    pub fn publish(&mut self) -> MoneroSettlementAdapterResult<String> {
        if self.status != AnchorManifestStatus::Prepared {
            return Err("settlement manifest can only publish from prepared".to_string());
        }
        self.status = AnchorManifestStatus::Published;
        self.validate()
    }

    pub fn confirm(&mut self, height: u64) -> MoneroSettlementAdapterResult<String> {
        if !matches!(
            self.status,
            AnchorManifestStatus::Prepared | AnchorManifestStatus::Published
        ) {
            return Err("settlement manifest cannot confirm from current status".to_string());
        }
        self.confirmed_at_height = Some(height);
        self.status = AnchorManifestStatus::Confirmed;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_live() {
            self.status = AnchorManifestStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReleasePlan {
    pub release_id: String,
    pub batch_id: String,
    pub withdrawal_id: String,
    pub lane: SettlementLane,
    pub recipient_commitment: String,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub account_nullifier: String,
    pub replay_key: String,
    pub reserve_spend_authorization_id: Option<String>,
    pub sponsor_lane_id: Option<String>,
    pub release_after_l2_height: u64,
    pub expires_at_height: u64,
    pub monero_tx_template_root: String,
    pub status: WithdrawalReleaseStatus,
}

impl WithdrawalReleasePlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        withdrawal_id: impl Into<String>,
        lane: SettlementLane,
        recipient_commitment: impl Into<String>,
        amount_piconero: u64,
        fee_piconero: u64,
        account_nullifier: impl Into<String>,
        reserve_spend_authorization_id: Option<String>,
        sponsor_lane_id: Option<String>,
        release_after_l2_height: u64,
        expires_at_height: u64,
        tx_template_payload: &Value,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let withdrawal_id = withdrawal_id.into();
        let recipient_commitment = recipient_commitment.into();
        let account_nullifier = account_nullifier.into();
        ensure_non_empty(&batch_id, "withdrawal release batch id")?;
        ensure_non_empty(&withdrawal_id, "withdrawal release withdrawal id")?;
        ensure_non_empty(&recipient_commitment, "withdrawal release recipient")?;
        ensure_non_empty(&account_nullifier, "withdrawal release nullifier")?;
        ensure_positive(amount_piconero, "withdrawal release amount")?;
        ensure_positive(fee_piconero, "withdrawal release fee")?;
        ensure_expiry(
            release_after_l2_height,
            expires_at_height,
            "withdrawal release",
        )?;
        ensure_optional_non_empty(
            &reserve_spend_authorization_id,
            "withdrawal release reserve authorization",
        )?;
        ensure_optional_non_empty(&sponsor_lane_id, "withdrawal release sponsor lane")?;
        let monero_tx_template_root = monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-TX-TEMPLATE",
            tx_template_payload,
        );
        let replay_key = monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-WITHDRAWAL-REPLAY-KEY",
            &json!({
                "batch_id": batch_id,
                "withdrawal_id": withdrawal_id,
                "recipient_commitment": recipient_commitment,
                "amount_piconero": amount_piconero,
                "account_nullifier": account_nullifier,
            }),
        );
        let mut release = Self {
            release_id: String::new(),
            batch_id,
            withdrawal_id,
            lane,
            recipient_commitment,
            amount_piconero,
            fee_piconero,
            account_nullifier,
            replay_key,
            reserve_spend_authorization_id,
            sponsor_lane_id,
            release_after_l2_height,
            expires_at_height,
            monero_tx_template_root,
            status: WithdrawalReleaseStatus::Planned,
        };
        release.release_id = monero_settlement_adapter_release_id(&release.identity_record());
        release.validate()?;
        Ok(release)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_release_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "account_nullifier": self.account_nullifier,
            "replay_key": self.replay_key,
            "monero_tx_template_root": self.monero_tx_template_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_withdrawal_release_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "release_id": self.release_id,
            "batch_id": self.batch_id,
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "recipient_commitment": self.recipient_commitment,
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "account_nullifier": self.account_nullifier,
            "replay_key": self.replay_key,
            "reserve_spend_authorization_id": self.reserve_spend_authorization_id,
            "sponsor_lane_id": self.sponsor_lane_id,
            "release_after_l2_height": self.release_after_l2_height,
            "expires_at_height": self.expires_at_height,
            "monero_tx_template_root": self.monero_tx_template_root,
            "status": self.status.as_str(),
        })
    }

    pub fn release_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-WITHDRAWAL-RELEASE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "release_root",
            self.release_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.release_id, "withdrawal release id")?;
        ensure_non_empty(&self.batch_id, "withdrawal release batch id")?;
        ensure_non_empty(&self.withdrawal_id, "withdrawal release withdrawal id")?;
        ensure_non_empty(&self.recipient_commitment, "withdrawal release recipient")?;
        ensure_non_empty(&self.account_nullifier, "withdrawal release nullifier")?;
        ensure_non_empty(&self.replay_key, "withdrawal release replay key")?;
        ensure_non_empty(
            &self.monero_tx_template_root,
            "withdrawal release tx template root",
        )?;
        ensure_positive(self.amount_piconero, "withdrawal release amount")?;
        ensure_positive(self.fee_piconero, "withdrawal release fee")?;
        ensure_expiry(
            self.release_after_l2_height,
            self.expires_at_height,
            "withdrawal release",
        )?;
        ensure_optional_non_empty(
            &self.reserve_spend_authorization_id,
            "withdrawal release reserve authorization",
        )?;
        ensure_optional_non_empty(&self.sponsor_lane_id, "withdrawal release sponsor lane")?;
        let computed = monero_settlement_adapter_release_id(&self.identity_record());
        if self.release_id != computed {
            return Err("withdrawal release id mismatch".to_string());
        }
        Ok(self.release_root())
    }

    pub fn authorize(
        &mut self,
        authorization_id: impl Into<String>,
    ) -> MoneroSettlementAdapterResult<String> {
        let authorization_id = authorization_id.into();
        ensure_non_empty(&authorization_id, "withdrawal release authorization id")?;
        if self.status != WithdrawalReleaseStatus::Planned {
            return Err("withdrawal release can only authorize from planned".to_string());
        }
        self.reserve_spend_authorization_id = Some(authorization_id);
        self.status = WithdrawalReleaseStatus::Authorized;
        self.validate()
    }

    pub fn mark_submitted(&mut self) -> MoneroSettlementAdapterResult<String> {
        if !matches!(
            self.status,
            WithdrawalReleaseStatus::Planned | WithdrawalReleaseStatus::Authorized
        ) {
            return Err("withdrawal release cannot submit from current status".to_string());
        }
        self.status = WithdrawalReleaseStatus::Submitted;
        self.validate()
    }

    pub fn hold_for_reorg(&mut self) -> MoneroSettlementAdapterResult<String> {
        if !self.status.is_open() {
            return Err("withdrawal release is not open".to_string());
        }
        self.status = WithdrawalReleaseStatus::HeldForReorg;
        self.validate()
    }

    pub fn mark_released(&mut self) -> MoneroSettlementAdapterResult<String> {
        if !matches!(
            self.status,
            WithdrawalReleaseStatus::Submitted
                | WithdrawalReleaseStatus::Confirming
                | WithdrawalReleaseStatus::Authorized
        ) {
            return Err("withdrawal release cannot release from current status".to_string());
        }
        self.status = WithdrawalReleaseStatus::Released;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_open() {
            self.status = WithdrawalReleaseStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxFeeBumpPlan {
    pub fee_bump_id: String,
    pub batch_id: String,
    pub release_id: Option<String>,
    pub parent_tx_id: String,
    pub replacement_tx_id: String,
    pub fee_asset_id: String,
    pub original_fee_piconero: u64,
    pub target_fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub bump_multiplier_bps: u64,
    pub sponsor_lane_id: Option<String>,
    pub planned_at_height: u64,
    pub expires_at_height: u64,
    pub reason: String,
    pub status: FeeBumpStatus,
}

impl TxFeeBumpPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        release_id: Option<String>,
        parent_tx_id: impl Into<String>,
        replacement_tx_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        original_fee_piconero: u64,
        target_fee_piconero: u64,
        max_fee_piconero: u64,
        sponsor_lane_id: Option<String>,
        planned_at_height: u64,
        expires_at_height: u64,
        reason: impl Into<String>,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let parent_tx_id = parent_tx_id.into();
        let replacement_tx_id = replacement_tx_id.into();
        let fee_asset_id = fee_asset_id.into();
        let reason = reason.into();
        ensure_non_empty(&batch_id, "fee bump batch id")?;
        ensure_optional_non_empty(&release_id, "fee bump release id")?;
        ensure_non_empty(&parent_tx_id, "fee bump parent tx id")?;
        ensure_non_empty(&replacement_tx_id, "fee bump replacement tx id")?;
        ensure_non_empty(&fee_asset_id, "fee bump fee asset id")?;
        ensure_non_empty(&reason, "fee bump reason")?;
        ensure_positive(original_fee_piconero, "fee bump original fee")?;
        ensure_positive(target_fee_piconero, "fee bump target fee")?;
        ensure_positive(max_fee_piconero, "fee bump max fee")?;
        ensure_expiry(planned_at_height, expires_at_height, "fee bump")?;
        ensure_optional_non_empty(&sponsor_lane_id, "fee bump sponsor lane")?;
        if target_fee_piconero <= original_fee_piconero {
            return Err("fee bump target must exceed original fee".to_string());
        }
        if max_fee_piconero < target_fee_piconero {
            return Err("fee bump max fee must cover target fee".to_string());
        }
        let bump_multiplier_bps = target_fee_piconero
            .saturating_mul(MONERO_SETTLEMENT_ADAPTER_MAX_BPS)
            / original_fee_piconero;
        let mut plan = Self {
            fee_bump_id: String::new(),
            batch_id,
            release_id,
            parent_tx_id,
            replacement_tx_id,
            fee_asset_id,
            original_fee_piconero,
            target_fee_piconero,
            max_fee_piconero,
            bump_multiplier_bps,
            sponsor_lane_id,
            planned_at_height,
            expires_at_height,
            reason,
            status: FeeBumpStatus::Planned,
        };
        plan.fee_bump_id = monero_settlement_adapter_fee_bump_id(&plan.identity_record());
        plan.validate()?;
        Ok(plan)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_fee_bump_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "release_id": self.release_id,
            "parent_tx_id": self.parent_tx_id,
            "replacement_tx_id": self.replacement_tx_id,
            "fee_asset_id": self.fee_asset_id,
            "original_fee_piconero": self.original_fee_piconero,
            "target_fee_piconero": self.target_fee_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "sponsor_lane_id": self.sponsor_lane_id,
            "planned_at_height": self.planned_at_height,
            "reason": self.reason,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_tx_fee_bump_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "fee_bump_id": self.fee_bump_id,
            "batch_id": self.batch_id,
            "release_id": self.release_id,
            "parent_tx_id": self.parent_tx_id,
            "replacement_tx_id": self.replacement_tx_id,
            "fee_asset_id": self.fee_asset_id,
            "original_fee_piconero": self.original_fee_piconero,
            "target_fee_piconero": self.target_fee_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "bump_multiplier_bps": self.bump_multiplier_bps,
            "sponsor_lane_id": self.sponsor_lane_id,
            "planned_at_height": self.planned_at_height,
            "expires_at_height": self.expires_at_height,
            "reason": self.reason,
            "status": self.status.as_str(),
        })
    }

    pub fn fee_bump_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-FEE-BUMP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "fee_bump_root",
            self.fee_bump_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.fee_bump_id, "fee bump id")?;
        ensure_non_empty(&self.batch_id, "fee bump batch id")?;
        ensure_optional_non_empty(&self.release_id, "fee bump release id")?;
        ensure_non_empty(&self.parent_tx_id, "fee bump parent tx id")?;
        ensure_non_empty(&self.replacement_tx_id, "fee bump replacement tx id")?;
        ensure_non_empty(&self.fee_asset_id, "fee bump fee asset id")?;
        ensure_non_empty(&self.reason, "fee bump reason")?;
        ensure_positive(self.original_fee_piconero, "fee bump original fee")?;
        ensure_positive(self.target_fee_piconero, "fee bump target fee")?;
        ensure_positive(self.max_fee_piconero, "fee bump max fee")?;
        ensure_positive(self.bump_multiplier_bps, "fee bump multiplier")?;
        ensure_expiry(self.planned_at_height, self.expires_at_height, "fee bump")?;
        ensure_optional_non_empty(&self.sponsor_lane_id, "fee bump sponsor lane")?;
        if self.target_fee_piconero <= self.original_fee_piconero {
            return Err("fee bump target must exceed original fee".to_string());
        }
        if self.max_fee_piconero < self.target_fee_piconero {
            return Err("fee bump max fee must cover target fee".to_string());
        }
        let computed = monero_settlement_adapter_fee_bump_id(&self.identity_record());
        if self.fee_bump_id != computed {
            return Err("fee bump id mismatch".to_string());
        }
        Ok(self.fee_bump_root())
    }

    pub fn mark_broadcast(&mut self) -> MoneroSettlementAdapterResult<String> {
        if self.status != FeeBumpStatus::Planned {
            return Err("fee bump can only broadcast from planned".to_string());
        }
        self.status = FeeBumpStatus::Broadcast;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_active() {
            self.status = FeeBumpStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonSubmissionReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub request_id: String,
    pub daemon_endpoint_id: String,
    pub tx_id: String,
    pub tx_blob_root: String,
    pub submitted_at_height: u64,
    pub daemon_height: u64,
    pub accepted_fee_piconero: u64,
    pub mempool_seen: bool,
    pub confirmations: u64,
    pub rejected_reason: Option<String>,
    pub status: DaemonSubmissionStatus,
}

impl DaemonSubmissionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        request_id: impl Into<String>,
        daemon_endpoint_id: impl Into<String>,
        tx_id: impl Into<String>,
        tx_blob_payload: &Value,
        submitted_at_height: u64,
        daemon_height: u64,
        accepted_fee_piconero: u64,
        mempool_seen: bool,
        confirmations: u64,
        rejected_reason: Option<String>,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let request_id = request_id.into();
        let daemon_endpoint_id = daemon_endpoint_id.into();
        let tx_id = tx_id.into();
        ensure_non_empty(&batch_id, "daemon receipt batch id")?;
        ensure_non_empty(&request_id, "daemon receipt request id")?;
        ensure_non_empty(&daemon_endpoint_id, "daemon receipt endpoint id")?;
        ensure_non_empty(&tx_id, "daemon receipt tx id")?;
        ensure_optional_non_empty(&rejected_reason, "daemon receipt rejected reason")?;
        if rejected_reason.is_none() {
            ensure_positive(accepted_fee_piconero, "daemon receipt accepted fee")?;
        }
        let tx_blob_root =
            monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-TX-BLOB", tx_blob_payload);
        let status = if rejected_reason.is_some() {
            DaemonSubmissionStatus::Rejected
        } else if confirmations > 0 {
            DaemonSubmissionStatus::Confirmed
        } else if mempool_seen {
            DaemonSubmissionStatus::InMempool
        } else {
            DaemonSubmissionStatus::Accepted
        };
        let mut receipt = Self {
            receipt_id: String::new(),
            batch_id,
            request_id,
            daemon_endpoint_id,
            tx_id,
            tx_blob_root,
            submitted_at_height,
            daemon_height,
            accepted_fee_piconero,
            mempool_seen,
            confirmations,
            rejected_reason,
            status,
        };
        receipt.receipt_id =
            monero_settlement_adapter_daemon_receipt_id(&receipt.identity_record());
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_daemon_receipt_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "request_id": self.request_id,
            "daemon_endpoint_id": self.daemon_endpoint_id,
            "tx_id": self.tx_id,
            "tx_blob_root": self.tx_blob_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_daemon_submission_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "request_id": self.request_id,
            "daemon_endpoint_id": self.daemon_endpoint_id,
            "tx_id": self.tx_id,
            "tx_blob_root": self.tx_blob_root,
            "submitted_at_height": self.submitted_at_height,
            "daemon_height": self.daemon_height,
            "accepted_fee_piconero": self.accepted_fee_piconero,
            "mempool_seen": self.mempool_seen,
            "confirmations": self.confirmations,
            "rejected_reason": self.rejected_reason,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-DAEMON-RECEIPT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.receipt_id, "daemon receipt id")?;
        ensure_non_empty(&self.batch_id, "daemon receipt batch id")?;
        ensure_non_empty(&self.request_id, "daemon receipt request id")?;
        ensure_non_empty(&self.daemon_endpoint_id, "daemon receipt endpoint id")?;
        ensure_non_empty(&self.tx_id, "daemon receipt tx id")?;
        ensure_non_empty(&self.tx_blob_root, "daemon receipt tx blob root")?;
        ensure_optional_non_empty(&self.rejected_reason, "daemon receipt rejected reason")?;
        if self.status != DaemonSubmissionStatus::Rejected {
            ensure_positive(self.accepted_fee_piconero, "daemon receipt accepted fee")?;
        }
        if self.status == DaemonSubmissionStatus::Rejected && self.rejected_reason.is_none() {
            return Err("daemon receipt rejection requires a reason".to_string());
        }
        let computed = monero_settlement_adapter_daemon_receipt_id(&self.identity_record());
        if self.receipt_id != computed {
            return Err("daemon receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }

    pub fn observe_confirmations(
        &mut self,
        confirmations: u64,
    ) -> MoneroSettlementAdapterResult<String> {
        self.confirmations = confirmations;
        if confirmations > 0 && self.status.is_success() {
            self.status = DaemonSubmissionStatus::Confirmed;
        }
        self.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSpendAuthorization {
    pub authorization_id: String,
    pub batch_id: String,
    pub reserve_wallet_id: String,
    pub spend_policy_root: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub amount_piconero: u64,
    pub fee_budget_piconero: u64,
    pub signer_set_root: String,
    pub pq_approval_id: Option<String>,
    pub authorized_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveSpendStatus,
}

impl ReserveSpendAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        reserve_wallet_id: impl Into<String>,
        spend_policy_root: impl Into<String>,
        input_commitment_root: impl Into<String>,
        output_commitment_root: impl Into<String>,
        key_image_root: impl Into<String>,
        amount_piconero: u64,
        fee_budget_piconero: u64,
        signer_set_root: impl Into<String>,
        pq_approval_id: Option<String>,
        authorized_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let reserve_wallet_id = reserve_wallet_id.into();
        let spend_policy_root = spend_policy_root.into();
        let input_commitment_root = input_commitment_root.into();
        let output_commitment_root = output_commitment_root.into();
        let key_image_root = key_image_root.into();
        let signer_set_root = signer_set_root.into();
        ensure_non_empty(&batch_id, "reserve spend batch id")?;
        ensure_non_empty(&reserve_wallet_id, "reserve spend wallet id")?;
        ensure_non_empty(&spend_policy_root, "reserve spend policy root")?;
        ensure_non_empty(&input_commitment_root, "reserve spend input root")?;
        ensure_non_empty(&output_commitment_root, "reserve spend output root")?;
        ensure_non_empty(&key_image_root, "reserve spend key image root")?;
        ensure_non_empty(&signer_set_root, "reserve spend signer set root")?;
        ensure_optional_non_empty(&pq_approval_id, "reserve spend pq approval id")?;
        ensure_positive(amount_piconero, "reserve spend amount")?;
        ensure_positive(fee_budget_piconero, "reserve spend fee budget")?;
        ensure_expiry(
            authorized_at_height,
            expires_at_height,
            "reserve spend authorization",
        )?;
        let mut authorization = Self {
            authorization_id: String::new(),
            batch_id,
            reserve_wallet_id,
            spend_policy_root,
            input_commitment_root,
            output_commitment_root,
            key_image_root,
            amount_piconero,
            fee_budget_piconero,
            signer_set_root,
            pq_approval_id,
            authorized_at_height,
            expires_at_height,
            status: ReserveSpendStatus::Authorized,
        };
        authorization.authorization_id =
            monero_settlement_adapter_reserve_authorization_id(&authorization.identity_record());
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_reserve_spend_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "reserve_wallet_id": self.reserve_wallet_id,
            "spend_policy_root": self.spend_policy_root,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "amount_piconero": self.amount_piconero,
            "fee_budget_piconero": self.fee_budget_piconero,
            "signer_set_root": self.signer_set_root,
            "authorized_at_height": self.authorized_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_reserve_spend_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "batch_id": self.batch_id,
            "reserve_wallet_id": self.reserve_wallet_id,
            "spend_policy_root": self.spend_policy_root,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "amount_piconero": self.amount_piconero,
            "fee_budget_piconero": self.fee_budget_piconero,
            "signer_set_root": self.signer_set_root,
            "pq_approval_id": self.pq_approval_id,
            "authorized_at_height": self.authorized_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn authorization_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-RESERVE-AUTHORIZATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "authorization_root",
            self.authorization_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.authorization_id, "reserve spend authorization id")?;
        ensure_non_empty(&self.batch_id, "reserve spend batch id")?;
        ensure_non_empty(&self.reserve_wallet_id, "reserve spend wallet id")?;
        ensure_non_empty(&self.spend_policy_root, "reserve spend policy root")?;
        ensure_non_empty(&self.input_commitment_root, "reserve spend input root")?;
        ensure_non_empty(&self.output_commitment_root, "reserve spend output root")?;
        ensure_non_empty(&self.key_image_root, "reserve spend key image root")?;
        ensure_non_empty(&self.signer_set_root, "reserve spend signer set root")?;
        ensure_optional_non_empty(&self.pq_approval_id, "reserve spend pq approval id")?;
        ensure_positive(self.amount_piconero, "reserve spend amount")?;
        ensure_positive(self.fee_budget_piconero, "reserve spend fee budget")?;
        ensure_expiry(
            self.authorized_at_height,
            self.expires_at_height,
            "reserve spend authorization",
        )?;
        let computed = monero_settlement_adapter_reserve_authorization_id(&self.identity_record());
        if self.authorization_id != computed {
            return Err("reserve spend authorization id mismatch".to_string());
        }
        Ok(self.authorization_root())
    }

    pub fn consume(&mut self) -> MoneroSettlementAdapterResult<String> {
        if self.status != ReserveSpendStatus::Authorized {
            return Err("reserve spend authorization is not authorized".to_string());
        }
        self.status = ReserveSpendStatus::Consumed;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_active() {
            self.status = ReserveSpendStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayProtectionRecord {
    pub protection_id: String,
    pub scope: ReplayProtectionScope,
    pub batch_id: String,
    pub subject_id: String,
    pub nullifier: String,
    pub replay_key: String,
    pub anchor_domain: String,
    pub first_seen_height: u64,
    pub consumed_by_tx_id: Option<String>,
    pub status: ReplayProtectionStatus,
}

impl ReplayProtectionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ReplayProtectionScope,
        batch_id: impl Into<String>,
        subject_id: impl Into<String>,
        nullifier: impl Into<String>,
        replay_key: impl Into<String>,
        anchor_domain: impl Into<String>,
        first_seen_height: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let subject_id = subject_id.into();
        let nullifier = nullifier.into();
        let replay_key = replay_key.into();
        let anchor_domain = anchor_domain.into();
        ensure_non_empty(&batch_id, "replay protection batch id")?;
        ensure_non_empty(&subject_id, "replay protection subject id")?;
        ensure_non_empty(&nullifier, "replay protection nullifier")?;
        ensure_non_empty(&replay_key, "replay protection key")?;
        ensure_non_empty(&anchor_domain, "replay protection anchor domain")?;
        let mut record = Self {
            protection_id: String::new(),
            scope,
            batch_id,
            subject_id,
            nullifier,
            replay_key,
            anchor_domain,
            first_seen_height,
            consumed_by_tx_id: None,
            status: ReplayProtectionStatus::Reserved,
        };
        record.protection_id =
            monero_settlement_adapter_replay_protection_id(&record.identity_record());
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_replay_protection_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "scope": self.scope.as_str(),
            "batch_id": self.batch_id,
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "replay_key": self.replay_key,
            "anchor_domain": self.anchor_domain,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_replay_protection",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "protection_id": self.protection_id,
            "scope": self.scope.as_str(),
            "batch_id": self.batch_id,
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "replay_key": self.replay_key,
            "anchor_domain": self.anchor_domain,
            "first_seen_height": self.first_seen_height,
            "consumed_by_tx_id": self.consumed_by_tx_id,
            "status": self.status.as_str(),
        })
    }

    pub fn replay_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-REPLAY-PROTECTION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "replay_root",
            self.replay_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.protection_id, "replay protection id")?;
        ensure_non_empty(&self.batch_id, "replay protection batch id")?;
        ensure_non_empty(&self.subject_id, "replay protection subject id")?;
        ensure_non_empty(&self.nullifier, "replay protection nullifier")?;
        ensure_non_empty(&self.replay_key, "replay protection key")?;
        ensure_non_empty(&self.anchor_domain, "replay protection anchor domain")?;
        ensure_optional_non_empty(&self.consumed_by_tx_id, "replay consumed tx id")?;
        if self.status == ReplayProtectionStatus::Consumed && self.consumed_by_tx_id.is_none() {
            return Err("consumed replay protection requires tx id".to_string());
        }
        let computed = monero_settlement_adapter_replay_protection_id(&self.identity_record());
        if self.protection_id != computed {
            return Err("replay protection id mismatch".to_string());
        }
        Ok(self.replay_root())
    }

    pub fn consume(&mut self, tx_id: impl Into<String>) -> MoneroSettlementAdapterResult<String> {
        let tx_id = tx_id.into();
        ensure_non_empty(&tx_id, "replay consumed tx id")?;
        if self.status != ReplayProtectionStatus::Reserved {
            return Err("replay protection can only consume from reserved".to_string());
        }
        self.consumed_by_tx_id = Some(tx_id);
        self.status = ReplayProtectionStatus::Consumed;
        self.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorSettlementLane {
    pub lane_id: String,
    pub sponsor_id: String,
    pub batch_id: Option<String>,
    pub fee_asset_id: String,
    pub budget_piconero: u64,
    pub reserved_piconero: u64,
    pub consumed_piconero: u64,
    pub rebate_bps: u64,
    pub allowed_lane_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorLaneStatus,
}

impl LowFeeSponsorSettlementLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: impl Into<String>,
        batch_id: Option<String>,
        fee_asset_id: impl Into<String>,
        budget_piconero: u64,
        rebate_bps: u64,
        allowed_lanes: &[SettlementLane],
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let sponsor_id = sponsor_id.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&sponsor_id, "sponsor lane sponsor id")?;
        ensure_optional_non_empty(&batch_id, "sponsor lane batch id")?;
        ensure_non_empty(&fee_asset_id, "sponsor lane fee asset id")?;
        ensure_positive(budget_piconero, "sponsor lane budget")?;
        ensure_bps(rebate_bps, "sponsor lane rebate")?;
        ensure_expiry(opened_at_height, expires_at_height, "sponsor lane")?;
        ensure_lane_set(allowed_lanes, "sponsor lane allowed lanes")?;
        let lane_labels = allowed_lanes
            .iter()
            .map(|lane| lane.as_str().to_string())
            .collect::<Vec<_>>();
        let allowed_lane_root = monero_settlement_adapter_string_set_root(
            "MONERO-SETTLEMENT-SPONSOR-ALLOWED-LANES",
            &lane_labels,
        );
        let mut lane = Self {
            lane_id: String::new(),
            sponsor_id,
            batch_id,
            fee_asset_id,
            budget_piconero,
            reserved_piconero: 0,
            consumed_piconero: 0,
            rebate_bps,
            allowed_lane_root,
            opened_at_height,
            expires_at_height,
            status: SponsorLaneStatus::Open,
        };
        lane.lane_id = monero_settlement_adapter_sponsor_lane_id(&lane.identity_record());
        lane.validate()?;
        Ok(lane)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_sponsor_lane_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "batch_id": self.batch_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_piconero": self.budget_piconero,
            "rebate_bps": self.rebate_bps,
            "allowed_lane_root": self.allowed_lane_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn remaining_budget_piconero(&self) -> u64 {
        self.budget_piconero
            .saturating_sub(self.reserved_piconero)
            .saturating_sub(self.consumed_piconero)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_low_fee_sponsor_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "batch_id": self.batch_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_piconero": self.budget_piconero,
            "reserved_piconero": self.reserved_piconero,
            "consumed_piconero": self.consumed_piconero,
            "remaining_budget_piconero": self.remaining_budget_piconero(),
            "rebate_bps": self.rebate_bps,
            "allowed_lane_root": self.allowed_lane_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsor_lane_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-SPONSOR-LANE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsor_lane_root",
            self.sponsor_lane_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.lane_id, "sponsor lane id")?;
        ensure_non_empty(&self.sponsor_id, "sponsor lane sponsor id")?;
        ensure_optional_non_empty(&self.batch_id, "sponsor lane batch id")?;
        ensure_non_empty(&self.fee_asset_id, "sponsor lane fee asset id")?;
        ensure_non_empty(&self.allowed_lane_root, "sponsor lane allowed root")?;
        ensure_positive(self.budget_piconero, "sponsor lane budget")?;
        ensure_bps(self.rebate_bps, "sponsor lane rebate")?;
        ensure_expiry(
            self.opened_at_height,
            self.expires_at_height,
            "sponsor lane",
        )?;
        let used = self
            .reserved_piconero
            .saturating_add(self.consumed_piconero);
        if used > self.budget_piconero {
            return Err("sponsor lane spends beyond budget".to_string());
        }
        let computed = monero_settlement_adapter_sponsor_lane_id(&self.identity_record());
        if self.lane_id != computed {
            return Err("sponsor lane id mismatch".to_string());
        }
        Ok(self.sponsor_lane_root())
    }

    pub fn reserve(&mut self, amount_piconero: u64) -> MoneroSettlementAdapterResult<String> {
        ensure_positive(amount_piconero, "sponsor lane reserve amount")?;
        if !self.status.is_active() {
            return Err("sponsor lane is not active".to_string());
        }
        if self.remaining_budget_piconero() < amount_piconero {
            return Err("sponsor lane budget exhausted".to_string());
        }
        self.reserved_piconero = self.reserved_piconero.saturating_add(amount_piconero);
        self.status = SponsorLaneStatus::Reserved;
        self.validate()
    }

    pub fn consume(&mut self, amount_piconero: u64) -> MoneroSettlementAdapterResult<String> {
        ensure_positive(amount_piconero, "sponsor lane consume amount")?;
        if !self.status.is_active() {
            return Err("sponsor lane is not active".to_string());
        }
        if self.reserved_piconero < amount_piconero {
            return Err("sponsor lane consume exceeds reserved amount".to_string());
        }
        self.reserved_piconero = self.reserved_piconero.saturating_sub(amount_piconero);
        self.consumed_piconero = self.consumed_piconero.saturating_add(amount_piconero);
        self.status = if self.remaining_budget_piconero() == 0 {
            SponsorLaneStatus::Exhausted
        } else {
            SponsorLaneStatus::Consumed
        };
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_active() {
            self.status = SponsorLaneStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSettlementApproval {
    pub approval_id: String,
    pub subject_kind: PqSettlementSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_id: String,
    pub signer_role: String,
    pub pq_scheme: String,
    pub pq_public_key_root: String,
    pub security_bits: u16,
    pub signature_root: String,
    pub weight: u64,
    pub quorum_weight: u64,
    pub approved_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqApprovalStatus,
}

impl PqSettlementApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: PqSettlementSubjectKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        signer_id: impl Into<String>,
        signer_role: impl Into<String>,
        pq_scheme: impl Into<String>,
        pq_public_key_material: impl Into<String>,
        security_bits: u16,
        signature_payload: &Value,
        weight: u64,
        quorum_weight: u64,
        approved_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let signer_id = signer_id.into();
        let signer_role = signer_role.into();
        let pq_scheme = pq_scheme.into();
        let pq_public_key_material = pq_public_key_material.into();
        ensure_non_empty(&subject_id, "pq approval subject id")?;
        ensure_non_empty(&subject_root, "pq approval subject root")?;
        ensure_non_empty(&signer_id, "pq approval signer id")?;
        ensure_non_empty(&signer_role, "pq approval signer role")?;
        ensure_non_empty(&pq_scheme, "pq approval scheme")?;
        ensure_non_empty(&pq_public_key_material, "pq approval public key")?;
        ensure_positive(weight, "pq approval weight")?;
        ensure_positive(quorum_weight, "pq approval quorum")?;
        ensure_expiry(approved_at_height, expires_at_height, "pq approval")?;
        if security_bits < 128 {
            return Err("pq approval security bits below floor".to_string());
        }
        let pq_public_key_root = monero_settlement_adapter_string_root(
            "MONERO-SETTLEMENT-PQ-PUBLIC-KEY",
            &pq_public_key_material,
        );
        let signature_root = monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-PQ-SIGNATURE",
            signature_payload,
        );
        let status = if weight >= quorum_weight {
            PqApprovalStatus::ThresholdMet
        } else {
            PqApprovalStatus::Accepted
        };
        let mut approval = Self {
            approval_id: String::new(),
            subject_kind,
            subject_id,
            subject_root,
            signer_id,
            signer_role,
            pq_scheme,
            pq_public_key_root,
            security_bits,
            signature_root,
            weight,
            quorum_weight,
            approved_at_height,
            expires_at_height,
            status,
        };
        approval.approval_id =
            monero_settlement_adapter_pq_approval_id(&approval.identity_record());
        approval.validate()?;
        Ok(approval)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_pq_approval_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_id": self.signer_id,
            "signer_role": self.signer_role,
            "pq_scheme": self.pq_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "approved_at_height": self.approved_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_pq_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_id": self.signer_id,
            "signer_role": self.signer_role,
            "pq_scheme": self.pq_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "security_bits": self.security_bits,
            "signature_root": self.signature_root,
            "weight": self.weight,
            "quorum_weight": self.quorum_weight,
            "approved_at_height": self.approved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn approval_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-PQ-APPROVAL",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "approval_root",
            self.approval_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.approval_id, "pq approval id")?;
        ensure_non_empty(&self.subject_id, "pq approval subject id")?;
        ensure_non_empty(&self.subject_root, "pq approval subject root")?;
        ensure_non_empty(&self.signer_id, "pq approval signer id")?;
        ensure_non_empty(&self.signer_role, "pq approval signer role")?;
        ensure_non_empty(&self.pq_scheme, "pq approval scheme")?;
        ensure_non_empty(&self.pq_public_key_root, "pq approval public key root")?;
        ensure_non_empty(&self.signature_root, "pq approval signature root")?;
        ensure_positive(self.weight, "pq approval weight")?;
        ensure_positive(self.quorum_weight, "pq approval quorum")?;
        ensure_expiry(
            self.approved_at_height,
            self.expires_at_height,
            "pq approval",
        )?;
        if self.security_bits < 128 {
            return Err("pq approval security bits below floor".to_string());
        }
        let computed = monero_settlement_adapter_pq_approval_id(&self.identity_record());
        if self.approval_id != computed {
            return Err("pq approval id mismatch".to_string());
        }
        Ok(self.approval_root())
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_usable() {
            self.status = PqApprovalStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgSignal {
    pub signal_id: String,
    pub batch_id: String,
    pub signal_kind: ReorgSignalKind,
    pub observed_at_height: u64,
    pub monero_height: u64,
    pub previous_block_hash: String,
    pub replacement_block_hash: Option<String>,
    pub affected_tx_id: Option<String>,
    pub evidence_root: String,
    pub quarantine_until_height: u64,
    pub status: ReorgSignalStatus,
}

impl ReorgSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        signal_kind: ReorgSignalKind,
        observed_at_height: u64,
        monero_height: u64,
        previous_block_hash: impl Into<String>,
        replacement_block_hash: Option<String>,
        affected_tx_id: Option<String>,
        evidence_payload: &Value,
        quarantine_until_height: u64,
    ) -> MoneroSettlementAdapterResult<Self> {
        let batch_id = batch_id.into();
        let previous_block_hash = previous_block_hash.into();
        ensure_non_empty(&batch_id, "reorg signal batch id")?;
        ensure_non_empty(&previous_block_hash, "reorg signal previous block hash")?;
        ensure_optional_non_empty(
            &replacement_block_hash,
            "reorg signal replacement block hash",
        )?;
        ensure_optional_non_empty(&affected_tx_id, "reorg signal affected tx id")?;
        if quarantine_until_height < observed_at_height {
            return Err("reorg signal quarantine precedes observation".to_string());
        }
        let evidence_root = monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-REORG-EVIDENCE",
            evidence_payload,
        );
        let mut signal = Self {
            signal_id: String::new(),
            batch_id,
            signal_kind,
            observed_at_height,
            monero_height,
            previous_block_hash,
            replacement_block_hash,
            affected_tx_id,
            evidence_root,
            quarantine_until_height,
            status: ReorgSignalStatus::Quarantined,
        };
        signal.signal_id = monero_settlement_adapter_reorg_signal_id(&signal.identity_record());
        signal.validate()?;
        Ok(signal)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_reorg_signal_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "signal_kind": self.signal_kind.as_str(),
            "observed_at_height": self.observed_at_height,
            "monero_height": self.monero_height,
            "previous_block_hash": self.previous_block_hash,
            "replacement_block_hash": self.replacement_block_hash,
            "affected_tx_id": self.affected_tx_id,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_reorg_signal",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "signal_id": self.signal_id,
            "batch_id": self.batch_id,
            "signal_kind": self.signal_kind.as_str(),
            "observed_at_height": self.observed_at_height,
            "monero_height": self.monero_height,
            "previous_block_hash": self.previous_block_hash,
            "replacement_block_hash": self.replacement_block_hash,
            "affected_tx_id": self.affected_tx_id,
            "evidence_root": self.evidence_root,
            "quarantine_until_height": self.quarantine_until_height,
            "status": self.status.as_str(),
        })
    }

    pub fn signal_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-REORG-SIGNAL",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "signal_root",
            self.signal_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.signal_id, "reorg signal id")?;
        ensure_non_empty(&self.batch_id, "reorg signal batch id")?;
        ensure_non_empty(
            &self.previous_block_hash,
            "reorg signal previous block hash",
        )?;
        ensure_optional_non_empty(
            &self.replacement_block_hash,
            "reorg signal replacement block hash",
        )?;
        ensure_optional_non_empty(&self.affected_tx_id, "reorg signal affected tx id")?;
        ensure_non_empty(&self.evidence_root, "reorg signal evidence root")?;
        if self.quarantine_until_height < self.observed_at_height {
            return Err("reorg signal quarantine precedes observation".to_string());
        }
        let computed = monero_settlement_adapter_reorg_signal_id(&self.identity_record());
        if self.signal_id != computed {
            return Err("reorg signal id mismatch".to_string());
        }
        Ok(self.signal_root())
    }

    pub fn resolve(&mut self) -> MoneroSettlementAdapterResult<String> {
        if !self.status.is_active() {
            return Err("reorg signal is not active".to_string());
        }
        self.status = ReorgSignalStatus::Resolved;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.quarantine_until_height && self.status.is_active() {
            self.status = ReorgSignalStatus::Expired;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAdapterEvent {
    pub event_id: String,
    pub sequence: u64,
    pub height: u64,
    pub event_kind: SettlementAdapterEventKind,
    pub subject_id: String,
    pub event_root: String,
}

impl SettlementAdapterEvent {
    pub fn new(
        sequence: u64,
        height: u64,
        event_kind: SettlementAdapterEventKind,
        subject_id: impl Into<String>,
        event_root: impl Into<String>,
    ) -> MoneroSettlementAdapterResult<Self> {
        let subject_id = subject_id.into();
        let event_root = event_root.into();
        ensure_non_empty(&subject_id, "settlement event subject id")?;
        ensure_non_empty(&event_root, "settlement event root")?;
        let mut event = Self {
            event_id: String::new(),
            sequence,
            height,
            event_kind,
            subject_id,
            event_root,
        };
        event.event_id = monero_settlement_adapter_event_id(&event.identity_record());
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_adapter_event_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "event_root": self.event_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_adapter_event",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "event_root": self.event_root,
        })
    }

    pub fn record_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-ADAPTER-EVENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        ensure_non_empty(&self.event_id, "settlement event id")?;
        ensure_non_empty(&self.subject_id, "settlement event subject id")?;
        ensure_non_empty(&self.event_root, "settlement event root")?;
        let computed = monero_settlement_adapter_event_id(&self.identity_record());
        if self.event_id != computed {
            return Err("settlement event id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementAdapterCounters {
    pub height: u64,
    pub batch_count: u64,
    pub open_batch_count: u64,
    pub settled_batch_count: u64,
    pub reorged_batch_count: u64,
    pub anchor_manifest_count: u64,
    pub confirmed_anchor_manifest_count: u64,
    pub release_plan_count: u64,
    pub open_release_plan_count: u64,
    pub released_withdrawal_count: u64,
    pub fee_bump_plan_count: u64,
    pub active_fee_bump_plan_count: u64,
    pub daemon_receipt_count: u64,
    pub successful_daemon_receipt_count: u64,
    pub confirmed_daemon_receipt_count: u64,
    pub reserve_authorization_count: u64,
    pub active_reserve_authorization_count: u64,
    pub replay_protection_count: u64,
    pub consumed_replay_protection_count: u64,
    pub sponsor_lane_count: u64,
    pub active_sponsor_lane_count: u64,
    pub remaining_sponsor_budget_piconero: u64,
    pub pq_approval_count: u64,
    pub usable_pq_approval_count: u64,
    pub reorg_signal_count: u64,
    pub active_reorg_signal_count: u64,
    pub event_count: u64,
    pub total_planned_withdrawal_piconero: u64,
    pub total_release_fee_piconero: u64,
    pub total_reserve_authorized_piconero: u64,
}

impl MoneroSettlementAdapterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_adapter_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "height": self.height,
            "batch_count": self.batch_count,
            "open_batch_count": self.open_batch_count,
            "settled_batch_count": self.settled_batch_count,
            "reorged_batch_count": self.reorged_batch_count,
            "anchor_manifest_count": self.anchor_manifest_count,
            "confirmed_anchor_manifest_count": self.confirmed_anchor_manifest_count,
            "release_plan_count": self.release_plan_count,
            "open_release_plan_count": self.open_release_plan_count,
            "released_withdrawal_count": self.released_withdrawal_count,
            "fee_bump_plan_count": self.fee_bump_plan_count,
            "active_fee_bump_plan_count": self.active_fee_bump_plan_count,
            "daemon_receipt_count": self.daemon_receipt_count,
            "successful_daemon_receipt_count": self.successful_daemon_receipt_count,
            "confirmed_daemon_receipt_count": self.confirmed_daemon_receipt_count,
            "reserve_authorization_count": self.reserve_authorization_count,
            "active_reserve_authorization_count": self.active_reserve_authorization_count,
            "replay_protection_count": self.replay_protection_count,
            "consumed_replay_protection_count": self.consumed_replay_protection_count,
            "sponsor_lane_count": self.sponsor_lane_count,
            "active_sponsor_lane_count": self.active_sponsor_lane_count,
            "remaining_sponsor_budget_piconero": self.remaining_sponsor_budget_piconero,
            "pq_approval_count": self.pq_approval_count,
            "usable_pq_approval_count": self.usable_pq_approval_count,
            "reorg_signal_count": self.reorg_signal_count,
            "active_reorg_signal_count": self.active_reorg_signal_count,
            "event_count": self.event_count,
            "total_planned_withdrawal_piconero": self.total_planned_withdrawal_piconero,
            "total_release_fee_piconero": self.total_release_fee_piconero,
            "total_reserve_authorized_piconero": self.total_reserve_authorized_piconero,
            "counters_root": self.counters_root(),
        })
    }

    pub fn counters_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-ADAPTER-COUNTERS",
            &json!({
                "height": self.height,
                "batch_count": self.batch_count,
                "open_batch_count": self.open_batch_count,
                "settled_batch_count": self.settled_batch_count,
                "reorged_batch_count": self.reorged_batch_count,
                "anchor_manifest_count": self.anchor_manifest_count,
                "release_plan_count": self.release_plan_count,
                "fee_bump_plan_count": self.fee_bump_plan_count,
                "daemon_receipt_count": self.daemon_receipt_count,
                "reserve_authorization_count": self.reserve_authorization_count,
                "replay_protection_count": self.replay_protection_count,
                "sponsor_lane_count": self.sponsor_lane_count,
                "pq_approval_count": self.pq_approval_count,
                "reorg_signal_count": self.reorg_signal_count,
                "event_count": self.event_count,
                "total_planned_withdrawal_piconero": self.total_planned_withdrawal_piconero,
                "total_release_fee_piconero": self.total_release_fee_piconero,
                "total_reserve_authorized_piconero": self.total_reserve_authorized_piconero,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementAdapterRoots {
    pub config_root: String,
    pub batch_root: String,
    pub anchor_manifest_root: String,
    pub release_plan_root: String,
    pub fee_bump_plan_root: String,
    pub daemon_receipt_root: String,
    pub reserve_authorization_root: String,
    pub replay_protection_root: String,
    pub sponsor_lane_root: String,
    pub pq_approval_root: String,
    pub reorg_signal_root: String,
    pub event_root: String,
    pub replay_key_set_root: String,
    pub nullifier_set_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl MoneroSettlementAdapterRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_settlement_adapter_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "batch_root": self.batch_root,
            "anchor_manifest_root": self.anchor_manifest_root,
            "release_plan_root": self.release_plan_root,
            "fee_bump_plan_root": self.fee_bump_plan_root,
            "daemon_receipt_root": self.daemon_receipt_root,
            "reserve_authorization_root": self.reserve_authorization_root,
            "replay_protection_root": self.replay_protection_root,
            "sponsor_lane_root": self.sponsor_lane_root,
            "pq_approval_root": self.pq_approval_root,
            "reorg_signal_root": self.reorg_signal_root,
            "event_root": self.event_root,
            "replay_key_set_root": self.replay_key_set_root,
            "nullifier_set_root": self.nullifier_set_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-ADAPTER-ROOTS",
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            with_root_field(
                self.public_record_without_state_root(),
                "roots_root",
                self.roots_root(),
            ),
            "state_root",
            self.state_root.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementAdapterState {
    pub height: u64,
    pub network: String,
    pub observed_monero_height: u64,
    pub observed_monero_block_hash: String,
    pub next_event_sequence: u64,
    pub config: MoneroSettlementAdapterConfig,
    pub batches: BTreeMap<String, MoneroSettlementBatch>,
    pub anchor_manifests: BTreeMap<String, SettlementAnchorManifest>,
    pub release_plans: BTreeMap<String, WithdrawalReleasePlan>,
    pub fee_bump_plans: BTreeMap<String, TxFeeBumpPlan>,
    pub daemon_receipts: BTreeMap<String, DaemonSubmissionReceipt>,
    pub reserve_spend_authorizations: BTreeMap<String, ReserveSpendAuthorization>,
    pub replay_protections: BTreeMap<String, ReplayProtectionRecord>,
    pub sponsor_lanes: BTreeMap<String, LowFeeSponsorSettlementLane>,
    pub pq_approvals: BTreeMap<String, PqSettlementApproval>,
    pub reorg_signals: BTreeMap<String, ReorgSignal>,
    pub events: BTreeMap<String, SettlementAdapterEvent>,
    pub reserved_replay_keys: BTreeSet<String>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl MoneroSettlementAdapterState {
    pub fn new(config: MoneroSettlementAdapterConfig) -> MoneroSettlementAdapterResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            network: config.network.clone(),
            observed_monero_height: 0,
            observed_monero_block_hash: monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-EMPTY-MONERO-TIP",
                &config.network,
            ),
            next_event_sequence: 0,
            config,
            batches: BTreeMap::new(),
            anchor_manifests: BTreeMap::new(),
            release_plans: BTreeMap::new(),
            fee_bump_plans: BTreeMap::new(),
            daemon_receipts: BTreeMap::new(),
            reserve_spend_authorizations: BTreeMap::new(),
            replay_protections: BTreeMap::new(),
            sponsor_lanes: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            reorg_signals: BTreeMap::new(),
            events: BTreeMap::new(),
            reserved_replay_keys: BTreeSet::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> MoneroSettlementAdapterResult<Self> {
        let mut state = Self::new(MoneroSettlementAdapterConfig::default())?;
        state.set_height(256)?;
        state.set_monero_tip(
            2_904_256,
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-MONERO-BLOCK",
                "block-2904256",
            ),
        )?;

        let mut sponsor_lane = LowFeeSponsorSettlementLane::new(
            "devnet-low-fee-sponsor",
            None,
            state.config.fee_asset_id.clone(),
            600_000_000,
            state.config.low_fee_rebate_bps,
            &[SettlementLane::LowFee, SettlementLane::PrivateExit],
            state.height,
            state
                .height
                .saturating_add(state.config.sponsorship_ttl_blocks),
        )?;
        sponsor_lane.reserve(80_000_000)?;
        let sponsor_lane_id = sponsor_lane.lane_id.clone();
        let sponsor_lane_root = sponsor_lane.sponsor_lane_root();
        state.insert_low_fee_sponsor_lane(sponsor_lane)?;

        let withdrawal_payload = json!({
            "claims": [
                {
                    "withdrawal_id": "devnet-withdrawal-a",
                    "amount_piconero": 1_200_000_000_000_u64,
                    "lane": "low_fee"
                },
                {
                    "withdrawal_id": "devnet-withdrawal-b",
                    "amount_piconero": 800_000_000_000_u64,
                    "lane": "standard"
                }
            ],
        });
        let withdrawal_root = monero_settlement_adapter_payload_root(
            "MONERO-SETTLEMENT-DEVNET-WITHDRAWALS",
            &withdrawal_payload,
        );
        let nullifiers = vec![
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-NULLIFIER",
                "devnet-withdrawal-a",
            ),
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-NULLIFIER",
                "devnet-withdrawal-b",
            ),
        ];
        let nullifier_root = monero_settlement_adapter_string_set_root(
            "MONERO-SETTLEMENT-DEVNET-NULLIFIER-SET",
            &nullifiers,
        );
        let reserve_spend_root = monero_settlement_adapter_string_root(
            "MONERO-SETTLEMENT-DEVNET-RESERVE-SPEND",
            "planned-reserve-spend",
        );
        let fee_plan_root = monero_settlement_adapter_string_root(
            "MONERO-SETTLEMENT-DEVNET-FEE-PLAN",
            "planned-fee-plan",
        );
        let pq_approval_root = monero_settlement_adapter_string_root(
            "MONERO-SETTLEMENT-DEVNET-PQ-APPROVAL",
            "pending-approval",
        );

        let mut batch = MoneroSettlementBatch::new(
            7,
            SettlementLane::LowFee,
            state.network.clone(),
            state.config.asset_id.clone(),
            220,
            255,
            state.observed_monero_height,
            state.observed_monero_block_hash.clone(),
            state.height,
            state.config.batch_ttl_blocks,
            state.config.reorg_hold_blocks,
            withdrawal_root.clone(),
            nullifier_root.clone(),
            reserve_spend_root,
            sponsor_lane_root,
            fee_plan_root,
            pq_approval_root,
            2,
            2_000_000_000_000,
            120_000_000,
            state.config.monero_finality_depth,
        )?;
        batch.mark_anchored()?;
        let batch_id = batch.batch_id.clone();
        state.insert_batch(batch)?;

        let mut anchor_manifest = SettlementAnchorManifest::new(
            batch_id.clone(),
            AnchorKind::BatchCommitment,
            0,
            state.height,
            state.observed_monero_height,
            state.observed_monero_block_hash.clone(),
            withdrawal_root,
            state.height,
            state.height.saturating_add(state.config.batch_ttl_blocks),
        )?;
        anchor_manifest.publish()?;
        state.insert_anchor_manifest(anchor_manifest)?;

        let mut release_a = WithdrawalReleasePlan::new(
            batch_id.clone(),
            "devnet-withdrawal-a",
            SettlementLane::LowFee,
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-RECIPIENT",
                "recipient-a",
            ),
            1_200_000_000_000,
            60_000_000,
            nullifiers[0].clone(),
            None,
            Some(sponsor_lane_id.clone()),
            state.height.saturating_add(state.config.l2_finality_depth),
            state.height.saturating_add(state.config.release_ttl_blocks),
            &json!({"tx_template": "devnet-release-a"}),
        )?;
        release_a.mark_submitted()?;
        let release_a_id = release_a.release_id.clone();
        let release_a_replay = release_a.replay_key.clone();
        state.insert_withdrawal_release_plan(release_a)?;

        let release_b = WithdrawalReleasePlan::new(
            batch_id.clone(),
            "devnet-withdrawal-b",
            SettlementLane::Standard,
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-RECIPIENT",
                "recipient-b",
            ),
            800_000_000_000,
            60_000_000,
            nullifiers[1].clone(),
            None,
            None,
            state.height.saturating_add(state.config.l2_finality_depth),
            state.height.saturating_add(state.config.release_ttl_blocks),
            &json!({"tx_template": "devnet-release-b"}),
        )?;
        state.insert_withdrawal_release_plan(release_b)?;

        let replay_a = ReplayProtectionRecord::new(
            ReplayProtectionScope::Withdrawal,
            batch_id.clone(),
            release_a_id.clone(),
            nullifiers[0].clone(),
            release_a_replay,
            "monero-mainnet-like-devnet",
            state.height,
        )?;
        state.insert_replay_protection(replay_a)?;

        let reserve_authorization = ReserveSpendAuthorization::new(
            batch_id.clone(),
            "devnet-hot-buffer-wallet",
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-SPEND-POLICY",
                "hot-buffer-release-policy",
            ),
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-INPUTS",
                "reserve-inputs",
            ),
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-OUTPUTS",
                "release-outputs",
            ),
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-KEY-IMAGES",
                "planned-key-images",
            ),
            2_000_000_000_000,
            180_000_000,
            monero_settlement_adapter_string_root(
                "MONERO-SETTLEMENT-DEVNET-SIGNER-SET",
                "reserve-signers",
            ),
            None,
            state.height,
            state.height.saturating_add(state.config.release_ttl_blocks),
        )?;
        state.insert_reserve_spend_authorization(reserve_authorization)?;

        let fee_bump = TxFeeBumpPlan::new(
            batch_id.clone(),
            Some(release_a_id.clone()),
            "devnet-release-parent-tx",
            "devnet-release-replacement-tx",
            state.config.fee_asset_id.clone(),
            60_000_000,
            90_000_000,
            180_000_000,
            Some(sponsor_lane_id),
            state.height,
            state
                .height
                .saturating_add(state.config.fee_bump_ttl_blocks),
            "mempool minimum fee rose before anchor finality",
        )?;
        state.insert_tx_fee_bump_plan(fee_bump)?;

        let batch_root_for_approval = match state.batches.get(&batch_id) {
            Some(batch) => batch.batch_root(),
            None => return Err("devnet settlement batch missing after insert".to_string()),
        };
        let approval = PqSettlementApproval::new(
            PqSettlementSubjectKind::SettlementBatch,
            batch_id.clone(),
            batch_root_for_approval,
            "devnet-settlement-council-a",
            "settlement_council",
            "ML-DSA-65",
            "devnet-pq-key-a",
            state.config.min_pq_security_bits,
            &json!({"signature": "devnet-pq-signature-a"}),
            state.config.pq_approval_quorum_weight,
            state.config.pq_approval_quorum_weight,
            state.height,
            state.height.saturating_add(state.config.batch_ttl_blocks),
        )?;
        state.insert_pq_settlement_approval(approval)?;

        let receipt = DaemonSubmissionReceipt::new(
            batch_id,
            "devnet-submit-request-a",
            "devnet-daemon-alpha",
            "devnet-release-replacement-tx",
            &json!({"tx_blob": "opaque-devnet-blob-root-only"}),
            state.height,
            state.observed_monero_height,
            90_000_000,
            true,
            1,
            None,
        )?;
        state.insert_daemon_submission_receipt(receipt)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroSettlementAdapterResult<String> {
        self.height = height;
        for batch in self.batches.values_mut() {
            batch.set_height(height);
        }
        for manifest in self.anchor_manifests.values_mut() {
            manifest.set_height(height);
        }
        for release in self.release_plans.values_mut() {
            release.set_height(height);
        }
        for fee_bump in self.fee_bump_plans.values_mut() {
            fee_bump.set_height(height);
        }
        for authorization in self.reserve_spend_authorizations.values_mut() {
            authorization.set_height(height);
        }
        for sponsor_lane in self.sponsor_lanes.values_mut() {
            sponsor_lane.set_height(height);
        }
        for approval in self.pq_approvals.values_mut() {
            approval.set_height(height);
        }
        for signal in self.reorg_signals.values_mut() {
            signal.set_height(height);
        }
        self.validate()
    }

    pub fn set_monero_tip(
        &mut self,
        height: u64,
        block_hash: impl Into<String>,
    ) -> MoneroSettlementAdapterResult<String> {
        let block_hash = block_hash.into();
        ensure_non_empty(&block_hash, "monero settlement observed block hash")?;
        self.observed_monero_height = height;
        self.observed_monero_block_hash = block_hash;
        self.validate()
    }

    pub fn insert_batch(
        &mut self,
        batch: MoneroSettlementBatch,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = batch.validate()?;
        if batch.network != self.network {
            return Err("settlement batch network mismatch".to_string());
        }
        if batch.asset_id != self.config.asset_id {
            return Err("settlement batch asset mismatch".to_string());
        }
        if batch.withdrawal_count > self.config.max_batch_withdrawals {
            return Err("settlement batch exceeds configured withdrawal limit".to_string());
        }
        let batch_id = batch.batch_id.clone();
        self.batches.insert(batch_id.clone(), batch);
        self.record_event(
            SettlementAdapterEventKind::BatchPlanned,
            batch_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_anchor_manifest(
        &mut self,
        manifest: SettlementAnchorManifest,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = manifest.validate()?;
        if !self.batches.contains_key(&manifest.batch_id) {
            return Err("settlement manifest references missing batch".to_string());
        }
        let manifest_id = manifest.manifest_id.clone();
        let batch_id = manifest.batch_id.clone();
        self.anchor_manifests.insert(manifest_id.clone(), manifest);
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            if batch.status == SettlementBatchStatus::Draft {
                batch.mark_anchored()?;
            }
        }
        self.record_event(
            SettlementAdapterEventKind::AnchorManifest,
            manifest_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_withdrawal_release_plan(
        &mut self,
        release: WithdrawalReleasePlan,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = release.validate()?;
        if !self.batches.contains_key(&release.batch_id) {
            return Err("withdrawal release references missing batch".to_string());
        }
        if self.reserved_replay_keys.contains(&release.replay_key) {
            return Err("withdrawal release replay key already reserved".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&release.account_nullifier)
        {
            return Err("withdrawal release nullifier already consumed".to_string());
        }
        if self
            .release_plans
            .values()
            .any(|existing| existing.account_nullifier == release.account_nullifier)
        {
            return Err("withdrawal release nullifier already planned".to_string());
        }
        if let Some(sponsor_lane_id) = &release.sponsor_lane_id {
            if !self.sponsor_lanes.contains_key(sponsor_lane_id) {
                return Err("withdrawal release references missing sponsor lane".to_string());
            }
            if !release.lane.sponsor_eligible() {
                return Err("withdrawal release sponsor lane used for ineligible lane".to_string());
            }
        }
        if let Some(authorization_id) = &release.reserve_spend_authorization_id {
            if !self
                .reserve_spend_authorizations
                .contains_key(authorization_id)
            {
                return Err(
                    "withdrawal release references missing reserve authorization".to_string(),
                );
            }
        }
        let release_id = release.release_id.clone();
        self.reserved_replay_keys.insert(release.replay_key.clone());
        self.release_plans.insert(release_id.clone(), release);
        self.record_event(
            SettlementAdapterEventKind::WithdrawalRelease,
            release_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_tx_fee_bump_plan(
        &mut self,
        plan: TxFeeBumpPlan,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = plan.validate()?;
        if plan.fee_asset_id != self.config.fee_asset_id {
            return Err("fee bump asset mismatch".to_string());
        }
        if plan.bump_multiplier_bps > self.config.max_fee_bump_multiplier_bps {
            return Err("fee bump multiplier exceeds policy".to_string());
        }
        if !self.batches.contains_key(&plan.batch_id) {
            return Err("fee bump references missing batch".to_string());
        }
        if let Some(release_id) = &plan.release_id {
            if !self.release_plans.contains_key(release_id) {
                return Err("fee bump references missing withdrawal release".to_string());
            }
        }
        if let Some(sponsor_lane_id) = &plan.sponsor_lane_id {
            if !self.sponsor_lanes.contains_key(sponsor_lane_id) {
                return Err("fee bump references missing sponsor lane".to_string());
            }
        }
        let plan_id = plan.fee_bump_id.clone();
        let batch_id = plan.batch_id.clone();
        self.fee_bump_plans.insert(plan_id.clone(), plan);
        let fee_plan_root = self.fee_bump_plan_root();
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            batch.fee_plan_root = fee_plan_root;
        }
        self.record_event(
            SettlementAdapterEventKind::FeeBumpPlan,
            plan_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_daemon_submission_receipt(
        &mut self,
        receipt: DaemonSubmissionReceipt,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = receipt.validate()?;
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err("daemon receipt references missing batch".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        let batch_id = receipt.batch_id.clone();
        let receipt_status = receipt.status;
        let confirmations = receipt.confirmations;
        self.daemon_receipts.insert(receipt_id.clone(), receipt);
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            match receipt_status {
                DaemonSubmissionStatus::Confirmed => {
                    if confirmations >= batch.min_confirmations {
                        batch.mark_settled()?;
                    } else if batch.status.is_open() {
                        batch.status = SettlementBatchStatus::Confirming;
                    }
                }
                DaemonSubmissionStatus::Accepted | DaemonSubmissionStatus::InMempool => {
                    if matches!(
                        batch.status,
                        SettlementBatchStatus::Anchored | SettlementBatchStatus::Approved
                    ) {
                        batch.mark_submitted()?;
                    }
                }
                DaemonSubmissionStatus::Rejected => {
                    batch.status = SettlementBatchStatus::Failed;
                }
                DaemonSubmissionStatus::Reorged => {
                    batch.status = SettlementBatchStatus::Reorged;
                }
                DaemonSubmissionStatus::Prepared
                | DaemonSubmissionStatus::Submitted
                | DaemonSubmissionStatus::Expired => {}
            }
        }
        self.record_event(
            SettlementAdapterEventKind::DaemonReceipt,
            receipt_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_reserve_spend_authorization(
        &mut self,
        authorization: ReserveSpendAuthorization,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = authorization.validate()?;
        if !self.batches.contains_key(&authorization.batch_id) {
            return Err("reserve authorization references missing batch".to_string());
        }
        if let Some(approval_id) = &authorization.pq_approval_id {
            if !self.pq_approvals.contains_key(approval_id) {
                return Err("reserve authorization references missing pq approval".to_string());
            }
        }
        let authorization_id = authorization.authorization_id.clone();
        let batch_id = authorization.batch_id.clone();
        self.reserve_spend_authorizations
            .insert(authorization_id.clone(), authorization);
        let reserve_authorization_root = self.reserve_authorization_root();
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            batch.reserve_spend_root = reserve_authorization_root;
        }
        self.record_event(
            SettlementAdapterEventKind::ReserveSpendAuthorization,
            authorization_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_replay_protection(
        &mut self,
        protection: ReplayProtectionRecord,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = protection.validate()?;
        if !self.batches.contains_key(&protection.batch_id) {
            return Err("replay protection references missing batch".to_string());
        }
        if self.reserved_replay_keys.contains(&protection.replay_key)
            && !self
                .release_plans
                .values()
                .any(|release| release.replay_key == protection.replay_key)
        {
            return Err("replay protection key already reserved".to_string());
        }
        if self.consumed_nullifiers.contains(&protection.nullifier) {
            return Err("replay protection nullifier already consumed".to_string());
        }
        if self
            .replay_protections
            .values()
            .any(|record| record.nullifier == protection.nullifier)
        {
            return Err("replay protection nullifier already exists".to_string());
        }
        if self
            .replay_protections
            .values()
            .any(|record| record.replay_key == protection.replay_key)
        {
            return Err("replay protection key already exists".to_string());
        }
        let protection_id = protection.protection_id.clone();
        self.reserved_replay_keys
            .insert(protection.replay_key.clone());
        if protection.status == ReplayProtectionStatus::Consumed {
            self.consumed_nullifiers
                .insert(protection.nullifier.clone());
        }
        self.replay_protections
            .insert(protection_id.clone(), protection);
        self.record_event(
            SettlementAdapterEventKind::ReplayProtection,
            protection_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_low_fee_sponsor_lane(
        &mut self,
        lane: LowFeeSponsorSettlementLane,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = lane.validate()?;
        if lane.fee_asset_id != self.config.fee_asset_id {
            return Err("sponsor lane fee asset mismatch".to_string());
        }
        if let Some(batch_id) = &lane.batch_id {
            if !self.batches.contains_key(batch_id) {
                return Err("sponsor lane references missing batch".to_string());
            }
        }
        let lane_id = lane.lane_id.clone();
        let batch_id = lane.batch_id.clone();
        self.sponsor_lanes.insert(lane_id.clone(), lane);
        if let Some(batch_id) = batch_id {
            let sponsor_root = self.sponsor_lane_root();
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.sponsor_lane_root = sponsor_root;
            }
        }
        self.record_event(
            SettlementAdapterEventKind::SponsorLane,
            lane_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_pq_settlement_approval(
        &mut self,
        approval: PqSettlementApproval,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = approval.validate()?;
        if approval.security_bits < self.config.min_pq_security_bits {
            return Err("pq approval does not meet configured security floor".to_string());
        }
        if approval.quorum_weight != self.config.pq_approval_quorum_weight {
            return Err("pq approval quorum weight mismatch".to_string());
        }
        self.ensure_subject_exists(approval.subject_kind, &approval.subject_id)?;
        let approval_id = approval.approval_id.clone();
        let subject_kind = approval.subject_kind;
        let subject_id = approval.subject_id.clone();
        let approval_status = approval.status;
        self.pq_approvals.insert(approval_id.clone(), approval);
        if subject_kind == PqSettlementSubjectKind::SettlementBatch
            && approval_status == PqApprovalStatus::ThresholdMet
        {
            if let Some(batch) = self.batches.get_mut(&subject_id) {
                batch.mark_approved(root.clone())?;
            }
        }
        self.record_event(
            SettlementAdapterEventKind::PqApproval,
            approval_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_reorg_signal(
        &mut self,
        signal: ReorgSignal,
    ) -> MoneroSettlementAdapterResult<String> {
        let root = signal.validate()?;
        if !self.batches.contains_key(&signal.batch_id) {
            return Err("reorg signal references missing batch".to_string());
        }
        let signal_id = signal.signal_id.clone();
        let batch_id = signal.batch_id.clone();
        let quarantine_until_height = signal.quarantine_until_height;
        let active = signal.status.is_active();
        self.reorg_signals.insert(signal_id.clone(), signal);
        if active {
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.hold_for_reorg(quarantine_until_height)?;
            }
            for release in self
                .release_plans
                .values_mut()
                .filter(|release| release.batch_id == batch_id)
            {
                if release.status.is_open() {
                    release.hold_for_reorg()?;
                }
            }
        }
        self.record_event(
            SettlementAdapterEventKind::ReorgSignal,
            signal_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn counters(&self) -> MoneroSettlementAdapterCounters {
        MoneroSettlementAdapterCounters {
            height: self.height,
            batch_count: self.batches.len() as u64,
            open_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status.is_open())
                .count() as u64,
            settled_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status == SettlementBatchStatus::Settled)
                .count() as u64,
            reorged_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status == SettlementBatchStatus::Reorged)
                .count() as u64,
            anchor_manifest_count: self.anchor_manifests.len() as u64,
            confirmed_anchor_manifest_count: self
                .anchor_manifests
                .values()
                .filter(|manifest| manifest.status == AnchorManifestStatus::Confirmed)
                .count() as u64,
            release_plan_count: self.release_plans.len() as u64,
            open_release_plan_count: self
                .release_plans
                .values()
                .filter(|release| release.status.is_open())
                .count() as u64,
            released_withdrawal_count: self
                .release_plans
                .values()
                .filter(|release| release.status == WithdrawalReleaseStatus::Released)
                .count() as u64,
            fee_bump_plan_count: self.fee_bump_plans.len() as u64,
            active_fee_bump_plan_count: self
                .fee_bump_plans
                .values()
                .filter(|plan| plan.status.is_active())
                .count() as u64,
            daemon_receipt_count: self.daemon_receipts.len() as u64,
            successful_daemon_receipt_count: self
                .daemon_receipts
                .values()
                .filter(|receipt| receipt.status.is_success())
                .count() as u64,
            confirmed_daemon_receipt_count: self
                .daemon_receipts
                .values()
                .filter(|receipt| receipt.status == DaemonSubmissionStatus::Confirmed)
                .count() as u64,
            reserve_authorization_count: self.reserve_spend_authorizations.len() as u64,
            active_reserve_authorization_count: self
                .reserve_spend_authorizations
                .values()
                .filter(|authorization| authorization.status.is_active())
                .count() as u64,
            replay_protection_count: self.replay_protections.len() as u64,
            consumed_replay_protection_count: self
                .replay_protections
                .values()
                .filter(|record| record.status == ReplayProtectionStatus::Consumed)
                .count() as u64,
            sponsor_lane_count: self.sponsor_lanes.len() as u64,
            active_sponsor_lane_count: self
                .sponsor_lanes
                .values()
                .filter(|lane| lane.status.is_active())
                .count() as u64,
            remaining_sponsor_budget_piconero: self
                .sponsor_lanes
                .values()
                .map(LowFeeSponsorSettlementLane::remaining_budget_piconero)
                .sum(),
            pq_approval_count: self.pq_approvals.len() as u64,
            usable_pq_approval_count: self
                .pq_approvals
                .values()
                .filter(|approval| approval.status.is_usable())
                .count() as u64,
            reorg_signal_count: self.reorg_signals.len() as u64,
            active_reorg_signal_count: self
                .reorg_signals
                .values()
                .filter(|signal| signal.status.is_active())
                .count() as u64,
            event_count: self.events.len() as u64,
            total_planned_withdrawal_piconero: self
                .release_plans
                .values()
                .map(|release| release.amount_piconero)
                .sum(),
            total_release_fee_piconero: self
                .release_plans
                .values()
                .map(|release| release.fee_piconero)
                .sum(),
            total_reserve_authorized_piconero: self
                .reserve_spend_authorizations
                .values()
                .map(|authorization| authorization.amount_piconero)
                .sum(),
        }
    }

    pub fn roots(&self) -> MoneroSettlementAdapterRoots {
        let counters = self.counters();
        let state_without_root = self.public_record_without_state_root(&counters);
        let state_root = monero_settlement_adapter_state_root_from_record(&state_without_root);
        MoneroSettlementAdapterRoots {
            config_root: self.config.config_root(),
            batch_root: self.batch_root(),
            anchor_manifest_root: self.anchor_manifest_root(),
            release_plan_root: self.release_plan_root(),
            fee_bump_plan_root: self.fee_bump_plan_root(),
            daemon_receipt_root: self.daemon_receipt_root(),
            reserve_authorization_root: self.reserve_authorization_root(),
            replay_protection_root: self.replay_protection_root(),
            sponsor_lane_root: self.sponsor_lane_root(),
            pq_approval_root: self.pq_approval_root(),
            reorg_signal_root: self.reorg_signal_root(),
            event_root: self.event_root(),
            replay_key_set_root: self.replay_key_set_root(),
            nullifier_set_root: self.nullifier_set_root(),
            counters_root: counters.counters_root(),
            public_record_root: monero_settlement_adapter_payload_root(
                "MONERO-SETTLEMENT-ADAPTER-PUBLIC-RECORD",
                &json!({
                    "height": self.height,
                    "network": self.network,
                    "observed_monero_height": self.observed_monero_height,
                    "observed_monero_block_hash": self.observed_monero_block_hash,
                    "next_event_sequence": self.next_event_sequence,
                    "counters_root": counters.counters_root(),
                }),
            ),
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        monero_settlement_adapter_state_root_from_record(
            &self.public_record_without_state_root(&self.counters()),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_state_root(&self.counters()),
            "state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> MoneroSettlementAdapterResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.network, "monero settlement state network")?;
        ensure_non_empty(
            &self.observed_monero_block_hash,
            "monero settlement observed block hash",
        )?;
        if self.network != self.config.network {
            return Err("monero settlement state network mismatch".to_string());
        }

        for batch in self.batches.values() {
            batch.validate()?;
            if batch.network != self.network {
                return Err("settlement batch network mismatch".to_string());
            }
            if batch.asset_id != self.config.asset_id {
                return Err("settlement batch asset mismatch".to_string());
            }
            if batch.withdrawal_count > self.config.max_batch_withdrawals {
                return Err("settlement batch exceeds configured withdrawal limit".to_string());
            }
            if self.config.require_pq_approval
                && matches!(
                    batch.status,
                    SettlementBatchStatus::Approved
                        | SettlementBatchStatus::Submitted
                        | SettlementBatchStatus::Confirming
                        | SettlementBatchStatus::Settled
                )
                && !self.has_threshold_approval(
                    PqSettlementSubjectKind::SettlementBatch,
                    &batch.batch_id,
                )
            {
                return Err("settlement batch requires threshold pq approval".to_string());
            }
        }
        for manifest in self.anchor_manifests.values() {
            manifest.validate()?;
            if !self.batches.contains_key(&manifest.batch_id) {
                return Err("settlement manifest references missing batch".to_string());
            }
        }
        let mut release_nullifiers = BTreeSet::new();
        let mut release_replay_keys = BTreeSet::new();
        for release in self.release_plans.values() {
            release.validate()?;
            if !self.batches.contains_key(&release.batch_id) {
                return Err("withdrawal release references missing batch".to_string());
            }
            if !release_nullifiers.insert(release.account_nullifier.clone()) {
                return Err("withdrawal release nullifier reused".to_string());
            }
            if !release_replay_keys.insert(release.replay_key.clone()) {
                return Err("withdrawal release replay key reused".to_string());
            }
            if let Some(sponsor_lane_id) = &release.sponsor_lane_id {
                if !self.sponsor_lanes.contains_key(sponsor_lane_id) {
                    return Err("withdrawal release references missing sponsor lane".to_string());
                }
                if !release.lane.sponsor_eligible() {
                    return Err(
                        "withdrawal release sponsor lane used for ineligible lane".to_string()
                    );
                }
            }
            if let Some(authorization_id) = &release.reserve_spend_authorization_id {
                if !self
                    .reserve_spend_authorizations
                    .contains_key(authorization_id)
                {
                    return Err(
                        "withdrawal release references missing reserve authorization".to_string(),
                    );
                }
            }
        }
        for plan in self.fee_bump_plans.values() {
            plan.validate()?;
            if plan.fee_asset_id != self.config.fee_asset_id {
                return Err("fee bump asset mismatch".to_string());
            }
            if plan.bump_multiplier_bps > self.config.max_fee_bump_multiplier_bps {
                return Err("fee bump multiplier exceeds policy".to_string());
            }
            if !self.batches.contains_key(&plan.batch_id) {
                return Err("fee bump references missing batch".to_string());
            }
            if let Some(release_id) = &plan.release_id {
                if !self.release_plans.contains_key(release_id) {
                    return Err("fee bump references missing release".to_string());
                }
            }
            if let Some(sponsor_lane_id) = &plan.sponsor_lane_id {
                if !self.sponsor_lanes.contains_key(sponsor_lane_id) {
                    return Err("fee bump references missing sponsor lane".to_string());
                }
            }
        }
        for receipt in self.daemon_receipts.values() {
            receipt.validate()?;
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err("daemon receipt references missing batch".to_string());
            }
        }
        for authorization in self.reserve_spend_authorizations.values() {
            authorization.validate()?;
            if !self.batches.contains_key(&authorization.batch_id) {
                return Err("reserve authorization references missing batch".to_string());
            }
            if let Some(approval_id) = &authorization.pq_approval_id {
                if !self.pq_approvals.contains_key(approval_id) {
                    return Err("reserve authorization references missing pq approval".to_string());
                }
            }
        }
        let mut replay_keys = release_replay_keys;
        let mut protection_replay_keys = BTreeSet::new();
        let mut consumed_nullifiers = BTreeSet::new();
        for protection in self.replay_protections.values() {
            protection.validate()?;
            if !self.batches.contains_key(&protection.batch_id) {
                return Err("replay protection references missing batch".to_string());
            }
            if !replay_keys.insert(protection.replay_key.clone())
                && !self
                    .release_plans
                    .values()
                    .any(|release| release.replay_key == protection.replay_key)
            {
                return Err("replay protection key reused".to_string());
            }
            if !protection_replay_keys.insert(protection.replay_key.clone()) {
                return Err("replay protection key reused".to_string());
            }
            if protection.status == ReplayProtectionStatus::Consumed
                && !consumed_nullifiers.insert(protection.nullifier.clone())
            {
                return Err("replay protection nullifier consumed twice".to_string());
            }
        }
        for key in &self.reserved_replay_keys {
            ensure_non_empty(key, "reserved replay key")?;
            if !replay_keys.contains(key) {
                return Err("reserved replay key set contains unknown key".to_string());
            }
        }
        for key in &replay_keys {
            if !self.reserved_replay_keys.contains(key) {
                return Err("reserved replay key set is missing known key".to_string());
            }
        }
        for nullifier in &self.consumed_nullifiers {
            ensure_non_empty(nullifier, "consumed nullifier")?;
            if !consumed_nullifiers.contains(nullifier) {
                return Err("consumed nullifier set contains unknown nullifier".to_string());
            }
        }
        for nullifier in &consumed_nullifiers {
            if !self.consumed_nullifiers.contains(nullifier) {
                return Err("consumed nullifier set is missing known nullifier".to_string());
            }
        }
        for lane in self.sponsor_lanes.values() {
            lane.validate()?;
            if lane.fee_asset_id != self.config.fee_asset_id {
                return Err("sponsor lane fee asset mismatch".to_string());
            }
            if let Some(batch_id) = &lane.batch_id {
                if !self.batches.contains_key(batch_id) {
                    return Err("sponsor lane references missing batch".to_string());
                }
            }
        }
        for approval in self.pq_approvals.values() {
            approval.validate()?;
            if approval.security_bits < self.config.min_pq_security_bits {
                return Err("pq approval does not meet configured security floor".to_string());
            }
            if approval.quorum_weight != self.config.pq_approval_quorum_weight {
                return Err("pq approval quorum weight mismatch".to_string());
            }
            self.ensure_subject_exists(approval.subject_kind, &approval.subject_id)?;
        }
        for signal in self.reorg_signals.values() {
            signal.validate()?;
            if !self.batches.contains_key(&signal.batch_id) {
                return Err("reorg signal references missing batch".to_string());
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn batch_root(&self) -> String {
        monero_settlement_adapter_batch_collection_root(
            &self.batches.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn anchor_manifest_root(&self) -> String {
        monero_settlement_adapter_anchor_manifest_collection_root(
            &self.anchor_manifests.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn release_plan_root(&self) -> String {
        monero_settlement_adapter_release_collection_root(
            &self.release_plans.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn fee_bump_plan_root(&self) -> String {
        monero_settlement_adapter_fee_bump_collection_root(
            &self.fee_bump_plans.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn daemon_receipt_root(&self) -> String {
        monero_settlement_adapter_daemon_receipt_collection_root(
            &self.daemon_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reserve_authorization_root(&self) -> String {
        monero_settlement_adapter_reserve_authorization_collection_root(
            &self
                .reserve_spend_authorizations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn replay_protection_root(&self) -> String {
        monero_settlement_adapter_replay_protection_collection_root(
            &self
                .replay_protections
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_lane_root(&self) -> String {
        monero_settlement_adapter_sponsor_lane_collection_root(
            &self.sponsor_lanes.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn pq_approval_root(&self) -> String {
        monero_settlement_adapter_pq_approval_collection_root(
            &self.pq_approvals.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reorg_signal_root(&self) -> String {
        monero_settlement_adapter_reorg_signal_collection_root(
            &self.reorg_signals.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn event_root(&self) -> String {
        monero_settlement_adapter_event_collection_root(
            &self.events.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn replay_key_set_root(&self) -> String {
        let keys = self
            .reserved_replay_keys
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        monero_settlement_adapter_string_set_root("MONERO-SETTLEMENT-REPLAY-KEY-SET", &keys)
    }

    pub fn nullifier_set_root(&self) -> String {
        let nullifiers = self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>();
        monero_settlement_adapter_string_set_root(
            "MONERO-SETTLEMENT-CONSUMED-NULLIFIER-SET",
            &nullifiers,
        )
    }

    fn public_record_without_state_root(
        &self,
        counters: &MoneroSettlementAdapterCounters,
    ) -> Value {
        json!({
            "kind": "monero_settlement_adapter_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION,
            "height": self.height,
            "network": self.network,
            "observed_monero_height": self.observed_monero_height,
            "observed_monero_block_hash": self.observed_monero_block_hash,
            "next_event_sequence": self.next_event_sequence,
            "config": self.config.public_record(),
            "roots": {
                "config_root": self.config.config_root(),
                "batch_root": self.batch_root(),
                "anchor_manifest_root": self.anchor_manifest_root(),
                "release_plan_root": self.release_plan_root(),
                "fee_bump_plan_root": self.fee_bump_plan_root(),
                "daemon_receipt_root": self.daemon_receipt_root(),
                "reserve_authorization_root": self.reserve_authorization_root(),
                "replay_protection_root": self.replay_protection_root(),
                "sponsor_lane_root": self.sponsor_lane_root(),
                "pq_approval_root": self.pq_approval_root(),
                "reorg_signal_root": self.reorg_signal_root(),
                "event_root": self.event_root(),
                "replay_key_set_root": self.replay_key_set_root(),
                "nullifier_set_root": self.nullifier_set_root(),
                "counters_root": counters.counters_root(),
            },
            "counters": counters.public_record(),
        })
    }

    fn record_event(
        &mut self,
        event_kind: SettlementAdapterEventKind,
        subject_id: String,
        event_root: String,
    ) -> MoneroSettlementAdapterResult<String> {
        let event = SettlementAdapterEvent::new(
            self.next_event_sequence,
            self.height,
            event_kind,
            subject_id,
            event_root,
        )?;
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        let root = event.record_root();
        self.events.insert(event.event_id.clone(), event);
        Ok(root)
    }

    fn ensure_subject_exists(
        &self,
        subject_kind: PqSettlementSubjectKind,
        subject_id: &str,
    ) -> MoneroSettlementAdapterResult<()> {
        ensure_non_empty(subject_id, "pq approval subject id")?;
        let exists = match subject_kind {
            PqSettlementSubjectKind::SettlementBatch => self.batches.contains_key(subject_id),
            PqSettlementSubjectKind::AnchorManifest => {
                self.anchor_manifests.contains_key(subject_id)
            }
            PqSettlementSubjectKind::WithdrawalRelease => {
                self.release_plans.contains_key(subject_id)
            }
            PqSettlementSubjectKind::ReserveSpend => {
                self.reserve_spend_authorizations.contains_key(subject_id)
            }
            PqSettlementSubjectKind::FeeBump => self.fee_bump_plans.contains_key(subject_id),
            PqSettlementSubjectKind::SponsorLane => self.sponsor_lanes.contains_key(subject_id),
        };
        if exists {
            Ok(())
        } else {
            Err("pq approval references missing subject".to_string())
        }
    }

    fn has_threshold_approval(
        &self,
        subject_kind: PqSettlementSubjectKind,
        subject_id: &str,
    ) -> bool {
        let mut weight = 0_u64;
        for approval in self.pq_approvals.values() {
            if approval.subject_kind == subject_kind
                && approval.subject_id == subject_id
                && approval.status.is_usable()
            {
                weight = weight.saturating_add(approval.weight);
            }
        }
        weight >= self.config.pq_approval_quorum_weight
    }
}

pub fn monero_settlement_adapter_state_root_from_record(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-ADAPTER-STATE", record)
}

pub fn monero_settlement_adapter_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_settlement_adapter_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_SETTLEMENT_ADAPTER_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_settlement_adapter_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn monero_settlement_adapter_config_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-CONFIG-ID", record)
}

pub fn monero_settlement_adapter_batch_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-BATCH-ID", record)
}

pub fn monero_settlement_adapter_anchor_manifest_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-ANCHOR-MANIFEST-ID", record)
}

pub fn monero_settlement_adapter_release_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-RELEASE-ID", record)
}

pub fn monero_settlement_adapter_fee_bump_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-FEE-BUMP-ID", record)
}

pub fn monero_settlement_adapter_daemon_receipt_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-DAEMON-RECEIPT-ID", record)
}

pub fn monero_settlement_adapter_reserve_authorization_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-RESERVE-AUTHORIZATION-ID", record)
}

pub fn monero_settlement_adapter_replay_protection_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-REPLAY-PROTECTION-ID", record)
}

pub fn monero_settlement_adapter_sponsor_lane_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-SPONSOR-LANE-ID", record)
}

pub fn monero_settlement_adapter_pq_approval_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-PQ-APPROVAL-ID", record)
}

pub fn monero_settlement_adapter_reorg_signal_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-REORG-SIGNAL-ID", record)
}

pub fn monero_settlement_adapter_event_id(record: &Value) -> String {
    monero_settlement_adapter_payload_root("MONERO-SETTLEMENT-EVENT-ID", record)
}

pub fn monero_settlement_adapter_batch_collection_root(
    records: &[MoneroSettlementBatch],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-BATCH-COLLECTION",
        records
            .iter()
            .map(|record| (record.batch_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_anchor_manifest_collection_root(
    records: &[SettlementAnchorManifest],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-ANCHOR-MANIFEST-COLLECTION",
        records
            .iter()
            .map(|record| (record.manifest_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_release_collection_root(
    records: &[WithdrawalReleasePlan],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-RELEASE-COLLECTION",
        records
            .iter()
            .map(|record| (record.release_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_fee_bump_collection_root(records: &[TxFeeBumpPlan]) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-FEE-BUMP-COLLECTION",
        records
            .iter()
            .map(|record| (record.fee_bump_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_daemon_receipt_collection_root(
    records: &[DaemonSubmissionReceipt],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-DAEMON-RECEIPT-COLLECTION",
        records
            .iter()
            .map(|record| (record.receipt_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_reserve_authorization_collection_root(
    records: &[ReserveSpendAuthorization],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-RESERVE-AUTHORIZATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.authorization_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_replay_protection_collection_root(
    records: &[ReplayProtectionRecord],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-REPLAY-PROTECTION-COLLECTION",
        records
            .iter()
            .map(|record| (record.protection_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_sponsor_lane_collection_root(
    records: &[LowFeeSponsorSettlementLane],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-SPONSOR-LANE-COLLECTION",
        records
            .iter()
            .map(|record| (record.lane_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_pq_approval_collection_root(
    records: &[PqSettlementApproval],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-PQ-APPROVAL-COLLECTION",
        records
            .iter()
            .map(|record| (record.approval_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_reorg_signal_collection_root(records: &[ReorgSignal]) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-REORG-SIGNAL-COLLECTION",
        records
            .iter()
            .map(|record| (record.signal_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_settlement_adapter_event_collection_root(
    records: &[SettlementAdapterEvent],
) -> String {
    keyed_value_root(
        "MONERO-SETTLEMENT-EVENT-COLLECTION",
        records
            .iter()
            .map(|record| (record.event_id.clone(), record.public_record()))
            .collect(),
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

fn with_string_field(mut record: Value, field: &str, value: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(value));
    }
    record
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroSettlementAdapterResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_optional_non_empty(
    value: &Option<String>,
    label: &str,
) -> MoneroSettlementAdapterResult<()> {
    if let Some(value) = value {
        ensure_non_empty(value, label)
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroSettlementAdapterResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroSettlementAdapterResult<()> {
    if value > MONERO_SETTLEMENT_ADAPTER_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_expiry(
    start_height: u64,
    expires_at_height: u64,
    label: &str,
) -> MoneroSettlementAdapterResult<()> {
    if expires_at_height <= start_height {
        Err(format!("{label} expiry must be after start height"))
    } else {
        Ok(())
    }
}

fn ensure_height_range(
    start_height: u64,
    end_height: u64,
    label: &str,
) -> MoneroSettlementAdapterResult<()> {
    if end_height < start_height {
        Err(format!("{label} end height precedes start height"))
    } else {
        Ok(())
    }
}

fn ensure_lane_set(lanes: &[SettlementLane], label: &str) -> MoneroSettlementAdapterResult<()> {
    if lanes.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for lane in lanes {
        if !seen.insert(lane.as_str().to_string()) {
            return Err(format!("{label} contains duplicate lane"));
        }
    }
    Ok(())
}
