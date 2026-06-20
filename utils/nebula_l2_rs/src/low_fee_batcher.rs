use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeBatcherResult<T> = Result<T, String>;

pub const LOW_FEE_BATCHER_PROTOCOL_VERSION: &str = "nebula-low-fee-batcher-v1";
pub const LOW_FEE_BATCHER_PQ_AUTH_SCHEME: &str = "ml-dsa-65-low-fee-batch-auth-v1";
pub const LOW_FEE_BATCHER_ROUTE_COMMITMENT_SCHEME: &str =
    "shake256-private-batch-route-commitment-v1";
pub const LOW_FEE_BATCHER_DEVNET_HEIGHT: u64 = 144;
pub const LOW_FEE_BATCHER_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const LOW_FEE_BATCHER_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const LOW_FEE_BATCHER_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 128;
pub const LOW_FEE_BATCHER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const LOW_FEE_BATCHER_DEFAULT_MAX_INTENT_WEIGHT: u64 = 80_000;
pub const LOW_FEE_BATCHER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 4_500_000;
pub const LOW_FEE_BATCHER_DEFAULT_TARGET_DISCOUNT_BPS: u64 = 7_000;
pub const LOW_FEE_BATCHER_DEFAULT_MAX_SPONSOR_SHARE_BPS: u64 = 8_500;
pub const LOW_FEE_BATCHER_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeBatchLane {
    PrivateTransfer,
    PrivateSwap,
    ContractCall,
    Lending,
    BridgeExit,
    ProofMaintenance,
    WalletSync,
}

impl LowFeeBatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::Lending => "lending",
            Self::BridgeExit => "bridge_exit",
            Self::ProofMaintenance => "proof_maintenance",
            Self::WalletSync => "wallet_sync",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::BridgeExit => 1_000,
            Self::PrivateSwap => 880,
            Self::Lending => 820,
            Self::ContractCall => 760,
            Self::PrivateTransfer => 720,
            Self::WalletSync => 420,
            Self::ProofMaintenance => 320,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::PrivateSwap | Self::ContractCall | Self::Lending
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchIntentKind {
    ShieldedTransfer,
    PrivateAmmSwap,
    ConfidentialLoan,
    ContractInvocation,
    BridgeWithdrawal,
    ProofAggregation,
    WalletMaintenance,
}

impl BatchIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedTransfer => "shielded_transfer",
            Self::PrivateAmmSwap => "private_amm_swap",
            Self::ConfidentialLoan => "confidential_loan",
            Self::ContractInvocation => "contract_invocation",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletMaintenance => "wallet_maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchIntentStatus {
    Queued,
    Reserved,
    Packed,
    Settled,
    Expired,
    Cancelled,
}

impl BatchIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Reserved => "reserved",
            Self::Packed => "packed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Queued | Self::Reserved | Self::Packed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Available,
    Reserved,
    Consumed,
    Slashed,
    Expired,
    Paused,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Available | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBidPrivacyClass {
    Public,
    Bucketed,
    Encrypted,
    StealthSponsored,
}

impl FeeBidPrivacyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Bucketed => "bucketed",
            Self::Encrypted => "encrypted",
            Self::StealthSponsored => "stealth_sponsored",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchExecutionStatus {
    Open,
    Sealed,
    Proving,
    Posted,
    Challenged,
    Finalized,
    Abandoned,
}

impl BatchExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Posted => "posted",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Abandoned => "abandoned",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Proving | Self::Posted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBatchAuthorizationSubject {
    UserIntent,
    SponsorBudget,
    BatchPlan,
    SettlementReceipt,
    EmergencyCancel,
}

impl PqBatchAuthorizationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserIntent => "user_intent",
            Self::SponsorBudget => "sponsor_budget",
            Self::BatchPlan => "batch_plan",
            Self::SettlementReceipt => "settlement_receipt",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBatchAuthorizationStatus {
    Pending,
    Accepted,
    Superseded,
    Revoked,
    Expired,
}

impl PqBatchAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatcherConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub batch_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_intent_weight: u64,
    pub max_batch_weight: u64,
    pub target_discount_bps: u64,
    pub max_sponsor_share_bps: u64,
    pub min_reserve_coverage_bps: u64,
}

impl LowFeeBatcherConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: LOW_FEE_BATCHER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            batch_window_blocks: LOW_FEE_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS,
            receipt_ttl_blocks: LOW_FEE_BATCHER_DEFAULT_RECEIPT_TTL_BLOCKS,
            sponsor_ttl_blocks: LOW_FEE_BATCHER_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_privacy_set_size: LOW_FEE_BATCHER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_intent_weight: LOW_FEE_BATCHER_DEFAULT_MAX_INTENT_WEIGHT,
            max_batch_weight: LOW_FEE_BATCHER_DEFAULT_MAX_BATCH_WEIGHT,
            target_discount_bps: LOW_FEE_BATCHER_DEFAULT_TARGET_DISCOUNT_BPS,
            max_sponsor_share_bps: LOW_FEE_BATCHER_DEFAULT_MAX_SPONSOR_SHARE_BPS,
            min_reserve_coverage_bps: LOW_FEE_BATCHER_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
        }
    }

    pub fn validate(&self) -> LowFeeBatcherResult<()> {
        if self.protocol_version != LOW_FEE_BATCHER_PROTOCOL_VERSION {
            return Err("low-fee batcher protocol version mismatch".to_string());
        }
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_positive("batch_window_blocks", self.batch_window_blocks)?;
        ensure_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        ensure_positive("sponsor_ttl_blocks", self.sponsor_ttl_blocks)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("max_intent_weight", self.max_intent_weight)?;
        ensure_positive("max_batch_weight", self.max_batch_weight)?;
        ensure_bps("target_discount_bps", self.target_discount_bps)?;
        ensure_bps("max_sponsor_share_bps", self.max_sponsor_share_bps)?;
        if self.max_batch_weight < self.max_intent_weight {
            return Err("max_batch_weight is below max_intent_weight".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "batch_window_blocks": self.batch_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_intent_weight": self.max_intent_weight,
            "max_batch_weight": self.max_batch_weight,
            "target_discount_bps": self.target_discount_bps,
            "max_sponsor_share_bps": self.max_sponsor_share_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
        })
    }

    pub fn config_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatchIntent {
    pub intent_id: String,
    pub lane: LowFeeBatchLane,
    pub kind: BatchIntentKind,
    pub status: BatchIntentStatus,
    pub user_commitment: String,
    pub encrypted_payload_root: String,
    pub route_commitment: String,
    pub fee_bid_commitment: String,
    pub max_fee_micro_units: u64,
    pub expected_discount_bps: u64,
    pub sponsor_id: Option<String>,
    pub privacy_set_target: u64,
    pub intent_weight: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
    pub pq_authorization_ids: Vec<String>,
}

impl LowFeeBatchIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: LowFeeBatchLane,
        kind: BatchIntentKind,
        user_commitment: &str,
        encrypted_payload_root: &str,
        route_commitment: &str,
        fee_bid_commitment: &str,
        max_fee_micro_units: u64,
        expected_discount_bps: u64,
        sponsor_id: Option<String>,
        privacy_set_target: u64,
        intent_weight: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        nullifier_root: &str,
        pq_authorization_ids: Vec<String>,
    ) -> LowFeeBatcherResult<Self> {
        let intent_id = low_fee_batch_intent_id(
            lane,
            kind,
            user_commitment,
            encrypted_payload_root,
            opened_at_height,
        );
        let intent = Self {
            intent_id,
            lane,
            kind,
            status: BatchIntentStatus::Queued,
            user_commitment: user_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            route_commitment: route_commitment.to_string(),
            fee_bid_commitment: fee_bid_commitment.to_string(),
            max_fee_micro_units,
            expected_discount_bps,
            sponsor_id,
            privacy_set_target,
            intent_weight,
            opened_at_height,
            expires_at_height,
            nullifier_root: nullifier_root.to_string(),
            pq_authorization_ids,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "user_commitment": self.user_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "route_commitment": self.route_commitment,
            "fee_bid_commitment": self.fee_bid_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "expected_discount_bps": self.expected_discount_bps,
            "sponsor_id": self.sponsor_id,
            "privacy_set_target": self.privacy_set_target,
            "intent_weight": self.intent_weight,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_ids": self.pq_authorization_ids,
        })
    }

    pub fn intent_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-INTENT", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        ensure_non_empty("intent_id", &self.intent_id)?;
        ensure_non_empty("user_commitment", &self.user_commitment)?;
        ensure_non_empty("encrypted_payload_root", &self.encrypted_payload_root)?;
        ensure_non_empty("route_commitment", &self.route_commitment)?;
        ensure_non_empty("fee_bid_commitment", &self.fee_bid_commitment)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_positive("max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_positive("privacy_set_target", self.privacy_set_target)?;
        ensure_positive("intent_weight", self.intent_weight)?;
        ensure_bps("expected_discount_bps", self.expected_discount_bps)?;
        ensure_height_window(self.opened_at_height, self.expires_at_height, "intent")?;
        ensure_unique_strings(&self.pq_authorization_ids, "intent pq_authorization_ids")?;
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorBudget {
    pub sponsor_id: String,
    pub status: SponsorReservationStatus,
    pub sponsor_commitment: String,
    pub treasury_asset_id: String,
    pub reserve_proof_root: String,
    pub total_budget_micro_units: u64,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub max_per_intent_micro_units: u64,
    pub allowed_lanes: Vec<LowFeeBatchLane>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub pq_authorization_ids: Vec<String>,
}

impl LowFeeSponsorBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        treasury_asset_id: &str,
        reserve_proof_root: &str,
        total_budget_micro_units: u64,
        reserved_micro_units: u64,
        consumed_micro_units: u64,
        max_per_intent_micro_units: u64,
        allowed_lanes: Vec<LowFeeBatchLane>,
        opened_at_height: u64,
        expires_at_height: u64,
        pq_authorization_ids: Vec<String>,
    ) -> LowFeeBatcherResult<Self> {
        let sponsor_id = low_fee_sponsor_budget_id(
            sponsor_commitment,
            treasury_asset_id,
            reserve_proof_root,
            opened_at_height,
        );
        let budget = Self {
            sponsor_id,
            status: SponsorReservationStatus::Available,
            sponsor_commitment: sponsor_commitment.to_string(),
            treasury_asset_id: treasury_asset_id.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            total_budget_micro_units,
            reserved_micro_units,
            consumed_micro_units,
            max_per_intent_micro_units,
            allowed_lanes,
            opened_at_height,
            expires_at_height,
            pq_authorization_ids,
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn available_micro_units(&self) -> u64 {
        self.total_budget_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.consumed_micro_units)
    }

    pub fn public_record(&self) -> Value {
        let allowed_lanes = self
            .allowed_lanes
            .iter()
            .map(|lane| lane.as_str())
            .collect::<Vec<_>>();
        json!({
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "treasury_asset_id": self.treasury_asset_id,
            "reserve_proof_root": self.reserve_proof_root,
            "total_budget_micro_units": self.total_budget_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "available_micro_units": self.available_micro_units(),
            "max_per_intent_micro_units": self.max_per_intent_micro_units,
            "allowed_lanes": allowed_lanes,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_authorization_ids": self.pq_authorization_ids,
        })
    }

    pub fn budget_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-SPONSOR-BUDGET", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        ensure_non_empty("sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("treasury_asset_id", &self.treasury_asset_id)?;
        ensure_non_empty("reserve_proof_root", &self.reserve_proof_root)?;
        ensure_positive("total_budget_micro_units", self.total_budget_micro_units)?;
        ensure_positive(
            "max_per_intent_micro_units",
            self.max_per_intent_micro_units,
        )?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "sponsor budget",
        )?;
        if self
            .consumed_micro_units
            .saturating_add(self.reserved_micro_units)
            > self.total_budget_micro_units
        {
            return Err("sponsor budget over-reserved".to_string());
        }
        if self.allowed_lanes.is_empty() {
            return Err("sponsor budget has no allowed lanes".to_string());
        }
        ensure_unique_strings(&self.pq_authorization_ids, "sponsor pq_authorization_ids")?;
        Ok(self.budget_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatchWindow {
    pub window_id: String,
    pub lane: LowFeeBatchLane,
    pub status: BatchExecutionStatus,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub target_weight: u64,
    pub reserved_weight: u64,
    pub min_privacy_set_size: u64,
    pub target_discount_bps: u64,
    pub sponsor_share_bps: u64,
    pub route_policy_root: String,
    pub packed_intent_ids: Vec<String>,
}

impl LowFeeBatchWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: LowFeeBatchLane,
        opened_at_height: u64,
        closes_at_height: u64,
        target_weight: u64,
        reserved_weight: u64,
        min_privacy_set_size: u64,
        target_discount_bps: u64,
        sponsor_share_bps: u64,
        route_policy_root: &str,
        packed_intent_ids: Vec<String>,
    ) -> LowFeeBatcherResult<Self> {
        let window_id = low_fee_batch_window_id(lane, opened_at_height, route_policy_root);
        let window = Self {
            window_id,
            lane,
            status: BatchExecutionStatus::Open,
            opened_at_height,
            closes_at_height,
            target_weight,
            reserved_weight,
            min_privacy_set_size,
            target_discount_bps,
            sponsor_share_bps,
            route_policy_root: route_policy_root.to_string(),
            packed_intent_ids,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "target_weight": self.target_weight,
            "reserved_weight": self.reserved_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_discount_bps": self.target_discount_bps,
            "sponsor_share_bps": self.sponsor_share_bps,
            "route_policy_root": self.route_policy_root,
            "packed_intent_ids": self.packed_intent_ids,
        })
    }

    pub fn window_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("route_policy_root", &self.route_policy_root)?;
        ensure_height_window(self.opened_at_height, self.closes_at_height, "batch window")?;
        ensure_positive("target_weight", self.target_weight)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps("target_discount_bps", self.target_discount_bps)?;
        ensure_bps("sponsor_share_bps", self.sponsor_share_bps)?;
        if self.reserved_weight > self.target_weight {
            return Err("batch window reserved_weight exceeds target_weight".to_string());
        }
        ensure_unique_strings(&self.packed_intent_ids, "window packed_intent_ids")?;
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExecutionPlan {
    pub plan_id: String,
    pub window_id: String,
    pub status: BatchExecutionStatus,
    pub sequencer_commitment: String,
    pub ordered_intent_root: String,
    pub net_fee_commitment: String,
    pub sponsor_debit_root: String,
    pub proof_request_root: String,
    pub expected_settlement_height: u64,
    pub max_posted_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_ids: Vec<String>,
}

impl LowFeeExecutionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        sequencer_commitment: &str,
        ordered_intent_root: &str,
        net_fee_commitment: &str,
        sponsor_debit_root: &str,
        proof_request_root: &str,
        expected_settlement_height: u64,
        max_posted_fee_micro_units: u64,
        privacy_set_size: u64,
        pq_authorization_ids: Vec<String>,
    ) -> LowFeeBatcherResult<Self> {
        let plan_id = low_fee_execution_plan_id(
            window_id,
            sequencer_commitment,
            ordered_intent_root,
            expected_settlement_height,
        );
        let plan = Self {
            plan_id,
            window_id: window_id.to_string(),
            status: BatchExecutionStatus::Sealed,
            sequencer_commitment: sequencer_commitment.to_string(),
            ordered_intent_root: ordered_intent_root.to_string(),
            net_fee_commitment: net_fee_commitment.to_string(),
            sponsor_debit_root: sponsor_debit_root.to_string(),
            proof_request_root: proof_request_root.to_string(),
            expected_settlement_height,
            max_posted_fee_micro_units,
            privacy_set_size,
            pq_authorization_ids,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "window_id": self.window_id,
            "status": self.status.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "ordered_intent_root": self.ordered_intent_root,
            "net_fee_commitment": self.net_fee_commitment,
            "sponsor_debit_root": self.sponsor_debit_root,
            "proof_request_root": self.proof_request_root,
            "expected_settlement_height": self.expected_settlement_height,
            "max_posted_fee_micro_units": self.max_posted_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_ids": self.pq_authorization_ids,
        })
    }

    pub fn plan_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-EXECUTION-PLAN", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        ensure_non_empty("plan_id", &self.plan_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("sequencer_commitment", &self.sequencer_commitment)?;
        ensure_non_empty("ordered_intent_root", &self.ordered_intent_root)?;
        ensure_non_empty("net_fee_commitment", &self.net_fee_commitment)?;
        ensure_non_empty("sponsor_debit_root", &self.sponsor_debit_root)?;
        ensure_non_empty("proof_request_root", &self.proof_request_root)?;
        ensure_positive(
            "expected_settlement_height",
            self.expected_settlement_height,
        )?;
        ensure_positive(
            "max_posted_fee_micro_units",
            self.max_posted_fee_micro_units,
        )?;
        ensure_positive("privacy_set_size", self.privacy_set_size)?;
        ensure_unique_strings(&self.pq_authorization_ids, "plan pq_authorization_ids")?;
        Ok(self.plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettlementReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub batch_root: String,
    pub proof_root: String,
    pub posted_fee_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub user_paid_micro_units: u64,
    pub realized_discount_bps: u64,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
    pub monero_anchor_id: Option<String>,
    pub pq_authorization_ids: Vec<String>,
}

impl LowFeeSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: &str,
        batch_root: &str,
        proof_root: &str,
        posted_fee_micro_units: u64,
        sponsor_paid_micro_units: u64,
        user_paid_micro_units: u64,
        realized_discount_bps: u64,
        settled_at_height: u64,
        expires_at_height: u64,
        monero_anchor_id: Option<String>,
        pq_authorization_ids: Vec<String>,
    ) -> LowFeeBatcherResult<Self> {
        let receipt_id =
            low_fee_settlement_receipt_id(plan_id, batch_root, proof_root, settled_at_height);
        let receipt = Self {
            receipt_id,
            plan_id: plan_id.to_string(),
            batch_root: batch_root.to_string(),
            proof_root: proof_root.to_string(),
            posted_fee_micro_units,
            sponsor_paid_micro_units,
            user_paid_micro_units,
            realized_discount_bps,
            settled_at_height,
            expires_at_height,
            monero_anchor_id,
            pq_authorization_ids,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "batch_root": self.batch_root,
            "proof_root": self.proof_root,
            "posted_fee_micro_units": self.posted_fee_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "user_paid_micro_units": self.user_paid_micro_units,
            "realized_discount_bps": self.realized_discount_bps,
            "settled_at_height": self.settled_at_height,
            "expires_at_height": self.expires_at_height,
            "monero_anchor_id": self.monero_anchor_id,
            "pq_authorization_ids": self.pq_authorization_ids,
        })
    }

    pub fn receipt_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-SETTLEMENT-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("plan_id", &self.plan_id)?;
        ensure_non_empty("batch_root", &self.batch_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_positive("posted_fee_micro_units", self.posted_fee_micro_units)?;
        ensure_bps("realized_discount_bps", self.realized_discount_bps)?;
        ensure_height_window(
            self.settled_at_height,
            self.expires_at_height,
            "settlement receipt",
        )?;
        ensure_unique_strings(&self.pq_authorization_ids, "receipt pq_authorization_ids")?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBatchAuthorization {
    pub authorization_id: String,
    pub subject: PqBatchAuthorizationSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub status: PqBatchAuthorizationStatus,
    pub signer_commitment: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqBatchAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: PqBatchAuthorizationSubject,
        subject_id: &str,
        subject_root: &str,
        signer_commitment: &str,
        public_key_commitment: &str,
        signature_root: &str,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> LowFeeBatcherResult<Self> {
        let authorization_id = pq_batch_authorization_id(
            subject,
            subject_id,
            subject_root,
            signer_commitment,
            signed_at_height,
        );
        let authorization = Self {
            authorization_id,
            subject,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            status: PqBatchAuthorizationStatus::Accepted,
            signer_commitment: signer_commitment.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            signature_root: signature_root.to_string(),
            signed_at_height,
            expires_at_height,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "subject": self.subject.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "status": self.status.as_str(),
            "scheme": LOW_FEE_BATCHER_PQ_AUTH_SCHEME,
            "signer_commitment": self.signer_commitment,
            "public_key_commitment": self.public_key_commitment,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn authorization_root(&self) -> String {
        low_fee_batcher_payload_root("LOW-FEE-BATCHER-PQ-AUTHORIZATION", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        ensure_non_empty("authorization_id", &self.authorization_id)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("subject_root", &self.subject_root)?;
        ensure_non_empty("signer_commitment", &self.signer_commitment)?;
        ensure_non_empty("public_key_commitment", &self.public_key_commitment)?;
        ensure_non_empty("signature_root", &self.signature_root)?;
        ensure_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "pq authorization",
        )?;
        Ok(self.authorization_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatcherRoots {
    pub config_root: String,
    pub intent_root: String,
    pub sponsor_budget_root: String,
    pub batch_window_root: String,
    pub execution_plan_root: String,
    pub settlement_receipt_root: String,
    pub pq_authorization_root: String,
    pub public_record_root: String,
}

impl LowFeeBatcherRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "sponsor_budget_root": self.sponsor_budget_root,
            "batch_window_root": self.batch_window_root,
            "execution_plan_root": self.execution_plan_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "pq_authorization_root": self.pq_authorization_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatcherCounters {
    pub intent_count: u64,
    pub live_intent_count: u64,
    pub sponsor_budget_count: u64,
    pub spendable_sponsor_budget_count: u64,
    pub batch_window_count: u64,
    pub live_batch_window_count: u64,
    pub execution_plan_count: u64,
    pub live_execution_plan_count: u64,
    pub settlement_receipt_count: u64,
    pub pq_authorization_count: u64,
    pub usable_pq_authorization_count: u64,
    pub total_sponsor_budget_micro_units: u64,
    pub available_sponsor_budget_micro_units: u64,
    pub pending_intent_weight: u64,
}

impl LowFeeBatcherCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_count": self.intent_count,
            "live_intent_count": self.live_intent_count,
            "sponsor_budget_count": self.sponsor_budget_count,
            "spendable_sponsor_budget_count": self.spendable_sponsor_budget_count,
            "batch_window_count": self.batch_window_count,
            "live_batch_window_count": self.live_batch_window_count,
            "execution_plan_count": self.execution_plan_count,
            "live_execution_plan_count": self.live_execution_plan_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "pq_authorization_count": self.pq_authorization_count,
            "usable_pq_authorization_count": self.usable_pq_authorization_count,
            "total_sponsor_budget_micro_units": self.total_sponsor_budget_micro_units,
            "available_sponsor_budget_micro_units": self.available_sponsor_budget_micro_units,
            "pending_intent_weight": self.pending_intent_weight,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatcherState {
    pub config: LowFeeBatcherConfig,
    pub height: u64,
    pub intents: BTreeMap<String, LowFeeBatchIntent>,
    pub sponsor_budgets: BTreeMap<String, LowFeeSponsorBudget>,
    pub batch_windows: BTreeMap<String, LowFeeBatchWindow>,
    pub execution_plans: BTreeMap<String, LowFeeExecutionPlan>,
    pub settlement_receipts: BTreeMap<String, LowFeeSettlementReceipt>,
    pub pq_authorizations: BTreeMap<String, PqBatchAuthorization>,
    pub public_records: BTreeMap<String, Value>,
}

impl LowFeeBatcherState {
    pub fn new(config: LowFeeBatcherConfig) -> LowFeeBatcherResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            intents: BTreeMap::new(),
            sponsor_budgets: BTreeMap::new(),
            batch_windows: BTreeMap::new(),
            execution_plans: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> LowFeeBatcherResult<Self> {
        let mut state = Self::new(LowFeeBatcherConfig::devnet())?;
        state.height = LOW_FEE_BATCHER_DEVNET_HEIGHT;

        let sponsor = LowFeeSponsorBudget::new(
            "devnet-low-fee-sponsor",
            "asset:wxmr",
            "reserve-proof-root:devnet-low-fee-sponsor",
            900_000_000,
            120_000_000,
            15_000_000,
            5_000_000,
            vec![
                LowFeeBatchLane::PrivateTransfer,
                LowFeeBatchLane::PrivateSwap,
                LowFeeBatchLane::ContractCall,
                LowFeeBatchLane::BridgeExit,
            ],
            state.height,
            state.height + state.config.sponsor_ttl_blocks,
            Vec::new(),
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor_budget(sponsor)?;

        let intent = LowFeeBatchIntent::new(
            LowFeeBatchLane::PrivateSwap,
            BatchIntentKind::PrivateAmmSwap,
            "user-commitment:devnet-private-swap",
            "encrypted-payload-root:devnet-private-swap",
            "route-commitment:devnet-private-swap",
            "fee-bid-commitment:devnet-private-swap",
            140_000,
            7_200,
            Some(sponsor_id.clone()),
            state.config.min_privacy_set_size,
            42_000,
            state.height,
            state.height + state.config.batch_window_blocks,
            "nullifier-root:devnet-private-swap",
            Vec::new(),
        )?;
        let intent_id = intent.intent_id.clone();
        state.insert_intent(intent)?;

        let window = LowFeeBatchWindow::new(
            LowFeeBatchLane::PrivateSwap,
            state.height,
            state.height + state.config.batch_window_blocks,
            1_000_000,
            42_000,
            state.config.min_privacy_set_size,
            state.config.target_discount_bps,
            6_000,
            "route-policy-root:devnet-private-swap-window",
            vec![intent_id.clone()],
        )?;
        let window_id = window.window_id.clone();
        state.insert_batch_window(window)?;

        let plan = LowFeeExecutionPlan::new(
            &window_id,
            "sequencer-commitment:devnet-low-fee-batch",
            &low_fee_batcher_string_set_root("LOW-FEE-BATCHER-ORDERED-INTENTS", &[intent_id]),
            "net-fee-commitment:devnet-low-fee-batch",
            &low_fee_batcher_string_set_root("LOW-FEE-BATCHER-SPONSOR-DEBITS", &[sponsor_id]),
            "proof-request-root:devnet-low-fee-batch",
            state.height + 2,
            80_000,
            96,
            Vec::new(),
        )?;
        let plan_id = plan.plan_id.clone();
        let plan_root = plan.plan_root();
        state.insert_execution_plan(plan)?;

        let auth = PqBatchAuthorization::new(
            PqBatchAuthorizationSubject::BatchPlan,
            &plan_id,
            &plan_root,
            "sequencer-pq-signer:devnet-low-fee-batch",
            "ml-dsa-public-key-commitment:devnet-low-fee-batch",
            "ml-dsa-signature-root:devnet-low-fee-batch",
            state.height,
            state.height + state.config.receipt_ttl_blocks,
        )?;
        state.insert_pq_authorization(auth)?;

        state.record_public_record(
            "devnet_low_fee_batcher_bootstrap",
            json!({
                "height": state.height,
                "lane": LowFeeBatchLane::PrivateSwap.as_str(),
                "route_commitment_scheme": LOW_FEE_BATCHER_ROUTE_COMMITMENT_SCHEME,
                "pq_authorization_scheme": LOW_FEE_BATCHER_PQ_AUTH_SCHEME,
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeBatcherResult<String> {
        if height < self.height {
            return Err("low-fee batcher height cannot move backwards".to_string());
        }
        self.height = height;
        for intent in self.intents.values_mut() {
            if intent.status.live() && intent.expires_at_height < height {
                intent.status = BatchIntentStatus::Expired;
            }
        }
        for budget in self.sponsor_budgets.values_mut() {
            if budget.status.spendable() && budget.expires_at_height < height {
                budget.status = SponsorReservationStatus::Expired;
            }
        }
        for auth in self.pq_authorizations.values_mut() {
            if auth.status.usable() && auth.expires_at_height < height {
                auth.status = PqBatchAuthorizationStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn insert_intent(&mut self, intent: LowFeeBatchIntent) -> LowFeeBatcherResult<String> {
        let root = intent.validate()?;
        if intent.intent_weight > self.config.max_intent_weight {
            return Err("intent weight exceeds configured maximum".to_string());
        }
        if intent.privacy_set_target < self.config.min_privacy_set_size {
            return Err("intent privacy set target below configured minimum".to_string());
        }
        self.intents.insert(intent.intent_id.clone(), intent);
        Ok(root)
    }

    pub fn insert_sponsor_budget(
        &mut self,
        budget: LowFeeSponsorBudget,
    ) -> LowFeeBatcherResult<String> {
        let root = budget.validate()?;
        self.sponsor_budgets
            .insert(budget.sponsor_id.clone(), budget);
        Ok(root)
    }

    pub fn insert_batch_window(
        &mut self,
        window: LowFeeBatchWindow,
    ) -> LowFeeBatcherResult<String> {
        let root = window.validate()?;
        if window.target_weight > self.config.max_batch_weight {
            return Err("batch window target weight exceeds configured maximum".to_string());
        }
        self.batch_windows.insert(window.window_id.clone(), window);
        Ok(root)
    }

    pub fn insert_execution_plan(
        &mut self,
        plan: LowFeeExecutionPlan,
    ) -> LowFeeBatcherResult<String> {
        let root = plan.validate()?;
        self.execution_plans.insert(plan.plan_id.clone(), plan);
        Ok(root)
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: LowFeeSettlementReceipt,
    ) -> LowFeeBatcherResult<String> {
        let root = receipt.validate()?;
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqBatchAuthorization,
    ) -> LowFeeBatcherResult<String> {
        let root = authorization.validate()?;
        self.pq_authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        Ok(root)
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        payload: Value,
    ) -> LowFeeBatcherResult<String> {
        ensure_non_empty("public record label", label)?;
        let record_id = low_fee_batcher_public_record_id(label, self.height, &payload);
        self.public_records.insert(record_id.clone(), payload);
        Ok(record_id)
    }

    pub fn live_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| intent.status.live())
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    pub fn live_window_ids(&self) -> Vec<String> {
        self.batch_windows
            .values()
            .filter(|window| window.status.live())
            .map(|window| window.window_id.clone())
            .collect()
    }

    pub fn total_available_sponsor_budget(&self) -> u64 {
        self.sponsor_budgets
            .values()
            .filter(|budget| budget.status.spendable())
            .map(LowFeeSponsorBudget::available_micro_units)
            .sum()
    }

    pub fn pending_intent_weight(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status.live())
            .map(|intent| intent.intent_weight)
            .sum()
    }

    pub fn intent_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-INTENT-COLLECTION",
            &self
                .intents
                .values()
                .map(LowFeeBatchIntent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_budget_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-SPONSOR-BUDGET-COLLECTION",
            &self
                .sponsor_budgets
                .values()
                .map(LowFeeSponsorBudget::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_window_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-WINDOW-COLLECTION",
            &self
                .batch_windows
                .values()
                .map(LowFeeBatchWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_plan_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-EXECUTION-PLAN-COLLECTION",
            &self
                .execution_plans
                .values()
                .map(LowFeeExecutionPlan::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-SETTLEMENT-RECEIPT-COLLECTION",
            &self
                .settlement_receipts
                .values()
                .map(LowFeeSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_authorization_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-PQ-AUTHORIZATION-COLLECTION",
            &self
                .pq_authorizations
                .values()
                .map(PqBatchAuthorization::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        low_fee_batcher_collection_root(
            "LOW-FEE-BATCHER-PUBLIC-RECORD-COLLECTION",
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> LowFeeBatcherRoots {
        LowFeeBatcherRoots {
            config_root: self.config.config_root(),
            intent_root: self.intent_root(),
            sponsor_budget_root: self.sponsor_budget_root(),
            batch_window_root: self.batch_window_root(),
            execution_plan_root: self.execution_plan_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            pq_authorization_root: self.pq_authorization_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> LowFeeBatcherCounters {
        LowFeeBatcherCounters {
            intent_count: self.intents.len() as u64,
            live_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status.live())
                .count() as u64,
            sponsor_budget_count: self.sponsor_budgets.len() as u64,
            spendable_sponsor_budget_count: self
                .sponsor_budgets
                .values()
                .filter(|budget| budget.status.spendable())
                .count() as u64,
            batch_window_count: self.batch_windows.len() as u64,
            live_batch_window_count: self
                .batch_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            execution_plan_count: self.execution_plans.len() as u64,
            live_execution_plan_count: self
                .execution_plans
                .values()
                .filter(|plan| plan.status.live())
                .count() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            usable_pq_authorization_count: self
                .pq_authorizations
                .values()
                .filter(|auth| auth.status.usable())
                .count() as u64,
            total_sponsor_budget_micro_units: self
                .sponsor_budgets
                .values()
                .map(|budget| budget.total_budget_micro_units)
                .sum(),
            available_sponsor_budget_micro_units: self.total_available_sponsor_budget(),
            pending_intent_weight: self.pending_intent_weight(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": LOW_FEE_BATCHER_PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_intent_ids": self.live_intent_ids(),
            "live_window_ids": self.live_window_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_batcher_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> LowFeeBatcherResult<String> {
        self.config.validate()?;
        let mut intent_nullifiers = BTreeSet::new();
        for intent in self.intents.values() {
            intent.validate()?;
            if intent.intent_weight > self.config.max_intent_weight {
                return Err(format!("intent {} exceeds max weight", intent.intent_id));
            }
            if !intent_nullifiers.insert(intent.nullifier_root.clone()) {
                return Err("duplicate low-fee intent nullifier root".to_string());
            }
            if let Some(sponsor_id) = &intent.sponsor_id {
                if !self.sponsor_budgets.contains_key(sponsor_id) {
                    return Err(format!(
                        "intent {} references missing sponsor",
                        intent.intent_id
                    ));
                }
            }
        }
        for budget in self.sponsor_budgets.values() {
            budget.validate()?;
        }
        for window in self.batch_windows.values() {
            window.validate()?;
            if window.target_weight > self.config.max_batch_weight {
                return Err(format!(
                    "window {} exceeds max batch weight",
                    window.window_id
                ));
            }
            for intent_id in &window.packed_intent_ids {
                if !self.intents.contains_key(intent_id) {
                    return Err(format!(
                        "window {} references missing intent",
                        window.window_id
                    ));
                }
            }
        }
        for plan in self.execution_plans.values() {
            plan.validate()?;
            if !self.batch_windows.contains_key(&plan.window_id) {
                return Err(format!("plan {} references missing window", plan.plan_id));
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.execution_plans.contains_key(&receipt.plan_id) {
                return Err(format!(
                    "receipt {} references missing plan",
                    receipt.receipt_id
                ));
            }
        }
        for authorization in self.pq_authorizations.values() {
            authorization.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn low_fee_batcher_state_root_from_record(record: &Value) -> String {
    low_fee_batcher_payload_root("LOW-FEE-BATCHER-STATE-ROOT", record)
}

pub fn low_fee_batcher_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn low_fee_batcher_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn low_fee_batcher_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn low_fee_batcher_collection_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn low_fee_batch_intent_id(
    lane: LowFeeBatchLane,
    kind: BatchIntentKind,
    user_commitment: &str,
    encrypted_payload_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-INTENT-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(user_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn low_fee_sponsor_budget_id(
    sponsor_commitment: &str,
    treasury_asset_id: &str,
    reserve_proof_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-SPONSOR-BUDGET-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(treasury_asset_id),
            HashPart::Str(reserve_proof_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn low_fee_batch_window_id(
    lane: LowFeeBatchLane,
    opened_at_height: u64,
    route_policy_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-WINDOW-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(route_policy_root),
        ],
        16,
    )
}

pub fn low_fee_execution_plan_id(
    window_id: &str,
    sequencer_commitment: &str,
    ordered_intent_root: &str,
    expected_settlement_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-EXECUTION-PLAN-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(ordered_intent_root),
            HashPart::Int(expected_settlement_height as i128),
        ],
        16,
    )
}

pub fn low_fee_settlement_receipt_id(
    plan_id: &str,
    batch_root: &str,
    proof_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(plan_id),
            HashPart::Str(batch_root),
            HashPart::Str(proof_root),
            HashPart::Int(settled_at_height as i128),
        ],
        16,
    )
}

pub fn pq_batch_authorization_id(
    subject: PqBatchAuthorizationSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(subject.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Int(signed_at_height as i128),
        ],
        16,
    )
}

pub fn low_fee_batcher_public_record_id(label: &str, height: u64, payload: &Value) -> String {
    domain_hash(
        "LOW-FEE-BATCHER-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(LOW_FEE_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Json(payload),
        ],
        16,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> LowFeeBatcherResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> LowFeeBatcherResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> LowFeeBatcherResult<()> {
    if value > LOW_FEE_BATCHER_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> LowFeeBatcherResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> LowFeeBatcherResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
