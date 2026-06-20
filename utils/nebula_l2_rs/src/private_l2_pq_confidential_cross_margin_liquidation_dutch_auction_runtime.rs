use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialCrossMarginLiquidationDutchAuctionRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialCrossMarginLiquidationDutchAuctionRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LIQUIDATION_DUTCH_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-margin-liquidation-dutch-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LIQUIDATION_DUTCH_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-record-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-liquidation-attestation-v1";
pub const ORACLE_ATTESTATION_SUITE: &str =
    "threshold-oracle+zk-price-band+pq-witness-attestation-v1";
pub const SEALED_TRIGGER_SUITE: &str = "confidential-cross-margin-sealed-trigger-v1";
pub const DUTCH_AUCTION_SUITE: &str = "confidential-liquidation-dutch-auction-v1";
pub const BIDDER_COMMITMENT_SUITE: &str = "commit-reveal-private-liquidator-bid-v1";
pub const PARTIAL_RECEIPT_SUITE: &str = "partial-cross-margin-liquidation-receipt-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "view-budgeted-public-risk-redaction-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_104_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_720_000;
pub const DEVNET_SETTLEMENT_ASSET: &str = "wxmr-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_TRIGGER_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_REVEAL_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_ORACLE_STALENESS_BLOCKS: u64 = 5;
pub const DEFAULT_INITIAL_DISCOUNT_BPS: u64 = 20;
pub const DEFAULT_MAX_DISCOUNT_BPS: u64 = 1_250;
pub const DEFAULT_DECAY_STEP_BPS: u64 = 50;
pub const DEFAULT_KEEPER_REBATE_BPS: u64 = 12;
pub const DEFAULT_INSURANCE_REBATE_BPS: u64 = 8;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 4;
pub const DEFAULT_MIN_HEALTH_FACTOR_BPS: u64 = 11_500;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 8_000;
pub const DEFAULT_LIQUIDATION_CLOSE_FACTOR_BPS: u64 = 5_000;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 160;
pub const DEFAULT_REBATE_POOL_MICRO_UNITS: u64 = 750_000_000;
pub const MAX_MARGIN_ACCOUNTS: usize = 262_144;
pub const MAX_RISK_BUCKETS: usize = 4_096;
pub const MAX_SEALED_TRIGGERS: usize = 524_288;
pub const MAX_AUCTIONS: usize = 524_288;
pub const MAX_BIDDER_COMMITMENTS: usize = 1_048_576;
pub const MAX_ORACLE_ATTESTATIONS: usize = 524_288;
pub const MAX_PARTIAL_RECEIPTS: usize = 1_048_576;
pub const MAX_REBATE_POOLS: usize = 65_536;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginAccountStatus {
    Active,
    Watchlisted,
    TriggerSealed,
    Auctioning,
    PartiallyLiquidated,
    Rebalanced,
    Settled,
    Frozen,
}

impl MarginAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Watchlisted => "watchlisted",
            Self::TriggerSealed => "trigger_sealed",
            Self::Auctioning => "auctioning",
            Self::PartiallyLiquidated => "partially_liquidated",
            Self::Rebalanced => "rebalanced",
            Self::Settled => "settled",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBucketKind {
    StableCollateral,
    VolatileCollateral,
    MoneroCollateral,
    PrivatePerps,
    LendingDebt,
    AmmLp,
    BridgeCredit,
    SyntheticAsset,
}

impl RiskBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableCollateral => "stable_collateral",
            Self::VolatileCollateral => "volatile_collateral",
            Self::MoneroCollateral => "monero_collateral",
            Self::PrivatePerps => "private_perps",
            Self::LendingDebt => "lending_debt",
            Self::AmmLp => "amm_lp",
            Self::BridgeCredit => "bridge_credit",
            Self::SyntheticAsset => "synthetic_asset",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerStatus {
    Sealed,
    OracleMatched,
    RiskVerified,
    AuctionOpened,
    Cancelled,
    Expired,
    Settled,
    Slashed,
}

impl TriggerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::OracleMatched => "oracle_matched",
            Self::RiskVerified => "risk_verified",
            Self::AuctionOpened => "auction_opened",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Scheduled,
    Open,
    CommitPhase,
    RevealPhase,
    Clearing,
    PartiallyFilled,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::CommitPhase => "commit_phase",
            Self::RevealPhase => "reveal_phase",
            Self::Clearing => "clearing",
            Self::PartiallyFilled => "partially_filled",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveKind {
    Linear,
    Stepwise,
    ExponentialApprox,
    OracleBandAnchored,
}

impl CurveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::Stepwise => "stepwise",
            Self::ExponentialApprox => "exponential_approx",
            Self::OracleBandAnchored => "oracle_band_anchored",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidCommitmentStatus {
    Committed,
    Revealed,
    Selected,
    PartiallySelected,
    Settled,
    Refunded,
    Slashed,
    Expired,
}

impl BidCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::PartiallySelected => "partially_selected",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Quorum,
    Disputed,
    Final,
    Stale,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Quorum => "quorum",
            Self::Disputed => "disputed",
            Self::Final => "final",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Applied,
    RebateQueued,
    Settled,
    Disputed,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::RebateQueued => "rebate_queued",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub settlement_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub trigger_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub oracle_staleness_blocks: u64,
    pub initial_discount_bps: u64,
    pub max_discount_bps: u64,
    pub decay_step_bps: u64,
    pub keeper_rebate_bps: u64,
    pub insurance_rebate_bps: u64,
    pub protocol_fee_bps: u64,
    pub min_health_factor_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_close_factor_bps: u64,
    pub redaction_budget_units: u64,
    pub max_margin_accounts: usize,
    pub max_risk_buckets: usize,
    pub max_auctions: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            trigger_ttl_blocks: DEFAULT_TRIGGER_TTL_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            reveal_ttl_blocks: DEFAULT_REVEAL_TTL_BLOCKS,
            oracle_staleness_blocks: DEFAULT_ORACLE_STALENESS_BLOCKS,
            initial_discount_bps: DEFAULT_INITIAL_DISCOUNT_BPS,
            max_discount_bps: DEFAULT_MAX_DISCOUNT_BPS,
            decay_step_bps: DEFAULT_DECAY_STEP_BPS,
            keeper_rebate_bps: DEFAULT_KEEPER_REBATE_BPS,
            insurance_rebate_bps: DEFAULT_INSURANCE_REBATE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            min_health_factor_bps: DEFAULT_MIN_HEALTH_FACTOR_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_close_factor_bps: DEFAULT_LIQUIDATION_CLOSE_FACTOR_BPS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_margin_accounts: MAX_MARGIN_ACCOUNTS,
            max_risk_buckets: MAX_RISK_BUCKETS,
            max_auctions: MAX_AUCTIONS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        require_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        require_nonzero("min_pq_security_bits", self.min_pq_security_bits as u64)?;
        require_bps("initial_discount_bps", self.initial_discount_bps)?;
        require_bps("max_discount_bps", self.max_discount_bps)?;
        require_bps("keeper_rebate_bps", self.keeper_rebate_bps)?;
        require_bps("insurance_rebate_bps", self.insurance_rebate_bps)?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        require_bps(
            "liquidation_close_factor_bps",
            self.liquidation_close_factor_bps,
        )?;
        if self.initial_discount_bps > self.max_discount_bps {
            return Err("initial_discount_bps must be <= max_discount_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub margin_accounts: u64,
    pub risk_buckets: u64,
    pub sealed_triggers: u64,
    pub dutch_auctions: u64,
    pub bidder_commitments: u64,
    pub oracle_attestations: u64,
    pub rebate_pools: u64,
    pub partial_receipts: u64,
    pub redaction_budgets: u64,
    pub slashing_events: u64,
    pub settled_auctions: u64,
    pub total_liquidated_notional_micro_units: u64,
    pub next_sequence: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub margin_accounts_root: String,
    pub risk_buckets_root: String,
    pub sealed_triggers_root: String,
    pub dutch_auctions_root: String,
    pub bidder_commitments_root: String,
    pub oracle_attestations_root: String,
    pub rebate_pools_root: String,
    pub partial_receipts_root: String,
    pub redaction_budgets_root: String,
    pub active_auction_set_root: String,
    pub sealed_trigger_queue_root: String,
    pub public_event_log_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            margin_accounts_root: empty_root("MARGIN-ACCOUNTS"),
            risk_buckets_root: empty_root("RISK-BUCKETS"),
            sealed_triggers_root: empty_root("SEALED-TRIGGERS"),
            dutch_auctions_root: empty_root("DUTCH-AUCTIONS"),
            bidder_commitments_root: empty_root("BIDDER-COMMITMENTS"),
            oracle_attestations_root: empty_root("ORACLE-ATTESTATIONS"),
            rebate_pools_root: empty_root("REBATE-POOLS"),
            partial_receipts_root: empty_root("PARTIAL-RECEIPTS"),
            redaction_budgets_root: empty_root("REDACTION-BUDGETS"),
            active_auction_set_root: empty_root("ACTIVE-AUCTION-SET"),
            sealed_trigger_queue_root: empty_root("SEALED-TRIGGER-QUEUE"),
            public_event_log_root: empty_root("PUBLIC-EVENT-LOG"),
            state_root: empty_root("STATE"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialCommitment {
    pub commitment: String,
    pub nullifier: String,
    pub opening_hint: String,
    pub asset_id: String,
    pub value_range_root: String,
}

impl ConfidentialCommitment {
    pub fn new(label: &str, asset_id: &str, value_hint: u64) -> Self {
        let commitment = deterministic_id("CONFIDENTIAL-COMMITMENT", &[label, asset_id]);
        Self {
            nullifier: nullifier_id("CONFIDENTIAL-COMMITMENT", &[label, asset_id]),
            opening_hint: deterministic_id(
                "CONFIDENTIAL-OPENING-HINT",
                &[label, asset_id, &value_hint.to_string()],
            ),
            value_range_root: deterministic_id(
                "CONFIDENTIAL-VALUE-RANGE",
                &[label, asset_id, &value_hint.to_string()],
            ),
            commitment,
            asset_id: asset_id.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "commitment": self.commitment,
            "nullifier": self.nullifier,
            "value_range_root": self.value_range_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAuthorization {
    pub scheme: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
}

impl PqAuthorization {
    pub fn new(label: &str, public_key_commitment: &str, signature_commitment: &str) -> Self {
        Self {
            scheme: PQ_ATTESTATION_SUITE.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            transcript_hash: deterministic_id(
                "PQ-AUTH-TRANSCRIPT",
                &[label, public_key_commitment, signature_commitment],
            ),
            signature_commitment: signature_commitment.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarginAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub status: MarginAccountStatus,
    pub collateral_commitments: BTreeMap<String, ConfidentialCommitment>,
    pub debt_commitments: BTreeMap<String, ConfidentialCommitment>,
    pub position_commitment_root: String,
    pub risk_bucket_ids: BTreeSet<String>,
    pub health_factor_commitment: String,
    pub maintenance_margin_commitment: String,
    pub liquidation_threshold_bps: u64,
    pub redaction_budget_id: String,
    pub pq_authorization: PqAuthorization,
    pub last_risk_epoch: u64,
    pub updated_l2_height: u64,
}

impl MarginAccount {
    pub fn devnet(id: &str, owner: &str, buckets: &[String], sequence: u64) -> Self {
        let mut collateral_commitments = BTreeMap::new();
        collateral_commitments.insert(
            DEVNET_SETTLEMENT_ASSET.to_string(),
            ConfidentialCommitment::new(&format!("{id}-collateral"), DEVNET_SETTLEMENT_ASSET, 1),
        );
        collateral_commitments.insert(
            "zusd-devnet".to_string(),
            ConfidentialCommitment::new(&format!("{id}-stable"), "zusd-devnet", 2),
        );
        let mut debt_commitments = BTreeMap::new();
        debt_commitments.insert(
            "perp-usd-devnet".to_string(),
            ConfidentialCommitment::new(&format!("{id}-perp-debt"), "perp-usd-devnet", 3),
        );
        let risk_bucket_ids = buckets.iter().cloned().collect::<BTreeSet<_>>();
        let position_commitment_root = map_root("ACCOUNT-POSITIONS", &collateral_commitments);
        Self {
            account_id: id.to_string(),
            owner_commitment: owner.to_string(),
            status: MarginAccountStatus::Watchlisted,
            collateral_commitments,
            debt_commitments,
            position_commitment_root,
            risk_bucket_ids,
            health_factor_commitment: deterministic_id(
                "HEALTH-FACTOR-COMMITMENT",
                &[id, &sequence.to_string()],
            ),
            maintenance_margin_commitment: deterministic_id(
                "MAINTENANCE-MARGIN-COMMITMENT",
                &[id, &sequence.to_string()],
            ),
            liquidation_threshold_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            redaction_budget_id: redaction_budget_id(id),
            pq_authorization: PqAuthorization::new(
                id,
                &deterministic_id("OWNER-PK", &[owner]),
                &deterministic_id("OWNER-SIG", &[owner, id]),
            ),
            last_risk_epoch: sequence,
            updated_l2_height: DEVNET_L2_HEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "collateral_root": map_root("ACCOUNT-COLLATERAL", &self.collateral_commitments),
            "debt_root": map_root("ACCOUNT-DEBT", &self.debt_commitments),
            "health_factor_commitment": self.health_factor_commitment,
            "last_risk_epoch": self.last_risk_epoch,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "maintenance_margin_commitment": self.maintenance_margin_commitment,
            "owner_commitment": self.owner_commitment,
            "position_commitment_root": self.position_commitment_root,
            "pq_authorization": self.pq_authorization.public_record(),
            "redaction_budget_id": self.redaction_budget_id,
            "risk_bucket_root": set_root("ACCOUNT-RISK-BUCKETS", &self.risk_bucket_ids),
            "status": self.status.as_str(),
            "updated_l2_height": self.updated_l2_height
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskBucket {
    pub bucket_id: String,
    pub kind: RiskBucketKind,
    pub asset_id: String,
    pub margin_weight_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub max_close_factor_bps: u64,
    pub price_band_bps: u64,
    pub oracle_set_id: String,
    pub active_accounts: BTreeSet<String>,
    pub net_exposure_commitment: String,
    pub stress_loss_commitment: String,
}

impl RiskBucket {
    pub fn new(kind: RiskBucketKind, asset_id: &str, sequence: u64) -> Self {
        let label = format!("{}-{asset_id}-{sequence}", kind.as_str());
        Self {
            bucket_id: deterministic_id("RISK-BUCKET-ID", &[&label]),
            kind,
            asset_id: asset_id.to_string(),
            margin_weight_bps: match kind {
                RiskBucketKind::StableCollateral => 9_200,
                RiskBucketKind::MoneroCollateral => 7_500,
                RiskBucketKind::VolatileCollateral => 6_500,
                RiskBucketKind::AmmLp => 5_800,
                RiskBucketKind::BridgeCredit => 7_000,
                RiskBucketKind::LendingDebt => 10_500,
                RiskBucketKind::PrivatePerps => 12_500,
                RiskBucketKind::SyntheticAsset => 8_500,
            },
            liquidation_penalty_bps: 350,
            max_close_factor_bps: DEFAULT_LIQUIDATION_CLOSE_FACTOR_BPS,
            price_band_bps: 80,
            oracle_set_id: deterministic_id("ORACLE-SET", &[asset_id]),
            active_accounts: BTreeSet::new(),
            net_exposure_commitment: deterministic_id("NET-EXPOSURE", &[&label]),
            stress_loss_commitment: deterministic_id("STRESS-LOSS", &[&label]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active_accounts_root": set_root("RISK-BUCKET-ACTIVE-ACCOUNTS", &self.active_accounts),
            "asset_id": self.asset_id,
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "margin_weight_bps": self.margin_weight_bps,
            "max_close_factor_bps": self.max_close_factor_bps,
            "net_exposure_commitment": self.net_exposure_commitment,
            "oracle_set_id": self.oracle_set_id,
            "price_band_bps": self.price_band_bps,
            "stress_loss_commitment": self.stress_loss_commitment
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OraclePqAttestation {
    pub attestation_id: String,
    pub oracle_set_id: String,
    pub asset_id: String,
    pub price_band_commitment: String,
    pub median_price_commitment: String,
    pub confidence_bps: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub signer_commitments: BTreeSet<String>,
    pub quorum_threshold: u16,
    pub pq_authorization: PqAuthorization,
    pub status: AttestationStatus,
}

impl OraclePqAttestation {
    pub fn new(asset_id: &str, price_hint: u64, sequence: u64) -> Self {
        let oracle_set_id = deterministic_id("ORACLE-SET", &[asset_id]);
        let attestation_id = deterministic_id(
            "ORACLE-ATTESTATION-ID",
            &[asset_id, &price_hint.to_string(), &sequence.to_string()],
        );
        let mut signer_commitments = BTreeSet::new();
        signer_commitments.insert(deterministic_id("ORACLE-SIGNER", &[asset_id, "0"]));
        signer_commitments.insert(deterministic_id("ORACLE-SIGNER", &[asset_id, "1"]));
        signer_commitments.insert(deterministic_id("ORACLE-SIGNER", &[asset_id, "2"]));
        Self {
            attestation_id: attestation_id.clone(),
            oracle_set_id,
            asset_id: asset_id.to_string(),
            price_band_commitment: deterministic_id(
                "PRICE-BAND",
                &[asset_id, &price_hint.to_string()],
            ),
            median_price_commitment: deterministic_id(
                "MEDIAN-PRICE",
                &[asset_id, &price_hint.to_string()],
            ),
            confidence_bps: 9_850,
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            signer_commitments,
            quorum_threshold: 3,
            pq_authorization: PqAuthorization::new(
                &attestation_id,
                &deterministic_id("ORACLE-QUORUM-PK", &[asset_id]),
                &deterministic_id("ORACLE-QUORUM-SIG", &[asset_id, &sequence.to_string()]),
            ),
            status: AttestationStatus::Quorum,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "attestation_id": self.attestation_id,
            "confidence_bps": self.confidence_bps,
            "l2_height": self.l2_height,
            "median_price_commitment": self.median_price_commitment,
            "monero_height": self.monero_height,
            "oracle_set_id": self.oracle_set_id,
            "pq_authorization": self.pq_authorization.public_record(),
            "price_band_commitment": self.price_band_commitment,
            "quorum_threshold": self.quorum_threshold,
            "signer_root": set_root("ORACLE-SIGNERS", &self.signer_commitments),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedLiquidationTrigger {
    pub trigger_id: String,
    pub account_id: String,
    pub risk_bucket_id: String,
    pub trigger_commitment: String,
    pub health_factor_commitment: String,
    pub oracle_attestation_id: String,
    pub liquidation_bound_commitment: String,
    pub sealed_witness_root: String,
    pub submitter_commitment: String,
    pub status: TriggerStatus,
    pub expires_l2_height: u64,
    pub pq_authorization: PqAuthorization,
}

impl SealedLiquidationTrigger {
    pub fn new(
        account_id: &str,
        risk_bucket_id: &str,
        oracle_attestation_id: &str,
        submitter: &str,
        sequence: u64,
    ) -> Self {
        let trigger_id = deterministic_id(
            "SEALED-LIQUIDATION-TRIGGER-ID",
            &[
                account_id,
                risk_bucket_id,
                oracle_attestation_id,
                &sequence.to_string(),
            ],
        );
        Self {
            trigger_id: trigger_id.clone(),
            account_id: account_id.to_string(),
            risk_bucket_id: risk_bucket_id.to_string(),
            trigger_commitment: deterministic_id(
                "SEALED-TRIGGER-COMMITMENT",
                &[account_id, risk_bucket_id, &sequence.to_string()],
            ),
            health_factor_commitment: deterministic_id(
                "SEALED-TRIGGER-HEALTH",
                &[account_id, &sequence.to_string()],
            ),
            oracle_attestation_id: oracle_attestation_id.to_string(),
            liquidation_bound_commitment: deterministic_id(
                "LIQUIDATION-BOUND",
                &[account_id, risk_bucket_id],
            ),
            sealed_witness_root: deterministic_id("SEALED-WITNESS-ROOT", &[&trigger_id]),
            submitter_commitment: submitter.to_string(),
            status: TriggerStatus::RiskVerified,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_TRIGGER_TTL_BLOCKS,
            pq_authorization: PqAuthorization::new(
                &trigger_id,
                &deterministic_id("KEEPER-PK", &[submitter]),
                &deterministic_id("KEEPER-SIG", &[submitter, &trigger_id]),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "expires_l2_height": self.expires_l2_height,
            "health_factor_commitment": self.health_factor_commitment,
            "liquidation_bound_commitment": self.liquidation_bound_commitment,
            "oracle_attestation_id": self.oracle_attestation_id,
            "pq_authorization": self.pq_authorization.public_record(),
            "risk_bucket_id": self.risk_bucket_id,
            "sealed_witness_root": self.sealed_witness_root,
            "status": self.status.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "trigger_commitment": self.trigger_commitment,
            "trigger_id": self.trigger_id
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DutchPriceCurve {
    pub curve_id: String,
    pub kind: CurveKind,
    pub start_price_commitment: String,
    pub reserve_price_commitment: String,
    pub initial_discount_bps: u64,
    pub max_discount_bps: u64,
    pub decay_step_bps: u64,
    pub step_blocks: u64,
    pub oracle_anchor_attestation_id: String,
}

impl DutchPriceCurve {
    pub fn new(auction_id: &str, oracle_attestation_id: &str) -> Self {
        Self {
            curve_id: deterministic_id("DUTCH-CURVE-ID", &[auction_id, oracle_attestation_id]),
            kind: CurveKind::OracleBandAnchored,
            start_price_commitment: deterministic_id("DUTCH-START-PRICE", &[auction_id]),
            reserve_price_commitment: deterministic_id("DUTCH-RESERVE-PRICE", &[auction_id]),
            initial_discount_bps: DEFAULT_INITIAL_DISCOUNT_BPS,
            max_discount_bps: DEFAULT_MAX_DISCOUNT_BPS,
            decay_step_bps: DEFAULT_DECAY_STEP_BPS,
            step_blocks: 2,
            oracle_anchor_attestation_id: oracle_attestation_id.to_string(),
        }
    }

    pub fn discount_at(&self, elapsed_blocks: u64) -> u64 {
        let steps = elapsed_blocks / self.step_blocks.max(1);
        self.initial_discount_bps
            .saturating_add(steps.saturating_mul(self.decay_step_bps))
            .min(self.max_discount_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "curve_id": self.curve_id,
            "decay_step_bps": self.decay_step_bps,
            "initial_discount_bps": self.initial_discount_bps,
            "kind": self.kind.as_str(),
            "max_discount_bps": self.max_discount_bps,
            "oracle_anchor_attestation_id": self.oracle_anchor_attestation_id,
            "reserve_price_commitment": self.reserve_price_commitment,
            "start_price_commitment": self.start_price_commitment,
            "step_blocks": self.step_blocks
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DutchAuction {
    pub auction_id: String,
    pub trigger_id: String,
    pub account_id: String,
    pub risk_bucket_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub close_factor_bps: u64,
    pub notional_commitment: String,
    pub price_curve: DutchPriceCurve,
    pub bidder_commitment_ids: BTreeSet<String>,
    pub selected_receipt_ids: BTreeSet<String>,
    pub rebate_pool_id: String,
    pub status: AuctionStatus,
    pub opens_l2_height: u64,
    pub reveal_l2_height: u64,
    pub expires_l2_height: u64,
}

impl DutchAuction {
    pub fn new(
        trigger: &SealedLiquidationTrigger,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        sequence: u64,
    ) -> Self {
        let auction_id = deterministic_id(
            "DUTCH-AUCTION-ID",
            &[
                &trigger.trigger_id,
                collateral_asset_id,
                &sequence.to_string(),
            ],
        );
        Self {
            auction_id: auction_id.clone(),
            trigger_id: trigger.trigger_id.clone(),
            account_id: trigger.account_id.clone(),
            risk_bucket_id: trigger.risk_bucket_id.clone(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            close_factor_bps: DEFAULT_LIQUIDATION_CLOSE_FACTOR_BPS,
            notional_commitment: deterministic_id("AUCTION-NOTIONAL", &[&auction_id]),
            price_curve: DutchPriceCurve::new(&auction_id, &trigger.oracle_attestation_id),
            bidder_commitment_ids: BTreeSet::new(),
            selected_receipt_ids: BTreeSet::new(),
            rebate_pool_id: rebate_pool_id(&auction_id),
            status: AuctionStatus::CommitPhase,
            opens_l2_height: DEVNET_L2_HEIGHT + 1,
            reveal_l2_height: DEVNET_L2_HEIGHT + DEFAULT_REVEAL_TTL_BLOCKS,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_AUCTION_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "auction_id": self.auction_id,
            "bidder_commitment_root": set_root("AUCTION-BIDDER-COMMITMENTS", &self.bidder_commitment_ids),
            "close_factor_bps": self.close_factor_bps,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "expires_l2_height": self.expires_l2_height,
            "notional_commitment": self.notional_commitment,
            "opens_l2_height": self.opens_l2_height,
            "price_curve": self.price_curve.public_record(),
            "rebate_pool_id": self.rebate_pool_id,
            "reveal_l2_height": self.reveal_l2_height,
            "risk_bucket_id": self.risk_bucket_id,
            "selected_receipt_root": set_root("AUCTION-SELECTED-RECEIPTS", &self.selected_receipt_ids),
            "status": self.status.as_str(),
            "trigger_id": self.trigger_id
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidderCommitment {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub fill_amount_commitment: String,
    pub max_discount_bps_commitment: String,
    pub collateral_destination_commitment: String,
    pub bond_commitment: ConfidentialCommitment,
    pub reveal_nullifier: String,
    pub priority_fee_commitment: String,
    pub status: BidCommitmentStatus,
    pub pq_authorization: PqAuthorization,
}

impl BidderCommitment {
    pub fn new(auction_id: &str, bidder_label: &str, sequence: u64) -> Self {
        let bid_id = deterministic_id(
            "BIDDER-COMMITMENT-ID",
            &[auction_id, bidder_label, &sequence.to_string()],
        );
        Self {
            bid_id: bid_id.clone(),
            auction_id: auction_id.to_string(),
            bidder_commitment: deterministic_id("BIDDER-COMMITMENT", &[bidder_label]),
            fill_amount_commitment: deterministic_id("BID-FILL-AMOUNT", &[&bid_id]),
            max_discount_bps_commitment: deterministic_id("BID-MAX-DISCOUNT", &[&bid_id]),
            collateral_destination_commitment: deterministic_id(
                "BID-COLLATERAL-DESTINATION",
                &[&bid_id],
            ),
            bond_commitment: ConfidentialCommitment::new(
                &format!("{bid_id}-bond"),
                DEVNET_SETTLEMENT_ASSET,
                4,
            ),
            reveal_nullifier: nullifier_id("BID-REVEAL", &[&bid_id]),
            priority_fee_commitment: deterministic_id("BID-PRIORITY-FEE", &[&bid_id]),
            status: BidCommitmentStatus::Committed,
            pq_authorization: PqAuthorization::new(
                &bid_id,
                &deterministic_id("BIDDER-PK", &[bidder_label]),
                &deterministic_id("BIDDER-SIG", &[bidder_label, auction_id]),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "bidder_commitment": self.bidder_commitment,
            "bond_commitment": self.bond_commitment.public_record(),
            "collateral_destination_commitment": self.collateral_destination_commitment,
            "fill_amount_commitment": self.fill_amount_commitment,
            "max_discount_bps_commitment": self.max_discount_bps_commitment,
            "pq_authorization": self.pq_authorization.public_record(),
            "priority_fee_commitment": self.priority_fee_commitment,
            "reveal_nullifier": self.reveal_nullifier,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebatePool {
    pub pool_id: String,
    pub auction_id: String,
    pub asset_id: String,
    pub available_micro_units: u64,
    pub keeper_rebate_bps: u64,
    pub insurance_rebate_bps: u64,
    pub protocol_fee_bps: u64,
    pub paid_receipt_ids: BTreeSet<String>,
    pub accrued_rebate_commitment: String,
}

impl RebatePool {
    pub fn new(auction_id: &str) -> Self {
        Self {
            pool_id: rebate_pool_id(auction_id),
            auction_id: auction_id.to_string(),
            asset_id: DEVNET_SETTLEMENT_ASSET.to_string(),
            available_micro_units: DEFAULT_REBATE_POOL_MICRO_UNITS,
            keeper_rebate_bps: DEFAULT_KEEPER_REBATE_BPS,
            insurance_rebate_bps: DEFAULT_INSURANCE_REBATE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            paid_receipt_ids: BTreeSet::new(),
            accrued_rebate_commitment: deterministic_id("REBATE-ACCRUAL", &[auction_id]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accrued_rebate_commitment": self.accrued_rebate_commitment,
            "asset_id": self.asset_id,
            "auction_id": self.auction_id,
            "available_micro_units": self.available_micro_units,
            "insurance_rebate_bps": self.insurance_rebate_bps,
            "keeper_rebate_bps": self.keeper_rebate_bps,
            "paid_receipt_root": set_root("REBATE-PAID-RECEIPTS", &self.paid_receipt_ids),
            "pool_id": self.pool_id,
            "protocol_fee_bps": self.protocol_fee_bps
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialLiquidationReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub account_id: String,
    pub selected_bid_id: String,
    pub liquidated_collateral_commitment: String,
    pub repaid_debt_commitment: String,
    pub realized_discount_bps: u64,
    pub remaining_health_factor_commitment: String,
    pub rebate_pool_id: String,
    pub rebate_commitment: String,
    pub settlement_nullifier: String,
    pub status: ReceiptStatus,
    pub l2_height: u64,
}

impl PartialLiquidationReceipt {
    pub fn new(auction: &DutchAuction, bid: &BidderCommitment, elapsed_blocks: u64) -> Self {
        let receipt_id = deterministic_id(
            "PARTIAL-LIQUIDATION-RECEIPT-ID",
            &[&auction.auction_id, &bid.bid_id],
        );
        Self {
            receipt_id: receipt_id.clone(),
            auction_id: auction.auction_id.clone(),
            account_id: auction.account_id.clone(),
            selected_bid_id: bid.bid_id.clone(),
            liquidated_collateral_commitment: deterministic_id(
                "LIQUIDATED-COLLATERAL",
                &[&receipt_id],
            ),
            repaid_debt_commitment: deterministic_id("REPAID-DEBT", &[&receipt_id]),
            realized_discount_bps: auction.price_curve.discount_at(elapsed_blocks),
            remaining_health_factor_commitment: deterministic_id(
                "POST-LIQUIDATION-HEALTH",
                &[&receipt_id],
            ),
            rebate_pool_id: auction.rebate_pool_id.clone(),
            rebate_commitment: deterministic_id("RECEIPT-REBATE", &[&receipt_id]),
            settlement_nullifier: nullifier_id("LIQUIDATION-SETTLEMENT", &[&receipt_id]),
            status: ReceiptStatus::RebateQueued,
            l2_height: DEVNET_L2_HEIGHT + elapsed_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "auction_id": self.auction_id,
            "l2_height": self.l2_height,
            "liquidated_collateral_commitment": self.liquidated_collateral_commitment,
            "realized_discount_bps": self.realized_discount_bps,
            "rebate_commitment": self.rebate_commitment,
            "rebate_pool_id": self.rebate_pool_id,
            "receipt_id": self.receipt_id,
            "remaining_health_factor_commitment": self.remaining_health_factor_commitment,
            "repaid_debt_commitment": self.repaid_debt_commitment,
            "selected_bid_id": self.selected_bid_id,
            "settlement_nullifier": self.settlement_nullifier,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub account_id: String,
    pub total_units: u64,
    pub consumed_units: u64,
    pub redacted_fields: BTreeSet<String>,
    pub allowed_view_tags: BTreeSet<String>,
    pub audit_commitment: String,
    pub expires_l2_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn new(account_id: &str) -> Self {
        let mut redacted_fields = BTreeSet::new();
        redacted_fields.insert("position_size".to_string());
        redacted_fields.insert("owner_identity".to_string());
        redacted_fields.insert("exact_liquidation_price".to_string());
        let mut allowed_view_tags = BTreeSet::new();
        allowed_view_tags.insert(deterministic_id("VIEW-TAG", &[account_id, "risk"]));
        allowed_view_tags.insert(deterministic_id("VIEW-TAG", &[account_id, "auction"]));
        Self {
            budget_id: redaction_budget_id(account_id),
            account_id: account_id.to_string(),
            total_units: DEFAULT_REDACTION_BUDGET_UNITS,
            consumed_units: 24,
            redacted_fields,
            allowed_view_tags,
            audit_commitment: deterministic_id("REDACTION-AUDIT", &[account_id]),
            expires_l2_height: DEVNET_L2_HEIGHT + 4_096,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "allowed_view_tag_root": set_root("REDACTION-ALLOWED-VIEW-TAGS", &self.allowed_view_tags),
            "audit_commitment": self.audit_commitment,
            "budget_id": self.budget_id,
            "consumed_units": self.consumed_units,
            "expires_l2_height": self.expires_l2_height,
            "redacted_field_root": set_root("REDACTION-FIELDS", &self.redacted_fields),
            "remaining_units": self.remaining_units(),
            "total_units": self.total_units
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub margin_accounts: BTreeMap<String, MarginAccount>,
    pub risk_buckets: BTreeMap<String, RiskBucket>,
    pub sealed_triggers: BTreeMap<String, SealedLiquidationTrigger>,
    pub dutch_auctions: BTreeMap<String, DutchAuction>,
    pub bidder_commitments: BTreeMap<String, BidderCommitment>,
    pub oracle_attestations: BTreeMap<String, OraclePqAttestation>,
    pub rebate_pools: BTreeMap<String, RebatePool>,
    pub partial_receipts: BTreeMap<String, PartialLiquidationReceipt>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub active_auction_ids: BTreeSet<String>,
    pub sealed_trigger_queue: BTreeSet<String>,
    pub public_event_log: Vec<String>,
}

impl State {
    pub fn empty() -> Self {
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            margin_accounts: BTreeMap::new(),
            risk_buckets: BTreeMap::new(),
            sealed_triggers: BTreeMap::new(),
            dutch_auctions: BTreeMap::new(),
            bidder_commitments: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            rebate_pools: BTreeMap::new(),
            partial_receipts: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            active_auction_ids: BTreeSet::new(),
            sealed_trigger_queue: BTreeSet::new(),
            public_event_log: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::empty();

        let mut stable_bucket = RiskBucket::new(RiskBucketKind::StableCollateral, "zusd-devnet", 0);
        let mut xmr_bucket =
            RiskBucket::new(RiskBucketKind::MoneroCollateral, DEVNET_SETTLEMENT_ASSET, 1);
        let mut perp_bucket = RiskBucket::new(RiskBucketKind::PrivatePerps, "perp-usd-devnet", 2);

        let bucket_ids = vec![
            stable_bucket.bucket_id.clone(),
            xmr_bucket.bucket_id.clone(),
            perp_bucket.bucket_id.clone(),
        ];

        let account = MarginAccount::devnet(
            &deterministic_id("MARGIN-ACCOUNT-ID", &["devnet-account-0"]),
            &deterministic_id("OWNER-COMMITMENT", &["devnet-owner-0"]),
            &bucket_ids,
            0,
        );

        stable_bucket
            .active_accounts
            .insert(account.account_id.clone());
        xmr_bucket
            .active_accounts
            .insert(account.account_id.clone());
        perp_bucket
            .active_accounts
            .insert(account.account_id.clone());

        state
            .insert_risk_bucket(stable_bucket)
            .expect("valid devnet bucket");
        state
            .insert_risk_bucket(xmr_bucket)
            .expect("valid devnet bucket");
        state
            .insert_risk_bucket(perp_bucket.clone())
            .expect("valid devnet bucket");
        state
            .insert_margin_account(account.clone())
            .expect("valid devnet account");

        let oracle = OraclePqAttestation::new(DEVNET_SETTLEMENT_ASSET, 172_500_000, 0);
        state
            .insert_oracle_attestation(oracle.clone())
            .expect("valid devnet oracle");

        let trigger = SealedLiquidationTrigger::new(
            &account.account_id,
            &perp_bucket.bucket_id,
            &oracle.attestation_id,
            &deterministic_id("KEEPER-COMMITMENT", &["devnet-keeper-0"]),
            0,
        );
        state
            .insert_sealed_trigger(trigger.clone())
            .expect("valid devnet trigger");

        let auction = DutchAuction::new(&trigger, DEVNET_SETTLEMENT_ASSET, "perp-usd-devnet", 0);
        state
            .insert_dutch_auction(auction.clone())
            .expect("valid devnet auction");

        let bid_a = BidderCommitment::new(&auction.auction_id, "devnet-bidder-a", 0);
        let bid_b = BidderCommitment::new(&auction.auction_id, "devnet-bidder-b", 1);
        state
            .insert_bidder_commitment(bid_a.clone())
            .expect("valid devnet bid");
        state
            .insert_bidder_commitment(bid_b)
            .expect("valid devnet bid");

        let receipt = PartialLiquidationReceipt::new(&auction, &bid_a, 6);
        state
            .insert_partial_receipt(receipt)
            .expect("valid devnet receipt");

        state.push_event(
            "devnet_initialized",
            "cross_margin_liquidation_dutch_auction",
        );
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let second_oracle = OraclePqAttestation::new("zusd-devnet", 100_000_000, 1);
        state
            .insert_oracle_attestation(second_oracle)
            .expect("valid demo oracle");
        state.push_event("demo_oracle_refresh", "zusd-devnet");
        state.recompute_roots();
        state
    }

    pub fn insert_margin_account(&mut self, account: MarginAccount) -> Result<()> {
        self.ensure_capacity(
            "margin_accounts",
            self.margin_accounts.len(),
            MAX_MARGIN_ACCOUNTS,
        )?;
        require_nonempty("account_id", &account.account_id)?;
        self.redaction_budgets.insert(
            account.redaction_budget_id.clone(),
            PrivacyRedactionBudget::new(&account.account_id),
        );
        self.margin_accounts
            .insert(account.account_id.clone(), account.clone());
        self.counters.margin_accounts = self.margin_accounts.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.push_event("margin_account_inserted", &account.account_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_risk_bucket(&mut self, bucket: RiskBucket) -> Result<()> {
        self.ensure_capacity("risk_buckets", self.risk_buckets.len(), MAX_RISK_BUCKETS)?;
        require_nonempty("bucket_id", &bucket.bucket_id)?;
        require_bps("margin_weight_bps", bucket.margin_weight_bps)?;
        self.risk_buckets
            .insert(bucket.bucket_id.clone(), bucket.clone());
        self.counters.risk_buckets = self.risk_buckets.len() as u64;
        self.push_event("risk_bucket_inserted", &bucket.bucket_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_oracle_attestation(&mut self, attestation: OraclePqAttestation) -> Result<()> {
        self.ensure_capacity(
            "oracle_attestations",
            self.oracle_attestations.len(),
            MAX_ORACLE_ATTESTATIONS,
        )?;
        require_nonempty("attestation_id", &attestation.attestation_id)?;
        self.oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.counters.oracle_attestations = self.oracle_attestations.len() as u64;
        self.push_event("oracle_attestation_inserted", &attestation.attestation_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_sealed_trigger(&mut self, trigger: SealedLiquidationTrigger) -> Result<()> {
        self.ensure_capacity(
            "sealed_triggers",
            self.sealed_triggers.len(),
            MAX_SEALED_TRIGGERS,
        )?;
        self.require_account(&trigger.account_id)?;
        self.require_risk_bucket(&trigger.risk_bucket_id)?;
        self.require_oracle_attestation(&trigger.oracle_attestation_id)?;
        self.sealed_trigger_queue.insert(trigger.trigger_id.clone());
        self.sealed_triggers
            .insert(trigger.trigger_id.clone(), trigger.clone());
        if let Some(account) = self.margin_accounts.get_mut(&trigger.account_id) {
            account.status = MarginAccountStatus::TriggerSealed;
        }
        self.counters.sealed_triggers = self.sealed_triggers.len() as u64;
        self.push_event("sealed_trigger_inserted", &trigger.trigger_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_dutch_auction(&mut self, auction: DutchAuction) -> Result<()> {
        self.ensure_capacity("dutch_auctions", self.dutch_auctions.len(), MAX_AUCTIONS)?;
        self.require_trigger(&auction.trigger_id)?;
        self.rebate_pools.insert(
            auction.rebate_pool_id.clone(),
            RebatePool::new(&auction.auction_id),
        );
        self.active_auction_ids.insert(auction.auction_id.clone());
        if let Some(trigger) = self.sealed_triggers.get_mut(&auction.trigger_id) {
            trigger.status = TriggerStatus::AuctionOpened;
        }
        if let Some(account) = self.margin_accounts.get_mut(&auction.account_id) {
            account.status = MarginAccountStatus::Auctioning;
        }
        self.dutch_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        self.counters.dutch_auctions = self.dutch_auctions.len() as u64;
        self.counters.rebate_pools = self.rebate_pools.len() as u64;
        self.push_event("dutch_auction_inserted", &auction.auction_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_bidder_commitment(&mut self, bid: BidderCommitment) -> Result<()> {
        self.ensure_capacity(
            "bidder_commitments",
            self.bidder_commitments.len(),
            MAX_BIDDER_COMMITMENTS,
        )?;
        self.require_auction(&bid.auction_id)?;
        if let Some(auction) = self.dutch_auctions.get_mut(&bid.auction_id) {
            auction.bidder_commitment_ids.insert(bid.bid_id.clone());
        }
        self.bidder_commitments
            .insert(bid.bid_id.clone(), bid.clone());
        self.counters.bidder_commitments = self.bidder_commitments.len() as u64;
        self.push_event("bidder_commitment_inserted", &bid.bid_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_partial_receipt(&mut self, receipt: PartialLiquidationReceipt) -> Result<()> {
        self.ensure_capacity(
            "partial_receipts",
            self.partial_receipts.len(),
            MAX_PARTIAL_RECEIPTS,
        )?;
        self.require_auction(&receipt.auction_id)?;
        self.require_bid(&receipt.selected_bid_id)?;
        if let Some(auction) = self.dutch_auctions.get_mut(&receipt.auction_id) {
            auction.status = AuctionStatus::PartiallyFilled;
            auction
                .selected_receipt_ids
                .insert(receipt.receipt_id.clone());
        }
        if let Some(account) = self.margin_accounts.get_mut(&receipt.account_id) {
            account.status = MarginAccountStatus::PartiallyLiquidated;
            account.health_factor_commitment = receipt.remaining_health_factor_commitment.clone();
        }
        if let Some(pool) = self.rebate_pools.get_mut(&receipt.rebate_pool_id) {
            pool.paid_receipt_ids.insert(receipt.receipt_id.clone());
        }
        self.counters.total_liquidated_notional_micro_units = self
            .counters
            .total_liquidated_notional_micro_units
            .saturating_add(1_000_000);
        self.partial_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.counters.partial_receipts = self.partial_receipts.len() as u64;
        self.push_event("partial_receipt_inserted", &receipt.receipt_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn settle_auction(&mut self, auction_id: &str) -> Result<()> {
        self.require_auction(auction_id)?;
        let account_id = self
            .dutch_auctions
            .get(auction_id)
            .map(|auction| auction.account_id.clone())
            .unwrap_or_default();
        if let Some(auction) = self.dutch_auctions.get_mut(auction_id) {
            auction.status = AuctionStatus::Settled;
        }
        if let Some(account) = self.margin_accounts.get_mut(&account_id) {
            account.status = MarginAccountStatus::Rebalanced;
        }
        self.active_auction_ids.remove(auction_id);
        self.counters.settled_auctions = self.counters.settled_auctions.saturating_add(1);
        self.push_event("auction_settled", auction_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "hash_suite": HASH_SUITE,
            "protocol_version": PROTOCOL_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "roots": {
                "active_auction_set_root": self.roots.active_auction_set_root,
                "bidder_commitments_root": self.roots.bidder_commitments_root,
                "dutch_auctions_root": self.roots.dutch_auctions_root,
                "margin_accounts_root": self.roots.margin_accounts_root,
                "oracle_attestations_root": self.roots.oracle_attestations_root,
                "partial_receipts_root": self.roots.partial_receipts_root,
                "public_event_log_root": self.roots.public_event_log_root,
                "rebate_pools_root": self.roots.rebate_pools_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "risk_buckets_root": self.roots.risk_buckets_root,
                "sealed_trigger_queue_root": self.roots.sealed_trigger_queue_root,
                "sealed_triggers_root": self.roots.sealed_triggers_root
            },
            "schema_version": SCHEMA_VERSION
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn recompute_roots(&mut self) {
        self.roots.margin_accounts_root = map_root("MARGIN-ACCOUNTS", &self.margin_accounts);
        self.roots.risk_buckets_root = map_root("RISK-BUCKETS", &self.risk_buckets);
        self.roots.sealed_triggers_root = map_root("SEALED-TRIGGERS", &self.sealed_triggers);
        self.roots.dutch_auctions_root = map_root("DUTCH-AUCTIONS", &self.dutch_auctions);
        self.roots.bidder_commitments_root =
            map_root("BIDDER-COMMITMENTS", &self.bidder_commitments);
        self.roots.oracle_attestations_root =
            map_root("ORACLE-ATTESTATIONS", &self.oracle_attestations);
        self.roots.rebate_pools_root = map_root("REBATE-POOLS", &self.rebate_pools);
        self.roots.partial_receipts_root = map_root("PARTIAL-RECEIPTS", &self.partial_receipts);
        self.roots.redaction_budgets_root = map_root("REDACTION-BUDGETS", &self.redaction_budgets);
        self.roots.active_auction_set_root =
            set_root("ACTIVE-AUCTION-SET", &self.active_auction_ids);
        self.roots.sealed_trigger_queue_root =
            set_root("SEALED-TRIGGER-QUEUE", &self.sealed_trigger_queue);
        self.roots.public_event_log_root =
            string_root("PUBLIC-EVENT-LOG", self.public_event_log.iter());
        self.roots.state_root = self.state_root();
    }

    fn ensure_capacity(&self, label: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exceeded: {len} >= {max}"))
        } else {
            Ok(())
        }
    }

    fn require_account(&self, account_id: &str) -> Result<()> {
        if self.margin_accounts.contains_key(account_id) {
            Ok(())
        } else {
            Err(format!("unknown margin account: {account_id}"))
        }
    }

    fn require_risk_bucket(&self, bucket_id: &str) -> Result<()> {
        if self.risk_buckets.contains_key(bucket_id) {
            Ok(())
        } else {
            Err(format!("unknown risk bucket: {bucket_id}"))
        }
    }

    fn require_oracle_attestation(&self, attestation_id: &str) -> Result<()> {
        if self.oracle_attestations.contains_key(attestation_id) {
            Ok(())
        } else {
            Err(format!("unknown oracle attestation: {attestation_id}"))
        }
    }

    fn require_trigger(&self, trigger_id: &str) -> Result<()> {
        if self.sealed_triggers.contains_key(trigger_id) {
            Ok(())
        } else {
            Err(format!("unknown sealed trigger: {trigger_id}"))
        }
    }

    fn require_auction(&self, auction_id: &str) -> Result<()> {
        if self.dutch_auctions.contains_key(auction_id) {
            Ok(())
        } else {
            Err(format!("unknown dutch auction: {auction_id}"))
        }
    }

    fn require_bid(&self, bid_id: &str) -> Result<()> {
        if self.bidder_commitments.contains_key(bid_id) {
            Ok(())
        } else {
            Err(format!("unknown bidder commitment: {bid_id}"))
        }
    }

    fn push_event(&mut self, kind: &str, id: &str) {
        let event = deterministic_id(
            "LIQUIDATION-RUNTIME-EVENT",
            &[kind, id, &self.counters.next_sequence.to_string()],
        );
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.public_event_log.push(event);
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

macro_rules! impl_public_record_forward {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl PublicRecord for $ty {
                fn public_record(&self) -> Value {
                    <$ty>::public_record(self)
                }
            }
        )+
    };
}

impl_public_record_forward!(
    ConfidentialCommitment,
    MarginAccount,
    RiskBucket,
    OraclePqAttestation,
    SealedLiquidationTrigger,
    DutchAuction,
    BidderCommitment,
    RebatePool,
    PartialLiquidationReceipt,
    PrivacyRedactionBudget,
);

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    hash_json(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-MARGIN-LIQUIDATION-DUTCH-AUCTION-STATE-ROOT",
        record,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CROSS-MARGIN-LIQUIDATION-{domain}"),
        records,
    )
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn hash_json(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn nullifier_id(domain: &str, parts: &[&str]) -> String {
    deterministic_id(
        &format!("NULLIFIER-{domain}"),
        &[CHAIN_ID, PROTOCOL_VERSION, &parts.join(":")],
    )
}

pub fn rebate_pool_id(auction_id: &str) -> String {
    deterministic_id("REBATE-POOL-ID", &[auction_id])
}

pub fn redaction_budget_id(account_id: &str) -> String {
    deterministic_id("REDACTION-BUDGET-ID", &[account_id])
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CROSS-MARGIN-LIQUIDATION-{domain}"),
        &[],
    )
}

pub fn map_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(id, item)| json!({"id": id, "record": item.public_record()}))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|item| json!({"item": item}))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn string_root<'a, I>(domain: &str, values: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = values
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

pub fn require_nonzero(label: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{label} must be nonzero"))
    } else {
        Ok(())
    }
}

pub fn require_bps(label: &str, value: u64) -> Result<()> {
    if value <= MAX_BPS {
        Ok(())
    } else {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    }
}

pub fn require_eq(label: &str, value: &str, expected: &str) -> Result<()> {
    if value == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} mismatch: expected {expected}, got {value}"
        ))
    }
}
