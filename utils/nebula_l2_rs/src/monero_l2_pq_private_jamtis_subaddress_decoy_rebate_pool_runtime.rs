use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateJamtisSubaddressDecoyRebatePoolRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = MoneroL2PqPrivateJamtisSubaddressDecoyRebatePoolRuntimeResult<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_SUBADDRESS_DECOY_REBATE_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_SUBADDRESS_DECOY_REBATE_POOL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const JAMTIS_SUBADDRESS_LANE_SUITE: &str =
    "monero-jamtis-subaddress-lane-routing-commitment-root-v1";
pub const DECOY_REBATE_POOL_SUITE: &str =
    "monero-l2-private-decoy-rebate-pool-liquidity-commitment-root-v1";
pub const SCAN_CREDIT_CLAIM_SUITE: &str =
    "monero-l2-private-subaddress-scan-credit-claim-nullifier-root-v1";
pub const PQ_SPONSOR_RECEIPT_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-decoy-rebate-sponsor-receipt-root-v1";
pub const PRIVACY_BUDGET_SUITE: &str =
    "operator-safe-jamtis-subaddress-decoy-rebate-privacy-budget-root-v1";
pub const DECOY_QUALITY_PROOF_SUITE: &str =
    "monero-decoy-age-distribution-ring-quality-proof-commitment-root-v1";
pub const NULLIFIER_GUARD_SUITE: &str =
    "jamtis-subaddress-decoy-rebate-nullifier-replay-guard-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-jamtis-subaddress-decoy-rebate-operator-summary-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "jamtis-subaddress-decoy-rebate-pool-public-record-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_view_keys_key_images_subaddress_indices_or_wallet_graphs";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-l2-pq-private-jamtis-subaddress-decoy-rebate-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "xmr-decoy-scan-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 1_711_200;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 64;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_SUBADDRESS_BUCKET_SIZE: u32 = 128;
pub const DEFAULT_TARGET_SUBADDRESS_BUCKET_SIZE: u32 = 2_048;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 8_800;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BPS: u64 = 7_600;
pub const DEFAULT_TARGET_DECOY_QUALITY_BPS: u64 = 9_200;
pub const DEFAULT_MAX_SCAN_FEE_PICONERO: u64 = 3_600;
pub const DEFAULT_TARGET_SCAN_FEE_PICONERO: u64 = 850;
pub const DEFAULT_REBATE_BPS: u64 = 8_900;
pub const DEFAULT_POOL_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u64 = 500;
pub const DEFAULT_SPONSOR_FILL_BPS: u64 = 9_400;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_NULLIFIER_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 65_536;
pub const DEFAULT_MAX_DISCLOSURE_FIELDS: u32 = 4;
pub const DEFAULT_DAILY_WALLET_CAP_PICONERO: u64 = 120_000;
pub const MAX_LANES: usize = 1_048_576;
pub const MAX_POOLS: usize = 262_144;
pub const MAX_SCAN_CLAIMS: usize = 4_194_304;
pub const MAX_SPONSOR_RECEIPTS: usize = 4_194_304;
pub const MAX_QUALITY_PROOFS: usize = 4_194_304;
pub const MAX_PRIVACY_BUDGETS: usize = 2_097_152;
pub const MAX_NULLIFIERS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubaddressLaneKind {
    WalletIncremental,
    WalletRestore,
    MerchantReceive,
    BridgeDeposit,
    BridgeWithdrawal,
    AtomicSwap,
    WatchOnlyAudit,
    ReorgRepair,
    Emergency,
}

impl SubaddressLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletIncremental => "wallet_incremental",
            Self::WalletRestore => "wallet_restore",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::AtomicSwap => "atomic_swap",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::ReorgRepair => 960,
            Self::BridgeWithdrawal => 930,
            Self::BridgeDeposit => 900,
            Self::WalletRestore => 860,
            Self::AtomicSwap => 840,
            Self::MerchantReceive => 820,
            Self::WatchOnlyAudit => 780,
            Self::WalletIncremental => 720,
        }
    }

    pub fn fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::WalletIncremental => config.target_scan_fee_piconero,
            Self::WalletRestore | Self::WatchOnlyAudit => config.max_scan_fee_piconero * 8 / 10,
            Self::MerchantReceive | Self::AtomicSwap => config.max_scan_fee_piconero * 9 / 10,
            Self::BridgeDeposit | Self::BridgeWithdrawal | Self::ReorgRepair | Self::Emergency => {
                config.max_scan_fee_piconero
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Draft,
    Committed,
    Bucketed,
    PoolMatched,
    ClaimReady,
    Sponsored,
    Anchored,
    Settled,
    Expired,
    Rejected,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Bucketed => "bucketed",
            Self::PoolMatched => "pool_matched",
            Self::ClaimReady => "claim_ready",
            Self::Sponsored => "sponsored",
            Self::Anchored => "anchored",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Bucketed
                | Self::PoolMatched
                | Self::ClaimReady
                | Self::Sponsored
                | Self::Anchored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Attested,
    Active,
    Draining,
    Quarantined,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Open,
    Reserved,
    QualityProved,
    SponsorAuthorized,
    Settled,
    ClawedBack,
    Expired,
    Quarantined,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::QualityProved => "quality_proved",
            Self::SponsorAuthorized => "sponsor_authorized",
            Self::Settled => "settled",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn redeemable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Reserved | Self::QualityProved | Self::SponsorAuthorized
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReceiptStatus {
    Submitted,
    Accepted,
    StrongQuorum,
    WeakPqEvidence,
    Revoked,
    Expired,
    Rejected,
}

impl SponsorReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::StrongQuorum => "strong_quorum",
            Self::WeakPqEvidence => "weak_pq_evidence",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn counts_for_settlement(self) -> bool {
        matches!(self, Self::Accepted | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    JamtisSubaddressLane,
    DecoyBucket,
    ScanWork,
    SponsorMetadata,
    QualityProof,
    PublicAudit,
    OperatorSummary,
}

impl BudgetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JamtisSubaddressLane => "jamtis_subaddress_lane",
            Self::DecoyBucket => "decoy_bucket",
            Self::ScanWork => "scan_work",
            Self::SponsorMetadata => "sponsor_metadata",
            Self::QualityProof => "quality_proof",
            Self::PublicAudit => "public_audit",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub bridge_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_subaddress_bucket_size: u32,
    pub target_subaddress_bucket_size: u32,
    pub min_decoy_entropy_bps: u64,
    pub min_decoy_freshness_bps: u64,
    pub target_decoy_quality_bps: u64,
    pub max_scan_fee_piconero: u64,
    pub target_scan_fee_piconero: u64,
    pub rebate_bps: u64,
    pub pool_reserve_bps: u64,
    pub operator_fee_share_bps: u64,
    pub sponsor_fill_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub lane_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub nullifier_ttl_blocks: u64,
    pub privacy_budget_units: u64,
    pub max_disclosure_fields: u32,
    pub daily_wallet_cap_piconero: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_subaddress_bucket_size: DEFAULT_MIN_SUBADDRESS_BUCKET_SIZE,
            target_subaddress_bucket_size: DEFAULT_TARGET_SUBADDRESS_BUCKET_SIZE,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_decoy_freshness_bps: DEFAULT_MIN_DECOY_FRESHNESS_BPS,
            target_decoy_quality_bps: DEFAULT_TARGET_DECOY_QUALITY_BPS,
            max_scan_fee_piconero: DEFAULT_MAX_SCAN_FEE_PICONERO,
            target_scan_fee_piconero: DEFAULT_TARGET_SCAN_FEE_PICONERO,
            rebate_bps: DEFAULT_REBATE_BPS,
            pool_reserve_bps: DEFAULT_POOL_RESERVE_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            sponsor_fill_bps: DEFAULT_SPONSOR_FILL_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            nullifier_ttl_blocks: DEFAULT_NULLIFIER_TTL_BLOCKS,
            privacy_budget_units: DEFAULT_PRIVACY_BUDGET_UNITS,
            max_disclosure_fields: DEFAULT_MAX_DISCLOSURE_FIELDS,
            daily_wallet_cap_piconero: DEFAULT_DAILY_WALLET_CAP_PICONERO,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_ring_size == 0 || self.target_ring_size < self.min_ring_size {
            return Err("invalid ring size bounds".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid privacy set bounds".to_string());
        }
        if self.min_subaddress_bucket_size == 0
            || self.target_subaddress_bucket_size < self.min_subaddress_bucket_size
        {
            return Err("invalid subaddress bucket bounds".to_string());
        }
        if self.min_decoy_entropy_bps > MAX_BPS
            || self.min_decoy_freshness_bps > MAX_BPS
            || self.target_decoy_quality_bps > MAX_BPS
            || self.rebate_bps > MAX_BPS
            || self.pool_reserve_bps > MAX_BPS
            || self.operator_fee_share_bps > MAX_BPS
            || self.sponsor_fill_bps > MAX_BPS
        {
            return Err("basis point configuration exceeds max".to_string());
        }
        if self.target_scan_fee_piconero > self.max_scan_fee_piconero {
            return Err("target scan fee exceeds max scan fee".to_string());
        }
        if self.min_pq_security_bits == 0
            || self.target_pq_security_bits < self.min_pq_security_bits
        {
            return Err("invalid pq security bounds".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "bridge_id": self.bridge_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_subaddress_bucket_size": self.min_subaddress_bucket_size,
            "target_subaddress_bucket_size": self.target_subaddress_bucket_size,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_decoy_freshness_bps": self.min_decoy_freshness_bps,
            "target_decoy_quality_bps": self.target_decoy_quality_bps,
            "max_scan_fee_piconero": self.max_scan_fee_piconero,
            "target_scan_fee_piconero": self.target_scan_fee_piconero,
            "rebate_bps": self.rebate_bps,
            "pool_reserve_bps": self.pool_reserve_bps,
            "operator_fee_share_bps": self.operator_fee_share_bps,
            "sponsor_fill_bps": self.sponsor_fill_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "lane_ttl_blocks": self.lane_ttl_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "nullifier_ttl_blocks": self.nullifier_ttl_blocks,
            "privacy_budget_units": self.privacy_budget_units,
            "max_disclosure_fields": self.max_disclosure_fields,
            "daily_wallet_cap_piconero": self.daily_wallet_cap_piconero,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub jamtis_lanes: u64,
    pub active_lanes: u64,
    pub decoy_rebate_pools: u64,
    pub active_pools: u64,
    pub scan_credit_claims: u64,
    pub settled_claims: u64,
    pub pq_sponsor_receipts: u64,
    pub accepted_sponsor_receipts: u64,
    pub decoy_quality_proofs: u64,
    pub passing_quality_proofs: u64,
    pub privacy_budgets: u64,
    pub nullifier_guards: u64,
    pub replay_rejections: u64,
    pub operator_summaries: u64,
    pub total_reserved_piconero: u64,
    pub total_settled_piconero: u64,
    pub total_scan_fee_piconero: u64,
    pub total_rebate_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "jamtis_lanes": self.jamtis_lanes,
            "active_lanes": self.active_lanes,
            "decoy_rebate_pools": self.decoy_rebate_pools,
            "active_pools": self.active_pools,
            "scan_credit_claims": self.scan_credit_claims,
            "settled_claims": self.settled_claims,
            "pq_sponsor_receipts": self.pq_sponsor_receipts,
            "accepted_sponsor_receipts": self.accepted_sponsor_receipts,
            "decoy_quality_proofs": self.decoy_quality_proofs,
            "passing_quality_proofs": self.passing_quality_proofs,
            "privacy_budgets": self.privacy_budgets,
            "nullifier_guards": self.nullifier_guards,
            "replay_rejections": self.replay_rejections,
            "operator_summaries": self.operator_summaries,
            "total_reserved_piconero": self.total_reserved_piconero,
            "total_settled_piconero": self.total_settled_piconero,
            "total_scan_fee_piconero": self.total_scan_fee_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub jamtis_lane_root: String,
    pub decoy_rebate_pool_root: String,
    pub scan_credit_claim_root: String,
    pub pq_sponsor_receipt_root: String,
    pub privacy_budget_root: String,
    pub decoy_quality_proof_root: String,
    pub nullifier_guard_root: String,
    pub replay_guard_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            counters_root: counters.state_root(),
            jamtis_lane_root: empty_root("jamtis_lanes"),
            decoy_rebate_pool_root: empty_root("decoy_rebate_pools"),
            scan_credit_claim_root: empty_root("scan_credit_claims"),
            pq_sponsor_receipt_root: empty_root("pq_sponsor_receipts"),
            privacy_budget_root: empty_root("privacy_budgets"),
            decoy_quality_proof_root: empty_root("decoy_quality_proofs"),
            nullifier_guard_root: empty_root("nullifier_guards"),
            replay_guard_root: empty_root("replay_guards"),
            operator_summary_root: empty_root("operator_summaries"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "jamtis_lane_root": self.jamtis_lane_root,
            "decoy_rebate_pool_root": self.decoy_rebate_pool_root,
            "scan_credit_claim_root": self.scan_credit_claim_root,
            "pq_sponsor_receipt_root": self.pq_sponsor_receipt_root,
            "privacy_budget_root": self.privacy_budget_root,
            "decoy_quality_proof_root": self.decoy_quality_proof_root,
            "nullifier_guard_root": self.nullifier_guard_root,
            "replay_guard_root": self.replay_guard_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JamtisSubaddressLane {
    pub lane_id: String,
    pub account_commitment: String,
    pub subaddress_bucket_commitment: String,
    pub jamtis_routing_hint_root: String,
    pub viewtag_bucket_root: String,
    pub decoy_bucket_root: String,
    pub kind: SubaddressLaneKind,
    pub status: LaneStatus,
    pub epoch: u64,
    pub anchor_height: u64,
    pub expires_height: u64,
    pub bucket_size: u32,
    pub ring_size: u16,
    pub privacy_set_size: u64,
    pub scan_fee_cap_piconero: u64,
    pub priority_weight: u64,
    pub nullifier_domain: String,
}

impl JamtisSubaddressLane {
    pub fn new(
        config: &Config,
        kind: SubaddressLaneKind,
        account_commitment: impl Into<String>,
        subaddress_bucket_commitment: impl Into<String>,
        jamtis_routing_hint_root: impl Into<String>,
        viewtag_bucket_root: impl Into<String>,
        decoy_bucket_root: impl Into<String>,
        anchor_height: u64,
        bucket_size: u32,
        privacy_set_size: u64,
    ) -> Result<Self> {
        let account_commitment = account_commitment.into();
        let subaddress_bucket_commitment = subaddress_bucket_commitment.into();
        let jamtis_routing_hint_root = jamtis_routing_hint_root.into();
        let viewtag_bucket_root = viewtag_bucket_root.into();
        let decoy_bucket_root = decoy_bucket_root.into();
        let record = json!({
            "account_commitment": account_commitment,
            "subaddress_bucket_commitment": subaddress_bucket_commitment,
            "jamtis_routing_hint_root": jamtis_routing_hint_root,
            "viewtag_bucket_root": viewtag_bucket_root,
            "decoy_bucket_root": decoy_bucket_root,
            "kind": kind.as_str(),
            "anchor_height": anchor_height,
            "bucket_size": bucket_size,
            "privacy_set_size": privacy_set_size,
        });
        let lane_id = id_from_record("jamtis_lane", &record);
        let mut lane = Self {
            lane_id,
            account_commitment,
            subaddress_bucket_commitment,
            jamtis_routing_hint_root,
            viewtag_bucket_root,
            decoy_bucket_root,
            kind,
            status: LaneStatus::Committed,
            epoch: anchor_height / DEVNET_EPOCH,
            anchor_height,
            expires_height: anchor_height.saturating_add(config.lane_ttl_blocks),
            bucket_size,
            ring_size: config.target_ring_size,
            privacy_set_size,
            scan_fee_cap_piconero: kind.fee_cap(config),
            priority_weight: kind.priority_weight(),
            nullifier_domain: deterministic_root("lane_nullifier_domain", &record.to_string()),
        };
        lane.validate(config)?;
        Ok(lane)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_root("account_commitment", &self.account_commitment)?;
        validate_root(
            "subaddress_bucket_commitment",
            &self.subaddress_bucket_commitment,
        )?;
        validate_root("jamtis_routing_hint_root", &self.jamtis_routing_hint_root)?;
        validate_root("viewtag_bucket_root", &self.viewtag_bucket_root)?;
        validate_root("decoy_bucket_root", &self.decoy_bucket_root)?;
        if self.bucket_size < config.min_subaddress_bucket_size {
            return Err("subaddress bucket below minimum".to_string());
        }
        if self.ring_size < config.min_ring_size {
            return Err("ring size below minimum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy set below minimum".to_string());
        }
        if self.scan_fee_cap_piconero > config.max_scan_fee_piconero {
            return Err("scan fee cap exceeds runtime maximum".to_string());
        }
        Ok(())
    }

    pub fn mark_bucketed(&mut self) {
        if self.status.live() {
            self.status = LaneStatus::Bucketed;
        }
    }

    pub fn mark_pool_matched(&mut self) {
        if self.status.live() {
            self.status = LaneStatus::PoolMatched;
        }
    }

    pub fn mark_sponsored(&mut self) {
        if self.status.live() {
            self.status = LaneStatus::Sponsored;
        }
    }

    pub fn expire_if_stale(&mut self, height: u64) -> bool {
        if self.status.live() && height > self.expires_height {
            self.status = LaneStatus::Expired;
            return true;
        }
        false
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "subaddress_bucket_commitment": self.subaddress_bucket_commitment,
            "jamtis_routing_hint_root": self.jamtis_routing_hint_root,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "decoy_bucket_root": self.decoy_bucket_root,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "anchor_height": self.anchor_height,
            "expires_height": self.expires_height,
            "bucket_size": self.bucket_size,
            "ring_size": self.ring_size,
            "privacy_set_size": self.privacy_set_size,
            "scan_fee_cap_piconero": self.scan_fee_cap_piconero,
            "priority_weight": self.priority_weight,
            "nullifier_domain": self.nullifier_domain,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("jamtis_lane", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyRebatePool {
    pub pool_id: String,
    pub sponsor_committee_root: String,
    pub liquidity_commitment_root: String,
    pub decoy_inventory_root: String,
    pub eligible_lane_root: String,
    pub status: PoolStatus,
    pub anchor_height: u64,
    pub expires_height: u64,
    pub reserved_piconero: u64,
    pub available_piconero: u64,
    pub min_quality_bps: u64,
    pub max_scan_fee_piconero: u64,
    pub rebate_bps: u64,
    pub pool_reserve_bps: u64,
    pub sponsor_fill_bps: u64,
}

impl DecoyRebatePool {
    pub fn new(
        config: &Config,
        sponsor_committee_root: impl Into<String>,
        liquidity_commitment_root: impl Into<String>,
        decoy_inventory_root: impl Into<String>,
        eligible_lane_root: impl Into<String>,
        anchor_height: u64,
        available_piconero: u64,
    ) -> Result<Self> {
        let sponsor_committee_root = sponsor_committee_root.into();
        let liquidity_commitment_root = liquidity_commitment_root.into();
        let decoy_inventory_root = decoy_inventory_root.into();
        let eligible_lane_root = eligible_lane_root.into();
        let record = json!({
            "sponsor_committee_root": sponsor_committee_root,
            "liquidity_commitment_root": liquidity_commitment_root,
            "decoy_inventory_root": decoy_inventory_root,
            "eligible_lane_root": eligible_lane_root,
            "anchor_height": anchor_height,
            "available_piconero": available_piconero,
        });
        let mut pool = Self {
            pool_id: id_from_record("decoy_rebate_pool", &record),
            sponsor_committee_root,
            liquidity_commitment_root,
            decoy_inventory_root,
            eligible_lane_root,
            status: PoolStatus::Attested,
            anchor_height,
            expires_height: anchor_height.saturating_add(config.receipt_ttl_blocks),
            reserved_piconero: 0,
            available_piconero,
            min_quality_bps: config.target_decoy_quality_bps,
            max_scan_fee_piconero: config.max_scan_fee_piconero,
            rebate_bps: config.rebate_bps,
            pool_reserve_bps: config.pool_reserve_bps,
            sponsor_fill_bps: config.sponsor_fill_bps,
        };
        pool.validate(config)?;
        Ok(pool)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_root("sponsor_committee_root", &self.sponsor_committee_root)?;
        validate_root("liquidity_commitment_root", &self.liquidity_commitment_root)?;
        validate_root("decoy_inventory_root", &self.decoy_inventory_root)?;
        validate_root("eligible_lane_root", &self.eligible_lane_root)?;
        if self.min_quality_bps
            < config
                .min_decoy_entropy_bps
                .min(config.min_decoy_freshness_bps)
        {
            return Err("pool min quality below configured floor".to_string());
        }
        if self.max_scan_fee_piconero > config.max_scan_fee_piconero {
            return Err("pool scan fee cap exceeds configured maximum".to_string());
        }
        if self.rebate_bps > MAX_BPS
            || self.pool_reserve_bps > MAX_BPS
            || self.sponsor_fill_bps > MAX_BPS
        {
            return Err("pool bps exceeds max".to_string());
        }
        Ok(())
    }

    pub fn reserve(&mut self, amount: u64) -> Result<()> {
        if !self.status.accepts_claims() {
            return Err("pool does not accept claims".to_string());
        }
        if amount > self.available_piconero {
            return Err("insufficient pool liquidity".to_string());
        }
        self.available_piconero = self.available_piconero.saturating_sub(amount);
        self.reserved_piconero = self.reserved_piconero.saturating_add(amount);
        self.status = PoolStatus::Active;
        Ok(())
    }

    pub fn settle(&mut self, amount: u64) {
        self.reserved_piconero = self.reserved_piconero.saturating_sub(amount);
    }

    pub fn release(&mut self, amount: u64) {
        self.reserved_piconero = self.reserved_piconero.saturating_sub(amount);
        self.available_piconero = self.available_piconero.saturating_add(amount);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_committee_root": self.sponsor_committee_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "decoy_inventory_root": self.decoy_inventory_root,
            "eligible_lane_root": self.eligible_lane_root,
            "status": self.status.as_str(),
            "anchor_height": self.anchor_height,
            "expires_height": self.expires_height,
            "reserved_piconero": self.reserved_piconero,
            "available_piconero": self.available_piconero,
            "min_quality_bps": self.min_quality_bps,
            "max_scan_fee_piconero": self.max_scan_fee_piconero,
            "rebate_bps": self.rebate_bps,
            "pool_reserve_bps": self.pool_reserve_bps,
            "sponsor_fill_bps": self.sponsor_fill_bps,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("decoy_rebate_pool", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanCreditClaim {
    pub claim_id: String,
    pub lane_id: String,
    pub pool_id: String,
    pub claim_nullifier: String,
    pub wallet_cap_nullifier: String,
    pub scan_work_commitment: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub status: ClaimStatus,
    pub anchor_height: u64,
    pub expires_height: u64,
    pub scan_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub quality_floor_bps: u64,
    pub privacy_set_size: u64,
}

impl ScanCreditClaim {
    pub fn new(
        config: &Config,
        lane: &JamtisSubaddressLane,
        pool: &DecoyRebatePool,
        claim_nullifier: impl Into<String>,
        wallet_cap_nullifier: impl Into<String>,
        scan_work_commitment: impl Into<String>,
        anchor_height: u64,
        scan_fee_piconero: u64,
    ) -> Result<Self> {
        let claim_nullifier = claim_nullifier.into();
        let wallet_cap_nullifier = wallet_cap_nullifier.into();
        let scan_work_commitment = scan_work_commitment.into();
        validate_root("claim_nullifier", &claim_nullifier)?;
        validate_root("wallet_cap_nullifier", &wallet_cap_nullifier)?;
        validate_root("scan_work_commitment", &scan_work_commitment)?;
        if scan_fee_piconero > lane.scan_fee_cap_piconero
            || scan_fee_piconero > pool.max_scan_fee_piconero
        {
            return Err("scan fee exceeds lane or pool cap".to_string());
        }
        let rebate_piconero = rebate_amount(scan_fee_piconero, pool.rebate_bps, config);
        let fee_commitment = deterministic_root(
            "fee_commitment",
            &format!("{}:{scan_fee_piconero}", lane.lane_id),
        );
        let rebate_commitment = deterministic_root(
            "rebate_commitment",
            &format!("{}:{rebate_piconero}", pool.pool_id),
        );
        let record = json!({
            "lane_id": lane.lane_id,
            "pool_id": pool.pool_id,
            "claim_nullifier": claim_nullifier,
            "wallet_cap_nullifier": wallet_cap_nullifier,
            "scan_work_commitment": scan_work_commitment,
            "fee_commitment": fee_commitment,
            "rebate_commitment": rebate_commitment,
            "anchor_height": anchor_height,
        });
        Ok(Self {
            claim_id: id_from_record("scan_credit_claim", &record),
            lane_id: lane.lane_id.clone(),
            pool_id: pool.pool_id.clone(),
            claim_nullifier,
            wallet_cap_nullifier,
            scan_work_commitment,
            fee_commitment,
            rebate_commitment,
            status: ClaimStatus::Reserved,
            anchor_height,
            expires_height: anchor_height.saturating_add(config.claim_ttl_blocks),
            scan_fee_piconero,
            rebate_piconero,
            quality_floor_bps: pool.min_quality_bps,
            privacy_set_size: lane.privacy_set_size,
        })
    }

    pub fn mark_quality_proved(&mut self) {
        if self.status.redeemable() {
            self.status = ClaimStatus::QualityProved;
        }
    }

    pub fn mark_authorized(&mut self) {
        if self.status.redeemable() {
            self.status = ClaimStatus::SponsorAuthorized;
        }
    }

    pub fn mark_settled(&mut self) {
        self.status = ClaimStatus::Settled;
    }

    pub fn expire_if_stale(&mut self, height: u64) -> bool {
        if self.status.redeemable() && height > self.expires_height {
            self.status = ClaimStatus::Expired;
            return true;
        }
        false
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "lane_id": self.lane_id,
            "pool_id": self.pool_id,
            "claim_nullifier": self.claim_nullifier,
            "wallet_cap_nullifier": self.wallet_cap_nullifier,
            "scan_work_commitment": self.scan_work_commitment,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "status": self.status.as_str(),
            "anchor_height": self.anchor_height,
            "expires_height": self.expires_height,
            "scan_fee_piconero": self.scan_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "quality_floor_bps": self.quality_floor_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("scan_credit_claim", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorReceipt {
    pub receipt_id: String,
    pub claim_id: String,
    pub sponsor_commitment: String,
    pub pq_public_key_root: String,
    pub authorization_root: String,
    pub signature_bundle_root: String,
    pub transcript_root: String,
    pub status: SponsorReceiptStatus,
    pub anchor_height: u64,
    pub expires_height: u64,
    pub pq_security_bits: u16,
    pub sponsor_fill_bps: u64,
}

impl PqSponsorReceipt {
    pub fn new(
        config: &Config,
        claim: &ScanCreditClaim,
        sponsor_commitment: impl Into<String>,
        pq_public_key_root: impl Into<String>,
        authorization_root: impl Into<String>,
        signature_bundle_root: impl Into<String>,
        transcript_root: impl Into<String>,
        anchor_height: u64,
        pq_security_bits: u16,
    ) -> Result<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let pq_public_key_root = pq_public_key_root.into();
        let authorization_root = authorization_root.into();
        let signature_bundle_root = signature_bundle_root.into();
        let transcript_root = transcript_root.into();
        validate_root("sponsor_commitment", &sponsor_commitment)?;
        validate_root("pq_public_key_root", &pq_public_key_root)?;
        validate_root("authorization_root", &authorization_root)?;
        validate_root("signature_bundle_root", &signature_bundle_root)?;
        validate_root("transcript_root", &transcript_root)?;
        if pq_security_bits < config.min_pq_security_bits {
            return Err("pq sponsor receipt below minimum security bits".to_string());
        }
        let status = if pq_security_bits >= config.target_pq_security_bits {
            SponsorReceiptStatus::StrongQuorum
        } else {
            SponsorReceiptStatus::Accepted
        };
        let record = json!({
            "claim_id": claim.claim_id,
            "sponsor_commitment": sponsor_commitment,
            "pq_public_key_root": pq_public_key_root,
            "authorization_root": authorization_root,
            "signature_bundle_root": signature_bundle_root,
            "transcript_root": transcript_root,
            "pq_security_bits": pq_security_bits,
        });
        Ok(Self {
            receipt_id: id_from_record("pq_sponsor_receipt", &record),
            claim_id: claim.claim_id.clone(),
            sponsor_commitment,
            pq_public_key_root,
            authorization_root,
            signature_bundle_root,
            transcript_root,
            status,
            anchor_height,
            expires_height: anchor_height.saturating_add(config.receipt_ttl_blocks),
            pq_security_bits,
            sponsor_fill_bps: config.sponsor_fill_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "sponsor_commitment": self.sponsor_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "authorization_root": self.authorization_root,
            "signature_bundle_root": self.signature_bundle_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "anchor_height": self.anchor_height,
            "expires_height": self.expires_height,
            "pq_security_bits": self.pq_security_bits,
            "sponsor_fill_bps": self.sponsor_fill_bps,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq_sponsor_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyQualityProof {
    pub proof_id: String,
    pub claim_id: String,
    pub decoy_distribution_root: String,
    pub age_histogram_root: String,
    pub ring_member_liquidity_root: String,
    pub anti_linkability_root: String,
    pub entropy_bps: u64,
    pub freshness_bps: u64,
    pub liquidity_bps: u64,
    pub anti_linkability_bps: u64,
    pub quality_bps: u64,
    pub anchor_height: u64,
    pub passed: bool,
}

impl DecoyQualityProof {
    pub fn new(
        config: &Config,
        claim: &ScanCreditClaim,
        decoy_distribution_root: impl Into<String>,
        age_histogram_root: impl Into<String>,
        ring_member_liquidity_root: impl Into<String>,
        anti_linkability_root: impl Into<String>,
        scores: DecoyQualityScores,
        anchor_height: u64,
    ) -> Result<Self> {
        let decoy_distribution_root = decoy_distribution_root.into();
        let age_histogram_root = age_histogram_root.into();
        let ring_member_liquidity_root = ring_member_liquidity_root.into();
        let anti_linkability_root = anti_linkability_root.into();
        validate_root("decoy_distribution_root", &decoy_distribution_root)?;
        validate_root("age_histogram_root", &age_histogram_root)?;
        validate_root("ring_member_liquidity_root", &ring_member_liquidity_root)?;
        validate_root("anti_linkability_root", &anti_linkability_root)?;
        scores.validate()?;
        let quality_bps = weighted_quality_bps(scores);
        let passed = scores.entropy_bps >= config.min_decoy_entropy_bps
            && scores.freshness_bps >= config.min_decoy_freshness_bps
            && quality_bps >= claim.quality_floor_bps;
        let record = json!({
            "claim_id": claim.claim_id,
            "decoy_distribution_root": decoy_distribution_root,
            "age_histogram_root": age_histogram_root,
            "ring_member_liquidity_root": ring_member_liquidity_root,
            "anti_linkability_root": anti_linkability_root,
            "quality_bps": quality_bps,
            "anchor_height": anchor_height,
        });
        Ok(Self {
            proof_id: id_from_record("decoy_quality_proof", &record),
            claim_id: claim.claim_id.clone(),
            decoy_distribution_root,
            age_histogram_root,
            ring_member_liquidity_root,
            anti_linkability_root,
            entropy_bps: scores.entropy_bps,
            freshness_bps: scores.freshness_bps,
            liquidity_bps: scores.liquidity_bps,
            anti_linkability_bps: scores.anti_linkability_bps,
            quality_bps,
            anchor_height,
            passed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "claim_id": self.claim_id,
            "decoy_distribution_root": self.decoy_distribution_root,
            "age_histogram_root": self.age_histogram_root,
            "ring_member_liquidity_root": self.ring_member_liquidity_root,
            "anti_linkability_root": self.anti_linkability_root,
            "entropy_bps": self.entropy_bps,
            "freshness_bps": self.freshness_bps,
            "liquidity_bps": self.liquidity_bps,
            "anti_linkability_bps": self.anti_linkability_bps,
            "quality_bps": self.quality_bps,
            "anchor_height": self.anchor_height,
            "passed": self.passed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("decoy_quality_proof", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct DecoyQualityScores {
    pub entropy_bps: u64,
    pub freshness_bps: u64,
    pub liquidity_bps: u64,
    pub anti_linkability_bps: u64,
}

impl DecoyQualityScores {
    pub fn validate(self) -> Result<()> {
        if self.entropy_bps > MAX_BPS
            || self.freshness_bps > MAX_BPS
            || self.liquidity_bps > MAX_BPS
            || self.anti_linkability_bps > MAX_BPS
        {
            return Err("quality score exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub scope: BudgetScope,
    pub subject_id: String,
    pub redaction_root: String,
    pub disclosed_fields: u32,
    pub budget_units: u64,
    pub spent_units: u64,
    pub min_anonymity_set: u64,
    pub anchor_height: u64,
}

impl PrivacyBudget {
    pub fn new(
        config: &Config,
        scope: BudgetScope,
        subject_id: impl Into<String>,
        redaction_root: impl Into<String>,
        disclosed_fields: u32,
        spent_units: u64,
        min_anonymity_set: u64,
        anchor_height: u64,
    ) -> Result<Self> {
        let subject_id = subject_id.into();
        let redaction_root = redaction_root.into();
        validate_root("redaction_root", &redaction_root)?;
        if disclosed_fields > config.max_disclosure_fields {
            return Err("privacy budget discloses too many fields".to_string());
        }
        if spent_units > config.privacy_budget_units {
            return Err("privacy budget overspent".to_string());
        }
        if min_anonymity_set < config.min_privacy_set_size {
            return Err("privacy budget anonymity set below minimum".to_string());
        }
        let record = json!({
            "scope": scope.as_str(),
            "subject_id": subject_id,
            "redaction_root": redaction_root,
            "anchor_height": anchor_height,
        });
        Ok(Self {
            budget_id: id_from_record("privacy_budget", &record),
            scope,
            subject_id,
            redaction_root,
            disclosed_fields,
            budget_units: config.privacy_budget_units,
            spent_units,
            min_anonymity_set,
            anchor_height,
        })
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "redaction_root": self.redaction_root,
            "disclosed_fields": self.disclosed_fields,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "min_anonymity_set": self.min_anonymity_set,
            "anchor_height": self.anchor_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("privacy_budget", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierGuard {
    pub nullifier: String,
    pub domain: String,
    pub subject_id: String,
    pub first_seen_height: u64,
    pub expires_height: u64,
    pub replay_count: u64,
}

impl NullifierGuard {
    pub fn new(
        config: &Config,
        nullifier: impl Into<String>,
        domain: impl Into<String>,
        subject_id: impl Into<String>,
        first_seen_height: u64,
    ) -> Result<Self> {
        let nullifier = nullifier.into();
        let domain = domain.into();
        validate_root("nullifier", &nullifier)?;
        validate_root("domain", &domain)?;
        Ok(Self {
            nullifier,
            domain,
            subject_id: subject_id.into(),
            first_seen_height,
            expires_height: first_seen_height.saturating_add(config.nullifier_ttl_blocks),
            replay_count: 0,
        })
    }

    pub fn mark_replay(&mut self) {
        self.replay_count = self.replay_count.saturating_add(1);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "domain": self.domain,
            "subject_id": self.subject_id,
            "first_seen_height": self.first_seen_height,
            "expires_height": self.expires_height,
            "replay_count": self.replay_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("nullifier_guard", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub lane_root: String,
    pub pool_root: String,
    pub claim_root: String,
    pub quality_root: String,
    pub receipt_root: String,
    pub privacy_budget_root: String,
    pub epoch: u64,
    pub anchor_height: u64,
    pub active_lanes: u64,
    pub active_pools: u64,
    pub settled_claims: u64,
    pub avg_quality_bps: u64,
    pub avg_scan_fee_piconero: u64,
    pub privacy_budget_remaining_units: u64,
}

impl OperatorSummary {
    pub fn from_state(
        state: &State,
        operator_commitment: impl Into<String>,
        anchor_height: u64,
    ) -> Result<Self> {
        let operator_commitment = operator_commitment.into();
        validate_root("operator_commitment", &operator_commitment)?;
        let active_lanes = state
            .jamtis_lanes
            .values()
            .filter(|lane| lane.status.live())
            .count() as u64;
        let active_pools = state
            .decoy_rebate_pools
            .values()
            .filter(|pool| pool.status.accepts_claims())
            .count() as u64;
        let settled_claims = state
            .scan_credit_claims
            .values()
            .filter(|claim| claim.status == ClaimStatus::Settled)
            .count() as u64;
        let avg_quality_bps = average(
            state
                .decoy_quality_proofs
                .values()
                .map(|proof| proof.quality_bps),
        );
        let avg_scan_fee_piconero = average(
            state
                .scan_credit_claims
                .values()
                .map(|claim| claim.scan_fee_piconero),
        );
        let privacy_budget_remaining_units = state
            .privacy_budgets
            .values()
            .map(PrivacyBudget::remaining_units)
            .sum();
        let record = json!({
            "operator_commitment": operator_commitment,
            "epoch": anchor_height / DEVNET_EPOCH,
            "anchor_height": anchor_height,
            "roots": state.roots.public_record(),
        });
        Ok(Self {
            summary_id: id_from_record("operator_summary", &record),
            operator_commitment,
            lane_root: state.roots.jamtis_lane_root.clone(),
            pool_root: state.roots.decoy_rebate_pool_root.clone(),
            claim_root: state.roots.scan_credit_claim_root.clone(),
            quality_root: state.roots.decoy_quality_proof_root.clone(),
            receipt_root: state.roots.pq_sponsor_receipt_root.clone(),
            privacy_budget_root: state.roots.privacy_budget_root.clone(),
            epoch: anchor_height / DEVNET_EPOCH,
            anchor_height,
            active_lanes,
            active_pools,
            settled_claims,
            avg_quality_bps,
            avg_scan_fee_piconero,
            privacy_budget_remaining_units,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "lane_root": self.lane_root,
            "pool_root": self.pool_root,
            "claim_root": self.claim_root,
            "quality_root": self.quality_root,
            "receipt_root": self.receipt_root,
            "privacy_budget_root": self.privacy_budget_root,
            "epoch": self.epoch,
            "anchor_height": self.anchor_height,
            "active_lanes": self.active_lanes,
            "active_pools": self.active_pools,
            "settled_claims": self.settled_claims,
            "avg_quality_bps": self.avg_quality_bps,
            "avg_scan_fee_piconero": self.avg_scan_fee_piconero,
            "privacy_budget_remaining_units": self.privacy_budget_remaining_units,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub jamtis_lanes: BTreeMap<String, JamtisSubaddressLane>,
    pub decoy_rebate_pools: BTreeMap<String, DecoyRebatePool>,
    pub scan_credit_claims: BTreeMap<String, ScanCreditClaim>,
    pub pq_sponsor_receipts: BTreeMap<String, PqSponsorReceipt>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub decoy_quality_proofs: BTreeMap<String, DecoyQualityProof>,
    pub nullifier_guards: BTreeMap<String, NullifierGuard>,
    pub replay_guards: BTreeSet<String>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Ok(Self {
            config,
            counters,
            roots,
            jamtis_lanes: BTreeMap::new(),
            decoy_rebate_pools: BTreeMap::new(),
            scan_credit_claims: BTreeMap::new(),
            pq_sponsor_receipts: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            decoy_quality_proofs: BTreeMap::new(),
            nullifier_guards: BTreeMap::new(),
            replay_guards: BTreeSet::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet config");
        seed_devnet(&mut state).expect("valid devnet fixture");
        state.refresh_roots();
        state
    }

    pub fn register_lane(
        &mut self,
        kind: SubaddressLaneKind,
        account_commitment: impl Into<String>,
        subaddress_bucket_commitment: impl Into<String>,
        jamtis_routing_hint_root: impl Into<String>,
        viewtag_bucket_root: impl Into<String>,
        decoy_bucket_root: impl Into<String>,
        anchor_height: u64,
        bucket_size: u32,
        privacy_set_size: u64,
    ) -> Result<String> {
        if self.jamtis_lanes.len() >= MAX_LANES {
            return Err("lane capacity reached".to_string());
        }
        let lane = JamtisSubaddressLane::new(
            &self.config,
            kind,
            account_commitment,
            subaddress_bucket_commitment,
            jamtis_routing_hint_root,
            viewtag_bucket_root,
            decoy_bucket_root,
            anchor_height,
            bucket_size,
            privacy_set_size,
        )?;
        let lane_id = lane.lane_id.clone();
        self.jamtis_lanes.insert(lane_id.clone(), lane);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn register_pool(
        &mut self,
        sponsor_committee_root: impl Into<String>,
        liquidity_commitment_root: impl Into<String>,
        decoy_inventory_root: impl Into<String>,
        eligible_lane_root: impl Into<String>,
        anchor_height: u64,
        available_piconero: u64,
    ) -> Result<String> {
        if self.decoy_rebate_pools.len() >= MAX_POOLS {
            return Err("pool capacity reached".to_string());
        }
        let pool = DecoyRebatePool::new(
            &self.config,
            sponsor_committee_root,
            liquidity_commitment_root,
            decoy_inventory_root,
            eligible_lane_root,
            anchor_height,
            available_piconero,
        )?;
        let pool_id = pool.pool_id.clone();
        self.decoy_rebate_pools.insert(pool_id.clone(), pool);
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn reserve_scan_credit(
        &mut self,
        lane_id: &str,
        pool_id: &str,
        claim_nullifier: impl Into<String>,
        wallet_cap_nullifier: impl Into<String>,
        scan_work_commitment: impl Into<String>,
        anchor_height: u64,
        scan_fee_piconero: u64,
    ) -> Result<String> {
        if self.scan_credit_claims.len() >= MAX_SCAN_CLAIMS {
            return Err("scan claim capacity reached".to_string());
        }
        let lane = self
            .jamtis_lanes
            .get(lane_id)
            .ok_or_else(|| "missing lane".to_string())?
            .clone();
        let pool = self
            .decoy_rebate_pools
            .get(pool_id)
            .ok_or_else(|| "missing pool".to_string())?
            .clone();
        let claim_nullifier = claim_nullifier.into();
        self.guard_nullifier(
            claim_nullifier.clone(),
            lane.nullifier_domain.clone(),
            lane_id.to_string(),
            anchor_height,
        )?;
        let claim = ScanCreditClaim::new(
            &self.config,
            &lane,
            &pool,
            claim_nullifier,
            wallet_cap_nullifier,
            scan_work_commitment,
            anchor_height,
            scan_fee_piconero,
        )?;
        let claim_id = claim.claim_id.clone();
        let rebate_piconero = claim.rebate_piconero;
        self.decoy_rebate_pools
            .get_mut(pool_id)
            .ok_or_else(|| "missing pool".to_string())?
            .reserve(rebate_piconero)?;
        if let Some(lane) = self.jamtis_lanes.get_mut(lane_id) {
            lane.mark_pool_matched();
        }
        self.scan_credit_claims.insert(claim_id.clone(), claim);
        self.refresh_roots();
        Ok(claim_id)
    }

    pub fn attach_quality_proof(
        &mut self,
        claim_id: &str,
        decoy_distribution_root: impl Into<String>,
        age_histogram_root: impl Into<String>,
        ring_member_liquidity_root: impl Into<String>,
        anti_linkability_root: impl Into<String>,
        scores: DecoyQualityScores,
        anchor_height: u64,
    ) -> Result<String> {
        if self.decoy_quality_proofs.len() >= MAX_QUALITY_PROOFS {
            return Err("quality proof capacity reached".to_string());
        }
        let claim = self
            .scan_credit_claims
            .get(claim_id)
            .ok_or_else(|| "missing claim".to_string())?
            .clone();
        let proof = DecoyQualityProof::new(
            &self.config,
            &claim,
            decoy_distribution_root,
            age_histogram_root,
            ring_member_liquidity_root,
            anti_linkability_root,
            scores,
            anchor_height,
        )?;
        let proof_id = proof.proof_id.clone();
        if proof.passed {
            if let Some(claim) = self.scan_credit_claims.get_mut(claim_id) {
                claim.mark_quality_proved();
            }
        }
        self.decoy_quality_proofs.insert(proof_id.clone(), proof);
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn attach_pq_sponsor_receipt(
        &mut self,
        claim_id: &str,
        sponsor_commitment: impl Into<String>,
        pq_public_key_root: impl Into<String>,
        authorization_root: impl Into<String>,
        signature_bundle_root: impl Into<String>,
        transcript_root: impl Into<String>,
        anchor_height: u64,
        pq_security_bits: u16,
    ) -> Result<String> {
        if self.pq_sponsor_receipts.len() >= MAX_SPONSOR_RECEIPTS {
            return Err("pq sponsor receipt capacity reached".to_string());
        }
        let claim = self
            .scan_credit_claims
            .get(claim_id)
            .ok_or_else(|| "missing claim".to_string())?
            .clone();
        let receipt = PqSponsorReceipt::new(
            &self.config,
            &claim,
            sponsor_commitment,
            pq_public_key_root,
            authorization_root,
            signature_bundle_root,
            transcript_root,
            anchor_height,
            pq_security_bits,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        if receipt.status.counts_for_settlement() {
            if let Some(claim) = self.scan_credit_claims.get_mut(claim_id) {
                claim.mark_authorized();
            }
        }
        self.pq_sponsor_receipts.insert(receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn settle_claim(&mut self, claim_id: &str) -> Result<()> {
        let claim = self
            .scan_credit_claims
            .get(claim_id)
            .ok_or_else(|| "missing claim".to_string())?
            .clone();
        if claim.status != ClaimStatus::SponsorAuthorized {
            return Err("claim is not sponsor authorized".to_string());
        }
        let has_quality = self
            .decoy_quality_proofs
            .values()
            .any(|proof| proof.claim_id == claim_id && proof.passed);
        if !has_quality {
            return Err("claim missing passing decoy quality proof".to_string());
        }
        let has_receipt = self
            .pq_sponsor_receipts
            .values()
            .any(|receipt| receipt.claim_id == claim_id && receipt.status.counts_for_settlement());
        if !has_receipt {
            return Err("claim missing accepted pq sponsor receipt".to_string());
        }
        if let Some(pool) = self.decoy_rebate_pools.get_mut(&claim.pool_id) {
            pool.settle(claim.rebate_piconero);
        }
        if let Some(lane) = self.jamtis_lanes.get_mut(&claim.lane_id) {
            lane.status = LaneStatus::Settled;
        }
        if let Some(claim) = self.scan_credit_claims.get_mut(claim_id) {
            claim.mark_settled();
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn record_privacy_budget(
        &mut self,
        scope: BudgetScope,
        subject_id: impl Into<String>,
        redaction_root: impl Into<String>,
        disclosed_fields: u32,
        spent_units: u64,
        min_anonymity_set: u64,
        anchor_height: u64,
    ) -> Result<String> {
        if self.privacy_budgets.len() >= MAX_PRIVACY_BUDGETS {
            return Err("privacy budget capacity reached".to_string());
        }
        let budget = PrivacyBudget::new(
            &self.config,
            scope,
            subject_id,
            redaction_root,
            disclosed_fields,
            spent_units,
            min_anonymity_set,
            anchor_height,
        )?;
        let budget_id = budget.budget_id.clone();
        self.privacy_budgets.insert(budget_id.clone(), budget);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn record_operator_summary(
        &mut self,
        operator_commitment: impl Into<String>,
        anchor_height: u64,
    ) -> Result<String> {
        let summary = OperatorSummary::from_state(self, operator_commitment, anchor_height)?;
        let summary_id = summary.summary_id.clone();
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn guard_nullifier(
        &mut self,
        nullifier: impl Into<String>,
        domain: impl Into<String>,
        subject_id: impl Into<String>,
        height: u64,
    ) -> Result<()> {
        if self.nullifier_guards.len() >= MAX_NULLIFIERS {
            return Err("nullifier capacity reached".to_string());
        }
        let nullifier = nullifier.into();
        let domain = domain.into();
        let guard_key = format!("{domain}:{nullifier}");
        if self.replay_guards.contains(&guard_key) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            if let Some(guard) = self.nullifier_guards.get_mut(&guard_key) {
                guard.mark_replay();
            }
            self.refresh_roots();
            return Err("nullifier replay rejected".to_string());
        }
        let guard = NullifierGuard::new(&self.config, nullifier, domain, subject_id, height)?;
        self.replay_guards.insert(guard_key.clone());
        self.nullifier_guards.insert(guard_key, guard);
        self.refresh_roots();
        Ok(())
    }

    pub fn expire_stale(&mut self, height: u64) {
        for lane in self.jamtis_lanes.values_mut() {
            lane.expire_if_stale(height);
        }
        for claim in self.scan_credit_claims.values_mut() {
            if claim.expire_if_stale(height) {
                if let Some(pool) = self.decoy_rebate_pools.get_mut(&claim.pool_id) {
                    pool.release(claim.rebate_piconero);
                }
            }
        }
        self.refresh_roots();
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.compute_counters();
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            jamtis_lane_root: map_root("jamtis_lanes", &self.jamtis_lanes, |lane| {
                lane.public_record()
            }),
            decoy_rebate_pool_root: map_root(
                "decoy_rebate_pools",
                &self.decoy_rebate_pools,
                |pool| pool.public_record(),
            ),
            scan_credit_claim_root: map_root(
                "scan_credit_claims",
                &self.scan_credit_claims,
                |claim| claim.public_record(),
            ),
            pq_sponsor_receipt_root: map_root(
                "pq_sponsor_receipts",
                &self.pq_sponsor_receipts,
                |receipt| receipt.public_record(),
            ),
            privacy_budget_root: map_root("privacy_budgets", &self.privacy_budgets, |budget| {
                budget.public_record()
            }),
            decoy_quality_proof_root: map_root(
                "decoy_quality_proofs",
                &self.decoy_quality_proofs,
                |proof| proof.public_record(),
            ),
            nullifier_guard_root: map_root("nullifier_guards", &self.nullifier_guards, |guard| {
                guard.public_record()
            }),
            replay_guard_root: set_root("replay_guards", &self.replay_guards),
            operator_summary_root: map_root(
                "operator_summaries",
                &self.operator_summaries,
                |summary| summary.public_record(),
            ),
            state_root: String::new(),
        };
        self.roots.state_root = self.state_root();
    }

    pub fn compute_counters(&self) -> Counters {
        Counters {
            jamtis_lanes: self.jamtis_lanes.len() as u64,
            active_lanes: self
                .jamtis_lanes
                .values()
                .filter(|lane| lane.status.live())
                .count() as u64,
            decoy_rebate_pools: self.decoy_rebate_pools.len() as u64,
            active_pools: self
                .decoy_rebate_pools
                .values()
                .filter(|pool| pool.status.accepts_claims())
                .count() as u64,
            scan_credit_claims: self.scan_credit_claims.len() as u64,
            settled_claims: self
                .scan_credit_claims
                .values()
                .filter(|claim| claim.status == ClaimStatus::Settled)
                .count() as u64,
            pq_sponsor_receipts: self.pq_sponsor_receipts.len() as u64,
            accepted_sponsor_receipts: self
                .pq_sponsor_receipts
                .values()
                .filter(|receipt| receipt.status.counts_for_settlement())
                .count() as u64,
            decoy_quality_proofs: self.decoy_quality_proofs.len() as u64,
            passing_quality_proofs: self
                .decoy_quality_proofs
                .values()
                .filter(|proof| proof.passed)
                .count() as u64,
            privacy_budgets: self.privacy_budgets.len() as u64,
            nullifier_guards: self.nullifier_guards.len() as u64,
            replay_rejections: self.counters.replay_rejections,
            operator_summaries: self.operator_summaries.len() as u64,
            total_reserved_piconero: self
                .decoy_rebate_pools
                .values()
                .map(|pool| pool.reserved_piconero)
                .sum(),
            total_settled_piconero: self
                .scan_credit_claims
                .values()
                .filter(|claim| claim.status == ClaimStatus::Settled)
                .map(|claim| claim.rebate_piconero)
                .sum(),
            total_scan_fee_piconero: self
                .scan_credit_claims
                .values()
                .map(|claim| claim.scan_fee_piconero)
                .sum(),
            total_rebate_piconero: self
                .scan_credit_claims
                .values()
                .map(|claim| claim.rebate_piconero)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "jamtis_subaddress_lane_suite": JAMTIS_SUBADDRESS_LANE_SUITE,
            "decoy_rebate_pool_suite": DECOY_REBATE_POOL_SUITE,
            "scan_credit_claim_suite": SCAN_CREDIT_CLAIM_SUITE,
            "pq_sponsor_receipt_suite": PQ_SPONSOR_RECEIPT_SUITE,
            "privacy_budget_suite": PRIVACY_BUDGET_SUITE,
            "decoy_quality_proof_suite": DECOY_QUALITY_PROOF_SUITE,
            "nullifier_guard_suite": NULLIFIER_GUARD_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "roots_root": self.roots.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:state-root",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn seed_devnet(state: &mut State) -> Result<()> {
    let lane_a = state.register_lane(
        SubaddressLaneKind::WalletIncremental,
        deterministic_root("account_commitment", "devnet-wallet-a"),
        deterministic_root("subaddress_bucket", "devnet-wallet-a-bucket-0"),
        deterministic_root("jamtis_hint", "devnet-wallet-a-hints"),
        deterministic_root("viewtag_bucket", "devnet-wallet-a-viewtags"),
        deterministic_root("decoy_bucket", "devnet-wallet-a-decoys"),
        DEVNET_HEIGHT,
        2_048,
        524_288,
    )?;
    let lane_b = state.register_lane(
        SubaddressLaneKind::BridgeWithdrawal,
        deterministic_root("account_commitment", "devnet-bridge-withdrawal"),
        deterministic_root("subaddress_bucket", "devnet-bridge-bucket-7"),
        deterministic_root("jamtis_hint", "devnet-bridge-hints"),
        deterministic_root("viewtag_bucket", "devnet-bridge-viewtags"),
        deterministic_root("decoy_bucket", "devnet-bridge-decoys"),
        DEVNET_HEIGHT + 3,
        4_096,
        1_048_576,
    )?;
    let pool = state.register_pool(
        deterministic_root("sponsor_committee", "devnet-sponsor-committee"),
        deterministic_root("liquidity_commitment", "devnet-rebate-liquidity"),
        deterministic_root("decoy_inventory", "devnet-decoy-inventory"),
        deterministic_root("eligible_lanes", "wallet-and-bridge"),
        DEVNET_HEIGHT + 6,
        2_500_000,
    )?;
    let claim_a = state.reserve_scan_credit(
        &lane_a,
        &pool,
        deterministic_root("claim_nullifier", "wallet-a-claim-0"),
        deterministic_root("wallet_cap_nullifier", "wallet-a-day-0"),
        deterministic_root("scan_work", "wallet-a-viewtag-scan-work"),
        DEVNET_HEIGHT + 9,
        720,
    )?;
    state.attach_quality_proof(
        &claim_a,
        deterministic_root("decoy_distribution", "wallet-a-distribution"),
        deterministic_root("age_histogram", "wallet-a-age-histogram"),
        deterministic_root("liquidity", "wallet-a-ring-liquidity"),
        deterministic_root("anti_linkability", "wallet-a-anti-linkability"),
        DecoyQualityScores {
            entropy_bps: 9_460,
            freshness_bps: 8_920,
            liquidity_bps: 9_180,
            anti_linkability_bps: 9_640,
        },
        DEVNET_HEIGHT + 12,
    )?;
    state.attach_pq_sponsor_receipt(
        &claim_a,
        deterministic_root("sponsor_commitment", "devnet-sponsor-a"),
        deterministic_root("pq_public_key", "devnet-sponsor-a-ml-dsa"),
        deterministic_root("authorization", "devnet-sponsor-a-authorization"),
        deterministic_root("signature_bundle", "devnet-sponsor-a-signature-bundle"),
        deterministic_root("transcript", "devnet-sponsor-a-transcript"),
        DEVNET_HEIGHT + 15,
        256,
    )?;
    state.settle_claim(&claim_a)?;
    let claim_b = state.reserve_scan_credit(
        &lane_b,
        &pool,
        deterministic_root("claim_nullifier", "bridge-withdrawal-claim-0"),
        deterministic_root("wallet_cap_nullifier", "bridge-withdrawal-day-0"),
        deterministic_root("scan_work", "bridge-withdrawal-viewtag-scan-work"),
        DEVNET_HEIGHT + 18,
        1_900,
    )?;
    state.attach_quality_proof(
        &claim_b,
        deterministic_root("decoy_distribution", "bridge-withdrawal-distribution"),
        deterministic_root("age_histogram", "bridge-withdrawal-age-histogram"),
        deterministic_root("liquidity", "bridge-withdrawal-ring-liquidity"),
        deterministic_root("anti_linkability", "bridge-withdrawal-anti-linkability"),
        DecoyQualityScores {
            entropy_bps: 9_280,
            freshness_bps: 8_740,
            liquidity_bps: 9_050,
            anti_linkability_bps: 9_420,
        },
        DEVNET_HEIGHT + 21,
    )?;
    state.attach_pq_sponsor_receipt(
        &claim_b,
        deterministic_root("sponsor_commitment", "devnet-sponsor-b"),
        deterministic_root("pq_public_key", "devnet-sponsor-b-ml-dsa"),
        deterministic_root("authorization", "devnet-sponsor-b-authorization"),
        deterministic_root("signature_bundle", "devnet-sponsor-b-signature-bundle"),
        deterministic_root("transcript", "devnet-sponsor-b-transcript"),
        DEVNET_HEIGHT + 24,
        256,
    )?;
    state.record_privacy_budget(
        BudgetScope::JamtisSubaddressLane,
        lane_a,
        deterministic_root("redaction", "wallet-a-roots-only"),
        2,
        8_192,
        524_288,
        DEVNET_HEIGHT + 27,
    )?;
    state.record_privacy_budget(
        BudgetScope::QualityProof,
        claim_b,
        deterministic_root("redaction", "bridge-quality-roots-only"),
        3,
        12_288,
        1_048_576,
        DEVNET_HEIGHT + 30,
    )?;
    state.record_operator_summary(
        deterministic_root("operator_commitment", "devnet-operator"),
        DEVNET_HEIGHT + 33,
    )?;
    Ok(())
}

fn rebate_amount(scan_fee_piconero: u64, rebate_bps: u64, config: &Config) -> u64 {
    let capped_fee = scan_fee_piconero.min(config.max_scan_fee_piconero);
    capped_fee.saturating_mul(rebate_bps.min(MAX_BPS)) / MAX_BPS
}

fn weighted_quality_bps(scores: DecoyQualityScores) -> u64 {
    scores
        .entropy_bps
        .saturating_mul(40)
        .saturating_add(scores.freshness_bps.saturating_mul(25))
        .saturating_add(scores.liquidity_bps.saturating_mul(20))
        .saturating_add(scores.anti_linkability_bps.saturating_mul(15))
        / 100
}

fn average<I>(values: I) -> u64
where
    I: IntoIterator<Item = u64>,
{
    let mut total = 0u64;
    let mut count = 0u64;
    for value in values {
        total = total.saturating_add(value);
        count = count.saturating_add(1);
    }
    if count == 0 {
        0
    } else {
        total / count
    }
}

fn validate_root(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    if value.len() < 16 {
        return Err(format!("{label} is too short"));
    }
    Ok(())
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:{domain}:root"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:{domain}:id"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        16,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:{domain}:record"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": public(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-jamtis-subaddress-decoy-rebate-pool:{domain}"),
        &leaves,
    )
}
