use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-sponsored-bundle-relay-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_ENCRYPTION_SUITE: &str =
    "ml-kem-1024+x25519-hybrid-encrypted-l2-bundle-v1";
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_RECEIPT_SUITE: &str =
    "zk-pq-private-l2-sponsored-relay-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_NULLIFIER_SUITE: &str =
    "zk-nullifier-fence-sponsored-bundle-relay-v1";
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_REBATE_SUITE: &str =
    "roots-only-low-fee-sponsored-bundle-rebate-v1";
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEVNET_HEIGHT: u64 = 1_184_000;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_LANES: usize = 128;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_BUNDLES: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_QUOTES: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_WINDOWS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_WINDOW_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS: u64 = 7;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MIN_SPONSOR_COVER_BPS: u64 =
    7_500;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 10;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 40;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 64;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_WINDOW_BUNDLES: usize =
    16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayLaneKind {
    PrivateContractCall,
    DefiSwap,
    StableSwap,
    Lending,
    Perpetuals,
    Options,
    VaultStrategy,
    AccountAbstraction,
    OracleThenCall,
    Bridge,
    SettlementHook,
    EmergencyEscape,
}

impl RelayLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiSwap => "defi_swap",
            Self::StableSwap => "stable_swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::VaultStrategy => "vault_strategy",
            Self::AccountAbstraction => "account_abstraction",
            Self::OracleThenCall => "oracle_then_call",
            Self::Bridge => "bridge",
            Self::SettlementHook => "settlement_hook",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::SettlementHook => 9_800,
            Self::Perpetuals => 9_300,
            Self::Bridge => 9_100,
            Self::DefiSwap => 9_000,
            Self::StableSwap => 8_800,
            Self::PrivateContractCall => 8_600,
            Self::OracleThenCall => 8_400,
            Self::Lending => 8_200,
            Self::Options => 7_900,
            Self::VaultStrategy => 7_700,
            Self::AccountAbstraction => 7_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayLaneStatus {
    Open,
    Congested,
    SponsorOnly,
    Draining,
    Paused,
    Retired,
}

impl RelayLaneStatus {
    pub fn accepts_bundles(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::SponsorOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    ContractCall,
    MultiCall,
    AmmSwap,
    StableSwap,
    LendingSupply,
    LendingBorrow,
    PerpOpen,
    PerpClose,
    OptionMint,
    VaultDeposit,
    VaultWithdraw,
    AccountAbstractionUserOp,
    OracleReadThenCall,
    BridgeLock,
    BridgeRelease,
    SettlementCallback,
}

impl BundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::MultiCall => "multi_call",
            Self::AmmSwap => "amm_swap",
            Self::StableSwap => "stable_swap",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::OptionMint => "option_mint",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::AccountAbstractionUserOp => "account_abstraction_user_op",
            Self::OracleReadThenCall => "oracle_read_then_call",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::SettlementCallback => "settlement_callback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Encrypted,
    Quoted,
    Sponsored,
    Windowed,
    Relayed,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

impl BundleStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Quoted | Self::Sponsored | Self::Windowed | Self::Relayed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Paused,
    Draining,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorStatus {
    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Reserved,
    Filled,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sealed,
    Relayed,
    Settled,
    RebatePosted,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Included,
    Settled,
    Rebated,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    Donated,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHealthStatus {
    Healthy,
    Degraded,
    Congested,
    Failing,
    Paused,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub encryption_suite: String,
    pub receipt_suite: String,
    pub nullifier_suite: String,
    pub rebate_suite: String,
    pub max_lanes: usize,
    pub max_bundles: usize,
    pub max_quotes: usize,
    pub max_windows: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub min_privacy_set_size: u64,
    pub window_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub min_sponsor_cover_bps: u64,
    pub target_rebate_bps: u64,
    pub quote_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub coalesced_window_blocks: u64,
    pub max_window_bundles: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_HASH_SUITE.to_string(),
            encryption_suite: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_ENCRYPTION_SUITE
                .to_string(),
            receipt_suite: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_RECEIPT_SUITE
                .to_string(),
            nullifier_suite: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_NULLIFIER_SUITE
                .to_string(),
            rebate_suite: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_REBATE_SUITE
                .to_string(),
            max_lanes: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_LANES,
            max_bundles: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_BUNDLES,
            max_quotes: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_QUOTES,
            max_windows: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_WINDOWS,
            max_receipts: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_REBATES,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            window_privacy_set_size:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_WINDOW_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
            min_sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MIN_SPONSOR_COVER_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            bundle_ttl_blocks:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_BUNDLE_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            coalesced_window_blocks:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_WINDOW_BLOCKS,
            max_window_bundles:
                PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEFAULT_MAX_WINDOW_BUNDLES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "encryption_suite": self.encryption_suite,
            "receipt_suite": self.receipt_suite,
            "nullifier_suite": self.nullifier_suite,
            "rebate_suite": self.rebate_suite,
            "max_lanes": self.max_lanes,
            "max_bundles": self.max_bundles,
            "max_quotes": self.max_quotes,
            "max_windows": self.max_windows,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "min_privacy_set_size": self.min_privacy_set_size,
            "window_privacy_set_size": self.window_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "min_sponsor_cover_bps": self.min_sponsor_cover_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "coalesced_window_blocks": self.coalesced_window_blocks,
            "max_window_bundles": self.max_window_bundles,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RelayLane {
    pub lane_id: String,
    pub lane_kind: RelayLaneKind,
    pub status: RelayLaneStatus,
    pub route_id: String,
    pub sequencer_committee: String,
    pub sponsor_allowlist_root: String,
    pub accepted_contract_root: String,
    pub priority_weight: u64,
    pub base_fee_microunits: u64,
    pub congestion_multiplier_bps: u64,
    pub target_latency_ms: u64,
    pub max_bundle_gas: u64,
    pub max_window_bundles: usize,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl RelayLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind,
            "status": self.status,
            "route_id": self.route_id,
            "sequencer_committee": self.sequencer_committee,
            "sponsor_allowlist_root": self.sponsor_allowlist_root,
            "accepted_contract_root": self.accepted_contract_root,
            "priority_weight": self.priority_weight,
            "base_fee_microunits": self.base_fee_microunits,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "target_latency_ms": self.target_latency_ms,
            "max_bundle_gas": self.max_bundle_gas,
            "max_window_bundles": self.max_window_bundles,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SponsorCreditAccount {
    pub sponsor_id: String,
    pub status: SponsorStatus,
    pub owner_commitment: String,
    pub lane_allowlist_root: String,
    pub policy_root: String,
    pub available_credit_microunits: u64,
    pub reserved_credit_microunits: u64,
    pub spent_credit_microunits: u64,
    pub rebate_credit_microunits: u64,
    pub max_cover_bps: u64,
    pub min_rebate_bps: u64,
    pub priority_boost_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl SponsorCreditAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "lane_allowlist_root": self.lane_allowlist_root,
            "policy_root": self.policy_root,
            "available_credit_microunits": self.available_credit_microunits,
            "reserved_credit_microunits": self.reserved_credit_microunits,
            "spent_credit_microunits": self.spent_credit_microunits,
            "rebate_credit_microunits": self.rebate_credit_microunits,
            "max_cover_bps": self.max_cover_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "priority_boost_bps": self.priority_boost_bps,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub sponsor_id: Option<String>,
    pub bundle_kind: BundleKind,
    pub status: BundleStatus,
    pub sender_commitment: String,
    pub target_contract_root: String,
    pub encrypted_payload_hash: String,
    pub encrypted_payload_size_bytes: u64,
    pub call_data_commitment: String,
    pub asset_flow_commitment: String,
    pub dependency_root: String,
    pub nullifier_hash: String,
    pub privacy_fence_id: String,
    pub gas_limit: u64,
    pub user_fee_limit_microunits: u64,
    pub max_fee_bps: u64,
    pub quote_id: Option<String>,
    pub window_id: Option<String>,
    pub receipt_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "bundle_kind": self.bundle_kind,
            "status": self.status,
            "sender_commitment": self.sender_commitment,
            "target_contract_root": self.target_contract_root,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "encrypted_payload_size_bytes": self.encrypted_payload_size_bytes,
            "call_data_commitment": self.call_data_commitment,
            "asset_flow_commitment": self.asset_flow_commitment,
            "dependency_root": self.dependency_root,
            "nullifier_hash": self.nullifier_hash,
            "privacy_fence_id": self.privacy_fence_id,
            "gas_limit": self.gas_limit,
            "user_fee_limit_microunits": self.user_fee_limit_microunits,
            "max_fee_bps": self.max_fee_bps,
            "quote_id": self.quote_id,
            "window_id": self.window_id,
            "receipt_id": self.receipt_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub sponsor_id: String,
    pub status: QuoteStatus,
    pub user_fee_microunits: u64,
    pub sponsor_cover_microunits: u64,
    pub relay_fee_microunits: u64,
    pub estimated_l1_da_fee_microunits: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub route_health_score: u64,
    pub quote_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "user_fee_microunits": self.user_fee_microunits,
            "sponsor_cover_microunits": self.sponsor_cover_microunits,
            "relay_fee_microunits": self.relay_fee_microunits,
            "estimated_l1_da_fee_microunits": self.estimated_l1_da_fee_microunits,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "route_health_score": self.route_health_score,
            "quote_root": self.quote_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CoalescedBatchWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: WindowStatus,
    pub open_height: u64,
    pub close_height: u64,
    pub sealed_at_height: Option<u64>,
    pub bundle_ids: BTreeSet<String>,
    pub bundle_root: String,
    pub nullifier_root: String,
    pub sponsor_root: String,
    pub fee_quote_root: String,
    pub total_user_fee_microunits: u64,
    pub total_sponsor_cover_microunits: u64,
    pub privacy_set_size: u64,
    pub relay_route_id: String,
}

impl CoalescedBatchWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "open_height": self.open_height,
            "close_height": self.close_height,
            "sealed_at_height": self.sealed_at_height,
            "bundle_ids": self.bundle_ids,
            "bundle_root": self.bundle_root,
            "nullifier_root": self.nullifier_root,
            "sponsor_root": self.sponsor_root,
            "fee_quote_root": self.fee_quote_root,
            "total_user_fee_microunits": self.total_user_fee_microunits,
            "total_sponsor_cover_microunits": self.total_sponsor_cover_microunits,
            "privacy_set_size": self.privacy_set_size,
            "relay_route_id": self.relay_route_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RelayReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub window_id: String,
    pub lane_id: String,
    pub status: ReceiptStatus,
    pub inclusion_root: String,
    pub execution_trace_root: String,
    pub settlement_tx_hash: String,
    pub fee_paid_microunits: u64,
    pub sponsor_paid_microunits: u64,
    pub gas_used: u64,
    pub rebate_id: Option<String>,
    pub relayed_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl RelayReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "inclusion_root": self.inclusion_root,
            "execution_trace_root": self.execution_trace_root,
            "settlement_tx_hash": self.settlement_tx_hash,
            "fee_paid_microunits": self.fee_paid_microunits,
            "sponsor_paid_microunits": self.sponsor_paid_microunits,
            "gas_used": self.gas_used,
            "rebate_id": self.rebate_id,
            "relayed_at_height": self.relayed_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RebateClaim {
    pub rebate_id: String,
    pub receipt_id: String,
    pub bundle_id: String,
    pub sponsor_id: String,
    pub status: RebateStatus,
    pub beneficiary_commitment: String,
    pub rebate_microunits: u64,
    pub rebate_bps: u64,
    pub claim_nullifier: String,
    pub proof_root: String,
    pub accrued_at_height: u64,
    pub expires_at_height: u64,
}

impl RebateClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_microunits": self.rebate_microunits,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier": self.claim_nullifier,
            "proof_root": self.proof_root,
            "accrued_at_height": self.accrued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RouteHealth {
    pub route_id: String,
    pub lane_id: String,
    pub status: RouteHealthStatus,
    pub rolling_success_bps: u64,
    pub median_latency_ms: u64,
    pub congestion_bps: u64,
    pub quote_fill_bps: u64,
    pub privacy_set_size: u64,
    pub last_failure_root: String,
    pub updated_at_height: u64,
}

impl RouteHealth {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "rolling_success_bps": self.rolling_success_bps,
            "median_latency_ms": self.median_latency_ms,
            "congestion_bps": self.congestion_bps,
            "quote_fill_bps": self.quote_fill_bps,
            "privacy_set_size": self.privacy_set_size,
            "last_failure_root": self.last_failure_root,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane_id: String,
    pub nullifier_root: String,
    pub used_nullifiers: BTreeSet<String>,
    pub caller_set_root: String,
    pub contract_set_root: String,
    pub min_privacy_set_size: u64,
    pub observed_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "nullifier_root": self.nullifier_root,
            "used_nullifiers": self.used_nullifiers,
            "caller_set_root": self.caller_set_root,
            "contract_set_root": self.contract_set_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "observed_privacy_set_size": self.observed_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RelayEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub lane_id: Option<String>,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl RelayEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "lane_id": self.lane_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub sponsor_count: u64,
    pub encrypted_bundle_count: u64,
    pub active_bundle_count: u64,
    pub quote_count: u64,
    pub open_window_count: u64,
    pub sealed_window_count: u64,
    pub receipt_count: u64,
    pub settled_receipt_count: u64,
    pub rebate_count: u64,
    pub privacy_fence_count: u64,
    pub used_nullifier_count: u64,
    pub route_health_count: u64,
    pub event_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "sponsor_count": self.sponsor_count,
            "encrypted_bundle_count": self.encrypted_bundle_count,
            "active_bundle_count": self.active_bundle_count,
            "quote_count": self.quote_count,
            "open_window_count": self.open_window_count,
            "sealed_window_count": self.sealed_window_count,
            "receipt_count": self.receipt_count,
            "settled_receipt_count": self.settled_receipt_count,
            "rebate_count": self.rebate_count,
            "privacy_fence_count": self.privacy_fence_count,
            "used_nullifier_count": self.used_nullifier_count,
            "route_health_count": self.route_health_count,
            "event_count": self.event_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub sponsor_credit_root: String,
    pub encrypted_bundle_root: String,
    pub fee_quote_root: String,
    pub coalesced_window_root: String,
    pub relay_receipt_root: String,
    pub rebate_root: String,
    pub route_health_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "encrypted_bundle_root": self.encrypted_bundle_root,
            "fee_quote_root": self.fee_quote_root,
            "coalesced_window_root": self.coalesced_window_root,
            "relay_receipt_root": self.relay_receipt_root,
            "rebate_root": self.rebate_root,
            "route_health_root": self.route_health_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub lanes: BTreeMap<String, RelayLane>,
    pub sponsors: BTreeMap<String, SponsorCreditAccount>,
    pub encrypted_bundles: BTreeMap<String, EncryptedBundle>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub windows: BTreeMap<String, CoalescedBatchWindow>,
    pub relay_receipts: BTreeMap<String, RelayReceipt>,
    pub rebates: BTreeMap<String, RebateClaim>,
    pub route_health: BTreeMap<String, RouteHealth>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub used_nullifiers: BTreeSet<String>,
    pub events: Vec<RelayEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            current_height: 0,
            lanes: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            encrypted_bundles: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            windows: BTreeMap::new(),
            relay_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            route_health: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            current_height: PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_DEVNET_HEIGHT,
            ..Self::default()
        };
        let swap_lane_id = relay_lane_id("devnet-route-swap", RelayLaneKind::DefiSwap, 0);
        let call_lane_id = relay_lane_id(
            "devnet-route-contract",
            RelayLaneKind::PrivateContractCall,
            1,
        );
        let escape_lane_id =
            relay_lane_id("devnet-route-escape", RelayLaneKind::EmergencyEscape, 2);
        let sponsor_a = sponsor_id("devnet-sponsor-alpha", "alpha-policy-root", 0);
        let sponsor_b = sponsor_id("devnet-sponsor-beta", "beta-policy-root", 1);

        state
            .register_lane(RelayLane {
                lane_id: swap_lane_id.clone(),
                lane_kind: RelayLaneKind::DefiSwap,
                status: RelayLaneStatus::Open,
                route_id: "devnet-route-swap".to_string(),
                sequencer_committee: "devnet-pq-sequencer-committee-a".to_string(),
                sponsor_allowlist_root: public_record_root(&json!(["alpha", "beta"])),
                accepted_contract_root: public_record_root(&json!(["amm", "stable-swap"])),
                priority_weight: RelayLaneKind::DefiSwap.default_priority(),
                base_fee_microunits: 420,
                congestion_multiplier_bps: 10_200,
                target_latency_ms: 450,
                max_bundle_gas: 2_500_000,
                max_window_bundles: 4_096,
                privacy_set_size: 196_608,
                created_at_height: state.current_height - 80,
                updated_at_height: state.current_height - 2,
            })
            .expect("devnet lane");
        state
            .register_lane(RelayLane {
                lane_id: call_lane_id.clone(),
                lane_kind: RelayLaneKind::PrivateContractCall,
                status: RelayLaneStatus::Open,
                route_id: "devnet-route-contract".to_string(),
                sequencer_committee: "devnet-pq-sequencer-committee-b".to_string(),
                sponsor_allowlist_root: public_record_root(&json!(["alpha"])),
                accepted_contract_root: public_record_root(&json!(["vault", "router", "nft"])),
                priority_weight: RelayLaneKind::PrivateContractCall.default_priority(),
                base_fee_microunits: 360,
                congestion_multiplier_bps: 9_700,
                target_latency_ms: 600,
                max_bundle_gas: 1_750_000,
                max_window_bundles: 8_192,
                privacy_set_size: 147_456,
                created_at_height: state.current_height - 77,
                updated_at_height: state.current_height - 3,
            })
            .expect("devnet lane");
        state
            .register_lane(RelayLane {
                lane_id: escape_lane_id.clone(),
                lane_kind: RelayLaneKind::EmergencyEscape,
                status: RelayLaneStatus::SponsorOnly,
                route_id: "devnet-route-escape".to_string(),
                sequencer_committee: "devnet-pq-sequencer-committee-hot".to_string(),
                sponsor_allowlist_root: public_record_root(&json!(["beta"])),
                accepted_contract_root: public_record_root(&json!(["escape-hatch"])),
                priority_weight: RelayLaneKind::EmergencyEscape.default_priority(),
                base_fee_microunits: 1_200,
                congestion_multiplier_bps: 10_000,
                target_latency_ms: 250,
                max_bundle_gas: 3_000_000,
                max_window_bundles: 1_024,
                privacy_set_size: 65_536,
                created_at_height: state.current_height - 60,
                updated_at_height: state.current_height - 1,
            })
            .expect("devnet lane");

        state
            .register_sponsor(SponsorCreditAccount {
                sponsor_id: sponsor_a.clone(),
                status: SponsorStatus::Active,
                owner_commitment: "dnr1sponsor-alpha-owner-commitment".to_string(),
                lane_allowlist_root: public_record_root(&json!([swap_lane_id, call_lane_id])),
                policy_root: "alpha-policy-root".to_string(),
                available_credit_microunits: 180_000_000,
                reserved_credit_microunits: 0,
                spent_credit_microunits: 8_420_000,
                rebate_credit_microunits: 740_000,
                max_cover_bps: 9_500,
                min_rebate_bps: 4,
                priority_boost_bps: 250,
                opened_at_height: state.current_height - 1_000,
                updated_at_height: state.current_height - 4,
            })
            .expect("devnet sponsor");
        state
            .register_sponsor(SponsorCreditAccount {
                sponsor_id: sponsor_b.clone(),
                status: SponsorStatus::Active,
                owner_commitment: "dnr1sponsor-beta-owner-commitment".to_string(),
                lane_allowlist_root: public_record_root(&json!([escape_lane_id])),
                policy_root: "beta-policy-root".to_string(),
                available_credit_microunits: 90_000_000,
                reserved_credit_microunits: 0,
                spent_credit_microunits: 2_200_000,
                rebate_credit_microunits: 300_000,
                max_cover_bps: 10_000,
                min_rebate_bps: 8,
                priority_boost_bps: 600,
                opened_at_height: state.current_height - 900,
                updated_at_height: state.current_height - 5,
            })
            .expect("devnet sponsor");

        let bundle = state
            .submit_encrypted_bundle(SubmitBundle {
                lane_id: state
                    .lanes
                    .values()
                    .find(|lane| lane.lane_kind == RelayLaneKind::DefiSwap)
                    .expect("swap lane")
                    .lane_id
                    .clone(),
                sponsor_id: Some(sponsor_a),
                bundle_kind: BundleKind::AmmSwap,
                sender_commitment: "dnr1sender-commitment-devnet-swap".to_string(),
                target_contract_root: public_record_root(&json!(["amm-pool-a", "router-a"])),
                encrypted_payload_hash: payload_root(
                    "DEVNET-ENCRYPTED-SWAP",
                    &json!({"ciphertext": "sample"}),
                ),
                encrypted_payload_size_bytes: 18_240,
                call_data_commitment: public_record_root(&json!({"selector": "swap_exact_in"})),
                asset_flow_commitment: public_record_root(&json!({"in": "pUSD", "out": "pETH"})),
                dependency_root: merkle_root("DEVNET-BUNDLE-DEPENDENCIES", &[]),
                nullifier_hash: nullifier_id("devnet-swap-nullifier", 0),
                gas_limit: 1_200_000,
                user_fee_limit_microunits: 1_000,
                max_fee_bps: 9,
            })
            .expect("devnet bundle");
        let quote = state
            .post_fee_quote(PostFeeQuote {
                bundle_id: bundle.clone(),
                sponsor_id: state.sponsors.keys().next().expect("sponsor").clone(),
                user_fee_microunits: 120,
                sponsor_cover_microunits: 740,
                relay_fee_microunits: 860,
                estimated_l1_da_fee_microunits: 210,
                rebate_bps: 6,
                sponsor_cover_bps: 8_604,
            })
            .expect("devnet quote");
        let window = state.open_or_assign_window(&bundle).expect("devnet window");
        state.seal_window(&window).expect("devnet seal");
        let receipt = state
            .record_receipt(RecordReceipt {
                bundle_id: bundle,
                window_id: window,
                quote_id: quote,
                execution_trace_root: public_record_root(&json!({"steps": 7, "ok": true})),
                settlement_tx_hash: tx_hash("devnet-settlement", 0),
                fee_paid_microunits: 120,
                sponsor_paid_microunits: 740,
                gas_used: 1_041_500,
            })
            .expect("devnet receipt");
        state
            .accrue_rebate(&receipt, "dnr1beneficiary-devnet-swap")
            .expect("devnet rebate");
        state
    }

    pub fn register_lane(
        &mut self,
        lane: RelayLane,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<()> {
        if self.lanes.len() >= self.config.max_lanes && !self.lanes.contains_key(&lane.lane_id) {
            return Err("lane capacity exceeded".to_string());
        }
        if lane.privacy_set_size < self.config.min_privacy_set_size {
            return Err("lane privacy set is below configured minimum".to_string());
        }
        self.emit_event(
            "lane_registered",
            &lane.lane_id,
            Some(&lane.lane_id),
            &lane.public_record(),
        );
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn register_sponsor(
        &mut self,
        sponsor: SponsorCreditAccount,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<()> {
        if sponsor.max_cover_bps > PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_MAX_BPS {
            return Err("sponsor cover exceeds bps ceiling".to_string());
        }
        self.emit_event(
            "sponsor_registered",
            &sponsor.sponsor_id,
            None,
            &sponsor.public_record(),
        );
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn submit_encrypted_bundle(
        &mut self,
        request: SubmitBundle,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<String> {
        if self.encrypted_bundles.len() >= self.config.max_bundles {
            return Err("bundle capacity exceeded".to_string());
        }
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "unknown relay lane".to_string())?;
        if !lane.status.accepts_bundles() {
            return Err("relay lane is not accepting bundles".to_string());
        }
        if request.gas_limit > lane.max_bundle_gas {
            return Err("bundle gas exceeds lane maximum".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("bundle fee bps exceeds low-fee ceiling".to_string());
        }
        if self.used_nullifiers.contains(&request.nullifier_hash) {
            return Err("nullifier already consumed".to_string());
        }
        if let Some(sponsor_id) = &request.sponsor_id {
            let sponsor = self
                .sponsors
                .get(sponsor_id)
                .ok_or_else(|| "unknown sponsor".to_string())?;
            if !sponsor.status.accepts_quotes() {
                return Err("sponsor is not active".to_string());
            }
        }

        let fence_id = privacy_fence_id(
            &request.lane_id,
            &request.nullifier_hash,
            self.current_height,
        );
        let bundle_id = encrypted_bundle_id(
            &request.lane_id,
            &request.sender_commitment,
            &request.encrypted_payload_hash,
            &request.nullifier_hash,
            self.current_height,
        );
        let bundle = EncryptedBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id.clone(),
            sponsor_id: request.sponsor_id,
            bundle_kind: request.bundle_kind,
            status: BundleStatus::Encrypted,
            sender_commitment: request.sender_commitment,
            target_contract_root: request.target_contract_root,
            encrypted_payload_hash: request.encrypted_payload_hash,
            encrypted_payload_size_bytes: request.encrypted_payload_size_bytes,
            call_data_commitment: request.call_data_commitment,
            asset_flow_commitment: request.asset_flow_commitment,
            dependency_root: request.dependency_root,
            nullifier_hash: request.nullifier_hash.clone(),
            privacy_fence_id: fence_id.clone(),
            gas_limit: request.gas_limit,
            user_fee_limit_microunits: request.user_fee_limit_microunits,
            max_fee_bps: request.max_fee_bps,
            quote_id: None,
            window_id: None,
            receipt_id: None,
            created_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.bundle_ttl_blocks,
        };
        self.used_nullifiers.insert(request.nullifier_hash.clone());
        self.privacy_fences.insert(
            fence_id.clone(),
            PrivacyFence {
                fence_id,
                lane_id: request.lane_id.clone(),
                nullifier_root: merkle_root(
                    "SPONSORED-BUNDLE-PRIVACY-FENCE-NULLIFIER",
                    &[json!(request.nullifier_hash)],
                ),
                used_nullifiers: BTreeSet::from([request.nullifier_hash]),
                caller_set_root: public_record_root(&json!([bundle.sender_commitment])),
                contract_set_root: bundle.target_contract_root.clone(),
                min_privacy_set_size: self.config.min_privacy_set_size,
                observed_privacy_set_size: lane.privacy_set_size,
                opened_at_height: self.current_height,
                expires_at_height: bundle.expires_at_height,
            },
        );
        self.emit_event(
            "bundle_encrypted",
            &bundle_id,
            Some(&request.lane_id),
            &bundle.public_record(),
        );
        self.encrypted_bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn post_fee_quote(
        &mut self,
        request: PostFeeQuote,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<String> {
        if self.fee_quotes.len() >= self.config.max_quotes {
            return Err("quote capacity exceeded".to_string());
        }
        let bundle = self
            .encrypted_bundles
            .get(&request.bundle_id)
            .ok_or_else(|| "unknown bundle".to_string())?;
        let lane = self
            .lanes
            .get(&bundle.lane_id)
            .ok_or_else(|| "unknown lane".to_string())?;
        let sponsor = self
            .sponsors
            .get(&request.sponsor_id)
            .ok_or_else(|| "unknown sponsor".to_string())?;
        if !sponsor.status.accepts_quotes() {
            return Err("sponsor is not active".to_string());
        }
        if request.sponsor_cover_bps < self.config.min_sponsor_cover_bps {
            return Err("sponsor cover below configured minimum".to_string());
        }
        if request.user_fee_microunits > bundle.user_fee_limit_microunits {
            return Err("quote exceeds user fee limit".to_string());
        }
        if request.sponsor_cover_microunits > sponsor.available_credit_microunits {
            return Err("insufficient sponsor credit".to_string());
        }
        let route_health_score = self
            .route_health
            .get(&lane.route_id)
            .map(route_health_score)
            .unwrap_or(9_000);
        let quote_id = fee_quote_id(
            &request.bundle_id,
            &request.sponsor_id,
            request.relay_fee_microunits,
            self.current_height,
        );
        let quote_root = payload_root(
            "SPONSORED-BUNDLE-FEE-QUOTE",
            &json!({
                "bundle_id": request.bundle_id,
                "sponsor_id": request.sponsor_id,
                "relay_fee_microunits": request.relay_fee_microunits,
                "rebate_bps": request.rebate_bps,
            }),
        );
        let quote = FeeQuote {
            quote_id: quote_id.clone(),
            bundle_id: request.bundle_id.clone(),
            lane_id: bundle.lane_id.clone(),
            sponsor_id: request.sponsor_id.clone(),
            status: QuoteStatus::Posted,
            user_fee_microunits: request.user_fee_microunits,
            sponsor_cover_microunits: request.sponsor_cover_microunits,
            relay_fee_microunits: request.relay_fee_microunits,
            estimated_l1_da_fee_microunits: request.estimated_l1_da_fee_microunits,
            rebate_bps: request.rebate_bps,
            sponsor_cover_bps: request.sponsor_cover_bps,
            route_health_score,
            quote_root,
            posted_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.quote_ttl_blocks,
        };
        if let Some(sponsor) = self.sponsors.get_mut(&request.sponsor_id) {
            sponsor.available_credit_microunits -= request.sponsor_cover_microunits;
            sponsor.reserved_credit_microunits += request.sponsor_cover_microunits;
            sponsor.updated_at_height = self.current_height;
        }
        if let Some(bundle) = self.encrypted_bundles.get_mut(&request.bundle_id) {
            bundle.status = BundleStatus::Quoted;
            bundle.sponsor_id = Some(request.sponsor_id.clone());
            bundle.quote_id = Some(quote_id.clone());
        }
        self.emit_event(
            "fee_quote_posted",
            &quote_id,
            Some(&quote.lane_id),
            &quote.public_record(),
        );
        self.fee_quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn open_or_assign_window(
        &mut self,
        bundle_id: &str,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<String> {
        let bundle = self
            .encrypted_bundles
            .get(bundle_id)
            .ok_or_else(|| "unknown bundle".to_string())?
            .clone();
        let window_id = self
            .windows
            .values()
            .find(|window| {
                window.lane_id == bundle.lane_id
                    && window.status == WindowStatus::Open
                    && window.bundle_ids.len() < self.config.max_window_bundles
                    && self.current_height <= window.close_height
            })
            .map(|window| window.window_id.clone())
            .unwrap_or_else(|| {
                coalesced_window_id(
                    &bundle.lane_id,
                    self.current_height,
                    self.windows.len() as u64,
                )
            });

        if !self.windows.contains_key(&window_id) {
            if self.windows.len() >= self.config.max_windows {
                return Err("window capacity exceeded".to_string());
            }
            let lane = self
                .lanes
                .get(&bundle.lane_id)
                .ok_or_else(|| "unknown lane".to_string())?;
            self.windows.insert(
                window_id.clone(),
                CoalescedBatchWindow {
                    window_id: window_id.clone(),
                    lane_id: bundle.lane_id.clone(),
                    status: WindowStatus::Open,
                    open_height: self.current_height,
                    close_height: self.current_height + self.config.coalesced_window_blocks,
                    sealed_at_height: None,
                    bundle_ids: BTreeSet::new(),
                    bundle_root: merkle_root("SPONSORED-BUNDLE-EMPTY-WINDOW", &[]),
                    nullifier_root: merkle_root("SPONSORED-BUNDLE-EMPTY-NULLIFIERS", &[]),
                    sponsor_root: merkle_root("SPONSORED-BUNDLE-EMPTY-SPONSORS", &[]),
                    fee_quote_root: merkle_root("SPONSORED-BUNDLE-EMPTY-QUOTES", &[]),
                    total_user_fee_microunits: 0,
                    total_sponsor_cover_microunits: 0,
                    privacy_set_size: self
                        .config
                        .window_privacy_set_size
                        .max(lane.privacy_set_size),
                    relay_route_id: lane.route_id.clone(),
                },
            );
        }

        if let Some(window) = self.windows.get_mut(&window_id) {
            window.bundle_ids.insert(bundle_id.to_string());
            window.total_user_fee_microunits += bundle
                .quote_id
                .as_ref()
                .and_then(|quote_id| self.fee_quotes.get(quote_id))
                .map(|quote| quote.user_fee_microunits)
                .unwrap_or(0);
            window.total_sponsor_cover_microunits += bundle
                .quote_id
                .as_ref()
                .and_then(|quote_id| self.fee_quotes.get(quote_id))
                .map(|quote| quote.sponsor_cover_microunits)
                .unwrap_or(0);
            refresh_window_roots(window, &self.encrypted_bundles, &self.fee_quotes);
        }
        if let Some(bundle) = self.encrypted_bundles.get_mut(bundle_id) {
            bundle.window_id = Some(window_id.clone());
            bundle.status = BundleStatus::Windowed;
        }
        self.emit_event(
            "bundle_windowed",
            bundle_id,
            Some(&bundle.lane_id),
            &json!({ "bundle_id": bundle_id, "window_id": window_id }),
        );
        Ok(window_id)
    }

    pub fn seal_window(
        &mut self,
        window_id: &str,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<()> {
        let window = self
            .windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown window".to_string())?;
        if window.status != WindowStatus::Open {
            return Err("window is not open".to_string());
        }
        window.status = WindowStatus::Sealed;
        window.sealed_at_height = Some(self.current_height);
        refresh_window_roots(window, &self.encrypted_bundles, &self.fee_quotes);
        let lane_id = window.lane_id.clone();
        let record = window.public_record();
        self.emit_event("window_sealed", window_id, Some(&lane_id), &record);
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        request: RecordReceipt,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<String> {
        if self.relay_receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        let quote = self
            .fee_quotes
            .get(&request.quote_id)
            .ok_or_else(|| "unknown quote".to_string())?
            .clone();
        let bundle = self
            .encrypted_bundles
            .get(&request.bundle_id)
            .ok_or_else(|| "unknown bundle".to_string())?
            .clone();
        if quote.bundle_id != request.bundle_id {
            return Err("quote does not belong to bundle".to_string());
        }
        let window = self
            .windows
            .get_mut(&request.window_id)
            .ok_or_else(|| "unknown window".to_string())?;
        if !window.bundle_ids.contains(&request.bundle_id) {
            return Err("bundle is not in the window".to_string());
        }
        let receipt_id = relay_receipt_id(
            &request.bundle_id,
            &request.window_id,
            &request.settlement_tx_hash,
            self.current_height,
        );
        let inclusion_root = payload_root(
            "SPONSORED-BUNDLE-RELAY-INCLUSION",
            &json!({
                "bundle_id": request.bundle_id,
                "window_id": request.window_id,
                "bundle_root": window.bundle_root,
            }),
        );
        let receipt = RelayReceipt {
            receipt_id: receipt_id.clone(),
            bundle_id: request.bundle_id.clone(),
            window_id: request.window_id.clone(),
            lane_id: bundle.lane_id.clone(),
            status: ReceiptStatus::Settled,
            inclusion_root,
            execution_trace_root: request.execution_trace_root,
            settlement_tx_hash: request.settlement_tx_hash,
            fee_paid_microunits: request.fee_paid_microunits,
            sponsor_paid_microunits: request.sponsor_paid_microunits,
            gas_used: request.gas_used,
            rebate_id: None,
            relayed_at_height: self.current_height,
            finalized_at_height: Some(self.current_height),
        };
        window.status = WindowStatus::Settled;
        if let Some(bundle) = self.encrypted_bundles.get_mut(&request.bundle_id) {
            bundle.status = BundleStatus::Settled;
            bundle.receipt_id = Some(receipt_id.clone());
        }
        if let Some(quote) = self.fee_quotes.get_mut(&request.quote_id) {
            quote.status = QuoteStatus::Filled;
        }
        if let Some(sponsor) = self.sponsors.get_mut(&quote.sponsor_id) {
            sponsor.reserved_credit_microunits = sponsor
                .reserved_credit_microunits
                .saturating_sub(quote.sponsor_cover_microunits);
            sponsor.spent_credit_microunits += request.sponsor_paid_microunits;
            sponsor.updated_at_height = self.current_height;
        }
        self.emit_event(
            "relay_receipt_recorded",
            &receipt_id,
            Some(&bundle.lane_id),
            &receipt.public_record(),
        );
        self.relay_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn accrue_rebate(
        &mut self,
        receipt_id: &str,
        beneficiary_commitment: &str,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<String> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        let receipt = self
            .relay_receipts
            .get(receipt_id)
            .ok_or_else(|| "unknown receipt".to_string())?
            .clone();
        let bundle = self
            .encrypted_bundles
            .get(&receipt.bundle_id)
            .ok_or_else(|| "unknown bundle".to_string())?
            .clone();
        let quote = bundle
            .quote_id
            .as_ref()
            .and_then(|quote_id| self.fee_quotes.get(quote_id))
            .ok_or_else(|| "bundle has no filled quote".to_string())?
            .clone();
        let rebate_microunits = quote.relay_fee_microunits * quote.rebate_bps
            / PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_MAX_BPS;
        let claim_nullifier = nullifier_id(beneficiary_commitment, self.rebates.len() as u64);
        let rebate_id = rebate_id(receipt_id, beneficiary_commitment, rebate_microunits);
        let rebate = RebateClaim {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            bundle_id: receipt.bundle_id.clone(),
            sponsor_id: quote.sponsor_id.clone(),
            status: RebateStatus::Claimable,
            beneficiary_commitment: beneficiary_commitment.to_string(),
            rebate_microunits,
            rebate_bps: quote.rebate_bps,
            claim_nullifier,
            proof_root: payload_root(
                "SPONSORED-BUNDLE-REBATE-PROOF",
                &json!({ "receipt_id": receipt_id, "quote_root": quote.quote_root }),
            ),
            accrued_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.receipt_ttl_blocks,
        };
        if let Some(bundle) = self.encrypted_bundles.get_mut(&receipt.bundle_id) {
            bundle.status = BundleStatus::Rebated;
        }
        if let Some(receipt) = self.relay_receipts.get_mut(receipt_id) {
            receipt.status = ReceiptStatus::Rebated;
            receipt.rebate_id = Some(rebate_id.clone());
        }
        if let Some(window) = self.windows.get_mut(&receipt.window_id) {
            window.status = WindowStatus::RebatePosted;
        }
        if let Some(sponsor) = self.sponsors.get_mut(&quote.sponsor_id) {
            sponsor.rebate_credit_microunits += rebate_microunits;
            sponsor.updated_at_height = self.current_height;
        }
        self.emit_event(
            "rebate_accrued",
            &rebate_id,
            Some(&receipt.lane_id),
            &rebate.public_record(),
        );
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn update_route_health(
        &mut self,
        health: RouteHealth,
    ) -> PrivateL2LowFeeSponsoredBundleRelayRuntimeResult<()> {
        if !self.lanes.contains_key(&health.lane_id) {
            return Err("unknown lane for route health".to_string());
        }
        self.emit_event(
            "route_health_updated",
            &health.route_id,
            Some(&health.lane_id),
            &health.public_record(),
        );
        self.route_health.insert(health.route_id.clone(), health);
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let active_bundle_count = self
            .encrypted_bundles
            .values()
            .filter(|bundle| bundle.status.active())
            .count() as u64;
        Counters {
            lane_count: self.lanes.len() as u64,
            sponsor_count: self.sponsors.len() as u64,
            encrypted_bundle_count: self.encrypted_bundles.len() as u64,
            active_bundle_count,
            quote_count: self.fee_quotes.len() as u64,
            open_window_count: self
                .windows
                .values()
                .filter(|window| window.status == WindowStatus::Open)
                .count() as u64,
            sealed_window_count: self
                .windows
                .values()
                .filter(|window| window.status == WindowStatus::Sealed)
                .count() as u64,
            receipt_count: self.relay_receipts.len() as u64,
            settled_receipt_count: self
                .relay_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ReceiptStatus::Settled | ReceiptStatus::Rebated
                    )
                })
                .count() as u64,
            rebate_count: self.rebates.len() as u64,
            privacy_fence_count: self.privacy_fences.len() as u64,
            used_nullifier_count: self.used_nullifiers.len() as u64,
            route_health_count: self.route_health.len() as u64,
            event_count: self.events.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let config_root = payload_root("SPONSORED-BUNDLE-CONFIG", &self.config.public_record());
        let lane_root = map_root("SPONSORED-BUNDLE-LANES", &self.lanes);
        let sponsor_credit_root = map_root("SPONSORED-BUNDLE-SPONSORS", &self.sponsors);
        let encrypted_bundle_root = map_root(
            "SPONSORED-BUNDLE-ENCRYPTED-BUNDLES",
            &self.encrypted_bundles,
        );
        let fee_quote_root = map_root("SPONSORED-BUNDLE-FEE-QUOTES", &self.fee_quotes);
        let coalesced_window_root = map_root("SPONSORED-BUNDLE-WINDOWS", &self.windows);
        let relay_receipt_root = map_root("SPONSORED-BUNDLE-RECEIPTS", &self.relay_receipts);
        let rebate_root = map_root("SPONSORED-BUNDLE-REBATES", &self.rebates);
        let route_health_root = map_root("SPONSORED-BUNDLE-ROUTE-HEALTH", &self.route_health);
        let privacy_fence_root = map_root("SPONSORED-BUNDLE-PRIVACY-FENCES", &self.privacy_fences);
        let nullifier_root = merkle_root(
            "SPONSORED-BUNDLE-USED-NULLIFIERS",
            &self
                .used_nullifiers
                .iter()
                .map(|value| json!(value))
                .collect::<Vec<_>>(),
        );
        let event_root = merkle_root(
            "SPONSORED-BUNDLE-EVENTS",
            &self
                .events
                .iter()
                .map(RelayEvent::public_record)
                .collect::<Vec<_>>(),
        );
        let counters_root = payload_root("SPONSORED-BUNDLE-COUNTERS", &counters.public_record());
        let partial = json!({
            "config_root": config_root,
            "lane_root": lane_root,
            "sponsor_credit_root": sponsor_credit_root,
            "encrypted_bundle_root": encrypted_bundle_root,
            "fee_quote_root": fee_quote_root,
            "coalesced_window_root": coalesced_window_root,
            "relay_receipt_root": relay_receipt_root,
            "rebate_root": rebate_root,
            "route_health_root": route_health_root,
            "privacy_fence_root": privacy_fence_root,
            "nullifier_root": nullifier_root,
            "event_root": event_root,
            "counters_root": counters_root,
        });
        Roots {
            config_root,
            lane_root,
            sponsor_credit_root,
            encrypted_bundle_root,
            fee_quote_root,
            coalesced_window_root,
            relay_receipt_root,
            rebate_root,
            route_health_root,
            privacy_fence_root,
            nullifier_root,
            event_root,
            counters_root,
            public_record_root: public_record_root(&partial),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(state_root_from_record(&record));
        record
    }

    pub fn public_record_root(&self) -> String {
        public_record_root(&self.public_record_without_state_root())
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let counters = self.counters();
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "lanes": self.lanes.values().map(RelayLane::public_record).collect::<Vec<_>>(),
            "sponsors": self.sponsors.values().map(SponsorCreditAccount::public_record).collect::<Vec<_>>(),
            "encrypted_bundles": self.encrypted_bundles.values().map(EncryptedBundle::public_record).collect::<Vec<_>>(),
            "fee_quotes": self.fee_quotes.values().map(FeeQuote::public_record).collect::<Vec<_>>(),
            "coalesced_windows": self.windows.values().map(CoalescedBatchWindow::public_record).collect::<Vec<_>>(),
            "relay_receipts": self.relay_receipts.values().map(RelayReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(RebateClaim::public_record).collect::<Vec<_>>(),
            "route_health": self.route_health.values().map(RouteHealth::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "used_nullifiers": self.used_nullifiers,
            "events": self.events.iter().map(RelayEvent::public_record).collect::<Vec<_>>(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str, lane_id: Option<&str>, payload: &Value) {
        let event_id = event_id(
            kind,
            subject_id,
            self.events.len() as u64,
            self.current_height,
        );
        self.events.push(RelayEvent {
            event_id,
            event_kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            lane_id: lane_id.map(str::to_string),
            payload_root: payload_root("SPONSORED-BUNDLE-EVENT-PAYLOAD", payload),
            emitted_at_height: self.current_height,
        });
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubmitBundle {
    pub lane_id: String,
    pub sponsor_id: Option<String>,
    pub bundle_kind: BundleKind,
    pub sender_commitment: String,
    pub target_contract_root: String,
    pub encrypted_payload_hash: String,
    pub encrypted_payload_size_bytes: u64,
    pub call_data_commitment: String,
    pub asset_flow_commitment: String,
    pub dependency_root: String,
    pub nullifier_hash: String,
    pub gas_limit: u64,
    pub user_fee_limit_microunits: u64,
    pub max_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PostFeeQuote {
    pub bundle_id: String,
    pub sponsor_id: String,
    pub user_fee_microunits: u64,
    pub sponsor_cover_microunits: u64,
    pub relay_fee_microunits: u64,
    pub estimated_l1_da_fee_microunits: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecordReceipt {
    pub bundle_id: String,
    pub window_id: String,
    pub quote_id: String,
    pub execution_trace_root: String,
    pub settlement_tx_hash: String,
    pub fee_paid_microunits: u64,
    pub sponsor_paid_microunits: u64,
    pub gas_used: u64,
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-SPONSORED-BUNDLE-RELAY-STATE",
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(record: &Value) -> String {
    payload_root(
        "PRIVATE-L2-LOW-FEE-SPONSORED-BUNDLE-RELAY-PUBLIC-RECORD",
        record,
    )
}

pub fn relay_lane_id(route_id: &str, lane_kind: RelayLaneKind, nonce: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-RELAY-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(lane_kind.as_str()),
            HashPart::U64(nonce),
        ],
        16,
    )
}

pub fn sponsor_id(owner_commitment: &str, policy_root: &str, nonce: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(policy_root),
            HashPart::U64(nonce),
        ],
        16,
    )
}

pub fn encrypted_bundle_id(
    lane_id: &str,
    sender_commitment: &str,
    encrypted_payload_hash: &str,
    nullifier_hash: &str,
    height: u64,
) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-ENCRYPTED-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(sender_commitment),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Str(nullifier_hash),
            HashPart::U64(height),
        ],
        16,
    )
}

pub fn fee_quote_id(
    bundle_id: &str,
    sponsor_id: &str,
    relay_fee_microunits: u64,
    height: u64,
) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-FEE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(sponsor_id),
            HashPart::U64(relay_fee_microunits),
            HashPart::U64(height),
        ],
        16,
    )
}

pub fn coalesced_window_id(lane_id: &str, open_height: u64, ordinal: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-COALESCED-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::U64(open_height),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

pub fn relay_receipt_id(
    bundle_id: &str,
    window_id: &str,
    settlement_tx_hash: &str,
    height: u64,
) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-RELAY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(window_id),
            HashPart::Str(settlement_tx_hash),
            HashPart::U64(height),
        ],
        16,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_commitment: &str, rebate_microunits: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(rebate_microunits),
        ],
        16,
    )
}

pub fn privacy_fence_id(lane_id: &str, nullifier_hash: &str, height: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(nullifier_hash),
            HashPart::U64(height),
        ],
        16,
    )
}

pub fn nullifier_id(seed: &str, nonce: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn tx_hash(seed: &str, nonce: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-TX-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn event_id(kind: &str, subject_id: &str, ordinal: u64, height: u64) -> String {
    domain_hash(
        "SPONSORED-BUNDLE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::U64(ordinal),
            HashPart::U64(height),
        ],
        16,
    )
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for RelayLane {
    fn public_record(&self) -> Value {
        RelayLane::public_record(self)
    }
}

impl PublicRecord for SponsorCreditAccount {
    fn public_record(&self) -> Value {
        SponsorCreditAccount::public_record(self)
    }
}

impl PublicRecord for EncryptedBundle {
    fn public_record(&self) -> Value {
        EncryptedBundle::public_record(self)
    }
}

impl PublicRecord for FeeQuote {
    fn public_record(&self) -> Value {
        FeeQuote::public_record(self)
    }
}

impl PublicRecord for CoalescedBatchWindow {
    fn public_record(&self) -> Value {
        CoalescedBatchWindow::public_record(self)
    }
}

impl PublicRecord for RelayReceipt {
    fn public_record(&self) -> Value {
        RelayReceipt::public_record(self)
    }
}

impl PublicRecord for RebateClaim {
    fn public_record(&self) -> Value {
        RebateClaim::public_record(self)
    }
}

impl PublicRecord for RouteHealth {
    fn public_record(&self) -> Value {
        RouteHealth::public_record(self)
    }
}

impl PublicRecord for PrivacyFence {
    fn public_record(&self) -> Value {
        PrivacyFence::public_record(self)
    }
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|(id, value)| json!({ "id": id, "record": value.public_record() }))
            .collect::<Vec<_>>(),
    )
}

fn refresh_window_roots(
    window: &mut CoalescedBatchWindow,
    bundles: &BTreeMap<String, EncryptedBundle>,
    quotes: &BTreeMap<String, FeeQuote>,
) {
    let bundle_records = window
        .bundle_ids
        .iter()
        .filter_map(|bundle_id| bundles.get(bundle_id))
        .map(EncryptedBundle::public_record)
        .collect::<Vec<_>>();
    let nullifier_records = window
        .bundle_ids
        .iter()
        .filter_map(|bundle_id| bundles.get(bundle_id))
        .map(|bundle| json!(bundle.nullifier_hash))
        .collect::<Vec<_>>();
    let sponsor_records = window
        .bundle_ids
        .iter()
        .filter_map(|bundle_id| bundles.get(bundle_id))
        .filter_map(|bundle| bundle.sponsor_id.as_ref())
        .map(|sponsor_id| json!(sponsor_id))
        .collect::<Vec<_>>();
    let quote_records = window
        .bundle_ids
        .iter()
        .filter_map(|bundle_id| bundles.get(bundle_id))
        .filter_map(|bundle| bundle.quote_id.as_ref())
        .filter_map(|quote_id| quotes.get(quote_id))
        .map(FeeQuote::public_record)
        .collect::<Vec<_>>();
    window.bundle_root = merkle_root("SPONSORED-BUNDLE-WINDOW-BUNDLES", &bundle_records);
    window.nullifier_root = merkle_root("SPONSORED-BUNDLE-WINDOW-NULLIFIERS", &nullifier_records);
    window.sponsor_root = merkle_root("SPONSORED-BUNDLE-WINDOW-SPONSORS", &sponsor_records);
    window.fee_quote_root = merkle_root("SPONSORED-BUNDLE-WINDOW-QUOTES", &quote_records);
}

fn route_health_score(health: &RouteHealth) -> u64 {
    let reliability = health.rolling_success_bps;
    let latency_penalty = (health.median_latency_ms / 10).min(2_000);
    let congestion_penalty = health.congestion_bps / 4;
    reliability
        .saturating_add(health.quote_fill_bps / 10)
        .saturating_sub(latency_penalty)
        .saturating_sub(congestion_penalty)
        .min(PRIVATE_L2_LOW_FEE_SPONSORED_BUNDLE_RELAY_RUNTIME_MAX_BPS)
}
