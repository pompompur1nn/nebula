use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-smoothing-reserve-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_SMOOTHING_RESERVE_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-confidential-fee-smoothing-reserve-auth-v1";
pub const PQ_SEALING_SCHEME: &str = "ml-kem-1024+xwing-sealed-confidential-reserve-drawdown-v1";
pub const RESERVE_ATTESTATION_SCHEME: &str =
    "pq-authenticated-confidential-fee-reserve-attestation-root-v1";
pub const PRIVATE_DRAWDOWN_RECEIPT_SCHEME: &str =
    "zk-pq-private-fee-reserve-drawdown-receipt-root-v1";
pub const LOW_FEE_CLEARING_SCHEME: &str = "private-low-fee-batch-clearing-reserve-netting-root-v1";
pub const REDACTION_ROOT_SCHEME: &str = "operator-safe-redacted-low-fee-reserve-disclosure-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str = "roots-only-low-fee-reserve-operator-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_184_800;
pub const DEVNET_EPOCH: u64 = 6_628;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEVNET_RESERVE_ASSET_ID: &str = "wxmr-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_SUBSIDY_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_WALLET_MICRO_FEE_CAP_PICONERO: u64 = 40_000;
pub const DEFAULT_RESERVE_TARGET_BPS: u64 = 1_800;
pub const DEFAULT_RESERVE_FLOOR_BPS: u64 = 450;
pub const DEFAULT_SPONSOR_MATCH_BPS: u64 = 7_500;
pub const DEFAULT_VOLATILITY_DAMPENING_BPS: u64 = 6_200;
pub const DEFAULT_DA_HEDGE_COVER_BPS: u64 = 8_000;
pub const DEFAULT_PROOF_HEDGE_COVER_BPS: u64 = 7_250;
pub const DEFAULT_EMERGENCY_SUBSIDY_BPS: u64 = 9_000;
pub const DEFAULT_BATCH_CLEARING_REBATE_BPS: u64 = 6_500;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 15;
pub const MAX_BUCKETS: usize = 262_144;
pub const MAX_SPONSORS: usize = 524_288;
pub const MAX_QUOTES: usize = 2_097_152;
pub const MAX_SUBSIDY_WINDOWS: usize = 131_072;
pub const MAX_HEDGES: usize = 1_048_576;
pub const MAX_MICRO_CAPS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_CLEARINGS: usize = 1_048_576;
pub const MAX_REDACTIONS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    WalletTransfer,
    ConfidentialSwap,
    DefiContractCall,
    TokenMintBurn,
    AccountAbstraction,
    MoneroBridgeExit,
    RecursiveProof,
    BlobDa,
    FastPreconfirmation,
    EmergencyEscape,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::DefiContractCall => "defi_contract_call",
            Self::TokenMintBurn => "token_mint_burn",
            Self::AccountAbstraction => "account_abstraction",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::RecursiveProof => "recursive_proof",
            Self::BlobDa => "blob_da",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 3,
            Self::ConfidentialSwap => 5,
            Self::DefiContractCall => 8,
            Self::TokenMintBurn => 4,
            Self::AccountAbstraction => 6,
            Self::MoneroBridgeExit => 9,
            Self::RecursiveProof => 7,
            Self::BlobDa => 6,
            Self::FastPreconfirmation => 5,
            Self::EmergencyEscape => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Proposed,
    Active,
    Conserving,
    Refilling,
    Subsidizing,
    Hedged,
    Frozen,
    Retired,
}

impl BucketStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Conserving | Self::Refilling | Self::Subsidizing | Self::Hedged
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pledged,
    Active,
    Matching,
    Locked,
    Refilling,
    Exhausted,
    Paused,
    Retired,
    Slashed,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Matching | Self::Locked | Self::Refilling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Proposed,
    Dampened,
    ReserveBacked,
    WalletCapped,
    Hedged,
    Accepted,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeKind {
    DaBlobFee,
    RecursiveProofFee,
    MoneroBridgeFee,
    ContractExecutionFee,
    PreconfirmationFee,
    CrossAssetGas,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeStatus {
    Quoted,
    Reserved,
    Live,
    Covering,
    Settled,
    Expired,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyStatus {
    Scheduled,
    Active,
    Drawing,
    CoolingDown,
    Closed,
    Cancelled,
}

impl SubsidyStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::Active | Self::Drawing | Self::CoolingDown
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    PrivateCommitted,
    Attested,
    Batched,
    Settled,
    Redacted,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingStatus {
    Open,
    Reserving,
    Netting,
    Subsidizing,
    ProofQueued,
    Cleared,
    Failed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    WalletIdentity,
    SponsorIdentity,
    ContractCalldata,
    DrawdownAmount,
    HedgeCounterparty,
    OperatorNote,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub quote_asset_id: String,
    pub reserve_asset_id: String,
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub subsidy_window_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub wallet_micro_fee_cap_piconero: u64,
    pub reserve_target_bps: u64,
    pub reserve_floor_bps: u64,
    pub sponsor_match_bps: u64,
    pub volatility_dampening_bps: u64,
    pub da_hedge_cover_bps: u64,
    pub proof_hedge_cover_bps: u64,
    pub emergency_subsidy_bps: u64,
    pub batch_clearing_rebate_bps: u64,
    pub operator_fee_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            subsidy_window_blocks: DEFAULT_SUBSIDY_WINDOW_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            wallet_micro_fee_cap_piconero: DEFAULT_WALLET_MICRO_FEE_CAP_PICONERO,
            reserve_target_bps: DEFAULT_RESERVE_TARGET_BPS,
            reserve_floor_bps: DEFAULT_RESERVE_FLOOR_BPS,
            sponsor_match_bps: DEFAULT_SPONSOR_MATCH_BPS,
            volatility_dampening_bps: DEFAULT_VOLATILITY_DAMPENING_BPS,
            da_hedge_cover_bps: DEFAULT_DA_HEDGE_COVER_BPS,
            proof_hedge_cover_bps: DEFAULT_PROOF_HEDGE_COVER_BPS,
            emergency_subsidy_bps: DEFAULT_EMERGENCY_SUBSIDY_BPS,
            batch_clearing_rebate_bps: DEFAULT_BATCH_CLEARING_REBATE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_scheme": PQ_AUTH_SCHEME,
            "pq_sealing_scheme": PQ_SEALING_SCHEME,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "subsidy_window_blocks": self.subsidy_window_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_user_fee_bps": self.target_user_fee_bps,
            "wallet_micro_fee_cap_piconero": self.wallet_micro_fee_cap_piconero,
            "reserve_target_bps": self.reserve_target_bps,
            "reserve_floor_bps": self.reserve_floor_bps,
            "sponsor_match_bps": self.sponsor_match_bps,
            "volatility_dampening_bps": self.volatility_dampening_bps,
            "da_hedge_cover_bps": self.da_hedge_cover_bps,
            "proof_hedge_cover_bps": self.proof_hedge_cover_bps,
            "emergency_subsidy_bps": self.emergency_subsidy_bps,
            "batch_clearing_rebate_bps": self.batch_clearing_rebate_bps,
            "operator_fee_bps": self.operator_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub buckets_created: u64,
    pub sponsor_deposits: u64,
    pub quotes_issued: u64,
    pub subsidy_windows_opened: u64,
    pub hedges_reserved: u64,
    pub wallet_caps_set: u64,
    pub pq_attestations: u64,
    pub private_receipts: u64,
    pub clearing_batches: u64,
    pub redactions: u64,
    pub reserve_drawdown_piconero: u128,
    pub sponsor_locked_piconero: u128,
    pub user_fee_savings_piconero: u128,
    pub batch_items_cleared: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "buckets_created": self.buckets_created,
            "sponsor_deposits": self.sponsor_deposits,
            "quotes_issued": self.quotes_issued,
            "subsidy_windows_opened": self.subsidy_windows_opened,
            "hedges_reserved": self.hedges_reserved,
            "wallet_caps_set": self.wallet_caps_set,
            "pq_attestations": self.pq_attestations,
            "private_receipts": self.private_receipts,
            "clearing_batches": self.clearing_batches,
            "redactions": self.redactions,
            "reserve_drawdown_piconero": self.reserve_drawdown_piconero,
            "sponsor_locked_piconero": self.sponsor_locked_piconero,
            "user_fee_savings_piconero": self.user_fee_savings_piconero,
            "batch_items_cleared": self.batch_items_cleared,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bucket_root: String,
    pub sponsor_root: String,
    pub quote_root: String,
    pub subsidy_root: String,
    pub hedge_root: String,
    pub wallet_cap_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub clearing_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bucket_root": self.bucket_root,
            "sponsor_root": self.sponsor_root,
            "quote_root": self.quote_root,
            "subsidy_root": self.subsidy_root,
            "hedge_root": self.hedge_root,
            "wallet_cap_root": self.wallet_cap_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "clearing_root": self.clearing_root,
            "redaction_root": self.redaction_root,
            "operator_summary_root": self.operator_summary_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveBucketRecord {
    pub bucket_id: String,
    pub lane: FeeLane,
    pub status: BucketStatus,
    pub reserve_commitment: String,
    pub available_piconero: u128,
    pub target_piconero: u128,
    pub floor_piconero: u128,
    pub smoothed_fee_bps: u64,
    pub max_drawdown_bps: u64,
    pub refill_priority: u64,
    pub sponsor_set_root: String,
    pub hedge_set_root: String,
    pub redaction_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl ReserveBucketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "lane_priority_weight": self.lane.priority_weight(),
            "status": self.status,
            "usable": self.status.usable(),
            "reserve_commitment": self.reserve_commitment,
            "available_piconero": self.available_piconero,
            "target_piconero": self.target_piconero,
            "floor_piconero": self.floor_piconero,
            "smoothed_fee_bps": self.smoothed_fee_bps,
            "max_drawdown_bps": self.max_drawdown_bps,
            "refill_priority": self.refill_priority,
            "sponsor_set_root": self.sponsor_set_root,
            "hedge_set_root": self.hedge_set_root,
            "redaction_root": self.redaction_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorDepositRecord {
    pub sponsor_id: String,
    pub deposit_id: String,
    pub status: SponsorStatus,
    pub bucket_id: String,
    pub sponsor_commitment: String,
    pub locked_amount_piconero: u128,
    pub match_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_attestation_id: String,
    pub covenant_root: String,
    pub refund_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorDepositRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "deposit_id": self.deposit_id,
            "status": self.status,
            "usable": self.status.usable(),
            "bucket_id": self.bucket_id,
            "sponsor_commitment": self.sponsor_commitment,
            "locked_amount_piconero": self.locked_amount_piconero,
            "match_bps": self.match_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_attestation_id": self.pq_attestation_id,
            "covenant_root": self.covenant_root,
            "refund_commitment": self.refund_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VolatilityDampeningQuote {
    pub quote_id: String,
    pub wallet_cap_id: String,
    pub lane: FeeLane,
    pub status: QuoteStatus,
    pub request_commitment: String,
    pub raw_fee_piconero: u64,
    pub smoothed_fee_piconero: u64,
    pub wallet_cap_piconero: u64,
    pub reserve_subsidy_piconero: u64,
    pub volatility_index_bps: u64,
    pub dampening_bps: u64,
    pub da_hedge_id: Option<String>,
    pub proof_hedge_id: Option<String>,
    pub expires_at_height: u64,
}

impl VolatilityDampeningQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "wallet_cap_id": self.wallet_cap_id,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "status": self.status,
            "request_commitment": self.request_commitment,
            "raw_fee_piconero": self.raw_fee_piconero,
            "smoothed_fee_piconero": self.smoothed_fee_piconero,
            "wallet_cap_piconero": self.wallet_cap_piconero,
            "reserve_subsidy_piconero": self.reserve_subsidy_piconero,
            "volatility_index_bps": self.volatility_index_bps,
            "dampening_bps": self.dampening_bps,
            "da_hedge_id": self.da_hedge_id,
            "proof_hedge_id": self.proof_hedge_id,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmergencySubsidyWindow {
    pub window_id: String,
    pub status: SubsidyStatus,
    pub lane_set: BTreeSet<FeeLane>,
    pub trigger_root: String,
    pub reserve_cap_piconero: u128,
    pub drawn_piconero: u128,
    pub subsidy_bps: u64,
    pub operator_quorum_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl EmergencySubsidyWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "status": self.status,
            "live": self.status.live(),
            "lane_set": self.lane_set,
            "trigger_root": self.trigger_root,
            "reserve_cap_piconero": self.reserve_cap_piconero,
            "drawn_piconero": self.drawn_piconero,
            "subsidy_bps": self.subsidy_bps,
            "operator_quorum_root": self.operator_quorum_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeHedgeRecord {
    pub hedge_id: String,
    pub kind: HedgeKind,
    pub status: HedgeStatus,
    pub lane: FeeLane,
    pub notional_piconero: u128,
    pub cover_bps: u64,
    pub premium_piconero: u64,
    pub counterparty_commitment: String,
    pub settlement_root: String,
    pub pq_signature_root: String,
    pub expires_at_height: u64,
}

impl FeeHedgeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "hedge_id": self.hedge_id,
            "kind": self.kind,
            "status": self.status,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "notional_piconero": self.notional_piconero,
            "cover_bps": self.cover_bps,
            "premium_piconero": self.premium_piconero,
            "counterparty_commitment": self.counterparty_commitment,
            "settlement_root": self.settlement_root,
            "pq_signature_root": self.pq_signature_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletMicroFeeCap {
    pub cap_id: String,
    pub wallet_commitment: String,
    pub lane_set: BTreeSet<FeeLane>,
    pub per_tx_cap_piconero: u64,
    pub epoch_cap_piconero: u64,
    pub consumed_piconero: u64,
    pub sponsor_bucket_id: String,
    pub private_policy_root: String,
    pub expires_at_height: u64,
}

impl WalletMicroFeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "wallet_commitment": self.wallet_commitment,
            "lane_set": self.lane_set,
            "per_tx_cap_piconero": self.per_tx_cap_piconero,
            "epoch_cap_piconero": self.epoch_cap_piconero,
            "consumed_piconero": self.consumed_piconero,
            "sponsor_bucket_id": self.sponsor_bucket_id,
            "private_policy_root": self.private_policy_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqReserveAttestation {
    pub attestation_id: String,
    pub attestor_id: String,
    pub reserve_root: String,
    pub bucket_root: String,
    pub sponsor_root: String,
    pub min_security_bits: u16,
    pub pq_signature_root: String,
    pub transcript_hash: String,
    pub produced_at_height: u64,
}

impl PqReserveAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestor_id": self.attestor_id,
            "reserve_root": self.reserve_root,
            "bucket_root": self.bucket_root,
            "sponsor_root": self.sponsor_root,
            "min_security_bits": self.min_security_bits,
            "pq_signature_root": self.pq_signature_root,
            "transcript_hash": self.transcript_hash,
            "produced_at_height": self.produced_at_height,
            "scheme": RESERVE_ATTESTATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateDrawdownReceipt {
    pub receipt_id: String,
    pub quote_id: String,
    pub bucket_id: String,
    pub status: ReceiptStatus,
    pub drawdown_commitment: String,
    pub sealed_wallet_hint: String,
    pub reserve_delta_piconero: i128,
    pub user_fee_savings_piconero: u64,
    pub nullifier_hash: String,
    pub redaction_id: String,
    pub produced_at_height: u64,
}

impl PrivateDrawdownReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "quote_id": self.quote_id,
            "bucket_id": self.bucket_id,
            "status": self.status,
            "drawdown_commitment": self.drawdown_commitment,
            "sealed_wallet_hint": self.sealed_wallet_hint,
            "reserve_delta_piconero": self.reserve_delta_piconero,
            "user_fee_savings_piconero": self.user_fee_savings_piconero,
            "nullifier_hash": self.nullifier_hash,
            "redaction_id": self.redaction_id,
            "produced_at_height": self.produced_at_height,
            "scheme": PRIVATE_DRAWDOWN_RECEIPT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBatchClearing {
    pub clearing_id: String,
    pub status: ClearingStatus,
    pub lane: FeeLane,
    pub quote_root: String,
    pub receipt_root: String,
    pub item_count: u64,
    pub gross_fee_piconero: u128,
    pub net_user_fee_piconero: u128,
    pub reserve_subsidy_piconero: u128,
    pub batch_rebate_piconero: u128,
    pub proof_batch_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeBatchClearing {
    pub fn public_record(&self) -> Value {
        json!({
            "clearing_id": self.clearing_id,
            "status": self.status,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "quote_root": self.quote_root,
            "receipt_root": self.receipt_root,
            "item_count": self.item_count,
            "gross_fee_piconero": self.gross_fee_piconero,
            "net_user_fee_piconero": self.net_user_fee_piconero,
            "reserve_subsidy_piconero": self.reserve_subsidy_piconero,
            "batch_rebate_piconero": self.batch_rebate_piconero,
            "proof_batch_root": self.proof_batch_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": LOW_FEE_CLEARING_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionRecord {
    pub redaction_id: String,
    pub scope: RedactionScope,
    pub subject_commitment: String,
    pub redacted_root: String,
    pub disclosure_policy_root: String,
    pub operator_safe: bool,
    pub produced_at_height: u64,
}

impl RedactionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "scope": self.scope,
            "subject_commitment": self.subject_commitment,
            "redacted_root": self.redacted_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "operator_safe": self.operator_safe,
            "produced_at_height": self.produced_at_height,
            "scheme": REDACTION_ROOT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub epoch: u64,
    pub active_bucket_count: u64,
    pub live_sponsor_count: u64,
    pub wallet_cap_count: u64,
    pub open_subsidy_windows: u64,
    pub total_available_piconero: u128,
    pub total_locked_sponsor_piconero: u128,
    pub total_user_savings_piconero: u128,
    pub reserve_health_bps: u64,
    pub public_message_root: String,
    pub produced_at_height: u64,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "epoch": self.epoch,
            "active_bucket_count": self.active_bucket_count,
            "live_sponsor_count": self.live_sponsor_count,
            "wallet_cap_count": self.wallet_cap_count,
            "open_subsidy_windows": self.open_subsidy_windows,
            "total_available_piconero": self.total_available_piconero,
            "total_locked_sponsor_piconero": self.total_locked_sponsor_piconero,
            "total_user_savings_piconero": self.total_user_savings_piconero,
            "reserve_health_bps": self.reserve_health_bps,
            "public_message_root": self.public_message_root,
            "produced_at_height": self.produced_at_height,
            "scheme": PUBLIC_SUMMARY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuoteRequest {
    pub wallet_commitment: String,
    pub lane: FeeLane,
    pub raw_fee_piconero: u64,
    pub volatility_index_bps: u64,
    pub da_fee_piconero: u64,
    pub proof_fee_piconero: u64,
    pub contract_call_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub reserve_buckets: BTreeMap<String, ReserveBucketRecord>,
    pub sponsor_deposits: BTreeMap<String, SponsorDepositRecord>,
    pub quotes: BTreeMap<String, VolatilityDampeningQuote>,
    pub subsidy_windows: BTreeMap<String, EmergencySubsidyWindow>,
    pub hedges: BTreeMap<String, FeeHedgeRecord>,
    pub wallet_caps: BTreeMap<String, WalletMicroFeeCap>,
    pub attestations: BTreeMap<String, PqReserveAttestation>,
    pub drawdown_receipts: BTreeMap<String, PrivateDrawdownReceipt>,
    pub clearings: BTreeMap<String, LowFeeBatchClearing>,
    pub redactions: BTreeMap<String, RedactionRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            reserve_buckets: BTreeMap::new(),
            sponsor_deposits: BTreeMap::new(),
            quotes: BTreeMap::new(),
            subsidy_windows: BTreeMap::new(),
            hedges: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            attestations: BTreeMap::new(),
            drawdown_receipts: BTreeMap::new(),
            clearings: BTreeMap::new(),
            redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn add_bucket(&mut self, record: ReserveBucketRecord) -> Result<()> {
        ensure!(
            self.reserve_buckets.len() < MAX_BUCKETS,
            "reserve bucket limit reached"
        );
        ensure!(
            record.smoothed_fee_bps <= MAX_BPS,
            "smoothed fee exceeds bps range"
        );
        ensure!(
            record.max_drawdown_bps <= MAX_BPS,
            "drawdown exceeds bps range"
        );
        self.reserve_buckets
            .insert(record.bucket_id.clone(), record);
        self.counters.buckets_created = self.counters.buckets_created.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_sponsor_deposit(&mut self, record: SponsorDepositRecord) -> Result<()> {
        ensure!(
            self.sponsor_deposits.len() < MAX_SPONSORS,
            "sponsor deposit limit reached"
        );
        ensure!(
            record.match_bps <= MAX_BPS,
            "sponsor match exceeds bps range"
        );
        ensure!(
            self.reserve_buckets.contains_key(&record.bucket_id),
            "unknown reserve bucket {}",
            record.bucket_id
        );
        self.counters.sponsor_locked_piconero = self
            .counters
            .sponsor_locked_piconero
            .saturating_add(record.locked_amount_piconero);
        self.sponsor_deposits
            .insert(record.deposit_id.clone(), record);
        self.counters.sponsor_deposits = self.counters.sponsor_deposits.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn set_wallet_cap(&mut self, cap: WalletMicroFeeCap) -> Result<()> {
        ensure!(
            self.wallet_caps.len() < MAX_MICRO_CAPS,
            "wallet cap limit reached"
        );
        ensure!(
            cap.consumed_piconero <= cap.epoch_cap_piconero,
            "wallet cap over-consumed"
        );
        self.wallet_caps.insert(cap.cap_id.clone(), cap);
        self.counters.wallet_caps_set = self.counters.wallet_caps_set.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_hedge(&mut self, hedge: FeeHedgeRecord) -> Result<()> {
        ensure!(self.hedges.len() < MAX_HEDGES, "hedge limit reached");
        ensure!(hedge.cover_bps <= MAX_BPS, "hedge cover exceeds bps range");
        self.hedges.insert(hedge.hedge_id.clone(), hedge);
        self.counters.hedges_reserved = self.counters.hedges_reserved.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_subsidy_window(&mut self, window: EmergencySubsidyWindow) -> Result<()> {
        ensure!(
            self.subsidy_windows.len() < MAX_SUBSIDY_WINDOWS,
            "subsidy window limit reached"
        );
        ensure!(window.subsidy_bps <= MAX_BPS, "subsidy exceeds bps range");
        self.subsidy_windows
            .insert(window.window_id.clone(), window);
        self.counters.subsidy_windows_opened =
            self.counters.subsidy_windows_opened.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn issue_quote(&mut self, request: QuoteRequest) -> Result<VolatilityDampeningQuote> {
        ensure!(self.quotes.len() < MAX_QUOTES, "quote limit reached");
        ensure!(
            request.volatility_index_bps <= MAX_BPS,
            "volatility index exceeds bps range"
        );
        let wallet_cap_piconero = self
            .wallet_caps
            .values()
            .find(|cap| {
                cap.wallet_commitment == request.wallet_commitment
                    && cap.lane_set.contains(&request.lane)
                    && cap.expires_at_height >= self.height
            })
            .map(|cap| cap.per_tx_cap_piconero)
            .unwrap_or(self.config.wallet_micro_fee_cap_piconero);
        let dampened = dampened_fee(
            request.raw_fee_piconero,
            request.volatility_index_bps,
            self.config.volatility_dampening_bps,
        );
        let smoothed_fee_piconero = dampened.min(wallet_cap_piconero);
        let reserve_subsidy_piconero = request
            .raw_fee_piconero
            .saturating_sub(smoothed_fee_piconero);
        let quote_id = domain_hash(
            "LOW-FEE-SMOOTHING-QUOTE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(request.lane.as_str()),
                HashPart::Str(&request.wallet_commitment),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.counters.quotes_issued as i128),
            ],
            32,
        );
        let quote = VolatilityDampeningQuote {
            quote_id: quote_id.clone(),
            wallet_cap_id: wallet_cap_id_for(&request.wallet_commitment, request.lane),
            lane: request.lane,
            status: QuoteStatus::ReserveBacked,
            request_commitment: domain_hash(
                "LOW-FEE-SMOOTHING-REQUEST",
                &[
                    HashPart::Str(&request.wallet_commitment),
                    HashPart::Str(request.lane.as_str()),
                    HashPart::Int(request.raw_fee_piconero as i128),
                    HashPart::Int(request.da_fee_piconero as i128),
                    HashPart::Int(request.proof_fee_piconero as i128),
                    HashPart::Str(&request.contract_call_commitment),
                ],
                32,
            ),
            raw_fee_piconero: request.raw_fee_piconero,
            smoothed_fee_piconero,
            wallet_cap_piconero,
            reserve_subsidy_piconero,
            volatility_index_bps: request.volatility_index_bps,
            dampening_bps: self.config.volatility_dampening_bps,
            da_hedge_id: (request.da_fee_piconero > wallet_cap_piconero / 2)
                .then(|| deterministic_id("da-hedge", &quote_id)),
            proof_hedge_id: (request.proof_fee_piconero > wallet_cap_piconero / 2)
                .then(|| deterministic_id("proof-hedge", &quote_id)),
            expires_at_height: self.height.saturating_add(self.config.quote_ttl_blocks),
        };
        self.quotes.insert(quote_id, quote.clone());
        self.counters.quotes_issued = self.counters.quotes_issued.saturating_add(1);
        self.refresh_roots();
        Ok(quote)
    }

    pub fn record_attestation(&mut self, attestation: PqReserveAttestation) -> Result<()> {
        ensure!(
            self.attestations.len() < MAX_ATTESTATIONS,
            "pq attestation limit reached"
        );
        ensure!(
            attestation.min_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below configured minimum"
        );
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_private_drawdown(&mut self, receipt: PrivateDrawdownReceipt) -> Result<()> {
        ensure!(
            self.drawdown_receipts.len() < MAX_RECEIPTS,
            "receipt limit reached"
        );
        self.counters.reserve_drawdown_piconero = self
            .counters
            .reserve_drawdown_piconero
            .saturating_add(receipt.reserve_delta_piconero.unsigned_abs());
        self.counters.user_fee_savings_piconero = self
            .counters
            .user_fee_savings_piconero
            .saturating_add(receipt.user_fee_savings_piconero as u128);
        self.drawdown_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.counters.private_receipts = self.counters.private_receipts.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_clearing(&mut self, clearing: LowFeeBatchClearing) -> Result<()> {
        ensure!(
            self.clearings.len() < MAX_CLEARINGS,
            "clearing limit reached"
        );
        self.counters.batch_items_cleared = self
            .counters
            .batch_items_cleared
            .saturating_add(clearing.item_count);
        self.clearings
            .insert(clearing.clearing_id.clone(), clearing);
        self.counters.clearing_batches = self.counters.clearing_batches.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_redaction(&mut self, redaction: RedactionRecord) -> Result<()> {
        ensure!(
            self.redactions.len() < MAX_REDACTIONS,
            "redaction limit reached"
        );
        self.redactions
            .insert(redaction.redaction_id.clone(), redaction);
        self.counters.redactions = self.counters.redactions.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, summary: OperatorSafeSummary) {
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "active_bucket_count": self.reserve_buckets.values().filter(|bucket| bucket.status.usable()).count(),
            "live_sponsor_count": self.sponsor_deposits.values().filter(|sponsor| sponsor.status.usable()).count(),
            "open_subsidy_windows": self.subsidy_windows.values().filter(|window| window.status.live()).count(),
            "operator_summary_scheme": PUBLIC_SUMMARY_SCHEME,
        })
    }

    pub fn refresh_roots(&mut self) {
        let config_root = domain_hash(
            "LOW-FEE-SMOOTHING-CONFIG",
            &[HashPart::Json(&self.config.public_record())],
            32,
        );
        let bucket_root = merkle_root(
            "LOW-FEE-SMOOTHING-BUCKETS",
            self.reserve_buckets
                .values()
                .map(ReserveBucketRecord::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let sponsor_root = merkle_root(
            "LOW-FEE-SMOOTHING-SPONSORS",
            self.sponsor_deposits
                .values()
                .map(SponsorDepositRecord::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let quote_root = merkle_root(
            "LOW-FEE-SMOOTHING-QUOTES",
            self.quotes
                .values()
                .map(VolatilityDampeningQuote::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let subsidy_root = merkle_root(
            "LOW-FEE-SMOOTHING-SUBSIDY-WINDOWS",
            self.subsidy_windows
                .values()
                .map(EmergencySubsidyWindow::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let hedge_root = merkle_root(
            "LOW-FEE-SMOOTHING-HEDGES",
            self.hedges
                .values()
                .map(FeeHedgeRecord::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let wallet_cap_root = merkle_root(
            "LOW-FEE-SMOOTHING-WALLET-CAPS",
            self.wallet_caps
                .values()
                .map(WalletMicroFeeCap::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let attestation_root = merkle_root(
            "LOW-FEE-SMOOTHING-PQ-ATTESTATIONS",
            self.attestations
                .values()
                .map(PqReserveAttestation::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let receipt_root = merkle_root(
            "LOW-FEE-SMOOTHING-DRAWDOWN-RECEIPTS",
            self.drawdown_receipts
                .values()
                .map(PrivateDrawdownReceipt::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let clearing_root = merkle_root(
            "LOW-FEE-SMOOTHING-CLEARINGS",
            self.clearings
                .values()
                .map(LowFeeBatchClearing::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let redaction_root = merkle_root(
            "LOW-FEE-SMOOTHING-REDACTIONS",
            self.redactions
                .values()
                .map(RedactionRecord::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let operator_summary_root = merkle_root(
            "LOW-FEE-SMOOTHING-OPERATOR-SUMMARIES",
            self.operator_summaries
                .values()
                .map(OperatorSafeSummary::public_record)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let counters_root = domain_hash(
            "LOW-FEE-SMOOTHING-COUNTERS",
            &[HashPart::Json(&self.counters.public_record())],
            32,
        );
        let state_root = domain_hash(
            "LOW-FEE-SMOOTHING-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&bucket_root),
                HashPart::Str(&sponsor_root),
                HashPart::Str(&quote_root),
                HashPart::Str(&subsidy_root),
                HashPart::Str(&hedge_root),
                HashPart::Str(&wallet_cap_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&clearing_root),
                HashPart::Str(&redaction_root),
                HashPart::Str(&operator_summary_root),
                HashPart::Str(&counters_root),
            ],
            32,
        );
        self.roots = Roots {
            config_root,
            bucket_root,
            sponsor_root,
            quote_root,
            subsidy_root,
            hedge_root,
            wallet_cap_root,
            attestation_root,
            receipt_root,
            clearing_root,
            redaction_root,
            operator_summary_root,
            counters_root,
            state_root,
        };
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH);
    let wallet_lane_set = BTreeSet::from([
        FeeLane::WalletTransfer,
        FeeLane::ConfidentialSwap,
        FeeLane::DefiContractCall,
        FeeLane::FastPreconfirmation,
    ]);
    let emergency_lane_set = BTreeSet::from([
        FeeLane::WalletTransfer,
        FeeLane::DefiContractCall,
        FeeLane::MoneroBridgeExit,
        FeeLane::EmergencyEscape,
    ]);

    let bucket_id = deterministic_id("bucket", "wallet-transfer-primary");
    let sponsor_set_root = merkle_root(
        "LOW-FEE-SMOOTHING-DEVNET-SPONSOR-SET",
        &[
            json!({"sponsor": "devnet-sponsor-a"}),
            json!({"sponsor": "devnet-sponsor-b"}),
        ],
    );
    let hedge_set_root = merkle_root(
        "LOW-FEE-SMOOTHING-DEVNET-HEDGE-SET",
        &[json!({"hedge": "da"}), json!({"hedge": "proof"})],
    );
    state
        .add_bucket(ReserveBucketRecord {
            bucket_id: bucket_id.clone(),
            lane: FeeLane::WalletTransfer,
            status: BucketStatus::Subsidizing,
            reserve_commitment: deterministic_id("reserve-commitment", &bucket_id),
            available_piconero: 8_500_000_000_000,
            target_piconero: 12_000_000_000_000,
            floor_piconero: 2_500_000_000_000,
            smoothed_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_drawdown_bps: DEFAULT_RESERVE_FLOOR_BPS,
            refill_priority: 9,
            sponsor_set_root,
            hedge_set_root,
            redaction_root: deterministic_id("bucket-redaction", &bucket_id),
            opened_at_height: DEVNET_HEIGHT - 720,
            updated_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet bucket");

    let sponsor_id = deterministic_id("sponsor", "foundation-low-fee");
    state
        .add_sponsor_deposit(SponsorDepositRecord {
            sponsor_id: sponsor_id.clone(),
            deposit_id: deterministic_id("deposit", &sponsor_id),
            status: SponsorStatus::Matching,
            bucket_id: bucket_id.clone(),
            sponsor_commitment: deterministic_id("sponsor-commitment", &sponsor_id),
            locked_amount_piconero: 4_250_000_000_000,
            match_bps: DEFAULT_SPONSOR_MATCH_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_attestation_id: deterministic_id("attestation", &sponsor_id),
            covenant_root: deterministic_id("sponsor-covenant", &sponsor_id),
            refund_commitment: deterministic_id("sponsor-refund", &sponsor_id),
            opened_at_height: DEVNET_HEIGHT - 600,
            expires_at_height: DEVNET_HEIGHT + 21_600,
        })
        .expect("devnet sponsor");

    let cap_id = wallet_cap_id_for("wallet-commitment-devnet-001", FeeLane::WalletTransfer);
    state
        .set_wallet_cap(WalletMicroFeeCap {
            cap_id: cap_id.clone(),
            wallet_commitment: "wallet-commitment-devnet-001".to_string(),
            lane_set: wallet_lane_set,
            per_tx_cap_piconero: DEFAULT_WALLET_MICRO_FEE_CAP_PICONERO,
            epoch_cap_piconero: 900_000,
            consumed_piconero: 120_000,
            sponsor_bucket_id: bucket_id.clone(),
            private_policy_root: deterministic_id("wallet-policy", &cap_id),
            expires_at_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS,
        })
        .expect("devnet wallet cap");

    let da_hedge_id = deterministic_id("da-hedge", "devnet-primary");
    state
        .reserve_hedge(FeeHedgeRecord {
            hedge_id: da_hedge_id.clone(),
            kind: HedgeKind::DaBlobFee,
            status: HedgeStatus::Covering,
            lane: FeeLane::BlobDa,
            notional_piconero: 2_100_000_000_000,
            cover_bps: DEFAULT_DA_HEDGE_COVER_BPS,
            premium_piconero: 55_000,
            counterparty_commitment: deterministic_id("hedge-counterparty", &da_hedge_id),
            settlement_root: deterministic_id("hedge-settlement", &da_hedge_id),
            pq_signature_root: deterministic_id("hedge-pq-signature", &da_hedge_id),
            expires_at_height: DEVNET_HEIGHT + 1_440,
        })
        .expect("devnet da hedge");

    let proof_hedge_id = deterministic_id("proof-hedge", "devnet-primary");
    state
        .reserve_hedge(FeeHedgeRecord {
            hedge_id: proof_hedge_id.clone(),
            kind: HedgeKind::RecursiveProofFee,
            status: HedgeStatus::Live,
            lane: FeeLane::RecursiveProof,
            notional_piconero: 1_800_000_000_000,
            cover_bps: DEFAULT_PROOF_HEDGE_COVER_BPS,
            premium_piconero: 48_000,
            counterparty_commitment: deterministic_id("hedge-counterparty", &proof_hedge_id),
            settlement_root: deterministic_id("hedge-settlement", &proof_hedge_id),
            pq_signature_root: deterministic_id("hedge-pq-signature", &proof_hedge_id),
            expires_at_height: DEVNET_HEIGHT + 1_440,
        })
        .expect("devnet proof hedge");

    let quote = state
        .issue_quote(QuoteRequest {
            wallet_commitment: "wallet-commitment-devnet-001".to_string(),
            lane: FeeLane::WalletTransfer,
            raw_fee_piconero: 118_000,
            volatility_index_bps: 6_900,
            da_fee_piconero: 32_000,
            proof_fee_piconero: 41_000,
            contract_call_commitment: deterministic_id("call", "devnet-wallet-transfer"),
        })
        .expect("devnet quote");

    let redaction_id = deterministic_id("redaction", &quote.quote_id);
    state
        .add_redaction(RedactionRecord {
            redaction_id: redaction_id.clone(),
            scope: RedactionScope::WalletIdentity,
            subject_commitment: quote.request_commitment.clone(),
            redacted_root: deterministic_id("redacted-wallet", &quote.quote_id),
            disclosure_policy_root: deterministic_id("redaction-policy", &quote.quote_id),
            operator_safe: true,
            produced_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet redaction");

    state
        .open_subsidy_window(EmergencySubsidyWindow {
            window_id: deterministic_id("subsidy-window", "devnet-da-spike"),
            status: SubsidyStatus::Drawing,
            lane_set: emergency_lane_set,
            trigger_root: deterministic_id("subsidy-trigger", "devnet-da-spike"),
            reserve_cap_piconero: 1_500_000_000_000,
            drawn_piconero: 280_000_000_000,
            subsidy_bps: DEFAULT_EMERGENCY_SUBSIDY_BPS,
            operator_quorum_root: deterministic_id("operator-quorum", "devnet-emergency"),
            opened_at_height: DEVNET_HEIGHT - 12,
            closes_at_height: DEVNET_HEIGHT + DEFAULT_SUBSIDY_WINDOW_BLOCKS,
        })
        .expect("devnet subsidy window");

    state
        .record_private_drawdown(PrivateDrawdownReceipt {
            receipt_id: deterministic_id("drawdown-receipt", &quote.quote_id),
            quote_id: quote.quote_id.clone(),
            bucket_id: bucket_id.clone(),
            status: ReceiptStatus::Batched,
            drawdown_commitment: deterministic_id("drawdown-commitment", &quote.quote_id),
            sealed_wallet_hint: deterministic_id("sealed-wallet-hint", &quote.quote_id),
            reserve_delta_piconero: -(quote.reserve_subsidy_piconero as i128),
            user_fee_savings_piconero: quote.reserve_subsidy_piconero,
            nullifier_hash: deterministic_id("drawdown-nullifier", &quote.quote_id),
            redaction_id,
            produced_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet drawdown receipt");

    let quote_root = merkle_root(
        "LOW-FEE-SMOOTHING-DEVNET-CLEARING-QUOTES",
        &[quote.public_record()],
    );
    let receipt_root = merkle_root(
        "LOW-FEE-SMOOTHING-DEVNET-CLEARING-RECEIPTS",
        state
            .drawdown_receipts
            .values()
            .map(PrivateDrawdownReceipt::public_record)
            .collect::<Vec<_>>()
            .as_slice(),
    );
    state
        .add_clearing(LowFeeBatchClearing {
            clearing_id: deterministic_id("clearing", "devnet-wallet-micro-batch"),
            status: ClearingStatus::Cleared,
            lane: FeeLane::WalletTransfer,
            quote_root,
            receipt_root,
            item_count: 4_096,
            gross_fee_piconero: 483_328_000,
            net_user_fee_piconero: 163_840_000,
            reserve_subsidy_piconero: 319_488_000,
            batch_rebate_piconero: 106_496_000,
            proof_batch_root: deterministic_id("proof-batch", "devnet-wallet-micro-batch"),
            opened_at_height: DEVNET_HEIGHT - 4,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_CLEARING_TTL_BLOCKS,
        })
        .expect("devnet clearing");

    let reserve_root = domain_hash(
        "LOW-FEE-SMOOTHING-DEVNET-RESERVE-ROOT",
        &[
            HashPart::Str(&state.roots.bucket_root),
            HashPart::Str(&state.roots.sponsor_root),
            HashPart::Str(&state.roots.hedge_root),
        ],
        32,
    );
    state
        .record_attestation(PqReserveAttestation {
            attestation_id: deterministic_id("attestation", "devnet-reserve"),
            attestor_id: "pq-reserve-attestor-devnet-0".to_string(),
            reserve_root,
            bucket_root: state.roots.bucket_root.clone(),
            sponsor_root: state.roots.sponsor_root.clone(),
            min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pq_signature_root: deterministic_id("pq-signature", "devnet-reserve"),
            transcript_hash: deterministic_id("attestation-transcript", "devnet-reserve"),
            produced_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet attestation");

    state.publish_operator_summary(OperatorSafeSummary {
        summary_id: deterministic_id("operator-summary", "devnet"),
        epoch: DEVNET_EPOCH,
        active_bucket_count: state
            .reserve_buckets
            .values()
            .filter(|bucket| bucket.status.usable())
            .count() as u64,
        live_sponsor_count: state
            .sponsor_deposits
            .values()
            .filter(|sponsor| sponsor.status.usable())
            .count() as u64,
        wallet_cap_count: state.wallet_caps.len() as u64,
        open_subsidy_windows: state
            .subsidy_windows
            .values()
            .filter(|window| window.status.live())
            .count() as u64,
        total_available_piconero: state
            .reserve_buckets
            .values()
            .map(|bucket| bucket.available_piconero)
            .sum(),
        total_locked_sponsor_piconero: state
            .sponsor_deposits
            .values()
            .map(|sponsor| sponsor.locked_amount_piconero)
            .sum(),
        total_user_savings_piconero: state.counters.user_fee_savings_piconero,
        reserve_health_bps: 7_083,
        public_message_root: deterministic_id("operator-message", "low-fee-reserve-healthy"),
        produced_at_height: DEVNET_HEIGHT,
    });

    state.refresh_roots();
    state
}

pub fn demo() -> Value {
    let state = devnet();
    json!({
        "runtime": "private_l2_low_fee_pq_confidential_fee_smoothing_reserve",
        "protocol_version": PROTOCOL_VERSION,
        "state_root": state.state_root(),
        "public_record": state.public_record(),
    })
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

fn dampened_fee(raw_fee_piconero: u64, volatility_index_bps: u64, dampening_bps: u64) -> u64 {
    let volatility_excess = volatility_index_bps.saturating_sub(DEFAULT_TARGET_USER_FEE_BPS);
    let dampened_excess = (volatility_excess as u128)
        .saturating_mul(dampening_bps as u128)
        .saturating_div(MAX_BPS as u128) as u64;
    let discount_bps = dampened_excess.min(MAX_BPS);
    let retained_bps = MAX_BPS.saturating_sub(discount_bps);
    ((raw_fee_piconero as u128)
        .saturating_mul(retained_bps as u128)
        .saturating_div(MAX_BPS as u128)) as u64
}

fn wallet_cap_id_for(wallet_commitment: &str, lane: FeeLane) -> String {
    domain_hash(
        "LOW-FEE-SMOOTHING-WALLET-CAP-ID",
        &[
            HashPart::Str(wallet_commitment),
            HashPart::Str(lane.as_str()),
        ],
        32,
    )
}

fn deterministic_id(domain: &str, seed: &str) -> String {
    domain_hash(
        "LOW-FEE-SMOOTHING-DETERMINISTIC-ID",
        &[HashPart::Str(domain), HashPart::Str(seed)],
        32,
    )
}
