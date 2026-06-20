use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-confidential-liquidation-backstop-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_KEEPER_POOL_SCHEME: &str =
    "ml-kem-1024+zk-private-keeper-pool-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_TICKET_SCHEME: &str =
    "roots-only-confidential-risk-backstop-ticket-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_BATCH_SCHEME: &str =
    "zk-pq-encrypted-liquidation-backstop-batch-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_SOLVENCY_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-solvency-attestation-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-backstop-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_RECEIPT_SCHEME: &str =
    "zk-pq-private-liquidation-backstop-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_REBATE_SCHEME: &str =
    "roots-only-low-fee-backstop-rebate-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "deterministic-confidential-liquidation-privacy-fence-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-liquidation-backstop-low-fee";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEVNET_HEIGHT: u64 = 917_000;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_KEEPER_POOLS:
    usize = 262_144;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_TICKETS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    262_144;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_REBATES: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_FENCES: usize =
    524_288;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_TICKETS_PER_BATCH: usize = 512;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 14;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_BACKSTOP_BONUS_BPS: u64 = 80;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_BACKSTOP_BONUS_BPS: u64 = 900;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_REBATE_BPS: u64 =
    4;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_REBATE_BPS: u64 =
    24;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_POOL_TTL_BLOCKS:
    u64 = 21_600;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS:
    u64 = 24;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 10;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 1_440;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopVenue {
    PrivateAmm,
    LendingPool,
    PerpEngine,
    StableSwap,
    VaultRouter,
    BridgeReserve,
    InsuranceFund,
    InternalNetting,
}
impl BackstopVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::LendingPool => "lending_pool",
            Self::PerpEngine => "perp_engine",
            Self::StableSwap => "stable_swap",
            Self::VaultRouter => "vault_router",
            Self::BridgeReserve => "bridge_reserve",
            Self::InsuranceFund => "insurance_fund",
            Self::InternalNetting => "internal_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopTicketKind {
    LendingShortfall,
    PerpMarginGap,
    StablecoinBadDebt,
    OptionsExerciseGap,
    BridgeReserveShock,
    OracleLagLoss,
    VaultStrategyLoss,
    InsuranceOverflow,
}
impl BackstopTicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LendingShortfall => "lending_shortfall",
            Self::PerpMarginGap => "perp_margin_gap",
            Self::StablecoinBadDebt => "stablecoin_bad_debt",
            Self::OptionsExerciseGap => "options_exercise_gap",
            Self::BridgeReserveShock => "bridge_reserve_shock",
            Self::OracleLagLoss => "oracle_lag_loss",
            Self::VaultStrategyLoss => "vault_strategy_loss",
            Self::InsuranceOverflow => "insurance_overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Proposed,
    Active,
    Saturated,
    Paused,
    Draining,
    Closed,
    Slashed,
    Expired,
}
impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
    pub fn accepts_ticket(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    SolvencyAttested,
    SponsorReserved,
    Batched,
    Settled,
    Rebated,
    Rejected,
    Expired,
}
impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SolvencyAttested => "solvency_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
    pub fn can_attest(self) -> bool {
        matches!(self, Self::Open | Self::SolvencyAttested)
    }
    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Open | Self::SolvencyAttested)
    }
    pub fn can_batch(self) -> bool {
        matches!(self, Self::SolvencyAttested | Self::SponsorReserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    Sponsored,
    Executing,
    SettlementReady,
    Settled,
    Rebated,
    Disputed,
    Expired,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Sponsored => "sponsored",
            Self::Executing => "executing",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Expired,
}
impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}
impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimed,
    Donated,
    Expired,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Donated => "donated",
            Self::Expired => "expired",
        }
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeeperPool {
    pub pool_id: String,
    pub label: String,
    pub venue: BackstopVenue,
    pub status: PoolStatus,
    pub operator_commitment: String,
    pub liquidity_commitment: String,
    pub keeper_set_root: String,
    pub max_ticket_notional_micro_units: u64,
    pub available_backstop_micro_units: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub metadata_root: String,
}
impl PublicRecord for KeeperPool {
    fn public_record(&self) -> Value {
        json!({"kind":"keeper_pool","pool_id":self.pool_id,"label":self.label,"venue":self.venue.as_str(),"status":self.status.as_str(),"operator_commitment":self.operator_commitment,"liquidity_commitment":self.liquidity_commitment,"keeper_set_root":self.keeper_set_root,"max_ticket_notional_micro_units":self.max_ticket_notional_micro_units,"available_backstop_micro_units":self.available_backstop_micro_units,"fee_bps":self.fee_bps,"privacy_set_size":self.privacy_set_size,"pq_security_bits":self.pq_security_bits,"opened_height":self.opened_height,"expiry_height":self.expiry_height,"metadata_root":self.metadata_root})
    }
}
impl KeeperPool {
    pub fn root(&self) -> String {
        payload_root(stringify!(KeeperPool), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskBackstopTicket {
    pub ticket_id: String,
    pub pool_id: String,
    pub kind: BackstopTicketKind,
    pub venue: BackstopVenue,
    pub status: TicketStatus,
    pub debtor_commitment: String,
    pub collateral_commitment: String,
    pub shortfall_commitment: String,
    pub liquidation_hint_root: String,
    pub max_user_fee_bps: u64,
    pub requested_bonus_bps: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub attestation_ids: Vec<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
}
impl PublicRecord for RiskBackstopTicket {
    fn public_record(&self) -> Value {
        json!({"kind":"risk_backstop_ticket","ticket_id":self.ticket_id,"pool_id":self.pool_id,"ticket_kind":self.kind.as_str(),"venue":self.venue.as_str(),"status":self.status.as_str(),"debtor_commitment":self.debtor_commitment,"collateral_commitment":self.collateral_commitment,"shortfall_commitment":self.shortfall_commitment,"liquidation_hint_root":self.liquidation_hint_root,"max_user_fee_bps":self.max_user_fee_bps,"requested_bonus_bps":self.requested_bonus_bps,"privacy_set_size":self.privacy_set_size,"opened_height":self.opened_height,"expiry_height":self.expiry_height,"attestation_ids":self.attestation_ids,"reservation_id":self.reservation_id,"batch_id":self.batch_id})
    }
}
impl RiskBackstopTicket {
    pub fn root(&self) -> String {
        payload_root(stringify!(RiskBackstopTicket), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedLiquidationBatch {
    pub batch_id: String,
    pub pool_id: String,
    pub status: BatchStatus,
    pub ticket_ids: Vec<String>,
    pub encrypted_payload_root: String,
    pub execution_plan_root: String,
    pub net_shortfall_commitment: String,
    pub keeper_fee_bps: u64,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub built_height: u64,
    pub expiry_height: u64,
    pub reservation_ids: Vec<String>,
    pub receipt_id: Option<String>,
}
impl PublicRecord for EncryptedLiquidationBatch {
    fn public_record(&self) -> Value {
        json!({"kind":"encrypted_liquidation_batch","batch_id":self.batch_id,"pool_id":self.pool_id,"status":self.status.as_str(),"ticket_ids":self.ticket_ids,"encrypted_payload_root":self.encrypted_payload_root,"execution_plan_root":self.execution_plan_root,"net_shortfall_commitment":self.net_shortfall_commitment,"keeper_fee_bps":self.keeper_fee_bps,"user_fee_bps":self.user_fee_bps,"privacy_set_size":self.privacy_set_size,"built_height":self.built_height,"expiry_height":self.expiry_height,"reservation_ids":self.reservation_ids,"receipt_id":self.receipt_id})
    }
}
impl EncryptedLiquidationBatch {
    pub fn root(&self) -> String {
        payload_root(stringify!(EncryptedLiquidationBatch), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolvencyAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub pool_id: String,
    pub status: AttestationStatus,
    pub attestor_committee: String,
    pub solvency_root: String,
    pub oracle_window_root: String,
    pub risk_limits_root: String,
    pub min_coverage_bps: u64,
    pub liquidity_after_commitment: String,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
}
impl PublicRecord for SolvencyAttestation {
    fn public_record(&self) -> Value {
        json!({"kind":"solvency_attestation","attestation_id":self.attestation_id,"ticket_id":self.ticket_id,"pool_id":self.pool_id,"status":self.status.as_str(),"attestor_committee":self.attestor_committee,"solvency_root":self.solvency_root,"oracle_window_root":self.oracle_window_root,"risk_limits_root":self.risk_limits_root,"min_coverage_bps":self.min_coverage_bps,"liquidity_after_commitment":self.liquidity_after_commitment,"pq_security_bits":self.pq_security_bits,"submitted_height":self.submitted_height,"expires_height":self.expires_height})
    }
}
impl SolvencyAttestation {
    pub fn root(&self) -> String {
        payload_root(stringify!(SolvencyAttestation), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub ticket_id: String,
    pub batch_id: Option<String>,
    pub sponsor_commitment: String,
    pub status: ReservationStatus,
    pub fee_budget_micro_units: u64,
    pub covered_fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
}
impl PublicRecord for SponsorReservation {
    fn public_record(&self) -> Value {
        json!({"kind":"sponsor_reservation","reservation_id":self.reservation_id,"ticket_id":self.ticket_id,"batch_id":self.batch_id,"sponsor_commitment":self.sponsor_commitment,"status":self.status.as_str(),"fee_budget_micro_units":self.fee_budget_micro_units,"covered_fee_bps":self.covered_fee_bps,"rebate_bps":self.rebate_bps,"privacy_set_size":self.privacy_set_size,"reserved_height":self.reserved_height,"expires_height":self.expires_height,"consumed_height":self.consumed_height})
    }
}
impl SponsorReservation {
    pub fn root(&self) -> String {
        payload_root(stringify!(SponsorReservation), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub settlement_root: String,
    pub filled_ticket_root: String,
    pub spent_reservation_root: String,
    pub keeper_payout_commitment: String,
    pub protocol_fee_commitment: String,
    pub settled_height: u64,
    pub finalized_height: Option<u64>,
}
impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        json!({"kind":"settlement_receipt","receipt_id":self.receipt_id,"batch_id":self.batch_id,"status":self.status.as_str(),"settlement_root":self.settlement_root,"filled_ticket_root":self.filled_ticket_root,"spent_reservation_root":self.spent_reservation_root,"keeper_payout_commitment":self.keeper_payout_commitment,"protocol_fee_commitment":self.protocol_fee_commitment,"settled_height":self.settled_height,"finalized_height":self.finalized_height})
    }
}
impl SettlementReceipt {
    pub fn root(&self) -> String {
        payload_root(stringify!(SettlementReceipt), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeeperRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub reservation_id: String,
    pub status: RebateStatus,
    pub claim_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub queued_height: u64,
    pub expires_height: u64,
    pub claimed_height: Option<u64>,
}
impl PublicRecord for KeeperRebate {
    fn public_record(&self) -> Value {
        json!({"kind":"keeper_rebate","rebate_id":self.rebate_id,"receipt_id":self.receipt_id,"reservation_id":self.reservation_id,"status":self.status.as_str(),"claim_commitment":self.claim_commitment,"rebate_commitment":self.rebate_commitment,"rebate_bps":self.rebate_bps,"privacy_set_size":self.privacy_set_size,"queued_height":self.queued_height,"expires_height":self.expires_height,"claimed_height":self.claimed_height})
    }
}
impl KeeperRebate {
    pub fn root(&self) -> String {
        payload_root(stringify!(KeeperRebate), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub subject_id: String,
    pub scope: String,
    pub nullifier_root: String,
    pub viewer_set_root: String,
    pub disclosure_policy_root: String,
    pub min_delay_blocks: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}
impl PublicRecord for PrivacyFence {
    fn public_record(&self) -> Value {
        json!({"kind":"privacy_fence","fence_id":self.fence_id,"subject_id":self.subject_id,"scope":self.scope,"nullifier_root":self.nullifier_root,"viewer_set_root":self.viewer_set_root,"disclosure_policy_root":self.disclosure_policy_root,"min_delay_blocks":self.min_delay_blocks,"privacy_set_size":self.privacy_set_size,"opened_height":self.opened_height,"expires_height":self.expires_height})
    }
}
impl PrivacyFence {
    pub fn root(&self) -> String {
        payload_root(stringify!(PrivacyFence), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub monero_network: String,
    pub low_fee_lane: String,
    pub keeper_pool_scheme: String,
    pub ticket_scheme: String,
    pub batch_scheme: String,
    pub solvency_scheme: String,
    pub sponsor_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub privacy_fence_scheme: String,
    pub max_keeper_pools: usize,
    pub max_tickets: usize,
    pub max_batches: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_tickets_per_batch: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_keeper_fee_bps: u64,
    pub min_backstop_bonus_bps: u64,
    pub max_backstop_bonus_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub pool_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
}
impl Config {
    pub fn devnet() -> Self {
        Self { chain_id: CHAIN_ID.to_string(), protocol_version: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_PROTOCOL_VERSION.to_string(), schema_version: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_SCHEMA_VERSION, hash_suite: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_HASH_SUITE.to_string(), monero_network: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(), low_fee_lane: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), keeper_pool_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_KEEPER_POOL_SCHEME.to_string(), ticket_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_TICKET_SCHEME.to_string(), batch_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_BATCH_SCHEME.to_string(), solvency_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_SOLVENCY_SCHEME.to_string(), sponsor_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_SPONSOR_SCHEME.to_string(), receipt_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_RECEIPT_SCHEME.to_string(), rebate_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_REBATE_SCHEME.to_string(), privacy_fence_scheme: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_PRIVACY_FENCE_SCHEME.to_string(), max_keeper_pools: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_KEEPER_POOLS, max_tickets: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_TICKETS, max_batches: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_BATCHES, max_attestations: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_ATTESTATIONS, max_reservations: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_RESERVATIONS, max_receipts: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_RECEIPTS, max_rebates: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_REBATES, max_fences: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_FENCES, max_tickets_per_batch: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_TICKETS_PER_BATCH, min_privacy_set_size: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE, batch_privacy_set_size: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, min_pq_security_bits: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS, max_user_fee_bps: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS, max_keeper_fee_bps: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS, min_backstop_bonus_bps: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_BACKSTOP_BONUS_BPS, max_backstop_bonus_bps: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_BACKSTOP_BONUS_BPS, min_rebate_bps: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MIN_REBATE_BPS, max_rebate_bps: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_MAX_REBATE_BPS, pool_ttl_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_POOL_TTL_BLOCKS, ticket_ttl_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS, batch_ttl_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS, reservation_ttl_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS, settlement_ttl_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS, rebate_epoch_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS }
    }
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_bps(self.max_user_fee_bps, "max user fee bps")?;
        ensure_bps(self.max_keeper_fee_bps, "max keeper fee bps")?;
        ensure_bps(self.min_backstop_bonus_bps, "min backstop bonus bps")?;
        ensure_bps(self.max_backstop_bonus_bps, "max backstop bonus bps")?;
        ensure_bps(self.min_rebate_bps, "min rebate bps")?;
        ensure_bps(self.max_rebate_bps, "max rebate bps")?;
        if self.min_backstop_bonus_bps > self.max_backstop_bonus_bps {
            return Err("min backstop bonus exceeds max backstop bonus".to_string());
        }
        if self.min_rebate_bps > self.max_rebate_bps {
            return Err("min rebate exceeds max rebate".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set cannot be below minimum privacy set".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": self.chain_id, "protocol_version": self.protocol_version, "schema_version": self.schema_version, "hash_suite": self.hash_suite, "monero_network": self.monero_network, "low_fee_lane": self.low_fee_lane, "keeper_pool_scheme": self.keeper_pool_scheme, "ticket_scheme": self.ticket_scheme, "batch_scheme": self.batch_scheme, "solvency_scheme": self.solvency_scheme, "sponsor_scheme": self.sponsor_scheme, "receipt_scheme": self.receipt_scheme, "rebate_scheme": self.rebate_scheme, "privacy_fence_scheme": self.privacy_fence_scheme, "max_keeper_pools": self.max_keeper_pools, "max_tickets": self.max_tickets, "max_batches": self.max_batches, "max_attestations": self.max_attestations, "max_reservations": self.max_reservations, "max_receipts": self.max_receipts, "max_rebates": self.max_rebates, "max_fences": self.max_fences, "max_tickets_per_batch": self.max_tickets_per_batch, "min_privacy_set_size": self.min_privacy_set_size, "batch_privacy_set_size": self.batch_privacy_set_size, "min_pq_security_bits": self.min_pq_security_bits, "max_user_fee_bps": self.max_user_fee_bps, "max_keeper_fee_bps": self.max_keeper_fee_bps, "min_backstop_bonus_bps": self.min_backstop_bonus_bps, "max_backstop_bonus_bps": self.max_backstop_bonus_bps, "min_rebate_bps": self.min_rebate_bps, "max_rebate_bps": self.max_rebate_bps, "pool_ttl_blocks": self.pool_ttl_blocks, "ticket_ttl_blocks": self.ticket_ttl_blocks, "batch_ttl_blocks": self.batch_ttl_blocks, "reservation_ttl_blocks": self.reservation_ttl_blocks, "settlement_ttl_blocks": self.settlement_ttl_blocks, "rebate_epoch_blocks": self.rebate_epoch_blocks })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub keeper_pool_root: String,
    pub ticket_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub active_pool_root: String,
    pub open_ticket_root: String,
    pub pending_batch_root: String,
    pub settlement_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "keeper_pool_root": self.keeper_pool_root, "ticket_root": self.ticket_root, "batch_root": self.batch_root, "attestation_root": self.attestation_root, "reservation_root": self.reservation_root, "receipt_root": self.receipt_root, "rebate_root": self.rebate_root, "privacy_fence_root": self.privacy_fence_root, "active_pool_root": self.active_pool_root, "open_ticket_root": self.open_ticket_root, "pending_batch_root": self.pending_batch_root, "settlement_root": self.settlement_root })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub keeper_pools: BTreeMap<String, KeeperPool>,
    pub tickets: BTreeMap<String, RiskBackstopTicket>,
    pub batches: BTreeMap<String, EncryptedLiquidationBatch>,
    pub attestations: BTreeMap<String, SolvencyAttestation>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, KeeperRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub active_pool_ids: BTreeSet<String>,
    pub open_ticket_ids: BTreeSet<String>,
    pub pending_batch_ids: BTreeSet<String>,
    pub settlement_receipt_ids: BTreeSet<String>,
}
impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            keeper_pools: BTreeMap::new(),
            tickets: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            active_pool_ids: BTreeSet::new(),
            open_ticket_ids: BTreeSet::new(),
            pending_batch_ids: BTreeSet::new(),
            settlement_receipt_ids: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_DEVNET_HEIGHT,
        )?;
        let pool_a = state.register_keeper_pool(
            "devnet-xmr-lending-backstop",
            BackstopVenue::LendingPool,
            "keeper-committee-devnet-alpha",
            2_500_000_000,
            12,
            state.config.batch_privacy_set_size,
            json!({"strategy":"rapid_private_repay","asset":"pxmr","tier":"senior"}),
        )?;
        let pool_b = state.register_keeper_pool(
            "devnet-perp-margin-backstop",
            BackstopVenue::PerpEngine,
            "keeper-committee-devnet-beta",
            1_800_000_000,
            14,
            state.config.batch_privacy_set_size,
            json!({"strategy":"flash_close_then_net","asset":"pxmr-usd","tier":"junior"}),
        )?;
        let ticket_a = state.open_ticket(
            &pool_a,
            BackstopTicketKind::LendingShortfall,
            BackstopVenue::LendingPool,
            "debtor-note-devnet-alpha",
            "collateral-note-devnet-alpha",
            "shortfall-note-devnet-alpha",
            10,
            220,
            state.config.batch_privacy_set_size,
            json!({"oracle_window":"devnet-12-blocks","health_factor":"below-one"}),
        )?;
        let ticket_b = state.open_ticket(
            &pool_b,
            BackstopTicketKind::PerpMarginGap,
            BackstopVenue::PerpEngine,
            "debtor-note-devnet-beta",
            "collateral-note-devnet-beta",
            "shortfall-note-devnet-beta",
            11,
            180,
            state.config.batch_privacy_set_size,
            json!({"oracle_window":"devnet-8-blocks","funding":"netted"}),
        )?;
        state.submit_solvency_attestation(
            &ticket_a,
            "devnet-risk-committee-alpha",
            10_000,
            "liquidity-after-alpha",
            json!({"coverage":"overcollateralized","paths":3}),
            json!({"oracle":"xmr-usd-devnet","lag_blocks":2}),
            json!({"max_pool_share_bps":2_500}),
        )?;
        state.submit_solvency_attestation(
            &ticket_b,
            "devnet-risk-committee-beta",
            10_000,
            "liquidity-after-beta",
            json!({"coverage":"sufficient","paths":2}),
            json!({"oracle":"perp-mark-devnet","lag_blocks":1}),
            json!({"max_pool_share_bps":2_000}),
        )?;
        let reservation_a = state.reserve_sponsor_budget(
            &ticket_a,
            "devnet-sponsor-vault-alpha",
            4_800_000,
            9_400,
            12,
            state.config.batch_privacy_set_size,
        )?;
        let reservation_b = state.reserve_sponsor_budget(
            &ticket_b,
            "devnet-sponsor-vault-beta",
            3_900_000,
            9_200,
            10,
            state.config.batch_privacy_set_size,
        )?;
        let batch = state.build_encrypted_batch(
            &pool_a,
            vec![ticket_a.clone()],
            "encrypted-liquidation-payload-devnet-alpha",
            "execution-plan-devnet-alpha",
            "net-shortfall-devnet-alpha",
            13,
            9,
            state.config.batch_privacy_set_size,
        )?;
        state.attach_reservation_to_batch(&reservation_a, &batch)?;
        let receipt = state.publish_settlement_receipt(
            &batch,
            "settlement-root-devnet-alpha",
            "filled-ticket-root-devnet-alpha",
            "spent-reservation-root-devnet-alpha",
            "keeper-payout-devnet-alpha",
            "protocol-fee-devnet-alpha",
        )?;
        state.queue_rebate(
            &receipt,
            &reservation_a,
            "claim-devnet-alpha",
            "rebate-devnet-alpha",
            12,
            state.config.batch_privacy_set_size,
        )?;
        state.open_privacy_fence(
            &ticket_b,
            "ticket-prebatch-view",
            "nullifier-root-devnet-beta",
            "viewer-root-devnet-beta",
            "policy-root-devnet-beta",
            4,
            state.config.batch_privacy_set_size,
        )?;
        state.release_reservation(&reservation_b)?;
        Ok(state)
    }
    pub fn roots(&self) -> Roots {
        Roots {
            keeper_pool_root: map_root("keeper-pools", &self.keeper_pools),
            ticket_root: map_root("tickets", &self.tickets),
            batch_root: map_root("batches", &self.batches),
            attestation_root: map_root("attestations", &self.attestations),
            reservation_root: map_root("reservations", &self.reservations),
            receipt_root: map_root("receipts", &self.receipts),
            rebate_root: map_root("rebates", &self.rebates),
            privacy_fence_root: map_root("privacy-fences", &self.privacy_fences),
            active_pool_root: set_root("active-pools", &self.active_pool_ids),
            open_ticket_root: set_root("open-tickets", &self.open_ticket_ids),
            pending_batch_root: set_root("pending-batches", &self.pending_batch_ids),
            settlement_root: set_root("settlement-receipts", &self.settlement_receipt_ids),
        }
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({ "kind": "private_l2_low_fee_confidential_liquidation_backstop_runtime_state", "config": self.config.public_record(), "current_height": self.current_height, "roots": self.roots().public_record(), "counts": { "keeper_pools": self.keeper_pools.len(), "tickets": self.tickets.len(), "batches": self.batches.len(), "attestations": self.attestations.len(), "reservations": self.reservations.len(), "receipts": self.receipts.len(), "rebates": self.rebates.len(), "privacy_fences": self.privacy_fences.len() }, "indexes": { "active_pool_ids": self.active_pool_ids.iter().cloned().collect::<Vec<_>>(), "open_ticket_ids": self.open_ticket_ids.iter().cloned().collect::<Vec<_>>(), "pending_batch_ids": self.pending_batch_ids.iter().cloned().collect::<Vec<_>>(), "settlement_receipt_ids": self.settlement_receipt_ids.iter().cloned().collect::<Vec<_>>() } })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn register_keeper_pool(
        &mut self,
        label: &str,
        venue: BackstopVenue,
        operator_label: &str,
        available_backstop_micro_units: u64,
        fee_bps: u64,
        privacy_set_size: u64,
        metadata: Value,
    ) -> Result<String> {
        self.ensure_capacity(
            self.keeper_pools.len(),
            self.config.max_keeper_pools,
            "keeper pools",
        )?;
        ensure_non_empty(label, "pool label")?;
        ensure_non_empty(operator_label, "operator label")?;
        ensure_bps(fee_bps, "keeper fee bps")?;
        if fee_bps > self.config.max_keeper_fee_bps {
            return Err("keeper fee exceeds configured low-fee ceiling".to_string());
        }
        self.ensure_privacy_set(privacy_set_size, "pool privacy set")?;
        let pool_id = deterministic_id(
            "keeper-pool",
            self.keeper_pools.len() as u64,
            &[label, venue.as_str(), operator_label],
        );
        let pool = KeeperPool {
            pool_id: pool_id.clone(),
            label: label.to_string(),
            venue,
            status: PoolStatus::Active,
            operator_commitment: commitment_root("pool-operator", operator_label),
            liquidity_commitment: commitment_root(
                "pool-liquidity",
                &available_backstop_micro_units.to_string(),
            ),
            keeper_set_root: payload_root(
                "KEEPER-SET",
                &json!({"label": label, "operator": operator_label}),
            ),
            max_ticket_notional_micro_units: available_backstop_micro_units / 4,
            available_backstop_micro_units,
            fee_bps,
            privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            opened_height: self.current_height,
            expiry_height: self.current_height + self.config.pool_ttl_blocks,
            metadata_root: roots_only_payload("keeper_pool_metadata", &pool_id, &metadata),
        };
        self.active_pool_ids.insert(pool_id.clone());
        self.keeper_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }
    pub fn open_ticket(
        &mut self,
        pool_id: &str,
        kind: BackstopTicketKind,
        venue: BackstopVenue,
        debtor_label: &str,
        collateral_label: &str,
        shortfall_label: &str,
        max_user_fee_bps: u64,
        requested_bonus_bps: u64,
        privacy_set_size: u64,
        liquidation_hint: Value,
    ) -> Result<String> {
        self.ensure_capacity(self.tickets.len(), self.config.max_tickets, "tickets")?;
        let pool = self
            .keeper_pools
            .get(pool_id)
            .ok_or_else(|| format!("unknown keeper pool {pool_id}"))?;
        if !pool.status.accepts_ticket() {
            return Err("keeper pool is not accepting tickets".to_string());
        }
        ensure_bps(max_user_fee_bps, "max user fee bps")?;
        ensure_bps(requested_bonus_bps, "requested bonus bps")?;
        if max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("user fee exceeds configured low-fee ceiling".to_string());
        }
        if requested_bonus_bps < self.config.min_backstop_bonus_bps
            || requested_bonus_bps > self.config.max_backstop_bonus_bps
        {
            return Err("requested backstop bonus is outside configured bounds".to_string());
        }
        self.ensure_privacy_set(privacy_set_size, "ticket privacy set")?;
        let ticket_id = deterministic_id(
            "risk-ticket",
            self.tickets.len() as u64,
            &[pool_id, kind.as_str(), debtor_label, shortfall_label],
        );
        let ticket = RiskBackstopTicket {
            ticket_id: ticket_id.clone(),
            pool_id: pool_id.to_string(),
            kind,
            venue,
            status: TicketStatus::Open,
            debtor_commitment: commitment_root("ticket-debtor", debtor_label),
            collateral_commitment: commitment_root("ticket-collateral", collateral_label),
            shortfall_commitment: commitment_root("ticket-shortfall", shortfall_label),
            liquidation_hint_root: roots_only_payload(
                "liquidation_hint",
                &ticket_id,
                &liquidation_hint,
            ),
            max_user_fee_bps,
            requested_bonus_bps,
            privacy_set_size,
            opened_height: self.current_height,
            expiry_height: self.current_height + self.config.ticket_ttl_blocks,
            attestation_ids: Vec::new(),
            reservation_id: None,
            batch_id: None,
        };
        self.open_ticket_ids.insert(ticket_id.clone());
        self.tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }
    pub fn submit_solvency_attestation(
        &mut self,
        ticket_id: &str,
        committee: &str,
        min_coverage_bps: u64,
        liquidity_after_label: &str,
        solvency_payload: Value,
        oracle_payload: Value,
        risk_limits_payload: Value,
    ) -> Result<String> {
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        ensure_non_empty(committee, "attestor committee")?;
        ensure_bps(min_coverage_bps, "min coverage bps")?;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        if !ticket.status.can_attest() {
            return Err("ticket cannot accept solvency attestations".to_string());
        }
        let attestation_id = deterministic_id(
            "solvency-attestation",
            self.attestations.len() as u64,
            &[ticket_id, committee, liquidity_after_label],
        );
        let attestation = SolvencyAttestation {
            attestation_id: attestation_id.clone(),
            ticket_id: ticket_id.to_string(),
            pool_id: ticket.pool_id.clone(),
            status: AttestationStatus::Accepted,
            attestor_committee: committee.to_string(),
            solvency_root: roots_only_payload(
                "solvency_payload",
                &attestation_id,
                &solvency_payload,
            ),
            oracle_window_root: roots_only_payload(
                "oracle_window",
                &attestation_id,
                &oracle_payload,
            ),
            risk_limits_root: roots_only_payload(
                "risk_limits",
                &attestation_id,
                &risk_limits_payload,
            ),
            min_coverage_bps,
            liquidity_after_commitment: commitment_root("liquidity-after", liquidity_after_label),
            pq_security_bits: self.config.min_pq_security_bits,
            submitted_height: self.current_height,
            expires_height: self.current_height + self.config.settlement_ttl_blocks,
        };
        ticket.attestation_ids.push(attestation_id.clone());
        ticket.status = TicketStatus::SolvencyAttested;
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }
    pub fn reserve_sponsor_budget(
        &mut self,
        ticket_id: &str,
        sponsor_label: &str,
        fee_budget_micro_units: u64,
        covered_fee_bps: u64,
        rebate_bps: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.reservations.len(),
            self.config.max_reservations,
            "reservations",
        )?;
        ensure_non_empty(sponsor_label, "sponsor label")?;
        ensure_bps(covered_fee_bps, "covered fee bps")?;
        ensure_bps(rebate_bps, "rebate bps")?;
        if rebate_bps < self.config.min_rebate_bps || rebate_bps > self.config.max_rebate_bps {
            return Err("rebate bps outside configured bounds".to_string());
        }
        self.ensure_privacy_set(privacy_set_size, "reservation privacy set")?;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        if !ticket.status.can_reserve() {
            return Err("ticket cannot accept sponsor reservation".to_string());
        }
        let reservation_id = deterministic_id(
            "sponsor-reservation",
            self.reservations.len() as u64,
            &[ticket_id, sponsor_label],
        );
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            ticket_id: ticket_id.to_string(),
            batch_id: None,
            sponsor_commitment: commitment_root("sponsor", sponsor_label),
            status: ReservationStatus::Reserved,
            fee_budget_micro_units,
            covered_fee_bps,
            rebate_bps,
            privacy_set_size,
            reserved_height: self.current_height,
            expires_height: self.current_height + self.config.reservation_ttl_blocks,
            consumed_height: None,
        };
        ticket.reservation_id = Some(reservation_id.clone());
        ticket.status = TicketStatus::SponsorReserved;
        self.reservations
            .insert(reservation_id.clone(), reservation);
        Ok(reservation_id)
    }
    pub fn build_encrypted_batch(
        &mut self,
        pool_id: &str,
        ticket_ids: Vec<String>,
        encrypted_payload_label: &str,
        execution_plan_label: &str,
        net_shortfall_label: &str,
        keeper_fee_bps: u64,
        user_fee_bps: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        if ticket_ids.is_empty() {
            return Err("batch requires at least one ticket".to_string());
        }
        if ticket_ids.len() > self.config.max_tickets_per_batch {
            return Err("batch exceeds max tickets per batch".to_string());
        }
        ensure_bps(keeper_fee_bps, "keeper fee bps")?;
        ensure_bps(user_fee_bps, "user fee bps")?;
        if keeper_fee_bps > self.config.max_keeper_fee_bps
            || user_fee_bps > self.config.max_user_fee_bps
        {
            return Err("batch fee exceeds configured low-fee ceiling".to_string());
        }
        self.ensure_privacy_set(privacy_set_size, "batch privacy set")?;
        let mut reservation_ids = Vec::new();
        for ticket_id in &ticket_ids {
            let ticket = self
                .tickets
                .get(ticket_id)
                .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
            if ticket.pool_id != pool_id {
                return Err("all tickets in batch must share the keeper pool".to_string());
            }
            if !ticket.status.can_batch() {
                return Err(format!("ticket {ticket_id} is not batchable"));
            }
            if let Some(reservation_id) = &ticket.reservation_id {
                reservation_ids.push(reservation_id.clone());
            }
        }
        let batch_id = deterministic_id(
            "encrypted-batch",
            self.batches.len() as u64,
            &[pool_id, encrypted_payload_label, execution_plan_label],
        );
        for ticket_id in &ticket_ids {
            let ticket = self
                .tickets
                .get_mut(ticket_id)
                .expect("ticket existence checked");
            ticket.status = TicketStatus::Batched;
            ticket.batch_id = Some(batch_id.clone());
            self.open_ticket_ids.remove(ticket_id);
        }
        let batch = EncryptedLiquidationBatch {
            batch_id: batch_id.clone(),
            pool_id: pool_id.to_string(),
            status: BatchStatus::SettlementReady,
            ticket_ids,
            encrypted_payload_root: commitment_root("encrypted-payload", encrypted_payload_label),
            execution_plan_root: commitment_root("execution-plan", execution_plan_label),
            net_shortfall_commitment: commitment_root("net-shortfall", net_shortfall_label),
            keeper_fee_bps,
            user_fee_bps,
            privacy_set_size,
            built_height: self.current_height,
            expiry_height: self.current_height + self.config.batch_ttl_blocks,
            reservation_ids,
            receipt_id: None,
        };
        self.pending_batch_ids.insert(batch_id.clone());
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }
    pub fn attach_reservation_to_batch(
        &mut self,
        reservation_id: &str,
        batch_id: &str,
    ) -> Result<()> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| format!("unknown reservation {reservation_id}"))?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch {batch_id}"))?;
        if reservation.status != ReservationStatus::Reserved {
            return Err("reservation is not reserved".to_string());
        }
        if !batch.reservation_ids.iter().any(|id| id == reservation_id) {
            batch.reservation_ids.push(reservation_id.to_string());
        }
        reservation.batch_id = Some(batch_id.to_string());
        Ok(())
    }
    pub fn publish_settlement_receipt(
        &mut self,
        batch_id: &str,
        settlement_label: &str,
        filled_ticket_label: &str,
        spent_reservation_label: &str,
        keeper_payout_label: &str,
        protocol_fee_label: &str,
    ) -> Result<String> {
        self.ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch {batch_id}"))?;
        if !batch.status.can_settle() {
            return Err("batch is not settlement ready".to_string());
        }
        let receipt_id = deterministic_id(
            "settlement-receipt",
            self.receipts.len() as u64,
            &[batch_id, settlement_label],
        );
        batch.status = BatchStatus::Settled;
        batch.receipt_id = Some(receipt_id.clone());
        self.pending_batch_ids.remove(batch_id);
        self.settlement_receipt_ids.insert(receipt_id.clone());
        for ticket_id in &batch.ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Settled;
            }
        }
        for reservation_id in &batch.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
                reservation.consumed_height = Some(self.current_height);
            }
        }
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: batch_id.to_string(),
            status: ReceiptStatus::Published,
            settlement_root: commitment_root("settlement", settlement_label),
            filled_ticket_root: commitment_root("filled-tickets", filled_ticket_label),
            spent_reservation_root: commitment_root("spent-reservations", spent_reservation_label),
            keeper_payout_commitment: commitment_root("keeper-payout", keeper_payout_label),
            protocol_fee_commitment: commitment_root("protocol-fee", protocol_fee_label),
            settled_height: self.current_height,
            finalized_height: None,
        };
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }
    pub fn finalize_receipt(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        receipt.status = ReceiptStatus::Finalized;
        receipt.finalized_height = Some(self.current_height);
        Ok(())
    }
    pub fn queue_rebate(
        &mut self,
        receipt_id: &str,
        reservation_id: &str,
        claim_label: &str,
        rebate_label: &str,
        rebate_bps: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        if !self.receipts.contains_key(receipt_id) {
            return Err(format!("unknown receipt {receipt_id}"));
        }
        if !self.reservations.contains_key(reservation_id) {
            return Err(format!("unknown reservation {reservation_id}"));
        }
        ensure_bps(rebate_bps, "rebate bps")?;
        self.ensure_privacy_set(privacy_set_size, "rebate privacy set")?;
        let rebate_id = deterministic_id(
            "keeper-rebate",
            self.rebates.len() as u64,
            &[receipt_id, reservation_id, claim_label],
        );
        let rebate = KeeperRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            reservation_id: reservation_id.to_string(),
            status: RebateStatus::Queued,
            claim_commitment: commitment_root("rebate-claim", claim_label),
            rebate_commitment: commitment_root("rebate", rebate_label),
            rebate_bps,
            privacy_set_size,
            queued_height: self.current_height,
            expires_height: self.current_height + self.config.rebate_epoch_blocks,
            claimed_height: None,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }
    pub fn claim_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate {rebate_id}"))?;
        if rebate.status != RebateStatus::Queued {
            return Err("rebate is not queued".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        rebate.claimed_height = Some(self.current_height);
        Ok(())
    }
    pub fn open_privacy_fence(
        &mut self,
        subject_id: &str,
        scope: &str,
        nullifier_label: &str,
        viewer_label: &str,
        disclosure_policy_label: &str,
        min_delay_blocks: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.privacy_fences.len(),
            self.config.max_fences,
            "privacy fences",
        )?;
        ensure_non_empty(subject_id, "privacy fence subject")?;
        ensure_non_empty(scope, "privacy fence scope")?;
        self.ensure_privacy_set(privacy_set_size, "privacy fence set")?;
        let fence_id = deterministic_id(
            "privacy-fence",
            self.privacy_fences.len() as u64,
            &[subject_id, scope, nullifier_label],
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            subject_id: subject_id.to_string(),
            scope: scope.to_string(),
            nullifier_root: commitment_root("fence-nullifier", nullifier_label),
            viewer_set_root: commitment_root("fence-viewers", viewer_label),
            disclosure_policy_root: commitment_root("fence-policy", disclosure_policy_label),
            min_delay_blocks,
            privacy_set_size,
            opened_height: self.current_height,
            expires_height: self.current_height + self.config.ticket_ttl_blocks,
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        Ok(fence_id)
    }
    pub fn release_reservation(&mut self, reservation_id: &str) -> Result<()> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| format!("unknown reservation {reservation_id}"))?;
        if reservation.status != ReservationStatus::Reserved {
            return Err("only reserved sponsor budget can be released".to_string());
        }
        reservation.status = ReservationStatus::Released;
        Ok(())
    }
    pub fn pause_pool(&mut self, pool_id: &str) -> Result<()> {
        let pool = self
            .keeper_pools
            .get_mut(pool_id)
            .ok_or_else(|| format!("unknown pool {pool_id}"))?;
        pool.status = PoolStatus::Paused;
        self.active_pool_ids.remove(pool_id);
        Ok(())
    }
    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.current_height {
            return Err("cannot move runtime height backwards".to_string());
        }
        self.current_height = new_height;
        Ok(())
    }
    pub fn expire_height(&mut self, height: u64) {
        self.current_height = self.current_height.max(height);
        for (pool_id, pool) in &mut self.keeper_pools {
            if pool.expiry_height <= height
                && matches!(
                    pool.status,
                    PoolStatus::Active | PoolStatus::Saturated | PoolStatus::Paused
                )
            {
                pool.status = PoolStatus::Expired;
                self.active_pool_ids.remove(pool_id);
            }
        }
        for (ticket_id, ticket) in &mut self.tickets {
            if ticket.expiry_height <= height
                && !matches!(
                    ticket.status,
                    TicketStatus::Settled | TicketStatus::Rebated | TicketStatus::Rejected
                )
            {
                ticket.status = TicketStatus::Expired;
                self.open_ticket_ids.remove(ticket_id);
            }
        }
        for (batch_id, batch) in &mut self.batches {
            if batch.expiry_height <= height
                && !matches!(
                    batch.status,
                    BatchStatus::Settled | BatchStatus::Rebated | BatchStatus::Disputed
                )
            {
                batch.status = BatchStatus::Expired;
                self.pending_batch_ids.remove(batch_id);
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.expires_height <= height
                && reservation.status == ReservationStatus::Reserved
            {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.expires_height <= height && rebate.status == RebateStatus::Queued {
                rebate.status = RebateStatus::Expired;
            }
        }
    }
    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exhausted"))
        } else {
            Ok(())
        }
    }
    fn ensure_privacy_set(&self, privacy_set_size: u64, label: &str) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            Err(format!("{label} below configured minimum privacy set"))
        } else {
            Ok(())
        }
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-LIQUIDATION-BACKSTOP-PAYLOAD",
        &[
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-LIQUIDATION-BACKSTOP-STATE",
        &[
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn deterministic_id(label: &str, nonce: u64, parts: &[&str]) -> String {
    let parts_value = Value::Array(
        parts
            .iter()
            .map(|part| Value::String((*part).to_string()))
            .collect(),
    );
    format!(
        "plflb_{}",
        domain_hash(
            "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-LIQUIDATION-BACKSTOP-ID",
            &[
                HashPart::Str(label),
                HashPart::U64(nonce),
                HashPart::Json(&parts_value)
            ],
            16
        )
    )
}
pub fn commitment_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-LIQUIDATION-BACKSTOP-COMMITMENT",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}
pub fn roots_only_payload(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    payload_root(
        "ROOTS-ONLY-PAYLOAD",
        &json!({"record_kind": record_kind, "subject_id": subject_id, "payload_root": payload_root(record_kind, payload)}),
    )
}
fn map_root<T: PublicRecord>(label: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .values()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-low-fee-liquidation-backstop-{label}"),
        &leaves,
    )
}
fn set_root(label: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-low-fee-liquidation-backstop-{label}"),
        &leaves,
    )
}
fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > PRIVATE_L2_LOW_FEE_CONFIDENTIAL_LIQUIDATION_BACKSTOP_RUNTIME_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

pub fn privacy_fence_policy_hint_001_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-001",
        &json!({
            "hint": 1,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_002_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-002",
        &json!({
            "hint": 2,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_003_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-003",
        &json!({
            "hint": 3,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_004_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-004",
        &json!({
            "hint": 4,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_005_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-005",
        &json!({
            "hint": 5,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_006_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-006",
        &json!({
            "hint": 6,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_007_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-007",
        &json!({
            "hint": 7,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_008_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-008",
        &json!({
            "hint": 8,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_009_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-009",
        &json!({
            "hint": 9,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_010_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-010",
        &json!({
            "hint": 10,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_011_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-011",
        &json!({
            "hint": 11,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_012_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-012",
        &json!({
            "hint": 12,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_013_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-013",
        &json!({
            "hint": 13,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_014_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-014",
        &json!({
            "hint": 14,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_015_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-015",
        &json!({
            "hint": 15,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_016_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-016",
        &json!({
            "hint": 16,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_017_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-017",
        &json!({
            "hint": 17,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_018_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-018",
        &json!({
            "hint": 18,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_019_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-019",
        &json!({
            "hint": 19,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_020_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-020",
        &json!({
            "hint": 20,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_021_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-021",
        &json!({
            "hint": 21,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_022_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-022",
        &json!({
            "hint": 22,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_023_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-023",
        &json!({
            "hint": 23,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_024_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-024",
        &json!({
            "hint": 24,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_025_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-025",
        &json!({
            "hint": 25,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_026_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-026",
        &json!({
            "hint": 26,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_027_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-027",
        &json!({
            "hint": 27,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_028_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-028",
        &json!({
            "hint": 28,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_029_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-029",
        &json!({
            "hint": 29,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_030_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-030",
        &json!({
            "hint": 30,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_031_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-031",
        &json!({
            "hint": 31,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_032_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-032",
        &json!({
            "hint": 32,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_033_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-033",
        &json!({
            "hint": 33,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_034_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-034",
        &json!({
            "hint": 34,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_035_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-035",
        &json!({
            "hint": 35,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_036_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-036",
        &json!({
            "hint": 36,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_037_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-037",
        &json!({
            "hint": 37,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_038_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-038",
        &json!({
            "hint": 38,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_039_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-039",
        &json!({
            "hint": 39,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_040_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-040",
        &json!({
            "hint": 40,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_041_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-041",
        &json!({
            "hint": 41,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_042_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-042",
        &json!({
            "hint": 42,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_043_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-043",
        &json!({
            "hint": 43,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_044_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-044",
        &json!({
            "hint": 44,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_045_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-045",
        &json!({
            "hint": 45,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_046_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-046",
        &json!({
            "hint": 46,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_047_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-047",
        &json!({
            "hint": 47,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_048_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-048",
        &json!({
            "hint": 48,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_049_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-049",
        &json!({
            "hint": 49,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_050_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-050",
        &json!({
            "hint": 50,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_051_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-051",
        &json!({
            "hint": 51,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_052_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-052",
        &json!({
            "hint": 52,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_053_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-053",
        &json!({
            "hint": 53,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_054_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-054",
        &json!({
            "hint": 54,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_055_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-055",
        &json!({
            "hint": 55,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_056_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-056",
        &json!({
            "hint": 56,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_057_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-057",
        &json!({
            "hint": 57,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_058_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-058",
        &json!({
            "hint": 58,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_059_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-059",
        &json!({
            "hint": 59,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_060_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-060",
        &json!({
            "hint": 60,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_061_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-061",
        &json!({
            "hint": 61,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_062_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-062",
        &json!({
            "hint": 62,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_063_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-063",
        &json!({
            "hint": 63,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_064_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-064",
        &json!({
            "hint": 64,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_065_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-065",
        &json!({
            "hint": 65,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_066_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-066",
        &json!({
            "hint": 66,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_067_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-067",
        &json!({
            "hint": 67,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_068_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-068",
        &json!({
            "hint": 68,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_069_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-069",
        &json!({
            "hint": 69,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_070_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-070",
        &json!({
            "hint": 70,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_071_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-071",
        &json!({
            "hint": 71,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_072_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-072",
        &json!({
            "hint": 72,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_073_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-073",
        &json!({
            "hint": 73,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_074_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-074",
        &json!({
            "hint": 74,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_075_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-075",
        &json!({
            "hint": 75,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_076_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-076",
        &json!({
            "hint": 76,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_077_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-077",
        &json!({
            "hint": 77,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_078_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-078",
        &json!({
            "hint": 78,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_079_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-079",
        &json!({
            "hint": 79,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_080_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-080",
        &json!({
            "hint": 80,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_081_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-081",
        &json!({
            "hint": 81,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_082_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-082",
        &json!({
            "hint": 82,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_083_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-083",
        &json!({
            "hint": 83,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_084_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-084",
        &json!({
            "hint": 84,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_085_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-085",
        &json!({
            "hint": 85,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_086_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-086",
        &json!({
            "hint": 86,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_087_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-087",
        &json!({
            "hint": 87,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_088_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-088",
        &json!({
            "hint": 88,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_089_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-089",
        &json!({
            "hint": 89,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_090_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-090",
        &json!({
            "hint": 90,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_091_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-091",
        &json!({
            "hint": 91,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_092_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-092",
        &json!({
            "hint": 92,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}

pub fn privacy_fence_policy_hint_093_root() -> String {
    payload_root(
        "PRIVACY-FENCE-POLICY-HINT-093",
        &json!({
            "hint": 93,
            "purpose": "low_fee_confidential_liquidation_backstop",
            "privacy": "roots_only_minimum_disclosure",
            "safety": "solvency_first_keeper_execution",
        }),
    )
}
