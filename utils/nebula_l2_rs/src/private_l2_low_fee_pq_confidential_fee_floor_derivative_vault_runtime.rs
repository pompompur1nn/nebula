use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialFeeFloorDerivativeVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_FLOOR_DERIVATIVE_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-fee-floor-derivative-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_FLOOR_DERIVATIVE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_FEE_ORACLE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-fee-floor-oracle-attestation-v1";
pub const PQ_SEALED_VAULT_NOTE_SCHEME: &str =
    "ml-kem-1024+xwing-confidential-fee-floor-vault-note-v1";
pub const FEE_FLOOR_SWAP_SCHEME: &str = "private-l2-low-fee-floor-swap-commitment-v1";
pub const FEE_FLOOR_OPTION_SCHEME: &str = "private-l2-low-fee-floor-option-commitment-v1";
pub const SPONSOR_LIQUIDITY_SCHEME: &str = "roots-only-sponsor-liquidity-fee-floor-vault-v1";
pub const HEDGED_USER_CAP_SCHEME: &str = "private-l2-hedged-user-fee-cap-root-v1";
pub const SETTLEMENT_REBATE_SCHEME: &str = "private-l2-fee-floor-settlement-rebate-root-v1";
pub const RESERVE_ACCOUNTING_SCHEME: &str = "public-reserve-accounting-with-private-notes-v1";
pub const VOLATILITY_WINDOW_SCHEME: &str = "pq-attested-fee-volatility-window-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "operator-safe-fee-floor-derivative-vault-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 2_744_800;
pub const DEVNET_EPOCH: u64 = 4_116;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "fee-credit-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_VAULT_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 120;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_FLOOR_BPS: u64 = 4;
pub const DEFAULT_FLOOR_HEADROOM_BPS: u64 = 3;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_750;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_250;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_500;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 900;
pub const DEFAULT_VOL_HAIRCUT_BPS: u64 = 700;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 6_000;
pub const DEFAULT_PROTOCOL_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_MAX_VAULTS: usize = 262_144;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 262_144;
pub const DEFAULT_MAX_INSTRUMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_VOL_WINDOWS: usize = 1_048_576;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_USER_CAPS: usize = 4_194_304;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_RESERVE_LEDGERS: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    PrivateTransfer,
    ConfidentialSwap,
    LendingPool,
    OptionsVault,
    Perpetuals,
    ContractCall,
    AccountAbstraction,
    BridgeExit,
    ProofAggregation,
    OracleUpdate,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::LendingPool => "lending_pool",
            Self::OptionsVault => "options_vault",
            Self::Perpetuals => "perpetuals",
            Self::ContractCall => "contract_call",
            Self::AccountAbstraction => "account_abstraction",
            Self::BridgeExit => "bridge_exit",
            Self::ProofAggregation => "proof_aggregation",
            Self::OracleUpdate => "oracle_update",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    Hedging,
    Settling,
    Rebating,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Hedging => "hedging",
            Self::Settling => "settling",
            Self::Rebating => "rebating",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentKind {
    FeeFloorSwap,
    FeeFloorCall,
    FeeFloorPut,
    FeeFloorCollar,
    SponsorLiquidityForward,
    VolatilitySwap,
}

impl InstrumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeFloorSwap => "fee_floor_swap",
            Self::FeeFloorCall => "fee_floor_call",
            Self::FeeFloorPut => "fee_floor_put",
            Self::FeeFloorCollar => "fee_floor_collar",
            Self::SponsorLiquidityForward => "sponsor_liquidity_forward",
            Self::VolatilitySwap => "volatility_swap",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentSide {
    UserPaysFloor,
    UserReceivesFloor,
    BuyFeeCap,
    SellFeeCap,
    SponsorShortFees,
    SponsorLongRebates,
}

impl InstrumentSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPaysFloor => "user_pays_floor",
            Self::UserReceivesFloor => "user_receives_floor",
            Self::BuyFeeCap => "buy_fee_cap",
            Self::SellFeeCap => "sell_fee_cap",
            Self::SponsorShortFees => "sponsor_short_fees",
            Self::SponsorLongRebates => "sponsor_long_rebates",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Posted,
    Attested,
    Active,
    Settled,
    Rebated,
    Expired,
    Quarantined,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_fee_oracle_attestation_scheme: String,
    pub pq_sealed_vault_note_scheme: String,
    pub fee_floor_swap_scheme: String,
    pub fee_floor_option_scheme: String,
    pub sponsor_liquidity_scheme: String,
    pub hedged_user_cap_scheme: String,
    pub settlement_rebate_scheme: String,
    pub reserve_accounting_scheme: String,
    pub volatility_window_scheme: String,
    pub fee_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub vault_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_floor_bps: u64,
    pub floor_headroom_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub vol_haircut_bps: u64,
    pub rebate_share_bps: u64,
    pub protocol_reserve_bps: u64,
    pub max_vaults: usize,
    pub max_sponsor_pools: usize,
    pub max_instruments: usize,
    pub max_vol_windows: usize,
    pub max_oracle_attestations: usize,
    pub max_user_caps: usize,
    pub max_settlements: usize,
    pub max_rebates: usize,
    pub max_reserve_ledgers: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_fee_oracle_attestation_scheme: PQ_FEE_ORACLE_ATTESTATION_SCHEME.to_string(),
            pq_sealed_vault_note_scheme: PQ_SEALED_VAULT_NOTE_SCHEME.to_string(),
            fee_floor_swap_scheme: FEE_FLOOR_SWAP_SCHEME.to_string(),
            fee_floor_option_scheme: FEE_FLOOR_OPTION_SCHEME.to_string(),
            sponsor_liquidity_scheme: SPONSOR_LIQUIDITY_SCHEME.to_string(),
            hedged_user_cap_scheme: HEDGED_USER_CAP_SCHEME.to_string(),
            settlement_rebate_scheme: SETTLEMENT_REBATE_SCHEME.to_string(),
            reserve_accounting_scheme: RESERVE_ACCOUNTING_SCHEME.to_string(),
            volatility_window_scheme: VOLATILITY_WINDOW_SCHEME.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            vault_ttl_blocks: DEFAULT_VAULT_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_floor_bps: DEFAULT_TARGET_FLOOR_BPS,
            floor_headroom_bps: DEFAULT_FLOOR_HEADROOM_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            vol_haircut_bps: DEFAULT_VOL_HAIRCUT_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            protocol_reserve_bps: DEFAULT_PROTOCOL_RESERVE_BPS,
            max_vaults: DEFAULT_MAX_VAULTS,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_instruments: DEFAULT_MAX_INSTRUMENTS,
            max_vol_windows: DEFAULT_MAX_VOL_WINDOWS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_user_caps: DEFAULT_MAX_USER_CAPS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_reserve_ledgers: DEFAULT_MAX_RESERVE_LEDGERS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub sponsor_pools: u64,
    pub instruments: u64,
    pub volatility_windows: u64,
    pub oracle_attestations: u64,
    pub hedged_user_caps: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub reserve_ledgers: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vaults_root: String,
    pub sponsor_pools_root: String,
    pub instruments_root: String,
    pub volatility_windows_root: String,
    pub oracle_attestations_root: String,
    pub hedged_user_caps_root: String,
    pub settlements_root: String,
    pub rebates_root: String,
    pub reserve_ledgers_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VaultRecord {
    pub vault_id: String,
    pub lane: FeeLane,
    pub status: VaultStatus,
    pub sponsor_pool_id: String,
    pub vault_commitment: String,
    pub fee_floor_bps: u64,
    pub max_user_fee_bps: u64,
    pub notional_fee_credits: u64,
    pub reserved_fee_credits: u64,
    pub settlement_rebate_credits: u64,
    pub open_height: u64,
    pub expiry_height: u64,
    pub privacy_set_size: u64,
}

impl VaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sponsor_pool_id": self.sponsor_pool_id,
            "vault_commitment": self.vault_commitment,
            "fee_floor_bps": self.fee_floor_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "notional_fee_credits": self.notional_fee_credits,
            "reserved_fee_credits": self.reserved_fee_credits,
            "settlement_rebate_credits": self.settlement_rebate_credits,
            "open_height": self.open_height,
            "expiry_height": self.expiry_height,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SponsorPoolRecord {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub available_liquidity: u64,
    pub reserved_liquidity: u64,
    pub paid_liquidity: u64,
    pub cover_bps: u64,
    pub reserve_bps: u64,
    pub status: RecordStatus,
    pub pq_attestation_root: String,
}

impl SponsorPoolRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "available_liquidity": self.available_liquidity,
            "reserved_liquidity": self.reserved_liquidity,
            "paid_liquidity": self.paid_liquidity,
            "cover_bps": self.cover_bps,
            "reserve_bps": self.reserve_bps,
            "status": self.status.as_str(),
            "pq_attestation_root": self.pq_attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct InstrumentRecord {
    pub instrument_id: String,
    pub vault_id: String,
    pub owner_commitment: String,
    pub kind: InstrumentKind,
    pub side: InstrumentSide,
    pub notional_fee_credits: u64,
    pub strike_fee_bps: u64,
    pub premium_micro: u64,
    pub margin_micro: u64,
    pub maturity_height: u64,
    pub sealed_terms_root: String,
    pub status: RecordStatus,
}

impl InstrumentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "instrument_id": self.instrument_id,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "kind": self.kind.as_str(),
            "side": self.side.as_str(),
            "notional_fee_credits": self.notional_fee_credits,
            "strike_fee_bps": self.strike_fee_bps,
            "premium_micro": self.premium_micro,
            "margin_micro": self.margin_micro,
            "maturity_height": self.maturity_height,
            "sealed_terms_root": self.sealed_terms_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VolatilityWindowRecord {
    pub window_id: String,
    pub lane: FeeLane,
    pub start_height: u64,
    pub end_height: u64,
    pub observed_floor_bps: u64,
    pub realized_vol_bps: u64,
    pub stress_vol_bps: u64,
    pub sample_count: u64,
    pub oracle_attestation_root: String,
}

impl VolatilityWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "observed_floor_bps": self.observed_floor_bps,
            "realized_vol_bps": self.realized_vol_bps,
            "stress_vol_bps": self.stress_vol_bps,
            "sample_count": self.sample_count,
            "oracle_attestation_root": self.oracle_attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OracleAttestationRecord {
    pub attestation_id: String,
    pub oracle_committee: String,
    pub lane: FeeLane,
    pub height: u64,
    pub fee_floor_bps: u64,
    pub fee_cap_bps: u64,
    pub volatility_bps: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub status: RecordStatus,
}

impl OracleAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "oracle_committee": self.oracle_committee,
            "lane": self.lane.as_str(),
            "height": self.height,
            "fee_floor_bps": self.fee_floor_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "volatility_bps": self.volatility_bps,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct HedgedUserCapRecord {
    pub cap_id: String,
    pub vault_id: String,
    pub user_commitment: String,
    pub instrument_id: String,
    pub cap_bps: u64,
    pub charged_bps: u64,
    pub sponsor_cover_micro: u64,
    pub rebate_commitment: String,
    pub status: RecordStatus,
}

impl HedgedUserCapRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "vault_id": self.vault_id,
            "user_commitment": self.user_commitment,
            "instrument_id": self.instrument_id,
            "cap_bps": self.cap_bps,
            "charged_bps": self.charged_bps,
            "sponsor_cover_micro": self.sponsor_cover_micro,
            "rebate_commitment": self.rebate_commitment,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub vault_id: String,
    pub attestation_id: String,
    pub realized_fee_bps: u64,
    pub floor_fee_bps: u64,
    pub gross_payout_micro: i128,
    pub sponsor_paid_micro: u64,
    pub reserve_delta_micro: i128,
    pub settlement_root: String,
    pub status: RecordStatus,
}

impl SettlementRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "vault_id": self.vault_id,
            "attestation_id": self.attestation_id,
            "realized_fee_bps": self.realized_fee_bps,
            "floor_fee_bps": self.floor_fee_bps,
            "gross_payout_micro": self.gross_payout_micro.to_string(),
            "sponsor_paid_micro": self.sponsor_paid_micro,
            "reserve_delta_micro": self.reserve_delta_micro.to_string(),
            "settlement_root": self.settlement_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub settlement_id: String,
    pub beneficiary_commitment: String,
    pub amount_micro: u64,
    pub reserve_source: String,
    pub expiry_height: u64,
    pub receipt_root: String,
    pub status: RecordStatus,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "amount_micro": self.amount_micro,
            "reserve_source": self.reserve_source,
            "expiry_height": self.expiry_height,
            "receipt_root": self.receipt_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReserveLedgerRecord {
    pub ledger_id: String,
    pub vault_id: String,
    pub asset_id: String,
    pub opening_reserve_micro: u64,
    pub sponsor_inflow_micro: u64,
    pub settlement_outflow_micro: u64,
    pub rebate_outflow_micro: u64,
    pub closing_reserve_micro: u64,
    pub accounting_root: String,
}

impl ReserveLedgerRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub sequence: u64,
}

impl EventRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub network: String,
    pub monero_network: String,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, VaultRecord>,
    pub sponsor_pools: BTreeMap<String, SponsorPoolRecord>,
    pub instruments: BTreeMap<String, InstrumentRecord>,
    pub volatility_windows: BTreeMap<String, VolatilityWindowRecord>,
    pub oracle_attestations: BTreeMap<String, OracleAttestationRecord>,
    pub hedged_user_caps: BTreeMap<String, HedgedUserCapRecord>,
    pub settlements: BTreeMap<String, SettlementRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub reserve_ledgers: BTreeMap<String, ReserveLedgerRecord>,
    pub events: Vec<EventRecord>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
        network: impl Into<String>,
        monero_network: impl Into<String>,
    ) -> Self {
        let mut state = Self {
            config,
            network: network.into(),
            monero_network: monero_network.into(),
            height: 0,
            epoch: 0,
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            instruments: BTreeMap::new(),
            volatility_windows: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            hedged_user_caps: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            reserve_ledgers: BTreeMap::new(),
            events: Vec::new(),
            nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_L2_NETWORK, DEVNET_MONERO_NETWORK);
        state.height = DEVNET_HEIGHT;
        state.epoch = DEVNET_EPOCH;
        state.refresh_roots();
        state
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            vaults_root: map_root(
                "VAULTS",
                self.vaults
                    .values()
                    .map(VaultRecord::public_record)
                    .collect(),
            ),
            sponsor_pools_root: map_root(
                "SPONSOR-POOLS",
                self.sponsor_pools
                    .values()
                    .map(SponsorPoolRecord::public_record)
                    .collect(),
            ),
            instruments_root: map_root(
                "INSTRUMENTS",
                self.instruments
                    .values()
                    .map(InstrumentRecord::public_record)
                    .collect(),
            ),
            volatility_windows_root: map_root(
                "VOLATILITY-WINDOWS",
                self.volatility_windows
                    .values()
                    .map(VolatilityWindowRecord::public_record)
                    .collect(),
            ),
            oracle_attestations_root: map_root(
                "ORACLE-ATTESTATIONS",
                self.oracle_attestations
                    .values()
                    .map(OracleAttestationRecord::public_record)
                    .collect(),
            ),
            hedged_user_caps_root: map_root(
                "HEDGED-USER-CAPS",
                self.hedged_user_caps
                    .values()
                    .map(HedgedUserCapRecord::public_record)
                    .collect(),
            ),
            settlements_root: map_root(
                "SETTLEMENTS",
                self.settlements
                    .values()
                    .map(SettlementRecord::public_record)
                    .collect(),
            ),
            rebates_root: map_root(
                "REBATES",
                self.rebates
                    .values()
                    .map(RebateRecord::public_record)
                    .collect(),
            ),
            reserve_ledgers_root: map_root(
                "RESERVE-LEDGERS",
                self.reserve_ledgers
                    .values()
                    .map(ReserveLedgerRecord::public_record)
                    .collect(),
            ),
            events_root: map_root(
                "EVENTS",
                self.events.iter().map(EventRecord::public_record).collect(),
            ),
            state_root: String::new(),
        };
        roots.state_root = record_root("STATE", &self.public_record_with_roots(&roots));
        roots
    }

    pub fn refresh_roots(&mut self) {
        self.roots = self.roots();
    }

    pub fn add_sponsor_pool(
        &mut self,
        sponsor_commitment: impl Into<String>,
        liquidity: u64,
    ) -> Result<String> {
        ensure!(
            self.sponsor_pools.len() < self.config.max_sponsor_pools,
            "sponsor pool limit reached"
        );
        let sponsor_commitment = sponsor_commitment.into();
        let pool_id = record_id(
            "SPONSOR-POOL",
            &[HashPart::Str(&sponsor_commitment), HashPart::U64(liquidity)],
        );
        let pq_attestation_root = record_root(
            "SPONSOR-LIQUIDITY-ATTESTATION",
            &json!({"sponsor_commitment": sponsor_commitment, "liquidity": liquidity}),
        );
        self.sponsor_pools.insert(
            pool_id.clone(),
            SponsorPoolRecord {
                pool_id: pool_id.clone(),
                sponsor_commitment,
                asset_id: self.config.fee_asset_id.clone(),
                available_liquidity: liquidity,
                reserved_liquidity: 0,
                paid_liquidity: 0,
                cover_bps: self.config.sponsor_cover_bps,
                reserve_bps: self.config.sponsor_reserve_bps,
                status: RecordStatus::Active,
                pq_attestation_root,
            },
        );
        self.counters.sponsor_pools += 1;
        self.emit_event("sponsor_pool_active", &pool_id);
        Ok(pool_id)
    }

    pub fn open_vault(
        &mut self,
        lane: FeeLane,
        sponsor_pool_id: impl Into<String>,
        vault_commitment: impl Into<String>,
        notional_fee_credits: u64,
    ) -> Result<String> {
        ensure!(
            self.vaults.len() < self.config.max_vaults,
            "vault limit reached"
        );
        let sponsor_pool_id = sponsor_pool_id.into();
        ensure!(
            self.sponsor_pools.contains_key(&sponsor_pool_id),
            "missing sponsor pool {}",
            sponsor_pool_id
        );
        let vault_commitment = vault_commitment.into();
        let reserve = bps(notional_fee_credits, self.config.sponsor_reserve_bps);
        let vault_id = record_id(
            "VAULT",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(&sponsor_pool_id),
                HashPart::Str(&vault_commitment),
                HashPart::U64(notional_fee_credits),
            ],
        );
        if let Some(pool) = self.sponsor_pools.get_mut(&sponsor_pool_id) {
            ensure!(
                pool.available_liquidity >= reserve,
                "insufficient sponsor reserve"
            );
            pool.available_liquidity -= reserve;
            pool.reserved_liquidity += reserve;
        }
        self.vaults.insert(
            vault_id.clone(),
            VaultRecord {
                vault_id: vault_id.clone(),
                lane,
                status: VaultStatus::Active,
                sponsor_pool_id,
                vault_commitment,
                fee_floor_bps: self.config.target_floor_bps,
                max_user_fee_bps: self.config.max_user_fee_bps,
                notional_fee_credits,
                reserved_fee_credits: reserve,
                settlement_rebate_credits: 0,
                open_height: self.height,
                expiry_height: self.height + self.config.vault_ttl_blocks,
                privacy_set_size: self.config.target_privacy_set_size,
            },
        );
        self.counters.vaults += 1;
        self.emit_event("vault_opened", &vault_id);
        Ok(vault_id)
    }

    pub fn add_instrument(
        &mut self,
        vault_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        kind: InstrumentKind,
        side: InstrumentSide,
        notional_fee_credits: u64,
    ) -> Result<String> {
        ensure!(
            self.instruments.len() < self.config.max_instruments,
            "instrument limit reached"
        );
        let vault_id = vault_id.into();
        ensure!(
            self.vaults.contains_key(&vault_id),
            "missing vault {}",
            vault_id
        );
        let owner_commitment = owner_commitment.into();
        let strike_fee_bps = self.config.target_floor_bps + self.config.floor_headroom_bps;
        let margin_micro = bps(notional_fee_credits, self.config.initial_margin_bps);
        let sealed_terms_root = record_root(
            "SEALED-INSTRUMENT-TERMS",
            &json!({
                "vault_id": vault_id,
                "owner_commitment": owner_commitment,
                "kind": kind.as_str(),
                "side": side.as_str(),
                "notional_fee_credits": notional_fee_credits
            }),
        );
        let instrument_id = record_id(
            "INSTRUMENT",
            &[
                HashPart::Str(&vault_id),
                HashPart::Str(&owner_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Str(side.as_str()),
            ],
        );
        self.instruments.insert(
            instrument_id.clone(),
            InstrumentRecord {
                instrument_id: instrument_id.clone(),
                vault_id,
                owner_commitment,
                kind,
                side,
                notional_fee_credits,
                strike_fee_bps,
                premium_micro: bps(notional_fee_credits, self.config.target_user_fee_bps),
                margin_micro,
                maturity_height: self.height + self.config.settlement_ttl_blocks,
                sealed_terms_root,
                status: RecordStatus::Active,
            },
        );
        self.counters.instruments += 1;
        self.emit_event("instrument_active", &instrument_id);
        Ok(instrument_id)
    }

    pub fn attest_fee_oracle(
        &mut self,
        oracle_committee: impl Into<String>,
        lane: FeeLane,
        fee_floor_bps: u64,
        fee_cap_bps: u64,
        volatility_bps: u64,
    ) -> Result<String> {
        ensure!(
            self.oracle_attestations.len() < self.config.max_oracle_attestations,
            "oracle attestation limit reached"
        );
        ensure!(fee_floor_bps <= fee_cap_bps, "floor exceeds cap");
        let oracle_committee = oracle_committee.into();
        let transcript = json!({
            "oracle_committee": oracle_committee,
            "lane": lane.as_str(),
            "height": self.height,
            "fee_floor_bps": fee_floor_bps,
            "fee_cap_bps": fee_cap_bps,
            "volatility_bps": volatility_bps
        });
        let transcript_root = record_root("PQ-FEE-ORACLE-TRANSCRIPT", &transcript);
        let pq_signature_root = record_root(
            "PQ-FEE-ORACLE-SIGNATURE",
            &json!({"transcript_root": transcript_root}),
        );
        let attestation_id = record_id(
            "ORACLE-ATTESTATION",
            &[
                HashPart::Str(&oracle_committee),
                HashPart::Str(lane.as_str()),
                HashPart::U64(self.height),
                HashPart::Str(&transcript_root),
            ],
        );
        self.oracle_attestations.insert(
            attestation_id.clone(),
            OracleAttestationRecord {
                attestation_id: attestation_id.clone(),
                oracle_committee,
                lane,
                height: self.height,
                fee_floor_bps,
                fee_cap_bps,
                volatility_bps,
                pq_signature_root,
                transcript_root,
                status: RecordStatus::Attested,
            },
        );
        self.counters.oracle_attestations += 1;
        self.emit_event("oracle_attested", &attestation_id);
        Ok(attestation_id)
    }

    pub fn add_volatility_window(
        &mut self,
        lane: FeeLane,
        observed_floor_bps: u64,
        realized_vol_bps: u64,
        stress_vol_bps: u64,
        sample_count: u64,
        oracle_attestation_root: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.volatility_windows.len() < self.config.max_vol_windows,
            "volatility window limit reached"
        );
        let oracle_attestation_root = oracle_attestation_root.into();
        let window_id = record_id(
            "VOLATILITY-WINDOW",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::U64(self.height.saturating_sub(self.config.epoch_blocks)),
                HashPart::U64(self.height),
                HashPart::Str(&oracle_attestation_root),
            ],
        );
        self.volatility_windows.insert(
            window_id.clone(),
            VolatilityWindowRecord {
                window_id: window_id.clone(),
                lane,
                start_height: self.height.saturating_sub(self.config.epoch_blocks),
                end_height: self.height,
                observed_floor_bps,
                realized_vol_bps,
                stress_vol_bps,
                sample_count,
                oracle_attestation_root,
            },
        );
        self.counters.volatility_windows += 1;
        self.emit_event("volatility_window_recorded", &window_id);
        Ok(window_id)
    }

    pub fn hedge_user_cap(
        &mut self,
        vault_id: impl Into<String>,
        user_commitment: impl Into<String>,
        instrument_id: impl Into<String>,
        charged_bps: u64,
    ) -> Result<String> {
        ensure!(
            self.hedged_user_caps.len() < self.config.max_user_caps,
            "user cap limit reached"
        );
        let vault_id = vault_id.into();
        let user_commitment = user_commitment.into();
        let instrument_id = instrument_id.into();
        ensure!(
            self.vaults.contains_key(&vault_id),
            "missing vault {}",
            vault_id
        );
        ensure!(
            self.instruments.contains_key(&instrument_id),
            "missing instrument {}",
            instrument_id
        );
        let cap_bps = self.config.max_user_fee_bps;
        let sponsor_cover_micro = if charged_bps > cap_bps {
            bps(charged_bps - cap_bps, self.config.sponsor_cover_bps)
        } else {
            0
        };
        let rebate_commitment = record_id(
            "USER-CAP-REBATE-COMMITMENT",
            &[
                HashPart::Str(&vault_id),
                HashPart::Str(&user_commitment),
                HashPart::U64(charged_bps),
            ],
        );
        let cap_id = record_id(
            "HEDGED-USER-CAP",
            &[
                HashPart::Str(&vault_id),
                HashPart::Str(&user_commitment),
                HashPart::Str(&instrument_id),
            ],
        );
        self.hedged_user_caps.insert(
            cap_id.clone(),
            HedgedUserCapRecord {
                cap_id: cap_id.clone(),
                vault_id,
                user_commitment,
                instrument_id,
                cap_bps,
                charged_bps,
                sponsor_cover_micro,
                rebate_commitment,
                status: RecordStatus::Active,
            },
        );
        self.counters.hedged_user_caps += 1;
        self.emit_event("hedged_user_cap_active", &cap_id);
        Ok(cap_id)
    }

    pub fn settle_vault(
        &mut self,
        vault_id: impl Into<String>,
        attestation_id: impl Into<String>,
        realized_fee_bps: u64,
    ) -> Result<String> {
        ensure!(
            self.settlements.len() < self.config.max_settlements,
            "settlement limit reached"
        );
        let vault_id = vault_id.into();
        let attestation_id = attestation_id.into();
        let vault = self
            .vaults
            .get(&vault_id)
            .cloned()
            .ok_or_else(|| format!("missing vault {vault_id}"))?;
        ensure!(
            self.oracle_attestations.contains_key(&attestation_id),
            "missing attestation {}",
            attestation_id
        );
        let over_floor_bps = realized_fee_bps.saturating_sub(vault.fee_floor_bps);
        let gross_payout_micro = bps(vault.notional_fee_credits, over_floor_bps) as i128;
        let sponsor_paid_micro = bps(
            gross_payout_micro.max(0) as u64,
            self.config.sponsor_cover_bps,
        );
        let reserve_delta_micro = -(sponsor_paid_micro as i128);
        let settlement_root = record_root(
            "SETTLEMENT",
            &json!({
                "vault_id": vault_id,
                "attestation_id": attestation_id,
                "realized_fee_bps": realized_fee_bps,
                "gross_payout_micro": gross_payout_micro.to_string()
            }),
        );
        let settlement_id = record_id(
            "SETTLEMENT",
            &[
                HashPart::Str(&vault_id),
                HashPart::Str(&attestation_id),
                HashPart::Str(&settlement_root),
            ],
        );
        self.settlements.insert(
            settlement_id.clone(),
            SettlementRecord {
                settlement_id: settlement_id.clone(),
                vault_id: vault_id.clone(),
                attestation_id,
                realized_fee_bps,
                floor_fee_bps: vault.fee_floor_bps,
                gross_payout_micro,
                sponsor_paid_micro,
                reserve_delta_micro,
                settlement_root,
                status: RecordStatus::Settled,
            },
        );
        if let Some(vault) = self.vaults.get_mut(&vault_id) {
            vault.status = VaultStatus::Settling;
            vault.settlement_rebate_credits = bps(sponsor_paid_micro, self.config.rebate_share_bps);
        }
        self.counters.settlements += 1;
        self.emit_event("vault_settled", &settlement_id);
        Ok(settlement_id)
    }

    pub fn add_rebate(
        &mut self,
        settlement_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        amount_micro: u64,
    ) -> Result<String> {
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate limit reached"
        );
        let settlement_id = settlement_id.into();
        ensure!(
            self.settlements.contains_key(&settlement_id),
            "missing settlement {}",
            settlement_id
        );
        let beneficiary_commitment = beneficiary_commitment.into();
        let receipt_root = record_root(
            "REBATE-RECEIPT",
            &json!({"settlement_id": settlement_id, "beneficiary_commitment": beneficiary_commitment, "amount_micro": amount_micro}),
        );
        let rebate_id = record_id(
            "REBATE",
            &[
                HashPart::Str(&settlement_id),
                HashPart::Str(&beneficiary_commitment),
                HashPart::Str(&receipt_root),
            ],
        );
        self.rebates.insert(
            rebate_id.clone(),
            RebateRecord {
                rebate_id: rebate_id.clone(),
                settlement_id,
                beneficiary_commitment,
                amount_micro,
                reserve_source: "sponsor_fee_floor_vault_reserve".to_string(),
                expiry_height: self.height + self.config.rebate_ttl_blocks,
                receipt_root,
                status: RecordStatus::Rebated,
            },
        );
        self.counters.rebates += 1;
        self.emit_event("settlement_rebate_recorded", &rebate_id);
        Ok(rebate_id)
    }

    pub fn record_reserve_ledger(
        &mut self,
        vault_id: impl Into<String>,
        opening_reserve_micro: u64,
        sponsor_inflow_micro: u64,
        settlement_outflow_micro: u64,
        rebate_outflow_micro: u64,
    ) -> Result<String> {
        ensure!(
            self.reserve_ledgers.len() < self.config.max_reserve_ledgers,
            "reserve ledger limit reached"
        );
        let vault_id = vault_id.into();
        ensure!(
            self.vaults.contains_key(&vault_id),
            "missing vault {}",
            vault_id
        );
        let closing_reserve_micro = opening_reserve_micro
            .saturating_add(sponsor_inflow_micro)
            .saturating_sub(settlement_outflow_micro)
            .saturating_sub(rebate_outflow_micro);
        let accounting_root = record_root(
            "RESERVE-ACCOUNTING",
            &json!({
                "vault_id": vault_id,
                "opening_reserve_micro": opening_reserve_micro,
                "sponsor_inflow_micro": sponsor_inflow_micro,
                "settlement_outflow_micro": settlement_outflow_micro,
                "rebate_outflow_micro": rebate_outflow_micro,
                "closing_reserve_micro": closing_reserve_micro
            }),
        );
        let ledger_id = record_id(
            "RESERVE-LEDGER",
            &[
                HashPart::Str(&vault_id),
                HashPart::Str(&accounting_root),
                HashPart::U64(self.counters.reserve_ledgers),
            ],
        );
        self.reserve_ledgers.insert(
            ledger_id.clone(),
            ReserveLedgerRecord {
                ledger_id: ledger_id.clone(),
                vault_id,
                asset_id: self.config.fee_asset_id.clone(),
                opening_reserve_micro,
                sponsor_inflow_micro,
                settlement_outflow_micro,
                rebate_outflow_micro,
                closing_reserve_micro,
                accounting_root,
            },
        );
        self.counters.reserve_ledgers += 1;
        self.emit_event("reserve_ledger_recorded", &ledger_id);
        Ok(ledger_id)
    }

    pub fn public_record(&self) -> Value {
        self.public_record_with_roots(&self.roots())
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn public_record_with_roots(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_protocol_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_FLOOR_DERIVATIVE_VAULT_RUNTIME_PROTOCOL_VERSION,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "network": self.network,
            "monero_network": self.monero_network,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "vault_count": self.vaults.len(),
            "sponsor_pool_count": self.sponsor_pools.len(),
            "instrument_count": self.instruments.len(),
            "volatility_window_count": self.volatility_windows.len(),
            "oracle_attestation_count": self.oracle_attestations.len(),
            "hedged_user_cap_count": self.hedged_user_caps.len(),
            "settlement_count": self.settlements.len(),
            "rebate_count": self.rebates.len(),
            "reserve_ledger_count": self.reserve_ledgers.len(),
            "nullifier_count": self.nullifiers.len()
        })
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        let sequence = self.counters.events;
        let payload_root = record_root(
            "EVENT-PAYLOAD",
            &json!({"kind": kind, "subject_id": subject_id, "sequence": sequence}),
        );
        let event_id = record_id(
            "EVENT",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(sequence),
            ],
        );
        self.events.push(EventRecord {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            sequence,
        });
        self.counters.events += 1;
        self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let sponsor_pool_id = state
        .add_sponsor_pool("demo-sponsor-liquidity-commitment", 24_000_000)
        .expect("demo sponsor pool");
    let vault_id = state
        .open_vault(
            FeeLane::ConfidentialSwap,
            sponsor_pool_id,
            "demo-fee-floor-vault-commitment",
            8_000_000,
        )
        .expect("demo vault");
    let instrument_id = state
        .add_instrument(
            vault_id.clone(),
            "demo-user-hedge-commitment",
            InstrumentKind::FeeFloorCollar,
            InstrumentSide::BuyFeeCap,
            3_500_000,
        )
        .expect("demo instrument");
    let attestation_id = state
        .attest_fee_oracle(
            "demo-pq-fee-oracle-committee",
            FeeLane::ConfidentialSwap,
            4,
            13,
            930,
        )
        .expect("demo oracle attestation");
    let attestation_root = state
        .oracle_attestations
        .get(&attestation_id)
        .map(|record| record.transcript_root.clone())
        .expect("demo oracle transcript");
    state
        .add_volatility_window(
            FeeLane::ConfidentialSwap,
            4,
            720,
            1_140,
            384,
            attestation_root,
        )
        .expect("demo volatility window");
    state
        .hedge_user_cap(
            vault_id.clone(),
            "demo-user-cap-commitment",
            instrument_id,
            17,
        )
        .expect("demo hedged cap");
    let settlement_id = state
        .settle_vault(vault_id.clone(), attestation_id, 13)
        .expect("demo settlement");
    state
        .add_rebate(settlement_id, "demo-user-rebate-commitment", 18_900)
        .expect("demo rebate");
    state
        .record_reserve_ledger(vault_id, 1_000_000, 100_000, 63_000, 18_900)
        .expect("demo reserve ledger");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-DERIVATIVE-VAULT-{}",
            domain
        ),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn record_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-DERIVATIVE-VAULT-ID-{}",
            domain
        ),
        parts,
        32,
    )
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    let leaves: Vec<Value> = records
        .iter()
        .map(|record| Value::String(record_root(domain, record)))
        .collect();
    merkle_root(
        &format!(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-DERIVATIVE-VAULT-{}",
            domain
        ),
        &leaves,
    )
}

fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps).saturating_div(MAX_BPS)
}
