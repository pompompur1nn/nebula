use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialMicroFeeFuturesClearingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MICRO_FEE_FUTURES_CLEARING_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-micro-fee-futures-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MICRO_FEE_FUTURES_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_026_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "xmr-private-margin-devnet";
pub const DEVNET_ORACLE_ID: &str = "devnet-confidential-micro-fee-oracle";
pub const DEVNET_CLEARING_HOUSE_ID: &str = "devnet-micro-fee-futures-clearing-house";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-micro-fee-clearing-v1";
pub const CONFIDENTIAL_NOTE_SCHEME: &str =
    "ringct-bulletproofs-plus-confidential-margin-note-root-v1";
pub const BATCH_NETTING_SCHEME: &str =
    "low-fee-confidential-micro-fee-futures-batch-netting-root-v1";
pub const REBATE_LEDGER_SCHEME: &str = "confidential-micro-fee-futures-maker-rebate-ledger-root-v1";
pub const LIQUIDATION_GUARD_SCHEME: &str =
    "private-l2-confidential-micro-fee-liquidation-guard-root-v1";
pub const REPLAY_DOMAIN: &str =
    "private-l2-low-fee-pq-confidential-micro-fee-futures-clearing-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAKER_FEE_BPS: u64 = 1;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_REBATE_BPS: u64 = 2;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_100;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 750;
pub const DEFAULT_LIQUIDATION_MARGIN_BPS: u64 = 525;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 900;
pub const DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 18;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_CLEARING_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_REBATE_CLAIM_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_LIQUIDATION_GRACE_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_BATCH_LOTS: usize = 512;
pub const DEFAULT_MAX_CONTRACT_NOTIONAL_PICONERO: u128 = 2_500_000_000_000;
pub const DEFAULT_MAX_ACCOUNT_NOTIONAL_PICONERO: u128 = 250_000_000_000;
pub const DEFAULT_MAX_BATCH_NOTIONAL_PICONERO: u128 = 5_000_000_000_000;
pub const MAX_CONTRACTS: usize = 262_144;
pub const MAX_CLEARING_LOTS: usize = 4_194_304;
pub const MAX_MARGIN_NOTES: usize = 4_194_304;
pub const MAX_BATCHES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_REBATE_ACCOUNTS: usize = 2_097_152;
pub const MAX_LIQUIDATION_GUARDS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_NULLIFIERS: usize = 8_388_608;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeIndexKind {
    ExecutionGas,
    DataAvailability,
    BlobWitness,
    BridgeExit,
    ProverTime,
    OracleUpdate,
    CrossContractCall,
    LiquidationPath,
}

impl FeeIndexKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionGas => "execution_gas",
            Self::DataAvailability => "data_availability",
            Self::BlobWitness => "blob_witness",
            Self::BridgeExit => "bridge_exit",
            Self::ProverTime => "prover_time",
            Self::OracleUpdate => "oracle_update",
            Self::CrossContractCall => "cross_contract_call",
            Self::LiquidationPath => "liquidation_path",
        }
    }

    pub fn oracle_weight(self) -> u64 {
        match self {
            Self::LiquidationPath => 10_000,
            Self::BridgeExit => 9_500,
            Self::ProverTime => 8_800,
            Self::DataAvailability => 8_600,
            Self::BlobWitness => 8_100,
            Self::ExecutionGas => 7_900,
            Self::CrossContractCall => 7_500,
            Self::OracleUpdate => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Draft,
    Listed,
    Trading,
    NettingOnly,
    ReduceOnly,
    OracleGuarded,
    Halted,
    Matured,
    Settled,
    Retired,
}

impl ContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Listed => "listed",
            Self::Trading => "trading",
            Self::NettingOnly => "netting_only",
            Self::ReduceOnly => "reduce_only",
            Self::OracleGuarded => "oracle_guarded",
            Self::Halted => "halted",
            Self::Matured => "matured",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_new_lots(self) -> bool {
        matches!(self, Self::Trading | Self::OracleGuarded)
    }

    pub fn allows_reduce(self) -> bool {
        matches!(
            self,
            Self::Trading
                | Self::NettingOnly
                | Self::ReduceOnly
                | Self::OracleGuarded
                | Self::Matured
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotSide {
    LongFee,
    ShortFee,
    MakerHedge,
    TakerHedge,
    LiquidationBackstop,
}

impl LotSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongFee => "long_fee",
            Self::ShortFee => "short_fee",
            Self::MakerHedge => "maker_hedge",
            Self::TakerHedge => "taker_hedge",
            Self::LiquidationBackstop => "liquidation_backstop",
        }
    }

    pub fn sign(self) -> i128 {
        match self {
            Self::LongFee | Self::MakerHedge | Self::LiquidationBackstop => 1,
            Self::ShortFee | Self::TakerHedge => -1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Committed,
    MarginReserved,
    BatchQueued,
    Netted,
    Settled,
    RebateQueued,
    LiquidationGuarded,
    Cancelled,
    Expired,
}

impl LotStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::MarginReserved | Self::BatchQueued | Self::Netted
        )
    }

    pub fn public_label(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::MarginReserved => "margin_reserved",
            Self::BatchQueued => "batch_queued",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::RebateQueued => "rebate_queued",
            Self::LiquidationGuarded => "liquidation_guarded",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginNoteStatus {
    Pending,
    Locked,
    Reserved,
    Released,
    Slashed,
    LiquidationEscrow,
    Expired,
}

impl MarginNoteStatus {
    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Locked | Self::Reserved | Self::LiquidationEscrow
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingBatchStatus {
    Open,
    Full,
    AttestationPending,
    Attested,
    Settling,
    Settled,
    Disputed,
    Quarantined,
    Expired,
}

impl NettingBatchStatus {
    pub fn accepts_lots(self) -> bool {
        matches!(self, Self::Open | Self::Full)
    }

    pub fn counted_as_live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Full | Self::AttestationPending | Self::Attested | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Quarantined,
    Disputed,
    Expired,
    Revoked,
}

impl AttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    DonatedToFeePool,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Watching,
    GracePeriod,
    AuctionQueued,
    BackstopFilled,
    Released,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ContractListed,
    LotCommitted,
    MarginNoteLocked,
    BatchOpened,
    LotNetted,
    BatchAttested,
    BatchSettled,
    RebateAccrued,
    LiquidationGuardRaised,
    OperatorSummaryPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractListed => "contract_listed",
            Self::LotCommitted => "lot_committed",
            Self::MarginNoteLocked => "margin_note_locked",
            Self::BatchOpened => "batch_opened",
            Self::LotNetted => "lot_netted",
            Self::BatchAttested => "batch_attested",
            Self::BatchSettled => "batch_settled",
            Self::RebateAccrued => "rebate_accrued",
            Self::LiquidationGuardRaised => "liquidation_guard_raised",
            Self::OperatorSummaryPublished => "operator_summary_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub clearing_house_id: String,
    pub oracle_id: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub confidential_note_scheme: String,
    pub batch_netting_scheme: String,
    pub rebate_ledger_scheme: String,
    pub liquidation_guard_scheme: String,
    pub replay_domain: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub protocol_fee_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_margin_bps: u64,
    pub max_leverage_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub clearing_window_blocks: u64,
    pub rebate_claim_ttl_blocks: u64,
    pub liquidation_grace_blocks: u64,
    pub max_batch_lots: usize,
    pub max_contract_notional_piconero: u128,
    pub max_account_notional_piconero: u128,
    pub max_batch_notional_piconero: u128,
    pub max_contracts: usize,
    pub max_clearing_lots: usize,
    pub max_margin_notes: usize,
    pub max_batches: usize,
    pub max_attestations: usize,
    pub max_rebate_accounts: usize,
    pub max_liquidation_guards: usize,
    pub max_operator_summaries: usize,
    pub max_nullifiers: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            clearing_house_id: DEVNET_CLEARING_HOUSE_ID.to_string(),
            oracle_id: DEVNET_ORACLE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            confidential_note_scheme: CONFIDENTIAL_NOTE_SCHEME.to_string(),
            batch_netting_scheme: BATCH_NETTING_SCHEME.to_string(),
            rebate_ledger_scheme: REBATE_LEDGER_SCHEME.to_string(),
            liquidation_guard_scheme: LIQUIDATION_GUARD_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            maker_fee_bps: DEFAULT_MAKER_FEE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_margin_bps: DEFAULT_LIQUIDATION_MARGIN_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            max_oracle_staleness_blocks: DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            clearing_window_blocks: DEFAULT_CLEARING_WINDOW_BLOCKS,
            rebate_claim_ttl_blocks: DEFAULT_REBATE_CLAIM_TTL_BLOCKS,
            liquidation_grace_blocks: DEFAULT_LIQUIDATION_GRACE_BLOCKS,
            max_batch_lots: DEFAULT_MAX_BATCH_LOTS,
            max_contract_notional_piconero: DEFAULT_MAX_CONTRACT_NOTIONAL_PICONERO,
            max_account_notional_piconero: DEFAULT_MAX_ACCOUNT_NOTIONAL_PICONERO,
            max_batch_notional_piconero: DEFAULT_MAX_BATCH_NOTIONAL_PICONERO,
            max_contracts: MAX_CONTRACTS,
            max_clearing_lots: MAX_CLEARING_LOTS,
            max_margin_notes: MAX_MARGIN_NOTES,
            max_batches: MAX_BATCHES,
            max_attestations: MAX_ATTESTATIONS,
            max_rebate_accounts: MAX_REBATE_ACCOUNTS,
            max_liquidation_guards: MAX_LIQUIDATION_GUARDS,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
            max_nullifiers: MAX_NULLIFIERS,
            max_events: MAX_EVENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "clearing_house_id": self.clearing_house_id,
            "oracle_id": self.oracle_id,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "confidential_note_scheme": self.confidential_note_scheme,
            "batch_netting_scheme": self.batch_netting_scheme,
            "rebate_ledger_scheme": self.rebate_ledger_scheme,
            "liquidation_guard_scheme": self.liquidation_guard_scheme,
            "replay_domain": self.replay_domain,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_margin_bps": self.liquidation_margin_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "clearing_window_blocks": self.clearing_window_blocks,
            "rebate_claim_ttl_blocks": self.rebate_claim_ttl_blocks,
            "liquidation_grace_blocks": self.liquidation_grace_blocks,
            "max_batch_lots": self.max_batch_lots,
            "max_contract_notional_piconero": self.max_contract_notional_piconero.to_string(),
            "max_account_notional_piconero": self.max_account_notional_piconero.to_string(),
            "max_batch_notional_piconero": self.max_batch_notional_piconero.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub contracts: u64,
    pub active_contracts: u64,
    pub clearing_lots: u64,
    pub live_lots: u64,
    pub netted_lots: u64,
    pub settled_lots: u64,
    pub margin_notes: u64,
    pub locked_margin_notes: u64,
    pub margin_reserved_piconero: u128,
    pub batch_count: u64,
    pub live_batches: u64,
    pub settled_batches: u64,
    pub pq_attestations: u64,
    pub accepted_attestations: u64,
    pub quarantined_attestations: u64,
    pub rebate_accounts: u64,
    pub claimable_rebate_accounts: u64,
    pub rebate_accrued_piconero: u128,
    pub rebate_claimed_piconero: u128,
    pub liquidation_guards: u64,
    pub active_liquidation_guards: u64,
    pub operator_summaries: u64,
    pub consumed_nullifiers: u64,
    pub events: u64,
    pub gross_notional_piconero: u128,
    pub net_notional_piconero: i128,
    pub fee_charged_piconero: u128,
    pub protocol_fee_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "contracts": self.contracts,
            "active_contracts": self.active_contracts,
            "clearing_lots": self.clearing_lots,
            "live_lots": self.live_lots,
            "netted_lots": self.netted_lots,
            "settled_lots": self.settled_lots,
            "margin_notes": self.margin_notes,
            "locked_margin_notes": self.locked_margin_notes,
            "margin_reserved_piconero": self.margin_reserved_piconero.to_string(),
            "batch_count": self.batch_count,
            "live_batches": self.live_batches,
            "settled_batches": self.settled_batches,
            "pq_attestations": self.pq_attestations,
            "accepted_attestations": self.accepted_attestations,
            "quarantined_attestations": self.quarantined_attestations,
            "rebate_accounts": self.rebate_accounts,
            "claimable_rebate_accounts": self.claimable_rebate_accounts,
            "rebate_accrued_piconero": self.rebate_accrued_piconero.to_string(),
            "rebate_claimed_piconero": self.rebate_claimed_piconero.to_string(),
            "liquidation_guards": self.liquidation_guards,
            "active_liquidation_guards": self.active_liquidation_guards,
            "operator_summaries": self.operator_summaries,
            "consumed_nullifiers": self.consumed_nullifiers,
            "events": self.events,
            "gross_notional_piconero": self.gross_notional_piconero.to_string(),
            "net_notional_piconero": self.net_notional_piconero.to_string(),
            "fee_charged_piconero": self.fee_charged_piconero.to_string(),
            "protocol_fee_piconero": self.protocol_fee_piconero.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub contracts_root: String,
    pub clearing_lots_root: String,
    pub margin_notes_root: String,
    pub batch_netting_root: String,
    pub pq_attestations_root: String,
    pub rebate_ledgers_root: String,
    pub liquidation_guards_root: String,
    pub operator_summaries_root: String,
    pub nullifiers_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "contracts_root": self.contracts_root,
            "clearing_lots_root": self.clearing_lots_root,
            "margin_notes_root": self.margin_notes_root,
            "batch_netting_root": self.batch_netting_root,
            "pq_attestations_root": self.pq_attestations_root,
            "rebate_ledgers_root": self.rebate_ledgers_root,
            "liquidation_guards_root": self.liquidation_guards_root,
            "operator_summaries_root": self.operator_summaries_root,
            "nullifiers_root": self.nullifiers_root,
            "events_root": self.events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeFutureContract {
    pub contract_id: String,
    pub index_kind: FeeIndexKind,
    pub status: ContractStatus,
    pub oracle_feed_id: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub base_fee_quote_piconero: u64,
    pub tick_size_piconero: u64,
    pub lot_size_units: u64,
    pub max_open_interest_units: u64,
    pub open_interest_units: u64,
    pub maturity_height: u64,
    pub settlement_height: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub rebate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_margin_bps: u64,
    pub max_account_notional_piconero: u128,
    pub max_contract_notional_piconero: u128,
    pub privacy_set_size: u64,
    pub encrypted_terms_root: String,
    pub pq_listing_attestation_root: String,
    pub created_height: u64,
}

impl FeeFutureContract {
    pub fn notional_for_units(&self, units: u64) -> u128 {
        self.base_fee_quote_piconero as u128 * self.lot_size_units as u128 * units as u128
    }

    pub fn margin_required(&self, units: u64) -> u128 {
        bps_amount(self.notional_for_units(units), self.initial_margin_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "index_kind": self.index_kind.as_str(),
            "status": self.status.as_str(),
            "oracle_feed_id": self.oracle_feed_id,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "base_fee_quote_piconero": self.base_fee_quote_piconero,
            "tick_size_piconero": self.tick_size_piconero,
            "lot_size_units": self.lot_size_units,
            "max_open_interest_units": self.max_open_interest_units,
            "open_interest_units": self.open_interest_units,
            "maturity_height": self.maturity_height,
            "settlement_height": self.settlement_height,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "rebate_bps": self.rebate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_margin_bps": self.liquidation_margin_bps,
            "max_account_notional_piconero": self.max_account_notional_piconero.to_string(),
            "max_contract_notional_piconero": self.max_contract_notional_piconero.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "encrypted_terms_root": self.encrypted_terms_root,
            "pq_listing_attestation_root": self.pq_listing_attestation_root,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingLot {
    pub lot_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub side: LotSide,
    pub status: LotStatus,
    pub units: u64,
    pub limit_fee_piconero: u64,
    pub execution_fee_piconero: u64,
    pub notional_piconero: u128,
    pub margin_note_id: String,
    pub batch_id: Option<String>,
    pub rebate_account_id: String,
    pub nullifier: String,
    pub encrypted_lot_root: String,
    pub witness_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl ClearingLot {
    pub fn signed_notional(&self) -> i128 {
        self.side.sign() * self.notional_piconero as i128
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "contract_id": self.contract_id,
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "side": self.side.as_str(),
            "status": self.status.public_label(),
            "units": self.units,
            "limit_fee_piconero": self.limit_fee_piconero,
            "execution_fee_piconero": self.execution_fee_piconero,
            "notional_piconero": self.notional_piconero.to_string(),
            "margin_note_id": self.margin_note_id,
            "batch_id": self.batch_id,
            "rebate_account_id": self.rebate_account_id,
            "nullifier": self.nullifier,
            "encrypted_lot_root": self.encrypted_lot_root,
            "witness_root": self.witness_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub lot_id: Option<String>,
    pub status: MarginNoteStatus,
    pub collateral_asset_id: String,
    pub locked_amount_piconero: u128,
    pub reserved_amount_piconero: u128,
    pub maintenance_amount_piconero: u128,
    pub liquidation_threshold_piconero: u128,
    pub confidential_balance_root: String,
    pub range_proof_root: String,
    pub key_image_commitment: String,
    pub nullifier: String,
    pub created_height: u64,
    pub unlock_height: u64,
}

impl MarginNote {
    pub fn surplus_margin(&self) -> u128 {
        self.locked_amount_piconero
            .saturating_sub(self.reserved_amount_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "lot_id": self.lot_id,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
            "collateral_asset_id": self.collateral_asset_id,
            "locked_amount_piconero": self.locked_amount_piconero.to_string(),
            "reserved_amount_piconero": self.reserved_amount_piconero.to_string(),
            "maintenance_amount_piconero": self.maintenance_amount_piconero.to_string(),
            "liquidation_threshold_piconero": self.liquidation_threshold_piconero.to_string(),
            "confidential_balance_root": self.confidential_balance_root,
            "range_proof_root": self.range_proof_root,
            "key_image_commitment": self.key_image_commitment,
            "nullifier": self.nullifier,
            "created_height": self.created_height,
            "unlock_height": self.unlock_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchNettingRecord {
    pub batch_id: String,
    pub contract_id: String,
    pub status: NettingBatchStatus,
    pub lot_ids: Vec<String>,
    pub long_units: u64,
    pub short_units: u64,
    pub net_units: i128,
    pub gross_notional_piconero: u128,
    pub net_notional_piconero: i128,
    pub fee_charged_piconero: u128,
    pub protocol_fee_piconero: u128,
    pub maker_rebate_piconero: u128,
    pub privacy_set_size: u64,
    pub low_fee_score: u64,
    pub netting_root: String,
    pub settlement_root: String,
    pub pq_attestation_id: Option<String>,
    pub opened_height: u64,
    pub closed_height: Option<u64>,
}

impl BatchNettingRecord {
    pub fn compression_ratio_bps(&self) -> u64 {
        if self.gross_notional_piconero == 0 {
            return 0;
        }
        let net = self.net_notional_piconero.unsigned_abs();
        let saved = self.gross_notional_piconero.saturating_sub(net);
        ((saved.saturating_mul(MAX_BPS as u128)) / self.gross_notional_piconero) as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "contract_id": self.contract_id,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
            "lot_ids": self.lot_ids,
            "long_units": self.long_units,
            "short_units": self.short_units,
            "net_units": self.net_units.to_string(),
            "gross_notional_piconero": self.gross_notional_piconero.to_string(),
            "net_notional_piconero": self.net_notional_piconero.to_string(),
            "fee_charged_piconero": self.fee_charged_piconero.to_string(),
            "protocol_fee_piconero": self.protocol_fee_piconero.to_string(),
            "maker_rebate_piconero": self.maker_rebate_piconero.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "low_fee_score": self.low_fee_score,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "netting_root": self.netting_root,
            "settlement_root": self.settlement_root,
            "pq_attestation_id": self.pq_attestation_id,
            "opened_height": self.opened_height,
            "closed_height": self.closed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSettlementAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub contract_id: String,
    pub status: AttestationStatus,
    pub attestor_committee_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_fallback_root: String,
    pub ml_kem_transcript_root: String,
    pub settlement_statement_root: String,
    pub netting_root: String,
    pub oracle_mark_piconero: u64,
    pub oracle_height: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PqSettlementAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "contract_id": self.contract_id,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
            "attestor_committee_root": self.attestor_committee_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_fallback_root": self.slh_dsa_fallback_root,
            "ml_kem_transcript_root": self.ml_kem_transcript_root,
            "settlement_statement_root": self.settlement_statement_root,
            "netting_root": self.netting_root,
            "oracle_mark_piconero": self.oracle_mark_piconero,
            "oracle_height": self.oracle_height,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateLedger {
    pub rebate_account_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub status: RebateStatus,
    pub accrued_piconero: u128,
    pub claimable_piconero: u128,
    pub claimed_piconero: u128,
    pub batch_ids: Vec<String>,
    pub claim_note_root: String,
    pub privacy_set_size: u64,
    pub last_accrual_height: u64,
    pub claim_deadline_height: u64,
}

impl RebateLedger {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_account_id": self.rebate_account_id,
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
            "accrued_piconero": self.accrued_piconero.to_string(),
            "claimable_piconero": self.claimable_piconero.to_string(),
            "claimed_piconero": self.claimed_piconero.to_string(),
            "batch_ids": self.batch_ids,
            "claim_note_root": self.claim_note_root,
            "privacy_set_size": self.privacy_set_size,
            "last_accrual_height": self.last_accrual_height,
            "claim_deadline_height": self.claim_deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationGuard {
    pub guard_id: String,
    pub contract_id: String,
    pub lot_id: String,
    pub margin_note_id: String,
    pub status: GuardStatus,
    pub account_commitment: String,
    pub observed_margin_piconero: u128,
    pub maintenance_margin_piconero: u128,
    pub liquidation_threshold_piconero: u128,
    pub backstop_commitment: String,
    pub guard_root: String,
    pub raised_height: u64,
    pub grace_ends_height: u64,
}

impl LiquidationGuard {
    pub fn deficit_piconero(&self) -> u128 {
        self.maintenance_margin_piconero
            .saturating_sub(self.observed_margin_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "contract_id": self.contract_id,
            "lot_id": self.lot_id,
            "margin_note_id": self.margin_note_id,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
            "account_commitment": self.account_commitment,
            "observed_margin_piconero": self.observed_margin_piconero.to_string(),
            "maintenance_margin_piconero": self.maintenance_margin_piconero.to_string(),
            "liquidation_threshold_piconero": self.liquidation_threshold_piconero.to_string(),
            "backstop_commitment": self.backstop_commitment,
            "guard_root": self.guard_root,
            "raised_height": self.raised_height,
            "grace_ends_height": self.grace_ends_height,
            "deficit_piconero": self.deficit_piconero().to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub height: u64,
    pub operator_commitment: String,
    pub active_contracts: u64,
    pub open_batches: u64,
    pub settled_batches: u64,
    pub gross_notional_piconero: u128,
    pub net_notional_piconero: i128,
    pub fee_charged_piconero: u128,
    pub rebate_accrued_piconero: u128,
    pub liquidation_guards: u64,
    pub privacy_set_floor: u64,
    pub pq_security_floor: u16,
    pub roots_root: String,
    pub state_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "height": self.height,
            "operator_commitment": self.operator_commitment,
            "active_contracts": self.active_contracts,
            "open_batches": self.open_batches,
            "settled_batches": self.settled_batches,
            "gross_notional_piconero": self.gross_notional_piconero.to_string(),
            "net_notional_piconero": self.net_notional_piconero.to_string(),
            "fee_charged_piconero": self.fee_charged_piconero.to_string(),
            "rebate_accrued_piconero": self.rebate_accrued_piconero.to_string(),
            "liquidation_guards": self.liquidation_guards,
            "privacy_set_floor": self.privacy_set_floor,
            "pq_security_floor": self.pq_security_floor,
            "roots_root": self.roots_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub height: u64,
    pub subject_id: String,
    pub public_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "height": self.height,
            "subject_id": self.subject_id,
            "public_root": self.public_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateContractRequest {
    pub contract_id: String,
    pub index_kind: FeeIndexKind,
    pub oracle_feed_id: String,
    pub base_fee_quote_piconero: u64,
    pub tick_size_piconero: u64,
    pub lot_size_units: u64,
    pub max_open_interest_units: u64,
    pub maturity_height: u64,
    pub settlement_height: u64,
    pub encrypted_terms_root: String,
    pub pq_listing_attestation_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LockMarginNoteRequest {
    pub note_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub locked_amount_piconero: u128,
    pub confidential_balance_root: String,
    pub range_proof_root: String,
    pub key_image_commitment: String,
    pub nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitLotRequest {
    pub lot_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub side: LotSide,
    pub units: u64,
    pub limit_fee_piconero: u64,
    pub margin_note_id: String,
    pub rebate_account_id: String,
    pub nullifier: String,
    pub encrypted_lot_root: String,
    pub witness_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenBatchRequest {
    pub batch_id: String,
    pub contract_id: String,
    pub lot_ids: Vec<String>,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitAttestationRequest {
    pub attestation_id: String,
    pub batch_id: String,
    pub attestor_committee_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_fallback_root: String,
    pub ml_kem_transcript_root: String,
    pub settlement_statement_root: String,
    pub oracle_mark_piconero: u64,
    pub oracle_height: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RaiseLiquidationGuardRequest {
    pub guard_id: String,
    pub lot_id: String,
    pub margin_note_id: String,
    pub observed_margin_piconero: u128,
    pub backstop_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishOperatorSummaryRequest {
    pub summary_id: String,
    pub operator_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub contracts: BTreeMap<String, FeeFutureContract>,
    pub clearing_lots: BTreeMap<String, ClearingLot>,
    pub margin_notes: BTreeMap<String, MarginNote>,
    pub batch_netting: BTreeMap<String, BatchNettingRecord>,
    pub pq_attestations: BTreeMap<String, PqSettlementAttestation>,
    pub rebate_ledgers: BTreeMap<String, RebateLedger>,
    pub liquidation_guards: BTreeMap<String, LiquidationGuard>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT)
    }
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            contracts: BTreeMap::new(),
            clearing_lots: BTreeMap::new(),
            margin_notes: BTreeMap::new(),
            batch_netting: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rebate_ledgers: BTreeMap::new(),
            liquidation_guards: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.refresh();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let contract = state.create_contract(CreateContractRequest {
            contract_id: "devnet-micro-fee-da-future-0001".to_string(),
            index_kind: FeeIndexKind::DataAvailability,
            oracle_feed_id: DEVNET_ORACLE_ID.to_string(),
            base_fee_quote_piconero: 11,
            tick_size_piconero: 1,
            lot_size_units: 1_000_000,
            max_open_interest_units: 20_000,
            maturity_height: DEVNET_HEIGHT + 240,
            settlement_height: DEVNET_HEIGHT + 264,
            encrypted_terms_root: "devnet-encrypted-terms-root-da".to_string(),
            pq_listing_attestation_root: "devnet-pq-listing-root-da".to_string(),
        });
        let _ = contract;
        let _ = state.lock_margin_note(LockMarginNoteRequest {
            note_id: "devnet-margin-note-a".to_string(),
            owner_commitment: "owner-commitment-devnet-a".to_string(),
            contract_id: "devnet-micro-fee-da-future-0001".to_string(),
            locked_amount_piconero: 10_000_000_000,
            confidential_balance_root: "confidential-balance-root-a".to_string(),
            range_proof_root: "range-proof-root-a".to_string(),
            key_image_commitment: "key-image-commitment-a".to_string(),
            nullifier: "margin-nullifier-a".to_string(),
        });
        let _ = state.lock_margin_note(LockMarginNoteRequest {
            note_id: "devnet-margin-note-b".to_string(),
            owner_commitment: "owner-commitment-devnet-b".to_string(),
            contract_id: "devnet-micro-fee-da-future-0001".to_string(),
            locked_amount_piconero: 9_000_000_000,
            confidential_balance_root: "confidential-balance-root-b".to_string(),
            range_proof_root: "range-proof-root-b".to_string(),
            key_image_commitment: "key-image-commitment-b".to_string(),
            nullifier: "margin-nullifier-b".to_string(),
        });
        let _ = state.commit_lot(CommitLotRequest {
            lot_id: "devnet-lot-long-a".to_string(),
            contract_id: "devnet-micro-fee-da-future-0001".to_string(),
            owner_commitment: "owner-commitment-devnet-a".to_string(),
            account_commitment: "account-commitment-devnet-a".to_string(),
            side: LotSide::LongFee,
            units: 80,
            limit_fee_piconero: 12,
            margin_note_id: "devnet-margin-note-a".to_string(),
            rebate_account_id: "rebate-devnet-a".to_string(),
            nullifier: "lot-nullifier-a".to_string(),
            encrypted_lot_root: "encrypted-lot-root-a".to_string(),
            witness_root: "witness-root-a".to_string(),
        });
        let _ = state.commit_lot(CommitLotRequest {
            lot_id: "devnet-lot-short-b".to_string(),
            contract_id: "devnet-micro-fee-da-future-0001".to_string(),
            owner_commitment: "owner-commitment-devnet-b".to_string(),
            account_commitment: "account-commitment-devnet-b".to_string(),
            side: LotSide::ShortFee,
            units: 76,
            limit_fee_piconero: 10,
            margin_note_id: "devnet-margin-note-b".to_string(),
            rebate_account_id: "rebate-devnet-b".to_string(),
            nullifier: "lot-nullifier-b".to_string(),
            encrypted_lot_root: "encrypted-lot-root-b".to_string(),
            witness_root: "witness-root-b".to_string(),
        });
        let _ = state.open_batch(OpenBatchRequest {
            batch_id: "devnet-batch-da-0001".to_string(),
            contract_id: "devnet-micro-fee-da-future-0001".to_string(),
            lot_ids: vec![
                "devnet-lot-long-a".to_string(),
                "devnet-lot-short-b".to_string(),
            ],
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        });
        let _ = state.submit_attestation(SubmitAttestationRequest {
            attestation_id: "devnet-pq-attestation-da-0001".to_string(),
            batch_id: "devnet-batch-da-0001".to_string(),
            attestor_committee_root: "committee-root-devnet-a".to_string(),
            ml_dsa_signature_root: "ml-dsa-signature-root-devnet-a".to_string(),
            slh_dsa_fallback_root: "slh-dsa-fallback-root-devnet-a".to_string(),
            ml_kem_transcript_root: "ml-kem-transcript-root-devnet-a".to_string(),
            settlement_statement_root: "settlement-statement-root-devnet-a".to_string(),
            oracle_mark_piconero: 10,
            oracle_height: DEVNET_HEIGHT + 1,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        });
        let _ = state.settle_batch("devnet-batch-da-0001");
        let _ = state.publish_operator_summary(PublishOperatorSummaryRequest {
            summary_id: "devnet-operator-summary-0001".to_string(),
            operator_commitment: "operator-commitment-devnet".to_string(),
        });
        state.refresh();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.height += 12;
        let _ = state.create_contract(CreateContractRequest {
            contract_id: "demo-micro-fee-prover-future-0002".to_string(),
            index_kind: FeeIndexKind::ProverTime,
            oracle_feed_id: "demo-confidential-prover-fee-oracle".to_string(),
            base_fee_quote_piconero: 19,
            tick_size_piconero: 1,
            lot_size_units: 250_000,
            max_open_interest_units: 50_000,
            maturity_height: state.height + 360,
            settlement_height: state.height + 384,
            encrypted_terms_root: "demo-encrypted-terms-root-prover".to_string(),
            pq_listing_attestation_root: "demo-pq-listing-root-prover".to_string(),
        });
        state.refresh();
        state
    }

    pub fn create_contract(&mut self, request: CreateContractRequest) -> Result<FeeFutureContract> {
        self.ensure_id("contract_id", &request.contract_id)?;
        self.ensure_capacity(self.contracts.len(), self.config.max_contracts, "contracts")?;
        if self.contracts.contains_key(&request.contract_id) {
            return Err(format!("contract already exists: {}", request.contract_id));
        }
        self.ensure_id("oracle_feed_id", &request.oracle_feed_id)?;
        self.ensure_nonzero("base_fee_quote_piconero", request.base_fee_quote_piconero)?;
        self.ensure_nonzero("tick_size_piconero", request.tick_size_piconero)?;
        self.ensure_nonzero("lot_size_units", request.lot_size_units)?;
        if request.maturity_height <= self.height {
            return Err("maturity height must be in the future".to_string());
        }
        if request.settlement_height < request.maturity_height {
            return Err("settlement height must not precede maturity".to_string());
        }
        let contract = FeeFutureContract {
            contract_id: request.contract_id,
            index_kind: request.index_kind,
            status: ContractStatus::Trading,
            oracle_feed_id: request.oracle_feed_id,
            fee_asset_id: self.config.fee_asset_id.clone(),
            collateral_asset_id: self.config.collateral_asset_id.clone(),
            base_fee_quote_piconero: request.base_fee_quote_piconero,
            tick_size_piconero: request.tick_size_piconero,
            lot_size_units: request.lot_size_units,
            max_open_interest_units: request.max_open_interest_units,
            open_interest_units: 0,
            maturity_height: request.maturity_height,
            settlement_height: request.settlement_height,
            maker_fee_bps: self.config.maker_fee_bps,
            taker_fee_bps: self.config.taker_fee_bps,
            rebate_bps: self.config.rebate_bps,
            initial_margin_bps: self.config.initial_margin_bps,
            maintenance_margin_bps: self.config.maintenance_margin_bps,
            liquidation_margin_bps: self.config.liquidation_margin_bps,
            max_account_notional_piconero: self.config.max_account_notional_piconero,
            max_contract_notional_piconero: self.config.max_contract_notional_piconero,
            privacy_set_size: self.config.min_privacy_set_size,
            encrypted_terms_root: request.encrypted_terms_root,
            pq_listing_attestation_root: request.pq_listing_attestation_root,
            created_height: self.height,
        };
        let contract_id = contract.contract_id.clone();
        self.contracts.insert(contract_id.clone(), contract.clone());
        self.push_event(
            EventKind::ContractListed,
            &contract_id,
            &contract.public_record(),
        );
        self.refresh();
        Ok(contract)
    }

    pub fn lock_margin_note(&mut self, request: LockMarginNoteRequest) -> Result<MarginNote> {
        self.ensure_id("note_id", &request.note_id)?;
        self.ensure_capacity(
            self.margin_notes.len(),
            self.config.max_margin_notes,
            "margin notes",
        )?;
        if self.margin_notes.contains_key(&request.note_id) {
            return Err(format!("margin note already exists: {}", request.note_id));
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err(format!("nullifier already consumed: {}", request.nullifier));
        }
        let contract = self.contract(&request.contract_id)?;
        let maintenance = bps_amount(
            request.locked_amount_piconero,
            contract.maintenance_margin_bps,
        );
        let liquidation = bps_amount(
            request.locked_amount_piconero,
            contract.liquidation_margin_bps,
        );
        let note = MarginNote {
            note_id: request.note_id,
            owner_commitment: request.owner_commitment,
            contract_id: request.contract_id,
            lot_id: None,
            status: MarginNoteStatus::Locked,
            collateral_asset_id: self.config.collateral_asset_id.clone(),
            locked_amount_piconero: request.locked_amount_piconero,
            reserved_amount_piconero: 0,
            maintenance_amount_piconero: maintenance,
            liquidation_threshold_piconero: liquidation,
            confidential_balance_root: request.confidential_balance_root,
            range_proof_root: request.range_proof_root,
            key_image_commitment: request.key_image_commitment,
            nullifier: request.nullifier,
            created_height: self.height,
            unlock_height: self.height + self.config.clearing_window_blocks,
        };
        self.consumed_nullifiers.insert(note.nullifier.clone());
        self.margin_notes.insert(note.note_id.clone(), note.clone());
        self.push_event(
            EventKind::MarginNoteLocked,
            &note.note_id,
            &note.public_record(),
        );
        self.refresh();
        Ok(note)
    }

    pub fn commit_lot(&mut self, request: CommitLotRequest) -> Result<ClearingLot> {
        self.ensure_id("lot_id", &request.lot_id)?;
        self.ensure_capacity(
            self.clearing_lots.len(),
            self.config.max_clearing_lots,
            "clearing lots",
        )?;
        if self.clearing_lots.contains_key(&request.lot_id) {
            return Err(format!("lot already exists: {}", request.lot_id));
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err(format!("nullifier already consumed: {}", request.nullifier));
        }
        let contract = self.contract(&request.contract_id)?.clone();
        if !contract.status.accepts_new_lots() {
            return Err(format!(
                "contract does not accept new lots: {}",
                contract.contract_id
            ));
        }
        if contract.open_interest_units.saturating_add(request.units)
            > contract.max_open_interest_units
        {
            return Err("contract open interest limit exceeded".to_string());
        }
        let required_margin = contract.margin_required(request.units);
        {
            let note = self
                .margin_notes
                .get_mut(&request.margin_note_id)
                .ok_or_else(|| format!("unknown margin note: {}", request.margin_note_id))?;
            if note.contract_id != request.contract_id {
                return Err("margin note contract mismatch".to_string());
            }
            if !note.status.spendable() || note.surplus_margin() < required_margin {
                return Err("insufficient spendable margin".to_string());
            }
            note.status = MarginNoteStatus::Reserved;
            note.reserved_amount_piconero = note
                .reserved_amount_piconero
                .saturating_add(required_margin);
            note.lot_id = Some(request.lot_id.clone());
        }
        let notional = contract.notional_for_units(request.units);
        let fee = bps_amount(notional, self.fee_bps_for_side(request.side));
        let lot = ClearingLot {
            lot_id: request.lot_id,
            contract_id: request.contract_id,
            owner_commitment: request.owner_commitment,
            account_commitment: request.account_commitment,
            side: request.side,
            status: LotStatus::MarginReserved,
            units: request.units,
            limit_fee_piconero: request.limit_fee_piconero,
            execution_fee_piconero: fee as u64,
            notional_piconero: notional,
            margin_note_id: request.margin_note_id,
            batch_id: None,
            rebate_account_id: request.rebate_account_id,
            nullifier: request.nullifier,
            encrypted_lot_root: request.encrypted_lot_root,
            witness_root: request.witness_root,
            created_height: self.height,
            expires_height: self.height + self.config.clearing_window_blocks,
        };
        self.contracts
            .get_mut(&lot.contract_id)
            .expect("contract checked")
            .open_interest_units += lot.units;
        self.consumed_nullifiers.insert(lot.nullifier.clone());
        self.clearing_lots.insert(lot.lot_id.clone(), lot.clone());
        self.ensure_rebate_account(&lot);
        self.push_event(EventKind::LotCommitted, &lot.lot_id, &lot.public_record());
        self.refresh();
        Ok(lot)
    }

    pub fn open_batch(&mut self, request: OpenBatchRequest) -> Result<BatchNettingRecord> {
        self.ensure_id("batch_id", &request.batch_id)?;
        self.ensure_capacity(
            self.batch_netting.len(),
            self.config.max_batches,
            "netting batches",
        )?;
        if self.batch_netting.contains_key(&request.batch_id) {
            return Err(format!("batch already exists: {}", request.batch_id));
        }
        if request.lot_ids.is_empty() {
            return Err("batch requires at least one lot".to_string());
        }
        if request.lot_ids.len() > self.config.max_batch_lots {
            return Err("batch lot limit exceeded".to_string());
        }
        if request.privacy_set_size < self.config.batch_privacy_set_size {
            return Err("batch privacy set below configured floor".to_string());
        }
        let contract_id = request.contract_id.clone();
        let mut long_units = 0_u64;
        let mut short_units = 0_u64;
        let mut gross = 0_u128;
        let mut net = 0_i128;
        let mut fee = 0_u128;
        let mut rebate = 0_u128;
        for lot_id in &request.lot_ids {
            let lot = self
                .clearing_lots
                .get(lot_id)
                .ok_or_else(|| format!("unknown clearing lot: {lot_id}"))?;
            if lot.contract_id != contract_id {
                return Err(format!("lot contract mismatch: {lot_id}"));
            }
            if !lot.status.live() {
                return Err(format!("lot is not live: {lot_id}"));
            }
            match lot.side {
                LotSide::LongFee | LotSide::MakerHedge | LotSide::LiquidationBackstop => {
                    long_units = long_units.saturating_add(lot.units)
                }
                LotSide::ShortFee | LotSide::TakerHedge => {
                    short_units = short_units.saturating_add(lot.units)
                }
            }
            gross = gross.saturating_add(lot.notional_piconero);
            net = net.saturating_add(lot.signed_notional());
            fee = fee.saturating_add(lot.execution_fee_piconero as u128);
            rebate =
                rebate.saturating_add(bps_amount(lot.notional_piconero, self.config.rebate_bps));
        }
        if gross > self.config.max_batch_notional_piconero {
            return Err("batch notional exceeds configured cap".to_string());
        }
        let protocol_fee = bps_amount(gross, self.config.protocol_fee_bps);
        let leaf = json!({
            "batch_id": request.batch_id,
            "contract_id": contract_id,
            "lot_ids": request.lot_ids,
            "gross": gross.to_string(),
            "net": net.to_string(),
            "privacy_set_size": request.privacy_set_size,
        });
        let netting_root = root_from_record("BATCH-NETTING", &leaf);
        let settlement_root = root_from_record("BATCH-SETTLEMENT", &leaf);
        let batch = BatchNettingRecord {
            batch_id: leaf["batch_id"].as_str().unwrap_or_default().to_string(),
            contract_id,
            status: NettingBatchStatus::AttestationPending,
            lot_ids: request.lot_ids,
            long_units,
            short_units,
            net_units: long_units as i128 - short_units as i128,
            gross_notional_piconero: gross,
            net_notional_piconero: net,
            fee_charged_piconero: fee,
            protocol_fee_piconero: protocol_fee,
            maker_rebate_piconero: rebate,
            privacy_set_size: request.privacy_set_size,
            low_fee_score: low_fee_score(gross, net, fee, rebate),
            netting_root,
            settlement_root,
            pq_attestation_id: None,
            opened_height: self.height,
            closed_height: None,
        };
        for lot_id in &batch.lot_ids {
            if let Some(lot) = self.clearing_lots.get_mut(lot_id) {
                lot.status = LotStatus::BatchQueued;
                lot.batch_id = Some(batch.batch_id.clone());
            }
        }
        self.batch_netting
            .insert(batch.batch_id.clone(), batch.clone());
        self.push_event(
            EventKind::BatchOpened,
            &batch.batch_id,
            &batch.public_record(),
        );
        self.refresh();
        Ok(batch)
    }

    pub fn submit_attestation(
        &mut self,
        request: SubmitAttestationRequest,
    ) -> Result<PqSettlementAttestation> {
        self.ensure_id("attestation_id", &request.attestation_id)?;
        self.ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_attestations,
            "pq attestations",
        )?;
        if self.pq_attestations.contains_key(&request.attestation_id) {
            return Err(format!(
                "attestation already exists: {}",
                request.attestation_id
            ));
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security bits below configured floor".to_string());
        }
        if request.privacy_set_size < self.config.batch_privacy_set_size {
            return Err("attestation privacy set below configured floor".to_string());
        }
        if self.height.saturating_sub(request.oracle_height)
            > self.config.max_oracle_staleness_blocks
        {
            return Err("oracle mark is stale".to_string());
        }
        let batch = self
            .batch_netting
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown batch: {}", request.batch_id))?;
        let attestation = PqSettlementAttestation {
            attestation_id: request.attestation_id,
            batch_id: request.batch_id,
            contract_id: batch.contract_id.clone(),
            status: AttestationStatus::Accepted,
            attestor_committee_root: request.attestor_committee_root,
            ml_dsa_signature_root: request.ml_dsa_signature_root,
            slh_dsa_fallback_root: request.slh_dsa_fallback_root,
            ml_kem_transcript_root: request.ml_kem_transcript_root,
            settlement_statement_root: request.settlement_statement_root,
            netting_root: batch.netting_root.clone(),
            oracle_mark_piconero: request.oracle_mark_piconero,
            oracle_height: request.oracle_height,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            submitted_height: self.height,
            expires_height: self.height + self.config.attestation_ttl_blocks,
        };
        batch.status = NettingBatchStatus::Attested;
        batch.pq_attestation_id = Some(attestation.attestation_id.clone());
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.push_event(
            EventKind::BatchAttested,
            &attestation.attestation_id,
            &attestation.public_record(),
        );
        self.refresh();
        Ok(attestation)
    }

    pub fn settle_batch(&mut self, batch_id: &str) -> Result<BatchNettingRecord> {
        let batch = self
            .batch_netting
            .get(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?
            .clone();
        if batch.status != NettingBatchStatus::Attested {
            return Err("batch must be attested before settlement".to_string());
        }
        let attestation_id = batch
            .pq_attestation_id
            .clone()
            .ok_or_else(|| "batch missing attestation".to_string())?;
        let attestation = self
            .pq_attestations
            .get(&attestation_id)
            .ok_or_else(|| format!("unknown attestation: {attestation_id}"))?;
        if !attestation.status.usable() {
            return Err("attestation is not usable".to_string());
        }
        for lot_id in &batch.lot_ids {
            if let Some(lot) = self.clearing_lots.get_mut(lot_id) {
                lot.status = LotStatus::Settled;
            }
        }
        for lot_id in &batch.lot_ids {
            let lot = self
                .clearing_lots
                .get(lot_id)
                .ok_or_else(|| format!("unknown clearing lot: {lot_id}"))?
                .clone();
            self.accrue_rebate(&lot, batch.batch_id.clone())?;
            if let Some(note) = self.margin_notes.get_mut(&lot.margin_note_id) {
                note.status = MarginNoteStatus::Released;
                note.reserved_amount_piconero = 0;
                note.unlock_height = self.height;
            }
        }
        let settled = self.batch_netting.get_mut(batch_id).expect("batch checked");
        settled.status = NettingBatchStatus::Settled;
        settled.closed_height = Some(self.height);
        let record = settled.clone();
        self.push_event(EventKind::BatchSettled, batch_id, &record.public_record());
        self.refresh();
        Ok(record)
    }

    pub fn raise_liquidation_guard(
        &mut self,
        request: RaiseLiquidationGuardRequest,
    ) -> Result<LiquidationGuard> {
        self.ensure_id("guard_id", &request.guard_id)?;
        self.ensure_capacity(
            self.liquidation_guards.len(),
            self.config.max_liquidation_guards,
            "liquidation guards",
        )?;
        let lot = self
            .clearing_lots
            .get(&request.lot_id)
            .ok_or_else(|| format!("unknown lot: {}", request.lot_id))?
            .clone();
        let note = self
            .margin_notes
            .get(&request.margin_note_id)
            .ok_or_else(|| format!("unknown margin note: {}", request.margin_note_id))?
            .clone();
        let contract = self.contract(&lot.contract_id)?.clone();
        let maintenance = bps_amount(lot.notional_piconero, contract.maintenance_margin_bps);
        let liquidation = bps_amount(lot.notional_piconero, contract.liquidation_margin_bps);
        if request.observed_margin_piconero >= maintenance {
            return Err("observed margin is above maintenance requirement".to_string());
        }
        let guard_root = root_from_record(
            "LIQUIDATION-GUARD",
            &json!({
                "guard_id": request.guard_id,
                "lot_id": lot.lot_id,
                "note_id": note.note_id,
                "observed_margin_piconero": request.observed_margin_piconero.to_string(),
                "maintenance_margin_piconero": maintenance.to_string(),
            }),
        );
        let guard = LiquidationGuard {
            guard_id: request.guard_id,
            contract_id: lot.contract_id.clone(),
            lot_id: lot.lot_id.clone(),
            margin_note_id: note.note_id,
            status: GuardStatus::GracePeriod,
            account_commitment: lot.account_commitment.clone(),
            observed_margin_piconero: request.observed_margin_piconero,
            maintenance_margin_piconero: maintenance,
            liquidation_threshold_piconero: liquidation,
            backstop_commitment: request.backstop_commitment,
            guard_root,
            raised_height: self.height,
            grace_ends_height: self.height + self.config.liquidation_grace_blocks,
        };
        if let Some(lot) = self.clearing_lots.get_mut(&guard.lot_id) {
            lot.status = LotStatus::LiquidationGuarded;
        }
        if let Some(note) = self.margin_notes.get_mut(&guard.margin_note_id) {
            note.status = MarginNoteStatus::LiquidationEscrow;
        }
        self.liquidation_guards
            .insert(guard.guard_id.clone(), guard.clone());
        self.push_event(
            EventKind::LiquidationGuardRaised,
            &guard.guard_id,
            &guard.public_record(),
        );
        self.refresh();
        Ok(guard)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: PublishOperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        self.ensure_id("summary_id", &request.summary_id)?;
        self.ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator summaries",
        )?;
        self.refresh();
        let roots_root = root_from_record("ROOTS", &self.roots.public_record());
        let summary = OperatorSummary {
            summary_id: request.summary_id,
            height: self.height,
            operator_commitment: request.operator_commitment,
            active_contracts: self.counters.active_contracts,
            open_batches: self.counters.live_batches,
            settled_batches: self.counters.settled_batches,
            gross_notional_piconero: self.counters.gross_notional_piconero,
            net_notional_piconero: self.counters.net_notional_piconero,
            fee_charged_piconero: self.counters.fee_charged_piconero,
            rebate_accrued_piconero: self.counters.rebate_accrued_piconero,
            liquidation_guards: self.counters.active_liquidation_guards,
            privacy_set_floor: self.config.min_privacy_set_size,
            pq_security_floor: self.config.min_pq_security_bits,
            roots_root,
            state_root: self.state_root(),
        };
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary.clone());
        self.push_event(
            EventKind::OperatorSummaryPublished,
            &summary.summary_id,
            &summary.public_record(),
        );
        self.refresh();
        Ok(summary)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "clearing_house_id": self.config.clearing_house_id,
            "oracle_id": self.config.oracle_id,
            "fee_asset_id": self.config.fee_asset_id,
            "collateral_asset_id": self.config.collateral_asset_id,
            "hash_suite": self.config.hash_suite,
            "pq_attestation_suite": self.config.pq_attestation_suite,
            "config_root": self.roots.config_root,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "contracts": self.contracts.len(),
            "clearing_lots": self.clearing_lots.len(),
            "margin_notes": self.margin_notes.len(),
            "batch_netting": self.batch_netting.len(),
            "pq_attestations": self.pq_attestations.len(),
            "rebate_ledgers": self.rebate_ledgers.len(),
            "liquidation_guards": self.liquidation_guards.len(),
            "operator_summaries": self.operator_summaries.len(),
            "public_risk": self.public_risk_snapshot(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MICRO-FEE-FUTURES-CLEARING:STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.contracts_root),
                HashPart::Str(&self.roots.clearing_lots_root),
                HashPart::Str(&self.roots.margin_notes_root),
                HashPart::Str(&self.roots.batch_netting_root),
                HashPart::Str(&self.roots.pq_attestations_root),
                HashPart::Str(&self.roots.rebate_ledgers_root),
                HashPart::Str(&self.roots.liquidation_guards_root),
                HashPart::Str(&self.roots.operator_summaries_root),
                HashPart::Str(&self.roots.nullifiers_root),
                HashPart::Str(&self.roots.events_root),
            ],
            32,
        )
    }

    pub fn roots(&self) -> Roots {
        let mut clone = self.clone();
        clone.refresh();
        clone.roots
    }

    pub fn refresh(&mut self) {
        self.recompute_counters();
        self.roots.config_root = root_from_record("CONFIG", &self.config.public_record());
        self.roots.counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        self.roots.contracts_root = map_root("contracts", &self.contracts);
        self.roots.clearing_lots_root = map_root("clearing_lots", &self.clearing_lots);
        self.roots.margin_notes_root = map_root("margin_notes", &self.margin_notes);
        self.roots.batch_netting_root = map_root("batch_netting", &self.batch_netting);
        self.roots.pq_attestations_root = map_root("pq_attestations", &self.pq_attestations);
        self.roots.rebate_ledgers_root = map_root("rebate_ledgers", &self.rebate_ledgers);
        self.roots.liquidation_guards_root =
            map_root("liquidation_guards", &self.liquidation_guards);
        self.roots.operator_summaries_root =
            map_root("operator_summaries", &self.operator_summaries);
        self.roots.nullifiers_root = set_root("consumed_nullifiers", &self.consumed_nullifiers);
        self.roots.events_root = events_root(&self.events);
        self.roots.state_root = self.state_root();
    }

    fn recompute_counters(&mut self) {
        let mut counters = Counters::default();
        counters.contracts = self.contracts.len() as u64;
        counters.active_contracts = self
            .contracts
            .values()
            .filter(|contract| {
                contract.status.accepts_new_lots() || contract.status.allows_reduce()
            })
            .count() as u64;
        counters.clearing_lots = self.clearing_lots.len() as u64;
        counters.live_lots = self
            .clearing_lots
            .values()
            .filter(|lot| lot.status.live())
            .count() as u64;
        counters.netted_lots = self
            .clearing_lots
            .values()
            .filter(|lot| matches!(lot.status, LotStatus::Netted | LotStatus::Settled))
            .count() as u64;
        counters.settled_lots = self
            .clearing_lots
            .values()
            .filter(|lot| lot.status == LotStatus::Settled)
            .count() as u64;
        counters.margin_notes = self.margin_notes.len() as u64;
        counters.locked_margin_notes = self
            .margin_notes
            .values()
            .filter(|note| note.status.spendable())
            .count() as u64;
        counters.margin_reserved_piconero = self
            .margin_notes
            .values()
            .map(|note| note.reserved_amount_piconero)
            .sum();
        counters.batch_count = self.batch_netting.len() as u64;
        counters.live_batches = self
            .batch_netting
            .values()
            .filter(|batch| batch.status.counted_as_live())
            .count() as u64;
        counters.settled_batches = self
            .batch_netting
            .values()
            .filter(|batch| batch.status == NettingBatchStatus::Settled)
            .count() as u64;
        counters.pq_attestations = self.pq_attestations.len() as u64;
        counters.accepted_attestations = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.status == AttestationStatus::Accepted)
            .count() as u64;
        counters.quarantined_attestations = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.status == AttestationStatus::Quarantined)
            .count() as u64;
        counters.rebate_accounts = self.rebate_ledgers.len() as u64;
        counters.claimable_rebate_accounts = self
            .rebate_ledgers
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Claimable)
            .count() as u64;
        counters.rebate_accrued_piconero = self
            .rebate_ledgers
            .values()
            .map(|rebate| rebate.accrued_piconero)
            .sum();
        counters.rebate_claimed_piconero = self
            .rebate_ledgers
            .values()
            .map(|rebate| rebate.claimed_piconero)
            .sum();
        counters.liquidation_guards = self.liquidation_guards.len() as u64;
        counters.active_liquidation_guards = self
            .liquidation_guards
            .values()
            .filter(|guard| {
                matches!(
                    guard.status,
                    GuardStatus::Watching | GuardStatus::GracePeriod | GuardStatus::AuctionQueued
                )
            })
            .count() as u64;
        counters.operator_summaries = self.operator_summaries.len() as u64;
        counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        counters.events = self.events.len() as u64;
        counters.gross_notional_piconero = self
            .batch_netting
            .values()
            .map(|batch| batch.gross_notional_piconero)
            .sum();
        counters.net_notional_piconero = self
            .batch_netting
            .values()
            .map(|batch| batch.net_notional_piconero)
            .sum();
        counters.fee_charged_piconero = self
            .batch_netting
            .values()
            .map(|batch| batch.fee_charged_piconero)
            .sum();
        counters.protocol_fee_piconero = self
            .batch_netting
            .values()
            .map(|batch| batch.protocol_fee_piconero)
            .sum();
        self.counters = counters;
    }

    fn public_risk_snapshot(&self) -> Value {
        let open_interest_units: u64 = self
            .contracts
            .values()
            .map(|contract| contract.open_interest_units)
            .sum();
        let max_low_fee_bps = self
            .contracts
            .values()
            .map(|contract| contract.maker_fee_bps.max(contract.taker_fee_bps))
            .max()
            .unwrap_or_default();
        json!({
            "open_interest_units": open_interest_units,
            "max_low_fee_bps": max_low_fee_bps,
            "batch_compression_bps": self.weighted_batch_compression_bps(),
            "active_liquidation_guards": self.counters.active_liquidation_guards,
            "accepted_pq_attestations": self.counters.accepted_attestations,
            "privacy_set_floor": self.config.min_privacy_set_size,
            "batch_privacy_set_size": self.config.batch_privacy_set_size,
            "pq_security_floor": self.config.min_pq_security_bits,
        })
    }

    fn weighted_batch_compression_bps(&self) -> u64 {
        let gross: u128 = self
            .batch_netting
            .values()
            .map(|batch| batch.gross_notional_piconero)
            .sum();
        if gross == 0 {
            return 0;
        }
        let saved: u128 = self
            .batch_netting
            .values()
            .map(|batch| {
                batch
                    .gross_notional_piconero
                    .saturating_sub(batch.net_notional_piconero.unsigned_abs())
            })
            .sum();
        ((saved.saturating_mul(MAX_BPS as u128)) / gross) as u64
    }

    fn contract(&self, contract_id: &str) -> Result<&FeeFutureContract> {
        self.contracts
            .get(contract_id)
            .ok_or_else(|| format!("unknown contract: {contract_id}"))
    }

    fn fee_bps_for_side(&self, side: LotSide) -> u64 {
        match side {
            LotSide::MakerHedge | LotSide::LiquidationBackstop => self.config.maker_fee_bps,
            LotSide::LongFee | LotSide::ShortFee | LotSide::TakerHedge => self.config.taker_fee_bps,
        }
    }

    fn ensure_rebate_account(&mut self, lot: &ClearingLot) {
        self.rebate_ledgers
            .entry(lot.rebate_account_id.clone())
            .or_insert_with(|| RebateLedger {
                rebate_account_id: lot.rebate_account_id.clone(),
                owner_commitment: lot.owner_commitment.clone(),
                contract_id: lot.contract_id.clone(),
                status: RebateStatus::Accruing,
                accrued_piconero: 0,
                claimable_piconero: 0,
                claimed_piconero: 0,
                batch_ids: Vec::new(),
                claim_note_root: root_from_record(
                    "REBATE-CLAIM-NOTE",
                    &json!({
                        "rebate_account_id": lot.rebate_account_id,
                        "owner_commitment": lot.owner_commitment,
                    }),
                ),
                privacy_set_size: self.config.min_privacy_set_size,
                last_accrual_height: self.height,
                claim_deadline_height: self.height + self.config.rebate_claim_ttl_blocks,
            });
    }

    fn accrue_rebate(&mut self, lot: &ClearingLot, batch_id: String) -> Result<()> {
        let rebate = bps_amount(lot.notional_piconero, self.config.rebate_bps);
        let ledger = self
            .rebate_ledgers
            .get_mut(&lot.rebate_account_id)
            .ok_or_else(|| format!("missing rebate ledger: {}", lot.rebate_account_id))?;
        ledger.accrued_piconero = ledger.accrued_piconero.saturating_add(rebate);
        ledger.claimable_piconero = ledger.claimable_piconero.saturating_add(rebate);
        ledger.status = RebateStatus::Claimable;
        ledger.last_accrual_height = self.height;
        ledger.claim_deadline_height = self.height + self.config.rebate_claim_ttl_blocks;
        if !ledger.batch_ids.contains(&batch_id) {
            ledger.batch_ids.push(batch_id);
        }
        let record = ledger.public_record();
        let subject = ledger.rebate_account_id.clone();
        self.push_event(EventKind::RebateAccrued, &subject, &record);
        Ok(())
    }

    fn push_event(&mut self, kind: EventKind, subject_id: &str, record: &Value) {
        if self.events.len() >= self.config.max_events {
            return;
        }
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MICRO-FEE-FUTURES-CLEARING:EVENT-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Json(record),
            ],
            16,
        );
        self.events.push(RuntimeEvent {
            event_id,
            kind,
            height: self.height,
            subject_id: subject_id.to_string(),
            public_root: root_from_record("EVENT-PAYLOAD", record),
        });
    }

    fn ensure_id(&self, label: &str, value: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(format!("{label} must not be empty"));
        }
        Ok(())
    }

    fn ensure_nonzero(&self, label: &str, value: u64) -> Result<()> {
        if value == 0 {
            return Err(format!("{label} must be non-zero"));
        }
        Ok(())
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!("{label} capacity exhausted"));
        }
        Ok(())
    }
}

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

pub fn roots(state: &State) -> Roots {
    state.roots()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MICRO-FEE-FUTURES-CLEARING:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PUBLIC-RECORD", record)
}

pub fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn low_fee_score(gross: u128, net: i128, fee: u128, rebate: u128) -> u64 {
    if gross == 0 {
        return 0;
    }
    let compression = gross.saturating_sub(net.unsigned_abs());
    let compression_bps = compression.saturating_mul(MAX_BPS as u128) / gross;
    let fee_bps = fee.saturating_mul(MAX_BPS as u128) / gross;
    let rebate_bps = rebate.saturating_mul(MAX_BPS as u128) / gross;
    compression_bps
        .saturating_add(rebate_bps)
        .saturating_sub(fee_bps)
        .min(u64::MAX as u128) as u64
}

fn canonical_json<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization_error": true}))
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "value": canonical_json(value),
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn events_root(events: &[RuntimeEvent]) -> String {
    let leaves: Vec<Value> = events
        .iter()
        .map(|event| {
            json!({
                "event_id": event.event_id,
                "kind": event.kind.as_str(),
                "height": event.height,
                "subject_id": event.subject_id,
                "public_root": event.public_root,
            })
        })
        .collect();
    merkle_root("events", &leaves)
}
