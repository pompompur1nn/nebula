use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialCalldataRebateNettingVaultRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialCalldataRebateNettingVaultRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CALLDATA_REBATE_NETTING_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-calldata-rebate-netting-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CALLDATA_REBATE_NETTING_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTED_CALLDATA_FEE_ROOT_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-attested-calldata-fee-root-v1";
pub const CONFIDENTIAL_COMPRESSION_COUPON_SUITE: &str =
    "ML-KEM-1024-sealed-calldata-compression-coupon-netting-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "private-l2-low-fee-calldata-rebate-settlement-batch-v1";
pub const CONGESTION_BAND_SUITE: &str = "private-l2-calldata-congestion-band-netting-vault-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_calldata_payloads_coupon_plaintexts_wallet_addresses_view_keys_or_fee_witnesses";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-calldata-rebate-netting-vault-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "calldata-compression-rebate-coupon-devnet";
pub const DEVNET_HEIGHT: u64 = 5_410_000;
pub const DEVNET_EPOCH: u64 = 51_200;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_CALLDATA_FEE_MICRO_UNITS: u64 = 6_400;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_BASE_REBATE_BPS: u64 = 1_400;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 7_200;
pub const DEFAULT_MIN_COMPRESSION_BPS: u64 = 1_800;
pub const DEFAULT_TARGET_COMPRESSION_BPS: u64 = 7_000;
pub const DEFAULT_ATTESTED_ROOT_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_COUPON_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_NETTING_WINDOW_SLOTS: u64 = 288;
pub const DEFAULT_SETTLEMENT_FINALITY_SLOTS: u64 = 36;
pub const DEFAULT_MAX_CALLDATA_BYTES_PER_BATCH: u64 = 12 * 1_048_576;
pub const DEFAULT_MAX_COUPONS_PER_NETTING: usize = 65_536;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:ROOTS";
const D_VAULTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:VAULTS";
const D_FEE_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:FEE-ROOTS";
const D_COUPONS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:COUPONS";
const D_BANDS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:BANDS";
const D_BATCHES: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:BATCHES";
const D_SETTLEMENTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:EVENTS";
const D_PUBLIC: &str = "PL2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:PUBLIC";

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataLane {
    WalletTransfer,
    ConfidentialContractCall,
    BridgeDeposit,
    BridgeExit,
    DexIntent,
    PaymasterSponsoredCall,
    OracleUpdate,
    StateWitnessRefresh,
    EmergencyCancel,
}

impl CalldataLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeExit => "bridge_exit",
            Self::DexIntent => "dex_intent",
            Self::PaymasterSponsoredCall => "paymaster_sponsored_call",
            Self::OracleUpdate => "oracle_update",
            Self::StateWitnessRefresh => "state_witness_refresh",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::BridgeExit => 9_600,
            Self::BridgeDeposit => 9_200,
            Self::ConfidentialContractCall => 8_800,
            Self::DexIntent => 8_300,
            Self::PaymasterSponsoredCall => 7_800,
            Self::WalletTransfer => 7_200,
            Self::OracleUpdate => 6_600,
            Self::StateWitnessRefresh => 6_000,
        }
    }

    pub fn compression_floor_bps(self) -> u64 {
        match self {
            Self::EmergencyCancel => 1_500,
            Self::BridgeExit => 2_600,
            Self::BridgeDeposit => 3_200,
            Self::ConfidentialContractCall => 4_800,
            Self::DexIntent => 4_200,
            Self::PaymasterSponsoredCall => 3_800,
            Self::WalletTransfer => 3_400,
            Self::OracleUpdate => 5_600,
            Self::StateWitnessRefresh => 6_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionBand {
    Idle,
    Low,
    Normal,
    Busy,
    Surge,
    Crisis,
}

impl CongestionBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Busy => "busy",
            Self::Surge => "surge",
            Self::Crisis => "crisis",
        }
    }

    pub fn from_pressure_bps(pressure_bps: u64) -> Self {
        match pressure_bps {
            0..=2_499 => Self::Idle,
            2_500..=5_999 => Self::Low,
            6_000..=10_999 => Self::Normal,
            11_000..=17_999 => Self::Busy,
            18_000..=27_999 => Self::Surge,
            _ => Self::Crisis,
        }
    }

    pub fn rebate_multiplier_bps(self) -> u64 {
        match self {
            Self::Idle => 2_000,
            Self::Low => 5_000,
            Self::Normal => 10_000,
            Self::Busy => 14_000,
            Self::Surge => 20_000,
            Self::Crisis => 28_000,
        }
    }

    pub fn netting_haircut_bps(self) -> u64 {
        match self {
            Self::Idle => 0,
            Self::Low => 100,
            Self::Normal => 250,
            Self::Busy => 500,
            Self::Surge => 900,
            Self::Crisis => 1_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Open,
    Netting,
    Settling,
    Paused,
    Sealed,
    Retired,
}

impl VaultStatus {
    pub fn accepts_coupons(self) -> bool {
        matches!(self, Self::Draft | Self::Open | Self::Netting)
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Netting | Self::Settling)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Netting => "netting",
            Self::Settling => "settling",
            Self::Paused => "paused",
            Self::Sealed => "sealed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRootPurpose {
    CalldataBaseFee,
    CalldataBytePrice,
    CongestionBand,
    CompressionOracle,
    SettlementEligibility,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Netted,
    PartiallySettled,
    Settled,
    Expired,
    Quarantined,
}

impl CouponStatus {
    pub fn redeemable(self) -> bool {
        matches!(self, Self::Issued | Self::Netted | Self::PartiallySettled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Netted => "netted",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Draft,
    Admitted,
    Netted,
    Submitted,
    Finalized,
    Disputed,
    Expired,
}

impl SettlementBatchStatus {
    pub fn accepts_settlement(self) -> bool {
        matches!(self, Self::Admitted | Self::Netted | Self::Submitted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub base_calldata_fee_micro_units: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub base_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_compression_bps: u64,
    pub target_compression_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub attested_root_ttl_slots: u64,
    pub coupon_ttl_slots: u64,
    pub netting_window_slots: u64,
    pub settlement_finality_slots: u64,
    pub max_calldata_bytes_per_batch: u64,
    pub max_coupons_per_netting: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            base_calldata_fee_micro_units: DEFAULT_BASE_CALLDATA_FEE_MICRO_UNITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            base_rebate_bps: DEFAULT_BASE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_compression_bps: DEFAULT_MIN_COMPRESSION_BPS,
            target_compression_bps: DEFAULT_TARGET_COMPRESSION_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            attested_root_ttl_slots: DEFAULT_ATTESTED_ROOT_TTL_SLOTS,
            coupon_ttl_slots: DEFAULT_COUPON_TTL_SLOTS,
            netting_window_slots: DEFAULT_NETTING_WINDOW_SLOTS,
            settlement_finality_slots: DEFAULT_SETTLEMENT_FINALITY_SLOTS,
            max_calldata_bytes_per_batch: DEFAULT_MAX_CALLDATA_BYTES_PER_BATCH,
            max_coupons_per_netting: DEFAULT_MAX_COUPONS_PER_NETTING,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "base_calldata_fee_micro_units": self.base_calldata_fee_micro_units,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "base_rebate_bps": self.base_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_compression_bps": self.min_compression_bps,
            "target_compression_bps": self.target_compression_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "attested_root_ttl_slots": self.attested_root_ttl_slots,
            "coupon_ttl_slots": self.coupon_ttl_slots,
            "netting_window_slots": self.netting_window_slots,
            "settlement_finality_slots": self.settlement_finality_slots,
            "max_calldata_bytes_per_batch": self.max_calldata_bytes_per_batch,
            "max_coupons_per_netting": self.max_coupons_per_netting,
            "max_public_events": self.max_public_events,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults_opened: u64,
    pub pq_fee_roots_attested: u64,
    pub compression_coupons_issued: u64,
    pub congestion_bands_recorded: u64,
    pub settlement_batches_opened: u64,
    pub settlement_batches_finalized: u64,
    pub coupon_nullifiers_seen: u64,
    pub rebates_netted_micro_units: u64,
    pub rebates_settled_micro_units: u64,
    pub calldata_bytes_admitted: u64,
    pub calldata_bytes_saved: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults_opened": self.vaults_opened,
            "pq_fee_roots_attested": self.pq_fee_roots_attested,
            "compression_coupons_issued": self.compression_coupons_issued,
            "congestion_bands_recorded": self.congestion_bands_recorded,
            "settlement_batches_opened": self.settlement_batches_opened,
            "settlement_batches_finalized": self.settlement_batches_finalized,
            "coupon_nullifiers_seen": self.coupon_nullifiers_seen,
            "rebates_netted_micro_units": self.rebates_netted_micro_units,
            "rebates_settled_micro_units": self.rebates_settled_micro_units,
            "calldata_bytes_admitted": self.calldata_bytes_admitted,
            "calldata_bytes_saved": self.calldata_bytes_saved,
            "events_emitted": self.events_emitted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub vaults_root: String,
    pub pq_attested_calldata_fee_roots_root: String,
    pub compression_coupons_root: String,
    pub congestion_bands_root: String,
    pub settlement_batches_root: String,
    pub settlement_receipts_root: String,
    pub coupon_nullifiers_root: String,
    pub indexes_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "vaults_root": self.vaults_root,
            "pq_attested_calldata_fee_roots_root": self.pq_attested_calldata_fee_roots_root,
            "compression_coupons_root": self.compression_coupons_root,
            "congestion_bands_root": self.congestion_bands_root,
            "settlement_batches_root": self.settlement_batches_root,
            "settlement_receipts_root": self.settlement_receipts_root,
            "coupon_nullifiers_root": self.coupon_nullifiers_root,
            "indexes_root": self.indexes_root,
            "events_root": self.events_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultInput {
    pub operator_commitment: String,
    pub settlement_asset_id: String,
    pub epoch: u64,
    pub open_slot: u64,
    pub close_slot: u64,
    pub privacy_set_size: u64,
    pub reserve_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CalldataRebateVault {
    pub vault_id: String,
    pub operator_commitment: String,
    pub settlement_asset_id: String,
    pub epoch: u64,
    pub open_slot: u64,
    pub close_slot: u64,
    pub status: VaultStatus,
    pub privacy_set_size: u64,
    pub reserve_commitment: String,
    pub netted_rebate_micro_units: u64,
    pub settled_rebate_micro_units: u64,
    pub admitted_coupon_count: u64,
    pub latest_congestion_band: CongestionBand,
}

impl CalldataRebateVault {
    pub fn from_input(input: VaultInput, nonce: u64) -> Self {
        let vault_id = vault_id(&input.operator_commitment, input.epoch, nonce);
        Self {
            vault_id,
            operator_commitment: input.operator_commitment,
            settlement_asset_id: input.settlement_asset_id,
            epoch: input.epoch,
            open_slot: input.open_slot,
            close_slot: input.close_slot,
            status: VaultStatus::Open,
            privacy_set_size: input.privacy_set_size,
            reserve_commitment: input.reserve_commitment,
            netted_rebate_micro_units: 0,
            settled_rebate_micro_units: 0,
            admitted_coupon_count: 0,
            latest_congestion_band: CongestionBand::Normal,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "operator_commitment": self.operator_commitment,
            "settlement_asset_id": self.settlement_asset_id,
            "epoch": self.epoch,
            "open_slot": self.open_slot,
            "close_slot": self.close_slot,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "reserve_commitment": self.reserve_commitment,
            "netted_rebate_micro_units": self.netted_rebate_micro_units,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "admitted_coupon_count": self.admitted_coupon_count,
            "latest_congestion_band": self.latest_congestion_band.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqFeeRootInput {
    pub vault_id: String,
    pub purpose: FeeRootPurpose,
    pub slot: u64,
    pub valid_until_slot: u64,
    pub fee_root: String,
    pub congestion_pressure_bps: u64,
    pub median_calldata_fee_micro_units: u64,
    pub pq_attestor_commitment: String,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestedCalldataFeeRoot {
    pub fee_root_id: String,
    pub vault_id: String,
    pub purpose: FeeRootPurpose,
    pub slot: u64,
    pub valid_until_slot: u64,
    pub fee_root: String,
    pub congestion_pressure_bps: u64,
    pub congestion_band: CongestionBand,
    pub median_calldata_fee_micro_units: u64,
    pub pq_attestor_commitment: String,
    pub pq_signature_root: String,
}

impl PqAttestedCalldataFeeRoot {
    pub fn from_input(input: PqFeeRootInput, nonce: u64) -> Self {
        let congestion_band = CongestionBand::from_pressure_bps(input.congestion_pressure_bps);
        Self {
            fee_root_id: fee_root_id(&input.vault_id, input.purpose, input.slot, nonce),
            vault_id: input.vault_id,
            purpose: input.purpose,
            slot: input.slot,
            valid_until_slot: input.valid_until_slot,
            fee_root: input.fee_root,
            congestion_pressure_bps: input.congestion_pressure_bps,
            congestion_band,
            median_calldata_fee_micro_units: input.median_calldata_fee_micro_units,
            pq_attestor_commitment: input.pq_attestor_commitment,
            pq_signature_root: input.pq_signature_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_root_id": self.fee_root_id,
            "vault_id": self.vault_id,
            "purpose": format!("{:?}", self.purpose),
            "slot": self.slot,
            "valid_until_slot": self.valid_until_slot,
            "fee_root": self.fee_root,
            "congestion_pressure_bps": self.congestion_pressure_bps,
            "congestion_band": self.congestion_band.as_str(),
            "median_calldata_fee_micro_units": self.median_calldata_fee_micro_units,
            "pq_attestor_commitment": self.pq_attestor_commitment,
            "pq_signature_root": self.pq_signature_root,
            "suite": PQ_ATTESTED_CALLDATA_FEE_ROOT_SUITE,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionCouponInput {
    pub vault_id: String,
    pub lane: CalldataLane,
    pub owner_commitment: String,
    pub coupon_commitment: String,
    pub nullifier_commitment: String,
    pub encrypted_coupon_payload_root: String,
    pub raw_calldata_bytes: u64,
    pub compressed_calldata_bytes: u64,
    pub eligible_rebate_micro_units: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionCoupon {
    pub coupon_id: String,
    pub vault_id: String,
    pub lane: CalldataLane,
    pub owner_commitment: String,
    pub coupon_commitment: String,
    pub nullifier_commitment: String,
    pub encrypted_coupon_payload_root: String,
    pub raw_calldata_bytes: u64,
    pub compressed_calldata_bytes: u64,
    pub saved_calldata_bytes: u64,
    pub compression_bps: u64,
    pub eligible_rebate_micro_units: u64,
    pub netted_rebate_micro_units: u64,
    pub settled_rebate_micro_units: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
    pub status: CouponStatus,
}

impl CompressionCoupon {
    pub fn from_input(input: CompressionCouponInput, band: CongestionBand, nonce: u64) -> Self {
        let saved_calldata_bytes = input
            .raw_calldata_bytes
            .saturating_sub(input.compressed_calldata_bytes);
        let compression_bps = ratio_bps(saved_calldata_bytes, input.raw_calldata_bytes);
        let band_rebate = input
            .eligible_rebate_micro_units
            .saturating_mul(band.rebate_multiplier_bps())
            / MAX_BPS;
        let haircut = band_rebate.saturating_mul(band.netting_haircut_bps()) / MAX_BPS;
        let netted_rebate_micro_units = band_rebate.saturating_sub(haircut);
        Self {
            coupon_id: coupon_id(&input.vault_id, &input.coupon_commitment, nonce),
            vault_id: input.vault_id,
            lane: input.lane,
            owner_commitment: input.owner_commitment,
            coupon_commitment: input.coupon_commitment,
            nullifier_commitment: input.nullifier_commitment,
            encrypted_coupon_payload_root: input.encrypted_coupon_payload_root,
            raw_calldata_bytes: input.raw_calldata_bytes,
            compressed_calldata_bytes: input.compressed_calldata_bytes,
            saved_calldata_bytes,
            compression_bps,
            eligible_rebate_micro_units: input.eligible_rebate_micro_units,
            netted_rebate_micro_units,
            settled_rebate_micro_units: 0,
            issued_slot: input.issued_slot,
            expires_slot: input.expires_slot,
            status: CouponStatus::Issued,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "vault_id": self.vault_id,
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "coupon_commitment": self.coupon_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "encrypted_coupon_payload_root": self.encrypted_coupon_payload_root,
            "raw_calldata_bytes": self.raw_calldata_bytes,
            "compressed_calldata_bytes": self.compressed_calldata_bytes,
            "saved_calldata_bytes": self.saved_calldata_bytes,
            "compression_bps": self.compression_bps,
            "eligible_rebate_micro_units": self.eligible_rebate_micro_units,
            "netted_rebate_micro_units": self.netted_rebate_micro_units,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "issued_slot": self.issued_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str(),
            "suite": CONFIDENTIAL_COMPRESSION_COUPON_SUITE,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionBandEntry {
    pub band_id: String,
    pub vault_id: String,
    pub band: CongestionBand,
    pub pressure_bps: u64,
    pub slot: u64,
    pub fee_root_id: String,
    pub calldata_fee_root: String,
    pub attestation_root: String,
}

impl CongestionBandEntry {
    pub fn new(fee_root: &PqAttestedCalldataFeeRoot, nonce: u64) -> Self {
        Self {
            band_id: band_id(
                &fee_root.vault_id,
                fee_root.congestion_band,
                fee_root.slot,
                nonce,
            ),
            vault_id: fee_root.vault_id.clone(),
            band: fee_root.congestion_band,
            pressure_bps: fee_root.congestion_pressure_bps,
            slot: fee_root.slot,
            fee_root_id: fee_root.fee_root_id.clone(),
            calldata_fee_root: fee_root.fee_root.clone(),
            attestation_root: fee_root.pq_signature_root.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "band_id": self.band_id,
            "vault_id": self.vault_id,
            "band": self.band.as_str(),
            "pressure_bps": self.pressure_bps,
            "slot": self.slot,
            "fee_root_id": self.fee_root_id,
            "calldata_fee_root": self.calldata_fee_root,
            "attestation_root": self.attestation_root,
            "suite": CONGESTION_BAND_SUITE,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatchInput {
    pub vault_id: String,
    pub fee_root_id: String,
    pub batch_commitment: String,
    pub coupon_ids: Vec<String>,
    pub settlement_slot: u64,
    pub settlement_fee_micro_units: u64,
    pub batch_proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub vault_id: String,
    pub fee_root_id: String,
    pub batch_commitment: String,
    pub coupon_ids: Vec<String>,
    pub coupon_count: u64,
    pub raw_calldata_bytes: u64,
    pub compressed_calldata_bytes: u64,
    pub saved_calldata_bytes: u64,
    pub gross_rebate_micro_units: u64,
    pub settlement_fee_micro_units: u64,
    pub net_rebate_micro_units: u64,
    pub settlement_slot: u64,
    pub batch_proof_root: String,
    pub status: SettlementBatchStatus,
}

impl LowFeeSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "fee_root_id": self.fee_root_id,
            "batch_commitment": self.batch_commitment,
            "coupon_ids": self.coupon_ids,
            "coupon_count": self.coupon_count,
            "raw_calldata_bytes": self.raw_calldata_bytes,
            "compressed_calldata_bytes": self.compressed_calldata_bytes,
            "saved_calldata_bytes": self.saved_calldata_bytes,
            "gross_rebate_micro_units": self.gross_rebate_micro_units,
            "settlement_fee_micro_units": self.settlement_fee_micro_units,
            "net_rebate_micro_units": self.net_rebate_micro_units,
            "settlement_slot": self.settlement_slot,
            "batch_proof_root": self.batch_proof_root,
            "status": format!("{:?}", self.status),
            "suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub vault_id: String,
    pub settled_rebate_micro_units: u64,
    pub settled_coupon_count: u64,
    pub finalized_slot: u64,
    pub settlement_tx_root: String,
    pub operator_receipt_root: String,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "settled_coupon_count": self.settled_coupon_count,
            "finalized_slot": self.finalized_slot,
            "settlement_tx_root": self.settlement_tx_root,
            "operator_receipt_root": self.operator_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub nonce: u64,
}

impl RuntimeEvent {
    pub fn new(kind: impl Into<String>, subject_id: impl Into<String>, nonce: u64) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        Self {
            event_id: event_id(&kind, &subject_id, nonce),
            kind,
            subject_id,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, CalldataRebateVault>,
    pub pq_attested_calldata_fee_roots: BTreeMap<String, PqAttestedCalldataFeeRoot>,
    pub compression_coupons: BTreeMap<String, CompressionCoupon>,
    pub congestion_bands: BTreeMap<String, CongestionBandEntry>,
    pub settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub coupon_nullifiers: BTreeSet<String>,
    pub coupons_by_vault: BTreeMap<String, BTreeSet<String>>,
    pub batches_by_vault: BTreeMap<String, BTreeSet<String>>,
    pub fee_roots_by_vault: BTreeMap<String, BTreeSet<String>>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            pq_attested_calldata_fee_roots: BTreeMap::new(),
            compression_coupons: BTreeMap::new(),
            congestion_bands: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            coupon_nullifiers: BTreeSet::new(),
            coupons_by_vault: BTreeMap::new(),
            batches_by_vault: BTreeMap::new(),
            fee_roots_by_vault: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let vault = state
            .open_vault(VaultInput {
                operator_commitment: commitment("operator", &["devnet-netting-operator"]),
                settlement_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
                epoch: DEVNET_EPOCH,
                open_slot: DEVNET_HEIGHT,
                close_slot: DEVNET_HEIGHT + DEFAULT_NETTING_WINDOW_SLOTS,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                reserve_commitment: commitment("reserve", &["calldata-rebate-devnet"]),
            })
            .expect("devnet vault opens");
        let fee_root = state
            .attest_fee_root(PqFeeRootInput {
                vault_id: vault.vault_id.clone(),
                purpose: FeeRootPurpose::CalldataBaseFee,
                slot: DEVNET_HEIGHT + 4,
                valid_until_slot: DEVNET_HEIGHT + DEFAULT_ATTESTED_ROOT_TTL_SLOTS,
                fee_root: commitment("fee-root", &["devnet-calldata-fee-root"]),
                congestion_pressure_bps: 8_200,
                median_calldata_fee_micro_units: DEFAULT_BASE_CALLDATA_FEE_MICRO_UNITS,
                pq_attestor_commitment: commitment("attestor", &["ml-dsa-devnet-committee"]),
                pq_signature_root: commitment("pq-signature-root", &["fee-root-signatures"]),
            })
            .expect("devnet fee root attests");
        let first = state
            .issue_compression_coupon(CompressionCouponInput {
                vault_id: vault.vault_id.clone(),
                lane: CalldataLane::ConfidentialContractCall,
                owner_commitment: commitment("owner", &["contract-call-cohort-a"]),
                coupon_commitment: commitment("coupon", &["coupon-a"]),
                nullifier_commitment: commitment("nullifier", &["coupon-a"]),
                encrypted_coupon_payload_root: commitment("payload", &["coupon-a"]),
                raw_calldata_bytes: 96_000,
                compressed_calldata_bytes: 31_000,
                eligible_rebate_micro_units: 42_000,
                issued_slot: DEVNET_HEIGHT + 8,
                expires_slot: DEVNET_HEIGHT + DEFAULT_COUPON_TTL_SLOTS,
            })
            .expect("devnet coupon a issues");
        let second = state
            .issue_compression_coupon(CompressionCouponInput {
                vault_id: vault.vault_id.clone(),
                lane: CalldataLane::PaymasterSponsoredCall,
                owner_commitment: commitment("owner", &["paymaster-cohort-b"]),
                coupon_commitment: commitment("coupon", &["coupon-b"]),
                nullifier_commitment: commitment("nullifier", &["coupon-b"]),
                encrypted_coupon_payload_root: commitment("payload", &["coupon-b"]),
                raw_calldata_bytes: 64_000,
                compressed_calldata_bytes: 22_000,
                eligible_rebate_micro_units: 27_000,
                issued_slot: DEVNET_HEIGHT + 9,
                expires_slot: DEVNET_HEIGHT + DEFAULT_COUPON_TTL_SLOTS,
            })
            .expect("devnet coupon b issues");
        let batch = state
            .open_settlement_batch(SettlementBatchInput {
                vault_id: vault.vault_id.clone(),
                fee_root_id: fee_root.fee_root_id.clone(),
                batch_commitment: commitment("batch", &["devnet-low-fee-settlement"]),
                coupon_ids: vec![first.coupon_id.clone(), second.coupon_id.clone()],
                settlement_slot: DEVNET_HEIGHT + 24,
                settlement_fee_micro_units: 1_700,
                batch_proof_root: commitment("batch-proof", &["devnet-low-fee-settlement"]),
            })
            .expect("devnet settlement batch opens");
        state
            .finalize_settlement_batch(
                &batch.batch_id,
                DEVNET_HEIGHT + 24 + DEFAULT_SETTLEMENT_FINALITY_SLOTS,
                commitment("settlement-tx", &["devnet-finalized"]),
                commitment("operator-receipt", &["devnet-finalized"]),
            )
            .expect("devnet settlement finalizes");
        state.recompute_roots();
        state
    }

    pub fn open_vault(&mut self, input: VaultInput) -> Result<CalldataRebateVault> {
        ensure!(
            input.close_slot > input.open_slot,
            "vault close slot must be after open slot"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set {} below minimum {}",
            input.privacy_set_size,
            self.config.min_privacy_set_size
        );
        let nonce = self.counters.vaults_opened.saturating_add(1);
        let vault = CalldataRebateVault::from_input(input, nonce);
        self.vaults.insert(vault.vault_id.clone(), vault.clone());
        self.counters.vaults_opened = nonce;
        self.emit("vault_opened", &vault.vault_id);
        self.recompute_roots();
        Ok(vault)
    }

    pub fn attest_fee_root(&mut self, input: PqFeeRootInput) -> Result<PqAttestedCalldataFeeRoot> {
        ensure!(
            input.valid_until_slot > input.slot,
            "fee root must expire after attested slot"
        );
        let vault = self
            .vaults
            .get_mut(&input.vault_id)
            .ok_or_else(|| format!("unknown vault {}", input.vault_id))?;
        ensure!(
            vault.status.accepts_batches(),
            "vault {} does not accept fee roots",
            vault.vault_id
        );
        let nonce = self.counters.pq_fee_roots_attested.saturating_add(1);
        let fee_root = PqAttestedCalldataFeeRoot::from_input(input, nonce);
        vault.latest_congestion_band = fee_root.congestion_band;
        self.fee_roots_by_vault
            .entry(fee_root.vault_id.clone())
            .or_default()
            .insert(fee_root.fee_root_id.clone());
        self.pq_attested_calldata_fee_roots
            .insert(fee_root.fee_root_id.clone(), fee_root.clone());
        let band = CongestionBandEntry::new(&fee_root, nonce);
        self.congestion_bands.insert(band.band_id.clone(), band);
        self.counters.pq_fee_roots_attested = nonce;
        self.counters.congestion_bands_recorded =
            self.counters.congestion_bands_recorded.saturating_add(1);
        self.emit("pq_calldata_fee_root_attested", &fee_root.fee_root_id);
        self.recompute_roots();
        Ok(fee_root)
    }

    pub fn issue_compression_coupon(
        &mut self,
        input: CompressionCouponInput,
    ) -> Result<CompressionCoupon> {
        ensure!(
            input.raw_calldata_bytes > 0,
            "raw calldata bytes must be non-zero"
        );
        ensure!(
            input.compressed_calldata_bytes < input.raw_calldata_bytes,
            "compressed calldata must be smaller than raw calldata"
        );
        ensure!(
            input.expires_slot > input.issued_slot,
            "coupon expiry must be after issuance"
        );
        let vault = self
            .vaults
            .get_mut(&input.vault_id)
            .ok_or_else(|| format!("unknown vault {}", input.vault_id))?;
        ensure!(
            vault.status.accepts_coupons(),
            "vault {} does not accept coupons",
            vault.vault_id
        );
        let compression_bps = ratio_bps(
            input
                .raw_calldata_bytes
                .saturating_sub(input.compressed_calldata_bytes),
            input.raw_calldata_bytes,
        );
        ensure!(
            compression_bps >= input.lane.compression_floor_bps(),
            "compression {} bps below lane floor {}",
            compression_bps,
            input.lane.compression_floor_bps()
        );
        ensure!(
            compression_bps >= self.config.min_compression_bps,
            "compression {} bps below config floor {}",
            compression_bps,
            self.config.min_compression_bps
        );
        ensure!(
            !self.coupon_nullifiers.contains(&input.nullifier_commitment),
            "coupon nullifier already seen"
        );
        let nonce = self.counters.compression_coupons_issued.saturating_add(1);
        let band = vault.latest_congestion_band;
        let coupon = CompressionCoupon::from_input(input, band, nonce);
        vault.admitted_coupon_count = vault.admitted_coupon_count.saturating_add(1);
        vault.netted_rebate_micro_units = vault
            .netted_rebate_micro_units
            .saturating_add(coupon.netted_rebate_micro_units);
        self.coupon_nullifiers
            .insert(coupon.nullifier_commitment.clone());
        self.coupons_by_vault
            .entry(coupon.vault_id.clone())
            .or_default()
            .insert(coupon.coupon_id.clone());
        self.counters.compression_coupons_issued = nonce;
        self.counters.coupon_nullifiers_seen =
            self.counters.coupon_nullifiers_seen.saturating_add(1);
        self.counters.rebates_netted_micro_units = self
            .counters
            .rebates_netted_micro_units
            .saturating_add(coupon.netted_rebate_micro_units);
        self.counters.calldata_bytes_admitted = self
            .counters
            .calldata_bytes_admitted
            .saturating_add(coupon.raw_calldata_bytes);
        self.counters.calldata_bytes_saved = self
            .counters
            .calldata_bytes_saved
            .saturating_add(coupon.saved_calldata_bytes);
        self.compression_coupons
            .insert(coupon.coupon_id.clone(), coupon.clone());
        self.emit("compression_coupon_issued", &coupon.coupon_id);
        self.recompute_roots();
        Ok(coupon)
    }

    pub fn open_settlement_batch(
        &mut self,
        input: SettlementBatchInput,
    ) -> Result<LowFeeSettlementBatch> {
        ensure!(
            !input.coupon_ids.is_empty(),
            "settlement batch must include coupons"
        );
        ensure!(
            input.coupon_ids.len() <= self.config.max_coupons_per_netting,
            "too many coupons in netting batch"
        );
        let vault = self
            .vaults
            .get(&input.vault_id)
            .ok_or_else(|| format!("unknown vault {}", input.vault_id))?;
        ensure!(
            vault.status.accepts_batches(),
            "vault {} does not accept settlement batches",
            vault.vault_id
        );
        ensure!(
            self.pq_attested_calldata_fee_roots
                .contains_key(&input.fee_root_id),
            "unknown fee root {}",
            input.fee_root_id
        );
        let mut raw_calldata_bytes = 0_u64;
        let mut compressed_calldata_bytes = 0_u64;
        let mut saved_calldata_bytes = 0_u64;
        let mut gross_rebate_micro_units = 0_u64;
        let unique_coupon_ids = input.coupon_ids.iter().collect::<BTreeSet<_>>();
        ensure!(
            unique_coupon_ids.len() == input.coupon_ids.len(),
            "settlement batch contains duplicate coupons"
        );
        for coupon_id in &input.coupon_ids {
            let coupon = self
                .compression_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("unknown coupon {coupon_id}"))?;
            ensure!(
                coupon.vault_id == input.vault_id,
                "coupon {} belongs to a different vault",
                coupon_id
            );
            ensure!(
                coupon.status.redeemable(),
                "coupon {} is not redeemable",
                coupon_id
            );
            raw_calldata_bytes = raw_calldata_bytes.saturating_add(coupon.raw_calldata_bytes);
            compressed_calldata_bytes =
                compressed_calldata_bytes.saturating_add(coupon.compressed_calldata_bytes);
            saved_calldata_bytes = saved_calldata_bytes.saturating_add(coupon.saved_calldata_bytes);
            gross_rebate_micro_units =
                gross_rebate_micro_units.saturating_add(coupon.netted_rebate_micro_units);
        }
        ensure!(
            raw_calldata_bytes <= self.config.max_calldata_bytes_per_batch,
            "calldata bytes {} exceed batch maximum {}",
            raw_calldata_bytes,
            self.config.max_calldata_bytes_per_batch
        );
        let nonce = self.counters.settlement_batches_opened.saturating_add(1);
        let net_rebate_micro_units =
            gross_rebate_micro_units.saturating_sub(input.settlement_fee_micro_units);
        let batch = LowFeeSettlementBatch {
            batch_id: batch_id(&input.vault_id, &input.batch_commitment, nonce),
            vault_id: input.vault_id,
            fee_root_id: input.fee_root_id,
            batch_commitment: input.batch_commitment,
            coupon_count: input.coupon_ids.len() as u64,
            coupon_ids: input.coupon_ids,
            raw_calldata_bytes,
            compressed_calldata_bytes,
            saved_calldata_bytes,
            gross_rebate_micro_units,
            settlement_fee_micro_units: input.settlement_fee_micro_units,
            net_rebate_micro_units,
            settlement_slot: input.settlement_slot,
            batch_proof_root: input.batch_proof_root,
            status: SettlementBatchStatus::Admitted,
        };
        for coupon_id in &batch.coupon_ids {
            if let Some(coupon) = self.compression_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Netted;
            }
        }
        self.batches_by_vault
            .entry(batch.vault_id.clone())
            .or_default()
            .insert(batch.batch_id.clone());
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.counters.settlement_batches_opened = nonce;
        self.emit("low_fee_settlement_batch_opened", &batch.batch_id);
        self.recompute_roots();
        Ok(batch)
    }

    pub fn finalize_settlement_batch(
        &mut self,
        batch_id: &str,
        finalized_slot: u64,
        settlement_tx_root: String,
        operator_receipt_root: String,
    ) -> Result<SettlementReceipt> {
        let batch = self
            .settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown settlement batch {batch_id}"))?;
        ensure!(
            batch.status.accepts_settlement(),
            "batch {} does not accept finalization",
            batch_id
        );
        batch.status = SettlementBatchStatus::Finalized;
        for coupon_id in &batch.coupon_ids {
            if let Some(coupon) = self.compression_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Settled;
                coupon.settled_rebate_micro_units = coupon.netted_rebate_micro_units;
            }
        }
        if let Some(vault) = self.vaults.get_mut(&batch.vault_id) {
            vault.status = VaultStatus::Settling;
            vault.settled_rebate_micro_units = vault
                .settled_rebate_micro_units
                .saturating_add(batch.net_rebate_micro_units);
        }
        let nonce = self.counters.settlement_batches_finalized.saturating_add(1);
        let receipt = SettlementReceipt {
            receipt_id: receipt_id(batch_id, nonce),
            batch_id: batch_id.to_string(),
            vault_id: batch.vault_id.clone(),
            settled_rebate_micro_units: batch.net_rebate_micro_units,
            settled_coupon_count: batch.coupon_count,
            finalized_slot,
            settlement_tx_root,
            operator_receipt_root,
        };
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.counters.settlement_batches_finalized = nonce;
        self.counters.rebates_settled_micro_units = self
            .counters
            .rebates_settled_micro_units
            .saturating_add(receipt.settled_rebate_micro_units);
        self.emit("low_fee_settlement_batch_finalized", batch_id);
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn expire_coupon(&mut self, coupon_id: &str, current_slot: u64) -> Result<()> {
        let coupon = self
            .compression_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown coupon {coupon_id}"))?;
        ensure!(
            current_slot >= coupon.expires_slot,
            "coupon {} has not expired",
            coupon_id
        );
        ensure!(
            coupon.status.redeemable(),
            "coupon {} cannot be expired from status {:?}",
            coupon_id,
            coupon.status
        );
        coupon.status = CouponStatus::Expired;
        self.emit("compression_coupon_expired", coupon_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attested_calldata_fee_root_suite": PQ_ATTESTED_CALLDATA_FEE_ROOT_SUITE,
            "confidential_compression_coupon_suite": CONFIDENTIAL_COMPRESSION_COUPON_SUITE,
            "low_fee_settlement_batch_suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "vaults": self.vaults.values().map(CalldataRebateVault::public_record).collect::<Vec<_>>(),
            "pq_attested_calldata_fee_roots": self.pq_attested_calldata_fee_roots.values().map(PqAttestedCalldataFeeRoot::public_record).collect::<Vec<_>>(),
            "compression_coupons": self.compression_coupons.values().map(CompressionCoupon::public_record).collect::<Vec<_>>(),
            "congestion_bands": self.congestion_bands.values().map(CongestionBandEntry::public_record).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.values().map(LowFeeSettlementBatch::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "coupon_nullifiers_root": set_root(D_NULLIFIERS, &self.coupon_nullifiers),
            "indexes_root": merkle_root(D_PUBLIC, &[
                json!({"coupons_by_vault": self.coupons_by_vault}),
                json!({"batches_by_vault": self.batches_by_vault}),
                json!({"fee_roots_by_vault": self.fee_roots_by_vault}),
            ]),
            "events": self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config_root": self.config.state_root(),
            "counters_root": self.counters.state_root(),
            "roots": self.roots.public_record_without_state_root(),
            "vaults_root": map_root(D_VAULTS, &self.vaults, CalldataRebateVault::public_record),
            "pq_attested_calldata_fee_roots_root": map_root(D_FEE_ROOTS, &self.pq_attested_calldata_fee_roots, PqAttestedCalldataFeeRoot::public_record),
            "compression_coupons_root": map_root(D_COUPONS, &self.compression_coupons, CompressionCoupon::public_record),
            "congestion_bands_root": map_root(D_BANDS, &self.congestion_bands, CongestionBandEntry::public_record),
            "settlement_batches_root": map_root(D_BATCHES, &self.settlement_batches, LowFeeSettlementBatch::public_record),
            "settlement_receipts_root": map_root(D_SETTLEMENTS, &self.settlement_receipts, SettlementReceipt::public_record),
            "coupon_nullifiers_root": set_root(D_NULLIFIERS, &self.coupon_nullifiers),
            "indexes_root": merkle_root(D_PUBLIC, &[
                json!({"coupons_by_vault": self.coupons_by_vault}),
                json!({"batches_by_vault": self.batches_by_vault}),
                json!({"fee_roots_by_vault": self.fee_roots_by_vault}),
            ]),
            "events_root": merkle_root(D_EVENTS, &self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>()),
        })
    }

    pub fn recompute_roots(&mut self) {
        self.roots.vaults_root =
            map_root(D_VAULTS, &self.vaults, CalldataRebateVault::public_record);
        self.roots.pq_attested_calldata_fee_roots_root = map_root(
            D_FEE_ROOTS,
            &self.pq_attested_calldata_fee_roots,
            PqAttestedCalldataFeeRoot::public_record,
        );
        self.roots.compression_coupons_root = map_root(
            D_COUPONS,
            &self.compression_coupons,
            CompressionCoupon::public_record,
        );
        self.roots.congestion_bands_root = map_root(
            D_BANDS,
            &self.congestion_bands,
            CongestionBandEntry::public_record,
        );
        self.roots.settlement_batches_root = map_root(
            D_BATCHES,
            &self.settlement_batches,
            LowFeeSettlementBatch::public_record,
        );
        self.roots.settlement_receipts_root = map_root(
            D_SETTLEMENTS,
            &self.settlement_receipts,
            SettlementReceipt::public_record,
        );
        self.roots.coupon_nullifiers_root = set_root(D_NULLIFIERS, &self.coupon_nullifiers);
        self.roots.indexes_root = merkle_root(
            D_PUBLIC,
            &[
                json!({"coupons_by_vault": self.coupons_by_vault}),
                json!({"batches_by_vault": self.batches_by_vault}),
                json!({"fee_roots_by_vault": self.fee_roots_by_vault}),
            ],
        );
        self.roots.events_root = merkle_root(
            D_EVENTS,
            &self
                .events
                .iter()
                .map(RuntimeEvent::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = self.state_root();
    }

    fn emit(&mut self, kind: impl Into<String>, subject_id: impl Into<String>) {
        if self.events.len() >= self.config.max_public_events {
            return;
        }
        let nonce = self.counters.events_emitted.saturating_add(1);
        self.events.push(RuntimeEvent::new(kind, subject_id, nonce));
        self.counters.events_emitted = nonce;
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

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MAX_BPS) / denominator
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:{domain}"),
        &hash_parts,
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": record_root(domain, &json!({"key": key, "record": public_record(value)})),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({"value": value, "record_root": record_root(domain, &json!({"value": value}))}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(D_STATE, &[HashPart::Json(record)], 32)
}

fn vault_id(operator_commitment: &str, epoch: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:VAULT-ID",
        &[
            HashPart::Str(operator_commitment),
            HashPart::U64(epoch),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn fee_root_id(vault_id: &str, purpose: FeeRootPurpose, slot: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:FEE-ROOT-ID",
        &[
            HashPart::Str(vault_id),
            HashPart::Str(&format!("{purpose:?}")),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn coupon_id(vault_id: &str, coupon_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:COUPON-ID",
        &[
            HashPart::Str(vault_id),
            HashPart::Str(coupon_commitment),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn band_id(vault_id: &str, band: CongestionBand, slot: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:BAND-ID",
        &[
            HashPart::Str(vault_id),
            HashPart::Str(band.as_str()),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn batch_id(vault_id: &str, batch_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:BATCH-ID",
        &[
            HashPart::Str(vault_id),
            HashPart::Str(batch_commitment),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn receipt_id(batch_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:RECEIPT-ID",
        &[HashPart::Str(batch_id), HashPart::U64(nonce)],
        20,
    )
}

fn event_id(kind: &str, subject_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-CALLDATA-REBATE-NETTING-VAULT:EVENT-ID",
        &[
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::U64(nonce),
        ],
        20,
    )
}
