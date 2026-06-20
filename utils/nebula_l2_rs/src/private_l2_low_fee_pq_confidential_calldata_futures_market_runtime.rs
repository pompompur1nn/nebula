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

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CALLDATA_FUTURES_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-calldata-futures-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CALLDATA_FUTURES_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PQ_SEALING_SUITE: &str = "ML-KEM-1024+X25519Kyber768Draft00-sealed-calldata-v1";
pub const CONFIDENTIAL_CALLDATA_FUTURES_PROTOCOL: &str =
    "monero-l2-low-fee-pq-confidential-calldata-futures-market-v1";
pub const SEALED_CALLDATA_FUTURE_SCHEME: &str = "sealed-calldata-future-commitment-v1";
pub const DA_CAPACITY_BAND_SCHEME: &str = "private-da-capacity-band-root-v1";
pub const SPONSOR_VAULT_SCHEME: &str = "anonymous-calldata-sponsor-vault-root-v1";
pub const SETTLEMENT_COUPON_SCHEME: &str = "confidential-calldata-settlement-coupon-root-v1";
pub const ORACLE_ATTESTATION_SCHEME: &str = "pq-calldata-fee-oracle-attestation-root-v1";
pub const CONGESTION_HEDGE_SCHEME: &str = "sealed-congestion-hedge-position-root-v1";
pub const CONTRACT_CALL_RESERVATION_SCHEME: &str = "private-contract-call-reservation-root-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-confidential-calldata-rebate-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-l2-calldata-futures-nullifier-fence-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-calldata-futures-slasher-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_880_144;
pub const DEVNET_EPOCH: u64 = 4_002;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_NULLIFIER_SET_SIZE: u64 = 4_096;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MARKET_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_BASE_CALLDATA_MICRO_FEE: u64 = 9;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_MAKER_FEE_BPS: u64 = 1;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 2;
pub const DEFAULT_ORACLE_FEE_BPS: u64 = 1;
pub const DEFAULT_ROUTER_FEE_BPS: u64 = 2;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_600;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_200;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 700;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 50_000;
pub const DEFAULT_MAX_SEALED_FUTURES: usize = 8_388_608;
pub const DEFAULT_MAX_DA_CAPACITY_BANDS: usize = 1_048_576;
pub const DEFAULT_MAX_SPONSOR_VAULTS: usize = 524_288;
pub const DEFAULT_MAX_SETTLEMENT_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_CONGESTION_HEDGES: usize = 4_194_304;
pub const DEFAULT_MAX_CONTRACT_CALL_RESERVATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataLaneKind {
    PrivateContractCall,
    DefiSettlement,
    OracleUpdate,
    BridgeMessage,
    SequencerInbox,
    RecursiveWitness,
    MoneroExit,
    EmergencyEscape,
}
impl CalldataLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiSettlement => "defi_settlement",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeMessage => "bridge_message",
            Self::SequencerInbox => "sequencer_inbox",
            Self::RecursiveWitness => "recursive_witness",
            Self::MoneroExit => "monero_exit",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureStatus {
    Proposed,
    Open,
    Reserved,
    Hedged,
    Settling,
    Settled,
    Rebated,
    Expired,
    Challenged,
    Slashed,
    Rejected,
}
impl FutureStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::Open
                | Self::Reserved
                | Self::Hedged
                | Self::Settling
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityBandStatus {
    Draft,
    Active,
    Saturated,
    Throttled,
    Settling,
    Retired,
    Slashed,
}
impl CapacityBandStatus {
    pub fn accepts_reservations(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Active,
    Draining,
    Paused,
    Locked,
    Slashed,
    Retired,
}
impl VaultStatus {
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Locked,
    Redeemed,
    Expired,
    Challenged,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Submitted,
    Quorum,
    Usable,
    Superseded,
    Disputed,
    Expired,
    Slashed,
}
impl OracleStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Quorum | Self::Usable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeSide {
    LongCongestion,
    ShortCongestion,
    SponsorCovered,
    RebateProtected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Requested,
    Admitted,
    Packed,
    Executed,
    Settled,
    Rebated,
    Expired,
    Cancelled,
    Challenged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidOracle,
    WithheldData,
    DoubleReservation,
    CouponReplay,
    FenceViolation,
    SponsorInsolvency,
    InvalidPqSignature,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub market_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_nullifier_set_size: u64,
    pub base_calldata_micro_fee: u64,
    pub max_user_fee_bps: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub oracle_fee_bps: u64,
    pub router_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub max_leverage_bps: u64,
    pub max_sealed_futures: usize,
    pub max_da_capacity_bands: usize,
    pub max_sponsor_vaults: usize,
    pub max_settlement_coupons: usize,
    pub max_oracle_attestations: usize,
    pub max_congestion_hedges: usize,
    pub max_contract_call_reservations: usize,
    pub max_fee_rebates: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            market_ttl_blocks: DEFAULT_MARKET_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_nullifier_set_size: DEFAULT_MIN_NULLIFIER_SET_SIZE,
            base_calldata_micro_fee: DEFAULT_BASE_CALLDATA_MICRO_FEE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            maker_fee_bps: DEFAULT_MAKER_FEE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            oracle_fee_bps: DEFAULT_ORACLE_FEE_BPS,
            router_fee_bps: DEFAULT_ROUTER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            max_sealed_futures: DEFAULT_MAX_SEALED_FUTURES,
            max_da_capacity_bands: DEFAULT_MAX_DA_CAPACITY_BANDS,
            max_sponsor_vaults: DEFAULT_MAX_SPONSOR_VAULTS,
            max_settlement_coupons: DEFAULT_MAX_SETTLEMENT_COUPONS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_congestion_hedges: DEFAULT_MAX_CONGESTION_HEDGES,
            max_contract_call_reservations: DEFAULT_MAX_CONTRACT_CALL_RESERVATIONS,
            max_fee_rebates: DEFAULT_MAX_FEE_REBATES,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.chain_id == CHAIN_ID,
            "unexpected chain id: {}",
            self.chain_id
        );
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version: {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unexpected schema version: {}",
            self.schema_version
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security floor too low"
        );
        ensure!(
            self.min_privacy_set_size >= self.min_nullifier_set_size,
            "privacy set must cover nullifier set"
        );
        for (name, bps) in [
            ("max_user_fee_bps", self.max_user_fee_bps),
            ("maker_fee_bps", self.maker_fee_bps),
            ("taker_fee_bps", self.taker_fee_bps),
            ("oracle_fee_bps", self.oracle_fee_bps),
            ("router_fee_bps", self.router_fee_bps),
            ("sponsor_cover_bps", self.sponsor_cover_bps),
            ("sponsor_reserve_bps", self.sponsor_reserve_bps),
            ("rebate_bps", self.rebate_bps),
            ("slash_bps", self.slash_bps),
            ("initial_margin_bps", self.initial_margin_bps),
            ("maintenance_margin_bps", self.maintenance_margin_bps),
            ("max_leverage_bps", self.max_leverage_bps),
        ] {
            ensure!(bps <= MAX_BPS * 10, "{} out of range", name);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sealed_futures: u64,
    pub da_capacity_bands: u64,
    pub sponsor_vaults: u64,
    pub settlement_coupons: u64,
    pub oracle_attestations: u64,
    pub congestion_hedges: u64,
    pub contract_call_reservations: u64,
    pub fee_rebates: u64,
    pub privacy_fences: u64,
    pub slashing_evidence: u64,
    pub active_futures: u64,
    pub active_reservations: u64,
    pub total_reserved_bytes: u128,
    pub total_sponsored_micro_fee: u128,
    pub total_rebated_micro_fee: u128,
    pub total_slashed_micro_fee: u128,
}
impl Counters {
    pub fn empty() -> Self {
        Self {
            sealed_futures: 0,
            da_capacity_bands: 0,
            sponsor_vaults: 0,
            settlement_coupons: 0,
            oracle_attestations: 0,
            congestion_hedges: 0,
            contract_call_reservations: 0,
            fee_rebates: 0,
            privacy_fences: 0,
            slashing_evidence: 0,
            active_futures: 0,
            active_reservations: 0,
            total_reserved_bytes: 0,
            total_sponsored_micro_fee: 0,
            total_rebated_micro_fee: 0,
            total_slashed_micro_fee: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub sealed_future_root: String,
    pub da_capacity_band_root: String,
    pub sponsor_vault_root: String,
    pub settlement_coupon_root: String,
    pub oracle_attestation_root: String,
    pub congestion_hedge_root: String,
    pub contract_call_reservation_root: String,
    pub fee_rebate_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub index_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCalldataFuture {
    pub future_id: String,
    pub lane: CalldataLaneKind,
    pub owner_commitment: String,
    pub sealed_terms_root: String,
    pub calldata_commitment_root: String,
    pub max_bytes: u64,
    pub strike_micro_fee_per_byte: u64,
    pub collateral_commitment: String,
    pub sponsor_vault_id: Option<String>,
    pub capacity_band_id: String,
    pub oracle_attestation_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FutureStatus,
}
impl SealedCalldataFuture {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-FUTURE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaCapacityBand {
    pub band_id: String,
    pub lane: CalldataLaneKind,
    pub provider_committee_root: String,
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub target_micro_fee_per_byte: u64,
    pub max_micro_fee_per_byte: u64,
    pub reserved_bytes: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: CapacityBandStatus,
}
impl DaCapacityBand {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn available_bytes(&self) -> u64 {
        self.max_bytes.saturating_sub(self.reserved_bytes)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-CAPACITY-BAND-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub balance_commitment: String,
    pub available_micro_fee: u128,
    pub reserved_micro_fee: u128,
    pub min_privacy_set_size: u64,
    pub nullifier_root: String,
    pub opened_at_height: u64,
    pub status: VaultStatus,
}
impl SponsorVault {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-SPONSOR-VAULT-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementCoupon {
    pub coupon_id: String,
    pub future_id: String,
    pub reservation_id: Option<String>,
    pub owner_commitment: String,
    pub coupon_commitment: String,
    pub settlement_root: String,
    pub face_micro_fee: u128,
    pub rebate_micro_fee: u128,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: CouponStatus,
}
impl SettlementCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-SETTLEMENT-COUPON-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub oracle_committee_root: String,
    pub lane: CalldataLaneKind,
    pub fee_observation_root: String,
    pub congestion_score_bps: u64,
    pub median_micro_fee_per_byte: u64,
    pub p95_micro_fee_per_byte: u64,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: OracleStatus,
}
impl OracleAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-ORACLE-ATTESTATION-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionHedge {
    pub hedge_id: String,
    pub future_id: String,
    pub side: HedgeSide,
    pub notional_bytes: u64,
    pub entry_micro_fee_per_byte: u64,
    pub limit_micro_fee_per_byte: u64,
    pub margin_commitment: String,
    pub liquidation_fence_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FutureStatus,
}
impl CongestionHedge {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-CONGESTION-HEDGE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallReservation {
    pub reservation_id: String,
    pub future_id: String,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub call_bundle_root: String,
    pub max_calldata_bytes: u64,
    pub reserved_micro_fee: u128,
    pub execution_hint_root: String,
    pub nullifier_fence_id: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}
impl ContractCallReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-CONTRACT-CALL-RESERVATION-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub coupon_id: String,
    pub reservation_id: Option<String>,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub amount_micro_fee: u128,
    pub proof_root: String,
    pub issued_at_height: u64,
    pub status: CouponStatus,
}
impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-FEE-REBATE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub account_commitment: String,
    pub nullifier_root: String,
    pub membership_root: String,
    pub min_anonymity_set_size: u64,
    pub spent_nullifiers: BTreeSet<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}
impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({"fence_id": self.fence_id, "account_commitment": self.account_commitment, "nullifier_root": self.nullifier_root, "membership_root": self.membership_root, "min_anonymity_set_size": self.min_anonymity_set_size, "spent_nullifiers": self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(), "opened_at_height": self.opened_at_height, "expires_at_height": self.expires_at_height})
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-PRIVACY-FENCE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub subject_commitment: String,
    pub reason: SlashingReason,
    pub related_future_id: Option<String>,
    pub related_reservation_id: Option<String>,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_micro_fee: u128,
    pub submitted_at_height: u64,
    pub resolved: bool,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "CALLDATA-SLASHING-EVIDENCE-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub sealed_futures: BTreeMap<String, SealedCalldataFuture>,
    pub da_capacity_bands: BTreeMap<String, DaCapacityBand>,
    pub sponsor_vaults: BTreeMap<String, SponsorVault>,
    pub settlement_coupons: BTreeMap<String, SettlementCoupon>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub congestion_hedges: BTreeMap<String, CongestionHedge>,
    pub contract_call_reservations: BTreeMap<String, ContractCallReservation>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::empty(),
            sealed_futures: BTreeMap::new(),
            da_capacity_bands: BTreeMap::new(),
            sponsor_vaults: BTreeMap::new(),
            settlement_coupons: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            congestion_hedges: BTreeMap::new(),
            contract_call_reservations: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
        })
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.seed_devnet();
        state
    }
    fn seed_devnet(&mut self) {
        let band = DaCapacityBand {
            band_id: da_capacity_band_id(
                CalldataLaneKind::PrivateContractCall,
                "devnet-provider-root",
                0,
                262_144,
                DEVNET_HEIGHT,
            ),
            lane: CalldataLaneKind::PrivateContractCall,
            provider_committee_root: "devnet-provider-root".to_string(),
            min_bytes: 0,
            max_bytes: 262_144,
            target_micro_fee_per_byte: 9,
            max_micro_fee_per_byte: 18,
            reserved_bytes: 96_000,
            privacy_set_size: self.config.target_privacy_set_size,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.market_ttl_blocks,
            status: CapacityBandStatus::Active,
        };
        let band_id = band.band_id.clone();
        self.upsert_da_capacity_band(band).expect("seed band");
        let vault = SponsorVault {
            vault_id: sponsor_vault_id("devnet-sponsor", DEVNET_FEE_ASSET_ID, DEVNET_HEIGHT),
            sponsor_commitment: "devnet-sponsor".to_string(),
            asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            balance_commitment: "devnet-sponsor-balance".to_string(),
            available_micro_fee: 20_000_000,
            reserved_micro_fee: 3_000_000,
            min_privacy_set_size: self.config.min_privacy_set_size,
            nullifier_root: domain_hash("DEVNET-SPONSOR-NULLIFIER", &[HashPart::Str(CHAIN_ID)], 32),
            opened_at_height: DEVNET_HEIGHT,
            status: VaultStatus::Active,
        };
        let vault_id = vault.vault_id.clone();
        self.upsert_sponsor_vault(vault).expect("seed vault");
        let oracle = OracleAttestation {
            attestation_id: oracle_attestation_id(
                CalldataLaneKind::PrivateContractCall,
                "devnet-oracle",
                DEVNET_HEIGHT,
            ),
            oracle_committee_root: "devnet-oracle".to_string(),
            lane: CalldataLaneKind::PrivateContractCall,
            fee_observation_root: domain_hash(
                "DEVNET-FEE-OBSERVATION",
                &[HashPart::Str(CHAIN_ID)],
                32,
            ),
            congestion_score_bps: 4_200,
            median_micro_fee_per_byte: 9,
            p95_micro_fee_per_byte: 14,
            pq_signature_root: domain_hash(
                "DEVNET-ORACLE-SIG",
                &[HashPart::Str(PQ_AUTH_SUITE)],
                32,
            ),
            attested_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.oracle_ttl_blocks,
            status: OracleStatus::Usable,
        };
        let oracle_id = oracle.attestation_id.clone();
        self.upsert_oracle_attestation(oracle).expect("seed oracle");
        let fence = PrivacyFence {
            fence_id: privacy_fence_id("devnet-account", "devnet-nullifier-root", DEVNET_HEIGHT),
            account_commitment: "devnet-account".to_string(),
            nullifier_root: "devnet-nullifier-root".to_string(),
            membership_root: domain_hash("DEVNET-MEMBERSHIP", &[HashPart::Str(CHAIN_ID)], 32),
            min_anonymity_set_size: self.config.min_privacy_set_size,
            spent_nullifiers: BTreeSet::new(),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.market_ttl_blocks,
        };
        let fence_id = fence.fence_id.clone();
        self.upsert_privacy_fence(fence).expect("seed fence");
        let future = SealedCalldataFuture {
            future_id: sealed_calldata_future_id(
                CalldataLaneKind::PrivateContractCall,
                "devnet-owner",
                "devnet-terms",
                DEVNET_HEIGHT,
            ),
            lane: CalldataLaneKind::PrivateContractCall,
            owner_commitment: "devnet-owner".to_string(),
            sealed_terms_root: "devnet-terms".to_string(),
            calldata_commitment_root: domain_hash(
                "DEVNET-CALLDATA",
                &[HashPart::Str(CHAIN_ID)],
                32,
            ),
            max_bytes: 48_000,
            strike_micro_fee_per_byte: 9,
            collateral_commitment: "devnet-collateral".to_string(),
            sponsor_vault_id: Some(vault_id),
            capacity_band_id: band_id,
            oracle_attestation_id: Some(oracle_id),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.market_ttl_blocks,
            status: FutureStatus::Reserved,
        };
        let future_id = future.future_id.clone();
        self.upsert_sealed_future(future).expect("seed future");
        let reservation = ContractCallReservation {
            reservation_id: contract_call_reservation_id(
                &future_id,
                "devnet-contract",
                "devnet-bundle",
                DEVNET_HEIGHT,
            ),
            future_id: future_id.clone(),
            contract_commitment: "devnet-contract".to_string(),
            caller_commitment: "devnet-caller".to_string(),
            call_bundle_root: "devnet-bundle".to_string(),
            max_calldata_bytes: 12_000,
            reserved_micro_fee: 108_000,
            execution_hint_root: domain_hash("DEVNET-EXEC-HINT", &[HashPart::Str(CHAIN_ID)], 32),
            nullifier_fence_id: fence_id,
            reserved_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.reservation_ttl_blocks,
            status: ReservationStatus::Admitted,
        };
        self.upsert_contract_call_reservation(reservation)
            .expect("seed reservation");
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: domain_hash(
                "CALLDATA-CONFIG",
                &[HashPart::Json(&self.config.public_record())],
                32,
            ),
            sealed_future_root: map_root(
                "CALLDATA-SEALED-FUTURES",
                &self.sealed_futures,
                SealedCalldataFuture::public_record,
            ),
            da_capacity_band_root: map_root(
                "CALLDATA-DA-CAPACITY-BANDS",
                &self.da_capacity_bands,
                DaCapacityBand::public_record,
            ),
            sponsor_vault_root: map_root(
                "CALLDATA-SPONSOR-VAULTS",
                &self.sponsor_vaults,
                SponsorVault::public_record,
            ),
            settlement_coupon_root: map_root(
                "CALLDATA-SETTLEMENT-COUPONS",
                &self.settlement_coupons,
                SettlementCoupon::public_record,
            ),
            oracle_attestation_root: map_root(
                "CALLDATA-ORACLE-ATTESTATIONS",
                &self.oracle_attestations,
                OracleAttestation::public_record,
            ),
            congestion_hedge_root: map_root(
                "CALLDATA-CONGESTION-HEDGES",
                &self.congestion_hedges,
                CongestionHedge::public_record,
            ),
            contract_call_reservation_root: map_root(
                "CALLDATA-CONTRACT-CALL-RESERVATIONS",
                &self.contract_call_reservations,
                ContractCallReservation::public_record,
            ),
            fee_rebate_root: map_root(
                "CALLDATA-FEE-REBATES",
                &self.fee_rebates,
                FeeRebate::public_record,
            ),
            privacy_fence_root: map_root(
                "CALLDATA-PRIVACY-FENCES",
                &self.privacy_fences,
                PrivacyFence::public_record,
            ),
            slashing_evidence_root: map_root(
                "CALLDATA-SLASHING-EVIDENCE",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            index_root: self.index_root(),
        }
    }
    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.sealed_futures = self.sealed_futures.len() as u64;
        counters.da_capacity_bands = self.da_capacity_bands.len() as u64;
        counters.sponsor_vaults = self.sponsor_vaults.len() as u64;
        counters.settlement_coupons = self.settlement_coupons.len() as u64;
        counters.oracle_attestations = self.oracle_attestations.len() as u64;
        counters.congestion_hedges = self.congestion_hedges.len() as u64;
        counters.contract_call_reservations = self.contract_call_reservations.len() as u64;
        counters.fee_rebates = self.fee_rebates.len() as u64;
        counters.privacy_fences = self.privacy_fences.len() as u64;
        counters.slashing_evidence = self.slashing_evidence.len() as u64;
        counters.active_futures = self
            .sealed_futures
            .values()
            .filter(|future| future.status.active())
            .count() as u64;
        counters.active_reservations = self
            .contract_call_reservations
            .values()
            .filter(|reservation| {
                matches!(
                    reservation.status,
                    ReservationStatus::Requested
                        | ReservationStatus::Admitted
                        | ReservationStatus::Packed
                        | ReservationStatus::Challenged
                )
            })
            .count() as u64;
        counters.total_reserved_bytes = self
            .contract_call_reservations
            .values()
            .map(|reservation| reservation.max_calldata_bytes as u128)
            .sum();
        counters.total_sponsored_micro_fee = self
            .sponsor_vaults
            .values()
            .map(|vault| vault.reserved_micro_fee)
            .sum();
        counters.total_rebated_micro_fee = self
            .fee_rebates
            .values()
            .map(|rebate| rebate.amount_micro_fee)
            .sum();
        counters.total_slashed_micro_fee = self
            .slashing_evidence
            .values()
            .map(|evidence| evidence.slash_micro_fee)
            .sum();
        counters
    }
    fn index_root(&self) -> String {
        let record = json!({"future_ids": self.sealed_futures.keys().cloned().collect::<Vec<_>>(), "band_ids": self.da_capacity_bands.keys().cloned().collect::<Vec<_>>(), "vault_ids": self.sponsor_vaults.keys().cloned().collect::<Vec<_>>(), "reservation_ids": self.contract_call_reservations.keys().cloned().collect::<Vec<_>>(), "fence_ids": self.privacy_fences.keys().cloned().collect::<Vec<_>>()});
        domain_hash("CALLDATA-FUTURES-INDEX", &[HashPart::Json(&record)], 32)
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({"chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "hash_suite": HASH_SUITE, "pq_auth_suite": PQ_AUTH_SUITE, "pq_sealing_suite": PQ_SEALING_SUITE, "protocol": CONFIDENTIAL_CALLDATA_FUTURES_PROTOCOL, "config": self.config.public_record(), "counters": counters.public_record(), "roots": roots.public_record()})
    }
    pub fn upsert_sealed_future(&mut self, future: SealedCalldataFuture) -> Result<()> {
        ensure!(
            self.sealed_futures.len() < self.config.max_sealed_futures
                || self.sealed_futures.contains_key(&future.future_id),
            "sealed future capacity exceeded"
        );
        ensure!(future.max_bytes > 0, "future must reserve positive bytes");
        ensure!(
            future.expires_at_height > future.opened_at_height,
            "future expiry must be after opening"
        );
        ensure!(
            future.strike_micro_fee_per_byte
                <= self.config.base_calldata_micro_fee.saturating_mul(100),
            "future strike too high"
        );
        ensure!(
            self.da_capacity_bands
                .contains_key(&future.capacity_band_id),
            "missing capacity band {}",
            future.capacity_band_id
        );
        if let Some(vault_id) = &future.sponsor_vault_id {
            ensure!(
                self.sponsor_vaults
                    .get(vault_id)
                    .map(|vault| vault.status.can_sponsor())
                    .unwrap_or(false),
                "sponsor vault unavailable"
            );
        }
        if let Some(attestation_id) = &future.oracle_attestation_id {
            ensure!(
                self.oracle_attestations
                    .get(attestation_id)
                    .map(|att| att.status.usable())
                    .unwrap_or(false),
                "oracle attestation unavailable"
            );
        }
        self.sealed_futures.insert(future.future_id.clone(), future);
        Ok(())
    }
    pub fn upsert_da_capacity_band(&mut self, band: DaCapacityBand) -> Result<()> {
        ensure!(
            self.da_capacity_bands.len() < self.config.max_da_capacity_bands
                || self.da_capacity_bands.contains_key(&band.band_id),
            "capacity band limit exceeded"
        );
        ensure!(
            band.max_bytes >= band.min_bytes,
            "invalid capacity band range"
        );
        ensure!(
            band.reserved_bytes <= band.max_bytes,
            "reserved bytes exceed band"
        );
        ensure!(
            band.privacy_set_size >= self.config.min_privacy_set_size,
            "capacity band privacy set too small"
        );
        self.da_capacity_bands.insert(band.band_id.clone(), band);
        Ok(())
    }
    pub fn upsert_sponsor_vault(&mut self, vault: SponsorVault) -> Result<()> {
        ensure!(
            self.sponsor_vaults.len() < self.config.max_sponsor_vaults
                || self.sponsor_vaults.contains_key(&vault.vault_id),
            "sponsor vault limit exceeded"
        );
        ensure!(
            vault.asset_id == self.config.fee_asset_id,
            "unexpected sponsor asset"
        );
        ensure!(
            vault.min_privacy_set_size >= self.config.min_privacy_set_size,
            "sponsor privacy set too small"
        );
        ensure!(
            vault.available_micro_fee >= vault.reserved_micro_fee,
            "sponsor vault over reserved"
        );
        self.sponsor_vaults.insert(vault.vault_id.clone(), vault);
        Ok(())
    }
    pub fn upsert_settlement_coupon(&mut self, coupon: SettlementCoupon) -> Result<()> {
        ensure!(
            self.settlement_coupons.len() < self.config.max_settlement_coupons
                || self.settlement_coupons.contains_key(&coupon.coupon_id),
            "coupon limit exceeded"
        );
        ensure!(
            self.sealed_futures.contains_key(&coupon.future_id),
            "coupon future missing"
        );
        ensure!(
            coupon.expires_at_height > coupon.issued_at_height,
            "coupon expiry must be after issue"
        );
        self.settlement_coupons
            .insert(coupon.coupon_id.clone(), coupon);
        Ok(())
    }
    pub fn upsert_oracle_attestation(&mut self, attestation: OracleAttestation) -> Result<()> {
        ensure!(
            self.oracle_attestations.len() < self.config.max_oracle_attestations
                || self
                    .oracle_attestations
                    .contains_key(&attestation.attestation_id),
            "oracle attestation limit exceeded"
        );
        ensure!(
            attestation.expires_at_height > attestation.attested_at_height,
            "oracle expiry must be after attestation"
        );
        ensure!(
            attestation.congestion_score_bps <= MAX_BPS,
            "oracle congestion score out of range"
        );
        ensure!(
            attestation.p95_micro_fee_per_byte >= attestation.median_micro_fee_per_byte,
            "oracle p95 below median"
        );
        self.oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }
    pub fn upsert_congestion_hedge(&mut self, hedge: CongestionHedge) -> Result<()> {
        ensure!(
            self.congestion_hedges.len() < self.config.max_congestion_hedges
                || self.congestion_hedges.contains_key(&hedge.hedge_id),
            "hedge limit exceeded"
        );
        ensure!(
            self.sealed_futures.contains_key(&hedge.future_id),
            "hedge future missing"
        );
        ensure!(hedge.notional_bytes > 0, "hedge notional must be positive");
        ensure!(
            hedge.expires_at_height > hedge.opened_at_height,
            "hedge expiry must be after opening"
        );
        self.congestion_hedges.insert(hedge.hedge_id.clone(), hedge);
        Ok(())
    }
    pub fn upsert_contract_call_reservation(
        &mut self,
        reservation: ContractCallReservation,
    ) -> Result<()> {
        ensure!(
            self.contract_call_reservations.len() < self.config.max_contract_call_reservations
                || self
                    .contract_call_reservations
                    .contains_key(&reservation.reservation_id),
            "reservation limit exceeded"
        );
        ensure!(
            self.sealed_futures.contains_key(&reservation.future_id),
            "reservation future missing"
        );
        ensure!(
            self.privacy_fences
                .contains_key(&reservation.nullifier_fence_id),
            "reservation privacy fence missing"
        );
        ensure!(
            reservation.max_calldata_bytes > 0,
            "reservation bytes must be positive"
        );
        ensure!(
            reservation.expires_at_height > reservation.reserved_at_height,
            "reservation expiry must be after opening"
        );
        self.contract_call_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }
    pub fn upsert_fee_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        ensure!(
            self.fee_rebates.len() < self.config.max_fee_rebates
                || self.fee_rebates.contains_key(&rebate.rebate_id),
            "rebate limit exceeded"
        );
        ensure!(
            self.settlement_coupons.contains_key(&rebate.coupon_id),
            "rebate coupon missing"
        );
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }
    pub fn upsert_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        ensure!(
            self.privacy_fences.len() < self.config.max_privacy_fences
                || self.privacy_fences.contains_key(&fence.fence_id),
            "privacy fence limit exceeded"
        );
        ensure!(
            fence.min_anonymity_set_size >= self.config.min_nullifier_set_size,
            "privacy fence anonymity set too small"
        );
        ensure!(
            fence.expires_at_height > fence.opened_at_height,
            "privacy fence expiry must be after opening"
        );
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }
    pub fn upsert_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<()> {
        ensure!(
            self.slashing_evidence.len() < self.config.max_slashing_evidence
                || self.slashing_evidence.contains_key(&evidence.evidence_id),
            "slashing evidence limit exceeded"
        );
        ensure!(
            evidence.slash_micro_fee > 0,
            "slash amount must be positive"
        );
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash("CALLDATA-FUTURES-STATE-ROOT", &[HashPart::Json(record)], 32)
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values.values().map(public_record).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn sealed_calldata_future_id(
    lane: CalldataLaneKind,
    owner_commitment: &str,
    sealed_terms_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-FUTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(sealed_terms_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn da_capacity_band_id(
    lane: CalldataLaneKind,
    provider_committee_root: &str,
    min_bytes: u64,
    max_bytes: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-CAPACITY-BAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(provider_committee_root),
            HashPart::U64(min_bytes),
            HashPart::U64(max_bytes),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn sponsor_vault_id(sponsor_commitment: &str, asset_id: &str, opened_at_height: u64) -> String {
    domain_hash(
        "CALLDATA-SPONSOR-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(asset_id),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn settlement_coupon_id(
    future_id: &str,
    owner_commitment: &str,
    settlement_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-SETTLEMENT-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(future_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(settlement_root),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}
pub fn oracle_attestation_id(
    lane: CalldataLaneKind,
    oracle_committee_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(oracle_committee_root),
            HashPart::U64(attested_at_height),
        ],
        32,
    )
}
pub fn congestion_hedge_id(
    future_id: &str,
    side: HedgeSide,
    margin_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-CONGESTION-HEDGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(future_id),
            HashPart::Str(&format!("{:?}", side)),
            HashPart::Str(margin_commitment),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn contract_call_reservation_id(
    future_id: &str,
    contract_commitment: &str,
    call_bundle_root: &str,
    reserved_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-CONTRACT-CALL-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(future_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(call_bundle_root),
            HashPart::U64(reserved_at_height),
        ],
        32,
    )
}
pub fn fee_rebate_id(
    coupon_id: &str,
    recipient_commitment: &str,
    proof_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(coupon_id),
            HashPart::Str(recipient_commitment),
            HashPart::Str(proof_root),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}
pub fn privacy_fence_id(
    account_commitment: &str,
    nullifier_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(nullifier_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    subject_commitment: &str,
    evidence_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "CALLDATA-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(evidence_root),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

pub const AUDIT_DOMAIN_TAGS: &[&str] = &[
    "calldata-futures-audit-domain-0001",
    "calldata-futures-audit-domain-0002",
    "calldata-futures-audit-domain-0003",
    "calldata-futures-audit-domain-0004",
    "calldata-futures-audit-domain-0005",
    "calldata-futures-audit-domain-0006",
    "calldata-futures-audit-domain-0007",
    "calldata-futures-audit-domain-0008",
    "calldata-futures-audit-domain-0009",
    "calldata-futures-audit-domain-0010",
    "calldata-futures-audit-domain-0011",
    "calldata-futures-audit-domain-0012",
    "calldata-futures-audit-domain-0013",
    "calldata-futures-audit-domain-0014",
    "calldata-futures-audit-domain-0015",
    "calldata-futures-audit-domain-0016",
    "calldata-futures-audit-domain-0017",
    "calldata-futures-audit-domain-0018",
    "calldata-futures-audit-domain-0019",
    "calldata-futures-audit-domain-0020",
    "calldata-futures-audit-domain-0021",
    "calldata-futures-audit-domain-0022",
    "calldata-futures-audit-domain-0023",
    "calldata-futures-audit-domain-0024",
    "calldata-futures-audit-domain-0025",
    "calldata-futures-audit-domain-0026",
    "calldata-futures-audit-domain-0027",
    "calldata-futures-audit-domain-0028",
    "calldata-futures-audit-domain-0029",
    "calldata-futures-audit-domain-0030",
    "calldata-futures-audit-domain-0031",
    "calldata-futures-audit-domain-0032",
    "calldata-futures-audit-domain-0033",
    "calldata-futures-audit-domain-0034",
    "calldata-futures-audit-domain-0035",
    "calldata-futures-audit-domain-0036",
    "calldata-futures-audit-domain-0037",
    "calldata-futures-audit-domain-0038",
    "calldata-futures-audit-domain-0039",
    "calldata-futures-audit-domain-0040",
    "calldata-futures-audit-domain-0041",
    "calldata-futures-audit-domain-0042",
    "calldata-futures-audit-domain-0043",
    "calldata-futures-audit-domain-0044",
    "calldata-futures-audit-domain-0045",
    "calldata-futures-audit-domain-0046",
    "calldata-futures-audit-domain-0047",
    "calldata-futures-audit-domain-0048",
    "calldata-futures-audit-domain-0049",
    "calldata-futures-audit-domain-0050",
    "calldata-futures-audit-domain-0051",
    "calldata-futures-audit-domain-0052",
    "calldata-futures-audit-domain-0053",
    "calldata-futures-audit-domain-0054",
    "calldata-futures-audit-domain-0055",
    "calldata-futures-audit-domain-0056",
    "calldata-futures-audit-domain-0057",
    "calldata-futures-audit-domain-0058",
    "calldata-futures-audit-domain-0059",
    "calldata-futures-audit-domain-0060",
    "calldata-futures-audit-domain-0061",
    "calldata-futures-audit-domain-0062",
    "calldata-futures-audit-domain-0063",
    "calldata-futures-audit-domain-0064",
    "calldata-futures-audit-domain-0065",
    "calldata-futures-audit-domain-0066",
    "calldata-futures-audit-domain-0067",
    "calldata-futures-audit-domain-0068",
    "calldata-futures-audit-domain-0069",
    "calldata-futures-audit-domain-0070",
    "calldata-futures-audit-domain-0071",
    "calldata-futures-audit-domain-0072",
    "calldata-futures-audit-domain-0073",
    "calldata-futures-audit-domain-0074",
    "calldata-futures-audit-domain-0075",
    "calldata-futures-audit-domain-0076",
    "calldata-futures-audit-domain-0077",
    "calldata-futures-audit-domain-0078",
    "calldata-futures-audit-domain-0079",
    "calldata-futures-audit-domain-0080",
    "calldata-futures-audit-domain-0081",
    "calldata-futures-audit-domain-0082",
    "calldata-futures-audit-domain-0083",
    "calldata-futures-audit-domain-0084",
    "calldata-futures-audit-domain-0085",
    "calldata-futures-audit-domain-0086",
    "calldata-futures-audit-domain-0087",
    "calldata-futures-audit-domain-0088",
    "calldata-futures-audit-domain-0089",
    "calldata-futures-audit-domain-0090",
    "calldata-futures-audit-domain-0091",
    "calldata-futures-audit-domain-0092",
    "calldata-futures-audit-domain-0093",
    "calldata-futures-audit-domain-0094",
    "calldata-futures-audit-domain-0095",
    "calldata-futures-audit-domain-0096",
    "calldata-futures-audit-domain-0097",
    "calldata-futures-audit-domain-0098",
    "calldata-futures-audit-domain-0099",
    "calldata-futures-audit-domain-0100",
    "calldata-futures-audit-domain-0101",
    "calldata-futures-audit-domain-0102",
    "calldata-futures-audit-domain-0103",
    "calldata-futures-audit-domain-0104",
    "calldata-futures-audit-domain-0105",
    "calldata-futures-audit-domain-0106",
    "calldata-futures-audit-domain-0107",
    "calldata-futures-audit-domain-0108",
    "calldata-futures-audit-domain-0109",
    "calldata-futures-audit-domain-0110",
    "calldata-futures-audit-domain-0111",
    "calldata-futures-audit-domain-0112",
    "calldata-futures-audit-domain-0113",
    "calldata-futures-audit-domain-0114",
    "calldata-futures-audit-domain-0115",
    "calldata-futures-audit-domain-0116",
    "calldata-futures-audit-domain-0117",
    "calldata-futures-audit-domain-0118",
    "calldata-futures-audit-domain-0119",
    "calldata-futures-audit-domain-0120",
    "calldata-futures-audit-domain-0121",
    "calldata-futures-audit-domain-0122",
    "calldata-futures-audit-domain-0123",
    "calldata-futures-audit-domain-0124",
    "calldata-futures-audit-domain-0125",
    "calldata-futures-audit-domain-0126",
    "calldata-futures-audit-domain-0127",
    "calldata-futures-audit-domain-0128",
    "calldata-futures-audit-domain-0129",
    "calldata-futures-audit-domain-0130",
    "calldata-futures-audit-domain-0131",
    "calldata-futures-audit-domain-0132",
    "calldata-futures-audit-domain-0133",
    "calldata-futures-audit-domain-0134",
    "calldata-futures-audit-domain-0135",
    "calldata-futures-audit-domain-0136",
    "calldata-futures-audit-domain-0137",
    "calldata-futures-audit-domain-0138",
    "calldata-futures-audit-domain-0139",
    "calldata-futures-audit-domain-0140",
    "calldata-futures-audit-domain-0141",
    "calldata-futures-audit-domain-0142",
    "calldata-futures-audit-domain-0143",
    "calldata-futures-audit-domain-0144",
    "calldata-futures-audit-domain-0145",
    "calldata-futures-audit-domain-0146",
    "calldata-futures-audit-domain-0147",
    "calldata-futures-audit-domain-0148",
    "calldata-futures-audit-domain-0149",
    "calldata-futures-audit-domain-0150",
    "calldata-futures-audit-domain-0151",
    "calldata-futures-audit-domain-0152",
    "calldata-futures-audit-domain-0153",
    "calldata-futures-audit-domain-0154",
    "calldata-futures-audit-domain-0155",
    "calldata-futures-audit-domain-0156",
    "calldata-futures-audit-domain-0157",
    "calldata-futures-audit-domain-0158",
    "calldata-futures-audit-domain-0159",
    "calldata-futures-audit-domain-0160",
    "calldata-futures-audit-domain-0161",
    "calldata-futures-audit-domain-0162",
    "calldata-futures-audit-domain-0163",
    "calldata-futures-audit-domain-0164",
    "calldata-futures-audit-domain-0165",
    "calldata-futures-audit-domain-0166",
    "calldata-futures-audit-domain-0167",
    "calldata-futures-audit-domain-0168",
    "calldata-futures-audit-domain-0169",
    "calldata-futures-audit-domain-0170",
    "calldata-futures-audit-domain-0171",
    "calldata-futures-audit-domain-0172",
    "calldata-futures-audit-domain-0173",
    "calldata-futures-audit-domain-0174",
    "calldata-futures-audit-domain-0175",
    "calldata-futures-audit-domain-0176",
    "calldata-futures-audit-domain-0177",
    "calldata-futures-audit-domain-0178",
    "calldata-futures-audit-domain-0179",
    "calldata-futures-audit-domain-0180",
    "calldata-futures-audit-domain-0181",
    "calldata-futures-audit-domain-0182",
    "calldata-futures-audit-domain-0183",
    "calldata-futures-audit-domain-0184",
    "calldata-futures-audit-domain-0185",
    "calldata-futures-audit-domain-0186",
    "calldata-futures-audit-domain-0187",
    "calldata-futures-audit-domain-0188",
    "calldata-futures-audit-domain-0189",
    "calldata-futures-audit-domain-0190",
    "calldata-futures-audit-domain-0191",
    "calldata-futures-audit-domain-0192",
    "calldata-futures-audit-domain-0193",
    "calldata-futures-audit-domain-0194",
    "calldata-futures-audit-domain-0195",
    "calldata-futures-audit-domain-0196",
    "calldata-futures-audit-domain-0197",
    "calldata-futures-audit-domain-0198",
    "calldata-futures-audit-domain-0199",
    "calldata-futures-audit-domain-0200",
    "calldata-futures-audit-domain-0201",
    "calldata-futures-audit-domain-0202",
    "calldata-futures-audit-domain-0203",
    "calldata-futures-audit-domain-0204",
    "calldata-futures-audit-domain-0205",
    "calldata-futures-audit-domain-0206",
    "calldata-futures-audit-domain-0207",
    "calldata-futures-audit-domain-0208",
    "calldata-futures-audit-domain-0209",
    "calldata-futures-audit-domain-0210",
    "calldata-futures-audit-domain-0211",
    "calldata-futures-audit-domain-0212",
    "calldata-futures-audit-domain-0213",
    "calldata-futures-audit-domain-0214",
    "calldata-futures-audit-domain-0215",
    "calldata-futures-audit-domain-0216",
    "calldata-futures-audit-domain-0217",
    "calldata-futures-audit-domain-0218",
    "calldata-futures-audit-domain-0219",
    "calldata-futures-audit-domain-0220",
    "calldata-futures-audit-domain-0221",
    "calldata-futures-audit-domain-0222",
    "calldata-futures-audit-domain-0223",
    "calldata-futures-audit-domain-0224",
    "calldata-futures-audit-domain-0225",
    "calldata-futures-audit-domain-0226",
    "calldata-futures-audit-domain-0227",
    "calldata-futures-audit-domain-0228",
    "calldata-futures-audit-domain-0229",
    "calldata-futures-audit-domain-0230",
    "calldata-futures-audit-domain-0231",
    "calldata-futures-audit-domain-0232",
    "calldata-futures-audit-domain-0233",
    "calldata-futures-audit-domain-0234",
    "calldata-futures-audit-domain-0235",
    "calldata-futures-audit-domain-0236",
    "calldata-futures-audit-domain-0237",
    "calldata-futures-audit-domain-0238",
    "calldata-futures-audit-domain-0239",
    "calldata-futures-audit-domain-0240",
    "calldata-futures-audit-domain-0241",
    "calldata-futures-audit-domain-0242",
    "calldata-futures-audit-domain-0243",
    "calldata-futures-audit-domain-0244",
    "calldata-futures-audit-domain-0245",
    "calldata-futures-audit-domain-0246",
    "calldata-futures-audit-domain-0247",
    "calldata-futures-audit-domain-0248",
    "calldata-futures-audit-domain-0249",
    "calldata-futures-audit-domain-0250",
    "calldata-futures-audit-domain-0251",
    "calldata-futures-audit-domain-0252",
    "calldata-futures-audit-domain-0253",
    "calldata-futures-audit-domain-0254",
    "calldata-futures-audit-domain-0255",
    "calldata-futures-audit-domain-0256",
    "calldata-futures-audit-domain-0257",
    "calldata-futures-audit-domain-0258",
    "calldata-futures-audit-domain-0259",
    "calldata-futures-audit-domain-0260",
    "calldata-futures-audit-domain-0261",
    "calldata-futures-audit-domain-0262",
    "calldata-futures-audit-domain-0263",
    "calldata-futures-audit-domain-0264",
    "calldata-futures-audit-domain-0265",
    "calldata-futures-audit-domain-0266",
    "calldata-futures-audit-domain-0267",
    "calldata-futures-audit-domain-0268",
    "calldata-futures-audit-domain-0269",
    "calldata-futures-audit-domain-0270",
    "calldata-futures-audit-domain-0271",
    "calldata-futures-audit-domain-0272",
    "calldata-futures-audit-domain-0273",
    "calldata-futures-audit-domain-0274",
    "calldata-futures-audit-domain-0275",
    "calldata-futures-audit-domain-0276",
    "calldata-futures-audit-domain-0277",
    "calldata-futures-audit-domain-0278",
    "calldata-futures-audit-domain-0279",
    "calldata-futures-audit-domain-0280",
    "calldata-futures-audit-domain-0281",
    "calldata-futures-audit-domain-0282",
    "calldata-futures-audit-domain-0283",
    "calldata-futures-audit-domain-0284",
    "calldata-futures-audit-domain-0285",
    "calldata-futures-audit-domain-0286",
    "calldata-futures-audit-domain-0287",
    "calldata-futures-audit-domain-0288",
    "calldata-futures-audit-domain-0289",
    "calldata-futures-audit-domain-0290",
    "calldata-futures-audit-domain-0291",
    "calldata-futures-audit-domain-0292",
    "calldata-futures-audit-domain-0293",
    "calldata-futures-audit-domain-0294",
    "calldata-futures-audit-domain-0295",
    "calldata-futures-audit-domain-0296",
    "calldata-futures-audit-domain-0297",
    "calldata-futures-audit-domain-0298",
    "calldata-futures-audit-domain-0299",
    "calldata-futures-audit-domain-0300",
    "calldata-futures-audit-domain-0301",
    "calldata-futures-audit-domain-0302",
    "calldata-futures-audit-domain-0303",
    "calldata-futures-audit-domain-0304",
    "calldata-futures-audit-domain-0305",
    "calldata-futures-audit-domain-0306",
    "calldata-futures-audit-domain-0307",
    "calldata-futures-audit-domain-0308",
    "calldata-futures-audit-domain-0309",
    "calldata-futures-audit-domain-0310",
    "calldata-futures-audit-domain-0311",
    "calldata-futures-audit-domain-0312",
    "calldata-futures-audit-domain-0313",
    "calldata-futures-audit-domain-0314",
    "calldata-futures-audit-domain-0315",
    "calldata-futures-audit-domain-0316",
    "calldata-futures-audit-domain-0317",
    "calldata-futures-audit-domain-0318",
    "calldata-futures-audit-domain-0319",
    "calldata-futures-audit-domain-0320",
    "calldata-futures-audit-domain-0321",
    "calldata-futures-audit-domain-0322",
    "calldata-futures-audit-domain-0323",
    "calldata-futures-audit-domain-0324",
    "calldata-futures-audit-domain-0325",
    "calldata-futures-audit-domain-0326",
    "calldata-futures-audit-domain-0327",
    "calldata-futures-audit-domain-0328",
    "calldata-futures-audit-domain-0329",
    "calldata-futures-audit-domain-0330",
    "calldata-futures-audit-domain-0331",
    "calldata-futures-audit-domain-0332",
    "calldata-futures-audit-domain-0333",
    "calldata-futures-audit-domain-0334",
    "calldata-futures-audit-domain-0335",
    "calldata-futures-audit-domain-0336",
    "calldata-futures-audit-domain-0337",
    "calldata-futures-audit-domain-0338",
    "calldata-futures-audit-domain-0339",
    "calldata-futures-audit-domain-0340",
    "calldata-futures-audit-domain-0341",
    "calldata-futures-audit-domain-0342",
    "calldata-futures-audit-domain-0343",
    "calldata-futures-audit-domain-0344",
    "calldata-futures-audit-domain-0345",
    "calldata-futures-audit-domain-0346",
    "calldata-futures-audit-domain-0347",
    "calldata-futures-audit-domain-0348",
    "calldata-futures-audit-domain-0349",
    "calldata-futures-audit-domain-0350",
    "calldata-futures-audit-domain-0351",
    "calldata-futures-audit-domain-0352",
    "calldata-futures-audit-domain-0353",
    "calldata-futures-audit-domain-0354",
    "calldata-futures-audit-domain-0355",
    "calldata-futures-audit-domain-0356",
    "calldata-futures-audit-domain-0357",
    "calldata-futures-audit-domain-0358",
    "calldata-futures-audit-domain-0359",
    "calldata-futures-audit-domain-0360",
    "calldata-futures-audit-domain-0361",
    "calldata-futures-audit-domain-0362",
    "calldata-futures-audit-domain-0363",
    "calldata-futures-audit-domain-0364",
    "calldata-futures-audit-domain-0365",
    "calldata-futures-audit-domain-0366",
    "calldata-futures-audit-domain-0367",
    "calldata-futures-audit-domain-0368",
    "calldata-futures-audit-domain-0369",
    "calldata-futures-audit-domain-0370",
    "calldata-futures-audit-domain-0371",
    "calldata-futures-audit-domain-0372",
    "calldata-futures-audit-domain-0373",
    "calldata-futures-audit-domain-0374",
    "calldata-futures-audit-domain-0375",
    "calldata-futures-audit-domain-0376",
    "calldata-futures-audit-domain-0377",
    "calldata-futures-audit-domain-0378",
    "calldata-futures-audit-domain-0379",
    "calldata-futures-audit-domain-0380",
    "calldata-futures-audit-domain-0381",
    "calldata-futures-audit-domain-0382",
    "calldata-futures-audit-domain-0383",
    "calldata-futures-audit-domain-0384",
    "calldata-futures-audit-domain-0385",
    "calldata-futures-audit-domain-0386",
    "calldata-futures-audit-domain-0387",
    "calldata-futures-audit-domain-0388",
    "calldata-futures-audit-domain-0389",
    "calldata-futures-audit-domain-0390",
    "calldata-futures-audit-domain-0391",
    "calldata-futures-audit-domain-0392",
    "calldata-futures-audit-domain-0393",
    "calldata-futures-audit-domain-0394",
    "calldata-futures-audit-domain-0395",
    "calldata-futures-audit-domain-0396",
    "calldata-futures-audit-domain-0397",
    "calldata-futures-audit-domain-0398",
    "calldata-futures-audit-domain-0399",
    "calldata-futures-audit-domain-0400",
    "calldata-futures-audit-domain-0401",
    "calldata-futures-audit-domain-0402",
    "calldata-futures-audit-domain-0403",
    "calldata-futures-audit-domain-0404",
    "calldata-futures-audit-domain-0405",
    "calldata-futures-audit-domain-0406",
    "calldata-futures-audit-domain-0407",
    "calldata-futures-audit-domain-0408",
    "calldata-futures-audit-domain-0409",
    "calldata-futures-audit-domain-0410",
    "calldata-futures-audit-domain-0411",
    "calldata-futures-audit-domain-0412",
    "calldata-futures-audit-domain-0413",
    "calldata-futures-audit-domain-0414",
    "calldata-futures-audit-domain-0415",
    "calldata-futures-audit-domain-0416",
    "calldata-futures-audit-domain-0417",
    "calldata-futures-audit-domain-0418",
    "calldata-futures-audit-domain-0419",
    "calldata-futures-audit-domain-0420",
    "calldata-futures-audit-domain-0421",
    "calldata-futures-audit-domain-0422",
    "calldata-futures-audit-domain-0423",
    "calldata-futures-audit-domain-0424",
    "calldata-futures-audit-domain-0425",
    "calldata-futures-audit-domain-0426",
    "calldata-futures-audit-domain-0427",
    "calldata-futures-audit-domain-0428",
    "calldata-futures-audit-domain-0429",
    "calldata-futures-audit-domain-0430",
    "calldata-futures-audit-domain-0431",
    "calldata-futures-audit-domain-0432",
    "calldata-futures-audit-domain-0433",
    "calldata-futures-audit-domain-0434",
    "calldata-futures-audit-domain-0435",
    "calldata-futures-audit-domain-0436",
    "calldata-futures-audit-domain-0437",
    "calldata-futures-audit-domain-0438",
    "calldata-futures-audit-domain-0439",
    "calldata-futures-audit-domain-0440",
    "calldata-futures-audit-domain-0441",
    "calldata-futures-audit-domain-0442",
    "calldata-futures-audit-domain-0443",
    "calldata-futures-audit-domain-0444",
    "calldata-futures-audit-domain-0445",
    "calldata-futures-audit-domain-0446",
    "calldata-futures-audit-domain-0447",
    "calldata-futures-audit-domain-0448",
    "calldata-futures-audit-domain-0449",
    "calldata-futures-audit-domain-0450",
    "calldata-futures-audit-domain-0451",
    "calldata-futures-audit-domain-0452",
    "calldata-futures-audit-domain-0453",
    "calldata-futures-audit-domain-0454",
    "calldata-futures-audit-domain-0455",
    "calldata-futures-audit-domain-0456",
    "calldata-futures-audit-domain-0457",
    "calldata-futures-audit-domain-0458",
    "calldata-futures-audit-domain-0459",
    "calldata-futures-audit-domain-0460",
    "calldata-futures-audit-domain-0461",
    "calldata-futures-audit-domain-0462",
    "calldata-futures-audit-domain-0463",
    "calldata-futures-audit-domain-0464",
    "calldata-futures-audit-domain-0465",
    "calldata-futures-audit-domain-0466",
    "calldata-futures-audit-domain-0467",
    "calldata-futures-audit-domain-0468",
    "calldata-futures-audit-domain-0469",
    "calldata-futures-audit-domain-0470",
    "calldata-futures-audit-domain-0471",
    "calldata-futures-audit-domain-0472",
    "calldata-futures-audit-domain-0473",
    "calldata-futures-audit-domain-0474",
    "calldata-futures-audit-domain-0475",
    "calldata-futures-audit-domain-0476",
    "calldata-futures-audit-domain-0477",
    "calldata-futures-audit-domain-0478",
    "calldata-futures-audit-domain-0479",
    "calldata-futures-audit-domain-0480",
    "calldata-futures-audit-domain-0481",
    "calldata-futures-audit-domain-0482",
    "calldata-futures-audit-domain-0483",
    "calldata-futures-audit-domain-0484",
    "calldata-futures-audit-domain-0485",
    "calldata-futures-audit-domain-0486",
    "calldata-futures-audit-domain-0487",
    "calldata-futures-audit-domain-0488",
    "calldata-futures-audit-domain-0489",
    "calldata-futures-audit-domain-0490",
    "calldata-futures-audit-domain-0491",
    "calldata-futures-audit-domain-0492",
    "calldata-futures-audit-domain-0493",
    "calldata-futures-audit-domain-0494",
    "calldata-futures-audit-domain-0495",
    "calldata-futures-audit-domain-0496",
    "calldata-futures-audit-domain-0497",
    "calldata-futures-audit-domain-0498",
    "calldata-futures-audit-domain-0499",
    "calldata-futures-audit-domain-0500",
    "calldata-futures-audit-domain-0501",
    "calldata-futures-audit-domain-0502",
    "calldata-futures-audit-domain-0503",
    "calldata-futures-audit-domain-0504",
    "calldata-futures-audit-domain-0505",
    "calldata-futures-audit-domain-0506",
    "calldata-futures-audit-domain-0507",
    "calldata-futures-audit-domain-0508",
    "calldata-futures-audit-domain-0509",
    "calldata-futures-audit-domain-0510",
    "calldata-futures-audit-domain-0511",
    "calldata-futures-audit-domain-0512",
    "calldata-futures-audit-domain-0513",
    "calldata-futures-audit-domain-0514",
    "calldata-futures-audit-domain-0515",
    "calldata-futures-audit-domain-0516",
    "calldata-futures-audit-domain-0517",
    "calldata-futures-audit-domain-0518",
    "calldata-futures-audit-domain-0519",
    "calldata-futures-audit-domain-0520",
    "calldata-futures-audit-domain-0521",
    "calldata-futures-audit-domain-0522",
    "calldata-futures-audit-domain-0523",
    "calldata-futures-audit-domain-0524",
    "calldata-futures-audit-domain-0525",
    "calldata-futures-audit-domain-0526",
    "calldata-futures-audit-domain-0527",
    "calldata-futures-audit-domain-0528",
    "calldata-futures-audit-domain-0529",
    "calldata-futures-audit-domain-0530",
    "calldata-futures-audit-domain-0531",
    "calldata-futures-audit-domain-0532",
    "calldata-futures-audit-domain-0533",
    "calldata-futures-audit-domain-0534",
    "calldata-futures-audit-domain-0535",
    "calldata-futures-audit-domain-0536",
    "calldata-futures-audit-domain-0537",
    "calldata-futures-audit-domain-0538",
    "calldata-futures-audit-domain-0539",
    "calldata-futures-audit-domain-0540",
    "calldata-futures-audit-domain-0541",
    "calldata-futures-audit-domain-0542",
    "calldata-futures-audit-domain-0543",
    "calldata-futures-audit-domain-0544",
    "calldata-futures-audit-domain-0545",
    "calldata-futures-audit-domain-0546",
    "calldata-futures-audit-domain-0547",
    "calldata-futures-audit-domain-0548",
    "calldata-futures-audit-domain-0549",
    "calldata-futures-audit-domain-0550",
    "calldata-futures-audit-domain-0551",
    "calldata-futures-audit-domain-0552",
    "calldata-futures-audit-domain-0553",
    "calldata-futures-audit-domain-0554",
    "calldata-futures-audit-domain-0555",
    "calldata-futures-audit-domain-0556",
    "calldata-futures-audit-domain-0557",
    "calldata-futures-audit-domain-0558",
    "calldata-futures-audit-domain-0559",
    "calldata-futures-audit-domain-0560",
    "calldata-futures-audit-domain-0561",
    "calldata-futures-audit-domain-0562",
    "calldata-futures-audit-domain-0563",
    "calldata-futures-audit-domain-0564",
    "calldata-futures-audit-domain-0565",
    "calldata-futures-audit-domain-0566",
    "calldata-futures-audit-domain-0567",
    "calldata-futures-audit-domain-0568",
    "calldata-futures-audit-domain-0569",
    "calldata-futures-audit-domain-0570",
    "calldata-futures-audit-domain-0571",
    "calldata-futures-audit-domain-0572",
    "calldata-futures-audit-domain-0573",
    "calldata-futures-audit-domain-0574",
    "calldata-futures-audit-domain-0575",
    "calldata-futures-audit-domain-0576",
    "calldata-futures-audit-domain-0577",
    "calldata-futures-audit-domain-0578",
    "calldata-futures-audit-domain-0579",
    "calldata-futures-audit-domain-0580",
    "calldata-futures-audit-domain-0581",
    "calldata-futures-audit-domain-0582",
    "calldata-futures-audit-domain-0583",
    "calldata-futures-audit-domain-0584",
    "calldata-futures-audit-domain-0585",
    "calldata-futures-audit-domain-0586",
    "calldata-futures-audit-domain-0587",
    "calldata-futures-audit-domain-0588",
    "calldata-futures-audit-domain-0589",
    "calldata-futures-audit-domain-0590",
    "calldata-futures-audit-domain-0591",
    "calldata-futures-audit-domain-0592",
    "calldata-futures-audit-domain-0593",
    "calldata-futures-audit-domain-0594",
    "calldata-futures-audit-domain-0595",
    "calldata-futures-audit-domain-0596",
    "calldata-futures-audit-domain-0597",
    "calldata-futures-audit-domain-0598",
    "calldata-futures-audit-domain-0599",
    "calldata-futures-audit-domain-0600",
    "calldata-futures-audit-domain-0601",
    "calldata-futures-audit-domain-0602",
    "calldata-futures-audit-domain-0603",
    "calldata-futures-audit-domain-0604",
    "calldata-futures-audit-domain-0605",
    "calldata-futures-audit-domain-0606",
    "calldata-futures-audit-domain-0607",
    "calldata-futures-audit-domain-0608",
    "calldata-futures-audit-domain-0609",
    "calldata-futures-audit-domain-0610",
    "calldata-futures-audit-domain-0611",
    "calldata-futures-audit-domain-0612",
    "calldata-futures-audit-domain-0613",
    "calldata-futures-audit-domain-0614",
    "calldata-futures-audit-domain-0615",
    "calldata-futures-audit-domain-0616",
    "calldata-futures-audit-domain-0617",
    "calldata-futures-audit-domain-0618",
    "calldata-futures-audit-domain-0619",
    "calldata-futures-audit-domain-0620",
    "calldata-futures-audit-domain-0621",
    "calldata-futures-audit-domain-0622",
    "calldata-futures-audit-domain-0623",
    "calldata-futures-audit-domain-0624",
    "calldata-futures-audit-domain-0625",
    "calldata-futures-audit-domain-0626",
    "calldata-futures-audit-domain-0627",
    "calldata-futures-audit-domain-0628",
    "calldata-futures-audit-domain-0629",
    "calldata-futures-audit-domain-0630",
    "calldata-futures-audit-domain-0631",
    "calldata-futures-audit-domain-0632",
    "calldata-futures-audit-domain-0633",
    "calldata-futures-audit-domain-0634",
    "calldata-futures-audit-domain-0635",
    "calldata-futures-audit-domain-0636",
    "calldata-futures-audit-domain-0637",
    "calldata-futures-audit-domain-0638",
    "calldata-futures-audit-domain-0639",
    "calldata-futures-audit-domain-0640",
    "calldata-futures-audit-domain-0641",
    "calldata-futures-audit-domain-0642",
    "calldata-futures-audit-domain-0643",
    "calldata-futures-audit-domain-0644",
    "calldata-futures-audit-domain-0645",
    "calldata-futures-audit-domain-0646",
    "calldata-futures-audit-domain-0647",
    "calldata-futures-audit-domain-0648",
    "calldata-futures-audit-domain-0649",
    "calldata-futures-audit-domain-0650",
    "calldata-futures-audit-domain-0651",
    "calldata-futures-audit-domain-0652",
    "calldata-futures-audit-domain-0653",
    "calldata-futures-audit-domain-0654",
    "calldata-futures-audit-domain-0655",
    "calldata-futures-audit-domain-0656",
    "calldata-futures-audit-domain-0657",
    "calldata-futures-audit-domain-0658",
    "calldata-futures-audit-domain-0659",
    "calldata-futures-audit-domain-0660",
    "calldata-futures-audit-domain-0661",
    "calldata-futures-audit-domain-0662",
    "calldata-futures-audit-domain-0663",
    "calldata-futures-audit-domain-0664",
    "calldata-futures-audit-domain-0665",
    "calldata-futures-audit-domain-0666",
    "calldata-futures-audit-domain-0667",
    "calldata-futures-audit-domain-0668",
    "calldata-futures-audit-domain-0669",
    "calldata-futures-audit-domain-0670",
    "calldata-futures-audit-domain-0671",
    "calldata-futures-audit-domain-0672",
    "calldata-futures-audit-domain-0673",
    "calldata-futures-audit-domain-0674",
    "calldata-futures-audit-domain-0675",
    "calldata-futures-audit-domain-0676",
    "calldata-futures-audit-domain-0677",
    "calldata-futures-audit-domain-0678",
    "calldata-futures-audit-domain-0679",
    "calldata-futures-audit-domain-0680",
    "calldata-futures-audit-domain-0681",
    "calldata-futures-audit-domain-0682",
    "calldata-futures-audit-domain-0683",
    "calldata-futures-audit-domain-0684",
    "calldata-futures-audit-domain-0685",
    "calldata-futures-audit-domain-0686",
    "calldata-futures-audit-domain-0687",
    "calldata-futures-audit-domain-0688",
    "calldata-futures-audit-domain-0689",
    "calldata-futures-audit-domain-0690",
    "calldata-futures-audit-domain-0691",
    "calldata-futures-audit-domain-0692",
    "calldata-futures-audit-domain-0693",
    "calldata-futures-audit-domain-0694",
    "calldata-futures-audit-domain-0695",
    "calldata-futures-audit-domain-0696",
    "calldata-futures-audit-domain-0697",
    "calldata-futures-audit-domain-0698",
    "calldata-futures-audit-domain-0699",
    "calldata-futures-audit-domain-0700",
    "calldata-futures-audit-domain-0701",
    "calldata-futures-audit-domain-0702",
    "calldata-futures-audit-domain-0703",
    "calldata-futures-audit-domain-0704",
    "calldata-futures-audit-domain-0705",
    "calldata-futures-audit-domain-0706",
    "calldata-futures-audit-domain-0707",
    "calldata-futures-audit-domain-0708",
    "calldata-futures-audit-domain-0709",
    "calldata-futures-audit-domain-0710",
    "calldata-futures-audit-domain-0711",
    "calldata-futures-audit-domain-0712",
    "calldata-futures-audit-domain-0713",
    "calldata-futures-audit-domain-0714",
    "calldata-futures-audit-domain-0715",
    "calldata-futures-audit-domain-0716",
    "calldata-futures-audit-domain-0717",
    "calldata-futures-audit-domain-0718",
    "calldata-futures-audit-domain-0719",
    "calldata-futures-audit-domain-0720",
    "calldata-futures-audit-domain-0721",
    "calldata-futures-audit-domain-0722",
    "calldata-futures-audit-domain-0723",
    "calldata-futures-audit-domain-0724",
    "calldata-futures-audit-domain-0725",
    "calldata-futures-audit-domain-0726",
    "calldata-futures-audit-domain-0727",
    "calldata-futures-audit-domain-0728",
    "calldata-futures-audit-domain-0729",
    "calldata-futures-audit-domain-0730",
    "calldata-futures-audit-domain-0731",
    "calldata-futures-audit-domain-0732",
    "calldata-futures-audit-domain-0733",
    "calldata-futures-audit-domain-0734",
    "calldata-futures-audit-domain-0735",
    "calldata-futures-audit-domain-0736",
    "calldata-futures-audit-domain-0737",
    "calldata-futures-audit-domain-0738",
    "calldata-futures-audit-domain-0739",
    "calldata-futures-audit-domain-0740",
    "calldata-futures-audit-domain-0741",
    "calldata-futures-audit-domain-0742",
    "calldata-futures-audit-domain-0743",
    "calldata-futures-audit-domain-0744",
    "calldata-futures-audit-domain-0745",
    "calldata-futures-audit-domain-0746",
    "calldata-futures-audit-domain-0747",
    "calldata-futures-audit-domain-0748",
    "calldata-futures-audit-domain-0749",
    "calldata-futures-audit-domain-0750",
    "calldata-futures-audit-domain-0751",
    "calldata-futures-audit-domain-0752",
    "calldata-futures-audit-domain-0753",
    "calldata-futures-audit-domain-0754",
    "calldata-futures-audit-domain-0755",
    "calldata-futures-audit-domain-0756",
    "calldata-futures-audit-domain-0757",
    "calldata-futures-audit-domain-0758",
    "calldata-futures-audit-domain-0759",
    "calldata-futures-audit-domain-0760",
    "calldata-futures-audit-domain-0761",
    "calldata-futures-audit-domain-0762",
    "calldata-futures-audit-domain-0763",
    "calldata-futures-audit-domain-0764",
    "calldata-futures-audit-domain-0765",
    "calldata-futures-audit-domain-0766",
    "calldata-futures-audit-domain-0767",
    "calldata-futures-audit-domain-0768",
    "calldata-futures-audit-domain-0769",
    "calldata-futures-audit-domain-0770",
    "calldata-futures-audit-domain-0771",
    "calldata-futures-audit-domain-0772",
    "calldata-futures-audit-domain-0773",
    "calldata-futures-audit-domain-0774",
    "calldata-futures-audit-domain-0775",
    "calldata-futures-audit-domain-0776",
    "calldata-futures-audit-domain-0777",
    "calldata-futures-audit-domain-0778",
    "calldata-futures-audit-domain-0779",
    "calldata-futures-audit-domain-0780",
    "calldata-futures-audit-domain-0781",
    "calldata-futures-audit-domain-0782",
    "calldata-futures-audit-domain-0783",
    "calldata-futures-audit-domain-0784",
    "calldata-futures-audit-domain-0785",
    "calldata-futures-audit-domain-0786",
    "calldata-futures-audit-domain-0787",
    "calldata-futures-audit-domain-0788",
    "calldata-futures-audit-domain-0789",
    "calldata-futures-audit-domain-0790",
    "calldata-futures-audit-domain-0791",
    "calldata-futures-audit-domain-0792",
    "calldata-futures-audit-domain-0793",
    "calldata-futures-audit-domain-0794",
    "calldata-futures-audit-domain-0795",
    "calldata-futures-audit-domain-0796",
    "calldata-futures-audit-domain-0797",
    "calldata-futures-audit-domain-0798",
    "calldata-futures-audit-domain-0799",
    "calldata-futures-audit-domain-0800",
    "calldata-futures-audit-domain-0801",
    "calldata-futures-audit-domain-0802",
    "calldata-futures-audit-domain-0803",
    "calldata-futures-audit-domain-0804",
    "calldata-futures-audit-domain-0805",
    "calldata-futures-audit-domain-0806",
    "calldata-futures-audit-domain-0807",
    "calldata-futures-audit-domain-0808",
    "calldata-futures-audit-domain-0809",
    "calldata-futures-audit-domain-0810",
    "calldata-futures-audit-domain-0811",
    "calldata-futures-audit-domain-0812",
    "calldata-futures-audit-domain-0813",
    "calldata-futures-audit-domain-0814",
    "calldata-futures-audit-domain-0815",
    "calldata-futures-audit-domain-0816",
    "calldata-futures-audit-domain-0817",
    "calldata-futures-audit-domain-0818",
    "calldata-futures-audit-domain-0819",
    "calldata-futures-audit-domain-0820",
    "calldata-futures-audit-domain-0821",
    "calldata-futures-audit-domain-0822",
    "calldata-futures-audit-domain-0823",
    "calldata-futures-audit-domain-0824",
    "calldata-futures-audit-domain-0825",
    "calldata-futures-audit-domain-0826",
    "calldata-futures-audit-domain-0827",
    "calldata-futures-audit-domain-0828",
    "calldata-futures-audit-domain-0829",
    "calldata-futures-audit-domain-0830",
    "calldata-futures-audit-domain-0831",
    "calldata-futures-audit-domain-0832",
    "calldata-futures-audit-domain-0833",
    "calldata-futures-audit-domain-0834",
    "calldata-futures-audit-domain-0835",
    "calldata-futures-audit-domain-0836",
    "calldata-futures-audit-domain-0837",
    "calldata-futures-audit-domain-0838",
    "calldata-futures-audit-domain-0839",
    "calldata-futures-audit-domain-0840",
    "calldata-futures-audit-domain-0841",
    "calldata-futures-audit-domain-0842",
    "calldata-futures-audit-domain-0843",
    "calldata-futures-audit-domain-0844",
    "calldata-futures-audit-domain-0845",
    "calldata-futures-audit-domain-0846",
    "calldata-futures-audit-domain-0847",
    "calldata-futures-audit-domain-0848",
    "calldata-futures-audit-domain-0849",
    "calldata-futures-audit-domain-0850",
    "calldata-futures-audit-domain-0851",
    "calldata-futures-audit-domain-0852",
    "calldata-futures-audit-domain-0853",
    "calldata-futures-audit-domain-0854",
    "calldata-futures-audit-domain-0855",
    "calldata-futures-audit-domain-0856",
    "calldata-futures-audit-domain-0857",
    "calldata-futures-audit-domain-0858",
    "calldata-futures-audit-domain-0859",
    "calldata-futures-audit-domain-0860",
    "calldata-futures-audit-domain-0861",
    "calldata-futures-audit-domain-0862",
    "calldata-futures-audit-domain-0863",
    "calldata-futures-audit-domain-0864",
    "calldata-futures-audit-domain-0865",
    "calldata-futures-audit-domain-0866",
    "calldata-futures-audit-domain-0867",
    "calldata-futures-audit-domain-0868",
    "calldata-futures-audit-domain-0869",
    "calldata-futures-audit-domain-0870",
    "calldata-futures-audit-domain-0871",
    "calldata-futures-audit-domain-0872",
    "calldata-futures-audit-domain-0873",
    "calldata-futures-audit-domain-0874",
    "calldata-futures-audit-domain-0875",
    "calldata-futures-audit-domain-0876",
    "calldata-futures-audit-domain-0877",
    "calldata-futures-audit-domain-0878",
    "calldata-futures-audit-domain-0879",
    "calldata-futures-audit-domain-0880",
    "calldata-futures-audit-domain-0881",
    "calldata-futures-audit-domain-0882",
    "calldata-futures-audit-domain-0883",
    "calldata-futures-audit-domain-0884",
    "calldata-futures-audit-domain-0885",
    "calldata-futures-audit-domain-0886",
    "calldata-futures-audit-domain-0887",
    "calldata-futures-audit-domain-0888",
    "calldata-futures-audit-domain-0889",
    "calldata-futures-audit-domain-0890",
    "calldata-futures-audit-domain-0891",
    "calldata-futures-audit-domain-0892",
    "calldata-futures-audit-domain-0893",
    "calldata-futures-audit-domain-0894",
    "calldata-futures-audit-domain-0895",
    "calldata-futures-audit-domain-0896",
    "calldata-futures-audit-domain-0897",
    "calldata-futures-audit-domain-0898",
    "calldata-futures-audit-domain-0899",
    "calldata-futures-audit-domain-0900",
    "calldata-futures-audit-domain-0901",
    "calldata-futures-audit-domain-0902",
    "calldata-futures-audit-domain-0903",
    "calldata-futures-audit-domain-0904",
    "calldata-futures-audit-domain-0905",
    "calldata-futures-audit-domain-0906",
    "calldata-futures-audit-domain-0907",
    "calldata-futures-audit-domain-0908",
    "calldata-futures-audit-domain-0909",
    "calldata-futures-audit-domain-0910",
    "calldata-futures-audit-domain-0911",
    "calldata-futures-audit-domain-0912",
    "calldata-futures-audit-domain-0913",
    "calldata-futures-audit-domain-0914",
    "calldata-futures-audit-domain-0915",
    "calldata-futures-audit-domain-0916",
    "calldata-futures-audit-domain-0917",
    "calldata-futures-audit-domain-0918",
    "calldata-futures-audit-domain-0919",
    "calldata-futures-audit-domain-0920",
    "calldata-futures-audit-domain-0921",
    "calldata-futures-audit-domain-0922",
    "calldata-futures-audit-domain-0923",
    "calldata-futures-audit-domain-0924",
    "calldata-futures-audit-domain-0925",
    "calldata-futures-audit-domain-0926",
    "calldata-futures-audit-domain-0927",
    "calldata-futures-audit-domain-0928",
    "calldata-futures-audit-domain-0929",
    "calldata-futures-audit-domain-0930",
    "calldata-futures-audit-domain-0931",
    "calldata-futures-audit-domain-0932",
    "calldata-futures-audit-domain-0933",
    "calldata-futures-audit-domain-0934",
    "calldata-futures-audit-domain-0935",
    "calldata-futures-audit-domain-0936",
    "calldata-futures-audit-domain-0937",
    "calldata-futures-audit-domain-0938",
    "calldata-futures-audit-domain-0939",
    "calldata-futures-audit-domain-0940",
    "calldata-futures-audit-domain-0941",
    "calldata-futures-audit-domain-0942",
    "calldata-futures-audit-domain-0943",
    "calldata-futures-audit-domain-0944",
    "calldata-futures-audit-domain-0945",
    "calldata-futures-audit-domain-0946",
    "calldata-futures-audit-domain-0947",
    "calldata-futures-audit-domain-0948",
    "calldata-futures-audit-domain-0949",
    "calldata-futures-audit-domain-0950",
    "calldata-futures-audit-domain-0951",
    "calldata-futures-audit-domain-0952",
    "calldata-futures-audit-domain-0953",
    "calldata-futures-audit-domain-0954",
    "calldata-futures-audit-domain-0955",
    "calldata-futures-audit-domain-0956",
    "calldata-futures-audit-domain-0957",
    "calldata-futures-audit-domain-0958",
    "calldata-futures-audit-domain-0959",
    "calldata-futures-audit-domain-0960",
    "calldata-futures-audit-domain-0961",
    "calldata-futures-audit-domain-0962",
    "calldata-futures-audit-domain-0963",
    "calldata-futures-audit-domain-0964",
    "calldata-futures-audit-domain-0965",
    "calldata-futures-audit-domain-0966",
    "calldata-futures-audit-domain-0967",
    "calldata-futures-audit-domain-0968",
    "calldata-futures-audit-domain-0969",
    "calldata-futures-audit-domain-0970",
    "calldata-futures-audit-domain-0971",
    "calldata-futures-audit-domain-0972",
    "calldata-futures-audit-domain-0973",
    "calldata-futures-audit-domain-0974",
    "calldata-futures-audit-domain-0975",
    "calldata-futures-audit-domain-0976",
    "calldata-futures-audit-domain-0977",
    "calldata-futures-audit-domain-0978",
    "calldata-futures-audit-domain-0979",
    "calldata-futures-audit-domain-0980",
    "calldata-futures-audit-domain-0981",
    "calldata-futures-audit-domain-0982",
    "calldata-futures-audit-domain-0983",
    "calldata-futures-audit-domain-0984",
    "calldata-futures-audit-domain-0985",
    "calldata-futures-audit-domain-0986",
    "calldata-futures-audit-domain-0987",
    "calldata-futures-audit-domain-0988",
    "calldata-futures-audit-domain-0989",
    "calldata-futures-audit-domain-0990",
    "calldata-futures-audit-domain-0991",
    "calldata-futures-audit-domain-0992",
    "calldata-futures-audit-domain-0993",
    "calldata-futures-audit-domain-0994",
    "calldata-futures-audit-domain-0995",
    "calldata-futures-audit-domain-0996",
    "calldata-futures-audit-domain-0997",
    "calldata-futures-audit-domain-0998",
    "calldata-futures-audit-domain-0999",
    "calldata-futures-audit-domain-1000",
    "calldata-futures-audit-domain-1001",
    "calldata-futures-audit-domain-1002",
    "calldata-futures-audit-domain-1003",
    "calldata-futures-audit-domain-1004",
    "calldata-futures-audit-domain-1005",
    "calldata-futures-audit-domain-1006",
    "calldata-futures-audit-domain-1007",
    "calldata-futures-audit-domain-1008",
    "calldata-futures-audit-domain-1009",
    "calldata-futures-audit-domain-1010",
    "calldata-futures-audit-domain-1011",
    "calldata-futures-audit-domain-1012",
    "calldata-futures-audit-domain-1013",
    "calldata-futures-audit-domain-1014",
    "calldata-futures-audit-domain-1015",
    "calldata-futures-audit-domain-1016",
    "calldata-futures-audit-domain-1017",
    "calldata-futures-audit-domain-1018",
    "calldata-futures-audit-domain-1019",
    "calldata-futures-audit-domain-1020",
    "calldata-futures-audit-domain-1021",
    "calldata-futures-audit-domain-1022",
    "calldata-futures-audit-domain-1023",
    "calldata-futures-audit-domain-1024",
    "calldata-futures-audit-domain-1025",
    "calldata-futures-audit-domain-1026",
    "calldata-futures-audit-domain-1027",
    "calldata-futures-audit-domain-1028",
    "calldata-futures-audit-domain-1029",
    "calldata-futures-audit-domain-1030",
    "calldata-futures-audit-domain-1031",
    "calldata-futures-audit-domain-1032",
    "calldata-futures-audit-domain-1033",
    "calldata-futures-audit-domain-1034",
    "calldata-futures-audit-domain-1035",
    "calldata-futures-audit-domain-1036",
    "calldata-futures-audit-domain-1037",
    "calldata-futures-audit-domain-1038",
    "calldata-futures-audit-domain-1039",
    "calldata-futures-audit-domain-1040",
    "calldata-futures-audit-domain-1041",
    "calldata-futures-audit-domain-1042",
    "calldata-futures-audit-domain-1043",
    "calldata-futures-audit-domain-1044",
    "calldata-futures-audit-domain-1045",
    "calldata-futures-audit-domain-1046",
    "calldata-futures-audit-domain-1047",
    "calldata-futures-audit-domain-1048",
    "calldata-futures-audit-domain-1049",
    "calldata-futures-audit-domain-1050",
    "calldata-futures-audit-domain-1051",
    "calldata-futures-audit-domain-1052",
    "calldata-futures-audit-domain-1053",
    "calldata-futures-audit-domain-1054",
    "calldata-futures-audit-domain-1055",
    "calldata-futures-audit-domain-1056",
    "calldata-futures-audit-domain-1057",
    "calldata-futures-audit-domain-1058",
    "calldata-futures-audit-domain-1059",
    "calldata-futures-audit-domain-1060",
    "calldata-futures-audit-domain-1061",
    "calldata-futures-audit-domain-1062",
    "calldata-futures-audit-domain-1063",
    "calldata-futures-audit-domain-1064",
    "calldata-futures-audit-domain-1065",
    "calldata-futures-audit-domain-1066",
    "calldata-futures-audit-domain-1067",
    "calldata-futures-audit-domain-1068",
    "calldata-futures-audit-domain-1069",
    "calldata-futures-audit-domain-1070",
    "calldata-futures-audit-domain-1071",
    "calldata-futures-audit-domain-1072",
    "calldata-futures-audit-domain-1073",
    "calldata-futures-audit-domain-1074",
    "calldata-futures-audit-domain-1075",
    "calldata-futures-audit-domain-1076",
    "calldata-futures-audit-domain-1077",
    "calldata-futures-audit-domain-1078",
    "calldata-futures-audit-domain-1079",
    "calldata-futures-audit-domain-1080",
    "calldata-futures-audit-domain-1081",
    "calldata-futures-audit-domain-1082",
    "calldata-futures-audit-domain-1083",
    "calldata-futures-audit-domain-1084",
    "calldata-futures-audit-domain-1085",
    "calldata-futures-audit-domain-1086",
    "calldata-futures-audit-domain-1087",
    "calldata-futures-audit-domain-1088",
    "calldata-futures-audit-domain-1089",
    "calldata-futures-audit-domain-1090",
    "calldata-futures-audit-domain-1091",
    "calldata-futures-audit-domain-1092",
    "calldata-futures-audit-domain-1093",
    "calldata-futures-audit-domain-1094",
    "calldata-futures-audit-domain-1095",
    "calldata-futures-audit-domain-1096",
    "calldata-futures-audit-domain-1097",
    "calldata-futures-audit-domain-1098",
    "calldata-futures-audit-domain-1099",
    "calldata-futures-audit-domain-1100",
    "calldata-futures-audit-domain-1101",
    "calldata-futures-audit-domain-1102",
    "calldata-futures-audit-domain-1103",
    "calldata-futures-audit-domain-1104",
    "calldata-futures-audit-domain-1105",
    "calldata-futures-audit-domain-1106",
    "calldata-futures-audit-domain-1107",
    "calldata-futures-audit-domain-1108",
    "calldata-futures-audit-domain-1109",
    "calldata-futures-audit-domain-1110",
    "calldata-futures-audit-domain-1111",
    "calldata-futures-audit-domain-1112",
    "calldata-futures-audit-domain-1113",
    "calldata-futures-audit-domain-1114",
    "calldata-futures-audit-domain-1115",
    "calldata-futures-audit-domain-1116",
    "calldata-futures-audit-domain-1117",
    "calldata-futures-audit-domain-1118",
    "calldata-futures-audit-domain-1119",
    "calldata-futures-audit-domain-1120",
    "calldata-futures-audit-domain-1121",
    "calldata-futures-audit-domain-1122",
    "calldata-futures-audit-domain-1123",
    "calldata-futures-audit-domain-1124",
    "calldata-futures-audit-domain-1125",
    "calldata-futures-audit-domain-1126",
    "calldata-futures-audit-domain-1127",
    "calldata-futures-audit-domain-1128",
    "calldata-futures-audit-domain-1129",
    "calldata-futures-audit-domain-1130",
    "calldata-futures-audit-domain-1131",
    "calldata-futures-audit-domain-1132",
    "calldata-futures-audit-domain-1133",
    "calldata-futures-audit-domain-1134",
    "calldata-futures-audit-domain-1135",
    "calldata-futures-audit-domain-1136",
    "calldata-futures-audit-domain-1137",
    "calldata-futures-audit-domain-1138",
    "calldata-futures-audit-domain-1139",
    "calldata-futures-audit-domain-1140",
    "calldata-futures-audit-domain-1141",
    "calldata-futures-audit-domain-1142",
    "calldata-futures-audit-domain-1143",
    "calldata-futures-audit-domain-1144",
    "calldata-futures-audit-domain-1145",
    "calldata-futures-audit-domain-1146",
    "calldata-futures-audit-domain-1147",
    "calldata-futures-audit-domain-1148",
    "calldata-futures-audit-domain-1149",
    "calldata-futures-audit-domain-1150",
    "calldata-futures-audit-domain-1151",
    "calldata-futures-audit-domain-1152",
    "calldata-futures-audit-domain-1153",
    "calldata-futures-audit-domain-1154",
    "calldata-futures-audit-domain-1155",
    "calldata-futures-audit-domain-1156",
    "calldata-futures-audit-domain-1157",
    "calldata-futures-audit-domain-1158",
    "calldata-futures-audit-domain-1159",
    "calldata-futures-audit-domain-1160",
    "calldata-futures-audit-domain-1161",
    "calldata-futures-audit-domain-1162",
    "calldata-futures-audit-domain-1163",
    "calldata-futures-audit-domain-1164",
    "calldata-futures-audit-domain-1165",
    "calldata-futures-audit-domain-1166",
    "calldata-futures-audit-domain-1167",
    "calldata-futures-audit-domain-1168",
    "calldata-futures-audit-domain-1169",
    "calldata-futures-audit-domain-1170",
    "calldata-futures-audit-domain-1171",
    "calldata-futures-audit-domain-1172",
    "calldata-futures-audit-domain-1173",
    "calldata-futures-audit-domain-1174",
    "calldata-futures-audit-domain-1175",
    "calldata-futures-audit-domain-1176",
    "calldata-futures-audit-domain-1177",
    "calldata-futures-audit-domain-1178",
    "calldata-futures-audit-domain-1179",
    "calldata-futures-audit-domain-1180",
    "calldata-futures-audit-domain-1181",
    "calldata-futures-audit-domain-1182",
    "calldata-futures-audit-domain-1183",
    "calldata-futures-audit-domain-1184",
    "calldata-futures-audit-domain-1185",
    "calldata-futures-audit-domain-1186",
    "calldata-futures-audit-domain-1187",
    "calldata-futures-audit-domain-1188",
    "calldata-futures-audit-domain-1189",
    "calldata-futures-audit-domain-1190",
    "calldata-futures-audit-domain-1191",
    "calldata-futures-audit-domain-1192",
    "calldata-futures-audit-domain-1193",
    "calldata-futures-audit-domain-1194",
    "calldata-futures-audit-domain-1195",
    "calldata-futures-audit-domain-1196",
    "calldata-futures-audit-domain-1197",
    "calldata-futures-audit-domain-1198",
    "calldata-futures-audit-domain-1199",
    "calldata-futures-audit-domain-1200",
    "calldata-futures-audit-domain-1201",
    "calldata-futures-audit-domain-1202",
    "calldata-futures-audit-domain-1203",
    "calldata-futures-audit-domain-1204",
    "calldata-futures-audit-domain-1205",
    "calldata-futures-audit-domain-1206",
    "calldata-futures-audit-domain-1207",
    "calldata-futures-audit-domain-1208",
    "calldata-futures-audit-domain-1209",
    "calldata-futures-audit-domain-1210",
    "calldata-futures-audit-domain-1211",
    "calldata-futures-audit-domain-1212",
    "calldata-futures-audit-domain-1213",
    "calldata-futures-audit-domain-1214",
    "calldata-futures-audit-domain-1215",
    "calldata-futures-audit-domain-1216",
    "calldata-futures-audit-domain-1217",
    "calldata-futures-audit-domain-1218",
    "calldata-futures-audit-domain-1219",
    "calldata-futures-audit-domain-1220",
    "calldata-futures-audit-domain-1221",
    "calldata-futures-audit-domain-1222",
    "calldata-futures-audit-domain-1223",
    "calldata-futures-audit-domain-1224",
    "calldata-futures-audit-domain-1225",
    "calldata-futures-audit-domain-1226",
    "calldata-futures-audit-domain-1227",
    "calldata-futures-audit-domain-1228",
    "calldata-futures-audit-domain-1229",
    "calldata-futures-audit-domain-1230",
    "calldata-futures-audit-domain-1231",
    "calldata-futures-audit-domain-1232",
    "calldata-futures-audit-domain-1233",
    "calldata-futures-audit-domain-1234",
    "calldata-futures-audit-domain-1235",
    "calldata-futures-audit-domain-1236",
    "calldata-futures-audit-domain-1237",
    "calldata-futures-audit-domain-1238",
    "calldata-futures-audit-domain-1239",
    "calldata-futures-audit-domain-1240",
    "calldata-futures-audit-domain-1241",
    "calldata-futures-audit-domain-1242",
    "calldata-futures-audit-domain-1243",
    "calldata-futures-audit-domain-1244",
    "calldata-futures-audit-domain-1245",
    "calldata-futures-audit-domain-1246",
    "calldata-futures-audit-domain-1247",
    "calldata-futures-audit-domain-1248",
    "calldata-futures-audit-domain-1249",
    "calldata-futures-audit-domain-1250",
    "calldata-futures-audit-domain-1251",
    "calldata-futures-audit-domain-1252",
    "calldata-futures-audit-domain-1253",
    "calldata-futures-audit-domain-1254",
    "calldata-futures-audit-domain-1255",
    "calldata-futures-audit-domain-1256",
    "calldata-futures-audit-domain-1257",
    "calldata-futures-audit-domain-1258",
    "calldata-futures-audit-domain-1259",
    "calldata-futures-audit-domain-1260",
    "calldata-futures-audit-domain-1261",
    "calldata-futures-audit-domain-1262",
    "calldata-futures-audit-domain-1263",
    "calldata-futures-audit-domain-1264",
    "calldata-futures-audit-domain-1265",
    "calldata-futures-audit-domain-1266",
    "calldata-futures-audit-domain-1267",
    "calldata-futures-audit-domain-1268",
    "calldata-futures-audit-domain-1269",
    "calldata-futures-audit-domain-1270",
    "calldata-futures-audit-domain-1271",
    "calldata-futures-audit-domain-1272",
    "calldata-futures-audit-domain-1273",
    "calldata-futures-audit-domain-1274",
    "calldata-futures-audit-domain-1275",
    "calldata-futures-audit-domain-1276",
    "calldata-futures-audit-domain-1277",
    "calldata-futures-audit-domain-1278",
    "calldata-futures-audit-domain-1279",
    "calldata-futures-audit-domain-1280",
    "calldata-futures-audit-domain-1281",
    "calldata-futures-audit-domain-1282",
    "calldata-futures-audit-domain-1283",
    "calldata-futures-audit-domain-1284",
    "calldata-futures-audit-domain-1285",
    "calldata-futures-audit-domain-1286",
    "calldata-futures-audit-domain-1287",
    "calldata-futures-audit-domain-1288",
    "calldata-futures-audit-domain-1289",
    "calldata-futures-audit-domain-1290",
    "calldata-futures-audit-domain-1291",
    "calldata-futures-audit-domain-1292",
    "calldata-futures-audit-domain-1293",
    "calldata-futures-audit-domain-1294",
    "calldata-futures-audit-domain-1295",
    "calldata-futures-audit-domain-1296",
    "calldata-futures-audit-domain-1297",
    "calldata-futures-audit-domain-1298",
    "calldata-futures-audit-domain-1299",
    "calldata-futures-audit-domain-1300",
    "calldata-futures-audit-domain-1301",
    "calldata-futures-audit-domain-1302",
    "calldata-futures-audit-domain-1303",
    "calldata-futures-audit-domain-1304",
    "calldata-futures-audit-domain-1305",
    "calldata-futures-audit-domain-1306",
    "calldata-futures-audit-domain-1307",
    "calldata-futures-audit-domain-1308",
    "calldata-futures-audit-domain-1309",
    "calldata-futures-audit-domain-1310",
    "calldata-futures-audit-domain-1311",
    "calldata-futures-audit-domain-1312",
    "calldata-futures-audit-domain-1313",
    "calldata-futures-audit-domain-1314",
    "calldata-futures-audit-domain-1315",
    "calldata-futures-audit-domain-1316",
    "calldata-futures-audit-domain-1317",
    "calldata-futures-audit-domain-1318",
    "calldata-futures-audit-domain-1319",
    "calldata-futures-audit-domain-1320",
    "calldata-futures-audit-domain-1321",
    "calldata-futures-audit-domain-1322",
    "calldata-futures-audit-domain-1323",
    "calldata-futures-audit-domain-1324",
    "calldata-futures-audit-domain-1325",
    "calldata-futures-audit-domain-1326",
    "calldata-futures-audit-domain-1327",
    "calldata-futures-audit-domain-1328",
    "calldata-futures-audit-domain-1329",
    "calldata-futures-audit-domain-1330",
    "calldata-futures-audit-domain-1331",
    "calldata-futures-audit-domain-1332",
    "calldata-futures-audit-domain-1333",
    "calldata-futures-audit-domain-1334",
    "calldata-futures-audit-domain-1335",
    "calldata-futures-audit-domain-1336",
    "calldata-futures-audit-domain-1337",
    "calldata-futures-audit-domain-1338",
    "calldata-futures-audit-domain-1339",
    "calldata-futures-audit-domain-1340",
    "calldata-futures-audit-domain-1341",
    "calldata-futures-audit-domain-1342",
    "calldata-futures-audit-domain-1343",
    "calldata-futures-audit-domain-1344",
    "calldata-futures-audit-domain-1345",
    "calldata-futures-audit-domain-1346",
    "calldata-futures-audit-domain-1347",
    "calldata-futures-audit-domain-1348",
    "calldata-futures-audit-domain-1349",
    "calldata-futures-audit-domain-1350",
    "calldata-futures-audit-domain-1351",
    "calldata-futures-audit-domain-1352",
    "calldata-futures-audit-domain-1353",
    "calldata-futures-audit-domain-1354",
    "calldata-futures-audit-domain-1355",
    "calldata-futures-audit-domain-1356",
    "calldata-futures-audit-domain-1357",
    "calldata-futures-audit-domain-1358",
    "calldata-futures-audit-domain-1359",
    "calldata-futures-audit-domain-1360",
    "calldata-futures-audit-domain-1361",
    "calldata-futures-audit-domain-1362",
    "calldata-futures-audit-domain-1363",
    "calldata-futures-audit-domain-1364",
    "calldata-futures-audit-domain-1365",
    "calldata-futures-audit-domain-1366",
    "calldata-futures-audit-domain-1367",
    "calldata-futures-audit-domain-1368",
    "calldata-futures-audit-domain-1369",
    "calldata-futures-audit-domain-1370",
    "calldata-futures-audit-domain-1371",
    "calldata-futures-audit-domain-1372",
    "calldata-futures-audit-domain-1373",
    "calldata-futures-audit-domain-1374",
    "calldata-futures-audit-domain-1375",
    "calldata-futures-audit-domain-1376",
    "calldata-futures-audit-domain-1377",
    "calldata-futures-audit-domain-1378",
    "calldata-futures-audit-domain-1379",
    "calldata-futures-audit-domain-1380",
    "calldata-futures-audit-domain-1381",
    "calldata-futures-audit-domain-1382",
    "calldata-futures-audit-domain-1383",
    "calldata-futures-audit-domain-1384",
    "calldata-futures-audit-domain-1385",
    "calldata-futures-audit-domain-1386",
    "calldata-futures-audit-domain-1387",
    "calldata-futures-audit-domain-1388",
    "calldata-futures-audit-domain-1389",
    "calldata-futures-audit-domain-1390",
    "calldata-futures-audit-domain-1391",
    "calldata-futures-audit-domain-1392",
    "calldata-futures-audit-domain-1393",
    "calldata-futures-audit-domain-1394",
    "calldata-futures-audit-domain-1395",
    "calldata-futures-audit-domain-1396",
    "calldata-futures-audit-domain-1397",
    "calldata-futures-audit-domain-1398",
    "calldata-futures-audit-domain-1399",
    "calldata-futures-audit-domain-1400",
    "calldata-futures-audit-domain-1401",
    "calldata-futures-audit-domain-1402",
    "calldata-futures-audit-domain-1403",
    "calldata-futures-audit-domain-1404",
    "calldata-futures-audit-domain-1405",
    "calldata-futures-audit-domain-1406",
    "calldata-futures-audit-domain-1407",
    "calldata-futures-audit-domain-1408",
    "calldata-futures-audit-domain-1409",
    "calldata-futures-audit-domain-1410",
    "calldata-futures-audit-domain-1411",
    "calldata-futures-audit-domain-1412",
    "calldata-futures-audit-domain-1413",
    "calldata-futures-audit-domain-1414",
    "calldata-futures-audit-domain-1415",
    "calldata-futures-audit-domain-1416",
    "calldata-futures-audit-domain-1417",
    "calldata-futures-audit-domain-1418",
    "calldata-futures-audit-domain-1419",
    "calldata-futures-audit-domain-1420",
    "calldata-futures-audit-domain-1421",
    "calldata-futures-audit-domain-1422",
    "calldata-futures-audit-domain-1423",
    "calldata-futures-audit-domain-1424",
    "calldata-futures-audit-domain-1425",
    "calldata-futures-audit-domain-1426",
    "calldata-futures-audit-domain-1427",
    "calldata-futures-audit-domain-1428",
    "calldata-futures-audit-domain-1429",
    "calldata-futures-audit-domain-1430",
    "calldata-futures-audit-domain-1431",
    "calldata-futures-audit-domain-1432",
    "calldata-futures-audit-domain-1433",
    "calldata-futures-audit-domain-1434",
    "calldata-futures-audit-domain-1435",
    "calldata-futures-audit-domain-1436",
    "calldata-futures-audit-domain-1437",
    "calldata-futures-audit-domain-1438",
    "calldata-futures-audit-domain-1439",
    "calldata-futures-audit-domain-1440",
    "calldata-futures-audit-domain-1441",
    "calldata-futures-audit-domain-1442",
    "calldata-futures-audit-domain-1443",
    "calldata-futures-audit-domain-1444",
    "calldata-futures-audit-domain-1445",
    "calldata-futures-audit-domain-1446",
    "calldata-futures-audit-domain-1447",
    "calldata-futures-audit-domain-1448",
    "calldata-futures-audit-domain-1449",
    "calldata-futures-audit-domain-1450",
    "calldata-futures-audit-domain-1451",
    "calldata-futures-audit-domain-1452",
    "calldata-futures-audit-domain-1453",
    "calldata-futures-audit-domain-1454",
    "calldata-futures-audit-domain-1455",
    "calldata-futures-audit-domain-1456",
    "calldata-futures-audit-domain-1457",
    "calldata-futures-audit-domain-1458",
    "calldata-futures-audit-domain-1459",
    "calldata-futures-audit-domain-1460",
    "calldata-futures-audit-domain-1461",
    "calldata-futures-audit-domain-1462",
    "calldata-futures-audit-domain-1463",
    "calldata-futures-audit-domain-1464",
    "calldata-futures-audit-domain-1465",
    "calldata-futures-audit-domain-1466",
    "calldata-futures-audit-domain-1467",
    "calldata-futures-audit-domain-1468",
    "calldata-futures-audit-domain-1469",
    "calldata-futures-audit-domain-1470",
    "calldata-futures-audit-domain-1471",
    "calldata-futures-audit-domain-1472",
    "calldata-futures-audit-domain-1473",
    "calldata-futures-audit-domain-1474",
    "calldata-futures-audit-domain-1475",
    "calldata-futures-audit-domain-1476",
    "calldata-futures-audit-domain-1477",
    "calldata-futures-audit-domain-1478",
    "calldata-futures-audit-domain-1479",
    "calldata-futures-audit-domain-1480",
    "calldata-futures-audit-domain-1481",
    "calldata-futures-audit-domain-1482",
    "calldata-futures-audit-domain-1483",
    "calldata-futures-audit-domain-1484",
    "calldata-futures-audit-domain-1485",
    "calldata-futures-audit-domain-1486",
    "calldata-futures-audit-domain-1487",
    "calldata-futures-audit-domain-1488",
    "calldata-futures-audit-domain-1489",
    "calldata-futures-audit-domain-1490",
    "calldata-futures-audit-domain-1491",
    "calldata-futures-audit-domain-1492",
    "calldata-futures-audit-domain-1493",
    "calldata-futures-audit-domain-1494",
    "calldata-futures-audit-domain-1495",
    "calldata-futures-audit-domain-1496",
    "calldata-futures-audit-domain-1497",
    "calldata-futures-audit-domain-1498",
    "calldata-futures-audit-domain-1499",
    "calldata-futures-audit-domain-1500",
    "calldata-futures-audit-domain-1501",
    "calldata-futures-audit-domain-1502",
    "calldata-futures-audit-domain-1503",
    "calldata-futures-audit-domain-1504",
    "calldata-futures-audit-domain-1505",
    "calldata-futures-audit-domain-1506",
    "calldata-futures-audit-domain-1507",
    "calldata-futures-audit-domain-1508",
    "calldata-futures-audit-domain-1509",
    "calldata-futures-audit-domain-1510",
    "calldata-futures-audit-domain-1511",
    "calldata-futures-audit-domain-1512",
    "calldata-futures-audit-domain-1513",
    "calldata-futures-audit-domain-1514",
    "calldata-futures-audit-domain-1515",
    "calldata-futures-audit-domain-1516",
    "calldata-futures-audit-domain-1517",
    "calldata-futures-audit-domain-1518",
    "calldata-futures-audit-domain-1519",
    "calldata-futures-audit-domain-1520",
    "calldata-futures-audit-domain-1521",
    "calldata-futures-audit-domain-1522",
    "calldata-futures-audit-domain-1523",
    "calldata-futures-audit-domain-1524",
    "calldata-futures-audit-domain-1525",
    "calldata-futures-audit-domain-1526",
    "calldata-futures-audit-domain-1527",
    "calldata-futures-audit-domain-1528",
    "calldata-futures-audit-domain-1529",
    "calldata-futures-audit-domain-1530",
    "calldata-futures-audit-domain-1531",
    "calldata-futures-audit-domain-1532",
    "calldata-futures-audit-domain-1533",
    "calldata-futures-audit-domain-1534",
    "calldata-futures-audit-domain-1535",
    "calldata-futures-audit-domain-1536",
    "calldata-futures-audit-domain-1537",
    "calldata-futures-audit-domain-1538",
    "calldata-futures-audit-domain-1539",
    "calldata-futures-audit-domain-1540",
    "calldata-futures-audit-domain-1541",
    "calldata-futures-audit-domain-1542",
    "calldata-futures-audit-domain-1543",
    "calldata-futures-audit-domain-1544",
    "calldata-futures-audit-domain-1545",
    "calldata-futures-audit-domain-1546",
    "calldata-futures-audit-domain-1547",
    "calldata-futures-audit-domain-1548",
    "calldata-futures-audit-domain-1549",
    "calldata-futures-audit-domain-1550",
    "calldata-futures-audit-domain-1551",
    "calldata-futures-audit-domain-1552",
    "calldata-futures-audit-domain-1553",
    "calldata-futures-audit-domain-1554",
    "calldata-futures-audit-domain-1555",
    "calldata-futures-audit-domain-1556",
    "calldata-futures-audit-domain-1557",
    "calldata-futures-audit-domain-1558",
    "calldata-futures-audit-domain-1559",
    "calldata-futures-audit-domain-1560",
    "calldata-futures-audit-domain-1561",
    "calldata-futures-audit-domain-1562",
    "calldata-futures-audit-domain-1563",
    "calldata-futures-audit-domain-1564",
    "calldata-futures-audit-domain-1565",
    "calldata-futures-audit-domain-1566",
    "calldata-futures-audit-domain-1567",
    "calldata-futures-audit-domain-1568",
    "calldata-futures-audit-domain-1569",
    "calldata-futures-audit-domain-1570",
    "calldata-futures-audit-domain-1571",
    "calldata-futures-audit-domain-1572",
    "calldata-futures-audit-domain-1573",
    "calldata-futures-audit-domain-1574",
    "calldata-futures-audit-domain-1575",
    "calldata-futures-audit-domain-1576",
    "calldata-futures-audit-domain-1577",
    "calldata-futures-audit-domain-1578",
    "calldata-futures-audit-domain-1579",
    "calldata-futures-audit-domain-1580",
    "calldata-futures-audit-domain-1581",
    "calldata-futures-audit-domain-1582",
    "calldata-futures-audit-domain-1583",
    "calldata-futures-audit-domain-1584",
    "calldata-futures-audit-domain-1585",
    "calldata-futures-audit-domain-1586",
    "calldata-futures-audit-domain-1587",
    "calldata-futures-audit-domain-1588",
    "calldata-futures-audit-domain-1589",
    "calldata-futures-audit-domain-1590",
    "calldata-futures-audit-domain-1591",
    "calldata-futures-audit-domain-1592",
    "calldata-futures-audit-domain-1593",
    "calldata-futures-audit-domain-1594",
    "calldata-futures-audit-domain-1595",
    "calldata-futures-audit-domain-1596",
    "calldata-futures-audit-domain-1597",
    "calldata-futures-audit-domain-1598",
    "calldata-futures-audit-domain-1599",
    "calldata-futures-audit-domain-1600",
    "calldata-futures-audit-domain-1601",
    "calldata-futures-audit-domain-1602",
    "calldata-futures-audit-domain-1603",
    "calldata-futures-audit-domain-1604",
    "calldata-futures-audit-domain-1605",
    "calldata-futures-audit-domain-1606",
    "calldata-futures-audit-domain-1607",
    "calldata-futures-audit-domain-1608",
    "calldata-futures-audit-domain-1609",
    "calldata-futures-audit-domain-1610",
    "calldata-futures-audit-domain-1611",
    "calldata-futures-audit-domain-1612",
    "calldata-futures-audit-domain-1613",
    "calldata-futures-audit-domain-1614",
    "calldata-futures-audit-domain-1615",
    "calldata-futures-audit-domain-1616",
    "calldata-futures-audit-domain-1617",
    "calldata-futures-audit-domain-1618",
    "calldata-futures-audit-domain-1619",
    "calldata-futures-audit-domain-1620",
    "calldata-futures-audit-domain-1621",
    "calldata-futures-audit-domain-1622",
    "calldata-futures-audit-domain-1623",
    "calldata-futures-audit-domain-1624",
    "calldata-futures-audit-domain-1625",
    "calldata-futures-audit-domain-1626",
    "calldata-futures-audit-domain-1627",
    "calldata-futures-audit-domain-1628",
    "calldata-futures-audit-domain-1629",
    "calldata-futures-audit-domain-1630",
    "calldata-futures-audit-domain-1631",
    "calldata-futures-audit-domain-1632",
    "calldata-futures-audit-domain-1633",
    "calldata-futures-audit-domain-1634",
    "calldata-futures-audit-domain-1635",
    "calldata-futures-audit-domain-1636",
    "calldata-futures-audit-domain-1637",
    "calldata-futures-audit-domain-1638",
    "calldata-futures-audit-domain-1639",
    "calldata-futures-audit-domain-1640",
    "calldata-futures-audit-domain-1641",
    "calldata-futures-audit-domain-1642",
    "calldata-futures-audit-domain-1643",
    "calldata-futures-audit-domain-1644",
    "calldata-futures-audit-domain-1645",
    "calldata-futures-audit-domain-1646",
    "calldata-futures-audit-domain-1647",
    "calldata-futures-audit-domain-1648",
    "calldata-futures-audit-domain-1649",
    "calldata-futures-audit-domain-1650",
    "calldata-futures-audit-domain-1651",
    "calldata-futures-audit-domain-1652",
    "calldata-futures-audit-domain-1653",
    "calldata-futures-audit-domain-1654",
    "calldata-futures-audit-domain-1655",
    "calldata-futures-audit-domain-1656",
    "calldata-futures-audit-domain-1657",
    "calldata-futures-audit-domain-1658",
    "calldata-futures-audit-domain-1659",
    "calldata-futures-audit-domain-1660",
    "calldata-futures-audit-domain-1661",
    "calldata-futures-audit-domain-1662",
    "calldata-futures-audit-domain-1663",
    "calldata-futures-audit-domain-1664",
    "calldata-futures-audit-domain-1665",
    "calldata-futures-audit-domain-1666",
    "calldata-futures-audit-domain-1667",
    "calldata-futures-audit-domain-1668",
    "calldata-futures-audit-domain-1669",
    "calldata-futures-audit-domain-1670",
    "calldata-futures-audit-domain-1671",
    "calldata-futures-audit-domain-1672",
    "calldata-futures-audit-domain-1673",
    "calldata-futures-audit-domain-1674",
    "calldata-futures-audit-domain-1675",
    "calldata-futures-audit-domain-1676",
    "calldata-futures-audit-domain-1677",
    "calldata-futures-audit-domain-1678",
    "calldata-futures-audit-domain-1679",
    "calldata-futures-audit-domain-1680",
    "calldata-futures-audit-domain-1681",
    "calldata-futures-audit-domain-1682",
    "calldata-futures-audit-domain-1683",
    "calldata-futures-audit-domain-1684",
    "calldata-futures-audit-domain-1685",
    "calldata-futures-audit-domain-1686",
    "calldata-futures-audit-domain-1687",
    "calldata-futures-audit-domain-1688",
    "calldata-futures-audit-domain-1689",
    "calldata-futures-audit-domain-1690",
    "calldata-futures-audit-domain-1691",
    "calldata-futures-audit-domain-1692",
    "calldata-futures-audit-domain-1693",
    "calldata-futures-audit-domain-1694",
    "calldata-futures-audit-domain-1695",
    "calldata-futures-audit-domain-1696",
    "calldata-futures-audit-domain-1697",
    "calldata-futures-audit-domain-1698",
    "calldata-futures-audit-domain-1699",
    "calldata-futures-audit-domain-1700",
    "calldata-futures-audit-domain-1701",
    "calldata-futures-audit-domain-1702",
    "calldata-futures-audit-domain-1703",
    "calldata-futures-audit-domain-1704",
    "calldata-futures-audit-domain-1705",
    "calldata-futures-audit-domain-1706",
    "calldata-futures-audit-domain-1707",
    "calldata-futures-audit-domain-1708",
    "calldata-futures-audit-domain-1709",
    "calldata-futures-audit-domain-1710",
    "calldata-futures-audit-domain-1711",
    "calldata-futures-audit-domain-1712",
    "calldata-futures-audit-domain-1713",
    "calldata-futures-audit-domain-1714",
    "calldata-futures-audit-domain-1715",
    "calldata-futures-audit-domain-1716",
    "calldata-futures-audit-domain-1717",
    "calldata-futures-audit-domain-1718",
    "calldata-futures-audit-domain-1719",
    "calldata-futures-audit-domain-1720",
    "calldata-futures-audit-domain-1721",
    "calldata-futures-audit-domain-1722",
    "calldata-futures-audit-domain-1723",
    "calldata-futures-audit-domain-1724",
    "calldata-futures-audit-domain-1725",
    "calldata-futures-audit-domain-1726",
    "calldata-futures-audit-domain-1727",
    "calldata-futures-audit-domain-1728",
    "calldata-futures-audit-domain-1729",
    "calldata-futures-audit-domain-1730",
    "calldata-futures-audit-domain-1731",
    "calldata-futures-audit-domain-1732",
    "calldata-futures-audit-domain-1733",
    "calldata-futures-audit-domain-1734",
    "calldata-futures-audit-domain-1735",
    "calldata-futures-audit-domain-1736",
    "calldata-futures-audit-domain-1737",
    "calldata-futures-audit-domain-1738",
    "calldata-futures-audit-domain-1739",
    "calldata-futures-audit-domain-1740",
    "calldata-futures-audit-domain-1741",
    "calldata-futures-audit-domain-1742",
    "calldata-futures-audit-domain-1743",
    "calldata-futures-audit-domain-1744",
    "calldata-futures-audit-domain-1745",
    "calldata-futures-audit-domain-1746",
    "calldata-futures-audit-domain-1747",
    "calldata-futures-audit-domain-1748",
    "calldata-futures-audit-domain-1749",
    "calldata-futures-audit-domain-1750",
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn devnet_roots_are_deterministic() {
        let left = State::devnet().state_root();
        let right = state_root_from_public_record(&devnet_public_record());
        assert_eq!(left, right);
    }
}
