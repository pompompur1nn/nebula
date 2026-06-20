use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeEncryptedBatchCallRouterRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-encrypted-batch-call-router-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_ENCRYPTION_SUITE: &str =
    "ml-kem-1024+x25519-hybrid-sealed-contract-call-v1";
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_PQ_SIGNATURE_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-router-attestation-v1";
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_BATCH_PROOF_SUITE: &str =
    "recursive-stark-private-batch-call-settlement-v1";
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_NULLIFIER_SUITE: &str =
    "zk-nullifier-fence-private-contract-call-v1";
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEVNET_HEIGHT: u64 = 971_000;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_LANES: usize = 96;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_CALLS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_DEPENDENCIES: usize =
    4_194_304;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_QUOTES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_VOUCHERS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    4_194_304;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_REBATES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 131_072;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS: u64 =
    9;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    8_750;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 10;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 8;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_CALL_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_LATENCY_MS: u64 =
    550;
pub const PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_CALLS: usize =
    8_192;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingLaneKind {
    DefiSwap,
    Lending,
    Perpetuals,
    Options,
    StableSwap,
    TokenTransfer,
    VaultStrategy,
    OracleThenCall,
    AccountAbstraction,
    MoneroBridge,
    SettlementHook,
    EmergencyEscape,
}

impl RoutingLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::StableSwap => "stable_swap",
            Self::TokenTransfer => "token_transfer",
            Self::VaultStrategy => "vault_strategy",
            Self::OracleThenCall => "oracle_then_call",
            Self::AccountAbstraction => "account_abstraction",
            Self::MoneroBridge => "monero_bridge",
            Self::SettlementHook => "settlement_hook",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::SettlementHook => 9_800,
            Self::MoneroBridge => 9_500,
            Self::Perpetuals => 9_100,
            Self::DefiSwap => 8_900,
            Self::StableSwap => 8_700,
            Self::OracleThenCall => 8_400,
            Self::Lending => 8_200,
            Self::Options => 8_000,
            Self::VaultStrategy => 7_700,
            Self::AccountAbstraction => 7_500,
            Self::TokenTransfer => 7_200,
        }
    }

    pub fn default_latency_target_ms(self) -> u64 {
        match self {
            Self::EmergencyEscape => 250,
            Self::SettlementHook => 350,
            Self::Perpetuals => 400,
            Self::DefiSwap | Self::StableSwap => 450,
            Self::MoneroBridge => 500,
            Self::OracleThenCall => 550,
            Self::Lending | Self::Options => 650,
            Self::VaultStrategy => 800,
            Self::AccountAbstraction => 900,
            Self::TokenTransfer => 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    SponsorOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_calls(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::SponsorOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    ConfidentialInvoke,
    MultiCall,
    AmmSwap,
    StableSwap,
    LendingSupply,
    LendingBorrow,
    VaultDeposit,
    VaultWithdraw,
    PerpOpen,
    PerpClose,
    OptionMint,
    TokenTransfer,
    OracleReadThenCall,
    BridgeLock,
    BridgeRelease,
    SettlementCallback,
}

impl CallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialInvoke => "confidential_invoke",
            Self::MultiCall => "multi_call",
            Self::AmmSwap => "amm_swap",
            Self::StableSwap => "stable_swap",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::OptionMint => "option_mint",
            Self::TokenTransfer => "token_transfer",
            Self::OracleReadThenCall => "oracle_read_then_call",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::SettlementCallback => "settlement_callback",
        }
    }

    pub fn defi_weight(self) -> u64 {
        match self {
            Self::SettlementCallback => 9_800,
            Self::BridgeRelease | Self::BridgeLock => 9_300,
            Self::PerpOpen | Self::PerpClose => 9_000,
            Self::AmmSwap | Self::StableSwap => 8_800,
            Self::LendingBorrow | Self::VaultWithdraw => 8_500,
            Self::OracleReadThenCall | Self::MultiCall => 8_100,
            Self::LendingSupply | Self::VaultDeposit => 7_700,
            Self::OptionMint => 7_400,
            Self::ConfidentialInvoke => 7_100,
            Self::TokenTransfer => 6_900,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    ReadAfterWrite,
    WriteAfterRead,
    WriteAfterWrite,
    NullifierOrdering,
    AssetConservation,
    OracleFreshness,
    PriceBound,
    CallbackOrdering,
    SponsorReservation,
    SettlementBarrier,
    PrivacyFence,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadAfterWrite => "read_after_write",
            Self::WriteAfterRead => "write_after_read",
            Self::WriteAfterWrite => "write_after_write",
            Self::NullifierOrdering => "nullifier_ordering",
            Self::AssetConservation => "asset_conservation",
            Self::OracleFreshness => "oracle_freshness",
            Self::PriceBound => "price_bound",
            Self::CallbackOrdering => "callback_ordering",
            Self::SponsorReservation => "sponsor_reservation",
            Self::SettlementBarrier => "settlement_barrier",
            Self::PrivacyFence => "privacy_fence",
        }
    }

    pub fn strict(self) -> bool {
        matches!(
            self,
            Self::WriteAfterWrite
                | Self::NullifierOrdering
                | Self::AssetConservation
                | Self::SponsorReservation
                | Self::SettlementBarrier
                | Self::PrivacyFence
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Submitted,
    DependencyChecked,
    Quoted,
    Reserved,
    Batched,
    Executed,
    Settled,
    Rebated,
    Expired,
    Rejected,
}

impl CallStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::DependencyChecked
                | Self::Quoted
                | Self::Reserved
                | Self::Batched
                | Self::Executed
        )
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
    Slashed,
}

impl QuoteStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Open,
    Reserved,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Planned,
    Sealed,
    Proved,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    Finalized,
    Reverted,
    Challenged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encryption_suite: String,
    pub pq_signature_suite: String,
    pub batch_proof_suite: String,
    pub nullifier_suite: String,
    pub max_lanes: usize,
    pub max_calls: usize,
    pub max_dependencies: usize,
    pub max_quotes: usize,
    pub max_vouchers: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_batch_calls: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub call_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub target_latency_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_HASH_SUITE
                .to_string(),
            encryption_suite:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_ENCRYPTION_SUITE
                    .to_string(),
            pq_signature_suite:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_PQ_SIGNATURE_SUITE
                    .to_string(),
            batch_proof_suite:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_BATCH_PROOF_SUITE
                    .to_string(),
            nullifier_suite:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_NULLIFIER_SUITE
                    .to_string(),
            max_lanes: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_LANES,
            max_calls: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_CALLS,
            max_dependencies:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_DEPENDENCIES,
            max_quotes: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_QUOTES,
            max_vouchers:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_VOUCHERS,
            max_reservations:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_REBATES,
            max_batch_calls:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_CALLS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_user_fee_bps:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            call_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_CALL_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            target_latency_ms:
                PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_LATENCY_MS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes: u64,
    pub encrypted_calls: u64,
    pub dependencies: u64,
    pub sponsor_vouchers: u64,
    pub fee_quotes: u64,
    pub reservations: u64,
    pub batches: u64,
    pub settlement_receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub nullifier_fences: u64,
    pub public_records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub encrypted_call_root: String,
    pub dependency_root: String,
    pub sponsor_voucher_root: String,
    pub reservation_root: String,
    pub fee_quote_root: String,
    pub batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_fence_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingLane {
    pub lane_id: String,
    pub kind: RoutingLaneKind,
    pub status: LaneStatus,
    pub sequencer_id: String,
    pub sponsor_pool_id: String,
    pub contract_namespace_root: String,
    pub priority_weight: u64,
    pub target_latency_ms: u64,
    pub max_batch_calls: usize,
    pub base_fee_micros: u64,
    pub congestion_fee_micros: u64,
    pub rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub accepted_call_kinds: BTreeSet<CallKind>,
}

impl RoutingLane {
    pub fn record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "sequencer_id": self.sequencer_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "contract_namespace_root": self.contract_namespace_root,
            "priority_weight": self.priority_weight,
            "target_latency_ms": self.target_latency_ms,
            "max_batch_calls": self.max_batch_calls,
            "base_fee_micros": self.base_fee_micros,
            "congestion_fee_micros": self.congestion_fee_micros,
            "rebate_bps": self.rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "accepted_call_kinds": self.accepted_call_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBatchCall {
    pub call_id: String,
    pub lane_id: String,
    pub call_kind: CallKind,
    pub status: CallStatus,
    pub submitter_commitment: String,
    pub contract_commitment: String,
    pub method_selector_commitment: String,
    pub encrypted_payload_root: String,
    pub ciphertext_digest: String,
    pub payload_byte_len: u64,
    pub calldata_units: u64,
    pub read_set_root: String,
    pub write_set_root: String,
    pub asset_delta_root: String,
    pub nullifier_root: String,
    pub privacy_fence_id: String,
    pub sponsor_voucher_id: Option<String>,
    pub reservation_id: Option<String>,
    pub max_fee_micros: u64,
    pub max_latency_ms: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub pq_security_bits: u16,
}

impl EncryptedBatchCall {
    pub fn record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "call_kind": self.call_kind.as_str(),
            "status": self.status,
            "submitter_commitment": self.submitter_commitment,
            "contract_commitment": self.contract_commitment,
            "method_selector_commitment": self.method_selector_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_digest": self.ciphertext_digest,
            "payload_byte_len": self.payload_byte_len,
            "calldata_units": self.calldata_units,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "asset_delta_root": self.asset_delta_root,
            "nullifier_root": self.nullifier_root,
            "privacy_fence_id": self.privacy_fence_id,
            "sponsor_voucher_id": self.sponsor_voucher_id,
            "reservation_id": self.reservation_id,
            "max_fee_micros": self.max_fee_micros,
            "max_latency_ms": self.max_latency_ms,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallDependency {
    pub dependency_id: String,
    pub call_id: String,
    pub depends_on_call_id: Option<String>,
    pub kind: DependencyKind,
    pub lane_id: String,
    pub proof_root: String,
    pub witness_commitment: String,
    pub ordering_key: String,
    pub strict: bool,
    pub checked_height: u64,
}

impl CallDependency {
    pub fn record(&self) -> Value {
        json!({
            "dependency_id": self.dependency_id,
            "call_id": self.call_id,
            "depends_on_call_id": self.depends_on_call_id,
            "kind": self.kind.as_str(),
            "lane_id": self.lane_id,
            "proof_root": self.proof_root,
            "witness_commitment": self.witness_commitment,
            "ordering_key": self.ordering_key,
            "strict": self.strict,
            "checked_height": self.checked_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorVoucher {
    pub voucher_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub status: VoucherStatus,
    pub budget_micros: u64,
    pub reserved_micros: u64,
    pub consumed_micros: u64,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub allowed_call_root: String,
    pub nullifier_fence_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl SponsorVoucher {
    pub fn record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "budget_micros": self.budget_micros,
            "reserved_micros": self.reserved_micros,
            "consumed_micros": self.consumed_micros,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "allowed_call_root": self.allowed_call_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub voucher_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub sponsor_id: String,
    pub reserved_micros: u64,
    pub cover_bps: u64,
    pub privacy_set_size: u64,
    pub reservation_nullifier: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl SponsorReservation {
    pub fn record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "voucher_id": self.voucher_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "reserved_micros": self.reserved_micros,
            "cover_bps": self.cover_bps,
            "privacy_set_size": self.privacy_set_size,
            "reservation_nullifier": self.reservation_nullifier,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub router_id: String,
    pub status: QuoteStatus,
    pub base_fee_micros: u64,
    pub execution_fee_micros: u64,
    pub proof_fee_micros: u64,
    pub da_fee_micros: u64,
    pub sponsor_credit_micros: u64,
    pub rebate_micros: u64,
    pub total_user_fee_micros: u64,
    pub max_fee_bps: u64,
    pub latency_target_ms: u64,
    pub quote_height: u64,
    pub expires_height: u64,
}

impl FeeQuote {
    pub fn record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "router_id": self.router_id,
            "status": self.status,
            "base_fee_micros": self.base_fee_micros,
            "execution_fee_micros": self.execution_fee_micros,
            "proof_fee_micros": self.proof_fee_micros,
            "da_fee_micros": self.da_fee_micros,
            "sponsor_credit_micros": self.sponsor_credit_micros,
            "rebate_micros": self.rebate_micros,
            "total_user_fee_micros": self.total_user_fee_micros,
            "max_fee_bps": self.max_fee_bps,
            "latency_target_ms": self.latency_target_ms,
            "quote_height": self.quote_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub router_id: String,
    pub status: BatchStatus,
    pub call_ids: Vec<String>,
    pub call_root: String,
    pub dependency_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub encrypted_payload_root: String,
    pub aggregate_nullifier_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub public_input_root: String,
    pub proof_root: String,
    pub planned_height: u64,
    pub settlement_height: u64,
}

impl CallBatch {
    pub fn record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "router_id": self.router_id,
            "status": self.status,
            "call_ids": self.call_ids,
            "call_root": self.call_root,
            "dependency_root": self.dependency_root,
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "public_input_root": self.public_input_root,
            "proof_root": self.proof_root,
            "planned_height": self.planned_height,
            "settlement_height": self.settlement_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub status: ReceiptStatus,
    pub output_commitment: String,
    pub state_delta_root: String,
    pub event_root: String,
    pub fee_paid_micros: u64,
    pub sponsor_paid_micros: u64,
    pub rebate_id: Option<String>,
    pub nullifier_root: String,
    pub public_record_hash: String,
    pub settled_height: u64,
}

impl SettlementReceipt {
    pub fn record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "output_commitment": self.output_commitment,
            "state_delta_root": self.state_delta_root,
            "event_root": self.event_root,
            "fee_paid_micros": self.fee_paid_micros,
            "sponsor_paid_micros": self.sponsor_paid_micros,
            "rebate_id": self.rebate_id,
            "nullifier_root": self.nullifier_root,
            "public_record_hash": self.public_record_hash,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub beneficiary_commitment: String,
    pub amount_micros: u64,
    pub reason: String,
    pub claim_nullifier: String,
    pub claim_root: String,
    pub issued_height: u64,
}

impl Rebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "amount_micros": self.amount_micros,
            "reason": self.reason,
            "claim_nullifier": self.claim_nullifier,
            "claim_root": self.claim_root,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane_id: String,
    pub subject_commitment: String,
    pub anonymity_set_root: String,
    pub nullifier_root: String,
    pub allowed_disclosure_root: String,
    pub minimum_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivacyFence {
    pub fn record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "subject_commitment": self.subject_commitment,
            "anonymity_set_root": self.anonymity_set_root,
            "nullifier_root": self.nullifier_root,
            "allowed_disclosure_root": self.allowed_disclosure_root,
            "minimum_set_size": self.minimum_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub nullifier_id: String,
    pub fence_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub nullifier_commitment: String,
    pub spent: bool,
    pub spent_height: Option<u64>,
}

impl NullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "fence_id": self.fence_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "nullifier_commitment": self.nullifier_commitment,
            "spent": self.spent,
            "spent_height": self.spent_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, RoutingLane>,
    pub encrypted_calls: BTreeMap<String, EncryptedBatchCall>,
    pub dependencies: BTreeMap<String, CallDependency>,
    pub sponsor_vouchers: BTreeMap<String, SponsorVoucher>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub batches: BTreeMap<String, CallBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, Rebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::empty(),
            lanes: BTreeMap::new(),
            encrypted_calls: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            sponsor_vouchers: BTreeMap::new(),
            reservations: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
        };
        state.recompute();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEVNET_HEIGHT;
        let defi_lane_id = lane_id(RoutingLaneKind::DefiSwap, "devnet-defi-router");
        let bridge_lane_id = lane_id(RoutingLaneKind::MoneroBridge, "devnet-xmr-router");
        let settlement_lane_id =
            lane_id(RoutingLaneKind::SettlementHook, "devnet-settlement-router");

        state.insert_lane(sample_lane(
            &defi_lane_id,
            RoutingLaneKind::DefiSwap,
            "sequencer-devnet-fast-01",
            "sponsor-pool-defi-low-fee",
            310,
        ));
        state.insert_lane(sample_lane(
            &bridge_lane_id,
            RoutingLaneKind::MoneroBridge,
            "sequencer-devnet-bridge-01",
            "sponsor-pool-xmr-fast-exit",
            420,
        ));
        state.insert_lane(sample_lane(
            &settlement_lane_id,
            RoutingLaneKind::SettlementHook,
            "sequencer-devnet-proof-01",
            "sponsor-pool-settlement-rebate",
            280,
        ));

        let fence_a = privacy_fence_id(&defi_lane_id, "alice-session-01");
        let fence_b = privacy_fence_id(&bridge_lane_id, "bob-session-01");
        state.insert_privacy_fence(sample_privacy_fence(
            &fence_a,
            &defi_lane_id,
            "alice-session-01",
            height,
        ));
        state.insert_privacy_fence(sample_privacy_fence(
            &fence_b,
            &bridge_lane_id,
            "bob-session-01",
            height,
        ));

        let call_a = call_id(&defi_lane_id, "alice-swap-usdc-xmr", 0);
        let call_b = call_id(&defi_lane_id, "alice-lend-rebalance", 1);
        let call_c = call_id(&bridge_lane_id, "bob-xmr-fast-exit", 0);
        state.insert_encrypted_call(sample_call(
            &call_a,
            &defi_lane_id,
            CallKind::AmmSwap,
            &fence_a,
            "alice-swap-usdc-xmr",
            height,
        ));
        state.insert_encrypted_call(sample_call(
            &call_b,
            &defi_lane_id,
            CallKind::LendingSupply,
            &fence_a,
            "alice-lend-rebalance",
            height + 1,
        ));
        state.insert_encrypted_call(sample_call(
            &call_c,
            &bridge_lane_id,
            CallKind::BridgeRelease,
            &fence_b,
            "bob-xmr-fast-exit",
            height + 2,
        ));

        let voucher_a = voucher_id("sponsor-defi-foundation", &defi_lane_id, 0);
        let voucher_b = voucher_id("sponsor-monero-relay", &bridge_lane_id, 0);
        state.insert_sponsor_voucher(sample_voucher(
            &voucher_a,
            "sponsor-defi-foundation",
            &defi_lane_id,
            height,
        ));
        state.insert_sponsor_voucher(sample_voucher(
            &voucher_b,
            "sponsor-monero-relay",
            &bridge_lane_id,
            height,
        ));

        let reservation_a = reservation_id(&voucher_a, &call_a);
        let reservation_c = reservation_id(&voucher_b, &call_c);
        state.insert_reservation(sample_reservation(
            &reservation_a,
            &voucher_a,
            &call_a,
            &defi_lane_id,
            "sponsor-defi-foundation",
            height + 1,
        ));
        state.insert_reservation(sample_reservation(
            &reservation_c,
            &voucher_b,
            &call_c,
            &bridge_lane_id,
            "sponsor-monero-relay",
            height + 2,
        ));

        state.insert_dependency(sample_dependency(
            &dependency_id(&call_b, Some(&call_a), DependencyKind::ReadAfterWrite),
            &call_b,
            Some(&call_a),
            DependencyKind::ReadAfterWrite,
            &defi_lane_id,
            height + 2,
        ));
        state.insert_dependency(sample_dependency(
            &dependency_id(&call_a, None, DependencyKind::PrivacyFence),
            &call_a,
            None,
            DependencyKind::PrivacyFence,
            &defi_lane_id,
            height + 1,
        ));
        state.insert_dependency(sample_dependency(
            &dependency_id(&call_c, None, DependencyKind::NullifierOrdering),
            &call_c,
            None,
            DependencyKind::NullifierOrdering,
            &bridge_lane_id,
            height + 2,
        ));

        let quote_a = quote_id(&call_a, "router-fast-01", height + 2);
        let quote_b = quote_id(&call_b, "router-fast-01", height + 2);
        let quote_c = quote_id(&call_c, "router-bridge-01", height + 3);
        state.insert_fee_quote(sample_quote(
            &quote_a,
            &call_a,
            &defi_lane_id,
            "router-fast-01",
            1_150,
            height + 2,
        ));
        state.insert_fee_quote(sample_quote(
            &quote_b,
            &call_b,
            &defi_lane_id,
            "router-fast-01",
            980,
            height + 2,
        ));
        state.insert_fee_quote(sample_quote(
            &quote_c,
            &call_c,
            &bridge_lane_id,
            "router-bridge-01",
            1_420,
            height + 3,
        ));

        let batch_a = batch_id(&defi_lane_id, "router-fast-01", height + 4);
        let batch_c = batch_id(&bridge_lane_id, "router-bridge-01", height + 5);
        state.insert_batch(sample_batch(
            &batch_a,
            &defi_lane_id,
            "router-fast-01",
            vec![call_a.clone(), call_b.clone()],
            height + 4,
        ));
        state.insert_batch(sample_batch(
            &batch_c,
            &bridge_lane_id,
            "router-bridge-01",
            vec![call_c.clone()],
            height + 5,
        ));

        let receipt_a = receipt_id(&batch_a, &call_a);
        let receipt_b = receipt_id(&batch_a, &call_b);
        let receipt_c = receipt_id(&batch_c, &call_c);
        let rebate_a = rebate_id(&receipt_a, &call_a);
        let rebate_c = rebate_id(&receipt_c, &call_c);
        state.insert_settlement_receipt(sample_receipt(
            &receipt_a,
            &batch_a,
            &call_a,
            &defi_lane_id,
            Some(&rebate_a),
            height + 8,
        ));
        state.insert_settlement_receipt(sample_receipt(
            &receipt_b,
            &batch_a,
            &call_b,
            &defi_lane_id,
            None,
            height + 8,
        ));
        state.insert_settlement_receipt(sample_receipt(
            &receipt_c,
            &batch_c,
            &call_c,
            &bridge_lane_id,
            Some(&rebate_c),
            height + 9,
        ));
        state.insert_rebate(sample_rebate(
            &rebate_a,
            &receipt_a,
            &call_a,
            &defi_lane_id,
            82,
            height + 9,
        ));
        state.insert_rebate(sample_rebate(
            &rebate_c,
            &receipt_c,
            &call_c,
            &bridge_lane_id,
            104,
            height + 10,
        ));

        state.insert_nullifier_fence(sample_nullifier(
            &nullifier_id(&fence_a, &call_a, 0),
            &fence_a,
            &call_a,
            &defi_lane_id,
            true,
            Some(height + 8),
        ));
        state.insert_nullifier_fence(sample_nullifier(
            &nullifier_id(&fence_b, &call_c, 0),
            &fence_b,
            &call_c,
            &bridge_lane_id,
            true,
            Some(height + 9),
        ));

        state.recompute();
        state
    }

    pub fn insert_lane(&mut self, lane: RoutingLane) {
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.recompute();
    }

    pub fn insert_encrypted_call(&mut self, call: EncryptedBatchCall) {
        self.encrypted_calls.insert(call.call_id.clone(), call);
        self.recompute();
    }

    pub fn insert_dependency(&mut self, dependency: CallDependency) {
        self.dependencies
            .insert(dependency.dependency_id.clone(), dependency);
        self.recompute();
    }

    pub fn insert_sponsor_voucher(&mut self, voucher: SponsorVoucher) {
        self.sponsor_vouchers
            .insert(voucher.voucher_id.clone(), voucher);
        self.recompute();
    }

    pub fn insert_reservation(&mut self, reservation: SponsorReservation) {
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute();
    }

    pub fn insert_fee_quote(&mut self, quote: FeeQuote) {
        self.fee_quotes.insert(quote.quote_id.clone(), quote);
        self.recompute();
    }

    pub fn insert_batch(&mut self, batch: CallBatch) {
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute();
    }

    pub fn insert_settlement_receipt(&mut self, receipt: SettlementReceipt) {
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.recompute();
    }

    pub fn insert_rebate(&mut self, rebate: Rebate) {
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute();
    }

    pub fn insert_privacy_fence(&mut self, fence: PrivacyFence) {
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        self.recompute();
    }

    pub fn insert_nullifier_fence(&mut self, fence: NullifierFence) {
        self.nullifier_fences
            .insert(fence.nullifier_id.clone(), fence);
        self.recompute();
    }

    pub fn quote_for_call(&self, call_id: &str) -> Option<&FeeQuote> {
        self.fee_quotes
            .values()
            .filter(|quote| quote.call_id == call_id && quote.status.selectable())
            .min_by_key(|quote| quote.total_user_fee_micros)
    }

    pub fn public_record(&self) -> Value {
        let roots = self.compute_roots_without_state();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height_hint": PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEVNET_HEIGHT,
            "hash_suite": self.config.hash_suite,
            "encryption_suite": self.config.encryption_suite,
            "pq_signature_suite": self.config.pq_signature_suite,
            "batch_proof_suite": self.config.batch_proof_suite,
            "nullifier_suite": self.config.nullifier_suite,
            "counters": self.counters,
            "roots": {
                "lane_root": roots.lane_root,
                "encrypted_call_root": roots.encrypted_call_root,
                "dependency_root": roots.dependency_root,
                "sponsor_voucher_root": roots.sponsor_voucher_root,
                "reservation_root": roots.reservation_root,
                "fee_quote_root": roots.fee_quote_root,
                "batch_root": roots.batch_root,
                "settlement_receipt_root": roots.settlement_receipt_root,
                "rebate_root": roots.rebate_root,
                "privacy_fence_root": roots.privacy_fence_root,
                "nullifier_fence_root": roots.nullifier_fence_root,
            },
            "policy": {
                "max_batch_calls": self.config.max_batch_calls,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "batch_privacy_set_size": self.config.batch_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "target_user_fee_bps": self.config.target_user_fee_bps,
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "target_rebate_bps": self.config.target_rebate_bps,
                "sponsor_cover_bps": self.config.sponsor_cover_bps,
                "target_latency_ms": self.config.target_latency_ms,
            },
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn recompute(&mut self) {
        self.counters = Counters {
            lanes: self.lanes.len() as u64,
            encrypted_calls: self.encrypted_calls.len() as u64,
            dependencies: self.dependencies.len() as u64,
            sponsor_vouchers: self.sponsor_vouchers.len() as u64,
            fee_quotes: self.fee_quotes.len() as u64,
            reservations: self.reservations.len() as u64,
            batches: self.batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            nullifier_fences: self.nullifier_fences.len() as u64,
            public_records: 1,
        };
        let public_record = self.public_record();
        let public_record_root = public_record_root(&public_record);
        let state_root = state_root_from_record(&public_record);
        let mut roots = self.compute_roots_without_state();
        roots.public_record_root = public_record_root;
        roots.state_root = state_root;
        self.roots = roots;
    }

    fn compute_roots_without_state(&self) -> Roots {
        let lane_records = records_from_map(&self.lanes, RoutingLane::record);
        let call_records = records_from_map(&self.encrypted_calls, EncryptedBatchCall::record);
        let dependency_records = records_from_map(&self.dependencies, CallDependency::record);
        let voucher_records = records_from_map(&self.sponsor_vouchers, SponsorVoucher::record);
        let reservation_records = records_from_map(&self.reservations, SponsorReservation::record);
        let quote_records = records_from_map(&self.fee_quotes, FeeQuote::record);
        let batch_records = records_from_map(&self.batches, CallBatch::record);
        let receipt_records =
            records_from_map(&self.settlement_receipts, SettlementReceipt::record);
        let rebate_records = records_from_map(&self.rebates, Rebate::record);
        let privacy_records = records_from_map(&self.privacy_fences, PrivacyFence::record);
        let nullifier_records = records_from_map(&self.nullifier_fences, NullifierFence::record);

        Roots {
            lane_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-LANE",
                &lane_records,
            ),
            encrypted_call_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-CALL",
                &call_records,
            ),
            dependency_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEPENDENCY",
                &dependency_records,
            ),
            sponsor_voucher_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-VOUCHER",
                &voucher_records,
            ),
            reservation_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-RESERVATION",
                &reservation_records,
            ),
            fee_quote_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-QUOTE",
                &quote_records,
            ),
            batch_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-BATCH",
                &batch_records,
            ),
            settlement_receipt_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-RECEIPT",
                &receipt_records,
            ),
            rebate_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-REBATE",
                &rebate_records,
            ),
            privacy_fence_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PRIVACY-FENCE",
                &privacy_records,
            ),
            nullifier_fence_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-NULLIFIER-FENCE",
                &nullifier_records,
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PUBLIC-RECORD",
                &[],
            ),
            state_root: merkle_root("PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-STATE", &[]),
        }
    }
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            lane_root: merkle_root("PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-LANE", &[]),
            encrypted_call_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-CALL",
                &[],
            ),
            dependency_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEPENDENCY",
                &[],
            ),
            sponsor_voucher_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-VOUCHER",
                &[],
            ),
            reservation_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-RESERVATION",
                &[],
            ),
            fee_quote_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-QUOTE",
                &[],
            ),
            batch_root: merkle_root("PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-BATCH", &[]),
            settlement_receipt_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-RECEIPT",
                &[],
            ),
            rebate_root: merkle_root("PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-REBATE", &[]),
            privacy_fence_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PRIVACY-FENCE",
                &[],
            ),
            nullifier_fence_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-NULLIFIER-FENCE",
                &[],
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PUBLIC-RECORD",
                &[],
            ),
            state_root: merkle_root("PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-STATE", &[]),
        }
    }
}

pub fn payload_root(payloads: &[Value]) -> String {
    merkle_root(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PAYLOAD",
        payloads,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PUBLIC-RECORD",
        record,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-STATE",
        record,
    )
}

pub fn lane_id(kind: RoutingLaneKind, seed: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn call_id(lane_id: &str, payload_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(payload_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn dependency_id(
    call_id: &str,
    depends_on_call_id: Option<&str>,
    kind: DependencyKind,
) -> String {
    let parent = depends_on_call_id.unwrap_or("none");
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEPENDENCY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(parent),
            HashPart::Str(kind.as_str()),
        ],
        32,
    )
}

pub fn voucher_id(sponsor_id: &str, lane_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn reservation_id(voucher_id: &str, call_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(voucher_id),
            HashPart::Str(call_id),
        ],
        32,
    )
}

pub fn quote_id(call_id: &str, router_id: &str, quote_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(router_id),
            HashPart::U64(quote_height),
        ],
        32,
    )
}

pub fn batch_id(lane_id: &str, router_id: &str, planned_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(router_id),
            HashPart::U64(planned_height),
        ],
        32,
    )
}

pub fn receipt_id(batch_id: &str, call_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(call_id),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, call_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(call_id),
        ],
        32,
    )
}

pub fn privacy_fence_id(lane_id: &str, subject_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(subject_commitment),
        ],
        32,
    )
}

pub fn nullifier_id(fence_id: &str, call_id: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(fence_id),
            HashPart::Str(call_id),
            HashPart::U64(index),
        ],
        32,
    )
}

fn records_from_map<T, F>(items: &BTreeMap<String, T>, record_fn: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    items.values().map(record_fn).collect::<Vec<_>>()
}

fn sample_lane(
    lane_id: &str,
    kind: RoutingLaneKind,
    sequencer_id: &str,
    sponsor_pool_id: &str,
    base_fee_micros: u64,
) -> RoutingLane {
    let mut accepted_call_kinds = BTreeSet::new();
    accepted_call_kinds.insert(CallKind::ConfidentialInvoke);
    accepted_call_kinds.insert(CallKind::MultiCall);
    accepted_call_kinds.insert(CallKind::AmmSwap);
    accepted_call_kinds.insert(CallKind::StableSwap);
    accepted_call_kinds.insert(CallKind::LendingSupply);
    accepted_call_kinds.insert(CallKind::LendingBorrow);
    accepted_call_kinds.insert(CallKind::BridgeRelease);
    accepted_call_kinds.insert(CallKind::SettlementCallback);
    RoutingLane {
        lane_id: lane_id.to_string(),
        kind,
        status: LaneStatus::Open,
        sequencer_id: sequencer_id.to_string(),
        sponsor_pool_id: sponsor_pool_id.to_string(),
        contract_namespace_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-CONTRACT-NAMESPACE",
            &[json!({"lane_id": lane_id, "kind": kind.as_str()})],
        ),
        priority_weight: kind.default_priority_weight(),
        target_latency_ms: kind.default_latency_target_ms(),
        max_batch_calls: 4_096,
        base_fee_micros,
        congestion_fee_micros: base_fee_micros / 5,
        rebate_bps:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
        min_privacy_set_size:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
        min_pq_security_bits:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        accepted_call_kinds,
    }
}

fn sample_call(
    call_id: &str,
    lane_id: &str,
    call_kind: CallKind,
    fence_id: &str,
    seed: &str,
    height: u64,
) -> EncryptedBatchCall {
    let payloads = vec![
        json!({"seed": seed, "part": "contract", "kind": call_kind.as_str()}),
        json!({"seed": seed, "part": "sealed_args", "suite": PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_ENCRYPTION_SUITE}),
    ];
    EncryptedBatchCall {
        call_id: call_id.to_string(),
        lane_id: lane_id.to_string(),
        call_kind,
        status: CallStatus::Settled,
        submitter_commitment: stable_commitment("submitter", seed),
        contract_commitment: stable_commitment("contract", seed),
        method_selector_commitment: stable_commitment("method", call_kind.as_str()),
        encrypted_payload_root: payload_root(&payloads),
        ciphertext_digest: stable_commitment("ciphertext", seed),
        payload_byte_len: 1_024 + call_kind.defi_weight() / 10,
        calldata_units: 16 + call_kind.defi_weight() / 1_000,
        read_set_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-READ-SET",
            &[json!({"seed": seed})],
        ),
        write_set_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-WRITE-SET",
            &[json!({"seed": seed})],
        ),
        asset_delta_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-ASSET-DELTA",
            &[json!({"seed": seed, "fee_bps": 9})],
        ),
        nullifier_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-CALL-NULLIFIER",
            &[json!({"seed": seed})],
        ),
        privacy_fence_id: fence_id.to_string(),
        sponsor_voucher_id: None,
        reservation_id: None,
        max_fee_micros: 2_500,
        max_latency_ms: 650,
        submitted_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_CALL_TTL_BLOCKS,
        pq_security_bits:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
    }
}

fn sample_dependency(
    dependency_id: &str,
    call_id: &str,
    depends_on_call_id: Option<&str>,
    kind: DependencyKind,
    lane_id: &str,
    height: u64,
) -> CallDependency {
    CallDependency {
        dependency_id: dependency_id.to_string(),
        call_id: call_id.to_string(),
        depends_on_call_id: depends_on_call_id.map(str::to_string),
        kind,
        lane_id: lane_id.to_string(),
        proof_root: root_from_record(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-DEPENDENCY-PROOF",
            &json!({"call_id": call_id, "depends_on_call_id": depends_on_call_id, "kind": kind.as_str()}),
        ),
        witness_commitment: stable_commitment("dependency-witness", call_id),
        ordering_key: stable_commitment("dependency-ordering", kind.as_str()),
        strict: kind.strict(),
        checked_height: height,
    }
}

fn sample_voucher(
    voucher_id: &str,
    sponsor_id: &str,
    lane_id: &str,
    height: u64,
) -> SponsorVoucher {
    SponsorVoucher {
        voucher_id: voucher_id.to_string(),
        sponsor_id: sponsor_id.to_string(),
        lane_id: lane_id.to_string(),
        status: VoucherStatus::Reserved,
        budget_micros: 2_500_000,
        reserved_micros: 180_000,
        consumed_micros: 96_000,
        min_privacy_set_size:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
        max_fee_bps:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
        allowed_call_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-ALLOWED-CALL",
            &[json!({"lane_id": lane_id})],
        ),
        nullifier_fence_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-SPONSOR-NULLIFIER",
            &[json!({"sponsor_id": sponsor_id})],
        ),
        opened_height: height,
        expires_height: height + 720,
    }
}

fn sample_reservation(
    reservation_id: &str,
    voucher_id: &str,
    call_id: &str,
    lane_id: &str,
    sponsor_id: &str,
    height: u64,
) -> SponsorReservation {
    SponsorReservation {
        reservation_id: reservation_id.to_string(),
        voucher_id: voucher_id.to_string(),
        call_id: call_id.to_string(),
        lane_id: lane_id.to_string(),
        sponsor_id: sponsor_id.to_string(),
        reserved_micros: 90_000,
        cover_bps: PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
        privacy_set_size:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
        reservation_nullifier: stable_commitment("reservation-nullifier", reservation_id),
        opened_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
    }
}

fn sample_quote(
    quote_id: &str,
    call_id: &str,
    lane_id: &str,
    router_id: &str,
    base_fee_micros: u64,
    height: u64,
) -> FeeQuote {
    let execution_fee_micros = base_fee_micros * 2;
    let proof_fee_micros = base_fee_micros / 2;
    let da_fee_micros = base_fee_micros / 3;
    let sponsor_credit_micros = base_fee_micros;
    let rebate_micros = base_fee_micros / 12;
    let gross = base_fee_micros + execution_fee_micros + proof_fee_micros + da_fee_micros;
    FeeQuote {
        quote_id: quote_id.to_string(),
        call_id: call_id.to_string(),
        lane_id: lane_id.to_string(),
        router_id: router_id.to_string(),
        status: QuoteStatus::Filled,
        base_fee_micros,
        execution_fee_micros,
        proof_fee_micros,
        da_fee_micros,
        sponsor_credit_micros,
        rebate_micros,
        total_user_fee_micros: gross.saturating_sub(sponsor_credit_micros + rebate_micros),
        max_fee_bps:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
        latency_target_ms:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_TARGET_LATENCY_MS,
        quote_height: height,
        expires_height: height
            + PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
    }
}

fn sample_batch(
    batch_id: &str,
    lane_id: &str,
    router_id: &str,
    call_ids: Vec<String>,
    height: u64,
) -> CallBatch {
    let call_records = call_ids
        .iter()
        .map(|call_id| json!({"call_id": call_id}))
        .collect::<Vec<_>>();
    CallBatch {
        batch_id: batch_id.to_string(),
        lane_id: lane_id.to_string(),
        router_id: router_id.to_string(),
        status: BatchStatus::Settled,
        call_ids,
        call_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-CALL",
            &call_records,
        ),
        dependency_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-DEPENDENCY",
            &call_records,
        ),
        quote_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-QUOTE",
            &call_records,
        ),
        reservation_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-RESERVATION",
            &call_records,
        ),
        encrypted_payload_root: payload_root(&call_records),
        aggregate_nullifier_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-NULLIFIER",
            &call_records,
        ),
        state_read_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-READ",
            &call_records,
        ),
        state_write_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-WRITE",
            &call_records,
        ),
        public_input_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-PUBLIC-INPUT",
            &call_records,
        ),
        proof_root: root_from_record(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-BATCH-PROOF",
            &json!({"batch_id": batch_id, "call_count": call_records.len()}),
        ),
        planned_height: height,
        settlement_height: height + 4,
    }
}

fn sample_receipt(
    receipt_id: &str,
    batch_id: &str,
    call_id: &str,
    lane_id: &str,
    rebate_id: Option<&str>,
    height: u64,
) -> SettlementReceipt {
    let public_record = json!({
        "receipt_id": receipt_id,
        "batch_id": batch_id,
        "call_id": call_id,
        "lane_id": lane_id,
        "status": "finalized",
    });
    SettlementReceipt {
        receipt_id: receipt_id.to_string(),
        batch_id: batch_id.to_string(),
        call_id: call_id.to_string(),
        lane_id: lane_id.to_string(),
        status: ReceiptStatus::Finalized,
        output_commitment: stable_commitment("receipt-output", receipt_id),
        state_delta_root: root_from_record(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-STATE-DELTA",
            &json!({"call_id": call_id}),
        ),
        event_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-EVENT",
            &[public_record.clone()],
        ),
        fee_paid_micros: 1_800,
        sponsor_paid_micros: 1_200,
        rebate_id: rebate_id.map(str::to_string),
        nullifier_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-RECEIPT-NULLIFIER",
            &[json!({"receipt_id": receipt_id})],
        ),
        public_record_hash: public_record_root(&public_record),
        settled_height: height,
    }
}

fn sample_rebate(
    rebate_id: &str,
    receipt_id: &str,
    call_id: &str,
    lane_id: &str,
    amount_micros: u64,
    height: u64,
) -> Rebate {
    Rebate {
        rebate_id: rebate_id.to_string(),
        receipt_id: receipt_id.to_string(),
        call_id: call_id.to_string(),
        lane_id: lane_id.to_string(),
        beneficiary_commitment: stable_commitment("rebate-beneficiary", call_id),
        amount_micros,
        reason: "low_fee_batch_surplus_return".to_string(),
        claim_nullifier: stable_commitment("rebate-claim-nullifier", rebate_id),
        claim_root: root_from_record(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-REBATE-CLAIM",
            &json!({"rebate_id": rebate_id, "amount_micros": amount_micros}),
        ),
        issued_height: height,
    }
}

fn sample_privacy_fence(
    fence_id: &str,
    lane_id: &str,
    subject_commitment: &str,
    height: u64,
) -> PrivacyFence {
    PrivacyFence {
        fence_id: fence_id.to_string(),
        lane_id: lane_id.to_string(),
        subject_commitment: stable_commitment("privacy-subject", subject_commitment),
        anonymity_set_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-ANONYMITY-SET",
            &[json!({"subject": subject_commitment})],
        ),
        nullifier_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-FENCE-NULLIFIER",
            &[json!({"subject": subject_commitment})],
        ),
        allowed_disclosure_root: merkle_root(
            "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-DEVNET-DISCLOSURE",
            &[json!({"lane_id": lane_id})],
        ),
        minimum_set_size:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
        pq_security_bits:
            PRIVATE_L2_LOW_FEE_ENCRYPTED_BATCH_CALL_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        opened_height: height,
        expires_height: height + 144,
    }
}

fn sample_nullifier(
    nullifier_id: &str,
    fence_id: &str,
    call_id: &str,
    lane_id: &str,
    spent: bool,
    spent_height: Option<u64>,
) -> NullifierFence {
    NullifierFence {
        nullifier_id: nullifier_id.to_string(),
        fence_id: fence_id.to_string(),
        call_id: call_id.to_string(),
        lane_id: lane_id.to_string(),
        nullifier_commitment: stable_commitment("nullifier", nullifier_id),
        spent,
        spent_height,
    }
}

fn stable_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ENCRYPTED-BATCH-CALL-ROUTER-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}
