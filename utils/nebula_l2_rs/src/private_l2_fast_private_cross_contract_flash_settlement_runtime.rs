use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-private-cross-contract-flash-settlement-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_PREAUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-flash-settlement-preauth-v1";
pub const FLASH_PROOF_SUITE: &str = "recursive-stark-private-atomic-flash-settlement-proof-v1";
pub const RECEIPT_SUITE: &str = "private-cross-contract-flash-receipt-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-private-flash-settlement-rebate-root-v1";
pub const SLASHING_SUITE: &str = "atomicity-and-proof-violation-slashing-root-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 1_720_000;
pub const DEFAULT_DEVNET_EPOCH: u64 = 16_384;
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_LEG_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_PREAUTH_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 4;
pub const DEFAULT_LOCK_TTL_BLOCKS: u64 = 5;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_SLOTS: usize = 2_097_152;
pub const DEFAULT_MAX_LEGS: usize = 8_388_608;
pub const DEFAULT_MAX_PREAUTHS: usize = 8_388_608;
pub const DEFAULT_MAX_BUNDLES: usize = 1_048_576;
pub const DEFAULT_MAX_LOCKS: usize = 8_388_608;
pub const DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_SLASHES: usize = 1_048_576;
pub const DEFAULT_MAX_LEGS_PER_SLOT: usize = 64;
pub const DEFAULT_MAX_LEGS_PER_BUNDLE: usize = 512;
pub const DEFAULT_MAX_LOCKS_PER_BUNDLE: usize = 1_024;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 450;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_LIQUIDITY_REBATE_BPS: u64 = 3;
pub const DEFAULT_PROOF_FAILURE_SLASH_BPS: u64 = 2_000;
pub const DEFAULT_ATOMICITY_FAILURE_SLASH_BPS: u64 = 3_500;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlashLane {
    PrivateDefi,
    ConfidentialAmm,
    PrivateToken,
    Lending,
    Perpetuals,
    Vault,
    Oracle,
    MoneroBridge,
    Paymaster,
    Emergency,
}

impl FlashLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDefi => "private_defi",
            Self::ConfidentialAmm => "confidential_amm",
            Self::PrivateToken => "private_token",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Vault => "vault",
            Self::Oracle => "oracle",
            Self::MoneroBridge => "monero_bridge",
            Self::Paymaster => "paymaster",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::MoneroBridge => 9_700,
            Self::Perpetuals => 9_300,
            Self::PrivateDefi => 9_000,
            Self::ConfidentialAmm => 8_900,
            Self::Lending => 8_600,
            Self::Vault => 8_300,
            Self::PrivateToken => 8_100,
            Self::Paymaster => 7_800,
            Self::Oracle => 7_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLegKind {
    ShieldedCall,
    ConfidentialSwap,
    TokenMint,
    TokenBurn,
    TokenTransfer,
    AddLiquidity,
    RemoveLiquidity,
    Borrow,
    Repay,
    Liquidation,
    VaultDeposit,
    VaultRedeem,
    OracleRead,
    Callback,
    BridgeLock,
    BridgeRelease,
}

impl ContractLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedCall => "shielded_call",
            Self::ConfidentialSwap => "confidential_swap",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::TokenTransfer => "token_transfer",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Liquidation => "liquidation",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultRedeem => "vault_redeem",
            Self::OracleRead => "oracle_read",
            Self::Callback => "callback",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
        }
    }

    pub fn mutates_liquidity(self) -> bool {
        matches!(
            self,
            Self::ConfidentialSwap
                | Self::AddLiquidity
                | Self::RemoveLiquidity
                | Self::Borrow
                | Self::Repay
                | Self::Liquidation
                | Self::VaultDeposit
                | Self::VaultRedeem
                | Self::BridgeLock
                | Self::BridgeRelease
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Reserved,
    Legged,
    Preauthorized,
    Bundled,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Legged => "legged",
            Self::Preauthorized => "preauthorized",
            Self::Bundled => "bundled",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_legs(self) -> bool {
        matches!(self, Self::Reserved | Self::Legged | Self::Preauthorized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegStatus {
    Sealed,
    PqPreauthorized,
    LiquidityLocked,
    Bundled,
    Executed,
    Receipted,
    Rejected,
    Slashed,
}

impl LegStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::PqPreauthorized => "pq_preauthorized",
            Self::LiquidityLocked => "liquidity_locked",
            Self::Bundled => "bundled",
            Self::Executed => "executed",
            Self::Receipted => "receipted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::PqPreauthorized | Self::LiquidityLocked | Self::Bundled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPreauthKind {
    User,
    Solver,
    LiquidityVenue,
    Contract,
    Paymaster,
    Operator,
    EmergencyCommittee,
}

impl PqPreauthKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Solver => "solver",
            Self::LiquidityVenue => "liquidity_venue",
            Self::Contract => "contract",
            Self::Paymaster => "paymaster",
            Self::Operator => "operator",
            Self::EmergencyCommittee => "emergency_committee",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPreauthStatus {
    Submitted,
    Verified,
    Consumed,
    Expired,
    Rejected,
    Slashed,
}

impl PqPreauthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Built,
    LiquidityLocked,
    Proving,
    Proven,
    Settled,
    Receipted,
    Failed,
    Disputed,
    Slashed,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::LiquidityLocked => "liquidity_locked",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Receipted => "receipted",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityLockStatus {
    Reserved,
    Locked,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl LiquidityLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Locked => "locked",
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
    RebateIssued,
    Disputed,
    Slashed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::RebateIssued => "rebate_issued",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashKind {
    AtomicityViolation,
    InvalidProof,
    MissingPqPreauthorization,
    DoubleSpendNullifier,
    LiquidityLockDefault,
    ReceiptEquivocation,
    StaleBundle,
    FeeOvercharge,
}

impl SlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtomicityViolation => "atomicity_violation",
            Self::InvalidProof => "invalid_proof",
            Self::MissingPqPreauthorization => "missing_pq_preauthorization",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::LiquidityLockDefault => "liquidity_lock_default",
            Self::ReceiptEquivocation => "receipt_equivocation",
            Self::StaleBundle => "stale_bundle",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }

    pub fn proof_related(self) -> bool {
        matches!(
            self,
            Self::InvalidProof | Self::MissingPqPreauthorization | Self::DoubleSpendNullifier
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_preauth_suite: String,
    pub flash_proof_suite: String,
    pub receipt_suite: String,
    pub low_fee_rebate_suite: String,
    pub slashing_suite: String,
    pub slot_ttl_blocks: u64,
    pub leg_ttl_blocks: u64,
    pub preauth_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_slots: usize,
    pub max_legs: usize,
    pub max_preauths: usize,
    pub max_bundles: usize,
    pub max_locks: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_slashes: usize,
    pub max_legs_per_slot: usize,
    pub max_legs_per_bundle: usize,
    pub max_locks_per_bundle: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_latency_ms: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub liquidity_rebate_bps: u64,
    pub proof_failure_slash_bps: u64,
    pub atomicity_failure_slash_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_preauth_suite: PQ_PREAUTH_SUITE.to_string(),
            flash_proof_suite: FLASH_PROOF_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            slashing_suite: SLASHING_SUITE.to_string(),
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            leg_ttl_blocks: DEFAULT_LEG_TTL_BLOCKS,
            preauth_ttl_blocks: DEFAULT_PREAUTH_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            lock_ttl_blocks: DEFAULT_LOCK_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_slots: DEFAULT_MAX_SLOTS,
            max_legs: DEFAULT_MAX_LEGS,
            max_preauths: DEFAULT_MAX_PREAUTHS,
            max_bundles: DEFAULT_MAX_BUNDLES,
            max_locks: DEFAULT_MAX_LOCKS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_slashes: DEFAULT_MAX_SLASHES,
            max_legs_per_slot: DEFAULT_MAX_LEGS_PER_SLOT,
            max_legs_per_bundle: DEFAULT_MAX_LEGS_PER_BUNDLE,
            max_locks_per_bundle: DEFAULT_MAX_LOCKS_PER_BUNDLE,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            liquidity_rebate_bps: DEFAULT_LIQUIDITY_REBATE_BPS,
            proof_failure_slash_bps: DEFAULT_PROOF_FAILURE_SLASH_BPS,
            atomicity_failure_slash_bps: DEFAULT_ATOMICITY_FAILURE_SLASH_BPS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub slots_reserved: u64,
    pub legs_submitted: u64,
    pub preauths_verified: u64,
    pub bundles_built: u64,
    pub liquidity_locks_coordinated: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub slashes_opened: u64,
    pub slots_settled: u64,
    pub bundles_failed: u64,
    pub nullifiers_seen: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub slot_root: String,
    pub leg_root: String,
    pub preauth_root: String,
    pub bundle_root: String,
    pub lock_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub operator_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = json!({"empty": true});
        let public_record_root = public_record_root("FLASH-SETTLEMENT-EMPTY-PUBLIC", &[empty]);
        let state_root = state_root_from_record(&json!({"public_record_root": public_record_root}));
        Self {
            slot_root: deterministic_root("empty_slot_root", "genesis", 0),
            leg_root: deterministic_root("empty_leg_root", "genesis", 0),
            preauth_root: deterministic_root("empty_preauth_root", "genesis", 0),
            bundle_root: deterministic_root("empty_bundle_root", "genesis", 0),
            lock_root: deterministic_root("empty_lock_root", "genesis", 0),
            receipt_root: deterministic_root("empty_receipt_root", "genesis", 0),
            rebate_root: deterministic_root("empty_rebate_root", "genesis", 0),
            slashing_root: deterministic_root("empty_slashing_root", "genesis", 0),
            nullifier_root: deterministic_root("empty_nullifier_root", "genesis", 0),
            operator_root: deterministic_root("empty_operator_root", "genesis", 0),
            public_record_root,
            state_root,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FlashSettlementSlot {
    pub slot_id: String,
    pub lane: FlashLane,
    pub reserver_commitment: String,
    pub intent_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub priority_weight: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub expected_leg_count: usize,
    pub leg_ids: BTreeSet<String>,
    pub preauth_ids: BTreeSet<String>,
    pub bundle_id: Option<String>,
    pub status: SlotStatus,
}

impl FlashSettlementSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "lane": self.lane.as_str(),
            "reserver_commitment": self.reserver_commitment,
            "intent_root": self.intent_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "priority_weight": self.priority_weight,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "expected_leg_count": self.expected_leg_count,
            "leg_ids_root": set_root("FLASH-SETTLEMENT-SLOT-LEG-IDS", &self.leg_ids),
            "preauth_ids_root": set_root("FLASH-SETTLEMENT-SLOT-PREAUTH-IDS", &self.preauth_ids),
            "bundle_id": self.bundle_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedExecutionLeg {
    pub leg_id: String,
    pub slot_id: String,
    pub kind: ContractLegKind,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub sealed_call_root: String,
    pub encrypted_witness_root: String,
    pub asset_commitment_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub required_lock_root: String,
    pub dependency_root: String,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub preauth_id: Option<String>,
    pub lock_id: Option<String>,
    pub bundle_id: Option<String>,
    pub status: LegStatus,
}

impl SealedExecutionLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "leg_id": self.leg_id,
            "slot_id": self.slot_id,
            "kind": self.kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "caller_commitment": self.caller_commitment,
            "sealed_call_root": self.sealed_call_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "asset_commitment_root": self.asset_commitment_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "required_lock_root": self.required_lock_root,
            "dependency_root": self.dependency_root,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "preauth_id": self.preauth_id,
            "lock_id": self.lock_id,
            "bundle_id": self.bundle_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqPreauthorization {
    pub preauth_id: String,
    pub slot_id: String,
    pub leg_id: String,
    pub kind: PqPreauthKind,
    pub signer_commitment: String,
    pub transcript_root: String,
    pub proof_root: String,
    pub signature_root: String,
    pub aggregate_key_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub verified_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqPreauthStatus,
}

impl PqPreauthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "preauth_id": self.preauth_id,
            "slot_id": self.slot_id,
            "leg_id": self.leg_id,
            "kind": self.kind.as_str(),
            "signer_commitment": self.signer_commitment,
            "transcript_root": self.transcript_root,
            "proof_root": self.proof_root,
            "signature_root": self.signature_root,
            "aggregate_key_root": self.aggregate_key_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "verified_at_height": self.verified_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityLock {
    pub lock_id: String,
    pub slot_id: String,
    pub leg_id: String,
    pub venue_commitment: String,
    pub asset_commitment_root: String,
    pub amount_bucket_root: String,
    pub lock_proof_root: String,
    pub release_note_root: String,
    pub locked_at_height: u64,
    pub expires_at_height: u64,
    pub status: LiquidityLockStatus,
}

impl LiquidityLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "slot_id": self.slot_id,
            "leg_id": self.leg_id,
            "venue_commitment": self.venue_commitment,
            "asset_commitment_root": self.asset_commitment_root,
            "amount_bucket_root": self.amount_bucket_root,
            "lock_proof_root": self.lock_proof_root,
            "release_note_root": self.release_note_root,
            "locked_at_height": self.locked_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AtomicFlashBundle {
    pub bundle_id: String,
    pub lane: FlashLane,
    pub builder_commitment: String,
    pub slot_ids: BTreeSet<String>,
    pub leg_ids: BTreeSet<String>,
    pub lock_ids: BTreeSet<String>,
    pub preauth_ids: BTreeSet<String>,
    pub route_plan_root: String,
    pub atomicity_root: String,
    pub proof_root: String,
    pub fee_quote_root: String,
    pub privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
    pub status: BundleStatus,
}

impl AtomicFlashBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "lane": self.lane.as_str(),
            "builder_commitment": self.builder_commitment,
            "slot_ids_root": set_root("FLASH-SETTLEMENT-BUNDLE-SLOT-IDS", &self.slot_ids),
            "leg_ids_root": set_root("FLASH-SETTLEMENT-BUNDLE-LEG-IDS", &self.leg_ids),
            "lock_ids_root": set_root("FLASH-SETTLEMENT-BUNDLE-LOCK-IDS", &self.lock_ids),
            "preauth_ids_root": set_root("FLASH-SETTLEMENT-BUNDLE-PREAUTH-IDS", &self.preauth_ids),
            "route_plan_root": self.route_plan_root,
            "atomicity_root": self.atomicity_root,
            "proof_root": self.proof_root,
            "fee_quote_root": self.fee_quote_root,
            "privacy_set_size": self.privacy_set_size,
            "target_latency_ms": self.target_latency_ms,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub publisher_commitment: String,
    pub execution_root: String,
    pub note_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub proof_root: String,
    pub fee_paid_root: String,
    pub published_at_height: u64,
    pub finalizes_at_height: u64,
    pub status: ReceiptStatus,
}

impl PrivateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "publisher_commitment": self.publisher_commitment,
            "execution_root": self.execution_root,
            "note_root": self.note_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "proof_root": self.proof_root,
            "fee_paid_root": self.fee_paid_root,
            "published_at_height": self.published_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvent {
    pub slash_id: String,
    pub kind: SlashKind,
    pub accused_commitment: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub disputed_root: String,
    pub penalty_bps: u64,
    pub opened_at_height: u64,
}

impl SlashingEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "kind": self.kind.as_str(),
            "accused_commitment": self.accused_commitment,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "disputed_root": self.disputed_root,
            "penalty_bps": self.penalty_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveFlashSlotRequest {
    pub lane: FlashLane,
    pub reserver_commitment: String,
    pub intent_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub expected_leg_count: usize,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitSealedLegRequest {
    pub slot_id: String,
    pub kind: ContractLegKind,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub sealed_call_root: String,
    pub encrypted_witness_root: String,
    pub asset_commitment_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub required_lock_root: String,
    pub dependency_root: String,
    pub privacy_set_size: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyPqPreauthorizationRequest {
    pub slot_id: String,
    pub leg_id: String,
    pub kind: PqPreauthKind,
    pub signer_commitment: String,
    pub transcript_root: String,
    pub proof_root: String,
    pub signature_root: String,
    pub aggregate_key_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoordinateLiquidityLockRequest {
    pub slot_id: String,
    pub leg_id: String,
    pub venue_commitment: String,
    pub asset_commitment_root: String,
    pub amount_bucket_root: String,
    pub lock_proof_root: String,
    pub release_note_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildAtomicBundleRequest {
    pub lane: FlashLane,
    pub builder_commitment: String,
    pub slot_ids: Vec<String>,
    pub route_plan_root: String,
    pub atomicity_root: String,
    pub proof_root: String,
    pub fee_quote_root: String,
    pub privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishPrivateReceiptRequest {
    pub bundle_id: String,
    pub publisher_commitment: String,
    pub execution_root: String,
    pub note_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub proof_root: String,
    pub fee_paid_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueRebateRequest {
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashViolationRequest {
    pub kind: SlashKind,
    pub accused_commitment: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub disputed_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub counters: Counters,
    pub slots: BTreeMap<String, FlashSettlementSlot>,
    pub legs: BTreeMap<String, SealedExecutionLeg>,
    pub preauthorizations: BTreeMap<String, PqPreauthorization>,
    pub liquidity_locks: BTreeMap<String, LiquidityLock>,
    pub bundles: BTreeMap<String, AtomicFlashBundle>,
    pub receipts: BTreeMap<String, PrivateReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashes: BTreeMap<String, SlashingEvent>,
    pub seen_nullifiers: BTreeSet<String>,
    pub fast_operators: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut fast_operators = BTreeSet::new();
        fast_operators.insert(deterministic_root("operator", "devnet-flash-builder-0", 0));
        fast_operators.insert(deterministic_root("operator", "devnet-flash-builder-1", 1));
        Self {
            config: Config::devnet(),
            current_height: DEFAULT_DEVNET_HEIGHT,
            current_epoch: DEFAULT_DEVNET_EPOCH,
            counters: Counters::default(),
            slots: BTreeMap::new(),
            legs: BTreeMap::new(),
            preauthorizations: BTreeMap::new(),
            liquidity_locks: BTreeMap::new(),
            bundles: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashes: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
            fast_operators,
        }
    }

    pub fn advance_height(&mut self, next_height: u64) -> Result<()> {
        if next_height < self.current_height {
            return Err("next height cannot move backward".to_string());
        }
        self.current_height = next_height;
        self.current_epoch = next_height / self.config.slot_ttl_blocks.max(1);
        Ok(())
    }

    pub fn reserve_flash_settlement_slot(
        &mut self,
        request: ReserveFlashSlotRequest,
    ) -> Result<FlashSettlementSlot> {
        ensure_capacity("slots", self.slots.len(), self.config.max_slots)?;
        ensure_non_empty("reserver_commitment", &request.reserver_commitment)?;
        ensure_root("intent_root", &request.intent_root)?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        ensure_min_privacy(&self.config, request.privacy_set_size)?;
        if request.expected_leg_count == 0
            || request.expected_leg_count > self.config.max_legs_per_slot
        {
            return Err("expected leg count outside configured slot bounds".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("slot max fee exceeds low-fee policy".to_string());
        }

        let slot_id = flash_slot_id(
            request.lane,
            &request.reserver_commitment,
            &request.intent_root,
            request.nonce,
        );
        ensure_absent("slot", &self.slots, &slot_id)?;
        let slot = FlashSettlementSlot {
            slot_id: slot_id.clone(),
            lane: request.lane,
            reserver_commitment: request.reserver_commitment,
            intent_root: request.intent_root,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            priority_weight: request.lane.priority_weight(),
            reserved_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.slot_ttl_blocks,
            expected_leg_count: request.expected_leg_count,
            leg_ids: BTreeSet::new(),
            preauth_ids: BTreeSet::new(),
            bundle_id: None,
            status: SlotStatus::Reserved,
        };
        self.slots.insert(slot_id, slot.clone());
        self.counters.slots_reserved = self.counters.slots_reserved.saturating_add(1);
        Ok(slot)
    }

    pub fn submit_sealed_cross_contract_execution_leg(
        &mut self,
        request: SubmitSealedLegRequest,
    ) -> Result<SealedExecutionLeg> {
        ensure_capacity("legs", self.legs.len(), self.config.max_legs)?;
        ensure_root("sealed_call_root", &request.sealed_call_root)?;
        ensure_root("encrypted_witness_root", &request.encrypted_witness_root)?;
        ensure_root("asset_commitment_root", &request.asset_commitment_root)?;
        ensure_root("nullifier_root", &request.nullifier_root)?;
        ensure_root("output_note_root", &request.output_note_root)?;
        ensure_root("required_lock_root", &request.required_lock_root)?;
        ensure_root("dependency_root", &request.dependency_root)?;
        ensure_min_privacy(&self.config, request.privacy_set_size)?;
        if self.seen_nullifiers.contains(&request.nullifier_root) {
            return Err("nullifier root already seen".to_string());
        }

        let slot = self
            .slots
            .get_mut(&request.slot_id)
            .ok_or_else(|| "slot not found".to_string())?;
        if !slot.status.accepts_legs() {
            return Err("slot no longer accepts sealed legs".to_string());
        }
        if self.current_height > slot.expires_at_height {
            slot.status = SlotStatus::Expired;
            return Err("slot expired".to_string());
        }
        if slot.leg_ids.len() >= slot.expected_leg_count
            || slot.leg_ids.len() >= self.config.max_legs_per_slot
        {
            return Err("slot leg capacity exhausted".to_string());
        }

        let leg_id = execution_leg_id(
            &request.slot_id,
            request.kind,
            &request.contract_commitment,
            &request.sealed_call_root,
            request.nonce,
        );
        ensure_absent("leg", &self.legs, &leg_id)?;
        let leg = SealedExecutionLeg {
            leg_id: leg_id.clone(),
            slot_id: request.slot_id.clone(),
            kind: request.kind,
            contract_commitment: request.contract_commitment,
            caller_commitment: request.caller_commitment,
            sealed_call_root: request.sealed_call_root,
            encrypted_witness_root: request.encrypted_witness_root,
            asset_commitment_root: request.asset_commitment_root,
            nullifier_root: request.nullifier_root.clone(),
            output_note_root: request.output_note_root,
            required_lock_root: request.required_lock_root,
            dependency_root: request.dependency_root,
            privacy_set_size: request.privacy_set_size,
            submitted_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.leg_ttl_blocks,
            preauth_id: None,
            lock_id: None,
            bundle_id: None,
            status: LegStatus::Sealed,
        };
        slot.leg_ids.insert(leg_id.clone());
        slot.status = SlotStatus::Legged;
        self.seen_nullifiers.insert(request.nullifier_root);
        self.legs.insert(leg_id, leg.clone());
        self.counters.legs_submitted = self.counters.legs_submitted.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        Ok(leg)
    }

    pub fn verify_pq_preauthorization(
        &mut self,
        request: VerifyPqPreauthorizationRequest,
    ) -> Result<PqPreauthorization> {
        ensure_capacity(
            "preauthorizations",
            self.preauthorizations.len(),
            self.config.max_preauths,
        )?;
        ensure_root("transcript_root", &request.transcript_root)?;
        ensure_root("proof_root", &request.proof_root)?;
        ensure_root("signature_root", &request.signature_root)?;
        ensure_root("aggregate_key_root", &request.aggregate_key_root)?;
        ensure_pq(&self.config, request.pq_security_bits)?;
        ensure_min_privacy(&self.config, request.privacy_set_size)?;

        let slot = self
            .slots
            .get_mut(&request.slot_id)
            .ok_or_else(|| "slot not found".to_string())?;
        let leg = self
            .legs
            .get_mut(&request.leg_id)
            .ok_or_else(|| "leg not found".to_string())?;
        if leg.slot_id != request.slot_id {
            return Err("preauthorization leg does not belong to slot".to_string());
        }
        if self.current_height > leg.expires_at_height {
            leg.status = LegStatus::Rejected;
            return Err("leg expired before pq preauthorization".to_string());
        }

        let preauth_id = pq_preauthorization_id(
            request.kind,
            &request.leg_id,
            &request.proof_root,
            request.nonce,
        );
        ensure_absent("preauthorization", &self.preauthorizations, &preauth_id)?;
        let preauth = PqPreauthorization {
            preauth_id: preauth_id.clone(),
            slot_id: request.slot_id,
            leg_id: request.leg_id.clone(),
            kind: request.kind,
            signer_commitment: request.signer_commitment,
            transcript_root: request.transcript_root,
            proof_root: request.proof_root,
            signature_root: request.signature_root,
            aggregate_key_root: request.aggregate_key_root,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            verified_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.preauth_ttl_blocks,
            status: PqPreauthStatus::Verified,
        };
        leg.preauth_id = Some(preauth_id.clone());
        leg.status = LegStatus::PqPreauthorized;
        slot.preauth_ids.insert(preauth_id.clone());
        slot.status = SlotStatus::Preauthorized;
        self.preauthorizations.insert(preauth_id, preauth.clone());
        self.counters.preauths_verified = self.counters.preauths_verified.saturating_add(1);
        Ok(preauth)
    }

    pub fn coordinate_liquidity_lock(
        &mut self,
        request: CoordinateLiquidityLockRequest,
    ) -> Result<LiquidityLock> {
        ensure_capacity(
            "liquidity_locks",
            self.liquidity_locks.len(),
            self.config.max_locks,
        )?;
        ensure_root("asset_commitment_root", &request.asset_commitment_root)?;
        ensure_root("amount_bucket_root", &request.amount_bucket_root)?;
        ensure_root("lock_proof_root", &request.lock_proof_root)?;
        ensure_root("release_note_root", &request.release_note_root)?;

        let leg = self
            .legs
            .get_mut(&request.leg_id)
            .ok_or_else(|| "leg not found".to_string())?;
        if leg.slot_id != request.slot_id {
            return Err("lock leg does not belong to slot".to_string());
        }
        if !leg.kind.mutates_liquidity() {
            return Err("leg kind does not require a liquidity lock".to_string());
        }
        if !matches!(leg.status, LegStatus::PqPreauthorized | LegStatus::Sealed) {
            return Err("leg cannot accept liquidity lock in current status".to_string());
        }

        let lock_id = liquidity_lock_id(
            &request.slot_id,
            &request.leg_id,
            &request.venue_commitment,
            request.nonce,
        );
        ensure_absent("liquidity lock", &self.liquidity_locks, &lock_id)?;
        let lock = LiquidityLock {
            lock_id: lock_id.clone(),
            slot_id: request.slot_id,
            leg_id: request.leg_id,
            venue_commitment: request.venue_commitment,
            asset_commitment_root: request.asset_commitment_root,
            amount_bucket_root: request.amount_bucket_root,
            lock_proof_root: request.lock_proof_root,
            release_note_root: request.release_note_root,
            locked_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.lock_ttl_blocks,
            status: LiquidityLockStatus::Locked,
        };
        leg.lock_id = Some(lock_id.clone());
        leg.status = LegStatus::LiquidityLocked;
        self.liquidity_locks.insert(lock_id, lock.clone());
        self.counters.liquidity_locks_coordinated =
            self.counters.liquidity_locks_coordinated.saturating_add(1);
        Ok(lock)
    }

    pub fn build_atomic_flash_settlement_bundle(
        &mut self,
        request: BuildAtomicBundleRequest,
    ) -> Result<AtomicFlashBundle> {
        ensure_capacity("bundles", self.bundles.len(), self.config.max_bundles)?;
        ensure_unique("slot_ids", &request.slot_ids)?;
        ensure_root("route_plan_root", &request.route_plan_root)?;
        ensure_root("atomicity_root", &request.atomicity_root)?;
        ensure_root("proof_root", &request.proof_root)?;
        ensure_root("fee_quote_root", &request.fee_quote_root)?;
        ensure_min_privacy(&self.config, request.privacy_set_size)?;
        if request.target_latency_ms > self.config.target_latency_ms {
            return Err("bundle target latency exceeds fast-settlement target".to_string());
        }
        if request.slot_ids.is_empty() {
            return Err("bundle requires at least one slot".to_string());
        }

        let mut slot_ids = BTreeSet::new();
        let mut leg_ids = BTreeSet::new();
        let mut lock_ids = BTreeSet::new();
        let mut preauth_ids = BTreeSet::new();
        for slot_id in request.slot_ids.iter() {
            let slot = self
                .slots
                .get(slot_id)
                .ok_or_else(|| "bundle slot not found".to_string())?;
            if slot.lane != request.lane {
                return Err("bundle lane mismatch".to_string());
            }
            if self.current_height > slot.expires_at_height {
                return Err("bundle contains expired slot".to_string());
            }
            if slot.leg_ids.len() != slot.expected_leg_count {
                return Err("bundle slot does not have expected leg count".to_string());
            }
            slot_ids.insert(slot_id.clone());
            for leg_id in slot.leg_ids.iter() {
                let leg = self
                    .legs
                    .get(leg_id)
                    .ok_or_else(|| "bundle leg not found".to_string())?;
                if !leg.status.live() {
                    return Err("bundle contains non-live leg".to_string());
                }
                if leg.preauth_id.is_none() {
                    return Err("bundle leg missing pq preauthorization".to_string());
                }
                leg_ids.insert(leg_id.clone());
                if let Some(preauth_id) = leg.preauth_id.as_ref() {
                    preauth_ids.insert(preauth_id.clone());
                }
                if let Some(lock_id) = leg.lock_id.as_ref() {
                    lock_ids.insert(lock_id.clone());
                }
            }
        }
        if leg_ids.len() > self.config.max_legs_per_bundle {
            return Err("bundle leg capacity exceeded".to_string());
        }
        if lock_ids.len() > self.config.max_locks_per_bundle {
            return Err("bundle lock capacity exceeded".to_string());
        }

        let bundle_id = atomic_bundle_id(
            &request.builder_commitment,
            &request.route_plan_root,
            &request.atomicity_root,
            request.nonce,
        );
        ensure_absent("bundle", &self.bundles, &bundle_id)?;
        let bundle = AtomicFlashBundle {
            bundle_id: bundle_id.clone(),
            lane: request.lane,
            builder_commitment: request.builder_commitment,
            slot_ids,
            leg_ids,
            lock_ids,
            preauth_ids,
            route_plan_root: request.route_plan_root,
            atomicity_root: request.atomicity_root,
            proof_root: request.proof_root,
            fee_quote_root: request.fee_quote_root,
            privacy_set_size: request.privacy_set_size,
            target_latency_ms: request.target_latency_ms,
            built_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.bundle_ttl_blocks,
            status: BundleStatus::LiquidityLocked,
        };

        for slot_id in bundle.slot_ids.iter() {
            if let Some(slot) = self.slots.get_mut(slot_id) {
                slot.bundle_id = Some(bundle_id.clone());
                slot.status = SlotStatus::Bundled;
            }
        }
        for leg_id in bundle.leg_ids.iter() {
            if let Some(leg) = self.legs.get_mut(leg_id) {
                leg.bundle_id = Some(bundle_id.clone());
                leg.status = LegStatus::Bundled;
            }
        }
        for preauth_id in bundle.preauth_ids.iter() {
            if let Some(preauth) = self.preauthorizations.get_mut(preauth_id) {
                preauth.status = PqPreauthStatus::Consumed;
            }
        }
        self.bundles.insert(bundle_id, bundle.clone());
        self.counters.bundles_built = self.counters.bundles_built.saturating_add(1);
        Ok(bundle)
    }

    pub fn publish_private_receipt(
        &mut self,
        request: PublishPrivateReceiptRequest,
    ) -> Result<PrivateReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        ensure_root("execution_root", &request.execution_root)?;
        ensure_root("note_root", &request.note_root)?;
        ensure_root("spent_nullifier_root", &request.spent_nullifier_root)?;
        ensure_root("output_commitment_root", &request.output_commitment_root)?;
        ensure_root("proof_root", &request.proof_root)?;
        ensure_root("fee_paid_root", &request.fee_paid_root)?;

        let bundle = self
            .bundles
            .get_mut(&request.bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        if self.current_height > bundle.expires_at_height {
            bundle.status = BundleStatus::Failed;
            self.counters.bundles_failed = self.counters.bundles_failed.saturating_add(1);
            return Err("bundle expired before receipt publication".to_string());
        }

        let receipt_id = private_receipt_id(
            &request.bundle_id,
            &request.execution_root,
            &request.note_root,
            request.nonce,
        );
        ensure_absent("receipt", &self.receipts, &receipt_id)?;
        let receipt = PrivateReceipt {
            receipt_id: receipt_id.clone(),
            bundle_id: request.bundle_id.clone(),
            publisher_commitment: request.publisher_commitment,
            execution_root: request.execution_root,
            note_root: request.note_root,
            spent_nullifier_root: request.spent_nullifier_root,
            output_commitment_root: request.output_commitment_root,
            proof_root: request.proof_root,
            fee_paid_root: request.fee_paid_root,
            published_at_height: self.current_height,
            finalizes_at_height: self.current_height + self.config.receipt_finality_blocks,
            status: ReceiptStatus::Published,
        };

        bundle.status = BundleStatus::Receipted;
        for slot_id in bundle.slot_ids.iter() {
            if let Some(slot) = self.slots.get_mut(slot_id) {
                slot.status = SlotStatus::Settled;
                self.counters.slots_settled = self.counters.slots_settled.saturating_add(1);
            }
        }
        for leg_id in bundle.leg_ids.iter() {
            if let Some(leg) = self.legs.get_mut(leg_id) {
                leg.status = LegStatus::Receipted;
            }
        }
        for lock_id in bundle.lock_ids.iter() {
            if let Some(lock) = self.liquidity_locks.get_mut(lock_id) {
                lock.status = LiquidityLockStatus::Consumed;
            }
        }

        self.receipts.insert(receipt_id, receipt.clone());
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        Ok(receipt)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        ensure_non_empty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_root("rebate_note_root", &request.rebate_note_root)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.rebate_bps > self.config.target_rebate_bps + self.config.liquidity_rebate_bps {
            return Err("rebate exceeds configured low-fee budget".to_string());
        }
        let receipt = self
            .receipts
            .get_mut(&request.receipt_id)
            .ok_or_else(|| "receipt not found".to_string())?;
        if matches!(
            receipt.status,
            ReceiptStatus::Disputed | ReceiptStatus::Slashed
        ) {
            return Err("cannot rebate disputed receipt".to_string());
        }

        let rebate_id = fee_rebate_id(
            &request.receipt_id,
            &request.beneficiary_commitment,
            &request.rebate_note_root,
            request.nonce,
        );
        ensure_absent("rebate", &self.rebates, &rebate_id)?;
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_note_root: request.rebate_note_root,
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_bps: request.rebate_bps,
            issued_at_height: self.current_height,
        };
        receipt.status = ReceiptStatus::RebateIssued;
        self.rebates.insert(rebate_id, rebate.clone());
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        Ok(rebate)
    }

    pub fn slash_failed_atomicity_or_proof_violation(
        &mut self,
        request: SlashViolationRequest,
    ) -> Result<SlashingEvent> {
        ensure_capacity("slashes", self.slashes.len(), self.config.max_slashes)?;
        ensure_non_empty("accused_commitment", &request.accused_commitment)?;
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_root("evidence_root", &request.evidence_root)?;
        ensure_root("disputed_root", &request.disputed_root)?;
        let penalty_bps = if request.kind.proof_related() {
            self.config.proof_failure_slash_bps
        } else {
            self.config.atomicity_failure_slash_bps
        };
        let slash_id = slash_id(
            request.kind,
            &request.accused_commitment,
            &request.subject_id,
            &request.evidence_root,
            request.nonce,
        );
        ensure_absent("slash", &self.slashes, &slash_id)?;
        self.mark_subject_slashed(&request.subject_id);
        let event = SlashingEvent {
            slash_id: slash_id.clone(),
            kind: request.kind,
            accused_commitment: request.accused_commitment,
            subject_id: request.subject_id,
            evidence_root: request.evidence_root,
            disputed_root: request.disputed_root,
            penalty_bps,
            opened_at_height: self.current_height,
        };
        self.slashes.insert(slash_id, event.clone());
        self.counters.slashes_opened = self.counters.slashes_opened.saturating_add(1);
        Ok(event)
    }

    pub fn expire_stale_records(&mut self) -> u64 {
        let mut expired = 0_u64;
        for slot in self.slots.values_mut() {
            if matches!(
                slot.status,
                SlotStatus::Reserved | SlotStatus::Legged | SlotStatus::Preauthorized
            ) && self.current_height > slot.expires_at_height
            {
                slot.status = SlotStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for leg in self.legs.values_mut() {
            if leg.status.live() && self.current_height > leg.expires_at_height {
                leg.status = LegStatus::Rejected;
                expired = expired.saturating_add(1);
            }
        }
        for preauth in self.preauthorizations.values_mut() {
            if matches!(
                preauth.status,
                PqPreauthStatus::Submitted | PqPreauthStatus::Verified
            ) && self.current_height > preauth.expires_at_height
            {
                preauth.status = PqPreauthStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for lock in self.liquidity_locks.values_mut() {
            if matches!(
                lock.status,
                LiquidityLockStatus::Reserved | LiquidityLockStatus::Locked
            ) && self.current_height > lock.expires_at_height
            {
                lock.status = LiquidityLockStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for bundle in self.bundles.values_mut() {
            if matches!(
                bundle.status,
                BundleStatus::Built | BundleStatus::LiquidityLocked | BundleStatus::Proving
            ) && self.current_height > bundle.expires_at_height
            {
                bundle.status = BundleStatus::Failed;
                self.counters.bundles_failed = self.counters.bundles_failed.saturating_add(1);
                expired = expired.saturating_add(1);
            }
        }
        expired
    }

    pub fn roots(&self) -> Roots {
        let slot_root = map_root(
            "FLASH-SETTLEMENT-SLOTS",
            &self.slots,
            FlashSettlementSlot::public_record,
        );
        let leg_root = map_root(
            "FLASH-SETTLEMENT-LEGS",
            &self.legs,
            SealedExecutionLeg::public_record,
        );
        let preauth_root = map_root(
            "FLASH-SETTLEMENT-PREAUTHS",
            &self.preauthorizations,
            PqPreauthorization::public_record,
        );
        let bundle_root = map_root(
            "FLASH-SETTLEMENT-BUNDLES",
            &self.bundles,
            AtomicFlashBundle::public_record,
        );
        let lock_root = map_root(
            "FLASH-SETTLEMENT-LIQUIDITY-LOCKS",
            &self.liquidity_locks,
            LiquidityLock::public_record,
        );
        let receipt_root = map_root(
            "FLASH-SETTLEMENT-RECEIPTS",
            &self.receipts,
            PrivateReceipt::public_record,
        );
        let rebate_root = map_root(
            "FLASH-SETTLEMENT-REBATES",
            &self.rebates,
            FeeRebate::public_record,
        );
        let slashing_root = map_root(
            "FLASH-SETTLEMENT-SLASHES",
            &self.slashes,
            SlashingEvent::public_record,
        );
        let nullifier_root = set_root("FLASH-SETTLEMENT-NULLIFIERS", &self.seen_nullifiers);
        let operator_root = set_root("FLASH-SETTLEMENT-FAST-OPERATORS", &self.fast_operators);
        let public_without_state = self.public_record_without_state_root_with_roots(
            &slot_root,
            &leg_root,
            &preauth_root,
            &bundle_root,
            &lock_root,
            &receipt_root,
            &rebate_root,
            &slashing_root,
            &nullifier_root,
            &operator_root,
        );
        let public_record_root = public_record_root(
            "FLASH-SETTLEMENT-PUBLIC-RECORD",
            &[public_without_state.clone()],
        );
        let state_root = state_root_from_record(&public_without_state);
        Roots {
            slot_root,
            leg_root,
            preauth_root,
            bundle_root,
            lock_root,
            receipt_root,
            rebate_root,
            slashing_root,
            nullifier_root,
            operator_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        self.public_record_without_state_root_with_roots(
            &roots.slot_root,
            &roots.leg_root,
            &roots.preauth_root,
            &roots.bundle_root,
            &roots.lock_root,
            &roots.receipt_root,
            &roots.rebate_root,
            &roots.slashing_root,
            &roots.nullifier_root,
            &roots.operator_root,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root_with_roots(
            &roots.slot_root,
            &roots.leg_root,
            &roots.preauth_root,
            &roots.bundle_root,
            &roots.lock_root,
            &roots.receipt_root,
            &roots.rebate_root,
            &roots.slashing_root,
            &roots.nullifier_root,
            &roots.operator_root,
        );
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "public_record_root".to_string(),
                Value::String(roots.public_record_root),
            );
            object.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn public_record_without_state_root_with_roots(
        &self,
        slot_root: &str,
        leg_root: &str,
        preauth_root: &str,
        bundle_root: &str,
        lock_root: &str,
        receipt_root: &str,
        rebate_root: &str,
        slashing_root: &str,
        nullifier_root: &str,
        operator_root: &str,
    ) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "counters": self.counters,
            "roots": {
                "slot_root": slot_root,
                "leg_root": leg_root,
                "preauth_root": preauth_root,
                "bundle_root": bundle_root,
                "lock_root": lock_root,
                "receipt_root": receipt_root,
                "rebate_root": rebate_root,
                "slashing_root": slashing_root,
                "nullifier_root": nullifier_root,
                "operator_root": operator_root,
            },
            "policy": {
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "target_latency_ms": self.config.target_latency_ms,
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "target_rebate_bps": self.config.target_rebate_bps,
            },
        })
    }

    fn mark_subject_slashed(&mut self, subject_id: &str) {
        if let Some(slot) = self.slots.get_mut(subject_id) {
            slot.status = SlotStatus::Slashed;
        }
        if let Some(leg) = self.legs.get_mut(subject_id) {
            leg.status = LegStatus::Slashed;
        }
        if let Some(preauth) = self.preauthorizations.get_mut(subject_id) {
            preauth.status = PqPreauthStatus::Slashed;
        }
        if let Some(lock) = self.liquidity_locks.get_mut(subject_id) {
            lock.status = LiquidityLockStatus::Slashed;
        }
        if let Some(bundle) = self.bundles.get_mut(subject_id) {
            bundle.status = BundleStatus::Slashed;
        }
        if let Some(receipt) = self.receipts.get_mut(subject_id) {
            receipt.status = ReceiptStatus::Slashed;
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn flash_slot_id(
    lane: FlashLane,
    reserver_commitment: &str,
    intent_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(reserver_commitment),
            HashPart::Str(intent_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn execution_leg_id(
    slot_id: &str,
    kind: ContractLegKind,
    contract_commitment: &str,
    sealed_call_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-LEG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(slot_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_call_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_preauthorization_id(
    kind: PqPreauthKind,
    leg_id: &str,
    proof_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-PQ-PREAUTH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(leg_id),
            HashPart::Str(proof_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn liquidity_lock_id(
    slot_id: &str,
    leg_id: &str,
    venue_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-LIQUIDITY-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(slot_id),
            HashPart::Str(leg_id),
            HashPart::Str(venue_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn atomic_bundle_id(
    builder_commitment: &str,
    route_plan_root: &str,
    atomicity_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(builder_commitment),
            HashPart::Str(route_plan_root),
            HashPart::Str(atomicity_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_receipt_id(
    bundle_id: &str,
    execution_root: &str,
    note_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bundle_id),
            HashPart::Str(execution_root),
            HashPart::Str(note_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn fee_rebate_id(
    receipt_id: &str,
    beneficiary_commitment: &str,
    rebate_note_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(rebate_note_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn slash_id(
    kind: SlashKind,
    accused_commitment: &str,
    subject_id: &str,
    evidence_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(accused_commitment),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root(
        "PRIVATE-L2-FAST-PRIVATE-CROSS-CONTRACT-FLASH-SETTLEMENT-STATE-ROOT",
        record,
    )
}

fn public_records_from_map<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(public_record).collect()
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    public_record_root(domain, &public_records_from_map(map, public_record))
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|item| Value::String(item.clone()))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must be non-empty"));
    }
    Ok(())
}

fn ensure_root(name: &str, value: &str) -> Result<()> {
    ensure_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be hash-like"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} exceeds max bps"));
    }
    Ok(())
}

fn ensure_pq(config: &Config, bits: u16) -> Result<()> {
    if bits < config.min_pq_security_bits {
        return Err("pq security bits below configured minimum".to_string());
    }
    Ok(())
}

fn ensure_min_privacy(config: &Config, observed: u64) -> Result<()> {
    if observed < config.min_privacy_set_size {
        return Err("privacy set below configured minimum".to_string());
    }
    Ok(())
}

fn ensure_capacity(name: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        return Err(format!("{name} capacity exhausted"));
    }
    Ok(())
}

fn ensure_unique(name: &str, values: &[String]) -> Result<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{name} must be unique"));
    }
    Ok(())
}

fn ensure_absent<T>(name: &str, map: &BTreeMap<String, T>, id: &str) -> Result<()> {
    if map.contains_key(id) {
        return Err(format!("{name} already exists"));
    }
    Ok(())
}

pub fn invariant_anchor_001(state: &State) -> Value {
    json!({"invariant":"flash_anchor_001","state_root":state.state_root(),"slots":state.counters.slots_reserved,"legs":state.counters.legs_submitted})
}

pub fn invariant_anchor_002(state: &State) -> Value {
    json!({"invariant":"flash_anchor_002","state_root":state.state_root(),"preauths":state.counters.preauths_verified,"bundles":state.counters.bundles_built})
}

pub fn invariant_anchor_003(state: &State) -> Value {
    json!({"invariant":"flash_anchor_003","state_root":state.state_root(),"locks":state.counters.liquidity_locks_coordinated,"receipts":state.counters.receipts_published})
}

pub fn invariant_anchor_004(state: &State) -> Value {
    json!({"invariant":"flash_anchor_004","state_root":state.state_root(),"rebates":state.counters.rebates_issued,"slashes":state.counters.slashes_opened})
}

pub fn invariant_anchor_005(state: &State) -> Value {
    let roots = state.roots();
    json!({"invariant":"flash_anchor_005","slot_root":roots.slot_root,"leg_root":roots.leg_root})
}

pub fn invariant_anchor_006(state: &State) -> Value {
    let roots = state.roots();
    json!({"invariant":"flash_anchor_006","preauth_root":roots.preauth_root,"bundle_root":roots.bundle_root})
}

pub fn invariant_anchor_007(state: &State) -> Value {
    let roots = state.roots();
    json!({"invariant":"flash_anchor_007","lock_root":roots.lock_root,"receipt_root":roots.receipt_root})
}

pub fn invariant_anchor_008(state: &State) -> Value {
    let roots = state.roots();
    json!({"invariant":"flash_anchor_008","rebate_root":roots.rebate_root,"slashing_root":roots.slashing_root})
}

pub fn invariant_anchor_009(state: &State) -> Value {
    let roots = state.roots();
    json!({"invariant":"flash_anchor_009","nullifier_root":roots.nullifier_root,"operator_root":roots.operator_root})
}

pub fn invariant_anchor_010(state: &State) -> Value {
    json!({"invariant":"flash_anchor_010","height":state.current_height,"epoch":state.current_epoch,"chain_id":CHAIN_ID})
}

pub fn invariant_anchor_011(state: &State) -> Value {
    json!({"invariant":"flash_anchor_011","slots":state.slots.len(),"max_slots":state.config.max_slots})
}

pub fn invariant_anchor_012(state: &State) -> Value {
    json!({"invariant":"flash_anchor_012","legs":state.legs.len(),"max_legs":state.config.max_legs})
}

pub fn invariant_anchor_013(state: &State) -> Value {
    json!({"invariant":"flash_anchor_013","preauthorizations":state.preauthorizations.len(),"max_preauths":state.config.max_preauths})
}

pub fn invariant_anchor_014(state: &State) -> Value {
    json!({"invariant":"flash_anchor_014","liquidity_locks":state.liquidity_locks.len(),"max_locks":state.config.max_locks})
}

pub fn invariant_anchor_015(state: &State) -> Value {
    json!({"invariant":"flash_anchor_015","bundles":state.bundles.len(),"max_bundles":state.config.max_bundles})
}

pub fn invariant_anchor_016(state: &State) -> Value {
    json!({"invariant":"flash_anchor_016","receipts":state.receipts.len(),"max_receipts":state.config.max_receipts})
}

pub fn invariant_anchor_017(state: &State) -> Value {
    json!({"invariant":"flash_anchor_017","rebates":state.rebates.len(),"max_rebates":state.config.max_rebates})
}

pub fn invariant_anchor_018(state: &State) -> Value {
    json!({"invariant":"flash_anchor_018","slashes":state.slashes.len(),"max_slashes":state.config.max_slashes})
}

pub fn invariant_anchor_019(state: &State) -> Value {
    json!({"invariant":"flash_anchor_019","min_privacy_set_size":state.config.min_privacy_set_size,"target_privacy_set_size":state.config.target_privacy_set_size})
}

pub fn invariant_anchor_020(state: &State) -> Value {
    json!({"invariant":"flash_anchor_020","min_pq_security_bits":state.config.min_pq_security_bits,"target_latency_ms":state.config.target_latency_ms})
}

pub fn invariant_anchor_021(state: &State) -> Value {
    json!({"invariant":"flash_anchor_021","slot_ttl_blocks":state.config.slot_ttl_blocks,"bundle_ttl_blocks":state.config.bundle_ttl_blocks})
}

pub fn invariant_anchor_022(state: &State) -> Value {
    json!({"invariant":"flash_anchor_022","leg_ttl_blocks":state.config.leg_ttl_blocks,"preauth_ttl_blocks":state.config.preauth_ttl_blocks})
}

pub fn invariant_anchor_023(state: &State) -> Value {
    json!({"invariant":"flash_anchor_023","lock_ttl_blocks":state.config.lock_ttl_blocks,"receipt_finality_blocks":state.config.receipt_finality_blocks})
}

pub fn invariant_anchor_024(state: &State) -> Value {
    json!({"invariant":"flash_anchor_024","max_user_fee_bps":state.config.max_user_fee_bps,"target_rebate_bps":state.config.target_rebate_bps})
}

pub fn invariant_anchor_025(state: &State) -> Value {
    json!({"invariant":"flash_anchor_025","liquidity_rebate_bps":state.config.liquidity_rebate_bps,"proof_failure_slash_bps":state.config.proof_failure_slash_bps})
}

pub fn invariant_anchor_026(state: &State) -> Value {
    json!({"invariant":"flash_anchor_026","atomicity_failure_slash_bps":state.config.atomicity_failure_slash_bps,"fee_asset_id":state.config.fee_asset_id})
}

pub fn invariant_anchor_027(state: &State) -> Value {
    let open = state
        .slots
        .values()
        .filter(|slot| slot.status.accepts_legs())
        .count();
    json!({"invariant":"flash_anchor_027","open_slots":open,"total_slots":state.slots.len()})
}

pub fn invariant_anchor_028(state: &State) -> Value {
    let live = state.legs.values().filter(|leg| leg.status.live()).count();
    json!({"invariant":"flash_anchor_028","live_legs":live,"total_legs":state.legs.len()})
}

pub fn invariant_anchor_029(state: &State) -> Value {
    let verified = state
        .preauthorizations
        .values()
        .filter(|preauth| {
            matches!(
                preauth.status,
                PqPreauthStatus::Verified | PqPreauthStatus::Consumed
            )
        })
        .count();
    json!({"invariant":"flash_anchor_029","verified_or_consumed_preauths":verified,"total_preauths":state.preauthorizations.len()})
}

pub fn invariant_anchor_030(state: &State) -> Value {
    let locked = state
        .liquidity_locks
        .values()
        .filter(|lock| {
            matches!(
                lock.status,
                LiquidityLockStatus::Locked | LiquidityLockStatus::Consumed
            )
        })
        .count();
    json!({"invariant":"flash_anchor_030","locked_or_consumed_liquidity":locked,"total_locks":state.liquidity_locks.len()})
}

pub fn invariant_anchor_031(state: &State) -> Value {
    let settled = state
        .bundles
        .values()
        .filter(|bundle| {
            matches!(
                bundle.status,
                BundleStatus::Settled | BundleStatus::Receipted
            )
        })
        .count();
    json!({"invariant":"flash_anchor_031","settled_or_receipted_bundles":settled,"total_bundles":state.bundles.len()})
}

pub fn invariant_anchor_032(state: &State) -> Value {
    let finalizable = state
        .receipts
        .values()
        .filter(|receipt| state.current_height >= receipt.finalizes_at_height)
        .count();
    json!({"invariant":"flash_anchor_032","finalizable_receipts":finalizable,"total_receipts":state.receipts.len()})
}

pub fn invariant_anchor_033(state: &State) -> Value {
    json!({"invariant":"flash_anchor_033","seen_nullifiers":state.seen_nullifiers.len(),"counter_nullifiers":state.counters.nullifiers_seen})
}

pub fn invariant_anchor_034(state: &State) -> Value {
    json!({"invariant":"flash_anchor_034","fast_operators":state.fast_operators.len(),"operator_root":set_root("FLASH-SETTLEMENT-FAST-OPERATORS", &state.fast_operators)})
}

pub fn invariant_anchor_035(state: &State) -> Value {
    json!({"invariant":"flash_anchor_035","hash_suite":state.config.hash_suite,"pq_preauth_suite":state.config.pq_preauth_suite})
}

pub fn invariant_anchor_036(state: &State) -> Value {
    json!({"invariant":"flash_anchor_036","flash_proof_suite":state.config.flash_proof_suite,"receipt_suite":state.config.receipt_suite})
}

pub fn invariant_anchor_037(state: &State) -> Value {
    json!({"invariant":"flash_anchor_037","rebate_suite":state.config.low_fee_rebate_suite,"slashing_suite":state.config.slashing_suite})
}

pub fn invariant_anchor_038(state: &State) -> Value {
    json!({"invariant":"flash_anchor_038","l2_network":state.config.l2_network,"monero_network":state.config.monero_network})
}

pub fn invariant_anchor_039(state: &State) -> Value {
    let roots = state.roots();
    json!({"invariant":"flash_anchor_039","public_record_root":roots.public_record_root,"state_root":roots.state_root})
}

pub fn invariant_anchor_040(state: &State) -> Value {
    json!({"invariant":"flash_anchor_040","protocol_version":state.config.protocol_version,"schema_version":state.config.schema_version})
}

pub fn flash_runtime_audit_record(state: &State) -> Value {
    let roots = state.roots();
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "chain_id": CHAIN_ID,
        "height": state.current_height,
        "epoch": state.current_epoch,
        "roots": roots,
        "counters": state.counters,
        "capacity": {
            "slots": [state.slots.len(), state.config.max_slots],
            "legs": [state.legs.len(), state.config.max_legs],
            "preauthorizations": [state.preauthorizations.len(), state.config.max_preauths],
            "locks": [state.liquidity_locks.len(), state.config.max_locks],
            "bundles": [state.bundles.len(), state.config.max_bundles],
            "receipts": [state.receipts.len(), state.config.max_receipts],
            "rebates": [state.rebates.len(), state.config.max_rebates],
            "slashes": [state.slashes.len(), state.config.max_slashes]
        }
    })
}

pub fn lane_slot_summary(state: &State, lane: FlashLane) -> Value {
    let total = state
        .slots
        .values()
        .filter(|slot| slot.lane == lane)
        .count();
    let open = state
        .slots
        .values()
        .filter(|slot| slot.lane == lane && slot.status.accepts_legs())
        .count();
    json!({"lane":lane.as_str(),"total_slots":total,"open_slots":open})
}

pub fn lane_bundle_summary(state: &State, lane: FlashLane) -> Value {
    let total = state
        .bundles
        .values()
        .filter(|bundle| bundle.lane == lane)
        .count();
    let receipted = state
        .bundles
        .values()
        .filter(|bundle| bundle.lane == lane && matches!(bundle.status, BundleStatus::Receipted))
        .count();
    json!({"lane":lane.as_str(),"total_bundles":total,"receipted_bundles":receipted})
}

pub fn slot_status_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for slot in state.slots.values() {
        *counts.entry(slot.status.as_str().to_string()).or_default() += 1;
    }
    json!({"kind":"slot_status_summary","counts":counts})
}

pub fn leg_status_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for leg in state.legs.values() {
        *counts.entry(leg.status.as_str().to_string()).or_default() += 1;
    }
    json!({"kind":"leg_status_summary","counts":counts})
}

pub fn preauthorization_status_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for preauth in state.preauthorizations.values() {
        *counts
            .entry(preauth.status.as_str().to_string())
            .or_default() += 1;
    }
    json!({"kind":"preauthorization_status_summary","counts":counts})
}

pub fn liquidity_lock_status_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for lock in state.liquidity_locks.values() {
        *counts.entry(lock.status.as_str().to_string()).or_default() += 1;
    }
    json!({"kind":"liquidity_lock_status_summary","counts":counts})
}

pub fn bundle_status_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for bundle in state.bundles.values() {
        *counts
            .entry(bundle.status.as_str().to_string())
            .or_default() += 1;
    }
    json!({"kind":"bundle_status_summary","counts":counts})
}

pub fn receipt_status_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for receipt in state.receipts.values() {
        *counts
            .entry(receipt.status.as_str().to_string())
            .or_default() += 1;
    }
    json!({"kind":"receipt_status_summary","counts":counts})
}

pub fn slash_kind_summary(state: &State) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for slash in state.slashes.values() {
        *counts.entry(slash.kind.as_str().to_string()).or_default() += 1;
    }
    json!({"kind":"slash_kind_summary","counts":counts})
}

pub fn latency_policy_record(state: &State) -> Value {
    json!({
        "kind": "latency_policy",
        "target_latency_ms": state.config.target_latency_ms,
        "bundle_ttl_blocks": state.config.bundle_ttl_blocks,
        "slot_ttl_blocks": state.config.slot_ttl_blocks,
        "lock_ttl_blocks": state.config.lock_ttl_blocks,
    })
}

pub fn privacy_policy_record(state: &State) -> Value {
    json!({
        "kind": "privacy_policy",
        "min_privacy_set_size": state.config.min_privacy_set_size,
        "target_privacy_set_size": state.config.target_privacy_set_size,
        "seen_nullifier_root": set_root("FLASH-SETTLEMENT-NULLIFIERS", &state.seen_nullifiers),
    })
}

pub fn pq_policy_record(state: &State) -> Value {
    json!({
        "kind": "pq_policy",
        "suite": state.config.pq_preauth_suite,
        "min_pq_security_bits": state.config.min_pq_security_bits,
        "preauthorization_root": map_root(
            "FLASH-SETTLEMENT-PREAUTHS",
            &state.preauthorizations,
            PqPreauthorization::public_record,
        ),
    })
}

pub fn fee_policy_record(state: &State) -> Value {
    json!({
        "kind": "fee_policy",
        "fee_asset_id": state.config.fee_asset_id,
        "max_user_fee_bps": state.config.max_user_fee_bps,
        "target_rebate_bps": state.config.target_rebate_bps,
        "liquidity_rebate_bps": state.config.liquidity_rebate_bps,
    })
}

pub fn slashing_policy_record(state: &State) -> Value {
    json!({
        "kind": "slashing_policy",
        "proof_failure_slash_bps": state.config.proof_failure_slash_bps,
        "atomicity_failure_slash_bps": state.config.atomicity_failure_slash_bps,
        "slashing_root": map_root("FLASH-SETTLEMENT-SLASHES", &state.slashes, SlashingEvent::public_record),
    })
}

pub fn capacity_policy_record(state: &State) -> Value {
    json!({
        "kind": "capacity_policy",
        "max_legs_per_slot": state.config.max_legs_per_slot,
        "max_legs_per_bundle": state.config.max_legs_per_bundle,
        "max_locks_per_bundle": state.config.max_locks_per_bundle,
    })
}

pub fn flash_runtime_dashboard_record(state: &State) -> Value {
    json!({
        "audit": flash_runtime_audit_record(state),
        "slot_status": slot_status_summary(state),
        "leg_status": leg_status_summary(state),
        "preauthorization_status": preauthorization_status_summary(state),
        "liquidity_lock_status": liquidity_lock_status_summary(state),
        "bundle_status": bundle_status_summary(state),
        "receipt_status": receipt_status_summary(state),
        "slash_kind": slash_kind_summary(state),
        "latency_policy": latency_policy_record(state),
        "privacy_policy": privacy_policy_record(state),
        "pq_policy": pq_policy_record(state),
        "fee_policy": fee_policy_record(state),
        "slashing_policy": slashing_policy_record(state),
        "capacity_policy": capacity_policy_record(state),
    })
}
