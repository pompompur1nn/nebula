use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialVaultProofRouterRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_VAULT_PROOF_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-vault-proof-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_VAULT_PROOF_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-vault-proof-router-v1";
pub const VAULT_SCHEME: &str = "pq-confidential-defi-vault-root-v1";
pub const PROOF_ROUTE_SCHEME: &str = "sealed-confidential-vault-proof-route-root-v1";
pub const PQ_PROOF_SCHEME: &str = "pq-vault-proof-authorization-root-v1";
pub const PROVER_RESERVATION_SCHEME: &str = "low-fee-vault-proof-prover-reservation-root-v1";
pub const BATCH_SCHEME: &str = "recursive-confidential-vault-proof-batch-root-v1";
pub const RECEIPT_SCHEME: &str = "confidential-vault-proof-settlement-receipt-root-v1";
pub const REBATE_SCHEME: &str = "confidential-vault-proof-low-fee-rebate-root-v1";
pub const PRIVACY_SCHEME: &str = "confidential-vault-proof-privacy-accounting-root-v1";
pub const SLASHING_SCHEME: &str = "confidential-vault-proof-router-slashing-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_032_000;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 11;
pub const DEFAULT_MAX_PROVER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_SLASHING_BPS: u64 = 2_500;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VAULTS: usize = 1_048_576;
pub const MAX_ROUTES: usize = 4_194_304;
pub const MAX_PROOFS: usize = 4_194_304;
pub const MAX_RESERVATIONS: usize = 2_097_152;
pub const MAX_BATCHES: usize = 1_048_576;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_PRIVACY_RECORDS: usize = 2_097_152;
pub const MAX_SLASHES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    Lending,
    StableSwap,
    PerpetualMargin,
    Options,
    SyntheticAsset,
    TokenBasket,
    Treasury,
    Insurance,
    LiquidStaking,
    CrossContract,
}

impl VaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lending => "lending",
            Self::StableSwap => "stable_swap",
            Self::PerpetualMargin => "perpetual_margin",
            Self::Options => "options",
            Self::SyntheticAsset => "synthetic_asset",
            Self::TokenBasket => "token_basket",
            Self::Treasury => "treasury",
            Self::Insurance => "insurance",
            Self::LiquidStaking => "liquid_staking",
            Self::CrossContract => "cross_contract",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    Solvency,
    Collateralization,
    PriceBound,
    WithdrawalEligibility,
    LiquidationSafety,
    YieldAccrual,
    TreasurySpend,
    TokenBasketComposition,
    CrossContractState,
    EmergencyExit,
}

impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Solvency => "solvency",
            Self::Collateralization => "collateralization",
            Self::PriceBound => "price_bound",
            Self::WithdrawalEligibility => "withdrawal_eligibility",
            Self::LiquidationSafety => "liquidation_safety",
            Self::YieldAccrual => "yield_accrual",
            Self::TreasurySpend => "treasury_spend",
            Self::TokenBasketComposition => "token_basket_composition",
            Self::CrossContractState => "cross_contract_state",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePriority {
    Normal,
    Fast,
    BatchCheap,
    Emergency,
    DeFiCritical,
}

impl RoutePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::BatchCheap => "batch_cheap",
            Self::Emergency => "emergency",
            Self::DeFiCritical => "defi_critical",
        }
    }

    pub fn latency_weight(self) -> u64 {
        match self {
            Self::Emergency => 5,
            Self::DeFiCritical => 4,
            Self::Fast => 3,
            Self::Normal => 2,
            Self::BatchCheap => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Active,
    Paused,
    Draining,
    Frozen,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
        }
    }

    pub fn accepts_routes(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Submitted,
    ProofAttached,
    Reserved,
    Batched,
    Settled,
    Expired,
    Slashed,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ProofAttached => "proof_attached",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::ProofAttached | Self::Reserved | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Attached,
    Accepted,
    Rejected,
    Expired,
    Slashed,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
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
pub enum BatchStatus {
    Open,
    Proving,
    Published,
    Settled,
    Expired,
    Slashed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Published => "published",
            Self::Settled => "settled",
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
    Issued,
    Claimed,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidPqProof,
    InvalidVaultProof,
    StaleRoute,
    FeeGouging,
    PrivacySetUnderflow,
    DoubleSpendNullifier,
    BatchMismatch,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqProof => "invalid_pq_proof",
            Self::InvalidVaultProof => "invalid_vault_proof",
            Self::StaleRoute => "stale_route",
            Self::FeeGouging => "fee_gouging",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::BatchMismatch => "batch_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub route_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_prover_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_bps: u64,
    pub max_batch_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_prover_fee_bps: DEFAULT_MAX_PROVER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            slashing_bps: DEFAULT_SLASHING_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "route_ttl_blocks": self.route_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_prover_fee_bps": self.max_prover_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "slashing_bps": self.slashing_bps,
            "max_batch_items": self.max_batch_items,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vaults_registered: u64,
    pub routes_submitted: u64,
    pub proofs_attached: u64,
    pub reservations_created: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub privacy_records: u64,
    pub slashes: u64,
    pub expired_routes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub vault_root: String,
    pub route_root: String,
    pub pq_proof_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_root": self.vault_root,
            "route_root": self.route_root,
            "pq_proof_root": self.pq_proof_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_root": self.privacy_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterVaultRequest {
    pub operator_id: String,
    pub vault_label: String,
    pub vault_kind: VaultKind,
    pub asset_commitment_root: String,
    pub policy_root: String,
    pub covenant_root: String,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_prover_fee_bps: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultRecord {
    pub vault_id: String,
    pub operator_id: String,
    pub vault_label: String,
    pub vault_kind: VaultKind,
    pub status: VaultStatus,
    pub asset_commitment_root: String,
    pub policy_root: String,
    pub covenant_root: String,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_prover_fee_bps: u64,
    pub metadata_root: String,
    pub registered_height: u64,
}

impl VaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "operator_id": self.operator_id,
            "vault_label": self.vault_label,
            "vault_kind": self.vault_kind.as_str(),
            "status": self.status.as_str(),
            "asset_commitment_root": self.asset_commitment_root,
            "policy_root": self.policy_root,
            "covenant_root": self.covenant_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_prover_fee_bps": self.max_prover_fee_bps,
            "metadata_root": self.metadata_root,
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitProofRouteRequest {
    pub vault_id: String,
    pub submitter_id: String,
    pub proof_kind: ProofKind,
    pub priority: RoutePriority,
    pub sealed_input_root: String,
    pub encrypted_witness_root: String,
    pub output_commitment_root: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofRouteRecord {
    pub route_id: String,
    pub vault_id: String,
    pub submitter_id: String,
    pub proof_kind: ProofKind,
    pub priority: RoutePriority,
    pub status: RouteStatus,
    pub sealed_input_root: String,
    pub encrypted_witness_root: String,
    pub output_commitment_root: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub metadata_root: String,
    pub submitted_height: u64,
    pub expires_at_height: u64,
}

impl ProofRouteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "vault_id": self.vault_id,
            "submitter_id": self.submitter_id,
            "proof_kind": self.proof_kind.as_str(),
            "priority": self.priority.as_str(),
            "status": self.status.as_str(),
            "sealed_input_root": self.sealed_input_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": root_from_strings("VAULT-PROOF-ROUTE-NULLIFIER", &[&self.nullifier]),
            "metadata_root": self.metadata_root,
            "submitted_height": self.submitted_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttachPqProofRequest {
    pub route_id: String,
    pub prover_id: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub proof_commitment_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub proof_fee_bps: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqVaultProofRecord {
    pub proof_id: String,
    pub route_id: String,
    pub prover_id: String,
    pub status: ProofStatus,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub proof_commitment_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub proof_fee_bps: u64,
    pub metadata_root: String,
    pub attached_height: u64,
    pub expires_at_height: u64,
}

impl PqVaultProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "route_id": self.route_id,
            "prover_id": self.prover_id,
            "status": self.status.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "proof_commitment_root": self.proof_commitment_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "proof_fee_bps": self.proof_fee_bps,
            "metadata_root": self.metadata_root,
            "attached_height": self.attached_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveProverRouteRequest {
    pub route_id: String,
    pub proof_id: String,
    pub prover_id: String,
    pub reserved_capacity_units: u64,
    pub max_latency_ms: u64,
    pub fee_quote_bps: u64,
    pub reservation_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProverRouteReservation {
    pub reservation_id: String,
    pub route_id: String,
    pub proof_id: String,
    pub prover_id: String,
    pub status: ReservationStatus,
    pub reserved_capacity_units: u64,
    pub max_latency_ms: u64,
    pub fee_quote_bps: u64,
    pub reservation_commitment_root: String,
    pub reserved_height: u64,
    pub expires_at_height: u64,
}

impl ProverRouteReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "route_id": self.route_id,
            "proof_id": self.proof_id,
            "prover_id": self.prover_id,
            "status": self.status.as_str(),
            "reserved_capacity_units": self.reserved_capacity_units,
            "max_latency_ms": self.max_latency_ms,
            "fee_quote_bps": self.fee_quote_bps,
            "reservation_commitment_root": self.reservation_commitment_root,
            "reserved_height": self.reserved_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildVaultProofBatchRequest {
    pub builder_id: String,
    pub route_ids: Vec<String>,
    pub proof_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub recursive_proof_root: String,
    pub aggregate_output_root: String,
    pub batch_privacy_set_size: u64,
    pub fee_asset_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultProofBatch {
    pub batch_id: String,
    pub builder_id: String,
    pub status: BatchStatus,
    pub route_ids: Vec<String>,
    pub proof_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub recursive_proof_root: String,
    pub aggregate_output_root: String,
    pub batch_root: String,
    pub batch_privacy_set_size: u64,
    pub fee_asset_id: String,
    pub built_height: u64,
    pub expires_at_height: u64,
}

impl VaultProofBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "builder_id": self.builder_id,
            "status": self.status.as_str(),
            "route_root": root_from_strings("VAULT-PROOF-BATCH-ROUTES", &self.route_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "proof_root": root_from_strings("VAULT-PROOF-BATCH-PROOFS", &self.proof_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "reservation_root": root_from_strings("VAULT-PROOF-BATCH-RESERVATIONS", &self.reservation_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "recursive_proof_root": self.recursive_proof_root,
            "aggregate_output_root": self.aggregate_output_root,
            "batch_root": self.batch_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "fee_asset_id": self.fee_asset_id,
            "built_height": self.built_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishVaultProofReceiptRequest {
    pub batch_id: String,
    pub publisher_id: String,
    pub settlement_root: String,
    pub fee_paid: u64,
    pub rebate_pool: u64,
    pub finality_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultProofReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub publisher_id: String,
    pub status: ReceiptStatus,
    pub settlement_root: String,
    pub fee_paid: u64,
    pub rebate_pool: u64,
    pub published_height: u64,
    pub finality_height: u64,
}

impl VaultProofReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "publisher_id": self.publisher_id,
            "status": self.status.as_str(),
            "settlement_root": self.settlement_root,
            "fee_paid": self.fee_paid,
            "rebate_pool": self.rebate_pool,
            "published_height": self.published_height,
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueRebateRequest {
    pub receipt_id: String,
    pub route_id: String,
    pub beneficiary_id: String,
    pub amount: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub route_id: String,
    pub beneficiary_id: String,
    pub status: RebateStatus,
    pub amount: u64,
    pub reason: String,
    pub issued_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "route_id": self.route_id,
            "beneficiary_id": self.beneficiary_id,
            "status": self.status.as_str(),
            "amount": self.amount,
            "reason": self.reason,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountPrivacySetRequest {
    pub route_id: String,
    pub proof_id: String,
    pub privacy_epoch: u64,
    pub observed_set_size: u64,
    pub anonymity_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyAccountingRecord {
    pub privacy_id: String,
    pub route_id: String,
    pub proof_id: String,
    pub privacy_epoch: u64,
    pub observed_set_size: u64,
    pub anonymity_root: String,
    pub accounted_height: u64,
}

impl PrivacyAccountingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_id": self.privacy_id,
            "route_id": self.route_id,
            "proof_id": self.proof_id,
            "privacy_epoch": self.privacy_epoch,
            "observed_set_size": self.observed_set_size,
            "anonymity_root": self.anonymity_root,
            "accounted_height": self.accounted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashRequest {
    pub offender_id: String,
    pub route_id: Option<String>,
    pub proof_id: Option<String>,
    pub batch_id: Option<String>,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub stake_units: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub slash_id: String,
    pub offender_id: String,
    pub route_id: Option<String>,
    pub proof_id: Option<String>,
    pub batch_id: Option<String>,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub stake_units: u64,
    pub slashed_units: u64,
    pub slashed_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "offender_id": self.offender_id,
            "route_id": self.route_id,
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "stake_units": self.stake_units,
            "slashed_units": self.slashed_units,
            "slashed_height": self.slashed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub vaults: BTreeMap<String, VaultRecord>,
    pub routes: BTreeMap<String, ProofRouteRecord>,
    pub proofs: BTreeMap<String, PqVaultProofRecord>,
    pub reservations: BTreeMap<String, ProverRouteReservation>,
    pub batches: BTreeMap<String, VaultProofBatch>,
    pub receipts: BTreeMap<String, VaultProofReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_records: BTreeMap<String, PrivacyAccountingRecord>,
    pub slashes: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::with_config(Config::default())
    }
}

impl State {
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            routes: BTreeMap::new(),
            proofs: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_records: BTreeMap::new(),
            slashes: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let vault = state.register_vault(RegisterVaultRequest {
            operator_id: "devnet-vault-operator-0".to_string(),
            vault_label: "devnet-private-token-basket-vault".to_string(),
            vault_kind: VaultKind::TokenBasket,
            asset_commitment_root: deterministic_root(
                "asset-commitment",
                "devnet-token-basket",
                "0",
            ),
            policy_root: deterministic_root("policy", "devnet-token-basket", "0"),
            covenant_root: deterministic_root("covenant", "devnet-token-basket", "0"),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_prover_fee_bps: DEFAULT_MAX_PROVER_FEE_BPS,
            metadata: json!({"lane": "devnet", "purpose": "pq-confidential-vault-proof-routing"}),
        });
        if let Ok(vault) = vault {
            let route = state.submit_proof_route(SubmitProofRouteRequest {
                vault_id: vault.vault_id.clone(),
                submitter_id: "devnet-vault-user-0".to_string(),
                proof_kind: ProofKind::Collateralization,
                priority: RoutePriority::Fast,
                sealed_input_root: deterministic_root("sealed-input", &vault.vault_id, "0"),
                encrypted_witness_root: deterministic_root(
                    "encrypted-witness",
                    &vault.vault_id,
                    "0",
                ),
                output_commitment_root: deterministic_root("output", &vault.vault_id, "0"),
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                nullifier: deterministic_root("nullifier", &vault.vault_id, "0"),
                metadata: json!({"devnet": true}),
            });
            if let Ok(route) = route {
                let proof = state.attach_pq_proof(AttachPqProofRequest {
                    route_id: route.route_id.clone(),
                    prover_id: "devnet-pq-prover-0".to_string(),
                    pq_public_key_root: deterministic_root("pq-key", &route.route_id, "0"),
                    pq_signature_root: deterministic_root("pq-signature", &route.route_id, "0"),
                    proof_commitment_root: deterministic_root("proof", &route.route_id, "0"),
                    transcript_root: deterministic_root("transcript", &route.route_id, "0"),
                    security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                    proof_fee_bps: DEFAULT_MAX_PROVER_FEE_BPS,
                    metadata: json!({"proof_system": "recursive-stark-pq-wrapper"}),
                });
                if let Ok(proof) = proof {
                    let reservation = state.reserve_prover_route(ReserveProverRouteRequest {
                        route_id: route.route_id.clone(),
                        proof_id: proof.proof_id.clone(),
                        prover_id: proof.prover_id.clone(),
                        reserved_capacity_units: 1,
                        max_latency_ms: 450,
                        fee_quote_bps: DEFAULT_MAX_PROVER_FEE_BPS,
                        reservation_commitment_root: deterministic_root(
                            "reservation",
                            &route.route_id,
                            "0",
                        ),
                    });
                    if let Ok(reservation) = reservation {
                        let batch = state.build_vault_proof_batch(BuildVaultProofBatchRequest {
                            builder_id: "devnet-proof-router-0".to_string(),
                            route_ids: vec![route.route_id.clone()],
                            proof_ids: vec![proof.proof_id.clone()],
                            reservation_ids: vec![reservation.reservation_id.clone()],
                            recursive_proof_root: deterministic_root(
                                "recursive-proof",
                                &route.route_id,
                                "0",
                            ),
                            aggregate_output_root: deterministic_root(
                                "aggregate-output",
                                &route.route_id,
                                "0",
                            ),
                            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                        });
                        if let Ok(batch) = batch {
                            let receipt = state.publish_vault_proof_receipt(
                                PublishVaultProofReceiptRequest {
                                    batch_id: batch.batch_id.clone(),
                                    publisher_id: "devnet-proof-router-0".to_string(),
                                    settlement_root: deterministic_root(
                                        "settlement",
                                        &batch.batch_id,
                                        "0",
                                    ),
                                    fee_paid: 8,
                                    rebate_pool: 3,
                                    finality_height: state.height + DEFAULT_RECEIPT_FINALITY_BLOCKS,
                                },
                            );
                            if let Ok(receipt) = receipt {
                                let _ = state.issue_rebate(IssueRebateRequest {
                                    receipt_id: receipt.receipt_id,
                                    route_id: route.route_id.clone(),
                                    beneficiary_id: route.submitter_id.clone(),
                                    amount: 3,
                                    reason: "devnet-low-fee-proof-routing".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        state
    }

    pub fn register_vault(&mut self, request: RegisterVaultRequest) -> Result<VaultRecord> {
        if self.vaults.len() >= MAX_VAULTS {
            return Err("vault capacity reached".to_string());
        }
        if request.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("vault pq security below minimum".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("vault user fee exceeds runtime maximum".to_string());
        }
        if request.max_prover_fee_bps > self.config.max_prover_fee_bps {
            return Err("vault prover fee exceeds runtime maximum".to_string());
        }
        let sequence = self.counters.vaults_registered + 1;
        let metadata_root = root_from_record("VAULT-METADATA", &request.metadata);
        let vault_id = vault_id(sequence, &request, &metadata_root);
        let record = VaultRecord {
            vault_id: vault_id.clone(),
            operator_id: request.operator_id,
            vault_label: request.vault_label,
            vault_kind: request.vault_kind,
            status: VaultStatus::Active,
            asset_commitment_root: request.asset_commitment_root,
            policy_root: request.policy_root,
            covenant_root: request.covenant_root,
            min_pq_security_bits: request.min_pq_security_bits,
            max_user_fee_bps: request.max_user_fee_bps,
            max_prover_fee_bps: request.max_prover_fee_bps,
            metadata_root,
            registered_height: self.height,
        };
        self.vaults.insert(vault_id, record.clone());
        self.counters.vaults_registered = sequence;
        Ok(record)
    }

    pub fn submit_proof_route(
        &mut self,
        request: SubmitProofRouteRequest,
    ) -> Result<ProofRouteRecord> {
        if self.routes.len() >= MAX_ROUTES {
            return Err("route capacity reached".to_string());
        }
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        if !vault.status.accepts_routes() {
            return Err("vault does not accept proof routes".to_string());
        }
        if request.max_user_fee_bps > vault.max_user_fee_bps {
            return Err("route fee exceeds vault maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below runtime minimum".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("route nullifier already consumed".to_string());
        }
        let sequence = self.counters.routes_submitted + 1;
        let metadata_root = root_from_record("VAULT-PROOF-ROUTE-METADATA", &request.metadata);
        let route_id = proof_route_id(sequence, &request, &metadata_root);
        self.consumed_nullifiers.insert(request.nullifier.clone());
        let record = ProofRouteRecord {
            route_id: route_id.clone(),
            vault_id: request.vault_id,
            submitter_id: request.submitter_id,
            proof_kind: request.proof_kind,
            priority: request.priority,
            status: RouteStatus::Submitted,
            sealed_input_root: request.sealed_input_root,
            encrypted_witness_root: request.encrypted_witness_root,
            output_commitment_root: request.output_commitment_root,
            fee_asset_id: request.fee_asset_id,
            max_user_fee_bps: request.max_user_fee_bps,
            privacy_set_size: request.privacy_set_size,
            nullifier: request.nullifier,
            metadata_root,
            submitted_height: self.height,
            expires_at_height: self.height + self.config.route_ttl_blocks,
        };
        self.routes.insert(route_id, record.clone());
        self.counters.routes_submitted = sequence;
        Ok(record)
    }

    pub fn attach_pq_proof(&mut self, request: AttachPqProofRequest) -> Result<PqVaultProofRecord> {
        if self.proofs.len() >= MAX_PROOFS {
            return Err("proof capacity reached".to_string());
        }
        let route = self
            .routes
            .get_mut(&request.route_id)
            .ok_or_else(|| "unknown route".to_string())?;
        if !route.status.live() {
            return Err("route is not live".to_string());
        }
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("pq proof below security minimum".to_string());
        }
        if request.proof_fee_bps > self.config.max_prover_fee_bps {
            return Err("proof fee exceeds runtime maximum".to_string());
        }
        let sequence = self.counters.proofs_attached + 1;
        let metadata_root = root_from_record("VAULT-PQ-PROOF-METADATA", &request.metadata);
        let proof_id = pq_vault_proof_id(sequence, &request, &metadata_root);
        let record = PqVaultProofRecord {
            proof_id: proof_id.clone(),
            route_id: request.route_id,
            prover_id: request.prover_id,
            status: ProofStatus::Attached,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            proof_commitment_root: request.proof_commitment_root,
            transcript_root: request.transcript_root,
            security_bits: request.security_bits,
            proof_fee_bps: request.proof_fee_bps,
            metadata_root,
            attached_height: self.height,
            expires_at_height: self.height + self.config.proof_ttl_blocks,
        };
        route.status = RouteStatus::ProofAttached;
        self.proofs.insert(proof_id, record.clone());
        self.counters.proofs_attached = sequence;
        Ok(record)
    }

    pub fn reserve_prover_route(
        &mut self,
        request: ReserveProverRouteRequest,
    ) -> Result<ProverRouteReservation> {
        if self.reservations.len() >= MAX_RESERVATIONS {
            return Err("reservation capacity reached".to_string());
        }
        let route = self
            .routes
            .get_mut(&request.route_id)
            .ok_or_else(|| "unknown route".to_string())?;
        let proof = self
            .proofs
            .get(&request.proof_id)
            .ok_or_else(|| "unknown proof".to_string())?;
        if proof.route_id != route.route_id {
            return Err("proof route mismatch".to_string());
        }
        if proof.prover_id != request.prover_id {
            return Err("proof prover mismatch".to_string());
        }
        if request.fee_quote_bps > self.config.max_prover_fee_bps {
            return Err("reservation fee quote exceeds runtime maximum".to_string());
        }
        let sequence = self.counters.reservations_created + 1;
        let reservation_id = prover_route_reservation_id(sequence, &request);
        let record = ProverRouteReservation {
            reservation_id: reservation_id.clone(),
            route_id: request.route_id,
            proof_id: request.proof_id,
            prover_id: request.prover_id,
            status: ReservationStatus::Reserved,
            reserved_capacity_units: request.reserved_capacity_units,
            max_latency_ms: request.max_latency_ms,
            fee_quote_bps: request.fee_quote_bps,
            reservation_commitment_root: request.reservation_commitment_root,
            reserved_height: self.height,
            expires_at_height: self.height + self.config.reservation_ttl_blocks,
        };
        route.status = RouteStatus::Reserved;
        self.reservations.insert(reservation_id, record.clone());
        self.counters.reservations_created = sequence;
        Ok(record)
    }

    pub fn build_vault_proof_batch(
        &mut self,
        request: BuildVaultProofBatchRequest,
    ) -> Result<VaultProofBatch> {
        if self.batches.len() >= MAX_BATCHES {
            return Err("batch capacity reached".to_string());
        }
        if request.route_ids.is_empty() {
            return Err("batch must include at least one route".to_string());
        }
        if request.route_ids.len() > self.config.max_batch_items {
            return Err("batch item limit exceeded".to_string());
        }
        if request.batch_privacy_set_size < self.config.batch_privacy_set_size {
            return Err("batch privacy set below target".to_string());
        }
        for route_id in &request.route_ids {
            let route = self
                .routes
                .get(route_id)
                .ok_or_else(|| format!("unknown route {route_id}"))?;
            if !route.status.live() {
                return Err(format!("route {route_id} is not batchable"));
            }
        }
        for proof_id in &request.proof_ids {
            let proof = self
                .proofs
                .get(proof_id)
                .ok_or_else(|| format!("unknown proof {proof_id}"))?;
            if proof.status == ProofStatus::Rejected || proof.status == ProofStatus::Slashed {
                return Err(format!("proof {proof_id} is not batchable"));
            }
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .reservations
                .get(reservation_id)
                .ok_or_else(|| format!("unknown reservation {reservation_id}"))?;
            if reservation.status != ReservationStatus::Reserved {
                return Err(format!("reservation {reservation_id} is not usable"));
            }
        }
        let sequence = self.counters.batches_built + 1;
        let batch_root = vault_proof_batch_root(
            &request.route_ids,
            &request.proof_ids,
            &request.reservation_ids,
            &request.recursive_proof_root,
            &request.aggregate_output_root,
        );
        let batch_id = vault_proof_batch_id(sequence, &request.builder_id, &batch_root);
        for route_id in &request.route_ids {
            if let Some(route) = self.routes.get_mut(route_id) {
                route.status = RouteStatus::Batched;
            }
        }
        for proof_id in &request.proof_ids {
            if let Some(proof) = self.proofs.get_mut(proof_id) {
                proof.status = ProofStatus::Accepted;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let record = VaultProofBatch {
            batch_id: batch_id.clone(),
            builder_id: request.builder_id,
            status: BatchStatus::Proving,
            route_ids: request.route_ids,
            proof_ids: request.proof_ids,
            reservation_ids: request.reservation_ids,
            recursive_proof_root: request.recursive_proof_root,
            aggregate_output_root: request.aggregate_output_root,
            batch_root,
            batch_privacy_set_size: request.batch_privacy_set_size,
            fee_asset_id: request.fee_asset_id,
            built_height: self.height,
            expires_at_height: self.height + self.config.batch_ttl_blocks,
        };
        self.batches.insert(batch_id, record.clone());
        self.counters.batches_built = sequence;
        Ok(record)
    }

    pub fn publish_vault_proof_receipt(
        &mut self,
        request: PublishVaultProofReceiptRequest,
    ) -> Result<VaultProofReceipt> {
        if self.receipts.len() >= MAX_RECEIPTS {
            return Err("receipt capacity reached".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        if batch.status == BatchStatus::Slashed || batch.status == BatchStatus::Expired {
            return Err("batch is not receiptable".to_string());
        }
        let sequence = self.counters.receipts_published + 1;
        let receipt_id = vault_proof_receipt_id(sequence, &request);
        let receipt = VaultProofReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            publisher_id: request.publisher_id,
            status: ReceiptStatus::Published,
            settlement_root: request.settlement_root,
            fee_paid: request.fee_paid,
            rebate_pool: request.rebate_pool,
            published_height: self.height,
            finality_height: request.finality_height,
        };
        batch.status = BatchStatus::Published;
        for route_id in &batch.route_ids {
            if let Some(route) = self.routes.get_mut(route_id) {
                route.status = RouteStatus::Settled;
            }
        }
        self.receipts.insert(receipt_id, receipt.clone());
        self.counters.receipts_published = sequence;
        Ok(receipt)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        if self.rebates.len() >= MAX_REBATES {
            return Err("rebate capacity reached".to_string());
        }
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("unknown receipt".to_string());
        }
        if !self.routes.contains_key(&request.route_id) {
            return Err("unknown route".to_string());
        }
        let sequence = self.counters.rebates_issued + 1;
        let rebate_id = fee_rebate_id(sequence, &request);
        let record = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id,
            route_id: request.route_id,
            beneficiary_id: request.beneficiary_id,
            status: RebateStatus::Issued,
            amount: request.amount,
            reason: request.reason,
            issued_height: self.height,
        };
        self.rebates.insert(rebate_id, record.clone());
        self.counters.rebates_issued = sequence;
        Ok(record)
    }

    pub fn account_privacy_set(
        &mut self,
        request: AccountPrivacySetRequest,
    ) -> Result<PrivacyAccountingRecord> {
        if self.privacy_records.len() >= MAX_PRIVACY_RECORDS {
            return Err("privacy accounting capacity reached".to_string());
        }
        if request.observed_set_size < self.config.min_privacy_set_size {
            return Err("observed privacy set below runtime minimum".to_string());
        }
        if !self.routes.contains_key(&request.route_id) {
            return Err("unknown route".to_string());
        }
        if !self.proofs.contains_key(&request.proof_id) {
            return Err("unknown proof".to_string());
        }
        let sequence = self.counters.privacy_records + 1;
        let privacy_id = privacy_accounting_id(sequence, &request);
        let record = PrivacyAccountingRecord {
            privacy_id: privacy_id.clone(),
            route_id: request.route_id,
            proof_id: request.proof_id,
            privacy_epoch: request.privacy_epoch,
            observed_set_size: request.observed_set_size,
            anonymity_root: request.anonymity_root,
            accounted_height: self.height,
        };
        self.privacy_records.insert(privacy_id, record.clone());
        self.counters.privacy_records = sequence;
        Ok(record)
    }

    pub fn slash(&mut self, request: SlashRequest) -> Result<SlashingEvidence> {
        if self.slashes.len() >= MAX_SLASHES {
            return Err("slashing capacity reached".to_string());
        }
        let sequence = self.counters.slashes + 1;
        let slash_id = slashing_evidence_id(sequence, &request);
        let slashed_units = mul_bps(request.stake_units, self.config.slashing_bps);
        if let Some(route_id) = &request.route_id {
            if let Some(route) = self.routes.get_mut(route_id) {
                route.status = RouteStatus::Slashed;
            }
        }
        if let Some(proof_id) = &request.proof_id {
            if let Some(proof) = self.proofs.get_mut(proof_id) {
                proof.status = ProofStatus::Slashed;
            }
        }
        if let Some(batch_id) = &request.batch_id {
            if let Some(batch) = self.batches.get_mut(batch_id) {
                batch.status = BatchStatus::Slashed;
            }
        }
        let record = SlashingEvidence {
            slash_id: slash_id.clone(),
            offender_id: request.offender_id,
            route_id: request.route_id,
            proof_id: request.proof_id,
            batch_id: request.batch_id,
            reason: request.reason,
            evidence_root: request.evidence_root,
            stake_units: request.stake_units,
            slashed_units,
            slashed_height: self.height,
        };
        self.slashes.insert(slash_id, record.clone());
        self.counters.slashes = sequence;
        Ok(record)
    }

    pub fn expire_stale(&mut self, height: u64) {
        self.height = self.height.max(height);
        for route in self.routes.values_mut() {
            if route.status.live() && route.expires_at_height <= self.height {
                route.status = RouteStatus::Expired;
                self.counters.expired_routes += 1;
            }
        }
        for proof in self.proofs.values_mut() {
            if proof.status == ProofStatus::Attached && proof.expires_at_height <= self.height {
                proof.status = ProofStatus::Expired;
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status == ReservationStatus::Reserved
                && reservation.expires_at_height <= self.height
            {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for batch in self.batches.values_mut() {
            if matches!(batch.status, BatchStatus::Open | BatchStatus::Proving)
                && batch.expires_at_height <= self.height
            {
                batch.status = BatchStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            vault_root: map_root("VAULT-ROOT", &self.vaults),
            route_root: map_root("VAULT-PROOF-ROUTE-ROOT", &self.routes),
            pq_proof_root: map_root("VAULT-PQ-PROOF-ROOT", &self.proofs),
            reservation_root: map_root("VAULT-PROVER-RESERVATION-ROOT", &self.reservations),
            batch_root: map_root("VAULT-PROOF-BATCH-ROOT", &self.batches),
            receipt_root: map_root("VAULT-PROOF-RECEIPT-ROOT", &self.receipts),
            rebate_root: map_root("VAULT-PROOF-REBATE-ROOT", &self.rebates),
            privacy_root: map_root("VAULT-PROOF-PRIVACY-ROOT", &self.privacy_records),
            slashing_root: map_root("VAULT-PROOF-SLASHING-ROOT", &self.slashes),
            nullifier_root: set_root("VAULT-PROOF-NULLIFIER-ROOT", &self.consumed_nullifiers),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "config": self.config.public_record(),
            "height": self.height,
            "counters": self.counters,
            "roots": roots.public_record(),
            "live_route_count": self.routes.values().filter(|route| route.status.live()).count(),
            "open_batch_count": self.batches.values().filter(|batch| matches!(batch.status, BatchStatus::Open | BatchStatus::Proving)).count(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_confidential_vault_proof_router_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_confidential_vault_proof_router_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn vault_id(sequence: u64, request: &RegisterVaultRequest, metadata_root: &str) -> String {
    root_from_strings(
        "VAULT-ID",
        &[
            &sequence.to_string(),
            &request.operator_id,
            &request.vault_label,
            request.vault_kind.as_str(),
            &request.asset_commitment_root,
            &request.policy_root,
            &request.covenant_root,
            metadata_root,
        ],
    )
}

pub fn proof_route_id(
    sequence: u64,
    request: &SubmitProofRouteRequest,
    metadata_root: &str,
) -> String {
    root_from_strings(
        "VAULT-PROOF-ROUTE-ID",
        &[
            &sequence.to_string(),
            &request.vault_id,
            &request.submitter_id,
            request.proof_kind.as_str(),
            request.priority.as_str(),
            &request.sealed_input_root,
            &request.encrypted_witness_root,
            &request.output_commitment_root,
            &request.nullifier,
            metadata_root,
        ],
    )
}

pub fn pq_vault_proof_id(
    sequence: u64,
    request: &AttachPqProofRequest,
    metadata_root: &str,
) -> String {
    root_from_strings(
        "VAULT-PQ-PROOF-ID",
        &[
            &sequence.to_string(),
            &request.route_id,
            &request.prover_id,
            &request.pq_public_key_root,
            &request.pq_signature_root,
            &request.proof_commitment_root,
            &request.transcript_root,
            &request.security_bits.to_string(),
            metadata_root,
        ],
    )
}

pub fn prover_route_reservation_id(sequence: u64, request: &ReserveProverRouteRequest) -> String {
    root_from_strings(
        "VAULT-PROVER-ROUTE-RESERVATION-ID",
        &[
            &sequence.to_string(),
            &request.route_id,
            &request.proof_id,
            &request.prover_id,
            &request.reserved_capacity_units.to_string(),
            &request.max_latency_ms.to_string(),
            &request.fee_quote_bps.to_string(),
            &request.reservation_commitment_root,
        ],
    )
}

pub fn vault_proof_batch_id(sequence: u64, builder_id: &str, batch_root: &str) -> String {
    root_from_strings(
        "VAULT-PROOF-BATCH-ID",
        &[&sequence.to_string(), builder_id, batch_root],
    )
}

pub fn vault_proof_receipt_id(sequence: u64, request: &PublishVaultProofReceiptRequest) -> String {
    root_from_strings(
        "VAULT-PROOF-RECEIPT-ID",
        &[
            &sequence.to_string(),
            &request.batch_id,
            &request.publisher_id,
            &request.settlement_root,
            &request.fee_paid.to_string(),
            &request.rebate_pool.to_string(),
            &request.finality_height.to_string(),
        ],
    )
}

pub fn fee_rebate_id(sequence: u64, request: &IssueRebateRequest) -> String {
    root_from_strings(
        "VAULT-PROOF-FEE-REBATE-ID",
        &[
            &sequence.to_string(),
            &request.receipt_id,
            &request.route_id,
            &request.beneficiary_id,
            &request.amount.to_string(),
            &request.reason,
        ],
    )
}

pub fn privacy_accounting_id(sequence: u64, request: &AccountPrivacySetRequest) -> String {
    root_from_strings(
        "VAULT-PROOF-PRIVACY-ACCOUNTING-ID",
        &[
            &sequence.to_string(),
            &request.route_id,
            &request.proof_id,
            &request.privacy_epoch.to_string(),
            &request.observed_set_size.to_string(),
            &request.anonymity_root,
        ],
    )
}

pub fn slashing_evidence_id(sequence: u64, request: &SlashRequest) -> String {
    root_from_strings(
        "VAULT-PROOF-SLASHING-ID",
        &[
            &sequence.to_string(),
            &request.offender_id,
            request.route_id.as_deref().unwrap_or(""),
            request.proof_id.as_deref().unwrap_or(""),
            request.batch_id.as_deref().unwrap_or(""),
            request.reason.as_str(),
            &request.evidence_root,
            &request.stake_units.to_string(),
        ],
    )
}

pub fn vault_proof_batch_root(
    route_ids: &[String],
    proof_ids: &[String],
    reservation_ids: &[String],
    recursive_proof_root: &str,
    aggregate_output_root: &str,
) -> String {
    let route_refs = route_ids.iter().map(String::as_str).collect::<Vec<_>>();
    let proof_refs = proof_ids.iter().map(String::as_str).collect::<Vec<_>>();
    let reservation_refs = reservation_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    root_from_strings(
        "VAULT-PROOF-BATCH-ROOT",
        &[
            &root_from_strings("VAULT-PROOF-BATCH-ROUTES", &route_refs),
            &root_from_strings("VAULT-PROOF-BATCH-PROOFS", &proof_refs),
            &root_from_strings("VAULT-PROOF-BATCH-RESERVATIONS", &reservation_refs),
            recursive_proof_root,
            aggregate_output_root,
        ],
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: &str) -> String {
    root_from_strings("VAULT-PROOF-DETERMINISTIC-ROOT", &[label, subject, nonce])
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-VAULT-PROOF-ROUTER-RUNTIME-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn root_from_strings(domain: &str, values: &[&str]) -> String {
    let parts = values
        .iter()
        .map(|value| HashPart::Str(value))
        .collect::<Vec<_>>();
    domain_hash(domain, &parts, 32)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

pub fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps).saturating_add(MAX_BPS - 1) / MAX_BPS
}
