use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Runtime = State;
pub type PrivateL2LowFeeIntentNettingClearingRuntimeResult<T> = Result<T, String>;

pub const PROTOCOL_VERSION: &str = "nebula-private-l2-low-fee-intent-netting-clearing-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_INTENT_SCHEME: &str = "ml-kem-1024+xwing-sealed-private-intent-v1";
pub const PQ_AUTH_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256s-runtime-auth-v1";
pub const CLEARING_PROOF_SCHEME: &str = "zk-netting-clearing-proof-pq-v1";
pub const NETTING_PROOF_SCHEME: &str = "zk-private-balance-netting-proof-v1";
pub const SPONSOR_VOUCHER_SCHEME: &str = "low-fee-private-sponsor-voucher-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "zk-private-clearing-settlement-receipt-v1";
pub const DEVNET_HEIGHT: u64 = 512_880;
pub const DEVNET_EPOCH: u64 = 712;
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_REBATE_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_INTENTS_PER_BATCH: usize = 2_048;
pub const DEFAULT_MAX_SOLVERS_PER_BATCH: usize = 128;
pub const DEFAULT_MAX_SPONSOR_RESERVATIONS: usize = 4_096;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_NULLIFIER_FENCE_SIZE: u64 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 42;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 24;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 16;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 250_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    SwapExactIn,
    SwapExactOut,
    LimitSwap,
    DarkpoolCross,
    LendingBorrow,
    LendingRepay,
    VaultDeposit,
    VaultWithdraw,
    PerpOpen,
    PerpClose,
    BridgeExit,
    StableSwap,
    LiquidityProvision,
    CrossMarginRebalance,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::LimitSwap => "limit_swap",
            Self::DarkpoolCross => "darkpool_cross",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::BridgeExit => "bridge_exit",
            Self::StableSwap => "stable_swap",
            Self::LiquidityProvision => "liquidity_provision",
            Self::CrossMarginRebalance => "cross_margin_rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueKind {
    PrivateAmm,
    Darkpool,
    Rfq,
    LendingPool,
    Perps,
    Vault,
    Bridge,
    InternalNetting,
}

impl VenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::Darkpool => "darkpool",
            Self::Rfq => "rfq",
            Self::LendingPool => "lending_pool",
            Self::Perps => "perps",
            Self::Vault => "vault",
            Self::Bridge => "bridge",
            Self::InternalNetting => "internal_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Admitted,
    Reserved,
    Netted,
    Cleared,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Admitted => "admitted",
            Self::Reserved => "reserved",
            Self::Netted => "netted",
            Self::Cleared => "cleared",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Encrypted | Self::Admitted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Registered,
    Committed,
    Selected,
    Settled,
    Slashed,
    Suspended,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Committed => "committed",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Suspended => "suspended",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Registered | Self::Committed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Solving,
    Netted,
    Clearing,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Solving => "solving",
            Self::Netted => "netted",
            Self::Clearing => "clearing",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_receipt(self) -> bool {
        matches!(self, Self::SettlementReady | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub encrypted_intent_scheme: String,
    pub pq_auth_scheme: String,
    pub clearing_proof_scheme: String,
    pub netting_proof_scheme: String,
    pub sponsor_voucher_scheme: String,
    pub settlement_receipt_scheme: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub rebate_window_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_solvers_per_batch: usize,
    pub max_sponsor_reservations: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_nullifier_fence_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            encrypted_intent_scheme: ENCRYPTED_INTENT_SCHEME.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            clearing_proof_scheme: CLEARING_PROOF_SCHEME.to_string(),
            netting_proof_scheme: NETTING_PROOF_SCHEME.to_string(),
            sponsor_voucher_scheme: SPONSOR_VOUCHER_SCHEME.to_string(),
            settlement_receipt_scheme: SETTLEMENT_RECEIPT_SCHEME.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            rebate_window_blocks: DEFAULT_REBATE_WINDOW_BLOCKS,
            max_intents_per_batch: DEFAULT_MAX_INTENTS_PER_BATCH,
            max_solvers_per_batch: DEFAULT_MAX_SOLVERS_PER_BATCH,
            max_sponsor_reservations: DEFAULT_MAX_SPONSOR_RESERVATIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_nullifier_fence_size: DEFAULT_MIN_NULLIFIER_FENCE_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
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
            "encrypted_intent_scheme": self.encrypted_intent_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "clearing_proof_scheme": self.clearing_proof_scheme,
            "netting_proof_scheme": self.netting_proof_scheme,
            "sponsor_voucher_scheme": self.sponsor_voucher_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "rebate_window_blocks": self.rebate_window_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_solvers_per_batch": self.max_solvers_per_batch,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_nullifier_fence_size": self.min_nullifier_fence_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_sequence: u64,
    pub next_solver_sequence: u64,
    pub next_batch_sequence: u64,
    pub next_netting_sequence: u64,
    pub next_sponsor_sequence: u64,
    pub next_reservation_sequence: u64,
    pub next_receipt_sequence: u64,
    pub next_rebate_sequence: u64,
    pub encrypted_intents: u64,
    pub admitted_intents: u64,
    pub netted_intents: u64,
    pub cleared_intents: u64,
    pub settled_intents: u64,
    pub rejected_intents: u64,
    pub solver_commitments: u64,
    pub clearing_batches: u64,
    pub sponsor_vouchers: u64,
    pub active_reservations: u64,
    pub consumed_reservations: u64,
    pub settlement_receipts: u64,
    pub rebate_commitments: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_intent_sequence": self.next_intent_sequence,
            "next_solver_sequence": self.next_solver_sequence,
            "next_batch_sequence": self.next_batch_sequence,
            "next_netting_sequence": self.next_netting_sequence,
            "next_sponsor_sequence": self.next_sponsor_sequence,
            "next_reservation_sequence": self.next_reservation_sequence,
            "next_receipt_sequence": self.next_receipt_sequence,
            "next_rebate_sequence": self.next_rebate_sequence,
            "encrypted_intents": self.encrypted_intents,
            "admitted_intents": self.admitted_intents,
            "netted_intents": self.netted_intents,
            "cleared_intents": self.cleared_intents,
            "settled_intents": self.settled_intents,
            "rejected_intents": self.rejected_intents,
            "solver_commitments": self.solver_commitments,
            "clearing_batches": self.clearing_batches,
            "sponsor_vouchers": self.sponsor_vouchers,
            "active_reservations": self.active_reservations,
            "consumed_reservations": self.consumed_reservations,
            "settlement_receipts": self.settlement_receipts,
            "rebate_commitments": self.rebate_commitments,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub kind: IntentKind,
    pub venue: VenueKind,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub amount_bucket: u64,
    pub max_fee_micro_units: u64,
    pub max_slippage_bps: u64,
    pub privacy_set_id: String,
    pub nullifier_fence_id: String,
    pub encrypted_payload_root: String,
    pub route_hint_root: String,
    pub constraint_root: String,
    pub sponsor_hint_root: String,
    pub pq_ephemeral_key_root: String,
    pub status: IntentStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "kind": self.kind.as_str(),
            "venue": self.venue.as_str(),
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "amount_bucket": self.amount_bucket,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_slippage_bps": self.max_slippage_bps,
            "privacy_set_id": self.privacy_set_id,
            "nullifier_fence_id": self.nullifier_fence_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "route_hint_root": self.route_hint_root,
            "constraint_root": self.constraint_root,
            "sponsor_hint_root": self.sponsor_hint_root,
            "pq_ephemeral_key_root": self.pq_ephemeral_key_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ENCRYPTED-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub solver_id: String,
    pub batch_id: String,
    pub solver_commitment: String,
    pub route_commitment_root: String,
    pub inventory_root: String,
    pub solver_fee_bps: u64,
    pub expected_rebate_bps: u64,
    pub pq_attestation_root: String,
    pub status: SolverStatus,
    pub committed_at_height: u64,
}

impl SolverCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "batch_id": self.batch_id,
            "solver_commitment": self.solver_commitment,
            "route_commitment_root": self.route_commitment_root,
            "inventory_root": self.inventory_root,
            "solver_fee_bps": self.solver_fee_bps,
            "expected_rebate_bps": self.expected_rebate_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "status": self.status.as_str(),
            "committed_at_height": self.committed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingProof {
    pub proof_id: String,
    pub batch_id: String,
    pub intent_root: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub net_delta_root: String,
    pub conservation_root: String,
    pub privacy_set_root: String,
    pub nullifier_fence_root: String,
    pub proof_root: String,
    pub verifier_key_root: String,
    pub pq_transcript_root: String,
    pub fee_saved_micro_units: u64,
    pub proof_size_bytes: u64,
    pub generated_at_height: u64,
}

impl NettingProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "intent_root": self.intent_root,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "net_delta_root": self.net_delta_root,
            "conservation_root": self.conservation_root,
            "privacy_set_root": self.privacy_set_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "proof_root": self.proof_root,
            "verifier_key_root": self.verifier_key_root,
            "pq_transcript_root": self.pq_transcript_root,
            "fee_saved_micro_units": self.fee_saved_micro_units,
            "proof_size_bytes": self.proof_size_bytes,
            "generated_at_height": self.generated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub solver_id: String,
    pub intent_ids: Vec<String>,
    pub status: BatchStatus,
    pub encrypted_intent_root: String,
    pub solver_commitment_root: String,
    pub netting_proof_id: String,
    pub clearing_proof_root: String,
    pub settlement_call_root: String,
    pub fee_vector_root: String,
    pub rebate_root: String,
    pub sponsor_reservation_root: String,
    pub privacy_set_root: String,
    pub nullifier_fence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ClearingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "solver_id": self.solver_id,
            "intent_ids": self.intent_ids,
            "status": self.status.as_str(),
            "encrypted_intent_root": self.encrypted_intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "netting_proof_id": self.netting_proof_id,
            "clearing_proof_root": self.clearing_proof_root,
            "settlement_call_root": self.settlement_call_root,
            "fee_vector_root": self.fee_vector_root,
            "rebate_root": self.rebate_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "privacy_set_root": self.privacy_set_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorVoucher {
    pub voucher_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub total_budget_micro_units: u64,
    pub remaining_budget_micro_units: u64,
    pub max_fee_per_intent_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub eligible_kind_root: String,
    pub eligible_venue_root: String,
    pub rebate_bps: u64,
    pub status: SponsorStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "total_budget_micro_units": self.total_budget_micro_units,
            "remaining_budget_micro_units": self.remaining_budget_micro_units,
            "max_fee_per_intent_micro_units": self.max_fee_per_intent_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "eligible_kind_root": self.eligible_kind_root,
            "eligible_venue_root": self.eligible_venue_root,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub voucher_id: String,
    pub intent_id: String,
    pub batch_id: String,
    pub reserved_micro_units: u64,
    pub rebate_bps: u64,
    pub reservation_root: String,
    pub status: ReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "voucher_id": self.voucher_id,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "reserved_micro_units": self.reserved_micro_units,
            "rebate_bps": self.rebate_bps,
            "reservation_root": self.reservation_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateCommitment {
    pub rebate_id: String,
    pub reservation_id: String,
    pub intent_id: String,
    pub recipient_commitment: String,
    pub asset_id: String,
    pub rebate_micro_units: u64,
    pub fee_paid_micro_units: u64,
    pub low_fee_score: u64,
    pub proof_root: String,
    pub committed_at_height: u64,
}

impl RebateCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.reservation_id,
            "intent_id": self.intent_id,
            "recipient_commitment": self.recipient_commitment,
            "asset_id": self.asset_id,
            "rebate_micro_units": self.rebate_micro_units,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "low_fee_score": self.low_fee_score,
            "proof_root": self.proof_root,
            "committed_at_height": self.committed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySet {
    pub privacy_set_id: String,
    pub epoch: u64,
    pub asset_root: String,
    pub member_commitment_root: String,
    pub decoy_root: String,
    pub anonymity_size: u64,
    pub min_entropy_bits: u16,
    pub opened_at_height: u64,
}

impl PrivacySet {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_set_id": self.privacy_set_id,
            "epoch": self.epoch,
            "asset_root": self.asset_root,
            "member_commitment_root": self.member_commitment_root,
            "decoy_root": self.decoy_root,
            "anonymity_size": self.anonymity_size,
            "min_entropy_bits": self.min_entropy_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub epoch: u64,
    pub nullifier_root: String,
    pub spent_key_image_root: String,
    pub pending_key_image_root: String,
    pub fence_size: u64,
    pub expires_at_height: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "epoch": self.epoch,
            "nullifier_root": self.nullifier_root,
            "spent_key_image_root": self.spent_key_image_root,
            "pending_key_image_root": self.pending_key_image_root,
            "fence_size": self.fence_size,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub netting_proof_id: String,
    pub settlement_tx_root: String,
    pub settlement_state_root: String,
    pub output_note_root: String,
    pub consumed_nullifier_root: String,
    pub rebate_root: String,
    pub sponsor_debit_root: String,
    pub public_audit_root: String,
    pub status: ReceiptStatus,
    pub settled_at_height: u64,
    pub finalized_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "netting_proof_id": self.netting_proof_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_state_root": self.settlement_state_root,
            "output_note_root": self.output_note_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "rebate_root": self.rebate_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "public_audit_root": self.public_audit_root,
            "status": self.status.as_str(),
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneLiquidity {
    pub lane_id: String,
    pub venue: VenueKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub private_reserve_root: String,
    pub nettable_inventory_root: String,
    pub oracle_price_root: String,
    pub max_netting_amount_bucket: u64,
    pub fee_ceiling_bps: u64,
    pub solver_count: u64,
    pub privacy_set_id: String,
    pub opened_at_height: u64,
}

impl LaneLiquidity {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "venue": self.venue.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "private_reserve_root": self.private_reserve_root,
            "nettable_inventory_root": self.nettable_inventory_root,
            "oracle_price_root": self.oracle_price_root,
            "max_netting_amount_bucket": self.max_netting_amount_bucket,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "solver_count": self.solver_count,
            "privacy_set_id": self.privacy_set_id,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub intent_id: String,
    pub lane_id: String,
    pub base_fee_micro_units: u64,
    pub solver_fee_micro_units: u64,
    pub privacy_fee_micro_units: u64,
    pub sponsor_offset_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub fee_cap_micro_units: u64,
    pub rebate_bps: u64,
    pub quote_root: String,
    pub quoted_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "base_fee_micro_units": self.base_fee_micro_units,
            "solver_fee_micro_units": self.solver_fee_micro_units,
            "privacy_fee_micro_units": self.privacy_fee_micro_units,
            "sponsor_offset_micro_units": self.sponsor_offset_micro_units,
            "user_fee_micro_units": self.user_fee_micro_units,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "rebate_bps": self.rebate_bps,
            "quote_root": self.quote_root,
            "quoted_at_height": self.quoted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingCheckpoint {
    pub checkpoint_id: String,
    pub batch_id: String,
    pub receipt_id: String,
    pub root_before: String,
    pub root_after: String,
    pub public_record_root: String,
    pub state_root: String,
    pub data_availability_root: String,
    pub pq_signature_root: String,
    pub posted_at_height: u64,
}

impl ClearingCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "root_before": self.root_before,
            "root_after": self.root_after,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
            "data_availability_root": self.data_availability_root,
            "pq_signature_root": self.pq_signature_root,
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditWindow {
    pub audit_id: String,
    pub epoch: u64,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub fee_quote_root: String,
    pub lane_root: String,
    pub nullifier_fence_root: String,
    pub privacy_set_root: String,
    pub max_fee_bps_observed: u64,
    pub average_user_fee_micro_units: u64,
    pub total_fee_saved_micro_units: u64,
    pub opened_at_height: u64,
    pub closed_at_height: u64,
}

impl AuditWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "epoch": self.epoch,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "fee_quote_root": self.fee_quote_root,
            "lane_root": self.lane_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "privacy_set_root": self.privacy_set_root,
            "max_fee_bps_observed": self.max_fee_bps_observed,
            "average_user_fee_micro_units": self.average_user_fee_micro_units,
            "total_fee_saved_micro_units": self.total_fee_saved_micro_units,
            "opened_at_height": self.opened_at_height,
            "closed_at_height": self.closed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicy {
    pub policy_id: String,
    pub min_privacy_set_size: u64,
    pub min_nullifier_fence_size: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub pq_security_bits: u16,
    pub require_encrypted_payloads: bool,
    pub require_private_solver_commitments: bool,
    pub require_sponsor_reservation_before_settlement: bool,
    pub activated_at_height: u64,
}

impl RuntimePolicy {
    pub fn from_config(config: &Config, activated_at_height: u64) -> Self {
        let policy_record = json!({
            "min_privacy_set_size": config.min_privacy_set_size,
            "min_nullifier_fence_size": config.min_nullifier_fence_size,
            "max_user_fee_bps": config.max_user_fee_bps,
            "max_solver_fee_bps": config.max_solver_fee_bps,
            "min_rebate_bps": config.min_rebate_bps,
            "pq_security_bits": config.min_pq_security_bits,
        });
        Self {
            policy_id: payload_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:POLICY-ID",
                &policy_record,
            ),
            min_privacy_set_size: config.min_privacy_set_size,
            min_nullifier_fence_size: config.min_nullifier_fence_size,
            max_user_fee_bps: config.max_user_fee_bps,
            max_solver_fee_bps: config.max_solver_fee_bps,
            min_rebate_bps: config.min_rebate_bps,
            pq_security_bits: config.min_pq_security_bits,
            require_encrypted_payloads: true,
            require_private_solver_commitments: true,
            require_sponsor_reservation_before_settlement: true,
            activated_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_nullifier_fence_size": self.min_nullifier_fence_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "pq_security_bits": self.pq_security_bits,
            "require_encrypted_payloads": self.require_encrypted_payloads,
            "require_private_solver_commitments": self.require_private_solver_commitments,
            "require_sponsor_reservation_before_settlement": self.require_sponsor_reservation_before_settlement,
            "activated_at_height": self.activated_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub intent_root: String,
    pub solver_root: String,
    pub batch_root: String,
    pub netting_proof_root: String,
    pub sponsor_voucher_root: String,
    pub sponsor_reservation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_set_root: String,
    pub nullifier_fence_root: String,
    pub lane_liquidity_root: String,
    pub fee_quote_root: String,
    pub checkpoint_root: String,
    pub audit_window_root: String,
    pub policy_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_root": self.intent_root,
            "solver_root": self.solver_root,
            "batch_root": self.batch_root,
            "netting_proof_root": self.netting_proof_root,
            "sponsor_voucher_root": self.sponsor_voucher_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_set_root": self.privacy_set_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "lane_liquidity_root": self.lane_liquidity_root,
            "fee_quote_root": self.fee_quote_root,
            "checkpoint_root": self.checkpoint_root,
            "audit_window_root": self.audit_window_root,
            "policy_root": self.policy_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub current_epoch: u64,
    pub intents: BTreeMap<String, EncryptedIntent>,
    pub solvers: BTreeMap<String, SolverCommitment>,
    pub batches: BTreeMap<String, ClearingBatch>,
    pub netting_proofs: BTreeMap<String, NettingProof>,
    pub sponsor_vouchers: BTreeMap<String, SponsorVoucher>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebate_commitments: BTreeMap<String, RebateCommitment>,
    pub privacy_sets: BTreeMap<String, PrivacySet>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub lane_liquidity: BTreeMap<String, LaneLiquidity>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub clearing_checkpoints: BTreeMap<String, ClearingCheckpoint>,
    pub audit_windows: BTreeMap<String, AuditWindow>,
    pub runtime_policies: BTreeMap<String, RuntimePolicy>,
    pub spent_nullifiers: BTreeSet<String>,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            current_height: 0,
            current_epoch: 0,
            intents: BTreeMap::new(),
            solvers: BTreeMap::new(),
            batches: BTreeMap::new(),
            netting_proofs: BTreeMap::new(),
            sponsor_vouchers: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebate_commitments: BTreeMap::new(),
            privacy_sets: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            lane_liquidity: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            clearing_checkpoints: BTreeMap::new(),
            audit_windows: BTreeMap::new(),
            runtime_policies: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        let current_epoch = current_height / config.epoch_blocks.max(1);
        let mut state = Self {
            config,
            current_height,
            current_epoch,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default(), DEVNET_HEIGHT);
        state.current_epoch = DEVNET_EPOCH;

        let privacy_set_id = privacy_set_id(DEVNET_EPOCH, "wxmr-usdc-private-lane");
        let nullifier_fence_id = nullifier_fence_id(DEVNET_EPOCH, "wxmr-usdc-private-lane");
        let batch_id = clearing_batch_id(DEVNET_EPOCH, 1, "solver:devnet:mist");
        let solver_id = solver_id("solver:devnet:mist", 1);
        let voucher_id = sponsor_voucher_id("sponsor:devnet:fee-relief", DEVNET_EPOCH);
        let lane_id = lane_liquidity_id(
            VenueKind::PrivateAmm,
            "wxmr-devnet",
            "usdc-devnet",
            DEVNET_EPOCH,
        );

        let intent_a = devnet_intent(
            1,
            IntentKind::SwapExactIn,
            VenueKind::PrivateAmm,
            "wxmr-devnet",
            "usdc-devnet",
            &privacy_set_id,
            &nullifier_fence_id,
            DEVNET_HEIGHT,
        );
        let intent_b = devnet_intent(
            2,
            IntentKind::LendingRepay,
            VenueKind::LendingPool,
            "usdc-devnet",
            "wxmr-devnet",
            &privacy_set_id,
            &nullifier_fence_id,
            DEVNET_HEIGHT + 1,
        );
        let intent_c = devnet_intent(
            3,
            IntentKind::VaultDeposit,
            VenueKind::Vault,
            "wxmr-devnet",
            "pvault-wxmr",
            &privacy_set_id,
            &nullifier_fence_id,
            DEVNET_HEIGHT + 2,
        );

        state.insert_privacy_set(PrivacySet {
            privacy_set_id: privacy_set_id.clone(),
            epoch: DEVNET_EPOCH,
            asset_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-ASSETS",
                &[
                    json!("wxmr-devnet"),
                    json!("usdc-devnet"),
                    json!("pvault-wxmr"),
                ],
            ),
            member_commitment_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-MEMBERS",
                &[
                    json!("member:alpha"),
                    json!("member:bravo"),
                    json!("member:charlie"),
                ],
            ),
            decoy_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-DECOYS",
                &[json!("decoy:00"), json!("decoy:01"), json!("decoy:02")],
            ),
            anonymity_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_entropy_bits: 128,
            opened_at_height: DEVNET_HEIGHT - 18,
        });
        state.insert_nullifier_fence(NullifierFence {
            fence_id: nullifier_fence_id.clone(),
            epoch: DEVNET_EPOCH,
            nullifier_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-NULLIFIERS",
                &[json!("nf:devnet:alpha"), json!("nf:devnet:bravo")],
            ),
            spent_key_image_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-SPENT-KEY-IMAGES",
                &[json!("ki:spent:00")],
            ),
            pending_key_image_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-PENDING-KEY-IMAGES",
                &[json!("ki:pending:00"), json!("ki:pending:01")],
            ),
            fence_size: DEFAULT_MIN_NULLIFIER_FENCE_SIZE * 2,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_INTENT_TTL_BLOCKS,
        });
        state.insert_lane_liquidity(LaneLiquidity {
            lane_id: lane_id.clone(),
            venue: VenueKind::PrivateAmm,
            base_asset_id: "wxmr-devnet".to_string(),
            quote_asset_id: "usdc-devnet".to_string(),
            private_reserve_root: payload_root(
                "DEVNET-LANE-PRIVATE-RESERVE",
                &json!("reserve-root"),
            ),
            nettable_inventory_root: payload_root(
                "DEVNET-LANE-NETTABLE-INVENTORY",
                &json!("nettable-inventory-root"),
            ),
            oracle_price_root: payload_root(
                "DEVNET-LANE-ORACLE-PRICE",
                &json!({"wxmr_usdc": "158.42"}),
            ),
            max_netting_amount_bucket: 4_096,
            fee_ceiling_bps: 14,
            solver_count: 3,
            privacy_set_id: privacy_set_id.clone(),
            opened_at_height: DEVNET_HEIGHT - 20,
        });
        let policy = RuntimePolicy::from_config(&state.config, DEVNET_HEIGHT - 20);
        state.insert_runtime_policy(policy);

        state.insert_intent(intent_a.clone());
        state.insert_intent(intent_b.clone());
        state.insert_intent(intent_c.clone());
        for (sequence, intent_id) in [
            intent_a.intent_id.clone(),
            intent_b.intent_id.clone(),
            intent_c.intent_id.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            state.insert_fee_quote(FeeQuote {
                quote_id: fee_quote_id(&intent_id, &lane_id, sequence as u64 + 1),
                intent_id,
                lane_id: lane_id.clone(),
                base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
                solver_fee_micro_units: 48,
                privacy_fee_micro_units: 30,
                sponsor_offset_micro_units: 84,
                user_fee_micro_units: 36,
                fee_cap_micro_units: 180,
                rebate_bps: 7,
                quote_root: payload_root("DEVNET-FEE-QUOTE", &json!({"sequence": sequence + 1})),
                quoted_at_height: DEVNET_HEIGHT + 3,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_RESERVATION_TTL_BLOCKS,
            });
        }
        state.insert_solver(SolverCommitment {
            solver_id: solver_id.clone(),
            batch_id: batch_id.clone(),
            solver_commitment: payload_root("DEVNET-SOLVER-COMMITMENT", &json!("mist-route")),
            route_commitment_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-ROUTES",
                &[
                    json!("amm:wxmr-usdc"),
                    json!("lending:repay"),
                    json!("vault:deposit"),
                ],
            ),
            inventory_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-INVENTORY",
                &[
                    json!({"asset": "wxmr-devnet", "bucket": 80}),
                    json!({"asset": "usdc-devnet", "bucket": 112}),
                ],
            ),
            solver_fee_bps: 9,
            expected_rebate_bps: 7,
            pq_attestation_root: payload_root(
                "DEVNET-PQ-SOLVER-ATTESTATION",
                &json!("ml-dsa-attested"),
            ),
            status: SolverStatus::Selected,
            committed_at_height: DEVNET_HEIGHT + 3,
        });

        state.insert_sponsor_voucher(SponsorVoucher {
            voucher_id: voucher_id.clone(),
            sponsor_commitment: "sponsor:commitment:devnet:fee-relief".to_string(),
            asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            total_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            remaining_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS - 720,
            max_fee_per_intent_micro_units: 500,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            eligible_kind_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-ELIGIBLE-KINDS",
                &[
                    json!("swap_exact_in"),
                    json!("lending_repay"),
                    json!("vault_deposit"),
                ],
            ),
            eligible_venue_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-ELIGIBLE-VENUES",
                &[json!("private_amm"), json!("lending_pool"), json!("vault")],
            ),
            rebate_bps: 7,
            status: SponsorStatus::Active,
            opened_at_height: DEVNET_HEIGHT - 40,
            expires_at_height: DEVNET_HEIGHT + 400,
        });

        let reservation_ids = [
            intent_a.intent_id.clone(),
            intent_b.intent_id.clone(),
            intent_c.intent_id.clone(),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, intent_id)| {
            let reservation_id = sponsor_reservation_id(&voucher_id, &intent_id, index as u64 + 1);
            state.insert_sponsor_reservation(SponsorReservation {
                reservation_id: reservation_id.clone(),
                voucher_id: voucher_id.clone(),
                intent_id,
                batch_id: batch_id.clone(),
                reserved_micro_units: 240,
                rebate_bps: 7,
                reservation_root: payload_root(
                    "DEVNET-SPONSOR-RESERVATION",
                    &json!({"sequence": index + 1}),
                ),
                status: ReservationStatus::Consumed,
                reserved_at_height: DEVNET_HEIGHT + 4,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_RESERVATION_TTL_BLOCKS,
            });
            reservation_id
        })
        .collect::<Vec<_>>();

        let intent_ids = vec![intent_a.intent_id, intent_b.intent_id, intent_c.intent_id];
        let intent_records = intent_ids
            .iter()
            .filter_map(|id| state.intents.get(id))
            .map(EncryptedIntent::public_record)
            .collect::<Vec<_>>();
        let intent_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:BATCH-INTENTS",
            &intent_records,
        );
        let netting_proof_id = netting_proof_id(&batch_id, 1);
        state.insert_netting_proof(NettingProof {
            proof_id: netting_proof_id.clone(),
            batch_id: batch_id.clone(),
            intent_root: intent_root.clone(),
            input_commitment_root: payload_root("DEVNET-NETTING-INPUTS", &json!(&intent_ids)),
            output_commitment_root: payload_root(
                "DEVNET-NETTING-OUTPUTS",
                &json!("balanced-private-notes"),
            ),
            net_delta_root: payload_root(
                "DEVNET-NET-DELTA",
                &json!({"wxmr-devnet": 0, "usdc-devnet": 0}),
            ),
            conservation_root: payload_root("DEVNET-CONSERVATION", &json!("assets-conserved")),
            privacy_set_root: state.roots.privacy_set_root.clone(),
            nullifier_fence_root: state.roots.nullifier_fence_root.clone(),
            proof_root: payload_root("DEVNET-NETTING-PROOF", &json!("zk-proof-bytes-root")),
            verifier_key_root: payload_root("DEVNET-NETTING-VK", &json!("vk:netting:v1")),
            pq_transcript_root: payload_root(
                "DEVNET-NETTING-PQ-TRANSCRIPT",
                &json!("ml-dsa+slh-dsa"),
            ),
            fee_saved_micro_units: 1_920,
            proof_size_bytes: 9_216,
            generated_at_height: DEVNET_HEIGHT + 5,
        });
        state.insert_batch(ClearingBatch {
            batch_id: batch_id.clone(),
            epoch: DEVNET_EPOCH,
            solver_id,
            intent_ids: intent_ids.clone(),
            status: BatchStatus::Settled,
            encrypted_intent_root: intent_root,
            solver_commitment_root: state.roots.solver_root.clone(),
            netting_proof_id: netting_proof_id.clone(),
            clearing_proof_root: payload_root(
                "DEVNET-CLEARING-PROOF",
                &json!("clearing-proof-root"),
            ),
            settlement_call_root: payload_root(
                "DEVNET-SETTLEMENT-CALL",
                &json!("settle-private-netted-batch"),
            ),
            fee_vector_root: payload_root("DEVNET-FEE-VECTOR", &json!([120, 120, 120])),
            rebate_root: payload_root("DEVNET-REBATE-VECTOR", &json!([84, 84, 84])),
            sponsor_reservation_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:DEVNET-RESERVATION-IDS",
                &reservation_ids
                    .iter()
                    .map(|id| json!(id))
                    .collect::<Vec<_>>(),
            ),
            privacy_set_root: state.roots.privacy_set_root.clone(),
            nullifier_fence_root: state.roots.nullifier_fence_root.clone(),
            opened_at_height: DEVNET_HEIGHT + 4,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_CLEARING_TTL_BLOCKS,
        });
        for (index, reservation_id) in reservation_ids.iter().enumerate() {
            let intent_id = intent_ids[index].clone();
            state.insert_rebate_commitment(RebateCommitment {
                rebate_id: rebate_id(&intent_id, reservation_id, index as u64 + 1),
                reservation_id: reservation_id.clone(),
                intent_id,
                recipient_commitment: format!("recipient:devnet:{index}"),
                asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                rebate_micro_units: 84,
                fee_paid_micro_units: 120,
                low_fee_score: 980,
                proof_root: payload_root("DEVNET-REBATE-PROOF", &json!({"index": index})),
                committed_at_height: DEVNET_HEIGHT + 6,
            });
        }
        state.insert_settlement_receipt(SettlementReceipt {
            receipt_id: settlement_receipt_id(&batch_id, &netting_proof_id, 1),
            batch_id,
            netting_proof_id,
            settlement_tx_root: payload_root("DEVNET-SETTLEMENT-TX", &json!("tx:private-l2:clear")),
            settlement_state_root: payload_root("DEVNET-SETTLEMENT-STATE", &json!("post-state")),
            output_note_root: payload_root("DEVNET-OUTPUT-NOTES", &json!("notes-root")),
            consumed_nullifier_root: payload_root(
                "DEVNET-CONSUMED-NULLIFIERS",
                &json!("consumed-root"),
            ),
            rebate_root: state.roots.rebate_root.clone(),
            sponsor_debit_root: payload_root("DEVNET-SPONSOR-DEBITS", &json!("debit:720")),
            public_audit_root: payload_root(
                "DEVNET-PUBLIC-AUDIT",
                &json!("public-minimal-audit-record"),
            ),
            status: ReceiptStatus::Finalized,
            settled_at_height: DEVNET_HEIGHT + 7,
            finalized_at_height: DEVNET_HEIGHT + 12,
        });
        let receipt_id = state
            .settlement_receipts
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "receipt:missing".to_string());
        let checkpoint_root_before = state.roots.state_root.clone();
        state.insert_clearing_checkpoint(ClearingCheckpoint {
            checkpoint_id: clearing_checkpoint_id(&receipt_id, DEVNET_EPOCH, 1),
            batch_id: state
                .batches
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "batch:missing".to_string()),
            receipt_id,
            root_before: checkpoint_root_before,
            root_after: state.state_root(),
            public_record_root: state.public_record_root(),
            state_root: state.state_root(),
            data_availability_root: payload_root(
                "DEVNET-CLEARING-DA",
                &json!("compressed-public-record"),
            ),
            pq_signature_root: payload_root(
                "DEVNET-CHECKPOINT-PQ-SIGNATURE",
                &json!("ml-dsa-signature-root"),
            ),
            posted_at_height: DEVNET_HEIGHT + 13,
        });
        state.insert_audit_window(AuditWindow {
            audit_id: audit_window_id(DEVNET_EPOCH, "low-fee-private-clearing"),
            epoch: DEVNET_EPOCH,
            batch_root: state.roots.batch_root.clone(),
            receipt_root: state.roots.receipt_root.clone(),
            rebate_root: state.roots.rebate_root.clone(),
            fee_quote_root: state.roots.fee_quote_root.clone(),
            lane_root: state.roots.lane_liquidity_root.clone(),
            nullifier_fence_root: state.roots.nullifier_fence_root.clone(),
            privacy_set_root: state.roots.privacy_set_root.clone(),
            max_fee_bps_observed: 9,
            average_user_fee_micro_units: 36,
            total_fee_saved_micro_units: 1_920,
            opened_at_height: DEVNET_HEIGHT,
            closed_at_height: DEVNET_HEIGHT + 13,
        });
        state.spent_nullifiers.insert("nf:devnet:alpha".to_string());
        state.spent_nullifiers.insert("nf:devnet:bravo".to_string());
        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn insert_intent(&mut self, intent: EncryptedIntent) {
        self.intents.insert(intent.intent_id.clone(), intent);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_solver(&mut self, solver: SolverCommitment) {
        self.solvers.insert(solver.solver_id.clone(), solver);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_batch(&mut self, batch: ClearingBatch) {
        self.batches.insert(batch.batch_id.clone(), batch);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_netting_proof(&mut self, proof: NettingProof) {
        self.netting_proofs.insert(proof.proof_id.clone(), proof);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_sponsor_voucher(&mut self, voucher: SponsorVoucher) {
        self.sponsor_vouchers
            .insert(voucher.voucher_id.clone(), voucher);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_sponsor_reservation(&mut self, reservation: SponsorReservation) {
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_settlement_receipt(&mut self, receipt: SettlementReceipt) {
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_rebate_commitment(&mut self, rebate: RebateCommitment) {
        self.rebate_commitments
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn insert_privacy_set(&mut self, privacy_set: PrivacySet) {
        self.privacy_sets
            .insert(privacy_set.privacy_set_id.clone(), privacy_set);
        self.refresh_roots();
    }

    pub fn insert_nullifier_fence(&mut self, fence: NullifierFence) {
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
        self.refresh_roots();
    }

    pub fn insert_lane_liquidity(&mut self, lane: LaneLiquidity) {
        self.lane_liquidity.insert(lane.lane_id.clone(), lane);
        self.refresh_roots();
    }

    pub fn insert_fee_quote(&mut self, quote: FeeQuote) {
        self.fee_quotes.insert(quote.quote_id.clone(), quote);
        self.refresh_roots();
    }

    pub fn insert_clearing_checkpoint(&mut self, checkpoint: ClearingCheckpoint) {
        self.clearing_checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
        self.refresh_roots();
    }

    pub fn insert_audit_window(&mut self, audit_window: AuditWindow) {
        self.audit_windows
            .insert(audit_window.audit_id.clone(), audit_window);
        self.refresh_roots();
    }

    pub fn insert_runtime_policy(&mut self, policy: RuntimePolicy) {
        self.runtime_policies
            .insert(policy.policy_id.clone(), policy);
        self.refresh_roots();
    }

    pub fn mark_intent_status(
        &mut self,
        intent_id: &str,
        status: IntentStatus,
    ) -> PrivateL2LowFeeIntentNettingClearingRuntimeResult<()> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("unknown intent id: {intent_id}"))?;
        intent.status = status;
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("state record is object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots_without_self_reference(&self.roots),
        })
    }

    pub fn public_record_root(&self) -> String {
        public_record_root(&self.public_record_without_root())
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn refresh_counters(&mut self) {
        self.counters.encrypted_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Encrypted)
            .count() as u64;
        self.counters.admitted_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Admitted)
            .count() as u64;
        self.counters.netted_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Netted)
            .count() as u64;
        self.counters.cleared_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Cleared)
            .count() as u64;
        self.counters.settled_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Settled)
            .count() as u64;
        self.counters.rejected_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Rejected)
            .count() as u64;
        self.counters.solver_commitments = self.solvers.len() as u64;
        self.counters.clearing_batches = self.batches.len() as u64;
        self.counters.sponsor_vouchers = self.sponsor_vouchers.len() as u64;
        self.counters.active_reservations = self
            .sponsor_reservations
            .values()
            .filter(|reservation| reservation.status == ReservationStatus::Reserved)
            .count() as u64;
        self.counters.consumed_reservations = self
            .sponsor_reservations
            .values()
            .filter(|reservation| reservation.status == ReservationStatus::Consumed)
            .count() as u64;
        self.counters.settlement_receipts = self.settlement_receipts.len() as u64;
        self.counters.rebate_commitments = self.rebate_commitments.len() as u64;
        self.counters.next_intent_sequence = self.intents.len() as u64 + 1;
        self.counters.next_solver_sequence = self.solvers.len() as u64 + 1;
        self.counters.next_batch_sequence = self.batches.len() as u64 + 1;
        self.counters.next_netting_sequence = self.netting_proofs.len() as u64 + 1;
        self.counters.next_sponsor_sequence = self.sponsor_vouchers.len() as u64 + 1;
        self.counters.next_reservation_sequence = self.sponsor_reservations.len() as u64 + 1;
        self.counters.next_receipt_sequence = self.settlement_receipts.len() as u64 + 1;
        self.counters.next_rebate_sequence = self.rebate_commitments.len() as u64 + 1;
    }

    pub fn refresh_roots(&mut self) {
        self.roots.intent_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:INTENTS",
            self.intents
                .values()
                .map(EncryptedIntent::public_record)
                .collect(),
        );
        self.roots.solver_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SOLVERS",
            self.solvers
                .values()
                .map(SolverCommitment::public_record)
                .collect(),
        );
        self.roots.batch_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:BATCHES",
            self.batches
                .values()
                .map(ClearingBatch::public_record)
                .collect(),
        );
        self.roots.netting_proof_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:NETTING-PROOFS",
            self.netting_proofs
                .values()
                .map(NettingProof::public_record)
                .collect(),
        );
        self.roots.sponsor_voucher_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SPONSOR-VOUCHERS",
            self.sponsor_vouchers
                .values()
                .map(SponsorVoucher::public_record)
                .collect(),
        );
        self.roots.sponsor_reservation_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SPONSOR-RESERVATIONS",
            self.sponsor_reservations
                .values()
                .map(SponsorReservation::public_record)
                .collect(),
        );
        self.roots.receipt_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        self.roots.rebate_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:REBATES",
            self.rebate_commitments
                .values()
                .map(RebateCommitment::public_record)
                .collect(),
        );
        self.roots.privacy_set_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:PRIVACY-SETS",
            self.privacy_sets
                .values()
                .map(PrivacySet::public_record)
                .collect(),
        );
        self.roots.nullifier_fence_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:NULLIFIER-FENCES",
            self.nullifier_fences
                .values()
                .map(NullifierFence::public_record)
                .collect(),
        );
        self.roots.lane_liquidity_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:LANE-LIQUIDITY",
            self.lane_liquidity
                .values()
                .map(LaneLiquidity::public_record)
                .collect(),
        );
        self.roots.fee_quote_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:FEE-QUOTES",
            self.fee_quotes
                .values()
                .map(FeeQuote::public_record)
                .collect(),
        );
        self.roots.checkpoint_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:CLEARING-CHECKPOINTS",
            self.clearing_checkpoints
                .values()
                .map(ClearingCheckpoint::public_record)
                .collect(),
        );
        self.roots.audit_window_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:AUDIT-WINDOWS",
            self.audit_windows
                .values()
                .map(AuditWindow::public_record)
                .collect(),
        );
        self.roots.policy_root = records_root(
            "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:RUNTIME-POLICIES",
            self.runtime_policies
                .values()
                .map(RuntimePolicy::public_record)
                .collect(),
        );
        self.roots.public_record_root = self.public_record_root();
        self.roots.state_root = self.state_root();
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
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
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:PUBLIC-RECORD",
        record,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:STATE-ROOT",
        record,
    )
}

pub fn encrypted_intent_id(
    owner_commitment: &str,
    kind: IntentKind,
    encrypted_payload_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:ENCRYPTED-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn solver_id(solver_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SOLVER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_commitment),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn clearing_batch_id(epoch: u64, sequence: u64, solver_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:CLEARING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(sequence as i128),
            HashPart::Str(solver_commitment),
        ],
        32,
    )
}

pub fn netting_proof_id(batch_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:NETTING-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn sponsor_voucher_id(sponsor_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SPONSOR-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(voucher_id: &str, intent_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(voucher_id),
            HashPart::Str(intent_id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, netting_proof_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(netting_proof_id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn rebate_id(intent_id: &str, reservation_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(reservation_id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn privacy_set_id(epoch: u64, lane: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:PRIVACY-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(lane),
        ],
        32,
    )
}

pub fn nullifier_fence_id(epoch: u64, lane: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(lane),
        ],
        32,
    )
}

pub fn lane_liquidity_id(
    venue: VenueKind,
    base_asset_id: &str,
    quote_asset_id: &str,
    epoch: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:LANE-LIQUIDITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(venue.as_str()),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn fee_quote_id(intent_id: &str, lane_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:FEE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(lane_id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn clearing_checkpoint_id(receipt_id: &str, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:CLEARING-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn audit_window_id(epoch: u64, scope: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-INTENT-NETTING-CLEARING:AUDIT-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(scope),
        ],
        32,
    )
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn roots_without_self_reference(roots: &Roots) -> Value {
    json!({
        "intent_root": roots.intent_root,
        "solver_root": roots.solver_root,
        "batch_root": roots.batch_root,
        "netting_proof_root": roots.netting_proof_root,
        "sponsor_voucher_root": roots.sponsor_voucher_root,
        "sponsor_reservation_root": roots.sponsor_reservation_root,
        "receipt_root": roots.receipt_root,
        "rebate_root": roots.rebate_root,
        "privacy_set_root": roots.privacy_set_root,
        "nullifier_fence_root": roots.nullifier_fence_root,
        "lane_liquidity_root": roots.lane_liquidity_root,
        "fee_quote_root": roots.fee_quote_root,
        "checkpoint_root": roots.checkpoint_root,
        "audit_window_root": roots.audit_window_root,
        "policy_root": roots.policy_root,
    })
}

fn devnet_intent(
    sequence: u64,
    kind: IntentKind,
    venue: VenueKind,
    source_asset_id: &str,
    target_asset_id: &str,
    privacy_set_id: &str,
    nullifier_fence_id: &str,
    submitted_at_height: u64,
) -> EncryptedIntent {
    let encrypted_payload = json!({
        "sequence": sequence,
        "kind": kind.as_str(),
        "venue": venue.as_str(),
        "source_asset_id": source_asset_id,
        "target_asset_id": target_asset_id,
        "note": "devnet encrypted payload commitment only",
    });
    let encrypted_payload_root =
        payload_root("DEVNET-ENCRYPTED-INTENT-PAYLOAD", &encrypted_payload);
    let owner_commitment = format!("owner:commitment:devnet:{sequence}");
    EncryptedIntent {
        intent_id: encrypted_intent_id(&owner_commitment, kind, &encrypted_payload_root, sequence),
        owner_commitment,
        kind,
        venue,
        source_asset_id: source_asset_id.to_string(),
        target_asset_id: target_asset_id.to_string(),
        amount_bucket: 64 + sequence * 16,
        max_fee_micro_units: 180,
        max_slippage_bps: 35,
        privacy_set_id: privacy_set_id.to_string(),
        nullifier_fence_id: nullifier_fence_id.to_string(),
        encrypted_payload_root,
        route_hint_root: payload_root(
            "DEVNET-ROUTE-HINT",
            &json!({"sequence": sequence, "venue": venue.as_str()}),
        ),
        constraint_root: payload_root(
            "DEVNET-CONSTRAINTS",
            &json!({"ttl": DEFAULT_INTENT_TTL_BLOCKS, "max_fee": 180}),
        ),
        sponsor_hint_root: payload_root("DEVNET-SPONSOR-HINT", &json!("fee-relief")),
        pq_ephemeral_key_root: payload_root(
            "DEVNET-PQ-EPHEMERAL-KEY",
            &json!({"sequence": sequence}),
        ),
        status: IntentStatus::Settled,
        submitted_at_height,
        expires_at_height: submitted_at_height + DEFAULT_INTENT_TTL_BLOCKS,
    }
}
