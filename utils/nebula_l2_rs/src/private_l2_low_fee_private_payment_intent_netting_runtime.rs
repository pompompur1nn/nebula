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
    "nebula-private-l2-low-fee-private-payment-intent-netting-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256s-payment-intent-auth-v1";
pub const PQ_SEALING_SCHEME: &str = "ml-kem-1024+xwing-sealed-payment-intent-v1";
pub const PRIVATE_PAYMENT_PROOF_SCHEME: &str = "zk-private-payment-intent-proof-pq-v1";
pub const NETTING_PROOF_SCHEME: &str = "zk-private-low-fee-payment-netting-proof-v1";
pub const CHANNEL_SETTLEMENT_SCHEME: &str = "monero-l2-private-payment-channel-root-v1";
pub const FAST_RECEIPT_SCHEME: &str = "fast-private-payment-receipt-pq-v1";
pub const SPONSOR_CAPACITY_SCHEME: &str = "low-fee-private-payment-sponsor-capacity-v1";
pub const REBATE_PROOF_SCHEME: &str = "low-fee-private-payment-rebate-proof-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "private-payment-netting-slasher-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 226_170;
pub const DEVNET_EPOCH: u64 = 314;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_PAYMENT_ASSET_ID: &str = "pxmr-devnet";
pub const DEFAULT_CORRIDOR_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 40;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_PRIVACY_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 128;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 28;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 4;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_000;
pub const DEFAULT_REBATE_BPS: u64 = 7;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_MAX_INTENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_CORRIDORS: usize = 131_072;
pub const DEFAULT_MAX_RECEIPTS: usize = 262_144;
pub const DEFAULT_MAX_SPONSORS: usize = 16_384;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorridorKind {
    Merchant,
    WalletToWallet,
    DefiPayment,
    ContractEscrow,
    TokenTransfer,
    BridgeExit,
    Payroll,
    Streaming,
}

impl CorridorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merchant => "merchant",
            Self::WalletToWallet => "wallet_to_wallet",
            Self::DefiPayment => "defi_payment",
            Self::ContractEscrow => "contract_escrow",
            Self::TokenTransfer => "token_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::Payroll => "payroll",
            Self::Streaming => "streaming",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorridorStatus {
    Open,
    Active,
    Draining,
    Settling,
    Settled,
    Paused,
    Closed,
    Slashed,
}

impl CorridorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentIntentKind {
    PayInvoice,
    PayAddress,
    ContractCall,
    TokenTransfer,
    DefiSwapPayment,
    VaultDeposit,
    LendingRepay,
    PayrollDisbursement,
    StreamingTick,
    BridgeExitPayment,
}

impl PaymentIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayInvoice => "pay_invoice",
            Self::PayAddress => "pay_address",
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::DefiSwapPayment => "defi_swap_payment",
            Self::VaultDeposit => "vault_deposit",
            Self::LendingRepay => "lending_repay",
            Self::PayrollDisbursement => "payroll_disbursement",
            Self::StreamingTick => "streaming_tick",
            Self::BridgeExitPayment => "bridge_exit_payment",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    SponsorReserved,
    Netted,
    ReceiptReady,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Netted => "netted",
            Self::ReceiptReady => "receipt_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Sealed | Self::Admitted | Self::SponsorReserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Netted,
    Receipting,
    ChannelSettling,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Netted => "netted",
            Self::Receipting => "receipting",
            Self::ChannelSettling => "channel_settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Receipting | Self::ChannelSettling)
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

    pub fn reservable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Held,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Provisional,
    FastAccepted,
    Finalized,
    Failed,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisional => "provisional",
            Self::FastAccepted => "fast_accepted",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyEventKind {
    CorridorOpen,
    IntentSubmit,
    SponsorReserve,
    BatchNet,
    ReceiptProduce,
    ChannelSettle,
    Rebate,
    Slash,
}

impl PrivacyEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CorridorOpen => "corridor_open",
            Self::IntentSubmit => "intent_submit",
            Self::SponsorReserve => "sponsor_reserve",
            Self::BatchNet => "batch_net",
            Self::ReceiptProduce => "receipt_produce",
            Self::ChannelSettle => "channel_settle",
            Self::Rebate => "rebate",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Open,
    Accepted,
    Rejected,
    Executed,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub default_payment_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub pq_sealing_scheme: String,
    pub private_payment_proof_scheme: String,
    pub netting_proof_scheme: String,
    pub channel_settlement_scheme: String,
    pub fast_receipt_scheme: String,
    pub sponsor_capacity_scheme: String,
    pub rebate_proof_scheme: String,
    pub slashing_evidence_scheme: String,
    pub genesis_height: u64,
    pub current_height: u64,
    pub epoch: u64,
    pub corridor_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub privacy_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub max_intents_per_batch: usize,
    pub max_corridors: usize,
    pub max_receipts: usize,
    pub max_sponsors: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            default_payment_asset_id: DEVNET_PAYMENT_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            pq_sealing_scheme: PQ_SEALING_SCHEME.to_string(),
            private_payment_proof_scheme: PRIVATE_PAYMENT_PROOF_SCHEME.to_string(),
            netting_proof_scheme: NETTING_PROOF_SCHEME.to_string(),
            channel_settlement_scheme: CHANNEL_SETTLEMENT_SCHEME.to_string(),
            fast_receipt_scheme: FAST_RECEIPT_SCHEME.to_string(),
            sponsor_capacity_scheme: SPONSOR_CAPACITY_SCHEME.to_string(),
            rebate_proof_scheme: REBATE_PROOF_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            genesis_height: DEVNET_HEIGHT,
            current_height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            corridor_ttl_blocks: DEFAULT_CORRIDOR_TTL_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            privacy_epoch_blocks: DEFAULT_PRIVACY_EPOCH_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_intents_per_batch: DEFAULT_MAX_INTENTS_PER_BATCH,
            max_corridors: DEFAULT_MAX_CORRIDORS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_sponsors: DEFAULT_MAX_SPONSORS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "default_payment_asset_id": self.default_payment_asset_id,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_sealing_scheme": self.pq_sealing_scheme,
            "private_payment_proof_scheme": self.private_payment_proof_scheme,
            "netting_proof_scheme": self.netting_proof_scheme,
            "channel_settlement_scheme": self.channel_settlement_scheme,
            "fast_receipt_scheme": self.fast_receipt_scheme,
            "sponsor_capacity_scheme": self.sponsor_capacity_scheme,
            "rebate_proof_scheme": self.rebate_proof_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "genesis_height": self.genesis_height,
            "current_height": self.current_height,
            "epoch": self.epoch,
            "corridor_ttl_blocks": self.corridor_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "privacy_epoch_blocks": self.privacy_epoch_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "netting_fee_bps": self.netting_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "slash_bps": self.slash_bps,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_corridors": self.max_corridors,
            "max_receipts": self.max_receipts,
            "max_sponsors": self.max_sponsors,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-NETTING-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub corridors_opened: u64,
    pub intents_submitted: u64,
    pub intents_netted: u64,
    pub batches_created: u64,
    pub sponsor_reservations: u64,
    pub receipts_produced: u64,
    pub channel_settlements: u64,
    pub privacy_events: u64,
    pub rebates_accrued: u64,
    pub rebates_claimed: u64,
    pub slashing_cases: u64,
    pub slashing_executions: u64,
    pub total_gross_fee_micro_units: u64,
    pub total_net_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_slashed_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "corridors_opened": self.corridors_opened,
            "intents_submitted": self.intents_submitted,
            "intents_netted": self.intents_netted,
            "batches_created": self.batches_created,
            "sponsor_reservations": self.sponsor_reservations,
            "receipts_produced": self.receipts_produced,
            "channel_settlements": self.channel_settlements,
            "privacy_events": self.privacy_events,
            "rebates_accrued": self.rebates_accrued,
            "rebates_claimed": self.rebates_claimed,
            "slashing_cases": self.slashing_cases,
            "slashing_executions": self.slashing_executions,
            "total_gross_fee_micro_units": self.total_gross_fee_micro_units,
            "total_net_fee_micro_units": self.total_net_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "total_slashed_micro_units": self.total_slashed_micro_units,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-NETTING-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub corridor_root: String,
    pub intent_root: String,
    pub batch_root: String,
    pub sponsor_root: String,
    pub reservation_root: String,
    pub receipt_root: String,
    pub settlement_root: String,
    pub privacy_budget_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "corridor_root": self.corridor_root,
            "intent_root": self.intent_root,
            "batch_root": self.batch_root,
            "sponsor_root": self.sponsor_root,
            "reservation_root": self.reservation_root,
            "receipt_root": self.receipt_root,
            "settlement_root": self.settlement_root,
            "privacy_budget_root": self.privacy_budget_root,
            "rebate_root": self.rebate_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-NETTING-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenCorridorRequest {
    pub payer_commitment: String,
    pub payee_commitment: String,
    pub corridor_kind: CorridorKind,
    pub asset_id: String,
    pub capacity_commitment: String,
    pub capacity_hint_micro_units: u64,
    pub viewing_policy_root: String,
    pub pq_key_root: String,
    pub initial_channel_root: String,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentCorridor {
    pub corridor_id: String,
    pub payer_commitment: String,
    pub payee_commitment: String,
    pub corridor_kind: CorridorKind,
    pub status: CorridorStatus,
    pub asset_id: String,
    pub capacity_commitment: String,
    pub capacity_hint_micro_units: u64,
    pub spent_hint_micro_units: u64,
    pub viewing_policy_root: String,
    pub pq_key_root: String,
    pub latest_channel_root: String,
    pub latest_batch_id: Option<String>,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl PaymentCorridor {
    pub fn public_record(&self) -> Value {
        json!({
            "corridor_id": self.corridor_id,
            "chain_id": CHAIN_ID,
            "payer_commitment": self.payer_commitment,
            "payee_commitment": self.payee_commitment,
            "corridor_kind": self.corridor_kind.as_str(),
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "capacity_commitment": self.capacity_commitment,
            "capacity_hint_micro_units": self.capacity_hint_micro_units,
            "spent_hint_micro_units": self.spent_hint_micro_units,
            "viewing_policy_root": self.viewing_policy_root,
            "pq_key_root": self.pq_key_root,
            "latest_channel_root": self.latest_channel_root,
            "latest_batch_id": self.latest_batch_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-CORRIDOR", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSealedPaymentIntentRequest {
    pub corridor_id: String,
    pub payer_note_commitment: String,
    pub payee_note_commitment: String,
    pub intent_kind: PaymentIntentKind,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub max_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub encrypted_payload_hash: String,
    pub proof_public_input_root: String,
    pub decoy_set_root: String,
    pub nullifier_hash: String,
    pub pq_auth_root: String,
    pub sponsor_hint: Option<String>,
    pub submitted_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPaymentIntent {
    pub intent_id: String,
    pub corridor_id: String,
    pub payer_note_commitment: String,
    pub payee_note_commitment: String,
    pub intent_kind: PaymentIntentKind,
    pub status: IntentStatus,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub gross_fee_micro_units: u64,
    pub net_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub encrypted_payload_hash: String,
    pub proof_public_input_root: String,
    pub decoy_set_root: String,
    pub nullifier_hash: String,
    pub pq_auth_root: String,
    pub sponsor_id: Option<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl SealedPaymentIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "chain_id": CHAIN_ID,
            "corridor_id": self.corridor_id,
            "payer_note_commitment": self.payer_note_commitment,
            "payee_note_commitment": self.payee_note_commitment,
            "intent_kind": self.intent_kind.as_str(),
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "net_fee_micro_units": self.net_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_public_input_root": self.proof_public_input_root,
            "decoy_set_root": self.decoy_set_root,
            "nullifier_hash": self.nullifier_hash,
            "pq_auth_root": self.pq_auth_root,
            "sponsor_id": self.sponsor_id,
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEALED-PAYMENT-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorCapacityRequest {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub capacity_micro_units: u64,
    pub max_cover_bps: u64,
    pub pq_stake_root: String,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorStatus,
    pub fee_asset_id: String,
    pub capacity_micro_units: u64,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub rebated_micro_units: u64,
    pub slashed_micro_units: u64,
    pub max_cover_bps: u64,
    pub pq_stake_root: String,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub nonce: u64,
}

impl SponsorAccount {
    pub fn available_micro_units(&self) -> u64 {
        self.capacity_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.consumed_micro_units)
            .saturating_sub(self.slashed_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "chain_id": CHAIN_ID,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "capacity_micro_units": self.capacity_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "rebated_micro_units": self.rebated_micro_units,
            "slashed_micro_units": self.slashed_micro_units,
            "max_cover_bps": self.max_cover_bps,
            "pq_stake_root": self.pq_stake_root,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-SPONSOR-ACCOUNT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorCapacityRequest {
    pub sponsor_id: String,
    pub intent_id: String,
    pub requested_micro_units: u64,
    pub reserved_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_id: String,
    pub intent_id: String,
    pub status: ReservationStatus,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "reserved_micro_units": self.reserved_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-SPONSOR-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPaymentBatchRequest {
    pub operator_commitment: String,
    pub corridor_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub liquidity_hint_root: String,
    pub solver_commitment: String,
    pub netting_proof_root: String,
    pub batch_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingLeg {
    pub asset_id: String,
    pub corridor_id: String,
    pub debit_bucket: u64,
    pub credit_bucket: u64,
    pub fee_micro_units: u64,
    pub intent_count: u64,
}

impl NettingLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "asset_id": self.asset_id,
            "corridor_id": self.corridor_id,
            "debit_bucket": self.debit_bucket,
            "credit_bucket": self.credit_bucket,
            "fee_micro_units": self.fee_micro_units,
            "intent_count": self.intent_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentNettingBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub operator_commitment: String,
    pub solver_commitment: String,
    pub corridor_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub netting_legs: Vec<NettingLeg>,
    pub liquidity_hint_root: String,
    pub intent_root: String,
    pub corridor_root: String,
    pub netting_leg_root: String,
    pub netting_proof_root: String,
    pub gross_fee_micro_units: u64,
    pub net_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub batch_height: u64,
    pub expires_at_height: u64,
    pub channel_settlement_root: Option<String>,
    pub receipt_root: Option<String>,
    pub nonce: u64,
}

impl PaymentNettingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "chain_id": CHAIN_ID,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "solver_commitment": self.solver_commitment,
            "corridor_ids": self.corridor_ids,
            "intent_ids": self.intent_ids,
            "netting_legs": self.netting_legs.iter().map(NettingLeg::public_record).collect::<Vec<_>>(),
            "liquidity_hint_root": self.liquidity_hint_root,
            "intent_root": self.intent_root,
            "corridor_root": self.corridor_root,
            "netting_leg_root": self.netting_leg_root,
            "netting_proof_root": self.netting_proof_root,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "net_fee_micro_units": self.net_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "batch_height": self.batch_height,
            "expires_at_height": self.expires_at_height,
            "channel_settlement_root": self.channel_settlement_root,
            "receipt_root": self.receipt_root,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-NETTING-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPrivateReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub batch_id: String,
    pub corridor_id: String,
    pub status: ReceiptStatus,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub fee_micro_units: u64,
    pub encrypted_receipt_hash: String,
    pub recipient_view_tag_root: String,
    pub proof_public_input_root: String,
    pub receipt_signature_root: String,
    pub produced_at_height: u64,
    pub finalizes_at_height: u64,
}

impl FastPrivateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "chain_id": CHAIN_ID,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "corridor_id": self.corridor_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket,
            "fee_micro_units": self.fee_micro_units,
            "encrypted_receipt_hash": self.encrypted_receipt_hash,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "proof_public_input_root": self.proof_public_input_root,
            "receipt_signature_root": self.receipt_signature_root,
            "produced_at_height": self.produced_at_height,
            "finalizes_at_height": self.finalizes_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAST-PRIVATE-PAYMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRootRequest {
    pub batch_id: String,
    pub channel_settlement_root: String,
    pub availability_root: String,
    pub settlement_proof_root: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSettlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub channel_settlement_root: String,
    pub availability_root: String,
    pub settlement_proof_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub settled_at_height: u64,
}

impl ChannelSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "channel_settlement_root": self.channel_settlement_root,
            "availability_root": self.availability_root,
            "settlement_proof_root": self.settlement_proof_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-CHANNEL-SETTLEMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetEntry {
    pub budget_id: String,
    pub subject_commitment: String,
    pub event_kind: PrivacyEventKind,
    pub privacy_epoch: u64,
    pub privacy_cost_units: u64,
    pub privacy_set_size: u64,
    pub decoy_set_root: String,
    pub event_root: String,
    pub recorded_at_height: u64,
}

impl PrivacyBudgetEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "chain_id": CHAIN_ID,
            "subject_commitment": self.subject_commitment,
            "event_kind": self.event_kind.as_str(),
            "privacy_epoch": self.privacy_epoch,
            "privacy_cost_units": self.privacy_cost_units,
            "privacy_set_size": self.privacy_set_size,
            "decoy_set_root": self.decoy_set_root,
            "event_root": self.event_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-PRIVACY-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub sponsor_id: String,
    pub batch_id: String,
    pub intent_ids: Vec<String>,
    pub status: RebateStatus,
    pub gross_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub proof_root: String,
    pub accrued_at_height: u64,
    pub claimed_at_height: Option<u64>,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "batch_id": self.batch_id,
            "intent_ids": self.intent_ids,
            "status": self.status.as_str(),
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "proof_root": self.proof_root,
            "accrued_at_height": self.accrued_at_height,
            "claimed_at_height": self.claimed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingCase {
    pub case_id: String,
    pub offender_id: String,
    pub related_batch_id: Option<String>,
    pub related_intent_id: Option<String>,
    pub status: SlashingStatus,
    pub evidence_root: String,
    pub slash_micro_units: u64,
    pub reporter_commitment: String,
    pub opened_at_height: u64,
    pub executed_at_height: Option<u64>,
}

impl SlashingCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "chain_id": CHAIN_ID,
            "offender_id": self.offender_id,
            "related_batch_id": self.related_batch_id,
            "related_intent_id": self.related_intent_id,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "slash_micro_units": self.slash_micro_units,
            "reporter_commitment": self.reporter_commitment,
            "opened_at_height": self.opened_at_height,
            "executed_at_height": self.executed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PAYMENT-SLASHING-CASE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub corridors: BTreeMap<String, PaymentCorridor>,
    pub intents: BTreeMap<String, SealedPaymentIntent>,
    pub batches: BTreeMap<String, PaymentNettingBatch>,
    pub sponsors: BTreeMap<String, SponsorAccount>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub receipts: BTreeMap<String, FastPrivateReceipt>,
    pub settlements: BTreeMap<String, ChannelSettlement>,
    pub privacy_budget: BTreeMap<String, PrivacyBudgetEntry>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_cases: BTreeMap<String, SlashingCase>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            corridors: BTreeMap::new(),
            intents: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            settlements: BTreeMap::new(),
            privacy_budget: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_cases: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let sponsor_id = sponsor_id(
            "devnet-low-fee-sponsor",
            DEVNET_FEE_ASSET_ID,
            DEFAULT_BASE_FEE_MICRO_UNITS * 1_000_000,
            DEVNET_HEIGHT,
            1,
        );
        let sponsor = SponsorAccount {
            sponsor_id: sponsor_id.clone(),
            sponsor_commitment: "devnet-low-fee-sponsor".to_string(),
            status: SponsorStatus::Active,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            capacity_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS * 1_000_000,
            reserved_micro_units: 0,
            consumed_micro_units: 0,
            rebated_micro_units: 0,
            slashed_micro_units: 0,
            max_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            pq_stake_root: payload_root("DEVNET-SPONSOR-PQ-STAKE", &json!({"stake": "devnet"})),
            policy_root: payload_root(
                "DEVNET-SPONSOR-POLICY",
                &json!({"cover_bps": DEFAULT_SPONSOR_COVER_BPS}),
            ),
            opened_at_height: DEVNET_HEIGHT,
            nonce: 1,
        };
        state.sponsors.insert(sponsor_id, sponsor);
        state
    }

    pub fn open_private_payment_corridor(
        &mut self,
        request: OpenCorridorRequest,
    ) -> Result<PaymentCorridor> {
        if self.corridors.len() >= self.config.max_corridors {
            return Err("private payment corridor registry is full".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("corridor privacy set is below runtime minimum".to_string());
        }
        let corridor_id = corridor_id(
            &request.payer_commitment,
            &request.payee_commitment,
            request.corridor_kind,
            &request.asset_id,
            request.opened_at_height,
            request.nonce,
        );
        if self.corridors.contains_key(&corridor_id) {
            return Err("private payment corridor already exists".to_string());
        }
        let corridor = PaymentCorridor {
            corridor_id: corridor_id.clone(),
            payer_commitment: request.payer_commitment.clone(),
            payee_commitment: request.payee_commitment.clone(),
            corridor_kind: request.corridor_kind,
            status: CorridorStatus::Open,
            asset_id: request.asset_id,
            capacity_commitment: request.capacity_commitment,
            capacity_hint_micro_units: request.capacity_hint_micro_units,
            spent_hint_micro_units: 0,
            viewing_policy_root: request.viewing_policy_root,
            pq_key_root: request.pq_key_root,
            latest_channel_root: request.initial_channel_root,
            latest_batch_id: None,
            min_privacy_set_size: request.min_privacy_set_size,
            opened_at_height: request.opened_at_height,
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.corridor_ttl_blocks),
            nonce: request.nonce,
        };
        self.corridors.insert(corridor_id.clone(), corridor.clone());
        self.counters.corridors_opened = self.counters.corridors_opened.saturating_add(1);
        self.record_privacy_event(
            request.payer_commitment,
            PrivacyEventKind::CorridorOpen,
            request.min_privacy_set_size,
            empty_root("CORRIDOR-DECOYS"),
            corridor.root(),
            request.opened_at_height,
        );
        Ok(corridor)
    }

    pub fn submit_sealed_payment_intent(
        &mut self,
        request: SubmitSealedPaymentIntentRequest,
    ) -> Result<SealedPaymentIntent> {
        let corridor = self
            .corridors
            .get(&request.corridor_id)
            .ok_or_else(|| "unknown private payment corridor".to_string())?;
        if !corridor.status.accepts_intents() {
            return Err("private payment corridor does not accept intents".to_string());
        }
        if request.submitted_at_height > corridor.expires_at_height {
            return Err("private payment corridor has expired".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("payment intent user fee bound exceeds runtime maximum".to_string());
        }
        if self.nullifiers.contains(&request.nullifier_hash) {
            return Err("payment intent nullifier already used".to_string());
        }
        let gross_fee = fee_for_amount(
            request.amount_bucket,
            self.config.netting_fee_bps,
            self.config.base_fee_micro_units,
        )
        .min(request.max_fee_micro_units);
        let intent_id = intent_id(
            &request.corridor_id,
            &request.nullifier_hash,
            &request.encrypted_payload_hash,
            request.submitted_at_height,
            request.nonce,
        );
        let intent = SealedPaymentIntent {
            intent_id: intent_id.clone(),
            corridor_id: request.corridor_id,
            payer_note_commitment: request.payer_note_commitment.clone(),
            payee_note_commitment: request.payee_note_commitment,
            intent_kind: request.intent_kind,
            status: IntentStatus::Admitted,
            asset_id: request.asset_id,
            amount_bucket: request.amount_bucket,
            gross_fee_micro_units: gross_fee,
            net_fee_micro_units: gross_fee,
            rebate_micro_units: 0,
            max_fee_micro_units: request.max_fee_micro_units,
            max_user_fee_bps: request.max_user_fee_bps,
            encrypted_payload_hash: request.encrypted_payload_hash,
            proof_public_input_root: request.proof_public_input_root,
            decoy_set_root: request.decoy_set_root.clone(),
            nullifier_hash: request.nullifier_hash.clone(),
            pq_auth_root: request.pq_auth_root,
            sponsor_id: request.sponsor_hint,
            reservation_id: None,
            batch_id: None,
            receipt_id: None,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.intent_ttl_blocks),
            nonce: request.nonce,
        };
        self.nullifiers.insert(request.nullifier_hash);
        self.intents.insert(intent_id.clone(), intent.clone());
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.counters.total_gross_fee_micro_units = self
            .counters
            .total_gross_fee_micro_units
            .saturating_add(gross_fee);
        self.record_privacy_event(
            request.payer_note_commitment,
            PrivacyEventKind::IntentSubmit,
            self.config.target_privacy_set_size,
            request.decoy_set_root,
            intent.root(),
            request.submitted_at_height,
        );
        Ok(intent)
    }

    pub fn register_sponsor_capacity(
        &mut self,
        request: SponsorCapacityRequest,
    ) -> Result<SponsorAccount> {
        if self.sponsors.len() >= self.config.max_sponsors {
            return Err("sponsor registry is full".to_string());
        }
        if request.max_cover_bps > MAX_BPS {
            return Err("sponsor cover bps exceeds maximum".to_string());
        }
        let sponsor_id = sponsor_id(
            &request.sponsor_commitment,
            &request.fee_asset_id,
            request.capacity_micro_units,
            request.opened_at_height,
            request.nonce,
        );
        let sponsor = SponsorAccount {
            sponsor_id: if request.sponsor_id.is_empty() {
                sponsor_id
            } else {
                request.sponsor_id
            },
            sponsor_commitment: request.sponsor_commitment,
            status: SponsorStatus::Active,
            fee_asset_id: request.fee_asset_id,
            capacity_micro_units: request.capacity_micro_units,
            reserved_micro_units: 0,
            consumed_micro_units: 0,
            rebated_micro_units: 0,
            slashed_micro_units: 0,
            max_cover_bps: request.max_cover_bps,
            pq_stake_root: request.pq_stake_root,
            policy_root: request.policy_root,
            opened_at_height: request.opened_at_height,
            nonce: request.nonce,
        };
        self.sponsors
            .insert(sponsor.sponsor_id.clone(), sponsor.clone());
        Ok(sponsor)
    }

    pub fn reserve_sponsor_capacity(
        &mut self,
        request: ReserveSponsorCapacityRequest,
    ) -> Result<SponsorReservation> {
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "unknown payment intent".to_string())?;
        if !intent.status.batchable() {
            return Err("payment intent cannot reserve sponsor capacity".to_string());
        }
        let sponsor = self
            .sponsors
            .get_mut(&request.sponsor_id)
            .ok_or_else(|| "unknown sponsor".to_string())?;
        if !sponsor.status.reservable() {
            return Err("sponsor is not reservable".to_string());
        }
        let covered = proportional_amount(intent.gross_fee_micro_units, sponsor.max_cover_bps);
        let reserve_amount = request.requested_micro_units.min(covered);
        if reserve_amount == 0 || sponsor.available_micro_units() < reserve_amount {
            return Err("insufficient sponsor capacity".to_string());
        }
        let reservation_id = reservation_id(
            &request.sponsor_id,
            &request.intent_id,
            reserve_amount,
            request.reserved_at_height,
            request.nonce,
        );
        sponsor.reserved_micro_units = sponsor.reserved_micro_units.saturating_add(reserve_amount);
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_id: request.sponsor_id.clone(),
            intent_id: request.intent_id.clone(),
            status: ReservationStatus::Held,
            reserved_micro_units: reserve_amount,
            consumed_micro_units: 0,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.reservation_ttl_blocks),
            nonce: request.nonce,
        };
        intent.status = IntentStatus::SponsorReserved;
        intent.sponsor_id = Some(request.sponsor_id.clone());
        intent.reservation_id = Some(reservation_id.clone());
        self.reservations
            .insert(reservation_id.clone(), reservation.clone());
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        self.record_privacy_event(
            request.sponsor_id,
            PrivacyEventKind::SponsorReserve,
            self.config.min_privacy_set_size,
            empty_root("SPONSOR-RESERVE-DECOYS"),
            reservation.root(),
            request.reserved_at_height,
        );
        Ok(reservation)
    }

    pub fn net_many_intents_into_low_fee_payment_batch(
        &mut self,
        request: NetPaymentBatchRequest,
    ) -> Result<PaymentNettingBatch> {
        if request.intent_ids.is_empty() {
            return Err("netting batch requires at least one payment intent".to_string());
        }
        if request.intent_ids.len() > self.config.max_intents_per_batch {
            return Err("netting batch exceeds maximum payment intent count".to_string());
        }
        let mut corridor_ids = BTreeSet::new();
        for corridor_id in &request.corridor_ids {
            if !self.corridors.contains_key(corridor_id) {
                return Err(format!("unknown private payment corridor {corridor_id}"));
            }
            corridor_ids.insert(corridor_id.clone());
        }
        let mut legs: BTreeMap<(String, String), NettingLeg> = BTreeMap::new();
        let mut gross_fee = 0_u64;
        let mut net_fee = 0_u64;
        let mut rebate = 0_u64;
        let mut batchable = Vec::new();
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown payment intent {intent_id}"))?;
            if !intent.status.batchable() {
                return Err(format!("payment intent {intent_id} is not batchable"));
            }
            if request.batch_height > intent.expires_at_height {
                return Err(format!("payment intent {intent_id} has expired"));
            }
            if !corridor_ids.contains(&intent.corridor_id) {
                return Err(format!("payment intent {intent_id} corridor not included"));
            }
            let key = (intent.asset_id.clone(), intent.corridor_id.clone());
            let leg = legs.entry(key).or_insert_with(|| NettingLeg {
                asset_id: intent.asset_id.clone(),
                corridor_id: intent.corridor_id.clone(),
                debit_bucket: 0,
                credit_bucket: 0,
                fee_micro_units: 0,
                intent_count: 0,
            });
            leg.debit_bucket = leg.debit_bucket.saturating_add(intent.amount_bucket);
            leg.credit_bucket = leg
                .credit_bucket
                .saturating_add(proportional_amount(intent.amount_bucket, MAX_BPS - 2));
            leg.fee_micro_units = leg
                .fee_micro_units
                .saturating_add(intent.net_fee_micro_units);
            leg.intent_count = leg.intent_count.saturating_add(1);
            gross_fee = gross_fee.saturating_add(intent.gross_fee_micro_units);
            let intent_rebate =
                proportional_amount(intent.gross_fee_micro_units, self.config.rebate_bps);
            rebate = rebate.saturating_add(intent_rebate);
            net_fee =
                net_fee.saturating_add(intent.gross_fee_micro_units.saturating_sub(intent_rebate));
            batchable.push(intent_id.clone());
        }
        let netting_legs = legs.into_values().collect::<Vec<_>>();
        let intent_root = id_root("PAYMENT-BATCH-INTENT-IDS", &request.intent_ids);
        let corridor_root = id_root("PAYMENT-BATCH-CORRIDOR-IDS", &request.corridor_ids);
        let netting_leg_root = merkle_root(
            "PAYMENT-BATCH-NETTING-LEGS",
            &netting_legs
                .iter()
                .map(NettingLeg::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_id = batch_id(
            &request.operator_commitment,
            &intent_root,
            &corridor_root,
            &request.netting_proof_root,
            request.batch_height,
            request.nonce,
        );
        let batch = PaymentNettingBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Netted,
            operator_commitment: request.operator_commitment.clone(),
            solver_commitment: request.solver_commitment,
            corridor_ids: request.corridor_ids,
            intent_ids: request.intent_ids.clone(),
            netting_legs,
            liquidity_hint_root: request.liquidity_hint_root,
            intent_root,
            corridor_root,
            netting_leg_root,
            netting_proof_root: request.netting_proof_root,
            gross_fee_micro_units: gross_fee,
            net_fee_micro_units: net_fee,
            rebate_micro_units: rebate,
            privacy_set_size: self
                .config
                .target_privacy_set_size
                .max(batchable.len() as u64),
            batch_height: request.batch_height,
            expires_at_height: request
                .batch_height
                .saturating_add(self.config.batch_ttl_blocks),
            channel_settlement_root: None,
            receipt_root: None,
            nonce: request.nonce,
        };
        for intent_id in batchable {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Netted;
                intent.batch_id = Some(batch_id.clone());
                let intent_rebate =
                    proportional_amount(intent.gross_fee_micro_units, self.config.rebate_bps);
                intent.rebate_micro_units = intent_rebate;
                intent.net_fee_micro_units =
                    intent.gross_fee_micro_units.saturating_sub(intent_rebate);
            }
        }
        for corridor_id in &batch.corridor_ids {
            if let Some(corridor) = self.corridors.get_mut(corridor_id) {
                corridor.status = CorridorStatus::Active;
                corridor.latest_batch_id = Some(batch_id.clone());
            }
        }
        self.batches.insert(batch_id.clone(), batch.clone());
        self.counters.batches_created = self.counters.batches_created.saturating_add(1);
        self.counters.intents_netted = self
            .counters
            .intents_netted
            .saturating_add(batch.intent_ids.len() as u64);
        self.counters.total_net_fee_micro_units = self
            .counters
            .total_net_fee_micro_units
            .saturating_add(net_fee);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(rebate);
        self.record_privacy_event(
            request.operator_commitment,
            PrivacyEventKind::BatchNet,
            batch.privacy_set_size,
            empty_root("PAYMENT-BATCH-DECOYS"),
            batch.root(),
            batch.batch_height,
        );
        Ok(batch)
    }

    pub fn produce_fast_private_receipts(
        &mut self,
        batch_id: &str,
        produced_at_height: u64,
    ) -> Result<Vec<FastPrivateReceipt>> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "unknown payment netting batch".to_string())?
            .clone();
        if !matches!(batch.status, BatchStatus::Netted | BatchStatus::Receipting) {
            return Err("payment netting batch is not ready for receipts".to_string());
        }
        if self.receipts.len().saturating_add(batch.intent_ids.len()) > self.config.max_receipts {
            return Err("receipt registry capacity exceeded".to_string());
        }
        let mut receipts = Vec::with_capacity(batch.intent_ids.len());
        for intent_id in &batch.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("missing payment intent {intent_id}"))?
                .clone();
            let receipt_id = receipt_id(
                intent_id,
                batch_id,
                &intent.payee_note_commitment,
                produced_at_height,
            );
            let encrypted_receipt_hash = domain_hash(
                "FAST-PAYMENT-RECEIPT-CIPHERTEXT",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&receipt_id),
                    HashPart::Str(&intent.encrypted_payload_hash),
                    HashPart::Int(intent.amount_bucket as i128),
                ],
                32,
            );
            let receipt = FastPrivateReceipt {
                receipt_id: receipt_id.clone(),
                intent_id: intent_id.clone(),
                batch_id: batch_id.to_string(),
                corridor_id: intent.corridor_id.clone(),
                status: ReceiptStatus::FastAccepted,
                asset_id: intent.asset_id.clone(),
                amount_bucket: intent.amount_bucket,
                fee_micro_units: intent.net_fee_micro_units,
                encrypted_receipt_hash,
                recipient_view_tag_root: payload_root(
                    "FAST-PAYMENT-RECEIPT-VIEW-TAG",
                    &json!({"payee_note_commitment": intent.payee_note_commitment}),
                ),
                proof_public_input_root: intent.proof_public_input_root.clone(),
                receipt_signature_root: domain_hash(
                    "FAST-PAYMENT-RECEIPT-SIGNATURE-ROOT",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(&receipt_id),
                        HashPart::Str(&batch.operator_commitment),
                        HashPart::Str(FAST_RECEIPT_SCHEME),
                    ],
                    32,
                ),
                produced_at_height,
                finalizes_at_height: produced_at_height
                    .saturating_add(self.config.receipt_finality_blocks),
            };
            self.receipts.insert(receipt_id.clone(), receipt.clone());
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::ReceiptReady;
                intent.receipt_id = Some(receipt_id);
            }
            receipts.push(receipt);
        }
        let receipt_root = merkle_root(
            "PAYMENT-BATCH-FAST-RECEIPTS",
            &receipts
                .iter()
                .map(FastPrivateReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Receipting;
            batch.receipt_root = Some(receipt_root);
        }
        self.counters.receipts_produced = self
            .counters
            .receipts_produced
            .saturating_add(receipts.len() as u64);
        self.record_privacy_event(
            batch.operator_commitment,
            PrivacyEventKind::ReceiptProduce,
            self.config.target_privacy_set_size,
            empty_root("FAST-RECEIPT-DECOYS"),
            id_root(
                "FAST-RECEIPT-IDS",
                &receipts
                    .iter()
                    .map(|r| r.receipt_id.clone())
                    .collect::<Vec<_>>(),
            ),
            produced_at_height,
        );
        Ok(receipts)
    }

    pub fn settle_channel_batch_roots(
        &mut self,
        request: SettleBatchRootRequest,
    ) -> Result<ChannelSettlement> {
        let pre_state_root = self.state_root();
        let batch_snapshot = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown payment netting batch".to_string())?
            .clone();
        if !batch_snapshot.status.can_settle() {
            return Err("payment batch cannot settle channel roots".to_string());
        }
        let settlement_id = settlement_id(
            &request.batch_id,
            &request.channel_settlement_root,
            &request.settlement_proof_root,
            request.settled_at_height,
        );
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Settled;
            batch.channel_settlement_root = Some(request.channel_settlement_root.clone());
        }
        let reservation_consumptions = batch_snapshot
            .intent_ids
            .iter()
            .filter_map(|intent_id| {
                self.intents.get(intent_id).and_then(|intent| {
                    intent.reservation_id.clone().map(|reservation_id| {
                        (
                            intent_id.clone(),
                            reservation_id,
                            intent.net_fee_micro_units,
                        )
                    })
                })
            })
            .collect::<Vec<_>>();
        for (intent_id, _, _) in &reservation_consumptions {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
            }
        }
        for (_, reservation_id, fee_micro_units) in reservation_consumptions {
            self.consume_reservation(&reservation_id, fee_micro_units)?;
        }
        for corridor_id in &batch_snapshot.corridor_ids {
            if let Some(corridor) = self.corridors.get_mut(corridor_id) {
                corridor.status = CorridorStatus::Settling;
                corridor.latest_channel_root = request.channel_settlement_root.clone();
            }
        }
        let post_state_root = self.state_root_without_settlement(&settlement_id);
        let settlement = ChannelSettlement {
            settlement_id: settlement_id.clone(),
            batch_id: request.batch_id.clone(),
            channel_settlement_root: request.channel_settlement_root,
            availability_root: request.availability_root,
            settlement_proof_root: request.settlement_proof_root,
            pre_state_root,
            post_state_root,
            settled_at_height: request.settled_at_height,
        };
        self.settlements
            .insert(settlement_id.clone(), settlement.clone());
        self.counters.channel_settlements = self.counters.channel_settlements.saturating_add(1);
        self.record_privacy_event(
            request.batch_id,
            PrivacyEventKind::ChannelSettle,
            self.config.target_privacy_set_size,
            empty_root("CHANNEL-SETTLEMENT-DECOYS"),
            settlement.root(),
            request.settled_at_height,
        );
        Ok(settlement)
    }

    pub fn accrue_rebate(
        &mut self,
        sponsor_id: &str,
        batch_id: &str,
        proof_root: String,
        accrued_at_height: u64,
    ) -> Result<FeeRebate> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "unknown payment netting batch".to_string())?;
        let sponsored_intents = batch
            .intent_ids
            .iter()
            .filter(|intent_id| {
                self.intents
                    .get(*intent_id)
                    .and_then(|intent| intent.sponsor_id.as_deref())
                    == Some(sponsor_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        if sponsored_intents.is_empty() {
            return Err("batch has no intents sponsored by requested sponsor".to_string());
        }
        let gross_fee = sponsored_intents
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .map(|intent| intent.gross_fee_micro_units)
            .sum::<u64>();
        let rebate_amount = proportional_amount(gross_fee, self.config.rebate_bps);
        let rebate_id = rebate_id(sponsor_id, batch_id, &proof_root, accrued_at_height);
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "unknown sponsor".to_string())?;
        sponsor.rebated_micro_units = sponsor.rebated_micro_units.saturating_add(rebate_amount);
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            sponsor_id: sponsor_id.to_string(),
            batch_id: batch_id.to_string(),
            intent_ids: sponsored_intents,
            status: RebateStatus::Claimable,
            gross_fee_micro_units: gross_fee,
            rebate_micro_units: rebate_amount,
            proof_root,
            accrued_at_height,
            claimed_at_height: None,
        };
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.counters.rebates_accrued = self.counters.rebates_accrued.saturating_add(1);
        self.record_privacy_event(
            sponsor_id.to_string(),
            PrivacyEventKind::Rebate,
            self.config.min_privacy_set_size,
            empty_root("REBATE-DECOYS"),
            rebate.root(),
            accrued_at_height,
        );
        Ok(rebate)
    }

    pub fn claim_rebate(&mut self, rebate_id: &str, claimed_at_height: u64) -> Result<FeeRebate> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "unknown fee rebate".to_string())?;
        if rebate.status != RebateStatus::Claimable {
            return Err("fee rebate is not claimable".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        rebate.claimed_at_height = Some(claimed_at_height);
        self.counters.rebates_claimed = self.counters.rebates_claimed.saturating_add(1);
        Ok(rebate.clone())
    }

    pub fn open_slashing_case(
        &mut self,
        offender_id: String,
        related_batch_id: Option<String>,
        related_intent_id: Option<String>,
        evidence_root: String,
        reporter_commitment: String,
        opened_at_height: u64,
    ) -> Result<SlashingCase> {
        let base = self
            .sponsors
            .get(&offender_id)
            .map(|sponsor| sponsor.capacity_micro_units)
            .unwrap_or_else(|| {
                related_intent_id
                    .as_ref()
                    .and_then(|intent_id| self.intents.get(intent_id))
                    .map(|intent| intent.gross_fee_micro_units)
                    .unwrap_or(self.config.base_fee_micro_units)
            });
        let slash_micro_units = proportional_amount(base, self.config.slash_bps).max(1);
        let case_id = slashing_case_id(
            &offender_id,
            related_batch_id.as_deref(),
            related_intent_id.as_deref(),
            &evidence_root,
            opened_at_height,
        );
        let case = SlashingCase {
            case_id: case_id.clone(),
            offender_id,
            related_batch_id,
            related_intent_id,
            status: SlashingStatus::Open,
            evidence_root,
            slash_micro_units,
            reporter_commitment: reporter_commitment.clone(),
            opened_at_height,
            executed_at_height: None,
        };
        self.slashing_cases.insert(case_id.clone(), case.clone());
        self.counters.slashing_cases = self.counters.slashing_cases.saturating_add(1);
        self.record_privacy_event(
            reporter_commitment,
            PrivacyEventKind::Slash,
            self.config.min_privacy_set_size,
            empty_root("SLASHING-DECOYS"),
            case.root(),
            opened_at_height,
        );
        Ok(case)
    }

    pub fn execute_slashing_case(
        &mut self,
        case_id: &str,
        executed_at_height: u64,
    ) -> Result<SlashingCase> {
        let case = self
            .slashing_cases
            .get_mut(case_id)
            .ok_or_else(|| "unknown slashing case".to_string())?;
        if !matches!(case.status, SlashingStatus::Open | SlashingStatus::Accepted) {
            return Err("slashing case cannot be executed".to_string());
        }
        if let Some(sponsor) = self.sponsors.get_mut(&case.offender_id) {
            let slash = case.slash_micro_units.min(sponsor.available_micro_units());
            sponsor.slashed_micro_units = sponsor.slashed_micro_units.saturating_add(slash);
            sponsor.status = SponsorStatus::Slashed;
            case.slash_micro_units = slash;
        }
        if let Some(intent_id) = case.related_intent_id.clone() {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Slashed;
            }
        }
        if let Some(batch_id) = case.related_batch_id.clone() {
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.status = BatchStatus::Disputed;
            }
        }
        case.status = SlashingStatus::Executed;
        case.executed_at_height = Some(executed_at_height);
        self.counters.slashing_executions = self.counters.slashing_executions.saturating_add(1);
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(case.slash_micro_units);
        Ok(case.clone())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            corridor_root: map_root(
                "PAYMENT-CORRIDORS",
                self.corridors.values().map(PaymentCorridor::public_record),
            ),
            intent_root: map_root(
                "PAYMENT-INTENTS",
                self.intents
                    .values()
                    .map(SealedPaymentIntent::public_record),
            ),
            batch_root: map_root(
                "PAYMENT-BATCHES",
                self.batches
                    .values()
                    .map(PaymentNettingBatch::public_record),
            ),
            sponsor_root: map_root(
                "PAYMENT-SPONSORS",
                self.sponsors.values().map(SponsorAccount::public_record),
            ),
            reservation_root: map_root(
                "PAYMENT-SPONSOR-RESERVATIONS",
                self.reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            receipt_root: map_root(
                "PAYMENT-FAST-RECEIPTS",
                self.receipts
                    .values()
                    .map(FastPrivateReceipt::public_record),
            ),
            settlement_root: map_root(
                "PAYMENT-CHANNEL-SETTLEMENTS",
                self.settlements
                    .values()
                    .map(ChannelSettlement::public_record),
            ),
            privacy_budget_root: map_root(
                "PAYMENT-PRIVACY-BUDGET",
                self.privacy_budget
                    .values()
                    .map(PrivacyBudgetEntry::public_record),
            ),
            rebate_root: map_root(
                "PAYMENT-FEE-REBATES",
                self.rebates.values().map(FeeRebate::public_record),
            ),
            slashing_root: map_root(
                "PAYMENT-SLASHING-CASES",
                self.slashing_cases
                    .values()
                    .map(SlashingCase::public_record),
            ),
            nullifier_root: id_root(
                "PAYMENT-NULLIFIERS",
                &self.nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            counters_root: self.counters.root(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_root();
        with_root_field(
            record,
            "private_payment_intent_netting_state_root",
            self.state_root(),
        )
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    fn consume_reservation(&mut self, reservation_id: &str, fee_micro_units: u64) -> Result<()> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "unknown sponsor reservation".to_string())?;
        if reservation.status != ReservationStatus::Held {
            return Ok(());
        }
        let consumed = fee_micro_units.min(reservation.reserved_micro_units);
        reservation.consumed_micro_units = consumed;
        reservation.status = ReservationStatus::Consumed;
        if let Some(sponsor) = self.sponsors.get_mut(&reservation.sponsor_id) {
            sponsor.reserved_micro_units = sponsor.reserved_micro_units.saturating_sub(consumed);
            sponsor.consumed_micro_units = sponsor.consumed_micro_units.saturating_add(consumed);
            if sponsor.available_micro_units() == 0 {
                sponsor.status = SponsorStatus::Exhausted;
            }
        }
        Ok(())
    }

    fn record_privacy_event(
        &mut self,
        subject_commitment: String,
        event_kind: PrivacyEventKind,
        privacy_set_size: u64,
        decoy_set_root: String,
        event_root: String,
        recorded_at_height: u64,
    ) {
        let privacy_epoch = if self.config.privacy_epoch_blocks == 0 {
            0
        } else {
            recorded_at_height / self.config.privacy_epoch_blocks
        };
        let privacy_cost_units = privacy_cost_units(
            privacy_set_size,
            self.config.target_privacy_set_size,
            self.config.min_decoy_set_size,
        );
        let budget_id = privacy_budget_id(
            &subject_commitment,
            event_kind,
            privacy_epoch,
            &event_root,
            recorded_at_height,
        );
        let entry = PrivacyBudgetEntry {
            budget_id: budget_id.clone(),
            subject_commitment,
            event_kind,
            privacy_epoch,
            privacy_cost_units,
            privacy_set_size,
            decoy_set_root,
            event_root,
            recorded_at_height,
        };
        self.privacy_budget.insert(budget_id, entry);
        self.counters.privacy_events = self.counters.privacy_events.saturating_add(1);
    }

    fn state_root_without_settlement(&self, pending_settlement_id: &str) -> String {
        domain_hash(
            "PRIVATE-PAYMENT-INTENT-NETTING-STATE-PENDING-SETTLEMENT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(pending_settlement_id),
                HashPart::Json(&self.public_record_without_root()),
            ],
            32,
        )
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn id_root(domain: &str, ids: &[String]) -> String {
    merkle_root(
        domain,
        &ids.iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &records.into_iter().collect::<Vec<_>>())
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-PAYMENT-INTENT-NETTING-STATE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(ref mut object) = record {
        object.insert(field.to_string(), Value::String(root));
    }
    record
}

pub fn corridor_id(
    payer_commitment: &str,
    payee_commitment: &str,
    corridor_kind: CorridorKind,
    asset_id: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-PAYMENT-CORRIDOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(payer_commitment),
            HashPart::Str(payee_commitment),
            HashPart::Str(corridor_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_id(
    corridor_id: &str,
    nullifier_hash: &str,
    encrypted_payload_hash: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "SEALED-PAYMENT-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(corridor_id),
            HashPart::Str(nullifier_hash),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn sponsor_id(
    sponsor_commitment: &str,
    fee_asset_id: &str,
    capacity_micro_units: u64,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PAYMENT-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(capacity_micro_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn reservation_id(
    sponsor_id: &str,
    intent_id: &str,
    reserved_micro_units: u64,
    reserved_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PAYMENT-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(intent_id),
            HashPart::Int(reserved_micro_units as i128),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn batch_id(
    operator_commitment: &str,
    intent_root: &str,
    corridor_root: &str,
    netting_proof_root: &str,
    batch_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-PAYMENT-NETTING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(intent_root),
            HashPart::Str(corridor_root),
            HashPart::Str(netting_proof_root),
            HashPart::Int(batch_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn receipt_id(
    intent_id: &str,
    batch_id: &str,
    payee_note_commitment: &str,
    produced_at_height: u64,
) -> String {
    domain_hash(
        "FAST-PRIVATE-PAYMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(batch_id),
            HashPart::Str(payee_note_commitment),
            HashPart::Int(produced_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_id(
    batch_id: &str,
    channel_settlement_root: &str,
    settlement_proof_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PAYMENT-CHANNEL-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(channel_settlement_root),
            HashPart::Str(settlement_proof_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn privacy_budget_id(
    subject_commitment: &str,
    event_kind: PrivacyEventKind,
    privacy_epoch: u64,
    event_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PAYMENT-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(event_kind.as_str()),
            HashPart::Int(privacy_epoch as i128),
            HashPart::Str(event_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(
    sponsor_id: &str,
    batch_id: &str,
    proof_root: &str,
    accrued_at_height: u64,
) -> String {
    domain_hash(
        "PAYMENT-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(batch_id),
            HashPart::Str(proof_root),
            HashPart::Int(accrued_at_height as i128),
        ],
        32,
    )
}

pub fn slashing_case_id(
    offender_id: &str,
    related_batch_id: Option<&str>,
    related_intent_id: Option<&str>,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PAYMENT-SLASHING-CASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(offender_id),
            HashPart::Str(related_batch_id.unwrap_or("")),
            HashPart::Str(related_intent_id.unwrap_or("")),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn fee_for_amount(amount_bucket: u64, fee_bps: u64, base_fee_micro_units: u64) -> u64 {
    base_fee_micro_units.saturating_add(proportional_amount(amount_bucket, fee_bps))
}

pub fn proportional_amount(amount: u64, bps: u64) -> u64 {
    ((amount as u128).saturating_mul(bps as u128) / MAX_BPS as u128).min(u64::MAX as u128) as u64
}

pub fn privacy_cost_units(
    privacy_set_size: u64,
    target_privacy_set_size: u64,
    min_decoy_set_size: u64,
) -> u64 {
    if privacy_set_size >= target_privacy_set_size {
        1
    } else {
        let shortfall = target_privacy_set_size.saturating_sub(privacy_set_size);
        1_u64
            .saturating_add(shortfall / min_decoy_set_size.max(1))
            .max(1)
    }
}
