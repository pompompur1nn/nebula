use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

macro_rules! ensure {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateIntentBatchAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-private-intent-batch-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_HEIGHT:
    u64 = 742_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_L2_NETWORK:
    &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_CONTRACT_BOOK:
    &str = "devnet-pq-confidential-contract-private-intent-book";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_FEE_ASSET_ID:
    &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_REBATE_POOL:
    &str = "devnet-private-intent-netting-rebate-pool";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_HASH_SUITE:
    &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_INTENT_SCHEME:
    &str = "ml-kem-1024-encrypted-confidential-contract-intent-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_BID_SCHEME:
    &str = "ml-kem-1024-sealed-private-intent-auction-bid-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_CLEARING_SCHEME:
    &str = "zk-pq-private-intent-batch-clearing-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_PQ_ATTESTATION_SCHEME:
    &str = "ml-dsa-87+slh-dsa-shake-192f-private-contract-execution-attestation-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SETTLEMENT_SCHEME:
    &str = "confidential-contract-private-intent-settlement-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_REBATE_SCHEME:
    &str = "low-fee-netting-rebate-receipt-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DISCLOSURE_SCHEME:
    &str = "selective-disclosure-view-key-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SUMMARY_SCHEME:
    &str = "redacted-operator-summary-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_REPLAY_DOMAIN:
    &str = "private-l2-pq-confidential-contract-private-intent-batch-auction-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_TARGET_BATCH_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_MEV_DELAY_BLOCKS: u64 = 4;
pub const DEFAULT_NETTING_REBATE_BPS: u64 = 700;
pub const DEFAULT_OPERATOR_REDACTION_BUDGET: u64 = 1_000_000;
pub const DEFAULT_MIN_CLEARING_FILL_BPS: u64 = 8_500;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 1_024;
pub const MAX_INTENT_BOOKS: usize = 65_536;
pub const MAX_ENCRYPTED_INTENTS: usize = 1_048_576;
pub const MAX_ENCRYPTED_BIDS: usize = 1_048_576;
pub const MAX_CLEARING_BATCHES: usize = 262_144;
pub const MAX_PQ_ATTESTATIONS: usize = 1_048_576;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_DISCLOSURES: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_REPLAY_FENCES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Swap,
    Transfer,
    Mint,
    Burn,
    DefiCall,
    ContractCall,
    LiquidationProtect,
    EmergencyCancel,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Transfer => "transfer",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::DefiCall => "defi_call",
            Self::ContractCall => "contract_call",
            Self::LiquidationProtect => "liquidation_protect",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::LiquidationProtect => 9_400,
            Self::Burn => 8_700,
            Self::Swap => 8_200,
            Self::DefiCall => 7_900,
            Self::ContractCall => 7_600,
            Self::Transfer => 7_100,
            Self::Mint => 6_800,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLane {
    DarkPool,
    LowFeeNetting,
    FastConfidential,
    SolverOnly,
    AuditorView,
    Emergency,
}

impl PrivacyLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DarkPool => "dark_pool",
            Self::LowFeeNetting => "low_fee_netting",
            Self::FastConfidential => "fast_confidential",
            Self::SolverOnly => "solver_only",
            Self::AuditorView => "auditor_view",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFeeNetting => config.low_fee_bps,
            Self::DarkPool | Self::AuditorView => config.max_user_fee_bps / 2,
            Self::SolverOnly => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::FastConfidential | Self::Emergency => config.max_user_fee_bps,
        }
    }

    pub fn rebate_eligible(self) -> bool {
        matches!(self, Self::LowFeeNetting | Self::DarkPool)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Prioritized,
    BidMatched,
    Clearing,
    Attested,
    Settled,
    Disclosed,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Prioritized => "prioritized",
            Self::BidMatched => "bid_matched",
            Self::Clearing => "clearing",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Disclosed => "disclosed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Prioritized
                | Self::BidMatched
                | Self::Clearing
                | Self::Attested
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Eligible,
    Selected,
    Cleared,
    Settled,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Cleared => "cleared",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingStatus {
    Open,
    Sealed,
    MevDelayed,
    Attesting,
    Cleared,
    Settling,
    Settled,
    Rejected,
    Expired,
}

impl ClearingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::MevDelayed => "mev_delayed",
            Self::Attesting => "attesting",
            Self::Cleared => "cleared",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    Accepted,
    Disputed,
    Finalized,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn acceptable(self) -> bool {
        matches!(self, Self::Posted | Self::Accepted | Self::Finalized)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub contract_book: String,
    pub fee_asset_id: String,
    pub rebate_pool: String,
    pub hash_suite: String,
    pub intent_scheme: String,
    pub bid_scheme: String,
    pub clearing_scheme: String,
    pub pq_attestation_scheme: String,
    pub settlement_scheme: String,
    pub rebate_scheme: String,
    pub disclosure_scheme: String,
    pub summary_scheme: String,
    pub replay_domain: String,
    pub intent_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub mev_delay_blocks: u64,
    pub netting_rebate_bps: u64,
    pub operator_redaction_budget: u64,
    pub min_clearing_fill_bps: u64,
    pub max_batch_items: usize,
    pub max_intent_books: usize,
    pub max_encrypted_intents: usize,
    pub max_encrypted_bids: usize,
    pub max_clearing_batches: usize,
    pub max_pq_attestations: usize,
    pub max_settlements: usize,
    pub max_rebates: usize,
    pub max_disclosures: usize,
    pub max_operator_summaries: usize,
    pub max_replay_fences: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SCHEMA_VERSION,
            l2_network: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            contract_book: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_CONTRACT_BOOK.to_string(),
            fee_asset_id: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(),
            rebate_pool: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_REBATE_POOL.to_string(),
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_HASH_SUITE.to_string(),
            intent_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_INTENT_SCHEME.to_string(),
            bid_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_BID_SCHEME.to_string(),
            clearing_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_CLEARING_SCHEME.to_string(),
            pq_attestation_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_PQ_ATTESTATION_SCHEME.to_string(),
            settlement_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SETTLEMENT_SCHEME.to_string(),
            rebate_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_REBATE_SCHEME.to_string(),
            disclosure_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DISCLOSURE_SCHEME.to_string(),
            summary_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SUMMARY_SCHEME.to_string(),
            replay_domain: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_REPLAY_DOMAIN.to_string(),
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_batch_privacy_set_size: DEFAULT_TARGET_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            mev_delay_blocks: DEFAULT_MEV_DELAY_BLOCKS,
            netting_rebate_bps: DEFAULT_NETTING_REBATE_BPS,
            operator_redaction_budget: DEFAULT_OPERATOR_REDACTION_BUDGET,
            min_clearing_fill_bps: DEFAULT_MIN_CLEARING_FILL_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_intent_books: MAX_INTENT_BOOKS,
            max_encrypted_intents: MAX_ENCRYPTED_INTENTS,
            max_encrypted_bids: MAX_ENCRYPTED_BIDS,
            max_clearing_batches: MAX_CLEARING_BATCHES,
            max_pq_attestations: MAX_PQ_ATTESTATIONS,
            max_settlements: MAX_SETTLEMENTS,
            max_rebates: MAX_REBATES,
            max_disclosures: MAX_DISCLOSURES,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
            max_replay_fences: MAX_REPLAY_FENCES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "contract_book": self.contract_book,
            "fee_asset_id": self.fee_asset_id,
            "rebate_pool": self.rebate_pool,
            "hash_suite": self.hash_suite,
            "intent_scheme": self.intent_scheme,
            "bid_scheme": self.bid_scheme,
            "clearing_scheme": self.clearing_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "settlement_scheme": self.settlement_scheme,
            "rebate_scheme": self.rebate_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "summary_scheme": self.summary_scheme,
            "replay_domain": self.replay_domain,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_batch_privacy_set_size": self.target_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "mev_delay_blocks": self.mev_delay_blocks,
            "netting_rebate_bps": self.netting_rebate_bps,
            "operator_redaction_budget": self.operator_redaction_budget,
            "min_clearing_fill_bps": self.min_clearing_fill_bps,
            "max_batch_items": self.max_batch_items
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub intent_books: u64,
    pub encrypted_intents: u64,
    pub encrypted_bids: u64,
    pub clearing_batches: u64,
    pub pq_attestations: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub disclosures: u64,
    pub operator_summaries: u64,
    pub replay_fences: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_books": self.intent_books,
            "encrypted_intents": self.encrypted_intents,
            "encrypted_bids": self.encrypted_bids,
            "clearing_batches": self.clearing_batches,
            "pq_attestations": self.pq_attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "disclosures": self.disclosures,
            "operator_summaries": self.operator_summaries,
            "replay_fences": self.replay_fences
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub intent_book_root: String,
    pub encrypted_intent_root: String,
    pub encrypted_bid_root: String,
    pub clearing_batch_root: String,
    pub pq_attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub disclosure_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub replay_fence_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = empty_root("private-intent-batch-auction");
        Self {
            intent_book_root: empty_root("intent-books"),
            encrypted_intent_root: empty_root("encrypted-intents"),
            encrypted_bid_root: empty_root("encrypted-bids"),
            clearing_batch_root: empty_root("clearing-batches"),
            pq_attestation_root: empty_root("pq-attestations"),
            settlement_root: empty_root("settlements"),
            rebate_root: empty_root("rebates"),
            disclosure_root: empty_root("disclosures"),
            redaction_budget_root: empty_root("redaction-budgets"),
            operator_summary_root: empty_root("operator-summaries"),
            replay_fence_root: empty_root("replay-fences"),
            state_root: empty,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_book_root": self.intent_book_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "encrypted_bid_root": self.encrypted_bid_root,
            "clearing_batch_root": self.clearing_batch_root,
            "pq_attestation_root": self.pq_attestation_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "disclosure_root": self.disclosure_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "replay_fence_root": self.replay_fence_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentBook {
    pub book_id: String,
    pub contract_id: String,
    pub lane: PrivacyLane,
    pub asset_pair_commitment: String,
    pub policy_root: String,
    pub solver_registry_root: String,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_enabled: bool,
    pub opened_at_height: u64,
}

impl IntentBook {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "contract_id": self.contract_id,
            "lane": self.lane.as_str(),
            "asset_pair_commitment": self.asset_pair_commitment,
            "policy_root": self.policy_root,
            "solver_registry_root": self.solver_registry_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_enabled": self.low_fee_enabled,
            "opened_at_height": self.opened_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenIntentBookRequest {
    pub contract_id: String,
    pub lane: PrivacyLane,
    pub asset_pair_commitment: String,
    pub policy_root: String,
    pub solver_registry_root: String,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_enabled: bool,
}

impl OpenIntentBookRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "lane": self.lane.as_str(),
            "asset_pair_commitment": self.asset_pair_commitment,
            "policy_root": self.policy_root,
            "solver_registry_root": self.solver_registry_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_enabled": self.low_fee_enabled
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub book_id: String,
    pub kind: IntentKind,
    pub lane: PrivacyLane,
    pub ciphertext_root: String,
    pub intent_commitment: String,
    pub nullifier: String,
    pub fee_commitment: String,
    pub priority_hint: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub status: IntentStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub batch_id: Option<String>,
    pub attestation_id: Option<String>,
    pub settlement_id: Option<String>,
}

impl EncryptedIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "book_id": self.book_id,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "ciphertext_root": self.ciphertext_root,
            "intent_commitment": self.intent_commitment,
            "nullifier": self.nullifier,
            "fee_commitment": self.fee_commitment,
            "priority_hint": self.priority_hint,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "batch_id": self.batch_id,
            "attestation_id": self.attestation_id,
            "settlement_id": self.settlement_id
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedIntentRequest {
    pub book_id: String,
    pub kind: IntentKind,
    pub lane: PrivacyLane,
    pub ciphertext_root: String,
    pub intent_commitment: String,
    pub nullifier: String,
    pub fee_commitment: String,
    pub priority_hint: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl SubmitEncryptedIntentRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "ciphertext_root": self.ciphertext_root,
            "intent_commitment": self.intent_commitment,
            "nullifier": self.nullifier,
            "fee_commitment": self.fee_commitment,
            "priority_hint": self.priority_hint,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBid {
    pub bid_id: String,
    pub book_id: String,
    pub solver_id: String,
    pub sealed_bid_root: String,
    pub price_commitment: String,
    pub inventory_commitment: String,
    pub solver_fee_bps: u64,
    pub pq_key_root: String,
    pub status: BidStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub selected_batch_id: Option<String>,
}

impl EncryptedBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "book_id": self.book_id,
            "solver_id": self.solver_id,
            "sealed_bid_root": self.sealed_bid_root,
            "price_commitment": self.price_commitment,
            "inventory_commitment": self.inventory_commitment,
            "solver_fee_bps": self.solver_fee_bps,
            "pq_key_root": self.pq_key_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "selected_batch_id": self.selected_batch_id
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedBidRequest {
    pub book_id: String,
    pub solver_id: String,
    pub sealed_bid_root: String,
    pub price_commitment: String,
    pub inventory_commitment: String,
    pub solver_fee_bps: u64,
    pub pq_key_root: String,
}

impl SubmitEncryptedBidRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "solver_id": self.solver_id,
            "sealed_bid_root": self.sealed_bid_root,
            "price_commitment": self.price_commitment,
            "inventory_commitment": self.inventory_commitment,
            "solver_fee_bps": self.solver_fee_bps,
            "pq_key_root": self.pq_key_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub book_id: String,
    pub intent_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub clearing_price_root: String,
    pub netting_root: String,
    pub mev_delay_until_height: u64,
    pub fill_bps: u64,
    pub user_fee_bps: u64,
    pub status: ClearingStatus,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub selected_solver_id: Option<String>,
    pub attestation_id: Option<String>,
    pub settlement_id: Option<String>,
}

impl ClearingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "book_id": self.book_id,
            "intent_ids": self.intent_ids,
            "bid_ids": self.bid_ids,
            "clearing_price_root": self.clearing_price_root,
            "netting_root": self.netting_root,
            "mev_delay_until_height": self.mev_delay_until_height,
            "fill_bps": self.fill_bps,
            "user_fee_bps": self.user_fee_bps,
            "status": self.status.as_str(),
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "selected_solver_id": self.selected_solver_id,
            "attestation_id": self.attestation_id,
            "settlement_id": self.settlement_id
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearBatchRequest {
    pub book_id: String,
    pub intent_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub clearing_price_root: String,
    pub netting_root: String,
    pub fill_bps: u64,
    pub selected_solver_id: String,
}

impl ClearBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "intent_ids": self.intent_ids,
            "bid_ids": self.bid_ids,
            "clearing_price_root": self.clearing_price_root,
            "netting_root": self.netting_root,
            "fill_bps": self.fill_bps,
            "selected_solver_id": self.selected_solver_id
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqExecutionAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub prover_id: String,
    pub pq_scheme: String,
    pub transcript_root: String,
    pub execution_trace_root: String,
    pub disclosure_policy_root: String,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqExecutionAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "prover_id": self.prover_id,
            "pq_scheme": self.pq_scheme,
            "transcript_root": self.transcript_root,
            "execution_trace_root": self.execution_trace_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostPqExecutionAttestationRequest {
    pub batch_id: String,
    pub prover_id: String,
    pub transcript_root: String,
    pub execution_trace_root: String,
    pub disclosure_policy_root: String,
    pub pq_security_bits: u16,
}

impl PostPqExecutionAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "prover_id": self.prover_id,
            "transcript_root": self.transcript_root,
            "execution_trace_root": self.execution_trace_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "pq_security_bits": self.pq_security_bits
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub attestation_id: String,
    pub settlement_root: String,
    pub transfer_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub finality_height: u64,
    pub settled_at_height: u64,
}

impl Settlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "attestation_id": self.attestation_id,
            "settlement_root": self.settlement_root,
            "transfer_root": self.transfer_root,
            "fee_root": self.fee_root,
            "rebate_root": self.rebate_root,
            "finality_height": self.finality_height,
            "settled_at_height": self.settled_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub attestation_id: String,
    pub settlement_root: String,
    pub transfer_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub finality_height: u64,
}

impl SettleBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "attestation_id": self.attestation_id,
            "settlement_root": self.settlement_root,
            "transfer_root": self.transfer_root,
            "fee_root": self.fee_root,
            "rebate_root": self.rebate_root,
            "finality_height": self.finality_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub reason: String,
    pub issued_at_height: u64,
}

impl NettingRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "reason": self.reason,
            "issued_at_height": self.issued_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRebateRequest {
    pub settlement_id: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub operator_id: String,
    pub budget_remaining: u64,
    pub summaries_posted: u64,
    pub disclosures_approved: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "budget_remaining": self.budget_remaining,
            "summaries_posted": self.summaries_posted,
            "disclosures_approved": self.disclosures_approved
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosure {
    pub disclosure_id: String,
    pub subject_id: String,
    pub viewer_id: String,
    pub view_key_root: String,
    pub field_mask_root: String,
    pub expires_at_height: u64,
    pub approved_at_height: u64,
}

impl SelectiveDisclosure {
    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "subject_id": self.subject_id,
            "viewer_id": self.viewer_id,
            "view_key_root": self.view_key_root,
            "field_mask_root": self.field_mask_root,
            "expires_at_height": self.expires_at_height,
            "approved_at_height": self.approved_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveDisclosureRequest {
    pub operator_id: String,
    pub subject_id: String,
    pub viewer_id: String,
    pub view_key_root: String,
    pub field_mask_root: String,
    pub budget_cost: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub redacted_activity_root: String,
    pub aggregate_volume_commitment: String,
    pub aggregate_fee_commitment: String,
    pub privacy_set_size: u64,
    pub mev_protection_root: String,
    pub budget_spent: u64,
    pub posted_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "redacted_activity_root": self.redacted_activity_root,
            "aggregate_volume_commitment": self.aggregate_volume_commitment,
            "aggregate_fee_commitment": self.aggregate_fee_commitment,
            "privacy_set_size": self.privacy_set_size,
            "mev_protection_root": self.mev_protection_root,
            "budget_spent": self.budget_spent,
            "posted_at_height": self.posted_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostOperatorSummaryRequest {
    pub operator_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub redacted_activity_root: String,
    pub aggregate_volume_commitment: String,
    pub aggregate_fee_commitment: String,
    pub privacy_set_size: u64,
    pub mev_protection_root: String,
    pub budget_spent: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub intent_books: BTreeMap<String, IntentBook>,
    pub encrypted_intents: BTreeMap<String, EncryptedIntent>,
    pub encrypted_bids: BTreeMap<String, EncryptedBid>,
    pub clearing_batches: BTreeMap<String, ClearingBatch>,
    pub pq_attestations: BTreeMap<String, PqExecutionAttestation>,
    pub settlements: BTreeMap<String, Settlement>,
    pub rebates: BTreeMap<String, NettingRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub disclosures: BTreeMap<String, SelectiveDisclosure>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub replay_fences: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            height: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_DEVNET_HEIGHT,
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            intent_books: BTreeMap::new(),
            encrypted_intents: BTreeMap::new(),
            encrypted_bids: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            replay_fences: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let book_id = state
            .open_intent_book(OpenIntentBookRequest {
                contract_id: "devnet-confidential-swap-contract".to_string(),
                lane: PrivacyLane::LowFeeNetting,
                asset_pair_commitment: devnet_root("asset-pair"),
                policy_root: devnet_root("intent-policy"),
                solver_registry_root: devnet_root("solver-registry"),
                min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_user_fee_bps: DEFAULT_LOW_FEE_BPS,
                low_fee_enabled: true,
            })
            .unwrap_or_else(|_| "devnet-book".to_string());
        let intent_id = state
            .submit_encrypted_intent(SubmitEncryptedIntentRequest {
                book_id: book_id.clone(),
                kind: IntentKind::Swap,
                lane: PrivacyLane::LowFeeNetting,
                ciphertext_root: devnet_root("intent-ciphertext"),
                intent_commitment: devnet_root("intent-commitment"),
                nullifier: devnet_root("intent-nullifier"),
                fee_commitment: devnet_root("intent-fee"),
                priority_hint: 42,
                max_fee_bps: DEFAULT_LOW_FEE_BPS,
                privacy_set_size: DEFAULT_TARGET_BATCH_PRIVACY_SET_SIZE,
            })
            .unwrap_or_else(|_| "devnet-intent".to_string());
        let bid_id = state
            .submit_encrypted_bid(SubmitEncryptedBidRequest {
                book_id: book_id.clone(),
                solver_id: "devnet-solver-0".to_string(),
                sealed_bid_root: devnet_root("sealed-bid"),
                price_commitment: devnet_root("price"),
                inventory_commitment: devnet_root("inventory"),
                solver_fee_bps: DEFAULT_LOW_FEE_BPS,
                pq_key_root: devnet_root("solver-pq-key"),
            })
            .unwrap_or_else(|_| "devnet-bid".to_string());
        let batch_id = state
            .clear_batch(ClearBatchRequest {
                book_id,
                intent_ids: vec![intent_id],
                bid_ids: vec![bid_id],
                clearing_price_root: devnet_root("clearing-price"),
                netting_root: devnet_root("netting"),
                fill_bps: MAX_BPS,
                selected_solver_id: "devnet-solver-0".to_string(),
            })
            .unwrap_or_else(|_| "devnet-batch".to_string());
        state.advance_height(state.height.saturating_add(DEFAULT_MEV_DELAY_BLOCKS));
        let attestation_id = state
            .post_pq_execution_attestation(PostPqExecutionAttestationRequest {
                batch_id: batch_id.clone(),
                prover_id: "devnet-pq-prover".to_string(),
                transcript_root: devnet_root("pq-transcript"),
                execution_trace_root: devnet_root("execution-trace"),
                disclosure_policy_root: devnet_root("disclosure-policy"),
                pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            })
            .unwrap_or_else(|_| "devnet-attestation".to_string());
        let settlement_id = state
            .settle_batch(SettleBatchRequest {
                batch_id,
                attestation_id,
                settlement_root: devnet_root("settlement"),
                transfer_root: devnet_root("transfers"),
                fee_root: devnet_root("fees"),
                rebate_root: devnet_root("settlement-rebates"),
                finality_height: state.height.saturating_add(6),
            })
            .unwrap_or_else(|_| "devnet-settlement".to_string());
        let _ = state.issue_rebate(IssueRebateRequest {
            settlement_id,
            recipient_commitment: devnet_root("rebate-recipient"),
            rebate_commitment: devnet_root("rebate"),
            rebate_bps: DEFAULT_NETTING_REBATE_BPS,
            reason: "low_fee_netting".to_string(),
        });
        let _ = state.post_operator_summary(PostOperatorSummaryRequest {
            operator_id: "devnet-operator".to_string(),
            window_start_height: state.height,
            window_end_height: state.height.saturating_add(12),
            redacted_activity_root: devnet_root("operator-redacted-activity"),
            aggregate_volume_commitment: devnet_root("operator-volume"),
            aggregate_fee_commitment: devnet_root("operator-fee"),
            privacy_set_size: DEFAULT_TARGET_BATCH_PRIVACY_SET_SIZE,
            mev_protection_root: devnet_root("mev-protection"),
            budget_spent: 10,
        });
        state.refresh_roots();
        state
    }

    pub fn open_intent_book(&mut self, request: OpenIntentBookRequest) -> Result<String> {
        ensure_capacity(
            self.intent_books.len(),
            self.config.max_intent_books,
            "intent_book",
        )?;
        required("contract_id", &request.contract_id)?;
        required("asset_pair_commitment", &request.asset_pair_commitment)?;
        required("policy_root", &request.policy_root)?;
        required("solver_registry_root", &request.solver_registry_root)?;
        ensure_bps(request.max_user_fee_bps, "max_user_fee_bps")?;
        ensure!(
            request.min_privacy_set_size >= self.config.min_privacy_set_size,
            "intent book privacy set below minimum"
        );
        let sequence = self.counters.intent_books.saturating_add(1);
        let book_id = deterministic_id("intent_book", &request.public_record(), sequence);
        ensure!(
            !self.intent_books.contains_key(&book_id),
            "intent book exists"
        );
        self.intent_books.insert(
            book_id.clone(),
            IntentBook {
                book_id: book_id.clone(),
                contract_id: request.contract_id,
                lane: request.lane,
                asset_pair_commitment: request.asset_pair_commitment,
                policy_root: request.policy_root,
                solver_registry_root: request.solver_registry_root,
                min_privacy_set_size: request.min_privacy_set_size,
                max_user_fee_bps: request.max_user_fee_bps,
                low_fee_enabled: request.low_fee_enabled,
                opened_at_height: self.height,
            },
        );
        self.counters.intent_books = self.intent_books.len() as u64;
        self.refresh_roots();
        Ok(book_id)
    }

    pub fn submit_encrypted_intent(
        &mut self,
        request: SubmitEncryptedIntentRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.encrypted_intents.len(),
            self.config.max_encrypted_intents,
            "encrypted_intent",
        )?;
        self.intent_books
            .get(&request.book_id)
            .ok_or_else(|| "intent book missing".to_string())?;
        required("ciphertext_root", &request.ciphertext_root)?;
        required("intent_commitment", &request.intent_commitment)?;
        required("nullifier", &request.nullifier)?;
        required("fee_commitment", &request.fee_commitment)?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "intent privacy set below minimum"
        );
        self.insert_replay_fence(&request.nullifier)?;
        let sequence = self.counters.encrypted_intents.saturating_add(1);
        let intent_id = deterministic_id("encrypted_intent", &request.public_record(), sequence);
        let record = EncryptedIntent {
            intent_id: intent_id.clone(),
            book_id: request.book_id,
            kind: request.kind,
            lane: request.lane,
            ciphertext_root: request.ciphertext_root,
            intent_commitment: request.intent_commitment,
            nullifier: request.nullifier,
            fee_commitment: request.fee_commitment,
            priority_hint: request
                .priority_hint
                .saturating_add(request.kind.priority_weight()),
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            status: IntentStatus::Prioritized,
            submitted_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.intent_ttl_blocks),
            batch_id: None,
            attestation_id: None,
            settlement_id: None,
        };
        self.encrypted_intents.insert(intent_id.clone(), record);
        self.counters.encrypted_intents = self.encrypted_intents.len() as u64;
        self.refresh_roots();
        Ok(intent_id)
    }

    pub fn submit_encrypted_bid(&mut self, request: SubmitEncryptedBidRequest) -> Result<String> {
        ensure_capacity(
            self.encrypted_bids.len(),
            self.config.max_encrypted_bids,
            "encrypted_bid",
        )?;
        self.intent_books
            .get(&request.book_id)
            .ok_or_else(|| "intent book missing".to_string())?;
        required("solver_id", &request.solver_id)?;
        required("sealed_bid_root", &request.sealed_bid_root)?;
        required("price_commitment", &request.price_commitment)?;
        required("inventory_commitment", &request.inventory_commitment)?;
        required("pq_key_root", &request.pq_key_root)?;
        ensure_bps(request.solver_fee_bps, "solver_fee_bps")?;
        let sequence = self.counters.encrypted_bids.saturating_add(1);
        let bid_id = deterministic_id("encrypted_bid", &request.public_record(), sequence);
        self.encrypted_bids.insert(
            bid_id.clone(),
            EncryptedBid {
                bid_id: bid_id.clone(),
                book_id: request.book_id,
                solver_id: request.solver_id,
                sealed_bid_root: request.sealed_bid_root,
                price_commitment: request.price_commitment,
                inventory_commitment: request.inventory_commitment,
                solver_fee_bps: request.solver_fee_bps,
                pq_key_root: request.pq_key_root,
                status: BidStatus::Eligible,
                submitted_at_height: self.height,
                expires_at_height: self.height.saturating_add(self.config.bid_ttl_blocks),
                selected_batch_id: None,
            },
        );
        self.counters.encrypted_bids = self.encrypted_bids.len() as u64;
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn clear_batch(&mut self, request: ClearBatchRequest) -> Result<String> {
        ensure_capacity(
            self.clearing_batches.len(),
            self.config.max_clearing_batches,
            "clearing_batch",
        )?;
        let user_fee_bps = self
            .intent_books
            .get(&request.book_id)
            .ok_or_else(|| "intent book missing".to_string())?
            .lane
            .fee_bps(&self.config);
        required("clearing_price_root", &request.clearing_price_root)?;
        required("netting_root", &request.netting_root)?;
        required("selected_solver_id", &request.selected_solver_id)?;
        ensure!(!request.intent_ids.is_empty(), "batch has no intents");
        ensure!(!request.bid_ids.is_empty(), "batch has no bids");
        ensure!(
            request.intent_ids.len() <= self.config.max_batch_items,
            "too many batch intents"
        );
        ensure!(
            request.fill_bps >= self.config.min_clearing_fill_bps && request.fill_bps <= MAX_BPS,
            "clearing fill outside policy"
        );
        for intent_id in &request.intent_ids {
            let intent = self
                .encrypted_intents
                .get(intent_id)
                .ok_or_else(|| "batch intent missing".to_string())?;
            ensure!(
                intent.book_id == request.book_id,
                "batch intent book mismatch"
            );
            ensure!(intent.status.live(), "batch intent is not live");
        }
        for bid_id in &request.bid_ids {
            let bid = self
                .encrypted_bids
                .get(bid_id)
                .ok_or_else(|| "batch bid missing".to_string())?;
            ensure!(bid.book_id == request.book_id, "batch bid book mismatch");
            ensure!(
                bid.status == BidStatus::Eligible,
                "batch bid is not eligible"
            );
        }
        let sequence = self.counters.clearing_batches.saturating_add(1);
        let batch_id = deterministic_id("clearing_batch", &request.public_record(), sequence);
        for intent_id in &request.intent_ids {
            let intent = self
                .encrypted_intents
                .get_mut(intent_id)
                .ok_or_else(|| "batch intent missing".to_string())?;
            intent.status = IntentStatus::Clearing;
            intent.batch_id = Some(batch_id.clone());
        }
        for bid_id in &request.bid_ids {
            let bid = self
                .encrypted_bids
                .get_mut(bid_id)
                .ok_or_else(|| "batch bid missing".to_string())?;
            bid.status = BidStatus::Selected;
            bid.selected_batch_id = Some(batch_id.clone());
        }
        self.clearing_batches.insert(
            batch_id.clone(),
            ClearingBatch {
                batch_id: batch_id.clone(),
                book_id: request.book_id,
                intent_ids: request.intent_ids,
                bid_ids: request.bid_ids,
                clearing_price_root: request.clearing_price_root,
                netting_root: request.netting_root,
                mev_delay_until_height: self.height.saturating_add(self.config.mev_delay_blocks),
                fill_bps: request.fill_bps,
                user_fee_bps,
                status: ClearingStatus::MevDelayed,
                sealed_at_height: self.height,
                expires_at_height: self.height.saturating_add(self.config.clearing_ttl_blocks),
                selected_solver_id: Some(request.selected_solver_id),
                attestation_id: None,
                settlement_id: None,
            },
        );
        self.counters.clearing_batches = self.clearing_batches.len() as u64;
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn post_pq_execution_attestation(
        &mut self,
        request: PostPqExecutionAttestationRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_pq_attestations,
            "pq_attestation",
        )?;
        required("prover_id", &request.prover_id)?;
        required("transcript_root", &request.transcript_root)?;
        required("execution_trace_root", &request.execution_trace_root)?;
        required("disclosure_policy_root", &request.disclosure_policy_root)?;
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ security below minimum"
        );
        let batch = self
            .clearing_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "clearing batch missing".to_string())?;
        ensure!(
            self.height >= batch.mev_delay_until_height,
            "MEV delay still active"
        );
        ensure!(
            matches!(
                batch.status,
                ClearingStatus::MevDelayed | ClearingStatus::Sealed | ClearingStatus::Attesting
            ),
            "batch not attestable"
        );
        let sequence = self.counters.pq_attestations.saturating_add(1);
        let attestation_id = deterministic_id(
            "pq_execution_attestation",
            &request.public_record(),
            sequence,
        );
        batch.status = ClearingStatus::Cleared;
        batch.attestation_id = Some(attestation_id.clone());
        self.pq_attestations.insert(
            attestation_id.clone(),
            PqExecutionAttestation {
                attestation_id: attestation_id.clone(),
                batch_id: request.batch_id.clone(),
                prover_id: request.prover_id,
                pq_scheme: self.config.pq_attestation_scheme.clone(),
                transcript_root: request.transcript_root,
                execution_trace_root: request.execution_trace_root,
                disclosure_policy_root: request.disclosure_policy_root,
                pq_security_bits: request.pq_security_bits,
                status: AttestationStatus::Accepted,
                posted_at_height: self.height,
                expires_at_height: self
                    .height
                    .saturating_add(self.config.attestation_ttl_blocks),
            },
        );
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.encrypted_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Attested;
                intent.attestation_id = Some(attestation_id.clone());
            }
        }
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<String> {
        ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlement",
        )?;
        required("settlement_root", &request.settlement_root)?;
        required("transfer_root", &request.transfer_root)?;
        required("fee_root", &request.fee_root)?;
        required("rebate_root", &request.rebate_root)?;
        let attestation = self
            .pq_attestations
            .get(&request.attestation_id)
            .ok_or_else(|| "PQ attestation missing".to_string())?;
        ensure!(
            attestation.acceptable_status(),
            "PQ attestation unacceptable"
        );
        ensure!(
            attestation.batch_id == request.batch_id,
            "attestation batch mismatch"
        );
        let batch = self
            .clearing_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "clearing batch missing".to_string())?;
        ensure!(
            batch.attestation_id.as_deref() == Some(&request.attestation_id),
            "batch attestation mismatch"
        );
        let sequence = self.counters.settlements.saturating_add(1);
        let settlement_id = deterministic_id("settlement", &request.public_record(), sequence);
        batch.status = ClearingStatus::Settled;
        batch.settlement_id = Some(settlement_id.clone());
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.encrypted_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                intent.settlement_id = Some(settlement_id.clone());
            }
        }
        for bid_id in &batch.bid_ids {
            if let Some(bid) = self.encrypted_bids.get_mut(bid_id) {
                bid.status = BidStatus::Settled;
            }
        }
        self.settlements.insert(
            settlement_id.clone(),
            Settlement {
                settlement_id: settlement_id.clone(),
                batch_id: request.batch_id,
                attestation_id: request.attestation_id,
                settlement_root: request.settlement_root,
                transfer_root: request.transfer_root,
                fee_root: request.fee_root,
                rebate_root: request.rebate_root,
                finality_height: request.finality_height,
                settled_at_height: self.height,
            },
        );
        self.counters.settlements = self.settlements.len() as u64;
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<String> {
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebate")?;
        self.settlements
            .get(&request.settlement_id)
            .ok_or_else(|| "settlement missing".to_string())?;
        required("recipient_commitment", &request.recipient_commitment)?;
        required("rebate_commitment", &request.rebate_commitment)?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        ensure!(
            request.rebate_bps <= self.config.netting_rebate_bps,
            "rebate exceeds netting policy"
        );
        let payload = json!({
            "settlement_id": request.settlement_id,
            "recipient_commitment": request.recipient_commitment,
            "rebate_commitment": request.rebate_commitment,
            "rebate_bps": request.rebate_bps,
            "reason": request.reason
        });
        let sequence = self.counters.rebates.saturating_add(1);
        let rebate_id = deterministic_id("netting_rebate", &payload, sequence);
        self.rebates.insert(
            rebate_id.clone(),
            NettingRebate {
                rebate_id: rebate_id.clone(),
                settlement_id: payload["settlement_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                recipient_commitment: payload["recipient_commitment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                rebate_commitment: payload["rebate_commitment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                rebate_bps: request.rebate_bps,
                reason: payload["reason"]
                    .as_str()
                    .unwrap_or("low_fee_netting")
                    .to_string(),
                issued_at_height: self.height,
            },
        );
        self.counters.rebates = self.rebates.len() as u64;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn approve_disclosure(&mut self, request: ApproveDisclosureRequest) -> Result<String> {
        ensure_capacity(
            self.disclosures.len(),
            self.config.max_disclosures,
            "disclosure",
        )?;
        required("operator_id", &request.operator_id)?;
        required("subject_id", &request.subject_id)?;
        required("viewer_id", &request.viewer_id)?;
        required("view_key_root", &request.view_key_root)?;
        required("field_mask_root", &request.field_mask_root)?;
        let budget = self
            .redaction_budgets
            .entry(request.operator_id.clone())
            .or_insert_with(|| RedactionBudget {
                operator_id: request.operator_id.clone(),
                budget_remaining: self.config.operator_redaction_budget,
                summaries_posted: 0,
                disclosures_approved: 0,
            });
        ensure!(
            budget.budget_remaining >= request.budget_cost,
            "redaction budget exhausted"
        );
        budget.budget_remaining = budget.budget_remaining.saturating_sub(request.budget_cost);
        budget.disclosures_approved = budget.disclosures_approved.saturating_add(1);
        let payload = json!({
            "operator_id": request.operator_id,
            "subject_id": request.subject_id,
            "viewer_id": request.viewer_id,
            "view_key_root": request.view_key_root,
            "field_mask_root": request.field_mask_root
        });
        let sequence = self.counters.disclosures.saturating_add(1);
        let disclosure_id = deterministic_id("selective_disclosure", &payload, sequence);
        self.disclosures.insert(
            disclosure_id.clone(),
            SelectiveDisclosure {
                disclosure_id: disclosure_id.clone(),
                subject_id: payload["subject_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                viewer_id: payload["viewer_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                view_key_root: payload["view_key_root"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                field_mask_root: payload["field_mask_root"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                expires_at_height: self
                    .height
                    .saturating_add(self.config.disclosure_ttl_blocks),
                approved_at_height: self.height,
            },
        );
        self.counters.disclosures = self.disclosures.len() as u64;
        self.refresh_roots();
        Ok(disclosure_id)
    }

    pub fn post_operator_summary(&mut self, request: PostOperatorSummaryRequest) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator_summary",
        )?;
        required("operator_id", &request.operator_id)?;
        required("redacted_activity_root", &request.redacted_activity_root)?;
        required(
            "aggregate_volume_commitment",
            &request.aggregate_volume_commitment,
        )?;
        required(
            "aggregate_fee_commitment",
            &request.aggregate_fee_commitment,
        )?;
        required("mev_protection_root", &request.mev_protection_root)?;
        ensure!(
            request.window_start_height <= request.window_end_height,
            "summary window inverted"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "summary privacy set below minimum"
        );
        let budget = self
            .redaction_budgets
            .entry(request.operator_id.clone())
            .or_insert_with(|| RedactionBudget {
                operator_id: request.operator_id.clone(),
                budget_remaining: self.config.operator_redaction_budget,
                summaries_posted: 0,
                disclosures_approved: 0,
            });
        ensure!(
            budget.budget_remaining >= request.budget_spent,
            "redaction budget exhausted"
        );
        budget.budget_remaining = budget.budget_remaining.saturating_sub(request.budget_spent);
        budget.summaries_posted = budget.summaries_posted.saturating_add(1);
        let payload = json!({
            "operator_id": request.operator_id,
            "window_start_height": request.window_start_height,
            "window_end_height": request.window_end_height,
            "redacted_activity_root": request.redacted_activity_root,
            "aggregate_volume_commitment": request.aggregate_volume_commitment,
            "aggregate_fee_commitment": request.aggregate_fee_commitment,
            "privacy_set_size": request.privacy_set_size,
            "mev_protection_root": request.mev_protection_root
        });
        let sequence = self.counters.operator_summaries.saturating_add(1);
        let summary_id = deterministic_id("operator_summary", &payload, sequence);
        self.operator_summaries.insert(
            summary_id.clone(),
            OperatorSummary {
                summary_id: summary_id.clone(),
                operator_id: payload["operator_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                window_start_height: request.window_start_height,
                window_end_height: request.window_end_height,
                redacted_activity_root: payload["redacted_activity_root"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                aggregate_volume_commitment: payload["aggregate_volume_commitment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                aggregate_fee_commitment: payload["aggregate_fee_commitment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                privacy_set_size: request.privacy_set_size,
                mev_protection_root: payload["mev_protection_root"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                budget_spent: request.budget_spent,
                posted_at_height: self.height,
            },
        );
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn advance_height(&mut self, height: u64) {
        self.height = self.height.max(height);
        self.refresh_roots();
    }

    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }

    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_INTENT_BATCH_AUCTION_RUNTIME_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private-l2-pq-confidential-contract-private-intent-batch-auction:state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&self.roots_without_state().public_record()),
            ],
            32,
        )
    }

    fn refresh_roots(&mut self) {
        self.counters.replay_fences = self.replay_fences.len() as u64;
        let roots = self.compute_roots();
        self.roots = roots;
    }

    fn roots_without_state(&self) -> Roots {
        let mut roots = self.roots.clone();
        roots.state_root.clear();
        roots
    }

    fn compute_roots(&self) -> Roots {
        let mut roots = Roots {
            intent_book_root: map_root("intent-books", &self.intent_books),
            encrypted_intent_root: map_root("encrypted-intents", &self.encrypted_intents),
            encrypted_bid_root: map_root("encrypted-bids", &self.encrypted_bids),
            clearing_batch_root: map_root("clearing-batches", &self.clearing_batches),
            pq_attestation_root: map_root("pq-attestations", &self.pq_attestations),
            settlement_root: map_root("settlements", &self.settlements),
            rebate_root: map_root("rebates", &self.rebates),
            disclosure_root: map_root("disclosures", &self.disclosures),
            redaction_budget_root: map_root("redaction-budgets", &self.redaction_budgets),
            operator_summary_root: map_root("operator-summaries", &self.operator_summaries),
            replay_fence_root: set_root("replay-fences", &self.replay_fences),
            state_root: String::new(),
        };
        roots.state_root = domain_hash(
            "private-l2-pq-confidential-contract-private-intent-batch-auction:state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        );
        roots
    }

    fn insert_replay_fence(&mut self, nullifier: &str) -> Result<()> {
        ensure_capacity(
            self.replay_fences.len(),
            self.config.max_replay_fences,
            "replay_fence",
        )?;
        ensure!(
            !self.replay_fences.contains(nullifier),
            "replay fence already exists"
        );
        self.replay_fences.insert(nullifier.to_string());
        Ok(())
    }
}

impl PqExecutionAttestation {
    fn acceptable_status(&self) -> bool {
        self.status.acceptable()
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

pub fn intent_book_id(request: &OpenIntentBookRequest, sequence: u64) -> String {
    deterministic_id("intent_book", &request.public_record(), sequence)
}

pub fn encrypted_intent_id(request: &SubmitEncryptedIntentRequest, sequence: u64) -> String {
    deterministic_id("encrypted_intent", &request.public_record(), sequence)
}

pub fn encrypted_bid_id(request: &SubmitEncryptedBidRequest, sequence: u64) -> String {
    deterministic_id("encrypted_bid", &request.public_record(), sequence)
}

pub fn clearing_batch_id(request: &ClearBatchRequest, sequence: u64) -> String {
    deterministic_id("clearing_batch", &request.public_record(), sequence)
}

fn deterministic_id(kind: &str, record: &Value, sequence: u64) -> String {
    format!(
        "{}-{}",
        kind,
        domain_hash(
            "private-l2-pq-confidential-contract-private-intent-batch-auction:id",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind),
                HashPart::U64(sequence),
                HashPart::Json(record)
            ],
            16
        )
    )
}

fn devnet_root(label: &str) -> String {
    domain_hash(
        "private-l2-pq-confidential-contract-private-intent-batch-auction:devnet-root",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("private-l2-pq-confidential-contract-private-intent-batch-auction:{label}"),
        &[],
    )
}

fn map_root<T>(label: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": value.public_record_value() }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-confidential-contract-private-intent-batch-auction:{label}"),
        &leaves,
    )
}

fn set_root(label: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "fence": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-confidential-contract-private-intent-batch-auction:{label}"),
        &leaves,
    )
}

trait PublicRecord {
    fn public_record_value(&self) -> Value;
}

impl PublicRecord for IntentBook {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for EncryptedIntent {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for EncryptedBid {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for ClearingBatch {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqExecutionAttestation {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for Settlement {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for NettingRebate {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for SelectiveDisclosure {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for OperatorSummary {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn required(name: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), format!("{name} empty"));
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    ensure!(current < max, format!("{label} capacity reached"));
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    ensure!(value <= MAX_BPS, format!("{label} exceeds basis points"));
    Ok(())
}
