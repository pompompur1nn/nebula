use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-rollup-escape-hatch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_PQ_PROOF_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-rollup-exit-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_EXIT_NOTE_SCHEME: &str =
    "monero-private-exit-note-nullifier-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_LIQUIDITY_QUOTE_SCHEME: &str =
    "confidential-fast-exit-liquidity-quote-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_RESCUE_BATCH_SCHEME: &str =
    "pq-private-rollup-rescue-batch-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_WATCHER_QUORUM_SCHEME: &str =
    "monero-watchtower-pq-escape-quorum-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_RECEIPT_SCHEME: &str =
    "monero-private-rollup-exit-receipt-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_REBATE_SCHEME: &str =
    "low-fee-private-exit-rebate-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_SLASHING_SCHEME: &str =
    "escape-hatch-router-slashing-evidence-root-v1";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEVNET_HEIGHT: u64 = 1_042_000;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    262_144;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_EXIT_TTL_BLOCKS: u64 = 720;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS: u64 = 360;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 48;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 64;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_FAST_EXIT_BLOCKS: u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_REBATE_BPS: u64 = 6;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_SLASHING_BPS: u64 = 2_500;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_POLICIES: usize = 65_536;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_REQUESTS: usize = 2_097_152;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_PROOFS: usize = 4_194_304;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_QUOTES: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_BATCHES: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_RECEIPTS: usize = 4_194_304;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_REBATES: usize = 4_194_304;
pub const MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_SLASHING_EVIDENCE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapePolicyKind {
    NormalExit,
    FastLiquidityExit,
    SequencerHalt,
    BridgeFreeze,
    ReorgRescue,
    WatcherForcedExit,
    EmergencyMigration,
}

impl EscapePolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NormalExit => "normal_exit",
            Self::FastLiquidityExit => "fast_liquidity_exit",
            Self::SequencerHalt => "sequencer_halt",
            Self::BridgeFreeze => "bridge_freeze",
            Self::ReorgRescue => "reorg_rescue",
            Self::WatcherForcedExit => "watcher_forced_exit",
            Self::EmergencyMigration => "emergency_migration",
        }
    }

    pub fn requires_watchers(self) -> bool {
        matches!(
            self,
            Self::SequencerHalt
                | Self::BridgeFreeze
                | Self::ReorgRescue
                | Self::WatcherForcedExit
                | Self::EmergencyMigration
        )
    }

    pub fn supports_fast_liquidity(self) -> bool {
        matches!(
            self,
            Self::FastLiquidityExit
                | Self::SequencerHalt
                | Self::BridgeFreeze
                | Self::EmergencyMigration
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeRequestKind {
    NoteBurn,
    LiquidityAdvance,
    ContractStateWithdrawal,
    TokenBridgeExit,
    AccountMigration,
    ForcedInclusionExit,
    ReorgRecoveryExit,
}

impl EscapeRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoteBurn => "note_burn",
            Self::LiquidityAdvance => "liquidity_advance",
            Self::ContractStateWithdrawal => "contract_state_withdrawal",
            Self::TokenBridgeExit => "token_bridge_exit",
            Self::AccountMigration => "account_migration",
            Self::ForcedInclusionExit => "forced_inclusion_exit",
            Self::ReorgRecoveryExit => "reorg_recovery_exit",
        }
    }

    pub fn needs_contract_root(self) -> bool {
        matches!(
            self,
            Self::ContractStateWithdrawal | Self::TokenBridgeExit | Self::AccountMigration
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLane {
    LowFeeBatch,
    FastLiquidity,
    WatcherForced,
    ReorgRescue,
    EmergencyEscape,
    ContractHandoff,
}

impl ExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeBatch => "low_fee_batch",
            Self::FastLiquidity => "fast_liquidity",
            Self::WatcherForced => "watcher_forced",
            Self::ReorgRescue => "reorg_rescue",
            Self::EmergencyEscape => "emergency_escape",
            Self::ContractHandoff => "contract_handoff",
        }
    }

    pub fn urgency_weight(self) -> u64 {
        match self {
            Self::LowFeeBatch => 1,
            Self::ContractHandoff => 2,
            Self::FastLiquidity => 4,
            Self::WatcherForced => 7,
            Self::ReorgRescue => 9,
            Self::EmergencyEscape => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeRequestStatus {
    Submitted,
    ProofAttached,
    LiquidityQuoted,
    LiquidityAccepted,
    Batched,
    ReceiptPublished,
    Settled,
    Expired,
    Rejected,
    Slashed,
}

impl EscapeRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ProofAttached => "proof_attached",
            Self::LiquidityQuoted => "liquidity_quoted",
            Self::LiquidityAccepted => "liquidity_accepted",
            Self::Batched => "batched",
            Self::ReceiptPublished => "receipt_published",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::ProofAttached
                | Self::LiquidityQuoted
                | Self::LiquidityAccepted
                | Self::Batched
                | Self::ReceiptPublished
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqProofStatus {
    Submitted,
    Verified,
    Linked,
    Consumed,
    Rejected,
    Expired,
}

impl PqProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Linked => "linked",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityQuoteStatus {
    Posted,
    Accepted,
    Superseded,
    Expired,
    Slashed,
}

impl LiquidityQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueBatchStatus {
    Open,
    Sealed,
    WatcherAttested,
    ReceiptReady,
    Settled,
    Expired,
    Slashed,
}

impl RescueBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::WatcherAttested => "watcher_attested",
            Self::ReceiptReady => "receipt_ready",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_publish_receipt(self) -> bool {
        matches!(self, Self::WatcherAttested | Self::ReceiptReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Failed,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
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
    InvalidPqSignature,
    StaleQuote,
    DoubleReceipt,
    MissingWatcherQuorum,
    LiquidityShortfall,
    PrivacySetViolation,
    ExcessiveFee,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::StaleQuote => "stale_quote",
            Self::DoubleReceipt => "double_receipt",
            Self::MissingWatcherQuorum => "missing_watcher_quorum",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::PrivacySetViolation => "privacy_set_violation",
            Self::ExcessiveFee => "excessive_fee",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub hash_suite: String,
    pub pq_proof_suite: String,
    pub exit_note_scheme: String,
    pub liquidity_quote_scheme: String,
    pub rescue_batch_scheme: String,
    pub watcher_quorum_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub genesis_height: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub exit_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub fast_exit_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
    pub max_policies: usize,
    pub max_requests: usize,
    pub max_proofs: usize,
    pub max_quotes: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_slashing_evidence: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_HASH_SUITE.to_string(),
            pq_proof_suite: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_PQ_PROOF_SUITE
                .to_string(),
            exit_note_scheme: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_EXIT_NOTE_SCHEME
                .to_string(),
            liquidity_quote_scheme:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_LIQUIDITY_QUOTE_SCHEME.to_string(),
            rescue_batch_scheme:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_RESCUE_BATCH_SCHEME.to_string(),
            watcher_quorum_scheme:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_WATCHER_QUORUM_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            rebate_scheme: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_REBATE_SCHEME
                .to_string(),
            slashing_scheme: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_SLASHING_SCHEME
                .to_string(),
            genesis_height: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEVNET_HEIGHT,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            exit_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_EXIT_TTL_BLOCKS,
            proof_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS,
            quote_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            batch_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            fast_exit_blocks:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_FAST_EXIT_BLOCKS,
            max_user_fee_bps:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_REBATE_BPS,
            slashing_penalty_bps:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_DEFAULT_SLASHING_BPS,
            max_policies: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_POLICIES,
            max_requests: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_REQUESTS,
            max_proofs: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_PROOFS,
            max_quotes: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_QUOTES,
            max_batches: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_BATCHES,
            max_receipts: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_RECEIPTS,
            max_rebates: MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_REBATES,
            max_slashing_evidence:
                MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_SLASHING_EVIDENCE,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policies_registered: u64,
    pub exits_submitted: u64,
    pub pq_proofs_attached: u64,
    pub liquidity_quotes_posted: u64,
    pub liquidity_quotes_accepted: u64,
    pub rescue_batches_built: u64,
    pub watcher_attestations_recorded: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub slashing_events: u64,
    pub expired_requests: u64,
    pub total_requested_piconero: u128,
    pub total_fast_liquidity_piconero: u128,
    pub total_rebated_piconero: u128,
    pub total_slashed_bond_piconero: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_root: String,
    pub request_root: String,
    pub proof_root: String,
    pub quote_root: String,
    pub batch_root: String,
    pub watcher_attestation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub consumed_nullifier_root: String,
    pub checkpoint_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscapePolicy {
    pub id: String,
    pub kind: EscapePolicyKind,
    pub operator_commitment: String,
    pub policy_root: String,
    pub allowed_lanes: BTreeSet<ExitLane>,
    pub min_privacy_set_size: u64,
    pub min_watcher_quorum: u16,
    pub max_fee_bps: u64,
    pub fast_liquidity_cap_piconero: u128,
    pub bond_piconero: u128,
    pub pq_security_bits: u16,
    pub activated_height: u64,
    pub disabled_height: Option<u64>,
}

impl EscapePolicy {
    pub fn active_at(&self, height: u64) -> bool {
        self.activated_height <= height
            && self
                .disabled_height
                .map(|disabled| disabled > height)
                .unwrap_or(true)
    }

    pub fn supports_lane(&self, lane: ExitLane) -> bool {
        self.allowed_lanes.contains(&lane)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateExitRequest {
    pub id: String,
    pub kind: EscapeRequestKind,
    pub lane: ExitLane,
    pub policy_id: String,
    pub owner_commitment: String,
    pub stealth_address_commitment: String,
    pub amount_commitment: String,
    pub amount_piconero_hint: u128,
    pub note_nullifier: String,
    pub contract_state_root: Option<String>,
    pub bridge_context_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: EscapeRequestStatus,
    pub pq_proof_id: Option<String>,
    pub liquidity_quote_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub metadata_root: String,
}

impl PrivateExitRequest {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height && self.status.live()
    }

    pub fn needs_liquidity(&self) -> bool {
        matches!(
            self.lane,
            ExitLane::FastLiquidity | ExitLane::WatcherForced | ExitLane::EmergencyEscape
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExitProof {
    pub id: String,
    pub request_id: String,
    pub proof_root: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub witness_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: PqProofStatus,
}

impl PqExitProof {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height
            && matches!(
                self.status,
                PqProofStatus::Submitted | PqProofStatus::Verified | PqProofStatus::Linked
            )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityQuote {
    pub id: String,
    pub request_id: String,
    pub relayer_commitment: String,
    pub liquidity_pool_commitment: String,
    pub advance_amount_piconero: u128,
    pub fee_bps: u64,
    pub settlement_height: u64,
    pub quote_root: String,
    pub pq_signature_root: String,
    pub posted_height: u64,
    pub expires_height: u64,
    pub status: LiquidityQuoteStatus,
}

impl LiquidityQuote {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height && matches!(self.status, LiquidityQuoteStatus::Posted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub id: String,
    pub batch_id: String,
    pub watcher_set_root: String,
    pub quorum_signature_root: String,
    pub observed_monero_tip_root: String,
    pub observed_l2_state_root: String,
    pub verdict_root: String,
    pub signer_count: u16,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RescueBatch {
    pub id: String,
    pub lane: ExitLane,
    pub policy_id: String,
    pub request_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub total_amount_hint_piconero: u128,
    pub total_liquidity_advance_piconero: u128,
    pub max_fee_bps: u64,
    pub batch_root: String,
    pub nullifier_root: String,
    pub bridge_context_root: String,
    pub watcher_attestation_id: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: RescueBatchStatus,
}

impl RescueBatch {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height
            && matches!(
                self.status,
                RescueBatchStatus::Open
                    | RescueBatchStatus::Sealed
                    | RescueBatchStatus::WatcherAttested
                    | RescueBatchStatus::ReceiptReady
            )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceipt {
    pub id: String,
    pub batch_id: String,
    pub request_ids: Vec<String>,
    pub monero_txset_root: String,
    pub withdrawal_note_root: String,
    pub fee_root: String,
    pub pq_receipt_signature_root: String,
    pub watcher_attestation_id: String,
    pub published_height: u64,
    pub finalized_height: Option<u64>,
    pub status: ReceiptStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub id: String,
    pub request_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub rebate_amount_piconero: u128,
    pub rebate_bps: u64,
    pub issued_height: u64,
    pub status: RebateStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub id: String,
    pub subject_commitment: String,
    pub request_id: Option<String>,
    pub batch_id: Option<String>,
    pub quote_id: Option<String>,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub penalty_bps: u64,
    pub slashed_bond_piconero: u128,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeCheckpoint {
    pub id: String,
    pub height: u64,
    pub state_root: String,
    pub live_request_count: u64,
    pub pending_batch_count: u64,
    pub total_requested_piconero: u128,
    pub total_fast_liquidity_piconero: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPolicyRequest {
    pub kind: EscapePolicyKind,
    pub operator_commitment: String,
    pub policy_root: String,
    pub allowed_lanes: BTreeSet<ExitLane>,
    pub min_privacy_set_size: u64,
    pub min_watcher_quorum: u16,
    pub max_fee_bps: u64,
    pub fast_liquidity_cap_piconero: u128,
    pub bond_piconero: u128,
    pub pq_security_bits: u16,
    pub activated_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitExitRequest {
    pub kind: EscapeRequestKind,
    pub lane: ExitLane,
    pub policy_id: String,
    pub owner_commitment: String,
    pub stealth_address_commitment: String,
    pub amount_commitment: String,
    pub amount_piconero_hint: u128,
    pub note_nullifier: String,
    pub contract_state_root: Option<String>,
    pub bridge_context_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqProofRequest {
    pub request_id: String,
    pub proof_root: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub witness_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostLiquidityQuoteRequest {
    pub request_id: String,
    pub relayer_commitment: String,
    pub liquidity_pool_commitment: String,
    pub advance_amount_piconero: u128,
    pub fee_bps: u64,
    pub settlement_height: u64,
    pub quote_root: String,
    pub pq_signature_root: String,
    pub posted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildRescueBatchRequest {
    pub lane: ExitLane,
    pub policy_id: String,
    pub request_ids: Vec<String>,
    pub bridge_context_root: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestBatchRequest {
    pub batch_id: String,
    pub watcher_set_root: String,
    pub quorum_signature_root: String,
    pub observed_monero_tip_root: String,
    pub observed_l2_state_root: String,
    pub verdict_root: String,
    pub signer_count: u16,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishReceiptRequest {
    pub batch_id: String,
    pub monero_txset_root: String,
    pub withdrawal_note_root: String,
    pub fee_root: String,
    pub pq_receipt_signature_root: String,
    pub published_height: u64,
    pub finalize: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRequest {
    pub subject_commitment: String,
    pub request_id: Option<String>,
    pub batch_id: Option<String>,
    pub quote_id: Option<String>,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub bond_piconero: u128,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub policies: BTreeMap<String, EscapePolicy>,
    pub requests: BTreeMap<String, PrivateExitRequest>,
    pub proofs: BTreeMap<String, PqExitProof>,
    pub quotes: BTreeMap<String, LiquidityQuote>,
    pub batches: BTreeMap<String, RescueBatch>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub receipts: BTreeMap<String, ExitReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub checkpoints: BTreeMap<String, RuntimeCheckpoint>,
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
            counters: Counters::default(),
            policies: BTreeMap::new(),
            requests: BTreeMap::new(),
            proofs: BTreeMap::new(),
            quotes: BTreeMap::new(),
            batches: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            checkpoints: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let mut emergency_lanes = BTreeSet::new();
        emergency_lanes.insert(ExitLane::LowFeeBatch);
        emergency_lanes.insert(ExitLane::FastLiquidity);
        emergency_lanes.insert(ExitLane::WatcherForced);
        emergency_lanes.insert(ExitLane::EmergencyEscape);

        let policy = state
            .register_policy(RegisterPolicyRequest {
                kind: EscapePolicyKind::EmergencyMigration,
                operator_commitment: "devnet-escape-hatch-operator".to_string(),
                policy_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-policy",
                    &[
                        "emergency-migration",
                        "fast-liquidity",
                        "watcher-forced-exit",
                        "low-fee-private-batch",
                    ],
                ),
                allowed_lanes: emergency_lanes,
                min_privacy_set_size: state.config.min_privacy_set_size,
                min_watcher_quorum: 5,
                max_fee_bps: state.config.max_user_fee_bps,
                fast_liquidity_cap_piconero: 50_000_000_000_000,
                bond_piconero: 5_000_000_000_000,
                pq_security_bits: state.config.min_pq_security_bits,
                activated_height: state.config.genesis_height,
            })
            .expect("devnet policy");

        let exit = state
            .submit_private_exit(SubmitExitRequest {
                kind: EscapeRequestKind::LiquidityAdvance,
                lane: ExitLane::FastLiquidity,
                policy_id: policy.id.clone(),
                owner_commitment: "devnet-owner-commitment".to_string(),
                stealth_address_commitment: "devnet-monero-stealth-output-commitment".to_string(),
                amount_commitment: "devnet-confidential-amount-commitment".to_string(),
                amount_piconero_hint: 4_200_000_000_000,
                note_nullifier: "devnet-private-exit-nullifier".to_string(),
                contract_state_root: None,
                bridge_context_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-bridge-context",
                    &[
                        "monero-devnet-tip",
                        "nebula-devnet-state",
                        "reserve-attested",
                    ],
                ),
                fee_asset_id: "piconero-devnet".to_string(),
                max_fee_bps: 8,
                privacy_set_size: state.config.min_privacy_set_size * 2,
                submitted_height: state.config.genesis_height + 1,
                metadata_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-exit-metadata",
                    &["wallet-priority-fast", "no-selective-disclosure"],
                ),
            })
            .expect("devnet exit");

        state
            .attach_pq_proof(AttachPqProofRequest {
                request_id: exit.id.clone(),
                proof_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-proof",
                    &[
                        "ml-kem",
                        "ml-dsa",
                        "slh-dsa",
                        "private-nullifier-membership",
                    ],
                ),
                public_key_commitment: "devnet-pq-exit-public-key-commitment".to_string(),
                signature_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-proof-signature",
                    &["signature-share-a", "signature-share-b"],
                ),
                witness_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-proof-witness",
                    &["note-membership", "policy-membership", "amount-range"],
                ),
                pq_security_bits: state.config.min_pq_security_bits,
                privacy_set_size: state.config.batch_privacy_set_size,
                submitted_height: state.config.genesis_height + 2,
            })
            .expect("devnet pq proof");

        let quote = state
            .post_liquidity_quote(PostLiquidityQuoteRequest {
                request_id: exit.id.clone(),
                relayer_commitment: "devnet-fast-exit-relayer".to_string(),
                liquidity_pool_commitment: "devnet-private-exit-liquidity-pool".to_string(),
                advance_amount_piconero: 4_196_000_000_000,
                fee_bps: 4,
                settlement_height: state.config.genesis_height + state.config.fast_exit_blocks,
                quote_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-liquidity-quote",
                    &["fast-advance", "low-fee", "private-routing"],
                ),
                pq_signature_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-quote-signature",
                    &["relayer-pq-signature", "pool-pq-signature"],
                ),
                posted_height: state.config.genesis_height + 3,
            })
            .expect("devnet liquidity quote");

        state
            .accept_liquidity_quote(&exit.id, &quote.id, state.config.genesis_height + 4)
            .expect("devnet accept quote");

        let batch = state
            .build_rescue_batch(BuildRescueBatchRequest {
                lane: ExitLane::FastLiquidity,
                policy_id: policy.id,
                request_ids: vec![exit.id.clone()],
                bridge_context_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-batch-context",
                    &["monero-tip", "l2-state", "fast-liquidity"],
                ),
                created_height: state.config.genesis_height + 5,
            })
            .expect("devnet rescue batch");

        state
            .attest_batch(AttestBatchRequest {
                batch_id: batch.id.clone(),
                watcher_set_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-watchers",
                    &[
                        "watcher-a",
                        "watcher-b",
                        "watcher-c",
                        "watcher-d",
                        "watcher-e",
                    ],
                ),
                quorum_signature_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-watcher-quorum",
                    &["ml-dsa-quorum", "slh-dsa-fallback"],
                ),
                observed_monero_tip_root: "devnet-monero-tip-root".to_string(),
                observed_l2_state_root: "devnet-l2-state-root".to_string(),
                verdict_root: root_from_strings(
                    "monero-l2-pq-private-rollup-escape-hatch:devnet-verdict",
                    &["request-valid", "liquidity-valid", "privacy-set-ok"],
                ),
                signer_count: 5,
                pq_security_bits: state.config.min_pq_security_bits,
                attested_height: state.config.genesis_height + 6,
            })
            .expect("devnet attest batch");

        state
            .publish_receipt(PublishReceiptRequest {
                batch_id: batch.id,
                monero_txset_root: "devnet-monero-exit-txset-root".to_string(),
                withdrawal_note_root: "devnet-withdrawal-note-root".to_string(),
                fee_root: "devnet-low-fee-root".to_string(),
                pq_receipt_signature_root: "devnet-pq-receipt-signature-root".to_string(),
                published_height: state.config.genesis_height + 7,
                finalize: true,
            })
            .expect("devnet receipt");

        state.checkpoint(state.config.genesis_height + 8);
        state
    }

    pub fn register_policy(
        &mut self,
        request: RegisterPolicyRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<EscapePolicy> {
        if self.policies.len() >= self.config.max_policies {
            return Err("escape policy capacity exceeded".to_string());
        }
        if request.operator_commitment.is_empty() || request.policy_root.is_empty() {
            return Err("operator commitment and policy root are required".to_string());
        }
        if request.allowed_lanes.is_empty() {
            return Err("policy must allow at least one exit lane".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("policy fee cap exceeds runtime fee cap".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("policy privacy set is below runtime minimum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("policy PQ security is below runtime minimum".to_string());
        }

        let id = escape_policy_id(
            request.kind,
            &request.operator_commitment,
            &request.policy_root,
            request.activated_height,
        );
        if self.policies.contains_key(&id) {
            return Err("escape policy already exists".to_string());
        }

        let policy = EscapePolicy {
            id: id.clone(),
            kind: request.kind,
            operator_commitment: request.operator_commitment,
            policy_root: request.policy_root,
            allowed_lanes: request.allowed_lanes,
            min_privacy_set_size: request.min_privacy_set_size,
            min_watcher_quorum: request.min_watcher_quorum,
            max_fee_bps: request.max_fee_bps,
            fast_liquidity_cap_piconero: request.fast_liquidity_cap_piconero,
            bond_piconero: request.bond_piconero,
            pq_security_bits: request.pq_security_bits,
            activated_height: request.activated_height,
            disabled_height: None,
        };
        self.policies.insert(id, policy.clone());
        self.counters.policies_registered += 1;
        Ok(policy)
    }

    pub fn disable_policy(
        &mut self,
        policy_id: &str,
        disabled_height: u64,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<()> {
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| "unknown escape policy".to_string())?;
        if disabled_height < policy.activated_height {
            return Err("policy cannot be disabled before activation".to_string());
        }
        policy.disabled_height = Some(disabled_height);
        Ok(())
    }

    pub fn submit_private_exit(
        &mut self,
        request: SubmitExitRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<PrivateExitRequest> {
        if self.requests.len() >= self.config.max_requests {
            return Err("escape request capacity exceeded".to_string());
        }
        if self.consumed_nullifiers.contains(&request.note_nullifier) {
            return Err("exit note nullifier already consumed".to_string());
        }
        if request.owner_commitment.is_empty()
            || request.stealth_address_commitment.is_empty()
            || request.amount_commitment.is_empty()
            || request.note_nullifier.is_empty()
        {
            return Err("exit request commitments are required".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("requested fee cap exceeds runtime maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set is below runtime minimum".to_string());
        }
        if request.kind.needs_contract_root() && request.contract_state_root.is_none() {
            return Err("contract-rooted exit requires a contract state root".to_string());
        }

        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "unknown escape policy".to_string())?;
        if !policy.active_at(request.submitted_height) {
            return Err("escape policy is not active".to_string());
        }
        if !policy.supports_lane(request.lane) {
            return Err("escape policy does not support requested lane".to_string());
        }
        if request.max_fee_bps > policy.max_fee_bps {
            return Err("requested fee cap exceeds policy maximum".to_string());
        }
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("request privacy set is below policy minimum".to_string());
        }

        let id = exit_request_id(
            request.kind,
            request.lane,
            &request.policy_id,
            &request.note_nullifier,
            request.submitted_height,
        );
        if self.requests.contains_key(&id) {
            return Err("exit request already exists".to_string());
        }

        let exit = PrivateExitRequest {
            id: id.clone(),
            kind: request.kind,
            lane: request.lane,
            policy_id: request.policy_id,
            owner_commitment: request.owner_commitment,
            stealth_address_commitment: request.stealth_address_commitment,
            amount_commitment: request.amount_commitment,
            amount_piconero_hint: request.amount_piconero_hint,
            note_nullifier: request.note_nullifier,
            contract_state_root: request.contract_state_root,
            bridge_context_root: request.bridge_context_root,
            fee_asset_id: request.fee_asset_id,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            submitted_height: request.submitted_height,
            expires_height: request.submitted_height + self.config.exit_ttl_blocks,
            status: EscapeRequestStatus::Submitted,
            pq_proof_id: None,
            liquidity_quote_id: None,
            batch_id: None,
            receipt_id: None,
            metadata_root: request.metadata_root,
        };

        self.consumed_nullifiers.insert(exit.note_nullifier.clone());
        self.counters.exits_submitted += 1;
        self.counters.total_requested_piconero = self
            .counters
            .total_requested_piconero
            .saturating_add(exit.amount_piconero_hint);
        self.requests.insert(id, exit.clone());
        Ok(exit)
    }

    pub fn attach_pq_proof(
        &mut self,
        request: AttachPqProofRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<PqExitProof> {
        if self.proofs.len() >= self.config.max_proofs {
            return Err("PQ proof capacity exceeded".to_string());
        }
        let exit = self
            .requests
            .get(&request.request_id)
            .ok_or_else(|| "unknown escape request".to_string())?;
        if !matches!(
            exit.status,
            EscapeRequestStatus::Submitted | EscapeRequestStatus::ProofAttached
        ) {
            return Err("escape request is not accepting PQ proofs".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ proof security level is below runtime minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("PQ proof privacy set is below runtime minimum".to_string());
        }
        if request.proof_root.is_empty()
            || request.public_key_commitment.is_empty()
            || request.signature_root.is_empty()
            || request.witness_root.is_empty()
        {
            return Err("PQ proof roots and commitments are required".to_string());
        }

        let id = pq_proof_id(
            &request.request_id,
            &request.proof_root,
            &request.signature_root,
            request.submitted_height,
        );
        if self.proofs.contains_key(&id) {
            return Err("PQ proof already exists".to_string());
        }

        let proof = PqExitProof {
            id: id.clone(),
            request_id: request.request_id.clone(),
            proof_root: request.proof_root,
            public_key_commitment: request.public_key_commitment,
            signature_root: request.signature_root,
            witness_root: request.witness_root,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            submitted_height: request.submitted_height,
            expires_height: request.submitted_height + self.config.proof_ttl_blocks,
            status: PqProofStatus::Verified,
        };
        self.proofs.insert(id.clone(), proof.clone());
        if let Some(exit) = self.requests.get_mut(&request.request_id) {
            exit.pq_proof_id = Some(id);
            exit.status = EscapeRequestStatus::ProofAttached;
        }
        self.counters.pq_proofs_attached += 1;
        Ok(proof)
    }

    pub fn post_liquidity_quote(
        &mut self,
        request: PostLiquidityQuoteRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<LiquidityQuote> {
        if self.quotes.len() >= self.config.max_quotes {
            return Err("liquidity quote capacity exceeded".to_string());
        }
        let exit = self
            .requests
            .get(&request.request_id)
            .ok_or_else(|| "unknown escape request".to_string())?;
        if !exit.needs_liquidity() {
            return Err("escape lane does not require fast liquidity".to_string());
        }
        if !matches!(
            exit.status,
            EscapeRequestStatus::ProofAttached | EscapeRequestStatus::LiquidityQuoted
        ) {
            return Err("escape request is not ready for liquidity quotes".to_string());
        }
        if request.fee_bps > exit.max_fee_bps || request.fee_bps > self.config.max_user_fee_bps {
            return Err("liquidity quote fee exceeds cap".to_string());
        }
        if request.advance_amount_piconero > exit.amount_piconero_hint {
            return Err("liquidity advance exceeds requested amount".to_string());
        }
        if request.relayer_commitment.is_empty()
            || request.liquidity_pool_commitment.is_empty()
            || request.quote_root.is_empty()
            || request.pq_signature_root.is_empty()
        {
            return Err("liquidity quote commitments are required".to_string());
        }

        let id = liquidity_quote_id(
            &request.request_id,
            &request.relayer_commitment,
            &request.quote_root,
            request.posted_height,
        );
        if self.quotes.contains_key(&id) {
            return Err("liquidity quote already exists".to_string());
        }

        let quote = LiquidityQuote {
            id: id.clone(),
            request_id: request.request_id.clone(),
            relayer_commitment: request.relayer_commitment,
            liquidity_pool_commitment: request.liquidity_pool_commitment,
            advance_amount_piconero: request.advance_amount_piconero,
            fee_bps: request.fee_bps,
            settlement_height: request.settlement_height,
            quote_root: request.quote_root,
            pq_signature_root: request.pq_signature_root,
            posted_height: request.posted_height,
            expires_height: request.posted_height + self.config.quote_ttl_blocks,
            status: LiquidityQuoteStatus::Posted,
        };
        self.quotes.insert(id.clone(), quote.clone());
        if let Some(exit) = self.requests.get_mut(&request.request_id) {
            exit.liquidity_quote_id = Some(id);
            exit.status = EscapeRequestStatus::LiquidityQuoted;
        }
        self.counters.liquidity_quotes_posted += 1;
        Ok(quote)
    }

    pub fn accept_liquidity_quote(
        &mut self,
        request_id: &str,
        quote_id: &str,
        height: u64,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<()> {
        let exit = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "unknown escape request".to_string())?;
        if exit.expired_at(height) {
            exit.status = EscapeRequestStatus::Expired;
            return Err("escape request expired".to_string());
        }
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| "unknown liquidity quote".to_string())?;
        if quote.request_id != request_id {
            return Err("liquidity quote belongs to another request".to_string());
        }
        if quote.expired_at(height) {
            quote.status = LiquidityQuoteStatus::Expired;
            return Err("liquidity quote expired".to_string());
        }
        if !matches!(quote.status, LiquidityQuoteStatus::Posted) {
            return Err("liquidity quote is not open".to_string());
        }

        quote.status = LiquidityQuoteStatus::Accepted;
        exit.liquidity_quote_id = Some(quote_id.to_string());
        exit.status = EscapeRequestStatus::LiquidityAccepted;
        self.counters.liquidity_quotes_accepted += 1;
        self.counters.total_fast_liquidity_piconero = self
            .counters
            .total_fast_liquidity_piconero
            .saturating_add(quote.advance_amount_piconero);
        Ok(())
    }

    pub fn build_rescue_batch(
        &mut self,
        request: BuildRescueBatchRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<RescueBatch> {
        if self.batches.len() >= self.config.max_batches {
            return Err("rescue batch capacity exceeded".to_string());
        }
        if request.request_ids.is_empty() {
            return Err("rescue batch requires at least one request".to_string());
        }
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "unknown escape policy".to_string())?;
        if !policy.supports_lane(request.lane) {
            return Err("policy does not support batch lane".to_string());
        }

        let mut quote_ids = Vec::new();
        let mut nullifiers = Vec::new();
        let mut total_amount_hint_piconero = 0_u128;
        let mut total_liquidity_advance_piconero = 0_u128;
        let mut max_fee_bps = 0_u64;

        for request_id in &request.request_ids {
            let exit = self
                .requests
                .get(request_id)
                .ok_or_else(|| format!("unknown escape request {request_id}"))?;
            if exit.policy_id != request.policy_id {
                return Err("all batch requests must share a policy".to_string());
            }
            if exit.lane != request.lane {
                return Err("all batch requests must share a lane".to_string());
            }
            if exit.expired_at(request.created_height) {
                return Err("batch contains an expired request".to_string());
            }
            if exit.pq_proof_id.is_none() {
                return Err("batch request is missing a PQ proof".to_string());
            }
            if exit.needs_liquidity() && exit.liquidity_quote_id.is_none() {
                return Err("batch request is missing fast liquidity quote".to_string());
            }
            if !matches!(
                exit.status,
                EscapeRequestStatus::ProofAttached
                    | EscapeRequestStatus::LiquidityQuoted
                    | EscapeRequestStatus::LiquidityAccepted
            ) {
                return Err("batch request is not ready".to_string());
            }
            total_amount_hint_piconero =
                total_amount_hint_piconero.saturating_add(exit.amount_piconero_hint);
            max_fee_bps = max_fee_bps.max(exit.max_fee_bps);
            nullifiers.push(json!({
                "request_id": exit.id,
                "note_nullifier": exit.note_nullifier,
            }));
            if let Some(quote_id) = &exit.liquidity_quote_id {
                let quote = self
                    .quotes
                    .get(quote_id)
                    .ok_or_else(|| "request points to unknown liquidity quote".to_string())?;
                if quote.status != LiquidityQuoteStatus::Accepted {
                    return Err("liquidity quote must be accepted before batching".to_string());
                }
                total_liquidity_advance_piconero =
                    total_liquidity_advance_piconero.saturating_add(quote.advance_amount_piconero);
                quote_ids.push(quote_id.clone());
            }
        }

        if total_liquidity_advance_piconero > policy.fast_liquidity_cap_piconero {
            return Err("batch exceeds policy fast liquidity cap".to_string());
        }

        let nullifier_root = merkle_root(
            "monero-l2-pq-private-rollup-escape-hatch:nullifiers",
            &nullifiers,
        );
        let batch_root = rescue_batch_root(
            request.lane,
            &request.policy_id,
            &request.request_ids,
            &quote_ids,
            &nullifier_root,
            &request.bridge_context_root,
        );
        let id = rescue_batch_id(
            request.lane,
            &request.policy_id,
            &batch_root,
            request.created_height,
        );
        if self.batches.contains_key(&id) {
            return Err("rescue batch already exists".to_string());
        }

        for request_id in &request.request_ids {
            if let Some(exit) = self.requests.get_mut(request_id) {
                exit.batch_id = Some(id.clone());
                exit.status = EscapeRequestStatus::Batched;
            }
        }

        let batch = RescueBatch {
            id: id.clone(),
            lane: request.lane,
            policy_id: request.policy_id,
            request_ids: request.request_ids,
            quote_ids,
            total_amount_hint_piconero,
            total_liquidity_advance_piconero,
            max_fee_bps,
            batch_root,
            nullifier_root,
            bridge_context_root: request.bridge_context_root,
            watcher_attestation_id: None,
            created_height: request.created_height,
            expires_height: request.created_height + self.config.batch_ttl_blocks,
            status: RescueBatchStatus::Sealed,
        };
        self.batches.insert(id, batch.clone());
        self.counters.rescue_batches_built += 1;
        Ok(batch)
    }

    pub fn attest_batch(
        &mut self,
        request: AttestBatchRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<WatcherAttestation> {
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown rescue batch".to_string())?;
        if batch.expired_at(request.attested_height) {
            return Err("rescue batch expired".to_string());
        }
        let policy = self
            .policies
            .get(&batch.policy_id)
            .ok_or_else(|| "batch policy not found".to_string())?;
        if request.signer_count < policy.min_watcher_quorum {
            return Err("watcher signer count below policy quorum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("watcher attestation PQ security below runtime minimum".to_string());
        }

        let id = watcher_attestation_id(
            &request.batch_id,
            &request.watcher_set_root,
            &request.quorum_signature_root,
            request.attested_height,
        );
        if self.watcher_attestations.contains_key(&id) {
            return Err("watcher attestation already exists".to_string());
        }

        let attestation = WatcherAttestation {
            id: id.clone(),
            batch_id: request.batch_id.clone(),
            watcher_set_root: request.watcher_set_root,
            quorum_signature_root: request.quorum_signature_root,
            observed_monero_tip_root: request.observed_monero_tip_root,
            observed_l2_state_root: request.observed_l2_state_root,
            verdict_root: request.verdict_root,
            signer_count: request.signer_count,
            pq_security_bits: request.pq_security_bits,
            attested_height: request.attested_height,
        };
        self.watcher_attestations
            .insert(id.clone(), attestation.clone());
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.watcher_attestation_id = Some(id);
            batch.status = RescueBatchStatus::WatcherAttested;
        }
        self.counters.watcher_attestations_recorded += 1;
        Ok(attestation)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishReceiptRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<ExitReceipt> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown rescue batch".to_string())?;
        if batch.expired_at(request.published_height) {
            return Err("rescue batch expired".to_string());
        }
        if !batch.status.can_publish_receipt() {
            return Err("rescue batch is not ready for receipt publication".to_string());
        }
        let watcher_attestation_id = batch
            .watcher_attestation_id
            .clone()
            .ok_or_else(|| "rescue batch is missing watcher attestation".to_string())?;
        let id = receipt_id(
            &request.batch_id,
            &request.monero_txset_root,
            &request.pq_receipt_signature_root,
            request.published_height,
        );
        if self.receipts.contains_key(&id) {
            return Err("exit receipt already exists".to_string());
        }

        let finalized_height = if request.finalize {
            Some(request.published_height)
        } else {
            None
        };
        let status = if request.finalize {
            ReceiptStatus::Finalized
        } else {
            ReceiptStatus::Published
        };
        let request_ids = batch.request_ids.clone();
        let receipt = ExitReceipt {
            id: id.clone(),
            batch_id: request.batch_id.clone(),
            request_ids: request_ids.clone(),
            monero_txset_root: request.monero_txset_root,
            withdrawal_note_root: request.withdrawal_note_root,
            fee_root: request.fee_root,
            pq_receipt_signature_root: request.pq_receipt_signature_root,
            watcher_attestation_id,
            published_height: request.published_height,
            finalized_height,
            status,
        };
        self.receipts.insert(id.clone(), receipt.clone());
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = if request.finalize {
                RescueBatchStatus::Settled
            } else {
                RescueBatchStatus::ReceiptReady
            };
        }

        for request_id in request_ids {
            if let Some(exit) = self.requests.get_mut(&request_id) {
                exit.receipt_id = Some(id.clone());
                exit.status = if request.finalize {
                    EscapeRequestStatus::Settled
                } else {
                    EscapeRequestStatus::ReceiptPublished
                };
            }
            if request.finalize {
                self.issue_rebate_for_request(&request_id, &id, request.published_height)?;
            }
        }
        self.counters.receipts_published += 1;
        Ok(receipt)
    }

    pub fn issue_rebate_for_request(
        &mut self,
        request_id: &str,
        receipt_id: &str,
        issued_height: u64,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<Option<FeeRebate>> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        let exit = self
            .requests
            .get(request_id)
            .ok_or_else(|| "unknown escape request".to_string())?;
        if self.config.target_rebate_bps == 0 {
            return Ok(None);
        }
        let rebate_amount_piconero = exit
            .amount_piconero_hint
            .saturating_mul(self.config.target_rebate_bps as u128)
            / MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_BPS as u128;
        if rebate_amount_piconero == 0 {
            return Ok(None);
        }
        let id = rebate_id(
            request_id,
            receipt_id,
            &exit.owner_commitment,
            issued_height,
        );
        if self.rebates.contains_key(&id) {
            return Ok(self.rebates.get(&id).cloned());
        }

        let rebate = FeeRebate {
            id: id.clone(),
            request_id: request_id.to_string(),
            receipt_id: receipt_id.to_string(),
            beneficiary_commitment: exit.owner_commitment.clone(),
            fee_asset_id: exit.fee_asset_id.clone(),
            rebate_amount_piconero,
            rebate_bps: self.config.target_rebate_bps,
            issued_height,
            status: RebateStatus::Issued,
        };
        self.rebates.insert(id, rebate.clone());
        self.counters.rebates_issued += 1;
        self.counters.total_rebated_piconero = self
            .counters
            .total_rebated_piconero
            .saturating_add(rebate.rebate_amount_piconero);
        Ok(Some(rebate))
    }

    pub fn slash(
        &mut self,
        request: SlashRequest,
    ) -> MoneroL2PqPrivateRollupEscapeHatchRuntimeResult<SlashingEvidence> {
        if self.slashing_evidence.len() >= self.config.max_slashing_evidence {
            return Err("slashing evidence capacity exceeded".to_string());
        }
        if request.subject_commitment.is_empty() || request.evidence_root.is_empty() {
            return Err("slashing subject and evidence root are required".to_string());
        }
        let slashed_bond_piconero = request
            .bond_piconero
            .saturating_mul(self.config.slashing_penalty_bps as u128)
            / MONERO_L2_PQ_PRIVATE_ROLLUP_ESCAPE_HATCH_RUNTIME_MAX_BPS as u128;
        let id = slashing_evidence_id(
            &request.subject_commitment,
            request.reason,
            &request.evidence_root,
            request.submitted_height,
        );
        if self.slashing_evidence.contains_key(&id) {
            return Err("slashing evidence already exists".to_string());
        }
        let evidence = SlashingEvidence {
            id: id.clone(),
            subject_commitment: request.subject_commitment,
            request_id: request.request_id.clone(),
            batch_id: request.batch_id.clone(),
            quote_id: request.quote_id.clone(),
            reason: request.reason,
            evidence_root: request.evidence_root,
            penalty_bps: self.config.slashing_penalty_bps,
            slashed_bond_piconero,
            submitted_height: request.submitted_height,
        };
        self.slashing_evidence.insert(id, evidence.clone());

        if let Some(request_id) = request.request_id {
            if let Some(exit) = self.requests.get_mut(&request_id) {
                exit.status = EscapeRequestStatus::Slashed;
            }
        }
        if let Some(batch_id) = request.batch_id {
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.status = RescueBatchStatus::Slashed;
            }
        }
        if let Some(quote_id) = request.quote_id {
            if let Some(quote) = self.quotes.get_mut(&quote_id) {
                quote.status = LiquidityQuoteStatus::Slashed;
            }
        }
        self.counters.slashing_events += 1;
        self.counters.total_slashed_bond_piconero = self
            .counters
            .total_slashed_bond_piconero
            .saturating_add(slashed_bond_piconero);
        Ok(evidence)
    }

    pub fn expire_stale(&mut self, height: u64) -> usize {
        let mut expired = 0_usize;
        for proof in self.proofs.values_mut() {
            if proof.expired_at(height) {
                proof.status = PqProofStatus::Expired;
                expired += 1;
            }
        }
        for quote in self.quotes.values_mut() {
            if quote.expired_at(height) {
                quote.status = LiquidityQuoteStatus::Expired;
                expired += 1;
            }
        }
        for batch in self.batches.values_mut() {
            if batch.expired_at(height) {
                batch.status = RescueBatchStatus::Expired;
                expired += 1;
            }
        }
        for request in self.requests.values_mut() {
            if request.expired_at(height) {
                request.status = EscapeRequestStatus::Expired;
                expired += 1;
                self.counters.expired_requests += 1;
            }
        }
        expired
    }

    pub fn live_request_count(&self) -> u64 {
        self.requests
            .values()
            .filter(|request| request.status.live())
            .count() as u64
    }

    pub fn pending_batch_count(&self) -> u64 {
        self.batches
            .values()
            .filter(|batch| {
                matches!(
                    batch.status,
                    RescueBatchStatus::Open
                        | RescueBatchStatus::Sealed
                        | RescueBatchStatus::WatcherAttested
                        | RescueBatchStatus::ReceiptReady
                )
            })
            .count() as u64
    }

    pub fn roots(&self) -> Roots {
        Roots {
            policy_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:policies",
                &self.policies,
            ),
            request_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:requests",
                &self.requests,
            ),
            proof_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:proofs",
                &self.proofs,
            ),
            quote_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:quotes",
                &self.quotes,
            ),
            batch_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:batches",
                &self.batches,
            ),
            watcher_attestation_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:watcher-attestations",
                &self.watcher_attestations,
            ),
            receipt_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:receipts",
                &self.receipts,
            ),
            rebate_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:rebates",
                &self.rebates,
            ),
            slashing_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:slashing",
                &self.slashing_evidence,
            ),
            consumed_nullifier_root: set_root(
                "monero-l2-pq-private-rollup-escape-hatch:consumed-nullifiers",
                &self.consumed_nullifiers,
            ),
            checkpoint_root: map_root(
                "monero-l2-pq-private-rollup-escape-hatch:checkpoints",
                &self.checkpoints,
            ),
        }
    }

    pub fn checkpoint(&mut self, height: u64) -> RuntimeCheckpoint {
        let state_root = self.state_root();
        let id = checkpoint_id(&state_root, height);
        let checkpoint = RuntimeCheckpoint {
            id: id.clone(),
            height,
            state_root,
            live_request_count: self.live_request_count(),
            pending_batch_count: self.pending_batch_count(),
            total_requested_piconero: self.counters.total_requested_piconero,
            total_fast_liquidity_piconero: self.counters.total_fast_liquidity_piconero,
        };
        self.checkpoints.insert(id, checkpoint.clone());
        checkpoint
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "hash_suite": self.config.hash_suite,
            "pq_proof_suite": self.config.pq_proof_suite,
            "config": self.config,
            "counters": self.counters,
            "roots": roots,
            "policy_count": self.policies.len(),
            "request_count": self.requests.len(),
            "proof_count": self.proofs.len(),
            "quote_count": self.quotes.len(),
            "batch_count": self.batches.len(),
            "watcher_attestation_count": self.watcher_attestations.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
            "slashing_evidence_count": self.slashing_evidence.len(),
            "consumed_nullifier_count": self.consumed_nullifiers.len(),
            "checkpoint_count": self.checkpoints.len(),
            "live_request_count": self.live_request_count(),
            "pending_batch_count": self.pending_batch_count(),
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_private_rollup_escape_hatch_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn monero_l2_pq_private_rollup_escape_hatch_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn escape_policy_id(
    kind: EscapePolicyKind,
    operator_commitment: &str,
    policy_root: &str,
    activated_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:policy-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(policy_root),
            HashPart::U64(activated_height),
        ],
        16,
    )
}

pub fn exit_request_id(
    kind: EscapeRequestKind,
    lane: ExitLane,
    policy_id: &str,
    note_nullifier: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:exit-request-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(policy_id),
            HashPart::Str(note_nullifier),
            HashPart::U64(submitted_height),
        ],
        16,
    )
}

pub fn pq_proof_id(
    request_id: &str,
    proof_root: &str,
    signature_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:pq-proof-id",
        &[
            HashPart::Str(request_id),
            HashPart::Str(proof_root),
            HashPart::Str(signature_root),
            HashPart::U64(submitted_height),
        ],
        16,
    )
}

pub fn liquidity_quote_id(
    request_id: &str,
    relayer_commitment: &str,
    quote_root: &str,
    posted_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:liquidity-quote-id",
        &[
            HashPart::Str(request_id),
            HashPart::Str(relayer_commitment),
            HashPart::Str(quote_root),
            HashPart::U64(posted_height),
        ],
        16,
    )
}

pub fn rescue_batch_id(
    lane: ExitLane,
    policy_id: &str,
    batch_root: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:rescue-batch-id",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(policy_id),
            HashPart::Str(batch_root),
            HashPart::U64(created_height),
        ],
        16,
    )
}

pub fn watcher_attestation_id(
    batch_id: &str,
    watcher_set_root: &str,
    quorum_signature_root: &str,
    attested_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:watcher-attestation-id",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(watcher_set_root),
            HashPart::Str(quorum_signature_root),
            HashPart::U64(attested_height),
        ],
        16,
    )
}

pub fn receipt_id(
    batch_id: &str,
    monero_txset_root: &str,
    pq_receipt_signature_root: &str,
    published_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:receipt-id",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(monero_txset_root),
            HashPart::Str(pq_receipt_signature_root),
            HashPart::U64(published_height),
        ],
        16,
    )
}

pub fn rebate_id(
    request_id: &str,
    receipt_id: &str,
    beneficiary_commitment: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:rebate-id",
        &[
            HashPart::Str(request_id),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(issued_height),
        ],
        16,
    )
}

pub fn slashing_evidence_id(
    subject_commitment: &str,
    reason: SlashReason,
    evidence_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:slashing-evidence-id",
        &[
            HashPart::Str(subject_commitment),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(submitted_height),
        ],
        16,
    )
}

pub fn checkpoint_id(state_root: &str, height: u64) -> String {
    domain_hash(
        "monero-l2-pq-private-rollup-escape-hatch:checkpoint-id",
        &[HashPart::Str(state_root), HashPart::U64(height)],
        16,
    )
}

pub fn rescue_batch_root(
    lane: ExitLane,
    policy_id: &str,
    request_ids: &[String],
    quote_ids: &[String],
    nullifier_root: &str,
    bridge_context_root: &str,
) -> String {
    let record = json!({
        "lane": lane.as_str(),
        "policy_id": policy_id,
        "request_ids": request_ids,
        "quote_ids": quote_ids,
        "nullifier_root": nullifier_root,
        "bridge_context_root": bridge_context_root,
    });
    root_from_record(
        "monero-l2-pq-private-rollup-escape-hatch:rescue-batch-root",
        &record,
    )
}

pub fn root_from_strings(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "monero-l2-pq-private-rollup-escape-hatch:state-root",
        record,
    )
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).expect("serializable map value"),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
