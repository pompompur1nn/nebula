use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqFastFinalityBridgeRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-fast-finality-bridge-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_HEIGHT: u64 = 640_000;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-fast-finality-bridge-devnet-committee";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_HEADER_CHECKPOINT_SCHEME: &str =
    "roots-only-monero-header-checkpoint-root-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-fast-finality-committee-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_NOTE_MANIFEST_SCHEME: &str =
    "private-bridge-note-manifest-roots-only-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_EXIT_LIQUIDITY_SCHEME: &str =
    "fast-exit-liquidity-confirmation-root-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_SETTLEMENT_WINDOW_SCHEME: &str =
    "low-fee-private-settlement-window-root-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DISPUTE_RECEIPT_SCHEME: &str =
    "pq-fast-finality-bridge-dispute-receipt-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_FINALITY_RECEIPT_SCHEME: &str =
    "pq-fast-finality-private-bridge-receipt-v1";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-fast-finality-bridge-devnet";
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_L2_FINALITY_DEPTH: u64 = 4;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MANIFEST_TTL_BLOCKS: u64 = 48;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_LIQUIDITY_TTL_BLOCKS: u64 = 36;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 96;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 67;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 6;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 32;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_CHECKPOINTS: usize = 262_144;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_ATTESTATIONS: usize = 524_288;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_MANIFESTS: usize = 524_288;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_LIQUIDITY_CONFIRMATIONS: usize = 524_288;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_SETTLEMENT_WINDOWS: usize = 262_144;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_DISPUTES: usize = 262_144;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    PrivateEntry,
    PrivateExit,
    Bidirectional,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateEntry => "private_entry",
            Self::PrivateExit => "private_exit",
            Self::Bidirectional => "bidirectional",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Proposed,
    Attested,
    StrongQuorum,
    Finalized,
    Disputed,
    Rejected,
    Expired,
}

impl FinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::StrongQuorum => "strong_quorum",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Published,
    LiquidityConfirmed,
    SettlementQueued,
    Settled,
    Disputed,
    Expired,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::LiquidityConfirmed => "liquidity_confirmed",
            Self::SettlementQueued => "settlement_queued",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityStatus {
    Confirmed,
    FinalityLocked,
    Released,
    Settled,
    Disputed,
    Expired,
}

impl LiquidityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::FinalityLocked => "finality_locked",
            Self::Released => "released",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementWindowStatus {
    Open,
    Sealed,
    Finalized,
    Disputed,
    Expired,
}

impl SettlementWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    HeaderReorg,
    WeakPqQuorum,
    InvalidNoteManifest,
    LiquidityDefault,
    SettlementMismatch,
    PrivacyLeak,
    ReplayOrDoubleSpend,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderReorg => "header_reorg",
            Self::WeakPqQuorum => "weak_pq_quorum",
            Self::InvalidNoteManifest => "invalid_note_manifest",
            Self::LiquidityDefault => "liquidity_default",
            Self::SettlementMismatch => "settlement_mismatch",
            Self::PrivacyLeak => "privacy_leak",
            Self::ReplayOrDoubleSpend => "replay_or_double_spend",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidenceSubmitted,
    Sustained,
    Rejected,
    Expired,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    HeaderCheckpointed,
    CommitteeAttested,
    NoteManifestPublished,
    LiquidityConfirmed,
    SettlementWindowOpened,
    SettlementFinalized,
    DisputeFiled,
    DisputeResolved,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderCheckpointed => "header_checkpointed",
            Self::CommitteeAttested => "committee_attested",
            Self::NoteManifestPublished => "note_manifest_published",
            Self::LiquidityConfirmed => "liquidity_confirmed",
            Self::SettlementWindowOpened => "settlement_window_opened",
            Self::SettlementFinalized => "settlement_finalized",
            Self::DisputeFiled => "dispute_filed",
            Self::DisputeResolved => "dispute_resolved",
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
    pub asset_id: String,
    pub fee_asset_id: String,
    pub committee_id: String,
    pub hash_suite: String,
    pub header_checkpoint_scheme: String,
    pub pq_attestation_scheme: String,
    pub note_manifest_scheme: String,
    pub exit_liquidity_scheme: String,
    pub settlement_window_scheme: String,
    pub dispute_receipt_scheme: String,
    pub finality_receipt_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub monero_finality_depth: u64,
    pub l2_finality_depth: u64,
    pub attestation_ttl_blocks: u64,
    pub manifest_ttl_blocks: u64,
    pub liquidity_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub dispute_window_blocks: u64,
    pub min_committee_weight: u64,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub roots_only: bool,
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
            schema_version: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(),
            committee_id: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_COMMITTEE_ID.to_string(),
            hash_suite: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_HASH_SUITE.to_string(),
            header_checkpoint_scheme:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_HEADER_CHECKPOINT_SCHEME.to_string(),
            pq_attestation_scheme: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_PQ_ATTESTATION_SCHEME
                .to_string(),
            note_manifest_scheme: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_NOTE_MANIFEST_SCHEME
                .to_string(),
            exit_liquidity_scheme: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_EXIT_LIQUIDITY_SCHEME
                .to_string(),
            settlement_window_scheme:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_SETTLEMENT_WINDOW_SCHEME.to_string(),
            dispute_receipt_scheme:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DISPUTE_RECEIPT_SCHEME.to_string(),
            finality_receipt_scheme:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_FINALITY_RECEIPT_SCHEME.to_string(),
            replay_domain: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_REPLAY_DOMAIN.to_string(),
            genesis_height: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEVNET_HEIGHT,
            monero_finality_depth:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MONERO_FINALITY_DEPTH,
            l2_finality_depth: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_L2_FINALITY_DEPTH,
            attestation_ttl_blocks:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            manifest_ttl_blocks:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MANIFEST_TTL_BLOCKS,
            liquidity_ttl_blocks:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_LIQUIDITY_TTL_BLOCKS,
            settlement_window_blocks:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            dispute_window_blocks:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            min_committee_weight:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT,
            committee_quorum_bps:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_STRONG_QUORUM_BPS,
            min_pq_security_bits:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size:
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            low_fee_bps: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require(
            self.roots_only,
            "pq fast finality bridge must remain roots-only",
        )?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("asset_id", &self.asset_id)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        required("committee_id", &self.committee_id)?;
        require(
            self.monero_finality_depth > 0,
            "monero finality depth is zero",
        )?;
        require(self.l2_finality_depth > 0, "l2 finality depth is zero")?;
        require(self.attestation_ttl_blocks > 0, "attestation ttl is zero")?;
        require(self.manifest_ttl_blocks > 0, "manifest ttl is zero")?;
        require(self.liquidity_ttl_blocks > 0, "liquidity ttl is zero")?;
        require(
            self.settlement_window_blocks > 0,
            "settlement window is zero",
        )?;
        require(self.dispute_window_blocks > 0, "dispute window is zero")?;
        require(
            self.min_committee_weight > 0,
            "minimum committee weight is zero",
        )?;
        require(
            self.committee_quorum_bps > 0
                && self.committee_quorum_bps <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_BPS,
            "committee quorum bps invalid",
        )?;
        require(
            self.strong_quorum_bps >= self.committee_quorum_bps
                && self.strong_quorum_bps <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_BPS,
            "strong quorum bps invalid",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "minimum pq security below policy",
        )?;
        require(self.min_privacy_set_size > 0, "privacy set size is zero")?;
        require(
            self.low_fee_bps <= self.max_user_fee_bps
                && self.max_user_fee_bps <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_BPS,
            "fee bps policy invalid",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub checkpoint_counter: u64,
    pub attestation_counter: u64,
    pub manifest_counter: u64,
    pub liquidity_confirmation_counter: u64,
    pub settlement_window_counter: u64,
    pub dispute_counter: u64,
    pub receipt_counter: u64,
    pub finalized_manifests: u64,
    pub settled_liquidity_confirmations: u64,
    pub disputes_sustained: u64,
    pub disputes_rejected: u64,
    pub low_fee_windows_opened: u64,
    pub total_manifest_amount_piconero: u128,
    pub total_low_fee_piconero: u128,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub checkpoint_root: String,
    pub attestation_root: String,
    pub note_manifest_root: String,
    pub liquidity_confirmation_root: String,
    pub settlement_window_root: String,
    pub dispute_receipt_root: String,
    pub finality_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroHeaderCheckpoint {
    pub checkpoint_id: String,
    pub sequence: u64,
    pub submitter_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub cumulative_difficulty_root: String,
    pub pow_context_root: String,
    pub tx_tree_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub header_chain_root: String,
    pub checkpoint_root: String,
    pub status: FinalityStatus,
    pub expires_at_l2_height: u64,
}

impl MoneroHeaderCheckpoint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-HEADER-CHECKPOINT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFinalityCommitteeAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub checkpoint_id: String,
    pub committee_id: String,
    pub epoch: u64,
    pub signer_count: u64,
    pub signer_weight: u64,
    pub total_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum: bool,
    pub pq_security_bits: u16,
    pub finality_state_root: String,
    pub header_checkpoint_root: String,
    pub bridge_note_root: String,
    pub liquidity_root: String,
    pub aggregate_ml_dsa_signature_root: String,
    pub aggregate_slh_dsa_signature_root: String,
    pub committee_bitmap_root: String,
    pub status: FinalityStatus,
    pub expires_at_l2_height: u64,
}

impl PqFinalityCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-PQ-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBridgeNoteManifestRecord {
    pub manifest_id: String,
    pub sequence: u64,
    pub checkpoint_id: String,
    pub attestation_id: String,
    pub operator_id: String,
    pub direction: BridgeDirection,
    pub note_count: u64,
    pub amount_piconero: u128,
    pub privacy_set_size: u64,
    pub encrypted_note_bundle_root: String,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub recipient_ciphertext_root: String,
    pub view_tag_root: String,
    pub release_authorization_root: String,
    pub fee_commitment_root: String,
    pub manifest_nonce: String,
    pub status: ManifestStatus,
    pub expires_at_l2_height: u64,
}

impl PrivateBridgeNoteManifestRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-NOTE-MANIFEST",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitLiquidityConfirmationRecord {
    pub confirmation_id: String,
    pub sequence: u64,
    pub manifest_id: String,
    pub liquidity_provider_id: String,
    pub vault_id: String,
    pub amount_piconero: u128,
    pub fee_piconero: u128,
    pub max_fee_bps: u64,
    pub reserve_proof_root: String,
    pub liquidity_lock_root: String,
    pub release_tx_root: String,
    pub settlement_commitment_root: String,
    pub pq_signature_root: String,
    pub status: LiquidityStatus,
    pub expires_at_l2_height: u64,
}

impl FastExitLiquidityConfirmationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-LIQUIDITY-CONFIRMATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettlementWindowRecord {
    pub window_id: String,
    pub sequence: u64,
    pub coordinator_id: String,
    pub manifest_root: String,
    pub liquidity_confirmation_root: String,
    pub included_manifest_ids: Vec<String>,
    pub opened_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub aggregate_amount_piconero: u128,
    pub aggregate_fee_piconero: u128,
    pub settlement_batch_root: String,
    pub withdrawal_release_root: String,
    pub pq_signature_root: String,
    pub status: SettlementWindowStatus,
}

impl LowFeeSettlementWindowRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-SETTLEMENT-WINDOW",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeReceiptRecord {
    pub dispute_id: String,
    pub sequence: u64,
    pub challenger_id: String,
    pub kind: DisputeKind,
    pub status: DisputeStatus,
    pub checkpoint_id: Option<String>,
    pub attestation_id: Option<String>,
    pub manifest_id: Option<String>,
    pub confirmation_id: Option<String>,
    pub window_id: Option<String>,
    pub allegation_root: String,
    pub encrypted_evidence_root: String,
    pub selective_disclosure_root: String,
    pub bond_commitment_root: String,
    pub resolution_root: String,
    pub opened_l2_height: u64,
    pub deadline_l2_height: u64,
    pub dispute_nonce: String,
}

impl DisputeReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-DISPUTE-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityBridgeReceiptRecord {
    pub receipt_id: String,
    pub sequence: u64,
    pub kind: ReceiptKind,
    pub actor_id: String,
    pub checkpoint_id: Option<String>,
    pub attestation_id: Option<String>,
    pub manifest_id: Option<String>,
    pub confirmation_id: Option<String>,
    pub window_id: Option<String>,
    pub dispute_id: Option<String>,
    pub issued_l2_height: u64,
    pub event_root: String,
    pub receipt_root: String,
}

impl FinalityBridgeReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderCheckpointRequest {
    pub submitter_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub cumulative_difficulty_root: String,
    pub pow_context_root: String,
    pub tx_tree_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub header_chain_root: String,
    pub checkpoint_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFinalityCommitteeAttestationRequest {
    pub checkpoint_id: String,
    pub committee_id: String,
    pub epoch: u64,
    pub signer_count: u64,
    pub signer_weight: u64,
    pub total_weight: u64,
    pub pq_security_bits: u16,
    pub finality_state_root: String,
    pub header_checkpoint_root: String,
    pub bridge_note_root: String,
    pub liquidity_root: String,
    pub aggregate_ml_dsa_signature_root: String,
    pub aggregate_slh_dsa_signature_root: String,
    pub committee_bitmap_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBridgeNoteManifestRequest {
    pub checkpoint_id: String,
    pub attestation_id: String,
    pub operator_id: String,
    pub direction: BridgeDirection,
    pub note_count: u64,
    pub amount_piconero: u128,
    pub privacy_set_size: u64,
    pub encrypted_note_bundle_root: String,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub recipient_ciphertext_root: String,
    pub view_tag_root: String,
    pub release_authorization_root: String,
    pub fee_commitment_root: String,
    pub manifest_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitLiquidityConfirmationRequest {
    pub manifest_id: String,
    pub liquidity_provider_id: String,
    pub vault_id: String,
    pub amount_piconero: u128,
    pub fee_piconero: u128,
    pub max_fee_bps: u64,
    pub reserve_proof_root: String,
    pub liquidity_lock_root: String,
    pub release_tx_root: String,
    pub settlement_commitment_root: String,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettlementWindowRequest {
    pub coordinator_id: String,
    pub included_manifest_ids: Vec<String>,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub settlement_batch_root: String,
    pub withdrawal_release_root: String,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeReceiptRequest {
    pub challenger_id: String,
    pub kind: DisputeKind,
    pub checkpoint_id: Option<String>,
    pub attestation_id: Option<String>,
    pub manifest_id: Option<String>,
    pub confirmation_id: Option<String>,
    pub window_id: Option<String>,
    pub allegation_root: String,
    pub encrypted_evidence_root: String,
    pub selective_disclosure_root: String,
    pub bond_commitment_root: String,
    pub dispute_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveDisputeRequest {
    pub dispute_id: String,
    pub resolver_id: String,
    pub sustained: bool,
    pub resolution_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeSettlementWindowRequest {
    pub window_id: String,
    pub finalizer_id: String,
    pub final_settlement_root: String,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub counters: Counters,
    pub checkpoints: BTreeMap<String, MoneroHeaderCheckpoint>,
    pub attestations: BTreeMap<String, PqFinalityCommitteeAttestation>,
    pub manifests: BTreeMap<String, PrivateBridgeNoteManifestRecord>,
    pub liquidity_confirmations: BTreeMap<String, FastExitLiquidityConfirmationRecord>,
    pub settlement_windows: BTreeMap<String, LowFeeSettlementWindowRecord>,
    pub disputes: BTreeMap<String, DisputeReceiptRecord>,
    pub receipts: BTreeMap<String, FinalityBridgeReceiptRecord>,
    pub nullifiers: BTreeSet<String>,
    pub manifests_by_checkpoint: BTreeMap<String, BTreeSet<String>>,
    pub liquidity_by_manifest: BTreeMap<String, BTreeSet<String>>,
    pub windows_by_manifest: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> Self {
        let current_l2_height = config.genesis_height;
        Self {
            config,
            current_l2_height,
            counters: Counters::default(),
            checkpoints: BTreeMap::new(),
            attestations: BTreeMap::new(),
            manifests: BTreeMap::new(),
            liquidity_confirmations: BTreeMap::new(),
            settlement_windows: BTreeMap::new(),
            disputes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            manifests_by_checkpoint: BTreeMap::new(),
            liquidity_by_manifest: BTreeMap::new(),
            windows_by_manifest: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn record_header_checkpoint(
        &mut self,
        request: HeaderCheckpointRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<MoneroHeaderCheckpoint> {
        self.config.validate()?;
        ensure_capacity(
            self.checkpoints.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_CHECKPOINTS,
            "checkpoints",
        )?;
        required("submitter_id", &request.submitter_id)?;
        required("checkpoint_nonce", &request.checkpoint_nonce)?;
        validate_root("block_hash_root", &request.block_hash_root)?;
        validate_root(
            "previous_block_hash_root",
            &request.previous_block_hash_root,
        )?;
        validate_root(
            "cumulative_difficulty_root",
            &request.cumulative_difficulty_root,
        )?;
        validate_root("pow_context_root", &request.pow_context_root)?;
        validate_root("tx_tree_root", &request.tx_tree_root)?;
        validate_root("output_root", &request.output_root)?;
        validate_root("key_image_root", &request.key_image_root)?;
        validate_root("header_chain_root", &request.header_chain_root)?;
        self.current_l2_height = self.current_l2_height.max(request.l2_height);
        self.counters.checkpoint_counter = self.counters.checkpoint_counter.saturating_add(1);
        let sequence = self.counters.checkpoint_counter;
        let checkpoint_commitment_root = monero_header_checkpoint_commitment(&request, sequence);
        let checkpoint_id =
            monero_header_checkpoint_id(&request, sequence, &checkpoint_commitment_root);
        let record = MoneroHeaderCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            sequence,
            submitter_id: request.submitter_id,
            monero_height: request.monero_height,
            l2_height: request.l2_height,
            block_hash_root: request.block_hash_root,
            previous_block_hash_root: request.previous_block_hash_root,
            cumulative_difficulty_root: request.cumulative_difficulty_root,
            pow_context_root: request.pow_context_root,
            tx_tree_root: request.tx_tree_root,
            output_root: request.output_root,
            key_image_root: request.key_image_root,
            header_chain_root: request.header_chain_root,
            checkpoint_root: checkpoint_commitment_root,
            status: FinalityStatus::Proposed,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.checkpoints
            .insert(checkpoint_id.clone(), record.clone());
        self.record_public(
            format!("checkpoint:{checkpoint_id}"),
            record.public_record(),
        )?;
        let _ = self.issue_receipt(
            ReceiptKind::HeaderCheckpointed,
            &record.submitter_id,
            Some(&checkpoint_id),
            None,
            None,
            None,
            None,
            None,
            record.checkpoint_root.clone(),
        )?;
        Ok(record)
    }

    pub fn attest_checkpoint(
        &mut self,
        request: PqFinalityCommitteeAttestationRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<PqFinalityCommitteeAttestation> {
        self.config.validate()?;
        ensure_capacity(
            self.attestations.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_ATTESTATIONS,
            "attestations",
        )?;
        required("checkpoint_id", &request.checkpoint_id)?;
        required("committee_id", &request.committee_id)?;
        validate_attestation_policy(&request, &self.config)?;
        let checkpoint = self
            .checkpoints
            .get(&request.checkpoint_id)
            .ok_or_else(|| "checkpoint not found".to_string())?
            .clone();
        require(
            !checkpoint.status.terminal(),
            "checkpoint is already terminal",
        )?;
        self.counters.attestation_counter = self.counters.attestation_counter.saturating_add(1);
        let sequence = self.counters.attestation_counter;
        let quorum_bps = bps(request.signer_weight, request.total_weight);
        let strong_quorum = quorum_bps >= self.config.strong_quorum_bps;
        let status = if strong_quorum {
            FinalityStatus::StrongQuorum
        } else {
            FinalityStatus::Attested
        };
        let attestation_id = pq_finality_committee_attestation_id(&request, sequence, quorum_bps);
        let record = PqFinalityCommitteeAttestation {
            attestation_id: attestation_id.clone(),
            sequence,
            checkpoint_id: request.checkpoint_id.clone(),
            committee_id: request.committee_id,
            epoch: request.epoch,
            signer_count: request.signer_count,
            signer_weight: request.signer_weight,
            total_weight: request.total_weight,
            quorum_bps,
            strong_quorum,
            pq_security_bits: request.pq_security_bits,
            finality_state_root: request.finality_state_root,
            header_checkpoint_root: request.header_checkpoint_root,
            bridge_note_root: request.bridge_note_root,
            liquidity_root: request.liquidity_root,
            aggregate_ml_dsa_signature_root: request.aggregate_ml_dsa_signature_root,
            aggregate_slh_dsa_signature_root: request.aggregate_slh_dsa_signature_root,
            committee_bitmap_root: request.committee_bitmap_root,
            status,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.manifest_ttl_blocks),
        };
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        if let Some(checkpoint) = self.checkpoints.get_mut(&request.checkpoint_id) {
            checkpoint.status = status;
        }
        self.record_public(
            format!("attestation:{attestation_id}"),
            record.public_record(),
        )?;
        let _ = self.issue_receipt(
            ReceiptKind::CommitteeAttested,
            &record.committee_id,
            Some(&record.checkpoint_id),
            Some(&attestation_id),
            None,
            None,
            None,
            None,
            record.state_root(),
        )?;
        Ok(record)
    }

    pub fn publish_note_manifest(
        &mut self,
        request: PrivateBridgeNoteManifestRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<PrivateBridgeNoteManifestRecord> {
        self.config.validate()?;
        ensure_capacity(
            self.manifests.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_MANIFESTS,
            "manifests",
        )?;
        required("operator_id", &request.operator_id)?;
        required("manifest_nonce", &request.manifest_nonce)?;
        validate_root(
            "encrypted_note_bundle_root",
            &request.encrypted_note_bundle_root,
        )?;
        validate_root("note_commitment_root", &request.note_commitment_root)?;
        validate_root("nullifier_root", &request.nullifier_root)?;
        validate_root(
            "recipient_ciphertext_root",
            &request.recipient_ciphertext_root,
        )?;
        validate_root("view_tag_root", &request.view_tag_root)?;
        validate_root(
            "release_authorization_root",
            &request.release_authorization_root,
        )?;
        validate_root("fee_commitment_root", &request.fee_commitment_root)?;
        require(request.note_count > 0, "manifest note count is zero")?;
        require(request.amount_piconero > 0, "manifest amount is zero")?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "manifest privacy set below floor",
        )?;
        require(
            self.checkpoints.contains_key(&request.checkpoint_id),
            "checkpoint not found",
        )?;
        require(
            self.attestations.contains_key(&request.attestation_id),
            "attestation not found",
        )?;
        require(
            self.nullifiers.insert(request.nullifier_root.clone()),
            "manifest nullifier root already used",
        )?;
        self.counters.manifest_counter = self.counters.manifest_counter.saturating_add(1);
        let sequence = self.counters.manifest_counter;
        let manifest_id = private_bridge_note_manifest_id(&request, sequence);
        let record = PrivateBridgeNoteManifestRecord {
            manifest_id: manifest_id.clone(),
            sequence,
            checkpoint_id: request.checkpoint_id.clone(),
            attestation_id: request.attestation_id,
            operator_id: request.operator_id,
            direction: request.direction,
            note_count: request.note_count,
            amount_piconero: request.amount_piconero,
            privacy_set_size: request.privacy_set_size,
            encrypted_note_bundle_root: request.encrypted_note_bundle_root,
            note_commitment_root: request.note_commitment_root,
            nullifier_root: request.nullifier_root,
            recipient_ciphertext_root: request.recipient_ciphertext_root,
            view_tag_root: request.view_tag_root,
            release_authorization_root: request.release_authorization_root,
            fee_commitment_root: request.fee_commitment_root,
            manifest_nonce: request.manifest_nonce,
            status: ManifestStatus::Published,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.manifest_ttl_blocks),
        };
        self.counters.total_manifest_amount_piconero = self
            .counters
            .total_manifest_amount_piconero
            .saturating_add(record.amount_piconero);
        self.manifests.insert(manifest_id.clone(), record.clone());
        self.manifests_by_checkpoint
            .entry(request.checkpoint_id)
            .or_default()
            .insert(manifest_id.clone());
        self.record_public(format!("manifest:{manifest_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::NoteManifestPublished,
            &record.operator_id,
            Some(&record.checkpoint_id),
            Some(&record.attestation_id),
            Some(&manifest_id),
            None,
            None,
            None,
            record.state_root(),
        )?;
        Ok(record)
    }

    pub fn confirm_fast_exit_liquidity(
        &mut self,
        request: FastExitLiquidityConfirmationRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<FastExitLiquidityConfirmationRecord> {
        self.config.validate()?;
        ensure_capacity(
            self.liquidity_confirmations.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_LIQUIDITY_CONFIRMATIONS,
            "liquidity confirmations",
        )?;
        required("liquidity_provider_id", &request.liquidity_provider_id)?;
        required("vault_id", &request.vault_id)?;
        validate_root("reserve_proof_root", &request.reserve_proof_root)?;
        validate_root("liquidity_lock_root", &request.liquidity_lock_root)?;
        validate_root("release_tx_root", &request.release_tx_root)?;
        validate_root(
            "settlement_commitment_root",
            &request.settlement_commitment_root,
        )?;
        validate_root("pq_signature_root", &request.pq_signature_root)?;
        require(request.amount_piconero > 0, "liquidity amount is zero")?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "liquidity fee bps above bridge cap",
        )?;
        let manifest = self
            .manifests
            .get(&request.manifest_id)
            .ok_or_else(|| "manifest not found".to_string())?
            .clone();
        require(
            request.amount_piconero >= manifest.amount_piconero,
            "liquidity confirmation underfunds manifest",
        )?;
        require(
            request.fee_piconero <= fee_for_amount(request.amount_piconero, request.max_fee_bps),
            "liquidity fee exceeds cap",
        )?;
        self.counters.liquidity_confirmation_counter = self
            .counters
            .liquidity_confirmation_counter
            .saturating_add(1);
        let sequence = self.counters.liquidity_confirmation_counter;
        let confirmation_id = fast_exit_liquidity_confirmation_id(&request, sequence);
        let record = FastExitLiquidityConfirmationRecord {
            confirmation_id: confirmation_id.clone(),
            sequence,
            manifest_id: request.manifest_id.clone(),
            liquidity_provider_id: request.liquidity_provider_id,
            vault_id: request.vault_id,
            amount_piconero: request.amount_piconero,
            fee_piconero: request.fee_piconero,
            max_fee_bps: request.max_fee_bps,
            reserve_proof_root: request.reserve_proof_root,
            liquidity_lock_root: request.liquidity_lock_root,
            release_tx_root: request.release_tx_root,
            settlement_commitment_root: request.settlement_commitment_root,
            pq_signature_root: request.pq_signature_root,
            status: LiquidityStatus::Confirmed,
            expires_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.liquidity_ttl_blocks),
        };
        self.liquidity_confirmations
            .insert(confirmation_id.clone(), record.clone());
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest.status = ManifestStatus::LiquidityConfirmed;
        }
        self.liquidity_by_manifest
            .entry(request.manifest_id)
            .or_default()
            .insert(confirmation_id.clone());
        self.record_public(
            format!("liquidity_confirmation:{confirmation_id}"),
            record.public_record(),
        )?;
        let _ = self.issue_receipt(
            ReceiptKind::LiquidityConfirmed,
            &record.liquidity_provider_id,
            None,
            None,
            Some(&record.manifest_id),
            Some(&confirmation_id),
            None,
            None,
            record.state_root(),
        )?;
        Ok(record)
    }

    pub fn open_low_fee_settlement_window(
        &mut self,
        request: LowFeeSettlementWindowRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<LowFeeSettlementWindowRecord> {
        self.config.validate()?;
        ensure_capacity(
            self.settlement_windows.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_SETTLEMENT_WINDOWS,
            "settlement windows",
        )?;
        required("coordinator_id", &request.coordinator_id)?;
        validate_root("settlement_batch_root", &request.settlement_batch_root)?;
        validate_root("withdrawal_release_root", &request.withdrawal_release_root)?;
        validate_root("pq_signature_root", &request.pq_signature_root)?;
        require(
            !request.included_manifest_ids.is_empty(),
            "settlement window has no manifests",
        )?;
        require(
            request.low_fee_bps <= self.config.low_fee_bps,
            "settlement window fee exceeds low-fee policy",
        )?;
        require(
            request.max_user_fee_bps <= self.config.max_user_fee_bps,
            "settlement window max fee exceeds policy",
        )?;
        let mut aggregate_amount_piconero = 0u128;
        let mut aggregate_fee_piconero = 0u128;
        for manifest_id in &request.included_manifest_ids {
            let manifest = self
                .manifests
                .get(manifest_id)
                .ok_or_else(|| "settlement manifest not found".to_string())?;
            aggregate_amount_piconero =
                aggregate_amount_piconero.saturating_add(manifest.amount_piconero);
            aggregate_fee_piconero = aggregate_fee_piconero.saturating_add(fee_for_amount(
                manifest.amount_piconero,
                request.low_fee_bps,
            ));
        }
        self.counters.settlement_window_counter =
            self.counters.settlement_window_counter.saturating_add(1);
        let sequence = self.counters.settlement_window_counter;
        let manifest_root = id_list_root("WINDOW-MANIFESTS", &request.included_manifest_ids);
        let liquidity_ids = request
            .included_manifest_ids
            .iter()
            .flat_map(|manifest_id| {
                self.liquidity_by_manifest
                    .get(manifest_id)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let liquidity_confirmation_root = id_list_root("WINDOW-LIQUIDITY", &liquidity_ids);
        let window_id = low_fee_settlement_window_id(
            &request,
            sequence,
            &manifest_root,
            &liquidity_confirmation_root,
        );
        let record = LowFeeSettlementWindowRecord {
            window_id: window_id.clone(),
            sequence,
            coordinator_id: request.coordinator_id,
            manifest_root,
            liquidity_confirmation_root,
            included_manifest_ids: request.included_manifest_ids,
            opened_l2_height: self.current_l2_height,
            closes_at_l2_height: self
                .current_l2_height
                .saturating_add(self.config.settlement_window_blocks),
            low_fee_bps: request.low_fee_bps,
            max_user_fee_bps: request.max_user_fee_bps,
            aggregate_amount_piconero,
            aggregate_fee_piconero,
            settlement_batch_root: request.settlement_batch_root,
            withdrawal_release_root: request.withdrawal_release_root,
            pq_signature_root: request.pq_signature_root,
            status: SettlementWindowStatus::Open,
        };
        for manifest_id in &record.included_manifest_ids {
            if let Some(manifest) = self.manifests.get_mut(manifest_id) {
                manifest.status = ManifestStatus::SettlementQueued;
            }
            self.windows_by_manifest
                .entry(manifest_id.clone())
                .or_default()
                .insert(window_id.clone());
        }
        self.counters.low_fee_windows_opened =
            self.counters.low_fee_windows_opened.saturating_add(1);
        self.counters.total_low_fee_piconero = self
            .counters
            .total_low_fee_piconero
            .saturating_add(record.aggregate_fee_piconero);
        self.settlement_windows
            .insert(window_id.clone(), record.clone());
        self.record_public(
            format!("settlement_window:{window_id}"),
            record.public_record(),
        )?;
        let _ = self.issue_receipt(
            ReceiptKind::SettlementWindowOpened,
            &record.coordinator_id,
            None,
            None,
            None,
            None,
            Some(&window_id),
            None,
            record.state_root(),
        )?;
        Ok(record)
    }

    pub fn finalize_settlement_window(
        &mut self,
        request: FinalizeSettlementWindowRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<FinalityBridgeReceiptRecord> {
        self.config.validate()?;
        required("window_id", &request.window_id)?;
        required("finalizer_id", &request.finalizer_id)?;
        validate_root("final_settlement_root", &request.final_settlement_root)?;
        validate_root("pq_signature_root", &request.pq_signature_root)?;
        let (manifest_ids, window_root, window_public) = {
            let window = self
                .settlement_windows
                .get_mut(&request.window_id)
                .ok_or_else(|| "settlement window not found".to_string())?;
            require(
                window.status == SettlementWindowStatus::Open
                    || window.status == SettlementWindowStatus::Sealed,
                "settlement window is not finalizable",
            )?;
            window.status = SettlementWindowStatus::Finalized;
            (
                window.included_manifest_ids.clone(),
                window.state_root(),
                window.public_record(),
            )
        };
        for manifest_id in manifest_ids {
            if let Some(manifest) = self.manifests.get_mut(&manifest_id) {
                manifest.status = ManifestStatus::Settled;
                self.counters.finalized_manifests =
                    self.counters.finalized_manifests.saturating_add(1);
            }
            if let Some(confirmation_ids) = self.liquidity_by_manifest.get(&manifest_id).cloned() {
                for confirmation_id in confirmation_ids {
                    if let Some(confirmation) =
                        self.liquidity_confirmations.get_mut(&confirmation_id)
                    {
                        confirmation.status = LiquidityStatus::Settled;
                        self.counters.settled_liquidity_confirmations = self
                            .counters
                            .settled_liquidity_confirmations
                            .saturating_add(1);
                    }
                }
            }
        }
        self.record_public(
            format!("settlement_window:{}", request.window_id),
            window_public,
        )?;
        self.issue_receipt(
            ReceiptKind::SettlementFinalized,
            &request.finalizer_id,
            None,
            None,
            None,
            None,
            Some(&request.window_id),
            None,
            final_settlement_commitment(&request, &window_root),
        )
    }

    pub fn file_dispute(
        &mut self,
        request: DisputeReceiptRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<DisputeReceiptRecord> {
        self.config.validate()?;
        ensure_capacity(
            self.disputes.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_DISPUTES,
            "disputes",
        )?;
        required("challenger_id", &request.challenger_id)?;
        required("dispute_nonce", &request.dispute_nonce)?;
        validate_root("allegation_root", &request.allegation_root)?;
        validate_root("encrypted_evidence_root", &request.encrypted_evidence_root)?;
        validate_root(
            "selective_disclosure_root",
            &request.selective_disclosure_root,
        )?;
        validate_root("bond_commitment_root", &request.bond_commitment_root)?;
        require(
            request.checkpoint_id.is_some()
                || request.attestation_id.is_some()
                || request.manifest_id.is_some()
                || request.confirmation_id.is_some()
                || request.window_id.is_some(),
            "dispute must target a bridge record",
        )?;
        self.counters.dispute_counter = self.counters.dispute_counter.saturating_add(1);
        let sequence = self.counters.dispute_counter;
        let dispute_id = dispute_receipt_id(&request, sequence);
        let record = DisputeReceiptRecord {
            dispute_id: dispute_id.clone(),
            sequence,
            challenger_id: request.challenger_id,
            kind: request.kind,
            status: DisputeStatus::Open,
            checkpoint_id: request.checkpoint_id,
            attestation_id: request.attestation_id,
            manifest_id: request.manifest_id,
            confirmation_id: request.confirmation_id,
            window_id: request.window_id,
            allegation_root: request.allegation_root,
            encrypted_evidence_root: request.encrypted_evidence_root,
            selective_disclosure_root: request.selective_disclosure_root,
            bond_commitment_root: request.bond_commitment_root,
            resolution_root: empty_root("MONERO-L2-PQ-FAST-FINALITY-BRIDGE-EMPTY-RESOLUTION"),
            opened_l2_height: self.current_l2_height,
            deadline_l2_height: self
                .current_l2_height
                .saturating_add(self.config.dispute_window_blocks),
            dispute_nonce: request.dispute_nonce,
        };
        self.mark_disputed(&record);
        self.disputes.insert(dispute_id.clone(), record.clone());
        self.record_public(format!("dispute:{dispute_id}"), record.public_record())?;
        let _ = self.issue_receipt(
            ReceiptKind::DisputeFiled,
            &record.challenger_id,
            record.checkpoint_id.as_deref(),
            record.attestation_id.as_deref(),
            record.manifest_id.as_deref(),
            record.confirmation_id.as_deref(),
            record.window_id.as_deref(),
            Some(&dispute_id),
            record.state_root(),
        )?;
        Ok(record)
    }

    pub fn resolve_dispute(
        &mut self,
        request: ResolveDisputeRequest,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<FinalityBridgeReceiptRecord> {
        self.config.validate()?;
        required("dispute_id", &request.dispute_id)?;
        required("resolver_id", &request.resolver_id)?;
        validate_root("resolution_root", &request.resolution_root)?;
        let (
            dispute_root,
            dispute_public,
            checkpoint_id,
            attestation_id,
            manifest_id,
            confirmation_id,
            window_id,
        ) = {
            let dispute = self
                .disputes
                .get_mut(&request.dispute_id)
                .ok_or_else(|| "dispute not found".to_string())?;
            require(
                dispute.status == DisputeStatus::Open
                    || dispute.status == DisputeStatus::EvidenceSubmitted,
                "dispute is not resolvable",
            )?;
            dispute.status = if request.sustained {
                self.counters.disputes_sustained =
                    self.counters.disputes_sustained.saturating_add(1);
                DisputeStatus::Sustained
            } else {
                self.counters.disputes_rejected = self.counters.disputes_rejected.saturating_add(1);
                DisputeStatus::Rejected
            };
            dispute.resolution_root = request.resolution_root;
            (
                dispute.state_root(),
                dispute.public_record(),
                dispute.checkpoint_id.clone(),
                dispute.attestation_id.clone(),
                dispute.manifest_id.clone(),
                dispute.confirmation_id.clone(),
                dispute.window_id.clone(),
            )
        };
        self.record_public(format!("dispute:{}", request.dispute_id), dispute_public)?;
        self.issue_receipt(
            ReceiptKind::DisputeResolved,
            &request.resolver_id,
            checkpoint_id.as_deref(),
            attestation_id.as_deref(),
            manifest_id.as_deref(),
            confirmation_id.as_deref(),
            window_id.as_deref(),
            Some(&request.dispute_id),
            dispute_root,
        )
    }

    pub fn advance_l2_height(&mut self, next_height: u64) {
        self.current_l2_height = self.current_l2_height.max(next_height);
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters().state_root(),
            checkpoint_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-CHECKPOINTS",
                &self.checkpoints,
                MoneroHeaderCheckpoint::public_record,
            ),
            attestation_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-ATTESTATIONS",
                &self.attestations,
                PqFinalityCommitteeAttestation::public_record,
            ),
            note_manifest_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-NOTE-MANIFESTS",
                &self.manifests,
                PrivateBridgeNoteManifestRecord::public_record,
            ),
            liquidity_confirmation_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-LIQUIDITY-CONFIRMATIONS",
                &self.liquidity_confirmations,
                FastExitLiquidityConfirmationRecord::public_record,
            ),
            settlement_window_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-SETTLEMENT-WINDOWS",
                &self.settlement_windows,
                LowFeeSettlementWindowRecord::public_record,
            ),
            dispute_receipt_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-DISPUTES",
                &self.disputes,
                DisputeReceiptRecord::public_record,
            ),
            finality_receipt_root: map_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-RECEIPTS",
                &self.receipts,
                FinalityBridgeReceiptRecord::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-NULLIFIERS",
                &self.nullifiers,
            ),
            public_record_root: map_value_root(
                "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-PUBLIC-RECORDS",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_pq_fast_finality_bridge_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_SCHEMA_VERSION,
            "privacy_boundary": "roots_only_no_plaintext_monero_addresses_no_amounts_no_view_keys_encrypted_note_manifests_only",
            "current_l2_height": self.current_l2_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
            "checkpoint_count": self.checkpoints.len(),
            "attestation_count": self.attestations.len(),
            "manifest_count": self.manifests.len(),
            "liquidity_confirmation_count": self.liquidity_confirmations.len(),
            "settlement_window_count": self.settlement_windows.len(),
            "dispute_count": self.disputes.len(),
            "receipt_count": self.receipts.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        monero_l2_pq_fast_finality_bridge_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
        self.config.validate()?;
        require(
            self.checkpoints.len() <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_CHECKPOINTS,
            "too many checkpoints",
        )?;
        require(
            self.attestations.len() <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_ATTESTATIONS,
            "too many attestations",
        )?;
        require(
            self.manifests.len() <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_MANIFESTS,
            "too many manifests",
        )?;
        require(
            self.liquidity_confirmations.len()
                <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_LIQUIDITY_CONFIRMATIONS,
            "too many liquidity confirmations",
        )?;
        require(
            self.settlement_windows.len()
                <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_SETTLEMENT_WINDOWS,
            "too many settlement windows",
        )?;
        require(
            self.disputes.len() <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_DISPUTES,
            "too many disputes",
        )?;
        require(
            self.receipts.len() <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_RECEIPTS,
            "too many receipts",
        )?;
        require(
            self.public_records.len()
                <= MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_PUBLIC_RECORDS,
            "too many public records",
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_receipt(
        &mut self,
        kind: ReceiptKind,
        actor_id: &str,
        checkpoint_id: Option<&str>,
        attestation_id: Option<&str>,
        manifest_id: Option<&str>,
        confirmation_id: Option<&str>,
        window_id: Option<&str>,
        dispute_id: Option<&str>,
        event_root: String,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<FinalityBridgeReceiptRecord> {
        ensure_capacity(
            self.receipts.len(),
            MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_RECEIPTS,
            "receipts",
        )?;
        required("actor_id", actor_id)?;
        validate_root("event_root", &event_root)?;
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let sequence = self.counters.receipt_counter;
        let receipt_root = finality_bridge_receipt_commitment(
            sequence,
            kind,
            actor_id,
            checkpoint_id,
            attestation_id,
            manifest_id,
            confirmation_id,
            window_id,
            dispute_id,
            self.current_l2_height,
            &event_root,
        );
        let receipt_id = finality_bridge_receipt_id(sequence, &receipt_root);
        let record = FinalityBridgeReceiptRecord {
            receipt_id: receipt_id.clone(),
            sequence,
            kind,
            actor_id: actor_id.to_string(),
            checkpoint_id: checkpoint_id.map(str::to_string),
            attestation_id: attestation_id.map(str::to_string),
            manifest_id: manifest_id.map(str::to_string),
            confirmation_id: confirmation_id.map(str::to_string),
            window_id: window_id.map(str::to_string),
            dispute_id: dispute_id.map(str::to_string),
            issued_l2_height: self.current_l2_height,
            event_root,
            receipt_root,
        };
        self.receipts.insert(receipt_id.clone(), record.clone());
        self.record_public(format!("receipt:{receipt_id}"), record.public_record())?;
        Ok(record)
    }

    fn record_public(
        &mut self,
        key: String,
        record: Value,
    ) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
        if !self.public_records.contains_key(&key) {
            ensure_capacity(
                self.public_records.len(),
                MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_PUBLIC_RECORDS,
                "public records",
            )?;
        }
        self.public_records.insert(key, record);
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    fn mark_disputed(&mut self, dispute: &DisputeReceiptRecord) {
        if let Some(checkpoint_id) = dispute.checkpoint_id.as_deref() {
            if let Some(checkpoint) = self.checkpoints.get_mut(checkpoint_id) {
                checkpoint.status = FinalityStatus::Disputed;
            }
        }
        if let Some(attestation_id) = dispute.attestation_id.as_deref() {
            if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                attestation.status = FinalityStatus::Disputed;
            }
        }
        if let Some(manifest_id) = dispute.manifest_id.as_deref() {
            if let Some(manifest) = self.manifests.get_mut(manifest_id) {
                manifest.status = ManifestStatus::Disputed;
            }
        }
        if let Some(confirmation_id) = dispute.confirmation_id.as_deref() {
            if let Some(confirmation) = self.liquidity_confirmations.get_mut(confirmation_id) {
                confirmation.status = LiquidityStatus::Disputed;
            }
        }
        if let Some(window_id) = dispute.window_id.as_deref() {
            if let Some(window) = self.settlement_windows.get_mut(window_id) {
                window.status = SettlementWindowStatus::Disputed;
            }
        }
    }
}

pub fn monero_l2_pq_fast_finality_bridge_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_fast_finality_bridge_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_fast_finality_bridge_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn monero_l2_pq_fast_finality_bridge_runtime_state_root_from_record(record: &Value) -> String {
    record_root("MONERO-L2-PQ-FAST-FINALITY-BRIDGE-STATE", record)
}

pub fn monero_header_checkpoint_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-HEADER-CHECKPOINT-ROOT",
        records,
    )
}

pub fn pq_finality_committee_attestation_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-COMMITTEE-ATTESTATION-ROOT",
        records,
    )
}

pub fn private_bridge_note_manifest_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-NOTE-MANIFEST-ROOT",
        records,
    )
}

pub fn fast_exit_liquidity_confirmation_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-LIQUIDITY-CONFIRMATION-ROOT",
        records,
    )
}

pub fn low_fee_settlement_window_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-SETTLEMENT-WINDOW-ROOT",
        records,
    )
}

pub fn dispute_receipt_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-DISPUTE-RECEIPT-ROOT",
        records,
    )
}

pub fn monero_header_checkpoint_commitment(
    request: &HeaderCheckpointRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-HEADER-CHECKPOINT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.submitter_id),
            HashPart::Int(request.monero_height as i128),
            HashPart::Int(request.l2_height as i128),
            HashPart::Str(&request.block_hash_root),
            HashPart::Str(&request.previous_block_hash_root),
            HashPart::Str(&request.cumulative_difficulty_root),
            HashPart::Str(&request.header_chain_root),
            HashPart::Str(&request.checkpoint_nonce),
        ],
        32,
    )
}

pub fn monero_header_checkpoint_id(
    request: &HeaderCheckpointRequest,
    sequence: u64,
    checkpoint_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-HEADER-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Int(request.monero_height as i128),
            HashPart::Int(request.l2_height as i128),
            HashPart::Str(checkpoint_root),
            HashPart::Str(&request.checkpoint_nonce),
        ],
        32,
    )
}

pub fn pq_finality_committee_attestation_id(
    request: &PqFinalityCommitteeAttestationRequest,
    sequence: u64,
    quorum_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.committee_id),
            HashPart::Int(request.epoch as i128),
            HashPart::Int(quorum_bps as i128),
            HashPart::Str(&request.finality_state_root),
            HashPart::Str(&request.aggregate_ml_dsa_signature_root),
            HashPart::Str(&request.aggregate_slh_dsa_signature_root),
        ],
        32,
    )
}

pub fn private_bridge_note_manifest_id(
    request: &PrivateBridgeNoteManifestRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-NOTE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.operator_id),
            HashPart::Str(request.direction.as_str()),
            HashPart::Int(request.note_count as i128),
            HashPart::Str(&request.note_commitment_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.manifest_nonce),
        ],
        32,
    )
}

pub fn fast_exit_liquidity_confirmation_id(
    request: &FastExitLiquidityConfirmationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-LIQUIDITY-CONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.manifest_id),
            HashPart::Str(&request.liquidity_provider_id),
            HashPart::Str(&request.vault_id),
            HashPart::Int(request.amount_piconero.min(i128::MAX as u128) as i128),
            HashPart::Int(request.fee_piconero.min(i128::MAX as u128) as i128),
            HashPart::Str(&request.liquidity_lock_root),
            HashPart::Str(&request.settlement_commitment_root),
            HashPart::Str(&request.pq_signature_root),
        ],
        32,
    )
}

pub fn low_fee_settlement_window_id(
    request: &LowFeeSettlementWindowRequest,
    sequence: u64,
    manifest_root: &str,
    liquidity_confirmation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-SETTLEMENT-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.coordinator_id),
            HashPart::Str(manifest_root),
            HashPart::Str(liquidity_confirmation_root),
            HashPart::Int(request.low_fee_bps as i128),
            HashPart::Str(&request.settlement_batch_root),
            HashPart::Str(&request.withdrawal_release_root),
            HashPart::Str(&request.pq_signature_root),
        ],
        32,
    )
}

pub fn dispute_receipt_id(request: &DisputeReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.challenger_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(request.checkpoint_id.as_deref().unwrap_or("")),
            HashPart::Str(request.attestation_id.as_deref().unwrap_or("")),
            HashPart::Str(request.manifest_id.as_deref().unwrap_or("")),
            HashPart::Str(request.confirmation_id.as_deref().unwrap_or("")),
            HashPart::Str(request.window_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.allegation_root),
            HashPart::Str(&request.dispute_nonce),
        ],
        32,
    )
}

pub fn finality_bridge_receipt_id(sequence: u64, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn finality_bridge_receipt_commitment(
    sequence: u64,
    kind: ReceiptKind,
    actor_id: &str,
    checkpoint_id: Option<&str>,
    attestation_id: Option<&str>,
    manifest_id: Option<&str>,
    confirmation_id: Option<&str>,
    window_id: Option<&str>,
    dispute_id: Option<&str>,
    issued_l2_height: u64,
    event_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-RECEIPT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(actor_id),
            HashPart::Str(checkpoint_id.unwrap_or("")),
            HashPart::Str(attestation_id.unwrap_or("")),
            HashPart::Str(manifest_id.unwrap_or("")),
            HashPart::Str(confirmation_id.unwrap_or("")),
            HashPart::Str(window_id.unwrap_or("")),
            HashPart::Str(dispute_id.unwrap_or("")),
            HashPart::Int(issued_l2_height as i128),
            HashPart::Str(event_root),
        ],
        32,
    )
}

fn final_settlement_commitment(
    request: &FinalizeSettlementWindowRequest,
    window_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FAST-FINALITY-BRIDGE-FINAL-SETTLEMENT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.finalizer_id),
            HashPart::Str(&request.final_settlement_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(window_root),
        ],
        32,
    )
}

fn validate_attestation_policy(
    request: &PqFinalityCommitteeAttestationRequest,
    config: &Config,
) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
    validate_root("finality_state_root", &request.finality_state_root)?;
    validate_root("header_checkpoint_root", &request.header_checkpoint_root)?;
    validate_root("bridge_note_root", &request.bridge_note_root)?;
    validate_root("liquidity_root", &request.liquidity_root)?;
    validate_root(
        "aggregate_ml_dsa_signature_root",
        &request.aggregate_ml_dsa_signature_root,
    )?;
    validate_root(
        "aggregate_slh_dsa_signature_root",
        &request.aggregate_slh_dsa_signature_root,
    )?;
    validate_root("committee_bitmap_root", &request.committee_bitmap_root)?;
    require(
        request.committee_id == config.committee_id,
        "committee id mismatch",
    )?;
    require(request.total_weight > 0, "attestation total weight is zero")?;
    require(
        request.signer_weight >= config.min_committee_weight,
        "attestation signer weight below minimum",
    )?;
    require(
        bps(request.signer_weight, request.total_weight) >= config.committee_quorum_bps,
        "attestation quorum below threshold",
    )?;
    require(
        request.pq_security_bits >= config.min_pq_security_bits,
        "attestation pq security below policy",
    )?;
    Ok(())
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-FAST-FINALITY-BRIDGE-{label}-ID-LIST"),
        &records,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_BPS) / denominator
}

fn fee_for_amount(amount: u128, fee_bps: u64) -> u128 {
    amount.saturating_mul(fee_bps as u128)
        / MONERO_L2_PQ_FAST_FINALITY_BRIDGE_RUNTIME_MAX_BPS as u128
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
    require(current < max, &format!("{label} capacity exceeded"))
}

fn validate_root(field: &str, value: &str) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
    required(field, value)
}

fn required(field: &str, value: &str) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn require(condition: bool, message: &str) -> MoneroL2PqFastFinalityBridgeRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
