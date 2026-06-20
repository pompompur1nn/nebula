use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, HashPart};

pub type PrivateDaEscrowResult<T> = Result<T, String>;

pub const PRIVATE_DA_ESCROW_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_DA_ESCROW_PROTOCOL_ID: &str = "nebula-private-da-escrow-v1";
pub const PRIVATE_DA_ESCROW_HASH_SUITE: &str = "SHAKE256";
pub const PRIVATE_DA_ESCROW_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_DA_ESCROW_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128f";
pub const PRIVATE_DA_ESCROW_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_DA_ESCROW_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-encrypted-da-blob-v1";
pub const PRIVATE_DA_ESCROW_ERASURE_SCHEME: &str = "shake256-hybrid-rs-fri-erasure-v1";
pub const PRIVATE_DA_ESCROW_FEE_ASSET_ID: &str = "asset:dxmr";
pub const PRIVATE_DA_ESCROW_DEVNET_HEIGHT: u64 = 720;
pub const PRIVATE_DA_ESCROW_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_DA_ESCROW_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_DA_ESCROW_DEFAULT_RETENTION_BLOCKS: u64 = 14_400;
pub const PRIVATE_DA_ESCROW_DEFAULT_PROVIDER_BOND_UNITS: u64 = 250_000;
pub const PRIVATE_DA_ESCROW_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 125_000;
pub const PRIVATE_DA_ESCROW_DEFAULT_LOW_FEE_CAP_UNITS: u64 = 4;
pub const PRIVATE_DA_ESCROW_DEFAULT_BASE_FEE_PER_KIB: u64 = 1;
pub const PRIVATE_DA_ESCROW_DEFAULT_REPORTER_REWARD_BPS: u64 = 2_000;
pub const PRIVATE_DA_ESCROW_DEFAULT_PROVIDER_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_DA_ESCROW_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const PRIVATE_DA_ESCROW_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DA_ESCROW_MAX_BLOBS: usize = 65_536;
pub const PRIVATE_DA_ESCROW_MAX_ERASURE_COMMITMENTS: usize = 262_144;
pub const PRIVATE_DA_ESCROW_MAX_PROVIDER_BONDS: usize = 16_384;
pub const PRIVATE_DA_ESCROW_MAX_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_DA_ESCROW_MAX_SPONSORSHIPS: usize = 65_536;
pub const PRIVATE_DA_ESCROW_MAX_REVEAL_WINDOWS: usize = 131_072;
pub const PRIVATE_DA_ESCROW_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_DA_ESCROW_MAX_DATA_LANES: usize = 1_024;
pub const PRIVATE_DA_ESCROW_MAX_BRIDGE_BATCHES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDaBlobKind {
    PrivateTransfer,
    PrivateContractCall,
    DefiSwap,
    Lending,
    MoneroBridge,
    RecursiveProof,
    ForcedInclusion,
    Governance,
    Emergency,
}

impl PrivateDaBlobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::MoneroBridge => "monero_bridge",
            Self::RecursiveProof => "recursive_proof",
            Self::ForcedInclusion => "forced_inclusion",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_lane_key(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private-transfer-da",
            Self::PrivateContractCall => "private-contract-da",
            Self::DefiSwap => "private-defi-swap-da",
            Self::Lending => "private-lending-da",
            Self::MoneroBridge => "monero-bridge-da",
            Self::RecursiveProof => "recursive-proof-da",
            Self::ForcedInclusion => "forced-inclusion-da",
            Self::Governance => "governance-da",
            Self::Emergency => "emergency-da",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::ForcedInclusion => 96,
            Self::MoneroBridge => 92,
            Self::PrivateTransfer => 88,
            Self::PrivateContractCall => 84,
            Self::DefiSwap => 82,
            Self::Lending => 80,
            Self::RecursiveProof => 72,
            Self::Governance => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDaEscrowStatus {
    Active,
    Paused,
    Pending,
    Locked,
    Attested,
    Revealing,
    Revealed,
    Challenged,
    Settled,
    Slashed,
    Expired,
    Revoked,
}

impl PrivateDaEscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Pending => "pending",
            Self::Locked => "locked",
            Self::Attested => "attested",
            Self::Revealing => "revealing",
            Self::Revealed => "revealed",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Pending | Self::Locked | Self::Attested | Self::Revealing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDaChallengeKind {
    MissingShard,
    InvalidOpening,
    BadPqAttestation,
    RevealWindowMissed,
    BondUnderfunded,
    SponsorOverspend,
    MoneroBatchMismatch,
}

impl PrivateDaChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingShard => "missing_shard",
            Self::InvalidOpening => "invalid_opening",
            Self::BadPqAttestation => "bad_pq_attestation",
            Self::RevealWindowMissed => "reveal_window_missed",
            Self::BondUnderfunded => "bond_underfunded",
            Self::SponsorOverspend => "sponsor_overspend",
            Self::MoneroBatchMismatch => "monero_batch_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaEscrowConfig {
    pub protocol_id: String,
    pub fee_asset_id: String,
    pub reveal_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub retention_blocks: u64,
    pub provider_bond_units: u64,
    pub sponsor_budget_units: u64,
    pub low_fee_cap_units: u64,
    pub base_fee_per_kib: u64,
    pub reporter_reward_bps: u64,
    pub provider_slash_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub min_original_shards: u64,
    pub min_parity_shards: u64,
    pub max_blob_bytes: u64,
    pub min_privacy_set_size: u64,
}

impl Default for PrivateDaEscrowConfig {
    fn default() -> Self {
        Self {
            protocol_id: PRIVATE_DA_ESCROW_PROTOCOL_ID.to_string(),
            fee_asset_id: PRIVATE_DA_ESCROW_FEE_ASSET_ID.to_string(),
            reveal_window_blocks: PRIVATE_DA_ESCROW_DEFAULT_REVEAL_WINDOW_BLOCKS,
            challenge_window_blocks: PRIVATE_DA_ESCROW_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            retention_blocks: PRIVATE_DA_ESCROW_DEFAULT_RETENTION_BLOCKS,
            provider_bond_units: PRIVATE_DA_ESCROW_DEFAULT_PROVIDER_BOND_UNITS,
            sponsor_budget_units: PRIVATE_DA_ESCROW_DEFAULT_SPONSOR_BUDGET_UNITS,
            low_fee_cap_units: PRIVATE_DA_ESCROW_DEFAULT_LOW_FEE_CAP_UNITS,
            base_fee_per_kib: PRIVATE_DA_ESCROW_DEFAULT_BASE_FEE_PER_KIB,
            reporter_reward_bps: PRIVATE_DA_ESCROW_DEFAULT_REPORTER_REWARD_BPS,
            provider_slash_bps: PRIVATE_DA_ESCROW_DEFAULT_PROVIDER_SLASH_BPS,
            sponsor_rebate_bps: PRIVATE_DA_ESCROW_DEFAULT_SPONSOR_REBATE_BPS,
            min_original_shards: 16,
            min_parity_shards: 16,
            max_blob_bytes: 4 * 1024 * 1024,
            min_privacy_set_size: 128,
        }
    }
}

impl PrivateDaEscrowConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_da_escrow_config",
            "protocol_version": PRIVATE_DA_ESCROW_PROTOCOL_VERSION,
            "protocol_id": self.protocol_id,
            "hash_suite": PRIVATE_DA_ESCROW_HASH_SUITE,
            "pq_signature_scheme": PRIVATE_DA_ESCROW_PQ_SIGNATURE_SCHEME,
            "pq_backup_scheme": PRIVATE_DA_ESCROW_PQ_BACKUP_SCHEME,
            "pq_kem_scheme": PRIVATE_DA_ESCROW_PQ_KEM_SCHEME,
            "encryption_scheme": PRIVATE_DA_ESCROW_ENCRYPTION_SCHEME,
            "erasure_scheme": PRIVATE_DA_ESCROW_ERASURE_SCHEME,
            "fee_asset_id": self.fee_asset_id,
            "reveal_window_blocks": self.reveal_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "retention_blocks": self.retention_blocks,
            "provider_bond_units": self.provider_bond_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "low_fee_cap_units": self.low_fee_cap_units,
            "base_fee_per_kib": self.base_fee_per_kib,
            "reporter_reward_bps": self.reporter_reward_bps,
            "provider_slash_bps": self.provider_slash_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "min_original_shards": self.min_original_shards,
            "min_parity_shards": self.min_parity_shards,
            "max_blob_bytes": self.max_blob_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        private_da_escrow_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.protocol_id, "config protocol id")?;
        ensure_non_empty(&self.fee_asset_id, "config fee asset id")?;
        ensure_positive(self.reveal_window_blocks, "config reveal window")?;
        ensure_positive(self.challenge_window_blocks, "config challenge window")?;
        ensure_positive(self.retention_blocks, "config retention blocks")?;
        ensure_positive(self.provider_bond_units, "config provider bond")?;
        ensure_positive(self.sponsor_budget_units, "config sponsor budget")?;
        ensure_positive(self.base_fee_per_kib, "config base fee per kib")?;
        ensure_positive(self.min_original_shards, "config original shards")?;
        ensure_positive(self.min_parity_shards, "config parity shards")?;
        ensure_positive(self.max_blob_bytes, "config max blob bytes")?;
        ensure_positive(self.min_privacy_set_size, "config privacy set")?;
        ensure_bps(self.reporter_reward_bps, "config reporter reward")?;
        ensure_bps(self.provider_slash_bps, "config provider slash")?;
        ensure_bps(self.sponsor_rebate_bps, "config sponsor rebate")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRollupBlobEscrow {
    pub blob_id: String,
    pub batch_id: String,
    pub lane_key: String,
    pub blob_kind: PrivateDaBlobKind,
    pub sequencer_commitment: String,
    pub encrypted_blob_root: String,
    pub ciphertext_commitment_root: String,
    pub kem_ciphertext_root: String,
    pub privacy_manifest_root: String,
    pub erasure_commitment_root: String,
    pub provider_set_root: String,
    pub sponsor_id: String,
    pub payload_bytes: u64,
    pub encoded_bytes: u64,
    pub original_shards: u64,
    pub parity_shards: u64,
    pub privacy_set_size: u64,
    pub max_fee_units: u64,
    pub posted_at_height: u64,
    pub reveal_deadline_height: u64,
    pub retention_deadline_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl EncryptedRollupBlobEscrow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        lane_key: &str,
        blob_kind: PrivateDaBlobKind,
        sequencer_label: &str,
        encrypted_blob_root: &str,
        ciphertext_commitment_root: &str,
        kem_ciphertext_root: &str,
        payload_bytes: u64,
        posted_at_height: u64,
        config: &PrivateDaEscrowConfig,
        nonce: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(batch_id, "blob batch id")?;
        ensure_non_empty(lane_key, "blob lane key")?;
        ensure_non_empty(sequencer_label, "blob sequencer")?;
        ensure_non_empty(encrypted_blob_root, "blob encrypted root")?;
        ensure_non_empty(
            ciphertext_commitment_root,
            "blob ciphertext commitment root",
        )?;
        ensure_non_empty(kem_ciphertext_root, "blob kem ciphertext root")?;
        ensure_positive(payload_bytes, "blob payload bytes")?;
        if payload_bytes > config.max_blob_bytes {
            return Err("blob payload exceeds config max".to_string());
        }

        let original_shards = config.min_original_shards;
        let parity_shards = config.min_parity_shards;
        let encoded_bytes = encoded_size(payload_bytes, original_shards, parity_shards);
        let sequencer_commitment = private_da_escrow_commitment("sequencer", sequencer_label);
        let privacy_manifest_root = private_da_escrow_payload_root(
            "BLOB-PRIVACY-MANIFEST",
            &json!({
                "privacy_set_size": config.min_privacy_set_size,
                "sequencer_commitment": sequencer_commitment,
                "lane_key": lane_key,
                "blob_kind": blob_kind.as_str(),
            }),
        );
        let erasure_commitment_root = private_da_escrow_payload_root(
            "BLOB-ERASURE-PLAN",
            &json!({
                "original_shards": original_shards,
                "parity_shards": parity_shards,
                "encoded_bytes": encoded_bytes,
                "scheme": PRIVATE_DA_ESCROW_ERASURE_SCHEME,
            }),
        );
        let provider_set_root = private_da_escrow_commitment("provider-set", "pending");
        let sponsor_id = String::new();
        let reveal_deadline_height = posted_at_height.saturating_add(config.reveal_window_blocks);
        let retention_deadline_height = posted_at_height.saturating_add(config.retention_blocks);
        let max_fee_units = fee_for_bytes(encoded_bytes, config.base_fee_per_kib);
        let blob_id = private_da_escrow_blob_id(
            batch_id,
            lane_key,
            blob_kind,
            &sequencer_commitment,
            encrypted_blob_root,
            posted_at_height,
            nonce,
        );

        Ok(Self {
            blob_id,
            batch_id: batch_id.to_string(),
            lane_key: lane_key.to_string(),
            blob_kind,
            sequencer_commitment,
            encrypted_blob_root: encrypted_blob_root.to_string(),
            ciphertext_commitment_root: ciphertext_commitment_root.to_string(),
            kem_ciphertext_root: kem_ciphertext_root.to_string(),
            privacy_manifest_root,
            erasure_commitment_root,
            provider_set_root,
            sponsor_id,
            payload_bytes,
            encoded_bytes,
            original_shards,
            parity_shards,
            privacy_set_size: config.min_privacy_set_size,
            max_fee_units,
            posted_at_height,
            reveal_deadline_height,
            retention_deadline_height,
            status: PrivateDaEscrowStatus::Locked,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blob_id": self.blob_id,
            "batch_id": self.batch_id,
            "lane_key": self.lane_key,
            "blob_kind": self.blob_kind.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "encrypted_blob_root": self.encrypted_blob_root,
            "ciphertext_commitment_root": self.ciphertext_commitment_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "privacy_manifest_root": self.privacy_manifest_root,
            "erasure_commitment_root": self.erasure_commitment_root,
            "provider_set_root": self.provider_set_root,
            "sponsor_id": self.sponsor_id,
            "payload_bytes": self.payload_bytes,
            "encoded_bytes": self.encoded_bytes,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_units": self.max_fee_units,
            "posted_at_height": self.posted_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "retention_deadline_height": self.retention_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.blob_id, "blob id")?;
        ensure_non_empty(&self.batch_id, "blob batch id")?;
        ensure_non_empty(&self.lane_key, "blob lane key")?;
        ensure_non_empty(&self.sequencer_commitment, "blob sequencer commitment")?;
        ensure_non_empty(&self.encrypted_blob_root, "blob encrypted root")?;
        ensure_non_empty(
            &self.ciphertext_commitment_root,
            "blob ciphertext commitment root",
        )?;
        ensure_non_empty(&self.kem_ciphertext_root, "blob kem ciphertext root")?;
        ensure_non_empty(&self.privacy_manifest_root, "blob privacy manifest")?;
        ensure_non_empty(&self.erasure_commitment_root, "blob erasure root")?;
        ensure_positive(self.payload_bytes, "blob payload bytes")?;
        ensure_positive(self.encoded_bytes, "blob encoded bytes")?;
        ensure_positive(self.original_shards, "blob original shards")?;
        ensure_positive(self.parity_shards, "blob parity shards")?;
        ensure_positive(self.privacy_set_size, "blob privacy set")?;
        ensure_height_window(
            self.posted_at_height,
            self.reveal_deadline_height,
            "blob reveal",
        )?;
        ensure_height_window(
            self.posted_at_height,
            self.retention_deadline_height,
            "blob retention",
        )?;
        Ok(private_da_escrow_record_root("BLOB", &self.public_record()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureCodeCommitment {
    pub commitment_id: String,
    pub blob_id: String,
    pub provider_id: String,
    pub shard_index: u64,
    pub original_shards: u64,
    pub parity_shards: u64,
    pub shard_commitment: String,
    pub shard_opening_root: String,
    pub encoded_size_bytes: u64,
    pub custody_until_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl ErasureCodeCommitment {
    pub fn devnet(
        blob_id: &str,
        provider_id: &str,
        shard_index: u64,
        original_shards: u64,
        parity_shards: u64,
        height: u64,
        retention_blocks: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(blob_id, "erasure blob id")?;
        ensure_non_empty(provider_id, "erasure provider id")?;
        ensure_positive(original_shards, "erasure original shards")?;
        ensure_positive(parity_shards, "erasure parity shards")?;
        let total = original_shards.saturating_add(parity_shards);
        if shard_index >= total {
            return Err("erasure shard index outside shard set".to_string());
        }
        let label = format!("{blob_id}:{provider_id}:{shard_index}");
        let shard_commitment = private_da_escrow_commitment("devnet-shard", &label);
        let shard_opening_root = private_da_escrow_commitment("devnet-opening", &label);
        let commitment_id = private_da_escrow_erasure_commitment_id(
            blob_id,
            provider_id,
            shard_index,
            &shard_commitment,
        );
        Ok(Self {
            commitment_id,
            blob_id: blob_id.to_string(),
            provider_id: provider_id.to_string(),
            shard_index,
            original_shards,
            parity_shards,
            shard_commitment,
            shard_opening_root,
            encoded_size_bytes: 8_192,
            custody_until_height: height.saturating_add(retention_blocks),
            status: PrivateDaEscrowStatus::Locked,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "blob_id": self.blob_id,
            "provider_id": self.provider_id,
            "shard_index": self.shard_index,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "shard_commitment": self.shard_commitment,
            "shard_opening_root": self.shard_opening_root,
            "encoded_size_bytes": self.encoded_size_bytes,
            "custody_until_height": self.custody_until_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.commitment_id, "erasure commitment id")?;
        ensure_non_empty(&self.blob_id, "erasure blob id")?;
        ensure_non_empty(&self.provider_id, "erasure provider id")?;
        ensure_non_empty(&self.shard_commitment, "erasure shard commitment")?;
        ensure_non_empty(&self.shard_opening_root, "erasure opening root")?;
        ensure_positive(self.original_shards, "erasure original shards")?;
        ensure_positive(self.parity_shards, "erasure parity shards")?;
        ensure_positive(self.encoded_size_bytes, "erasure encoded size")?;
        if self.shard_index >= self.original_shards.saturating_add(self.parity_shards) {
            return Err("erasure shard index outside shard set".to_string());
        }
        Ok(private_da_escrow_record_root(
            "ERASURE-COMMITMENT",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProviderBond {
    pub provider_id: String,
    pub operator_commitment: String,
    pub bond_asset_id: String,
    pub bonded_units: u64,
    pub slashable_units: u64,
    pub custody_lane_root: String,
    pub pq_signing_key_commitment: String,
    pub pq_kem_key_commitment: String,
    pub opened_at_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl DaProviderBond {
    pub fn devnet(
        label: &str,
        lane_keys: &[String],
        height: u64,
        bond_units: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(label, "provider label")?;
        ensure_string_set(lane_keys, "provider lanes")?;
        ensure_positive(bond_units, "provider bond units")?;
        let operator_commitment = private_da_escrow_commitment("operator", label);
        let custody_lane_root = private_da_escrow_string_set_root("PROVIDER-LANES", lane_keys);
        let pq_signing_key_commitment = private_da_escrow_commitment("pq-signing-key", label);
        let pq_kem_key_commitment = private_da_escrow_commitment("pq-kem-key", label);
        let provider_id = private_da_escrow_provider_id(
            &operator_commitment,
            &custody_lane_root,
            &pq_signing_key_commitment,
        );
        Ok(Self {
            provider_id,
            operator_commitment,
            bond_asset_id: PRIVATE_DA_ESCROW_FEE_ASSET_ID.to_string(),
            bonded_units: bond_units,
            slashable_units: bond_units,
            custody_lane_root,
            pq_signing_key_commitment,
            pq_kem_key_commitment,
            opened_at_height: height,
            status: PrivateDaEscrowStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bonded_units": self.bonded_units,
            "slashable_units": self.slashable_units,
            "custody_lane_root": self.custody_lane_root,
            "pq_signing_key_commitment": self.pq_signing_key_commitment,
            "pq_kem_key_commitment": self.pq_kem_key_commitment,
            "opened_at_height": self.opened_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.provider_id, "provider id")?;
        ensure_non_empty(&self.operator_commitment, "provider operator commitment")?;
        ensure_non_empty(&self.bond_asset_id, "provider bond asset")?;
        ensure_non_empty(&self.custody_lane_root, "provider lane root")?;
        ensure_non_empty(&self.pq_signing_key_commitment, "provider pq signing key")?;
        ensure_non_empty(&self.pq_kem_key_commitment, "provider pq kem key")?;
        ensure_positive(self.bonded_units, "provider bonded units")?;
        if self.slashable_units > self.bonded_units {
            return Err("provider slashable units exceed bond".to_string());
        }
        Ok(private_da_escrow_record_root(
            "PROVIDER-BOND",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqProviderAttestation {
    pub attestation_id: String,
    pub blob_id: String,
    pub provider_id: String,
    pub attested_erasure_root: String,
    pub availability_claim_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl PqProviderAttestation {
    pub fn new(
        blob_id: &str,
        provider_id: &str,
        erasure_root: &str,
        availability_claim: &Value,
        height: u64,
        challenge_window: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(blob_id, "attestation blob id")?;
        ensure_non_empty(provider_id, "attestation provider id")?;
        ensure_non_empty(erasure_root, "attestation erasure root")?;
        ensure_positive(challenge_window, "attestation challenge window")?;
        let availability_claim_root =
            private_da_escrow_payload_root("ATTESTATION-CLAIM", availability_claim);
        let transcript_root = private_da_escrow_payload_root(
            "ATTESTATION-TRANSCRIPT",
            &json!({
                "blob_id": blob_id,
                "provider_id": provider_id,
                "erasure_root": erasure_root,
                "availability_claim_root": availability_claim_root,
                "height": height,
            }),
        );
        let pq_signature_root =
            private_da_escrow_commitment("devnet-pq-attestation-signature", &transcript_root);
        let attestation_id =
            private_da_escrow_attestation_id(blob_id, provider_id, &transcript_root);
        Ok(Self {
            attestation_id,
            blob_id: blob_id.to_string(),
            provider_id: provider_id.to_string(),
            attested_erasure_root: erasure_root.to_string(),
            availability_claim_root,
            transcript_root,
            pq_signature_root,
            attested_at_height: height,
            expires_at_height: height.saturating_add(challenge_window),
            status: PrivateDaEscrowStatus::Attested,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "blob_id": self.blob_id,
            "provider_id": self.provider_id,
            "attested_erasure_root": self.attested_erasure_root,
            "availability_claim_root": self.availability_claim_root,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.blob_id, "attestation blob id")?;
        ensure_non_empty(&self.provider_id, "attestation provider id")?;
        ensure_non_empty(&self.attested_erasure_root, "attestation erasure root")?;
        ensure_non_empty(&self.availability_claim_root, "attestation claim root")?;
        ensure_non_empty(&self.transcript_root, "attestation transcript root")?;
        ensure_non_empty(&self.pq_signature_root, "attestation signature root")?;
        ensure_height_window(
            self.attested_at_height,
            self.expires_at_height,
            "attestation expiry",
        )?;
        Ok(private_da_escrow_record_root(
            "PQ-ATTESTATION",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDaSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_per_blob_units: u64,
    pub eligibility_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl LowFeeDaSponsorship {
    pub fn devnet(
        sponsor_label: &str,
        lane_key: &str,
        budget_units: u64,
        max_fee_per_blob_units: u64,
        height: u64,
        retention_blocks: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(sponsor_label, "sponsor label")?;
        ensure_non_empty(lane_key, "sponsor lane key")?;
        ensure_positive(budget_units, "sponsor budget")?;
        ensure_positive(max_fee_per_blob_units, "sponsor fee cap")?;
        ensure_positive(retention_blocks, "sponsor retention")?;
        let sponsor_commitment = private_da_escrow_commitment("sponsor", sponsor_label);
        let eligibility_root = private_da_escrow_payload_root(
            "SPONSOR-ELIGIBILITY",
            &json!({
                "lane_key": lane_key,
                "low_fee_cap_units": max_fee_per_blob_units,
                "private_contracts": true,
                "monero_bridge_batches": true,
            }),
        );
        let sponsorship_id = private_da_escrow_sponsorship_id(
            &sponsor_commitment,
            lane_key,
            PRIVATE_DA_ESCROW_FEE_ASSET_ID,
            &eligibility_root,
            height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            lane_key: lane_key.to_string(),
            fee_asset_id: PRIVATE_DA_ESCROW_FEE_ASSET_ID.to_string(),
            budget_units,
            spent_units: 0,
            max_fee_per_blob_units,
            eligibility_root,
            opened_at_height: height,
            expires_at_height: height.saturating_add(retention_blocks),
            status: PrivateDaEscrowStatus::Active,
        })
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_fee_per_blob_units": self.max_fee_per_blob_units,
            "eligibility_root": self.eligibility_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor")?;
        ensure_non_empty(&self.lane_key, "sponsorship lane")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_non_empty(&self.eligibility_root, "sponsorship eligibility")?;
        ensure_positive(self.budget_units, "sponsorship budget")?;
        ensure_positive(self.max_fee_per_blob_units, "sponsorship fee cap")?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "sponsorship expiry",
        )?;
        if self.spent_units > self.budget_units {
            return Err("sponsorship spent units exceed budget".to_string());
        }
        Ok(private_da_escrow_record_root(
            "SPONSORSHIP",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRevealWindow {
    pub window_id: String,
    pub blob_id: String,
    pub encrypted_blob_root: String,
    pub reveal_key_commitment: String,
    pub requester_commitment: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub revealed_at_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl BlobRevealWindow {
    pub fn new(
        blob_id: &str,
        encrypted_blob_root: &str,
        requester_label: &str,
        opened_at_height: u64,
        reveal_window_blocks: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(blob_id, "reveal blob id")?;
        ensure_non_empty(encrypted_blob_root, "reveal encrypted root")?;
        ensure_non_empty(requester_label, "reveal requester")?;
        ensure_positive(reveal_window_blocks, "reveal window blocks")?;
        let requester_commitment =
            private_da_escrow_commitment("reveal-requester", requester_label);
        let reveal_key_commitment = private_da_escrow_commitment("reveal-key", blob_id);
        let deadline_height = opened_at_height.saturating_add(reveal_window_blocks);
        let window_id = private_da_escrow_reveal_window_id(
            blob_id,
            &requester_commitment,
            opened_at_height,
            &reveal_key_commitment,
        );
        Ok(Self {
            window_id,
            blob_id: blob_id.to_string(),
            encrypted_blob_root: encrypted_blob_root.to_string(),
            reveal_key_commitment,
            requester_commitment,
            opened_at_height,
            deadline_height,
            revealed_at_height: 0,
            status: PrivateDaEscrowStatus::Revealing,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "blob_id": self.blob_id,
            "encrypted_blob_root": self.encrypted_blob_root,
            "reveal_key_commitment": self.reveal_key_commitment,
            "requester_commitment": self.requester_commitment,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "revealed_at_height": self.revealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.window_id, "reveal window id")?;
        ensure_non_empty(&self.blob_id, "reveal blob id")?;
        ensure_non_empty(&self.encrypted_blob_root, "reveal encrypted root")?;
        ensure_non_empty(&self.reveal_key_commitment, "reveal key commitment")?;
        ensure_non_empty(&self.requester_commitment, "reveal requester commitment")?;
        ensure_height_window(self.opened_at_height, self.deadline_height, "reveal window")?;
        if self.revealed_at_height > 0 && self.revealed_at_height > self.deadline_height {
            return Err("reveal happened after deadline".to_string());
        }
        Ok(private_da_escrow_record_root(
            "REVEAL-WINDOW",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeReceipt {
    pub receipt_id: String,
    pub blob_id: String,
    pub provider_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: PrivateDaChallengeKind,
    pub evidence_root: String,
    pub required_root: String,
    pub observed_root: String,
    pub opened_at_height: u64,
    pub resolve_deadline_height: u64,
    pub slash_units: u64,
    pub status: PrivateDaEscrowStatus,
}

impl ChallengeReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_id: &str,
        provider_id: &str,
        challenger_label: &str,
        challenge_kind: PrivateDaChallengeKind,
        required_root: &str,
        observed_root: &str,
        opened_at_height: u64,
        challenge_window_blocks: u64,
        slash_units: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(blob_id, "challenge blob id")?;
        ensure_non_empty(provider_id, "challenge provider id")?;
        ensure_non_empty(challenger_label, "challenge challenger")?;
        ensure_non_empty(required_root, "challenge required root")?;
        ensure_non_empty(observed_root, "challenge observed root")?;
        ensure_positive(challenge_window_blocks, "challenge window")?;
        let challenger_commitment = private_da_escrow_commitment("challenger", challenger_label);
        let evidence_root = private_da_escrow_payload_root(
            "CHALLENGE-EVIDENCE",
            &json!({
                "challenge_kind": challenge_kind.as_str(),
                "required_root": required_root,
                "observed_root": observed_root,
            }),
        );
        let receipt_id = private_da_escrow_challenge_receipt_id(
            blob_id,
            provider_id,
            challenge_kind,
            &evidence_root,
            opened_at_height,
        );
        Ok(Self {
            receipt_id,
            blob_id: blob_id.to_string(),
            provider_id: provider_id.to_string(),
            challenger_commitment,
            challenge_kind,
            evidence_root,
            required_root: required_root.to_string(),
            observed_root: observed_root.to_string(),
            opened_at_height,
            resolve_deadline_height: opened_at_height.saturating_add(challenge_window_blocks),
            slash_units,
            status: PrivateDaEscrowStatus::Challenged,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "blob_id": self.blob_id,
            "provider_id": self.provider_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "evidence_root": self.evidence_root,
            "required_root": self.required_root,
            "observed_root": self.observed_root,
            "opened_at_height": self.opened_at_height,
            "resolve_deadline_height": self.resolve_deadline_height,
            "slash_units": self.slash_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.receipt_id, "challenge receipt id")?;
        ensure_non_empty(&self.blob_id, "challenge blob id")?;
        ensure_non_empty(&self.provider_id, "challenge provider id")?;
        ensure_non_empty(&self.challenger_commitment, "challenge challenger")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence")?;
        ensure_non_empty(&self.required_root, "challenge required root")?;
        ensure_non_empty(&self.observed_root, "challenge observed root")?;
        ensure_height_window(
            self.opened_at_height,
            self.resolve_deadline_height,
            "challenge resolution",
        )?;
        Ok(private_da_escrow_record_root(
            "CHALLENGE-RECEIPT",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractDataLane {
    pub lane_id: String,
    pub lane_key: String,
    pub contract_root: String,
    pub solver_committee_root: String,
    pub max_blob_bytes: u64,
    pub priority: u64,
    pub sponsored: bool,
    pub opened_at_height: u64,
    pub status: PrivateDaEscrowStatus,
}

impl PrivateContractDataLane {
    pub fn devnet(
        kind: PrivateDaBlobKind,
        height: u64,
        max_blob_bytes: u64,
    ) -> PrivateDaEscrowResult<Self> {
        ensure_positive(max_blob_bytes, "lane max blob bytes")?;
        let lane_key = kind.default_lane_key().to_string();
        let contract_root = private_da_escrow_commitment("devnet-contract-root", &lane_key);
        let solver_committee_root =
            private_da_escrow_commitment("devnet-solver-committee", &lane_key);
        let lane_id = private_da_escrow_data_lane_id(&lane_key, &contract_root, height);
        Ok(Self {
            lane_id,
            lane_key,
            contract_root,
            solver_committee_root,
            max_blob_bytes,
            priority: kind.priority(),
            sponsored: true,
            opened_at_height: height,
            status: PrivateDaEscrowStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "contract_root": self.contract_root,
            "solver_committee_root": self.solver_committee_root,
            "max_blob_bytes": self.max_blob_bytes,
            "priority": self.priority,
            "sponsored": self.sponsored,
            "opened_at_height": self.opened_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.lane_id, "data lane id")?;
        ensure_non_empty(&self.lane_key, "data lane key")?;
        ensure_non_empty(&self.contract_root, "data lane contract root")?;
        ensure_non_empty(&self.solver_committee_root, "data lane solver root")?;
        ensure_positive(self.max_blob_bytes, "data lane max blob bytes")?;
        Ok(private_da_escrow_record_root(
            "DATA-LANE",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeBatchBlob {
    pub bridge_batch_id: String,
    pub blob_id: String,
    pub monero_block_root: String,
    pub monero_txid_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub reserve_proof_root: String,
    pub bridge_amount_commitment: String,
    pub da_settlement_root: String,
    pub posted_at_height: u64,
    pub monero_confirmations: u64,
    pub status: PrivateDaEscrowStatus,
}

impl MoneroBridgeBatchBlob {
    pub fn devnet(blob_id: &str, height: u64, confirmations: u64) -> PrivateDaEscrowResult<Self> {
        ensure_non_empty(blob_id, "bridge blob id")?;
        let monero_block_root = private_da_escrow_commitment("devnet-monero-block", blob_id);
        let monero_txid_root = private_da_escrow_commitment("devnet-monero-txid", blob_id);
        let output_commitment_root =
            private_da_escrow_commitment("devnet-output-commitment", blob_id);
        let key_image_root = private_da_escrow_commitment("devnet-key-image", blob_id);
        let reserve_proof_root = private_da_escrow_commitment("devnet-reserve-proof", blob_id);
        let bridge_amount_commitment =
            private_da_escrow_commitment("devnet-bridge-amount", blob_id);
        let da_settlement_root = private_da_escrow_commitment("devnet-da-settlement", blob_id);
        let bridge_batch_id = private_da_escrow_monero_bridge_batch_id(
            blob_id,
            &monero_block_root,
            &monero_txid_root,
            height,
        );
        Ok(Self {
            bridge_batch_id,
            blob_id: blob_id.to_string(),
            monero_block_root,
            monero_txid_root,
            output_commitment_root,
            key_image_root,
            reserve_proof_root,
            bridge_amount_commitment,
            da_settlement_root,
            posted_at_height: height,
            monero_confirmations: confirmations,
            status: PrivateDaEscrowStatus::Attested,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bridge_batch_id": self.bridge_batch_id,
            "blob_id": self.blob_id,
            "monero_block_root": self.monero_block_root,
            "monero_txid_root": self.monero_txid_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "reserve_proof_root": self.reserve_proof_root,
            "bridge_amount_commitment": self.bridge_amount_commitment,
            "da_settlement_root": self.da_settlement_root,
            "posted_at_height": self.posted_at_height,
            "monero_confirmations": self.monero_confirmations,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        ensure_non_empty(&self.bridge_batch_id, "bridge batch id")?;
        ensure_non_empty(&self.blob_id, "bridge blob id")?;
        ensure_non_empty(&self.monero_block_root, "bridge block root")?;
        ensure_non_empty(&self.monero_txid_root, "bridge txid root")?;
        ensure_non_empty(&self.output_commitment_root, "bridge output root")?;
        ensure_non_empty(&self.key_image_root, "bridge key image root")?;
        ensure_non_empty(&self.reserve_proof_root, "bridge reserve proof")?;
        ensure_non_empty(&self.bridge_amount_commitment, "bridge amount")?;
        ensure_non_empty(&self.da_settlement_root, "bridge da settlement")?;
        Ok(private_da_escrow_record_root(
            "MONERO-BRIDGE-BATCH",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaEscrowRoots {
    pub config_root: String,
    pub encrypted_blob_root: String,
    pub erasure_commitment_root: String,
    pub provider_bond_root: String,
    pub pq_attestation_root: String,
    pub sponsorship_root: String,
    pub reveal_window_root: String,
    pub challenge_receipt_root: String,
    pub data_lane_root: String,
    pub monero_bridge_batch_root: String,
}

impl PrivateDaEscrowRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "encrypted_blob_root": self.encrypted_blob_root,
            "erasure_commitment_root": self.erasure_commitment_root,
            "provider_bond_root": self.provider_bond_root,
            "pq_attestation_root": self.pq_attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "reveal_window_root": self.reveal_window_root,
            "challenge_receipt_root": self.challenge_receipt_root,
            "data_lane_root": self.data_lane_root,
            "monero_bridge_batch_root": self.monero_bridge_batch_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_da_escrow_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaEscrowCounters {
    pub encrypted_blobs: u64,
    pub live_encrypted_blobs: u64,
    pub erasure_commitments: u64,
    pub provider_bonds: u64,
    pub active_provider_bonds: u64,
    pub pq_attestations: u64,
    pub active_sponsorships: u64,
    pub reveal_windows: u64,
    pub open_challenges: u64,
    pub private_contract_data_lanes: u64,
    pub monero_bridge_batches: u64,
    pub total_payload_bytes: u64,
    pub total_encoded_bytes: u64,
    pub total_sponsored_units: u64,
    pub total_provider_bond_units: u64,
}

impl PrivateDaEscrowCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "encrypted_blobs": self.encrypted_blobs,
            "live_encrypted_blobs": self.live_encrypted_blobs,
            "erasure_commitments": self.erasure_commitments,
            "provider_bonds": self.provider_bonds,
            "active_provider_bonds": self.active_provider_bonds,
            "pq_attestations": self.pq_attestations,
            "active_sponsorships": self.active_sponsorships,
            "reveal_windows": self.reveal_windows,
            "open_challenges": self.open_challenges,
            "private_contract_data_lanes": self.private_contract_data_lanes,
            "monero_bridge_batches": self.monero_bridge_batches,
            "total_payload_bytes": self.total_payload_bytes,
            "total_encoded_bytes": self.total_encoded_bytes,
            "total_sponsored_units": self.total_sponsored_units,
            "total_provider_bond_units": self.total_provider_bond_units,
        })
    }

    pub fn state_root(&self) -> String {
        private_da_escrow_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaEscrowState {
    pub height: u64,
    pub status: PrivateDaEscrowStatus,
    pub config: PrivateDaEscrowConfig,
    pub encrypted_blobs: BTreeMap<String, EncryptedRollupBlobEscrow>,
    pub erasure_commitments: BTreeMap<String, ErasureCodeCommitment>,
    pub provider_bonds: BTreeMap<String, DaProviderBond>,
    pub pq_attestations: BTreeMap<String, PqProviderAttestation>,
    pub sponsorships: BTreeMap<String, LowFeeDaSponsorship>,
    pub reveal_windows: BTreeMap<String, BlobRevealWindow>,
    pub challenge_receipts: BTreeMap<String, ChallengeReceipt>,
    pub data_lanes: BTreeMap<String, PrivateContractDataLane>,
    pub monero_bridge_batches: BTreeMap<String, MoneroBridgeBatchBlob>,
}

impl PrivateDaEscrowState {
    pub fn devnet() -> PrivateDaEscrowResult<Self> {
        let config = PrivateDaEscrowConfig::devnet();
        let height = PRIVATE_DA_ESCROW_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            status: PrivateDaEscrowStatus::Active,
            config,
            encrypted_blobs: BTreeMap::new(),
            erasure_commitments: BTreeMap::new(),
            provider_bonds: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            reveal_windows: BTreeMap::new(),
            challenge_receipts: BTreeMap::new(),
            data_lanes: BTreeMap::new(),
            monero_bridge_batches: BTreeMap::new(),
        };

        let private_lane = PrivateContractDataLane::devnet(
            PrivateDaBlobKind::PrivateContractCall,
            height,
            512 * 1024,
        )?;
        let bridge_lane =
            PrivateContractDataLane::devnet(PrivateDaBlobKind::MoneroBridge, height, 1024 * 1024)?;
        state.insert_data_lane(private_lane)?;
        state.insert_data_lane(bridge_lane)?;

        let lane_keys = state
            .data_lanes
            .values()
            .map(|lane| lane.lane_key.clone())
            .collect::<Vec<_>>();
        let provider_a = DaProviderBond::devnet(
            "devnet-da-provider-a",
            &lane_keys,
            height,
            state.config.provider_bond_units,
        )?;
        let provider_b = DaProviderBond::devnet(
            "devnet-da-provider-b",
            &lane_keys,
            height,
            state.config.provider_bond_units,
        )?;
        let provider_a_id = state.insert_provider_bond(provider_a)?;
        let provider_b_id = state.insert_provider_bond(provider_b)?;

        let sponsorship = LowFeeDaSponsorship::devnet(
            "devnet-da-sponsor",
            PrivateDaBlobKind::PrivateContractCall.default_lane_key(),
            state.config.sponsor_budget_units,
            state.config.low_fee_cap_units,
            height,
            state.config.retention_blocks,
        )?;
        state.insert_sponsorship(sponsorship)?;

        let blob = EncryptedRollupBlobEscrow::new(
            "devnet-private-contract-batch-0",
            PrivateDaBlobKind::PrivateContractCall.default_lane_key(),
            PrivateDaBlobKind::PrivateContractCall,
            "devnet-sequencer",
            &private_da_escrow_commitment("devnet-encrypted-blob", "private-contract-batch-0"),
            &private_da_escrow_commitment("devnet-ciphertext", "private-contract-batch-0"),
            &private_da_escrow_commitment("devnet-kem", "private-contract-batch-0"),
            96 * 1024,
            height,
            &state.config,
            0,
        )?;
        let blob_id = state.insert_encrypted_blob(blob)?;

        for (index, provider_id) in [&provider_a_id, &provider_b_id].iter().enumerate() {
            let commitment = ErasureCodeCommitment::devnet(
                &blob_id,
                provider_id,
                index as u64,
                state.config.min_original_shards,
                state.config.min_parity_shards,
                height,
                state.config.retention_blocks,
            )?;
            state.insert_erasure_commitment(commitment)?;
        }

        let attestation = PqProviderAttestation::new(
            &blob_id,
            &provider_a_id,
            &state.erasure_commitment_root(),
            &json!({ "availability": "sampled", "threshold": "2-of-2", "devnet": true }),
            height,
            state.config.challenge_window_blocks,
        )?;
        state.insert_pq_attestation(attestation)?;

        let reveal_window = BlobRevealWindow::new(
            &blob_id,
            &private_da_escrow_commitment("devnet-encrypted-blob", "private-contract-batch-0"),
            "devnet-light-client",
            height,
            state.config.reveal_window_blocks,
        )?;
        state.insert_reveal_window(reveal_window)?;

        let bridge_batch = MoneroBridgeBatchBlob::devnet(&blob_id, height, 20)?;
        state.insert_monero_bridge_batch(bridge_batch)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateDaEscrowResult<()> {
        if height < self.height {
            return Err("private DA escrow height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn insert_encrypted_blob(
        &mut self,
        blob: EncryptedRollupBlobEscrow,
    ) -> PrivateDaEscrowResult<String> {
        blob.validate()?;
        let id = blob.blob_id.clone();
        insert_unique(
            &mut self.encrypted_blobs,
            id.clone(),
            blob,
            "encrypted blob",
        )?;
        Ok(id)
    }

    pub fn insert_erasure_commitment(
        &mut self,
        commitment: ErasureCodeCommitment,
    ) -> PrivateDaEscrowResult<String> {
        commitment.validate()?;
        let id = commitment.commitment_id.clone();
        insert_unique(
            &mut self.erasure_commitments,
            id.clone(),
            commitment,
            "erasure commitment",
        )?;
        Ok(id)
    }

    pub fn insert_provider_bond(&mut self, bond: DaProviderBond) -> PrivateDaEscrowResult<String> {
        bond.validate()?;
        let id = bond.provider_id.clone();
        insert_unique(&mut self.provider_bonds, id.clone(), bond, "provider bond")?;
        Ok(id)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqProviderAttestation,
    ) -> PrivateDaEscrowResult<String> {
        attestation.validate()?;
        let id = attestation.attestation_id.clone();
        insert_unique(
            &mut self.pq_attestations,
            id.clone(),
            attestation,
            "pq attestation",
        )?;
        Ok(id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeDaSponsorship,
    ) -> PrivateDaEscrowResult<String> {
        sponsorship.validate()?;
        let id = sponsorship.sponsorship_id.clone();
        insert_unique(
            &mut self.sponsorships,
            id.clone(),
            sponsorship,
            "sponsorship",
        )?;
        Ok(id)
    }

    pub fn insert_reveal_window(
        &mut self,
        window: BlobRevealWindow,
    ) -> PrivateDaEscrowResult<String> {
        window.validate()?;
        let id = window.window_id.clone();
        insert_unique(
            &mut self.reveal_windows,
            id.clone(),
            window,
            "reveal window",
        )?;
        Ok(id)
    }

    pub fn insert_challenge_receipt(
        &mut self,
        receipt: ChallengeReceipt,
    ) -> PrivateDaEscrowResult<String> {
        receipt.validate()?;
        let id = receipt.receipt_id.clone();
        insert_unique(
            &mut self.challenge_receipts,
            id.clone(),
            receipt,
            "challenge receipt",
        )?;
        Ok(id)
    }

    pub fn insert_data_lane(
        &mut self,
        lane: PrivateContractDataLane,
    ) -> PrivateDaEscrowResult<String> {
        lane.validate()?;
        let id = lane.lane_id.clone();
        insert_unique(&mut self.data_lanes, id.clone(), lane, "data lane")?;
        Ok(id)
    }

    pub fn insert_monero_bridge_batch(
        &mut self,
        batch: MoneroBridgeBatchBlob,
    ) -> PrivateDaEscrowResult<String> {
        batch.validate()?;
        let id = batch.bridge_batch_id.clone();
        insert_unique(
            &mut self.monero_bridge_batches,
            id.clone(),
            batch,
            "monero bridge batch",
        )?;
        Ok(id)
    }

    pub fn roots(&self) -> PrivateDaEscrowRoots {
        PrivateDaEscrowRoots {
            config_root: self.config.state_root(),
            encrypted_blob_root: self.encrypted_blob_root(),
            erasure_commitment_root: self.erasure_commitment_root(),
            provider_bond_root: self.provider_bond_root(),
            pq_attestation_root: self.pq_attestation_root(),
            sponsorship_root: self.sponsorship_root(),
            reveal_window_root: self.reveal_window_root(),
            challenge_receipt_root: self.challenge_receipt_root(),
            data_lane_root: self.data_lane_root(),
            monero_bridge_batch_root: self.monero_bridge_batch_root(),
        }
    }

    pub fn counters(&self) -> PrivateDaEscrowCounters {
        let mut counters = PrivateDaEscrowCounters {
            encrypted_blobs: self.encrypted_blobs.len() as u64,
            erasure_commitments: self.erasure_commitments.len() as u64,
            provider_bonds: self.provider_bonds.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            reveal_windows: self.reveal_windows.len() as u64,
            private_contract_data_lanes: self.data_lanes.len() as u64,
            monero_bridge_batches: self.monero_bridge_batches.len() as u64,
            ..PrivateDaEscrowCounters::default()
        };
        for blob in self.encrypted_blobs.values() {
            if blob.status.live() && blob.retention_deadline_height >= self.height {
                counters.live_encrypted_blobs = counters.live_encrypted_blobs.saturating_add(1);
            }
            counters.total_payload_bytes = counters
                .total_payload_bytes
                .saturating_add(blob.payload_bytes);
            counters.total_encoded_bytes = counters
                .total_encoded_bytes
                .saturating_add(blob.encoded_bytes);
        }
        for bond in self.provider_bonds.values() {
            counters.total_provider_bond_units = counters
                .total_provider_bond_units
                .saturating_add(bond.bonded_units);
            if bond.status == PrivateDaEscrowStatus::Active {
                counters.active_provider_bonds = counters.active_provider_bonds.saturating_add(1);
            }
        }
        for sponsorship in self.sponsorships.values() {
            counters.total_sponsored_units = counters
                .total_sponsored_units
                .saturating_add(sponsorship.spent_units);
            if sponsorship.status == PrivateDaEscrowStatus::Active
                && sponsorship.expires_at_height >= self.height
            {
                counters.active_sponsorships = counters.active_sponsorships.saturating_add(1);
            }
        }
        for receipt in self.challenge_receipts.values() {
            if receipt.status == PrivateDaEscrowStatus::Challenged
                && receipt.resolve_deadline_height >= self.height
            {
                counters.open_challenges = counters.open_challenges.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_da_escrow_state",
            "protocol_version": PRIVATE_DA_ESCROW_PROTOCOL_VERSION,
            "protocol_id": PRIVATE_DA_ESCROW_PROTOCOL_ID,
            "hash_suite": PRIVATE_DA_ESCROW_HASH_SUITE,
            "pq_signature_scheme": PRIVATE_DA_ESCROW_PQ_SIGNATURE_SCHEME,
            "pq_backup_scheme": PRIVATE_DA_ESCROW_PQ_BACKUP_SCHEME,
            "pq_kem_scheme": PRIVATE_DA_ESCROW_PQ_KEM_SCHEME,
            "encryption_scheme": PRIVATE_DA_ESCROW_ENCRYPTION_SCHEME,
            "erasure_scheme": PRIVATE_DA_ESCROW_ERASURE_SCHEME,
            "height": self.height,
            "status": self.status.as_str(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "private_da_escrow_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_da_escrow_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> PrivateDaEscrowResult<String> {
        self.config.validate()?;
        if !matches!(
            self.status,
            PrivateDaEscrowStatus::Active
                | PrivateDaEscrowStatus::Paused
                | PrivateDaEscrowStatus::Challenged
        ) {
            return Err("state status is invalid".to_string());
        }
        ensure_capacity(
            self.encrypted_blobs.len(),
            PRIVATE_DA_ESCROW_MAX_BLOBS,
            "blobs",
        )?;
        ensure_capacity(
            self.erasure_commitments.len(),
            PRIVATE_DA_ESCROW_MAX_ERASURE_COMMITMENTS,
            "erasure commitments",
        )?;
        ensure_capacity(
            self.provider_bonds.len(),
            PRIVATE_DA_ESCROW_MAX_PROVIDER_BONDS,
            "provider bonds",
        )?;
        ensure_capacity(
            self.pq_attestations.len(),
            PRIVATE_DA_ESCROW_MAX_ATTESTATIONS,
            "pq attestations",
        )?;
        ensure_capacity(
            self.sponsorships.len(),
            PRIVATE_DA_ESCROW_MAX_SPONSORSHIPS,
            "sponsorships",
        )?;
        ensure_capacity(
            self.reveal_windows.len(),
            PRIVATE_DA_ESCROW_MAX_REVEAL_WINDOWS,
            "reveal windows",
        )?;
        ensure_capacity(
            self.challenge_receipts.len(),
            PRIVATE_DA_ESCROW_MAX_CHALLENGES,
            "challenge receipts",
        )?;
        ensure_capacity(
            self.data_lanes.len(),
            PRIVATE_DA_ESCROW_MAX_DATA_LANES,
            "data lanes",
        )?;
        ensure_capacity(
            self.monero_bridge_batches.len(),
            PRIVATE_DA_ESCROW_MAX_BRIDGE_BATCHES,
            "monero bridge batches",
        )?;

        for (id, lane) in &self.data_lanes {
            if id != &lane.lane_id {
                return Err("data lane map key mismatch".to_string());
            }
            lane.validate()?;
        }
        let lane_keys = self
            .data_lanes
            .values()
            .map(|lane| lane.lane_key.clone())
            .collect::<BTreeSet<_>>();
        for (id, blob) in &self.encrypted_blobs {
            if id != &blob.blob_id {
                return Err("encrypted blob map key mismatch".to_string());
            }
            blob.validate()?;
            if !lane_keys.contains(&blob.lane_key) {
                return Err("encrypted blob references unknown lane".to_string());
            }
            if blob.payload_bytes > self.config.max_blob_bytes {
                return Err("encrypted blob exceeds configured max bytes".to_string());
            }
            if blob.privacy_set_size < self.config.min_privacy_set_size {
                return Err("encrypted blob privacy set below floor".to_string());
            }
        }
        for (id, bond) in &self.provider_bonds {
            if id != &bond.provider_id {
                return Err("provider bond map key mismatch".to_string());
            }
            bond.validate()?;
            if bond.bonded_units < self.config.provider_bond_units {
                return Err("provider bond below configured minimum".to_string());
            }
        }
        for (id, commitment) in &self.erasure_commitments {
            if id != &commitment.commitment_id {
                return Err("erasure commitment map key mismatch".to_string());
            }
            commitment.validate()?;
            if !self.encrypted_blobs.contains_key(&commitment.blob_id) {
                return Err("erasure commitment references unknown blob".to_string());
            }
            if !self.provider_bonds.contains_key(&commitment.provider_id) {
                return Err("erasure commitment references unknown provider".to_string());
            }
        }
        for (id, attestation) in &self.pq_attestations {
            if id != &attestation.attestation_id {
                return Err("pq attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            if !self.encrypted_blobs.contains_key(&attestation.blob_id) {
                return Err("pq attestation references unknown blob".to_string());
            }
            if !self.provider_bonds.contains_key(&attestation.provider_id) {
                return Err("pq attestation references unknown provider".to_string());
            }
        }
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
            if sponsorship.max_fee_per_blob_units > self.config.low_fee_cap_units {
                return Err("sponsorship fee cap exceeds low fee config".to_string());
            }
            if !lane_keys.contains(&sponsorship.lane_key) {
                return Err("sponsorship references unknown lane".to_string());
            }
        }
        for (id, window) in &self.reveal_windows {
            if id != &window.window_id {
                return Err("reveal window map key mismatch".to_string());
            }
            window.validate()?;
            if !self.encrypted_blobs.contains_key(&window.blob_id) {
                return Err("reveal window references unknown blob".to_string());
            }
        }
        for (id, receipt) in &self.challenge_receipts {
            if id != &receipt.receipt_id {
                return Err("challenge receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.encrypted_blobs.contains_key(&receipt.blob_id) {
                return Err("challenge receipt references unknown blob".to_string());
            }
            if !self.provider_bonds.contains_key(&receipt.provider_id) {
                return Err("challenge receipt references unknown provider".to_string());
            }
        }
        for (id, batch) in &self.monero_bridge_batches {
            if id != &batch.bridge_batch_id {
                return Err("monero bridge batch map key mismatch".to_string());
            }
            batch.validate()?;
            if !self.encrypted_blobs.contains_key(&batch.blob_id) {
                return Err("monero bridge batch references unknown blob".to_string());
            }
        }
        Ok(self.state_root())
    }

    pub fn encrypted_blob_root(&self) -> String {
        collection_root(
            "ENCRYPTED-BLOB-SET",
            self.encrypted_blobs
                .values()
                .map(EncryptedRollupBlobEscrow::public_record)
                .collect(),
        )
    }

    pub fn erasure_commitment_root(&self) -> String {
        collection_root(
            "ERASURE-COMMITMENT-SET",
            self.erasure_commitments
                .values()
                .map(ErasureCodeCommitment::public_record)
                .collect(),
        )
    }

    pub fn provider_bond_root(&self) -> String {
        collection_root(
            "PROVIDER-BOND-SET",
            self.provider_bonds
                .values()
                .map(DaProviderBond::public_record)
                .collect(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        collection_root(
            "PQ-ATTESTATION-SET",
            self.pq_attestations
                .values()
                .map(PqProviderAttestation::public_record)
                .collect(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        collection_root(
            "SPONSORSHIP-SET",
            self.sponsorships
                .values()
                .map(LowFeeDaSponsorship::public_record)
                .collect(),
        )
    }

    pub fn reveal_window_root(&self) -> String {
        collection_root(
            "REVEAL-WINDOW-SET",
            self.reveal_windows
                .values()
                .map(BlobRevealWindow::public_record)
                .collect(),
        )
    }

    pub fn challenge_receipt_root(&self) -> String {
        collection_root(
            "CHALLENGE-RECEIPT-SET",
            self.challenge_receipts
                .values()
                .map(ChallengeReceipt::public_record)
                .collect(),
        )
    }

    pub fn data_lane_root(&self) -> String {
        collection_root(
            "DATA-LANE-SET",
            self.data_lanes
                .values()
                .map(PrivateContractDataLane::public_record)
                .collect(),
        )
    }

    pub fn monero_bridge_batch_root(&self) -> String {
        collection_root(
            "MONERO-BRIDGE-BATCH-SET",
            self.monero_bridge_batches
                .values()
                .map(MoneroBridgeBatchBlob::public_record)
                .collect(),
        )
    }
}

pub fn private_da_escrow_state_root_from_record(record: &Value) -> String {
    private_da_escrow_record_root("STATE", record)
}

pub fn private_da_escrow_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-DA-ESCROW-{domain}"),
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(PRIVATE_DA_ESCROW_PROTOCOL_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_da_escrow_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-DA-ESCROW-{domain}"),
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_da_escrow_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-COMMITMENT",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_da_escrow_blob_id(
    batch_id: &str,
    lane_key: &str,
    blob_kind: PrivateDaBlobKind,
    sequencer_commitment: &str,
    encrypted_blob_root: &str,
    posted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-BLOB-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(batch_id),
            HashPart::Str(lane_key),
            HashPart::Str(blob_kind.as_str()),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(encrypted_blob_root),
            HashPart::Int(posted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_da_escrow_erasure_commitment_id(
    blob_id: &str,
    provider_id: &str,
    shard_index: u64,
    shard_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-ERASURE-COMMITMENT-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(blob_id),
            HashPart::Str(provider_id),
            HashPart::Int(shard_index as i128),
            HashPart::Str(shard_commitment),
        ],
        32,
    )
}

pub fn private_da_escrow_provider_id(
    operator_commitment: &str,
    lane_root: &str,
    pq_signing_key_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-PROVIDER-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(operator_commitment),
            HashPart::Str(lane_root),
            HashPart::Str(pq_signing_key_commitment),
        ],
        32,
    )
}

pub fn private_da_escrow_attestation_id(
    blob_id: &str,
    provider_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-ATTESTATION-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(blob_id),
            HashPart::Str(provider_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn private_da_escrow_sponsorship_id(
    sponsor_commitment: &str,
    lane_key: &str,
    fee_asset_id: &str,
    eligibility_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-SPONSORSHIP-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_key),
            HashPart::Str(fee_asset_id),
            HashPart::Str(eligibility_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_da_escrow_reveal_window_id(
    blob_id: &str,
    requester_commitment: &str,
    opened_at_height: u64,
    reveal_key_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-REVEAL-WINDOW-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(blob_id),
            HashPart::Str(requester_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(reveal_key_commitment),
        ],
        32,
    )
}

pub fn private_da_escrow_challenge_receipt_id(
    blob_id: &str,
    provider_id: &str,
    challenge_kind: PrivateDaChallengeKind,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-CHALLENGE-RECEIPT-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(blob_id),
            HashPart::Str(provider_id),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_da_escrow_data_lane_id(
    lane_key: &str,
    contract_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-DATA-LANE-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(lane_key),
            HashPart::Str(contract_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_da_escrow_monero_bridge_batch_id(
    blob_id: &str,
    monero_block_root: &str,
    monero_txid_root: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DA-ESCROW-MONERO-BRIDGE-BATCH-ID",
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Str(blob_id),
            HashPart::Str(monero_block_root),
            HashPart::Str(monero_txid_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn private_da_escrow_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    collection_root(domain, records)
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    domain_hash(
        &format!("PRIVATE-DA-ESCROW-{domain}"),
        &[
            HashPart::Int(PRIVATE_DA_ESCROW_PROTOCOL_VERSION as i128),
            HashPart::Json(&Value::Array(records)),
        ],
        32,
    )
}

fn encoded_size(payload_bytes: u64, original_shards: u64, parity_shards: u64) -> u64 {
    if original_shards == 0 {
        return payload_bytes;
    }
    ((payload_bytes as u128) * (original_shards.saturating_add(parity_shards) as u128))
        .div_ceil(original_shards as u128)
        .min(u64::MAX as u128) as u64
}

fn fee_for_bytes(encoded_bytes: u64, fee_per_kib: u64) -> u64 {
    let kib = (encoded_bytes as u128).div_ceil(1024);
    (kib * (fee_per_kib as u128)).min(u64::MAX as u128) as u64
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateDaEscrowResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateDaEscrowResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateDaEscrowResult<()> {
    if value > PRIVATE_DA_ESCROW_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> PrivateDaEscrowResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn ensure_capacity(len: usize, max: usize, label: &str) -> PrivateDaEscrowResult<()> {
    if len > max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> PrivateDaEscrowResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> PrivateDaEscrowResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id, record);
    Ok(())
}
