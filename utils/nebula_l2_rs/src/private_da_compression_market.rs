use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDaCompressionMarketResult<T> = Result<T, String>;

pub const PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION: &str =
    "nebula-private-da-compression-market-v1";
pub const PRIVATE_DA_COMPRESSION_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_DA_COMPRESSION_MARKET_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_DA_COMPRESSION_MARKET_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-da-compression-attestation-v1";
pub const PRIVATE_DA_COMPRESSION_MARKET_COMPRESSION_PROOF_SCHEME: &str =
    "zk-private-da-compression-ratio-proof-v1";
pub const PRIVATE_DA_COMPRESSION_MARKET_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-da-compression-sponsor-v1";
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_BASE_PRICE_MICRO_UNITS: u64 = 90;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MAX_BATCH_BYTES: u64 = 2_097_152;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MAX_COMPRESSED_BYTES: u64 = 393_216;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MAX_CODEC_COUNT: usize = 32;
pub const PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodecFamily {
    ZstdDictionary,
    BrotliStatic,
    PoseidonPacked,
    RangeProofAware,
    MoneroViewTagDelta,
    RecursiveProofDelta,
}

impl CompressionCodecFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZstdDictionary => "zstd_dictionary",
            Self::BrotliStatic => "brotli_static",
            Self::PoseidonPacked => "poseidon_packed",
            Self::RangeProofAware => "range_proof_aware",
            Self::MoneroViewTagDelta => "monero_view_tag_delta",
            Self::RecursiveProofDelta => "recursive_proof_delta",
        }
    }

    pub fn devnet_ratio_bps(self) -> u64 {
        match self {
            Self::ZstdDictionary => 3_800,
            Self::BrotliStatic => 4_200,
            Self::PoseidonPacked => 2_900,
            Self::RangeProofAware => 2_500,
            Self::MoneroViewTagDelta => 1_800,
            Self::RecursiveProofDelta => 2_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionLaneKind {
    PrivateTransfer,
    MoneroBridge,
    SmartContractWitness,
    DefiBatch,
    RecursiveProof,
    WalletSyncDelta,
}

impl CompressionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::SmartContractWitness => "smart_contract_witness",
            Self::DefiBatch => "defi_batch",
            Self::RecursiveProof => "recursive_proof",
            Self::WalletSyncDelta => "wallet_sync_delta",
        }
    }

    pub fn default_priority(self) -> CompressionPriority {
        match self {
            Self::MoneroBridge | Self::RecursiveProof => CompressionPriority::Fast,
            Self::WalletSyncDelta => CompressionPriority::LowFee,
            Self::PrivateTransfer | Self::SmartContractWitness | Self::DefiBatch => {
                CompressionPriority::Balanced
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionPriority {
    LowFee,
    Balanced,
    Fast,
    Emergency,
}

impl CompressionPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Balanced => "balanced",
            Self::Fast => "fast",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::LowFee => 5_500,
            Self::Balanced => 10_000,
            Self::Fast => 16_000,
            Self::Emergency => 25_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionLaneStatus {
    Active,
    Throttled,
    Draining,
    Paused,
    Retired,
}

impl CompressionLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_jobs(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionJobStatus {
    Pending,
    Assigned,
    Compressed,
    Posted,
    Settled,
    Challenged,
    Expired,
    Rejected,
}

impl CompressionJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Assigned => "assigned",
            Self::Compressed => "compressed",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    Quarantined,
    Slashed,
    Retired,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Available,
    Withheld,
    InvalidProof,
    ReorgPending,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Withheld => "withheld",
            Self::InvalidProof => "invalid_proof",
            Self::ReorgPending => "reorg_pending",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Open,
    Reserved,
    Claimed,
    Exhausted,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Claimed => "claimed",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionChallengeKind {
    BadRatioProof,
    BlobUnavailable,
    WrongDictionary,
    SettlementMismatch,
    PqSignatureInvalid,
}

impl CompressionChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRatioProof => "bad_ratio_proof",
            Self::BlobUnavailable => "blob_unavailable",
            Self::WrongDictionary => "wrong_dictionary",
            Self::SettlementMismatch => "settlement_mismatch",
            Self::PqSignatureInvalid => "pq_signature_invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionChallengeStatus {
    Open,
    Proving,
    Upheld,
    Rejected,
    Expired,
}

impl CompressionChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaCompressionMarketConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub base_price_micro_units: u64,
    pub low_fee_rebate_bps: u64,
    pub max_batch_bytes: u64,
    pub max_compressed_bytes: u64,
    pub batch_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_codec_count: usize,
    pub hash_suite: String,
    pub pq_attestation_scheme: String,
    pub compression_proof_scheme: String,
    pub low_fee_sponsor_scheme: String,
}

impl PrivateDaCompressionMarketConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_DA_COMPRESSION_MARKET_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_FEE_ASSET_ID.to_string(),
            base_price_micro_units: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_BASE_PRICE_MICRO_UNITS,
            low_fee_rebate_bps: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_REBATE_BPS,
            max_batch_bytes: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MAX_BATCH_BYTES,
            max_compressed_bytes: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MAX_COMPRESSED_BYTES,
            batch_ttl_blocks: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_BATCH_TTL_BLOCKS,
            challenge_window_blocks: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_codec_count: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MAX_CODEC_COUNT,
            hash_suite: PRIVATE_DA_COMPRESSION_MARKET_HASH_SUITE.to_string(),
            pq_attestation_scheme: PRIVATE_DA_COMPRESSION_MARKET_PQ_ATTESTATION_SCHEME.to_string(),
            compression_proof_scheme: PRIVATE_DA_COMPRESSION_MARKET_COMPRESSION_PROOF_SCHEME
                .to_string(),
            low_fee_sponsor_scheme: PRIVATE_DA_COMPRESSION_MARKET_LOW_FEE_SPONSOR_SCHEME
                .to_string(),
        }
    }

    pub fn validate(&self) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("config.protocol_version", &self.protocol_version)?;
        ensure_nonempty("config.chain_id", &self.chain_id)?;
        ensure_nonempty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("config.hash_suite", &self.hash_suite)?;
        ensure_nonempty("config.pq_attestation_scheme", &self.pq_attestation_scheme)?;
        ensure_nonempty(
            "config.compression_proof_scheme",
            &self.compression_proof_scheme,
        )?;
        ensure_nonempty(
            "config.low_fee_sponsor_scheme",
            &self.low_fee_sponsor_scheme,
        )?;
        ensure_positive("config.base_price_micro_units", self.base_price_micro_units)?;
        ensure_positive("config.max_batch_bytes", self.max_batch_bytes)?;
        ensure_positive("config.max_compressed_bytes", self.max_compressed_bytes)?;
        ensure_positive("config.batch_ttl_blocks", self.batch_ttl_blocks)?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.max_compressed_bytes > self.max_batch_bytes {
            return Err("config.max_compressed_bytes cannot exceed max_batch_bytes".to_string());
        }
        if self.max_codec_count == 0 {
            return Err("config.max_codec_count must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_da_compression_market_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "fee_asset_id": self.fee_asset_id,
            "base_price_micro_units": self.base_price_micro_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_batch_bytes": self.max_batch_bytes,
            "max_compressed_bytes": self.max_compressed_bytes,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_codec_count": self.max_codec_count,
            "hash_suite": self.hash_suite,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "compression_proof_scheme": self.compression_proof_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
        })
    }

    pub fn root(&self) -> String {
        pdac_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionCodec {
    pub codec_id: String,
    pub family: CompressionCodecFamily,
    pub dictionary_root: String,
    pub verifier_key_root: String,
    pub target_ratio_bps: u64,
    pub max_decompress_micros: u64,
    pub min_pq_security_bits: u16,
    pub active: bool,
}

impl CompressionCodec {
    pub fn devnet(codec_id: &str, family: CompressionCodecFamily) -> Self {
        let dictionary_root = pdac_string_root("CODEC-DICTIONARY", &format!("{codec_id}:dict"));
        let verifier_key_root = pdac_string_root("CODEC-VERIFYING-KEY", &format!("{codec_id}:vk"));
        Self {
            codec_id: codec_id.to_string(),
            family,
            dictionary_root,
            verifier_key_root,
            target_ratio_bps: family.devnet_ratio_bps(),
            max_decompress_micros: 25_000,
            min_pq_security_bits: PRIVATE_DA_COMPRESSION_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS,
            active: true,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateDaCompressionMarketConfig,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("codec.codec_id", &self.codec_id)?;
        ensure_nonempty("codec.dictionary_root", &self.dictionary_root)?;
        ensure_nonempty("codec.verifier_key_root", &self.verifier_key_root)?;
        ensure_bps("codec.target_ratio_bps", self.target_ratio_bps)?;
        ensure_positive("codec.max_decompress_micros", self.max_decompress_micros)?;
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err(format!("codec {} below pq security floor", self.codec_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_codec",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "codec_id": self.codec_id,
            "family": self.family.as_str(),
            "dictionary_root": self.dictionary_root,
            "verifier_key_root": self.verifier_key_root,
            "target_ratio_bps": self.target_ratio_bps,
            "max_decompress_micros": self.max_decompress_micros,
            "min_pq_security_bits": self.min_pq_security_bits,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionLane {
    pub lane_id: String,
    pub lane_kind: CompressionLaneKind,
    pub priority: CompressionPriority,
    pub status: CompressionLaneStatus,
    pub max_batch_bytes: u64,
    pub min_privacy_set_size: u64,
    pub accepted_codec_ids: BTreeSet<String>,
    pub sponsor_required: bool,
    pub created_height: u64,
    pub updated_height: u64,
}

impl CompressionLane {
    pub fn devnet(
        lane_id: &str,
        lane_kind: CompressionLaneKind,
        codec_ids: &[String],
        height: u64,
        config: &PrivateDaCompressionMarketConfig,
    ) -> Self {
        Self {
            lane_id: lane_id.to_string(),
            lane_kind,
            priority: lane_kind.default_priority(),
            status: CompressionLaneStatus::Active,
            max_batch_bytes: config.max_batch_bytes,
            min_privacy_set_size: config.min_privacy_set_size,
            accepted_codec_ids: codec_ids.iter().cloned().collect(),
            sponsor_required: matches!(lane_kind, CompressionLaneKind::WalletSyncDelta),
            created_height: height,
            updated_height: height,
        }
    }

    pub fn validate(
        &self,
        codecs: &BTreeMap<String, CompressionCodec>,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("lane.lane_id", &self.lane_id)?;
        ensure_positive("lane.max_batch_bytes", self.max_batch_bytes)?;
        ensure_positive("lane.min_privacy_set_size", self.min_privacy_set_size)?;
        if self.accepted_codec_ids.is_empty() {
            return Err(format!(
                "lane {} must accept at least one codec",
                self.lane_id
            ));
        }
        for codec_id in &self.accepted_codec_ids {
            let codec = codecs.get(codec_id).ok_or_else(|| {
                format!(
                    "lane {} references missing codec {}",
                    self.lane_id, codec_id
                )
            })?;
            if !codec.active {
                return Err(format!(
                    "lane {} references inactive codec {}",
                    self.lane_id, codec_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "priority": self.priority.as_str(),
            "status": self.status.as_str(),
            "max_batch_bytes": self.max_batch_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
            "accepted_codec_ids": self.accepted_codec_ids.iter().cloned().collect::<Vec<_>>(),
            "sponsor_required": self.sponsor_required,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionProvider {
    pub provider_id: String,
    pub operator_commitment: String,
    pub status: ProviderStatus,
    pub supported_codec_ids: BTreeSet<String>,
    pub bond_units: u64,
    pub price_multiplier_bps: u64,
    pub pq_attestation_key_root: String,
    pub served_jobs: u64,
    pub slashed_jobs: u64,
    pub registered_height: u64,
}

impl CompressionProvider {
    pub fn devnet(provider_id: &str, codec_ids: &[String], height: u64) -> Self {
        Self {
            provider_id: provider_id.to_string(),
            operator_commitment: pdac_string_root("PROVIDER-OPERATOR", provider_id),
            status: ProviderStatus::Active,
            supported_codec_ids: codec_ids.iter().cloned().collect(),
            bond_units: 2_500_000,
            price_multiplier_bps: 10_000,
            pq_attestation_key_root: pdac_string_root("PROVIDER-PQ-KEY", provider_id),
            served_jobs: 0,
            slashed_jobs: 0,
            registered_height: height,
        }
    }

    pub fn validate(
        &self,
        codecs: &BTreeMap<String, CompressionCodec>,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("provider.provider_id", &self.provider_id)?;
        ensure_nonempty("provider.operator_commitment", &self.operator_commitment)?;
        ensure_nonempty(
            "provider.pq_attestation_key_root",
            &self.pq_attestation_key_root,
        )?;
        ensure_positive("provider.bond_units", self.bond_units)?;
        ensure_bps("provider.price_multiplier_bps", self.price_multiplier_bps)?;
        if self.supported_codec_ids.is_empty() {
            return Err(format!("provider {} supports no codecs", self.provider_id));
        }
        for codec_id in &self.supported_codec_ids {
            if !codecs.contains_key(codec_id) {
                return Err(format!(
                    "provider {} references missing codec {}",
                    self.provider_id, codec_id
                ));
            }
        }
        Ok(())
    }

    pub fn active(&self) -> bool {
        self.status == ProviderStatus::Active
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_provider",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "supported_codec_ids": self.supported_codec_ids.iter().cloned().collect::<Vec<_>>(),
            "bond_units": self.bond_units,
            "price_multiplier_bps": self.price_multiplier_bps,
            "pq_attestation_key_root": self.pq_attestation_key_root,
            "served_jobs": self.served_jobs,
            "slashed_jobs": self.slashed_jobs,
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionJob {
    pub job_id: String,
    pub lane_id: String,
    pub codec_id: String,
    pub provider_id: String,
    pub source_payload_root: String,
    pub compressed_payload_root: String,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub priority: CompressionPriority,
    pub status: CompressionJobStatus,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub price_micro_units: u64,
}

impl CompressionJob {
    pub fn devnet(
        job_id: &str,
        lane: &CompressionLane,
        codec: &CompressionCodec,
        provider: &CompressionProvider,
        original_bytes: u64,
        height: u64,
        config: &PrivateDaCompressionMarketConfig,
    ) -> Self {
        let compressed_bytes = original_bytes
            .saturating_mul(codec.target_ratio_bps)
            .saturating_div(PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS)
            .max(1);
        let price_micro_units = compression_price_micro_units(
            config.base_price_micro_units,
            original_bytes,
            codec.target_ratio_bps,
            lane.priority,
            provider.price_multiplier_bps,
        );
        Self {
            job_id: job_id.to_string(),
            lane_id: lane.lane_id.clone(),
            codec_id: codec.codec_id.clone(),
            provider_id: provider.provider_id.clone(),
            source_payload_root: pdac_string_root("JOB-SOURCE", job_id),
            compressed_payload_root: pdac_string_root("JOB-COMPRESSED", job_id),
            original_bytes,
            compressed_bytes,
            priority: lane.priority,
            status: CompressionJobStatus::Pending,
            privacy_set_size: lane.min_privacy_set_size.max(config.min_privacy_set_size),
            submitted_height: height,
            expires_height: height.saturating_add(config.batch_ttl_blocks),
            price_micro_units,
        }
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, CompressionLane>,
        codecs: &BTreeMap<String, CompressionCodec>,
        providers: &BTreeMap<String, CompressionProvider>,
        config: &PrivateDaCompressionMarketConfig,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("job.job_id", &self.job_id)?;
        ensure_nonempty("job.source_payload_root", &self.source_payload_root)?;
        ensure_nonempty("job.compressed_payload_root", &self.compressed_payload_root)?;
        ensure_positive("job.original_bytes", self.original_bytes)?;
        ensure_positive("job.compressed_bytes", self.compressed_bytes)?;
        ensure_positive("job.privacy_set_size", self.privacy_set_size)?;
        if self.original_bytes > config.max_batch_bytes {
            return Err(format!("job {} exceeds max batch bytes", self.job_id));
        }
        if self.compressed_bytes > config.max_compressed_bytes {
            return Err(format!("job {} exceeds max compressed bytes", self.job_id));
        }
        if self.submitted_height >= self.expires_height {
            return Err(format!("job {} has invalid expiry", self.job_id));
        }
        let lane = lanes
            .get(&self.lane_id)
            .ok_or_else(|| format!("job {} missing lane {}", self.job_id, self.lane_id))?;
        if !lane.status.accepts_jobs() && !self.status.terminal() {
            return Err(format!("job {} lane does not accept jobs", self.job_id));
        }
        if !lane.accepted_codec_ids.contains(&self.codec_id) {
            return Err(format!("job {} codec not accepted by lane", self.job_id));
        }
        let codec = codecs
            .get(&self.codec_id)
            .ok_or_else(|| format!("job {} missing codec {}", self.job_id, self.codec_id))?;
        if !codec.active {
            return Err(format!("job {} uses inactive codec", self.job_id));
        }
        let provider = providers
            .get(&self.provider_id)
            .ok_or_else(|| format!("job {} missing provider {}", self.job_id, self.provider_id))?;
        if !provider.supported_codec_ids.contains(&self.codec_id) {
            return Err(format!(
                "job {} provider does not support codec",
                self.job_id
            ));
        }
        Ok(())
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.original_bytes == 0 {
            return PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS;
        }
        self.compressed_bytes
            .saturating_mul(PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS)
            .saturating_div(self.original_bytes)
    }

    pub fn expired(&self, height: u64) -> bool {
        !self.status.terminal() && height > self.expires_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_job",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "job_id": self.job_id,
            "lane_id": self.lane_id,
            "codec_id": self.codec_id,
            "provider_id": self.provider_id,
            "source_payload_root": self.source_payload_root,
            "compressed_payload_root": self.compressed_payload_root,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "priority": self.priority.as_str(),
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "price_micro_units": self.price_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub job_ids: Vec<String>,
    pub source_root: String,
    pub compressed_root: String,
    pub settlement_root: String,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
    pub status: CompressionJobStatus,
    pub opened_height: u64,
    pub posted_height: Option<u64>,
}

impl CompressionBatch {
    pub fn new(
        batch_id: &str,
        lane_id: &str,
        jobs: &[CompressionJob],
        height: u64,
    ) -> PrivateDaCompressionMarketResult<Self> {
        if jobs.is_empty() {
            return Err("compression batch requires at least one job".to_string());
        }
        let job_ids = jobs
            .iter()
            .map(|job| job.job_id.clone())
            .collect::<Vec<_>>();
        let source_root = merkle_root(
            "PRIVATE-DA-COMPRESSION-BATCH-SOURCE",
            &jobs
                .iter()
                .map(|job| json!({"job_id": job.job_id, "source": job.source_payload_root}))
                .collect::<Vec<_>>(),
        );
        let compressed_root = merkle_root(
            "PRIVATE-DA-COMPRESSION-BATCH-COMPRESSED",
            &jobs
                .iter()
                .map(|job| json!({"job_id": job.job_id, "compressed": job.compressed_payload_root}))
                .collect::<Vec<_>>(),
        );
        let total_original_bytes = jobs.iter().map(|job| job.original_bytes).sum::<u64>();
        let total_compressed_bytes = jobs.iter().map(|job| job.compressed_bytes).sum::<u64>();
        let settlement_root = pdac_payload_root(
            "BATCH-SETTLEMENT",
            &json!({
                "batch_id": batch_id,
                "lane_id": lane_id,
                "job_ids": job_ids,
                "total_original_bytes": total_original_bytes,
                "total_compressed_bytes": total_compressed_bytes,
            }),
        );
        Ok(Self {
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            job_ids,
            source_root,
            compressed_root,
            settlement_root,
            total_original_bytes,
            total_compressed_bytes,
            status: CompressionJobStatus::Assigned,
            opened_height: height,
            posted_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "job_ids": self.job_ids,
            "source_root": self.source_root,
            "compressed_root": self.compressed_root,
            "settlement_root": self.settlement_root,
            "total_original_bytes": self.total_original_bytes,
            "total_compressed_bytes": self.total_compressed_bytes,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "posted_height": self.posted_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub provider_id: String,
    pub watcher_id: String,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub sample_root: String,
    pub security_bits: u16,
    pub height: u64,
}

impl AvailabilityAttestation {
    pub fn devnet(
        attestation_id: &str,
        batch_id: &str,
        provider_id: &str,
        watcher_id: &str,
        height: u64,
        config: &PrivateDaCompressionMarketConfig,
    ) -> Self {
        Self {
            attestation_id: attestation_id.to_string(),
            batch_id: batch_id.to_string(),
            provider_id: provider_id.to_string(),
            watcher_id: watcher_id.to_string(),
            verdict: AttestationVerdict::Available,
            pq_signature_root: pdac_string_root("ATTESTATION-PQ-SIGNATURE", attestation_id),
            sample_root: pdac_string_root("ATTESTATION-SAMPLE", attestation_id),
            security_bits: config.min_pq_security_bits,
            height,
        }
    }

    pub fn validate(
        &self,
        batches: &BTreeMap<String, CompressionBatch>,
        providers: &BTreeMap<String, CompressionProvider>,
        config: &PrivateDaCompressionMarketConfig,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("attestation.attestation_id", &self.attestation_id)?;
        ensure_nonempty("attestation.watcher_id", &self.watcher_id)?;
        ensure_nonempty("attestation.pq_signature_root", &self.pq_signature_root)?;
        ensure_nonempty("attestation.sample_root", &self.sample_root)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below pq security floor",
                self.attestation_id
            ));
        }
        if !batches.contains_key(&self.batch_id) {
            return Err(format!("attestation {} missing batch", self.attestation_id));
        }
        if !providers.contains_key(&self.provider_id) {
            return Err(format!(
                "attestation {} missing provider",
                self.attestation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "availability_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "provider_id": self.provider_id,
            "watcher_id": self.watcher_id,
            "verdict": self.verdict.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "sample_root": self.sample_root,
            "security_bits": self.security_bits,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionSponsorship {
    pub sponsorship_id: String,
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub budget_micro_units: u64,
    pub reserved_micro_units: u64,
    pub claimed_micro_units: u64,
    pub rebate_bps: u64,
    pub status: SponsorshipStatus,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl CompressionSponsorship {
    pub fn devnet(
        sponsorship_id: &str,
        lane_id: &str,
        height: u64,
        config: &PrivateDaCompressionMarketConfig,
    ) -> Self {
        Self {
            sponsorship_id: sponsorship_id.to_string(),
            lane_id: lane_id.to_string(),
            sponsor_commitment: pdac_string_root("SPONSOR-COMMITMENT", sponsorship_id),
            budget_micro_units: 1_000_000,
            reserved_micro_units: 75_000,
            claimed_micro_units: 0,
            rebate_bps: config.low_fee_rebate_bps,
            status: SponsorshipStatus::Open,
            opened_height: height,
            expires_height: height.saturating_add(config.batch_ttl_blocks.saturating_mul(8)),
        }
    }

    pub fn available_micro_units(&self) -> u64 {
        self.budget_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.claimed_micro_units)
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, CompressionLane>,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_nonempty("sponsorship.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_positive("sponsorship.budget_micro_units", self.budget_micro_units)?;
        ensure_bps("sponsorship.rebate_bps", self.rebate_bps)?;
        if !lanes.contains_key(&self.lane_id) {
            return Err(format!("sponsorship {} missing lane", self.sponsorship_id));
        }
        if self
            .reserved_micro_units
            .saturating_add(self.claimed_micro_units)
            > self.budget_micro_units
        {
            return Err(format!("sponsorship {} over-reserved", self.sponsorship_id));
        }
        if self.opened_height >= self.expires_height {
            return Err(format!(
                "sponsorship {} has invalid expiry",
                self.sponsorship_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_micro_units": self.budget_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "claimed_micro_units": self.claimed_micro_units,
            "available_micro_units": self.available_micro_units(),
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionChallenge {
    pub challenge_id: String,
    pub batch_id: String,
    pub job_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: CompressionChallengeKind,
    pub status: CompressionChallengeStatus,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl CompressionChallenge {
    pub fn devnet(
        challenge_id: &str,
        batch_id: &str,
        job_id: &str,
        challenge_kind: CompressionChallengeKind,
        height: u64,
        config: &PrivateDaCompressionMarketConfig,
    ) -> Self {
        Self {
            challenge_id: challenge_id.to_string(),
            batch_id: batch_id.to_string(),
            job_id: job_id.to_string(),
            challenger_commitment: pdac_string_root("CHALLENGER", challenge_id),
            challenge_kind,
            status: CompressionChallengeStatus::Open,
            evidence_root: pdac_string_root("CHALLENGE-EVIDENCE", challenge_id),
            slash_bps: 2_500,
            opened_height: height,
            expires_height: height.saturating_add(config.challenge_window_blocks),
        }
    }

    pub fn validate(
        &self,
        batches: &BTreeMap<String, CompressionBatch>,
        jobs: &BTreeMap<String, CompressionJob>,
    ) -> PrivateDaCompressionMarketResult<()> {
        ensure_nonempty("challenge.challenge_id", &self.challenge_id)?;
        ensure_nonempty(
            "challenge.challenger_commitment",
            &self.challenger_commitment,
        )?;
        ensure_nonempty("challenge.evidence_root", &self.evidence_root)?;
        ensure_bps("challenge.slash_bps", self.slash_bps)?;
        if !batches.contains_key(&self.batch_id) {
            return Err(format!("challenge {} missing batch", self.challenge_id));
        }
        if !jobs.contains_key(&self.job_id) {
            return Err(format!("challenge {} missing job", self.challenge_id));
        }
        if self.opened_height >= self.expires_height {
            return Err(format!(
                "challenge {} has invalid expiry",
                self.challenge_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "job_id": self.job_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "slash_bps": self.slash_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionMarketEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl CompressionMarketEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> PrivateDaCompressionMarketResult<Self> {
        ensure_nonempty("event.event_kind", event_kind)?;
        ensure_nonempty("event.subject_id", subject_id)?;
        let payload_root = pdac_payload_root("EVENT-PAYLOAD", payload);
        let event_id =
            compression_market_event_id(event_kind, subject_id, &payload_root, height, sequence);
        Ok(Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            height,
            sequence,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_market_event",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaCompressionMarketRoots {
    pub config_root: String,
    pub codec_root: String,
    pub lane_root: String,
    pub provider_root: String,
    pub job_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub event_root: String,
}

impl PrivateDaCompressionMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "codec_root": self.codec_root,
            "lane_root": self.lane_root,
            "provider_root": self.provider_root,
            "job_root": self.job_root,
            "batch_root": self.batch_root,
            "attestation_root": self.attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaCompressionMarketCounters {
    pub codec_count: u64,
    pub lane_count: u64,
    pub provider_count: u64,
    pub active_provider_count: u64,
    pub job_count: u64,
    pub live_job_count: u64,
    pub batch_count: u64,
    pub attestation_count: u64,
    pub sponsorship_count: u64,
    pub challenge_count: u64,
    pub event_count: u64,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
    pub available_sponsor_micro_units: u64,
}

impl PrivateDaCompressionMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "codec_count": self.codec_count,
            "lane_count": self.lane_count,
            "provider_count": self.provider_count,
            "active_provider_count": self.active_provider_count,
            "job_count": self.job_count,
            "live_job_count": self.live_job_count,
            "batch_count": self.batch_count,
            "attestation_count": self.attestation_count,
            "sponsorship_count": self.sponsorship_count,
            "challenge_count": self.challenge_count,
            "event_count": self.event_count,
            "total_original_bytes": self.total_original_bytes,
            "total_compressed_bytes": self.total_compressed_bytes,
            "available_sponsor_micro_units": self.available_sponsor_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDaCompressionMarketState {
    pub config: PrivateDaCompressionMarketConfig,
    pub height: u64,
    pub codecs: BTreeMap<String, CompressionCodec>,
    pub lanes: BTreeMap<String, CompressionLane>,
    pub providers: BTreeMap<String, CompressionProvider>,
    pub jobs: BTreeMap<String, CompressionJob>,
    pub batches: BTreeMap<String, CompressionBatch>,
    pub attestations: BTreeMap<String, AvailabilityAttestation>,
    pub sponsorships: BTreeMap<String, CompressionSponsorship>,
    pub challenges: BTreeMap<String, CompressionChallenge>,
    pub events: BTreeMap<String, CompressionMarketEvent>,
}

impl PrivateDaCompressionMarketState {
    pub fn devnet() -> PrivateDaCompressionMarketResult<Self> {
        let config = PrivateDaCompressionMarketConfig::devnet();
        let height = 1_024;
        let mut state = Self {
            config,
            height,
            codecs: BTreeMap::new(),
            lanes: BTreeMap::new(),
            providers: BTreeMap::new(),
            jobs: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        let codec_a = CompressionCodec::devnet(
            "codec:range-proof-aware:devnet",
            CompressionCodecFamily::RangeProofAware,
        );
        let codec_b = CompressionCodec::devnet(
            "codec:monero-view-tag-delta:devnet",
            CompressionCodecFamily::MoneroViewTagDelta,
        );
        let codec_c = CompressionCodec::devnet(
            "codec:recursive-proof-delta:devnet",
            CompressionCodecFamily::RecursiveProofDelta,
        );
        state.insert_codec(codec_a)?;
        state.insert_codec(codec_b)?;
        state.insert_codec(codec_c)?;
        let codec_ids = state.codecs.keys().cloned().collect::<Vec<_>>();
        let bridge_lane = CompressionLane::devnet(
            "lane:compression:monero_bridge",
            CompressionLaneKind::MoneroBridge,
            &codec_ids,
            height,
            &state.config,
        );
        let wallet_lane = CompressionLane::devnet(
            "lane:compression:wallet_sync_delta",
            CompressionLaneKind::WalletSyncDelta,
            &codec_ids,
            height,
            &state.config,
        );
        state.insert_lane(bridge_lane)?;
        state.insert_lane(wallet_lane)?;
        let provider =
            CompressionProvider::devnet("provider:compression:devnet-a", &codec_ids, height);
        state.insert_provider(provider)?;
        let lane = state
            .lanes
            .get("lane:compression:monero_bridge")
            .cloned()
            .ok_or_else(|| "missing devnet compression lane".to_string())?;
        let codec = state
            .codecs
            .get("codec:range-proof-aware:devnet")
            .cloned()
            .ok_or_else(|| "missing devnet compression codec".to_string())?;
        let provider = state
            .providers
            .get("provider:compression:devnet-a")
            .cloned()
            .ok_or_else(|| "missing devnet compression provider".to_string())?;
        let job_a = CompressionJob::devnet(
            "job:compression:monero-bridge:1",
            &lane,
            &codec,
            &provider,
            640_000,
            height,
            &state.config,
        );
        let job_b = CompressionJob::devnet(
            "job:compression:monero-bridge:2",
            &lane,
            &codec,
            &provider,
            512_000,
            height,
            &state.config,
        );
        state.insert_job(job_a)?;
        state.insert_job(job_b)?;
        let jobs = state.jobs.values().cloned().collect::<Vec<_>>();
        let batch = CompressionBatch::new(
            "batch:compression:monero-bridge:1",
            &lane.lane_id,
            &jobs,
            height,
        )?;
        let batch_id = batch.batch_id.clone();
        state.insert_batch(batch)?;
        state.insert_attestation(AvailabilityAttestation::devnet(
            "attestation:compression:monero-bridge:1",
            &batch_id,
            &provider.provider_id,
            "pq-watchtower:compression:devnet",
            height.saturating_add(1),
            &state.config,
        ))?;
        state.insert_sponsorship(CompressionSponsorship::devnet(
            "sponsorship:compression:wallet-delta:1",
            "lane:compression:wallet_sync_delta",
            height,
            &state.config,
        ))?;
        state.insert_challenge(CompressionChallenge::devnet(
            "challenge:compression:ratio-proof:1",
            &batch_id,
            "job:compression:monero-bridge:1",
            CompressionChallengeKind::BadRatioProof,
            height.saturating_add(2),
            &state.config,
        ))?;
        state.emit_event(
            "devnet_seeded",
            "private_da_compression_market",
            &state.public_record(),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateDaCompressionMarketResult<()> {
        if height < self.height {
            return Err(format!(
                "private da compression market height cannot move backward from {} to {}",
                self.height, height
            ));
        }
        self.height = height;
        for job in self.jobs.values_mut() {
            if job.expired(height) {
                job.status = CompressionJobStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_codec(
        &mut self,
        codec: CompressionCodec,
    ) -> PrivateDaCompressionMarketResult<()> {
        if self.codecs.len() >= self.config.max_codec_count
            && !self.codecs.contains_key(&codec.codec_id)
        {
            return Err("private da compression codec limit exceeded".to_string());
        }
        codec.validate(&self.config)?;
        self.codecs.insert(codec.codec_id.clone(), codec);
        Ok(())
    }

    pub fn insert_lane(&mut self, lane: CompressionLane) -> PrivateDaCompressionMarketResult<()> {
        lane.validate(&self.codecs)?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_provider(
        &mut self,
        provider: CompressionProvider,
    ) -> PrivateDaCompressionMarketResult<()> {
        provider.validate(&self.codecs)?;
        self.providers
            .insert(provider.provider_id.clone(), provider);
        Ok(())
    }

    pub fn insert_job(&mut self, job: CompressionJob) -> PrivateDaCompressionMarketResult<()> {
        job.validate(&self.lanes, &self.codecs, &self.providers, &self.config)?;
        self.jobs.insert(job.job_id.clone(), job);
        Ok(())
    }

    pub fn insert_batch(
        &mut self,
        batch: CompressionBatch,
    ) -> PrivateDaCompressionMarketResult<()> {
        if !self.lanes.contains_key(&batch.lane_id) {
            return Err(format!(
                "compression batch {} references missing lane",
                batch.batch_id
            ));
        }
        for job_id in &batch.job_ids {
            if !self.jobs.contains_key(job_id) {
                return Err(format!(
                    "compression batch {} references missing job {}",
                    batch.batch_id, job_id
                ));
            }
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_attestation(
        &mut self,
        attestation: AvailabilityAttestation,
    ) -> PrivateDaCompressionMarketResult<()> {
        attestation.validate(&self.batches, &self.providers, &self.config)?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: CompressionSponsorship,
    ) -> PrivateDaCompressionMarketResult<()> {
        sponsorship.validate(&self.lanes)?;
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: CompressionChallenge,
    ) -> PrivateDaCompressionMarketResult<()> {
        challenge.validate(&self.batches, &self.jobs)?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn emit_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> PrivateDaCompressionMarketResult<String> {
        let sequence = self.events.len() as u64;
        let event =
            CompressionMarketEvent::new(event_kind, subject_id, payload, self.height, sequence)?;
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn active_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.status.accepts_jobs())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn active_provider_ids(&self) -> Vec<String> {
        self.providers
            .values()
            .filter(|provider| provider.active())
            .map(|provider| provider.provider_id.clone())
            .collect()
    }

    pub fn live_job_ids(&self) -> Vec<String> {
        self.jobs
            .values()
            .filter(|job| !job.status.terminal())
            .map(|job| job.job_id.clone())
            .collect()
    }

    pub fn available_sponsor_micro_units(&self) -> u64 {
        self.sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status == SponsorshipStatus::Open)
            .map(CompressionSponsorship::available_micro_units)
            .sum()
    }

    pub fn roots(&self) -> PrivateDaCompressionMarketRoots {
        PrivateDaCompressionMarketRoots {
            config_root: self.config.root(),
            codec_root: map_root("CODECS", &self.codecs, CompressionCodec::public_record),
            lane_root: map_root("LANES", &self.lanes, CompressionLane::public_record),
            provider_root: map_root(
                "PROVIDERS",
                &self.providers,
                CompressionProvider::public_record,
            ),
            job_root: map_root("JOBS", &self.jobs, CompressionJob::public_record),
            batch_root: map_root("BATCHES", &self.batches, CompressionBatch::public_record),
            attestation_root: map_root(
                "ATTESTATIONS",
                &self.attestations,
                AvailabilityAttestation::public_record,
            ),
            sponsorship_root: map_root(
                "SPONSORSHIPS",
                &self.sponsorships,
                CompressionSponsorship::public_record,
            ),
            challenge_root: map_root(
                "CHALLENGES",
                &self.challenges,
                CompressionChallenge::public_record,
            ),
            event_root: map_root(
                "EVENTS",
                &self.events,
                CompressionMarketEvent::public_record,
            ),
        }
    }

    pub fn counters(&self) -> PrivateDaCompressionMarketCounters {
        PrivateDaCompressionMarketCounters {
            codec_count: self.codecs.len() as u64,
            lane_count: self.lanes.len() as u64,
            provider_count: self.providers.len() as u64,
            active_provider_count: self
                .providers
                .values()
                .filter(|provider| provider.active())
                .count() as u64,
            job_count: self.jobs.len() as u64,
            live_job_count: self
                .jobs
                .values()
                .filter(|job| !job.status.terminal())
                .count() as u64,
            batch_count: self.batches.len() as u64,
            attestation_count: self.attestations.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            challenge_count: self.challenges.len() as u64,
            event_count: self.events.len() as u64,
            total_original_bytes: self.jobs.values().map(|job| job.original_bytes).sum(),
            total_compressed_bytes: self.jobs.values().map(|job| job.compressed_bytes).sum(),
            available_sponsor_micro_units: self.available_sponsor_micro_units(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_da_compression_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DA_COMPRESSION_MARKET_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        private_da_compression_market_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateDaCompressionMarketResult<()> {
        self.config.validate()?;
        for codec in self.codecs.values() {
            codec.validate(&self.config)?;
        }
        for lane in self.lanes.values() {
            lane.validate(&self.codecs)?;
        }
        for provider in self.providers.values() {
            provider.validate(&self.codecs)?;
        }
        for job in self.jobs.values() {
            job.validate(&self.lanes, &self.codecs, &self.providers, &self.config)?;
        }
        for batch in self.batches.values() {
            if !self.lanes.contains_key(&batch.lane_id) {
                return Err(format!("batch {} references missing lane", batch.batch_id));
            }
            for job_id in &batch.job_ids {
                if !self.jobs.contains_key(job_id) {
                    return Err(format!(
                        "batch {} references missing job {}",
                        batch.batch_id, job_id
                    ));
                }
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.batches, &self.providers, &self.config)?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate(&self.lanes)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate(&self.batches, &self.jobs)?;
        }
        Ok(())
    }
}

pub fn private_da_compression_market_state_root_from_record(record: &Value) -> String {
    pdac_payload_root("STATE", record)
}

pub fn compression_market_event_id(
    event_kind: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    pdac_hash(
        "EVENT-ID",
        &[
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn compression_price_micro_units(
    base_price_micro_units: u64,
    original_bytes: u64,
    target_ratio_bps: u64,
    priority: CompressionPriority,
    provider_multiplier_bps: u64,
) -> u64 {
    let kilobytes = original_bytes.saturating_add(1_023).saturating_div(1_024);
    let ratio_discount_bps = PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS.saturating_sub(target_ratio_bps);
    let discounted_bps = PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS
        .saturating_sub(ratio_discount_bps.saturating_div(2))
        .max(1_000);
    base_price_micro_units
        .saturating_mul(kilobytes.max(1))
        .saturating_mul(priority.fee_multiplier_bps())
        .saturating_div(PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS)
        .saturating_mul(provider_multiplier_bps)
        .saturating_div(PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS)
        .saturating_mul(discounted_bps)
        .saturating_div(PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS)
}

fn ensure_nonempty(label: &str, value: &str) -> PrivateDaCompressionMarketResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivateDaCompressionMarketResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PrivateDaCompressionMarketResult<()> {
    if value > PRIVATE_DA_COMPRESSION_MARKET_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| json!({"id": id, "record": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-DA-COMPRESSION-{domain}"), &leaves)
}

fn pdac_payload_root(domain: &str, payload: &Value) -> String {
    pdac_hash(domain, &[HashPart::Json(payload)])
}

fn pdac_string_root(domain: &str, value: &str) -> String {
    pdac_hash(domain, &[HashPart::Str(value)])
}

fn pdac_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-DA-COMPRESSION-MARKET-{domain}"),
        parts,
        32,
    )
}
