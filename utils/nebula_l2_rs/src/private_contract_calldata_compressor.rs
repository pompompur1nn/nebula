use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractCalldataCompressorResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PROTOCOL_VERSION: &str =
    "nebula-private-contract-calldata-compressor-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DICTIONARY_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+SHAKE256-calldata-dictionary-seal-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-decompressor-attestation-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_WITNESS_COMMITMENT_SUITE: &str =
    "private-calldata-witness-chunk-commitments-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_REBATE_SCHEME: &str =
    "low-fee-private-calldata-compression-rebate-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_CHALLENGE_SCHEME: &str =
    "invalid-private-calldata-decompression-challenge-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_ROLLBACK_SCHEME: &str =
    "private-calldata-decompression-rollback-receipt-v1";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEVNET_HEIGHT: u64 = 1_792;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEVNET_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEVNET_REBATE_VAULT: &str =
    "devnet-private-calldata-compression-rebate-vault";
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_DICTIONARY_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_BATCH_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 288;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_DICTIONARY_BYTES: u64 = 1_048_576;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_COMPRESSED_BYTES: u64 = 393_216;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_UNCOMPRESSED_BYTES: u64 = 4_194_304;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_WITNESS_CHUNKS: u64 = 512;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_WITNESS_CHUNK_BYTES: u64 = 4_096;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MIN_COMPRESSION_BPS: u64 = 2_000;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_REBATE_BPS: u64 = 8_500;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_PROVIDER_BOND_UNITS: u64 = 125_000;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_REBATE_BUDGET_UNITS: u64 = 750_000;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_DICTIONARIES: usize = 512;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_ABI_LANES: usize = 512;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_BATCHES: usize = 512;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_WITNESSES: usize = 1024;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_ATTESTATIONS: usize = 1024;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_REBATES: usize = 1024;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_CHALLENGES: usize = 512;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_ROLLBACKS: usize = 512;
pub const PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_PUBLIC_RECORDS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataCompressionLaneKind {
    PrivateSwap,
    Lending,
    Perps,
    Stablecoin,
    Governance,
    Account,
    Bridge,
    Oracle,
    Custom,
}

impl CalldataCompressionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Stablecoin => "stablecoin",
            Self::Governance => "governance",
            Self::Account => "account",
            Self::Bridge => "bridge",
            Self::Oracle => "oracle",
            Self::Custom => "custom",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::Bridge => 1_000,
            Self::Stablecoin => 925,
            Self::PrivateSwap => 875,
            Self::Lending => 850,
            Self::Perps => 825,
            Self::Oracle => 760,
            Self::Account => 700,
            Self::Governance => 520,
            Self::Custom => 400,
        }
    }

    pub fn private_by_default(self) -> bool {
        matches!(
            self,
            Self::PrivateSwap
                | Self::Lending
                | Self::Perps
                | Self::Stablecoin
                | Self::Account
                | Self::Bridge
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DictionaryScope {
    Contract,
    Namespace,
    Protocol,
    AccountClass,
    EmergencyPatch,
}

impl DictionaryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Namespace => "namespace",
            Self::Protocol => "protocol",
            Self::AccountClass => "account_class",
            Self::EmergencyPatch => "emergency_patch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DictionaryStatus {
    Draft,
    Sealed,
    Active,
    Rotating,
    Expired,
    Revoked,
}

impl DictionaryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Sealed | Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiLaneStatus {
    Draft,
    Active,
    Saturated,
    Paused,
    Retired,
}

impl AbiLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressedBatchStatus {
    Proposed,
    Witnessed,
    Attested,
    RebateReserved,
    Settled,
    Challenged,
    RolledBack,
    Expired,
}

impl CompressedBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Witnessed => "witnessed",
            Self::Attested => "attested",
            Self::RebateReserved => "rebate_reserved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::Witnessed
                | Self::Attested
                | Self::RebateReserved
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessChunkStatus {
    Committed,
    Available,
    Sampled,
    Pinned,
    Missing,
    Disputed,
}

impl WitnessChunkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Available => "available",
            Self::Sampled => "sampled",
            Self::Pinned => "pinned",
            Self::Missing => "missing",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Verified,
    Superseded,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Superseded => "superseded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Proposed | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Paid,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }

    pub fn payable(self) -> bool {
        matches!(self, Self::Quoted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceCommitted,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceCommitted => "evidence_committed",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceCommitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Prepared,
    Applied,
    Published,
    Disputed,
    Cancelled,
}

impl RollbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Published => "published",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCalldataCompressorConfig {
    pub epoch_blocks: u64,
    pub dictionary_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub rollback_window_blocks: u64,
    pub max_dictionary_bytes: u64,
    pub max_compressed_bytes: u64,
    pub max_uncompressed_bytes: u64,
    pub max_witness_chunks: u64,
    pub witness_chunk_bytes: u64,
    pub min_compression_bps: u64,
    pub max_rebate_bps: u64,
    pub min_pq_security_bits: u16,
    pub provider_bond_units: u64,
    pub rebate_budget_units: u64,
    pub fee_asset_id: String,
    pub rebate_vault_id: String,
    pub dictionary_encryption_suite: String,
    pub pq_attestation_suite: String,
    pub witness_commitment_suite: String,
    pub rebate_scheme: String,
    pub challenge_scheme: String,
    pub rollback_scheme: String,
    pub hash_suite: String,
    pub require_pq_attestation: bool,
    pub require_witness_chunks: bool,
}

impl PrivateContractCalldataCompressorConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_EPOCH_BLOCKS,
            dictionary_ttl_blocks:
                PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_DICTIONARY_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_BATCH_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            rollback_window_blocks:
                PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            max_dictionary_bytes: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_DICTIONARY_BYTES,
            max_compressed_bytes: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_COMPRESSED_BYTES,
            max_uncompressed_bytes:
                PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_UNCOMPRESSED_BYTES,
            max_witness_chunks: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_WITNESS_CHUNKS,
            witness_chunk_bytes: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_WITNESS_CHUNK_BYTES,
            min_compression_bps: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MIN_COMPRESSION_BPS,
            max_rebate_bps: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MAX_REBATE_BPS,
            min_pq_security_bits: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            provider_bond_units: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_PROVIDER_BOND_UNITS,
            rebate_budget_units: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEFAULT_REBATE_BUDGET_UNITS,
            fee_asset_id: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEVNET_FEE_ASSET_ID.to_string(),
            rebate_vault_id: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEVNET_REBATE_VAULT.to_string(),
            dictionary_encryption_suite:
                PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DICTIONARY_ENCRYPTION_SUITE.to_string(),
            pq_attestation_suite: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PQ_ATTESTATION_SUITE
                .to_string(),
            witness_commitment_suite: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_WITNESS_COMMITMENT_SUITE
                .to_string(),
            rebate_scheme: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_REBATE_SCHEME.to_string(),
            challenge_scheme: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_CHALLENGE_SCHEME.to_string(),
            rollback_scheme: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_ROLLBACK_SCHEME.to_string(),
            hash_suite: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_HASH_SUITE.to_string(),
            require_pq_attestation: true,
            require_witness_chunks: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_calldata_compressor_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_SCHEMA_VERSION,
            "epoch_blocks": self.epoch_blocks,
            "dictionary_ttl_blocks": self.dictionary_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "rollback_window_blocks": self.rollback_window_blocks,
            "max_dictionary_bytes": self.max_dictionary_bytes,
            "max_compressed_bytes": self.max_compressed_bytes,
            "max_uncompressed_bytes": self.max_uncompressed_bytes,
            "max_witness_chunks": self.max_witness_chunks,
            "witness_chunk_bytes": self.witness_chunk_bytes,
            "min_compression_bps": self.min_compression_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "provider_bond_units": self.provider_bond_units,
            "rebate_budget_units": self.rebate_budget_units,
            "fee_asset_id": self.fee_asset_id,
            "rebate_vault_id": self.rebate_vault_id,
            "dictionary_encryption_suite": self.dictionary_encryption_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "witness_commitment_suite": self.witness_commitment_suite,
            "rebate_scheme": self.rebate_scheme,
            "challenge_scheme": self.challenge_scheme,
            "rollback_scheme": self.rollback_scheme,
            "hash_suite": self.hash_suite,
            "require_pq_attestation": self.require_pq_attestation,
            "require_witness_chunks": self.require_witness_chunks,
        })
    }

    pub fn config_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "CONFIG",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCalldataCompressorResult<()> {
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("dictionary_ttl_blocks", self.dictionary_ttl_blocks)?;
        ensure_positive("batch_ttl_blocks", self.batch_ttl_blocks)?;
        ensure_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        ensure_positive("rollback_window_blocks", self.rollback_window_blocks)?;
        ensure_positive("max_dictionary_bytes", self.max_dictionary_bytes)?;
        ensure_positive("max_compressed_bytes", self.max_compressed_bytes)?;
        ensure_positive("max_uncompressed_bytes", self.max_uncompressed_bytes)?;
        ensure_positive("max_witness_chunks", self.max_witness_chunks)?;
        ensure_positive("witness_chunk_bytes", self.witness_chunk_bytes)?;
        ensure_positive("provider_bond_units", self.provider_bond_units)?;
        ensure_positive("rebate_budget_units", self.rebate_budget_units)?;
        validate_bps("min_compression_bps", self.min_compression_bps)?;
        validate_bps("max_rebate_bps", self.max_rebate_bps)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("rebate_vault_id", &self.rebate_vault_id)?;
        ensure_nonempty(
            "dictionary_encryption_suite",
            &self.dictionary_encryption_suite,
        )?;
        ensure_nonempty("pq_attestation_suite", &self.pq_attestation_suite)?;
        ensure_nonempty("witness_commitment_suite", &self.witness_commitment_suite)?;
        ensure_nonempty("rebate_scheme", &self.rebate_scheme)?;
        ensure_nonempty("challenge_scheme", &self.challenge_scheme)?;
        ensure_nonempty("rollback_scheme", &self.rollback_scheme)?;
        ensure_nonempty("hash_suite", &self.hash_suite)?;
        if self.min_pq_security_bits < 128 {
            return Err("private calldata compressor pq security below policy".to_string());
        }
        if self.max_compressed_bytes > self.max_uncompressed_bytes {
            return Err(
                "private calldata compressor compressed byte cap exceeds raw cap".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCalldataDictionary {
    pub dictionary_id: String,
    pub contract_commitment: String,
    pub namespace: String,
    pub scope: DictionaryScope,
    pub version: u64,
    pub ciphertext_root: String,
    pub token_root: String,
    pub selector_root: String,
    pub recipient_key_root: String,
    pub disclosure_policy_root: String,
    pub byte_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: DictionaryStatus,
}

impl EncryptedCalldataDictionary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_commitment: impl Into<String>,
        namespace: impl Into<String>,
        scope: DictionaryScope,
        version: u64,
        ciphertext_root: impl Into<String>,
        token_root: impl Into<String>,
        selector_root: impl Into<String>,
        recipient_key_root: impl Into<String>,
        disclosure_policy_root: impl Into<String>,
        byte_size: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let contract_commitment = contract_commitment.into();
        let namespace = namespace.into();
        let ciphertext_root = ciphertext_root.into();
        let token_root = token_root.into();
        let selector_root = selector_root.into();
        let recipient_key_root = recipient_key_root.into();
        let disclosure_policy_root = disclosure_policy_root.into();
        let dictionary_id = private_contract_calldata_compressor_hash(
            "DICTIONARY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&contract_commitment),
                HashPart::Str(&namespace),
                HashPart::Str(scope.as_str()),
                HashPart::Int(version as i128),
                HashPart::Str(&ciphertext_root),
            ],
        );
        Self {
            dictionary_id,
            contract_commitment,
            namespace,
            scope,
            version,
            ciphertext_root,
            token_root,
            selector_root,
            recipient_key_root,
            disclosure_policy_root,
            byte_size,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: DictionaryStatus::Sealed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_calldata_dictionary",
            "dictionary_id": self.dictionary_id,
            "contract_commitment": self.contract_commitment,
            "namespace": self.namespace,
            "scope": self.scope.as_str(),
            "version": self.version,
            "ciphertext_root": self.ciphertext_root,
            "token_root": self.token_root,
            "selector_root": self.selector_root,
            "recipient_key_root": self.recipient_key_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "byte_size": self.byte_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn dictionary_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "DICTIONARY",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(
        &self,
        config: &PrivateContractCalldataCompressorConfig,
    ) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("dictionary_id", &self.dictionary_id)?;
        ensure_nonempty("contract_commitment", &self.contract_commitment)?;
        ensure_nonempty("namespace", &self.namespace)?;
        ensure_nonempty("ciphertext_root", &self.ciphertext_root)?;
        ensure_nonempty("token_root", &self.token_root)?;
        ensure_nonempty("selector_root", &self.selector_root)?;
        ensure_nonempty("recipient_key_root", &self.recipient_key_root)?;
        ensure_nonempty("disclosure_policy_root", &self.disclosure_policy_root)?;
        ensure_positive("dictionary_version", self.version)?;
        ensure_positive("dictionary_byte_size", self.byte_size)?;
        if self.byte_size > config.max_dictionary_bytes {
            return Err("private calldata dictionary exceeds configured byte cap".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("private calldata dictionary expiry must be after creation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAbiCompressionLane {
    pub lane_id: String,
    pub contract_commitment: String,
    pub selector_root: String,
    pub dictionary_id: String,
    pub lane_kind: CalldataCompressionLaneKind,
    pub codec_profile: String,
    pub compression_strategy: String,
    pub priority: u64,
    pub expected_savings_bps: u64,
    pub max_batch_bytes: u64,
    pub activated_at_height: u64,
    pub status: AbiLaneStatus,
}

impl ContractAbiCompressionLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_commitment: impl Into<String>,
        selector_root: impl Into<String>,
        dictionary_id: impl Into<String>,
        lane_kind: CalldataCompressionLaneKind,
        codec_profile: impl Into<String>,
        compression_strategy: impl Into<String>,
        expected_savings_bps: u64,
        max_batch_bytes: u64,
        activated_at_height: u64,
    ) -> Self {
        let contract_commitment = contract_commitment.into();
        let selector_root = selector_root.into();
        let dictionary_id = dictionary_id.into();
        let codec_profile = codec_profile.into();
        let compression_strategy = compression_strategy.into();
        let lane_id = private_contract_calldata_compressor_hash(
            "ABI-LANE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&contract_commitment),
                HashPart::Str(&selector_root),
                HashPart::Str(&dictionary_id),
                HashPart::Str(lane_kind.as_str()),
                HashPart::Str(&codec_profile),
            ],
        );
        Self {
            lane_id,
            contract_commitment,
            selector_root,
            dictionary_id,
            lane_kind,
            codec_profile,
            compression_strategy,
            priority: lane_kind.default_priority(),
            expected_savings_bps,
            max_batch_bytes,
            activated_at_height,
            status: AbiLaneStatus::Active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_abi_compression_lane",
            "lane_id": self.lane_id,
            "contract_commitment": self.contract_commitment,
            "selector_root": self.selector_root,
            "dictionary_id": self.dictionary_id,
            "lane_kind": self.lane_kind.as_str(),
            "codec_profile": self.codec_profile,
            "compression_strategy": self.compression_strategy,
            "priority": self.priority,
            "expected_savings_bps": self.expected_savings_bps,
            "max_batch_bytes": self.max_batch_bytes,
            "activated_at_height": self.activated_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn lane_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "ABI-LANE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(
        &self,
        config: &PrivateContractCalldataCompressorConfig,
    ) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("contract_commitment", &self.contract_commitment)?;
        ensure_nonempty("selector_root", &self.selector_root)?;
        ensure_nonempty("dictionary_id", &self.dictionary_id)?;
        ensure_nonempty("codec_profile", &self.codec_profile)?;
        ensure_nonempty("compression_strategy", &self.compression_strategy)?;
        ensure_positive("lane_priority", self.priority)?;
        ensure_positive("lane_max_batch_bytes", self.max_batch_bytes)?;
        validate_bps("lane_expected_savings_bps", self.expected_savings_bps)?;
        if self.expected_savings_bps < config.min_compression_bps {
            return Err("private calldata lane expected savings below minimum".to_string());
        }
        if self.max_batch_bytes > config.max_compressed_bytes {
            return Err("private calldata lane max batch bytes exceeds config".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedCalldataBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub dictionary_id: String,
    pub submitter_commitment: String,
    pub compressed_calldata_root: String,
    pub decompressed_calldata_root: String,
    pub call_index_root: String,
    pub nullifier_root: String,
    pub privacy_budget_root: String,
    pub witness_chunk_root: String,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub call_count: u64,
    pub fee_units: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: CompressedBatchStatus,
}

impl CompressedCalldataBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: impl Into<String>,
        dictionary_id: impl Into<String>,
        submitter_commitment: impl Into<String>,
        compressed_calldata_root: impl Into<String>,
        decompressed_calldata_root: impl Into<String>,
        call_index_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        witness_chunk_root: impl Into<String>,
        compressed_bytes: u64,
        uncompressed_bytes: u64,
        call_count: u64,
        fee_units: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let lane_id = lane_id.into();
        let dictionary_id = dictionary_id.into();
        let submitter_commitment = submitter_commitment.into();
        let compressed_calldata_root = compressed_calldata_root.into();
        let decompressed_calldata_root = decompressed_calldata_root.into();
        let call_index_root = call_index_root.into();
        let nullifier_root = nullifier_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        let witness_chunk_root = witness_chunk_root.into();
        let batch_id = private_contract_calldata_compressor_hash(
            "BATCH-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&lane_id),
                HashPart::Str(&dictionary_id),
                HashPart::Str(&submitter_commitment),
                HashPart::Str(&compressed_calldata_root),
                HashPart::Int(submitted_at_height as i128),
            ],
        );
        Self {
            batch_id,
            lane_id,
            dictionary_id,
            submitter_commitment,
            compressed_calldata_root,
            decompressed_calldata_root,
            call_index_root,
            nullifier_root,
            privacy_budget_root,
            witness_chunk_root,
            compressed_bytes,
            uncompressed_bytes,
            call_count,
            fee_units,
            submitted_at_height,
            expires_at_height: submitted_at_height.saturating_add(ttl_blocks),
            status: CompressedBatchStatus::Proposed,
        }
    }

    pub fn compression_savings_bps(&self) -> u64 {
        if self.uncompressed_bytes == 0 || self.compressed_bytes >= self.uncompressed_bytes {
            return 0;
        }
        self.uncompressed_bytes
            .saturating_sub(self.compressed_bytes)
            .saturating_mul(PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_BPS)
            / self.uncompressed_bytes
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compressed_calldata_batch",
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "dictionary_id": self.dictionary_id,
            "submitter_commitment": self.submitter_commitment,
            "compressed_calldata_root": self.compressed_calldata_root,
            "decompressed_calldata_root": self.decompressed_calldata_root,
            "call_index_root": self.call_index_root,
            "nullifier_root": self.nullifier_root,
            "privacy_budget_root": self.privacy_budget_root,
            "witness_chunk_root": self.witness_chunk_root,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "call_count": self.call_count,
            "fee_units": self.fee_units,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "compression_savings_bps": self.compression_savings_bps(),
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        private_contract_calldata_compressor_hash("BATCH", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(
        &self,
        config: &PrivateContractCalldataCompressorConfig,
    ) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("dictionary_id", &self.dictionary_id)?;
        ensure_nonempty("submitter_commitment", &self.submitter_commitment)?;
        ensure_nonempty("compressed_calldata_root", &self.compressed_calldata_root)?;
        ensure_nonempty(
            "decompressed_calldata_root",
            &self.decompressed_calldata_root,
        )?;
        ensure_nonempty("call_index_root", &self.call_index_root)?;
        ensure_nonempty("nullifier_root", &self.nullifier_root)?;
        ensure_nonempty("privacy_budget_root", &self.privacy_budget_root)?;
        ensure_nonempty("witness_chunk_root", &self.witness_chunk_root)?;
        ensure_positive("compressed_bytes", self.compressed_bytes)?;
        ensure_positive("uncompressed_bytes", self.uncompressed_bytes)?;
        ensure_positive("call_count", self.call_count)?;
        if self.compressed_bytes > config.max_compressed_bytes {
            return Err("private calldata compressed batch exceeds byte cap".to_string());
        }
        if self.uncompressed_bytes > config.max_uncompressed_bytes {
            return Err("private calldata decompressed batch exceeds byte cap".to_string());
        }
        if self.compressed_bytes >= self.uncompressed_bytes {
            return Err("private calldata batch does not compress calldata".to_string());
        }
        if self.compression_savings_bps() < config.min_compression_bps {
            return Err("private calldata batch savings below minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("private calldata batch expiry must be after submission".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessChunkCommitment {
    pub chunk_id: String,
    pub batch_id: String,
    pub chunk_index: u64,
    pub chunk_count: u64,
    pub compressed_chunk_root: String,
    pub decompressed_chunk_root: String,
    pub availability_provider: String,
    pub da_pointer_root: String,
    pub chunk_byte_size: u64,
    pub committed_at_height: u64,
    pub status: WitnessChunkStatus,
}

impl WitnessChunkCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        chunk_index: u64,
        chunk_count: u64,
        compressed_chunk_root: impl Into<String>,
        decompressed_chunk_root: impl Into<String>,
        availability_provider: impl Into<String>,
        da_pointer_root: impl Into<String>,
        chunk_byte_size: u64,
        committed_at_height: u64,
    ) -> Self {
        let batch_id = batch_id.into();
        let compressed_chunk_root = compressed_chunk_root.into();
        let decompressed_chunk_root = decompressed_chunk_root.into();
        let availability_provider = availability_provider.into();
        let da_pointer_root = da_pointer_root.into();
        let chunk_id = private_contract_calldata_compressor_hash(
            "WITNESS-CHUNK-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&batch_id),
                HashPart::Int(chunk_index as i128),
                HashPart::Int(chunk_count as i128),
                HashPart::Str(&compressed_chunk_root),
            ],
        );
        Self {
            chunk_id,
            batch_id,
            chunk_index,
            chunk_count,
            compressed_chunk_root,
            decompressed_chunk_root,
            availability_provider,
            da_pointer_root,
            chunk_byte_size,
            committed_at_height,
            status: WitnessChunkStatus::Committed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_chunk_commitment",
            "chunk_id": self.chunk_id,
            "batch_id": self.batch_id,
            "chunk_index": self.chunk_index,
            "chunk_count": self.chunk_count,
            "compressed_chunk_root": self.compressed_chunk_root,
            "decompressed_chunk_root": self.decompressed_chunk_root,
            "availability_provider": self.availability_provider,
            "da_pointer_root": self.da_pointer_root,
            "chunk_byte_size": self.chunk_byte_size,
            "committed_at_height": self.committed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn chunk_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "WITNESS-CHUNK",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(
        &self,
        config: &PrivateContractCalldataCompressorConfig,
    ) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("chunk_id", &self.chunk_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("compressed_chunk_root", &self.compressed_chunk_root)?;
        ensure_nonempty("decompressed_chunk_root", &self.decompressed_chunk_root)?;
        ensure_nonempty("availability_provider", &self.availability_provider)?;
        ensure_nonempty("da_pointer_root", &self.da_pointer_root)?;
        ensure_positive("chunk_count", self.chunk_count)?;
        ensure_positive("chunk_byte_size", self.chunk_byte_size)?;
        if self.chunk_index >= self.chunk_count {
            return Err("private calldata witness chunk index outside chunk count".to_string());
        }
        if self.chunk_count > config.max_witness_chunks {
            return Err("private calldata witness chunk count exceeds config".to_string());
        }
        if self.chunk_byte_size > config.witness_chunk_bytes {
            return Err("private calldata witness chunk byte size exceeds config".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDecompressorAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub decompressor_commitment: String,
    pub pq_public_key_commitment: String,
    pub dictionary_id: String,
    pub codec_profile: String,
    pub transcript_root: String,
    pub decompressed_calldata_root: String,
    pub witness_chunk_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl PqDecompressorAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        decompressor_commitment: impl Into<String>,
        pq_public_key_commitment: impl Into<String>,
        dictionary_id: impl Into<String>,
        codec_profile: impl Into<String>,
        transcript_root: impl Into<String>,
        decompressed_calldata_root: impl Into<String>,
        witness_chunk_root: impl Into<String>,
        signature_root: impl Into<String>,
        security_bits: u16,
        attested_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let batch_id = batch_id.into();
        let decompressor_commitment = decompressor_commitment.into();
        let pq_public_key_commitment = pq_public_key_commitment.into();
        let dictionary_id = dictionary_id.into();
        let codec_profile = codec_profile.into();
        let transcript_root = transcript_root.into();
        let decompressed_calldata_root = decompressed_calldata_root.into();
        let witness_chunk_root = witness_chunk_root.into();
        let signature_root = signature_root.into();
        let attestation_id = private_contract_calldata_compressor_hash(
            "PQ-DECOMPRESSOR-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&batch_id),
                HashPart::Str(&decompressor_commitment),
                HashPart::Str(&dictionary_id),
                HashPart::Str(&transcript_root),
                HashPart::Int(attested_at_height as i128),
            ],
        );
        Self {
            attestation_id,
            batch_id,
            decompressor_commitment,
            pq_public_key_commitment,
            dictionary_id,
            codec_profile,
            transcript_root,
            decompressed_calldata_root,
            witness_chunk_root,
            signature_root,
            security_bits,
            attested_at_height,
            expires_at_height: attested_at_height.saturating_add(ttl_blocks),
            status: AttestationStatus::Proposed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_decompressor_attestation",
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "decompressor_commitment": self.decompressor_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "dictionary_id": self.dictionary_id,
            "codec_profile": self.codec_profile,
            "transcript_root": self.transcript_root,
            "decompressed_calldata_root": self.decompressed_calldata_root,
            "witness_chunk_root": self.witness_chunk_root,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "PQ-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(
        &self,
        config: &PrivateContractCalldataCompressorConfig,
    ) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("attestation_id", &self.attestation_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("decompressor_commitment", &self.decompressor_commitment)?;
        ensure_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        ensure_nonempty("dictionary_id", &self.dictionary_id)?;
        ensure_nonempty("codec_profile", &self.codec_profile)?;
        ensure_nonempty("transcript_root", &self.transcript_root)?;
        ensure_nonempty(
            "decompressed_calldata_root",
            &self.decompressed_calldata_root,
        )?;
        ensure_nonempty("witness_chunk_root", &self.witness_chunk_root)?;
        ensure_nonempty("signature_root", &self.signature_root)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err(
                "private calldata decompressor attestation below pq security floor".to_string(),
            );
        }
        if self.expires_at_height <= self.attested_at_height {
            return Err(
                "private calldata attestation expiry must be after attestation".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeCompressionRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub rebate_vault_id: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub compressed_fee_units: u64,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub compression_savings_bps: u64,
    pub sponsor_proof_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: RebateStatus,
}

impl LowFeeCompressionRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        config: &PrivateContractCalldataCompressorConfig,
        gross_fee_units: u64,
        compressed_fee_units: u64,
        compression_savings_bps: u64,
        sponsor_proof_root: impl Into<String>,
        reserved_at_height: u64,
    ) -> Self {
        let batch_id = batch_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let sponsor_proof_root = sponsor_proof_root.into();
        let rebate_bps = compression_savings_bps.min(config.max_rebate_bps);
        let rebate_units = gross_fee_units
            .saturating_sub(compressed_fee_units)
            .saturating_mul(rebate_bps)
            / PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_BPS;
        let rebate_id = private_contract_calldata_compressor_hash(
            "LOW-FEE-REBATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&batch_id),
                HashPart::Str(&beneficiary_commitment),
                HashPart::Str(&config.rebate_vault_id),
                HashPart::Str(&sponsor_proof_root),
            ],
        );
        Self {
            rebate_id,
            batch_id,
            beneficiary_commitment,
            rebate_vault_id: config.rebate_vault_id.clone(),
            fee_asset_id: config.fee_asset_id.clone(),
            gross_fee_units,
            compressed_fee_units,
            rebate_units,
            rebate_bps,
            compression_savings_bps,
            sponsor_proof_root,
            reserved_at_height,
            expires_at_height: reserved_at_height.saturating_add(config.batch_ttl_blocks),
            status: RebateStatus::Quoted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_compression_rebate",
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_vault_id": self.rebate_vault_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "compressed_fee_units": self.compressed_fee_units,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "compression_savings_bps": self.compression_savings_bps,
            "sponsor_proof_root": self.sponsor_proof_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn rebate_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "REBATE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(
        &self,
        config: &PrivateContractCalldataCompressorConfig,
    ) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("rebate_id", &self.rebate_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("beneficiary_commitment", &self.beneficiary_commitment)?;
        ensure_nonempty("rebate_vault_id", &self.rebate_vault_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("sponsor_proof_root", &self.sponsor_proof_root)?;
        ensure_positive("gross_fee_units", self.gross_fee_units)?;
        validate_bps("rebate_bps", self.rebate_bps)?;
        validate_bps("compression_savings_bps", self.compression_savings_bps)?;
        if self.compressed_fee_units > self.gross_fee_units {
            return Err("private calldata rebate compressed fee exceeds gross fee".to_string());
        }
        if self.rebate_bps > config.max_rebate_bps {
            return Err("private calldata rebate bps exceeds configured cap".to_string());
        }
        if self.rebate_units > config.rebate_budget_units {
            return Err("private calldata rebate exceeds configured budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidDecompressionChallenge {
    pub challenge_id: String,
    pub batch_id: String,
    pub challenger_commitment: String,
    pub challenged_attestation_id: String,
    pub claimed_decompressed_root: String,
    pub counterexample_root: String,
    pub evidence_witness_root: String,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ChallengeStatus,
}

impl InvalidDecompressionChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        challenged_attestation_id: impl Into<String>,
        claimed_decompressed_root: impl Into<String>,
        counterexample_root: impl Into<String>,
        evidence_witness_root: impl Into<String>,
        bond_asset_id: impl Into<String>,
        bond_units: u64,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let batch_id = batch_id.into();
        let challenger_commitment = challenger_commitment.into();
        let challenged_attestation_id = challenged_attestation_id.into();
        let claimed_decompressed_root = claimed_decompressed_root.into();
        let counterexample_root = counterexample_root.into();
        let evidence_witness_root = evidence_witness_root.into();
        let bond_asset_id = bond_asset_id.into();
        let challenge_id = private_contract_calldata_compressor_hash(
            "INVALID-DECOMPRESSION-CHALLENGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&batch_id),
                HashPart::Str(&challenger_commitment),
                HashPart::Str(&challenged_attestation_id),
                HashPart::Str(&counterexample_root),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Self {
            challenge_id,
            batch_id,
            challenger_commitment,
            challenged_attestation_id,
            claimed_decompressed_root,
            counterexample_root,
            evidence_witness_root,
            bond_asset_id,
            bond_units,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(challenge_window_blocks),
            status: ChallengeStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invalid_decompression_challenge",
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "challenger_commitment": self.challenger_commitment,
            "challenged_attestation_id": self.challenged_attestation_id,
            "claimed_decompressed_root": self.claimed_decompressed_root,
            "counterexample_root": self.counterexample_root,
            "evidence_witness_root": self.evidence_witness_root,
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn challenge_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "CHALLENGE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("challenge_id", &self.challenge_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("challenger_commitment", &self.challenger_commitment)?;
        ensure_nonempty("challenged_attestation_id", &self.challenged_attestation_id)?;
        ensure_nonempty("claimed_decompressed_root", &self.claimed_decompressed_root)?;
        ensure_nonempty("counterexample_root", &self.counterexample_root)?;
        ensure_nonempty("evidence_witness_root", &self.evidence_witness_root)?;
        ensure_nonempty("bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("challenge_bond_units", self.bond_units)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("private calldata challenge expiry must be after opening".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReceipt {
    pub rollback_id: String,
    pub batch_id: String,
    pub challenge_id: String,
    pub operator_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub reverted_call_root: String,
    pub rebate_clawback_root: String,
    pub slashing_root: String,
    pub rollback_reason_root: String,
    pub prepared_at_height: u64,
    pub applied_at_height: u64,
    pub status: RollbackStatus,
}

impl RollbackReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        challenge_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        reverted_call_root: impl Into<String>,
        rebate_clawback_root: impl Into<String>,
        slashing_root: impl Into<String>,
        rollback_reason_root: impl Into<String>,
        prepared_at_height: u64,
        applied_at_height: u64,
    ) -> Self {
        let batch_id = batch_id.into();
        let challenge_id = challenge_id.into();
        let operator_commitment = operator_commitment.into();
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let reverted_call_root = reverted_call_root.into();
        let rebate_clawback_root = rebate_clawback_root.into();
        let slashing_root = slashing_root.into();
        let rollback_reason_root = rollback_reason_root.into();
        let rollback_id = private_contract_calldata_compressor_hash(
            "ROLLBACK-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&batch_id),
                HashPart::Str(&challenge_id),
                HashPart::Str(&pre_state_root),
                HashPart::Str(&post_state_root),
                HashPart::Int(applied_at_height as i128),
            ],
        );
        Self {
            rollback_id,
            batch_id,
            challenge_id,
            operator_commitment,
            pre_state_root,
            post_state_root,
            reverted_call_root,
            rebate_clawback_root,
            slashing_root,
            rollback_reason_root,
            prepared_at_height,
            applied_at_height,
            status: RollbackStatus::Prepared,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollback_receipt",
            "rollback_id": self.rollback_id,
            "batch_id": self.batch_id,
            "challenge_id": self.challenge_id,
            "operator_commitment": self.operator_commitment,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "reverted_call_root": self.reverted_call_root,
            "rebate_clawback_root": self.rebate_clawback_root,
            "slashing_root": self.slashing_root,
            "rollback_reason_root": self.rollback_reason_root,
            "prepared_at_height": self.prepared_at_height,
            "applied_at_height": self.applied_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn rollback_root(&self) -> String {
        private_contract_calldata_compressor_hash(
            "ROLLBACK",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCalldataCompressorResult<()> {
        ensure_nonempty("rollback_id", &self.rollback_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("challenge_id", &self.challenge_id)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("pre_state_root", &self.pre_state_root)?;
        ensure_nonempty("post_state_root", &self.post_state_root)?;
        ensure_nonempty("reverted_call_root", &self.reverted_call_root)?;
        ensure_nonempty("rebate_clawback_root", &self.rebate_clawback_root)?;
        ensure_nonempty("slashing_root", &self.slashing_root)?;
        ensure_nonempty("rollback_reason_root", &self.rollback_reason_root)?;
        if self.applied_at_height < self.prepared_at_height {
            return Err("private calldata rollback applied before preparation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCalldataCompressorRoots {
    pub config_root: String,
    pub dictionary_root: String,
    pub abi_lane_root: String,
    pub batch_root: String,
    pub witness_chunk_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub challenge_root: String,
    pub rollback_root: String,
    pub lane_pressure_root: String,
    pub state_root: String,
}

impl PrivateContractCalldataCompressorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "dictionary_root": self.dictionary_root,
            "abi_lane_root": self.abi_lane_root,
            "batch_root": self.batch_root,
            "witness_chunk_root": self.witness_chunk_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "challenge_root": self.challenge_root,
            "rollback_root": self.rollback_root,
            "lane_pressure_root": self.lane_pressure_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCalldataCompressorCounters {
    pub dictionaries: u64,
    pub active_dictionaries: u64,
    pub abi_lanes: u64,
    pub active_abi_lanes: u64,
    pub compressed_batches: u64,
    pub live_batches: u64,
    pub witness_chunks: u64,
    pub pq_attestations: u64,
    pub verified_attestations: u64,
    pub rebates: u64,
    pub payable_rebates: u64,
    pub challenges: u64,
    pub open_challenges: u64,
    pub rollbacks: u64,
    pub total_compressed_bytes: u64,
    pub total_uncompressed_bytes: u64,
    pub total_rebate_units: u64,
    pub total_fee_units: u64,
}

impl PrivateContractCalldataCompressorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "dictionaries": self.dictionaries,
            "active_dictionaries": self.active_dictionaries,
            "abi_lanes": self.abi_lanes,
            "active_abi_lanes": self.active_abi_lanes,
            "compressed_batches": self.compressed_batches,
            "live_batches": self.live_batches,
            "witness_chunks": self.witness_chunks,
            "pq_attestations": self.pq_attestations,
            "verified_attestations": self.verified_attestations,
            "rebates": self.rebates,
            "payable_rebates": self.payable_rebates,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "rollbacks": self.rollbacks,
            "total_compressed_bytes": self.total_compressed_bytes,
            "total_uncompressed_bytes": self.total_uncompressed_bytes,
            "total_rebate_units": self.total_rebate_units,
            "total_fee_units": self.total_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCalldataCompressorState {
    pub config: PrivateContractCalldataCompressorConfig,
    pub height: u64,
    pub dictionaries: BTreeMap<String, EncryptedCalldataDictionary>,
    pub abi_lanes: BTreeMap<String, ContractAbiCompressionLane>,
    pub batches: BTreeMap<String, CompressedCalldataBatch>,
    pub witness_chunks: BTreeMap<String, WitnessChunkCommitment>,
    pub attestations: BTreeMap<String, PqDecompressorAttestation>,
    pub rebates: BTreeMap<String, LowFeeCompressionRebate>,
    pub challenges: BTreeMap<String, InvalidDecompressionChallenge>,
    pub rollbacks: BTreeMap<String, RollbackReceipt>,
    pub lane_batches: BTreeMap<String, BTreeSet<String>>,
    pub dictionary_batches: BTreeMap<String, BTreeSet<String>>,
}

impl PrivateContractCalldataCompressorState {
    pub fn devnet() -> Self {
        Self {
            config: PrivateContractCalldataCompressorConfig::devnet(),
            height: PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_DEVNET_HEIGHT,
            dictionaries: BTreeMap::new(),
            abi_lanes: BTreeMap::new(),
            batches: BTreeMap::new(),
            witness_chunks: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            challenges: BTreeMap::new(),
            rollbacks: BTreeMap::new(),
            lane_batches: BTreeMap::new(),
            dictionary_batches: BTreeMap::new(),
        }
    }

    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> PrivateContractCalldataCompressorResult<()> {
        if next_height < self.height {
            return Err("private calldata compressor height cannot move backwards".to_string());
        }
        self.height = next_height;
        Ok(())
    }

    pub fn insert_dictionary(
        &mut self,
        dictionary: EncryptedCalldataDictionary,
    ) -> PrivateContractCalldataCompressorResult<String> {
        dictionary.validate(&self.config)?;
        let dictionary_id = dictionary.dictionary_id.clone();
        self.dictionaries.insert(dictionary_id.clone(), dictionary);
        Ok(dictionary_id)
    }

    pub fn insert_abi_lane(
        &mut self,
        lane: ContractAbiCompressionLane,
    ) -> PrivateContractCalldataCompressorResult<String> {
        lane.validate(&self.config)?;
        if !self.dictionaries.contains_key(&lane.dictionary_id) {
            return Err("private calldata abi lane references missing dictionary".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.abi_lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn insert_batch(
        &mut self,
        batch: CompressedCalldataBatch,
    ) -> PrivateContractCalldataCompressorResult<String> {
        batch.validate(&self.config)?;
        if !self.abi_lanes.contains_key(&batch.lane_id) {
            return Err("private calldata batch references missing abi lane".to_string());
        }
        if !self.dictionaries.contains_key(&batch.dictionary_id) {
            return Err("private calldata batch references missing dictionary".to_string());
        }
        let batch_id = batch.batch_id.clone();
        self.lane_batches
            .entry(batch.lane_id.clone())
            .or_default()
            .insert(batch_id.clone());
        self.dictionary_batches
            .entry(batch.dictionary_id.clone())
            .or_default()
            .insert(batch_id.clone());
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn insert_witness_chunk(
        &mut self,
        chunk: WitnessChunkCommitment,
    ) -> PrivateContractCalldataCompressorResult<String> {
        chunk.validate(&self.config)?;
        if !self.batches.contains_key(&chunk.batch_id) {
            return Err("private calldata witness chunk references missing batch".to_string());
        }
        let chunk_id = chunk.chunk_id.clone();
        self.witness_chunks.insert(chunk_id.clone(), chunk);
        Ok(chunk_id)
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqDecompressorAttestation,
    ) -> PrivateContractCalldataCompressorResult<String> {
        attestation.validate(&self.config)?;
        if !self.batches.contains_key(&attestation.batch_id) {
            return Err("private calldata attestation references missing batch".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_rebate(
        &mut self,
        rebate: LowFeeCompressionRebate,
    ) -> PrivateContractCalldataCompressorResult<String> {
        rebate.validate(&self.config)?;
        if !self.batches.contains_key(&rebate.batch_id) {
            return Err("private calldata rebate references missing batch".to_string());
        }
        let rebate_id = rebate.rebate_id.clone();
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: InvalidDecompressionChallenge,
    ) -> PrivateContractCalldataCompressorResult<String> {
        challenge.validate()?;
        if !self.batches.contains_key(&challenge.batch_id) {
            return Err("private calldata challenge references missing batch".to_string());
        }
        if !self
            .attestations
            .contains_key(&challenge.challenged_attestation_id)
        {
            return Err("private calldata challenge references missing attestation".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn insert_rollback(
        &mut self,
        rollback: RollbackReceipt,
    ) -> PrivateContractCalldataCompressorResult<String> {
        rollback.validate()?;
        if !self.batches.contains_key(&rollback.batch_id) {
            return Err("private calldata rollback references missing batch".to_string());
        }
        if !self.challenges.contains_key(&rollback.challenge_id) {
            return Err("private calldata rollback references missing challenge".to_string());
        }
        let rollback_id = rollback.rollback_id.clone();
        self.rollbacks.insert(rollback_id.clone(), rollback);
        Ok(rollback_id)
    }

    pub fn roots(&self) -> PrivateContractCalldataCompressorRoots {
        let config_root = self.config.config_root();
        let dictionary_root = private_contract_calldata_compressor_merkle(
            "DICTIONARIES",
            self.dictionaries
                .values()
                .map(EncryptedCalldataDictionary::public_record)
                .collect(),
        );
        let abi_lane_root = private_contract_calldata_compressor_merkle(
            "ABI-LANES",
            self.abi_lanes
                .values()
                .map(ContractAbiCompressionLane::public_record)
                .collect(),
        );
        let batch_root = private_contract_calldata_compressor_merkle(
            "BATCHES",
            self.batches
                .values()
                .map(CompressedCalldataBatch::public_record)
                .collect(),
        );
        let witness_chunk_root = private_contract_calldata_compressor_merkle(
            "WITNESS-CHUNKS",
            self.witness_chunks
                .values()
                .map(WitnessChunkCommitment::public_record)
                .collect(),
        );
        let attestation_root = private_contract_calldata_compressor_merkle(
            "ATTESTATIONS",
            self.attestations
                .values()
                .map(PqDecompressorAttestation::public_record)
                .collect(),
        );
        let rebate_root = private_contract_calldata_compressor_merkle(
            "REBATES",
            self.rebates
                .values()
                .map(LowFeeCompressionRebate::public_record)
                .collect(),
        );
        let challenge_root = private_contract_calldata_compressor_merkle(
            "CHALLENGES",
            self.challenges
                .values()
                .map(InvalidDecompressionChallenge::public_record)
                .collect(),
        );
        let rollback_root = private_contract_calldata_compressor_merkle(
            "ROLLBACKS",
            self.rollbacks
                .values()
                .map(RollbackReceipt::public_record)
                .collect(),
        );
        let lane_pressure_root = private_contract_calldata_compressor_hash(
            "LANE-PRESSURE",
            &[HashPart::Json(&json!(self.lane_pressure_map()))],
        );
        let state_root = private_contract_calldata_compressor_hash(
            "STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&dictionary_root),
                HashPart::Str(&abi_lane_root),
                HashPart::Str(&batch_root),
                HashPart::Str(&witness_chunk_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&rebate_root),
                HashPart::Str(&challenge_root),
                HashPart::Str(&rollback_root),
                HashPart::Str(&lane_pressure_root),
            ],
        );
        PrivateContractCalldataCompressorRoots {
            config_root,
            dictionary_root,
            abi_lane_root,
            batch_root,
            witness_chunk_root,
            attestation_root,
            rebate_root,
            challenge_root,
            rollback_root,
            lane_pressure_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateContractCalldataCompressorCounters {
        let mut counters = PrivateContractCalldataCompressorCounters::default();
        counters.dictionaries = self.dictionaries.len() as u64;
        counters.active_dictionaries = self
            .dictionaries
            .values()
            .filter(|dictionary| dictionary.status.usable())
            .count() as u64;
        counters.abi_lanes = self.abi_lanes.len() as u64;
        counters.active_abi_lanes = self
            .abi_lanes
            .values()
            .filter(|lane| lane.status.accepts_batches())
            .count() as u64;
        counters.compressed_batches = self.batches.len() as u64;
        counters.live_batches = self
            .batches
            .values()
            .filter(|batch| batch.status.live())
            .count() as u64;
        counters.witness_chunks = self.witness_chunks.len() as u64;
        counters.pq_attestations = self.attestations.len() as u64;
        counters.verified_attestations = self
            .attestations
            .values()
            .filter(|attestation| attestation.status.usable())
            .count() as u64;
        counters.rebates = self.rebates.len() as u64;
        counters.payable_rebates = self
            .rebates
            .values()
            .filter(|rebate| rebate.status.payable())
            .count() as u64;
        counters.challenges = self.challenges.len() as u64;
        counters.open_challenges = self
            .challenges
            .values()
            .filter(|challenge| challenge.status.open())
            .count() as u64;
        counters.rollbacks = self.rollbacks.len() as u64;
        counters.total_compressed_bytes = self
            .batches
            .values()
            .map(|batch| batch.compressed_bytes)
            .fold(0_u64, u64::saturating_add);
        counters.total_uncompressed_bytes = self
            .batches
            .values()
            .map(|batch| batch.uncompressed_bytes)
            .fold(0_u64, u64::saturating_add);
        counters.total_rebate_units = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_units)
            .fold(0_u64, u64::saturating_add);
        counters.total_fee_units = self
            .batches
            .values()
            .map(|batch| batch.fee_units)
            .fold(0_u64, u64::saturating_add);
        counters
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_contract_calldata_compressor_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "lane_pressure": self.lane_pressure_map(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateContractCalldataCompressorResult<()> {
        self.config.validate()?;
        if self.dictionaries.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_DICTIONARIES {
            return Err("private calldata compressor dictionary set exceeds cap".to_string());
        }
        if self.abi_lanes.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_ABI_LANES {
            return Err("private calldata compressor abi lane set exceeds cap".to_string());
        }
        if self.batches.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_BATCHES {
            return Err("private calldata compressor batch set exceeds cap".to_string());
        }
        if self.witness_chunks.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_WITNESSES {
            return Err("private calldata compressor witness set exceeds cap".to_string());
        }
        if self.attestations.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_ATTESTATIONS {
            return Err("private calldata compressor attestation set exceeds cap".to_string());
        }
        if self.rebates.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_REBATES {
            return Err("private calldata compressor rebate set exceeds cap".to_string());
        }
        if self.challenges.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_CHALLENGES {
            return Err("private calldata compressor challenge set exceeds cap".to_string());
        }
        if self.rollbacks.len() > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_ROLLBACKS {
            return Err("private calldata compressor rollback set exceeds cap".to_string());
        }
        let record_count = self.dictionaries.len()
            + self.abi_lanes.len()
            + self.batches.len()
            + self.witness_chunks.len()
            + self.attestations.len()
            + self.rebates.len()
            + self.challenges.len()
            + self.rollbacks.len();
        if record_count > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_PUBLIC_RECORDS {
            return Err("private calldata compressor public record set exceeds cap".to_string());
        }
        for dictionary in self.dictionaries.values() {
            dictionary.validate(&self.config)?;
        }
        for lane in self.abi_lanes.values() {
            lane.validate(&self.config)?;
            if !self.dictionaries.contains_key(&lane.dictionary_id) {
                return Err("private calldata compressor lane missing dictionary".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate(&self.config)?;
            if !self.abi_lanes.contains_key(&batch.lane_id) {
                return Err("private calldata compressor batch missing lane".to_string());
            }
            if !self.dictionaries.contains_key(&batch.dictionary_id) {
                return Err("private calldata compressor batch missing dictionary".to_string());
            }
        }
        for chunk in self.witness_chunks.values() {
            chunk.validate(&self.config)?;
            if !self.batches.contains_key(&chunk.batch_id) {
                return Err("private calldata compressor witness missing batch".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.config)?;
            if !self.batches.contains_key(&attestation.batch_id) {
                return Err("private calldata compressor attestation missing batch".to_string());
            }
        }
        for rebate in self.rebates.values() {
            rebate.validate(&self.config)?;
            if !self.batches.contains_key(&rebate.batch_id) {
                return Err("private calldata compressor rebate missing batch".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.batches.contains_key(&challenge.batch_id) {
                return Err("private calldata compressor challenge missing batch".to_string());
            }
            if !self
                .attestations
                .contains_key(&challenge.challenged_attestation_id)
            {
                return Err("private calldata compressor challenge missing attestation".to_string());
            }
        }
        for rollback in self.rollbacks.values() {
            rollback.validate()?;
            if !self.batches.contains_key(&rollback.batch_id) {
                return Err("private calldata compressor rollback missing batch".to_string());
            }
            if !self.challenges.contains_key(&rollback.challenge_id) {
                return Err("private calldata compressor rollback missing challenge".to_string());
            }
        }
        self.validate_batch_indexes()?;
        Ok(())
    }

    pub fn lane_pressure_map(&self) -> BTreeMap<String, Value> {
        let mut pressure = BTreeMap::new();
        for (lane_id, lane) in &self.abi_lanes {
            let batch_ids = match self.lane_batches.get(lane_id) {
                Some(batch_ids) => batch_ids.clone(),
                None => BTreeSet::new(),
            };
            let mut live_batches = 0_u64;
            let mut compressed_bytes = 0_u64;
            let mut uncompressed_bytes = 0_u64;
            let mut fee_units = 0_u64;
            for batch_id in &batch_ids {
                if let Some(batch) = self.batches.get(batch_id) {
                    if batch.status.live() {
                        live_batches = live_batches.saturating_add(1);
                    }
                    compressed_bytes = compressed_bytes.saturating_add(batch.compressed_bytes);
                    uncompressed_bytes =
                        uncompressed_bytes.saturating_add(batch.uncompressed_bytes);
                    fee_units = fee_units.saturating_add(batch.fee_units);
                }
            }
            pressure.insert(
                lane_id.clone(),
                json!({
                    "lane_kind": lane.lane_kind.as_str(),
                    "status": lane.status.as_str(),
                    "priority": lane.priority,
                    "batch_count": batch_ids.len() as u64,
                    "live_batches": live_batches,
                    "compressed_bytes": compressed_bytes,
                    "uncompressed_bytes": uncompressed_bytes,
                    "fee_units": fee_units,
                    "expected_savings_bps": lane.expected_savings_bps,
                }),
            );
        }
        pressure
    }

    fn validate_batch_indexes(&self) -> PrivateContractCalldataCompressorResult<()> {
        for (lane_id, batch_ids) in &self.lane_batches {
            if !self.abi_lanes.contains_key(lane_id) {
                return Err(
                    "private calldata compressor lane index references missing lane".to_string(),
                );
            }
            for batch_id in batch_ids {
                let Some(batch) = self.batches.get(batch_id) else {
                    return Err(
                        "private calldata compressor lane index references missing batch"
                            .to_string(),
                    );
                };
                if &batch.lane_id != lane_id {
                    return Err(
                        "private calldata compressor lane index contains wrong batch".to_string(),
                    );
                }
            }
        }
        for (dictionary_id, batch_ids) in &self.dictionary_batches {
            if !self.dictionaries.contains_key(dictionary_id) {
                return Err(
                    "private calldata compressor dictionary index references missing dictionary"
                        .to_string(),
                );
            }
            for batch_id in batch_ids {
                let Some(batch) = self.batches.get(batch_id) else {
                    return Err(
                        "private calldata compressor dictionary index references missing batch"
                            .to_string(),
                    );
                };
                if &batch.dictionary_id != dictionary_id {
                    return Err(
                        "private calldata compressor dictionary index contains wrong batch"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub fn private_contract_calldata_compressor_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let scoped_domain = format!(
        "PRIVATE-CONTRACT-CALLDATA-COMPRESSOR:{}:{}",
        PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PROTOCOL_VERSION, domain
    );
    domain_hash(&scoped_domain, parts, 32)
}

pub fn private_contract_calldata_compressor_payload_root(label: &str, payload: &Value) -> String {
    private_contract_calldata_compressor_hash(
        "PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(payload),
        ],
    )
}

pub fn private_contract_calldata_compressor_id(label: &str, value: &str) -> String {
    private_contract_calldata_compressor_hash(
        "ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
    )
}

pub fn private_contract_calldata_compressor_merkle(domain: &str, leaves: Vec<Value>) -> String {
    let scoped_domain = format!(
        "PRIVATE-CONTRACT-CALLDATA-COMPRESSOR:{}:{}",
        PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_PROTOCOL_VERSION, domain
    );
    merkle_root(&scoped_domain, &leaves)
}

fn ensure_nonempty(label: &str, value: &str) -> PrivateContractCalldataCompressorResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "private calldata compressor {label} must be populated"
        ));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivateContractCalldataCompressorResult<()> {
    if value == 0 {
        return Err(format!(
            "private calldata compressor {label} must be positive"
        ));
    }
    Ok(())
}

fn validate_bps(label: &str, value: u64) -> PrivateContractCalldataCompressorResult<()> {
    if value > PRIVATE_CONTRACT_CALLDATA_COMPRESSOR_MAX_BPS {
        return Err(format!(
            "private calldata compressor {label} exceeds max bps"
        ));
    }
    Ok(())
}
