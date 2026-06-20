use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PqBlobProofMarketResult<T> = Result<T, String>;

pub const PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION: u32 = 1;
pub const PQ_BLOB_PROOF_MARKET_PROTOCOL_ID: &str = "nebula-l2-pq-blob-proof-market-v1";
pub const PQ_BLOB_PROOF_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PQ_BLOB_PROOF_MARKET_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_BLOB_PROOF_MARKET_KEM_SUITE: &str = "ML-KEM-1024";
pub const PQ_BLOB_PROOF_MARKET_ENCRYPTION_SUITE: &str =
    "ml-kem-1024+shake256-stream-sealed-proof-blob-v1";
pub const PQ_BLOB_PROOF_MARKET_ML_DSA_SUITE: &str = "ML-DSA-87";
pub const PQ_BLOB_PROOF_MARKET_SLH_DSA_SUITE: &str = "SLH-DSA-SHAKE-192f";
pub const PQ_BLOB_PROOF_MARKET_RECURSION_SCHEME: &str =
    "nebula-devnet-recursive-proof-bid-market-v1";
pub const PQ_BLOB_PROOF_MARKET_DA_SCHEME: &str = "private-da-availability-proof-bundle-v1";
pub const PQ_BLOB_PROOF_MARKET_PRIVATE_LANE_SCHEME: &str = "sealed-private-contract-proof-lane-v1";
pub const PQ_BLOB_PROOF_MARKET_DEVNET_HEIGHT: u64 = 1_536;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_BID_WINDOW_BLOCKS: u64 = 6;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_PROOF_TTL_BLOCKS: u64 = 48;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_DA_WINDOW_BLOCKS: u64 = 32;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_FRAUD_WINDOW_BLOCKS: u64 = 144;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_PRIVATE_LANE_TTL_BLOCKS: u64 = 720;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_LOW_FEE_CAP_UNITS: u64 = 4;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 150_000;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_CHALLENGER_BOND_UNITS: u64 = 50_000;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_PROVER_BOND_UNITS: u64 = 75_000;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_SLASH_BPS: u64 = 3_000;
pub const PQ_BLOB_PROOF_MARKET_DEFAULT_PROTOCOL_FEE_BPS: u64 = 200;
pub const PQ_BLOB_PROOF_MARKET_MAX_BPS: u64 = 10_000;
pub const PQ_BLOB_PROOF_MARKET_MAX_BLOBS: usize = 131_072;
pub const PQ_BLOB_PROOF_MARKET_MAX_ATTESTATIONS: usize = 262_144;
pub const PQ_BLOB_PROOF_MARKET_MAX_RECURSIVE_BIDS: usize = 131_072;
pub const PQ_BLOB_PROOF_MARKET_MAX_DA_PROOFS: usize = 262_144;
pub const PQ_BLOB_PROOF_MARKET_MAX_SPONSORSHIPS: usize = 131_072;
pub const PQ_BLOB_PROOF_MARKET_MAX_CHALLENGER_BONDS: usize = 131_072;
pub const PQ_BLOB_PROOF_MARKET_MAX_FRAUD_EVIDENCE: usize = 262_144;
pub const PQ_BLOB_PROOF_MARKET_MAX_PRIVATE_LANES: usize = 16_384;
pub const PQ_BLOB_PROOF_MARKET_MAX_LATENCY_OBSERVATIONS: usize = 262_144;
pub const PQ_BLOB_PROOF_MARKET_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBlobKind {
    RollupValidity,
    MoneroBridge,
    PrivateContractCall,
    PrivateDefiBatch,
    RecursiveAggregation,
    DaSampling,
    FraudResponse,
    LowFeePublicGood,
}

impl ProofBlobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupValidity => "rollup_validity",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateDefiBatch => "private_defi_batch",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::DaSampling => "da_sampling",
            Self::FraudResponse => "fraud_response",
            Self::LowFeePublicGood => "low_fee_public_good",
        }
    }

    pub fn private(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge | Self::PrivateContractCall | Self::PrivateDefiBatch
        )
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::FraudResponse => 10_000,
            Self::MoneroBridge => 9_200,
            Self::PrivateDefiBatch => 8_800,
            Self::PrivateContractCall => 8_400,
            Self::RollupValidity => 7_500,
            Self::DaSampling => 7_200,
            Self::RecursiveAggregation => 6_600,
            Self::LowFeePublicGood => 5_800,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobProofStatus {
    Posted,
    Bidding,
    Assigned,
    Proving,
    Attested,
    Available,
    Sponsored,
    Challenged,
    Settled,
    Slashed,
    Expired,
}

impl BlobProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Bidding => "bidding",
            Self::Assigned => "assigned",
            Self::Proving => "proving",
            Self::Attested => "attested",
            Self::Available => "available",
            Self::Sponsored => "sponsored",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Posted
                | Self::Bidding
                | Self::Assigned
                | Self::Proving
                | Self::Attested
                | Self::Available
                | Self::Sponsored
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverAttestationScheme {
    MlDsa87,
    SlhDsaShake192f,
    HybridMlDsaSlhDsa,
}

impl ProverAttestationScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake192f => "slh_dsa_shake_192f",
            Self::HybridMlDsaSlhDsa => "hybrid_ml_dsa_slh_dsa",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveBidTier {
    PublicGood,
    Standard,
    Fast,
    BridgeExit,
    PrivateContract,
    Emergency,
}

impl RecursiveBidTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicGood => "public_good",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::BridgeExit => "bridge_exit",
            Self::PrivateContract => "private_contract",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::BridgeExit => 9_000,
            Self::PrivateContract => 8_500,
            Self::Fast => 7_500,
            Self::Standard => 5_000,
            Self::PublicGood => 3_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    Immediate,
    Fast,
    Standard,
    Deferred,
    Expired,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Deferred => "deferred",
            Self::Expired => "expired",
        }
    }

    pub fn target_blocks(self) -> u64 {
        match self {
            Self::Immediate => 1,
            Self::Fast => 3,
            Self::Standard => 8,
            Self::Deferred => 24,
            Self::Expired => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaProofKind {
    KzgOpening,
    ErasureShardCustody,
    SamplingTranscript,
    PrivateDaEscrow,
    BridgeAvailability,
}

impl DaProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KzgOpening => "kzg_opening",
            Self::ErasureShardCustody => "erasure_shard_custody",
            Self::SamplingTranscript => "sampling_transcript",
            Self::PrivateDaEscrow => "private_da_escrow",
            Self::BridgeAvailability => "bridge_availability",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudEvidenceKind {
    InvalidProof,
    MissingDa,
    LateProof,
    BadPqSignature,
    RecursiveMismatch,
    PrivateLaneDisclosure,
    SponsorOverspend,
}

impl FraudEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::MissingDa => "missing_da",
            Self::LateProof => "late_proof",
            Self::BadPqSignature => "bad_pq_signature",
            Self::RecursiveMismatch => "recursive_mismatch",
            Self::PrivateLaneDisclosure => "private_lane_disclosure",
            Self::SponsorOverspend => "sponsor_overspend",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBlobProofMarketConfig {
    pub protocol_version: u32,
    pub protocol_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub kem_suite: String,
    pub encryption_suite: String,
    pub ml_dsa_suite: String,
    pub slh_dsa_suite: String,
    pub recursion_scheme: String,
    pub da_scheme: String,
    pub private_lane_scheme: String,
    pub bid_window_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub da_window_blocks: u64,
    pub fraud_window_blocks: u64,
    pub private_lane_ttl_blocks: u64,
    pub min_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub low_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub challenger_bond_units: u64,
    pub prover_bond_units: u64,
    pub slash_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_blobs: usize,
    pub max_attestations: usize,
    pub max_recursive_bids: usize,
    pub max_da_proofs: usize,
    pub max_sponsorships: usize,
    pub max_challenger_bonds: usize,
    pub max_fraud_evidence: usize,
    pub max_private_lanes: usize,
    pub max_latency_observations: usize,
    pub max_public_records: usize,
}

impl Default for PqBlobProofMarketConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PqBlobProofMarketConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION,
            protocol_id: PQ_BLOB_PROOF_MARKET_PROTOCOL_ID.to_string(),
            schema_version: PQ_BLOB_PROOF_MARKET_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PQ_BLOB_PROOF_MARKET_HASH_SUITE.to_string(),
            kem_suite: PQ_BLOB_PROOF_MARKET_KEM_SUITE.to_string(),
            encryption_suite: PQ_BLOB_PROOF_MARKET_ENCRYPTION_SUITE.to_string(),
            ml_dsa_suite: PQ_BLOB_PROOF_MARKET_ML_DSA_SUITE.to_string(),
            slh_dsa_suite: PQ_BLOB_PROOF_MARKET_SLH_DSA_SUITE.to_string(),
            recursion_scheme: PQ_BLOB_PROOF_MARKET_RECURSION_SCHEME.to_string(),
            da_scheme: PQ_BLOB_PROOF_MARKET_DA_SCHEME.to_string(),
            private_lane_scheme: PQ_BLOB_PROOF_MARKET_PRIVATE_LANE_SCHEME.to_string(),
            bid_window_blocks: PQ_BLOB_PROOF_MARKET_DEFAULT_BID_WINDOW_BLOCKS,
            proof_ttl_blocks: PQ_BLOB_PROOF_MARKET_DEFAULT_PROOF_TTL_BLOCKS,
            da_window_blocks: PQ_BLOB_PROOF_MARKET_DEFAULT_DA_WINDOW_BLOCKS,
            fraud_window_blocks: PQ_BLOB_PROOF_MARKET_DEFAULT_FRAUD_WINDOW_BLOCKS,
            private_lane_ttl_blocks: PQ_BLOB_PROOF_MARKET_DEFAULT_PRIVATE_LANE_TTL_BLOCKS,
            min_security_bits: PQ_BLOB_PROOF_MARKET_DEFAULT_MIN_SECURITY_BITS,
            min_privacy_set_size: PQ_BLOB_PROOF_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE,
            low_fee_cap_units: PQ_BLOB_PROOF_MARKET_DEFAULT_LOW_FEE_CAP_UNITS,
            sponsor_budget_units: PQ_BLOB_PROOF_MARKET_DEFAULT_SPONSOR_BUDGET_UNITS,
            challenger_bond_units: PQ_BLOB_PROOF_MARKET_DEFAULT_CHALLENGER_BOND_UNITS,
            prover_bond_units: PQ_BLOB_PROOF_MARKET_DEFAULT_PROVER_BOND_UNITS,
            slash_bps: PQ_BLOB_PROOF_MARKET_DEFAULT_SLASH_BPS,
            protocol_fee_bps: PQ_BLOB_PROOF_MARKET_DEFAULT_PROTOCOL_FEE_BPS,
            max_blobs: PQ_BLOB_PROOF_MARKET_MAX_BLOBS,
            max_attestations: PQ_BLOB_PROOF_MARKET_MAX_ATTESTATIONS,
            max_recursive_bids: PQ_BLOB_PROOF_MARKET_MAX_RECURSIVE_BIDS,
            max_da_proofs: PQ_BLOB_PROOF_MARKET_MAX_DA_PROOFS,
            max_sponsorships: PQ_BLOB_PROOF_MARKET_MAX_SPONSORSHIPS,
            max_challenger_bonds: PQ_BLOB_PROOF_MARKET_MAX_CHALLENGER_BONDS,
            max_fraud_evidence: PQ_BLOB_PROOF_MARKET_MAX_FRAUD_EVIDENCE,
            max_private_lanes: PQ_BLOB_PROOF_MARKET_MAX_PRIVATE_LANES,
            max_latency_observations: PQ_BLOB_PROOF_MARKET_MAX_LATENCY_OBSERVATIONS,
            max_public_records: PQ_BLOB_PROOF_MARKET_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqBlobProofMarketResult<String> {
        if self.protocol_version != PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION {
            return Err("config protocol version mismatch".to_string());
        }
        if self.chain_id.as_str() != CHAIN_ID {
            return Err("config chain id mismatch".to_string());
        }
        ensure_non_empty(&self.protocol_id, "config protocol id")?;
        ensure_non_empty(&self.hash_suite, "config hash suite")?;
        ensure_non_empty(&self.kem_suite, "config kem suite")?;
        ensure_non_empty(&self.encryption_suite, "config encryption suite")?;
        ensure_non_empty(&self.ml_dsa_suite, "config ml dsa suite")?;
        ensure_non_empty(&self.slh_dsa_suite, "config slh dsa suite")?;
        ensure_non_empty(&self.recursion_scheme, "config recursion scheme")?;
        ensure_non_empty(&self.da_scheme, "config da scheme")?;
        ensure_non_empty(&self.private_lane_scheme, "config private lane scheme")?;
        ensure_positive(self.bid_window_blocks, "config bid window")?;
        ensure_positive(self.proof_ttl_blocks, "config proof ttl")?;
        ensure_positive(self.da_window_blocks, "config da window")?;
        ensure_positive(self.fraud_window_blocks, "config fraud window")?;
        ensure_positive(self.private_lane_ttl_blocks, "config private lane ttl")?;
        if self.min_security_bits < 128 {
            return Err("config security bits below floor".to_string());
        }
        ensure_positive(self.min_privacy_set_size, "config privacy set")?;
        ensure_positive(self.sponsor_budget_units, "config sponsor budget")?;
        ensure_positive(self.challenger_bond_units, "config challenger bond")?;
        ensure_positive(self.prover_bond_units, "config prover bond")?;
        ensure_bps(self.slash_bps, "config slash bps")?;
        ensure_bps(self.protocol_fee_bps, "config protocol fee bps")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBlobProofMarketRoots {
    pub config_root: String,
    pub encrypted_blob_root: String,
    pub prover_attestation_root: String,
    pub recursive_bid_root: String,
    pub da_availability_root: String,
    pub sponsorship_credit_root: String,
    pub challenger_bond_root: String,
    pub fraud_evidence_root: String,
    pub private_lane_root: String,
    pub latency_observation_root: String,
    pub public_record_root: String,
}

impl PqBlobProofMarketRoots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBlobProofMarketCounters {
    pub encrypted_blobs: u64,
    pub live_blobs: u64,
    pub private_blobs: u64,
    pub prover_attestations: u64,
    pub recursive_bids: u64,
    pub accepted_recursive_bids: u64,
    pub da_availability_proofs: u64,
    pub active_sponsorship_credits: u64,
    pub challenger_bonds: u64,
    pub open_challenger_bonds: u64,
    pub fraud_evidence_items: u64,
    pub unresolved_fraud_evidence_items: u64,
    pub private_contract_lanes: u64,
    pub active_private_contract_lanes: u64,
    pub latency_observations: u64,
    pub public_records: u64,
}

impl PqBlobProofMarketCounters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemEncryptedProofBlob {
    pub blob_id: String,
    pub request_id: String,
    pub blob_kind: ProofBlobKind,
    pub status: BlobProofStatus,
    pub encrypted_proof_root: String,
    pub kem_ciphertext_root: String,
    pub ciphertext_commitment_root: String,
    pub public_input_root: String,
    pub private_witness_commitment: String,
    pub recursive_accumulator_root: String,
    pub da_commitment_root: String,
    pub private_lane_id: String,
    pub sponsor_credit_id: String,
    pub assigned_bid_id: String,
    pub payload_bytes: u64,
    pub encrypted_bytes: u64,
    pub max_fee_units: u64,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub posted_height: u64,
    pub bid_deadline_height: u64,
    pub proof_deadline_height: u64,
}

impl MlKemEncryptedProofBlob {
    #[allow(clippy::too_many_arguments)]
    pub fn devnet(
        label: &str,
        blob_kind: ProofBlobKind,
        height: u64,
        config: &PqBlobProofMarketConfig,
        nonce: u64,
    ) -> Self {
        let encrypted_proof_root = demo_root("encrypted-proof", label);
        let kem_ciphertext_root = demo_root("kem-ciphertext", label);
        let public_input_root = demo_root("public-input", label);
        let request_id = deterministic_id(
            "REQUEST-ID",
            &json!({
                "label": label,
                "kind": blob_kind.as_str(),
                "height": height,
                "nonce": nonce,
            }),
        );
        let blob_id = deterministic_id(
            "BLOB-ID",
            &json!({
                "request_id": request_id,
                "encrypted_proof_root": encrypted_proof_root,
                "kem_ciphertext_root": kem_ciphertext_root,
                "height": height,
            }),
        );
        Self {
            blob_id,
            request_id,
            blob_kind,
            status: if blob_kind == ProofBlobKind::LowFeePublicGood {
                BlobProofStatus::Sponsored
            } else {
                BlobProofStatus::Bidding
            },
            encrypted_proof_root,
            kem_ciphertext_root,
            ciphertext_commitment_root: demo_root("ciphertext-commitment", label),
            public_input_root,
            private_witness_commitment: demo_root("private-witness", label),
            recursive_accumulator_root: demo_root("recursive-accumulator", label),
            da_commitment_root: demo_root("da-commitment", label),
            private_lane_id: String::new(),
            sponsor_credit_id: String::new(),
            assigned_bid_id: String::new(),
            payload_bytes: 192 * 1024,
            encrypted_bytes: 208 * 1024,
            max_fee_units: if blob_kind == ProofBlobKind::LowFeePublicGood {
                config.low_fee_cap_units
            } else {
                48
            },
            security_bits: config.min_security_bits,
            privacy_set_size: if blob_kind.private() {
                config.min_privacy_set_size * 4
            } else {
                config.min_privacy_set_size
            },
            posted_height: height,
            bid_deadline_height: height.saturating_add(config.bid_window_blocks),
            proof_deadline_height: height.saturating_add(config.proof_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("ENCRYPTED-PROOF-BLOB", &self.public_record())
    }

    pub fn validate(&self, config: &PqBlobProofMarketConfig) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.blob_id, "blob id")?;
        ensure_non_empty(&self.request_id, "blob request id")?;
        ensure_hash_like(&self.encrypted_proof_root, "blob encrypted proof root")?;
        ensure_hash_like(&self.kem_ciphertext_root, "blob kem ciphertext root")?;
        ensure_hash_like(
            &self.ciphertext_commitment_root,
            "blob ciphertext commitment root",
        )?;
        ensure_hash_like(&self.public_input_root, "blob public input root")?;
        ensure_hash_like(
            &self.private_witness_commitment,
            "blob private witness commitment",
        )?;
        ensure_hash_like(
            &self.recursive_accumulator_root,
            "blob recursive accumulator root",
        )?;
        ensure_hash_like(&self.da_commitment_root, "blob da commitment root")?;
        ensure_positive(self.payload_bytes, "blob payload bytes")?;
        ensure_positive(self.encrypted_bytes, "blob encrypted bytes")?;
        ensure_positive(self.max_fee_units, "blob max fee units")?;
        if self.security_bits < config.min_security_bits {
            return Err("blob security bits below config".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("blob privacy set below config".to_string());
        }
        ensure_height_window(self.posted_height, self.bid_deadline_height, "blob bid")?;
        ensure_height_window(
            self.bid_deadline_height,
            self.proof_deadline_height,
            "blob proof",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqProverAttestation {
    pub attestation_id: String,
    pub blob_id: String,
    pub prover_id: String,
    pub scheme: ProverAttestationScheme,
    pub statement_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub public_key_root: String,
    pub proof_output_root: String,
    pub bonded_units: u64,
    pub weight_bps: u64,
    pub attested_height: u64,
    pub expires_height: u64,
    pub accepted: bool,
}

impl PqProverAttestation {
    pub fn devnet(blob_id: &str, prover_label: &str, height: u64, ttl: u64) -> Self {
        let statement_root = demo_root("attestation-statement", prover_label);
        let attestation_id = deterministic_id(
            "PROVER-ATTESTATION-ID",
            &json!({
                "blob_id": blob_id,
                "prover": prover_label,
                "statement_root": statement_root,
                "height": height,
            }),
        );
        Self {
            attestation_id,
            blob_id: blob_id.to_string(),
            prover_id: deterministic_id("PROVER-ID", &json!({ "label": prover_label })),
            scheme: ProverAttestationScheme::HybridMlDsaSlhDsa,
            statement_root,
            ml_dsa_signature_root: demo_root("ml-dsa-signature", prover_label),
            slh_dsa_signature_root: demo_root("slh-dsa-signature", prover_label),
            public_key_root: demo_root("prover-public-key", prover_label),
            proof_output_root: demo_root("proof-output", prover_label),
            bonded_units: PQ_BLOB_PROOF_MARKET_DEFAULT_PROVER_BOND_UNITS,
            weight_bps: 7_500,
            attested_height: height.saturating_add(4),
            expires_height: height.saturating_add(ttl),
            accepted: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("PROVER-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self, config: &PqBlobProofMarketConfig) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.blob_id, "attestation blob id")?;
        ensure_non_empty(&self.prover_id, "attestation prover id")?;
        ensure_hash_like(&self.statement_root, "attestation statement root")?;
        ensure_hash_like(&self.ml_dsa_signature_root, "attestation ml dsa signature")?;
        ensure_hash_like(
            &self.slh_dsa_signature_root,
            "attestation slh dsa signature",
        )?;
        ensure_hash_like(&self.public_key_root, "attestation public key")?;
        ensure_hash_like(&self.proof_output_root, "attestation proof output")?;
        if self.bonded_units < config.prover_bond_units {
            return Err("attestation prover bond below config".to_string());
        }
        ensure_bps(self.weight_bps, "attestation weight")?;
        ensure_height_window(
            self.attested_height,
            self.expires_height,
            "attestation expiry",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofBid {
    pub bid_id: String,
    pub blob_id: String,
    pub prover_id: String,
    pub tier: RecursiveBidTier,
    pub latency_class: LatencyClass,
    pub child_proof_root: String,
    pub recursive_plan_root: String,
    pub verifier_key_root: String,
    pub offered_fee_units: u64,
    pub collateral_units: u64,
    pub max_depth: u64,
    pub child_proof_count: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub accepted: bool,
}

impl RecursiveProofBid {
    pub fn devnet(
        blob_id: &str,
        prover_id: &str,
        tier: RecursiveBidTier,
        height: u64,
        config: &PqBlobProofMarketConfig,
    ) -> Self {
        let recursive_plan_root = demo_root("recursive-plan", blob_id);
        let bid_id = deterministic_id(
            "RECURSIVE-BID-ID",
            &json!({
                "blob_id": blob_id,
                "prover_id": prover_id,
                "tier": tier.as_str(),
                "plan": recursive_plan_root,
                "height": height,
            }),
        );
        Self {
            bid_id,
            blob_id: blob_id.to_string(),
            prover_id: prover_id.to_string(),
            tier,
            latency_class: if tier == RecursiveBidTier::Emergency {
                LatencyClass::Immediate
            } else {
                LatencyClass::Fast
            },
            child_proof_root: demo_root("child-proof-set", blob_id),
            recursive_plan_root,
            verifier_key_root: demo_root("recursive-verifier-key", blob_id),
            offered_fee_units: 24,
            collateral_units: config.prover_bond_units,
            max_depth: 4,
            child_proof_count: 32,
            opened_height: height,
            expires_height: height.saturating_add(config.bid_window_blocks),
            accepted: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("RECURSIVE-PROOF-BID", &self.public_record())
    }

    pub fn validate(&self, config: &PqBlobProofMarketConfig) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.bid_id, "recursive bid id")?;
        ensure_non_empty(&self.blob_id, "recursive bid blob id")?;
        ensure_non_empty(&self.prover_id, "recursive bid prover id")?;
        ensure_hash_like(&self.child_proof_root, "recursive bid child proof root")?;
        ensure_hash_like(&self.recursive_plan_root, "recursive bid plan root")?;
        ensure_hash_like(&self.verifier_key_root, "recursive bid verifier key")?;
        ensure_positive(self.offered_fee_units, "recursive bid fee")?;
        if self.collateral_units < config.prover_bond_units {
            return Err("recursive bid collateral below config".to_string());
        }
        ensure_positive(self.max_depth, "recursive bid max depth")?;
        ensure_positive(self.child_proof_count, "recursive bid child count")?;
        ensure_height_window(self.opened_height, self.expires_height, "recursive bid")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaAvailabilityProof {
    pub availability_id: String,
    pub blob_id: String,
    pub proof_kind: DaProofKind,
    pub provider_id: String,
    pub sample_root: String,
    pub shard_commitment_root: String,
    pub opening_root: String,
    pub erasure_plan_root: String,
    pub available_shards: u64,
    pub required_shards: u64,
    pub posted_height: u64,
    pub expires_height: u64,
    pub accepted: bool,
}

impl DaAvailabilityProof {
    pub fn devnet(blob_id: &str, provider_label: &str, height: u64, ttl: u64) -> Self {
        let sample_root = demo_root("da-sample", provider_label);
        let availability_id = deterministic_id(
            "DA-AVAILABILITY-ID",
            &json!({
                "blob_id": blob_id,
                "provider": provider_label,
                "sample_root": sample_root,
                "height": height,
            }),
        );
        Self {
            availability_id,
            blob_id: blob_id.to_string(),
            proof_kind: DaProofKind::PrivateDaEscrow,
            provider_id: deterministic_id("DA-PROVIDER-ID", &json!({ "label": provider_label })),
            sample_root,
            shard_commitment_root: demo_root("da-shard-commitment", provider_label),
            opening_root: demo_root("da-opening", provider_label),
            erasure_plan_root: demo_root("da-erasure-plan", provider_label),
            available_shards: 62,
            required_shards: 48,
            posted_height: height.saturating_add(2),
            expires_height: height.saturating_add(ttl),
            accepted: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("DA-AVAILABILITY-PROOF", &self.public_record())
    }

    pub fn validate(&self) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.availability_id, "da availability id")?;
        ensure_non_empty(&self.blob_id, "da availability blob id")?;
        ensure_non_empty(&self.provider_id, "da availability provider id")?;
        ensure_hash_like(&self.sample_root, "da sample root")?;
        ensure_hash_like(&self.shard_commitment_root, "da shard commitment")?;
        ensure_hash_like(&self.opening_root, "da opening root")?;
        ensure_hash_like(&self.erasure_plan_root, "da erasure plan")?;
        ensure_positive(self.required_shards, "da required shards")?;
        if self.available_shards < self.required_shards {
            return Err("da available shards below required shards".to_string());
        }
        ensure_height_window(self.posted_height, self.expires_height, "da availability")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorshipCredit {
    pub credit_id: String,
    pub blob_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub max_fee_per_blob_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub active: bool,
}

impl LowFeeSponsorshipCredit {
    pub fn devnet(
        blob_id: &str,
        lane_key: &str,
        height: u64,
        config: &PqBlobProofMarketConfig,
    ) -> Self {
        let sponsor_commitment = demo_root("sponsor", lane_key);
        let credit_id = deterministic_id(
            "LOW-FEE-SPONSORSHIP-CREDIT-ID",
            &json!({
                "blob_id": blob_id,
                "lane_key": lane_key,
                "sponsor": sponsor_commitment,
                "height": height,
            }),
        );
        Self {
            credit_id,
            blob_id: blob_id.to_string(),
            sponsor_commitment,
            beneficiary_commitment: demo_root("sponsor-beneficiary", lane_key),
            lane_key: lane_key.to_string(),
            fee_asset_id: "asset:dxmr".to_string(),
            budget_units: config.sponsor_budget_units,
            reserved_units: 4,
            consumed_units: 1,
            max_fee_per_blob_units: config.low_fee_cap_units,
            opened_height: height,
            expires_height: height.saturating_add(config.private_lane_ttl_blocks),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("LOW-FEE-SPONSORSHIP-CREDIT", &self.public_record())
    }

    pub fn validate(&self, config: &PqBlobProofMarketConfig) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.credit_id, "sponsorship credit id")?;
        ensure_non_empty(&self.blob_id, "sponsorship blob id")?;
        ensure_hash_like(&self.sponsor_commitment, "sponsorship sponsor")?;
        ensure_hash_like(&self.beneficiary_commitment, "sponsorship beneficiary")?;
        ensure_non_empty(&self.lane_key, "sponsorship lane")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_positive(self.budget_units, "sponsorship budget")?;
        if self.budget_units > config.sponsor_budget_units {
            return Err("sponsorship budget exceeds config".to_string());
        }
        if self.reserved_units > self.budget_units || self.consumed_units > self.reserved_units {
            return Err("sponsorship accounting is inconsistent".to_string());
        }
        if self.max_fee_per_blob_units > config.low_fee_cap_units {
            return Err("sponsorship fee cap exceeds config".to_string());
        }
        ensure_height_window(self.opened_height, self.expires_height, "sponsorship")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengerBond {
    pub bond_id: String,
    pub blob_id: String,
    pub challenger_commitment: String,
    pub target_prover_id: String,
    pub evidence_root: String,
    pub bonded_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub slashed: bool,
    pub released: bool,
}

impl ChallengerBond {
    pub fn devnet(
        blob_id: &str,
        target_prover_id: &str,
        height: u64,
        config: &PqBlobProofMarketConfig,
    ) -> Self {
        let challenger_commitment = demo_root("challenger", blob_id);
        let evidence_root = demo_root("challenger-evidence", blob_id);
        let bond_id = deterministic_id(
            "CHALLENGER-BOND-ID",
            &json!({
                "blob_id": blob_id,
                "challenger": challenger_commitment,
                "evidence": evidence_root,
                "height": height,
            }),
        );
        Self {
            bond_id,
            blob_id: blob_id.to_string(),
            challenger_commitment,
            target_prover_id: target_prover_id.to_string(),
            evidence_root,
            bonded_units: config.challenger_bond_units,
            opened_height: height.saturating_add(8),
            expires_height: height.saturating_add(config.fraud_window_blocks),
            slashed: false,
            released: false,
        }
    }

    pub fn open(&self) -> bool {
        !self.slashed && !self.released
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("CHALLENGER-BOND", &self.public_record())
    }

    pub fn validate(&self, config: &PqBlobProofMarketConfig) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.bond_id, "challenger bond id")?;
        ensure_non_empty(&self.blob_id, "challenger bond blob id")?;
        ensure_hash_like(&self.challenger_commitment, "challenger commitment")?;
        ensure_non_empty(&self.target_prover_id, "challenger target prover")?;
        ensure_hash_like(&self.evidence_root, "challenger evidence root")?;
        if self.bonded_units < config.challenger_bond_units {
            return Err("challenger bond below config".to_string());
        }
        if self.slashed && self.released {
            return Err("challenger bond cannot be both slashed and released".to_string());
        }
        ensure_height_window(self.opened_height, self.expires_height, "challenger bond")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudEvidenceQueueItem {
    pub evidence_id: String,
    pub blob_id: String,
    pub bond_id: String,
    pub evidence_kind: FraudEvidenceKind,
    pub sealed_evidence_root: String,
    pub public_claim_root: String,
    pub queue_priority: u64,
    pub disclosure_bps: u64,
    pub observed_height: u64,
    pub resolve_deadline_height: u64,
    pub resolved: bool,
}

impl FraudEvidenceQueueItem {
    pub fn devnet(
        blob_id: &str,
        bond_id: &str,
        height: u64,
        config: &PqBlobProofMarketConfig,
    ) -> Self {
        let sealed_evidence_root = demo_root("sealed-fraud-evidence", blob_id);
        let evidence_id = deterministic_id(
            "FRAUD-EVIDENCE-ID",
            &json!({
                "blob_id": blob_id,
                "bond_id": bond_id,
                "sealed_evidence_root": sealed_evidence_root,
                "height": height,
            }),
        );
        Self {
            evidence_id,
            blob_id: blob_id.to_string(),
            bond_id: bond_id.to_string(),
            evidence_kind: FraudEvidenceKind::RecursiveMismatch,
            sealed_evidence_root,
            public_claim_root: demo_root("fraud-public-claim", blob_id),
            queue_priority: 9_100,
            disclosure_bps: 400,
            observed_height: height.saturating_add(9),
            resolve_deadline_height: height.saturating_add(config.fraud_window_blocks),
            resolved: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("FRAUD-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.evidence_id, "fraud evidence id")?;
        ensure_non_empty(&self.blob_id, "fraud evidence blob id")?;
        ensure_non_empty(&self.bond_id, "fraud evidence bond id")?;
        ensure_hash_like(&self.sealed_evidence_root, "fraud sealed evidence")?;
        ensure_hash_like(&self.public_claim_root, "fraud public claim")?;
        ensure_positive(self.queue_priority, "fraud queue priority")?;
        ensure_bps(self.disclosure_bps, "fraud disclosure bps")?;
        ensure_height_window(
            self.observed_height,
            self.resolve_deadline_height,
            "fraud evidence",
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractProofLane {
    pub lane_id: String,
    pub lane_key: String,
    pub contract_commitment_root: String,
    pub privacy_group_root: String,
    pub encrypted_policy_root: String,
    pub permitted_prover_root: String,
    pub da_lane_root: String,
    pub min_privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub active: bool,
}

impl PrivateContractProofLane {
    pub fn devnet(lane_key: &str, height: u64, config: &PqBlobProofMarketConfig) -> Self {
        let contract_commitment_root = demo_root("private-contract", lane_key);
        let lane_id = deterministic_id(
            "PRIVATE-CONTRACT-PROOF-LANE-ID",
            &json!({
                "lane_key": lane_key,
                "contract": contract_commitment_root,
                "height": height,
            }),
        );
        Self {
            lane_id,
            lane_key: lane_key.to_string(),
            contract_commitment_root,
            privacy_group_root: demo_root("private-lane-group", lane_key),
            encrypted_policy_root: demo_root("private-lane-policy", lane_key),
            permitted_prover_root: demo_root("private-lane-provers", lane_key),
            da_lane_root: demo_root("private-lane-da", lane_key),
            min_privacy_set_size: config.min_privacy_set_size * 4,
            opened_height: height,
            expires_height: height.saturating_add(config.private_lane_ttl_blocks),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("PRIVATE-CONTRACT-PROOF-LANE", &self.public_record())
    }

    pub fn validate(&self, config: &PqBlobProofMarketConfig) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.lane_id, "private lane id")?;
        ensure_non_empty(&self.lane_key, "private lane key")?;
        ensure_hash_like(&self.contract_commitment_root, "private lane contract")?;
        ensure_hash_like(&self.privacy_group_root, "private lane group")?;
        ensure_hash_like(&self.encrypted_policy_root, "private lane policy")?;
        ensure_hash_like(&self.permitted_prover_root, "private lane provers")?;
        ensure_hash_like(&self.da_lane_root, "private lane da")?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("private lane privacy set below config".to_string());
        }
        ensure_height_window(self.opened_height, self.expires_height, "private lane")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLatencyObservation {
    pub observation_id: String,
    pub blob_id: String,
    pub bid_id: String,
    pub latency_class: LatencyClass,
    pub posted_height: u64,
    pub completed_height: u64,
    pub target_blocks: u64,
    pub fee_rebate_bps: u64,
}

impl ProofLatencyObservation {
    pub fn devnet(blob_id: &str, bid_id: &str, height: u64, latency_class: LatencyClass) -> Self {
        let completed_height = height.saturating_add(latency_class.target_blocks().max(1));
        let observation_id = deterministic_id(
            "LATENCY-OBSERVATION-ID",
            &json!({
                "blob_id": blob_id,
                "bid_id": bid_id,
                "class": latency_class.as_str(),
                "completed_height": completed_height,
            }),
        );
        Self {
            observation_id,
            blob_id: blob_id.to_string(),
            bid_id: bid_id.to_string(),
            latency_class,
            posted_height: height,
            completed_height,
            target_blocks: latency_class.target_blocks().max(1),
            fee_rebate_bps: if matches!(latency_class, LatencyClass::Immediate | LatencyClass::Fast)
            {
                2_500
            } else {
                0
            },
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("LATENCY-OBSERVATION", &self.public_record())
    }

    pub fn validate(&self) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.observation_id, "latency observation id")?;
        ensure_non_empty(&self.blob_id, "latency blob id")?;
        ensure_non_empty(&self.bid_id, "latency bid id")?;
        if self.completed_height < self.posted_height {
            return Err("latency completed before posted".to_string());
        }
        ensure_positive(self.target_blocks, "latency target")?;
        ensure_bps(self.fee_rebate_bps, "latency rebate bps")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBlobProofPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
}

impl PqBlobProofPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PqBlobProofMarketResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.subject_id, "public record subject")?;
        ensure_hash_like(&self.subject_root, "public record subject root")?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBlobProofMarketState {
    pub height: u64,
    pub status: BlobProofStatus,
    pub config: PqBlobProofMarketConfig,
    pub encrypted_blobs: BTreeMap<String, MlKemEncryptedProofBlob>,
    pub prover_attestations: BTreeMap<String, PqProverAttestation>,
    pub recursive_bids: BTreeMap<String, RecursiveProofBid>,
    pub da_availability_proofs: BTreeMap<String, DaAvailabilityProof>,
    pub sponsorship_credits: BTreeMap<String, LowFeeSponsorshipCredit>,
    pub challenger_bonds: BTreeMap<String, ChallengerBond>,
    pub fraud_evidence_queue: BTreeMap<String, FraudEvidenceQueueItem>,
    pub private_contract_lanes: BTreeMap<String, PrivateContractProofLane>,
    pub latency_observations: BTreeMap<String, ProofLatencyObservation>,
    pub public_records: BTreeMap<String, PqBlobProofPublicRecord>,
}

impl PqBlobProofMarketState {
    pub fn devnet() -> PqBlobProofMarketResult<Self> {
        let height = PQ_BLOB_PROOF_MARKET_DEVNET_HEIGHT;
        let config = PqBlobProofMarketConfig::devnet();
        let mut state = Self {
            height,
            status: BlobProofStatus::Available,
            config,
            encrypted_blobs: BTreeMap::new(),
            prover_attestations: BTreeMap::new(),
            recursive_bids: BTreeMap::new(),
            da_availability_proofs: BTreeMap::new(),
            sponsorship_credits: BTreeMap::new(),
            challenger_bonds: BTreeMap::new(),
            fraud_evidence_queue: BTreeMap::new(),
            private_contract_lanes: BTreeMap::new(),
            latency_observations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqBlobProofMarketResult<()> {
        self.height = height;
        for blob in self.encrypted_blobs.values_mut() {
            if height > blob.proof_deadline_height && blob.status.live() {
                blob.status = BlobProofStatus::Expired;
            }
        }
        for credit in self.sponsorship_credits.values_mut() {
            if height > credit.expires_height {
                credit.active = false;
            }
        }
        for lane in self.private_contract_lanes.values_mut() {
            if height > lane.expires_height {
                lane.active = false;
            }
        }
        for evidence in self.fraud_evidence_queue.values_mut() {
            if height > evidence.resolve_deadline_height {
                evidence.resolved = true;
            }
        }
        self.validate().map(|_| ())
    }

    pub fn roots(&self) -> PqBlobProofMarketRoots {
        PqBlobProofMarketRoots {
            config_root: self.config.state_root(),
            encrypted_blob_root: collection_root(
                "ENCRYPTED-BLOBS",
                self.encrypted_blobs
                    .values()
                    .map(MlKemEncryptedProofBlob::public_record)
                    .collect(),
            ),
            prover_attestation_root: collection_root(
                "PROVER-ATTESTATIONS",
                self.prover_attestations
                    .values()
                    .map(PqProverAttestation::public_record)
                    .collect(),
            ),
            recursive_bid_root: collection_root(
                "RECURSIVE-BIDS",
                self.recursive_bids
                    .values()
                    .map(RecursiveProofBid::public_record)
                    .collect(),
            ),
            da_availability_root: collection_root(
                "DA-AVAILABILITY-PROOFS",
                self.da_availability_proofs
                    .values()
                    .map(DaAvailabilityProof::public_record)
                    .collect(),
            ),
            sponsorship_credit_root: collection_root(
                "SPONSORSHIP-CREDITS",
                self.sponsorship_credits
                    .values()
                    .map(LowFeeSponsorshipCredit::public_record)
                    .collect(),
            ),
            challenger_bond_root: collection_root(
                "CHALLENGER-BONDS",
                self.challenger_bonds
                    .values()
                    .map(ChallengerBond::public_record)
                    .collect(),
            ),
            fraud_evidence_root: collection_root(
                "FRAUD-EVIDENCE-QUEUE",
                self.fraud_evidence_queue
                    .values()
                    .map(FraudEvidenceQueueItem::public_record)
                    .collect(),
            ),
            private_lane_root: collection_root(
                "PRIVATE-CONTRACT-LANES",
                self.private_contract_lanes
                    .values()
                    .map(PrivateContractProofLane::public_record)
                    .collect(),
            ),
            latency_observation_root: collection_root(
                "LATENCY-OBSERVATIONS",
                self.latency_observations
                    .values()
                    .map(ProofLatencyObservation::public_record)
                    .collect(),
            ),
            public_record_root: collection_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(PqBlobProofPublicRecord::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqBlobProofMarketCounters {
        PqBlobProofMarketCounters {
            encrypted_blobs: self.encrypted_blobs.len() as u64,
            live_blobs: self
                .encrypted_blobs
                .values()
                .filter(|blob| blob.status.live())
                .count() as u64,
            private_blobs: self
                .encrypted_blobs
                .values()
                .filter(|blob| blob.blob_kind.private())
                .count() as u64,
            prover_attestations: self.prover_attestations.len() as u64,
            recursive_bids: self.recursive_bids.len() as u64,
            accepted_recursive_bids: self
                .recursive_bids
                .values()
                .filter(|bid| bid.accepted)
                .count() as u64,
            da_availability_proofs: self.da_availability_proofs.len() as u64,
            active_sponsorship_credits: self
                .sponsorship_credits
                .values()
                .filter(|credit| credit.active)
                .count() as u64,
            challenger_bonds: self.challenger_bonds.len() as u64,
            open_challenger_bonds: self
                .challenger_bonds
                .values()
                .filter(|bond| bond.open())
                .count() as u64,
            fraud_evidence_items: self.fraud_evidence_queue.len() as u64,
            unresolved_fraud_evidence_items: self
                .fraud_evidence_queue
                .values()
                .filter(|evidence| !evidence.resolved)
                .count() as u64,
            private_contract_lanes: self.private_contract_lanes.len() as u64,
            active_private_contract_lanes: self
                .private_contract_lanes
                .values()
                .filter(|lane| lane.active)
                .count() as u64,
            latency_observations: self.latency_observations.len() as u64,
            public_records: self.public_records.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "pq_blob_proof_market_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        pq_blob_proof_market_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> PqBlobProofMarketResult<String> {
        self.config.validate()?;
        ensure_capacity(
            self.encrypted_blobs.len(),
            self.config.max_blobs,
            "encrypted blobs",
        )?;
        ensure_capacity(
            self.prover_attestations.len(),
            self.config.max_attestations,
            "prover attestations",
        )?;
        ensure_capacity(
            self.recursive_bids.len(),
            self.config.max_recursive_bids,
            "recursive bids",
        )?;
        ensure_capacity(
            self.da_availability_proofs.len(),
            self.config.max_da_proofs,
            "da availability proofs",
        )?;
        ensure_capacity(
            self.sponsorship_credits.len(),
            self.config.max_sponsorships,
            "sponsorship credits",
        )?;
        ensure_capacity(
            self.challenger_bonds.len(),
            self.config.max_challenger_bonds,
            "challenger bonds",
        )?;
        ensure_capacity(
            self.fraud_evidence_queue.len(),
            self.config.max_fraud_evidence,
            "fraud evidence",
        )?;
        ensure_capacity(
            self.private_contract_lanes.len(),
            self.config.max_private_lanes,
            "private lanes",
        )?;
        ensure_capacity(
            self.latency_observations.len(),
            self.config.max_latency_observations,
            "latency observations",
        )?;
        ensure_capacity(
            self.public_records.len(),
            self.config.max_public_records,
            "public records",
        )?;

        let lane_keys = self
            .private_contract_lanes
            .values()
            .map(|lane| lane.lane_key.clone())
            .collect::<BTreeSet<_>>();

        for (id, lane) in &self.private_contract_lanes {
            ensure_key_matches(id, &lane.lane_id, "private lane")?;
            lane.validate(&self.config)?;
        }
        for (id, blob) in &self.encrypted_blobs {
            ensure_key_matches(id, &blob.blob_id, "encrypted blob")?;
            blob.validate(&self.config)?;
            if !blob.private_lane_id.is_empty()
                && !self
                    .private_contract_lanes
                    .contains_key(&blob.private_lane_id)
            {
                return Err("blob references unknown private lane".to_string());
            }
            if blob.blob_kind.private() && blob.private_lane_id.is_empty() {
                return Err("private blob requires private lane".to_string());
            }
            if !blob.sponsor_credit_id.is_empty()
                && !self
                    .sponsorship_credits
                    .contains_key(&blob.sponsor_credit_id)
            {
                return Err("blob references unknown sponsorship credit".to_string());
            }
            if !blob.assigned_bid_id.is_empty()
                && !self.recursive_bids.contains_key(&blob.assigned_bid_id)
            {
                return Err("blob references unknown assigned bid".to_string());
            }
        }
        for (id, attestation) in &self.prover_attestations {
            ensure_key_matches(id, &attestation.attestation_id, "attestation")?;
            attestation.validate(&self.config)?;
            ensure_exists(
                &attestation.blob_id,
                &self.encrypted_blobs,
                "attestation blob",
            )?;
        }
        for (id, bid) in &self.recursive_bids {
            ensure_key_matches(id, &bid.bid_id, "recursive bid")?;
            bid.validate(&self.config)?;
            ensure_exists(&bid.blob_id, &self.encrypted_blobs, "recursive bid blob")?;
        }
        for (id, da) in &self.da_availability_proofs {
            ensure_key_matches(id, &da.availability_id, "da availability")?;
            da.validate()?;
            ensure_exists(&da.blob_id, &self.encrypted_blobs, "da availability blob")?;
        }
        for (id, credit) in &self.sponsorship_credits {
            ensure_key_matches(id, &credit.credit_id, "sponsorship credit")?;
            credit.validate(&self.config)?;
            ensure_exists(&credit.blob_id, &self.encrypted_blobs, "sponsorship blob")?;
            if !lane_keys.contains(&credit.lane_key) {
                return Err("sponsorship references unknown lane key".to_string());
            }
        }
        for (id, bond) in &self.challenger_bonds {
            ensure_key_matches(id, &bond.bond_id, "challenger bond")?;
            bond.validate(&self.config)?;
            ensure_exists(&bond.blob_id, &self.encrypted_blobs, "challenger bond blob")?;
        }
        for (id, evidence) in &self.fraud_evidence_queue {
            ensure_key_matches(id, &evidence.evidence_id, "fraud evidence")?;
            evidence.validate()?;
            ensure_exists(
                &evidence.blob_id,
                &self.encrypted_blobs,
                "fraud evidence blob",
            )?;
            ensure_exists(
                &evidence.bond_id,
                &self.challenger_bonds,
                "fraud evidence bond",
            )?;
        }
        for (id, observation) in &self.latency_observations {
            ensure_key_matches(id, &observation.observation_id, "latency observation")?;
            observation.validate()?;
            ensure_exists(&observation.blob_id, &self.encrypted_blobs, "latency blob")?;
            ensure_exists(&observation.bid_id, &self.recursive_bids, "latency bid")?;
        }
        for (id, record) in &self.public_records {
            ensure_key_matches(id, &record.record_id, "public record")?;
            record.validate()?;
            if record.height > self.height {
                return Err("public record height exceeds state height".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_blob_proof_market_state",
            "protocol_version": PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION,
            "protocol_id": PQ_BLOB_PROOF_MARKET_PROTOCOL_ID,
            "schema_version": PQ_BLOB_PROOF_MARKET_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "status": self.status.as_str(),
            "hash_suite": PQ_BLOB_PROOF_MARKET_HASH_SUITE,
            "kem_suite": PQ_BLOB_PROOF_MARKET_KEM_SUITE,
            "encryption_suite": PQ_BLOB_PROOF_MARKET_ENCRYPTION_SUITE,
            "ml_dsa_suite": PQ_BLOB_PROOF_MARKET_ML_DSA_SUITE,
            "slh_dsa_suite": PQ_BLOB_PROOF_MARKET_SLH_DSA_SUITE,
            "recursion_scheme": PQ_BLOB_PROOF_MARKET_RECURSION_SCHEME,
            "da_scheme": PQ_BLOB_PROOF_MARKET_DA_SCHEME,
            "private_lane_scheme": PQ_BLOB_PROOF_MARKET_PRIVATE_LANE_SCHEME,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    fn insert_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
    ) -> PqBlobProofMarketResult<()> {
        let record_id = deterministic_id(
            "PUBLIC-RECORD-ID",
            &json!({
                "kind": record_kind,
                "subject_id": subject_id,
                "subject_root": subject_root,
                "height": self.height,
            }),
        );
        let record = PqBlobProofPublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height: self.height,
        };
        record.validate()?;
        self.public_records.insert(record_id, record);
        Ok(())
    }

    fn seed_devnet_records(&mut self) -> PqBlobProofMarketResult<()> {
        let lane = PrivateContractProofLane::devnet(
            "private-defi-proof-lane-devnet",
            self.height,
            &self.config,
        );
        let lane_id = lane.lane_id.clone();
        let lane_key = lane.lane_key.clone();
        let lane_root = lane.state_root();
        self.private_contract_lanes.insert(lane_id.clone(), lane);
        self.insert_public_record("private_contract_proof_lane", &lane_id, &lane_root)?;

        let mut blob = MlKemEncryptedProofBlob::devnet(
            "private-defi-proof-blob-0001",
            ProofBlobKind::PrivateDefiBatch,
            self.height,
            &self.config,
            1,
        );
        blob.private_lane_id = lane_id.clone();
        blob.status = BlobProofStatus::Assigned;

        let attestation =
            PqProverAttestation::devnet(&blob.blob_id, "devnet-prover-alpha", self.height, 96);
        let bid = RecursiveProofBid::devnet(
            &blob.blob_id,
            &attestation.prover_id,
            RecursiveBidTier::PrivateContract,
            self.height,
            &self.config,
        );
        blob.assigned_bid_id = bid.bid_id.clone();
        let da = DaAvailabilityProof::devnet(
            &blob.blob_id,
            "devnet-da-provider-alpha",
            self.height,
            self.config.da_window_blocks,
        );
        let credit =
            LowFeeSponsorshipCredit::devnet(&blob.blob_id, &lane_key, self.height, &self.config);
        blob.sponsor_credit_id = credit.credit_id.clone();
        let bond = ChallengerBond::devnet(
            &blob.blob_id,
            &attestation.prover_id,
            self.height,
            &self.config,
        );
        let evidence =
            FraudEvidenceQueueItem::devnet(&blob.blob_id, &bond.bond_id, self.height, &self.config);
        let latency = ProofLatencyObservation::devnet(
            &blob.blob_id,
            &bid.bid_id,
            self.height,
            LatencyClass::Fast,
        );

        let blob_id = blob.blob_id.clone();
        let blob_root = blob.state_root();
        let attestation_id = attestation.attestation_id.clone();
        let attestation_root = attestation.state_root();
        let bid_id = bid.bid_id.clone();
        let bid_root = bid.state_root();
        let da_id = da.availability_id.clone();
        let da_root = da.state_root();
        let credit_id = credit.credit_id.clone();
        let credit_root = credit.state_root();
        let bond_id = bond.bond_id.clone();
        let bond_root = bond.state_root();
        let evidence_id = evidence.evidence_id.clone();
        let evidence_root = evidence.state_root();
        let latency_id = latency.observation_id.clone();
        let latency_root = latency.state_root();

        self.encrypted_blobs.insert(blob_id.clone(), blob);
        self.prover_attestations
            .insert(attestation_id.clone(), attestation);
        self.recursive_bids.insert(bid_id.clone(), bid);
        self.da_availability_proofs.insert(da_id.clone(), da);
        self.sponsorship_credits.insert(credit_id.clone(), credit);
        self.challenger_bonds.insert(bond_id.clone(), bond);
        self.fraud_evidence_queue
            .insert(evidence_id.clone(), evidence);
        self.latency_observations
            .insert(latency_id.clone(), latency);

        self.insert_public_record("ml_kem_encrypted_proof_blob", &blob_id, &blob_root)?;
        self.insert_public_record("pq_prover_attestation", &attestation_id, &attestation_root)?;
        self.insert_public_record("recursive_proof_bid", &bid_id, &bid_root)?;
        self.insert_public_record("da_availability_proof", &da_id, &da_root)?;
        self.insert_public_record("low_fee_sponsorship_credit", &credit_id, &credit_root)?;
        self.insert_public_record("challenger_bond", &bond_id, &bond_root)?;
        self.insert_public_record("fraud_evidence_queue_item", &evidence_id, &evidence_root)?;
        self.insert_public_record("proof_latency_observation", &latency_id, &latency_root)?;

        let mut public_blob = MlKemEncryptedProofBlob::devnet(
            "low-fee-public-good-proof-blob-0002",
            ProofBlobKind::LowFeePublicGood,
            self.height,
            &self.config,
            2,
        );
        public_blob.status = BlobProofStatus::Sponsored;
        let public_blob_id = public_blob.blob_id.clone();
        let public_blob_root = public_blob.state_root();
        self.encrypted_blobs
            .insert(public_blob_id.clone(), public_blob);
        self.insert_public_record(
            "ml_kem_encrypted_low_fee_proof_blob",
            &public_blob_id,
            &public_blob_root,
        )?;

        Ok(())
    }
}

pub fn pq_blob_proof_market_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-BLOB-PROOF-MARKET-STATE",
        &[
            HashPart::Int(PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION as i128),
            HashPart::Str(PQ_BLOB_PROOF_MARKET_PROTOCOL_ID),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PQ-BLOB-PROOF-MARKET-{domain}"),
        &[
            HashPart::Int(PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION as i128),
            HashPart::Str(PQ_BLOB_PROOF_MARKET_PROTOCOL_ID),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    payload_root(domain, &json!({ "records": records }))
}

fn deterministic_id(domain: &str, payload: &Value) -> String {
    payload_root(domain, payload)
}

fn demo_root(scope: &str, label: &str) -> String {
    domain_hash(
        "PQ-BLOB-PROOF-MARKET-DEVNET-SEED",
        &[
            HashPart::Int(PQ_BLOB_PROOF_MARKET_PROTOCOL_VERSION as i128),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(label),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PqBlobProofMarketResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PqBlobProofMarketResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PqBlobProofMarketResult<()> {
    if value > PQ_BLOB_PROOF_MARKET_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_hash_like(value: &str, label: &str) -> PqBlobProofMarketResult<()> {
    ensure_non_empty(value, label)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> PqBlobProofMarketResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn ensure_capacity(len: usize, max: usize, label: &str) -> PqBlobProofMarketResult<()> {
    if len > max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_key_matches(key: &str, id: &str, label: &str) -> PqBlobProofMarketResult<()> {
    if key != id {
        return Err(format!("{label} map key mismatch"));
    }
    Ok(())
}

fn ensure_exists<T>(
    id: &str,
    map: &BTreeMap<String, T>,
    label: &str,
) -> PqBlobProofMarketResult<()> {
    if !map.contains_key(id) {
        return Err(format!("{label} references unknown id"));
    }
    Ok(())
}
