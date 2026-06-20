use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialLatticeProofCompressionMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialLatticeProofCompressionMarketRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_PROOF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-lattice-proof-compression-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_PROOF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_COMPRESSION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-lattice-proof-compression-v1";
pub const PROOF_BUNDLE_SCHEME: &str = "sealed-post-quantum-proof-bundle-root-v1";
pub const COMPRESSION_QUOTE_SCHEME: &str = "sealed-lattice-compression-fee-quote-root-v1";
pub const RESERVED_LANE_SCHEME: &str = "reserved-pq-proof-lane-commitment-v1";
pub const VERIFIER_RECEIPT_SCHEME: &str = "pq-compressed-proof-verifier-receipt-v1";
pub const REBATE_SCHEME: &str = "low-fee-lattice-proof-compression-rebate-v1";
pub const SLASHING_SCHEME: &str = "lattice-compressor-slashing-quarantine-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "lattice-proof-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "public-lattice-proof-compression-market-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_MARKET_ID: &str = "devnet-lattice-proof-compression-market";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_180_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_COMPRESSION_RATIO_BPS: u64 = 2_500;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_PROVIDER_STAKE_FLOOR_PICONERO: u128 = 50_000_000_000;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_RESERVED_LANE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_EVIDENCE_WINDOW_BLOCKS: u64 = 288;
pub const DEFAULT_MAX_BUNDLES: usize = 1_048_576;
pub const DEFAULT_MAX_PROVIDERS: usize = 65_536;
pub const DEFAULT_MAX_QUOTES: usize = 2_097_152;
pub const DEFAULT_MAX_RESERVED_LANES: usize = 524_288;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_QUARANTINES: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleKind {
    MoneroRingCt,
    SeraphisMigration,
    BridgeReserve,
    RecursiveRollup,
    ContractWitness,
    LiquidityNetting,
    EmergencyExit,
}

impl ProofBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroRingCt => "monero_ringct",
            Self::SeraphisMigration => "seraphis_migration",
            Self::BridgeReserve => "bridge_reserve",
            Self::RecursiveRollup => "recursive_rollup",
            Self::ContractWitness => "contract_witness",
            Self::LiquidityNetting => "liquidity_netting",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::BridgeReserve => 9_300,
            Self::SeraphisMigration => 8_900,
            Self::MoneroRingCt => 8_600,
            Self::RecursiveRollup => 8_250,
            Self::LiquidityNetting => 7_800,
            Self::ContractWitness => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Submitted,
    Quoted,
    Reserved,
    Compressing,
    Compressed,
    Verified,
    Rebated,
    Expired,
    Quarantined,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Compressing => "compressing",
            Self::Compressed => "compressed",
            Self::Verified => "verified",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    Throttled,
    Probation,
    Quarantined,
    Slashed,
    Retired,
}

impl ProviderStatus {
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    LatticeDictionary,
    ModuleSyndromeDelta,
    RecursiveTranscriptFold,
    RangeProofDedup,
    HybridWitnessPack,
    EmergencyMinimal,
}

impl CompressionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatticeDictionary => "lattice_dictionary",
            Self::ModuleSyndromeDelta => "module_syndrome_delta",
            Self::RecursiveTranscriptFold => "recursive_transcript_fold",
            Self::RangeProofDedup => "range_proof_dedup",
            Self::HybridWitnessPack => "hybrid_witness_pack",
            Self::EmergencyMinimal => "emergency_minimal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Filled,
    Expired,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Reserved,
    Compressing,
    Verifying,
    Released,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVerdict {
    Accepted,
    AcceptedWithRedactions,
    NeedsRecompression,
    Rejected,
}

impl ReceiptVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithRedactions => "accepted_with_redactions",
            Self::NeedsRecompression => "needs_recompression",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    Miscompression,
    WithheldOutput,
    InvalidLatticeTranscript,
    FeeOvercharge,
    PrivacyLeak,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Miscompression => "miscompression",
            Self::WithheldOutput => "withheld_output",
            Self::InvalidLatticeTranscript => "invalid_lattice_transcript",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_compression_suite: String,
    pub proof_bundle_scheme: String,
    pub compression_quote_scheme: String,
    pub reserved_lane_scheme: String,
    pub verifier_receipt_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub redaction_budget_scheme: String,
    pub public_record_scheme: String,
    pub l2_network: String,
    pub monero_network: String,
    pub market_id: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_compression_ratio_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub provider_stake_floor_piconero: u128,
    pub quote_ttl_blocks: u64,
    pub reserved_lane_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub evidence_window_blocks: u64,
    pub max_bundles: usize,
    pub max_providers: usize,
    pub max_quotes: usize,
    pub max_reserved_lanes: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_compression_suite: PQ_COMPRESSION_SUITE.to_string(),
            proof_bundle_scheme: PROOF_BUNDLE_SCHEME.to_string(),
            compression_quote_scheme: COMPRESSION_QUOTE_SCHEME.to_string(),
            reserved_lane_scheme: RESERVED_LANE_SCHEME.to_string(),
            verifier_receipt_scheme: VERIFIER_RECEIPT_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            slashing_scheme: SLASHING_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_compression_ratio_bps: DEFAULT_TARGET_COMPRESSION_RATIO_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            provider_stake_floor_piconero: DEFAULT_PROVIDER_STAKE_FLOOR_PICONERO,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            reserved_lane_ttl_blocks: DEFAULT_RESERVED_LANE_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            evidence_window_blocks: DEFAULT_EVIDENCE_WINDOW_BLOCKS,
            max_bundles: DEFAULT_MAX_BUNDLES,
            max_providers: DEFAULT_MAX_PROVIDERS,
            max_quotes: DEFAULT_MAX_QUOTES,
            max_reserved_lanes: DEFAULT_MAX_RESERVED_LANES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_compression_suite": self.pq_compression_suite,
            "proof_bundle_scheme": self.proof_bundle_scheme,
            "compression_quote_scheme": self.compression_quote_scheme,
            "reserved_lane_scheme": self.reserved_lane_scheme,
            "verifier_receipt_scheme": self.verifier_receipt_scheme,
            "rebate_scheme": self.rebate_scheme,
            "slashing_scheme": self.slashing_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "public_record_scheme": self.public_record_scheme,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "market_id": self.market_id,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_compression_ratio_bps": self.target_compression_ratio_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "provider_stake_floor_piconero": self.provider_stake_floor_piconero.to_string(),
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reserved_lane_ttl_blocks": self.reserved_lane_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "evidence_window_blocks": self.evidence_window_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bundles: u64,
    pub providers: u64,
    pub quotes: u64,
    pub reserved_lanes: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub quarantines: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub verified_bundles: u64,
    pub slashed_providers: u64,
    pub total_fee_piconero: u128,
    pub total_rebate_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "bundles": self.bundles,
            "providers": self.providers,
            "quotes": self.quotes,
            "reserved_lanes": self.reserved_lanes,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "quarantines": self.quarantines,
            "redaction_budgets": self.redaction_budgets,
            "public_records": self.public_records,
            "verified_bundles": self.verified_bundles,
            "slashed_providers": self.slashed_providers,
            "total_fee_piconero": self.total_fee_piconero.to_string(),
            "total_rebate_piconero": self.total_rebate_piconero.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub bundle_root: String,
    pub provider_root: String,
    pub quote_root: String,
    pub reserved_lane_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "bundle_root": self.bundle_root,
            "provider_root": self.provider_root,
            "quote_root": self.quote_root,
            "reserved_lane_root": self.reserved_lane_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofBundle {
    pub bundle_id: String,
    pub kind: ProofBundleKind,
    pub status: BundleStatus,
    pub submitter_commitment: String,
    pub sealed_proof_root: String,
    pub redacted_context_root: String,
    pub privacy_nullifier: String,
    pub uncompressed_bytes: u64,
    pub target_compressed_bytes: u64,
    pub fee_cap_piconero: u128,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl ProofBundle {
    pub fn new(
        sequence: u64,
        kind: ProofBundleKind,
        submitter_commitment: &str,
        sealed_proof_root: &str,
        redacted_context_root: &str,
        privacy_nullifier: &str,
        uncompressed_bytes: u64,
        fee_cap_piconero: u128,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty(submitter_commitment, "submitter commitment")?;
        ensure_non_empty(sealed_proof_root, "sealed proof root")?;
        ensure_non_empty(redacted_context_root, "redacted context root")?;
        ensure_non_empty(privacy_nullifier, "privacy nullifier")?;
        if uncompressed_bytes == 0 {
            return Err("uncompressed bytes must be positive".to_string());
        }
        let target_compressed_bytes =
            uncompressed_bytes.saturating_mul(config.target_compression_ratio_bps) / MAX_BPS;
        let bundle_id = module_hash(
            "BUNDLE-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(kind.as_str()),
                HashPart::Str(sealed_proof_root),
                HashPart::Str(privacy_nullifier),
            ],
        );
        Ok(Self {
            bundle_id,
            kind,
            status: BundleStatus::Submitted,
            submitter_commitment: submitter_commitment.to_string(),
            sealed_proof_root: sealed_proof_root.to_string(),
            redacted_context_root: redacted_context_root.to_string(),
            privacy_nullifier: privacy_nullifier.to_string(),
            uncompressed_bytes,
            target_compressed_bytes,
            fee_cap_piconero,
            privacy_set_size: config.min_privacy_set_size,
            created_height: height,
            expires_height: height.saturating_add(config.quote_ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_bundle",
            "bundle_id": self.bundle_id,
            "bundle_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "sealed_proof_root": self.sealed_proof_root,
            "redacted_context_root": self.redacted_context_root,
            "uncompressed_bytes": self.uncompressed_bytes,
            "target_compressed_bytes": self.target_compressed_bytes,
            "fee_cap_piconero": self.fee_cap_piconero.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionProvider {
    pub provider_id: String,
    pub status: ProviderStatus,
    pub operator_commitment: String,
    pub pq_attestation_root: String,
    pub stake_commitment: String,
    pub supported_modes: BTreeSet<CompressionMode>,
    pub max_bundle_bytes: u64,
    pub min_fee_piconero: u128,
    pub stake_floor_piconero: u128,
    pub registered_height: u64,
}

impl CompressionProvider {
    pub fn new(
        sequence: u64,
        operator_commitment: &str,
        pq_attestation_root: &str,
        stake_commitment: &str,
        supported_modes: impl IntoIterator<Item = CompressionMode>,
        max_bundle_bytes: u64,
        min_fee_piconero: u128,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty(operator_commitment, "operator commitment")?;
        ensure_non_empty(pq_attestation_root, "pq attestation root")?;
        ensure_non_empty(stake_commitment, "stake commitment")?;
        let supported_modes = supported_modes.into_iter().collect::<BTreeSet<_>>();
        if supported_modes.is_empty() {
            return Err("provider must support at least one compression mode".to_string());
        }
        let provider_id = module_hash(
            "PROVIDER-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(operator_commitment),
                HashPart::Str(pq_attestation_root),
            ],
        );
        Ok(Self {
            provider_id,
            status: ProviderStatus::Active,
            operator_commitment: operator_commitment.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            stake_commitment: stake_commitment.to_string(),
            supported_modes,
            max_bundle_bytes,
            min_fee_piconero,
            stake_floor_piconero: config.provider_stake_floor_piconero,
            registered_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_provider",
            "provider_id": self.provider_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "pq_attestation_root": self.pq_attestation_root,
            "stake_commitment": self.stake_commitment,
            "supported_modes": records(self.supported_modes.iter().map(|mode| json!(mode.as_str()))),
            "max_bundle_bytes": self.max_bundle_bytes,
            "min_fee_piconero": self.min_fee_piconero.to_string(),
            "stake_floor_piconero": self.stake_floor_piconero.to_string(),
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub bundle_id: String,
    pub provider_id: String,
    pub mode: CompressionMode,
    pub status: QuoteStatus,
    pub quoted_fee_piconero: u128,
    pub expected_rebate_piconero: u128,
    pub expected_compressed_bytes: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_quote",
            "quote_id": self.quote_id,
            "bundle_id": self.bundle_id,
            "provider_id": self.provider_id,
            "mode": self.mode.as_str(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "quoted_fee_piconero": self.quoted_fee_piconero.to_string(),
            "expected_rebate_piconero": self.expected_rebate_piconero.to_string(),
            "expected_compressed_bytes": self.expected_compressed_bytes,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservedProofLane {
    pub lane_id: String,
    pub bundle_id: String,
    pub quote_id: String,
    pub provider_id: String,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
}

impl ReservedProofLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserved_proof_lane",
            "lane_id": self.lane_id,
            "bundle_id": self.bundle_id,
            "quote_id": self.quote_id,
            "provider_id": self.provider_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "priority_weight": self.priority_weight,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub provider_id: String,
    pub compressed_proof_root: String,
    pub verifier_committee_root: String,
    pub verdict: ReceiptVerdict,
    pub compressed_bytes: u64,
    pub fee_paid_piconero: u128,
    pub verified_height: u64,
    pub expires_height: u64,
}

impl VerifierReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_receipt",
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "provider_id": self.provider_id,
            "compressed_proof_root": self.compressed_proof_root,
            "verifier_committee_root": self.verifier_committee_root,
            "verdict": self.verdict.as_str(),
            "compressed_bytes": self.compressed_bytes,
            "fee_paid_piconero": self.fee_paid_piconero.to_string(),
            "verified_height": self.verified_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateClaim {
    pub rebate_id: String,
    pub bundle_id: String,
    pub receipt_id: String,
    pub claimant_commitment: String,
    pub amount_piconero: u128,
    pub settled_height: u64,
}

impl RebateClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_claim",
            "rebate_id": self.rebate_id,
            "bundle_id": self.bundle_id,
            "receipt_id": self.receipt_id,
            "amount_piconero": self.amount_piconero.to_string(),
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineCase {
    pub quarantine_id: String,
    pub bundle_id: String,
    pub provider_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub slash_amount_piconero: u128,
    pub opened_height: u64,
}

impl QuarantineCase {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quarantine_case",
            "quarantine_id": self.quarantine_id,
            "bundle_id": self.bundle_id,
            "provider_id": self.provider_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slash_amount_piconero": self.slash_amount_piconero.to_string(),
            "opened_height": self.opened_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch: u64,
    pub allowed_redactions: u64,
    pub consumed_redactions: u64,
    pub budget_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "redaction_budget",
            "budget_id": self.budget_id,
            "epoch": self.epoch,
            "allowed_redactions": self.allowed_redactions,
            "consumed_redactions": self.consumed_redactions,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicMarketRecord {
    pub record_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub public_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl PublicMarketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_market_record",
            "record_id": self.record_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "public_root": self.public_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub bundles: BTreeMap<String, ProofBundle>,
    pub providers: BTreeMap<String, CompressionProvider>,
    pub quotes: BTreeMap<String, FeeQuote>,
    pub reserved_lanes: BTreeMap<String, ReservedProofLane>,
    pub receipts: BTreeMap<String, VerifierReceipt>,
    pub rebates: BTreeMap<String, RebateClaim>,
    pub quarantines: BTreeMap<String, QuarantineCase>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, PublicMarketRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            height: DEVNET_HEIGHT,
            bundles: BTreeMap::new(),
            providers: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reserved_lanes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let provider_id = state
            .register_provider(
                "devnet-lattice-compressor-commitment",
                &module_hash("DEVNET-PQ-ATTESTATION", &[HashPart::Str("ml-dsa-87")]),
                &module_hash("DEVNET-STAKE", &[HashPart::Str("provider-stake")]),
                [
                    CompressionMode::LatticeDictionary,
                    CompressionMode::RecursiveTranscriptFold,
                    CompressionMode::RangeProofDedup,
                ],
                8_388_608,
                1_250_000,
            )
            .expect("valid devnet provider");
        let bundle_id = state
            .submit_bundle(
                ProofBundleKind::MoneroRingCt,
                "devnet-submitment-commitment",
                &module_hash("DEVNET-SEALED-PROOF", &[HashPart::Str("ringct-batch")]),
                &module_hash("DEVNET-REDACTED-CONTEXT", &[HashPart::Str("monero-l2")]),
                "devnet-private-nullifier-0",
                1_048_576,
                2_000_000,
            )
            .expect("valid devnet bundle");
        let quote_id = state
            .post_quote(
                &bundle_id,
                &provider_id,
                CompressionMode::LatticeDictionary,
                1_200_000,
                786_432,
            )
            .expect("valid devnet quote");
        let lane_id = state
            .reserve_lane(&quote_id)
            .expect("valid devnet reserved lane");
        let receipt_id = state
            .record_receipt(
                &bundle_id,
                &provider_id,
                &module_hash("DEVNET-COMPRESSED-PROOF", &[HashPart::Str(&lane_id)]),
                &module_hash("DEVNET-VERIFIER-COMMITTEE", &[HashPart::Str("committee-0")]),
                ReceiptVerdict::AcceptedWithRedactions,
                720_896,
                1_200_000,
            )
            .expect("valid devnet receipt");
        state
            .settle_rebate(
                &bundle_id,
                &receipt_id,
                "devnet-rebate-claimant-commitment",
                120_000,
            )
            .expect("valid devnet rebate");
        state
            .open_redaction_budget("devnet-redaction-owner-commitment", 0, 128)
            .expect("valid devnet redaction budget");
        state
    }

    pub fn submit_bundle(
        &mut self,
        kind: ProofBundleKind,
        submitter_commitment: &str,
        sealed_proof_root: &str,
        redacted_context_root: &str,
        privacy_nullifier: &str,
        uncompressed_bytes: u64,
        fee_cap_piconero: u128,
    ) -> Result<String> {
        ensure_capacity(self.bundles.len(), self.config.max_bundles, "bundles")?;
        if self.spent_nullifiers.contains(privacy_nullifier) {
            return Err("privacy nullifier already spent".to_string());
        }
        let sequence = self.counters.bundles.saturating_add(1);
        let bundle = ProofBundle::new(
            sequence,
            kind,
            submitter_commitment,
            sealed_proof_root,
            redacted_context_root,
            privacy_nullifier,
            uncompressed_bytes,
            fee_cap_piconero,
            self.height,
            &self.config,
        )?;
        let bundle_id = bundle.bundle_id.clone();
        let public_root = module_hash("BUNDLE-PUBLIC", &[HashPart::Json(&bundle.public_record())]);
        self.spent_nullifiers.insert(privacy_nullifier.to_string());
        self.bundles.insert(bundle_id.clone(), bundle);
        self.counters.bundles = sequence;
        self.emit_public_record("bundle_submitted", &bundle_id, &public_root)?;
        Ok(bundle_id)
    }

    pub fn register_provider(
        &mut self,
        operator_commitment: &str,
        pq_attestation_root: &str,
        stake_commitment: &str,
        supported_modes: impl IntoIterator<Item = CompressionMode>,
        max_bundle_bytes: u64,
        min_fee_piconero: u128,
    ) -> Result<String> {
        ensure_capacity(self.providers.len(), self.config.max_providers, "providers")?;
        let sequence = self.counters.providers.saturating_add(1);
        let provider = CompressionProvider::new(
            sequence,
            operator_commitment,
            pq_attestation_root,
            stake_commitment,
            supported_modes,
            max_bundle_bytes,
            min_fee_piconero,
            self.height,
            &self.config,
        )?;
        let provider_id = provider.provider_id.clone();
        let public_root = module_hash(
            "PROVIDER-PUBLIC",
            &[HashPart::Json(&provider.public_record())],
        );
        self.providers.insert(provider_id.clone(), provider);
        self.counters.providers = sequence;
        self.emit_public_record("provider_registered", &provider_id, &public_root)?;
        Ok(provider_id)
    }

    pub fn post_quote(
        &mut self,
        bundle_id: &str,
        provider_id: &str,
        mode: CompressionMode,
        quoted_fee_piconero: u128,
        expected_compressed_bytes: u64,
    ) -> Result<String> {
        ensure_capacity(self.quotes.len(), self.config.max_quotes, "quotes")?;
        let bundle = self
            .bundles
            .get(bundle_id)
            .ok_or_else(|| "unknown bundle_id".to_string())?;
        let provider = self
            .providers
            .get(provider_id)
            .ok_or_else(|| "unknown provider_id".to_string())?;
        if !provider.status.accepts_work() {
            return Err("provider is not accepting work".to_string());
        }
        if !provider.supported_modes.contains(&mode) {
            return Err("provider does not support quote mode".to_string());
        }
        if quoted_fee_piconero > bundle.fee_cap_piconero {
            return Err("quoted fee exceeds bundle fee cap".to_string());
        }
        let sequence = self.counters.quotes.saturating_add(1);
        let expected_rebate_piconero =
            quoted_fee_piconero.saturating_mul(self.config.target_rebate_bps as u128) / 100;
        let quote_id = module_hash(
            "QUOTE-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(bundle_id),
                HashPart::Str(provider_id),
                HashPart::Str(mode.as_str()),
            ],
        );
        let quote = FeeQuote {
            quote_id: quote_id.clone(),
            bundle_id: bundle_id.to_string(),
            provider_id: provider_id.to_string(),
            mode,
            status: QuoteStatus::Posted,
            quoted_fee_piconero,
            expected_rebate_piconero,
            expected_compressed_bytes,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.quote_ttl_blocks),
        };
        let public_root = module_hash("QUOTE-PUBLIC", &[HashPart::Json(&quote.public_record())]);
        self.quotes.insert(quote_id.clone(), quote);
        self.counters.quotes = sequence;
        self.emit_public_record("quote_posted", &quote_id, &public_root)?;
        Ok(quote_id)
    }

    pub fn reserve_lane(&mut self, quote_id: &str) -> Result<String> {
        ensure_capacity(
            self.reserved_lanes.len(),
            self.config.max_reserved_lanes,
            "reserved lanes",
        )?;
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| "unknown quote_id".to_string())?;
        quote.status = QuoteStatus::Selected;
        let bundle = self
            .bundles
            .get_mut(&quote.bundle_id)
            .ok_or_else(|| "unknown quote bundle_id".to_string())?;
        bundle.status = BundleStatus::Reserved;
        let sequence = self.counters.reserved_lanes.saturating_add(1);
        let lane_id = module_hash(
            "RESERVED-LANE-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(quote_id),
                HashPart::Str(&quote.bundle_id),
                HashPart::Str(&quote.provider_id),
            ],
        );
        let lane = ReservedProofLane {
            lane_id: lane_id.clone(),
            bundle_id: quote.bundle_id.clone(),
            quote_id: quote_id.to_string(),
            provider_id: quote.provider_id.clone(),
            status: LaneStatus::Reserved,
            priority_weight: bundle.kind.priority_weight(),
            reserved_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.reserved_lane_ttl_blocks),
        };
        let public_root = module_hash("LANE-PUBLIC", &[HashPart::Json(&lane.public_record())]);
        self.reserved_lanes.insert(lane_id.clone(), lane);
        self.counters.reserved_lanes = sequence;
        self.emit_public_record("lane_reserved", &lane_id, &public_root)?;
        Ok(lane_id)
    }

    pub fn record_receipt(
        &mut self,
        bundle_id: &str,
        provider_id: &str,
        compressed_proof_root: &str,
        verifier_committee_root: &str,
        verdict: ReceiptVerdict,
        compressed_bytes: u64,
        fee_paid_piconero: u128,
    ) -> Result<String> {
        ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        ensure_non_empty(compressed_proof_root, "compressed proof root")?;
        ensure_non_empty(verifier_committee_root, "verifier committee root")?;
        let bundle = self
            .bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "unknown bundle_id".to_string())?;
        if !self.providers.contains_key(provider_id) {
            return Err("unknown provider_id".to_string());
        }
        bundle.status = match verdict {
            ReceiptVerdict::Accepted | ReceiptVerdict::AcceptedWithRedactions => {
                BundleStatus::Verified
            }
            ReceiptVerdict::NeedsRecompression => BundleStatus::Compressed,
            ReceiptVerdict::Rejected => BundleStatus::Quarantined,
        };
        let sequence = self.counters.receipts.saturating_add(1);
        let receipt_id = module_hash(
            "RECEIPT-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(bundle_id),
                HashPart::Str(provider_id),
                HashPart::Str(compressed_proof_root),
            ],
        );
        let receipt = VerifierReceipt {
            receipt_id: receipt_id.clone(),
            bundle_id: bundle_id.to_string(),
            provider_id: provider_id.to_string(),
            compressed_proof_root: compressed_proof_root.to_string(),
            verifier_committee_root: verifier_committee_root.to_string(),
            verdict,
            compressed_bytes,
            fee_paid_piconero,
            verified_height: self.height,
            expires_height: self.height.saturating_add(self.config.receipt_ttl_blocks),
        };
        let public_root = module_hash(
            "RECEIPT-PUBLIC",
            &[HashPart::Json(&receipt.public_record())],
        );
        self.receipts.insert(receipt_id.clone(), receipt);
        self.counters.receipts = sequence;
        self.counters.verified_bundles = self.counters.verified_bundles.saturating_add(1);
        self.counters.total_fee_piconero = self
            .counters
            .total_fee_piconero
            .saturating_add(fee_paid_piconero);
        self.emit_public_record("receipt_recorded", &receipt_id, &public_root)?;
        Ok(receipt_id)
    }

    pub fn settle_rebate(
        &mut self,
        bundle_id: &str,
        receipt_id: &str,
        claimant_commitment: &str,
        amount_piconero: u128,
    ) -> Result<String> {
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        ensure_non_empty(claimant_commitment, "claimant commitment")?;
        if !self.receipts.contains_key(receipt_id) {
            return Err("unknown receipt_id".to_string());
        }
        let sequence = self.counters.rebates.saturating_add(1);
        let rebate_id = module_hash(
            "REBATE-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(bundle_id),
                HashPart::Str(receipt_id),
                HashPart::Str(claimant_commitment),
            ],
        );
        let rebate = RebateClaim {
            rebate_id: rebate_id.clone(),
            bundle_id: bundle_id.to_string(),
            receipt_id: receipt_id.to_string(),
            claimant_commitment: claimant_commitment.to_string(),
            amount_piconero,
            settled_height: self.height,
        };
        let public_root = module_hash("REBATE-PUBLIC", &[HashPart::Json(&rebate.public_record())]);
        if let Some(bundle) = self.bundles.get_mut(bundle_id) {
            bundle.status = BundleStatus::Rebated;
        }
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates = sequence;
        self.counters.total_rebate_piconero = self
            .counters
            .total_rebate_piconero
            .saturating_add(amount_piconero);
        self.emit_public_record("rebate_settled", &rebate_id, &public_root)?;
        Ok(rebate_id)
    }

    pub fn quarantine(
        &mut self,
        bundle_id: &str,
        provider_id: &str,
        reason: QuarantineReason,
        evidence_root: &str,
        slash_amount_piconero: u128,
    ) -> Result<String> {
        ensure_capacity(
            self.quarantines.len(),
            self.config.max_quarantines,
            "quarantines",
        )?;
        ensure_non_empty(evidence_root, "evidence root")?;
        let sequence = self.counters.quarantines.saturating_add(1);
        let quarantine_id = module_hash(
            "QUARANTINE-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(bundle_id),
                HashPart::Str(provider_id),
                HashPart::Str(reason.as_str()),
                HashPart::Str(evidence_root),
            ],
        );
        let case = QuarantineCase {
            quarantine_id: quarantine_id.clone(),
            bundle_id: bundle_id.to_string(),
            provider_id: provider_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            slash_amount_piconero,
            opened_height: self.height,
        };
        let public_root = module_hash(
            "QUARANTINE-PUBLIC",
            &[HashPart::Json(&case.public_record())],
        );
        if let Some(bundle) = self.bundles.get_mut(bundle_id) {
            bundle.status = BundleStatus::Quarantined;
        }
        if let Some(provider) = self.providers.get_mut(provider_id) {
            provider.status = ProviderStatus::Quarantined;
        }
        self.quarantines.insert(quarantine_id.clone(), case);
        self.counters.quarantines = sequence;
        self.counters.slashed_providers = self.counters.slashed_providers.saturating_add(1);
        self.emit_public_record("quarantine_opened", &quarantine_id, &public_root)?;
        Ok(quarantine_id)
    }

    pub fn open_redaction_budget(
        &mut self,
        owner_commitment: &str,
        epoch: u64,
        allowed_redactions: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction budgets",
        )?;
        ensure_non_empty(owner_commitment, "owner commitment")?;
        let sequence = self.counters.redaction_budgets.saturating_add(1);
        let budget_root = module_hash(
            "REDACTION-BUDGET-ROOT",
            &[
                HashPart::U64(epoch),
                HashPart::U64(allowed_redactions),
                HashPart::Str(owner_commitment),
            ],
        );
        let budget_id = module_hash(
            "REDACTION-BUDGET-ID",
            &[HashPart::U64(sequence), HashPart::Str(&budget_root)],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            owner_commitment: owner_commitment.to_string(),
            epoch,
            allowed_redactions,
            consumed_redactions: 0,
            budget_root,
        };
        let public_root = module_hash(
            "REDACTION-PUBLIC",
            &[HashPart::Json(&budget.public_record())],
        );
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets = sequence;
        self.emit_public_record("redaction_budget_opened", &budget_id, &public_root)?;
        Ok(budget_id)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: module_hash("CONFIG", &[HashPart::Json(&self.config.public_record())]),
            counters_root: module_hash(
                "COUNTERS",
                &[HashPart::Json(&self.counters.public_record())],
            ),
            bundle_root: map_root(
                "BUNDLES",
                self.bundles.values().map(ProofBundle::public_record),
            ),
            provider_root: map_root(
                "PROVIDERS",
                self.providers
                    .values()
                    .map(CompressionProvider::public_record),
            ),
            quote_root: map_root("QUOTES", self.quotes.values().map(FeeQuote::public_record)),
            reserved_lane_root: map_root(
                "RESERVED-LANES",
                self.reserved_lanes
                    .values()
                    .map(ReservedProofLane::public_record),
            ),
            receipt_root: map_root(
                "RECEIPTS",
                self.receipts.values().map(VerifierReceipt::public_record),
            ),
            rebate_root: map_root(
                "REBATES",
                self.rebates.values().map(RebateClaim::public_record),
            ),
            quarantine_root: map_root(
                "QUARANTINES",
                self.quarantines.values().map(QuarantineCase::public_record),
            ),
            redaction_budget_root: map_root(
                "REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            nullifier_root: merkle_root(
                "LATTICE-PROOF-COMPRESSION-NULLIFIERS",
                self.spent_nullifiers
                    .iter()
                    .map(|nullifier| module_hash("NULLIFIER", &[HashPart::Str(nullifier)])),
            ),
            public_record_root: map_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(PublicMarketRecord::public_record),
            ),
            state_root: String::new(),
        };
        roots.state_root = module_hash(
            "STATE",
            &[
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.counters_root),
                HashPart::Str(&roots.bundle_root),
                HashPart::Str(&roots.provider_root),
                HashPart::Str(&roots.quote_root),
                HashPart::Str(&roots.reserved_lane_root),
                HashPart::Str(&roots.receipt_root),
                HashPart::Str(&roots.rebate_root),
                HashPart::Str(&roots.quarantine_root),
                HashPart::Str(&roots.redaction_budget_root),
                HashPart::Str(&roots.nullifier_root),
                HashPart::Str(&roots.public_record_root),
            ],
        );
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_lattice_proof_compression_market_runtime",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "bundles": records(self.bundles.values().map(ProofBundle::public_record)),
            "providers": records(self.providers.values().map(CompressionProvider::public_record)),
            "quotes": records(self.quotes.values().map(FeeQuote::public_record)),
            "reserved_lanes": records(self.reserved_lanes.values().map(ReservedProofLane::public_record)),
            "receipts": records(self.receipts.values().map(VerifierReceipt::public_record)),
            "rebates": records(self.rebates.values().map(RebateClaim::public_record)),
            "quarantines": records(self.quarantines.values().map(QuarantineCase::public_record)),
            "redaction_budgets": records(self.redaction_budgets.values().map(RedactionBudget::public_record)),
            "public_records": records(self.public_records.values().map(PublicMarketRecord::public_record)),
            "spent_nullifier_count": self.spent_nullifiers.len(),
            "state_root": self.state_root(),
        })
    }

    fn emit_public_record(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        public_root: &str,
    ) -> Result<()> {
        ensure_capacity(
            self.public_records.len(),
            self.config.max_public_records,
            "public records",
        )?;
        let sequence = self.counters.public_records.saturating_add(1);
        let record_id = module_hash(
            "PUBLIC-RECORD-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Str(public_root),
            ],
        );
        let record = PublicMarketRecord {
            record_id: record_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            public_root: public_root.to_string(),
            height: self.height,
            sequence,
        };
        self.public_records.insert(record_id, record);
        self.counters.public_records = sequence;
        Ok(())
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

fn module_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-PROOF-COMPRESSION-MARKET-{domain}"),
        parts,
        32,
    )
}

fn map_root(domain: &str, values: impl Iterator<Item = Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-PROOF-COMPRESSION-MARKET-{domain}"),
        values.map(|value| module_hash("LEAF", &[HashPart::Json(&value)])),
    )
}

fn records(values: impl Iterator<Item = Value>) -> Vec<Value> {
    values.collect()
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(current_len: usize, max_len: usize, label: &str) -> Result<()> {
    if current_len >= max_len {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}
