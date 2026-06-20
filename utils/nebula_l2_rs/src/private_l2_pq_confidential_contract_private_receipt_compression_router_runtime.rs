use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateReceiptCompressionRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_RECEIPT_COMPRESSION_ROUTER_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-pq-confidential-contract-private-receipt-compression-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_RECEIPT_COMPRESSION_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ROUTER_ID: &str =
    "private-l2-pq-confidential-contract-private-receipt-compression-router-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REWARD_ASSET_ID: &str = "receipt-compression-credit-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROUTE_SCHEME: &str = "confidential-contract-private-receipt-compression-route-root-v1";
pub const ENCRYPTED_BUNDLE_SCHEME: &str =
    "ml-kem-1024-sealed-confidential-contract-private-receipt-bundle-root-v1";
pub const COMPRESSOR_COMMITMENT_SCHEME: &str =
    "private-receipt-compressor-capacity-commitment-root-v1";
pub const PQ_COMPRESSOR_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-private-receipt-compressor-attestation-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "view-key-safe-confidential-contract-private-receipt-redaction-budget-root-v1";
pub const LOW_FEE_REWARD_SCHEME: &str =
    "low-fee-private-receipt-compression-reward-accounting-root-v1";
pub const NAMESPACE_RENT_CREDIT_SCHEME: &str =
    "confidential-contract-namespace-rent-credit-netting-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "operator-safe-private-receipt-compression-router-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str = "roots_only_no_plaintext_contract_args_receipt_payloads_addresses_view_keys_amounts_or_decryption_shares";
pub const REPLAY_DOMAIN: &str =
    "private-l2-pq-confidential-contract-private-receipt-compression-router-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_BUNDLE_RECEIPTS: u64 = 8;
pub const DEFAULT_TARGET_BUNDLE_RECEIPTS: u64 = 128;
pub const DEFAULT_MAX_BUNDLE_RECEIPTS: u64 = 1_024;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REWARD_SETTLEMENT_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRICT_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 5;
pub const DEFAULT_STANDARD_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_FAST_LANE_FEE_CAP_BPS: u64 = 18;
pub const DEFAULT_REWARD_BPS: u64 = 4;
pub const DEFAULT_RENT_CREDIT_BPS: u64 = 2_500;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH: u64 = 8_192;
pub const DEFAULT_OPERATOR_BUCKET_SIZE: u64 = 64;
pub const MAX_ROUTES: usize = 2_097_152;
pub const MAX_BUNDLES: usize = 4_194_304;
pub const MAX_COMPRESSOR_COMMITMENTS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_REWARDS: usize = 4_194_304;
pub const MAX_RENT_CREDITS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_EVENTS: usize = 8_388_608;

macro_rules! snake_enum {
    ($name:ident { $($variant:ident => $text:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name { pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $text),+ } } }
    };
}

snake_enum!(ContractRuntimeKind { ConfidentialEvm => "confidential_evm", NoirCircuit => "noir_circuit", CairoPrivateVm => "cairo_private_vm", WasmPrivateVm => "wasm_private_vm", ShieldedHook => "shielded_hook", SettlementAdapter => "settlement_adapter" });
snake_enum!(ReceiptClass { ContractCall => "contract_call", ContractDeploy => "contract_deploy", EventLog => "event_log", StateDelta => "state_delta", FeeDebit => "fee_debit", RentCredit => "rent_credit", RevertTrace => "revert_trace", ComplianceDisclosure => "compliance_disclosure" });
snake_enum!(CompressionCodec { ZstdDictionary => "zstd_dictionary", BrotliDictionary => "brotli_dictionary", RiscZeroRecursive => "risc_zero_recursive", Halo2Recursive => "halo2_recursive", Plonky2Recursive => "plonky2_recursive", VerkleDelta => "verkle_delta", PoseidonTranscript => "poseidon_transcript" });
impl CompressionCodec {
    pub fn compression_weight(self) -> u64 {
        match self {
            Self::ZstdDictionary => 620,
            Self::BrotliDictionary => 650,
            Self::RiscZeroRecursive => 900,
            Self::Halo2Recursive => 880,
            Self::Plonky2Recursive => 860,
            Self::VerkleDelta => 760,
            Self::PoseidonTranscript => 820,
        }
    }
}
snake_enum!(RouteLane { LowFee => "low_fee", Standard => "standard", FastContract => "fast_contract", BulkArchive => "bulk_archive", NamespaceRent => "namespace_rent", EmergencyDisclosure => "emergency_disclosure" });
impl RouteLane {
    pub fn fee_cap_bps(self, c: &Config) -> u64 {
        match self {
            Self::LowFee | Self::BulkArchive | Self::NamespaceRent => c.low_fee_cap_bps,
            Self::Standard => c.standard_fee_cap_bps,
            Self::FastContract | Self::EmergencyDisclosure => c.fast_lane_fee_cap_bps,
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyDisclosure => 1000,
            Self::FastContract => 920,
            Self::NamespaceRent => 840,
            Self::Standard => 760,
            Self::LowFee => 700,
            Self::BulkArchive => 640,
        }
    }
}
snake_enum!(RouteStatus { Drafted => "drafted", Active => "active", CapacityBound => "capacity_bound", BundleQueued => "bundle_queued", Compressing => "compressing", Attesting => "attesting", Settling => "settling", Settled => "settled", Expired => "expired", Revoked => "revoked", Slashed => "slashed" });
impl RouteStatus {
    pub fn accepts_bundles(self) -> bool {
        matches!(
            self,
            Self::Active | Self::CapacityBound | Self::BundleQueued
        )
    }
    pub fn operator_visible(self) -> bool {
        matches!(
            self,
            Self::CapacityBound
                | Self::BundleQueued
                | Self::Compressing
                | Self::Attesting
                | Self::Settling
                | Self::Settled
        )
    }
}
snake_enum!(BundleStatus { Sealed => "sealed", PrivacyChecked => "privacy_checked", Routed => "routed", CompressorAssigned => "compressor_assigned", Compressed => "compressed", Attested => "attested", RewardQueued => "reward_queued", Settled => "settled", RedactionHeld => "redaction_held", Rejected => "rejected", Expired => "expired" });
impl BundleStatus {
    pub fn rewardable(self) -> bool {
        matches!(
            self,
            Self::Compressed | Self::Attested | Self::RewardQueued | Self::Settled
        )
    }
}
snake_enum!(CommitmentStatus { Posted => "posted", Bonded => "bonded", CapacityOpen => "capacity_open", CapacityReserved => "capacity_reserved", Exhausted => "exhausted", Suspended => "suspended", Slashed => "slashed", Revoked => "revoked" });
impl CommitmentStatus {
    pub fn reservable(self) -> bool {
        matches!(
            self,
            Self::Bonded | Self::CapacityOpen | Self::CapacityReserved
        )
    }
}
snake_enum!(AttestationStatus { Submitted => "submitted", Accepted => "accepted", Quorum => "quorum", StrictQuorum => "strict_quorum", Expired => "expired", Revoked => "revoked", Rejected => "rejected", Slashed => "slashed" });
impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrictQuorum)
    }
}
snake_enum!(RedactionBudgetStatus { Open => "open", Reserved => "reserved", Applied => "applied", Exhausted => "exhausted", Revoked => "revoked" });
snake_enum!(RewardStatus { Metered => "metered", Eligible => "eligible", Queued => "queued", Paid => "paid", ClawedBack => "clawed_back", Rejected => "rejected" });
snake_enum!(RentCreditStatus { Accruing => "accruing", OffsetPending => "offset_pending", OffsetApplied => "offset_applied", Exhausted => "exhausted", Revoked => "revoked" });
snake_enum!(SummaryAudience { Operator => "operator", ContractOwner => "contract_owner", Compressor => "compressor", Watchtower => "watchtower", Sponsor => "sponsor", Public => "public" });
snake_enum!(RuntimeEventKind { RouteOpened => "route_opened", BundleSealed => "bundle_sealed", CommitmentPosted => "commitment_posted", CompressorAssigned => "compressor_assigned", BundleCompressed => "bundle_compressed", AttestationAccepted => "attestation_accepted", RedactionBudgetApplied => "redaction_budget_applied", RewardSettled => "reward_settled", RentCreditApplied => "rent_credit_applied", SummaryPublished => "summary_published" });

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub router_id: String,
    pub fee_asset_id: String,
    pub reward_asset_id: String,
    pub hash_suite: String,
    pub route_scheme: String,
    pub encrypted_bundle_scheme: String,
    pub compressor_commitment_scheme: String,
    pub pq_compressor_attestation_scheme: String,
    pub redaction_budget_scheme: String,
    pub low_fee_reward_scheme: String,
    pub namespace_rent_credit_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub replay_domain: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_bundle_receipts: u64,
    pub target_bundle_receipts: u64,
    pub max_bundle_receipts: u64,
    pub route_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub reward_settlement_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub quorum_bps: u64,
    pub strict_quorum_bps: u64,
    pub low_fee_cap_bps: u64,
    pub standard_fee_cap_bps: u64,
    pub fast_lane_fee_cap_bps: u64,
    pub reward_bps: u64,
    pub rent_credit_bps: u64,
    pub max_redaction_units_per_epoch: u64,
    pub operator_bucket_size: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            reward_asset_id: DEVNET_REWARD_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            route_scheme: ROUTE_SCHEME.to_string(),
            encrypted_bundle_scheme: ENCRYPTED_BUNDLE_SCHEME.to_string(),
            compressor_commitment_scheme: COMPRESSOR_COMMITMENT_SCHEME.to_string(),
            pq_compressor_attestation_scheme: PQ_COMPRESSOR_ATTESTATION_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            low_fee_reward_scheme: LOW_FEE_REWARD_SCHEME.to_string(),
            namespace_rent_credit_scheme: NAMESPACE_RENT_CREDIT_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_bundle_receipts: DEFAULT_MIN_BUNDLE_RECEIPTS,
            target_bundle_receipts: DEFAULT_TARGET_BUNDLE_RECEIPTS,
            max_bundle_receipts: DEFAULT_MAX_BUNDLE_RECEIPTS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            reward_settlement_ttl_blocks: DEFAULT_REWARD_SETTLEMENT_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strict_quorum_bps: DEFAULT_STRICT_QUORUM_BPS,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            standard_fee_cap_bps: DEFAULT_STANDARD_FEE_CAP_BPS,
            fast_lane_fee_cap_bps: DEFAULT_FAST_LANE_FEE_CAP_BPS,
            reward_bps: DEFAULT_REWARD_BPS,
            rent_credit_bps: DEFAULT_RENT_CREDIT_BPS,
            max_redaction_units_per_epoch: DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH,
            operator_bucket_size: DEFAULT_OPERATOR_BUCKET_SIZE,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(
                "unsupported private receipt compression router protocol version".to_string(),
            );
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(
                "unsupported private receipt compression router schema version".to_string(),
            );
        }
        if self.chain_id.trim().is_empty() || self.router_id.trim().is_empty() {
            return Err("chain id and router id are required".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_privacy_set_size > self.target_privacy_set_size
        {
            return Err("privacy set bounds are invalid".to_string());
        }
        if self.min_bundle_receipts == 0
            || self.min_bundle_receipts > self.target_bundle_receipts
            || self.target_bundle_receipts > self.max_bundle_receipts
        {
            return Err("bundle receipt bounds are invalid".to_string());
        }
        if self.quorum_bps > MAX_BPS
            || self.strict_quorum_bps > MAX_BPS
            || self.quorum_bps > self.strict_quorum_bps
        {
            return Err("attestation quorum bps are invalid".to_string());
        }
        if self.low_fee_cap_bps > self.standard_fee_cap_bps
            || self.standard_fee_cap_bps > self.fast_lane_fee_cap_bps
            || self.fast_lane_fee_cap_bps > MAX_BPS
        {
            return Err("fee cap bps are invalid".to_string());
        }
        if self.reward_bps > MAX_BPS || self.rent_credit_bps > MAX_BPS {
            return Err("reward or rent credit bps exceed max".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security bits must be at least 192".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol_version": self.protocol_version, "schema_version": self.schema_version, "chain_id": self.chain_id, "l2_network": self.l2_network, "monero_network": self.monero_network, "router_id": self.router_id, "fee_asset_id": self.fee_asset_id, "reward_asset_id": self.reward_asset_id, "hash_suite": self.hash_suite, "route_scheme": self.route_scheme, "encrypted_bundle_scheme": self.encrypted_bundle_scheme, "compressor_commitment_scheme": self.compressor_commitment_scheme, "pq_compressor_attestation_scheme": self.pq_compressor_attestation_scheme, "redaction_budget_scheme": self.redaction_budget_scheme, "low_fee_reward_scheme": self.low_fee_reward_scheme, "namespace_rent_credit_scheme": self.namespace_rent_credit_scheme, "operator_summary_scheme": self.operator_summary_scheme, "privacy_boundary": self.privacy_boundary, "replay_domain": self.replay_domain, "min_privacy_set_size": self.min_privacy_set_size, "target_privacy_set_size": self.target_privacy_set_size, "min_bundle_receipts": self.min_bundle_receipts, "target_bundle_receipts": self.target_bundle_receipts, "max_bundle_receipts": self.max_bundle_receipts, "route_ttl_blocks": self.route_ttl_blocks, "bundle_ttl_blocks": self.bundle_ttl_blocks, "attestation_ttl_blocks": self.attestation_ttl_blocks, "redaction_epoch_blocks": self.redaction_epoch_blocks, "reward_settlement_ttl_blocks": self.reward_settlement_ttl_blocks, "min_pq_security_bits": self.min_pq_security_bits, "quorum_bps": self.quorum_bps, "strict_quorum_bps": self.strict_quorum_bps, "low_fee_cap_bps": self.low_fee_cap_bps, "standard_fee_cap_bps": self.standard_fee_cap_bps, "fast_lane_fee_cap_bps": self.fast_lane_fee_cap_bps, "reward_bps": self.reward_bps, "rent_credit_bps": self.rent_credit_bps, "max_redaction_units_per_epoch": self.max_redaction_units_per_epoch, "operator_bucket_size": self.operator_bucket_size })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub routes: u64,
    pub encrypted_bundles: u64,
    pub compressor_commitments: u64,
    pub pq_compressor_attestations: u64,
    pub redaction_budgets: u64,
    pub low_fee_rewards: u64,
    pub namespace_rent_credits: u64,
    pub operator_summaries: u64,
    pub events: u64,
    pub total_receipts_routed: u64,
    pub total_receipts_compressed: u64,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
    pub total_fee_units: u64,
    pub total_reward_units: u64,
    pub total_rent_credit_units: u64,
    pub total_redaction_units_reserved: u64,
    pub total_redaction_units_used: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "routes": self.routes, "encrypted_bundles": self.encrypted_bundles, "compressor_commitments": self.compressor_commitments, "pq_compressor_attestations": self.pq_compressor_attestations, "redaction_budgets": self.redaction_budgets, "low_fee_rewards": self.low_fee_rewards, "namespace_rent_credits": self.namespace_rent_credits, "operator_summaries": self.operator_summaries, "events": self.events, "total_receipts_routed": self.total_receipts_routed, "total_receipts_compressed": self.total_receipts_compressed, "total_original_bytes": self.total_original_bytes, "total_compressed_bytes": self.total_compressed_bytes, "total_fee_units": self.total_fee_units, "total_reward_units": self.total_reward_units, "total_rent_credit_units": self.total_rent_credit_units, "total_redaction_units_reserved": self.total_redaction_units_reserved, "total_redaction_units_used": self.total_redaction_units_used })
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub route_root: String,
    pub encrypted_bundle_root: String,
    pub compressor_commitment_root: String,
    pub pq_compressor_attestation_root: String,
    pub redaction_budget_root: String,
    pub low_fee_reward_root: String,
    pub namespace_rent_credit_root: String,
    pub operator_summary_root: String,
    pub event_root: String,
    pub counters_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "config_root": self.config_root, "route_root": self.route_root, "encrypted_bundle_root": self.encrypted_bundle_root, "compressor_commitment_root": self.compressor_commitment_root, "pq_compressor_attestation_root": self.pq_compressor_attestation_root, "redaction_budget_root": self.redaction_budget_root, "low_fee_reward_root": self.low_fee_reward_root, "namespace_rent_credit_root": self.namespace_rent_credit_root, "operator_summary_root": self.operator_summary_root, "event_root": self.event_root, "counters_root": self.counters_root })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateReceiptCompressionRoute {
    pub route_id: String,
    pub contract_namespace: String,
    pub contract_commitment: String,
    pub contract_runtime: ContractRuntimeKind,
    pub receipt_class: ReceiptClass,
    pub lane: RouteLane,
    pub status: RouteStatus,
    pub codec: CompressionCodec,
    pub owner_commitment: String,
    pub compressor_pool_id: String,
    pub privacy_set_size: u64,
    pub min_bundle_receipts: u64,
    pub max_bundle_receipts: u64,
    pub fee_cap_bps: u64,
    pub reward_bps: u64,
    pub rent_credit_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub redaction_policy_root: String,
    pub namespace_rent_root: String,
    pub replay_domain: String,
    pub metadata_commitment: String,
}
impl PrivateReceiptCompressionRoute {
    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.accepts_bundles() && height <= self.expires_height
    }
    pub fn privacy_weight(&self) -> u64 {
        self.privacy_set_size
            .saturating_mul(self.codec.compression_weight())
            .saturating_div(1_000)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "contract_namespace": self.contract_namespace,
            "contract_commitment": self.contract_commitment,
            "contract_runtime": self.contract_runtime,
            "receipt_class": self.receipt_class,
            "lane": self.lane,
            "status": self.status,
            "codec": self.codec,
            "owner_commitment": self.owner_commitment,
            "compressor_pool_id": self.compressor_pool_id,
            "privacy_set_size": self.privacy_set_size,
            "min_bundle_receipts": self.min_bundle_receipts,
            "max_bundle_receipts": self.max_bundle_receipts,
            "fee_cap_bps": self.fee_cap_bps,
            "reward_bps": self.reward_bps,
            "rent_credit_bps": self.rent_credit_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "redaction_policy_root": self.redaction_policy_root,
            "namespace_rent_root": self.namespace_rent_root,
            "replay_domain": self.replay_domain,
            "metadata_commitment": self.metadata_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptBundle {
    pub bundle_id: String,
    pub route_id: String,
    pub contract_namespace: String,
    pub status: BundleStatus,
    pub codec: CompressionCodec,
    pub receipt_count: u64,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub fee_units: u64,
    pub privacy_set_size: u64,
    pub encrypted_payload_root: String,
    pub receipt_commitment_root: String,
    pub nullifier_root: String,
    pub view_tag_bucket_root: String,
    pub sender_bucket: String,
    pub compressor_id: String,
    pub pq_ciphertext_commitment: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub compressed_height: Option<u64>,
    pub redaction_budget_id: Option<String>,
    pub attestation_ids: BTreeSet<String>,
}
impl EncryptedReceiptBundle {
    pub fn compression_ratio_bps(&self) -> u64 {
        if self.original_bytes == 0 {
            0
        } else {
            self.compressed_bytes
                .saturating_mul(MAX_BPS)
                .saturating_div(self.original_bytes)
        }
    }
    pub fn saved_bytes(&self) -> u64 {
        self.original_bytes.saturating_sub(self.compressed_bytes)
    }
    pub fn low_fee_score(&self) -> u64 {
        self.saved_bytes()
            .saturating_mul(self.receipt_count.max(1))
            .saturating_div(self.fee_units.max(1))
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_height
    }
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "route_id": self.route_id,
            "contract_namespace": self.contract_namespace,
            "status": self.status,
            "codec": self.codec,
            "receipt_count": self.receipt_count,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "fee_units": self.fee_units,
            "privacy_set_size": self.privacy_set_size,
            "encrypted_payload_root": self.encrypted_payload_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "nullifier_root": self.nullifier_root,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "sender_bucket": self.sender_bucket,
            "compressor_id": self.compressor_id,
            "pq_ciphertext_commitment": self.pq_ciphertext_commitment,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "compressed_height": self.compressed_height,
            "redaction_budget_id": self.redaction_budget_id,
            "attestation_ids": self.attestation_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressorCommitment {
    pub commitment_id: String,
    pub compressor_id: String,
    pub operator_id: String,
    pub pool_id: String,
    pub status: CommitmentStatus,
    pub supported_codecs: BTreeSet<CompressionCodec>,
    pub max_bundle_receipts: u64,
    pub available_receipt_capacity: u64,
    pub bonded_fee_units: u64,
    pub min_reward_bps: u64,
    pub pq_identity_root: String,
    pub capacity_commitment_root: String,
    pub slashing_key_commitment: String,
    pub posted_height: u64,
    pub expires_height: u64,
}
impl CompressorCommitment {
    pub fn supports(&self, codec: CompressionCodec) -> bool {
        self.supported_codecs.contains(&codec)
    }
    pub fn can_accept(&self, codec: CompressionCodec, receipt_count: u64, height: u64) -> bool {
        self.status.reservable()
            && self.supports(codec)
            && self.available_receipt_capacity >= receipt_count
            && receipt_count <= self.max_bundle_receipts
            && height <= self.expires_height
    }
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "compressor_id": self.compressor_id,
            "operator_id": self.operator_id,
            "pool_id": self.pool_id,
            "status": self.status,
            "supported_codecs": self.supported_codecs,
            "max_bundle_receipts": self.max_bundle_receipts,
            "available_receipt_capacity": self.available_receipt_capacity,
            "bonded_fee_units": self.bonded_fee_units,
            "min_reward_bps": self.min_reward_bps,
            "pq_identity_root": self.pq_identity_root,
            "capacity_commitment_root": self.capacity_commitment_root,
            "slashing_key_commitment": self.slashing_key_commitment,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCompressorAttestation {
    pub attestation_id: String,
    pub bundle_id: String,
    pub compressor_id: String,
    pub committee_id: String,
    pub status: AttestationStatus,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub compressed_receipt_root: String,
    pub decompression_witness_root: String,
    pub transcript_root: String,
    pub signer_bitmap_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}
impl PqCompressorAttestation {
    pub fn strict(&self, config: &Config) -> bool {
        self.status.counts_for_quorum()
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.quorum_weight_bps >= config.strict_quorum_bps
    }
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bundle_id": self.bundle_id,
            "compressor_id": self.compressor_id,
            "committee_id": self.committee_id,
            "status": self.status,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "compressed_receipt_root": self.compressed_receipt_root,
            "decompression_witness_root": self.decompression_witness_root,
            "transcript_root": self.transcript_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub route_id: String,
    pub owner_bucket: String,
    pub epoch: u64,
    pub status: RedactionBudgetStatus,
    pub reserved_units: u64,
    pub used_units: u64,
    pub redaction_policy_root: String,
    pub selective_disclosure_root: String,
    pub view_key_safety_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}
impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.reserved_units.saturating_sub(self.used_units)
    }
    pub fn can_spend(&self, units: u64, height: u64) -> bool {
        matches!(
            self.status,
            RedactionBudgetStatus::Open | RedactionBudgetStatus::Reserved
        ) && self.remaining_units() >= units
            && height <= self.expires_height
    }
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "route_id": self.route_id,
            "owner_bucket": self.owner_bucket,
            "epoch": self.epoch,
            "status": self.status,
            "reserved_units": self.reserved_units,
            "used_units": self.used_units,
            "redaction_policy_root": self.redaction_policy_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "view_key_safety_root": self.view_key_safety_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCompressionReward {
    pub reward_id: String,
    pub bundle_id: String,
    pub route_id: String,
    pub compressor_id: String,
    pub sponsor_id: String,
    pub status: RewardStatus,
    pub reward_asset_id: String,
    pub saved_bytes: u64,
    pub receipt_count: u64,
    pub fee_units_paid: u64,
    pub reward_units: u64,
    pub reward_bps: u64,
    pub low_fee_score: u64,
    pub settlement_root: String,
    pub metered_height: u64,
    pub payable_height: u64,
}
impl LowFeeCompressionReward {
    pub fn effective_reward_per_receipt(&self) -> u64 {
        self.reward_units.saturating_div(self.receipt_count.max(1))
    }
    pub fn public_record(&self) -> Value {
        json!({
            "reward_id": self.reward_id,
            "bundle_id": self.bundle_id,
            "route_id": self.route_id,
            "compressor_id": self.compressor_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "reward_asset_id": self.reward_asset_id,
            "saved_bytes": self.saved_bytes,
            "receipt_count": self.receipt_count,
            "fee_units_paid": self.fee_units_paid,
            "reward_units": self.reward_units,
            "reward_bps": self.reward_bps,
            "low_fee_score": self.low_fee_score,
            "settlement_root": self.settlement_root,
            "metered_height": self.metered_height,
            "payable_height": self.payable_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceRentCredit {
    pub credit_id: String,
    pub contract_namespace: String,
    pub route_id: String,
    pub owner_commitment: String,
    pub status: RentCreditStatus,
    pub credit_units: u64,
    pub applied_units: u64,
    pub rent_epoch: u64,
    pub compression_saved_bytes: u64,
    pub receipt_count: u64,
    pub namespace_rent_root: String,
    pub settlement_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}
impl NamespaceRentCredit {
    pub fn remaining_units(&self) -> u64 {
        self.credit_units.saturating_sub(self.applied_units)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "contract_namespace": self.contract_namespace,
            "route_id": self.route_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status,
            "credit_units": self.credit_units,
            "applied_units": self.applied_units,
            "rent_epoch": self.rent_epoch,
            "compression_saved_bytes": self.compression_saved_bytes,
            "receipt_count": self.receipt_count,
            "namespace_rent_root": self.namespace_rent_root,
            "settlement_root": self.settlement_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub audience: SummaryAudience,
    pub from_height: u64,
    pub to_height: u64,
    pub route_count: u64,
    pub bundle_count: u64,
    pub compressed_receipts: u64,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub fee_units: u64,
    pub reward_units: u64,
    pub rent_credit_units: u64,
    pub attestation_count: u64,
    pub redaction_units_used: u64,
    pub route_root: String,
    pub bundle_root: String,
    pub reward_root: String,
    pub privacy_boundary: String,
}
impl OperatorSummary {
    pub fn saved_bytes(&self) -> u64 {
        self.original_bytes.saturating_sub(self.compressed_bytes)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "audience": self.audience,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "route_count": self.route_count,
            "bundle_count": self.bundle_count,
            "compressed_receipts": self.compressed_receipts,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "fee_units": self.fee_units,
            "reward_units": self.reward_units,
            "rent_credit_units": self.rent_credit_units,
            "attestation_count": self.attestation_count,
            "redaction_units_used": self.redaction_units_used,
            "route_root": self.route_root,
            "bundle_root": self.bundle_root,
            "reward_root": self.reward_root,
            "privacy_boundary": self.privacy_boundary,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub route_id: Option<String>,
    pub bundle_id: Option<String>,
    pub operator_id: Option<String>,
    pub public_note: String,
    pub event_root: String,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "route_id": self.route_id,
            "bundle_id": self.bundle_id,
            "operator_id": self.operator_id,
            "public_note": self.public_note,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub routes: BTreeMap<String, PrivateReceiptCompressionRoute>,
    pub encrypted_bundles: BTreeMap<String, EncryptedReceiptBundle>,
    pub compressor_commitments: BTreeMap<String, CompressorCommitment>,
    pub pq_compressor_attestations: BTreeMap<String, PqCompressorAttestation>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub low_fee_rewards: BTreeMap<String, LowFeeCompressionReward>,
    pub namespace_rent_credits: BTreeMap<String, NamespaceRentCredit>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            routes: BTreeMap::new(),
            encrypted_bundles: BTreeMap::new(),
            compressor_commitments: BTreeMap::new(),
            pq_compressor_attestations: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            low_fee_rewards: BTreeMap::new(),
            namespace_rent_credits: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), 1_740_000).expect("devnet config is valid");
        state.seed_devnet();
        state
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "height": self.height, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record(), "route_count": self.routes.len(), "encrypted_bundle_count": self.encrypted_bundles.len(), "compressor_commitment_count": self.compressor_commitments.len(), "pq_compressor_attestation_count": self.pq_compressor_attestations.len(), "redaction_budget_count": self.redaction_budgets.len(), "low_fee_reward_count": self.low_fee_rewards.len(), "namespace_rent_credit_count": self.namespace_rent_credits.len(), "operator_summary_count": self.operator_summaries.len(), "event_count": self.events.len(), "privacy_boundary": PRIVACY_BOUNDARY })
    }
    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: value_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-CONFIG",
                &self.config.public_record(),
            ),
            route_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-ROUTES",
                &self.routes,
                |v| v.public_record(),
            ),
            encrypted_bundle_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-BUNDLES",
                &self.encrypted_bundles,
                |v| v.public_record(),
            ),
            compressor_commitment_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-COMPRESSORS",
                &self.compressor_commitments,
                |v| v.public_record(),
            ),
            pq_compressor_attestation_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-ATTESTATIONS",
                &self.pq_compressor_attestations,
                |v| v.public_record(),
            ),
            redaction_budget_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-REDACTIONS",
                &self.redaction_budgets,
                |v| v.public_record(),
            ),
            low_fee_reward_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-REWARDS",
                &self.low_fee_rewards,
                |v| v.public_record(),
            ),
            namespace_rent_credit_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-RENT-CREDITS",
                &self.namespace_rent_credits,
                |v| v.public_record(),
            ),
            operator_summary_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-SUMMARIES",
                &self.operator_summaries,
                |v| v.public_record(),
            ),
            event_root: map_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-EVENTS",
                &self.events,
                |v| v.public_record(),
            ),
            counters_root: value_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-COUNTERS",
                &self.counters.public_record(),
            ),
        };
    }

    pub fn open_route(&mut self, input: RouteInput) -> Result<String> {
        if self.routes.len() >= MAX_ROUTES {
            return Err("private receipt compression route capacity exceeded".to_string());
        }
        let route_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-ROUTE-ID",
            &[
                HashPart::Str(&input.contract_namespace),
                HashPart::Str(&input.contract_commitment),
                HashPart::Str(input.lane.as_str()),
                HashPart::U64(self.counters.routes + 1),
            ],
        );
        let route = PrivateReceiptCompressionRoute {
            route_id: route_id.clone(),
            contract_namespace: input.contract_namespace,
            contract_commitment: input.contract_commitment,
            contract_runtime: input.contract_runtime,
            receipt_class: input.receipt_class,
            lane: input.lane,
            status: RouteStatus::Active,
            codec: input.codec,
            owner_commitment: input.owner_commitment,
            compressor_pool_id: input.compressor_pool_id,
            privacy_set_size: input.privacy_set_size,
            min_bundle_receipts: input.min_bundle_receipts,
            max_bundle_receipts: input.max_bundle_receipts,
            fee_cap_bps: input.lane.fee_cap_bps(&self.config),
            reward_bps: self.config.reward_bps,
            rent_credit_bps: self.config.rent_credit_bps,
            opened_height: self.height,
            expires_height: self.height.saturating_add(self.config.route_ttl_blocks),
            redaction_policy_root: input.redaction_policy_root,
            namespace_rent_root: input.namespace_rent_root,
            replay_domain: self.config.replay_domain.clone(),
            metadata_commitment: input.metadata_commitment,
        };
        self.routes.insert(route_id.clone(), route);
        self.counters.routes += 1;
        self.push_event(
            RuntimeEventKind::RouteOpened,
            route_id.clone(),
            Some(route_id.clone()),
            None,
            None,
            "private receipt compression route opened",
        );
        self.refresh_roots();
        Ok(route_id)
    }
    pub fn post_compressor_commitment(
        &mut self,
        input: CompressorCommitmentInput,
    ) -> Result<String> {
        let commitment_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-COMPRESSOR-ID",
            &[
                HashPart::Str(&input.compressor_id),
                HashPart::Str(&input.operator_id),
                HashPart::U64(self.counters.compressor_commitments + 1),
            ],
        );
        let commitment = CompressorCommitment {
            commitment_id: commitment_id.clone(),
            compressor_id: input.compressor_id.clone(),
            operator_id: input.operator_id.clone(),
            pool_id: input.pool_id,
            status: CommitmentStatus::CapacityOpen,
            supported_codecs: input.supported_codecs,
            max_bundle_receipts: input.max_bundle_receipts,
            available_receipt_capacity: input.available_receipt_capacity,
            bonded_fee_units: input.bonded_fee_units,
            min_reward_bps: input.min_reward_bps,
            pq_identity_root: input.pq_identity_root,
            capacity_commitment_root: input.capacity_commitment_root,
            slashing_key_commitment: input.slashing_key_commitment,
            posted_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.compressor_commitments
            .insert(commitment_id.clone(), commitment);
        self.counters.compressor_commitments += 1;
        self.push_event(
            RuntimeEventKind::CommitmentPosted,
            commitment_id.clone(),
            None,
            None,
            Some(input.operator_id),
            "pq compressor capacity commitment posted",
        );
        self.refresh_roots();
        Ok(commitment_id)
    }
    pub fn seal_bundle(&mut self, input: BundleInput) -> Result<String> {
        let route = self
            .routes
            .get(&input.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        if !route.is_live_at(self.height) {
            return Err("route is not accepting private receipt bundles".to_string());
        }
        let commitment = self
            .compressor_commitments
            .values_mut()
            .find(|commitment| commitment.can_accept(route.codec, input.receipt_count, self.height))
            .ok_or_else(|| "no eligible compressor capacity commitment".to_string())?;
        commitment.available_receipt_capacity = commitment
            .available_receipt_capacity
            .saturating_sub(input.receipt_count);
        commitment.status = CommitmentStatus::CapacityReserved;
        let compressor_id = commitment.compressor_id.clone();
        let bundle_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-BUNDLE-ID",
            &[
                HashPart::Str(&input.route_id),
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::U64(self.counters.encrypted_bundles + 1),
            ],
        );
        let bundle = EncryptedReceiptBundle {
            bundle_id: bundle_id.clone(),
            route_id: input.route_id.clone(),
            contract_namespace: route.contract_namespace.clone(),
            status: BundleStatus::CompressorAssigned,
            codec: route.codec,
            receipt_count: input.receipt_count,
            original_bytes: input.original_bytes,
            compressed_bytes: input.compressed_bytes,
            fee_units: input.fee_units,
            privacy_set_size: input.privacy_set_size,
            encrypted_payload_root: input.encrypted_payload_root,
            receipt_commitment_root: input.receipt_commitment_root,
            nullifier_root: input.nullifier_root,
            view_tag_bucket_root: input.view_tag_bucket_root,
            sender_bucket: input.sender_bucket,
            compressor_id: compressor_id.clone(),
            pq_ciphertext_commitment: input.pq_ciphertext_commitment,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.bundle_ttl_blocks),
            compressed_height: None,
            redaction_budget_id: input.redaction_budget_id,
            attestation_ids: BTreeSet::new(),
        };
        self.counters.encrypted_bundles += 1;
        self.counters.total_receipts_routed = self
            .counters
            .total_receipts_routed
            .saturating_add(bundle.receipt_count);
        self.counters.total_original_bytes = self
            .counters
            .total_original_bytes
            .saturating_add(bundle.original_bytes);
        self.counters.total_compressed_bytes = self
            .counters
            .total_compressed_bytes
            .saturating_add(bundle.compressed_bytes);
        self.counters.total_fee_units = self
            .counters
            .total_fee_units
            .saturating_add(bundle.fee_units);
        self.encrypted_bundles.insert(bundle_id.clone(), bundle);
        self.push_event(
            RuntimeEventKind::BundleSealed,
            bundle_id.clone(),
            Some(input.route_id),
            Some(bundle_id.clone()),
            Some(compressor_id),
            "encrypted private receipt bundle sealed and assigned",
        );
        self.refresh_roots();
        Ok(bundle_id)
    }
    pub fn accept_attestation(&mut self, input: AttestationInput) -> Result<String> {
        let bundle = self
            .encrypted_bundles
            .get_mut(&input.bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        let status = if input.quorum_weight_bps >= self.config.strict_quorum_bps {
            AttestationStatus::StrictQuorum
        } else if input.quorum_weight_bps >= self.config.quorum_bps {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        let attestation_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-ATTESTATION-ID",
            &[
                HashPart::Str(&input.bundle_id),
                HashPart::Str(&input.compressor_id),
                HashPart::U64(self.counters.pq_compressor_attestations + 1),
            ],
        );
        bundle.status = BundleStatus::Attested;
        bundle.compressed_height = Some(self.height);
        bundle.attestation_ids.insert(attestation_id.clone());
        self.counters.total_receipts_compressed = self
            .counters
            .total_receipts_compressed
            .saturating_add(bundle.receipt_count);
        let attestation = PqCompressorAttestation {
            attestation_id: attestation_id.clone(),
            bundle_id: input.bundle_id.clone(),
            compressor_id: input.compressor_id.clone(),
            committee_id: input.committee_id,
            status,
            pq_scheme: self.config.pq_compressor_attestation_scheme.clone(),
            pq_security_bits: input.pq_security_bits,
            quorum_weight_bps: input.quorum_weight_bps,
            compressed_receipt_root: input.compressed_receipt_root,
            decompression_witness_root: input.decompression_witness_root,
            transcript_root: input.transcript_root,
            signer_bitmap_root: input.signer_bitmap_root,
            submitted_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.pq_compressor_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_compressor_attestations += 1;
        self.push_event(
            RuntimeEventKind::AttestationAccepted,
            attestation_id.clone(),
            None,
            Some(input.bundle_id),
            Some(input.compressor_id),
            "pq compressor attestation accepted",
        );
        self.refresh_roots();
        Ok(attestation_id)
    }
    pub fn reserve_redaction_budget(&mut self, input: RedactionBudgetInput) -> Result<String> {
        let budget_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-REDACTION-BUDGET-ID",
            &[
                HashPart::Str(&input.route_id),
                HashPart::Str(&input.owner_bucket),
                HashPart::U64(input.epoch),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            route_id: input.route_id.clone(),
            owner_bucket: input.owner_bucket,
            epoch: input.epoch,
            status: RedactionBudgetStatus::Reserved,
            reserved_units: input.reserved_units,
            used_units: input.used_units,
            redaction_policy_root: input.redaction_policy_root,
            selective_disclosure_root: input.selective_disclosure_root,
            view_key_safety_root: input.view_key_safety_root,
            opened_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.redaction_epoch_blocks),
        };
        self.counters.redaction_budgets += 1;
        self.counters.total_redaction_units_reserved = self
            .counters
            .total_redaction_units_reserved
            .saturating_add(budget.reserved_units);
        self.counters.total_redaction_units_used = self
            .counters
            .total_redaction_units_used
            .saturating_add(budget.used_units);
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.push_event(
            RuntimeEventKind::RedactionBudgetApplied,
            budget_id.clone(),
            Some(input.route_id),
            None,
            None,
            "private receipt redaction budget reserved",
        );
        self.refresh_roots();
        Ok(budget_id)
    }
    pub fn settle_low_fee_reward(
        &mut self,
        bundle_id: &str,
        sponsor_id: impl Into<String>,
    ) -> Result<String> {
        let bundle = self
            .encrypted_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "bundle not found".to_string())?;
        if !bundle.status.rewardable() {
            return Err("bundle is not rewardable".to_string());
        }
        let reward_units = bundle
            .saved_bytes()
            .saturating_mul(self.config.reward_bps)
            .saturating_div(MAX_BPS)
            .saturating_add(bundle.receipt_count);
        let reward_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-REWARD-ID",
            &[
                HashPart::Str(bundle_id),
                HashPart::Str(&bundle.compressor_id),
                HashPart::U64(self.counters.low_fee_rewards + 1),
            ],
        );
        let reward = LowFeeCompressionReward {
            reward_id: reward_id.clone(),
            bundle_id: bundle_id.to_string(),
            route_id: bundle.route_id.clone(),
            compressor_id: bundle.compressor_id.clone(),
            sponsor_id: sponsor_id.into(),
            status: RewardStatus::Queued,
            reward_asset_id: self.config.reward_asset_id.clone(),
            saved_bytes: bundle.saved_bytes(),
            receipt_count: bundle.receipt_count,
            fee_units_paid: bundle.fee_units,
            reward_units,
            reward_bps: self.config.reward_bps,
            low_fee_score: bundle.low_fee_score(),
            settlement_root: value_root(
                "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-REWARD-SETTLEMENT",
                &bundle.public_record(),
            ),
            metered_height: self.height,
            payable_height: self
                .height
                .saturating_add(self.config.reward_settlement_ttl_blocks),
        };
        bundle.status = BundleStatus::RewardQueued;
        self.counters.low_fee_rewards += 1;
        self.counters.total_reward_units = self
            .counters
            .total_reward_units
            .saturating_add(reward.reward_units);
        self.low_fee_rewards.insert(reward_id.clone(), reward);
        self.push_event(
            RuntimeEventKind::RewardSettled,
            reward_id.clone(),
            None,
            Some(bundle_id.to_string()),
            None,
            "low-fee private receipt compression reward queued",
        );
        self.refresh_roots();
        Ok(reward_id)
    }
    pub fn issue_namespace_rent_credit(
        &mut self,
        input: NamespaceRentCreditInput,
    ) -> Result<String> {
        let credit_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-RENT-CREDIT-ID",
            &[
                HashPart::Str(&input.contract_namespace),
                HashPart::Str(&input.route_id),
                HashPart::U64(input.rent_epoch),
            ],
        );
        let credit = NamespaceRentCredit {
            credit_id: credit_id.clone(),
            contract_namespace: input.contract_namespace,
            route_id: input.route_id.clone(),
            owner_commitment: input.owner_commitment,
            status: RentCreditStatus::OffsetPending,
            credit_units: input.credit_units,
            applied_units: input.applied_units,
            rent_epoch: input.rent_epoch,
            compression_saved_bytes: input.compression_saved_bytes,
            receipt_count: input.receipt_count,
            namespace_rent_root: input.namespace_rent_root,
            settlement_root: input.settlement_root,
            created_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.reward_settlement_ttl_blocks),
        };
        self.counters.namespace_rent_credits += 1;
        self.counters.total_rent_credit_units = self
            .counters
            .total_rent_credit_units
            .saturating_add(credit.credit_units);
        self.namespace_rent_credits
            .insert(credit_id.clone(), credit);
        self.push_event(
            RuntimeEventKind::RentCreditApplied,
            credit_id.clone(),
            Some(input.route_id),
            None,
            None,
            "namespace rent credit issued from compression savings",
        );
        self.refresh_roots();
        Ok(credit_id)
    }
    pub fn publish_operator_summary(&mut self, input: OperatorSummaryInput) -> Result<String> {
        let summary_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-SUMMARY-ID",
            &[
                HashPart::Str(&input.operator_id),
                HashPart::Str(input.audience.as_str()),
                HashPart::U64(self.counters.operator_summaries + 1),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id: input.operator_id.clone(),
            audience: input.audience,
            from_height: input.from_height,
            to_height: input.to_height,
            route_count: input.route_count,
            bundle_count: input.bundle_count,
            compressed_receipts: input.compressed_receipts,
            original_bytes: input.original_bytes,
            compressed_bytes: input.compressed_bytes,
            fee_units: input.fee_units,
            reward_units: input.reward_units,
            rent_credit_units: input.rent_credit_units,
            attestation_count: input.attestation_count,
            redaction_units_used: input.redaction_units_used,
            route_root: self.roots.route_root.clone(),
            bundle_root: self.roots.encrypted_bundle_root.clone(),
            reward_root: self.roots.low_fee_reward_root.clone(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries += 1;
        self.push_event(
            RuntimeEventKind::SummaryPublished,
            summary_id.clone(),
            None,
            None,
            Some(input.operator_id),
            "operator-safe private receipt compression summary published",
        );
        self.refresh_roots();
        Ok(summary_id)
    }
    fn push_event(
        &mut self,
        kind: RuntimeEventKind,
        subject_id: String,
        route_id: Option<String>,
        bundle_id: Option<String>,
        operator_id: Option<String>,
        public_note: &str,
    ) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = deterministic_id(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-EVENT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
                HashPart::U64(self.counters.events + 1),
            ],
        );
        let event_root = domain_hash(
            "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-EVENT-ROOT",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
                HashPart::U64(self.height),
            ],
            32,
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            height: self.height,
            kind,
            subject_id,
            route_id,
            bundle_id,
            operator_id,
            public_note: public_note.to_string(),
            event_root,
        };
        self.events.insert(event_id, event);
        self.counters.events += 1;
    }
    fn seed_devnet(&mut self) {
        let mut codecs = BTreeSet::new();
        codecs.insert(CompressionCodec::ZstdDictionary);
        codecs.insert(CompressionCodec::Halo2Recursive);
        codecs.insert(CompressionCodec::PoseidonTranscript);
        let _ = self
            .post_compressor_commitment(CompressorCommitmentInput {
                compressor_id: "compressor-devnet-alpha".to_string(),
                operator_id: "operator-devnet-compression-alpha".to_string(),
                pool_id: "pool-low-fee-contract-receipts".to_string(),
                supported_codecs: codecs,
                max_bundle_receipts: 512,
                available_receipt_capacity: 4_096,
                bonded_fee_units: 9_000_000,
                min_reward_bps: 2,
                pq_identity_root: fixture_hash("pq-identity-alpha"),
                capacity_commitment_root: fixture_hash("capacity-alpha"),
                slashing_key_commitment: fixture_hash("slashing-alpha"),
            })
            .expect("devnet compressor commitment is valid");
        let route_id = self
            .open_route(RouteInput {
                contract_namespace: "swap.private.dex.devnet".to_string(),
                contract_commitment: fixture_hash("contract-swap-private-dex"),
                contract_runtime: ContractRuntimeKind::ConfidentialEvm,
                receipt_class: ReceiptClass::ContractCall,
                lane: RouteLane::LowFee,
                codec: CompressionCodec::Halo2Recursive,
                owner_commitment: fixture_hash("owner-swap-dao"),
                compressor_pool_id: "pool-low-fee-contract-receipts".to_string(),
                privacy_set_size: 262_144,
                min_bundle_receipts: 16,
                max_bundle_receipts: 512,
                redaction_policy_root: fixture_hash("redaction-policy-swap"),
                namespace_rent_root: fixture_hash("namespace-rent-swap"),
                metadata_commitment: fixture_hash("route-metadata-swap"),
            })
            .expect("devnet route is valid");
        let budget_id = self
            .reserve_redaction_budget(RedactionBudgetInput {
                route_id: route_id.clone(),
                owner_bucket: "owner-bucket-swap-dao".to_string(),
                epoch: 2_417,
                reserved_units: 512,
                used_units: 64,
                redaction_policy_root: fixture_hash("redaction-budget-policy-swap"),
                selective_disclosure_root: fixture_hash("selective-disclosure-swap"),
                view_key_safety_root: fixture_hash("view-key-safety-swap"),
            })
            .expect("devnet redaction budget is valid");
        let bundle_id = self
            .seal_bundle(BundleInput {
                route_id: route_id.clone(),
                receipt_count: 144,
                original_bytes: 1_179_648,
                compressed_bytes: 183_296,
                fee_units: 420,
                privacy_set_size: 262_144,
                encrypted_payload_root: fixture_hash("encrypted-payload-bundle-1"),
                receipt_commitment_root: fixture_hash("receipt-commitments-bundle-1"),
                nullifier_root: fixture_hash("nullifiers-bundle-1"),
                view_tag_bucket_root: fixture_hash("view-tags-bundle-1"),
                sender_bucket: "sender-bucket-8192-a".to_string(),
                pq_ciphertext_commitment: fixture_hash("pq-ciphertext-bundle-1"),
                redaction_budget_id: Some(budget_id),
            })
            .expect("devnet bundle is valid");
        let _ = self
            .accept_attestation(AttestationInput {
                bundle_id: bundle_id.clone(),
                compressor_id: "compressor-devnet-alpha".to_string(),
                committee_id: "pq-committee-devnet-receipt-compression".to_string(),
                pq_security_bits: 256,
                quorum_weight_bps: 8_250,
                compressed_receipt_root: fixture_hash("compressed-receipts-bundle-1"),
                decompression_witness_root: fixture_hash("decompression-witness-bundle-1"),
                transcript_root: fixture_hash("compression-transcript-bundle-1"),
                signer_bitmap_root: fixture_hash("signer-bitmap-bundle-1"),
            })
            .expect("devnet attestation is valid");
        let _ = self
            .settle_low_fee_reward(&bundle_id, "sponsor-devnet-low-fee-receipts")
            .expect("devnet reward is valid");
        let _ = self
            .issue_namespace_rent_credit(NamespaceRentCreditInput {
                contract_namespace: "swap.private.dex.devnet".to_string(),
                route_id: route_id.clone(),
                owner_commitment: fixture_hash("owner-swap-dao"),
                credit_units: 2_048,
                applied_units: 256,
                rent_epoch: 2_417,
                compression_saved_bytes: 996_352,
                receipt_count: 144,
                namespace_rent_root: fixture_hash("namespace-rent-credit-swap"),
                settlement_root: fixture_hash("namespace-rent-settlement-swap"),
            })
            .expect("devnet namespace rent credit is valid");
        let _ = self
            .publish_operator_summary(OperatorSummaryInput {
                operator_id: "operator-devnet-compression-alpha".to_string(),
                audience: SummaryAudience::Public,
                from_height: self.height.saturating_sub(72),
                to_height: self.height,
                route_count: 1,
                bundle_count: 1,
                compressed_receipts: 144,
                original_bytes: 1_179_648,
                compressed_bytes: 183_296,
                fee_units: 420,
                reward_units: 542,
                rent_credit_units: 2_048,
                attestation_count: 1,
                redaction_units_used: 64,
            })
            .expect("devnet operator summary is valid");
        self.refresh_roots();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteInput {
    pub contract_namespace: String,
    pub contract_commitment: String,
    pub contract_runtime: ContractRuntimeKind,
    pub receipt_class: ReceiptClass,
    pub lane: RouteLane,
    pub codec: CompressionCodec,
    pub owner_commitment: String,
    pub compressor_pool_id: String,
    pub privacy_set_size: u64,
    pub min_bundle_receipts: u64,
    pub max_bundle_receipts: u64,
    pub redaction_policy_root: String,
    pub namespace_rent_root: String,
    pub metadata_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleInput {
    pub route_id: String,
    pub receipt_count: u64,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub fee_units: u64,
    pub privacy_set_size: u64,
    pub encrypted_payload_root: String,
    pub receipt_commitment_root: String,
    pub nullifier_root: String,
    pub view_tag_bucket_root: String,
    pub sender_bucket: String,
    pub pq_ciphertext_commitment: String,
    pub redaction_budget_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressorCommitmentInput {
    pub compressor_id: String,
    pub operator_id: String,
    pub pool_id: String,
    pub supported_codecs: BTreeSet<CompressionCodec>,
    pub max_bundle_receipts: u64,
    pub available_receipt_capacity: u64,
    pub bonded_fee_units: u64,
    pub min_reward_bps: u64,
    pub pq_identity_root: String,
    pub capacity_commitment_root: String,
    pub slashing_key_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationInput {
    pub bundle_id: String,
    pub compressor_id: String,
    pub committee_id: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub compressed_receipt_root: String,
    pub decompression_witness_root: String,
    pub transcript_root: String,
    pub signer_bitmap_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetInput {
    pub route_id: String,
    pub owner_bucket: String,
    pub epoch: u64,
    pub reserved_units: u64,
    pub used_units: u64,
    pub redaction_policy_root: String,
    pub selective_disclosure_root: String,
    pub view_key_safety_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceRentCreditInput {
    pub contract_namespace: String,
    pub route_id: String,
    pub owner_commitment: String,
    pub credit_units: u64,
    pub applied_units: u64,
    pub rent_epoch: u64,
    pub compression_saved_bytes: u64,
    pub receipt_count: u64,
    pub namespace_rent_root: String,
    pub settlement_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryInput {
    pub operator_id: String,
    pub audience: SummaryAudience,
    pub from_height: u64,
    pub to_height: u64,
    pub route_count: u64,
    pub bundle_count: u64,
    pub compressed_receipts: u64,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub fee_units: u64,
    pub reward_units: u64,
    pub rent_credit_units: u64,
    pub attestation_count: u64,
    pub redaction_units_used: u64,
}

impl State {
    pub fn get_route(&self, id: &str) -> Option<&PrivateReceiptCompressionRoute> {
        self.routes.get(id)
    }
    pub fn contains_route(&self, id: &str) -> bool {
        self.routes.contains_key(id)
    }
    pub fn route_public_record(&self, id: &str) -> Option<Value> {
        self.routes.get(id).map(|item| item.public_record())
    }
    pub fn route_ids(&self) -> Vec<String> {
        self.routes.keys().cloned().collect()
    }
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}
pub fn route_root(state: &State) -> String {
    state.roots.route_root.clone()
}

impl State {
    pub fn get_encrypted_bundle(&self, id: &str) -> Option<&EncryptedReceiptBundle> {
        self.encrypted_bundles.get(id)
    }
    pub fn contains_encrypted_bundle(&self, id: &str) -> bool {
        self.encrypted_bundles.contains_key(id)
    }
    pub fn encrypted_bundle_public_record(&self, id: &str) -> Option<Value> {
        self.encrypted_bundles
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn encrypted_bundle_ids(&self) -> Vec<String> {
        self.encrypted_bundles.keys().cloned().collect()
    }
    pub fn encrypted_bundle_count(&self) -> usize {
        self.encrypted_bundles.len()
    }
}
pub fn encrypted_bundle_root(state: &State) -> String {
    state.roots.encrypted_bundle_root.clone()
}

impl State {
    pub fn get_compressor_commitment(&self, id: &str) -> Option<&CompressorCommitment> {
        self.compressor_commitments.get(id)
    }
    pub fn contains_compressor_commitment(&self, id: &str) -> bool {
        self.compressor_commitments.contains_key(id)
    }
    pub fn compressor_commitment_public_record(&self, id: &str) -> Option<Value> {
        self.compressor_commitments
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn compressor_commitment_ids(&self) -> Vec<String> {
        self.compressor_commitments.keys().cloned().collect()
    }
    pub fn compressor_commitment_count(&self) -> usize {
        self.compressor_commitments.len()
    }
}
pub fn compressor_commitment_root(state: &State) -> String {
    state.roots.compressor_commitment_root.clone()
}

impl State {
    pub fn get_pq_compressor_attestation(&self, id: &str) -> Option<&PqCompressorAttestation> {
        self.pq_compressor_attestations.get(id)
    }
    pub fn contains_pq_compressor_attestation(&self, id: &str) -> bool {
        self.pq_compressor_attestations.contains_key(id)
    }
    pub fn pq_compressor_attestation_public_record(&self, id: &str) -> Option<Value> {
        self.pq_compressor_attestations
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn pq_compressor_attestation_ids(&self) -> Vec<String> {
        self.pq_compressor_attestations.keys().cloned().collect()
    }
    pub fn pq_compressor_attestation_count(&self) -> usize {
        self.pq_compressor_attestations.len()
    }
}
pub fn pq_compressor_attestation_root(state: &State) -> String {
    state.roots.pq_compressor_attestation_root.clone()
}

impl State {
    pub fn get_redaction_budget(&self, id: &str) -> Option<&RedactionBudget> {
        self.redaction_budgets.get(id)
    }
    pub fn contains_redaction_budget(&self, id: &str) -> bool {
        self.redaction_budgets.contains_key(id)
    }
    pub fn redaction_budget_public_record(&self, id: &str) -> Option<Value> {
        self.redaction_budgets
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn redaction_budget_ids(&self) -> Vec<String> {
        self.redaction_budgets.keys().cloned().collect()
    }
    pub fn redaction_budget_count(&self) -> usize {
        self.redaction_budgets.len()
    }
}
pub fn redaction_budget_root(state: &State) -> String {
    state.roots.redaction_budget_root.clone()
}

impl State {
    pub fn get_low_fee_reward(&self, id: &str) -> Option<&LowFeeCompressionReward> {
        self.low_fee_rewards.get(id)
    }
    pub fn contains_low_fee_reward(&self, id: &str) -> bool {
        self.low_fee_rewards.contains_key(id)
    }
    pub fn low_fee_reward_public_record(&self, id: &str) -> Option<Value> {
        self.low_fee_rewards
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn low_fee_reward_ids(&self) -> Vec<String> {
        self.low_fee_rewards.keys().cloned().collect()
    }
    pub fn low_fee_reward_count(&self) -> usize {
        self.low_fee_rewards.len()
    }
}
pub fn low_fee_reward_root(state: &State) -> String {
    state.roots.low_fee_reward_root.clone()
}

impl State {
    pub fn get_namespace_rent_credit(&self, id: &str) -> Option<&NamespaceRentCredit> {
        self.namespace_rent_credits.get(id)
    }
    pub fn contains_namespace_rent_credit(&self, id: &str) -> bool {
        self.namespace_rent_credits.contains_key(id)
    }
    pub fn namespace_rent_credit_public_record(&self, id: &str) -> Option<Value> {
        self.namespace_rent_credits
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn namespace_rent_credit_ids(&self) -> Vec<String> {
        self.namespace_rent_credits.keys().cloned().collect()
    }
    pub fn namespace_rent_credit_count(&self) -> usize {
        self.namespace_rent_credits.len()
    }
}
pub fn namespace_rent_credit_root(state: &State) -> String {
    state.roots.namespace_rent_credit_root.clone()
}

impl State {
    pub fn get_operator_summary(&self, id: &str) -> Option<&OperatorSummary> {
        self.operator_summaries.get(id)
    }
    pub fn contains_operator_summary(&self, id: &str) -> bool {
        self.operator_summaries.contains_key(id)
    }
    pub fn operator_summary_public_record(&self, id: &str) -> Option<Value> {
        self.operator_summaries
            .get(id)
            .map(|item| item.public_record())
    }
    pub fn operator_summary_ids(&self) -> Vec<String> {
        self.operator_summaries.keys().cloned().collect()
    }
    pub fn operator_summary_count(&self) -> usize {
        self.operator_summaries.len()
    }
}
pub fn operator_summary_root(state: &State) -> String {
    state.roots.operator_summary_root.clone()
}

impl State {
    pub fn get_event(&self, id: &str) -> Option<&RuntimeEvent> {
        self.events.get(id)
    }
    pub fn contains_event(&self, id: &str) -> bool {
        self.events.contains_key(id)
    }
    pub fn event_public_record(&self, id: &str) -> Option<Value> {
        self.events.get(id).map(|item| item.public_record())
    }
    pub fn event_ids(&self) -> Vec<String> {
        self.events.keys().cloned().collect()
    }
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}
pub fn event_root(state: &State) -> String {
    state.roots.event_root.clone()
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
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-RECEIPT-COMPRESSION-ROUTER-STATE",
        &[HashPart::Json(record)],
        32,
    )
}
pub fn value_root(domain: &'static str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}
pub fn map_root<T, F>(domain: &'static str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, item)| {
            json!(domain_hash(
                domain,
                &[HashPart::Str(id), HashPart::Json(&f(item))],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn deterministic_id(domain: &'static str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
pub fn fixture_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-RECEIPT-COMPRESSION-ROUTER-DEVNET-FIXTURE",
        &[HashPart::Str(label)],
        32,
    )
}

impl State {
    pub fn privacy_audit_bucket_0(&self) -> Value {
        json!({
            "bucket": 0,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_1(&self) -> Value {
        json!({
            "bucket": 1,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_2(&self) -> Value {
        json!({
            "bucket": 2,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_3(&self) -> Value {
        json!({
            "bucket": 3,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_4(&self) -> Value {
        json!({
            "bucket": 4,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_5(&self) -> Value {
        json!({
            "bucket": 5,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_6(&self) -> Value {
        json!({
            "bucket": 6,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_7(&self) -> Value {
        json!({
            "bucket": 7,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_8(&self) -> Value {
        json!({
            "bucket": 8,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_9(&self) -> Value {
        json!({
            "bucket": 9,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_10(&self) -> Value {
        json!({
            "bucket": 10,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_11(&self) -> Value {
        json!({
            "bucket": 11,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_12(&self) -> Value {
        json!({
            "bucket": 12,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_13(&self) -> Value {
        json!({
            "bucket": 13,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_14(&self) -> Value {
        json!({
            "bucket": 14,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_15(&self) -> Value {
        json!({
            "bucket": 15,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_16(&self) -> Value {
        json!({
            "bucket": 16,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_17(&self) -> Value {
        json!({
            "bucket": 17,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_18(&self) -> Value {
        json!({
            "bucket": 18,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_19(&self) -> Value {
        json!({
            "bucket": 19,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_20(&self) -> Value {
        json!({
            "bucket": 20,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_21(&self) -> Value {
        json!({
            "bucket": 21,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_22(&self) -> Value {
        json!({
            "bucket": 22,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_23(&self) -> Value {
        json!({
            "bucket": 23,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_24(&self) -> Value {
        json!({
            "bucket": 24,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_25(&self) -> Value {
        json!({
            "bucket": 25,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_26(&self) -> Value {
        json!({
            "bucket": 26,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_27(&self) -> Value {
        json!({
            "bucket": 27,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_28(&self) -> Value {
        json!({
            "bucket": 28,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}

impl State {
    pub fn privacy_audit_bucket_29(&self) -> Value {
        json!({
            "bucket": 29,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "route_root": self.roots.route_root,
            "bundle_root": self.roots.encrypted_bundle_root,
            "attestation_root": self.roots.pq_compressor_attestation_root,
            "redaction_root": self.roots.redaction_budget_root,
            "low_fee_reward_root": self.roots.low_fee_reward_root,
            "namespace_rent_credit_root": self.roots.namespace_rent_credit_root,
            "state_root": self.state_root(),
        })
    }
}
