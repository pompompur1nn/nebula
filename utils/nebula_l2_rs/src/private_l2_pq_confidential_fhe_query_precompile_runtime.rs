use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialFheQueryPrecompileRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_QUERY_PRECOMPILE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-fhe-query-precompile-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FHE_QUERY_PRECOMPILE_RUNTIME_PROTOCOL_VERSION;
pub const MODULE_PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FHE_QUERY_PRECOMPILE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 913_600;
pub const DEVNET_NETWORK: &str = "nebula-private-l2-devnet";
pub const MONERO_NETWORK: &str = "monero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FHE_PARAMETER_SCHEME: &str = "rlwe-mlwe-hybrid-confidential-query-params-v1";
pub const PQ_SIGNATURE_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f";
pub const PQ_KEM_SCHEME: &str = "ml-kem-1024+hybrid-x25519-envelope-v1";
pub const TRANSCRIPT_SCHEME: &str = "canonical-fhe-query-transcript-v1";
pub const PUBLIC_ROOT_SCHEME: &str = "deterministic-public-root-commitment-v1";
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_NOISE_BUDGET_BITS: u16 = 96;
pub const DEFAULT_MAX_CIPHERTEXT_BYTES: u64 = 262_144;
pub const DEFAULT_MAX_QUERY_GAS: u64 = 3_000_000;
pub const DEFAULT_BASE_FEE_MICRONEBULA: u64 = 125;
pub const DEFAULT_BYTE_FEE_MICRONEBULA: u64 = 1;
pub const DEFAULT_BOOTSTRAP_FEE_MICRONEBULA: u64 = 25_000;
pub const DEFAULT_MAX_BOOTSTRAPS_PER_QUERY: u16 = 3;
pub const DEFAULT_MAX_PUBLIC_OUTPUT_BYTES: u64 = 4_096;
pub const DEFAULT_MIN_COMMITTEE_SHARES: u16 = 3;
pub const DEFAULT_MIN_ATTESTATION_QUORUM: u16 = 5;
pub const DEFAULT_ROOT_EPOCH_BLOCKS: u64 = 32;
pub const DEFAULT_MAX_REVEAL_DELAY_BLOCKS: u64 = 144;
pub const MAX_KEYSETS: usize = 262_144;
pub const MAX_CIPHERTEXTS: usize = 1_048_576;
pub const MAX_QUERY_PLANS: usize = 1_048_576;
pub const MAX_ACCESS_POLICIES: usize = 262_144;
pub const MAX_EXECUTION_RECEIPTS: usize = 2_097_152;
pub const MAX_PROOF_ATTESTATIONS: usize = 2_097_152;
pub const MAX_FEE_QUOTES: usize = 1_048_576;
pub const MAX_DECRYPTION_SHARES: usize = 2_097_152;
pub const MAX_PUBLIC_ROOTS: usize = 1_048_576;
pub const MAX_AUDIT_SEALS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FheScheme {
    Bfv,
    Bgv,
    Ckks,
    Tfhe,
    HybridRlweMlwe,
}

impl FheScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bfv => "bfv",
            Self::Bgv => "bgv",
            Self::Ckks => "ckks",
            Self::Tfhe => "tfhe",
            Self::HybridRlweMlwe => "hybrid_rlwe_mlwe",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    BalancePredicate,
    AllowListMembership,
    RangeFilter,
    PrivateSwapQuote,
    VotingTally,
    ComplianceGate,
    ContractStoragePredicate,
    OracleAggregate,
}

impl QueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BalancePredicate => "balance_predicate",
            Self::AllowListMembership => "allow_list_membership",
            Self::RangeFilter => "range_filter",
            Self::PrivateSwapQuote => "private_swap_quote",
            Self::VotingTally => "voting_tally",
            Self::ComplianceGate => "compliance_gate",
            Self::ContractStoragePredicate => "contract_storage_predicate",
            Self::OracleAggregate => "oracle_aggregate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiphertextClass {
    Input,
    StateCell,
    Accumulator,
    OutputCommitment,
    ThresholdShare,
    AuditCanary,
}

impl CiphertextClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::StateCell => "state_cell",
            Self::Accumulator => "accumulator",
            Self::OutputCommitment => "output_commitment",
            Self::ThresholdShare => "threshold_share",
            Self::AuditCanary => "audit_canary",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    FullyPrivate,
    PredicateOnly,
    AggregateOnly,
    DelayedReveal,
    PublicCommitment,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyPrivate => "fully_private",
            Self::PredicateOnly => "predicate_only",
            Self::AggregateOnly => "aggregate_only",
            Self::DelayedReveal => "delayed_reveal",
            Self::PublicCommitment => "public_commitment",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Draft,
    Committed,
    Scheduled,
    Executed,
    Settled,
    Rejected,
    Quarantined,
}

impl QueryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Scheduled => "scheduled",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Scheduled | Self::Executed | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ParameterSet,
    KeyCeremony,
    QueryCircuit,
    ExecutionTrace,
    NoiseBound,
    PublicRoot,
    FeeMeter,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParameterSet => "parameter_set",
            Self::KeyCeremony => "key_ceremony",
            Self::QueryCircuit => "query_circuit",
            Self::ExecutionTrace => "execution_trace",
            Self::NoiseBound => "noise_bound",
            Self::PublicRoot => "public_root",
            Self::FeeMeter => "fee_meter",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Observed,
    Accepted,
    Superseded,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Open,
    ContractScoped,
    ViewKeyScoped,
    CommitteeScoped,
    EmergencyPaused,
}

impl PolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ContractScoped => "contract_scoped",
            Self::ViewKeyScoped => "view_key_scoped",
            Self::CommitteeScoped => "committee_scoped",
            Self::EmergencyPaused => "emergency_paused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeTier {
    FreeDevnet,
    Low,
    Normal,
    Urgent,
    BatchDiscount,
}

impl FeeTier {
    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::FreeDevnet => 0,
            Self::Low => 7_500,
            Self::Normal => 10_000,
            Self::Urgent => 18_000,
            Self::BatchDiscount => 5_000,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreeDevnet => "free_devnet",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Urgent => "urgent",
            Self::BatchDiscount => "batch_discount",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    Epoch,
    QueryBatch,
    Contract,
    Fee,
    Attestation,
    Emergency,
}

impl RootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Epoch => "epoch",
            Self::QueryBatch => "query_batch",
            Self::Contract => "contract",
            Self::Fee => "fee",
            Self::Attestation => "attestation",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSealStatus {
    Open,
    Sealed,
    Published,
    Challenged,
    Revoked,
}

impl AuditSealStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub network: String,
    pub monero_network: String,
    pub devnet_height: u64,
    pub fhe_parameter_scheme: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub transcript_scheme: String,
    pub public_root_scheme: String,
    pub target_pq_security_bits: u16,
    pub min_noise_budget_bits: u16,
    pub max_ciphertext_bytes: u64,
    pub max_query_gas: u64,
    pub base_fee_micronebula: u64,
    pub byte_fee_micronebula: u64,
    pub bootstrap_fee_micronebula: u64,
    pub max_bootstraps_per_query: u16,
    pub max_public_output_bytes: u64,
    pub min_committee_shares: u16,
    pub min_attestation_quorum: u16,
    pub root_epoch_blocks: u64,
    pub max_reveal_delay_blocks: u64,
    pub deterministic_public_roots: bool,
    pub require_pq_attestations: bool,
    pub enforce_low_fee_cap: bool,
    pub allow_devnet_free_tier: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            network: DEVNET_NETWORK.to_string(),
            monero_network: MONERO_NETWORK.to_string(),
            devnet_height: DEVNET_HEIGHT,
            fhe_parameter_scheme: FHE_PARAMETER_SCHEME.to_string(),
            pq_signature_scheme: PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PQ_KEM_SCHEME.to_string(),
            transcript_scheme: TRANSCRIPT_SCHEME.to_string(),
            public_root_scheme: PUBLIC_ROOT_SCHEME.to_string(),
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_noise_budget_bits: DEFAULT_MIN_NOISE_BUDGET_BITS,
            max_ciphertext_bytes: DEFAULT_MAX_CIPHERTEXT_BYTES,
            max_query_gas: DEFAULT_MAX_QUERY_GAS,
            base_fee_micronebula: DEFAULT_BASE_FEE_MICRONEBULA,
            byte_fee_micronebula: DEFAULT_BYTE_FEE_MICRONEBULA,
            bootstrap_fee_micronebula: DEFAULT_BOOTSTRAP_FEE_MICRONEBULA,
            max_bootstraps_per_query: DEFAULT_MAX_BOOTSTRAPS_PER_QUERY,
            max_public_output_bytes: DEFAULT_MAX_PUBLIC_OUTPUT_BYTES,
            min_committee_shares: DEFAULT_MIN_COMMITTEE_SHARES,
            min_attestation_quorum: DEFAULT_MIN_ATTESTATION_QUORUM,
            root_epoch_blocks: DEFAULT_ROOT_EPOCH_BLOCKS,
            max_reveal_delay_blocks: DEFAULT_MAX_REVEAL_DELAY_BLOCKS,
            deterministic_public_roots: true,
            require_pq_attestations: true,
            enforce_low_fee_cap: true,
            allow_devnet_free_tier: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "network": self.network,
            "monero_network": self.monero_network,
            "devnet_height": self.devnet_height,
            "fhe_parameter_scheme": self.fhe_parameter_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "transcript_scheme": self.transcript_scheme,
            "public_root_scheme": self.public_root_scheme,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_noise_budget_bits": self.min_noise_budget_bits,
            "max_ciphertext_bytes": self.max_ciphertext_bytes,
            "max_query_gas": self.max_query_gas,
            "base_fee_micronebula": self.base_fee_micronebula,
            "byte_fee_micronebula": self.byte_fee_micronebula,
            "bootstrap_fee_micronebula": self.bootstrap_fee_micronebula,
            "max_bootstraps_per_query": self.max_bootstraps_per_query,
            "max_public_output_bytes": self.max_public_output_bytes,
            "min_committee_shares": self.min_committee_shares,
            "min_attestation_quorum": self.min_attestation_quorum,
            "root_epoch_blocks": self.root_epoch_blocks,
            "max_reveal_delay_blocks": self.max_reveal_delay_blocks,
            "deterministic_public_roots": self.deterministic_public_roots,
            "require_pq_attestations": self.require_pq_attestations,
            "enforce_low_fee_cap": self.enforce_low_fee_cap,
            "allow_devnet_free_tier": self.allow_devnet_free_tier,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub keysets: u64,
    pub ciphertexts: u64,
    pub query_plans: u64,
    pub access_policies: u64,
    pub execution_receipts: u64,
    pub proof_attestations: u64,
    pub fee_quotes: u64,
    pub decryption_shares: u64,
    pub public_roots: u64,
    pub audit_seals: u64,
    pub accepted_queries: u64,
    pub settled_queries: u64,
    pub accepted_attestations: u64,
    pub low_fee_quotes: u64,
    pub rejected_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "keysets": self.keysets,
            "ciphertexts": self.ciphertexts,
            "query_plans": self.query_plans,
            "access_policies": self.access_policies,
            "execution_receipts": self.execution_receipts,
            "proof_attestations": self.proof_attestations,
            "fee_quotes": self.fee_quotes,
            "decryption_shares": self.decryption_shares,
            "public_roots": self.public_roots,
            "audit_seals": self.audit_seals,
            "accepted_queries": self.accepted_queries,
            "settled_queries": self.settled_queries,
            "accepted_attestations": self.accepted_attestations,
            "low_fee_quotes": self.low_fee_quotes,
            "rejected_records": self.rejected_records,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub keyset_root: String,
    pub ciphertext_root: String,
    pub query_plan_root: String,
    pub access_policy_root: String,
    pub execution_receipt_root: String,
    pub proof_attestation_root: String,
    pub fee_quote_root: String,
    pub decryption_share_root: String,
    pub public_root_publication_root: String,
    pub audit_seal_root: String,
    pub indexes_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = empty_root("roots");
        Self {
            config_root: empty.clone(),
            keyset_root: empty.clone(),
            ciphertext_root: empty.clone(),
            query_plan_root: empty.clone(),
            access_policy_root: empty.clone(),
            execution_receipt_root: empty.clone(),
            proof_attestation_root: empty.clone(),
            fee_quote_root: empty.clone(),
            decryption_share_root: empty.clone(),
            public_root_publication_root: empty.clone(),
            audit_seal_root: empty.clone(),
            indexes_root: empty.clone(),
            counters_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "keyset_root": self.keyset_root,
            "ciphertext_root": self.ciphertext_root,
            "query_plan_root": self.query_plan_root,
            "access_policy_root": self.access_policy_root,
            "execution_receipt_root": self.execution_receipt_root,
            "proof_attestation_root": self.proof_attestation_root,
            "fee_quote_root": self.fee_quote_root,
            "decryption_share_root": self.decryption_share_root,
            "public_root_publication_root": self.public_root_publication_root,
            "audit_seal_root": self.audit_seal_root,
            "indexes_root": self.indexes_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysetRequest {
    pub keyset_id: String,
    pub scheme: FheScheme,
    pub parameter_digest: String,
    pub evaluation_key_root: String,
    pub public_key_root: String,
    pub key_committee_root: String,
    pub activation_height: u64,
    pub rotation_epoch: u64,
    pub pq_security_bits: u16,
    pub threshold_shares: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysetRecord {
    pub keyset_id: String,
    pub scheme: FheScheme,
    pub parameter_digest: String,
    pub evaluation_key_root: String,
    pub public_key_root: String,
    pub key_committee_root: String,
    pub activation_height: u64,
    pub rotation_epoch: u64,
    pub pq_security_bits: u16,
    pub threshold_shares: u16,
    pub accepted: bool,
}

impl KeysetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "keyset_id": self.keyset_id,
            "scheme": self.scheme.as_str(),
            "parameter_digest": self.parameter_digest,
            "evaluation_key_root": self.evaluation_key_root,
            "public_key_root": self.public_key_root,
            "key_committee_root": self.key_committee_root,
            "activation_height": self.activation_height,
            "rotation_epoch": self.rotation_epoch,
            "pq_security_bits": self.pq_security_bits,
            "threshold_shares": self.threshold_shares,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("KeysetRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextRequest {
    pub ciphertext_id: String,
    pub keyset_id: String,
    pub class: CiphertextClass,
    pub owner_commitment: String,
    pub contract_id: String,
    pub ciphertext_root: String,
    pub size_bytes: u64,
    pub noise_budget_bits: u16,
    pub created_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextRecord {
    pub ciphertext_id: String,
    pub keyset_id: String,
    pub class: CiphertextClass,
    pub owner_commitment: String,
    pub contract_id: String,
    pub ciphertext_root: String,
    pub size_bytes: u64,
    pub noise_budget_bits: u16,
    pub created_height: u64,
    pub ttl_blocks: u64,
    pub accepted: bool,
}

impl CiphertextRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "ciphertext_id": self.ciphertext_id,
            "keyset_id": self.keyset_id,
            "class": self.class.as_str(),
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "ciphertext_root": self.ciphertext_root,
            "size_bytes": self.size_bytes,
            "noise_budget_bits": self.noise_budget_bits,
            "created_height": self.created_height,
            "ttl_blocks": self.ttl_blocks,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("CiphertextRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryPlanRequest {
    pub query_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub keyset_id: String,
    pub kind: QueryKind,
    pub visibility: Visibility,
    pub input_ciphertext_ids: Vec<String>,
    pub circuit_digest: String,
    pub predicate_commitment: String,
    pub max_gas: u64,
    pub expected_output_bytes: u64,
    pub bootstrap_count: u16,
    pub min_noise_budget_bits: u16,
    pub status: QueryStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryPlanRecord {
    pub query_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub keyset_id: String,
    pub kind: QueryKind,
    pub visibility: Visibility,
    pub input_ciphertext_ids: Vec<String>,
    pub circuit_digest: String,
    pub predicate_commitment: String,
    pub max_gas: u64,
    pub expected_output_bytes: u64,
    pub bootstrap_count: u16,
    pub min_noise_budget_bits: u16,
    pub status: QueryStatus,
    pub transcript_hash: String,
    pub accepted: bool,
}

impl QueryPlanRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "query_id": self.query_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "keyset_id": self.keyset_id,
            "kind": self.kind.as_str(),
            "visibility": self.visibility.as_str(),
            "input_ciphertext_ids": self.input_ciphertext_ids,
            "circuit_digest": self.circuit_digest,
            "predicate_commitment": self.predicate_commitment,
            "max_gas": self.max_gas,
            "expected_output_bytes": self.expected_output_bytes,
            "bootstrap_count": self.bootstrap_count,
            "min_noise_budget_bits": self.min_noise_budget_bits,
            "status": self.status.as_str(),
            "transcript_hash": self.transcript_hash,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("QueryPlanRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPolicyRequest {
    pub policy_id: String,
    pub contract_id: String,
    pub mode: PolicyMode,
    pub allowed_caller_root: String,
    pub allowed_keyset_root: String,
    pub max_queries_per_epoch: u64,
    pub epoch: u64,
    pub paused: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPolicyRecord {
    pub policy_id: String,
    pub contract_id: String,
    pub mode: PolicyMode,
    pub allowed_caller_root: String,
    pub allowed_keyset_root: String,
    pub max_queries_per_epoch: u64,
    pub epoch: u64,
    pub paused: bool,
    pub accepted: bool,
}

impl AccessPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "mode": self.mode.as_str(),
            "allowed_caller_root": self.allowed_caller_root,
            "allowed_keyset_root": self.allowed_keyset_root,
            "max_queries_per_epoch": self.max_queries_per_epoch,
            "epoch": self.epoch,
            "paused": self.paused,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("AccessPolicyRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionReceiptRequest {
    pub receipt_id: String,
    pub query_id: String,
    pub executor_id: String,
    pub execution_height: u64,
    pub gas_used: u64,
    pub output_commitment_root: String,
    pub new_ciphertext_ids: Vec<String>,
    pub noise_floor_bits: u16,
    pub public_output_bytes: u64,
    pub deterministic_root: String,
    pub status: QueryStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionReceiptRecord {
    pub receipt_id: String,
    pub query_id: String,
    pub executor_id: String,
    pub execution_height: u64,
    pub gas_used: u64,
    pub output_commitment_root: String,
    pub new_ciphertext_ids: Vec<String>,
    pub noise_floor_bits: u16,
    pub public_output_bytes: u64,
    pub deterministic_root: String,
    pub status: QueryStatus,
    pub accepted: bool,
}

impl ExecutionReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "query_id": self.query_id,
            "executor_id": self.executor_id,
            "execution_height": self.execution_height,
            "gas_used": self.gas_used,
            "output_commitment_root": self.output_commitment_root,
            "new_ciphertext_ids": self.new_ciphertext_ids,
            "noise_floor_bits": self.noise_floor_bits,
            "public_output_bytes": self.public_output_bytes,
            "deterministic_root": self.deterministic_root,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("ExecutionReceiptRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofAttestationRequest {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub signer_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub status: AttestationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofAttestationRecord {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub signer_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub status: AttestationStatus,
    pub accepted: bool,
}

impl ProofAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "signer_id": self.signer_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_height": self.attested_height,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("ProofAttestationRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeQuoteRequest {
    pub quote_id: String,
    pub query_id: String,
    pub tier: FeeTier,
    pub ciphertext_bytes: u64,
    pub gas_limit: u64,
    pub bootstrap_count: u16,
    pub valid_until_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeQuoteRecord {
    pub quote_id: String,
    pub query_id: String,
    pub tier: FeeTier,
    pub ciphertext_bytes: u64,
    pub gas_limit: u64,
    pub bootstrap_count: u16,
    pub valid_until_height: u64,
    pub fee_micronebula: u64,
    pub accepted: bool,
}

impl FeeQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "query_id": self.query_id,
            "tier": self.tier.as_str(),
            "ciphertext_bytes": self.ciphertext_bytes,
            "gas_limit": self.gas_limit,
            "bootstrap_count": self.bootstrap_count,
            "valid_until_height": self.valid_until_height,
            "fee_micronebula": self.fee_micronebula,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("FeeQuoteRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShareRequest {
    pub share_id: String,
    pub query_id: String,
    pub committee_member_id: String,
    pub share_commitment_root: String,
    pub proof_root: String,
    pub reveal_after_height: u64,
    pub reveal_before_height: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShareRecord {
    pub share_id: String,
    pub query_id: String,
    pub committee_member_id: String,
    pub share_commitment_root: String,
    pub proof_root: String,
    pub reveal_after_height: u64,
    pub reveal_before_height: u64,
    pub pq_security_bits: u16,
    pub accepted: bool,
}

impl DecryptionShareRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "query_id": self.query_id,
            "committee_member_id": self.committee_member_id,
            "share_commitment_root": self.share_commitment_root,
            "proof_root": self.proof_root,
            "reveal_after_height": self.reveal_after_height,
            "reveal_before_height": self.reveal_before_height,
            "pq_security_bits": self.pq_security_bits,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("DecryptionShareRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicRootPublicationRequest {
    pub publication_id: String,
    pub kind: RootKind,
    pub epoch: u64,
    pub contract_id: String,
    pub root: String,
    pub leaf_count: u64,
    pub source_root: String,
    pub published_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicRootPublicationRecord {
    pub publication_id: String,
    pub kind: RootKind,
    pub epoch: u64,
    pub contract_id: String,
    pub root: String,
    pub leaf_count: u64,
    pub source_root: String,
    pub published_height: u64,
    pub accepted: bool,
}

impl PublicRootPublicationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "publication_id": self.publication_id,
            "kind": self.kind.as_str(),
            "epoch": self.epoch,
            "contract_id": self.contract_id,
            "root": self.root,
            "leaf_count": self.leaf_count,
            "source_root": self.source_root,
            "published_height": self.published_height,
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("PublicRootPublicationRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditSealRequest {
    pub seal_id: String,
    pub query_id: String,
    pub transcript_root: String,
    pub root_publication_id: String,
    pub fee_quote_id: String,
    pub attestation_root: String,
    pub sealed_height: u64,
    pub status: AuditSealStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditSealRecord {
    pub seal_id: String,
    pub query_id: String,
    pub transcript_root: String,
    pub root_publication_id: String,
    pub fee_quote_id: String,
    pub attestation_root: String,
    pub sealed_height: u64,
    pub status: AuditSealStatus,
    pub accepted: bool,
}

impl AuditSealRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "seal_id": self.seal_id,
            "query_id": self.query_id,
            "transcript_root": self.transcript_root,
            "root_publication_id": self.root_publication_id,
            "fee_quote_id": self.fee_quote_id,
            "attestation_root": self.attestation_root,
            "sealed_height": self.sealed_height,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("AuditSealRecord", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub keysets: BTreeMap<String, KeysetRecord>,
    pub ciphertexts: BTreeMap<String, CiphertextRecord>,
    pub query_plans: BTreeMap<String, QueryPlanRecord>,
    pub access_policies: BTreeMap<String, AccessPolicyRecord>,
    pub execution_receipts: BTreeMap<String, ExecutionReceiptRecord>,
    pub proof_attestations: BTreeMap<String, ProofAttestationRecord>,
    pub fee_quotes: BTreeMap<String, FeeQuoteRecord>,
    pub decryption_shares: BTreeMap<String, DecryptionShareRecord>,
    pub public_roots: BTreeMap<String, PublicRootPublicationRecord>,
    pub audit_seals: BTreeMap<String, AuditSealRecord>,
    pub contract_query_index: BTreeMap<String, BTreeSet<String>>,
    pub query_attestation_index: BTreeMap<String, BTreeSet<String>>,
    pub query_share_index: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            keysets: BTreeMap::new(),
            ciphertexts: BTreeMap::new(),
            query_plans: BTreeMap::new(),
            access_policies: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            proof_attestations: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            decryption_shares: BTreeMap::new(),
            public_roots: BTreeMap::new(),
            audit_seals: BTreeMap::new(),
            contract_query_index: BTreeMap::new(),
            query_attestation_index: BTreeMap::new(),
            query_share_index: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let height = state.config.devnet_height;
        let _ = state.register_keyset(KeysetRequest {
            keyset_id: "fhe-keyset-demo-001".to_string(),
            scheme: FheScheme::HybridRlweMlwe,
            parameter_digest: deterministic_id("parameter-demo", "hybrid-rlwe-mlwe"),
            evaluation_key_root: deterministic_id("eval-key-root", "demo"),
            public_key_root: deterministic_id("public-key-root", "demo"),
            key_committee_root: deterministic_id("committee-root", "demo"),
            activation_height: height,
            rotation_epoch: 1,
            pq_security_bits: state.config.target_pq_security_bits,
            threshold_shares: state.config.min_committee_shares,
        });
        let _ = state.register_access_policy(AccessPolicyRequest {
            policy_id: "policy-demo-001".to_string(),
            contract_id: "private-contract-demo".to_string(),
            mode: PolicyMode::ContractScoped,
            allowed_caller_root: deterministic_id("caller-root", "demo"),
            allowed_keyset_root: deterministic_id("keyset-root", "demo"),
            max_queries_per_epoch: 4_096,
            epoch: state.root_epoch(height),
            paused: false,
        });
        for (idx, class) in [
            CiphertextClass::Input,
            CiphertextClass::StateCell,
            CiphertextClass::Accumulator,
        ]
        .into_iter()
        .enumerate()
        {
            let _ = state.register_ciphertext(CiphertextRequest {
                ciphertext_id: format!("ct-demo-{idx:03}"),
                keyset_id: "fhe-keyset-demo-001".to_string(),
                class,
                owner_commitment: deterministic_id("owner", &idx.to_string()),
                contract_id: "private-contract-demo".to_string(),
                ciphertext_root: deterministic_id("ct-root", &idx.to_string()),
                size_bytes: 24_576,
                noise_budget_bits: 144,
                created_height: height,
                ttl_blocks: 720,
            });
        }
        let _ = state.commit_query_plan(QueryPlanRequest {
            query_id: "query-demo-001".to_string(),
            contract_id: "private-contract-demo".to_string(),
            caller_commitment: deterministic_id("caller", "demo"),
            keyset_id: "fhe-keyset-demo-001".to_string(),
            kind: QueryKind::ContractStoragePredicate,
            visibility: Visibility::PredicateOnly,
            input_ciphertext_ids: vec![
                "ct-demo-000".to_string(),
                "ct-demo-001".to_string(),
                "ct-demo-002".to_string(),
            ],
            circuit_digest: deterministic_id("circuit", "storage-predicate"),
            predicate_commitment: deterministic_id("predicate", "demo"),
            max_gas: 1_250_000,
            expected_output_bytes: 96,
            bootstrap_count: 1,
            min_noise_budget_bits: 128,
            status: QueryStatus::Committed,
        });
        let _ = state.quote_fee(FeeQuoteRequest {
            quote_id: "quote-demo-001".to_string(),
            query_id: "query-demo-001".to_string(),
            tier: FeeTier::Low,
            ciphertext_bytes: 73_728,
            gas_limit: 1_250_000,
            bootstrap_count: 1,
            valid_until_height: height + 32,
        });
        let deterministic_root = state.deterministic_query_root("query-demo-001");
        let _ = state.record_execution_receipt(ExecutionReceiptRequest {
            receipt_id: "receipt-demo-001".to_string(),
            query_id: "query-demo-001".to_string(),
            executor_id: "executor-demo-a".to_string(),
            execution_height: height + 1,
            gas_used: 811_000,
            output_commitment_root: deterministic_id("output-root", "demo"),
            new_ciphertext_ids: vec!["ct-output-demo-001".to_string()],
            noise_floor_bits: 118,
            public_output_bytes: 64,
            deterministic_root,
            status: QueryStatus::Executed,
        });
        for signer in [
            "attester-a",
            "attester-b",
            "attester-c",
            "attester-d",
            "attester-e",
        ] {
            let _ = state.record_proof_attestation(ProofAttestationRequest {
                attestation_id: format!("attestation-demo-{signer}"),
                kind: AttestationKind::ExecutionTrace,
                signer_id: signer.to_string(),
                subject_id: "query-demo-001".to_string(),
                subject_root: state.deterministic_query_root("query-demo-001"),
                signature_root: deterministic_id("signature", signer),
                pq_security_bits: state.config.target_pq_security_bits,
                attested_height: height + 2,
                status: AttestationStatus::Accepted,
            });
        }
        for member in ["member-a", "member-b", "member-c"] {
            let _ = state.record_decryption_share(DecryptionShareRequest {
                share_id: format!("share-demo-{member}"),
                query_id: "query-demo-001".to_string(),
                committee_member_id: member.to_string(),
                share_commitment_root: deterministic_id("share", member),
                proof_root: deterministic_id("share-proof", member),
                reveal_after_height: height + 3,
                reveal_before_height: height + 48,
                pq_security_bits: state.config.target_pq_security_bits,
            });
        }
        let _ = state.publish_public_root(PublicRootPublicationRequest {
            publication_id: "root-demo-001".to_string(),
            kind: RootKind::QueryBatch,
            epoch: state.root_epoch(height),
            contract_id: "private-contract-demo".to_string(),
            root: state.deterministic_query_root("query-demo-001"),
            leaf_count: 1,
            source_root: state.roots.query_plan_root.clone(),
            published_height: height + 3,
        });
        let _ = state.seal_audit(AuditSealRequest {
            seal_id: "seal-demo-001".to_string(),
            query_id: "query-demo-001".to_string(),
            transcript_root: state.deterministic_query_root("query-demo-001"),
            root_publication_id: "root-demo-001".to_string(),
            fee_quote_id: "quote-demo-001".to_string(),
            attestation_root: state.roots.proof_attestation_root.clone(),
            sealed_height: height + 4,
            status: AuditSealStatus::Published,
        });
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "keysets": self.keysets.values().map(KeysetRecord::public_record).collect::<Vec<_>>(),
            "ciphertexts": self.ciphertexts.values().map(CiphertextRecord::public_record).collect::<Vec<_>>(),
            "query_plans": self.query_plans.values().map(QueryPlanRecord::public_record).collect::<Vec<_>>(),
            "access_policies": self.access_policies.values().map(AccessPolicyRecord::public_record).collect::<Vec<_>>(),
            "execution_receipts": self.execution_receipts.values().map(ExecutionReceiptRecord::public_record).collect::<Vec<_>>(),
            "proof_attestations": self.proof_attestations.values().map(ProofAttestationRecord::public_record).collect::<Vec<_>>(),
            "fee_quotes": self.fee_quotes.values().map(FeeQuoteRecord::public_record).collect::<Vec<_>>(),
            "decryption_shares": self.decryption_shares.values().map(DecryptionShareRecord::public_record).collect::<Vec<_>>(),
            "public_roots": self.public_roots.values().map(PublicRootPublicationRecord::public_record).collect::<Vec<_>>(),
            "audit_seals": self.audit_seals.values().map(AuditSealRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn register_keyset(&mut self, request: KeysetRequest) -> Result<KeysetRecord> {
        self.ensure_capacity(self.keysets.len(), MAX_KEYSETS, "keysets")?;
        ensure_non_empty(&request.keyset_id, "keyset_id")?;
        let accepted = request.pq_security_bits >= self.config.target_pq_security_bits
            && request.threshold_shares >= self.config.min_committee_shares
            && !request.parameter_digest.is_empty()
            && !request.public_key_root.is_empty()
            && !request.evaluation_key_root.is_empty();
        let record = KeysetRecord {
            keyset_id: request.keyset_id,
            scheme: request.scheme,
            parameter_digest: request.parameter_digest,
            evaluation_key_root: request.evaluation_key_root,
            public_key_root: request.public_key_root,
            key_committee_root: request.key_committee_root,
            activation_height: request.activation_height,
            rotation_epoch: request.rotation_epoch,
            pq_security_bits: request.pq_security_bits,
            threshold_shares: request.threshold_shares,
            accepted,
        };
        if accepted {
            self.counters.keysets = self.counters.keysets.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.keysets
            .insert(record.keyset_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_ciphertext(&mut self, request: CiphertextRequest) -> Result<CiphertextRecord> {
        self.ensure_capacity(self.ciphertexts.len(), MAX_CIPHERTEXTS, "ciphertexts")?;
        ensure_non_empty(&request.ciphertext_id, "ciphertext_id")?;
        let accepted = self
            .keysets
            .get(&request.keyset_id)
            .map(|keyset| keyset.accepted)
            .unwrap_or(false)
            && request.size_bytes <= self.config.max_ciphertext_bytes
            && request.noise_budget_bits >= self.config.min_noise_budget_bits
            && !request.ciphertext_root.is_empty();
        let record = CiphertextRecord {
            ciphertext_id: request.ciphertext_id,
            keyset_id: request.keyset_id,
            class: request.class,
            owner_commitment: request.owner_commitment,
            contract_id: request.contract_id,
            ciphertext_root: request.ciphertext_root,
            size_bytes: request.size_bytes,
            noise_budget_bits: request.noise_budget_bits,
            created_height: request.created_height,
            ttl_blocks: request.ttl_blocks,
            accepted,
        };
        if accepted {
            self.counters.ciphertexts = self.counters.ciphertexts.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.ciphertexts
            .insert(record.ciphertext_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn commit_query_plan(&mut self, request: QueryPlanRequest) -> Result<QueryPlanRecord> {
        self.ensure_capacity(self.query_plans.len(), MAX_QUERY_PLANS, "query_plans")?;
        ensure_non_empty(&request.query_id, "query_id")?;
        let all_inputs_known = request.input_ciphertext_ids.iter().all(|id| {
            self.ciphertexts
                .get(id)
                .map(|ciphertext| ciphertext.accepted && ciphertext.keyset_id == request.keyset_id)
                .unwrap_or(false)
        });
        let transcript_hash = query_transcript_hash(&request);
        let accepted = all_inputs_known
            && self
                .keysets
                .get(&request.keyset_id)
                .map(|keyset| keyset.accepted)
                .unwrap_or(false)
            && request.status.is_live()
            && request.max_gas <= self.config.max_query_gas
            && request.expected_output_bytes <= self.config.max_public_output_bytes
            && request.bootstrap_count <= self.config.max_bootstraps_per_query
            && request.min_noise_budget_bits >= self.config.min_noise_budget_bits
            && !request.circuit_digest.is_empty();
        let record = QueryPlanRecord {
            query_id: request.query_id,
            contract_id: request.contract_id,
            caller_commitment: request.caller_commitment,
            keyset_id: request.keyset_id,
            kind: request.kind,
            visibility: request.visibility,
            input_ciphertext_ids: sorted_strings(request.input_ciphertext_ids),
            circuit_digest: request.circuit_digest,
            predicate_commitment: request.predicate_commitment,
            max_gas: request.max_gas,
            expected_output_bytes: request.expected_output_bytes,
            bootstrap_count: request.bootstrap_count,
            min_noise_budget_bits: request.min_noise_budget_bits,
            status: request.status,
            transcript_hash,
            accepted,
        };
        if accepted {
            self.counters.query_plans = self.counters.query_plans.saturating_add(1);
            self.counters.accepted_queries = self.counters.accepted_queries.saturating_add(1);
            self.contract_query_index
                .entry(record.contract_id.clone())
                .or_default()
                .insert(record.query_id.clone());
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.query_plans
            .insert(record.query_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_access_policy(
        &mut self,
        request: AccessPolicyRequest,
    ) -> Result<AccessPolicyRecord> {
        self.ensure_capacity(
            self.access_policies.len(),
            MAX_ACCESS_POLICIES,
            "access_policies",
        )?;
        ensure_non_empty(&request.policy_id, "policy_id")?;
        let accepted = !request.contract_id.is_empty()
            && request.max_queries_per_epoch > 0
            && !matches!(request.mode, PolicyMode::EmergencyPaused) == !request.paused;
        let record = AccessPolicyRecord {
            policy_id: request.policy_id,
            contract_id: request.contract_id,
            mode: request.mode,
            allowed_caller_root: request.allowed_caller_root,
            allowed_keyset_root: request.allowed_keyset_root,
            max_queries_per_epoch: request.max_queries_per_epoch,
            epoch: request.epoch,
            paused: request.paused,
            accepted,
        };
        if accepted {
            self.counters.access_policies = self.counters.access_policies.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.access_policies
            .insert(record.policy_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_execution_receipt(
        &mut self,
        request: ExecutionReceiptRequest,
    ) -> Result<ExecutionReceiptRecord> {
        self.ensure_capacity(
            self.execution_receipts.len(),
            MAX_EXECUTION_RECEIPTS,
            "execution_receipts",
        )?;
        ensure_non_empty(&request.receipt_id, "receipt_id")?;
        let expected_root = self.deterministic_query_root(&request.query_id);
        let accepted = self
            .query_plans
            .get(&request.query_id)
            .map(|query| query.accepted)
            .unwrap_or(false)
            && request.gas_used <= self.config.max_query_gas
            && request.noise_floor_bits >= self.config.min_noise_budget_bits
            && request.public_output_bytes <= self.config.max_public_output_bytes
            && request.status == QueryStatus::Executed
            && (!self.config.deterministic_public_roots
                || request.deterministic_root == expected_root);
        let record = ExecutionReceiptRecord {
            receipt_id: request.receipt_id,
            query_id: request.query_id,
            executor_id: request.executor_id,
            execution_height: request.execution_height,
            gas_used: request.gas_used,
            output_commitment_root: request.output_commitment_root,
            new_ciphertext_ids: sorted_strings(request.new_ciphertext_ids),
            noise_floor_bits: request.noise_floor_bits,
            public_output_bytes: request.public_output_bytes,
            deterministic_root: request.deterministic_root,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.execution_receipts = self.counters.execution_receipts.saturating_add(1);
            self.counters.settled_queries = self.counters.settled_queries.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.execution_receipts
            .insert(record.receipt_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_proof_attestation(
        &mut self,
        request: ProofAttestationRequest,
    ) -> Result<ProofAttestationRecord> {
        self.ensure_capacity(
            self.proof_attestations.len(),
            MAX_PROOF_ATTESTATIONS,
            "proof_attestations",
        )?;
        ensure_non_empty(&request.attestation_id, "attestation_id")?;
        let accepted = request.pq_security_bits >= self.config.target_pq_security_bits
            && matches!(
                request.status,
                AttestationStatus::Observed | AttestationStatus::Accepted
            )
            && !request.signature_root.is_empty()
            && !request.subject_root.is_empty();
        let record = ProofAttestationRecord {
            attestation_id: request.attestation_id,
            kind: request.kind,
            signer_id: request.signer_id,
            subject_id: request.subject_id,
            subject_root: request.subject_root,
            signature_root: request.signature_root,
            pq_security_bits: request.pq_security_bits,
            attested_height: request.attested_height,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.proof_attestations = self.counters.proof_attestations.saturating_add(1);
            self.counters.accepted_attestations =
                self.counters.accepted_attestations.saturating_add(1);
            self.query_attestation_index
                .entry(record.subject_id.clone())
                .or_default()
                .insert(record.signer_id.clone());
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.proof_attestations
            .insert(record.attestation_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn quote_fee(&mut self, request: FeeQuoteRequest) -> Result<FeeQuoteRecord> {
        self.ensure_capacity(self.fee_quotes.len(), MAX_FEE_QUOTES, "fee_quotes")?;
        ensure_non_empty(&request.quote_id, "quote_id")?;
        let fee_micronebula = self.compute_fee_micronebula(
            request.tier,
            request.ciphertext_bytes,
            request.gas_limit,
            request.bootstrap_count,
        );
        let accepted = self
            .query_plans
            .get(&request.query_id)
            .map(|query| query.accepted)
            .unwrap_or(false)
            && request.ciphertext_bytes <= self.config.max_ciphertext_bytes.saturating_mul(8)
            && request.gas_limit <= self.config.max_query_gas
            && request.bootstrap_count <= self.config.max_bootstraps_per_query
            && (self.config.allow_devnet_free_tier || request.tier != FeeTier::FreeDevnet);
        let record = FeeQuoteRecord {
            quote_id: request.quote_id,
            query_id: request.query_id,
            tier: request.tier,
            ciphertext_bytes: request.ciphertext_bytes,
            gas_limit: request.gas_limit,
            bootstrap_count: request.bootstrap_count,
            valid_until_height: request.valid_until_height,
            fee_micronebula,
            accepted,
        };
        if accepted {
            self.counters.fee_quotes = self.counters.fee_quotes.saturating_add(1);
            if matches!(
                record.tier,
                FeeTier::FreeDevnet | FeeTier::Low | FeeTier::BatchDiscount
            ) {
                self.counters.low_fee_quotes = self.counters.low_fee_quotes.saturating_add(1);
            }
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.fee_quotes
            .insert(record.quote_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_decryption_share(
        &mut self,
        request: DecryptionShareRequest,
    ) -> Result<DecryptionShareRecord> {
        self.ensure_capacity(
            self.decryption_shares.len(),
            MAX_DECRYPTION_SHARES,
            "decryption_shares",
        )?;
        ensure_non_empty(&request.share_id, "share_id")?;
        let accepted = self
            .query_plans
            .get(&request.query_id)
            .map(|query| query.accepted)
            .unwrap_or(false)
            && request.reveal_before_height > request.reveal_after_height
            && request.reveal_before_height - request.reveal_after_height
                <= self.config.max_reveal_delay_blocks
            && request.pq_security_bits >= self.config.target_pq_security_bits
            && !request.share_commitment_root.is_empty()
            && !request.proof_root.is_empty();
        let record = DecryptionShareRecord {
            share_id: request.share_id,
            query_id: request.query_id,
            committee_member_id: request.committee_member_id,
            share_commitment_root: request.share_commitment_root,
            proof_root: request.proof_root,
            reveal_after_height: request.reveal_after_height,
            reveal_before_height: request.reveal_before_height,
            pq_security_bits: request.pq_security_bits,
            accepted,
        };
        if accepted {
            self.counters.decryption_shares = self.counters.decryption_shares.saturating_add(1);
            self.query_share_index
                .entry(record.query_id.clone())
                .or_default()
                .insert(record.committee_member_id.clone());
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.decryption_shares
            .insert(record.share_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn publish_public_root(
        &mut self,
        request: PublicRootPublicationRequest,
    ) -> Result<PublicRootPublicationRecord> {
        self.ensure_capacity(self.public_roots.len(), MAX_PUBLIC_ROOTS, "public_roots")?;
        ensure_non_empty(&request.publication_id, "publication_id")?;
        let accepted = self.config.deterministic_public_roots
            && !request.root.is_empty()
            && !request.source_root.is_empty()
            && request.leaf_count > 0;
        let record = PublicRootPublicationRecord {
            publication_id: request.publication_id,
            kind: request.kind,
            epoch: request.epoch,
            contract_id: request.contract_id,
            root: request.root,
            leaf_count: request.leaf_count,
            source_root: request.source_root,
            published_height: request.published_height,
            accepted,
        };
        if accepted {
            self.counters.public_roots = self.counters.public_roots.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.public_roots
            .insert(record.publication_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn seal_audit(&mut self, request: AuditSealRequest) -> Result<AuditSealRecord> {
        self.ensure_capacity(self.audit_seals.len(), MAX_AUDIT_SEALS, "audit_seals")?;
        ensure_non_empty(&request.seal_id, "seal_id")?;
        let accepted = self
            .query_plans
            .get(&request.query_id)
            .map(|query| query.accepted)
            .unwrap_or(false)
            && self
                .public_roots
                .get(&request.root_publication_id)
                .map(|root| root.accepted)
                .unwrap_or(false)
            && self
                .fee_quotes
                .get(&request.fee_quote_id)
                .map(|quote| quote.accepted)
                .unwrap_or(false)
            && matches!(
                request.status,
                AuditSealStatus::Sealed | AuditSealStatus::Published
            );
        let record = AuditSealRecord {
            seal_id: request.seal_id,
            query_id: request.query_id,
            transcript_root: request.transcript_root,
            root_publication_id: request.root_publication_id,
            fee_quote_id: request.fee_quote_id,
            attestation_root: request.attestation_root,
            sealed_height: request.sealed_height,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.audit_seals = self.counters.audit_seals.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.audit_seals
            .insert(record.seal_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn compute_fee_micronebula(
        &self,
        tier: FeeTier,
        ciphertext_bytes: u64,
        gas_limit: u64,
        bootstrap_count: u16,
    ) -> u64 {
        let byte_fee = ciphertext_bytes.saturating_mul(self.config.byte_fee_micronebula);
        let gas_fee = gas_limit.saturating_div(1_000);
        let bootstrap_fee =
            u64::from(bootstrap_count).saturating_mul(self.config.bootstrap_fee_micronebula);
        let raw_fee = self
            .config
            .base_fee_micronebula
            .saturating_add(byte_fee)
            .saturating_add(gas_fee)
            .saturating_add(bootstrap_fee);
        raw_fee.saturating_mul(tier.multiplier_bps()) / 10_000
    }

    pub fn root_epoch(&self, height: u64) -> u64 {
        if self.config.root_epoch_blocks == 0 {
            return 0;
        }
        height / self.config.root_epoch_blocks
    }

    pub fn attestation_quorum_met(&self, subject_id: &str) -> bool {
        match self.query_attestation_index.get(subject_id) {
            Some(signers) => signers.len() >= usize::from(self.config.min_attestation_quorum),
            None => false,
        }
    }

    pub fn decryption_share_threshold_met(&self, query_id: &str) -> bool {
        match self.query_share_index.get(query_id) {
            Some(members) => members.len() >= usize::from(self.config.min_committee_shares),
            None => false,
        }
    }

    pub fn deterministic_query_root(&self, query_id: &str) -> String {
        let query = self
            .query_plans
            .get(query_id)
            .map(QueryPlanRecord::public_record);
        let receipt_records = self
            .execution_receipts
            .values()
            .filter(|receipt| receipt.query_id == query_id)
            .map(ExecutionReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .proof_attestations
            .values()
            .filter(|attestation| attestation.subject_id == query_id)
            .map(ProofAttestationRecord::public_record)
            .collect::<Vec<_>>();
        value_root(
            "deterministic_query_root",
            &json!({
                "query_id": query_id,
                "query": query,
                "execution_receipts": receipt_records,
                "proof_attestations": attestation_records,
            }),
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = value_root("config", &self.config.public_record());
        self.roots.keyset_root = record_root(
            "keysets",
            self.keysets.values().map(KeysetRecord::public_record),
        );
        self.roots.ciphertext_root = record_root(
            "ciphertexts",
            self.ciphertexts
                .values()
                .map(CiphertextRecord::public_record),
        );
        self.roots.query_plan_root = record_root(
            "query_plans",
            self.query_plans
                .values()
                .map(QueryPlanRecord::public_record),
        );
        self.roots.access_policy_root = record_root(
            "access_policies",
            self.access_policies
                .values()
                .map(AccessPolicyRecord::public_record),
        );
        self.roots.execution_receipt_root = record_root(
            "execution_receipts",
            self.execution_receipts
                .values()
                .map(ExecutionReceiptRecord::public_record),
        );
        self.roots.proof_attestation_root = record_root(
            "proof_attestations",
            self.proof_attestations
                .values()
                .map(ProofAttestationRecord::public_record),
        );
        self.roots.fee_quote_root = record_root(
            "fee_quotes",
            self.fee_quotes.values().map(FeeQuoteRecord::public_record),
        );
        self.roots.decryption_share_root = record_root(
            "decryption_shares",
            self.decryption_shares
                .values()
                .map(DecryptionShareRecord::public_record),
        );
        self.roots.public_root_publication_root = record_root(
            "public_root_publications",
            self.public_roots
                .values()
                .map(PublicRootPublicationRecord::public_record),
        );
        self.roots.audit_seal_root = record_root(
            "audit_seals",
            self.audit_seals
                .values()
                .map(AuditSealRecord::public_record),
        );
        self.roots.indexes_root = value_root(
            "indexes",
            &json!({
                "contract_query_index": set_index_record(&self.contract_query_index),
                "query_attestation_index": set_index_record(&self.query_attestation_index),
                "query_share_index": set_index_record(&self.query_share_index),
            }),
        );
        self.roots.counters_root = value_root("counters", &self.counters.public_record());
        self.roots.state_root = value_root(
            "state",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "config_root": self.roots.config_root,
                "keyset_root": self.roots.keyset_root,
                "ciphertext_root": self.roots.ciphertext_root,
                "query_plan_root": self.roots.query_plan_root,
                "access_policy_root": self.roots.access_policy_root,
                "execution_receipt_root": self.roots.execution_receipt_root,
                "proof_attestation_root": self.roots.proof_attestation_root,
                "fee_quote_root": self.roots.fee_quote_root,
                "decryption_share_root": self.roots.decryption_share_root,
                "public_root_publication_root": self.roots.public_root_publication_root,
                "audit_seal_root": self.roots.audit_seal_root,
                "indexes_root": self.roots.indexes_root,
                "counters_root": self.roots.counters_root,
            }),
        );
    }

    fn ensure_capacity(&mut self, len: usize, max: usize, label: &str) -> Result<()> {
        if len >= max {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

pub fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-FHE-DETERMINISTIC-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn query_transcript_hash(request: &QueryPlanRequest) -> String {
    let inputs = sorted_strings(request.input_ciphertext_ids.clone());
    let record = json!({
        "query_id": request.query_id,
        "contract_id": request.contract_id,
        "caller_commitment": request.caller_commitment,
        "keyset_id": request.keyset_id,
        "kind": request.kind.as_str(),
        "visibility": request.visibility.as_str(),
        "input_ciphertext_ids": inputs,
        "circuit_digest": request.circuit_digest,
        "predicate_commitment": request.predicate_commitment,
        "max_gas": request.max_gas,
        "expected_output_bytes": request.expected_output_bytes,
        "bootstrap_count": request.bootstrap_count,
        "min_noise_budget_bits": request.min_noise_budget_bits,
        "status": request.status.as_str(),
    });
    domain_hash(
        "PRIVATE-L2-FHE-QUERY-TRANSCRIPT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(TRANSCRIPT_SCHEME),
            HashPart::Json(&record),
        ],
        32,
    )
}

pub fn value_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FHE-{domain}-ROOT"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn record_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let mut leaves = records.into_iter().collect::<Vec<_>>();
    leaves.sort_by(|left, right| canonical_json(left).cmp(&canonical_json(right)));
    if leaves.is_empty() {
        return empty_root(domain);
    }
    merkle_root(&format!("PRIVATE-L2-FHE-{domain}"), &leaves)
}

pub fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FHE-{domain}-EMPTY"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(HASH_SUITE)],
        32,
    )
}

fn stable_digest(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FHE-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(record),
        ],
        32,
    )
}

fn canonical_json(value: &Value) -> String {
    match serde_json::to_string(value) {
        Ok(encoded) => encoded,
        Err(error) => format!("serde-json-error:{error}"),
    }
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(())
}

fn set_index_record(index: &BTreeMap<String, BTreeSet<String>>) -> Value {
    let entries = index
        .iter()
        .map(|(key, values)| {
            json!({
                "key": key,
                "values": values.iter().cloned().collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    json!(entries)
}
