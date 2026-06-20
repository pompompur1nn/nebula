use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateStateOracleMeshRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STATE_ORACLE_MESH_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-private-state-oracle-mesh-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STATE_ORACLE_MESH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_QUERY_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-state-query-attestation-v1";
pub const ENCRYPTED_QUERY_SUITE: &str =
    "ML-KEM-1024+Poseidon2-transcript+AEAD-confidential-contract-state-query-v1";
pub const PRIVATE_STATE_ROOT_SUITE: &str =
    "contract-private-state-sparse-merkle-root-commitment-v1";
pub const CALLBACK_RECEIPT_SUITE: &str =
    "confidential-contract-private-state-oracle-callback-receipt-v1";
pub const ACCESS_BUDGET_SUITE: &str = "private-state-oracle-access-budget-nullifier-v1";
pub const FEE_SPONSOR_SUITE: &str = "private-state-oracle-fee-sponsor-authorization-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "private-state-oracle-redaction-budget-and-disclosure-window-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "deterministic-private-state-oracle-mesh-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 2_240_128;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_QUERY_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_ROOT_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_ACCESS_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 10_080;
pub const DEFAULT_MIN_COMMITTEE_MEMBERS: u64 = 5;
pub const DEFAULT_MIN_ATTESTER_WEIGHT: u64 = 7;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_QUERY_BYTES: u64 = 131_072;
pub const DEFAULT_MAX_CALLBACK_BYTES: u64 = 65_536;
pub const DEFAULT_BASE_QUERY_FEE_MICRO_CREDITS: u128 = 3_500;
pub const DEFAULT_CALLBACK_FEE_MICRO_CREDITS: u128 = 1_250;
pub const DEFAULT_REDACTION_FEE_MICRO_CREDITS: u128 = 800;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 650;
pub const DEFAULT_OPERATOR_REBATE_BPS: u64 = 350;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_CONTRACTS: usize = 1_048_576;
pub const MAX_COMMITTEES: usize = 262_144;
pub const MAX_ORACLE_MEMBERS: usize = 4_194_304;
pub const MAX_PRIVATE_ROOTS: usize = 8_388_608;
pub const MAX_ENCRYPTED_QUERIES: usize = 16_777_216;
pub const MAX_ATTESTATIONS: usize = 33_554_432;
pub const MAX_CALLBACK_RECEIPTS: usize = 16_777_216;
pub const MAX_ACCESS_BUDGETS: usize = 8_388_608;
pub const MAX_FEE_SPONSORS: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 8_388_608;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Dex,
    Lending,
    Perpetuals,
    Bridge,
    Governance,
    AccountAbstraction,
    TokenRegistry,
    ComplianceVault,
    CrossRollup,
    Custom,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::AccountAbstraction => "account_abstraction",
            Self::TokenRegistry => "token_registry",
            Self::ComplianceVault => "compliance_vault",
            Self::CrossRollup => "cross_rollup",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Proposed,
    Active,
    Throttled,
    Paused,
    Draining,
    Retired,
}

impl ContractStatus {
    pub fn accepts_queries(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteePurpose {
    StateRootWitness,
    QueryDecrypt,
    CallbackExecutor,
    RedactionReviewer,
    FeeSponsor,
    Watchtower,
    EmergencySigner,
}

impl CommitteePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateRootWitness => "state_root_witness",
            Self::QueryDecrypt => "query_decrypt",
            Self::CallbackExecutor => "callback_executor",
            Self::RedactionReviewer => "redaction_reviewer",
            Self::FeeSponsor => "fee_sponsor",
            Self::Watchtower => "watchtower",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Pending,
    Active,
    Degraded,
    Suspended,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn can_vote(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    StorageSlot,
    PrivateMapping,
    NullifierSet,
    NoteCommitment,
    AccountPolicy,
    RiskMetric,
    TokenBalance,
    BridgeReserve,
    EventCursor,
    Composite,
}

impl QueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StorageSlot => "storage_slot",
            Self::PrivateMapping => "private_mapping",
            Self::NullifierSet => "nullifier_set",
            Self::NoteCommitment => "note_commitment",
            Self::AccountPolicy => "account_policy",
            Self::RiskMetric => "risk_metric",
            Self::TokenBalance => "token_balance",
            Self::BridgeReserve => "bridge_reserve",
            Self::EventCursor => "event_cursor",
            Self::Composite => "composite",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::StorageSlot => 8,
            Self::PrivateMapping => 12,
            Self::NullifierSet => 18,
            Self::NoteCommitment => 14,
            Self::AccountPolicy => 9,
            Self::RiskMetric => 16,
            Self::TokenBalance => 10,
            Self::BridgeReserve => 20,
            Self::EventCursor => 6,
            Self::Composite => 24,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Encrypted,
    BudgetReserved,
    Attested,
    Sponsored,
    Routed,
    Fulfilled,
    Redacted,
    Disputed,
    Expired,
    Cancelled,
}

impl QueryStatus {
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::BudgetReserved
                | Self::Attested
                | Self::Sponsored
                | Self::Routed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootStatus {
    Proposed,
    Witnessed,
    Active,
    Superseded,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    QueryWellFormed,
    AccessAuthorized,
    StateRootFresh,
    CommitteeQuorum,
    CallbackSafe,
    RedactionAllowed,
    SponsorApproved,
    EmergencyOverride,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWeight,
    Quarantined,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackStatus {
    Pending,
    Executed,
    Delivered,
    Redacted,
    Reverted,
    Expired,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    Exhausted,
    Frozen,
    Refunded,
    Expired,
}

impl BudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Proposed,
    Active,
    Depleted,
    Suspended,
    Retired,
}

impl SponsorStatus {
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionReason {
    CallerPrivacy,
    TradeSecret,
    ComplianceHold,
    CommitteeSafety,
    EmergencyCircuit,
    ExpiredConsent,
    Custom,
}

impl RedactionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallerPrivacy => "caller_privacy",
            Self::TradeSecret => "trade_secret",
            Self::ComplianceHold => "compliance_hold",
            Self::CommitteeSafety => "committee_safety",
            Self::EmergencyCircuit => "emergency_circuit",
            Self::ExpiredConsent => "expired_consent",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_query_suite: String,
    pub pq_query_attestation_suite: String,
    pub private_state_root_suite: String,
    pub callback_receipt_suite: String,
    pub access_budget_suite: String,
    pub fee_sponsor_suite: String,
    pub redaction_budget_suite: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub query_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub callback_ttl_blocks: u64,
    pub root_ttl_blocks: u64,
    pub access_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub min_committee_members: u64,
    pub min_attester_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_query_bytes: u64,
    pub max_callback_bytes: u64,
    pub base_query_fee_micro_credits: u128,
    pub callback_fee_micro_credits: u128,
    pub redaction_fee_micro_credits: u128,
    pub sponsor_rebate_bps: u64,
    pub operator_rebate_bps: u64,
    pub max_contracts: usize,
    pub max_committees: usize,
    pub max_oracle_members: usize,
    pub max_private_roots: usize,
    pub max_encrypted_queries: usize,
    pub max_attestations: usize,
    pub max_callback_receipts: usize,
    pub max_access_budgets: usize,
    pub max_fee_sponsors: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_query_suite: ENCRYPTED_QUERY_SUITE.to_string(),
            pq_query_attestation_suite: PQ_QUERY_ATTESTATION_SUITE.to_string(),
            private_state_root_suite: PRIVATE_STATE_ROOT_SUITE.to_string(),
            callback_receipt_suite: CALLBACK_RECEIPT_SUITE.to_string(),
            access_budget_suite: ACCESS_BUDGET_SUITE.to_string(),
            fee_sponsor_suite: FEE_SPONSOR_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            query_ttl_blocks: DEFAULT_QUERY_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            callback_ttl_blocks: DEFAULT_CALLBACK_TTL_BLOCKS,
            root_ttl_blocks: DEFAULT_ROOT_TTL_BLOCKS,
            access_window_blocks: DEFAULT_ACCESS_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            min_committee_members: DEFAULT_MIN_COMMITTEE_MEMBERS,
            min_attester_weight: DEFAULT_MIN_ATTESTER_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_query_bytes: DEFAULT_MAX_QUERY_BYTES,
            max_callback_bytes: DEFAULT_MAX_CALLBACK_BYTES,
            base_query_fee_micro_credits: DEFAULT_BASE_QUERY_FEE_MICRO_CREDITS,
            callback_fee_micro_credits: DEFAULT_CALLBACK_FEE_MICRO_CREDITS,
            redaction_fee_micro_credits: DEFAULT_REDACTION_FEE_MICRO_CREDITS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            operator_rebate_bps: DEFAULT_OPERATOR_REBATE_BPS,
            max_contracts: MAX_CONTRACTS,
            max_committees: MAX_COMMITTEES,
            max_oracle_members: MAX_ORACLE_MEMBERS,
            max_private_roots: MAX_PRIVATE_ROOTS,
            max_encrypted_queries: MAX_ENCRYPTED_QUERIES,
            max_attestations: MAX_ATTESTATIONS,
            max_callback_receipts: MAX_CALLBACK_RECEIPTS,
            max_access_budgets: MAX_ACCESS_BUDGETS,
            max_fee_sponsors: MAX_FEE_SPONSORS,
            max_redaction_budgets: MAX_REDACTION_BUDGETS,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
        }
    }
}

impl PublicRecord for Config {
    fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "encrypted_query_suite": self.encrypted_query_suite,
            "pq_query_attestation_suite": self.pq_query_attestation_suite,
            "private_state_root_suite": self.private_state_root_suite,
            "callback_receipt_suite": self.callback_receipt_suite,
            "access_budget_suite": self.access_budget_suite,
            "fee_sponsor_suite": self.fee_sponsor_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "public_record_scheme": self.public_record_scheme,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "query_ttl_blocks": self.query_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "callback_ttl_blocks": self.callback_ttl_blocks,
            "root_ttl_blocks": self.root_ttl_blocks,
            "access_window_blocks": self.access_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "min_committee_members": self.min_committee_members,
            "min_attester_weight": self.min_attester_weight,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_query_bytes": self.max_query_bytes,
            "max_callback_bytes": self.max_callback_bytes,
            "base_query_fee_micro_credits": self.base_query_fee_micro_credits.to_string(),
            "callback_fee_micro_credits": self.callback_fee_micro_credits.to_string(),
            "redaction_fee_micro_credits": self.redaction_fee_micro_credits.to_string(),
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "operator_rebate_bps": self.operator_rebate_bps,
            "max_contracts": self.max_contracts,
            "max_committees": self.max_committees,
            "max_oracle_members": self.max_oracle_members,
            "max_private_roots": self.max_private_roots,
            "max_encrypted_queries": self.max_encrypted_queries,
            "max_attestations": self.max_attestations,
            "max_callback_receipts": self.max_callback_receipts,
            "max_access_budgets": self.max_access_budgets,
            "max_fee_sponsors": self.max_fee_sponsors,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_operator_summaries": self.max_operator_summaries
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub contracts: u64,
    pub committees: u64,
    pub oracle_members: u64,
    pub private_state_roots: u64,
    pub encrypted_queries: u64,
    pub pq_query_attestations: u64,
    pub callback_receipts: u64,
    pub access_budgets: u64,
    pub fee_sponsors: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub fulfilled_queries: u64,
    pub disputed_queries: u64,
    pub redacted_callbacks: u64,
    pub sponsored_fees_micro_credits: u128,
    pub consumed_access_units: u64,
    pub consumed_redaction_units: u64,
}

impl PublicRecord for Counters {
    fn public_record(&self) -> Value {
        json!({
            "contracts": self.contracts,
            "committees": self.committees,
            "oracle_members": self.oracle_members,
            "private_state_roots": self.private_state_roots,
            "encrypted_queries": self.encrypted_queries,
            "pq_query_attestations": self.pq_query_attestations,
            "callback_receipts": self.callback_receipts,
            "access_budgets": self.access_budgets,
            "fee_sponsors": self.fee_sponsors,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "fulfilled_queries": self.fulfilled_queries,
            "disputed_queries": self.disputed_queries,
            "redacted_callbacks": self.redacted_callbacks,
            "sponsored_fees_micro_credits": self.sponsored_fees_micro_credits.to_string(),
            "consumed_access_units": self.consumed_access_units,
            "consumed_redaction_units": self.consumed_redaction_units
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub contracts_root: String,
    pub committees_root: String,
    pub oracle_members_root: String,
    pub private_state_roots_root: String,
    pub encrypted_queries_root: String,
    pub pq_query_attestations_root: String,
    pub callback_receipts_root: String,
    pub access_budgets_root: String,
    pub fee_sponsors_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            contracts_root: empty_root("contracts"),
            committees_root: empty_root("committees"),
            oracle_members_root: empty_root("oracle-members"),
            private_state_roots_root: empty_root("private-state-roots"),
            encrypted_queries_root: empty_root("encrypted-queries"),
            pq_query_attestations_root: empty_root("pq-query-attestations"),
            callback_receipts_root: empty_root("callback-receipts"),
            access_budgets_root: empty_root("access-budgets"),
            fee_sponsors_root: empty_root("fee-sponsors"),
            redaction_budgets_root: empty_root("redaction-budgets"),
            operator_summaries_root: empty_root("operator-summaries"),
            state_root: empty_root("state"),
        }
    }
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "contracts_root": self.contracts_root,
            "committees_root": self.committees_root,
            "oracle_members_root": self.oracle_members_root,
            "private_state_roots_root": self.private_state_roots_root,
            "encrypted_queries_root": self.encrypted_queries_root,
            "pq_query_attestations_root": self.pq_query_attestations_root,
            "callback_receipts_root": self.callback_receipts_root,
            "access_budgets_root": self.access_budgets_root,
            "fee_sponsors_root": self.fee_sponsors_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root
        })
    }
}

impl PublicRecord for Roots {
    fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractRegistryEntry {
    pub contract_id: String,
    pub domain: ContractDomain,
    pub status: ContractStatus,
    pub private_state_namespace: String,
    pub root_commitment: String,
    pub callback_endpoint_commitment: String,
    pub owner_view_tag: String,
    pub committee_id: String,
    pub min_query_privacy_set_size: u64,
    pub max_query_bytes: u64,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl ContractRegistryEntry {
    pub fn new(
        domain: ContractDomain,
        private_state_namespace: impl Into<String>,
        callback_endpoint_commitment: impl Into<String>,
        owner_view_tag: impl Into<String>,
        committee_id: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let private_state_namespace = private_state_namespace.into();
        let callback_endpoint_commitment = callback_endpoint_commitment.into();
        let owner_view_tag = owner_view_tag.into();
        let committee_id = committee_id.into();
        let root_commitment = record_root(
            "contract-initial-private-root",
            &json!({
                "domain": domain.as_str(),
                "namespace": private_state_namespace,
                "height": height
            }),
        );
        let contract_id = id_from_record(
            "contract",
            &json!({
                "domain": domain.as_str(),
                "namespace": private_state_namespace,
                "callback": callback_endpoint_commitment,
                "owner_view_tag": owner_view_tag,
                "committee_id": committee_id,
                "height": height
            }),
        );
        let metadata_root = record_root(
            "contract-metadata",
            &json!({
                "contract_id": contract_id,
                "namespace": private_state_namespace,
                "committee_id": committee_id
            }),
        );
        Self {
            contract_id,
            domain,
            status: ContractStatus::Active,
            private_state_namespace,
            root_commitment,
            callback_endpoint_commitment,
            owner_view_tag,
            committee_id,
            min_query_privacy_set_size: config.min_privacy_set_size,
            max_query_bytes: config.max_query_bytes,
            registered_at_height: height,
            expires_at_height: height + config.root_ttl_blocks,
            metadata_root,
        }
    }
}

impl PublicRecord for ContractRegistryEntry {
    fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "private_state_namespace": self.private_state_namespace,
            "root_commitment": self.root_commitment,
            "callback_endpoint_commitment": self.callback_endpoint_commitment,
            "owner_view_tag": self.owner_view_tag,
            "committee_id": self.committee_id,
            "min_query_privacy_set_size": self.min_query_privacy_set_size,
            "max_query_bytes": self.max_query_bytes,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleCommittee {
    pub committee_id: String,
    pub purpose: CommitteePurpose,
    pub status: ContractStatus,
    pub epoch: u64,
    pub member_set_root: String,
    pub aggregate_pq_key_root: String,
    pub threshold_weight: u64,
    pub strong_threshold_weight: u64,
    pub total_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub rotates_at_height: u64,
}

impl OracleCommittee {
    pub fn new(purpose: CommitteePurpose, epoch: u64, height: u64, config: &Config) -> Self {
        let committee_id = id_from_record(
            "oracle-committee",
            &json!({
                "purpose": purpose.as_str(),
                "epoch": epoch,
                "height": height
            }),
        );
        let total_weight = config.min_attester_weight * config.min_committee_members;
        let threshold_weight = bps_to_weight(total_weight, config.quorum_bps);
        let strong_threshold_weight = bps_to_weight(total_weight, config.strong_quorum_bps);
        let aggregate_pq_key_root = record_root(
            "committee-aggregate-pq-key",
            &json!({
                "committee_id": committee_id,
                "purpose": purpose.as_str(),
                "epoch": epoch
            }),
        );
        Self {
            committee_id,
            purpose,
            status: ContractStatus::Active,
            epoch,
            member_set_root: empty_root("committee-members"),
            aggregate_pq_key_root,
            threshold_weight,
            strong_threshold_weight,
            total_weight,
            quorum_bps: config.quorum_bps,
            strong_quorum_bps: config.strong_quorum_bps,
            privacy_set_size: config.target_privacy_set_size,
            created_at_height: height,
            rotates_at_height: height + config.root_ttl_blocks,
        }
    }
}

impl PublicRecord for OracleCommittee {
    fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "purpose": self.purpose.as_str(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "epoch": self.epoch,
            "member_set_root": self.member_set_root,
            "aggregate_pq_key_root": self.aggregate_pq_key_root,
            "threshold_weight": self.threshold_weight,
            "strong_threshold_weight": self.strong_threshold_weight,
            "total_weight": self.total_weight,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "rotates_at_height": self.rotates_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleMember {
    pub member_id: String,
    pub committee_id: String,
    pub operator_id: String,
    pub status: MemberStatus,
    pub weight: u64,
    pub pq_signing_key_commitment: String,
    pub pq_kem_key_commitment: String,
    pub view_tag: String,
    pub slash_nullifier: String,
    pub joined_at_height: u64,
    pub last_attested_height: u64,
}

impl OracleMember {
    pub fn new(
        committee_id: impl Into<String>,
        operator_id: impl Into<String>,
        view_tag: impl Into<String>,
        weight: u64,
        height: u64,
    ) -> Self {
        let committee_id = committee_id.into();
        let operator_id = operator_id.into();
        let view_tag = view_tag.into();
        let member_id = id_from_record(
            "oracle-member",
            &json!({
                "committee_id": committee_id,
                "operator_id": operator_id,
                "view_tag": view_tag,
                "height": height
            }),
        );
        let pq_signing_key_commitment =
            record_root("member-pq-signing-key", &json!({ "member_id": member_id }));
        let pq_kem_key_commitment =
            record_root("member-pq-kem-key", &json!({ "member_id": member_id }));
        let slash_nullifier = id_from_record(
            "member-slash-nullifier",
            &json!({
                "member_id": member_id,
                "operator_id": operator_id
            }),
        );
        Self {
            member_id,
            committee_id,
            operator_id,
            status: MemberStatus::Active,
            weight,
            pq_signing_key_commitment,
            pq_kem_key_commitment,
            view_tag,
            slash_nullifier,
            joined_at_height: height,
            last_attested_height: 0,
        }
    }
}

impl PublicRecord for OracleMember {
    fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "operator_id": self.operator_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "weight": self.weight,
            "pq_signing_key_commitment": self.pq_signing_key_commitment,
            "pq_kem_key_commitment": self.pq_kem_key_commitment,
            "view_tag": self.view_tag,
            "slash_nullifier": self.slash_nullifier,
            "joined_at_height": self.joined_at_height,
            "last_attested_height": self.last_attested_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateStateRoot {
    pub root_id: String,
    pub contract_id: String,
    pub committee_id: String,
    pub status: RootStatus,
    pub private_state_root: String,
    pub nullifier_root: String,
    pub access_policy_root: String,
    pub redaction_policy_root: String,
    pub witness_bundle_root: String,
    pub epoch: u64,
    pub height: u64,
    pub expires_at_height: u64,
    pub attester_weight: u64,
}

impl PrivateStateRoot {
    pub fn new(
        contract_id: impl Into<String>,
        committee_id: impl Into<String>,
        private_state_root: impl Into<String>,
        epoch: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let contract_id = contract_id.into();
        let committee_id = committee_id.into();
        let private_state_root = private_state_root.into();
        let root_id = id_from_record(
            "private-state-root",
            &json!({
                "contract_id": contract_id,
                "committee_id": committee_id,
                "private_state_root": private_state_root,
                "epoch": epoch,
                "height": height
            }),
        );
        Self {
            root_id,
            contract_id,
            committee_id,
            status: RootStatus::Active,
            private_state_root: private_state_root.clone(),
            nullifier_root: record_root(
                "private-state-nullifier-root",
                &json!({ "private_state_root": private_state_root }),
            ),
            access_policy_root: record_root(
                "private-state-access-policy-root",
                &json!({ "private_state_root": private_state_root }),
            ),
            redaction_policy_root: record_root(
                "private-state-redaction-policy-root",
                &json!({ "private_state_root": private_state_root }),
            ),
            witness_bundle_root: record_root(
                "private-state-witness-bundle-root",
                &json!({ "private_state_root": private_state_root }),
            ),
            epoch,
            height,
            expires_at_height: height + config.root_ttl_blocks,
            attester_weight: config.min_attester_weight * config.min_committee_members,
        }
    }
}

impl PublicRecord for PrivateStateRoot {
    fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "contract_id": self.contract_id,
            "committee_id": self.committee_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "private_state_root": self.private_state_root,
            "nullifier_root": self.nullifier_root,
            "access_policy_root": self.access_policy_root,
            "redaction_policy_root": self.redaction_policy_root,
            "witness_bundle_root": self.witness_bundle_root,
            "epoch": self.epoch,
            "height": self.height,
            "expires_at_height": self.expires_at_height,
            "attester_weight": self.attester_weight
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateQuery {
    pub query_id: String,
    pub contract_id: String,
    pub committee_id: String,
    pub root_id: String,
    pub query_kind: QueryKind,
    pub status: QueryStatus,
    pub encrypted_payload_root: String,
    pub payload_bytes: u64,
    pub callback_commitment: String,
    pub caller_access_tag: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
    pub access_units: u64,
    pub fee_micro_credits: u128,
    pub sponsor_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedStateQuery {
    pub fn new(
        contract_id: impl Into<String>,
        committee_id: impl Into<String>,
        root_id: impl Into<String>,
        query_kind: QueryKind,
        encrypted_payload_root: impl Into<String>,
        callback_commitment: impl Into<String>,
        caller_access_tag: impl Into<String>,
        payload_bytes: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let contract_id = contract_id.into();
        let committee_id = committee_id.into();
        let root_id = root_id.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let callback_commitment = callback_commitment.into();
        let caller_access_tag = caller_access_tag.into();
        let replay_nullifier = id_from_record(
            "query-replay-nullifier",
            &json!({
                "contract_id": contract_id,
                "root_id": root_id,
                "payload_root": encrypted_payload_root,
                "caller_access_tag": caller_access_tag
            }),
        );
        let query_id = id_from_record(
            "encrypted-state-query",
            &json!({
                "contract_id": contract_id,
                "committee_id": committee_id,
                "root_id": root_id,
                "query_kind": query_kind.as_str(),
                "payload_root": encrypted_payload_root,
                "replay_nullifier": replay_nullifier,
                "height": height
            }),
        );
        let access_units = query_kind.default_weight() + (payload_bytes / 4096);
        let fee_micro_credits =
            config.base_query_fee_micro_credits + (access_units as u128 * 25_u128);
        Self {
            query_id,
            contract_id,
            committee_id,
            root_id,
            query_kind,
            status: QueryStatus::Encrypted,
            encrypted_payload_root,
            payload_bytes,
            callback_commitment,
            caller_access_tag,
            replay_nullifier,
            privacy_set_size: config.target_privacy_set_size,
            access_units,
            fee_micro_credits,
            sponsor_id: None,
            created_at_height: height,
            expires_at_height: height + config.query_ttl_blocks,
        }
    }
}

impl PublicRecord for EncryptedStateQuery {
    fn public_record(&self) -> Value {
        json!({
            "query_id": self.query_id,
            "contract_id": self.contract_id,
            "committee_id": self.committee_id,
            "root_id": self.root_id,
            "query_kind": self.query_kind.as_str(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "payload_bytes": self.payload_bytes,
            "callback_commitment": self.callback_commitment,
            "caller_access_tag": self.caller_access_tag,
            "replay_nullifier": self.replay_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "access_units": self.access_units,
            "fee_micro_credits": self.fee_micro_credits.to_string(),
            "sponsor_id": self.sponsor_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqQueryAttestation {
    pub attestation_id: String,
    pub query_id: String,
    pub committee_id: String,
    pub root_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub signer_member_ids: BTreeSet<String>,
    pub signer_weight: u64,
    pub threshold_weight: u64,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub warning_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqQueryAttestation {
    pub fn new(
        query: &EncryptedStateQuery,
        kind: AttestationKind,
        verdict: AttestationVerdict,
        signer_member_ids: BTreeSet<String>,
        signer_weight: u64,
        threshold_weight: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let transcript_root = record_root(
            "pq-query-attestation-transcript",
            &json!({
                "query": query.public_record(),
                "kind": format!("{:?}", kind).to_lowercase(),
                "verdict": format!("{:?}", verdict).to_lowercase(),
                "signer_member_ids": signer_member_ids
            }),
        );
        let attestation_id = id_from_record(
            "pq-query-attestation",
            &json!({
                "query_id": query.query_id,
                "kind": format!("{:?}", kind).to_lowercase(),
                "transcript_root": transcript_root,
                "height": height
            }),
        );
        Self {
            attestation_id: attestation_id.clone(),
            query_id: query.query_id.clone(),
            committee_id: query.committee_id.clone(),
            root_id: query.root_id.clone(),
            kind,
            verdict,
            signer_member_ids,
            signer_weight,
            threshold_weight,
            transcript_root,
            pq_signature_root: record_root(
                "pq-query-attestation-signature",
                &json!({ "attestation_id": attestation_id }),
            ),
            warning_root: empty_root("attestation-warnings"),
            issued_at_height: height,
            expires_at_height: height + config.attestation_ttl_blocks,
        }
    }
}

impl PublicRecord for PqQueryAttestation {
    fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "query_id": self.query_id,
            "committee_id": self.committee_id,
            "root_id": self.root_id,
            "kind": format!("{:?}", self.kind).to_lowercase(),
            "verdict": format!("{:?}", self.verdict).to_lowercase(),
            "signer_member_ids": self.signer_member_ids,
            "signer_weight": self.signer_weight,
            "threshold_weight": self.threshold_weight,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "warning_root": self.warning_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallbackReceipt {
    pub receipt_id: String,
    pub query_id: String,
    pub contract_id: String,
    pub callback_status: CallbackStatus,
    pub callback_result_root: String,
    pub public_result_commitment: String,
    pub redacted_result_root: String,
    pub gas_used: u64,
    pub callback_bytes: u64,
    pub delivered_to: String,
    pub delivery_nullifier: String,
    pub executed_at_height: u64,
    pub expires_at_height: u64,
}

impl CallbackReceipt {
    pub fn new(
        query: &EncryptedStateQuery,
        callback_result_root: impl Into<String>,
        delivered_to: impl Into<String>,
        gas_used: u64,
        callback_bytes: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let callback_result_root = callback_result_root.into();
        let delivered_to = delivered_to.into();
        let delivery_nullifier = id_from_record(
            "callback-delivery-nullifier",
            &json!({
                "query_id": query.query_id,
                "delivered_to": delivered_to,
                "result_root": callback_result_root
            }),
        );
        let receipt_id = id_from_record(
            "callback-receipt",
            &json!({
                "query_id": query.query_id,
                "delivery_nullifier": delivery_nullifier,
                "height": height
            }),
        );
        Self {
            receipt_id,
            query_id: query.query_id.clone(),
            contract_id: query.contract_id.clone(),
            callback_status: CallbackStatus::Delivered,
            callback_result_root: callback_result_root.clone(),
            public_result_commitment: record_root(
                "callback-public-result-commitment",
                &json!({ "result_root": callback_result_root }),
            ),
            redacted_result_root: empty_root("callback-redaction"),
            gas_used,
            callback_bytes,
            delivered_to,
            delivery_nullifier,
            executed_at_height: height,
            expires_at_height: height + config.callback_ttl_blocks,
        }
    }
}

impl PublicRecord for CallbackReceipt {
    fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "query_id": self.query_id,
            "contract_id": self.contract_id,
            "callback_status": format!("{:?}", self.callback_status).to_lowercase(),
            "callback_result_root": self.callback_result_root,
            "public_result_commitment": self.public_result_commitment,
            "redacted_result_root": self.redacted_result_root,
            "gas_used": self.gas_used,
            "callback_bytes": self.callback_bytes,
            "delivered_to": self.delivered_to,
            "delivery_nullifier": self.delivery_nullifier,
            "executed_at_height": self.executed_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessBudget {
    pub budget_id: String,
    pub owner_view_tag: String,
    pub contract_id: String,
    pub status: BudgetStatus,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub query_cap: u64,
    pub spent_query_count: u64,
    pub budget_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl AccessBudget {
    pub fn new(
        owner_view_tag: impl Into<String>,
        contract_id: impl Into<String>,
        total_units: u64,
        query_cap: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let owner_view_tag = owner_view_tag.into();
        let contract_id = contract_id.into();
        let budget_id = id_from_record(
            "access-budget",
            &json!({
                "owner_view_tag": owner_view_tag,
                "contract_id": contract_id,
                "total_units": total_units,
                "height": height
            }),
        );
        Self {
            budget_id: budget_id.clone(),
            owner_view_tag,
            contract_id,
            status: BudgetStatus::Open,
            total_units,
            reserved_units: 0,
            consumed_units: 0,
            query_cap,
            spent_query_count: 0,
            budget_nullifier_root: record_root(
                "access-budget-nullifier-root",
                &json!({ "budget_id": budget_id }),
            ),
            opened_at_height: height,
            expires_at_height: height + config.access_window_blocks,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }
}

impl PublicRecord for AccessBudget {
    fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_view_tag": self.owner_view_tag,
            "contract_id": self.contract_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "query_cap": self.query_cap,
            "spent_query_count": self.spent_query_count,
            "budget_nullifier_root": self.budget_nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsor {
    pub sponsor_id: String,
    pub sponsor_view_tag: String,
    pub contract_id: String,
    pub status: SponsorStatus,
    pub max_fee_per_query_micro_credits: u128,
    pub remaining_budget_micro_credits: u128,
    pub spent_budget_micro_credits: u128,
    pub sponsored_query_count: u64,
    pub authorization_root: String,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsor {
    pub fn new(
        sponsor_view_tag: impl Into<String>,
        contract_id: impl Into<String>,
        max_fee_per_query_micro_credits: u128,
        total_budget_micro_credits: u128,
        height: u64,
        config: &Config,
    ) -> Self {
        let sponsor_view_tag = sponsor_view_tag.into();
        let contract_id = contract_id.into();
        let sponsor_id = id_from_record(
            "fee-sponsor",
            &json!({
                "sponsor_view_tag": sponsor_view_tag,
                "contract_id": contract_id,
                "budget": total_budget_micro_credits.to_string(),
                "height": height
            }),
        );
        Self {
            sponsor_id: sponsor_id.clone(),
            sponsor_view_tag,
            contract_id,
            status: SponsorStatus::Active,
            max_fee_per_query_micro_credits,
            remaining_budget_micro_credits: total_budget_micro_credits,
            spent_budget_micro_credits: 0,
            sponsored_query_count: 0,
            authorization_root: record_root(
                "fee-sponsor-authorization",
                &json!({ "sponsor_id": sponsor_id }),
            ),
            rebate_bps: config.sponsor_rebate_bps,
            opened_at_height: height,
            expires_at_height: height + config.access_window_blocks,
        }
    }
}

impl PublicRecord for FeeSponsor {
    fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_view_tag": self.sponsor_view_tag,
            "contract_id": self.contract_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "max_fee_per_query_micro_credits": self.max_fee_per_query_micro_credits.to_string(),
            "remaining_budget_micro_credits": self.remaining_budget_micro_credits.to_string(),
            "spent_budget_micro_credits": self.spent_budget_micro_credits.to_string(),
            "sponsored_query_count": self.sponsored_query_count,
            "authorization_root": self.authorization_root,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub redaction_id: String,
    pub owner_view_tag: String,
    pub contract_id: String,
    pub status: BudgetStatus,
    pub reason: RedactionReason,
    pub total_redaction_units: u64,
    pub consumed_redaction_units: u64,
    pub disclosure_floor_root: String,
    pub redaction_policy_root: String,
    pub reviewer_committee_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn new(
        owner_view_tag: impl Into<String>,
        contract_id: impl Into<String>,
        reviewer_committee_id: impl Into<String>,
        reason: RedactionReason,
        total_redaction_units: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let owner_view_tag = owner_view_tag.into();
        let contract_id = contract_id.into();
        let reviewer_committee_id = reviewer_committee_id.into();
        let redaction_id = id_from_record(
            "redaction-budget",
            &json!({
                "owner_view_tag": owner_view_tag,
                "contract_id": contract_id,
                "reason": reason.as_str(),
                "height": height
            }),
        );
        Self {
            redaction_id: redaction_id.clone(),
            owner_view_tag,
            contract_id,
            status: BudgetStatus::Open,
            reason,
            total_redaction_units,
            consumed_redaction_units: 0,
            disclosure_floor_root: record_root(
                "redaction-disclosure-floor",
                &json!({ "redaction_id": redaction_id }),
            ),
            redaction_policy_root: record_root(
                "redaction-policy-root",
                &json!({ "redaction_id": redaction_id }),
            ),
            reviewer_committee_id,
            opened_at_height: height,
            expires_at_height: height + config.redaction_window_blocks,
        }
    }

    pub fn remaining_redaction_units(&self) -> u64 {
        self.total_redaction_units
            .saturating_sub(self.consumed_redaction_units)
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "owner_view_tag": self.owner_view_tag,
            "contract_id": self.contract_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "reason": self.reason.as_str(),
            "total_redaction_units": self.total_redaction_units,
            "consumed_redaction_units": self.consumed_redaction_units,
            "remaining_redaction_units": self.remaining_redaction_units(),
            "disclosure_floor_root": self.disclosure_floor_root,
            "redaction_policy_root": self.redaction_policy_root,
            "reviewer_committee_id": self.reviewer_committee_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub active_member_count: u64,
    pub attestation_count: u64,
    pub callback_count: u64,
    pub sponsored_fee_micro_credits: u128,
    pub slash_count: u64,
    pub average_latency_blocks: u64,
    pub earned_rebate_micro_credits: u128,
    pub latest_member_set_root: String,
    pub latest_query_root: String,
    pub latest_receipt_root: String,
    pub generated_at_height: u64,
}

impl OperatorSummary {
    pub fn new(
        operator_id: impl Into<String>,
        epoch: u64,
        active_member_count: u64,
        attestation_count: u64,
        callback_count: u64,
        sponsored_fee_micro_credits: u128,
        height: u64,
    ) -> Self {
        let operator_id = operator_id.into();
        let summary_id = id_from_record(
            "operator-summary",
            &json!({
                "operator_id": operator_id,
                "epoch": epoch,
                "height": height
            }),
        );
        let earned_rebate_micro_credits = sponsored_fee_micro_credits / 20;
        Self {
            summary_id,
            operator_id,
            epoch,
            active_member_count,
            attestation_count,
            callback_count,
            sponsored_fee_micro_credits,
            slash_count: 0,
            average_latency_blocks: 2,
            earned_rebate_micro_credits,
            latest_member_set_root: empty_root("operator-members"),
            latest_query_root: empty_root("operator-queries"),
            latest_receipt_root: empty_root("operator-receipts"),
            generated_at_height: height,
        }
    }
}

impl PublicRecord for OperatorSummary {
    fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "active_member_count": self.active_member_count,
            "attestation_count": self.attestation_count,
            "callback_count": self.callback_count,
            "sponsored_fee_micro_credits": self.sponsored_fee_micro_credits.to_string(),
            "slash_count": self.slash_count,
            "average_latency_blocks": self.average_latency_blocks,
            "earned_rebate_micro_credits": self.earned_rebate_micro_credits.to_string(),
            "latest_member_set_root": self.latest_member_set_root,
            "latest_query_root": self.latest_query_root,
            "latest_receipt_root": self.latest_receipt_root,
            "generated_at_height": self.generated_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub contracts: BTreeMap<String, ContractRegistryEntry>,
    pub committees: BTreeMap<String, OracleCommittee>,
    pub oracle_members: BTreeMap<String, OracleMember>,
    pub private_state_roots: BTreeMap<String, PrivateStateRoot>,
    pub encrypted_queries: BTreeMap<String, EncryptedStateQuery>,
    pub pq_query_attestations: BTreeMap<String, PqQueryAttestation>,
    pub callback_receipts: BTreeMap<String, CallbackReceipt>,
    pub access_budgets: BTreeMap<String, AccessBudget>,
    pub fee_sponsors: BTreeMap<String, FeeSponsor>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            epoch,
            contracts: BTreeMap::new(),
            committees: BTreeMap::new(),
            oracle_members: BTreeMap::new(),
            private_state_roots: BTreeMap::new(),
            encrypted_queries: BTreeMap::new(),
            pq_query_attestations: BTreeMap::new(),
            callback_receipts: BTreeMap::new(),
            access_budgets: BTreeMap::new(),
            fee_sponsors: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        build_devnet_state()
    }

    pub fn register_contract(&mut self, entry: ContractRegistryEntry) -> Result<String> {
        ensure!(
            self.contracts.len() < self.config.max_contracts,
            "contract capacity reached"
        );
        ensure!(
            !self.contracts.contains_key(&entry.contract_id),
            "contract already registered: {}",
            entry.contract_id
        );
        let id = entry.contract_id.clone();
        self.contracts.insert(id.clone(), entry);
        self.refresh_roots();
        Ok(id)
    }

    pub fn add_committee(&mut self, committee: OracleCommittee) -> Result<String> {
        ensure!(
            self.committees.len() < self.config.max_committees,
            "committee capacity reached"
        );
        ensure!(
            !self.committees.contains_key(&committee.committee_id),
            "committee already exists: {}",
            committee.committee_id
        );
        let id = committee.committee_id.clone();
        self.committees.insert(id.clone(), committee);
        self.refresh_committee_roots();
        self.refresh_roots();
        Ok(id)
    }

    pub fn add_oracle_member(&mut self, member: OracleMember) -> Result<String> {
        ensure!(
            self.oracle_members.len() < self.config.max_oracle_members,
            "oracle member capacity reached"
        );
        ensure!(
            self.committees.contains_key(&member.committee_id),
            "unknown committee: {}",
            member.committee_id
        );
        ensure!(
            !self.oracle_members.contains_key(&member.member_id),
            "oracle member already exists: {}",
            member.member_id
        );
        let id = member.member_id.clone();
        self.oracle_members.insert(id.clone(), member);
        self.refresh_committee_roots();
        self.refresh_roots();
        Ok(id)
    }

    pub fn publish_private_state_root(&mut self, root: PrivateStateRoot) -> Result<String> {
        ensure!(
            self.private_state_roots.len() < self.config.max_private_roots,
            "private root capacity reached"
        );
        ensure!(
            self.contracts.contains_key(&root.contract_id),
            "unknown contract: {}",
            root.contract_id
        );
        ensure!(
            self.committees.contains_key(&root.committee_id),
            "unknown committee: {}",
            root.committee_id
        );
        let id = root.root_id.clone();
        self.private_state_roots.insert(id.clone(), root);
        self.refresh_roots();
        Ok(id)
    }

    pub fn open_access_budget(&mut self, budget: AccessBudget) -> Result<String> {
        ensure!(
            self.access_budgets.len() < self.config.max_access_budgets,
            "access budget capacity reached"
        );
        ensure!(
            self.contracts.contains_key(&budget.contract_id),
            "unknown contract: {}",
            budget.contract_id
        );
        let id = budget.budget_id.clone();
        self.access_budgets.insert(id.clone(), budget);
        self.refresh_roots();
        Ok(id)
    }

    pub fn add_fee_sponsor(&mut self, sponsor: FeeSponsor) -> Result<String> {
        ensure!(
            self.fee_sponsors.len() < self.config.max_fee_sponsors,
            "fee sponsor capacity reached"
        );
        ensure!(
            self.contracts.contains_key(&sponsor.contract_id),
            "unknown contract: {}",
            sponsor.contract_id
        );
        let id = sponsor.sponsor_id.clone();
        self.fee_sponsors.insert(id.clone(), sponsor);
        self.refresh_roots();
        Ok(id)
    }

    pub fn open_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity reached"
        );
        ensure!(
            self.contracts.contains_key(&budget.contract_id),
            "unknown contract: {}",
            budget.contract_id
        );
        let id = budget.redaction_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        self.refresh_roots();
        Ok(id)
    }

    pub fn submit_encrypted_query(
        &mut self,
        mut query: EncryptedStateQuery,
        budget_id: Option<&str>,
        sponsor_id: Option<&str>,
    ) -> Result<String> {
        ensure!(
            self.encrypted_queries.len() < self.config.max_encrypted_queries,
            "encrypted query capacity reached"
        );
        let contract = self
            .contracts
            .get(&query.contract_id)
            .ok_or_else(|| format!("unknown contract: {}", query.contract_id))?;
        ensure!(
            contract.status.accepts_queries(),
            "contract does not accept queries: {}",
            query.contract_id
        );
        ensure!(
            self.private_state_roots.contains_key(&query.root_id),
            "unknown private state root: {}",
            query.root_id
        );
        ensure!(
            query.payload_bytes <= self.config.max_query_bytes,
            "query payload exceeds max bytes"
        );
        ensure!(
            query.privacy_set_size >= self.config.min_privacy_set_size,
            "query privacy set below minimum"
        );
        if let Some(budget_id) = budget_id {
            let budget = self
                .access_budgets
                .get_mut(budget_id)
                .ok_or_else(|| format!("unknown access budget: {}", budget_id))?;
            ensure!(budget.status.spendable(), "access budget is not spendable");
            ensure!(
                budget.contract_id == query.contract_id,
                "access budget contract mismatch"
            );
            ensure!(
                budget.remaining_units() >= query.access_units,
                "access budget has insufficient units"
            );
            ensure!(
                budget.spent_query_count < budget.query_cap,
                "access budget query cap reached"
            );
            budget.reserved_units += query.access_units;
            budget.spent_query_count += 1;
            budget.status = BudgetStatus::Reserved;
            query.status = QueryStatus::BudgetReserved;
        }
        if let Some(sponsor_id) = sponsor_id {
            let sponsor = self
                .fee_sponsors
                .get_mut(sponsor_id)
                .ok_or_else(|| format!("unknown fee sponsor: {}", sponsor_id))?;
            ensure!(sponsor.status.can_sponsor(), "fee sponsor is inactive");
            ensure!(
                sponsor.contract_id == query.contract_id,
                "fee sponsor contract mismatch"
            );
            ensure!(
                query.fee_micro_credits <= sponsor.max_fee_per_query_micro_credits,
                "query fee exceeds sponsor per-query cap"
            );
            ensure!(
                sponsor.remaining_budget_micro_credits >= query.fee_micro_credits,
                "fee sponsor has insufficient budget"
            );
            sponsor.remaining_budget_micro_credits -= query.fee_micro_credits;
            sponsor.spent_budget_micro_credits += query.fee_micro_credits;
            sponsor.sponsored_query_count += 1;
            query.sponsor_id = Some(sponsor_id.to_string());
            query.status = QueryStatus::Sponsored;
            self.counters.sponsored_fees_micro_credits += query.fee_micro_credits;
        }
        let id = query.query_id.clone();
        self.encrypted_queries.insert(id.clone(), query);
        self.refresh_roots();
        Ok(id)
    }

    pub fn attest_query(&mut self, attestation: PqQueryAttestation) -> Result<String> {
        ensure!(
            self.pq_query_attestations.len() < self.config.max_attestations,
            "attestation capacity reached"
        );
        let query = self
            .encrypted_queries
            .get_mut(&attestation.query_id)
            .ok_or_else(|| format!("unknown query: {}", attestation.query_id))?;
        ensure!(query.status.is_open(), "query is not open");
        ensure!(
            attestation.signer_weight >= attestation.threshold_weight,
            "attestation signer weight below threshold"
        );
        if attestation.verdict.accepted() {
            query.status = QueryStatus::Attested;
        } else {
            query.status = QueryStatus::Disputed;
            self.counters.disputed_queries += 1;
        }
        for member_id in &attestation.signer_member_ids {
            if let Some(member) = self.oracle_members.get_mut(member_id) {
                member.last_attested_height = attestation.issued_at_height;
            }
        }
        let id = attestation.attestation_id.clone();
        self.pq_query_attestations.insert(id.clone(), attestation);
        self.refresh_roots();
        Ok(id)
    }

    pub fn deliver_callback(&mut self, receipt: CallbackReceipt) -> Result<String> {
        ensure!(
            self.callback_receipts.len() < self.config.max_callback_receipts,
            "callback receipt capacity reached"
        );
        let query = self
            .encrypted_queries
            .get_mut(&receipt.query_id)
            .ok_or_else(|| format!("unknown query: {}", receipt.query_id))?;
        ensure!(
            receipt.callback_bytes <= self.config.max_callback_bytes,
            "callback bytes exceeds maximum"
        );
        query.status = QueryStatus::Fulfilled;
        self.counters.fulfilled_queries += 1;
        self.counters.consumed_access_units += query.access_units;
        let id = receipt.receipt_id.clone();
        self.callback_receipts.insert(id.clone(), receipt);
        self.refresh_roots();
        Ok(id)
    }

    pub fn redact_callback(
        &mut self,
        receipt_id: &str,
        redaction_id: &str,
        units: u64,
        redacted_result_root: impl Into<String>,
    ) -> Result<()> {
        let receipt = self
            .callback_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown callback receipt: {}", receipt_id))?;
        let redaction = self
            .redaction_budgets
            .get_mut(redaction_id)
            .ok_or_else(|| format!("unknown redaction budget: {}", redaction_id))?;
        ensure!(
            redaction.status.spendable(),
            "redaction budget is not spendable"
        );
        ensure!(
            redaction.contract_id == receipt.contract_id,
            "redaction budget contract mismatch"
        );
        ensure!(
            redaction.remaining_redaction_units() >= units,
            "redaction budget has insufficient units"
        );
        redaction.consumed_redaction_units += units;
        receipt.callback_status = CallbackStatus::Redacted;
        receipt.redacted_result_root = redacted_result_root.into();
        self.counters.redacted_callbacks += 1;
        self.counters.consumed_redaction_units += units;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity reached"
        );
        let id = summary.summary_id.clone();
        self.operator_summaries.insert(id.clone(), summary);
        self.refresh_roots();
        Ok(id)
    }

    pub fn operator_summary_for(&self, operator_id: &str) -> OperatorSummary {
        let active_member_count = self
            .oracle_members
            .values()
            .filter(|member| member.operator_id == operator_id && member.status.can_vote())
            .count() as u64;
        let attestation_count = self
            .pq_query_attestations
            .values()
            .filter(|attestation| {
                attestation.signer_member_ids.iter().any(|member_id| {
                    self.oracle_members
                        .get(member_id)
                        .map(|member| member.operator_id == operator_id)
                        .unwrap_or(false)
                })
            })
            .count() as u64;
        let callback_count = self
            .callback_receipts
            .values()
            .filter(|receipt| receipt.delivered_to == operator_id)
            .count() as u64;
        let sponsored_fee_micro_credits = self
            .fee_sponsors
            .values()
            .filter(|sponsor| sponsor.sponsor_view_tag == operator_id)
            .map(|sponsor| sponsor.spent_budget_micro_credits)
            .sum();
        let mut summary = OperatorSummary::new(
            operator_id,
            self.epoch,
            active_member_count,
            attestation_count,
            callback_count,
            sponsored_fee_micro_credits,
            self.height,
        );
        summary.latest_member_set_root = map_root(
            "operator-summary-members",
            &self
                .oracle_members
                .iter()
                .filter(|(_, member)| member.operator_id == operator_id)
                .map(|(id, member)| (id.clone(), member.clone()))
                .collect(),
            OracleMember::public_record,
        );
        summary.latest_query_root = map_root(
            "operator-summary-queries",
            &self.encrypted_queries,
            EncryptedStateQuery::public_record,
        );
        summary.latest_receipt_root = map_root(
            "operator-summary-receipts",
            &self.callback_receipts,
            CallbackReceipt::public_record,
        );
        summary
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots_without_state_root().public_record_without_state_root(),
            "contracts": map_records(&self.contracts, ContractRegistryEntry::public_record),
            "committees": map_records(&self.committees, OracleCommittee::public_record),
            "oracle_members": map_records(&self.oracle_members, OracleMember::public_record),
            "private_state_roots": map_records(&self.private_state_roots, PrivateStateRoot::public_record),
            "encrypted_queries": map_records(&self.encrypted_queries, EncryptedStateQuery::public_record),
            "pq_query_attestations": map_records(&self.pq_query_attestations, PqQueryAttestation::public_record),
            "callback_receipts": map_records(&self.callback_receipts, CallbackReceipt::public_record),
            "access_budgets": map_records(&self.access_budgets, AccessBudget::public_record),
            "fee_sponsors": map_records(&self.fee_sponsors, FeeSponsor::public_record),
            "redaction_budgets": map_records(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": map_records(&self.operator_summaries, OperatorSummary::public_record)
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn roots_without_state_root(&self) -> Roots {
        let mut roots = Roots {
            config_root: record_root("config", &self.config.public_record()),
            counters_root: record_root("counters", &self.counters.public_record()),
            contracts_root: map_root(
                "contracts",
                &self.contracts,
                ContractRegistryEntry::public_record,
            ),
            committees_root: map_root(
                "committees",
                &self.committees,
                OracleCommittee::public_record,
            ),
            oracle_members_root: map_root(
                "oracle-members",
                &self.oracle_members,
                OracleMember::public_record,
            ),
            private_state_roots_root: map_root(
                "private-state-roots",
                &self.private_state_roots,
                PrivateStateRoot::public_record,
            ),
            encrypted_queries_root: map_root(
                "encrypted-queries",
                &self.encrypted_queries,
                EncryptedStateQuery::public_record,
            ),
            pq_query_attestations_root: map_root(
                "pq-query-attestations",
                &self.pq_query_attestations,
                PqQueryAttestation::public_record,
            ),
            callback_receipts_root: map_root(
                "callback-receipts",
                &self.callback_receipts,
                CallbackReceipt::public_record,
            ),
            access_budgets_root: map_root(
                "access-budgets",
                &self.access_budgets,
                AccessBudget::public_record,
            ),
            fee_sponsors_root: map_root(
                "fee-sponsors",
                &self.fee_sponsors,
                FeeSponsor::public_record,
            ),
            redaction_budgets_root: map_root(
                "redaction-budgets",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summaries_root: map_root(
                "operator-summaries",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "height": self.height,
            "epoch": self.epoch,
            "roots": roots.public_record_without_state_root()
        }));
        roots
    }

    pub fn refresh_roots(&mut self) {
        self.counters.contracts = self.contracts.len() as u64;
        self.counters.committees = self.committees.len() as u64;
        self.counters.oracle_members = self.oracle_members.len() as u64;
        self.counters.private_state_roots = self.private_state_roots.len() as u64;
        self.counters.encrypted_queries = self.encrypted_queries.len() as u64;
        self.counters.pq_query_attestations = self.pq_query_attestations.len() as u64;
        self.counters.callback_receipts = self.callback_receipts.len() as u64;
        self.counters.access_budgets = self.access_budgets.len() as u64;
        self.counters.fee_sponsors = self.fee_sponsors.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots = self.roots_without_state_root();
        self.roots.state_root = self.state_root();
    }

    fn refresh_committee_roots(&mut self) {
        let committee_ids: Vec<String> = self.committees.keys().cloned().collect();
        for committee_id in committee_ids {
            let members: BTreeMap<String, OracleMember> = self
                .oracle_members
                .iter()
                .filter(|(_, member)| member.committee_id == committee_id)
                .map(|(id, member)| (id.clone(), member.clone()))
                .collect();
            if let Some(committee) = self.committees.get_mut(&committee_id) {
                committee.member_set_root = map_root(
                    "committee-member-set",
                    &members,
                    OracleMember::public_record,
                );
                committee.total_weight = members
                    .values()
                    .filter(|member| member.status.can_vote())
                    .map(|member| member.weight)
                    .sum();
                committee.threshold_weight =
                    bps_to_weight(committee.total_weight, committee.quorum_bps);
                committee.strong_threshold_weight =
                    bps_to_weight(committee.total_weight, committee.strong_quorum_bps);
            }
        }
    }
}

fn build_devnet_state() -> State {
    let config = Config::default();
    let mut state = State::new(config.clone(), DEVNET_HEIGHT, DEVNET_EPOCH);
    let query_committee = OracleCommittee::new(
        CommitteePurpose::QueryDecrypt,
        DEVNET_EPOCH,
        DEVNET_HEIGHT,
        &config,
    );
    let callback_committee = OracleCommittee::new(
        CommitteePurpose::CallbackExecutor,
        DEVNET_EPOCH,
        DEVNET_HEIGHT,
        &config,
    );
    let query_committee_id = state.add_committee(query_committee).unwrap_or_default();
    let callback_committee_id = state.add_committee(callback_committee).unwrap_or_default();
    for index in 0..5 {
        let member = OracleMember::new(
            query_committee_id.clone(),
            format!("devnet-oracle-operator-{}", index + 1),
            format!("view:query:{}", index + 1),
            config.min_attester_weight,
            DEVNET_HEIGHT + index,
        );
        let _ = state.add_oracle_member(member);
    }
    for index in 0..5 {
        let member = OracleMember::new(
            callback_committee_id.clone(),
            format!("devnet-callback-operator-{}", index + 1),
            format!("view:callback:{}", index + 1),
            config.min_attester_weight,
            DEVNET_HEIGHT + 16 + index,
        );
        let _ = state.add_oracle_member(member);
    }
    let contract = ContractRegistryEntry::new(
        ContractDomain::Lending,
        "private:lending:vault:dxmr",
        "callback:commitment:lending-risk-engine",
        "view:owner:lending-risk-engine",
        query_committee_id.clone(),
        DEVNET_HEIGHT + 24,
        &config,
    );
    let contract_id = state.register_contract(contract).unwrap_or_default();
    let root = PrivateStateRoot::new(
        contract_id.clone(),
        query_committee_id.clone(),
        record_root(
            "devnet-private-lending-state",
            &json!({
                "contract_id": contract_id,
                "height": DEVNET_HEIGHT + 25
            }),
        ),
        DEVNET_EPOCH,
        DEVNET_HEIGHT + 25,
        &config,
    );
    let root_id = state.publish_private_state_root(root).unwrap_or_default();
    let budget = AccessBudget::new(
        "view:caller:position-manager",
        contract_id.clone(),
        10_000,
        256,
        DEVNET_HEIGHT + 26,
        &config,
    );
    let budget_id = state.open_access_budget(budget).unwrap_or_default();
    let sponsor = FeeSponsor::new(
        "devnet-sponsor:risk-desk",
        contract_id.clone(),
        25_000,
        5_000_000,
        DEVNET_HEIGHT + 27,
        &config,
    );
    let sponsor_id = state.add_fee_sponsor(sponsor).unwrap_or_default();
    let redaction = RedactionBudget::new(
        "view:owner:lending-risk-engine",
        contract_id.clone(),
        callback_committee_id,
        RedactionReason::CallerPrivacy,
        512,
        DEVNET_HEIGHT + 28,
        &config,
    );
    let redaction_id = state.open_redaction_budget(redaction).unwrap_or_default();
    let query = EncryptedStateQuery::new(
        contract_id.clone(),
        query_committee_id,
        root_id,
        QueryKind::RiskMetric,
        record_root(
            "devnet-encrypted-query-payload",
            &json!({ "slot": "ltv:bucket" }),
        ),
        "callback:commitment:lending-risk-engine",
        "view:caller:position-manager",
        16_384,
        DEVNET_HEIGHT + 29,
        &config,
    );
    let query_clone = query.clone();
    let query_id = state
        .submit_encrypted_query(query, Some(&budget_id), Some(&sponsor_id))
        .unwrap_or_default();
    let signer_member_ids: BTreeSet<String> = state
        .oracle_members
        .values()
        .filter(|member| member.committee_id == query_clone.committee_id)
        .map(|member| member.member_id.clone())
        .collect();
    let signer_weight = state
        .oracle_members
        .values()
        .filter(|member| signer_member_ids.contains(&member.member_id))
        .map(|member| member.weight)
        .sum();
    let attestation = PqQueryAttestation::new(
        &query_clone,
        AttestationKind::QueryWellFormed,
        AttestationVerdict::Valid,
        signer_member_ids,
        signer_weight,
        config.min_attester_weight * config.min_committee_members,
        DEVNET_HEIGHT + 30,
        &config,
    );
    let _ = state.attest_query(attestation);
    let fulfilled_query = state
        .encrypted_queries
        .get(&query_id)
        .cloned()
        .unwrap_or(query_clone);
    let receipt = CallbackReceipt::new(
        &fulfilled_query,
        record_root("devnet-callback-result", &json!({ "risk": "healthy" })),
        "devnet-callback-operator-1",
        84_000,
        4_096,
        DEVNET_HEIGHT + 31,
        &config,
    );
    let receipt_id = state.deliver_callback(receipt).unwrap_or_default();
    let _ = state.redact_callback(
        &receipt_id,
        &redaction_id,
        8,
        record_root(
            "devnet-redacted-callback-result",
            &json!({ "risk": "redacted" }),
        ),
    );
    let summary = state.operator_summary_for("devnet-oracle-operator-1");
    let _ = state.insert_operator_summary(summary);
    state.refresh_roots();
    state
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

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-ORACLE-MESH-RECORD",
        &[
            HashPart::Text(PROTOCOL_VERSION),
            HashPart::Text(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-ORACLE-MESH-ID",
        &[
            HashPart::Text(PROTOCOL_VERSION),
            HashPart::Text(domain),
            HashPart::Json(record),
        ],
        24,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-ORACLE-MESH-STATE",
        &[HashPart::Text(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    record_root(domain, &json!({ "empty": true }))
}

pub fn map_records<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    Value::Array(
        records
            .iter()
            .map(|(id, record)| {
                json!({
                    "id": id,
                    "record": public_record(record)
                })
            })
            .collect(),
    )
}

pub fn map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    if records.is_empty() {
        return empty_root(domain);
    }
    record_root(domain, &map_records(records, public_record))
}

pub fn bps_to_weight(total_weight: u64, bps: u64) -> u64 {
    if total_weight == 0 {
        return 0;
    }
    ((total_weight as u128 * bps as u128 + (MAX_BPS as u128 - 1)) / MAX_BPS as u128) as u64
}
