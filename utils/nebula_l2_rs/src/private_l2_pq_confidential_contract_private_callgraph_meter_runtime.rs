use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateCallgraphMeterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_CALLGRAPH_METER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-private-callgraph-meter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_CALLGRAPH_METER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "dnr-devnet-fee";
pub const DEVNET_HEIGHT: u64 = 86_400;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONTRACT_SESSION_SCHEME: &str = "private-contract-session-commitment-root-v1";
pub const CALLGRAPH_COMMITMENT_SCHEME: &str = "private-callgraph-commitment-root-v1";
pub const METER_BUCKET_SCHEME: &str = "callgraph-gas-witness-meter-bucket-root-v1";
pub const PQ_EXECUTION_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-callgraph-execution-attestation-v1";
pub const DISCLOSURE_BUDGET_SCHEME: &str = "selective-disclosure-budget-root-v1";
pub const SETTLEMENT_SCHEME: &str = "private-callgraph-meter-settlement-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-callgraph-meter-rebate-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "redacted-private-callgraph-operator-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "commitments_only_no_plaintext_contract_inputs_outputs_storage_slots_call_edges_or_witnesses";
pub const DEFAULT_MAX_CALL_DEPTH: u16 = 32;
pub const DEFAULT_MAX_CALLS_PER_SESSION: u32 = 512;
pub const DEFAULT_MAX_METER_BUCKETS: usize = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_DISCLOSURE_BUDGET_UNITS: u64 = 64;
pub const DEFAULT_DISCLOSURE_RENEWAL_BLOCKS: u64 = 7_200;
pub const DEFAULT_OPERATOR_SUMMARY_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_REBATE_BPS: u64 = 3;
pub const DEFAULT_FAST_AGGREGATION_MIN_SESSIONS: u64 = 8;
pub const DEFAULT_FAST_AGGREGATION_TARGET_SESSIONS: u64 = 128;
pub const DEFAULT_WITNESS_BYTE_PRICE_MICRO_UNITS: u64 = 2;
pub const DEFAULT_GAS_UNIT_PRICE_MICRO_UNITS: u64 = 1;
pub const DEFAULT_SETTLEMENT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_SETTLEMENT_QUORUM_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Open,
    CallgraphCommitted,
    Metered,
    Attesting,
    Attested,
    Settled,
    Rebated,
    Disputed,
    Expired,
    Rejected,
}

impl SessionStatus {
    pub fn accepts_callgraph(self) -> bool {
        matches!(self, Self::Open | Self::CallgraphCommitted)
    }

    pub fn accepts_metering(self) -> bool {
        matches!(self, Self::CallgraphCommitted | Self::Metered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallEdgeVisibility {
    FullyPrivate,
    ContractClassOnly,
    SelectorBucketOnly,
    AuditorDisclosable,
    OperatorRedacted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallgraphStatus {
    Submitted,
    DepthChecked,
    Aggregated,
    Metered,
    Attested,
    Settled,
    Disputed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterBucketKind {
    ExecutionGas,
    WitnessBytes,
    StorageRead,
    StorageWrite,
    ContractSpawn,
    CrossContractCall,
    CryptoPrecompile,
    PqVerification,
    Disclosure,
    Aggregation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterBucketStatus {
    Open,
    Aggregated,
    Attested,
    Settled,
    Rebated,
    Exhausted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    None,
    MeterTotals,
    ContractClass,
    SelectorBucket,
    EdgeCount,
    WitnessSizeBucket,
    AuditorOnly,
    RegulatorOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureBudgetStatus {
    Planned,
    Reserved,
    Consumed,
    Renewed,
    Exhausted,
    Revoked,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Aggregating,
    Attested,
    Published,
    Finalized,
    Disputed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Applied,
    Published,
    Exhausted,
    ClawedBack,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Auditor,
    Sponsor,
    Sequencer,
    Watchtower,
    Public,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryRisk {
    Nominal,
    Elevated,
    DisclosurePressure,
    MeterDrift,
    AttestationLag,
    Halt,
}

impl SummaryRisk {
    pub fn halts(self) -> bool {
        matches!(self, Self::Halt)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub contract_session_scheme: String,
    pub callgraph_commitment_scheme: String,
    pub meter_bucket_scheme: String,
    pub pq_execution_attestation_scheme: String,
    pub disclosure_budget_scheme: String,
    pub settlement_scheme: String,
    pub rebate_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub max_call_depth: u16,
    pub max_calls_per_session: u32,
    pub max_meter_buckets: usize,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub attestation_ttl_blocks: u64,
    pub disclosure_budget_units: u64,
    pub disclosure_renewal_blocks: u64,
    pub operator_summary_bucket_size: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub fast_aggregation_min_sessions: u64,
    pub fast_aggregation_target_sessions: u64,
    pub witness_byte_price_micro_units: u64,
    pub gas_unit_price_micro_units: u64,
    pub settlement_quorum_bps: u64,
    pub strong_settlement_quorum_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            contract_session_scheme: CONTRACT_SESSION_SCHEME.to_string(),
            callgraph_commitment_scheme: CALLGRAPH_COMMITMENT_SCHEME.to_string(),
            meter_bucket_scheme: METER_BUCKET_SCHEME.to_string(),
            pq_execution_attestation_scheme: PQ_EXECUTION_ATTESTATION_SCHEME.to_string(),
            disclosure_budget_scheme: DISCLOSURE_BUDGET_SCHEME.to_string(),
            settlement_scheme: SETTLEMENT_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            max_calls_per_session: DEFAULT_MAX_CALLS_PER_SESSION,
            max_meter_buckets: DEFAULT_MAX_METER_BUCKETS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            disclosure_budget_units: DEFAULT_DISCLOSURE_BUDGET_UNITS,
            disclosure_renewal_blocks: DEFAULT_DISCLOSURE_RENEWAL_BLOCKS,
            operator_summary_bucket_size: DEFAULT_OPERATOR_SUMMARY_BUCKET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            fast_aggregation_min_sessions: DEFAULT_FAST_AGGREGATION_MIN_SESSIONS,
            fast_aggregation_target_sessions: DEFAULT_FAST_AGGREGATION_TARGET_SESSIONS,
            witness_byte_price_micro_units: DEFAULT_WITNESS_BYTE_PRICE_MICRO_UNITS,
            gas_unit_price_micro_units: DEFAULT_GAS_UNIT_PRICE_MICRO_UNITS,
            settlement_quorum_bps: DEFAULT_SETTLEMENT_QUORUM_BPS,
            strong_settlement_quorum_bps: DEFAULT_STRONG_SETTLEMENT_QUORUM_BPS,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub contract_sessions: u64,
    pub callgraph_commitments: u64,
    pub meter_buckets: u64,
    pub pq_attestations: u64,
    pub disclosure_budgets: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub operator_summaries: u64,
    pub aggregation_rounds: u64,
    pub rejected_records: u64,
}

impl Counters {
    pub fn next(&mut self) -> u64 {
        self.next_sequence += 1;
        self.next_sequence
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub session_root: String,
    pub callgraph_root: String,
    pub meter_bucket_root: String,
    pub attestation_root: String,
    pub disclosure_budget_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub operator_summary_root: String,
    pub aggregation_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            session_root: empty_root("CALLGRAPH-METER-SESSION"),
            callgraph_root: empty_root("CALLGRAPH-METER-CALLGRAPH"),
            meter_bucket_root: empty_root("CALLGRAPH-METER-BUCKET"),
            attestation_root: empty_root("CALLGRAPH-METER-ATTESTATION"),
            disclosure_budget_root: empty_root("CALLGRAPH-METER-DISCLOSURE"),
            settlement_root: empty_root("CALLGRAPH-METER-SETTLEMENT"),
            rebate_root: empty_root("CALLGRAPH-METER-REBATE"),
            operator_summary_root: empty_root("CALLGRAPH-METER-OPERATOR-SUMMARY"),
            aggregation_root: empty_root("CALLGRAPH-METER-AGGREGATION"),
            nullifier_root: empty_root("CALLGRAPH-METER-NULLIFIER"),
            public_record_root: empty_root("CALLGRAPH-METER-PUBLIC-RECORD"),
            state_root: empty_root("CALLGRAPH-METER-STATE"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractSessionRequest {
    pub caller_commitment: String,
    pub contract_class_commitment: String,
    pub entry_selector_commitment: String,
    pub private_input_root: String,
    pub encrypted_context_root: String,
    pub disclosure_policy_root: String,
    pub max_call_depth: u16,
    pub max_calls: u32,
    pub fee_cap_micro_units: u64,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub session_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractSessionRecord {
    pub session_id: String,
    pub sequence: u64,
    pub status: SessionStatus,
    pub caller_commitment: String,
    pub contract_class_commitment: String,
    pub entry_selector_commitment: String,
    pub private_input_root: String,
    pub encrypted_context_root: String,
    pub disclosure_policy_root: String,
    pub max_call_depth: u16,
    pub max_calls: u32,
    pub fee_cap_micro_units: u64,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub callgraph_commitments: BTreeSet<String>,
    pub meter_buckets: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub settlement_ids: BTreeSet<String>,
    pub rebate_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallgraphCommitmentRequest {
    pub session_id: String,
    pub prover_id: String,
    pub callgraph_root: String,
    pub edge_commitment_root: String,
    pub node_commitment_root: String,
    pub storage_access_root: String,
    pub private_output_root: String,
    pub witness_commitment_root: String,
    pub call_count: u32,
    pub max_depth_observed: u16,
    pub visibility: CallEdgeVisibility,
    pub aggregation_hint_root: String,
    pub commitment_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallgraphCommitmentRecord {
    pub callgraph_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub status: CallgraphStatus,
    pub prover_id: String,
    pub callgraph_root: String,
    pub edge_commitment_root: String,
    pub node_commitment_root: String,
    pub storage_access_root: String,
    pub private_output_root: String,
    pub witness_commitment_root: String,
    pub call_count: u32,
    pub max_depth_observed: u16,
    pub visibility: CallEdgeVisibility,
    pub aggregation_hint_root: String,
    pub privacy_preserving_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeterBucketRequest {
    pub session_id: String,
    pub callgraph_id: String,
    pub bucket_kind: MeterBucketKind,
    pub gas_units: u64,
    pub witness_bytes: u64,
    pub storage_read_units: u64,
    pub storage_write_units: u64,
    pub call_count_bucket: u64,
    pub depth_bucket: u64,
    pub private_meter_root: String,
    pub aggregation_root: String,
    pub fee_quote_micro_units: u64,
    pub bucket_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeterBucketRecord {
    pub bucket_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub callgraph_id: String,
    pub status: MeterBucketStatus,
    pub bucket_kind: MeterBucketKind,
    pub gas_units: u64,
    pub witness_bytes: u64,
    pub storage_read_units: u64,
    pub storage_write_units: u64,
    pub call_count_bucket: u64,
    pub depth_bucket: u64,
    pub private_meter_root: String,
    pub aggregation_root: String,
    pub fee_quote_micro_units: u64,
    pub metered_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExecutionAttestationRequest {
    pub session_id: String,
    pub callgraph_id: String,
    pub attester_id: String,
    pub committee_id: String,
    pub l2_height: u64,
    pub expires_l2_height: u64,
    pub pq_security_bits: u16,
    pub attester_weight_bps: u64,
    pub execution_transcript_root: String,
    pub meter_transcript_root: String,
    pub disclosure_transcript_root: String,
    pub signature_commitment: String,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExecutionAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub callgraph_id: String,
    pub status: AttestationStatus,
    pub attester_id: String,
    pub committee_id: String,
    pub l2_height: u64,
    pub expires_l2_height: u64,
    pub pq_security_bits: u16,
    pub attester_weight_bps: u64,
    pub execution_transcript_root: String,
    pub meter_transcript_root: String,
    pub disclosure_transcript_root: String,
    pub signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureBudgetRequest {
    pub session_id: String,
    pub grantee_commitment: String,
    pub scope: DisclosureScope,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub disclosure_root: String,
    pub policy_root: String,
    pub renew_after_l2_height: u64,
    pub budget_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureBudgetRecord {
    pub budget_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub status: DisclosureBudgetStatus,
    pub grantee_commitment: String,
    pub scope: DisclosureScope,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub remaining_units: u64,
    pub disclosure_root: String,
    pub policy_root: String,
    pub renew_after_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRequest {
    pub session_id: String,
    pub aggregator_id: String,
    pub meter_bucket_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub settlement_batch_root: String,
    pub fee_liability_root: String,
    pub private_receipt_root: String,
    pub settlement_l2_height: u64,
    pub aggregation_round: u64,
    pub settlement_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub status: SettlementStatus,
    pub aggregator_id: String,
    pub meter_bucket_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub settlement_batch_root: String,
    pub fee_liability_root: String,
    pub private_receipt_root: String,
    pub settlement_l2_height: u64,
    pub aggregation_round: u64,
    pub total_metered_fee_micro_units: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub session_id: String,
    pub settlement_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub rebate_basis_micro_units: u64,
    pub sponsor_pool_root: String,
    pub rebate_policy_root: String,
    pub rebate_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub settlement_id: String,
    pub status: RebateStatus,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub rebate_basis_micro_units: u64,
    pub rebate_amount_micro_units: u64,
    pub sponsor_pool_root: String,
    pub rebate_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub producer_id: String,
    pub audience: SummaryAudience,
    pub risk: SummaryRisk,
    pub session_ids: BTreeSet<String>,
    pub settlement_ids: BTreeSet<String>,
    pub bucketed_metrics_root: String,
    pub redacted_callgraph_root: String,
    pub redacted_exception_root: String,
    pub fee_summary_root: String,
    pub disclosure_summary_root: String,
    pub summary_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub sequence: u64,
    pub producer_id: String,
    pub audience: SummaryAudience,
    pub risk: SummaryRisk,
    pub session_count_bucket: u64,
    pub settlement_count_bucket: u64,
    pub metered_fee_bucket: u64,
    pub rebate_bucket: u64,
    pub operator_safe_root: String,
    pub bucketed_metrics_root: String,
    pub redacted_callgraph_root: String,
    pub redacted_exception_root: String,
    pub fee_summary_root: String,
    pub disclosure_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregationRoundRecord {
    pub aggregation_id: String,
    pub sequence: u64,
    pub aggregator_id: String,
    pub session_root: String,
    pub callgraph_root: String,
    pub meter_root: String,
    pub settlement_root: String,
    pub session_count: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sessions: BTreeMap<String, ContractSessionRecord>,
    pub callgraphs: BTreeMap<String, CallgraphCommitmentRecord>,
    pub meter_buckets: BTreeMap<String, MeterBucketRecord>,
    pub attestations: BTreeMap<String, PqExecutionAttestationRecord>,
    pub disclosure_budgets: BTreeMap<String, DisclosureBudgetRecord>,
    pub settlements: BTreeMap<String, SettlementRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub aggregation_rounds: BTreeMap<String, AggregationRoundRecord>,
    pub nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet()).expect("devnet config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        require(config.max_call_depth > 0, "max call depth must be nonzero")?;
        require(
            config.max_calls_per_session > 0,
            "max calls must be nonzero",
        )?;
        require(
            config.min_pq_security_bits <= config.target_pq_security_bits,
            "min pq security exceeds target",
        )?;
        require(
            config.settlement_quorum_bps <= MAX_BPS
                && config.strong_settlement_quorum_bps <= MAX_BPS,
            "quorum bps exceeds max",
        )?;
        require(
            config.settlement_quorum_bps <= config.strong_settlement_quorum_bps,
            "strong quorum below quorum",
        )?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sessions: BTreeMap::new(),
            callgraphs: BTreeMap::new(),
            meter_buckets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            disclosure_budgets: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            aggregation_rounds: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn open_contract_session(
        &mut self,
        request: ContractSessionRequest,
    ) -> Result<ContractSessionRecord> {
        require(
            request.opened_l2_height < request.expires_l2_height,
            "session expiry must be after open height",
        )?;
        require(
            request.max_call_depth <= self.config.max_call_depth,
            "session call depth exceeds config",
        )?;
        require(
            request.max_calls <= self.config.max_calls_per_session,
            "session call count exceeds config",
        )?;
        let sequence = self.counters.next();
        let session_id = session_id(sequence, &request);
        require_unique(&mut self.nullifiers, "session", &session_id)?;
        let record = ContractSessionRecord {
            session_id: session_id.clone(),
            sequence,
            status: SessionStatus::Open,
            caller_commitment: request.caller_commitment,
            contract_class_commitment: request.contract_class_commitment,
            entry_selector_commitment: request.entry_selector_commitment,
            private_input_root: request.private_input_root,
            encrypted_context_root: request.encrypted_context_root,
            disclosure_policy_root: request.disclosure_policy_root,
            max_call_depth: request.max_call_depth,
            max_calls: request.max_calls,
            fee_cap_micro_units: request.fee_cap_micro_units,
            opened_l2_height: request.opened_l2_height,
            expires_l2_height: request.expires_l2_height,
            callgraph_commitments: BTreeSet::new(),
            meter_buckets: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            settlement_ids: BTreeSet::new(),
            rebate_ids: BTreeSet::new(),
        };
        self.sessions.insert(session_id, record.clone());
        self.counters.contract_sessions += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn commit_callgraph(
        &mut self,
        request: CallgraphCommitmentRequest,
    ) -> Result<CallgraphCommitmentRecord> {
        let session = self
            .sessions
            .get(&request.session_id)
            .ok_or_else(|| "unknown session".to_string())?;
        require(
            session.status.accepts_callgraph(),
            "session does not accept callgraph commitments",
        )?;
        require(
            request.call_count <= session.max_calls,
            "call count exceeds session max",
        )?;
        require(
            request.max_depth_observed <= session.max_call_depth,
            "observed depth exceeds session max",
        )?;
        let sequence = self.counters.next();
        let private_commitment = private_callgraph_commitment(sequence, &request);
        let callgraph_id = callgraph_id(sequence, &request, &private_commitment);
        require_unique(&mut self.nullifiers, "callgraph", &callgraph_id)?;
        let record = CallgraphCommitmentRecord {
            callgraph_id: callgraph_id.clone(),
            sequence,
            session_id: request.session_id.clone(),
            status: CallgraphStatus::DepthChecked,
            prover_id: request.prover_id,
            callgraph_root: request.callgraph_root,
            edge_commitment_root: request.edge_commitment_root,
            node_commitment_root: request.node_commitment_root,
            storage_access_root: request.storage_access_root,
            private_output_root: request.private_output_root,
            witness_commitment_root: request.witness_commitment_root,
            call_count: request.call_count,
            max_depth_observed: request.max_depth_observed,
            visibility: request.visibility,
            aggregation_hint_root: request.aggregation_hint_root,
            privacy_preserving_commitment: private_commitment,
        };
        self.callgraphs.insert(callgraph_id.clone(), record.clone());
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::CallgraphCommitted;
            session.callgraph_commitments.insert(callgraph_id);
        }
        self.counters.callgraph_commitments += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn record_meter_bucket(
        &mut self,
        request: MeterBucketRequest,
    ) -> Result<MeterBucketRecord> {
        let session = self
            .sessions
            .get(&request.session_id)
            .ok_or_else(|| "unknown session".to_string())?;
        require(
            session.status.accepts_metering(),
            "session does not accept metering",
        )?;
        require(
            self.callgraphs.contains_key(&request.callgraph_id),
            "unknown callgraph",
        )?;
        require(
            session.meter_buckets.len() < self.config.max_meter_buckets,
            "session meter bucket limit reached",
        )?;
        let sequence = self.counters.next();
        let metered_fee = self.metered_fee_micro_units(&request);
        require(
            metered_fee <= session.fee_cap_micro_units,
            "metered fee exceeds session cap",
        )?;
        let bucket_id = meter_bucket_id(sequence, &request, metered_fee);
        require_unique(&mut self.nullifiers, "meter_bucket", &bucket_id)?;
        let record = MeterBucketRecord {
            bucket_id: bucket_id.clone(),
            sequence,
            session_id: request.session_id.clone(),
            callgraph_id: request.callgraph_id.clone(),
            status: MeterBucketStatus::Aggregated,
            bucket_kind: request.bucket_kind,
            gas_units: request.gas_units,
            witness_bytes: request.witness_bytes,
            storage_read_units: request.storage_read_units,
            storage_write_units: request.storage_write_units,
            call_count_bucket: request.call_count_bucket,
            depth_bucket: request.depth_bucket,
            private_meter_root: request.private_meter_root,
            aggregation_root: request.aggregation_root,
            fee_quote_micro_units: request.fee_quote_micro_units,
            metered_fee_micro_units: metered_fee,
        };
        self.meter_buckets.insert(bucket_id.clone(), record.clone());
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::Metered;
            session.meter_buckets.insert(bucket_id.clone());
        }
        if let Some(callgraph) = self.callgraphs.get_mut(&request.callgraph_id) {
            callgraph.status = CallgraphStatus::Metered;
        }
        self.counters.meter_buckets += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn attest_execution(
        &mut self,
        request: PqExecutionAttestationRequest,
    ) -> Result<PqExecutionAttestationRecord> {
        require(
            self.sessions.contains_key(&request.session_id),
            "unknown session",
        )?;
        require(
            self.callgraphs.contains_key(&request.callgraph_id),
            "unknown callgraph",
        )?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security below minimum",
        )?;
        require(
            request.l2_height < request.expires_l2_height,
            "attestation already expired",
        )?;
        let sequence = self.counters.next();
        let attestation_id = attestation_id(sequence, &request);
        require_unique(&mut self.nullifiers, "attestation", &attestation_id)?;
        let status = if request.attester_weight_bps >= self.config.strong_settlement_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if request.attester_weight_bps >= self.config.settlement_quorum_bps {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        let record = PqExecutionAttestationRecord {
            attestation_id: attestation_id.clone(),
            sequence,
            session_id: request.session_id.clone(),
            callgraph_id: request.callgraph_id.clone(),
            status,
            attester_id: request.attester_id,
            committee_id: request.committee_id,
            l2_height: request.l2_height,
            expires_l2_height: request.expires_l2_height,
            pq_security_bits: request.pq_security_bits,
            attester_weight_bps: request.attester_weight_bps,
            execution_transcript_root: request.execution_transcript_root,
            meter_transcript_root: request.meter_transcript_root,
            disclosure_transcript_root: request.disclosure_transcript_root,
            signature_commitment: request.signature_commitment,
        };
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = if status.counts_for_quorum() {
                SessionStatus::Attested
            } else {
                SessionStatus::Attesting
            };
            session.attestation_ids.insert(attestation_id.clone());
        }
        if let Some(callgraph) = self.callgraphs.get_mut(&request.callgraph_id) {
            callgraph.status = CallgraphStatus::Attested;
        }
        self.counters.pq_attestations += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn reserve_disclosure_budget(
        &mut self,
        request: DisclosureBudgetRequest,
    ) -> Result<DisclosureBudgetRecord> {
        require(
            self.sessions.contains_key(&request.session_id),
            "unknown session",
        )?;
        require(
            request.total_units <= self.config.disclosure_budget_units,
            "disclosure budget exceeds config",
        )?;
        require(
            request.reserved_units + request.consumed_units <= request.total_units,
            "disclosure units exceed total",
        )?;
        let sequence = self.counters.next();
        let remaining_units = request
            .total_units
            .saturating_sub(request.reserved_units + request.consumed_units);
        let budget_id = disclosure_budget_id(sequence, &request, remaining_units);
        require_unique(&mut self.nullifiers, "disclosure_budget", &budget_id)?;
        let status = if remaining_units == 0 {
            DisclosureBudgetStatus::Exhausted
        } else if request.consumed_units > 0 {
            DisclosureBudgetStatus::Consumed
        } else {
            DisclosureBudgetStatus::Reserved
        };
        let record = DisclosureBudgetRecord {
            budget_id: budget_id.clone(),
            sequence,
            session_id: request.session_id,
            status,
            grantee_commitment: request.grantee_commitment,
            scope: request.scope,
            total_units: request.total_units,
            reserved_units: request.reserved_units,
            consumed_units: request.consumed_units,
            remaining_units,
            disclosure_root: request.disclosure_root,
            policy_root: request.policy_root,
            renew_after_l2_height: request.renew_after_l2_height,
        };
        self.disclosure_budgets.insert(budget_id, record.clone());
        self.counters.disclosure_budgets += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn settle_metering(&mut self, request: SettlementRequest) -> Result<SettlementRecord> {
        require(
            self.sessions.contains_key(&request.session_id),
            "unknown session",
        )?;
        require(
            !request.meter_bucket_ids.is_empty(),
            "settlement needs meter buckets",
        )?;
        require(
            !request.attestation_ids.is_empty(),
            "settlement needs attestations",
        )?;
        let total_metered_fee = self.total_metered_fee(&request.meter_bucket_ids)?;
        let quorum_weight_bps = self.quorum_weight_bps(&request.attestation_ids)?;
        require(
            quorum_weight_bps >= self.config.settlement_quorum_bps,
            "settlement quorum not reached",
        )?;
        let sequence = self.counters.next();
        let settlement_id = settlement_id(sequence, &request, total_metered_fee, quorum_weight_bps);
        require_unique(&mut self.nullifiers, "settlement", &settlement_id)?;
        let status = if quorum_weight_bps >= self.config.strong_settlement_quorum_bps {
            SettlementStatus::Finalized
        } else {
            SettlementStatus::Attested
        };
        let record = SettlementRecord {
            settlement_id: settlement_id.clone(),
            sequence,
            session_id: request.session_id.clone(),
            status,
            aggregator_id: request.aggregator_id,
            meter_bucket_ids: request.meter_bucket_ids.clone(),
            attestation_ids: request.attestation_ids,
            settlement_batch_root: request.settlement_batch_root,
            fee_liability_root: request.fee_liability_root,
            private_receipt_root: request.private_receipt_root,
            settlement_l2_height: request.settlement_l2_height,
            aggregation_round: request.aggregation_round,
            total_metered_fee_micro_units: total_metered_fee,
            quorum_weight_bps,
        };
        self.settlements
            .insert(settlement_id.clone(), record.clone());
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::Settled;
            session.settlement_ids.insert(settlement_id.clone());
        }
        for bucket_id in &request.meter_bucket_ids {
            if let Some(bucket) = self.meter_buckets.get_mut(bucket_id) {
                bucket.status = MeterBucketStatus::Settled;
            }
        }
        self.counters.settlements += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn apply_low_fee_rebate(&mut self, request: RebateRequest) -> Result<RebateRecord> {
        require(
            self.sessions.contains_key(&request.session_id),
            "unknown session",
        )?;
        require(
            self.settlements.contains_key(&request.settlement_id),
            "unknown settlement",
        )?;
        let sequence = self.counters.next();
        let rebate_amount = request
            .rebate_basis_micro_units
            .saturating_mul(self.config.rebate_bps)
            / MAX_BPS;
        let rebate_id = rebate_id(sequence, &request, rebate_amount);
        require_unique(&mut self.nullifiers, "rebate", &rebate_id)?;
        let record = RebateRecord {
            rebate_id: rebate_id.clone(),
            sequence,
            session_id: request.session_id.clone(),
            settlement_id: request.settlement_id,
            status: RebateStatus::Applied,
            sponsor_id: request.sponsor_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_basis_micro_units: request.rebate_basis_micro_units,
            rebate_amount_micro_units: rebate_amount,
            sponsor_pool_root: request.sponsor_pool_root,
            rebate_policy_root: request.rebate_policy_root,
        };
        self.rebates.insert(rebate_id.clone(), record.clone());
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::Rebated;
            session.rebate_ids.insert(rebate_id);
        }
        self.counters.rebates += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummaryRecord> {
        require(!request.session_ids.is_empty(), "summary needs sessions")?;
        for session_id in &request.session_ids {
            require(
                self.sessions.contains_key(session_id),
                "unknown summary session",
            )?;
        }
        for settlement_id in &request.settlement_ids {
            require(
                self.settlements.contains_key(settlement_id),
                "unknown summary settlement",
            )?;
        }
        let sequence = self.counters.next();
        let session_count_bucket = bucket_count(
            request.session_ids.len() as u64,
            self.config.operator_summary_bucket_size,
        );
        let settlement_count_bucket = bucket_count(
            request.settlement_ids.len() as u64,
            self.config.operator_summary_bucket_size,
        );
        let metered_fee_bucket = bucket_count(
            self.total_settlement_fees(&request.settlement_ids),
            self.config.operator_summary_bucket_size,
        );
        let rebate_bucket = bucket_count(
            self.total_session_rebates(&request.session_ids),
            self.config.operator_summary_bucket_size,
        );
        let operator_safe_root = operator_safe_summary_root(
            sequence,
            &request,
            session_count_bucket,
            settlement_count_bucket,
            metered_fee_bucket,
            rebate_bucket,
        );
        let summary_id = summary_id(sequence, &request, &operator_safe_root);
        require_unique(&mut self.nullifiers, "operator_summary", &summary_id)?;
        let record = OperatorSummaryRecord {
            summary_id: summary_id.clone(),
            sequence,
            producer_id: request.producer_id,
            audience: request.audience,
            risk: request.risk,
            session_count_bucket,
            settlement_count_bucket,
            metered_fee_bucket,
            rebate_bucket,
            operator_safe_root,
            bucketed_metrics_root: request.bucketed_metrics_root,
            redacted_callgraph_root: request.redacted_callgraph_root,
            redacted_exception_root: request.redacted_exception_root,
            fee_summary_root: request.fee_summary_root,
            disclosure_summary_root: request.disclosure_summary_root,
        };
        self.operator_summaries.insert(summary_id, record.clone());
        self.counters.operator_summaries += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn aggregate_fast_round(
        &mut self,
        aggregator_id: String,
    ) -> Result<AggregationRoundRecord> {
        require(
            self.sessions.len() as u64 >= self.config.fast_aggregation_min_sessions,
            "not enough sessions for fast aggregation round",
        )?;
        let sequence = self.counters.next();
        let session_root = map_root("CALLGRAPH-METER-AGG-SESSION", &self.sessions);
        let callgraph_root = map_root("CALLGRAPH-METER-AGG-CALLGRAPH", &self.callgraphs);
        let meter_root = map_root("CALLGRAPH-METER-AGG-METER", &self.meter_buckets);
        let settlement_root = map_root("CALLGRAPH-METER-AGG-SETTLEMENT", &self.settlements);
        let total_fee_micro_units = self
            .meter_buckets
            .values()
            .map(|bucket| bucket.metered_fee_micro_units)
            .sum();
        let total_rebate_micro_units = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_amount_micro_units)
            .sum();
        let aggregation_id = domain_hash(
            "CALLGRAPH-METER-AGGREGATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(&aggregator_id),
                HashPart::Str(&session_root),
                HashPart::Str(&meter_root),
                HashPart::U64(total_fee_micro_units),
                HashPart::U64(total_rebate_micro_units),
            ],
            32,
        );
        require_unique(&mut self.nullifiers, "aggregation", &aggregation_id)?;
        let record = AggregationRoundRecord {
            aggregation_id: aggregation_id.clone(),
            sequence,
            aggregator_id,
            session_root,
            callgraph_root,
            meter_root,
            settlement_root,
            session_count: self.sessions.len() as u64,
            total_fee_micro_units,
            total_rebate_micro_units,
        };
        self.aggregation_rounds
            .insert(aggregation_id, record.clone());
        self.counters.aggregation_rounds += 1;
        self.recompute_roots();
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": record_value(&self.config),
            "counters": record_value(&self.counters),
            "roots": record_value(&self.roots),
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
    }

    fn metered_fee_micro_units(&self, request: &MeterBucketRequest) -> u64 {
        let gas_fee = request
            .gas_units
            .saturating_mul(self.config.gas_unit_price_micro_units);
        let witness_fee = request
            .witness_bytes
            .saturating_mul(self.config.witness_byte_price_micro_units);
        gas_fee
            .saturating_add(witness_fee)
            .saturating_add(request.fee_quote_micro_units)
    }

    fn total_metered_fee(&self, bucket_ids: &BTreeSet<String>) -> Result<u64> {
        let mut total = 0u64;
        for bucket_id in bucket_ids {
            let bucket = self
                .meter_buckets
                .get(bucket_id)
                .ok_or_else(|| format!("unknown meter bucket: {bucket_id}"))?;
            total = total.saturating_add(bucket.metered_fee_micro_units);
        }
        Ok(total)
    }

    fn quorum_weight_bps(&self, attestation_ids: &BTreeSet<String>) -> Result<u64> {
        let mut total = 0u64;
        for attestation_id in attestation_ids {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| format!("unknown attestation: {attestation_id}"))?;
            if attestation.status.counts_for_quorum() {
                total = total.saturating_add(attestation.attester_weight_bps);
            }
        }
        Ok(total.min(MAX_BPS))
    }

    fn total_settlement_fees(&self, settlement_ids: &BTreeSet<String>) -> u64 {
        settlement_ids
            .iter()
            .filter_map(|settlement_id| self.settlements.get(settlement_id))
            .map(|settlement| settlement.total_metered_fee_micro_units)
            .sum()
    }

    fn total_session_rebates(&self, session_ids: &BTreeSet<String>) -> u64 {
        self.rebates
            .values()
            .filter(|rebate| session_ids.contains(&rebate.session_id))
            .map(|rebate| rebate.rebate_amount_micro_units)
            .sum()
    }

    fn recompute_roots(&mut self) {
        self.roots.session_root = map_root("CALLGRAPH-METER-SESSION", &self.sessions);
        self.roots.callgraph_root = map_root("CALLGRAPH-METER-CALLGRAPH", &self.callgraphs);
        self.roots.meter_bucket_root = map_root("CALLGRAPH-METER-BUCKET", &self.meter_buckets);
        self.roots.attestation_root = map_root("CALLGRAPH-METER-ATTESTATION", &self.attestations);
        self.roots.disclosure_budget_root =
            map_root("CALLGRAPH-METER-DISCLOSURE", &self.disclosure_budgets);
        self.roots.settlement_root = map_root("CALLGRAPH-METER-SETTLEMENT", &self.settlements);
        self.roots.rebate_root = map_root("CALLGRAPH-METER-REBATE", &self.rebates);
        self.roots.operator_summary_root =
            map_root("CALLGRAPH-METER-OPERATOR-SUMMARY", &self.operator_summaries);
        self.roots.aggregation_root =
            map_root("CALLGRAPH-METER-AGGREGATION", &self.aggregation_rounds);
        self.roots.nullifier_root = set_root("CALLGRAPH-METER-NULLIFIER", &self.nullifiers);
        self.roots.public_record_root = domain_hash(
            "CALLGRAPH-METER-PUBLIC-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        );
        self.roots.state_root = self.compute_state_root();
    }

    fn compute_state_root(&self) -> String {
        let config_record = record_value(&self.config);
        let counters_record = record_value(&self.counters);
        domain_hash(
            "CALLGRAPH-METER-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&config_record),
                HashPart::Json(&counters_record),
                HashPart::Str(&self.roots.session_root),
                HashPart::Str(&self.roots.callgraph_root),
                HashPart::Str(&self.roots.meter_bucket_root),
                HashPart::Str(&self.roots.attestation_root),
                HashPart::Str(&self.roots.disclosure_budget_root),
                HashPart::Str(&self.roots.settlement_root),
                HashPart::Str(&self.roots.rebate_root),
                HashPart::Str(&self.roots.operator_summary_root),
                HashPart::Str(&self.roots.aggregation_root),
                HashPart::Str(&self.roots.nullifier_root),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let session = state
        .open_contract_session(ContractSessionRequest {
            caller_commitment: seeded_root("caller"),
            contract_class_commitment: seeded_root("contract-class"),
            entry_selector_commitment: seeded_root("entry-selector"),
            private_input_root: seeded_root("private-input"),
            encrypted_context_root: seeded_root("encrypted-context"),
            disclosure_policy_root: seeded_root("disclosure-policy"),
            max_call_depth: 8,
            max_calls: 64,
            fee_cap_micro_units: 8_000_000,
            opened_l2_height: DEVNET_HEIGHT,
            expires_l2_height: DEVNET_HEIGHT + 96,
            session_nonce: "devnet-session-0".to_string(),
        })
        .expect("demo session opens");
    let callgraph = state
        .commit_callgraph(CallgraphCommitmentRequest {
            session_id: session.session_id.clone(),
            prover_id: "devnet-prover-0".to_string(),
            callgraph_root: seeded_root("callgraph"),
            edge_commitment_root: seeded_root("edges"),
            node_commitment_root: seeded_root("nodes"),
            storage_access_root: seeded_root("storage"),
            private_output_root: seeded_root("private-output"),
            witness_commitment_root: seeded_root("witness"),
            call_count: 32,
            max_depth_observed: 6,
            visibility: CallEdgeVisibility::FullyPrivate,
            aggregation_hint_root: seeded_root("aggregation-hint"),
            commitment_nonce: "devnet-callgraph-0".to_string(),
        })
        .expect("demo callgraph commits");
    let bucket = state
        .record_meter_bucket(MeterBucketRequest {
            session_id: session.session_id.clone(),
            callgraph_id: callgraph.callgraph_id.clone(),
            bucket_kind: MeterBucketKind::ExecutionGas,
            gas_units: 1_250_000,
            witness_bytes: 96_000,
            storage_read_units: 512,
            storage_write_units: 64,
            call_count_bucket: 64,
            depth_bucket: 8,
            private_meter_root: seeded_root("private-meter"),
            aggregation_root: seeded_root("meter-aggregation"),
            fee_quote_micro_units: 1_000,
            bucket_nonce: "devnet-meter-bucket-0".to_string(),
        })
        .expect("demo bucket meters");
    let attestation = state
        .attest_execution(PqExecutionAttestationRequest {
            session_id: session.session_id.clone(),
            callgraph_id: callgraph.callgraph_id.clone(),
            attester_id: "devnet-attester-0".to_string(),
            committee_id: "devnet-pq-committee".to_string(),
            l2_height: DEVNET_HEIGHT + 4,
            expires_l2_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attester_weight_bps: DEFAULT_STRONG_SETTLEMENT_QUORUM_BPS,
            execution_transcript_root: seeded_root("execution-transcript"),
            meter_transcript_root: seeded_root("meter-transcript"),
            disclosure_transcript_root: seeded_root("disclosure-transcript"),
            signature_commitment: seeded_root("pq-signature"),
            attestation_nonce: "devnet-attestation-0".to_string(),
        })
        .expect("demo attestation accepts");
    state
        .reserve_disclosure_budget(DisclosureBudgetRequest {
            session_id: session.session_id.clone(),
            grantee_commitment: seeded_root("auditor-grantee"),
            scope: DisclosureScope::MeterTotals,
            total_units: 16,
            reserved_units: 4,
            consumed_units: 2,
            disclosure_root: seeded_root("selective-disclosure"),
            policy_root: seeded_root("budget-policy"),
            renew_after_l2_height: DEVNET_HEIGHT + DEFAULT_DISCLOSURE_RENEWAL_BLOCKS,
            budget_nonce: "devnet-budget-0".to_string(),
        })
        .expect("demo disclosure budget reserves");
    let mut bucket_ids = BTreeSet::new();
    bucket_ids.insert(bucket.bucket_id.clone());
    let mut attestation_ids = BTreeSet::new();
    attestation_ids.insert(attestation.attestation_id.clone());
    let settlement = state
        .settle_metering(SettlementRequest {
            session_id: session.session_id.clone(),
            aggregator_id: "devnet-fast-aggregator-0".to_string(),
            meter_bucket_ids: bucket_ids,
            attestation_ids,
            settlement_batch_root: seeded_root("settlement-batch"),
            fee_liability_root: seeded_root("fee-liability"),
            private_receipt_root: seeded_root("private-receipt"),
            settlement_l2_height: DEVNET_HEIGHT + 8,
            aggregation_round: 1,
            settlement_nonce: "devnet-settlement-0".to_string(),
        })
        .expect("demo settlement finalizes");
    state
        .apply_low_fee_rebate(RebateRequest {
            session_id: session.session_id.clone(),
            settlement_id: settlement.settlement_id.clone(),
            sponsor_id: "devnet-low-fee-sponsor-0".to_string(),
            beneficiary_commitment: seeded_root("beneficiary"),
            rebate_basis_micro_units: settlement.total_metered_fee_micro_units,
            sponsor_pool_root: seeded_root("sponsor-pool"),
            rebate_policy_root: seeded_root("rebate-policy"),
            rebate_nonce: "devnet-rebate-0".to_string(),
        })
        .expect("demo rebate applies");
    let mut session_ids = BTreeSet::new();
    session_ids.insert(session.session_id);
    let mut settlement_ids = BTreeSet::new();
    settlement_ids.insert(settlement.settlement_id);
    state
        .publish_operator_summary(OperatorSummaryRequest {
            producer_id: "devnet-operator-0".to_string(),
            audience: SummaryAudience::Operator,
            risk: SummaryRisk::Nominal,
            session_ids,
            settlement_ids,
            bucketed_metrics_root: seeded_root("summary-metrics"),
            redacted_callgraph_root: seeded_root("summary-callgraph"),
            redacted_exception_root: seeded_root("summary-exceptions"),
            fee_summary_root: seeded_root("summary-fees"),
            disclosure_summary_root: seeded_root("summary-disclosures"),
            summary_nonce: "devnet-summary-0".to_string(),
        })
        .expect("demo summary publishes");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_unique(nullifiers: &mut BTreeSet<String>, domain: &str, value: &str) -> Result<()> {
    let key = format!("{domain}:{value}");
    if nullifiers.insert(key) {
        Ok(())
    } else {
        Err(format!("duplicate {domain} nullifier"))
    }
}

fn record_value<T: Serialize>(record: &T) -> Value {
    serde_json::to_value(record).expect("record serializes")
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, record)| {
            let value = record_value(record);
            domain_hash(
                &format!("{domain}-LEAF"),
                &[HashPart::Str(key), HashPart::Json(&value)],
                32,
            )
        })
        .collect::<Vec<_>>();
    let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn seeded_root(seed: &str) -> String {
    domain_hash(
        "CALLGRAPH-METER-DEVNET-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn bucket_count(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        value.div_ceil(bucket_size) * bucket_size
    }
}

fn session_id(sequence: u64, request: &ContractSessionRequest) -> String {
    domain_hash(
        "CALLGRAPH-METER-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.contract_class_commitment),
            HashPart::Str(&request.entry_selector_commitment),
            HashPart::Str(&request.private_input_root),
            HashPart::Str(&request.session_nonce),
        ],
        32,
    )
}

fn private_callgraph_commitment(sequence: u64, request: &CallgraphCommitmentRequest) -> String {
    let visibility = enum_tag(request.visibility);
    domain_hash(
        "CALLGRAPH-METER-PRIVATE-CALLGRAPH-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.callgraph_root),
            HashPart::Str(&request.edge_commitment_root),
            HashPart::Str(&request.node_commitment_root),
            HashPart::Str(&request.witness_commitment_root),
            HashPart::Str(&visibility),
        ],
        32,
    )
}

fn callgraph_id(
    sequence: u64,
    request: &CallgraphCommitmentRequest,
    private_commitment: &str,
) -> String {
    domain_hash(
        "CALLGRAPH-METER-CALLGRAPH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.prover_id),
            HashPart::Str(private_commitment),
            HashPart::U64(request.call_count as u64),
            HashPart::U64(request.max_depth_observed as u64),
            HashPart::Str(&request.commitment_nonce),
        ],
        32,
    )
}

fn meter_bucket_id(
    sequence: u64,
    request: &MeterBucketRequest,
    metered_fee_micro_units: u64,
) -> String {
    let bucket_kind = enum_tag(request.bucket_kind);
    domain_hash(
        "CALLGRAPH-METER-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.callgraph_id),
            HashPart::Str(&bucket_kind),
            HashPart::U64(request.gas_units),
            HashPart::U64(request.witness_bytes),
            HashPart::U64(metered_fee_micro_units),
            HashPart::Str(&request.private_meter_root),
            HashPart::Str(&request.bucket_nonce),
        ],
        32,
    )
}

fn attestation_id(sequence: u64, request: &PqExecutionAttestationRequest) -> String {
    domain_hash(
        "CALLGRAPH-METER-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.callgraph_id),
            HashPart::Str(&request.attester_id),
            HashPart::Str(&request.committee_id),
            HashPart::U64(request.l2_height),
            HashPart::U64(request.pq_security_bits as u64),
            HashPart::U64(request.attester_weight_bps),
            HashPart::Str(&request.execution_transcript_root),
            HashPart::Str(&request.signature_commitment),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

fn disclosure_budget_id(
    sequence: u64,
    request: &DisclosureBudgetRequest,
    remaining_units: u64,
) -> String {
    let scope = enum_tag(request.scope);
    domain_hash(
        "CALLGRAPH-METER-DISCLOSURE-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.grantee_commitment),
            HashPart::Str(&scope),
            HashPart::U64(request.total_units),
            HashPart::U64(remaining_units),
            HashPart::Str(&request.disclosure_root),
            HashPart::Str(&request.budget_nonce),
        ],
        32,
    )
}

fn settlement_id(
    sequence: u64,
    request: &SettlementRequest,
    total_metered_fee: u64,
    quorum_weight_bps: u64,
) -> String {
    let bucket_root = set_root(
        "CALLGRAPH-METER-SETTLEMENT-BUCKET-IDS",
        &request.meter_bucket_ids,
    );
    let attestation_root = set_root(
        "CALLGRAPH-METER-SETTLEMENT-ATTESTATION-IDS",
        &request.attestation_ids,
    );
    domain_hash(
        "CALLGRAPH-METER-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.aggregator_id),
            HashPart::Str(&bucket_root),
            HashPart::Str(&attestation_root),
            HashPart::Str(&request.settlement_batch_root),
            HashPart::U64(total_metered_fee),
            HashPart::U64(quorum_weight_bps),
            HashPart::Str(&request.settlement_nonce),
        ],
        32,
    )
}

fn rebate_id(sequence: u64, request: &RebateRequest, rebate_amount: u64) -> String {
    domain_hash(
        "CALLGRAPH-METER-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.settlement_id),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::U64(request.rebate_basis_micro_units),
            HashPart::U64(rebate_amount),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

fn operator_safe_summary_root(
    sequence: u64,
    request: &OperatorSummaryRequest,
    session_count_bucket: u64,
    settlement_count_bucket: u64,
    metered_fee_bucket: u64,
    rebate_bucket: u64,
) -> String {
    let audience = enum_tag(request.audience);
    let risk = enum_tag(request.risk);
    domain_hash(
        "CALLGRAPH-METER-OPERATOR-SAFE-SUMMARY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.producer_id),
            HashPart::Str(&audience),
            HashPart::Str(&risk),
            HashPart::Str(&request.bucketed_metrics_root),
            HashPart::Str(&request.redacted_callgraph_root),
            HashPart::Str(&request.redacted_exception_root),
            HashPart::U64(session_count_bucket),
            HashPart::U64(settlement_count_bucket),
            HashPart::U64(metered_fee_bucket),
            HashPart::U64(rebate_bucket),
        ],
        32,
    )
}

fn summary_id(sequence: u64, request: &OperatorSummaryRequest, operator_safe_root: &str) -> String {
    let audience = enum_tag(request.audience);
    domain_hash(
        "CALLGRAPH-METER-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.producer_id),
            HashPart::Str(&audience),
            HashPart::Str(operator_safe_root),
            HashPart::Str(&request.summary_nonce),
        ],
        32,
    )
}

fn enum_tag<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}
