use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractPrivateEventBusRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractPrivateEventBusRuntimeResult<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_BUS_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-private-event-bus-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_BUS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_TOPIC_SUITE: &str = "ML-KEM-1024+Poseidon2-encrypted-event-topic-root-v1";
pub const COHORT_DISCLOSURE_SUITE: &str = "subscriber-cohort-selective-disclosure-policy-v1";
pub const PQ_PUBLISHER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-event-publisher-v1";
pub const REPLAY_GUARD_SUITE: &str = "confidential-contract-event-bus-replay-nullifier-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-confidential-contract-event-batch-root-v1";
pub const CALLBACK_ENVELOPE_SUITE: &str = "bounded-contract-callback-envelope-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "topic-field-redaction-budget-ledger-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "operator-safe-private-event-bus-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 2_236_800;
pub const DEVNET_EPOCH: u64 = 3_108;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_EVENT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REPLAY_GUARD_TTL_BLOCKS: u64 = 8_640;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_TOPIC_LEAKAGE_BPS: u64 = 35;
pub const DEFAULT_MAX_FIELD_LEAKAGE_BPS: u64 = 80;
pub const DEFAULT_MAX_DISCLOSURE_BPS: u64 = 120;
pub const DEFAULT_BASE_EVENT_FEE_MICRO_CREDITS: u128 = 900;
pub const DEFAULT_TARGET_BATCH_REBATE_BPS: u64 = 850;
pub const DEFAULT_CALLBACK_REBATE_BPS: u64 = 400;
pub const DEFAULT_MIN_ATTESTER_WEIGHT: u64 = 7;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_TOPICS: usize = 2_097_152;
pub const MAX_COHORTS: usize = 1_048_576;
pub const MAX_POLICIES: usize = 1_048_576;
pub const MAX_EVENTS: usize = 16_777_216;
pub const MAX_ATTESTATIONS: usize = 33_554_432;
pub const MAX_REPLAY_GUARDS: usize = 33_554_432;
pub const MAX_BATCHES: usize = 4_194_304;
pub const MAX_CALLBACKS: usize = 8_388_608;
pub const MAX_REDACTION_BUDGETS: usize = 4_194_304;
pub const MAX_PUBLIC_RECORDS: usize = 33_554_432;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventBusDomain {
    Token,
    Dex,
    Lending,
    Oracle,
    Bridge,
    Governance,
    Wallet,
    AccountSession,
    Risk,
    Custom,
}

impl EventBusDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::Wallet => "wallet",
            Self::AccountSession => "account_session",
            Self::Risk => "risk",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopicVisibility {
    Opaque,
    CohortSearchable,
    AuditorSearchable,
    CallbackOnly,
    AggregatePublic,
    PublicCommitment,
}

impl TopicVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::CohortSearchable => "cohort_searchable",
            Self::AuditorSearchable => "auditor_searchable",
            Self::CallbackOnly => "callback_only",
            Self::AggregatePublic => "aggregate_public",
            Self::PublicCommitment => "public_commitment",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortKind {
    ContractOwner,
    Counterparty,
    WalletViewers,
    SolverSet,
    OracleSet,
    AuditorSet,
    GovernanceCouncil,
    Watchtower,
    PublicMirror,
}

impl CohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractOwner => "contract_owner",
            Self::Counterparty => "counterparty",
            Self::WalletViewers => "wallet_viewers",
            Self::SolverSet => "solver_set",
            Self::OracleSet => "oracle_set",
            Self::AuditorSet => "auditor_set",
            Self::GovernanceCouncil => "governance_council",
            Self::Watchtower => "watchtower",
            Self::PublicMirror => "public_mirror",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureMode {
    Deny,
    CountOnly,
    ShapeOnly,
    TopicPrefix,
    RedactedPayload,
    CallbackEnvelope,
    FullForCohort,
    AuditorEscrow,
}

impl DisclosureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::CountOnly => "count_only",
            Self::ShapeOnly => "shape_only",
            Self::TopicPrefix => "topic_prefix",
            Self::RedactedPayload => "redacted_payload",
            Self::CallbackEnvelope => "callback_envelope",
            Self::FullForCohort => "full_for_cohort",
            Self::AuditorEscrow => "auditor_escrow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Draft,
    Active,
    Queued,
    Attested,
    Batched,
    Delivered,
    Settled,
    Quarantined,
    Revoked,
    Expired,
}

impl RecordStatus {
    pub fn accepts_events(self) -> bool {
        matches!(self, Self::Draft | Self::Active | Self::Queued)
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Attested | Self::Queued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackKind {
    ContractHook,
    WalletNotification,
    RiskHook,
    OracleCallback,
    BridgeWatcher,
    GovernanceAudit,
    SettlementReceipt,
    Custom,
}

impl CallbackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractHook => "contract_hook",
            Self::WalletNotification => "wallet_notification",
            Self::RiskHook => "risk_hook",
            Self::OracleCallback => "oracle_callback",
            Self::BridgeWatcher => "bridge_watcher",
            Self::GovernanceAudit => "governance_audit",
            Self::SettlementReceipt => "settlement_receipt",
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
    pub encrypted_topic_suite: String,
    pub cohort_disclosure_suite: String,
    pub pq_publisher_attestation_suite: String,
    pub replay_guard_suite: String,
    pub low_fee_batch_suite: String,
    pub callback_envelope_suite: String,
    pub redaction_budget_suite: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub event_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub replay_guard_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub callback_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_topic_leakage_bps: u64,
    pub max_field_leakage_bps: u64,
    pub max_disclosure_bps: u64,
    pub base_event_fee_micro_credits: u128,
    pub target_batch_rebate_bps: u64,
    pub callback_rebate_bps: u64,
    pub min_attester_weight: u64,
    pub quorum_bps: u64,
    pub max_topics: usize,
    pub max_cohorts: usize,
    pub max_policies: usize,
    pub max_events: usize,
    pub max_attestations: usize,
    pub max_replay_guards: usize,
    pub max_batches: usize,
    pub max_callbacks: usize,
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
            encrypted_topic_suite: ENCRYPTED_TOPIC_SUITE.to_string(),
            cohort_disclosure_suite: COHORT_DISCLOSURE_SUITE.to_string(),
            pq_publisher_attestation_suite: PQ_PUBLISHER_ATTESTATION_SUITE.to_string(),
            replay_guard_suite: REPLAY_GUARD_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            callback_envelope_suite: CALLBACK_ENVELOPE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            event_ttl_blocks: DEFAULT_EVENT_TTL_BLOCKS,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            replay_guard_ttl_blocks: DEFAULT_REPLAY_GUARD_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            callback_ttl_blocks: DEFAULT_CALLBACK_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_topic_leakage_bps: DEFAULT_MAX_TOPIC_LEAKAGE_BPS,
            max_field_leakage_bps: DEFAULT_MAX_FIELD_LEAKAGE_BPS,
            max_disclosure_bps: DEFAULT_MAX_DISCLOSURE_BPS,
            base_event_fee_micro_credits: DEFAULT_BASE_EVENT_FEE_MICRO_CREDITS,
            target_batch_rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            callback_rebate_bps: DEFAULT_CALLBACK_REBATE_BPS,
            min_attester_weight: DEFAULT_MIN_ATTESTER_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            max_topics: MAX_TOPICS,
            max_cohorts: MAX_COHORTS,
            max_policies: MAX_POLICIES,
            max_events: MAX_EVENTS,
            max_attestations: MAX_ATTESTATIONS,
            max_replay_guards: MAX_REPLAY_GUARDS,
            max_batches: MAX_BATCHES,
            max_callbacks: MAX_CALLBACKS,
            max_redaction_budgets: MAX_REDACTION_BUDGETS,
            max_public_records: MAX_PUBLIC_RECORDS,
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
    pub encrypted_topics: u64,
    pub subscriber_cohorts: u64,
    pub disclosure_policies: u64,
    pub encrypted_events: u64,
    pub publisher_attestations: u64,
    pub replay_guards: u64,
    pub low_fee_batches: u64,
    pub callback_envelopes: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub quarantined_records: u64,
    pub rejected_records: u64,
    pub total_fee_micro_credits: u128,
    pub total_rebate_micro_credits: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub encrypted_topic_root: String,
    pub subscriber_cohort_root: String,
    pub disclosure_policy_root: String,
    pub encrypted_event_root: String,
    pub publisher_attestation_root: String,
    pub replay_guard_root: String,
    pub low_fee_batch_root: String,
    pub callback_envelope_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            encrypted_topic_root: empty_root("ENCRYPTED-TOPIC"),
            subscriber_cohort_root: empty_root("SUBSCRIBER-COHORT"),
            disclosure_policy_root: empty_root("DISCLOSURE-POLICY"),
            encrypted_event_root: empty_root("ENCRYPTED-EVENT"),
            publisher_attestation_root: empty_root("PUBLISHER-ATTESTATION"),
            replay_guard_root: empty_root("REPLAY-GUARD"),
            low_fee_batch_root: empty_root("LOW-FEE-BATCH"),
            callback_envelope_root: empty_root("CALLBACK-ENVELOPE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for Roots {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedTopic {
    pub topic_id: String,
    pub contract_id: String,
    pub domain: EventBusDomain,
    pub visibility: TopicVisibility,
    pub encrypted_topic_commitment: String,
    pub topic_ciphertext_root: String,
    pub indexed_field_root: String,
    pub subscriber_cohort_ids: BTreeSet<String>,
    pub privacy_set_size: u64,
    pub topic_leakage_bps: u64,
    pub status: RecordStatus,
}

impl PublicRecord for EncryptedTopic {
    fn public_record(&self) -> Value {
        json!({
            "topic_id": self.topic_id,
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "visibility": self.visibility.as_str(),
            "encrypted_topic_commitment": self.encrypted_topic_commitment,
            "topic_ciphertext_root": self.topic_ciphertext_root,
            "indexed_field_root": self.indexed_field_root,
            "subscriber_cohort_ids": sorted_strings(&self.subscriber_cohort_ids),
            "privacy_set_size": self.privacy_set_size,
            "topic_leakage_bps": self.topic_leakage_bps,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriberCohort {
    pub cohort_id: String,
    pub kind: CohortKind,
    pub encrypted_membership_root: String,
    pub view_key_commitment_root: String,
    pub delivery_endpoint_commitment: String,
    pub min_privacy_set_size: u64,
    pub disclosure_policy_ids: BTreeSet<String>,
    pub active_subscribers: u64,
    pub status: RecordStatus,
}

impl PublicRecord for SubscriberCohort {
    fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "kind": self.kind.as_str(),
            "encrypted_membership_root": self.encrypted_membership_root,
            "view_key_commitment_root": self.view_key_commitment_root,
            "delivery_endpoint_commitment": self.delivery_endpoint_commitment,
            "min_privacy_set_size": self.min_privacy_set_size,
            "disclosure_policy_ids": sorted_strings(&self.disclosure_policy_ids),
            "active_subscribers": self.active_subscribers,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosurePolicy {
    pub policy_id: String,
    pub topic_id: String,
    pub cohort_id: String,
    pub mode: DisclosureMode,
    pub allowed_field_root: String,
    pub denied_field_root: String,
    pub auditor_set_root: String,
    pub max_topic_leakage_bps: u64,
    pub max_field_leakage_bps: u64,
    pub expires_at_height: u64,
    pub status: RecordStatus,
}

impl PublicRecord for DisclosurePolicy {
    fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "topic_id": self.topic_id,
            "cohort_id": self.cohort_id,
            "mode": self.mode.as_str(),
            "allowed_field_root": self.allowed_field_root,
            "denied_field_root": self.denied_field_root,
            "auditor_set_root": self.auditor_set_root,
            "max_topic_leakage_bps": self.max_topic_leakage_bps,
            "max_field_leakage_bps": self.max_field_leakage_bps,
            "expires_at_height": self.expires_at_height,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedEvent {
    pub event_id: String,
    pub topic_id: String,
    pub publisher_contract_id: String,
    pub encrypted_payload_root: String,
    pub encrypted_topic_tag: String,
    pub callback_envelope_id: Option<String>,
    pub replay_guard_id: String,
    pub disclosure_policy_ids: BTreeSet<String>,
    pub fee_micro_credits: u128,
    pub emitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: RecordStatus,
}

impl PublicRecord for EncryptedEvent {
    fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "topic_id": self.topic_id,
            "publisher_contract_id": self.publisher_contract_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "encrypted_topic_tag": self.encrypted_topic_tag,
            "callback_envelope_id": self.callback_envelope_id,
            "replay_guard_id": self.replay_guard_id,
            "disclosure_policy_ids": sorted_strings(&self.disclosure_policy_ids),
            "fee_micro_credits": self.fee_micro_credits.to_string(),
            "emitted_at_height": self.emitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPublisherAttestation {
    pub attestation_id: String,
    pub event_id: String,
    pub publisher_contract_id: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub attester_weight: u64,
    pub pq_security_bits: u16,
    pub expires_at_height: u64,
    pub status: RecordStatus,
}

impl PublicRecord for PqPublisherAttestation {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayGuard {
    pub replay_guard_id: String,
    pub nullifier_commitment: String,
    pub topic_id: String,
    pub publisher_contract_id: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl PublicRecord for ReplayGuard {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeEventBatch {
    pub batch_id: String,
    pub event_ids: BTreeSet<String>,
    pub batcher_id: String,
    pub encrypted_batch_root: String,
    pub callback_envelope_root: String,
    pub public_record_root: String,
    pub base_fee_micro_credits: u128,
    pub rebate_micro_credits: u128,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub status: RecordStatus,
}

impl PublicRecord for LowFeeEventBatch {
    fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "event_ids": sorted_strings(&self.event_ids),
            "batcher_id": self.batcher_id,
            "encrypted_batch_root": self.encrypted_batch_root,
            "callback_envelope_root": self.callback_envelope_root,
            "public_record_root": self.public_record_root,
            "base_fee_micro_credits": self.base_fee_micro_credits.to_string(),
            "rebate_micro_credits": self.rebate_micro_credits.to_string(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallbackEnvelope {
    pub envelope_id: String,
    pub event_id: String,
    pub target_contract_id: String,
    pub callback_kind: CallbackKind,
    pub selector_commitment: String,
    pub argument_ciphertext_root: String,
    pub gas_limit: u64,
    pub fee_rebate_bps: u64,
    pub expires_at_height: u64,
    pub status: RecordStatus,
}

impl PublicRecord for ContractCallbackEnvelope {
    fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "event_id": self.event_id,
            "target_contract_id": self.target_contract_id,
            "callback_kind": self.callback_kind.as_str(),
            "selector_commitment": self.selector_commitment,
            "argument_ciphertext_root": self.argument_ciphertext_root,
            "gas_limit": self.gas_limit,
            "fee_rebate_bps": self.fee_rebate_bps,
            "expires_at_height": self.expires_at_height,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub policy_id: String,
    pub cohort_id: String,
    pub total_budget_bps: u64,
    pub spent_budget_bps: u64,
    pub field_redaction_root: String,
    pub epoch: u64,
    pub status: RecordStatus,
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub public_commitment: String,
    pub state_root: String,
    pub emitted_at_height: u64,
}

impl PublicRecord for DeterministicPublicRecord {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishEventRequest {
    pub topic_id: String,
    pub publisher_contract_id: String,
    pub encrypted_payload_root: String,
    pub encrypted_topic_tag: String,
    pub replay_nullifier_commitment: String,
    pub disclosure_policy_ids: BTreeSet<String>,
    pub callback_envelope_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub encrypted_topics: BTreeMap<String, EncryptedTopic>,
    pub subscriber_cohorts: BTreeMap<String, SubscriberCohort>,
    pub disclosure_policies: BTreeMap<String, DisclosurePolicy>,
    pub encrypted_events: BTreeMap<String, EncryptedEvent>,
    pub publisher_attestations: BTreeMap<String, PqPublisherAttestation>,
    pub replay_guards: BTreeMap<String, ReplayGuard>,
    pub low_fee_batches: BTreeMap<String, LowFeeEventBatch>,
    pub callback_envelopes: BTreeMap<String, ContractCallbackEnvelope>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub deterministic_public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub quarantined: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            encrypted_topics: BTreeMap::new(),
            subscriber_cohorts: BTreeMap::new(),
            disclosure_policies: BTreeMap::new(),
            encrypted_events: BTreeMap::new(),
            publisher_attestations: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            callback_envelopes: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
            quarantined: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH);
        state.seed_devnet();
        state
    }

    pub fn register_topic(&mut self, mut topic: EncryptedTopic) -> Result<String> {
        ensure!(
            self.encrypted_topics.len() < self.config.max_topics,
            "encrypted topic capacity exceeded"
        );
        if topic.privacy_set_size < self.config.min_privacy_set_size
            || topic.topic_leakage_bps > self.config.max_topic_leakage_bps
        {
            topic.status = RecordStatus::Quarantined;
            self.quarantined.insert(topic.topic_id.clone());
            self.counters.quarantined_records = self.counters.quarantined_records.saturating_add(1);
        }
        let id = topic.topic_id.clone();
        let is_new = !self.encrypted_topics.contains_key(&id);
        self.encrypted_topics.insert(id.clone(), topic);
        if is_new {
            self.counters.encrypted_topics = self.counters.encrypted_topics.saturating_add(1);
        }
        self.refresh_roots();
        Ok(id)
    }

    pub fn register_cohort(&mut self, mut cohort: SubscriberCohort) -> Result<String> {
        ensure!(
            self.subscriber_cohorts.len() < self.config.max_cohorts,
            "subscriber cohort capacity exceeded"
        );
        if cohort.min_privacy_set_size < self.config.min_privacy_set_size {
            cohort.status = RecordStatus::Quarantined;
            self.quarantined.insert(cohort.cohort_id.clone());
            self.counters.quarantined_records = self.counters.quarantined_records.saturating_add(1);
        }
        let id = cohort.cohort_id.clone();
        let is_new = !self.subscriber_cohorts.contains_key(&id);
        self.subscriber_cohorts.insert(id.clone(), cohort);
        if is_new {
            self.counters.subscriber_cohorts = self.counters.subscriber_cohorts.saturating_add(1);
        }
        self.refresh_roots();
        Ok(id)
    }

    pub fn register_policy(&mut self, mut policy: DisclosurePolicy) -> Result<String> {
        ensure!(
            self.disclosure_policies.len() < self.config.max_policies,
            "disclosure policy capacity exceeded"
        );
        ensure!(
            self.encrypted_topics.contains_key(&policy.topic_id),
            "unknown topic {}",
            policy.topic_id
        );
        ensure!(
            self.subscriber_cohorts.contains_key(&policy.cohort_id),
            "unknown cohort {}",
            policy.cohort_id
        );
        if policy.max_topic_leakage_bps > self.config.max_topic_leakage_bps
            || policy.max_field_leakage_bps > self.config.max_field_leakage_bps
        {
            policy.status = RecordStatus::Quarantined;
            self.quarantined.insert(policy.policy_id.clone());
            self.counters.quarantined_records = self.counters.quarantined_records.saturating_add(1);
        }
        let id = policy.policy_id.clone();
        let topic_id = policy.topic_id.clone();
        let cohort_id = policy.cohort_id.clone();
        let is_new = !self.disclosure_policies.contains_key(&id);
        self.disclosure_policies.insert(id.clone(), policy);
        if let Some(topic) = self.encrypted_topics.get_mut(&topic_id) {
            topic.subscriber_cohort_ids.insert(cohort_id.clone());
        }
        if let Some(cohort) = self.subscriber_cohorts.get_mut(&cohort_id) {
            cohort.disclosure_policy_ids.insert(id.clone());
        }
        if is_new {
            self.counters.disclosure_policies = self.counters.disclosure_policies.saturating_add(1);
        }
        self.refresh_roots();
        Ok(id)
    }

    pub fn publish_event(&mut self, request: PublishEventRequest) -> Result<String> {
        ensure!(
            self.encrypted_events.len() < self.config.max_events,
            "encrypted event capacity exceeded"
        );
        let topic = self
            .encrypted_topics
            .get(&request.topic_id)
            .ok_or_else(|| format!("unknown topic {}", request.topic_id))?;
        ensure!(
            topic.status.accepts_events(),
            "topic {} does not accept events",
            request.topic_id
        );
        for policy_id in &request.disclosure_policy_ids {
            ensure!(
                self.disclosure_policies.contains_key(policy_id),
                "unknown disclosure policy {}",
                policy_id
            );
        }
        ensure!(
            !self
                .replay_guards
                .values()
                .any(|guard| guard.nullifier_commitment == request.replay_nullifier_commitment),
            "replay guard already consumed"
        );

        let next = self.counters.encrypted_events.saturating_add(1);
        let event_id = deterministic_id("EVENT", next, &json!(&request));
        let replay_guard_id = deterministic_id(
            "REPLAY-GUARD",
            next,
            &json!({
                "topic_id": request.topic_id,
                "publisher_contract_id": request.publisher_contract_id,
                "nullifier_commitment": request.replay_nullifier_commitment,
            }),
        );
        let fee_micro_credits = self.config.base_event_fee_micro_credits;
        let event = EncryptedEvent {
            event_id: event_id.clone(),
            topic_id: request.topic_id.clone(),
            publisher_contract_id: request.publisher_contract_id.clone(),
            encrypted_payload_root: request.encrypted_payload_root,
            encrypted_topic_tag: request.encrypted_topic_tag,
            callback_envelope_id: request.callback_envelope_id,
            replay_guard_id: replay_guard_id.clone(),
            disclosure_policy_ids: request.disclosure_policy_ids,
            fee_micro_credits,
            emitted_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.event_ttl_blocks),
            status: RecordStatus::Queued,
        };
        let guard = ReplayGuard {
            replay_guard_id: replay_guard_id.clone(),
            nullifier_commitment: request.replay_nullifier_commitment,
            topic_id: event.topic_id.clone(),
            publisher_contract_id: event.publisher_contract_id.clone(),
            first_seen_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.replay_guard_ttl_blocks),
            consumed: true,
        };
        self.encrypted_events.insert(event_id.clone(), event);
        self.replay_guards.insert(replay_guard_id, guard);
        self.counters.encrypted_events = self.counters.encrypted_events.saturating_add(1);
        self.counters.replay_guards = self.counters.replay_guards.saturating_add(1);
        self.counters.total_fee_micro_credits = self
            .counters
            .total_fee_micro_credits
            .saturating_add(fee_micro_credits);
        self.refresh_roots();
        Ok(event_id)
    }

    pub fn attest_publisher(&mut self, mut attestation: PqPublisherAttestation) -> Result<String> {
        ensure!(
            self.publisher_attestations.len() < self.config.max_attestations,
            "publisher attestation capacity exceeded"
        );
        ensure!(
            self.encrypted_events.contains_key(&attestation.event_id),
            "unknown event {}",
            attestation.event_id
        );
        if attestation.attester_weight < self.config.min_attester_weight
            || attestation.pq_security_bits < self.config.min_pq_security_bits
        {
            attestation.status = RecordStatus::Quarantined;
            self.quarantined.insert(attestation.attestation_id.clone());
            self.counters.quarantined_records = self.counters.quarantined_records.saturating_add(1);
        }
        let id = attestation.attestation_id.clone();
        let event_id = attestation.event_id.clone();
        let is_new = !self.publisher_attestations.contains_key(&id);
        self.publisher_attestations.insert(id.clone(), attestation);
        if let Some(event) = self.encrypted_events.get_mut(&event_id) {
            event.status = RecordStatus::Attested;
        }
        if is_new {
            self.counters.publisher_attestations =
                self.counters.publisher_attestations.saturating_add(1);
        }
        self.refresh_roots();
        Ok(id)
    }

    pub fn register_callback_envelope(
        &mut self,
        envelope: ContractCallbackEnvelope,
    ) -> Result<String> {
        ensure!(
            self.callback_envelopes.len() < self.config.max_callbacks,
            "callback envelope capacity exceeded"
        );
        let id = envelope.envelope_id.clone();
        let is_new = !self.callback_envelopes.contains_key(&id);
        self.callback_envelopes.insert(id.clone(), envelope);
        if is_new {
            self.counters.callback_envelopes = self.counters.callback_envelopes.saturating_add(1);
        }
        self.refresh_roots();
        Ok(id)
    }

    pub fn register_redaction_budget(&mut self, mut budget: RedactionBudget) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exceeded"
        );
        ensure!(
            self.disclosure_policies.contains_key(&budget.policy_id),
            "unknown policy {}",
            budget.policy_id
        );
        if budget.total_budget_bps > self.config.max_disclosure_bps
            || budget.spent_budget_bps > budget.total_budget_bps
        {
            budget.status = RecordStatus::Quarantined;
            self.quarantined.insert(budget.budget_id.clone());
            self.counters.quarantined_records = self.counters.quarantined_records.saturating_add(1);
        }
        let id = budget.budget_id.clone();
        let is_new = !self.redaction_budgets.contains_key(&id);
        self.redaction_budgets.insert(id.clone(), budget);
        if is_new {
            self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        }
        self.refresh_roots();
        Ok(id)
    }

    pub fn seal_low_fee_batch(
        &mut self,
        batcher_id: String,
        event_ids: BTreeSet<String>,
    ) -> Result<String> {
        ensure!(
            self.low_fee_batches.len() < self.config.max_batches,
            "low-fee batch capacity exceeded"
        );
        ensure!(
            !event_ids.is_empty(),
            "low-fee batch requires at least one event"
        );
        for event_id in &event_ids {
            let event = self
                .encrypted_events
                .get(event_id)
                .ok_or_else(|| format!("unknown event {}", event_id))?;
            ensure!(
                event.status.batchable(),
                "event {} is not batchable",
                event_id
            );
        }
        let base_fee = event_ids.iter().fold(0u128, |sum, event_id| {
            sum.saturating_add(
                self.encrypted_events
                    .get(event_id)
                    .map(|event| event.fee_micro_credits)
                    .unwrap_or_default(),
            )
        });
        let rebate = base_fee.saturating_mul(u128::from(self.config.target_batch_rebate_bps))
            / u128::from(MAX_BPS);
        let next = self.counters.low_fee_batches.saturating_add(1);
        let public_records: Vec<Value> = event_ids
            .iter()
            .filter_map(|event_id| self.encrypted_events.get(event_id))
            .map(PublicRecord::public_record)
            .collect();
        let batch_id = deterministic_id(
            "LOW-FEE-BATCH",
            next,
            &json!({
                "batcher_id": batcher_id,
                "event_ids": sorted_strings(&event_ids),
            }),
        );
        let batch = LowFeeEventBatch {
            batch_id: batch_id.clone(),
            event_ids: event_ids.clone(),
            batcher_id,
            encrypted_batch_root: public_record_root("BATCH-EVENTS", &public_records),
            callback_envelope_root: self.roots.callback_envelope_root.clone(),
            public_record_root: public_record_root("BATCH-PUBLIC-RECORDS", &public_records),
            base_fee_micro_credits: base_fee,
            rebate_micro_credits: rebate,
            opened_at_height: self.height,
            sealed_at_height: self.height.saturating_add(self.config.batch_window_blocks),
            status: RecordStatus::Batched,
        };
        for event_id in &event_ids {
            if let Some(event) = self.encrypted_events.get_mut(event_id) {
                event.status = RecordStatus::Batched;
            }
        }
        self.low_fee_batches.insert(batch_id.clone(), batch);
        self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        self.counters.total_rebate_micro_credits = self
            .counters
            .total_rebate_micro_credits
            .saturating_add(rebate);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: impl Into<String>,
        subject_id: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.deterministic_public_records.len() < self.config.max_public_records,
            "public record capacity exceeded"
        );
        let record_kind = record_kind.into();
        let subject_id = subject_id.into();
        let next = self.counters.public_records.saturating_add(1);
        let public_commitment = deterministic_record_root(
            "PUBLIC-RECORD-COMMITMENT",
            &json!({
                "record_kind": record_kind,
                "subject_id": subject_id,
                "height": self.height,
                "roots": self.roots,
            }),
        );
        let record_id = deterministic_id(
            "PUBLIC-RECORD",
            next,
            &json!({
                "record_kind": record_kind,
                "subject_id": subject_id,
                "public_commitment": public_commitment,
            }),
        );
        let record = DeterministicPublicRecord {
            record_id: record_id.clone(),
            record_kind,
            subject_id,
            public_commitment,
            state_root: self.roots.state_root.clone(),
            emitted_at_height: self.height,
        };
        self.deterministic_public_records
            .insert(record_id.clone(), record);
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        self.refresh_roots();
        Ok(record_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": {
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "hash_suite": self.config.hash_suite,
                "encrypted_topic_suite": self.config.encrypted_topic_suite,
                "cohort_disclosure_suite": self.config.cohort_disclosure_suite,
                "pq_publisher_attestation_suite": self.config.pq_publisher_attestation_suite,
                "replay_guard_suite": self.config.replay_guard_suite,
                "low_fee_batch_suite": self.config.low_fee_batch_suite,
                "callback_envelope_suite": self.config.callback_envelope_suite,
                "redaction_budget_suite": self.config.redaction_budget_suite,
                "public_record_scheme": self.config.public_record_scheme,
                "monero_network": self.config.monero_network,
                "l2_network": self.config.l2_network,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "max_topic_leakage_bps": self.config.max_topic_leakage_bps,
                "max_field_leakage_bps": self.config.max_field_leakage_bps,
                "max_disclosure_bps": self.config.max_disclosure_bps,
                "base_event_fee_micro_credits": self.config.base_event_fee_micro_credits.to_string(),
                "target_batch_rebate_bps": self.config.target_batch_rebate_bps,
                "callback_rebate_bps": self.config.callback_rebate_bps,
                "quorum_bps": self.config.quorum_bps,
            },
            "height": self.height,
            "epoch": self.epoch,
            "counters": {
                "encrypted_topics": self.counters.encrypted_topics,
                "subscriber_cohorts": self.counters.subscriber_cohorts,
                "disclosure_policies": self.counters.disclosure_policies,
                "encrypted_events": self.counters.encrypted_events,
                "publisher_attestations": self.counters.publisher_attestations,
                "replay_guards": self.counters.replay_guards,
                "low_fee_batches": self.counters.low_fee_batches,
                "callback_envelopes": self.counters.callback_envelopes,
                "redaction_budgets": self.counters.redaction_budgets,
                "public_records": self.counters.public_records,
                "quarantined_records": self.counters.quarantined_records,
                "rejected_records": self.counters.rejected_records,
                "total_fee_micro_credits": self.counters.total_fee_micro_credits.to_string(),
                "total_rebate_micro_credits": self.counters.total_rebate_micro_credits.to_string(),
            },
            "roots": self.roots,
            "encrypted_topics": values_record(&self.encrypted_topics),
            "subscriber_cohorts": values_record(&self.subscriber_cohorts),
            "disclosure_policies": values_record(&self.disclosure_policies),
            "encrypted_events": values_record(&self.encrypted_events),
            "publisher_attestations": values_record(&self.publisher_attestations),
            "replay_guards": values_record(&self.replay_guards),
            "low_fee_batches": values_record(&self.low_fee_batches),
            "callback_envelopes": values_record(&self.callback_envelopes),
            "redaction_budgets": values_record(&self.redaction_budgets),
            "deterministic_public_records": values_record(&self.deterministic_public_records),
            "quarantined": sorted_strings(&self.quarantined),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let mut record = self.public_record();
        if let Some(roots) = record.get_mut("roots") {
            if let Some(object) = roots.as_object_mut() {
                object.insert("state_root".to_string(), json!(empty_root("STATE")));
            }
        }
        record
    }

    fn refresh_roots(&mut self) {
        self.roots.encrypted_topic_root =
            public_record_root("ENCRYPTED-TOPIC", &values_record(&self.encrypted_topics));
        self.roots.subscriber_cohort_root = public_record_root(
            "SUBSCRIBER-COHORT",
            &values_record(&self.subscriber_cohorts),
        );
        self.roots.disclosure_policy_root = public_record_root(
            "DISCLOSURE-POLICY",
            &values_record(&self.disclosure_policies),
        );
        self.roots.encrypted_event_root =
            public_record_root("ENCRYPTED-EVENT", &values_record(&self.encrypted_events));
        self.roots.publisher_attestation_root = public_record_root(
            "PUBLISHER-ATTESTATION",
            &values_record(&self.publisher_attestations),
        );
        self.roots.replay_guard_root =
            public_record_root("REPLAY-GUARD", &values_record(&self.replay_guards));
        self.roots.low_fee_batch_root =
            public_record_root("LOW-FEE-BATCH", &values_record(&self.low_fee_batches));
        self.roots.callback_envelope_root = public_record_root(
            "CALLBACK-ENVELOPE",
            &values_record(&self.callback_envelopes),
        );
        self.roots.redaction_budget_root =
            public_record_root("REDACTION-BUDGET", &values_record(&self.redaction_budgets));
        self.roots.public_record_root = public_record_root(
            "PUBLIC-RECORD",
            &values_record(&self.deterministic_public_records),
        );
        self.roots.state_root = self.state_root();
    }

    fn seed_devnet(&mut self) {
        let cohort_id = self
            .register_cohort(SubscriberCohort {
                cohort_id: "cohort-devnet-wallet-watchers".to_string(),
                kind: CohortKind::WalletViewers,
                encrypted_membership_root: deterministic_record_root(
                    "DEVNET-COHORT-MEMBERS",
                    &json!(["wallet-alpha", "wallet-beta", "watchtower-gamma"]),
                ),
                view_key_commitment_root: deterministic_record_root(
                    "DEVNET-VIEW-KEYS",
                    &json!("view-key-cohort-devnet"),
                ),
                delivery_endpoint_commitment: deterministic_record_root(
                    "DEVNET-ENDPOINT",
                    &json!("encrypted-push-relay"),
                ),
                min_privacy_set_size: self.config.target_privacy_set_size,
                disclosure_policy_ids: BTreeSet::new(),
                active_subscribers: 131_072,
                status: RecordStatus::Active,
            })
            .unwrap_or_default();
        let topic_id = self
            .register_topic(EncryptedTopic {
                topic_id: "topic-devnet-private-token-transfer".to_string(),
                contract_id: "contract-confidential-token-devnet".to_string(),
                domain: EventBusDomain::Token,
                visibility: TopicVisibility::CohortSearchable,
                encrypted_topic_commitment: deterministic_record_root(
                    "DEVNET-TOPIC",
                    &json!("Transfer(address,address,uint256)"),
                ),
                topic_ciphertext_root: deterministic_record_root(
                    "DEVNET-TOPIC-CIPHERTEXT",
                    &json!("sealed-transfer-topic"),
                ),
                indexed_field_root: deterministic_record_root(
                    "DEVNET-INDEXED-FIELDS",
                    &json!(["sender_tag", "receiver_tag", "amount_bucket"]),
                ),
                subscriber_cohort_ids: BTreeSet::new(),
                privacy_set_size: self.config.target_privacy_set_size,
                topic_leakage_bps: 22,
                status: RecordStatus::Active,
            })
            .unwrap_or_default();
        let policy_id = self
            .register_policy(DisclosurePolicy {
                policy_id: "policy-devnet-wallet-redacted-transfer".to_string(),
                topic_id: topic_id.clone(),
                cohort_id: cohort_id.clone(),
                mode: DisclosureMode::RedactedPayload,
                allowed_field_root: deterministic_record_root(
                    "DEVNET-ALLOWED-FIELDS",
                    &json!(["view_tag", "direction", "amount_bucket"]),
                ),
                denied_field_root: deterministic_record_root(
                    "DEVNET-DENIED-FIELDS",
                    &json!(["raw_amount", "counterparty_address", "memo"]),
                ),
                auditor_set_root: deterministic_record_root(
                    "DEVNET-AUDITORS",
                    &json!(["auditor-alpha", "auditor-beta", "auditor-gamma"]),
                ),
                max_topic_leakage_bps: 30,
                max_field_leakage_bps: 65,
                expires_at_height: self
                    .height
                    .saturating_add(self.config.disclosure_ttl_blocks),
                status: RecordStatus::Active,
            })
            .unwrap_or_default();
        let callback_id = self
            .register_callback_envelope(ContractCallbackEnvelope {
                envelope_id: "callback-devnet-transfer-hook".to_string(),
                event_id: "pending-devnet-transfer-event".to_string(),
                target_contract_id: "contract-confidential-wallet-index-devnet".to_string(),
                callback_kind: CallbackKind::WalletNotification,
                selector_commitment: deterministic_record_root(
                    "DEVNET-CALLBACK-SELECTOR",
                    &json!("on_private_event(bytes32,bytes)"),
                ),
                argument_ciphertext_root: deterministic_record_root(
                    "DEVNET-CALLBACK-ARGS",
                    &json!("sealed-wallet-notification-args"),
                ),
                gas_limit: 950_000,
                fee_rebate_bps: self.config.callback_rebate_bps,
                expires_at_height: self.height.saturating_add(self.config.callback_ttl_blocks),
                status: RecordStatus::Queued,
            })
            .unwrap_or_default();
        let mut policies = BTreeSet::new();
        policies.insert(policy_id.clone());
        let event_id = self
            .publish_event(PublishEventRequest {
                topic_id,
                publisher_contract_id: "contract-confidential-token-devnet".to_string(),
                encrypted_payload_root: deterministic_record_root(
                    "DEVNET-EVENT-PAYLOAD",
                    &json!("sealed-transfer-payload-0001"),
                ),
                encrypted_topic_tag: deterministic_record_root(
                    "DEVNET-EVENT-TAG",
                    &json!("tag-transfer-epoch-3108"),
                ),
                replay_nullifier_commitment: deterministic_record_root(
                    "DEVNET-REPLAY",
                    &json!("transfer-nullifier-0001"),
                ),
                disclosure_policy_ids: policies,
                callback_envelope_id: Some(callback_id),
            })
            .unwrap_or_default();
        let _ignored = self.attest_publisher(PqPublisherAttestation {
            attestation_id: "attestation-devnet-publisher-transfer-0001".to_string(),
            event_id: event_id.clone(),
            publisher_contract_id: "contract-confidential-token-devnet".to_string(),
            pq_public_key_commitment: deterministic_record_root(
                "DEVNET-PQ-PUBKEY",
                &json!("ml-dsa-publisher-key-devnet"),
            ),
            signature_commitment: deterministic_record_root(
                "DEVNET-PQ-SIGNATURE",
                &json!("signature-transfer-0001"),
            ),
            transcript_root: deterministic_record_root(
                "DEVNET-PUBLISHER-TRANSCRIPT",
                &json!("publisher-transcript-0001"),
            ),
            attester_weight: self.config.min_attester_weight,
            pq_security_bits: self.config.min_pq_security_bits,
            expires_at_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
            status: RecordStatus::Attested,
        });
        let _ignored = self.register_redaction_budget(RedactionBudget {
            budget_id: "budget-devnet-wallet-transfer-redaction".to_string(),
            policy_id,
            cohort_id,
            total_budget_bps: 90,
            spent_budget_bps: 18,
            field_redaction_root: deterministic_record_root(
                "DEVNET-REDACTION-BUDGET",
                &json!(["amount_bucket", "time_bucket", "direction"]),
            ),
            epoch: self.epoch,
            status: RecordStatus::Active,
        });
        let mut batch_events = BTreeSet::new();
        batch_events.insert(event_id.clone());
        let _ignored =
            self.seal_low_fee_batch("batcher-devnet-low-fee-alpha".to_string(), batch_events);
        let _ignored = self.publish_public_record("encrypted_event", event_id);
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

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-BUS:{domain}-ROOT"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-BUS:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-BUS:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_id(domain: &str, sequence: u64, record: &Value) -> String {
    deterministic_record_root(domain, &json!({"sequence": sequence, "record": record}))
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T>(records: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    records.values().map(PublicRecord::public_record).collect()
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}
