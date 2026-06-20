use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractFheEventSettlementBusRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FHE_EVENT_SETTLEMENT_BUS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-fhe-event-settlement-bus-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FHE_EVENT_SETTLEMENT_BUS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_BUS_ID: &str = "private-l2-pq-confidential-contract-fhe-event-bus-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "dnr-low-fee-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EVENT_CIPHERTEXT_SCHEME: &str = "hpke-ml-kem-1024-contract-event-aead-v1";
pub const FHE_ENVELOPE_SCHEME: &str = "tfhe-radix-64-settlement-envelope-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-oracle-attestation-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "selective-disclosure-redaction-budget-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "private-contract-event-low-fee-batch-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-confidential-event-bus-summary-root-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_EVENT_BYTES: usize = 16_384;
pub const DEFAULT_MAX_BATCH_EVENTS: usize = 512;
pub const DEFAULT_MAX_LANE_DEPTH: usize = 8_192;
pub const DEFAULT_LOW_FEE_MICRO_DNR: u64 = 25;
pub const DEFAULT_STANDARD_FEE_MICRO_DNR: u64 = 90;
pub const DEFAULT_FAST_FEE_MICRO_DNR: u64 = 250;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_OPERATOR_EPOCH_BLOCKS: u64 = 720;

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BusLaneKind {
    LowFee,
    Standard,
    Fast,
    ContractSystem,
    Oracle,
    Emergency,
}

impl BusLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::ContractSystem => "contract_system",
            Self::Oracle => "oracle",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_micro_dnr(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_micro_dnr,
            Self::Standard | Self::ContractSystem | Self::Oracle => config.standard_fee_micro_dnr,
            Self::Fast | Self::Emergency => config.fast_fee_micro_dnr,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::Oracle => 880,
            Self::ContractSystem => 820,
            Self::Standard => 720,
            Self::LowFee => 640,
        }
    }
}

status_enum!(EncryptedEventStatus { Received => "received", Filtered => "filtered", Enveloped => "enveloped", Batched => "batched", Delivered => "delivered", Rejected => "rejected", Redacted => "redacted" });
status_enum!(EnvelopeStatus { Open => "open", Proved => "proved", Attested => "attested", Settled => "settled", Disputed => "disputed", Expired => "expired" });
status_enum!(LaneStatus { Open => "open", Congested => "congested", Paused => "paused", Draining => "draining", Closed => "closed" });
status_enum!(FilterAction { Include => "include", Exclude => "exclude", Redact => "redact", AggregateOnly => "aggregate_only" });
status_enum!(AttestationVerdict { Pending => "pending", Valid => "valid", Invalid => "invalid", NeedsQuorum => "needs_quorum", Challenged => "challenged" });
status_enum!(RedactionBudgetStatus { Active => "active", Exhausted => "exhausted", Suspended => "suspended", Expired => "expired", Revoked => "revoked" });
status_enum!(BatchStatus { Assembling => "assembling", Sealed => "sealed", Proved => "proved", Submitted => "submitted", Finalized => "finalized", Disputed => "disputed", Expired => "expired" });
status_enum!(DeliveryStatus { Queued => "queued", Sent => "sent", Acked => "acked", Deferred => "deferred", Failed => "failed" });

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub network: String,
    pub bus_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub event_ciphertext_scheme: String,
    pub fhe_envelope_scheme: String,
    pub pq_attestation_scheme: String,
    pub redaction_budget_scheme: String,
    pub low_fee_batch_scheme: String,
    pub operator_summary_scheme: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_event_bytes: usize,
    pub max_batch_events: usize,
    pub max_lane_depth: usize,
    pub low_fee_micro_dnr: u64,
    pub standard_fee_micro_dnr: u64,
    pub fast_fee_micro_dnr: u64,
    pub redaction_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub operator_epoch_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            network: DEVNET_NETWORK.to_string(),
            bus_id: DEVNET_BUS_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            event_ciphertext_scheme: EVENT_CIPHERTEXT_SCHEME.to_string(),
            fhe_envelope_scheme: FHE_ENVELOPE_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            low_fee_batch_scheme: LOW_FEE_BATCH_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_batch_events: DEFAULT_MAX_BATCH_EVENTS,
            max_lane_depth: DEFAULT_MAX_LANE_DEPTH,
            low_fee_micro_dnr: DEFAULT_LOW_FEE_MICRO_DNR,
            standard_fee_micro_dnr: DEFAULT_STANDARD_FEE_MICRO_DNR,
            fast_fee_micro_dnr: DEFAULT_FAST_FEE_MICRO_DNR,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            operator_epoch_blocks: DEFAULT_OPERATOR_EPOCH_BLOCKS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub encrypted_events: u64,
    pub settlement_envelopes: u64,
    pub bus_lanes: u64,
    pub subscriber_filters: u64,
    pub pq_oracle_attestations: u64,
    pub redaction_budgets: u64,
    pub low_fee_batches: u64,
    pub batch_deliveries: u64,
    pub operator_summaries: u64,
    pub delivered_events: u64,
    pub rejected_events: u64,
    pub redacted_events: u64,
    pub total_fee_micro_dnr: u64,
}

impl Counters {
    pub fn next_id(&mut self, label: &str) -> String {
        self.next_sequence = self.next_sequence.saturating_add(1);
        format!("{label}-{:012}", self.next_sequence)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub encrypted_event_root: String,
    pub settlement_envelope_root: String,
    pub bus_lane_root: String,
    pub subscriber_filter_root: String,
    pub pq_oracle_attestation_root: String,
    pub redaction_budget_root: String,
    pub low_fee_batch_root: String,
    pub batch_delivery_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub fee_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash("private-contract-fhe-event-bus:root:empty", &[], 32);
        Self {
            encrypted_event_root: empty.clone(),
            settlement_envelope_root: empty.clone(),
            bus_lane_root: empty.clone(),
            subscriber_filter_root: empty.clone(),
            pq_oracle_attestation_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            low_fee_batch_root: empty.clone(),
            batch_delivery_root: empty.clone(),
            operator_summary_root: empty.clone(),
            nullifier_root: empty.clone(),
            fee_root: empty.clone(),
            state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorization {
    pub scheme: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub security_bits: u16,
}

impl PqAuthorization {
    pub fn devnet(label: &str) -> Self {
        Self {
            scheme: PQ_ATTESTATION_SCHEME.to_string(),
            public_key_commitment: commitment("pq-pk", label),
            transcript_hash: commitment("pq-transcript", label),
            signature_commitment: commitment("pq-signature", label),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": self.scheme,
            "public_key_commitment": self.public_key_commitment,
            "transcript_hash": self.transcript_hash,
            "signature_commitment": self.signature_commitment,
            "security_bits": self.security_bits
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialContractRef {
    pub contract_id: String,
    pub deployment_root: String,
    pub code_hash: String,
    pub policy_root: String,
    pub privacy_domain: String,
}

impl ConfidentialContractRef {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "deployment_root": self.deployment_root,
            "code_hash": self.code_hash,
            "policy_root": self.policy_root,
            "privacy_domain": self.privacy_domain
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedContractEvent {
    pub event_id: String,
    pub sequence: u64,
    pub lane_id: String,
    pub contract: ConfidentialContractRef,
    pub emitter_commitment: String,
    pub topic_commitment: String,
    pub ciphertext_hash: String,
    pub ciphertext_bytes: usize,
    pub event_nonce_commitment: String,
    pub event_nullifier: String,
    pub fhe_input_root: String,
    pub access_policy_root: String,
    pub fee_micro_dnr: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: EncryptedEventStatus,
}

impl EncryptedContractEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "sequence": self.sequence,
            "lane_id": self.lane_id,
            "contract": self.contract.public_record(),
            "emitter_commitment": self.emitter_commitment,
            "topic_commitment": self.topic_commitment,
            "ciphertext_hash": self.ciphertext_hash,
            "ciphertext_bytes": self.ciphertext_bytes,
            "event_nonce_commitment": self.event_nonce_commitment,
            "event_nullifier": self.event_nullifier,
            "fhe_input_root": self.fhe_input_root,
            "access_policy_root": self.access_policy_root,
            "fee_micro_dnr": self.fee_micro_dnr,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FheSettlementEnvelope {
    pub envelope_id: String,
    pub lane_id: String,
    pub event_ids: BTreeSet<String>,
    pub encrypted_state_delta_root: String,
    pub encrypted_receipt_root: String,
    pub fhe_circuit_hash: String,
    pub proof_commitment: String,
    pub aggregation_key_commitment: String,
    pub settlement_anchor: String,
    pub privacy_set_size: u64,
    pub fee_micro_dnr: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: EnvelopeStatus,
}

impl FheSettlementEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "lane_id": self.lane_id,
            "event_ids": self.event_ids,
            "encrypted_state_delta_root": self.encrypted_state_delta_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "fhe_circuit_hash": self.fhe_circuit_hash,
            "proof_commitment": self.proof_commitment,
            "aggregation_key_commitment": self.aggregation_key_commitment,
            "settlement_anchor": self.settlement_anchor,
            "privacy_set_size": self.privacy_set_size,
            "fee_micro_dnr": self.fee_micro_dnr,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BusLane {
    pub lane_id: String,
    pub kind: BusLaneKind,
    pub status: LaneStatus,
    pub operator_id: String,
    pub fee_micro_dnr: u64,
    pub max_depth: usize,
    pub queued_events: BTreeSet<String>,
    pub delivered_events: BTreeSet<String>,
    pub congestion_score: u64,
    pub privacy_floor: u64,
}

impl BusLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_id": self.operator_id,
            "fee_micro_dnr": self.fee_micro_dnr,
            "max_depth": self.max_depth,
            "queued_events": self.queued_events,
            "delivered_events": self.delivered_events,
            "congestion_score": self.congestion_score,
            "privacy_floor": self.privacy_floor
        })
    }

    pub fn accepts_events(&self) -> bool {
        matches!(self.status, LaneStatus::Open | LaneStatus::Congested)
            && self.queued_events.len() < self.max_depth
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriberFilter {
    pub filter_id: String,
    pub subscriber_id: String,
    pub lane_ids: BTreeSet<String>,
    pub contract_ids: BTreeSet<String>,
    pub topic_commitments: BTreeSet<String>,
    pub min_privacy_set_size: u64,
    pub action: FilterAction,
    pub redaction_budget_id: Option<String>,
    pub pq_authorization: PqAuthorization,
    pub active: bool,
}

impl SubscriberFilter {
    pub fn public_record(&self) -> Value {
        json!({
            "filter_id": self.filter_id,
            "subscriber_id": self.subscriber_id,
            "lane_ids": self.lane_ids,
            "contract_ids": self.contract_ids,
            "topic_commitments": self.topic_commitments,
            "min_privacy_set_size": self.min_privacy_set_size,
            "action": self.action.as_str(),
            "redaction_budget_id": self.redaction_budget_id,
            "pq_authorization": self.pq_authorization.public_record(),
            "active": self.active
        })
    }

    pub fn matches_event(&self, event: &EncryptedContractEvent) -> bool {
        self.active
            && (self.lane_ids.is_empty() || self.lane_ids.contains(&event.lane_id))
            && (self.contract_ids.is_empty()
                || self.contract_ids.contains(&event.contract.contract_id))
            && (self.topic_commitments.is_empty()
                || self.topic_commitments.contains(&event.topic_commitment))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub oracle_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub observed_root: String,
    pub claimed_height: u64,
    pub expires_height: u64,
    pub verdict: AttestationVerdict,
    pub pq_authorization: PqAuthorization,
    pub evidence_hash: String,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "oracle_id": self.oracle_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "observed_root": self.observed_root,
            "claimed_height": self.claimed_height,
            "expires_height": self.expires_height,
            "verdict": self.verdict.as_str(),
            "pq_authorization": self.pq_authorization.public_record(),
            "evidence_hash": self.evidence_hash
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope_root: String,
    pub allowed_fields: BTreeSet<String>,
    pub total_units: u64,
    pub spent_units: u64,
    pub per_event_cap: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: RedactionBudgetStatus,
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.spent_units)
    }

    pub fn can_spend(&self, units: u64, height: u64) -> bool {
        matches!(self.status, RedactionBudgetStatus::Active)
            && height <= self.expires_height
            && units <= self.per_event_cap
            && units <= self.remaining_units()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "scope_root": self.scope_root,
            "allowed_fields": self.allowed_fields,
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "per_event_cap": self.per_event_cap,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub envelope_ids: BTreeSet<String>,
    pub event_ids: BTreeSet<String>,
    pub aggregate_ciphertext_root: String,
    pub fee_commitment_root: String,
    pub delivery_root: String,
    pub total_fee_micro_dnr: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub sealed_height: Option<u64>,
    pub expires_height: u64,
    pub status: BatchStatus,
}

impl LowFeeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "envelope_ids": self.envelope_ids,
            "event_ids": self.event_ids,
            "aggregate_ciphertext_root": self.aggregate_ciphertext_root,
            "fee_commitment_root": self.fee_commitment_root,
            "delivery_root": self.delivery_root,
            "total_fee_micro_dnr": self.total_fee_micro_dnr,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchDelivery {
    pub delivery_id: String,
    pub batch_id: String,
    pub subscriber_id: String,
    pub filter_id: String,
    pub encrypted_payload_hash: String,
    pub ack_commitment: String,
    pub fee_micro_dnr: u64,
    pub status: DeliveryStatus,
}

impl BatchDelivery {
    pub fn public_record(&self) -> Value {
        json!({
            "delivery_id": self.delivery_id,
            "batch_id": self.batch_id,
            "subscriber_id": self.subscriber_id,
            "filter_id": self.filter_id,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "ack_commitment": self.ack_commitment,
            "fee_micro_dnr": self.fee_micro_dnr,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lane_ids: BTreeSet<String>,
    pub encrypted_event_count: u64,
    pub envelope_count: u64,
    pub low_fee_batch_count: u64,
    pub delivered_count: u64,
    pub rejected_count: u64,
    pub redacted_count: u64,
    pub fee_micro_dnr: u64,
    pub public_root: String,
    pub pq_authorization: PqAuthorization,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "lane_ids": self.lane_ids,
            "encrypted_event_count": self.encrypted_event_count,
            "envelope_count": self.envelope_count,
            "low_fee_batch_count": self.low_fee_batch_count,
            "delivered_count": self.delivered_count,
            "rejected_count": self.rejected_count,
            "redacted_count": self.redacted_count,
            "fee_micro_dnr": self.fee_micro_dnr,
            "public_root": self.public_root,
            "pq_authorization": self.pq_authorization.public_record()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub encrypted_events: BTreeMap<String, EncryptedContractEvent>,
    pub settlement_envelopes: BTreeMap<String, FheSettlementEnvelope>,
    pub bus_lanes: BTreeMap<String, BusLane>,
    pub subscriber_filters: BTreeMap<String, SubscriberFilter>,
    pub pq_oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatch>,
    pub batch_deliveries: BTreeMap<String, BatchDelivery>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            encrypted_events: BTreeMap::new(),
            settlement_envelopes: BTreeMap::new(),
            bus_lanes: BTreeMap::new(),
            subscriber_filters: BTreeMap::new(),
            pq_oracle_attestations: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            batch_deliveries: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn add_bus_lane(&mut self, lane: BusLane) -> Result<()> {
        if self.bus_lanes.contains_key(&lane.lane_id) {
            return Err(format!("duplicate bus lane {}", lane.lane_id));
        }
        self.counters.bus_lanes = self.counters.bus_lanes.saturating_add(1);
        self.bus_lanes.insert(lane.lane_id.clone(), lane);
        self.recompute_roots();
        Ok(())
    }

    pub fn ingest_encrypted_event(&mut self, event: EncryptedContractEvent) -> Result<()> {
        if event.ciphertext_bytes > self.config.max_event_bytes {
            return Err(format!(
                "event {} exceeds max encrypted bytes",
                event.event_id
            ));
        }
        let lane = self
            .bus_lanes
            .get_mut(&event.lane_id)
            .ok_or_else(|| format!("missing lane {}", event.lane_id))?;
        if !lane.accepts_events() {
            return Err(format!("lane {} cannot accept event", event.lane_id));
        }
        if self.nullifiers.contains(&event.event_nullifier) {
            return Err(format!(
                "duplicate event nullifier {}",
                event.event_nullifier
            ));
        }
        lane.queued_events.insert(event.event_id.clone());
        self.nullifiers.insert(event.event_nullifier.clone());
        self.counters.encrypted_events = self.counters.encrypted_events.saturating_add(1);
        self.counters.total_fee_micro_dnr = self
            .counters
            .total_fee_micro_dnr
            .saturating_add(event.fee_micro_dnr);
        self.encrypted_events.insert(event.event_id.clone(), event);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_subscriber_filter(&mut self, filter: SubscriberFilter) -> Result<()> {
        if self.subscriber_filters.contains_key(&filter.filter_id) {
            return Err(format!("duplicate subscriber filter {}", filter.filter_id));
        }
        if filter.pq_authorization.security_bits < self.config.min_pq_security_bits {
            return Err("subscriber filter pq authorization below security floor".to_string());
        }
        self.counters.subscriber_filters = self.counters.subscriber_filters.saturating_add(1);
        self.subscriber_filters
            .insert(filter.filter_id.clone(), filter);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        if self.redaction_budgets.contains_key(&budget.budget_id) {
            return Err(format!("duplicate redaction budget {}", budget.budget_id));
        }
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.recompute_roots();
        Ok(())
    }

    pub fn spend_redaction_budget(
        &mut self,
        budget_id: &str,
        units: u64,
        height: u64,
    ) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("missing redaction budget {budget_id}"))?;
        if !budget.can_spend(units, height) {
            return Err(format!("redaction budget {budget_id} cannot spend {units}"));
        }
        budget.spent_units = budget.spent_units.saturating_add(units);
        if budget.remaining_units() == 0 {
            budget.status = RedactionBudgetStatus::Exhausted;
        }
        self.counters.redacted_events = self.counters.redacted_events.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_settlement_envelope(&mut self, envelope: FheSettlementEnvelope) -> Result<()> {
        if self
            .settlement_envelopes
            .contains_key(&envelope.envelope_id)
        {
            return Err(format!(
                "duplicate settlement envelope {}",
                envelope.envelope_id
            ));
        }
        if envelope.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "envelope {} below privacy set floor",
                envelope.envelope_id
            ));
        }
        for event_id in &envelope.event_ids {
            if !self.encrypted_events.contains_key(event_id) {
                return Err(format!("envelope references missing event {event_id}"));
            }
        }
        self.counters.settlement_envelopes = self.counters.settlement_envelopes.saturating_add(1);
        self.counters.total_fee_micro_dnr = self
            .counters
            .total_fee_micro_dnr
            .saturating_add(envelope.fee_micro_dnr);
        self.settlement_envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_pq_oracle_attestation(&mut self, attestation: PqOracleAttestation) -> Result<()> {
        if self
            .pq_oracle_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err(format!(
                "duplicate pq oracle attestation {}",
                attestation.attestation_id
            ));
        }
        if attestation.pq_authorization.security_bits < self.config.min_pq_security_bits {
            return Err("oracle attestation pq authorization below security floor".to_string());
        }
        self.counters.pq_oracle_attestations =
            self.counters.pq_oracle_attestations.saturating_add(1);
        self.pq_oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_low_fee_batch(&mut self, batch: LowFeeBatch) -> Result<()> {
        if self.low_fee_batches.contains_key(&batch.batch_id) {
            return Err(format!("duplicate low fee batch {}", batch.batch_id));
        }
        if batch.event_ids.len() > self.config.max_batch_events {
            return Err(format!("batch {} exceeds max event count", batch.batch_id));
        }
        if batch.privacy_set_size < self.config.batch_privacy_set_size {
            return Err(format!(
                "batch {} below batch privacy floor",
                batch.batch_id
            ));
        }
        self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        self.counters.total_fee_micro_dnr = self
            .counters
            .total_fee_micro_dnr
            .saturating_add(batch.total_fee_micro_dnr);
        self.low_fee_batches.insert(batch.batch_id.clone(), batch);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_batch_delivery(&mut self, delivery: BatchDelivery) -> Result<()> {
        if self.batch_deliveries.contains_key(&delivery.delivery_id) {
            return Err(format!("duplicate batch delivery {}", delivery.delivery_id));
        }
        if !self.low_fee_batches.contains_key(&delivery.batch_id) {
            return Err(format!("missing batch {}", delivery.batch_id));
        }
        if !self.subscriber_filters.contains_key(&delivery.filter_id) {
            return Err(format!("missing filter {}", delivery.filter_id));
        }
        self.counters.batch_deliveries = self.counters.batch_deliveries.saturating_add(1);
        self.counters.total_fee_micro_dnr = self
            .counters
            .total_fee_micro_dnr
            .saturating_add(delivery.fee_micro_dnr);
        self.batch_deliveries
            .insert(delivery.delivery_id.clone(), delivery);
        self.recompute_roots();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        if self.operator_summaries.contains_key(&summary.summary_id) {
            return Err(format!("duplicate operator summary {}", summary.summary_id));
        }
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.recompute_roots();
        Ok(())
    }

    pub fn matching_filters(&self, event_id: &str) -> Vec<&SubscriberFilter> {
        let Some(event) = self.encrypted_events.get(event_id) else {
            return Vec::new();
        };
        self.subscriber_filters
            .values()
            .filter(|filter| filter.matches_event(event))
            .collect()
    }

    pub fn recompute_roots(&mut self) {
        self.roots.encrypted_event_root = map_root(
            "private-contract-fhe-event-bus:encrypted-events",
            &self.encrypted_events,
            EncryptedContractEvent::public_record,
        );
        self.roots.settlement_envelope_root = map_root(
            "private-contract-fhe-event-bus:settlement-envelopes",
            &self.settlement_envelopes,
            FheSettlementEnvelope::public_record,
        );
        self.roots.bus_lane_root = map_root(
            "private-contract-fhe-event-bus:bus-lanes",
            &self.bus_lanes,
            BusLane::public_record,
        );
        self.roots.subscriber_filter_root = map_root(
            "private-contract-fhe-event-bus:subscriber-filters",
            &self.subscriber_filters,
            SubscriberFilter::public_record,
        );
        self.roots.pq_oracle_attestation_root = map_root(
            "private-contract-fhe-event-bus:pq-oracle-attestations",
            &self.pq_oracle_attestations,
            PqOracleAttestation::public_record,
        );
        self.roots.redaction_budget_root = map_root(
            "private-contract-fhe-event-bus:redaction-budgets",
            &self.redaction_budgets,
            RedactionBudget::public_record,
        );
        self.roots.low_fee_batch_root = map_root(
            "private-contract-fhe-event-bus:low-fee-batches",
            &self.low_fee_batches,
            LowFeeBatch::public_record,
        );
        self.roots.batch_delivery_root = map_root(
            "private-contract-fhe-event-bus:batch-deliveries",
            &self.batch_deliveries,
            BatchDelivery::public_record,
        );
        self.roots.operator_summary_root = map_root(
            "private-contract-fhe-event-bus:operator-summaries",
            &self.operator_summaries,
            OperatorSummary::public_record,
        );
        let nullifier_values = self
            .nullifiers
            .iter()
            .map(|value| json!(value))
            .collect::<Vec<_>>();
        self.roots.nullifier_root = merkle_root(
            "private-contract-fhe-event-bus:nullifiers",
            &nullifier_values,
        );
        self.roots.fee_root = domain_hash(
            "private-contract-fhe-event-bus:fees",
            &[
                HashPart::U64(self.counters.total_fee_micro_dnr),
                HashPart::U64(self.counters.delivered_events),
                HashPart::U64(self.counters.rejected_events),
                HashPart::U64(self.counters.redacted_events),
            ],
            32,
        );
        self.roots.state_root = state_root_from_parts(&self.config, &self.counters, &self.roots);
    }
}

pub fn devnet() -> State {
    State::new(Config::devnet())
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .add_bus_lane(make_lane(
            "lane-low-fee",
            BusLaneKind::LowFee,
            "operator-alpha",
            &state.config,
        ))
        .expect("devnet low-fee lane");
    state
        .add_bus_lane(make_lane(
            "lane-fast",
            BusLaneKind::Fast,
            "operator-beta",
            &state.config,
        ))
        .expect("devnet fast lane");

    let budget = RedactionBudget {
        budget_id: "budget-auditor-selective-view".to_string(),
        owner_commitment: commitment("budget-owner", "auditor"),
        scope_root: commitment("budget-scope", "contracts"),
        allowed_fields: set(["topic_commitment", "fee_micro_dnr", "settlement_anchor"]),
        total_units: 128,
        spent_units: 4,
        per_event_cap: 8,
        created_height: 128,
        expires_height: 128 + state.config.redaction_ttl_blocks,
        status: RedactionBudgetStatus::Active,
    };
    state
        .add_redaction_budget(budget)
        .expect("devnet redaction budget");

    let filter = SubscriberFilter {
        filter_id: "filter-auditor-low-fee-contracts".to_string(),
        subscriber_id: "subscriber-auditor-001".to_string(),
        lane_ids: set(["lane-low-fee"]),
        contract_ids: set(["contract-private-swap", "contract-private-vault"]),
        topic_commitments: BTreeSet::new(),
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        action: FilterAction::AggregateOnly,
        redaction_budget_id: Some("budget-auditor-selective-view".to_string()),
        pq_authorization: PqAuthorization::devnet("filter-auditor"),
        active: true,
    };
    state
        .add_subscriber_filter(filter)
        .expect("devnet subscriber filter");

    for (idx, contract_id) in [
        "contract-private-swap",
        "contract-private-vault",
        "contract-private-payroll",
    ]
    .iter()
    .enumerate()
    {
        let event = make_event(idx as u64 + 1, "lane-low-fee", contract_id, &state.config);
        state.ingest_encrypted_event(event).expect("devnet event");
    }

    let envelope_events = state
        .encrypted_events
        .keys()
        .take(2)
        .cloned()
        .collect::<BTreeSet<_>>();
    let envelope = FheSettlementEnvelope {
        envelope_id: "envelope-low-fee-0001".to_string(),
        lane_id: "lane-low-fee".to_string(),
        event_ids: envelope_events.clone(),
        encrypted_state_delta_root: commitment("fhe-state-delta", "envelope-low-fee-0001"),
        encrypted_receipt_root: commitment("fhe-receipt", "envelope-low-fee-0001"),
        fhe_circuit_hash: commitment("fhe-circuit", "settle-contract-events"),
        proof_commitment: commitment("fhe-proof", "envelope-low-fee-0001"),
        aggregation_key_commitment: commitment("fhe-aggregation-key", "operator-alpha"),
        settlement_anchor: commitment("settlement-anchor", "envelope-low-fee-0001"),
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        fee_micro_dnr: 70,
        opened_height: 130,
        expires_height: 130 + state.config.batch_ttl_blocks,
        status: EnvelopeStatus::Attested,
    };
    state
        .add_settlement_envelope(envelope)
        .expect("devnet envelope");

    let attestation = PqOracleAttestation {
        attestation_id: "attestation-oracle-0001".to_string(),
        oracle_id: "oracle-pq-fhe-001".to_string(),
        subject_kind: "fhe_settlement_envelope".to_string(),
        subject_id: "envelope-low-fee-0001".to_string(),
        observed_root: state.roots.settlement_envelope_root.clone(),
        claimed_height: 132,
        expires_height: 132 + state.config.attestation_ttl_blocks,
        verdict: AttestationVerdict::Valid,
        pq_authorization: PqAuthorization::devnet("oracle-pq-fhe-001"),
        evidence_hash: commitment("oracle-evidence", "envelope-low-fee-0001"),
    };
    state
        .add_pq_oracle_attestation(attestation)
        .expect("devnet attestation");

    let batch = LowFeeBatch {
        batch_id: "batch-low-fee-0001".to_string(),
        lane_id: "lane-low-fee".to_string(),
        envelope_ids: set(["envelope-low-fee-0001"]),
        event_ids: envelope_events,
        aggregate_ciphertext_root: commitment("batch-ciphertext", "batch-low-fee-0001"),
        fee_commitment_root: commitment("batch-fee", "batch-low-fee-0001"),
        delivery_root: commitment("batch-delivery", "batch-low-fee-0001"),
        total_fee_micro_dnr: 180,
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        opened_height: 134,
        sealed_height: Some(136),
        expires_height: 134 + state.config.batch_ttl_blocks,
        status: BatchStatus::Submitted,
    };
    state.add_low_fee_batch(batch).expect("devnet batch");

    let delivery = BatchDelivery {
        delivery_id: "delivery-auditor-0001".to_string(),
        batch_id: "batch-low-fee-0001".to_string(),
        subscriber_id: "subscriber-auditor-001".to_string(),
        filter_id: "filter-auditor-low-fee-contracts".to_string(),
        encrypted_payload_hash: commitment("delivery-payload", "auditor-0001"),
        ack_commitment: commitment("delivery-ack", "auditor-0001"),
        fee_micro_dnr: 5,
        status: DeliveryStatus::Acked,
    };
    state.add_batch_delivery(delivery).expect("devnet delivery");

    let summary = OperatorSummary {
        summary_id: "summary-operator-alpha-epoch-0001".to_string(),
        operator_id: "operator-alpha".to_string(),
        epoch: 1,
        lane_ids: set(["lane-low-fee"]),
        encrypted_event_count: state.encrypted_events.len() as u64,
        envelope_count: state.settlement_envelopes.len() as u64,
        low_fee_batch_count: state.low_fee_batches.len() as u64,
        delivered_count: state.batch_deliveries.len() as u64,
        rejected_count: state.counters.rejected_events,
        redacted_count: state.counters.redacted_events,
        fee_micro_dnr: state.counters.total_fee_micro_dnr,
        public_root: state.roots.state_root.clone(),
        pq_authorization: PqAuthorization::devnet("operator-alpha-summary"),
    };
    state
        .add_operator_summary(summary)
        .expect("devnet operator summary");
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "config": state.config,
        "counters": state.counters,
        "roots": state.roots,
        "encrypted_events": values(&state.encrypted_events, EncryptedContractEvent::public_record),
        "settlement_envelopes": values(&state.settlement_envelopes, FheSettlementEnvelope::public_record),
        "bus_lanes": values(&state.bus_lanes, BusLane::public_record),
        "subscriber_filters": values(&state.subscriber_filters, SubscriberFilter::public_record),
        "pq_oracle_attestations": values(&state.pq_oracle_attestations, PqOracleAttestation::public_record),
        "redaction_budgets": values(&state.redaction_budgets, RedactionBudget::public_record),
        "low_fee_batches": values(&state.low_fee_batches, LowFeeBatch::public_record),
        "batch_deliveries": values(&state.batch_deliveries, BatchDelivery::public_record),
        "operator_summaries": values(&state.operator_summaries, OperatorSummary::public_record),
        "nullifier_root": state.roots.nullifier_root,
    })
}

pub fn state_root(state: &State) -> String {
    state_root_from_parts(&state.config, &state.counters, &state.roots)
}

pub fn state_root_from_parts(config: &Config, counters: &Counters, roots: &Roots) -> String {
    let root_record = json!({
        "protocol_version": config.protocol_version,
        "schema_version": config.schema_version,
        "chain_id": config.chain_id,
        "network": config.network,
        "bus_id": config.bus_id,
        "counters": counters,
        "encrypted_event_root": roots.encrypted_event_root,
        "settlement_envelope_root": roots.settlement_envelope_root,
        "bus_lane_root": roots.bus_lane_root,
        "subscriber_filter_root": roots.subscriber_filter_root,
        "pq_oracle_attestation_root": roots.pq_oracle_attestation_root,
        "redaction_budget_root": roots.redaction_budget_root,
        "low_fee_batch_root": roots.low_fee_batch_root,
        "batch_delivery_root": roots.batch_delivery_root,
        "operator_summary_root": roots.operator_summary_root,
        "nullifier_root": roots.nullifier_root,
        "fee_root": roots.fee_root,
    });
    domain_hash(
        "private-contract-fhe-event-bus:state-root",
        &[HashPart::Json(&root_record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"id": key, "record": f(value)}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn values<T, F>(map: &BTreeMap<String, T>, f: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(f).collect()
}

fn commitment(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(label)], 32)
}

fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.into_iter().map(str::to_string).collect()
}

fn make_lane(lane_id: &str, kind: BusLaneKind, operator_id: &str, config: &Config) -> BusLane {
    BusLane {
        lane_id: lane_id.to_string(),
        kind,
        status: LaneStatus::Open,
        operator_id: operator_id.to_string(),
        fee_micro_dnr: kind.fee_micro_dnr(config),
        max_depth: config.max_lane_depth,
        queued_events: BTreeSet::new(),
        delivered_events: BTreeSet::new(),
        congestion_score: 0,
        privacy_floor: config.min_privacy_set_size,
    }
}

fn make_event(
    sequence: u64,
    lane_id: &str,
    contract_id: &str,
    config: &Config,
) -> EncryptedContractEvent {
    let event_id = format!("event-{sequence:012}");
    EncryptedContractEvent {
        event_id: event_id.clone(),
        sequence,
        lane_id: lane_id.to_string(),
        contract: ConfidentialContractRef {
            contract_id: contract_id.to_string(),
            deployment_root: commitment("contract-deployment", contract_id),
            code_hash: commitment("contract-code", contract_id),
            policy_root: commitment("contract-policy", contract_id),
            privacy_domain: "private-contract-devnet".to_string(),
        },
        emitter_commitment: commitment("event-emitter", &event_id),
        topic_commitment: commitment("event-topic", contract_id),
        ciphertext_hash: commitment("event-ciphertext", &event_id),
        ciphertext_bytes: 2048,
        event_nonce_commitment: commitment("event-nonce", &event_id),
        event_nullifier: commitment("event-nullifier", &event_id),
        fhe_input_root: commitment("event-fhe-input", &event_id),
        access_policy_root: commitment("event-access-policy", &event_id),
        fee_micro_dnr: BusLaneKind::LowFee.fee_micro_dnr(config),
        created_height: 128 + sequence,
        expires_height: 128 + sequence + config.batch_ttl_blocks,
        status: EncryptedEventStatus::Received,
    }
}

impl State {
    pub fn encrypted_event(&self, id: &str) -> Option<&EncryptedContractEvent> {
        self.encrypted_events.get(id)
    }

    pub fn encrypted_event_record(&self, id: &str) -> Option<Value> {
        self.encrypted_events
            .get(id)
            .map(EncryptedContractEvent::public_record)
    }

    pub fn encrypted_event_ids(&self) -> Vec<String> {
        self.encrypted_events.keys().cloned().collect()
    }

    pub fn settlement_envelope(&self, id: &str) -> Option<&FheSettlementEnvelope> {
        self.settlement_envelopes.get(id)
    }

    pub fn settlement_envelope_record(&self, id: &str) -> Option<Value> {
        self.settlement_envelopes
            .get(id)
            .map(FheSettlementEnvelope::public_record)
    }

    pub fn settlement_envelope_ids(&self) -> Vec<String> {
        self.settlement_envelopes.keys().cloned().collect()
    }

    pub fn bus_lane(&self, id: &str) -> Option<&BusLane> {
        self.bus_lanes.get(id)
    }

    pub fn bus_lane_record(&self, id: &str) -> Option<Value> {
        self.bus_lanes.get(id).map(BusLane::public_record)
    }

    pub fn bus_lane_ids(&self) -> Vec<String> {
        self.bus_lanes.keys().cloned().collect()
    }

    pub fn subscriber_filter(&self, id: &str) -> Option<&SubscriberFilter> {
        self.subscriber_filters.get(id)
    }

    pub fn subscriber_filter_record(&self, id: &str) -> Option<Value> {
        self.subscriber_filters
            .get(id)
            .map(SubscriberFilter::public_record)
    }

    pub fn subscriber_filter_ids(&self) -> Vec<String> {
        self.subscriber_filters.keys().cloned().collect()
    }

    pub fn pq_oracle_attestation(&self, id: &str) -> Option<&PqOracleAttestation> {
        self.pq_oracle_attestations.get(id)
    }

    pub fn pq_oracle_attestation_record(&self, id: &str) -> Option<Value> {
        self.pq_oracle_attestations
            .get(id)
            .map(PqOracleAttestation::public_record)
    }

    pub fn pq_oracle_attestation_ids(&self) -> Vec<String> {
        self.pq_oracle_attestations.keys().cloned().collect()
    }

    pub fn redaction_budget(&self, id: &str) -> Option<&RedactionBudget> {
        self.redaction_budgets.get(id)
    }

    pub fn redaction_budget_record(&self, id: &str) -> Option<Value> {
        self.redaction_budgets
            .get(id)
            .map(RedactionBudget::public_record)
    }

    pub fn redaction_budget_ids(&self) -> Vec<String> {
        self.redaction_budgets.keys().cloned().collect()
    }

    pub fn low_fee_batch(&self, id: &str) -> Option<&LowFeeBatch> {
        self.low_fee_batches.get(id)
    }

    pub fn low_fee_batch_record(&self, id: &str) -> Option<Value> {
        self.low_fee_batches.get(id).map(LowFeeBatch::public_record)
    }

    pub fn low_fee_batch_ids(&self) -> Vec<String> {
        self.low_fee_batches.keys().cloned().collect()
    }

    pub fn batch_delivery(&self, id: &str) -> Option<&BatchDelivery> {
        self.batch_deliveries.get(id)
    }

    pub fn batch_delivery_record(&self, id: &str) -> Option<Value> {
        self.batch_deliveries
            .get(id)
            .map(BatchDelivery::public_record)
    }

    pub fn batch_delivery_ids(&self) -> Vec<String> {
        self.batch_deliveries.keys().cloned().collect()
    }

    pub fn operator_summary(&self, id: &str) -> Option<&OperatorSummary> {
        self.operator_summaries.get(id)
    }

    pub fn operator_summary_record(&self, id: &str) -> Option<Value> {
        self.operator_summaries
            .get(id)
            .map(OperatorSummary::public_record)
    }

    pub fn operator_summary_ids(&self) -> Vec<String> {
        self.operator_summaries.keys().cloned().collect()
    }

    pub fn events_by_status(&self, status: EncryptedEventStatus) -> Vec<&EncryptedContractEvent> {
        self.encrypted_events
            .values()
            .filter(|event| event.status == status)
            .collect()
    }

    pub fn envelopes_by_status(&self, status: EnvelopeStatus) -> Vec<&FheSettlementEnvelope> {
        self.settlement_envelopes
            .values()
            .filter(|envelope| envelope.status == status)
            .collect()
    }

    pub fn lanes_by_status(&self, status: LaneStatus) -> Vec<&BusLane> {
        self.bus_lanes
            .values()
            .filter(|lane| lane.status == status)
            .collect()
    }

    pub fn batches_by_status(&self, status: BatchStatus) -> Vec<&LowFeeBatch> {
        self.low_fee_batches
            .values()
            .filter(|batch| batch.status == status)
            .collect()
    }

    pub fn deliveries_by_status(&self, status: DeliveryStatus) -> Vec<&BatchDelivery> {
        self.batch_deliveries
            .values()
            .filter(|delivery| delivery.status == status)
            .collect()
    }

    pub fn low_fee_queue_depth(&self) -> usize {
        self.bus_lanes
            .values()
            .filter(|lane| lane.kind == BusLaneKind::LowFee)
            .map(|lane| lane.queued_events.len())
            .sum()
    }

    pub fn active_privacy_capacity(&self) -> u64 {
        self.bus_lanes
            .values()
            .filter(|lane| lane.status == LaneStatus::Open)
            .map(|lane| lane.privacy_floor)
            .sum()
    }

    pub fn low_fee_savings_micro_dnr(&self) -> u64 {
        self.encrypted_events
            .values()
            .filter(|event| {
                self.bus_lanes
                    .get(&event.lane_id)
                    .map(|lane| lane.kind == BusLaneKind::LowFee)
                    .unwrap_or(false)
            })
            .map(|event| {
                self.config
                    .standard_fee_micro_dnr
                    .saturating_sub(event.fee_micro_dnr)
            })
            .sum()
    }

    pub fn public_metrics(&self) -> Value {
        json!({
            "encrypted_events": self.encrypted_events.len(),
            "settlement_envelopes": self.settlement_envelopes.len(),
            "bus_lanes": self.bus_lanes.len(),
            "subscriber_filters": self.subscriber_filters.len(),
            "pq_oracle_attestations": self.pq_oracle_attestations.len(),
            "redaction_budgets": self.redaction_budgets.len(),
            "low_fee_batches": self.low_fee_batches.len(),
            "batch_deliveries": self.batch_deliveries.len(),
            "operator_summaries": self.operator_summaries.len(),
            "low_fee_queue_depth": self.low_fee_queue_depth(),
            "active_privacy_capacity": self.active_privacy_capacity(),
            "low_fee_savings_micro_dnr": self.low_fee_savings_micro_dnr(),
            "state_root": self.roots.state_root
        })
    }
}

pub fn encrypted_event_leaf_hash(record: &EncryptedContractEvent) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:encrypted-event:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn settlement_envelope_leaf_hash(record: &FheSettlementEnvelope) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:settlement-envelope:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn bus_lane_leaf_hash(record: &BusLane) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:bus-lane:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn subscriber_filter_leaf_hash(record: &SubscriberFilter) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:subscriber-filter:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn pq_oracle_attestation_leaf_hash(record: &PqOracleAttestation) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:pq-oracle-attestation:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn redaction_budget_leaf_hash(record: &RedactionBudget) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:redaction-budget:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn low_fee_batch_leaf_hash(record: &LowFeeBatch) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:low-fee-batch:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn batch_delivery_leaf_hash(record: &BatchDelivery) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:batch-delivery:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn operator_summary_leaf_hash(record: &OperatorSummary) -> String {
    let value = record.public_record();
    domain_hash(
        "private-contract-fhe-event-bus:operator-summary:leaf-hash",
        &[HashPart::Json(&value)],
        32,
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvariantReport {
    pub ok: bool,
    pub checked_roots: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

impl InvariantReport {
    pub fn public_record(&self) -> Value {
        json!({
            "ok": self.ok,
            "checked_roots": self.checked_roots,
            "warnings": self.warnings
        })
    }
}

pub fn invariant_report(state: &State) -> InvariantReport {
    let mut warnings = Vec::new();
    for (event_id, event) in &state.encrypted_events {
        if !state.bus_lanes.contains_key(&event.lane_id) {
            warnings.push(format!(
                "event {event_id} references missing lane {}",
                event.lane_id
            ));
        }
        if event.ciphertext_bytes > state.config.max_event_bytes {
            warnings.push(format!("event {event_id} exceeds ciphertext byte cap"));
        }
    }
    for (envelope_id, envelope) in &state.settlement_envelopes {
        if envelope.privacy_set_size < state.config.min_privacy_set_size {
            warnings.push(format!("envelope {envelope_id} below privacy floor"));
        }
        for event_id in &envelope.event_ids {
            if !state.encrypted_events.contains_key(event_id) {
                warnings.push(format!(
                    "envelope {envelope_id} references missing event {event_id}"
                ));
            }
        }
    }
    for (batch_id, batch) in &state.low_fee_batches {
        if batch.privacy_set_size < state.config.batch_privacy_set_size {
            warnings.push(format!("batch {batch_id} below batch privacy floor"));
        }
        if batch.event_ids.len() > state.config.max_batch_events {
            warnings.push(format!("batch {batch_id} exceeds max event count"));
        }
    }
    let mut checked_roots = BTreeMap::new();
    checked_roots.insert(
        "encrypted_event_root".to_string(),
        state.roots.encrypted_event_root.clone(),
    );
    checked_roots.insert(
        "settlement_envelope_root".to_string(),
        state.roots.settlement_envelope_root.clone(),
    );
    checked_roots.insert(
        "bus_lane_root".to_string(),
        state.roots.bus_lane_root.clone(),
    );
    checked_roots.insert(
        "subscriber_filter_root".to_string(),
        state.roots.subscriber_filter_root.clone(),
    );
    checked_roots.insert(
        "pq_oracle_attestation_root".to_string(),
        state.roots.pq_oracle_attestation_root.clone(),
    );
    checked_roots.insert(
        "redaction_budget_root".to_string(),
        state.roots.redaction_budget_root.clone(),
    );
    checked_roots.insert(
        "low_fee_batch_root".to_string(),
        state.roots.low_fee_batch_root.clone(),
    );
    checked_roots.insert(
        "batch_delivery_root".to_string(),
        state.roots.batch_delivery_root.clone(),
    );
    checked_roots.insert(
        "operator_summary_root".to_string(),
        state.roots.operator_summary_root.clone(),
    );
    checked_roots.insert("state_root".to_string(), state.roots.state_root.clone());
    InvariantReport {
        ok: warnings.is_empty(),
        checked_roots,
        warnings,
    }
}
