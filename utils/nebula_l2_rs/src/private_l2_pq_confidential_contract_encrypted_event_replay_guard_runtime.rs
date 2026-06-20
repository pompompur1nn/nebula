use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractEncryptedEventReplayGuardRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractEncryptedEventReplayGuardRuntimeResult<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_EVENT_REPLAY_GUARD_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-encrypted-event-replay-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_EVENT_REPLAY_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_TOPIC_SUITE: &str = "ML-KEM-1024+Poseidon2-encrypted-topic-commitment-v1";
pub const EVENT_NULLIFIER_SUITE: &str = "confidential-contract-event-nullifier-v1";
pub const REPLAY_WINDOW_SUITE: &str = "bounded-height-event-replay-window-v1";
pub const CALLBACK_FENCE_SUITE: &str = "confidential-callback-fence-root-v1";
pub const PQ_PUBLISHER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-event-publisher-attestation-v1";
pub const DUPLICATE_QUARANTINE_SUITE: &str = "duplicate-event-quarantine-evidence-v1";
pub const LOW_FEE_BATCH_REBATE_SUITE: &str = "low-fee-event-batch-guard-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "encrypted-event-redaction-budget-ledger-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-encrypted-event-replay-guard-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 2_243_120;
pub const DEVNET_EPOCH: u64 = 3_117;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 8_640;
pub const DEFAULT_CALLBACK_FENCE_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PUBLISHER_WEIGHT: u64 = 7;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MAX_TOPIC_LEAKAGE_BPS: u64 = 35;
pub const DEFAULT_MAX_PAYLOAD_REDACTION_BPS: u64 = 80;
pub const DEFAULT_BASE_EVENT_FEE_MICRO_CREDITS: u128 = 900;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 850;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventDomain {
    Token,
    Dex,
    Lending,
    Oracle,
    Bridge,
    Governance,
    Wallet,
    Risk,
    Custom,
}

impl EventDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::Wallet => "wallet",
            Self::Risk => "risk",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Pending,
    Accepted,
    Fenced,
    Quarantined,
    Rebated,
    Expired,
}

impl GuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Fenced => "fenced",
            Self::Quarantined => "quarantined",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
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
    pub event_nullifier_suite: String,
    pub replay_window_suite: String,
    pub callback_fence_suite: String,
    pub pq_publisher_attestation_suite: String,
    pub duplicate_quarantine_suite: String,
    pub low_fee_batch_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub l2_network: String,
    pub replay_window_blocks: u64,
    pub callback_fence_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_publisher_weight: u64,
    pub quorum_bps: u64,
    pub max_topic_leakage_bps: u64,
    pub max_payload_redaction_bps: u64,
    pub base_event_fee_micro_credits: u128,
    pub batch_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_topic_suite: ENCRYPTED_TOPIC_SUITE.to_string(),
            event_nullifier_suite: EVENT_NULLIFIER_SUITE.to_string(),
            replay_window_suite: REPLAY_WINDOW_SUITE.to_string(),
            callback_fence_suite: CALLBACK_FENCE_SUITE.to_string(),
            pq_publisher_attestation_suite: PQ_PUBLISHER_ATTESTATION_SUITE.to_string(),
            duplicate_quarantine_suite: DUPLICATE_QUARANTINE_SUITE.to_string(),
            low_fee_batch_rebate_suite: LOW_FEE_BATCH_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            callback_fence_blocks: DEFAULT_CALLBACK_FENCE_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_publisher_weight: DEFAULT_MIN_PUBLISHER_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            max_topic_leakage_bps: DEFAULT_MAX_TOPIC_LEAKAGE_BPS,
            max_payload_redaction_bps: DEFAULT_MAX_PAYLOAD_REDACTION_BPS,
            base_event_fee_micro_credits: DEFAULT_BASE_EVENT_FEE_MICRO_CREDITS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub encrypted_topics: u64,
    pub event_nullifiers: u64,
    pub replay_windows: u64,
    pub callback_fences: u64,
    pub publisher_attestations: u64,
    pub duplicate_quarantines: u64,
    pub low_fee_batch_rebates: u64,
    pub redaction_budgets: u64,
    pub accepted_events: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub encrypted_topic_root: String,
    pub event_nullifier_root: String,
    pub replay_window_root: String,
    pub callback_fence_root: String,
    pub publisher_attestation_root: String,
    pub duplicate_quarantine_root: String,
    pub low_fee_batch_rebate_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            encrypted_topic_root: empty_root("ENCRYPTED-TOPIC"),
            event_nullifier_root: empty_root("EVENT-NULLIFIER"),
            replay_window_root: empty_root("REPLAY-WINDOW"),
            callback_fence_root: empty_root("CALLBACK-FENCE"),
            publisher_attestation_root: empty_root("PUBLISHER-ATTESTATION"),
            duplicate_quarantine_root: empty_root("DUPLICATE-QUARANTINE"),
            low_fee_batch_rebate_root: empty_root("LOW-FEE-BATCH-REBATE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedTopic {
    pub topic_id: String,
    pub domain: EventDomain,
    pub contract_commitment: String,
    pub encrypted_topic_commitment: String,
    pub topic_epoch: u64,
    pub leakage_bps: u64,
}

impl EncryptedTopic {
    pub fn public_record(&self) -> Value {
        json!({
            "topic_id": self.topic_id,
            "domain": self.domain.as_str(),
            "contract_commitment": self.contract_commitment,
            "encrypted_topic_commitment": self.encrypted_topic_commitment,
            "topic_epoch": self.topic_epoch,
            "leakage_bps": self.leakage_bps
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventNullifier {
    pub nullifier_id: String,
    pub topic_id: String,
    pub event_commitment: String,
    pub publisher_commitment: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: GuardStatus,
}

impl EventNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "topic_id": self.topic_id,
            "event_commitment": self.event_commitment,
            "publisher_commitment": self.publisher_commitment,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayWindow {
    pub window_id: String,
    pub topic_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub nullifier_count: u64,
    pub window_root: String,
}

impl ReplayWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "topic_id": self.topic_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "nullifier_count": self.nullifier_count,
            "window_root": self.window_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallbackFence {
    pub fence_id: String,
    pub callback_commitment: String,
    pub allowed_topic_ids: BTreeSet<String>,
    pub min_height: u64,
    pub max_height: u64,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl CallbackFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "callback_commitment": self.callback_commitment,
            "allowed_topic_ids": self.allowed_topic_ids,
            "min_height": self.min_height,
            "max_height": self.max_height,
            "consumed_nullifier_count": self.consumed_nullifiers.len()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherAttestation {
    pub attestation_id: String,
    pub publisher_commitment: String,
    pub event_commitment: String,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub signer_weight: u64,
    pub valid_until_height: u64,
    pub attestation_root: String,
}

impl PublisherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "publisher_commitment": self.publisher_commitment,
            "event_commitment": self.event_commitment,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "signer_weight": self.signer_weight,
            "valid_until_height": self.valid_until_height,
            "attestation_root": self.attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DuplicateQuarantine {
    pub quarantine_id: String,
    pub nullifier_id: String,
    pub original_event_commitment: String,
    pub duplicate_event_commitment: String,
    pub evidence_root: String,
    pub quarantined_at_height: u64,
}

impl DuplicateQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "nullifier_id": self.nullifier_id,
            "original_event_commitment": self.original_event_commitment,
            "duplicate_event_commitment": self.duplicate_event_commitment,
            "evidence_root": self.evidence_root,
            "quarantined_at_height": self.quarantined_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchRebate {
    pub rebate_id: String,
    pub batch_root: String,
    pub event_count: u64,
    pub gross_fee_micro_credits: u128,
    pub rebate_micro_credits: u128,
    pub cleared_at_height: u64,
}

impl LowFeeBatchRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_root": self.batch_root,
            "event_count": self.event_count,
            "gross_fee_micro_credits": self.gross_fee_micro_credits,
            "rebate_micro_credits": self.rebate_micro_credits,
            "cleared_at_height": self.cleared_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub topic_id: String,
    pub topic_leakage_bps: u64,
    pub payload_redaction_bps: u64,
    pub remaining_disclosures: u64,
    pub budget_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "topic_id": self.topic_id,
            "topic_leakage_bps": self.topic_leakage_bps,
            "payload_redaction_bps": self.payload_redaction_bps,
            "remaining_disclosures": self.remaining_disclosures,
            "budget_root": self.budget_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub encrypted_topics: BTreeMap<String, EncryptedTopic>,
    pub event_nullifiers: BTreeMap<String, EventNullifier>,
    pub replay_windows: BTreeMap<String, ReplayWindow>,
    pub callback_fences: BTreeMap<String, CallbackFence>,
    pub publisher_attestations: BTreeMap<String, PublisherAttestation>,
    pub duplicate_quarantines: BTreeMap<String, DuplicateQuarantine>,
    pub low_fee_batch_rebates: BTreeMap<String, LowFeeBatchRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::empty(),
            encrypted_topics: BTreeMap::new(),
            event_nullifiers: BTreeMap::new(),
            replay_windows: BTreeMap::new(),
            callback_fences: BTreeMap::new(),
            publisher_attestations: BTreeMap::new(),
            duplicate_quarantines: BTreeMap::new(),
            low_fee_batch_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH);
        state.seed_devnet();
        state
    }

    pub fn register_topic(&mut self, topic: EncryptedTopic) -> Result<String> {
        ensure!(
            topic.leakage_bps <= self.config.max_topic_leakage_bps,
            "topic leakage {} exceeds configured maximum {}",
            topic.leakage_bps,
            self.config.max_topic_leakage_bps
        );
        let id = topic.topic_id.clone();
        self.encrypted_topics.insert(id.clone(), topic);
        self.refresh_roots();
        Ok(id)
    }

    pub fn observe_event_nullifier(&mut self, mut nullifier: EventNullifier) -> Result<String> {
        ensure!(
            self.encrypted_topics.contains_key(&nullifier.topic_id),
            "unknown encrypted topic {}",
            nullifier.topic_id
        );
        if let Some(existing) = self.event_nullifiers.get(&nullifier.nullifier_id) {
            nullifier.status = GuardStatus::Quarantined;
            let quarantine = duplicate_quarantine(existing, &nullifier, self.height);
            self.duplicate_quarantines
                .insert(quarantine.quarantine_id.clone(), quarantine);
        } else {
            self.counters.accepted_events = self.counters.accepted_events.saturating_add(1);
        }
        let id = nullifier.nullifier_id.clone();
        self.event_nullifiers.insert(id.clone(), nullifier);
        self.refresh_roots();
        Ok(id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": PUBLIC_RECORD_SCHEME,
            "config": {
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "hash_suite": self.config.hash_suite,
                "encrypted_topic_suite": self.config.encrypted_topic_suite,
                "event_nullifier_suite": self.config.event_nullifier_suite,
                "replay_window_suite": self.config.replay_window_suite,
                "callback_fence_suite": self.config.callback_fence_suite,
                "pq_publisher_attestation_suite": self.config.pq_publisher_attestation_suite,
                "duplicate_quarantine_suite": self.config.duplicate_quarantine_suite,
                "low_fee_batch_rebate_suite": self.config.low_fee_batch_rebate_suite,
                "redaction_budget_suite": self.config.redaction_budget_suite,
                "l2_network": self.config.l2_network,
                "replay_window_blocks": self.config.replay_window_blocks,
                "callback_fence_blocks": self.config.callback_fence_blocks,
                "attestation_ttl_blocks": self.config.attestation_ttl_blocks,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "min_publisher_weight": self.config.min_publisher_weight,
                "quorum_bps": self.config.quorum_bps,
                "max_topic_leakage_bps": self.config.max_topic_leakage_bps,
                "max_payload_redaction_bps": self.config.max_payload_redaction_bps,
                "base_event_fee_micro_credits": self.config.base_event_fee_micro_credits,
                "batch_rebate_bps": self.config.batch_rebate_bps
            },
            "height": self.height,
            "epoch": self.epoch,
            "counters": self.counters,
            "roots": self.roots,
            "encrypted_topics": self.encrypted_topics.values().map(EncryptedTopic::public_record).collect::<Vec<_>>(),
            "event_nullifiers": self.event_nullifiers.values().map(EventNullifier::public_record).collect::<Vec<_>>(),
            "replay_windows": self.replay_windows.values().map(ReplayWindow::public_record).collect::<Vec<_>>(),
            "callback_fences": self.callback_fences.values().map(CallbackFence::public_record).collect::<Vec<_>>(),
            "publisher_attestations": self.publisher_attestations.values().map(PublisherAttestation::public_record).collect::<Vec<_>>(),
            "duplicate_quarantines": self.duplicate_quarantines.values().map(DuplicateQuarantine::public_record).collect::<Vec<_>>(),
            "low_fee_batch_rebates": self.low_fee_batch_rebates.values().map(LowFeeBatchRebate::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>()
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn seed_devnet(&mut self) {
        let topic = EncryptedTopic {
            topic_id: "evt-topic-devnet-swap-v1".to_string(),
            domain: EventDomain::Dex,
            contract_commitment: commitment("contract", "confidential-swap-router"),
            encrypted_topic_commitment: commitment("topic", "swap-fill"),
            topic_epoch: self.epoch,
            leakage_bps: 24,
        };
        let topic_id = self.register_topic(topic).expect("devnet topic");
        let nullifier = EventNullifier {
            nullifier_id: "evt-nullifier-devnet-0001".to_string(),
            topic_id: topic_id.clone(),
            event_commitment: commitment("event", "swap-fill-0001"),
            publisher_commitment: commitment("publisher", "sequencer-a"),
            first_seen_height: self.height,
            expires_at_height: self.height + self.config.replay_window_blocks,
            status: GuardStatus::Accepted,
        };
        self.observe_event_nullifier(nullifier)
            .expect("devnet nullifier");
        self.replay_windows.insert(
            "replay-window-devnet-swap".to_string(),
            ReplayWindow {
                window_id: "replay-window-devnet-swap".to_string(),
                topic_id: topic_id.clone(),
                start_height: self.height,
                end_height: self.height + self.config.replay_window_blocks,
                nullifier_count: 1,
                window_root: deterministic_record_root("REPLAY-WINDOW", &json!([topic_id])),
            },
        );
        self.callback_fences.insert(
            "callback-fence-devnet-router".to_string(),
            CallbackFence {
                fence_id: "callback-fence-devnet-router".to_string(),
                callback_commitment: commitment("callback", "router-settlement-hook"),
                allowed_topic_ids: BTreeSet::from(["evt-topic-devnet-swap-v1".to_string()]),
                min_height: self.height,
                max_height: self.height + self.config.callback_fence_blocks,
                consumed_nullifiers: BTreeSet::from(["evt-nullifier-devnet-0001".to_string()]),
            },
        );
        self.publisher_attestations.insert(
            "publisher-attestation-devnet-a".to_string(),
            PublisherAttestation {
                attestation_id: "publisher-attestation-devnet-a".to_string(),
                publisher_commitment: commitment("publisher", "sequencer-a"),
                event_commitment: commitment("event", "swap-fill-0001"),
                pq_scheme: PQ_PUBLISHER_ATTESTATION_SUITE.to_string(),
                pq_security_bits: 256,
                signer_weight: 9,
                valid_until_height: self.height + self.config.attestation_ttl_blocks,
                attestation_root: commitment("attestation", "sequencer-a-swap-fill-0001"),
            },
        );
        self.low_fee_batch_rebates.insert(
            "rebate-devnet-batch-0001".to_string(),
            LowFeeBatchRebate {
                rebate_id: "rebate-devnet-batch-0001".to_string(),
                batch_root: deterministic_record_root(
                    "LOW-FEE-BATCH",
                    &json!(["evt-nullifier-devnet-0001"]),
                ),
                event_count: 1,
                gross_fee_micro_credits: self.config.base_event_fee_micro_credits,
                rebate_micro_credits: self.config.base_event_fee_micro_credits
                    * self.config.batch_rebate_bps as u128
                    / MAX_BPS as u128,
                cleared_at_height: self.height,
            },
        );
        self.redaction_budgets.insert(
            "redaction-budget-devnet-swap".to_string(),
            RedactionBudget {
                budget_id: "redaction-budget-devnet-swap".to_string(),
                topic_id: "evt-topic-devnet-swap-v1".to_string(),
                topic_leakage_bps: 24,
                payload_redaction_bps: 72,
                remaining_disclosures: 16,
                budget_root: commitment("redaction-budget", "swap-fill-budget"),
            },
        );
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        self.counters = Counters {
            encrypted_topics: self.encrypted_topics.len() as u64,
            event_nullifiers: self.event_nullifiers.len() as u64,
            replay_windows: self.replay_windows.len() as u64,
            callback_fences: self.callback_fences.len() as u64,
            publisher_attestations: self.publisher_attestations.len() as u64,
            duplicate_quarantines: self.duplicate_quarantines.len() as u64,
            low_fee_batch_rebates: self.low_fee_batch_rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            accepted_events: self.counters.accepted_events,
        };
        self.roots = Roots {
            encrypted_topic_root: public_record_root(
                "ENCRYPTED-TOPIC",
                &self
                    .encrypted_topics
                    .values()
                    .map(EncryptedTopic::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_nullifier_root: public_record_root(
                "EVENT-NULLIFIER",
                &self
                    .event_nullifiers
                    .values()
                    .map(EventNullifier::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_window_root: public_record_root(
                "REPLAY-WINDOW",
                &self
                    .replay_windows
                    .values()
                    .map(ReplayWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            callback_fence_root: public_record_root(
                "CALLBACK-FENCE",
                &self
                    .callback_fences
                    .values()
                    .map(CallbackFence::public_record)
                    .collect::<Vec<_>>(),
            ),
            publisher_attestation_root: public_record_root(
                "PUBLISHER-ATTESTATION",
                &self
                    .publisher_attestations
                    .values()
                    .map(PublisherAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            duplicate_quarantine_root: public_record_root(
                "DUPLICATE-QUARANTINE",
                &self
                    .duplicate_quarantines
                    .values()
                    .map(DuplicateQuarantine::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_rebate_root: public_record_root(
                "LOW-FEE-BATCH-REBATE",
                &self
                    .low_fee_batch_rebates
                    .values()
                    .map(LowFeeBatchRebate::public_record)
                    .collect::<Vec<_>>(),
            ),
            redaction_budget_root: public_record_root(
                "REDACTION-BUDGET",
                &self
                    .redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        };
        self.roots.public_record_root =
            deterministic_record_root("PUBLIC-RECORD", &self.public_record_without_state_root());
        self.roots.state_root = self.state_root();
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-EVENT-REPLAY-GUARD:{domain}-ROOT"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-EVENT-REPLAY-GUARD:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-EVENT-REPLAY-GUARD:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-EVENT-REPLAY-GUARD:{domain}:EMPTY"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-EVENT-REPLAY-GUARD:{domain}:COMMITMENT"
        ),
        &[HashPart::Str(label)],
        32,
    )
}

fn duplicate_quarantine(
    existing: &EventNullifier,
    duplicate: &EventNullifier,
    height: u64,
) -> DuplicateQuarantine {
    let evidence = json!({
        "nullifier_id": existing.nullifier_id,
        "original_event_commitment": existing.event_commitment,
        "duplicate_event_commitment": duplicate.event_commitment,
        "height": height
    });
    DuplicateQuarantine {
        quarantine_id: deterministic_record_root("DUPLICATE-QUARANTINE-ID", &evidence),
        nullifier_id: existing.nullifier_id.clone(),
        original_event_commitment: existing.event_commitment.clone(),
        duplicate_event_commitment: duplicate.event_commitment.clone(),
        evidence_root: deterministic_record_root("DUPLICATE-QUARANTINE-EVIDENCE", &evidence),
        quarantined_at_height: height,
    }
}
