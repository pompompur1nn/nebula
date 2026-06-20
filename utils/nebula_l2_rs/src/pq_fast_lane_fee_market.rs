use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqFastLaneFeeMarketResult<T> = Result<T, String>;

pub const PQ_FAST_LANE_FEE_MARKET_PROTOCOL_VERSION: &str = "nebula-pq-fast-lane-fee-market-v1";
pub const PROTOCOL_VERSION: &str = PQ_FAST_LANE_FEE_MARKET_PROTOCOL_VERSION;
pub const PQ_FAST_LANE_FEE_MARKET_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_FAST_LANE_FEE_MARKET_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-128f-fast-lane-auth-v1";
pub const PQ_FAST_LANE_FEE_MARKET_SEALED_INTENT_SUITE: &str =
    "ML-KEM-1024+threshold-private-intent-seal-v1";
pub const DEFAULT_TARGET_BATCH_MS: u64 = 180;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_MAX_BATCH_WEIGHT: u64 = 2_500_000;
pub const DEFAULT_MAX_INTENTS_PER_BATCH: usize = 512;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 80;
pub const DEFAULT_MAX_FEE_MICRO_UNITS: u64 = 1_200;
pub const DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 220;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 150_000_000;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 48;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    PrivateContractCall,
    ConfidentialTokenTransfer,
    ConfidentialTokenMint,
    PrivateDefiSwap,
    MoneroExit,
    BridgeExit,
    WalletRecovery,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::ConfidentialTokenMint => "confidential_token_mint",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::MoneroExit => "monero_exit",
            Self::BridgeExit => "bridge_exit",
            Self::WalletRecovery => "wallet_recovery",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::MoneroExit => 1_000,
            Self::BridgeExit => 940,
            Self::WalletRecovery => 860,
            Self::PrivateDefiSwap => 780,
            Self::PrivateContractCall => 700,
            Self::ConfidentialTokenMint => 620,
            Self::ConfidentialTokenTransfer => 560,
        }
    }

    pub fn default_lane(self) -> FastLaneClass {
        match self {
            Self::PrivateContractCall => FastLaneClass::PrivateContracts,
            Self::ConfidentialTokenTransfer | Self::ConfidentialTokenMint => {
                FastLaneClass::ConfidentialTokens
            }
            Self::PrivateDefiSwap => FastLaneClass::PrivateDefi,
            Self::MoneroExit | Self::BridgeExit => FastLaneClass::PrivateExit,
            Self::WalletRecovery => FastLaneClass::Recovery,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneClass {
    PrivateContracts,
    ConfidentialTokens,
    PrivateDefi,
    PrivateExit,
    Recovery,
}

impl FastLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContracts => "private_contracts",
            Self::ConfidentialTokens => "confidential_tokens",
            Self::PrivateDefi => "private_defi",
            Self::PrivateExit => "private_exit",
            Self::Recovery => "recovery",
        }
    }

    pub fn ordering_rank(self) -> u64 {
        match self {
            Self::PrivateExit => 0,
            Self::Recovery => 1,
            Self::PrivateDefi => 2,
            Self::PrivateContracts => 3,
            Self::ConfidentialTokens => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Admitted,
    Deferred,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Deferred => "deferred",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Selected,
    Sealed,
    Settled,
    Disputed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub chain_id: String,
    pub target_batch_ms: u64,
    pub intent_ttl_blocks: u64,
    pub max_batch_weight: u64,
    pub max_intents_per_batch: usize,
    pub base_fee_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub low_fee_cap_micro_units: u64,
    pub sponsor_budget_micro_units: u64,
    pub min_privacy_set: u64,
    pub require_pq_authorization: bool,
    pub require_payload_roots_only: bool,
    pub enable_low_fee_sponsorship: bool,
}

impl Config {
    pub fn devnet() -> Self {
        let mut config = Self {
            config_id: String::new(),
            chain_id: CHAIN_ID.to_string(),
            target_batch_ms: DEFAULT_TARGET_BATCH_MS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            max_batch_weight: DEFAULT_MAX_BATCH_WEIGHT,
            max_intents_per_batch: DEFAULT_MAX_INTENTS_PER_BATCH,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_fee_micro_units: DEFAULT_MAX_FEE_MICRO_UNITS,
            low_fee_cap_micro_units: DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            sponsor_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            require_pq_authorization: true,
            require_payload_roots_only: true,
            enable_low_fee_sponsorship: true,
        };
        config.config_id = pq_fast_lane_fee_market_payload_root(
            "PQ-FAST-LANE-FEE-MARKET-CONFIG",
            &config.public_record_without_id(),
        );
        config
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "config_id".to_string(),
                Value::String(self.config_id.clone()),
            );
        }
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.chain_id,
            "target_batch_ms": self.target_batch_ms,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "max_batch_weight": self.max_batch_weight,
            "max_intents_per_batch": self.max_intents_per_batch,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "min_privacy_set": self.min_privacy_set,
            "require_pq_authorization": self.require_pq_authorization,
            "require_payload_roots_only": self.require_payload_roots_only,
            "enable_low_fee_sponsorship": self.enable_low_fee_sponsorship,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSubmission {
    pub kind: IntentKind,
    pub payload_root: String,
    pub nullifier_root: String,
    pub account_commitment: String,
    pub max_fee_micro_units: u64,
    pub estimated_weight: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub sponsor_hint: Option<String>,
    pub deadline_block: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneIntent {
    pub intent_id: String,
    pub kind: IntentKind,
    pub lane: FastLaneClass,
    pub status: IntentStatus,
    pub payload_root: String,
    pub nullifier_root: String,
    pub account_commitment: String,
    pub max_fee_micro_units: u64,
    pub charged_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub estimated_weight: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub sponsor_hint: Option<String>,
    pub admitted_block: u64,
    pub deadline_block: u64,
    pub batch_id: Option<String>,
}

impl FastLaneIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "payload_root": self.payload_root,
            "nullifier_root": self.nullifier_root,
            "account_commitment": self.account_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "estimated_weight": self.estimated_weight,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "sponsor_hint": self.sponsor_hint,
            "admitted_block": self.admitted_block,
            "deadline_block": self.deadline_block,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub selected_block: u64,
    pub target_settlement_block: u64,
    pub lane_mix: BTreeMap<String, u64>,
    pub intent_ids: Vec<String>,
    pub intent_root: String,
    pub total_weight: u64,
    pub total_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub privacy_floor_met: bool,
    pub pq_aggregate_authorization_root: String,
    pub settlement_root: Option<String>,
}

impl FastLaneBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "selected_block": self.selected_block,
            "target_settlement_block": self.target_settlement_block,
            "lane_mix": self.lane_mix,
            "intent_ids": self.intent_ids,
            "intent_root": self.intent_root,
            "total_weight": self.total_weight,
            "total_fee_micro_units": self.total_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "privacy_floor_met": self.privacy_floor_met,
            "pq_aggregate_authorization_root": self.pq_aggregate_authorization_root,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub submitted_intents: u64,
    pub admitted_intents: u64,
    pub deferred_intents: u64,
    pub rejected_intents: u64,
    pub selected_batches: u64,
    pub settled_batches: u64,
    pub sponsored_fee_micro_units: u64,
    pub collected_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "submitted_intents": self.submitted_intents,
            "admitted_intents": self.admitted_intents,
            "deferred_intents": self.deferred_intents,
            "rejected_intents": self.rejected_intents,
            "selected_batches": self.selected_batches,
            "settled_batches": self.settled_batches,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "collected_fee_micro_units": self.collected_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_block: u64,
    pub sponsor_budget_remaining_micro_units: u64,
    pub intents: BTreeMap<String, FastLaneIntent>,
    pub pending_queue: BTreeSet<String>,
    pub batches: BTreeMap<String, FastLaneBatch>,
    pub counters: Counters,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self {
            sponsor_budget_remaining_micro_units: config.sponsor_budget_micro_units,
            config,
            current_block: 1,
            intents: BTreeMap::new(),
            pending_queue: BTreeSet::new(),
            batches: BTreeMap::new(),
            counters: Counters::default(),
        }
    }

    pub fn submit_intent(
        &mut self,
        submission: IntentSubmission,
        observed_block: u64,
    ) -> PqFastLaneFeeMarketResult<FastLaneIntent> {
        self.current_block = self.current_block.max(observed_block);
        self.counters.submitted_intents = self.counters.submitted_intents.saturating_add(1);
        self.validate_submission(&submission, observed_block)?;

        let charged_fee = self.quote_fee_micro_units(&submission);
        let sponsored_fee = self.sponsor_amount(charged_fee, &submission);
        let status = if submission.privacy_set_size >= self.config.min_privacy_set {
            IntentStatus::Admitted
        } else {
            IntentStatus::Deferred
        };
        let intent_id = pq_fast_lane_fee_market_payload_root(
            "PQ-FAST-LANE-FEE-MARKET-INTENT-ID",
            &json!({
                "kind": submission.kind.as_str(),
                "payload_root": submission.payload_root,
                "nullifier_root": submission.nullifier_root,
                "account_commitment": submission.account_commitment,
                "pq_authorization_root": submission.pq_authorization_root,
                "observed_block": observed_block,
                "sequence": self.counters.submitted_intents,
            }),
        );
        if self.intents.contains_key(&intent_id) {
            return Err(format!("duplicate fast lane intent {intent_id}"));
        }

        let intent = FastLaneIntent {
            intent_id: intent_id.clone(),
            kind: submission.kind,
            lane: submission.kind.default_lane(),
            status,
            payload_root: submission.payload_root,
            nullifier_root: submission.nullifier_root,
            account_commitment: submission.account_commitment,
            max_fee_micro_units: submission.max_fee_micro_units,
            charged_fee_micro_units: charged_fee.saturating_sub(sponsored_fee),
            sponsored_fee_micro_units: sponsored_fee,
            estimated_weight: submission.estimated_weight,
            privacy_set_size: submission.privacy_set_size,
            pq_authorization_root: submission.pq_authorization_root,
            sponsor_hint: submission.sponsor_hint,
            admitted_block: observed_block,
            deadline_block: submission.deadline_block,
            batch_id: None,
        };

        if matches!(intent.status, IntentStatus::Admitted) {
            self.counters.admitted_intents = self.counters.admitted_intents.saturating_add(1);
            self.pending_queue.insert(intent_id.clone());
        } else {
            self.counters.deferred_intents = self.counters.deferred_intents.saturating_add(1);
        }
        self.sponsor_budget_remaining_micro_units = self
            .sponsor_budget_remaining_micro_units
            .saturating_sub(intent.sponsored_fee_micro_units);
        self.counters.sponsored_fee_micro_units = self
            .counters
            .sponsored_fee_micro_units
            .saturating_add(intent.sponsored_fee_micro_units);
        self.intents.insert(intent_id, intent.clone());
        Ok(intent)
    }

    pub fn select_batch(
        &mut self,
        builder_id: impl Into<String>,
        observed_block: u64,
    ) -> PqFastLaneFeeMarketResult<FastLaneBatch> {
        self.current_block = self.current_block.max(observed_block);
        let builder_id = builder_id.into();
        if builder_id.trim().is_empty() {
            return Err("builder id must not be empty".to_string());
        }

        let mut candidates = self
            .pending_queue
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .filter(|intent| {
                intent.status == IntentStatus::Admitted && intent.deadline_block >= observed_block
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by_key(|intent| {
            (
                intent.lane.ordering_rank(),
                u64::MAX.saturating_sub(intent.kind.priority_weight()),
                intent.charged_fee_micro_units,
                intent.admitted_block,
                intent.intent_id.clone(),
            )
        });

        let mut selected = Vec::new();
        let mut total_weight = 0_u64;
        for intent in candidates {
            if selected.len() >= self.config.max_intents_per_batch {
                break;
            }
            let next_weight = total_weight.saturating_add(intent.estimated_weight);
            if next_weight > self.config.max_batch_weight && !selected.is_empty() {
                continue;
            }
            total_weight = next_weight;
            selected.push(intent);
        }
        if selected.is_empty() {
            return Err("no admissible PQ fast lane intents available for batching".to_string());
        }

        let intent_ids = selected
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        let intent_records = selected
            .iter()
            .map(FastLaneIntent::public_record)
            .collect::<Vec<_>>();
        let intent_root = merkle_root("PQ-FAST-LANE-FEE-MARKET-BATCH-INTENTS", &intent_records);
        let pq_auth_records = selected
            .iter()
            .map(|intent| Value::String(intent.pq_authorization_root.clone()))
            .collect::<Vec<_>>();
        let pq_aggregate_authorization_root =
            merkle_root("PQ-FAST-LANE-FEE-MARKET-BATCH-PQ-AUTH", &pq_auth_records);
        let mut lane_mix = BTreeMap::new();
        for intent in &selected {
            *lane_mix
                .entry(intent.lane.as_str().to_string())
                .or_insert(0) += 1;
        }
        let total_fee_micro_units = selected
            .iter()
            .map(|intent| intent.charged_fee_micro_units)
            .sum::<u64>();
        let sponsored_fee_micro_units = selected
            .iter()
            .map(|intent| intent.sponsored_fee_micro_units)
            .sum::<u64>();
        let privacy_floor_met = selected
            .iter()
            .map(|intent| intent.privacy_set_size)
            .min()
            .unwrap_or_default()
            >= self.config.min_privacy_set;
        let batch_id = pq_fast_lane_fee_market_payload_root(
            "PQ-FAST-LANE-FEE-MARKET-BATCH-ID",
            &json!({
                "builder_id": builder_id,
                "observed_block": observed_block,
                "intent_root": intent_root,
                "sequence": self.counters.selected_batches.saturating_add(1),
            }),
        );
        let batch = FastLaneBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Selected,
            selected_block: observed_block,
            target_settlement_block: observed_block.saturating_add(1),
            lane_mix,
            intent_ids: intent_ids.clone(),
            intent_root,
            total_weight,
            total_fee_micro_units,
            sponsored_fee_micro_units,
            privacy_floor_met,
            pq_aggregate_authorization_root,
            settlement_root: None,
        };

        for intent_id in intent_ids {
            self.pending_queue.remove(&intent_id);
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Batched;
                intent.batch_id = Some(batch_id.clone());
            }
        }
        self.counters.selected_batches = self.counters.selected_batches.saturating_add(1);
        self.batches.insert(batch_id, batch.clone());
        Ok(batch)
    }

    pub fn settle_batch(
        &mut self,
        batch_id: impl AsRef<str>,
        settlement_payload_root: impl Into<String>,
        observed_block: u64,
    ) -> PqFastLaneFeeMarketResult<FastLaneBatch> {
        self.current_block = self.current_block.max(observed_block);
        let batch_id = batch_id.as_ref();
        let settlement_payload_root = settlement_payload_root.into();
        ensure_root_like(&settlement_payload_root, "settlement payload root")?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown PQ fast lane batch {batch_id}"))?;
        if batch.status == BatchStatus::Settled {
            return Err(format!("batch {batch_id} is already settled"));
        }

        let settlement_root = pq_fast_lane_fee_market_payload_root(
            "PQ-FAST-LANE-FEE-MARKET-SETTLEMENT",
            &json!({
                "batch_id": batch_id,
                "settlement_payload_root": settlement_payload_root,
                "observed_block": observed_block,
                "intent_root": batch.intent_root,
            }),
        );
        batch.status = BatchStatus::Settled;
        batch.settlement_root = Some(settlement_root);
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
            }
        }
        self.counters.settled_batches = self.counters.settled_batches.saturating_add(1);
        self.counters.collected_fee_micro_units = self
            .counters
            .collected_fee_micro_units
            .saturating_add(batch.total_fee_micro_units);
        Ok(batch.clone())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        pq_fast_lane_fee_market_state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": PQ_FAST_LANE_FEE_MARKET_HASH_SUITE,
            "pq_auth_suite": PQ_FAST_LANE_FEE_MARKET_PQ_AUTH_SUITE,
            "sealed_intent_suite": PQ_FAST_LANE_FEE_MARKET_SEALED_INTENT_SUITE,
            "config": self.config.public_record(),
            "current_block": self.current_block,
            "sponsor_budget_remaining_micro_units": self.sponsor_budget_remaining_micro_units,
            "counters": self.counters.public_record(),
            "pending_queue": self.pending_queue.iter().cloned().collect::<Vec<_>>(),
            "intents": self.intents.values().map(FastLaneIntent::public_record).collect::<Vec<_>>(),
            "batches": self.batches.values().map(FastLaneBatch::public_record).collect::<Vec<_>>(),
        })
    }

    fn validate_submission(
        &mut self,
        submission: &IntentSubmission,
        observed_block: u64,
    ) -> PqFastLaneFeeMarketResult<()> {
        if submission.deadline_block <= observed_block {
            self.counters.rejected_intents = self.counters.rejected_intents.saturating_add(1);
            return Err("intent deadline must be after observed block".to_string());
        }
        if submission.deadline_block > observed_block.saturating_add(self.config.intent_ttl_blocks)
        {
            self.counters.rejected_intents = self.counters.rejected_intents.saturating_add(1);
            return Err("intent deadline exceeds configured TTL".to_string());
        }
        ensure_root_like(&submission.payload_root, "payload root")?;
        ensure_root_like(&submission.nullifier_root, "nullifier root")?;
        ensure_root_like(&submission.account_commitment, "account commitment")?;
        if self.config.require_pq_authorization {
            ensure_root_like(&submission.pq_authorization_root, "PQ authorization root")?;
        }
        if submission.estimated_weight == 0 {
            return Err("estimated weight must be non-zero".to_string());
        }
        if submission.max_fee_micro_units > self.config.max_fee_micro_units {
            return Err("intent max fee exceeds market cap".to_string());
        }
        Ok(())
    }

    fn quote_fee_micro_units(&self, submission: &IntentSubmission) -> u64 {
        let weight_fee = submission
            .estimated_weight
            .saturating_mul(self.config.base_fee_micro_units)
            .saturating_add(999)
            / 1_000;
        weight_fee
            .saturating_add(submission.kind.priority_weight() / 10)
            .min(submission.max_fee_micro_units)
            .min(self.config.max_fee_micro_units)
    }

    fn sponsor_amount(&self, charged_fee: u64, submission: &IntentSubmission) -> u64 {
        if !self.config.enable_low_fee_sponsorship || submission.sponsor_hint.is_none() {
            return 0;
        }
        let target_discount = charged_fee.saturating_sub(self.config.low_fee_cap_micro_units);
        target_discount.min(self.sponsor_budget_remaining_micro_units)
    }
}

pub fn pq_fast_lane_fee_market_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn pq_fast_lane_fee_market_state_root_from_record(record: &Value) -> String {
    pq_fast_lane_fee_market_payload_root("PQ-FAST-LANE-FEE-MARKET-STATE", record)
}

fn ensure_root_like(value: &str, label: &str) -> PqFastLaneFeeMarketResult<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}
