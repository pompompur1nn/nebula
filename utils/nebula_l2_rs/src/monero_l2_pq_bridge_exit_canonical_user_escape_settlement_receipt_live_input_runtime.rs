use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptLiveInputRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-settlement-receipt-live-input-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_INPUT_SUITE: &str =
    "canonical-user-escape-settlement-receipt-live-input-fail-closed-v1";
pub const DEFAULT_CURRENT_L2_HEIGHT: u64 = 9_216;
pub const DEFAULT_MAX_FRESHNESS_LAG_BLOCKS: u64 = 96;
pub const DEFAULT_LOW_COST_FEE_BOUND_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MIN_AMOUNT_ATOMIC: u128 = 1_000_000_000;
pub const DEFAULT_MAX_AMOUNT_ATOMIC: u128 = 250_000_000_000;
pub const DEFAULT_MIN_OBSERVER_ATTESTATIONS: u64 = 3;
pub const DEFAULT_LIVE_INPUT_SEQUENCE: u64 = 42;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInputField {
    SettlementReceiptRoot,
    AmountCommitmentRoot,
    FeeBoundRoot,
    FreshnessRoot,
    ObserverAttestationRoot,
}

impl LiveInputField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementReceiptRoot => "settlement_receipt_root",
            Self::AmountCommitmentRoot => "amount_commitment_root",
            Self::FeeBoundRoot => "fee_bound_root",
            Self::FreshnessRoot => "freshness_root",
            Self::ObserverAttestationRoot => "observer_attestation_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessRecordStatus {
    Accepted,
    Stale,
    Rejected,
}

impl HarnessRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
        }
    }

    pub fn admissible(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    MissingReceiptRoot,
    MissingAmountCommitment,
    MissingFeeBound,
    MissingFreshnessRoot,
    AmountBelowMinimum,
    AmountAboveMaximum,
    FeeAboveBound,
    FreshnessTooOld,
    ObserverQuorumMissing,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MissingReceiptRoot => "missing_receipt_root",
            Self::MissingAmountCommitment => "missing_amount_commitment",
            Self::MissingFeeBound => "missing_fee_bound",
            Self::MissingFreshnessRoot => "missing_freshness_root",
            Self::AmountBelowMinimum => "amount_below_minimum",
            Self::AmountAboveMaximum => "amount_above_maximum",
            Self::FeeAboveBound => "fee_above_bound",
            Self::FreshnessTooOld => "freshness_too_old",
            Self::ObserverQuorumMissing => "observer_quorum_missing",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub live_input_suite: String,
    pub current_l2_height: u64,
    pub max_freshness_lag_blocks: u64,
    pub low_cost_fee_bound_atomic: u128,
    pub min_amount_atomic: u128,
    pub max_amount_atomic: u128,
    pub min_observer_attestations: u64,
    pub require_all_live_roots: bool,
    pub fail_closed_on_rejection: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            live_input_suite: LIVE_INPUT_SUITE.to_string(),
            current_l2_height: DEFAULT_CURRENT_L2_HEIGHT,
            max_freshness_lag_blocks: DEFAULT_MAX_FRESHNESS_LAG_BLOCKS,
            low_cost_fee_bound_atomic: DEFAULT_LOW_COST_FEE_BOUND_ATOMIC,
            min_amount_atomic: DEFAULT_MIN_AMOUNT_ATOMIC,
            max_amount_atomic: DEFAULT_MAX_AMOUNT_ATOMIC,
            min_observer_attestations: DEFAULT_MIN_OBSERVER_ATTESTATIONS,
            require_all_live_roots: true,
            fail_closed_on_rejection: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "live_input_suite": self.live_input_suite,
            "current_l2_height": self.current_l2_height,
            "max_freshness_lag_blocks": self.max_freshness_lag_blocks,
            "low_cost_fee_bound_atomic": self.low_cost_fee_bound_atomic.to_string(),
            "min_amount_atomic": self.min_amount_atomic.to_string(),
            "max_amount_atomic": self.max_amount_atomic.to_string(),
            "min_observer_attestations": self.min_observer_attestations,
            "require_all_live_roots": self.require_all_live_roots,
            "fail_closed_on_rejection": self.fail_closed_on_rejection,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedSettlementReceiptInput {
    pub observation_id: String,
    pub receipt_id: String,
    pub settlement_receipt_root: String,
    pub amount_commitment_root: String,
    pub amount_atomic: u128,
    pub fee_bound_root: String,
    pub fee_atomic: u128,
    pub freshness_root: String,
    pub observed_l2_height: u64,
    pub observer_attestation_root: String,
    pub observer_attestation_count: u64,
    pub sequence: u64,
}

impl ObservedSettlementReceiptInput {
    pub fn devnet(config: &Config) -> Self {
        let sequence = DEFAULT_LIVE_INPUT_SEQUENCE;
        let receipt_id = live_hash("receipt", sequence);
        Self {
            observation_id: live_hash("observation", sequence),
            settlement_receipt_root: live_hash("settlement-receipt-root", sequence),
            amount_commitment_root: live_hash("amount-commitment-root", sequence),
            amount_atomic: config.min_amount_atomic.saturating_mul(7),
            fee_bound_root: live_hash("fee-bound-root", sequence),
            fee_atomic: config.low_cost_fee_bound_atomic.saturating_sub(1_000_000),
            freshness_root: live_hash("freshness-root", sequence),
            observed_l2_height: config.current_l2_height.saturating_sub(12),
            observer_attestation_root: live_hash("observer-attestation-root", sequence),
            observer_attestation_count: config.min_observer_attestations,
            receipt_id,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "receipt_id": self.receipt_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "amount_commitment_root": self.amount_commitment_root,
            "amount_atomic": self.amount_atomic.to_string(),
            "fee_bound_root": self.fee_bound_root,
            "fee_atomic": self.fee_atomic.to_string(),
            "freshness_root": self.freshness_root,
            "observed_l2_height": self.observed_l2_height,
            "observer_attestation_root": self.observer_attestation_root,
            "observer_attestation_count": self.observer_attestation_count,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed-settlement-receipt-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalHarnessInputRecord {
    pub record_id: String,
    pub receipt_id: String,
    pub settlement_receipt_root: String,
    pub amount_commitment_root: String,
    pub fee_bound_root: String,
    pub freshness_root: String,
    pub observer_attestation_root: String,
    pub amount_atomic: u128,
    pub fee_atomic: u128,
    pub observed_l2_height: u64,
    pub freshness_lag_blocks: u64,
    pub observer_attestation_count: u64,
    pub status: HarnessRecordStatus,
    pub rejection_reason: RejectionReason,
    pub live_input_root: String,
}

impl CanonicalHarnessInputRecord {
    pub fn from_observed(
        config: &Config,
        input: &ObservedSettlementReceiptInput,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptLiveInputRuntimeResult<Self> {
        let freshness_lag_blocks = config
            .current_l2_height
            .saturating_sub(input.observed_l2_height);
        let rejection_reason = rejection_reason(config, input, freshness_lag_blocks);
        let status = record_status(config, rejection_reason);
        let live_input_root = input.state_root();
        let record_id = canonical_record_id(&input.receipt_id, &live_input_root);

        Ok(Self {
            record_id,
            receipt_id: input.receipt_id.clone(),
            settlement_receipt_root: input.settlement_receipt_root.clone(),
            amount_commitment_root: input.amount_commitment_root.clone(),
            fee_bound_root: input.fee_bound_root.clone(),
            freshness_root: input.freshness_root.clone(),
            observer_attestation_root: input.observer_attestation_root.clone(),
            amount_atomic: input.amount_atomic,
            fee_atomic: input.fee_atomic,
            observed_l2_height: input.observed_l2_height,
            freshness_lag_blocks,
            observer_attestation_count: input.observer_attestation_count,
            status,
            rejection_reason,
            live_input_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "receipt_id": self.receipt_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_bound_root": self.fee_bound_root,
            "freshness_root": self.freshness_root,
            "observer_attestation_root": self.observer_attestation_root,
            "amount_atomic": self.amount_atomic.to_string(),
            "fee_atomic": self.fee_atomic.to_string(),
            "observed_l2_height": self.observed_l2_height,
            "freshness_lag_blocks": self.freshness_lag_blocks,
            "observer_attestation_count": self.observer_attestation_count,
            "status": self.status.as_str(),
            "rejection_reason": self.rejection_reason.as_str(),
            "live_input_root": self.live_input_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("canonical-harness-input-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveInputBinding {
    pub field: LiveInputField,
    pub root: String,
    pub receipt_id: String,
    pub sequence: u64,
}

impl LiveInputBinding {
    pub fn public_record(&self) -> Value {
        json!({
            "field": self.field.as_str(),
            "root": self.root,
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub observed_inputs: u64,
    pub canonical_records: u64,
    pub accepted_records: u64,
    pub rejected_records: u64,
    pub stale_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "observed_inputs": self.observed_inputs,
            "canonical_records": self.canonical_records,
            "accepted_records": self.accepted_records,
            "rejected_records": self.rejected_records,
            "stale_records": self.stale_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub observed_inputs: Vec<ObservedSettlementReceiptInput>,
    pub canonical_records: Vec<CanonicalHarnessInputRecord>,
    pub live_input_bindings: Vec<LiveInputBinding>,
    pub counters: Counters,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let observed_input = ObservedSettlementReceiptInput::devnet(&config);
        let canonical_record =
            match CanonicalHarnessInputRecord::from_observed(&config, &observed_input) {
                Ok(record) => record,
                Err(message) => canonical_error_record(&observed_input, &message),
            };
        let live_input_bindings = bindings_for(&observed_input);
        let counters = counters_for(&[canonical_record.clone()], 1);

        Self {
            config,
            observed_inputs: vec![observed_input],
            canonical_records: vec![canonical_record],
            live_input_bindings,
            counters,
        }
    }

    pub fn ingest_observed_settlement_receipt(
        &mut self,
        input: ObservedSettlementReceiptInput,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptLiveInputRuntimeResult<
        CanonicalHarnessInputRecord,
    > {
        let record = CanonicalHarnessInputRecord::from_observed(&self.config, &input)?;
        self.live_input_bindings.extend(bindings_for(&input));
        self.observed_inputs.push(input);
        self.canonical_records.push(record.clone());
        self.counters = counters_for(&self.canonical_records, self.observed_inputs.len() as u64);
        Ok(record)
    }

    pub fn observed_input_root(&self) -> String {
        merkle_root(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-OBSERVED-INPUTS",
            &self
                .observed_inputs
                .iter()
                .map(ObservedSettlementReceiptInput::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn canonical_record_root(&self) -> String {
        merkle_root(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-CANONICAL-RECORDS",
            &self
                .canonical_records
                .iter()
                .map(CanonicalHarnessInputRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn live_input_binding_root(&self) -> String {
        merkle_root(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-BINDINGS",
            &self
                .live_input_bindings
                .iter()
                .map(LiveInputBinding::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn admissible_record_count(&self) -> u64 {
        self.canonical_records
            .iter()
            .filter(|record| record.status.admissible())
            .count() as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "observed_input_root": self.observed_input_root(),
            "canonical_record_root": self.canonical_record_root(),
            "live_input_binding_root": self.live_input_binding_root(),
            "admissible_record_count": self.admissible_record_count(),
            "observed_inputs": self.observed_inputs.iter().map(ObservedSettlementReceiptInput::public_record).collect::<Vec<_>>(),
            "canonical_records": self.canonical_records.iter().map(CanonicalHarnessInputRecord::public_record).collect::<Vec<_>>(),
            "live_input_bindings": self.live_input_bindings.iter().map(LiveInputBinding::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-INPUT-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.observed_input_root()),
                HashPart::Str(&self.canonical_record_root()),
                HashPart::Str(&self.live_input_binding_root()),
            ],
            32,
        )
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

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn canonical_error_record(
    input: &ObservedSettlementReceiptInput,
    message: &str,
) -> CanonicalHarnessInputRecord {
    CanonicalHarnessInputRecord {
        record_id: live_hash("canonical-record-error", input.sequence),
        receipt_id: input.receipt_id.clone(),
        settlement_receipt_root: input.settlement_receipt_root.clone(),
        amount_commitment_root: input.amount_commitment_root.clone(),
        fee_bound_root: input.fee_bound_root.clone(),
        freshness_root: input.freshness_root.clone(),
        observer_attestation_root: input.observer_attestation_root.clone(),
        amount_atomic: input.amount_atomic,
        fee_atomic: input.fee_atomic,
        observed_l2_height: input.observed_l2_height,
        freshness_lag_blocks: 0,
        observer_attestation_count: input.observer_attestation_count,
        status: HarnessRecordStatus::Rejected,
        rejection_reason: RejectionReason::MissingReceiptRoot,
        live_input_root: domain_hash(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-INPUT-ERROR",
            &[HashPart::Str(message)],
            32,
        ),
    }
}

fn bindings_for(input: &ObservedSettlementReceiptInput) -> Vec<LiveInputBinding> {
    vec![
        live_input_binding(
            LiveInputField::SettlementReceiptRoot,
            &input.settlement_receipt_root,
            input,
        ),
        live_input_binding(
            LiveInputField::AmountCommitmentRoot,
            &input.amount_commitment_root,
            input,
        ),
        live_input_binding(LiveInputField::FeeBoundRoot, &input.fee_bound_root, input),
        live_input_binding(LiveInputField::FreshnessRoot, &input.freshness_root, input),
        live_input_binding(
            LiveInputField::ObserverAttestationRoot,
            &input.observer_attestation_root,
            input,
        ),
    ]
}

fn live_input_binding(
    field: LiveInputField,
    root: &str,
    input: &ObservedSettlementReceiptInput,
) -> LiveInputBinding {
    LiveInputBinding {
        field,
        root: root.to_string(),
        receipt_id: input.receipt_id.clone(),
        sequence: input.sequence,
    }
}

fn counters_for(records: &[CanonicalHarnessInputRecord], observed_inputs: u64) -> Counters {
    let accepted_records = records
        .iter()
        .filter(|record| record.status == HarnessRecordStatus::Accepted)
        .count() as u64;
    let rejected_records = records
        .iter()
        .filter(|record| record.status == HarnessRecordStatus::Rejected)
        .count() as u64;
    let stale_records = records
        .iter()
        .filter(|record| record.status == HarnessRecordStatus::Stale)
        .count() as u64;

    Counters {
        observed_inputs,
        canonical_records: records.len() as u64,
        accepted_records,
        rejected_records,
        stale_records,
    }
}

fn rejection_reason(
    config: &Config,
    input: &ObservedSettlementReceiptInput,
    freshness_lag_blocks: u64,
) -> RejectionReason {
    if input.settlement_receipt_root.is_empty() {
        RejectionReason::MissingReceiptRoot
    } else if input.amount_commitment_root.is_empty() {
        RejectionReason::MissingAmountCommitment
    } else if input.fee_bound_root.is_empty() {
        RejectionReason::MissingFeeBound
    } else if input.freshness_root.is_empty() {
        RejectionReason::MissingFreshnessRoot
    } else if input.amount_atomic < config.min_amount_atomic {
        RejectionReason::AmountBelowMinimum
    } else if input.amount_atomic > config.max_amount_atomic {
        RejectionReason::AmountAboveMaximum
    } else if input.fee_atomic > config.low_cost_fee_bound_atomic {
        RejectionReason::FeeAboveBound
    } else if freshness_lag_blocks > config.max_freshness_lag_blocks {
        RejectionReason::FreshnessTooOld
    } else if input.observer_attestation_count < config.min_observer_attestations {
        RejectionReason::ObserverQuorumMissing
    } else {
        RejectionReason::None
    }
}

fn record_status(config: &Config, rejection_reason: RejectionReason) -> HarnessRecordStatus {
    match rejection_reason {
        RejectionReason::None => HarnessRecordStatus::Accepted,
        RejectionReason::FreshnessTooOld if !config.fail_closed_on_rejection => {
            HarnessRecordStatus::Stale
        }
        _ => HarnessRecordStatus::Rejected,
    }
}

fn canonical_record_id(receipt_id: &str, live_input_root: &str) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-INPUT-CANONICAL-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(live_input_root),
        ],
        32,
    )
}

fn live_hash(label: &str, sequence: u64) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-INPUT-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-INPUT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
