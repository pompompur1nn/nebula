use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptLiveHandlerBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-settlement-receipt-live-handler-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HANDLER_BINDING_SUITE: &str =
    "canonical-user-escape-settlement-receipt-live-handler-binding-fail-closed-v1";
pub const DEFAULT_CURRENT_L2_HEIGHT: u64 = 9_216;
pub const DEFAULT_LIVE_INPUT_SEQUENCE: u64 = 42;
pub const DEFAULT_MIN_HANDLER_ATTESTATIONS: u64 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerKind {
    SettlementReceiptIngester,
    AmountCommitment,
    FeeBound,
    ChallengeDisputeClock,
    WithdrawalClaimLink,
}

impl HandlerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementReceiptIngester => "settlement_receipt_ingester",
            Self::AmountCommitment => "amount_commitment_handler",
            Self::FeeBound => "fee_bound_handler",
            Self::ChallengeDisputeClock => "challenge_dispute_clock_handler",
            Self::WithdrawalClaimLink => "withdrawal_claim_link_handler",
        }
    }

    pub fn live_input_field(self) -> &'static str {
        match self {
            Self::SettlementReceiptIngester => "settlement_receipt_root",
            Self::AmountCommitment => "amount_commitment_root",
            Self::FeeBound => "fee_bound_root",
            Self::ChallengeDisputeClock => "freshness_root",
            Self::WithdrawalClaimLink => "withdrawal_claim_link_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Bound,
    Rejected,
}

impl BindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingRejectionReason {
    None,
    EmptyLiveInputRoot,
    EmptyHandlerObservationRoot,
    HandlerAttestationMissing,
    ReceiptMismatch,
}

impl BindingRejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::EmptyLiveInputRoot => "empty_live_input_root",
            Self::EmptyHandlerObservationRoot => "empty_handler_observation_root",
            Self::HandlerAttestationMissing => "handler_attestation_missing",
            Self::ReceiptMismatch => "receipt_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub handler_binding_suite: String,
    pub current_l2_height: u64,
    pub min_handler_attestations: u64,
    pub require_all_handlers: bool,
    pub fail_closed_on_rejection: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            handler_binding_suite: HANDLER_BINDING_SUITE.to_string(),
            current_l2_height: DEFAULT_CURRENT_L2_HEIGHT,
            min_handler_attestations: DEFAULT_MIN_HANDLER_ATTESTATIONS,
            require_all_handlers: true,
            fail_closed_on_rejection: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "handler_binding_suite": self.handler_binding_suite,
            "current_l2_height": self.current_l2_height,
            "min_handler_attestations": self.min_handler_attestations,
            "require_all_handlers": self.require_all_handlers,
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
pub struct LiveInputRecord {
    pub live_input_id: String,
    pub receipt_id: String,
    pub settlement_receipt_root: String,
    pub amount_commitment_root: String,
    pub fee_bound_root: String,
    pub freshness_root: String,
    pub withdrawal_claim_link_root: String,
    pub sequence: u64,
}

impl LiveInputRecord {
    pub fn devnet() -> Self {
        let sequence = DEFAULT_LIVE_INPUT_SEQUENCE;
        Self {
            live_input_id: seeded_root("live-input", "settlement-receipt-live-input"),
            receipt_id: seeded_root("receipt", "settlement-receipt-devnet-0001"),
            settlement_receipt_root: seeded_root(
                "settlement-receipt-root",
                "handler-bound-settlement-receipt",
            ),
            amount_commitment_root: seeded_root(
                "amount-commitment-root",
                "handler-bound-amount-commitment",
            ),
            fee_bound_root: seeded_root("fee-bound-root", "handler-bound-low-cost-fee"),
            freshness_root: seeded_root("freshness-root", "handler-bound-challenge-clock"),
            withdrawal_claim_link_root: seeded_root(
                "withdrawal-claim-link-root",
                "handler-bound-withdrawal-claim",
            ),
            sequence,
        }
    }

    pub fn root_for(&self, handler_kind: HandlerKind) -> &str {
        match handler_kind {
            HandlerKind::SettlementReceiptIngester => &self.settlement_receipt_root,
            HandlerKind::AmountCommitment => &self.amount_commitment_root,
            HandlerKind::FeeBound => &self.fee_bound_root,
            HandlerKind::ChallengeDisputeClock => &self.freshness_root,
            HandlerKind::WithdrawalClaimLink => &self.withdrawal_claim_link_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "live_input_id": self.live_input_id,
            "receipt_id": self.receipt_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_bound_root": self.fee_bound_root,
            "freshness_root": self.freshness_root,
            "withdrawal_claim_link_root": self.withdrawal_claim_link_root,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerObservation {
    pub observation_id: String,
    pub handler_kind: HandlerKind,
    pub handler_id: String,
    pub receipt_id: String,
    pub handler_observation_root: String,
    pub observed_live_input_root: String,
    pub observed_at_l2_height: u64,
    pub attestation_count: u64,
}

impl HandlerObservation {
    pub fn devnet(
        config: &Config,
        live_input: &LiveInputRecord,
        handler_kind: HandlerKind,
    ) -> Self {
        let observed_live_input_root = live_input.root_for(handler_kind).to_string();
        let handler_id = handler_id(handler_kind);
        let handler_observation_root = handler_observation_root(
            handler_kind,
            &handler_id,
            &live_input.receipt_id,
            &observed_live_input_root,
            config.current_l2_height,
        );
        let observation_id = domain_hash(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-OBSERVATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(handler_kind.as_str()),
                HashPart::Str(&handler_id),
                HashPart::Str(&handler_observation_root),
            ],
            32,
        );

        Self {
            observation_id,
            handler_kind,
            handler_id,
            receipt_id: live_input.receipt_id.clone(),
            handler_observation_root,
            observed_live_input_root,
            observed_at_l2_height: config.current_l2_height,
            attestation_count: config.min_handler_attestations,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "handler_kind": self.handler_kind.as_str(),
            "handler_id": self.handler_id,
            "receipt_id": self.receipt_id,
            "handler_observation_root": self.handler_observation_root,
            "observed_live_input_root": self.observed_live_input_root,
            "observed_at_l2_height": self.observed_at_l2_height,
            "attestation_count": self.attestation_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerBindingRecord {
    pub binding_id: String,
    pub handler_kind: HandlerKind,
    pub live_input_field: String,
    pub receipt_id: String,
    pub live_input_root: String,
    pub handler_observation_root: String,
    pub observation_root: String,
    pub status: BindingStatus,
    pub rejection_reason: BindingRejectionReason,
}

impl HandlerBindingRecord {
    pub fn bind(
        config: &Config,
        live_input: &LiveInputRecord,
        observation: &HandlerObservation,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptLiveHandlerBindingRuntimeResult<Self>
    {
        let live_input_root = live_input.root_for(observation.handler_kind).to_string();
        let rejection_reason = rejection_reason(config, live_input, observation, &live_input_root);
        let status = if rejection_reason == BindingRejectionReason::None {
            BindingStatus::Bound
        } else {
            BindingStatus::Rejected
        };
        let observation_root = observation.state_root();
        let binding_id = binding_id(
            observation.handler_kind,
            &live_input.receipt_id,
            &live_input_root,
            &observation.handler_observation_root,
        );

        Ok(Self {
            binding_id,
            handler_kind: observation.handler_kind,
            live_input_field: observation.handler_kind.live_input_field().to_string(),
            receipt_id: live_input.receipt_id.clone(),
            live_input_root,
            handler_observation_root: observation.handler_observation_root.clone(),
            observation_root,
            status,
            rejection_reason,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "handler_kind": self.handler_kind.as_str(),
            "live_input_field": self.live_input_field,
            "receipt_id": self.receipt_id,
            "live_input_root": self.live_input_root,
            "handler_observation_root": self.handler_observation_root,
            "observation_root": self.observation_root,
            "status": self.status.as_str(),
            "rejection_reason": self.rejection_reason.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_binding_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub live_input_records: u64,
    pub handler_observations: u64,
    pub handler_bindings: u64,
    pub bound_handler_bindings: u64,
    pub rejected_handler_bindings: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "live_input_records": self.live_input_records,
            "handler_observations": self.handler_observations,
            "handler_bindings": self.handler_bindings,
            "bound_handler_bindings": self.bound_handler_bindings,
            "rejected_handler_bindings": self.rejected_handler_bindings,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub live_input_records: Vec<LiveInputRecord>,
    pub handler_observations: Vec<HandlerObservation>,
    pub handler_bindings: Vec<HandlerBindingRecord>,
    pub counters: Counters,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let live_input = LiveInputRecord::devnet();
        let handler_observations = handler_kinds()
            .iter()
            .map(|handler_kind| HandlerObservation::devnet(&config, &live_input, *handler_kind))
            .collect::<Vec<_>>();
        let handler_bindings = handler_observations
            .iter()
            .filter_map(|observation| {
                HandlerBindingRecord::bind(&config, &live_input, observation).ok()
            })
            .collect::<Vec<_>>();
        let counters = counters_for(1, &handler_observations, &handler_bindings);

        Self {
            config,
            live_input_records: vec![live_input],
            handler_observations,
            handler_bindings,
            counters,
        }
    }

    pub fn bind_handler_observation(
        &mut self,
        live_input: LiveInputRecord,
        observation: HandlerObservation,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptLiveHandlerBindingRuntimeResult<
        HandlerBindingRecord,
    > {
        let binding = HandlerBindingRecord::bind(&self.config, &live_input, &observation)?;
        self.live_input_records.push(live_input);
        self.handler_observations.push(observation);
        self.handler_bindings.push(binding.clone());
        self.counters = counters_for(
            self.live_input_records.len() as u64,
            &self.handler_observations,
            &self.handler_bindings,
        );
        Ok(binding)
    }

    pub fn live_input_record_root(&self) -> String {
        merkle_records(
            "live-input-records",
            self.live_input_records
                .iter()
                .map(LiveInputRecord::public_record)
                .collect(),
        )
    }

    pub fn handler_observation_root(&self) -> String {
        merkle_records(
            "handler-observations",
            self.handler_observations
                .iter()
                .map(HandlerObservation::public_record)
                .collect(),
        )
    }

    pub fn handler_binding_root(&self) -> String {
        merkle_records(
            "handler-bindings",
            self.handler_bindings
                .iter()
                .map(HandlerBindingRecord::public_record)
                .collect(),
        )
    }

    pub fn all_required_handlers_bound(&self) -> bool {
        handler_kinds().iter().all(|handler_kind| {
            self.handler_bindings.iter().any(|binding| {
                binding.handler_kind == *handler_kind && binding.status == BindingStatus::Bound
            })
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "live_input_record_root": self.live_input_record_root(),
            "handler_observation_root": self.handler_observation_root(),
            "handler_binding_root": self.handler_binding_root(),
            "all_required_handlers_bound": self.all_required_handlers_bound(),
            "live_input_records": self.live_input_records.iter().map(LiveInputRecord::public_record).collect::<Vec<_>>(),
            "handler_observations": self.handler_observations.iter().map(HandlerObservation::public_record).collect::<Vec<_>>(),
            "handler_bindings": self.handler_bindings.iter().map(HandlerBindingRecord::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.live_input_record_root()),
                HashPart::Str(&self.handler_observation_root()),
                HashPart::Str(&self.handler_binding_root()),
                HashPart::Str(bool_str(self.all_required_handlers_bound())),
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

fn handler_kinds() -> [HandlerKind; 5] {
    [
        HandlerKind::SettlementReceiptIngester,
        HandlerKind::AmountCommitment,
        HandlerKind::FeeBound,
        HandlerKind::ChallengeDisputeClock,
        HandlerKind::WithdrawalClaimLink,
    ]
}

fn rejection_reason(
    config: &Config,
    live_input: &LiveInputRecord,
    observation: &HandlerObservation,
    live_input_root: &str,
) -> BindingRejectionReason {
    if live_input_root.is_empty() {
        BindingRejectionReason::EmptyLiveInputRoot
    } else if observation.handler_observation_root.is_empty() {
        BindingRejectionReason::EmptyHandlerObservationRoot
    } else if observation.attestation_count < config.min_handler_attestations {
        BindingRejectionReason::HandlerAttestationMissing
    } else if observation.receipt_id != live_input.receipt_id {
        BindingRejectionReason::ReceiptMismatch
    } else {
        BindingRejectionReason::None
    }
}

fn counters_for(
    live_input_records: u64,
    observations: &[HandlerObservation],
    bindings: &[HandlerBindingRecord],
) -> Counters {
    let bound_handler_bindings = bindings
        .iter()
        .filter(|binding| binding.status == BindingStatus::Bound)
        .count() as u64;
    let rejected_handler_bindings = bindings
        .iter()
        .filter(|binding| binding.status == BindingStatus::Rejected)
        .count() as u64;

    Counters {
        live_input_records,
        handler_observations: observations.len() as u64,
        handler_bindings: bindings.len() as u64,
        bound_handler_bindings,
        rejected_handler_bindings,
    }
}

fn handler_id(handler_kind: HandlerKind) -> String {
    seeded_root("handler-id", handler_kind.as_str())
}

fn handler_observation_root(
    handler_kind: HandlerKind,
    handler_id: &str,
    receipt_id: &str,
    live_input_root: &str,
    observed_at_l2_height: u64,
) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-HANDLER-OBSERVATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(handler_kind.as_str()),
            HashPart::Str(handler_id),
            HashPart::Str(receipt_id),
            HashPart::Str(live_input_root),
            HashPart::U64(observed_at_l2_height),
        ],
        32,
    )
}

fn binding_id(
    handler_kind: HandlerKind,
    receipt_id: &str,
    live_input_root: &str,
    handler_observation_root: &str,
) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(handler_kind.as_str()),
            HashPart::Str(receipt_id),
            HashPart::Str(live_input_root),
            HashPart::Str(handler_observation_root),
        ],
        32,
    )
}

fn seeded_root(label: &str, seed: &str) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn merkle_records(label: &str, records: Vec<Value>) -> String {
    merkle_root(
        "USER-ESCAPE-SETTLEMENT-RECEIPT-LIVE-HANDLER-BINDING-MERKLE",
        &records
            .iter()
            .map(|record| record_root(label, record))
            .collect::<Vec<_>>(),
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
