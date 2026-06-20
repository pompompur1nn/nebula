use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialGapLiveHandlerBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-gap-live-handler-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub live_input_lane: String,
    pub handler_lane: String,
    pub escape_package_id: String,
    pub required_observation_count: u64,
    pub required_handler_count: u64,
    pub binding_mode: String,
    pub release_policy: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            live_input_lane: "canonical_user_escape_adversarial_gap".to_string(),
            handler_lane: "canonical_user_escape_handler_observations".to_string(),
            escape_package_id: "devnet-user-escape-package-canonical-pq-v1".to_string(),
            required_observation_count: 9,
            required_handler_count: 9,
            binding_mode: "live_input_to_handler_observation".to_string(),
            release_policy: "fail_closed_until_handler_resolution".to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "live_input_lane": self.live_input_lane,
            "handler_lane": self.handler_lane,
            "escape_package_id": self.escape_package_id,
            "required_observation_count": self.required_observation_count,
            "required_handler_count": self.required_handler_count,
            "binding_mode": self.binding_mode,
            "release_policy": self.release_policy,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialObservationKind {
    Reorg,
    WatcherCollusion,
    SequencerHalt,
    ForgedReceipt,
    StalePqEpoch,
    LiquidityExhaustion,
    MetadataLeak,
    ChallengeBypass,
    WalletRecoveryMismatch,
}

impl AdversarialObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::SequencerHalt => "sequencer_halt",
            Self::ForgedReceipt => "forged_receipt",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeak => "metadata_leak",
            Self::ChallengeBypass => "challenge_bypass",
            Self::WalletRecoveryMismatch => "wallet_recovery_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerDecision {
    Hold,
    Quarantine,
    Reject,
}

impl HandlerDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveInputRecord {
    pub record_id: String,
    pub kind: AdversarialObservationKind,
    pub live_input_observation_id: String,
    pub live_input_evidence_root: String,
    pub signal: String,
    pub observed_value: String,
    pub expected_value: String,
}

impl LiveInputRecord {
    pub fn new(
        kind: AdversarialObservationKind,
        signal: &str,
        observed_value: &str,
        expected_value: &str,
    ) -> Self {
        let seed_record = json!({
            "kind": kind.as_str(),
            "signal": signal,
            "observed_value": observed_value,
            "expected_value": expected_value,
        });
        let live_input_evidence_root = record_root("live_input_record_evidence", &seed_record);
        let live_input_observation_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-LIVE-INPUT-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&live_input_evidence_root),
            ],
            16,
        );
        let record_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-LIVE-RECORD-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&live_input_observation_id),
                HashPart::Str(&live_input_evidence_root),
            ],
            16,
        );

        Self {
            record_id,
            kind,
            live_input_observation_id,
            live_input_evidence_root,
            signal: signal.to_string(),
            observed_value: observed_value.to_string(),
            expected_value: expected_value.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "kind": self.kind.as_str(),
            "live_input_observation_id": self.live_input_observation_id,
            "live_input_evidence_root": self.live_input_evidence_root,
            "signal": self.signal,
            "observed_value": self.observed_value,
            "expected_value": self.expected_value,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_record", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerObservation {
    pub handler_observation_id: String,
    pub kind: AdversarialObservationKind,
    pub handler_id: String,
    pub handler_stage: String,
    pub observed_at_ms: u64,
    pub handler_signal: String,
    pub handler_value: String,
    pub mitigation: String,
    pub decision: HandlerDecision,
    pub transcript_root: String,
}

impl HandlerObservation {
    pub fn new(
        kind: AdversarialObservationKind,
        handler_id: &str,
        handler_stage: &str,
        observed_at_ms: u64,
        handler_signal: &str,
        handler_value: &str,
        mitigation: &str,
        decision: HandlerDecision,
    ) -> Self {
        let transcript_record = json!({
            "kind": kind.as_str(),
            "handler_id": handler_id,
            "handler_stage": handler_stage,
            "observed_at_ms": observed_at_ms,
            "handler_signal": handler_signal,
            "handler_value": handler_value,
            "mitigation": mitigation,
            "decision": decision.as_str(),
        });
        let transcript_root = record_root("handler_observation_transcript", &transcript_record);
        let handler_observation_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-OBSERVATION-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(handler_id),
                HashPart::Str(&transcript_root),
            ],
            16,
        );

        Self {
            handler_observation_id,
            kind,
            handler_id: handler_id.to_string(),
            handler_stage: handler_stage.to_string(),
            observed_at_ms,
            handler_signal: handler_signal.to_string(),
            handler_value: handler_value.to_string(),
            mitigation: mitigation.to_string(),
            decision,
            transcript_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handler_observation_id": self.handler_observation_id,
            "kind": self.kind.as_str(),
            "handler_id": self.handler_id,
            "handler_stage": self.handler_stage,
            "observed_at_ms": self.observed_at_ms,
            "handler_signal": self.handler_signal,
            "handler_value": self.handler_value,
            "mitigation": self.mitigation,
            "decision": self.decision.as_str(),
            "transcript_root": self.transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRecord {
    pub binding_id: String,
    pub kind: AdversarialObservationKind,
    pub live_input_root: String,
    pub handler_observation_root: String,
    pub binding_digest: String,
    pub handler_decision: HandlerDecision,
    pub release_allowed: bool,
}

impl BindingRecord {
    pub fn bind(live_input: &LiveInputRecord, handler_observation: &HandlerObservation) -> Self {
        let live_input_root = live_input.state_root();
        let handler_observation_root = handler_observation.state_root();
        let binding_digest = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-DIGEST",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(live_input.kind.as_str()),
                HashPart::Str(&live_input_root),
                HashPart::Str(&handler_observation_root),
                HashPart::Str(handler_observation.decision.as_str()),
                HashPart::Str("release_allowed=false"),
            ],
            32,
        );
        let binding_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&live_input.live_input_observation_id),
                HashPart::Str(&handler_observation.handler_observation_id),
                HashPart::Str(&binding_digest),
            ],
            16,
        );

        Self {
            binding_id,
            kind: live_input.kind,
            live_input_root,
            handler_observation_root,
            binding_digest,
            handler_decision: handler_observation.decision,
            release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "kind": self.kind.as_str(),
            "live_input_root": self.live_input_root,
            "handler_observation_root": self.handler_observation_root,
            "binding_digest": self.binding_digest,
            "handler_decision": self.handler_decision.as_str(),
            "release_allowed": self.release_allowed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub live_inputs: Vec<LiveInputRecord>,
    pub handler_observations: Vec<HandlerObservation>,
    pub bindings: Vec<BindingRecord>,
    pub live_input_root: String,
    pub handler_observation_root: String,
    pub binding_root: String,
}

impl State {
    pub fn new(
        config: Config,
        live_inputs: Vec<LiveInputRecord>,
        handler_observations: Vec<HandlerObservation>,
    ) -> Self {
        let bindings = live_inputs
            .iter()
            .zip(handler_observations.iter())
            .map(|(live_input, handler_observation)| {
                BindingRecord::bind(live_input, handler_observation)
            })
            .collect::<Vec<_>>();
        let live_input_records = live_inputs
            .iter()
            .map(LiveInputRecord::public_record)
            .collect::<Vec<_>>();
        let handler_observation_records = handler_observations
            .iter()
            .map(HandlerObservation::public_record)
            .collect::<Vec<_>>();
        let binding_records = bindings
            .iter()
            .map(BindingRecord::public_record)
            .collect::<Vec<_>>();

        Self {
            config,
            live_inputs,
            handler_observations,
            bindings,
            live_input_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-LIVE-INPUTS",
                &live_input_records,
            ),
            handler_observation_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-HANDLER-OBSERVATIONS",
                &handler_observation_records,
            ),
            binding_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-RECORDS",
                &binding_records,
            ),
        }
    }

    pub fn devnet() -> Self {
        Self::new(
            Config::default(),
            devnet_live_inputs(),
            devnet_handler_observations(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "live_input_root": self.live_input_root,
            "handler_observation_root": self.handler_observation_root,
            "binding_root": self.binding_root,
            "live_inputs": self
                .live_inputs
                .iter()
                .map(LiveInputRecord::public_record)
                .collect::<Vec<_>>(),
            "handler_observations": self
                .handler_observations
                .iter()
                .map(HandlerObservation::public_record)
                .collect::<Vec<_>>(),
            "bindings": self
                .bindings
                .iter()
                .map(BindingRecord::public_record)
                .collect::<Vec<_>>(),
            "release_allowed": self.release_allowed(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let state_record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config.state_root(),
            "live_input_root": self.live_input_root,
            "handler_observation_root": self.handler_observation_root,
            "binding_root": self.binding_root,
            "release_allowed": self.release_allowed(),
        });

        domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&state_record),
            ],
            32,
        )
    }

    pub fn release_allowed(&self) -> bool {
        self.bindings.iter().all(|binding| binding.release_allowed)
    }

    pub fn validate(&self) -> Result<String> {
        if self.live_inputs.len() != self.config.required_observation_count as usize {
            return Err("handler binding runtime must bind exactly nine live inputs".to_string());
        }
        if self.handler_observations.len() != self.config.required_handler_count as usize {
            return Err(
                "handler binding runtime must bind exactly nine handler observations".to_string(),
            );
        }
        if self.bindings.len() != self.live_inputs.len() {
            return Err("handler binding records must match live input records".to_string());
        }
        if self.release_allowed() {
            return Err(
                "handler binding runtime must fail closed for adversarial gaps".to_string(),
            );
        }
        if self
            .live_inputs
            .iter()
            .zip(self.handler_observations.iter())
            .any(|(live_input, handler_observation)| live_input.kind != handler_observation.kind)
        {
            return Err(
                "handler binding runtime cannot bind mismatched adversarial kinds".to_string(),
            );
        }

        Ok(self.state_root())
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

fn devnet_live_inputs() -> Vec<LiveInputRecord> {
    vec![
        LiveInputRecord::new(
            AdversarialObservationKind::Reorg,
            "monero_anchor_replaced",
            "anchor_depth=7,replacement_depth=2",
            "anchor_depth>=18,current_canonical_anchor",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::WatcherCollusion,
            "watcher_entropy_overlap",
            "shared_cluster=4,independent_signers=1",
            "shared_cluster<=1,independent_signers>=5",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::SequencerHalt,
            "sequencer_no_progress",
            "halt_ms=180000,last_l2_height=4260191",
            "halt_ms<=90000,l2_height_advances",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::ForgedReceipt,
            "receipt_transcript_mismatch",
            "receipt_root=forged,signer_set_root=unknown",
            "receipt_root=canonical,signer_set_root=devnet_quorum",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::StalePqEpoch,
            "pq_epoch_expired",
            "package_epoch=41,current_epoch=42,grace_blocks=0",
            "package_epoch=42,current_epoch=42,grace_blocks=0",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::LiquidityExhaustion,
            "reserve_bps_below_escape_amount",
            "available_bps=7200,requested_bps=10000",
            "available_bps>=10000,requested_bps=10000",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::MetadataLeak,
            "wallet_metadata_over_budget",
            "metadata_fields=6,linkable_fields=4",
            "metadata_fields<=3,linkable_fields=0",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::ChallengeBypass,
            "challenge_window_short_circuit",
            "elapsed_blocks=92,release_attempted=true",
            "elapsed_blocks>=720,release_attempted_after_window",
        ),
        LiveInputRecord::new(
            AdversarialObservationKind::WalletRecoveryMismatch,
            "recovery_commitment_mismatch",
            "wallet_recovery_root=alternate,owner_commitment=canonical",
            "wallet_recovery_root=canonical,owner_commitment=canonical",
        ),
    ]
}

fn devnet_handler_observations() -> Vec<HandlerObservation> {
    vec![
        HandlerObservation::new(
            AdversarialObservationKind::Reorg,
            "canonicality_handler",
            "monero_finality_check",
            1_719_000_001_250,
            "handler_anchor_depth_below_policy",
            "replacement_depth=2,required_depth=18",
            "hold_until_canonical_depth_restored",
            HandlerDecision::Hold,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::WatcherCollusion,
            "watcher_quorum_handler",
            "signer_entropy_check",
            1_719_000_002_250,
            "handler_watcher_cluster_detected",
            "shared_cluster=4,max_shared_cluster=1",
            "quarantine_watcher_cluster",
            HandlerDecision::Quarantine,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::SequencerHalt,
            "sequencer_liveness_handler",
            "escape_timeout_check",
            1_719_000_003_250,
            "handler_l2_height_stalled",
            "halt_ms=180000,max_halt_ms=90000",
            "force_exit_timeout_path",
            HandlerDecision::Hold,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::ForgedReceipt,
            "receipt_transcript_handler",
            "receipt_domain_check",
            1_719_000_004_250,
            "handler_receipt_root_mismatch",
            "receipt_root=forged,signer_set_root=unknown",
            "reject_receipt_transcript",
            HandlerDecision::Reject,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::StalePqEpoch,
            "pq_epoch_handler",
            "epoch_freshness_check",
            1_719_000_005_250,
            "handler_epoch_expired",
            "package_epoch=41,current_epoch=42",
            "require_fresh_pq_epoch",
            HandlerDecision::Reject,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::LiquidityExhaustion,
            "reserve_sufficiency_handler",
            "liquidity_release_check",
            1_719_000_006_250,
            "handler_reserve_below_request",
            "available_bps=7200,requested_bps=10000",
            "hold_for_reserve_replenishment",
            HandlerDecision::Hold,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::MetadataLeak,
            "privacy_budget_handler",
            "metadata_budget_check",
            1_719_000_007_250,
            "handler_metadata_over_budget",
            "metadata_fields=6,max_metadata_fields=3",
            "redact_and_reblind_package",
            HandlerDecision::Quarantine,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::ChallengeBypass,
            "challenge_window_handler",
            "release_window_check",
            1_719_000_008_250,
            "handler_challenge_window_short",
            "elapsed_blocks=92,required_blocks=720",
            "enforce_full_challenge_window",
            HandlerDecision::Reject,
        ),
        HandlerObservation::new(
            AdversarialObservationKind::WalletRecoveryMismatch,
            "wallet_recovery_handler",
            "recovery_commitment_check",
            1_719_000_009_250,
            "handler_recovery_commitment_mismatch",
            "wallet_recovery_root=alternate,owner_commitment=canonical",
            "require_recovery_commitment_reconciliation",
            HandlerDecision::Reject,
        ),
    ]
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BINDING-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
