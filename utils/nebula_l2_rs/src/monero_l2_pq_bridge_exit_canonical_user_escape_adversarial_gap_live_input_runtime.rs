use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialGapLiveInputRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-gap-live-input-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub live_input_lane: String,
    pub escape_package_id: String,
    pub min_watcher_quorum: u64,
    pub max_colluding_watchers: u64,
    pub min_monero_confirmations: u64,
    pub max_sequencer_halt_ms: u64,
    pub pq_epoch_grace_blocks: u64,
    pub min_liquidity_bps: u64,
    pub max_metadata_fields: u64,
    pub challenge_window_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            live_input_lane: "canonical_user_escape_adversarial_gap".to_string(),
            escape_package_id: "devnet-user-escape-package-canonical-pq-v1".to_string(),
            min_watcher_quorum: 5,
            max_colluding_watchers: 1,
            min_monero_confirmations: 18,
            max_sequencer_halt_ms: 90_000,
            pq_epoch_grace_blocks: 0,
            min_liquidity_bps: 10_000,
            max_metadata_fields: 3,
            challenge_window_blocks: 720,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "live_input_lane": self.live_input_lane,
            "escape_package_id": self.escape_package_id,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_colluding_watchers": self.max_colluding_watchers,
            "min_monero_confirmations": self.min_monero_confirmations,
            "max_sequencer_halt_ms": self.max_sequencer_halt_ms,
            "pq_epoch_grace_blocks": self.pq_epoch_grace_blocks,
            "min_liquidity_bps": self.min_liquidity_bps,
            "max_metadata_fields": self.max_metadata_fields,
            "challenge_window_blocks": self.challenge_window_blocks,
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
pub enum ObservationSeverity {
    Hold,
    Quarantine,
    Reject,
}

impl ObservationSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveInputObservation {
    pub observation_id: String,
    pub kind: AdversarialObservationKind,
    pub severity: ObservationSeverity,
    pub observed_at_ms: u64,
    pub monero_height: u64,
    pub l2_height: u64,
    pub watcher_quorum: u64,
    pub signal: String,
    pub observed_value: String,
    pub expected_value: String,
    pub evidence_root: String,
    pub capture_digest: String,
}

impl LiveInputObservation {
    pub fn new(
        kind: AdversarialObservationKind,
        severity: ObservationSeverity,
        observed_at_ms: u64,
        monero_height: u64,
        l2_height: u64,
        watcher_quorum: u64,
        signal: &str,
        observed_value: &str,
        expected_value: &str,
    ) -> Self {
        let capture_digest = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-CAPTURE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::U64(observed_at_ms),
                HashPart::U64(monero_height),
                HashPart::U64(l2_height),
                HashPart::U64(watcher_quorum),
                HashPart::Str(signal),
                HashPart::Str(observed_value),
                HashPart::Str(expected_value),
            ],
            32,
        );
        let evidence_record = json!({
            "kind": kind.as_str(),
            "severity": severity.as_str(),
            "observed_at_ms": observed_at_ms,
            "monero_height": monero_height,
            "l2_height": l2_height,
            "watcher_quorum": watcher_quorum,
            "signal": signal,
            "observed_value": observed_value,
            "expected_value": expected_value,
            "capture_digest": capture_digest,
        });
        let evidence_root = record_root("live_input_evidence", &evidence_record);
        let observation_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-OBSERVATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&evidence_root),
            ],
            16,
        );

        Self {
            observation_id,
            kind,
            severity,
            observed_at_ms,
            monero_height,
            l2_height,
            watcher_quorum,
            signal: signal.to_string(),
            observed_value: observed_value.to_string(),
            expected_value: expected_value.to_string(),
            evidence_root,
            capture_digest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "observed_at_ms": self.observed_at_ms,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "watcher_quorum": self.watcher_quorum,
            "signal": self.signal,
            "observed_value": self.observed_value,
            "expected_value": self.expected_value,
            "evidence_root": self.evidence_root,
            "capture_digest": self.capture_digest,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapAssessment {
    pub assessment_id: String,
    pub kind: AdversarialObservationKind,
    pub observation_root: String,
    pub fail_closed_action: String,
    pub release_allowed: bool,
    pub operator_action: String,
}

impl GapAssessment {
    pub fn from_observation(observation: &LiveInputObservation) -> Self {
        let fail_closed_action = match observation.kind {
            AdversarialObservationKind::Reorg => "hold_until_canonical_depth_restored",
            AdversarialObservationKind::WatcherCollusion => "quarantine_watcher_cluster",
            AdversarialObservationKind::SequencerHalt => "force_exit_timeout_path",
            AdversarialObservationKind::ForgedReceipt => "reject_receipt_transcript",
            AdversarialObservationKind::StalePqEpoch => "require_fresh_pq_epoch",
            AdversarialObservationKind::LiquidityExhaustion => "hold_for_reserve_replenishment",
            AdversarialObservationKind::MetadataLeak => "redact_and_reblind_package",
            AdversarialObservationKind::ChallengeBypass => "enforce_full_challenge_window",
            AdversarialObservationKind::WalletRecoveryMismatch => {
                "require_recovery_commitment_reconciliation"
            }
        }
        .to_string();
        let operator_action = match observation.severity {
            ObservationSeverity::Hold => "keep_escape_package_queued",
            ObservationSeverity::Quarantine => "isolate_live_input_lane",
            ObservationSeverity::Reject => "block_release_and_emit_adversarial_receipt",
        }
        .to_string();
        let observation_record = observation.public_record();
        let observation_root = record_root("live_input_observation", &observation_record);
        let assessment_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-ASSESSMENT-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(observation.kind.as_str()),
                HashPart::Str(&observation_root),
                HashPart::Str(&fail_closed_action),
                HashPart::Str("release_allowed=false"),
            ],
            16,
        );

        Self {
            assessment_id,
            kind: observation.kind,
            observation_root,
            fail_closed_action,
            release_allowed: false,
            operator_action,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "assessment_id": self.assessment_id,
            "kind": self.kind.as_str(),
            "observation_root": self.observation_root,
            "fail_closed_action": self.fail_closed_action,
            "release_allowed": self.release_allowed,
            "operator_action": self.operator_action,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub observations: Vec<LiveInputObservation>,
    pub assessments: Vec<GapAssessment>,
    pub observation_root: String,
    pub assessment_root: String,
}

impl State {
    pub fn new(config: Config, observations: Vec<LiveInputObservation>) -> Self {
        let assessments = observations
            .iter()
            .map(GapAssessment::from_observation)
            .collect::<Vec<_>>();
        let observation_records = observations
            .iter()
            .map(LiveInputObservation::public_record)
            .collect::<Vec<_>>();
        let assessment_records = assessments
            .iter()
            .map(GapAssessment::public_record)
            .collect::<Vec<_>>();

        Self {
            config,
            observations,
            assessments,
            observation_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-OBSERVATIONS",
                &observation_records,
            ),
            assessment_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-ASSESSMENTS",
                &assessment_records,
            ),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let observations = devnet_observations();

        Self::new(config, observations)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "observation_root": self.observation_root,
            "assessment_root": self.assessment_root,
            "observations": self
                .observations
                .iter()
                .map(LiveInputObservation::public_record)
                .collect::<Vec<_>>(),
            "assessments": self
                .assessments
                .iter()
                .map(GapAssessment::public_record)
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
            "observation_root": self.observation_root,
            "assessment_root": self.assessment_root,
            "release_allowed": self.release_allowed(),
        });

        domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&state_record),
            ],
            32,
        )
    }

    pub fn release_allowed(&self) -> bool {
        self.assessments
            .iter()
            .all(|assessment| assessment.release_allowed)
    }

    pub fn validate(&self) -> Result<String> {
        if self.observations.len() != 9 {
            return Err(
                "adversarial gap live input lane must capture exactly nine observations"
                    .to_string(),
            );
        }
        if self.assessments.len() != self.observations.len() {
            return Err(
                "adversarial gap live input assessments must match observations".to_string(),
            );
        }
        if self.release_allowed() {
            return Err("adversarial gap live input lane must fail closed".to_string());
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

fn devnet_observations() -> Vec<LiveInputObservation> {
    vec![
        LiveInputObservation::new(
            AdversarialObservationKind::Reorg,
            ObservationSeverity::Hold,
            1_719_000_001_000,
            3_530_190,
            4_260_190,
            5,
            "monero_anchor_replaced",
            "anchor_depth=7,replacement_depth=2",
            "anchor_depth>=18,current_canonical_anchor",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::WatcherCollusion,
            ObservationSeverity::Quarantine,
            1_719_000_002_000,
            3_530_191,
            4_260_191,
            5,
            "watcher_entropy_overlap",
            "shared_cluster=4,independent_signers=1",
            "shared_cluster<=1,independent_signers>=5",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::SequencerHalt,
            ObservationSeverity::Hold,
            1_719_000_003_000,
            3_530_192,
            4_260_191,
            5,
            "sequencer_no_progress",
            "halt_ms=180000,last_l2_height=4260191",
            "halt_ms<=90000,l2_height_advances",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::ForgedReceipt,
            ObservationSeverity::Reject,
            1_719_000_004_000,
            3_530_193,
            4_260_192,
            5,
            "receipt_transcript_mismatch",
            "receipt_root=forged,signer_set_root=unknown",
            "receipt_root=canonical,signer_set_root=devnet_quorum",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::StalePqEpoch,
            ObservationSeverity::Reject,
            1_719_000_005_000,
            3_530_194,
            4_260_193,
            5,
            "pq_epoch_expired",
            "package_epoch=41,current_epoch=42,grace_blocks=0",
            "package_epoch=42,current_epoch=42,grace_blocks=0",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::LiquidityExhaustion,
            ObservationSeverity::Hold,
            1_719_000_006_000,
            3_530_195,
            4_260_194,
            5,
            "reserve_bps_below_escape_amount",
            "available_bps=7200,requested_bps=10000",
            "available_bps>=10000,requested_bps=10000",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::MetadataLeak,
            ObservationSeverity::Quarantine,
            1_719_000_007_000,
            3_530_196,
            4_260_195,
            5,
            "wallet_metadata_over_budget",
            "metadata_fields=6,linkable_fields=4",
            "metadata_fields<=3,linkable_fields=0",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::ChallengeBypass,
            ObservationSeverity::Reject,
            1_719_000_008_000,
            3_530_197,
            4_260_196,
            5,
            "challenge_window_short_circuit",
            "elapsed_blocks=92,release_attempted=true",
            "elapsed_blocks>=720,release_attempted_after_window",
        ),
        LiveInputObservation::new(
            AdversarialObservationKind::WalletRecoveryMismatch,
            ObservationSeverity::Reject,
            1_719_000_009_000,
            3_530_198,
            4_260_197,
            5,
            "recovery_commitment_mismatch",
            "wallet_recovery_root=alternate,owner_commitment=canonical",
            "wallet_recovery_root=canonical,owner_commitment=canonical",
        ),
    ]
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-LIVE-INPUT-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
