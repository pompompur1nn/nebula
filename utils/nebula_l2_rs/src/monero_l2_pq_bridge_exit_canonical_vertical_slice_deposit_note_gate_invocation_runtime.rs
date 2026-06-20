use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceDepositNoteGateInvocationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-gate-invocation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DEVNET_L2_NETWORK: &str = "nebula-devnet";
const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
const DEVNET_ASSET_ID: &str = "wxmr-devnet";
const DEVNET_L2_REFERENCE_HEIGHT: u64 = 4_260_000;
const DEVNET_MONERO_REFERENCE_HEIGHT: u64 = 3_540_000;
const DEVNET_REQUIRED_MONERO_CONFIRMATIONS: u64 = 20;
const DEVNET_WATCHER_QUORUM_BPS: u64 = 6_700;
const DEVNET_MIN_PRIVACY_SET_SIZE: u64 = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub required_monero_confirmations: u64,
    pub watcher_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub runtime_execution_deferred: bool,
    pub cargo_execution_deferred: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            l2_reference_height: DEVNET_L2_REFERENCE_HEIGHT,
            monero_reference_height: DEVNET_MONERO_REFERENCE_HEIGHT,
            required_monero_confirmations: DEVNET_REQUIRED_MONERO_CONFIRMATIONS,
            watcher_quorum_bps: DEVNET_WATCHER_QUORUM_BPS,
            min_privacy_set_size: DEVNET_MIN_PRIVACY_SET_SIZE,
            runtime_execution_deferred: true,
            cargo_execution_deferred: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "required_monero_confirmations": self.required_monero_confirmations,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "runtime_execution_deferred": yes_no(self.runtime_execution_deferred),
            "cargo_execution_deferred": yes_no(self.cargo_execution_deferred),
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pass,
    ReleaseBlocked,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ReleaseBlocked => "release_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationInputs {
    pub monero_lock_evidence_root: String,
    pub watcher_pq_quorum_root: String,
    pub deposit_finality_root: String,
    pub note_commitment_root: String,
    pub privacy_redaction_root: String,
    pub expected_output_root: String,
    pub pass_reason_root: String,
    pub fail_reason_root: String,
}

impl InvocationInputs {
    pub fn devnet(config: &Config) -> Self {
        let monero_lock_evidence_root = input_root(
            "monero_lock_evidence",
            config,
            json!({
                "txid": "devnet-monero-lock-0001",
                "output_index": 0,
                "amount_commitment": commitment("amount", "deposit-lock"),
                "recipient_l2_account": commitment("recipient", "private-note-gate"),
                "monero_height": config.monero_reference_height,
            }),
        );
        let watcher_pq_quorum_root = input_root(
            "watcher_pq_quorum",
            config,
            json!({
                "quorum_bps": config.watcher_quorum_bps,
                "scheme": "ml-dsa-87-ed25519-hybrid-devnet",
                "transcript_root": commitment("pq-transcript", "deposit-note-invocation"),
                "watcher_set_root": commitment("watcher-set", "canonical-devnet"),
            }),
        );
        let deposit_finality_root = input_root(
            "deposit_finality",
            config,
            json!({
                "observed_confirmations": config.required_monero_confirmations,
                "required_confirmations": config.required_monero_confirmations,
                "finality_anchor": commitment("finality-anchor", "monero-lock"),
            }),
        );
        let note_commitment_root = input_root(
            "note_commitment",
            config,
            json!({
                "asset_id": config.asset_id,
                "note_commitment": commitment("note", "minted-private-deposit"),
                "nullifier_domain": commitment("nullifier-domain", "forced-exit"),
                "spend_authority": "redacted",
            }),
        );
        let privacy_redaction_root = input_root(
            "privacy_redaction",
            config,
            json!({
                "min_privacy_set_size": config.min_privacy_set_size,
                "public_fields": ["asset_id", "finality_class", "quorum_class"],
                "redacted_fields": ["sender", "amount", "wallet_view_material", "spend_authority"],
            }),
        );
        let expected_output_root = input_root(
            "expected_output",
            config,
            json!({
                "gate_status": GateStatus::Pass.as_str(),
                "private_note_event": "deposit_note_mint_ready",
                "release_state": "blocked_until_runtime_and_cargo_execution",
                "next_vertical_slice": "private_note_spend_or_forced_exit_claim",
            }),
        );
        let pass_reason_root = reason_root(
            "pass",
            config,
            &[
                "monero_lock_has_required_confirmations",
                "watcher_pq_quorum_meets_threshold",
                "deposit_finality_matches_note_commitment",
                "privacy_redaction_limits_public_surface",
            ],
        );
        let fail_reason_root = reason_root(
            "fail",
            config,
            &[
                "monero_lock_missing_or_immature",
                "watcher_pq_quorum_below_threshold",
                "deposit_finality_mismatch",
                "note_commitment_or_redaction_root_mismatch",
            ],
        );

        Self {
            monero_lock_evidence_root,
            watcher_pq_quorum_root,
            deposit_finality_root,
            note_commitment_root,
            privacy_redaction_root,
            expected_output_root,
            pass_reason_root,
            fail_reason_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "monero_lock_evidence_root": self.monero_lock_evidence_root,
            "watcher_pq_quorum_root": self.watcher_pq_quorum_root,
            "deposit_finality_root": self.deposit_finality_root,
            "note_commitment_root": self.note_commitment_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "expected_output_root": self.expected_output_root,
            "pass_reason_root": self.pass_reason_root,
            "fail_reason_root": self.fail_reason_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("invocation_inputs", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBlockingState {
    pub production_release_allowed: bool,
    pub runtime_execution_deferred: bool,
    pub cargo_execution_deferred: bool,
    pub blocking_root: String,
    pub blocking_reasons: Vec<String>,
}

impl ReleaseBlockingState {
    pub fn devnet(config: &Config) -> Self {
        let blocking_reasons = vec![
            "runtime invocation is recorded deterministically but live execution is deferred"
                .to_string(),
            "cargo verification is deferred by workflow for this vertical slice".to_string(),
            "production release waits for executed runtime evidence".to_string(),
        ];
        let blocking_records = blocking_reasons
            .iter()
            .enumerate()
            .map(|(index, reason)| {
                json!({
                    "index": index as u64,
                    "reason": reason,
                    "l2_reference_height": config.l2_reference_height,
                    "monero_reference_height": config.monero_reference_height,
                })
            })
            .collect::<Vec<_>>();

        Self {
            production_release_allowed: false,
            runtime_execution_deferred: config.runtime_execution_deferred,
            cargo_execution_deferred: config.cargo_execution_deferred,
            blocking_root: merkle_root(
                "monero-l2-pq-bridge-exit-deposit-note-gate-release-blockers",
                &blocking_records,
            ),
            blocking_reasons,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "production_release_allowed": yes_no(self.production_release_allowed),
            "runtime_execution_deferred": yes_no(self.runtime_execution_deferred),
            "cargo_execution_deferred": yes_no(self.cargo_execution_deferred),
            "blocking_root": self.blocking_root,
            "blocking_reasons": self.blocking_reasons,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_blocking_state", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationDecision {
    pub status: GateStatus,
    pub invocation_id: String,
    pub input_root: String,
    pub release_blocking_root: String,
    pub output_root: String,
}

impl InvocationDecision {
    pub fn from_parts(inputs: &InvocationInputs, release: &ReleaseBlockingState) -> Self {
        let input_root = inputs.state_root();
        let release_blocking_root = release.state_root();
        let output_root = domain_hash(
            "monero-l2-pq-bridge-exit-deposit-note-gate-output",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(GateStatus::ReleaseBlocked.as_str()),
                HashPart::Str(&inputs.expected_output_root),
                HashPart::Str(&release_blocking_root),
            ],
            32,
        );
        let invocation_id = domain_hash(
            "monero-l2-pq-bridge-exit-deposit-note-gate-invocation-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&input_root),
                HashPart::Str(&output_root),
            ],
            16,
        );

        Self {
            status: GateStatus::ReleaseBlocked,
            invocation_id,
            input_root,
            release_blocking_root,
            output_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "invocation_id": self.invocation_id,
            "input_root": self.input_root,
            "release_blocking_root": self.release_blocking_root,
            "output_root": self.output_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("invocation_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub inputs: InvocationInputs,
    pub release_blocking_state: ReleaseBlockingState,
    pub decision: InvocationDecision,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let inputs = InvocationInputs::devnet(&config);
        let release_blocking_state = ReleaseBlockingState::devnet(&config);
        let decision = InvocationDecision::from_parts(&inputs, &release_blocking_state);

        Self {
            config,
            inputs,
            release_blocking_state,
            decision,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "inputs": self.inputs.public_record(),
            "release_blocking_state": self.release_blocking_state.public_record(),
            "decision": self.decision.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-gate-invocation-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.inputs.state_root()),
                HashPart::Str(&self.release_blocking_state.state_root()),
                HashPart::Str(&self.decision.state_root()),
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

fn input_root(kind: &str, config: &Config, payload: Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-deposit-note-gate-input",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Json(&payload),
        ],
        32,
    )
}

fn reason_root(kind: &str, config: &Config, reasons: &[&str]) -> String {
    let leaves = reasons
        .iter()
        .enumerate()
        .map(|(index, reason)| {
            json!({
                "kind": kind,
                "index": index as u64,
                "reason": reason,
                "chain_id": config.chain_id,
                "protocol_version": PROTOCOL_VERSION,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-deposit-note-gate-{kind}-reasons"),
        &leaves,
    )
}

fn commitment(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-deposit-note-gate-commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-deposit-note-gate-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
