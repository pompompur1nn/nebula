use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeWalletRunbookHandlerBoundExecutionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-wallet-runbook-handler-bound-execution-runtime-v1";

const PROTOCOL_LABEL: &str =
    "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_handler_bound_execution";
const HASH_SUITE: &str = "SHAKE256-domain-separated-merkle-json-v1";
const RUNBOOK_ID: &str = "devnet-user-escape-package-001";
const WALLET_ID: &str = "escape-wallet-alpha";
const EXECUTION_LANE_ID: &str = "handler-bound-forced-exit-lane-001";
const HANDLER_BINDING_SET_ID: &str = "devnet-user-escape-handler-binding-set-001";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub monero_network: String,
    pub runbook_id: String,
    pub wallet_id: String,
    pub execution_lane_id: String,
    pub handler_binding_set_id: String,
    pub replay_schema_version: u64,
    pub min_wallet_scan_confirmations: u64,
    pub min_crosscheck_confirmations: u64,
    pub release_finality_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            hash_suite: HASH_SUITE.to_string(),
            monero_network: "monero-devnet".to_string(),
            runbook_id: RUNBOOK_ID.to_string(),
            wallet_id: WALLET_ID.to_string(),
            execution_lane_id: EXECUTION_LANE_ID.to_string(),
            handler_binding_set_id: HANDLER_BINDING_SET_ID.to_string(),
            replay_schema_version: 1,
            min_wallet_scan_confirmations: 12,
            min_crosscheck_confirmations: 3,
            release_finality_blocks: 10,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "monero_network": self.monero_network,
            "runbook_id": self.runbook_id,
            "wallet_id": self.wallet_id,
            "execution_lane_id": self.execution_lane_id,
            "handler_binding_set_id": self.handler_binding_set_id,
            "replay_schema_version": self.replay_schema_version,
            "min_wallet_scan_confirmations": self.min_wallet_scan_confirmations,
            "min_crosscheck_confirmations": self.min_crosscheck_confirmations,
            "release_finality_blocks": self.release_finality_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        runtime_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerBoundRoots {
    pub wallet_scan_root: String,
    pub proof_collection_root: String,
    pub forced_exit_claim_root: String,
    pub pq_authorization_root: String,
    pub live_feed_crosscheck_root: String,
    pub release_verifier_replay_root: String,
    pub local_recovery_replay_root: String,
    pub handler_binding_root: String,
}

impl HandlerBoundRoots {
    pub fn devnet() -> Self {
        let wallet_scan_root = seed_root("wallet-scan", "escape-wallet-alpha-height-17680");
        let proof_collection_root = seed_root("proof-collection", "exit-proof-package-v1");
        let forced_exit_claim_root = seed_root("forced-exit-claim", "claim-package-v1");
        let pq_authorization_root = seed_root("pq-authorization", "wallet-pq-auth-v1");
        let live_feed_crosscheck_root =
            seed_root("live-feed-crosscheck", "operator-watchtower-local-match");
        let release_verifier_replay_root =
            seed_root("release-verifier-replay", "release-receipt-proof-v1");
        let local_recovery_replay_root =
            seed_root("local-recovery-replay", "wallet-local-replay-v1");
        let handler_binding_root = runtime_hash(
            "HANDLER-BOUND-ROOTS",
            &[HashPart::Json(&json!({
                "wallet_scan_root": wallet_scan_root,
                "proof_collection_root": proof_collection_root,
                "forced_exit_claim_root": forced_exit_claim_root,
                "pq_authorization_root": pq_authorization_root,
                "live_feed_crosscheck_root": live_feed_crosscheck_root,
                "release_verifier_replay_root": release_verifier_replay_root,
                "local_recovery_replay_root": local_recovery_replay_root,
            }))],
        );

        Self {
            wallet_scan_root,
            proof_collection_root,
            forced_exit_claim_root,
            pq_authorization_root,
            live_feed_crosscheck_root,
            release_verifier_replay_root,
            local_recovery_replay_root,
            handler_binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_scan_root": self.wallet_scan_root,
            "proof_collection_root": self.proof_collection_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "pq_authorization_root": self.pq_authorization_root,
            "live_feed_crosscheck_root": self.live_feed_crosscheck_root,
            "release_verifier_replay_root": self.release_verifier_replay_root,
            "local_recovery_replay_root": self.local_recovery_replay_root,
            "handler_binding_root": self.handler_binding_root,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash(
            "HANDLER-BOUND-ROOT-SET",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Replayable,
    WaitingForConfirmations,
    ReleaseVerified,
}

impl ExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replayable => "replayable",
            Self::WaitingForConfirmations => "waiting_for_confirmations",
            Self::ReleaseVerified => "release_verified",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletExecutionStep {
    pub ordinal: u64,
    pub step_id: String,
    pub handler_stage: String,
    pub replay_command: String,
    pub input_roots: Vec<String>,
    pub output_root: String,
    pub execution_status: ExecutionStatus,
}

impl WalletExecutionStep {
    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "step_id": self.step_id,
            "handler_stage": self.handler_stage,
            "replay_command": self.replay_command,
            "input_roots": self.input_roots,
            "output_root": self.output_root,
            "execution_status": self.execution_status.as_str(),
            "step_root": self.step_root_without_self_reference(),
        })
    }

    fn public_record_without_step_root(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "step_id": self.step_id,
            "handler_stage": self.handler_stage,
            "replay_command": self.replay_command,
            "input_roots": self.input_roots,
            "output_root": self.output_root,
            "execution_status": self.execution_status.as_str(),
        })
    }

    pub fn step_root_without_self_reference(&self) -> String {
        runtime_hash(
            "WALLET-EXECUTION-STEP",
            &[HashPart::Json(&self.public_record_without_step_root())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub handler_bound_root_set_root: String,
    pub execution_step_root: String,
    pub execution_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "handler_bound_root_set_root": self.handler_bound_root_set_root,
            "execution_step_root": self.execution_step_root,
            "execution_record_root": self.execution_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub handler_bound_roots: HandlerBoundRoots,
    pub execution_steps: Vec<WalletExecutionStep>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let handler_bound_roots = HandlerBoundRoots::devnet();
        let execution_steps = execution_steps(&handler_bound_roots);

        Self {
            config,
            handler_bound_roots,
            execution_steps,
        }
    }

    pub fn roots(&self) -> Roots {
        let step_roots = self
            .execution_steps
            .iter()
            .map(|step| Value::String(step.step_root_without_self_reference()))
            .collect::<Vec<_>>();
        let execution_step_root = merkle_root("HANDLER-BOUND-WALLET-EXECUTION-STEPS", &step_roots);
        let execution_record_root = runtime_hash(
            "EXECUTION-RECORD",
            &[
                HashPart::Str(&self.config.execution_lane_id),
                HashPart::Json(&self.handler_bound_roots.public_record()),
                HashPart::Str(&execution_step_root),
            ],
        );

        Roots {
            config_root: self.config.config_root(),
            handler_bound_root_set_root: self.handler_bound_roots.root(),
            execution_step_root,
            execution_record_root,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "config": self.config.public_record(),
            "handler_bound_roots": self.handler_bound_roots.public_record(),
            "roots": self.roots().public_record(),
            "execution_steps": self.execution_steps
                .iter()
                .map(WalletExecutionStep::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "STATE",
            &[HashPart::Json(&self.public_record_without_root())],
        )
    }

    pub fn replay_execution_steps(&self) -> Vec<Value> {
        self.execution_steps
            .iter()
            .map(WalletExecutionStep::public_record)
            .collect()
    }

    pub fn verify_handler_binding_root(&self, handler_binding_root: &str) -> Result<String> {
        if handler_binding_root == self.handler_bound_roots.handler_binding_root {
            Ok(self.roots().execution_record_root)
        } else {
            Err("handler_binding_root_mismatch".to_string())
        }
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

fn execution_steps(roots: &HandlerBoundRoots) -> Vec<WalletExecutionStep> {
    vec![
        wallet_step(
            1,
            "wallet_scan_export",
            "wallet_scan_export",
            "wallet escape replay scan --bind-handler-root",
            vec![roots.handler_binding_root.clone()],
            roots.wallet_scan_root.clone(),
            ExecutionStatus::Replayable,
        ),
        wallet_step(
            2,
            "proof_collection_import",
            "proof_collection",
            "wallet escape replay collect-proofs --from-scan-root",
            vec![roots.wallet_scan_root.clone()],
            roots.proof_collection_root.clone(),
            ExecutionStatus::Replayable,
        ),
        wallet_step(
            3,
            "forced_exit_claim_build",
            "forced_exit_claim_builder",
            "wallet escape replay build-claim --from-proof-root",
            vec![
                roots.wallet_scan_root.clone(),
                roots.proof_collection_root.clone(),
            ],
            roots.forced_exit_claim_root.clone(),
            ExecutionStatus::Replayable,
        ),
        wallet_step(
            4,
            "pq_authorization_export",
            "pq_authorization_exporter",
            "wallet escape replay authorize-pq --from-claim-root",
            vec![roots.forced_exit_claim_root.clone()],
            roots.pq_authorization_root.clone(),
            ExecutionStatus::Replayable,
        ),
        wallet_step(
            5,
            "live_feed_crosscheck",
            "live_feed_crosscheck",
            "wallet escape replay crosscheck-live-feed --require-quorum",
            vec![
                roots.forced_exit_claim_root.clone(),
                roots.pq_authorization_root.clone(),
            ],
            roots.live_feed_crosscheck_root.clone(),
            ExecutionStatus::WaitingForConfirmations,
        ),
        wallet_step(
            6,
            "release_verifier_replay",
            "release_verifier_replay",
            "wallet escape replay verify-release --from-crosscheck-root",
            vec![
                roots.live_feed_crosscheck_root.clone(),
                roots.forced_exit_claim_root.clone(),
            ],
            roots.release_verifier_replay_root.clone(),
            ExecutionStatus::ReleaseVerified,
        ),
        wallet_step(
            7,
            "local_recovery_replay",
            "local_recovery_replay",
            "wallet escape replay local-recovery --seal-execution-record",
            vec![
                roots.release_verifier_replay_root.clone(),
                roots.pq_authorization_root.clone(),
            ],
            roots.local_recovery_replay_root.clone(),
            ExecutionStatus::ReleaseVerified,
        ),
    ]
}

fn wallet_step(
    ordinal: u64,
    step_id: &str,
    handler_stage: &str,
    replay_command: &str,
    input_roots: Vec<String>,
    output_root: String,
    execution_status: ExecutionStatus,
) -> WalletExecutionStep {
    WalletExecutionStep {
        ordinal,
        step_id: step_id.to_string(),
        handler_stage: handler_stage.to_string(),
        replay_command: replay_command.to_string(),
        input_roots,
        output_root,
        execution_status,
    }
}

fn seed_root(label: &str, value: &str) -> String {
    runtime_hash("SEED", &[HashPart::Str(label), HashPart::Str(value)])
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let part_record = parts.iter().map(hash_part_record).collect::<Vec<_>>();

    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_LABEL),
            HashPart::Str(
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(&json!(part_record)),
        ],
        32,
    )
}

fn hash_part_record(part: &HashPart<'_>) -> Value {
    match part {
        HashPart::Bytes(value) => json!({
            "kind": "bytes",
            "value": hex::encode(value),
        }),
        HashPart::Str(value) => json!({
            "kind": "str",
            "value": value,
        }),
        HashPart::U64(value) => json!({
            "kind": "u64",
            "value": value,
        }),
        HashPart::Int(value) => json!({
            "kind": "int",
            "value": value.to_string(),
        }),
        HashPart::Json(value) => json!({
            "kind": "json",
            "value": value,
        }),
    }
}
