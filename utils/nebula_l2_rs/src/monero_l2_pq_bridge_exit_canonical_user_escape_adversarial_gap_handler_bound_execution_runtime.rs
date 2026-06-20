use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialGapHandlerBoundExecutionRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-gap-handler-bound-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub lane_id: String,
    pub handler_binding_lane: String,
    pub escape_package_id: String,
    pub execution_mode: String,
    pub decision_policy: String,
    pub required_gap_root_count: u64,
    pub reject_on_critical_gap: u64,
    pub hold_on_recoverable_gap: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lane_id: "canonical_user_escape_handler_bound_execution".to_string(),
            handler_binding_lane: "canonical_user_escape_adversarial_gap_handler_binding"
                .to_string(),
            escape_package_id: "devnet-user-escape-package-canonical-pq-v1".to_string(),
            execution_mode: "deterministic_forced_exit_lane".to_string(),
            decision_policy: "reject_critical_hold_recoverable_fail_closed".to_string(),
            required_gap_root_count: 9,
            reject_on_critical_gap: 1,
            hold_on_recoverable_gap: 1,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "handler_binding_lane": self.handler_binding_lane,
            "escape_package_id": self.escape_package_id,
            "execution_mode": self.execution_mode,
            "decision_policy": self.decision_policy,
            "required_gap_root_count": self.required_gap_root_count,
            "reject_on_critical_gap": self.reject_on_critical_gap,
            "hold_on_recoverable_gap": self.hold_on_recoverable_gap,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    Reorg,
    WatcherCollusion,
    SequencerHalt,
    Forgery,
    Pq,
    Liquidity,
    Metadata,
    Bypass,
    WalletMismatch,
}

impl GapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::SequencerHalt => "sequencer_halt",
            Self::Forgery => "forgery",
            Self::Pq => "pq",
            Self::Liquidity => "liquidity",
            Self::Metadata => "metadata",
            Self::Bypass => "bypass",
            Self::WalletMismatch => "wallet_mismatch",
        }
    }

    pub fn default_decision(self) -> ExecutionDecision {
        match self {
            Self::Reorg
            | Self::WatcherCollusion
            | Self::SequencerHalt
            | Self::Liquidity
            | Self::Metadata => ExecutionDecision::Hold,
            Self::Forgery | Self::Pq | Self::Bypass | Self::WalletMismatch => {
                ExecutionDecision::Reject
            }
        }
    }

    pub fn handler_action(self) -> &'static str {
        match self {
            Self::Reorg => "hold_until_canonical_anchor_depth_restored",
            Self::WatcherCollusion => "hold_until_independent_watcher_quorum_rebound",
            Self::SequencerHalt => "hold_for_forced_exit_timeout_execution",
            Self::Forgery => "reject_forged_receipt_transcript",
            Self::Pq => "reject_stale_or_invalid_pq_epoch",
            Self::Liquidity => "hold_until_escape_reserve_replenished",
            Self::Metadata => "hold_for_metadata_redaction_and_reblind",
            Self::Bypass => "reject_challenge_window_bypass",
            Self::WalletMismatch => "reject_wallet_recovery_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDecision {
    Hold,
    Reject,
}

impl ExecutionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerBoundGapRoot {
    pub kind: GapKind,
    pub handler_bound_root: String,
}

impl HandlerBoundGapRoot {
    pub fn new(kind: GapKind, handler_bound_root: &str) -> Self {
        Self {
            kind,
            handler_bound_root: handler_bound_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "handler_bound_root": self.handler_bound_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_bound_gap_root", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub execution_id: String,
    pub kind: GapKind,
    pub handler_bound_root: String,
    pub decision: ExecutionDecision,
    pub handler_action: String,
    pub release_allowed: u64,
    pub execution_digest: String,
}

impl ExecutionRecord {
    pub fn from_gap_root(gap_root: &HandlerBoundGapRoot) -> Self {
        let decision = gap_root.kind.default_decision();
        let handler_action = gap_root.kind.handler_action().to_string();
        let release_allowed = match decision {
            ExecutionDecision::Hold | ExecutionDecision::Reject => 0,
        };
        let execution_digest = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-EXECUTION-DIGEST",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(gap_root.kind.as_str()),
                HashPart::Str(&gap_root.handler_bound_root),
                HashPart::Str(decision.as_str()),
                HashPart::Str(&handler_action),
                HashPart::U64(release_allowed),
            ],
            32,
        );
        let execution_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-EXECUTION-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(gap_root.kind.as_str()),
                HashPart::Str(&execution_digest),
            ],
            16,
        );

        Self {
            execution_id,
            kind: gap_root.kind,
            handler_bound_root: gap_root.handler_bound_root.clone(),
            decision,
            handler_action,
            release_allowed,
            execution_digest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_id": self.execution_id,
            "kind": self.kind.as_str(),
            "handler_bound_root": self.handler_bound_root,
            "decision": self.decision.as_str(),
            "handler_action": self.handler_action,
            "release_allowed": self.release_allowed,
            "execution_digest": self.execution_digest,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution_record", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub handler_bound_gap_roots: Vec<HandlerBoundGapRoot>,
    pub execution_records: Vec<ExecutionRecord>,
    pub handler_bound_gap_root: String,
    pub execution_record_root: String,
    pub held_count: u64,
    pub rejected_count: u64,
}

impl State {
    pub fn new(config: Config, handler_bound_gap_roots: Vec<HandlerBoundGapRoot>) -> Self {
        let execution_records = handler_bound_gap_roots
            .iter()
            .map(ExecutionRecord::from_gap_root)
            .collect::<Vec<_>>();
        let held_count = execution_records
            .iter()
            .filter(|record| record.decision == ExecutionDecision::Hold)
            .count() as u64;
        let rejected_count = execution_records
            .iter()
            .filter(|record| record.decision == ExecutionDecision::Reject)
            .count() as u64;
        let gap_records = handler_bound_gap_roots
            .iter()
            .map(HandlerBoundGapRoot::public_record)
            .collect::<Vec<_>>();
        let execution_record_values = execution_records
            .iter()
            .map(ExecutionRecord::public_record)
            .collect::<Vec<_>>();

        Self {
            config,
            handler_bound_gap_roots,
            execution_records,
            handler_bound_gap_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-GAP-ROOTS",
                &gap_records,
            ),
            execution_record_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-EXECUTION-RECORDS",
                &execution_record_values,
            ),
            held_count,
            rejected_count,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::default(), devnet_gap_roots())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "handler_bound_gap_root": self.handler_bound_gap_root,
            "execution_record_root": self.execution_record_root,
            "held_count": self.held_count,
            "rejected_count": self.rejected_count,
            "handler_bound_gap_roots": self
                .handler_bound_gap_roots
                .iter()
                .map(HandlerBoundGapRoot::public_record)
                .collect::<Vec<_>>(),
            "execution_records": self
                .execution_records
                .iter()
                .map(ExecutionRecord::public_record)
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
            "handler_bound_gap_root": self.handler_bound_gap_root,
            "execution_record_root": self.execution_record_root,
            "held_count": self.held_count,
            "rejected_count": self.rejected_count,
            "release_allowed": self.release_allowed(),
        });

        domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-EXECUTION-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&state_record),
            ],
            32,
        )
    }

    pub fn release_allowed(&self) -> u64 {
        0
    }

    pub fn validate(&self) -> Result<String> {
        if self.handler_bound_gap_roots.len() as u64 != self.config.required_gap_root_count {
            return Err(
                "handler-bound execution runtime requires exactly nine gap roots".to_string(),
            );
        }
        if self.execution_records.len() != self.handler_bound_gap_roots.len() {
            return Err("handler-bound execution records must match consumed roots".to_string());
        }
        if self.held_count < self.config.hold_on_recoverable_gap {
            return Err("handler-bound execution runtime must hold recoverable gaps".to_string());
        }
        if self.rejected_count < self.config.reject_on_critical_gap {
            return Err("handler-bound execution runtime must reject critical gaps".to_string());
        }
        if self.release_allowed() != 0 {
            return Err("handler-bound execution runtime must fail closed".to_string());
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

fn devnet_gap_roots() -> Vec<HandlerBoundGapRoot> {
    vec![
        devnet_gap_root(GapKind::Reorg, "monero_anchor_reorg_handler_bound"),
        devnet_gap_root(GapKind::WatcherCollusion, "watcher_collusion_handler_bound"),
        devnet_gap_root(GapKind::SequencerHalt, "sequencer_halt_handler_bound"),
        devnet_gap_root(GapKind::Forgery, "forged_receipt_handler_bound"),
        devnet_gap_root(GapKind::Pq, "stale_pq_epoch_handler_bound"),
        devnet_gap_root(GapKind::Liquidity, "liquidity_exhaustion_handler_bound"),
        devnet_gap_root(GapKind::Metadata, "metadata_leak_handler_bound"),
        devnet_gap_root(GapKind::Bypass, "challenge_bypass_handler_bound"),
        devnet_gap_root(GapKind::WalletMismatch, "wallet_mismatch_handler_bound"),
    ]
}

fn devnet_gap_root(kind: GapKind, label: &str) -> HandlerBoundGapRoot {
    let root = domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-DEVNET-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
        ],
        32,
    );

    HandlerBoundGapRoot::new(kind, &root)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-EXECUTION-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
