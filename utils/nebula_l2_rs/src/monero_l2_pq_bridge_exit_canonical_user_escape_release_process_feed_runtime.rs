use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReleaseProcessFeedRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-release-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROCESS_FEED_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-release-process-feed-v1";
pub const DEFAULT_NETWORK: &str = "devnet";
pub const DEFAULT_ESCAPE_ID: &str = "canonical-user-escape-release-process-feed-devnet-0001";
pub const DEFAULT_PROCESS_FEED_ID: &str =
    "canonical-user-escape-release-process-feed-runtime-devnet-v1";
pub const DEFAULT_RELEASE_INSTRUCTION_ID: &str =
    "release-instruction-canonical-user-escape-devnet-0001";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Observed,
    Missing,
    Mismatched,
    Stale,
    Rejected,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Observed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseInstructionKind {
    UserEscapePayout,
    ForcedExitPayout,
}

impl ReleaseInstructionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserEscapePayout => "user_escape_payout",
            Self::ForcedExitPayout => "forced_exit_payout",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastStatus {
    Accepted,
    Pending,
    Rejected,
}

impl BroadcastStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
        }
    }

    pub fn confirms_release(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Committed,
    Missing,
    Mismatched,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
        }
    }

    pub fn confirms_payout(self) -> bool {
        matches!(self, Self::Committed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineStatus {
    Open,
    Due,
    Expired,
    Satisfied,
}

impl DeadlineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Due => "due",
            Self::Expired => "expired",
            Self::Satisfied => "satisfied",
        }
    }

    pub fn forces_exit_authorization(self) -> bool {
        matches!(self, Self::Due | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldReason {
    None,
    MissingInstruction,
    BroadcastNotFinal,
    PayoutCommitmentMismatch,
    DeadlineNotReached,
    FeedRootMismatch,
}

impl ReleaseHoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MissingInstruction => "missing_instruction",
            Self::BroadcastNotFinal => "broadcast_not_final",
            Self::PayoutCommitmentMismatch => "payout_commitment_mismatch",
            Self::DeadlineNotReached => "deadline_not_reached",
            Self::FeedRootMismatch => "feed_root_mismatch",
        }
    }

    pub fn blocks_withdrawal(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalAuthorization {
    Authorized,
    DeniedFailClosed,
}

impl WithdrawalAuthorization {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::DeniedFailClosed => "denied_fail_closed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub process_feed_suite: String,
    pub network: String,
    pub escape_id: String,
    pub process_feed_id: String,
    pub min_broadcast_confirmations: u64,
    pub forced_exit_grace_blocks: u64,
    pub fail_closed_on_missing_feed: bool,
    pub fail_closed_on_root_mismatch: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            process_feed_suite: PROCESS_FEED_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            process_feed_id: DEFAULT_PROCESS_FEED_ID.to_string(),
            min_broadcast_confirmations: 20,
            forced_exit_grace_blocks: 720,
            fail_closed_on_missing_feed: true,
            fail_closed_on_root_mismatch: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "process_feed_suite": self.process_feed_suite,
            "network": self.network,
            "escape_id": self.escape_id,
            "process_feed_id": self.process_feed_id,
            "min_broadcast_confirmations": self.min_broadcast_confirmations,
            "forced_exit_grace_blocks": self.forced_exit_grace_blocks,
            "fail_closed_on_missing_feed": bool_label(self.fail_closed_on_missing_feed),
            "fail_closed_on_root_mismatch": bool_label(self.fail_closed_on_root_mismatch)
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInstructionObservation {
    pub instruction_id: String,
    pub escape_id: String,
    pub instruction_kind: ReleaseInstructionKind,
    pub payout_address_commitment: String,
    pub amount_piconero: u64,
    pub release_manifest_root: String,
    pub pq_authorization_root: String,
    pub feed_status: FeedStatus,
    pub observed_at_l2_height: u64,
}

impl ReleaseInstructionObservation {
    pub fn devnet(config: &Config) -> Self {
        let payout_address_commitment = lane_root("payout-address", &config.escape_id);
        let release_manifest_root = lane_root("release-manifest", &config.escape_id);
        let pq_authorization_root = lane_root("pq-release-authorization", &config.escape_id);

        Self {
            instruction_id: DEFAULT_RELEASE_INSTRUCTION_ID.to_string(),
            escape_id: config.escape_id.clone(),
            instruction_kind: ReleaseInstructionKind::UserEscapePayout,
            payout_address_commitment,
            amount_piconero: 125_000_000_000,
            release_manifest_root,
            pq_authorization_root,
            feed_status: FeedStatus::Observed,
            observed_at_l2_height: 4_240_020,
        }
    }

    pub fn accepted(&self) -> bool {
        self.feed_status.is_accepted()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "instruction_id": self.instruction_id,
            "escape_id": self.escape_id,
            "instruction_kind": self.instruction_kind.as_str(),
            "payout_address_commitment": self.payout_address_commitment,
            "amount_piconero": self.amount_piconero,
            "release_manifest_root": self.release_manifest_root,
            "pq_authorization_root": self.pq_authorization_root,
            "feed_status": self.feed_status.as_str(),
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_instruction_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BroadcastReceiptObservation {
    pub instruction_id: String,
    pub monero_txid_commitment: String,
    pub broadcast_receipt_root: String,
    pub status: BroadcastStatus,
    pub confirmations: u64,
    pub observed_at_monero_height: u64,
    pub feed_status: FeedStatus,
}

impl BroadcastReceiptObservation {
    pub fn devnet(config: &Config, instruction: &ReleaseInstructionObservation) -> Self {
        let monero_txid_commitment = lane_root("monero-release-txid", &instruction.instruction_id);
        let broadcast_receipt_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-BROADCAST-RECEIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&instruction.instruction_id),
                HashPart::Str(&monero_txid_commitment),
                HashPart::U64(config.min_broadcast_confirmations),
            ],
            32,
        );

        Self {
            instruction_id: instruction.instruction_id.clone(),
            monero_txid_commitment,
            broadcast_receipt_root,
            status: BroadcastStatus::Accepted,
            confirmations: config.min_broadcast_confirmations,
            observed_at_monero_height: 3_160_044,
            feed_status: FeedStatus::Observed,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.feed_status.is_accepted()
            && self.status.confirms_release()
            && self.confirmations >= config.min_broadcast_confirmations
    }

    pub fn public_record(&self) -> Value {
        json!({
            "instruction_id": self.instruction_id,
            "monero_txid_commitment": self.monero_txid_commitment,
            "broadcast_receipt_root": self.broadcast_receipt_root,
            "status": self.status.as_str(),
            "confirmations": self.confirmations,
            "observed_at_monero_height": self.observed_at_monero_height,
            "feed_status": self.feed_status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        record_root("broadcast_receipt_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayoutCommitmentObservation {
    pub instruction_id: String,
    pub payout_commitment_root: String,
    pub payout_address_commitment: String,
    pub amount_piconero: u64,
    pub reserve_debit_commitment: String,
    pub status: CommitmentStatus,
    pub feed_status: FeedStatus,
}

impl PayoutCommitmentObservation {
    pub fn devnet(instruction: &ReleaseInstructionObservation) -> Self {
        let reserve_debit_commitment = lane_root("reserve-debit", &instruction.instruction_id);
        let payout_commitment_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-PAYOUT-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&instruction.instruction_id),
                HashPart::Str(&instruction.payout_address_commitment),
                HashPart::U64(instruction.amount_piconero),
                HashPart::Str(&reserve_debit_commitment),
            ],
            32,
        );

        Self {
            instruction_id: instruction.instruction_id.clone(),
            payout_commitment_root,
            payout_address_commitment: instruction.payout_address_commitment.clone(),
            amount_piconero: instruction.amount_piconero,
            reserve_debit_commitment,
            status: CommitmentStatus::Committed,
            feed_status: FeedStatus::Observed,
        }
    }

    pub fn accepted(&self, instruction: &ReleaseInstructionObservation) -> bool {
        self.feed_status.is_accepted()
            && self.status.confirms_payout()
            && self.payout_address_commitment == instruction.payout_address_commitment
            && self.amount_piconero == instruction.amount_piconero
    }

    pub fn public_record(&self) -> Value {
        json!({
            "instruction_id": self.instruction_id,
            "payout_commitment_root": self.payout_commitment_root,
            "payout_address_commitment": self.payout_address_commitment,
            "amount_piconero": self.amount_piconero,
            "reserve_debit_commitment": self.reserve_debit_commitment,
            "status": self.status.as_str(),
            "feed_status": self.feed_status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        record_root("payout_commitment_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForcedExitDeadlineObservation {
    pub escape_id: String,
    pub requested_at_l2_height: u64,
    pub deadline_l2_height: u64,
    pub observed_at_l2_height: u64,
    pub status: DeadlineStatus,
    pub deadline_root: String,
    pub feed_status: FeedStatus,
}

impl ForcedExitDeadlineObservation {
    pub fn devnet(config: &Config) -> Self {
        let requested_at_l2_height = 4_239_300;
        let deadline_l2_height = requested_at_l2_height + config.forced_exit_grace_blocks;
        let observed_at_l2_height = 4_240_024;
        let deadline_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-FORCED-EXIT-DEADLINE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.escape_id),
                HashPart::U64(requested_at_l2_height),
                HashPart::U64(deadline_l2_height),
                HashPart::U64(observed_at_l2_height),
            ],
            32,
        );

        Self {
            escape_id: config.escape_id.clone(),
            requested_at_l2_height,
            deadline_l2_height,
            observed_at_l2_height,
            status: DeadlineStatus::Expired,
            deadline_root,
            feed_status: FeedStatus::Observed,
        }
    }

    pub fn accepted(&self) -> bool {
        self.feed_status.is_accepted() && self.status.forces_exit_authorization()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "requested_at_l2_height": self.requested_at_l2_height,
            "deadline_l2_height": self.deadline_l2_height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status.as_str(),
            "deadline_root": self.deadline_root,
            "feed_status": self.feed_status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced_exit_deadline_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldObservation {
    pub escape_id: String,
    pub reason: ReleaseHoldReason,
    pub source_root: String,
    pub feed_status: FeedStatus,
}

impl HoldObservation {
    pub fn clear(config: &Config) -> Self {
        Self {
            escape_id: config.escape_id.clone(),
            reason: ReleaseHoldReason::None,
            source_root: lane_root("release-hold-clear", &config.escape_id),
            feed_status: FeedStatus::Observed,
        }
    }

    pub fn blocks_release(&self) -> bool {
        self.feed_status.is_accepted() && self.reason.blocks_withdrawal()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "reason": self.reason.as_str(),
            "source_root": self.source_root,
            "feed_status": self.feed_status.as_str()
        })
    }

    pub fn state_root(&self) -> String {
        record_root("hold_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalAuthorizationDecision {
    pub escape_id: String,
    pub authorization: WithdrawalAuthorization,
    pub reason: String,
    pub fail_closed: bool,
    pub release_process_feed_root: String,
    pub decision_root: String,
}

impl WithdrawalAuthorizationDecision {
    pub fn evaluate(
        config: &Config,
        instruction: &ReleaseInstructionObservation,
        broadcast: &BroadcastReceiptObservation,
        payout: &PayoutCommitmentObservation,
        deadline: &ForcedExitDeadlineObservation,
        hold: &HoldObservation,
        release_process_feed_root: &str,
    ) -> Self {
        let instruction_ok = instruction.accepted();
        let broadcast_ok = broadcast.accepted(config);
        let payout_ok = payout.accepted(instruction);
        let deadline_ok = deadline.accepted();
        let hold_clear = !hold.blocks_release();
        let feed_complete = instruction_ok && broadcast_ok && payout_ok && deadline_ok;
        let authorized = feed_complete && hold_clear;
        let fail_closed = config.fail_closed_on_missing_feed || config.fail_closed_on_root_mismatch;
        let authorization = if authorized {
            WithdrawalAuthorization::Authorized
        } else {
            WithdrawalAuthorization::DeniedFailClosed
        };
        let reason = decision_reason(
            instruction_ok,
            broadcast_ok,
            payout_ok,
            deadline_ok,
            hold_clear,
        );
        let decision_root = authorization_decision_root(
            &config.escape_id,
            authorization,
            &reason,
            fail_closed,
            release_process_feed_root,
        );

        Self {
            escape_id: config.escape_id.clone(),
            authorization,
            reason,
            fail_closed,
            release_process_feed_root: release_process_feed_root.to_string(),
            decision_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "authorization": self.authorization.as_str(),
            "reason": self.reason,
            "fail_closed": bool_label(self.fail_closed),
            "release_process_feed_root": self.release_process_feed_root,
            "decision_root": self.decision_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("withdrawal_authorization_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub release_instruction: ReleaseInstructionObservation,
    pub broadcast_receipt: BroadcastReceiptObservation,
    pub payout_commitment: PayoutCommitmentObservation,
    pub forced_exit_deadline: ForcedExitDeadlineObservation,
    pub release_hold: HoldObservation,
    pub withdrawal_authorization: WithdrawalAuthorizationDecision,
    pub release_process_feed_root: String,
    pub runtime_state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let release_instruction = ReleaseInstructionObservation::devnet(&config);
        let broadcast_receipt = BroadcastReceiptObservation::devnet(&config, &release_instruction);
        let payout_commitment = PayoutCommitmentObservation::devnet(&release_instruction);
        let forced_exit_deadline = ForcedExitDeadlineObservation::devnet(&config);
        let release_hold = HoldObservation::clear(&config);
        let release_process_feed_root = process_feed_root(
            &release_instruction,
            &broadcast_receipt,
            &payout_commitment,
            &forced_exit_deadline,
            &release_hold,
        );
        let withdrawal_authorization = WithdrawalAuthorizationDecision::evaluate(
            &config,
            &release_instruction,
            &broadcast_receipt,
            &payout_commitment,
            &forced_exit_deadline,
            &release_hold,
            &release_process_feed_root,
        );
        let runtime_state_root = runtime_state_root(
            &config,
            &release_instruction,
            &broadcast_receipt,
            &payout_commitment,
            &forced_exit_deadline,
            &release_hold,
            &withdrawal_authorization,
            &release_process_feed_root,
        );

        Self {
            config,
            release_instruction,
            broadcast_receipt,
            payout_commitment,
            forced_exit_deadline,
            release_hold,
            withdrawal_authorization,
            release_process_feed_root,
            runtime_state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "release_instruction": self.release_instruction.public_record(),
            "broadcast_receipt": self.broadcast_receipt.public_record(),
            "payout_commitment": self.payout_commitment.public_record(),
            "forced_exit_deadline": self.forced_exit_deadline.public_record(),
            "release_hold": self.release_hold.public_record(),
            "withdrawal_authorization": self.withdrawal_authorization.public_record(),
            "release_process_feed_root": self.release_process_feed_root,
            "runtime_state_root": self.runtime_state_root
        })
    }

    pub fn state_root(&self) -> String {
        self.runtime_state_root.clone()
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

pub fn process_feed_root(
    instruction: &ReleaseInstructionObservation,
    broadcast: &BroadcastReceiptObservation,
    payout: &PayoutCommitmentObservation,
    deadline: &ForcedExitDeadlineObservation,
    hold: &HoldObservation,
) -> String {
    let records = vec![
        instruction.public_record(),
        broadcast.public_record(),
        payout.public_record(),
        deadline.public_record(),
        hold.public_record(),
    ];
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-OBSERVATION",
        &records,
    )
}

pub fn runtime_state_root(
    config: &Config,
    instruction: &ReleaseInstructionObservation,
    broadcast: &BroadcastReceiptObservation,
    payout: &PayoutCommitmentObservation,
    deadline: &ForcedExitDeadlineObservation,
    hold: &HoldObservation,
    authorization: &WithdrawalAuthorizationDecision,
    release_process_feed_root: &str,
) -> String {
    let records = vec![
        config.public_record(),
        instruction.public_record(),
        broadcast.public_record(),
        payout.public_record(),
        deadline.public_record(),
        hold.public_record(),
        authorization.public_record(),
        json!({ "release_process_feed_root": release_process_feed_root }),
    ];
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-RUNTIME-STATE",
        &records,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn authorization_decision_root(
    escape_id: &str,
    authorization: WithdrawalAuthorization,
    reason: &str,
    fail_closed: bool,
    release_process_feed_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-WITHDRAWAL-AUTHORIZATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(escape_id),
            HashPart::Str(authorization.as_str()),
            HashPart::Str(reason),
            HashPart::Str(bool_label(fail_closed)),
            HashPart::Str(release_process_feed_root),
        ],
        32,
    )
}

fn decision_reason(
    instruction_ok: bool,
    broadcast_ok: bool,
    payout_ok: bool,
    deadline_ok: bool,
    hold_clear: bool,
) -> String {
    if !instruction_ok {
        ReleaseHoldReason::MissingInstruction.as_str().to_string()
    } else if !broadcast_ok {
        ReleaseHoldReason::BroadcastNotFinal.as_str().to_string()
    } else if !payout_ok {
        ReleaseHoldReason::PayoutCommitmentMismatch
            .as_str()
            .to_string()
    } else if !deadline_ok {
        ReleaseHoldReason::DeadlineNotReached.as_str().to_string()
    } else if !hold_clear {
        ReleaseHoldReason::FeedRootMismatch.as_str().to_string()
    } else {
        "all_process_feed_observations_accepted".to_string()
    }
}

fn lane_root(lane: &str, subject: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-PROCESS-FEED-LANE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(subject),
        ],
        32,
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
