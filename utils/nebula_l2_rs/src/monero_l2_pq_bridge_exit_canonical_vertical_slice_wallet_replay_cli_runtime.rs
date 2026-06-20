use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWalletReplayCliRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_REPLAY_CLI_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-wallet-replay-cli-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_REPLAY_CLI_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLI_REPLAY_SUITE: &str = "forced-exit-wallet-replay-cli-deterministic-v1";
pub const REDACTION_SUITE: &str = "wallet-replay-roots-only-evidence-redaction-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_SCAN_START_HEIGHT: u64 = 3_510_400;
pub const DEFAULT_MONERO_SCAN_END_HEIGHT: u64 = 3_510_520;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_260_144;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RECOVERY_RETRY_LIMIT: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletReplayCliStepKind {
    ScanDeposit,
    ReconstructNote,
    ReplayPrivateTransfer,
    ReplayContractReceipt,
    BuildWithdrawalClaim,
    WatchChallengeWindow,
    RecoverUnderAdversarialConditions,
    ExportRedactedEvidence,
}

impl WalletReplayCliStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanDeposit => "scan_deposit",
            Self::ReconstructNote => "reconstruct_note",
            Self::ReplayPrivateTransfer => "replay_private_transfer",
            Self::ReplayContractReceipt => "replay_contract_receipt",
            Self::BuildWithdrawalClaim => "build_withdrawal_claim",
            Self::WatchChallengeWindow => "watch_challenge_window",
            Self::RecoverUnderAdversarialConditions => "recover_under_adversarial_conditions",
            Self::ExportRedactedEvidence => "export_redacted_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletReplayCliStepStatus {
    Deterministic,
    RequiresRetry,
    Recoverable,
    Redacted,
}

impl WalletReplayCliStepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::RequiresRetry => "requires_retry",
            Self::Recoverable => "recoverable",
            Self::Redacted => "redacted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub cli_replay_suite: String,
    pub redaction_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub wallet_profile: String,
    pub monero_scan_start_height: u64,
    pub monero_scan_end_height: u64,
    pub l2_reference_height: u64,
    pub challenge_window_blocks: u64,
    pub recovery_retry_limit: u64,
    pub require_redacted_export: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            cli_replay_suite: CLI_REPLAY_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            wallet_profile: "forced-exit-wallet-replay-devnet".to_string(),
            monero_scan_start_height: DEFAULT_MONERO_SCAN_START_HEIGHT,
            monero_scan_end_height: DEFAULT_MONERO_SCAN_END_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            recovery_retry_limit: DEFAULT_RECOVERY_RETRY_LIMIT,
            require_redacted_export: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "cli_replay_suite": self.cli_replay_suite,
            "redaction_suite": self.redaction_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "wallet_profile": self.wallet_profile,
            "monero_scan_start_height": self.monero_scan_start_height,
            "monero_scan_end_height": self.monero_scan_end_height,
            "l2_reference_height": self.l2_reference_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "recovery_retry_limit": self.recovery_retry_limit,
            "require_redacted_export": self.require_redacted_export,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletReplayCliStep {
    pub sequence: u64,
    pub kind: WalletReplayCliStepKind,
    pub status: WalletReplayCliStepStatus,
    pub command: String,
    pub input_root: String,
    pub output_root: String,
    pub transcript_root: String,
    pub redaction_root: String,
    pub checkpoint_height: u64,
    pub retry_budget: u64,
    pub notes: String,
}

impl WalletReplayCliStep {
    pub fn public_record(&self) -> Value {
        json!({
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "command": self.command,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "transcript_root": self.transcript_root,
            "redaction_root": self.redaction_root,
            "checkpoint_height": self.checkpoint_height,
            "retry_budget": self.retry_budget,
            "notes": self.notes,
        })
    }

    pub fn step_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-STEP",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(self.sequence),
                HashPart::Str(self.kind.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.command),
                HashPart::Str(&self.input_root),
                HashPart::Str(&self.output_root),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.redaction_root),
                HashPart::U64(self.checkpoint_height),
                HashPart::U64(self.retry_budget),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletReplayCliPayload {
    pub payload_id: String,
    pub owner_commitment: String,
    pub deposit_scan_root: String,
    pub reconstructed_note_root: String,
    pub private_transfer_root: String,
    pub contract_receipt_root: String,
    pub withdrawal_claim_root: String,
    pub challenge_window_root: String,
    pub recovery_root: String,
    pub redacted_evidence_root: String,
    pub export_manifest_root: String,
}

impl WalletReplayCliPayload {
    pub fn public_record(&self) -> Value {
        json!({
            "payload_id": self.payload_id,
            "owner_commitment": self.owner_commitment,
            "deposit_scan_root": self.deposit_scan_root,
            "reconstructed_note_root": self.reconstructed_note_root,
            "private_transfer_root": self.private_transfer_root,
            "contract_receipt_root": self.contract_receipt_root,
            "withdrawal_claim_root": self.withdrawal_claim_root,
            "challenge_window_root": self.challenge_window_root,
            "recovery_root": self.recovery_root,
            "redacted_evidence_root": self.redacted_evidence_root,
            "export_manifest_root": self.export_manifest_root,
        })
    }

    pub fn payload_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-PAYLOAD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletReplayCliCounters {
    pub total_steps: u64,
    pub deterministic_steps: u64,
    pub recovery_steps: u64,
    pub redacted_exports: u64,
    pub retry_budget_total: u64,
}

impl WalletReplayCliCounters {
    pub fn from_steps(steps: &[WalletReplayCliStep]) -> Self {
        let deterministic_steps = steps
            .iter()
            .filter(|step| step.status == WalletReplayCliStepStatus::Deterministic)
            .count() as u64;
        let recovery_steps = steps
            .iter()
            .filter(|step| step.status == WalletReplayCliStepStatus::Recoverable)
            .count() as u64;
        let redacted_exports = steps
            .iter()
            .filter(|step| step.status == WalletReplayCliStepStatus::Redacted)
            .count() as u64;
        let retry_budget_total = steps.iter().map(|step| step.retry_budget).sum();

        Self {
            total_steps: steps.len() as u64,
            deterministic_steps,
            recovery_steps,
            redacted_exports,
            retry_budget_total,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_steps": self.total_steps,
            "deterministic_steps": self.deterministic_steps,
            "recovery_steps": self.recovery_steps,
            "redacted_exports": self.redacted_exports,
            "retry_budget_total": self.retry_budget_total,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub payload: WalletReplayCliPayload,
    pub steps: Vec<WalletReplayCliStep>,
    pub counters: WalletReplayCliCounters,
    pub labels: BTreeMap<String, String>,
}

impl State {
    pub fn new(
        config: Config,
        payload: WalletReplayCliPayload,
        steps: Vec<WalletReplayCliStep>,
        labels: BTreeMap<String, String>,
    ) -> Self {
        let counters = WalletReplayCliCounters::from_steps(&steps);
        Self {
            config,
            payload,
            steps,
            counters,
            labels,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let payload = devnet_payload(&config);
        let steps = deterministic_cli_steps(&config, &payload);
        let mut labels = BTreeMap::new();
        labels.insert("slice".to_string(), "forced-exit-wallet-replay".to_string());
        labels.insert("network".to_string(), config.l2_network.clone());
        labels.insert("redaction".to_string(), REDACTION_SUITE.to_string());
        Self::new(config, payload, steps, labels)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "payload": self.payload.public_record(),
            "steps": self.steps.iter().map(WalletReplayCliStep::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "labels": self.labels,
            "step_root": self.step_root(),
            "payload_root": self.payload.payload_root(),
        })
    }

    pub fn step_root(&self) -> String {
        let records = self
            .steps
            .iter()
            .map(WalletReplayCliStep::step_root)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-STEPS", &records)
    }

    pub fn public_record_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-PUBLIC-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.payload.payload_root()),
                HashPart::Str(&self.step_root()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&json!(self.labels)),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

pub fn deterministic_cli_steps(
    config: &Config,
    payload: &WalletReplayCliPayload,
) -> Vec<WalletReplayCliStep> {
    vec![
        cli_step(
            1,
            WalletReplayCliStepKind::ScanDeposit,
            WalletReplayCliStepStatus::Deterministic,
            "nebula-wallet-replay scan-deposit --network monero-devnet --from-height 3510400 --to-height 3510520 --redact",
            &payload.deposit_scan_root,
            &payload.reconstructed_note_root,
            config.monero_scan_end_height,
            0,
            "Scan canonical Monero deposit outputs and retain only output commitments, tx roots, and witness roots.",
        ),
        cli_step(
            2,
            WalletReplayCliStepKind::ReconstructNote,
            WalletReplayCliStepStatus::Deterministic,
            "nebula-wallet-replay reconstruct-note --from deposit-scan.json --owner-commitment",
            &payload.reconstructed_note_root,
            &payload.private_transfer_root,
            config.l2_reference_height,
            0,
            "Rebuild the wallet note from local view material without exporting spend keys or clear receiver data.",
        ),
        cli_step(
            3,
            WalletReplayCliStepKind::ReplayPrivateTransfer,
            WalletReplayCliStepStatus::Deterministic,
            "nebula-wallet-replay replay-private-transfer --note note.redacted.json --canonical",
            &payload.private_transfer_root,
            &payload.contract_receipt_root,
            config.l2_reference_height + 1,
            0,
            "Replay the shielded transfer path and bind nullifier, membership witness, and fee roots.",
        ),
        cli_step(
            4,
            WalletReplayCliStepKind::ReplayContractReceipt,
            WalletReplayCliStepStatus::Deterministic,
            "nebula-wallet-replay replay-contract-receipt --receipt-root --event-root",
            &payload.contract_receipt_root,
            &payload.withdrawal_claim_root,
            config.l2_reference_height + 2,
            0,
            "Replay the forced-exit contract receipt with canonical event ordering.",
        ),
        cli_step(
            5,
            WalletReplayCliStepKind::BuildWithdrawalClaim,
            WalletReplayCliStepStatus::Deterministic,
            "nebula-wallet-replay build-withdrawal-claim --recipient commitment --claim-root",
            &payload.withdrawal_claim_root,
            &payload.challenge_window_root,
            config.l2_reference_height + 3,
            0,
            "Build a withdrawal claim from redacted note, finality, receipt, and witness roots.",
        ),
        cli_step(
            6,
            WalletReplayCliStepKind::WatchChallengeWindow,
            WalletReplayCliStepStatus::RequiresRetry,
            "nebula-wallet-replay watch-challenge-window --claim-root --until-final",
            &payload.challenge_window_root,
            &payload.recovery_root,
            config.l2_reference_height + config.challenge_window_blocks,
            config.recovery_retry_limit,
            "Watch for double-spend, invalid-witness, censorship, and watcher-silence challenges.",
        ),
        cli_step(
            7,
            WalletReplayCliStepKind::RecoverUnderAdversarialConditions,
            WalletReplayCliStepStatus::Recoverable,
            "nebula-wallet-replay recover --from checkpoint --prefer-canonical-root",
            &payload.recovery_root,
            &payload.redacted_evidence_root,
            config.l2_reference_height + config.challenge_window_blocks + 1,
            config.recovery_retry_limit,
            "Recover deterministically across censored RPC reads, stale receipts, and reordered watcher evidence.",
        ),
        cli_step(
            8,
            WalletReplayCliStepKind::ExportRedactedEvidence,
            WalletReplayCliStepStatus::Redacted,
            "nebula-wallet-replay export-redacted-evidence --manifest-root --no-secrets",
            &payload.redacted_evidence_root,
            &payload.export_manifest_root,
            config.l2_reference_height + config.challenge_window_blocks + 2,
            0,
            "Export roots-only evidence suitable for CLI regression fixtures and public forced-exit review.",
        ),
    ]
}

fn devnet_payload(config: &Config) -> WalletReplayCliPayload {
    let owner_commitment = leaf_root("OWNER-COMMITMENT", "wallet-replay-owner-devnet");
    let deposit_scan_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-DEPOSIT-SCAN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.monero_network),
            HashPart::U64(config.monero_scan_start_height),
            HashPart::U64(config.monero_scan_end_height),
            HashPart::Str(&owner_commitment),
        ],
        32,
    );
    let reconstructed_note_root = chained_root("RECONSTRUCTED-NOTE", &deposit_scan_root);
    let private_transfer_root = chained_root("PRIVATE-TRANSFER", &reconstructed_note_root);
    let contract_receipt_root = chained_root("CONTRACT-RECEIPT", &private_transfer_root);
    let withdrawal_claim_root = chained_root("WITHDRAWAL-CLAIM", &contract_receipt_root);
    let challenge_window_root = chained_root("CHALLENGE-WINDOW", &withdrawal_claim_root);
    let recovery_root = chained_root("ADVERSARIAL-RECOVERY", &challenge_window_root);
    let redacted_evidence_root = chained_root("REDACTED-EVIDENCE", &recovery_root);
    let export_manifest_root = chained_root("EXPORT-MANIFEST", &redacted_evidence_root);
    let payload_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-PAYLOAD-ID",
        &[
            HashPart::Str(&owner_commitment),
            HashPart::Str(&deposit_scan_root),
            HashPart::Str(&export_manifest_root),
        ],
        32,
    );

    WalletReplayCliPayload {
        payload_id,
        owner_commitment,
        deposit_scan_root,
        reconstructed_note_root,
        private_transfer_root,
        contract_receipt_root,
        withdrawal_claim_root,
        challenge_window_root,
        recovery_root,
        redacted_evidence_root,
        export_manifest_root,
    }
}

fn cli_step(
    sequence: u64,
    kind: WalletReplayCliStepKind,
    status: WalletReplayCliStepStatus,
    command: &str,
    input_root: &str,
    output_root: &str,
    checkpoint_height: u64,
    retry_budget: u64,
    notes: &str,
) -> WalletReplayCliStep {
    let transcript_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(command),
            HashPart::Str(input_root),
            HashPart::Str(output_root),
            HashPart::U64(checkpoint_height),
        ],
        32,
    );
    let redaction_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CLI-REDACTION",
        &[
            HashPart::Str(REDACTION_SUITE),
            HashPart::Str(&transcript_root),
            HashPart::Str(output_root),
        ],
        32,
    );

    WalletReplayCliStep {
        sequence,
        kind,
        status,
        command: command.to_string(),
        input_root: input_root.to_string(),
        output_root: output_root.to_string(),
        transcript_root,
        redaction_root,
        checkpoint_height,
        retry_budget,
        notes: notes.to_string(),
    }
}

fn chained_root(label: &str, previous_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-CHAINED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(previous_root),
        ],
        32,
    )
}

fn leaf_root(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-REPLAY-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}
