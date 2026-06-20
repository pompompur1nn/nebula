use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialGateExecutionReceiptRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-execution-receipt-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.adversarial-gate-execution-receipt.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const EXECUTION_STATUS: &str = "deferred";
pub const RECEIPT_DECISION: &str = "reject_fail_closed";
pub const RELEASE_POLICY: &str = "production_release_hold";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-execution-receipt-runtime";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub execution_status: String,
    pub receipt_decision: String,
    pub release_policy: String,
    pub forced_exit_epoch: u64,
    pub l2_finality_lag_blocks: u64,
    pub monero_reorg_hold_blocks: u64,
    pub sequencer_outage_grace_ms: u64,
    pub receipt_withholding_grace_ms: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub pq_key_ttl_blocks: u64,
    pub reserve_floor_piconero: u64,
    pub liquidity_floor_piconero: u64,
    pub metadata_privacy_budget_bits: u64,
    pub wallet_recovery_deadline_ms: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            execution_status: EXECUTION_STATUS.to_string(),
            receipt_decision: RECEIPT_DECISION.to_string(),
            release_policy: RELEASE_POLICY.to_string(),
            forced_exit_epoch: 42,
            l2_finality_lag_blocks: 12,
            monero_reorg_hold_blocks: 20,
            sequencer_outage_grace_ms: 15_000,
            receipt_withholding_grace_ms: 45_000,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            pq_key_ttl_blocks: 720,
            reserve_floor_piconero: 18_000_000_000_000,
            liquidity_floor_piconero: 7_000_000_000_000,
            metadata_privacy_budget_bits: 6,
            wallet_recovery_deadline_ms: 30_000,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "execution_status": self.execution_status,
            "receipt_decision": self.receipt_decision,
            "release_policy": self.release_policy,
            "forced_exit_epoch": self.forced_exit_epoch,
            "l2_finality_lag_blocks": self.l2_finality_lag_blocks,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "sequencer_outage_grace_ms": self.sequencer_outage_grace_ms,
            "receipt_withholding_grace_ms": self.receipt_withholding_grace_ms,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "pq_key_ttl_blocks": self.pq_key_ttl_blocks,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "liquidity_floor_piconero": self.liquidity_floor_piconero,
            "metadata_privacy_budget_bits": self.metadata_privacy_budget_bits,
            "wallet_recovery_deadline_ms": self.wallet_recovery_deadline_ms,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialGateCase {
    SequencerOutage,
    WatcherCollusion,
    MoneroReorg,
    WithheldReceipt,
    StalePqKey,
    ReserveShortfall,
    LiquidityExhaustion,
    MetadataLeak,
    WalletRecovery,
}

impl AdversarialGateCase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerOutage => "sequencer_outage",
            Self::WatcherCollusion => "watcher_collusion",
            Self::MoneroReorg => "monero_reorg",
            Self::WithheldReceipt => "withheld_receipt",
            Self::StalePqKey => "stale_pq_key",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeak => "metadata_leak",
            Self::WalletRecovery => "wallet_recovery",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReceiptEnvelopeEvidence {
    pub case_id: String,
    pub case: AdversarialGateCase,
    pub gate: String,
    pub execution_attempt_id: String,
    pub expected_invocation_root: String,
    pub expected_preflight_root: String,
    pub receipt_status: String,
    pub receipt_decision: String,
    pub rejection_reason: String,
    pub rejection_receipt_root: String,
    pub operator_evidence: Vec<String>,
    pub operator_evidence_root: String,
    pub wallet_visible_message: String,
    pub wallet_visible_no_go_root: String,
    pub release_hold: bool,
    pub release_hold_reason: String,
    pub envelope_root: String,
}

impl ReceiptEnvelopeEvidence {
    pub fn new(
        case_id: &str,
        case: AdversarialGateCase,
        gate: &str,
        adversarial_signal: &str,
        rejection_reason: &str,
        wallet_visible_message: &str,
        operator_evidence: Vec<&str>,
    ) -> Self {
        let execution_attempt_id = execution_attempt_id(case_id, gate, adversarial_signal);
        let expected_invocation_root = expected_invocation_root(case_id, case, gate);
        let expected_preflight_root =
            expected_preflight_root(case_id, case, gate, rejection_reason);
        let operator_evidence = operator_evidence
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let operator_evidence_record = json!({
            "case_id": case_id,
            "case": case.as_str(),
            "gate": gate,
            "execution_attempt_id": execution_attempt_id,
            "adversarial_signal": adversarial_signal,
            "operator_evidence": operator_evidence,
        });
        let operator_evidence_root = domain_hash(
            &format!("{DOMAIN}:operator-evidence-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&operator_evidence_record),
            ],
            32,
        );
        let rejection_record = json!({
            "case_id": case_id,
            "case": case.as_str(),
            "gate": gate,
            "execution_attempt_id": execution_attempt_id,
            "expected_invocation_root": expected_invocation_root,
            "expected_preflight_root": expected_preflight_root,
            "receipt_status": EXECUTION_STATUS,
            "receipt_decision": RECEIPT_DECISION,
            "rejection_reason": rejection_reason,
            "operator_evidence_root": operator_evidence_root,
        });
        let rejection_receipt_root = domain_hash(
            &format!("{DOMAIN}:rejection-receipt-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&rejection_record),
            ],
            32,
        );
        let wallet_no_go_record = json!({
            "case_id": case_id,
            "case": case.as_str(),
            "wallet_visible_message": wallet_visible_message,
            "rejection_receipt_root": rejection_receipt_root,
            "release_hold": true,
        });
        let wallet_visible_no_go_root = domain_hash(
            &format!("{DOMAIN}:wallet-visible-no-go-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&wallet_no_go_record),
            ],
            32,
        );
        let release_hold_reason = format!(
            "production release held while {} receipt execution is deferred",
            case.as_str()
        );
        let envelope_record = json!({
            "case_id": case_id,
            "case": case.as_str(),
            "gate": gate,
            "execution_attempt_id": execution_attempt_id,
            "expected_invocation_root": expected_invocation_root,
            "expected_preflight_root": expected_preflight_root,
            "rejection_receipt_root": rejection_receipt_root,
            "operator_evidence_root": operator_evidence_root,
            "wallet_visible_no_go_root": wallet_visible_no_go_root,
            "release_hold": true,
            "release_hold_reason": release_hold_reason,
        });

        Self {
            case_id: case_id.to_string(),
            case,
            gate: gate.to_string(),
            execution_attempt_id,
            expected_invocation_root,
            expected_preflight_root,
            receipt_status: EXECUTION_STATUS.to_string(),
            receipt_decision: RECEIPT_DECISION.to_string(),
            rejection_reason: rejection_reason.to_string(),
            rejection_receipt_root,
            operator_evidence,
            operator_evidence_root,
            wallet_visible_message: wallet_visible_message.to_string(),
            wallet_visible_no_go_root,
            release_hold: true,
            release_hold_reason,
            envelope_root: domain_hash(
                &format!("{DOMAIN}:receipt-envelope-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&envelope_record),
                ],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "case": self.case.as_str(),
            "gate": self.gate,
            "execution_attempt_id": self.execution_attempt_id,
            "expected_invocation_root": self.expected_invocation_root,
            "expected_preflight_root": self.expected_preflight_root,
            "receipt_status": self.receipt_status,
            "receipt_decision": self.receipt_decision,
            "rejection_reason": self.rejection_reason,
            "rejection_receipt_root": self.rejection_receipt_root,
            "operator_evidence": self.operator_evidence,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_message": self.wallet_visible_message,
            "wallet_visible_no_go_root": self.wallet_visible_no_go_root,
            "release_hold": self.release_hold,
            "release_hold_reason": self.release_hold_reason,
            "envelope_root": self.envelope_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub receipt_envelopes: Vec<ReceiptEnvelopeEvidence>,
    pub expected_invocation_roots: BTreeMap<String, String>,
    pub expected_preflight_roots: BTreeMap<String, String>,
    pub rejection_receipt_roots: BTreeMap<String, String>,
    pub release_hold: bool,
    pub receipt_envelope_root: String,
    pub rejection_receipt_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_no_go_root: String,
    pub expected_invocation_root: String,
    pub expected_preflight_root: String,
    pub production_release_hold_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let receipt_envelopes = devnet_receipt_envelopes();
        let expected_invocation_roots = receipt_envelopes
            .iter()
            .map(|receipt| {
                (
                    receipt.case_id.clone(),
                    receipt.expected_invocation_root.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let expected_preflight_roots = receipt_envelopes
            .iter()
            .map(|receipt| {
                (
                    receipt.case_id.clone(),
                    receipt.expected_preflight_root.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let rejection_receipt_roots = receipt_envelopes
            .iter()
            .map(|receipt| {
                (
                    receipt.case_id.clone(),
                    receipt.rejection_receipt_root.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let receipt_records = receipt_envelopes
            .iter()
            .map(ReceiptEnvelopeEvidence::public_record)
            .collect::<Vec<_>>();
        let rejection_records = receipt_envelopes
            .iter()
            .map(|receipt| {
                json!({
                    "case_id": receipt.case_id,
                    "case": receipt.case.as_str(),
                    "receipt_decision": receipt.receipt_decision,
                    "rejection_reason": receipt.rejection_reason,
                    "rejection_receipt_root": receipt.rejection_receipt_root,
                })
            })
            .collect::<Vec<_>>();
        let operator_records = receipt_envelopes
            .iter()
            .map(|receipt| {
                json!({
                    "case_id": receipt.case_id,
                    "operator_evidence_root": receipt.operator_evidence_root,
                })
            })
            .collect::<Vec<_>>();
        let wallet_records = receipt_envelopes
            .iter()
            .map(|receipt| {
                json!({
                    "case_id": receipt.case_id,
                    "wallet_visible_message": receipt.wallet_visible_message,
                    "wallet_visible_no_go_root": receipt.wallet_visible_no_go_root,
                })
            })
            .collect::<Vec<_>>();
        let invocation_records = expected_invocation_roots
            .iter()
            .map(|(case_id, root)| json!({ "case_id": case_id, "expected_invocation_root": root }))
            .collect::<Vec<_>>();
        let preflight_records = expected_preflight_roots
            .iter()
            .map(|(case_id, root)| json!({ "case_id": case_id, "expected_preflight_root": root }))
            .collect::<Vec<_>>();
        let release_hold_records = receipt_envelopes
            .iter()
            .map(|receipt| {
                json!({
                    "case_id": receipt.case_id,
                    "release_hold": receipt.release_hold,
                    "release_hold_reason": receipt.release_hold_reason,
                    "envelope_root": receipt.envelope_root,
                })
            })
            .collect::<Vec<_>>();

        Self {
            config,
            runtime_id: runtime_id(),
            l2_tip_height: 88_240,
            monero_tip_height: 3_451_904,
            receipt_envelopes,
            expected_invocation_roots,
            expected_preflight_roots,
            rejection_receipt_roots,
            release_hold: true,
            receipt_envelope_root: merkle_root(
                &format!("{DOMAIN}:receipt-envelope-root"),
                &receipt_records,
            ),
            rejection_receipt_root: merkle_root(
                &format!("{DOMAIN}:rejection-receipt-root"),
                &rejection_records,
            ),
            operator_evidence_root: merkle_root(
                &format!("{DOMAIN}:operator-evidence-root"),
                &operator_records,
            ),
            wallet_visible_no_go_root: merkle_root(
                &format!("{DOMAIN}:wallet-visible-no-go-root"),
                &wallet_records,
            ),
            expected_invocation_root: merkle_root(
                &format!("{DOMAIN}:expected-invocation-root"),
                &invocation_records,
            ),
            expected_preflight_root: merkle_root(
                &format!("{DOMAIN}:expected-preflight-root"),
                &preflight_records,
            ),
            production_release_hold_root: merkle_root(
                &format!("{DOMAIN}:production-release-hold-root"),
                &release_hold_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let receipt_records = self
            .receipt_envelopes
            .iter()
            .map(ReceiptEnvelopeEvidence::public_record)
            .collect::<Vec<_>>();

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_execution_receipt_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "config": self.config.public_record(),
            "execution_status": EXECUTION_STATUS,
            "receipt_decision": RECEIPT_DECISION,
            "release_policy": RELEASE_POLICY,
            "receipt_envelopes": receipt_records,
            "expected_invocation_roots": self.expected_invocation_roots,
            "expected_preflight_roots": self.expected_preflight_roots,
            "rejection_receipt_roots": self.rejection_receipt_roots,
            "release_hold": self.release_hold,
            "receipt_envelope_root": self.receipt_envelope_root,
            "rejection_receipt_root": self.rejection_receipt_root,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_no_go_root": self.wallet_visible_no_go_root,
            "expected_invocation_root": self.expected_invocation_root,
            "expected_preflight_root": self.expected_preflight_root,
            "production_release_hold_root": self.production_release_hold_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();
        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Json(&config_record),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.l2_tip_height),
                HashPart::U64(self.monero_tip_height),
                HashPart::Str(&self.receipt_envelope_root),
                HashPart::Str(&self.rejection_receipt_root),
                HashPart::Str(&self.operator_evidence_root),
                HashPart::Str(&self.wallet_visible_no_go_root),
                HashPart::Str(&self.expected_invocation_root),
                HashPart::Str(&self.expected_preflight_root),
                HashPart::Str(&self.production_release_hold_root),
                HashPart::Str(if self.release_hold { "true" } else { "false" }),
            ],
            32,
        )
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

fn runtime_id() -> String {
    domain_hash(
        &format!("{DOMAIN}:runtime-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
            HashPart::Str("adversarial-gate-execution-receipt-wave"),
        ],
        32,
    )
}

fn execution_attempt_id(case_id: &str, gate: &str, adversarial_signal: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:execution-attempt-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(case_id),
            HashPart::Str(gate),
            HashPart::Str(adversarial_signal),
            HashPart::Str(EXECUTION_STATUS),
        ],
        32,
    )
}

fn expected_invocation_root(case_id: &str, case: AdversarialGateCase, gate: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-invocation-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str("monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-invocation-runtime/v1"),
            HashPart::Str(case_id),
            HashPart::Str(case.as_str()),
            HashPart::Str(gate),
            HashPart::Str("accepted=false"),
            HashPart::Str("state_mutated=false"),
        ],
        32,
    )
}

fn expected_preflight_root(
    case_id: &str,
    case: AdversarialGateCase,
    gate: &str,
    rejection_reason: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-preflight-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str("monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-preflight-runtime/v1"),
            HashPart::Str(case_id),
            HashPart::Str(case.as_str()),
            HashPart::Str(gate),
            HashPart::Str(rejection_reason),
            HashPart::Str(RELEASE_POLICY),
        ],
        32,
    )
}

fn devnet_receipt_envelopes() -> Vec<ReceiptEnvelopeEvidence> {
    vec![
        ReceiptEnvelopeEvidence::new(
            "receipt-sequencer-outage",
            AdversarialGateCase::SequencerOutage,
            "forced_exit_escape_hatch",
            "sequencer remains unavailable when the forced-exit claim reaches execution boundary",
            "reject receipt because liveness witness root is absent and execution is deferred",
            "forced exit paused: sequencer outage proof is incomplete",
            vec![
                "l2 tip stagnation root",
                "claim queue root",
                "missing liveness witness root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-watcher-collusion",
            AdversarialGateCase::WatcherCollusion,
            "watcher_quorum_attestation",
            "conflicting watcher set exceeds the tolerated fault limit at receipt production",
            "reject receipt because split-proof evidence is unresolved",
            "forced exit paused: watcher quorum evidence is disputed",
            vec![
                "conflicting watcher signature root",
                "watcher identity commitment root",
                "honest minority absence root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-monero-reorg",
            AdversarialGateCase::MoneroReorg,
            "monero_finality_guard",
            "alternate Monero header chain invalidates the assumed lock depth",
            "reject receipt because canonical lock depth cannot be proven",
            "forced exit paused: Monero finality guard is active",
            vec![
                "alternate header chain root",
                "lock transaction depth root",
                "canonicality recomputation root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-withheld-receipt",
            AdversarialGateCase::WithheldReceipt,
            "private_receipt_availability",
            "encrypted transfer receipt remains unavailable after withholding grace",
            "reject receipt because availability proof and wallet recovery commitment are missing",
            "forced exit paused: private receipt is unavailable",
            vec![
                "receipt absence proof root",
                "withholding grace timer root",
                "wallet rescan recovery root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-stale-pq-key",
            AdversarialGateCase::StalePqKey,
            "pq_release_authority",
            "post-quantum release authority key exceeds ttl before receipt signing",
            "reject receipt because fresh authority key root is not bound",
            "forced exit paused: release authority key is stale",
            vec![
                "pq key age root",
                "missing rotation transcript root",
                "authority key registry root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-reserve-shortfall",
            AdversarialGateCase::ReserveShortfall,
            "reserve_sufficiency",
            "reserve commitment is below floor for the pending forced-exit batch",
            "reject receipt because reserve floor coverage is insufficient",
            "forced exit paused: reserve floor is not met",
            vec![
                "reserve balance commitment root",
                "pending forced-exit liability root",
                "deficit remediation root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-liquidity-exhaustion",
            AdversarialGateCase::LiquidityExhaustion,
            "liquidity_backstop",
            "fast-exit liquidity lane is exhausted while backlog remains open",
            "reject receipt because slow-path fallback root is incomplete",
            "forced exit paused: liquidity backstop is unavailable",
            vec![
                "liquidity lane balance root",
                "forced-exit backlog root",
                "slow-path settlement fallback root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-metadata-leak",
            AdversarialGateCase::MetadataLeak,
            "metadata_privacy_budget",
            "execution receipt transcript would exceed the public linkage budget",
            "reject receipt because redacted transcript root is not clean",
            "forced exit paused: receipt metadata privacy check failed",
            vec![
                "linkage budget measurement root",
                "redacted transcript root",
                "selective disclosure proof root",
            ],
        ),
        ReceiptEnvelopeEvidence::new(
            "receipt-wallet-recovery",
            AdversarialGateCase::WalletRecovery,
            "wallet_recovery_path",
            "wallet cannot reconstruct claim payload at receipt boundary",
            "reject receipt because wallet-visible recovery vector is not reproducible",
            "forced exit paused: wallet recovery evidence is incomplete",
            vec![
                "wallet reconstruction vector root",
                "exportable claim root",
                "local recovery deadline root",
            ],
        ),
    ]
}
