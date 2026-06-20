use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialGatePreflightRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-preflight-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.adversarial-gate-preflight.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-preflight-runtime";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub forced_exit_epoch: u64,
    pub l2_finality_lag_blocks: u64,
    pub sequencer_outage_grace_ms: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub monero_reorg_hold_blocks: u64,
    pub receipt_withholding_grace_ms: u64,
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
            forced_exit_epoch: 42,
            l2_finality_lag_blocks: 12,
            sequencer_outage_grace_ms: 15_000,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            monero_reorg_hold_blocks: 20,
            receipt_withholding_grace_ms: 45_000,
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
            "forced_exit_epoch": self.forced_exit_epoch,
            "l2_finality_lag_blocks": self.l2_finality_lag_blocks,
            "sequencer_outage_grace_ms": self.sequencer_outage_grace_ms,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "receipt_withholding_grace_ms": self.receipt_withholding_grace_ms,
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
pub struct PreflightEvidence {
    pub case_id: String,
    pub case: AdversarialGateCase,
    pub gate: String,
    pub adversarial_signal: String,
    pub observed_input_root: String,
    pub required_countermeasure: String,
    pub expected_rejection_root: String,
    pub fail_closed_reason: String,
    pub fail_closed_reason_root: String,
    pub release_hold: bool,
    pub release_hold_reason: String,
    pub evidence_root: String,
}

impl PreflightEvidence {
    pub fn new(
        case_id: &str,
        case: AdversarialGateCase,
        gate: &str,
        adversarial_signal: &str,
        required_countermeasure: &str,
        fail_closed_reason: &str,
        release_hold_reason: &str,
    ) -> Self {
        let observed_record = json!({
            "case_id": case_id,
            "case": case.as_str(),
            "gate": gate,
            "adversarial_signal": adversarial_signal,
        });
        let observed_input_root = domain_hash(
            &format!("{DOMAIN}:observed-input-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&observed_record),
            ],
            32,
        );
        let expected_rejection_root = domain_hash(
            &format!("{DOMAIN}:expected-rejection-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(case_id),
                HashPart::Str(gate),
                HashPart::Str(fail_closed_reason),
                HashPart::Str(&observed_input_root),
            ],
            32,
        );
        let fail_closed_reason_root = domain_hash(
            &format!("{DOMAIN}:fail-closed-reason-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(case.as_str()),
                HashPart::Str(fail_closed_reason),
                HashPart::Str(release_hold_reason),
            ],
            32,
        );
        let evidence_record = json!({
            "case_id": case_id,
            "case": case.as_str(),
            "gate": gate,
            "adversarial_signal": adversarial_signal,
            "observed_input_root": observed_input_root,
            "required_countermeasure": required_countermeasure,
            "expected_rejection_root": expected_rejection_root,
            "fail_closed_reason": fail_closed_reason,
            "fail_closed_reason_root": fail_closed_reason_root,
            "release_hold": true,
            "release_hold_reason": release_hold_reason,
        });

        Self {
            case_id: case_id.to_string(),
            case,
            gate: gate.to_string(),
            adversarial_signal: adversarial_signal.to_string(),
            observed_input_root,
            required_countermeasure: required_countermeasure.to_string(),
            expected_rejection_root,
            fail_closed_reason: fail_closed_reason.to_string(),
            fail_closed_reason_root,
            release_hold: true,
            release_hold_reason: release_hold_reason.to_string(),
            evidence_root: domain_hash(
                &format!("{DOMAIN}:preflight-evidence-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&evidence_record),
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
            "adversarial_signal": self.adversarial_signal,
            "observed_input_root": self.observed_input_root,
            "required_countermeasure": self.required_countermeasure,
            "expected_rejection_root": self.expected_rejection_root,
            "fail_closed_reason": self.fail_closed_reason,
            "fail_closed_reason_root": self.fail_closed_reason_root,
            "release_hold": self.release_hold,
            "release_hold_reason": self.release_hold_reason,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub preflight_cases: Vec<PreflightEvidence>,
    pub expected_rejection_roots: BTreeMap<String, String>,
    pub fail_closed_reasons: BTreeMap<String, String>,
    pub release_hold: bool,
    pub release_hold_root: String,
    pub evidence_root: String,
    pub expected_rejection_root: String,
    pub fail_closed_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let preflight_cases = devnet_preflight_cases();
        let expected_rejection_roots = preflight_cases
            .iter()
            .map(|case| (case.case_id.clone(), case.expected_rejection_root.clone()))
            .collect::<BTreeMap<_, _>>();
        let fail_closed_reasons = preflight_cases
            .iter()
            .map(|case| (case.case_id.clone(), case.fail_closed_reason.clone()))
            .collect::<BTreeMap<_, _>>();
        let evidence_records = preflight_cases
            .iter()
            .map(PreflightEvidence::public_record)
            .collect::<Vec<_>>();
        let expected_records = expected_rejection_roots
            .iter()
            .map(|(case_id, root)| json!({ "case_id": case_id, "expected_rejection_root": root }))
            .collect::<Vec<_>>();
        let fail_closed_records = preflight_cases
            .iter()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "case": case.case.as_str(),
                    "fail_closed_reason": case.fail_closed_reason,
                    "fail_closed_reason_root": case.fail_closed_reason_root,
                    "release_hold": case.release_hold,
                })
            })
            .collect::<Vec<_>>();
        let release_records = preflight_cases
            .iter()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "release_hold": case.release_hold,
                    "release_hold_reason": case.release_hold_reason,
                    "expected_rejection_root": case.expected_rejection_root,
                })
            })
            .collect::<Vec<_>>();

        Self {
            config,
            runtime_id: runtime_id(),
            l2_tip_height: 88_240,
            monero_tip_height: 3_451_904,
            preflight_cases,
            expected_rejection_roots,
            fail_closed_reasons,
            release_hold: true,
            release_hold_root: merkle_root(
                &format!("{DOMAIN}:release-hold-root"),
                &release_records,
            ),
            evidence_root: merkle_root(&format!("{DOMAIN}:evidence-root"), &evidence_records),
            expected_rejection_root: merkle_root(
                &format!("{DOMAIN}:expected-rejections-root"),
                &expected_records,
            ),
            fail_closed_root: merkle_root(
                &format!("{DOMAIN}:fail-closed-root"),
                &fail_closed_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let case_records = self
            .preflight_cases
            .iter()
            .map(PreflightEvidence::public_record)
            .collect::<Vec<_>>();

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_preflight_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "config": self.config.public_record(),
            "preflight_cases": case_records,
            "expected_rejection_roots": self.expected_rejection_roots,
            "fail_closed_reasons": self.fail_closed_reasons,
            "release_hold": self.release_hold,
            "release_hold_root": self.release_hold_root,
            "evidence_root": self.evidence_root,
            "expected_rejection_root": self.expected_rejection_root,
            "fail_closed_root": self.fail_closed_root,
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
                HashPart::Json(&config_record),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.l2_tip_height),
                HashPart::U64(self.monero_tip_height),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(&self.expected_rejection_root),
                HashPart::Str(&self.fail_closed_root),
                HashPart::Str(&self.release_hold_root),
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
            HashPart::Str("adversarial-gate-preflight-wave"),
        ],
        32,
    )
}

fn devnet_preflight_cases() -> Vec<PreflightEvidence> {
    vec![
        PreflightEvidence::new(
            "preflight-sequencer-outage",
            AdversarialGateCase::SequencerOutage,
            "forced_exit_escape_hatch",
            "l2 head stalls beyond sequencer outage grace while forced exit claim is pending",
            "admit escape-hatch path only after deterministic liveness witness root is present",
            "reject runtime execution until sequencer outage evidence binds l2 tip and claim queue root",
            "release held while liveness witness root is missing",
        ),
        PreflightEvidence::new(
            "preflight-watcher-collusion",
            AdversarialGateCase::WatcherCollusion,
            "watcher_quorum_attestation",
            "fault-limit-plus-one watcher signatures share the same conflicting Monero observation",
            "require independent quorum split proof and slashable watcher identity commitments",
            "reject runtime execution until collusion split proof and honest minority root are bound",
            "release held while watcher collusion evidence is unresolved",
        ),
        PreflightEvidence::new(
            "preflight-monero-reorg",
            AdversarialGateCase::MoneroReorg,
            "monero_finality_guard",
            "lock transaction depth drops below reorg hold after alternate header chain appears",
            "require alternate-header root and canonical-depth recomputation before exit release",
            "reject runtime execution until reorg trace root proves the lock remains canonical",
            "release held while Monero reorg trace is active",
        ),
        PreflightEvidence::new(
            "preflight-withheld-receipt",
            AdversarialGateCase::WithheldReceipt,
            "private_receipt_availability",
            "encrypted transfer receipt is absent after withholding grace",
            "require receipt absence proof and wallet-rescan recovery commitment",
            "reject runtime execution until withheld receipt recovery proof is attached",
            "release held while receipt availability is not proven",
        ),
        PreflightEvidence::new(
            "preflight-stale-pq-key",
            AdversarialGateCase::StalePqKey,
            "pq_release_authority",
            "release authority key age exceeds configured post-quantum key ttl",
            "require fresh authority key root and rotation transcript before release",
            "reject runtime execution until stale pq key rotation evidence is bound",
            "release held while pq authority key is stale",
        ),
        PreflightEvidence::new(
            "preflight-reserve-shortfall",
            AdversarialGateCase::ReserveShortfall,
            "reserve_sufficiency",
            "available reserve commitment is below reserve floor for pending forced exits",
            "require reserve proof handoff and deficit remediation root",
            "reject runtime execution until reserve floor evidence covers every pending claim",
            "release held while reserve shortfall remains open",
        ),
        PreflightEvidence::new(
            "preflight-liquidity-exhaustion",
            AdversarialGateCase::LiquidityExhaustion,
            "liquidity_backstop",
            "fast-exit liquidity lane falls below floor while forced-exit backlog remains nonzero",
            "require slow-path settlement fallback and liquidity backstop root",
            "reject runtime execution until liquidity exhaustion fallback root is present",
            "release held while liquidity exhaustion fallback is incomplete",
        ),
        PreflightEvidence::new(
            "preflight-metadata-leak",
            AdversarialGateCase::MetadataLeak,
            "metadata_privacy_budget",
            "public transcript would reveal more scan linkage bits than the privacy budget permits",
            "require redacted transcript root and selective disclosure proof",
            "reject runtime execution until metadata leak regression root is clean",
            "release held while metadata privacy budget is exceeded",
        ),
        PreflightEvidence::new(
            "preflight-wallet-recovery",
            AdversarialGateCase::WalletRecovery,
            "wallet_recovery_path",
            "wallet cannot reconstruct claim payload before recovery deadline",
            "require deterministic wallet reconstruction vector and exportable claim root",
            "reject runtime execution until wallet recovery evidence proves user can exit locally",
            "release held while wallet recovery path is not reproducible",
        ),
    ]
}
