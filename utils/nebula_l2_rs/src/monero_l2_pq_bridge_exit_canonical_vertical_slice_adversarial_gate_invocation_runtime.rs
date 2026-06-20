use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialGateInvocationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-invocation-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-19.forced-exit.vertical-slice.adversarial-gate.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-invocation-runtime";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub forced_exit_epoch: u64,
    pub l2_finality_lag_blocks: u64,
    pub monero_reorg_hold_blocks: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub pq_key_ttl_blocks: u64,
    pub receipt_withholding_grace_ms: u64,
    pub reserve_floor_piconero: u64,
    pub liquidity_floor_piconero: u64,
    pub metadata_privacy_budget_bits: u64,
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
            monero_reorg_hold_blocks: 20,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            pq_key_ttl_blocks: 720,
            receipt_withholding_grace_ms: 45_000,
            reserve_floor_piconero: 18_000_000_000_000,
            liquidity_floor_piconero: 7_000_000_000_000,
            metadata_privacy_budget_bits: 6,
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
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "pq_key_ttl_blocks": self.pq_key_ttl_blocks,
            "receipt_withholding_grace_ms": self.receipt_withholding_grace_ms,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "liquidity_floor_piconero": self.liquidity_floor_piconero,
            "metadata_privacy_budget_bits": self.metadata_privacy_budget_bits,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateCaseKind {
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

impl GateCaseKind {
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateInvocationCase {
    pub case_id: String,
    pub kind: GateCaseKind,
    pub gate: String,
    pub invocation: String,
    pub adversarial_signal: String,
    pub expected_output: String,
    pub fail_closed: bool,
    pub evidence: Vec<String>,
    pub evidence_root: String,
}

impl GateInvocationCase {
    pub fn new(
        case_id: &str,
        kind: GateCaseKind,
        gate: &str,
        invocation: &str,
        adversarial_signal: &str,
        expected_output: &str,
        evidence: Vec<&str>,
    ) -> Self {
        let evidence = evidence
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<String>>();
        let evidence_record = json!({
            "case_id": case_id,
            "kind": kind.as_str(),
            "gate": gate,
            "invocation": invocation,
            "adversarial_signal": adversarial_signal,
            "expected_output": expected_output,
            "evidence": evidence,
        });

        Self {
            case_id: case_id.to_string(),
            kind,
            gate: gate.to_string(),
            invocation: invocation.to_string(),
            adversarial_signal: adversarial_signal.to_string(),
            expected_output: expected_output.to_string(),
            fail_closed: true,
            evidence,
            evidence_root: domain_hash(
                &format!("{DOMAIN}:case-evidence-root"),
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
            "kind": self.kind.as_str(),
            "gate": self.gate,
            "invocation": self.invocation,
            "adversarial_signal": self.adversarial_signal,
            "expected_output": self.expected_output,
            "fail_closed": self.fail_closed,
            "evidence": self.evidence,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationResult {
    pub case_id: String,
    pub invoked_gate: String,
    pub accepted: bool,
    pub fail_closed_output: String,
    pub state_mutated: bool,
    pub evidence_root: String,
    pub result_root: String,
}

impl InvocationResult {
    pub fn from_case(case: &GateInvocationCase) -> Self {
        let result_record = json!({
            "case_id": case.case_id,
            "invoked_gate": case.gate,
            "accepted": false,
            "fail_closed_output": case.expected_output,
            "state_mutated": false,
            "evidence_root": case.evidence_root,
        });

        Self {
            case_id: case.case_id.clone(),
            invoked_gate: case.gate.clone(),
            accepted: false,
            fail_closed_output: case.expected_output.clone(),
            state_mutated: false,
            evidence_root: case.evidence_root.clone(),
            result_root: domain_hash(
                &format!("{DOMAIN}:invocation-result-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&result_record),
                ],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "invoked_gate": self.invoked_gate,
            "accepted": self.accepted,
            "fail_closed_output": self.fail_closed_output,
            "state_mutated": self.state_mutated,
            "evidence_root": self.evidence_root,
            "result_root": self.result_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub cases: Vec<GateInvocationCase>,
    pub results: Vec<InvocationResult>,
    pub evidence_root: String,
    pub invocation_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = devnet_cases();
        let results = cases
            .iter()
            .map(InvocationResult::from_case)
            .collect::<Vec<_>>();
        let evidence_records = cases
            .iter()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "kind": case.kind.as_str(),
                    "evidence_root": case.evidence_root,
                    "evidence": case.evidence,
                })
            })
            .collect::<Vec<_>>();
        let result_records = results
            .iter()
            .map(InvocationResult::public_record)
            .collect::<Vec<_>>();

        Self {
            config,
            runtime_id: runtime_id(),
            l2_tip_height: 88_240,
            monero_tip_height: 3_451_904,
            cases,
            results,
            evidence_root: merkle_root(&format!("{DOMAIN}:evidence"), &evidence_records),
            invocation_root: merkle_root(&format!("{DOMAIN}:invocations"), &result_records),
        }
    }

    pub fn public_record(&self) -> Value {
        let case_records = self
            .cases
            .iter()
            .map(GateInvocationCase::public_record)
            .collect::<Vec<_>>();
        let result_records = self
            .results
            .iter()
            .map(InvocationResult::public_record)
            .collect::<Vec<_>>();

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_invocation_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "config": self.config.public_record(),
            "cases": case_records,
            "results": result_records,
            "case_root": merkle_root(&format!("{DOMAIN}:cases"), &case_records),
            "evidence_root": self.evidence_root,
            "invocation_root": self.invocation_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();
        let case_records = self
            .cases
            .iter()
            .map(GateInvocationCase::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(&format!("{DOMAIN}:cases"), &case_records);

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
                HashPart::Str(&case_root),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(&self.invocation_root),
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
        ],
        16,
    )
}

fn devnet_cases() -> Vec<GateInvocationCase> {
    vec![
        GateInvocationCase::new(
            "gate-case-sequencer-outage",
            GateCaseKind::SequencerOutage,
            "ordered_batch_presence_gate",
            "invoke_forced_exit_ordering_without_live_sequencer",
            "l2_batch_gap_exceeds_finality_lag",
            "reject_and_promote_watcher_ordered_forced_exit_queue",
            vec![
                "l2-gap:88228-88240",
                "forced-exit-queue:epoch-42",
                "sequencer-heartbeat:missing",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-watcher-collusion",
            GateCaseKind::WatcherCollusion,
            "watcher_quorum_equivocation_gate",
            "invoke_release_authorization_with_conflicting_watcher_views",
            "quorum_bitmap_contains_equivocation_pairs",
            "reject_and_freeze_colluding_watcher_bitmap",
            vec![
                "watcher:devnet-w2:view-a",
                "watcher:devnet-w2:view-b",
                "watcher:devnet-w4:view-b",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-monero-reorg",
            GateCaseKind::MoneroReorg,
            "monero_anchor_depth_gate",
            "invoke_release_against_reorged_monero_anchor",
            "anchor_parent_mismatch_at_height_3451886",
            "reject_and_quarantine_claim_until_anchor_rebind",
            vec![
                "xmr:3451886:old-anchor",
                "xmr:3451886:new-anchor",
                "hold-window:20",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-withheld-receipt",
            GateCaseKind::WithheldReceipt,
            "public_receipt_availability_gate",
            "invoke_release_broadcast_without_public_execution_receipt",
            "receipt_absent_after_grace_window",
            "reject_and_emit_recovery_receipt_stub",
            vec![
                "release:devnet-rx-7004",
                "receipt-window:45000ms",
                "receipt-root:absent",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-stale-pq-key",
            GateCaseKind::StalePqKey,
            "pq_authority_epoch_gate",
            "invoke_release_with_expired_pq_authority_key",
            "release_auth_epoch_128_seen_at_l2_height_88240",
            "reject_and_require_fresh_pq_authority_rotation",
            vec![
                "pq-authority:epoch-128",
                "pq-authority:epoch-129",
                "ttl-blocks:720",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-reserve-shortfall",
            GateCaseKind::ReserveShortfall,
            "reserve_floor_gate",
            "invoke_exit_settlement_below_canonical_reserve_floor",
            "reserve_floor_breached_by_pending_exit_set",
            "reject_and_preserve_claims_until_reserve_replenishment",
            vec![
                "reserve:devnet-vault-a",
                "reserve-floor:18000000000000",
                "exit-set:epoch-42",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-liquidity-exhaustion",
            GateCaseKind::LiquidityExhaustion,
            "liquidity_sufficiency_gate",
            "invoke_batch_release_with_exhausted_liquidity_lane",
            "available_liquidity_below_required_release_sum",
            "reject_and_schedule_pro_rata_liquidity_recovery",
            vec![
                "liquidity-lane:canonical-exit",
                "liquidity-floor:7000000000000",
                "release-batch:forced-exit-devnet-42",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-metadata-leak",
            GateCaseKind::MetadataLeak,
            "metadata_privacy_budget_gate",
            "invoke_exit_batch_with_linkable_wallet_shape",
            "wallet_cluster_entropy_delta_below_budget",
            "reject_and_pad_batch_until_privacy_budget_recovers",
            vec![
                "privacy-budget:epoch-42",
                "batch-shape:forced-exit-devnet-42",
                "entropy-delta:below-6-bits",
            ],
        ),
        GateInvocationCase::new(
            "gate-case-wallet-recovery",
            GateCaseKind::WalletRecovery,
            "wallet_recovery_completeness_gate",
            "invoke_claim_recovery_without_reconstructable_wallet_state",
            "view_key_commitment_matches_no_reconstructable_wallet_state",
            "reject_and_publish_minimal_wallet_recovery_manifest",
            vec![
                "wallet:devnet-user-17",
                "claim:forced-exit-17-42",
                "audit-path:claim-commitment",
            ],
        ),
    ]
}
