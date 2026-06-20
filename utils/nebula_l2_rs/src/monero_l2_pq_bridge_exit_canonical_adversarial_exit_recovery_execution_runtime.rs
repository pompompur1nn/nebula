use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalAdversarialExitRecoveryExecutionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_ADVERSARIAL_EXIT_RECOVERY_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-adversarial-exit-recovery-execution-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_ADVERSARIAL_EXIT_RECOVERY_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-18.forced-exit.adversarial-recovery.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-adversarial-exit-recovery-execution-runtime";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub l2_finality_lag_blocks: u64,
    pub monero_reorg_hold_blocks: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub pq_authority_epoch_ttl_blocks: u64,
    pub receipt_withholding_grace_ms: u64,
    pub reserve_floor_piconero: u64,
    pub metadata_privacy_budget_bits: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            l2_finality_lag_blocks: 12,
            monero_reorg_hold_blocks: 20,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            pq_authority_epoch_ttl_blocks: 720,
            receipt_withholding_grace_ms: 45_000,
            reserve_floor_piconero: 18_000_000_000_000,
            metadata_privacy_budget_bits: 6,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "l2_finality_lag_blocks": self.l2_finality_lag_blocks,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "pq_authority_epoch_ttl_blocks": self.pq_authority_epoch_ttl_blocks,
            "receipt_withholding_grace_ms": self.receipt_withholding_grace_ms,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "metadata_privacy_budget_bits": self.metadata_privacy_budget_bits
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdversarialCase {
    pub id: String,
    pub adversary: String,
    pub trigger: String,
    pub observed_signal: String,
    pub blocked_hazard: String,
    pub recovery_action: String,
    pub fail_closed: bool,
    pub recovery_deadline_ms: u64,
    pub evidence_refs: Vec<String>,
}

impl AdversarialCase {
    fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "adversary": self.adversary,
            "trigger": self.trigger,
            "observed_signal": self.observed_signal,
            "blocked_hazard": self.blocked_hazard,
            "recovery_action": self.recovery_action,
            "fail_closed": self.fail_closed,
            "recovery_deadline_ms": self.recovery_deadline_ms,
            "evidence_refs": self.evidence_refs
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryStep {
    pub ordinal: u64,
    pub action: String,
    pub gate: String,
    pub executor: String,
    pub output: String,
}

impl RecoveryStep {
    fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "action": self.action,
            "gate": self.gate,
            "executor": self.executor,
            "output": self.output
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub forced_exit_epoch: u64,
    pub cases: Vec<AdversarialCase>,
    pub recovery_steps: Vec<RecoveryStep>,
    pub receipt_root: String,
    pub watcher_attestation_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = devnet_cases();
        let recovery_steps = devnet_recovery_steps();
        let receipt_leaves = cases
            .iter()
            .map(AdversarialCase::public_record)
            .collect::<Vec<_>>();
        let watcher_leaves = recovery_steps
            .iter()
            .map(RecoveryStep::public_record)
            .collect::<Vec<_>>();

        Self {
            config,
            runtime_id: runtime_id(),
            l2_tip_height: 88_240,
            monero_tip_height: 3_451_904,
            forced_exit_epoch: 42,
            cases,
            recovery_steps,
            receipt_root: merkle_root(&format!("{DOMAIN}:receipt-root"), &receipt_leaves),
            watcher_attestation_root: merkle_root(
                &format!("{DOMAIN}:watcher-attestation-root"),
                &watcher_leaves,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let case_records = self
            .cases
            .iter()
            .map(AdversarialCase::public_record)
            .collect::<Vec<_>>();
        let recovery_records = self
            .recovery_steps
            .iter()
            .map(RecoveryStep::public_record)
            .collect::<Vec<_>>();

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_adversarial_exit_recovery_execution_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "config": self.config.public_record(),
            "cases": case_records,
            "recovery_steps": recovery_records,
            "receipt_root": self.receipt_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "case_root": merkle_root(&format!("{DOMAIN}:cases"), &case_records),
            "recovery_root": merkle_root(&format!("{DOMAIN}:recovery-steps"), &recovery_records),
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        let case_records = self
            .cases
            .iter()
            .map(AdversarialCase::public_record)
            .collect::<Vec<_>>();
        let recovery_records = self
            .recovery_steps
            .iter()
            .map(RecoveryStep::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(&format!("{DOMAIN}:cases"), &case_records);
        let recovery_root = merkle_root(&format!("{DOMAIN}:recovery-steps"), &recovery_records);
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
                HashPart::U64(self.forced_exit_epoch),
                HashPart::Str(&case_root),
                HashPart::Str(&recovery_root),
                HashPart::Str(&self.receipt_root),
                HashPart::Str(&self.watcher_attestation_root),
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

fn devnet_cases() -> Vec<AdversarialCase> {
    vec![
        AdversarialCase {
            id: "case-sequencer-failure".to_string(),
            adversary: "sequencer_failure".to_string(),
            trigger: "l2_batch_gap_exceeds_finality_lag".to_string(),
            observed_signal: "forced_exit_claims_present_without_ordered_batch".to_string(),
            blocked_hazard: "operator_can_delay_canonical_exit_ordering".to_string(),
            recovery_action: "promote_forced_exit_queue_to_watcher_ordered_batch".to_string(),
            fail_closed: true,
            recovery_deadline_ms: 12_000,
            evidence_refs: vec![
                "l2_gap:88228-88240".to_string(),
                "queue_root:forced-exit-devnet-42".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-watcher-collusion".to_string(),
            adversary: "watcher_collusion".to_string(),
            trigger: "two_watchers_sign_conflicting_release_views".to_string(),
            observed_signal: "quorum_bitmap_contains_equivocation_pairs".to_string(),
            blocked_hazard: "colluding_watchers_can_unfreeze_invalid_release".to_string(),
            recovery_action: "slash_equivocators_and_raise_honest_quorum_override".to_string(),
            fail_closed: true,
            recovery_deadline_ms: 18_000,
            evidence_refs: vec![
                "watcher:devnet-w2:view-a".to_string(),
                "watcher:devnet-w2:view-b".to_string(),
                "watcher:devnet-w4:view-b".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-monero-reorg".to_string(),
            adversary: "monero_reorg".to_string(),
            trigger: "monero_lock_depth_drops_below_hold_window".to_string(),
            observed_signal: "anchor_parent_mismatch_at_height_3451886".to_string(),
            blocked_hazard: "exit_releases_against_reorged_lock_output".to_string(),
            recovery_action: "quarantine_claim_and_rebind_to_surviving_monero_anchor".to_string(),
            fail_closed: true,
            recovery_deadline_ms: 30_000,
            evidence_refs: vec![
                "xmr:3451886:old-anchor".to_string(),
                "xmr:3451886:new-anchor".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-liquidity-exhaustion".to_string(),
            adversary: "liquidity_exhaustion".to_string(),
            trigger: "reserve_floor_breached_by_pending_exit_set".to_string(),
            observed_signal: "available_reserve_piconero_below_required_release_sum".to_string(),
            blocked_hazard: "partial_settlement_creates_unclaimable_tail".to_string(),
            recovery_action: "freeze_new_releases_and_pro_rata_schedule_replenishment".to_string(),
            fail_closed: true,
            recovery_deadline_ms: 20_000,
            evidence_refs: vec![
                "reserve:devnet-vault-a".to_string(),
                "exit-set:epoch-42".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-stale-pq-authority".to_string(),
            adversary: "stale_pq_authority".to_string(),
            trigger: "authority_epoch_age_exceeds_ttl".to_string(),
            observed_signal: "release_auth_epoch_128_seen_at_l2_height_88240".to_string(),
            blocked_hazard: "expired_pq_authority_can_authorize_exit_release".to_string(),
            recovery_action: "rotate_to_fresh_authority_and_replay_authorization_set".to_string(),
            fail_closed: true,
            recovery_deadline_ms: 16_000,
            evidence_refs: vec![
                "pq-authority:epoch-128".to_string(),
                "pq-authority:epoch-129".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-withheld-receipt".to_string(),
            adversary: "withheld_receipt".to_string(),
            trigger: "release_broadcast_without_public_execution_receipt".to_string(),
            observed_signal: "receipt_absent_after_grace_window".to_string(),
            blocked_hazard: "operator_can_hide_failed_release_execution".to_string(),
            recovery_action: "invalidate_release_and_emit_recovery_receipt_stub".to_string(),
            fail_closed: true,
            recovery_deadline_ms: 45_000,
            evidence_refs: vec![
                "release:devnet-rx-7004".to_string(),
                "receipt-window:45000ms".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-metadata-leak".to_string(),
            adversary: "metadata_leak".to_string(),
            trigger: "exit_batch_shape_exceeds_privacy_budget".to_string(),
            observed_signal: "wallet_cluster_entropy_delta_below_budget".to_string(),
            blocked_hazard: "forced_exit_metadata_links_wallet_to_monero_output".to_string(),
            recovery_action: "pad_batch_and_delay_release_until_privacy_budget_recovers"
                .to_string(),
            fail_closed: true,
            recovery_deadline_ms: 24_000,
            evidence_refs: vec![
                "privacy-budget:epoch-42".to_string(),
                "batch-shape:forced-exit-devnet-42".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-wallet-reconstruction".to_string(),
            adversary: "wallet_reconstruction".to_string(),
            trigger: "wallet_claim_export_missing_local_recovery_secret".to_string(),
            observed_signal: "view_key_commitment_matches_no_reconstructable_wallet_state"
                .to_string(),
            blocked_hazard: "user_cannot_recover_exit_claim_after_operator_failure".to_string(),
            recovery_action: "derive_minimal_wallet_state_from_claim_commitment_and_audit_path"
                .to_string(),
            fail_closed: true,
            recovery_deadline_ms: 28_000,
            evidence_refs: vec![
                "wallet:devnet-user-17".to_string(),
                "claim:forced-exit-17-42".to_string(),
            ],
        },
        AdversarialCase {
            id: "case-fail-closed-actions".to_string(),
            adversary: "compound_adversarial_recovery".to_string(),
            trigger: "multiple_recovery_guards_fire_in_same_exit_epoch".to_string(),
            observed_signal: "release_pipeline_enters_fail_closed_mode".to_string(),
            blocked_hazard: "mixed_recovery_paths_can_double_release_or_skip_user_claim"
                .to_string(),
            recovery_action: "halt_release_pipeline_preserve_claims_and_publish_replay_bundle"
                .to_string(),
            fail_closed: true,
            recovery_deadline_ms: 10_000,
            evidence_refs: vec![
                "guard:settlement".to_string(),
                "guard:authority".to_string(),
                "guard:privacy".to_string(),
                "guard:liquidity".to_string(),
            ],
        },
    ]
}

fn devnet_recovery_steps() -> Vec<RecoveryStep> {
    vec![
        RecoveryStep {
            ordinal: 1,
            action: "seal_forced_exit_queue_snapshot".to_string(),
            gate: "canonical_queue_root_available".to_string(),
            executor: "watcher_quorum".to_string(),
            output: "queue_snapshot_receipt".to_string(),
        },
        RecoveryStep {
            ordinal: 2,
            action: "freeze_release_pipeline".to_string(),
            gate: "any_adversarial_case_fail_closed".to_string(),
            executor: "recovery_runtime".to_string(),
            output: "release_freeze_marker".to_string(),
        },
        RecoveryStep {
            ordinal: 3,
            action: "bind_monero_anchor_window".to_string(),
            gate: "monero_hold_depth_satisfied".to_string(),
            executor: "monero_finality_watcher".to_string(),
            output: "anchor_rebind_receipt".to_string(),
        },
        RecoveryStep {
            ordinal: 4,
            action: "rotate_pq_release_authority".to_string(),
            gate: "fresh_authority_epoch_available".to_string(),
            executor: "pq_authority_committee".to_string(),
            output: "authority_rotation_receipt".to_string(),
        },
        RecoveryStep {
            ordinal: 5,
            action: "rebuild_wallet_claim_views".to_string(),
            gate: "claim_commitment_audit_paths_complete".to_string(),
            executor: "wallet_recovery_worker".to_string(),
            output: "wallet_reconstruction_manifest".to_string(),
        },
        RecoveryStep {
            ordinal: 6,
            action: "publish_replay_bundle".to_string(),
            gate: "receipts_and_attestations_rooted".to_string(),
            executor: "recovery_runtime".to_string(),
            output: "adversarial_exit_recovery_replay_bundle".to_string(),
        },
    ]
}
