use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2RuntimeCheckpointJournalResult<T> = Result<T, String>;

pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION: &str =
    "nebula-private-l2-runtime-checkpoint-journal-v1";
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_EPOCH_BLOCKS: u64 = 12;
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_MAX_COMPONENTS: usize = 64;
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_MAX_CHECKPOINTS: usize = 16_384;
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeComponentKind {
    IntentGateway,
    PqMempoolScheduler,
    FastLaneFeeMarket,
    ContractRuntimeHost,
    StateTransitionEngine,
    ExecutionService,
    RecursiveProofAggregator,
    FeeSponsorSettlement,
    FlowReceiptBook,
    SettlementManifest,
    FinalityVoteQuorum,
    ExitClaimQueue,
    TokenContractAbiRegistry,
}

impl RuntimeComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentGateway => "intent_gateway",
            Self::PqMempoolScheduler => "pq_mempool_scheduler",
            Self::FastLaneFeeMarket => "fast_lane_fee_market",
            Self::ContractRuntimeHost => "contract_runtime_host",
            Self::StateTransitionEngine => "state_transition_engine",
            Self::ExecutionService => "execution_service",
            Self::RecursiveProofAggregator => "recursive_proof_aggregator",
            Self::FeeSponsorSettlement => "fee_sponsor_settlement",
            Self::FlowReceiptBook => "flow_receipt_book",
            Self::SettlementManifest => "settlement_manifest",
            Self::FinalityVoteQuorum => "finality_vote_quorum",
            Self::ExitClaimQueue => "exit_claim_queue",
            Self::TokenContractAbiRegistry => "token_contract_abi_registry",
        }
    }

    pub fn critical_for_replay(self) -> bool {
        matches!(
            self,
            Self::IntentGateway
                | Self::PqMempoolScheduler
                | Self::StateTransitionEngine
                | Self::ExecutionService
                | Self::RecursiveProofAggregator
                | Self::SettlementManifest
                | Self::FinalityVoteQuorum
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    Open,
    Sealed,
    ReplayReady,
    Finalized,
    Rejected,
}

impl CheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::ReplayReady => "replay_ready",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    FastPath,
    FullAudit,
    MoneroExitOnly,
    ContractOnly,
    EmergencyRecovery,
}

impl ReplayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPath => "fast_path",
            Self::FullAudit => "full_audit",
            Self::MoneroExitOnly => "monero_exit_only",
            Self::ContractOnly => "contract_only",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn requires_all_critical(self) -> bool {
        matches!(self, Self::FullAudit | Self::EmergencyRecovery)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub epoch_blocks: u64,
    pub replay_window_blocks: u64,
    pub max_components: usize,
    pub max_checkpoints: usize,
    pub min_pq_security_bits: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PQ_SIGNATURE_SCHEME
                .to_string(),
            epoch_blocks: PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_EPOCH_BLOCKS,
            replay_window_blocks:
                PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_REPLAY_WINDOW_BLOCKS,
            max_components: PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_MAX_COMPONENTS,
            max_checkpoints: PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_MAX_CHECKPOINTS,
            min_pq_security_bits:
                PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> PrivateL2RuntimeCheckpointJournalResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.hash_suite.is_empty()
            || self.pq_signature_scheme.is_empty()
        {
            return Err("runtime checkpoint journal labels cannot be empty".to_string());
        }
        if self.epoch_blocks == 0
            || self.replay_window_blocks == 0
            || self.max_components == 0
            || self.max_checkpoints == 0
            || self.min_pq_security_bits == 0
        {
            return Err("runtime checkpoint journal thresholds must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_checkpoint_journal_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "epoch_blocks": self.epoch_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "max_components": self.max_components,
            "max_checkpoints": self.max_checkpoints,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentSnapshot {
    pub snapshot_id: String,
    pub component_kind: RuntimeComponentKind,
    pub label: String,
    pub height: u64,
    pub state_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub pq_attestation_root: String,
    pub metadata_root: String,
}

impl ComponentSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        component_kind: RuntimeComponentKind,
        label: &str,
        height: u64,
        state: &Value,
        receipt: &Value,
        nullifier: &Value,
        pq_attestation: &Value,
        metadata: &Value,
    ) -> PrivateL2RuntimeCheckpointJournalResult<Self> {
        if label.is_empty() {
            return Err("runtime checkpoint component label cannot be empty".to_string());
        }
        let state_root = runtime_checkpoint_payload_root("COMPONENT-STATE", state);
        let receipt_root = runtime_checkpoint_payload_root("COMPONENT-RECEIPT", receipt);
        let nullifier_root = runtime_checkpoint_payload_root("COMPONENT-NULLIFIER", nullifier);
        let pq_attestation_root =
            runtime_checkpoint_payload_root("COMPONENT-PQ-ATTESTATION", pq_attestation);
        let metadata_root = runtime_checkpoint_payload_root("COMPONENT-METADATA", metadata);
        let snapshot_id = component_snapshot_id(
            component_kind,
            label,
            height,
            &state_root,
            &receipt_root,
            &nullifier_root,
            &pq_attestation_root,
            &metadata_root,
        );
        Ok(Self {
            snapshot_id,
            component_kind,
            label: label.to_string(),
            height,
            state_root,
            receipt_root,
            nullifier_root,
            pq_attestation_root,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_component_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "component_kind": self.component_kind.as_str(),
            "label": self.label,
            "height": self.height,
            "state_root": self.state_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "metadata_root": self.metadata_root,
            "critical_for_replay": self.component_kind.critical_for_replay(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCheckpoint {
    pub checkpoint_id: String,
    pub label: String,
    pub status: CheckpointStatus,
    pub opened_height: u64,
    pub sealed_height: Option<u64>,
    pub replay_deadline_height: u64,
    pub replay_mode: ReplayMode,
    pub operator_commitment: String,
    pub component_snapshot_ids: Vec<String>,
    pub component_root: String,
    pub replay_bundle_root: Option<String>,
}

impl RuntimeCheckpoint {
    pub fn new(
        label: &str,
        opened_height: u64,
        replay_deadline_height: u64,
        replay_mode: ReplayMode,
        operator_label: &str,
    ) -> PrivateL2RuntimeCheckpointJournalResult<Self> {
        if label.is_empty() || operator_label.is_empty() {
            return Err("runtime checkpoint labels cannot be empty".to_string());
        }
        if replay_deadline_height < opened_height {
            return Err(
                "runtime checkpoint replay deadline cannot precede open height".to_string(),
            );
        }
        let operator_commitment = runtime_checkpoint_string_root("OPERATOR", operator_label);
        let component_root = merkle_root("PRIVATE-L2-RUNTIME-CHECKPOINT-COMPONENTS", &[]);
        let checkpoint_id = runtime_checkpoint_id(
            label,
            opened_height,
            replay_deadline_height,
            replay_mode,
            &operator_commitment,
            &component_root,
        );
        Ok(Self {
            checkpoint_id,
            label: label.to_string(),
            status: CheckpointStatus::Open,
            opened_height,
            sealed_height: None,
            replay_deadline_height,
            replay_mode,
            operator_commitment,
            component_snapshot_ids: Vec::new(),
            component_root,
            replay_bundle_root: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "label": self.label,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "replay_deadline_height": self.replay_deadline_height,
            "replay_mode": self.replay_mode.as_str(),
            "operator_commitment": self.operator_commitment,
            "component_snapshot_ids": self.component_snapshot_ids,
            "component_root": self.component_root,
            "replay_bundle_root": self.replay_bundle_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub bundle_id: String,
    pub checkpoint_id: String,
    pub mode: ReplayMode,
    pub height: u64,
    pub component_root: String,
    pub state_transition_root: String,
    pub execution_receipt_root: String,
    pub settlement_manifest_root: String,
    pub finality_certificate_root: String,
    pub pq_attestation_root: String,
}

impl ReplayBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: &str,
        mode: ReplayMode,
        height: u64,
        component_records: &[Value],
        state_transition: &Value,
        execution_receipt: &Value,
        settlement_manifest: &Value,
        finality_certificate: &Value,
        pq_attestation: &Value,
    ) -> PrivateL2RuntimeCheckpointJournalResult<Self> {
        if checkpoint_id.is_empty() {
            return Err(
                "runtime checkpoint replay bundle checkpoint id cannot be empty".to_string(),
            );
        }
        let component_root = merkle_root(
            "PRIVATE-L2-RUNTIME-REPLAY-BUNDLE-COMPONENTS",
            component_records,
        );
        let state_transition_root =
            runtime_checkpoint_payload_root("REPLAY-STATE-TRANSITION", state_transition);
        let execution_receipt_root =
            runtime_checkpoint_payload_root("REPLAY-EXECUTION-RECEIPT", execution_receipt);
        let settlement_manifest_root =
            runtime_checkpoint_payload_root("REPLAY-SETTLEMENT-MANIFEST", settlement_manifest);
        let finality_certificate_root =
            runtime_checkpoint_payload_root("REPLAY-FINALITY-CERTIFICATE", finality_certificate);
        let pq_attestation_root =
            runtime_checkpoint_payload_root("REPLAY-PQ-ATTESTATION", pq_attestation);
        let bundle_id = replay_bundle_id(
            checkpoint_id,
            mode,
            height,
            &component_root,
            &state_transition_root,
            &execution_receipt_root,
            &settlement_manifest_root,
            &finality_certificate_root,
            &pq_attestation_root,
        );
        Ok(Self {
            bundle_id,
            checkpoint_id: checkpoint_id.to_string(),
            mode,
            height,
            component_root,
            state_transition_root,
            execution_receipt_root,
            settlement_manifest_root,
            finality_certificate_root,
            pq_attestation_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_replay_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "checkpoint_id": self.checkpoint_id,
            "mode": self.mode.as_str(),
            "height": self.height,
            "component_root": self.component_root,
            "state_transition_root": self.state_transition_root,
            "execution_receipt_root": self.execution_receipt_root,
            "settlement_manifest_root": self.settlement_manifest_root,
            "finality_certificate_root": self.finality_certificate_root,
            "pq_attestation_root": self.pq_attestation_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub checkpoints_opened: u64,
    pub checkpoints_sealed: u64,
    pub checkpoints_finalized: u64,
    pub component_snapshots: u64,
    pub replay_bundles: u64,
    pub rejected_checkpoints: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_checkpoint_journal_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION,
            "checkpoints_opened": self.checkpoints_opened,
            "checkpoints_sealed": self.checkpoints_sealed,
            "checkpoints_finalized": self.checkpoints_finalized,
            "component_snapshots": self.component_snapshots,
            "replay_bundles": self.replay_bundles,
            "rejected_checkpoints": self.rejected_checkpoints,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub checkpoint_root: String,
    pub component_snapshot_root: String,
    pub replay_bundle_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: runtime_checkpoint_payload_root("CONFIG", &config.public_record()),
            checkpoint_root: merkle_root("PRIVATE-L2-RUNTIME-CHECKPOINTS", &[]),
            component_snapshot_root: merkle_root("PRIVATE-L2-RUNTIME-COMPONENT-SNAPSHOTS", &[]),
            replay_bundle_root: merkle_root("PRIVATE-L2-RUNTIME-REPLAY-BUNDLES", &[]),
            counter_root: runtime_checkpoint_payload_root(
                "COUNTERS",
                &Counters::default().public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_checkpoint_journal_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "checkpoint_root": self.checkpoint_root,
            "component_snapshot_root": self.component_snapshot_root,
            "replay_bundle_root": self.replay_bundle_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub checkpoints: BTreeMap<String, RuntimeCheckpoint>,
    pub component_snapshots: BTreeMap<String, ComponentSnapshot>,
    pub replay_bundles: BTreeMap<String, ReplayBundle>,
    pub counters: Counters,
    pub roots: Roots,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateL2RuntimeCheckpointJournalResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            height,
            checkpoints: BTreeMap::new(),
            component_snapshots: BTreeMap::new(),
            replay_bundles: BTreeMap::new(),
            counters: Counters::default(),
            roots,
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> PrivateL2RuntimeCheckpointJournalResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEVNET_HEIGHT,
        )?;
        let checkpoint_id = state.open_checkpoint(
            "devnet-private-l2-runtime-checkpoint",
            PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEVNET_HEIGHT,
            ReplayMode::FullAudit,
            "devnet-operator",
        )?;
        for (component_kind, label) in [
            (RuntimeComponentKind::IntentGateway, "intent-gateway"),
            (RuntimeComponentKind::PqMempoolScheduler, "pq-mempool"),
            (
                RuntimeComponentKind::StateTransitionEngine,
                "state-transition",
            ),
            (RuntimeComponentKind::ExecutionService, "execution-service"),
            (
                RuntimeComponentKind::RecursiveProofAggregator,
                "proof-aggregator",
            ),
            (
                RuntimeComponentKind::SettlementManifest,
                "settlement-manifest",
            ),
            (RuntimeComponentKind::FinalityVoteQuorum, "finality-quorum"),
        ] {
            state.append_component_snapshot(
                &checkpoint_id,
                ComponentSnapshot::new(
                    component_kind,
                    label,
                    PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEVNET_HEIGHT,
                    &json!({"state_root": format!("devnet-{label}-state-root")}),
                    &json!({"receipt_root": format!("devnet-{label}-receipt-root")}),
                    &json!({"nullifier_root": format!("devnet-{label}-nullifier-root")}),
                    &json!({"pq_attestation_root": format!("devnet-{label}-pq-root")}),
                    &json!({"source": "devnet"}),
                )?,
            )?;
        }
        state.seal_checkpoint(
            &checkpoint_id,
            PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_DEVNET_HEIGHT,
            &json!({"state_transition": "devnet"}),
            &json!({"execution_receipt": "devnet"}),
            &json!({"settlement_manifest": "devnet"}),
            &json!({"finality_certificate": "devnet"}),
            &json!({"pq_attestation": "devnet"}),
        )?;
        Ok(state)
    }

    pub fn open_checkpoint(
        &mut self,
        label: &str,
        opened_height: u64,
        replay_mode: ReplayMode,
        operator_label: &str,
    ) -> PrivateL2RuntimeCheckpointJournalResult<String> {
        if self.checkpoints.len() >= self.config.max_checkpoints {
            return Err("runtime checkpoint capacity exhausted".to_string());
        }
        let checkpoint = RuntimeCheckpoint::new(
            label,
            opened_height,
            opened_height.saturating_add(self.config.replay_window_blocks),
            replay_mode,
            operator_label,
        )?;
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        if self
            .checkpoints
            .insert(checkpoint_id.clone(), checkpoint)
            .is_some()
        {
            return Err("runtime checkpoint already exists".to_string());
        }
        self.counters.checkpoints_opened = self.counters.checkpoints_opened.saturating_add(1);
        self.refresh();
        Ok(checkpoint_id)
    }

    pub fn append_component_snapshot(
        &mut self,
        checkpoint_id: &str,
        snapshot: ComponentSnapshot,
    ) -> PrivateL2RuntimeCheckpointJournalResult<String> {
        if self.component_snapshots.len()
            >= self.config.max_components * self.config.max_checkpoints
        {
            return Err("runtime component snapshot capacity exhausted".to_string());
        }
        {
            let checkpoint = self
                .checkpoints
                .get(checkpoint_id)
                .ok_or_else(|| "runtime checkpoint not found".to_string())?;
            if checkpoint.status != CheckpointStatus::Open {
                return Err("runtime checkpoint is not open".to_string());
            }
            if checkpoint.component_snapshot_ids.len() >= self.config.max_components {
                return Err("runtime checkpoint component limit exceeded".to_string());
            }
        }
        let snapshot_id = snapshot.snapshot_id.clone();
        if self
            .component_snapshots
            .insert(snapshot_id.clone(), snapshot)
            .is_some()
        {
            return Err("runtime component snapshot already exists".to_string());
        }
        {
            let checkpoint = self
                .checkpoints
                .get_mut(checkpoint_id)
                .ok_or_else(|| "runtime checkpoint not found".to_string())?;
            checkpoint.component_snapshot_ids.push(snapshot_id.clone());
        }
        let component_root = self.component_root_for_checkpoint(checkpoint_id)?;
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| "runtime checkpoint not found".to_string())?;
        checkpoint.component_root = component_root;
        self.counters.component_snapshots = self.counters.component_snapshots.saturating_add(1);
        self.refresh();
        Ok(snapshot_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_checkpoint(
        &mut self,
        checkpoint_id: &str,
        sealed_height: u64,
        state_transition: &Value,
        execution_receipt: &Value,
        settlement_manifest: &Value,
        finality_certificate: &Value,
        pq_attestation: &Value,
    ) -> PrivateL2RuntimeCheckpointJournalResult<String> {
        let component_records = self.component_records_for_checkpoint(checkpoint_id)?;
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| "runtime checkpoint not found".to_string())?
            .clone();
        if checkpoint.status != CheckpointStatus::Open {
            return Err("runtime checkpoint is not open".to_string());
        }
        if checkpoint.replay_mode.requires_all_critical()
            && !self.has_all_critical_components(&checkpoint.component_snapshot_ids)
        {
            return Err("runtime checkpoint missing critical replay components".to_string());
        }
        let bundle = ReplayBundle::new(
            checkpoint_id,
            checkpoint.replay_mode,
            sealed_height,
            &component_records,
            state_transition,
            execution_receipt,
            settlement_manifest,
            finality_certificate,
            pq_attestation,
        )?;
        let bundle_id = bundle.bundle_id.clone();
        self.replay_bundles.insert(bundle_id.clone(), bundle);
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| "runtime checkpoint not found".to_string())?;
        checkpoint.status = CheckpointStatus::ReplayReady;
        checkpoint.sealed_height = Some(sealed_height);
        checkpoint.replay_bundle_root = Some(runtime_checkpoint_string_root("BUNDLE", &bundle_id));
        self.counters.checkpoints_sealed = self.counters.checkpoints_sealed.saturating_add(1);
        self.counters.replay_bundles = self.counters.replay_bundles.saturating_add(1);
        self.refresh();
        Ok(bundle_id)
    }

    pub fn finalize_checkpoint(
        &mut self,
        checkpoint_id: &str,
    ) -> PrivateL2RuntimeCheckpointJournalResult<()> {
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| "runtime checkpoint not found".to_string())?;
        if checkpoint.status != CheckpointStatus::ReplayReady {
            return Err("runtime checkpoint is not replay ready".to_string());
        }
        checkpoint.status = CheckpointStatus::Finalized;
        self.counters.checkpoints_finalized = self.counters.checkpoints_finalized.saturating_add(1);
        self.refresh();
        Ok(())
    }

    pub fn refresh(&mut self) {
        let checkpoint_records = self
            .checkpoints
            .values()
            .map(RuntimeCheckpoint::public_record)
            .collect::<Vec<_>>();
        let snapshot_records = self
            .component_snapshots
            .values()
            .map(ComponentSnapshot::public_record)
            .collect::<Vec<_>>();
        let bundle_records = self
            .replay_bundles
            .values()
            .map(ReplayBundle::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: runtime_checkpoint_payload_root("CONFIG", &self.config.public_record()),
            checkpoint_root: merkle_root("PRIVATE-L2-RUNTIME-CHECKPOINTS", &checkpoint_records),
            component_snapshot_root: merkle_root(
                "PRIVATE-L2-RUNTIME-COMPONENT-SNAPSHOTS",
                &snapshot_records,
            ),
            replay_bundle_root: merkle_root("PRIVATE-L2-RUNTIME-REPLAY-BUNDLES", &bundle_records),
            counter_root: runtime_checkpoint_payload_root(
                "COUNTERS",
                &self.counters.public_record(),
            ),
        };
        self.state_root =
            runtime_checkpoint_payload_root("STATE", &self.public_record_without_root());
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_runtime_checkpoint_journal_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_RUNTIME_CHECKPOINT_JOURNAL_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root));
            object.insert(
                "checkpoints".to_string(),
                json!(self
                    .checkpoints
                    .values()
                    .map(RuntimeCheckpoint::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "component_snapshots".to_string(),
                json!(self
                    .component_snapshots
                    .values()
                    .map(ComponentSnapshot::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "replay_bundles".to_string(),
                json!(self
                    .replay_bundles
                    .values()
                    .map(ReplayBundle::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    fn component_records_for_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> PrivateL2RuntimeCheckpointJournalResult<Vec<Value>> {
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| "runtime checkpoint not found".to_string())?;
        Ok(checkpoint
            .component_snapshot_ids
            .iter()
            .filter_map(|snapshot_id| self.component_snapshots.get(snapshot_id))
            .map(ComponentSnapshot::public_record)
            .collect::<Vec<_>>())
    }

    fn component_root_for_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> PrivateL2RuntimeCheckpointJournalResult<String> {
        Ok(merkle_root(
            "PRIVATE-L2-RUNTIME-CHECKPOINT-COMPONENTS",
            &self.component_records_for_checkpoint(checkpoint_id)?,
        ))
    }

    fn has_all_critical_components(&self, snapshot_ids: &[String]) -> bool {
        let present = snapshot_ids
            .iter()
            .filter_map(|snapshot_id| self.component_snapshots.get(snapshot_id))
            .map(|snapshot| snapshot.component_kind)
            .collect::<BTreeSet<_>>();
        [
            RuntimeComponentKind::IntentGateway,
            RuntimeComponentKind::PqMempoolScheduler,
            RuntimeComponentKind::StateTransitionEngine,
            RuntimeComponentKind::ExecutionService,
            RuntimeComponentKind::RecursiveProofAggregator,
            RuntimeComponentKind::SettlementManifest,
            RuntimeComponentKind::FinalityVoteQuorum,
        ]
        .into_iter()
        .all(|component| present.contains(&component))
    }
}

pub fn runtime_checkpoint_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-RUNTIME-CHECKPOINT-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn runtime_checkpoint_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-RUNTIME-CHECKPOINT-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn component_snapshot_id(
    component_kind: RuntimeComponentKind,
    label: &str,
    height: u64,
    state_root: &str,
    receipt_root: &str,
    nullifier_root: &str,
    pq_attestation_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-RUNTIME-COMPONENT-SNAPSHOT-ID",
        &[
            HashPart::Str(component_kind.as_str()),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Str(state_root),
            HashPart::Str(receipt_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn runtime_checkpoint_id(
    label: &str,
    opened_height: u64,
    replay_deadline_height: u64,
    replay_mode: ReplayMode,
    operator_commitment: &str,
    component_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-RUNTIME-CHECKPOINT-ID",
        &[
            HashPart::Str(label),
            HashPart::Int(opened_height as i128),
            HashPart::Int(replay_deadline_height as i128),
            HashPart::Str(replay_mode.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(component_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn replay_bundle_id(
    checkpoint_id: &str,
    mode: ReplayMode,
    height: u64,
    component_root: &str,
    state_transition_root: &str,
    execution_receipt_root: &str,
    settlement_manifest_root: &str,
    finality_certificate_root: &str,
    pq_attestation_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-RUNTIME-REPLAY-BUNDLE-ID",
        &[
            HashPart::Str(checkpoint_id),
            HashPart::Str(mode.as_str()),
            HashPart::Int(height as i128),
            HashPart::Str(component_root),
            HashPart::Str(state_transition_root),
            HashPart::Str(execution_receipt_root),
            HashPart::Str(settlement_manifest_root),
            HashPart::Str(finality_certificate_root),
            HashPart::Str(pq_attestation_root),
        ],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    runtime_checkpoint_payload_root("RECORD", record)
}

pub fn devnet() -> PrivateL2RuntimeCheckpointJournalResult<State> {
    State::devnet()
}
