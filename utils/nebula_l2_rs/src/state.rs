use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const STATE_PROTOCOL_VERSION: &str = "nebula-state-v1";
pub const STATE_SCHEMA_VERSION: u64 = 1;
pub const STATE_EMPTY_VALUE_ROOT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const STATE_MAX_PROOF_SIBLINGS: usize = 64;
pub const STATE_DEFAULT_CHECKPOINT_INTERVAL: u64 = 64;
pub const STATE_DEFAULT_PRUNE_RETENTION_BLOCKS: u64 = 4096;
pub const STATE_TOMBSTONE_VALUE: &str = "deleted";

pub type StateResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StateDomain {
    Accounts,
    Contracts,
    Defi,
    Privacy,
    Bridge,
    Mempool,
    Sequencer,
    Governance,
    Runtime,
    Settlement,
    Custom(String),
}

impl StateDomain {
    pub fn label(&self) -> String {
        match self {
            StateDomain::Accounts => "accounts".to_string(),
            StateDomain::Contracts => "contracts".to_string(),
            StateDomain::Defi => "defi".to_string(),
            StateDomain::Privacy => "privacy".to_string(),
            StateDomain::Bridge => "bridge".to_string(),
            StateDomain::Mempool => "mempool".to_string(),
            StateDomain::Sequencer => "sequencer".to_string(),
            StateDomain::Governance => "governance".to_string(),
            StateDomain::Runtime => "runtime".to_string(),
            StateDomain::Settlement => "settlement".to_string(),
            StateDomain::Custom(label) => label.clone(),
        }
    }

    pub fn root_domain(&self) -> String {
        format!("STATE-DOMAIN-{}", self.label().to_ascii_uppercase())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_domain",
            "chain_id": CHAIN_ID,
            "label": self.label(),
            "root_domain": self.root_domain(),
        })
    }

    pub fn all_builtin() -> Vec<Self> {
        vec![
            StateDomain::Accounts,
            StateDomain::Contracts,
            StateDomain::Defi,
            StateDomain::Privacy,
            StateDomain::Bridge,
            StateDomain::Mempool,
            StateDomain::Sequencer,
            StateDomain::Governance,
            StateDomain::Runtime,
            StateDomain::Settlement,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateLeaf {
    pub domain: StateDomain,
    pub key: String,
    pub value_root: String,
    pub version: u64,
    pub height: u64,
    pub public_metadata: Value,
    pub private_payload_root: String,
    pub deleted: bool,
}

impl StateLeaf {
    pub fn new(
        domain: StateDomain,
        key: impl Into<String>,
        value_root: impl Into<String>,
        version: u64,
        height: u64,
        public_metadata: Value,
    ) -> Self {
        Self {
            domain,
            key: key.into(),
            value_root: value_root.into(),
            version,
            height,
            public_metadata,
            private_payload_root: STATE_EMPTY_VALUE_ROOT.to_string(),
            deleted: false,
        }
    }

    pub fn with_private_payload_root(mut self, private_payload_root: impl Into<String>) -> Self {
        self.private_payload_root = private_payload_root.into();
        self
    }

    pub fn tombstone(
        domain: StateDomain,
        key: impl Into<String>,
        version: u64,
        height: u64,
    ) -> Self {
        let key = key.into();
        Self {
            domain,
            key,
            value_root: state_string_root(STATE_TOMBSTONE_VALUE),
            version,
            height,
            public_metadata: json!({"deleted": true}),
            private_payload_root: STATE_EMPTY_VALUE_ROOT.to_string(),
            deleted: true,
        }
    }

    pub fn leaf_id(&self) -> String {
        state_leaf_id(&self.domain, &self.key, self.version, self.height)
    }

    pub fn root(&self) -> String {
        state_leaf_root(self)
    }

    pub fn validate(&self) -> StateResult<()> {
        if self.key.is_empty() {
            return Err("state leaf key cannot be empty".to_string());
        }
        if self.value_root.is_empty() {
            return Err("state leaf value_root cannot be empty".to_string());
        }
        if self.private_payload_root.is_empty() {
            return Err("state leaf private_payload_root cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_leaf",
            "chain_id": CHAIN_ID,
            "domain": self.domain.label(),
            "key": self.key,
            "leaf_id": self.leaf_id(),
            "value_root": self.value_root,
            "version": self.version,
            "height": self.height,
            "public_metadata": self.public_metadata,
            "private_payload_root": self.private_payload_root,
            "deleted": self.deleted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRootVector {
    pub accounts_root: String,
    pub contracts_root: String,
    pub defi_root: String,
    pub privacy_root: String,
    pub bridge_root: String,
    pub mempool_root: String,
    pub sequencer_root: String,
    pub governance_root: String,
    pub runtime_root: String,
    pub settlement_root: String,
    pub custom_roots: BTreeMap<String, String>,
}

impl StateRootVector {
    pub fn empty() -> Self {
        Self {
            accounts_root: empty_domain_root(&StateDomain::Accounts),
            contracts_root: empty_domain_root(&StateDomain::Contracts),
            defi_root: empty_domain_root(&StateDomain::Defi),
            privacy_root: empty_domain_root(&StateDomain::Privacy),
            bridge_root: empty_domain_root(&StateDomain::Bridge),
            mempool_root: empty_domain_root(&StateDomain::Mempool),
            sequencer_root: empty_domain_root(&StateDomain::Sequencer),
            governance_root: empty_domain_root(&StateDomain::Governance),
            runtime_root: empty_domain_root(&StateDomain::Runtime),
            settlement_root: empty_domain_root(&StateDomain::Settlement),
            custom_roots: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> String {
        state_root_vector_root(self)
    }

    pub fn domain_root(&self, domain: &StateDomain) -> String {
        match domain {
            StateDomain::Accounts => self.accounts_root.clone(),
            StateDomain::Contracts => self.contracts_root.clone(),
            StateDomain::Defi => self.defi_root.clone(),
            StateDomain::Privacy => self.privacy_root.clone(),
            StateDomain::Bridge => self.bridge_root.clone(),
            StateDomain::Mempool => self.mempool_root.clone(),
            StateDomain::Sequencer => self.sequencer_root.clone(),
            StateDomain::Governance => self.governance_root.clone(),
            StateDomain::Runtime => self.runtime_root.clone(),
            StateDomain::Settlement => self.settlement_root.clone(),
            StateDomain::Custom(label) => self
                .custom_roots
                .get(label)
                .cloned()
                .unwrap_or_else(|| empty_domain_root(domain)),
        }
    }

    pub fn set_domain_root(&mut self, domain: &StateDomain, root: impl Into<String>) {
        let root = root.into();
        match domain {
            StateDomain::Accounts => self.accounts_root = root,
            StateDomain::Contracts => self.contracts_root = root,
            StateDomain::Defi => self.defi_root = root,
            StateDomain::Privacy => self.privacy_root = root,
            StateDomain::Bridge => self.bridge_root = root,
            StateDomain::Mempool => self.mempool_root = root,
            StateDomain::Sequencer => self.sequencer_root = root,
            StateDomain::Governance => self.governance_root = root,
            StateDomain::Runtime => self.runtime_root = root,
            StateDomain::Settlement => self.settlement_root = root,
            StateDomain::Custom(label) => {
                self.custom_roots.insert(label.clone(), root);
            }
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_root_vector",
            "chain_id": CHAIN_ID,
            "schema_version": STATE_SCHEMA_VERSION,
            "accounts_root": self.accounts_root,
            "contracts_root": self.contracts_root,
            "defi_root": self.defi_root,
            "privacy_root": self.privacy_root,
            "bridge_root": self.bridge_root,
            "mempool_root": self.mempool_root,
            "sequencer_root": self.sequencer_root,
            "governance_root": self.governance_root,
            "runtime_root": self.runtime_root,
            "settlement_root": self.settlement_root,
            "custom_roots": self.custom_roots,
            "root": self.root(),
        })
    }
}

impl Default for StateRootVector {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub block_root: String,
    pub parent_snapshot_id: String,
    pub parent_state_root: String,
    pub root_vector: StateRootVector,
    pub leaf_count: u64,
    pub transaction_count: u64,
    pub da_root: String,
    pub settlement_anchor_root: String,
    pub timestamp_ms: u64,
    pub operator_label: String,
}

impl StateSnapshot {
    pub fn state_root(&self) -> String {
        self.root_vector.root()
    }

    pub fn expected_snapshot_id(&self) -> String {
        state_snapshot_id(
            self.height,
            &self.block_root,
            &self.parent_snapshot_id,
            &self.parent_state_root,
            &self.state_root(),
            self.leaf_count,
            self.transaction_count,
            &self.da_root,
            &self.settlement_anchor_root,
        )
    }

    pub fn validate(&self) -> StateResult<()> {
        if self.block_root.is_empty() {
            return Err("state snapshot block_root cannot be empty".to_string());
        }
        if self.parent_state_root.is_empty() {
            return Err("state snapshot parent_state_root cannot be empty".to_string());
        }
        if self.da_root.is_empty() {
            return Err("state snapshot da_root cannot be empty".to_string());
        }
        if self.settlement_anchor_root.is_empty() {
            return Err("state snapshot settlement_anchor_root cannot be empty".to_string());
        }
        if self.snapshot_id != self.expected_snapshot_id() {
            return Err("state snapshot id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_PROTOCOL_VERSION,
            "schema_version": STATE_SCHEMA_VERSION,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "block_root": self.block_root,
            "parent_snapshot_id": self.parent_snapshot_id,
            "parent_state_root": self.parent_state_root,
            "state_root": self.state_root(),
            "root_vector": self.root_vector.public_record(),
            "leaf_count": self.leaf_count,
            "transaction_count": self.transaction_count,
            "da_root": self.da_root,
            "settlement_anchor_root": self.settlement_anchor_root,
            "timestamp_ms": self.timestamp_ms,
            "operator_commitment": state_string_root(&self.operator_label),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateDeltaOpKind {
    Insert,
    Update,
    Delete,
}

impl StateDeltaOpKind {
    pub fn label(&self) -> &'static str {
        match self {
            StateDeltaOpKind::Insert => "insert",
            StateDeltaOpKind::Update => "update",
            StateDeltaOpKind::Delete => "delete",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDeltaOperation {
    pub op_index: u64,
    pub op_kind: StateDeltaOpKind,
    pub domain: StateDomain,
    pub key: String,
    pub before_root: String,
    pub after_root: String,
    pub leaf: StateLeaf,
    pub transaction_id: String,
    pub public_metadata: Value,
}

impl StateDeltaOperation {
    pub fn validate(&self) -> StateResult<()> {
        if self.key.is_empty() {
            return Err("state delta operation key cannot be empty".to_string());
        }
        if self.after_root.is_empty() {
            return Err("state delta operation after_root cannot be empty".to_string());
        }
        if self.leaf.key != self.key {
            return Err("state delta operation leaf key mismatch".to_string());
        }
        if self.leaf.domain != self.domain {
            return Err("state delta operation leaf domain mismatch".to_string());
        }
        if self.leaf.root() != self.after_root {
            return Err("state delta operation after_root mismatch".to_string());
        }
        match self.op_kind {
            StateDeltaOpKind::Delete if !self.leaf.deleted => {
                Err("delete operation must carry a tombstone leaf".to_string())
            }
            StateDeltaOpKind::Insert | StateDeltaOpKind::Update if self.leaf.deleted => {
                Err("insert/update operation cannot carry a tombstone leaf".to_string())
            }
            _ => Ok(()),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_delta_operation",
            "chain_id": CHAIN_ID,
            "op_index": self.op_index,
            "op_kind": self.op_kind.label(),
            "domain": self.domain.label(),
            "key": self.key,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "leaf": self.leaf.public_record(),
            "transaction_id": self.transaction_id,
            "public_metadata": self.public_metadata,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDelta {
    pub delta_id: String,
    pub height: u64,
    pub prev_snapshot_id: String,
    pub next_snapshot_id: String,
    pub prev_state_root: String,
    pub next_state_root: String,
    pub operations: Vec<StateDeltaOperation>,
    pub transaction_root: String,
    pub fee_root: String,
    pub authorization_root: String,
}

impl StateDelta {
    pub fn touched_domain_root(&self) -> String {
        let domains = self
            .operations
            .iter()
            .map(|operation| operation.domain.label())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        merkle_root("STATE-DELTA-TOUCHED-DOMAIN", &domains)
    }

    pub fn operation_root(&self) -> String {
        merkle_root(
            "STATE-DELTA-OPERATION",
            &self
                .operations
                .iter()
                .map(StateDeltaOperation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn expected_delta_id(&self) -> String {
        state_delta_id(
            self.height,
            &self.prev_snapshot_id,
            &self.next_snapshot_id,
            &self.prev_state_root,
            &self.next_state_root,
            &self.operation_root(),
            &self.transaction_root,
            &self.fee_root,
            &self.authorization_root,
        )
    }

    pub fn validate(&self) -> StateResult<()> {
        if self.operations.is_empty() {
            return Err("state delta must contain at least one operation".to_string());
        }
        if self.prev_state_root.is_empty() || self.next_state_root.is_empty() {
            return Err("state delta roots cannot be empty".to_string());
        }
        let mut expected_index = 0_u64;
        for operation in &self.operations {
            if operation.op_index != expected_index {
                return Err("state delta operation indexes must be contiguous".to_string());
            }
            operation.validate()?;
            expected_index += 1;
        }
        if self.delta_id != self.expected_delta_id() {
            return Err("state delta id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_delta",
            "chain_id": CHAIN_ID,
            "delta_id": self.delta_id,
            "height": self.height,
            "prev_snapshot_id": self.prev_snapshot_id,
            "next_snapshot_id": self.next_snapshot_id,
            "prev_state_root": self.prev_state_root,
            "next_state_root": self.next_state_root,
            "operation_root": self.operation_root(),
            "operation_count": self.operations.len(),
            "touched_domain_root": self.touched_domain_root(),
            "transaction_root": self.transaction_root,
            "fee_root": self.fee_root,
            "authorization_root": self.authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateProofDirection {
    Left,
    Right,
}

impl StateProofDirection {
    pub fn label(&self) -> &'static str {
        match self {
            StateProofDirection::Left => "left",
            StateProofDirection::Right => "right",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProofStep {
    pub depth: u64,
    pub direction: StateProofDirection,
    pub sibling_root: String,
}

impl StateProofStep {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_proof_step",
            "depth": self.depth,
            "direction": self.direction.label(),
            "sibling_root": self.sibling_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    pub proof_id: String,
    pub snapshot_id: String,
    pub domain: StateDomain,
    pub key: String,
    pub exists: bool,
    pub leaf: Option<StateLeaf>,
    pub leaf_root: String,
    pub proof_steps: Vec<StateProofStep>,
    pub expected_domain_root: String,
    pub expected_state_root: String,
    pub proof_payload_root: String,
}

impl StateProof {
    pub fn computed_domain_root(&self) -> StateResult<String> {
        if self.proof_steps.len() > STATE_MAX_PROOF_SIBLINGS {
            return Err("state proof has too many siblings".to_string());
        }
        let mut current = self.leaf_root.clone();
        for step in &self.proof_steps {
            if step.sibling_root.is_empty() {
                return Err("state proof sibling_root cannot be empty".to_string());
            }
            current = match step.direction {
                StateProofDirection::Left => domain_hash(
                    "STATE-PROOF-NODE",
                    &[
                        HashPart::Str(&step.sibling_root),
                        HashPart::Str(&current),
                        HashPart::Int(step.depth as i128),
                    ],
                    32,
                ),
                StateProofDirection::Right => domain_hash(
                    "STATE-PROOF-NODE",
                    &[
                        HashPart::Str(&current),
                        HashPart::Str(&step.sibling_root),
                        HashPart::Int(step.depth as i128),
                    ],
                    32,
                ),
            };
        }
        Ok(current)
    }

    pub fn expected_proof_id(&self) -> String {
        state_proof_id(
            &self.snapshot_id,
            &self.domain,
            &self.key,
            self.exists,
            &self.leaf_root,
            &self.expected_domain_root,
            &self.expected_state_root,
            &self.proof_payload_root,
        )
    }

    pub fn validate(&self) -> StateResult<()> {
        if self.snapshot_id.is_empty() {
            return Err("state proof snapshot_id cannot be empty".to_string());
        }
        if self.key.is_empty() {
            return Err("state proof key cannot be empty".to_string());
        }
        if self.exists && self.leaf.is_none() {
            return Err("state proof exists=true requires a leaf".to_string());
        }
        if let Some(leaf) = &self.leaf {
            leaf.validate()?;
            if leaf.key != self.key {
                return Err("state proof leaf key mismatch".to_string());
            }
            if leaf.domain != self.domain {
                return Err("state proof leaf domain mismatch".to_string());
            }
            if leaf.root() != self.leaf_root {
                return Err("state proof leaf_root mismatch".to_string());
            }
        }
        if self.proof_id != self.expected_proof_id() {
            return Err("state proof id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_proof",
            "chain_id": CHAIN_ID,
            "proof_id": self.proof_id,
            "snapshot_id": self.snapshot_id,
            "domain": self.domain.label(),
            "key": self.key,
            "exists": self.exists,
            "leaf_root": self.leaf_root,
            "proof_step_root": merkle_root(
                "STATE-PROOF-STEP",
                &self.proof_steps.iter().map(StateProofStep::public_record).collect::<Vec<_>>()
            ),
            "expected_domain_root": self.expected_domain_root,
            "expected_state_root": self.expected_state_root,
            "proof_payload_root": self.proof_payload_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatePruneCheckpoint {
    pub checkpoint_id: String,
    pub snapshot_id: String,
    pub retain_after_height: u64,
    pub pruned_leaf_count: u64,
    pub retained_leaf_count: u64,
    pub root_vector_root: String,
    pub archive_manifest_root: String,
    pub created_at_height: u64,
}

impl StatePruneCheckpoint {
    pub fn expected_checkpoint_id(&self) -> String {
        state_prune_checkpoint_id(
            &self.snapshot_id,
            self.retain_after_height,
            self.pruned_leaf_count,
            self.retained_leaf_count,
            &self.root_vector_root,
            &self.archive_manifest_root,
            self.created_at_height,
        )
    }

    pub fn validate(&self) -> StateResult<()> {
        if self.snapshot_id.is_empty() {
            return Err("state prune checkpoint snapshot_id cannot be empty".to_string());
        }
        if self.root_vector_root.is_empty() {
            return Err("state prune checkpoint root_vector_root cannot be empty".to_string());
        }
        if self.archive_manifest_root.is_empty() {
            return Err("state prune checkpoint archive_manifest_root cannot be empty".to_string());
        }
        if self.checkpoint_id != self.expected_checkpoint_id() {
            return Err("state prune checkpoint id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_prune_checkpoint",
            "chain_id": CHAIN_ID,
            "checkpoint_id": self.checkpoint_id,
            "snapshot_id": self.snapshot_id,
            "retain_after_height": self.retain_after_height,
            "pruned_leaf_count": self.pruned_leaf_count,
            "retained_leaf_count": self.retained_leaf_count,
            "root_vector_root": self.root_vector_root,
            "archive_manifest_root": self.archive_manifest_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateForkEvidence {
    pub evidence_id: String,
    pub height: u64,
    pub left_snapshot_id: String,
    pub right_snapshot_id: String,
    pub left_state_root: String,
    pub right_state_root: String,
    pub conflict_domain: StateDomain,
    pub conflict_key: String,
    pub reporter_label: String,
    pub reported_at_height: u64,
}

impl StateForkEvidence {
    pub fn expected_evidence_id(&self) -> String {
        state_fork_evidence_id(
            self.height,
            &self.left_snapshot_id,
            &self.right_snapshot_id,
            &self.left_state_root,
            &self.right_state_root,
            &self.conflict_domain,
            &self.conflict_key,
            &self.reporter_label,
            self.reported_at_height,
        )
    }

    pub fn validate(&self) -> StateResult<()> {
        if self.left_snapshot_id == self.right_snapshot_id {
            return Err("state fork evidence requires two different snapshots".to_string());
        }
        if self.left_state_root == self.right_state_root {
            return Err("state fork evidence requires conflicting roots".to_string());
        }
        if self.conflict_key.is_empty() {
            return Err("state fork evidence conflict_key cannot be empty".to_string());
        }
        if self.evidence_id != self.expected_evidence_id() {
            return Err("state fork evidence id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_fork_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "height": self.height,
            "left_snapshot_id": self.left_snapshot_id,
            "right_snapshot_id": self.right_snapshot_id,
            "left_state_root": self.left_state_root,
            "right_state_root": self.right_state_root,
            "conflict_domain": self.conflict_domain.label(),
            "conflict_key": self.conflict_key,
            "reporter_commitment": state_string_root(&self.reporter_label),
            "reported_at_height": self.reported_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAccumulator {
    pub leaves: BTreeMap<String, StateLeaf>,
    pub snapshots: BTreeMap<String, StateSnapshot>,
    pub deltas: BTreeMap<String, StateDelta>,
    pub prune_checkpoints: BTreeMap<String, StatePruneCheckpoint>,
    pub fork_evidence: BTreeMap<String, StateForkEvidence>,
    pub current_height: u64,
    pub current_snapshot_id: String,
    pub transaction_count: u64,
}

impl StateAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state_root(&self) -> String {
        self.build_root_vector().root()
    }

    pub fn leaf_key(domain: &StateDomain, key: &str) -> String {
        domain_hash(
            "STATE-ACCUMULATOR-LEAF-KEY",
            &[HashPart::Str(&domain.label()), HashPart::Str(key)],
            32,
        )
    }

    pub fn get_leaf(&self, domain: &StateDomain, key: &str) -> Option<&StateLeaf> {
        self.leaves.get(&Self::leaf_key(domain, key))
    }

    pub fn upsert_leaf(&mut self, mut leaf: StateLeaf) -> StateResult<StateDeltaOperation> {
        leaf.validate()?;
        let storage_key = Self::leaf_key(&leaf.domain, &leaf.key);
        let before_root = self
            .leaves
            .get(&storage_key)
            .map(StateLeaf::root)
            .unwrap_or_else(|| STATE_EMPTY_VALUE_ROOT.to_string());
        let op_kind = if before_root == STATE_EMPTY_VALUE_ROOT {
            StateDeltaOpKind::Insert
        } else {
            StateDeltaOpKind::Update
        };
        leaf.version = leaf.version.max(
            self.leaves
                .get(&storage_key)
                .map(|existing| existing.version.saturating_add(1))
                .unwrap_or(leaf.version),
        );
        let after_root = leaf.root();
        self.leaves.insert(storage_key, leaf.clone());
        Ok(StateDeltaOperation {
            op_index: 0,
            op_kind,
            domain: leaf.domain.clone(),
            key: leaf.key.clone(),
            before_root,
            after_root,
            leaf,
            transaction_id: String::new(),
            public_metadata: json!({}),
        })
    }

    pub fn delete_leaf(
        &mut self,
        domain: StateDomain,
        key: &str,
        height: u64,
    ) -> StateResult<StateDeltaOperation> {
        let storage_key = Self::leaf_key(&domain, key);
        let before_root = self
            .leaves
            .get(&storage_key)
            .map(StateLeaf::root)
            .unwrap_or_else(|| STATE_EMPTY_VALUE_ROOT.to_string());
        if before_root == STATE_EMPTY_VALUE_ROOT {
            return Err("cannot delete an unknown state leaf".to_string());
        }
        let version = self
            .leaves
            .get(&storage_key)
            .map(|existing| existing.version.saturating_add(1))
            .unwrap_or(1);
        let leaf = StateLeaf::tombstone(domain.clone(), key, version, height);
        let after_root = leaf.root();
        self.leaves.insert(storage_key, leaf.clone());
        Ok(StateDeltaOperation {
            op_index: 0,
            op_kind: StateDeltaOpKind::Delete,
            domain,
            key: key.to_string(),
            before_root,
            after_root,
            leaf,
            transaction_id: String::new(),
            public_metadata: json!({}),
        })
    }

    pub fn apply_operations(
        &mut self,
        height: u64,
        operations: Vec<StateDeltaOperation>,
        transaction_root: &str,
        fee_root: &str,
        authorization_root: &str,
    ) -> StateResult<StateDelta> {
        if operations.is_empty() {
            return Err("cannot apply an empty state operation set".to_string());
        }
        let prev_snapshot_id = self.current_snapshot_id.clone();
        let prev_state_root = self.state_root();
        let mut indexed_operations = Vec::with_capacity(operations.len());
        for (index, mut operation) in operations.into_iter().enumerate() {
            operation.op_index = index as u64;
            operation.validate()?;
            let storage_key = Self::leaf_key(&operation.domain, &operation.key);
            self.leaves.insert(storage_key, operation.leaf.clone());
            indexed_operations.push(operation);
        }
        self.current_height = height;
        self.transaction_count = self
            .transaction_count
            .saturating_add(indexed_operations.len() as u64);
        let next_state_root = self.state_root();
        let next_snapshot_id = state_string_root(&format!(
            "pending-snapshot:{height}:{next_state_root}:{}",
            self.transaction_count
        ));
        let mut delta = StateDelta {
            delta_id: String::new(),
            height,
            prev_snapshot_id,
            next_snapshot_id,
            prev_state_root,
            next_state_root,
            operations: indexed_operations,
            transaction_root: transaction_root.to_string(),
            fee_root: fee_root.to_string(),
            authorization_root: authorization_root.to_string(),
        };
        delta.delta_id = delta.expected_delta_id();
        delta.validate()?;
        self.deltas.insert(delta.delta_id.clone(), delta.clone());
        Ok(delta)
    }

    pub fn finalize_snapshot(
        &mut self,
        height: u64,
        block_root: &str,
        da_root: &str,
        settlement_anchor_root: &str,
        timestamp_ms: u64,
        operator_label: &str,
    ) -> StateResult<StateSnapshot> {
        if block_root.is_empty() {
            return Err("cannot finalize state snapshot with empty block_root".to_string());
        }
        let parent_snapshot_id = self.current_snapshot_id.clone();
        let parent_state_root = self
            .snapshots
            .get(&parent_snapshot_id)
            .map(StateSnapshot::state_root)
            .unwrap_or_else(|| empty_global_state_root());
        let root_vector = self.build_root_vector();
        let mut snapshot = StateSnapshot {
            snapshot_id: String::new(),
            height,
            block_root: block_root.to_string(),
            parent_snapshot_id,
            parent_state_root,
            root_vector,
            leaf_count: self.visible_leaf_count(),
            transaction_count: self.transaction_count,
            da_root: da_root.to_string(),
            settlement_anchor_root: settlement_anchor_root.to_string(),
            timestamp_ms,
            operator_label: operator_label.to_string(),
        };
        snapshot.snapshot_id = snapshot.expected_snapshot_id();
        snapshot.validate()?;
        self.current_height = height;
        self.current_snapshot_id = snapshot.snapshot_id.clone();
        self.snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn build_root_vector(&self) -> StateRootVector {
        let mut vector = StateRootVector::empty();
        for domain in StateDomain::all_builtin() {
            vector.set_domain_root(&domain, self.domain_root(&domain));
        }
        let custom_domains = self
            .leaves
            .values()
            .filter_map(|leaf| match &leaf.domain {
                StateDomain::Custom(label) => Some(label.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for label in custom_domains {
            let domain = StateDomain::Custom(label);
            vector.set_domain_root(&domain, self.domain_root(&domain));
        }
        vector
    }

    pub fn domain_root(&self, domain: &StateDomain) -> String {
        let leaves = self
            .leaves
            .values()
            .filter(|leaf| &leaf.domain == domain && !leaf.deleted)
            .map(StateLeaf::public_record)
            .collect::<Vec<_>>();
        if leaves.is_empty() {
            empty_domain_root(domain)
        } else {
            merkle_root(&domain.root_domain(), &leaves)
        }
    }

    pub fn visible_leaf_count(&self) -> u64 {
        self.leaves.values().filter(|leaf| !leaf.deleted).count() as u64
    }

    pub fn create_membership_proof(
        &self,
        snapshot_id: &str,
        domain: StateDomain,
        key: &str,
    ) -> StateResult<StateProof> {
        let snapshot = self
            .snapshots
            .get(snapshot_id)
            .ok_or_else(|| "unknown state snapshot".to_string())?;
        let leaf = self.get_leaf(&domain, key).cloned();
        let exists = leaf.as_ref().map(|leaf| !leaf.deleted).unwrap_or(false);
        let leaf_root = leaf
            .as_ref()
            .map(StateLeaf::root)
            .unwrap_or_else(|| non_membership_leaf_root(&domain, key));
        let proof_payload_root = state_value_root(&json!({
            "snapshot_id": snapshot_id,
            "domain": domain.label(),
            "key": key,
            "exists": exists,
            "leaf_root": leaf_root,
        }));
        let expected_domain_root = snapshot.root_vector.domain_root(&domain);
        let expected_state_root = snapshot.state_root();
        let mut proof = StateProof {
            proof_id: String::new(),
            snapshot_id: snapshot_id.to_string(),
            domain,
            key: key.to_string(),
            exists,
            leaf,
            leaf_root,
            proof_steps: Vec::new(),
            expected_domain_root,
            expected_state_root,
            proof_payload_root,
        };
        proof.proof_id = proof.expected_proof_id();
        proof.validate()?;
        Ok(proof)
    }

    pub fn verify_proof(&self, proof: &StateProof) -> StateResult<bool> {
        proof.validate()?;
        let snapshot = self
            .snapshots
            .get(&proof.snapshot_id)
            .ok_or_else(|| "unknown state snapshot".to_string())?;
        if proof.expected_state_root != snapshot.state_root() {
            return Ok(false);
        }
        if proof.expected_domain_root != snapshot.root_vector.domain_root(&proof.domain) {
            return Ok(false);
        }
        if proof.proof_steps.is_empty() {
            let direct_root = if proof.exists {
                self.domain_root(&proof.domain)
            } else {
                snapshot.root_vector.domain_root(&proof.domain)
            };
            return Ok(direct_root == proof.expected_domain_root);
        }
        proof
            .computed_domain_root()
            .map(|root| root == proof.expected_domain_root)
    }

    pub fn prune_before(
        &mut self,
        retain_after_height: u64,
        archive_manifest_root: &str,
    ) -> StateResult<StatePruneCheckpoint> {
        if archive_manifest_root.is_empty() {
            return Err("archive_manifest_root cannot be empty".to_string());
        }
        let before = self.leaves.len() as u64;
        self.leaves
            .retain(|_, leaf| leaf.height >= retain_after_height || !leaf.deleted);
        let retained = self.leaves.len() as u64;
        let pruned = before.saturating_sub(retained);
        let root_vector_root = self.build_root_vector().root();
        let mut checkpoint = StatePruneCheckpoint {
            checkpoint_id: String::new(),
            snapshot_id: self.current_snapshot_id.clone(),
            retain_after_height,
            pruned_leaf_count: pruned,
            retained_leaf_count: retained,
            root_vector_root,
            archive_manifest_root: archive_manifest_root.to_string(),
            created_at_height: self.current_height,
        };
        checkpoint.checkpoint_id = checkpoint.expected_checkpoint_id();
        checkpoint.validate()?;
        self.prune_checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn record_fork_conflict(
        &mut self,
        height: u64,
        left_snapshot_id: &str,
        right_snapshot_id: &str,
        conflict_domain: StateDomain,
        conflict_key: &str,
        reporter_label: &str,
    ) -> StateResult<StateForkEvidence> {
        let left = self
            .snapshots
            .get(left_snapshot_id)
            .ok_or_else(|| "unknown left snapshot".to_string())?;
        let right = self
            .snapshots
            .get(right_snapshot_id)
            .ok_or_else(|| "unknown right snapshot".to_string())?;
        let mut evidence = StateForkEvidence {
            evidence_id: String::new(),
            height,
            left_snapshot_id: left_snapshot_id.to_string(),
            right_snapshot_id: right_snapshot_id.to_string(),
            left_state_root: left.state_root(),
            right_state_root: right.state_root(),
            conflict_domain,
            conflict_key: conflict_key.to_string(),
            reporter_label: reporter_label.to_string(),
            reported_at_height: self.current_height,
        };
        evidence.evidence_id = evidence.expected_evidence_id();
        evidence.validate()?;
        self.fork_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        Ok(evidence)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_accumulator",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "current_snapshot_id": self.current_snapshot_id,
            "state_root": self.state_root(),
            "leaf_count": self.visible_leaf_count(),
            "snapshot_count": self.snapshots.len(),
            "delta_count": self.deltas.len(),
            "prune_checkpoint_count": self.prune_checkpoints.len(),
            "fork_evidence_count": self.fork_evidence.len(),
            "transaction_count": self.transaction_count,
        })
    }
}

pub fn state_leaf_id(domain: &StateDomain, key: &str, version: u64, height: u64) -> String {
    domain_hash(
        "STATE-LEAF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&domain.label()),
            HashPart::Str(key),
            HashPart::Int(version as i128),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn state_leaf_root(leaf: &StateLeaf) -> String {
    domain_hash(
        "STATE-LEAF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&leaf.domain.label()),
            HashPart::Str(&leaf.key),
            HashPart::Str(&leaf.value_root),
            HashPart::Int(leaf.version as i128),
            HashPart::Int(leaf.height as i128),
            HashPart::Json(&leaf.public_metadata),
            HashPart::Str(&leaf.private_payload_root),
            HashPart::Str(if leaf.deleted { "deleted" } else { "active" }),
        ],
        32,
    )
}

pub fn state_root_vector_root(vector: &StateRootVector) -> String {
    domain_hash(
        "STATE-ROOT-VECTOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&vector.accounts_root),
            HashPart::Str(&vector.contracts_root),
            HashPart::Str(&vector.defi_root),
            HashPart::Str(&vector.privacy_root),
            HashPart::Str(&vector.bridge_root),
            HashPart::Str(&vector.mempool_root),
            HashPart::Str(&vector.sequencer_root),
            HashPart::Str(&vector.governance_root),
            HashPart::Str(&vector.runtime_root),
            HashPart::Str(&vector.settlement_root),
            HashPart::Json(&json!(vector.custom_roots)),
        ],
        32,
    )
}

pub fn state_snapshot_id(
    height: u64,
    block_root: &str,
    parent_snapshot_id: &str,
    parent_state_root: &str,
    state_root: &str,
    leaf_count: u64,
    transaction_count: u64,
    da_root: &str,
    settlement_anchor_root: &str,
) -> String {
    domain_hash(
        "STATE-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(block_root),
            HashPart::Str(parent_snapshot_id),
            HashPart::Str(parent_state_root),
            HashPart::Str(state_root),
            HashPart::Int(leaf_count as i128),
            HashPart::Int(transaction_count as i128),
            HashPart::Str(da_root),
            HashPart::Str(settlement_anchor_root),
        ],
        32,
    )
}

pub fn state_delta_id(
    height: u64,
    prev_snapshot_id: &str,
    next_snapshot_id: &str,
    prev_state_root: &str,
    next_state_root: &str,
    operation_root: &str,
    transaction_root: &str,
    fee_root: &str,
    authorization_root: &str,
) -> String {
    domain_hash(
        "STATE-DELTA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(prev_snapshot_id),
            HashPart::Str(next_snapshot_id),
            HashPart::Str(prev_state_root),
            HashPart::Str(next_state_root),
            HashPart::Str(operation_root),
            HashPart::Str(transaction_root),
            HashPart::Str(fee_root),
            HashPart::Str(authorization_root),
        ],
        32,
    )
}

pub fn state_delta_root(delta: &StateDelta) -> String {
    domain_hash(
        "STATE-DELTA-ROOT",
        &[HashPart::Json(&delta.public_record())],
        32,
    )
}

pub fn state_proof_id(
    snapshot_id: &str,
    domain: &StateDomain,
    key: &str,
    exists: bool,
    leaf_root: &str,
    expected_domain_root: &str,
    expected_state_root: &str,
    proof_payload_root: &str,
) -> String {
    domain_hash(
        "STATE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(snapshot_id),
            HashPart::Str(&domain.label()),
            HashPart::Str(key),
            HashPart::Str(if exists { "exists" } else { "missing" }),
            HashPart::Str(leaf_root),
            HashPart::Str(expected_domain_root),
            HashPart::Str(expected_state_root),
            HashPart::Str(proof_payload_root),
        ],
        32,
    )
}

pub fn state_proof_root(proof: &StateProof) -> String {
    domain_hash(
        "STATE-PROOF-ROOT",
        &[HashPart::Json(&proof.public_record())],
        32,
    )
}

pub fn state_prune_checkpoint_id(
    snapshot_id: &str,
    retain_after_height: u64,
    pruned_leaf_count: u64,
    retained_leaf_count: u64,
    root_vector_root: &str,
    archive_manifest_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-PRUNE-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(snapshot_id),
            HashPart::Int(retain_after_height as i128),
            HashPart::Int(pruned_leaf_count as i128),
            HashPart::Int(retained_leaf_count as i128),
            HashPart::Str(root_vector_root),
            HashPart::Str(archive_manifest_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn state_fork_evidence_id(
    height: u64,
    left_snapshot_id: &str,
    right_snapshot_id: &str,
    left_state_root: &str,
    right_state_root: &str,
    conflict_domain: &StateDomain,
    conflict_key: &str,
    reporter_label: &str,
    reported_at_height: u64,
) -> String {
    domain_hash(
        "STATE-FORK-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(left_snapshot_id),
            HashPart::Str(right_snapshot_id),
            HashPart::Str(left_state_root),
            HashPart::Str(right_state_root),
            HashPart::Str(&conflict_domain.label()),
            HashPart::Str(conflict_key),
            HashPart::Str(&state_string_root(reporter_label)),
            HashPart::Int(reported_at_height as i128),
        ],
        32,
    )
}

pub fn state_string_root(value: &str) -> String {
    domain_hash("STATE-STRING-ROOT", &[HashPart::Str(value)], 32)
}

pub fn state_value_root(value: &Value) -> String {
    domain_hash("STATE-VALUE-ROOT", &[HashPart::Json(value)], 32)
}

pub fn empty_domain_root(domain: &StateDomain) -> String {
    domain_hash(
        "STATE-DOMAIN-EMPTY",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(&domain.label())],
        32,
    )
}

pub fn empty_global_state_root() -> String {
    StateRootVector::empty().root()
}

pub fn non_membership_leaf_root(domain: &StateDomain, key: &str) -> String {
    domain_hash(
        "STATE-NON-MEMBERSHIP-LEAF",
        &[HashPart::Str(&domain.label()), HashPart::Str(key)],
        32,
    )
}
