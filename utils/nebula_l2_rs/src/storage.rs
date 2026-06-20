use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        crypto_policy_root, sign_network_authorization, verify_network_authorization, Authorization,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type StorageResult<T> = Result<T, String>;

pub const STORAGE_SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBounds {
    pub max_snapshots: u64,
    pub max_checkpoints: u64,
    pub max_chunks: u64,
    pub max_retention_decisions: u64,
    pub max_restore_plans: u64,
    pub retain_recent_heights: u64,
}

impl Default for StorageBounds {
    fn default() -> Self {
        Self {
            max_snapshots: 1024,
            max_checkpoints: 1024,
            max_chunks: 8192,
            max_retention_decisions: 1024,
            max_restore_plans: 1024,
            retain_recent_heights: 128,
        }
    }
}

impl StorageBounds {
    pub fn public_record(&self) -> Value {
        json!({
            "max_snapshots": self.max_snapshots,
            "max_checkpoints": self.max_checkpoints,
            "max_chunks": self.max_chunks,
            "max_retention_decisions": self.max_retention_decisions,
            "max_restore_plans": self.max_restore_plans,
            "retain_recent_heights": self.retain_recent_heights,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageComponentRoots {
    pub note_root: String,
    pub nullifier_root: String,
    pub contract_root: String,
    pub wasm_runtime_root: String,
    pub account_root: String,
    pub asset_root: String,
    pub sealed_swap_settlement_receipt_root: String,
    pub bridge_root: String,
    pub fee_root: String,
    pub crypto_policy_root: String,
    pub custom_roots: BTreeMap<String, String>,
}

impl StorageComponentRoots {
    pub fn empty() -> Self {
        Self {
            note_root: merkle_root("NOTE", &[]),
            nullifier_root: merkle_root("NULLIFIER", &[]),
            contract_root: merkle_root("CONTRACT", &[]),
            wasm_runtime_root: merkle_root("WASM-RUNTIME", &[]),
            account_root: merkle_root("ACCOUNT", &[]),
            asset_root: merkle_root("ASSET", &[]),
            sealed_swap_settlement_receipt_root: merkle_root("SEALED-SWAP-SETTLEMENT-RECEIPT", &[]),
            bridge_root: merkle_root("BRIDGE", &[]),
            fee_root: merkle_root("FEE", &[]),
            crypto_policy_root: crypto_policy_root(),
            custom_roots: BTreeMap::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_root": self.note_root,
            "nullifier_root": self.nullifier_root,
            "contract_root": self.contract_root,
            "wasm_runtime_root": self.wasm_runtime_root,
            "account_root": self.account_root,
            "asset_root": self.asset_root,
            "sealed_swap_settlement_receipt_root": self.sealed_swap_settlement_receipt_root,
            "bridge_root": self.bridge_root,
            "fee_root": self.fee_root,
            "crypto_policy_root": self.crypto_policy_root,
            "custom_roots": self.custom_roots,
        })
    }

    pub fn component_root(&self) -> String {
        domain_hash(
            "STORAGE-COMPONENT-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for StorageComponentRoots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageServiceRoots {
    pub da_root: String,
    pub proof_root: String,
    pub consensus_root: String,
    pub monero_root: String,
    pub bridge_root: String,
    pub mempool_root: String,
    pub network_root: String,
    pub watchtower_root: String,
    pub custom_roots: BTreeMap<String, String>,
}

impl StorageServiceRoots {
    pub fn empty() -> Self {
        Self {
            da_root: merkle_root("DA", &[]),
            proof_root: merkle_root("PROOF", &[]),
            consensus_root: merkle_root("CONSENSUS", &[]),
            monero_root: merkle_root("MONERO", &[]),
            bridge_root: merkle_root("BRIDGE", &[]),
            mempool_root: merkle_root("MEMPOOL", &[]),
            network_root: merkle_root("NETWORK", &[]),
            watchtower_root: merkle_root("WATCHTOWER", &[]),
            custom_roots: BTreeMap::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "da_root": self.da_root,
            "proof_root": self.proof_root,
            "consensus_root": self.consensus_root,
            "monero_root": self.monero_root,
            "bridge_root": self.bridge_root,
            "mempool_root": self.mempool_root,
            "network_root": self.network_root,
            "watchtower_root": self.watchtower_root,
            "custom_roots": self.custom_roots,
        })
    }

    pub fn service_root(&self) -> String {
        domain_hash(
            "STORAGE-SERVICE-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for StorageServiceRoots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSnapshotRecord {
    pub snapshot_id: String,
    pub version: u64,
    pub chain_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub prev_block_hash: String,
    pub block_root: String,
    pub state_root: String,
    pub component_roots: StorageComponentRoots,
    pub service_roots: StorageServiceRoots,
    pub chunk_root: String,
    pub chunk_count: u64,
    pub created_at_ms: u64,
    pub finalized: bool,
}

impl StorageSnapshotRecord {
    pub fn new(
        block_height: u64,
        block_hash: impl Into<String>,
        prev_block_hash: impl Into<String>,
        block_root: impl Into<String>,
        state_root: impl Into<String>,
        component_roots: StorageComponentRoots,
        service_roots: StorageServiceRoots,
        chunk_root: impl Into<String>,
        chunk_count: u64,
        created_at_ms: u64,
        finalized: bool,
    ) -> Self {
        let mut snapshot = Self {
            snapshot_id: String::new(),
            version: STORAGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            block_height,
            block_hash: block_hash.into(),
            prev_block_hash: prev_block_hash.into(),
            block_root: block_root.into(),
            state_root: state_root.into(),
            component_roots,
            service_roots,
            chunk_root: chunk_root.into(),
            chunk_count,
            created_at_ms,
            finalized,
        };
        snapshot.snapshot_id = storage_snapshot_id(&snapshot.identity_record());
        snapshot
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "storage_snapshot",
            "version": self.version,
            "chain_id": self.chain_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "prev_block_hash": self.prev_block_hash,
            "block_root": self.block_root,
            "state_root": self.state_root,
            "component_roots": self.component_roots.public_record(),
            "component_root": self.component_roots.component_root(),
            "service_roots": self.service_roots.public_record(),
            "service_root": self.service_roots.service_root(),
            "chunk_root": self.chunk_root,
            "chunk_count": self.chunk_count,
            "created_at_ms": self.created_at_ms,
            "finalized": self.finalized,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.snapshot_id == storage_snapshot_id(&self.identity_record())
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("storage snapshot identity record object")
            .insert(
                "snapshot_id".to_string(),
                Value::String(self.snapshot_id.clone()),
            );
        record
    }

    pub fn snapshot_root(&self) -> String {
        domain_hash(
            "STORAGE-SNAPSHOT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("storage snapshot public record object")
            .insert(
                "snapshot_root".to_string(),
                Value::String(self.snapshot_root()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCheckpointRecord {
    pub checkpoint_id: String,
    pub version: u64,
    pub chain_id: String,
    pub snapshot_id: String,
    pub snapshot_root: String,
    pub manifest_root: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub component_root: String,
    pub service_root: String,
    pub chunk_root: String,
    pub created_at_ms: u64,
    pub authorization: Option<Authorization>,
}

impl StorageCheckpointRecord {
    pub fn from_snapshot(
        snapshot: &StorageSnapshotRecord,
        manifest_root: impl Into<String>,
        created_at_ms: u64,
    ) -> Self {
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            version: STORAGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            snapshot_id: snapshot.snapshot_id.clone(),
            snapshot_root: snapshot.snapshot_root(),
            manifest_root: manifest_root.into(),
            block_height: snapshot.block_height,
            block_hash: snapshot.block_hash.clone(),
            state_root: snapshot.state_root.clone(),
            component_root: snapshot.component_roots.component_root(),
            service_root: snapshot.service_roots.service_root(),
            chunk_root: snapshot.chunk_root.clone(),
            created_at_ms,
            authorization: None,
        };
        checkpoint.checkpoint_id = storage_checkpoint_id(&checkpoint.identity_record());
        checkpoint
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "storage_checkpoint",
            "version": self.version,
            "chain_id": self.chain_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_root": self.snapshot_root,
            "manifest_root": self.manifest_root,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "component_root": self.component_root,
            "service_root": self.service_root,
            "chunk_root": self.chunk_root,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.checkpoint_id == storage_checkpoint_id(&self.identity_record())
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("storage checkpoint identity record object")
            .insert(
                "checkpoint_id".to_string(),
                Value::String(self.checkpoint_id.clone()),
            );
        record
    }

    pub fn checkpoint_root(&self) -> String {
        domain_hash(
            "STORAGE-CHECKPOINT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn sign(&mut self, signer_label: &str) {
        self.authorization = Some(sign_network_authorization(
            signer_label,
            "storage_checkpoint",
            &self.unsigned_record(),
        ));
    }

    pub fn verify_authorization(&self) -> bool {
        self.authorization.as_ref().is_some_and(|authorization| {
            verify_network_authorization(
                &authorization.auth_public_key,
                "storage_checkpoint",
                &self.unsigned_record(),
                authorization,
            )
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("storage checkpoint public record object");
        object.insert(
            "checkpoint_root".to_string(),
            Value::String(self.checkpoint_root()),
        );
        if let Some(authorization) = &self.authorization {
            object.insert(
                "auth_scheme".to_string(),
                Value::String(authorization.auth_scheme.clone()),
            );
            object.insert(
                "auth_public_key".to_string(),
                Value::String(authorization.auth_public_key.clone()),
            );
            object.insert(
                "auth_transcript_hash".to_string(),
                Value::String(authorization.auth_transcript_hash.clone()),
            );
            object.insert(
                "auth_signature".to_string(),
                Value::String(authorization.auth_signature.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageChunkRecord {
    pub chunk_id: String,
    pub version: u64,
    pub chain_id: String,
    pub snapshot_id: Option<String>,
    pub namespace: String,
    pub ordinal: u64,
    pub byte_len: u64,
    pub payload_hash: String,
    pub payload_commitment: String,
    pub codec: String,
    pub encrypted: bool,
    pub created_at_ms: u64,
}

impl StorageChunkRecord {
    pub fn new(
        snapshot_id: Option<String>,
        namespace: impl Into<String>,
        ordinal: u64,
        byte_len: u64,
        payload_hash: impl Into<String>,
        payload_commitment: impl Into<String>,
        codec: impl Into<String>,
        encrypted: bool,
        created_at_ms: u64,
    ) -> Self {
        let mut chunk = Self {
            chunk_id: String::new(),
            version: STORAGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            snapshot_id,
            namespace: namespace.into(),
            ordinal,
            byte_len,
            payload_hash: payload_hash.into(),
            payload_commitment: payload_commitment.into(),
            codec: codec.into(),
            encrypted,
            created_at_ms,
        };
        chunk.chunk_id = storage_chunk_id(&chunk.identity_record());
        chunk
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "storage_chunk",
            "version": self.version,
            "chain_id": self.chain_id,
            "snapshot_id": self.snapshot_id,
            "namespace": self.namespace,
            "ordinal": self.ordinal,
            "byte_len": self.byte_len,
            "payload_hash": self.payload_hash,
            "payload_commitment": self.payload_commitment,
            "codec": self.codec,
            "encrypted": self.encrypted,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.chunk_id == storage_chunk_id(&self.identity_record())
    }

    pub fn chunk_root(&self) -> String {
        domain_hash(
            "STORAGE-CHUNK",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("storage chunk identity record object")
            .insert("chunk_id".to_string(), Value::String(self.chunk_id.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("storage chunk public record object")
            .insert("chunk_root".to_string(), Value::String(self.chunk_root()));
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRetentionDecision {
    pub decision_id: String,
    pub version: u64,
    pub chain_id: String,
    pub decision_kind: String,
    pub decided_at_height: u64,
    pub decided_at_ms: u64,
    pub retain_from_height: u64,
    pub prune_before_height: u64,
    pub retained_snapshot_ids: Vec<String>,
    pub pruned_snapshot_ids: Vec<String>,
    pub pruned_chunk_ids: Vec<String>,
    pub previous_manifest_root: String,
    pub reason: String,
}

impl StorageRetentionDecision {
    pub fn new(
        decision_kind: impl Into<String>,
        decided_at_height: u64,
        decided_at_ms: u64,
        retain_from_height: u64,
        prune_before_height: u64,
        retained_snapshot_ids: Vec<String>,
        pruned_snapshot_ids: Vec<String>,
        pruned_chunk_ids: Vec<String>,
        previous_manifest_root: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let mut decision = Self {
            decision_id: String::new(),
            version: STORAGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            decision_kind: decision_kind.into(),
            decided_at_height,
            decided_at_ms,
            retain_from_height,
            prune_before_height,
            retained_snapshot_ids,
            pruned_snapshot_ids,
            pruned_chunk_ids,
            previous_manifest_root: previous_manifest_root.into(),
            reason: reason.into(),
        };
        decision.decision_id = storage_retention_decision_id(&decision.identity_record());
        decision
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "storage_retention_decision",
            "version": self.version,
            "chain_id": self.chain_id,
            "decision_kind": self.decision_kind,
            "decided_at_height": self.decided_at_height,
            "decided_at_ms": self.decided_at_ms,
            "retain_from_height": self.retain_from_height,
            "prune_before_height": self.prune_before_height,
            "retained_snapshot_ids": self.retained_snapshot_ids,
            "pruned_snapshot_ids": self.pruned_snapshot_ids,
            "pruned_chunk_ids": self.pruned_chunk_ids,
            "previous_manifest_root": self.previous_manifest_root,
            "reason": self.reason,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.decision_id == storage_retention_decision_id(&self.identity_record())
    }

    pub fn decision_root(&self) -> String {
        domain_hash(
            "STORAGE-RETENTION-DECISION",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("storage retention decision identity record object")
            .insert(
                "decision_id".to_string(),
                Value::String(self.decision_id.clone()),
            );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("storage retention decision public record object")
            .insert(
                "decision_root".to_string(),
                Value::String(self.decision_root()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRestorePlan {
    pub restore_plan_id: String,
    pub version: u64,
    pub chain_id: String,
    pub target_snapshot_id: String,
    pub target_checkpoint_id: Option<String>,
    pub target_block_height: u64,
    pub target_block_hash: String,
    pub target_state_root: String,
    pub required_snapshot_ids: Vec<String>,
    pub required_checkpoint_ids: Vec<String>,
    pub required_chunk_ids: Vec<String>,
    pub expected_manifest_root: String,
    pub created_at_ms: u64,
    pub status: String,
}

impl StorageRestorePlan {
    pub fn new(
        target_snapshot_id: impl Into<String>,
        target_checkpoint_id: Option<String>,
        target_block_height: u64,
        target_block_hash: impl Into<String>,
        target_state_root: impl Into<String>,
        required_snapshot_ids: Vec<String>,
        required_checkpoint_ids: Vec<String>,
        required_chunk_ids: Vec<String>,
        expected_manifest_root: impl Into<String>,
        created_at_ms: u64,
        status: impl Into<String>,
    ) -> Self {
        let mut plan = Self {
            restore_plan_id: String::new(),
            version: STORAGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            target_snapshot_id: target_snapshot_id.into(),
            target_checkpoint_id,
            target_block_height,
            target_block_hash: target_block_hash.into(),
            target_state_root: target_state_root.into(),
            required_snapshot_ids,
            required_checkpoint_ids,
            required_chunk_ids,
            expected_manifest_root: expected_manifest_root.into(),
            created_at_ms,
            status: status.into(),
        };
        plan.restore_plan_id = storage_restore_plan_id(&plan.identity_record());
        plan
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "storage_restore_plan",
            "version": self.version,
            "chain_id": self.chain_id,
            "target_snapshot_id": self.target_snapshot_id,
            "target_checkpoint_id": self.target_checkpoint_id,
            "target_block_height": self.target_block_height,
            "target_block_hash": self.target_block_hash,
            "target_state_root": self.target_state_root,
            "required_snapshot_ids": self.required_snapshot_ids,
            "required_checkpoint_ids": self.required_checkpoint_ids,
            "required_chunk_ids": self.required_chunk_ids,
            "expected_manifest_root": self.expected_manifest_root,
            "created_at_ms": self.created_at_ms,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.restore_plan_id == storage_restore_plan_id(&self.identity_record())
    }

    pub fn restore_plan_root(&self) -> String {
        domain_hash(
            "STORAGE-RESTORE-PLAN",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("storage restore plan identity record object")
            .insert(
                "restore_plan_id".to_string(),
                Value::String(self.restore_plan_id.clone()),
            );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("storage restore plan public record object")
            .insert(
                "restore_plan_root".to_string(),
                Value::String(self.restore_plan_root()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageJournalEntry {
    pub sequence: u64,
    pub entry_id: String,
    pub previous_entry_id: Option<String>,
    pub entry_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub snapshot_id: Option<String>,
    pub block_height: Option<u64>,
    pub recorded_at_ms: u64,
}

impl StorageJournalEntry {
    pub fn new(
        sequence: u64,
        previous_entry_id: Option<String>,
        entry_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        snapshot_id: Option<String>,
        block_height: Option<u64>,
        recorded_at_ms: u64,
    ) -> Self {
        let mut entry = Self {
            sequence,
            entry_id: String::new(),
            previous_entry_id,
            entry_kind: entry_kind.into(),
            subject_id: subject_id.into(),
            subject_root: subject_root.into(),
            snapshot_id,
            block_height,
            recorded_at_ms,
        };
        entry.entry_id = storage_journal_entry_id(&entry.identity_record());
        entry
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "storage_journal_entry",
            "chain_id": CHAIN_ID,
            "sequence": self.sequence,
            "previous_entry_id": self.previous_entry_id,
            "entry_kind": self.entry_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "snapshot_id": self.snapshot_id,
            "block_height": self.block_height,
            "recorded_at_ms": self.recorded_at_ms,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.entry_id == storage_journal_entry_id(&self.identity_record())
    }

    pub fn entry_root(&self) -> String {
        domain_hash(
            "STORAGE-JOURNAL-ENTRY",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("storage journal entry identity record object")
            .insert("entry_id".to_string(), Value::String(self.entry_id.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("storage journal entry public record object")
            .insert("entry_root".to_string(), Value::String(self.entry_root()));
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageState {
    pub bounds: StorageBounds,
    pub snapshots: BTreeMap<String, StorageSnapshotRecord>,
    pub checkpoints: BTreeMap<String, StorageCheckpointRecord>,
    pub chunks: BTreeMap<String, StorageChunkRecord>,
    pub retention_decisions: BTreeMap<String, StorageRetentionDecision>,
    pub restore_plans: BTreeMap<String, StorageRestorePlan>,
    pub journal: Vec<StorageJournalEntry>,
}

impl Default for StorageState {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageState {
    pub fn new() -> Self {
        Self::bounded(StorageBounds::default())
    }

    pub fn bounded(bounds: StorageBounds) -> Self {
        Self {
            bounds,
            snapshots: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            chunks: BTreeMap::new(),
            retention_decisions: BTreeMap::new(),
            restore_plans: BTreeMap::new(),
            journal: Vec::new(),
        }
    }

    pub fn latest_snapshot_id(&self) -> Option<String> {
        self.snapshots
            .values()
            .max_by_key(|snapshot| snapshot.block_height)
            .map(|snapshot| snapshot.snapshot_id.clone())
    }

    pub fn latest_checkpoint_id(&self) -> Option<String> {
        self.checkpoints
            .values()
            .max_by_key(|checkpoint| checkpoint.block_height)
            .map(|checkpoint| checkpoint.checkpoint_id.clone())
    }

    pub fn latest_journal_entry_id(&self) -> Option<String> {
        self.journal.last().map(|entry| entry.entry_id.clone())
    }

    pub fn insert_snapshot(&mut self, snapshot: StorageSnapshotRecord) -> StorageResult<()> {
        if !snapshot.verify_id() {
            return Err("storage snapshot id mismatch".to_string());
        }
        ensure_room(
            self.snapshots.len(),
            self.bounds.max_snapshots,
            "storage snapshot",
        )?;
        insert_unique_record(
            &mut self.snapshots,
            snapshot.snapshot_id.clone(),
            snapshot.clone(),
            "storage snapshot",
        )?;
        let snapshot_id = snapshot.snapshot_id.clone();
        self.append_journal_entry(
            "snapshot",
            snapshot_id.clone(),
            snapshot.snapshot_root(),
            Some(snapshot_id),
            Some(snapshot.block_height),
            snapshot.created_at_ms,
        );
        Ok(())
    }

    pub fn insert_checkpoint(&mut self, checkpoint: StorageCheckpointRecord) -> StorageResult<()> {
        if !checkpoint.verify_id() {
            return Err("storage checkpoint id mismatch".to_string());
        }
        if checkpoint.authorization.is_some() && !checkpoint.verify_authorization() {
            return Err("storage checkpoint authorization failed".to_string());
        }
        if !self.snapshots.contains_key(&checkpoint.snapshot_id) {
            return Err("storage checkpoint references unknown snapshot".to_string());
        }
        ensure_room(
            self.checkpoints.len(),
            self.bounds.max_checkpoints,
            "storage checkpoint",
        )?;
        insert_unique_record(
            &mut self.checkpoints,
            checkpoint.checkpoint_id.clone(),
            checkpoint.clone(),
            "storage checkpoint",
        )?;
        self.append_journal_entry(
            "checkpoint",
            checkpoint.checkpoint_id.clone(),
            checkpoint.checkpoint_root(),
            Some(checkpoint.snapshot_id.clone()),
            Some(checkpoint.block_height),
            checkpoint.created_at_ms,
        );
        Ok(())
    }

    pub fn insert_chunk(&mut self, chunk: StorageChunkRecord) -> StorageResult<()> {
        if !chunk.verify_id() {
            return Err("storage chunk id mismatch".to_string());
        }
        ensure_room(self.chunks.len(), self.bounds.max_chunks, "storage chunk")?;
        insert_unique_record(
            &mut self.chunks,
            chunk.chunk_id.clone(),
            chunk.clone(),
            "storage chunk",
        )?;
        self.append_journal_entry(
            "chunk",
            chunk.chunk_id.clone(),
            chunk.chunk_root(),
            chunk.snapshot_id.clone(),
            None,
            chunk.created_at_ms,
        );
        Ok(())
    }

    pub fn record_retention_decision(
        &mut self,
        decision: StorageRetentionDecision,
    ) -> StorageResult<()> {
        if !decision.verify_id() {
            return Err("storage retention decision id mismatch".to_string());
        }
        ensure_room(
            self.retention_decisions.len(),
            self.bounds.max_retention_decisions,
            "storage retention decision",
        )?;
        insert_unique_record(
            &mut self.retention_decisions,
            decision.decision_id.clone(),
            decision.clone(),
            "storage retention decision",
        )?;
        self.append_journal_entry(
            "retention_decision",
            decision.decision_id.clone(),
            decision.decision_root(),
            None,
            Some(decision.decided_at_height),
            decision.decided_at_ms,
        );
        Ok(())
    }

    pub fn record_restore_plan(&mut self, plan: StorageRestorePlan) -> StorageResult<()> {
        if !plan.verify_id() {
            return Err("storage restore plan id mismatch".to_string());
        }
        ensure_room(
            self.restore_plans.len(),
            self.bounds.max_restore_plans,
            "storage restore plan",
        )?;
        insert_unique_record(
            &mut self.restore_plans,
            plan.restore_plan_id.clone(),
            plan.clone(),
            "storage restore plan",
        )?;
        self.append_journal_entry(
            "restore_plan",
            plan.restore_plan_id.clone(),
            plan.restore_plan_root(),
            Some(plan.target_snapshot_id.clone()),
            Some(plan.target_block_height),
            plan.created_at_ms,
        );
        Ok(())
    }

    pub fn snapshot_root(&self) -> String {
        storage_snapshot_root(&self.snapshots.values().cloned().collect::<Vec<_>>())
    }

    pub fn checkpoint_root(&self) -> String {
        storage_checkpoint_root(&self.checkpoints.values().cloned().collect::<Vec<_>>())
    }

    pub fn chunk_root(&self) -> String {
        storage_chunk_root(&self.chunks.values().cloned().collect::<Vec<_>>())
    }

    pub fn retention_decision_root(&self) -> String {
        storage_retention_decision_root(
            &self
                .retention_decisions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn restore_plan_root(&self) -> String {
        storage_restore_plan_root(&self.restore_plans.values().cloned().collect::<Vec<_>>())
    }

    pub fn journal_root(&self) -> String {
        storage_journal_root(&self.journal)
    }

    pub fn unsigned_manifest_record(&self) -> Value {
        json!({
            "kind": "storage_manifest",
            "version": STORAGE_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "bounds": self.bounds.public_record(),
            "snapshot_root": self.snapshot_root(),
            "checkpoint_root": self.checkpoint_root(),
            "chunk_root": self.chunk_root(),
            "retention_decision_root": self.retention_decision_root(),
            "restore_plan_root": self.restore_plan_root(),
            "journal_root": self.journal_root(),
            "snapshot_count": self.snapshots.len() as u64,
            "checkpoint_count": self.checkpoints.len() as u64,
            "chunk_count": self.chunks.len() as u64,
            "retention_decision_count": self.retention_decisions.len() as u64,
            "restore_plan_count": self.restore_plans.len() as u64,
            "journal_entry_count": self.journal.len() as u64,
            "latest_snapshot_id": self.latest_snapshot_id(),
            "latest_checkpoint_id": self.latest_checkpoint_id(),
            "latest_journal_entry_id": self.latest_journal_entry_id(),
        })
    }

    pub fn manifest_root(&self) -> String {
        domain_hash(
            "STORAGE-MANIFEST",
            &[HashPart::Json(&self.unsigned_manifest_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_manifest_record();
        record
            .as_object_mut()
            .expect("storage manifest public record object")
            .insert(
                "manifest_root".to_string(),
                Value::String(self.manifest_root()),
            );
        record
    }

    fn append_journal_entry(
        &mut self,
        entry_kind: &str,
        subject_id: String,
        subject_root: String,
        snapshot_id: Option<String>,
        block_height: Option<u64>,
        recorded_at_ms: u64,
    ) {
        let entry = StorageJournalEntry::new(
            self.journal.len() as u64,
            self.latest_journal_entry_id(),
            entry_kind,
            subject_id,
            subject_root,
            snapshot_id,
            block_height,
            recorded_at_ms,
        );
        self.journal.push(entry);
    }
}

pub fn storage_snapshot_id(record: &Value) -> String {
    domain_hash("STORAGE-SNAPSHOT-ID", &[HashPart::Json(record)], 32)
}

pub fn storage_checkpoint_id(record: &Value) -> String {
    domain_hash("STORAGE-CHECKPOINT-ID", &[HashPart::Json(record)], 32)
}

pub fn storage_chunk_id(record: &Value) -> String {
    domain_hash("STORAGE-CHUNK-ID", &[HashPart::Json(record)], 32)
}

pub fn storage_retention_decision_id(record: &Value) -> String {
    domain_hash(
        "STORAGE-RETENTION-DECISION-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn storage_restore_plan_id(record: &Value) -> String {
    domain_hash("STORAGE-RESTORE-PLAN-ID", &[HashPart::Json(record)], 32)
}

pub fn storage_journal_entry_id(record: &Value) -> String {
    domain_hash("STORAGE-JOURNAL-ENTRY-ID", &[HashPart::Json(record)], 32)
}

pub fn storage_snapshot_root(snapshots: &[StorageSnapshotRecord]) -> String {
    merkle_root(
        "STORAGE-SNAPSHOT",
        &snapshots
            .iter()
            .map(StorageSnapshotRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn storage_checkpoint_root(checkpoints: &[StorageCheckpointRecord]) -> String {
    merkle_root(
        "STORAGE-CHECKPOINT",
        &checkpoints
            .iter()
            .map(StorageCheckpointRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn storage_chunk_root(chunks: &[StorageChunkRecord]) -> String {
    merkle_root(
        "STORAGE-CHUNK",
        &chunks
            .iter()
            .map(StorageChunkRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn storage_retention_decision_root(decisions: &[StorageRetentionDecision]) -> String {
    merkle_root(
        "STORAGE-RETENTION-DECISION",
        &decisions
            .iter()
            .map(StorageRetentionDecision::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn storage_restore_plan_root(plans: &[StorageRestorePlan]) -> String {
    merkle_root(
        "STORAGE-RESTORE-PLAN",
        &plans
            .iter()
            .map(StorageRestorePlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn storage_journal_root(entries: &[StorageJournalEntry]) -> String {
    merkle_root(
        "STORAGE-JOURNAL",
        &entries
            .iter()
            .map(StorageJournalEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_room(current_len: usize, max_len: u64, label: &str) -> StorageResult<()> {
    if max_len > 0 && (current_len as u64) >= max_len {
        return Err(format!("{label} bound exceeded"));
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> StorageResult<()> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id, record);
    Ok(())
}
