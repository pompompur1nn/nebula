use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const INDEXER_PROTOCOL_VERSION: &str = "nebula-indexer-v1";
pub const INDEXER_EVENT_DOMAIN_ACCOUNT: &str = "account";
pub const INDEXER_EVENT_DOMAIN_CONTRACT: &str = "contract";
pub const INDEXER_EVENT_DOMAIN_TOKEN: &str = "token";
pub const INDEXER_EVENT_DOMAIN_ORACLE: &str = "oracle";
pub const INDEXER_EVENT_DOMAIN_BRIDGE: &str = "bridge";
pub const INDEXER_EVENT_VISIBILITY_PUBLIC: &str = "public";
pub const INDEXER_EVENT_VISIBILITY_COMMITTED: &str = "committed";
pub const INDEXER_QUERY_SCOPE_EVENTS: &str = "events";
pub const INDEXER_QUERY_DEFAULT_LIMIT: u64 = 64;
pub const INDEXER_QUERY_MAX_LIMIT: u64 = 512;
pub const INDEXER_DEFAULT_CURSOR_TTL_BLOCKS: u64 = 32;
pub const INDEXER_DEFAULT_SUBSCRIPTION_TTL_BLOCKS: u64 = 128;
pub const INDEXER_DEFAULT_RECEIPT_ACK_BLOCKS: u64 = 4;
pub const INDEXER_CHECKPOINT_FINALITY_DEPTH: u64 = 2;
pub const INDEXER_SUBSCRIPTION_STATUS_ACTIVE: &str = "active";
pub const INDEXER_SUBSCRIPTION_STATUS_PAUSED: &str = "paused";
pub const INDEXER_SUBSCRIPTION_STATUS_EXPIRED: &str = "expired";
pub const INDEXER_RECEIPT_STATUS_DELIVERED: &str = "delivered";
pub const INDEXER_RECEIPT_STATUS_ACKED: &str = "acked";
pub const INDEXER_RECEIPT_STATUS_EXPIRED: &str = "expired";

pub type IndexerResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerEventInput {
    pub event_kind: String,
    pub subject_id: String,
    pub tx_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub event_index: u64,
    pub topics: Vec<String>,
    pub payload: Value,
    pub source_root: String,
    pub previous_event_root: String,
    pub visibility: String,
}

impl IndexerEventInput {
    pub fn new(
        event_kind: impl Into<String>,
        subject_id: impl Into<String>,
        tx_hash: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        event_index: u64,
        payload: Value,
    ) -> Self {
        Self {
            event_kind: event_kind.into(),
            subject_id: subject_id.into(),
            tx_hash: tx_hash.into(),
            block_height,
            block_hash: block_hash.into(),
            event_index,
            topics: Vec::new(),
            payload,
            source_root: indexer_empty_root("event-source"),
            previous_event_root: indexer_empty_root("event-chain"),
            visibility: INDEXER_EVENT_VISIBILITY_PUBLIC.to_string(),
        }
    }

    pub fn with_topics(mut self, topics: Vec<String>) -> Self {
        self.topics = topics;
        self
    }

    pub fn with_source_root(mut self, source_root: impl Into<String>) -> Self {
        self.source_root = source_root.into();
        self
    }

    pub fn with_previous_event_root(mut self, previous_event_root: impl Into<String>) -> Self {
        self.previous_event_root = previous_event_root.into();
        self
    }

    pub fn committed(mut self) -> Self {
        self.visibility = INDEXER_EVENT_VISIBILITY_COMMITTED.to_string();
        self
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.event_kind.is_empty() {
            return Err("indexer event kind cannot be empty".to_string());
        }
        if self.subject_id.is_empty() {
            return Err("indexer event subject cannot be empty".to_string());
        }
        if self.tx_hash.is_empty() {
            return Err("indexer event tx_hash cannot be empty".to_string());
        }
        if self.block_hash.is_empty() {
            return Err("indexer event block_hash cannot be empty".to_string());
        }
        if self.source_root.is_empty() {
            return Err("indexer event source_root cannot be empty".to_string());
        }
        if self.previous_event_root.is_empty() {
            return Err("indexer event previous_event_root cannot be empty".to_string());
        }
        validate_event_visibility(&self.visibility)?;
        Ok(indexer_payload_root(&self.payload))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedEvent {
    pub event_id: String,
    pub event_domain: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_commitment: String,
    pub tx_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub event_index: u64,
    pub topic_root: String,
    pub topics: Vec<String>,
    pub payload_root: String,
    pub public_payload: Value,
    pub source_root: String,
    pub previous_event_root: String,
    pub visibility: String,
}

impl IndexedEvent {
    pub fn from_input(event_domain: &str, input: IndexerEventInput) -> IndexerResult<Self> {
        validate_event_domain(event_domain)?;
        let payload_root = input.validate()?;
        let subject_commitment = indexer_subject_commitment(event_domain, &input.subject_id);
        let topic_root = indexer_topic_root(&input.topics);
        let public_payload = if input.visibility == INDEXER_EVENT_VISIBILITY_PUBLIC {
            input.payload.clone()
        } else {
            Value::Null
        };
        let event_id = indexer_event_id(
            event_domain,
            &input.event_kind,
            &subject_commitment,
            &input.tx_hash,
            input.block_height,
            &input.block_hash,
            input.event_index,
            &topic_root,
            &payload_root,
            &input.source_root,
            &input.previous_event_root,
        );
        Ok(Self {
            event_id,
            event_domain: event_domain.to_string(),
            event_kind: input.event_kind,
            subject_id: input.subject_id,
            subject_commitment,
            tx_hash: input.tx_hash,
            block_height: input.block_height,
            block_hash: input.block_hash,
            event_index: input.event_index,
            topic_root,
            topics: input.topics,
            payload_root,
            public_payload,
            source_root: input.source_root,
            previous_event_root: input.previous_event_root,
            visibility: input.visibility,
        })
    }

    pub fn account(input: IndexerEventInput) -> IndexerResult<Self> {
        Self::from_input(INDEXER_EVENT_DOMAIN_ACCOUNT, input)
    }

    pub fn contract(input: IndexerEventInput) -> IndexerResult<Self> {
        Self::from_input(INDEXER_EVENT_DOMAIN_CONTRACT, input)
    }

    pub fn token(input: IndexerEventInput) -> IndexerResult<Self> {
        Self::from_input(INDEXER_EVENT_DOMAIN_TOKEN, input)
    }

    pub fn oracle(input: IndexerEventInput) -> IndexerResult<Self> {
        Self::from_input(INDEXER_EVENT_DOMAIN_ORACLE, input)
    }

    pub fn bridge(input: IndexerEventInput) -> IndexerResult<Self> {
        Self::from_input(INDEXER_EVENT_DOMAIN_BRIDGE, input)
    }

    pub fn expected_event_id(&self) -> String {
        indexer_event_id(
            &self.event_domain,
            &self.event_kind,
            &self.subject_commitment,
            &self.tx_hash,
            self.block_height,
            &self.block_hash,
            self.event_index,
            &self.topic_root,
            &self.payload_root,
            &self.source_root,
            &self.previous_event_root,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        validate_event_domain(&self.event_domain)?;
        validate_event_visibility(&self.visibility)?;
        if self.event_kind.is_empty() || self.event_id.is_empty() {
            return Err("indexer event identifiers cannot be empty".to_string());
        }
        if self.subject_id.is_empty() || self.subject_commitment.is_empty() {
            return Err("indexer event subject cannot be empty".to_string());
        }
        if self.tx_hash.is_empty() || self.block_hash.is_empty() {
            return Err("indexer event block anchors cannot be empty".to_string());
        }
        if self.topic_root != indexer_topic_root(&self.topics) {
            return Err("indexer event topic root mismatch".to_string());
        }
        if self.subject_commitment
            != indexer_subject_commitment(&self.event_domain, &self.subject_id)
        {
            return Err("indexer event subject commitment mismatch".to_string());
        }
        if self.visibility == INDEXER_EVENT_VISIBILITY_PUBLIC
            && self.payload_root != indexer_payload_root(&self.public_payload)
        {
            return Err("indexer event payload root mismatch".to_string());
        }
        if self.visibility == INDEXER_EVENT_VISIBILITY_COMMITTED && !self.public_payload.is_null() {
            return Err("committed indexer event cannot expose public payload".to_string());
        }
        if self.event_id != self.expected_event_id() {
            return Err("indexer event id mismatch".to_string());
        }
        Ok(self.event_id.clone())
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!({
            "kind": "indexed_event",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_domain": self.event_domain,
            "event_kind": self.event_kind,
            "subject_commitment": self.subject_commitment,
            "tx_hash": self.tx_hash,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "event_index": self.event_index,
            "topic_root": self.topic_root,
            "payload_root": self.payload_root,
            "source_root": self.source_root,
            "previous_event_root": self.previous_event_root,
            "visibility": self.visibility,
        });
        if self.visibility == INDEXER_EVENT_VISIBILITY_PUBLIC {
            record
                .as_object_mut()
                .expect("indexed event public record object")
                .insert("public_payload".to_string(), self.public_payload.clone());
        }
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("indexed event state record object");
        object.insert(
            "subject_id".to_string(),
            Value::String(self.subject_id.clone()),
        );
        object.insert("topics".to_string(), json!(self.topics));
        object.insert("public_payload".to_string(), self.public_payload.clone());
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerBlockAnchor {
    pub anchor_id: String,
    pub height: u64,
    pub block_hash: String,
    pub indexed_at_height: u64,
    pub source_root: String,
}

impl IndexerBlockAnchor {
    pub fn new(
        height: u64,
        block_hash: &str,
        indexed_at_height: u64,
        source_root: &str,
    ) -> IndexerResult<Self> {
        if block_hash.is_empty() || source_root.is_empty() {
            return Err("indexer block anchor hash and source root are required".to_string());
        }
        let anchor_id = indexer_block_anchor_id(height, block_hash, indexed_at_height, source_root);
        Ok(Self {
            anchor_id,
            height,
            block_hash: block_hash.to_string(),
            indexed_at_height,
            source_root: source_root.to_string(),
        })
    }

    pub fn expected_anchor_id(&self) -> String {
        indexer_block_anchor_id(
            self.height,
            &self.block_hash,
            self.indexed_at_height,
            &self.source_root,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.anchor_id.is_empty() || self.block_hash.is_empty() || self.source_root.is_empty() {
            return Err("indexer block anchor identifiers cannot be empty".to_string());
        }
        if self.anchor_id != self.expected_anchor_id() {
            return Err("indexer block anchor id mismatch".to_string());
        }
        Ok(self.anchor_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_block_anchor",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "anchor_id": self.anchor_id,
            "height": self.height,
            "block_hash": self.block_hash,
            "indexed_at_height": self.indexed_at_height,
            "source_root": self.source_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerBlockManifestEntry {
    pub entry_id: String,
    pub height: u64,
    pub block_hash: String,
    pub event_root: String,
    pub event_count: u64,
    pub checkpoint_id: String,
    pub checkpoint_root: String,
}

impl IndexerBlockManifestEntry {
    pub fn new(
        height: u64,
        block_hash: &str,
        events: &[IndexedEvent],
        checkpoint: Option<&IndexerEventCheckpoint>,
    ) -> IndexerResult<Self> {
        if block_hash.is_empty() {
            return Err("indexer block manifest entry block_hash is required".to_string());
        }
        for event in events {
            if event.block_height != height || event.block_hash != block_hash {
                return Err("indexer block manifest entry event anchor mismatch".to_string());
            }
        }
        let event_root = indexer_event_root(events);
        let (checkpoint_id, checkpoint_root) = checkpoint
            .map(|checkpoint| {
                (
                    checkpoint.checkpoint_id.clone(),
                    checkpoint.checkpoint_root(),
                )
            })
            .unwrap_or_else(|| (String::new(), indexer_empty_root("block-checkpoint")));
        let entry_id = indexer_block_manifest_entry_id(
            height,
            block_hash,
            &event_root,
            events.len() as u64,
            &checkpoint_root,
        );
        Ok(Self {
            entry_id,
            height,
            block_hash: block_hash.to_string(),
            event_root,
            event_count: events.len() as u64,
            checkpoint_id,
            checkpoint_root,
        })
    }

    pub fn expected_entry_id(&self) -> String {
        indexer_block_manifest_entry_id(
            self.height,
            &self.block_hash,
            &self.event_root,
            self.event_count,
            &self.checkpoint_root,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.entry_id.is_empty() || self.block_hash.is_empty() {
            return Err("indexer block manifest entry identifiers cannot be empty".to_string());
        }
        if self.event_root.is_empty() || self.checkpoint_root.is_empty() {
            return Err("indexer block manifest entry roots cannot be empty".to_string());
        }
        if self.entry_id != self.expected_entry_id() {
            return Err("indexer block manifest entry id mismatch".to_string());
        }
        Ok(self.entry_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_block_manifest_entry",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "height": self.height,
            "block_hash": self.block_hash,
            "event_root": self.event_root,
            "event_count": self.event_count,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_root": self.checkpoint_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerBlockRangeManifest {
    pub manifest_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub entry_root: String,
    pub event_root: String,
    pub checkpoint_root: String,
    pub event_count: u64,
    pub checkpoint_count: u64,
    pub previous_manifest_root: String,
    pub generated_at_height: u64,
    pub entries: Vec<IndexerBlockManifestEntry>,
}

impl IndexerBlockRangeManifest {
    pub fn new(
        from_height: u64,
        to_height: u64,
        entries: Vec<IndexerBlockManifestEntry>,
        events: &[IndexedEvent],
        checkpoints: &[IndexerEventCheckpoint],
        previous_manifest_root: &str,
        generated_at_height: u64,
    ) -> IndexerResult<Self> {
        if from_height > to_height {
            return Err("indexer block range manifest height range is invalid".to_string());
        }
        if entries.is_empty() {
            return Err("indexer block range manifest requires entries".to_string());
        }
        if previous_manifest_root.is_empty() {
            return Err("indexer block range manifest previous root is required".to_string());
        }
        let entry_root = indexer_block_manifest_entry_root(&entries);
        let event_root = indexer_event_root(events);
        let checkpoint_root = indexer_event_checkpoint_root(checkpoints);
        let manifest_id = indexer_block_range_manifest_id(
            from_height,
            to_height,
            &entry_root,
            &event_root,
            &checkpoint_root,
            events.len() as u64,
            checkpoints.len() as u64,
            previous_manifest_root,
            generated_at_height,
        );
        let manifest = Self {
            manifest_id,
            from_height,
            to_height,
            entry_root,
            event_root,
            checkpoint_root,
            event_count: events.len() as u64,
            checkpoint_count: checkpoints.len() as u64,
            previous_manifest_root: previous_manifest_root.to_string(),
            generated_at_height,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn expected_manifest_id(&self) -> String {
        indexer_block_range_manifest_id(
            self.from_height,
            self.to_height,
            &self.entry_root,
            &self.event_root,
            &self.checkpoint_root,
            self.event_count,
            self.checkpoint_count,
            &self.previous_manifest_root,
            self.generated_at_height,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.manifest_id.is_empty() {
            return Err("indexer block range manifest id cannot be empty".to_string());
        }
        if self.from_height > self.to_height {
            return Err("indexer block range manifest height range is invalid".to_string());
        }
        if self.entries.is_empty() {
            return Err("indexer block range manifest requires entries".to_string());
        }
        if self.previous_manifest_root.is_empty() {
            return Err("indexer block range manifest previous root is required".to_string());
        }
        let mut heights = self
            .entries
            .iter()
            .map(|entry| entry.height)
            .collect::<Vec<_>>();
        heights.sort_unstable();
        if heights.first().copied() != Some(self.from_height)
            || heights.last().copied() != Some(self.to_height)
        {
            return Err("indexer block range manifest does not span declared heights".to_string());
        }
        for window in heights.windows(2) {
            if window[1] != window[0] + 1 {
                return Err("indexer block range manifest contains a height gap".to_string());
            }
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        if self.entry_root != indexer_block_manifest_entry_root(&self.entries) {
            return Err("indexer block range manifest entry root mismatch".to_string());
        }
        if self.manifest_id != self.expected_manifest_id() {
            return Err("indexer block range manifest id mismatch".to_string());
        }
        Ok(self.manifest_id.clone())
    }

    pub fn manifest_root(&self) -> String {
        indexer_block_range_manifest_root(&[self.clone()])
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_block_range_manifest",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "entry_root": self.entry_root,
            "event_root": self.event_root,
            "checkpoint_root": self.checkpoint_root,
            "event_count": self.event_count,
            "checkpoint_count": self.checkpoint_count,
            "previous_manifest_root": self.previous_manifest_root,
            "generated_at_height": self.generated_at_height,
            "entries": self.entries.iter().map(IndexerBlockManifestEntry::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerEventCheckpoint {
    pub checkpoint_id: String,
    pub sequence: u64,
    pub block_height: u64,
    pub block_hash: String,
    pub event_root: String,
    pub event_count: u64,
    pub first_event_id: String,
    pub last_event_id: String,
    pub previous_checkpoint_root: String,
    pub cumulative_event_root: String,
    pub replay_guard_root: String,
    pub finalized: bool,
}

impl IndexerEventCheckpoint {
    pub fn new(
        sequence: u64,
        block_height: u64,
        block_hash: &str,
        events: &[IndexedEvent],
        previous_checkpoint_root: &str,
        finalized: bool,
    ) -> IndexerResult<Self> {
        if sequence == 0 {
            return Err("indexer checkpoint sequence must be positive".to_string());
        }
        if block_hash.is_empty() {
            return Err("indexer checkpoint block_hash is required".to_string());
        }
        if previous_checkpoint_root.is_empty() {
            return Err("indexer checkpoint previous root is required".to_string());
        }
        for event in events {
            if event.block_height != block_height || event.block_hash != block_hash {
                return Err("indexer checkpoint event anchor mismatch".to_string());
            }
        }
        let ordered = ordered_events(events);
        let event_root = indexer_event_root(&ordered);
        let first_event_id = ordered
            .first()
            .map(|event| event.event_id.clone())
            .unwrap_or_default();
        let last_event_id = ordered
            .last()
            .map(|event| event.event_id.clone())
            .unwrap_or_default();
        let replay_guard_root = indexer_replay_guard_root(
            sequence,
            block_height,
            block_hash,
            &event_root,
            previous_checkpoint_root,
        );
        let cumulative_event_root = indexer_cumulative_event_root(
            previous_checkpoint_root,
            &event_root,
            &replay_guard_root,
        );
        let checkpoint_id = indexer_event_checkpoint_id(
            sequence,
            block_height,
            block_hash,
            &event_root,
            ordered.len() as u64,
            previous_checkpoint_root,
            &cumulative_event_root,
            &replay_guard_root,
            finalized,
        );
        Ok(Self {
            checkpoint_id,
            sequence,
            block_height,
            block_hash: block_hash.to_string(),
            event_root,
            event_count: ordered.len() as u64,
            first_event_id,
            last_event_id,
            previous_checkpoint_root: previous_checkpoint_root.to_string(),
            cumulative_event_root,
            replay_guard_root,
            finalized,
        })
    }

    pub fn expected_checkpoint_id(&self) -> String {
        indexer_event_checkpoint_id(
            self.sequence,
            self.block_height,
            &self.block_hash,
            &self.event_root,
            self.event_count,
            &self.previous_checkpoint_root,
            &self.cumulative_event_root,
            &self.replay_guard_root,
            self.finalized,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.sequence == 0 {
            return Err("indexer checkpoint sequence must be positive".to_string());
        }
        if self.checkpoint_id.is_empty() || self.block_hash.is_empty() {
            return Err("indexer checkpoint identifiers cannot be empty".to_string());
        }
        if self.event_root.is_empty()
            || self.previous_checkpoint_root.is_empty()
            || self.cumulative_event_root.is_empty()
            || self.replay_guard_root.is_empty()
        {
            return Err("indexer checkpoint roots cannot be empty".to_string());
        }
        if self.event_count == 0
            && (!self.first_event_id.is_empty() || !self.last_event_id.is_empty())
        {
            return Err("empty indexer checkpoint cannot carry event ids".to_string());
        }
        if self.event_count > 0 && (self.first_event_id.is_empty() || self.last_event_id.is_empty())
        {
            return Err("indexer checkpoint event ids are required".to_string());
        }
        let expected_replay_guard_root = indexer_replay_guard_root(
            self.sequence,
            self.block_height,
            &self.block_hash,
            &self.event_root,
            &self.previous_checkpoint_root,
        );
        if self.replay_guard_root != expected_replay_guard_root {
            return Err("indexer checkpoint replay guard mismatch".to_string());
        }
        if self.cumulative_event_root
            != indexer_cumulative_event_root(
                &self.previous_checkpoint_root,
                &self.event_root,
                &self.replay_guard_root,
            )
        {
            return Err("indexer checkpoint cumulative root mismatch".to_string());
        }
        if self.checkpoint_id != self.expected_checkpoint_id() {
            return Err("indexer checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_id.clone())
    }

    pub fn checkpoint_root(&self) -> String {
        domain_hash(
            "INDEXER-EVENT-CHECKPOINT-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_event_checkpoint",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "sequence": self.sequence,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "event_root": self.event_root,
            "event_count": self.event_count,
            "first_event_id": self.first_event_id,
            "last_event_id": self.last_event_id,
            "previous_checkpoint_root": self.previous_checkpoint_root,
            "cumulative_event_root": self.cumulative_event_root,
            "replay_guard_root": self.replay_guard_root,
            "finalized": self.finalized,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerQueryFilter {
    pub event_domains: Vec<String>,
    pub event_kinds: Vec<String>,
    pub subject_commitments: Vec<String>,
    pub topic_roots: Vec<String>,
    pub from_height: u64,
    pub to_height: u64,
    pub include_committed_payloads: bool,
    pub limit: u64,
}

impl IndexerQueryFilter {
    pub fn all() -> Self {
        Self {
            event_domains: Vec::new(),
            event_kinds: Vec::new(),
            subject_commitments: Vec::new(),
            topic_roots: Vec::new(),
            from_height: 0,
            to_height: 0,
            include_committed_payloads: false,
            limit: INDEXER_QUERY_DEFAULT_LIMIT,
        }
    }

    pub fn for_subject(event_domain: &str, subject_id: &str) -> IndexerResult<Self> {
        validate_event_domain(event_domain)?;
        Ok(Self {
            event_domains: vec![event_domain.to_string()],
            subject_commitments: vec![indexer_subject_commitment(event_domain, subject_id)],
            ..Self::all()
        })
    }

    pub fn with_event_kind(mut self, event_kind: impl Into<String>) -> Self {
        self.event_kinds.push(event_kind.into());
        self
    }

    pub fn with_height_range(mut self, from_height: u64, to_height: u64) -> Self {
        self.from_height = from_height;
        self.to_height = to_height;
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    pub fn filter_root(&self) -> String {
        indexer_query_filter_root(self)
    }

    pub fn subject_root(&self) -> String {
        indexer_query_subject_root(&self.subject_commitments)
    }

    pub fn validate(&self) -> IndexerResult<String> {
        for domain in &self.event_domains {
            validate_event_domain(domain)?;
        }
        if self.to_height != 0 && self.from_height > self.to_height {
            return Err("indexer query filter height range is invalid".to_string());
        }
        if self.limit == 0 || self.limit > INDEXER_QUERY_MAX_LIMIT {
            return Err("indexer query filter limit is out of range".to_string());
        }
        Ok(self.filter_root())
    }

    pub fn matches_event(&self, event: &IndexedEvent) -> bool {
        if !self.event_domains.is_empty() && !self.event_domains.contains(&event.event_domain) {
            return false;
        }
        if !self.event_kinds.is_empty() && !self.event_kinds.contains(&event.event_kind) {
            return false;
        }
        if !self.subject_commitments.is_empty()
            && !self.subject_commitments.contains(&event.subject_commitment)
        {
            return false;
        }
        if !self.topic_roots.is_empty() && !self.topic_roots.contains(&event.topic_root) {
            return false;
        }
        if event.block_height < self.from_height {
            return false;
        }
        if self.to_height != 0 && event.block_height > self.to_height {
            return false;
        }
        self.include_committed_payloads || event.visibility == INDEXER_EVENT_VISIBILITY_PUBLIC
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_query_filter",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "event_domains": sorted_strings(&self.event_domains),
            "event_kinds": sorted_strings(&self.event_kinds),
            "subject_commitment_root": indexer_query_subject_root(&self.subject_commitments),
            "topic_root": indexer_query_topic_root(&self.topic_roots),
            "from_height": self.from_height,
            "to_height": self.to_height,
            "include_committed_payloads": self.include_committed_payloads,
            "limit": self.limit,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerQueryCursor {
    pub cursor_id: String,
    pub scope: String,
    pub subject_commitment: String,
    pub filter_root: String,
    pub after_height: u64,
    pub after_event_index: u64,
    pub after_event_id: String,
    pub page_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub cursor_commitment: String,
    pub cursor_nonce: String,
}

impl IndexerQueryCursor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &str,
        subject_commitment: &str,
        filter_root: &str,
        after_height: u64,
        after_event_index: u64,
        after_event_id: &str,
        page_size: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        cursor_nonce: &str,
    ) -> IndexerResult<Self> {
        if scope.is_empty() || subject_commitment.is_empty() || filter_root.is_empty() {
            return Err("indexer cursor scope and roots are required".to_string());
        }
        if page_size == 0 || page_size > INDEXER_QUERY_MAX_LIMIT {
            return Err("indexer cursor page_size is out of range".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("indexer cursor must expire after it is issued".to_string());
        }
        if cursor_nonce.is_empty() {
            return Err("indexer cursor nonce is required".to_string());
        }
        let cursor_commitment =
            indexer_query_cursor_commitment(subject_commitment, filter_root, cursor_nonce);
        let cursor_id = indexer_query_cursor_id(
            scope,
            subject_commitment,
            filter_root,
            after_height,
            after_event_index,
            after_event_id,
            page_size,
            issued_at_height,
            expires_at_height,
            &cursor_commitment,
        );
        Ok(Self {
            cursor_id,
            scope: scope.to_string(),
            subject_commitment: subject_commitment.to_string(),
            filter_root: filter_root.to_string(),
            after_height,
            after_event_index,
            after_event_id: after_event_id.to_string(),
            page_size,
            issued_at_height,
            expires_at_height,
            cursor_commitment,
            cursor_nonce: cursor_nonce.to_string(),
        })
    }

    pub fn expected_cursor_id(&self) -> String {
        indexer_query_cursor_id(
            &self.scope,
            &self.subject_commitment,
            &self.filter_root,
            self.after_height,
            self.after_event_index,
            &self.after_event_id,
            self.page_size,
            self.issued_at_height,
            self.expires_at_height,
            &self.cursor_commitment,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.scope.is_empty()
            || self.subject_commitment.is_empty()
            || self.filter_root.is_empty()
            || self.cursor_id.is_empty()
            || self.cursor_commitment.is_empty()
            || self.cursor_nonce.is_empty()
        {
            return Err("indexer cursor identifiers cannot be empty".to_string());
        }
        if self.page_size == 0 || self.page_size > INDEXER_QUERY_MAX_LIMIT {
            return Err("indexer cursor page_size is out of range".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("indexer cursor must expire after it is issued".to_string());
        }
        if self.cursor_commitment
            != indexer_query_cursor_commitment(
                &self.subject_commitment,
                &self.filter_root,
                &self.cursor_nonce,
            )
        {
            return Err("indexer cursor commitment mismatch".to_string());
        }
        if self.cursor_id != self.expected_cursor_id() {
            return Err("indexer cursor id mismatch".to_string());
        }
        Ok(self.cursor_id.clone())
    }

    pub fn cursor_root(&self) -> String {
        domain_hash(
            "INDEXER-QUERY-CURSOR-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_query_cursor",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "cursor_id": self.cursor_id,
            "scope": self.scope,
            "subject_commitment": self.subject_commitment,
            "filter_root": self.filter_root,
            "after_height": self.after_height,
            "after_event_index": self.after_event_index,
            "after_event_id": self.after_event_id,
            "page_size": self.page_size,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "cursor_commitment": self.cursor_commitment,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("indexer cursor state record object")
            .insert(
                "cursor_nonce".to_string(),
                Value::String(self.cursor_nonce.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerQueryAuthorization {
    pub authorization_id: String,
    pub requester_commitment: String,
    pub scope: String,
    pub filter_root: String,
    pub cursor_root: String,
    pub allowed_event_root: String,
    pub policy_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub proof_system: String,
}

impl IndexerQueryAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_commitment: &str,
        scope: &str,
        filter_root: &str,
        cursor_root: &str,
        allowed_event_root: &str,
        policy_root: &str,
        issued_at_height: u64,
        expires_at_height: u64,
        proof_system: &str,
    ) -> IndexerResult<Self> {
        if requester_commitment.is_empty()
            || scope.is_empty()
            || filter_root.is_empty()
            || cursor_root.is_empty()
            || allowed_event_root.is_empty()
            || policy_root.is_empty()
            || proof_system.is_empty()
        {
            return Err("indexer query authorization roots are required".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("indexer query authorization must expire after issue height".to_string());
        }
        let authorization_id = indexer_query_authorization_id(
            requester_commitment,
            scope,
            filter_root,
            cursor_root,
            allowed_event_root,
            policy_root,
            issued_at_height,
            expires_at_height,
            proof_system,
        );
        Ok(Self {
            authorization_id,
            requester_commitment: requester_commitment.to_string(),
            scope: scope.to_string(),
            filter_root: filter_root.to_string(),
            cursor_root: cursor_root.to_string(),
            allowed_event_root: allowed_event_root.to_string(),
            policy_root: policy_root.to_string(),
            issued_at_height,
            expires_at_height,
            proof_system: proof_system.to_string(),
        })
    }

    pub fn expected_authorization_id(&self) -> String {
        indexer_query_authorization_id(
            &self.requester_commitment,
            &self.scope,
            &self.filter_root,
            &self.cursor_root,
            &self.allowed_event_root,
            &self.policy_root,
            self.issued_at_height,
            self.expires_at_height,
            &self.proof_system,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.authorization_id.is_empty()
            || self.requester_commitment.is_empty()
            || self.scope.is_empty()
            || self.filter_root.is_empty()
            || self.cursor_root.is_empty()
            || self.allowed_event_root.is_empty()
            || self.policy_root.is_empty()
            || self.proof_system.is_empty()
        {
            return Err("indexer query authorization identifiers cannot be empty".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("indexer query authorization must expire after issue height".to_string());
        }
        if self.authorization_id != self.expected_authorization_id() {
            return Err("indexer query authorization id mismatch".to_string());
        }
        Ok(self.authorization_id.clone())
    }

    pub fn authorization_root(&self) -> String {
        domain_hash(
            "INDEXER-QUERY-AUTHORIZATION-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_query_authorization",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "requester_commitment": self.requester_commitment,
            "scope": self.scope,
            "filter_root": self.filter_root,
            "cursor_root": self.cursor_root,
            "allowed_event_root": self.allowed_event_root,
            "policy_root": self.policy_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "proof_system": self.proof_system,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerSubscription {
    pub subscription_id: String,
    pub subscriber_commitment: String,
    pub filter: IndexerQueryFilter,
    pub filter_root: String,
    pub min_confirmations: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
    pub subscription_commitment: String,
    pub subscription_nonce: String,
}

impl IndexerSubscription {
    pub fn new(
        subscriber_commitment: &str,
        filter: IndexerQueryFilter,
        min_confirmations: u64,
        created_at_height: u64,
        expires_at_height: u64,
        subscription_nonce: &str,
    ) -> IndexerResult<Self> {
        if subscriber_commitment.is_empty() || subscription_nonce.is_empty() {
            return Err("indexer subscription subscriber and nonce are required".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("indexer subscription must expire after creation".to_string());
        }
        let filter_root = filter.validate()?;
        let subscription_commitment = indexer_subscription_commitment(
            subscriber_commitment,
            &filter_root,
            subscription_nonce,
        );
        let subscription_id = indexer_subscription_id(
            subscriber_commitment,
            &filter_root,
            min_confirmations,
            created_at_height,
            expires_at_height,
            &subscription_commitment,
        );
        Ok(Self {
            subscription_id,
            subscriber_commitment: subscriber_commitment.to_string(),
            filter,
            filter_root,
            min_confirmations,
            created_at_height,
            expires_at_height,
            status: INDEXER_SUBSCRIPTION_STATUS_ACTIVE.to_string(),
            subscription_commitment,
            subscription_nonce: subscription_nonce.to_string(),
        })
    }

    pub fn expected_subscription_id(&self) -> String {
        indexer_subscription_id(
            &self.subscriber_commitment,
            &self.filter_root,
            self.min_confirmations,
            self.created_at_height,
            self.expires_at_height,
            &self.subscription_commitment,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.subscription_id.is_empty()
            || self.subscriber_commitment.is_empty()
            || self.filter_root.is_empty()
            || self.subscription_commitment.is_empty()
            || self.subscription_nonce.is_empty()
        {
            return Err("indexer subscription identifiers cannot be empty".to_string());
        }
        if !matches!(
            self.status.as_str(),
            INDEXER_SUBSCRIPTION_STATUS_ACTIVE
                | INDEXER_SUBSCRIPTION_STATUS_PAUSED
                | INDEXER_SUBSCRIPTION_STATUS_EXPIRED
        ) {
            return Err("indexer subscription status is unknown".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("indexer subscription must expire after creation".to_string());
        }
        if self.filter_root != self.filter.validate()? {
            return Err("indexer subscription filter root mismatch".to_string());
        }
        if self.subscription_commitment
            != indexer_subscription_commitment(
                &self.subscriber_commitment,
                &self.filter_root,
                &self.subscription_nonce,
            )
        {
            return Err("indexer subscription commitment mismatch".to_string());
        }
        if self.subscription_id != self.expected_subscription_id() {
            return Err("indexer subscription id mismatch".to_string());
        }
        Ok(self.subscription_id.clone())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == INDEXER_SUBSCRIPTION_STATUS_ACTIVE
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn matches_event(&self, event: &IndexedEvent, observed_at_height: u64) -> bool {
        self.is_active_at(observed_at_height)
            && event.block_height.saturating_add(self.min_confirmations) <= observed_at_height
            && self.filter.matches_event(event)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_subscription",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "subscription_id": self.subscription_id,
            "subscriber_commitment": self.subscriber_commitment,
            "filter_root": self.filter_root,
            "min_confirmations": self.min_confirmations,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
            "subscription_commitment": self.subscription_commitment,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("indexer subscription state record object");
        object.insert("filter".to_string(), self.filter.public_record());
        object.insert(
            "subscription_nonce".to_string(),
            Value::String(self.subscription_nonce.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerSubscriptionReceipt {
    pub receipt_id: String,
    pub subscription_id: String,
    pub subscriber_commitment: String,
    pub cursor_id: String,
    pub event_id: String,
    pub event_public_root: String,
    pub delivery_root: String,
    pub delivered_at_height: u64,
    pub ack_deadline_height: u64,
    pub expires_at_height: u64,
    pub status: String,
    pub receipt_nonce: String,
}

impl IndexerSubscriptionReceipt {
    pub fn new(
        subscription: &IndexerSubscription,
        event: &IndexedEvent,
        cursor_id: &str,
        delivered_at_height: u64,
        receipt_nonce: &str,
    ) -> IndexerResult<Self> {
        if cursor_id.is_empty() || receipt_nonce.is_empty() {
            return Err("indexer subscription receipt cursor and nonce are required".to_string());
        }
        subscription.validate()?;
        event.validate()?;
        let event_public_root = domain_hash(
            "INDEXER-SUBSCRIPTION-EVENT-PUBLIC",
            &[HashPart::Json(&event.public_record())],
            32,
        );
        let delivery_root = indexer_subscription_delivery_root(
            &subscription.subscription_id,
            cursor_id,
            &event.event_id,
            &event_public_root,
            delivered_at_height,
        );
        let ack_deadline_height =
            delivered_at_height.saturating_add(INDEXER_DEFAULT_RECEIPT_ACK_BLOCKS);
        let expires_at_height =
            ack_deadline_height.saturating_add(INDEXER_DEFAULT_CURSOR_TTL_BLOCKS);
        let receipt_id = indexer_subscription_receipt_id(
            &subscription.subscription_id,
            &subscription.subscriber_commitment,
            cursor_id,
            &event.event_id,
            &delivery_root,
            delivered_at_height,
            receipt_nonce,
        );
        Ok(Self {
            receipt_id,
            subscription_id: subscription.subscription_id.clone(),
            subscriber_commitment: subscription.subscriber_commitment.clone(),
            cursor_id: cursor_id.to_string(),
            event_id: event.event_id.clone(),
            event_public_root,
            delivery_root,
            delivered_at_height,
            ack_deadline_height,
            expires_at_height,
            status: INDEXER_RECEIPT_STATUS_DELIVERED.to_string(),
            receipt_nonce: receipt_nonce.to_string(),
        })
    }

    pub fn expected_receipt_id(&self) -> String {
        indexer_subscription_receipt_id(
            &self.subscription_id,
            &self.subscriber_commitment,
            &self.cursor_id,
            &self.event_id,
            &self.delivery_root,
            self.delivered_at_height,
            &self.receipt_nonce,
        )
    }

    pub fn validate(&self) -> IndexerResult<String> {
        if self.receipt_id.is_empty()
            || self.subscription_id.is_empty()
            || self.subscriber_commitment.is_empty()
            || self.cursor_id.is_empty()
            || self.event_id.is_empty()
            || self.event_public_root.is_empty()
            || self.delivery_root.is_empty()
            || self.receipt_nonce.is_empty()
        {
            return Err("indexer subscription receipt identifiers cannot be empty".to_string());
        }
        if !matches!(
            self.status.as_str(),
            INDEXER_RECEIPT_STATUS_DELIVERED
                | INDEXER_RECEIPT_STATUS_ACKED
                | INDEXER_RECEIPT_STATUS_EXPIRED
        ) {
            return Err("indexer subscription receipt status is unknown".to_string());
        }
        if self.ack_deadline_height < self.delivered_at_height
            || self.expires_at_height < self.ack_deadline_height
        {
            return Err("indexer subscription receipt deadline order is invalid".to_string());
        }
        if self.receipt_id != self.expected_receipt_id() {
            return Err("indexer subscription receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_subscription_receipt",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "subscription_id": self.subscription_id,
            "subscriber_commitment": self.subscriber_commitment,
            "cursor_id": self.cursor_id,
            "event_id": self.event_id,
            "event_public_root": self.event_public_root,
            "delivery_root": self.delivery_root,
            "delivered_at_height": self.delivered_at_height,
            "ack_deadline_height": self.ack_deadline_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("indexer subscription receipt state record object")
            .insert(
                "receipt_nonce".to_string(),
                Value::String(self.receipt_nonce.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerQueryPage {
    pub page_id: String,
    pub filter_root: String,
    pub cursor_root: String,
    pub authorization_id: String,
    pub event_root: String,
    pub events: Vec<IndexedEvent>,
    pub next_cursor: Option<IndexerQueryCursor>,
    pub returned_count: u64,
    pub more_results: bool,
}

impl IndexerQueryPage {
    pub fn new(
        filter_root: &str,
        cursor_root: &str,
        authorization_id: &str,
        events: Vec<IndexedEvent>,
        next_cursor: Option<IndexerQueryCursor>,
        more_results: bool,
    ) -> Self {
        let event_root = indexer_event_root(&events);
        let next_cursor_root = next_cursor
            .as_ref()
            .map(IndexerQueryCursor::cursor_root)
            .unwrap_or_else(|| indexer_empty_root("next-cursor"));
        let page_id = indexer_query_page_id(
            filter_root,
            cursor_root,
            authorization_id,
            &event_root,
            &next_cursor_root,
            events.len() as u64,
            more_results,
        );
        Self {
            page_id,
            filter_root: filter_root.to_string(),
            cursor_root: cursor_root.to_string(),
            authorization_id: authorization_id.to_string(),
            event_root,
            returned_count: events.len() as u64,
            events,
            next_cursor,
            more_results,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_query_page",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "page_id": self.page_id,
            "filter_root": self.filter_root,
            "cursor_root": self.cursor_root,
            "authorization_id": self.authorization_id,
            "event_root": self.event_root,
            "events": self.events.iter().map(IndexedEvent::public_record).collect::<Vec<_>>(),
            "next_cursor": self.next_cursor.as_ref().map(IndexerQueryCursor::public_record),
            "returned_count": self.returned_count,
            "more_results": self.more_results,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerState {
    pub height: u64,
    pub block_anchors: BTreeMap<u64, IndexerBlockAnchor>,
    pub events: BTreeMap<String, IndexedEvent>,
    pub events_by_block: BTreeMap<u64, Vec<String>>,
    pub events_by_subject: BTreeMap<String, Vec<String>>,
    pub event_positions: BTreeMap<String, String>,
    pub block_hash_by_height: BTreeMap<u64, String>,
    pub checkpoints: BTreeMap<String, IndexerEventCheckpoint>,
    pub manifests: BTreeMap<String, IndexerBlockRangeManifest>,
    pub cursors: BTreeMap<String, IndexerQueryCursor>,
    pub query_authorizations: BTreeMap<String, IndexerQueryAuthorization>,
    pub subscriptions: BTreeMap<String, IndexerSubscription>,
    pub subscription_receipts: BTreeMap<String, IndexerSubscriptionReceipt>,
    pub last_checkpoint_root: String,
    pub last_manifest_root: String,
}

impl IndexerState {
    pub fn new() -> Self {
        Self {
            height: 0,
            block_anchors: BTreeMap::new(),
            events: BTreeMap::new(),
            events_by_block: BTreeMap::new(),
            events_by_subject: BTreeMap::new(),
            event_positions: BTreeMap::new(),
            block_hash_by_height: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            manifests: BTreeMap::new(),
            cursors: BTreeMap::new(),
            query_authorizations: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            subscription_receipts: BTreeMap::new(),
            last_checkpoint_root: indexer_empty_root("checkpoint"),
            last_manifest_root: indexer_empty_root("manifest"),
        }
    }

    pub fn index_account_event(&mut self, input: IndexerEventInput) -> IndexerResult<String> {
        self.apply_event(IndexedEvent::account(input)?)
    }

    pub fn index_contract_event(&mut self, input: IndexerEventInput) -> IndexerResult<String> {
        self.apply_event(IndexedEvent::contract(input)?)
    }

    pub fn index_token_event(&mut self, input: IndexerEventInput) -> IndexerResult<String> {
        self.apply_event(IndexedEvent::token(input)?)
    }

    pub fn index_oracle_event(&mut self, input: IndexerEventInput) -> IndexerResult<String> {
        self.apply_event(IndexedEvent::oracle(input)?)
    }

    pub fn index_bridge_event(&mut self, input: IndexerEventInput) -> IndexerResult<String> {
        self.apply_event(IndexedEvent::bridge(input)?)
    }

    pub fn apply_block_anchor(&mut self, anchor: IndexerBlockAnchor) -> IndexerResult<String> {
        let anchor_id = anchor.validate()?;
        if let Some(existing) = self.block_anchors.get(&anchor.height) {
            if existing.block_hash == anchor.block_hash {
                return Err("indexer block anchor already applied".to_string());
            }
            return Err("indexer block anchor conflicts with indexed height".to_string());
        }
        if let Some(existing_block_hash) = self.block_hash_by_height.get(&anchor.height) {
            if existing_block_hash != &anchor.block_hash {
                return Err("indexer block anchor conflicts with indexed block hash".to_string());
            }
        }
        self.height = self.height.max(anchor.indexed_at_height).max(anchor.height);
        self.block_hash_by_height
            .insert(anchor.height, anchor.block_hash.clone());
        self.block_anchors.insert(anchor.height, anchor);
        Ok(anchor_id)
    }

    pub fn apply_event(&mut self, event: IndexedEvent) -> IndexerResult<String> {
        let event_id = event.validate()?;
        if self.events.contains_key(&event_id) {
            return Err("indexer event already applied".to_string());
        }
        if let Some(existing_block_hash) = self.block_hash_by_height.get(&event.block_height) {
            if existing_block_hash != &event.block_hash {
                return Err("indexer event conflicts with indexed block hash".to_string());
            }
        }
        self.ensure_block_anchor(event.block_height, &event.block_hash, &event.source_root)?;
        let position_key = indexer_event_position_key(event.block_height, event.event_index);
        if self.event_positions.contains_key(&position_key) {
            return Err("indexer event position already occupied".to_string());
        }
        self.height = self.height.max(event.block_height);
        self.block_hash_by_height
            .insert(event.block_height, event.block_hash.clone());
        self.event_positions
            .insert(position_key, event.event_id.clone());
        self.events_by_block
            .entry(event.block_height)
            .or_default()
            .push(event.event_id.clone());
        self.events_by_subject
            .entry(event.subject_commitment.clone())
            .or_default()
            .push(event.event_id.clone());
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn apply_events(&mut self, events: Vec<IndexedEvent>) -> IndexerResult<String> {
        for event in events {
            self.apply_event(event)?;
        }
        Ok(self.event_root())
    }

    pub fn checkpoint_block(
        &mut self,
        block_height: u64,
        finalized: bool,
    ) -> IndexerResult<String> {
        let block_hash = self
            .block_hash_by_height
            .get(&block_height)
            .cloned()
            .ok_or_else(|| "indexer checkpoint block is not indexed".to_string())?;
        let events = self.events_for_height(block_height);
        let checkpoint = IndexerEventCheckpoint::new(
            self.checkpoints.len() as u64 + 1,
            block_height,
            &block_hash,
            &events,
            &self.last_checkpoint_root,
            finalized,
        )?;
        self.apply_event_checkpoint(checkpoint)
    }

    pub fn apply_event_checkpoint(
        &mut self,
        checkpoint: IndexerEventCheckpoint,
    ) -> IndexerResult<String> {
        let checkpoint_id = checkpoint.validate()?;
        if self.checkpoints.contains_key(&checkpoint_id) {
            return Err("indexer checkpoint already applied".to_string());
        }
        if checkpoint.sequence != self.checkpoints.len() as u64 + 1 {
            return Err("indexer checkpoint sequence is not next".to_string());
        }
        if checkpoint.previous_checkpoint_root != self.last_checkpoint_root {
            return Err("indexer checkpoint previous root mismatch".to_string());
        }
        let events = self.events_for_height(checkpoint.block_height);
        if checkpoint.event_root != indexer_event_root(&events) {
            return Err("indexer checkpoint event root does not match indexed block".to_string());
        }
        if checkpoint.event_count != events.len() as u64 {
            return Err("indexer checkpoint event count mismatch".to_string());
        }
        let checkpoint_root = checkpoint.checkpoint_root();
        self.height = self.height.max(checkpoint.block_height);
        self.last_checkpoint_root = checkpoint_root;
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        Ok(checkpoint_id)
    }

    pub fn build_block_range_manifest(
        &mut self,
        from_height: u64,
        to_height: u64,
        generated_at_height: u64,
    ) -> IndexerResult<String> {
        if from_height > to_height {
            return Err("indexer manifest height range is invalid".to_string());
        }
        let mut entries = Vec::new();
        let mut manifest_events = Vec::new();
        for height in from_height..=to_height {
            let anchor = self
                .block_anchors
                .get(&height)
                .cloned()
                .ok_or_else(|| "indexer manifest block height is not indexed".to_string())?;
            let events = self.events_for_height(height);
            manifest_events.extend(events.iter().cloned());
            let checkpoint = self
                .checkpoints
                .values()
                .find(|checkpoint| checkpoint.block_height == height)
                .cloned();
            entries.push(IndexerBlockManifestEntry::new(
                height,
                &anchor.block_hash,
                &events,
                checkpoint.as_ref(),
            )?);
        }
        let checkpoints = self
            .checkpoints
            .values()
            .filter(|checkpoint| {
                checkpoint.block_height >= from_height && checkpoint.block_height <= to_height
            })
            .cloned()
            .collect::<Vec<_>>();
        let manifest = IndexerBlockRangeManifest::new(
            from_height,
            to_height,
            entries,
            &manifest_events,
            &checkpoints,
            &self.last_manifest_root,
            generated_at_height,
        )?;
        self.apply_block_range_manifest(manifest)
    }

    pub fn apply_block_range_manifest(
        &mut self,
        manifest: IndexerBlockRangeManifest,
    ) -> IndexerResult<String> {
        let manifest_id = manifest.validate()?;
        if self.manifests.contains_key(&manifest_id) {
            return Err("indexer block range manifest already applied".to_string());
        }
        if manifest.previous_manifest_root != self.last_manifest_root {
            return Err("indexer block range manifest previous root mismatch".to_string());
        }
        let manifest_root = manifest.manifest_root();
        self.height = self.height.max(manifest.generated_at_height);
        self.last_manifest_root = manifest_root;
        self.manifests.insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn apply_query_cursor(&mut self, cursor: IndexerQueryCursor) -> IndexerResult<String> {
        let cursor_id = cursor.validate()?;
        if self.cursors.contains_key(&cursor_id) {
            return Err("indexer query cursor already exists".to_string());
        }
        self.cursors.insert(cursor_id.clone(), cursor);
        Ok(cursor_id)
    }

    pub fn create_query_cursor(
        &mut self,
        filter: &IndexerQueryFilter,
        page_size: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
        cursor_nonce: &str,
    ) -> IndexerResult<String> {
        let filter_root = filter.validate()?;
        let cursor = IndexerQueryCursor::new(
            INDEXER_QUERY_SCOPE_EVENTS,
            &filter.subject_root(),
            &filter_root,
            0,
            0,
            "",
            page_size,
            issued_at_height,
            issued_at_height.saturating_add(ttl_blocks.max(1)),
            cursor_nonce,
        )?;
        self.apply_query_cursor(cursor)
    }

    pub fn query_events(
        &self,
        filter: &IndexerQueryFilter,
        cursor: Option<&IndexerQueryCursor>,
        authorization_id: &str,
        next_cursor_nonce: &str,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> IndexerResult<IndexerQueryPage> {
        let filter_root = filter.validate()?;
        let subject_root = filter.subject_root();
        let (cursor_root, after_height, after_event_index, after_event_id, page_size) =
            if let Some(cursor) = cursor {
                cursor.validate()?;
                if cursor.scope != INDEXER_QUERY_SCOPE_EVENTS {
                    return Err("indexer query cursor scope mismatch".to_string());
                }
                if cursor.subject_commitment != subject_root || cursor.filter_root != filter_root {
                    return Err("indexer query cursor does not match filter".to_string());
                }
                if self.height > cursor.expires_at_height {
                    return Err("indexer query cursor expired".to_string());
                }
                (
                    cursor.cursor_root(),
                    cursor.after_height,
                    cursor.after_event_index,
                    cursor.after_event_id.clone(),
                    cursor.page_size,
                )
            } else {
                (
                    indexer_empty_root("query-cursor"),
                    0,
                    0,
                    String::new(),
                    filter.limit,
                )
            };
        let mut matches = self
            .events
            .values()
            .filter(|event| filter.matches_event(event))
            .filter(|event| {
                event_after_cursor(event, after_height, after_event_index, &after_event_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        matches = ordered_events(&matches);
        let limit = page_size.min(INDEXER_QUERY_MAX_LIMIT) as usize;
        let more_results = matches.len() > limit;
        let events = matches.into_iter().take(limit).collect::<Vec<_>>();
        let next_cursor = if more_results {
            events
                .last()
                .map(|event| {
                    IndexerQueryCursor::new(
                        INDEXER_QUERY_SCOPE_EVENTS,
                        &subject_root,
                        &filter_root,
                        event.block_height,
                        event.event_index,
                        &event.event_id,
                        page_size,
                        issued_at_height,
                        issued_at_height.saturating_add(ttl_blocks.max(1)),
                        next_cursor_nonce,
                    )
                })
                .transpose()?
        } else {
            None
        };
        Ok(IndexerQueryPage::new(
            &filter_root,
            &cursor_root,
            authorization_id,
            events,
            next_cursor,
            more_results,
        ))
    }

    pub fn authorize_query(
        &mut self,
        requester_label: &str,
        filter: &IndexerQueryFilter,
        cursor: Option<&IndexerQueryCursor>,
        policy: &Value,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> IndexerResult<String> {
        if requester_label.is_empty() {
            return Err("indexer query requester label cannot be empty".to_string());
        }
        let requester_commitment = indexer_requester_commitment(requester_label);
        let filter_root = filter.validate()?;
        let cursor_root = if let Some(cursor) = cursor {
            cursor.validate()?;
            cursor.cursor_root()
        } else {
            indexer_empty_root("query-cursor")
        };
        let allowed_events = self
            .events
            .values()
            .filter(|event| filter.matches_event(event))
            .cloned()
            .collect::<Vec<_>>();
        let allowed_event_root = indexer_event_root(&allowed_events);
        let policy_root = indexer_query_policy_root(policy);
        let authorization = IndexerQueryAuthorization::new(
            &requester_commitment,
            INDEXER_QUERY_SCOPE_EVENTS,
            &filter_root,
            &cursor_root,
            &allowed_event_root,
            &policy_root,
            issued_at_height,
            expires_at_height,
            "devnet-indexer-query-authorization",
        )?;
        self.apply_query_authorization(authorization)
    }

    pub fn apply_query_authorization(
        &mut self,
        authorization: IndexerQueryAuthorization,
    ) -> IndexerResult<String> {
        let authorization_id = authorization.validate()?;
        if self.query_authorizations.contains_key(&authorization_id) {
            return Err("indexer query authorization already exists".to_string());
        }
        self.query_authorizations
            .insert(authorization_id.clone(), authorization);
        Ok(authorization_id)
    }

    pub fn register_subscription(
        &mut self,
        subscription: IndexerSubscription,
    ) -> IndexerResult<String> {
        let subscription_id = subscription.validate()?;
        if self.subscriptions.contains_key(&subscription_id) {
            return Err("indexer subscription already exists".to_string());
        }
        self.subscriptions
            .insert(subscription_id.clone(), subscription);
        Ok(subscription_id)
    }

    pub fn subscribe(
        &mut self,
        subscriber_label: &str,
        filter: IndexerQueryFilter,
        min_confirmations: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        subscription_nonce: &str,
    ) -> IndexerResult<String> {
        if subscriber_label.is_empty() {
            return Err("indexer subscriber label cannot be empty".to_string());
        }
        let subscriber_commitment = indexer_requester_commitment(subscriber_label);
        let subscription = IndexerSubscription::new(
            &subscriber_commitment,
            filter,
            min_confirmations,
            created_at_height,
            created_at_height.saturating_add(ttl_blocks.max(1)),
            subscription_nonce,
        )?;
        self.register_subscription(subscription)
    }

    pub fn emit_subscription_receipts_for_event(
        &mut self,
        event_id: &str,
        delivered_at_height: u64,
        receipt_nonce: &str,
    ) -> IndexerResult<String> {
        let event = self
            .events
            .get(event_id)
            .cloned()
            .ok_or_else(|| "indexer subscription event is unknown".to_string())?;
        let subscriptions = self
            .subscriptions
            .values()
            .filter(|subscription| subscription.matches_event(&event, delivered_at_height))
            .cloned()
            .collect::<Vec<_>>();
        let mut receipts = Vec::new();
        for subscription in subscriptions {
            let cursor_nonce = format!("{receipt_nonce}:cursor:{}", subscription.subscription_id);
            let cursor = IndexerQueryCursor::new(
                INDEXER_QUERY_SCOPE_EVENTS,
                &subscription.filter.subject_root(),
                &subscription.filter_root,
                event.block_height,
                event.event_index,
                &event.event_id,
                subscription.filter.limit,
                delivered_at_height,
                delivered_at_height.saturating_add(INDEXER_DEFAULT_CURSOR_TTL_BLOCKS),
                &cursor_nonce,
            )?;
            let cursor_id = self.apply_query_cursor(cursor)?;
            let per_receipt_nonce =
                format!("{receipt_nonce}:receipt:{}", subscription.subscription_id);
            let receipt = IndexerSubscriptionReceipt::new(
                &subscription,
                &event,
                &cursor_id,
                delivered_at_height,
                &per_receipt_nonce,
            )?;
            self.apply_subscription_receipt(receipt.clone())?;
            receipts.push(receipt);
        }
        Ok(indexer_subscription_receipt_root(&receipts))
    }

    pub fn apply_subscription_receipt(
        &mut self,
        receipt: IndexerSubscriptionReceipt,
    ) -> IndexerResult<String> {
        let receipt_id = receipt.validate()?;
        if self.subscription_receipts.contains_key(&receipt_id) {
            return Err("indexer subscription receipt already exists".to_string());
        }
        self.subscription_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    fn ensure_block_anchor(
        &mut self,
        block_height: u64,
        block_hash: &str,
        source_root: &str,
    ) -> IndexerResult<String> {
        if let Some(anchor) = self.block_anchors.get(&block_height) {
            if anchor.block_hash == block_hash {
                return Ok(anchor.anchor_id.clone());
            }
            return Err("indexer block anchor conflicts with indexed height".to_string());
        }
        let anchor = IndexerBlockAnchor::new(block_height, block_hash, block_height, source_root)?;
        self.apply_block_anchor(anchor)
    }

    pub fn events_for_height(&self, block_height: u64) -> Vec<IndexedEvent> {
        let ids = self
            .events_by_block
            .get(&block_height)
            .cloned()
            .unwrap_or_default();
        let events = ids
            .iter()
            .filter_map(|event_id| self.events.get(event_id).cloned())
            .collect::<Vec<_>>();
        ordered_events(&events)
    }

    pub fn block_anchor_root(&self) -> String {
        indexer_block_anchor_root(&self.block_anchors.values().cloned().collect::<Vec<_>>())
    }

    pub fn event_root(&self) -> String {
        indexer_event_root(&self.events.values().cloned().collect::<Vec<_>>())
    }

    pub fn checkpoint_root(&self) -> String {
        indexer_event_checkpoint_root(&self.checkpoints.values().cloned().collect::<Vec<_>>())
    }

    pub fn manifest_root(&self) -> String {
        indexer_block_range_manifest_root(&self.manifests.values().cloned().collect::<Vec<_>>())
    }

    pub fn cursor_root(&self) -> String {
        indexer_query_cursor_root(&self.cursors.values().cloned().collect::<Vec<_>>())
    }

    pub fn query_authorization_root(&self) -> String {
        indexer_query_authorization_root(
            &self
                .query_authorizations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn subscription_root(&self) -> String {
        indexer_subscription_root(&self.subscriptions.values().cloned().collect::<Vec<_>>())
    }

    pub fn subscription_receipt_root(&self) -> String {
        indexer_subscription_receipt_root(
            &self
                .subscription_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        indexer_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "indexer_state",
            "chain_id": CHAIN_ID,
            "indexer_protocol_version": INDEXER_PROTOCOL_VERSION,
            "height": self.height,
            "block_anchor_root": self.block_anchor_root(),
            "block_anchor_count": self.block_anchors.len() as u64,
            "event_root": self.event_root(),
            "event_count": self.events.len() as u64,
            "checkpoint_root": self.checkpoint_root(),
            "checkpoint_count": self.checkpoints.len() as u64,
            "manifest_root": self.manifest_root(),
            "manifest_count": self.manifests.len() as u64,
            "cursor_root": self.cursor_root(),
            "cursor_count": self.cursors.len() as u64,
            "query_authorization_root": self.query_authorization_root(),
            "query_authorization_count": self.query_authorizations.len() as u64,
            "subscription_root": self.subscription_root(),
            "subscription_count": self.subscriptions.len() as u64,
            "subscription_receipt_root": self.subscription_receipt_root(),
            "subscription_receipt_count": self.subscription_receipts.len() as u64,
            "last_checkpoint_root": self.last_checkpoint_root,
            "last_manifest_root": self.last_manifest_root,
        })
    }
}

impl Default for IndexerState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn indexer_payload_root(payload: &Value) -> String {
    domain_hash(
        "INDEXER-PAYLOAD-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn indexer_event_source_root(source: &Value) -> String {
    domain_hash(
        "INDEXER-EVENT-SOURCE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(source)],
        32,
    )
}

pub fn indexer_empty_root(label: &str) -> String {
    domain_hash(
        "INDEXER-EMPTY-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn indexer_subject_commitment(event_domain: &str, subject_id: &str) -> String {
    domain_hash(
        "INDEXER-SUBJECT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_domain),
            HashPart::Str(subject_id),
        ],
        32,
    )
}

pub fn indexer_requester_commitment(requester_label: &str) -> String {
    domain_hash(
        "INDEXER-REQUESTER-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(requester_label)],
        32,
    )
}

pub fn indexer_topic_root(topics: &[String]) -> String {
    merkle_root(
        "INDEXER-TOPIC",
        &sorted_strings(topics)
            .iter()
            .map(|topic| {
                json!({
                    "topic_commitment": domain_hash(
                        "INDEXER-TOPIC-COMMITMENT",
                        &[HashPart::Str(CHAIN_ID), HashPart::Str(topic)],
                        32,
                    )
                })
            })
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indexer_event_id(
    event_domain: &str,
    event_kind: &str,
    subject_commitment: &str,
    tx_hash: &str,
    block_height: u64,
    block_hash: &str,
    event_index: u64,
    topic_root: &str,
    payload_root: &str,
    source_root: &str,
    previous_event_root: &str,
) -> String {
    domain_hash(
        "INDEXER-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(INDEXER_PROTOCOL_VERSION),
            HashPart::Str(event_domain),
            HashPart::Str(event_kind),
            HashPart::Str(subject_commitment),
            HashPart::Str(tx_hash),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Int(event_index as i128),
            HashPart::Str(topic_root),
            HashPart::Str(payload_root),
            HashPart::Str(source_root),
            HashPart::Str(previous_event_root),
        ],
        32,
    )
}

pub fn indexer_event_root(events: &[IndexedEvent]) -> String {
    merkle_root(
        "INDEXER-EVENT",
        &ordered_events(events)
            .iter()
            .map(IndexedEvent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_event_checkpoint_root(checkpoints: &[IndexerEventCheckpoint]) -> String {
    let mut ordered = checkpoints.to_vec();
    ordered.sort_by(|left, right| {
        (
            left.sequence,
            left.block_height,
            left.checkpoint_id.as_str(),
        )
            .cmp(&(
                right.sequence,
                right.block_height,
                right.checkpoint_id.as_str(),
            ))
    });
    merkle_root(
        "INDEXER-EVENT-CHECKPOINT",
        &ordered
            .iter()
            .map(IndexerEventCheckpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indexer_event_checkpoint_id(
    sequence: u64,
    block_height: u64,
    block_hash: &str,
    event_root: &str,
    event_count: u64,
    previous_checkpoint_root: &str,
    cumulative_event_root: &str,
    replay_guard_root: &str,
    finalized: bool,
) -> String {
    domain_hash(
        "INDEXER-EVENT-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(event_root),
            HashPart::Int(event_count as i128),
            HashPart::Str(previous_checkpoint_root),
            HashPart::Str(cumulative_event_root),
            HashPart::Str(replay_guard_root),
            HashPart::Str(if finalized { "final" } else { "soft" }),
        ],
        32,
    )
}

pub fn indexer_replay_guard_root(
    sequence: u64,
    block_height: u64,
    block_hash: &str,
    event_root: &str,
    previous_checkpoint_root: &str,
) -> String {
    domain_hash(
        "INDEXER-REPLAY-GUARD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(INDEXER_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(event_root),
            HashPart::Str(previous_checkpoint_root),
        ],
        32,
    )
}

pub fn indexer_cumulative_event_root(
    previous_checkpoint_root: &str,
    event_root: &str,
    replay_guard_root: &str,
) -> String {
    domain_hash(
        "INDEXER-CUMULATIVE-EVENT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(previous_checkpoint_root),
            HashPart::Str(event_root),
            HashPart::Str(replay_guard_root),
        ],
        32,
    )
}

pub fn indexer_block_anchor_id(
    height: u64,
    block_hash: &str,
    indexed_at_height: u64,
    source_root: &str,
) -> String {
    domain_hash(
        "INDEXER-BLOCK-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(block_hash),
            HashPart::Int(indexed_at_height as i128),
            HashPart::Str(source_root),
        ],
        32,
    )
}

pub fn indexer_block_anchor_root(anchors: &[IndexerBlockAnchor]) -> String {
    let mut ordered = anchors.to_vec();
    ordered.sort_by(|left, right| {
        (left.height, left.anchor_id.as_str()).cmp(&(right.height, right.anchor_id.as_str()))
    });
    merkle_root(
        "INDEXER-BLOCK-ANCHOR",
        &ordered
            .iter()
            .map(IndexerBlockAnchor::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_block_manifest_entry_id(
    height: u64,
    block_hash: &str,
    event_root: &str,
    event_count: u64,
    checkpoint_root: &str,
) -> String {
    domain_hash(
        "INDEXER-BLOCK-MANIFEST-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(event_root),
            HashPart::Int(event_count as i128),
            HashPart::Str(checkpoint_root),
        ],
        32,
    )
}

pub fn indexer_block_manifest_entry_root(entries: &[IndexerBlockManifestEntry]) -> String {
    let mut ordered = entries.to_vec();
    ordered.sort_by(|left, right| {
        (left.height, left.entry_id.as_str()).cmp(&(right.height, right.entry_id.as_str()))
    });
    merkle_root(
        "INDEXER-BLOCK-MANIFEST-ENTRY",
        &ordered
            .iter()
            .map(IndexerBlockManifestEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indexer_block_range_manifest_id(
    from_height: u64,
    to_height: u64,
    entry_root: &str,
    event_root: &str,
    checkpoint_root: &str,
    event_count: u64,
    checkpoint_count: u64,
    previous_manifest_root: &str,
    generated_at_height: u64,
) -> String {
    domain_hash(
        "INDEXER-BLOCK-RANGE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(from_height as i128),
            HashPart::Int(to_height as i128),
            HashPart::Str(entry_root),
            HashPart::Str(event_root),
            HashPart::Str(checkpoint_root),
            HashPart::Int(event_count as i128),
            HashPart::Int(checkpoint_count as i128),
            HashPart::Str(previous_manifest_root),
            HashPart::Int(generated_at_height as i128),
        ],
        32,
    )
}

pub fn indexer_block_range_manifest_root(manifests: &[IndexerBlockRangeManifest]) -> String {
    let mut ordered = manifests.to_vec();
    ordered.sort_by(|left, right| {
        (left.from_height, left.to_height, left.manifest_id.as_str()).cmp(&(
            right.from_height,
            right.to_height,
            right.manifest_id.as_str(),
        ))
    });
    merkle_root(
        "INDEXER-BLOCK-RANGE-MANIFEST",
        &ordered
            .iter()
            .map(IndexerBlockRangeManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_query_filter_root(filter: &IndexerQueryFilter) -> String {
    domain_hash(
        "INDEXER-QUERY-FILTER-ROOT",
        &[HashPart::Json(&filter.public_record())],
        32,
    )
}

pub fn indexer_query_subject_root(subject_commitments: &[String]) -> String {
    merkle_root(
        "INDEXER-QUERY-SUBJECT",
        &sorted_strings(subject_commitments)
            .iter()
            .map(|subject_commitment| json!({ "subject_commitment": subject_commitment }))
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_query_topic_root(topic_roots: &[String]) -> String {
    merkle_root(
        "INDEXER-QUERY-TOPIC",
        &sorted_strings(topic_roots)
            .iter()
            .map(|topic_root| json!({ "topic_root": topic_root }))
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_query_cursor_commitment(
    subject_commitment: &str,
    filter_root: &str,
    cursor_nonce: &str,
) -> String {
    domain_hash(
        "INDEXER-QUERY-CURSOR-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(filter_root),
            HashPart::Str(cursor_nonce),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indexer_query_cursor_id(
    scope: &str,
    subject_commitment: &str,
    filter_root: &str,
    after_height: u64,
    after_event_index: u64,
    after_event_id: &str,
    page_size: u64,
    issued_at_height: u64,
    expires_at_height: u64,
    cursor_commitment: &str,
) -> String {
    domain_hash(
        "INDEXER-QUERY-CURSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(subject_commitment),
            HashPart::Str(filter_root),
            HashPart::Int(after_height as i128),
            HashPart::Int(after_event_index as i128),
            HashPart::Str(after_event_id),
            HashPart::Int(page_size as i128),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(cursor_commitment),
        ],
        32,
    )
}

pub fn indexer_query_cursor_root(cursors: &[IndexerQueryCursor]) -> String {
    let mut ordered = cursors.to_vec();
    ordered.sort_by(|left, right| left.cursor_id.cmp(&right.cursor_id));
    merkle_root(
        "INDEXER-QUERY-CURSOR",
        &ordered
            .iter()
            .map(IndexerQueryCursor::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indexer_query_authorization_id(
    requester_commitment: &str,
    scope: &str,
    filter_root: &str,
    cursor_root: &str,
    allowed_event_root: &str,
    policy_root: &str,
    issued_at_height: u64,
    expires_at_height: u64,
    proof_system: &str,
) -> String {
    domain_hash(
        "INDEXER-QUERY-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester_commitment),
            HashPart::Str(scope),
            HashPart::Str(filter_root),
            HashPart::Str(cursor_root),
            HashPart::Str(allowed_event_root),
            HashPart::Str(policy_root),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(proof_system),
        ],
        32,
    )
}

pub fn indexer_query_authorization_root(authorizations: &[IndexerQueryAuthorization]) -> String {
    let mut ordered = authorizations.to_vec();
    ordered.sort_by(|left, right| left.authorization_id.cmp(&right.authorization_id));
    merkle_root(
        "INDEXER-QUERY-AUTHORIZATION",
        &ordered
            .iter()
            .map(IndexerQueryAuthorization::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_query_policy_root(policy: &Value) -> String {
    domain_hash(
        "INDEXER-QUERY-POLICY-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(policy)],
        32,
    )
}

pub fn indexer_subscription_commitment(
    subscriber_commitment: &str,
    filter_root: &str,
    subscription_nonce: &str,
) -> String {
    domain_hash(
        "INDEXER-SUBSCRIPTION-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subscriber_commitment),
            HashPart::Str(filter_root),
            HashPart::Str(subscription_nonce),
        ],
        32,
    )
}

pub fn indexer_subscription_id(
    subscriber_commitment: &str,
    filter_root: &str,
    min_confirmations: u64,
    created_at_height: u64,
    expires_at_height: u64,
    subscription_commitment: &str,
) -> String {
    domain_hash(
        "INDEXER-SUBSCRIPTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subscriber_commitment),
            HashPart::Str(filter_root),
            HashPart::Int(min_confirmations as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(subscription_commitment),
        ],
        32,
    )
}

pub fn indexer_subscription_root(subscriptions: &[IndexerSubscription]) -> String {
    let mut ordered = subscriptions.to_vec();
    ordered.sort_by(|left, right| left.subscription_id.cmp(&right.subscription_id));
    merkle_root(
        "INDEXER-SUBSCRIPTION",
        &ordered
            .iter()
            .map(IndexerSubscription::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_subscription_delivery_root(
    subscription_id: &str,
    cursor_id: &str,
    event_id: &str,
    event_public_root: &str,
    delivered_at_height: u64,
) -> String {
    domain_hash(
        "INDEXER-SUBSCRIPTION-DELIVERY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subscription_id),
            HashPart::Str(cursor_id),
            HashPart::Str(event_id),
            HashPart::Str(event_public_root),
            HashPart::Int(delivered_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indexer_subscription_receipt_id(
    subscription_id: &str,
    subscriber_commitment: &str,
    cursor_id: &str,
    event_id: &str,
    delivery_root: &str,
    delivered_at_height: u64,
    receipt_nonce: &str,
) -> String {
    domain_hash(
        "INDEXER-SUBSCRIPTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subscription_id),
            HashPart::Str(subscriber_commitment),
            HashPart::Str(cursor_id),
            HashPart::Str(event_id),
            HashPart::Str(delivery_root),
            HashPart::Int(delivered_at_height as i128),
            HashPart::Str(receipt_nonce),
        ],
        32,
    )
}

pub fn indexer_subscription_receipt_root(receipts: &[IndexerSubscriptionReceipt]) -> String {
    let mut ordered = receipts.to_vec();
    ordered.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    merkle_root(
        "INDEXER-SUBSCRIPTION-RECEIPT",
        &ordered
            .iter()
            .map(IndexerSubscriptionReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn indexer_query_page_id(
    filter_root: &str,
    cursor_root: &str,
    authorization_id: &str,
    event_root: &str,
    next_cursor_root: &str,
    returned_count: u64,
    more_results: bool,
) -> String {
    domain_hash(
        "INDEXER-QUERY-PAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(filter_root),
            HashPart::Str(cursor_root),
            HashPart::Str(authorization_id),
            HashPart::Str(event_root),
            HashPart::Str(next_cursor_root),
            HashPart::Int(returned_count as i128),
            HashPart::Str(if more_results { "more" } else { "done" }),
        ],
        32,
    )
}

pub fn indexer_state_root_from_record(record: &Value) -> String {
    domain_hash("INDEXER-STATE-ROOT", &[HashPart::Json(record)], 32)
}

fn validate_event_domain(event_domain: &str) -> IndexerResult<()> {
    if matches!(
        event_domain,
        INDEXER_EVENT_DOMAIN_ACCOUNT
            | INDEXER_EVENT_DOMAIN_CONTRACT
            | INDEXER_EVENT_DOMAIN_TOKEN
            | INDEXER_EVENT_DOMAIN_ORACLE
            | INDEXER_EVENT_DOMAIN_BRIDGE
    ) {
        Ok(())
    } else {
        Err("indexer event domain is unknown".to_string())
    }
}

fn validate_event_visibility(visibility: &str) -> IndexerResult<()> {
    if matches!(
        visibility,
        INDEXER_EVENT_VISIBILITY_PUBLIC | INDEXER_EVENT_VISIBILITY_COMMITTED
    ) {
        Ok(())
    } else {
        Err("indexer event visibility is unknown".to_string())
    }
}

fn ordered_events(events: &[IndexedEvent]) -> Vec<IndexedEvent> {
    let mut ordered = events.to_vec();
    ordered.sort_by(|left, right| {
        (left.block_height, left.event_index, left.event_id.as_str()).cmp(&(
            right.block_height,
            right.event_index,
            right.event_id.as_str(),
        ))
    });
    ordered
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn indexer_event_position_key(block_height: u64, event_index: u64) -> String {
    format!("{block_height}:{event_index}")
}

fn event_after_cursor(
    event: &IndexedEvent,
    after_height: u64,
    after_event_index: u64,
    after_event_id: &str,
) -> bool {
    (
        event.block_height,
        event.event_index,
        event.event_id.as_str(),
    ) > (after_height, after_event_index, after_event_id)
}
