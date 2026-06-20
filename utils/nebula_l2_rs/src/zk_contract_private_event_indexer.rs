use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkContractPrivateEventIndexerResult<T> = Result<T, String>;

pub const ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION: &str =
    "nebula-zk-contract-private-event-indexer-v1";
pub const ZK_CONTRACT_PRIVATE_EVENT_INDEXER_MAX_TOPIC_COUNT: usize = 8;
pub const ZK_CONTRACT_PRIVATE_EVENT_INDEXER_MAX_BATCH_SIZE: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventVisibility {
    Shielded,
    SelectiveDisclosure,
    PublicRootOnly,
}

impl EventVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shielded => "shielded",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::PublicRootOnly => "public_root_only",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CursorStatus {
    Open,
    Sealed,
    Proved,
    Challenged,
}

impl CursorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proved => "proved",
            Self::Challenged => "challenged",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatus {
    Pending,
    Verified,
    Rejected,
}

impl ProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub indexer_label_commitment: String,
    pub max_topics_per_event: usize,
    pub max_events_per_cursor: usize,
    pub retention_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub sponsor_fee_floor_micro_units: u64,
    pub pq_attestation_scheme: String,
    pub private_event_schema_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            indexer_label_commitment: zk_private_event_commitment("indexer", "devnet-indexer"),
            max_topics_per_event: ZK_CONTRACT_PRIVATE_EVENT_INDEXER_MAX_TOPIC_COUNT,
            max_events_per_cursor: ZK_CONTRACT_PRIVATE_EVENT_INDEXER_MAX_BATCH_SIZE,
            retention_window_blocks: 7_200,
            challenge_window_blocks: 16,
            sponsor_fee_floor_micro_units: 12,
            pq_attestation_scheme: "ML-DSA-65+SLH-DSA-SHAKE-128s".to_string(),
            private_event_schema_root: zk_private_event_string_root(
                "schema",
                &[
                    "contract_commitment",
                    "topic_root",
                    "encrypted_payload_root",
                    "nullifier_root",
                    "cursor_id",
                ],
            ),
        }
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private event indexer chain id mismatch".to_string());
        }
        if self.indexer_label_commitment.is_empty()
            || self.pq_attestation_scheme.is_empty()
            || self.private_event_schema_root.is_empty()
        {
            return Err("private event indexer config commitments cannot be empty".to_string());
        }
        if self.max_topics_per_event == 0
            || self.max_topics_per_event > ZK_CONTRACT_PRIVATE_EVENT_INDEXER_MAX_TOPIC_COUNT
        {
            return Err("private event indexer topic limit is invalid".to_string());
        }
        if self.max_events_per_cursor == 0
            || self.max_events_per_cursor > ZK_CONTRACT_PRIVATE_EVENT_INDEXER_MAX_BATCH_SIZE
        {
            return Err("private event indexer cursor limit is invalid".to_string());
        }
        if self.retention_window_blocks <= self.challenge_window_blocks {
            return Err("private event indexer retention must exceed challenge window".to_string());
        }
        if self.sponsor_fee_floor_micro_units == 0 {
            return Err("private event indexer sponsor floor must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_indexer_config",
            "chain_id": self.chain_id,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "indexer_label_commitment": self.indexer_label_commitment,
            "max_topics_per_event": self.max_topics_per_event,
            "max_events_per_cursor": self.max_events_per_cursor,
            "retention_window_blocks": self.retention_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "sponsor_fee_floor_micro_units": self.sponsor_fee_floor_micro_units,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "private_event_schema_root": self.private_event_schema_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStream {
    pub stream_id: String,
    pub contract_commitment: String,
    pub deployment_root: String,
    pub abi_commitment: String,
    pub owner_commitment: String,
    pub visibility: EventVisibility,
    pub sponsor_policy_root: String,
    pub cursor_count: u64,
    pub event_count: u64,
    pub active: bool,
}

impl ContractStream {
    pub fn new(
        contract_label: &str,
        deployment_root: &str,
        abi_commitment: &str,
        owner_label: &str,
        visibility: EventVisibility,
        sponsor_policy: &Value,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if contract_label.is_empty()
            || deployment_root.is_empty()
            || abi_commitment.is_empty()
            || owner_label.is_empty()
        {
            return Err("private event stream inputs cannot be empty".to_string());
        }
        let contract_commitment = zk_private_event_commitment("contract", contract_label);
        let owner_commitment = zk_private_event_commitment("owner", owner_label);
        let sponsor_policy_root =
            zk_private_event_payload_root("stream-sponsor-policy", sponsor_policy);
        let stream_id = zk_private_event_id(
            "stream",
            &[
                &contract_commitment,
                deployment_root,
                abi_commitment,
                &owner_commitment,
                visibility.as_str(),
                &sponsor_policy_root,
            ],
        );
        Ok(Self {
            stream_id,
            contract_commitment,
            deployment_root: deployment_root.to_string(),
            abi_commitment: abi_commitment.to_string(),
            owner_commitment,
            visibility,
            sponsor_policy_root,
            cursor_count: 0,
            event_count: 0,
            active: true,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.stream_id.is_empty()
            || self.contract_commitment.is_empty()
            || self.deployment_root.is_empty()
            || self.abi_commitment.is_empty()
            || self.owner_commitment.is_empty()
            || self.sponsor_policy_root.is_empty()
        {
            return Err("private event stream commitments cannot be empty".to_string());
        }
        let expected = zk_private_event_id(
            "stream",
            &[
                &self.contract_commitment,
                &self.deployment_root,
                &self.abi_commitment,
                &self.owner_commitment,
                self.visibility.as_str(),
                &self.sponsor_policy_root,
            ],
        );
        if self.stream_id != expected {
            return Err("private event stream id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_stream",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "stream_id": self.stream_id,
            "contract_commitment": self.contract_commitment,
            "deployment_root": self.deployment_root,
            "abi_commitment": self.abi_commitment,
            "owner_commitment": self.owner_commitment,
            "visibility": self.visibility.as_str(),
            "sponsor_policy_root": self.sponsor_policy_root,
            "cursor_count": self.cursor_count,
            "event_count": self.event_count,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateEventEnvelope {
    pub event_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub height: u64,
    pub topic_root: String,
    pub encrypted_payload_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub fee_sponsor_commitment: String,
    pub disclosure_root: String,
}

impl PrivateEventEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream_id: &str,
        sequence: u64,
        height: u64,
        topics: &[String],
        payload_label: &str,
        nullifier_label: &str,
        witness_label: &str,
        sponsor_label: &str,
        disclosure: &Value,
        config: &Config,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if stream_id.is_empty()
            || payload_label.is_empty()
            || nullifier_label.is_empty()
            || witness_label.is_empty()
            || sponsor_label.is_empty()
        {
            return Err("private event envelope inputs cannot be empty".to_string());
        }
        if topics.is_empty() || topics.len() > config.max_topics_per_event {
            return Err("private event envelope topic count is invalid".to_string());
        }
        let topic_root = zk_private_event_string_root(
            "topic",
            &topics.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let encrypted_payload_root = zk_private_event_commitment("payload", payload_label);
        let nullifier_root = zk_private_event_commitment("nullifier", nullifier_label);
        let witness_root = zk_private_event_commitment("witness", witness_label);
        let fee_sponsor_commitment = zk_private_event_commitment("sponsor", sponsor_label);
        let disclosure_root = zk_private_event_payload_root("event-disclosure", disclosure);
        let event_id = zk_private_event_id(
            "event",
            &[
                stream_id,
                &sequence.to_string(),
                &height.to_string(),
                &topic_root,
                &encrypted_payload_root,
                &nullifier_root,
                &witness_root,
                &fee_sponsor_commitment,
                &disclosure_root,
            ],
        );
        Ok(Self {
            event_id,
            stream_id: stream_id.to_string(),
            sequence,
            height,
            topic_root,
            encrypted_payload_root,
            nullifier_root,
            witness_root,
            fee_sponsor_commitment,
            disclosure_root,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.event_id.is_empty()
            || self.stream_id.is_empty()
            || self.topic_root.is_empty()
            || self.encrypted_payload_root.is_empty()
            || self.nullifier_root.is_empty()
            || self.witness_root.is_empty()
            || self.fee_sponsor_commitment.is_empty()
            || self.disclosure_root.is_empty()
        {
            return Err("private event envelope commitments cannot be empty".to_string());
        }
        let expected = zk_private_event_id(
            "event",
            &[
                &self.stream_id,
                &self.sequence.to_string(),
                &self.height.to_string(),
                &self.topic_root,
                &self.encrypted_payload_root,
                &self.nullifier_root,
                &self.witness_root,
                &self.fee_sponsor_commitment,
                &self.disclosure_root,
            ],
        );
        if self.event_id != expected {
            return Err("private event envelope id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "height": self.height,
            "topic_root": self.topic_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier_root": self.nullifier_root,
            "witness_root": self.witness_root,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCursorBatch {
    pub cursor_id: String,
    pub stream_id: String,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub event_root: String,
    pub index_proof_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub status: CursorStatus,
}

impl EventCursorBatch {
    pub fn new(
        stream_id: &str,
        events: &[PrivateEventEnvelope],
        opened_at_height: u64,
        sealed_at_height: u64,
        proof_label: &str,
        config: &Config,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if stream_id.is_empty() || proof_label.is_empty() {
            return Err("private event cursor inputs cannot be empty".to_string());
        }
        if events.is_empty() || events.len() > config.max_events_per_cursor {
            return Err("private event cursor batch size is invalid".to_string());
        }
        if sealed_at_height < opened_at_height {
            return Err("private event cursor cannot seal before it opens".to_string());
        }
        let mut sequences = events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        let from_sequence = sequences.first().copied().unwrap_or_default();
        let to_sequence = sequences.last().copied().unwrap_or_default();
        let event_root = merkle_root(
            "ZK-CONTRACT-PRIVATE-EVENT:cursor-events",
            &events
                .iter()
                .map(PrivateEventEnvelope::public_record)
                .collect::<Vec<_>>(),
        );
        let index_proof_root = zk_private_event_commitment("cursor-proof", proof_label);
        let cursor_id = zk_private_event_id(
            "cursor",
            &[
                stream_id,
                &from_sequence.to_string(),
                &to_sequence.to_string(),
                &event_root,
                &index_proof_root,
                &opened_at_height.to_string(),
                &sealed_at_height.to_string(),
            ],
        );
        Ok(Self {
            cursor_id,
            stream_id: stream_id.to_string(),
            from_sequence,
            to_sequence,
            event_root,
            index_proof_root,
            opened_at_height,
            sealed_at_height,
            status: CursorStatus::Sealed,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.cursor_id.is_empty()
            || self.stream_id.is_empty()
            || self.event_root.is_empty()
            || self.index_proof_root.is_empty()
        {
            return Err("private event cursor commitments cannot be empty".to_string());
        }
        if self.to_sequence < self.from_sequence {
            return Err("private event cursor sequence range is invalid".to_string());
        }
        if self.sealed_at_height < self.opened_at_height {
            return Err("private event cursor height range is invalid".to_string());
        }
        let expected = zk_private_event_id(
            "cursor",
            &[
                &self.stream_id,
                &self.from_sequence.to_string(),
                &self.to_sequence.to_string(),
                &self.event_root,
                &self.index_proof_root,
                &self.opened_at_height.to_string(),
                &self.sealed_at_height.to_string(),
            ],
        );
        if self.cursor_id != expected {
            return Err("private event cursor id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_cursor",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "cursor_id": self.cursor_id,
            "stream_id": self.stream_id,
            "from_sequence": self.from_sequence,
            "to_sequence": self.to_sequence,
            "event_root": self.event_root,
            "index_proof_root": self.index_proof_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexProofReceipt {
    pub receipt_id: String,
    pub cursor_id: String,
    pub prover_commitment: String,
    pub recursive_proof_root: String,
    pub verified_at_height: u64,
    pub fee_micro_units: u64,
    pub status: ProofStatus,
}

impl IndexProofReceipt {
    pub fn new(
        cursor_id: &str,
        prover_label: &str,
        proof_label: &str,
        verified_at_height: u64,
        fee_micro_units: u64,
        status: ProofStatus,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if cursor_id.is_empty() || prover_label.is_empty() || proof_label.is_empty() {
            return Err("private event proof receipt inputs cannot be empty".to_string());
        }
        if fee_micro_units == 0 {
            return Err("private event proof receipt fee must be positive".to_string());
        }
        let prover_commitment = zk_private_event_commitment("prover", prover_label);
        let recursive_proof_root = zk_private_event_commitment("recursive-proof", proof_label);
        let receipt_id = zk_private_event_id(
            "receipt",
            &[
                cursor_id,
                &prover_commitment,
                &recursive_proof_root,
                &verified_at_height.to_string(),
                &fee_micro_units.to_string(),
                status.as_str(),
            ],
        );
        Ok(Self {
            receipt_id,
            cursor_id: cursor_id.to_string(),
            prover_commitment,
            recursive_proof_root,
            verified_at_height,
            fee_micro_units,
            status,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.receipt_id.is_empty()
            || self.cursor_id.is_empty()
            || self.prover_commitment.is_empty()
            || self.recursive_proof_root.is_empty()
        {
            return Err("private event proof receipt commitments cannot be empty".to_string());
        }
        if self.fee_micro_units == 0 {
            return Err("private event proof receipt fee must be positive".to_string());
        }
        let expected = zk_private_event_id(
            "receipt",
            &[
                &self.cursor_id,
                &self.prover_commitment,
                &self.recursive_proof_root,
                &self.verified_at_height.to_string(),
                &self.fee_micro_units.to_string(),
                self.status.as_str(),
            ],
        );
        if self.receipt_id != expected {
            return Err("private event proof receipt id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_proof_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "cursor_id": self.cursor_id,
            "prover_commitment": self.prover_commitment,
            "recursive_proof_root": self.recursive_proof_root,
            "verified_at_height": self.verified_at_height,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriberFilter {
    pub filter_id: String,
    pub subscriber_commitment: String,
    pub stream_id: String,
    pub topic_filter_root: String,
    pub disclosure_policy_root: String,
    pub max_lag_blocks: u64,
    pub active: bool,
}

impl SubscriberFilter {
    pub fn new(
        subscriber_label: &str,
        stream_id: &str,
        topic_filters: &[String],
        disclosure_policy: &Value,
        max_lag_blocks: u64,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if subscriber_label.is_empty() || stream_id.is_empty() || topic_filters.is_empty() {
            return Err("private event subscriber filter inputs cannot be empty".to_string());
        }
        if max_lag_blocks == 0 {
            return Err("private event subscriber max lag must be positive".to_string());
        }
        let subscriber_commitment = zk_private_event_commitment("subscriber", subscriber_label);
        let topic_filter_root = zk_private_event_string_root(
            "subscriber-topic",
            &topic_filters.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let disclosure_policy_root =
            zk_private_event_payload_root("subscriber-disclosure-policy", disclosure_policy);
        let filter_id = zk_private_event_id(
            "filter",
            &[
                &subscriber_commitment,
                stream_id,
                &topic_filter_root,
                &disclosure_policy_root,
                &max_lag_blocks.to_string(),
            ],
        );
        Ok(Self {
            filter_id,
            subscriber_commitment,
            stream_id: stream_id.to_string(),
            topic_filter_root,
            disclosure_policy_root,
            max_lag_blocks,
            active: true,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.filter_id.is_empty()
            || self.subscriber_commitment.is_empty()
            || self.stream_id.is_empty()
            || self.topic_filter_root.is_empty()
            || self.disclosure_policy_root.is_empty()
        {
            return Err("private event subscriber filter commitments cannot be empty".to_string());
        }
        if self.max_lag_blocks == 0 {
            return Err("private event subscriber max lag must be positive".to_string());
        }
        let expected = zk_private_event_id(
            "filter",
            &[
                &self.subscriber_commitment,
                &self.stream_id,
                &self.topic_filter_root,
                &self.disclosure_policy_root,
                &self.max_lag_blocks.to_string(),
            ],
        );
        if self.filter_id != expected {
            return Err("private event subscriber filter id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_subscriber_filter",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "filter_id": self.filter_id,
            "subscriber_commitment": self.subscriber_commitment,
            "stream_id": self.stream_id,
            "topic_filter_root": self.topic_filter_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "max_lag_blocks": self.max_lag_blocks,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorLedgerEntry {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub budget_micro_units: u64,
    pub spent_micro_units: u64,
    pub cursor_root: String,
    pub policy_root: String,
    pub active: bool,
}

impl SponsorLedgerEntry {
    pub fn new(
        sponsor_label: &str,
        budget_micro_units: u64,
        spent_micro_units: u64,
        cursor_ids: &[String],
        policy: &Value,
        config: &Config,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if sponsor_label.is_empty() || cursor_ids.is_empty() {
            return Err("private event sponsor inputs cannot be empty".to_string());
        }
        if budget_micro_units < config.sponsor_fee_floor_micro_units {
            return Err("private event sponsor budget below floor".to_string());
        }
        if spent_micro_units > budget_micro_units {
            return Err("private event sponsor spent exceeds budget".to_string());
        }
        let sponsor_commitment = zk_private_event_commitment("ledger-sponsor", sponsor_label);
        let cursor_root = zk_private_event_string_root(
            "sponsor-cursor",
            &cursor_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let policy_root = zk_private_event_payload_root("sponsor-policy", policy);
        let sponsor_id = zk_private_event_id(
            "sponsor-ledger",
            &[
                &sponsor_commitment,
                &budget_micro_units.to_string(),
                &spent_micro_units.to_string(),
                &cursor_root,
                &policy_root,
            ],
        );
        Ok(Self {
            sponsor_id,
            sponsor_commitment,
            budget_micro_units,
            spent_micro_units,
            cursor_root,
            policy_root,
            active: true,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.sponsor_id.is_empty()
            || self.sponsor_commitment.is_empty()
            || self.cursor_root.is_empty()
            || self.policy_root.is_empty()
        {
            return Err("private event sponsor commitments cannot be empty".to_string());
        }
        if self.spent_micro_units > self.budget_micro_units {
            return Err("private event sponsor spent exceeds budget".to_string());
        }
        let expected = zk_private_event_id(
            "sponsor-ledger",
            &[
                &self.sponsor_commitment,
                &self.budget_micro_units.to_string(),
                &self.spent_micro_units.to_string(),
                &self.cursor_root,
                &self.policy_root,
            ],
        );
        if self.sponsor_id != expected {
            return Err("private event sponsor id mismatch".to_string());
        }
        Ok(())
    }

    pub fn available_micro_units(&self) -> u64 {
        self.budget_micro_units
            .saturating_sub(self.spent_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_sponsor",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_micro_units": self.budget_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "available_micro_units": self.available_micro_units(),
            "cursor_root": self.cursor_root,
            "policy_root": self.policy_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub cursor_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved: bool,
}

impl ChallengeRecord {
    pub fn new(
        cursor_id: &str,
        challenger_label: &str,
        evidence: &Value,
        opened_at_height: u64,
        config: &Config,
    ) -> ZkContractPrivateEventIndexerResult<Self> {
        if cursor_id.is_empty() || challenger_label.is_empty() {
            return Err("private event challenge inputs cannot be empty".to_string());
        }
        let challenger_commitment = zk_private_event_commitment("challenger", challenger_label);
        let evidence_root = zk_private_event_payload_root("challenge-evidence", evidence);
        let expires_at_height = opened_at_height.saturating_add(config.challenge_window_blocks);
        let challenge_id = zk_private_event_id(
            "challenge",
            &[
                cursor_id,
                &challenger_commitment,
                &evidence_root,
                &opened_at_height.to_string(),
                &expires_at_height.to_string(),
            ],
        );
        Ok(Self {
            challenge_id,
            cursor_id: cursor_id.to_string(),
            challenger_commitment,
            evidence_root,
            opened_at_height,
            expires_at_height,
            resolved: false,
        })
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        if self.challenge_id.is_empty()
            || self.cursor_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("private event challenge commitments cannot be empty".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("private event challenge expiry is invalid".to_string());
        }
        let expected = zk_private_event_id(
            "challenge",
            &[
                &self.cursor_id,
                &self.challenger_commitment,
                &self.evidence_root,
                &self.opened_at_height.to_string(),
                &self.expires_at_height.to_string(),
            ],
        );
        if self.challenge_id != expected {
            return Err("private event challenge id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "cursor_id": self.cursor_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub stream_root: String,
    pub event_root: String,
    pub cursor_root: String,
    pub proof_receipt_root: String,
    pub subscriber_root: String,
    pub sponsor_root: String,
    pub challenge_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "stream_root": self.stream_root,
            "event_root": self.event_root,
            "cursor_root": self.cursor_root,
            "proof_receipt_root": self.proof_receipt_root,
            "subscriber_root": self.subscriber_root,
            "sponsor_root": self.sponsor_root,
            "challenge_root": self.challenge_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub stream_count: u64,
    pub active_stream_count: u64,
    pub event_count: u64,
    pub cursor_count: u64,
    pub live_cursor_count: u64,
    pub verified_proof_count: u64,
    pub subscriber_count: u64,
    pub active_subscriber_count: u64,
    pub sponsor_count: u64,
    pub open_challenge_count: u64,
    pub total_sponsor_budget_micro_units: u64,
    pub total_sponsor_available_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_count": self.stream_count,
            "active_stream_count": self.active_stream_count,
            "event_count": self.event_count,
            "cursor_count": self.cursor_count,
            "live_cursor_count": self.live_cursor_count,
            "verified_proof_count": self.verified_proof_count,
            "subscriber_count": self.subscriber_count,
            "active_subscriber_count": self.active_subscriber_count,
            "sponsor_count": self.sponsor_count,
            "open_challenge_count": self.open_challenge_count,
            "total_sponsor_budget_micro_units": self.total_sponsor_budget_micro_units,
            "total_sponsor_available_micro_units": self.total_sponsor_available_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub streams: BTreeMap<String, ContractStream>,
    pub events: BTreeMap<String, PrivateEventEnvelope>,
    pub cursors: BTreeMap<String, EventCursorBatch>,
    pub proof_receipts: BTreeMap<String, IndexProofReceipt>,
    pub subscribers: BTreeMap<String, SubscriberFilter>,
    pub sponsor_ledger: BTreeMap<String, SponsorLedgerEntry>,
    pub challenges: BTreeMap<String, ChallengeRecord>,
    pub nullifier_index: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> ZkContractPrivateEventIndexerResult<Self> {
        let config = Config::devnet();
        let mut state = Self {
            height: 4,
            config,
            streams: BTreeMap::new(),
            events: BTreeMap::new(),
            cursors: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            subscribers: BTreeMap::new(),
            sponsor_ledger: BTreeMap::new(),
            challenges: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
        };

        let stream = ContractStream::new(
            "private-swap-router",
            &zk_private_event_commitment("deployment", "private-swap-router-v1"),
            &zk_private_event_commitment("abi", "swap-router-events-v1"),
            "router-governance",
            EventVisibility::Shielded,
            &json!({"sponsor": "router-relay", "max_fee_micro_units": 96}),
        )?;
        let stream_id = stream.stream_id.clone();
        state.insert_stream(stream)?;

        let event_a = PrivateEventEnvelope::new(
            &stream_id,
            1,
            2,
            &[
                "swap_commitment".to_string(),
                "pool_commitment".to_string(),
                "fee_commitment".to_string(),
            ],
            "encrypted-swap-event-a",
            "nullifier-a",
            "witness-a",
            "router-relay",
            &json!({"mode": "root_only"}),
            &state.config,
        )?;
        let event_b = PrivateEventEnvelope::new(
            &stream_id,
            2,
            3,
            &[
                "liquidity_commitment".to_string(),
                "price_band_commitment".to_string(),
            ],
            "encrypted-liquidity-event-b",
            "nullifier-b",
            "witness-b",
            "router-relay",
            &json!({"mode": "selective", "auditor": "devnet-auditor"}),
            &state.config,
        )?;
        state.insert_event(event_a.clone())?;
        state.insert_event(event_b.clone())?;

        let cursor = EventCursorBatch::new(
            &stream_id,
            &[event_a, event_b],
            2,
            4,
            "cursor-proof-a",
            &state.config,
        )?;
        let cursor_id = cursor.cursor_id.clone();
        state.insert_cursor(cursor)?;
        state.insert_proof_receipt(IndexProofReceipt::new(
            &cursor_id,
            "devnet-recursive-prover",
            "recursive-proof-a",
            4,
            64,
            ProofStatus::Verified,
        )?)?;
        state.insert_subscriber(SubscriberFilter::new(
            "private-wallet-sdk",
            &stream_id,
            &[
                "swap_commitment".to_string(),
                "liquidity_commitment".to_string(),
            ],
            &json!({"deliver": "topic_roots", "lag_blocks": 3}),
            8,
        )?)?;
        state.insert_sponsor(SponsorLedgerEntry::new(
            "router-relay",
            4_096,
            64,
            &[cursor_id.clone()],
            &json!({"floor": state.config.sponsor_fee_floor_micro_units, "rebate": "low_fee"}),
            &state.config,
        )?)?;
        state.insert_challenge(ChallengeRecord::new(
            &cursor_id,
            "watchtower-a",
            &json!({"claim": "topic_order_check", "severity": "notice"}),
            4,
            &state.config,
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_stream(
        &mut self,
        stream: ContractStream,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        stream.validate()?;
        self.streams.insert(stream.stream_id.clone(), stream);
        Ok(())
    }

    pub fn insert_event(
        &mut self,
        event: PrivateEventEnvelope,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        event.validate()?;
        if !self.streams.contains_key(&event.stream_id) {
            return Err("private event references unknown stream".to_string());
        }
        if self.nullifier_index.contains(&event.nullifier_root) {
            return Err("private event nullifier already indexed".to_string());
        }
        self.nullifier_index.insert(event.nullifier_root.clone());
        if let Some(stream) = self.streams.get_mut(&event.stream_id) {
            stream.event_count = stream.event_count.saturating_add(1);
        }
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn insert_cursor(
        &mut self,
        cursor: EventCursorBatch,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        cursor.validate()?;
        if !self.streams.contains_key(&cursor.stream_id) {
            return Err("private event cursor references unknown stream".to_string());
        }
        if let Some(stream) = self.streams.get_mut(&cursor.stream_id) {
            stream.cursor_count = stream.cursor_count.saturating_add(1);
        }
        self.cursors.insert(cursor.cursor_id.clone(), cursor);
        Ok(())
    }

    pub fn insert_proof_receipt(
        &mut self,
        receipt: IndexProofReceipt,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        receipt.validate()?;
        if !self.cursors.contains_key(&receipt.cursor_id) {
            return Err("private event proof references unknown cursor".to_string());
        }
        if receipt.status == ProofStatus::Verified {
            if let Some(cursor) = self.cursors.get_mut(&receipt.cursor_id) {
                cursor.status = CursorStatus::Proved;
            }
        }
        self.proof_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_subscriber(
        &mut self,
        subscriber: SubscriberFilter,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        subscriber.validate()?;
        if !self.streams.contains_key(&subscriber.stream_id) {
            return Err("private event subscriber references unknown stream".to_string());
        }
        self.subscribers
            .insert(subscriber.filter_id.clone(), subscriber);
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: SponsorLedgerEntry,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        sponsor.validate()?;
        self.sponsor_ledger
            .insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: ChallengeRecord,
    ) -> ZkContractPrivateEventIndexerResult<()> {
        challenge.validate()?;
        if !self.cursors.contains_key(&challenge.cursor_id) {
            return Err("private event challenge references unknown cursor".to_string());
        }
        if let Some(cursor) = self.cursors.get_mut(&challenge.cursor_id) {
            cursor.status = CursorStatus::Challenged;
        }
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkContractPrivateEventIndexerResult<()> {
        if height < self.height {
            return Err("private event indexer height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, delta: u64) -> ZkContractPrivateEventIndexerResult<()> {
        self.height = self.height.saturating_add(delta);
        Ok(())
    }

    pub fn validate(&self) -> ZkContractPrivateEventIndexerResult<()> {
        self.config.validate()?;
        let mut nullifiers = BTreeSet::new();
        for stream in self.streams.values() {
            stream.validate()?;
        }
        for event in self.events.values() {
            event.validate()?;
            if !self.streams.contains_key(&event.stream_id) {
                return Err("private event references unknown stream".to_string());
            }
            if !nullifiers.insert(event.nullifier_root.clone()) {
                return Err("private event duplicate nullifier".to_string());
            }
        }
        for cursor in self.cursors.values() {
            cursor.validate()?;
            if !self.streams.contains_key(&cursor.stream_id) {
                return Err("private event cursor references unknown stream".to_string());
            }
        }
        for receipt in self.proof_receipts.values() {
            receipt.validate()?;
            if !self.cursors.contains_key(&receipt.cursor_id) {
                return Err("private event receipt references unknown cursor".to_string());
            }
        }
        for subscriber in self.subscribers.values() {
            subscriber.validate()?;
            if !self.streams.contains_key(&subscriber.stream_id) {
                return Err("private event subscriber references unknown stream".to_string());
            }
        }
        for sponsor in self.sponsor_ledger.values() {
            sponsor.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.cursors.contains_key(&challenge.cursor_id) {
                return Err("private event challenge references unknown cursor".to_string());
            }
        }
        if nullifiers != self.nullifier_index {
            return Err("private event nullifier index mismatch".to_string());
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: zk_private_event_payload_root("config", &self.config.public_record()),
            stream_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:streams",
                &self
                    .streams
                    .values()
                    .map(ContractStream::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:events",
                &self
                    .events
                    .values()
                    .map(PrivateEventEnvelope::public_record)
                    .collect::<Vec<_>>(),
            ),
            cursor_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:cursors",
                &self
                    .cursors
                    .values()
                    .map(EventCursorBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            proof_receipt_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:proof-receipts",
                &self
                    .proof_receipts
                    .values()
                    .map(IndexProofReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            subscriber_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:subscribers",
                &self
                    .subscribers
                    .values()
                    .map(SubscriberFilter::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:sponsors",
                &self
                    .sponsor_ledger
                    .values()
                    .map(SponsorLedgerEntry::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_root: merkle_root(
                "ZK-CONTRACT-PRIVATE-EVENT:challenges",
                &self
                    .challenges
                    .values()
                    .map(ChallengeRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            stream_count: self.streams.len() as u64,
            active_stream_count: self.streams.values().filter(|stream| stream.active).count()
                as u64,
            event_count: self.events.len() as u64,
            cursor_count: self.cursors.len() as u64,
            live_cursor_count: self
                .cursors
                .values()
                .filter(|cursor| cursor.status.is_live())
                .count() as u64,
            verified_proof_count: self
                .proof_receipts
                .values()
                .filter(|receipt| receipt.status == ProofStatus::Verified)
                .count() as u64,
            subscriber_count: self.subscribers.len() as u64,
            active_subscriber_count: self
                .subscribers
                .values()
                .filter(|subscriber| subscriber.active)
                .count() as u64,
            sponsor_count: self.sponsor_ledger.len() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| !challenge.resolved)
                .count() as u64,
            total_sponsor_budget_micro_units: self
                .sponsor_ledger
                .values()
                .map(|sponsor| sponsor.budget_micro_units)
                .sum(),
            total_sponsor_available_micro_units: self
                .sponsor_ledger
                .values()
                .map(SponsorLedgerEntry::available_micro_units)
                .sum(),
        }
    }

    pub fn live_cursor_ids(&self) -> Vec<String> {
        self.cursors
            .values()
            .filter(|cursor| cursor.status.is_live())
            .map(|cursor| cursor.cursor_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| !challenge.resolved)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_contract_private_event_indexer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_PRIVATE_EVENT_INDEXER_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_cursor_ids": self.live_cursor_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-CONTRACT-PRIVATE-EVENT:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ZkContractPrivateEventIndexerResult<State> {
    State::devnet()
}

fn zk_private_event_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({"part": part}))
        .collect::<Vec<_>>();
    let root = merkle_root(&format!("ZK-CONTRACT-PRIVATE-EVENT:{domain}:id"), &leaves);
    domain_hash(
        &format!("ZK-CONTRACT-PRIVATE-EVENT:{domain}:id-final"),
        &[HashPart::Str(root.as_str())],
        16,
    )
}

fn zk_private_event_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("ZK-CONTRACT-PRIVATE-EVENT:{domain}:commitment"),
        &[HashPart::Str(label)],
        32,
    )
}

fn zk_private_event_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("ZK-CONTRACT-PRIVATE-EVENT:{domain}:payload"),
        &[HashPart::Json(payload)],
        32,
    )
}

fn zk_private_event_string_root(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({"value": part}))
        .collect::<Vec<_>>();
    merkle_root(&format!("ZK-CONTRACT-PRIVATE-EVENT:{domain}"), &leaves)
}
