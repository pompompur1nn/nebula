use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        public_key_for_label, sign_validator_authorization, sign_watchtower_authorization,
        verify_validator_authorization, verify_watchtower_authorization, Authorization, CryptoRole,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type AvailabilityResult<T> = Result<T, String>;

pub const AVAILABILITY_PROTOCOL_VERSION: u64 = 1;
pub const AVAILABILITY_DEFAULT_EPOCH_LENGTH: u64 = 120;
pub const AVAILABILITY_DEFAULT_QUORUM_BPS: u64 = 6_667;
pub const AVAILABILITY_DEFAULT_SHARD_SIZE_BYTES: u64 = 512;
pub const AVAILABILITY_DEFAULT_ORIGINAL_SHARDS: u64 = 8;
pub const AVAILABILITY_DEFAULT_PARITY_SHARDS: u64 = 8;
pub const AVAILABILITY_DEFAULT_SAMPLE_COUNT: u64 = 8;
pub const AVAILABILITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 8;
pub const AVAILABILITY_DEFAULT_RETENTION_BLOCKS: u64 = 14_400;
pub const AVAILABILITY_ARCHIVE_GRACE_BLOCKS: u64 = 120;
pub const AVAILABILITY_MAX_COMMITTEE_MEMBERS: u64 = 256;
pub const AVAILABILITY_MAX_SHARDS_PER_BATCH: u64 = 4_096;
pub const AVAILABILITY_MAX_SAMPLE_COUNT: u64 = 128;
pub const AVAILABILITY_MISSING_SAMPLE_SLASH_BPS: u64 = 250;
pub const AVAILABILITY_INVALID_ATTESTATION_SLASH_BPS: u64 = 1_000;
pub const AVAILABILITY_RETENTION_GAP_SLASH_BPS: u64 = 500;
pub const AVAILABILITY_RETENTION_FEE_BLOCK_QUANTUM: u64 = 720;
pub const DA_LOW_FEE_LANE_TYPE: &str = "low_fee_da";
pub const DA_BATCHED_TX_LANE_KEY: &str = "batched_transactions";
pub const DA_MONERO_PROOF_LANE_KEY: &str = "monero_proofs";
pub const DA_ARCHIVE_REPLAY_LANE_KEY: &str = "archive_replay";
pub const DA_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const DA_QUOTE_DEFAULT_TTL_BLOCKS: u64 = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitteeMember {
    pub member_id: String,
    pub validator_id: String,
    pub label: String,
    pub consensus_public_key: String,
    pub da_public_key: String,
    pub bonded_stake: u64,
    pub effective_stake: u64,
    pub archive_capacity_bytes: u64,
    pub max_shards_per_epoch: u64,
    pub joined_at_height: u64,
    pub retired_at_height: u64,
    pub slashed_stake: u64,
    pub missed_sample_count: u64,
    pub status: String,
}

impl DaCommitteeMember {
    pub fn new(
        label: impl Into<String>,
        validator_id: impl Into<String>,
        bonded_stake: u64,
        archive_capacity_bytes: u64,
        max_shards_per_epoch: u64,
        joined_at_height: u64,
    ) -> AvailabilityResult<Self> {
        let label = label.into();
        let validator_id = validator_id.into();
        if label.trim().is_empty() {
            return Err("DA committee member label cannot be empty".to_string());
        }
        if validator_id.trim().is_empty() {
            return Err("DA committee member validator id cannot be empty".to_string());
        }
        if bonded_stake == 0 {
            return Err("DA committee member stake cannot be zero".to_string());
        }
        let consensus_public_key =
            public_key_for_label(CryptoRole::ValidatorSignature, &label).public_key;
        let da_public_key = public_key_for_label(CryptoRole::NetworkSignature, &label).public_key;
        let member_id =
            da_committee_member_id(&validator_id, &consensus_public_key, &da_public_key);
        Ok(Self {
            member_id,
            validator_id,
            label,
            consensus_public_key,
            da_public_key,
            bonded_stake,
            effective_stake: bonded_stake,
            archive_capacity_bytes,
            max_shards_per_epoch,
            joined_at_height,
            retired_at_height: 0,
            slashed_stake: 0,
            missed_sample_count: 0,
            status: "active".to_string(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.effective_stake > 0
            && self.joined_at_height <= height
            && (self.retired_at_height == 0 || height < self.retired_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_committee_member",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "validator_id": self.validator_id,
            "label": self.label,
            "consensus_public_key": self.consensus_public_key,
            "da_public_key": self.da_public_key,
            "bonded_stake": self.bonded_stake,
            "effective_stake": self.effective_stake,
            "archive_capacity_bytes": self.archive_capacity_bytes,
            "max_shards_per_epoch": self.max_shards_per_epoch,
            "joined_at_height": self.joined_at_height,
            "retired_at_height": self.retired_at_height,
            "slashed_stake": self.slashed_stake,
            "missed_sample_count": self.missed_sample_count,
            "status": self.status,
        })
    }

    pub fn member_root(&self) -> String {
        domain_hash(
            "DA-COMMITTEE-MEMBER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.validator_id, "DA committee member validator id")?;
        ensure_non_empty(&self.label, "DA committee member label")?;
        ensure_non_empty(
            &self.consensus_public_key,
            "DA committee member consensus public key",
        )?;
        ensure_non_empty(&self.da_public_key, "DA committee member public key")?;
        if self.bonded_stake == 0 {
            return Err("DA committee member bonded stake cannot be zero".to_string());
        }
        if self.effective_stake > self.bonded_stake {
            return Err("DA committee member effective stake exceeds bonded stake".to_string());
        }
        if self.slashed_stake > self.bonded_stake {
            return Err("DA committee member slashed stake exceeds bonded stake".to_string());
        }
        if self.retired_at_height > 0 && self.retired_at_height <= self.joined_at_height {
            return Err("DA committee member retirement precedes join height".to_string());
        }
        ensure_status(
            &self.status,
            &["active", "exiting", "retired", "slashed", "slashed_out"],
            "DA committee member status",
        )?;
        let expected_consensus =
            public_key_for_label(CryptoRole::ValidatorSignature, &self.label).public_key;
        if self.consensus_public_key != expected_consensus {
            return Err("DA committee member consensus public key mismatch".to_string());
        }
        let expected_da =
            public_key_for_label(CryptoRole::NetworkSignature, &self.label).public_key;
        if self.da_public_key != expected_da {
            return Err("DA committee member public key mismatch".to_string());
        }
        if self.member_id
            != da_committee_member_id(
                &self.validator_id,
                &self.consensus_public_key,
                &self.da_public_key,
            )
        {
            return Err("DA committee member id mismatch".to_string());
        }
        Ok(self.member_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub quorum_bps: u64,
    pub sample_size: u64,
    pub retention_blocks: u64,
    pub selection_seed: String,
    pub members: Vec<DaCommitteeMember>,
    pub status: String,
}

impl DaCommittee {
    pub fn new(
        epoch: u64,
        epoch_start_height: u64,
        epoch_end_height: u64,
        selection_seed: impl Into<String>,
        members: Vec<DaCommitteeMember>,
    ) -> AvailabilityResult<Self> {
        Self::with_policy(
            epoch,
            epoch_start_height,
            epoch_end_height,
            AVAILABILITY_DEFAULT_QUORUM_BPS,
            AVAILABILITY_DEFAULT_SAMPLE_COUNT,
            AVAILABILITY_DEFAULT_RETENTION_BLOCKS,
            selection_seed,
            members,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_policy(
        epoch: u64,
        epoch_start_height: u64,
        epoch_end_height: u64,
        quorum_bps: u64,
        sample_size: u64,
        retention_blocks: u64,
        selection_seed: impl Into<String>,
        members: Vec<DaCommitteeMember>,
    ) -> AvailabilityResult<Self> {
        let mut committee = Self {
            committee_id: String::new(),
            epoch,
            epoch_start_height,
            epoch_end_height,
            quorum_bps,
            sample_size,
            retention_blocks,
            selection_seed: selection_seed.into(),
            members,
            status: "active".to_string(),
        };
        committee.committee_id = da_committee_id(&committee.identity_record());
        committee.validate()?;
        Ok(committee)
    }

    pub fn member_records(&self) -> Vec<Value> {
        let mut records = self
            .members
            .iter()
            .map(|member| (member.member_id.clone(), member.public_record()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(|(_, record)| record).collect()
    }

    pub fn member_root(&self) -> String {
        merkle_root("DA-COMMITTEE-MEMBER", &self.member_records())
    }

    pub fn total_stake(&self) -> u64 {
        self.members.iter().fold(0_u64, |total, member| {
            total.saturating_add(member.effective_stake)
        })
    }

    pub fn quorum_stake(&self) -> u64 {
        bps_ceil(self.total_stake(), self.quorum_bps)
    }

    pub fn active_member_count_at(&self, height: u64) -> u64 {
        self.members
            .iter()
            .filter(|member| member.is_active_at(height))
            .count() as u64
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_committee",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "epoch": self.epoch,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "quorum_bps": self.quorum_bps,
            "sample_size": self.sample_size,
            "retention_blocks": self.retention_blocks,
            "selection_seed": self.selection_seed,
            "member_root": self.member_root(),
            "member_count": self.members.len() as u64,
            "total_stake": self.total_stake(),
            "quorum_stake": self.quorum_stake(),
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.committee_id == da_committee_id(&self.identity_record())
    }

    pub fn committee_root(&self) -> String {
        domain_hash(
            "DA-COMMITTEE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("DA committee identity record object")
            .insert(
                "committee_id".to_string(),
                Value::String(self.committee_id.clone()),
            );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("DA committee public record object");
        object.insert(
            "committee_root".to_string(),
            Value::String(self.committee_root()),
        );
        object.insert("members".to_string(), Value::Array(self.member_records()));
        record
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        if self.epoch_end_height < self.epoch_start_height {
            return Err("DA committee epoch range is inverted".to_string());
        }
        validate_bps(self.quorum_bps, "DA committee quorum")?;
        if self.quorum_bps == 0 {
            return Err("DA committee quorum cannot be zero".to_string());
        }
        if self.sample_size == 0 {
            return Err("DA committee sample size cannot be zero".to_string());
        }
        if self.sample_size > AVAILABILITY_MAX_SAMPLE_COUNT {
            return Err("DA committee sample size exceeds maximum".to_string());
        }
        if self.retention_blocks == 0 {
            return Err("DA committee retention blocks cannot be zero".to_string());
        }
        ensure_non_empty(&self.selection_seed, "DA committee selection seed")?;
        ensure_status(
            &self.status,
            &["active", "rotating", "retired", "halted"],
            "DA committee status",
        )?;
        if self.members.is_empty() {
            return Err("DA committee requires members".to_string());
        }
        if self.members.len() as u64 > AVAILABILITY_MAX_COMMITTEE_MEMBERS {
            return Err("DA committee member count exceeds maximum".to_string());
        }
        let mut member_ids = Vec::with_capacity(self.members.len());
        let mut validator_ids = Vec::with_capacity(self.members.len());
        for member in &self.members {
            member.validate()?;
            member_ids.push(member.member_id.clone());
            validator_ids.push(member.validator_id.clone());
        }
        ensure_unique_strings(&member_ids, "DA committee member")?;
        ensure_unique_strings(&validator_ids, "DA committee validator")?;
        if self.total_stake() == 0 {
            return Err("DA committee total stake cannot be zero".to_string());
        }
        if !self.verify_id() {
            return Err("DA committee id mismatch".to_string());
        }
        Ok(self.committee_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureShardCommitment {
    pub shard_id: String,
    pub batch_id: String,
    pub block_height: u64,
    pub lane_id: String,
    pub payload_hash: String,
    pub shard_index: u64,
    pub shard_kind: String,
    pub shard_size_bytes: u64,
    pub encoded_size_bytes: u64,
    pub shard_hash: String,
    pub proof_root: String,
    pub retention_until_height: u64,
    pub shard_commitment: String,
    pub status: String,
}

impl ErasureShardCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        block_height: u64,
        lane_id: impl Into<String>,
        payload_hash: impl Into<String>,
        shard_index: u64,
        shard_kind: impl Into<String>,
        shard_size_bytes: u64,
        encoded_size_bytes: u64,
        shard_hash: impl Into<String>,
        proof_root: impl Into<String>,
        retention_until_height: u64,
    ) -> Self {
        let mut shard = Self {
            shard_id: String::new(),
            batch_id: batch_id.into(),
            block_height,
            lane_id: lane_id.into(),
            payload_hash: payload_hash.into(),
            shard_index,
            shard_kind: shard_kind.into(),
            shard_size_bytes,
            encoded_size_bytes,
            shard_hash: shard_hash.into(),
            proof_root: proof_root.into(),
            retention_until_height,
            shard_commitment: String::new(),
            status: "committed".to_string(),
        };
        shard.shard_id = erasure_shard_commitment_id(&shard.commitment_record());
        shard.shard_commitment = erasure_shard_commitment_hash(&shard.commitment_record());
        shard
    }

    pub fn commitment_record(&self) -> Value {
        json!({
            "kind": "erasure_shard_commitment",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "block_height": self.block_height,
            "lane_id": self.lane_id,
            "payload_hash": self.payload_hash,
            "shard_index": self.shard_index,
            "shard_kind": self.shard_kind,
            "shard_size_bytes": self.shard_size_bytes,
            "encoded_size_bytes": self.encoded_size_bytes,
            "shard_hash": self.shard_hash,
            "proof_root": self.proof_root,
            "retention_until_height": self.retention_until_height,
            "status": self.status,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.commitment_record();
        let object = record
            .as_object_mut()
            .expect("erasure shard commitment record object");
        object.insert("batch_id".to_string(), Value::String(self.batch_id.clone()));
        object.insert("shard_id".to_string(), Value::String(self.shard_id.clone()));
        object.insert(
            "shard_commitment".to_string(),
            Value::String(self.shard_commitment.clone()),
        );
        record
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.batch_id, "erasure shard batch id")?;
        ensure_non_empty(&self.lane_id, "erasure shard lane id")?;
        ensure_non_empty(&self.payload_hash, "erasure shard payload hash")?;
        ensure_non_empty(&self.shard_hash, "erasure shard hash")?;
        ensure_non_empty(&self.proof_root, "erasure shard proof root")?;
        ensure_status(
            &self.shard_kind,
            &["data", "parity", "repair"],
            "erasure shard kind",
        )?;
        ensure_status(
            &self.status,
            &["committed", "available", "missing", "challenged", "pruned"],
            "erasure shard status",
        )?;
        if self.shard_size_bytes == 0 {
            return Err("erasure shard size cannot be zero".to_string());
        }
        if self.encoded_size_bytes == 0 {
            return Err("erasure encoded shard size cannot be zero".to_string());
        }
        if self.retention_until_height <= self.block_height {
            return Err("erasure shard retention must extend past block height".to_string());
        }
        if self.shard_id != erasure_shard_commitment_id(&self.commitment_record()) {
            return Err("erasure shard id mismatch".to_string());
        }
        if self.shard_commitment != erasure_shard_commitment_hash(&self.commitment_record()) {
            return Err("erasure shard commitment mismatch".to_string());
        }
        Ok(self.shard_commitment.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureBatchCommitment {
    pub batch_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub tx_root: String,
    pub payload_hash: String,
    pub lane_id: String,
    pub lane_type: String,
    pub lane_key: String,
    pub committee_id: String,
    pub commitment_scheme: String,
    pub shard_size_bytes: u64,
    pub original_shard_count: u64,
    pub parity_shard_count: u64,
    pub original_bytes: u64,
    pub encoded_bytes: u64,
    pub retention_until_height: u64,
    pub created_at_height: u64,
    pub shards: Vec<ErasureShardCommitment>,
    pub status: String,
}

impl ErasureBatchCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_height: u64,
        block_hash: impl Into<String>,
        tx_root: impl Into<String>,
        payload_hash: impl Into<String>,
        lane: &DaLane,
        committee_id: impl Into<String>,
        original_bytes: u64,
        retention_until_height: u64,
        created_at_height: u64,
        mut shards: Vec<ErasureShardCommitment>,
    ) -> AvailabilityResult<Self> {
        let lane_id = lane.lane_id.clone();
        let mut batch = Self {
            batch_id: String::new(),
            block_height,
            block_hash: block_hash.into(),
            tx_root: tx_root.into(),
            payload_hash: payload_hash.into(),
            lane_id,
            lane_type: lane.lane_type.clone(),
            lane_key: lane.lane_key.clone(),
            committee_id: committee_id.into(),
            commitment_scheme: "rs-devnet-merkle-shards-v1".to_string(),
            shard_size_bytes: lane.shard_size_bytes,
            original_shard_count: shards
                .iter()
                .filter(|shard| shard.shard_kind == "data")
                .count() as u64,
            parity_shard_count: shards
                .iter()
                .filter(|shard| shard.shard_kind == "parity")
                .count() as u64,
            original_bytes,
            encoded_bytes: shards.iter().fold(0_u64, |total, shard| {
                total.saturating_add(shard.encoded_size_bytes)
            }),
            retention_until_height,
            created_at_height,
            shards: Vec::new(),
            status: "committed".to_string(),
        };
        batch.batch_id = erasure_batch_id(
            batch.block_height,
            &batch.payload_hash,
            &batch.lane_id,
            &batch.committee_id,
            &erasure_shard_commitment_root(&shards),
        );
        for shard in &mut shards {
            shard.batch_id = batch.batch_id.clone();
        }
        batch.shards = shards;
        batch.validate()?;
        Ok(batch)
    }

    pub fn shard_commitment_root(&self) -> String {
        erasure_shard_commitment_root(&self.shards)
    }

    pub fn shard_root(&self) -> String {
        erasure_shard_root(&self.shards)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "erasure_batch_commitment",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "tx_root": self.tx_root,
            "payload_hash": self.payload_hash,
            "lane_id": self.lane_id,
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "committee_id": self.committee_id,
            "commitment_scheme": self.commitment_scheme,
            "shard_size_bytes": self.shard_size_bytes,
            "original_shard_count": self.original_shard_count,
            "parity_shard_count": self.parity_shard_count,
            "original_bytes": self.original_bytes,
            "encoded_bytes": self.encoded_bytes,
            "retention_until_height": self.retention_until_height,
            "created_at_height": self.created_at_height,
            "shard_commitment_root": self.shard_commitment_root(),
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.batch_id
            == erasure_batch_id(
                self.block_height,
                &self.payload_hash,
                &self.lane_id,
                &self.committee_id,
                &self.shard_commitment_root(),
            )
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("erasure batch identity record object");
        object.insert("batch_id".to_string(), Value::String(self.batch_id.clone()));
        object.insert("shard_root".to_string(), Value::String(self.shard_root()));
        object.insert("shard_count".to_string(), json!(self.shards.len() as u64));
        record
    }

    pub fn batch_root(&self) -> String {
        domain_hash(
            "DA-ERASURE-BATCH",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("erasure batch public record object");
        object.insert("batch_root".to_string(), Value::String(self.batch_root()));
        object.insert(
            "shards".to_string(),
            Value::Array(
                self.shards
                    .iter()
                    .map(ErasureShardCommitment::public_record)
                    .collect(),
            ),
        );
        record
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.block_hash, "erasure batch block hash")?;
        ensure_non_empty(&self.tx_root, "erasure batch tx root")?;
        ensure_non_empty(&self.payload_hash, "erasure batch payload hash")?;
        ensure_non_empty(&self.lane_id, "erasure batch lane id")?;
        ensure_non_empty(&self.lane_type, "erasure batch lane type")?;
        ensure_non_empty(&self.lane_key, "erasure batch lane key")?;
        ensure_non_empty(&self.committee_id, "erasure batch committee id")?;
        ensure_non_empty(&self.commitment_scheme, "erasure batch commitment scheme")?;
        ensure_status(
            &self.status,
            &["committed", "available", "challenged", "retained", "pruned"],
            "erasure batch status",
        )?;
        if self.shard_size_bytes == 0 {
            return Err("erasure batch shard size cannot be zero".to_string());
        }
        if self.shards.is_empty() {
            return Err("erasure batch requires shards".to_string());
        }
        if self.shards.len() as u64 > AVAILABILITY_MAX_SHARDS_PER_BATCH {
            return Err("erasure batch shard count exceeds maximum".to_string());
        }
        if self.original_shard_count == 0 {
            return Err("erasure batch original shard count cannot be zero".to_string());
        }
        if self.parity_shard_count == 0 {
            return Err("erasure batch parity shard count cannot be zero".to_string());
        }
        if self.original_shard_count + self.parity_shard_count != self.shards.len() as u64 {
            return Err("erasure batch shard count mismatch".to_string());
        }
        if self.original_bytes == 0 {
            return Err("erasure batch original bytes cannot be zero".to_string());
        }
        let encoded_bytes = self.shards.iter().fold(0_u64, |total, shard| {
            total.saturating_add(shard.encoded_size_bytes)
        });
        if self.encoded_bytes != encoded_bytes {
            return Err("erasure batch encoded byte count mismatch".to_string());
        }
        if self.encoded_bytes < self.original_bytes {
            return Err("erasure batch encoded bytes below original bytes".to_string());
        }
        if self.retention_until_height <= self.block_height {
            return Err("erasure batch retention must extend past block height".to_string());
        }
        let mut indices = Vec::with_capacity(self.shards.len());
        let mut data_count = 0_u64;
        let mut parity_count = 0_u64;
        for shard in &self.shards {
            shard.validate()?;
            if shard.batch_id != self.batch_id {
                return Err("erasure shard references different batch".to_string());
            }
            if shard.block_height != self.block_height
                || shard.lane_id != self.lane_id
                || shard.payload_hash != self.payload_hash
            {
                return Err("erasure shard commitment target mismatch".to_string());
            }
            if shard.retention_until_height != self.retention_until_height {
                return Err("erasure shard retention mismatch".to_string());
            }
            if shard.shard_kind == "data" {
                data_count = data_count.saturating_add(1);
            } else if shard.shard_kind == "parity" {
                parity_count = parity_count.saturating_add(1);
            }
            indices.push(shard.shard_index);
        }
        ensure_unique_u64(&indices, "erasure shard index")?;
        if data_count != self.original_shard_count || parity_count != self.parity_shard_count {
            return Err("erasure batch shard kind count mismatch".to_string());
        }
        if !self.verify_id() {
            return Err("erasure batch id mismatch".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingChallenge {
    pub challenge_id: String,
    pub batch_id: String,
    pub committee_id: String,
    pub challenger_label: String,
    pub challenger_public_key: String,
    pub challenge_height: u64,
    pub expires_at_height: u64,
    pub sample_seed: String,
    pub sample_indices: Vec<u64>,
    pub sample_root: String,
    pub status: String,
    pub authorization: Authorization,
}

impl SamplingChallenge {
    pub fn new(
        batch: &ErasureBatchCommitment,
        challenger_label: &str,
        challenge_height: u64,
        challenge_window_blocks: u64,
        sample_count: u64,
    ) -> AvailabilityResult<Self> {
        if challenge_window_blocks == 0 {
            return Err("sampling challenge window cannot be zero".to_string());
        }
        if sample_count == 0 {
            return Err("sampling challenge sample count cannot be zero".to_string());
        }
        let challenger_public_key =
            public_key_for_label(CryptoRole::WatchtowerSignature, challenger_label).public_key;
        let sample_seed = sampling_challenge_seed(
            &batch.batch_id,
            &batch.payload_hash,
            challenger_label,
            challenge_height,
        );
        let sample_indices =
            derive_sample_indices(&sample_seed, batch.shards.len() as u64, sample_count)?;
        let sample_root = sampling_index_root(&sample_indices);
        let challenge_id = sampling_challenge_id(
            &batch.batch_id,
            &batch.committee_id,
            challenger_label,
            challenge_height,
            &sample_root,
        );
        let mut challenge = Self {
            challenge_id,
            batch_id: batch.batch_id.clone(),
            committee_id: batch.committee_id.clone(),
            challenger_label: challenger_label.to_string(),
            challenger_public_key,
            challenge_height,
            expires_at_height: challenge_height.saturating_add(challenge_window_blocks),
            sample_seed,
            sample_indices,
            sample_root,
            status: "open".to_string(),
            authorization: empty_authorization(CryptoRole::WatchtowerSignature, challenger_label),
        };
        challenge.authorization = sign_watchtower_authorization(
            challenger_label,
            "availability_sampling_challenge",
            &challenge.unsigned_record(),
        );
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "availability_sampling_challenge",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "committee_id": self.committee_id,
            "challenger_label": self.challenger_label,
            "challenger_public_key": self.challenger_public_key,
            "challenge_height": self.challenge_height,
            "expires_at_height": self.expires_at_height,
            "sample_seed": self.sample_seed,
            "sample_indices": self.sample_indices,
            "sample_count": self.sample_indices.len() as u64,
            "sample_root": self.sample_root,
            "status": self.status,
        })
    }

    pub fn challenge_root(&self) -> String {
        domain_hash(
            "DA-SAMPLING-CHALLENGE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        with_authorization(
            with_root_field(
                self.unsigned_record(),
                "challenge_root",
                self.challenge_root(),
            ),
            &self.authorization,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_watchtower_authorization(
            &self.challenger_public_key,
            "availability_sampling_challenge",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.batch_id, "sampling challenge batch id")?;
        ensure_non_empty(&self.committee_id, "sampling challenge committee id")?;
        ensure_non_empty(
            &self.challenger_label,
            "sampling challenge challenger label",
        )?;
        ensure_non_empty(
            &self.challenger_public_key,
            "sampling challenge challenger public key",
        )?;
        ensure_non_empty(&self.sample_seed, "sampling challenge sample seed")?;
        if self.expires_at_height <= self.challenge_height {
            return Err("sampling challenge expiry must be after challenge height".to_string());
        }
        if self.sample_indices.is_empty() {
            return Err("sampling challenge requires sample indices".to_string());
        }
        if self.sample_indices.len() as u64 > AVAILABILITY_MAX_SAMPLE_COUNT {
            return Err("sampling challenge sample count exceeds maximum".to_string());
        }
        ensure_unique_u64(&self.sample_indices, "sampling challenge sample index")?;
        if self.sample_root != sampling_index_root(&self.sample_indices) {
            return Err("sampling challenge sample root mismatch".to_string());
        }
        if self.challenge_id
            != sampling_challenge_id(
                &self.batch_id,
                &self.committee_id,
                &self.challenger_label,
                self.challenge_height,
                &self.sample_root,
            )
        {
            return Err("sampling challenge id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &["open", "answered", "expired", "slashable", "closed"],
            "sampling challenge status",
        )?;
        let expected_public_key =
            public_key_for_label(CryptoRole::WatchtowerSignature, &self.challenger_label)
                .public_key;
        if self.challenger_public_key != expected_public_key {
            return Err("sampling challenge public key mismatch".to_string());
        }
        if !self.verify_authorization() {
            return Err("sampling challenge authorization failed".to_string());
        }
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingResponse {
    pub response_id: String,
    pub challenge_id: String,
    pub batch_id: String,
    pub responder_member_id: String,
    pub responder_label: String,
    pub responder_public_key: String,
    pub response_height: u64,
    pub sampled_shards: Vec<ErasureShardCommitment>,
    pub sampled_shard_root: String,
    pub unavailable_indices: Vec<u64>,
    pub status: String,
    pub authorization: Authorization,
}

impl SamplingResponse {
    pub fn new(
        challenge: &SamplingChallenge,
        member: &DaCommitteeMember,
        sampled_shards: Vec<ErasureShardCommitment>,
        unavailable_indices: Vec<u64>,
        response_height: u64,
    ) -> AvailabilityResult<Self> {
        let sampled_shard_root = erasure_sampled_shard_root(&sampled_shards);
        let response_id = sampling_response_id(
            &challenge.challenge_id,
            &member.member_id,
            response_height,
            &sampled_shard_root,
        );
        let status = if unavailable_indices.is_empty() {
            "answered"
        } else {
            "partial"
        };
        let mut response = Self {
            response_id,
            challenge_id: challenge.challenge_id.clone(),
            batch_id: challenge.batch_id.clone(),
            responder_member_id: member.member_id.clone(),
            responder_label: member.label.clone(),
            responder_public_key: member.consensus_public_key.clone(),
            response_height,
            sampled_shards,
            sampled_shard_root,
            unavailable_indices,
            status: status.to_string(),
            authorization: empty_authorization(CryptoRole::ValidatorSignature, &member.label),
        };
        response.authorization = sign_validator_authorization(
            &response.responder_label,
            "availability_sampling_response",
            &response.unsigned_record(),
        );
        response.validate()?;
        Ok(response)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "availability_sampling_response",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "response_id": self.response_id,
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "responder_member_id": self.responder_member_id,
            "responder_label": self.responder_label,
            "responder_public_key": self.responder_public_key,
            "response_height": self.response_height,
            "sampled_shard_root": self.sampled_shard_root,
            "sampled_shard_count": self.sampled_shards.len() as u64,
            "unavailable_indices": self.unavailable_indices,
            "unavailable_count": self.unavailable_indices.len() as u64,
            "status": self.status,
        })
    }

    pub fn response_root(&self) -> String {
        domain_hash(
            "DA-SAMPLING-RESPONSE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = with_root_field(
            self.unsigned_record(),
            "response_root",
            self.response_root(),
        );
        record
            .as_object_mut()
            .expect("sampling response public record object")
            .insert(
                "sampled_shards".to_string(),
                Value::Array(
                    self.sampled_shards
                        .iter()
                        .map(ErasureShardCommitment::public_record)
                        .collect(),
                ),
            );
        with_authorization(record, &self.authorization)
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.responder_public_key,
            "availability_sampling_response",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.challenge_id, "sampling response challenge id")?;
        ensure_non_empty(&self.batch_id, "sampling response batch id")?;
        ensure_non_empty(&self.responder_member_id, "sampling response member id")?;
        ensure_non_empty(&self.responder_label, "sampling response label")?;
        ensure_non_empty(&self.responder_public_key, "sampling response public key")?;
        ensure_status(
            &self.status,
            &["answered", "partial", "late", "rejected"],
            "sampling response status",
        )?;
        ensure_unique_u64(
            &self.unavailable_indices,
            "sampling response unavailable index",
        )?;
        let mut sampled_indices = Vec::with_capacity(self.sampled_shards.len());
        for shard in &self.sampled_shards {
            shard.validate()?;
            if shard.batch_id != self.batch_id {
                return Err("sampling response shard batch mismatch".to_string());
            }
            sampled_indices.push(shard.shard_index);
        }
        ensure_unique_u64(&sampled_indices, "sampling response sampled shard")?;
        if self.sampled_shard_root != erasure_sampled_shard_root(&self.sampled_shards) {
            return Err("sampling response sampled shard root mismatch".to_string());
        }
        if self.response_id
            != sampling_response_id(
                &self.challenge_id,
                &self.responder_member_id,
                self.response_height,
                &self.sampled_shard_root,
            )
        {
            return Err("sampling response id mismatch".to_string());
        }
        if !self.verify_authorization() {
            return Err("sampling response authorization failed".to_string());
        }
        Ok(self.response_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub validator_id: String,
    pub signer_label: String,
    pub consensus_public_key: String,
    pub stake_weight: u64,
    pub attested_at_height: u64,
    pub shard_commitment_root: String,
    pub sample_challenge_root: String,
    pub retained_until_height: u64,
    pub availability_claim: String,
    pub status: String,
    pub authorization: Authorization,
}

impl AvailabilityAttestation {
    pub fn new(
        batch: &ErasureBatchCommitment,
        member: &DaCommitteeMember,
        sample_challenge_root: impl Into<String>,
        attested_at_height: u64,
        availability_claim: impl Into<String>,
    ) -> AvailabilityResult<Self> {
        let availability_claim = availability_claim.into();
        let shard_commitment_root = batch.shard_commitment_root();
        let attestation_id = availability_attestation_id(
            &batch.batch_id,
            &batch.committee_id,
            &member.member_id,
            attested_at_height,
            &shard_commitment_root,
            &availability_claim,
        );
        let mut attestation = Self {
            attestation_id,
            batch_id: batch.batch_id.clone(),
            committee_id: batch.committee_id.clone(),
            member_id: member.member_id.clone(),
            validator_id: member.validator_id.clone(),
            signer_label: member.label.clone(),
            consensus_public_key: member.consensus_public_key.clone(),
            stake_weight: member.effective_stake,
            attested_at_height,
            shard_commitment_root,
            sample_challenge_root: sample_challenge_root.into(),
            retained_until_height: batch.retention_until_height,
            availability_claim,
            status: "attested".to_string(),
            authorization: empty_authorization(CryptoRole::ValidatorSignature, &member.label),
        };
        attestation.authorization = sign_validator_authorization(
            &attestation.signer_label,
            "availability_attestation",
            &attestation.unsigned_record(),
        );
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "availability_attestation",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "validator_id": self.validator_id,
            "signer_label": self.signer_label,
            "consensus_public_key": self.consensus_public_key,
            "stake_weight": self.stake_weight,
            "attested_at_height": self.attested_at_height,
            "shard_commitment_root": self.shard_commitment_root,
            "sample_challenge_root": self.sample_challenge_root,
            "retained_until_height": self.retained_until_height,
            "availability_claim": self.availability_claim,
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        domain_hash(
            "DA-AVAILABILITY-ATTESTATION",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        with_authorization(
            with_root_field(
                self.unsigned_record(),
                "attestation_root",
                self.attestation_root(),
            ),
            &self.authorization,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.consensus_public_key,
            "availability_attestation",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.batch_id, "availability attestation batch id")?;
        ensure_non_empty(&self.committee_id, "availability attestation committee id")?;
        ensure_non_empty(&self.member_id, "availability attestation member id")?;
        ensure_non_empty(&self.validator_id, "availability attestation validator id")?;
        ensure_non_empty(&self.signer_label, "availability attestation signer label")?;
        ensure_non_empty(
            &self.consensus_public_key,
            "availability attestation consensus public key",
        )?;
        ensure_non_empty(
            &self.shard_commitment_root,
            "availability attestation shard commitment root",
        )?;
        ensure_non_empty(
            &self.availability_claim,
            "availability attestation availability claim",
        )?;
        ensure_status(
            &self.availability_claim,
            &["available", "sampled", "retained", "unavailable"],
            "availability attestation claim",
        )?;
        ensure_status(
            &self.status,
            &["attested", "challenged", "accepted", "rejected"],
            "availability attestation status",
        )?;
        if self.stake_weight == 0 {
            return Err("availability attestation stake cannot be zero".to_string());
        }
        if self.retained_until_height <= self.attested_at_height {
            return Err(
                "availability attestation retention expired before attestation".to_string(),
            );
        }
        if self.attestation_id
            != availability_attestation_id(
                &self.batch_id,
                &self.committee_id,
                &self.member_id,
                self.attested_at_height,
                &self.shard_commitment_root,
                &self.availability_claim,
            )
        {
            return Err("availability attestation id mismatch".to_string());
        }
        if !self.verify_authorization() {
            return Err("availability attestation authorization failed".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaLane {
    pub lane_id: String,
    pub lane_type: String,
    pub lane_key: String,
    pub priority: u64,
    pub shard_size_bytes: u64,
    pub base_fee_per_encoded_byte: u64,
    pub retention_fee_per_byte_quantum: u64,
    pub sample_fee_units: u64,
    pub floor_fee_units: u64,
    pub target_bytes_per_block: u64,
    pub max_bytes_per_quote: u64,
    pub default_retention_blocks: u64,
    pub subsidy_bps: u64,
    pub status: String,
}

impl DaLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_type: impl Into<String>,
        lane_key: impl Into<String>,
        priority: u64,
        shard_size_bytes: u64,
        base_fee_per_encoded_byte: u64,
        retention_fee_per_byte_quantum: u64,
        sample_fee_units: u64,
        floor_fee_units: u64,
        target_bytes_per_block: u64,
        max_bytes_per_quote: u64,
        default_retention_blocks: u64,
        subsidy_bps: u64,
    ) -> AvailabilityResult<Self> {
        let lane_type = lane_type.into();
        let lane_key = lane_key.into();
        let lane_id = da_lane_id(&lane_type, &lane_key);
        let lane = Self {
            lane_id,
            lane_type,
            lane_key,
            priority,
            shard_size_bytes,
            base_fee_per_encoded_byte,
            retention_fee_per_byte_quantum,
            sample_fee_units,
            floor_fee_units,
            target_bytes_per_block,
            max_bytes_per_quote,
            default_retention_blocks,
            subsidy_bps: std::cmp::min(subsidy_bps, 10_000),
            status: "active".to_string(),
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn batched_transactions() -> Self {
        Self::new(
            DA_LOW_FEE_LANE_TYPE,
            DA_BATCHED_TX_LANE_KEY,
            10,
            AVAILABILITY_DEFAULT_SHARD_SIZE_BYTES,
            1,
            1,
            2,
            1,
            768_000,
            2_097_152,
            AVAILABILITY_DEFAULT_RETENTION_BLOCKS,
            6_000,
        )
        .expect("default batched transaction DA lane")
    }

    pub fn monero_proofs() -> Self {
        Self::new(
            DA_LOW_FEE_LANE_TYPE,
            DA_MONERO_PROOF_LANE_KEY,
            20,
            AVAILABILITY_DEFAULT_SHARD_SIZE_BYTES,
            2,
            1,
            4,
            2,
            384_000,
            1_048_576,
            AVAILABILITY_DEFAULT_RETENTION_BLOCKS * 2,
            4_000,
        )
        .expect("default Monero proof DA lane")
    }

    pub fn archive_replay() -> Self {
        Self::new(
            DA_LOW_FEE_LANE_TYPE,
            DA_ARCHIVE_REPLAY_LANE_KEY,
            30,
            AVAILABILITY_DEFAULT_SHARD_SIZE_BYTES,
            1,
            2,
            1,
            1,
            256_000,
            4_194_304,
            AVAILABILITY_DEFAULT_RETENTION_BLOCKS * 8,
            8_000,
        )
        .expect("default archive replay DA lane")
    }

    pub fn default_low_fee_lanes() -> Vec<Self> {
        vec![
            Self::batched_transactions(),
            Self::monero_proofs(),
            Self::archive_replay(),
        ]
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_lane",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "priority": self.priority,
            "shard_size_bytes": self.shard_size_bytes,
            "base_fee_per_encoded_byte": self.base_fee_per_encoded_byte,
            "retention_fee_per_byte_quantum": self.retention_fee_per_byte_quantum,
            "sample_fee_units": self.sample_fee_units,
            "floor_fee_units": self.floor_fee_units,
            "target_bytes_per_block": self.target_bytes_per_block,
            "max_bytes_per_quote": self.max_bytes_per_quote,
            "default_retention_blocks": self.default_retention_blocks,
            "subsidy_bps": self.subsidy_bps,
            "status": self.status,
        })
    }

    pub fn lane_root(&self) -> String {
        domain_hash("DA-LANE", &[HashPart::Json(&self.public_record())], 32)
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.lane_type, "DA lane type")?;
        ensure_non_empty(&self.lane_key, "DA lane key")?;
        if self.lane_id != da_lane_id(&self.lane_type, &self.lane_key) {
            return Err("DA lane id mismatch".to_string());
        }
        if self.shard_size_bytes == 0 {
            return Err("DA lane shard size cannot be zero".to_string());
        }
        if self.target_bytes_per_block == 0 {
            return Err("DA lane target bytes cannot be zero".to_string());
        }
        if self.max_bytes_per_quote < self.shard_size_bytes {
            return Err("DA lane max quote bytes below shard size".to_string());
        }
        if self.default_retention_blocks == 0 {
            return Err("DA lane default retention cannot be zero".to_string());
        }
        validate_bps(self.subsidy_bps, "DA lane subsidy")?;
        ensure_status(
            &self.status,
            &["active", "paused", "retired"],
            "DA lane status",
        )?;
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaFeeQuote {
    pub quote_id: String,
    pub lane_id: String,
    pub lane_type: String,
    pub lane_key: String,
    pub quote_height: u64,
    pub expires_at_height: u64,
    pub payload_bytes: u64,
    pub encoded_bytes: u64,
    pub retention_blocks: u64,
    pub sample_count: u64,
    pub base_fee_per_encoded_byte: u64,
    pub retention_fee_per_byte_quantum: u64,
    pub sample_fee_units: u64,
    pub congestion_multiplier_bps: u64,
    pub subsidy_bps: u64,
    pub base_fee_units: u64,
    pub retention_fee_units: u64,
    pub sample_fee_total_units: u64,
    pub gross_fee_units: u64,
    pub subsidy_units: u64,
    pub quoted_fee_units: u64,
    pub fee_asset_id: String,
    pub payer_commitment: String,
    pub settlement_root: String,
    pub status: String,
}

impl DaFeeQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn from_lane(
        lane: &DaLane,
        quote_height: u64,
        ttl_blocks: u64,
        payload_bytes: u64,
        encoded_bytes: u64,
        sample_count: u64,
        retention_blocks: u64,
        congestion_multiplier_bps: u64,
        fee_asset_id: impl Into<String>,
        payer_commitment: impl Into<String>,
        settlement_root: impl Into<String>,
    ) -> AvailabilityResult<Self> {
        if ttl_blocks == 0 {
            return Err("DA fee quote ttl cannot be zero".to_string());
        }
        if payload_bytes == 0 {
            return Err("DA fee quote payload bytes cannot be zero".to_string());
        }
        if encoded_bytes < payload_bytes {
            return Err("DA fee quote encoded bytes below payload bytes".to_string());
        }
        let retention_blocks = if retention_blocks == 0 {
            lane.default_retention_blocks
        } else {
            retention_blocks
        };
        let sample_count = if sample_count == 0 {
            AVAILABILITY_DEFAULT_SAMPLE_COUNT
        } else {
            sample_count
        };
        let congestion_multiplier_bps = std::cmp::max(10_000, congestion_multiplier_bps);
        let base_fee_units = mul_div_u64(encoded_bytes, lane.base_fee_per_encoded_byte, 1);
        let base_fee_units = mul_div_u64(base_fee_units, congestion_multiplier_bps, 10_000);
        let retention_quanta = retention_blocks.div_ceil(AVAILABILITY_RETENTION_FEE_BLOCK_QUANTUM);
        let retention_fee_units = mul_div_u64(
            encoded_bytes,
            lane.retention_fee_per_byte_quantum
                .saturating_mul(retention_quanta),
            1,
        );
        let sample_fee_total_units = lane.sample_fee_units.saturating_mul(sample_count);
        let gross_fee_units = std::cmp::max(
            lane.floor_fee_units,
            base_fee_units
                .saturating_add(retention_fee_units)
                .saturating_add(sample_fee_total_units),
        );
        let subsidy_units = mul_div_u64(gross_fee_units, lane.subsidy_bps, 10_000);
        let quoted_fee_units = gross_fee_units.saturating_sub(subsidy_units);
        let mut quote = Self {
            quote_id: String::new(),
            lane_id: lane.lane_id.clone(),
            lane_type: lane.lane_type.clone(),
            lane_key: lane.lane_key.clone(),
            quote_height,
            expires_at_height: quote_height.saturating_add(ttl_blocks),
            payload_bytes,
            encoded_bytes,
            retention_blocks,
            sample_count,
            base_fee_per_encoded_byte: lane.base_fee_per_encoded_byte,
            retention_fee_per_byte_quantum: lane.retention_fee_per_byte_quantum,
            sample_fee_units: lane.sample_fee_units,
            congestion_multiplier_bps,
            subsidy_bps: lane.subsidy_bps,
            base_fee_units,
            retention_fee_units,
            sample_fee_total_units,
            gross_fee_units,
            subsidy_units,
            quoted_fee_units,
            fee_asset_id: fee_asset_id.into(),
            payer_commitment: payer_commitment.into(),
            settlement_root: settlement_root.into(),
            status: "quoted".to_string(),
        };
        quote.quote_id = da_fee_quote_id(&quote.identity_record());
        quote.validate()?;
        Ok(quote)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "da_fee_quote",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_type": self.lane_type,
            "lane_key": self.lane_key,
            "quote_height": self.quote_height,
            "expires_at_height": self.expires_at_height,
            "payload_bytes": self.payload_bytes,
            "encoded_bytes": self.encoded_bytes,
            "retention_blocks": self.retention_blocks,
            "sample_count": self.sample_count,
            "base_fee_per_encoded_byte": self.base_fee_per_encoded_byte,
            "retention_fee_per_byte_quantum": self.retention_fee_per_byte_quantum,
            "sample_fee_units": self.sample_fee_units,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "subsidy_bps": self.subsidy_bps,
            "base_fee_units": self.base_fee_units,
            "retention_fee_units": self.retention_fee_units,
            "sample_fee_total_units": self.sample_fee_total_units,
            "gross_fee_units": self.gross_fee_units,
            "subsidy_units": self.subsidy_units,
            "quoted_fee_units": self.quoted_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "payer_commitment": self.payer_commitment,
            "settlement_root": self.settlement_root,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.quote_id == da_fee_quote_id(&self.identity_record())
    }

    pub fn quote_root(&self) -> String {
        domain_hash(
            "DA-FEE-QUOTE",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("DA fee quote identity record object")
            .insert("quote_id".to_string(), Value::String(self.quote_id.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "quote_root",
            self.quote_root(),
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.lane_id, "DA fee quote lane id")?;
        ensure_non_empty(&self.lane_type, "DA fee quote lane type")?;
        ensure_non_empty(&self.lane_key, "DA fee quote lane key")?;
        ensure_non_empty(&self.fee_asset_id, "DA fee quote fee asset id")?;
        ensure_non_empty(&self.payer_commitment, "DA fee quote payer commitment")?;
        ensure_non_empty(&self.settlement_root, "DA fee quote settlement root")?;
        if self.lane_id != da_lane_id(&self.lane_type, &self.lane_key) {
            return Err("DA fee quote lane id mismatch".to_string());
        }
        if self.expires_at_height <= self.quote_height {
            return Err("DA fee quote expiry must be after quote height".to_string());
        }
        if self.payload_bytes == 0 || self.encoded_bytes == 0 {
            return Err("DA fee quote byte counts cannot be zero".to_string());
        }
        if self.encoded_bytes < self.payload_bytes {
            return Err("DA fee quote encoded bytes below payload bytes".to_string());
        }
        if self.retention_blocks == 0 {
            return Err("DA fee quote retention blocks cannot be zero".to_string());
        }
        if self.sample_count == 0 {
            return Err("DA fee quote sample count cannot be zero".to_string());
        }
        validate_bps(self.subsidy_bps, "DA fee quote subsidy")?;
        if self.gross_fee_units < self.quoted_fee_units {
            return Err("DA fee quote quoted fee exceeds gross fee".to_string());
        }
        if self.subsidy_units != self.gross_fee_units.saturating_sub(self.quoted_fee_units) {
            return Err("DA fee quote subsidy arithmetic mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &["quoted", "accepted", "expired", "settled"],
            "DA fee quote status",
        )?;
        if !self.verify_id() {
            return Err("DA fee quote id mismatch".to_string());
        }
        Ok(self.quote_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRetentionPolicy {
    pub retention_policy_id: String,
    pub min_retention_blocks: u64,
    pub hot_retention_blocks: u64,
    pub archive_retention_blocks: u64,
    pub grace_blocks: u64,
    pub replication_factor: u64,
    pub proof_cadence_blocks: u64,
    pub prune_after_blocks: u64,
    pub status: String,
}

impl Default for ArchiveRetentionPolicy {
    fn default() -> Self {
        Self::default_low_fee()
    }
}

impl ArchiveRetentionPolicy {
    pub fn default_low_fee() -> Self {
        let mut policy = Self {
            retention_policy_id: String::new(),
            min_retention_blocks: AVAILABILITY_DEFAULT_RETENTION_BLOCKS,
            hot_retention_blocks: AVAILABILITY_DEFAULT_RETENTION_BLOCKS,
            archive_retention_blocks: AVAILABILITY_DEFAULT_RETENTION_BLOCKS * 8,
            grace_blocks: AVAILABILITY_ARCHIVE_GRACE_BLOCKS,
            replication_factor: 3,
            proof_cadence_blocks: 720,
            prune_after_blocks: AVAILABILITY_DEFAULT_RETENTION_BLOCKS * 16,
            status: "active".to_string(),
        };
        policy.retention_policy_id = archive_retention_policy_id(&policy.identity_record());
        policy
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "archive_retention_policy",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "min_retention_blocks": self.min_retention_blocks,
            "hot_retention_blocks": self.hot_retention_blocks,
            "archive_retention_blocks": self.archive_retention_blocks,
            "grace_blocks": self.grace_blocks,
            "replication_factor": self.replication_factor,
            "proof_cadence_blocks": self.proof_cadence_blocks,
            "prune_after_blocks": self.prune_after_blocks,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.retention_policy_id == archive_retention_policy_id(&self.identity_record())
    }

    pub fn policy_root(&self) -> String {
        domain_hash(
            "DA-ARCHIVE-RETENTION-POLICY",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("archive policy object")
            .insert(
                "retention_policy_id".to_string(),
                Value::String(self.retention_policy_id.clone()),
            );
        record
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "policy_root",
            self.policy_root(),
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        if self.min_retention_blocks == 0 {
            return Err("archive retention minimum cannot be zero".to_string());
        }
        if self.hot_retention_blocks < self.min_retention_blocks {
            return Err("hot retention below minimum retention".to_string());
        }
        if self.archive_retention_blocks < self.hot_retention_blocks {
            return Err("archive retention below hot retention".to_string());
        }
        if self.replication_factor == 0 {
            return Err("archive retention replication factor cannot be zero".to_string());
        }
        if self.proof_cadence_blocks == 0 {
            return Err("archive retention proof cadence cannot be zero".to_string());
        }
        if self.prune_after_blocks < self.archive_retention_blocks {
            return Err("archive prune window below archive retention".to_string());
        }
        ensure_status(
            &self.status,
            &["active", "paused", "retired"],
            "archive retention policy status",
        )?;
        if !self.verify_id() {
            return Err("archive retention policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRetentionRecord {
    pub retention_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub retention_policy_id: String,
    pub retained_from_height: u64,
    pub retain_until_height: u64,
    pub prunable_after_height: u64,
    pub archive_node_ids: Vec<String>,
    pub archive_root: String,
    pub proof_root: String,
    pub recorded_at_height: u64,
    pub status: String,
}

impl ArchiveRetentionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        lane_id: impl Into<String>,
        policy: &ArchiveRetentionPolicy,
        retained_from_height: u64,
        archive_node_ids: Vec<String>,
        archive_root: impl Into<String>,
        proof_root: impl Into<String>,
        recorded_at_height: u64,
    ) -> AvailabilityResult<Self> {
        let retain_until_height =
            retained_from_height.saturating_add(policy.archive_retention_blocks);
        let prunable_after_height = retained_from_height.saturating_add(policy.prune_after_blocks);
        let mut record = Self {
            retention_id: String::new(),
            batch_id: batch_id.into(),
            lane_id: lane_id.into(),
            retention_policy_id: policy.retention_policy_id.clone(),
            retained_from_height,
            retain_until_height,
            prunable_after_height,
            archive_node_ids,
            archive_root: archive_root.into(),
            proof_root: proof_root.into(),
            recorded_at_height,
            status: "retained".to_string(),
        };
        record.retention_id = archive_retention_record_id(&record.identity_record());
        record.validate()?;
        Ok(record)
    }

    pub fn node_root(&self) -> String {
        archive_node_root(&self.archive_node_ids)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "archive_retention_record",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "retention_policy_id": self.retention_policy_id,
            "retained_from_height": self.retained_from_height,
            "retain_until_height": self.retain_until_height,
            "prunable_after_height": self.prunable_after_height,
            "archive_node_root": self.node_root(),
            "archive_root": self.archive_root,
            "proof_root": self.proof_root,
            "recorded_at_height": self.recorded_at_height,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.retention_id == archive_retention_record_id(&self.identity_record())
    }

    pub fn retention_root(&self) -> String {
        domain_hash(
            "DA-ARCHIVE-RETENTION-RECORD",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("archive retention record object");
        object.insert(
            "retention_id".to_string(),
            Value::String(self.retention_id.clone()),
        );
        object.insert(
            "archive_node_ids".to_string(),
            json!(self.archive_node_ids.clone()),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "retention_root",
            self.retention_root(),
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.batch_id, "archive retention batch id")?;
        ensure_non_empty(&self.lane_id, "archive retention lane id")?;
        ensure_non_empty(&self.retention_policy_id, "archive retention policy id")?;
        ensure_non_empty(&self.archive_root, "archive retention archive root")?;
        ensure_non_empty(&self.proof_root, "archive retention proof root")?;
        if self.retain_until_height <= self.retained_from_height {
            return Err("archive retention end must exceed start".to_string());
        }
        if self.prunable_after_height < self.retain_until_height {
            return Err("archive retention prune height before retention end".to_string());
        }
        if self.archive_node_ids.is_empty() {
            return Err("archive retention requires archive nodes".to_string());
        }
        ensure_unique_strings(&self.archive_node_ids, "archive retention node")?;
        ensure_status(
            &self.status,
            &["retained", "expiring", "prunable", "pruned", "gap"],
            "archive retention status",
        )?;
        if !self.verify_id() {
            return Err("archive retention id mismatch".to_string());
        }
        Ok(self.retention_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityEvidence {
    pub evidence_id: String,
    pub evidence_kind: String,
    pub batch_id: String,
    pub challenge_id: Option<String>,
    pub attestation_id: Option<String>,
    pub member_id: String,
    pub validator_id: String,
    pub reporter_label: String,
    pub reporter_public_key: String,
    pub reported_at_height: u64,
    pub expected_root: String,
    pub observed_root: String,
    pub missing_indices: Vec<u64>,
    pub slash_bps: u64,
    pub slash_amount: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl AvailabilityEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: impl Into<String>,
        batch_id: impl Into<String>,
        challenge_id: Option<String>,
        attestation_id: Option<String>,
        member_id: impl Into<String>,
        validator_id: impl Into<String>,
        reporter_label: impl Into<String>,
        reported_at_height: u64,
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        missing_indices: Vec<u64>,
        slash_bps: u64,
        slash_amount: u64,
    ) -> AvailabilityResult<Self> {
        let reporter_label = reporter_label.into();
        let reporter_public_key =
            public_key_for_label(CryptoRole::WatchtowerSignature, &reporter_label).public_key;
        let mut evidence = Self {
            evidence_id: String::new(),
            evidence_kind: evidence_kind.into(),
            batch_id: batch_id.into(),
            challenge_id,
            attestation_id,
            member_id: member_id.into(),
            validator_id: validator_id.into(),
            reporter_label,
            reporter_public_key,
            reported_at_height,
            expected_root: expected_root.into(),
            observed_root: observed_root.into(),
            missing_indices,
            slash_bps,
            slash_amount,
            status: "reported".to_string(),
            authorization: empty_authorization(CryptoRole::WatchtowerSignature, ""),
        };
        evidence.evidence_id = availability_evidence_id(&evidence.identity_record());
        evidence.authorization = sign_watchtower_authorization(
            &evidence.reporter_label,
            "availability_evidence",
            &evidence.unsigned_record(),
        );
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn missing_samples(
        challenge: &SamplingChallenge,
        member: &DaCommitteeMember,
        reporter_label: &str,
        reported_at_height: u64,
        missing_indices: Vec<u64>,
        stake_before: u64,
    ) -> AvailabilityResult<Self> {
        let slash_amount = mul_div_u64(stake_before, AVAILABILITY_MISSING_SAMPLE_SLASH_BPS, 10_000);
        Self::new(
            "missing_sample_response",
            challenge.batch_id.as_str(),
            Some(challenge.challenge_id.clone()),
            None,
            member.member_id.as_str(),
            member.validator_id.as_str(),
            reporter_label,
            reported_at_height,
            challenge.sample_root.as_str(),
            merkle_root("DA-MISSING-SAMPLE", &[]),
            missing_indices,
            AVAILABILITY_MISSING_SAMPLE_SLASH_BPS,
            slash_amount,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "availability_evidence",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "evidence_kind": self.evidence_kind,
            "batch_id": self.batch_id,
            "challenge_id": self.challenge_id,
            "attestation_id": self.attestation_id,
            "member_id": self.member_id,
            "validator_id": self.validator_id,
            "reporter_label": self.reporter_label,
            "reporter_public_key": self.reporter_public_key,
            "reported_at_height": self.reported_at_height,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "missing_indices": self.missing_indices,
            "missing_root": sampling_index_root(&self.missing_indices),
            "slash_bps": self.slash_bps,
            "slash_amount": self.slash_amount,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.evidence_id == availability_evidence_id(&self.identity_record())
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("availability evidence object")
            .insert(
                "evidence_id".to_string(),
                Value::String(self.evidence_id.clone()),
            );
        record
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "DA-AVAILABILITY-EVIDENCE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        with_authorization(
            with_root_field(
                self.unsigned_record(),
                "evidence_root",
                self.evidence_root(),
            ),
            &self.authorization,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_watchtower_authorization(
            &self.reporter_public_key,
            "availability_evidence",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_status(
            &self.evidence_kind,
            &[
                "missing_sample_response",
                "invalid_shard_commitment",
                "invalid_attestation",
                "retention_gap",
                "replay_mismatch",
            ],
            "availability evidence kind",
        )?;
        ensure_non_empty(&self.batch_id, "availability evidence batch id")?;
        ensure_non_empty(&self.member_id, "availability evidence member id")?;
        ensure_non_empty(&self.validator_id, "availability evidence validator id")?;
        ensure_non_empty(&self.reporter_label, "availability evidence reporter")?;
        ensure_non_empty(
            &self.reporter_public_key,
            "availability evidence reporter public key",
        )?;
        ensure_non_empty(&self.expected_root, "availability evidence expected root")?;
        ensure_non_empty(&self.observed_root, "availability evidence observed root")?;
        validate_bps(self.slash_bps, "availability evidence slash")?;
        ensure_unique_u64(&self.missing_indices, "availability evidence missing index")?;
        ensure_status(
            &self.status,
            &["reported", "slashable", "accepted", "rejected", "slashed"],
            "availability evidence status",
        )?;
        if !self.verify_id() {
            return Err("availability evidence id mismatch".to_string());
        }
        let expected_public_key =
            public_key_for_label(CryptoRole::WatchtowerSignature, &self.reporter_label).public_key;
        if self.reporter_public_key != expected_public_key {
            return Err("availability evidence reporter public key mismatch".to_string());
        }
        if !self.verify_authorization() {
            return Err("availability evidence authorization failed".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilitySlashRecord {
    pub slash_id: String,
    pub evidence_id: String,
    pub validator_id: String,
    pub member_id: String,
    pub stake_before: u64,
    pub slash_bps: u64,
    pub slash_amount: u64,
    pub stake_after: u64,
    pub slashed_at_height: u64,
    pub reason: String,
    pub settlement_root: String,
    pub status: String,
}

impl AvailabilitySlashRecord {
    pub fn from_evidence(
        evidence: &AvailabilityEvidence,
        stake_before: u64,
        slashed_at_height: u64,
        settlement_root: impl Into<String>,
    ) -> AvailabilityResult<Self> {
        let slash_amount = std::cmp::min(
            evidence.slash_amount,
            mul_div_u64(stake_before, evidence.slash_bps, 10_000),
        );
        let mut record = Self {
            slash_id: String::new(),
            evidence_id: evidence.evidence_id.clone(),
            validator_id: evidence.validator_id.clone(),
            member_id: evidence.member_id.clone(),
            stake_before,
            slash_bps: evidence.slash_bps,
            slash_amount,
            stake_after: stake_before.saturating_sub(slash_amount),
            slashed_at_height,
            reason: evidence.evidence_kind.clone(),
            settlement_root: settlement_root.into(),
            status: "slashed".to_string(),
        };
        record.slash_id = availability_slash_id(&record.identity_record());
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "availability_slash_record",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "validator_id": self.validator_id,
            "member_id": self.member_id,
            "stake_before": self.stake_before,
            "slash_bps": self.slash_bps,
            "slash_amount": self.slash_amount,
            "stake_after": self.stake_after,
            "slashed_at_height": self.slashed_at_height,
            "reason": self.reason,
            "settlement_root": self.settlement_root,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.slash_id == availability_slash_id(&self.identity_record())
    }

    pub fn slash_root(&self) -> String {
        domain_hash(
            "DA-AVAILABILITY-SLASH",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("availability slash record object")
            .insert("slash_id".to_string(), Value::String(self.slash_id.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "slash_root",
            self.slash_root(),
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.evidence_id, "availability slash evidence id")?;
        ensure_non_empty(&self.validator_id, "availability slash validator id")?;
        ensure_non_empty(&self.member_id, "availability slash member id")?;
        ensure_non_empty(&self.reason, "availability slash reason")?;
        ensure_non_empty(&self.settlement_root, "availability slash settlement root")?;
        validate_bps(self.slash_bps, "availability slash bps")?;
        if self.slash_amount > self.stake_before {
            return Err("availability slash amount exceeds stake".to_string());
        }
        if self.stake_after != self.stake_before.saturating_sub(self.slash_amount) {
            return Err("availability slash stake arithmetic mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &["pending", "slashed", "reversed"],
            "availability slash status",
        )?;
        if !self.verify_id() {
            return Err("availability slash id mismatch".to_string());
        }
        Ok(self.slash_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayManifestEntry {
    pub entry_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub artifact_kind: String,
    pub artifact_root: String,
    pub required: bool,
    pub replay_status: String,
    pub notes: String,
}

impl ReplayManifestEntry {
    pub fn new(
        sequence: u64,
        batch_id: impl Into<String>,
        artifact_kind: impl Into<String>,
        artifact_root: impl Into<String>,
        required: bool,
        replay_status: impl Into<String>,
        notes: impl Into<String>,
    ) -> AvailabilityResult<Self> {
        let mut entry = Self {
            entry_id: String::new(),
            sequence,
            batch_id: batch_id.into(),
            artifact_kind: artifact_kind.into(),
            artifact_root: artifact_root.into(),
            required,
            replay_status: replay_status.into(),
            notes: notes.into(),
        };
        entry.entry_id = replay_manifest_entry_id(&entry.identity_record());
        entry.validate()?;
        Ok(entry)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "availability_replay_manifest_entry",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "batch_id": self.batch_id,
            "artifact_kind": self.artifact_kind,
            "artifact_root": self.artifact_root,
            "required": self.required,
            "replay_status": self.replay_status,
            "notes": self.notes,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.entry_id == replay_manifest_entry_id(&self.identity_record())
    }

    pub fn entry_root(&self) -> String {
        self.entry_root_raw()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("replay manifest entry record object");
        object.insert("entry_id".to_string(), Value::String(self.entry_id.clone()));
        object.insert(
            "entry_root".to_string(),
            Value::String(self.entry_root_raw()),
        );
        record
    }

    fn entry_root_raw(&self) -> String {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("replay manifest entry raw record object")
            .insert("entry_id".to_string(), Value::String(self.entry_id.clone()));
        domain_hash("DA-REPLAY-MANIFEST-ENTRY", &[HashPart::Json(&record)], 32)
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.batch_id, "replay manifest entry batch id")?;
        ensure_non_empty(&self.artifact_kind, "replay manifest entry artifact kind")?;
        ensure_non_empty(&self.artifact_root, "replay manifest entry artifact root")?;
        ensure_status(
            &self.replay_status,
            &["required", "available", "verified", "missing", "ignored"],
            "replay manifest entry status",
        )?;
        if !self.verify_id() {
            return Err("replay manifest entry id mismatch".to_string());
        }
        Ok(self.entry_root_raw())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub manifest_id: String,
    pub replay_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub da_state_root: String,
    pub batch_root: String,
    pub challenge_root: String,
    pub attestation_root: String,
    pub evidence_root: String,
    pub quote_root: String,
    pub retention_root: String,
    pub entries: Vec<ReplayManifestEntry>,
    pub generated_at_height: u64,
    pub status: String,
}

impl ReplayManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replay_id: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        da_state_root: impl Into<String>,
        batch_root: impl Into<String>,
        challenge_root: impl Into<String>,
        attestation_root: impl Into<String>,
        evidence_root: impl Into<String>,
        quote_root: impl Into<String>,
        retention_root: impl Into<String>,
        entries: Vec<ReplayManifestEntry>,
        generated_at_height: u64,
    ) -> AvailabilityResult<Self> {
        let mut manifest = Self {
            manifest_id: String::new(),
            replay_id: replay_id.into(),
            block_height,
            block_hash: block_hash.into(),
            da_state_root: da_state_root.into(),
            batch_root: batch_root.into(),
            challenge_root: challenge_root.into(),
            attestation_root: attestation_root.into(),
            evidence_root: evidence_root.into(),
            quote_root: quote_root.into(),
            retention_root: retention_root.into(),
            entries,
            generated_at_height,
            status: "ready".to_string(),
        };
        manifest.manifest_id = replay_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_state(
        replay_id: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        state: &AvailabilityState,
        entries: Vec<ReplayManifestEntry>,
        generated_at_height: u64,
    ) -> AvailabilityResult<Self> {
        Self::new(
            replay_id,
            block_height,
            block_hash,
            state.state_root(),
            state.batch_root(),
            state.challenge_root(),
            state.attestation_root(),
            state.evidence_root(),
            state.quote_root(),
            state.retention_root(),
            entries,
            generated_at_height,
        )
    }

    pub fn entry_records(&self) -> Vec<Value> {
        let mut records = self
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.sequence,
                    entry.entry_id.clone(),
                    entry.public_record(),
                )
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        records.into_iter().map(|(_, _, record)| record).collect()
    }

    pub fn entry_root(&self) -> String {
        merkle_root("DA-REPLAY-MANIFEST-ENTRY", &self.entry_records())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "availability_replay_manifest",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "replay_id": self.replay_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "da_state_root": self.da_state_root,
            "batch_root": self.batch_root,
            "challenge_root": self.challenge_root,
            "attestation_root": self.attestation_root,
            "evidence_root": self.evidence_root,
            "quote_root": self.quote_root,
            "retention_root": self.retention_root,
            "entry_root": self.entry_root(),
            "entry_count": self.entries.len() as u64,
            "generated_at_height": self.generated_at_height,
            "status": self.status,
        })
    }

    pub fn verify_id(&self) -> bool {
        self.manifest_id == replay_manifest_id(&self.identity_record())
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("replay manifest identity record object")
            .insert(
                "manifest_id".to_string(),
                Value::String(self.manifest_id.clone()),
            );
        record
    }

    pub fn manifest_root(&self) -> String {
        domain_hash(
            "DA-REPLAY-MANIFEST",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = with_root_field(
            self.public_record_without_root(),
            "manifest_root",
            self.manifest_root(),
        );
        record
            .as_object_mut()
            .expect("replay manifest public record object")
            .insert("entries".to_string(), Value::Array(self.entry_records()));
        record
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        ensure_non_empty(&self.replay_id, "replay manifest replay id")?;
        ensure_non_empty(&self.block_hash, "replay manifest block hash")?;
        ensure_non_empty(&self.da_state_root, "replay manifest DA state root")?;
        ensure_non_empty(&self.batch_root, "replay manifest batch root")?;
        ensure_non_empty(&self.challenge_root, "replay manifest challenge root")?;
        ensure_non_empty(&self.attestation_root, "replay manifest attestation root")?;
        ensure_non_empty(&self.evidence_root, "replay manifest evidence root")?;
        ensure_non_empty(&self.quote_root, "replay manifest quote root")?;
        ensure_non_empty(&self.retention_root, "replay manifest retention root")?;
        let mut sequences = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            sequences.push(entry.sequence);
        }
        ensure_unique_u64(&sequences, "replay manifest entry sequence")?;
        ensure_status(
            &self.status,
            &["ready", "verified", "failed", "archived"],
            "replay manifest status",
        )?;
        if !self.verify_id() {
            return Err("replay manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityState {
    pub current_height: u64,
    pub committees: BTreeMap<String, DaCommittee>,
    pub lanes: BTreeMap<String, DaLane>,
    pub batches: BTreeMap<String, ErasureBatchCommitment>,
    pub challenges: BTreeMap<String, SamplingChallenge>,
    pub responses: BTreeMap<String, SamplingResponse>,
    pub attestations: BTreeMap<String, AvailabilityAttestation>,
    pub fee_quotes: BTreeMap<String, DaFeeQuote>,
    pub retention_policies: BTreeMap<String, ArchiveRetentionPolicy>,
    pub retention_records: BTreeMap<String, ArchiveRetentionRecord>,
    pub evidence: BTreeMap<String, AvailabilityEvidence>,
    pub slash_records: BTreeMap<String, AvailabilitySlashRecord>,
    pub replay_manifests: BTreeMap<String, ReplayManifest>,
}

impl Default for AvailabilityState {
    fn default() -> Self {
        Self::new()
    }
}

impl AvailabilityState {
    pub fn new() -> Self {
        let mut state = Self::empty(0);
        for lane in DaLane::default_low_fee_lanes() {
            state.lanes.insert(lane.lane_id.clone(), lane);
        }
        let policy = ArchiveRetentionPolicy::default();
        state
            .retention_policies
            .insert(policy.retention_policy_id.clone(), policy);
        state
    }

    pub fn empty(current_height: u64) -> Self {
        Self {
            current_height,
            committees: BTreeMap::new(),
            lanes: BTreeMap::new(),
            batches: BTreeMap::new(),
            challenges: BTreeMap::new(),
            responses: BTreeMap::new(),
            attestations: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            retention_policies: BTreeMap::new(),
            retention_records: BTreeMap::new(),
            evidence: BTreeMap::new(),
            slash_records: BTreeMap::new(),
            replay_manifests: BTreeMap::new(),
        }
    }

    pub fn set_current_height(&mut self, current_height: u64) -> AvailabilityResult<String> {
        self.current_height = current_height;
        Ok(self.state_root())
    }

    pub fn apply_committee(&mut self, committee: DaCommittee) -> AvailabilityResult<String> {
        let root = committee.validate()?;
        insert_unique_record(
            &mut self.committees,
            committee.committee_id.clone(),
            committee,
            "DA committee",
        )?;
        Ok(root)
    }

    pub fn apply_lane(&mut self, lane: DaLane) -> AvailabilityResult<String> {
        let root = lane.validate()?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(root)
    }

    pub fn apply_erasure_batch(
        &mut self,
        batch: ErasureBatchCommitment,
    ) -> AvailabilityResult<String> {
        let root = batch.validate()?;
        if !self.lanes.contains_key(&batch.lane_id) {
            return Err("erasure batch references unknown DA lane".to_string());
        }
        if !self.committees.contains_key(&batch.committee_id) {
            return Err("erasure batch references unknown DA committee".to_string());
        }
        insert_unique_record(
            &mut self.batches,
            batch.batch_id.clone(),
            batch,
            "erasure batch",
        )?;
        Ok(root)
    }

    pub fn apply_sampling_challenge(
        &mut self,
        challenge: SamplingChallenge,
    ) -> AvailabilityResult<String> {
        let root = challenge.validate()?;
        let batch = self
            .batches
            .get(&challenge.batch_id)
            .ok_or_else(|| "sampling challenge references unknown batch".to_string())?;
        if batch.committee_id != challenge.committee_id {
            return Err("sampling challenge committee mismatch".to_string());
        }
        let shard_count = batch.shards.len() as u64;
        if challenge
            .sample_indices
            .iter()
            .any(|index| *index >= shard_count)
        {
            return Err("sampling challenge index exceeds shard count".to_string());
        }
        insert_unique_record(
            &mut self.challenges,
            challenge.challenge_id.clone(),
            challenge,
            "sampling challenge",
        )?;
        Ok(root)
    }

    pub fn apply_sampling_response(
        &mut self,
        response: SamplingResponse,
    ) -> AvailabilityResult<String> {
        let root = response.validate()?;
        let challenge = self
            .challenges
            .get(&response.challenge_id)
            .ok_or_else(|| "sampling response references unknown challenge".to_string())?;
        if response.batch_id != challenge.batch_id {
            return Err("sampling response batch mismatch".to_string());
        }
        if response.response_height > challenge.expires_at_height {
            return Err("sampling response is late".to_string());
        }
        let requested = challenge
            .sample_indices
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for shard in &response.sampled_shards {
            if !requested.contains(&shard.shard_index) {
                return Err("sampling response included unrequested shard".to_string());
            }
        }
        for index in &response.unavailable_indices {
            if !requested.contains(index) {
                return Err("sampling response missing index was not requested".to_string());
            }
        }
        insert_unique_record(
            &mut self.responses,
            response.response_id.clone(),
            response,
            "sampling response",
        )?;
        Ok(root)
    }

    pub fn apply_attestation(
        &mut self,
        attestation: AvailabilityAttestation,
    ) -> AvailabilityResult<String> {
        let root = attestation.validate()?;
        let batch = self
            .batches
            .get(&attestation.batch_id)
            .ok_or_else(|| "availability attestation references unknown batch".to_string())?;
        if batch.committee_id != attestation.committee_id {
            return Err("availability attestation committee mismatch".to_string());
        }
        if batch.shard_commitment_root() != attestation.shard_commitment_root {
            return Err("availability attestation shard commitment root mismatch".to_string());
        }
        let committee = self
            .committees
            .get(&attestation.committee_id)
            .ok_or_else(|| "availability attestation references unknown committee".to_string())?;
        let member = committee
            .members
            .iter()
            .find(|member| member.member_id == attestation.member_id)
            .ok_or_else(|| "availability attestation member is not in committee".to_string())?;
        if member.validator_id != attestation.validator_id {
            return Err("availability attestation validator mismatch".to_string());
        }
        insert_unique_record(
            &mut self.attestations,
            attestation.attestation_id.clone(),
            attestation,
            "availability attestation",
        )?;
        Ok(root)
    }

    pub fn apply_fee_quote(&mut self, quote: DaFeeQuote) -> AvailabilityResult<String> {
        let root = quote.validate()?;
        if !self.lanes.contains_key(&quote.lane_id) {
            return Err("DA fee quote references unknown lane".to_string());
        }
        insert_unique_record(
            &mut self.fee_quotes,
            quote.quote_id.clone(),
            quote,
            "DA fee quote",
        )?;
        Ok(root)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn quote_lane(
        &mut self,
        lane_id: &str,
        payload_bytes: u64,
        encoded_bytes: u64,
        sample_count: u64,
        retention_blocks: u64,
        congestion_multiplier_bps: u64,
        fee_asset_id: &str,
        payer_commitment: &str,
        settlement_root: &str,
    ) -> AvailabilityResult<DaFeeQuote> {
        let lane = self
            .lanes
            .get(lane_id)
            .cloned()
            .ok_or_else(|| "DA fee quote lane is missing".to_string())?;
        let quote = DaFeeQuote::from_lane(
            &lane,
            self.current_height,
            DA_QUOTE_DEFAULT_TTL_BLOCKS,
            payload_bytes,
            encoded_bytes,
            sample_count,
            retention_blocks,
            congestion_multiplier_bps,
            fee_asset_id,
            payer_commitment,
            settlement_root,
        )?;
        self.apply_fee_quote(quote.clone())?;
        Ok(quote)
    }

    pub fn apply_retention_policy(
        &mut self,
        policy: ArchiveRetentionPolicy,
    ) -> AvailabilityResult<String> {
        let root = policy.validate()?;
        self.retention_policies
            .insert(policy.retention_policy_id.clone(), policy);
        Ok(root)
    }

    pub fn apply_archive_retention(
        &mut self,
        retention: ArchiveRetentionRecord,
    ) -> AvailabilityResult<String> {
        let root = retention.validate()?;
        if !self.batches.contains_key(&retention.batch_id) {
            return Err("archive retention references unknown batch".to_string());
        }
        if !self.lanes.contains_key(&retention.lane_id) {
            return Err("archive retention references unknown lane".to_string());
        }
        if !self
            .retention_policies
            .contains_key(&retention.retention_policy_id)
        {
            return Err("archive retention references unknown policy".to_string());
        }
        insert_unique_record(
            &mut self.retention_records,
            retention.retention_id.clone(),
            retention,
            "archive retention",
        )?;
        Ok(root)
    }

    pub fn apply_evidence(&mut self, evidence: AvailabilityEvidence) -> AvailabilityResult<String> {
        let root = evidence.validate()?;
        if !self.batches.contains_key(&evidence.batch_id) {
            return Err("availability evidence references unknown batch".to_string());
        }
        if let Some(challenge_id) = &evidence.challenge_id {
            if !self.challenges.contains_key(challenge_id) {
                return Err("availability evidence references unknown challenge".to_string());
            }
        }
        if let Some(attestation_id) = &evidence.attestation_id {
            if !self.attestations.contains_key(attestation_id) {
                return Err("availability evidence references unknown attestation".to_string());
            }
        }
        insert_unique_record(
            &mut self.evidence,
            evidence.evidence_id.clone(),
            evidence,
            "availability evidence",
        )?;
        Ok(root)
    }

    pub fn apply_slash_record(
        &mut self,
        slash: AvailabilitySlashRecord,
    ) -> AvailabilityResult<String> {
        let root = slash.validate()?;
        if !self.evidence.contains_key(&slash.evidence_id) {
            return Err("availability slash references unknown evidence".to_string());
        }
        insert_unique_record(
            &mut self.slash_records,
            slash.slash_id.clone(),
            slash,
            "availability slash",
        )?;
        Ok(root)
    }

    pub fn apply_replay_manifest(
        &mut self,
        manifest: ReplayManifest,
    ) -> AvailabilityResult<String> {
        let root = manifest.validate()?;
        insert_unique_record(
            &mut self.replay_manifests,
            manifest.manifest_id.clone(),
            manifest,
            "replay manifest",
        )?;
        Ok(root)
    }

    pub fn committee_root(&self) -> String {
        da_committee_root(&self.committees.values().cloned().collect::<Vec<_>>())
    }

    pub fn lane_root(&self) -> String {
        da_lane_root(&self.lanes.values().cloned().collect::<Vec<_>>())
    }

    pub fn batch_root(&self) -> String {
        erasure_batch_root(&self.batches.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_root(&self) -> String {
        sampling_challenge_root(&self.challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn response_root(&self) -> String {
        sampling_response_root(&self.responses.values().cloned().collect::<Vec<_>>())
    }

    pub fn attestation_root(&self) -> String {
        availability_attestation_root(&self.attestations.values().cloned().collect::<Vec<_>>())
    }

    pub fn quote_root(&self) -> String {
        da_fee_quote_root(&self.fee_quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn retention_policy_root(&self) -> String {
        archive_retention_policy_root(
            &self
                .retention_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn retention_root(&self) -> String {
        archive_retention_root(&self.retention_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn evidence_root(&self) -> String {
        availability_evidence_root(&self.evidence.values().cloned().collect::<Vec<_>>())
    }

    pub fn slash_root(&self) -> String {
        availability_slash_root(&self.slash_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn replay_manifest_root(&self) -> String {
        replay_manifest_root(&self.replay_manifests.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "availability_state",
            "chain_id": CHAIN_ID,
            "availability_protocol_version": AVAILABILITY_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "committee_root": self.committee_root(),
            "lane_root": self.lane_root(),
            "batch_root": self.batch_root(),
            "challenge_root": self.challenge_root(),
            "response_root": self.response_root(),
            "attestation_root": self.attestation_root(),
            "quote_root": self.quote_root(),
            "retention_policy_root": self.retention_policy_root(),
            "retention_root": self.retention_root(),
            "evidence_root": self.evidence_root(),
            "slash_root": self.slash_root(),
            "replay_manifest_root": self.replay_manifest_root(),
            "committee_count": self.committees.len() as u64,
            "lane_count": self.lanes.len() as u64,
            "batch_count": self.batches.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "response_count": self.responses.len() as u64,
            "attestation_count": self.attestations.len() as u64,
            "quote_count": self.fee_quotes.len() as u64,
            "retention_policy_count": self.retention_policies.len() as u64,
            "retention_count": self.retention_records.len() as u64,
            "evidence_count": self.evidence.len() as u64,
            "slash_count": self.slash_records.len() as u64,
            "replay_manifest_count": self.replay_manifests.len() as u64,
        })
    }

    pub fn state_root(&self) -> String {
        availability_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "availability_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> AvailabilityResult<String> {
        for committee in self.committees.values() {
            committee.validate()?;
        }
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for batch in self.batches.values() {
            batch.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        for response in self.responses.values() {
            response.validate()?;
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
        }
        for quote in self.fee_quotes.values() {
            quote.validate()?;
        }
        for policy in self.retention_policies.values() {
            policy.validate()?;
        }
        for retention in self.retention_records.values() {
            retention.validate()?;
        }
        for evidence in self.evidence.values() {
            evidence.validate()?;
        }
        for slash in self.slash_records.values() {
            slash.validate()?;
        }
        for manifest in self.replay_manifests.values() {
            manifest.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn da_committee_member_id(
    validator_id: &str,
    consensus_public_key: &str,
    da_public_key: &str,
) -> String {
    domain_hash(
        "DA-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Str(consensus_public_key),
            HashPart::Str(da_public_key),
        ],
        32,
    )
}

pub fn da_committee_id(record: &Value) -> String {
    domain_hash("DA-COMMITTEE-ID", &[HashPart::Json(record)], 32)
}

pub fn erasure_shard_commitment_id(record: &Value) -> String {
    domain_hash("DA-ERASURE-SHARD-ID", &[HashPart::Json(record)], 32)
}

pub fn erasure_shard_commitment_hash(record: &Value) -> String {
    domain_hash("DA-ERASURE-SHARD-COMMITMENT", &[HashPart::Json(record)], 32)
}

pub fn erasure_batch_id(
    block_height: u64,
    payload_hash: &str,
    lane_id: &str,
    committee_id: &str,
    shard_commitment_root: &str,
) -> String {
    domain_hash(
        "DA-ERASURE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(payload_hash),
            HashPart::Str(lane_id),
            HashPart::Str(committee_id),
            HashPart::Str(shard_commitment_root),
        ],
        32,
    )
}

pub fn sampling_challenge_seed(
    batch_id: &str,
    payload_hash: &str,
    challenger_label: &str,
    challenge_height: u64,
) -> String {
    domain_hash(
        "DA-SAMPLING-CHALLENGE-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(payload_hash),
            HashPart::Str(challenger_label),
            HashPart::Int(challenge_height as i128),
        ],
        32,
    )
}

pub fn sampling_challenge_id(
    batch_id: &str,
    committee_id: &str,
    challenger_label: &str,
    challenge_height: u64,
    sample_root: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(committee_id),
            HashPart::Str(challenger_label),
            HashPart::Int(challenge_height as i128),
            HashPart::Str(sample_root),
        ],
        32,
    )
}

pub fn sampling_response_id(
    challenge_id: &str,
    member_id: &str,
    response_height: u64,
    sampled_shard_root: &str,
) -> String {
    domain_hash(
        "DA-SAMPLING-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(member_id),
            HashPart::Int(response_height as i128),
            HashPart::Str(sampled_shard_root),
        ],
        32,
    )
}

pub fn availability_attestation_id(
    batch_id: &str,
    committee_id: &str,
    member_id: &str,
    attested_at_height: u64,
    shard_commitment_root: &str,
    availability_claim: &str,
) -> String {
    domain_hash(
        "DA-AVAILABILITY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(committee_id),
            HashPart::Str(member_id),
            HashPart::Int(attested_at_height as i128),
            HashPart::Str(shard_commitment_root),
            HashPart::Str(availability_claim),
        ],
        32,
    )
}

pub fn da_lane_id(lane_type: &str, lane_key: &str) -> String {
    domain_hash(
        "DA-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_type),
            HashPart::Str(lane_key),
        ],
        32,
    )
}

pub fn da_fee_quote_id(record: &Value) -> String {
    domain_hash("DA-FEE-QUOTE-ID", &[HashPart::Json(record)], 32)
}

pub fn archive_retention_policy_id(record: &Value) -> String {
    domain_hash(
        "DA-ARCHIVE-RETENTION-POLICY-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn archive_retention_record_id(record: &Value) -> String {
    domain_hash(
        "DA-ARCHIVE-RETENTION-RECORD-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn availability_evidence_id(record: &Value) -> String {
    domain_hash("DA-AVAILABILITY-EVIDENCE-ID", &[HashPart::Json(record)], 32)
}

pub fn availability_slash_id(record: &Value) -> String {
    domain_hash("DA-AVAILABILITY-SLASH-ID", &[HashPart::Json(record)], 32)
}

pub fn replay_manifest_entry_id(record: &Value) -> String {
    domain_hash("DA-REPLAY-MANIFEST-ENTRY-ID", &[HashPart::Json(record)], 32)
}

pub fn replay_manifest_id(record: &Value) -> String {
    domain_hash("DA-REPLAY-MANIFEST-ID", &[HashPart::Json(record)], 32)
}

pub fn sampling_index_root(indices: &[u64]) -> String {
    let records = indices
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|index| json!(index))
        .collect::<Vec<_>>();
    merkle_root("DA-SAMPLING-INDEX", &records)
}

pub fn archive_node_root(node_ids: &[String]) -> String {
    let records = node_ids
        .iter()
        .filter(|node_id| !node_id.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root("DA-ARCHIVE-NODE", &records)
}

pub fn da_committee_root(committees: &[DaCommittee]) -> String {
    let mut records = committees
        .iter()
        .map(|committee| (committee.committee_id.clone(), committee.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-COMMITTEE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn da_lane_root(lanes: &[DaLane]) -> String {
    let mut records = lanes
        .iter()
        .map(|lane| (lane.lane_id.clone(), lane.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-LANE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn erasure_shard_commitment_root(shards: &[ErasureShardCommitment]) -> String {
    let mut records = shards
        .iter()
        .map(|shard| (shard.shard_index, shard.commitment_record()))
        .collect::<Vec<_>>();
    records.sort_by_key(|(index, _)| *index);
    merkle_root(
        "DA-ERASURE-SHARD-COMMITMENT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn erasure_shard_root(shards: &[ErasureShardCommitment]) -> String {
    let mut records = shards
        .iter()
        .map(|shard| (shard.shard_index, shard.public_record()))
        .collect::<Vec<_>>();
    records.sort_by_key(|(index, _)| *index);
    merkle_root(
        "DA-ERASURE-SHARD",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn erasure_sampled_shard_root(shards: &[ErasureShardCommitment]) -> String {
    let mut records = shards
        .iter()
        .map(|shard| (shard.shard_index, shard.public_record()))
        .collect::<Vec<_>>();
    records.sort_by_key(|(index, _)| *index);
    merkle_root(
        "DA-SAMPLED-ERASURE-SHARD",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn erasure_batch_root(batches: &[ErasureBatchCommitment]) -> String {
    let mut records = batches
        .iter()
        .map(|batch| (batch.batch_id.clone(), batch.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-ERASURE-BATCH",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn sampling_challenge_root(challenges: &[SamplingChallenge]) -> String {
    let mut records = challenges
        .iter()
        .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-SAMPLING-CHALLENGE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn sampling_response_root(responses: &[SamplingResponse]) -> String {
    let mut records = responses
        .iter()
        .map(|response| (response.response_id.clone(), response.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-SAMPLING-RESPONSE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn availability_attestation_root(attestations: &[AvailabilityAttestation]) -> String {
    let mut records = attestations
        .iter()
        .map(|attestation| {
            (
                attestation.attestation_id.clone(),
                attestation.public_record(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-AVAILABILITY-ATTESTATION",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn da_fee_quote_root(quotes: &[DaFeeQuote]) -> String {
    let mut records = quotes
        .iter()
        .map(|quote| (quote.quote_id.clone(), quote.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-FEE-QUOTE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn archive_retention_policy_root(policies: &[ArchiveRetentionPolicy]) -> String {
    let mut records = policies
        .iter()
        .map(|policy| (policy.retention_policy_id.clone(), policy.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-ARCHIVE-RETENTION-POLICY",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn archive_retention_root(retention_records: &[ArchiveRetentionRecord]) -> String {
    let mut records = retention_records
        .iter()
        .map(|retention| (retention.retention_id.clone(), retention.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-ARCHIVE-RETENTION",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn availability_evidence_root(evidence: &[AvailabilityEvidence]) -> String {
    let mut records = evidence
        .iter()
        .map(|evidence| (evidence.evidence_id.clone(), evidence.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-AVAILABILITY-EVIDENCE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn availability_slash_root(slashes: &[AvailabilitySlashRecord]) -> String {
    let mut records = slashes
        .iter()
        .map(|slash| (slash.slash_id.clone(), slash.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-AVAILABILITY-SLASH",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn replay_manifest_root(manifests: &[ReplayManifest]) -> String {
    let mut records = manifests
        .iter()
        .map(|manifest| (manifest.manifest_id.clone(), manifest.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DA-REPLAY-MANIFEST",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn availability_state_root_from_record(record: &Value) -> String {
    domain_hash("DA-AVAILABILITY-STATE", &[HashPart::Json(record)], 32)
}

pub fn derive_sample_indices(
    seed: &str,
    shard_count: u64,
    sample_count: u64,
) -> AvailabilityResult<Vec<u64>> {
    if shard_count == 0 {
        return Err("cannot sample from zero shards".to_string());
    }
    if sample_count == 0 {
        return Err("sample count cannot be zero".to_string());
    }
    let target = std::cmp::min(sample_count, shard_count);
    let mut selected = BTreeSet::new();
    let mut nonce = 0_u64;
    while selected.len() < target as usize {
        let candidate_hash = domain_hash(
            "DA-SAMPLING-CANDIDATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        selected.insert(hash_to_u64(&candidate_hash) % shard_count);
        nonce = nonce.saturating_add(1);
    }
    Ok(selected.into_iter().collect())
}

fn empty_authorization(role: CryptoRole, signer_label: &str) -> Authorization {
    Authorization {
        signer_label: signer_label.to_string(),
        auth_scheme: role.scheme().to_string(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn with_authorization(mut record: Value, authorization: &Authorization) -> Value {
    let object = record
        .as_object_mut()
        .expect("authorization target record object");
    object.insert(
        "signer_label".to_string(),
        Value::String(authorization.signer_label.clone()),
    );
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
    record
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    record
        .as_object_mut()
        .expect("root target record object")
        .insert(field.to_string(), Value::String(root));
    record
}

fn ensure_non_empty(value: &str, label: &str) -> AvailabilityResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> AvailabilityResult<()> {
    if allowed.iter().any(|allowed| *allowed == value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn validate_bps(value: u64, label: &str) -> AvailabilityResult<()> {
    if value > 10_000 {
        return Err(format!("{label} basis points exceed 100%"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> AvailabilityResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn ensure_unique_u64(values: &[u64], label: &str) -> AvailabilityResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> AvailabilityResult<()> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id, record);
    Ok(())
}

fn bps_ceil(value: u64, bps: u64) -> u64 {
    ((value as u128) * (bps as u128))
        .div_ceil(10_000u128)
        .min(u64::MAX as u128) as u64
}

fn mul_div_u64(value: u64, multiplier: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    ((value as u128) * (multiplier as u128) / (divisor as u128)).min(u64::MAX as u128) as u64
}

fn hash_to_u64(hash: &str) -> u64 {
    let prefix = hash.get(0..16).unwrap_or(hash);
    u64::from_str_radix(prefix, 16).unwrap_or(0)
}
