use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqPrivacyPreservingDataAvailabilityQuorumResult<T> = Result<T, String>;

pub const PQ_PRIVACY_PRESERVING_DATA_AVAILABILITY_QUORUM_PROTOCOL_VERSION: &str =
    "nebula-l2-pq-privacy-preserving-data-availability-quorum-v1";

const PROTOCOL_ID: &str = "pq-privacy-preserving-da-quorum";
const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
const PQ_BACKUP_SIGNATURE_SUITE: &str = "SLH-DSA-SHAKE-256f";
const PQ_KEM_SUITE: &str = "ML-KEM-1024";
const ERASURE_SUITE: &str = "rs-32-32-shake256-kzg-compatible-commitment";
const PRIVACY_PROOF_SUITE: &str = "zk-viewtag-nullifier-redaction-v1";
const MONERO_ANCHOR_SUITE: &str = "monero-anchor-aware-da-quorum-v1";
const RECEIPT_SUITE: &str = "low-fee-private-da-receipt-v1";
const DEFAULT_HEIGHT: u64 = 4_096;
const DEFAULT_QUORUM_BPS: u64 = 6_667;
const DEFAULT_PRIVACY_QUORUM_BPS: u64 = 7_500;
const DEFAULT_MIN_SECURITY_BITS: u64 = 256;
const DEFAULT_ORIGINAL_SHARDS: u64 = 32;
const DEFAULT_PARITY_SHARDS: u64 = 32;
const DEFAULT_SHARD_SIZE_BYTES: u64 = 2_048;
const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 64;
const DEFAULT_MONERO_CONFIRMATIONS: u64 = 12;
const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 192;
const DEFAULT_RETENTION_BLOCKS: u64 = 21_600;
const DEFAULT_MAX_BATCH_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_LOW_FEE_MICROUNITS: u64 = 3;
const DEFAULT_ATTESTATION_REWARD_MICROUNITS: u64 = 12;
const DEFAULT_CHALLENGE_BOND_MICROUNITS: u64 = 250_000;
const DEFAULT_SLASH_BPS: u64 = 2_500;
const MAX_BPS: u64 = 10_000;
const MAX_COMMITTEE_MEMBERS: usize = 4_096;
const MAX_BATCHES: usize = 262_144;
const MAX_SHARDS: usize = 16_777_216;
const MAX_ATTESTATIONS: usize = 4_194_304;
const MAX_CHALLENGES: usize = 1_048_576;
const MAX_RECEIPTS: usize = 1_048_576;
const MAX_MONERO_ANCHORS: usize = 524_288;
const MAX_PUBLIC_EVENTS: usize = 2_097_152;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_id: String,
    pub chain_id: String,
    pub quorum_bps: u64,
    pub privacy_quorum_bps: u64,
    pub min_security_bits: u64,
    pub original_shards: u64,
    pub parity_shards: u64,
    pub shard_size_bytes: u64,
    pub challenge_window_blocks: u64,
    pub monero_confirmations: u64,
    pub receipt_ttl_blocks: u64,
    pub retention_blocks: u64,
    pub max_batch_bytes: u64,
    pub low_fee_micro_units: u64,
    pub attestation_reward_micro_units: u64,
    pub challenge_bond_micro_units: u64,
    pub slash_bps: u64,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub pq_backup_signature_suite: String,
    pub pq_kem_suite: String,
    pub erasure_suite: String,
    pub privacy_proof_suite: String,
    pub monero_anchor_suite: String,
    pub receipt_suite: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub committee_root: String,
    pub batch_root: String,
    pub shard_commitment_root: String,
    pub pq_attestation_root: String,
    pub privacy_claim_root: String,
    pub monero_anchor_root: String,
    pub challenge_window_root: String,
    pub receipt_root: String,
    pub low_fee_lane_root: String,
    pub public_event_root: String,
    pub config_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub committee_members: u64,
    pub active_committee_members: u64,
    pub batches: u64,
    pub finalized_batches: u64,
    pub low_fee_batches: u64,
    pub monero_anchored_batches: u64,
    pub private_batches: u64,
    pub shard_commitments: u64,
    pub usable_shards: u64,
    pub pq_attestations: u64,
    pub accepted_pq_attestations: u64,
    pub privacy_claims: u64,
    pub monero_anchors: u64,
    pub confirmed_monero_anchors: u64,
    pub open_challenges: u64,
    pub resolved_challenges: u64,
    pub receipts: u64,
    pub accepted_receipts: u64,
    pub public_events: u64,
    pub total_original_bytes: u64,
    pub total_encoded_bytes: u64,
    pub total_fee_micro_units: u64,
    pub total_attested_weight: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub committee_members: Vec<Value>,
    pub batches: Vec<Value>,
    pub shard_commitments: Vec<Value>,
    pub pq_attestations: Vec<Value>,
    pub privacy_claims: Vec<Value>,
    pub monero_anchors: Vec<Value>,
    pub challenge_windows: Vec<Value>,
    pub receipts: Vec<Value>,
    pub low_fee_lanes: Vec<Value>,
    pub public_events: Vec<Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_id: PROTOCOL_ID.to_string(),
            chain_id: CHAIN_ID.to_string(),
            quorum_bps: DEFAULT_QUORUM_BPS,
            privacy_quorum_bps: DEFAULT_PRIVACY_QUORUM_BPS,
            min_security_bits: DEFAULT_MIN_SECURITY_BITS,
            original_shards: DEFAULT_ORIGINAL_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
            shard_size_bytes: DEFAULT_SHARD_SIZE_BYTES,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            monero_confirmations: DEFAULT_MONERO_CONFIRMATIONS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            retention_blocks: DEFAULT_RETENTION_BLOCKS,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            low_fee_micro_units: DEFAULT_LOW_FEE_MICROUNITS,
            attestation_reward_micro_units: DEFAULT_ATTESTATION_REWARD_MICROUNITS,
            challenge_bond_micro_units: DEFAULT_CHALLENGE_BOND_MICROUNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            pq_backup_signature_suite: PQ_BACKUP_SIGNATURE_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            erasure_suite: ERASURE_SUITE.to_string(),
            privacy_proof_suite: PRIVACY_PROOF_SUITE.to_string(),
            monero_anchor_suite: MONERO_ANCHOR_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
        }
    }
}

impl Config {
    fn validate(&self) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
        ensure_non_empty(&self.protocol_id, "protocol id")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.hash_suite, "hash suite")?;
        ensure_non_empty(&self.pq_signature_suite, "pq signature suite")?;
        ensure_non_empty(&self.pq_backup_signature_suite, "pq backup signature suite")?;
        ensure_non_empty(&self.pq_kem_suite, "pq kem suite")?;
        ensure_non_empty(&self.erasure_suite, "erasure suite")?;
        ensure_non_empty(&self.privacy_proof_suite, "privacy proof suite")?;
        ensure_non_empty(&self.monero_anchor_suite, "monero anchor suite")?;
        ensure_non_empty(&self.receipt_suite, "receipt suite")?;
        ensure_at_most(self.quorum_bps, MAX_BPS, "quorum bps")?;
        ensure_at_most(self.privacy_quorum_bps, MAX_BPS, "privacy quorum bps")?;
        ensure_at_most(self.slash_bps, MAX_BPS, "slash bps")?;
        ensure_positive(self.quorum_bps, "quorum bps")?;
        ensure_positive(self.privacy_quorum_bps, "privacy quorum bps")?;
        ensure_positive(self.min_security_bits, "minimum security bits")?;
        ensure_positive(self.original_shards, "original shards")?;
        ensure_positive(self.parity_shards, "parity shards")?;
        ensure_positive(self.shard_size_bytes, "shard size bytes")?;
        ensure_positive(self.challenge_window_blocks, "challenge window blocks")?;
        ensure_positive(self.monero_confirmations, "monero confirmations")?;
        ensure_positive(self.receipt_ttl_blocks, "receipt ttl blocks")?;
        ensure_positive(self.retention_blocks, "retention blocks")?;
        ensure_positive(self.max_batch_bytes, "max batch bytes")?;
        ensure_positive(self.low_fee_micro_units, "low fee micro units")?;
        if self.min_security_bits < DEFAULT_MIN_SECURITY_BITS {
            return Err("minimum security bits below post-quantum policy".to_string());
        }
        if self.privacy_quorum_bps < self.quorum_bps {
            return Err("privacy quorum cannot be lower than base quorum".to_string());
        }
        Ok(())
    }

    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PQ_PRIVACY_PRESERVING_DATA_AVAILABILITY_QUORUM_PROTOCOL_VERSION,
            "protocol_id": self.protocol_id,
            "chain_id": self.chain_id,
            "quorum_bps": self.quorum_bps,
            "privacy_quorum_bps": self.privacy_quorum_bps,
            "min_security_bits": self.min_security_bits,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "shard_size_bytes": self.shard_size_bytes,
            "challenge_window_blocks": self.challenge_window_blocks,
            "monero_confirmations": self.monero_confirmations,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "retention_blocks": self.retention_blocks,
            "max_batch_bytes": self.max_batch_bytes,
            "low_fee_micro_units": self.low_fee_micro_units,
            "attestation_reward_micro_units": self.attestation_reward_micro_units,
            "challenge_bond_micro_units": self.challenge_bond_micro_units,
            "slash_bps": self.slash_bps,
            "hash_suite": self.hash_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "pq_backup_signature_suite": self.pq_backup_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "erasure_suite": self.erasure_suite,
            "privacy_proof_suite": self.privacy_proof_suite,
            "monero_anchor_suite": self.monero_anchor_suite,
            "receipt_suite": self.receipt_suite,
        })
    }
}

impl State {
    pub fn devnet() -> PqPrivacyPreservingDataAvailabilityQuorumResult<Self> {
        let config = Config::default();
        let committee_members = devnet_committee_members();
        let low_fee_lanes = devnet_low_fee_lanes(&config);
        let monero_anchors = devnet_monero_anchors(&config);
        let batches = devnet_batches(&config, &monero_anchors);
        let shard_commitments = devnet_shard_commitments(&config, &batches);
        let privacy_claims = devnet_privacy_claims(&config, &batches);
        let pq_attestations = devnet_pq_attestations(&config, &committee_members, &batches);
        let challenge_windows = devnet_challenge_windows(&config, &batches);
        let receipts = devnet_receipts(&config, &batches, &pq_attestations);
        let public_events = devnet_public_events(
            &batches,
            &pq_attestations,
            &challenge_windows,
            &receipts,
            &monero_anchors,
        );
        let state = Self {
            height: DEFAULT_HEIGHT,
            config,
            committee_members,
            batches,
            shard_commitments,
            pq_attestations,
            privacy_claims,
            monero_anchors,
            challenge_windows,
            receipts,
            low_fee_lanes,
            public_events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
        self.config.validate()?;
        ensure_len_at_most(
            self.committee_members.len(),
            MAX_COMMITTEE_MEMBERS,
            "committee members",
        )?;
        ensure_len_at_most(self.batches.len(), MAX_BATCHES, "batches")?;
        ensure_len_at_most(
            self.shard_commitments.len(),
            MAX_SHARDS,
            "shard commitments",
        )?;
        ensure_len_at_most(
            self.pq_attestations.len(),
            MAX_ATTESTATIONS,
            "pq attestations",
        )?;
        ensure_len_at_most(
            self.challenge_windows.len(),
            MAX_CHALLENGES,
            "challenge windows",
        )?;
        ensure_len_at_most(self.receipts.len(), MAX_RECEIPTS, "receipts")?;
        ensure_len_at_most(
            self.monero_anchors.len(),
            MAX_MONERO_ANCHORS,
            "monero anchors",
        )?;
        ensure_len_at_most(self.public_events.len(), MAX_PUBLIC_EVENTS, "public events")?;
        validate_unique_ids(&self.committee_members, "member_id", "committee member")?;
        validate_unique_ids(&self.batches, "batch_id", "batch")?;
        validate_unique_ids(&self.shard_commitments, "shard_id", "shard commitment")?;
        validate_unique_ids(&self.pq_attestations, "attestation_id", "pq attestation")?;
        validate_unique_ids(&self.privacy_claims, "claim_id", "privacy claim")?;
        validate_unique_ids(&self.monero_anchors, "anchor_id", "monero anchor")?;
        validate_unique_ids(&self.challenge_windows, "challenge_id", "challenge window")?;
        validate_unique_ids(&self.receipts, "receipt_id", "receipt")?;
        validate_unique_ids(&self.low_fee_lanes, "lane_id", "low fee lane")?;
        validate_committee_members(&self.committee_members)?;
        validate_low_fee_lanes(&self.low_fee_lanes)?;
        validate_monero_anchors(&self.monero_anchors, self.height, &self.config)?;
        validate_batches(&self.batches, &self.config, &self.monero_anchors)?;
        validate_shard_commitments(&self.shard_commitments, &self.batches, &self.config)?;
        validate_privacy_claims(&self.privacy_claims, &self.batches, &self.config)?;
        validate_pq_attestations(
            &self.pq_attestations,
            &self.committee_members,
            &self.batches,
            &self.config,
        )?;
        validate_challenge_windows(&self.challenge_windows, &self.batches, self.height)?;
        validate_receipts(
            &self.receipts,
            &self.batches,
            &self.pq_attestations,
            self.height,
        )?;
        validate_quorums(
            &self.batches,
            &self.committee_members,
            &self.pq_attestations,
            &self.config,
        )?;
        Ok(())
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(
        &mut self,
        delta: u64,
    ) -> PqPrivacyPreservingDataAvailabilityQuorumResult<u64> {
        let next = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "height update overflow".to_string())?;
        self.set_height(next)?;
        Ok(self.height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(&self.config.public_record());
        let committee_root = merkle_root(
            "PQ-PRIVACY-DA-COMMITTEE",
            &normalized(&self.committee_members),
        );
        let batch_root = merkle_root("PQ-PRIVACY-DA-BATCH", &normalized(&self.batches));
        let shard_commitment_root = merkle_root(
            "PQ-PRIVACY-DA-SHARD-COMMITMENT",
            &normalized(&self.shard_commitments),
        );
        let pq_attestation_root = merkle_root(
            "PQ-PRIVACY-DA-ATTESTATION",
            &normalized(&self.pq_attestations),
        );
        let privacy_claim_root = merkle_root(
            "PQ-PRIVACY-DA-PRIVACY-CLAIM",
            &normalized(&self.privacy_claims),
        );
        let monero_anchor_root = merkle_root(
            "PQ-PRIVACY-DA-MONERO-ANCHOR",
            &normalized(&self.monero_anchors),
        );
        let challenge_window_root = merkle_root(
            "PQ-PRIVACY-DA-CHALLENGE-WINDOW",
            &normalized(&self.challenge_windows),
        );
        let receipt_root = merkle_root("PQ-PRIVACY-DA-RECEIPT", &normalized(&self.receipts));
        let low_fee_lane_root = merkle_root(
            "PQ-PRIVACY-DA-LOW-FEE-LANE",
            &normalized(&self.low_fee_lanes),
        );
        let public_event_root = merkle_root(
            "PQ-PRIVACY-DA-PUBLIC-EVENT",
            &normalized(&self.public_events),
        );
        let root_record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_PRIVACY_PRESERVING_DATA_AVAILABILITY_QUORUM_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": &config_root,
            "committee_root": &committee_root,
            "batch_root": &batch_root,
            "shard_commitment_root": &shard_commitment_root,
            "pq_attestation_root": &pq_attestation_root,
            "privacy_claim_root": &privacy_claim_root,
            "monero_anchor_root": &monero_anchor_root,
            "challenge_window_root": &challenge_window_root,
            "receipt_root": &receipt_root,
            "low_fee_lane_root": &low_fee_lane_root,
            "public_event_root": &public_event_root,
        });
        let state_root = root_from_record(&root_record);
        Roots {
            committee_root,
            batch_root,
            shard_commitment_root,
            pq_attestation_root,
            privacy_claim_root,
            monero_anchor_root,
            challenge_window_root,
            receipt_root,
            low_fee_lane_root,
            public_event_root,
            config_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let active_committee_members = count_by_status(&self.committee_members, "active");
        let finalized_batches = count_by_status(&self.batches, "finalized");
        let low_fee_batches = count_bool(&self.batches, "low_fee");
        let monero_anchored_batches = self
            .batches
            .iter()
            .filter(|record| string_field(record, "monero_anchor_id").is_some())
            .count() as u64;
        let private_batches = count_bool(&self.batches, "privacy_preserving");
        let usable_shards = self
            .shard_commitments
            .iter()
            .filter(|record| {
                matches!(
                    string_field(record, "status").as_deref(),
                    Some("committed") | Some("sampled") | Some("repaired")
                )
            })
            .count() as u64;
        let accepted_pq_attestations = self
            .pq_attestations
            .iter()
            .filter(|record| {
                matches!(
                    string_field(record, "status").as_deref(),
                    Some("accepted") | Some("finalized")
                )
            })
            .count() as u64;
        let confirmed_monero_anchors = self
            .monero_anchors
            .iter()
            .filter(|record| matches!(string_field(record, "status").as_deref(), Some("confirmed")))
            .count() as u64;
        let open_challenges = self
            .challenge_windows
            .iter()
            .filter(|record| matches!(string_field(record, "status").as_deref(), Some("open")))
            .count() as u64;
        let resolved_challenges = self
            .challenge_windows
            .iter()
            .filter(|record| {
                matches!(
                    string_field(record, "status").as_deref(),
                    Some("resolved") | Some("dismissed") | Some("slashed")
                )
            })
            .count() as u64;
        let accepted_receipts = self
            .receipts
            .iter()
            .filter(|record| {
                matches!(
                    string_field(record, "status").as_deref(),
                    Some("accepted") | Some("settled")
                )
            })
            .count() as u64;
        Counters {
            committee_members: self.committee_members.len() as u64,
            active_committee_members,
            batches: self.batches.len() as u64,
            finalized_batches,
            low_fee_batches,
            monero_anchored_batches,
            private_batches,
            shard_commitments: self.shard_commitments.len() as u64,
            usable_shards,
            pq_attestations: self.pq_attestations.len() as u64,
            accepted_pq_attestations,
            privacy_claims: self.privacy_claims.len() as u64,
            monero_anchors: self.monero_anchors.len() as u64,
            confirmed_monero_anchors,
            open_challenges,
            resolved_challenges,
            receipts: self.receipts.len() as u64,
            accepted_receipts,
            public_events: self.public_events.len() as u64,
            total_original_bytes: sum_u64(&self.batches, "original_bytes"),
            total_encoded_bytes: sum_u64(&self.batches, "encoded_bytes"),
            total_fee_micro_units: sum_u64(&self.receipts, "fee_micro_units"),
            total_attested_weight: sum_u64(&self.pq_attestations, "attested_weight"),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let state_root = roots.state_root.clone();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_PRIVACY_PRESERVING_DATA_AVAILABILITY_QUORUM_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots,
            "counters": counters,
            "committee_members": normalized(&self.committee_members),
            "batches": normalized(&self.batches),
            "shard_commitments": normalized(&self.shard_commitments),
            "pq_attestations": normalized(&self.pq_attestations),
            "privacy_claims": normalized(&self.privacy_claims),
            "monero_anchors": normalized(&self.monero_anchors),
            "challenge_windows": normalized(&self.challenge_windows),
            "receipts": normalized(&self.receipts),
            "low_fee_lanes": normalized(&self.low_fee_lanes),
            "public_events": normalized(&self.public_events),
            "state_root": state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn root_from_record(record: &Value) -> String {
    let mut payload = record.clone();
    remove_recursive(&mut payload, "state_root");
    domain_hash(
        "PQ-PRIVACY-PRESERVING-DA-QUORUM-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVACY_PRESERVING_DATA_AVAILABILITY_QUORUM_PROTOCOL_VERSION),
            HashPart::Json(&payload),
        ],
        32,
    )
}

pub fn devnet() -> PqPrivacyPreservingDataAvailabilityQuorumResult<State> {
    State::devnet()
}

fn devnet_committee_members() -> Vec<Value> {
    [
        ("pq-da-sequencer-a", "sequencer", 40_u64),
        ("pq-da-watchtower-b", "watchtower", 30_u64),
        ("pq-da-archive-c", "archive_provider", 20_u64),
        ("pq-da-monero-observer-d", "monero_observer", 15_u64),
        ("pq-da-repair-e", "repair_provider", 15_u64),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (label, role, weight))| {
        let key_commitment = string_root("PQ-DA-MEMBER-KEY", label);
        let backup_key_commitment = string_root("PQ-DA-MEMBER-BACKUP-KEY", label);
        let member_id = record_id("PQ-DA-MEMBER-ID", &[("label", label), ("role", role)]);
        json!({
            "member_id": member_id,
            "label": label,
            "role": role,
            "status": "active",
            "weight": weight,
            "stake_micro_units": weight * 1_000_000,
            "pq_public_key_commitment": key_commitment,
            "pq_backup_public_key_commitment": backup_key_commitment,
            "kem_public_key_commitment": string_root("PQ-DA-MEMBER-KEM", label),
            "privacy_guardian": matches!(role, "sequencer" | "watchtower" | "monero_observer"),
            "low_fee_sponsor": index % 2 == 0,
            "joined_height": DEFAULT_HEIGHT - 512 + (index as u64 * 8),
            "rotation_epoch": 1_u64,
        })
    })
    .collect()
}

fn devnet_low_fee_lanes(config: &Config) -> Vec<Value> {
    [
        ("private_transfer", 10_000_u64, true, "shielded wallets"),
        ("monero_anchor", 9_600_u64, true, "monero bridge anchor"),
        ("defi_swap", 8_400_u64, true, "private defi"),
        ("token_transfer", 8_000_u64, true, "confidential token"),
        ("contract_call", 7_600_u64, true, "private contract"),
        ("proof_aggregation", 7_000_u64, false, "recursive proof"),
    ]
    .into_iter()
    .map(|(lane, priority, privacy_required, description)| {
        json!({
            "lane_id": record_id("PQ-DA-LANE-ID", &[("lane", lane)]),
            "lane": lane,
            "description": description,
            "status": "active",
            "priority": priority,
            "privacy_required": privacy_required,
            "target_fee_micro_units": config.low_fee_micro_units,
            "max_batch_bytes": config.max_batch_bytes / 2,
            "retention_blocks": config.retention_blocks,
            "sponsor_pool_root": string_root("PQ-DA-LANE-SPONSOR-POOL", lane),
        })
    })
    .collect()
}

fn devnet_monero_anchors(config: &Config) -> Vec<Value> {
    (0..3)
        .map(|index| {
            let block_height = 3_000_000_u64 + index as u64;
            let tx_root = domain_hash(
                "PQ-DA-MONERO-TX-ROOT",
                &[
                    HashPart::Int(block_height as i128),
                    HashPart::Int(index as i128),
                ],
                32,
            );
            let anchor_id = domain_hash(
                "PQ-DA-MONERO-ANCHOR-ID",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Int(block_height as i128),
                    HashPart::Str(&tx_root),
                ],
                32,
            );
            json!({
                "anchor_id": anchor_id,
                "network": "monero-devnet",
                "status": "confirmed",
                "monero_height": block_height,
                "observed_l2_height": DEFAULT_HEIGHT - 40 + index as u64,
                "confirmations": config.monero_confirmations + 4 + index as u64,
                "block_hash_commitment": string_root("PQ-DA-MONERO-BLOCK", &block_height.to_string()),
                "tx_root": tx_root,
                "view_tag_root": string_root("PQ-DA-MONERO-VIEW-TAG-ROOT", &block_height.to_string()),
                "anchor_proof_root": string_root("PQ-DA-MONERO-ANCHOR-PROOF", &block_height.to_string()),
                "reserve_epoch": 7_u64,
            })
        })
        .collect()
}

fn devnet_batches(config: &Config, monero_anchors: &[Value]) -> Vec<Value> {
    [
        ("private_transfer", true, Some(0_usize), 42_000_u64, "finalized"),
        ("monero_anchor", true, Some(1_usize), 58_000_u64, "finalized"),
        ("defi_swap", true, None, 64_000_u64, "attested"),
        ("token_transfer", true, None, 39_000_u64, "attested"),
        ("contract_call", true, None, 71_000_u64, "sampling"),
        ("proof_aggregation", false, Some(2_usize), 84_000_u64, "attested"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (lane, privacy_preserving, anchor_index, original_bytes, status))| {
        let batch_label = format!("{lane}-{index}");
        let payload_hash = string_root("PQ-DA-BATCH-PAYLOAD", &batch_label);
        let batch_id = domain_hash(
            "PQ-DA-BATCH-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane),
                HashPart::Str(&payload_hash),
                HashPart::Int(index as i128),
            ],
            32,
        );
        let anchor_id = anchor_index
            .and_then(|slot| monero_anchors.get(slot))
            .and_then(|record| string_field(record, "anchor_id"));
        let encoded_bytes =
            original_bytes * (config.original_shards + config.parity_shards) / config.original_shards;
        json!({
            "batch_id": batch_id,
            "lane": lane,
            "status": status,
            "height": DEFAULT_HEIGHT - 16 + index as u64,
            "deadline_height": DEFAULT_HEIGHT - 16 + index as u64 + config.challenge_window_blocks,
            "low_fee": true,
            "privacy_preserving": privacy_preserving,
            "monero_anchor_id": anchor_id,
            "payload_hash": payload_hash,
            "sequencer_commitment": string_root("PQ-DA-BATCH-SEQUENCER", &batch_label),
            "state_delta_commitment": string_root("PQ-DA-BATCH-STATE-DELTA", &batch_label),
            "nullifier_root": string_root("PQ-DA-BATCH-NULLIFIER", &batch_label),
            "recipient_commitment_root": string_root("PQ-DA-BATCH-RECIPIENT", &batch_label),
            "contract_call_root": string_root("PQ-DA-BATCH-CONTRACT-CALL", &batch_label),
            "token_commitment_root": string_root("PQ-DA-BATCH-TOKEN", &batch_label),
            "original_bytes": original_bytes,
            "encoded_bytes": encoded_bytes,
            "original_shards": config.original_shards,
            "parity_shards": config.parity_shards,
            "shard_size_bytes": config.shard_size_bytes,
            "erasure_commitment_root": string_root("PQ-DA-BATCH-ERASURE", &batch_label),
            "privacy_budget_micro_units": config.low_fee_micro_units * original_bytes.div_ceil(1024),
        })
    })
    .collect()
}

fn devnet_shard_commitments(config: &Config, batches: &[Value]) -> Vec<Value> {
    let mut commitments = Vec::new();
    for batch in batches {
        let Some(batch_id) = string_field(batch, "batch_id") else {
            continue;
        };
        let Some(payload_hash) = string_field(batch, "payload_hash") else {
            continue;
        };
        for shard_index in 0..(config.original_shards + config.parity_shards) {
            let role = if shard_index < config.original_shards {
                "original"
            } else {
                "parity"
            };
            let shard_id = domain_hash(
                "PQ-DA-SHARD-ID",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&batch_id),
                    HashPart::Int(shard_index as i128),
                    HashPart::Str(role),
                ],
                32,
            );
            let status = if shard_index % 19 == 0 {
                "sampled"
            } else {
                "committed"
            };
            commitments.push(json!({
                "shard_id": shard_id,
                "batch_id": batch_id,
                "shard_index": shard_index,
                "role": role,
                "status": status,
                "payload_hash": payload_hash,
                "commitment": domain_hash(
                    "PQ-DA-SHARD-COMMITMENT",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(&payload_hash),
                        HashPart::Int(shard_index as i128),
                        HashPart::Str(role),
                    ],
                    32,
                ),
                "proof_commitment": domain_hash(
                    "PQ-DA-SHARD-PROOF-COMMITMENT",
                    &[
                        HashPart::Str(&batch_id),
                        HashPart::Int(shard_index as i128),
                    ],
                    32,
                ),
                "size_bytes": config.shard_size_bytes,
                "availability_hint": domain_hash(
                    "PQ-DA-SHARD-AVAILABILITY-HINT",
                    &[
                        HashPart::Str(&batch_id),
                        HashPart::Int((shard_index % 8) as i128),
                    ],
                    16,
                ),
            }));
        }
    }
    commitments
}

fn devnet_privacy_claims(config: &Config, batches: &[Value]) -> Vec<Value> {
    batches
        .iter()
        .filter(|batch| bool_field(batch, "privacy_preserving"))
        .filter_map(|batch| {
            let batch_id = string_field(batch, "batch_id")?;
            let lane = string_field(batch, "lane")?;
            let claim_id = domain_hash(
                "PQ-DA-PRIVACY-CLAIM-ID",
                &[HashPart::Str(&batch_id), HashPart::Str(&lane)],
                32,
            );
            Some(json!({
                "claim_id": claim_id,
                "batch_id": batch_id,
                "lane": lane,
                "status": "verified",
                "proof_system": config.privacy_proof_suite,
                "selective_disclosure_root": string_root("PQ-DA-PRIVACY-SELECTIVE-DISCLOSURE", &batch_id),
                "view_tag_commitment_root": string_root("PQ-DA-PRIVACY-VIEW-TAGS", &batch_id),
                "nullifier_non_membership_root": string_root("PQ-DA-PRIVACY-NULLIFIER-NON-MEMBERSHIP", &batch_id),
                "contract_calldata_redaction_root": string_root("PQ-DA-PRIVACY-CALLDATA-REDACTION", &batch_id),
                "min_security_bits": config.min_security_bits,
                "leakage_budget_bits": 0_u64,
            }))
        })
        .collect()
}

fn devnet_pq_attestations(
    config: &Config,
    committee_members: &[Value],
    batches: &[Value],
) -> Vec<Value> {
    let mut attestations = Vec::new();
    for batch in batches {
        let Some(batch_id) = string_field(batch, "batch_id") else {
            continue;
        };
        let Some(payload_hash) = string_field(batch, "payload_hash") else {
            continue;
        };
        for member in committee_members {
            let Some(member_id) = string_field(member, "member_id") else {
                continue;
            };
            let Some(role) = string_field(member, "role") else {
                continue;
            };
            let weight = u64_field(member, "weight").map_or(0, |value| value);
            if role == "repair_provider"
                && string_field(batch, "status").as_deref() == Some("finalized")
            {
                continue;
            }
            let attestation_id = domain_hash(
                "PQ-DA-ATTESTATION-ID",
                &[
                    HashPart::Str(&batch_id),
                    HashPart::Str(&member_id),
                    HashPart::Str(&payload_hash),
                ],
                32,
            );
            let status = if bool_field(batch, "privacy_preserving") || role != "archive_provider" {
                "accepted"
            } else {
                "submitted"
            };
            attestations.push(json!({
                "attestation_id": attestation_id,
                "batch_id": batch_id,
                "member_id": member_id,
                "member_role": role,
                "status": status,
                "attested_weight": weight,
                "height": DEFAULT_HEIGHT - 8,
                "payload_hash": payload_hash,
                "erasure_root": string_field(batch, "erasure_commitment_root"),
                "privacy_claimed": bool_field(batch, "privacy_preserving"),
                "monero_anchor_id": string_field(batch, "monero_anchor_id"),
                "signature_scheme": config.pq_signature_suite,
                "backup_signature_scheme": config.pq_backup_signature_suite,
                "kem_ciphertext_commitment": domain_hash(
                    "PQ-DA-ATTESTATION-KEM-CIPHERTEXT",
                    &[HashPart::Str(&batch_id), HashPart::Str(&member_id)],
                    32,
                ),
                "signature_root": domain_hash(
                    "PQ-DA-ATTESTATION-SIGNATURE",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(&batch_id),
                        HashPart::Str(&member_id),
                        HashPart::Str(&payload_hash),
                    ],
                    64,
                ),
                "low_fee_receipt_hint": domain_hash(
                    "PQ-DA-ATTESTATION-RECEIPT-HINT",
                    &[HashPart::Str(&batch_id), HashPart::Str(&member_id)],
                    16,
                ),
            }));
        }
    }
    attestations
}

fn devnet_challenge_windows(config: &Config, batches: &[Value]) -> Vec<Value> {
    batches
        .iter()
        .filter_map(|batch| {
            let batch_id = string_field(batch, "batch_id")?;
            let height = u64_field(batch, "height")?;
            let status = if string_field(batch, "status").as_deref() == Some("sampling") {
                "open"
            } else {
                "resolved"
            };
            Some(json!({
                "challenge_id": domain_hash(
                    "PQ-DA-CHALLENGE-ID",
                    &[HashPart::Str(&batch_id), HashPart::Int(height as i128)],
                    32,
                ),
                "batch_id": batch_id,
                "status": status,
                "opened_height": height,
                "deadline_height": height + config.challenge_window_blocks,
                "bond_micro_units": config.challenge_bond_micro_units,
                "challenger_commitment": string_root("PQ-DA-CHALLENGER", &batch_id),
                "sampling_seed_commitment": string_root("PQ-DA-CHALLENGE-SAMPLING-SEED", &batch_id),
                "withheld_shard_root": string_root("PQ-DA-CHALLENGE-WITHHELD-SHARD", &batch_id),
                "resolution_root": string_root("PQ-DA-CHALLENGE-RESOLUTION", &batch_id),
            }))
        })
        .collect()
}

fn devnet_receipts(config: &Config, batches: &[Value], attestations: &[Value]) -> Vec<Value> {
    batches
        .iter()
        .filter_map(|batch| {
            let batch_id = string_field(batch, "batch_id")?;
            let lane = string_field(batch, "lane")?;
            let attestation_root = merkle_root(
                "PQ-DA-RECEIPT-ATTESTATION",
                &attestations
                    .iter()
                    .filter(|attestation| {
                        string_field(attestation, "batch_id").as_deref() == Some(batch_id.as_str())
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            Some(json!({
                "receipt_id": domain_hash(
                    "PQ-DA-RECEIPT-ID",
                    &[HashPart::Str(&batch_id), HashPart::Str(&lane)],
                    32,
                ),
                "batch_id": batch_id,
                "lane": lane,
                "status": if string_field(batch, "status").as_deref() == Some("sampling") {
                    "pending"
                } else {
                    "accepted"
                },
                "issued_height": DEFAULT_HEIGHT - 4,
                "expires_height": DEFAULT_HEIGHT - 4 + config.receipt_ttl_blocks,
                "fee_asset_id": "dxmr",
                "fee_micro_units": config.low_fee_micro_units
                    * u64_field(batch, "original_bytes")
                        .map_or(0, |value| value)
                        .div_ceil(1024),
                "attestation_root": attestation_root,
                "receipt_commitment": string_root("PQ-DA-RECEIPT-COMMITMENT", &batch_id),
                "privacy_receipt_root": string_root("PQ-DA-RECEIPT-PRIVACY", &batch_id),
                "sponsor_commitment": string_root("PQ-DA-RECEIPT-SPONSOR", &batch_id),
            }))
        })
        .collect()
}

fn devnet_public_events(
    batches: &[Value],
    attestations: &[Value],
    challenges: &[Value],
    receipts: &[Value],
    anchors: &[Value],
) -> Vec<Value> {
    let mut events = Vec::new();
    for batch in batches {
        if let Some(batch_id) = string_field(batch, "batch_id") {
            events.push(event_record("batch_posted", &batch_id, batch));
        }
    }
    for attestation in attestations.iter().take(16) {
        if let Some(attestation_id) = string_field(attestation, "attestation_id") {
            events.push(event_record("pq_attestation", &attestation_id, attestation));
        }
    }
    for challenge in challenges {
        if let Some(challenge_id) = string_field(challenge, "challenge_id") {
            events.push(event_record("challenge_window", &challenge_id, challenge));
        }
    }
    for receipt in receipts {
        if let Some(receipt_id) = string_field(receipt, "receipt_id") {
            events.push(event_record("receipt_issued", &receipt_id, receipt));
        }
    }
    for anchor in anchors {
        if let Some(anchor_id) = string_field(anchor, "anchor_id") {
            events.push(event_record("monero_anchor_observed", &anchor_id, anchor));
        }
    }
    events
}

fn event_record(kind: &str, object_id: &str, payload: &Value) -> Value {
    let payload_root = root_from_record(payload);
    json!({
        "event_id": domain_hash(
            "PQ-DA-PUBLIC-EVENT-ID",
            &[HashPart::Str(kind), HashPart::Str(object_id), HashPart::Str(&payload_root)],
            32,
        ),
        "kind": kind,
        "object_id": object_id,
        "height": DEFAULT_HEIGHT,
        "payload_root": payload_root,
    })
}

fn validate_committee_members(
    records: &[Value],
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let mut total_weight = 0_u64;
    for record in records {
        require_string(record, "member_id")?;
        require_string(record, "label")?;
        let role = require_string(record, "role")?;
        require_allowed(
            &role,
            &[
                "sequencer",
                "watchtower",
                "archive_provider",
                "monero_observer",
                "repair_provider",
                "challenger",
                "emergency_council",
            ],
            "committee member role",
        )?;
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &["active", "jailed", "rotating", "retired"],
            "member status",
        )?;
        let weight = require_u64(record, "weight")?;
        ensure_positive(weight, "committee member weight")?;
        total_weight = total_weight
            .checked_add(weight)
            .ok_or_else(|| "committee weight overflow".to_string())?;
        require_string(record, "pq_public_key_commitment")?;
        require_string(record, "pq_backup_public_key_commitment")?;
        require_string(record, "kem_public_key_commitment")?;
    }
    ensure_positive(total_weight, "committee total weight")
}

fn validate_low_fee_lanes(
    records: &[Value],
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    for record in records {
        require_string(record, "lane_id")?;
        require_string(record, "lane")?;
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &["active", "paused", "degraded", "retired"],
            "lane status",
        )?;
        ensure_positive(require_u64(record, "priority")?, "lane priority")?;
        ensure_positive(
            require_u64(record, "target_fee_micro_units")?,
            "lane target fee micro units",
        )?;
        require_bool(record, "privacy_required")?;
        require_string(record, "sponsor_pool_root")?;
    }
    Ok(())
}

fn validate_monero_anchors(
    records: &[Value],
    l2_height: u64,
    config: &Config,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    for record in records {
        require_string(record, "anchor_id")?;
        require_string(record, "network")?;
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &["observed", "confirmed", "reorged", "expired"],
            "anchor status",
        )?;
        ensure_positive(require_u64(record, "monero_height")?, "monero height")?;
        let observed_l2_height = require_u64(record, "observed_l2_height")?;
        if observed_l2_height > l2_height {
            return Err("monero anchor observed in future L2 height".to_string());
        }
        let confirmations = require_u64(record, "confirmations")?;
        if status == "confirmed" && confirmations < config.monero_confirmations {
            return Err("confirmed monero anchor below confirmation policy".to_string());
        }
        require_string(record, "block_hash_commitment")?;
        require_string(record, "tx_root")?;
        require_string(record, "view_tag_root")?;
        require_string(record, "anchor_proof_root")?;
    }
    Ok(())
}

fn validate_batches(
    records: &[Value],
    config: &Config,
    monero_anchors: &[Value],
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let anchor_ids = id_set(monero_anchors, "anchor_id");
    for record in records {
        require_string(record, "batch_id")?;
        require_string(record, "lane")?;
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &[
                "posted",
                "sampling",
                "attested",
                "challenged",
                "finalized",
                "expired",
                "slashed",
            ],
            "batch status",
        )?;
        let original_bytes = require_u64(record, "original_bytes")?;
        ensure_positive(original_bytes, "batch original bytes")?;
        ensure_at_most(
            original_bytes,
            config.max_batch_bytes,
            "batch original bytes",
        )?;
        let encoded_bytes = require_u64(record, "encoded_bytes")?;
        if encoded_bytes < original_bytes {
            return Err("encoded batch bytes below original bytes".to_string());
        }
        if require_u64(record, "original_shards")? != config.original_shards {
            return Err("batch original shard count differs from config".to_string());
        }
        if require_u64(record, "parity_shards")? != config.parity_shards {
            return Err("batch parity shard count differs from config".to_string());
        }
        require_bool(record, "low_fee")?;
        require_bool(record, "privacy_preserving")?;
        require_string(record, "payload_hash")?;
        require_string(record, "sequencer_commitment")?;
        require_string(record, "state_delta_commitment")?;
        require_string(record, "erasure_commitment_root")?;
        if let Some(anchor_id) = string_field(record, "monero_anchor_id") {
            if !anchor_ids.contains(&anchor_id) {
                return Err(format!(
                    "batch references unknown monero anchor {anchor_id}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_shard_commitments(
    records: &[Value],
    batches: &[Value],
    config: &Config,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let batch_ids = id_set(batches, "batch_id");
    let expected_per_batch = config.original_shards + config.parity_shards;
    let mut per_batch: BTreeMap<String, u64> = BTreeMap::new();
    for record in records {
        require_string(record, "shard_id")?;
        let batch_id = require_string(record, "batch_id")?;
        if !batch_ids.contains(&batch_id) {
            return Err(format!(
                "shard commitment references unknown batch {batch_id}"
            ));
        }
        let shard_index = require_u64(record, "shard_index")?;
        if shard_index >= expected_per_batch {
            return Err("shard index outside configured erasure set".to_string());
        }
        let role = require_string(record, "role")?;
        require_allowed(&role, &["original", "parity", "repair"], "shard role")?;
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &[
                "committed",
                "sampled",
                "missing",
                "repaired",
                "withheld",
                "invalid",
            ],
            "shard status",
        )?;
        ensure_positive(require_u64(record, "size_bytes")?, "shard size bytes")?;
        require_string(record, "commitment")?;
        require_string(record, "proof_commitment")?;
        *per_batch.entry(batch_id).or_default() += 1;
    }
    for batch in batches {
        let batch_id = require_string(batch, "batch_id")?;
        let count = per_batch.get(&batch_id).copied().map_or(0, |value| value);
        if count != expected_per_batch {
            return Err(format!(
                "batch {batch_id} has {count} shard commitments, expected {expected_per_batch}"
            ));
        }
    }
    Ok(())
}

fn validate_privacy_claims(
    records: &[Value],
    batches: &[Value],
    config: &Config,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let private_batch_ids = batches
        .iter()
        .filter(|batch| bool_field(batch, "privacy_preserving"))
        .filter_map(|batch| string_field(batch, "batch_id"))
        .collect::<BTreeSet<_>>();
    for record in records {
        require_string(record, "claim_id")?;
        let batch_id = require_string(record, "batch_id")?;
        if !private_batch_ids.contains(&batch_id) {
            return Err(format!(
                "privacy claim references non-private batch {batch_id}"
            ));
        }
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &["submitted", "verified", "rejected"],
            "privacy claim status",
        )?;
        let proof_system = require_string(record, "proof_system")?;
        if proof_system != config.privacy_proof_suite {
            return Err("privacy claim proof system differs from config".to_string());
        }
        require_string(record, "selective_disclosure_root")?;
        require_string(record, "view_tag_commitment_root")?;
        require_string(record, "nullifier_non_membership_root")?;
        require_string(record, "contract_calldata_redaction_root")?;
        if require_u64(record, "leakage_budget_bits")? != 0 {
            return Err("privacy claim leaks more than the zero disclosure budget".to_string());
        }
    }
    Ok(())
}

fn validate_pq_attestations(
    records: &[Value],
    committee_members: &[Value],
    batches: &[Value],
    config: &Config,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let member_ids = id_set(committee_members, "member_id");
    let batch_ids = id_set(batches, "batch_id");
    for record in records {
        require_string(record, "attestation_id")?;
        let batch_id = require_string(record, "batch_id")?;
        if !batch_ids.contains(&batch_id) {
            return Err(format!("attestation references unknown batch {batch_id}"));
        }
        let member_id = require_string(record, "member_id")?;
        if !member_ids.contains(&member_id) {
            return Err(format!("attestation references unknown member {member_id}"));
        }
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &["submitted", "accepted", "finalized", "rejected", "slashed"],
            "attestation status",
        )?;
        ensure_positive(require_u64(record, "attested_weight")?, "attested weight")?;
        require_string(record, "payload_hash")?;
        let signature_scheme = require_string(record, "signature_scheme")?;
        if signature_scheme != config.pq_signature_suite {
            return Err("attestation signature suite differs from config".to_string());
        }
        let backup_signature_scheme = require_string(record, "backup_signature_scheme")?;
        if backup_signature_scheme != config.pq_backup_signature_suite {
            return Err("attestation backup signature suite differs from config".to_string());
        }
        require_string(record, "kem_ciphertext_commitment")?;
        require_string(record, "signature_root")?;
    }
    Ok(())
}

fn validate_challenge_windows(
    records: &[Value],
    batches: &[Value],
    height: u64,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let batch_ids = id_set(batches, "batch_id");
    for record in records {
        require_string(record, "challenge_id")?;
        let batch_id = require_string(record, "batch_id")?;
        if !batch_ids.contains(&batch_id) {
            return Err(format!("challenge references unknown batch {batch_id}"));
        }
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &[
                "open",
                "evidence_submitted",
                "resolved",
                "dismissed",
                "slashed",
                "expired",
            ],
            "challenge status",
        )?;
        let opened_height = require_u64(record, "opened_height")?;
        let deadline_height = require_u64(record, "deadline_height")?;
        if deadline_height <= opened_height {
            return Err("challenge deadline must be after opening height".to_string());
        }
        if status == "open" && height > deadline_height {
            return Err(format!("challenge {batch_id} is open past deadline"));
        }
        ensure_positive(require_u64(record, "bond_micro_units")?, "challenge bond")?;
        require_string(record, "challenger_commitment")?;
        require_string(record, "sampling_seed_commitment")?;
        require_string(record, "withheld_shard_root")?;
        require_string(record, "resolution_root")?;
    }
    Ok(())
}

fn validate_receipts(
    records: &[Value],
    batches: &[Value],
    attestations: &[Value],
    height: u64,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let batch_ids = id_set(batches, "batch_id");
    let attestation_roots = attestations
        .iter()
        .filter_map(|record| {
            Some((
                require_string(record, "batch_id").ok()?,
                root_from_record(record),
            ))
        })
        .collect::<Vec<_>>();
    for record in records {
        require_string(record, "receipt_id")?;
        let batch_id = require_string(record, "batch_id")?;
        if !batch_ids.contains(&batch_id) {
            return Err(format!("receipt references unknown batch {batch_id}"));
        }
        let status = require_string(record, "status")?;
        require_allowed(
            &status,
            &["pending", "accepted", "settled", "expired"],
            "receipt status",
        )?;
        let issued_height = require_u64(record, "issued_height")?;
        let expires_height = require_u64(record, "expires_height")?;
        if expires_height <= issued_height {
            return Err("receipt expiry must be after issue height".to_string());
        }
        if status != "expired" && height > expires_height {
            return Err(format!(
                "receipt {batch_id} has expired but status is {status}"
            ));
        }
        ensure_positive(require_u64(record, "fee_micro_units")?, "receipt fee")?;
        require_string(record, "fee_asset_id")?;
        require_string(record, "attestation_root")?;
        require_string(record, "receipt_commitment")?;
        require_string(record, "privacy_receipt_root")?;
        let has_attestation = attestation_roots
            .iter()
            .any(|(attested_batch, _)| attested_batch == &batch_id);
        if !has_attestation {
            return Err(format!("receipt {batch_id} lacks attestations"));
        }
    }
    Ok(())
}

fn validate_quorums(
    batches: &[Value],
    committee_members: &[Value],
    attestations: &[Value],
    config: &Config,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let total_weight = committee_members
        .iter()
        .filter(|record| string_field(record, "status").as_deref() == Some("active"))
        .map(|record| u64_field(record, "weight").map_or(0, |value| value))
        .sum::<u64>();
    ensure_positive(total_weight, "active quorum weight")?;
    let member_weights = committee_members
        .iter()
        .filter_map(|member| {
            Some((
                string_field(member, "member_id")?,
                u64_field(member, "weight")?,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    for batch in batches {
        let batch_id = require_string(batch, "batch_id")?;
        let status = require_string(batch, "status")?;
        if !matches!(status.as_str(), "attested" | "finalized") {
            continue;
        }
        let mut seen = BTreeSet::new();
        let mut weight = 0_u64;
        for attestation in attestations {
            if string_field(attestation, "batch_id").as_deref() != Some(batch_id.as_str()) {
                continue;
            }
            if !matches!(
                string_field(attestation, "status").as_deref(),
                Some("accepted") | Some("finalized")
            ) {
                continue;
            }
            let member_id = require_string(attestation, "member_id")?;
            if seen.insert(member_id.clone()) {
                weight = weight
                    .checked_add(
                        member_weights
                            .get(&member_id)
                            .copied()
                            .map_or(0, |value| value),
                    )
                    .ok_or_else(|| "attestation quorum weight overflow".to_string())?;
            }
        }
        let required_bps = if bool_field(batch, "privacy_preserving") {
            config.privacy_quorum_bps
        } else {
            config.quorum_bps
        };
        if weight.saturating_mul(MAX_BPS) < total_weight.saturating_mul(required_bps) {
            return Err(format!("batch {batch_id} does not satisfy DA quorum"));
        }
    }
    Ok(())
}

fn validate_unique_ids(
    records: &[Value],
    field: &str,
    label: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    let mut seen = BTreeSet::new();
    for record in records {
        let id = require_string(record, field)?;
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate {label} id {id}"));
        }
    }
    Ok(())
}

fn require_string(
    record: &Value,
    field: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<String> {
    string_field(record, field).ok_or_else(|| format!("missing or invalid string field {field}"))
}

fn require_u64(
    record: &Value,
    field: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<u64> {
    u64_field(record, field).ok_or_else(|| format!("missing or invalid u64 field {field}"))
}

fn require_bool(
    record: &Value,
    field: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<bool> {
    record
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or invalid bool field {field}"))
}

fn require_allowed(
    value: &str,
    allowed: &[&str],
    label: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("invalid {label}: {value}"))
    }
}

fn ensure_non_empty(
    value: &str,
    label: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_at_most(
    value: u64,
    max: u64,
    label: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    if value > max {
        Err(format!("{label} exceeds maximum {max}"))
    } else {
        Ok(())
    }
}

fn ensure_len_at_most(
    value: usize,
    max: usize,
    label: &str,
) -> PqPrivacyPreservingDataAvailabilityQuorumResult<()> {
    if value > max {
        Err(format!("{label} exceeds maximum length {max}"))
    } else {
        Ok(())
    }
}

fn string_field(record: &Value, field: &str) -> Option<String> {
    match record.get(field) {
        Some(Value::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn u64_field(record: &Value, field: &str) -> Option<u64> {
    record.get(field).and_then(Value::as_u64)
}

fn bool_field(record: &Value, field: &str) -> bool {
    record
        .get(field)
        .and_then(Value::as_bool)
        .map_or(false, |value| value)
}

fn count_by_status(records: &[Value], status: &str) -> u64 {
    records
        .iter()
        .filter(|record| string_field(record, "status").as_deref() == Some(status))
        .count() as u64
}

fn count_bool(records: &[Value], field: &str) -> u64 {
    records
        .iter()
        .filter(|record| bool_field(record, field))
        .count() as u64
}

fn sum_u64(records: &[Value], field: &str) -> u64 {
    records
        .iter()
        .map(|record| u64_field(record, field).map_or(0, |value| value))
        .fold(0_u64, u64::saturating_add)
}

fn id_set(records: &[Value], field: &str) -> BTreeSet<String> {
    records
        .iter()
        .filter_map(|record| string_field(record, field))
        .collect()
}

fn normalized(records: &[Value]) -> Vec<Value> {
    let mut values = records.to_vec();
    values.sort_by(|left, right| root_from_record(left).cmp(&root_from_record(right)));
    values
}

fn record_id(domain: &str, fields: &[(&str, &str)]) -> String {
    let record = fields
        .iter()
        .map(|(key, value)| ((*key).to_string(), Value::String((*value).to_string())))
        .collect::<serde_json::Map<String, Value>>();
    domain_hash(domain, &[HashPart::Json(&Value::Object(record))], 32)
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVACY_PRESERVING_DATA_AVAILABILITY_QUORUM_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn remove_recursive(value: &mut Value, key: &str) {
    match value {
        Value::Object(map) => {
            map.remove(key);
            for child in map.values_mut() {
                remove_recursive(child, key);
            }
        }
        Value::Array(values) => {
            for child in values {
                remove_recursive(child, key);
            }
        }
        _ => {}
    }
}
