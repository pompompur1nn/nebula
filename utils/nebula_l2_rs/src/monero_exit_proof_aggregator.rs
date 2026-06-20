use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type MoneroExitProofAggregatorResult<T> = Result<T, String>;

pub const MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_VERSION: u32 = 1;
pub const MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_LABEL: &str =
    "nebula-monero-exit-proof-aggregator-v1";
pub const MONERO_EXIT_PROOF_AGGREGATOR_SCHEMA_VERSION: u64 = 1;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_HEIGHT: u64 = 288;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_EXIT_PROOF_AGGREGATOR_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_EXIT_PROOF_AGGREGATOR_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-exit-aggregator-devnet";
pub const MONERO_EXIT_PROOF_AGGREGATOR_STEALTH_SCHEME: &str = "monero-stealth-payout-proof-set-v1";
pub const MONERO_EXIT_PROOF_AGGREGATOR_RANGE_SCHEME: &str =
    "monero-batched-range-proof-aggregation-v1";
pub const MONERO_EXIT_PROOF_AGGREGATOR_KEY_IMAGE_SCHEME: &str =
    "monero-key-image-non-linkability-evidence-v1";
pub const MONERO_EXIT_PROOF_AGGREGATOR_CERTIFICATE_SCHEME: &str =
    "pq-batch-settlement-certificate-v1";
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_MAX_TICKETS_PER_BATCH: usize = 128;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_MAX_BATCH_UNITS: u64 = 2_000_000;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_TARGET_VERIFY_MICROS: u64 = 18_000;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_REORG_GRACE_BLOCKS: u64 = 8;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_BASE_FEE_BPS: u64 = 18;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_FAST_FEE_BPS: u64 = 55;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_SPONSOR_POOL_UNITS: u64 = 150_000;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_PQ_QUORUM: u64 = 2;
pub const MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const MONERO_EXIT_PROOF_AGGREGATOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitProofTicketStatus {
    Submitted,
    Aggregating,
    Proved,
    Certified,
    ChallengeOpen,
    Settled,
    ReorgHeld,
    Cancelled,
    Expired,
}

impl ExitProofTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Aggregating => "aggregating",
            Self::Proved => "proved",
            Self::Certified => "certified",
            Self::ChallengeOpen => "challenge_open",
            Self::Settled => "settled",
            Self::ReorgHeld => "reorg_held",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Aggregating
                | Self::Proved
                | Self::Certified
                | Self::ChallengeOpen
                | Self::ReorgHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationBatchStatus {
    Collecting,
    Sealed,
    Proved,
    PqAttested,
    ChallengeOpen,
    SettlementReady,
    Settled,
    ReorgHeld,
    Cancelled,
}

impl AggregationBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Proved => "proved",
            Self::PqAttested => "pq_attested",
            Self::ChallengeOpen => "challenge_open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::ReorgHeld => "reorg_held",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Collecting
                | Self::Sealed
                | Self::Proved
                | Self::PqAttested
                | Self::ChallengeOpen
                | Self::SettlementReady
                | Self::ReorgHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Exhausted,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitProofAggregatorConfig {
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_tickets_per_batch: usize,
    pub max_batch_units: u64,
    pub target_verify_micros: u64,
    pub batch_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_depth: u64,
    pub reorg_grace_blocks: u64,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub sponsor_pool_units: u64,
    pub pq_quorum: u64,
    pub watchtower_quorum: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub stealth_payout_scheme: String,
    pub range_proof_scheme: String,
    pub key_image_scheme: String,
    pub settlement_certificate_scheme: String,
}

impl Default for MoneroExitProofAggregatorConfig {
    fn default() -> Self {
        Self {
            monero_network: MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_FEE_ASSET_ID.to_string(),
            max_tickets_per_batch: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_MAX_TICKETS_PER_BATCH,
            max_batch_units: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_MAX_BATCH_UNITS,
            target_verify_micros: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_TARGET_VERIFY_MICROS,
            batch_window_blocks: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_BATCH_WINDOW_BLOCKS,
            challenge_window_blocks: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_depth: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_FINALITY_DEPTH,
            reorg_grace_blocks: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_REORG_GRACE_BLOCKS,
            min_ring_size: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_TARGET_RING_SIZE,
            base_fee_bps: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_FAST_FEE_BPS,
            low_fee_rebate_bps: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_LOW_FEE_REBATE_BPS,
            sponsor_pool_units: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_SPONSOR_POOL_UNITS,
            pq_quorum: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_PQ_QUORUM,
            watchtower_quorum: MONERO_EXIT_PROOF_AGGREGATOR_DEFAULT_WATCHTOWER_QUORUM,
            hash_suite: MONERO_EXIT_PROOF_AGGREGATOR_HASH_SUITE.to_string(),
            pq_suite: MONERO_EXIT_PROOF_AGGREGATOR_PQ_SUITE.to_string(),
            stealth_payout_scheme: MONERO_EXIT_PROOF_AGGREGATOR_STEALTH_SCHEME.to_string(),
            range_proof_scheme: MONERO_EXIT_PROOF_AGGREGATOR_RANGE_SCHEME.to_string(),
            key_image_scheme: MONERO_EXIT_PROOF_AGGREGATOR_KEY_IMAGE_SCHEME.to_string(),
            settlement_certificate_scheme: MONERO_EXIT_PROOF_AGGREGATOR_CERTIFICATE_SCHEME
                .to_string(),
        }
    }
}

impl MoneroExitProofAggregatorConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_proof_aggregator_config",
            "chain_id": CHAIN_ID,
            "protocol_label": MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_LABEL,
            "protocol_version": MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_VERSION,
            "schema_version": MONERO_EXIT_PROOF_AGGREGATOR_SCHEMA_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_tickets_per_batch": self.max_tickets_per_batch,
            "max_batch_units": self.max_batch_units,
            "target_verify_micros": self.target_verify_micros,
            "batch_window_blocks": self.batch_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_depth": self.finality_depth,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "sponsor_pool_units": self.sponsor_pool_units,
            "pq_quorum": self.pq_quorum,
            "watchtower_quorum": self.watchtower_quorum,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "stealth_payout_scheme": self.stealth_payout_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "key_image_scheme": self.key_image_scheme,
            "settlement_certificate_scheme": self.settlement_certificate_scheme,
        })
    }

    pub fn validate(&self) -> MoneroExitProofAggregatorResult<()> {
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.l2_network", &self.l2_network)?;
        ensure_non_empty("config.asset_id", &self.asset_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_usize_positive("config.max_tickets_per_batch", self.max_tickets_per_batch)?;
        ensure_positive("config.max_batch_units", self.max_batch_units)?;
        ensure_positive("config.target_verify_micros", self.target_verify_micros)?;
        ensure_positive("config.batch_window_blocks", self.batch_window_blocks)?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.finality_depth", self.finality_depth)?;
        ensure_positive("config.min_ring_size", self.min_ring_size)?;
        ensure_positive("config.target_ring_size", self.target_ring_size)?;
        if self.target_ring_size < self.min_ring_size {
            return Err("config target ring size is below minimum".to_string());
        }
        ensure_bps("config.base_fee_bps", self.base_fee_bps)?;
        ensure_bps("config.fast_fee_bps", self.fast_fee_bps)?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_positive("config.pq_quorum", self.pq_quorum)?;
        ensure_positive("config.watchtower_quorum", self.watchtower_quorum)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitProofAggregatorRoots {
    pub config_root: String,
    pub ticket_root: String,
    pub stealth_payout_proof_root: String,
    pub range_proof_aggregate_root: String,
    pub key_image_evidence_root: String,
    pub pq_attestation_root: String,
    pub batch_certificate_root: String,
    pub finality_window_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub public_record_root: String,
}

impl MoneroExitProofAggregatorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "ticket_root": self.ticket_root,
            "stealth_payout_proof_root": self.stealth_payout_proof_root,
            "range_proof_aggregate_root": self.range_proof_aggregate_root,
            "key_image_evidence_root": self.key_image_evidence_root,
            "pq_attestation_root": self.pq_attestation_root,
            "batch_certificate_root": self.batch_certificate_root,
            "finality_window_root": self.finality_window_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        aggregator_payload_root("MONERO-EXIT-PROOF-AGGREGATOR-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitProofAggregatorCounters {
    pub ticket_count: u64,
    pub live_ticket_count: u64,
    pub batch_count: u64,
    pub live_batch_count: u64,
    pub stealth_payout_proof_count: u64,
    pub range_proof_aggregate_count: u64,
    pub key_image_evidence_count: u64,
    pub pq_attestation_count: u64,
    pub settlement_certificate_count: u64,
    pub finality_window_count: u64,
    pub sponsorship_count: u64,
    pub challenge_count: u64,
    pub event_count: u64,
    pub pending_exit_units: u64,
    pub aggregated_exit_units: u64,
    pub sponsored_fee_units: u64,
}

impl MoneroExitProofAggregatorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_count": self.ticket_count,
            "live_ticket_count": self.live_ticket_count,
            "batch_count": self.batch_count,
            "live_batch_count": self.live_batch_count,
            "stealth_payout_proof_count": self.stealth_payout_proof_count,
            "range_proof_aggregate_count": self.range_proof_aggregate_count,
            "key_image_evidence_count": self.key_image_evidence_count,
            "pq_attestation_count": self.pq_attestation_count,
            "settlement_certificate_count": self.settlement_certificate_count,
            "finality_window_count": self.finality_window_count,
            "sponsorship_count": self.sponsorship_count,
            "challenge_count": self.challenge_count,
            "event_count": self.event_count,
            "pending_exit_units": self.pending_exit_units,
            "aggregated_exit_units": self.aggregated_exit_units,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }

    pub fn counters_root(&self) -> String {
        aggregator_payload_root(
            "MONERO-EXIT-PROOF-AGGREGATOR-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitProofTicket {
    pub ticket_id: String,
    pub exit_id: String,
    pub owner_commitment: String,
    pub amount_units: u64,
    pub fee_units: u64,
    pub nullifier_root: String,
    pub stealth_payout_root: String,
    pub range_proof_root: String,
    pub key_image_root: String,
    pub priority_score: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub batch_id: String,
    pub status: ExitProofTicketStatus,
}

impl ExitProofTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        amount_units: u64,
        fee_units: u64,
        nullifier_root: impl Into<String>,
        stealth_payout_root: impl Into<String>,
        range_proof_root: impl Into<String>,
        key_image_root: impl Into<String>,
        priority_score: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroExitProofAggregatorResult<Self> {
        let exit_id = exit_id.into();
        let owner_commitment = owner_commitment.into();
        let nullifier_root = nullifier_root.into();
        let stealth_payout_root = stealth_payout_root.into();
        let range_proof_root = range_proof_root.into();
        let key_image_root = key_image_root.into();
        let ticket_id = exit_proof_ticket_id(
            &exit_id,
            &owner_commitment,
            amount_units,
            &nullifier_root,
            &stealth_payout_root,
            &range_proof_root,
            &key_image_root,
            opened_at_height,
        );
        let ticket = Self {
            ticket_id,
            exit_id,
            owner_commitment,
            amount_units,
            fee_units,
            nullifier_root,
            stealth_payout_root,
            range_proof_root,
            key_image_root,
            priority_score,
            opened_at_height,
            expires_at_height,
            batch_id: String::new(),
            status: ExitProofTicketStatus::Submitted,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_proof_ticket",
            "ticket_id": self.ticket_id,
            "exit_id": self.exit_id,
            "owner_commitment": self.owner_commitment,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "nullifier_root": self.nullifier_root,
            "stealth_payout_root": self.stealth_payout_root,
            "range_proof_root": self.range_proof_root,
            "key_image_root": self.key_image_root,
            "priority_score": self.priority_score,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroExitProofAggregatorResult<String> {
        ensure_non_empty("ticket.ticket_id", &self.ticket_id)?;
        ensure_non_empty("ticket.exit_id", &self.exit_id)?;
        ensure_non_empty("ticket.owner_commitment", &self.owner_commitment)?;
        ensure_positive("ticket.amount_units", self.amount_units)?;
        ensure_non_empty("ticket.nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("ticket.stealth_payout_root", &self.stealth_payout_root)?;
        ensure_non_empty("ticket.range_proof_root", &self.range_proof_root)?;
        ensure_non_empty("ticket.key_image_root", &self.key_image_root)?;
        ensure_expiry(
            self.opened_at_height,
            self.expires_at_height,
            "ticket.expires_at_height",
        )?;
        Ok(aggregator_payload_root(
            "MONERO-EXIT-PROOF-AGGREGATOR-TICKET",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub ticket_ids: Vec<String>,
    pub ticket_root: String,
    pub total_units: u64,
    pub total_fee_units: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub challenge_deadline_height: u64,
    pub status: AggregationBatchStatus,
}

impl AggregationBatch {
    pub fn new(
        sequence: u64,
        ticket_ids: Vec<String>,
        total_units: u64,
        total_fee_units: u64,
        height: u64,
        config: &MoneroExitProofAggregatorConfig,
    ) -> MoneroExitProofAggregatorResult<Self> {
        ensure_unique_strings(&ticket_ids, "batch.ticket_ids")?;
        let ticket_root =
            string_list_root("MONERO-EXIT-PROOF-AGGREGATOR-BATCH-TICKETS", &ticket_ids);
        let sealed_at_height = height.saturating_add(config.batch_window_blocks);
        let challenge_deadline_height =
            sealed_at_height.saturating_add(config.challenge_window_blocks);
        let batch_id = aggregation_batch_id(
            sequence,
            &ticket_root,
            total_units,
            total_fee_units,
            height,
            challenge_deadline_height,
        );
        let batch = Self {
            batch_id,
            sequence,
            ticket_ids,
            ticket_root,
            total_units,
            total_fee_units,
            opened_at_height: height,
            sealed_at_height,
            challenge_deadline_height,
            status: AggregationBatchStatus::Collecting,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_proof_aggregation_batch",
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "ticket_ids": self.ticket_ids,
            "ticket_root": self.ticket_root,
            "total_units": self.total_units,
            "total_fee_units": self.total_fee_units,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroExitProofAggregatorResult<String> {
        ensure_non_empty("batch.batch_id", &self.batch_id)?;
        ensure_unique_strings(&self.ticket_ids, "batch.ticket_ids")?;
        ensure_non_empty("batch.ticket_root", &self.ticket_root)?;
        ensure_positive("batch.total_units", self.total_units)?;
        ensure_expiry(
            self.opened_at_height,
            self.sealed_at_height,
            "batch.sealed_at_height",
        )?;
        ensure_expiry(
            self.sealed_at_height,
            self.challenge_deadline_height,
            "batch.challenge_deadline_height",
        )?;
        Ok(aggregator_payload_root(
            "MONERO-EXIT-PROOF-AGGREGATOR-BATCH",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorRecord {
    pub record_id: String,
    pub kind: String,
    pub subject_id: String,
    pub batch_id: String,
    pub payload_root: String,
    pub evidence_root: String,
    pub status: String,
    pub height: u64,
}

impl AggregatorRecord {
    pub fn new(
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        batch_id: impl Into<String>,
        payload_root: impl Into<String>,
        evidence_root: impl Into<String>,
        status: impl Into<String>,
        height: u64,
    ) -> MoneroExitProofAggregatorResult<Self> {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let batch_id = batch_id.into();
        let payload_root = payload_root.into();
        let evidence_root = evidence_root.into();
        let status = status.into();
        let record_id = aggregator_record_id(
            &kind,
            &subject_id,
            &batch_id,
            &payload_root,
            &evidence_root,
            height,
        );
        let record = Self {
            record_id,
            kind,
            subject_id,
            batch_id,
            payload_root,
            evidence_root,
            status,
            height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind,
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "batch_id": self.batch_id,
            "payload_root": self.payload_root,
            "evidence_root": self.evidence_root,
            "status": self.status,
            "height": self.height,
        })
    }

    pub fn validate(&self) -> MoneroExitProofAggregatorResult<String> {
        ensure_non_empty("record.record_id", &self.record_id)?;
        ensure_non_empty("record.kind", &self.kind)?;
        ensure_non_empty("record.subject_id", &self.subject_id)?;
        ensure_non_empty("record.payload_root", &self.payload_root)?;
        ensure_non_empty("record.evidence_root", &self.evidence_root)?;
        ensure_non_empty("record.status", &self.status)?;
        Ok(aggregator_payload_root(
            "MONERO-EXIT-PROOF-AGGREGATOR-RECORD",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitProofAggregatorState {
    pub height: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub config: MoneroExitProofAggregatorConfig,
    pub tickets: BTreeMap<String, ExitProofTicket>,
    pub batches: BTreeMap<String, AggregationBatch>,
    pub stealth_payout_proofs: BTreeMap<String, AggregatorRecord>,
    pub range_proof_aggregates: BTreeMap<String, AggregatorRecord>,
    pub key_image_evidence: BTreeMap<String, AggregatorRecord>,
    pub pq_attestations: BTreeMap<String, AggregatorRecord>,
    pub settlement_certificates: BTreeMap<String, AggregatorRecord>,
    pub finality_windows: BTreeMap<String, AggregatorRecord>,
    pub sponsorships: BTreeMap<String, AggregatorRecord>,
    pub challenges: BTreeMap<String, AggregatorRecord>,
    pub events: BTreeMap<String, AggregatorRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl MoneroExitProofAggregatorState {
    pub fn devnet() -> MoneroExitProofAggregatorResult<Self> {
        let config = MoneroExitProofAggregatorConfig::devnet();
        config.validate()?;
        let mut state = Self {
            height: MONERO_EXIT_PROOF_AGGREGATOR_DEVNET_HEIGHT,
            monero_network: config.monero_network.clone(),
            l2_network: config.l2_network.clone(),
            asset_id: config.asset_id.clone(),
            fee_asset_id: config.fee_asset_id.clone(),
            config,
            tickets: BTreeMap::new(),
            batches: BTreeMap::new(),
            stealth_payout_proofs: BTreeMap::new(),
            range_proof_aggregates: BTreeMap::new(),
            key_image_evidence: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_certificates: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            events: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.seed_devnet_records()?;
        state.refresh_public_records();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroExitProofAggregatorResult<()> {
        if height < self.height {
            return Err("aggregator height cannot move backwards".to_string());
        }
        self.height = height;
        self.refresh_public_records();
        Ok(())
    }

    pub fn roots(&self) -> MoneroExitProofAggregatorRoots {
        MoneroExitProofAggregatorRoots {
            config_root: aggregator_payload_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-CONFIG",
                &self.config.public_record(),
            ),
            ticket_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-TICKET-SET",
                &self.tickets,
                ExitProofTicket::public_record,
            ),
            stealth_payout_proof_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-STEALTH-PAYOUT-SET",
                &self.stealth_payout_proofs,
                AggregatorRecord::public_record,
            ),
            range_proof_aggregate_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-RANGE-PROOF-SET",
                &self.range_proof_aggregates,
                AggregatorRecord::public_record,
            ),
            key_image_evidence_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-KEY-IMAGE-SET",
                &self.key_image_evidence,
                AggregatorRecord::public_record,
            ),
            pq_attestation_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-PQ-ATTESTATION-SET",
                &self.pq_attestations,
                AggregatorRecord::public_record,
            ),
            batch_certificate_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-CERTIFICATE-SET",
                &self.settlement_certificates,
                AggregatorRecord::public_record,
            ),
            finality_window_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-FINALITY-SET",
                &self.finality_windows,
                AggregatorRecord::public_record,
            ),
            sponsorship_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-SPONSORSHIP-SET",
                &self.sponsorships,
                AggregatorRecord::public_record,
            ),
            challenge_root: map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-CHALLENGE-SET",
                &self.challenges,
                AggregatorRecord::public_record,
            ),
            public_record_root: value_map_root(
                "MONERO-EXIT-PROOF-AGGREGATOR-PUBLIC-RECORD-SET",
                &self.public_records,
            ),
        }
    }

    pub fn counters(&self) -> MoneroExitProofAggregatorCounters {
        MoneroExitProofAggregatorCounters {
            ticket_count: self.tickets.len() as u64,
            live_ticket_count: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.is_live())
                .count() as u64,
            batch_count: self.batches.len() as u64,
            live_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status.is_live())
                .count() as u64,
            stealth_payout_proof_count: self.stealth_payout_proofs.len() as u64,
            range_proof_aggregate_count: self.range_proof_aggregates.len() as u64,
            key_image_evidence_count: self.key_image_evidence.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            settlement_certificate_count: self.settlement_certificates.len() as u64,
            finality_window_count: self.finality_windows.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            challenge_count: self.challenges.len() as u64,
            event_count: self.events.len() as u64,
            pending_exit_units: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.is_live())
                .map(|ticket| ticket.amount_units)
                .sum(),
            aggregated_exit_units: self.batches.values().map(|batch| batch.total_units).sum(),
            sponsored_fee_units: self
                .sponsorships
                .values()
                .filter(|record| record.status == SponsorshipStatus::Applied.as_str())
                .count() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_exit_proof_aggregator_state",
            "chain_id": CHAIN_ID,
            "protocol_label": MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_LABEL,
            "protocol_version": MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_VERSION,
            "schema_version": MONERO_EXIT_PROOF_AGGREGATOR_SCHEMA_VERSION,
            "height": self.height,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        monero_exit_proof_aggregator_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> MoneroExitProofAggregatorResult<String> {
        self.config.validate()?;
        if self.monero_network != self.config.monero_network {
            return Err("aggregator monero network differs from config".to_string());
        }
        if self.l2_network != self.config.l2_network {
            return Err("aggregator l2 network differs from config".to_string());
        }
        if self.asset_id != self.config.asset_id {
            return Err("aggregator asset differs from config".to_string());
        }
        if self.fee_asset_id != self.config.fee_asset_id {
            return Err("aggregator fee asset differs from config".to_string());
        }
        for ticket in self.tickets.values() {
            ticket.validate()?;
            if !ticket.batch_id.is_empty() && !self.batches.contains_key(&ticket.batch_id) {
                return Err(format!(
                    "ticket {} points to missing batch",
                    ticket.ticket_id
                ));
            }
        }
        for batch in self.batches.values() {
            batch.validate()?;
            if batch.ticket_ids.len() > self.config.max_tickets_per_batch {
                return Err("batch exceeds ticket limit".to_string());
            }
            if batch.total_units > self.config.max_batch_units {
                return Err("batch exceeds unit limit".to_string());
            }
            for ticket_id in &batch.ticket_ids {
                let ticket = self
                    .tickets
                    .get(ticket_id)
                    .ok_or_else(|| format!("batch points to missing ticket {}", ticket_id))?;
                if ticket.batch_id != batch.batch_id {
                    return Err(format!(
                        "batch reverse link mismatch for ticket {}",
                        ticket_id
                    ));
                }
            }
        }
        validate_record_map("stealth_payout", &self.stealth_payout_proofs)?;
        validate_record_map("range_proof", &self.range_proof_aggregates)?;
        validate_record_map("key_image", &self.key_image_evidence)?;
        validate_record_map("pq_attestation", &self.pq_attestations)?;
        validate_record_map("certificate", &self.settlement_certificates)?;
        validate_record_map("finality", &self.finality_windows)?;
        validate_record_map("sponsorship", &self.sponsorships)?;
        validate_record_map("challenge", &self.challenges)?;
        validate_record_map("event", &self.events)?;
        Ok(self.state_root())
    }

    fn seed_devnet_records(&mut self) -> MoneroExitProofAggregatorResult<()> {
        let mut ticket = ExitProofTicket::new(
            "devnet-exit-ticket-0",
            deterministic_commitment("devnet-exit-owner-0"),
            25_000,
            3,
            deterministic_root("devnet-nullifier-set-0"),
            deterministic_root("devnet-stealth-payout-0"),
            deterministic_root("devnet-range-proof-0"),
            deterministic_root("devnet-key-image-0"),
            700,
            self.height,
            self.height.saturating_add(48),
        )?;
        let batch = AggregationBatch::new(
            0,
            vec![ticket.ticket_id.clone()],
            ticket.amount_units,
            ticket.fee_units,
            self.height,
            &self.config,
        )?;
        ticket.batch_id = batch.batch_id.clone();
        ticket.status = ExitProofTicketStatus::Aggregating;

        let batch_id = batch.batch_id.clone();
        let ticket_id = ticket.ticket_id.clone();
        self.tickets.insert(ticket_id.clone(), ticket);
        self.batches.insert(batch_id.clone(), batch);

        self.insert_record(
            "stealth_payout_proof",
            &ticket_id,
            &batch_id,
            "devnet-stealth-payout-proof",
            "accepted",
        )?;
        self.insert_record(
            "range_proof_aggregate",
            &batch_id,
            &batch_id,
            "devnet-range-proof-aggregate",
            "accepted",
        )?;
        self.insert_record(
            "key_image_non_linkability",
            &ticket_id,
            &batch_id,
            "devnet-key-image-evidence",
            "accepted",
        )?;
        self.insert_record(
            "pq_aggregator_attestation",
            "devnet-aggregator-quorum",
            &batch_id,
            "devnet-pq-attestation",
            "accepted",
        )?;
        self.insert_record(
            "batch_settlement_certificate",
            &batch_id,
            &batch_id,
            "devnet-settlement-certificate",
            "ready",
        )?;
        self.insert_record(
            "reorg_safe_finality_window",
            &batch_id,
            &batch_id,
            "devnet-finality-window",
            "tracking",
        )?;
        self.insert_record(
            "low_fee_sponsorship",
            &ticket_id,
            &batch_id,
            "devnet-low-fee-sponsorship",
            SponsorshipStatus::Applied.as_str(),
        )?;
        self.insert_record(
            "challenge_window",
            &batch_id,
            &batch_id,
            "devnet-challenge-window",
            "open",
        )?;
        self.insert_record(
            "aggregator_event",
            &batch_id,
            &batch_id,
            "devnet-event-log",
            "recorded",
        )?;
        Ok(())
    }

    fn insert_record(
        &mut self,
        kind: &str,
        subject_id: &str,
        batch_id: &str,
        seed: &str,
        status: &str,
    ) -> MoneroExitProofAggregatorResult<String> {
        let record = AggregatorRecord::new(
            kind,
            subject_id,
            batch_id,
            deterministic_root(seed),
            deterministic_root(&format!("{seed}-evidence")),
            status,
            self.height,
        )?;
        let record_id = record.record_id.clone();
        match kind {
            "stealth_payout_proof" => {
                self.stealth_payout_proofs.insert(record_id.clone(), record);
            }
            "range_proof_aggregate" => {
                self.range_proof_aggregates
                    .insert(record_id.clone(), record);
            }
            "key_image_non_linkability" => {
                self.key_image_evidence.insert(record_id.clone(), record);
            }
            "pq_aggregator_attestation" => {
                self.pq_attestations.insert(record_id.clone(), record);
            }
            "batch_settlement_certificate" => {
                self.settlement_certificates
                    .insert(record_id.clone(), record);
            }
            "reorg_safe_finality_window" => {
                self.finality_windows.insert(record_id.clone(), record);
            }
            "low_fee_sponsorship" => {
                self.sponsorships.insert(record_id.clone(), record);
            }
            "challenge_window" => {
                self.challenges.insert(record_id.clone(), record);
            }
            _ => {
                self.events.insert(record_id.clone(), record);
            }
        }
        Ok(record_id)
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        insert_records(
            &mut self.public_records,
            "ticket",
            &self.tickets,
            ExitProofTicket::public_record,
        );
        insert_records(
            &mut self.public_records,
            "batch",
            &self.batches,
            AggregationBatch::public_record,
        );
        insert_records(
            &mut self.public_records,
            "stealth_payout_proof",
            &self.stealth_payout_proofs,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "range_proof_aggregate",
            &self.range_proof_aggregates,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "key_image_evidence",
            &self.key_image_evidence,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "pq_attestation",
            &self.pq_attestations,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "settlement_certificate",
            &self.settlement_certificates,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "finality_window",
            &self.finality_windows,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "sponsorship",
            &self.sponsorships,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "challenge",
            &self.challenges,
            AggregatorRecord::public_record,
        );
        insert_records(
            &mut self.public_records,
            "event",
            &self.events,
            AggregatorRecord::public_record,
        );
    }
}

pub fn monero_exit_proof_aggregator_state_root_from_record(record: &serde_json::Value) -> String {
    aggregator_payload_root("MONERO-EXIT-PROOF-AGGREGATOR-STATE", record)
}

#[allow(clippy::too_many_arguments)]
pub fn exit_proof_ticket_id(
    exit_id: &str,
    owner_commitment: &str,
    amount_units: u64,
    nullifier_root: &str,
    stealth_payout_root: &str,
    range_proof_root: &str,
    key_image_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-PROOF-AGGREGATOR-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(exit_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(amount_units as i128),
            HashPart::Str(nullifier_root),
            HashPart::Str(stealth_payout_root),
            HashPart::Str(range_proof_root),
            HashPart::Str(key_image_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn aggregation_batch_id(
    sequence: u64,
    ticket_root: &str,
    total_units: u64,
    total_fee_units: u64,
    opened_at_height: u64,
    challenge_deadline_height: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-PROOF-AGGREGATOR-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(ticket_root),
            HashPart::Int(total_units as i128),
            HashPart::Int(total_fee_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(challenge_deadline_height as i128),
        ],
        32,
    )
}

pub fn aggregator_record_id(
    kind: &str,
    subject_id: &str,
    batch_id: &str,
    payload_root: &str,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-PROOF-AGGREGATOR-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(batch_id),
            HashPart::Str(payload_root),
            HashPart::Str(evidence_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn aggregator_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_LABEL),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn deterministic_root(seed: &str) -> String {
    domain_hash(
        "MONERO-EXIT-PROOF-AGGREGATOR-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_LABEL),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn deterministic_commitment(seed: &str) -> String {
    domain_hash(
        "MONERO-EXIT-PROOF-AGGREGATOR-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_EXIT_PROOF_AGGREGATOR_PROTOCOL_LABEL),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values
        .iter()
        .map(|(id, value)| {
            json!({
                "id": id,
                "record": record_fn(value),
            })
        })
        .collect::<Vec<_>>();
    aggregator_payload_root(domain, &json!(records))
}

fn value_map_root(domain: &str, values: &BTreeMap<String, Value>) -> String {
    let records = values
        .iter()
        .map(|(id, value)| {
            json!({
                "id": id,
                "record": value,
            })
        })
        .collect::<Vec<_>>();
    aggregator_payload_root(domain, &json!(records))
}

fn string_list_root(domain: &str, values: &[String]) -> String {
    aggregator_payload_root(domain, &json!(values))
}

fn insert_records<T, F>(
    public_records: &mut BTreeMap<String, Value>,
    prefix: &str,
    values: &BTreeMap<String, T>,
    record_fn: F,
) where
    F: Fn(&T) -> Value,
{
    for (id, value) in values {
        public_records.insert(format!("{prefix}:{id}"), record_fn(value));
    }
}

fn validate_record_map(
    label: &str,
    values: &BTreeMap<String, AggregatorRecord>,
) -> MoneroExitProofAggregatorResult<()> {
    for (id, record) in values {
        ensure_non_empty(label, id)?;
        let root = record.validate()?;
        ensure_non_empty(label, &root)?;
    }
    Ok(())
}

fn ensure_non_empty(label: &str, value: &str) -> MoneroExitProofAggregatorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> MoneroExitProofAggregatorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_usize_positive(label: &str, value: usize) -> MoneroExitProofAggregatorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> MoneroExitProofAggregatorResult<()> {
    if value > MONERO_EXIT_PROOF_AGGREGATOR_MAX_BPS {
        return Err(format!("{label} exceeds basis point maximum"));
    }
    Ok(())
}

fn ensure_expiry(
    start_height: u64,
    expires_at_height: u64,
    label: &str,
) -> MoneroExitProofAggregatorResult<()> {
    if expires_at_height <= start_height {
        return Err(format!("{label} must be after start height"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> MoneroExitProofAggregatorResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate values"));
        }
    }
    Ok(())
}
