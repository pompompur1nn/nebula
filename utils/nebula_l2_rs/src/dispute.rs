use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DisputeResult<T> = Result<T, String>;

pub const DISPUTE_PROTOCOL_VERSION: u64 = 1;
pub const DISPUTE_DEFAULT_RESPONSE_WINDOW_BLOCKS: u64 = 20;
pub const DISPUTE_DEFAULT_ADJUDICATION_WINDOW_BLOCKS: u64 = 40;
pub const DISPUTE_DEFAULT_CHALLENGE_BOND_UNITS: u64 = 1_000;
pub const DISPUTE_MIN_CHALLENGE_BOND_UNITS: u64 = 100;
pub const DISPUTE_MAX_EVIDENCE_ITEMS: usize = 128;
pub const DISPUTE_MAX_MANIFEST_ENTRIES: usize = 128;
pub const DISPUTE_DEFAULT_BOND_ASSET_ID: &str = "dxmr";
pub const DISPUTE_STATUS_OPEN: &str = "open";
pub const DISPUTE_STATUS_RESPONDED: &str = "responded";
pub const DISPUTE_STATUS_RESPONSE_EXPIRED: &str = "response_expired";
pub const DISPUTE_STATUS_ADJUDICATED: &str = "adjudicated";
pub const DISPUTE_STATUS_REJECTED: &str = "rejected";
pub const DISPUTE_STATUS_CANCELLED: &str = "cancelled";
pub const DISPUTE_BOND_STATUS_LOCKED: &str = "locked";
pub const DISPUTE_BOND_STATUS_PARTIALLY_SLASHED: &str = "partially_slashed";
pub const DISPUTE_BOND_STATUS_SLASHED: &str = "slashed";
pub const DISPUTE_BOND_STATUS_REFUNDED: &str = "refunded";
pub const DISPUTE_BOND_STATUS_CLOSED: &str = "closed";
pub const DISPUTE_WINDOW_STATUS_OPEN: &str = "open";
pub const DISPUTE_WINDOW_STATUS_RESPONDED: &str = "responded";
pub const DISPUTE_WINDOW_STATUS_EXPIRED: &str = "expired";
pub const DISPUTE_WINDOW_STATUS_CLOSED: &str = "closed";
pub const DISPUTE_RESPONSE_KIND_DENIAL: &str = "denial";
pub const DISPUTE_RESPONSE_KIND_CONCESSION: &str = "concession";
pub const DISPUTE_RESPONSE_KIND_COUNTER_EVIDENCE: &str = "counter_evidence";
pub const DISPUTE_RECORD_STATUS_PENDING: &str = "pending";
pub const DISPUTE_RECORD_STATUS_APPLIED: &str = "applied";
pub const DISPUTE_RECORD_STATUS_REJECTED: &str = "rejected";
pub const DISPUTE_MANIFEST_STATUS_OPEN: &str = "open";
pub const DISPUTE_MANIFEST_STATUS_CONSUMED: &str = "consumed";
pub const DISPUTE_MANIFEST_STATUS_EXPIRED: &str = "expired";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    InvalidStateTransition,
    DataAvailabilityWithholding,
    InvalidBridgeRelease,
    OracleManipulation,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::DataAvailabilityWithholding => "data_availability_withholding",
            Self::InvalidBridgeRelease => "invalid_bridge_release",
            Self::OracleManipulation => "oracle_manipulation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeOutcome {
    ChallengerWins,
    ChallengerLoses,
    TimedOut,
    Settled,
}

impl DisputeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChallengerWins => "challenger_wins",
            Self::ChallengerLoses => "challenger_loses",
            Self::TimedOut => "timed_out",
            Self::Settled => "settled",
        }
    }

    pub fn case_status(self) -> &'static str {
        match self {
            Self::ChallengerWins | Self::TimedOut | Self::Settled => DISPUTE_STATUS_ADJUDICATED,
            Self::ChallengerLoses => DISPUTE_STATUS_REJECTED,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidStateTransitionClaim {
    pub claim_id: String,
    pub batch_id: String,
    pub receipt_id: String,
    pub transition_index: u64,
    pub previous_state_root: String,
    pub asserted_post_state_root: String,
    pub computed_post_state_root: String,
    pub state_write_root: String,
    pub receipt_root: String,
    pub execution_trace_root: String,
    pub proof_system: String,
    pub opened_at_height: u64,
}

impl InvalidStateTransitionClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        receipt_id: impl Into<String>,
        transition_index: u64,
        previous_state_root: impl Into<String>,
        asserted_post_state_root: impl Into<String>,
        computed_post_state_root: impl Into<String>,
        state_write_root: impl Into<String>,
        receipt_root: impl Into<String>,
        execution_trace_root: impl Into<String>,
        proof_system: impl Into<String>,
        opened_at_height: u64,
    ) -> DisputeResult<Self> {
        let mut claim = Self {
            claim_id: String::new(),
            batch_id: batch_id.into(),
            receipt_id: receipt_id.into(),
            transition_index,
            previous_state_root: previous_state_root.into(),
            asserted_post_state_root: asserted_post_state_root.into(),
            computed_post_state_root: computed_post_state_root.into(),
            state_write_root: state_write_root.into(),
            receipt_root: receipt_root.into(),
            execution_trace_root: execution_trace_root.into(),
            proof_system: proof_system.into(),
            opened_at_height,
        };
        claim.claim_id = invalid_state_transition_claim_id(
            &claim.batch_id,
            &claim.receipt_id,
            claim.transition_index,
            &claim.previous_state_root,
            &claim.asserted_post_state_root,
            &claim.computed_post_state_root,
            &claim.state_write_root,
            &claim.receipt_root,
        );
        claim.validate()?;
        Ok(claim)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invalid_state_transition_claim",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "transition_index": self.transition_index,
            "previous_state_root": self.previous_state_root,
            "asserted_post_state_root": self.asserted_post_state_root,
            "computed_post_state_root": self.computed_post_state_root,
            "state_write_root": self.state_write_root,
            "receipt_root": self.receipt_root,
            "execution_trace_root": self.execution_trace_root,
            "proof_system": self.proof_system,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn claim_root(&self) -> String {
        dispute_payload_root("DISPUTE-INVALID-STATE-TRANSITION", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.batch_id, "invalid state transition batch id")?;
        ensure_non_empty(&self.receipt_id, "invalid state transition receipt id")?;
        ensure_non_empty(
            &self.previous_state_root,
            "invalid state transition previous state root",
        )?;
        ensure_non_empty(
            &self.asserted_post_state_root,
            "invalid state transition asserted post state root",
        )?;
        ensure_non_empty(
            &self.computed_post_state_root,
            "invalid state transition computed post state root",
        )?;
        ensure_non_empty(
            &self.state_write_root,
            "invalid state transition state write root",
        )?;
        ensure_non_empty(&self.receipt_root, "invalid state transition receipt root")?;
        ensure_non_empty(
            &self.execution_trace_root,
            "invalid state transition execution trace root",
        )?;
        ensure_non_empty(&self.proof_system, "invalid state transition proof system")?;
        if self.asserted_post_state_root == self.computed_post_state_root {
            return Err(
                "invalid state transition claim requires a post-state mismatch".to_string(),
            );
        }
        if self.claim_id
            != invalid_state_transition_claim_id(
                &self.batch_id,
                &self.receipt_id,
                self.transition_index,
                &self.previous_state_root,
                &self.asserted_post_state_root,
                &self.computed_post_state_root,
                &self.state_write_root,
                &self.receipt_root,
            )
        {
            return Err("invalid state transition claim id mismatch".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaWithholdingClaim {
    pub claim_id: String,
    pub batch_id: String,
    pub da_reference_id: String,
    pub namespace: String,
    pub payload_hash: String,
    pub shard_commitment_root: String,
    pub unavailable_shard_indices: Vec<u64>,
    pub sample_challenge_root: String,
    pub sampling_response_root: String,
    pub attestation_root: String,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
}

impl DaWithholdingClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        da_reference_id: impl Into<String>,
        namespace: impl Into<String>,
        payload_hash: impl Into<String>,
        shard_commitment_root: impl Into<String>,
        unavailable_shard_indices: Vec<u64>,
        sample_challenge_root: impl Into<String>,
        sampling_response_root: impl Into<String>,
        attestation_root: impl Into<String>,
        opened_at_height: u64,
        response_deadline_height: u64,
    ) -> DisputeResult<Self> {
        let mut claim = Self {
            claim_id: String::new(),
            batch_id: batch_id.into(),
            da_reference_id: da_reference_id.into(),
            namespace: namespace.into(),
            payload_hash: payload_hash.into(),
            shard_commitment_root: shard_commitment_root.into(),
            unavailable_shard_indices,
            sample_challenge_root: sample_challenge_root.into(),
            sampling_response_root: sampling_response_root.into(),
            attestation_root: attestation_root.into(),
            opened_at_height,
            response_deadline_height,
        };
        claim.claim_id = da_withholding_claim_id(
            &claim.batch_id,
            &claim.da_reference_id,
            &claim.namespace,
            &claim.payload_hash,
            &claim.shard_commitment_root,
            &claim.unavailable_shard_indices,
            &claim.sample_challenge_root,
        );
        claim.validate()?;
        Ok(claim)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_withholding_claim",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "batch_id": self.batch_id,
            "da_reference_id": self.da_reference_id,
            "namespace": self.namespace,
            "payload_hash": self.payload_hash,
            "shard_commitment_root": self.shard_commitment_root,
            "unavailable_shard_indices": self.unavailable_shard_indices,
            "sample_challenge_root": self.sample_challenge_root,
            "sampling_response_root": self.sampling_response_root,
            "attestation_root": self.attestation_root,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
        })
    }

    pub fn claim_root(&self) -> String {
        dispute_payload_root("DISPUTE-DA-WITHHOLDING", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.batch_id, "DA withholding batch id")?;
        ensure_non_empty(&self.da_reference_id, "DA withholding reference id")?;
        ensure_non_empty(&self.namespace, "DA withholding namespace")?;
        ensure_non_empty(&self.payload_hash, "DA withholding payload hash")?;
        ensure_non_empty(
            &self.shard_commitment_root,
            "DA withholding shard commitment root",
        )?;
        ensure_non_empty(
            &self.sample_challenge_root,
            "DA withholding sample challenge root",
        )?;
        ensure_non_empty(
            &self.sampling_response_root,
            "DA withholding sampling response root",
        )?;
        ensure_non_empty(&self.attestation_root, "DA withholding attestation root")?;
        if self.unavailable_shard_indices.is_empty() {
            return Err("DA withholding claim requires unavailable shard indices".to_string());
        }
        ensure_unique_u64(
            &self.unavailable_shard_indices,
            "DA withholding unavailable shard index",
        )?;
        if self.response_deadline_height <= self.opened_at_height {
            return Err("DA withholding response deadline must be after opening".to_string());
        }
        if self.claim_id
            != da_withholding_claim_id(
                &self.batch_id,
                &self.da_reference_id,
                &self.namespace,
                &self.payload_hash,
                &self.shard_commitment_root,
                &self.unavailable_shard_indices,
                &self.sample_challenge_root,
            )
        {
            return Err("DA withholding claim id mismatch".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidBridgeReleaseClaim {
    pub claim_id: String,
    pub withdrawal_id: String,
    pub release_monero_txid_hash: String,
    pub expected_amount: u64,
    pub observed_amount: u64,
    pub expected_recipient_hash: String,
    pub observed_recipient_hash: String,
    pub signer_set_id: String,
    pub release_signature_root: String,
    pub reserve_report_root: String,
    pub released_at_height: u64,
    pub opened_at_height: u64,
}

impl InvalidBridgeReleaseClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        release_monero_txid_hash: impl Into<String>,
        expected_amount: u64,
        observed_amount: u64,
        expected_recipient_hash: impl Into<String>,
        observed_recipient_hash: impl Into<String>,
        signer_set_id: impl Into<String>,
        release_signature_root: impl Into<String>,
        reserve_report_root: impl Into<String>,
        released_at_height: u64,
        opened_at_height: u64,
    ) -> DisputeResult<Self> {
        let mut claim = Self {
            claim_id: String::new(),
            withdrawal_id: withdrawal_id.into(),
            release_monero_txid_hash: release_monero_txid_hash.into(),
            expected_amount,
            observed_amount,
            expected_recipient_hash: expected_recipient_hash.into(),
            observed_recipient_hash: observed_recipient_hash.into(),
            signer_set_id: signer_set_id.into(),
            release_signature_root: release_signature_root.into(),
            reserve_report_root: reserve_report_root.into(),
            released_at_height,
            opened_at_height,
        };
        claim.claim_id = invalid_bridge_release_claim_id(
            &claim.withdrawal_id,
            &claim.release_monero_txid_hash,
            claim.expected_amount,
            claim.observed_amount,
            &claim.expected_recipient_hash,
            &claim.observed_recipient_hash,
            &claim.release_signature_root,
        );
        claim.validate()?;
        Ok(claim)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invalid_bridge_release_claim",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "withdrawal_id": self.withdrawal_id,
            "release_monero_txid_hash": self.release_monero_txid_hash,
            "expected_amount": self.expected_amount,
            "observed_amount": self.observed_amount,
            "expected_recipient_hash": self.expected_recipient_hash,
            "observed_recipient_hash": self.observed_recipient_hash,
            "signer_set_id": self.signer_set_id,
            "release_signature_root": self.release_signature_root,
            "reserve_report_root": self.reserve_report_root,
            "released_at_height": self.released_at_height,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn claim_root(&self) -> String {
        dispute_payload_root("DISPUTE-INVALID-BRIDGE-RELEASE", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.withdrawal_id, "invalid bridge release withdrawal id")?;
        ensure_non_empty(
            &self.release_monero_txid_hash,
            "invalid bridge release txid hash",
        )?;
        ensure_non_empty(
            &self.expected_recipient_hash,
            "invalid bridge release expected recipient hash",
        )?;
        ensure_non_empty(
            &self.observed_recipient_hash,
            "invalid bridge release observed recipient hash",
        )?;
        ensure_non_empty(&self.signer_set_id, "invalid bridge release signer set id")?;
        ensure_non_empty(
            &self.release_signature_root,
            "invalid bridge release signature root",
        )?;
        ensure_non_empty(
            &self.reserve_report_root,
            "invalid bridge release reserve report root",
        )?;
        if self.expected_amount == 0 || self.observed_amount == 0 {
            return Err("invalid bridge release amounts must be positive".to_string());
        }
        if self.expected_amount == self.observed_amount
            && self.expected_recipient_hash == self.observed_recipient_hash
        {
            return Err(
                "invalid bridge release claim requires amount or recipient mismatch".to_string(),
            );
        }
        if self.claim_id
            != invalid_bridge_release_claim_id(
                &self.withdrawal_id,
                &self.release_monero_txid_hash,
                self.expected_amount,
                self.observed_amount,
                &self.expected_recipient_hash,
                &self.observed_recipient_hash,
                &self.release_signature_root,
            )
        {
            return Err("invalid bridge release claim id mismatch".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleManipulationClaim {
    pub claim_id: String,
    pub feed_id: String,
    pub aggregate_id: String,
    pub disputed_round: u64,
    pub reported_price: u64,
    pub reference_price: u64,
    pub deviation_bps: u64,
    pub max_deviation_bps: u64,
    pub observation_root: String,
    pub source_weight_root: String,
    pub reference_source_root: String,
    pub opened_at_height: u64,
}

impl OracleManipulationClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feed_id: impl Into<String>,
        aggregate_id: impl Into<String>,
        disputed_round: u64,
        reported_price: u64,
        reference_price: u64,
        max_deviation_bps: u64,
        observation_root: impl Into<String>,
        source_weight_root: impl Into<String>,
        reference_source_root: impl Into<String>,
        opened_at_height: u64,
    ) -> DisputeResult<Self> {
        let feed_id = feed_id.into();
        let aggregate_id = aggregate_id.into();
        let observation_root = observation_root.into();
        let source_weight_root = source_weight_root.into();
        let reference_source_root = reference_source_root.into();
        let deviation_bps = dispute_price_deviation_bps(reported_price, reference_price);
        let claim_id = oracle_manipulation_claim_id(
            &feed_id,
            &aggregate_id,
            disputed_round,
            reported_price,
            reference_price,
            deviation_bps,
            max_deviation_bps,
            &observation_root,
            &reference_source_root,
        );
        let claim = Self {
            claim_id,
            feed_id,
            aggregate_id,
            disputed_round,
            reported_price,
            reference_price,
            deviation_bps,
            max_deviation_bps,
            observation_root,
            source_weight_root,
            reference_source_root,
            opened_at_height,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_manipulation_claim",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "feed_id": self.feed_id,
            "aggregate_id": self.aggregate_id,
            "disputed_round": self.disputed_round,
            "reported_price": self.reported_price,
            "reference_price": self.reference_price,
            "deviation_bps": self.deviation_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "observation_root": self.observation_root,
            "source_weight_root": self.source_weight_root,
            "reference_source_root": self.reference_source_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn claim_root(&self) -> String {
        dispute_payload_root("DISPUTE-ORACLE-MANIPULATION", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.feed_id, "oracle manipulation feed id")?;
        ensure_non_empty(&self.aggregate_id, "oracle manipulation aggregate id")?;
        ensure_non_empty(
            &self.observation_root,
            "oracle manipulation observation root",
        )?;
        ensure_non_empty(
            &self.source_weight_root,
            "oracle manipulation source weight root",
        )?;
        ensure_non_empty(
            &self.reference_source_root,
            "oracle manipulation reference source root",
        )?;
        if self.reported_price == 0 || self.reference_price == 0 {
            return Err("oracle manipulation prices must be positive".to_string());
        }
        if self.deviation_bps
            != dispute_price_deviation_bps(self.reported_price, self.reference_price)
        {
            return Err("oracle manipulation deviation mismatch".to_string());
        }
        if self.deviation_bps <= self.max_deviation_bps {
            return Err(
                "oracle manipulation claim does not exceed deviation threshold".to_string(),
            );
        }
        if self.claim_id
            != oracle_manipulation_claim_id(
                &self.feed_id,
                &self.aggregate_id,
                self.disputed_round,
                self.reported_price,
                self.reference_price,
                self.deviation_bps,
                self.max_deviation_bps,
                &self.observation_root,
                &self.reference_source_root,
            )
        {
            return Err("oracle manipulation claim id mismatch".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_kind", content = "claim", rename_all = "snake_case")]
pub enum DisputeClaim {
    InvalidStateTransition(InvalidStateTransitionClaim),
    DataAvailabilityWithholding(DaWithholdingClaim),
    InvalidBridgeRelease(InvalidBridgeReleaseClaim),
    OracleManipulation(OracleManipulationClaim),
}

impl DisputeClaim {
    pub fn dispute_kind(&self) -> DisputeKind {
        match self {
            Self::InvalidStateTransition(_) => DisputeKind::InvalidStateTransition,
            Self::DataAvailabilityWithholding(_) => DisputeKind::DataAvailabilityWithholding,
            Self::InvalidBridgeRelease(_) => DisputeKind::InvalidBridgeRelease,
            Self::OracleManipulation(_) => DisputeKind::OracleManipulation,
        }
    }

    pub fn claim_id(&self) -> &str {
        match self {
            Self::InvalidStateTransition(claim) => &claim.claim_id,
            Self::DataAvailabilityWithholding(claim) => &claim.claim_id,
            Self::InvalidBridgeRelease(claim) => &claim.claim_id,
            Self::OracleManipulation(claim) => &claim.claim_id,
        }
    }

    pub fn subject_id(&self) -> &str {
        match self {
            Self::InvalidStateTransition(claim) => &claim.batch_id,
            Self::DataAvailabilityWithholding(claim) => &claim.batch_id,
            Self::InvalidBridgeRelease(claim) => &claim.withdrawal_id,
            Self::OracleManipulation(claim) => &claim.aggregate_id,
        }
    }

    pub fn public_record(&self) -> Value {
        match self {
            Self::InvalidStateTransition(claim) => claim.public_record(),
            Self::DataAvailabilityWithholding(claim) => claim.public_record(),
            Self::InvalidBridgeRelease(claim) => claim.public_record(),
            Self::OracleManipulation(claim) => claim.public_record(),
        }
    }

    pub fn claim_root(&self) -> String {
        dispute_claim_root(self)
    }

    pub fn validate(&self) -> DisputeResult<String> {
        match self {
            Self::InvalidStateTransition(claim) => claim.validate(),
            Self::DataAvailabilityWithholding(claim) => claim.validate(),
            Self::InvalidBridgeRelease(claim) => claim.validate(),
            Self::OracleManipulation(claim) => claim.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeEvidenceItem {
    pub evidence_id: String,
    pub evidence_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub metadata_root: String,
    pub source_commitment: String,
}

impl DisputeEvidenceItem {
    pub fn new(
        evidence_kind: impl Into<String>,
        subject_id: impl Into<String>,
        payload: &Value,
        metadata: &Value,
        source_commitment: impl Into<String>,
    ) -> DisputeResult<Self> {
        let evidence_kind = evidence_kind.into();
        let subject_id = subject_id.into();
        let payload_root = dispute_payload_root("DISPUTE-EVIDENCE-PAYLOAD", payload);
        let metadata_root = dispute_payload_root("DISPUTE-EVIDENCE-METADATA", metadata);
        let source_commitment = source_commitment.into();
        let evidence_id = dispute_evidence_item_id(
            &evidence_kind,
            &subject_id,
            &payload_root,
            &metadata_root,
            &source_commitment,
        );
        let item = Self {
            evidence_id,
            evidence_kind,
            subject_id,
            payload_root,
            metadata_root,
            source_commitment,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_evidence_item",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "metadata_root": self.metadata_root,
            "source_commitment": self.source_commitment,
        })
    }

    pub fn evidence_root(&self) -> String {
        dispute_payload_root("DISPUTE-EVIDENCE-ITEM", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.evidence_kind, "dispute evidence kind")?;
        ensure_non_empty(&self.subject_id, "dispute evidence subject id")?;
        ensure_non_empty(&self.payload_root, "dispute evidence payload root")?;
        ensure_non_empty(&self.metadata_root, "dispute evidence metadata root")?;
        ensure_non_empty(
            &self.source_commitment,
            "dispute evidence source commitment",
        )?;
        if self.evidence_id
            != dispute_evidence_item_id(
                &self.evidence_kind,
                &self.subject_id,
                &self.payload_root,
                &self.metadata_root,
                &self.source_commitment,
            )
        {
            return Err("dispute evidence item id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeEvidencePacket {
    pub packet_id: String,
    pub dispute_kind: DisputeKind,
    pub subject_id: String,
    pub packet_label: String,
    pub submitter_commitment: String,
    pub submitted_at_height: u64,
    pub item_root: String,
    pub items: Vec<DisputeEvidenceItem>,
}

impl DisputeEvidencePacket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute_kind: DisputeKind,
        subject_id: impl Into<String>,
        packet_label: impl Into<String>,
        submitter_commitment: impl Into<String>,
        submitted_at_height: u64,
        items: Vec<DisputeEvidenceItem>,
    ) -> DisputeResult<Self> {
        let subject_id = subject_id.into();
        let packet_label = packet_label.into();
        let submitter_commitment = submitter_commitment.into();
        let item_root = dispute_evidence_item_root(&items);
        let packet_id = dispute_evidence_packet_id(
            dispute_kind,
            &subject_id,
            &packet_label,
            &submitter_commitment,
            submitted_at_height,
            &item_root,
        );
        let packet = Self {
            packet_id,
            dispute_kind,
            subject_id,
            packet_label,
            submitter_commitment,
            submitted_at_height,
            item_root,
            items,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn item_records(&self) -> Vec<Value> {
        let mut records = self
            .items
            .iter()
            .map(|item| (item.evidence_id.clone(), item.public_record()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(|(_, record)| record).collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_evidence_packet",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "dispute_kind": self.dispute_kind.as_str(),
            "subject_id": self.subject_id,
            "packet_label": self.packet_label,
            "submitter_commitment": self.submitter_commitment,
            "submitted_at_height": self.submitted_at_height,
            "item_root": self.item_root,
            "items": self.item_records(),
        })
    }

    pub fn packet_root(&self) -> String {
        dispute_payload_root("DISPUTE-EVIDENCE-PACKET", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.subject_id, "dispute evidence packet subject id")?;
        ensure_non_empty(&self.packet_label, "dispute evidence packet label")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "dispute evidence packet submitter commitment",
        )?;
        if self.items.is_empty() {
            return Err("dispute evidence packet requires at least one item".to_string());
        }
        if self.items.len() > DISPUTE_MAX_EVIDENCE_ITEMS {
            return Err("dispute evidence packet item limit exceeded".to_string());
        }
        let mut ids = Vec::with_capacity(self.items.len());
        for item in &self.items {
            item.validate()?;
            if item.subject_id != self.subject_id {
                return Err("dispute evidence item subject mismatch".to_string());
            }
            ids.push(item.evidence_id.clone());
        }
        ensure_unique_strings(&ids, "dispute evidence item id")?;
        if self.item_root != dispute_evidence_item_root(&self.items) {
            return Err("dispute evidence packet item root mismatch".to_string());
        }
        if self.packet_id
            != dispute_evidence_packet_id(
                self.dispute_kind,
                &self.subject_id,
                &self.packet_label,
                &self.submitter_commitment,
                self.submitted_at_height,
                &self.item_root,
            )
        {
            return Err("dispute evidence packet id mismatch".to_string());
        }
        Ok(self.packet_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBond {
    pub bond_id: String,
    pub payer_commitment: String,
    pub asset_id: String,
    pub amount: u64,
    pub nonce: u64,
    pub locked_at_height: u64,
    pub unlock_after_height: u64,
    pub slashed_amount: u64,
    pub refunded_amount: u64,
    pub beneficiary_commitment: String,
    pub status: String,
}

impl ChallengeBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payer_commitment: impl Into<String>,
        asset_id: impl Into<String>,
        amount: u64,
        nonce: u64,
        locked_at_height: u64,
        unlock_after_height: u64,
        beneficiary_commitment: impl Into<String>,
    ) -> DisputeResult<Self> {
        let payer_commitment = payer_commitment.into();
        let asset_id = asset_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let bond_id = challenge_bond_id(
            &payer_commitment,
            &asset_id,
            amount,
            nonce,
            locked_at_height,
            unlock_after_height,
            &beneficiary_commitment,
        );
        let bond = Self {
            bond_id,
            payer_commitment,
            asset_id,
            amount,
            nonce,
            locked_at_height,
            unlock_after_height,
            slashed_amount: 0,
            refunded_amount: 0,
            beneficiary_commitment,
            status: DISPUTE_BOND_STATUS_LOCKED.to_string(),
        };
        bond.validate()?;
        Ok(bond)
    }

    pub fn available_amount(&self) -> u64 {
        self.amount
            .saturating_sub(self.slashed_amount)
            .saturating_sub(self.refunded_amount)
    }

    pub fn apply_slash(&mut self, amount: u64) -> DisputeResult<String> {
        if amount == 0 {
            return Err("challenge bond slash amount must be positive".to_string());
        }
        if amount > self.available_amount() {
            return Err("challenge bond slash exceeds available amount".to_string());
        }
        self.slashed_amount = self.slashed_amount.saturating_add(amount);
        self.refresh_status();
        self.validate()
    }

    pub fn apply_refund(&mut self, amount: u64) -> DisputeResult<String> {
        if amount == 0 {
            return Err("challenge bond refund amount must be positive".to_string());
        }
        if amount > self.available_amount() {
            return Err("challenge bond refund exceeds available amount".to_string());
        }
        self.refunded_amount = self.refunded_amount.saturating_add(amount);
        self.refresh_status();
        self.validate()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_bond",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "bond_id": self.bond_id,
            "payer_commitment": self.payer_commitment,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "nonce": self.nonce,
            "locked_at_height": self.locked_at_height,
            "unlock_after_height": self.unlock_after_height,
            "slashed_amount": self.slashed_amount,
            "refunded_amount": self.refunded_amount,
            "beneficiary_commitment": self.beneficiary_commitment,
            "available_amount": self.available_amount(),
            "status": self.status,
        })
    }

    pub fn bond_root(&self) -> String {
        dispute_payload_root("DISPUTE-CHALLENGE-BOND", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.payer_commitment, "challenge bond payer commitment")?;
        ensure_non_empty(&self.asset_id, "challenge bond asset id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "challenge bond beneficiary commitment",
        )?;
        if self.amount < DISPUTE_MIN_CHALLENGE_BOND_UNITS {
            return Err("challenge bond amount is below minimum".to_string());
        }
        if self.unlock_after_height <= self.locked_at_height {
            return Err("challenge bond unlock height must be after lock height".to_string());
        }
        if self.slashed_amount.saturating_add(self.refunded_amount) > self.amount {
            return Err("challenge bond accounted amount exceeds amount".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DISPUTE_BOND_STATUS_LOCKED,
                DISPUTE_BOND_STATUS_PARTIALLY_SLASHED,
                DISPUTE_BOND_STATUS_SLASHED,
                DISPUTE_BOND_STATUS_REFUNDED,
                DISPUTE_BOND_STATUS_CLOSED,
            ],
            "challenge bond status",
        )?;
        if self.bond_id
            != challenge_bond_id(
                &self.payer_commitment,
                &self.asset_id,
                self.amount,
                self.nonce,
                self.locked_at_height,
                self.unlock_after_height,
                &self.beneficiary_commitment,
            )
        {
            return Err("challenge bond id mismatch".to_string());
        }
        Ok(self.bond_root())
    }

    fn refresh_status(&mut self) {
        let accounted = self.slashed_amount.saturating_add(self.refunded_amount);
        self.status = if self.slashed_amount == self.amount {
            DISPUTE_BOND_STATUS_SLASHED.to_string()
        } else if self.refunded_amount == self.amount {
            DISPUTE_BOND_STATUS_REFUNDED.to_string()
        } else if accounted >= self.amount {
            DISPUTE_BOND_STATUS_CLOSED.to_string()
        } else if self.slashed_amount > 0 {
            DISPUTE_BOND_STATUS_PARTIALLY_SLASHED.to_string()
        } else {
            DISPUTE_BOND_STATUS_LOCKED.to_string()
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeResponseWindow {
    pub window_id: String,
    pub dispute_id: String,
    pub opened_at_height: u64,
    pub response_due_height: u64,
    pub adjudication_due_height: u64,
    pub closed_at_height: u64,
    pub status: String,
}

impl DisputeResponseWindow {
    pub fn new(
        dispute_id: impl Into<String>,
        opened_at_height: u64,
        response_window_blocks: u64,
        adjudication_window_blocks: u64,
    ) -> DisputeResult<Self> {
        if response_window_blocks == 0 {
            return Err("dispute response window must be positive".to_string());
        }
        if adjudication_window_blocks == 0 {
            return Err("dispute adjudication window must be positive".to_string());
        }
        let dispute_id = dispute_id.into();
        let response_due_height = opened_at_height.saturating_add(response_window_blocks);
        let adjudication_due_height =
            response_due_height.saturating_add(adjudication_window_blocks);
        let window_id = dispute_response_window_id(
            &dispute_id,
            opened_at_height,
            response_due_height,
            adjudication_due_height,
        );
        let window = Self {
            window_id,
            dispute_id,
            opened_at_height,
            response_due_height,
            adjudication_due_height,
            closed_at_height: 0,
            status: DISPUTE_WINDOW_STATUS_OPEN.to_string(),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn is_response_open(&self, height: u64) -> bool {
        self.status == DISPUTE_WINDOW_STATUS_OPEN
            && height >= self.opened_at_height
            && height <= self.response_due_height
    }

    pub fn response_expired(&self, height: u64) -> bool {
        height > self.response_due_height && self.status == DISPUTE_WINDOW_STATUS_OPEN
    }

    pub fn adjudication_expired(&self, height: u64) -> bool {
        height > self.adjudication_due_height
    }

    pub fn mark_responded(&mut self, height: u64) -> DisputeResult<String> {
        if !self.is_response_open(height) {
            return Err("dispute response window is not open".to_string());
        }
        self.status = DISPUTE_WINDOW_STATUS_RESPONDED.to_string();
        self.validate()
    }

    pub fn mark_expired(&mut self, height: u64) -> DisputeResult<String> {
        if !self.response_expired(height) {
            return Err("dispute response window has not expired".to_string());
        }
        self.status = DISPUTE_WINDOW_STATUS_EXPIRED.to_string();
        self.validate()
    }

    pub fn mark_closed(&mut self, height: u64) -> DisputeResult<String> {
        if height < self.opened_at_height {
            return Err("dispute response window cannot close before opening".to_string());
        }
        self.closed_at_height = height;
        self.status = DISPUTE_WINDOW_STATUS_CLOSED.to_string();
        self.validate()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_response_window",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "dispute_id": self.dispute_id,
            "opened_at_height": self.opened_at_height,
            "response_due_height": self.response_due_height,
            "adjudication_due_height": self.adjudication_due_height,
            "closed_at_height": self.closed_at_height,
            "status": self.status,
        })
    }

    pub fn window_root(&self) -> String {
        dispute_payload_root("DISPUTE-RESPONSE-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.dispute_id, "dispute response window dispute id")?;
        if self.response_due_height <= self.opened_at_height {
            return Err("dispute response due height must be after opening".to_string());
        }
        if self.adjudication_due_height <= self.response_due_height {
            return Err(
                "dispute adjudication due height must be after response due height".to_string(),
            );
        }
        if self.closed_at_height > 0 && self.closed_at_height < self.opened_at_height {
            return Err("dispute response window closed before opening".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DISPUTE_WINDOW_STATUS_OPEN,
                DISPUTE_WINDOW_STATUS_RESPONDED,
                DISPUTE_WINDOW_STATUS_EXPIRED,
                DISPUTE_WINDOW_STATUS_CLOSED,
            ],
            "dispute response window status",
        )?;
        if self.window_id
            != dispute_response_window_id(
                &self.dispute_id,
                self.opened_at_height,
                self.response_due_height,
                self.adjudication_due_height,
            )
        {
            return Err("dispute response window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeManifestEntry {
    pub entry_id: String,
    pub replay_scope: String,
    pub source_kind: String,
    pub source_id: String,
    pub record_root: String,
    pub nonce: u64,
    pub consumed_at_height: u64,
}

impl DisputeManifestEntry {
    pub fn new(
        replay_scope: impl Into<String>,
        source_kind: impl Into<String>,
        source_id: impl Into<String>,
        record_root: impl Into<String>,
        nonce: u64,
    ) -> DisputeResult<Self> {
        let replay_scope = replay_scope.into();
        let source_kind = source_kind.into();
        let source_id = source_id.into();
        let record_root = record_root.into();
        let entry_id =
            dispute_manifest_entry_id(&replay_scope, &source_kind, &source_id, &record_root, nonce);
        let entry = Self {
            entry_id,
            replay_scope,
            source_kind,
            source_id,
            record_root,
            nonce,
            consumed_at_height: 0,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn replay_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            CHAIN_ID, self.replay_scope, self.source_kind, self.source_id, self.nonce
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_manifest_entry",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "replay_scope": self.replay_scope,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "record_root": self.record_root,
            "nonce": self.nonce,
            "replay_key": self.replay_key(),
            "consumed_at_height": self.consumed_at_height,
        })
    }

    pub fn entry_root(&self) -> String {
        dispute_payload_root("DISPUTE-MANIFEST-ENTRY", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.replay_scope, "dispute manifest replay scope")?;
        ensure_non_empty(&self.source_kind, "dispute manifest source kind")?;
        ensure_non_empty(&self.source_id, "dispute manifest source id")?;
        ensure_non_empty(&self.record_root, "dispute manifest record root")?;
        if self.entry_id
            != dispute_manifest_entry_id(
                &self.replay_scope,
                &self.source_kind,
                &self.source_id,
                &self.record_root,
                self.nonce,
            )
        {
            return Err("dispute manifest entry id mismatch".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeManifest {
    pub manifest_id: String,
    pub replay_domain: String,
    pub opener_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub entry_root: String,
    pub entries: Vec<DisputeManifestEntry>,
    pub status: String,
}

impl DisputeManifest {
    pub fn new(
        replay_domain: impl Into<String>,
        opener_commitment: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
        entries: Vec<DisputeManifestEntry>,
    ) -> DisputeResult<Self> {
        let replay_domain = replay_domain.into();
        let opener_commitment = opener_commitment.into();
        let entry_root = dispute_manifest_entry_root(&entries);
        let manifest_id = dispute_manifest_id(
            &replay_domain,
            &opener_commitment,
            created_at_height,
            expires_at_height,
            &entry_root,
        );
        let manifest = Self {
            manifest_id,
            replay_domain,
            opener_commitment,
            created_at_height,
            expires_at_height,
            entry_root,
            entries,
            status: DISPUTE_MANIFEST_STATUS_OPEN.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn entry_records(&self) -> Vec<Value> {
        let mut records = self
            .entries
            .iter()
            .map(|entry| (entry.entry_id.clone(), entry.public_record()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(|(_, record)| record).collect()
    }

    pub fn contains_record_root(&self, record_root: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.record_root == record_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_manifest",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "replay_domain": self.replay_domain,
            "opener_commitment": self.opener_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "entry_root": self.entry_root,
            "entries": self.entry_records(),
            "status": self.status,
        })
    }

    pub fn manifest_root(&self) -> String {
        dispute_payload_root("DISPUTE-MANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.replay_domain, "dispute manifest replay domain")?;
        ensure_non_empty(
            &self.opener_commitment,
            "dispute manifest opener commitment",
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("dispute manifest expiry must be after creation".to_string());
        }
        if self.entries.is_empty() {
            return Err("dispute manifest requires at least one entry".to_string());
        }
        if self.entries.len() > DISPUTE_MAX_MANIFEST_ENTRIES {
            return Err("dispute manifest entry limit exceeded".to_string());
        }
        let mut entry_ids = Vec::with_capacity(self.entries.len());
        let mut replay_keys = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            entry_ids.push(entry.entry_id.clone());
            replay_keys.push(entry.replay_key());
        }
        ensure_unique_strings(&entry_ids, "dispute manifest entry id")?;
        ensure_unique_strings(&replay_keys, "dispute manifest replay key")?;
        if self.entry_root != dispute_manifest_entry_root(&self.entries) {
            return Err("dispute manifest entry root mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DISPUTE_MANIFEST_STATUS_OPEN,
                DISPUTE_MANIFEST_STATUS_CONSUMED,
                DISPUTE_MANIFEST_STATUS_EXPIRED,
            ],
            "dispute manifest status",
        )?;
        if self.manifest_id
            != dispute_manifest_id(
                &self.replay_domain,
                &self.opener_commitment,
                self.created_at_height,
                self.expires_at_height,
                &self.entry_root,
            )
        {
            return Err("dispute manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeCase {
    pub dispute_id: String,
    pub dispute_kind: DisputeKind,
    pub claim: DisputeClaim,
    pub claim_root: String,
    pub opener_commitment: String,
    pub opened_at_height: u64,
    pub challenge_bond_id: String,
    pub challenger_evidence_packet_id: String,
    pub response_window_id: String,
    pub manifest_id: String,
    pub response_id: String,
    pub adjudication_receipt_id: String,
    pub final_outcome: Option<DisputeOutcome>,
    pub status: String,
}

impl DisputeCase {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        claim: DisputeClaim,
        opener_commitment: impl Into<String>,
        challenge_bond_id: impl Into<String>,
        challenger_evidence_packet_id: impl Into<String>,
        manifest_id: impl Into<String>,
        opened_at_height: u64,
        response_window_blocks: u64,
        adjudication_window_blocks: u64,
    ) -> DisputeResult<(Self, DisputeResponseWindow)> {
        claim.validate()?;
        let dispute_kind = claim.dispute_kind();
        let claim_root = claim.claim_root();
        let opener_commitment = opener_commitment.into();
        let challenge_bond_id = challenge_bond_id.into();
        let challenger_evidence_packet_id = challenger_evidence_packet_id.into();
        let manifest_id = manifest_id.into();
        let dispute_id = dispute_case_id(
            dispute_kind,
            claim.claim_id(),
            &claim_root,
            &opener_commitment,
            &challenge_bond_id,
            &challenger_evidence_packet_id,
            &manifest_id,
            opened_at_height,
        );
        let response_window = DisputeResponseWindow::new(
            &dispute_id,
            opened_at_height,
            response_window_blocks,
            adjudication_window_blocks,
        )?;
        let case = Self {
            dispute_id,
            dispute_kind,
            claim,
            claim_root,
            opener_commitment,
            opened_at_height,
            challenge_bond_id,
            challenger_evidence_packet_id,
            response_window_id: response_window.window_id.clone(),
            manifest_id,
            response_id: String::new(),
            adjudication_receipt_id: String::new(),
            final_outcome: None,
            status: DISPUTE_STATUS_OPEN.to_string(),
        };
        case.validate()?;
        Ok((case, response_window))
    }

    pub fn attach_response(&mut self, response_id: impl Into<String>) -> DisputeResult<String> {
        if self.status != DISPUTE_STATUS_OPEN && self.status != DISPUTE_STATUS_RESPONSE_EXPIRED {
            return Err("dispute case cannot accept a response in its current status".to_string());
        }
        self.response_id = response_id.into();
        ensure_non_empty(&self.response_id, "dispute response id")?;
        self.status = DISPUTE_STATUS_RESPONDED.to_string();
        self.validate()
    }

    pub fn mark_response_expired(&mut self) -> DisputeResult<String> {
        if self.status != DISPUTE_STATUS_OPEN {
            return Err("dispute case response window is not open".to_string());
        }
        self.status = DISPUTE_STATUS_RESPONSE_EXPIRED.to_string();
        self.validate()
    }

    pub fn close_with_receipt(
        &mut self,
        adjudication_receipt_id: impl Into<String>,
        outcome: DisputeOutcome,
    ) -> DisputeResult<String> {
        self.adjudication_receipt_id = adjudication_receipt_id.into();
        ensure_non_empty(
            &self.adjudication_receipt_id,
            "dispute adjudication receipt id",
        )?;
        self.final_outcome = Some(outcome);
        self.status = outcome.case_status().to_string();
        self.validate()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_case",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "dispute_id": self.dispute_id,
            "dispute_kind": self.dispute_kind.as_str(),
            "claim": self.claim.public_record(),
            "claim_root": self.claim_root,
            "opener_commitment": self.opener_commitment,
            "opened_at_height": self.opened_at_height,
            "challenge_bond_id": self.challenge_bond_id,
            "challenger_evidence_packet_id": self.challenger_evidence_packet_id,
            "response_window_id": self.response_window_id,
            "manifest_id": self.manifest_id,
            "response_id": self.response_id,
            "adjudication_receipt_id": self.adjudication_receipt_id,
            "final_outcome": self.final_outcome.map(DisputeOutcome::as_str),
            "status": self.status,
        })
    }

    pub fn case_root(&self) -> String {
        dispute_payload_root("DISPUTE-CASE", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        self.claim.validate()?;
        if self.dispute_kind != self.claim.dispute_kind() {
            return Err("dispute case kind does not match claim".to_string());
        }
        ensure_non_empty(&self.claim_root, "dispute case claim root")?;
        ensure_non_empty(&self.opener_commitment, "dispute case opener commitment")?;
        ensure_non_empty(&self.challenge_bond_id, "dispute case challenge bond id")?;
        ensure_non_empty(
            &self.challenger_evidence_packet_id,
            "dispute case challenger evidence packet id",
        )?;
        ensure_non_empty(&self.response_window_id, "dispute case response window id")?;
        ensure_non_empty(&self.manifest_id, "dispute case manifest id")?;
        if self.claim_root != self.claim.claim_root() {
            return Err("dispute case claim root mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DISPUTE_STATUS_OPEN,
                DISPUTE_STATUS_RESPONDED,
                DISPUTE_STATUS_RESPONSE_EXPIRED,
                DISPUTE_STATUS_ADJUDICATED,
                DISPUTE_STATUS_REJECTED,
                DISPUTE_STATUS_CANCELLED,
            ],
            "dispute case status",
        )?;
        if matches!(
            self.status.as_str(),
            DISPUTE_STATUS_ADJUDICATED | DISPUTE_STATUS_REJECTED
        ) && (self.adjudication_receipt_id.is_empty() || self.final_outcome.is_none())
        {
            return Err(
                "closed dispute case requires adjudication receipt and outcome".to_string(),
            );
        }
        if self.dispute_id
            != dispute_case_id(
                self.dispute_kind,
                self.claim.claim_id(),
                &self.claim_root,
                &self.opener_commitment,
                &self.challenge_bond_id,
                &self.challenger_evidence_packet_id,
                &self.manifest_id,
                self.opened_at_height,
            )
        {
            return Err("dispute case id mismatch".to_string());
        }
        Ok(self.case_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeResponse {
    pub response_id: String,
    pub dispute_id: String,
    pub respondent_commitment: String,
    pub response_kind: String,
    pub requested_outcome: DisputeOutcome,
    pub submitted_at_height: u64,
    pub evidence_packet_id: String,
    pub evidence_root: String,
    pub status: String,
}

impl DisputeResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute_id: impl Into<String>,
        respondent_commitment: impl Into<String>,
        response_kind: impl Into<String>,
        requested_outcome: DisputeOutcome,
        submitted_at_height: u64,
        evidence_packet: &DisputeEvidencePacket,
    ) -> DisputeResult<Self> {
        evidence_packet.validate()?;
        let dispute_id = dispute_id.into();
        let respondent_commitment = respondent_commitment.into();
        let response_kind = response_kind.into();
        let evidence_root = evidence_packet.packet_root();
        let response_id = dispute_response_id(
            &dispute_id,
            &respondent_commitment,
            &response_kind,
            requested_outcome,
            submitted_at_height,
            &evidence_packet.packet_id,
            &evidence_root,
        );
        let response = Self {
            response_id,
            dispute_id,
            respondent_commitment,
            response_kind,
            requested_outcome,
            submitted_at_height,
            evidence_packet_id: evidence_packet.packet_id.clone(),
            evidence_root,
            status: DISPUTE_RECORD_STATUS_PENDING.to_string(),
        };
        response.validate()?;
        Ok(response)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_response",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "response_id": self.response_id,
            "dispute_id": self.dispute_id,
            "respondent_commitment": self.respondent_commitment,
            "response_kind": self.response_kind,
            "requested_outcome": self.requested_outcome.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "evidence_packet_id": self.evidence_packet_id,
            "evidence_root": self.evidence_root,
            "status": self.status,
        })
    }

    pub fn response_root(&self) -> String {
        dispute_payload_root("DISPUTE-RESPONSE", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.dispute_id, "dispute response dispute id")?;
        ensure_non_empty(
            &self.respondent_commitment,
            "dispute response respondent commitment",
        )?;
        ensure_status(
            &self.response_kind,
            &[
                DISPUTE_RESPONSE_KIND_DENIAL,
                DISPUTE_RESPONSE_KIND_CONCESSION,
                DISPUTE_RESPONSE_KIND_COUNTER_EVIDENCE,
            ],
            "dispute response kind",
        )?;
        ensure_non_empty(
            &self.evidence_packet_id,
            "dispute response evidence packet id",
        )?;
        ensure_non_empty(&self.evidence_root, "dispute response evidence root")?;
        ensure_status(
            &self.status,
            &[
                DISPUTE_RECORD_STATUS_PENDING,
                DISPUTE_RECORD_STATUS_APPLIED,
                DISPUTE_RECORD_STATUS_REJECTED,
            ],
            "dispute response status",
        )?;
        if self.response_id
            != dispute_response_id(
                &self.dispute_id,
                &self.respondent_commitment,
                &self.response_kind,
                self.requested_outcome,
                self.submitted_at_height,
                &self.evidence_packet_id,
                &self.evidence_root,
            )
        {
            return Err("dispute response id mismatch".to_string());
        }
        Ok(self.response_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub slash_id: String,
    pub dispute_id: String,
    pub target_commitment: String,
    pub bond_id: String,
    pub asset_id: String,
    pub amount: u64,
    pub reason: String,
    pub evidence_root: String,
    pub recipient_commitment: String,
    pub slashed_at_height: u64,
    pub status: String,
}

impl SlashingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute_id: impl Into<String>,
        target_commitment: impl Into<String>,
        bond_id: impl Into<String>,
        asset_id: impl Into<String>,
        amount: u64,
        reason: impl Into<String>,
        evidence_root: impl Into<String>,
        recipient_commitment: impl Into<String>,
        slashed_at_height: u64,
    ) -> DisputeResult<Self> {
        let dispute_id = dispute_id.into();
        let target_commitment = target_commitment.into();
        let bond_id = bond_id.into();
        let asset_id = asset_id.into();
        let reason = reason.into();
        let evidence_root = evidence_root.into();
        let recipient_commitment = recipient_commitment.into();
        let slash_id = slashing_record_id(
            &dispute_id,
            &target_commitment,
            &bond_id,
            &asset_id,
            amount,
            &reason,
            &evidence_root,
            slashed_at_height,
        );
        let slash = Self {
            slash_id,
            dispute_id,
            target_commitment,
            bond_id,
            asset_id,
            amount,
            reason,
            evidence_root,
            recipient_commitment,
            slashed_at_height,
            status: DISPUTE_RECORD_STATUS_PENDING.to_string(),
        };
        slash.validate()?;
        Ok(slash)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_slashing_record",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "slash_id": self.slash_id,
            "dispute_id": self.dispute_id,
            "target_commitment": self.target_commitment,
            "bond_id": self.bond_id,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "recipient_commitment": self.recipient_commitment,
            "slashed_at_height": self.slashed_at_height,
            "status": self.status,
        })
    }

    pub fn slash_root(&self) -> String {
        dispute_payload_root("DISPUTE-SLASHING-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.dispute_id, "dispute slashing dispute id")?;
        ensure_non_empty(
            &self.target_commitment,
            "dispute slashing target commitment",
        )?;
        ensure_non_empty(&self.asset_id, "dispute slashing asset id")?;
        ensure_non_empty(&self.reason, "dispute slashing reason")?;
        ensure_non_empty(&self.evidence_root, "dispute slashing evidence root")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "dispute slashing recipient commitment",
        )?;
        if self.amount == 0 {
            return Err("dispute slashing amount must be positive".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DISPUTE_RECORD_STATUS_PENDING,
                DISPUTE_RECORD_STATUS_APPLIED,
                DISPUTE_RECORD_STATUS_REJECTED,
            ],
            "dispute slashing status",
        )?;
        if self.slash_id
            != slashing_record_id(
                &self.dispute_id,
                &self.target_commitment,
                &self.bond_id,
                &self.asset_id,
                self.amount,
                &self.reason,
                &self.evidence_root,
                self.slashed_at_height,
            )
        {
            return Err("dispute slashing id mismatch".to_string());
        }
        Ok(self.slash_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompensationRecord {
    pub compensation_id: String,
    pub dispute_id: String,
    pub beneficiary_commitment: String,
    pub source_slash_id: String,
    pub asset_id: String,
    pub amount: u64,
    pub reason: String,
    pub compensated_at_height: u64,
    pub status: String,
}

impl CompensationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        source_slash_id: impl Into<String>,
        asset_id: impl Into<String>,
        amount: u64,
        reason: impl Into<String>,
        compensated_at_height: u64,
    ) -> DisputeResult<Self> {
        let dispute_id = dispute_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let source_slash_id = source_slash_id.into();
        let asset_id = asset_id.into();
        let reason = reason.into();
        let compensation_id = compensation_record_id(
            &dispute_id,
            &beneficiary_commitment,
            &source_slash_id,
            &asset_id,
            amount,
            &reason,
            compensated_at_height,
        );
        let compensation = Self {
            compensation_id,
            dispute_id,
            beneficiary_commitment,
            source_slash_id,
            asset_id,
            amount,
            reason,
            compensated_at_height,
            status: DISPUTE_RECORD_STATUS_PENDING.to_string(),
        };
        compensation.validate()?;
        Ok(compensation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_compensation_record",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "compensation_id": self.compensation_id,
            "dispute_id": self.dispute_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "source_slash_id": self.source_slash_id,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "reason": self.reason,
            "compensated_at_height": self.compensated_at_height,
            "status": self.status,
        })
    }

    pub fn compensation_root(&self) -> String {
        dispute_payload_root("DISPUTE-COMPENSATION-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.dispute_id, "dispute compensation dispute id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "dispute compensation beneficiary commitment",
        )?;
        ensure_non_empty(
            &self.source_slash_id,
            "dispute compensation source slash id",
        )?;
        ensure_non_empty(&self.asset_id, "dispute compensation asset id")?;
        ensure_non_empty(&self.reason, "dispute compensation reason")?;
        if self.amount == 0 {
            return Err("dispute compensation amount must be positive".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DISPUTE_RECORD_STATUS_PENDING,
                DISPUTE_RECORD_STATUS_APPLIED,
                DISPUTE_RECORD_STATUS_REJECTED,
            ],
            "dispute compensation status",
        )?;
        if self.compensation_id
            != compensation_record_id(
                &self.dispute_id,
                &self.beneficiary_commitment,
                &self.source_slash_id,
                &self.asset_id,
                self.amount,
                &self.reason,
                self.compensated_at_height,
            )
        {
            return Err("dispute compensation id mismatch".to_string());
        }
        Ok(self.compensation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjudicationReceipt {
    pub receipt_id: String,
    pub dispute_id: String,
    pub dispute_kind: DisputeKind,
    pub adjudicator_commitment: String,
    pub adjudicated_at_height: u64,
    pub outcome: DisputeOutcome,
    pub claim_root: String,
    pub challenger_evidence_root: String,
    pub response_evidence_root: String,
    pub ruling_root: String,
    pub slashing_root: String,
    pub compensation_root: String,
    pub manifest_id: String,
    pub final_status: String,
}

impl AdjudicationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute: &DisputeCase,
        adjudicator_commitment: impl Into<String>,
        adjudicated_at_height: u64,
        outcome: DisputeOutcome,
        challenger_evidence_root: impl Into<String>,
        response_evidence_root: impl Into<String>,
        ruling: &Value,
        slashing_records: &[SlashingRecord],
        compensation_records: &[CompensationRecord],
    ) -> DisputeResult<Self> {
        dispute.validate()?;
        let adjudicator_commitment = adjudicator_commitment.into();
        let challenger_evidence_root = challenger_evidence_root.into();
        let response_evidence_root = response_evidence_root.into();
        let ruling_root = dispute_payload_root("DISPUTE-RULING", ruling);
        let mut applied_slashing_records = slashing_records.to_vec();
        for record in &mut applied_slashing_records {
            record.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
            record.validate()?;
        }
        let mut applied_compensation_records = compensation_records.to_vec();
        for record in &mut applied_compensation_records {
            record.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
            record.validate()?;
        }
        let slashing_root = slashing_record_root(&applied_slashing_records);
        let compensation_root = compensation_record_root(&applied_compensation_records);
        let final_status = outcome.case_status().to_string();
        let receipt_id = adjudication_receipt_id(
            &dispute.dispute_id,
            dispute.dispute_kind,
            &adjudicator_commitment,
            adjudicated_at_height,
            outcome,
            &dispute.claim_root,
            &challenger_evidence_root,
            &response_evidence_root,
            &ruling_root,
            &slashing_root,
            &compensation_root,
            &dispute.manifest_id,
        );
        let receipt = Self {
            receipt_id,
            dispute_id: dispute.dispute_id.clone(),
            dispute_kind: dispute.dispute_kind,
            adjudicator_commitment,
            adjudicated_at_height,
            outcome,
            claim_root: dispute.claim_root.clone(),
            challenger_evidence_root,
            response_evidence_root,
            ruling_root,
            slashing_root,
            compensation_root,
            manifest_id: dispute.manifest_id.clone(),
            final_status,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_adjudication_receipt",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "dispute_id": self.dispute_id,
            "dispute_kind": self.dispute_kind.as_str(),
            "adjudicator_commitment": self.adjudicator_commitment,
            "adjudicated_at_height": self.adjudicated_at_height,
            "outcome": self.outcome.as_str(),
            "claim_root": self.claim_root,
            "challenger_evidence_root": self.challenger_evidence_root,
            "response_evidence_root": self.response_evidence_root,
            "ruling_root": self.ruling_root,
            "slashing_root": self.slashing_root,
            "compensation_root": self.compensation_root,
            "manifest_id": self.manifest_id,
            "final_status": self.final_status,
        })
    }

    pub fn receipt_root(&self) -> String {
        dispute_payload_root("DISPUTE-ADJUDICATION-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> DisputeResult<String> {
        ensure_non_empty(&self.dispute_id, "adjudication receipt dispute id")?;
        ensure_non_empty(
            &self.adjudicator_commitment,
            "adjudication receipt adjudicator commitment",
        )?;
        ensure_non_empty(&self.claim_root, "adjudication receipt claim root")?;
        ensure_non_empty(
            &self.challenger_evidence_root,
            "adjudication receipt challenger evidence root",
        )?;
        ensure_non_empty(
            &self.response_evidence_root,
            "adjudication receipt response evidence root",
        )?;
        ensure_non_empty(&self.ruling_root, "adjudication receipt ruling root")?;
        ensure_non_empty(&self.slashing_root, "adjudication receipt slashing root")?;
        ensure_non_empty(
            &self.compensation_root,
            "adjudication receipt compensation root",
        )?;
        ensure_non_empty(&self.manifest_id, "adjudication receipt manifest id")?;
        if self.final_status != self.outcome.case_status() {
            return Err("adjudication receipt final status mismatch".to_string());
        }
        if self.receipt_id
            != adjudication_receipt_id(
                &self.dispute_id,
                self.dispute_kind,
                &self.adjudicator_commitment,
                self.adjudicated_at_height,
                self.outcome,
                &self.claim_root,
                &self.challenger_evidence_root,
                &self.response_evidence_root,
                &self.ruling_root,
                &self.slashing_root,
                &self.compensation_root,
                &self.manifest_id,
            )
        {
            return Err("adjudication receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeState {
    pub current_height: u64,
    pub response_window_blocks: u64,
    pub adjudication_window_blocks: u64,
    pub minimum_challenge_bond_units: u64,
    pub disputes: BTreeMap<String, DisputeCase>,
    pub response_windows: BTreeMap<String, DisputeResponseWindow>,
    pub evidence_packets: BTreeMap<String, DisputeEvidencePacket>,
    pub challenge_bonds: BTreeMap<String, ChallengeBond>,
    pub responses: BTreeMap<String, DisputeResponse>,
    pub adjudication_receipts: BTreeMap<String, AdjudicationReceipt>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub compensation_records: BTreeMap<String, CompensationRecord>,
    pub manifests: BTreeMap<String, DisputeManifest>,
    pub consumed_replay_keys: BTreeSet<String>,
}

impl Default for DisputeState {
    fn default() -> Self {
        Self {
            current_height: 0,
            response_window_blocks: DISPUTE_DEFAULT_RESPONSE_WINDOW_BLOCKS,
            adjudication_window_blocks: DISPUTE_DEFAULT_ADJUDICATION_WINDOW_BLOCKS,
            minimum_challenge_bond_units: DISPUTE_MIN_CHALLENGE_BOND_UNITS,
            disputes: BTreeMap::new(),
            response_windows: BTreeMap::new(),
            evidence_packets: BTreeMap::new(),
            challenge_bonds: BTreeMap::new(),
            responses: BTreeMap::new(),
            adjudication_receipts: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            compensation_records: BTreeMap::new(),
            manifests: BTreeMap::new(),
            consumed_replay_keys: BTreeSet::new(),
        }
    }
}

impl DisputeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_policy(
        response_window_blocks: u64,
        adjudication_window_blocks: u64,
        minimum_challenge_bond_units: u64,
    ) -> DisputeResult<Self> {
        if response_window_blocks == 0 {
            return Err("dispute state response window must be positive".to_string());
        }
        if adjudication_window_blocks == 0 {
            return Err("dispute state adjudication window must be positive".to_string());
        }
        if minimum_challenge_bond_units == 0 {
            return Err("dispute state challenge bond minimum must be positive".to_string());
        }
        Ok(Self {
            response_window_blocks,
            adjudication_window_blocks,
            minimum_challenge_bond_units,
            ..Self::default()
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn open_dispute(
        &mut self,
        claim: DisputeClaim,
        opener_commitment: impl Into<String>,
        challenge_bond: ChallengeBond,
        evidence_packet: DisputeEvidencePacket,
        manifest: DisputeManifest,
    ) -> DisputeResult<String> {
        let opener_commitment = opener_commitment.into();
        let (dispute, response_window) = DisputeCase::open(
            claim,
            opener_commitment,
            &challenge_bond.bond_id,
            &evidence_packet.packet_id,
            &manifest.manifest_id,
            self.current_height,
            self.response_window_blocks,
            self.adjudication_window_blocks,
        )?;
        self.apply_dispute(
            dispute,
            response_window,
            challenge_bond,
            evidence_packet,
            manifest,
        )
    }

    pub fn apply_dispute(
        &mut self,
        dispute: DisputeCase,
        response_window: DisputeResponseWindow,
        challenge_bond: ChallengeBond,
        evidence_packet: DisputeEvidencePacket,
        manifest: DisputeManifest,
    ) -> DisputeResult<String> {
        dispute.validate()?;
        response_window.validate()?;
        challenge_bond.validate()?;
        evidence_packet.validate()?;
        manifest.validate()?;
        if dispute.response_window_id != response_window.window_id {
            return Err("dispute response window id mismatch".to_string());
        }
        if response_window.dispute_id != dispute.dispute_id {
            return Err("dispute response window dispute id mismatch".to_string());
        }
        if dispute.challenge_bond_id != challenge_bond.bond_id {
            return Err("dispute challenge bond id mismatch".to_string());
        }
        if dispute.challenger_evidence_packet_id != evidence_packet.packet_id {
            return Err("dispute evidence packet id mismatch".to_string());
        }
        if dispute.dispute_kind != evidence_packet.dispute_kind {
            return Err("dispute evidence packet kind mismatch".to_string());
        }
        if dispute.claim.subject_id() != evidence_packet.subject_id {
            return Err("dispute evidence packet subject mismatch".to_string());
        }
        if dispute.manifest_id != manifest.manifest_id {
            return Err("dispute manifest id mismatch".to_string());
        }
        if challenge_bond.amount < self.minimum_challenge_bond_units {
            return Err("dispute challenge bond below state minimum".to_string());
        }
        if challenge_bond.unlock_after_height < response_window.adjudication_due_height {
            return Err("dispute challenge bond must stay locked through adjudication".to_string());
        }
        if manifest.expires_at_height <= dispute.opened_at_height {
            return Err("dispute manifest expired before dispute opened".to_string());
        }
        if !manifest.contains_record_root(&dispute.claim_root)
            && !manifest.contains_record_root(&evidence_packet.packet_root())
        {
            return Err("dispute manifest does not cover claim or evidence root".to_string());
        }
        self.ensure_manifest_replay_fresh(&manifest)?;
        if self.disputes.contains_key(&dispute.dispute_id) {
            return Err("dispute case already exists".to_string());
        }
        if self
            .response_windows
            .contains_key(&response_window.window_id)
        {
            return Err("dispute response window already exists".to_string());
        }
        if self.challenge_bonds.contains_key(&challenge_bond.bond_id) {
            return Err("challenge bond already exists".to_string());
        }
        if self
            .evidence_packets
            .contains_key(&evidence_packet.packet_id)
        {
            return Err("dispute evidence packet already exists".to_string());
        }
        if self.manifests.contains_key(&manifest.manifest_id) {
            return Err("dispute manifest already exists".to_string());
        }
        self.consume_manifest_replay_keys(&manifest);
        let dispute_id = dispute.dispute_id.clone();
        self.response_windows
            .insert(response_window.window_id.clone(), response_window);
        self.challenge_bonds
            .insert(challenge_bond.bond_id.clone(), challenge_bond);
        self.evidence_packets
            .insert(evidence_packet.packet_id.clone(), evidence_packet);
        self.manifests
            .insert(manifest.manifest_id.clone(), manifest);
        self.disputes.insert(dispute_id.clone(), dispute);
        Ok(dispute_id)
    }

    pub fn submit_response(
        &mut self,
        mut response: DisputeResponse,
        evidence_packet: DisputeEvidencePacket,
    ) -> DisputeResult<String> {
        response.validate()?;
        evidence_packet.validate()?;
        let dispute = self
            .disputes
            .get(&response.dispute_id)
            .ok_or_else(|| "dispute response target is missing".to_string())?
            .clone();
        let window = self
            .response_windows
            .get(&dispute.response_window_id)
            .ok_or_else(|| "dispute response window is missing".to_string())?
            .clone();
        if !window.is_response_open(response.submitted_at_height) {
            return Err("dispute response submitted outside response window".to_string());
        }
        if response.evidence_packet_id != evidence_packet.packet_id {
            return Err("dispute response evidence packet id mismatch".to_string());
        }
        if response.evidence_root != evidence_packet.packet_root() {
            return Err("dispute response evidence root mismatch".to_string());
        }
        if evidence_packet.dispute_kind != dispute.dispute_kind {
            return Err("dispute response evidence kind mismatch".to_string());
        }
        if evidence_packet.subject_id != dispute.claim.subject_id() {
            return Err("dispute response evidence subject mismatch".to_string());
        }
        if self.responses.contains_key(&response.response_id) {
            return Err("dispute response already exists".to_string());
        }
        if self
            .evidence_packets
            .contains_key(&evidence_packet.packet_id)
        {
            return Err("dispute response evidence packet already exists".to_string());
        }
        response.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
        response.validate()?;
        let response_id = response.response_id.clone();
        let mut updated_window = window;
        updated_window.mark_responded(response.submitted_at_height)?;
        let mut updated_dispute = dispute;
        updated_dispute.attach_response(&response_id)?;
        self.evidence_packets
            .insert(evidence_packet.packet_id.clone(), evidence_packet);
        self.responses.insert(response_id.clone(), response);
        self.response_windows
            .insert(updated_window.window_id.clone(), updated_window);
        self.disputes
            .insert(updated_dispute.dispute_id.clone(), updated_dispute);
        Ok(response_id)
    }

    pub fn expire_response_window(
        &mut self,
        dispute_id: &str,
        height: u64,
    ) -> DisputeResult<String> {
        let mut dispute = self
            .disputes
            .get(dispute_id)
            .ok_or_else(|| "dispute case is missing".to_string())?
            .clone();
        if !dispute.response_id.is_empty() {
            return Err("dispute case already has a response".to_string());
        }
        let mut window = self
            .response_windows
            .get(&dispute.response_window_id)
            .ok_or_else(|| "dispute response window is missing".to_string())?
            .clone();
        window.mark_expired(height)?;
        dispute.mark_response_expired()?;
        self.response_windows
            .insert(window.window_id.clone(), window);
        self.disputes.insert(dispute.dispute_id.clone(), dispute);
        Ok(dispute_id.to_string())
    }

    pub fn adjudicate(
        &mut self,
        receipt: AdjudicationReceipt,
        mut slashing_records: Vec<SlashingRecord>,
        mut compensation_records: Vec<CompensationRecord>,
    ) -> DisputeResult<String> {
        receipt.validate()?;
        for slash in &mut slashing_records {
            slash.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
            slash.validate()?;
        }
        for compensation in &mut compensation_records {
            compensation.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
            compensation.validate()?;
        }
        let mut dispute = self
            .disputes
            .get(&receipt.dispute_id)
            .ok_or_else(|| "adjudication dispute is missing".to_string())?
            .clone();
        if matches!(
            dispute.status.as_str(),
            DISPUTE_STATUS_ADJUDICATED | DISPUTE_STATUS_REJECTED | DISPUTE_STATUS_CANCELLED
        ) {
            return Err("dispute case is already closed".to_string());
        }
        let mut window = self
            .response_windows
            .get(&dispute.response_window_id)
            .ok_or_else(|| "adjudication response window is missing".to_string())?
            .clone();
        if window.adjudication_expired(receipt.adjudicated_at_height) {
            return Err("dispute adjudication window expired".to_string());
        }
        let no_response_ready = window.status == DISPUTE_WINDOW_STATUS_EXPIRED
            || window.response_expired(receipt.adjudicated_at_height);
        if dispute.response_id.is_empty() && !no_response_ready {
            return Err("dispute response window is still open".to_string());
        }
        if receipt.dispute_kind != dispute.dispute_kind {
            return Err("adjudication receipt kind mismatch".to_string());
        }
        if receipt.claim_root != dispute.claim_root {
            return Err("adjudication receipt claim root mismatch".to_string());
        }
        if receipt.manifest_id != dispute.manifest_id {
            return Err("adjudication receipt manifest id mismatch".to_string());
        }
        if receipt.slashing_root != slashing_record_root(&slashing_records) {
            return Err("adjudication receipt slashing root mismatch".to_string());
        }
        if receipt.compensation_root != compensation_record_root(&compensation_records) {
            return Err("adjudication receipt compensation root mismatch".to_string());
        }
        if self.adjudication_receipts.contains_key(&receipt.receipt_id) {
            return Err("adjudication receipt already exists".to_string());
        }
        let slash_ids = slashing_records
            .iter()
            .map(|record| record.slash_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&slash_ids, "adjudication slashing id")?;
        let compensation_ids = compensation_records
            .iter()
            .map(|record| record.compensation_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&compensation_ids, "adjudication compensation id")?;
        for slash in &slashing_records {
            slash.validate()?;
            if slash.dispute_id != receipt.dispute_id {
                return Err("adjudication slashing dispute mismatch".to_string());
            }
            if self.slashing_records.contains_key(&slash.slash_id) {
                return Err("dispute slashing record already exists".to_string());
            }
        }
        for compensation in &compensation_records {
            compensation.validate()?;
            if compensation.dispute_id != receipt.dispute_id {
                return Err("adjudication compensation dispute mismatch".to_string());
            }
            if !slash_ids.contains(&compensation.source_slash_id)
                && !self
                    .slashing_records
                    .contains_key(&compensation.source_slash_id)
            {
                return Err("dispute compensation source slash is missing".to_string());
            }
            if self
                .compensation_records
                .contains_key(&compensation.compensation_id)
            {
                return Err("dispute compensation record already exists".to_string());
            }
        }
        for slash in slashing_records {
            self.apply_slashing_record(slash)?;
        }
        for compensation in compensation_records {
            self.apply_compensation_record(compensation)?;
        }
        window.mark_closed(receipt.adjudicated_at_height)?;
        dispute.close_with_receipt(&receipt.receipt_id, receipt.outcome)?;
        let receipt_id = receipt.receipt_id.clone();
        self.response_windows
            .insert(window.window_id.clone(), window);
        self.disputes.insert(dispute.dispute_id.clone(), dispute);
        self.adjudication_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn apply_slashing_record(&mut self, mut slash: SlashingRecord) -> DisputeResult<String> {
        slash.validate()?;
        if self.slashing_records.contains_key(&slash.slash_id) {
            return Err("dispute slashing record already exists".to_string());
        }
        if !self.disputes.contains_key(&slash.dispute_id) {
            return Err("dispute slashing target dispute is missing".to_string());
        }
        if !slash.bond_id.is_empty() {
            let bond = self
                .challenge_bonds
                .get_mut(&slash.bond_id)
                .ok_or_else(|| "dispute slashing bond is missing".to_string())?;
            if bond.asset_id != slash.asset_id {
                return Err("dispute slashing asset id mismatch".to_string());
            }
            bond.apply_slash(slash.amount)?;
        }
        slash.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
        slash.validate()?;
        let slash_id = slash.slash_id.clone();
        self.slashing_records.insert(slash_id.clone(), slash);
        Ok(slash_id)
    }

    pub fn apply_compensation_record(
        &mut self,
        mut compensation: CompensationRecord,
    ) -> DisputeResult<String> {
        compensation.validate()?;
        if self
            .compensation_records
            .contains_key(&compensation.compensation_id)
        {
            return Err("dispute compensation record already exists".to_string());
        }
        if !self.disputes.contains_key(&compensation.dispute_id) {
            return Err("dispute compensation target dispute is missing".to_string());
        }
        if !self
            .slashing_records
            .contains_key(&compensation.source_slash_id)
        {
            return Err("dispute compensation source slash is missing".to_string());
        }
        compensation.status = DISPUTE_RECORD_STATUS_APPLIED.to_string();
        compensation.validate()?;
        let compensation_id = compensation.compensation_id.clone();
        self.compensation_records
            .insert(compensation_id.clone(), compensation);
        Ok(compensation_id)
    }

    pub fn refund_challenge_bond(
        &mut self,
        bond_id: &str,
        amount: u64,
        height: u64,
    ) -> DisputeResult<String> {
        let bond = self
            .challenge_bonds
            .get_mut(bond_id)
            .ok_or_else(|| "challenge bond is missing".to_string())?;
        if height <= bond.unlock_after_height {
            return Err("challenge bond cannot be refunded before unlock height".to_string());
        }
        bond.apply_refund(amount)?;
        Ok(bond_id.to_string())
    }

    pub fn dispute_root(&self) -> String {
        dispute_case_root(&self.disputes.values().cloned().collect::<Vec<_>>())
    }

    pub fn response_window_root(&self) -> String {
        dispute_response_window_root(&self.response_windows.values().cloned().collect::<Vec<_>>())
    }

    pub fn evidence_packet_root(&self) -> String {
        dispute_evidence_packet_root(&self.evidence_packets.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_bond_root(&self) -> String {
        challenge_bond_root(&self.challenge_bonds.values().cloned().collect::<Vec<_>>())
    }

    pub fn response_root(&self) -> String {
        dispute_response_root(&self.responses.values().cloned().collect::<Vec<_>>())
    }

    pub fn adjudication_root(&self) -> String {
        adjudication_receipt_root(
            &self
                .adjudication_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn slashing_root(&self) -> String {
        slashing_record_root(&self.slashing_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn compensation_root(&self) -> String {
        compensation_record_root(
            &self
                .compensation_records
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn manifest_root(&self) -> String {
        dispute_manifest_root(&self.manifests.values().cloned().collect::<Vec<_>>())
    }

    pub fn replay_key_root(&self) -> String {
        dispute_string_root(
            "DISPUTE-CONSUMED-REPLAY-KEY",
            &self
                .consumed_replay_keys
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        dispute_state_root(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_state",
            "chain_id": CHAIN_ID,
            "dispute_protocol_version": DISPUTE_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "response_window_blocks": self.response_window_blocks,
            "adjudication_window_blocks": self.adjudication_window_blocks,
            "minimum_challenge_bond_units": self.minimum_challenge_bond_units,
            "dispute_root": self.dispute_root(),
            "response_window_root": self.response_window_root(),
            "evidence_packet_root": self.evidence_packet_root(),
            "challenge_bond_root": self.challenge_bond_root(),
            "response_root": self.response_root(),
            "adjudication_root": self.adjudication_root(),
            "slashing_root": self.slashing_root(),
            "compensation_root": self.compensation_root(),
            "manifest_root": self.manifest_root(),
            "replay_key_root": self.replay_key_root(),
            "dispute_count": self.disputes.len(),
            "response_window_count": self.response_windows.len(),
            "evidence_packet_count": self.evidence_packets.len(),
            "challenge_bond_count": self.challenge_bonds.len(),
            "response_count": self.responses.len(),
            "adjudication_count": self.adjudication_receipts.len(),
            "slashing_count": self.slashing_records.len(),
            "compensation_count": self.compensation_records.len(),
            "manifest_count": self.manifests.len(),
        })
    }

    fn ensure_manifest_replay_fresh(&self, manifest: &DisputeManifest) -> DisputeResult<()> {
        for entry in &manifest.entries {
            if self.consumed_replay_keys.contains(&entry.replay_key()) {
                return Err("dispute manifest replay key has already been consumed".to_string());
            }
        }
        Ok(())
    }

    fn consume_manifest_replay_keys(&mut self, manifest: &DisputeManifest) {
        for entry in &manifest.entries {
            self.consumed_replay_keys.insert(entry.replay_key());
        }
    }
}

pub fn invalid_state_transition_claim_id(
    batch_id: &str,
    receipt_id: &str,
    transition_index: u64,
    previous_state_root: &str,
    asserted_post_state_root: &str,
    computed_post_state_root: &str,
    state_write_root: &str,
    receipt_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-INVALID-STATE-TRANSITION-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(receipt_id),
            HashPart::Int(transition_index as i128),
            HashPart::Str(previous_state_root),
            HashPart::Str(asserted_post_state_root),
            HashPart::Str(computed_post_state_root),
            HashPart::Str(state_write_root),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

pub fn da_withholding_claim_id(
    batch_id: &str,
    da_reference_id: &str,
    namespace: &str,
    payload_hash: &str,
    shard_commitment_root: &str,
    unavailable_shard_indices: &[u64],
    sample_challenge_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-DA-WITHHOLDING-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(da_reference_id),
            HashPart::Str(namespace),
            HashPart::Str(payload_hash),
            HashPart::Str(shard_commitment_root),
            HashPart::Str(&dispute_u64_root(
                "DISPUTE-DA-UNAVAILABLE-SHARD",
                unavailable_shard_indices,
            )),
            HashPart::Str(sample_challenge_root),
        ],
        32,
    )
}

pub fn invalid_bridge_release_claim_id(
    withdrawal_id: &str,
    release_monero_txid_hash: &str,
    expected_amount: u64,
    observed_amount: u64,
    expected_recipient_hash: &str,
    observed_recipient_hash: &str,
    release_signature_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-INVALID-BRIDGE-RELEASE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(release_monero_txid_hash),
            HashPart::Int(expected_amount as i128),
            HashPart::Int(observed_amount as i128),
            HashPart::Str(expected_recipient_hash),
            HashPart::Str(observed_recipient_hash),
            HashPart::Str(release_signature_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_manipulation_claim_id(
    feed_id: &str,
    aggregate_id: &str,
    disputed_round: u64,
    reported_price: u64,
    reference_price: u64,
    deviation_bps: u64,
    max_deviation_bps: u64,
    observation_root: &str,
    reference_source_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-ORACLE-MANIPULATION-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(aggregate_id),
            HashPart::Int(disputed_round as i128),
            HashPart::Int(reported_price as i128),
            HashPart::Int(reference_price as i128),
            HashPart::Int(deviation_bps as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Str(observation_root),
            HashPart::Str(reference_source_root),
        ],
        32,
    )
}

pub fn dispute_claim_root(claim: &DisputeClaim) -> String {
    dispute_payload_root("DISPUTE-CLAIM", &claim.public_record())
}

pub fn dispute_evidence_item_id(
    evidence_kind: &str,
    subject_id: &str,
    payload_root: &str,
    metadata_root: &str,
    source_commitment: &str,
) -> String {
    domain_hash(
        "DISPUTE-EVIDENCE-ITEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Str(metadata_root),
            HashPart::Str(source_commitment),
        ],
        32,
    )
}

pub fn dispute_evidence_packet_id(
    dispute_kind: DisputeKind,
    subject_id: &str,
    packet_label: &str,
    submitter_commitment: &str,
    submitted_at_height: u64,
    item_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-EVIDENCE-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(packet_label),
            HashPart::Str(submitter_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Str(item_root),
        ],
        32,
    )
}

pub fn challenge_bond_id(
    payer_commitment: &str,
    asset_id: &str,
    amount: u64,
    nonce: u64,
    locked_at_height: u64,
    unlock_after_height: u64,
    beneficiary_commitment: &str,
) -> String {
    domain_hash(
        "DISPUTE-CHALLENGE-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(payer_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(amount as i128),
            HashPart::Int(nonce as i128),
            HashPart::Int(locked_at_height as i128),
            HashPart::Int(unlock_after_height as i128),
            HashPart::Str(beneficiary_commitment),
        ],
        32,
    )
}

pub fn dispute_response_window_id(
    dispute_id: &str,
    opened_at_height: u64,
    response_due_height: u64,
    adjudication_due_height: u64,
) -> String {
    domain_hash(
        "DISPUTE-RESPONSE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(response_due_height as i128),
            HashPart::Int(adjudication_due_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn dispute_case_id(
    dispute_kind: DisputeKind,
    claim_id: &str,
    claim_root: &str,
    opener_commitment: &str,
    challenge_bond_id: &str,
    challenger_evidence_packet_id: &str,
    manifest_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "DISPUTE-CASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_kind.as_str()),
            HashPart::Str(claim_id),
            HashPart::Str(claim_root),
            HashPart::Str(opener_commitment),
            HashPart::Str(challenge_bond_id),
            HashPart::Str(challenger_evidence_packet_id),
            HashPart::Str(manifest_id),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn dispute_response_id(
    dispute_id: &str,
    respondent_commitment: &str,
    response_kind: &str,
    requested_outcome: DisputeOutcome,
    submitted_at_height: u64,
    evidence_packet_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Str(respondent_commitment),
            HashPart::Str(response_kind),
            HashPart::Str(requested_outcome.as_str()),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Str(evidence_packet_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn slashing_record_id(
    dispute_id: &str,
    target_commitment: &str,
    bond_id: &str,
    asset_id: &str,
    amount: u64,
    reason: &str,
    evidence_root: &str,
    slashed_at_height: u64,
) -> String {
    domain_hash(
        "DISPUTE-SLASHING-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Str(target_commitment),
            HashPart::Str(bond_id),
            HashPart::Str(asset_id),
            HashPart::Int(amount as i128),
            HashPart::Str(reason),
            HashPart::Str(evidence_root),
            HashPart::Int(slashed_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compensation_record_id(
    dispute_id: &str,
    beneficiary_commitment: &str,
    source_slash_id: &str,
    asset_id: &str,
    amount: u64,
    reason: &str,
    compensated_at_height: u64,
) -> String {
    domain_hash(
        "DISPUTE-COMPENSATION-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(source_slash_id),
            HashPart::Str(asset_id),
            HashPart::Int(amount as i128),
            HashPart::Str(reason),
            HashPart::Int(compensated_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adjudication_receipt_id(
    dispute_id: &str,
    dispute_kind: DisputeKind,
    adjudicator_commitment: &str,
    adjudicated_at_height: u64,
    outcome: DisputeOutcome,
    claim_root: &str,
    challenger_evidence_root: &str,
    response_evidence_root: &str,
    ruling_root: &str,
    slashing_root: &str,
    compensation_root: &str,
    manifest_id: &str,
) -> String {
    domain_hash(
        "DISPUTE-ADJUDICATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Str(dispute_kind.as_str()),
            HashPart::Str(adjudicator_commitment),
            HashPart::Int(adjudicated_at_height as i128),
            HashPart::Str(outcome.as_str()),
            HashPart::Str(claim_root),
            HashPart::Str(challenger_evidence_root),
            HashPart::Str(response_evidence_root),
            HashPart::Str(ruling_root),
            HashPart::Str(slashing_root),
            HashPart::Str(compensation_root),
            HashPart::Str(manifest_id),
        ],
        32,
    )
}

pub fn dispute_manifest_entry_id(
    replay_scope: &str,
    source_kind: &str,
    source_id: &str,
    record_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "DISPUTE-MANIFEST-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(replay_scope),
            HashPart::Str(source_kind),
            HashPart::Str(source_id),
            HashPart::Str(record_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn dispute_manifest_id(
    replay_domain: &str,
    opener_commitment: &str,
    created_at_height: u64,
    expires_at_height: u64,
    entry_root: &str,
) -> String {
    domain_hash(
        "DISPUTE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(replay_domain),
            HashPart::Str(opener_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(entry_root),
        ],
        32,
    )
}

pub fn dispute_price_deviation_bps(left: u64, right: u64) -> u64 {
    if left == right {
        return 0;
    }
    let high = left.max(right) as u128;
    let low = left.min(right) as u128;
    if low == 0 {
        return 10_000;
    }
    let value = high.saturating_sub(low).saturating_mul(10_000) / low;
    value.min(u64::MAX as u128) as u64
}

pub fn dispute_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn dispute_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_u64_root(domain: &str, values: &[u64]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::Number((*value).into()))
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_evidence_item_root(items: &[DisputeEvidenceItem]) -> String {
    let mut records = items
        .iter()
        .map(|item| (item.evidence_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DISPUTE-EVIDENCE-ITEM",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_evidence_packet_root(packets: &[DisputeEvidencePacket]) -> String {
    merkle_root(
        "DISPUTE-EVIDENCE-PACKET",
        &packets
            .iter()
            .map(DisputeEvidencePacket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn challenge_bond_root(bonds: &[ChallengeBond]) -> String {
    merkle_root(
        "DISPUTE-CHALLENGE-BOND",
        &bonds
            .iter()
            .map(ChallengeBond::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_response_window_root(windows: &[DisputeResponseWindow]) -> String {
    merkle_root(
        "DISPUTE-RESPONSE-WINDOW",
        &windows
            .iter()
            .map(DisputeResponseWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_case_root(disputes: &[DisputeCase]) -> String {
    merkle_root(
        "DISPUTE-CASE",
        &disputes
            .iter()
            .map(DisputeCase::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_response_root(responses: &[DisputeResponse]) -> String {
    merkle_root(
        "DISPUTE-RESPONSE",
        &responses
            .iter()
            .map(DisputeResponse::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn slashing_record_root(records: &[SlashingRecord]) -> String {
    merkle_root(
        "DISPUTE-SLASHING-RECORD",
        &records
            .iter()
            .map(SlashingRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn compensation_record_root(records: &[CompensationRecord]) -> String {
    merkle_root(
        "DISPUTE-COMPENSATION-RECORD",
        &records
            .iter()
            .map(CompensationRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn adjudication_receipt_root(receipts: &[AdjudicationReceipt]) -> String {
    merkle_root(
        "DISPUTE-ADJUDICATION-RECEIPT",
        &receipts
            .iter()
            .map(AdjudicationReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_manifest_entry_root(entries: &[DisputeManifestEntry]) -> String {
    let mut records = entries
        .iter()
        .map(|entry| (entry.entry_id.clone(), entry.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "DISPUTE-MANIFEST-ENTRY",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_manifest_root(manifests: &[DisputeManifest]) -> String {
    merkle_root(
        "DISPUTE-MANIFEST",
        &manifests
            .iter()
            .map(DisputeManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn dispute_state_root(record: &Value) -> String {
    dispute_payload_root("DISPUTE-STATE", record)
}

fn ensure_non_empty(value: &str, label: &str) -> DisputeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> DisputeResult<()> {
    if !allowed.contains(&value) {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> DisputeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn ensure_unique_u64(values: &[u64], label: &str) -> DisputeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}
