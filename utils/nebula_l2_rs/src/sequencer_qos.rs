use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type SequencerQosResult<T> = Result<T, String>;

pub const SEQUENCER_QOS_PROTOCOL_VERSION: &str = "nebula-sequencer-qos-v1";
pub const SEQUENCER_QOS_DEFAULT_EPOCH_BLOCKS: u64 = 16;
pub const SEQUENCER_QOS_DEFAULT_PRECONFIRM_TTL_BLOCKS: u64 = 6;
pub const SEQUENCER_QOS_DEFAULT_QUEUE_DEPTH: u64 = 2048;
pub const SEQUENCER_QOS_DEFAULT_BURST_CREDITS: u64 = 256;
pub const SEQUENCER_QOS_DEFAULT_LOW_FEE_MIN_SHARE_BPS: u64 = 1_500;
pub const SEQUENCER_QOS_DEFAULT_PRIVATE_MIN_SHARE_BPS: u64 = 2_500;
pub const SEQUENCER_QOS_DEFAULT_BRIDGE_MIN_SHARE_BPS: u64 = 1_000;
pub const SEQUENCER_QOS_MAX_BPS: u64 = 10_000;
pub const SEQUENCER_QOS_WARN_PRESSURE_BPS: u64 = 7_500;
pub const SEQUENCER_QOS_SHED_PRESSURE_BPS: u64 = 9_500;
pub const SEQUENCER_QOS_STATUS_ACTIVE: &str = "active";
pub const SEQUENCER_QOS_STATUS_THROTTLED: &str = "throttled";
pub const SEQUENCER_QOS_STATUS_SHEDDING: &str = "shedding";
pub const SEQUENCER_QOS_STATUS_EXHAUSTED: &str = "exhausted";
pub const SEQUENCER_QOS_STATUS_ACCEPTED: &str = "accepted";
pub const SEQUENCER_QOS_STATUS_REJECTED: &str = "rejected";
pub const SEQUENCER_QOS_STATUS_PRECONFIRMED: &str = "preconfirmed";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QosLaneKind {
    System,
    MoneroBridge,
    PrivateTransfer,
    PrivateDefi,
    PublicDefi,
    ContractCall,
    ProofMarket,
    LowFee,
    Bulk,
    Custom(String),
}

impl QosLaneKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::System => "system".to_string(),
            Self::MoneroBridge => "monero_bridge".to_string(),
            Self::PrivateTransfer => "private_transfer".to_string(),
            Self::PrivateDefi => "private_defi".to_string(),
            Self::PublicDefi => "public_defi".to_string(),
            Self::ContractCall => "contract_call".to_string(),
            Self::ProofMarket => "proof_market".to_string(),
            Self::LowFee => "low_fee".to_string(),
            Self::Bulk => "bulk".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::System => 1_000_000,
            Self::MoneroBridge => 900_000,
            Self::ProofMarket => 800_000,
            Self::PrivateTransfer => 700_000,
            Self::PrivateDefi => 650_000,
            Self::PublicDefi => 600_000,
            Self::ContractCall => 500_000,
            Self::LowFee => 450_000,
            Self::Bulk => 100_000,
            Self::Custom(_) => 250_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QosClass {
    Critical,
    Interactive,
    Fast,
    Standard,
    Economy,
    Background,
}

impl QosClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Interactive => "interactive",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Economy => "economy",
            Self::Background => "background",
        }
    }

    pub fn latency_target_ms(&self) -> u64 {
        match self {
            Self::Critical => TARGET_BLOCK_MS / 5,
            Self::Interactive => TARGET_BLOCK_MS / 2,
            Self::Fast => TARGET_BLOCK_MS,
            Self::Standard => TARGET_BLOCK_MS * 2,
            Self::Economy => TARGET_BLOCK_MS * 4,
            Self::Background => TARGET_BLOCK_MS * 8,
        }
        .max(1)
    }

    pub fn priority_bonus(&self) -> u64 {
        match self {
            Self::Critical => 200_000,
            Self::Interactive => 150_000,
            Self::Fast => 100_000,
            Self::Standard => 50_000,
            Self::Economy => 20_000,
            Self::Background => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QosDecisionKind {
    Admit,
    Preconfirm,
    Delay,
    Throttle,
    Shed,
    Reject,
}

impl QosDecisionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Preconfirm => "preconfirm",
            Self::Delay => "delay",
            Self::Throttle => "throttle",
            Self::Shed => "shed",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QosOverloadAction {
    None,
    SpendBurstCredit,
    ReduceBulkLane,
    RequireHigherBond,
    PreserveLowFeeShare,
    PreserveBridgeShare,
    ShedBackground,
    EmergencyOnly,
}

impl QosOverloadAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SpendBurstCredit => "spend_burst_credit",
            Self::ReduceBulkLane => "reduce_bulk_lane",
            Self::RequireHigherBond => "require_higher_bond",
            Self::PreserveLowFeeShare => "preserve_low_fee_share",
            Self::PreserveBridgeShare => "preserve_bridge_share",
            Self::ShedBackground => "shed_background",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosLanePolicy {
    pub lane_id: String,
    pub label: String,
    pub lane_kind: QosLaneKind,
    pub qos_class: QosClass,
    pub min_share_bps: u64,
    pub max_share_bps: u64,
    pub max_queue_depth: u64,
    pub burst_credits: u64,
    pub min_fee_units: u64,
    pub anti_spam_bond_units: u64,
    pub preconfirm_enabled: bool,
    pub status: String,
}

impl QosLanePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        lane_kind: QosLaneKind,
        qos_class: QosClass,
        min_share_bps: u64,
        max_share_bps: u64,
        max_queue_depth: u64,
        burst_credits: u64,
        min_fee_units: u64,
        anti_spam_bond_units: u64,
        preconfirm_enabled: bool,
    ) -> SequencerQosResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "qos lane label")?;
        ensure_bps(min_share_bps, "qos lane min share")?;
        ensure_bps(max_share_bps, "qos lane max share")?;
        if min_share_bps > max_share_bps {
            return Err("qos lane min share exceeds max share".to_string());
        }
        ensure_positive(max_queue_depth, "qos lane max queue depth")?;
        let lane_id = qos_lane_policy_id(
            &label,
            &lane_kind,
            &qos_class,
            min_share_bps,
            max_share_bps,
            max_queue_depth,
            burst_credits,
            min_fee_units,
            anti_spam_bond_units,
            preconfirm_enabled,
        );
        Ok(Self {
            lane_id,
            label,
            lane_kind,
            qos_class,
            min_share_bps,
            max_share_bps,
            max_queue_depth,
            burst_credits,
            min_fee_units,
            anti_spam_bond_units,
            preconfirm_enabled,
            status: SEQUENCER_QOS_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn priority_floor(&self) -> u64 {
        self.lane_kind
            .default_priority()
            .saturating_add(self.qos_class.priority_bonus())
            .saturating_add(self.min_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_lane_policy",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_kind": self.lane_kind.as_str(),
            "qos_class": self.qos_class.as_str(),
            "min_share_bps": self.min_share_bps,
            "max_share_bps": self.max_share_bps,
            "max_queue_depth": self.max_queue_depth,
            "burst_credits": self.burst_credits,
            "min_fee_units": self.min_fee_units,
            "anti_spam_bond_units": self.anti_spam_bond_units,
            "preconfirm_enabled": self.preconfirm_enabled,
            "priority_floor": self.priority_floor(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosAdmissionRequest {
    pub request_id: String,
    pub tx_id: String,
    pub lane_id: String,
    pub qos_class: QosClass,
    pub fee_units: u64,
    pub low_fee_credit_units: u64,
    pub anti_spam_bond_units: u64,
    pub privacy_root: String,
    pub quantum_auth_root: String,
    pub access_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl QosAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: impl Into<String>,
        lane_id: impl Into<String>,
        qos_class: QosClass,
        fee_units: u64,
        low_fee_credit_units: u64,
        anti_spam_bond_units: u64,
        privacy_root: impl Into<String>,
        quantum_auth_root: impl Into<String>,
        access_root: impl Into<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> SequencerQosResult<Self> {
        let tx_id = tx_id.into();
        let lane_id = lane_id.into();
        let privacy_root = privacy_root.into();
        let quantum_auth_root = quantum_auth_root.into();
        let access_root = access_root.into();
        ensure_non_empty(&tx_id, "qos request tx id")?;
        ensure_non_empty(&lane_id, "qos request lane id")?;
        ensure_non_empty(&privacy_root, "qos request privacy root")?;
        ensure_non_empty(&quantum_auth_root, "qos request quantum auth root")?;
        ensure_non_empty(&access_root, "qos request access root")?;
        if expires_at_height <= submitted_at_height {
            return Err("qos request expiry must be after submission".to_string());
        }
        let request_id = qos_admission_request_id(
            &tx_id,
            &lane_id,
            &qos_class,
            fee_units,
            low_fee_credit_units,
            anti_spam_bond_units,
            &privacy_root,
            &quantum_auth_root,
            &access_root,
            submitted_at_height,
            expires_at_height,
        );
        Ok(Self {
            request_id,
            tx_id,
            lane_id,
            qos_class,
            fee_units,
            low_fee_credit_units,
            anti_spam_bond_units,
            privacy_root,
            quantum_auth_root,
            access_root,
            submitted_at_height,
            expires_at_height,
        })
    }

    pub fn effective_fee_units(&self) -> u64 {
        self.fee_units.saturating_add(self.low_fee_credit_units)
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_admission_request",
            "chain_id": CHAIN_ID,
            "request_id": self.request_id,
            "tx_id": self.tx_id,
            "lane_id": self.lane_id,
            "qos_class": self.qos_class.as_str(),
            "fee_units": self.fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "effective_fee_units": self.effective_fee_units(),
            "anti_spam_bond_units": self.anti_spam_bond_units,
            "privacy_root": self.privacy_root,
            "quantum_auth_root": self.quantum_auth_root,
            "access_root": self.access_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosQueueSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub lane_id: String,
    pub pending_count: u64,
    pub ready_count: u64,
    pub delayed_count: u64,
    pub admitted_count: u64,
    pub average_wait_blocks: u64,
    pub pressure_bps: u64,
    pub status: String,
}

impl QosQueueSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        lane: &QosLanePolicy,
        pending_count: u64,
        ready_count: u64,
        delayed_count: u64,
        admitted_count: u64,
        average_wait_blocks: u64,
    ) -> Self {
        let depth = pending_count
            .saturating_add(ready_count)
            .saturating_add(delayed_count);
        let pressure_bps = ratio_bps(depth, lane.max_queue_depth.max(1)).min(SEQUENCER_QOS_MAX_BPS);
        let status = if pressure_bps >= SEQUENCER_QOS_SHED_PRESSURE_BPS {
            SEQUENCER_QOS_STATUS_SHEDDING
        } else if pressure_bps >= SEQUENCER_QOS_WARN_PRESSURE_BPS {
            SEQUENCER_QOS_STATUS_THROTTLED
        } else {
            SEQUENCER_QOS_STATUS_ACTIVE
        }
        .to_string();
        let snapshot_id = qos_queue_snapshot_id(
            height,
            &lane.lane_id,
            pending_count,
            ready_count,
            delayed_count,
            admitted_count,
            average_wait_blocks,
            pressure_bps,
        );
        Self {
            snapshot_id,
            height,
            lane_id: lane.lane_id.clone(),
            pending_count,
            ready_count,
            delayed_count,
            admitted_count,
            average_wait_blocks,
            pressure_bps,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_queue_snapshot",
            "chain_id": CHAIN_ID,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "lane_id": self.lane_id,
            "pending_count": self.pending_count,
            "ready_count": self.ready_count,
            "delayed_count": self.delayed_count,
            "admitted_count": self.admitted_count,
            "average_wait_blocks": self.average_wait_blocks,
            "pressure_bps": self.pressure_bps,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosCreditBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub owner_commitment: String,
    pub epoch: u64,
    pub issued_credits: u64,
    pub spent_credits: u64,
    pub reserved_credits: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl QosCreditBucket {
    pub fn new(
        lane_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        epoch: u64,
        issued_credits: u64,
        expires_at_height: u64,
    ) -> SequencerQosResult<Self> {
        let lane_id = lane_id.into();
        let owner_commitment = owner_commitment.into();
        ensure_non_empty(&lane_id, "qos credit lane id")?;
        ensure_non_empty(&owner_commitment, "qos credit owner commitment")?;
        let bucket_id = qos_credit_bucket_id(
            &lane_id,
            &owner_commitment,
            epoch,
            issued_credits,
            expires_at_height,
        );
        Ok(Self {
            bucket_id,
            lane_id,
            owner_commitment,
            epoch,
            issued_credits,
            spent_credits: 0,
            reserved_credits: 0,
            expires_at_height,
            status: SEQUENCER_QOS_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn available_credits(&self) -> u64 {
        self.issued_credits
            .saturating_sub(self.spent_credits)
            .saturating_sub(self.reserved_credits)
    }

    pub fn reserve(&mut self, credits: u64) -> SequencerQosResult<()> {
        if self.available_credits() < credits {
            return Err("qos credit bucket insufficient credits".to_string());
        }
        self.reserved_credits = self.reserved_credits.saturating_add(credits);
        Ok(())
    }

    pub fn spend_reserved(&mut self, credits: u64) -> SequencerQosResult<()> {
        if self.reserved_credits < credits {
            return Err("qos credit bucket insufficient reserved credits".to_string());
        }
        self.reserved_credits = self.reserved_credits.saturating_sub(credits);
        self.spent_credits = self.spent_credits.saturating_add(credits);
        if self.available_credits() == 0 {
            self.status = SEQUENCER_QOS_STATUS_EXHAUSTED.to_string();
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_credit_bucket",
            "chain_id": CHAIN_ID,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "owner_commitment": self.owner_commitment,
            "epoch": self.epoch,
            "issued_credits": self.issued_credits,
            "spent_credits": self.spent_credits,
            "reserved_credits": self.reserved_credits,
            "available_credits": self.available_credits(),
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosAdmissionDecision {
    pub decision_id: String,
    pub request_id: String,
    pub lane_id: String,
    pub decision_kind: QosDecisionKind,
    pub overload_action: QosOverloadAction,
    pub priority_score: u64,
    pub target_height: u64,
    pub credit_bucket_id: Option<String>,
    pub queue_snapshot_root: String,
    pub reason_root: String,
    pub status: String,
}

impl QosAdmissionDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &QosAdmissionRequest,
        decision_kind: QosDecisionKind,
        overload_action: QosOverloadAction,
        priority_score: u64,
        target_height: u64,
        credit_bucket_id: Option<String>,
        queue_snapshot_root: impl Into<String>,
        reason: &Value,
    ) -> SequencerQosResult<Self> {
        let queue_snapshot_root = queue_snapshot_root.into();
        ensure_non_empty(&queue_snapshot_root, "qos decision snapshot root")?;
        let reason_root = sequencer_qos_payload_root("QOS-DECISION-REASON", reason);
        let status = match decision_kind {
            QosDecisionKind::Admit | QosDecisionKind::Preconfirm => SEQUENCER_QOS_STATUS_ACCEPTED,
            QosDecisionKind::Delay | QosDecisionKind::Throttle => SEQUENCER_QOS_STATUS_THROTTLED,
            QosDecisionKind::Shed | QosDecisionKind::Reject => SEQUENCER_QOS_STATUS_REJECTED,
        }
        .to_string();
        let decision_id = qos_admission_decision_id(
            &request.request_id,
            &request.lane_id,
            &decision_kind,
            &overload_action,
            priority_score,
            target_height,
            credit_bucket_id.as_deref(),
            &queue_snapshot_root,
            &reason_root,
        );
        Ok(Self {
            decision_id,
            request_id: request.request_id.clone(),
            lane_id: request.lane_id.clone(),
            decision_kind,
            overload_action,
            priority_score,
            target_height,
            credit_bucket_id,
            queue_snapshot_root,
            reason_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_admission_decision",
            "chain_id": CHAIN_ID,
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "lane_id": self.lane_id,
            "decision_kind": self.decision_kind.as_str(),
            "overload_action": self.overload_action.as_str(),
            "priority_score": self.priority_score,
            "target_height": self.target_height,
            "credit_bucket_id": self.credit_bucket_id,
            "queue_snapshot_root": self.queue_snapshot_root,
            "reason_root": self.reason_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosPreconfirmationPromise {
    pub promise_id: String,
    pub decision_id: String,
    pub request_id: String,
    pub target_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub priority_score: u64,
    pub promised_state_root: String,
    pub sequencer_commitment: String,
    pub status: String,
}

impl QosPreconfirmationPromise {
    pub fn new(
        decision: &QosAdmissionDecision,
        expires_at_height: u64,
        promised_state_root: impl Into<String>,
        sequencer_commitment: impl Into<String>,
    ) -> SequencerQosResult<Self> {
        let promised_state_root = promised_state_root.into();
        let sequencer_commitment = sequencer_commitment.into();
        ensure_non_empty(&promised_state_root, "qos preconfirmation promised root")?;
        ensure_non_empty(
            &sequencer_commitment,
            "qos preconfirmation sequencer commitment",
        )?;
        if expires_at_height <= decision.target_height {
            return Err("qos preconfirmation expiry must exceed target height".to_string());
        }
        let promise_id = qos_preconfirmation_promise_id(
            &decision.decision_id,
            &decision.request_id,
            decision.target_height,
            expires_at_height,
            &decision.lane_id,
            decision.priority_score,
            &promised_state_root,
            &sequencer_commitment,
        );
        Ok(Self {
            promise_id,
            decision_id: decision.decision_id.clone(),
            request_id: decision.request_id.clone(),
            target_height: decision.target_height,
            expires_at_height,
            lane_id: decision.lane_id.clone(),
            priority_score: decision.priority_score,
            promised_state_root,
            sequencer_commitment,
            status: SEQUENCER_QOS_STATUS_PRECONFIRMED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_preconfirmation_promise",
            "chain_id": CHAIN_ID,
            "promise_id": self.promise_id,
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "target_height": self.target_height,
            "expires_at_height": self.expires_at_height,
            "lane_id": self.lane_id,
            "priority_score": self.priority_score,
            "promised_state_root": self.promised_state_root,
            "sequencer_commitment": self.sequencer_commitment,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosFairnessEpoch {
    pub epoch_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub lane_share_root: String,
    pub admitted_root: String,
    pub delayed_root: String,
    pub low_fee_share_bps: u64,
    pub private_share_bps: u64,
    pub bridge_share_bps: u64,
    pub fairness_score_bps: u64,
    pub status: String,
}

impl QosFairnessEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        start_height: u64,
        end_height: u64,
        lanes: &[QosLanePolicy],
        admitted_decisions: &[QosAdmissionDecision],
        delayed_decisions: &[QosAdmissionDecision],
    ) -> SequencerQosResult<Self> {
        if end_height <= start_height {
            return Err("qos fairness epoch end must exceed start".to_string());
        }
        let lane_share_root = qos_lane_policy_root(lanes);
        let admitted_root = qos_admission_decision_root(admitted_decisions);
        let delayed_root = qos_admission_decision_root(delayed_decisions);
        let total_admitted = admitted_decisions.len() as u64;
        let low_fee_count = count_lane_kind(lanes, admitted_decisions, QosLaneKind::LowFee);
        let private_count =
            count_lane_kind(lanes, admitted_decisions, QosLaneKind::PrivateDefi).saturating_add(
                count_lane_kind(lanes, admitted_decisions, QosLaneKind::PrivateTransfer),
            );
        let bridge_count = count_lane_kind(lanes, admitted_decisions, QosLaneKind::MoneroBridge);
        let low_fee_share_bps = ratio_bps(low_fee_count, total_admitted.max(1));
        let private_share_bps = ratio_bps(private_count, total_admitted.max(1));
        let bridge_share_bps = ratio_bps(bridge_count, total_admitted.max(1));
        let fairness_score_bps = low_fee_share_bps
            .min(SEQUENCER_QOS_DEFAULT_LOW_FEE_MIN_SHARE_BPS)
            .saturating_add(private_share_bps.min(SEQUENCER_QOS_DEFAULT_PRIVATE_MIN_SHARE_BPS))
            .saturating_add(bridge_share_bps.min(SEQUENCER_QOS_DEFAULT_BRIDGE_MIN_SHARE_BPS))
            .saturating_mul(SEQUENCER_QOS_MAX_BPS)
            / SEQUENCER_QOS_DEFAULT_LOW_FEE_MIN_SHARE_BPS
                .saturating_add(SEQUENCER_QOS_DEFAULT_PRIVATE_MIN_SHARE_BPS)
                .saturating_add(SEQUENCER_QOS_DEFAULT_BRIDGE_MIN_SHARE_BPS)
                .max(1);
        let epoch_id = qos_fairness_epoch_id(
            epoch,
            start_height,
            end_height,
            &lane_share_root,
            &admitted_root,
            &delayed_root,
            low_fee_share_bps,
            private_share_bps,
            bridge_share_bps,
            fairness_score_bps,
        );
        Ok(Self {
            epoch_id,
            epoch,
            start_height,
            end_height,
            lane_share_root,
            admitted_root,
            delayed_root,
            low_fee_share_bps,
            private_share_bps,
            bridge_share_bps,
            fairness_score_bps,
            status: SEQUENCER_QOS_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_fairness_epoch",
            "chain_id": CHAIN_ID,
            "epoch_id": self.epoch_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "lane_share_root": self.lane_share_root,
            "admitted_root": self.admitted_root,
            "delayed_root": self.delayed_root,
            "low_fee_share_bps": self.low_fee_share_bps,
            "private_share_bps": self.private_share_bps,
            "bridge_share_bps": self.bridge_share_bps,
            "fairness_score_bps": self.fairness_score_bps,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerQosState {
    pub height: u64,
    pub epoch: u64,
    pub lanes: BTreeMap<String, QosLanePolicy>,
    pub requests: BTreeMap<String, QosAdmissionRequest>,
    pub queue_snapshots: BTreeMap<String, QosQueueSnapshot>,
    pub credit_buckets: BTreeMap<String, QosCreditBucket>,
    pub decisions: BTreeMap<String, QosAdmissionDecision>,
    pub preconfirmations: BTreeMap<String, QosPreconfirmationPromise>,
    pub fairness_epochs: BTreeMap<String, QosFairnessEpoch>,
}

impl SequencerQosState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_label: &str) -> SequencerQosResult<Self> {
        ensure_non_empty(operator_label, "qos devnet operator label")?;
        let mut state = Self::new();
        for lane in [
            QosLanePolicy::new(
                "system",
                QosLaneKind::System,
                QosClass::Critical,
                500,
                2_000,
                128,
                SEQUENCER_QOS_DEFAULT_BURST_CREDITS,
                0,
                0,
                true,
            )?,
            QosLanePolicy::new(
                "monero-bridge",
                QosLaneKind::MoneroBridge,
                QosClass::Fast,
                SEQUENCER_QOS_DEFAULT_BRIDGE_MIN_SHARE_BPS,
                3_000,
                SEQUENCER_QOS_DEFAULT_QUEUE_DEPTH,
                SEQUENCER_QOS_DEFAULT_BURST_CREDITS,
                1,
                5,
                true,
            )?,
            QosLanePolicy::new(
                "private-defi",
                QosLaneKind::PrivateDefi,
                QosClass::Interactive,
                SEQUENCER_QOS_DEFAULT_PRIVATE_MIN_SHARE_BPS,
                5_000,
                SEQUENCER_QOS_DEFAULT_QUEUE_DEPTH,
                SEQUENCER_QOS_DEFAULT_BURST_CREDITS,
                1,
                5,
                true,
            )?,
            QosLanePolicy::new(
                "low-fee",
                QosLaneKind::LowFee,
                QosClass::Economy,
                SEQUENCER_QOS_DEFAULT_LOW_FEE_MIN_SHARE_BPS,
                4_000,
                SEQUENCER_QOS_DEFAULT_QUEUE_DEPTH,
                SEQUENCER_QOS_DEFAULT_BURST_CREDITS.saturating_mul(2),
                0,
                2,
                true,
            )?,
            QosLanePolicy::new(
                "bulk",
                QosLaneKind::Bulk,
                QosClass::Background,
                0,
                2_000,
                SEQUENCER_QOS_DEFAULT_QUEUE_DEPTH,
                32,
                1,
                10,
                false,
            )?,
        ] {
            let lane_id = state.insert_lane(lane)?;
            let owner_commitment = sequencer_qos_string_root(
                "QOS-DEVNET-OWNER",
                &format!("{operator_label}:{lane_id}"),
            );
            let bucket = QosCreditBucket::new(
                lane_id,
                owner_commitment,
                0,
                SEQUENCER_QOS_DEFAULT_BURST_CREDITS,
                SEQUENCER_QOS_DEFAULT_EPOCH_BLOCKS,
            )?;
            state.insert_credit_bucket(bucket)?;
        }
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.epoch = height / SEQUENCER_QOS_DEFAULT_EPOCH_BLOCKS.max(1);
    }

    pub fn insert_lane(&mut self, lane: QosLanePolicy) -> SequencerQosResult<String> {
        let lane_id = lane.lane_id.clone();
        if self
            .lanes
            .values()
            .any(|existing| existing.label == lane.label && existing.lane_id != lane.lane_id)
        {
            return Err("qos lane label already exists".to_string());
        }
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn insert_credit_bucket(&mut self, bucket: QosCreditBucket) -> SequencerQosResult<String> {
        if !self.lanes.contains_key(&bucket.lane_id) {
            return Err("qos credit bucket references unknown lane".to_string());
        }
        let bucket_id = bucket.bucket_id.clone();
        self.credit_buckets.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }

    pub fn submit_request(&mut self, request: QosAdmissionRequest) -> SequencerQosResult<String> {
        if !self.lanes.contains_key(&request.lane_id) {
            return Err("qos request references unknown lane".to_string());
        }
        if request.is_expired(self.height) {
            return Err("qos request is expired".to_string());
        }
        let request_id = request.request_id.clone();
        self.requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    pub fn snapshot_lane(&mut self, lane_id: &str) -> SequencerQosResult<QosQueueSnapshot> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "qos snapshot unknown lane".to_string())?;
        let pending_count = self
            .requests
            .values()
            .filter(|request| request.lane_id == lane_id && !request.is_expired(self.height))
            .count() as u64;
        let ready_count = self
            .decisions
            .values()
            .filter(|decision| {
                decision.lane_id == lane_id
                    && matches!(
                        decision.decision_kind,
                        QosDecisionKind::Admit | QosDecisionKind::Preconfirm
                    )
            })
            .count() as u64;
        let delayed_count = self
            .decisions
            .values()
            .filter(|decision| {
                decision.lane_id == lane_id
                    && matches!(
                        decision.decision_kind,
                        QosDecisionKind::Delay | QosDecisionKind::Throttle
                    )
            })
            .count() as u64;
        let admitted_count = self
            .decisions
            .values()
            .filter(|decision| {
                decision.lane_id == lane_id
                    && matches!(
                        decision.decision_kind,
                        QosDecisionKind::Admit | QosDecisionKind::Preconfirm
                    )
            })
            .count() as u64;
        let average_wait_blocks = if pending_count == 0 {
            0
        } else {
            self.requests
                .values()
                .filter(|request| request.lane_id == lane_id)
                .map(|request| self.height.saturating_sub(request.submitted_at_height))
                .sum::<u64>()
                / pending_count.max(1)
        };
        let snapshot = QosQueueSnapshot::new(
            self.height,
            lane,
            pending_count,
            ready_count,
            delayed_count,
            admitted_count,
            average_wait_blocks,
        );
        self.queue_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn decide(&mut self, request_id: &str) -> SequencerQosResult<QosAdmissionDecision> {
        let request = self
            .requests
            .get(request_id)
            .cloned()
            .ok_or_else(|| "qos decision unknown request".to_string())?;
        let lane = self
            .lanes
            .get(&request.lane_id)
            .cloned()
            .ok_or_else(|| "qos decision unknown lane".to_string())?;
        let snapshot = self.snapshot_lane(&request.lane_id)?;
        let mut credit_bucket_id = None;
        let mut overload_action = QosOverloadAction::None;
        if request.low_fee_credit_units > 0 {
            if let Some(bucket) = self
                .credit_buckets
                .values_mut()
                .find(|bucket| bucket.lane_id == request.lane_id && bucket.available_credits() > 0)
            {
                let credits = request.low_fee_credit_units.min(bucket.available_credits());
                bucket.reserve(credits)?;
                credit_bucket_id = Some(bucket.bucket_id.clone());
                overload_action = QosOverloadAction::SpendBurstCredit;
            }
        }
        let priority_score = lane
            .priority_floor()
            .saturating_add(request.qos_class.priority_bonus())
            .saturating_add(request.effective_fee_units())
            .saturating_sub(snapshot.pressure_bps);
        let decision_kind = if request.fee_units < lane.min_fee_units
            && request.low_fee_credit_units == 0
            && lane.min_fee_units > 0
        {
            QosDecisionKind::Reject
        } else if request.anti_spam_bond_units < lane.anti_spam_bond_units {
            QosDecisionKind::Throttle
        } else if snapshot.pressure_bps >= SEQUENCER_QOS_SHED_PRESSURE_BPS
            && lane.lane_kind == QosLaneKind::Bulk
        {
            overload_action = QosOverloadAction::ShedBackground;
            QosDecisionKind::Shed
        } else if snapshot.pressure_bps >= SEQUENCER_QOS_WARN_PRESSURE_BPS {
            overload_action = match lane.lane_kind {
                QosLaneKind::LowFee => QosOverloadAction::PreserveLowFeeShare,
                QosLaneKind::MoneroBridge => QosOverloadAction::PreserveBridgeShare,
                _ => QosOverloadAction::RequireHigherBond,
            };
            QosDecisionKind::Delay
        } else if lane.preconfirm_enabled {
            QosDecisionKind::Preconfirm
        } else {
            QosDecisionKind::Admit
        };
        let decision = QosAdmissionDecision::new(
            &request,
            decision_kind,
            overload_action,
            priority_score,
            self.height.saturating_add(1),
            credit_bucket_id,
            sequencer_qos_payload_root("QOS-SNAPSHOT", &snapshot.public_record()),
            &json!({
                "lane": lane.public_record(),
                "snapshot": snapshot.public_record(),
            }),
        )?;
        self.decisions
            .insert(decision.decision_id.clone(), decision.clone());
        Ok(decision)
    }

    pub fn preconfirm(
        &mut self,
        decision_id: &str,
        promised_state_root: &str,
        sequencer_commitment: &str,
    ) -> SequencerQosResult<QosPreconfirmationPromise> {
        let decision = self
            .decisions
            .get(decision_id)
            .cloned()
            .ok_or_else(|| "qos preconfirmation unknown decision".to_string())?;
        if decision.decision_kind != QosDecisionKind::Preconfirm {
            return Err("qos preconfirmation requires preconfirm decision".to_string());
        }
        let promise = QosPreconfirmationPromise::new(
            &decision,
            self.height
                .saturating_add(SEQUENCER_QOS_DEFAULT_PRECONFIRM_TTL_BLOCKS),
            promised_state_root,
            sequencer_commitment,
        )?;
        self.preconfirmations
            .insert(promise.promise_id.clone(), promise.clone());
        Ok(promise)
    }

    pub fn close_epoch(&mut self) -> SequencerQosResult<QosFairnessEpoch> {
        let lanes = self.lanes.values().cloned().collect::<Vec<_>>();
        let admitted = self
            .decisions
            .values()
            .filter(|decision| {
                matches!(
                    decision.decision_kind,
                    QosDecisionKind::Admit | QosDecisionKind::Preconfirm
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let delayed = self
            .decisions
            .values()
            .filter(|decision| {
                matches!(
                    decision.decision_kind,
                    QosDecisionKind::Delay | QosDecisionKind::Throttle
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let start_height = self
            .epoch
            .saturating_mul(SEQUENCER_QOS_DEFAULT_EPOCH_BLOCKS);
        let end_height = start_height.saturating_add(SEQUENCER_QOS_DEFAULT_EPOCH_BLOCKS);
        let epoch = QosFairnessEpoch::new(
            self.epoch,
            start_height,
            end_height,
            &lanes,
            &admitted,
            &delayed,
        )?;
        self.fairness_epochs
            .insert(epoch.epoch_id.clone(), epoch.clone());
        Ok(epoch)
    }

    pub fn queue_pressure_bps(&self) -> u64 {
        let total_pending = self.requests.len() as u64;
        let total_depth = self
            .lanes
            .values()
            .map(|lane| lane.max_queue_depth)
            .sum::<u64>()
            .max(1);
        ratio_bps(total_pending, total_depth).min(SEQUENCER_QOS_MAX_BPS)
    }

    pub fn state_root(&self) -> String {
        sequencer_qos_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_qos_state",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_QOS_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "lane_root": qos_lane_policy_root_from_map(&self.lanes),
            "request_root": qos_admission_request_root_from_map(&self.requests),
            "queue_snapshot_root": qos_queue_snapshot_root_from_map(&self.queue_snapshots),
            "credit_bucket_root": qos_credit_bucket_root_from_map(&self.credit_buckets),
            "decision_root": qos_admission_decision_root_from_map(&self.decisions),
            "preconfirmation_root": qos_preconfirmation_promise_root_from_map(&self.preconfirmations),
            "fairness_epoch_root": qos_fairness_epoch_root_from_map(&self.fairness_epochs),
            "lane_count": self.lanes.len() as u64,
            "request_count": self.requests.len() as u64,
            "decision_count": self.decisions.len() as u64,
            "preconfirmation_count": self.preconfirmations.len() as u64,
            "queue_pressure_bps": self.queue_pressure_bps(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn qos_lane_policy_id(
    label: &str,
    lane_kind: &QosLaneKind,
    qos_class: &QosClass,
    min_share_bps: u64,
    max_share_bps: u64,
    max_queue_depth: u64,
    burst_credits: u64,
    min_fee_units: u64,
    anti_spam_bond_units: u64,
    preconfirm_enabled: bool,
) -> String {
    domain_hash(
        "QOS-LANE-POLICY-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(&lane_kind.as_str()),
            HashPart::Str(qos_class.as_str()),
            HashPart::Int(min_share_bps as i128),
            HashPart::Int(max_share_bps as i128),
            HashPart::Int(max_queue_depth as i128),
            HashPart::Int(burst_credits as i128),
            HashPart::Int(min_fee_units as i128),
            HashPart::Int(anti_spam_bond_units as i128),
            HashPart::Int(preconfirm_enabled as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn qos_admission_request_id(
    tx_id: &str,
    lane_id: &str,
    qos_class: &QosClass,
    fee_units: u64,
    low_fee_credit_units: u64,
    anti_spam_bond_units: u64,
    privacy_root: &str,
    quantum_auth_root: &str,
    access_root: &str,
    submitted_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "QOS-ADMISSION-REQUEST-ID",
        &[
            HashPart::Str(tx_id),
            HashPart::Str(lane_id),
            HashPart::Str(qos_class.as_str()),
            HashPart::Int(fee_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
            HashPart::Int(anti_spam_bond_units as i128),
            HashPart::Str(privacy_root),
            HashPart::Str(quantum_auth_root),
            HashPart::Str(access_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn qos_queue_snapshot_id(
    height: u64,
    lane_id: &str,
    pending_count: u64,
    ready_count: u64,
    delayed_count: u64,
    admitted_count: u64,
    average_wait_blocks: u64,
    pressure_bps: u64,
) -> String {
    domain_hash(
        "QOS-QUEUE-SNAPSHOT-ID",
        &[
            HashPart::Int(height as i128),
            HashPart::Str(lane_id),
            HashPart::Int(pending_count as i128),
            HashPart::Int(ready_count as i128),
            HashPart::Int(delayed_count as i128),
            HashPart::Int(admitted_count as i128),
            HashPart::Int(average_wait_blocks as i128),
            HashPart::Int(pressure_bps as i128),
        ],
        32,
    )
}

pub fn qos_credit_bucket_id(
    lane_id: &str,
    owner_commitment: &str,
    epoch: u64,
    issued_credits: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "QOS-CREDIT-BUCKET-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(epoch as i128),
            HashPart::Int(issued_credits as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn qos_admission_decision_id(
    request_id: &str,
    lane_id: &str,
    decision_kind: &QosDecisionKind,
    overload_action: &QosOverloadAction,
    priority_score: u64,
    target_height: u64,
    credit_bucket_id: Option<&str>,
    queue_snapshot_root: &str,
    reason_root: &str,
) -> String {
    domain_hash(
        "QOS-ADMISSION-DECISION-ID",
        &[
            HashPart::Str(request_id),
            HashPart::Str(lane_id),
            HashPart::Str(decision_kind.as_str()),
            HashPart::Str(overload_action.as_str()),
            HashPart::Int(priority_score as i128),
            HashPart::Int(target_height as i128),
            HashPart::Str(credit_bucket_id.unwrap_or("none")),
            HashPart::Str(queue_snapshot_root),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn qos_preconfirmation_promise_id(
    decision_id: &str,
    request_id: &str,
    target_height: u64,
    expires_at_height: u64,
    lane_id: &str,
    priority_score: u64,
    promised_state_root: &str,
    sequencer_commitment: &str,
) -> String {
    domain_hash(
        "QOS-PRECONFIRMATION-PROMISE-ID",
        &[
            HashPart::Str(decision_id),
            HashPart::Str(request_id),
            HashPart::Int(target_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(lane_id),
            HashPart::Int(priority_score as i128),
            HashPart::Str(promised_state_root),
            HashPart::Str(sequencer_commitment),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn qos_fairness_epoch_id(
    epoch: u64,
    start_height: u64,
    end_height: u64,
    lane_share_root: &str,
    admitted_root: &str,
    delayed_root: &str,
    low_fee_share_bps: u64,
    private_share_bps: u64,
    bridge_share_bps: u64,
    fairness_score_bps: u64,
) -> String {
    domain_hash(
        "QOS-FAIRNESS-EPOCH-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(lane_share_root),
            HashPart::Str(admitted_root),
            HashPart::Str(delayed_root),
            HashPart::Int(low_fee_share_bps as i128),
            HashPart::Int(private_share_bps as i128),
            HashPart::Int(bridge_share_bps as i128),
            HashPart::Int(fairness_score_bps as i128),
        ],
        32,
    )
}

pub fn sequencer_qos_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn sequencer_qos_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn sequencer_qos_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn qos_lane_policy_root(values: &[QosLanePolicy]) -> String {
    let leaves = values
        .iter()
        .map(QosLanePolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-LANE-POLICY-ROOT", &leaves)
}

pub fn qos_admission_request_root(values: &[QosAdmissionRequest]) -> String {
    let leaves = values
        .iter()
        .map(QosAdmissionRequest::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-ADMISSION-REQUEST-ROOT", &leaves)
}

pub fn qos_queue_snapshot_root(values: &[QosQueueSnapshot]) -> String {
    let leaves = values
        .iter()
        .map(QosQueueSnapshot::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-QUEUE-SNAPSHOT-ROOT", &leaves)
}

pub fn qos_credit_bucket_root(values: &[QosCreditBucket]) -> String {
    let leaves = values
        .iter()
        .map(QosCreditBucket::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-CREDIT-BUCKET-ROOT", &leaves)
}

pub fn qos_admission_decision_root(values: &[QosAdmissionDecision]) -> String {
    let leaves = values
        .iter()
        .map(QosAdmissionDecision::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-ADMISSION-DECISION-ROOT", &leaves)
}

pub fn qos_preconfirmation_promise_root(values: &[QosPreconfirmationPromise]) -> String {
    let leaves = values
        .iter()
        .map(QosPreconfirmationPromise::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-PRECONFIRMATION-PROMISE-ROOT", &leaves)
}

pub fn qos_fairness_epoch_root(values: &[QosFairnessEpoch]) -> String {
    let leaves = values
        .iter()
        .map(QosFairnessEpoch::public_record)
        .collect::<Vec<_>>();
    merkle_root("QOS-FAIRNESS-EPOCH-ROOT", &leaves)
}

pub fn qos_lane_policy_root_from_map(values: &BTreeMap<String, QosLanePolicy>) -> String {
    qos_lane_policy_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn qos_admission_request_root_from_map(
    values: &BTreeMap<String, QosAdmissionRequest>,
) -> String {
    qos_admission_request_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn qos_queue_snapshot_root_from_map(values: &BTreeMap<String, QosQueueSnapshot>) -> String {
    qos_queue_snapshot_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn qos_credit_bucket_root_from_map(values: &BTreeMap<String, QosCreditBucket>) -> String {
    qos_credit_bucket_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn qos_admission_decision_root_from_map(
    values: &BTreeMap<String, QosAdmissionDecision>,
) -> String {
    qos_admission_decision_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn qos_preconfirmation_promise_root_from_map(
    values: &BTreeMap<String, QosPreconfirmationPromise>,
) -> String {
    qos_preconfirmation_promise_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn qos_fairness_epoch_root_from_map(values: &BTreeMap<String, QosFairnessEpoch>) -> String {
    qos_fairness_epoch_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn sequencer_qos_state_root_from_record(record: &Value) -> String {
    sequencer_qos_payload_root("SEQUENCER-QOS-STATE-ROOT", record)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return SEQUENCER_QOS_MAX_BPS;
    }
    numerator
        .saturating_mul(SEQUENCER_QOS_MAX_BPS)
        .saturating_div(denominator)
}

fn count_lane_kind(
    lanes: &[QosLanePolicy],
    decisions: &[QosAdmissionDecision],
    kind: QosLaneKind,
) -> u64 {
    let lane_ids = lanes
        .iter()
        .filter(|lane| lane.lane_kind == kind)
        .map(|lane| lane.lane_id.clone())
        .collect::<BTreeSet<_>>();
    decisions
        .iter()
        .filter(|decision| lane_ids.contains(&decision.lane_id))
        .count() as u64
}

fn ensure_non_empty(value: &str, field: &str) -> SequencerQosResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> SequencerQosResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, field: &str) -> SequencerQosResult<()> {
    if value > SEQUENCER_QOS_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}
