use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-fault-proof-rollup-challenge/v1";
pub const PQ_CONFIDENTIAL_FAULT_PROOF_ROLLUP_CHALLENGE_PROTOCOL_VERSION: &str =
    "pq-fault-proof-challenge-runtime-0.1.0-devnet";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub network: String,
    pub challenge_window_slots: u64,
    pub timeout_slots: u64,
    pub escalation_slots: u64,
    pub max_batch_items: usize,
    pub min_watcher_quorum: u32,
    pub min_bridge_evidence_items: u32,
    pub min_private_commitments: u32,
    pub max_fee_per_challenge: u64,
    pub low_fee_batch_threshold: u64,
    pub require_pq_auth: bool,
    pub require_packet_root_match: bool,
    pub require_monero_bridge_evidence: bool,
    pub release_gate_min_score: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: "devnet".to_string(),
            challenge_window_slots: 720,
            timeout_slots: 1440,
            escalation_slots: 2160,
            max_batch_items: 64,
            min_watcher_quorum: 3,
            min_bridge_evidence_items: 2,
            min_private_commitments: 1,
            max_fee_per_challenge: 20_000,
            low_fee_batch_threshold: 2_500,
            require_pq_auth: true,
            require_packet_root_match: true,
            require_monero_bridge_evidence: true,
            release_gate_min_score: 850,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChallengeStatus {
    Open,
    Batched,
    EvidencePending,
    QuorumPending,
    ReadyForAdjudication,
    TimedOut,
    Escalated,
    Accepted,
    Rejected,
    Released,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceKind {
    FraudPacketRoot,
    DisputedStateTransition,
    WatcherQuorumAttestation,
    PrivateChallengerCommitment,
    MoneroBridgeDispute,
    TimeoutEscalation,
    ReleaseGateSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub challenge_windows_opened: u64,
    pub pq_auth_packets_recorded: u64,
    pub fraud_packet_roots_recorded: u64,
    pub disputed_transitions_recorded: u64,
    pub watcher_attestations_recorded: u64,
    pub private_commitments_recorded: u64,
    pub monero_evidence_items_recorded: u64,
    pub timeout_escalations_recorded: u64,
    pub low_fee_batches_opened: u64,
    pub release_gate_summaries_recorded: u64,
    pub accepted_challenges: u64,
    pub rejected_challenges: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            challenge_windows_opened: 0,
            pq_auth_packets_recorded: 0,
            fraud_packet_roots_recorded: 0,
            disputed_transitions_recorded: 0,
            watcher_attestations_recorded: 0,
            private_commitments_recorded: 0,
            monero_evidence_items_recorded: 0,
            timeout_escalations_recorded: 0,
            low_fee_batches_opened: 0,
            release_gate_summaries_recorded: 0,
            accepted_challenges: 0,
            rejected_challenges: 0,
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub challenge_root: String,
    pub packet_root: String,
    pub dispute_root: String,
    pub watcher_root: String,
    pub bridge_root: String,
    pub release_gate_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            challenge_root: deterministic_tag("challenge", "empty"),
            packet_root: deterministic_tag("packet", "empty"),
            dispute_root: deterministic_tag("dispute", "empty"),
            watcher_root: deterministic_tag("watcher", "empty"),
            bridge_root: deterministic_tag("bridge", "empty"),
            release_gate_root: deterministic_tag("release", "empty"),
            state_root: deterministic_tag("state", "empty"),
        }
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqAuthMaterial {
    pub auth_scheme: String,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_hash: String,
    pub signer_domain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeWindowRequest {
    pub challenge_id: String,
    pub rollup_id: String,
    pub assertion_id: String,
    pub challenger_commitment: String,
    pub opened_slot: u64,
    pub fee_limit: u64,
    pub pq_auth: PqAuthMaterial,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeWindowRecord {
    pub challenge_id: String,
    pub rollup_id: String,
    pub assertion_id: String,
    pub challenger_commitment: String,
    pub opened_slot: u64,
    pub closes_slot: u64,
    pub timeout_slot: u64,
    pub escalation_slot: u64,
    pub fee_limit: u64,
    pub status: ChallengeStatus,
    pub pq_auth_root: String,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FraudProofPacketRootRecord {
    pub challenge_id: String,
    pub packet_id: String,
    pub fraud_packet_root: String,
    pub packet_count: u32,
    pub encoded_size: u64,
    pub pq_auth_root: String,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisputedStateTransitionRecord {
    pub challenge_id: String,
    pub transition_id: String,
    pub pre_state_root: String,
    pub claimed_post_state_root: String,
    pub challenger_post_state_root: String,
    pub execution_trace_root: String,
    pub local_witness_root: String,
    pub step_index: u64,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherQuorumAttestationRecord {
    pub challenge_id: String,
    pub watcher_id: String,
    pub quorum_group: String,
    pub attestation_root: String,
    pub observed_packet_root: String,
    pub observed_state_root: String,
    pub pq_auth_root: String,
    pub stake_weight: u64,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateChallengerCommitmentRecord {
    pub challenge_id: String,
    pub commitment_id: String,
    pub nullifier_hash: String,
    pub private_input_commitment: String,
    pub challenger_view_tag: String,
    pub reveal_after_slot: u64,
    pub pq_auth_root: String,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoneroBridgeDisputeEvidenceRecord {
    pub challenge_id: String,
    pub bridge_event_id: String,
    pub monero_txid_commitment: String,
    pub key_image_commitment: String,
    pub ring_member_root: String,
    pub view_tag_commitment: String,
    pub bridge_checkpoint_root: String,
    pub evidence_root: String,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutEscalationRecord {
    pub challenge_id: String,
    pub escalation_id: String,
    pub requested_slot: u64,
    pub reason: String,
    pub prior_status: ChallengeStatus,
    pub new_status: ChallengeStatus,
    pub escalation_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LowFeeChallengeBatchRecord {
    pub batch_id: String,
    pub opened_slot: u64,
    pub fee_cap: u64,
    pub challenge_ids: Vec<String>,
    pub aggregate_packet_root: String,
    pub aggregate_dispute_root: String,
    pub aggregate_auth_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseGateSummaryRecord {
    pub challenge_id: String,
    pub summary_id: String,
    pub release_score: u64,
    pub evidence_score: u64,
    pub quorum_score: u64,
    pub bridge_score: u64,
    pub timeout_score: u64,
    pub release_allowed: bool,
    pub summary_root: String,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    pub challenge_id: String,
    pub decision_id: String,
    pub accepted: bool,
    pub decision_root: String,
    pub reason: String,
    pub recorded_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub challenges: BTreeMap<String, ChallengeWindowRecord>,
    pub packet_roots: BTreeMap<String, FraudProofPacketRootRecord>,
    pub disputed_transitions: BTreeMap<String, DisputedStateTransitionRecord>,
    pub watcher_attestations: BTreeMap<String, WatcherQuorumAttestationRecord>,
    pub private_commitments: BTreeMap<String, PrivateChallengerCommitmentRecord>,
    pub monero_bridge_evidence: BTreeMap<String, MoneroBridgeDisputeEvidenceRecord>,
    pub timeout_escalations: BTreeMap<String, TimeoutEscalationRecord>,
    pub low_fee_batches: BTreeMap<String, LowFeeChallengeBatchRecord>,
    pub release_gate_summaries: BTreeMap<String, ReleaseGateSummaryRecord>,
    pub decisions: BTreeMap<String, DecisionRecord>,
    pub challenge_events: BTreeMap<String, Vec<String>>,
    pub pending_low_fee_queue: VecDeque<String>,
}

pub type Runtime = State;

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::empty(),
            challenges: BTreeMap::new(),
            packet_roots: BTreeMap::new(),
            disputed_transitions: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            private_commitments: BTreeMap::new(),
            monero_bridge_evidence: BTreeMap::new(),
            timeout_escalations: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            release_gate_summaries: BTreeMap::new(),
            decisions: BTreeMap::new(),
            challenge_events: BTreeMap::new(),
            pending_low_fee_queue: VecDeque::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let auth = PqAuthMaterial {
            auth_scheme: "ml-dsa-87+slh-dsa-sha2-256f".to_string(),
            public_key_commitment: "pqpk_demo_commitment_001".to_string(),
            signature_commitment: "pqsig_demo_commitment_001".to_string(),
            transcript_hash: "transcript_demo_hash_001".to_string(),
            signer_domain: "nebula-rollup-challenger".to_string(),
        };
        let request = ChallengeWindowRequest {
            challenge_id: "challenge_demo_001".to_string(),
            rollup_id: "rollup_devnet_private_l2".to_string(),
            assertion_id: "assertion_demo_042".to_string(),
            challenger_commitment: "challenger_commitment_demo_001".to_string(),
            opened_slot: 10,
            fee_limit: 1_900,
            pq_auth: auth.clone(),
            note: "demo disputed confidential transition".to_string(),
        };
        let _ = state.open_challenge_window(request);
        let _ = state.record_fraud_packet_root(FraudProofPacketRootRecord {
            challenge_id: "challenge_demo_001".to_string(),
            packet_id: "packet_demo_001".to_string(),
            fraud_packet_root: "fraud_packet_root_demo_001".to_string(),
            packet_count: 5,
            encoded_size: 8192,
            pq_auth_root: state.pq_auth_root(&auth),
            recorded_slot: 11,
        });
        let _ = state.record_disputed_state_transition(DisputedStateTransitionRecord {
            challenge_id: "challenge_demo_001".to_string(),
            transition_id: "transition_demo_001".to_string(),
            pre_state_root: "pre_state_root_demo_001".to_string(),
            claimed_post_state_root: "claimed_post_state_root_bad".to_string(),
            challenger_post_state_root: "challenger_post_state_root_good".to_string(),
            execution_trace_root: "execution_trace_root_demo_001".to_string(),
            local_witness_root: "local_witness_root_demo_001".to_string(),
            step_index: 17,
            recorded_slot: 12,
        });
        for idx in 0..3 {
            let _ = state.record_watcher_attestation(WatcherQuorumAttestationRecord {
                challenge_id: "challenge_demo_001".to_string(),
                watcher_id: format!("watcher_demo_{:03}", idx + 1),
                quorum_group: "devnet_watchers".to_string(),
                attestation_root: format!("watcher_attestation_root_demo_{:03}", idx + 1),
                observed_packet_root: "fraud_packet_root_demo_001".to_string(),
                observed_state_root: "challenger_post_state_root_good".to_string(),
                pq_auth_root: state.pq_auth_root(&auth),
                stake_weight: 10 + idx as u64,
                recorded_slot: 13 + idx as u64,
            });
        }
        let _ = state.record_private_challenger_commitment(PrivateChallengerCommitmentRecord {
            challenge_id: "challenge_demo_001".to_string(),
            commitment_id: "private_commitment_demo_001".to_string(),
            nullifier_hash: "nullifier_demo_001".to_string(),
            private_input_commitment: "private_input_commitment_demo_001".to_string(),
            challenger_view_tag: "view_tag_demo_001".to_string(),
            reveal_after_slot: 800,
            pq_auth_root: state.pq_auth_root(&auth),
            recorded_slot: 15,
        });
        for idx in 0..2 {
            let _ = state.record_monero_bridge_evidence(MoneroBridgeDisputeEvidenceRecord {
                challenge_id: "challenge_demo_001".to_string(),
                bridge_event_id: format!("bridge_event_demo_{:03}", idx + 1),
                monero_txid_commitment: format!("monero_txid_commitment_demo_{:03}", idx + 1),
                key_image_commitment: format!("key_image_commitment_demo_{:03}", idx + 1),
                ring_member_root: format!("ring_member_root_demo_{:03}", idx + 1),
                view_tag_commitment: format!("bridge_view_tag_demo_{:03}", idx + 1),
                bridge_checkpoint_root: "bridge_checkpoint_root_demo_001".to_string(),
                evidence_root: format!("bridge_evidence_root_demo_{:03}", idx + 1),
                recorded_slot: 16 + idx as u64,
            });
        }
        let _ = state.open_low_fee_batch("low_fee_batch_demo_001".to_string(), 18);
        let _ = state.record_release_gate_summary(
            "challenge_demo_001".to_string(),
            "release_summary_demo_001".to_string(),
            20,
        );
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_protocol_version": PQ_CONFIDENTIAL_FAULT_PROOF_ROLLUP_CHALLENGE_PROTOCOL_VERSION,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "challenge_count": self.challenges.len(),
            "packet_root_count": self.packet_roots.len(),
            "disputed_transition_count": self.disputed_transitions.len(),
            "watcher_attestation_count": self.watcher_attestations.len(),
            "private_commitment_count": self.private_commitments.len(),
            "monero_bridge_evidence_count": self.monero_bridge_evidence.len(),
            "timeout_escalation_count": self.timeout_escalations.len(),
            "low_fee_batch_count": self.low_fee_batches.len(),
            "release_gate_summary_count": self.release_gate_summaries.len(),
            "decision_count": self.decisions.len(),
            "pending_low_fee_queue": self.pending_low_fee_queue,
            "release_gate_summary": self.release_gate_overview(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn open_challenge_window(
        &mut self,
        request: ChallengeWindowRequest,
    ) -> Result<ChallengeWindowRecord, String> {
        if request.challenge_id.is_empty() {
            return Err("challenge_id is required".to_string());
        }
        if self.challenges.contains_key(&request.challenge_id) {
            return Err("challenge_id already exists".to_string());
        }
        if self.config.require_pq_auth && !self.valid_pq_auth(&request.pq_auth) {
            return Err("pq authentication material is incomplete".to_string());
        }
        let record = ChallengeWindowRecord {
            challenge_id: request.challenge_id.clone(),
            rollup_id: request.rollup_id,
            assertion_id: request.assertion_id,
            challenger_commitment: request.challenger_commitment,
            opened_slot: request.opened_slot,
            closes_slot: request
                .opened_slot
                .saturating_add(self.config.challenge_window_slots),
            timeout_slot: request
                .opened_slot
                .saturating_add(self.config.timeout_slots),
            escalation_slot: request
                .opened_slot
                .saturating_add(self.config.escalation_slots),
            fee_limit: request.fee_limit,
            status: ChallengeStatus::Open,
            pq_auth_root: self.pq_auth_root(&request.pq_auth),
            note: request.note,
        };
        if record.fee_limit <= self.config.low_fee_batch_threshold {
            self.pending_low_fee_queue
                .push_back(record.challenge_id.clone());
        }
        self.challenges
            .insert(record.challenge_id.clone(), record.clone());
        self.counters.challenge_windows_opened =
            self.counters.challenge_windows_opened.saturating_add(1);
        self.counters.pq_auth_packets_recorded =
            self.counters.pq_auth_packets_recorded.saturating_add(1);
        self.append_event(&record.challenge_id, "challenge_window_opened");
        self.refresh_status(&record.challenge_id);
        self.recompute_roots();
        Ok(record)
    }

    pub fn record_fraud_packet_root(
        &mut self,
        record: FraudProofPacketRootRecord,
    ) -> Result<(), String> {
        self.require_challenge(&record.challenge_id)?;
        if record.packet_id.is_empty() {
            return Err("packet_id is required".to_string());
        }
        if record.fraud_packet_root.is_empty() {
            return Err("fraud_packet_root is required".to_string());
        }
        let key = composite_key(&record.challenge_id, &record.packet_id);
        self.packet_roots.insert(key, record.clone());
        self.counters.fraud_packet_roots_recorded =
            self.counters.fraud_packet_roots_recorded.saturating_add(1);
        self.append_event(&record.challenge_id, "fraud_packet_root_recorded");
        self.refresh_status(&record.challenge_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn record_disputed_state_transition(
        &mut self,
        record: DisputedStateTransitionRecord,
    ) -> Result<(), String> {
        self.require_challenge(&record.challenge_id)?;
        if record.transition_id.is_empty() {
            return Err("transition_id is required".to_string());
        }
        if record.claimed_post_state_root == record.challenger_post_state_root {
            return Err("disputed transition must contain divergent post roots".to_string());
        }
        let key = composite_key(&record.challenge_id, &record.transition_id);
        self.disputed_transitions.insert(key, record.clone());
        self.counters.disputed_transitions_recorded = self
            .counters
            .disputed_transitions_recorded
            .saturating_add(1);
        self.append_event(&record.challenge_id, "disputed_state_transition_recorded");
        self.refresh_status(&record.challenge_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn record_watcher_attestation(
        &mut self,
        record: WatcherQuorumAttestationRecord,
    ) -> Result<(), String> {
        self.require_challenge(&record.challenge_id)?;
        if record.watcher_id.is_empty() {
            return Err("watcher_id is required".to_string());
        }
        if self.config.require_packet_root_match
            && !self.packet_root_exists(&record.challenge_id, &record.observed_packet_root)
        {
            return Err("watcher observed packet root has not been recorded".to_string());
        }
        let key = composite_key(&record.challenge_id, &record.watcher_id);
        self.watcher_attestations.insert(key, record.clone());
        self.counters.watcher_attestations_recorded = self
            .counters
            .watcher_attestations_recorded
            .saturating_add(1);
        self.append_event(&record.challenge_id, "watcher_quorum_attestation_recorded");
        self.refresh_status(&record.challenge_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn record_private_challenger_commitment(
        &mut self,
        record: PrivateChallengerCommitmentRecord,
    ) -> Result<(), String> {
        self.require_challenge(&record.challenge_id)?;
        if record.commitment_id.is_empty() {
            return Err("commitment_id is required".to_string());
        }
        if record.nullifier_hash.is_empty() || record.private_input_commitment.is_empty() {
            return Err("private challenger commitment is incomplete".to_string());
        }
        let key = composite_key(&record.challenge_id, &record.commitment_id);
        self.private_commitments.insert(key, record.clone());
        self.counters.private_commitments_recorded =
            self.counters.private_commitments_recorded.saturating_add(1);
        self.append_event(
            &record.challenge_id,
            "private_challenger_commitment_recorded",
        );
        self.refresh_status(&record.challenge_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn record_monero_bridge_evidence(
        &mut self,
        record: MoneroBridgeDisputeEvidenceRecord,
    ) -> Result<(), String> {
        self.require_challenge(&record.challenge_id)?;
        if record.bridge_event_id.is_empty() {
            return Err("bridge_event_id is required".to_string());
        }
        if record.key_image_commitment.is_empty() || record.ring_member_root.is_empty() {
            return Err("monero bridge evidence is incomplete".to_string());
        }
        let key = composite_key(&record.challenge_id, &record.bridge_event_id);
        self.monero_bridge_evidence.insert(key, record.clone());
        self.counters.monero_evidence_items_recorded = self
            .counters
            .monero_evidence_items_recorded
            .saturating_add(1);
        self.append_event(
            &record.challenge_id,
            "monero_bridge_dispute_evidence_recorded",
        );
        self.refresh_status(&record.challenge_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn request_timeout_escalation(
        &mut self,
        challenge_id: String,
        escalation_id: String,
        requested_slot: u64,
        reason: String,
    ) -> Result<TimeoutEscalationRecord, String> {
        let prior = self.require_challenge(&challenge_id)?.status.clone();
        let challenge = self.require_challenge(&challenge_id)?.clone();
        let new_status = if requested_slot >= challenge.escalation_slot {
            ChallengeStatus::Escalated
        } else if requested_slot >= challenge.timeout_slot {
            ChallengeStatus::TimedOut
        } else {
            return Err("requested_slot is before timeout".to_string());
        };
        let root = deterministic_json_root(
            "timeout_escalation",
            &json!({
                "challenge_id": challenge_id,
                "escalation_id": escalation_id,
                "requested_slot": requested_slot,
                "reason": reason,
                "prior_status": prior,
                "new_status": new_status,
            }),
        );
        let record = TimeoutEscalationRecord {
            challenge_id: challenge_id.clone(),
            escalation_id,
            requested_slot,
            reason,
            prior_status: prior,
            new_status: new_status.clone(),
            escalation_root: root,
        };
        self.timeout_escalations.insert(
            composite_key(&challenge_id, &record.escalation_id),
            record.clone(),
        );
        self.set_status(&challenge_id, new_status);
        self.counters.timeout_escalations_recorded =
            self.counters.timeout_escalations_recorded.saturating_add(1);
        self.append_event(&challenge_id, "timeout_escalation_recorded");
        self.recompute_roots();
        Ok(record)
    }

    pub fn open_low_fee_batch(
        &mut self,
        batch_id: String,
        opened_slot: u64,
    ) -> Result<LowFeeChallengeBatchRecord, String> {
        if batch_id.is_empty() {
            return Err("batch_id is required".to_string());
        }
        if self.low_fee_batches.contains_key(&batch_id) {
            return Err("batch_id already exists".to_string());
        }
        let mut challenge_ids = Vec::new();
        while challenge_ids.len() < self.config.max_batch_items {
            match self.pending_low_fee_queue.pop_front() {
                Some(id) => {
                    if self.challenges.contains_key(&id) && !challenge_ids.contains(&id) {
                        challenge_ids.push(id);
                    }
                }
                None => break,
            }
        }
        if challenge_ids.is_empty() {
            return Err("no low-fee challenges are pending".to_string());
        }
        for challenge_id in &challenge_ids {
            self.set_status(challenge_id, ChallengeStatus::Batched);
            self.append_event(challenge_id, "low_fee_challenge_batched");
        }
        let aggregate_packet_root = self.aggregate_packet_root(&challenge_ids);
        let aggregate_dispute_root = self.aggregate_dispute_root(&challenge_ids);
        let aggregate_auth_root = self.aggregate_auth_root(&challenge_ids);
        let record = LowFeeChallengeBatchRecord {
            batch_id: batch_id.clone(),
            opened_slot,
            fee_cap: self.config.low_fee_batch_threshold,
            challenge_ids,
            aggregate_packet_root,
            aggregate_dispute_root,
            aggregate_auth_root,
        };
        self.low_fee_batches.insert(batch_id, record.clone());
        self.counters.low_fee_batches_opened =
            self.counters.low_fee_batches_opened.saturating_add(1);
        self.recompute_roots();
        Ok(record)
    }

    pub fn record_release_gate_summary(
        &mut self,
        challenge_id: String,
        summary_id: String,
        recorded_slot: u64,
    ) -> Result<ReleaseGateSummaryRecord, String> {
        self.require_challenge(&challenge_id)?;
        let evidence_score = self.evidence_score(&challenge_id);
        let quorum_score = self.quorum_score(&challenge_id);
        let bridge_score = self.bridge_score(&challenge_id);
        let timeout_score = self.timeout_score(&challenge_id);
        let release_score = evidence_score
            .saturating_add(quorum_score)
            .saturating_add(bridge_score)
            .saturating_add(timeout_score);
        let release_allowed = release_score >= self.config.release_gate_min_score
            && self.challenge_ready(&challenge_id);
        let summary_root = deterministic_json_root(
            "release_gate_summary",
            &json!({
                "challenge_id": challenge_id,
                "summary_id": summary_id,
                "release_score": release_score,
                "evidence_score": evidence_score,
                "quorum_score": quorum_score,
                "bridge_score": bridge_score,
                "timeout_score": timeout_score,
                "release_allowed": release_allowed,
                "recorded_slot": recorded_slot,
            }),
        );
        let record = ReleaseGateSummaryRecord {
            challenge_id: challenge_id.clone(),
            summary_id,
            release_score,
            evidence_score,
            quorum_score,
            bridge_score,
            timeout_score,
            release_allowed,
            summary_root,
            recorded_slot,
        };
        self.release_gate_summaries.insert(
            composite_key(&challenge_id, &record.summary_id),
            record.clone(),
        );
        self.counters.release_gate_summaries_recorded = self
            .counters
            .release_gate_summaries_recorded
            .saturating_add(1);
        if release_allowed {
            self.set_status(&challenge_id, ChallengeStatus::Released);
        }
        self.append_event(&challenge_id, "release_gate_summary_recorded");
        self.recompute_roots();
        Ok(record)
    }

    pub fn decide_challenge(
        &mut self,
        challenge_id: String,
        decision_id: String,
        accepted: bool,
        reason: String,
        recorded_slot: u64,
    ) -> Result<DecisionRecord, String> {
        self.require_challenge(&challenge_id)?;
        if !self.challenge_ready(&challenge_id) {
            return Err("challenge is not ready for decision".to_string());
        }
        let decision_root = deterministic_json_root(
            "decision",
            &json!({
                "challenge_id": challenge_id,
                "decision_id": decision_id,
                "accepted": accepted,
                "reason": reason,
                "recorded_slot": recorded_slot,
            }),
        );
        let record = DecisionRecord {
            challenge_id: challenge_id.clone(),
            decision_id,
            accepted,
            decision_root,
            reason,
            recorded_slot,
        };
        self.decisions.insert(
            composite_key(&challenge_id, &record.decision_id),
            record.clone(),
        );
        if accepted {
            self.set_status(&challenge_id, ChallengeStatus::Accepted);
            self.counters.accepted_challenges = self.counters.accepted_challenges.saturating_add(1);
        } else {
            self.set_status(&challenge_id, ChallengeStatus::Rejected);
            self.counters.rejected_challenges = self.counters.rejected_challenges.saturating_add(1);
        }
        self.append_event(&challenge_id, "challenge_decision_recorded");
        self.recompute_roots();
        Ok(record)
    }

    pub fn challenge_ready(&self, challenge_id: &str) -> bool {
        let has_packet = self
            .packet_roots
            .values()
            .any(|r| r.challenge_id == challenge_id);
        let has_transition = self
            .disputed_transitions
            .values()
            .any(|r| r.challenge_id == challenge_id);
        let watchers = self.distinct_watchers(challenge_id);
        let commitments = self
            .private_commitments
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .count() as u32;
        let bridge_items = self
            .monero_bridge_evidence
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .count() as u32;
        let bridge_ok = !self.config.require_monero_bridge_evidence
            || bridge_items >= self.config.min_bridge_evidence_items;
        has_packet
            && has_transition
            && watchers.len() as u32 >= self.config.min_watcher_quorum
            && commitments >= self.config.min_private_commitments
            && bridge_ok
    }

    pub fn challenge_snapshot(&self, challenge_id: &str) -> Value {
        json!({
            "challenge": self.challenges.get(challenge_id),
            "packets": self.records_for_challenge_packet(challenge_id),
            "transitions": self.records_for_challenge_transition(challenge_id),
            "watchers": self.records_for_challenge_watcher(challenge_id),
            "private_commitments": self.records_for_challenge_private(challenge_id),
            "monero_bridge_evidence": self.records_for_challenge_bridge(challenge_id),
            "timeouts": self.records_for_challenge_timeout(challenge_id),
            "release_summaries": self.records_for_challenge_release(challenge_id),
            "events": self.challenge_events.get(challenge_id),
            "ready": self.challenge_ready(challenge_id),
            "score": {
                "evidence": self.evidence_score(challenge_id),
                "quorum": self.quorum_score(challenge_id),
                "bridge": self.bridge_score(challenge_id),
                "timeout": self.timeout_score(challenge_id),
            },
        })
    }

    fn require_challenge(&self, challenge_id: &str) -> Result<&ChallengeWindowRecord, String> {
        match self.challenges.get(challenge_id) {
            Some(record) => Ok(record),
            None => Err("challenge_id is unknown".to_string()),
        }
    }

    fn set_status(&mut self, challenge_id: &str, status: ChallengeStatus) {
        if let Some(record) = self.challenges.get_mut(challenge_id) {
            record.status = status;
        }
    }

    fn refresh_status(&mut self, challenge_id: &str) {
        let current = self.challenges.get(challenge_id).map(|r| r.status.clone());
        if matches!(
            current,
            Some(ChallengeStatus::Accepted)
                | Some(ChallengeStatus::Rejected)
                | Some(ChallengeStatus::Released)
                | Some(ChallengeStatus::TimedOut)
                | Some(ChallengeStatus::Escalated)
        ) {
            return;
        }
        if self.challenge_ready(challenge_id) {
            self.set_status(challenge_id, ChallengeStatus::ReadyForAdjudication);
            return;
        }
        let has_packet = self
            .packet_roots
            .values()
            .any(|r| r.challenge_id == challenge_id);
        let has_transition = self
            .disputed_transitions
            .values()
            .any(|r| r.challenge_id == challenge_id);
        if has_packet && has_transition {
            self.set_status(challenge_id, ChallengeStatus::QuorumPending);
            return;
        }
        if has_packet {
            self.set_status(challenge_id, ChallengeStatus::EvidencePending);
        }
    }

    fn append_event(&mut self, challenge_id: &str, event: &str) {
        self.challenge_events
            .entry(challenge_id.to_string())
            .or_insert_with(Vec::new)
            .push(event.to_string());
    }

    fn valid_pq_auth(&self, auth: &PqAuthMaterial) -> bool {
        !auth.auth_scheme.is_empty()
            && !auth.public_key_commitment.is_empty()
            && !auth.signature_commitment.is_empty()
            && !auth.transcript_hash.is_empty()
            && !auth.signer_domain.is_empty()
    }

    fn pq_auth_root(&self, auth: &PqAuthMaterial) -> String {
        deterministic_json_root("pq_auth", &json!(auth))
    }

    fn packet_root_exists(&self, challenge_id: &str, packet_root: &str) -> bool {
        self.packet_roots.values().any(|record| {
            record.challenge_id == challenge_id && record.fraud_packet_root == packet_root
        })
    }

    fn distinct_watchers(&self, challenge_id: &str) -> BTreeSet<String> {
        self.watcher_attestations
            .values()
            .filter(|record| record.challenge_id == challenge_id)
            .map(|record| record.watcher_id.clone())
            .collect()
    }

    fn evidence_score(&self, challenge_id: &str) -> u64 {
        let packets = self
            .packet_roots
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .count() as u64;
        let transitions = self
            .disputed_transitions
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .count() as u64;
        packets
            .saturating_mul(120)
            .saturating_add(transitions.saturating_mul(180))
    }

    fn quorum_score(&self, challenge_id: &str) -> u64 {
        let distinct = self.distinct_watchers(challenge_id).len() as u64;
        let stake = self
            .watcher_attestations
            .values()
            .filter(|record| record.challenge_id == challenge_id)
            .fold(0_u64, |acc, record| acc.saturating_add(record.stake_weight));
        distinct.saturating_mul(90).saturating_add(stake.min(250))
    }

    fn bridge_score(&self, challenge_id: &str) -> u64 {
        self.monero_bridge_evidence
            .values()
            .filter(|record| record.challenge_id == challenge_id)
            .count() as u64
            * 140
    }

    fn timeout_score(&self, challenge_id: &str) -> u64 {
        self.timeout_escalations
            .values()
            .filter(|record| record.challenge_id == challenge_id)
            .map(|record| match record.new_status {
                ChallengeStatus::Escalated => 220,
                ChallengeStatus::TimedOut => 120,
                _ => 0,
            })
            .fold(0_u64, |acc, score| acc.saturating_add(score))
    }

    fn records_for_challenge_packet(&self, challenge_id: &str) -> Vec<FraudProofPacketRootRecord> {
        self.packet_roots
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn records_for_challenge_transition(
        &self,
        challenge_id: &str,
    ) -> Vec<DisputedStateTransitionRecord> {
        self.disputed_transitions
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn records_for_challenge_watcher(
        &self,
        challenge_id: &str,
    ) -> Vec<WatcherQuorumAttestationRecord> {
        self.watcher_attestations
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn records_for_challenge_private(
        &self,
        challenge_id: &str,
    ) -> Vec<PrivateChallengerCommitmentRecord> {
        self.private_commitments
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn records_for_challenge_bridge(
        &self,
        challenge_id: &str,
    ) -> Vec<MoneroBridgeDisputeEvidenceRecord> {
        self.monero_bridge_evidence
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn records_for_challenge_timeout(&self, challenge_id: &str) -> Vec<TimeoutEscalationRecord> {
        self.timeout_escalations
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn records_for_challenge_release(&self, challenge_id: &str) -> Vec<ReleaseGateSummaryRecord> {
        self.release_gate_summaries
            .values()
            .filter(|r| r.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    fn aggregate_packet_root(&self, challenge_ids: &[String]) -> String {
        let records: Vec<Value> = challenge_ids
            .iter()
            .map(|id| json!({ "challenge_id": id, "packets": self.records_for_challenge_packet(id) }))
            .collect();
        deterministic_json_root("aggregate_packet_root", &json!(records))
    }

    fn aggregate_dispute_root(&self, challenge_ids: &[String]) -> String {
        let records: Vec<Value> = challenge_ids
            .iter()
            .map(|id| json!({ "challenge_id": id, "transitions": self.records_for_challenge_transition(id) }))
            .collect();
        deterministic_json_root("aggregate_dispute_root", &json!(records))
    }

    fn aggregate_auth_root(&self, challenge_ids: &[String]) -> String {
        let records: Vec<Value> = challenge_ids
            .iter()
            .filter_map(|id| self.challenges.get(id))
            .map(|record| {
                json!({
                    "challenge_id": record.challenge_id,
                    "pq_auth_root": record.pq_auth_root,
                    "challenger_commitment": record.challenger_commitment,
                })
            })
            .collect();
        deterministic_json_root("aggregate_auth_root", &json!(records))
    }

    fn release_gate_overview(&self) -> Value {
        let released = self
            .release_gate_summaries
            .values()
            .filter(|record| record.release_allowed)
            .count();
        let blocked = self.release_gate_summaries.len().saturating_sub(released);
        json!({
            "released": released,
            "blocked": blocked,
            "min_score": self.config.release_gate_min_score,
            "latest_roots": {
                "release_gate_root": self.roots.release_gate_root,
                "state_root": self.roots.state_root,
            },
        })
    }

    fn recompute_roots(&mut self) {
        self.roots.challenge_root = deterministic_json_root("challenges", &json!(self.challenges));
        self.roots.packet_root = deterministic_json_root("packet_roots", &json!(self.packet_roots));
        self.roots.dispute_root =
            deterministic_json_root("disputed_transitions", &json!(self.disputed_transitions));
        self.roots.watcher_root =
            deterministic_json_root("watcher_attestations", &json!(self.watcher_attestations));
        self.roots.bridge_root = deterministic_json_root(
            "monero_bridge_evidence",
            &json!(self.monero_bridge_evidence),
        );
        self.roots.release_gate_root = deterministic_json_root(
            "release_gate_summaries",
            &json!(self.release_gate_summaries),
        );
        self.roots.state_root = deterministic_json_root(
            "state",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "module_protocol_version": PQ_CONFIDENTIAL_FAULT_PROOF_ROLLUP_CHALLENGE_PROTOCOL_VERSION,
                "config": self.config,
                "counters": self.counters,
                "challenge_root": self.roots.challenge_root,
                "packet_root": self.roots.packet_root,
                "dispute_root": self.roots.dispute_root,
                "watcher_root": self.roots.watcher_root,
                "bridge_root": self.roots.bridge_root,
                "release_gate_root": self.roots.release_gate_root,
                "decision_root": deterministic_json_root("decisions", &json!(self.decisions)),
                "batch_root": deterministic_json_root("low_fee_batches", &json!(self.low_fee_batches)),
            }),
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

fn composite_key(left: &str, right: &str) -> String {
    let mut key = String::with_capacity(left.len().saturating_add(right.len()).saturating_add(2));
    key.push_str(left);
    key.push_str("::");
    key.push_str(right);
    key
}

fn deterministic_tag(domain: &str, body: &str) -> String {
    deterministic_bytes_root(domain, body.as_bytes())
}

fn deterministic_json_root(domain: &str, value: &Value) -> String {
    deterministic_tag(domain, &canonical_json(value))
}

fn deterministic_bytes_root(domain: &str, bytes: &[u8]) -> String {
    let mut a: u64 = 0x243f_6a88_85a3_08d3;
    let mut b: u64 = 0x1319_8a2e_0370_7344;
    let mut c: u64 = 0xa409_3822_299f_31d0;
    let mut d: u64 = 0x082e_fa98_ec4e_6c89;
    for byte in domain.as_bytes().iter().chain(bytes.iter()) {
        let x = *byte as u64;
        a = a.rotate_left(5) ^ x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        b = b.rotate_left(7).wrapping_add(a ^ x);
        c ^= b
            .rotate_left(11)
            .wrapping_add(x.wrapping_mul(0x1000_0000_01b3));
        d = d.wrapping_add(c ^ a).rotate_left(13);
    }
    format!("droot_{:016x}{:016x}{:016x}{:016x}", a, b, c, d)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(v) => v.to_string(),
        Value::String(v) => canonical_string(v),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            let mut out = String::from("{");
            for (idx, (key, item)) in map.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_string(key));
                out.push(':');
                out.push_str(&canonical_json(item));
            }
            out.push('}');
            out
        }
    }
}

fn canonical_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
