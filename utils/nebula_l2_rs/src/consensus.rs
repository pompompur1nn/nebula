use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::{L2Block, Validator},
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_validator_authorization,
        verify_validator_authorization, Authorization, CryptoRole,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConsensusResult<T> = Result<T, String>;

pub const CONSENSUS_DEFAULT_EPOCH_LENGTH: u64 = 10;
pub const CONSENSUS_FAST_FINALITY_QUORUM_BPS: u64 = 6_667;
pub const CONSENSUS_EQUIVOCATION_SLASH_BPS: u64 = 2_500;
pub const CONSENSUS_DOWNTIME_SLASH_BPS: u64 = 250;
pub const CONSENSUS_DOWNTIME_GRACE_SLOTS: u64 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorStakeRecord {
    pub validator_id: String,
    pub label: String,
    pub consensus_public_key: String,
    pub network_public_key: String,
    pub bonded_stake: u64,
    pub delegated_stake: u64,
    pub effective_stake: u64,
    pub activation_height: u64,
    pub exit_requested_height: u64,
    pub exit_effective_height: u64,
    pub slashed_stake: u64,
    pub reward_units: u64,
    pub penalty_units: u64,
    pub produced_slot_count: u64,
    pub voted_block_count: u64,
    pub missed_slot_count: u64,
    pub status: String,
}

impl ValidatorStakeRecord {
    pub fn from_validator(validator: &Validator, activation_height: u64) -> Self {
        Self {
            validator_id: validator.validator_id.clone(),
            label: validator.label.clone(),
            consensus_public_key: validator.consensus_public_key.clone(),
            network_public_key: validator.network_public_key.clone(),
            bonded_stake: validator.stake,
            delegated_stake: 0,
            effective_stake: validator.stake,
            activation_height,
            exit_requested_height: 0,
            exit_effective_height: 0,
            slashed_stake: validator.slashed_stake,
            reward_units: 0,
            penalty_units: 0,
            produced_slot_count: 0,
            voted_block_count: 0,
            missed_slot_count: validator.omission_count,
            status: validator.status.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_stake_record",
            "chain_id": CHAIN_ID,
            "validator_id": self.validator_id,
            "label": self.label,
            "consensus_public_key": self.consensus_public_key,
            "network_public_key": self.network_public_key,
            "bonded_stake": self.bonded_stake,
            "delegated_stake": self.delegated_stake,
            "effective_stake": self.effective_stake,
            "activation_height": self.activation_height,
            "exit_requested_height": self.exit_requested_height,
            "exit_effective_height": self.exit_effective_height,
            "slashed_stake": self.slashed_stake,
            "reward_units": self.reward_units,
            "penalty_units": self.penalty_units,
            "produced_slot_count": self.produced_slot_count,
            "voted_block_count": self.voted_block_count,
            "missed_slot_count": self.missed_slot_count,
            "status": self.status,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.activation_height <= height
            && (self.exit_effective_height == 0 || height < self.exit_effective_height)
            && self.effective_stake > 0
    }

    pub fn request_exit(&self, requested_height: u64, exit_delay: u64) -> Self {
        Self {
            status: "exiting".to_string(),
            exit_requested_height: requested_height,
            exit_effective_height: requested_height.saturating_add(exit_delay),
            ..self.clone()
        }
    }

    pub fn apply_reward(&self, reward_units: u64) -> Self {
        Self {
            reward_units: self.reward_units.saturating_add(reward_units),
            ..self.clone()
        }
    }

    pub fn apply_missed_slots(&self, missed_slots: u64) -> Self {
        Self {
            missed_slot_count: self.missed_slot_count.saturating_add(missed_slots),
            ..self.clone()
        }
    }

    pub fn apply_vote_credit(&self) -> Self {
        Self {
            voted_block_count: self.voted_block_count.saturating_add(1),
            ..self.clone()
        }
    }

    pub fn apply_proposer_credit(&self) -> Self {
        Self {
            produced_slot_count: self.produced_slot_count.saturating_add(1),
            ..self.clone()
        }
    }

    pub fn slash(&self, slash_amount: u64, penalty_units: u64, reason_status: &str) -> Self {
        let slash_amount = std::cmp::min(slash_amount, self.effective_stake);
        let effective_stake = self.effective_stake.saturating_sub(slash_amount);
        Self {
            effective_stake,
            slashed_stake: self.slashed_stake.saturating_add(slash_amount),
            penalty_units: self.penalty_units.saturating_add(penalty_units),
            status: if effective_stake == 0 {
                "slashed_out".to_string()
            } else {
                reason_status.to_string()
            },
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetSnapshot {
    pub height: u64,
    pub epoch: u64,
    pub epoch_length: u64,
    pub quorum_bps: u64,
    pub active_validator_count: u64,
    pub total_effective_stake: u64,
    pub quorum_stake: u64,
    pub validator_root: String,
    pub proposer_schedule_root: String,
    pub finality_certificate_root: String,
    pub status: String,
}

impl ValidatorSetSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_set_snapshot",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "epoch_length": self.epoch_length,
            "quorum_bps": self.quorum_bps,
            "active_validator_count": self.active_validator_count,
            "total_effective_stake": self.total_effective_stake,
            "quorum_stake": self.quorum_stake,
            "validator_root": self.validator_root,
            "proposer_schedule_root": self.proposer_schedule_root,
            "finality_certificate_root": self.finality_certificate_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerSlot {
    pub slot_id: String,
    pub height: u64,
    pub epoch: u64,
    pub round: u64,
    pub proposer_validator_id: String,
    pub proposer_label: String,
    pub proposer_stake: u64,
    pub total_stake: u64,
    pub previous_block_hash: String,
    pub selection_seed: String,
    pub selection_weight: u64,
    pub status: String,
}

impl ProposerSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proposer_slot",
            "chain_id": CHAIN_ID,
            "slot_id": self.slot_id,
            "height": self.height,
            "epoch": self.epoch,
            "round": self.round,
            "proposer_validator_id": self.proposer_validator_id,
            "proposer_label": self.proposer_label,
            "proposer_stake": self.proposer_stake,
            "total_stake": self.total_stake,
            "previous_block_hash": self.previous_block_hash,
            "selection_seed": self.selection_seed,
            "selection_weight": self.selection_weight,
            "status": self.status,
        })
    }

    pub fn slot_root(&self) -> String {
        domain_hash(
            "PROPOSER-SLOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityVote {
    pub vote_id: String,
    pub block_height: u64,
    pub round: u64,
    pub block_hash: String,
    pub state_root: String,
    pub validator_id: String,
    pub validator_label: String,
    pub consensus_public_key: String,
    pub stake_weight: u64,
    pub signed_at_height: u64,
    pub authorization: Authorization,
}

impl FastFinalityVote {
    pub fn new(
        block_height: u64,
        round: u64,
        block_hash: &str,
        state_root: &str,
        validator: &ValidatorStakeRecord,
        signed_at_height: u64,
    ) -> ConsensusResult<Self> {
        if !validator.is_active_at(signed_at_height) {
            return Err("validator is not active for fast finality vote".to_string());
        }
        let vote_id = fast_finality_vote_id(
            block_height,
            round,
            block_hash,
            &validator.validator_id,
            &validator.consensus_public_key,
        );
        let mut vote = Self {
            vote_id,
            block_height,
            round,
            block_hash: block_hash.to_string(),
            state_root: state_root.to_string(),
            validator_id: validator.validator_id.clone(),
            validator_label: validator.label.clone(),
            consensus_public_key: validator.consensus_public_key.clone(),
            stake_weight: validator.effective_stake,
            signed_at_height,
            authorization: Authorization {
                signer_label: validator.label.clone(),
                auth_scheme: CryptoRole::ValidatorSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        vote.authorization = sign_validator_authorization(
            &vote.validator_label,
            "fast_finality_vote",
            &vote.unsigned_record(),
        );
        if !vote.verify_authorization() {
            return Err("fast finality vote authorization failed".to_string());
        }
        Ok(vote)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "fast_finality_vote",
            "chain_id": CHAIN_ID,
            "vote_id": self.vote_id,
            "block_height": self.block_height,
            "round": self.round,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "validator_id": self.validator_id,
            "validator_label": self.validator_label,
            "consensus_public_key": self.consensus_public_key,
            "stake_weight": self.stake_weight,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn vote_root(&self) -> String {
        domain_hash(
            "FAST-FINALITY-VOTE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("fast finality vote record object");
        object.insert("vote_root".to_string(), Value::String(self.vote_root()));
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.consensus_public_key,
            "fast_finality_vote",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificate {
    pub certificate_id: String,
    pub block_height: u64,
    pub round: u64,
    pub block_hash: String,
    pub state_root: String,
    pub total_stake: u64,
    pub voted_stake: u64,
    pub quorum_stake: u64,
    pub quorum_bps: u64,
    pub vote_root: String,
    pub voter_root: String,
    pub voters: Vec<String>,
    pub certified_at_height: u64,
    pub status: String,
}

impl FinalityCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_height: u64,
        round: u64,
        block_hash: &str,
        state_root: &str,
        total_stake: u64,
        quorum_stake: u64,
        quorum_bps: u64,
        votes: &[FastFinalityVote],
        certified_at_height: u64,
    ) -> ConsensusResult<Self> {
        if total_stake == 0 {
            return Err("cannot build finality certificate without validator stake".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut voters = Vec::new();
        let mut voted_stake = 0_u64;
        for vote in votes {
            if vote.block_height != block_height
                || vote.round != round
                || vote.block_hash != block_hash
                || vote.state_root != state_root
            {
                return Err("finality certificate vote target mismatch".to_string());
            }
            if !vote.verify_authorization() {
                return Err("invalid fast finality vote authorization".to_string());
            }
            if seen.insert(vote.validator_id.clone()) {
                voters.push(vote.validator_id.clone());
                voted_stake = voted_stake.saturating_add(vote.stake_weight);
            }
        }
        if voted_stake < quorum_stake {
            return Err("not enough stake for fast finality certificate".to_string());
        }
        voters.sort();
        let vote_root = merkle_root(
            "FINALITY-CERTIFICATE-VOTE",
            &votes
                .iter()
                .map(FastFinalityVote::public_record)
                .collect::<Vec<_>>(),
        );
        let voter_root = merkle_root(
            "FINALITY-CERTIFICATE-VOTER",
            &voters
                .iter()
                .map(|voter| Value::String(voter.clone()))
                .collect::<Vec<_>>(),
        );
        let certificate_id =
            finality_certificate_id(block_height, round, block_hash, state_root, &vote_root);
        Ok(Self {
            certificate_id,
            block_height,
            round,
            block_hash: block_hash.to_string(),
            state_root: state_root.to_string(),
            total_stake,
            voted_stake,
            quorum_stake,
            quorum_bps,
            vote_root,
            voter_root,
            voters,
            certified_at_height,
            status: "final".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_certificate",
            "chain_id": CHAIN_ID,
            "certificate_id": self.certificate_id,
            "certificate_root": self.certificate_root(),
            "block_height": self.block_height,
            "round": self.round,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "total_stake": self.total_stake,
            "voted_stake": self.voted_stake,
            "quorum_stake": self.quorum_stake,
            "quorum_bps": self.quorum_bps,
            "vote_root": self.vote_root,
            "voter_root": self.voter_root,
            "voter_count": self.voters.len() as u64,
            "certified_at_height": self.certified_at_height,
            "status": self.status,
        })
    }

    pub fn certificate_root(&self) -> String {
        domain_hash(
            "FAST-FINALITY-CERTIFICATE",
            &[HashPart::Json(&json!({
                "certificate_id": self.certificate_id,
                "block_height": self.block_height,
                "round": self.round,
                "block_hash": self.block_hash,
                "state_root": self.state_root,
                "total_stake": self.total_stake,
                "voted_stake": self.voted_stake,
                "quorum_stake": self.quorum_stake,
                "quorum_bps": self.quorum_bps,
                "vote_root": self.vote_root,
                "voter_root": self.voter_root,
                "certified_at_height": self.certified_at_height,
                "status": self.status,
            }))],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub evidence_id: String,
    pub validator_id: String,
    pub validator_label: String,
    pub block_height: u64,
    pub round: u64,
    pub left_vote_root: String,
    pub right_vote_root: String,
    pub left_block_hash: String,
    pub right_block_hash: String,
    pub slash_amount: u64,
    pub reporter_label: String,
    pub reporter_public_key: String,
    pub reported_at_height: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl EquivocationEvidence {
    pub fn new(
        left: &FastFinalityVote,
        right: &FastFinalityVote,
        slash_amount: u64,
        reporter_label: &str,
        reported_at_height: u64,
    ) -> ConsensusResult<Self> {
        if left.validator_id != right.validator_id
            || left.block_height != right.block_height
            || left.round != right.round
        {
            return Err(
                "equivocation evidence requires two votes by the same validator for one round"
                    .to_string(),
            );
        }
        if left.block_hash == right.block_hash && left.state_root == right.state_root {
            return Err("equivocation evidence requires conflicting vote targets".to_string());
        }
        let reporter_key = public_key_for_label(CryptoRole::ValidatorSignature, reporter_label);
        let evidence_id = equivocation_evidence_id(
            &left.validator_id,
            left.block_height,
            left.round,
            &left.vote_root(),
            &right.vote_root(),
        );
        let mut evidence = Self {
            evidence_id,
            validator_id: left.validator_id.clone(),
            validator_label: left.validator_label.clone(),
            block_height: left.block_height,
            round: left.round,
            left_vote_root: left.vote_root(),
            right_vote_root: right.vote_root(),
            left_block_hash: left.block_hash.clone(),
            right_block_hash: right.block_hash.clone(),
            slash_amount,
            reporter_label: reporter_label.to_string(),
            reporter_public_key: reporter_key.public_key,
            reported_at_height,
            status: "slashable".to_string(),
            authorization: Authorization {
                signer_label: reporter_label.to_string(),
                auth_scheme: CryptoRole::ValidatorSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        evidence.authorization = sign_validator_authorization(
            reporter_label,
            "equivocation_evidence",
            &evidence.unsigned_record(),
        );
        if !evidence.verify_authorization() {
            return Err("equivocation evidence authorization failed".to_string());
        }
        Ok(evidence)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "equivocation_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "validator_id": self.validator_id,
            "validator_label": self.validator_label,
            "block_height": self.block_height,
            "round": self.round,
            "left_vote_root": self.left_vote_root,
            "right_vote_root": self.right_vote_root,
            "left_block_hash": self.left_block_hash,
            "right_block_hash": self.right_block_hash,
            "slash_amount": self.slash_amount,
            "reporter_label": self.reporter_label,
            "reporter_public_key": self.reporter_public_key,
            "reported_at_height": self.reported_at_height,
            "status": self.status,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("equivocation evidence record object");
        object.insert(
            "evidence_root".to_string(),
            Value::String(self.evidence_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "EQUIVOCATION-EVIDENCE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.reporter_public_key,
            "equivocation_evidence",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DowntimeEvidence {
    pub evidence_id: String,
    pub validator_id: String,
    pub validator_label: String,
    pub missed_from_height: u64,
    pub missed_to_height: u64,
    pub missed_slot_count: u64,
    pub grace_slots: u64,
    pub slash_amount: u64,
    pub reporter_label: String,
    pub reporter_public_key: String,
    pub reported_at_height: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl DowntimeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator: &ValidatorStakeRecord,
        missed_from_height: u64,
        missed_to_height: u64,
        grace_slots: u64,
        slash_amount: u64,
        reporter_label: &str,
        reported_at_height: u64,
    ) -> ConsensusResult<Self> {
        if missed_to_height < missed_from_height {
            return Err("downtime evidence range is inverted".to_string());
        }
        let missed_slot_count = missed_to_height - missed_from_height + 1;
        let reporter_key = public_key_for_label(CryptoRole::ValidatorSignature, reporter_label);
        let evidence_id = downtime_evidence_id(
            &validator.validator_id,
            missed_from_height,
            missed_to_height,
            missed_slot_count,
        );
        let mut evidence = Self {
            evidence_id,
            validator_id: validator.validator_id.clone(),
            validator_label: validator.label.clone(),
            missed_from_height,
            missed_to_height,
            missed_slot_count,
            grace_slots,
            slash_amount,
            reporter_label: reporter_label.to_string(),
            reporter_public_key: reporter_key.public_key,
            reported_at_height,
            status: if missed_slot_count > grace_slots {
                "slashable"
            } else {
                "warning"
            }
            .to_string(),
            authorization: Authorization {
                signer_label: reporter_label.to_string(),
                auth_scheme: CryptoRole::ValidatorSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        evidence.authorization = sign_validator_authorization(
            reporter_label,
            "downtime_evidence",
            &evidence.unsigned_record(),
        );
        if !evidence.verify_authorization() {
            return Err("downtime evidence authorization failed".to_string());
        }
        Ok(evidence)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "downtime_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "validator_id": self.validator_id,
            "validator_label": self.validator_label,
            "missed_from_height": self.missed_from_height,
            "missed_to_height": self.missed_to_height,
            "missed_slot_count": self.missed_slot_count,
            "grace_slots": self.grace_slots,
            "slash_amount": self.slash_amount,
            "reporter_label": self.reporter_label,
            "reporter_public_key": self.reporter_public_key,
            "reported_at_height": self.reported_at_height,
            "status": self.status,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("downtime evidence record object");
        object.insert(
            "evidence_root".to_string(),
            Value::String(self.evidence_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "DOWNTIME-EVIDENCE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.reporter_public_key,
            "downtime_evidence",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    pub current_height: u64,
    pub epoch_length: u64,
    pub quorum_bps: u64,
    pub validators: BTreeMap<String, ValidatorStakeRecord>,
    pub proposer_slots: BTreeMap<String, ProposerSlot>,
    pub votes: BTreeMap<String, FastFinalityVote>,
    pub finality_certificates: BTreeMap<String, FinalityCertificate>,
    pub equivocation_evidence: BTreeMap<String, EquivocationEvidence>,
    pub downtime_evidence: BTreeMap<String, DowntimeEvidence>,
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new(
            CONSENSUS_DEFAULT_EPOCH_LENGTH,
            CONSENSUS_FAST_FINALITY_QUORUM_BPS,
        )
    }
}

impl ConsensusState {
    pub fn new(epoch_length: u64, quorum_bps: u64) -> Self {
        Self {
            current_height: 0,
            epoch_length: std::cmp::max(1, epoch_length),
            quorum_bps: quorum_bps.clamp(1, 10_000),
            validators: BTreeMap::new(),
            proposer_slots: BTreeMap::new(),
            votes: BTreeMap::new(),
            finality_certificates: BTreeMap::new(),
            equivocation_evidence: BTreeMap::new(),
            downtime_evidence: BTreeMap::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn import_validators(
        &mut self,
        validators: &[Validator],
        activation_height: u64,
    ) -> ConsensusResult<ValidatorSetSnapshot> {
        if validators.is_empty() {
            return Err("consensus requires at least one validator".to_string());
        }
        for validator in validators {
            if validator.stake == 0 {
                return Err("cannot import zero-stake validator".to_string());
            }
            self.validators
                .entry(validator.validator_id.clone())
                .and_modify(|record| {
                    record.bonded_stake = validator.stake;
                    record.effective_stake = validator.stake.saturating_sub(record.slashed_stake);
                    record.consensus_public_key = validator.consensus_public_key.clone();
                    record.network_public_key = validator.network_public_key.clone();
                    if record.status != "slashed_out" {
                        record.status = validator.status.clone();
                    }
                })
                .or_insert_with(|| {
                    ValidatorStakeRecord::from_validator(validator, activation_height)
                });
        }
        Ok(self.validator_set_snapshot(activation_height))
    }

    pub fn active_validators_at(&self, height: u64) -> Vec<ValidatorStakeRecord> {
        self.validators
            .values()
            .filter(|validator| validator.is_active_at(height))
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn active_total_stake_at(&self, height: u64) -> u64 {
        self.active_validators_at(height)
            .iter()
            .map(|validator| validator.effective_stake)
            .sum()
    }

    pub fn quorum_stake_at(&self, height: u64) -> u64 {
        quorum_stake(self.active_total_stake_at(height), self.quorum_bps)
    }

    pub fn record_proposer_slot(
        &mut self,
        height: u64,
        round: u64,
        previous_block_hash: &str,
    ) -> ConsensusResult<ProposerSlot> {
        let slot = self.select_proposer(height, round, previous_block_hash)?;
        if let Some(record) = self.validators.get_mut(&slot.proposer_validator_id) {
            *record = record.apply_proposer_credit();
        }
        self.proposer_slots
            .insert(slot.slot_id.clone(), slot.clone());
        Ok(slot)
    }

    pub fn select_proposer(
        &self,
        height: u64,
        round: u64,
        previous_block_hash: &str,
    ) -> ConsensusResult<ProposerSlot> {
        let mut validators = self.active_validators_at(height);
        if validators.is_empty() {
            return Err("cannot select proposer without active validators".to_string());
        }
        validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        let total_stake = validators
            .iter()
            .map(|validator| validator.effective_stake)
            .sum::<u64>();
        if total_stake == 0 {
            return Err("cannot select proposer without effective stake".to_string());
        }
        let selection_seed = domain_hash(
            "CONSENSUS-PROPOSER-SEED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(height as i128),
                HashPart::Int(round as i128),
                HashPart::Str(previous_block_hash),
                HashPart::Str(&self.validator_root()),
            ],
            32,
        );
        let selection_weight = hash_to_u64(&selection_seed) % total_stake;
        let mut cursor = 0_u64;
        let selected = validators
            .iter()
            .find(|validator| {
                cursor = cursor.saturating_add(validator.effective_stake);
                selection_weight < cursor
            })
            .cloned()
            .unwrap_or_else(|| validators[0].clone());
        let epoch = height / self.epoch_length;
        let slot_id = proposer_slot_id(height, round, &selected.validator_id, &selection_seed);
        Ok(ProposerSlot {
            slot_id,
            height,
            epoch,
            round,
            proposer_validator_id: selected.validator_id,
            proposer_label: selected.label,
            proposer_stake: selected.effective_stake,
            total_stake,
            previous_block_hash: previous_block_hash.to_string(),
            selection_seed,
            selection_weight,
            status: "assigned".to_string(),
        })
    }

    pub fn submit_finality_vote(
        &mut self,
        block: &L2Block,
        round: u64,
        validator_label: &str,
        signed_at_height: u64,
    ) -> ConsensusResult<FastFinalityVote> {
        let validator = self
            .validators
            .values()
            .find(|validator| validator.label == validator_label)
            .cloned()
            .ok_or_else(|| "unknown consensus validator label".to_string())?;
        let vote = FastFinalityVote::new(
            block.header.height,
            round,
            &block.header.block_hash(),
            &block.header.state_root,
            &validator,
            signed_at_height,
        )?;
        if let Some(record) = self.validators.get_mut(&validator.validator_id) {
            *record = record.apply_vote_credit();
        }
        self.votes.insert(vote.vote_id.clone(), vote.clone());
        Ok(vote)
    }

    pub fn certify_block(
        &mut self,
        block: &L2Block,
        round: u64,
        validator_labels: &[String],
        certified_at_height: u64,
    ) -> ConsensusResult<FinalityCertificate> {
        for label in validator_labels {
            self.submit_finality_vote(block, round, label, certified_at_height)?;
        }
        self.build_finality_certificate(
            block.header.height,
            round,
            &block.header.block_hash(),
            &block.header.state_root,
            certified_at_height,
        )
    }

    pub fn build_finality_certificate(
        &mut self,
        block_height: u64,
        round: u64,
        block_hash: &str,
        state_root: &str,
        certified_at_height: u64,
    ) -> ConsensusResult<FinalityCertificate> {
        let votes = self
            .votes
            .values()
            .filter(|vote| {
                vote.block_height == block_height
                    && vote.round == round
                    && vote.block_hash == block_hash
                    && vote.state_root == state_root
            })
            .cloned()
            .collect::<Vec<_>>();
        let total_stake = self.active_total_stake_at(block_height);
        let quorum_stake = quorum_stake(total_stake, self.quorum_bps);
        let certificate = FinalityCertificate::new(
            block_height,
            round,
            block_hash,
            state_root,
            total_stake,
            quorum_stake,
            self.quorum_bps,
            &votes,
            certified_at_height,
        )?;
        self.finality_certificates
            .insert(certificate.certificate_id.clone(), certificate.clone());
        Ok(certificate)
    }

    pub fn report_equivocation(
        &mut self,
        left_vote_id: &str,
        right_vote_id: &str,
        reporter_label: &str,
        reported_at_height: u64,
    ) -> ConsensusResult<EquivocationEvidence> {
        let left = self
            .votes
            .get(left_vote_id)
            .cloned()
            .ok_or_else(|| "left equivocation vote is missing".to_string())?;
        let right = self
            .votes
            .get(right_vote_id)
            .cloned()
            .ok_or_else(|| "right equivocation vote is missing".to_string())?;
        let stake = self
            .validators
            .get(&left.validator_id)
            .map(|validator| validator.effective_stake)
            .unwrap_or(left.stake_weight);
        let slash_amount = slash_amount(stake, CONSENSUS_EQUIVOCATION_SLASH_BPS);
        let evidence = EquivocationEvidence::new(
            &left,
            &right,
            slash_amount,
            reporter_label,
            reported_at_height,
        )?;
        self.apply_slash(&evidence.validator_id, slash_amount, "slashed_equivocation")?;
        self.equivocation_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        Ok(evidence)
    }

    pub fn report_downtime(
        &mut self,
        validator_id: &str,
        missed_from_height: u64,
        missed_to_height: u64,
        reporter_label: &str,
        reported_at_height: u64,
    ) -> ConsensusResult<DowntimeEvidence> {
        let validator = self
            .validators
            .get(validator_id)
            .cloned()
            .ok_or_else(|| "downtime validator is missing".to_string())?;
        let missed_slot_count = missed_to_height
            .checked_sub(missed_from_height)
            .ok_or_else(|| "downtime evidence range is inverted".to_string())?
            + 1;
        let slash_amount = if missed_slot_count > CONSENSUS_DOWNTIME_GRACE_SLOTS {
            slash_amount(validator.effective_stake, CONSENSUS_DOWNTIME_SLASH_BPS)
        } else {
            0
        };
        let evidence = DowntimeEvidence::new(
            &validator,
            missed_from_height,
            missed_to_height,
            CONSENSUS_DOWNTIME_GRACE_SLOTS,
            slash_amount,
            reporter_label,
            reported_at_height,
        )?;
        if let Some(record) = self.validators.get_mut(validator_id) {
            *record = record.apply_missed_slots(missed_slot_count);
        }
        if slash_amount > 0 {
            self.apply_slash(validator_id, slash_amount, "slashed_downtime")?;
        }
        self.downtime_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        Ok(evidence)
    }

    pub fn request_validator_exit(
        &mut self,
        validator_id: &str,
        requested_height: u64,
        exit_delay: u64,
    ) -> ConsensusResult<ValidatorStakeRecord> {
        let record = self
            .validators
            .get(validator_id)
            .cloned()
            .ok_or_else(|| "exit validator is missing".to_string())?
            .request_exit(requested_height, exit_delay);
        self.validators
            .insert(validator_id.to_string(), record.clone());
        Ok(record)
    }

    pub fn validator_set_snapshot(&self, height: u64) -> ValidatorSetSnapshot {
        let active_validator_count = self.active_validators_at(height).len() as u64;
        let total_effective_stake = self.active_total_stake_at(height);
        ValidatorSetSnapshot {
            height,
            epoch: height / self.epoch_length,
            epoch_length: self.epoch_length,
            quorum_bps: self.quorum_bps,
            active_validator_count,
            total_effective_stake,
            quorum_stake: quorum_stake(total_effective_stake, self.quorum_bps),
            validator_root: self.validator_root(),
            proposer_schedule_root: self.proposer_slot_root(),
            finality_certificate_root: self.finality_certificate_root(),
            status: if active_validator_count == 0 {
                "halted"
            } else {
                "live"
            }
            .to_string(),
        }
    }

    pub fn validator_root(&self) -> String {
        merkle_root(
            "CONSENSUS-VALIDATOR",
            &self
                .validators
                .values()
                .map(ValidatorStakeRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn proposer_slot_root(&self) -> String {
        merkle_root(
            "CONSENSUS-PROPOSER-SLOT",
            &self
                .proposer_slots
                .values()
                .map(ProposerSlot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn vote_root(&self) -> String {
        merkle_root(
            "CONSENSUS-FINALITY-VOTE",
            &self
                .votes
                .values()
                .map(FastFinalityVote::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn finality_certificate_root(&self) -> String {
        merkle_root(
            "CONSENSUS-FINALITY-CERTIFICATE",
            &self
                .finality_certificates
                .values()
                .map(FinalityCertificate::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn equivocation_root(&self) -> String {
        merkle_root(
            "CONSENSUS-EQUIVOCATION",
            &self
                .equivocation_evidence
                .values()
                .map(EquivocationEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn downtime_root(&self) -> String {
        merkle_root(
            "CONSENSUS-DOWNTIME",
            &self
                .downtime_evidence
                .values()
                .map(DowntimeEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CONSENSUS-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.current_height as i128),
                HashPart::Int(self.epoch_length as i128),
                HashPart::Int(self.quorum_bps as i128),
                HashPart::Str(&self.validator_root()),
                HashPart::Str(&self.proposer_slot_root()),
                HashPart::Str(&self.vote_root()),
                HashPart::Str(&self.finality_certificate_root()),
                HashPart::Str(&self.equivocation_root()),
                HashPart::Str(&self.downtime_root()),
                HashPart::Str(&crypto_policy_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let snapshot = self.validator_set_snapshot(self.current_height);
        json!({
            "kind": "consensus_state",
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "epoch_length": self.epoch_length,
            "quorum_bps": self.quorum_bps,
            "validator_root": self.validator_root(),
            "proposer_slot_root": self.proposer_slot_root(),
            "vote_root": self.vote_root(),
            "finality_certificate_root": self.finality_certificate_root(),
            "equivocation_root": self.equivocation_root(),
            "downtime_root": self.downtime_root(),
            "consensus_state_root": self.state_root(),
            "validator_count": self.validators.len() as u64,
            "active_validator_count": snapshot.active_validator_count,
            "total_effective_stake": snapshot.total_effective_stake,
            "quorum_stake": snapshot.quorum_stake,
            "proposer_slot_count": self.proposer_slots.len() as u64,
            "vote_count": self.votes.len() as u64,
            "finality_certificate_count": self.finality_certificates.len() as u64,
            "equivocation_evidence_count": self.equivocation_evidence.len() as u64,
            "downtime_evidence_count": self.downtime_evidence.len() as u64,
        })
    }

    fn apply_slash(
        &mut self,
        validator_id: &str,
        slash_amount: u64,
        reason_status: &str,
    ) -> ConsensusResult<()> {
        let record = self
            .validators
            .get(validator_id)
            .cloned()
            .ok_or_else(|| "slash validator is missing".to_string())?
            .slash(slash_amount, slash_amount, reason_status);
        self.validators.insert(validator_id.to_string(), record);
        Ok(())
    }
}

pub fn fast_finality_vote_id(
    block_height: u64,
    round: u64,
    block_hash: &str,
    validator_id: &str,
    consensus_public_key: &str,
) -> String {
    domain_hash(
        "FAST-FINALITY-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Int(round as i128),
            HashPart::Str(block_hash),
            HashPart::Str(validator_id),
            HashPart::Str(consensus_public_key),
        ],
        32,
    )
}

pub fn finality_certificate_id(
    block_height: u64,
    round: u64,
    block_hash: &str,
    state_root: &str,
    vote_root: &str,
) -> String {
    domain_hash(
        "FAST-FINALITY-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Int(round as i128),
            HashPart::Str(block_hash),
            HashPart::Str(state_root),
            HashPart::Str(vote_root),
        ],
        32,
    )
}

pub fn proposer_slot_id(
    height: u64,
    round: u64,
    validator_id: &str,
    selection_seed: &str,
) -> String {
    domain_hash(
        "PROPOSER-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(round as i128),
            HashPart::Str(validator_id),
            HashPart::Str(selection_seed),
        ],
        32,
    )
}

pub fn equivocation_evidence_id(
    validator_id: &str,
    block_height: u64,
    round: u64,
    left_vote_root: &str,
    right_vote_root: &str,
) -> String {
    domain_hash(
        "EQUIVOCATION-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Int(block_height as i128),
            HashPart::Int(round as i128),
            HashPart::Str(left_vote_root),
            HashPart::Str(right_vote_root),
        ],
        32,
    )
}

pub fn downtime_evidence_id(
    validator_id: &str,
    missed_from_height: u64,
    missed_to_height: u64,
    missed_slot_count: u64,
) -> String {
    domain_hash(
        "DOWNTIME-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Int(missed_from_height as i128),
            HashPart::Int(missed_to_height as i128),
            HashPart::Int(missed_slot_count as i128),
        ],
        32,
    )
}

pub fn quorum_stake(total_stake: u64, quorum_bps: u64) -> u64 {
    if total_stake == 0 {
        0
    } else {
        total_stake.saturating_mul(quorum_bps).div_ceil(10_000)
    }
}

pub fn slash_amount(stake: u64, slash_bps: u64) -> u64 {
    if stake == 0 || slash_bps == 0 {
        0
    } else {
        std::cmp::max(1, stake.saturating_mul(slash_bps).div_ceil(10_000))
    }
}

fn hash_to_u64(hash: &str) -> u64 {
    let prefix = hash.get(0..16).unwrap_or(hash);
    u64::from_str_radix(prefix, 16).unwrap_or_else(|_| {
        prefix.bytes().fold(0_u64, |acc, byte| {
            acc.wrapping_mul(257).wrapping_add(byte as u64)
        })
    })
}
