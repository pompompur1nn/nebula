use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::Validator,
    crypto_policy::{
        build_kem_envelope, sign_authorization, verify_authorization, Authorization, CryptoRole,
        KemEnvelope,
    },
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID,
};

pub type MempoolResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolAdmissionRequest {
    pub tx_public_record: Value,
    pub tx_state_record: Value,
    pub mempool_sequence: u64,
    pub relay_path: String,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
    pub sequencer_label: String,
    pub committee_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolAdmission {
    pub admission_id: String,
    pub mempool_sequence: u64,
    pub tx_public_hash: String,
    pub encrypted_payload_hash: String,
    pub committee_key_id: String,
    pub kem_ciphertext_hash: String,
    pub kem_envelope: KemEnvelope,
    pub relay_path: String,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
    pub sequencer_label: String,
    pub authorization: Authorization,
}

impl MempoolAdmission {
    pub fn build(request: MempoolAdmissionRequest) -> Self {
        let tx_public_hash = mempool_tx_public_hash(&request.tx_public_record);
        let encrypted_payload_hash = mempool_encrypted_payload_hash(&request.tx_state_record);
        let kem_envelope = mempool_kem_envelope(
            &request.committee_key_id,
            &encrypted_payload_hash,
            &request.relay_path,
            request.mempool_sequence,
        );
        let kem_ciphertext_hash = kem_envelope.ciphertext_hash.clone();
        let admission_id = mempool_admission_id(
            &tx_public_hash,
            &kem_ciphertext_hash,
            request.admitted_at_height,
            request.mempool_sequence,
        );
        let mut admission = Self {
            admission_id,
            mempool_sequence: request.mempool_sequence,
            tx_public_hash,
            encrypted_payload_hash,
            committee_key_id: request.committee_key_id,
            kem_ciphertext_hash,
            kem_envelope,
            relay_path: request.relay_path,
            admitted_at_height: request.admitted_at_height,
            expires_at_height: request.expires_at_height,
            sequencer_label: request.sequencer_label,
            authorization: empty_authorization(),
        };
        admission.authorization = sign_authorization(
            &admission.sequencer_label,
            "mempool_admission",
            &admission.unsigned_record(),
        );
        admission
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = json!({
            "admission_id": self.admission_id,
            "mempool_sequence": self.mempool_sequence,
            "tx_public_hash": self.tx_public_hash,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "committee_key_id": self.committee_key_id,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "kem_envelope": self.kem_envelope.public_record(),
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
            "sequencer_label": self.sequencer_label,
        });
        record
            .as_object_mut()
            .expect("mempool admission object")
            .extend(relay_path_public_metadata(&self.relay_path));
        record
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("mempool admission state object")
            .insert(
                "relay_path".to_string(),
                Value::String(self.relay_path.clone()),
            );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        self.verify_kem_envelope()
            && verify_authorization(
                &self.sequencer_label,
                "mempool_admission",
                &self.unsigned_record(),
                &self.authorization,
            )
    }

    pub fn verify_kem_envelope(&self) -> bool {
        self.kem_ciphertext_hash
            == mempool_kem_ciphertext_hash(
                &self.committee_key_id,
                &self.encrypted_payload_hash,
                &self.relay_path,
                self.mempool_sequence,
            )
            && self.kem_envelope
                == mempool_kem_envelope(
                    &self.committee_key_id,
                    &self.encrypted_payload_hash,
                    &self.relay_path,
                    self.mempool_sequence,
                )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolPreconfirmation {
    pub preconfirmation_id: String,
    pub admission_id: String,
    pub tx_public_hash: String,
    pub encrypted_payload_hash: String,
    pub target_height: u64,
    pub expires_at_height: u64,
    pub preconfirmed_at_height: u64,
    pub sequencer_label: String,
    pub promised_mempool_root: String,
    pub promised_pending_tx_count: u64,
    pub local_fee_market_root: String,
    pub authorization: Authorization,
}

impl MempoolPreconfirmation {
    pub fn build(
        admission: &MempoolAdmission,
        preconfirmed_at_height: u64,
        promised_mempool_root: &str,
        promised_pending_tx_count: u64,
        local_fee_market_root: &str,
    ) -> MempoolResult<Self> {
        Self::build_with_target_height(
            admission,
            preconfirmed_at_height,
            preconfirmed_at_height,
            promised_mempool_root,
            promised_pending_tx_count,
            local_fee_market_root,
        )
    }

    pub fn build_with_target_height(
        admission: &MempoolAdmission,
        preconfirmed_at_height: u64,
        target_height: u64,
        promised_mempool_root: &str,
        promised_pending_tx_count: u64,
        local_fee_market_root: &str,
    ) -> MempoolResult<Self> {
        if target_height < preconfirmed_at_height {
            return Err("mempool preconfirmation target is before preconfirmation".to_string());
        }
        if admission.expires_at_height < target_height {
            return Err("mempool preconfirmation target exceeds admission expiry".to_string());
        }
        let preconfirmation_id = domain_hash(
            "MEMPOOL-PRECONFIRMATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&admission.admission_id),
                HashPart::Str(&admission.tx_public_hash),
                HashPart::Int(target_height as i128),
                HashPart::Str(promised_mempool_root),
            ],
            32,
        );
        let mut preconfirmation = Self {
            preconfirmation_id,
            admission_id: admission.admission_id.clone(),
            tx_public_hash: admission.tx_public_hash.clone(),
            encrypted_payload_hash: admission.encrypted_payload_hash.clone(),
            target_height,
            expires_at_height: admission.expires_at_height,
            preconfirmed_at_height,
            sequencer_label: admission.sequencer_label.clone(),
            promised_mempool_root: promised_mempool_root.to_string(),
            promised_pending_tx_count,
            local_fee_market_root: local_fee_market_root.to_string(),
            authorization: empty_authorization(),
        };
        preconfirmation.authorization = sign_authorization(
            &preconfirmation.sequencer_label,
            "mempool_preconfirmation",
            &preconfirmation.unsigned_record(),
        );
        Ok(preconfirmation)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "admission_id": self.admission_id,
            "tx_public_hash": self.tx_public_hash,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "target_height": self.target_height,
            "expires_at_height": self.expires_at_height,
            "preconfirmed_at_height": self.preconfirmed_at_height,
            "sequencer_label": self.sequencer_label,
            "promised_mempool_root": self.promised_mempool_root,
            "promised_pending_tx_count": self.promised_pending_tx_count,
            "local_fee_market_root": self.local_fee_market_root,
        })
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization(
            &self.sequencer_label,
            "mempool_preconfirmation",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolOmissionEvidence {
    pub evidence_id: String,
    pub admission_id: String,
    pub tx_public_hash: String,
    pub encrypted_payload_hash: String,
    pub committee_key_id: String,
    pub kem_ciphertext_hash: String,
    pub kem_envelope: KemEnvelope,
    pub relay_path: String,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
    pub reported_at_height: u64,
    pub sequencer_label: String,
    pub reporter_label: String,
    pub missed_block_count: u64,
    pub penalty_units: u64,
    pub admission_auth_transcript_hash: String,
    pub admission_auth_signature: String,
    pub slashed_validator_id: String,
    pub slashed_amount: u64,
    pub validator_stake_after: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl MempoolOmissionEvidence {
    pub fn report(
        admission: &MempoolAdmission,
        reported_at_height: u64,
        reporter_label: &str,
        slashed_validator_id: &str,
        slashed_amount: u64,
        validator_stake_after: u64,
    ) -> MempoolResult<Self> {
        if reported_at_height <= admission.expires_at_height {
            return Err("mempool admission has not expired".to_string());
        }
        let missed_block_count = reported_at_height - admission.expires_at_height;
        let penalty_units = std::cmp::max(1, missed_block_count);
        let status = if slashed_validator_id.is_empty() {
            "unbonded_sequencer"
        } else if slashed_amount > 0 {
            "slashed"
        } else {
            "reported"
        };
        let evidence_id = domain_hash(
            "MEMPOOL-OMISSION-EVIDENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&admission.admission_id),
                HashPart::Int(admission.expires_at_height as i128),
                HashPart::Int(reported_at_height as i128),
                HashPart::Str(reporter_label),
            ],
            32,
        );
        let mut evidence = Self {
            evidence_id,
            admission_id: admission.admission_id.clone(),
            tx_public_hash: admission.tx_public_hash.clone(),
            encrypted_payload_hash: admission.encrypted_payload_hash.clone(),
            committee_key_id: admission.committee_key_id.clone(),
            kem_ciphertext_hash: admission.kem_ciphertext_hash.clone(),
            kem_envelope: admission.kem_envelope.clone(),
            relay_path: admission.relay_path.clone(),
            admitted_at_height: admission.admitted_at_height,
            expires_at_height: admission.expires_at_height,
            reported_at_height,
            sequencer_label: admission.sequencer_label.clone(),
            reporter_label: reporter_label.to_string(),
            missed_block_count,
            penalty_units,
            admission_auth_transcript_hash: admission.authorization.auth_transcript_hash.clone(),
            admission_auth_signature: admission.authorization.auth_signature.clone(),
            slashed_validator_id: slashed_validator_id.to_string(),
            slashed_amount,
            validator_stake_after,
            status: status.to_string(),
            authorization: empty_authorization(),
        };
        evidence.authorization = sign_authorization(
            reporter_label,
            "mempool_omission_evidence",
            &evidence.unsigned_record(),
        );
        Ok(evidence)
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = json!({
            "evidence_id": self.evidence_id,
            "admission_id": self.admission_id,
            "tx_public_hash": self.tx_public_hash,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "committee_key_id": self.committee_key_id,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "kem_envelope": self.kem_envelope.public_record(),
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
            "reported_at_height": self.reported_at_height,
            "sequencer_label": self.sequencer_label,
            "reporter_label": self.reporter_label,
            "missed_block_count": self.missed_block_count,
            "penalty_units": self.penalty_units,
            "admission_auth_transcript_hash": self.admission_auth_transcript_hash,
            "admission_auth_signature": self.admission_auth_signature,
            "slashed_validator_id": self.slashed_validator_id,
            "slashed_amount": self.slashed_amount,
            "validator_stake_after": self.validator_stake_after,
            "status": self.status,
        });
        record
            .as_object_mut()
            .expect("mempool omission evidence object")
            .extend(relay_path_public_metadata(&self.relay_path));
        record
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("mempool omission state object")
            .insert(
                "relay_path".to_string(),
                Value::String(self.relay_path.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolForcedInclusion {
    pub forced_inclusion_id: String,
    pub evidence_id: String,
    pub admission_id: String,
    pub tx_public_hash: String,
    pub old_encrypted_payload_hash: String,
    pub new_admission_id: String,
    pub new_encrypted_payload_hash: String,
    pub new_committee_key_id: String,
    pub new_kem_ciphertext_hash: String,
    pub new_kem_envelope: KemEnvelope,
    pub new_relay_path: String,
    pub forced_at_height: u64,
    pub sequencer_label: String,
    pub reporter_label: String,
    pub authorization: Authorization,
}

impl MempoolForcedInclusion {
    pub fn build(
        evidence: &MempoolOmissionEvidence,
        new_admission: &MempoolAdmission,
        forced_at_height: u64,
        sequencer_label: &str,
    ) -> MempoolResult<Self> {
        if evidence.tx_public_hash != new_admission.tx_public_hash {
            return Err("forced inclusion tx hash mismatch".to_string());
        }
        if new_admission.relay_path.is_empty() {
            return Err("forced inclusion relay path is required".to_string());
        }
        let forced_inclusion_id = domain_hash(
            "MEMPOOL-FORCED-INCLUSION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence.evidence_id),
                HashPart::Str(&evidence.admission_id),
                HashPart::Str(&new_admission.admission_id),
                HashPart::Int(forced_at_height as i128),
                HashPart::Str(sequencer_label),
            ],
            32,
        );
        let mut forced = Self {
            forced_inclusion_id,
            evidence_id: evidence.evidence_id.clone(),
            admission_id: evidence.admission_id.clone(),
            tx_public_hash: evidence.tx_public_hash.clone(),
            old_encrypted_payload_hash: evidence.encrypted_payload_hash.clone(),
            new_admission_id: new_admission.admission_id.clone(),
            new_encrypted_payload_hash: new_admission.encrypted_payload_hash.clone(),
            new_committee_key_id: new_admission.committee_key_id.clone(),
            new_kem_ciphertext_hash: new_admission.kem_ciphertext_hash.clone(),
            new_kem_envelope: new_admission.kem_envelope.clone(),
            new_relay_path: new_admission.relay_path.clone(),
            forced_at_height,
            sequencer_label: sequencer_label.to_string(),
            reporter_label: evidence.reporter_label.clone(),
            authorization: empty_authorization(),
        };
        forced.authorization = sign_authorization(
            sequencer_label,
            "mempool_forced_inclusion",
            &forced.unsigned_record(),
        );
        Ok(forced)
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = json!({
            "forced_inclusion_id": self.forced_inclusion_id,
            "evidence_id": self.evidence_id,
            "admission_id": self.admission_id,
            "tx_public_hash": self.tx_public_hash,
            "old_encrypted_payload_hash": self.old_encrypted_payload_hash,
            "new_admission_id": self.new_admission_id,
            "new_encrypted_payload_hash": self.new_encrypted_payload_hash,
            "new_committee_key_id": self.new_committee_key_id,
            "new_kem_ciphertext_hash": self.new_kem_ciphertext_hash,
            "new_kem_envelope": self.new_kem_envelope.public_record(),
            "forced_at_height": self.forced_at_height,
            "sequencer_label": self.sequencer_label,
            "reporter_label": self.reporter_label,
        });
        record
            .as_object_mut()
            .expect("mempool forced inclusion object")
            .extend(prefixed_relay_path_public_metadata(
                &self.new_relay_path,
                "new_relay_path",
            ));
        record
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record.as_object_mut().expect("forced state object").insert(
            "new_relay_path".to_string(),
            Value::String(self.new_relay_path.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolPreconfirmationMissEvidence {
    pub evidence_id: String,
    pub preconfirmation_id: String,
    pub admission_id: String,
    pub tx_public_hash: String,
    pub encrypted_payload_hash: String,
    pub target_height: u64,
    pub reported_at_height: u64,
    pub sequencer_label: String,
    pub reporter_label: String,
    pub missed_block_count: u64,
    pub penalty_units: u64,
    pub preconfirmation_auth_transcript_hash: String,
    pub preconfirmation_auth_signature: String,
    pub slashed_validator_id: String,
    pub slashed_amount: u64,
    pub validator_stake_after: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl MempoolPreconfirmationMissEvidence {
    pub fn report(
        preconfirmation: &MempoolPreconfirmation,
        reported_at_height: u64,
        reporter_label: &str,
        slashed_validator_id: &str,
        slashed_amount: u64,
        validator_stake_after: u64,
    ) -> MempoolResult<Self> {
        if reported_at_height <= preconfirmation.target_height {
            return Err("mempool preconfirmation target has not passed".to_string());
        }
        let missed_block_count = reported_at_height - preconfirmation.target_height;
        let penalty_units = std::cmp::max(1, missed_block_count);
        let status = if slashed_validator_id.is_empty() {
            "unbonded_sequencer"
        } else if slashed_amount > 0 {
            "slashed"
        } else {
            "reported"
        };
        let evidence_id = domain_hash(
            "MEMPOOL-PRECONFIRMATION-MISS-EVIDENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&preconfirmation.preconfirmation_id),
                HashPart::Int(preconfirmation.target_height as i128),
                HashPart::Int(reported_at_height as i128),
                HashPart::Str(reporter_label),
            ],
            32,
        );
        let mut evidence = Self {
            evidence_id,
            preconfirmation_id: preconfirmation.preconfirmation_id.clone(),
            admission_id: preconfirmation.admission_id.clone(),
            tx_public_hash: preconfirmation.tx_public_hash.clone(),
            encrypted_payload_hash: preconfirmation.encrypted_payload_hash.clone(),
            target_height: preconfirmation.target_height,
            reported_at_height,
            sequencer_label: preconfirmation.sequencer_label.clone(),
            reporter_label: reporter_label.to_string(),
            missed_block_count,
            penalty_units,
            preconfirmation_auth_transcript_hash: preconfirmation
                .authorization
                .auth_transcript_hash
                .clone(),
            preconfirmation_auth_signature: preconfirmation.authorization.auth_signature.clone(),
            slashed_validator_id: slashed_validator_id.to_string(),
            slashed_amount,
            validator_stake_after,
            status: status.to_string(),
            authorization: empty_authorization(),
        };
        evidence.authorization = sign_authorization(
            reporter_label,
            "mempool_preconfirmation_miss_evidence",
            &evidence.unsigned_record(),
        );
        Ok(evidence)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "preconfirmation_id": self.preconfirmation_id,
            "admission_id": self.admission_id,
            "tx_public_hash": self.tx_public_hash,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "target_height": self.target_height,
            "reported_at_height": self.reported_at_height,
            "sequencer_label": self.sequencer_label,
            "reporter_label": self.reporter_label,
            "missed_block_count": self.missed_block_count,
            "penalty_units": self.penalty_units,
            "preconfirmation_auth_transcript_hash": self.preconfirmation_auth_transcript_hash,
            "preconfirmation_auth_signature": self.preconfirmation_auth_signature,
            "slashed_validator_id": self.slashed_validator_id,
            "slashed_amount": self.slashed_amount,
            "validator_stake_after": self.validator_stake_after,
            "status": self.status,
        })
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolEncryptedBatchReceipt {
    pub batch_receipt_id: String,
    pub batch_sequence: u64,
    pub admission_root: String,
    pub encrypted_payload_root: String,
    pub relay_path_commitment_root: String,
    pub admission_count: u64,
    pub first_admitted_at_height: u64,
    pub last_admitted_at_height: u64,
    pub inclusion_deadline_height: u64,
    pub committee_key_id: String,
    pub sequencer_label: String,
    pub authorization: Authorization,
}

impl MempoolEncryptedBatchReceipt {
    pub fn build(
        admissions: &[MempoolAdmission],
        batch_sequence: u64,
        inclusion_deadline_height: u64,
        sequencer_label: &str,
    ) -> MempoolResult<Self> {
        if admissions.is_empty() {
            return Err("mempool encrypted batch receipt requires admissions".to_string());
        }
        let committee_key_id = admissions[0].committee_key_id.clone();
        let mut first_admitted_at_height = u64::MAX;
        let mut last_admitted_at_height = 0;
        for admission in admissions {
            if admission.committee_key_id != committee_key_id {
                return Err("mempool encrypted batch receipt committee mismatch".to_string());
            }
            first_admitted_at_height =
                std::cmp::min(first_admitted_at_height, admission.admitted_at_height);
            last_admitted_at_height =
                std::cmp::max(last_admitted_at_height, admission.admitted_at_height);
        }
        if inclusion_deadline_height < last_admitted_at_height {
            return Err("mempool encrypted batch receipt deadline precedes admission".to_string());
        }
        let admission_root = mempool_admission_root(admissions);
        let encrypted_payload_root = mempool_encrypted_batch_payload_root(admissions);
        let relay_path_commitment_root = mempool_batch_relay_path_commitment_root(admissions);
        let batch_receipt_id = mempool_encrypted_batch_receipt_id(
            batch_sequence,
            &admission_root,
            &encrypted_payload_root,
            &relay_path_commitment_root,
            inclusion_deadline_height,
            sequencer_label,
        );
        let mut receipt = Self {
            batch_receipt_id,
            batch_sequence,
            admission_root,
            encrypted_payload_root,
            relay_path_commitment_root,
            admission_count: admissions.len() as u64,
            first_admitted_at_height,
            last_admitted_at_height,
            inclusion_deadline_height,
            committee_key_id,
            sequencer_label: sequencer_label.to_string(),
            authorization: empty_authorization(),
        };
        receipt.authorization = sign_authorization(
            &receipt.sequencer_label,
            "mempool_encrypted_batch_receipt",
            &receipt.unsigned_record(),
        );
        Ok(receipt)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "batch_receipt_id": self.batch_receipt_id,
            "batch_sequence": self.batch_sequence,
            "admission_root": self.admission_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "relay_path_commitment_root": self.relay_path_commitment_root,
            "admission_count": self.admission_count,
            "first_admitted_at_height": self.first_admitted_at_height,
            "last_admitted_at_height": self.last_admitted_at_height,
            "inclusion_deadline_height": self.inclusion_deadline_height,
            "committee_key_id": self.committee_key_id,
            "sequencer_label": self.sequencer_label,
        })
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization(
            &self.sequencer_label,
            "mempool_encrypted_batch_receipt",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolRelayFairnessTicket {
    pub fairness_ticket_id: String,
    pub admission_id: String,
    pub tx_public_hash: String,
    pub encrypted_payload_hash: String,
    pub lane_id: String,
    pub lane_label: String,
    pub lane_sequence: u64,
    pub lane_start_height: u64,
    pub lane_end_height: u64,
    pub relay_path_policy: String,
    pub relay_path_hop_count: u64,
    pub relay_path_commitment: String,
    pub issued_at_height: u64,
    pub inclusion_deadline_height: u64,
    pub max_delay_blocks: u64,
    pub sequencer_label: String,
    pub authorization: Authorization,
}

impl MempoolRelayFairnessTicket {
    pub fn build(
        admission: &MempoolAdmission,
        lane_label: &str,
        lane_sequence: u64,
        lane_start_height: u64,
        lane_end_height: u64,
        issued_at_height: u64,
        max_delay_blocks: u64,
        sequencer_label: &str,
    ) -> MempoolResult<Self> {
        if lane_end_height < lane_start_height {
            return Err("mempool fairness lane ends before it starts".to_string());
        }
        if max_delay_blocks == 0 {
            return Err("mempool fairness ticket max delay must be positive".to_string());
        }
        if issued_at_height < admission.admitted_at_height {
            return Err("mempool fairness ticket predates admission".to_string());
        }
        if issued_at_height > lane_end_height {
            return Err("mempool fairness ticket is outside lane window".to_string());
        }
        let inclusion_deadline_height = admission
            .admitted_at_height
            .checked_add(max_delay_blocks)
            .ok_or_else(|| "mempool fairness ticket deadline overflow".to_string())?;
        if inclusion_deadline_height < issued_at_height {
            return Err("mempool fairness ticket deadline predates issue".to_string());
        }
        if inclusion_deadline_height > admission.expires_at_height {
            return Err("mempool fairness ticket exceeds admission expiry".to_string());
        }
        if inclusion_deadline_height > lane_end_height {
            return Err("mempool fairness ticket exceeds lane window".to_string());
        }
        let lane_id = mempool_anti_censorship_lane_id(
            lane_label,
            lane_sequence,
            lane_start_height,
            lane_end_height,
        );
        let relay_path_policy = relay_path_policy(&admission.relay_path);
        let relay_path_hop_count = relay_path_hop_count(&admission.relay_path);
        let relay_path_commitment = relay_path_commitment(&admission.relay_path);
        let fairness_ticket_id = mempool_relay_fairness_ticket_id(
            &admission.admission_id,
            &lane_id,
            issued_at_height,
            inclusion_deadline_height,
            sequencer_label,
        );
        let mut ticket = Self {
            fairness_ticket_id,
            admission_id: admission.admission_id.clone(),
            tx_public_hash: admission.tx_public_hash.clone(),
            encrypted_payload_hash: admission.encrypted_payload_hash.clone(),
            lane_id,
            lane_label: lane_label.to_string(),
            lane_sequence,
            lane_start_height,
            lane_end_height,
            relay_path_policy,
            relay_path_hop_count,
            relay_path_commitment,
            issued_at_height,
            inclusion_deadline_height,
            max_delay_blocks,
            sequencer_label: sequencer_label.to_string(),
            authorization: empty_authorization(),
        };
        ticket.authorization = sign_authorization(
            &ticket.sequencer_label,
            "mempool_relay_fairness_ticket",
            &ticket.unsigned_record(),
        );
        Ok(ticket)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "fairness_ticket_id": self.fairness_ticket_id,
            "admission_id": self.admission_id,
            "tx_public_hash": self.tx_public_hash,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "lane_id": self.lane_id,
            "lane_label": self.lane_label,
            "lane_sequence": self.lane_sequence,
            "lane_start_height": self.lane_start_height,
            "lane_end_height": self.lane_end_height,
            "relay_path_policy": self.relay_path_policy,
            "relay_path_hop_count": self.relay_path_hop_count,
            "relay_path_commitment": self.relay_path_commitment,
            "issued_at_height": self.issued_at_height,
            "inclusion_deadline_height": self.inclusion_deadline_height,
            "max_delay_blocks": self.max_delay_blocks,
            "sequencer_label": self.sequencer_label,
        })
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization(
            &self.sequencer_label,
            "mempool_relay_fairness_ticket",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolAntiCensorshipLaneCommitment {
    pub lane_commitment_id: String,
    pub lane_id: String,
    pub lane_label: String,
    pub lane_sequence: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub reserved_slot_count: u64,
    pub minimum_private_admissions: u64,
    pub fairness_ticket_root: String,
    pub encrypted_batch_receipt_root: String,
    pub forced_inclusion_root: String,
    pub sequencer_label: String,
    pub authorization: Authorization,
}

impl MempoolAntiCensorshipLaneCommitment {
    pub fn build(
        lane_label: &str,
        lane_sequence: u64,
        start_height: u64,
        end_height: u64,
        reserved_slot_count: u64,
        minimum_private_admissions: u64,
        fairness_tickets: &[MempoolRelayFairnessTicket],
        encrypted_batch_receipts: &[MempoolEncryptedBatchReceipt],
        forced_inclusions: &[MempoolForcedInclusion],
        sequencer_label: &str,
    ) -> MempoolResult<Self> {
        if end_height < start_height {
            return Err("mempool anti-censorship lane ends before it starts".to_string());
        }
        if reserved_slot_count == 0 {
            return Err("mempool anti-censorship lane requires reserved slots".to_string());
        }
        if minimum_private_admissions > reserved_slot_count {
            return Err("mempool anti-censorship lane minimum exceeds reserved slots".to_string());
        }
        let lane_id =
            mempool_anti_censorship_lane_id(lane_label, lane_sequence, start_height, end_height);
        for ticket in fairness_tickets {
            if ticket.lane_id != lane_id {
                return Err("mempool fairness ticket belongs to another lane".to_string());
            }
            if ticket.inclusion_deadline_height > end_height {
                return Err("mempool fairness ticket exceeds lane commitment".to_string());
            }
        }
        for receipt in encrypted_batch_receipts {
            if receipt.inclusion_deadline_height > end_height {
                return Err("mempool encrypted batch receipt exceeds lane commitment".to_string());
            }
        }
        for forced in forced_inclusions {
            if forced.forced_at_height < start_height || forced.forced_at_height > end_height {
                return Err("mempool forced inclusion is outside lane commitment".to_string());
            }
        }
        let fairness_ticket_root = mempool_relay_fairness_ticket_root(fairness_tickets);
        let encrypted_batch_receipt_root =
            mempool_encrypted_batch_receipt_root(encrypted_batch_receipts);
        let forced_inclusion_root = mempool_forced_inclusion_root(forced_inclusions);
        let lane_commitment_id = mempool_anti_censorship_lane_commitment_id(
            &lane_id,
            reserved_slot_count,
            minimum_private_admissions,
            &fairness_ticket_root,
            &encrypted_batch_receipt_root,
            &forced_inclusion_root,
            sequencer_label,
        );
        let mut commitment = Self {
            lane_commitment_id,
            lane_id,
            lane_label: lane_label.to_string(),
            lane_sequence,
            start_height,
            end_height,
            reserved_slot_count,
            minimum_private_admissions,
            fairness_ticket_root,
            encrypted_batch_receipt_root,
            forced_inclusion_root,
            sequencer_label: sequencer_label.to_string(),
            authorization: empty_authorization(),
        };
        commitment.authorization = sign_authorization(
            &commitment.sequencer_label,
            "mempool_anti_censorship_lane_commitment",
            &commitment.unsigned_record(),
        );
        Ok(commitment)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "lane_commitment_id": self.lane_commitment_id,
            "lane_id": self.lane_id,
            "lane_label": self.lane_label,
            "lane_sequence": self.lane_sequence,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "reserved_slot_count": self.reserved_slot_count,
            "minimum_private_admissions": self.minimum_private_admissions,
            "fairness_ticket_root": self.fairness_ticket_root,
            "encrypted_batch_receipt_root": self.encrypted_batch_receipt_root,
            "forced_inclusion_root": self.forced_inclusion_root,
            "sequencer_label": self.sequencer_label,
        })
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization)
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization(
            &self.sequencer_label,
            "mempool_anti_censorship_lane_commitment",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolState {
    pub pending_admissions: Vec<MempoolAdmission>,
    pub preconfirmations: BTreeMap<String, MempoolPreconfirmation>,
    pub preconfirmation_misses: BTreeMap<String, MempoolPreconfirmationMissEvidence>,
    pub omission_evidence: BTreeMap<String, MempoolOmissionEvidence>,
    pub forced_inclusions: BTreeMap<String, MempoolForcedInclusion>,
    pub encrypted_batch_receipts: BTreeMap<String, MempoolEncryptedBatchReceipt>,
    pub relay_fairness_tickets: BTreeMap<String, MempoolRelayFairnessTicket>,
    pub anti_censorship_lane_commitments: BTreeMap<String, MempoolAntiCensorshipLaneCommitment>,
}

impl MempoolState {
    pub fn admission_root(&self) -> String {
        mempool_admission_root(&self.pending_admissions)
    }

    pub fn preconfirmation_root(&self) -> String {
        merkle_root(
            "MEMPOOL-PRECONFIRMATION",
            &self
                .preconfirmations
                .values()
                .map(MempoolPreconfirmation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn preconfirmation_miss_root(&self) -> String {
        merkle_root(
            "MEMPOOL-PRECONFIRMATION-MISS-EVIDENCE",
            &self
                .preconfirmation_misses
                .values()
                .map(MempoolPreconfirmationMissEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn omission_evidence_root(&self) -> String {
        merkle_root(
            "MEMPOOL-OMISSION-EVIDENCE",
            &self
                .omission_evidence
                .values()
                .map(MempoolOmissionEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn forced_inclusion_root(&self) -> String {
        mempool_forced_inclusion_root(&self.forced_inclusions.values().cloned().collect::<Vec<_>>())
    }

    pub fn encrypted_batch_receipt_root(&self) -> String {
        mempool_encrypted_batch_receipt_root(
            &self
                .encrypted_batch_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn relay_fairness_ticket_root(&self) -> String {
        mempool_relay_fairness_ticket_root(
            &self
                .relay_fairness_tickets
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn anti_censorship_lane_commitment_root(&self) -> String {
        mempool_anti_censorship_lane_commitment_root(
            &self
                .anti_censorship_lane_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn admission_public_records(&self) -> Vec<Value> {
        self.pending_admissions
            .iter()
            .map(MempoolAdmission::public_record)
            .collect()
    }

    pub fn insert_admission(&mut self, admission: MempoolAdmission) -> MempoolResult<()> {
        if self
            .pending_admissions
            .iter()
            .any(|existing| existing.admission_id == admission.admission_id)
        {
            return Err("mempool admission already exists".to_string());
        }
        self.pending_admissions.push(admission);
        Ok(())
    }

    pub fn insert_preconfirmation(
        &mut self,
        preconfirmation: MempoolPreconfirmation,
    ) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.preconfirmations,
            preconfirmation.preconfirmation_id.clone(),
            preconfirmation,
            "preconfirmation",
        )
    }

    pub fn insert_preconfirmation_miss(
        &mut self,
        miss: MempoolPreconfirmationMissEvidence,
    ) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.preconfirmation_misses,
            miss.evidence_id.clone(),
            miss,
            "preconfirmation miss evidence",
        )
    }

    pub fn insert_omission_evidence(
        &mut self,
        evidence: MempoolOmissionEvidence,
    ) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.omission_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "omission evidence",
        )
    }

    pub fn insert_forced_inclusion(&mut self, forced: MempoolForcedInclusion) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.forced_inclusions,
            forced.forced_inclusion_id.clone(),
            forced,
            "forced inclusion",
        )
    }

    pub fn insert_encrypted_batch_receipt(
        &mut self,
        receipt: MempoolEncryptedBatchReceipt,
    ) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.encrypted_batch_receipts,
            receipt.batch_receipt_id.clone(),
            receipt,
            "encrypted batch receipt",
        )
    }

    pub fn insert_relay_fairness_ticket(
        &mut self,
        ticket: MempoolRelayFairnessTicket,
    ) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.relay_fairness_tickets,
            ticket.fairness_ticket_id.clone(),
            ticket,
            "relay fairness ticket",
        )
    }

    pub fn insert_anti_censorship_lane_commitment(
        &mut self,
        commitment: MempoolAntiCensorshipLaneCommitment,
    ) -> MempoolResult<()> {
        insert_unique_record(
            &mut self.anti_censorship_lane_commitments,
            commitment.lane_commitment_id.clone(),
            commitment,
            "anti-censorship lane commitment",
        )
    }
}

pub fn mempool_committee_key_id(validators: &[Validator]) -> String {
    let mut validators = validators
        .iter()
        .filter(|validator| validator.status == "active")
        .collect::<Vec<_>>();
    validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    merkle_root(
        "MEMPOOL-ML-KEM-COMMITTEE",
        &validators
            .iter()
            .map(|validator| {
                json!({
                    "validator_id": validator.validator_id,
                    "network_public_key": validator.network_public_key,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_tx_public_hash(tx_public_record: &Value) -> String {
    domain_hash("MEMPOOL-TX-PUBLIC", &[HashPart::Json(tx_public_record)], 32)
}

pub fn mempool_encrypted_payload_hash(tx_state_record: &Value) -> String {
    domain_hash(
        "MEMPOOL-ENCRYPTED-PAYLOAD",
        &[HashPart::Json(tx_state_record)],
        32,
    )
}

pub fn mempool_kem_ciphertext_hash(
    committee_key_id: &str,
    encrypted_payload_hash: &str,
    relay_path: &str,
    mempool_sequence: u64,
) -> String {
    domain_hash(
        "MEMPOOL-ML-KEM-CIPHERTEXT",
        &[
            HashPart::Str(committee_key_id),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Str(relay_path),
            HashPart::Int(mempool_sequence as i128),
        ],
        32,
    )
}

pub fn mempool_kem_envelope(
    committee_key_id: &str,
    encrypted_payload_hash: &str,
    relay_path: &str,
    mempool_sequence: u64,
) -> KemEnvelope {
    let mut envelope = build_kem_envelope(
        CryptoRole::KeyEstablishment,
        committee_key_id,
        committee_key_id,
        &mempool_kem_transcript(
            committee_key_id,
            encrypted_payload_hash,
            relay_path,
            mempool_sequence,
        ),
    );
    envelope.ciphertext_hash = mempool_kem_ciphertext_hash(
        committee_key_id,
        encrypted_payload_hash,
        relay_path,
        mempool_sequence,
    );
    envelope
}

pub fn mempool_kem_transcript(
    committee_key_id: &str,
    encrypted_payload_hash: &str,
    relay_path: &str,
    mempool_sequence: u64,
) -> Value {
    json!({
        "kind": "mempool_kem_transcript",
        "chain_id": CHAIN_ID,
        "committee_key_id": committee_key_id,
        "encrypted_payload_hash": encrypted_payload_hash,
        "relay_path_commitment": relay_path_commitment(relay_path),
        "relay_path_policy": relay_path_policy(relay_path),
        "relay_path_hop_count": relay_path_hop_count(relay_path),
        "mempool_sequence": mempool_sequence,
    })
}

pub fn mempool_admission_id(
    tx_public_hash: &str,
    kem_ciphertext_hash: &str,
    admitted_at_height: u64,
    mempool_sequence: u64,
) -> String {
    domain_hash(
        "MEMPOOL-ADMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_public_hash),
            HashPart::Str(kem_ciphertext_hash),
            HashPart::Int(admitted_at_height as i128),
            HashPart::Int(mempool_sequence as i128),
        ],
        32,
    )
}

pub fn mempool_admission_root(admissions: &[MempoolAdmission]) -> String {
    merkle_root(
        "MEMPOOL-ADMISSION",
        &admissions
            .iter()
            .map(MempoolAdmission::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_encrypted_batch_payload_root(admissions: &[MempoolAdmission]) -> String {
    merkle_root(
        "MEMPOOL-ENCRYPTED-BATCH-PAYLOAD",
        &admissions
            .iter()
            .map(|admission| {
                json!({
                    "admission_id": admission.admission_id,
                    "encrypted_payload_hash": admission.encrypted_payload_hash,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_batch_relay_path_commitment_root(admissions: &[MempoolAdmission]) -> String {
    merkle_root(
        "MEMPOOL-BATCH-RELAY-PATH-COMMITMENT",
        &admissions
            .iter()
            .map(|admission| {
                let mut record = json!({
                    "admission_id": admission.admission_id,
                });
                record
                    .as_object_mut()
                    .expect("batch relay commitment object")
                    .extend(relay_path_public_metadata(&admission.relay_path));
                record
            })
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_encrypted_batch_receipt_id(
    batch_sequence: u64,
    admission_root: &str,
    encrypted_payload_root: &str,
    relay_path_commitment_root: &str,
    inclusion_deadline_height: u64,
    sequencer_label: &str,
) -> String {
    domain_hash(
        "MEMPOOL-ENCRYPTED-BATCH-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_sequence as i128),
            HashPart::Str(admission_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(relay_path_commitment_root),
            HashPart::Int(inclusion_deadline_height as i128),
            HashPart::Str(sequencer_label),
        ],
        32,
    )
}

pub fn mempool_encrypted_batch_receipt_root(receipts: &[MempoolEncryptedBatchReceipt]) -> String {
    merkle_root(
        "MEMPOOL-ENCRYPTED-BATCH-RECEIPT",
        &receipts
            .iter()
            .map(MempoolEncryptedBatchReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_anti_censorship_lane_id(
    lane_label: &str,
    lane_sequence: u64,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "MEMPOOL-ANTI-CENSORSHIP-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_label),
            HashPart::Int(lane_sequence as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn mempool_relay_fairness_ticket_id(
    admission_id: &str,
    lane_id: &str,
    issued_at_height: u64,
    inclusion_deadline_height: u64,
    sequencer_label: &str,
) -> String {
    domain_hash(
        "MEMPOOL-RELAY-FAIRNESS-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(admission_id),
            HashPart::Str(lane_id),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(inclusion_deadline_height as i128),
            HashPart::Str(sequencer_label),
        ],
        32,
    )
}

pub fn mempool_relay_fairness_ticket_root(tickets: &[MempoolRelayFairnessTicket]) -> String {
    merkle_root(
        "MEMPOOL-RELAY-FAIRNESS-TICKET",
        &tickets
            .iter()
            .map(MempoolRelayFairnessTicket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_forced_inclusion_root(forced_inclusions: &[MempoolForcedInclusion]) -> String {
    merkle_root(
        "MEMPOOL-FORCED-INCLUSION",
        &forced_inclusions
            .iter()
            .map(MempoolForcedInclusion::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn mempool_anti_censorship_lane_commitment_id(
    lane_id: &str,
    reserved_slot_count: u64,
    minimum_private_admissions: u64,
    fairness_ticket_root: &str,
    encrypted_batch_receipt_root: &str,
    forced_inclusion_root: &str,
    sequencer_label: &str,
) -> String {
    domain_hash(
        "MEMPOOL-ANTI-CENSORSHIP-LANE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Int(reserved_slot_count as i128),
            HashPart::Int(minimum_private_admissions as i128),
            HashPart::Str(fairness_ticket_root),
            HashPart::Str(encrypted_batch_receipt_root),
            HashPart::Str(forced_inclusion_root),
            HashPart::Str(sequencer_label),
        ],
        32,
    )
}

pub fn mempool_anti_censorship_lane_commitment_root(
    commitments: &[MempoolAntiCensorshipLaneCommitment],
) -> String {
    merkle_root(
        "MEMPOOL-ANTI-CENSORSHIP-LANE-COMMITMENT",
        &commitments
            .iter()
            .map(MempoolAntiCensorshipLaneCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn relay_path_policy(relay_path: &str) -> String {
    let normalized = relay_path.trim().to_lowercase();
    if normalized.is_empty() || normalized == "direct" || normalized == "none" {
        return "direct".to_string();
    }
    if normalized.contains("forced") {
        return "forced-inclusion".to_string();
    }
    if normalized.contains("dandelion") {
        return "dandelion".to_string();
    }
    if normalized.contains("i2p") {
        return "i2p".to_string();
    }
    if normalized.contains("tor") {
        return "tor".to_string();
    }
    if normalized.contains("mix") {
        return "mixnet".to_string();
    }
    "private-relay".to_string()
}

pub fn relay_path_hop_count(relay_path: &str) -> u64 {
    let normalized = relay_path.trim();
    if normalized.is_empty() {
        return 0;
    }
    let compact = normalized.replace("->", "-").replace(['/', ',', ':'], "-");
    std::cmp::max(
        1,
        compact
            .split('-')
            .filter(|part| !part.trim().is_empty())
            .count() as u64,
    )
}

pub fn relay_path_commitment(relay_path: &str) -> String {
    let policy = relay_path_policy(relay_path);
    let hop_count = relay_path_hop_count(relay_path);
    domain_hash(
        "RELAY-PATH-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&policy),
            HashPart::Int(hop_count as i128),
            HashPart::Str(relay_path),
        ],
        32,
    )
}

pub fn relay_path_public_metadata(relay_path: &str) -> serde_json::Map<String, Value> {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "relay_path_policy".to_string(),
        Value::String(relay_path_policy(relay_path)),
    );
    metadata.insert(
        "relay_path_hop_count".to_string(),
        json!(relay_path_hop_count(relay_path)),
    );
    metadata.insert(
        "relay_path_commitment".to_string(),
        Value::String(relay_path_commitment(relay_path)),
    );
    metadata
}

pub fn prefixed_relay_path_public_metadata(
    relay_path: &str,
    field_prefix: &str,
) -> serde_json::Map<String, Value> {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        format!("{field_prefix}_policy"),
        Value::String(relay_path_policy(relay_path)),
    );
    metadata.insert(
        format!("{field_prefix}_hop_count"),
        json!(relay_path_hop_count(relay_path)),
    );
    metadata.insert(
        format!("{field_prefix}_commitment"),
        Value::String(relay_path_commitment(relay_path)),
    );
    metadata
}

fn with_authorization(mut record: Value, authorization: &Authorization) -> Value {
    let object = record
        .as_object_mut()
        .expect("authorization record must be an object");
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

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: ACCOUNT_SIGNATURE_SCHEME.to_string(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    record_id: String,
    record: T,
    record_kind: &str,
) -> MempoolResult<()> {
    if records.contains_key(&record_id) {
        return Err(format!("mempool {record_kind} already exists"));
    }
    records.insert(record_id, record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::{build_l2_block, BlockBuildInput, BlockStateRoots},
        fees::{BlockExecutionProfile, FeeMarketResource},
    };

    fn validator() -> Validator {
        Validator::new("devnet-proposer", 1_000).unwrap()
    }

    fn tx_public_record() -> Value {
        json!({"kind": "noop", "nonce": 1})
    }

    fn tx_state_record() -> Value {
        json!({"kind": "noop", "nonce": 1, "private_witness_hash": "hidden"})
    }

    fn admission() -> MempoolAdmission {
        MempoolAdmission::build(MempoolAdmissionRequest {
            tx_public_record: tx_public_record(),
            tx_state_record: tx_state_record(),
            mempool_sequence: 0,
            relay_path: "dandelion-stem-fluff".to_string(),
            admitted_at_height: 0,
            expires_at_height: 10,
            sequencer_label: "devnet-proposer".to_string(),
            committee_key_id: mempool_committee_key_id(&[validator()]),
        })
    }

    #[test]
    fn admission_and_preconfirmation_match_python_reference_vectors() {
        let admission = admission();
        assert_eq!(
            admission.committee_key_id,
            "933c1021cc34b4bcbbc336e280b1b29a2d0a61553c23da843ba71443b321787d"
        );
        assert_eq!(
            admission.tx_public_hash,
            "636463499974544706a4a143273976fd2b5e2ad6e54941f0c6f156c25063724b"
        );
        assert_eq!(
            admission.encrypted_payload_hash,
            "f6c8970ae575d7b03654e3630bc722fd87fb0d1716468356bc66cfe3a57dd505"
        );
        assert_eq!(
            admission.kem_ciphertext_hash,
            "a7c11079b53cdae3e7d2cb1210887d365d882522e71971768b3856046308e7b6"
        );
        assert_eq!(
            admission.admission_id,
            "8d8a506fc25323ec6c2d8779af06a5f5526f00f194631f40da8f85de9a9956be"
        );
        assert_eq!(
            admission.unsigned_record()["relay_path_policy"],
            "dandelion"
        );
        assert_eq!(admission.unsigned_record()["relay_path_hop_count"], 3);
        assert!(!admission
            .public_record()
            .to_string()
            .contains("dandelion-stem-fluff"));
        assert!(admission
            .state_record()
            .to_string()
            .contains("dandelion-stem-fluff"));
        assert!(admission.verify_authorization());
        assert_eq!(
            admission.authorization.auth_transcript_hash,
            "ea2372e5103dc5253942d0be65f544dff867ee173bd943fc6f967bd24ecac90c"
        );
        assert_eq!(
            mempool_admission_root(std::slice::from_ref(&admission)),
            "5ad4edf7354db4f6b4754be0a4f9ef44b35cb81e78cc984e6d45b179bdefba3b"
        );

        let preconfirmation = MempoolPreconfirmation::build(
            &admission,
            0,
            &mempool_admission_root(std::slice::from_ref(&admission)),
            1,
            &BlockExecutionProfile::empty().local_fee_market_root,
        )
        .unwrap();
        assert_eq!(
            preconfirmation.preconfirmation_id,
            "00f9e54718b3218def4f7262460bd7da08ff386668276b15863f7616b319112c"
        );
        assert_eq!(
            preconfirmation.authorization.auth_transcript_hash,
            "ced432127637df6686399344c922b27835afd5d16ce2c8f36788908d99660238"
        );
        assert!(preconfirmation.verify_authorization());
        assert_eq!(
            merkle_root(
                "MEMPOOL-PRECONFIRMATION",
                &[preconfirmation.public_record()]
            ),
            "d9efff3694f7adba0763265ff3bfe1437896d1a291d543fd590e5754de34e8fb"
        );
    }

    #[test]
    fn omission_forced_inclusion_and_preconfirmation_miss_match_python_vectors() {
        let admission = admission();
        let preconfirmation = MempoolPreconfirmation::build(
            &admission,
            0,
            &mempool_admission_root(std::slice::from_ref(&admission)),
            1,
            &BlockExecutionProfile::empty().local_fee_market_root,
        )
        .unwrap();
        let sequencer = validator();
        let omission = MempoolOmissionEvidence::report(
            &admission,
            11,
            "watchtower",
            &sequencer.validator_id,
            1,
            999,
        )
        .unwrap();
        assert_eq!(
            omission.evidence_id,
            "b3c407ef4dcecaf68a558fb584a96f3f06a67d88e8bc876c4ea306d9a81a011c"
        );
        assert_eq!(
            merkle_root("MEMPOOL-OMISSION-EVIDENCE", &[omission.public_record()]),
            "829380ddba7ef6fa67cbaab22d0c3547684b085906b870c22ea094ef16f6595d"
        );
        assert_eq!(
            omission.authorization.auth_transcript_hash,
            "5f2c9546d0cd021cbefbf4ca4e77e8b1e036950a19570d6f52684b2b33ed4f7a"
        );
        assert!(!omission
            .public_record()
            .to_string()
            .contains("dandelion-stem-fluff"));

        let new_admission = MempoolAdmission::build(MempoolAdmissionRequest {
            tx_public_record: tx_public_record(),
            tx_state_record: tx_state_record(),
            mempool_sequence: 0,
            relay_path: "forced-inclusion".to_string(),
            admitted_at_height: 11,
            expires_at_height: 21,
            sequencer_label: "devnet-proposer".to_string(),
            committee_key_id: admission.committee_key_id.clone(),
        });
        assert_eq!(
            new_admission.admission_id,
            "797be88b15e0a6895adbc57aa9b3fd5af234190f8734aa8cbdd10694d1d5510d"
        );
        let forced =
            MempoolForcedInclusion::build(&omission, &new_admission, 11, "devnet-proposer")
                .unwrap();
        assert_eq!(
            forced.forced_inclusion_id,
            "65ec672e6506cf21b8b32daebb8b62564a82c5bce2531184ecc21449ce8deb34"
        );
        assert_eq!(
            forced.unsigned_record()["new_relay_path_policy"],
            "forced-inclusion"
        );
        assert_eq!(
            merkle_root("MEMPOOL-FORCED-INCLUSION", &[forced.public_record()]),
            "d6c569ae47ef980c9a15e86019c0a73b3264ca9724879805ab748aa004a714f8"
        );

        let miss = MempoolPreconfirmationMissEvidence::report(
            &preconfirmation,
            2,
            "watchtower",
            &sequencer.validator_id,
            2,
            998,
        )
        .unwrap();
        assert_eq!(
            miss.evidence_id,
            "950c310c2371b5791f1ba0ab5fbf4324cef6cfd7e75433ef14963de65f908af7"
        );
        assert_eq!(
            merkle_root(
                "MEMPOOL-PRECONFIRMATION-MISS-EVIDENCE",
                &[miss.public_record()]
            ),
            "4dcfc633f9df317e2095874bfc48ce2c6eacb4121879121487b29c89196a888b"
        );
    }

    #[test]
    fn mempool_admission_records_feed_block_admission_root() {
        let admission = admission();
        let mut mempool = MempoolState {
            pending_admissions: vec![admission.clone()],
            ..MempoolState::default()
        };
        let preconfirmation = MempoolPreconfirmation::build(
            &admission,
            0,
            &mempool.admission_root(),
            1,
            &BlockExecutionProfile::empty().local_fee_market_root,
        )
        .unwrap();
        mempool
            .preconfirmations
            .insert(preconfirmation.preconfirmation_id.clone(), preconfirmation);

        let produced = build_l2_block(BlockBuildInput {
            height: 0,
            epoch: 0,
            timestamp_ms: 1_700_000_000_000,
            prev_block_hash: "GENESIS".to_string(),
            previous_state_root: "GENESIS".to_string(),
            transactions: vec![tx_public_record()],
            mempool_admissions: mempool.admission_public_records(),
            state_roots: BlockStateRoots::empty(),
            fee_resources: vec![FeeMarketResource::operation("noop", 1, "")],
            validators: vec![validator()],
            proposer_label: "devnet-proposer".to_string(),
        })
        .unwrap();
        assert_eq!(produced.block.header.mempool_admission_count, 1);
        assert_eq!(
            produced.block.header.mempool_admission_root,
            mempool.admission_root()
        );
        assert_eq!(mempool.preconfirmation_root().len(), 64);
        assert!(!produced
            .da_record
            .public_record()
            .to_string()
            .contains("dandelion-stem-fluff"));
    }
}
