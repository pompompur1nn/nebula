use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::L2BlockHeader,
    crypto_policy::{account_record, sign_authorization, verify_authorization, Authorization},
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID,
};

pub const BRIDGE_WITHDRAWAL_AMOUNT_BUCKET: u64 = 1_000;
pub const BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS: u64 = 2;
pub const BRIDGE_WITHDRAWAL_RELEASE_RATE_LIMIT_AMOUNT: u64 = 10_000;

pub type SettlementResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDepositAddress {
    pub deposit_id: String,
    pub recipient_view_key: String,
    pub monero_address: String,
    pub address_hash: String,
    pub status: String,
    pub created_at_ms: u64,
}

impl BridgeDepositAddress {
    pub fn request(
        recipient_view_key: impl Into<String>,
        deposit_index: u64,
        nonce: u64,
        created_at_ms: u64,
    ) -> Self {
        let recipient_view_key = recipient_view_key.into();
        let deposit_id = domain_hash(
            "BRIDGE-DEPOSIT-ID",
            &[
                HashPart::Str(&recipient_view_key),
                HashPart::Int(deposit_index as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let monero_address = format!(
            "xmr-devnet-{}",
            domain_hash(
                "BRIDGE-MONERO-ADDRESS",
                &[
                    HashPart::Str(&deposit_id),
                    HashPart::Str(&recipient_view_key)
                ],
                48,
            )
        );
        let address_hash = monero_address_hash(&monero_address);
        Self {
            deposit_id,
            recipient_view_key,
            monero_address,
            address_hash,
            status: "open".to_string(),
            created_at_ms,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "address_hash": self.address_hash,
            "status": self.status,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "recipient_view_key": self.recipient_view_key,
            "monero_address": self.monero_address,
            "address_hash": self.address_hash,
            "status": self.status,
            "created_at_ms": self.created_at_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDepositObservation {
    pub deposit_id: String,
    pub monero_txid: String,
    pub amount: u64,
    pub confirmations: u64,
    pub watcher_labels: Vec<String>,
    pub attestation_root: String,
    pub status: String,
    pub signer_set_id: String,
    pub signer_threshold: u64,
}

impl BridgeDepositObservation {
    pub fn observe(
        request: &BridgeDepositAddress,
        monero_txid: impl Into<String>,
        amount: u64,
        confirmations: u64,
        signer_set: &BridgeSignerSet,
        signer_labels: &[String],
    ) -> SettlementResult<Self> {
        if amount == 0 {
            return Err("bridge deposit amount must be positive".to_string());
        }
        validate_signer_quorum(signer_set, signer_labels, "bridge deposit")?;
        let monero_txid = monero_txid.into();
        let attestation_root = bridge_deposit_attestation_root(
            request,
            &monero_txid,
            amount,
            confirmations,
            &signer_set.signer_set_id,
            signer_labels,
        );
        Ok(Self {
            deposit_id: request.deposit_id.clone(),
            monero_txid,
            amount,
            confirmations,
            watcher_labels: signer_labels.to_vec(),
            attestation_root,
            status: "observed".to_string(),
            signer_set_id: signer_set.signer_set_id.clone(),
            signer_threshold: signer_set.threshold,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "monero_txid_hash": monero_txid_hash(&self.monero_txid),
            "amount": self.amount,
            "confirmations": self.confirmations,
            "signer_set_id": self.signer_set_id,
            "signer_threshold": self.signer_threshold,
            "signer_count": self.watcher_labels.len(),
            "attestation_root": self.attestation_root,
            "status": self.status,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "monero_txid": self.monero_txid,
            "amount": self.amount,
            "confirmations": self.confirmations,
            "watcher_labels": self.watcher_labels,
            "attestation_root": self.attestation_root,
            "status": self.status,
            "signer_set_id": self.signer_set_id,
            "signer_threshold": self.signer_threshold,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMintRecord {
    pub deposit_id: String,
    pub monero_txid: String,
    pub amount: u64,
    pub output_commitment: String,
    pub attestation_root: String,
    pub bridge_signature_root: String,
    pub signer_set_id: String,
    pub signer_threshold: u64,
    pub signer_count: u64,
    pub proof_system: String,
}

impl BridgeMintRecord {
    pub fn from_observation(
        observation: &BridgeDepositObservation,
        output_commitment: impl Into<String>,
    ) -> Self {
        Self {
            deposit_id: observation.deposit_id.clone(),
            monero_txid: observation.monero_txid.clone(),
            amount: observation.amount,
            output_commitment: output_commitment.into(),
            attestation_root: observation.attestation_root.clone(),
            bridge_signature_root: bridge_mint_signature_root(observation),
            signer_set_id: observation.signer_set_id.clone(),
            signer_threshold: observation.signer_threshold,
            signer_count: observation.watcher_labels.len() as u64,
            proof_system: "devnet-mock-bridge-deposit-proof".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_mint",
            "deposit_id": self.deposit_id,
            "monero_txid_hash": monero_txid_hash(&self.monero_txid),
            "amount": self.amount,
            "output_commitment": self.output_commitment,
            "attestation_root": self.attestation_root,
            "bridge_signature_root": self.bridge_signature_root,
            "signer_set_id": self.signer_set_id,
            "signer_threshold": self.signer_threshold,
            "signer_count": self.signer_count,
            "proof_system": self.proof_system,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalQueueRequest {
    pub spent_note_id: String,
    pub nullifier: String,
    pub amount: u64,
    pub monero_address: String,
    pub bridge_fee: u64,
    pub requested_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalRecord {
    pub withdrawal_id: String,
    pub nullifier: String,
    pub amount: u64,
    pub monero_address_hash: String,
    pub bridge_fee: u64,
    pub status: String,
    pub bridge_signature_root: String,
    pub queue_signer_set_id: String,
    pub queue_signer_threshold: u64,
    pub queue_signer_count: u64,
    pub requested_at_height: u64,
    pub amount_bucket: u64,
    pub privacy_delay_blocks: u64,
    pub release_not_before_height: u64,
    pub release_monero_txid_hash: String,
    pub release_signer_count: u64,
    pub release_signer_set_id: String,
    pub release_signature_root: String,
    pub release_confirmations: u64,
    pub released_at_height: u64,
    pub released_at_ms: u64,
    pub completed_at_ms: u64,
}

impl BridgeWithdrawalRecord {
    pub fn queue(
        request: BridgeWithdrawalQueueRequest,
        signer_set: &BridgeSignerSet,
        signer_labels: &[String],
    ) -> SettlementResult<Self> {
        if request.amount == 0 {
            return Err("bridge withdrawal amount must be positive".to_string());
        }
        validate_signer_quorum(signer_set, signer_labels, "bridge withdrawal queue")?;
        let monero_address_hash = withdrawal_monero_address_hash(&request.monero_address);
        let withdrawal_id = domain_hash(
            "BRIDGE-WITHDRAWAL-ID",
            &[
                HashPart::Str(&request.spent_note_id),
                HashPart::Str(&request.nullifier),
                HashPart::Int(request.amount as i128),
                HashPart::Int(request.bridge_fee as i128),
                HashPart::Str(&monero_address_hash),
            ],
            32,
        );
        let bridge_signature_root = bridge_withdrawal_queue_signature_root(
            &withdrawal_id,
            request.amount,
            &monero_address_hash,
            &signer_set.signer_set_id,
            signer_labels,
        );
        Ok(Self {
            withdrawal_id,
            nullifier: request.nullifier,
            amount: request.amount,
            monero_address_hash,
            bridge_fee: request.bridge_fee,
            status: "queued".to_string(),
            bridge_signature_root,
            queue_signer_set_id: signer_set.signer_set_id.clone(),
            queue_signer_threshold: signer_set.threshold,
            queue_signer_count: signer_labels.len() as u64,
            requested_at_height: request.requested_at_height,
            amount_bucket: amount_bucket(request.amount),
            privacy_delay_blocks: BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS,
            release_not_before_height: request.requested_at_height
                + BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS,
            release_monero_txid_hash: String::new(),
            release_signer_count: 0,
            release_signer_set_id: String::new(),
            release_signature_root: String::new(),
            release_confirmations: 0,
            released_at_height: 0,
            released_at_ms: 0,
            completed_at_ms: 0,
        })
    }

    pub fn release(
        &self,
        monero_txid: &str,
        released_at_height: u64,
        released_at_ms: u64,
        signer_set: &BridgeSignerSet,
        signer_labels: &[String],
    ) -> SettlementResult<Self> {
        if released_at_height < self.release_not_before_height {
            return Err("bridge withdrawal privacy delay has not elapsed".to_string());
        }
        validate_signer_quorum(signer_set, signer_labels, "bridge withdrawal release")?;
        let release_monero_txid_hash = monero_txid_hash(monero_txid);
        let release_signature_root = bridge_withdrawal_release_signature_root(
            self,
            &release_monero_txid_hash,
            signer_labels,
            &signer_set.signer_set_id,
        );
        Ok(Self {
            status: "submitted".to_string(),
            release_monero_txid_hash,
            release_signer_count: signer_labels.len() as u64,
            release_signer_set_id: signer_set.signer_set_id.clone(),
            release_signature_root,
            released_at_height,
            released_at_ms,
            ..self.clone()
        })
    }

    pub fn confirm(&self, confirmations: u64, finality_depth: u64, completed_at_ms: u64) -> Self {
        let status = if confirmations >= finality_depth {
            "completed"
        } else {
            "submitted"
        };
        Self {
            status: status.to_string(),
            release_confirmations: confirmations,
            completed_at_ms: if status == "completed" {
                completed_at_ms
            } else {
                self.completed_at_ms
            },
            ..self.clone()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "nullifier": self.nullifier,
            "amount": self.amount,
            "monero_address_hash": self.monero_address_hash,
            "bridge_fee": self.bridge_fee,
            "status": self.status,
            "bridge_signature_root": self.bridge_signature_root,
            "queue_signer_set_id": self.queue_signer_set_id,
            "queue_signer_threshold": self.queue_signer_threshold,
            "queue_signer_count": self.queue_signer_count,
            "requested_at_height": self.requested_at_height,
            "amount_bucket": self.amount_bucket,
            "privacy_delay_blocks": self.privacy_delay_blocks,
            "release_not_before_height": self.release_not_before_height,
            "release_monero_txid_hash": self.release_monero_txid_hash,
            "release_signer_count": self.release_signer_count,
            "release_signer_set_id": self.release_signer_set_id,
            "release_signature_root": self.release_signature_root,
            "release_confirmations": self.release_confirmations,
            "released_at_height": self.released_at_height,
            "released_at_ms": self.released_at_ms,
            "completed_at_ms": self.completed_at_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeReserveSnapshot {
    pub reserve_asset_id: String,
    pub deposited_amount: u64,
    pub released_amount: u64,
    pub completed_withdrawal_amount: u64,
    pub pending_withdrawal_amount: u64,
    pub queued_withdrawal_amount: u64,
    pub submitted_withdrawal_amount: u64,
    pub liability_amount: u64,
}

impl BridgeReserveSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_reserve_snapshot",
            "chain_id": CHAIN_ID,
            "reserve_asset_id": self.reserve_asset_id,
            "deposited_amount": self.deposited_amount,
            "released_amount": self.released_amount,
            "completed_withdrawal_amount": self.completed_withdrawal_amount,
            "pending_withdrawal_amount": self.pending_withdrawal_amount,
            "queued_withdrawal_amount": self.queued_withdrawal_amount,
            "submitted_withdrawal_amount": self.submitted_withdrawal_amount,
            "liability_amount": self.liability_amount,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeReserveReport {
    pub report_id: String,
    pub reserve_asset_id: String,
    pub reserve_address_hash_root: String,
    pub reported_reserve_amount_bucket: u64,
    pub deposited_amount: u64,
    pub released_amount: u64,
    pub completed_withdrawal_amount: u64,
    pub pending_withdrawal_amount: u64,
    pub queued_withdrawal_amount: u64,
    pub submitted_withdrawal_amount: u64,
    pub liability_amount: u64,
    pub coverage_bps: u64,
    pub status: String,
    pub reporter_labels: Vec<String>,
    pub reporter_signature_root: String,
    pub signer_set_id: String,
    pub signer_threshold: u64,
    pub reported_at_l2_height: u64,
    pub reported_at_ms: u64,
}

impl BridgeReserveReport {
    #[allow(clippy::too_many_arguments)]
    pub fn from_snapshot(
        snapshot: &BridgeReserveSnapshot,
        reserve_address_hash_root: impl Into<String>,
        reported_reserve_amount: u64,
        reported_at_l2_height: u64,
        reported_at_ms: u64,
        signer_set: &BridgeSignerSet,
        reporter_labels: &[String],
    ) -> SettlementResult<Self> {
        validate_signer_quorum(signer_set, reporter_labels, "bridge reserve report")?;
        let reserve_address_hash_root = reserve_address_hash_root.into();
        let reported_reserve_amount_bucket = amount_bucket(reported_reserve_amount);
        let coverage_bps = if snapshot.liability_amount == 0 {
            10_000
        } else {
            reported_reserve_amount_bucket.saturating_mul(10_000) / snapshot.liability_amount
        };
        let status = bridge_reserve_coverage_status(coverage_bps);
        let report_id = bridge_reserve_report_id(
            &snapshot.reserve_asset_id,
            &reserve_address_hash_root,
            reported_reserve_amount_bucket,
            snapshot.liability_amount,
            reported_at_l2_height,
        );
        let mut report = Self {
            report_id,
            reserve_asset_id: snapshot.reserve_asset_id.clone(),
            reserve_address_hash_root,
            reported_reserve_amount_bucket,
            deposited_amount: snapshot.deposited_amount,
            released_amount: snapshot.released_amount,
            completed_withdrawal_amount: snapshot.completed_withdrawal_amount,
            pending_withdrawal_amount: snapshot.pending_withdrawal_amount,
            queued_withdrawal_amount: snapshot.queued_withdrawal_amount,
            submitted_withdrawal_amount: snapshot.submitted_withdrawal_amount,
            liability_amount: snapshot.liability_amount,
            coverage_bps,
            status,
            reporter_labels: reporter_labels.to_vec(),
            reporter_signature_root: String::new(),
            signer_set_id: signer_set.signer_set_id.clone(),
            signer_threshold: signer_set.threshold,
            reported_at_l2_height,
            reported_at_ms,
        };
        report.reporter_signature_root = bridge_reserve_report_signature_root(&report);
        Ok(report)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "bridge_reserve_report",
            "chain_id": CHAIN_ID,
            "report_id": self.report_id,
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_address_hash_root": self.reserve_address_hash_root,
            "reported_reserve_amount_bucket": self.reported_reserve_amount_bucket,
            "deposited_amount": self.deposited_amount,
            "released_amount": self.released_amount,
            "completed_withdrawal_amount": self.completed_withdrawal_amount,
            "pending_withdrawal_amount": self.pending_withdrawal_amount,
            "queued_withdrawal_amount": self.queued_withdrawal_amount,
            "submitted_withdrawal_amount": self.submitted_withdrawal_amount,
            "liability_amount": self.liability_amount,
            "coverage_bps": self.coverage_bps,
            "status": self.status,
            "signer_set_id": self.signer_set_id,
            "signer_threshold": self.signer_threshold,
            "reported_at_l2_height": self.reported_at_l2_height,
            "reported_at_ms": self.reported_at_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("bridge reserve report unsigned record object");
        object.insert(
            "reporter_count".to_string(),
            json!(self.reporter_labels.len() as u64),
        );
        object.insert(
            "reporter_signature_root".to_string(),
            Value::String(self.reporter_signature_root.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalChallengeEvidence {
    pub evidence_id: String,
    pub withdrawal_id: String,
    pub challenge_kind: String,
    pub release_monero_txid_hash: String,
    pub old_monero_block_height: u64,
    pub old_monero_block_hash: String,
    pub new_monero_block_height: u64,
    pub new_monero_block_hash: String,
    pub reorg_depth: u64,
    pub status: String,
    pub reporter_labels: Vec<String>,
    pub reporter_signature_root: String,
    pub signer_set_id: String,
    pub signer_threshold: u64,
    pub reported_at_l2_height: u64,
    pub reported_at_ms: u64,
}

impl BridgeWithdrawalChallengeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn reorg(
        withdrawal: &BridgeWithdrawalRecord,
        old_monero_block_height: u64,
        old_monero_block_hash: impl Into<String>,
        new_monero_block_height: u64,
        new_monero_block_hash: impl Into<String>,
        reported_at_l2_height: u64,
        reported_at_ms: u64,
        signer_set: &BridgeSignerSet,
        reporter_labels: &[String],
    ) -> SettlementResult<Self> {
        if withdrawal.release_monero_txid_hash.is_empty() {
            return Err(
                "bridge withdrawal reorg evidence requires a released withdrawal".to_string(),
            );
        }
        validate_signer_quorum(
            signer_set,
            reporter_labels,
            "bridge withdrawal challenge evidence",
        )?;
        let old_monero_block_hash = old_monero_block_hash.into();
        let new_monero_block_hash = new_monero_block_hash.into();
        if old_monero_block_hash == new_monero_block_hash
            && old_monero_block_height == new_monero_block_height
        {
            return Err(
                "bridge withdrawal reorg evidence requires conflicting block observations"
                    .to_string(),
            );
        }
        let challenge_kind = "withdrawal_release_reorg".to_string();
        let reorg_depth = old_monero_block_height.abs_diff(new_monero_block_height);
        let evidence_id = bridge_withdrawal_challenge_evidence_id(
            &withdrawal.withdrawal_id,
            &challenge_kind,
            &withdrawal.release_monero_txid_hash,
            old_monero_block_height,
            &old_monero_block_hash,
            new_monero_block_height,
            &new_monero_block_hash,
        );
        let mut evidence = Self {
            evidence_id,
            withdrawal_id: withdrawal.withdrawal_id.clone(),
            challenge_kind,
            release_monero_txid_hash: withdrawal.release_monero_txid_hash.clone(),
            old_monero_block_height,
            old_monero_block_hash,
            new_monero_block_height,
            new_monero_block_hash,
            reorg_depth,
            status: if withdrawal.status == "completed" {
                "completed_release_reorg"
            } else {
                "release_reorg"
            }
            .to_string(),
            reporter_labels: reporter_labels.to_vec(),
            reporter_signature_root: String::new(),
            signer_set_id: signer_set.signer_set_id.clone(),
            signer_threshold: signer_set.threshold,
            reported_at_l2_height,
            reported_at_ms,
        };
        evidence.reporter_signature_root = bridge_withdrawal_challenge_signature_root(&evidence);
        Ok(evidence)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "bridge_withdrawal_challenge_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "withdrawal_id": self.withdrawal_id,
            "challenge_kind": self.challenge_kind,
            "release_monero_txid_hash": self.release_monero_txid_hash,
            "old_monero_block_height": self.old_monero_block_height,
            "old_monero_block_hash": self.old_monero_block_hash,
            "new_monero_block_height": self.new_monero_block_height,
            "new_monero_block_hash": self.new_monero_block_hash,
            "reorg_depth": self.reorg_depth,
            "status": self.status,
            "signer_set_id": self.signer_set_id,
            "signer_threshold": self.signer_threshold,
            "reported_at_l2_height": self.reported_at_l2_height,
            "reported_at_ms": self.reported_at_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("bridge withdrawal challenge evidence unsigned record object");
        object.insert(
            "reporter_count".to_string(),
            json!(self.reporter_labels.len() as u64),
        );
        object.insert(
            "reporter_signature_root".to_string(),
            Value::String(self.reporter_signature_root.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSignerSet {
    pub signer_set_id: String,
    pub epoch: u64,
    pub threshold: u64,
    pub signer_labels: Vec<String>,
    pub signer_public_key_root: String,
    pub active_from_height: u64,
    pub retired_at_height: u64,
    pub status: String,
    pub rotation_id: String,
    pub operator_label: String,
    pub authorization: Authorization,
}

impl BridgeSignerSet {
    pub fn new(
        signer_labels: &[String],
        threshold: u64,
        previous_set_id: &str,
        epoch: u64,
        active_from_height: u64,
        operator_label: impl Into<String>,
    ) -> SettlementResult<Self> {
        let operator_label = operator_label.into();
        let signer_labels = unique_labels(signer_labels)?;
        let threshold = if threshold == 0 {
            std::cmp::max(1, ((signer_labels.len() as u64) * 2).div_ceil(3))
        } else {
            threshold
        };
        if threshold > signer_labels.len() as u64 {
            return Err("bridge signer threshold exceeds signer count".to_string());
        }
        if operator_label.is_empty() {
            return Err("bridge signer set operator is required".to_string());
        }
        let signer_labels_json = json!(signer_labels);
        let rotation_id = domain_hash(
            "BRIDGE-SIGNER-SET-ROTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(previous_set_id),
                HashPart::Json(&signer_labels_json),
                HashPart::Int(threshold as i128),
                HashPart::Int(active_from_height as i128),
                HashPart::Str(&operator_label),
            ],
            32,
        );
        let signer_public_key_root = bridge_signer_public_key_root(&signer_labels);
        let signer_set_id = domain_hash(
            "BRIDGE-SIGNER-SET-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(epoch as i128),
                HashPart::Int(threshold as i128),
                HashPart::Json(&signer_labels_json),
                HashPart::Str(&signer_public_key_root),
                HashPart::Str(&rotation_id),
            ],
            32,
        );
        let mut signer_set = Self {
            signer_set_id,
            epoch,
            threshold,
            signer_labels,
            signer_public_key_root,
            active_from_height,
            retired_at_height: 0,
            status: "active".to_string(),
            rotation_id,
            operator_label,
            authorization: Authorization {
                signer_label: String::new(),
                auth_scheme: ACCOUNT_SIGNATURE_SCHEME.to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        signer_set.authorization = sign_authorization(
            &signer_set.operator_label,
            "bridge_signer_set_rotation",
            &signer_set.unsigned_record(),
        );
        Ok(signer_set)
    }

    pub fn retire(&self, retired_at_height: u64) -> Self {
        let mut retired = Self {
            status: "retired".to_string(),
            retired_at_height,
            ..self.clone()
        };
        retired.authorization = sign_authorization(
            &retired.operator_label,
            "bridge_signer_set_rotation",
            &retired.unsigned_record(),
        );
        retired
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "bridge_signer_set",
            "chain_id": CHAIN_ID,
            "signer_set_id": self.signer_set_id,
            "epoch": self.epoch,
            "threshold": self.threshold,
            "signer_labels": self.signer_labels,
            "signer_public_key_root": self.signer_public_key_root,
            "active_from_height": self.active_from_height,
            "retired_at_height": self.retired_at_height,
            "status": self.status,
            "rotation_id": self.rotation_id,
            "operator_label": self.operator_label,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("bridge signer set unsigned record object");
        object.insert("signer_count".to_string(), json!(self.signer_labels.len()));
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

    pub fn verify(&self) -> bool {
        if self.signer_labels.is_empty()
            || self.threshold == 0
            || self.threshold > self.signer_labels.len() as u64
        {
            return false;
        }
        if self.signer_public_key_root != bridge_signer_public_key_root(&self.signer_labels) {
            return false;
        }
        verify_authorization(
            &self.operator_label,
            "bridge_signer_set_rotation",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeState {
    pub wrapped_xmr_asset_id: String,
    pub deposit_addresses: BTreeMap<String, BridgeDepositAddress>,
    pub observations: BTreeMap<String, BridgeDepositObservation>,
    pub withdrawals: BTreeMap<String, BridgeWithdrawalRecord>,
    #[serde(default)]
    pub reserve_reports: BTreeMap<String, BridgeReserveReport>,
    #[serde(default)]
    pub withdrawal_challenges: BTreeMap<String, BridgeWithdrawalChallengeEvidence>,
    pub signer_sets: BTreeMap<String, BridgeSignerSet>,
    pub active_signer_set_id: String,
    pub paused: bool,
    pub pause_reason_hash: String,
    pub pause_action_id: String,
}

impl BridgeState {
    pub fn new(wrapped_xmr_asset_id: impl Into<String>) -> Self {
        Self {
            wrapped_xmr_asset_id: wrapped_xmr_asset_id.into(),
            ..Self::default()
        }
    }

    pub fn rotate_signer_set(
        &mut self,
        signer_labels: &[String],
        threshold: u64,
        active_from_height: u64,
        operator_label: &str,
    ) -> SettlementResult<BridgeSignerSet> {
        let previous_set_id = self.active_signer_set_id.clone();
        let signer_set = BridgeSignerSet::new(
            signer_labels,
            threshold,
            &previous_set_id,
            self.signer_sets.len() as u64,
            active_from_height,
            operator_label,
        )?;
        if let Some(previous) = self.signer_sets.get(&previous_set_id) {
            self.signer_sets
                .insert(previous_set_id, previous.retire(active_from_height));
        }
        self.active_signer_set_id = signer_set.signer_set_id.clone();
        self.signer_sets
            .insert(signer_set.signer_set_id.clone(), signer_set.clone());
        Ok(signer_set)
    }

    pub fn active_signer_set(&self) -> SettlementResult<&BridgeSignerSet> {
        self.signer_sets
            .get(&self.active_signer_set_id)
            .filter(|signer_set| signer_set.status == "active")
            .ok_or_else(|| "active bridge signer set is missing".to_string())
    }

    pub fn bridge_signer_set_root(&self) -> String {
        merkle_root(
            "BRIDGE-SIGNER-SET",
            &self
                .signer_sets
                .values()
                .map(BridgeSignerSet::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bridge_emergency_root(&self) -> String {
        merkle_root(
            "BRIDGE-EMERGENCY",
            &[json!({
                "paused": self.paused,
                "pause_reason_hash": self.pause_reason_hash,
                "pause_action_id": self.pause_action_id,
                "actions": Vec::<Value>::new(),
            })],
        )
    }

    pub fn reserve_snapshot(&self) -> BridgeReserveSnapshot {
        let deposited_amount = self
            .observations
            .values()
            .filter(|observation| observation.status == "observed")
            .fold(0_u64, |total, observation| {
                total.saturating_add(observation.amount)
            });
        let mut released_amount = 0_u64;
        let mut completed_withdrawal_amount = 0_u64;
        let mut queued_withdrawal_amount = 0_u64;
        let mut submitted_withdrawal_amount = 0_u64;
        for withdrawal in self.withdrawals.values() {
            if !withdrawal.release_monero_txid_hash.is_empty()
                || matches!(
                    withdrawal.status.as_str(),
                    "submitted" | "released" | "completed"
                )
            {
                released_amount = released_amount.saturating_add(withdrawal.amount);
            }
            match withdrawal.status.as_str() {
                "queued" => {
                    queued_withdrawal_amount =
                        queued_withdrawal_amount.saturating_add(withdrawal.amount);
                }
                "submitted" | "released" => {
                    submitted_withdrawal_amount =
                        submitted_withdrawal_amount.saturating_add(withdrawal.amount);
                }
                "completed" => {
                    completed_withdrawal_amount =
                        completed_withdrawal_amount.saturating_add(withdrawal.amount);
                }
                _ => {}
            }
        }
        let pending_withdrawal_amount =
            queued_withdrawal_amount.saturating_add(submitted_withdrawal_amount);
        let liability_amount = deposited_amount.saturating_sub(completed_withdrawal_amount);
        BridgeReserveSnapshot {
            reserve_asset_id: self.wrapped_xmr_asset_id.clone(),
            deposited_amount,
            released_amount,
            completed_withdrawal_amount,
            pending_withdrawal_amount,
            queued_withdrawal_amount,
            submitted_withdrawal_amount,
            liability_amount,
        }
    }

    pub fn publish_reserve_report(
        &mut self,
        reserve_addresses: &[String],
        reported_reserve_amount: u64,
        reported_at_l2_height: u64,
        reported_at_ms: u64,
        reporter_labels: &[String],
    ) -> SettlementResult<BridgeReserveReport> {
        let signer_set = self.active_signer_set()?.clone();
        let reserve_address_hash_root = bridge_reserve_address_hash_root(reserve_addresses);
        let report = BridgeReserveReport::from_snapshot(
            &self.reserve_snapshot(),
            reserve_address_hash_root,
            reported_reserve_amount,
            reported_at_l2_height,
            reported_at_ms,
            &signer_set,
            reporter_labels,
        )?;
        self.insert_reserve_report(report.clone())?;
        Ok(report)
    }

    pub fn insert_reserve_report(&mut self, report: BridgeReserveReport) -> SettlementResult<()> {
        if !self.wrapped_xmr_asset_id.is_empty()
            && report.reserve_asset_id != self.wrapped_xmr_asset_id
        {
            return Err("bridge reserve report asset id mismatch".to_string());
        }
        let expected_report_id = bridge_reserve_report_id(
            &report.reserve_asset_id,
            &report.reserve_address_hash_root,
            report.reported_reserve_amount_bucket,
            report.liability_amount,
            report.reported_at_l2_height,
        );
        if report.report_id != expected_report_id {
            return Err("bridge reserve report id mismatch".to_string());
        }
        let expected_coverage_bps = if report.liability_amount == 0 {
            10_000
        } else {
            report.reported_reserve_amount_bucket.saturating_mul(10_000) / report.liability_amount
        };
        if report.coverage_bps != expected_coverage_bps {
            return Err("bridge reserve report coverage mismatch".to_string());
        }
        if report.status != bridge_reserve_coverage_status(expected_coverage_bps) {
            return Err("bridge reserve report status mismatch".to_string());
        }
        let signer_set = self
            .signer_sets
            .get(&report.signer_set_id)
            .ok_or_else(|| "bridge reserve report signer set is missing".to_string())?;
        if report.signer_threshold != signer_set.threshold {
            return Err("bridge reserve report signer threshold mismatch".to_string());
        }
        validate_signer_quorum(signer_set, &report.reporter_labels, "bridge reserve report")?;
        if report.reporter_signature_root != bridge_reserve_report_signature_root(&report) {
            return Err("bridge reserve report signature root mismatch".to_string());
        }
        self.reserve_reports
            .insert(report.report_id.clone(), report);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_withdrawal_reorg_evidence(
        &mut self,
        withdrawal_id: &str,
        old_monero_block_height: u64,
        old_monero_block_hash: &str,
        new_monero_block_height: u64,
        new_monero_block_hash: &str,
        reported_at_l2_height: u64,
        reported_at_ms: u64,
        reporter_labels: &[String],
    ) -> SettlementResult<BridgeWithdrawalChallengeEvidence> {
        let signer_set = self.active_signer_set()?.clone();
        let withdrawal = self
            .withdrawals
            .get(withdrawal_id)
            .ok_or_else(|| "bridge withdrawal challenge target is missing".to_string())?
            .clone();
        let evidence = BridgeWithdrawalChallengeEvidence::reorg(
            &withdrawal,
            old_monero_block_height,
            old_monero_block_hash,
            new_monero_block_height,
            new_monero_block_hash,
            reported_at_l2_height,
            reported_at_ms,
            &signer_set,
            reporter_labels,
        )?;
        self.insert_withdrawal_challenge_evidence(evidence.clone())?;
        Ok(evidence)
    }

    pub fn insert_withdrawal_challenge_evidence(
        &mut self,
        evidence: BridgeWithdrawalChallengeEvidence,
    ) -> SettlementResult<()> {
        let withdrawal = self
            .withdrawals
            .get(&evidence.withdrawal_id)
            .ok_or_else(|| "bridge withdrawal challenge target is missing".to_string())?;
        if evidence.challenge_kind.is_empty() {
            return Err("bridge withdrawal challenge kind is required".to_string());
        }
        if evidence.release_monero_txid_hash.is_empty() {
            return Err("bridge withdrawal challenge requires a release txid hash".to_string());
        }
        if withdrawal.release_monero_txid_hash != evidence.release_monero_txid_hash {
            return Err("bridge withdrawal challenge release txid hash mismatch".to_string());
        }
        if evidence.old_monero_block_hash == evidence.new_monero_block_hash
            && evidence.old_monero_block_height == evidence.new_monero_block_height
        {
            return Err(
                "bridge withdrawal challenge requires conflicting block observations".to_string(),
            );
        }
        if evidence.reorg_depth
            != evidence
                .old_monero_block_height
                .abs_diff(evidence.new_monero_block_height)
        {
            return Err("bridge withdrawal challenge reorg depth mismatch".to_string());
        }
        let expected_evidence_id = bridge_withdrawal_challenge_evidence_id(
            &evidence.withdrawal_id,
            &evidence.challenge_kind,
            &evidence.release_monero_txid_hash,
            evidence.old_monero_block_height,
            &evidence.old_monero_block_hash,
            evidence.new_monero_block_height,
            &evidence.new_monero_block_hash,
        );
        if evidence.evidence_id != expected_evidence_id {
            return Err("bridge withdrawal challenge evidence id mismatch".to_string());
        }
        let signer_set = self
            .signer_sets
            .get(&evidence.signer_set_id)
            .ok_or_else(|| "bridge withdrawal challenge signer set is missing".to_string())?;
        if evidence.signer_threshold != signer_set.threshold {
            return Err("bridge withdrawal challenge signer threshold mismatch".to_string());
        }
        validate_signer_quorum(
            signer_set,
            &evidence.reporter_labels,
            "bridge withdrawal challenge evidence",
        )?;
        if evidence.reporter_signature_root != bridge_withdrawal_challenge_signature_root(&evidence)
        {
            return Err("bridge withdrawal challenge signature root mismatch".to_string());
        }
        self.withdrawal_challenges
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn bridge_withdrawal_challenge_root(&self) -> String {
        merkle_root(
            "BRIDGE-WITHDRAWAL-CHALLENGE",
            &self
                .withdrawal_challenges
                .values()
                .map(BridgeWithdrawalChallengeEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bridge_reserve_report_root(&self) -> String {
        merkle_root(
            "BRIDGE-RESERVE-REPORT",
            &self
                .reserve_reports
                .values()
                .map(BridgeReserveReport::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bridge_root(&self) -> String {
        merkle_root(
            "BRIDGE",
            &[json!({
                "wrapped_xmr_asset_id": self.wrapped_xmr_asset_id,
                "deposits": self.deposit_addresses.values().map(BridgeDepositAddress::public_record).collect::<Vec<_>>(),
                "observations": self.observations.values().map(BridgeDepositObservation::public_record).collect::<Vec<_>>(),
                "withdrawals": self.withdrawals.values().map(BridgeWithdrawalRecord::public_record).collect::<Vec<_>>(),
                "withdrawal_challenge_root": self.bridge_withdrawal_challenge_root(),
                "withdrawal_challenges": self.withdrawal_challenges.values().map(BridgeWithdrawalChallengeEvidence::public_record).collect::<Vec<_>>(),
                "signer_set_root": self.bridge_signer_set_root(),
                "active_signer_set_id": self.active_signer_set_id,
                "signer_sets": self.signer_sets.values().map(BridgeSignerSet::public_record).collect::<Vec<_>>(),
                "emergency_root": self.bridge_emergency_root(),
                "paused": self.paused,
                "pause_reason_hash": self.pause_reason_hash,
                "pause_action_id": self.pause_action_id,
                "reserve_report_root": self.bridge_reserve_report_root(),
                "reserve_reports": self.reserve_reports.values().map(BridgeReserveReport::public_record).collect::<Vec<_>>(),
            })],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCheckpoint {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub block_count: u64,
    pub complete: bool,
    pub block_hash_root: String,
    pub tx_root: String,
    pub state_root: String,
    pub da_root: String,
    pub validity_root: String,
    pub privacy_proof_aggregate_root: String,
    pub bridge_root: String,
    pub mempool_admission_root: String,
    pub validator_set_root: String,
    pub soft_finality_count: u64,
}

impl EpochCheckpoint {
    pub fn from_headers(
        headers: &[L2BlockHeader],
        epoch_size: u64,
        validity_roots: &[String],
        privacy_proof_aggregate_roots: &[String],
    ) -> SettlementResult<Self> {
        if headers.is_empty() {
            return Err("epoch checkpoint requires at least one header".to_string());
        }
        if epoch_size == 0 {
            return Err("epoch_size must be positive".to_string());
        }
        let epoch = headers[0].epoch;
        if headers.iter().any(|header| header.epoch != epoch) {
            return Err("epoch checkpoint headers must share an epoch".to_string());
        }
        let start_height = epoch * epoch_size;
        let end_height = headers.last().expect("headers non-empty").height;
        let block_count = headers.len() as u64;
        let block_hash_leaves = headers
            .iter()
            .map(|header| Value::String(header.block_hash()))
            .collect::<Vec<_>>();
        let tx_leaves = headers
            .iter()
            .map(|header| Value::String(header.tx_root.clone()))
            .collect::<Vec<_>>();
        let da_leaves = headers
            .iter()
            .map(|header| Value::String(header.da_root.clone()))
            .collect::<Vec<_>>();
        let mempool_leaves = headers
            .iter()
            .map(|header| Value::String(header.mempool_admission_root.clone()))
            .collect::<Vec<_>>();
        let validity_leaves = validity_roots
            .iter()
            .map(|root| Value::String(root.clone()))
            .collect::<Vec<_>>();
        let privacy_leaves = privacy_proof_aggregate_roots
            .iter()
            .map(|root| Value::String(root.clone()))
            .collect::<Vec<_>>();
        let last = headers.last().expect("headers non-empty");
        Ok(Self {
            epoch,
            start_height,
            end_height,
            block_count,
            complete: block_count == epoch_size,
            block_hash_root: merkle_root("EPOCH-BLOCK-HASH", &block_hash_leaves),
            tx_root: merkle_root("EPOCH-TX", &tx_leaves),
            state_root: last.state_root.clone(),
            da_root: merkle_root("EPOCH-DA", &da_leaves),
            validity_root: merkle_root("EPOCH-VALIDITY", &validity_leaves),
            privacy_proof_aggregate_root: merkle_root(
                "EPOCH-PRIVACY-PROOF-AGGREGATE",
                &privacy_leaves,
            ),
            bridge_root: last.bridge_root.clone(),
            mempool_admission_root: merkle_root("EPOCH-MEMPOOL-ADMISSION", &mempool_leaves),
            validator_set_root: last.validator_set_root.clone(),
            soft_finality_count: headers
                .iter()
                .map(|header| u64::from(header.soft_finality))
                .sum(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "epoch_checkpoint",
            "chain_id": CHAIN_ID,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "block_count": self.block_count,
            "complete": self.complete,
            "block_hash_root": self.block_hash_root,
            "tx_root": self.tx_root,
            "state_root": self.state_root,
            "da_root": self.da_root,
            "validity_root": self.validity_root,
            "privacy_proof_aggregate_root": self.privacy_proof_aggregate_root,
            "bridge_root": self.bridge_root,
            "mempool_admission_root": self.mempool_admission_root,
            "validator_set_root": self.validator_set_root,
            "soft_finality_count": self.soft_finality_count,
        })
    }

    pub fn checkpoint_root(&self) -> String {
        domain_hash(
            "EPOCH-CHECKPOINT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn anchor_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("checkpoint record object")
            .insert(
                "checkpoint_root".to_string(),
                Value::String(self.checkpoint_root()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorSubmission {
    pub anchor_id: String,
    pub block_height: u64,
    pub epoch: u64,
    pub anchor_commitment: String,
    pub checkpoint_root: String,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub epoch_block_count: u64,
    pub block_hash: String,
    pub state_root: String,
    pub bridge_root: String,
    pub submitter_label: String,
    pub monero_txid: String,
    pub confirmations: u64,
    pub status: String,
    pub submitted_at_ms: u64,
    pub finalized_at_ms: u64,
    pub authorization: Authorization,
}

impl AnchorSubmission {
    pub fn submit(
        header: &L2BlockHeader,
        checkpoint: &EpochCheckpoint,
        previous_epoch_checkpoint_root: &str,
        submitter_label: impl Into<String>,
        monero_txid: impl Into<String>,
        submitted_at_ms: u64,
    ) -> Self {
        let submitter_label = submitter_label.into();
        let monero_txid = monero_txid.into();
        let anchor_commitment = anchor_commitment(checkpoint, previous_epoch_checkpoint_root);
        let monero_txid_hash = monero_txid_hash(&monero_txid);
        let anchor_id = domain_hash(
            "ANCHOR-SUBMISSION-ID",
            &[
                HashPart::Int(header.height as i128),
                HashPart::Str(&anchor_commitment),
                HashPart::Str(&submitter_label),
                HashPart::Str(&monero_txid_hash),
            ],
            32,
        );
        let mut submission = Self {
            anchor_id,
            block_height: header.height,
            epoch: header.epoch,
            anchor_commitment,
            checkpoint_root: checkpoint.checkpoint_root(),
            epoch_start_height: checkpoint.start_height,
            epoch_end_height: checkpoint.end_height,
            epoch_block_count: checkpoint.block_count,
            block_hash: header.block_hash(),
            state_root: header.state_root.clone(),
            bridge_root: header.bridge_root.clone(),
            submitter_label,
            monero_txid,
            confirmations: 0,
            status: "submitted".to_string(),
            submitted_at_ms,
            finalized_at_ms: 0,
            authorization: Authorization {
                signer_label: String::new(),
                auth_scheme: ACCOUNT_SIGNATURE_SCHEME.to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        submission.authorization = sign_authorization(
            &submission.submitter_label,
            "monero_anchor_submission",
            &submission.unsigned_record(),
        );
        submission
    }

    pub fn confirm(&self, confirmations: u64, finality_depth: u64, finalized_at_ms: u64) -> Self {
        let is_final = confirmations >= finality_depth;
        Self {
            confirmations,
            status: if is_final { "final" } else { "submitted" }.to_string(),
            finalized_at_ms: if is_final {
                finalized_at_ms
            } else {
                self.finalized_at_ms
            },
            ..self.clone()
        }
    }

    pub fn monero_txid_hash(&self) -> String {
        monero_txid_hash(&self.monero_txid)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "monero_anchor_submission",
            "anchor_id": self.anchor_id,
            "block_height": self.block_height,
            "epoch": self.epoch,
            "anchor_commitment": self.anchor_commitment,
            "checkpoint_root": self.checkpoint_root,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "epoch_block_count": self.epoch_block_count,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "bridge_root": self.bridge_root,
            "submitter_label": self.submitter_label,
            "monero_txid_hash": self.monero_txid_hash(),
            "submitted_at_ms": self.submitted_at_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("anchor submission unsigned record object");
        object.insert("confirmations".to_string(), json!(self.confirmations));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("finalized_at_ms".to_string(), json!(self.finalized_at_ms));
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

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("anchor state record object")
            .insert(
                "monero_txid".to_string(),
                Value::String(self.monero_txid.clone()),
            );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization(
            &self.submitter_label,
            "monero_anchor_submission",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

pub fn anchor_commitment(
    checkpoint: &EpochCheckpoint,
    previous_epoch_checkpoint_root: &str,
) -> String {
    domain_hash(
        "NEBULA-L2-EPOCH-ANCHOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(checkpoint.epoch as i128),
            HashPart::Str(previous_epoch_checkpoint_root),
            HashPart::Json(&checkpoint.anchor_record()),
        ],
        32,
    )
}

pub fn monero_txid_hash(monero_txid: &str) -> String {
    domain_hash("MONERO-TXID-HASH", &[HashPart::Str(monero_txid)], 32)
}

pub fn monero_address_hash(monero_address: &str) -> String {
    domain_hash(
        "BRIDGE-MONERO-ADDRESS-HASH",
        &[HashPart::Str(monero_address)],
        32,
    )
}

pub fn withdrawal_monero_address_hash(monero_address: &str) -> String {
    domain_hash(
        "WITHDRAW-MONERO-ADDRESS-HASH",
        &[HashPart::Str(monero_address)],
        32,
    )
}

pub fn amount_bucket(amount: u64) -> u64 {
    amount.div_ceil(BRIDGE_WITHDRAWAL_AMOUNT_BUCKET) * BRIDGE_WITHDRAWAL_AMOUNT_BUCKET
}

pub fn bridge_reserve_address_hash_root(reserve_addresses: &[String]) -> String {
    merkle_root(
        "BRIDGE-RESERVE-ADDRESS",
        &reserve_addresses
            .iter()
            .map(|address| Value::String(monero_address_hash(address)))
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_reserve_report_id(
    reserve_asset_id: &str,
    reserve_address_hash_root: &str,
    reported_reserve_amount_bucket: u64,
    liability_amount: u64,
    reported_at_l2_height: u64,
) -> String {
    domain_hash(
        "BRIDGE-RESERVE-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(reserve_address_hash_root),
            HashPart::Int(reported_reserve_amount_bucket as i128),
            HashPart::Int(liability_amount as i128),
            HashPart::Int(reported_at_l2_height as i128),
        ],
        32,
    )
}

pub fn bridge_reserve_report_signature_root(report: &BridgeReserveReport) -> String {
    let payload = report.unsigned_record();
    merkle_root(
        "BRIDGE-RESERVE-REPORT-SIGNATURE",
        &report
            .reporter_labels
            .iter()
            .map(|label| {
                authorization_record(&sign_authorization(
                    label,
                    "bridge_reserve_report",
                    &payload,
                ))
            })
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_withdrawal_challenge_evidence_id(
    withdrawal_id: &str,
    challenge_kind: &str,
    release_monero_txid_hash: &str,
    old_monero_block_height: u64,
    old_monero_block_hash: &str,
    new_monero_block_height: u64,
    new_monero_block_hash: &str,
) -> String {
    domain_hash(
        "BRIDGE-WITHDRAWAL-CHALLENGE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(challenge_kind),
            HashPart::Str(release_monero_txid_hash),
            HashPart::Int(old_monero_block_height as i128),
            HashPart::Str(old_monero_block_hash),
            HashPart::Int(new_monero_block_height as i128),
            HashPart::Str(new_monero_block_hash),
        ],
        32,
    )
}

pub fn bridge_withdrawal_challenge_signature_root(
    evidence: &BridgeWithdrawalChallengeEvidence,
) -> String {
    let payload = evidence.unsigned_record();
    merkle_root(
        "BRIDGE-WITHDRAWAL-CHALLENGE-SIGNATURE",
        &evidence
            .reporter_labels
            .iter()
            .map(|label| {
                authorization_record(&sign_authorization(
                    label,
                    "bridge_withdrawal_challenge",
                    &payload,
                ))
            })
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_signer_public_key_root(signer_labels: &[String]) -> String {
    merkle_root(
        "BRIDGE-SIGNER-PUBLIC-KEY",
        &signer_labels
            .iter()
            .map(|label| {
                json!({
                    "signer_label": label,
                    "spend_public_key": account_record(label).spend_public_key,
                    "auth_scheme": ACCOUNT_SIGNATURE_SCHEME,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_deposit_observation_payload(
    request: &BridgeDepositAddress,
    monero_txid: &str,
    amount: u64,
    confirmations: u64,
    signer_set_id: &str,
) -> Value {
    json!({
        "deposit_id": request.deposit_id,
        "address_hash": request.address_hash,
        "monero_txid_hash": monero_txid_hash(monero_txid),
        "amount": amount,
        "confirmations": confirmations,
        "signer_set_id": signer_set_id,
    })
}

pub fn bridge_deposit_attestation_root(
    request: &BridgeDepositAddress,
    monero_txid: &str,
    amount: u64,
    confirmations: u64,
    signer_set_id: &str,
    signer_labels: &[String],
) -> String {
    let payload = bridge_deposit_observation_payload(
        request,
        monero_txid,
        amount,
        confirmations,
        signer_set_id,
    );
    merkle_root(
        "BRIDGE-DEPOSIT-ATTESTATION",
        &signer_labels
            .iter()
            .map(|label| {
                authorization_record(&sign_authorization(
                    label,
                    "bridge_deposit_observation",
                    &payload,
                ))
            })
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_mint_signature_root(observation: &BridgeDepositObservation) -> String {
    merkle_root(
        "BRIDGE-MINT-SIGNATURE",
        &observation
            .watcher_labels
            .iter()
            .map(|label| {
                let payload = json!({
                    "deposit_id": observation.deposit_id,
                    "monero_txid_hash": monero_txid_hash(&observation.monero_txid),
                    "amount": observation.amount,
                    "attestation_root": observation.attestation_root,
                    "signer_set_id": observation.signer_set_id,
                });
                authorization_record(&sign_authorization(label, "bridge_mint", &payload))
            })
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_withdrawal_queue_signature_root(
    withdrawal_id: &str,
    amount: u64,
    monero_address_hash: &str,
    signer_set_id: &str,
    signer_labels: &[String],
) -> String {
    let payload = json!({
        "withdrawal_id": withdrawal_id,
        "amount": amount,
        "monero_address_hash": monero_address_hash,
        "signer_set_id": signer_set_id,
    });
    merkle_root(
        "BRIDGE-WITHDRAWAL-QUEUE-SIGNATURE",
        &signer_labels
            .iter()
            .map(|label| {
                authorization_record(&sign_authorization(
                    label,
                    "bridge_withdrawal_queue",
                    &payload,
                ))
            })
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_withdrawal_release_signature_root(
    withdrawal: &BridgeWithdrawalRecord,
    monero_txid_hash: &str,
    signer_labels: &[String],
    signer_set_id: &str,
) -> String {
    let payload = json!({
        "withdrawal_id": withdrawal.withdrawal_id,
        "amount": withdrawal.amount,
        "monero_address_hash": withdrawal.monero_address_hash,
        "monero_txid_hash": monero_txid_hash,
        "signer_set_id": signer_set_id,
    });
    merkle_root(
        "BRIDGE-WITHDRAWAL-RELEASE-SIGNATURE",
        &signer_labels
            .iter()
            .map(|label| {
                authorization_record(&sign_authorization(
                    label,
                    "bridge_withdrawal_release",
                    &payload,
                ))
            })
            .collect::<Vec<_>>(),
    )
}

fn bridge_reserve_coverage_status(coverage_bps: u64) -> String {
    if coverage_bps >= 10_000 {
        "healthy"
    } else if coverage_bps >= 9_000 {
        "watch"
    } else {
        "underreserved"
    }
    .to_string()
}

fn authorization_record(authorization: &Authorization) -> Value {
    json!({
        "signer_label": authorization.signer_label,
        "auth_scheme": authorization.auth_scheme,
        "auth_public_key": authorization.auth_public_key,
        "auth_transcript_hash": authorization.auth_transcript_hash,
        "auth_signature": authorization.auth_signature,
    })
}

fn unique_labels(labels: &[String]) -> SettlementResult<Vec<String>> {
    if labels.is_empty() {
        return Err("bridge signer set requires signers".to_string());
    }
    let mut unique = Vec::new();
    for label in labels {
        if unique.contains(label) {
            return Err("bridge signer set contains duplicate signers".to_string());
        }
        unique.push(label.clone());
    }
    Ok(unique)
}

fn validate_signer_quorum(
    signer_set: &BridgeSignerSet,
    signer_labels: &[String],
    label: &str,
) -> SettlementResult<()> {
    let mut unique = BTreeSet::new();
    for signer_label in signer_labels {
        if !unique.insert(signer_label) {
            return Err(format!("{label} signer quorum contains duplicate signers"));
        }
    }
    if unique.len() < signer_set.threshold as usize {
        return Err(format!("{label} signer quorum not met"));
    }
    for signer_label in signer_labels {
        if !signer_set.signer_labels.contains(signer_label) {
            return Err(format!("{label} signer is not in the active signer set"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::{build_l2_block, BlockBuildInput, BlockStateRoots, ProducedBlock, Validator},
        fees::FeeMarketResource,
    };

    fn default_signer_labels() -> Vec<String> {
        vec![
            "bridge-signer-1".to_string(),
            "bridge-signer-2".to_string(),
            "bridge-signer-3".to_string(),
        ]
    }

    fn default_signers() -> Vec<String> {
        vec!["bridge-signer-1".to_string(), "bridge-signer-2".to_string()]
    }

    fn produced_block_with_bridge_root(bridge_root: String, height: u64) -> ProducedBlock {
        let input = BlockBuildInput {
            height,
            epoch: height / 10,
            timestamp_ms: 1_700_000_000_000 + height,
            prev_block_hash: if height == 0 {
                "GENESIS".to_string()
            } else {
                "previous".to_string()
            },
            previous_state_root: if height == 0 {
                "GENESIS".to_string()
            } else {
                "previous-state".to_string()
            },
            transactions: vec![json!({"kind": "noop", "height": height})],
            mempool_admissions: Vec::new(),
            state_roots: BlockStateRoots {
                bridge_root,
                ..BlockStateRoots::empty()
            },
            fee_resources: vec![FeeMarketResource::operation("noop", 1, "")],
            validators: vec![Validator::new("devnet-proposer", 1_000).unwrap()],
            proposer_label: "devnet-proposer".to_string(),
        };
        build_l2_block(input).unwrap()
    }

    #[test]
    fn bridge_signer_and_deposit_records_match_python_reference_vectors() {
        let mut bridge = BridgeState::new("");
        let signer_set = bridge
            .rotate_signer_set(&default_signer_labels(), 2, 0, "bridge-guardian")
            .unwrap();
        assert_eq!(
            signer_set.signer_set_id,
            "f7392db272e596608f3553c0f8047a44b87325bb4b05406a6039802cb0b72ea1"
        );
        assert_eq!(
            signer_set.rotation_id,
            "f0647051bbb538e737613cbac51b6c4f2f7645345c840de7ef5849ebd31948b1"
        );
        assert_eq!(
            signer_set.signer_public_key_root,
            "e1691721252e9bdf0c1caa0d0de89b119e2415729682794167ff42ae111a061e"
        );
        assert_eq!(
            bridge.bridge_signer_set_root(),
            "180af8c93b788cb09a7aeb59d3ec374256d1a215c9a094c7675e2d5fab58bd98"
        );
        assert!(signer_set.verify());

        let request = BridgeDepositAddress::request("alice-view-key", 0, 1, 1_700_000_000_000);
        assert_eq!(
            request.deposit_id,
            "9319d22bc60d1ebe801d8155be9b3be17640682444fae079c2fbdaf891d2f48f"
        );
        assert_eq!(
            request.address_hash,
            "2d0eeb24f9556aca8fa7a4650eb1e3e65dfec901f10ef3f53bd884426f5e0c93"
        );
        let observation = BridgeDepositObservation::observe(
            &request,
            "monero-txid-1",
            1_234_567,
            10,
            &signer_set,
            &default_signers(),
        )
        .unwrap();
        assert_eq!(
            observation.attestation_root,
            "dd9de500bb9f3ca74643f7ca3877c2077d1f99747844c66325d872569072509c"
        );
        assert_eq!(
            observation.public_record()["monero_txid_hash"],
            "f2e9c4300de1c16ba8bd24758e1f8bb7b6feac2f09b6acc1cde529b19d784bd5"
        );
        assert!(!observation
            .public_record()
            .to_string()
            .contains("monero-txid-1"));
    }

    #[test]
    fn queued_withdrawal_uses_hashed_address_bucket_delay_and_pq_quorum() {
        let signer_set =
            BridgeSignerSet::new(&default_signer_labels(), 2, "", 0, 0, "bridge-guardian").unwrap();
        let withdrawal = BridgeWithdrawalRecord::queue(
            BridgeWithdrawalQueueRequest {
                spent_note_id: "note-1".to_string(),
                nullifier: "nullifier-1".to_string(),
                amount: 25_000,
                monero_address: "84xmr-destination".to_string(),
                bridge_fee: 10,
                requested_at_height: 5,
            },
            &signer_set,
            &default_signers(),
        )
        .unwrap();

        assert_eq!(
            withdrawal.monero_address_hash,
            "7dc07ea09f0e4075d98bac52d6121cc619560e6880c46501ab60b701e5249555"
        );
        assert_eq!(
            withdrawal.withdrawal_id,
            "88f6da91e7bf6764813454735c759e119153ee8f0838ffd64cbac2a902a5f90f"
        );
        assert_eq!(
            withdrawal.bridge_signature_root,
            "c83a6e1f07af6b93af4fccbf66deb8cc40812e475864cfb1b4db5679739a9826"
        );
        assert_eq!(withdrawal.amount_bucket, 25_000);
        assert_eq!(withdrawal.release_not_before_height, 7);
        assert!(!withdrawal
            .public_record()
            .to_string()
            .contains("84xmr-destination"));

        assert!(withdrawal
            .release(
                "release-tx",
                6,
                1_700_000_000_100,
                &signer_set,
                &default_signers(),
            )
            .is_err());
        let released = withdrawal
            .release(
                "release-tx",
                7,
                1_700_000_000_100,
                &signer_set,
                &default_signers(),
            )
            .unwrap();
        assert_eq!(released.status, "submitted");
        assert_eq!(released.release_signer_count, 2);
        assert_eq!(released.release_monero_txid_hash.len(), 64);
    }

    #[test]
    fn epoch_checkpoint_and_anchor_amortize_l2_blocks_to_one_monero_commitment() {
        let mut bridge = BridgeState::new("wxmr-asset");
        bridge
            .rotate_signer_set(&default_signer_labels(), 2, 0, "bridge-guardian")
            .unwrap();
        let first = produced_block_with_bridge_root(bridge.bridge_root(), 0);
        let second = produced_block_with_bridge_root(bridge.bridge_root(), 1);
        let headers = vec![first.block.header.clone(), second.block.header.clone()];
        let validity_roots = vec![
            first.certificate.certificate_root(),
            second.certificate.certificate_root(),
        ];
        let aggregate_roots = vec![
            first.privacy_aggregate.aggregate_root(),
            second.privacy_aggregate.aggregate_root(),
        ];
        let checkpoint =
            EpochCheckpoint::from_headers(&headers, 10, &validity_roots, &aggregate_roots).unwrap();
        assert_eq!(checkpoint.epoch, 0);
        assert_eq!(checkpoint.block_count, 2);
        assert!(!checkpoint.complete);
        assert_eq!(checkpoint.soft_finality_count, 2);
        assert_eq!(checkpoint.checkpoint_root().len(), 64);

        let submission = AnchorSubmission::submit(
            &second.block.header,
            &checkpoint,
            "GENESIS",
            "anchor-submitter",
            "xmr-anchor-txid",
            1_700_000_000_500,
        );
        assert!(submission.verify_authorization());
        assert_eq!(submission.epoch_block_count, 2);
        assert_eq!(submission.monero_txid_hash().len(), 64);
        assert!(!submission
            .public_record()
            .to_string()
            .contains("xmr-anchor-txid"));
        let finalized = submission.confirm(10, 10, 1_700_000_001_000);
        assert_eq!(finalized.status, "final");
        assert_eq!(finalized.finalized_at_ms, 1_700_000_001_000);
    }
}
