use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::{
        sample_data_availability_set, BlockPrivacyProofAggregate, BlockValidityCertificate,
        DataAvailabilityRecord, DataAvailabilitySampleSet, L2Block,
    },
    crypto_policy::{
        public_key_for_label, sign_watchtower_authorization, verify_watchtower_authorization,
        Authorization, CryptoRole,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type WatchtowerResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockWatchtowerAuditReport {
    pub audit_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub tx_root: String,
    pub da_root: String,
    pub mempool_admission_root: String,
    pub validity_certificate_root: String,
    pub privacy_proof_aggregate_root: String,
    pub sampled_da_root: String,
    pub sampled_shard_indices: Vec<u64>,
    pub sampled_shard_count: u64,
    pub proof_status_root: String,
    pub bridge_root: String,
    pub watchtower_label: String,
    pub watchtower_public_key: String,
    pub reported_at_height: u64,
    pub reported_at_ms: u64,
    pub sample_set: DataAvailabilitySampleSet,
    pub authorization: Authorization,
}

impl BlockWatchtowerAuditReport {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "block_watchtower_audit_report",
            "chain_id": CHAIN_ID,
            "audit_id": self.audit_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "mempool_admission_root": self.mempool_admission_root,
            "validity_certificate_root": self.validity_certificate_root,
            "privacy_proof_aggregate_root": self.privacy_proof_aggregate_root,
            "sampled_da_root": self.sampled_da_root,
            "sampled_shard_indices": self.sampled_shard_indices,
            "sampled_shard_count": self.sampled_shard_count,
            "proof_status_root": self.proof_status_root,
            "bridge_root": self.bridge_root,
            "watchtower_label": self.watchtower_label,
            "watchtower_public_key": self.watchtower_public_key,
            "reported_at_height": self.reported_at_height,
            "reported_at_ms": self.reported_at_ms,
            "sample_set": self.sample_set.public_record(),
        })
    }

    pub fn audit_root(&self) -> String {
        domain_hash(
            "BLOCK-WATCHTOWER-AUDIT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("watchtower audit record object");
        object.insert("audit_root".to_string(), Value::String(self.audit_root()));
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
        verify_watchtower_authorization(
            &self.watchtower_public_key,
            "block_watchtower_audit_report",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockChallengeReport {
    pub challenge_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub challenge_kind: String,
    pub expected_root: String,
    pub observed_root: String,
    pub audit_id: Option<String>,
    pub reporter_label: String,
    pub reporter_public_key: String,
    pub reported_at_height: u64,
    pub slashable: bool,
    pub status: String,
    pub authorization: Authorization,
}

impl BlockChallengeReport {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "block_challenge_report",
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "challenge_kind": self.challenge_kind,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "audit_id": self.audit_id,
            "reporter_label": self.reporter_label,
            "reporter_public_key": self.reporter_public_key,
            "reported_at_height": self.reported_at_height,
            "slashable": self.slashable,
            "status": self.status,
        })
    }

    pub fn challenge_root(&self) -> String {
        domain_hash(
            "BLOCK-CHALLENGE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("block challenge record object");
        object.insert(
            "challenge_root".to_string(),
            Value::String(self.challenge_root()),
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

    pub fn verify_authorization(&self) -> bool {
        verify_watchtower_authorization(
            &self.reporter_public_key,
            "block_challenge_report",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerState {
    pub audits: BTreeMap<String, BlockWatchtowerAuditReport>,
    pub challenges: BTreeMap<String, BlockChallengeReport>,
}

impl WatchtowerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_audit(&mut self, audit: BlockWatchtowerAuditReport) -> WatchtowerResult<()> {
        if !audit.verify_authorization() {
            return Err("watchtower audit authorization failed".to_string());
        }
        self.audits.insert(audit.audit_id.clone(), audit);
        Ok(())
    }

    pub fn record_challenge(&mut self, challenge: BlockChallengeReport) -> WatchtowerResult<()> {
        if !challenge.verify_authorization() {
            return Err("watchtower challenge authorization failed".to_string());
        }
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn audit_root(&self) -> String {
        block_watchtower_audit_report_root(&self.audits.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_root(&self) -> String {
        block_challenge_report_root(&self.challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "watchtower_state",
            "chain_id": CHAIN_ID,
            "audit_root": self.audit_root(),
            "challenge_root": self.challenge_root(),
            "audit_count": self.audits.len() as u64,
            "challenge_count": self.challenges.len() as u64,
        })
    }
}

pub fn build_block_watchtower_audit_report(
    block: &L2Block,
    da_record: &DataAvailabilityRecord,
    certificate: &BlockValidityCertificate,
    aggregate: &BlockPrivacyProofAggregate,
    proof_status_root: &str,
    watchtower_label: &str,
    reported_at_height: u64,
    reported_at_ms: u64,
    shard_indices: &[u64],
) -> WatchtowerResult<BlockWatchtowerAuditReport> {
    if block.header.height != da_record.block_height {
        return Err("watchtower audit block/DA height mismatch".to_string());
    }
    if block.header.da_root != da_record.da_root() {
        return Err("watchtower audit DA root mismatch".to_string());
    }
    if block.header.block_hash() != certificate.block_hash {
        return Err("watchtower audit certificate block hash mismatch".to_string());
    }
    if aggregate.block_hash != block.header.block_hash() {
        return Err("watchtower audit aggregate block hash mismatch".to_string());
    }
    let sample_set = sample_data_availability_set(da_record, shard_indices)?;
    let watchtower_key = public_key_for_label(CryptoRole::WatchtowerSignature, watchtower_label);
    let audit_id = block_watchtower_audit_id(
        block.header.height,
        &block.header.block_hash(),
        &sample_set.sample_root,
        watchtower_label,
    );
    let mut report = BlockWatchtowerAuditReport {
        audit_id,
        block_height: block.header.height,
        block_hash: block.header.block_hash(),
        tx_root: block.header.tx_root.clone(),
        da_root: block.header.da_root.clone(),
        mempool_admission_root: block.header.mempool_admission_root.clone(),
        validity_certificate_root: certificate.certificate_root(),
        privacy_proof_aggregate_root: aggregate.aggregate_root(),
        sampled_da_root: sample_set.sample_root.clone(),
        sampled_shard_indices: sample_set.sample_indices.clone(),
        sampled_shard_count: sample_set.samples.len() as u64,
        proof_status_root: proof_status_root.to_string(),
        bridge_root: block.header.bridge_root.clone(),
        watchtower_label: watchtower_label.to_string(),
        watchtower_public_key: watchtower_key.public_key,
        reported_at_height,
        reported_at_ms,
        sample_set,
        authorization: Authorization {
            signer_label: watchtower_label.to_string(),
            auth_scheme: CryptoRole::WatchtowerSignature.scheme().to_string(),
            auth_public_key: String::new(),
            auth_transcript_hash: String::new(),
            auth_signature: String::new(),
        },
    };
    report.authorization = sign_watchtower_authorization(
        watchtower_label,
        "block_watchtower_audit_report",
        &report.unsigned_record(),
    );
    if !report.verify_authorization() {
        return Err("watchtower audit authorization failed".to_string());
    }
    Ok(report)
}

pub fn verify_block_watchtower_audit_report(
    report: &BlockWatchtowerAuditReport,
    block: &L2Block,
    da_record: &DataAvailabilityRecord,
    certificate: &BlockValidityCertificate,
    aggregate: &BlockPrivacyProofAggregate,
    proof_status_root: &str,
) -> bool {
    let rebuilt = build_block_watchtower_audit_report(
        block,
        da_record,
        certificate,
        aggregate,
        proof_status_root,
        &report.watchtower_label,
        report.reported_at_height,
        report.reported_at_ms,
        &report.sampled_shard_indices,
    );
    rebuilt.is_ok_and(|expected| expected.public_record() == report.public_record())
}

pub fn build_block_challenge_report(
    block: &L2Block,
    challenge_kind: &str,
    expected_root: &str,
    observed_root: &str,
    audit_id: Option<String>,
    reporter_label: &str,
    reported_at_height: u64,
) -> WatchtowerResult<BlockChallengeReport> {
    if challenge_kind.is_empty() {
        return Err("block challenge kind is required".to_string());
    }
    let reporter_key = public_key_for_label(CryptoRole::WatchtowerSignature, reporter_label);
    let challenge_id = block_challenge_report_id(
        block.header.height,
        &block.header.block_hash(),
        challenge_kind,
        observed_root,
        reporter_label,
    );
    let slashable = observed_root != expected_root
        && matches!(
            challenge_kind,
            "da-root-mismatch"
                | "validity-certificate-missing"
                | "privacy-aggregate-missing"
                | "prover-receipt-missing"
                | "bridge-root-mismatch"
                | "mempool-admission-root-mismatch"
        );
    let mut report = BlockChallengeReport {
        challenge_id,
        block_height: block.header.height,
        block_hash: block.header.block_hash(),
        challenge_kind: challenge_kind.to_string(),
        expected_root: expected_root.to_string(),
        observed_root: observed_root.to_string(),
        audit_id,
        reporter_label: reporter_label.to_string(),
        reporter_public_key: reporter_key.public_key,
        reported_at_height,
        slashable,
        status: if slashable { "open" } else { "disputed" }.to_string(),
        authorization: Authorization {
            signer_label: reporter_label.to_string(),
            auth_scheme: CryptoRole::WatchtowerSignature.scheme().to_string(),
            auth_public_key: String::new(),
            auth_transcript_hash: String::new(),
            auth_signature: String::new(),
        },
    };
    report.authorization = sign_watchtower_authorization(
        reporter_label,
        "block_challenge_report",
        &report.unsigned_record(),
    );
    if !report.verify_authorization() {
        return Err("watchtower challenge authorization failed".to_string());
    }
    Ok(report)
}

pub fn verify_block_challenge_report(report: &BlockChallengeReport, block: &L2Block) -> bool {
    let rebuilt = build_block_challenge_report(
        block,
        &report.challenge_kind,
        &report.expected_root,
        &report.observed_root,
        report.audit_id.clone(),
        &report.reporter_label,
        report.reported_at_height,
    );
    rebuilt.is_ok_and(|expected| expected.public_record() == report.public_record())
}

pub fn block_watchtower_audit_id(
    block_height: u64,
    block_hash: &str,
    sampled_da_root: &str,
    watchtower_label: &str,
) -> String {
    domain_hash(
        "BLOCK-WATCHTOWER-AUDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(sampled_da_root),
            HashPart::Str(watchtower_label),
        ],
        32,
    )
}

pub fn block_challenge_report_id(
    block_height: u64,
    block_hash: &str,
    challenge_kind: &str,
    observed_root: &str,
    reporter_label: &str,
) -> String {
    domain_hash(
        "BLOCK-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(challenge_kind),
            HashPart::Str(observed_root),
            HashPart::Str(reporter_label),
        ],
        32,
    )
}

pub fn block_watchtower_audit_report_root(reports: &[BlockWatchtowerAuditReport]) -> String {
    merkle_root(
        "BLOCK-WATCHTOWER-AUDIT",
        &reports
            .iter()
            .map(BlockWatchtowerAuditReport::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn block_challenge_report_root(reports: &[BlockChallengeReport]) -> String {
    merkle_root(
        "BLOCK-CHALLENGE-REPORT",
        &reports
            .iter()
            .map(BlockChallengeReport::public_record)
            .collect::<Vec<_>>(),
    )
}
