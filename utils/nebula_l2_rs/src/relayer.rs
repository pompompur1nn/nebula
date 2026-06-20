use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        crypto_policy_root, sign_network_authorization, verify_network_authorization, Authorization,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type RelayerResult<T> = Result<T, String>;

pub const RELAYER_PROTOCOL_VERSION: &str = "nebula-l2-relayer-v1";
pub const RELAYER_DEFAULT_JOB_TTL_BLOCKS: u64 = 80;
pub const RELAYER_DEFAULT_CONFIRMATION_DEPTH: u64 = 20;
pub const RELAYER_DEFAULT_MAX_BATCH_ITEMS: u64 = 64;
pub const RELAYER_DEFAULT_FEE_FLOOR_MICRO_XMR: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RelayerJobKind {
    AnchorL2Block,
    ObserveDeposit,
    ReleaseWithdrawal,
    PublishReserveReport,
    ChallengeWithdrawal,
    RecoverReorg,
}

impl RelayerJobKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnchorL2Block => "anchor_l2_block",
            Self::ObserveDeposit => "observe_deposit",
            Self::ReleaseWithdrawal => "release_withdrawal",
            Self::PublishReserveReport => "publish_reserve_report",
            Self::ChallengeWithdrawal => "challenge_withdrawal",
            Self::RecoverReorg => "recover_reorg",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RelayerJobStatus {
    Planned,
    Ready,
    Submitted,
    Observed,
    Finalized,
    Failed,
    Cancelled,
}

impl RelayerJobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Ready => "ready",
            Self::Submitted => "submitted",
            Self::Observed => "observed",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerFeePolicy {
    pub policy_id: String,
    pub fee_floor_micro_xmr: u64,
    pub fee_ceiling_micro_xmr: u64,
    pub urgency_multiplier_bps: u64,
    pub privacy_padding_outputs: u64,
    pub low_fee_lane_discount_bps: u64,
    pub max_batch_items: u64,
    pub public_metadata_root: String,
}

impl RelayerFeePolicy {
    pub fn new(
        fee_floor_micro_xmr: u64,
        fee_ceiling_micro_xmr: u64,
        urgency_multiplier_bps: u64,
        privacy_padding_outputs: u64,
        low_fee_lane_discount_bps: u64,
        max_batch_items: u64,
        public_metadata: &Value,
    ) -> Self {
        let public_metadata_root =
            relayer_payload_root("RELAYER-FEE-POLICY-METADATA", public_metadata);
        let policy_id = relayer_fee_policy_id(
            fee_floor_micro_xmr,
            fee_ceiling_micro_xmr,
            urgency_multiplier_bps,
            privacy_padding_outputs,
            low_fee_lane_discount_bps,
            max_batch_items,
            &public_metadata_root,
        );
        Self {
            policy_id,
            fee_floor_micro_xmr,
            fee_ceiling_micro_xmr,
            urgency_multiplier_bps,
            privacy_padding_outputs,
            low_fee_lane_discount_bps,
            max_batch_items,
            public_metadata_root,
        }
    }

    pub fn low_fee_default() -> Self {
        Self::new(
            RELAYER_DEFAULT_FEE_FLOOR_MICRO_XMR,
            RELAYER_DEFAULT_FEE_FLOOR_MICRO_XMR.saturating_mul(50),
            10_000,
            2,
            3_000,
            RELAYER_DEFAULT_MAX_BATCH_ITEMS,
            &json!({ "policy": "devnet_low_fee_private_bridge" }),
        )
    }

    pub fn quote_micro_xmr(&self, payload_bytes: u64, urgency_bps: u64, low_fee_lane: bool) -> u64 {
        let byte_fee = payload_bytes.saturating_div(512).saturating_add(1);
        let mut fee = self
            .fee_floor_micro_xmr
            .saturating_add(byte_fee.saturating_mul(self.urgency_multiplier_bps.max(1)))
            .saturating_mul(urgency_bps.max(1))
            / 10_000;
        if low_fee_lane {
            let discount = fee.saturating_mul(self.low_fee_lane_discount_bps) / 10_000;
            fee = fee.saturating_sub(discount);
        }
        fee.max(self.fee_floor_micro_xmr)
            .min(self.fee_ceiling_micro_xmr.max(self.fee_floor_micro_xmr))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relayer_fee_policy",
            "chain_id": CHAIN_ID,
            "relayer_protocol_version": RELAYER_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "fee_floor_micro_xmr": self.fee_floor_micro_xmr,
            "fee_ceiling_micro_xmr": self.fee_ceiling_micro_xmr,
            "urgency_multiplier_bps": self.urgency_multiplier_bps,
            "privacy_padding_outputs": self.privacy_padding_outputs,
            "low_fee_lane_discount_bps": self.low_fee_lane_discount_bps,
            "max_batch_items": self.max_batch_items,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn policy_root(&self) -> String {
        domain_hash(
            "RELAYER-FEE-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for RelayerFeePolicy {
    fn default() -> Self {
        Self::low_fee_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerEndpoint {
    pub endpoint_id: String,
    pub label: String,
    pub network: String,
    pub rpc_commitment: String,
    pub zmq_commitment: String,
    pub view_key_commitment: String,
    pub min_confirmation_depth: u64,
    pub public_metadata_root: String,
}

impl RelayerEndpoint {
    pub fn new(
        label: impl Into<String>,
        network: impl Into<String>,
        rpc_commitment: impl Into<String>,
        zmq_commitment: impl Into<String>,
        view_key_commitment: impl Into<String>,
        min_confirmation_depth: u64,
        public_metadata: &Value,
    ) -> Self {
        let label = label.into();
        let network = network.into();
        let rpc_commitment = rpc_commitment.into();
        let zmq_commitment = zmq_commitment.into();
        let view_key_commitment = view_key_commitment.into();
        let public_metadata_root =
            relayer_payload_root("RELAYER-ENDPOINT-METADATA", public_metadata);
        let endpoint_id = relayer_endpoint_id(
            &label,
            &network,
            &rpc_commitment,
            &zmq_commitment,
            &view_key_commitment,
            min_confirmation_depth,
        );
        Self {
            endpoint_id,
            label,
            network,
            rpc_commitment,
            zmq_commitment,
            view_key_commitment,
            min_confirmation_depth,
            public_metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relayer_endpoint",
            "chain_id": CHAIN_ID,
            "relayer_protocol_version": RELAYER_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "label": self.label,
            "network": self.network,
            "rpc_commitment": self.rpc_commitment,
            "zmq_commitment": self.zmq_commitment,
            "view_key_commitment": self.view_key_commitment,
            "min_confirmation_depth": self.min_confirmation_depth,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn endpoint_root(&self) -> String {
        domain_hash(
            "RELAYER-ENDPOINT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerJob {
    pub job_id: String,
    pub job_kind: RelayerJobKind,
    pub status: RelayerJobStatus,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub endpoint_id: Option<String>,
    pub fee_policy_id: String,
    pub quoted_fee_micro_xmr: u64,
    pub low_fee_lane: bool,
    pub privacy_padding_outputs: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
    pub attempts: u64,
    pub last_error_hash: String,
    pub authorization: Option<Authorization>,
}

impl RelayerJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_kind: RelayerJobKind,
        subject_id: impl Into<String>,
        subject_payload: &Value,
        endpoint_id: Option<String>,
        fee_policy: &RelayerFeePolicy,
        payload_bytes: u64,
        urgency_bps: u64,
        low_fee_lane: bool,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let subject_id = subject_id.into();
        let subject_root = relayer_payload_root("RELAYER-JOB-SUBJECT", subject_payload);
        let payload_root = relayer_payload_root("RELAYER-JOB-PAYLOAD", subject_payload);
        let quoted_fee_micro_xmr =
            fee_policy.quote_micro_xmr(payload_bytes, urgency_bps, low_fee_lane);
        let expires_at_height = created_at_height.saturating_add(ttl_blocks.max(1));
        let last_error_hash = relayer_error_hash("");
        let job_id = relayer_job_id(
            job_kind.as_str(),
            &subject_id,
            &subject_root,
            &payload_root,
            endpoint_id.as_deref().unwrap_or(""),
            created_at_height,
        );
        Self {
            job_id,
            job_kind,
            status: RelayerJobStatus::Planned,
            subject_id,
            subject_root,
            payload_root,
            endpoint_id,
            fee_policy_id: fee_policy.policy_id.clone(),
            quoted_fee_micro_xmr,
            low_fee_lane,
            privacy_padding_outputs: fee_policy.privacy_padding_outputs,
            created_at_height,
            expires_at_height,
            updated_at_height: created_at_height,
            attempts: 0,
            last_error_hash,
            authorization: None,
        }
    }

    pub fn mark_status(&mut self, status: RelayerJobStatus, height: u64, error_code: Option<&str>) {
        self.status = status;
        self.updated_at_height = height;
        if let Some(error_code) = error_code {
            self.last_error_hash = relayer_error_hash(error_code);
        }
    }

    pub fn record_attempt(&mut self, height: u64) {
        self.attempts = self.attempts.saturating_add(1);
        self.updated_at_height = height;
        self.status = RelayerJobStatus::Submitted;
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn sign(&mut self, signer_label: &str) {
        self.authorization = Some(sign_network_authorization(
            signer_label,
            "relayer_job",
            &self.unsigned_record(),
        ));
    }

    pub fn verify_authorization(&self) -> bool {
        self.authorization.as_ref().is_some_and(|authorization| {
            verify_network_authorization(
                &authorization.auth_public_key,
                "relayer_job",
                &self.unsigned_record(),
                authorization,
            )
        })
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "relayer_job",
            "chain_id": CHAIN_ID,
            "relayer_protocol_version": RELAYER_PROTOCOL_VERSION,
            "job_id": self.job_id,
            "job_kind": self.job_kind.as_str(),
            "status": self.status.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "endpoint_id": self.endpoint_id,
            "fee_policy_id": self.fee_policy_id,
            "quoted_fee_micro_xmr": self.quoted_fee_micro_xmr,
            "low_fee_lane": self.low_fee_lane,
            "privacy_padding_outputs": self.privacy_padding_outputs,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "updated_at_height": self.updated_at_height,
            "attempts": self.attempts,
            "last_error_hash": self.last_error_hash,
            "crypto_policy_root": crypto_policy_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("relayer job public record object");
        object.insert("job_root".to_string(), Value::String(self.job_root()));
        if let Some(authorization) = &self.authorization {
            insert_relayer_authorization(object, authorization);
        }
        record
    }

    pub fn job_root(&self) -> String {
        domain_hash(
            "RELAYER-JOB",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerObservationReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub endpoint_id: String,
    pub observed_height: u64,
    pub observed_block_hash: String,
    pub observed_tx_hash: String,
    pub confirmation_depth: u64,
    pub payload_root: String,
    pub finality_status: String,
    pub authorization: Authorization,
}

impl RelayerObservationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer_label: &str,
        job_id: &str,
        endpoint_id: &str,
        observed_height: u64,
        observed_block_hash: impl Into<String>,
        observed_tx_hash: impl Into<String>,
        confirmation_depth: u64,
        payload: &Value,
        finality_status: impl Into<String>,
    ) -> Self {
        let observed_block_hash = observed_block_hash.into();
        let observed_tx_hash = observed_tx_hash.into();
        let finality_status = finality_status.into();
        let payload_root = relayer_payload_root("RELAYER-OBSERVATION-PAYLOAD", payload);
        let receipt_id = relayer_observation_receipt_id(
            job_id,
            endpoint_id,
            observed_height,
            &observed_block_hash,
            &observed_tx_hash,
            &payload_root,
        );
        let mut receipt = Self {
            receipt_id,
            job_id: job_id.to_string(),
            endpoint_id: endpoint_id.to_string(),
            observed_height,
            observed_block_hash,
            observed_tx_hash,
            confirmation_depth,
            payload_root,
            finality_status,
            authorization: sign_network_authorization(
                signer_label,
                "relayer_observation_receipt_empty",
                &json!({}),
            ),
        };
        receipt.authorization = sign_network_authorization(
            signer_label,
            "relayer_observation_receipt",
            &receipt.unsigned_record(),
        );
        receipt
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "relayer_observation_receipt",
            "chain_id": CHAIN_ID,
            "relayer_protocol_version": RELAYER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "endpoint_id": self.endpoint_id,
            "observed_height": self.observed_height,
            "observed_block_hash": self.observed_block_hash,
            "observed_tx_hash": self.observed_tx_hash,
            "confirmation_depth": self.confirmation_depth,
            "payload_root": self.payload_root,
            "finality_status": self.finality_status,
        })
    }

    pub fn verify_authorization(&self) -> bool {
        verify_network_authorization(
            &self.authorization.auth_public_key,
            "relayer_observation_receipt",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("relayer observation receipt public record object");
        object.insert(
            "receipt_root".to_string(),
            Value::String(self.receipt_root()),
        );
        insert_relayer_authorization(object, &self.authorization);
        record
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "RELAYER-OBSERVATION-RECEIPT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerBatch {
    pub batch_id: String,
    pub batch_kind: RelayerJobKind,
    pub job_ids: Vec<String>,
    pub job_root: String,
    pub payload_root: String,
    pub total_fee_micro_xmr: u64,
    pub padding_output_count: u64,
    pub created_at_height: u64,
}

impl RelayerBatch {
    pub fn new(
        batch_kind: RelayerJobKind,
        jobs: &[RelayerJob],
        payload: &Value,
        created_at_height: u64,
    ) -> Self {
        let job_ids = jobs
            .iter()
            .map(|job| job.job_id.clone())
            .collect::<Vec<_>>();
        let job_root = relayer_string_root("RELAYER-BATCH-JOB", &job_ids);
        let payload_root = relayer_payload_root("RELAYER-BATCH-PAYLOAD", payload);
        let total_fee_micro_xmr = jobs
            .iter()
            .map(|job| job.quoted_fee_micro_xmr)
            .fold(0_u64, u64::saturating_add);
        let padding_output_count = jobs
            .iter()
            .map(|job| job.privacy_padding_outputs)
            .fold(0_u64, u64::saturating_add);
        let batch_id = relayer_batch_id(
            batch_kind.as_str(),
            &job_root,
            &payload_root,
            total_fee_micro_xmr,
            created_at_height,
        );
        Self {
            batch_id,
            batch_kind,
            job_ids,
            job_root,
            payload_root,
            total_fee_micro_xmr,
            padding_output_count,
            created_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relayer_batch",
            "chain_id": CHAIN_ID,
            "relayer_protocol_version": RELAYER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "batch_kind": self.batch_kind.as_str(),
            "job_root": self.job_root,
            "payload_root": self.payload_root,
            "total_fee_micro_xmr": self.total_fee_micro_xmr,
            "padding_output_count": self.padding_output_count,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn batch_root(&self) -> String {
        domain_hash(
            "RELAYER-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerState {
    pub operator_label: String,
    pub fee_policy: RelayerFeePolicy,
    pub endpoints: BTreeMap<String, RelayerEndpoint>,
    pub jobs: BTreeMap<String, RelayerJob>,
    pub observation_receipts: BTreeMap<String, RelayerObservationReceipt>,
    pub batches: BTreeMap<String, RelayerBatch>,
    pub current_height: u64,
    pub last_error_hash: String,
}

impl RelayerState {
    pub fn new(operator_label: impl Into<String>) -> Self {
        Self {
            operator_label: operator_label.into(),
            fee_policy: RelayerFeePolicy::default(),
            endpoints: BTreeMap::new(),
            jobs: BTreeMap::new(),
            observation_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            current_height: 0,
            last_error_hash: relayer_error_hash(""),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn insert_endpoint(&mut self, endpoint: RelayerEndpoint) -> RelayerResult<String> {
        if self.endpoints.contains_key(&endpoint.endpoint_id) {
            return Err("relayer endpoint already exists".to_string());
        }
        let endpoint_id = endpoint.endpoint_id.clone();
        self.endpoints.insert(endpoint_id.clone(), endpoint);
        Ok(endpoint_id)
    }

    pub fn schedule_anchor(
        &mut self,
        l2_block_hash: &str,
        state_root: &str,
        anchor_payload: &Value,
        endpoint_id: Option<String>,
        low_fee_lane: bool,
    ) -> RelayerResult<String> {
        self.ensure_endpoint_known(endpoint_id.as_deref())?;
        let mut job = RelayerJob::new(
            RelayerJobKind::AnchorL2Block,
            l2_block_hash,
            &json!({
                "l2_block_hash": l2_block_hash,
                "state_root": state_root,
                "anchor_payload_root": relayer_payload_root("RELAYER-ANCHOR-PAYLOAD", anchor_payload),
            }),
            endpoint_id,
            &self.fee_policy,
            relayer_json_len(anchor_payload),
            10_000,
            low_fee_lane,
            self.current_height,
            RELAYER_DEFAULT_JOB_TTL_BLOCKS,
        );
        job.sign(&self.operator_label);
        self.insert_job(job)
    }

    pub fn schedule_withdrawal_release(
        &mut self,
        withdrawal_id: &str,
        withdrawal_payload: &Value,
        endpoint_id: Option<String>,
        urgency_bps: u64,
        low_fee_lane: bool,
    ) -> RelayerResult<String> {
        self.ensure_endpoint_known(endpoint_id.as_deref())?;
        let mut job = RelayerJob::new(
            RelayerJobKind::ReleaseWithdrawal,
            withdrawal_id,
            withdrawal_payload,
            endpoint_id,
            &self.fee_policy,
            relayer_json_len(withdrawal_payload),
            urgency_bps,
            low_fee_lane,
            self.current_height,
            RELAYER_DEFAULT_JOB_TTL_BLOCKS,
        );
        job.sign(&self.operator_label);
        self.insert_job(job)
    }

    pub fn schedule_reserve_report(
        &mut self,
        reserve_report_id: &str,
        reserve_payload: &Value,
        endpoint_id: Option<String>,
    ) -> RelayerResult<String> {
        self.ensure_endpoint_known(endpoint_id.as_deref())?;
        let mut job = RelayerJob::new(
            RelayerJobKind::PublishReserveReport,
            reserve_report_id,
            reserve_payload,
            endpoint_id,
            &self.fee_policy,
            relayer_json_len(reserve_payload),
            8_000,
            true,
            self.current_height,
            RELAYER_DEFAULT_JOB_TTL_BLOCKS,
        );
        job.sign(&self.operator_label);
        self.insert_job(job)
    }

    pub fn insert_job(&mut self, job: RelayerJob) -> RelayerResult<String> {
        if job.authorization.is_some() && !job.verify_authorization() {
            return Err("relayer job authorization failed".to_string());
        }
        if self.jobs.contains_key(&job.job_id) {
            return Err("relayer job already exists".to_string());
        }
        let job_id = job.job_id.clone();
        self.jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn mark_ready(&mut self, job_id: &str) -> RelayerResult<()> {
        self.jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown relayer job".to_string())?
            .mark_status(RelayerJobStatus::Ready, self.current_height, None);
        Ok(())
    }

    pub fn record_submission_attempt(&mut self, job_id: &str) -> RelayerResult<()> {
        self.jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown relayer job".to_string())?
            .record_attempt(self.current_height);
        Ok(())
    }

    pub fn fail_job(&mut self, job_id: &str, error_code: &str) -> RelayerResult<()> {
        self.last_error_hash = relayer_error_hash(error_code);
        self.jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown relayer job".to_string())?
            .mark_status(
                RelayerJobStatus::Failed,
                self.current_height,
                Some(error_code),
            );
        Ok(())
    }

    pub fn record_observation(
        &mut self,
        job_id: &str,
        endpoint_id: &str,
        observed_height: u64,
        observed_block_hash: &str,
        observed_tx_hash: &str,
        confirmation_depth: u64,
        payload: &Value,
    ) -> RelayerResult<RelayerObservationReceipt> {
        self.ensure_endpoint_known(Some(endpoint_id))?;
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown relayer job".to_string())?;
        let finality_status = if confirmation_depth >= RELAYER_DEFAULT_CONFIRMATION_DEPTH {
            job.mark_status(RelayerJobStatus::Finalized, self.current_height, None);
            "finalized"
        } else {
            job.mark_status(RelayerJobStatus::Observed, self.current_height, None);
            "observed"
        };
        let receipt = RelayerObservationReceipt::new(
            &self.operator_label,
            job_id,
            endpoint_id,
            observed_height,
            observed_block_hash,
            observed_tx_hash,
            confirmation_depth,
            payload,
            finality_status,
        );
        if !receipt.verify_authorization() {
            return Err("relayer observation authorization failed".to_string());
        }
        self.observation_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn build_batch(
        &mut self,
        batch_kind: RelayerJobKind,
        max_items: u64,
        payload: &Value,
    ) -> RelayerResult<RelayerBatch> {
        let selected = self
            .jobs
            .values()
            .filter(|job| job.job_kind == batch_kind && job.status == RelayerJobStatus::Ready)
            .take(max_items.min(self.fee_policy.max_batch_items) as usize)
            .cloned()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err("no ready relayer jobs for batch".to_string());
        }
        let batch = RelayerBatch::new(batch_kind, &selected, payload, self.current_height);
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn expire_jobs(&mut self) -> Vec<String> {
        let mut expired = Vec::new();
        for job in self.jobs.values_mut() {
            if job.is_expired(self.current_height)
                && !matches!(
                    job.status,
                    RelayerJobStatus::Finalized
                        | RelayerJobStatus::Failed
                        | RelayerJobStatus::Cancelled
                )
            {
                job.mark_status(
                    RelayerJobStatus::Failed,
                    self.current_height,
                    Some("relayer_job_expired"),
                );
                expired.push(job.job_id.clone());
            }
        }
        expired
    }

    pub fn endpoint_root(&self) -> String {
        merkle_root(
            "RELAYER-ENDPOINT",
            &self
                .endpoints
                .values()
                .map(RelayerEndpoint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn job_root(&self) -> String {
        merkle_root(
            "RELAYER-JOB",
            &self
                .jobs
                .values()
                .map(RelayerJob::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn observation_receipt_root(&self) -> String {
        merkle_root(
            "RELAYER-OBSERVATION-RECEIPT",
            &self
                .observation_receipts
                .values()
                .map(RelayerObservationReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_root(&self) -> String {
        merkle_root(
            "RELAYER-BATCH",
            &self
                .batches
                .values()
                .map(RelayerBatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "RELAYER-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relayer_state",
            "chain_id": CHAIN_ID,
            "relayer_protocol_version": RELAYER_PROTOCOL_VERSION,
            "operator_label": self.operator_label,
            "fee_policy": self.fee_policy.public_record(),
            "endpoint_root": self.endpoint_root(),
            "job_root": self.job_root(),
            "observation_receipt_root": self.observation_receipt_root(),
            "batch_root": self.batch_root(),
            "current_height": self.current_height,
            "last_error_hash": self.last_error_hash,
            "endpoint_count": self.endpoints.len() as u64,
            "job_count": self.jobs.len() as u64,
            "observation_receipt_count": self.observation_receipts.len() as u64,
            "batch_count": self.batches.len() as u64,
        })
    }

    fn ensure_endpoint_known(&self, endpoint_id: Option<&str>) -> RelayerResult<()> {
        if let Some(endpoint_id) = endpoint_id {
            if !self.endpoints.contains_key(endpoint_id) {
                return Err("unknown relayer endpoint".to_string());
            }
        }
        Ok(())
    }
}

pub fn relayer_fee_policy_id(
    fee_floor_micro_xmr: u64,
    fee_ceiling_micro_xmr: u64,
    urgency_multiplier_bps: u64,
    privacy_padding_outputs: u64,
    low_fee_lane_discount_bps: u64,
    max_batch_items: u64,
    public_metadata_root: &str,
) -> String {
    domain_hash(
        "RELAYER-FEE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(fee_floor_micro_xmr as i128),
            HashPart::Int(fee_ceiling_micro_xmr as i128),
            HashPart::Int(urgency_multiplier_bps as i128),
            HashPart::Int(privacy_padding_outputs as i128),
            HashPart::Int(low_fee_lane_discount_bps as i128),
            HashPart::Int(max_batch_items as i128),
            HashPart::Str(public_metadata_root),
        ],
        32,
    )
}

pub fn relayer_endpoint_id(
    label: &str,
    network: &str,
    rpc_commitment: &str,
    zmq_commitment: &str,
    view_key_commitment: &str,
    min_confirmation_depth: u64,
) -> String {
    domain_hash(
        "RELAYER-ENDPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(network),
            HashPart::Str(rpc_commitment),
            HashPart::Str(zmq_commitment),
            HashPart::Str(view_key_commitment),
            HashPart::Int(min_confirmation_depth as i128),
        ],
        32,
    )
}

pub fn relayer_job_id(
    job_kind: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    endpoint_id: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "RELAYER-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Str(endpoint_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn relayer_observation_receipt_id(
    job_id: &str,
    endpoint_id: &str,
    observed_height: u64,
    observed_block_hash: &str,
    observed_tx_hash: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "RELAYER-OBSERVATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(endpoint_id),
            HashPart::Int(observed_height as i128),
            HashPart::Str(observed_block_hash),
            HashPart::Str(observed_tx_hash),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn relayer_batch_id(
    batch_kind: &str,
    job_root: &str,
    payload_root: &str,
    total_fee_micro_xmr: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "RELAYER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_kind),
            HashPart::Str(job_root),
            HashPart::Str(payload_root),
            HashPart::Int(total_fee_micro_xmr as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn relayer_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn relayer_error_hash(error_code: &str) -> String {
    domain_hash(
        "RELAYER-ERROR",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(error_code)],
        32,
    )
}

pub fn relayer_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

fn relayer_json_len(payload: &Value) -> u64 {
    serde_json::to_vec(payload)
        .map(|bytes| bytes.len() as u64)
        .unwrap_or_default()
}

fn insert_relayer_authorization(
    object: &mut serde_json::Map<String, Value>,
    authorization: &Authorization,
) {
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
}
