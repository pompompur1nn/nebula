use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type FastLaneSchedulerResult<T> = Result<T, String>;

pub const FAST_LANE_SCHEDULER_PROTOCOL_VERSION: &str = "nebula-fast-lane-scheduler-v1";
pub const FAST_LANE_SCHEDULER_DEFAULT_TARGET_BATCH_MS: u64 = 250;
pub const FAST_LANE_SCHEDULER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 4_000_000;
pub const FAST_LANE_SCHEDULER_DEFAULT_MAX_QUEUE_DEPTH: u64 = 50_000;
pub const FAST_LANE_SCHEDULER_DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 120;
pub const FAST_LANE_SCHEDULER_DEFAULT_PRIVACY_RESERVE_BPS: u64 = 2_000;
pub const FAST_LANE_SCHEDULER_DEFAULT_REBATE_BPS: u64 = 6_500;
pub const FAST_LANE_SCHEDULER_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 250_000_000;
pub const FAST_LANE_SCHEDULER_DEFAULT_TICKET_TTL_BLOCKS: u64 = 16;
pub const FAST_LANE_SCHEDULER_MAX_BPS: u64 = 10_000;
pub const FAST_LANE_SCHEDULER_MAX_TICKETS: usize = 512;
pub const FAST_LANE_SCHEDULER_MAX_BATCHES: usize = 128;
pub const FAST_LANE_SCHEDULER_MAX_WINDOWS: usize = 64;
pub const FAST_LANE_SCHEDULER_MAX_AUTHORIZATIONS: usize = 512;
pub const FAST_LANE_SCHEDULER_MAX_REBATES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneClass {
    BridgeExit,
    PrivateSwap,
    ContractCall,
    LendingLiquidation,
    WalletTransfer,
    ProofMaintenance,
    Governance,
}

impl FastLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeExit => "bridge_exit",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::LendingLiquidation => "lending_liquidation",
            Self::WalletTransfer => "wallet_transfer",
            Self::ProofMaintenance => "proof_maintenance",
            Self::Governance => "governance",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::BridgeExit => 1_000,
            Self::LendingLiquidation => 950,
            Self::PrivateSwap => 850,
            Self::ContractCall => 760,
            Self::WalletTransfer => 600,
            Self::ProofMaintenance => 420,
            Self::Governance => 300,
        }
    }

    pub fn target_latency_ms(self) -> u64 {
        match self {
            Self::BridgeExit => 400,
            Self::LendingLiquidation => 300,
            Self::PrivateSwap => 250,
            Self::ContractCall => 450,
            Self::WalletTransfer => 650,
            Self::ProofMaintenance => 1_500,
            Self::Governance => TARGET_BLOCK_MS,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::BridgeExit
                | Self::PrivateSwap
                | Self::ContractCall
                | Self::LendingLiquidation
                | Self::WalletTransfer
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneTicketStatus {
    Pending,
    Admitted,
    Deferred,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl FastLaneTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Admitted => "admitted",
            Self::Deferred => "deferred",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneBatchStatus {
    Open,
    Sealed,
    Published,
    Challenged,
    Finalized,
}

impl FastLaneBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneAuthorizationKind {
    PqWallet,
    SponsorPool,
    Paymaster,
    SequencerQuota,
    EmergencyBridge,
}

impl FastLaneAuthorizationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqWallet => "pq_wallet",
            Self::SponsorPool => "sponsor_pool",
            Self::Paymaster => "paymaster",
            Self::SequencerQuota => "sequencer_quota",
            Self::EmergencyBridge => "emergency_bridge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneBackpressureMode {
    Normal,
    CompressOnly,
    SponsorOnly,
    BridgePriority,
    EmergencyDrain,
}

impl FastLaneBackpressureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::CompressOnly => "compress_only",
            Self::SponsorOnly => "sponsor_only",
            Self::BridgePriority => "bridge_priority",
            Self::EmergencyDrain => "emergency_drain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneSchedulerConfig {
    pub config_id: String,
    pub target_batch_ms: u64,
    pub max_batch_weight: u64,
    pub max_queue_depth: u64,
    pub base_fee_micro_units: u64,
    pub privacy_reserve_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub sponsor_budget_units: u64,
    pub ticket_ttl_blocks: u64,
    pub require_pq_authorization: bool,
    pub allow_private_payload_roots_only: bool,
    pub enable_backpressure: bool,
    pub enable_low_fee_sponsorship: bool,
}

impl Default for FastLaneSchedulerConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            target_batch_ms: FAST_LANE_SCHEDULER_DEFAULT_TARGET_BATCH_MS,
            max_batch_weight: FAST_LANE_SCHEDULER_DEFAULT_MAX_BATCH_WEIGHT,
            max_queue_depth: FAST_LANE_SCHEDULER_DEFAULT_MAX_QUEUE_DEPTH,
            base_fee_micro_units: FAST_LANE_SCHEDULER_DEFAULT_BASE_FEE_MICRO_UNITS,
            privacy_reserve_bps: FAST_LANE_SCHEDULER_DEFAULT_PRIVACY_RESERVE_BPS,
            low_fee_rebate_bps: FAST_LANE_SCHEDULER_DEFAULT_REBATE_BPS,
            sponsor_budget_units: FAST_LANE_SCHEDULER_DEFAULT_SPONSOR_BUDGET_UNITS,
            ticket_ttl_blocks: FAST_LANE_SCHEDULER_DEFAULT_TICKET_TTL_BLOCKS,
            require_pq_authorization: true,
            allow_private_payload_roots_only: true,
            enable_backpressure: true,
            enable_low_fee_sponsorship: true,
        };
        config.config_id = fast_lane_scheduler_config_id(&config.identity_record());
        config
    }
}

impl FastLaneSchedulerConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "fast_lane_scheduler_config",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "target_batch_ms": self.target_batch_ms,
            "max_batch_weight": self.max_batch_weight,
            "max_queue_depth": self.max_queue_depth,
            "base_fee_micro_units": self.base_fee_micro_units,
            "privacy_reserve_bps": self.privacy_reserve_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "sponsor_budget_units": self.sponsor_budget_units,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "require_pq_authorization": self.require_pq_authorization,
            "allow_private_payload_roots_only": self.allow_private_payload_roots_only,
            "enable_backpressure": self.enable_backpressure,
            "enable_low_fee_sponsorship": self.enable_low_fee_sponsorship,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("fast lane scheduler config record object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn config_root(&self) -> String {
        fast_lane_scheduler_payload_root("FAST-LANE-SCHEDULER-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<String> {
        ensure_non_empty(&self.config_id, "fast lane scheduler config id")?;
        ensure_positive(self.target_batch_ms, "fast lane scheduler target batch ms")?;
        ensure_positive(
            self.max_batch_weight,
            "fast lane scheduler max batch weight",
        )?;
        ensure_positive(self.max_queue_depth, "fast lane scheduler max queue depth")?;
        ensure_positive(
            self.base_fee_micro_units,
            "fast lane scheduler base fee micro units",
        )?;
        validate_bps(
            self.privacy_reserve_bps,
            "fast lane scheduler privacy reserve bps",
        )?;
        validate_bps(
            self.low_fee_rebate_bps,
            "fast lane scheduler low fee rebate bps",
        )?;
        ensure_positive(
            self.ticket_ttl_blocks,
            "fast lane scheduler ticket ttl blocks",
        )?;
        if self.config_id != fast_lane_scheduler_config_id(&self.identity_record()) {
            return Err("fast lane scheduler config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLanePqAuthorization {
    pub authorization_id: String,
    pub authorization_kind: FastLaneAuthorizationKind,
    pub subject_commitment: String,
    pub class: FastLaneClass,
    pub max_fee_micro_units: u64,
    pub max_weight: u64,
    pub valid_after_height: u64,
    pub valid_until_height: u64,
    pub pq_algorithm: String,
    pub public_key_root: String,
    pub signature_root: String,
    pub disclosure_policy_root: String,
    pub revocation_nullifier: String,
}

impl FastLanePqAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_kind: FastLaneAuthorizationKind,
        subject_label: impl Into<String>,
        class: FastLaneClass,
        max_fee_micro_units: u64,
        max_weight: u64,
        valid_after_height: u64,
        valid_until_height: u64,
        pq_algorithm: impl Into<String>,
        public_key_material: impl Into<String>,
        signature_material: impl Into<String>,
        disclosure_policy: &Value,
    ) -> FastLaneSchedulerResult<Self> {
        if valid_until_height <= valid_after_height {
            return Err("fast lane pq authorization validity window is empty".to_string());
        }
        ensure_positive(
            max_fee_micro_units,
            "fast lane pq authorization max fee micro units",
        )?;
        ensure_positive(max_weight, "fast lane pq authorization max weight")?;
        let subject_label = subject_label.into();
        ensure_non_empty(&subject_label, "fast lane pq authorization subject")?;
        let pq_algorithm = pq_algorithm.into();
        ensure_non_empty(&pq_algorithm, "fast lane pq authorization algorithm")?;
        let public_key_material = public_key_material.into();
        let signature_material = signature_material.into();
        ensure_non_empty(
            &public_key_material,
            "fast lane pq authorization public key material",
        )?;
        ensure_non_empty(
            &signature_material,
            "fast lane pq authorization signature material",
        )?;
        let subject_commitment =
            fast_lane_scheduler_string_root("FAST-LANE-AUTH-SUBJECT", &subject_label);
        let public_key_root =
            fast_lane_scheduler_string_root("FAST-LANE-AUTH-PUBLIC-KEY", &public_key_material);
        let signature_root =
            fast_lane_scheduler_string_root("FAST-LANE-AUTH-SIGNATURE", &signature_material);
        let disclosure_policy_root =
            fast_lane_scheduler_payload_root("FAST-LANE-AUTH-DISCLOSURE-POLICY", disclosure_policy);
        let revocation_nullifier = fast_lane_scheduler_nullifier(
            "FAST-LANE-AUTH-REVOCATION",
            &[&subject_commitment, class.as_str(), &public_key_root],
        );
        let authorization_id = fast_lane_scheduler_authorization_id(
            authorization_kind,
            &subject_commitment,
            class,
            max_fee_micro_units,
            max_weight,
            valid_after_height,
            valid_until_height,
            &pq_algorithm,
            &public_key_root,
            &signature_root,
            &disclosure_policy_root,
        );
        Ok(Self {
            authorization_id,
            authorization_kind,
            subject_commitment,
            class,
            max_fee_micro_units,
            max_weight,
            valid_after_height,
            valid_until_height,
            pq_algorithm,
            public_key_root,
            signature_root,
            disclosure_policy_root,
            revocation_nullifier,
        })
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<()> {
        ensure_non_empty(&self.authorization_id, "fast lane pq authorization id")?;
        ensure_non_empty(
            &self.subject_commitment,
            "fast lane pq authorization subject commitment",
        )?;
        ensure_non_empty(&self.pq_algorithm, "fast lane pq authorization algorithm")?;
        ensure_non_empty(
            &self.public_key_root,
            "fast lane pq authorization public key root",
        )?;
        ensure_non_empty(
            &self.signature_root,
            "fast lane pq authorization signature root",
        )?;
        ensure_positive(
            self.max_fee_micro_units,
            "fast lane pq authorization max fee micro units",
        )?;
        ensure_positive(self.max_weight, "fast lane pq authorization max weight")?;
        if self.valid_until_height <= self.valid_after_height {
            return Err("fast lane pq authorization validity window is empty".to_string());
        }
        if self.authorization_id
            != fast_lane_scheduler_authorization_id(
                self.authorization_kind,
                &self.subject_commitment,
                self.class,
                self.max_fee_micro_units,
                self.max_weight,
                self.valid_after_height,
                self.valid_until_height,
                &self.pq_algorithm,
                &self.public_key_root,
                &self.signature_root,
                &self.disclosure_policy_root,
            )
        {
            return Err("fast lane pq authorization id mismatch".to_string());
        }
        Ok(())
    }

    pub fn covers(
        &self,
        class: FastLaneClass,
        fee_micro_units: u64,
        weight: u64,
        height: u64,
    ) -> bool {
        self.class == class
            && fee_micro_units <= self.max_fee_micro_units
            && weight <= self.max_weight
            && height >= self.valid_after_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_pq_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "authorization_kind": self.authorization_kind.as_str(),
            "subject_commitment": self.subject_commitment,
            "class": self.class.as_str(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_weight": self.max_weight,
            "valid_after_height": self.valid_after_height,
            "valid_until_height": self.valid_until_height,
            "pq_algorithm": self.pq_algorithm,
            "public_key_root": self.public_key_root,
            "signature_root": self.signature_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "revocation_nullifier": self.revocation_nullifier,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneAdmissionTicket {
    pub ticket_id: String,
    pub class: FastLaneClass,
    pub submitter_commitment: String,
    pub payload_root: String,
    pub privacy_label_root: String,
    pub nullifier_root: String,
    pub authorization_id: String,
    pub declared_weight: u64,
    pub max_fee_micro_units: u64,
    pub sponsor_credit_units: u64,
    pub priority_score: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub target_latency_ms: u64,
    pub status: FastLaneTicketStatus,
}

impl FastLaneAdmissionTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: FastLaneClass,
        submitter_label: impl Into<String>,
        payload: &Value,
        privacy_label: impl Into<String>,
        authorization_id: impl Into<String>,
        declared_weight: u64,
        max_fee_micro_units: u64,
        sponsor_credit_units: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> FastLaneSchedulerResult<Self> {
        ensure_positive(declared_weight, "fast lane ticket declared weight")?;
        ensure_positive(max_fee_micro_units, "fast lane ticket max fee")?;
        ensure_positive(ttl_blocks, "fast lane ticket ttl")?;
        let submitter_label = submitter_label.into();
        ensure_non_empty(&submitter_label, "fast lane ticket submitter label")?;
        let privacy_label = privacy_label.into();
        ensure_non_empty(&privacy_label, "fast lane ticket privacy label")?;
        let authorization_id = authorization_id.into();
        ensure_non_empty(&authorization_id, "fast lane ticket authorization id")?;
        let submitter_commitment =
            fast_lane_scheduler_string_root("FAST-LANE-TICKET-SUBMITTER", &submitter_label);
        let payload_root = fast_lane_scheduler_payload_root("FAST-LANE-TICKET-PAYLOAD", payload);
        let privacy_label_root =
            fast_lane_scheduler_string_root("FAST-LANE-TICKET-PRIVACY-LABEL", &privacy_label);
        let nullifier_root = fast_lane_scheduler_nullifier(
            "FAST-LANE-TICKET-NULLIFIER",
            &[&submitter_commitment, &payload_root, class.as_str()],
        );
        let priority_score = class
            .default_priority()
            .saturating_add(sponsor_credit_units / 1_000)
            .saturating_sub(declared_weight / 50_000);
        let expires_at_height = submitted_at_height.saturating_add(ttl_blocks);
        let target_latency_ms = class.target_latency_ms();
        let ticket_id = fast_lane_scheduler_ticket_id(
            class,
            &submitter_commitment,
            &payload_root,
            &privacy_label_root,
            &authorization_id,
            declared_weight,
            max_fee_micro_units,
            sponsor_credit_units,
            submitted_at_height,
            expires_at_height,
        );
        Ok(Self {
            ticket_id,
            class,
            submitter_commitment,
            payload_root,
            privacy_label_root,
            nullifier_root,
            authorization_id,
            declared_weight,
            max_fee_micro_units,
            sponsor_credit_units,
            priority_score,
            submitted_at_height,
            expires_at_height,
            target_latency_ms,
            status: FastLaneTicketStatus::Pending,
        })
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<()> {
        ensure_non_empty(&self.ticket_id, "fast lane ticket id")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "fast lane ticket submitter commitment",
        )?;
        ensure_non_empty(&self.payload_root, "fast lane ticket payload root")?;
        ensure_non_empty(
            &self.privacy_label_root,
            "fast lane ticket privacy label root",
        )?;
        ensure_non_empty(&self.nullifier_root, "fast lane ticket nullifier root")?;
        ensure_non_empty(&self.authorization_id, "fast lane ticket authorization id")?;
        ensure_positive(self.declared_weight, "fast lane ticket declared weight")?;
        ensure_positive(self.max_fee_micro_units, "fast lane ticket max fee")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("fast lane ticket expires before ttl window".to_string());
        }
        if self.ticket_id
            != fast_lane_scheduler_ticket_id(
                self.class,
                &self.submitter_commitment,
                &self.payload_root,
                &self.privacy_label_root,
                &self.authorization_id,
                self.declared_weight,
                self.max_fee_micro_units,
                self.sponsor_credit_units,
                self.submitted_at_height,
                self.expires_at_height,
            )
        {
            return Err("fast lane ticket id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn fee_density(&self) -> u64 {
        self.max_fee_micro_units
            .saturating_add(self.sponsor_credit_units)
            .saturating_mul(1_000)
            / self.declared_weight.max(1)
    }

    pub fn admission_score(&self, height: u64) -> u64 {
        let urgency = self.expires_at_height.saturating_sub(height).max(1);
        self.priority_score
            .saturating_mul(1_000)
            .saturating_add(self.fee_density())
            .saturating_add(10_000 / urgency)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_admission_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "class": self.class.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "payload_root": self.payload_root,
            "privacy_label_root": self.privacy_label_root,
            "nullifier_root": self.nullifier_root,
            "authorization_id": self.authorization_id,
            "declared_weight": self.declared_weight,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsor_credit_units": self.sponsor_credit_units,
            "priority_score": self.priority_score,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "target_latency_ms": self.target_latency_ms,
            "status": self.status.as_str(),
            "fee_density": self.fee_density(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneMicroBatch {
    pub batch_id: String,
    pub class: FastLaneClass,
    pub height: u64,
    pub scheduler_commitment: String,
    pub ticket_ids: Vec<String>,
    pub ticket_root: String,
    pub total_weight: u64,
    pub total_fee_micro_units: u64,
    pub total_sponsor_credit_units: u64,
    pub average_target_latency_ms: u64,
    pub payload_commitment_root: String,
    pub privacy_nullifier_root: String,
    pub sealed_at_ms: u64,
    pub status: FastLaneBatchStatus,
}

impl FastLaneMicroBatch {
    pub fn new(
        class: FastLaneClass,
        height: u64,
        scheduler_label: impl Into<String>,
        tickets: &[FastLaneAdmissionTicket],
        sealed_at_ms: u64,
    ) -> FastLaneSchedulerResult<Self> {
        if tickets.is_empty() {
            return Err("fast lane microbatch needs at least one ticket".to_string());
        }
        if tickets.len() > FAST_LANE_SCHEDULER_MAX_TICKETS {
            return Err("fast lane microbatch exceeds ticket limit".to_string());
        }
        let scheduler_label = scheduler_label.into();
        ensure_non_empty(&scheduler_label, "fast lane microbatch scheduler")?;
        let scheduler_commitment =
            fast_lane_scheduler_string_root("FAST-LANE-BATCH-SCHEDULER", &scheduler_label);
        let mut ticket_ids = Vec::with_capacity(tickets.len());
        let mut ticket_leaves = Vec::with_capacity(tickets.len());
        let mut payload_leaves = Vec::with_capacity(tickets.len());
        let mut nullifier_leaves = Vec::with_capacity(tickets.len());
        let mut total_weight = 0_u64;
        let mut total_fee_micro_units = 0_u64;
        let mut total_sponsor_credit_units = 0_u64;
        let mut latency_sum = 0_u64;
        for ticket in tickets {
            ticket.validate()?;
            if ticket.class != class {
                return Err("fast lane microbatch contains wrong class".to_string());
            }
            ticket_ids.push(ticket.ticket_id.clone());
            ticket_leaves.push(Value::String(ticket.ticket_id.clone()));
            payload_leaves.push(Value::String(ticket.payload_root.clone()));
            nullifier_leaves.push(Value::String(ticket.nullifier_root.clone()));
            total_weight = total_weight.saturating_add(ticket.declared_weight);
            total_fee_micro_units =
                total_fee_micro_units.saturating_add(ticket.max_fee_micro_units);
            total_sponsor_credit_units =
                total_sponsor_credit_units.saturating_add(ticket.sponsor_credit_units);
            latency_sum = latency_sum.saturating_add(ticket.target_latency_ms);
        }
        let ticket_root = merkle_root("FAST-LANE-BATCH-TICKETS", &ticket_leaves);
        let payload_commitment_root = merkle_root("FAST-LANE-BATCH-PAYLOADS", &payload_leaves);
        let privacy_nullifier_root = merkle_root("FAST-LANE-BATCH-NULLIFIERS", &nullifier_leaves);
        let average_target_latency_ms = latency_sum / tickets.len() as u64;
        let batch_id = fast_lane_scheduler_batch_id(
            class,
            height,
            &scheduler_commitment,
            &ticket_root,
            total_weight,
            total_fee_micro_units,
            total_sponsor_credit_units,
            sealed_at_ms,
        );
        Ok(Self {
            batch_id,
            class,
            height,
            scheduler_commitment,
            ticket_ids,
            ticket_root,
            total_weight,
            total_fee_micro_units,
            total_sponsor_credit_units,
            average_target_latency_ms,
            payload_commitment_root,
            privacy_nullifier_root,
            sealed_at_ms,
            status: FastLaneBatchStatus::Sealed,
        })
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<()> {
        ensure_non_empty(&self.batch_id, "fast lane microbatch id")?;
        ensure_non_empty(
            &self.scheduler_commitment,
            "fast lane microbatch scheduler commitment",
        )?;
        ensure_non_empty(&self.ticket_root, "fast lane microbatch ticket root")?;
        ensure_non_empty(
            &self.payload_commitment_root,
            "fast lane microbatch payload root",
        )?;
        ensure_non_empty(
            &self.privacy_nullifier_root,
            "fast lane microbatch nullifier root",
        )?;
        if self.ticket_ids.is_empty() {
            return Err("fast lane microbatch tickets cannot be empty".to_string());
        }
        ensure_positive(self.total_weight, "fast lane microbatch total weight")?;
        ensure_positive(
            self.total_fee_micro_units
                .saturating_add(self.total_sponsor_credit_units),
            "fast lane microbatch fee or sponsor total",
        )?;
        if self.batch_id
            != fast_lane_scheduler_batch_id(
                self.class,
                self.height,
                &self.scheduler_commitment,
                &self.ticket_root,
                self.total_weight,
                self.total_fee_micro_units,
                self.total_sponsor_credit_units,
                self.sealed_at_ms,
            )
        {
            return Err("fast lane microbatch id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_microbatch",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "class": self.class.as_str(),
            "height": self.height,
            "scheduler_commitment": self.scheduler_commitment,
            "ticket_ids": self.ticket_ids,
            "ticket_root": self.ticket_root,
            "total_weight": self.total_weight,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_sponsor_credit_units": self.total_sponsor_credit_units,
            "average_target_latency_ms": self.average_target_latency_ms,
            "payload_commitment_root": self.payload_commitment_root,
            "privacy_nullifier_root": self.privacy_nullifier_root,
            "sealed_at_ms": self.sealed_at_ms,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneBackpressureWindow {
    pub window_id: String,
    pub mode: FastLaneBackpressureMode,
    pub start_height: u64,
    pub end_height: u64,
    pub queue_depth: u64,
    pub max_admission_weight: u64,
    pub fee_multiplier_bps: u64,
    pub sponsor_multiplier_bps: u64,
    pub class_overrides: BTreeMap<String, u64>,
    pub reason_root: String,
}

impl FastLaneBackpressureWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: FastLaneBackpressureMode,
        start_height: u64,
        end_height: u64,
        queue_depth: u64,
        max_admission_weight: u64,
        fee_multiplier_bps: u64,
        sponsor_multiplier_bps: u64,
        class_overrides: BTreeMap<String, u64>,
        reason: &Value,
    ) -> FastLaneSchedulerResult<Self> {
        if end_height <= start_height {
            return Err("fast lane backpressure window has empty range".to_string());
        }
        ensure_positive(queue_depth, "fast lane backpressure queue depth")?;
        ensure_positive(
            max_admission_weight,
            "fast lane backpressure max admission weight",
        )?;
        validate_bps(
            fee_multiplier_bps,
            "fast lane backpressure fee multiplier bps",
        )?;
        validate_bps(
            sponsor_multiplier_bps,
            "fast lane backpressure sponsor multiplier bps",
        )?;
        let reason_root = fast_lane_scheduler_payload_root("FAST-LANE-BACKPRESSURE-REASON", reason);
        let window_id = fast_lane_scheduler_backpressure_window_id(
            mode,
            start_height,
            end_height,
            queue_depth,
            max_admission_weight,
            fee_multiplier_bps,
            sponsor_multiplier_bps,
            &class_overrides,
            &reason_root,
        );
        Ok(Self {
            window_id,
            mode,
            start_height,
            end_height,
            queue_depth,
            max_admission_weight,
            fee_multiplier_bps,
            sponsor_multiplier_bps,
            class_overrides,
            reason_root,
        })
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<()> {
        ensure_non_empty(&self.window_id, "fast lane backpressure window id")?;
        ensure_non_empty(&self.reason_root, "fast lane backpressure reason root")?;
        if self.end_height <= self.start_height {
            return Err("fast lane backpressure window has empty range".to_string());
        }
        ensure_positive(self.queue_depth, "fast lane backpressure queue depth")?;
        ensure_positive(
            self.max_admission_weight,
            "fast lane backpressure max admission weight",
        )?;
        validate_bps(
            self.fee_multiplier_bps,
            "fast lane backpressure fee multiplier bps",
        )?;
        validate_bps(
            self.sponsor_multiplier_bps,
            "fast lane backpressure sponsor multiplier bps",
        )?;
        if self.window_id
            != fast_lane_scheduler_backpressure_window_id(
                self.mode,
                self.start_height,
                self.end_height,
                self.queue_depth,
                self.max_admission_weight,
                self.fee_multiplier_bps,
                self.sponsor_multiplier_bps,
                &self.class_overrides,
                &self.reason_root,
            )
        {
            return Err("fast lane backpressure window id mismatch".to_string());
        }
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn class_multiplier_bps(&self, class: FastLaneClass) -> u64 {
        self.class_overrides
            .get(class.as_str())
            .copied()
            .unwrap_or(self.fee_multiplier_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_backpressure_window",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "mode": self.mode.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "queue_depth": self.queue_depth,
            "max_admission_weight": self.max_admission_weight,
            "fee_multiplier_bps": self.fee_multiplier_bps,
            "sponsor_multiplier_bps": self.sponsor_multiplier_bps,
            "class_overrides": self.class_overrides,
            "reason_root": self.reason_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneFeeRebate {
    pub rebate_id: String,
    pub ticket_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub gross_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub sponsor_credit_units: u64,
    pub settlement_height: u64,
    pub claim_nullifier: String,
}

impl FastLaneFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_id: impl Into<String>,
        batch_id: impl Into<String>,
        beneficiary_label: impl Into<String>,
        asset_id: impl Into<String>,
        gross_fee_micro_units: u64,
        rebate_bps: u64,
        sponsor_credit_units: u64,
        settlement_height: u64,
    ) -> FastLaneSchedulerResult<Self> {
        let ticket_id = ticket_id.into();
        let batch_id = batch_id.into();
        let beneficiary_label = beneficiary_label.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&ticket_id, "fast lane rebate ticket id")?;
        ensure_non_empty(&batch_id, "fast lane rebate batch id")?;
        ensure_non_empty(&beneficiary_label, "fast lane rebate beneficiary")?;
        ensure_non_empty(&asset_id, "fast lane rebate asset id")?;
        ensure_positive(gross_fee_micro_units, "fast lane rebate gross fee")?;
        validate_bps(rebate_bps, "fast lane rebate bps")?;
        let beneficiary_commitment =
            fast_lane_scheduler_string_root("FAST-LANE-REBATE-BENEFICIARY", &beneficiary_label);
        let rebate_micro_units =
            gross_fee_micro_units.saturating_mul(rebate_bps) / FAST_LANE_SCHEDULER_MAX_BPS;
        let claim_nullifier = fast_lane_scheduler_nullifier(
            "FAST-LANE-REBATE-CLAIM",
            &[&ticket_id, &batch_id, &beneficiary_commitment],
        );
        let rebate_id = fast_lane_scheduler_rebate_id(
            &ticket_id,
            &batch_id,
            &beneficiary_commitment,
            &asset_id,
            gross_fee_micro_units,
            rebate_micro_units,
            sponsor_credit_units,
            settlement_height,
            &claim_nullifier,
        );
        Ok(Self {
            rebate_id,
            ticket_id,
            batch_id,
            beneficiary_commitment,
            asset_id,
            gross_fee_micro_units,
            rebate_micro_units,
            sponsor_credit_units,
            settlement_height,
            claim_nullifier,
        })
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<()> {
        ensure_non_empty(&self.rebate_id, "fast lane rebate id")?;
        ensure_non_empty(&self.ticket_id, "fast lane rebate ticket id")?;
        ensure_non_empty(&self.batch_id, "fast lane rebate batch id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "fast lane rebate beneficiary commitment",
        )?;
        ensure_non_empty(&self.asset_id, "fast lane rebate asset id")?;
        ensure_non_empty(&self.claim_nullifier, "fast lane rebate claim nullifier")?;
        ensure_positive(self.gross_fee_micro_units, "fast lane rebate gross fee")?;
        if self.rebate_micro_units > self.gross_fee_micro_units {
            return Err("fast lane rebate exceeds gross fee".to_string());
        }
        if self.rebate_id
            != fast_lane_scheduler_rebate_id(
                &self.ticket_id,
                &self.batch_id,
                &self.beneficiary_commitment,
                &self.asset_id,
                self.gross_fee_micro_units,
                self.rebate_micro_units,
                self.sponsor_credit_units,
                self.settlement_height,
                &self.claim_nullifier,
            )
        {
            return Err("fast lane rebate id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "ticket_id": self.ticket_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_credit_units": self.sponsor_credit_units,
            "settlement_height": self.settlement_height,
            "claim_nullifier": self.claim_nullifier,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneSchedulerRoots {
    pub config_root: String,
    pub authorization_root: String,
    pub ticket_root: String,
    pub batch_root: String,
    pub backpressure_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub queue_root: String,
    pub state_root: String,
}

impl FastLaneSchedulerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_scheduler_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "authorization_root": self.authorization_root,
            "ticket_root": self.ticket_root,
            "batch_root": self.batch_root,
            "backpressure_root": self.backpressure_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "queue_root": self.queue_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneSchedulerCounters {
    pub authorizations: u64,
    pub pending_tickets: u64,
    pub admitted_tickets: u64,
    pub deferred_tickets: u64,
    pub batched_tickets: u64,
    pub expired_tickets: u64,
    pub batches: u64,
    pub backpressure_windows: u64,
    pub rebates: u64,
    pub total_weight: u64,
    pub total_fee_micro_units: u64,
    pub total_sponsor_credit_units: u64,
}

impl FastLaneSchedulerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_scheduler_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "authorizations": self.authorizations,
            "pending_tickets": self.pending_tickets,
            "admitted_tickets": self.admitted_tickets,
            "deferred_tickets": self.deferred_tickets,
            "batched_tickets": self.batched_tickets,
            "expired_tickets": self.expired_tickets,
            "batches": self.batches,
            "backpressure_windows": self.backpressure_windows,
            "rebates": self.rebates,
            "total_weight": self.total_weight,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_sponsor_credit_units": self.total_sponsor_credit_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneSchedulerState {
    pub height: u64,
    pub scheduler_label: String,
    pub config: FastLaneSchedulerConfig,
    pub authorizations: BTreeMap<String, FastLanePqAuthorization>,
    pub tickets: BTreeMap<String, FastLaneAdmissionTicket>,
    pub batches: BTreeMap<String, FastLaneMicroBatch>,
    pub backpressure_windows: BTreeMap<String, FastLaneBackpressureWindow>,
    pub rebates: BTreeMap<String, FastLaneFeeRebate>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub queue_by_class: BTreeMap<String, Vec<String>>,
}

impl FastLaneSchedulerState {
    pub fn new(
        scheduler_label: impl Into<String>,
        config: FastLaneSchedulerConfig,
    ) -> FastLaneSchedulerResult<Self> {
        config.validate()?;
        let scheduler_label = scheduler_label.into();
        ensure_non_empty(&scheduler_label, "fast lane scheduler label")?;
        Ok(Self {
            height: 0,
            scheduler_label,
            config,
            authorizations: BTreeMap::new(),
            tickets: BTreeMap::new(),
            batches: BTreeMap::new(),
            backpressure_windows: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            queue_by_class: BTreeMap::new(),
        })
    }

    pub fn devnet() -> FastLaneSchedulerResult<Self> {
        let config = FastLaneSchedulerConfig::default();
        let mut state = Self::new("devnet-fast-lane-scheduler", config)?;
        state.set_height(1);

        let bridge_auth = FastLanePqAuthorization::new(
            FastLaneAuthorizationKind::EmergencyBridge,
            "devnet-bridge-exit-wallet",
            FastLaneClass::BridgeExit,
            20_000,
            450_000,
            0,
            96,
            "dilithium5+kyber1024",
            "devnet-bridge-exit-pq-public-key",
            "devnet-bridge-exit-pq-signature",
            &json!({
                "policy": "payload_roots_only",
                "view_key_committee": "bridge-operators",
                "disclosure_delay_blocks": 720,
            }),
        )?;
        let swap_auth = FastLanePqAuthorization::new(
            FastLaneAuthorizationKind::PqWallet,
            "devnet-private-swap-wallet",
            FastLaneClass::PrivateSwap,
            12_000,
            300_000,
            0,
            64,
            "falcon1024+kyber768",
            "devnet-private-swap-pq-public-key",
            "devnet-private-swap-pq-signature",
            &json!({
                "policy": "encrypted_memo_only",
                "view_key_committee": "user-selected",
                "disclosure_delay_blocks": 0,
            }),
        )?;
        let contract_auth = FastLanePqAuthorization::new(
            FastLaneAuthorizationKind::Paymaster,
            "devnet-private-contract-paymaster",
            FastLaneClass::ContractCall,
            16_000,
            520_000,
            0,
            80,
            "dilithium3+ml-kem-768",
            "devnet-contract-paymaster-pq-public-key",
            "devnet-contract-paymaster-pq-signature",
            &json!({
                "policy": "sponsored_call_root",
                "view_key_committee": "paymaster-risk-desk",
                "disclosure_delay_blocks": 24,
            }),
        )?;
        let liquidation_auth = FastLanePqAuthorization::new(
            FastLaneAuthorizationKind::SequencerQuota,
            "devnet-liquidation-keeper",
            FastLaneClass::LendingLiquidation,
            18_000,
            480_000,
            0,
            48,
            "dilithium5",
            "devnet-liquidation-keeper-pq-public-key",
            "devnet-liquidation-keeper-pq-signature",
            &json!({
                "policy": "health_bucket_root",
                "view_key_committee": "risk-council",
                "disclosure_delay_blocks": 12,
            }),
        )?;

        state.insert_authorization(bridge_auth.clone())?;
        state.insert_authorization(swap_auth.clone())?;
        state.insert_authorization(contract_auth.clone())?;
        state.insert_authorization(liquidation_auth.clone())?;

        let bridge_ticket = FastLaneAdmissionTicket::new(
            FastLaneClass::BridgeExit,
            "devnet-bridge-exit-wallet",
            &json!({
                "route": "xmr_exit",
                "amount_commitment": "amount:bridge:devnet:001",
                "destination_view_tag": "encrypted-view-tag-001",
                "monero_unlock_hint": 12,
            }),
            "bridge_exit_sensitive",
            bridge_auth.authorization_id.clone(),
            420_000,
            18_000,
            8_000,
            1,
            state.config.ticket_ttl_blocks,
        )?;
        let swap_ticket = FastLaneAdmissionTicket::new(
            FastLaneClass::PrivateSwap,
            "devnet-private-swap-wallet",
            &json!({
                "intent": "swap",
                "sell_asset": "asset:wxmr",
                "buy_asset": "asset:usdd",
                "amount_commitment": "amount:swap:devnet:001",
                "min_out_commitment": "min-out:swap:devnet:001",
            }),
            "private_swap",
            swap_auth.authorization_id.clone(),
            260_000,
            10_000,
            5_000,
            1,
            state.config.ticket_ttl_blocks,
        )?;
        let contract_ticket = FastLaneAdmissionTicket::new(
            FastLaneClass::ContractCall,
            "devnet-private-contract-paymaster",
            &json!({
                "contract": "private-vault",
                "method": "rebalance",
                "calldata_root": "calldata:private-vault:rebalance:001",
                "state_access_root": "state-access:private-vault:001",
            }),
            "private_contract_call",
            contract_auth.authorization_id.clone(),
            480_000,
            14_000,
            6_000,
            1,
            state.config.ticket_ttl_blocks,
        )?;
        let liquidation_ticket = FastLaneAdmissionTicket::new(
            FastLaneClass::LendingLiquidation,
            "devnet-liquidation-keeper",
            &json!({
                "market": "wxmr-usdd",
                "position_commitment": "position:at-risk:001",
                "health_bucket": "danger",
                "auction_hint": "sealed-bid",
            }),
            "liquidation",
            liquidation_auth.authorization_id.clone(),
            440_000,
            15_000,
            7_000,
            1,
            state.config.ticket_ttl_blocks,
        )?;

        state.admit_ticket(bridge_ticket)?;
        state.admit_ticket(swap_ticket)?;
        state.admit_ticket(contract_ticket)?;
        state.admit_ticket(liquidation_ticket)?;

        let mut overrides = BTreeMap::new();
        overrides.insert(FastLaneClass::BridgeExit.as_str().to_string(), 8_500);
        overrides.insert(FastLaneClass::PrivateSwap.as_str().to_string(), 9_250);
        overrides.insert(FastLaneClass::ContractCall.as_str().to_string(), 9_000);
        let window = FastLaneBackpressureWindow::new(
            FastLaneBackpressureMode::CompressOnly,
            1,
            8,
            18_000,
            2_000_000,
            9_000,
            7_500,
            overrides,
            &json!({
                "source": "devnet_load_shedder",
                "reason": "prefer compressed private batches while mempool warms",
                "queue_root_hint": "devnet-fast-lane-queue",
            }),
        )?;
        state.insert_backpressure_window(window)?;

        state.close_microbatch(
            FastLaneClass::BridgeExit,
            "devnet-fast-lane-scheduler",
            1_700_000_000_250,
        )?;
        state.close_microbatch(
            FastLaneClass::PrivateSwap,
            "devnet-fast-lane-scheduler",
            1_700_000_000_500,
        )?;
        state.close_microbatch(
            FastLaneClass::ContractCall,
            "devnet-fast-lane-scheduler",
            1_700_000_000_750,
        )?;
        state.close_microbatch(
            FastLaneClass::LendingLiquidation,
            "devnet-fast-lane-scheduler",
            1_700_000_001_000,
        )?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.expire_tickets();
    }

    pub fn insert_authorization(
        &mut self,
        authorization: FastLanePqAuthorization,
    ) -> FastLaneSchedulerResult<String> {
        authorization.validate()?;
        let id = authorization.authorization_id.clone();
        self.authorizations.insert(id.clone(), authorization);
        Ok(id)
    }

    pub fn admit_ticket(
        &mut self,
        mut ticket: FastLaneAdmissionTicket,
    ) -> FastLaneSchedulerResult<String> {
        ticket.validate()?;
        if self.consumed_nullifiers.contains(&ticket.nullifier_root) {
            return Err("fast lane ticket nullifier already consumed".to_string());
        }
        if ticket.is_expired(self.height) {
            ticket.status = FastLaneTicketStatus::Expired;
        } else {
            let authorization = self
                .authorizations
                .get(&ticket.authorization_id)
                .ok_or_else(|| "fast lane ticket references unknown authorization".to_string())?;
            if !authorization.covers(
                ticket.class,
                ticket.max_fee_micro_units,
                ticket.declared_weight,
                self.height,
            ) {
                return Err("fast lane pq authorization does not cover ticket".to_string());
            }
            ticket.status = FastLaneTicketStatus::Admitted;
        }
        let ticket_id = ticket.ticket_id.clone();
        self.queue_by_class
            .entry(ticket.class.as_str().to_string())
            .or_default()
            .push(ticket_id.clone());
        self.consumed_nullifiers
            .insert(ticket.nullifier_root.clone());
        self.tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }

    pub fn insert_backpressure_window(
        &mut self,
        window: FastLaneBackpressureWindow,
    ) -> FastLaneSchedulerResult<String> {
        window.validate()?;
        let id = window.window_id.clone();
        self.backpressure_windows.insert(id.clone(), window);
        Ok(id)
    }

    pub fn active_backpressure_window(&self) -> Option<&FastLaneBackpressureWindow> {
        self.backpressure_windows
            .values()
            .filter(|window| window.active_at(self.height))
            .max_by_key(|window| window.queue_depth)
    }

    pub fn quote_fee_micro_units(&self, class: FastLaneClass, declared_weight: u64) -> u64 {
        let base = self
            .config
            .base_fee_micro_units
            .saturating_mul(declared_weight.max(1))
            / 1_000;
        let multiplier_bps = self
            .active_backpressure_window()
            .map(|window| window.class_multiplier_bps(class))
            .unwrap_or(FAST_LANE_SCHEDULER_MAX_BPS);
        base.saturating_mul(multiplier_bps) / FAST_LANE_SCHEDULER_MAX_BPS
    }

    pub fn close_microbatch(
        &mut self,
        class: FastLaneClass,
        scheduler_label: impl Into<String>,
        sealed_at_ms: u64,
    ) -> FastLaneSchedulerResult<String> {
        let class_key = class.as_str().to_string();
        let queued_ids = self
            .queue_by_class
            .get(&class_key)
            .cloned()
            .unwrap_or_default();
        if queued_ids.is_empty() {
            return Err(format!("fast lane class {class_key} has no queued tickets"));
        }

        let mut tickets = queued_ids
            .iter()
            .filter_map(|ticket_id| self.tickets.get(ticket_id))
            .filter(|ticket| {
                matches!(
                    ticket.status,
                    FastLaneTicketStatus::Pending | FastLaneTicketStatus::Admitted
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        tickets.sort_by(|left, right| {
            right
                .admission_score(self.height)
                .cmp(&left.admission_score(self.height))
                .then_with(|| left.ticket_id.cmp(&right.ticket_id))
        });

        let max_weight = self
            .active_backpressure_window()
            .map(|window| window.max_admission_weight)
            .unwrap_or(self.config.max_batch_weight)
            .min(self.config.max_batch_weight);
        let mut selected = Vec::new();
        let mut selected_weight = 0_u64;
        for ticket in tickets {
            if selected_weight.saturating_add(ticket.declared_weight) > max_weight {
                if let Some(stored) = self.tickets.get_mut(&ticket.ticket_id) {
                    stored.status = FastLaneTicketStatus::Deferred;
                }
                continue;
            }
            selected_weight = selected_weight.saturating_add(ticket.declared_weight);
            selected.push(ticket);
        }
        if selected.is_empty() {
            return Err("fast lane microbatch selection is empty".to_string());
        }

        let batch =
            FastLaneMicroBatch::new(class, self.height, scheduler_label, &selected, sealed_at_ms)?;
        let batch_id = batch.batch_id.clone();
        for ticket in &selected {
            if let Some(stored) = self.tickets.get_mut(&ticket.ticket_id) {
                stored.status = FastLaneTicketStatus::Batched;
            }
            let rebate = FastLaneFeeRebate::new(
                ticket.ticket_id.clone(),
                batch_id.clone(),
                format!("beneficiary:{}", ticket.submitter_commitment),
                "asset:wxmr",
                ticket.max_fee_micro_units,
                self.config.low_fee_rebate_bps,
                ticket.sponsor_credit_units,
                self.height,
            )?;
            self.rebates.insert(rebate.rebate_id.clone(), rebate);
        }
        self.batches.insert(batch_id.clone(), batch);
        self.queue_by_class.insert(
            class_key,
            queued_ids
                .into_iter()
                .filter(|ticket_id| {
                    self.tickets
                        .get(ticket_id)
                        .map(|ticket| !matches!(ticket.status, FastLaneTicketStatus::Batched))
                        .unwrap_or(false)
                })
                .collect(),
        );
        Ok(batch_id)
    }

    pub fn expire_tickets(&mut self) {
        for ticket in self.tickets.values_mut() {
            if matches!(
                ticket.status,
                FastLaneTicketStatus::Pending
                    | FastLaneTicketStatus::Admitted
                    | FastLaneTicketStatus::Deferred
            ) && ticket.is_expired(self.height)
            {
                ticket.status = FastLaneTicketStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> FastLaneSchedulerRoots {
        let config_root = self.config.config_root();
        let authorization_leaves = self
            .authorizations
            .values()
            .map(|authorization| authorization.public_record())
            .collect::<Vec<_>>();
        let ticket_leaves = self
            .tickets
            .values()
            .map(|ticket| ticket.public_record())
            .collect::<Vec<_>>();
        let batch_leaves = self
            .batches
            .values()
            .map(|batch| batch.public_record())
            .collect::<Vec<_>>();
        let backpressure_leaves = self
            .backpressure_windows
            .values()
            .map(|window| window.public_record())
            .collect::<Vec<_>>();
        let rebate_leaves = self
            .rebates
            .values()
            .map(|rebate| rebate.public_record())
            .collect::<Vec<_>>();
        let nullifier_leaves = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| Value::String(nullifier.clone()))
            .collect::<Vec<_>>();
        let queue_leaves = self
            .queue_by_class
            .iter()
            .map(|(class, ticket_ids)| {
                json!({
                    "class": class,
                    "ticket_ids": ticket_ids,
                    "ticket_count": ticket_ids.len(),
                })
            })
            .collect::<Vec<_>>();
        let authorization_root =
            merkle_root("FAST-LANE-SCHEDULER-AUTHORIZATIONS", &authorization_leaves);
        let ticket_root = merkle_root("FAST-LANE-SCHEDULER-TICKETS", &ticket_leaves);
        let batch_root = merkle_root("FAST-LANE-SCHEDULER-BATCHES", &batch_leaves);
        let backpressure_root =
            merkle_root("FAST-LANE-SCHEDULER-BACKPRESSURE", &backpressure_leaves);
        let rebate_root = merkle_root("FAST-LANE-SCHEDULER-REBATES", &rebate_leaves);
        let nullifier_root = merkle_root("FAST-LANE-SCHEDULER-NULLIFIERS", &nullifier_leaves);
        let queue_root = merkle_root("FAST-LANE-SCHEDULER-QUEUES", &queue_leaves);
        let state_record = json!({
            "kind": "fast_lane_scheduler_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "height": self.height,
            "scheduler_label_root": fast_lane_scheduler_string_root("FAST-LANE-SCHEDULER-LABEL", &self.scheduler_label),
            "config_root": config_root,
            "authorization_root": authorization_root,
            "ticket_root": ticket_root,
            "batch_root": batch_root,
            "backpressure_root": backpressure_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
            "queue_root": queue_root,
            "counters": self.counters().public_record(),
        });
        let state_root = pq_state_root(&state_record);
        FastLaneSchedulerRoots {
            config_root,
            authorization_root,
            ticket_root,
            batch_root,
            backpressure_root,
            rebate_root,
            nullifier_root,
            queue_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn counters(&self) -> FastLaneSchedulerCounters {
        let mut counters = FastLaneSchedulerCounters {
            authorizations: self.authorizations.len() as u64,
            batches: self.batches.len() as u64,
            backpressure_windows: self.backpressure_windows.len() as u64,
            rebates: self.rebates.len() as u64,
            ..FastLaneSchedulerCounters::default()
        };
        for ticket in self.tickets.values() {
            match ticket.status {
                FastLaneTicketStatus::Pending => counters.pending_tickets += 1,
                FastLaneTicketStatus::Admitted => counters.admitted_tickets += 1,
                FastLaneTicketStatus::Deferred => counters.deferred_tickets += 1,
                FastLaneTicketStatus::Batched | FastLaneTicketStatus::Settled => {
                    counters.batched_tickets += 1
                }
                FastLaneTicketStatus::Expired => counters.expired_tickets += 1,
                FastLaneTicketStatus::Rejected => {}
            }
            counters.total_weight = counters.total_weight.saturating_add(ticket.declared_weight);
            counters.total_fee_micro_units = counters
                .total_fee_micro_units
                .saturating_add(ticket.max_fee_micro_units);
            counters.total_sponsor_credit_units = counters
                .total_sponsor_credit_units
                .saturating_add(ticket.sponsor_credit_units);
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "fast_lane_scheduler_state",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_LANE_SCHEDULER_PROTOCOL_VERSION,
            "height": self.height,
            "scheduler_label": self.scheduler_label,
            "config": self.config.public_record(),
            "authorizations": self.authorizations.values().map(FastLanePqAuthorization::public_record).collect::<Vec<_>>(),
            "tickets": self.tickets.values().map(FastLaneAdmissionTicket::public_record).collect::<Vec<_>>(),
            "batches": self.batches.values().map(FastLaneMicroBatch::public_record).collect::<Vec<_>>(),
            "backpressure_windows": self.backpressure_windows.values().map(FastLaneBackpressureWindow::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FastLaneFeeRebate::public_record).collect::<Vec<_>>(),
            "consumed_nullifiers": self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "queue_by_class": self.queue_by_class,
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> FastLaneSchedulerResult<String> {
        ensure_non_empty(&self.scheduler_label, "fast lane scheduler label")?;
        self.config.validate()?;
        if self.authorizations.len() > FAST_LANE_SCHEDULER_MAX_AUTHORIZATIONS {
            return Err("fast lane scheduler has too many authorizations".to_string());
        }
        if self.tickets.len() > FAST_LANE_SCHEDULER_MAX_TICKETS {
            return Err("fast lane scheduler has too many tickets".to_string());
        }
        if self.batches.len() > FAST_LANE_SCHEDULER_MAX_BATCHES {
            return Err("fast lane scheduler has too many batches".to_string());
        }
        if self.backpressure_windows.len() > FAST_LANE_SCHEDULER_MAX_WINDOWS {
            return Err("fast lane scheduler has too many backpressure windows".to_string());
        }
        if self.rebates.len() > FAST_LANE_SCHEDULER_MAX_REBATES {
            return Err("fast lane scheduler has too many rebates".to_string());
        }
        for authorization in self.authorizations.values() {
            authorization.validate()?;
        }
        for ticket in self.tickets.values() {
            ticket.validate()?;
            if !self.authorizations.contains_key(&ticket.authorization_id) {
                return Err("fast lane ticket references missing authorization".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate()?;
            for ticket_id in &batch.ticket_ids {
                if !self.tickets.contains_key(ticket_id) {
                    return Err("fast lane batch references missing ticket".to_string());
                }
            }
        }
        for window in self.backpressure_windows.values() {
            window.validate()?;
        }
        for rebate in self.rebates.values() {
            rebate.validate()?;
            if !self.tickets.contains_key(&rebate.ticket_id) {
                return Err("fast lane rebate references missing ticket".to_string());
            }
            if !self.batches.contains_key(&rebate.batch_id) {
                return Err("fast lane rebate references missing batch".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn fast_lane_scheduler_state_root_from_record(record: &Value) -> String {
    pq_state_root(record)
}

pub fn fast_lane_scheduler_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn fast_lane_scheduler_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn fast_lane_scheduler_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(fast_lane_scheduler_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn fast_lane_scheduler_nullifier(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| Value::String((*part).to_string()))
        .collect::<Vec<_>>();
    let parts_root = merkle_root(domain, &leaves);
    domain_hash(
        &format!("{domain}:nullifier"),
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&parts_root),
        ],
        32,
    )
}

pub fn fast_lane_scheduler_config_id(record: &Value) -> String {
    fast_lane_scheduler_payload_root("FAST-LANE-SCHEDULER-CONFIG-ID", record)
}

#[allow(clippy::too_many_arguments)]
pub fn fast_lane_scheduler_authorization_id(
    authorization_kind: FastLaneAuthorizationKind,
    subject_commitment: &str,
    class: FastLaneClass,
    max_fee_micro_units: u64,
    max_weight: u64,
    valid_after_height: u64,
    valid_until_height: u64,
    pq_algorithm: &str,
    public_key_root: &str,
    signature_root: &str,
    disclosure_policy_root: &str,
) -> String {
    domain_hash(
        "FAST-LANE-SCHEDULER-AUTHORIZATION-ID",
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(authorization_kind.as_str()),
            HashPart::Str(subject_commitment),
            HashPart::Str(class.as_str()),
            HashPart::Int(max_fee_micro_units as i128),
            HashPart::Int(max_weight as i128),
            HashPart::Int(valid_after_height as i128),
            HashPart::Int(valid_until_height as i128),
            HashPart::Str(pq_algorithm),
            HashPart::Str(public_key_root),
            HashPart::Str(signature_root),
            HashPart::Str(disclosure_policy_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_lane_scheduler_ticket_id(
    class: FastLaneClass,
    submitter_commitment: &str,
    payload_root: &str,
    privacy_label_root: &str,
    authorization_id: &str,
    declared_weight: u64,
    max_fee_micro_units: u64,
    sponsor_credit_units: u64,
    submitted_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "FAST-LANE-SCHEDULER-TICKET-ID",
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class.as_str()),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_root),
            HashPart::Str(privacy_label_root),
            HashPart::Str(authorization_id),
            HashPart::Int(declared_weight as i128),
            HashPart::Int(max_fee_micro_units as i128),
            HashPart::Int(sponsor_credit_units as i128),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_lane_scheduler_batch_id(
    class: FastLaneClass,
    height: u64,
    scheduler_commitment: &str,
    ticket_root: &str,
    total_weight: u64,
    total_fee_micro_units: u64,
    total_sponsor_credit_units: u64,
    sealed_at_ms: u64,
) -> String {
    domain_hash(
        "FAST-LANE-SCHEDULER-BATCH-ID",
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class.as_str()),
            HashPart::Int(height as i128),
            HashPart::Str(scheduler_commitment),
            HashPart::Str(ticket_root),
            HashPart::Int(total_weight as i128),
            HashPart::Int(total_fee_micro_units as i128),
            HashPart::Int(total_sponsor_credit_units as i128),
            HashPart::Int(sealed_at_ms as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_lane_scheduler_backpressure_window_id(
    mode: FastLaneBackpressureMode,
    start_height: u64,
    end_height: u64,
    queue_depth: u64,
    max_admission_weight: u64,
    fee_multiplier_bps: u64,
    sponsor_multiplier_bps: u64,
    class_overrides: &BTreeMap<String, u64>,
    reason_root: &str,
) -> String {
    let override_record = json!(class_overrides);
    domain_hash(
        "FAST-LANE-SCHEDULER-BACKPRESSURE-ID",
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(mode.as_str()),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Int(queue_depth as i128),
            HashPart::Int(max_admission_weight as i128),
            HashPart::Int(fee_multiplier_bps as i128),
            HashPart::Int(sponsor_multiplier_bps as i128),
            HashPart::Json(&override_record),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_lane_scheduler_rebate_id(
    ticket_id: &str,
    batch_id: &str,
    beneficiary_commitment: &str,
    asset_id: &str,
    gross_fee_micro_units: u64,
    rebate_micro_units: u64,
    sponsor_credit_units: u64,
    settlement_height: u64,
    claim_nullifier: &str,
) -> String {
    domain_hash(
        "FAST-LANE-SCHEDULER-REBATE-ID",
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id),
            HashPart::Str(batch_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(gross_fee_micro_units as i128),
            HashPart::Int(rebate_micro_units as i128),
            HashPart::Int(sponsor_credit_units as i128),
            HashPart::Int(settlement_height as i128),
            HashPart::Str(claim_nullifier),
        ],
        32,
    )
}

fn pq_state_root(record: &Value) -> String {
    domain_hash(
        "FAST-LANE-SCHEDULER-STATE-ROOT",
        &[
            HashPart::Str(FAST_LANE_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> FastLaneSchedulerResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> FastLaneSchedulerResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> FastLaneSchedulerResult<()> {
    if value > FAST_LANE_SCHEDULER_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
