use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, HashPart};

pub type FastPrivateAdmissionControlResult<T> = Result<T, String>;

pub const FAST_PRIVATE_ADMISSION_CONTROL_PROTOCOL_VERSION: &str =
    "nebula-fast-private-admission-v1";
pub const FAST_PRIVATE_ADMISSION_CONTROL_PQ_AUTH_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const FAST_PRIVATE_ADMISSION_CONTROL_COMMITMENT_SCHEME: &str = "shake256-poseidon-hybrid";
pub const FAST_PRIVATE_ADMISSION_CONTROL_PROOF_SYSTEM: &str = "zk-fast-admission-v1";
pub const FAST_PRIVATE_ADMISSION_CONTROL_DEFAULT_WINDOW_BLOCKS: u64 = 12;
pub const FAST_PRIVATE_ADMISSION_CONTROL_DEFAULT_TICKET_TTL_BLOCKS: u64 = 48;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_LANES: usize = 128;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_WINDOWS: usize = 512;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_TICKETS: usize = 16_384;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_AUTHORIZATIONS: usize = 16_384;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_RECEIPTS: usize = 16_384;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_SPONSORS: usize = 512;
pub const FAST_PRIVATE_ADMISSION_CONTROL_MAX_EVENTS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionTrafficClass {
    PrivateTransfer,
    PrivateSwap,
    PrivateLending,
    PrivatePerp,
    ContractCall,
    MoneroBridge,
    ProofAggregation,
    WalletRecovery,
}

impl FastAdmissionTrafficClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerp => "private_perp",
            Self::ContractCall => "contract_call",
            Self::MoneroBridge => "monero_bridge",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionLaneStatus {
    Active,
    Throttled,
    Paused,
    Draining,
    Retired,
}

impl FastAdmissionLaneStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn admits(&self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionWindowStatus {
    Scheduled,
    Open,
    Sealed,
    Settled,
    Cancelled,
}

impl FastAdmissionWindowStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionTicketStatus {
    Pending,
    Authorized,
    Admitted,
    Rejected,
    Expired,
    Consumed,
}

impl FastAdmissionTicketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Admitted => "admitted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Consumed => "consumed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionAuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
}

impl FastAdmissionAuthorizationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdmissionDecisionKind {
    AdmitFast,
    AdmitNormal,
    Defer,
    Reject,
    RequireSponsorTopUp,
    RequirePrivacyBudget,
}

impl AdmissionDecisionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AdmitFast => "admit_fast",
            Self::AdmitNormal => "admit_normal",
            Self::Defer => "defer",
            Self::Reject => "reject",
            Self::RequireSponsorTopUp => "require_sponsor_top_up",
            Self::RequirePrivacyBudget => "require_privacy_budget",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionSponsorStatus {
    Active,
    Throttled,
    Exhausted,
    Revoked,
}

impl FastAdmissionSponsorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionReceiptStatus {
    Pending,
    Posted,
    Audited,
    Disputed,
}

impl FastAdmissionReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::Audited => "audited",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FastAdmissionEventKind {
    LaneOpened,
    WindowOpened,
    TicketSubmitted,
    AuthorizationValidated,
    TicketAdmitted,
    TicketRejected,
    SponsorDebited,
    WindowSealed,
}

impl FastAdmissionEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LaneOpened => "lane_opened",
            Self::WindowOpened => "window_opened",
            Self::TicketSubmitted => "ticket_submitted",
            Self::AuthorizationValidated => "authorization_validated",
            Self::TicketAdmitted => "ticket_admitted",
            Self::TicketRejected => "ticket_rejected",
            Self::SponsorDebited => "sponsor_debited",
            Self::WindowSealed => "window_sealed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastPrivateAdmissionControlConfig {
    pub protocol_version: String,
    pub window_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub max_fee_cap_units: u64,
    pub max_weight_per_window: u64,
    pub min_privacy_budget_units: u64,
    pub max_nullifiers_per_window: u64,
    pub pq_auth_scheme: String,
    pub commitment_scheme: String,
    pub proof_system: String,
}

impl Default for FastPrivateAdmissionControlConfig {
    fn default() -> Self {
        Self {
            protocol_version: FAST_PRIVATE_ADMISSION_CONTROL_PROTOCOL_VERSION.to_string(),
            window_blocks: FAST_PRIVATE_ADMISSION_CONTROL_DEFAULT_WINDOW_BLOCKS,
            ticket_ttl_blocks: FAST_PRIVATE_ADMISSION_CONTROL_DEFAULT_TICKET_TTL_BLOCKS,
            max_fee_cap_units: 50_000,
            max_weight_per_window: 2_500_000,
            min_privacy_budget_units: 10,
            max_nullifiers_per_window: 4_096,
            pq_auth_scheme: FAST_PRIVATE_ADMISSION_CONTROL_PQ_AUTH_SCHEME.to_string(),
            commitment_scheme: FAST_PRIVATE_ADMISSION_CONTROL_COMMITMENT_SCHEME.to_string(),
            proof_system: FAST_PRIVATE_ADMISSION_CONTROL_PROOF_SYSTEM.to_string(),
        }
    }
}

impl FastPrivateAdmissionControlConfig {
    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.protocol_version.trim().is_empty() {
            return Err("fast private admission protocol version cannot be empty".to_string());
        }
        if self.window_blocks == 0 || self.ticket_ttl_blocks == 0 {
            return Err("fast private admission windows must be positive".to_string());
        }
        if self.max_fee_cap_units == 0 || self.max_weight_per_window == 0 {
            return Err("fast private admission caps must be positive".to_string());
        }
        if self.min_privacy_budget_units == 0 || self.max_nullifiers_per_window == 0 {
            return Err("fast private admission privacy controls must be positive".to_string());
        }
        if self.pq_auth_scheme.trim().is_empty()
            || self.commitment_scheme.trim().is_empty()
            || self.proof_system.trim().is_empty()
        {
            return Err("fast private admission crypto labels cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_admission_config",
            "protocol_version": self.protocol_version,
            "window_blocks": self.window_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "max_fee_cap_units": self.max_fee_cap_units,
            "max_weight_per_window": self.max_weight_per_window,
            "min_privacy_budget_units": self.min_privacy_budget_units,
            "max_nullifiers_per_window": self.max_nullifiers_per_window,
            "pq_auth_scheme": self.pq_auth_scheme,
            "commitment_scheme": self.commitment_scheme,
            "proof_system": self.proof_system,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastAdmissionLane {
    pub lane_id: String,
    pub label: String,
    pub traffic_class: FastAdmissionTrafficClass,
    pub status: FastAdmissionLaneStatus,
    pub weight_limit: u64,
    pub fee_cap_units: u64,
    pub privacy_budget_floor_units: u64,
    pub sponsor_pool_root: String,
    pub policy_root: String,
    pub opened_at_height: u64,
}

impl FastAdmissionLane {
    pub fn new(
        label: &str,
        traffic_class: FastAdmissionTrafficClass,
        weight_limit: u64,
        fee_cap_units: u64,
        privacy_budget_floor_units: u64,
        sponsor_ids: &[String],
        opened_at_height: u64,
        policy: &Value,
    ) -> FastPrivateAdmissionControlResult<Self> {
        if label.trim().is_empty() {
            return Err("fast admission lane label cannot be empty".to_string());
        }
        if weight_limit == 0 || fee_cap_units == 0 || privacy_budget_floor_units == 0 {
            return Err("fast admission lane caps must be positive".to_string());
        }
        let sponsor_pool_root = fast_private_admission_string_set_root("LANE-SPONSOR", sponsor_ids);
        let policy_root = fast_private_admission_payload_root("LANE-POLICY", policy);
        let lane_id =
            fast_admission_lane_id(label, &traffic_class, &sponsor_pool_root, opened_at_height);
        let lane = Self {
            lane_id,
            label: label.to_string(),
            traffic_class,
            status: FastAdmissionLaneStatus::Active,
            weight_limit,
            fee_cap_units,
            privacy_budget_floor_units,
            sponsor_pool_root,
            policy_root,
            opened_at_height,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.lane_id.trim().is_empty() || self.label.trim().is_empty() {
            return Err("fast admission lane identifiers cannot be empty".to_string());
        }
        if self.weight_limit == 0 || self.fee_cap_units == 0 || self.privacy_budget_floor_units == 0
        {
            return Err("fast admission lane caps must be positive".to_string());
        }
        if self.sponsor_pool_root.trim().is_empty() || self.policy_root.trim().is_empty() {
            return Err("fast admission lane roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_admission_lane",
            "lane_id": self.lane_id,
            "label": self.label,
            "traffic_class": self.traffic_class.as_str(),
            "status": self.status.as_str(),
            "weight_limit": self.weight_limit,
            "fee_cap_units": self.fee_cap_units,
            "privacy_budget_floor_units": self.privacy_budget_floor_units,
            "sponsor_pool_root": self.sponsor_pool_root,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: FastAdmissionWindowStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub admitted_weight: u64,
    pub rejected_weight: u64,
    pub nullifier_root: String,
    pub ticket_root: String,
}

impl AdmissionWindow {
    pub fn new(
        lane_id: &str,
        start_height: u64,
        end_height: u64,
    ) -> FastPrivateAdmissionControlResult<Self> {
        if lane_id.trim().is_empty() {
            return Err("fast admission window lane id cannot be empty".to_string());
        }
        if start_height >= end_height {
            return Err("fast admission window end must be after start".to_string());
        }
        let window_id = admission_window_id(lane_id, start_height, end_height);
        let window = Self {
            window_id,
            lane_id: lane_id.to_string(),
            status: FastAdmissionWindowStatus::Open,
            start_height,
            end_height,
            admitted_weight: 0,
            rejected_weight: 0,
            nullifier_root: fast_private_admission_string_root("WINDOW-NULLIFIERS", "empty"),
            ticket_root: fast_private_admission_string_root("WINDOW-TICKETS", "empty"),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn set_roots(&mut self, nullifiers: &[String], ticket_ids: &[String]) {
        self.nullifier_root =
            fast_private_admission_string_set_root("WINDOW-NULLIFIERS", nullifiers);
        self.ticket_root = fast_private_admission_string_set_root("WINDOW-TICKETS", ticket_ids);
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.window_id.trim().is_empty() || self.lane_id.trim().is_empty() {
            return Err("fast admission window identifiers cannot be empty".to_string());
        }
        if self.start_height >= self.end_height {
            return Err("fast admission window end must be after start".to_string());
        }
        if self.nullifier_root.trim().is_empty() || self.ticket_root.trim().is_empty() {
            return Err("fast admission window roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_admission_window",
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "admitted_weight": self.admitted_weight,
            "rejected_weight": self.rejected_weight,
            "nullifier_root": self.nullifier_root,
            "ticket_root": self.ticket_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedAdmissionTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub owner_commitment: String,
    pub encrypted_payload_root: String,
    pub traffic_class: FastAdmissionTrafficClass,
    pub status: FastAdmissionTicketStatus,
    pub weight_units: u64,
    pub fee_cap_units: u64,
    pub privacy_budget_units: u64,
    pub rate_limit_nullifier: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedAdmissionTicket {
    pub fn new(
        lane_id: &str,
        window_id: &str,
        owner_label: &str,
        traffic_class: FastAdmissionTrafficClass,
        weight_units: u64,
        fee_cap_units: u64,
        privacy_budget_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        payload: &Value,
    ) -> FastPrivateAdmissionControlResult<Self> {
        if lane_id.trim().is_empty() || window_id.trim().is_empty() || owner_label.trim().is_empty()
        {
            return Err("fast admission ticket identifiers cannot be empty".to_string());
        }
        if weight_units == 0 || fee_cap_units == 0 || privacy_budget_units == 0 {
            return Err("fast admission ticket resource values must be positive".to_string());
        }
        if submitted_at_height >= expires_at_height {
            return Err("fast admission ticket expiry must be after submission".to_string());
        }
        let owner_commitment = fast_private_admission_string_root("TICKET-OWNER", owner_label);
        let encrypted_payload_root = fast_private_admission_payload_root("TICKET-PAYLOAD", payload);
        let rate_limit_nullifier = admission_rate_limit_nullifier(
            lane_id,
            window_id,
            &owner_commitment,
            submitted_at_height,
        );
        let ticket_id = encrypted_admission_ticket_id(
            lane_id,
            window_id,
            &owner_commitment,
            &rate_limit_nullifier,
        );
        let ticket = Self {
            ticket_id,
            lane_id: lane_id.to_string(),
            window_id: window_id.to_string(),
            owner_commitment,
            encrypted_payload_root,
            traffic_class,
            status: FastAdmissionTicketStatus::Pending,
            weight_units,
            fee_cap_units,
            privacy_budget_units,
            rate_limit_nullifier,
            submitted_at_height,
            expires_at_height,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.ticket_id.trim().is_empty()
            || self.lane_id.trim().is_empty()
            || self.window_id.trim().is_empty()
            || self.owner_commitment.trim().is_empty()
        {
            return Err("fast admission ticket identifiers cannot be empty".to_string());
        }
        if self.encrypted_payload_root.trim().is_empty()
            || self.rate_limit_nullifier.trim().is_empty()
        {
            return Err("fast admission ticket roots cannot be empty".to_string());
        }
        if self.weight_units == 0 || self.fee_cap_units == 0 || self.privacy_budget_units == 0 {
            return Err("fast admission ticket resource values must be positive".to_string());
        }
        if self.submitted_at_height >= self.expires_at_height {
            return Err("fast admission ticket expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_admission_ticket",
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "owner_commitment": self.owner_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "traffic_class": self.traffic_class.as_str(),
            "status": self.status.as_str(),
            "weight_units": self.weight_units,
            "fee_cap_units": self.fee_cap_units,
            "privacy_budget_units": self.privacy_budget_units,
            "rate_limit_nullifier": self.rate_limit_nullifier,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAdmissionAuthorization {
    pub authorization_id: String,
    pub ticket_id: String,
    pub signer_commitment: String,
    pub status: FastAdmissionAuthorizationStatus,
    pub signature_root: String,
    pub transcript_root: String,
    pub granted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAdmissionAuthorization {
    pub fn new(
        ticket_id: &str,
        signer_label: &str,
        granted_at_height: u64,
        expires_at_height: u64,
    ) -> FastPrivateAdmissionControlResult<Self> {
        if ticket_id.trim().is_empty() || signer_label.trim().is_empty() {
            return Err("fast admission authorization identifiers cannot be empty".to_string());
        }
        if granted_at_height >= expires_at_height {
            return Err("fast admission authorization expiry must be after grant".to_string());
        }
        let signer_commitment = fast_private_admission_string_root("AUTH-SIGNER", signer_label);
        let signature_root = fast_private_admission_payload_root(
            "AUTH-SIGNATURE",
            &json!({
                "scheme": FAST_PRIVATE_ADMISSION_CONTROL_PQ_AUTH_SCHEME,
                "ticket_id": ticket_id,
                "signer_commitment": signer_commitment,
            }),
        );
        let transcript_root = fast_private_admission_payload_root(
            "AUTH-TRANSCRIPT",
            &json!({
                "ticket_id": ticket_id,
                "signature_root": signature_root,
                "granted_at_height": granted_at_height,
            }),
        );
        let authorization_id =
            pq_admission_authorization_id(ticket_id, &signer_commitment, &signature_root);
        let authorization = Self {
            authorization_id,
            ticket_id: ticket_id.to_string(),
            signer_commitment,
            status: FastAdmissionAuthorizationStatus::Valid,
            signature_root,
            transcript_root,
            granted_at_height,
            expires_at_height,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.authorization_id.trim().is_empty()
            || self.ticket_id.trim().is_empty()
            || self.signer_commitment.trim().is_empty()
        {
            return Err("fast admission authorization identifiers cannot be empty".to_string());
        }
        if self.signature_root.trim().is_empty() || self.transcript_root.trim().is_empty() {
            return Err("fast admission authorization roots cannot be empty".to_string());
        }
        if self.granted_at_height >= self.expires_at_height {
            return Err("fast admission authorization expiry must be after grant".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_admission_authorization",
            "authorization_id": self.authorization_id,
            "ticket_id": self.ticket_id,
            "signer_commitment": self.signer_commitment,
            "status": self.status.as_str(),
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "granted_at_height": self.granted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionSponsorAccount {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: FastAdmissionSponsorStatus,
    pub available_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub lane_allowlist_root: String,
    pub policy_root: String,
}

impl AdmissionSponsorAccount {
    pub fn new(
        sponsor_label: &str,
        available_units: u64,
        lane_ids: &[String],
        policy: &Value,
    ) -> FastPrivateAdmissionControlResult<Self> {
        if sponsor_label.trim().is_empty() {
            return Err("fast admission sponsor label cannot be empty".to_string());
        }
        if available_units == 0 {
            return Err("fast admission sponsor budget must be positive".to_string());
        }
        let sponsor_commitment = fast_private_admission_string_root("SPONSOR", sponsor_label);
        let lane_allowlist_root = fast_private_admission_string_set_root("SPONSOR-LANE", lane_ids);
        let policy_root = fast_private_admission_payload_root("SPONSOR-POLICY", policy);
        let sponsor_id =
            admission_sponsor_account_id(&sponsor_commitment, &lane_allowlist_root, &policy_root);
        let sponsor = Self {
            sponsor_id,
            sponsor_commitment,
            status: FastAdmissionSponsorStatus::Active,
            available_units,
            reserved_units: 0,
            spent_units: 0,
            lane_allowlist_root,
            policy_root,
        };
        sponsor.validate()?;
        Ok(sponsor)
    }

    pub fn reserve(&mut self, units: u64) -> FastPrivateAdmissionControlResult<()> {
        if units == 0 {
            return Err("fast admission sponsor reserve must be positive".to_string());
        }
        if self.available_units < units {
            return Err("fast admission sponsor has insufficient budget".to_string());
        }
        self.available_units = self.available_units.saturating_sub(units);
        self.reserved_units = self.reserved_units.saturating_add(units);
        if self.available_units == 0 {
            self.status = FastAdmissionSponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn settle(&mut self, units: u64) -> FastPrivateAdmissionControlResult<()> {
        if units == 0 {
            return Err("fast admission sponsor settlement must be positive".to_string());
        }
        if self.reserved_units < units {
            return Err("fast admission sponsor settlement exceeds reserve".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.sponsor_id.trim().is_empty() || self.sponsor_commitment.trim().is_empty() {
            return Err("fast admission sponsor identifiers cannot be empty".to_string());
        }
        if self.lane_allowlist_root.trim().is_empty() || self.policy_root.trim().is_empty() {
            return Err("fast admission sponsor roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "admission_sponsor_account",
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "lane_allowlist_root": self.lane_allowlist_root,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionDecisionReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub decision: AdmissionDecisionKind,
    pub status: FastAdmissionReceiptStatus,
    pub fee_debit_root: String,
    pub privacy_budget_debit_root: String,
    pub admitted_weight: u64,
    pub posted_at_height: u64,
}

impl AdmissionDecisionReceipt {
    pub fn new(
        ticket: &EncryptedAdmissionTicket,
        decision: AdmissionDecisionKind,
        fee_debit_units: u64,
        privacy_budget_debit_units: u64,
        posted_at_height: u64,
    ) -> FastPrivateAdmissionControlResult<Self> {
        let fee_debit_root = fast_private_admission_amount_root("RECEIPT-FEE", fee_debit_units);
        let privacy_budget_debit_root = fast_private_admission_amount_root(
            "RECEIPT-PRIVACY-BUDGET",
            privacy_budget_debit_units,
        );
        let receipt_id = admission_decision_receipt_id(
            &ticket.ticket_id,
            decision.as_str(),
            &fee_debit_root,
            posted_at_height,
        );
        let receipt = Self {
            receipt_id,
            ticket_id: ticket.ticket_id.clone(),
            lane_id: ticket.lane_id.clone(),
            window_id: ticket.window_id.clone(),
            decision,
            status: FastAdmissionReceiptStatus::Posted,
            fee_debit_root,
            privacy_budget_debit_root,
            admitted_weight: ticket.weight_units,
            posted_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.ticket_id.trim().is_empty()
            || self.lane_id.trim().is_empty()
            || self.window_id.trim().is_empty()
        {
            return Err("fast admission receipt identifiers cannot be empty".to_string());
        }
        if self.fee_debit_root.trim().is_empty() || self.privacy_budget_debit_root.trim().is_empty()
        {
            return Err("fast admission receipt roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "admission_decision_receipt",
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
            "fee_debit_root": self.fee_debit_root,
            "privacy_budget_debit_root": self.privacy_budget_debit_root,
            "admitted_weight": self.admitted_weight,
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastAdmissionEvent {
    pub event_id: String,
    pub event_kind: FastAdmissionEventKind,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl FastAdmissionEvent {
    pub fn new(
        event_kind: FastAdmissionEventKind,
        subject_id: &str,
        height: u64,
        payload: &Value,
    ) -> FastPrivateAdmissionControlResult<Self> {
        if subject_id.trim().is_empty() {
            return Err("fast admission event subject cannot be empty".to_string());
        }
        let payload_root = fast_private_admission_payload_root("EVENT-PAYLOAD", payload);
        let event_id = fast_admission_event_id(&event_kind, subject_id, height, &payload_root);
        let event = Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            height,
            payload_root,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        if self.event_id.trim().is_empty()
            || self.subject_id.trim().is_empty()
            || self.payload_root.trim().is_empty()
        {
            return Err("fast admission event identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_admission_event",
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastPrivateAdmissionControlRoots {
    pub lane_root: String,
    pub window_root: String,
    pub ticket_root: String,
    pub authorization_root: String,
    pub sponsor_root: String,
    pub receipt_root: String,
    pub event_root: String,
}

impl FastPrivateAdmissionControlRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_admission_roots",
            "lane_root": self.lane_root,
            "window_root": self.window_root,
            "ticket_root": self.ticket_root,
            "authorization_root": self.authorization_root,
            "sponsor_root": self.sponsor_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastPrivateAdmissionControlCounters {
    pub lane_count: u64,
    pub open_window_count: u64,
    pub pending_ticket_count: u64,
    pub admitted_ticket_count: u64,
    pub valid_authorization_count: u64,
    pub active_sponsor_count: u64,
    pub receipt_count: u64,
    pub event_count: u64,
    pub available_sponsor_units: u64,
    pub admitted_weight: u64,
}

impl FastPrivateAdmissionControlCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_admission_counters",
            "lane_count": self.lane_count,
            "open_window_count": self.open_window_count,
            "pending_ticket_count": self.pending_ticket_count,
            "admitted_ticket_count": self.admitted_ticket_count,
            "valid_authorization_count": self.valid_authorization_count,
            "active_sponsor_count": self.active_sponsor_count,
            "receipt_count": self.receipt_count,
            "event_count": self.event_count,
            "available_sponsor_units": self.available_sponsor_units,
            "admitted_weight": self.admitted_weight,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastPrivateAdmissionControlState {
    pub config: FastPrivateAdmissionControlConfig,
    pub height: u64,
    pub active_window_id: Option<String>,
    pub lanes: BTreeMap<String, FastAdmissionLane>,
    pub windows: BTreeMap<String, AdmissionWindow>,
    pub tickets: BTreeMap<String, EncryptedAdmissionTicket>,
    pub authorizations: BTreeMap<String, PqAdmissionAuthorization>,
    pub sponsors: BTreeMap<String, AdmissionSponsorAccount>,
    pub receipts: BTreeMap<String, AdmissionDecisionReceipt>,
    pub events: BTreeMap<String, FastAdmissionEvent>,
}

impl Default for FastPrivateAdmissionControlState {
    fn default() -> Self {
        Self {
            config: FastPrivateAdmissionControlConfig::default(),
            height: 0,
            active_window_id: None,
            lanes: BTreeMap::new(),
            windows: BTreeMap::new(),
            tickets: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl FastPrivateAdmissionControlState {
    pub fn new(
        config: FastPrivateAdmissionControlConfig,
    ) -> FastPrivateAdmissionControlResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> FastPrivateAdmissionControlResult<Self> {
        let mut state = Self::new(FastPrivateAdmissionControlConfig::default())?;
        state.height = 1;

        let sponsor_seed = Vec::<String>::new();
        let lane = FastAdmissionLane::new(
            "devnet-private-swap-fast-lane",
            FastAdmissionTrafficClass::PrivateSwap,
            750_000,
            10_000,
            25,
            &sponsor_seed,
            state.height,
            &json!({"priority": "private-defi", "latency_target_ms": 500}),
        )?;
        let lane_id = lane.lane_id.clone();
        state.insert_lane(lane)?;

        let sponsor = AdmissionSponsorAccount::new(
            "devnet-fast-admission-sponsor",
            1_000_000,
            &[lane_id.clone()],
            &json!({"max_fee_cap_units": 10_000, "mode": "devnet"}),
        )?;
        state.insert_sponsor(sponsor)?;

        let window = AdmissionWindow::new(
            &lane_id,
            state.height,
            state.height.saturating_add(state.config.window_blocks),
        )?;
        let window_id = window.window_id.clone();
        state.active_window_id = Some(window_id.clone());
        state.insert_window(window)?;

        let ticket = EncryptedAdmissionTicket::new(
            &lane_id,
            &window_id,
            "devnet-private-swapper",
            FastAdmissionTrafficClass::PrivateSwap,
            25_000,
            8_000,
            30,
            state.height,
            state.height.saturating_add(state.config.ticket_ttl_blocks),
            &json!({"intent": "swap", "visibility": "encrypted"}),
        )?;
        let ticket_id = ticket.ticket_id.clone();
        state.insert_ticket(ticket)?;

        let authorization = PqAdmissionAuthorization::new(
            &ticket_id,
            "devnet-fast-admission-signer",
            state.height,
            state.height.saturating_add(state.config.ticket_ttl_blocks),
        )?;
        state.insert_authorization(authorization)?;
        let decision = state.evaluate_ticket(&ticket_id)?;
        state.apply_decision(&ticket_id, decision)?;

        state.insert_event(FastAdmissionEvent::new(
            FastAdmissionEventKind::LaneOpened,
            &lane_id,
            state.height,
            &json!({"source": "devnet"}),
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> FastPrivateAdmissionControlResult<()> {
        self.height = height;
        self.expire_records();
        Ok(())
    }

    pub fn insert_lane(
        &mut self,
        lane: FastAdmissionLane,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.lanes.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_LANES
            && !self.lanes.contains_key(&lane.lane_id)
        {
            return Err("fast admission lane limit exceeded".to_string());
        }
        lane.validate()?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_window(
        &mut self,
        window: AdmissionWindow,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.windows.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_WINDOWS
            && !self.windows.contains_key(&window.window_id)
        {
            return Err("fast admission window limit exceeded".to_string());
        }
        if !self.lanes.contains_key(&window.lane_id) {
            return Err("fast admission window references unknown lane".to_string());
        }
        window.validate()?;
        self.windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn insert_ticket(
        &mut self,
        ticket: EncryptedAdmissionTicket,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.tickets.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_TICKETS
            && !self.tickets.contains_key(&ticket.ticket_id)
        {
            return Err("fast admission ticket limit exceeded".to_string());
        }
        if !self.lanes.contains_key(&ticket.lane_id) {
            return Err("fast admission ticket references unknown lane".to_string());
        }
        if !self.windows.contains_key(&ticket.window_id) {
            return Err("fast admission ticket references unknown window".to_string());
        }
        let duplicate = self
            .tickets
            .values()
            .any(|existing| existing.rate_limit_nullifier == ticket.rate_limit_nullifier);
        if duplicate {
            return Err("fast admission ticket nullifier already used".to_string());
        }
        ticket.validate()?;
        self.tickets.insert(ticket.ticket_id.clone(), ticket);
        self.refresh_window_roots();
        Ok(())
    }

    pub fn insert_authorization(
        &mut self,
        authorization: PqAdmissionAuthorization,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.authorizations.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_AUTHORIZATIONS
            && !self
                .authorizations
                .contains_key(&authorization.authorization_id)
        {
            return Err("fast admission authorization limit exceeded".to_string());
        }
        if !self.tickets.contains_key(&authorization.ticket_id) {
            return Err("fast admission authorization references unknown ticket".to_string());
        }
        authorization.validate()?;
        self.authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: AdmissionSponsorAccount,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.sponsors.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_SPONSORS
            && !self.sponsors.contains_key(&sponsor.sponsor_id)
        {
            return Err("fast admission sponsor limit exceeded".to_string());
        }
        sponsor.validate()?;
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: AdmissionDecisionReceipt,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.receipts.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_RECEIPTS
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("fast admission receipt limit exceeded".to_string());
        }
        if !self.tickets.contains_key(&receipt.ticket_id) {
            return Err("fast admission receipt references unknown ticket".to_string());
        }
        receipt.validate()?;
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_event(
        &mut self,
        event: FastAdmissionEvent,
    ) -> FastPrivateAdmissionControlResult<()> {
        if self.events.len() >= FAST_PRIVATE_ADMISSION_CONTROL_MAX_EVENTS
            && !self.events.contains_key(&event.event_id)
        {
            return Err("fast admission event limit exceeded".to_string());
        }
        event.validate()?;
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn evaluate_ticket(
        &self,
        ticket_id: &str,
    ) -> FastPrivateAdmissionControlResult<AdmissionDecisionKind> {
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| "fast admission ticket not found".to_string())?;
        let lane = self
            .lanes
            .get(&ticket.lane_id)
            .ok_or_else(|| "fast admission lane not found".to_string())?;
        let window = self
            .windows
            .get(&ticket.window_id)
            .ok_or_else(|| "fast admission window not found".to_string())?;
        if !lane.status.admits() || window.status != FastAdmissionWindowStatus::Open {
            return Ok(AdmissionDecisionKind::Defer);
        }
        if ticket.fee_cap_units > lane.fee_cap_units
            || ticket.fee_cap_units > self.config.max_fee_cap_units
        {
            return Ok(AdmissionDecisionKind::Reject);
        }
        if ticket.privacy_budget_units < lane.privacy_budget_floor_units
            || ticket.privacy_budget_units < self.config.min_privacy_budget_units
        {
            return Ok(AdmissionDecisionKind::RequirePrivacyBudget);
        }
        if window.admitted_weight.saturating_add(ticket.weight_units) > lane.weight_limit
            || window.admitted_weight.saturating_add(ticket.weight_units)
                > self.config.max_weight_per_window
        {
            return Ok(AdmissionDecisionKind::Defer);
        }
        let valid_auth = self.authorizations.values().any(|authorization| {
            authorization.ticket_id == ticket.ticket_id
                && authorization.status == FastAdmissionAuthorizationStatus::Valid
                && authorization.expires_at_height > self.height
        });
        if !valid_auth {
            return Ok(AdmissionDecisionKind::AdmitNormal);
        }
        if self.available_sponsor_units() < ticket.fee_cap_units {
            return Ok(AdmissionDecisionKind::RequireSponsorTopUp);
        }
        Ok(AdmissionDecisionKind::AdmitFast)
    }

    pub fn apply_decision(
        &mut self,
        ticket_id: &str,
        decision: AdmissionDecisionKind,
    ) -> FastPrivateAdmissionControlResult<()> {
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| "fast admission ticket missing for decision".to_string())?
            .clone();
        if let Some(ticket_mut) = self.tickets.get_mut(ticket_id) {
            ticket_mut.status = match decision {
                AdmissionDecisionKind::AdmitFast | AdmissionDecisionKind::AdmitNormal => {
                    FastAdmissionTicketStatus::Admitted
                }
                AdmissionDecisionKind::Reject => FastAdmissionTicketStatus::Rejected,
                AdmissionDecisionKind::Defer
                | AdmissionDecisionKind::RequireSponsorTopUp
                | AdmissionDecisionKind::RequirePrivacyBudget => FastAdmissionTicketStatus::Pending,
            };
        }
        if matches!(
            decision,
            AdmissionDecisionKind::AdmitFast | AdmissionDecisionKind::AdmitNormal
        ) {
            if let Some(window) = self.windows.get_mut(&ticket.window_id) {
                window.admitted_weight = window.admitted_weight.saturating_add(ticket.weight_units);
            }
            self.debit_first_sponsor(ticket.fee_cap_units)?;
        } else if let Some(window) = self.windows.get_mut(&ticket.window_id) {
            window.rejected_weight = window.rejected_weight.saturating_add(ticket.weight_units);
        }
        let receipt = AdmissionDecisionReceipt::new(
            &ticket,
            decision.clone(),
            ticket.fee_cap_units,
            ticket.privacy_budget_units,
            self.height,
        )?;
        self.insert_receipt(receipt)?;
        self.insert_event(FastAdmissionEvent::new(
            match decision {
                AdmissionDecisionKind::AdmitFast | AdmissionDecisionKind::AdmitNormal => {
                    FastAdmissionEventKind::TicketAdmitted
                }
                AdmissionDecisionKind::Reject => FastAdmissionEventKind::TicketRejected,
                _ => FastAdmissionEventKind::TicketSubmitted,
            },
            ticket_id,
            self.height,
            &json!({"decision": decision.as_str()}),
        )?)?;
        self.refresh_window_roots();
        Ok(())
    }

    pub fn open_window_ids(&self) -> Vec<String> {
        self.windows
            .values()
            .filter(|window| window.status == FastAdmissionWindowStatus::Open)
            .map(|window| window.window_id.clone())
            .collect()
    }

    pub fn pending_ticket_ids(&self) -> Vec<String> {
        self.tickets
            .values()
            .filter(|ticket| {
                matches!(
                    ticket.status,
                    FastAdmissionTicketStatus::Pending | FastAdmissionTicketStatus::Authorized
                )
            })
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn available_sponsor_units(&self) -> u64 {
        self.sponsors
            .values()
            .filter(|sponsor| sponsor.status == FastAdmissionSponsorStatus::Active)
            .map(|sponsor| sponsor.available_units)
            .fold(0u64, u64::saturating_add)
    }

    pub fn roots(&self) -> FastPrivateAdmissionControlRoots {
        FastPrivateAdmissionControlRoots {
            lane_root: fast_admission_record_root(
                "LANES",
                &self
                    .lanes
                    .values()
                    .map(FastAdmissionLane::public_record)
                    .collect::<Vec<_>>(),
            ),
            window_root: fast_admission_record_root(
                "WINDOWS",
                &self
                    .windows
                    .values()
                    .map(AdmissionWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            ticket_root: fast_admission_record_root(
                "TICKETS",
                &self
                    .tickets
                    .values()
                    .map(EncryptedAdmissionTicket::public_record)
                    .collect::<Vec<_>>(),
            ),
            authorization_root: fast_admission_record_root(
                "AUTHORIZATIONS",
                &self
                    .authorizations
                    .values()
                    .map(PqAdmissionAuthorization::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_root: fast_admission_record_root(
                "SPONSORS",
                &self
                    .sponsors
                    .values()
                    .map(AdmissionSponsorAccount::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: fast_admission_record_root(
                "RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(AdmissionDecisionReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_root: fast_admission_record_root(
                "EVENTS",
                &self
                    .events
                    .values()
                    .map(FastAdmissionEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> FastPrivateAdmissionControlCounters {
        FastPrivateAdmissionControlCounters {
            lane_count: self.lanes.len() as u64,
            open_window_count: self.open_window_ids().len() as u64,
            pending_ticket_count: self.pending_ticket_ids().len() as u64,
            admitted_ticket_count: self
                .tickets
                .values()
                .filter(|ticket| ticket.status == FastAdmissionTicketStatus::Admitted)
                .count() as u64,
            valid_authorization_count: self
                .authorizations
                .values()
                .filter(|authorization| {
                    authorization.status == FastAdmissionAuthorizationStatus::Valid
                })
                .count() as u64,
            active_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status == FastAdmissionSponsorStatus::Active)
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            event_count: self.events.len() as u64,
            available_sponsor_units: self.available_sponsor_units(),
            admitted_weight: self
                .windows
                .values()
                .map(|window| window.admitted_weight)
                .fold(0u64, u64::saturating_add),
        }
    }

    pub fn validate(&self) -> FastPrivateAdmissionControlResult<()> {
        self.config.validate()?;
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for window in self.windows.values() {
            window.validate()?;
            if !self.lanes.contains_key(&window.lane_id) {
                return Err("fast admission window references missing lane".to_string());
            }
        }
        let mut nullifiers = BTreeSet::new();
        for ticket in self.tickets.values() {
            ticket.validate()?;
            if !self.lanes.contains_key(&ticket.lane_id) {
                return Err("fast admission ticket references missing lane".to_string());
            }
            if !self.windows.contains_key(&ticket.window_id) {
                return Err("fast admission ticket references missing window".to_string());
            }
            if !nullifiers.insert(ticket.rate_limit_nullifier.clone()) {
                return Err("fast admission duplicate rate-limit nullifier".to_string());
            }
        }
        for authorization in self.authorizations.values() {
            authorization.validate()?;
            if !self.tickets.contains_key(&authorization.ticket_id) {
                return Err("fast admission authorization references missing ticket".to_string());
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.tickets.contains_key(&receipt.ticket_id) {
                return Err("fast admission receipt references missing ticket".to_string());
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "fast_private_admission_control_state",
            "config": self.config.public_record(),
            "height": self.height,
            "active_window_id": self.active_window_id,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "open_window_ids": self.open_window_ids(),
            "pending_ticket_ids": self.pending_ticket_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        fast_private_admission_state_root_from_record(&self.public_record())
    }

    fn debit_first_sponsor(&mut self, units: u64) -> FastPrivateAdmissionControlResult<()> {
        if units == 0 {
            return Ok(());
        }
        let sponsor_id = self
            .sponsors
            .values()
            .find(|sponsor| {
                sponsor.status == FastAdmissionSponsorStatus::Active
                    && sponsor.available_units >= units
            })
            .map(|sponsor| sponsor.sponsor_id.clone())
            .ok_or_else(|| "fast admission sponsor budget unavailable".to_string())?;
        let sponsor = self
            .sponsors
            .get_mut(&sponsor_id)
            .ok_or_else(|| "fast admission sponsor missing after selection".to_string())?;
        sponsor.reserve(units)?;
        sponsor.settle(units)?;
        Ok(())
    }

    fn refresh_window_roots(&mut self) {
        let window_ids = self.windows.keys().cloned().collect::<Vec<_>>();
        for window_id in window_ids {
            let nullifiers = self
                .tickets
                .values()
                .filter(|ticket| ticket.window_id == window_id)
                .map(|ticket| ticket.rate_limit_nullifier.clone())
                .collect::<Vec<_>>();
            let ticket_ids = self
                .tickets
                .values()
                .filter(|ticket| ticket.window_id == window_id)
                .map(|ticket| ticket.ticket_id.clone())
                .collect::<Vec<_>>();
            if let Some(window) = self.windows.get_mut(&window_id) {
                window.set_roots(&nullifiers, &ticket_ids);
            }
        }
    }

    fn expire_records(&mut self) {
        for ticket in self.tickets.values_mut() {
            if self.height >= ticket.expires_at_height
                && matches!(
                    ticket.status,
                    FastAdmissionTicketStatus::Pending | FastAdmissionTicketStatus::Authorized
                )
            {
                ticket.status = FastAdmissionTicketStatus::Expired;
            }
        }
        for authorization in self.authorizations.values_mut() {
            if self.height >= authorization.expires_at_height
                && authorization.status == FastAdmissionAuthorizationStatus::Valid
            {
                authorization.status = FastAdmissionAuthorizationStatus::Expired;
            }
        }
        for window in self.windows.values_mut() {
            if self.height >= window.end_height && window.status == FastAdmissionWindowStatus::Open
            {
                window.status = FastAdmissionWindowStatus::Sealed;
            }
        }
    }
}

pub fn fast_private_admission_state_root_from_record(record: &Value) -> String {
    fast_private_admission_payload_root("STATE", record)
}

pub fn fast_private_admission_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("FAST-PRIVATE-ADMISSION-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn fast_private_admission_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("FAST-PRIVATE-ADMISSION-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

pub fn fast_private_admission_string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    domain_hash(
        &format!("FAST-PRIVATE-ADMISSION-{domain}"),
        &sorted
            .iter()
            .map(|value| HashPart::Str(value))
            .collect::<Vec<_>>(),
        32,
    )
}

pub fn fast_private_admission_amount_root(domain: &str, units: u64) -> String {
    domain_hash(
        &format!("FAST-PRIVATE-ADMISSION-{domain}"),
        &[HashPart::Int(units as i128)],
        32,
    )
}

pub fn fast_admission_lane_id(
    label: &str,
    traffic_class: &FastAdmissionTrafficClass,
    sponsor_pool_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-LANE-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(traffic_class.as_str()),
            HashPart::Str(sponsor_pool_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn admission_window_id(lane_id: &str, start_height: u64, end_height: u64) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-WINDOW-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn admission_rate_limit_nullifier(
    lane_id: &str,
    window_id: &str,
    owner_commitment: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-RATE-LIMIT-NULLIFIER",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(window_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn encrypted_admission_ticket_id(
    lane_id: &str,
    window_id: &str,
    owner_commitment: &str,
    rate_limit_nullifier: &str,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-TICKET-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(window_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(rate_limit_nullifier),
        ],
        32,
    )
}

pub fn pq_admission_authorization_id(
    ticket_id: &str,
    signer_commitment: &str,
    signature_root: &str,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-AUTHORIZATION-ID",
        &[
            HashPart::Str(ticket_id),
            HashPart::Str(signer_commitment),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

pub fn admission_sponsor_account_id(
    sponsor_commitment: &str,
    lane_allowlist_root: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-SPONSOR-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_allowlist_root),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn admission_decision_receipt_id(
    ticket_id: &str,
    decision: &str,
    fee_debit_root: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-RECEIPT-ID",
        &[
            HashPart::Str(ticket_id),
            HashPart::Str(decision),
            HashPart::Str(fee_debit_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn fast_admission_event_id(
    event_kind: &FastAdmissionEventKind,
    subject_id: &str,
    height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "FAST-PRIVATE-ADMISSION-EVENT-ID",
        &[
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn fast_admission_record_root(domain: &str, records: &[Value]) -> String {
    let mut roots = records
        .iter()
        .map(|record| fast_private_admission_payload_root("RECORD", record))
        .collect::<Vec<_>>();
    roots.sort();
    fast_private_admission_string_set_root(domain, &roots)
}
