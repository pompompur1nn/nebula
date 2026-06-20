use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialAccountRecoverySessionGuardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_RECOVERY_SESSION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-account-recovery-session-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_RECOVERY_SESSION_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-account-recovery-session-guard-v1";
pub const RECOVERY_POLICY_SCHEME: &str = "pq-confidential-account-recovery-policy-root-v1";
pub const SEALED_RECOVERY_SCHEME: &str = "ml-kem-sealed-private-account-recovery-request-root-v1";
pub const GUARDIAN_APPROVAL_SCHEME: &str = "pq-guardian-approval-quorum-root-v1";
pub const SESSION_GRANT_SCHEME: &str = "confidential-recovery-session-grant-root-v1";
pub const PAYMASTER_RESERVATION_SCHEME: &str = "low-fee-recovery-paymaster-reservation-root-v1";
pub const RECOVERY_RECEIPT_SCHEME: &str = "private-account-recovery-settlement-receipt-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "account-recovery-session-nullifier-fence-root-v1";
pub const CHALLENGE_SCHEME: &str = "account-recovery-session-guard-challenge-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_GUARDIAN_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_APPROVAL_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_POLICIES: usize = 1_048_576;
pub const DEFAULT_MAX_REQUESTS: usize = 2_097_152;
pub const DEFAULT_MAX_APPROVALS: usize = 4_194_304;
pub const DEFAULT_MAX_SESSIONS: usize = 2_097_152;
pub const DEFAULT_MAX_PAYMASTER_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryScope {
    SessionKey,
    SpendingKey,
    ContractWallet,
    GuardianSet,
    ViewKey,
    PaymasterPolicy,
}

impl RecoveryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionKey => "session_key",
            Self::SpendingKey => "spending_key",
            Self::ContractWallet => "contract_wallet",
            Self::GuardianSet => "guardian_set",
            Self::ViewKey => "view_key",
            Self::PaymasterPolicy => "paymaster_policy",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::SpendingKey => 1_000,
            Self::ContractWallet => 920,
            Self::GuardianSet => 850,
            Self::PaymasterPolicy => 760,
            Self::SessionKey => 640,
            Self::ViewKey => 540,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Submitted,
    Approved,
    SessionGranted,
    Sponsored,
    Settled,
    Cancelled,
    Challenged,
    Expired,
}

impl RecoveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::SessionGranted => "session_granted",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Submitted,
    Counted,
    Replaced,
    Slashed,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Replaced => "replaced",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Granted,
    Used,
    Revoked,
    Expired,
    Challenged,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Used => "used",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidGuardian,
    InsufficientQuorum,
    ReplayNullifier,
    SessionOverreach,
    FeeOvercharge,
    PrivacyLeak,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidGuardian => "invalid_guardian",
            Self::InsufficientQuorum => "insufficient_quorum",
            Self::ReplayNullifier => "replay_nullifier",
            Self::SessionOverreach => "session_overreach",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
        }
    }

    pub fn slash_bps(self) -> u64 {
        match self {
            Self::PrivacyLeak | Self::ReplayNullifier => 10_000,
            Self::InvalidGuardian | Self::SessionOverreach => 8_000,
            Self::InsufficientQuorum => 6_000,
            Self::FeeOvercharge => 3_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub guardian_quorum_bps: u64,
    pub recovery_ttl_blocks: u64,
    pub approval_ttl_blocks: u64,
    pub session_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_policies: usize,
    pub max_requests: usize,
    pub max_approvals: usize,
    pub max_sessions: usize,
    pub max_paymaster_reservations: usize,
    pub max_receipts: usize,
    pub max_privacy_fences: usize,
    pub max_challenges: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            guardian_quorum_bps: DEFAULT_GUARDIAN_QUORUM_BPS,
            recovery_ttl_blocks: DEFAULT_RECOVERY_TTL_BLOCKS,
            approval_ttl_blocks: DEFAULT_APPROVAL_TTL_BLOCKS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_policies: DEFAULT_MAX_POLICIES,
            max_requests: DEFAULT_MAX_REQUESTS,
            max_approvals: DEFAULT_MAX_APPROVALS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_paymaster_reservations: DEFAULT_MAX_PAYMASTER_RESERVATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_privacy_set_size < 16_384 {
            return Err("min_privacy_set_size below recovery privacy floor".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below PQ floor".to_string());
        }
        if self.max_user_fee_bps > 100 {
            return Err("max_user_fee_bps exceeds low-fee envelope".to_string());
        }
        if self.rebate_bps > self.max_user_fee_bps {
            return Err("rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.guardian_quorum_bps > MAX_BPS {
            return Err("guardian_quorum_bps cannot exceed MAX_BPS".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_account_recovery_session_guard_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "guardian_quorum_bps": self.guardian_quorum_bps,
            "recovery_ttl_blocks": self.recovery_ttl_blocks,
            "approval_ttl_blocks": self.approval_ttl_blocks,
            "session_ttl_blocks": self.session_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub next_policy: u64,
    pub next_request: u64,
    pub next_approval: u64,
    pub next_session: u64,
    pub next_paymaster_reservation: u64,
    pub next_receipt: u64,
    pub next_privacy_fence: u64,
    pub next_challenge: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_account_recovery_session_guard_counters",
            "policy_count": self.next_policy,
            "request_count": self.next_request,
            "approval_count": self.next_approval,
            "session_count": self.next_session,
            "paymaster_reservation_count": self.next_paymaster_reservation,
            "receipt_count": self.next_receipt,
            "privacy_fence_count": self.next_privacy_fence,
            "challenge_count": self.next_challenge,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub policy_root: String,
    pub request_root: String,
    pub approval_root: String,
    pub session_root: String,
    pub paymaster_root: String,
    pub receipt_root: String,
    pub privacy_fence_root: String,
    pub challenge_root: String,
    pub spent_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_account_recovery_session_guard_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "policy_root": self.policy_root,
            "request_root": self.request_root,
            "approval_root": self.approval_root,
            "session_root": self.session_root,
            "paymaster_root": self.paymaster_root,
            "receipt_root": self.receipt_root,
            "privacy_fence_root": self.privacy_fence_root,
            "challenge_root": self.challenge_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryPolicyRequest {
    pub account_commitment: String,
    pub guardian_set_root: String,
    pub scope: RecoveryScope,
    pub threshold_weight_bps: u64,
    pub policy_nonce_root: String,
    pub metadata_root: String,
    pub opened_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryPolicy {
    pub policy_id: String,
    pub account_commitment: String,
    pub guardian_set_root: String,
    pub scope: RecoveryScope,
    pub threshold_weight_bps: u64,
    pub policy_nonce_root: String,
    pub metadata_root: String,
    pub opened_height: u64,
}

impl RecoveryPolicy {
    pub fn from_request(config: &Config, request: RecoveryPolicyRequest) -> Result<Self> {
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("guardian_set_root", &request.guardian_set_root)?;
        ensure_nonempty("policy_nonce_root", &request.policy_nonce_root)?;
        if request.threshold_weight_bps < config.guardian_quorum_bps {
            return Err("policy threshold below configured guardian quorum".to_string());
        }
        let policy_id = recovery_policy_id(&request);
        Ok(Self {
            policy_id,
            account_commitment: request.account_commitment,
            guardian_set_root: request.guardian_set_root,
            scope: request.scope,
            threshold_weight_bps: request.threshold_weight_bps,
            policy_nonce_root: request.policy_nonce_root,
            metadata_root: request.metadata_root,
            opened_height: request.opened_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_account_recovery_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "account_commitment": self.account_commitment,
            "guardian_set_root": self.guardian_set_root,
            "scope": self.scope.as_str(),
            "threshold_weight_bps": self.threshold_weight_bps,
            "policy_nonce_root": self.policy_nonce_root,
            "metadata_root": self.metadata_root,
            "opened_height": self.opened_height,
            "scheme": RECOVERY_POLICY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedRecoveryRequestInput {
    pub policy_id: String,
    pub requester_commitment: String,
    pub encrypted_recovery_payload_root: String,
    pub target_key_commitment: String,
    pub recovery_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedRecoveryRequest {
    pub request_id: String,
    pub policy_id: String,
    pub requester_commitment: String,
    pub encrypted_recovery_payload_root: String,
    pub target_key_commitment: String,
    pub recovery_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: RecoveryStatus,
    pub priority_score: u64,
}

impl SealedRecoveryRequest {
    pub fn from_request(config: &Config, request: SealedRecoveryRequestInput) -> Result<Self> {
        ensure_nonempty("policy_id", &request.policy_id)?;
        ensure_nonempty("requester_commitment", &request.requester_commitment)?;
        ensure_nonempty(
            "encrypted_recovery_payload_root",
            &request.encrypted_recovery_payload_root,
        )?;
        ensure_nonempty("target_key_commitment", &request.target_key_commitment)?;
        ensure_nonempty("recovery_nullifier", &request.recovery_nullifier)?;
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err("recovery request privacy set below configured minimum".to_string());
        }
        let request_id = recovery_request_id(&request);
        Ok(Self {
            request_id,
            policy_id: request.policy_id,
            requester_commitment: request.requester_commitment,
            encrypted_recovery_payload_root: request.encrypted_recovery_payload_root,
            target_key_commitment: request.target_key_commitment,
            recovery_nullifier: request.recovery_nullifier,
            privacy_set_size: request.privacy_set_size,
            max_fee_micro_units: request.max_fee_micro_units,
            submitted_height: request.submitted_height,
            expires_height: request
                .submitted_height
                .saturating_add(config.recovery_ttl_blocks),
            status: RecoveryStatus::Submitted,
            priority_score: request
                .privacy_set_size
                .min(1_048_576)
                .saturating_div(1_024)
                .saturating_add(request.max_fee_micro_units.min(10_000_000) / 10_000),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_pq_confidential_recovery_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "requester_commitment": self.requester_commitment,
            "encrypted_recovery_payload_root": self.encrypted_recovery_payload_root,
            "target_key_commitment": self.target_key_commitment,
            "recovery_nullifier": self.recovery_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_micro_units": self.max_fee_micro_units,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
            "scheme": SEALED_RECOVERY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardianApprovalRequest {
    pub request_id: String,
    pub guardian_commitment: String,
    pub approval_weight_bps: u64,
    pub pq_signature_root: String,
    pub guardian_evidence_root: String,
    pub approved_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardianApproval {
    pub approval_id: String,
    pub request_id: String,
    pub guardian_commitment: String,
    pub approval_weight_bps: u64,
    pub pq_signature_root: String,
    pub guardian_evidence_root: String,
    pub approved_height: u64,
    pub expires_height: u64,
    pub status: ApprovalStatus,
}

impl GuardianApproval {
    pub fn from_request(config: &Config, request: GuardianApprovalRequest) -> Result<Self> {
        ensure_nonempty("request_id", &request.request_id)?;
        ensure_nonempty("guardian_commitment", &request.guardian_commitment)?;
        ensure_nonempty("pq_signature_root", &request.pq_signature_root)?;
        ensure_nonempty("guardian_evidence_root", &request.guardian_evidence_root)?;
        let approval_id = guardian_approval_id(&request);
        Ok(Self {
            approval_id,
            request_id: request.request_id,
            guardian_commitment: request.guardian_commitment,
            approval_weight_bps: request.approval_weight_bps,
            pq_signature_root: request.pq_signature_root,
            guardian_evidence_root: request.guardian_evidence_root,
            approved_height: request.approved_height,
            expires_height: request
                .approved_height
                .saturating_add(config.approval_ttl_blocks),
            status: ApprovalStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_guardian_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "guardian_commitment": self.guardian_commitment,
            "approval_weight_bps": self.approval_weight_bps,
            "pq_signature_root": self.pq_signature_root,
            "guardian_evidence_root": self.guardian_evidence_root,
            "approved_height": self.approved_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "scheme": GUARDIAN_APPROVAL_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoverySessionGrantRequest {
    pub request_id: String,
    pub policy_id: String,
    pub session_key_commitment: String,
    pub allowed_call_root: String,
    pub guardian_quorum_root: String,
    pub granted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoverySessionGrant {
    pub session_id: String,
    pub request_id: String,
    pub policy_id: String,
    pub session_key_commitment: String,
    pub allowed_call_root: String,
    pub guardian_quorum_root: String,
    pub granted_height: u64,
    pub expires_height: u64,
    pub status: SessionStatus,
}

impl RecoverySessionGrant {
    pub fn from_request(config: &Config, request: RecoverySessionGrantRequest) -> Result<Self> {
        ensure_nonempty("request_id", &request.request_id)?;
        ensure_nonempty("policy_id", &request.policy_id)?;
        ensure_nonempty("session_key_commitment", &request.session_key_commitment)?;
        ensure_nonempty("allowed_call_root", &request.allowed_call_root)?;
        ensure_nonempty("guardian_quorum_root", &request.guardian_quorum_root)?;
        let session_id = session_grant_id(&request);
        Ok(Self {
            session_id,
            request_id: request.request_id,
            policy_id: request.policy_id,
            session_key_commitment: request.session_key_commitment,
            allowed_call_root: request.allowed_call_root,
            guardian_quorum_root: request.guardian_quorum_root,
            granted_height: request.granted_height,
            expires_height: request
                .granted_height
                .saturating_add(config.session_ttl_blocks),
            status: SessionStatus::Granted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_recovery_session_grant",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "session_key_commitment": self.session_key_commitment,
            "allowed_call_root": self.allowed_call_root,
            "guardian_quorum_root": self.guardian_quorum_root,
            "granted_height": self.granted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "scheme": SESSION_GRANT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PaymasterReservationRequest {
    pub request_id: String,
    pub paymaster_id: String,
    pub beneficiary_commitment: String,
    pub max_fee_micro_units: u64,
    pub rebate_nullifier: String,
    pub policy_root: String,
    pub reserved_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PaymasterReservation {
    pub reservation_id: String,
    pub request_id: String,
    pub paymaster_id: String,
    pub beneficiary_commitment: String,
    pub max_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_nullifier: String,
    pub policy_root: String,
    pub reserved_height: u64,
}

impl PaymasterReservation {
    pub fn from_request(config: &Config, request: PaymasterReservationRequest) -> Result<Self> {
        ensure_nonempty("request_id", &request.request_id)?;
        ensure_nonempty("paymaster_id", &request.paymaster_id)?;
        ensure_nonempty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_nonempty("rebate_nullifier", &request.rebate_nullifier)?;
        ensure_nonempty("policy_root", &request.policy_root)?;
        let rebate_micro_units = request
            .max_fee_micro_units
            .saturating_mul(config.rebate_bps)
            / MAX_BPS;
        let reservation_id = paymaster_reservation_id(&request, rebate_micro_units);
        Ok(Self {
            reservation_id,
            request_id: request.request_id,
            paymaster_id: request.paymaster_id,
            beneficiary_commitment: request.beneficiary_commitment,
            max_fee_micro_units: request.max_fee_micro_units,
            rebate_micro_units,
            rebate_nullifier: request.rebate_nullifier,
            policy_root: request.policy_root,
            reserved_height: request.reserved_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_recovery_paymaster_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "request_id": self.request_id,
            "paymaster_id": self.paymaster_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_nullifier": self.rebate_nullifier,
            "policy_root": self.policy_root,
            "reserved_height": self.reserved_height,
            "scheme": PAYMASTER_RESERVATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryReceiptRequest {
    pub request_id: String,
    pub session_id: String,
    pub executor_id: String,
    pub new_account_state_root: String,
    pub encrypted_receipt_root: String,
    pub fee_paid_micro_units: u64,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub session_id: String,
    pub executor_id: String,
    pub new_account_state_root: String,
    pub encrypted_receipt_root: String,
    pub fee_paid_micro_units: u64,
    pub settled_height: u64,
    pub finality_height: u64,
}

impl RecoveryReceipt {
    pub fn from_request(config: &Config, request: RecoveryReceiptRequest) -> Result<Self> {
        ensure_nonempty("request_id", &request.request_id)?;
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("executor_id", &request.executor_id)?;
        ensure_nonempty("new_account_state_root", &request.new_account_state_root)?;
        ensure_nonempty("encrypted_receipt_root", &request.encrypted_receipt_root)?;
        let receipt_id = recovery_receipt_id(&request);
        Ok(Self {
            receipt_id,
            request_id: request.request_id,
            session_id: request.session_id,
            executor_id: request.executor_id,
            new_account_state_root: request.new_account_state_root,
            encrypted_receipt_root: request.encrypted_receipt_root,
            fee_paid_micro_units: request.fee_paid_micro_units,
            settled_height: request.settled_height,
            finality_height: request
                .settled_height
                .saturating_add(config.receipt_finality_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_account_recovery_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "executor_id": self.executor_id,
            "new_account_state_root": self.new_account_state_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "settled_height": self.settled_height,
            "finality_height": self.finality_height,
            "scheme": RECOVERY_RECEIPT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRequest {
    pub subject_id: String,
    pub nullifier: String,
    pub anchor_root: String,
    pub owner_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub subject_id: String,
    pub nullifier: String,
    pub anchor_root: String,
    pub owner_commitment: String,
    pub height: u64,
}

impl PrivacyFence {
    pub fn from_request(request: PrivacyFenceRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("nullifier", &request.nullifier)?;
        ensure_nonempty("anchor_root", &request.anchor_root)?;
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        let fence_id = privacy_fence_id(&request);
        Ok(Self {
            fence_id,
            subject_id: request.subject_id,
            nullifier: request.nullifier,
            anchor_root: request.anchor_root,
            owner_commitment: request.owner_commitment,
            height: request.height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "account_recovery_privacy_fence",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "fence_id": self.fence_id,
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "anchor_root": self.anchor_root,
            "owner_commitment": self.owner_commitment,
            "height": self.height,
            "scheme": PRIVACY_FENCE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeRequest {
    pub subject_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub bond_micro_units: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub bond_micro_units: u64,
    pub slash_bps: u64,
    pub height: u64,
    pub resolved: bool,
}

impl Challenge {
    pub fn from_request(request: ChallengeRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("challenger_commitment", &request.challenger_commitment)?;
        ensure_nonempty("evidence_root", &request.evidence_root)?;
        let challenge_id = challenge_id(&request);
        Ok(Self {
            challenge_id,
            subject_id: request.subject_id,
            challenger_commitment: request.challenger_commitment,
            kind: request.kind,
            evidence_root: request.evidence_root,
            bond_micro_units: request.bond_micro_units,
            slash_bps: request.kind.slash_bps(),
            height: request.height,
            resolved: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "account_recovery_session_guard_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "bond_micro_units": self.bond_micro_units,
            "slash_bps": self.slash_bps,
            "height": self.height,
            "resolved": self.resolved,
            "scheme": CHALLENGE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub policies: BTreeMap<String, RecoveryPolicy>,
    pub requests: BTreeMap<String, SealedRecoveryRequest>,
    pub approvals: BTreeMap<String, GuardianApproval>,
    pub sessions: BTreeMap<String, RecoverySessionGrant>,
    pub paymaster_reservations: BTreeMap<String, PaymasterReservation>,
    pub receipts: BTreeMap<String, RecoveryReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub challenges: BTreeMap<String, Challenge>,
    spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            policies: BTreeMap::new(),
            requests: BTreeMap::new(),
            approvals: BTreeMap::new(),
            sessions: BTreeMap::new(),
            paymaster_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::devnet()
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn register_policy(&mut self, request: RecoveryPolicyRequest) -> Result<RecoveryPolicy> {
        ensure_capacity("policies", self.policies.len(), self.config.max_policies)?;
        let policy = RecoveryPolicy::from_request(&self.config, request)?;
        ensure_absent("policy", &self.policies, &policy.policy_id)?;
        self.counters.next_policy = self.counters.next_policy.saturating_add(1);
        self.policies
            .insert(policy.policy_id.clone(), policy.clone());
        self.recompute_roots();
        Ok(policy)
    }

    pub fn submit_recovery(
        &mut self,
        request: SealedRecoveryRequestInput,
    ) -> Result<SealedRecoveryRequest> {
        ensure_capacity("requests", self.requests.len(), self.config.max_requests)?;
        if self.spent_nullifiers.contains(&request.recovery_nullifier) {
            return Err("recovery nullifier already spent".to_string());
        }
        ensure_known("policy", &self.policies, &request.policy_id)?;
        let recovery = SealedRecoveryRequest::from_request(&self.config, request)?;
        ensure_absent("recovery_request", &self.requests, &recovery.request_id)?;
        self.spent_nullifiers
            .insert(recovery.recovery_nullifier.clone());
        self.counters.next_request = self.counters.next_request.saturating_add(1);
        self.requests
            .insert(recovery.request_id.clone(), recovery.clone());
        self.recompute_roots();
        Ok(recovery)
    }

    pub fn approve_recovery(
        &mut self,
        request: GuardianApprovalRequest,
    ) -> Result<GuardianApproval> {
        ensure_capacity("approvals", self.approvals.len(), self.config.max_approvals)?;
        let approval = GuardianApproval::from_request(&self.config, request)?;
        let recovery = self
            .requests
            .get_mut(&approval.request_id)
            .ok_or_else(|| format!("unknown request_id {}", approval.request_id))?;
        ensure_absent("guardian_approval", &self.approvals, &approval.approval_id)?;
        approval_meets_quorum(
            approval.approval_weight_bps,
            self.config.guardian_quorum_bps,
        )?;
        recovery.status = RecoveryStatus::Approved;
        self.counters.next_approval = self.counters.next_approval.saturating_add(1);
        self.approvals
            .insert(approval.approval_id.clone(), approval.clone());
        self.recompute_roots();
        Ok(approval)
    }

    pub fn grant_session(
        &mut self,
        request: RecoverySessionGrantRequest,
    ) -> Result<RecoverySessionGrant> {
        ensure_capacity("sessions", self.sessions.len(), self.config.max_sessions)?;
        let session = RecoverySessionGrant::from_request(&self.config, request)?;
        ensure_known("policy", &self.policies, &session.policy_id)?;
        let recovery = self
            .requests
            .get_mut(&session.request_id)
            .ok_or_else(|| format!("unknown request_id {}", session.request_id))?;
        if recovery.status != RecoveryStatus::Approved {
            return Err("recovery request must be approved before session grant".to_string());
        }
        ensure_absent("session", &self.sessions, &session.session_id)?;
        recovery.status = RecoveryStatus::SessionGranted;
        self.counters.next_session = self.counters.next_session.saturating_add(1);
        self.sessions
            .insert(session.session_id.clone(), session.clone());
        self.recompute_roots();
        Ok(session)
    }

    pub fn reserve_paymaster(
        &mut self,
        request: PaymasterReservationRequest,
    ) -> Result<PaymasterReservation> {
        ensure_capacity(
            "paymaster_reservations",
            self.paymaster_reservations.len(),
            self.config.max_paymaster_reservations,
        )?;
        if self.spent_nullifiers.contains(&request.rebate_nullifier) {
            return Err("paymaster rebate nullifier already spent".to_string());
        }
        let reservation = PaymasterReservation::from_request(&self.config, request)?;
        let recovery = self
            .requests
            .get_mut(&reservation.request_id)
            .ok_or_else(|| format!("unknown request_id {}", reservation.request_id))?;
        ensure_absent(
            "paymaster_reservation",
            &self.paymaster_reservations,
            &reservation.reservation_id,
        )?;
        recovery.status = RecoveryStatus::Sponsored;
        self.spent_nullifiers
            .insert(reservation.rebate_nullifier.clone());
        self.counters.next_paymaster_reservation =
            self.counters.next_paymaster_reservation.saturating_add(1);
        self.paymaster_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.recompute_roots();
        Ok(reservation)
    }

    pub fn publish_receipt(&mut self, request: RecoveryReceiptRequest) -> Result<RecoveryReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        let receipt = RecoveryReceipt::from_request(&self.config, request)?;
        let recovery = self
            .requests
            .get_mut(&receipt.request_id)
            .ok_or_else(|| format!("unknown request_id {}", receipt.request_id))?;
        let session = self
            .sessions
            .get_mut(&receipt.session_id)
            .ok_or_else(|| format!("unknown session_id {}", receipt.session_id))?;
        ensure_absent("receipt", &self.receipts, &receipt.receipt_id)?;
        recovery.status = RecoveryStatus::Settled;
        session.status = SessionStatus::Used;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn insert_privacy_fence(&mut self, request: PrivacyFenceRequest) -> Result<PrivacyFence> {
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err("privacy fence nullifier already spent".to_string());
        }
        let fence = PrivacyFence::from_request(request)?;
        ensure_absent("privacy_fence", &self.privacy_fences, &fence.fence_id)?;
        self.spent_nullifiers.insert(fence.nullifier.clone());
        self.counters.next_privacy_fence = self.counters.next_privacy_fence.saturating_add(1);
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn file_challenge(&mut self, request: ChallengeRequest) -> Result<Challenge> {
        ensure_capacity(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        let challenge = Challenge::from_request(request)?;
        ensure_absent("challenge", &self.challenges, &challenge.challenge_id)?;
        if let Some(recovery) = self.requests.get_mut(&challenge.subject_id) {
            recovery.status = RecoveryStatus::Challenged;
        }
        if let Some(session) = self.sessions.get_mut(&challenge.subject_id) {
            session.status = SessionStatus::Challenged;
        }
        self.counters.next_challenge = self.counters.next_challenge.saturating_add(1);
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        self.recompute_roots();
        Ok(challenge)
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: record_root(
                "ACCOUNT-RECOVERY-GUARD-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: record_root(
                "ACCOUNT-RECOVERY-GUARD-COUNTERS",
                &self.counters.public_record(),
            ),
            policy_root: map_root("ACCOUNT-RECOVERY-GUARD-POLICIES", &self.policies),
            request_root: map_root("ACCOUNT-RECOVERY-GUARD-REQUESTS", &self.requests),
            approval_root: map_root("ACCOUNT-RECOVERY-GUARD-APPROVALS", &self.approvals),
            session_root: map_root("ACCOUNT-RECOVERY-GUARD-SESSIONS", &self.sessions),
            paymaster_root: map_root(
                "ACCOUNT-RECOVERY-GUARD-PAYMASTERS",
                &self.paymaster_reservations,
            ),
            receipt_root: map_root("ACCOUNT-RECOVERY-GUARD-RECEIPTS", &self.receipts),
            privacy_fence_root: map_root(
                "ACCOUNT-RECOVERY-GUARD-PRIVACY-FENCES",
                &self.privacy_fences,
            ),
            challenge_root: map_root("ACCOUNT-RECOVERY-GUARD-CHALLENGES", &self.challenges),
            spent_nullifier_root: set_root(
                "ACCOUNT-RECOVERY-GUARD-SPENT-NULLIFIERS",
                &self.spent_nullifiers,
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_account_recovery_session_guard_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "policy_count": self.policies.len(),
            "request_count": self.requests.len(),
            "approval_count": self.approvals.len(),
            "session_count": self.sessions.len(),
            "paymaster_reservation_count": self.paymaster_reservations.len(),
            "receipt_count": self.receipts.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "challenge_count": self.challenges.len(),
            "spent_nullifier_count": self.spent_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_confidential_account_recovery_session_guard_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_pq_confidential_account_recovery_session_guard_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn recovery_policy_id(request: &RecoveryPolicyRequest) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.guardian_set_root),
            HashPart::Str(request.scope.as_str()),
            HashPart::U64(request.threshold_weight_bps),
            HashPart::Str(&request.policy_nonce_root),
            HashPart::U64(request.opened_height),
        ],
        32,
    )
}

pub fn recovery_request_id(request: &SealedRecoveryRequestInput) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.requester_commitment),
            HashPart::Str(&request.encrypted_recovery_payload_root),
            HashPart::Str(&request.target_key_commitment),
            HashPart::Str(&request.recovery_nullifier),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn guardian_approval_id(request: &GuardianApprovalRequest) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.request_id),
            HashPart::Str(&request.guardian_commitment),
            HashPart::U64(request.approval_weight_bps),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.guardian_evidence_root),
            HashPart::U64(request.approved_height),
        ],
        32,
    )
}

pub fn session_grant_id(request: &RecoverySessionGrantRequest) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.request_id),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.session_key_commitment),
            HashPart::Str(&request.allowed_call_root),
            HashPart::Str(&request.guardian_quorum_root),
            HashPart::U64(request.granted_height),
        ],
        32,
    )
}

pub fn paymaster_reservation_id(
    request: &PaymasterReservationRequest,
    rebate_micro_units: u64,
) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-PAYMASTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.request_id),
            HashPart::Str(&request.paymaster_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::Str(&request.policy_root),
            HashPart::U64(request.max_fee_micro_units),
            HashPart::U64(rebate_micro_units),
            HashPart::U64(request.reserved_height),
        ],
        32,
    )
}

pub fn recovery_receipt_id(request: &RecoveryReceiptRequest) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.request_id),
            HashPart::Str(&request.session_id),
            HashPart::Str(&request.executor_id),
            HashPart::Str(&request.new_account_state_root),
            HashPart::Str(&request.encrypted_receipt_root),
            HashPart::U64(request.fee_paid_micro_units),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &PrivacyFenceRequest) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.anchor_root),
            HashPart::Str(&request.owner_commitment),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn challenge_id(request: &ChallengeRequest) -> String {
    domain_hash(
        "ACCOUNT-RECOVERY-GUARD-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.bond_micro_units),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn approval_meets_quorum(weight_bps: u64, quorum_bps: u64) -> Result<()> {
    if weight_bps < quorum_bps {
        Err("guardian approval weight below quorum".to_string())
    } else {
        Ok(())
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("ACCOUNT-RECOVERY-GUARD-STATE-ROOT", record)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

pub fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

pub fn ensure_known<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label} {key}"))
    }
}
