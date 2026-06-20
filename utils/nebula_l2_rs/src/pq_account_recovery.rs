use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqAccountRecoveryResult<T> = Result<T, String>;

pub const PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION: &str = "nebula-l2-pq-account-recovery-v1";
pub const PQ_ACCOUNT_RECOVERY_SECURITY_MODEL: &str = "deterministic-devnet-model-not-real-crypto";
pub const PQ_ACCOUNT_RECOVERY_COMMITMENT_SCHEME: &str = "shake256-domain-separated-canonical-json";
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 720;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_CHALLENGE_BLOCKS: u64 = 144;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_REQUEST_TTL_BLOCKS: u64 = 2_880;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_FREEZE_TTL_BLOCKS: u64 = 1_440;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 288;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 720;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MIN_APPROVAL_WEIGHT: u64 = 2;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_THRESHOLD_WEIGHT: u64 = 3;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MIN_DISTINCT_GUARDIANS: u64 = 2;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_GUARDIANS_PER_PROFILE: usize = 16;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_ACTIVE_REQUESTS_PER_ACCOUNT: usize = 4;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_APPROVALS_PER_REQUEST: usize = 32;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_DISCLOSURE_SCAN_BLOCKS: u64 = 20_160;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 9_000;
pub const PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_RECOVERY_FEE_UNITS: u64 = 10_000;
pub const PQ_ACCOUNT_RECOVERY_MAX_BPS: u64 = 10_000;
pub const PQ_ACCOUNT_RECOVERY_ML_DSA_44: &str = "ML-DSA-44";
pub const PQ_ACCOUNT_RECOVERY_ML_DSA_65: &str = "ML-DSA-65";
pub const PQ_ACCOUNT_RECOVERY_ML_DSA_87: &str = "ML-DSA-87";
pub const PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_128S: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_192S: &str = "SLH-DSA-SHAKE-192s";
pub const PQ_ACCOUNT_RECOVERY_HYBRID_ML_DSA_ED25519: &str = "ML-DSA-65+Ed25519";
pub const PQ_ACCOUNT_RECOVERY_HARDWARE_ATTESTED_ML_DSA: &str = "hardware-attested-ML-DSA-65";
pub const PQ_ACCOUNT_RECOVERY_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_ACCOUNT_RECOVERY_DEVNET_CHALLENGE_BOND_ASSET_ID: &str = "dusd-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecoveryAccountKind {
    PrivateWallet,
    ContractAccount,
    VaultAccount,
    PaymasterAccount,
    GuardianGroup,
}

impl PqRecoveryAccountKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateWallet => "private_wallet",
            Self::ContractAccount => "contract_account",
            Self::VaultAccount => "vault_account",
            Self::PaymasterAccount => "paymaster_account",
            Self::GuardianGroup => "guardian_group",
        }
    }

    pub fn requires_contract_root(self) -> bool {
        matches!(self, Self::ContractAccount | Self::PaymasterAccount)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecoveryProfileStatus {
    Draft,
    Active,
    Paused,
    Frozen,
    Rotating,
    Superseded,
    Revoked,
}

impl PqRecoveryProfileStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Rotating => "rotating",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_recovery(self) -> bool {
        matches!(self, Self::Active | Self::Frozen | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqGuardianAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    SlhDsaShake192s,
    HybridMlDsaEd25519,
    HardwareAttestedMlDsa,
}

impl PqGuardianAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => PQ_ACCOUNT_RECOVERY_ML_DSA_44,
            Self::MlDsa65 => PQ_ACCOUNT_RECOVERY_ML_DSA_65,
            Self::MlDsa87 => PQ_ACCOUNT_RECOVERY_ML_DSA_87,
            Self::SlhDsaShake128s => PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_128S,
            Self::SlhDsaShake192s => PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_192S,
            Self::HybridMlDsaEd25519 => PQ_ACCOUNT_RECOVERY_HYBRID_ML_DSA_ED25519,
            Self::HardwareAttestedMlDsa => PQ_ACCOUNT_RECOVERY_HARDWARE_ATTESTED_ML_DSA,
        }
    }

    pub fn family(self) -> &'static str {
        match self {
            Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87
            | Self::HybridMlDsaEd25519
            | Self::HardwareAttestedMlDsa => "ml_dsa",
            Self::SlhDsaShake128s | Self::SlhDsaShake192s => "slh_dsa",
        }
    }

    pub fn is_stateful_resistant(self) -> bool {
        matches!(self, Self::SlhDsaShake128s | Self::SlhDsaShake192s)
    }

    pub fn requires_hardware_policy(self) -> bool {
        matches!(self, Self::HardwareAttestedMlDsa)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqGuardianRole {
    Owner,
    SocialRecovery,
    ContractAdmin,
    EmergencyFreeze,
    EmergencyUnfreeze,
    ViewKeyWitness,
    SignerRotation,
    FeeSponsor,
    HardwareCoSigner,
    Watchtower,
}

impl PqGuardianRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::SocialRecovery => "social_recovery",
            Self::ContractAdmin => "contract_admin",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::EmergencyUnfreeze => "emergency_unfreeze",
            Self::ViewKeyWitness => "view_key_witness",
            Self::SignerRotation => "signer_rotation",
            Self::FeeSponsor => "fee_sponsor",
            Self::HardwareCoSigner => "hardware_co_signer",
            Self::Watchtower => "watchtower",
        }
    }

    pub fn can_approve_emergency(self) -> bool {
        matches!(
            self,
            Self::Owner
                | Self::EmergencyFreeze
                | Self::EmergencyUnfreeze
                | Self::Watchtower
                | Self::HardwareCoSigner
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqGuardianStatus {
    Pending,
    Active,
    Suspended,
    Rotating,
    Revoked,
    Expired,
}

impl PqGuardianStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqHardwarePolicyStatus {
    Draft,
    Active,
    Retired,
    Compromised,
    Expired,
}

impl PqHardwarePolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Compromised => "compromised",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalPurpose {
    RecoveryOpen,
    RecoveryExecute,
    EmergencyFreeze,
    EmergencyUnfreeze,
    SignerRotation,
    ViewKeyDisclosure,
    SponsorAuthorization,
    ContractAdminRecovery,
}

impl PqApprovalPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryOpen => "recovery_open",
            Self::RecoveryExecute => "recovery_execute",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::EmergencyUnfreeze => "emergency_unfreeze",
            Self::SignerRotation => "signer_rotation",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::SponsorAuthorization => "sponsor_authorization",
            Self::ContractAdminRecovery => "contract_admin_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalStatus {
    Draft,
    Submitted,
    Counted,
    Superseded,
    Rejected,
    Revoked,
    Expired,
}

impl PqApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn counts(self) -> bool {
        matches!(self, Self::Submitted | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecoveryRequestKind {
    WalletSpendKeyRecovery,
    WalletFullKeyRecovery,
    ContractOwnerRecovery,
    ContractGuardianRecovery,
    ViewKeyRecoveryOnly,
    HardwareSignerLost,
    EmergencyBreakGlass,
}

impl PqRecoveryRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSpendKeyRecovery => "wallet_spend_key_recovery",
            Self::WalletFullKeyRecovery => "wallet_full_key_recovery",
            Self::ContractOwnerRecovery => "contract_owner_recovery",
            Self::ContractGuardianRecovery => "contract_guardian_recovery",
            Self::ViewKeyRecoveryOnly => "view_key_recovery_only",
            Self::HardwareSignerLost => "hardware_signer_lost",
            Self::EmergencyBreakGlass => "emergency_break_glass",
        }
    }

    pub fn requires_view_key_proof(self) -> bool {
        matches!(
            self,
            Self::WalletFullKeyRecovery | Self::ViewKeyRecoveryOnly | Self::EmergencyBreakGlass
        )
    }

    pub fn is_contract_recovery(self) -> bool {
        matches!(
            self,
            Self::ContractOwnerRecovery | Self::ContractGuardianRecovery
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecoveryRequestStatus {
    Draft,
    Open,
    Timelocked,
    Challenged,
    Ready,
    Executed,
    Rejected,
    Cancelled,
    Expired,
}

impl PqRecoveryRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Timelocked => "timelocked",
            Self::Challenged => "challenged",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Timelocked | Self::Challenged | Self::Ready
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Rejected | Self::Cancelled | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqTimelockKind {
    StandardRecovery,
    FastHardwareRecovery,
    ContractAdminDelay,
    EmergencyShortDelay,
    ViewKeyDisclosureDelay,
}

impl PqTimelockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardRecovery => "standard_recovery",
            Self::FastHardwareRecovery => "fast_hardware_recovery",
            Self::ContractAdminDelay => "contract_admin_delay",
            Self::EmergencyShortDelay => "emergency_short_delay",
            Self::ViewKeyDisclosureDelay => "view_key_disclosure_delay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqTimelockStatus {
    WaitingForApprovals,
    ChallengeOpen,
    Mature,
    Released,
    Cancelled,
    Expired,
}

impl PqTimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WaitingForApprovals => "waiting_for_approvals",
            Self::ChallengeOpen => "challenge_open",
            Self::Mature => "mature",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::WaitingForApprovals | Self::ChallengeOpen | Self::Mature
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEmergencyFreezeScope {
    AllAccountActions,
    SpendOnly,
    ContractCalls,
    RecoveryOnly,
    ViewKeyDisclosure,
    SponsorshipOnly,
}

impl PqEmergencyFreezeScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllAccountActions => "all_account_actions",
            Self::SpendOnly => "spend_only",
            Self::ContractCalls => "contract_calls",
            Self::RecoveryOnly => "recovery_only",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::SponsorshipOnly => "sponsorship_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEmergencyFreezeStatus {
    Requested,
    Active,
    Challenged,
    Lifted,
    Expired,
    Rejected,
}

impl PqEmergencyFreezeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Challenged => "challenged",
            Self::Lifted => "lifted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Requested | Self::Active | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignerRotationStatus {
    Announced,
    WaitingForTimelock,
    Ready,
    Applied,
    Superseded,
    Rejected,
    Expired,
}

impl PqSignerRotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::WaitingForTimelock => "waiting_for_timelock",
            Self::Ready => "ready",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Announced | Self::WaitingForTimelock | Self::Ready
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqLimitedViewKeyScope {
    IncomingTransfers,
    OutgoingNullifiers,
    ContractEvents,
    RecoveryEvidence,
    AuditOnly,
    EmergencyFullWindow,
}

impl PqLimitedViewKeyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncomingTransfers => "incoming_transfers",
            Self::OutgoingNullifiers => "outgoing_nullifiers",
            Self::ContractEvents => "contract_events",
            Self::RecoveryEvidence => "recovery_evidence",
            Self::AuditOnly => "audit_only",
            Self::EmergencyFullWindow => "emergency_full_window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqLimitedViewKeyDisclosureStatus {
    Proposed,
    Approved,
    Active,
    Consumed,
    Revoked,
    Expired,
}

impl PqLimitedViewKeyDisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Approved | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecoveryFeeSponsorshipStatus {
    Offered,
    Reserved,
    PartiallySpent,
    Settled,
    Revoked,
    Expired,
}

impl PqRecoveryFeeSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::PartiallySpent => "partially_spent",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::PartiallySpent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecoveryAuditEventKind {
    ProfileInserted,
    GuardianInserted,
    HardwarePolicyInserted,
    RequestOpened,
    TimelockInserted,
    ApprovalRecorded,
    RequestReadinessChanged,
    RequestExecuted,
    FreezeOpened,
    FreezeLifted,
    RotationInserted,
    ViewKeyDisclosureInserted,
    SponsorshipInserted,
    SponsorshipSpent,
    DevnetFixtureInserted,
    HeightAdvanced,
    ValidationCheckpoint,
}

impl PqRecoveryAuditEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProfileInserted => "profile_inserted",
            Self::GuardianInserted => "guardian_inserted",
            Self::HardwarePolicyInserted => "hardware_policy_inserted",
            Self::RequestOpened => "request_opened",
            Self::TimelockInserted => "timelock_inserted",
            Self::ApprovalRecorded => "approval_recorded",
            Self::RequestReadinessChanged => "request_readiness_changed",
            Self::RequestExecuted => "request_executed",
            Self::FreezeOpened => "freeze_opened",
            Self::FreezeLifted => "freeze_lifted",
            Self::RotationInserted => "rotation_inserted",
            Self::ViewKeyDisclosureInserted => "view_key_disclosure_inserted",
            Self::SponsorshipInserted => "sponsorship_inserted",
            Self::SponsorshipSpent => "sponsorship_spent",
            Self::DevnetFixtureInserted => "devnet_fixture_inserted",
            Self::HeightAdvanced => "height_advanced",
            Self::ValidationCheckpoint => "validation_checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAccountRecoveryConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub security_model: String,
    pub commitment_scheme: String,
    pub default_min_approval_weight: u64,
    pub default_threshold_weight: u64,
    pub default_min_distinct_guardians: u64,
    pub default_recovery_delay_blocks: u64,
    pub default_challenge_blocks: u64,
    pub default_request_ttl_blocks: u64,
    pub default_freeze_ttl_blocks: u64,
    pub default_disclosure_ttl_blocks: u64,
    pub default_sponsorship_ttl_blocks: u64,
    pub max_guardians_per_profile: usize,
    pub max_active_requests_per_account: usize,
    pub max_approvals_per_request: usize,
    pub max_disclosure_scan_blocks: u64,
    pub require_hardware_for_contract_accounts: bool,
    pub require_limited_view_key_proof: bool,
    pub allow_low_fee_sponsorship: bool,
    pub min_sponsor_rebate_bps: u64,
    pub max_recovery_fee_units: u64,
    pub fee_asset_id: String,
    pub challenge_bond_asset_id: String,
    pub supported_guardian_algorithms: Vec<String>,
    pub privacy_metadata: Value,
}

impl Default for PqAccountRecoveryConfig {
    fn default() -> Self {
        Self {
            protocol_version: PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            security_model: PQ_ACCOUNT_RECOVERY_SECURITY_MODEL.to_string(),
            commitment_scheme: PQ_ACCOUNT_RECOVERY_COMMITMENT_SCHEME.to_string(),
            default_min_approval_weight: PQ_ACCOUNT_RECOVERY_DEFAULT_MIN_APPROVAL_WEIGHT,
            default_threshold_weight: PQ_ACCOUNT_RECOVERY_DEFAULT_THRESHOLD_WEIGHT,
            default_min_distinct_guardians: PQ_ACCOUNT_RECOVERY_DEFAULT_MIN_DISTINCT_GUARDIANS,
            default_recovery_delay_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_RECOVERY_DELAY_BLOCKS,
            default_challenge_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_CHALLENGE_BLOCKS,
            default_request_ttl_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_REQUEST_TTL_BLOCKS,
            default_freeze_ttl_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_FREEZE_TTL_BLOCKS,
            default_disclosure_ttl_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            default_sponsorship_ttl_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            max_guardians_per_profile: PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_GUARDIANS_PER_PROFILE,
            max_active_requests_per_account:
                PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_ACTIVE_REQUESTS_PER_ACCOUNT,
            max_approvals_per_request: PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_APPROVALS_PER_REQUEST,
            max_disclosure_scan_blocks: PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_DISCLOSURE_SCAN_BLOCKS,
            require_hardware_for_contract_accounts: true,
            require_limited_view_key_proof: true,
            allow_low_fee_sponsorship: true,
            min_sponsor_rebate_bps: PQ_ACCOUNT_RECOVERY_DEFAULT_LOW_FEE_REBATE_BPS,
            max_recovery_fee_units: PQ_ACCOUNT_RECOVERY_DEFAULT_MAX_RECOVERY_FEE_UNITS,
            fee_asset_id: PQ_ACCOUNT_RECOVERY_DEVNET_FEE_ASSET_ID.to_string(),
            challenge_bond_asset_id: PQ_ACCOUNT_RECOVERY_DEVNET_CHALLENGE_BOND_ASSET_ID.to_string(),
            supported_guardian_algorithms: vec![
                PQ_ACCOUNT_RECOVERY_ML_DSA_44.to_string(),
                PQ_ACCOUNT_RECOVERY_ML_DSA_65.to_string(),
                PQ_ACCOUNT_RECOVERY_ML_DSA_87.to_string(),
                PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_128S.to_string(),
                PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_192S.to_string(),
                PQ_ACCOUNT_RECOVERY_HYBRID_ML_DSA_ED25519.to_string(),
                PQ_ACCOUNT_RECOVERY_HARDWARE_ATTESTED_ML_DSA.to_string(),
            ],
            privacy_metadata: json!({
                "default_transport": "private-relay",
                "observer_model": "limited-view-key-disclosure",
                "nullifier_policy": "per-request-domain-separated",
                "devnet": true,
            }),
        }
    }
}

impl PqAccountRecoveryConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "security_model": self.security_model,
            "commitment_scheme": self.commitment_scheme,
            "default_min_approval_weight": self.default_min_approval_weight,
            "default_threshold_weight": self.default_threshold_weight,
            "default_min_distinct_guardians": self.default_min_distinct_guardians,
            "default_recovery_delay_blocks": self.default_recovery_delay_blocks,
            "default_challenge_blocks": self.default_challenge_blocks,
            "default_request_ttl_blocks": self.default_request_ttl_blocks,
            "default_freeze_ttl_blocks": self.default_freeze_ttl_blocks,
            "default_disclosure_ttl_blocks": self.default_disclosure_ttl_blocks,
            "default_sponsorship_ttl_blocks": self.default_sponsorship_ttl_blocks,
            "max_guardians_per_profile": self.max_guardians_per_profile,
            "max_active_requests_per_account": self.max_active_requests_per_account,
            "max_approvals_per_request": self.max_approvals_per_request,
            "max_disclosure_scan_blocks": self.max_disclosure_scan_blocks,
            "require_hardware_for_contract_accounts": self.require_hardware_for_contract_accounts,
            "require_limited_view_key_proof": self.require_limited_view_key_proof,
            "allow_low_fee_sponsorship": self.allow_low_fee_sponsorship,
            "min_sponsor_rebate_bps": self.min_sponsor_rebate_bps,
            "max_recovery_fee_units": self.max_recovery_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "challenge_bond_asset_id": self.challenge_bond_asset_id,
            "supported_guardian_algorithms": self.supported_guardian_algorithms,
            "privacy_metadata": self.privacy_metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.security_model, "security_model")?;
        ensure_non_empty(&self.commitment_scheme, "commitment_scheme")?;
        ensure_positive(
            self.default_min_approval_weight,
            "default_min_approval_weight",
        )?;
        ensure_positive(self.default_threshold_weight, "default_threshold_weight")?;
        ensure_positive(
            self.default_min_distinct_guardians,
            "default_min_distinct_guardians",
        )?;
        if self.default_threshold_weight < self.default_min_approval_weight {
            return Err("default_threshold_weight below min approval weight".to_string());
        }
        ensure_positive(
            self.default_recovery_delay_blocks,
            "default_recovery_delay_blocks",
        )?;
        ensure_positive(self.default_challenge_blocks, "default_challenge_blocks")?;
        ensure_positive(
            self.default_request_ttl_blocks,
            "default_request_ttl_blocks",
        )?;
        ensure_positive(self.default_freeze_ttl_blocks, "default_freeze_ttl_blocks")?;
        ensure_positive(
            self.default_disclosure_ttl_blocks,
            "default_disclosure_ttl_blocks",
        )?;
        ensure_positive(
            self.default_sponsorship_ttl_blocks,
            "default_sponsorship_ttl_blocks",
        )?;
        if self.max_guardians_per_profile == 0 {
            return Err("max_guardians_per_profile must be positive".to_string());
        }
        if self.max_active_requests_per_account == 0 {
            return Err("max_active_requests_per_account must be positive".to_string());
        }
        if self.max_approvals_per_request == 0 {
            return Err("max_approvals_per_request must be positive".to_string());
        }
        ensure_positive(
            self.max_disclosure_scan_blocks,
            "max_disclosure_scan_blocks",
        )?;
        validate_bps(self.min_sponsor_rebate_bps, "min_sponsor_rebate_bps")?;
        ensure_positive(self.max_recovery_fee_units, "max_recovery_fee_units")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.challenge_bond_asset_id, "challenge_bond_asset_id")?;
        ensure_unique_strings(
            &self.supported_guardian_algorithms,
            "supported_guardian_algorithms",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryQuorumPolicy {
    pub policy_id: String,
    pub min_approval_weight: u64,
    pub threshold_weight: u64,
    pub min_distinct_guardians: u64,
    pub required_roles: Vec<PqGuardianRole>,
    pub allow_slh_dsa_only_for_freeze: bool,
    pub require_hardware_attestation: bool,
    pub require_view_key_witness: bool,
    pub challenge_period_blocks: u64,
    pub execution_delay_blocks: u64,
    pub metadata: Value,
}

impl PqRecoveryQuorumPolicy {
    pub fn new(
        profile_seed: &str,
        min_approval_weight: u64,
        threshold_weight: u64,
        min_distinct_guardians: u64,
        required_roles: Vec<PqGuardianRole>,
        require_hardware_attestation: bool,
        require_view_key_witness: bool,
        challenge_period_blocks: u64,
        execution_delay_blocks: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_seed, "profile_seed")?;
        ensure_positive(min_approval_weight, "min_approval_weight")?;
        ensure_positive(threshold_weight, "threshold_weight")?;
        ensure_positive(min_distinct_guardians, "min_distinct_guardians")?;
        ensure_positive(challenge_period_blocks, "challenge_period_blocks")?;
        ensure_positive(execution_delay_blocks, "execution_delay_blocks")?;
        if threshold_weight < min_approval_weight {
            return Err("threshold_weight below min_approval_weight".to_string());
        }
        let role_root = merkle_root(
            "PQ-ACCOUNT-RECOVERY-QUORUM-ROLE",
            &required_roles
                .iter()
                .map(|role| Value::String(role.as_str().to_string()))
                .collect::<Vec<_>>(),
        );
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-QUORUM-METADATA", metadata);
        let policy_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-QUORUM-POLICY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(profile_seed),
                HashPart::Int(min_approval_weight as i128),
                HashPart::Int(threshold_weight as i128),
                HashPart::Int(min_distinct_guardians as i128),
                HashPart::Str(&role_root),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let policy = Self {
            policy_id,
            min_approval_weight,
            threshold_weight,
            min_distinct_guardians,
            required_roles,
            allow_slh_dsa_only_for_freeze: true,
            require_hardware_attestation,
            require_view_key_witness,
            challenge_period_blocks,
            execution_delay_blocks,
            metadata: metadata.clone(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "min_approval_weight": self.min_approval_weight,
            "threshold_weight": self.threshold_weight,
            "min_distinct_guardians": self.min_distinct_guardians,
            "required_roles": self.required_roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "allow_slh_dsa_only_for_freeze": self.allow_slh_dsa_only_for_freeze,
            "require_hardware_attestation": self.require_hardware_attestation,
            "require_view_key_witness": self.require_view_key_witness,
            "challenge_period_blocks": self.challenge_period_blocks,
            "execution_delay_blocks": self.execution_delay_blocks,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.policy_id, "policy_id")?;
        ensure_positive(self.min_approval_weight, "min_approval_weight")?;
        ensure_positive(self.threshold_weight, "threshold_weight")?;
        ensure_positive(self.min_distinct_guardians, "min_distinct_guardians")?;
        if self.threshold_weight < self.min_approval_weight {
            return Err("quorum threshold below min approval weight".to_string());
        }
        ensure_positive(self.challenge_period_blocks, "challenge_period_blocks")?;
        ensure_positive(self.execution_delay_blocks, "execution_delay_blocks")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryProfile {
    pub profile_id: String,
    pub account_commitment: String,
    pub account_kind: PqRecoveryAccountKind,
    pub wallet_policy_root: String,
    pub contract_code_root: String,
    pub owner_commitment_root: String,
    pub current_spend_key_root: String,
    pub current_view_key_commitment: String,
    pub guardian_set_root: String,
    pub quorum_policy: PqRecoveryQuorumPolicy,
    pub rotation_nonce: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
    pub status: PqRecoveryProfileStatus,
}

impl PqRecoveryProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: &str,
        account_kind: PqRecoveryAccountKind,
        wallet_policy_root: &str,
        contract_code_root: &str,
        owner_commitment_root: &str,
        current_spend_key_root: &str,
        current_view_key_commitment: &str,
        guardian_set_root: &str,
        quorum_policy: PqRecoveryQuorumPolicy,
        active_from_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(account_commitment, "account_commitment")?;
        ensure_non_empty(wallet_policy_root, "wallet_policy_root")?;
        ensure_non_empty(owner_commitment_root, "owner_commitment_root")?;
        ensure_non_empty(current_spend_key_root, "current_spend_key_root")?;
        ensure_non_empty(current_view_key_commitment, "current_view_key_commitment")?;
        ensure_non_empty(guardian_set_root, "guardian_set_root")?;
        if account_kind.requires_contract_root() {
            ensure_non_empty(contract_code_root, "contract_code_root")?;
        }
        ensure_height_order(
            active_from_height,
            expires_at_height,
            "profile active_from/expires_at",
        )?;
        quorum_policy.validate()?;
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-PROFILE-METADATA", metadata);
        let profile_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-PROFILE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(account_commitment),
                HashPart::Str(account_kind.as_str()),
                HashPart::Str(wallet_policy_root),
                HashPart::Str(contract_code_root),
                HashPart::Str(owner_commitment_root),
                HashPart::Str(current_spend_key_root),
                HashPart::Str(current_view_key_commitment),
                HashPart::Str(&quorum_policy.policy_id),
                HashPart::Int(active_from_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let profile = Self {
            profile_id,
            account_commitment: account_commitment.to_string(),
            account_kind,
            wallet_policy_root: wallet_policy_root.to_string(),
            contract_code_root: contract_code_root.to_string(),
            owner_commitment_root: owner_commitment_root.to_string(),
            current_spend_key_root: current_spend_key_root.to_string(),
            current_view_key_commitment: current_view_key_commitment.to_string(),
            guardian_set_root: guardian_set_root.to_string(),
            quorum_policy,
            rotation_nonce: 0,
            active_from_height,
            expires_at_height,
            metadata: metadata.clone(),
            status: PqRecoveryProfileStatus::Active,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "account_commitment": self.account_commitment,
            "account_kind": self.account_kind.as_str(),
            "wallet_policy_root": self.wallet_policy_root,
            "contract_code_root": self.contract_code_root,
            "owner_commitment_root": self.owner_commitment_root,
            "current_spend_key_root": self.current_spend_key_root,
            "current_view_key_commitment": self.current_view_key_commitment,
            "guardian_set_root": self.guardian_set_root,
            "quorum_policy": self.quorum_policy.public_record(),
            "rotation_nonce": self.rotation_nonce,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.account_commitment, "account_commitment")?;
        ensure_non_empty(&self.wallet_policy_root, "wallet_policy_root")?;
        ensure_non_empty(&self.owner_commitment_root, "owner_commitment_root")?;
        ensure_non_empty(&self.current_spend_key_root, "current_spend_key_root")?;
        ensure_non_empty(
            &self.current_view_key_commitment,
            "current_view_key_commitment",
        )?;
        ensure_non_empty(&self.guardian_set_root, "guardian_set_root")?;
        if self.account_kind.requires_contract_root() {
            ensure_non_empty(&self.contract_code_root, "contract_code_root")?;
        }
        ensure_height_order(
            self.active_from_height,
            self.expires_at_height,
            "profile active_from/expires_at",
        )?;
        self.quorum_policy.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqHardwareSignerPolicy {
    pub policy_id: String,
    pub profile_id: String,
    pub signer_label_commitment: String,
    pub vendor_commitment: String,
    pub firmware_root: String,
    pub secure_element_root: String,
    pub allowed_algorithms: Vec<PqGuardianAlgorithm>,
    pub anti_exfiltration_required: bool,
    pub user_presence_required: bool,
    pub offline_only: bool,
    pub max_recovery_amount_units: u64,
    pub attestation_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
    pub status: PqHardwarePolicyStatus,
}

impl PqHardwareSignerPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        signer_label_commitment: &str,
        vendor_commitment: &str,
        firmware_root: &str,
        secure_element_root: &str,
        allowed_algorithms: Vec<PqGuardianAlgorithm>,
        anti_exfiltration_required: bool,
        user_presence_required: bool,
        offline_only: bool,
        max_recovery_amount_units: u64,
        attestation_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(signer_label_commitment, "signer_label_commitment")?;
        ensure_non_empty(vendor_commitment, "vendor_commitment")?;
        ensure_non_empty(firmware_root, "firmware_root")?;
        ensure_non_empty(secure_element_root, "secure_element_root")?;
        ensure_non_empty(attestation_root, "attestation_root")?;
        ensure_height_order(
            created_at_height,
            expires_at_height,
            "hardware policy created_at/expires_at",
        )?;
        ensure_positive(max_recovery_amount_units, "max_recovery_amount_units")?;
        if allowed_algorithms.is_empty() {
            return Err("allowed_algorithms cannot be empty".to_string());
        }
        let algorithm_root = merkle_root(
            "PQ-ACCOUNT-RECOVERY-HARDWARE-POLICY-ALGORITHM",
            &allowed_algorithms
                .iter()
                .map(|algorithm| Value::String(algorithm.as_str().to_string()))
                .collect::<Vec<_>>(),
        );
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-HARDWARE-METADATA", metadata);
        let policy_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-HARDWARE-POLICY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(profile_id),
                HashPart::Str(signer_label_commitment),
                HashPart::Str(vendor_commitment),
                HashPart::Str(firmware_root),
                HashPart::Str(secure_element_root),
                HashPart::Str(&algorithm_root),
                HashPart::Str(attestation_root),
                HashPart::Int(created_at_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let policy = Self {
            policy_id,
            profile_id: profile_id.to_string(),
            signer_label_commitment: signer_label_commitment.to_string(),
            vendor_commitment: vendor_commitment.to_string(),
            firmware_root: firmware_root.to_string(),
            secure_element_root: secure_element_root.to_string(),
            allowed_algorithms,
            anti_exfiltration_required,
            user_presence_required,
            offline_only,
            max_recovery_amount_units,
            attestation_root: attestation_root.to_string(),
            created_at_height,
            expires_at_height,
            metadata: metadata.clone(),
            status: PqHardwarePolicyStatus::Active,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "profile_id": self.profile_id,
            "signer_label_commitment": self.signer_label_commitment,
            "vendor_commitment": self.vendor_commitment,
            "firmware_root": self.firmware_root,
            "secure_element_root": self.secure_element_root,
            "allowed_algorithms": self.allowed_algorithms.iter().map(|algorithm| algorithm.as_str()).collect::<Vec<_>>(),
            "anti_exfiltration_required": self.anti_exfiltration_required,
            "user_presence_required": self.user_presence_required,
            "offline_only": self.offline_only,
            "max_recovery_amount_units": self.max_recovery_amount_units,
            "attestation_root": self.attestation_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.policy_id, "policy_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.signer_label_commitment, "signer_label_commitment")?;
        ensure_non_empty(&self.vendor_commitment, "vendor_commitment")?;
        ensure_non_empty(&self.firmware_root, "firmware_root")?;
        ensure_non_empty(&self.secure_element_root, "secure_element_root")?;
        ensure_non_empty(&self.attestation_root, "attestation_root")?;
        ensure_positive(self.max_recovery_amount_units, "max_recovery_amount_units")?;
        ensure_height_order(
            self.created_at_height,
            self.expires_at_height,
            "hardware policy created_at/expires_at",
        )?;
        if self.allowed_algorithms.is_empty() {
            return Err("hardware policy allowed_algorithms cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardian {
    pub guardian_id: String,
    pub profile_id: String,
    pub role: PqGuardianRole,
    pub algorithm: PqGuardianAlgorithm,
    pub verification_key_commitment: String,
    pub proof_of_possession_root: String,
    pub hardware_policy_id: Option<String>,
    pub privacy_budget: u64,
    pub weight: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
    pub status: PqGuardianStatus,
}

impl PqGuardian {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        role: PqGuardianRole,
        algorithm: PqGuardianAlgorithm,
        verification_key_commitment: &str,
        proof_of_possession_root: &str,
        hardware_policy_id: Option<String>,
        privacy_budget: u64,
        weight: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(verification_key_commitment, "verification_key_commitment")?;
        ensure_non_empty(proof_of_possession_root, "proof_of_possession_root")?;
        ensure_positive(weight, "weight")?;
        ensure_height_order(
            activated_at_height,
            expires_at_height,
            "guardian activated_at/expires_at",
        )?;
        if algorithm.requires_hardware_policy() && hardware_policy_id.is_none() {
            return Err("hardware-attested guardian requires hardware_policy_id".to_string());
        }
        let hardware_policy_part = hardware_policy_id.as_deref().unwrap_or("");
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-GUARDIAN-METADATA", metadata);
        let guardian_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-GUARDIAN-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(profile_id),
                HashPart::Str(role.as_str()),
                HashPart::Str(algorithm.as_str()),
                HashPart::Str(verification_key_commitment),
                HashPart::Str(proof_of_possession_root),
                HashPart::Str(hardware_policy_part),
                HashPart::Int(weight as i128),
                HashPart::Int(activated_at_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let guardian = Self {
            guardian_id,
            profile_id: profile_id.to_string(),
            role,
            algorithm,
            verification_key_commitment: verification_key_commitment.to_string(),
            proof_of_possession_root: proof_of_possession_root.to_string(),
            hardware_policy_id,
            privacy_budget,
            weight,
            activated_at_height,
            expires_at_height,
            metadata: metadata.clone(),
            status: PqGuardianStatus::Active,
        };
        guardian.validate()?;
        Ok(guardian)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guardian_id": self.guardian_id,
            "profile_id": self.profile_id,
            "role": self.role.as_str(),
            "algorithm": self.algorithm.as_str(),
            "algorithm_family": self.algorithm.family(),
            "verification_key_commitment": self.verification_key_commitment,
            "proof_of_possession_root": self.proof_of_possession_root,
            "hardware_policy_id": self.hardware_policy_id,
            "privacy_budget": self.privacy_budget,
            "weight": self.weight,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.guardian_id, "guardian_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(
            &self.verification_key_commitment,
            "verification_key_commitment",
        )?;
        ensure_non_empty(&self.proof_of_possession_root, "proof_of_possession_root")?;
        ensure_positive(self.weight, "weight")?;
        ensure_height_order(
            self.activated_at_height,
            self.expires_at_height,
            "guardian activated_at/expires_at",
        )?;
        if self.algorithm.requires_hardware_policy() && self.hardware_policy_id.is_none() {
            return Err("hardware-attested guardian requires hardware_policy_id".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardianApproval {
    pub approval_id: String,
    pub profile_id: String,
    pub request_id: String,
    pub guardian_id: String,
    pub purpose: PqApprovalPurpose,
    pub status: PqApprovalStatus,
    pub weight: u64,
    pub signed_message_root: String,
    pub signature_scheme: String,
    pub signature_root: String,
    pub signer_policy_id: Option<String>,
    pub approval_nullifier: String,
    pub approved_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PqGuardianApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        request_id: &str,
        guardian_id: &str,
        purpose: PqApprovalPurpose,
        weight: u64,
        signed_message_root: &str,
        signature_scheme: &str,
        signature_root: &str,
        signer_policy_id: Option<String>,
        approved_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(request_id, "request_id")?;
        ensure_non_empty(guardian_id, "guardian_id")?;
        ensure_positive(weight, "weight")?;
        ensure_non_empty(signed_message_root, "signed_message_root")?;
        ensure_non_empty(signature_scheme, "signature_scheme")?;
        ensure_non_empty(signature_root, "signature_root")?;
        ensure_height_order(
            approved_height,
            expires_at_height,
            "approval approved_height/expires_at",
        )?;
        let signer_policy_part = signer_policy_id.as_deref().unwrap_or("");
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-APPROVAL-METADATA", metadata);
        let approval_nullifier = domain_hash(
            "PQ-ACCOUNT-RECOVERY-APPROVAL-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(profile_id),
                HashPart::Str(request_id),
                HashPart::Str(guardian_id),
                HashPart::Str(purpose.as_str()),
                HashPart::Str(signed_message_root),
            ],
            32,
        );
        let approval_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-APPROVAL-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(&approval_nullifier),
                HashPart::Str(signature_scheme),
                HashPart::Str(signature_root),
                HashPart::Str(signer_policy_part),
                HashPart::Int(approved_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let approval = Self {
            approval_id,
            profile_id: profile_id.to_string(),
            request_id: request_id.to_string(),
            guardian_id: guardian_id.to_string(),
            purpose,
            status: PqApprovalStatus::Submitted,
            weight,
            signed_message_root: signed_message_root.to_string(),
            signature_scheme: signature_scheme.to_string(),
            signature_root: signature_root.to_string(),
            signer_policy_id,
            approval_nullifier,
            approved_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "guardian_id": self.guardian_id,
            "purpose": self.purpose.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "signed_message_root": self.signed_message_root,
            "signature_scheme": self.signature_scheme,
            "signature_root": self.signature_root,
            "signer_policy_id": self.signer_policy_id,
            "approval_nullifier": self.approval_nullifier,
            "approved_height": self.approved_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.approval_id, "approval_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.request_id, "request_id")?;
        ensure_non_empty(&self.guardian_id, "guardian_id")?;
        ensure_positive(self.weight, "weight")?;
        ensure_non_empty(&self.signed_message_root, "signed_message_root")?;
        ensure_non_empty(&self.signature_scheme, "signature_scheme")?;
        ensure_non_empty(&self.signature_root, "signature_root")?;
        ensure_non_empty(&self.approval_nullifier, "approval_nullifier")?;
        ensure_height_order(
            self.approved_height,
            self.expires_at_height,
            "approval approved_height/expires_at",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqTimelockWindow {
    pub timelock_id: String,
    pub request_id: String,
    pub profile_id: String,
    pub kind: PqTimelockKind,
    pub status: PqTimelockStatus,
    pub opened_height: u64,
    pub challenge_until_height: u64,
    pub executable_after_height: u64,
    pub expires_at_height: u64,
    pub min_approval_weight: u64,
    pub observed_approval_weight: u64,
    pub challenge_root: String,
    pub release_root: Option<String>,
    pub metadata: Value,
}

impl PqTimelockWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: &str,
        profile_id: &str,
        kind: PqTimelockKind,
        opened_height: u64,
        challenge_until_height: u64,
        executable_after_height: u64,
        expires_at_height: u64,
        min_approval_weight: u64,
        challenge_root: &str,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(request_id, "request_id")?;
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_positive(min_approval_weight, "min_approval_weight")?;
        ensure_non_empty(challenge_root, "challenge_root")?;
        ensure_height_order(
            opened_height,
            challenge_until_height,
            "timelock opened/challenge",
        )?;
        ensure_height_order(
            challenge_until_height,
            executable_after_height,
            "timelock challenge/executable",
        )?;
        ensure_height_order(
            executable_after_height,
            expires_at_height,
            "timelock executable/expires",
        )?;
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-TIMELOCK-METADATA", metadata);
        let timelock_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-TIMELOCK-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(request_id),
                HashPart::Str(profile_id),
                HashPart::Str(kind.as_str()),
                HashPart::Int(opened_height as i128),
                HashPart::Int(challenge_until_height as i128),
                HashPart::Int(executable_after_height as i128),
                HashPart::Int(expires_at_height as i128),
                HashPart::Int(min_approval_weight as i128),
                HashPart::Str(challenge_root),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let window = Self {
            timelock_id,
            request_id: request_id.to_string(),
            profile_id: profile_id.to_string(),
            kind,
            status: PqTimelockStatus::WaitingForApprovals,
            opened_height,
            challenge_until_height,
            executable_after_height,
            expires_at_height,
            min_approval_weight,
            observed_approval_weight: 0,
            challenge_root: challenge_root.to_string(),
            release_root: None,
            metadata: metadata.clone(),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "timelock_id": self.timelock_id,
            "request_id": self.request_id,
            "profile_id": self.profile_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "challenge_until_height": self.challenge_until_height,
            "executable_after_height": self.executable_after_height,
            "expires_at_height": self.expires_at_height,
            "min_approval_weight": self.min_approval_weight,
            "observed_approval_weight": self.observed_approval_weight,
            "challenge_root": self.challenge_root,
            "release_root": self.release_root,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.timelock_id, "timelock_id")?;
        ensure_non_empty(&self.request_id, "request_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_positive(self.min_approval_weight, "min_approval_weight")?;
        ensure_non_empty(&self.challenge_root, "challenge_root")?;
        ensure_height_order(
            self.opened_height,
            self.challenge_until_height,
            "timelock opened/challenge",
        )?;
        ensure_height_order(
            self.challenge_until_height,
            self.executable_after_height,
            "timelock challenge/executable",
        )?;
        ensure_height_order(
            self.executable_after_height,
            self.expires_at_height,
            "timelock executable/expires",
        )?;
        Ok(())
    }

    pub fn refresh_status(&mut self, height: u64) {
        if matches!(
            self.status,
            PqTimelockStatus::Released | PqTimelockStatus::Cancelled | PqTimelockStatus::Expired
        ) {
            return;
        }
        if height > self.expires_at_height {
            self.status = PqTimelockStatus::Expired;
        } else if self.observed_approval_weight < self.min_approval_weight {
            self.status = PqTimelockStatus::WaitingForApprovals;
        } else if height <= self.challenge_until_height {
            self.status = PqTimelockStatus::ChallengeOpen;
        } else if height >= self.executable_after_height {
            self.status = PqTimelockStatus::Mature;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryRequest {
    pub request_id: String,
    pub profile_id: String,
    pub account_commitment: String,
    pub kind: PqRecoveryRequestKind,
    pub status: PqRecoveryRequestStatus,
    pub requested_by_commitment: String,
    pub new_spend_key_commitment: String,
    pub new_view_key_commitment: String,
    pub destination_contract_commitment: String,
    pub bundle_payload_root: String,
    pub limited_view_key_disclosure_id: Option<String>,
    pub sponsorship_id: Option<String>,
    pub timelock_id: String,
    pub approval_root: String,
    pub freeze_id: Option<String>,
    pub opened_height: u64,
    pub challenge_until_height: u64,
    pub executable_after_height: u64,
    pub expires_at_height: u64,
    pub executed_height: Option<u64>,
    pub rejection_root: Option<String>,
    pub metadata: Value,
}

impl PqRecoveryRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: &PqRecoveryProfile,
        kind: PqRecoveryRequestKind,
        requested_by_commitment: &str,
        new_spend_key_commitment: &str,
        new_view_key_commitment: &str,
        destination_contract_commitment: &str,
        bundle_payload_root: &str,
        limited_view_key_disclosure_id: Option<String>,
        sponsorship_id: Option<String>,
        opened_height: u64,
        challenge_until_height: u64,
        executable_after_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        profile.validate()?;
        ensure_non_empty(requested_by_commitment, "requested_by_commitment")?;
        ensure_non_empty(bundle_payload_root, "bundle_payload_root")?;
        if !matches!(kind, PqRecoveryRequestKind::ViewKeyRecoveryOnly) {
            ensure_non_empty(new_spend_key_commitment, "new_spend_key_commitment")?;
        }
        if kind.requires_view_key_proof() {
            ensure_non_empty(new_view_key_commitment, "new_view_key_commitment")?;
        }
        if kind.is_contract_recovery() {
            ensure_non_empty(
                destination_contract_commitment,
                "destination_contract_commitment",
            )?;
        }
        ensure_height_order(
            opened_height,
            challenge_until_height,
            "request opened/challenge",
        )?;
        ensure_height_order(
            challenge_until_height,
            executable_after_height,
            "request challenge/executable",
        )?;
        ensure_height_order(
            executable_after_height,
            expires_at_height,
            "request executable/expires",
        )?;
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-REQUEST-METADATA", metadata);
        let disclosure_part = limited_view_key_disclosure_id.as_deref().unwrap_or("");
        let sponsorship_part = sponsorship_id.as_deref().unwrap_or("");
        let request_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-REQUEST-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(&profile.profile_id),
                HashPart::Str(&profile.account_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Str(requested_by_commitment),
                HashPart::Str(new_spend_key_commitment),
                HashPart::Str(new_view_key_commitment),
                HashPart::Str(destination_contract_commitment),
                HashPart::Str(bundle_payload_root),
                HashPart::Str(disclosure_part),
                HashPart::Str(sponsorship_part),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let timelock_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-REQUEST-TIMELOCK-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request_id),
                HashPart::Int(challenge_until_height as i128),
                HashPart::Int(executable_after_height as i128),
            ],
            32,
        );
        let approval_root = merkle_root("PQ-ACCOUNT-RECOVERY-REQUEST-APPROVAL-EMPTY", &[]);
        let request = Self {
            request_id,
            profile_id: profile.profile_id.clone(),
            account_commitment: profile.account_commitment.clone(),
            kind,
            status: PqRecoveryRequestStatus::Open,
            requested_by_commitment: requested_by_commitment.to_string(),
            new_spend_key_commitment: new_spend_key_commitment.to_string(),
            new_view_key_commitment: new_view_key_commitment.to_string(),
            destination_contract_commitment: destination_contract_commitment.to_string(),
            bundle_payload_root: bundle_payload_root.to_string(),
            limited_view_key_disclosure_id,
            sponsorship_id,
            timelock_id,
            approval_root,
            freeze_id: None,
            opened_height,
            challenge_until_height,
            executable_after_height,
            expires_at_height,
            executed_height: None,
            rejection_root: None,
            metadata: metadata.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "profile_id": self.profile_id,
            "account_commitment": self.account_commitment,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requested_by_commitment": self.requested_by_commitment,
            "new_spend_key_commitment": self.new_spend_key_commitment,
            "new_view_key_commitment": self.new_view_key_commitment,
            "destination_contract_commitment": self.destination_contract_commitment,
            "bundle_payload_root": self.bundle_payload_root,
            "limited_view_key_disclosure_id": self.limited_view_key_disclosure_id,
            "sponsorship_id": self.sponsorship_id,
            "timelock_id": self.timelock_id,
            "approval_root": self.approval_root,
            "freeze_id": self.freeze_id,
            "opened_height": self.opened_height,
            "challenge_until_height": self.challenge_until_height,
            "executable_after_height": self.executable_after_height,
            "expires_at_height": self.expires_at_height,
            "executed_height": self.executed_height,
            "rejection_root": self.rejection_root,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.request_id, "request_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.account_commitment, "account_commitment")?;
        ensure_non_empty(&self.requested_by_commitment, "requested_by_commitment")?;
        ensure_non_empty(&self.bundle_payload_root, "bundle_payload_root")?;
        ensure_non_empty(&self.timelock_id, "timelock_id")?;
        ensure_non_empty(&self.approval_root, "approval_root")?;
        if !matches!(self.kind, PqRecoveryRequestKind::ViewKeyRecoveryOnly) {
            ensure_non_empty(&self.new_spend_key_commitment, "new_spend_key_commitment")?;
        }
        if self.kind.requires_view_key_proof() {
            ensure_non_empty(&self.new_view_key_commitment, "new_view_key_commitment")?;
        }
        if self.kind.is_contract_recovery() {
            ensure_non_empty(
                &self.destination_contract_commitment,
                "destination_contract_commitment",
            )?;
        }
        ensure_height_order(
            self.opened_height,
            self.challenge_until_height,
            "request opened/challenge",
        )?;
        ensure_height_order(
            self.challenge_until_height,
            self.executable_after_height,
            "request challenge/executable",
        )?;
        ensure_height_order(
            self.executable_after_height,
            self.expires_at_height,
            "request executable/expires",
        )?;
        if let Some(executed_height) = self.executed_height {
            if executed_height < self.executable_after_height {
                return Err("request executed before executable height".to_string());
            }
        }
        Ok(())
    }

    pub fn refresh_status(&mut self, height: u64, timelock: Option<&PqTimelockWindow>) {
        if self.status.is_terminal() {
            return;
        }
        if height > self.expires_at_height {
            self.status = PqRecoveryRequestStatus::Expired;
            return;
        }
        if let Some(timelock) = timelock {
            match timelock.status {
                PqTimelockStatus::WaitingForApprovals => {
                    self.status = PqRecoveryRequestStatus::Open;
                }
                PqTimelockStatus::ChallengeOpen => {
                    self.status = PqRecoveryRequestStatus::Timelocked;
                }
                PqTimelockStatus::Mature => {
                    self.status = PqRecoveryRequestStatus::Ready;
                }
                PqTimelockStatus::Cancelled => {
                    self.status = PqRecoveryRequestStatus::Cancelled;
                }
                PqTimelockStatus::Expired => {
                    self.status = PqRecoveryRequestStatus::Expired;
                }
                PqTimelockStatus::Released => {}
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqEmergencyFreeze {
    pub freeze_id: String,
    pub profile_id: String,
    pub request_id: Option<String>,
    pub scope: PqEmergencyFreezeScope,
    pub status: PqEmergencyFreezeStatus,
    pub reason_code: String,
    pub triggered_by_guardian_id: String,
    pub approval_root: String,
    pub freeze_root: String,
    pub opened_height: u64,
    pub challenge_until_height: u64,
    pub expires_at_height: u64,
    pub lifted_height: Option<u64>,
    pub metadata: Value,
}

impl PqEmergencyFreeze {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        request_id: Option<String>,
        scope: PqEmergencyFreezeScope,
        reason_code: &str,
        triggered_by_guardian_id: &str,
        approval_root: &str,
        opened_height: u64,
        challenge_until_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(reason_code, "reason_code")?;
        ensure_non_empty(triggered_by_guardian_id, "triggered_by_guardian_id")?;
        ensure_non_empty(approval_root, "approval_root")?;
        ensure_height_order(
            opened_height,
            challenge_until_height,
            "freeze opened/challenge",
        )?;
        ensure_height_order(
            challenge_until_height,
            expires_at_height,
            "freeze challenge/expires",
        )?;
        let request_part = request_id.as_deref().unwrap_or("");
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-FREEZE-METADATA", metadata);
        let freeze_root = domain_hash(
            "PQ-ACCOUNT-RECOVERY-FREEZE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(profile_id),
                HashPart::Str(request_part),
                HashPart::Str(scope.as_str()),
                HashPart::Str(reason_code),
                HashPart::Str(triggered_by_guardian_id),
                HashPart::Str(approval_root),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let freeze_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-FREEZE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(&freeze_root),
                HashPart::Int(expires_at_height as i128),
            ],
            32,
        );
        let freeze = Self {
            freeze_id,
            profile_id: profile_id.to_string(),
            request_id,
            scope,
            status: PqEmergencyFreezeStatus::Active,
            reason_code: reason_code.to_string(),
            triggered_by_guardian_id: triggered_by_guardian_id.to_string(),
            approval_root: approval_root.to_string(),
            freeze_root,
            opened_height,
            challenge_until_height,
            expires_at_height,
            lifted_height: None,
            metadata: metadata.clone(),
        };
        freeze.validate()?;
        Ok(freeze)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "freeze_id": self.freeze_id,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "reason_code": self.reason_code,
            "triggered_by_guardian_id": self.triggered_by_guardian_id,
            "approval_root": self.approval_root,
            "freeze_root": self.freeze_root,
            "opened_height": self.opened_height,
            "challenge_until_height": self.challenge_until_height,
            "expires_at_height": self.expires_at_height,
            "lifted_height": self.lifted_height,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.freeze_id, "freeze_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.reason_code, "reason_code")?;
        ensure_non_empty(&self.triggered_by_guardian_id, "triggered_by_guardian_id")?;
        ensure_non_empty(&self.approval_root, "approval_root")?;
        ensure_non_empty(&self.freeze_root, "freeze_root")?;
        ensure_height_order(
            self.opened_height,
            self.challenge_until_height,
            "freeze opened/challenge",
        )?;
        ensure_height_order(
            self.challenge_until_height,
            self.expires_at_height,
            "freeze challenge/expires",
        )?;
        if let Some(lifted_height) = self.lifted_height {
            if lifted_height < self.opened_height {
                return Err("freeze lifted before opened".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerRotation {
    pub rotation_id: String,
    pub profile_id: String,
    pub request_id: String,
    pub previous_spend_key_root: String,
    pub next_spend_key_commitment: String,
    pub previous_view_key_commitment: String,
    pub next_view_key_commitment: String,
    pub hardware_policy_id: Option<String>,
    pub approval_root: String,
    pub status: PqSignerRotationStatus,
    pub announced_height: u64,
    pub effective_height: u64,
    pub expires_at_height: u64,
    pub executed_height: Option<u64>,
    pub metadata: Value,
}

impl PqSignerRotation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        request_id: &str,
        previous_spend_key_root: &str,
        next_spend_key_commitment: &str,
        previous_view_key_commitment: &str,
        next_view_key_commitment: &str,
        hardware_policy_id: Option<String>,
        approval_root: &str,
        announced_height: u64,
        effective_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(request_id, "request_id")?;
        ensure_non_empty(previous_spend_key_root, "previous_spend_key_root")?;
        ensure_non_empty(next_spend_key_commitment, "next_spend_key_commitment")?;
        ensure_non_empty(previous_view_key_commitment, "previous_view_key_commitment")?;
        ensure_non_empty(next_view_key_commitment, "next_view_key_commitment")?;
        ensure_non_empty(approval_root, "approval_root")?;
        ensure_height_order(
            announced_height,
            effective_height,
            "rotation announced/effective",
        )?;
        ensure_height_order(
            effective_height,
            expires_at_height,
            "rotation effective/expires",
        )?;
        let hardware_policy_part = hardware_policy_id.as_deref().unwrap_or("");
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-ROTATION-METADATA", metadata);
        let rotation_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-SIGNER-ROTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(profile_id),
                HashPart::Str(request_id),
                HashPart::Str(previous_spend_key_root),
                HashPart::Str(next_spend_key_commitment),
                HashPart::Str(previous_view_key_commitment),
                HashPart::Str(next_view_key_commitment),
                HashPart::Str(hardware_policy_part),
                HashPart::Str(approval_root),
                HashPart::Int(announced_height as i128),
                HashPart::Int(effective_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let rotation = Self {
            rotation_id,
            profile_id: profile_id.to_string(),
            request_id: request_id.to_string(),
            previous_spend_key_root: previous_spend_key_root.to_string(),
            next_spend_key_commitment: next_spend_key_commitment.to_string(),
            previous_view_key_commitment: previous_view_key_commitment.to_string(),
            next_view_key_commitment: next_view_key_commitment.to_string(),
            hardware_policy_id,
            approval_root: approval_root.to_string(),
            status: PqSignerRotationStatus::WaitingForTimelock,
            announced_height,
            effective_height,
            expires_at_height,
            executed_height: None,
            metadata: metadata.clone(),
        };
        rotation.validate()?;
        Ok(rotation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "previous_spend_key_root": self.previous_spend_key_root,
            "next_spend_key_commitment": self.next_spend_key_commitment,
            "previous_view_key_commitment": self.previous_view_key_commitment,
            "next_view_key_commitment": self.next_view_key_commitment,
            "hardware_policy_id": self.hardware_policy_id,
            "approval_root": self.approval_root,
            "status": self.status.as_str(),
            "announced_height": self.announced_height,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
            "executed_height": self.executed_height,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.rotation_id, "rotation_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.request_id, "request_id")?;
        ensure_non_empty(&self.previous_spend_key_root, "previous_spend_key_root")?;
        ensure_non_empty(&self.next_spend_key_commitment, "next_spend_key_commitment")?;
        ensure_non_empty(
            &self.previous_view_key_commitment,
            "previous_view_key_commitment",
        )?;
        ensure_non_empty(&self.next_view_key_commitment, "next_view_key_commitment")?;
        ensure_non_empty(&self.approval_root, "approval_root")?;
        ensure_height_order(
            self.announced_height,
            self.effective_height,
            "rotation announced/effective",
        )?;
        ensure_height_order(
            self.effective_height,
            self.expires_at_height,
            "rotation effective/expires",
        )?;
        if let Some(executed_height) = self.executed_height {
            if executed_height < self.effective_height {
                return Err("rotation executed before effective height".to_string());
            }
        }
        Ok(())
    }

    pub fn refresh_status(&mut self, height: u64) {
        if matches!(
            self.status,
            PqSignerRotationStatus::Applied
                | PqSignerRotationStatus::Superseded
                | PqSignerRotationStatus::Rejected
                | PqSignerRotationStatus::Expired
        ) {
            return;
        }
        if height > self.expires_at_height {
            self.status = PqSignerRotationStatus::Expired;
        } else if height >= self.effective_height {
            self.status = PqSignerRotationStatus::Ready;
        } else {
            self.status = PqSignerRotationStatus::WaitingForTimelock;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLimitedViewKeyDisclosure {
    pub disclosure_id: String,
    pub profile_id: String,
    pub request_id: Option<String>,
    pub scope: PqLimitedViewKeyScope,
    pub status: PqLimitedViewKeyDisclosureStatus,
    pub subject_commitment: String,
    pub delegated_view_key_commitment: String,
    pub scan_window_start_height: u64,
    pub scan_window_end_height: u64,
    pub allowed_label_root: String,
    pub proof_system: String,
    pub disclosure_proof_root: String,
    pub verifier_committee_root: String,
    pub encrypted_payload_hash: String,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub disclosure_nullifier: String,
    pub metadata: Value,
}

impl PqLimitedViewKeyDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        request_id: Option<String>,
        scope: PqLimitedViewKeyScope,
        subject_commitment: &str,
        delegated_view_key_commitment: &str,
        scan_window_start_height: u64,
        scan_window_end_height: u64,
        allowed_label_root: &str,
        proof_system: &str,
        disclosure_proof_root: &str,
        verifier_committee_root: &str,
        encrypted_payload_hash: &str,
        opened_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(subject_commitment, "subject_commitment")?;
        ensure_non_empty(
            delegated_view_key_commitment,
            "delegated_view_key_commitment",
        )?;
        ensure_height_order(
            scan_window_start_height,
            scan_window_end_height,
            "disclosure scan window",
        )?;
        ensure_non_empty(allowed_label_root, "allowed_label_root")?;
        ensure_non_empty(proof_system, "proof_system")?;
        ensure_non_empty(disclosure_proof_root, "disclosure_proof_root")?;
        ensure_non_empty(verifier_committee_root, "verifier_committee_root")?;
        ensure_non_empty(encrypted_payload_hash, "encrypted_payload_hash")?;
        ensure_height_order(
            opened_height,
            expires_at_height,
            "disclosure opened/expires",
        )?;
        let request_part = request_id.as_deref().unwrap_or("");
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-DISCLOSURE-METADATA", metadata);
        let disclosure_nullifier = domain_hash(
            "PQ-ACCOUNT-RECOVERY-DISCLOSURE-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(profile_id),
                HashPart::Str(request_part),
                HashPart::Str(scope.as_str()),
                HashPart::Str(subject_commitment),
                HashPart::Str(delegated_view_key_commitment),
                HashPart::Int(scan_window_start_height as i128),
                HashPart::Int(scan_window_end_height as i128),
            ],
            32,
        );
        let disclosure_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-DISCLOSURE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(&disclosure_nullifier),
                HashPart::Str(disclosure_proof_root),
                HashPart::Str(encrypted_payload_hash),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let disclosure = Self {
            disclosure_id,
            profile_id: profile_id.to_string(),
            request_id,
            scope,
            status: PqLimitedViewKeyDisclosureStatus::Approved,
            subject_commitment: subject_commitment.to_string(),
            delegated_view_key_commitment: delegated_view_key_commitment.to_string(),
            scan_window_start_height,
            scan_window_end_height,
            allowed_label_root: allowed_label_root.to_string(),
            proof_system: proof_system.to_string(),
            disclosure_proof_root: disclosure_proof_root.to_string(),
            verifier_committee_root: verifier_committee_root.to_string(),
            encrypted_payload_hash: encrypted_payload_hash.to_string(),
            opened_height,
            expires_at_height,
            disclosure_nullifier,
            metadata: metadata.clone(),
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "subject_commitment": self.subject_commitment,
            "delegated_view_key_commitment": self.delegated_view_key_commitment,
            "scan_window_start_height": self.scan_window_start_height,
            "scan_window_end_height": self.scan_window_end_height,
            "allowed_label_root": self.allowed_label_root,
            "proof_system": self.proof_system,
            "disclosure_proof_root": self.disclosure_proof_root,
            "verifier_committee_root": self.verifier_committee_root,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "disclosure_nullifier": self.disclosure_nullifier,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.disclosure_id, "disclosure_id")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.subject_commitment, "subject_commitment")?;
        ensure_non_empty(
            &self.delegated_view_key_commitment,
            "delegated_view_key_commitment",
        )?;
        ensure_height_order(
            self.scan_window_start_height,
            self.scan_window_end_height,
            "disclosure scan window",
        )?;
        ensure_non_empty(&self.allowed_label_root, "allowed_label_root")?;
        ensure_non_empty(&self.proof_system, "proof_system")?;
        ensure_non_empty(&self.disclosure_proof_root, "disclosure_proof_root")?;
        ensure_non_empty(&self.verifier_committee_root, "verifier_committee_root")?;
        ensure_non_empty(&self.encrypted_payload_hash, "encrypted_payload_hash")?;
        ensure_non_empty(&self.disclosure_nullifier, "disclosure_nullifier")?;
        ensure_height_order(
            self.opened_height,
            self.expires_at_height,
            "disclosure opened/expires",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub profile_id: Option<String>,
    pub request_id: Option<String>,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_units: u64,
    pub rebate_bps: u64,
    pub lane_id: String,
    pub privacy_pool_root: String,
    pub eligibility_root: String,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub status: PqRecoveryFeeSponsorshipStatus,
    pub metadata: Value,
}

impl PqRecoveryFeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        profile_id: Option<String>,
        request_id: Option<String>,
        fee_asset_id: &str,
        budget_units: u64,
        max_fee_units: u64,
        rebate_bps: u64,
        lane_id: &str,
        privacy_pool_root: &str,
        eligibility_root: &str,
        opened_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(fee_asset_id, "fee_asset_id")?;
        ensure_positive(budget_units, "budget_units")?;
        ensure_positive(max_fee_units, "max_fee_units")?;
        validate_bps(rebate_bps, "rebate_bps")?;
        ensure_non_empty(lane_id, "lane_id")?;
        ensure_non_empty(privacy_pool_root, "privacy_pool_root")?;
        ensure_non_empty(eligibility_root, "eligibility_root")?;
        ensure_height_order(
            opened_height,
            expires_at_height,
            "sponsorship opened/expires",
        )?;
        let profile_part = profile_id.as_deref().unwrap_or("");
        let request_part = request_id.as_deref().unwrap_or("");
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-SPONSORSHIP-METADATA", metadata);
        let sponsorship_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-SPONSORSHIP-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(sponsor_commitment),
                HashPart::Str(profile_part),
                HashPart::Str(request_part),
                HashPart::Str(fee_asset_id),
                HashPart::Int(budget_units as i128),
                HashPart::Int(max_fee_units as i128),
                HashPart::Int(rebate_bps as i128),
                HashPart::Str(lane_id),
                HashPart::Str(privacy_pool_root),
                HashPart::Str(eligibility_root),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            profile_id,
            request_id,
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            spent_units: 0,
            max_fee_units,
            rebate_bps,
            lane_id: lane_id.to_string(),
            privacy_pool_root: privacy_pool_root.to_string(),
            eligibility_root: eligibility_root.to_string(),
            opened_height,
            expires_at_height,
            status: PqRecoveryFeeSponsorshipStatus::Offered,
            metadata: metadata.clone(),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "profile_id": self.profile_id,
            "request_id": self.request_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_fee_units": self.max_fee_units,
            "rebate_bps": self.rebate_bps,
            "lane_id": self.lane_id,
            "privacy_pool_root": self.privacy_pool_root,
            "eligibility_root": self.eligibility_root,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship_id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_positive(self.budget_units, "budget_units")?;
        ensure_positive(self.max_fee_units, "max_fee_units")?;
        validate_bps(self.rebate_bps, "rebate_bps")?;
        ensure_non_empty(&self.lane_id, "lane_id")?;
        ensure_non_empty(&self.privacy_pool_root, "privacy_pool_root")?;
        ensure_non_empty(&self.eligibility_root, "eligibility_root")?;
        ensure_height_order(
            self.opened_height,
            self.expires_at_height,
            "sponsorship opened/expires",
        )?;
        if self.spent_units > self.budget_units {
            return Err("sponsorship spent_units exceeds budget_units".to_string());
        }
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn spend(&mut self, units: u64) -> PqAccountRecoveryResult<()> {
        ensure_positive(units, "spend units")?;
        if units > self.max_fee_units {
            return Err("fee spend exceeds max_fee_units".to_string());
        }
        if units > self.remaining_units() {
            return Err("fee spend exceeds remaining sponsorship budget".to_string());
        }
        self.spent_units = self
            .spent_units
            .checked_add(units)
            .ok_or_else(|| "sponsorship spent_units overflow".to_string())?;
        self.status = if self.spent_units == self.budget_units {
            PqRecoveryFeeSponsorshipStatus::Settled
        } else {
            PqRecoveryFeeSponsorshipStatus::PartiallySpent
        };
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryAuditReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub height: u64,
    pub event_kind: PqRecoveryAuditEventKind,
    pub actor_commitment: String,
    pub subject_id: String,
    pub subject_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub metadata: Value,
}

impl PqRecoveryAuditReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        height: u64,
        event_kind: PqRecoveryAuditEventKind,
        actor_commitment: &str,
        subject_id: &str,
        subject_root: &str,
        state_root_before: &str,
        state_root_after: &str,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(actor_commitment, "actor_commitment")?;
        ensure_non_empty(subject_id, "subject_id")?;
        ensure_non_empty(subject_root, "subject_root")?;
        ensure_non_empty(state_root_before, "state_root_before")?;
        ensure_non_empty(state_root_after, "state_root_after")?;
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-AUDIT-METADATA", metadata);
        let receipt_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-AUDIT-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Int(sequence as i128),
                HashPart::Int(height as i128),
                HashPart::Str(event_kind.as_str()),
                HashPart::Str(actor_commitment),
                HashPart::Str(subject_id),
                HashPart::Str(subject_root),
                HashPart::Str(state_root_before),
                HashPart::Str(state_root_after),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let receipt = Self {
            receipt_id,
            sequence,
            height,
            event_kind,
            actor_commitment: actor_commitment.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            metadata: metadata.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.event_kind.as_str(),
            "actor_commitment": self.actor_commitment,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt_id")?;
        ensure_non_empty(&self.actor_commitment, "actor_commitment")?;
        ensure_non_empty(&self.subject_id, "subject_id")?;
        ensure_non_empty(&self.subject_root, "subject_root")?;
        ensure_non_empty(&self.state_root_before, "state_root_before")?;
        ensure_non_empty(&self.state_root_after, "state_root_after")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAccountRecoveryDevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub account_commitment: String,
    pub profile_id: String,
    pub guardian_ids: Vec<String>,
    pub hardware_policy_ids: Vec<String>,
    pub request_ids: Vec<String>,
    pub sponsorship_ids: Vec<String>,
    pub disclosure_ids: Vec<String>,
    pub expected_state_root: String,
    pub generated_at_height: u64,
    pub metadata: Value,
}

impl PqAccountRecoveryDevnetFixture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        account_commitment: &str,
        profile_id: &str,
        guardian_ids: Vec<String>,
        hardware_policy_ids: Vec<String>,
        request_ids: Vec<String>,
        sponsorship_ids: Vec<String>,
        disclosure_ids: Vec<String>,
        expected_state_root: &str,
        generated_at_height: u64,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<Self> {
        ensure_non_empty(label, "label")?;
        ensure_non_empty(account_commitment, "account_commitment")?;
        ensure_non_empty(profile_id, "profile_id")?;
        ensure_non_empty(expected_state_root, "expected_state_root")?;
        ensure_unique_strings(&guardian_ids, "fixture guardian_ids")?;
        ensure_unique_strings(&hardware_policy_ids, "fixture hardware_policy_ids")?;
        ensure_unique_strings(&request_ids, "fixture request_ids")?;
        ensure_unique_strings(&sponsorship_ids, "fixture sponsorship_ids")?;
        ensure_unique_strings(&disclosure_ids, "fixture disclosure_ids")?;
        let metadata_root =
            pq_account_recovery_payload_root("PQ-ACCOUNT-RECOVERY-FIXTURE-METADATA", metadata);
        let guardian_root = merkle_root(
            "PQ-ACCOUNT-RECOVERY-FIXTURE-GUARDIAN",
            &guardian_ids
                .iter()
                .map(|id| Value::String(id.clone()))
                .collect::<Vec<_>>(),
        );
        let fixture_id = domain_hash(
            "PQ-ACCOUNT-RECOVERY-FIXTURE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(account_commitment),
                HashPart::Str(profile_id),
                HashPart::Str(&guardian_root),
                HashPart::Str(expected_state_root),
                HashPart::Int(generated_at_height as i128),
                HashPart::Str(&metadata_root),
            ],
            32,
        );
        let fixture = Self {
            fixture_id,
            label: label.to_string(),
            account_commitment: account_commitment.to_string(),
            profile_id: profile_id.to_string(),
            guardian_ids,
            hardware_policy_ids,
            request_ids,
            sponsorship_ids,
            disclosure_ids,
            expected_state_root: expected_state_root.to_string(),
            generated_at_height,
            metadata: metadata.clone(),
        };
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "account_commitment": self.account_commitment,
            "profile_id": self.profile_id,
            "guardian_ids": self.guardian_ids,
            "hardware_policy_ids": self.hardware_policy_ids,
            "request_ids": self.request_ids,
            "sponsorship_ids": self.sponsorship_ids,
            "disclosure_ids": self.disclosure_ids,
            "expected_state_root": self.expected_state_root,
            "generated_at_height": self.generated_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<()> {
        ensure_non_empty(&self.fixture_id, "fixture_id")?;
        ensure_non_empty(&self.label, "label")?;
        ensure_non_empty(&self.account_commitment, "account_commitment")?;
        ensure_non_empty(&self.profile_id, "profile_id")?;
        ensure_non_empty(&self.expected_state_root, "expected_state_root")?;
        ensure_unique_strings(&self.guardian_ids, "fixture guardian_ids")?;
        ensure_unique_strings(&self.hardware_policy_ids, "fixture hardware_policy_ids")?;
        ensure_unique_strings(&self.request_ids, "fixture request_ids")?;
        ensure_unique_strings(&self.sponsorship_ids, "fixture sponsorship_ids")?;
        ensure_unique_strings(&self.disclosure_ids, "fixture disclosure_ids")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAccountRecoveryRoots {
    pub config_root: String,
    pub recovery_profile_root: String,
    pub pq_guardian_root: String,
    pub hardware_signer_policy_root: String,
    pub guardian_approval_root: String,
    pub recovery_request_root: String,
    pub timelock_window_root: String,
    pub emergency_freeze_root: String,
    pub signer_rotation_root: String,
    pub limited_view_key_disclosure_root: String,
    pub recovery_fee_sponsorship_root: String,
    pub audit_receipt_root: String,
    pub devnet_fixture_root: String,
}

impl PqAccountRecoveryRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "recovery_profile_root": self.recovery_profile_root,
            "pq_guardian_root": self.pq_guardian_root,
            "hardware_signer_policy_root": self.hardware_signer_policy_root,
            "guardian_approval_root": self.guardian_approval_root,
            "recovery_request_root": self.recovery_request_root,
            "timelock_window_root": self.timelock_window_root,
            "emergency_freeze_root": self.emergency_freeze_root,
            "signer_rotation_root": self.signer_rotation_root,
            "limited_view_key_disclosure_root": self.limited_view_key_disclosure_root,
            "recovery_fee_sponsorship_root": self.recovery_fee_sponsorship_root,
            "audit_receipt_root": self.audit_receipt_root,
            "devnet_fixture_root": self.devnet_fixture_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAccountRecoveryCounters {
    pub current_height: u64,
    pub recovery_profiles: u64,
    pub pq_guardians: u64,
    pub hardware_signer_policies: u64,
    pub guardian_approvals: u64,
    pub recovery_requests_total: u64,
    pub recovery_requests_active: u64,
    pub recovery_requests_ready: u64,
    pub timelock_windows_active: u64,
    pub emergency_freezes_active: u64,
    pub signer_rotations_active: u64,
    pub limited_view_key_disclosures_active: u64,
    pub recovery_fee_sponsorships_active: u64,
    pub audit_receipts: u64,
    pub devnet_fixtures: u64,
    pub total_sponsored_fee_units: u64,
}

impl PqAccountRecoveryCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "current_height": self.current_height,
            "recovery_profiles": self.recovery_profiles,
            "pq_guardians": self.pq_guardians,
            "hardware_signer_policies": self.hardware_signer_policies,
            "guardian_approvals": self.guardian_approvals,
            "recovery_requests_total": self.recovery_requests_total,
            "recovery_requests_active": self.recovery_requests_active,
            "recovery_requests_ready": self.recovery_requests_ready,
            "timelock_windows_active": self.timelock_windows_active,
            "emergency_freezes_active": self.emergency_freezes_active,
            "signer_rotations_active": self.signer_rotations_active,
            "limited_view_key_disclosures_active": self.limited_view_key_disclosures_active,
            "recovery_fee_sponsorships_active": self.recovery_fee_sponsorships_active,
            "audit_receipts": self.audit_receipts,
            "devnet_fixtures": self.devnet_fixtures,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAccountRecoveryState {
    pub height: u64,
    pub config: PqAccountRecoveryConfig,
    pub recovery_profiles: BTreeMap<String, PqRecoveryProfile>,
    pub pq_guardians: BTreeMap<String, PqGuardian>,
    pub hardware_signer_policies: BTreeMap<String, PqHardwareSignerPolicy>,
    pub guardian_approvals: BTreeMap<String, PqGuardianApproval>,
    pub recovery_requests: BTreeMap<String, PqRecoveryRequest>,
    pub timelock_windows: BTreeMap<String, PqTimelockWindow>,
    pub emergency_freezes: BTreeMap<String, PqEmergencyFreeze>,
    pub signer_rotations: BTreeMap<String, PqSignerRotation>,
    pub limited_view_key_disclosures: BTreeMap<String, PqLimitedViewKeyDisclosure>,
    pub recovery_fee_sponsorships: BTreeMap<String, PqRecoveryFeeSponsorship>,
    pub audit_receipts: BTreeMap<String, PqRecoveryAuditReceipt>,
    pub devnet_fixtures: BTreeMap<String, PqAccountRecoveryDevnetFixture>,
}

impl Default for PqAccountRecoveryState {
    fn default() -> Self {
        Self::new(PqAccountRecoveryConfig::default(), 0)
            .expect("default pq account recovery config validates")
    }
}

impl PqAccountRecoveryState {
    pub fn new(config: PqAccountRecoveryConfig, height: u64) -> PqAccountRecoveryResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            config,
            recovery_profiles: BTreeMap::new(),
            pq_guardians: BTreeMap::new(),
            hardware_signer_policies: BTreeMap::new(),
            guardian_approvals: BTreeMap::new(),
            recovery_requests: BTreeMap::new(),
            timelock_windows: BTreeMap::new(),
            emergency_freezes: BTreeMap::new(),
            signer_rotations: BTreeMap::new(),
            limited_view_key_disclosures: BTreeMap::new(),
            recovery_fee_sponsorships: BTreeMap::new(),
            audit_receipts: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PqAccountRecoveryResult<Self> {
        let mut state = Self::new(PqAccountRecoveryConfig::default(), 64)?;
        let actor = "devnet-pq-account-recovery-operator";

        let account_commitment = pq_account_recovery_string_root(
            "PQ-ACCOUNT-RECOVERY-DEVNET-ACCOUNT",
            "devnet-private-wallet-alpha",
        );
        let owner_root = pq_account_recovery_string_root(
            "PQ-ACCOUNT-RECOVERY-DEVNET-OWNER",
            "devnet-owner-commitment",
        );
        let spend_key_root = pq_account_recovery_string_root(
            "PQ-ACCOUNT-RECOVERY-DEVNET-SPEND-KEY",
            "devnet-spend-key-v1",
        );
        let view_key_commitment = pq_account_recovery_string_root(
            "PQ-ACCOUNT-RECOVERY-DEVNET-VIEW-KEY",
            "devnet-view-key-v1",
        );
        let wallet_policy_root = pq_account_recovery_string_root(
            "PQ-ACCOUNT-RECOVERY-DEVNET-WALLET-POLICY",
            "devnet-wallet-policy-root",
        );
        let empty_guardian_set_root =
            merkle_root("PQ-ACCOUNT-RECOVERY-DEVNET-EMPTY-GUARDIANS", &[]);
        let quorum_policy = PqRecoveryQuorumPolicy::new(
            "devnet-private-wallet-alpha",
            state.config.default_min_approval_weight,
            state.config.default_threshold_weight,
            state.config.default_min_distinct_guardians,
            vec![
                PqGuardianRole::SocialRecovery,
                PqGuardianRole::SignerRotation,
                PqGuardianRole::ViewKeyWitness,
            ],
            true,
            true,
            state.config.default_challenge_blocks,
            state.config.default_recovery_delay_blocks,
            &json!({
                "route": "private-wallet-social-recovery",
                "slh_dsa_guardian_required_for_freeze": true,
                "hardware_attestation_required_for_execution": true,
            }),
        )?;
        let profile = PqRecoveryProfile::new(
            &account_commitment,
            PqRecoveryAccountKind::PrivateWallet,
            &wallet_policy_root,
            "",
            &owner_root,
            &spend_key_root,
            &view_key_commitment,
            &empty_guardian_set_root,
            quorum_policy,
            state.height,
            state.height + 525_600,
            &json!({
                "label": "devnet-private-wallet-alpha",
                "privacy_mode": "shielded-account",
                "preferred_fee_lane": "low-fee-private-recovery",
            }),
        )?;
        let profile_id = state.insert_recovery_profile(profile, actor)?;

        let hardware_policy = PqHardwareSignerPolicy::new(
            &profile_id,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-HARDWARE-LABEL",
                "devnet-coldcard-pq",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-HARDWARE-VENDOR",
                "nebula-labs-devnet",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-FIRMWARE",
                "firmware-v0.9.0-pq",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-SECURE-ELEMENT",
                "secure-element-devnet",
            ),
            vec![
                PqGuardianAlgorithm::HardwareAttestedMlDsa,
                PqGuardianAlgorithm::MlDsa65,
            ],
            true,
            true,
            true,
            1_000_000,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-HARDWARE-ATTESTATION",
                "devnet-supply-chain-attestation",
            ),
            state.height,
            state.height + 525_600,
            &json!({
                "anti_exfiltration": "host_nonce_and_device_nonce",
                "screen_verification": true,
                "offline_qr": true,
            }),
        )?;
        let hardware_policy_id = state.insert_hardware_signer_policy(hardware_policy, actor)?;

        let guardian_a = PqGuardian::new(
            &profile_id,
            PqGuardianRole::SocialRecovery,
            PqGuardianAlgorithm::MlDsa65,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-GUARDIAN-A-KEY",
                "guardian-a-ml-dsa-65",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-GUARDIAN-A-POP",
                "guardian-a-proof-of-possession",
            ),
            None,
            32,
            1,
            state.height,
            state.height + 525_600,
            &json!({"label": "guardian-a", "transport": "sealed-relay"}),
        )?;
        let guardian_b = PqGuardian::new(
            &profile_id,
            PqGuardianRole::SignerRotation,
            PqGuardianAlgorithm::SlhDsaShake128s,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-GUARDIAN-B-KEY",
                "guardian-b-slh-dsa-shake-128s",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-GUARDIAN-B-POP",
                "guardian-b-proof-of-possession",
            ),
            None,
            16,
            1,
            state.height,
            state.height + 525_600,
            &json!({"label": "guardian-b", "stateless_hash_signatures": true}),
        )?;
        let guardian_c = PqGuardian::new(
            &profile_id,
            PqGuardianRole::HardwareCoSigner,
            PqGuardianAlgorithm::HardwareAttestedMlDsa,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-GUARDIAN-C-KEY",
                "guardian-c-hardware-ml-dsa",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-GUARDIAN-C-POP",
                "guardian-c-hardware-proof-of-possession",
            ),
            Some(hardware_policy_id.clone()),
            8,
            1,
            state.height,
            state.height + 525_600,
            &json!({"label": "guardian-c", "hardware_attested": true}),
        )?;
        let guardian_a_id = state.insert_pq_guardian(guardian_a, actor)?;
        let guardian_b_id = state.insert_pq_guardian(guardian_b, actor)?;
        let guardian_c_id = state.insert_pq_guardian(guardian_c, actor)?;
        state.refresh_profile_guardian_set_root(&profile_id)?;

        let disclosure = PqLimitedViewKeyDisclosure::new(
            &profile_id,
            None,
            PqLimitedViewKeyScope::RecoveryEvidence,
            &account_commitment,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-DELEGATED-VIEW-KEY",
                "delegated-view-key-recovery-proof",
            ),
            state.height.saturating_sub(32),
            state.height + 288,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-LABEL-ROOT",
                "labels:deposits,defi,bridge",
            ),
            "plonkish-limited-view-key-proof-devnet",
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-DISCLOSURE-PROOF",
                "limited-view-key-proof",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-DISCLOSURE-VERIFIER",
                "view-key-verifier-committee",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-DISCLOSURE-CIPHERTEXT",
                "encrypted-disclosure-payload",
            ),
            state.height,
            state.height + state.config.default_disclosure_ttl_blocks,
            &json!({
                "purpose": "prove wallet ownership without revealing spend authority",
                "nullifier_scope": "devnet-request",
            }),
        )?;
        let disclosure_id = state.insert_limited_view_key_disclosure(disclosure, actor)?;

        let sponsorship = PqRecoveryFeeSponsorship::new(
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-SPONSOR",
                "devnet-private-paymaster",
            ),
            Some(profile_id.clone()),
            None,
            PQ_ACCOUNT_RECOVERY_DEVNET_FEE_ASSET_ID,
            50_000,
            2_500,
            state.config.min_sponsor_rebate_bps,
            "devnet-low-fee-recovery-lane",
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-SPONSOR-POOL",
                "privacy-pool-root",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-SPONSOR-ELIGIBILITY",
                "recovery-eligibility-root",
            ),
            state.height,
            state.height + state.config.default_sponsorship_ttl_blocks,
            &json!({"policy": "first-recovery-free", "max_priority_fee": 100}),
        )?;
        let sponsorship_id = state.insert_recovery_fee_sponsorship(sponsorship, actor)?;

        let profile = state
            .recovery_profiles
            .get(&profile_id)
            .ok_or_else(|| "missing devnet profile".to_string())?
            .clone();
        let request = PqRecoveryRequest::new(
            &profile,
            PqRecoveryRequestKind::WalletFullKeyRecovery,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-REQUESTER",
                "devnet-wallet-owner-recovery-device",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-NEXT-SPEND-KEY",
                "devnet-spend-key-v2",
            ),
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-NEXT-VIEW-KEY",
                "devnet-view-key-v2",
            ),
            "",
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-BUNDLE",
                "timelocked-recovery-bundle",
            ),
            Some(disclosure_id.clone()),
            Some(sponsorship_id.clone()),
            state.height,
            state.height + state.config.default_challenge_blocks,
            state.height + state.config.default_recovery_delay_blocks,
            state.height + state.config.default_request_ttl_blocks,
            &json!({
                "bundle_kind": "wallet-full-key-recovery",
                "private_relay": true,
                "guardians": ["guardian-a", "guardian-b", "guardian-c"],
            }),
        )?;
        let request_id = state.open_recovery_request(request, actor)?;
        let timelock = PqTimelockWindow::new(
            &request_id,
            &profile_id,
            PqTimelockKind::StandardRecovery,
            state.height,
            state.height + state.config.default_challenge_blocks,
            state.height + state.config.default_recovery_delay_blocks,
            state.height + state.config.default_request_ttl_blocks,
            state.config.default_threshold_weight,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-CHALLENGE-ROOT",
                "challenge-window-open",
            ),
            &json!({"watchtower": "devnet-watchtower", "grace_blocks": 12}),
        )?;
        let timelock_id = state.insert_timelock_window(timelock, actor)?;
        if let Some(request) = state.recovery_requests.get_mut(&request_id) {
            request.timelock_id = timelock_id;
        }

        let signed_message_root = state.recovery_request_transcript_root(&request_id)?;
        let approval_a = PqGuardianApproval::new(
            &profile_id,
            &request_id,
            &guardian_a_id,
            PqApprovalPurpose::RecoveryOpen,
            1,
            &signed_message_root,
            PQ_ACCOUNT_RECOVERY_ML_DSA_65,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-APPROVAL-A-SIG",
                "guardian-a-signature",
            ),
            None,
            state.height + 1,
            state.height + state.config.default_request_ttl_blocks,
            &json!({"channel": "sealed-relay", "guardian": "a"}),
        )?;
        let approval_b = PqGuardianApproval::new(
            &profile_id,
            &request_id,
            &guardian_b_id,
            PqApprovalPurpose::RecoveryOpen,
            1,
            &signed_message_root,
            PQ_ACCOUNT_RECOVERY_SLH_DSA_SHAKE_128S,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-APPROVAL-B-SIG",
                "guardian-b-signature",
            ),
            None,
            state.height + 2,
            state.height + state.config.default_request_ttl_blocks,
            &json!({"channel": "airgapped-qr", "guardian": "b"}),
        )?;
        let approval_c = PqGuardianApproval::new(
            &profile_id,
            &request_id,
            &guardian_c_id,
            PqApprovalPurpose::RecoveryExecute,
            1,
            &signed_message_root,
            PQ_ACCOUNT_RECOVERY_HARDWARE_ATTESTED_ML_DSA,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-APPROVAL-C-SIG",
                "guardian-c-signature",
            ),
            Some(hardware_policy_id.clone()),
            state.height + 3,
            state.height + state.config.default_request_ttl_blocks,
            &json!({"channel": "hardware-offline", "guardian": "c"}),
        )?;
        state.record_guardian_approval(approval_a, actor)?;
        state.record_guardian_approval(approval_b, actor)?;
        state.record_guardian_approval(approval_c, actor)?;

        let freeze = PqEmergencyFreeze::new(
            &profile_id,
            Some(request_id.clone()),
            PqEmergencyFreezeScope::SpendOnly,
            "owner-reported-device-loss",
            &guardian_c_id,
            &state.approval_root_for_request(&request_id),
            state.height + 4,
            state.height + 4 + state.config.default_challenge_blocks,
            state.height + 4 + state.config.default_freeze_ttl_blocks,
            &json!({
                "privacy_preserving_reason": "device-loss",
                "auto_lift_after_rotation": true,
            }),
        )?;
        let freeze_id = state.insert_emergency_freeze(freeze, actor)?;
        if let Some(request) = state.recovery_requests.get_mut(&request_id) {
            request.freeze_id = Some(freeze_id.clone());
        }

        let rotation = PqSignerRotation::new(
            &profile_id,
            &request_id,
            &spend_key_root,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-NEXT-SPEND-KEY",
                "devnet-spend-key-v2",
            ),
            &view_key_commitment,
            &pq_account_recovery_string_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-NEXT-VIEW-KEY",
                "devnet-view-key-v2",
            ),
            Some(hardware_policy_id.clone()),
            &state.approval_root_for_request(&request_id),
            state.height + 4,
            state.height + state.config.default_recovery_delay_blocks,
            state.height + state.config.default_request_ttl_blocks,
            &json!({
                "rotation_kind": "post-quantum-wallet-recovery",
                "requires_hardware_cosigner": true,
            }),
        )?;
        let rotation_id = state.insert_signer_rotation(rotation, actor)?;
        state.spend_sponsorship(&sponsorship_id, 1_250, actor)?;

        let expected_state_root = state.state_root();
        let fixture = PqAccountRecoveryDevnetFixture::new(
            "devnet-pq-private-wallet-recovery",
            &account_commitment,
            &profile_id,
            vec![guardian_a_id, guardian_b_id, guardian_c_id],
            vec![hardware_policy_id],
            vec![request_id],
            vec![sponsorship_id],
            vec![disclosure_id],
            &expected_state_root,
            state.height,
            &json!({
                "scenario": "timelocked full wallet recovery with freeze, disclosure, sponsorship",
                "rotation_id": rotation_id,
                "freeze_id": freeze_id,
            }),
        )?;
        state.insert_devnet_fixture(fixture, actor)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqAccountRecoveryResult<String> {
        self.height = height;
        for guardian in self.pq_guardians.values_mut() {
            if guardian.status.usable() && height > guardian.expires_at_height {
                guardian.status = PqGuardianStatus::Expired;
            }
        }
        for policy in self.hardware_signer_policies.values_mut() {
            if policy.status.usable() && height > policy.expires_at_height {
                policy.status = PqHardwarePolicyStatus::Expired;
            }
        }
        for approval in self.guardian_approvals.values_mut() {
            if approval.status.counts() && height > approval.expires_at_height {
                approval.status = PqApprovalStatus::Expired;
            }
        }
        for disclosure in self.limited_view_key_disclosures.values_mut() {
            if disclosure.status.usable() && height > disclosure.expires_at_height {
                disclosure.status = PqLimitedViewKeyDisclosureStatus::Expired;
            }
        }
        for sponsorship in self.recovery_fee_sponsorships.values_mut() {
            if sponsorship.status.is_active() && height > sponsorship.expires_at_height {
                sponsorship.status = PqRecoveryFeeSponsorshipStatus::Expired;
            }
        }
        for freeze in self.emergency_freezes.values_mut() {
            if freeze.status.is_active() && height > freeze.expires_at_height {
                freeze.status = PqEmergencyFreezeStatus::Expired;
            }
        }
        for rotation in self.signer_rotations.values_mut() {
            rotation.refresh_status(height);
        }
        for timelock in self.timelock_windows.values_mut() {
            timelock.refresh_status(height);
        }
        let timelocks = self.timelock_windows.clone();
        for request in self.recovery_requests.values_mut() {
            let timelock = timelocks.get(&request.timelock_id);
            request.refresh_status(height, timelock);
        }
        for profile in self.recovery_profiles.values_mut() {
            if height > profile.expires_at_height
                && !matches!(
                    profile.status,
                    PqRecoveryProfileStatus::Revoked | PqRecoveryProfileStatus::Superseded
                )
            {
                profile.status = PqRecoveryProfileStatus::Revoked;
            }
        }
        let root = self.state_root();
        let event_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-HEIGHT-ADVANCE",
            &json!({"height": height, "state_root": root}),
        );
        self.audit(
            PqRecoveryAuditEventKind::HeightAdvanced,
            "system-height-clock",
            &height.to_string(),
            event_root,
            &json!({"height": height}),
        )?;
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn roots(&self) -> PqAccountRecoveryRoots {
        PqAccountRecoveryRoots {
            config_root: pq_account_recovery_payload_root(
                "PQ-ACCOUNT-RECOVERY-CONFIG",
                &self.config.public_record(),
            ),
            recovery_profile_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-PROFILE",
                &self
                    .recovery_profiles
                    .values()
                    .map(PqRecoveryProfile::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_guardian_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-GUARDIAN",
                &self
                    .pq_guardians
                    .values()
                    .map(PqGuardian::public_record)
                    .collect::<Vec<_>>(),
            ),
            hardware_signer_policy_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-HARDWARE-POLICY",
                &self
                    .hardware_signer_policies
                    .values()
                    .map(PqHardwareSignerPolicy::public_record)
                    .collect::<Vec<_>>(),
            ),
            guardian_approval_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-APPROVAL",
                &self
                    .guardian_approvals
                    .values()
                    .map(PqGuardianApproval::public_record)
                    .collect::<Vec<_>>(),
            ),
            recovery_request_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-REQUEST",
                &self
                    .recovery_requests
                    .values()
                    .map(PqRecoveryRequest::public_record)
                    .collect::<Vec<_>>(),
            ),
            timelock_window_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-TIMELOCK",
                &self
                    .timelock_windows
                    .values()
                    .map(PqTimelockWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            emergency_freeze_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-FREEZE",
                &self
                    .emergency_freezes
                    .values()
                    .map(PqEmergencyFreeze::public_record)
                    .collect::<Vec<_>>(),
            ),
            signer_rotation_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-ROTATION",
                &self
                    .signer_rotations
                    .values()
                    .map(PqSignerRotation::public_record)
                    .collect::<Vec<_>>(),
            ),
            limited_view_key_disclosure_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-DISCLOSURE",
                &self
                    .limited_view_key_disclosures
                    .values()
                    .map(PqLimitedViewKeyDisclosure::public_record)
                    .collect::<Vec<_>>(),
            ),
            recovery_fee_sponsorship_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-SPONSORSHIP",
                &self
                    .recovery_fee_sponsorships
                    .values()
                    .map(PqRecoveryFeeSponsorship::public_record)
                    .collect::<Vec<_>>(),
            ),
            audit_receipt_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-AUDIT",
                &self
                    .audit_receipts
                    .values()
                    .map(PqRecoveryAuditReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            devnet_fixture_root: pq_account_recovery_map_root(
                "PQ-ACCOUNT-RECOVERY-DEVNET-FIXTURE",
                &self
                    .devnet_fixtures
                    .values()
                    .map(PqAccountRecoveryDevnetFixture::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> PqAccountRecoveryCounters {
        PqAccountRecoveryCounters {
            current_height: self.height,
            recovery_profiles: self.recovery_profiles.len() as u64,
            pq_guardians: self.pq_guardians.len() as u64,
            hardware_signer_policies: self.hardware_signer_policies.len() as u64,
            guardian_approvals: self.guardian_approvals.len() as u64,
            recovery_requests_total: self.recovery_requests.len() as u64,
            recovery_requests_active: self
                .recovery_requests
                .values()
                .filter(|request| request.status.is_active())
                .count() as u64,
            recovery_requests_ready: self
                .recovery_requests
                .values()
                .filter(|request| matches!(request.status, PqRecoveryRequestStatus::Ready))
                .count() as u64,
            timelock_windows_active: self
                .timelock_windows
                .values()
                .filter(|window| window.status.is_active())
                .count() as u64,
            emergency_freezes_active: self
                .emergency_freezes
                .values()
                .filter(|freeze| freeze.status.is_active())
                .count() as u64,
            signer_rotations_active: self
                .signer_rotations
                .values()
                .filter(|rotation| rotation.status.is_active())
                .count() as u64,
            limited_view_key_disclosures_active: self
                .limited_view_key_disclosures
                .values()
                .filter(|disclosure| disclosure.status.usable())
                .count() as u64,
            recovery_fee_sponsorships_active: self
                .recovery_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_active())
                .count() as u64,
            audit_receipts: self.audit_receipts.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
            total_sponsored_fee_units: self
                .recovery_fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.spent_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        pq_account_recovery_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn validate(&self) -> PqAccountRecoveryResult<String> {
        self.config.validate()?;
        for profile in self.recovery_profiles.values() {
            profile.validate()?;
        }
        for policy in self.hardware_signer_policies.values() {
            policy.validate()?;
            if !self.recovery_profiles.contains_key(&policy.profile_id) {
                return Err(format!(
                    "hardware signer policy {} references missing profile {}",
                    policy.policy_id, policy.profile_id
                ));
            }
        }
        for guardian in self.pq_guardians.values() {
            guardian.validate()?;
            if !self.recovery_profiles.contains_key(&guardian.profile_id) {
                return Err(format!(
                    "guardian {} references missing profile {}",
                    guardian.guardian_id, guardian.profile_id
                ));
            }
            if !self
                .config
                .supported_guardian_algorithms
                .contains(&guardian.algorithm.as_str().to_string())
            {
                return Err(format!(
                    "guardian {} uses unsupported algorithm {}",
                    guardian.guardian_id,
                    guardian.algorithm.as_str()
                ));
            }
            if let Some(policy_id) = &guardian.hardware_policy_id {
                let policy = self
                    .hardware_signer_policies
                    .get(policy_id)
                    .ok_or_else(|| {
                        format!(
                            "guardian {} references missing hardware policy {}",
                            guardian.guardian_id, policy_id
                        )
                    })?;
                if policy.profile_id != guardian.profile_id {
                    return Err(format!(
                        "guardian {} hardware policy profile mismatch",
                        guardian.guardian_id
                    ));
                }
            }
        }
        for approval in self.guardian_approvals.values() {
            approval.validate()?;
            if !self.recovery_profiles.contains_key(&approval.profile_id) {
                return Err(format!(
                    "approval {} references missing profile {}",
                    approval.approval_id, approval.profile_id
                ));
            }
            let guardian = self
                .pq_guardians
                .get(&approval.guardian_id)
                .ok_or_else(|| {
                    format!(
                        "approval {} references missing guardian {}",
                        approval.approval_id, approval.guardian_id
                    )
                })?;
            if guardian.profile_id != approval.profile_id {
                return Err(format!(
                    "approval {} guardian/profile mismatch",
                    approval.approval_id
                ));
            }
            if !self.recovery_requests.contains_key(&approval.request_id) {
                return Err(format!(
                    "approval {} references missing request {}",
                    approval.approval_id, approval.request_id
                ));
            }
        }
        for request in self.recovery_requests.values() {
            request.validate()?;
            let profile = self
                .recovery_profiles
                .get(&request.profile_id)
                .ok_or_else(|| {
                    format!(
                        "request {} references missing profile {}",
                        request.request_id, request.profile_id
                    )
                })?;
            if !profile.status.accepts_recovery() && request.status.is_active() {
                return Err(format!(
                    "request {} active while profile {} does not accept recovery",
                    request.request_id, profile.profile_id
                ));
            }
            if !self.timelock_windows.contains_key(&request.timelock_id) {
                return Err(format!(
                    "request {} references missing timelock {}",
                    request.request_id, request.timelock_id
                ));
            }
            if self.config.require_limited_view_key_proof
                && request.kind.requires_view_key_proof()
                && request.limited_view_key_disclosure_id.is_none()
            {
                return Err(format!(
                    "request {} requires limited view key disclosure",
                    request.request_id
                ));
            }
            if let Some(disclosure_id) = &request.limited_view_key_disclosure_id {
                if !self
                    .limited_view_key_disclosures
                    .contains_key(disclosure_id)
                {
                    return Err(format!(
                        "request {} references missing disclosure {}",
                        request.request_id, disclosure_id
                    ));
                }
            }
            if let Some(sponsorship_id) = &request.sponsorship_id {
                if !self.recovery_fee_sponsorships.contains_key(sponsorship_id) {
                    return Err(format!(
                        "request {} references missing sponsorship {}",
                        request.request_id, sponsorship_id
                    ));
                }
            }
            if let Some(freeze_id) = &request.freeze_id {
                if !self.emergency_freezes.contains_key(freeze_id) {
                    return Err(format!(
                        "request {} references missing freeze {}",
                        request.request_id, freeze_id
                    ));
                }
            }
        }
        for timelock in self.timelock_windows.values() {
            timelock.validate()?;
            if !self.recovery_profiles.contains_key(&timelock.profile_id) {
                return Err(format!(
                    "timelock {} references missing profile {}",
                    timelock.timelock_id, timelock.profile_id
                ));
            }
            if !self.recovery_requests.contains_key(&timelock.request_id) {
                return Err(format!(
                    "timelock {} references missing request {}",
                    timelock.timelock_id, timelock.request_id
                ));
            }
        }
        for freeze in self.emergency_freezes.values() {
            freeze.validate()?;
            if !self.recovery_profiles.contains_key(&freeze.profile_id) {
                return Err(format!(
                    "freeze {} references missing profile {}",
                    freeze.freeze_id, freeze.profile_id
                ));
            }
            if !self
                .pq_guardians
                .contains_key(&freeze.triggered_by_guardian_id)
            {
                return Err(format!(
                    "freeze {} references missing triggering guardian {}",
                    freeze.freeze_id, freeze.triggered_by_guardian_id
                ));
            }
            if let Some(request_id) = &freeze.request_id {
                if !self.recovery_requests.contains_key(request_id) {
                    return Err(format!(
                        "freeze {} references missing request {}",
                        freeze.freeze_id, request_id
                    ));
                }
            }
        }
        for rotation in self.signer_rotations.values() {
            rotation.validate()?;
            if !self.recovery_profiles.contains_key(&rotation.profile_id) {
                return Err(format!(
                    "rotation {} references missing profile {}",
                    rotation.rotation_id, rotation.profile_id
                ));
            }
            if !self.recovery_requests.contains_key(&rotation.request_id) {
                return Err(format!(
                    "rotation {} references missing request {}",
                    rotation.rotation_id, rotation.request_id
                ));
            }
            if let Some(policy_id) = &rotation.hardware_policy_id {
                if !self.hardware_signer_policies.contains_key(policy_id) {
                    return Err(format!(
                        "rotation {} references missing hardware policy {}",
                        rotation.rotation_id, policy_id
                    ));
                }
            }
        }
        for disclosure in self.limited_view_key_disclosures.values() {
            disclosure.validate()?;
            if !self.recovery_profiles.contains_key(&disclosure.profile_id) {
                return Err(format!(
                    "disclosure {} references missing profile {}",
                    disclosure.disclosure_id, disclosure.profile_id
                ));
            }
            if disclosure
                .scan_window_end_height
                .saturating_sub(disclosure.scan_window_start_height)
                > self.config.max_disclosure_scan_blocks
            {
                return Err(format!(
                    "disclosure {} exceeds max scan window",
                    disclosure.disclosure_id
                ));
            }
            if let Some(request_id) = &disclosure.request_id {
                if !self.recovery_requests.contains_key(request_id) {
                    return Err(format!(
                        "disclosure {} references missing request {}",
                        disclosure.disclosure_id, request_id
                    ));
                }
            }
        }
        for sponsorship in self.recovery_fee_sponsorships.values() {
            sponsorship.validate()?;
            if sponsorship.rebate_bps < self.config.min_sponsor_rebate_bps {
                return Err(format!(
                    "sponsorship {} rebate below configured minimum",
                    sponsorship.sponsorship_id
                ));
            }
            if sponsorship.max_fee_units > self.config.max_recovery_fee_units {
                return Err(format!(
                    "sponsorship {} max fee exceeds configured maximum",
                    sponsorship.sponsorship_id
                ));
            }
            if let Some(profile_id) = &sponsorship.profile_id {
                if !self.recovery_profiles.contains_key(profile_id) {
                    return Err(format!(
                        "sponsorship {} references missing profile {}",
                        sponsorship.sponsorship_id, profile_id
                    ));
                }
            }
            if let Some(request_id) = &sponsorship.request_id {
                if !self.recovery_requests.contains_key(request_id) {
                    return Err(format!(
                        "sponsorship {} references missing request {}",
                        sponsorship.sponsorship_id, request_id
                    ));
                }
            }
        }
        for receipt in self.audit_receipts.values() {
            receipt.validate()?;
        }
        for fixture in self.devnet_fixtures.values() {
            fixture.validate()?;
            if !self.recovery_profiles.contains_key(&fixture.profile_id) {
                return Err(format!(
                    "fixture {} references missing profile {}",
                    fixture.fixture_id, fixture.profile_id
                ));
            }
        }
        Ok(self.state_root())
    }

    pub fn insert_recovery_profile(
        &mut self,
        profile: PqRecoveryProfile,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        profile.validate()?;
        let profile_id = profile.profile_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-PROFILE",
            &profile.public_record(),
        );
        insert_unique_record(
            &mut self.recovery_profiles,
            profile_id.clone(),
            profile,
            "recovery profile",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::ProfileInserted,
            actor,
            &profile_id,
            subject_root,
            &json!({ "profile_id": profile_id }),
        )?;
        Ok(profile_id)
    }

    pub fn insert_pq_guardian(
        &mut self,
        guardian: PqGuardian,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        guardian.validate()?;
        if !self.recovery_profiles.contains_key(&guardian.profile_id) {
            return Err(format!("missing guardian profile {}", guardian.profile_id));
        }
        if let Some(policy_id) = &guardian.hardware_policy_id {
            if !self.hardware_signer_policies.contains_key(policy_id) {
                return Err(format!("missing guardian hardware policy {policy_id}"));
            }
        }
        let count = self
            .pq_guardians
            .values()
            .filter(|existing| existing.profile_id == guardian.profile_id)
            .count();
        if count >= self.config.max_guardians_per_profile {
            return Err("profile guardian limit exceeded".to_string());
        }
        let guardian_id = guardian.guardian_id.clone();
        let profile_id = guardian.profile_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-GUARDIAN",
            &guardian.public_record(),
        );
        insert_unique_record(
            &mut self.pq_guardians,
            guardian_id.clone(),
            guardian,
            "pq guardian",
        )?;
        self.refresh_profile_guardian_set_root(&profile_id)?;
        self.audit(
            PqRecoveryAuditEventKind::GuardianInserted,
            actor,
            &guardian_id,
            subject_root,
            &json!({ "profile_id": profile_id }),
        )?;
        Ok(guardian_id)
    }

    pub fn insert_hardware_signer_policy(
        &mut self,
        policy: PqHardwareSignerPolicy,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        policy.validate()?;
        if !self.recovery_profiles.contains_key(&policy.profile_id) {
            return Err(format!(
                "missing hardware policy profile {}",
                policy.profile_id
            ));
        }
        let policy_id = policy.policy_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-HARDWARE",
            &policy.public_record(),
        );
        insert_unique_record(
            &mut self.hardware_signer_policies,
            policy_id.clone(),
            policy,
            "hardware signer policy",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::HardwarePolicyInserted,
            actor,
            &policy_id,
            subject_root,
            &json!({ "policy_id": policy_id }),
        )?;
        Ok(policy_id)
    }

    pub fn open_recovery_request(
        &mut self,
        request: PqRecoveryRequest,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        request.validate()?;
        let profile = self
            .recovery_profiles
            .get(&request.profile_id)
            .ok_or_else(|| format!("missing request profile {}", request.profile_id))?;
        if !profile.status.accepts_recovery() {
            return Err(format!(
                "profile {} does not accept recovery requests",
                profile.profile_id
            ));
        }
        let active_requests = self
            .recovery_requests
            .values()
            .filter(|existing| {
                existing.account_commitment == request.account_commitment
                    && existing.status.is_active()
            })
            .count();
        if active_requests >= self.config.max_active_requests_per_account {
            return Err("account active recovery request limit exceeded".to_string());
        }
        if self.config.require_hardware_for_contract_accounts
            && request.kind.is_contract_recovery()
            && !self.pq_guardians.values().any(|guardian| {
                guardian.profile_id == request.profile_id
                    && guardian.algorithm.requires_hardware_policy()
                    && guardian.status.usable()
            })
        {
            return Err("contract recovery requires active hardware guardian".to_string());
        }
        if self.config.require_limited_view_key_proof
            && request.kind.requires_view_key_proof()
            && request.limited_view_key_disclosure_id.is_none()
        {
            return Err("request requires limited view key disclosure".to_string());
        }
        let request_id = request.request_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-REQUEST",
            &request.public_record(),
        );
        insert_unique_record(
            &mut self.recovery_requests,
            request_id.clone(),
            request,
            "recovery request",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::RequestOpened,
            actor,
            &request_id,
            subject_root,
            &json!({ "request_id": request_id }),
        )?;
        Ok(request_id)
    }

    pub fn insert_timelock_window(
        &mut self,
        timelock: PqTimelockWindow,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        timelock.validate()?;
        if !self.recovery_profiles.contains_key(&timelock.profile_id) {
            return Err(format!("missing timelock profile {}", timelock.profile_id));
        }
        if !self.recovery_requests.contains_key(&timelock.request_id) {
            return Err(format!("missing timelock request {}", timelock.request_id));
        }
        let timelock_id = timelock.timelock_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-TIMELOCK",
            &timelock.public_record(),
        );
        insert_unique_record(
            &mut self.timelock_windows,
            timelock_id.clone(),
            timelock,
            "timelock window",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::TimelockInserted,
            actor,
            &timelock_id,
            subject_root,
            &json!({ "timelock_id": timelock_id }),
        )?;
        Ok(timelock_id)
    }

    pub fn record_guardian_approval(
        &mut self,
        mut approval: PqGuardianApproval,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        approval.validate()?;
        let request = self
            .recovery_requests
            .get(&approval.request_id)
            .ok_or_else(|| format!("missing approval request {}", approval.request_id))?;
        if request.profile_id != approval.profile_id {
            return Err("approval request/profile mismatch".to_string());
        }
        let guardian = self
            .pq_guardians
            .get(&approval.guardian_id)
            .ok_or_else(|| format!("missing approval guardian {}", approval.guardian_id))?;
        if guardian.profile_id != approval.profile_id {
            return Err("approval guardian/profile mismatch".to_string());
        }
        if !guardian.status.usable() {
            return Err(format!("guardian {} is not usable", guardian.guardian_id));
        }
        if approval.weight > guardian.weight {
            return Err("approval weight exceeds guardian weight".to_string());
        }
        if let Some(policy_id) = &approval.signer_policy_id {
            if !self.hardware_signer_policies.contains_key(policy_id) {
                return Err(format!(
                    "approval references missing signer policy {policy_id}"
                ));
            }
        }
        let current_approval_count = self
            .guardian_approvals
            .values()
            .filter(|existing| existing.request_id == approval.request_id)
            .count();
        if current_approval_count >= self.config.max_approvals_per_request {
            return Err("request approval limit exceeded".to_string());
        }
        if self
            .guardian_approvals
            .values()
            .any(|existing| existing.approval_nullifier == approval.approval_nullifier)
        {
            return Err("approval nullifier already used".to_string());
        }
        approval.status = PqApprovalStatus::Counted;
        let approval_id = approval.approval_id.clone();
        let request_id = approval.request_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-APPROVAL",
            &approval.public_record(),
        );
        insert_unique_record(
            &mut self.guardian_approvals,
            approval_id.clone(),
            approval,
            "guardian approval",
        )?;
        self.refresh_request_approval_state(&request_id)?;
        self.audit(
            PqRecoveryAuditEventKind::ApprovalRecorded,
            actor,
            &approval_id,
            subject_root,
            &json!({ "request_id": request_id }),
        )?;
        Ok(approval_id)
    }

    pub fn insert_emergency_freeze(
        &mut self,
        freeze: PqEmergencyFreeze,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        freeze.validate()?;
        if !self.recovery_profiles.contains_key(&freeze.profile_id) {
            return Err(format!("missing freeze profile {}", freeze.profile_id));
        }
        let guardian = self
            .pq_guardians
            .get(&freeze.triggered_by_guardian_id)
            .ok_or_else(|| {
                format!(
                    "missing freeze triggering guardian {}",
                    freeze.triggered_by_guardian_id
                )
            })?;
        if !guardian.role.can_approve_emergency() {
            return Err("triggering guardian cannot open emergency freeze".to_string());
        }
        let freeze_id = freeze.freeze_id.clone();
        let profile_id = freeze.profile_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-FREEZE",
            &freeze.public_record(),
        );
        insert_unique_record(
            &mut self.emergency_freezes,
            freeze_id.clone(),
            freeze,
            "emergency freeze",
        )?;
        if let Some(profile) = self.recovery_profiles.get_mut(&profile_id) {
            profile.status = PqRecoveryProfileStatus::Frozen;
        }
        self.audit(
            PqRecoveryAuditEventKind::FreezeOpened,
            actor,
            &freeze_id,
            subject_root,
            &json!({ "profile_id": profile_id }),
        )?;
        Ok(freeze_id)
    }

    pub fn lift_emergency_freeze(
        &mut self,
        freeze_id: &str,
        actor: &str,
        release_root: &str,
    ) -> PqAccountRecoveryResult<String> {
        ensure_non_empty(freeze_id, "freeze_id")?;
        ensure_non_empty(release_root, "release_root")?;
        let freeze = self
            .emergency_freezes
            .get_mut(freeze_id)
            .ok_or_else(|| format!("missing emergency freeze {freeze_id}"))?;
        if !freeze.status.is_active() {
            return Err(format!("freeze {freeze_id} is not active"));
        }
        freeze.status = PqEmergencyFreezeStatus::Lifted;
        freeze.lifted_height = Some(self.height);
        let profile_id = freeze.profile_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-FREEZE-LIFT",
            &freeze.public_record(),
        );
        if let Some(profile) = self.recovery_profiles.get_mut(&profile_id) {
            profile.status = PqRecoveryProfileStatus::Active;
        }
        self.audit(
            PqRecoveryAuditEventKind::FreezeLifted,
            actor,
            freeze_id,
            subject_root,
            &json!({ "release_root": release_root }),
        )?;
        Ok(self.state_root())
    }

    pub fn insert_signer_rotation(
        &mut self,
        rotation: PqSignerRotation,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        rotation.validate()?;
        if !self.recovery_profiles.contains_key(&rotation.profile_id) {
            return Err(format!("missing rotation profile {}", rotation.profile_id));
        }
        if !self.recovery_requests.contains_key(&rotation.request_id) {
            return Err(format!("missing rotation request {}", rotation.request_id));
        }
        if let Some(policy_id) = &rotation.hardware_policy_id {
            if !self.hardware_signer_policies.contains_key(policy_id) {
                return Err(format!("missing rotation hardware policy {policy_id}"));
            }
        }
        let rotation_id = rotation.rotation_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-ROTATION",
            &rotation.public_record(),
        );
        insert_unique_record(
            &mut self.signer_rotations,
            rotation_id.clone(),
            rotation,
            "signer rotation",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::RotationInserted,
            actor,
            &rotation_id,
            subject_root,
            &json!({ "rotation_id": rotation_id }),
        )?;
        Ok(rotation_id)
    }

    pub fn apply_signer_rotation(
        &mut self,
        rotation_id: &str,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        ensure_non_empty(rotation_id, "rotation_id")?;
        let rotation = self
            .signer_rotations
            .get_mut(rotation_id)
            .ok_or_else(|| format!("missing signer rotation {rotation_id}"))?;
        rotation.refresh_status(self.height);
        if !matches!(rotation.status, PqSignerRotationStatus::Ready) {
            return Err(format!("rotation {rotation_id} is not ready"));
        }
        rotation.status = PqSignerRotationStatus::Applied;
        rotation.executed_height = Some(self.height);
        let profile_id = rotation.profile_id.clone();
        let next_spend_key_commitment = rotation.next_spend_key_commitment.clone();
        let next_view_key_commitment = rotation.next_view_key_commitment.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-ROTATION-APPLY",
            &rotation.public_record(),
        );
        if let Some(profile) = self.recovery_profiles.get_mut(&profile_id) {
            profile.current_spend_key_root = next_spend_key_commitment;
            profile.current_view_key_commitment = next_view_key_commitment;
            profile.rotation_nonce = profile
                .rotation_nonce
                .checked_add(1)
                .ok_or_else(|| "profile rotation_nonce overflow".to_string())?;
            profile.status = PqRecoveryProfileStatus::Active;
        }
        self.audit(
            PqRecoveryAuditEventKind::RequestExecuted,
            actor,
            rotation_id,
            subject_root,
            &json!({ "rotation_id": rotation_id }),
        )?;
        Ok(self.state_root())
    }

    pub fn insert_limited_view_key_disclosure(
        &mut self,
        disclosure: PqLimitedViewKeyDisclosure,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        disclosure.validate()?;
        if !self.recovery_profiles.contains_key(&disclosure.profile_id) {
            return Err(format!(
                "missing disclosure profile {}",
                disclosure.profile_id
            ));
        }
        if disclosure
            .scan_window_end_height
            .saturating_sub(disclosure.scan_window_start_height)
            > self.config.max_disclosure_scan_blocks
        {
            return Err("limited view key disclosure scan window too large".to_string());
        }
        let disclosure_id = disclosure.disclosure_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-DISCLOSURE",
            &disclosure.public_record(),
        );
        insert_unique_record(
            &mut self.limited_view_key_disclosures,
            disclosure_id.clone(),
            disclosure,
            "limited view key disclosure",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::ViewKeyDisclosureInserted,
            actor,
            &disclosure_id,
            subject_root,
            &json!({ "disclosure_id": disclosure_id }),
        )?;
        Ok(disclosure_id)
    }

    pub fn insert_recovery_fee_sponsorship(
        &mut self,
        sponsorship: PqRecoveryFeeSponsorship,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        if !self.config.allow_low_fee_sponsorship {
            return Err("low-fee recovery sponsorship is disabled".to_string());
        }
        sponsorship.validate()?;
        if sponsorship.rebate_bps < self.config.min_sponsor_rebate_bps {
            return Err("sponsorship rebate below configured minimum".to_string());
        }
        if sponsorship.max_fee_units > self.config.max_recovery_fee_units {
            return Err("sponsorship max fee exceeds configured maximum".to_string());
        }
        if let Some(profile_id) = &sponsorship.profile_id {
            if !self.recovery_profiles.contains_key(profile_id) {
                return Err(format!("missing sponsorship profile {profile_id}"));
            }
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-SPONSORSHIP",
            &sponsorship.public_record(),
        );
        insert_unique_record(
            &mut self.recovery_fee_sponsorships,
            sponsorship_id.clone(),
            sponsorship,
            "recovery fee sponsorship",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::SponsorshipInserted,
            actor,
            &sponsorship_id,
            subject_root,
            &json!({ "sponsorship_id": sponsorship_id }),
        )?;
        Ok(sponsorship_id)
    }

    pub fn spend_sponsorship(
        &mut self,
        sponsorship_id: &str,
        units: u64,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        ensure_non_empty(sponsorship_id, "sponsorship_id")?;
        let sponsorship = self
            .recovery_fee_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| format!("missing sponsorship {sponsorship_id}"))?;
        sponsorship.spend(units)?;
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-SPONSORSHIP-SPEND",
            &sponsorship.public_record(),
        );
        self.audit(
            PqRecoveryAuditEventKind::SponsorshipSpent,
            actor,
            sponsorship_id,
            subject_root,
            &json!({ "units": units }),
        )?;
        Ok(self.state_root())
    }

    pub fn insert_devnet_fixture(
        &mut self,
        fixture: PqAccountRecoveryDevnetFixture,
        actor: &str,
    ) -> PqAccountRecoveryResult<String> {
        fixture.validate()?;
        let fixture_id = fixture.fixture_id.clone();
        let subject_root = pq_account_recovery_payload_root(
            "PQ-ACCOUNT-RECOVERY-AUDIT-FIXTURE",
            &fixture.public_record(),
        );
        insert_unique_record(
            &mut self.devnet_fixtures,
            fixture_id.clone(),
            fixture,
            "devnet fixture",
        )?;
        self.audit(
            PqRecoveryAuditEventKind::DevnetFixtureInserted,
            actor,
            &fixture_id,
            subject_root,
            &json!({ "fixture_id": fixture_id }),
        )?;
        Ok(fixture_id)
    }

    pub fn recovery_request_transcript_root(
        &self,
        request_id: &str,
    ) -> PqAccountRecoveryResult<String> {
        let request = self
            .recovery_requests
            .get(request_id)
            .ok_or_else(|| format!("missing recovery request {request_id}"))?;
        Ok(domain_hash(
            "PQ-ACCOUNT-RECOVERY-REQUEST-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Str(&request.request_id),
                HashPart::Str(&request.profile_id),
                HashPart::Str(&request.account_commitment),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.bundle_payload_root),
                HashPart::Str(&request.new_spend_key_commitment),
                HashPart::Str(&request.new_view_key_commitment),
                HashPart::Str(&request.approval_root),
                HashPart::Int(request.opened_height as i128),
            ],
            32,
        ))
    }

    pub fn approval_root_for_request(&self, request_id: &str) -> String {
        let approvals = self
            .guardian_approvals
            .values()
            .filter(|approval| approval.request_id == request_id && approval.status.counts())
            .map(PqGuardianApproval::public_record)
            .collect::<Vec<_>>();
        pq_account_recovery_map_root("PQ-ACCOUNT-RECOVERY-REQUEST-APPROVAL", &approvals)
    }

    pub fn counted_approval_weight_for_request(&self, request_id: &str) -> u64 {
        self.guardian_approvals
            .values()
            .filter(|approval| approval.request_id == request_id && approval.status.counts())
            .map(|approval| approval.weight)
            .sum()
    }

    pub fn distinct_guardian_count_for_request(&self, request_id: &str) -> u64 {
        let mut seen = BTreeMap::<String, ()>::new();
        for approval in self
            .guardian_approvals
            .values()
            .filter(|approval| approval.request_id == request_id && approval.status.counts())
        {
            seen.insert(approval.guardian_id.clone(), ());
        }
        seen.len() as u64
    }

    pub fn refresh_profile_guardian_set_root(
        &mut self,
        profile_id: &str,
    ) -> PqAccountRecoveryResult<String> {
        ensure_non_empty(profile_id, "profile_id")?;
        let guardian_records = self
            .pq_guardians
            .values()
            .filter(|guardian| guardian.profile_id == profile_id)
            .map(PqGuardian::public_record)
            .collect::<Vec<_>>();
        let guardian_set_root = pq_account_recovery_map_root(
            "PQ-ACCOUNT-RECOVERY-PROFILE-GUARDIAN-SET",
            &guardian_records,
        );
        let profile = self
            .recovery_profiles
            .get_mut(profile_id)
            .ok_or_else(|| format!("missing profile {profile_id}"))?;
        profile.guardian_set_root = guardian_set_root.clone();
        Ok(guardian_set_root)
    }

    fn refresh_request_approval_state(&mut self, request_id: &str) -> PqAccountRecoveryResult<()> {
        let approval_root = self.approval_root_for_request(request_id);
        let approval_weight = self.counted_approval_weight_for_request(request_id);
        let distinct_guardians = self.distinct_guardian_count_for_request(request_id);
        let (profile_id, timelock_id) = {
            let request = self
                .recovery_requests
                .get(request_id)
                .ok_or_else(|| format!("missing request {request_id}"))?;
            (request.profile_id.clone(), request.timelock_id.clone())
        };
        let profile = self
            .recovery_profiles
            .get(&profile_id)
            .ok_or_else(|| format!("missing profile {profile_id}"))?;
        if let Some(request) = self.recovery_requests.get_mut(request_id) {
            request.approval_root = approval_root.clone();
            if approval_weight >= profile.quorum_policy.threshold_weight
                && distinct_guardians >= profile.quorum_policy.min_distinct_guardians
            {
                request.status = PqRecoveryRequestStatus::Timelocked;
            }
        }
        if let Some(timelock) = self.timelock_windows.get_mut(&timelock_id) {
            timelock.observed_approval_weight = approval_weight;
            if approval_weight >= timelock.min_approval_weight
                && distinct_guardians >= profile.quorum_policy.min_distinct_guardians
            {
                timelock.status = if self.height <= timelock.challenge_until_height {
                    PqTimelockStatus::ChallengeOpen
                } else if self.height >= timelock.executable_after_height {
                    PqTimelockStatus::Mature
                } else {
                    PqTimelockStatus::ChallengeOpen
                };
            }
        }
        Ok(())
    }

    fn audit(
        &mut self,
        event_kind: PqRecoveryAuditEventKind,
        actor: &str,
        subject_id: &str,
        subject_root: String,
        metadata: &Value,
    ) -> PqAccountRecoveryResult<String> {
        ensure_non_empty(actor, "audit actor")?;
        ensure_non_empty(subject_id, "audit subject_id")?;
        ensure_non_empty(&subject_root, "audit subject_root")?;
        let sequence = self.audit_receipts.len() as u64;
        let state_root_before = self.state_root();
        let state_root_after = domain_hash(
            "PQ-ACCOUNT-RECOVERY-AUDIT-STATE-AFTER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
                HashPart::Int(sequence as i128),
                HashPart::Int(self.height as i128),
                HashPart::Str(event_kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(&subject_root),
                HashPart::Json(metadata),
            ],
            32,
        );
        let receipt = PqRecoveryAuditReceipt::new(
            sequence,
            self.height,
            event_kind,
            actor,
            subject_id,
            &subject_root,
            &state_root_before,
            &state_root_after,
            metadata,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        insert_unique_record(
            &mut self.audit_receipts,
            receipt_id.clone(),
            receipt,
            "audit receipt",
        )?;
        Ok(receipt_id)
    }
}

pub fn pq_account_recovery_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-ACCOUNT-RECOVERY-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn pq_account_recovery_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_account_recovery_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_ACCOUNT_RECOVERY_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_account_recovery_map_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn insert_unique_record<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> PqAccountRecoveryResult<()> {
    if map.contains_key(&key) {
        return Err(format!("{label} already exists: {key}"));
    }
    map.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> PqAccountRecoveryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> PqAccountRecoveryResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> PqAccountRecoveryResult<()> {
    if value > PQ_ACCOUNT_RECOVERY_MAX_BPS {
        Err(format!("{label} exceeds {PQ_ACCOUNT_RECOVERY_MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_height_order(start: u64, end: u64, label: &str) -> PqAccountRecoveryResult<()> {
    if start > end {
        Err(format!("{label} start height is after end height"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> PqAccountRecoveryResult<()> {
    let mut seen = BTreeMap::<&str, ()>::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if seen.insert(value.as_str(), ()).is_some() {
            return Err(format!("{label} contains duplicate value {value}"));
        }
    }
    Ok(())
}
