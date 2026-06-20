use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type QuantumSafeWalletSocialRecoveryGuardResult<T> = Result<T, String>;

pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PROTOCOL_VERSION: &str =
    "nebula-quantum-safe-wallet-social-recovery-guard-v1";
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-128f-social-recovery";
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PQ_KEM_SUITE: &str =
    "ML-KEM-1024-threshold-recovery-packet";
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_POLICY_HOOK_SUITE: &str =
    "private-wallet-policy-hook-v1";
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEVNET_HEIGHT: u64 = 8_420;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_DELAY_BLOCKS: u64 = 18;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_CHALLENGE_BLOCKS: u64 = 24;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_PACKET_TTL_BLOCKS: u64 = 96;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_SPONSOR_CAP_MICRO_UNITS: u64 =
    25_000_000;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_GUARDIAN_SETS: usize = 512;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_GUARDIANS_PER_SET: usize = 32;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_WALLETS: usize = 4_096;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_PACKETS: usize = 16_384;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_APPROVALS: usize = 65_536;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_LOCKS: usize = 16_384;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_REVOCATIONS: usize = 65_536;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_POLICY_HOOKS: usize = 8_192;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_SPONSOR_LANES: usize = 256;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_EVENTS: usize = 65_536;
pub const QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletClass {
    PrivateSmartAccount,
    ShieldedVault,
    ContractWallet,
    MobileSessionWallet,
    HardwareBackedWallet,
    MoneroLinkedWallet,
}

impl WalletClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSmartAccount => "private_smart_account",
            Self::ShieldedVault => "shielded_vault",
            Self::ContractWallet => "contract_wallet",
            Self::MobileSessionWallet => "mobile_session_wallet",
            Self::HardwareBackedWallet => "hardware_backed_wallet",
            Self::MoneroLinkedWallet => "monero_linked_wallet",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianRole {
    Primary,
    Delegate,
    Institutional,
    DeviceShard,
    RecoveryCouncil,
    EmergencyVeto,
}

impl GuardianRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Delegate => "delegate",
            Self::Institutional => "institutional",
            Self::DeviceShard => "device_shard",
            Self::RecoveryCouncil => "recovery_council",
            Self::EmergencyVeto => "emergency_veto",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianStatus {
    Pending,
    Active,
    Rotating,
    Suspended,
    Revoked,
}

impl GuardianStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPacketStatus {
    Sealed,
    Announced,
    CollectingApprovals,
    ThresholdMet,
    Locked,
    Executed,
    Expired,
    Cancelled,
    Challenged,
}

impl RecoveryPacketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Announced => "announced",
            Self::CollectingApprovals => "collecting_approvals",
            Self::ThresholdMet => "threshold_met",
            Self::Locked => "locked",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Submitted,
    Accepted,
    Duplicate,
    Revoked,
    Rejected,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelayLockStatus {
    Pending,
    Active,
    Matured,
    Executed,
    Cancelled,
    Challenged,
}

impl DelayLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Matured => "matured",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHookKind {
    SpendingLimit,
    DestinationAllowlist,
    PrivacyBudget,
    SessionKeyRevocation,
    ProofOfPossession,
    MoneroViewKeyDisclosure,
    RiskOracle,
}

impl PolicyHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendingLimit => "spending_limit",
            Self::DestinationAllowlist => "destination_allowlist",
            Self::PrivacyBudget => "privacy_budget",
            Self::SessionKeyRevocation => "session_key_revocation",
            Self::ProofOfPossession => "proof_of_possession",
            Self::MoneroViewKeyDisclosure => "monero_view_key_disclosure",
            Self::RiskOracle => "risk_oracle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorLaneKind {
    RetailRecovery,
    HardwareMigration,
    InstitutionalDesk,
    EmergencyLostDevice,
    LowFeeCommunity,
    ContractWalletBatch,
}

impl SponsorLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailRecovery => "retail_recovery",
            Self::HardwareMigration => "hardware_migration",
            Self::InstitutionalDesk => "institutional_desk",
            Self::EmergencyLostDevice => "emergency_lost_device",
            Self::LowFeeCommunity => "low_fee_community",
            Self::ContractWalletBatch => "contract_wallet_batch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub pq_kem_suite: String,
    pub policy_hook_suite: String,
    pub default_delay_blocks: u64,
    pub default_challenge_blocks: u64,
    pub default_packet_ttl_blocks: u64,
    pub default_sponsor_cap_micro_units: u64,
    pub min_guardian_threshold: u64,
    pub max_guardian_sets: usize,
    pub max_guardians_per_set: usize,
    pub max_wallets: usize,
    pub max_packets: usize,
    pub max_approvals: usize,
    pub max_locks: usize,
    pub max_revocations: usize,
    pub max_policy_hooks: usize,
    pub max_sponsor_lanes: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PROTOCOL_VERSION
                .to_string(),
            hash_suite: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_HASH_SUITE.to_string(),
            pq_signature_suite: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PQ_SIGNATURE_SUITE
                .to_string(),
            pq_kem_suite: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PQ_KEM_SUITE.to_string(),
            policy_hook_suite: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_POLICY_HOOK_SUITE
                .to_string(),
            default_delay_blocks: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_DELAY_BLOCKS,
            default_challenge_blocks:
                QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_CHALLENGE_BLOCKS,
            default_packet_ttl_blocks:
                QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_PACKET_TTL_BLOCKS,
            default_sponsor_cap_micro_units:
                QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEFAULT_SPONSOR_CAP_MICRO_UNITS,
            min_guardian_threshold: 2,
            max_guardian_sets: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_GUARDIAN_SETS,
            max_guardians_per_set: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_GUARDIANS_PER_SET,
            max_wallets: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_WALLETS,
            max_packets: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_PACKETS,
            max_approvals: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_APPROVALS,
            max_locks: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_LOCKS,
            max_revocations: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_REVOCATIONS,
            max_policy_hooks: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_POLICY_HOOKS,
            max_sponsor_lanes: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_SPONSOR_LANES,
            max_events: QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_EVENTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("pq signature suite", &self.pq_signature_suite)?;
        require_non_empty("pq kem suite", &self.pq_kem_suite)?;
        require_non_empty("policy hook suite", &self.policy_hook_suite)?;
        if self.default_delay_blocks == 0 {
            return Err("default recovery delay must be greater than zero".to_string());
        }
        if self.default_challenge_blocks == 0 {
            return Err("default challenge window must be greater than zero".to_string());
        }
        if self.default_packet_ttl_blocks <= self.default_delay_blocks {
            return Err("packet ttl must exceed the spending delay".to_string());
        }
        if self.min_guardian_threshold == 0 {
            return Err("minimum guardian threshold must be greater than zero".to_string());
        }
        if self.max_guardians_per_set < self.min_guardian_threshold as usize {
            return Err("max guardians per set must cover minimum threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_wallet_social_recovery_guard_config",
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "policy_hook_suite": self.policy_hook_suite,
            "default_delay_blocks": self.default_delay_blocks,
            "default_challenge_blocks": self.default_challenge_blocks,
            "default_packet_ttl_blocks": self.default_packet_ttl_blocks,
            "default_sponsor_cap_micro_units": self.default_sponsor_cap_micro_units,
            "min_guardian_threshold": self.min_guardian_threshold,
            "max_guardian_sets": self.max_guardian_sets,
            "max_guardians_per_set": self.max_guardians_per_set,
            "max_wallets": self.max_wallets,
            "max_packets": self.max_packets,
            "max_approvals": self.max_approvals,
            "max_locks": self.max_locks,
            "max_revocations": self.max_revocations,
            "max_policy_hooks": self.max_policy_hooks,
            "max_sponsor_lanes": self.max_sponsor_lanes,
            "max_events": self.max_events,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianCommitment {
    pub guardian_id: String,
    pub wallet_id: String,
    pub guardian_set_id: String,
    pub role: GuardianRole,
    pub status: GuardianStatus,
    pub pq_identity_commitment: String,
    pub recovery_share_commitment: String,
    pub notification_key_commitment: String,
    pub stake_commitment: String,
    pub metadata_root: String,
    pub weight: u64,
    pub added_height: u64,
    pub rotation_epoch: u64,
}

impl GuardianCommitment {
    pub fn new(
        wallet_id: &str,
        guardian_set_id: &str,
        role: GuardianRole,
        pq_identity_commitment: &str,
        recovery_share_commitment: &str,
        notification_key_commitment: &str,
        stake_commitment: &str,
        metadata_root: &str,
        weight: u64,
        added_height: u64,
        rotation_epoch: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let guardian_id = recovery_id(
            "GUARDIAN",
            &[
                wallet_id,
                guardian_set_id,
                role.as_str(),
                pq_identity_commitment,
                recovery_share_commitment,
                &rotation_epoch.to_string(),
            ],
        );
        let guardian = Self {
            guardian_id,
            wallet_id: wallet_id.to_string(),
            guardian_set_id: guardian_set_id.to_string(),
            role,
            status: GuardianStatus::Active,
            pq_identity_commitment: pq_identity_commitment.to_string(),
            recovery_share_commitment: recovery_share_commitment.to_string(),
            notification_key_commitment: notification_key_commitment.to_string(),
            stake_commitment: stake_commitment.to_string(),
            metadata_root: metadata_root.to_string(),
            weight,
            added_height,
            rotation_epoch,
        };
        guardian.validate()?;
        Ok(guardian)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("guardian id", &self.guardian_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("guardian set id", &self.guardian_set_id)?;
        require_non_empty("pq identity commitment", &self.pq_identity_commitment)?;
        require_non_empty("recovery share commitment", &self.recovery_share_commitment)?;
        require_non_empty(
            "notification key commitment",
            &self.notification_key_commitment,
        )?;
        require_non_empty("stake commitment", &self.stake_commitment)?;
        require_non_empty("metadata root", &self.metadata_root)?;
        if self.weight == 0 {
            return Err("guardian weight must be greater than zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_guardian_commitment",
            "guardian_id": self.guardian_id,
            "wallet_id": self.wallet_id,
            "guardian_set_id": self.guardian_set_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "pq_identity_commitment": self.pq_identity_commitment,
            "recovery_share_commitment": self.recovery_share_commitment,
            "notification_key_commitment": self.notification_key_commitment,
            "stake_commitment": self.stake_commitment,
            "metadata_root": self.metadata_root,
            "weight": self.weight,
            "added_height": self.added_height,
            "rotation_epoch": self.rotation_epoch,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet {
    pub guardian_set_id: String,
    pub wallet_id: String,
    pub guardian_ids: BTreeSet<String>,
    pub threshold_weight: u64,
    pub veto_weight: u64,
    pub guardian_root: String,
    pub policy_root: String,
    pub active: bool,
    pub epoch: u64,
}

impl GuardianSet {
    pub fn new(
        wallet_id: &str,
        guardian_ids: BTreeSet<String>,
        threshold_weight: u64,
        veto_weight: u64,
        guardian_root: &str,
        policy_root: &str,
        epoch: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let guardian_set_id = recovery_id(
            "GUARDIAN-SET",
            &[
                wallet_id,
                guardian_root,
                policy_root,
                &threshold_weight.to_string(),
                &epoch.to_string(),
            ],
        );
        let set = Self {
            guardian_set_id,
            wallet_id: wallet_id.to_string(),
            guardian_ids,
            threshold_weight,
            veto_weight,
            guardian_root: guardian_root.to_string(),
            policy_root: policy_root.to_string(),
            active: true,
            epoch,
        };
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("guardian set id", &self.guardian_set_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("guardian root", &self.guardian_root)?;
        require_non_empty("policy root", &self.policy_root)?;
        if self.guardian_ids.is_empty() {
            return Err("guardian set must contain at least one guardian".to_string());
        }
        if self.threshold_weight == 0 {
            return Err("guardian threshold weight must be greater than zero".to_string());
        }
        if self.guardian_ids.len() > QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_GUARDIANS_PER_SET
        {
            return Err("guardian set exceeds maximum guardian count".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_guardian_set",
            "guardian_set_id": self.guardian_set_id,
            "wallet_id": self.wallet_id,
            "guardian_ids": self.guardian_ids.iter().cloned().collect::<Vec<_>>(),
            "threshold_weight": self.threshold_weight,
            "veto_weight": self.veto_weight,
            "guardian_root": self.guardian_root,
            "policy_root": self.policy_root,
            "active": self.active,
            "epoch": self.epoch,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRecoveryPolicy {
    pub wallet_id: String,
    pub wallet_class: WalletClass,
    pub active_guardian_set_id: String,
    pub owner_commitment: String,
    pub spend_authority_commitment: String,
    pub recovery_destination_commitment: String,
    pub private_policy_root: String,
    pub daily_spend_limit_micro_units: u64,
    pub recovery_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub require_fee_sponsor: bool,
    pub allow_private_hooks: bool,
    pub revision: u64,
}

impl WalletRecoveryPolicy {
    pub fn new(
        wallet_class: WalletClass,
        active_guardian_set_id: &str,
        owner_commitment: &str,
        spend_authority_commitment: &str,
        recovery_destination_commitment: &str,
        private_policy_root: &str,
        daily_spend_limit_micro_units: u64,
        recovery_delay_blocks: u64,
        challenge_window_blocks: u64,
        require_fee_sponsor: bool,
        allow_private_hooks: bool,
        revision: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let wallet_id = recovery_id(
            "WALLET",
            &[
                wallet_class.as_str(),
                owner_commitment,
                spend_authority_commitment,
                private_policy_root,
                &revision.to_string(),
            ],
        );
        let policy = Self {
            wallet_id,
            wallet_class,
            active_guardian_set_id: active_guardian_set_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            spend_authority_commitment: spend_authority_commitment.to_string(),
            recovery_destination_commitment: recovery_destination_commitment.to_string(),
            private_policy_root: private_policy_root.to_string(),
            daily_spend_limit_micro_units,
            recovery_delay_blocks,
            challenge_window_blocks,
            require_fee_sponsor,
            allow_private_hooks,
            revision,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("active guardian set id", &self.active_guardian_set_id)?;
        require_non_empty("owner commitment", &self.owner_commitment)?;
        require_non_empty(
            "spend authority commitment",
            &self.spend_authority_commitment,
        )?;
        require_non_empty(
            "recovery destination commitment",
            &self.recovery_destination_commitment,
        )?;
        require_non_empty("private policy root", &self.private_policy_root)?;
        if self.recovery_delay_blocks == 0 {
            return Err("wallet recovery delay must be greater than zero".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("wallet challenge window must be greater than zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_wallet_recovery_policy",
            "wallet_id": self.wallet_id,
            "wallet_class": self.wallet_class.as_str(),
            "active_guardian_set_id": self.active_guardian_set_id,
            "owner_commitment": self.owner_commitment,
            "spend_authority_commitment": self.spend_authority_commitment,
            "recovery_destination_commitment": self.recovery_destination_commitment,
            "private_policy_root": self.private_policy_root,
            "daily_spend_limit_micro_units": self.daily_spend_limit_micro_units,
            "recovery_delay_blocks": self.recovery_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "require_fee_sponsor": self.require_fee_sponsor,
            "allow_private_hooks": self.allow_private_hooks,
            "revision": self.revision,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecoveryPacket {
    pub packet_id: String,
    pub wallet_id: String,
    pub guardian_set_id: String,
    pub new_spend_authority_commitment: String,
    pub encrypted_payload_root: String,
    pub pq_kem_ciphertext_root: String,
    pub recovery_hint_root: String,
    pub sponsor_lane_id: String,
    pub status: RecoveryPacketStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub approval_threshold_weight: u64,
    pub packet_fee_micro_units: u64,
}

impl EncryptedRecoveryPacket {
    pub fn new(
        wallet_id: &str,
        guardian_set_id: &str,
        new_spend_authority_commitment: &str,
        encrypted_payload_root: &str,
        pq_kem_ciphertext_root: &str,
        recovery_hint_root: &str,
        sponsor_lane_id: &str,
        opened_height: u64,
        expires_height: u64,
        approval_threshold_weight: u64,
        packet_fee_micro_units: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let packet_id = recovery_id(
            "PACKET",
            &[
                wallet_id,
                guardian_set_id,
                new_spend_authority_commitment,
                encrypted_payload_root,
                pq_kem_ciphertext_root,
                &opened_height.to_string(),
            ],
        );
        let packet = Self {
            packet_id,
            wallet_id: wallet_id.to_string(),
            guardian_set_id: guardian_set_id.to_string(),
            new_spend_authority_commitment: new_spend_authority_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            pq_kem_ciphertext_root: pq_kem_ciphertext_root.to_string(),
            recovery_hint_root: recovery_hint_root.to_string(),
            sponsor_lane_id: sponsor_lane_id.to_string(),
            status: RecoveryPacketStatus::CollectingApprovals,
            opened_height,
            expires_height,
            approval_threshold_weight,
            packet_fee_micro_units,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("packet id", &self.packet_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("guardian set id", &self.guardian_set_id)?;
        require_non_empty(
            "new spend authority commitment",
            &self.new_spend_authority_commitment,
        )?;
        require_non_empty("encrypted payload root", &self.encrypted_payload_root)?;
        require_non_empty("pq kem ciphertext root", &self.pq_kem_ciphertext_root)?;
        require_non_empty("recovery hint root", &self.recovery_hint_root)?;
        require_non_empty("sponsor lane id", &self.sponsor_lane_id)?;
        if self.expires_height <= self.opened_height {
            return Err("recovery packet expiry must be after opened height".to_string());
        }
        if self.approval_threshold_weight == 0 {
            return Err("recovery packet threshold weight must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_encrypted_recovery_packet",
            "packet_id": self.packet_id,
            "wallet_id": self.wallet_id,
            "guardian_set_id": self.guardian_set_id,
            "new_spend_authority_commitment": self.new_spend_authority_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "pq_kem_ciphertext_root": self.pq_kem_ciphertext_root,
            "recovery_hint_root": self.recovery_hint_root,
            "sponsor_lane_id": self.sponsor_lane_id,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "approval_threshold_weight": self.approval_threshold_weight,
            "packet_fee_micro_units": self.packet_fee_micro_units,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryApproval {
    pub approval_id: String,
    pub packet_id: String,
    pub guardian_id: String,
    pub guardian_set_id: String,
    pub approval_nullifier: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub policy_witness_root: String,
    pub status: ApprovalStatus,
    pub approval_weight: u64,
    pub submitted_height: u64,
}

impl PqRecoveryApproval {
    pub fn new(
        packet_id: &str,
        guardian_id: &str,
        guardian_set_id: &str,
        approval_nullifier: &str,
        pq_signature_root: &str,
        transcript_root: &str,
        policy_witness_root: &str,
        approval_weight: u64,
        submitted_height: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let approval_id = recovery_id(
            "APPROVAL",
            &[
                packet_id,
                guardian_id,
                approval_nullifier,
                pq_signature_root,
                &submitted_height.to_string(),
            ],
        );
        let approval = Self {
            approval_id,
            packet_id: packet_id.to_string(),
            guardian_id: guardian_id.to_string(),
            guardian_set_id: guardian_set_id.to_string(),
            approval_nullifier: approval_nullifier.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            transcript_root: transcript_root.to_string(),
            policy_witness_root: policy_witness_root.to_string(),
            status: ApprovalStatus::Accepted,
            approval_weight,
            submitted_height,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("approval id", &self.approval_id)?;
        require_non_empty("packet id", &self.packet_id)?;
        require_non_empty("guardian id", &self.guardian_id)?;
        require_non_empty("guardian set id", &self.guardian_set_id)?;
        require_non_empty("approval nullifier", &self.approval_nullifier)?;
        require_non_empty("pq signature root", &self.pq_signature_root)?;
        require_non_empty("transcript root", &self.transcript_root)?;
        require_non_empty("policy witness root", &self.policy_witness_root)?;
        if self.approval_weight == 0 {
            return Err("approval weight must be greater than zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_pq_recovery_approval",
            "approval_id": self.approval_id,
            "packet_id": self.packet_id,
            "guardian_id": self.guardian_id,
            "guardian_set_id": self.guardian_set_id,
            "approval_nullifier": self.approval_nullifier,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "policy_witness_root": self.policy_witness_root,
            "status": self.status.as_str(),
            "approval_weight": self.approval_weight,
            "submitted_height": self.submitted_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingDelayLock {
    pub lock_id: String,
    pub packet_id: String,
    pub wallet_id: String,
    pub approval_root: String,
    pub pre_recovery_spend_root: String,
    pub post_recovery_spend_root: String,
    pub status: DelayLockStatus,
    pub lock_height: u64,
    pub unlock_height: u64,
    pub challenge_deadline_height: u64,
}

impl SpendingDelayLock {
    pub fn new(
        packet_id: &str,
        wallet_id: &str,
        approval_root: &str,
        pre_recovery_spend_root: &str,
        post_recovery_spend_root: &str,
        lock_height: u64,
        unlock_height: u64,
        challenge_deadline_height: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let lock_id = recovery_id(
            "DELAY-LOCK",
            &[
                packet_id,
                wallet_id,
                approval_root,
                &lock_height.to_string(),
                &unlock_height.to_string(),
            ],
        );
        let lock = Self {
            lock_id,
            packet_id: packet_id.to_string(),
            wallet_id: wallet_id.to_string(),
            approval_root: approval_root.to_string(),
            pre_recovery_spend_root: pre_recovery_spend_root.to_string(),
            post_recovery_spend_root: post_recovery_spend_root.to_string(),
            status: DelayLockStatus::Active,
            lock_height,
            unlock_height,
            challenge_deadline_height,
        };
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("lock id", &self.lock_id)?;
        require_non_empty("packet id", &self.packet_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("approval root", &self.approval_root)?;
        require_non_empty("pre recovery spend root", &self.pre_recovery_spend_root)?;
        require_non_empty("post recovery spend root", &self.post_recovery_spend_root)?;
        if self.unlock_height <= self.lock_height {
            return Err("unlock height must be after lock height".to_string());
        }
        if self.challenge_deadline_height < self.unlock_height {
            return Err("challenge deadline must cover unlock height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_spending_delay_lock",
            "lock_id": self.lock_id,
            "packet_id": self.packet_id,
            "wallet_id": self.wallet_id,
            "approval_root": self.approval_root,
            "pre_recovery_spend_root": self.pre_recovery_spend_root,
            "post_recovery_spend_root": self.post_recovery_spend_root,
            "status": self.status.as_str(),
            "lock_height": self.lock_height,
            "unlock_height": self.unlock_height,
            "challenge_deadline_height": self.challenge_deadline_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationNullifier {
    pub nullifier_id: String,
    pub wallet_id: String,
    pub guardian_id: String,
    pub packet_id: String,
    pub revocation_nullifier: String,
    pub reason_root: String,
    pub witness_root: String,
    pub height: u64,
    pub active: bool,
}

impl RevocationNullifier {
    pub fn new(
        wallet_id: &str,
        guardian_id: &str,
        packet_id: &str,
        revocation_nullifier: &str,
        reason_root: &str,
        witness_root: &str,
        height: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let nullifier_id = recovery_id(
            "REVOCATION",
            &[
                wallet_id,
                guardian_id,
                packet_id,
                revocation_nullifier,
                &height.to_string(),
            ],
        );
        let nullifier = Self {
            nullifier_id,
            wallet_id: wallet_id.to_string(),
            guardian_id: guardian_id.to_string(),
            packet_id: packet_id.to_string(),
            revocation_nullifier: revocation_nullifier.to_string(),
            reason_root: reason_root.to_string(),
            witness_root: witness_root.to_string(),
            height,
            active: true,
        };
        nullifier.validate()?;
        Ok(nullifier)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("nullifier id", &self.nullifier_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("guardian id", &self.guardian_id)?;
        require_non_empty("packet id", &self.packet_id)?;
        require_non_empty("revocation nullifier", &self.revocation_nullifier)?;
        require_non_empty("reason root", &self.reason_root)?;
        require_non_empty("witness root", &self.witness_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_revocation_nullifier",
            "nullifier_id": self.nullifier_id,
            "wallet_id": self.wallet_id,
            "guardian_id": self.guardian_id,
            "packet_id": self.packet_id,
            "revocation_nullifier": self.revocation_nullifier,
            "reason_root": self.reason_root,
            "witness_root": self.witness_root,
            "height": self.height,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWalletPolicyHook {
    pub hook_id: String,
    pub wallet_id: String,
    pub hook_kind: PolicyHookKind,
    pub hook_commitment_root: String,
    pub verifier_key_root: String,
    pub confidential_state_root: String,
    pub enforcement_weight_bps: u64,
    pub active: bool,
    pub revision: u64,
}

impl PrivateWalletPolicyHook {
    pub fn new(
        wallet_id: &str,
        hook_kind: PolicyHookKind,
        hook_commitment_root: &str,
        verifier_key_root: &str,
        confidential_state_root: &str,
        enforcement_weight_bps: u64,
        revision: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let hook_id = recovery_id(
            "POLICY-HOOK",
            &[
                wallet_id,
                hook_kind.as_str(),
                hook_commitment_root,
                verifier_key_root,
                &revision.to_string(),
            ],
        );
        let hook = Self {
            hook_id,
            wallet_id: wallet_id.to_string(),
            hook_kind,
            hook_commitment_root: hook_commitment_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            confidential_state_root: confidential_state_root.to_string(),
            enforcement_weight_bps,
            active: true,
            revision,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("hook id", &self.hook_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("hook commitment root", &self.hook_commitment_root)?;
        require_non_empty("verifier key root", &self.verifier_key_root)?;
        require_non_empty("confidential state root", &self.confidential_state_root)?;
        if self.enforcement_weight_bps > QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_BPS {
            return Err("policy hook enforcement bps exceeds maximum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_private_wallet_policy_hook",
            "hook_id": self.hook_id,
            "wallet_id": self.wallet_id,
            "hook_kind": self.hook_kind.as_str(),
            "hook_commitment_root": self.hook_commitment_root,
            "verifier_key_root": self.verifier_key_root,
            "confidential_state_root": self.confidential_state_root,
            "enforcement_weight_bps": self.enforcement_weight_bps,
            "active": self.active,
            "revision": self.revision,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsoredRecoveryLane {
    pub lane_id: String,
    pub lane_kind: SponsorLaneKind,
    pub sponsor_commitment: String,
    pub budget_commitment_root: String,
    pub eligibility_root: String,
    pub max_fee_micro_units: u64,
    pub spent_fee_micro_units: u64,
    pub priority_bps: u64,
    pub active: bool,
}

impl FeeSponsoredRecoveryLane {
    pub fn new(
        lane_kind: SponsorLaneKind,
        sponsor_commitment: &str,
        budget_commitment_root: &str,
        eligibility_root: &str,
        max_fee_micro_units: u64,
        spent_fee_micro_units: u64,
        priority_bps: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let lane_id = recovery_id(
            "SPONSOR-LANE",
            &[
                lane_kind.as_str(),
                sponsor_commitment,
                budget_commitment_root,
                eligibility_root,
            ],
        );
        let lane = Self {
            lane_id,
            lane_kind,
            sponsor_commitment: sponsor_commitment.to_string(),
            budget_commitment_root: budget_commitment_root.to_string(),
            eligibility_root: eligibility_root.to_string(),
            max_fee_micro_units,
            spent_fee_micro_units,
            priority_bps,
            active: true,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("lane id", &self.lane_id)?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("budget commitment root", &self.budget_commitment_root)?;
        require_non_empty("eligibility root", &self.eligibility_root)?;
        if self.spent_fee_micro_units > self.max_fee_micro_units {
            return Err("spent sponsor fee exceeds lane cap".to_string());
        }
        if self.priority_bps > QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_MAX_BPS {
            return Err("sponsor lane priority bps exceeds maximum".to_string());
        }
        Ok(())
    }

    pub fn remaining_fee_micro_units(&self) -> u64 {
        self.max_fee_micro_units
            .saturating_sub(self.spent_fee_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_fee_sponsored_recovery_lane",
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "budget_commitment_root": self.budget_commitment_root,
            "eligibility_root": self.eligibility_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "spent_fee_micro_units": self.spent_fee_micro_units,
            "remaining_fee_micro_units": self.remaining_fee_micro_units(),
            "priority_bps": self.priority_bps,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAuditEvent {
    pub event_id: String,
    pub wallet_id: String,
    pub subject_id: String,
    pub event_kind: String,
    pub event_root: String,
    pub previous_event_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RecoveryAuditEvent {
    pub fn new(
        wallet_id: &str,
        subject_id: &str,
        event_kind: &str,
        event_root: &str,
        previous_event_root: &str,
        height: u64,
        sequence: u64,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let event_id = recovery_id(
            "AUDIT-EVENT",
            &[
                wallet_id,
                subject_id,
                event_kind,
                event_root,
                &height.to_string(),
                &sequence.to_string(),
            ],
        );
        let event = Self {
            event_id,
            wallet_id: wallet_id.to_string(),
            subject_id: subject_id.to_string(),
            event_kind: event_kind.to_string(),
            event_root: event_root.to_string(),
            previous_event_root: previous_event_root.to_string(),
            height,
            sequence,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        require_non_empty("event id", &self.event_id)?;
        require_non_empty("wallet id", &self.wallet_id)?;
        require_non_empty("subject id", &self.subject_id)?;
        require_non_empty("event kind", &self.event_kind)?;
        require_non_empty("event root", &self.event_root)?;
        require_non_empty("previous event root", &self.previous_event_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_recovery_audit_event",
            "event_id": self.event_id,
            "wallet_id": self.wallet_id,
            "subject_id": self.subject_id,
            "event_kind": self.event_kind,
            "event_root": self.event_root,
            "previous_event_root": self.previous_event_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub wallet_policy_root: String,
    pub guardian_set_root: String,
    pub guardian_commitment_root: String,
    pub recovery_packet_root: String,
    pub approval_root: String,
    pub delay_lock_root: String,
    pub revocation_nullifier_root: String,
    pub policy_hook_root: String,
    pub sponsor_lane_root: String,
    pub audit_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_wallet_social_recovery_guard_roots",
            "config_root": self.config_root,
            "wallet_policy_root": self.wallet_policy_root,
            "guardian_set_root": self.guardian_set_root,
            "guardian_commitment_root": self.guardian_commitment_root,
            "recovery_packet_root": self.recovery_packet_root,
            "approval_root": self.approval_root,
            "delay_lock_root": self.delay_lock_root,
            "revocation_nullifier_root": self.revocation_nullifier_root,
            "policy_hook_root": self.policy_hook_root,
            "sponsor_lane_root": self.sponsor_lane_root,
            "audit_event_root": self.audit_event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub wallet_policies: usize,
    pub guardian_sets: usize,
    pub guardian_commitments: usize,
    pub recovery_packets: usize,
    pub approvals: usize,
    pub delay_locks: usize,
    pub revocation_nullifiers: usize,
    pub policy_hooks: usize,
    pub sponsor_lanes: usize,
    pub audit_events: usize,
    pub active_packets: usize,
    pub threshold_met_packets: usize,
    pub active_delay_locks: usize,
    pub sponsored_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_wallet_social_recovery_guard_counters",
            "wallet_policies": self.wallet_policies,
            "guardian_sets": self.guardian_sets,
            "guardian_commitments": self.guardian_commitments,
            "recovery_packets": self.recovery_packets,
            "approvals": self.approvals,
            "delay_locks": self.delay_locks,
            "revocation_nullifiers": self.revocation_nullifiers,
            "policy_hooks": self.policy_hooks,
            "sponsor_lanes": self.sponsor_lanes,
            "audit_events": self.audit_events,
            "active_packets": self.active_packets,
            "threshold_met_packets": self.threshold_met_packets,
            "active_delay_locks": self.active_delay_locks,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub wallet_policies: BTreeMap<String, WalletRecoveryPolicy>,
    pub guardian_sets: BTreeMap<String, GuardianSet>,
    pub guardian_commitments: BTreeMap<String, GuardianCommitment>,
    pub recovery_packets: BTreeMap<String, EncryptedRecoveryPacket>,
    pub approvals: BTreeMap<String, PqRecoveryApproval>,
    pub delay_locks: BTreeMap<String, SpendingDelayLock>,
    pub revocation_nullifiers: BTreeMap<String, RevocationNullifier>,
    pub policy_hooks: BTreeMap<String, PrivateWalletPolicyHook>,
    pub sponsor_lanes: BTreeMap<String, FeeSponsoredRecoveryLane>,
    pub audit_events: BTreeMap<String, RecoveryAuditEvent>,
}

impl State {
    pub fn new(config: Config, height: u64) -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        config.validate()?;
        let state = Self {
            height,
            config,
            wallet_policies: BTreeMap::new(),
            guardian_sets: BTreeMap::new(),
            guardian_commitments: BTreeMap::new(),
            recovery_packets: BTreeMap::new(),
            approvals: BTreeMap::new(),
            delay_locks: BTreeMap::new(),
            revocation_nullifiers: BTreeMap::new(),
            policy_hooks: BTreeMap::new(),
            sponsor_lanes: BTreeMap::new(),
            audit_events: BTreeMap::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> QuantumSafeWalletSocialRecoveryGuardResult<Self> {
        let mut state = Self::new(
            Config::default(),
            QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_DEVNET_HEIGHT,
        )?;

        let sponsor_lane = FeeSponsoredRecoveryLane::new(
            SponsorLaneKind::RetailRecovery,
            &sample_root("sponsor", "community-recovery-vault"),
            &sample_root("sponsor-budget", "retail-lane"),
            &sample_root("eligibility", "low-fee-wallets"),
            25_000_000,
            4_200_000,
            7_500,
        )?;
        state.insert_sponsor_lane(sponsor_lane.clone())?;

        let policy = WalletRecoveryPolicy::new(
            WalletClass::PrivateSmartAccount,
            "pending-guardian-set",
            &sample_root("owner", "wallet-owner-a"),
            &sample_root("spend-authority", "wallet-owner-a-current"),
            &sample_root("recovery-destination", "wallet-owner-a-next"),
            &sample_root("private-policy", "wallet-owner-a"),
            500_000_000,
            state.config.default_delay_blocks,
            state.config.default_challenge_blocks,
            true,
            true,
            1,
        )?;
        let wallet_id = policy.wallet_id.clone();
        state.insert_wallet_policy(policy)?;

        let guardian_a = GuardianCommitment::new(
            &wallet_id,
            "pending-guardian-set",
            GuardianRole::Primary,
            &sample_root("guardian-identity", "alice"),
            &sample_root("guardian-share", "alice"),
            &sample_root("notification-key", "alice"),
            &sample_root("stake", "alice"),
            &sample_root("guardian-meta", "alice"),
            2,
            state.height,
            1,
        )?;
        let guardian_b = GuardianCommitment::new(
            &wallet_id,
            "pending-guardian-set",
            GuardianRole::DeviceShard,
            &sample_root("guardian-identity", "device"),
            &sample_root("guardian-share", "device"),
            &sample_root("notification-key", "device"),
            &sample_root("stake", "device"),
            &sample_root("guardian-meta", "device"),
            1,
            state.height,
            1,
        )?;
        let guardian_c = GuardianCommitment::new(
            &wallet_id,
            "pending-guardian-set",
            GuardianRole::RecoveryCouncil,
            &sample_root("guardian-identity", "council"),
            &sample_root("guardian-share", "council"),
            &sample_root("notification-key", "council"),
            &sample_root("stake", "council"),
            &sample_root("guardian-meta", "council"),
            2,
            state.height,
            1,
        )?;
        let guardian_ids = [
            guardian_a.guardian_id.clone(),
            guardian_b.guardian_id.clone(),
            guardian_c.guardian_id.clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        state.insert_guardian_commitment(guardian_a.clone())?;
        state.insert_guardian_commitment(guardian_b.clone())?;
        state.insert_guardian_commitment(guardian_c.clone())?;

        let guardian_records = guardian_ids
            .iter()
            .filter_map(|id| state.guardian_commitments.get(id))
            .map(GuardianCommitment::public_record)
            .collect::<Vec<_>>();
        let guardian_root = merkle_root(
            "QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:DEVNET-GUARDIANS",
            &guardian_records,
        );
        let guardian_set = GuardianSet::new(
            &wallet_id,
            guardian_ids,
            3,
            2,
            &guardian_root,
            &sample_root("guardian-set-policy", "wallet-owner-a"),
            1,
        )?;
        let guardian_set_id = guardian_set.guardian_set_id.clone();
        state.insert_guardian_set(guardian_set)?;
        if let Some(policy) = state.wallet_policies.get_mut(&wallet_id) {
            policy.active_guardian_set_id = guardian_set_id.clone();
        }

        let hook = PrivateWalletPolicyHook::new(
            &wallet_id,
            PolicyHookKind::SpendingLimit,
            &sample_root("hook", "daily-spend-limit"),
            &sample_root("verifier-key", "spending-limit"),
            &sample_root("confidential-state", "spending-limit"),
            6_500,
            1,
        )?;
        state.insert_policy_hook(hook)?;

        let packet = EncryptedRecoveryPacket::new(
            &wallet_id,
            &guardian_set_id,
            &sample_root("new-spend-authority", "wallet-owner-a-next"),
            &sample_root("encrypted-packet", "wallet-owner-a"),
            &sample_root("pq-kem-ciphertext", "wallet-owner-a"),
            &sample_root("recovery-hint", "wallet-owner-a"),
            &sponsor_lane.lane_id,
            state.height,
            state.height + state.config.default_packet_ttl_blocks,
            3,
            850_000,
        )?;
        let packet_id = packet.packet_id.clone();
        state.insert_recovery_packet(packet)?;

        let approval_a = PqRecoveryApproval::new(
            &packet_id,
            &guardian_a.guardian_id,
            &guardian_set_id,
            &sample_root("approval-nullifier", "alice"),
            &sample_root("pq-signature", "alice"),
            &sample_root("approval-transcript", "alice"),
            &sample_root("policy-witness", "alice"),
            2,
            state.height + 1,
        )?;
        let approval_c = PqRecoveryApproval::new(
            &packet_id,
            &guardian_c.guardian_id,
            &guardian_set_id,
            &sample_root("approval-nullifier", "council"),
            &sample_root("pq-signature", "council"),
            &sample_root("approval-transcript", "council"),
            &sample_root("policy-witness", "council"),
            2,
            state.height + 2,
        )?;
        state.insert_approval(approval_a)?;
        state.insert_approval(approval_c)?;

        let packet_approval_root = state.approval_root_for_packet(&packet_id);
        let lock = SpendingDelayLock::new(
            &packet_id,
            &wallet_id,
            &packet_approval_root,
            &sample_root("pre-recovery-spend", "wallet-owner-a"),
            &sample_root("post-recovery-spend", "wallet-owner-a"),
            state.height + 3,
            state.height + 3 + state.config.default_delay_blocks,
            state.height
                + 3
                + state.config.default_delay_blocks
                + state.config.default_challenge_blocks,
        )?;
        state.insert_delay_lock(lock)?;

        let revocation = RevocationNullifier::new(
            &wallet_id,
            &guardian_b.guardian_id,
            &packet_id,
            &sample_root("revocation-nullifier", "device"),
            &sample_root("revocation-reason", "lost-device"),
            &sample_root("revocation-witness", "device"),
            state.height + 4,
        )?;
        state.insert_revocation_nullifier(revocation)?;

        let checkpoint_event = RecoveryAuditEvent::new(
            &wallet_id,
            &packet_id,
            "threshold_met_and_delay_locked",
            &state.roots_without_state().public_record().to_string(),
            &sample_root("previous-event", "genesis"),
            state.height + 5,
            1,
        )?;
        state.insert_audit_event(checkpoint_event)?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        self.config.validate()?;
        if self.guardian_sets.len() > self.config.max_guardian_sets {
            return Err("guardian set count exceeds configuration limit".to_string());
        }
        if self.guardian_commitments.len()
            > self.config.max_guardians_per_set * self.config.max_guardian_sets
        {
            return Err("guardian commitment count exceeds configuration limit".to_string());
        }
        if self.wallet_policies.len() > self.config.max_wallets {
            return Err("wallet policy count exceeds configuration limit".to_string());
        }
        if self.recovery_packets.len() > self.config.max_packets {
            return Err("recovery packet count exceeds configuration limit".to_string());
        }
        if self.approvals.len() > self.config.max_approvals {
            return Err("approval count exceeds configuration limit".to_string());
        }
        if self.delay_locks.len() > self.config.max_locks {
            return Err("delay lock count exceeds configuration limit".to_string());
        }
        if self.revocation_nullifiers.len() > self.config.max_revocations {
            return Err("revocation nullifier count exceeds configuration limit".to_string());
        }
        if self.policy_hooks.len() > self.config.max_policy_hooks {
            return Err("policy hook count exceeds configuration limit".to_string());
        }
        if self.sponsor_lanes.len() > self.config.max_sponsor_lanes {
            return Err("sponsor lane count exceeds configuration limit".to_string());
        }
        if self.audit_events.len() > self.config.max_events {
            return Err("audit event count exceeds configuration limit".to_string());
        }
        for policy in self.wallet_policies.values() {
            policy.validate()?;
        }
        for set in self.guardian_sets.values() {
            set.validate()?;
            if !self.wallet_policies.contains_key(&set.wallet_id) {
                return Err(format!(
                    "guardian set references unknown wallet {}",
                    set.wallet_id
                ));
            }
        }
        for guardian in self.guardian_commitments.values() {
            guardian.validate()?;
            if !self.wallet_policies.contains_key(&guardian.wallet_id) {
                return Err(format!(
                    "guardian commitment references unknown wallet {}",
                    guardian.wallet_id
                ));
            }
        }
        for packet in self.recovery_packets.values() {
            packet.validate()?;
            if !self.wallet_policies.contains_key(&packet.wallet_id) {
                return Err(format!(
                    "recovery packet references unknown wallet {}",
                    packet.wallet_id
                ));
            }
            if !self.guardian_sets.contains_key(&packet.guardian_set_id) {
                return Err(format!(
                    "recovery packet references unknown guardian set {}",
                    packet.guardian_set_id
                ));
            }
            if !self.sponsor_lanes.contains_key(&packet.sponsor_lane_id) {
                return Err(format!(
                    "recovery packet references unknown sponsor lane {}",
                    packet.sponsor_lane_id
                ));
            }
        }
        for approval in self.approvals.values() {
            approval.validate()?;
            if !self.recovery_packets.contains_key(&approval.packet_id) {
                return Err(format!(
                    "approval references unknown packet {}",
                    approval.packet_id
                ));
            }
            if !self
                .guardian_commitments
                .contains_key(&approval.guardian_id)
            {
                return Err(format!(
                    "approval references unknown guardian {}",
                    approval.guardian_id
                ));
            }
        }
        for lock in self.delay_locks.values() {
            lock.validate()?;
            if !self.recovery_packets.contains_key(&lock.packet_id) {
                return Err(format!(
                    "delay lock references unknown packet {}",
                    lock.packet_id
                ));
            }
        }
        for nullifier in self.revocation_nullifiers.values() {
            nullifier.validate()?;
        }
        for hook in self.policy_hooks.values() {
            hook.validate()?;
            if !self.wallet_policies.contains_key(&hook.wallet_id) {
                return Err(format!(
                    "policy hook references unknown wallet {}",
                    hook.wallet_id
                ));
            }
        }
        for lane in self.sponsor_lanes.values() {
            lane.validate()?;
        }
        for event in self.audit_events.values() {
            event.validate()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        self.set_height(height)
    }

    pub fn insert_wallet_policy(
        &mut self,
        policy: WalletRecoveryPolicy,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        policy.validate()?;
        self.wallet_policies
            .insert(policy.wallet_id.clone(), policy);
        self.validate()
    }

    pub fn insert_guardian_set(
        &mut self,
        guardian_set: GuardianSet,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        guardian_set.validate()?;
        self.guardian_sets
            .insert(guardian_set.guardian_set_id.clone(), guardian_set);
        self.validate()
    }

    pub fn insert_guardian_commitment(
        &mut self,
        guardian: GuardianCommitment,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        guardian.validate()?;
        self.guardian_commitments
            .insert(guardian.guardian_id.clone(), guardian);
        self.validate()
    }

    pub fn insert_recovery_packet(
        &mut self,
        packet: EncryptedRecoveryPacket,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        packet.validate()?;
        self.recovery_packets
            .insert(packet.packet_id.clone(), packet);
        self.validate()
    }

    pub fn insert_approval(
        &mut self,
        approval: PqRecoveryApproval,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        approval.validate()?;
        self.approvals
            .insert(approval.approval_id.clone(), approval);
        self.validate()
    }

    pub fn insert_delay_lock(
        &mut self,
        lock: SpendingDelayLock,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        lock.validate()?;
        self.delay_locks.insert(lock.lock_id.clone(), lock);
        self.validate()
    }

    pub fn insert_revocation_nullifier(
        &mut self,
        nullifier: RevocationNullifier,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        nullifier.validate()?;
        self.revocation_nullifiers
            .insert(nullifier.nullifier_id.clone(), nullifier);
        self.validate()
    }

    pub fn insert_policy_hook(
        &mut self,
        hook: PrivateWalletPolicyHook,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        hook.validate()?;
        self.policy_hooks.insert(hook.hook_id.clone(), hook);
        self.validate()
    }

    pub fn insert_sponsor_lane(
        &mut self,
        lane: FeeSponsoredRecoveryLane,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        lane.validate()?;
        self.sponsor_lanes.insert(lane.lane_id.clone(), lane);
        self.validate()
    }

    pub fn insert_audit_event(
        &mut self,
        event: RecoveryAuditEvent,
    ) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
        event.validate()?;
        self.audit_events.insert(event.event_id.clone(), event);
        self.validate()
    }

    pub fn counters(&self) -> Counters {
        Counters {
            wallet_policies: self.wallet_policies.len(),
            guardian_sets: self.guardian_sets.len(),
            guardian_commitments: self.guardian_commitments.len(),
            recovery_packets: self.recovery_packets.len(),
            approvals: self.approvals.len(),
            delay_locks: self.delay_locks.len(),
            revocation_nullifiers: self.revocation_nullifiers.len(),
            policy_hooks: self.policy_hooks.len(),
            sponsor_lanes: self.sponsor_lanes.len(),
            audit_events: self.audit_events.len(),
            active_packets: self
                .recovery_packets
                .values()
                .filter(|packet| {
                    matches!(
                        packet.status,
                        RecoveryPacketStatus::Announced
                            | RecoveryPacketStatus::CollectingApprovals
                            | RecoveryPacketStatus::ThresholdMet
                            | RecoveryPacketStatus::Locked
                    )
                })
                .count(),
            threshold_met_packets: self
                .recovery_packets
                .values()
                .filter(|packet| {
                    self.accepted_approval_weight(&packet.packet_id)
                        >= packet.approval_threshold_weight
                })
                .count(),
            active_delay_locks: self
                .delay_locks
                .values()
                .filter(|lock| lock.status == DelayLockStatus::Active)
                .count(),
            sponsored_fee_micro_units: self
                .sponsor_lanes
                .values()
                .map(|lane| lane.spent_fee_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let mut roots = self.roots_without_state();
        roots.state_root = self.state_root_from_roots(&roots);
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "quantum_safe_wallet_social_recovery_guard_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "protocol_version": self.config.protocol_version,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "wallet_policies": self.wallet_policies.values().map(WalletRecoveryPolicy::public_record).collect::<Vec<_>>(),
            "guardian_sets": self.guardian_sets.values().map(GuardianSet::public_record).collect::<Vec<_>>(),
            "guardian_commitments": self.guardian_commitments.values().map(GuardianCommitment::public_record).collect::<Vec<_>>(),
            "recovery_packets": self.recovery_packets.values().map(EncryptedRecoveryPacket::public_record).collect::<Vec<_>>(),
            "approvals": self.approvals.values().map(PqRecoveryApproval::public_record).collect::<Vec<_>>(),
            "delay_locks": self.delay_locks.values().map(SpendingDelayLock::public_record).collect::<Vec<_>>(),
            "revocation_nullifiers": self.revocation_nullifiers.values().map(RevocationNullifier::public_record).collect::<Vec<_>>(),
            "policy_hooks": self.policy_hooks.values().map(PrivateWalletPolicyHook::public_record).collect::<Vec<_>>(),
            "sponsor_lanes": self.sponsor_lanes.values().map(FeeSponsoredRecoveryLane::public_record).collect::<Vec<_>>(),
            "audit_events": self.audit_events.values().map(RecoveryAuditEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn accepted_approval_weight(&self, packet_id: &str) -> u64 {
        self.approvals
            .values()
            .filter(|approval| {
                approval.packet_id == packet_id && approval.status == ApprovalStatus::Accepted
            })
            .map(|approval| approval.approval_weight)
            .sum()
    }

    pub fn approval_root_for_packet(&self, packet_id: &str) -> String {
        let approvals = self
            .approvals
            .values()
            .filter(|approval| approval.packet_id == packet_id)
            .map(PqRecoveryApproval::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:PACKET-APPROVAL",
            &approvals,
        )
    }

    fn roots_without_state(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            wallet_policy_root: map_root(
                "WALLET-POLICY",
                self.wallet_policies
                    .values()
                    .map(WalletRecoveryPolicy::public_record)
                    .collect(),
            ),
            guardian_set_root: map_root(
                "GUARDIAN-SET",
                self.guardian_sets
                    .values()
                    .map(GuardianSet::public_record)
                    .collect(),
            ),
            guardian_commitment_root: map_root(
                "GUARDIAN-COMMITMENT",
                self.guardian_commitments
                    .values()
                    .map(GuardianCommitment::public_record)
                    .collect(),
            ),
            recovery_packet_root: map_root(
                "RECOVERY-PACKET",
                self.recovery_packets
                    .values()
                    .map(EncryptedRecoveryPacket::public_record)
                    .collect(),
            ),
            approval_root: map_root(
                "PQ-APPROVAL",
                self.approvals
                    .values()
                    .map(PqRecoveryApproval::public_record)
                    .collect(),
            ),
            delay_lock_root: map_root(
                "DELAY-LOCK",
                self.delay_locks
                    .values()
                    .map(SpendingDelayLock::public_record)
                    .collect(),
            ),
            revocation_nullifier_root: map_root(
                "REVOCATION-NULLIFIER",
                self.revocation_nullifiers
                    .values()
                    .map(RevocationNullifier::public_record)
                    .collect(),
            ),
            policy_hook_root: map_root(
                "POLICY-HOOK",
                self.policy_hooks
                    .values()
                    .map(PrivateWalletPolicyHook::public_record)
                    .collect(),
            ),
            sponsor_lane_root: map_root(
                "SPONSOR-LANE",
                self.sponsor_lanes
                    .values()
                    .map(FeeSponsoredRecoveryLane::public_record)
                    .collect(),
            ),
            audit_event_root: map_root(
                "AUDIT-EVENT",
                self.audit_events
                    .values()
                    .map(RecoveryAuditEvent::public_record)
                    .collect(),
            ),
            state_root: String::new(),
        }
    }

    fn state_root_from_roots(&self, roots: &Roots) -> String {
        domain_hash(
            "QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(&self.height.to_string()),
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.wallet_policy_root),
                HashPart::Str(&roots.guardian_set_root),
                HashPart::Str(&roots.guardian_commitment_root),
                HashPart::Str(&roots.recovery_packet_root),
                HashPart::Str(&roots.approval_root),
                HashPart::Str(&roots.delay_lock_root),
                HashPart::Str(&roots.revocation_nullifier_root),
                HashPart::Str(&roots.policy_hook_root),
                HashPart::Str(&roots.sponsor_lane_root),
                HashPart::Str(&roots.audit_event_root),
            ],
            32,
        )
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    domain_hash(
        "QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> QuantumSafeWalletSocialRecoveryGuardResult<State> {
    State::devnet()
}

fn require_non_empty(label: &str, value: &str) -> QuantumSafeWalletSocialRecoveryGuardResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn recovery_id(domain: &str, parts: &[&str]) -> String {
    let part_records = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    let part_root = merkle_root(
        &format!("QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:{domain}:PARTS"),
        &part_records,
    );
    domain_hash(
        &format!("QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:{domain}:ID"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PROTOCOL_VERSION),
            HashPart::Str(&part_root),
        ],
        32,
    )
}

fn map_root(label: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:{label}"),
        &records,
    )
}

fn sample_root(label: &str, value: &str) -> String {
    domain_hash(
        &format!("QUANTUM-SAFE-WALLET-SOCIAL-RECOVERY-GUARD:SAMPLE:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(QUANTUM_SAFE_WALLET_SOCIAL_RECOVERY_GUARD_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}
