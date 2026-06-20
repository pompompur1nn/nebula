use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PqContractUpgradeGuardResult<T> = Result<T, String>;

pub const PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION: &str =
    "nebula-l2-pq-contract-upgrade-guard-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_SCHEMA_VERSION: u64 = 1;
pub const PQ_CONTRACT_UPGRADE_GUARD_SECURITY_MODEL: &str =
    "deterministic-devnet-pq-contract-upgrade-guard-not-real-crypto";
pub const PQ_CONTRACT_UPGRADE_GUARD_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PQ_CONTRACT_UPGRADE_GUARD_AUTHORITY_SCHEME: &str =
    "pq-threshold-contract-upgrade-authority-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_MANIFEST_SCHEME: &str =
    "timelocked-private-contract-upgrade-manifest-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_BYTECODE_COMMITMENT_SCHEME: &str =
    "shake256-contract-bytecode-compatibility-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_INTERFACE_COMMITMENT_SCHEME: &str =
    "shake256-canonical-interface-compatibility-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_DISCLOSURE_SCHEME: &str =
    "ml-kem-sealed-private-upgrade-disclosure-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-contract-upgrade-sponsorship-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_RECEIPT_SCHEME: &str = "private-contract-migration-receipt-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_ROLLBACK_SCHEME: &str =
    "deterministic-private-contract-rollback-plan-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_AUDIT_SCHEME: &str =
    "pq-private-contract-upgrade-audit-attestation-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-upgrade-guard-record-v1";
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_HEIGHT: u64 = 768;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_NOTICE_BLOCKS: u64 = 1_440;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_ACTIVATION_DELAY_BLOCKS: u64 = 2_880;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_EXECUTION_WINDOW_BLOCKS: u64 = 720;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 12;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_DISCLOSURE_WINDOW_BLOCKS: u64 = 240;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_PRIVATE_REVIEW_BLOCKS: u64 = 96;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 1_440;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 7_200;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 20_160;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MIN_AUTHORITY_SIGNERS: u64 = 3;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_AUTHORITY_THRESHOLD: u64 = 2;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MIN_AUDIT_ATTESTATIONS: u64 = 2;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MIN_AUDIT_SCORE_BPS: u64 = 8_500;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_000;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 500_000;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MAX_SPONSORED_FEE_UNITS: u64 = 2_500;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_BPS: u64 = 10_000;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_AUTHORITIES: usize = 128;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_MANIFESTS: usize = 256;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_COMPATIBILITY_COMMITMENTS: usize = 512;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_PAUSES: usize = 128;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_DISCLOSURE_WINDOWS: usize = 256;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_SPONSORSHIPS: usize = 256;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_RECEIPTS: usize = 512;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_ROLLBACK_PLANS: usize = 256;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_AUDIT_ATTESTATIONS: usize = 512;
pub const PQ_CONTRACT_UPGRADE_GUARD_MAX_PUBLIC_RECORDS: usize = 1_024;
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_LOW_FEE_LANE: &str = "private-contract-upgrades";
pub const PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_NAMESPACE: &str = "nebula.devnet.private";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardedContractKind {
    PrivateToken,
    PrivateAmm,
    PrivateLending,
    PrivateStablecoin,
    PrivateOracle,
    PrivatePaymaster,
    BridgeAdapter,
    Governance,
    AccountModule,
    Custom,
}

impl GuardedContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateToken => "private_token",
            Self::PrivateAmm => "private_amm",
            Self::PrivateLending => "private_lending",
            Self::PrivateStablecoin => "private_stablecoin",
            Self::PrivateOracle => "private_oracle",
            Self::PrivatePaymaster => "private_paymaster",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::AccountModule => "account_module",
            Self::Custom => "custom",
        }
    }

    pub fn is_defi(self) -> bool {
        matches!(
            self,
            Self::PrivateAmm | Self::PrivateLending | Self::PrivateStablecoin | Self::PrivateOracle
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractUpgradeRiskTier {
    Routine,
    PrivateStateMigration,
    DefiInvariant,
    BridgeCritical,
    EmergencyPatch,
}

impl ContractUpgradeRiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::PrivateStateMigration => "private_state_migration",
            Self::DefiInvariant => "defi_invariant",
            Self::BridgeCritical => "bridge_critical",
            Self::EmergencyPatch => "emergency_patch",
        }
    }

    pub fn emergency_capable(self) -> bool {
        matches!(self, Self::BridgeCritical | Self::EmergencyPatch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Timelocked,
    Disclosed,
    Ready,
    Executed,
    Expired,
    Vetoed,
    RolledBack,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Timelocked => "timelocked",
            Self::Disclosed => "disclosed",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Vetoed => "vetoed",
            Self::RolledBack => "rolled_back",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Timelocked | Self::Disclosed | Self::Ready
        )
    }

    pub fn executable(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Expired | Self::Vetoed | Self::RolledBack
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityKind {
    Bytecode,
    Interface,
    StorageLayout,
    PrivateStateSchema,
    VerifierKey,
    DefiInvariant,
}

impl CompatibilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bytecode => "bytecode",
            Self::Interface => "interface",
            Self::StorageLayout => "storage_layout",
            Self::PrivateStateSchema => "private_state_schema",
            Self::VerifierKey => "verifier_key",
            Self::DefiInvariant => "defi_invariant",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Proposed,
    Pinned,
    Verified,
    Failed,
    Superseded,
}

impl CompatibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Pinned => "pinned",
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Pinned | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyGuardMode {
    None,
    PauseCalls,
    PauseMutations,
    MigrationOnly,
    VetoUpgrade,
    Frozen,
}

impl EmergencyGuardMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PauseCalls => "pause_calls",
            Self::PauseMutations => "pause_mutations",
            Self::MigrationOnly => "migration_only",
            Self::VetoUpgrade => "veto_upgrade",
            Self::Frozen => "frozen",
        }
    }

    pub fn blocks_execution(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureAudience {
    UpgradeAuthority,
    Auditor,
    AffectedUsers,
    DefiIntegrator,
    Watchtower,
    PublicSummary,
}

impl DisclosureAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpgradeAuthority => "upgrade_authority",
            Self::Auditor => "auditor",
            Self::AffectedUsers => "affected_users",
            Self::DefiIntegrator => "defi_integrator",
            Self::Watchtower => "watchtower",
            Self::PublicSummary => "public_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Sealed,
    Open,
    Closed,
    Revoked,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Active,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Reserved | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationReceiptStatus {
    Pending,
    Accepted,
    Finalized,
    Rejected,
    RolledBack,
}

impl MigrationReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::RolledBack => "rolled_back",
        }
    }

    pub fn final_state(self) -> bool {
        matches!(self, Self::Finalized | Self::Rejected | Self::RolledBack)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Planned,
    Armed,
    Executed,
    Expired,
    Cancelled,
}

impl RollbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Armed => "armed",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Planned | Self::Armed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    Bytecode,
    Interface,
    PrivateState,
    DefiInvariant,
    Migration,
    Rollback,
    EmergencyControl,
    FeeSponsorship,
}

impl AuditScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bytecode => "bytecode",
            Self::Interface => "interface",
            Self::PrivateState => "private_state",
            Self::DefiInvariant => "defi_invariant",
            Self::Migration => "migration",
            Self::Rollback => "rollback",
            Self::EmergencyControl => "emergency_control",
            Self::FeeSponsorship => "fee_sponsorship",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Active,
    Accepted,
    Rejected,
    Expired,
    Revoked,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqContractUpgradeGuardConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub security_model: String,
    pub pq_suite: String,
    pub namespace: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub default_notice_blocks: u64,
    pub activation_delay_blocks: u64,
    pub execution_window_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub disclosure_window_blocks: u64,
    pub private_review_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub rollback_window_blocks: u64,
    pub audit_ttl_blocks: u64,
    pub min_authority_signers: u64,
    pub authority_threshold: u64,
    pub min_audit_attestations: u64,
    pub min_audit_score_bps: u64,
    pub max_disclosure_bps: u64,
    pub sponsor_budget_units: u64,
    pub max_sponsored_fee_units: u64,
    pub max_authorities: usize,
    pub max_manifests: usize,
    pub max_compatibility_commitments: usize,
    pub max_pauses: usize,
    pub max_disclosure_windows: usize,
    pub max_sponsorships: usize,
    pub max_receipts: usize,
    pub max_rollback_plans: usize,
    pub max_audit_attestations: usize,
    pub max_public_records: usize,
}

impl PqContractUpgradeGuardConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            security_model: PQ_CONTRACT_UPGRADE_GUARD_SECURITY_MODEL.to_string(),
            pq_suite: PQ_CONTRACT_UPGRADE_GUARD_PQ_SUITE.to_string(),
            namespace: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_NAMESPACE.to_string(),
            fee_asset_id: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_FEE_ASSET_ID.to_string(),
            low_fee_lane: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_LOW_FEE_LANE.to_string(),
            default_notice_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_NOTICE_BLOCKS,
            activation_delay_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_ACTIVATION_DELAY_BLOCKS,
            execution_window_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_EXECUTION_WINDOW_BLOCKS,
            emergency_delay_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            disclosure_window_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_DISCLOSURE_WINDOW_BLOCKS,
            private_review_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_PRIVATE_REVIEW_BLOCKS,
            sponsorship_ttl_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_SPONSOR_TTL_BLOCKS,
            rollback_window_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            audit_ttl_blocks: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_AUDIT_TTL_BLOCKS,
            min_authority_signers: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MIN_AUTHORITY_SIGNERS,
            authority_threshold: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_AUTHORITY_THRESHOLD,
            min_audit_attestations: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MIN_AUDIT_ATTESTATIONS,
            min_audit_score_bps: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MIN_AUDIT_SCORE_BPS,
            max_disclosure_bps: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MAX_DISCLOSURE_BPS,
            sponsor_budget_units: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_sponsored_fee_units: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_MAX_SPONSORED_FEE_UNITS,
            max_authorities: PQ_CONTRACT_UPGRADE_GUARD_MAX_AUTHORITIES,
            max_manifests: PQ_CONTRACT_UPGRADE_GUARD_MAX_MANIFESTS,
            max_compatibility_commitments: PQ_CONTRACT_UPGRADE_GUARD_MAX_COMPATIBILITY_COMMITMENTS,
            max_pauses: PQ_CONTRACT_UPGRADE_GUARD_MAX_PAUSES,
            max_disclosure_windows: PQ_CONTRACT_UPGRADE_GUARD_MAX_DISCLOSURE_WINDOWS,
            max_sponsorships: PQ_CONTRACT_UPGRADE_GUARD_MAX_SPONSORSHIPS,
            max_receipts: PQ_CONTRACT_UPGRADE_GUARD_MAX_RECEIPTS,
            max_rollback_plans: PQ_CONTRACT_UPGRADE_GUARD_MAX_ROLLBACK_PLANS,
            max_audit_attestations: PQ_CONTRACT_UPGRADE_GUARD_MAX_AUDIT_ATTESTATIONS,
            max_public_records: PQ_CONTRACT_UPGRADE_GUARD_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_upgrade_guard_config",
            "protocol_version": self.protocol_version,
            "schema_version": PQ_CONTRACT_UPGRADE_GUARD_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "security_model": self.security_model,
            "pq_suite": self.pq_suite,
            "namespace": self.namespace,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "default_notice_blocks": self.default_notice_blocks,
            "activation_delay_blocks": self.activation_delay_blocks,
            "execution_window_blocks": self.execution_window_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "disclosure_window_blocks": self.disclosure_window_blocks,
            "private_review_blocks": self.private_review_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "rollback_window_blocks": self.rollback_window_blocks,
            "audit_ttl_blocks": self.audit_ttl_blocks,
            "min_authority_signers": self.min_authority_signers,
            "authority_threshold": self.authority_threshold,
            "min_audit_attestations": self.min_audit_attestations,
            "min_audit_score_bps": self.min_audit_score_bps,
            "max_disclosure_bps": self.max_disclosure_bps,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_sponsored_fee_units": self.max_sponsored_fee_units,
            "max_authorities": self.max_authorities,
            "max_manifests": self.max_manifests,
            "max_compatibility_commitments": self.max_compatibility_commitments,
            "max_pauses": self.max_pauses,
            "max_disclosure_windows": self.max_disclosure_windows,
            "max_sponsorships": self.max_sponsorships,
            "max_receipts": self.max_receipts,
            "max_rollback_plans": self.max_rollback_plans,
            "max_audit_attestations": self.max_audit_attestations,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn root(&self) -> String {
        pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-GUARD-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_equal(
            "protocol version",
            &self.protocol_version,
            PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION,
        )?;
        require_equal("chain id", &self.chain_id, CHAIN_ID)?;
        require_non_empty("security model", &self.security_model)?;
        require_non_empty("pq suite", &self.pq_suite)?;
        require_non_empty("namespace", &self.namespace)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_non_empty("low fee lane", &self.low_fee_lane)?;
        require_positive("default notice blocks", self.default_notice_blocks)?;
        require_positive("activation delay blocks", self.activation_delay_blocks)?;
        require_positive("execution window blocks", self.execution_window_blocks)?;
        require_positive("emergency delay blocks", self.emergency_delay_blocks)?;
        require_positive("disclosure window blocks", self.disclosure_window_blocks)?;
        require_positive("private review blocks", self.private_review_blocks)?;
        require_positive("sponsorship ttl blocks", self.sponsorship_ttl_blocks)?;
        require_positive("rollback window blocks", self.rollback_window_blocks)?;
        require_positive("audit ttl blocks", self.audit_ttl_blocks)?;
        if self.authority_threshold == 0 || self.authority_threshold > self.min_authority_signers {
            return Err("authority threshold must be between 1 and signer count".to_string());
        }
        if self.min_audit_attestations == 0 {
            return Err("min audit attestations must be positive".to_string());
        }
        require_bps("min audit score bps", self.min_audit_score_bps)?;
        require_bps("max disclosure bps", self.max_disclosure_bps)?;
        require_positive("sponsor budget units", self.sponsor_budget_units)?;
        require_positive("max sponsored fee units", self.max_sponsored_fee_units)?;
        require_capacity("max authorities", self.max_authorities)?;
        require_capacity("max manifests", self.max_manifests)?;
        require_capacity(
            "max compatibility commitments",
            self.max_compatibility_commitments,
        )?;
        require_capacity("max pauses", self.max_pauses)?;
        require_capacity("max disclosure windows", self.max_disclosure_windows)?;
        require_capacity("max sponsorships", self.max_sponsorships)?;
        require_capacity("max receipts", self.max_receipts)?;
        require_capacity("max rollback plans", self.max_rollback_plans)?;
        require_capacity("max audit attestations", self.max_audit_attestations)?;
        require_capacity("max public records", self.max_public_records)?;
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeAuthority {
    pub authority_id: String,
    pub label: String,
    pub contract_scope: BTreeSet<String>,
    pub signer_commitments: Vec<String>,
    pub threshold: u64,
    pub pq_signature_scheme: String,
    pub veto_key_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub rotation_nonce: u64,
}

impl PqUpgradeAuthority {
    pub fn new(
        label: &str,
        contract_scope: BTreeSet<String>,
        signer_labels: &[&str],
        threshold: u64,
        veto_label: &str,
        created_at_height: u64,
        expires_at_height: u64,
        rotation_nonce: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("authority label", label)?;
        require_non_empty("veto label", veto_label)?;
        if signer_labels.is_empty() {
            return Err("authority signer labels must not be empty".to_string());
        }
        if threshold == 0 || threshold as usize > signer_labels.len() {
            return Err("authority threshold exceeds signer set".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("authority expiry must be after creation height".to_string());
        }
        let signer_commitments = signer_labels
            .iter()
            .map(|label| pq_contract_upgrade_guard_string_root("AUTHORITY-SIGNER", label))
            .collect::<Vec<_>>();
        let veto_key_commitment = pq_contract_upgrade_guard_string_root("VETO-KEY", veto_label);
        let authority_id = pq_upgrade_authority_id(
            label,
            &signer_commitments,
            threshold,
            &veto_key_commitment,
            created_at_height,
            rotation_nonce,
        );
        Ok(Self {
            authority_id,
            label: label.to_string(),
            contract_scope,
            signer_commitments,
            threshold,
            pq_signature_scheme: PQ_CONTRACT_UPGRADE_GUARD_AUTHORITY_SCHEME.to_string(),
            veto_key_commitment,
            created_at_height,
            expires_at_height,
            rotation_nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_upgrade_authority",
            "authority_id": self.authority_id,
            "label": self.label,
            "contract_scope": self.contract_scope.iter().cloned().collect::<Vec<_>>(),
            "signer_commitments": self.signer_commitments,
            "threshold": self.threshold,
            "pq_signature_scheme": self.pq_signature_scheme,
            "veto_key_commitment": self.veto_key_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "rotation_nonce": self.rotation_nonce,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("authority id", &self.authority_id)?;
        require_non_empty("authority label", &self.label)?;
        require_non_empty("pq signature scheme", &self.pq_signature_scheme)?;
        require_non_empty("veto key commitment", &self.veto_key_commitment)?;
        require_unique_strings(&self.signer_commitments, "authority signer commitment")?;
        if self.threshold == 0 || self.threshold as usize > self.signer_commitments.len() {
            return Err("authority threshold exceeds signer commitments".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("authority expiry must be after creation height".to_string());
        }
        Ok(self.authority_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockedUpgradeManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub contract_kind: GuardedContractKind,
    pub contract_namespace: String,
    pub authority_id: String,
    pub old_bytecode_root: String,
    pub new_bytecode_root: String,
    pub old_interface_root: String,
    pub new_interface_root: String,
    pub private_state_schema_root: String,
    pub verifier_key_root: String,
    pub manifest_payload_root: String,
    pub risk_tier: ContractUpgradeRiskTier,
    pub status: ManifestStatus,
    pub queued_at_height: u64,
    pub disclosure_opens_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub requires_private_disclosure: bool,
    pub requires_low_fee_sponsorship: bool,
    pub deterministic_record_root: String,
}

impl TimelockedUpgradeManifest {
    pub fn new(
        contract_id: &str,
        contract_kind: GuardedContractKind,
        contract_namespace: &str,
        authority_id: &str,
        old_bytecode_root: &str,
        new_bytecode_root: &str,
        old_interface_root: &str,
        new_interface_root: &str,
        private_state_schema_root: &str,
        verifier_key_root: &str,
        manifest_payload: &Value,
        risk_tier: ContractUpgradeRiskTier,
        queued_at_height: u64,
        disclosure_delay_blocks: u64,
        activation_delay_blocks: u64,
        execution_window_blocks: u64,
        requires_private_disclosure: bool,
        requires_low_fee_sponsorship: bool,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("contract id", contract_id)?;
        require_non_empty("contract namespace", contract_namespace)?;
        require_non_empty("authority id", authority_id)?;
        require_non_empty("old bytecode root", old_bytecode_root)?;
        require_non_empty("new bytecode root", new_bytecode_root)?;
        require_non_empty("old interface root", old_interface_root)?;
        require_non_empty("new interface root", new_interface_root)?;
        require_non_empty("private state schema root", private_state_schema_root)?;
        require_non_empty("verifier key root", verifier_key_root)?;
        require_positive("activation delay blocks", activation_delay_blocks)?;
        require_positive("execution window blocks", execution_window_blocks)?;
        let manifest_payload_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-MANIFEST-PAYLOAD",
            manifest_payload,
        );
        let disclosure_opens_at_height = queued_at_height.saturating_add(disclosure_delay_blocks);
        let executable_at_height = queued_at_height.saturating_add(activation_delay_blocks);
        let expires_at_height = executable_at_height.saturating_add(execution_window_blocks);
        if expires_at_height <= executable_at_height {
            return Err("manifest expiry must be after executable height".to_string());
        }
        let manifest_id = pq_contract_upgrade_manifest_id(
            contract_id,
            authority_id,
            &manifest_payload_root,
            new_bytecode_root,
            queued_at_height,
        );
        let deterministic_record_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-MANIFEST-DETERMINISTIC-RECORD",
            &json!({
                "contract_id": contract_id,
                "authority_id": authority_id,
                "new_bytecode_root": new_bytecode_root,
                "new_interface_root": new_interface_root,
                "manifest_payload_root": manifest_payload_root,
            }),
        );
        Ok(Self {
            manifest_id,
            contract_id: contract_id.to_string(),
            contract_kind,
            contract_namespace: contract_namespace.to_string(),
            authority_id: authority_id.to_string(),
            old_bytecode_root: old_bytecode_root.to_string(),
            new_bytecode_root: new_bytecode_root.to_string(),
            old_interface_root: old_interface_root.to_string(),
            new_interface_root: new_interface_root.to_string(),
            private_state_schema_root: private_state_schema_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            manifest_payload_root,
            risk_tier,
            status: ManifestStatus::Timelocked,
            queued_at_height,
            disclosure_opens_at_height,
            executable_at_height,
            expires_at_height,
            requires_private_disclosure,
            requires_low_fee_sponsorship,
            deterministic_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "timelocked_upgrade_manifest",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_MANIFEST_SCHEME,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "contract_kind": self.contract_kind.as_str(),
            "contract_namespace": self.contract_namespace,
            "authority_id": self.authority_id,
            "old_bytecode_root": self.old_bytecode_root,
            "new_bytecode_root": self.new_bytecode_root,
            "old_interface_root": self.old_interface_root,
            "new_interface_root": self.new_interface_root,
            "private_state_schema_root": self.private_state_schema_root,
            "verifier_key_root": self.verifier_key_root,
            "manifest_payload_root": self.manifest_payload_root,
            "risk_tier": self.risk_tier.as_str(),
            "status": self.status.as_str(),
            "queued_at_height": self.queued_at_height,
            "disclosure_opens_at_height": self.disclosure_opens_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "requires_private_disclosure": self.requires_private_disclosure,
            "requires_low_fee_sponsorship": self.requires_low_fee_sponsorship,
            "deterministic_record_root": self.deterministic_record_root,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("contract namespace", &self.contract_namespace)?;
        require_non_empty("authority id", &self.authority_id)?;
        require_non_empty("old bytecode root", &self.old_bytecode_root)?;
        require_non_empty("new bytecode root", &self.new_bytecode_root)?;
        require_non_empty("old interface root", &self.old_interface_root)?;
        require_non_empty("new interface root", &self.new_interface_root)?;
        require_non_empty("private state schema root", &self.private_state_schema_root)?;
        require_non_empty("verifier key root", &self.verifier_key_root)?;
        require_non_empty("manifest payload root", &self.manifest_payload_root)?;
        require_non_empty("deterministic record root", &self.deterministic_record_root)?;
        if self.executable_at_height <= self.queued_at_height {
            return Err("manifest executable height must be after queue height".to_string());
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err("manifest expiry must be after executable height".to_string());
        }
        if self.disclosure_opens_at_height > self.executable_at_height {
            return Err("manifest disclosure window opens after executable height".to_string());
        }
        Ok(self.manifest_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCommitment {
    pub commitment_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub kind: CompatibilityKind,
    pub status: CompatibilityStatus,
    pub old_root: String,
    pub new_root: String,
    pub compatibility_proof_root: String,
    pub incompatible_selector_commitments: Vec<String>,
    pub checked_at_height: u64,
    pub checker_commitment: String,
}

impl CompatibilityCommitment {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        kind: CompatibilityKind,
        old_root: &str,
        new_root: &str,
        proof_payload: &Value,
        incompatible_selector_commitments: Vec<String>,
        checked_at_height: u64,
        checker_label: &str,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("old root", old_root)?;
        require_non_empty("new root", new_root)?;
        require_non_empty("checker label", checker_label)?;
        let compatibility_proof_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-COMPATIBILITY-PROOF",
            proof_payload,
        );
        let checker_commitment =
            pq_contract_upgrade_guard_string_root("COMPATIBILITY-CHECKER", checker_label);
        let commitment_id = pq_compatibility_commitment_id(
            manifest_id,
            contract_id,
            kind,
            old_root,
            new_root,
            &compatibility_proof_root,
        );
        Ok(Self {
            commitment_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            kind,
            status: CompatibilityStatus::Verified,
            old_root: old_root.to_string(),
            new_root: new_root.to_string(),
            compatibility_proof_root,
            incompatible_selector_commitments,
            checked_at_height,
            checker_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compatibility_commitment",
            "commitment_id": self.commitment_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "compatibility_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "old_root": self.old_root,
            "new_root": self.new_root,
            "compatibility_proof_root": self.compatibility_proof_root,
            "incompatible_selector_commitments": self.incompatible_selector_commitments,
            "checked_at_height": self.checked_at_height,
            "checker_commitment": self.checker_commitment,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("compatibility commitment id", &self.commitment_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("old root", &self.old_root)?;
        require_non_empty("new root", &self.new_root)?;
        require_non_empty("compatibility proof root", &self.compatibility_proof_root)?;
        require_non_empty("checker commitment", &self.checker_commitment)?;
        require_unique_strings(
            &self.incompatible_selector_commitments,
            "incompatible selector commitment",
        )?;
        if self.status.usable() && !self.incompatible_selector_commitments.is_empty() {
            return Err(
                "usable compatibility commitment contains incompatible selectors".to_string(),
            );
        }
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPauseOrVeto {
    pub guard_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub authority_id: String,
    pub mode: EmergencyGuardMode,
    pub reason_root: String,
    pub evidence_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub lifted_at_height: Option<u64>,
}

impl EmergencyPauseOrVeto {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        authority_id: &str,
        mode: EmergencyGuardMode,
        reason_payload: &Value,
        evidence_payload: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("authority id", authority_id)?;
        if !mode.blocks_execution() {
            return Err("emergency guard mode must block execution".to_string());
        }
        if expires_at_height <= starts_at_height {
            return Err("emergency guard expiry must be after start".to_string());
        }
        let reason_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-PAUSE-REASON",
            reason_payload,
        );
        let evidence_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-PAUSE-EVIDENCE",
            evidence_payload,
        );
        let guard_id = pq_emergency_guard_id(
            manifest_id,
            contract_id,
            authority_id,
            mode,
            &reason_root,
            starts_at_height,
        );
        Ok(Self {
            guard_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            authority_id: authority_id.to_string(),
            mode,
            reason_root,
            evidence_root,
            starts_at_height,
            expires_at_height,
            lifted_at_height: None,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.lifted_at_height.is_none()
            && self.starts_at_height <= height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_pause_or_veto",
            "guard_id": self.guard_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "authority_id": self.authority_id,
            "mode": self.mode.as_str(),
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "lifted_at_height": self.lifted_at_height,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("guard id", &self.guard_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("authority id", &self.authority_id)?;
        require_non_empty("reason root", &self.reason_root)?;
        require_non_empty("evidence root", &self.evidence_root)?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("emergency guard expiry must be after start".to_string());
        }
        if let Some(lifted_at_height) = self.lifted_at_height {
            if lifted_at_height < self.starts_at_height {
                return Err("emergency guard lifted before start".to_string());
            }
        }
        Ok(self.guard_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDisclosureWindow {
    pub disclosure_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub audience: DisclosureAudience,
    pub status: DisclosureStatus,
    pub sealed_payload_root: String,
    pub recipient_key_root: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub max_disclosure_bps: u64,
}

impl PrivateDisclosureWindow {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        audience: DisclosureAudience,
        sealed_payload: &Value,
        recipient_key_label: &str,
        opens_at_height: u64,
        closes_at_height: u64,
        max_disclosure_bps: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("recipient key label", recipient_key_label)?;
        require_bps("max disclosure bps", max_disclosure_bps)?;
        if closes_at_height <= opens_at_height {
            return Err("disclosure close height must be after open height".to_string());
        }
        let sealed_payload_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-SEALED-DISCLOSURE",
            sealed_payload,
        );
        let recipient_key_root =
            pq_contract_upgrade_guard_string_root("DISCLOSURE-RECIPIENT", recipient_key_label);
        let disclosure_id = pq_private_disclosure_window_id(
            manifest_id,
            contract_id,
            audience,
            &sealed_payload_root,
            opens_at_height,
        );
        Ok(Self {
            disclosure_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            audience,
            status: DisclosureStatus::Open,
            sealed_payload_root,
            recipient_key_root,
            opens_at_height,
            closes_at_height,
            max_disclosure_bps,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        matches!(self.status, DisclosureStatus::Open)
            && self.opens_at_height <= height
            && height < self.closes_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_disclosure_window",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_DISCLOSURE_SCHEME,
            "disclosure_id": self.disclosure_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "audience": self.audience.as_str(),
            "status": self.status.as_str(),
            "sealed_payload_root": self.sealed_payload_root,
            "recipient_key_root": self.recipient_key_root,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "max_disclosure_bps": self.max_disclosure_bps,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("disclosure id", &self.disclosure_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("sealed payload root", &self.sealed_payload_root)?;
        require_non_empty("recipient key root", &self.recipient_key_root)?;
        require_bps("max disclosure bps", self.max_disclosure_bps)?;
        if self.closes_at_height <= self.opens_at_height {
            return Err("disclosure close height must be after open height".to_string());
        }
        Ok(self.disclosure_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeUpgradeSponsorship {
    pub sponsorship_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub status: SponsorshipStatus,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_units_per_migration: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeUpgradeSponsorship {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        low_fee_lane: &str,
        budget_units: u64,
        max_fee_units_per_migration: u64,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("sponsor label", sponsor_label)?;
        require_non_empty("fee asset id", fee_asset_id)?;
        require_non_empty("low fee lane", low_fee_lane)?;
        require_positive("budget units", budget_units)?;
        require_positive("max fee units per migration", max_fee_units_per_migration)?;
        if expires_at_height <= starts_at_height {
            return Err("sponsorship expiry must be after start".to_string());
        }
        let sponsor_commitment =
            pq_contract_upgrade_guard_string_root("LOW-FEE-SPONSOR", sponsor_label);
        let sponsorship_id = pq_low_fee_sponsorship_id(
            manifest_id,
            contract_id,
            &sponsor_commitment,
            fee_asset_id,
            starts_at_height,
        );
        Ok(Self {
            sponsorship_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            status: SponsorshipStatus::Active,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_units_per_migration,
            starts_at_height,
            expires_at_height,
        })
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_upgrade_sponsorship",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_SPONSORSHIP_SCHEME,
            "sponsorship_id": self.sponsorship_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "status": self.status.as_str(),
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_fee_units_per_migration": self.max_fee_units_per_migration,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("sponsorship id", &self.sponsorship_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_non_empty("low fee lane", &self.low_fee_lane)?;
        require_positive("budget units", self.budget_units)?;
        require_positive(
            "max fee units per migration",
            self.max_fee_units_per_migration,
        )?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("sponsorship reserved and spent units exceed budget".to_string());
        }
        if self.expires_at_height <= self.starts_at_height {
            return Err("sponsorship expiry must be after start".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub receipt_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub user_commitment: String,
    pub old_state_commitment: String,
    pub new_state_commitment: String,
    pub nullifier_root: String,
    pub migration_proof_root: String,
    pub sponsored_fee_units: u64,
    pub status: MigrationReceiptStatus,
    pub recorded_at_height: u64,
}

impl MigrationReceipt {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        user_label: &str,
        old_state_commitment: &str,
        new_state_commitment: &str,
        nullifier_label: &str,
        migration_proof: &Value,
        sponsored_fee_units: u64,
        recorded_at_height: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("user label", user_label)?;
        require_non_empty("old state commitment", old_state_commitment)?;
        require_non_empty("new state commitment", new_state_commitment)?;
        require_non_empty("nullifier label", nullifier_label)?;
        let user_commitment = pq_contract_upgrade_guard_string_root("MIGRATION-USER", user_label);
        let nullifier_root =
            pq_contract_upgrade_guard_string_root("MIGRATION-NULLIFIER", nullifier_label);
        let migration_proof_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-MIGRATION-PROOF",
            migration_proof,
        );
        let receipt_id = pq_migration_receipt_id(
            manifest_id,
            contract_id,
            &user_commitment,
            &nullifier_root,
            recorded_at_height,
        );
        Ok(Self {
            receipt_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            user_commitment,
            old_state_commitment: old_state_commitment.to_string(),
            new_state_commitment: new_state_commitment.to_string(),
            nullifier_root,
            migration_proof_root,
            sponsored_fee_units,
            status: MigrationReceiptStatus::Accepted,
            recorded_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "migration_receipt",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_RECEIPT_SCHEME,
            "receipt_id": self.receipt_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "user_commitment": self.user_commitment,
            "old_state_commitment": self.old_state_commitment,
            "new_state_commitment": self.new_state_commitment,
            "nullifier_root": self.nullifier_root,
            "migration_proof_root": self.migration_proof_root,
            "sponsored_fee_units": self.sponsored_fee_units,
            "status": self.status.as_str(),
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("receipt id", &self.receipt_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("user commitment", &self.user_commitment)?;
        require_non_empty("old state commitment", &self.old_state_commitment)?;
        require_non_empty("new state commitment", &self.new_state_commitment)?;
        require_non_empty("nullifier root", &self.nullifier_root)?;
        require_non_empty("migration proof root", &self.migration_proof_root)?;
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub rollback_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub authority_id: String,
    pub status: RollbackStatus,
    pub previous_bytecode_root: String,
    pub previous_interface_root: String,
    pub previous_state_schema_root: String,
    pub rollback_payload_root: String,
    pub armed_at_height: u64,
    pub expires_at_height: u64,
    pub requires_receipt_replay: bool,
}

impl RollbackPlan {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        authority_id: &str,
        previous_bytecode_root: &str,
        previous_interface_root: &str,
        previous_state_schema_root: &str,
        rollback_payload: &Value,
        armed_at_height: u64,
        expires_at_height: u64,
        requires_receipt_replay: bool,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("authority id", authority_id)?;
        require_non_empty("previous bytecode root", previous_bytecode_root)?;
        require_non_empty("previous interface root", previous_interface_root)?;
        require_non_empty("previous state schema root", previous_state_schema_root)?;
        if expires_at_height <= armed_at_height {
            return Err("rollback expiry must be after armed height".to_string());
        }
        let rollback_payload_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-ROLLBACK-PAYLOAD",
            rollback_payload,
        );
        let rollback_id = pq_rollback_plan_id(
            manifest_id,
            contract_id,
            authority_id,
            &rollback_payload_root,
            armed_at_height,
        );
        Ok(Self {
            rollback_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            authority_id: authority_id.to_string(),
            status: RollbackStatus::Armed,
            previous_bytecode_root: previous_bytecode_root.to_string(),
            previous_interface_root: previous_interface_root.to_string(),
            previous_state_schema_root: previous_state_schema_root.to_string(),
            rollback_payload_root,
            armed_at_height,
            expires_at_height,
            requires_receipt_replay,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollback_plan",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_ROLLBACK_SCHEME,
            "rollback_id": self.rollback_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "authority_id": self.authority_id,
            "status": self.status.as_str(),
            "previous_bytecode_root": self.previous_bytecode_root,
            "previous_interface_root": self.previous_interface_root,
            "previous_state_schema_root": self.previous_state_schema_root,
            "rollback_payload_root": self.rollback_payload_root,
            "armed_at_height": self.armed_at_height,
            "expires_at_height": self.expires_at_height,
            "requires_receipt_replay": self.requires_receipt_replay,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("rollback id", &self.rollback_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("authority id", &self.authority_id)?;
        require_non_empty("previous bytecode root", &self.previous_bytecode_root)?;
        require_non_empty("previous interface root", &self.previous_interface_root)?;
        require_non_empty(
            "previous state schema root",
            &self.previous_state_schema_root,
        )?;
        require_non_empty("rollback payload root", &self.rollback_payload_root)?;
        if self.expires_at_height <= self.armed_at_height {
            return Err("rollback expiry must be after armed height".to_string());
        }
        Ok(self.rollback_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAttestation {
    pub attestation_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub auditor_commitment: String,
    pub scopes: BTreeSet<AuditScope>,
    pub status: AuditStatus,
    pub attestation_root: String,
    pub score_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl AuditAttestation {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        auditor_label: &str,
        scopes: BTreeSet<AuditScope>,
        attestation_payload: &Value,
        score_bps: u64,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("auditor label", auditor_label)?;
        require_bps("score bps", score_bps)?;
        if scopes.is_empty() {
            return Err("audit scopes must not be empty".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("audit expiry must be after issue height".to_string());
        }
        let auditor_commitment = pq_contract_upgrade_guard_string_root("AUDITOR", auditor_label);
        let attestation_root = pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-AUDIT-ATTESTATION",
            attestation_payload,
        );
        let attestation_id = pq_audit_attestation_id(
            manifest_id,
            contract_id,
            &auditor_commitment,
            &attestation_root,
            issued_at_height,
        );
        Ok(Self {
            attestation_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            auditor_commitment,
            scopes,
            status: AuditStatus::Accepted,
            attestation_root,
            score_bps,
            issued_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_attestation",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_AUDIT_SCHEME,
            "attestation_id": self.attestation_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "auditor_commitment": self.auditor_commitment,
            "scopes": self.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "attestation_root": self.attestation_root,
            "score_bps": self.score_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("attestation id", &self.attestation_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("auditor commitment", &self.auditor_commitment)?;
        require_non_empty("attestation root", &self.attestation_root)?;
        require_bps("score bps", self.score_bps)?;
        if self.scopes.is_empty() {
            return Err("audit scopes must not be empty".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("audit expiry must be after issue height".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub previous_record_root: String,
    pub emitted_at_height: u64,
}

impl DeterministicPublicRecord {
    pub fn new(
        manifest_id: &str,
        contract_id: &str,
        record_kind: &str,
        payload: &Value,
        previous_record_root: &str,
        emitted_at_height: u64,
    ) -> PqContractUpgradeGuardResult<Self> {
        require_non_empty("manifest id", manifest_id)?;
        require_non_empty("contract id", contract_id)?;
        require_non_empty("record kind", record_kind)?;
        require_non_empty("previous record root", previous_record_root)?;
        let payload_root =
            pq_contract_upgrade_guard_payload_root("PQ-CONTRACT-UPGRADE-PUBLIC-RECORD", payload);
        let record_id = pq_deterministic_public_record_id(
            manifest_id,
            contract_id,
            record_kind,
            &payload_root,
            emitted_at_height,
        );
        Ok(Self {
            record_id,
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            record_kind: record_kind.to_string(),
            payload_root,
            previous_record_root: previous_record_root.to_string(),
            emitted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_public_record",
            "scheme": PQ_CONTRACT_UPGRADE_GUARD_PUBLIC_RECORD_SCHEME,
            "record_id": self.record_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "previous_record_root": self.previous_record_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("record id", &self.record_id)?;
        require_non_empty("manifest id", &self.manifest_id)?;
        require_non_empty("contract id", &self.contract_id)?;
        require_non_empty("record kind", &self.record_kind)?;
        require_non_empty("payload root", &self.payload_root)?;
        require_non_empty("previous record root", &self.previous_record_root)?;
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqContractUpgradeGuardRoots {
    pub config_root: String,
    pub authority_root: String,
    pub manifest_root: String,
    pub compatibility_root: String,
    pub emergency_guard_root: String,
    pub disclosure_root: String,
    pub sponsorship_root: String,
    pub receipt_root: String,
    pub rollback_root: String,
    pub audit_root: String,
    pub deterministic_public_record_root: String,
    pub active_contract_root: String,
    pub executable_manifest_root: String,
    pub state_root: String,
}

impl PqContractUpgradeGuardRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_upgrade_guard_roots",
            "protocol_version": PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "authority_root": self.authority_root,
            "manifest_root": self.manifest_root,
            "compatibility_root": self.compatibility_root,
            "emergency_guard_root": self.emergency_guard_root,
            "disclosure_root": self.disclosure_root,
            "sponsorship_root": self.sponsorship_root,
            "receipt_root": self.receipt_root,
            "rollback_root": self.rollback_root,
            "audit_root": self.audit_root,
            "deterministic_public_record_root": self.deterministic_public_record_root,
            "active_contract_root": self.active_contract_root,
            "executable_manifest_root": self.executable_manifest_root,
            "state_root": self.state_root,
        })
    }

    pub fn aggregate_root(&self) -> String {
        pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-GUARD-ROOTS",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        require_non_empty("config root", &self.config_root)?;
        require_non_empty("authority root", &self.authority_root)?;
        require_non_empty("manifest root", &self.manifest_root)?;
        require_non_empty("compatibility root", &self.compatibility_root)?;
        require_non_empty("emergency guard root", &self.emergency_guard_root)?;
        require_non_empty("disclosure root", &self.disclosure_root)?;
        require_non_empty("sponsorship root", &self.sponsorship_root)?;
        require_non_empty("receipt root", &self.receipt_root)?;
        require_non_empty("rollback root", &self.rollback_root)?;
        require_non_empty("audit root", &self.audit_root)?;
        require_non_empty(
            "deterministic public record root",
            &self.deterministic_public_record_root,
        )?;
        require_non_empty("active contract root", &self.active_contract_root)?;
        require_non_empty("executable manifest root", &self.executable_manifest_root)?;
        require_non_empty("state root", &self.state_root)?;
        Ok(self.aggregate_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqContractUpgradeGuardCounters {
    pub authority_count: u64,
    pub manifest_count: u64,
    pub open_manifest_count: u64,
    pub executable_manifest_count: u64,
    pub terminal_manifest_count: u64,
    pub compatibility_commitment_count: u64,
    pub verified_compatibility_count: u64,
    pub active_emergency_guard_count: u64,
    pub veto_count: u64,
    pub disclosure_window_count: u64,
    pub active_disclosure_window_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub migration_receipt_count: u64,
    pub finalized_migration_receipt_count: u64,
    pub rollback_plan_count: u64,
    pub active_rollback_plan_count: u64,
    pub audit_attestation_count: u64,
    pub accepted_audit_attestation_count: u64,
    pub deterministic_public_record_count: u64,
    pub total_sponsor_budget_units: u64,
    pub total_sponsor_reserved_units: u64,
    pub total_sponsor_spent_units: u64,
    pub total_sponsored_fee_units: u64,
}

impl PqContractUpgradeGuardCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_upgrade_guard_counters",
            "authority_count": self.authority_count,
            "manifest_count": self.manifest_count,
            "open_manifest_count": self.open_manifest_count,
            "executable_manifest_count": self.executable_manifest_count,
            "terminal_manifest_count": self.terminal_manifest_count,
            "compatibility_commitment_count": self.compatibility_commitment_count,
            "verified_compatibility_count": self.verified_compatibility_count,
            "active_emergency_guard_count": self.active_emergency_guard_count,
            "veto_count": self.veto_count,
            "disclosure_window_count": self.disclosure_window_count,
            "active_disclosure_window_count": self.active_disclosure_window_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "migration_receipt_count": self.migration_receipt_count,
            "finalized_migration_receipt_count": self.finalized_migration_receipt_count,
            "rollback_plan_count": self.rollback_plan_count,
            "active_rollback_plan_count": self.active_rollback_plan_count,
            "audit_attestation_count": self.audit_attestation_count,
            "accepted_audit_attestation_count": self.accepted_audit_attestation_count,
            "deterministic_public_record_count": self.deterministic_public_record_count,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_sponsor_reserved_units": self.total_sponsor_reserved_units,
            "total_sponsor_spent_units": self.total_sponsor_spent_units,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
        })
    }

    pub fn root(&self) -> String {
        pq_contract_upgrade_guard_payload_root(
            "PQ-CONTRACT-UPGRADE-GUARD-COUNTERS",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        if self.open_manifest_count > self.manifest_count {
            return Err("open manifest count exceeds total".to_string());
        }
        if self.executable_manifest_count > self.manifest_count {
            return Err("executable manifest count exceeds total".to_string());
        }
        if self.terminal_manifest_count > self.manifest_count {
            return Err("terminal manifest count exceeds total".to_string());
        }
        if self.verified_compatibility_count > self.compatibility_commitment_count {
            return Err("verified compatibility count exceeds total".to_string());
        }
        if self.active_disclosure_window_count > self.disclosure_window_count {
            return Err("active disclosure count exceeds total".to_string());
        }
        if self.active_sponsorship_count > self.sponsorship_count {
            return Err("active sponsorship count exceeds total".to_string());
        }
        if self.finalized_migration_receipt_count > self.migration_receipt_count {
            return Err("finalized receipt count exceeds total".to_string());
        }
        if self.active_rollback_plan_count > self.rollback_plan_count {
            return Err("active rollback plan count exceeds total".to_string());
        }
        if self.accepted_audit_attestation_count > self.audit_attestation_count {
            return Err("accepted audit attestation count exceeds total".to_string());
        }
        if self
            .total_sponsor_reserved_units
            .saturating_add(self.total_sponsor_spent_units)
            > self.total_sponsor_budget_units
        {
            return Err("sponsor reserved and spent units exceed budget".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqContractUpgradeGuardState {
    pub height: u64,
    pub config: PqContractUpgradeGuardConfig,
    pub authorities: BTreeMap<String, PqUpgradeAuthority>,
    pub manifests: BTreeMap<String, TimelockedUpgradeManifest>,
    pub compatibility_commitments: BTreeMap<String, CompatibilityCommitment>,
    pub emergency_guards: BTreeMap<String, EmergencyPauseOrVeto>,
    pub disclosure_windows: BTreeMap<String, PrivateDisclosureWindow>,
    pub sponsorships: BTreeMap<String, LowFeeUpgradeSponsorship>,
    pub migration_receipts: BTreeMap<String, MigrationReceipt>,
    pub rollback_plans: BTreeMap<String, RollbackPlan>,
    pub audit_attestations: BTreeMap<String, AuditAttestation>,
    pub deterministic_public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl PqContractUpgradeGuardState {
    pub fn devnet() -> PqContractUpgradeGuardResult<Self> {
        let mut state = Self {
            height: PQ_CONTRACT_UPGRADE_GUARD_DEFAULT_HEIGHT,
            config: PqContractUpgradeGuardConfig::devnet(),
            authorities: BTreeMap::new(),
            manifests: BTreeMap::new(),
            compatibility_commitments: BTreeMap::new(),
            emergency_guards: BTreeMap::new(),
            disclosure_windows: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            migration_receipts: BTreeMap::new(),
            rollback_plans: BTreeMap::new(),
            audit_attestations: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
        };

        let contract_id = pq_contract_upgrade_guard_string_root(
            "DEVNET-CONTRACT-ID",
            "nebula.devnet.private.amm.v1",
        );
        let old_bytecode_root =
            pq_contract_upgrade_guard_string_root("DEVNET-BYTECODE", "private-amm-v1");
        let new_bytecode_root =
            pq_contract_upgrade_guard_string_root("DEVNET-BYTECODE", "private-amm-v2-pq");
        let old_interface_root =
            pq_contract_upgrade_guard_string_root("DEVNET-INTERFACE", "private-amm-interface-v1");
        let new_interface_root =
            pq_contract_upgrade_guard_string_root("DEVNET-INTERFACE", "private-amm-interface-v2");
        let private_state_schema_root =
            pq_contract_upgrade_guard_string_root("DEVNET-STATE-SCHEMA", "private-amm-state-v2");
        let verifier_key_root =
            pq_contract_upgrade_guard_string_root("DEVNET-VERIFIER-KEY", "amm-upgrade-v2");

        let mut scope = BTreeSet::new();
        scope.insert(contract_id.clone());
        let authority = PqUpgradeAuthority::new(
            "devnet-private-defi-upgrade-council",
            scope,
            &[
                "guardian-ml-dsa-0",
                "guardian-ml-dsa-1",
                "guardian-slh-dsa-backup-0",
            ],
            state.config.authority_threshold,
            "devnet-private-defi-veto",
            state.height.saturating_sub(64),
            state.height.saturating_add(40_320),
            1,
        )?;
        let authority_id = authority.authority_id.clone();
        state.authorities.insert(authority_id.clone(), authority);

        let manifest = TimelockedUpgradeManifest::new(
            &contract_id,
            GuardedContractKind::PrivateAmm,
            "nebula.devnet.private.amm",
            &authority_id,
            &old_bytecode_root,
            &new_bytecode_root,
            &old_interface_root,
            &new_interface_root,
            &private_state_schema_root,
            &verifier_key_root,
            &json!({
                "upgrade": "private amm pq verifier and state migration",
                "privacy": "sealed route keys remain private",
                "defi_invariants": ["constant_product", "bounded_fee_growth"],
                "low_fee": true,
            }),
            ContractUpgradeRiskTier::DefiInvariant,
            state.height,
            state.config.private_review_blocks,
            state.config.activation_delay_blocks,
            state.config.execution_window_blocks,
            true,
            true,
        )?;
        let manifest_id = manifest.manifest_id.clone();
        state.manifests.insert(manifest_id.clone(), manifest);

        for (kind, old_root, new_root, payload) in [
            (
                CompatibilityKind::Bytecode,
                old_bytecode_root.as_str(),
                new_bytecode_root.as_str(),
                json!({"reproducible_build": true, "forbidden_opcodes": []}),
            ),
            (
                CompatibilityKind::Interface,
                old_interface_root.as_str(),
                new_interface_root.as_str(),
                json!({"removed_selectors": [], "added_private_selectors": ["rebalance_pq"]}),
            ),
            (
                CompatibilityKind::DefiInvariant,
                old_bytecode_root.as_str(),
                new_bytecode_root.as_str(),
                json!({"constant_product_delta_bps": 0, "oracle_dependency": "unchanged"}),
            ),
        ] {
            let commitment = CompatibilityCommitment::new(
                &manifest_id,
                &contract_id,
                kind,
                old_root,
                new_root,
                &payload,
                Vec::new(),
                state.height.saturating_add(4),
                "devnet-compatibility-checker",
            )?;
            state
                .compatibility_commitments
                .insert(commitment.commitment_id.clone(), commitment);
        }

        let disclosure = PrivateDisclosureWindow::new(
            &manifest_id,
            &contract_id,
            DisclosureAudience::Auditor,
            &json!({
                "sealed_witness": "amm-private-state-diff",
                "sealed_selector_map": true,
            }),
            "devnet-auditor-ml-kem-recipient",
            state
                .height
                .saturating_add(state.config.private_review_blocks),
            state
                .height
                .saturating_add(state.config.private_review_blocks)
                .saturating_add(state.config.disclosure_window_blocks),
            state.config.max_disclosure_bps,
        )?;
        state
            .disclosure_windows
            .insert(disclosure.disclosure_id.clone(), disclosure);

        let sponsorship = LowFeeUpgradeSponsorship::new(
            &manifest_id,
            &contract_id,
            "devnet-upgrade-paymaster",
            &state.config.fee_asset_id,
            &state.config.low_fee_lane,
            state.config.sponsor_budget_units,
            state.config.max_sponsored_fee_units,
            state.height,
            state
                .height
                .saturating_add(state.config.sponsorship_ttl_blocks),
        )?;
        state
            .sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);

        let receipt = MigrationReceipt::new(
            &manifest_id,
            &contract_id,
            "devnet-liquidity-provider-0",
            &pq_contract_upgrade_guard_string_root("DEVNET-OLD-LP-STATE", "lp0"),
            &pq_contract_upgrade_guard_string_root("DEVNET-NEW-LP-STATE", "lp0"),
            "lp0-upgrade-nullifier",
            &json!({
                "private_balance_preserved": true,
                "fee_sponsored": true,
            }),
            42,
            state.height.saturating_add(12),
        )?;
        state
            .migration_receipts
            .insert(receipt.receipt_id.clone(), receipt);

        let rollback = RollbackPlan::new(
            &manifest_id,
            &contract_id,
            &authority_id,
            &old_bytecode_root,
            &old_interface_root,
            &private_state_schema_root,
            &json!({
                "rollback_to": "private-amm-v1",
                "requires_receipt_replay": true,
                "keeps_user_nullifiers_private": true,
            }),
            state.height,
            state
                .height
                .saturating_add(state.config.rollback_window_blocks),
            true,
        )?;
        state
            .rollback_plans
            .insert(rollback.rollback_id.clone(), rollback);

        let mut scopes = BTreeSet::new();
        scopes.insert(AuditScope::Bytecode);
        scopes.insert(AuditScope::DefiInvariant);
        scopes.insert(AuditScope::PrivateState);
        scopes.insert(AuditScope::Migration);
        let audit = AuditAttestation::new(
            &manifest_id,
            &contract_id,
            "devnet-pq-auditor-0",
            scopes,
            &json!({
                "finding": "accepted for devnet",
                "defi_risk": "bounded",
                "privacy_regression": false,
            }),
            9_200,
            state.height.saturating_add(6),
            state.height.saturating_add(state.config.audit_ttl_blocks),
        )?;
        state
            .audit_attestations
            .insert(audit.attestation_id.clone(), audit);

        let emergency_guard = EmergencyPauseOrVeto::new(
            &manifest_id,
            &contract_id,
            &authority_id,
            EmergencyGuardMode::MigrationOnly,
            &json!({
                "reason": "defi integrator smoke-test window",
                "does_not_reveal_positions": true,
            }),
            &json!({
                "watchtower": "devnet-private-defi-watchtower",
                "evidence_commitment_only": true,
            }),
            state.height.saturating_add(1),
            state
                .height
                .saturating_add(state.config.emergency_delay_blocks),
        )?;
        state
            .emergency_guards
            .insert(emergency_guard.guard_id.clone(), emergency_guard);

        let record = DeterministicPublicRecord::new(
            &manifest_id,
            &contract_id,
            "upgrade_manifest_queued",
            &json!({
                "manifest_id": manifest_id,
                "contract_id": contract_id,
                "notice_blocks": state.config.default_notice_blocks,
                "low_fee_lane": state.config.low_fee_lane,
            }),
            &pq_contract_upgrade_guard_string_root("PUBLIC-RECORD-GENESIS", "devnet"),
            state.height,
        )?;
        state
            .deterministic_public_records
            .insert(record.record_id.clone(), record);

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqContractUpgradeGuardResult<()> {
        if height < self.height {
            return Err("height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> PqContractUpgradeGuardRoots {
        let authority_records = self
            .authorities
            .values()
            .map(PqUpgradeAuthority::public_record)
            .collect::<Vec<_>>();
        let manifest_records = self
            .manifests
            .values()
            .map(TimelockedUpgradeManifest::public_record)
            .collect::<Vec<_>>();
        let compatibility_records = self
            .compatibility_commitments
            .values()
            .map(CompatibilityCommitment::public_record)
            .collect::<Vec<_>>();
        let emergency_records = self
            .emergency_guards
            .values()
            .map(EmergencyPauseOrVeto::public_record)
            .collect::<Vec<_>>();
        let disclosure_records = self
            .disclosure_windows
            .values()
            .map(PrivateDisclosureWindow::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .sponsorships
            .values()
            .map(LowFeeUpgradeSponsorship::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .migration_receipts
            .values()
            .map(MigrationReceipt::public_record)
            .collect::<Vec<_>>();
        let rollback_records = self
            .rollback_plans
            .values()
            .map(RollbackPlan::public_record)
            .collect::<Vec<_>>();
        let audit_records = self
            .audit_attestations
            .values()
            .map(AuditAttestation::public_record)
            .collect::<Vec<_>>();
        let public_records = self
            .deterministic_public_records
            .values()
            .map(DeterministicPublicRecord::public_record)
            .collect::<Vec<_>>();
        let active_contracts = self
            .manifests
            .values()
            .filter(|manifest| manifest.status.open() || manifest.status.executable())
            .map(|manifest| Value::String(manifest.contract_id.clone()))
            .collect::<Vec<_>>();
        let executable_manifests = self
            .manifests
            .values()
            .filter(|manifest| manifest.status.executable())
            .map(|manifest| Value::String(manifest.manifest_id.clone()))
            .collect::<Vec<_>>();
        let state_without_root = self.public_record_without_state_root();
        let state_root = pq_contract_upgrade_guard_state_root_from_record(&state_without_root);
        PqContractUpgradeGuardRoots {
            config_root: self.config.root(),
            authority_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-AUTHORITIES",
                &authority_records,
            ),
            manifest_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-MANIFESTS",
                &manifest_records,
            ),
            compatibility_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-COMPATIBILITY",
                &compatibility_records,
            ),
            emergency_guard_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-EMERGENCY",
                &emergency_records,
            ),
            disclosure_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-DISCLOSURES",
                &disclosure_records,
            ),
            sponsorship_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-SPONSORSHIPS",
                &sponsorship_records,
            ),
            receipt_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-RECEIPTS",
                &receipt_records,
            ),
            rollback_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-ROLLBACKS",
                &rollback_records,
            ),
            audit_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-AUDITS",
                &audit_records,
            ),
            deterministic_public_record_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-PUBLIC-RECORDS",
                &public_records,
            ),
            active_contract_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-ACTIVE-CONTRACTS",
                &active_contracts,
            ),
            executable_manifest_root: pq_contract_upgrade_guard_list_root(
                "PQ-CONTRACT-UPGRADE-GUARD-EXECUTABLE-MANIFESTS",
                &executable_manifests,
            ),
            state_root,
        }
    }

    pub fn counters(&self) -> PqContractUpgradeGuardCounters {
        PqContractUpgradeGuardCounters {
            authority_count: self.authorities.len() as u64,
            manifest_count: self.manifests.len() as u64,
            open_manifest_count: self
                .manifests
                .values()
                .filter(|manifest| manifest.status.open())
                .count() as u64,
            executable_manifest_count: self
                .manifests
                .values()
                .filter(|manifest| manifest.status.executable())
                .count() as u64,
            terminal_manifest_count: self
                .manifests
                .values()
                .filter(|manifest| manifest.status.terminal())
                .count() as u64,
            compatibility_commitment_count: self.compatibility_commitments.len() as u64,
            verified_compatibility_count: self
                .compatibility_commitments
                .values()
                .filter(|commitment| commitment.status == CompatibilityStatus::Verified)
                .count() as u64,
            active_emergency_guard_count: self
                .emergency_guards
                .values()
                .filter(|guard| guard.active_at(self.height))
                .count() as u64,
            veto_count: self
                .emergency_guards
                .values()
                .filter(|guard| guard.mode == EmergencyGuardMode::VetoUpgrade)
                .count() as u64,
            disclosure_window_count: self.disclosure_windows.len() as u64,
            active_disclosure_window_count: self
                .disclosure_windows
                .values()
                .filter(|window| window.active_at(self.height))
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            active_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.active())
                .count() as u64,
            migration_receipt_count: self.migration_receipts.len() as u64,
            finalized_migration_receipt_count: self
                .migration_receipts
                .values()
                .filter(|receipt| receipt.status.final_state())
                .count() as u64,
            rollback_plan_count: self.rollback_plans.len() as u64,
            active_rollback_plan_count: self
                .rollback_plans
                .values()
                .filter(|plan| plan.status.active())
                .count() as u64,
            audit_attestation_count: self.audit_attestations.len() as u64,
            accepted_audit_attestation_count: self
                .audit_attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            deterministic_public_record_count: self.deterministic_public_records.len() as u64,
            total_sponsor_budget_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.budget_units)
                .sum(),
            total_sponsor_reserved_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_units)
                .sum(),
            total_sponsor_spent_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.spent_units)
                .sum(),
            total_sponsored_fee_units: self
                .migration_receipts
                .values()
                .map(|receipt| receipt.sponsored_fee_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "pq_contract_upgrade_guard_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION,
            "schema_version": PQ_CONTRACT_UPGRADE_GUARD_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "authorities": self.authorities.values().map(PqUpgradeAuthority::public_record).collect::<Vec<_>>(),
            "manifests": self.manifests.values().map(TimelockedUpgradeManifest::public_record).collect::<Vec<_>>(),
            "compatibility_commitments": self.compatibility_commitments.values().map(CompatibilityCommitment::public_record).collect::<Vec<_>>(),
            "emergency_guards": self.emergency_guards.values().map(EmergencyPauseOrVeto::public_record).collect::<Vec<_>>(),
            "disclosure_windows": self.disclosure_windows.values().map(PrivateDisclosureWindow::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeUpgradeSponsorship::public_record).collect::<Vec<_>>(),
            "migration_receipts": self.migration_receipts.values().map(MigrationReceipt::public_record).collect::<Vec<_>>(),
            "rollback_plans": self.rollback_plans.values().map(RollbackPlan::public_record).collect::<Vec<_>>(),
            "audit_attestations": self.audit_attestations.values().map(AuditAttestation::public_record).collect::<Vec<_>>(),
            "deterministic_public_records": self.deterministic_public_records.values().map(DeterministicPublicRecord::public_record).collect::<Vec<_>>(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_contract_upgrade_guard_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> PqContractUpgradeGuardResult<String> {
        self.config.validate()?;
        ensure_max_len(
            self.authorities.len(),
            self.config.max_authorities,
            "authorities",
        )?;
        ensure_max_len(self.manifests.len(), self.config.max_manifests, "manifests")?;
        ensure_max_len(
            self.compatibility_commitments.len(),
            self.config.max_compatibility_commitments,
            "compatibility commitments",
        )?;
        ensure_max_len(
            self.emergency_guards.len(),
            self.config.max_pauses,
            "pauses",
        )?;
        ensure_max_len(
            self.disclosure_windows.len(),
            self.config.max_disclosure_windows,
            "disclosure windows",
        )?;
        ensure_max_len(
            self.sponsorships.len(),
            self.config.max_sponsorships,
            "sponsorships",
        )?;
        ensure_max_len(
            self.migration_receipts.len(),
            self.config.max_receipts,
            "receipts",
        )?;
        ensure_max_len(
            self.rollback_plans.len(),
            self.config.max_rollback_plans,
            "rollback plans",
        )?;
        ensure_max_len(
            self.audit_attestations.len(),
            self.config.max_audit_attestations,
            "audit attestations",
        )?;
        ensure_max_len(
            self.deterministic_public_records.len(),
            self.config.max_public_records,
            "public records",
        )?;

        self.roots().validate()?;
        self.counters().validate()?;

        let authority_ids =
            validate_map(&self.authorities, "authority", PqUpgradeAuthority::validate)?;
        let authority_set = authority_ids.into_iter().collect::<BTreeSet<_>>();
        let manifest_ids = validate_map(
            &self.manifests,
            "manifest",
            TimelockedUpgradeManifest::validate,
        )?;
        let manifest_set = manifest_ids.into_iter().collect::<BTreeSet<_>>();
        let contract_set = self
            .manifests
            .values()
            .map(|manifest| manifest.contract_id.clone())
            .collect::<BTreeSet<_>>();

        for manifest in self.manifests.values() {
            if !authority_set.contains(&manifest.authority_id) {
                return Err("manifest references missing authority".to_string());
            }
            let authority = self
                .authorities
                .get(&manifest.authority_id)
                .ok_or_else(|| "manifest authority missing".to_string())?;
            if !authority.contract_scope.is_empty()
                && !authority.contract_scope.contains(&manifest.contract_id)
            {
                return Err("manifest contract outside authority scope".to_string());
            }
            if manifest.risk_tier.emergency_capable()
                && !self
                    .rollback_plans
                    .values()
                    .any(|plan| plan.manifest_id == manifest.manifest_id)
            {
                return Err("critical manifest missing rollback plan".to_string());
            }
        }

        self.validate_referenced_manifest_and_contracts(
            &manifest_set,
            &contract_set,
            &authority_set,
        )?;
        self.validate_manifest_readiness()?;
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "pq_contract_upgrade_guard_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION,
            "schema_version": PQ_CONTRACT_UPGRADE_GUARD_SCHEMA_VERSION,
            "height": self.height,
            "config_root": self.config.root(),
            "counter_root": self.counters().root(),
            "authority_ids": self.authorities.keys().cloned().collect::<Vec<_>>(),
            "manifest_ids": self.manifests.keys().cloned().collect::<Vec<_>>(),
            "compatibility_commitment_ids": self.compatibility_commitments.keys().cloned().collect::<Vec<_>>(),
            "emergency_guard_ids": self.emergency_guards.keys().cloned().collect::<Vec<_>>(),
            "disclosure_window_ids": self.disclosure_windows.keys().cloned().collect::<Vec<_>>(),
            "sponsorship_ids": self.sponsorships.keys().cloned().collect::<Vec<_>>(),
            "migration_receipt_ids": self.migration_receipts.keys().cloned().collect::<Vec<_>>(),
            "rollback_plan_ids": self.rollback_plans.keys().cloned().collect::<Vec<_>>(),
            "audit_attestation_ids": self.audit_attestations.keys().cloned().collect::<Vec<_>>(),
            "deterministic_public_record_ids": self.deterministic_public_records.keys().cloned().collect::<Vec<_>>(),
        })
    }

    fn validate_referenced_manifest_and_contracts(
        &self,
        manifest_set: &BTreeSet<String>,
        contract_set: &BTreeSet<String>,
        authority_set: &BTreeSet<String>,
    ) -> PqContractUpgradeGuardResult<()> {
        for (id, commitment) in &self.compatibility_commitments {
            if id != &commitment.commitment_id {
                return Err("compatibility commitment map key mismatch".to_string());
            }
            commitment.validate()?;
            require_reference(
                manifest_set,
                "compatibility manifest",
                &commitment.manifest_id,
            )?;
            require_reference(
                contract_set,
                "compatibility contract",
                &commitment.contract_id,
            )?;
        }
        for (id, guard) in &self.emergency_guards {
            if id != &guard.guard_id {
                return Err("emergency guard map key mismatch".to_string());
            }
            guard.validate()?;
            require_reference(manifest_set, "emergency manifest", &guard.manifest_id)?;
            require_reference(contract_set, "emergency contract", &guard.contract_id)?;
            require_reference(authority_set, "emergency authority", &guard.authority_id)?;
        }
        for (id, disclosure) in &self.disclosure_windows {
            if id != &disclosure.disclosure_id {
                return Err("disclosure window map key mismatch".to_string());
            }
            disclosure.validate()?;
            require_reference(manifest_set, "disclosure manifest", &disclosure.manifest_id)?;
            require_reference(contract_set, "disclosure contract", &disclosure.contract_id)?;
        }
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
            require_reference(
                manifest_set,
                "sponsorship manifest",
                &sponsorship.manifest_id,
            )?;
            require_reference(
                contract_set,
                "sponsorship contract",
                &sponsorship.contract_id,
            )?;
        }
        for (id, receipt) in &self.migration_receipts {
            if id != &receipt.receipt_id {
                return Err("migration receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            require_reference(manifest_set, "receipt manifest", &receipt.manifest_id)?;
            require_reference(contract_set, "receipt contract", &receipt.contract_id)?;
        }
        for (id, plan) in &self.rollback_plans {
            if id != &plan.rollback_id {
                return Err("rollback plan map key mismatch".to_string());
            }
            plan.validate()?;
            require_reference(manifest_set, "rollback manifest", &plan.manifest_id)?;
            require_reference(contract_set, "rollback contract", &plan.contract_id)?;
            require_reference(authority_set, "rollback authority", &plan.authority_id)?;
        }
        for (id, attestation) in &self.audit_attestations {
            if id != &attestation.attestation_id {
                return Err("audit attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            require_reference(manifest_set, "audit manifest", &attestation.manifest_id)?;
            require_reference(contract_set, "audit contract", &attestation.contract_id)?;
        }
        for (id, record) in &self.deterministic_public_records {
            if id != &record.record_id {
                return Err("public record map key mismatch".to_string());
            }
            record.validate()?;
            require_reference(manifest_set, "public record manifest", &record.manifest_id)?;
            require_reference(contract_set, "public record contract", &record.contract_id)?;
        }
        Ok(())
    }

    fn validate_manifest_readiness(&self) -> PqContractUpgradeGuardResult<()> {
        for manifest in self.manifests.values() {
            if manifest.status.executable() {
                let compatibility_count = self
                    .compatibility_commitments
                    .values()
                    .filter(|commitment| {
                        commitment.manifest_id == manifest.manifest_id
                            && commitment.status == CompatibilityStatus::Verified
                    })
                    .count() as u64;
                if compatibility_count < 2 {
                    return Err("executable manifest lacks compatibility proofs".to_string());
                }
                let accepted_audits = self
                    .audit_attestations
                    .values()
                    .filter(|attestation| {
                        attestation.manifest_id == manifest.manifest_id
                            && attestation.status.accepted()
                            && attestation.score_bps >= self.config.min_audit_score_bps
                    })
                    .count() as u64;
                if accepted_audits < self.config.min_audit_attestations {
                    return Err("executable manifest lacks accepted audit attestations".to_string());
                }
                if manifest.requires_private_disclosure
                    && !self
                        .disclosure_windows
                        .values()
                        .any(|window| window.manifest_id == manifest.manifest_id)
                {
                    return Err("executable manifest lacks private disclosure window".to_string());
                }
                if manifest.requires_low_fee_sponsorship
                    && !self
                        .sponsorships
                        .values()
                        .any(|sponsorship| sponsorship.manifest_id == manifest.manifest_id)
                {
                    return Err("executable manifest lacks low-fee sponsorship".to_string());
                }
            }
        }
        Ok(())
    }
}

pub fn pq_contract_upgrade_guard_state_root_from_record(record: &Value) -> String {
    pq_contract_upgrade_guard_payload_root("PQ-CONTRACT-UPGRADE-GUARD-STATE", record)
}

pub fn pq_contract_upgrade_guard_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn pq_contract_upgrade_guard_list_root(domain: &str, records: &[Value]) -> String {
    pq_contract_upgrade_guard_payload_root(domain, &Value::Array(records.to_vec()))
}

pub fn pq_contract_upgrade_guard_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-GUARD-STRING",
        &[
            HashPart::Str(PQ_CONTRACT_UPGRADE_GUARD_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_upgrade_authority_id(
    label: &str,
    signer_commitments: &[String],
    threshold: u64,
    veto_key_commitment: &str,
    created_at_height: u64,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-AUTHORITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(&Value::Array(
                signer_commitments
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect::<Vec<_>>(),
            )),
            HashPart::Int(threshold as i128),
            HashPart::Str(veto_key_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn pq_contract_upgrade_manifest_id(
    contract_id: &str,
    authority_id: &str,
    manifest_payload_root: &str,
    new_bytecode_root: &str,
    queued_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(authority_id),
            HashPart::Str(manifest_payload_root),
            HashPart::Str(new_bytecode_root),
            HashPart::Int(queued_at_height as i128),
        ],
        32,
    )
}

pub fn pq_compatibility_commitment_id(
    manifest_id: &str,
    contract_id: &str,
    kind: CompatibilityKind,
    old_root: &str,
    new_root: &str,
    proof_root: &str,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-COMPATIBILITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(old_root),
            HashPart::Str(new_root),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn pq_emergency_guard_id(
    manifest_id: &str,
    contract_id: &str,
    authority_id: &str,
    mode: EmergencyGuardMode,
    reason_root: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-EMERGENCY-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(authority_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(reason_root),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn pq_private_disclosure_window_id(
    manifest_id: &str,
    contract_id: &str,
    audience: DisclosureAudience,
    sealed_payload_root: &str,
    opens_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(audience.as_str()),
            HashPart::Str(sealed_payload_root),
            HashPart::Int(opens_at_height as i128),
        ],
        32,
    )
}

pub fn pq_low_fee_sponsorship_id(
    manifest_id: &str,
    contract_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn pq_migration_receipt_id(
    manifest_id: &str,
    contract_id: &str,
    user_commitment: &str,
    nullifier_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-MIGRATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(user_commitment),
            HashPart::Str(nullifier_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn pq_rollback_plan_id(
    manifest_id: &str,
    contract_id: &str,
    authority_id: &str,
    rollback_payload_root: &str,
    armed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-ROLLBACK-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(authority_id),
            HashPart::Str(rollback_payload_root),
            HashPart::Int(armed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_audit_attestation_id(
    manifest_id: &str,
    contract_id: &str,
    auditor_commitment: &str,
    attestation_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-AUDIT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(auditor_commitment),
            HashPart::Str(attestation_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn pq_deterministic_public_record_id(
    manifest_id: &str,
    contract_id: &str,
    record_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-UPGRADE-DETERMINISTIC-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(contract_id),
            HashPart::Str(record_kind),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}

fn validate_map<T, F>(
    values: &BTreeMap<String, T>,
    label: &str,
    validate: F,
) -> PqContractUpgradeGuardResult<Vec<String>>
where
    F: Fn(&T) -> PqContractUpgradeGuardResult<String>,
{
    let mut ids = Vec::with_capacity(values.len());
    for (id, value) in values {
        let validated_id = validate(value)?;
        if id != &validated_id {
            return Err(format!("{label} map key mismatch"));
        }
        ids.push(validated_id);
    }
    require_unique_strings(&ids, label)?;
    Ok(ids)
}

fn require_reference(
    set: &BTreeSet<String>,
    label: &str,
    value: &str,
) -> PqContractUpgradeGuardResult<()> {
    if !set.contains(value) {
        return Err(format!("{label} references missing id {value}"));
    }
    Ok(())
}

fn ensure_max_len(value: usize, max: usize, label: &str) -> PqContractUpgradeGuardResult<()> {
    if value > max {
        return Err(format!("{label} count exceeds configured maximum"));
    }
    Ok(())
}

fn require_equal(label: &str, actual: &str, expected: &str) -> PqContractUpgradeGuardResult<()> {
    if actual != expected {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> PqContractUpgradeGuardResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn require_positive(label: &str, value: u64) -> PqContractUpgradeGuardResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn require_capacity(label: &str, value: usize) -> PqContractUpgradeGuardResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> PqContractUpgradeGuardResult<()> {
    if value > PQ_CONTRACT_UPGRADE_GUARD_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn require_unique_strings(values: &[String], label: &str) -> PqContractUpgradeGuardResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} duplicated"));
        }
    }
    Ok(())
}
