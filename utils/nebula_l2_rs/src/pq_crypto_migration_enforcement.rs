use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqCryptoMigrationEnforcementResult<T> = Result<T, String>;

pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION: &str =
    "nebula-pq-crypto-migration-enforcement-v1";
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_SCHEMA_VERSION: &str =
    "pq-crypto-migration-enforcement-state-v1";
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEVNET_LABEL: &str =
    "devnet-pq-crypto-migration-enforcement";
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_HASH_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_RECEIPT_SCHEME: &str =
    "hybrid-classic-pq-credential-receipt-v1";
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_NULLIFIER_SCHEME: &str =
    "migration-revocation-nullifier-root-v1";
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_NOTICE_EPOCHS: u64 = 4;
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_EXCEPTION_EPOCHS: u64 = 2;
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_GRACE_EPOCHS: u64 = 1;
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_CHALLENGE_EPOCHS: u64 = 2;
pub const PQ_CRYPTO_MIGRATION_ENFORCEMENT_MIN_SECURITY_BITS: u16 = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementDomain {
    Accounts,
    Sequencers,
    BridgeCommittees,
    ProverMarkets,
    Wallets,
    ContractAuth,
    OperatorKeys,
}

impl EnforcementDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Sequencers => "sequencers",
            Self::BridgeCommittees => "bridge_committees",
            Self::ProverMarkets => "prover_markets",
            Self::Wallets => "wallets",
            Self::ContractAuth => "contract_auth",
            Self::OperatorKeys => "operator_keys",
        }
    }

    pub fn requires_continuity(self) -> bool {
        matches!(
            self,
            Self::Sequencers | Self::BridgeCommittees | Self::ContractAuth | Self::OperatorKeys
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStage {
    Discovery,
    Notice,
    HybridRequired,
    PqRequired,
    LegacyDisabled,
    EmergencyFreeze,
}

impl MigrationStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Notice => "notice",
            Self::HybridRequired => "hybrid_required",
            Self::PqRequired => "pq_required",
            Self::LegacyDisabled => "legacy_disabled",
            Self::EmergencyFreeze => "emergency_freeze",
        }
    }

    pub fn accepts_legacy(self) -> bool {
        matches!(self, Self::Discovery | Self::Notice | Self::HybridRequired)
    }

    pub fn requires_pq(self) -> bool {
        matches!(
            self,
            Self::HybridRequired | Self::PqRequired | Self::LegacyDisabled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ClassicOnly,
    PqOnly,
    Hybrid,
    CommitteeThreshold,
    WalletDelegation,
    ContractAuthorization,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClassicOnly => "classic_only",
            Self::PqOnly => "pq_only",
            Self::Hybrid => "hybrid",
            Self::CommitteeThreshold => "committee_threshold",
            Self::WalletDelegation => "wallet_delegation",
            Self::ContractAuthorization => "contract_authorization",
        }
    }

    pub fn has_pq_material(self) -> bool {
        !matches!(self, Self::ClassicOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Unknown,
    Scheduled,
    HybridCompliant,
    PqCompliant,
    ExceptionActive,
    Noncompliant,
    Revoked,
    Frozen,
}

impl ComplianceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Scheduled => "scheduled",
            Self::HybridCompliant => "hybrid_compliant",
            Self::PqCompliant => "pq_compliant",
            Self::ExceptionActive => "exception_active",
            Self::Noncompliant => "noncompliant",
            Self::Revoked => "revoked",
            Self::Frozen => "frozen",
        }
    }

    pub fn is_blocking(self) -> bool {
        matches!(self, Self::Noncompliant | Self::Revoked | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionReason {
    HardwareDelay,
    BridgeSafety,
    CourtOrder,
    SocialRecovery,
    SequencerContinuity,
    ProverMarketLiquidity,
    EmergencyCouncil,
}

impl ExceptionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardwareDelay => "hardware_delay",
            Self::BridgeSafety => "bridge_safety",
            Self::CourtOrder => "court_order",
            Self::SocialRecovery => "social_recovery",
            Self::SequencerContinuity => "sequencer_continuity",
            Self::ProverMarketLiquidity => "prover_market_liquidity",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    Observe,
    Warn,
    RequireHybridReceipt,
    DisableLegacySigning,
    QuarantineKey,
    RevokeCredential,
    SlashOperatorBond,
    FreezeSubject,
}

impl EnforcementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::RequireHybridReceipt => "require_hybrid_receipt",
            Self::DisableLegacySigning => "disable_legacy_signing",
            Self::QuarantineKey => "quarantine_key",
            Self::RevokeCredential => "revoke_credential",
            Self::SlashOperatorBond => "slash_operator_bond",
            Self::FreezeSubject => "freeze_subject",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: String,
    pub epoch_blocks: u64,
    pub notice_epochs: u64,
    pub exception_epochs: u64,
    pub grace_epochs: u64,
    pub challenge_epochs: u64,
    pub min_pq_security_bits: u16,
    pub receipt_scheme: String,
    pub nullifier_scheme: String,
    pub hash_scheme: String,
    pub enforcement_council_root: String,
    pub emergency_pause_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_CRYPTO_MIGRATION_ENFORCEMENT_SCHEMA_VERSION.to_string(),
            epoch_blocks: PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_EPOCH_BLOCKS,
            notice_epochs: PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_NOTICE_EPOCHS,
            exception_epochs: PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_EXCEPTION_EPOCHS,
            grace_epochs: PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_GRACE_EPOCHS,
            challenge_epochs: PQ_CRYPTO_MIGRATION_ENFORCEMENT_DEFAULT_CHALLENGE_EPOCHS,
            min_pq_security_bits: PQ_CRYPTO_MIGRATION_ENFORCEMENT_MIN_SECURITY_BITS,
            receipt_scheme: PQ_CRYPTO_MIGRATION_ENFORCEMENT_RECEIPT_SCHEME.to_string(),
            nullifier_scheme: PQ_CRYPTO_MIGRATION_ENFORCEMENT_NULLIFIER_SCHEME.to_string(),
            hash_scheme: PQ_CRYPTO_MIGRATION_ENFORCEMENT_HASH_SCHEME.to_string(),
            enforcement_council_root: leaf_hash(
                "PQ-CRYPTO-MIGRATION-ENFORCEMENT-COUNCIL",
                "devnet-council",
            ),
            emergency_pause_root: merkle_root("PQ-CRYPTO-MIGRATION-EMERGENCY-PAUSE", &[]),
        }
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.protocol_version != PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION {
            return Err("pq crypto migration enforcement protocol version mismatch".to_string());
        }
        if self.schema_version != PQ_CRYPTO_MIGRATION_ENFORCEMENT_SCHEMA_VERSION {
            return Err("pq crypto migration enforcement schema version mismatch".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err("epoch blocks must be nonzero".to_string());
        }
        if self.min_pq_security_bits < PQ_CRYPTO_MIGRATION_ENFORCEMENT_MIN_SECURITY_BITS {
            return Err("minimum pq security bits below enforcement floor".to_string());
        }
        if self.receipt_scheme.is_empty()
            || self.nullifier_scheme.is_empty()
            || self.hash_scheme.is_empty()
            || self.enforcement_council_root.is_empty()
            || self.emergency_pause_root.is_empty()
        {
            return Err("config roots and schemes must be populated".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "epoch_blocks": self.epoch_blocks,
            "notice_epochs": self.notice_epochs,
            "exception_epochs": self.exception_epochs,
            "grace_epochs": self.grace_epochs,
            "challenge_epochs": self.challenge_epochs,
            "min_pq_security_bits": self.min_pq_security_bits,
            "receipt_scheme": self.receipt_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "hash_scheme": self.hash_scheme,
            "enforcement_council_root": self.enforcement_council_root,
            "emergency_pause_root": self.emergency_pause_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeadlineEpoch {
    pub deadline_id: String,
    pub domain: EnforcementDomain,
    pub stage: MigrationStage,
    pub announce_epoch: u64,
    pub hybrid_required_epoch: u64,
    pub pq_required_epoch: u64,
    pub legacy_disabled_epoch: u64,
    pub enforcement_action: EnforcementAction,
    pub policy_root: String,
}

impl DeadlineEpoch {
    pub fn new(
        domain: EnforcementDomain,
        stage: MigrationStage,
        announce_epoch: u64,
        hybrid_required_epoch: u64,
        pq_required_epoch: u64,
        legacy_disabled_epoch: u64,
        enforcement_action: EnforcementAction,
        policy_root: &str,
    ) -> Self {
        let deadline_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-DEADLINE-ID",
            &[
                domain.as_str(),
                stage.as_str(),
                &announce_epoch.to_string(),
                &hybrid_required_epoch.to_string(),
                &pq_required_epoch.to_string(),
                &legacy_disabled_epoch.to_string(),
                enforcement_action.as_str(),
                policy_root,
            ],
        );
        Self {
            deadline_id,
            domain,
            stage,
            announce_epoch,
            hybrid_required_epoch,
            pq_required_epoch,
            legacy_disabled_epoch,
            enforcement_action,
            policy_root: policy_root.to_string(),
        }
    }

    pub fn stage_at_epoch(&self, epoch: u64) -> MigrationStage {
        if epoch >= self.legacy_disabled_epoch {
            MigrationStage::LegacyDisabled
        } else if epoch >= self.pq_required_epoch {
            MigrationStage::PqRequired
        } else if epoch >= self.hybrid_required_epoch {
            MigrationStage::HybridRequired
        } else if epoch >= self.announce_epoch {
            MigrationStage::Notice
        } else {
            MigrationStage::Discovery
        }
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.deadline_id.is_empty() || self.policy_root.is_empty() {
            return Err("deadline id and policy root must be populated".to_string());
        }
        if self.announce_epoch > self.hybrid_required_epoch
            || self.hybrid_required_epoch > self.pq_required_epoch
            || self.pq_required_epoch > self.legacy_disabled_epoch
        {
            return Err("deadline epochs must be ordered".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deadline_id": self.deadline_id,
            "domain": self.domain.as_str(),
            "stage": self.stage.as_str(),
            "announce_epoch": self.announce_epoch,
            "hybrid_required_epoch": self.hybrid_required_epoch,
            "pq_required_epoch": self.pq_required_epoch,
            "legacy_disabled_epoch": self.legacy_disabled_epoch,
            "enforcement_action": self.enforcement_action.as_str(),
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationSubject {
    pub subject_id: String,
    pub domain: EnforcementDomain,
    pub owner_commitment: String,
    pub current_credential_root: String,
    pub required_deadline_id: String,
    pub status: ComplianceStatus,
    pub first_seen_epoch: u64,
    pub last_checked_height: u64,
    pub exception_id: Option<String>,
    pub noncompliance_flag_id: Option<String>,
}

impl MigrationSubject {
    pub fn new(
        domain: EnforcementDomain,
        owner_commitment: &str,
        current_credential_root: &str,
        required_deadline_id: &str,
        first_seen_epoch: u64,
        last_checked_height: u64,
    ) -> Self {
        let subject_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-SUBJECT-ID",
            &[
                domain.as_str(),
                owner_commitment,
                current_credential_root,
                required_deadline_id,
                &first_seen_epoch.to_string(),
            ],
        );
        Self {
            subject_id,
            domain,
            owner_commitment: owner_commitment.to_string(),
            current_credential_root: current_credential_root.to_string(),
            required_deadline_id: required_deadline_id.to_string(),
            status: ComplianceStatus::Scheduled,
            first_seen_epoch,
            last_checked_height,
            exception_id: None,
            noncompliance_flag_id: None,
        }
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.subject_id.is_empty()
            || self.owner_commitment.is_empty()
            || self.current_credential_root.is_empty()
            || self.required_deadline_id.is_empty()
        {
            return Err("migration subject identifiers must be populated".to_string());
        }
        if self.status == ComplianceStatus::ExceptionActive && self.exception_id.is_none() {
            return Err("exception status requires exception id".to_string());
        }
        if self.status == ComplianceStatus::Noncompliant && self.noncompliance_flag_id.is_none() {
            return Err("noncompliant subject requires flag id".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "owner_commitment": self.owner_commitment,
            "current_credential_root": self.current_credential_root,
            "required_deadline_id": self.required_deadline_id,
            "status": self.status.as_str(),
            "first_seen_epoch": self.first_seen_epoch,
            "last_checked_height": self.last_checked_height,
            "exception_id": self.exception_id,
            "noncompliance_flag_id": self.noncompliance_flag_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridCredentialReceipt {
    pub receipt_id: String,
    pub subject_id: String,
    pub credential_kind: CredentialKind,
    pub classic_key_commitment: String,
    pub pq_key_commitment: String,
    pub pq_algorithm: String,
    pub pq_security_bits: u16,
    pub issued_epoch: u64,
    pub valid_until_epoch: u64,
    pub attester_root: String,
    pub proof_root: String,
    pub nullifier: String,
}

impl HybridCredentialReceipt {
    pub fn new(
        subject_id: &str,
        credential_kind: CredentialKind,
        classic_key_commitment: &str,
        pq_key_commitment: &str,
        pq_algorithm: &str,
        pq_security_bits: u16,
        issued_epoch: u64,
        valid_until_epoch: u64,
        attester_root: &str,
        proof_root: &str,
    ) -> Self {
        let nullifier = typed_hash(
            "PQ-CRYPTO-MIGRATION-RECEIPT-NULLIFIER",
            &[
                subject_id,
                credential_kind.as_str(),
                pq_key_commitment,
                pq_algorithm,
                &issued_epoch.to_string(),
            ],
        );
        let receipt_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-HYBRID-RECEIPT-ID",
            &[
                subject_id,
                credential_kind.as_str(),
                classic_key_commitment,
                pq_key_commitment,
                pq_algorithm,
                &pq_security_bits.to_string(),
                &issued_epoch.to_string(),
                &valid_until_epoch.to_string(),
                attester_root,
                proof_root,
                &nullifier,
            ],
        );
        Self {
            receipt_id,
            subject_id: subject_id.to_string(),
            credential_kind,
            classic_key_commitment: classic_key_commitment.to_string(),
            pq_key_commitment: pq_key_commitment.to_string(),
            pq_algorithm: pq_algorithm.to_string(),
            pq_security_bits,
            issued_epoch,
            valid_until_epoch,
            attester_root: attester_root.to_string(),
            proof_root: proof_root.to_string(),
            nullifier,
        }
    }

    pub fn validate(&self, config: &Config) -> PqCryptoMigrationEnforcementResult<()> {
        if self.receipt_id.is_empty()
            || self.subject_id.is_empty()
            || self.classic_key_commitment.is_empty()
            || self.pq_key_commitment.is_empty()
            || self.pq_algorithm.is_empty()
            || self.attester_root.is_empty()
            || self.proof_root.is_empty()
            || self.nullifier.is_empty()
        {
            return Err("hybrid credential receipt fields must be populated".to_string());
        }
        if !self.credential_kind.has_pq_material() {
            return Err("hybrid receipt cannot be classic only".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("hybrid receipt pq security bits below config floor".to_string());
        }
        if self.issued_epoch > self.valid_until_epoch {
            return Err("hybrid receipt validity epochs must be ordered".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "credential_kind": self.credential_kind.as_str(),
            "classic_key_commitment": self.classic_key_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "pq_algorithm": self.pq_algorithm,
            "pq_security_bits": self.pq_security_bits,
            "issued_epoch": self.issued_epoch,
            "valid_until_epoch": self.valid_until_epoch,
            "attester_root": self.attester_root,
            "proof_root": self.proof_root,
            "nullifier": self.nullifier,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExceptionWindow {
    pub exception_id: String,
    pub subject_id: String,
    pub reason: ExceptionReason,
    pub opened_epoch: u64,
    pub closes_epoch: u64,
    pub max_legacy_actions: u64,
    pub used_legacy_actions: u64,
    pub approval_root: String,
    pub disclosure_root: String,
}

impl ExceptionWindow {
    pub fn new(
        subject_id: &str,
        reason: ExceptionReason,
        opened_epoch: u64,
        closes_epoch: u64,
        max_legacy_actions: u64,
        approval_root: &str,
        disclosure_root: &str,
    ) -> Self {
        let exception_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-EXCEPTION-ID",
            &[
                subject_id,
                reason.as_str(),
                &opened_epoch.to_string(),
                &closes_epoch.to_string(),
                &max_legacy_actions.to_string(),
                approval_root,
                disclosure_root,
            ],
        );
        Self {
            exception_id,
            subject_id: subject_id.to_string(),
            reason,
            opened_epoch,
            closes_epoch,
            max_legacy_actions,
            used_legacy_actions: 0,
            approval_root: approval_root.to_string(),
            disclosure_root: disclosure_root.to_string(),
        }
    }

    pub fn active_at_epoch(&self, epoch: u64) -> bool {
        self.opened_epoch <= epoch
            && epoch <= self.closes_epoch
            && self.used_legacy_actions <= self.max_legacy_actions
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.exception_id.is_empty()
            || self.subject_id.is_empty()
            || self.approval_root.is_empty()
            || self.disclosure_root.is_empty()
        {
            return Err("exception window fields must be populated".to_string());
        }
        if self.opened_epoch > self.closes_epoch {
            return Err("exception window epochs must be ordered".to_string());
        }
        if self.used_legacy_actions > self.max_legacy_actions {
            return Err("exception window legacy usage exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exception_id": self.exception_id,
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "opened_epoch": self.opened_epoch,
            "closes_epoch": self.closes_epoch,
            "max_legacy_actions": self.max_legacy_actions,
            "used_legacy_actions": self.used_legacy_actions,
            "approval_root": self.approval_root,
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoncomplianceFlag {
    pub flag_id: String,
    pub subject_id: String,
    pub domain: EnforcementDomain,
    pub detected_height: u64,
    pub detected_epoch: u64,
    pub missing_requirement: String,
    pub action: EnforcementAction,
    pub evidence_root: String,
    pub cleared_by_receipt_id: Option<String>,
}

impl NoncomplianceFlag {
    pub fn new(
        subject_id: &str,
        domain: EnforcementDomain,
        detected_height: u64,
        detected_epoch: u64,
        missing_requirement: &str,
        action: EnforcementAction,
        evidence_root: &str,
    ) -> Self {
        let flag_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-NONCOMPLIANCE-FLAG-ID",
            &[
                subject_id,
                domain.as_str(),
                &detected_height.to_string(),
                &detected_epoch.to_string(),
                missing_requirement,
                action.as_str(),
                evidence_root,
            ],
        );
        Self {
            flag_id,
            subject_id: subject_id.to_string(),
            domain,
            detected_height,
            detected_epoch,
            missing_requirement: missing_requirement.to_string(),
            action,
            evidence_root: evidence_root.to_string(),
            cleared_by_receipt_id: None,
        }
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.flag_id.is_empty()
            || self.subject_id.is_empty()
            || self.missing_requirement.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("noncompliance flag fields must be populated".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "flag_id": self.flag_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "detected_height": self.detected_height,
            "detected_epoch": self.detected_epoch,
            "missing_requirement": self.missing_requirement,
            "action": self.action.as_str(),
            "evidence_root": self.evidence_root,
            "cleared_by_receipt_id": self.cleared_by_receipt_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub revocation_id: String,
    pub subject_id: String,
    pub receipt_id: String,
    pub nullifier: String,
    pub reason_root: String,
    pub revoked_at_height: u64,
    pub revoked_at_epoch: u64,
    pub authority_root: String,
}

impl RevocationRecord {
    pub fn new(
        subject_id: &str,
        receipt_id: &str,
        nullifier: &str,
        reason_root: &str,
        revoked_at_height: u64,
        revoked_at_epoch: u64,
        authority_root: &str,
    ) -> Self {
        let revocation_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-REVOCATION-ID",
            &[
                subject_id,
                receipt_id,
                nullifier,
                reason_root,
                &revoked_at_height.to_string(),
                &revoked_at_epoch.to_string(),
                authority_root,
            ],
        );
        Self {
            revocation_id,
            subject_id: subject_id.to_string(),
            receipt_id: receipt_id.to_string(),
            nullifier: nullifier.to_string(),
            reason_root: reason_root.to_string(),
            revoked_at_height,
            revoked_at_epoch,
            authority_root: authority_root.to_string(),
        }
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.revocation_id.is_empty()
            || self.subject_id.is_empty()
            || self.receipt_id.is_empty()
            || self.nullifier.is_empty()
            || self.reason_root.is_empty()
            || self.authority_root.is_empty()
        {
            return Err("revocation record fields must be populated".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "revocation_id": self.revocation_id,
            "subject_id": self.subject_id,
            "receipt_id": self.receipt_id,
            "nullifier": self.nullifier,
            "reason_root": self.reason_root,
            "revoked_at_height": self.revoked_at_height,
            "revoked_at_epoch": self.revoked_at_epoch,
            "authority_root": self.authority_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub decision_id: String,
    pub subject_id: String,
    pub domain: EnforcementDomain,
    pub stage: MigrationStage,
    pub status_after: ComplianceStatus,
    pub action: EnforcementAction,
    pub decision_height: u64,
    pub decision_epoch: u64,
    pub input_root: String,
    pub output_root: String,
}

impl EnforcementDecision {
    pub fn new(
        subject_id: &str,
        domain: EnforcementDomain,
        stage: MigrationStage,
        status_after: ComplianceStatus,
        action: EnforcementAction,
        decision_height: u64,
        decision_epoch: u64,
        input_root: &str,
        output_root: &str,
    ) -> Self {
        let decision_id = typed_hash(
            "PQ-CRYPTO-MIGRATION-ENFORCEMENT-DECISION-ID",
            &[
                subject_id,
                domain.as_str(),
                stage.as_str(),
                status_after.as_str(),
                action.as_str(),
                &decision_height.to_string(),
                &decision_epoch.to_string(),
                input_root,
                output_root,
            ],
        );
        Self {
            decision_id,
            subject_id: subject_id.to_string(),
            domain,
            stage,
            status_after,
            action,
            decision_height,
            decision_epoch,
            input_root: input_root.to_string(),
            output_root: output_root.to_string(),
        }
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        if self.decision_id.is_empty()
            || self.subject_id.is_empty()
            || self.input_root.is_empty()
            || self.output_root.is_empty()
        {
            return Err("enforcement decision fields must be populated".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "stage": self.stage.as_str(),
            "status_after": self.status_after.as_str(),
            "action": self.action.as_str(),
            "decision_height": self.decision_height,
            "decision_epoch": self.decision_epoch,
            "input_root": self.input_root,
            "output_root": self.output_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub deadline_root: String,
    pub subject_root: String,
    pub receipt_root: String,
    pub exception_root: String,
    pub noncompliance_root: String,
    pub revocation_root: String,
    pub nullifier_root: String,
    pub decision_root: String,
}

impl Roots {
    pub fn combined_root(&self) -> String {
        domain_hash(
            "PQ-CRYPTO-MIGRATION-ENFORCEMENT-ROOTS",
            &[
                HashPart::Str(PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.deadline_root),
                HashPart::Str(&self.subject_root),
                HashPart::Str(&self.receipt_root),
                HashPart::Str(&self.exception_root),
                HashPart::Str(&self.noncompliance_root),
                HashPart::Str(&self.revocation_root),
                HashPart::Str(&self.nullifier_root),
                HashPart::Str(&self.decision_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "deadline_root": self.deadline_root,
            "subject_root": self.subject_root,
            "receipt_root": self.receipt_root,
            "exception_root": self.exception_root,
            "noncompliance_root": self.noncompliance_root,
            "revocation_root": self.revocation_root,
            "nullifier_root": self.nullifier_root,
            "decision_root": self.decision_root,
            "combined_root": self.combined_root(),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub deadlines: u64,
    pub subjects: u64,
    pub compliant_subjects: u64,
    pub exception_subjects: u64,
    pub noncompliant_subjects: u64,
    pub blocking_subjects: u64,
    pub hybrid_receipts: u64,
    pub active_exceptions: u64,
    pub noncompliance_flags: u64,
    pub revocations: u64,
    pub decisions: u64,
    pub account_subjects: u64,
    pub sequencer_subjects: u64,
    pub bridge_committee_subjects: u64,
    pub prover_market_subjects: u64,
    pub wallet_subjects: u64,
    pub contract_auth_subjects: u64,
    pub operator_key_subjects: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "deadlines": self.deadlines,
            "subjects": self.subjects,
            "compliant_subjects": self.compliant_subjects,
            "exception_subjects": self.exception_subjects,
            "noncompliant_subjects": self.noncompliant_subjects,
            "blocking_subjects": self.blocking_subjects,
            "hybrid_receipts": self.hybrid_receipts,
            "active_exceptions": self.active_exceptions,
            "noncompliance_flags": self.noncompliance_flags,
            "revocations": self.revocations,
            "decisions": self.decisions,
            "account_subjects": self.account_subjects,
            "sequencer_subjects": self.sequencer_subjects,
            "bridge_committee_subjects": self.bridge_committee_subjects,
            "prover_market_subjects": self.prover_market_subjects,
            "wallet_subjects": self.wallet_subjects,
            "contract_auth_subjects": self.contract_auth_subjects,
            "operator_key_subjects": self.operator_key_subjects,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub deadlines: BTreeMap<String, DeadlineEpoch>,
    pub subjects: BTreeMap<String, MigrationSubject>,
    pub receipts: BTreeMap<String, HybridCredentialReceipt>,
    pub exceptions: BTreeMap<String, ExceptionWindow>,
    pub noncompliance_flags: BTreeMap<String, NoncomplianceFlag>,
    pub revocations: BTreeMap<String, RevocationRecord>,
    pub decisions: BTreeMap<String, EnforcementDecision>,
}

impl State {
    pub fn devnet() -> PqCryptoMigrationEnforcementResult<State> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = State {
            height: 0,
            config,
            deadlines: BTreeMap::new(),
            subjects: BTreeMap::new(),
            receipts: BTreeMap::new(),
            exceptions: BTreeMap::new(),
            noncompliance_flags: BTreeMap::new(),
            revocations: BTreeMap::new(),
            decisions: BTreeMap::new(),
        };
        state.seed_devnet_deadlines()?;
        state.seed_devnet_subjects()?;
        state.seed_devnet_receipts()?;
        state.seed_devnet_exceptions()?;
        state.seed_devnet_enforcement()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn update_height(&mut self, height: u64) {
        self.set_height(height);
    }

    pub fn current_epoch(&self) -> u64 {
        self.height / self.config.epoch_blocks
    }

    pub fn validate(&self) -> PqCryptoMigrationEnforcementResult<()> {
        self.config.validate()?;
        for deadline in self.deadlines.values() {
            deadline.validate()?;
        }
        for subject in self.subjects.values() {
            subject.validate()?;
            if !self.deadlines.contains_key(&subject.required_deadline_id) {
                return Err("subject references unknown deadline".to_string());
            }
            if let Some(exception_id) = &subject.exception_id {
                if !self.exceptions.contains_key(exception_id) {
                    return Err("subject references unknown exception".to_string());
                }
            }
            if let Some(flag_id) = &subject.noncompliance_flag_id {
                if !self.noncompliance_flags.contains_key(flag_id) {
                    return Err("subject references unknown noncompliance flag".to_string());
                }
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate(&self.config)?;
            if !self.subjects.contains_key(&receipt.subject_id) {
                return Err("receipt references unknown subject".to_string());
            }
        }
        for exception in self.exceptions.values() {
            exception.validate()?;
            if !self.subjects.contains_key(&exception.subject_id) {
                return Err("exception references unknown subject".to_string());
            }
        }
        for flag in self.noncompliance_flags.values() {
            flag.validate()?;
            if !self.subjects.contains_key(&flag.subject_id) {
                return Err("flag references unknown subject".to_string());
            }
        }
        let mut nullifiers = BTreeSet::new();
        for revocation in self.revocations.values() {
            revocation.validate()?;
            if !self.subjects.contains_key(&revocation.subject_id) {
                return Err("revocation references unknown subject".to_string());
            }
            if !self.receipts.contains_key(&revocation.receipt_id) {
                return Err("revocation references unknown receipt".to_string());
            }
            if !nullifiers.insert(revocation.nullifier.clone()) {
                return Err("duplicate revocation nullifier".to_string());
            }
        }
        for decision in self.decisions.values() {
            decision.validate()?;
            if !self.subjects.contains_key(&decision.subject_id) {
                return Err("decision references unknown subject".to_string());
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let deadline_records = self
            .deadlines
            .values()
            .map(DeadlineEpoch::public_record)
            .collect::<Vec<_>>();
        let subject_records = self
            .subjects
            .values()
            .map(MigrationSubject::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(HybridCredentialReceipt::public_record)
            .collect::<Vec<_>>();
        let exception_records = self
            .exceptions
            .values()
            .map(ExceptionWindow::public_record)
            .collect::<Vec<_>>();
        let flag_records = self
            .noncompliance_flags
            .values()
            .map(NoncomplianceFlag::public_record)
            .collect::<Vec<_>>();
        let revocation_records = self
            .revocations
            .values()
            .map(RevocationRecord::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .revocations
            .values()
            .map(|revocation| json!({"nullifier": revocation.nullifier}))
            .collect::<Vec<_>>();
        let decision_records = self
            .decisions
            .values()
            .map(EnforcementDecision::public_record)
            .collect::<Vec<_>>();
        Roots {
            config_root: domain_hash(
                "PQ-CRYPTO-MIGRATION-ENFORCEMENT-CONFIG",
                &[HashPart::Json(&config_record)],
                32,
            ),
            deadline_root: merkle_root("PQ-CRYPTO-MIGRATION-DEADLINES", &deadline_records),
            subject_root: merkle_root("PQ-CRYPTO-MIGRATION-SUBJECTS", &subject_records),
            receipt_root: merkle_root("PQ-CRYPTO-MIGRATION-HYBRID-RECEIPTS", &receipt_records),
            exception_root: merkle_root("PQ-CRYPTO-MIGRATION-EXCEPTIONS", &exception_records),
            noncompliance_root: merkle_root("PQ-CRYPTO-MIGRATION-FLAGS", &flag_records),
            revocation_root: merkle_root("PQ-CRYPTO-MIGRATION-REVOCATIONS", &revocation_records),
            nullifier_root: merkle_root("PQ-CRYPTO-MIGRATION-NULLIFIERS", &nullifier_records),
            decision_root: merkle_root("PQ-CRYPTO-MIGRATION-DECISIONS", &decision_records),
        }
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            deadlines: self.deadlines.len() as u64,
            subjects: self.subjects.len() as u64,
            hybrid_receipts: self.receipts.len() as u64,
            noncompliance_flags: self.noncompliance_flags.len() as u64,
            revocations: self.revocations.len() as u64,
            decisions: self.decisions.len() as u64,
            ..Counters::default()
        };
        let current_epoch = self.current_epoch();
        for subject in self.subjects.values() {
            match subject.status {
                ComplianceStatus::HybridCompliant | ComplianceStatus::PqCompliant => {
                    counters.compliant_subjects += 1;
                }
                ComplianceStatus::ExceptionActive => counters.exception_subjects += 1,
                ComplianceStatus::Noncompliant => counters.noncompliant_subjects += 1,
                _ => {}
            }
            if subject.status.is_blocking() {
                counters.blocking_subjects += 1;
            }
            match subject.domain {
                EnforcementDomain::Accounts => counters.account_subjects += 1,
                EnforcementDomain::Sequencers => counters.sequencer_subjects += 1,
                EnforcementDomain::BridgeCommittees => counters.bridge_committee_subjects += 1,
                EnforcementDomain::ProverMarkets => counters.prover_market_subjects += 1,
                EnforcementDomain::Wallets => counters.wallet_subjects += 1,
                EnforcementDomain::ContractAuth => counters.contract_auth_subjects += 1,
                EnforcementDomain::OperatorKeys => counters.operator_key_subjects += 1,
            }
        }
        counters.active_exceptions = self
            .exceptions
            .values()
            .filter(|exception| exception.active_at_epoch(current_epoch))
            .count() as u64;
        counters
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "current_epoch": self.current_epoch(),
            "config": self.config.public_record(),
            "deadlines": self.deadlines.values().map(DeadlineEpoch::public_record).collect::<Vec<_>>(),
            "subjects": self.subjects.values().map(MigrationSubject::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(HybridCredentialReceipt::public_record).collect::<Vec<_>>(),
            "exceptions": self.exceptions.values().map(ExceptionWindow::public_record).collect::<Vec<_>>(),
            "noncompliance_flags": self.noncompliance_flags.values().map(NoncomplianceFlag::public_record).collect::<Vec<_>>(),
            "revocations": self.revocations.values().map(RevocationRecord::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(EnforcementDecision::public_record).collect::<Vec<_>>(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn seed_devnet_deadlines(&mut self) -> PqCryptoMigrationEnforcementResult<()> {
        let entries = [
            (
                EnforcementDomain::Accounts,
                EnforcementAction::RequireHybridReceipt,
                "account-pq-migration-policy",
            ),
            (
                EnforcementDomain::Sequencers,
                EnforcementAction::DisableLegacySigning,
                "sequencer-pq-migration-policy",
            ),
            (
                EnforcementDomain::BridgeCommittees,
                EnforcementAction::QuarantineKey,
                "bridge-committee-pq-migration-policy",
            ),
            (
                EnforcementDomain::ProverMarkets,
                EnforcementAction::Warn,
                "prover-market-pq-migration-policy",
            ),
            (
                EnforcementDomain::Wallets,
                EnforcementAction::RequireHybridReceipt,
                "wallet-pq-migration-policy",
            ),
            (
                EnforcementDomain::ContractAuth,
                EnforcementAction::DisableLegacySigning,
                "contract-auth-pq-migration-policy",
            ),
            (
                EnforcementDomain::OperatorKeys,
                EnforcementAction::SlashOperatorBond,
                "operator-key-pq-migration-policy",
            ),
        ];
        for (index, (domain, action, policy_label)) in entries.iter().enumerate() {
            let offset = index as u64;
            let policy_root = leaf_hash("PQ-CRYPTO-MIGRATION-POLICY", policy_label);
            let deadline = DeadlineEpoch::new(
                *domain,
                MigrationStage::HybridRequired,
                1 + offset,
                4 + offset,
                8 + offset,
                10 + offset,
                *action,
                &policy_root,
            );
            deadline.validate()?;
            self.deadlines
                .insert(deadline.deadline_id.clone(), deadline);
        }
        Ok(())
    }

    fn seed_devnet_subjects(&mut self) -> PqCryptoMigrationEnforcementResult<()> {
        let domains = [
            EnforcementDomain::Accounts,
            EnforcementDomain::Sequencers,
            EnforcementDomain::BridgeCommittees,
            EnforcementDomain::ProverMarkets,
            EnforcementDomain::Wallets,
            EnforcementDomain::ContractAuth,
            EnforcementDomain::OperatorKeys,
        ];
        for (index, domain) in domains.iter().enumerate() {
            let deadline_id = self
                .deadlines
                .values()
                .find(|deadline| deadline.domain == *domain)
                .map(|deadline| deadline.deadline_id.clone())
                .ok_or_else(|| "missing devnet deadline".to_string())?;
            let owner = leaf_hash(
                "PQ-CRYPTO-MIGRATION-OWNER",
                &format!("{}-owner", domain.as_str()),
            );
            let credential = leaf_hash(
                "PQ-CRYPTO-MIGRATION-CREDENTIAL",
                &format!("{}-legacy-root", domain.as_str()),
            );
            let mut subject = MigrationSubject::new(
                *domain,
                &owner,
                &credential,
                &deadline_id,
                1 + index as u64,
                self.height,
            );
            subject.status = if domain.requires_continuity() {
                ComplianceStatus::HybridCompliant
            } else {
                ComplianceStatus::Scheduled
            };
            subject.validate()?;
            self.subjects.insert(subject.subject_id.clone(), subject);
        }
        Ok(())
    }

    fn seed_devnet_receipts(&mut self) -> PqCryptoMigrationEnforcementResult<()> {
        let subject_ids = self.subjects.keys().cloned().collect::<Vec<_>>();
        for (index, subject_id) in subject_ids.iter().enumerate() {
            let classic = leaf_hash(
                "PQ-CRYPTO-MIGRATION-CLASSIC-KEY",
                &format!("devnet-classic-key-{index}"),
            );
            let pq = leaf_hash(
                "PQ-CRYPTO-MIGRATION-PQ-KEY",
                &format!("devnet-pq-key-{index}"),
            );
            let attester = leaf_hash(
                "PQ-CRYPTO-MIGRATION-ATTESTER",
                &format!("devnet-attester-{index}"),
            );
            let proof = leaf_hash(
                "PQ-CRYPTO-MIGRATION-PROOF",
                &format!("devnet-proof-{index}"),
            );
            let receipt = HybridCredentialReceipt::new(
                subject_id,
                if index % 2 == 0 {
                    CredentialKind::Hybrid
                } else {
                    CredentialKind::PqOnly
                },
                &classic,
                &pq,
                if index % 2 == 0 {
                    "ml_dsa_65_with_ed25519_bridge"
                } else {
                    "ml_dsa_87"
                },
                if index % 2 == 0 { 192 } else { 256 },
                2,
                18,
                &attester,
                &proof,
            );
            receipt.validate(&self.config)?;
            if let Some(subject) = self.subjects.get_mut(subject_id) {
                subject.status = ComplianceStatus::HybridCompliant;
                subject.current_credential_root = receipt.pq_key_commitment.clone();
            }
            self.receipts.insert(receipt.receipt_id.clone(), receipt);
        }
        Ok(())
    }

    fn seed_devnet_exceptions(&mut self) -> PqCryptoMigrationEnforcementResult<()> {
        let wallet_subject = self
            .subjects
            .values()
            .find(|subject| subject.domain == EnforcementDomain::Wallets)
            .map(|subject| subject.subject_id.clone())
            .ok_or_else(|| "missing devnet wallet subject".to_string())?;
        let approval = leaf_hash("PQ-CRYPTO-MIGRATION-EXCEPTION-APPROVAL", "wallet-recovery");
        let disclosure = leaf_hash(
            "PQ-CRYPTO-MIGRATION-EXCEPTION-DISCLOSURE",
            "recovery-guarded-legacy-use",
        );
        let exception = ExceptionWindow::new(
            &wallet_subject,
            ExceptionReason::SocialRecovery,
            3,
            5,
            2,
            &approval,
            &disclosure,
        );
        exception.validate()?;
        if let Some(subject) = self.subjects.get_mut(&wallet_subject) {
            subject.status = ComplianceStatus::ExceptionActive;
            subject.exception_id = Some(exception.exception_id.clone());
        }
        self.exceptions
            .insert(exception.exception_id.clone(), exception);
        Ok(())
    }

    fn seed_devnet_enforcement(&mut self) -> PqCryptoMigrationEnforcementResult<()> {
        let operator_subject = self
            .subjects
            .values()
            .find(|subject| subject.domain == EnforcementDomain::OperatorKeys)
            .map(|subject| subject.subject_id.clone())
            .ok_or_else(|| "missing devnet operator subject".to_string())?;
        let evidence = leaf_hash(
            "PQ-CRYPTO-MIGRATION-NONCOMPLIANCE-EVIDENCE",
            "operator-late-rotation",
        );
        let flag = NoncomplianceFlag::new(
            &operator_subject,
            EnforcementDomain::OperatorKeys,
            0,
            0,
            "operator key must publish hybrid receipt before pq required epoch",
            EnforcementAction::SlashOperatorBond,
            &evidence,
        );
        flag.validate()?;
        if let Some(subject) = self.subjects.get_mut(&operator_subject) {
            subject.status = ComplianceStatus::Noncompliant;
            subject.noncompliance_flag_id = Some(flag.flag_id.clone());
        }
        let input_root = leaf_hash("PQ-CRYPTO-MIGRATION-DECISION-INPUT", &flag.flag_id);
        let output_root = leaf_hash("PQ-CRYPTO-MIGRATION-DECISION-OUTPUT", "bond-warning");
        let decision = EnforcementDecision::new(
            &operator_subject,
            EnforcementDomain::OperatorKeys,
            MigrationStage::HybridRequired,
            ComplianceStatus::Noncompliant,
            EnforcementAction::SlashOperatorBond,
            0,
            0,
            &input_root,
            &output_root,
        );
        decision.validate()?;
        let receipt = self
            .receipts
            .values()
            .find(|receipt| receipt.subject_id == operator_subject)
            .cloned()
            .ok_or_else(|| "missing devnet operator receipt".to_string())?;
        let revocation = RevocationRecord::new(
            &operator_subject,
            &receipt.receipt_id,
            &receipt.nullifier,
            &leaf_hash("PQ-CRYPTO-MIGRATION-REVOCATION-REASON", "operator-evidence"),
            0,
            0,
            &leaf_hash("PQ-CRYPTO-MIGRATION-REVOCATION-AUTHORITY", "devnet-council"),
        );
        revocation.validate()?;
        self.noncompliance_flags.insert(flag.flag_id.clone(), flag);
        self.decisions
            .insert(decision.decision_id.clone(), decision);
        self.revocations
            .insert(revocation.revocation_id.clone(), revocation);
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-CRYPTO-MIGRATION-ENFORCEMENT-STATE",
        &[
            HashPart::Str(PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PqCryptoMigrationEnforcementResult<State> {
    State::devnet()
}

fn typed_hash(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

fn leaf_hash(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_CRYPTO_MIGRATION_ENFORCEMENT_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}
