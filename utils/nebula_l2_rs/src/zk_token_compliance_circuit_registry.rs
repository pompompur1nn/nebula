use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkTokenComplianceCircuitRegistryResult<T> = Result<T, String>;

pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION: &str =
    "nebula-l2-zk-token-compliance-circuit-registry-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_SCHEMA_VERSION: u64 = 1;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEVNET_HEIGHT: u64 = 3_264;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_VERIFIER_SCHEME: &str =
    "pq-zk-token-compliance-verifier-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DISCLOSURE_SCHEME: &str =
    "selective-disclosure-commitment-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_UPGRADE_SCHEME: &str =
    "pq-governed-circuit-upgrade-slot-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_AUDIT_SCHEME: &str =
    "private-token-compliance-circuit-audit-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_CACHE_HINT_SCHEME: &str =
    "low-fee-proof-cache-hint-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_RECEIPT_SCHEME: &str =
    "token-compliance-verifier-receipt-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_REVOCATION_SCHEME: &str =
    "revocation-nullifier-set-v1";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_NAMESPACE: &str =
    "nebula.devnet.zk_token_compliance";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_CACHE_TTL_BLOCKS: u64 = 96;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 20_160;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_UPGRADE_TIMELOCK_BLOCKS: u64 = 720;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_MAX_BATCH_PROOFS: u64 = 512;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_TARGET_FEE_MICRO_XMR: u64 = 700;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_BPS: u64 = 10_000;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_CIRCUITS: usize = 512;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_DISCLOSURES: usize = 1_024;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_UPGRADE_SLOTS: usize = 128;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_AUDITS: usize = 1_024;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_CACHE_HINTS: usize = 2_048;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_RECEIPTS: usize = 4_096;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_SETS: usize = 256;
pub const ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_EVENTS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenRuleCircuitKind {
    TransferPolicy,
    MintAuthorization,
    BurnAuthorization,
    ShieldedKycGate,
    SanctionsScreen,
    JurisdictionFence,
    AccreditedInvestor,
    VelocityLimit,
    BalanceLimit,
    SupplyCap,
    DexListing,
    VaultShare,
    BridgeMintBurn,
    GovernanceVote,
    RoyaltyDistribution,
    PaymasterSpend,
    Custom,
}

impl TokenRuleCircuitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferPolicy => "transfer_policy",
            Self::MintAuthorization => "mint_authorization",
            Self::BurnAuthorization => "burn_authorization",
            Self::ShieldedKycGate => "shielded_kyc_gate",
            Self::SanctionsScreen => "sanctions_screen",
            Self::JurisdictionFence => "jurisdiction_fence",
            Self::AccreditedInvestor => "accredited_investor",
            Self::VelocityLimit => "velocity_limit",
            Self::BalanceLimit => "balance_limit",
            Self::SupplyCap => "supply_cap",
            Self::DexListing => "dex_listing",
            Self::VaultShare => "vault_share",
            Self::BridgeMintBurn => "bridge_mint_burn",
            Self::GovernanceVote => "governance_vote",
            Self::RoyaltyDistribution => "royalty_distribution",
            Self::PaymasterSpend => "paymaster_spend",
            Self::Custom => "custom",
        }
    }

    pub fn requires_revocation_set(self) -> bool {
        matches!(
            self,
            Self::ShieldedKycGate
                | Self::SanctionsScreen
                | Self::JurisdictionFence
                | Self::AccreditedInvestor
                | Self::PaymasterSpend
        )
    }

    pub fn touches_supply(self) -> bool {
        matches!(
            self,
            Self::MintAuthorization
                | Self::BurnAuthorization
                | Self::SupplyCap
                | Self::BridgeMintBurn
                | Self::VaultShare
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCircuitStatus {
    Draft,
    Auditing,
    Active,
    Paused,
    Deprecated,
    Frozen,
    EmergencyDisabled,
}

impl ComplianceCircuitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Auditing => "auditing",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deprecated => "deprecated",
            Self::Frozen => "frozen",
            Self::EmergencyDisabled => "emergency_disabled",
        }
    }

    pub fn accepts_proofs(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Frozen | Self::EmergencyDisabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureFieldKind {
    Jurisdiction,
    CredentialIssuer,
    CredentialClass,
    InvestorStatus,
    SanctionsEpoch,
    BalanceBucket,
    TransferLimitBucket,
    AssetClass,
    ExpiryWindow,
    AuditScope,
    Custom,
}

impl DisclosureFieldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jurisdiction => "jurisdiction",
            Self::CredentialIssuer => "credential_issuer",
            Self::CredentialClass => "credential_class",
            Self::InvestorStatus => "investor_status",
            Self::SanctionsEpoch => "sanctions_epoch",
            Self::BalanceBucket => "balance_bucket",
            Self::TransferLimitBucket => "transfer_limit_bucket",
            Self::AssetClass => "asset_class",
            Self::ExpiryWindow => "expiry_window",
            Self::AuditScope => "audit_scope",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeSlotStatus {
    Open,
    Committed,
    Timelocked,
    Ready,
    Executed,
    Cancelled,
    Vetoed,
}

impl UpgradeSlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Committed => "committed",
            Self::Timelocked => "timelocked",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Vetoed => "vetoed",
        }
    }

    pub fn is_pending(self) -> bool {
        matches!(self, Self::Committed | Self::Timelocked | Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditVerdict {
    Pending,
    Passed,
    PassedWithNotes,
    Failed,
    Expired,
    Revoked,
}

impl AuditVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::PassedWithNotes => "passed_with_notes",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::Passed | Self::PassedWithNotes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCacheHintKind {
    WarmVerifierKey,
    BatchSameCircuit,
    ReusePublicInputs,
    AggregateByAsset,
    AggregateByIssuer,
    FeeSponsored,
    LowLatencyLane,
    ArchiveOnly,
}

impl ProofCacheHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WarmVerifierKey => "warm_verifier_key",
            Self::BatchSameCircuit => "batch_same_circuit",
            Self::ReusePublicInputs => "reuse_public_inputs",
            Self::AggregateByAsset => "aggregate_by_asset",
            Self::AggregateByIssuer => "aggregate_by_issuer",
            Self::FeeSponsored => "fee_sponsored",
            Self::LowLatencyLane => "low_latency_lane",
            Self::ArchiveOnly => "archive_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Rejected,
    Deferred,
    Cached,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
            Self::Cached => "cached",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSetKind {
    Credential,
    Nullifier,
    Issuer,
    Circuit,
    Asset,
    Jurisdiction,
    Emergency,
}

impl RevocationSetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Nullifier => "nullifier",
            Self::Issuer => "issuer",
            Self::Circuit => "circuit",
            Self::Asset => "asset",
            Self::Jurisdiction => "jurisdiction",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub namespace: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub verifier_scheme: String,
    pub disclosure_scheme: String,
    pub upgrade_scheme: String,
    pub audit_scheme: String,
    pub cache_hint_scheme: String,
    pub receipt_scheme: String,
    pub revocation_scheme: String,
    pub default_cache_ttl_blocks: u64,
    pub default_audit_ttl_blocks: u64,
    pub default_upgrade_timelock_blocks: u64,
    pub default_disclosure_ttl_blocks: u64,
    pub max_batch_proofs: u64,
    pub target_fee_micro_xmr: u64,
    pub require_pq_governance: bool,
    pub require_active_audit: bool,
    pub require_revocation_checks: bool,
    pub allow_emergency_disable: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION.to_string(),
            schema_version: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_SCHEMA_VERSION,
            namespace: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_NAMESPACE.to_string(),
            fee_asset_id: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_HASH_SUITE.to_string(),
            pq_suite: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PQ_SUITE.to_string(),
            verifier_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_VERIFIER_SCHEME.to_string(),
            disclosure_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DISCLOSURE_SCHEME.to_string(),
            upgrade_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_UPGRADE_SCHEME.to_string(),
            audit_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_AUDIT_SCHEME.to_string(),
            cache_hint_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_CACHE_HINT_SCHEME.to_string(),
            receipt_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_RECEIPT_SCHEME.to_string(),
            revocation_scheme: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_REVOCATION_SCHEME.to_string(),
            default_cache_ttl_blocks: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_CACHE_TTL_BLOCKS,
            default_audit_ttl_blocks: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_AUDIT_TTL_BLOCKS,
            default_upgrade_timelock_blocks:
                ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_UPGRADE_TIMELOCK_BLOCKS,
            default_disclosure_ttl_blocks:
                ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            max_batch_proofs: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_MAX_BATCH_PROOFS,
            target_fee_micro_xmr: ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEFAULT_TARGET_FEE_MICRO_XMR,
            require_pq_governance: true,
            require_active_audit: true,
            require_revocation_checks: true,
            allow_emergency_disable: true,
        }
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "config chain_id")?;
        ensure_eq(
            &self.protocol_version,
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "protocol version",
        )?;
        ensure_nonzero(self.schema_version, "schema version")?;
        ensure_nonempty(&self.namespace, "namespace")?;
        ensure_nonempty(&self.fee_asset_id, "fee asset id")?;
        ensure_nonempty(&self.hash_suite, "hash suite")?;
        ensure_nonempty(&self.pq_suite, "pq suite")?;
        ensure_nonempty(&self.verifier_scheme, "verifier scheme")?;
        ensure_nonempty(&self.disclosure_scheme, "disclosure scheme")?;
        ensure_nonempty(&self.upgrade_scheme, "upgrade scheme")?;
        ensure_nonempty(&self.audit_scheme, "audit scheme")?;
        ensure_nonempty(&self.cache_hint_scheme, "cache hint scheme")?;
        ensure_nonempty(&self.receipt_scheme, "receipt scheme")?;
        ensure_nonempty(&self.revocation_scheme, "revocation scheme")?;
        ensure_nonzero(self.default_cache_ttl_blocks, "cache ttl")?;
        ensure_nonzero(self.default_audit_ttl_blocks, "audit ttl")?;
        ensure_nonzero(self.default_upgrade_timelock_blocks, "upgrade timelock")?;
        ensure_nonzero(self.default_disclosure_ttl_blocks, "disclosure ttl")?;
        ensure_nonzero(self.max_batch_proofs, "max batch proofs")?;
        ensure_nonzero(self.target_fee_micro_xmr, "target fee")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_token_compliance_circuit_registry_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "namespace": self.namespace,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "verifier_scheme": self.verifier_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "upgrade_scheme": self.upgrade_scheme,
            "audit_scheme": self.audit_scheme,
            "cache_hint_scheme": self.cache_hint_scheme,
            "receipt_scheme": self.receipt_scheme,
            "revocation_scheme": self.revocation_scheme,
            "default_cache_ttl_blocks": self.default_cache_ttl_blocks,
            "default_audit_ttl_blocks": self.default_audit_ttl_blocks,
            "default_upgrade_timelock_blocks": self.default_upgrade_timelock_blocks,
            "default_disclosure_ttl_blocks": self.default_disclosure_ttl_blocks,
            "max_batch_proofs": self.max_batch_proofs,
            "target_fee_micro_xmr": self.target_fee_micro_xmr,
            "require_pq_governance": self.require_pq_governance,
            "require_active_audit": self.require_active_audit,
            "require_revocation_checks": self.require_revocation_checks,
            "allow_emergency_disable": self.allow_emergency_disable,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRuleCircuit {
    pub circuit_id: String,
    pub token_class_id: String,
    pub issuer_commitment: String,
    pub rule_kind: TokenRuleCircuitKind,
    pub status: ComplianceCircuitStatus,
    pub verifier_key_root: String,
    pub constraint_system_root: String,
    pub public_input_schema_root: String,
    pub private_witness_schema_root: String,
    pub disclosure_policy_root: String,
    pub revocation_set_root: String,
    pub nullifier_namespace_root: String,
    pub audit_policy_root: String,
    pub low_fee_lane: String,
    pub max_proof_weight: u64,
    pub target_verify_micros: u64,
    pub min_security_bits: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub circuit_nonce: u64,
    pub tags: BTreeSet<String>,
}

impl TokenRuleCircuit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        token_class_id: &str,
        issuer_commitment: &str,
        rule_kind: TokenRuleCircuitKind,
        verifier_key_root: &str,
        disclosure_policy_root: &str,
        revocation_set_root: &str,
        activated_at_height: u64,
        circuit_nonce: u64,
    ) -> Self {
        let constraint_system_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-CONSTRAINT-SYSTEM",
            label,
            rule_kind.as_str(),
        );
        let public_input_schema_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-PUBLIC-INPUT-SCHEMA",
            label,
            token_class_id,
        );
        let private_witness_schema_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-PRIVATE-WITNESS-SCHEMA",
            label,
            issuer_commitment,
        );
        let nullifier_namespace_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-NULLIFIER-NAMESPACE",
            token_class_id,
            rule_kind.as_str(),
        );
        let audit_policy_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-AUDIT-POLICY",
            label,
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_AUDIT_SCHEME,
        );
        let low_fee_lane = format!("{}_{}", "token_compliance", rule_kind.as_str());
        let circuit_id = circuit_id(
            label,
            token_class_id,
            issuer_commitment,
            rule_kind,
            verifier_key_root,
            circuit_nonce,
        );
        Self {
            circuit_id,
            token_class_id: token_class_id.to_string(),
            issuer_commitment: issuer_commitment.to_string(),
            rule_kind,
            status: ComplianceCircuitStatus::Active,
            verifier_key_root: verifier_key_root.to_string(),
            constraint_system_root,
            public_input_schema_root,
            private_witness_schema_root,
            disclosure_policy_root: disclosure_policy_root.to_string(),
            revocation_set_root: revocation_set_root.to_string(),
            nullifier_namespace_root,
            audit_policy_root,
            low_fee_lane,
            max_proof_weight: 48_000,
            target_verify_micros: 850,
            min_security_bits: 192,
            activated_at_height,
            expires_at_height: activated_at_height.saturating_add(250_000),
            circuit_nonce,
            tags: BTreeSet::new(),
        }
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        if !tag.is_empty() {
            self.tags.insert(tag.to_string());
        }
        self
    }

    pub fn accepts_at_height(&self, height: u64) -> bool {
        self.status.accepts_proofs()
            && self.activated_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.circuit_id, "circuit id")?;
        ensure_nonempty(&self.token_class_id, "token class id")?;
        ensure_nonempty(&self.issuer_commitment, "issuer commitment")?;
        ensure_nonempty(&self.verifier_key_root, "verifier key root")?;
        ensure_nonempty(&self.constraint_system_root, "constraint system root")?;
        ensure_nonempty(&self.public_input_schema_root, "public input schema root")?;
        ensure_nonempty(
            &self.private_witness_schema_root,
            "private witness schema root",
        )?;
        ensure_nonempty(&self.disclosure_policy_root, "disclosure policy root")?;
        ensure_nonempty(&self.revocation_set_root, "revocation set root")?;
        ensure_nonempty(&self.nullifier_namespace_root, "nullifier namespace root")?;
        ensure_nonempty(&self.audit_policy_root, "audit policy root")?;
        ensure_nonempty(&self.low_fee_lane, "low fee lane")?;
        ensure_nonzero(self.max_proof_weight, "max proof weight")?;
        ensure_nonzero(self.target_verify_micros, "target verify micros")?;
        ensure_nonzero(self.min_security_bits, "min security bits")?;
        ensure_order(
            self.activated_at_height,
            self.expires_at_height,
            "circuit activation window",
        )?;
        if self.rule_kind.requires_revocation_set() && is_empty_root(&self.revocation_set_root) {
            return Err(format!(
                "rule kind {} requires a populated revocation set root",
                self.rule_kind.as_str()
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_token_rule_circuit",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "circuit_id": self.circuit_id,
            "token_class_id": self.token_class_id,
            "issuer_commitment": self.issuer_commitment,
            "rule_kind": self.rule_kind.as_str(),
            "status": self.status.as_str(),
            "verifier_key_root": self.verifier_key_root,
            "constraint_system_root": self.constraint_system_root,
            "public_input_schema_root": self.public_input_schema_root,
            "private_witness_schema_root": self.private_witness_schema_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "revocation_set_root": self.revocation_set_root,
            "nullifier_namespace_root": self.nullifier_namespace_root,
            "audit_policy_root": self.audit_policy_root,
            "low_fee_lane": self.low_fee_lane,
            "max_proof_weight": self.max_proof_weight,
            "target_verify_micros": self.target_verify_micros,
            "min_security_bits": self.min_security_bits,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "circuit_nonce": self.circuit_nonce,
            "tags": self.tags.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureCommitment {
    pub disclosure_id: String,
    pub subject_commitment: String,
    pub token_class_id: String,
    pub circuit_id: String,
    pub field_kind: DisclosureFieldKind,
    pub field_commitment_root: String,
    pub salted_value_root: String,
    pub auditor_set_root: String,
    pub viewer_policy_root: String,
    pub encrypted_hint_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub disclosure_nonce: u64,
}

impl SelectiveDisclosureCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        subject_commitment: &str,
        token_class_id: &str,
        circuit_id: &str,
        field_kind: DisclosureFieldKind,
        auditor_set_root: &str,
        valid_from_height: u64,
        ttl_blocks: u64,
        disclosure_nonce: u64,
    ) -> Self {
        let field_commitment_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-DISCLOSURE-FIELD",
            label,
            field_kind.as_str(),
        );
        let salted_value_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-DISCLOSURE-SALTED-VALUE",
            subject_commitment,
            label,
        );
        let viewer_policy_root =
            labeled_root("ZK-TOKEN-COMPLIANCE-VIEWER-POLICY", label, auditor_set_root);
        let encrypted_hint_root =
            labeled_root("ZK-TOKEN-COMPLIANCE-ENCRYPTED-HINT", label, circuit_id);
        let valid_until_height = valid_from_height.saturating_add(ttl_blocks);
        let disclosure_id = disclosure_id(
            subject_commitment,
            token_class_id,
            circuit_id,
            field_kind,
            &salted_value_root,
            disclosure_nonce,
        );
        Self {
            disclosure_id,
            subject_commitment: subject_commitment.to_string(),
            token_class_id: token_class_id.to_string(),
            circuit_id: circuit_id.to_string(),
            field_kind,
            field_commitment_root,
            salted_value_root,
            auditor_set_root: auditor_set_root.to_string(),
            viewer_policy_root,
            encrypted_hint_root,
            valid_from_height,
            valid_until_height,
            disclosure_nonce,
        }
    }

    pub fn is_active(&self, height: u64) -> bool {
        self.valid_from_height <= height && height <= self.valid_until_height
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.disclosure_id, "disclosure id")?;
        ensure_nonempty(&self.subject_commitment, "subject commitment")?;
        ensure_nonempty(&self.token_class_id, "token class id")?;
        ensure_nonempty(&self.circuit_id, "circuit id")?;
        ensure_nonempty(&self.field_commitment_root, "field commitment root")?;
        ensure_nonempty(&self.salted_value_root, "salted value root")?;
        ensure_nonempty(&self.auditor_set_root, "auditor set root")?;
        ensure_nonempty(&self.viewer_policy_root, "viewer policy root")?;
        ensure_nonempty(&self.encrypted_hint_root, "encrypted hint root")?;
        ensure_order(
            self.valid_from_height,
            self.valid_until_height,
            "disclosure validity window",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "subject_commitment": self.subject_commitment,
            "token_class_id": self.token_class_id,
            "circuit_id": self.circuit_id,
            "field_kind": self.field_kind.as_str(),
            "field_commitment_root": self.field_commitment_root,
            "salted_value_root": self.salted_value_root,
            "auditor_set_root": self.auditor_set_root,
            "viewer_policy_root": self.viewer_policy_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "disclosure_nonce": self.disclosure_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGovernedUpgradeSlot {
    pub slot_id: String,
    pub circuit_id: String,
    pub status: UpgradeSlotStatus,
    pub current_verifier_key_root: String,
    pub proposed_verifier_key_root: String,
    pub migration_circuit_root: String,
    pub governance_committee_root: String,
    pub pq_signature_aggregate_root: String,
    pub veto_commitment_root: String,
    pub opened_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub upgrade_nonce: u64,
}

impl PqGovernedUpgradeSlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        circuit_id: &str,
        current_verifier_key_root: &str,
        proposed_verifier_key_root: &str,
        governance_committee_root: &str,
        opened_at_height: u64,
        timelock_blocks: u64,
        upgrade_nonce: u64,
    ) -> Self {
        let migration_circuit_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-MIGRATION-CIRCUIT",
            circuit_id,
            proposed_verifier_key_root,
        );
        let pq_signature_aggregate_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-PQ-UPGRADE-SIGNATURE",
            label,
            circuit_id,
        );
        let veto_commitment_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-UPGRADE-VETO",
            label,
            governance_committee_root,
        );
        let executable_at_height = opened_at_height.saturating_add(timelock_blocks);
        let expires_at_height = executable_at_height.saturating_add(timelock_blocks);
        let slot_id = upgrade_slot_id(
            circuit_id,
            current_verifier_key_root,
            proposed_verifier_key_root,
            governance_committee_root,
            upgrade_nonce,
        );
        Self {
            slot_id,
            circuit_id: circuit_id.to_string(),
            status: UpgradeSlotStatus::Timelocked,
            current_verifier_key_root: current_verifier_key_root.to_string(),
            proposed_verifier_key_root: proposed_verifier_key_root.to_string(),
            migration_circuit_root,
            governance_committee_root: governance_committee_root.to_string(),
            pq_signature_aggregate_root,
            veto_commitment_root,
            opened_at_height,
            executable_at_height,
            expires_at_height,
            upgrade_nonce,
        }
    }

    pub fn ready_at_height(&self, height: u64) -> bool {
        self.status.is_pending()
            && self.executable_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.slot_id, "slot id")?;
        ensure_nonempty(&self.circuit_id, "circuit id")?;
        ensure_nonempty(&self.current_verifier_key_root, "current verifier key root")?;
        ensure_nonempty(
            &self.proposed_verifier_key_root,
            "proposed verifier key root",
        )?;
        ensure_nonempty(&self.migration_circuit_root, "migration circuit root")?;
        ensure_nonempty(&self.governance_committee_root, "governance committee root")?;
        ensure_nonempty(
            &self.pq_signature_aggregate_root,
            "pq signature aggregate root",
        )?;
        ensure_nonempty(&self.veto_commitment_root, "veto commitment root")?;
        ensure_order(
            self.opened_at_height,
            self.executable_at_height,
            "upgrade timelock",
        )?;
        ensure_order(
            self.executable_at_height,
            self.expires_at_height,
            "upgrade expiry",
        )?;
        if self.current_verifier_key_root == self.proposed_verifier_key_root {
            return Err("upgrade slot must change verifier key root".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_governed_upgrade_slot",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "slot_id": self.slot_id,
            "circuit_id": self.circuit_id,
            "status": self.status.as_str(),
            "current_verifier_key_root": self.current_verifier_key_root,
            "proposed_verifier_key_root": self.proposed_verifier_key_root,
            "migration_circuit_root": self.migration_circuit_root,
            "governance_committee_root": self.governance_committee_root,
            "pq_signature_aggregate_root": self.pq_signature_aggregate_root,
            "veto_commitment_root": self.veto_commitment_root,
            "opened_at_height": self.opened_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "upgrade_nonce": self.upgrade_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitAudit {
    pub audit_id: String,
    pub circuit_id: String,
    pub auditor_committee_root: String,
    pub transcript_root: String,
    pub coverage_root: String,
    pub finding_root: String,
    pub remediation_root: String,
    pub verdict: AuditVerdict,
    pub risk_score_bps: u64,
    pub audited_at_height: u64,
    pub expires_at_height: u64,
    pub audit_nonce: u64,
}

impl CircuitAudit {
    pub fn new(
        circuit_id: &str,
        auditor_committee_root: &str,
        verdict: AuditVerdict,
        risk_score_bps: u64,
        audited_at_height: u64,
        ttl_blocks: u64,
        audit_nonce: u64,
    ) -> Self {
        let transcript_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-AUDIT-TRANSCRIPT",
            circuit_id,
            auditor_committee_root,
        );
        let coverage_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-AUDIT-COVERAGE",
            circuit_id,
            verdict.as_str(),
        );
        let finding_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-AUDIT-FINDING",
            circuit_id,
            &risk_score_bps.to_string(),
        );
        let remediation_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-AUDIT-REMEDIATION",
            circuit_id,
            verdict.as_str(),
        );
        let expires_at_height = audited_at_height.saturating_add(ttl_blocks);
        let audit_id = audit_id(
            circuit_id,
            auditor_committee_root,
            &transcript_root,
            verdict,
            risk_score_bps,
            audit_nonce,
        );
        Self {
            audit_id,
            circuit_id: circuit_id.to_string(),
            auditor_committee_root: auditor_committee_root.to_string(),
            transcript_root,
            coverage_root,
            finding_root,
            remediation_root,
            verdict,
            risk_score_bps,
            audited_at_height,
            expires_at_height,
            audit_nonce,
        }
    }

    pub fn is_current(&self, height: u64) -> bool {
        self.verdict.is_acceptable()
            && self.audited_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.audit_id, "audit id")?;
        ensure_nonempty(&self.circuit_id, "circuit id")?;
        ensure_nonempty(&self.auditor_committee_root, "auditor committee root")?;
        ensure_nonempty(&self.transcript_root, "transcript root")?;
        ensure_nonempty(&self.coverage_root, "coverage root")?;
        ensure_nonempty(&self.finding_root, "finding root")?;
        ensure_nonempty(&self.remediation_root, "remediation root")?;
        ensure_bps(self.risk_score_bps, "risk score")?;
        ensure_order(
            self.audited_at_height,
            self.expires_at_height,
            "audit window",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "circuit_audit",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "audit_id": self.audit_id,
            "circuit_id": self.circuit_id,
            "auditor_committee_root": self.auditor_committee_root,
            "transcript_root": self.transcript_root,
            "coverage_root": self.coverage_root,
            "finding_root": self.finding_root,
            "remediation_root": self.remediation_root,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "audited_at_height": self.audited_at_height,
            "expires_at_height": self.expires_at_height,
            "audit_nonce": self.audit_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofCacheHint {
    pub hint_id: String,
    pub circuit_id: String,
    pub hint_kind: ProofCacheHintKind,
    pub cache_key_root: String,
    pub public_input_shape_root: String,
    pub fee_sponsor_commitment: String,
    pub expected_batch_size: u64,
    pub expected_fee_savings_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub hint_nonce: u64,
}

impl LowFeeProofCacheHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        circuit_id: &str,
        hint_kind: ProofCacheHintKind,
        fee_sponsor_commitment: &str,
        expected_batch_size: u64,
        expected_fee_savings_bps: u64,
        valid_from_height: u64,
        ttl_blocks: u64,
        hint_nonce: u64,
    ) -> Self {
        let cache_key_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-CACHE-KEY",
            circuit_id,
            hint_kind.as_str(),
        );
        let public_input_shape_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-CACHE-PUBLIC-INPUT",
            circuit_id,
            fee_sponsor_commitment,
        );
        let valid_until_height = valid_from_height.saturating_add(ttl_blocks);
        let hint_id = cache_hint_id(
            circuit_id,
            hint_kind,
            &cache_key_root,
            fee_sponsor_commitment,
            hint_nonce,
        );
        Self {
            hint_id,
            circuit_id: circuit_id.to_string(),
            hint_kind,
            cache_key_root,
            public_input_shape_root,
            fee_sponsor_commitment: fee_sponsor_commitment.to_string(),
            expected_batch_size,
            expected_fee_savings_bps,
            valid_from_height,
            valid_until_height,
            hint_nonce,
        }
    }

    pub fn is_usable(&self, height: u64) -> bool {
        self.valid_from_height <= height && height <= self.valid_until_height
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.hint_id, "hint id")?;
        ensure_nonempty(&self.circuit_id, "circuit id")?;
        ensure_nonempty(&self.cache_key_root, "cache key root")?;
        ensure_nonempty(&self.public_input_shape_root, "public input shape root")?;
        ensure_nonempty(&self.fee_sponsor_commitment, "fee sponsor commitment")?;
        ensure_nonzero(self.expected_batch_size, "expected batch size")?;
        ensure_bps(self.expected_fee_savings_bps, "expected fee savings")?;
        ensure_order(
            self.valid_from_height,
            self.valid_until_height,
            "cache hint window",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_cache_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "circuit_id": self.circuit_id,
            "hint_kind": self.hint_kind.as_str(),
            "cache_key_root": self.cache_key_root,
            "public_input_shape_root": self.public_input_shape_root,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "expected_batch_size": self.expected_batch_size,
            "expected_fee_savings_bps": self.expected_fee_savings_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "hint_nonce": self.hint_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierReceipt {
    pub receipt_id: String,
    pub circuit_id: String,
    pub proof_commitment: String,
    pub public_input_root: String,
    pub nullifier_root: String,
    pub disclosure_root: String,
    pub revocation_snapshot_root: String,
    pub verifier_node_commitment: String,
    pub status: ReceiptStatus,
    pub verified_at_height: u64,
    pub fee_charged_micro_xmr: u64,
    pub receipt_nonce: u64,
}

impl VerifierReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        circuit_id: &str,
        proof_commitment: &str,
        public_input_root: &str,
        nullifier_root: &str,
        disclosure_root: &str,
        revocation_snapshot_root: &str,
        verifier_node_commitment: &str,
        status: ReceiptStatus,
        verified_at_height: u64,
        fee_charged_micro_xmr: u64,
        receipt_nonce: u64,
    ) -> Self {
        let receipt_id = verifier_receipt_id(
            circuit_id,
            proof_commitment,
            public_input_root,
            nullifier_root,
            status,
            receipt_nonce,
        );
        Self {
            receipt_id,
            circuit_id: circuit_id.to_string(),
            proof_commitment: proof_commitment.to_string(),
            public_input_root: public_input_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            disclosure_root: disclosure_root.to_string(),
            revocation_snapshot_root: revocation_snapshot_root.to_string(),
            verifier_node_commitment: verifier_node_commitment.to_string(),
            status,
            verified_at_height,
            fee_charged_micro_xmr,
            receipt_nonce,
        }
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.receipt_id, "receipt id")?;
        ensure_nonempty(&self.circuit_id, "circuit id")?;
        ensure_nonempty(&self.proof_commitment, "proof commitment")?;
        ensure_nonempty(&self.public_input_root, "public input root")?;
        ensure_nonempty(&self.nullifier_root, "nullifier root")?;
        ensure_nonempty(&self.disclosure_root, "disclosure root")?;
        ensure_nonempty(&self.revocation_snapshot_root, "revocation snapshot root")?;
        ensure_nonempty(&self.verifier_node_commitment, "verifier node commitment")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "circuit_id": self.circuit_id,
            "proof_commitment": self.proof_commitment,
            "public_input_root": self.public_input_root,
            "nullifier_root": self.nullifier_root,
            "disclosure_root": self.disclosure_root,
            "revocation_snapshot_root": self.revocation_snapshot_root,
            "verifier_node_commitment": self.verifier_node_commitment,
            "status": self.status.as_str(),
            "verified_at_height": self.verified_at_height,
            "fee_charged_micro_xmr": self.fee_charged_micro_xmr,
            "receipt_nonce": self.receipt_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationNullifierSet {
    pub set_id: String,
    pub set_kind: RevocationSetKind,
    pub authority_commitment: String,
    pub set_root: String,
    pub accumulator_root: String,
    pub witness_update_root: String,
    pub epoch: u64,
    pub updated_at_height: u64,
    pub entry_count: u64,
    pub revoked_count: u64,
    pub nullifier_count: u64,
    pub set_nonce: u64,
}

impl RevocationNullifierSet {
    pub fn new(
        label: &str,
        set_kind: RevocationSetKind,
        authority_commitment: &str,
        epoch: u64,
        updated_at_height: u64,
        entry_count: u64,
        revoked_count: u64,
        nullifier_count: u64,
        set_nonce: u64,
    ) -> Self {
        let set_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-REVOCATION-SET",
            label,
            set_kind.as_str(),
        );
        let accumulator_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-REVOCATION-ACCUMULATOR",
            authority_commitment,
            label,
        );
        let witness_update_root = labeled_root(
            "ZK-TOKEN-COMPLIANCE-REVOCATION-WITNESS-UPDATE",
            label,
            &epoch.to_string(),
        );
        let set_id = revocation_set_id(set_kind, authority_commitment, &set_root, epoch, set_nonce);
        Self {
            set_id,
            set_kind,
            authority_commitment: authority_commitment.to_string(),
            set_root,
            accumulator_root,
            witness_update_root,
            epoch,
            updated_at_height,
            entry_count,
            revoked_count,
            nullifier_count,
            set_nonce,
        }
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.set_id, "set id")?;
        ensure_nonempty(&self.authority_commitment, "authority commitment")?;
        ensure_nonempty(&self.set_root, "set root")?;
        ensure_nonempty(&self.accumulator_root, "accumulator root")?;
        ensure_nonempty(&self.witness_update_root, "witness update root")?;
        if self.revoked_count > self.entry_count {
            return Err("revoked count cannot exceed entry count".to_string());
        }
        if self.nullifier_count > self.entry_count {
            return Err("nullifier count cannot exceed entry count".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "revocation_nullifier_set",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "set_id": self.set_id,
            "set_kind": self.set_kind.as_str(),
            "authority_commitment": self.authority_commitment,
            "set_root": self.set_root,
            "accumulator_root": self.accumulator_root,
            "witness_update_root": self.witness_update_root,
            "epoch": self.epoch,
            "updated_at_height": self.updated_at_height,
            "entry_count": self.entry_count,
            "revoked_count": self.revoked_count,
            "nullifier_count": self.nullifier_count,
            "set_nonce": self.set_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
    pub event_nonce: u64,
}

impl ComplianceEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        emitted_at_height: u64,
        event_nonce: u64,
    ) -> Self {
        let event_root = labeled_root("ZK-TOKEN-COMPLIANCE-EVENT-ROOT", event_kind, subject_id);
        let event_id = domain_hash(
            "ZK-TOKEN-COMPLIANCE-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&event_root),
                HashPart::Int(emitted_at_height as i128),
                HashPart::Int(event_nonce as i128),
            ],
            32,
        );
        Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            event_root,
            emitted_at_height,
            event_nonce,
        }
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        ensure_nonempty(&self.event_id, "event id")?;
        ensure_nonempty(&self.event_kind, "event kind")?;
        ensure_nonempty(&self.subject_id, "subject id")?;
        ensure_nonempty(&self.event_root, "event root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_event",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "emitted_at_height": self.emitted_at_height,
            "event_nonce": self.event_nonce,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub circuit_root: String,
    pub disclosure_root: String,
    pub upgrade_slot_root: String,
    pub audit_root: String,
    pub cache_hint_root: String,
    pub verifier_receipt_root: String,
    pub revocation_nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_token_compliance_circuit_registry_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "circuit_root": self.circuit_root,
            "disclosure_root": self.disclosure_root,
            "upgrade_slot_root": self.upgrade_slot_root,
            "audit_root": self.audit_root,
            "cache_hint_root": self.cache_hint_root,
            "verifier_receipt_root": self.verifier_receipt_root,
            "revocation_nullifier_root": self.revocation_nullifier_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ZK-TOKEN-COMPLIANCE-CIRCUIT-REGISTRY-ROOTS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION),
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.circuit_root),
                HashPart::Str(&self.disclosure_root),
                HashPart::Str(&self.upgrade_slot_root),
                HashPart::Str(&self.audit_root),
                HashPart::Str(&self.cache_hint_root),
                HashPart::Str(&self.verifier_receipt_root),
                HashPart::Str(&self.revocation_nullifier_root),
                HashPart::Str(&self.event_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub circuits: usize,
    pub active_circuits: usize,
    pub disclosures: usize,
    pub active_disclosures: usize,
    pub upgrade_slots: usize,
    pub pending_upgrade_slots: usize,
    pub audits: usize,
    pub current_audits: usize,
    pub cache_hints: usize,
    pub usable_cache_hints: usize,
    pub verifier_receipts: usize,
    pub accepted_receipts: usize,
    pub revocation_sets: usize,
    pub events: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_token_compliance_circuit_registry_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "circuits": self.circuits,
            "active_circuits": self.active_circuits,
            "disclosures": self.disclosures,
            "active_disclosures": self.active_disclosures,
            "upgrade_slots": self.upgrade_slots,
            "pending_upgrade_slots": self.pending_upgrade_slots,
            "audits": self.audits,
            "current_audits": self.current_audits,
            "cache_hints": self.cache_hints,
            "usable_cache_hints": self.usable_cache_hints,
            "verifier_receipts": self.verifier_receipts,
            "accepted_receipts": self.accepted_receipts,
            "revocation_sets": self.revocation_sets,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub circuits: BTreeMap<String, TokenRuleCircuit>,
    pub disclosures: BTreeMap<String, SelectiveDisclosureCommitment>,
    pub upgrade_slots: BTreeMap<String, PqGovernedUpgradeSlot>,
    pub audits: BTreeMap<String, CircuitAudit>,
    pub cache_hints: BTreeMap<String, LowFeeProofCacheHint>,
    pub verifier_receipts: BTreeMap<String, VerifierReceipt>,
    pub revocation_sets: BTreeMap<String, RevocationNullifierSet>,
    pub events: Vec<ComplianceEvent>,
}

impl State {
    pub fn devnet() -> ZkTokenComplianceCircuitRegistryResult<Self> {
        let config = Config::devnet();
        let height = ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_DEVNET_HEIGHT;
        let mut state = Self {
            config,
            height,
            circuits: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            upgrade_slots: BTreeMap::new(),
            audits: BTreeMap::new(),
            cache_hints: BTreeMap::new(),
            verifier_receipts: BTreeMap::new(),
            revocation_sets: BTreeMap::new(),
            events: Vec::new(),
        };
        state.seed_devnet_records();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        self.config.validate()?;
        ensure_capacity(
            self.circuits.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_CIRCUITS,
            "circuits",
        )?;
        ensure_capacity(
            self.disclosures.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_DISCLOSURES,
            "disclosures",
        )?;
        ensure_capacity(
            self.upgrade_slots.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_UPGRADE_SLOTS,
            "upgrade slots",
        )?;
        ensure_capacity(
            self.audits.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_AUDITS,
            "audits",
        )?;
        ensure_capacity(
            self.cache_hints.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_CACHE_HINTS,
            "cache hints",
        )?;
        ensure_capacity(
            self.verifier_receipts.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_RECEIPTS,
            "verifier receipts",
        )?;
        ensure_capacity(
            self.revocation_sets.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_SETS,
            "revocation sets",
        )?;
        ensure_capacity(
            self.events.len(),
            ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_EVENTS,
            "events",
        )?;
        for circuit in self.circuits.values() {
            circuit.validate()?;
        }
        for disclosure in self.disclosures.values() {
            disclosure.validate()?;
            ensure_known(&self.circuits, &disclosure.circuit_id, "disclosure circuit")?;
        }
        for slot in self.upgrade_slots.values() {
            slot.validate()?;
            ensure_known(&self.circuits, &slot.circuit_id, "upgrade circuit")?;
        }
        for audit in self.audits.values() {
            audit.validate()?;
            ensure_known(&self.circuits, &audit.circuit_id, "audit circuit")?;
        }
        for hint in self.cache_hints.values() {
            hint.validate()?;
            ensure_known(&self.circuits, &hint.circuit_id, "cache hint circuit")?;
        }
        for receipt in self.verifier_receipts.values() {
            receipt.validate()?;
            ensure_known(&self.circuits, &receipt.circuit_id, "receipt circuit")?;
        }
        for set in self.revocation_sets.values() {
            set.validate()?;
        }
        for event in &self.events {
            event.validate()?;
        }
        if self.config.require_active_audit {
            self.validate_active_audits()?;
        }
        if self.config.require_revocation_checks {
            self.validate_revocation_references()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkTokenComplianceCircuitRegistryResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> ZkTokenComplianceCircuitRegistryResult<()> {
        if height < self.height {
            return Err(format!(
                "height cannot move backward from {} to {}",
                self.height, height
            ));
        }
        self.height = height;
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            circuit_root: merkle_root(
                "ZK-TOKEN-COMPLIANCE-CIRCUIT",
                &records_from_map(&self.circuits),
            ),
            disclosure_root: merkle_root(
                "ZK-TOKEN-COMPLIANCE-DISCLOSURE",
                &records_from_map(&self.disclosures),
            ),
            upgrade_slot_root: merkle_root(
                "ZK-TOKEN-COMPLIANCE-UPGRADE-SLOT",
                &records_from_map(&self.upgrade_slots),
            ),
            audit_root: merkle_root("ZK-TOKEN-COMPLIANCE-AUDIT", &records_from_map(&self.audits)),
            cache_hint_root: merkle_root(
                "ZK-TOKEN-COMPLIANCE-CACHE-HINT",
                &records_from_map(&self.cache_hints),
            ),
            verifier_receipt_root: merkle_root(
                "ZK-TOKEN-COMPLIANCE-VERIFIER-RECEIPT",
                &records_from_map(&self.verifier_receipts),
            ),
            revocation_nullifier_root: merkle_root(
                "ZK-TOKEN-COMPLIANCE-REVOCATION-NULLIFIER",
                &records_from_map(&self.revocation_sets),
            ),
            event_root: merkle_root("ZK-TOKEN-COMPLIANCE-EVENT", &records_from_vec(&self.events)),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            circuits: self.circuits.len(),
            active_circuits: self
                .circuits
                .values()
                .filter(|circuit| circuit.accepts_at_height(self.height))
                .count(),
            disclosures: self.disclosures.len(),
            active_disclosures: self
                .disclosures
                .values()
                .filter(|disclosure| disclosure.is_active(self.height))
                .count(),
            upgrade_slots: self.upgrade_slots.len(),
            pending_upgrade_slots: self
                .upgrade_slots
                .values()
                .filter(|slot| slot.status.is_pending())
                .count(),
            audits: self.audits.len(),
            current_audits: self
                .audits
                .values()
                .filter(|audit| audit.is_current(self.height))
                .count(),
            cache_hints: self.cache_hints.len(),
            usable_cache_hints: self
                .cache_hints
                .values()
                .filter(|hint| hint.is_usable(self.height))
                .count(),
            verifier_receipts: self.verifier_receipts.len(),
            accepted_receipts: self
                .verifier_receipts
                .values()
                .filter(|receipt| receipt.status == ReceiptStatus::Accepted)
                .count(),
            revocation_sets: self.revocation_sets.len(),
            events: self.events.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "zk_token_compliance_circuit_registry_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        domain_hash(
            "ZK-TOKEN-COMPLIANCE-CIRCUIT-REGISTRY-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&counters.public_record()),
            ],
            32,
        )
    }

    fn validate_active_audits(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        for circuit in self.circuits.values() {
            if circuit.status.accepts_proofs() {
                let has_current_audit = self.audits.values().any(|audit| {
                    audit.circuit_id == circuit.circuit_id && audit.is_current(self.height)
                });
                if !has_current_audit {
                    return Err(format!(
                        "active circuit {} lacks current audit",
                        circuit.circuit_id
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_revocation_references(&self) -> ZkTokenComplianceCircuitRegistryResult<()> {
        let known_roots = self
            .revocation_sets
            .values()
            .map(|set| set.set_root.clone())
            .collect::<BTreeSet<_>>();
        for circuit in self.circuits.values() {
            if circuit.rule_kind.requires_revocation_set()
                && !known_roots.contains(&circuit.revocation_set_root)
            {
                return Err(format!(
                    "circuit {} references unknown revocation root",
                    circuit.circuit_id
                ));
            }
        }
        Ok(())
    }

    fn seed_devnet_records(&mut self) {
        let authority = commitment("devnet-compliance-authority");
        let issuer = commitment("devnet-token-issuer");
        let auditor = merkle_root(
            "ZK-TOKEN-COMPLIANCE-DEVNET-AUDITOR",
            &[
                json!("auditor-ml-dsa-87-a"),
                json!("auditor-slh-dsa-shake-b"),
                json!("auditor-threshold-c"),
            ],
        );
        let governance = merkle_root(
            "ZK-TOKEN-COMPLIANCE-DEVNET-GOVERNANCE",
            &[
                json!("governor-ml-dsa-87-a"),
                json!("governor-ml-dsa-87-b"),
                json!("governor-slh-dsa-shake-c"),
            ],
        );
        let credential_set = RevocationNullifierSet::new(
            "devnet-credential-revocation",
            RevocationSetKind::Credential,
            &authority,
            1,
            self.height,
            16_384,
            12,
            0,
            1,
        );
        let sanctions_set = RevocationNullifierSet::new(
            "devnet-sanctions-nullifier",
            RevocationSetKind::Nullifier,
            &authority,
            1,
            self.height,
            8_192,
            47,
            47,
            2,
        );
        let emergency_set = RevocationNullifierSet::new(
            "devnet-emergency-circuit-set",
            RevocationSetKind::Emergency,
            &authority,
            1,
            self.height,
            128,
            0,
            0,
            3,
        );
        let credential_root = credential_set.set_root.clone();
        let sanctions_root = sanctions_set.set_root.clone();
        let empty_revocation_root = emergency_set.set_root.clone();
        self.revocation_sets
            .insert(credential_set.set_id.clone(), credential_set);
        self.revocation_sets
            .insert(sanctions_set.set_id.clone(), sanctions_set);
        self.revocation_sets
            .insert(emergency_set.set_id.clone(), emergency_set);

        let transfer_circuit = TokenRuleCircuit::new(
            "devnet-private-transfer-policy",
            "private-token-wxmr",
            &issuer,
            TokenRuleCircuitKind::TransferPolicy,
            &labeled_root("ZK-TOKEN-COMPLIANCE-VK", "transfer", "wxmr"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-DISCLOSURE-POLICY", "transfer", "wxmr"),
            &empty_revocation_root,
            self.height.saturating_sub(12),
            10,
        )
        .with_tag("fast")
        .with_tag("low_fee")
        .with_tag("private_transfer");
        let kyc_circuit = TokenRuleCircuit::new(
            "devnet-shielded-kyc-gate",
            "private-token-usdd",
            &issuer,
            TokenRuleCircuitKind::ShieldedKycGate,
            &labeled_root("ZK-TOKEN-COMPLIANCE-VK", "kyc", "usdd"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-DISCLOSURE-POLICY", "kyc", "usdd"),
            &credential_root,
            self.height.saturating_sub(10),
            11,
        )
        .with_tag("selective_disclosure")
        .with_tag("credential")
        .with_tag("pq_governed");
        let sanctions_circuit = TokenRuleCircuit::new(
            "devnet-sanctions-screen",
            "private-token-usdd",
            &issuer,
            TokenRuleCircuitKind::SanctionsScreen,
            &labeled_root("ZK-TOKEN-COMPLIANCE-VK", "sanctions", "usdd"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-DISCLOSURE-POLICY", "sanctions", "usdd"),
            &sanctions_root,
            self.height.saturating_sub(8),
            12,
        )
        .with_tag("revocation")
        .with_tag("nullifier")
        .with_tag("compliance");
        let mint_circuit = TokenRuleCircuit::new(
            "devnet-bridge-mint-burn",
            "private-token-wxmr",
            &issuer,
            TokenRuleCircuitKind::BridgeMintBurn,
            &labeled_root("ZK-TOKEN-COMPLIANCE-VK", "bridge", "wxmr"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-DISCLOSURE-POLICY", "bridge", "wxmr"),
            &empty_revocation_root,
            self.height.saturating_sub(6),
            13,
        )
        .with_tag("monero_bridge")
        .with_tag("supply")
        .with_tag("reserve");

        let transfer_id = transfer_circuit.circuit_id.clone();
        let kyc_id = kyc_circuit.circuit_id.clone();
        let sanctions_id = sanctions_circuit.circuit_id.clone();
        let mint_id = mint_circuit.circuit_id.clone();
        let transfer_vk = transfer_circuit.verifier_key_root.clone();
        let kyc_vk = kyc_circuit.verifier_key_root.clone();
        self.circuits.insert(transfer_id.clone(), transfer_circuit);
        self.circuits.insert(kyc_id.clone(), kyc_circuit);
        self.circuits
            .insert(sanctions_id.clone(), sanctions_circuit);
        self.circuits.insert(mint_id.clone(), mint_circuit);

        let disclosure_a = SelectiveDisclosureCommitment::new(
            "devnet-jurisdiction-disclosure",
            &commitment("account-alpha"),
            "private-token-usdd",
            &kyc_id,
            DisclosureFieldKind::Jurisdiction,
            &auditor,
            self.height.saturating_sub(4),
            self.config.default_disclosure_ttl_blocks,
            20,
        );
        let disclosure_b = SelectiveDisclosureCommitment::new(
            "devnet-credential-class-disclosure",
            &commitment("account-beta"),
            "private-token-usdd",
            &kyc_id,
            DisclosureFieldKind::CredentialClass,
            &auditor,
            self.height.saturating_sub(4),
            self.config.default_disclosure_ttl_blocks,
            21,
        );
        let disclosure_root_a = disclosure_a.root();
        let disclosure_root_b = disclosure_b.root();
        self.disclosures
            .insert(disclosure_a.disclosure_id.clone(), disclosure_a);
        self.disclosures
            .insert(disclosure_b.disclosure_id.clone(), disclosure_b);

        let transfer_audit = CircuitAudit::new(
            &transfer_id,
            &auditor,
            AuditVerdict::Passed,
            70,
            self.height.saturating_sub(3),
            self.config.default_audit_ttl_blocks,
            30,
        );
        let kyc_audit = CircuitAudit::new(
            &kyc_id,
            &auditor,
            AuditVerdict::PassedWithNotes,
            120,
            self.height.saturating_sub(3),
            self.config.default_audit_ttl_blocks,
            31,
        );
        let sanctions_audit = CircuitAudit::new(
            &sanctions_id,
            &auditor,
            AuditVerdict::Passed,
            90,
            self.height.saturating_sub(3),
            self.config.default_audit_ttl_blocks,
            32,
        );
        let mint_audit = CircuitAudit::new(
            &mint_id,
            &auditor,
            AuditVerdict::Passed,
            95,
            self.height.saturating_sub(3),
            self.config.default_audit_ttl_blocks,
            33,
        );
        self.audits
            .insert(transfer_audit.audit_id.clone(), transfer_audit);
        self.audits.insert(kyc_audit.audit_id.clone(), kyc_audit);
        self.audits
            .insert(sanctions_audit.audit_id.clone(), sanctions_audit);
        self.audits.insert(mint_audit.audit_id.clone(), mint_audit);

        let upgrade_slot = PqGovernedUpgradeSlot::new(
            "devnet-transfer-policy-vk-upgrade",
            &transfer_id,
            &transfer_vk,
            &labeled_root("ZK-TOKEN-COMPLIANCE-VK", "transfer", "wxmr-v2"),
            &governance,
            self.height.saturating_sub(1),
            self.config.default_upgrade_timelock_blocks,
            40,
        );
        let kyc_upgrade_slot = PqGovernedUpgradeSlot::new(
            "devnet-kyc-gate-vk-upgrade",
            &kyc_id,
            &kyc_vk,
            &labeled_root("ZK-TOKEN-COMPLIANCE-VK", "kyc", "usdd-v2"),
            &governance,
            self.height,
            self.config.default_upgrade_timelock_blocks,
            41,
        );
        self.upgrade_slots
            .insert(upgrade_slot.slot_id.clone(), upgrade_slot);
        self.upgrade_slots
            .insert(kyc_upgrade_slot.slot_id.clone(), kyc_upgrade_slot);

        let transfer_hint = LowFeeProofCacheHint::new(
            &transfer_id,
            ProofCacheHintKind::BatchSameCircuit,
            &commitment("fee-sponsor-alpha"),
            256,
            2_400,
            self.height.saturating_sub(1),
            self.config.default_cache_ttl_blocks,
            50,
        );
        let kyc_hint = LowFeeProofCacheHint::new(
            &kyc_id,
            ProofCacheHintKind::WarmVerifierKey,
            &commitment("fee-sponsor-beta"),
            64,
            1_700,
            self.height.saturating_sub(1),
            self.config.default_cache_ttl_blocks,
            51,
        );
        self.cache_hints
            .insert(transfer_hint.hint_id.clone(), transfer_hint);
        self.cache_hints.insert(kyc_hint.hint_id.clone(), kyc_hint);

        let receipt_a = VerifierReceipt::new(
            &transfer_id,
            &commitment("proof-transfer-alpha"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-PUBLIC-INPUT", "transfer", "alpha"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-NULLIFIER", "transfer", "alpha"),
            &disclosure_root_a,
            &empty_revocation_root,
            &commitment("verifier-node-1"),
            ReceiptStatus::Accepted,
            self.height,
            480,
            60,
        );
        let receipt_b = VerifierReceipt::new(
            &kyc_id,
            &commitment("proof-kyc-beta"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-PUBLIC-INPUT", "kyc", "beta"),
            &labeled_root("ZK-TOKEN-COMPLIANCE-NULLIFIER", "kyc", "beta"),
            &disclosure_root_b,
            &credential_root,
            &commitment("verifier-node-2"),
            ReceiptStatus::Cached,
            self.height,
            390,
            61,
        );
        self.verifier_receipts
            .insert(receipt_a.receipt_id.clone(), receipt_a);
        self.verifier_receipts
            .insert(receipt_b.receipt_id.clone(), receipt_b);

        self.events.push(ComplianceEvent::new(
            "circuit_registered",
            &transfer_id,
            self.height.saturating_sub(12),
            70,
        ));
        self.events.push(ComplianceEvent::new(
            "selective_disclosure_committed",
            &kyc_id,
            self.height.saturating_sub(4),
            71,
        ));
        self.events.push(ComplianceEvent::new(
            "verifier_receipt_emitted",
            &transfer_id,
            self.height,
            72,
        ));
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-CIRCUIT-REGISTRY-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> Result<State, String> {
    State::devnet()
}

pub fn circuit_id(
    label: &str,
    token_class_id: &str,
    issuer_commitment: &str,
    rule_kind: TokenRuleCircuitKind,
    verifier_key_root: &str,
    circuit_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-CIRCUIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(token_class_id),
            HashPart::Str(issuer_commitment),
            HashPart::Str(rule_kind.as_str()),
            HashPart::Str(verifier_key_root),
            HashPart::Int(circuit_nonce as i128),
        ],
        32,
    )
}

pub fn disclosure_id(
    subject_commitment: &str,
    token_class_id: &str,
    circuit_id: &str,
    field_kind: DisclosureFieldKind,
    salted_value_root: &str,
    disclosure_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(token_class_id),
            HashPart::Str(circuit_id),
            HashPart::Str(field_kind.as_str()),
            HashPart::Str(salted_value_root),
            HashPart::Int(disclosure_nonce as i128),
        ],
        32,
    )
}

pub fn upgrade_slot_id(
    circuit_id: &str,
    current_verifier_key_root: &str,
    proposed_verifier_key_root: &str,
    governance_committee_root: &str,
    upgrade_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-UPGRADE-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_id),
            HashPart::Str(current_verifier_key_root),
            HashPart::Str(proposed_verifier_key_root),
            HashPart::Str(governance_committee_root),
            HashPart::Int(upgrade_nonce as i128),
        ],
        32,
    )
}

pub fn audit_id(
    circuit_id: &str,
    auditor_committee_root: &str,
    transcript_root: &str,
    verdict: AuditVerdict,
    risk_score_bps: u64,
    audit_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-AUDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_id),
            HashPart::Str(auditor_committee_root),
            HashPart::Str(transcript_root),
            HashPart::Str(verdict.as_str()),
            HashPart::Int(risk_score_bps as i128),
            HashPart::Int(audit_nonce as i128),
        ],
        32,
    )
}

pub fn cache_hint_id(
    circuit_id: &str,
    hint_kind: ProofCacheHintKind,
    cache_key_root: &str,
    fee_sponsor_commitment: &str,
    hint_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-CACHE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_id),
            HashPart::Str(hint_kind.as_str()),
            HashPart::Str(cache_key_root),
            HashPart::Str(fee_sponsor_commitment),
            HashPart::Int(hint_nonce as i128),
        ],
        32,
    )
}

pub fn verifier_receipt_id(
    circuit_id: &str,
    proof_commitment: &str,
    public_input_root: &str,
    nullifier_root: &str,
    status: ReceiptStatus,
    receipt_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-VERIFIER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_id),
            HashPart::Str(proof_commitment),
            HashPart::Str(public_input_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(status.as_str()),
            HashPart::Int(receipt_nonce as i128),
        ],
        32,
    )
}

pub fn revocation_set_id(
    set_kind: RevocationSetKind,
    authority_commitment: &str,
    set_root: &str,
    epoch: u64,
    set_nonce: u64,
) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-REVOCATION-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(set_kind.as_str()),
            HashPart::Str(authority_commitment),
            HashPart::Str(set_root),
            HashPart::Int(epoch as i128),
            HashPart::Int(set_nonce as i128),
        ],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "ZK-TOKEN-COMPLIANCE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn labeled_root(domain: &str, left: &str, right: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_PROTOCOL_VERSION),
            HashPart::Str(left),
            HashPart::Str(right),
        ],
        32,
    )
}

fn records_from_map<T>(items: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    items.values().map(PublicRecord::public_record).collect()
}

fn records_from_vec<T>(items: &[T]) -> Vec<Value>
where
    T: PublicRecord,
{
    items.iter().map(PublicRecord::public_record).collect()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for TokenRuleCircuit {
    fn public_record(&self) -> Value {
        TokenRuleCircuit::public_record(self)
    }
}

impl PublicRecord for SelectiveDisclosureCommitment {
    fn public_record(&self) -> Value {
        SelectiveDisclosureCommitment::public_record(self)
    }
}

impl PublicRecord for PqGovernedUpgradeSlot {
    fn public_record(&self) -> Value {
        PqGovernedUpgradeSlot::public_record(self)
    }
}

impl PublicRecord for CircuitAudit {
    fn public_record(&self) -> Value {
        CircuitAudit::public_record(self)
    }
}

impl PublicRecord for LowFeeProofCacheHint {
    fn public_record(&self) -> Value {
        LowFeeProofCacheHint::public_record(self)
    }
}

impl PublicRecord for VerifierReceipt {
    fn public_record(&self) -> Value {
        VerifierReceipt::public_record(self)
    }
}

impl PublicRecord for RevocationNullifierSet {
    fn public_record(&self) -> Value {
        RevocationNullifierSet::public_record(self)
    }
}

impl PublicRecord for ComplianceEvent {
    fn public_record(&self) -> Value {
        ComplianceEvent::public_record(self)
    }
}

fn ensure_nonempty(value: &str, label: &str) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_nonzero(value: u64, label: &str) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if value == 0 {
        Err(format!("{label} must be nonzero"))
    } else {
        Ok(())
    }
}

fn ensure_eq(
    actual: &str,
    expected: &str,
    label: &str,
) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if actual != expected {
        Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_order(start: u64, end: u64, label: &str) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if start > end {
        Err(format!("{label} start {start} exceeds end {end}"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if value > ZK_TOKEN_COMPLIANCE_CIRCUIT_REGISTRY_MAX_BPS {
        Err(format!("{label} bps {value} exceeds max"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    len: usize,
    max: usize,
    label: &str,
) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if len > max {
        Err(format!("{label} length {len} exceeds max {max}"))
    } else {
        Ok(())
    }
}

fn ensure_known<T>(
    map: &BTreeMap<String, T>,
    id: &str,
    label: &str,
) -> ZkTokenComplianceCircuitRegistryResult<()> {
    if map.contains_key(id) {
        Ok(())
    } else {
        Err(format!("{label} {id} is unknown"))
    }
}

fn is_empty_root(root: &str) -> bool {
    root == merkle_root("ZK-TOKEN-COMPLIANCE-EMPTY", &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_registry_validates_and_has_stable_roots() {
        let registry = State::devnet().and_then(|state| {
            state.validate()?;
            Ok(state)
        });
        assert!(registry.is_ok());
        if let Ok(state) = registry {
            assert_eq!(state.config.chain_id, CHAIN_ID);
            assert_eq!(state.counters().circuits, 4);
            assert_eq!(state.counters().revocation_sets, 3);
            assert_eq!(state.state_root().len(), 64);
        }
    }
}
