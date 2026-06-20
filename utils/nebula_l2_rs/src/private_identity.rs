use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, DEVNET_PRIVACY_PROOF_BYTES,
};

pub type PrivateIdentityResult<T> = Result<T, String>;

pub const PRIVATE_IDENTITY_PROTOCOL_VERSION: &str = "nebula-l2-private-identity-v1";
pub const PRIVATE_IDENTITY_COMMITMENT_SCHEME: &str = "shake256-domain-separated-devnet-commitment";
pub const PRIVATE_IDENTITY_ZK_PROOF_SYSTEM: &str = "devnet-mock-zk-selective-credential-proof";
pub const PRIVATE_IDENTITY_DISCLOSURE_PROOF_SYSTEM: &str =
    "devnet-mock-viewing-committee-disclosure-proof";
pub const PRIVATE_IDENTITY_NULLIFIER_SCHEME: &str = "devnet-credential-nullifier-shake256-v1";
pub const PRIVATE_IDENTITY_REVOCATION_SCHEME: &str = "devnet-issuer-revocation-accumulator-v1";
pub const PRIVATE_IDENTITY_PQ_ISSUER_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PRIVATE_IDENTITY_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const PRIVATE_IDENTITY_DEFAULT_NULLIFIER_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_IDENTITY_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 144;
pub const PRIVATE_IDENTITY_DEFAULT_CREDENTIAL_TTL_BLOCKS: u64 = 172_800;
pub const PRIVATE_IDENTITY_DEFAULT_MIN_ANONYMITY_SET: u64 = 128;
pub const PRIVATE_IDENTITY_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_IDENTITY_DEFAULT_MAX_DISCLOSURE_ATTRIBUTES: usize = 12;
pub const PRIVATE_IDENTITY_DEFAULT_MAX_RISK_SCORE_BPS: u64 = 7_500;
pub const PRIVATE_IDENTITY_DEFAULT_DEFI_ASSURANCE_LEVEL: u8 = 2;
pub const PRIVATE_IDENTITY_DEFAULT_SPONSOR_FEE_UNITS: u64 = 8;
pub const PRIVATE_IDENTITY_MAX_BPS: u64 = 10_000;
pub const PRIVATE_IDENTITY_DEFAULT_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_IDENTITY_LOW_FEE_LANE: &str = "private-identity-disclosure";
pub const PRIVATE_IDENTITY_FEE_ASSET_ID: &str = "piconero";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateIdentityStatus {
    Pending,
    Active,
    Frozen,
    Revoked,
    Expired,
}

impl PrivateIdentityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Pending | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Issued,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Issued | Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    AgeOver,
    Residency,
    SanctionsScreen,
    AccreditedInvestor,
    ProtocolReputation,
    DefiEligibility,
    HumanUniqueness,
    RiskAttestation,
    Custom(String),
}

impl CredentialKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::AgeOver => "age_over".to_string(),
            Self::Residency => "residency".to_string(),
            Self::SanctionsScreen => "sanctions_screen".to_string(),
            Self::AccreditedInvestor => "accredited_investor".to_string(),
            Self::ProtocolReputation => "protocol_reputation".to_string(),
            Self::DefiEligibility => "defi_eligibility".to_string(),
            Self::HumanUniqueness => "human_uniqueness".to_string(),
            Self::RiskAttestation => "risk_attestation".to_string(),
            Self::Custom(value) => normalize_label(value),
        }
    }

    pub fn default_assurance_level(&self) -> u8 {
        match self {
            Self::SanctionsScreen | Self::AccreditedInvestor => 3,
            Self::AgeOver | Self::Residency | Self::DefiEligibility => 2,
            Self::ProtocolReputation | Self::HumanUniqueness | Self::RiskAttestation => 1,
            Self::Custom(_) => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosurePurpose {
    DefiEligibility,
    RegulatoryInquiry,
    RiskReview,
    LiquidityLimit,
    IssuerAudit,
    UserRecovery,
    EmergencyCompliance,
    Custom(String),
}

impl DisclosurePurpose {
    pub fn as_str(&self) -> String {
        match self {
            Self::DefiEligibility => "defi_eligibility".to_string(),
            Self::RegulatoryInquiry => "regulatory_inquiry".to_string(),
            Self::RiskReview => "risk_review".to_string(),
            Self::LiquidityLimit => "liquidity_limit".to_string(),
            Self::IssuerAudit => "issuer_audit".to_string(),
            Self::UserRecovery => "user_recovery".to_string(),
            Self::EmergencyCompliance => "emergency_compliance".to_string(),
            Self::Custom(value) => normalize_label(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Draft,
    Verified,
    Consumed,
    Rejected,
    Expired,
}

impl ProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Verified => "verified",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryStatus {
    Open,
    Sealed,
    Rotating,
    Retired,
}

impl RegistryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Requested,
    Approved,
    Revealed,
    Rejected,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Revealed => "revealed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiGateKind {
    Swap,
    Lending,
    Perps,
    StablecoinMint,
    LiquidityMining,
    BridgeLimit,
}

impl DefiGateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::StablecoinMint => "stablecoin_mint",
            Self::LiquidityMining => "liquidity_mining",
            Self::BridgeLimit => "bridge_limit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTagKind {
    SanctionsScreen,
    Velocity,
    SybilResistance,
    BridgeExposure,
    OracleBehavior,
    LiquidityAbuse,
    IssuerConfidence,
}

impl RiskTagKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SanctionsScreen => "sanctions_screen",
            Self::Velocity => "velocity",
            Self::SybilResistance => "sybil_resistance",
            Self::BridgeExposure => "bridge_exposure",
            Self::OracleBehavior => "oracle_behavior",
            Self::LiquidityAbuse => "liquidity_abuse",
            Self::IssuerConfidence => "issuer_confidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Low,
    Watch,
    Elevated,
    High,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn default_score_bucket_bps(&self) -> u64 {
        match self {
            Self::Low => 1_000,
            Self::Watch => 2_500,
            Self::Elevated => 5_000,
            Self::High => 7_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIdentityConfig {
    pub nullifier_epoch_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub credential_ttl_blocks: u64,
    pub min_anonymity_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_disclosure_attributes: usize,
    pub max_risk_score_bps: u64,
    pub defi_min_assurance_level: u8,
    pub low_fee_max_sponsored_units: u64,
    pub default_privacy_set_size: u64,
    pub proof_bytes: u64,
    pub allow_emergency_viewing: bool,
    pub require_pq_issuer_attestations: bool,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
}

impl Default for PrivateIdentityConfig {
    fn default() -> Self {
        Self {
            nullifier_epoch_blocks: PRIVATE_IDENTITY_DEFAULT_NULLIFIER_EPOCH_BLOCKS,
            disclosure_ttl_blocks: PRIVATE_IDENTITY_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            credential_ttl_blocks: PRIVATE_IDENTITY_DEFAULT_CREDENTIAL_TTL_BLOCKS,
            min_anonymity_set_size: PRIVATE_IDENTITY_DEFAULT_MIN_ANONYMITY_SET,
            min_pq_security_bits: PRIVATE_IDENTITY_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_disclosure_attributes: PRIVATE_IDENTITY_DEFAULT_MAX_DISCLOSURE_ATTRIBUTES,
            max_risk_score_bps: PRIVATE_IDENTITY_DEFAULT_MAX_RISK_SCORE_BPS,
            defi_min_assurance_level: PRIVATE_IDENTITY_DEFAULT_DEFI_ASSURANCE_LEVEL,
            low_fee_max_sponsored_units: PRIVATE_IDENTITY_DEFAULT_SPONSOR_FEE_UNITS,
            default_privacy_set_size: PRIVATE_IDENTITY_DEFAULT_PRIVACY_SET_SIZE,
            proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
            allow_emergency_viewing: true,
            require_pq_issuer_attestations: true,
            low_fee_lane: PRIVATE_IDENTITY_LOW_FEE_LANE.to_string(),
            fee_asset_id: PRIVATE_IDENTITY_FEE_ASSET_ID.to_string(),
        }
    }
}

impl PrivateIdentityConfig {
    pub fn devnet() -> Self {
        Self {
            nullifier_epoch_blocks: 240,
            disclosure_ttl_blocks: 96,
            credential_ttl_blocks: 86_400,
            min_anonymity_set_size: 64,
            min_pq_security_bits: 192,
            max_disclosure_attributes: 16,
            max_risk_score_bps: 8_000,
            defi_min_assurance_level: 2,
            low_fee_max_sponsored_units: 12,
            default_privacy_set_size: 512,
            proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
            allow_emergency_viewing: true,
            require_pq_issuer_attestations: true,
            low_fee_lane: PRIVATE_IDENTITY_LOW_FEE_LANE.to_string(),
            fee_asset_id: PRIVATE_IDENTITY_FEE_ASSET_ID.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_identity_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "commitment_scheme": PRIVATE_IDENTITY_COMMITMENT_SCHEME,
            "zk_proof_system": PRIVATE_IDENTITY_ZK_PROOF_SYSTEM,
            "disclosure_proof_system": PRIVATE_IDENTITY_DISCLOSURE_PROOF_SYSTEM,
            "nullifier_scheme": PRIVATE_IDENTITY_NULLIFIER_SCHEME,
            "revocation_scheme": PRIVATE_IDENTITY_REVOCATION_SCHEME,
            "pq_issuer_scheme": PRIVATE_IDENTITY_PQ_ISSUER_SCHEME,
            "pq_kem_scheme": PRIVATE_IDENTITY_PQ_KEM_SCHEME,
            "nullifier_epoch_blocks": self.nullifier_epoch_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "credential_ttl_blocks": self.credential_ttl_blocks,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_disclosure_attributes": self.max_disclosure_attributes,
            "max_risk_score_bps": self.max_risk_score_bps,
            "defi_min_assurance_level": self.defi_min_assurance_level,
            "low_fee_max_sponsored_units": self.low_fee_max_sponsored_units,
            "default_privacy_set_size": self.default_privacy_set_size,
            "proof_bytes": self.proof_bytes,
            "allow_emergency_viewing": self.allow_emergency_viewing,
            "require_pq_issuer_attestations": self.require_pq_issuer_attestations,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
        })
    }

    pub fn config_root(&self) -> String {
        private_identity_payload_root("PRIVATE-IDENTITY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_zero(self.nullifier_epoch_blocks, "nullifier epoch blocks")?;
        ensure_non_zero(self.disclosure_ttl_blocks, "disclosure ttl blocks")?;
        ensure_non_zero(self.credential_ttl_blocks, "credential ttl blocks")?;
        ensure_non_zero(self.min_anonymity_set_size, "minimum anonymity set size")?;
        ensure_non_zero(self.low_fee_max_sponsored_units, "low fee sponsored units")?;
        if self.max_disclosure_attributes == 0 {
            return Err("max disclosure attributes cannot be zero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("private identity PQ security floor is too low".to_string());
        }
        validate_bps(self.max_risk_score_bps, "max risk score")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialAttributeCommitment {
    pub attribute_id: String,
    pub scope: String,
    pub key_commitment: String,
    pub value_commitment: String,
    pub salt_commitment: String,
    pub disclosure_policy_root: String,
}

impl CredentialAttributeCommitment {
    pub fn new(
        scope: impl Into<String>,
        key: &str,
        value: &str,
        salt: &str,
        disclosure_policy: &Value,
    ) -> PrivateIdentityResult<Self> {
        let scope = normalize_label(&scope.into());
        ensure_non_empty(&scope, "credential attribute scope")?;
        ensure_non_empty(key, "credential attribute key")?;
        ensure_non_empty(value, "credential attribute value")?;
        ensure_non_empty(salt, "credential attribute salt")?;
        let key_commitment = private_identity_commitment("ATTRIBUTE-KEY", &[key, salt]);
        let value_commitment = private_identity_commitment("ATTRIBUTE-VALUE", &[value, salt]);
        let salt_commitment = private_identity_commitment("ATTRIBUTE-SALT", &[salt, &scope]);
        let disclosure_policy_root =
            private_identity_payload_root("PRIVATE-IDENTITY-DISCLOSURE-POLICY", disclosure_policy);
        let attribute_id = domain_hash(
            "PRIVATE-IDENTITY-ATTRIBUTE-ID",
            &[
                HashPart::Str(&scope),
                HashPart::Str(&key_commitment),
                HashPart::Str(&value_commitment),
                HashPart::Str(&disclosure_policy_root),
            ],
            24,
        );
        Ok(Self {
            attribute_id,
            scope,
            key_commitment,
            value_commitment,
            salt_commitment,
            disclosure_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "credential_attribute_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "attribute_id": self.attribute_id,
            "scope": self.scope,
            "key_commitment": self.key_commitment,
            "value_commitment": self.value_commitment,
            "salt_commitment": self.salt_commitment,
            "disclosure_policy_root": self.disclosure_policy_root,
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.attribute_id, "attribute id")?;
        ensure_non_empty(&self.scope, "attribute scope")?;
        ensure_non_empty(&self.key_commitment, "attribute key commitment")?;
        ensure_non_empty(&self.value_commitment, "attribute value commitment")?;
        ensure_non_empty(&self.salt_commitment, "attribute salt commitment")?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "attribute disclosure policy root",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedIdentityCommitment {
    pub identity_id: String,
    pub label_hash: String,
    pub owner_commitment: String,
    pub viewing_commitment: String,
    pub recovery_commitment: String,
    pub spending_domain_root: String,
    pub compliance_anchor: String,
    pub anonymity_set_id: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub last_seen_height: u64,
    pub nonce: u64,
    pub status: PrivateIdentityStatus,
    pub metadata_root: String,
}

impl ShieldedIdentityCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_label: impl Into<String>,
        owner_secret: &str,
        viewing_key: &str,
        recovery_key: &str,
        spending_domain: &str,
        anonymity_set_id: impl Into<String>,
        privacy_set_size: u64,
        created_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> PrivateIdentityResult<Self> {
        let public_label = normalize_label(&public_label.into());
        let anonymity_set_id = normalize_label(&anonymity_set_id.into());
        ensure_non_empty(&public_label, "identity public label")?;
        ensure_non_empty(owner_secret, "identity owner secret")?;
        ensure_non_empty(viewing_key, "identity viewing key")?;
        ensure_non_empty(recovery_key, "identity recovery key")?;
        ensure_non_empty(spending_domain, "identity spending domain")?;
        ensure_non_empty(&anonymity_set_id, "identity anonymity set")?;
        ensure_non_zero(privacy_set_size, "privacy set size")?;
        let label_hash = private_identity_commitment("IDENTITY-LABEL", &[&public_label]);
        let owner_commitment = private_identity_commitment("IDENTITY-OWNER", &[owner_secret]);
        let viewing_commitment = private_identity_commitment("IDENTITY-VIEW", &[viewing_key]);
        let recovery_commitment = private_identity_commitment("IDENTITY-RECOVERY", &[recovery_key]);
        let spending_domain_root =
            private_identity_commitment("IDENTITY-SPENDING-DOMAIN", &[spending_domain]);
        let compliance_anchor = domain_hash(
            "PRIVATE-IDENTITY-COMPLIANCE-ANCHOR",
            &[
                HashPart::Str(&owner_commitment),
                HashPart::Str(&viewing_commitment),
                HashPart::Str(&recovery_commitment),
                HashPart::Str(&spending_domain_root),
                HashPart::Int(created_at_height as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let metadata_root = private_identity_payload_root("PRIVATE-IDENTITY-METADATA", metadata);
        let identity_id = domain_hash(
            "PRIVATE-IDENTITY-ID",
            &[
                HashPart::Str(&label_hash),
                HashPart::Str(&owner_commitment),
                HashPart::Str(&compliance_anchor),
                HashPart::Str(&anonymity_set_id),
                HashPart::Int(created_at_height as i128),
                HashPart::Int(nonce as i128),
            ],
            24,
        );
        let identity = Self {
            identity_id,
            label_hash,
            owner_commitment,
            viewing_commitment,
            recovery_commitment,
            spending_domain_root,
            compliance_anchor,
            anonymity_set_id,
            privacy_set_size,
            created_at_height,
            last_seen_height: created_at_height,
            nonce,
            status: PrivateIdentityStatus::Active,
            metadata_root,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn commitment_root(&self) -> String {
        private_identity_payload_root("PRIVATE-IDENTITY-COMMITMENT", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_identity_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "identity_id": self.identity_id,
            "label_hash": self.label_hash,
            "owner_commitment": self.owner_commitment,
            "viewing_commitment": self.viewing_commitment,
            "recovery_commitment": self.recovery_commitment,
            "spending_domain_root": self.spending_domain_root,
            "compliance_anchor": self.compliance_anchor,
            "anonymity_set_id": self.anonymity_set_id,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "last_seen_height": self.last_seen_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn set_status(&mut self, status: PrivateIdentityStatus, height: u64) {
        self.status = status;
        self.last_seen_height = height;
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.identity_id, "identity id")?;
        ensure_non_empty(&self.label_hash, "identity label hash")?;
        ensure_non_empty(&self.owner_commitment, "identity owner commitment")?;
        ensure_non_empty(&self.viewing_commitment, "identity viewing commitment")?;
        ensure_non_empty(&self.recovery_commitment, "identity recovery commitment")?;
        ensure_non_empty(&self.spending_domain_root, "identity spending domain root")?;
        ensure_non_empty(&self.compliance_anchor, "identity compliance anchor")?;
        ensure_non_empty(&self.anonymity_set_id, "identity anonymity set")?;
        ensure_non_zero(self.privacy_set_size, "identity privacy set size")?;
        if self.last_seen_height < self.created_at_height {
            return Err("identity last seen height cannot precede creation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCredentialIssuer {
    pub issuer_id: String,
    pub issuer_name_hash: String,
    pub operator_commitment: String,
    pub ml_dsa_public_key_commitment: String,
    pub slh_dsa_public_key_commitment: String,
    pub kem_public_key_commitment: String,
    pub credential_kind_root: String,
    pub jurisdiction_root: String,
    pub min_security_bits: u16,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateIdentityStatus,
    pub metadata_root: String,
}

impl PqCredentialIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_name: impl Into<String>,
        operator_secret: &str,
        ml_dsa_public_key: &str,
        slh_dsa_public_key: &str,
        kem_public_key: &str,
        credential_kinds: &[CredentialKind],
        jurisdictions: &[String],
        min_security_bits: u16,
        registered_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateIdentityResult<Self> {
        let issuer_name = normalize_label(&issuer_name.into());
        ensure_non_empty(&issuer_name, "issuer name")?;
        ensure_non_empty(operator_secret, "issuer operator commitment seed")?;
        ensure_non_empty(ml_dsa_public_key, "issuer ML-DSA public key")?;
        ensure_non_empty(slh_dsa_public_key, "issuer SLH-DSA public key")?;
        ensure_non_empty(kem_public_key, "issuer KEM public key")?;
        if credential_kinds.is_empty() {
            return Err("issuer requires at least one credential kind".to_string());
        }
        if jurisdictions.is_empty() {
            return Err("issuer requires at least one jurisdiction".to_string());
        }
        if min_security_bits < 128 {
            return Err("issuer PQ security bits below 128".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= registered_at_height {
            return Err("issuer expiry must be after registration".to_string());
        }
        let issuer_name_hash = private_identity_commitment("ISSUER-NAME", &[&issuer_name]);
        let operator_commitment =
            private_identity_commitment("ISSUER-OPERATOR", &[operator_secret]);
        let ml_dsa_public_key_commitment =
            private_identity_commitment("ISSUER-ML-DSA", &[ml_dsa_public_key]);
        let slh_dsa_public_key_commitment =
            private_identity_commitment("ISSUER-SLH-DSA", &[slh_dsa_public_key]);
        let kem_public_key_commitment =
            private_identity_commitment("ISSUER-KEM", &[kem_public_key]);
        let credential_kind_root = credential_kind_root(credential_kinds);
        let jurisdiction_root =
            private_identity_string_set_root("PRIVATE-IDENTITY-ISSUER-JURISDICTION", jurisdictions);
        let metadata_root =
            private_identity_payload_root("PRIVATE-IDENTITY-ISSUER-METADATA", metadata);
        let issuer_id = domain_hash(
            "PRIVATE-IDENTITY-ISSUER-ID",
            &[
                HashPart::Str(&issuer_name_hash),
                HashPart::Str(&operator_commitment),
                HashPart::Str(&ml_dsa_public_key_commitment),
                HashPart::Str(&slh_dsa_public_key_commitment),
                HashPart::Str(&credential_kind_root),
            ],
            24,
        );
        let issuer = Self {
            issuer_id,
            issuer_name_hash,
            operator_commitment,
            ml_dsa_public_key_commitment,
            slh_dsa_public_key_commitment,
            kem_public_key_commitment,
            credential_kind_root,
            jurisdiction_root,
            min_security_bits,
            registered_at_height,
            expires_at_height,
            status: PrivateIdentityStatus::Active,
            metadata_root,
        };
        issuer.validate()?;
        Ok(issuer)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_credential_issuer",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "issuer_id": self.issuer_id,
            "issuer_name_hash": self.issuer_name_hash,
            "operator_commitment": self.operator_commitment,
            "ml_dsa_public_key_commitment": self.ml_dsa_public_key_commitment,
            "slh_dsa_public_key_commitment": self.slh_dsa_public_key_commitment,
            "kem_public_key_commitment": self.kem_public_key_commitment,
            "credential_kind_root": self.credential_kind_root,
            "jurisdiction_root": self.jurisdiction_root,
            "min_security_bits": self.min_security_bits,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.issuer_id, "issuer id")?;
        ensure_non_empty(&self.operator_commitment, "issuer operator commitment")?;
        ensure_non_empty(
            &self.ml_dsa_public_key_commitment,
            "issuer ML-DSA key commitment",
        )?;
        ensure_non_empty(
            &self.slh_dsa_public_key_commitment,
            "issuer SLH-DSA key commitment",
        )?;
        ensure_non_empty(&self.kem_public_key_commitment, "issuer KEM key commitment")?;
        ensure_non_empty(&self.credential_kind_root, "issuer credential kind root")?;
        ensure_non_empty(&self.jurisdiction_root, "issuer jurisdiction root")?;
        if self.min_security_bits < 128 {
            return Err("issuer PQ security bits below 128".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.registered_at_height {
            return Err("issuer expiry must be after registration".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCredential {
    pub credential_id: String,
    pub issuer_id: String,
    pub subject_identity_id: String,
    pub subject_commitment: String,
    pub credential_kind: CredentialKind,
    pub attribute_root: String,
    pub hidden_attribute_root: String,
    pub selective_disclosure_root: String,
    pub revocation_registry_id: String,
    pub nullifier_registry_id: String,
    pub assurance_level: u8,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: CredentialStatus,
    pub metadata_root: String,
}

impl ShieldedCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: &PqCredentialIssuer,
        subject: &ShieldedIdentityCommitment,
        credential_kind: CredentialKind,
        attributes: &[CredentialAttributeCommitment],
        hidden_attributes: &[CredentialAttributeCommitment],
        revocation_registry_id: impl Into<String>,
        nullifier_registry_id: impl Into<String>,
        assurance_level: u8,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> PrivateIdentityResult<Self> {
        issuer.validate()?;
        subject.validate()?;
        if !subject.status.is_live() {
            return Err("credential subject identity is not live".to_string());
        }
        if assurance_level == 0 {
            return Err("credential assurance level cannot be zero".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= issued_at_height {
            return Err("credential expiry must be after issuance".to_string());
        }
        if attributes.is_empty() && hidden_attributes.is_empty() {
            return Err("credential requires at least one attribute commitment".to_string());
        }
        let revocation_registry_id = revocation_registry_id.into();
        let nullifier_registry_id = nullifier_registry_id.into();
        ensure_non_empty(&revocation_registry_id, "credential revocation registry")?;
        ensure_non_empty(&nullifier_registry_id, "credential nullifier registry")?;
        for attribute in attributes.iter().chain(hidden_attributes.iter()) {
            attribute.validate()?;
        }
        let attribute_root = credential_attribute_root(attributes);
        let hidden_attribute_root = credential_attribute_root(hidden_attributes);
        let selective_disclosure_root = private_identity_payload_root(
            "PRIVATE-IDENTITY-SELECTIVE-DISCLOSURE",
            &json!({
                "attribute_root": attribute_root,
                "hidden_attribute_root": hidden_attribute_root,
                "assurance_level": assurance_level,
                "credential_kind": credential_kind.as_str(),
            }),
        );
        let metadata_root =
            private_identity_payload_root("PRIVATE-IDENTITY-CREDENTIAL-METADATA", metadata);
        let subject_commitment = subject.commitment_root();
        let credential_id = domain_hash(
            "PRIVATE-IDENTITY-CREDENTIAL-ID",
            &[
                HashPart::Str(&issuer.issuer_id),
                HashPart::Str(&subject.identity_id),
                HashPart::Str(&subject_commitment),
                HashPart::Str(&credential_kind.as_str()),
                HashPart::Int(issued_at_height as i128),
                HashPart::Int(nonce as i128),
            ],
            24,
        );
        let credential = Self {
            credential_id,
            issuer_id: issuer.issuer_id.clone(),
            subject_identity_id: subject.identity_id.clone(),
            subject_commitment,
            credential_kind,
            attribute_root,
            hidden_attribute_root,
            selective_disclosure_root,
            revocation_registry_id,
            nullifier_registry_id,
            assurance_level,
            issued_at_height,
            expires_at_height,
            nonce,
            status: CredentialStatus::Active,
            metadata_root,
        };
        credential.validate()?;
        Ok(credential)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_credential",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "credential_id": self.credential_id,
            "issuer_id": self.issuer_id,
            "subject_identity_id": self.subject_identity_id,
            "subject_commitment": self.subject_commitment,
            "credential_kind": self.credential_kind.as_str(),
            "attribute_root": self.attribute_root,
            "hidden_attribute_root": self.hidden_attribute_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "revocation_registry_id": self.revocation_registry_id,
            "nullifier_registry_id": self.nullifier_registry_id,
            "assurance_level": self.assurance_level,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.credential_id, "credential id")?;
        ensure_non_empty(&self.issuer_id, "credential issuer id")?;
        ensure_non_empty(&self.subject_identity_id, "credential subject identity")?;
        ensure_non_empty(&self.subject_commitment, "credential subject commitment")?;
        ensure_non_empty(&self.attribute_root, "credential attribute root")?;
        ensure_non_empty(
            &self.hidden_attribute_root,
            "credential hidden attribute root",
        )?;
        ensure_non_empty(
            &self.selective_disclosure_root,
            "credential disclosure root",
        )?;
        ensure_non_empty(
            &self.revocation_registry_id,
            "credential revocation registry",
        )?;
        ensure_non_empty(&self.nullifier_registry_id, "credential nullifier registry")?;
        if self.assurance_level == 0 {
            return Err("credential assurance level cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.issued_at_height {
            return Err("credential expiry must be after issuance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkCredentialProof {
    pub proof_id: String,
    pub credential_id: String,
    pub subject_identity_id: String,
    pub verifier_domain: String,
    pub credential_kind: CredentialKind,
    pub disclosed_claim_root: String,
    pub hidden_claim_root: String,
    pub nullifier: String,
    pub revocation_checkpoint_root: String,
    pub issuer_attestation_root: String,
    pub proof_system: String,
    pub proof_bytes: u64,
    pub min_assurance_level: u8,
    pub generated_at_height: u64,
    pub expires_at_height: u64,
    pub status: ProofStatus,
}

impl ZkCredentialProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential: &ShieldedCredential,
        verifier_domain: impl Into<String>,
        disclosed_claim: &Value,
        hidden_claim: &Value,
        nullifier_seed: &str,
        revocation_checkpoint_root: impl Into<String>,
        issuer_attestation_root: impl Into<String>,
        min_assurance_level: u8,
        generated_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        credential.validate()?;
        if !credential.status.is_usable() {
            return Err("credential proof requires a usable credential".to_string());
        }
        let verifier_domain = normalize_label(&verifier_domain.into());
        ensure_non_empty(&verifier_domain, "proof verifier domain")?;
        ensure_non_empty(nullifier_seed, "proof nullifier seed")?;
        if min_assurance_level == 0 {
            return Err("proof minimum assurance level cannot be zero".to_string());
        }
        if credential.assurance_level < min_assurance_level {
            return Err("credential assurance level below proof requirement".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= generated_at_height {
            return Err("proof expiry must be after generation".to_string());
        }
        if credential.expires_at_height != 0 && expires_at_height > credential.expires_at_height {
            return Err("proof expiry cannot exceed credential expiry".to_string());
        }
        let disclosed_claim_root =
            private_identity_payload_root("PRIVATE-IDENTITY-DISCLOSED-CLAIM", disclosed_claim);
        let hidden_claim_root =
            private_identity_payload_root("PRIVATE-IDENTITY-HIDDEN-CLAIM", hidden_claim);
        let revocation_checkpoint_root = revocation_checkpoint_root.into();
        let issuer_attestation_root = issuer_attestation_root.into();
        ensure_non_empty(
            &revocation_checkpoint_root,
            "proof revocation checkpoint root",
        )?;
        ensure_non_empty(&issuer_attestation_root, "proof issuer attestation root")?;
        let nullifier = credential_nullifier(
            &credential.credential_id,
            &credential.subject_commitment,
            &verifier_domain,
            nullifier_seed,
        );
        let proof_id = domain_hash(
            "PRIVATE-IDENTITY-ZK-CREDENTIAL-PROOF-ID",
            &[
                HashPart::Str(&credential.credential_id),
                HashPart::Str(&credential.subject_identity_id),
                HashPart::Str(&verifier_domain),
                HashPart::Str(&disclosed_claim_root),
                HashPart::Str(&hidden_claim_root),
                HashPart::Str(&nullifier),
                HashPart::Int(generated_at_height as i128),
            ],
            24,
        );
        let proof = Self {
            proof_id,
            credential_id: credential.credential_id.clone(),
            subject_identity_id: credential.subject_identity_id.clone(),
            verifier_domain,
            credential_kind: credential.credential_kind.clone(),
            disclosed_claim_root,
            hidden_claim_root,
            nullifier,
            revocation_checkpoint_root,
            issuer_attestation_root,
            proof_system: PRIVATE_IDENTITY_ZK_PROOF_SYSTEM.to_string(),
            proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
            min_assurance_level,
            generated_at_height,
            expires_at_height,
            status: ProofStatus::Verified,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_credential_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "credential_id": self.credential_id,
            "subject_identity_id": self.subject_identity_id,
            "verifier_domain": self.verifier_domain,
            "credential_kind": self.credential_kind.as_str(),
            "disclosed_claim_root": self.disclosed_claim_root,
            "hidden_claim_root": self.hidden_claim_root,
            "nullifier": self.nullifier,
            "revocation_checkpoint_root": self.revocation_checkpoint_root,
            "issuer_attestation_root": self.issuer_attestation_root,
            "proof_system": self.proof_system,
            "proof_bytes": self.proof_bytes,
            "min_assurance_level": self.min_assurance_level,
            "generated_at_height": self.generated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.proof_id, "proof id")?;
        ensure_non_empty(&self.credential_id, "proof credential id")?;
        ensure_non_empty(&self.subject_identity_id, "proof subject identity")?;
        ensure_non_empty(&self.verifier_domain, "proof verifier domain")?;
        ensure_non_empty(&self.disclosed_claim_root, "proof disclosed claim root")?;
        ensure_non_empty(&self.hidden_claim_root, "proof hidden claim root")?;
        ensure_non_empty(&self.nullifier, "proof nullifier")?;
        ensure_non_empty(
            &self.revocation_checkpoint_root,
            "proof revocation checkpoint root",
        )?;
        ensure_non_empty(
            &self.issuer_attestation_root,
            "proof issuer attestation root",
        )?;
        ensure_non_empty(&self.proof_system, "proof system")?;
        if self.min_assurance_level == 0 {
            return Err("proof minimum assurance level cannot be zero".to_string());
        }
        if self.proof_bytes == 0 {
            return Err("proof byte size cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.generated_at_height {
            return Err("proof expiry must be after generation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialNullifierRecord {
    pub nullifier: String,
    pub credential_id: String,
    pub subject_identity_id: String,
    pub verifier_domain: String,
    pub action_scope: String,
    pub epoch: u64,
    pub first_seen_height: u64,
    pub proof_id: String,
    pub status: RegistryStatus,
}

impl CredentialNullifierRecord {
    pub fn from_proof(
        proof: &ZkCredentialProof,
        action_scope: impl Into<String>,
        epoch: u64,
        first_seen_height: u64,
    ) -> PrivateIdentityResult<Self> {
        proof.validate()?;
        let action_scope = normalize_label(&action_scope.into());
        ensure_non_empty(&action_scope, "nullifier action scope")?;
        Ok(Self {
            nullifier: proof.nullifier.clone(),
            credential_id: proof.credential_id.clone(),
            subject_identity_id: proof.subject_identity_id.clone(),
            verifier_domain: proof.verifier_domain.clone(),
            action_scope,
            epoch,
            first_seen_height,
            proof_id: proof.proof_id.clone(),
            status: RegistryStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "credential_nullifier_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "nullifier": self.nullifier,
            "credential_id": self.credential_id,
            "subject_identity_id": self.subject_identity_id,
            "verifier_domain": self.verifier_domain,
            "action_scope": self.action_scope,
            "epoch": self.epoch,
            "first_seen_height": self.first_seen_height,
            "proof_id": self.proof_id,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.nullifier, "nullifier")?;
        ensure_non_empty(&self.credential_id, "nullifier credential id")?;
        ensure_non_empty(&self.subject_identity_id, "nullifier subject identity")?;
        ensure_non_empty(&self.verifier_domain, "nullifier verifier domain")?;
        ensure_non_empty(&self.action_scope, "nullifier action scope")?;
        ensure_non_empty(&self.proof_id, "nullifier proof id")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialNullifierRegistry {
    pub registry_id: String,
    pub registry_scope: String,
    pub epoch: u64,
    pub nullifier_root: String,
    pub spent_count: u64,
    pub replay_window_blocks: u64,
    pub updated_at_height: u64,
    pub status: RegistryStatus,
}

impl CredentialNullifierRegistry {
    pub fn from_nullifiers(
        registry_scope: impl Into<String>,
        epoch: u64,
        nullifiers: &[CredentialNullifierRecord],
        replay_window_blocks: u64,
        updated_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        let registry_scope = normalize_label(&registry_scope.into());
        ensure_non_empty(&registry_scope, "nullifier registry scope")?;
        ensure_non_zero(replay_window_blocks, "nullifier replay window")?;
        for nullifier in nullifiers {
            nullifier.validate()?;
        }
        let nullifier_root = private_identity_nullifier_root(nullifiers);
        let registry_id = domain_hash(
            "PRIVATE-IDENTITY-NULLIFIER-REGISTRY-ID",
            &[
                HashPart::Str(&registry_scope),
                HashPart::Int(epoch as i128),
                HashPart::Str(&nullifier_root),
            ],
            24,
        );
        Ok(Self {
            registry_id,
            registry_scope,
            epoch,
            nullifier_root,
            spent_count: nullifiers.len() as u64,
            replay_window_blocks,
            updated_at_height,
            status: RegistryStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "credential_nullifier_registry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "registry_id": self.registry_id,
            "registry_scope": self.registry_scope,
            "epoch": self.epoch,
            "nullifier_root": self.nullifier_root,
            "spent_count": self.spent_count,
            "replay_window_blocks": self.replay_window_blocks,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.registry_id, "nullifier registry id")?;
        ensure_non_empty(&self.registry_scope, "nullifier registry scope")?;
        ensure_non_empty(&self.nullifier_root, "nullifier registry root")?;
        ensure_non_zero(self.replay_window_blocks, "nullifier replay window")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRevocationRecord {
    pub revocation_id: String,
    pub credential_id: String,
    pub issuer_id: String,
    pub registry_id: String,
    pub reason_code_commitment: String,
    pub evidence_root: String,
    pub revoked_at_height: u64,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub status: CredentialStatus,
}

impl CredentialRevocationRecord {
    pub fn new(
        credential: &ShieldedCredential,
        registry_id: impl Into<String>,
        reason_code: &str,
        evidence: &Value,
        revoked_at_height: u64,
        effective_at_height: u64,
        expires_at_height: u64,
        status: CredentialStatus,
    ) -> PrivateIdentityResult<Self> {
        credential.validate()?;
        let registry_id = registry_id.into();
        ensure_non_empty(&registry_id, "revocation registry id")?;
        ensure_non_empty(reason_code, "revocation reason code")?;
        if effective_at_height < revoked_at_height {
            return Err("revocation effective height cannot precede revoked height".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= effective_at_height {
            return Err("revocation expiry must be after effective height".to_string());
        }
        if !matches!(
            status,
            CredentialStatus::Suspended | CredentialStatus::Revoked | CredentialStatus::Expired
        ) {
            return Err("revocation status must suspend, revoke, or expire".to_string());
        }
        let reason_code_commitment =
            private_identity_commitment("REVOCATION-REASON", &[reason_code]);
        let evidence_root =
            private_identity_payload_root("PRIVATE-IDENTITY-REVOCATION-EVIDENCE", evidence);
        let revocation_id = domain_hash(
            "PRIVATE-IDENTITY-REVOCATION-ID",
            &[
                HashPart::Str(&credential.credential_id),
                HashPart::Str(&credential.issuer_id),
                HashPart::Str(&registry_id),
                HashPart::Str(&reason_code_commitment),
                HashPart::Int(revoked_at_height as i128),
            ],
            24,
        );
        Ok(Self {
            revocation_id,
            credential_id: credential.credential_id.clone(),
            issuer_id: credential.issuer_id.clone(),
            registry_id,
            reason_code_commitment,
            evidence_root,
            revoked_at_height,
            effective_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "credential_revocation_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "revocation_id": self.revocation_id,
            "credential_id": self.credential_id,
            "issuer_id": self.issuer_id,
            "registry_id": self.registry_id,
            "reason_code_commitment": self.reason_code_commitment,
            "evidence_root": self.evidence_root,
            "revoked_at_height": self.revoked_at_height,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.revocation_id, "revocation id")?;
        ensure_non_empty(&self.credential_id, "revocation credential id")?;
        ensure_non_empty(&self.issuer_id, "revocation issuer id")?;
        ensure_non_empty(&self.registry_id, "revocation registry id")?;
        ensure_non_empty(&self.reason_code_commitment, "revocation reason commitment")?;
        ensure_non_empty(&self.evidence_root, "revocation evidence root")?;
        if self.effective_at_height < self.revoked_at_height {
            return Err("revocation effective height cannot precede revoked height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRevocationRegistry {
    pub registry_id: String,
    pub issuer_id: String,
    pub credential_kind: CredentialKind,
    pub revoked_root: String,
    pub suspended_root: String,
    pub revoked_count: u64,
    pub suspended_count: u64,
    pub epoch: u64,
    pub updated_at_height: u64,
    pub status: RegistryStatus,
}

impl CredentialRevocationRegistry {
    pub fn from_records(
        issuer_id: impl Into<String>,
        credential_kind: CredentialKind,
        epoch: u64,
        revocations: &[CredentialRevocationRecord],
        updated_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        let issuer_id = issuer_id.into();
        ensure_non_empty(&issuer_id, "revocation registry issuer")?;
        for revocation in revocations {
            revocation.validate()?;
            if revocation.issuer_id != issuer_id {
                return Err("revocation registry contains foreign issuer record".to_string());
            }
        }
        let revoked = revocations
            .iter()
            .filter(|record| record.status == CredentialStatus::Revoked)
            .cloned()
            .collect::<Vec<_>>();
        let suspended = revocations
            .iter()
            .filter(|record| record.status == CredentialStatus::Suspended)
            .cloned()
            .collect::<Vec<_>>();
        let revoked_root = private_identity_revocation_root(&revoked);
        let suspended_root = private_identity_revocation_root(&suspended);
        let registry_id = domain_hash(
            "PRIVATE-IDENTITY-REVOCATION-REGISTRY-ID",
            &[
                HashPart::Str(&issuer_id),
                HashPart::Str(&credential_kind.as_str()),
                HashPart::Int(epoch as i128),
                HashPart::Str(&revoked_root),
                HashPart::Str(&suspended_root),
            ],
            24,
        );
        Ok(Self {
            registry_id,
            issuer_id,
            credential_kind,
            revoked_root,
            suspended_root,
            revoked_count: revoked.len() as u64,
            suspended_count: suspended.len() as u64,
            epoch,
            updated_at_height,
            status: RegistryStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "credential_revocation_registry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "registry_id": self.registry_id,
            "issuer_id": self.issuer_id,
            "credential_kind": self.credential_kind.as_str(),
            "revoked_root": self.revoked_root,
            "suspended_root": self.suspended_root,
            "revoked_count": self.revoked_count,
            "suspended_count": self.suspended_count,
            "epoch": self.epoch,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.registry_id, "revocation registry id")?;
        ensure_non_empty(&self.issuer_id, "revocation registry issuer")?;
        ensure_non_empty(&self.revoked_root, "revocation revoked root")?;
        ensure_non_empty(&self.suspended_root, "revocation suspended root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingCommitteeMember {
    pub member_id: String,
    pub committee_id: String,
    pub operator_commitment: String,
    pub pq_view_key_commitment: String,
    pub jurisdiction_root: String,
    pub allowed_purpose_root: String,
    pub quorum_weight: u64,
    pub joined_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateIdentityStatus,
}

impl ViewingCommitteeMember {
    pub fn new(
        committee_id: impl Into<String>,
        operator_secret: &str,
        pq_view_key: &str,
        jurisdictions: &[String],
        purposes: &[DisclosurePurpose],
        quorum_weight: u64,
        joined_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        let committee_id = normalize_label(&committee_id.into());
        ensure_non_empty(&committee_id, "viewing committee id")?;
        ensure_non_empty(operator_secret, "viewing committee operator secret")?;
        ensure_non_empty(pq_view_key, "viewing committee PQ view key")?;
        ensure_non_zero(quorum_weight, "viewing committee quorum weight")?;
        if jurisdictions.is_empty() {
            return Err("viewing committee member requires a jurisdiction root".to_string());
        }
        if purposes.is_empty() {
            return Err("viewing committee member requires at least one purpose".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= joined_at_height {
            return Err("viewing committee member expiry must be after join height".to_string());
        }
        let operator_commitment =
            private_identity_commitment("VIEWING-COMMITTEE-OPERATOR", &[operator_secret]);
        let pq_view_key_commitment =
            private_identity_commitment("VIEWING-COMMITTEE-PQ-KEY", &[pq_view_key]);
        let jurisdiction_root =
            private_identity_string_set_root("PRIVATE-IDENTITY-VIEW-JURISDICTION", jurisdictions);
        let allowed_purpose_root = disclosure_purpose_root(purposes);
        let member_id = domain_hash(
            "PRIVATE-IDENTITY-VIEW-COMMITTEE-MEMBER-ID",
            &[
                HashPart::Str(&committee_id),
                HashPart::Str(&operator_commitment),
                HashPart::Str(&pq_view_key_commitment),
                HashPart::Int(joined_at_height as i128),
            ],
            24,
        );
        Ok(Self {
            member_id,
            committee_id,
            operator_commitment,
            pq_view_key_commitment,
            jurisdiction_root,
            allowed_purpose_root,
            quorum_weight,
            joined_at_height,
            expires_at_height,
            status: PrivateIdentityStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "viewing_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "operator_commitment": self.operator_commitment,
            "pq_view_key_commitment": self.pq_view_key_commitment,
            "jurisdiction_root": self.jurisdiction_root,
            "allowed_purpose_root": self.allowed_purpose_root,
            "quorum_weight": self.quorum_weight,
            "joined_at_height": self.joined_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.member_id, "viewing committee member id")?;
        ensure_non_empty(&self.committee_id, "viewing committee id")?;
        ensure_non_empty(
            &self.operator_commitment,
            "viewing committee operator commitment",
        )?;
        ensure_non_empty(
            &self.pq_view_key_commitment,
            "viewing committee PQ view key commitment",
        )?;
        ensure_non_empty(
            &self.jurisdiction_root,
            "viewing committee jurisdiction root",
        )?;
        ensure_non_empty(&self.allowed_purpose_root, "viewing committee purpose root")?;
        ensure_non_zero(self.quorum_weight, "viewing committee quorum weight")?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.joined_at_height {
            return Err("viewing committee member expiry must be after join height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingDisclosure {
    pub disclosure_id: String,
    pub identity_id: String,
    pub credential_id: Option<String>,
    pub committee_id: String,
    pub purpose: DisclosurePurpose,
    pub disclosed_claim_root: String,
    pub encrypted_payload_root: String,
    pub viewer_policy_root: String,
    pub authorized_member_root: String,
    pub proof_id: String,
    pub sponsor_id: Option<String>,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub status: DisclosureStatus,
}

impl ViewingDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_id: impl Into<String>,
        credential_id: Option<String>,
        committee_id: impl Into<String>,
        purpose: DisclosurePurpose,
        disclosed_claim: &Value,
        encrypted_payload: &Value,
        viewer_policy: &Value,
        authorized_members: &[ViewingCommitteeMember],
        proof_id: impl Into<String>,
        sponsor_id: Option<String>,
        requested_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        let identity_id = identity_id.into();
        let committee_id = normalize_label(&committee_id.into());
        let proof_id = proof_id.into();
        ensure_non_empty(&identity_id, "viewing disclosure identity id")?;
        ensure_non_empty(&committee_id, "viewing disclosure committee id")?;
        ensure_non_empty(&proof_id, "viewing disclosure proof id")?;
        if authorized_members.is_empty() {
            return Err("viewing disclosure requires authorized committee members".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= requested_at_height {
            return Err("viewing disclosure expiry must be after request height".to_string());
        }
        for member in authorized_members {
            member.validate()?;
            if member.committee_id != committee_id {
                return Err("viewing disclosure contains member from another committee".to_string());
            }
        }
        let disclosed_claim_root =
            private_identity_payload_root("PRIVATE-IDENTITY-DISCLOSURE-CLAIM", disclosed_claim);
        let encrypted_payload_root = private_identity_payload_root(
            "PRIVATE-IDENTITY-DISCLOSURE-ENCRYPTED-PAYLOAD",
            encrypted_payload,
        );
        let viewer_policy_root =
            private_identity_payload_root("PRIVATE-IDENTITY-VIEWER-POLICY", viewer_policy);
        let authorized_member_root = viewing_committee_member_root(authorized_members);
        let disclosure_id = domain_hash(
            "PRIVATE-IDENTITY-VIEWING-DISCLOSURE-ID",
            &[
                HashPart::Str(&identity_id),
                HashPart::Str(credential_id.as_deref().unwrap_or("none")),
                HashPart::Str(&committee_id),
                HashPart::Str(&purpose.as_str()),
                HashPart::Str(&disclosed_claim_root),
                HashPart::Str(&authorized_member_root),
                HashPart::Int(requested_at_height as i128),
            ],
            24,
        );
        Ok(Self {
            disclosure_id,
            identity_id,
            credential_id,
            committee_id,
            purpose,
            disclosed_claim_root,
            encrypted_payload_root,
            viewer_policy_root,
            authorized_member_root,
            proof_id,
            sponsor_id,
            requested_at_height,
            expires_at_height,
            status: DisclosureStatus::Approved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "viewing_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "identity_id": self.identity_id,
            "credential_id": self.credential_id,
            "committee_id": self.committee_id,
            "purpose": self.purpose.as_str(),
            "disclosed_claim_root": self.disclosed_claim_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "viewer_policy_root": self.viewer_policy_root,
            "authorized_member_root": self.authorized_member_root,
            "proof_id": self.proof_id,
            "sponsor_id": self.sponsor_id,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.disclosure_id, "viewing disclosure id")?;
        ensure_non_empty(&self.identity_id, "viewing disclosure identity id")?;
        ensure_non_empty(&self.committee_id, "viewing disclosure committee id")?;
        ensure_non_empty(&self.disclosed_claim_root, "viewing disclosure claim root")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "viewing disclosure encrypted payload root",
        )?;
        ensure_non_empty(
            &self.viewer_policy_root,
            "viewing disclosure viewer policy root",
        )?;
        ensure_non_empty(
            &self.authorized_member_root,
            "viewing disclosure member root",
        )?;
        ensure_non_empty(&self.proof_id, "viewing disclosure proof id")?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.requested_at_height {
            return Err("viewing disclosure expiry must be after request height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiEligibilityGate {
    pub gate_id: String,
    pub market_id: String,
    pub gate_kind: DefiGateKind,
    pub required_credential_kind: CredentialKind,
    pub min_assurance_level: u8,
    pub min_age_years: Option<u16>,
    pub max_risk_score_bps: u64,
    pub required_region_root: String,
    pub excluded_region_root: String,
    pub accepted_issuer_root: String,
    pub low_fee_lane: String,
    pub created_at_height: u64,
    pub status: PrivateIdentityStatus,
    pub metadata_root: String,
}

impl DefiEligibilityGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        gate_kind: DefiGateKind,
        required_credential_kind: CredentialKind,
        min_assurance_level: u8,
        min_age_years: Option<u16>,
        max_risk_score_bps: u64,
        required_regions: &[String],
        excluded_regions: &[String],
        accepted_issuers: &[String],
        low_fee_lane: impl Into<String>,
        created_at_height: u64,
        metadata: &Value,
    ) -> PrivateIdentityResult<Self> {
        let market_id = normalize_label(&market_id.into());
        let low_fee_lane = normalize_label(&low_fee_lane.into());
        ensure_non_empty(&market_id, "DeFi gate market id")?;
        ensure_non_empty(&low_fee_lane, "DeFi gate low fee lane")?;
        if min_assurance_level == 0 {
            return Err("DeFi gate minimum assurance cannot be zero".to_string());
        }
        validate_bps(max_risk_score_bps, "DeFi gate max risk score")?;
        if accepted_issuers.is_empty() {
            return Err("DeFi gate requires at least one accepted issuer".to_string());
        }
        let required_region_root = private_identity_string_set_root(
            "PRIVATE-IDENTITY-GATE-REQUIRED-REGION",
            required_regions,
        );
        let excluded_region_root = private_identity_string_set_root(
            "PRIVATE-IDENTITY-GATE-EXCLUDED-REGION",
            excluded_regions,
        );
        let accepted_issuer_root = private_identity_string_set_root(
            "PRIVATE-IDENTITY-GATE-ACCEPTED-ISSUER",
            accepted_issuers,
        );
        let metadata_root =
            private_identity_payload_root("PRIVATE-IDENTITY-GATE-METADATA", metadata);
        let gate_id = domain_hash(
            "PRIVATE-IDENTITY-DEFI-GATE-ID",
            &[
                HashPart::Str(&market_id),
                HashPart::Str(gate_kind.as_str()),
                HashPart::Str(&required_credential_kind.as_str()),
                HashPart::Int(min_assurance_level as i128),
                HashPart::Str(&accepted_issuer_root),
                HashPart::Int(created_at_height as i128),
            ],
            24,
        );
        Ok(Self {
            gate_id,
            market_id,
            gate_kind,
            required_credential_kind,
            min_assurance_level,
            min_age_years,
            max_risk_score_bps,
            required_region_root,
            excluded_region_root,
            accepted_issuer_root,
            low_fee_lane,
            created_at_height,
            status: PrivateIdentityStatus::Active,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_eligibility_gate",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "gate_id": self.gate_id,
            "market_id": self.market_id,
            "gate_kind": self.gate_kind.as_str(),
            "required_credential_kind": self.required_credential_kind.as_str(),
            "min_assurance_level": self.min_assurance_level,
            "min_age_years": self.min_age_years,
            "max_risk_score_bps": self.max_risk_score_bps,
            "required_region_root": self.required_region_root,
            "excluded_region_root": self.excluded_region_root,
            "accepted_issuer_root": self.accepted_issuer_root,
            "low_fee_lane": self.low_fee_lane,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.gate_id, "DeFi gate id")?;
        ensure_non_empty(&self.market_id, "DeFi gate market id")?;
        ensure_non_empty(&self.required_region_root, "DeFi gate required region root")?;
        ensure_non_empty(&self.excluded_region_root, "DeFi gate excluded region root")?;
        ensure_non_empty(&self.accepted_issuer_root, "DeFi gate accepted issuer root")?;
        ensure_non_empty(&self.low_fee_lane, "DeFi gate low fee lane")?;
        if self.min_assurance_level == 0 {
            return Err("DeFi gate minimum assurance cannot be zero".to_string());
        }
        validate_bps(self.max_risk_score_bps, "DeFi gate max risk score")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiEligibilityGrant {
    pub grant_id: String,
    pub gate_id: String,
    pub identity_commitment: String,
    pub credential_proof_id: String,
    pub risk_tag_root: String,
    pub nullifier: String,
    pub max_notional_units: u64,
    pub fee_tier_bps: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateIdentityStatus,
}

impl DefiEligibilityGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gate: &DefiEligibilityGate,
        identity: &ShieldedIdentityCommitment,
        proof: &ZkCredentialProof,
        risk_tags: &[PrivacyPreservingRiskTag],
        max_notional_units: u64,
        fee_tier_bps: u64,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        gate.validate()?;
        identity.validate()?;
        proof.validate()?;
        ensure_non_zero(max_notional_units, "DeFi grant max notional units")?;
        validate_bps(fee_tier_bps, "DeFi grant fee tier")?;
        if proof.min_assurance_level < gate.min_assurance_level {
            return Err("DeFi grant proof assurance below gate requirement".to_string());
        }
        if proof.credential_kind.as_str() != gate.required_credential_kind.as_str() {
            return Err("DeFi grant proof credential kind does not satisfy gate".to_string());
        }
        if proof.subject_identity_id != identity.identity_id {
            return Err("DeFi grant proof subject does not match identity".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= valid_from_height {
            return Err("DeFi grant expiry must be after valid-from height".to_string());
        }
        for tag in risk_tags {
            tag.validate()?;
        }
        let risk_tag_root = privacy_risk_tag_root(risk_tags);
        let identity_commitment = identity.commitment_root();
        let grant_id = domain_hash(
            "PRIVATE-IDENTITY-DEFI-GRANT-ID",
            &[
                HashPart::Str(&gate.gate_id),
                HashPart::Str(&identity_commitment),
                HashPart::Str(&proof.proof_id),
                HashPart::Str(&proof.nullifier),
                HashPart::Int(valid_from_height as i128),
            ],
            24,
        );
        Ok(Self {
            grant_id,
            gate_id: gate.gate_id.clone(),
            identity_commitment,
            credential_proof_id: proof.proof_id.clone(),
            risk_tag_root,
            nullifier: proof.nullifier.clone(),
            max_notional_units,
            fee_tier_bps,
            valid_from_height,
            expires_at_height,
            status: PrivateIdentityStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_eligibility_grant",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "grant_id": self.grant_id,
            "gate_id": self.gate_id,
            "identity_commitment": self.identity_commitment,
            "credential_proof_id": self.credential_proof_id,
            "risk_tag_root": self.risk_tag_root,
            "nullifier": self.nullifier,
            "max_notional_units": self.max_notional_units,
            "fee_tier_bps": self.fee_tier_bps,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.grant_id, "DeFi grant id")?;
        ensure_non_empty(&self.gate_id, "DeFi grant gate id")?;
        ensure_non_empty(&self.identity_commitment, "DeFi grant identity commitment")?;
        ensure_non_empty(&self.credential_proof_id, "DeFi grant proof id")?;
        ensure_non_empty(&self.risk_tag_root, "DeFi grant risk tag root")?;
        ensure_non_empty(&self.nullifier, "DeFi grant nullifier")?;
        ensure_non_zero(self.max_notional_units, "DeFi grant max notional")?;
        validate_bps(self.fee_tier_bps, "DeFi grant fee tier")?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.valid_from_height {
            return Err("DeFi grant expiry must be after valid-from height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqIssuerAttestation {
    pub attestation_id: String,
    pub issuer_id: String,
    pub committee_id: String,
    pub credential_kind: CredentialKind,
    pub epoch: u64,
    pub subject_root: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateIdentityStatus,
}

impl PqIssuerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: &PqCredentialIssuer,
        committee_id: impl Into<String>,
        credential_kind: CredentialKind,
        epoch: u64,
        subject: &Value,
        attestation: &Value,
        signature_material: &str,
        transcript: &Value,
        security_bits: u16,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        issuer.validate()?;
        let committee_id = normalize_label(&committee_id.into());
        ensure_non_empty(&committee_id, "PQ issuer attestation committee")?;
        ensure_non_empty(signature_material, "PQ issuer signature material")?;
        if security_bits < issuer.min_security_bits {
            return Err("PQ issuer attestation security below issuer floor".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= issued_at_height {
            return Err("PQ issuer attestation expiry must be after issuance".to_string());
        }
        let subject_root = private_identity_payload_root("PRIVATE-IDENTITY-PQ-SUBJECT", subject);
        let attestation_root =
            private_identity_payload_root("PRIVATE-IDENTITY-PQ-ATTESTATION", attestation);
        let signature_root =
            private_identity_commitment("PQ-ISSUER-ATTESTATION-SIGNATURE", &[signature_material]);
        let transcript_root =
            private_identity_payload_root("PRIVATE-IDENTITY-PQ-TRANSCRIPT", transcript);
        let attestation_id = domain_hash(
            "PRIVATE-IDENTITY-PQ-ISSUER-ATTESTATION-ID",
            &[
                HashPart::Str(&issuer.issuer_id),
                HashPart::Str(&committee_id),
                HashPart::Str(&credential_kind.as_str()),
                HashPart::Int(epoch as i128),
                HashPart::Str(&subject_root),
                HashPart::Str(&attestation_root),
            ],
            24,
        );
        Ok(Self {
            attestation_id,
            issuer_id: issuer.issuer_id.clone(),
            committee_id,
            credential_kind,
            epoch,
            subject_root,
            attestation_root,
            signature_root,
            transcript_root,
            security_bits,
            issued_at_height,
            expires_at_height,
            status: PrivateIdentityStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_issuer_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "issuer_id": self.issuer_id,
            "committee_id": self.committee_id,
            "credential_kind": self.credential_kind.as_str(),
            "epoch": self.epoch,
            "subject_root": self.subject_root,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.attestation_id, "PQ issuer attestation id")?;
        ensure_non_empty(&self.issuer_id, "PQ issuer attestation issuer")?;
        ensure_non_empty(&self.committee_id, "PQ issuer attestation committee")?;
        ensure_non_empty(&self.subject_root, "PQ issuer attestation subject root")?;
        ensure_non_empty(&self.attestation_root, "PQ issuer attestation root")?;
        ensure_non_empty(&self.signature_root, "PQ issuer attestation signature root")?;
        ensure_non_empty(
            &self.transcript_root,
            "PQ issuer attestation transcript root",
        )?;
        if self.security_bits < 128 {
            return Err("PQ issuer attestation security below 128".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.issued_at_height {
            return Err("PQ issuer attestation expiry must be after issuance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDisclosureSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub identity_commitment: String,
    pub purpose: DisclosurePurpose,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub spent_fee_units: u64,
    pub disclosure_nullifier: String,
    pub eligible_gate_id: Option<String>,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeDisclosureSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_secret: &str,
        identity: &ShieldedIdentityCommitment,
        purpose: DisclosurePurpose,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        disclosure_nullifier_seed: &str,
        eligible_gate_id: Option<String>,
        reserved_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        identity.validate()?;
        ensure_non_empty(sponsor_secret, "disclosure sponsor secret")?;
        ensure_non_zero(max_fee_units, "disclosure sponsor max fee units")?;
        ensure_non_empty(
            disclosure_nullifier_seed,
            "disclosure sponsor nullifier seed",
        )?;
        let fee_asset_id = normalize_label(&fee_asset_id.into());
        ensure_non_empty(&fee_asset_id, "disclosure sponsor fee asset id")?;
        if expires_at_height != 0 && expires_at_height <= reserved_at_height {
            return Err("disclosure sponsor expiry must be after reservation".to_string());
        }
        let sponsor_commitment =
            private_identity_commitment("DISCLOSURE-SPONSOR", &[sponsor_secret]);
        let identity_commitment = identity.commitment_root();
        let disclosure_nullifier = domain_hash(
            "PRIVATE-IDENTITY-DISCLOSURE-SPONSOR-NULLIFIER",
            &[
                HashPart::Str(&identity_commitment),
                HashPart::Str(&purpose.as_str()),
                HashPart::Str(disclosure_nullifier_seed),
            ],
            32,
        );
        let sponsorship_id = domain_hash(
            "PRIVATE-IDENTITY-LOW-FEE-SPONSORSHIP-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&identity_commitment),
                HashPart::Str(&disclosure_nullifier),
                HashPart::Int(reserved_at_height as i128),
            ],
            24,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            identity_commitment,
            purpose,
            fee_asset_id,
            max_fee_units,
            spent_fee_units: 0,
            disclosure_nullifier,
            eligible_gate_id,
            reserved_at_height,
            expires_at_height,
            status: SponsorshipStatus::Reserved,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.spent_fee_units)
    }

    pub fn apply(&mut self, fee_units: u64) -> PrivateIdentityResult<()> {
        ensure_non_zero(fee_units, "disclosure sponsorship fee units")?;
        if fee_units > self.available_units() {
            return Err("disclosure sponsorship exceeds available units".to_string());
        }
        self.spent_fee_units += fee_units;
        self.status = SponsorshipStatus::Applied;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_disclosure_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "identity_commitment": self.identity_commitment,
            "purpose": self.purpose.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "available_fee_units": self.available_units(),
            "disclosure_nullifier": self.disclosure_nullifier,
            "eligible_gate_id": self.eligible_gate_id,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.sponsorship_id, "disclosure sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "disclosure sponsor commitment")?;
        ensure_non_empty(
            &self.identity_commitment,
            "disclosure sponsor identity commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "disclosure sponsor fee asset")?;
        ensure_non_empty(&self.disclosure_nullifier, "disclosure sponsor nullifier")?;
        ensure_non_zero(self.max_fee_units, "disclosure sponsor max fee units")?;
        if self.spent_fee_units > self.max_fee_units {
            return Err("disclosure sponsorship spent more than max".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.reserved_at_height {
            return Err("disclosure sponsorship expiry must be after reservation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingRiskTag {
    pub tag_id: String,
    pub identity_commitment: String,
    pub credential_id: Option<String>,
    pub tag_kind: RiskTagKind,
    pub severity: RiskSeverity,
    pub score_bucket_bps: u64,
    pub source_commitment: String,
    pub evidence_root: String,
    pub disclosure_policy_root: String,
    pub assigned_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateIdentityStatus,
}

impl PrivacyPreservingRiskTag {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: &ShieldedIdentityCommitment,
        credential_id: Option<String>,
        tag_kind: RiskTagKind,
        severity: RiskSeverity,
        score_bucket_bps: u64,
        source_secret: &str,
        evidence: &Value,
        disclosure_policy: &Value,
        assigned_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIdentityResult<Self> {
        identity.validate()?;
        validate_bps(score_bucket_bps, "risk tag score bucket")?;
        ensure_non_empty(source_secret, "risk tag source secret")?;
        if score_bucket_bps > severity.default_score_bucket_bps() {
            return Err("risk tag score bucket exceeds severity ceiling".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= assigned_at_height {
            return Err("risk tag expiry must be after assignment".to_string());
        }
        let identity_commitment = identity.commitment_root();
        let source_commitment = private_identity_commitment("RISK-TAG-SOURCE", &[source_secret]);
        let evidence_root =
            private_identity_payload_root("PRIVATE-IDENTITY-RISK-EVIDENCE", evidence);
        let disclosure_policy_root = private_identity_payload_root(
            "PRIVATE-IDENTITY-RISK-DISCLOSURE-POLICY",
            disclosure_policy,
        );
        let tag_id = domain_hash(
            "PRIVATE-IDENTITY-RISK-TAG-ID",
            &[
                HashPart::Str(&identity_commitment),
                HashPart::Str(credential_id.as_deref().unwrap_or("none")),
                HashPart::Str(tag_kind.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Int(score_bucket_bps as i128),
                HashPart::Str(&evidence_root),
            ],
            24,
        );
        Ok(Self {
            tag_id,
            identity_commitment,
            credential_id,
            tag_kind,
            severity,
            score_bucket_bps,
            source_commitment,
            evidence_root,
            disclosure_policy_root,
            assigned_at_height,
            expires_at_height,
            status: PrivateIdentityStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_preserving_risk_tag",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "tag_id": self.tag_id,
            "identity_commitment": self.identity_commitment,
            "credential_id": self.credential_id,
            "tag_kind": self.tag_kind.as_str(),
            "severity": self.severity.as_str(),
            "score_bucket_bps": self.score_bucket_bps,
            "source_commitment": self.source_commitment,
            "evidence_root": self.evidence_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "assigned_at_height": self.assigned_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        ensure_non_empty(&self.tag_id, "risk tag id")?;
        ensure_non_empty(&self.identity_commitment, "risk tag identity commitment")?;
        ensure_non_empty(&self.source_commitment, "risk tag source commitment")?;
        ensure_non_empty(&self.evidence_root, "risk tag evidence root")?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "risk tag disclosure policy root",
        )?;
        validate_bps(self.score_bucket_bps, "risk tag score")?;
        if self.score_bucket_bps > self.severity.default_score_bucket_bps() {
            return Err("risk tag score bucket exceeds severity ceiling".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.assigned_at_height {
            return Err("risk tag expiry must be after assignment".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIdentityCounters {
    pub identity_count: u64,
    pub active_identity_count: u64,
    pub credential_count: u64,
    pub active_credential_count: u64,
    pub proof_count: u64,
    pub nullifier_count: u64,
    pub revocation_count: u64,
    pub disclosure_count: u64,
    pub defi_gate_count: u64,
    pub defi_grant_count: u64,
    pub pq_issuer_count: u64,
    pub pq_attestation_count: u64,
    pub sponsorship_count: u64,
    pub risk_tag_count: u64,
    pub total_sponsored_fee_units: u64,
    pub total_available_sponsored_fee_units: u64,
}

impl PrivateIdentityCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_identity_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "identity_count": self.identity_count,
            "active_identity_count": self.active_identity_count,
            "credential_count": self.credential_count,
            "active_credential_count": self.active_credential_count,
            "proof_count": self.proof_count,
            "nullifier_count": self.nullifier_count,
            "revocation_count": self.revocation_count,
            "disclosure_count": self.disclosure_count,
            "defi_gate_count": self.defi_gate_count,
            "defi_grant_count": self.defi_grant_count,
            "pq_issuer_count": self.pq_issuer_count,
            "pq_attestation_count": self.pq_attestation_count,
            "sponsorship_count": self.sponsorship_count,
            "risk_tag_count": self.risk_tag_count,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_available_sponsored_fee_units": self.total_available_sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIdentityRoots {
    pub config_root: String,
    pub identity_root: String,
    pub credential_root: String,
    pub proof_root: String,
    pub nullifier_root: String,
    pub nullifier_registry_root: String,
    pub revocation_root: String,
    pub revocation_registry_root: String,
    pub committee_root: String,
    pub disclosure_root: String,
    pub defi_gate_root: String,
    pub defi_grant_root: String,
    pub pq_issuer_root: String,
    pub pq_attestation_root: String,
    pub sponsorship_root: String,
    pub risk_tag_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl PrivateIdentityRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_identity_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "identity_root": self.identity_root,
            "credential_root": self.credential_root,
            "proof_root": self.proof_root,
            "nullifier_root": self.nullifier_root,
            "nullifier_registry_root": self.nullifier_registry_root,
            "revocation_root": self.revocation_root,
            "revocation_registry_root": self.revocation_registry_root,
            "committee_root": self.committee_root,
            "disclosure_root": self.disclosure_root,
            "defi_gate_root": self.defi_gate_root,
            "defi_grant_root": self.defi_grant_root,
            "pq_issuer_root": self.pq_issuer_root,
            "pq_attestation_root": self.pq_attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "risk_tag_root": self.risk_tag_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }

    pub fn root_commitment(&self) -> String {
        private_identity_payload_root("PRIVATE-IDENTITY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIdentityState {
    pub config: PrivateIdentityConfig,
    pub height: u64,
    pub identities: BTreeMap<String, ShieldedIdentityCommitment>,
    pub credentials: BTreeMap<String, ShieldedCredential>,
    pub proofs: BTreeMap<String, ZkCredentialProof>,
    pub nullifiers: BTreeMap<String, CredentialNullifierRecord>,
    pub nullifier_registries: BTreeMap<String, CredentialNullifierRegistry>,
    pub revocations: BTreeMap<String, CredentialRevocationRecord>,
    pub revocation_registries: BTreeMap<String, CredentialRevocationRegistry>,
    pub committee_members: BTreeMap<String, ViewingCommitteeMember>,
    pub disclosures: BTreeMap<String, ViewingDisclosure>,
    pub defi_gates: BTreeMap<String, DefiEligibilityGate>,
    pub defi_grants: BTreeMap<String, DefiEligibilityGrant>,
    pub pq_issuers: BTreeMap<String, PqCredentialIssuer>,
    pub pq_attestations: BTreeMap<String, PqIssuerAttestation>,
    pub sponsorships: BTreeMap<String, LowFeeDisclosureSponsorship>,
    pub risk_tags: BTreeMap<String, PrivacyPreservingRiskTag>,
}

impl PrivateIdentityState {
    pub fn new(config: PrivateIdentityConfig) -> Self {
        Self {
            config,
            height: 0,
            identities: BTreeMap::new(),
            credentials: BTreeMap::new(),
            proofs: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            nullifier_registries: BTreeMap::new(),
            revocations: BTreeMap::new(),
            revocation_registries: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            defi_gates: BTreeMap::new(),
            defi_grants: BTreeMap::new(),
            pq_issuers: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            risk_tags: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateIdentityResult<Self> {
        let config = PrivateIdentityConfig::devnet();
        config.validate()?;
        let mut state = Self::new(config.clone());
        state.set_height(128);

        let jurisdictions = vec!["us".to_string(), "eu".to_string(), "global".to_string()];
        let issuer = PqCredentialIssuer::new(
            "nebula_devnet_identity_issuer",
            "devnet-issuer-operator-secret",
            "devnet-ml-dsa-public-key",
            "devnet-slh-dsa-public-key",
            "devnet-ml-kem-public-key",
            &[
                CredentialKind::AgeOver,
                CredentialKind::SanctionsScreen,
                CredentialKind::DefiEligibility,
                CredentialKind::RiskAttestation,
            ],
            &jurisdictions,
            config.min_pq_security_bits,
            1,
            0,
            &json!({"fixture": "private_identity_devnet_issuer"}),
        )?;
        state.insert_pq_issuer(issuer.clone())?;

        let identity = ShieldedIdentityCommitment::new(
            "devnet_liquidity_user",
            "devnet-owner-secret",
            "devnet-view-key",
            "devnet-recovery-key",
            "nebula-defi-main",
            "devnet-anonymity-set-alpha",
            config.default_privacy_set_size,
            8,
            1,
            &json!({"fixture": "shielded_identity", "tier": "devnet"}),
        )?;
        state.insert_identity(identity.clone())?;

        let attr_age = CredentialAttributeCommitment::new(
            "defi",
            "age_over",
            "21",
            "devnet-age-salt",
            &json!({"reveals": ["age_over"], "minimized": true}),
        )?;
        let attr_region = CredentialAttributeCommitment::new(
            "defi",
            "region_bucket",
            "allowed",
            "devnet-region-salt",
            &json!({"reveals": ["region_bucket"], "minimized": true}),
        )?;
        let hidden_sanctions = CredentialAttributeCommitment::new(
            "compliance",
            "sanctions_screen",
            "clear",
            "devnet-sanctions-salt",
            &json!({"reveals": [], "committee_only": true}),
        )?;
        let revocation_registry_seed = "devnet-revocation-registry";
        let nullifier_registry_seed = "devnet-nullifier-registry";
        let credential = ShieldedCredential::new(
            &issuer,
            &identity,
            CredentialKind::DefiEligibility,
            &[attr_age.clone(), attr_region.clone()],
            &[hidden_sanctions.clone()],
            revocation_registry_seed,
            nullifier_registry_seed,
            3,
            16,
            16 + config.credential_ttl_blocks,
            7,
            &json!({"fixture": "devnet_defi_credential"}),
        )?;
        state.insert_credential(credential.clone())?;

        let attestation = PqIssuerAttestation::new(
            &issuer,
            "devnet-viewing-committee",
            CredentialKind::DefiEligibility,
            state.height / config.nullifier_epoch_blocks,
            &json!({"credential_id": credential.credential_id, "subject": identity.commitment_root()}),
            &json!({"issuer_policy": "pq_only", "selective_disclosure": true}),
            "devnet-issuer-attestation-signature",
            &json!({"ml_dsa": "present", "slh_dsa_recovery": "present"}),
            config.min_pq_security_bits,
            state.height,
            state.height + config.disclosure_ttl_blocks,
        )?;
        state.insert_pq_attestation(attestation.clone())?;

        let proof = ZkCredentialProof::new(
            &credential,
            "nebula_private_defi",
            &json!({"age_over": true, "region_bucket": "allowed", "risk_bucket_lte": 2500}),
            &json!({"sanctions_screen": "hidden", "identity": "hidden"}),
            "devnet-proof-nullifier-seed",
            private_identity_revocation_registry_root(&[]),
            attestation.attestation_root.clone(),
            config.defi_min_assurance_level,
            state.height,
            state.height + config.disclosure_ttl_blocks,
        )?;
        state.insert_proof(proof.clone())?;

        let nullifier = CredentialNullifierRecord::from_proof(
            &proof,
            "defi_gate_admission",
            state.height / config.nullifier_epoch_blocks,
            state.height,
        )?;
        state.insert_nullifier(nullifier.clone())?;
        let nullifier_registry = CredentialNullifierRegistry::from_nullifiers(
            nullifier_registry_seed,
            state.height / config.nullifier_epoch_blocks,
            &[nullifier.clone()],
            config.nullifier_epoch_blocks,
            state.height,
        )?;
        state.insert_nullifier_registry(nullifier_registry)?;
        let revocation_registry = CredentialRevocationRegistry::from_records(
            issuer.issuer_id.clone(),
            CredentialKind::DefiEligibility,
            state.height / config.nullifier_epoch_blocks,
            &[],
            state.height,
        )?;
        state.insert_revocation_registry(revocation_registry)?;

        let purposes = vec![
            DisclosurePurpose::DefiEligibility,
            DisclosurePurpose::RiskReview,
            DisclosurePurpose::EmergencyCompliance,
        ];
        let member_a = ViewingCommitteeMember::new(
            "devnet-viewing-committee",
            "committee-operator-a",
            "committee-pq-view-key-a",
            &jurisdictions,
            &purposes,
            1,
            20,
            0,
        )?;
        let member_b = ViewingCommitteeMember::new(
            "devnet-viewing-committee",
            "committee-operator-b",
            "committee-pq-view-key-b",
            &jurisdictions,
            &purposes,
            1,
            20,
            0,
        )?;
        let member_c = ViewingCommitteeMember::new(
            "devnet-viewing-committee",
            "committee-operator-c",
            "committee-pq-view-key-c",
            &jurisdictions,
            &purposes,
            1,
            20,
            0,
        )?;
        state.insert_committee_member(member_a.clone())?;
        state.insert_committee_member(member_b.clone())?;
        state.insert_committee_member(member_c.clone())?;

        let risk_tag = PrivacyPreservingRiskTag::new(
            &identity,
            Some(credential.credential_id.clone()),
            RiskTagKind::SanctionsScreen,
            RiskSeverity::Low,
            1_000,
            "devnet-risk-oracle-source",
            &json!({"screening": "clear", "bucket": "low"}),
            &json!({"committee": "devnet-viewing-committee", "purpose": "risk_review"}),
            state.height,
            state.height + config.credential_ttl_blocks,
        )?;
        state.insert_risk_tag(risk_tag.clone())?;

        let gate = DefiEligibilityGate::new(
            "xmr_usdx_private_pool",
            DefiGateKind::Lending,
            CredentialKind::DefiEligibility,
            config.defi_min_assurance_level,
            Some(21),
            config.max_risk_score_bps,
            &["us".to_string(), "eu".to_string()],
            &["restricted".to_string()],
            std::slice::from_ref(&issuer.issuer_id),
            config.low_fee_lane.clone(),
            state.height,
            &json!({"fixture": "private_defi_lending_gate"}),
        )?;
        state.insert_defi_gate(gate.clone())?;
        let grant = DefiEligibilityGrant::new(
            &gate,
            &identity,
            &proof,
            std::slice::from_ref(&risk_tag),
            1_000_000_000,
            25,
            state.height,
            state.height + config.disclosure_ttl_blocks,
        )?;
        state.insert_defi_grant(grant.clone())?;

        let mut sponsorship = LowFeeDisclosureSponsorship::new(
            "devnet-sponsor-secret",
            &identity,
            DisclosurePurpose::DefiEligibility,
            config.fee_asset_id.clone(),
            config.low_fee_max_sponsored_units,
            "devnet-disclosure-nullifier",
            Some(gate.gate_id.clone()),
            state.height,
            state.height + config.disclosure_ttl_blocks,
        )?;
        sponsorship.apply(2)?;
        state.insert_sponsorship(sponsorship.clone())?;

        let disclosure = ViewingDisclosure::new(
            identity.identity_id.clone(),
            Some(credential.credential_id.clone()),
            "devnet-viewing-committee",
            DisclosurePurpose::DefiEligibility,
            &json!({"age_over": true, "region_bucket": "allowed", "max_notional_units": grant.max_notional_units}),
            &json!({"sealed_to": "committee", "payload": "devnet-encrypted-disclosure"}),
            &json!({"quorum": 2, "ttl_blocks": config.disclosure_ttl_blocks}),
            &[member_a, member_b, member_c],
            proof.proof_id.clone(),
            Some(sponsorship.sponsorship_id.clone()),
            state.height,
            state.height + config.disclosure_ttl_blocks,
        )?;
        state.insert_disclosure(disclosure)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_identity(
        &mut self,
        identity: ShieldedIdentityCommitment,
    ) -> PrivateIdentityResult<()> {
        identity.validate()?;
        if identity.privacy_set_size < self.config.min_anonymity_set_size {
            return Err("identity privacy set below configured floor".to_string());
        }
        self.identities
            .insert(identity.identity_id.clone(), identity);
        Ok(())
    }

    pub fn insert_pq_issuer(&mut self, issuer: PqCredentialIssuer) -> PrivateIdentityResult<()> {
        issuer.validate()?;
        if issuer.min_security_bits < self.config.min_pq_security_bits {
            return Err("issuer PQ security below configured floor".to_string());
        }
        self.pq_issuers.insert(issuer.issuer_id.clone(), issuer);
        Ok(())
    }

    pub fn insert_credential(
        &mut self,
        credential: ShieldedCredential,
    ) -> PrivateIdentityResult<()> {
        credential.validate()?;
        if !self.pq_issuers.contains_key(&credential.issuer_id) {
            return Err("credential references unknown PQ issuer".to_string());
        }
        if !self
            .identities
            .contains_key(&credential.subject_identity_id)
        {
            return Err("credential references unknown identity".to_string());
        }
        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    pub fn insert_proof(&mut self, proof: ZkCredentialProof) -> PrivateIdentityResult<()> {
        proof.validate()?;
        let credential = self
            .credentials
            .get(&proof.credential_id)
            .ok_or_else(|| "proof references unknown credential".to_string())?;
        if credential.subject_identity_id != proof.subject_identity_id {
            return Err("proof subject does not match credential".to_string());
        }
        if credential.assurance_level < proof.min_assurance_level {
            return Err("proof assurance level exceeds credential".to_string());
        }
        if self.nullifiers.contains_key(&proof.nullifier) {
            return Err("proof nullifier has already been spent".to_string());
        }
        self.proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_nullifier(
        &mut self,
        nullifier: CredentialNullifierRecord,
    ) -> PrivateIdentityResult<()> {
        nullifier.validate()?;
        if self.nullifiers.contains_key(&nullifier.nullifier) {
            return Err("credential nullifier is already registered".to_string());
        }
        if !self.proofs.contains_key(&nullifier.proof_id) {
            return Err("nullifier references unknown proof".to_string());
        }
        self.nullifiers
            .insert(nullifier.nullifier.clone(), nullifier);
        Ok(())
    }

    pub fn insert_nullifier_registry(
        &mut self,
        registry: CredentialNullifierRegistry,
    ) -> PrivateIdentityResult<()> {
        registry.validate()?;
        self.nullifier_registries
            .insert(registry.registry_id.clone(), registry);
        Ok(())
    }

    pub fn insert_revocation(
        &mut self,
        revocation: CredentialRevocationRecord,
    ) -> PrivateIdentityResult<()> {
        revocation.validate()?;
        if !self.credentials.contains_key(&revocation.credential_id) {
            return Err("revocation references unknown credential".to_string());
        }
        self.revocations
            .insert(revocation.revocation_id.clone(), revocation);
        Ok(())
    }

    pub fn insert_revocation_registry(
        &mut self,
        registry: CredentialRevocationRegistry,
    ) -> PrivateIdentityResult<()> {
        registry.validate()?;
        self.revocation_registries
            .insert(registry.registry_id.clone(), registry);
        Ok(())
    }

    pub fn insert_committee_member(
        &mut self,
        member: ViewingCommitteeMember,
    ) -> PrivateIdentityResult<()> {
        member.validate()?;
        self.committee_members
            .insert(member.member_id.clone(), member);
        Ok(())
    }

    pub fn insert_disclosure(
        &mut self,
        disclosure: ViewingDisclosure,
    ) -> PrivateIdentityResult<()> {
        disclosure.validate()?;
        if !self.identities.contains_key(&disclosure.identity_id) {
            return Err("disclosure references unknown identity".to_string());
        }
        if let Some(credential_id) = &disclosure.credential_id {
            if !self.credentials.contains_key(credential_id) {
                return Err("disclosure references unknown credential".to_string());
            }
        }
        if !self.proofs.contains_key(&disclosure.proof_id) {
            return Err("disclosure references unknown proof".to_string());
        }
        if let Some(sponsor_id) = &disclosure.sponsor_id {
            if !self.sponsorships.contains_key(sponsor_id) {
                return Err("disclosure references unknown sponsorship".to_string());
            }
        }
        self.disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure);
        Ok(())
    }

    pub fn insert_defi_gate(&mut self, gate: DefiEligibilityGate) -> PrivateIdentityResult<()> {
        gate.validate()?;
        if gate.min_assurance_level < self.config.defi_min_assurance_level {
            return Err("DeFi gate assurance below configured floor".to_string());
        }
        if gate.max_risk_score_bps > self.config.max_risk_score_bps {
            return Err("DeFi gate risk threshold exceeds configured cap".to_string());
        }
        self.defi_gates.insert(gate.gate_id.clone(), gate);
        Ok(())
    }

    pub fn insert_defi_grant(&mut self, grant: DefiEligibilityGrant) -> PrivateIdentityResult<()> {
        grant.validate()?;
        if !self.defi_gates.contains_key(&grant.gate_id) {
            return Err("DeFi grant references unknown gate".to_string());
        }
        if !self.proofs.contains_key(&grant.credential_proof_id) {
            return Err("DeFi grant references unknown proof".to_string());
        }
        self.defi_grants.insert(grant.grant_id.clone(), grant);
        Ok(())
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqIssuerAttestation,
    ) -> PrivateIdentityResult<()> {
        attestation.validate()?;
        if !self.pq_issuers.contains_key(&attestation.issuer_id) {
            return Err("PQ attestation references unknown issuer".to_string());
        }
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("PQ attestation below configured security floor".to_string());
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeDisclosureSponsorship,
    ) -> PrivateIdentityResult<()> {
        sponsorship.validate()?;
        if sponsorship.max_fee_units > self.config.low_fee_max_sponsored_units {
            return Err("disclosure sponsorship exceeds configured low-fee cap".to_string());
        }
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_risk_tag(&mut self, tag: PrivacyPreservingRiskTag) -> PrivateIdentityResult<()> {
        tag.validate()?;
        if tag.score_bucket_bps > self.config.max_risk_score_bps {
            return Err("risk tag score exceeds configured cap".to_string());
        }
        self.risk_tags.insert(tag.tag_id.clone(), tag);
        Ok(())
    }

    pub fn identity_count(&self) -> u64 {
        self.identities.len() as u64
    }

    pub fn active_identity_count(&self) -> u64 {
        self.identities
            .values()
            .filter(|identity| identity.status == PrivateIdentityStatus::Active)
            .count() as u64
    }

    pub fn credential_count(&self) -> u64 {
        self.credentials.len() as u64
    }

    pub fn active_credential_count(&self) -> u64 {
        self.credentials
            .values()
            .filter(|credential| credential.status == CredentialStatus::Active)
            .count() as u64
    }

    pub fn proof_count(&self) -> u64 {
        self.proofs.len() as u64
    }

    pub fn nullifier_count(&self) -> u64 {
        self.nullifiers.len() as u64
    }

    pub fn revocation_count(&self) -> u64 {
        self.revocations.len() as u64
    }

    pub fn disclosure_count(&self) -> u64 {
        self.disclosures.len() as u64
    }

    pub fn defi_gate_count(&self) -> u64 {
        self.defi_gates.len() as u64
    }

    pub fn defi_grant_count(&self) -> u64 {
        self.defi_grants.len() as u64
    }

    pub fn pq_issuer_count(&self) -> u64 {
        self.pq_issuers.len() as u64
    }

    pub fn pq_attestation_count(&self) -> u64 {
        self.pq_attestations.len() as u64
    }

    pub fn sponsorship_count(&self) -> u64 {
        self.sponsorships.len() as u64
    }

    pub fn risk_tag_count(&self) -> u64 {
        self.risk_tags.len() as u64
    }

    pub fn total_sponsored_fee_units(&self) -> u64 {
        self.sponsorships
            .values()
            .map(|sponsorship| sponsorship.max_fee_units)
            .sum()
    }

    pub fn total_available_sponsored_fee_units(&self) -> u64 {
        self.sponsorships
            .values()
            .map(LowFeeDisclosureSponsorship::available_units)
            .sum()
    }

    pub fn counters(&self) -> PrivateIdentityCounters {
        PrivateIdentityCounters {
            identity_count: self.identity_count(),
            active_identity_count: self.active_identity_count(),
            credential_count: self.credential_count(),
            active_credential_count: self.active_credential_count(),
            proof_count: self.proof_count(),
            nullifier_count: self.nullifier_count(),
            revocation_count: self.revocation_count(),
            disclosure_count: self.disclosure_count(),
            defi_gate_count: self.defi_gate_count(),
            defi_grant_count: self.defi_grant_count(),
            pq_issuer_count: self.pq_issuer_count(),
            pq_attestation_count: self.pq_attestation_count(),
            sponsorship_count: self.sponsorship_count(),
            risk_tag_count: self.risk_tag_count(),
            total_sponsored_fee_units: self.total_sponsored_fee_units(),
            total_available_sponsored_fee_units: self.total_available_sponsored_fee_units(),
        }
    }

    pub fn roots(&self) -> PrivateIdentityRoots {
        let config_root = self.config.config_root();
        let identity_root = private_identity_commitment_root(
            &self.identities.values().cloned().collect::<Vec<_>>(),
        );
        let credential_root = private_identity_credential_root(
            &self.credentials.values().cloned().collect::<Vec<_>>(),
        );
        let proof_root =
            private_identity_proof_root(&self.proofs.values().cloned().collect::<Vec<_>>());
        let nullifier_root =
            private_identity_nullifier_root(&self.nullifiers.values().cloned().collect::<Vec<_>>());
        let nullifier_registry_root = private_identity_nullifier_registry_root(
            &self
                .nullifier_registries
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        );
        let revocation_root = private_identity_revocation_root(
            &self.revocations.values().cloned().collect::<Vec<_>>(),
        );
        let revocation_registry_root = private_identity_revocation_registry_root(
            &self
                .revocation_registries
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        );
        let committee_root = viewing_committee_member_root(
            &self.committee_members.values().cloned().collect::<Vec<_>>(),
        );
        let disclosure_root =
            viewing_disclosure_root(&self.disclosures.values().cloned().collect::<Vec<_>>());
        let defi_gate_root = defi_gate_root(&self.defi_gates.values().cloned().collect::<Vec<_>>());
        let defi_grant_root =
            defi_grant_root(&self.defi_grants.values().cloned().collect::<Vec<_>>());
        let pq_issuer_root = pq_issuer_root(&self.pq_issuers.values().cloned().collect::<Vec<_>>());
        let pq_attestation_root =
            pq_issuer_attestation_root(&self.pq_attestations.values().cloned().collect::<Vec<_>>());
        let sponsorship_root =
            disclosure_sponsorship_root(&self.sponsorships.values().cloned().collect::<Vec<_>>());
        let risk_tag_root =
            privacy_risk_tag_root(&self.risk_tags.values().cloned().collect::<Vec<_>>());
        let counter_root = private_identity_payload_root(
            "PRIVATE-IDENTITY-COUNTERS",
            &self.counters().public_record(),
        );
        let state_record = json!({
            "config_root": config_root,
            "identity_root": identity_root,
            "credential_root": credential_root,
            "proof_root": proof_root,
            "nullifier_root": nullifier_root,
            "nullifier_registry_root": nullifier_registry_root,
            "revocation_root": revocation_root,
            "revocation_registry_root": revocation_registry_root,
            "committee_root": committee_root,
            "disclosure_root": disclosure_root,
            "defi_gate_root": defi_gate_root,
            "defi_grant_root": defi_grant_root,
            "pq_issuer_root": pq_issuer_root,
            "pq_attestation_root": pq_attestation_root,
            "sponsorship_root": sponsorship_root,
            "risk_tag_root": risk_tag_root,
            "counter_root": counter_root,
            "height": self.height,
        });
        let state_root = private_identity_state_root_from_record(&state_record);
        PrivateIdentityRoots {
            config_root,
            identity_root,
            credential_root,
            proof_root,
            nullifier_root,
            nullifier_registry_root,
            revocation_root,
            revocation_registry_root,
            committee_root,
            disclosure_root,
            defi_gate_root,
            defi_grant_root,
            pq_issuer_root,
            pq_attestation_root,
            sponsorship_root,
            risk_tag_root,
            counter_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_identity_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_IDENTITY_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> PrivateIdentityResult<()> {
        self.config.validate()?;
        let mut nullifier_set = BTreeSet::new();
        for identity in self.identities.values() {
            identity.validate()?;
            if identity.privacy_set_size < self.config.min_anonymity_set_size {
                return Err(format!(
                    "identity below privacy set floor: {}",
                    identity.identity_id
                ));
            }
        }
        for issuer in self.pq_issuers.values() {
            issuer.validate()?;
            if issuer.min_security_bits < self.config.min_pq_security_bits {
                return Err(format!("issuer below PQ floor: {}", issuer.issuer_id));
            }
        }
        for credential in self.credentials.values() {
            credential.validate()?;
            if !self.pq_issuers.contains_key(&credential.issuer_id) {
                return Err(format!(
                    "credential references unknown issuer: {}",
                    credential.credential_id
                ));
            }
            if !self
                .identities
                .contains_key(&credential.subject_identity_id)
            {
                return Err(format!(
                    "credential references unknown identity: {}",
                    credential.credential_id
                ));
            }
        }
        for proof in self.proofs.values() {
            proof.validate()?;
            if !self.credentials.contains_key(&proof.credential_id) {
                return Err(format!(
                    "proof references unknown credential: {}",
                    proof.proof_id
                ));
            }
        }
        for nullifier in self.nullifiers.values() {
            nullifier.validate()?;
            if !nullifier_set.insert(nullifier.nullifier.clone()) {
                return Err(format!("duplicate nullifier: {}", nullifier.nullifier));
            }
            if !self.proofs.contains_key(&nullifier.proof_id) {
                return Err(format!(
                    "nullifier references unknown proof: {}",
                    nullifier.nullifier
                ));
            }
        }
        for registry in self.nullifier_registries.values() {
            registry.validate()?;
        }
        for revocation in self.revocations.values() {
            revocation.validate()?;
            if !self.credentials.contains_key(&revocation.credential_id) {
                return Err(format!(
                    "revocation references unknown credential: {}",
                    revocation.revocation_id
                ));
            }
        }
        for registry in self.revocation_registries.values() {
            registry.validate()?;
        }
        for member in self.committee_members.values() {
            member.validate()?;
        }
        for disclosure in self.disclosures.values() {
            disclosure.validate()?;
            if !self.identities.contains_key(&disclosure.identity_id) {
                return Err(format!(
                    "disclosure references unknown identity: {}",
                    disclosure.disclosure_id
                ));
            }
        }
        for gate in self.defi_gates.values() {
            gate.validate()?;
            if gate.max_risk_score_bps > self.config.max_risk_score_bps {
                return Err(format!("DeFi gate exceeds risk cap: {}", gate.gate_id));
            }
        }
        for grant in self.defi_grants.values() {
            grant.validate()?;
            if !self.defi_gates.contains_key(&grant.gate_id) {
                return Err(format!(
                    "DeFi grant references unknown gate: {}",
                    grant.grant_id
                ));
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            if !self.pq_issuers.contains_key(&attestation.issuer_id) {
                return Err(format!(
                    "PQ attestation references unknown issuer: {}",
                    attestation.attestation_id
                ));
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if sponsorship.max_fee_units > self.config.low_fee_max_sponsored_units {
                return Err(format!(
                    "sponsorship exceeds fee cap: {}",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for tag in self.risk_tags.values() {
            tag.validate()?;
            if tag.score_bucket_bps > self.config.max_risk_score_bps {
                return Err(format!("risk tag exceeds risk cap: {}", tag.tag_id));
            }
        }
        Ok(())
    }
}

pub fn private_identity_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-IDENTITY-STATE",
        &[
            HashPart::Str(PRIVATE_IDENTITY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_identity_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn private_identity_commitment(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "value_commitment": domain_hash(
                    &format!("PRIVATE-IDENTITY-{domain}-PART"),
                    &[HashPart::Str(value)],
                    32,
                ),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-IDENTITY-{domain}"), &leaves)
}

pub fn credential_nullifier(
    credential_id: &str,
    subject_commitment: &str,
    verifier_domain: &str,
    nullifier_seed: &str,
) -> String {
    domain_hash(
        "PRIVATE-IDENTITY-CREDENTIAL-NULLIFIER",
        &[
            HashPart::Str(credential_id),
            HashPart::Str(subject_commitment),
            HashPart::Str(verifier_domain),
            HashPart::Str(nullifier_seed),
        ],
        32,
    )
}

pub fn credential_kind_root(kinds: &[CredentialKind]) -> String {
    let leaves = kinds
        .iter()
        .map(|kind| json!({"credential_kind": kind.as_str()}))
        .collect::<Vec<_>>();
    sorted_merkle_root(
        "PRIVATE-IDENTITY-CREDENTIAL-KIND",
        leaves,
        "credential_kind",
    )
}

pub fn disclosure_purpose_root(purposes: &[DisclosurePurpose]) -> String {
    let leaves = purposes
        .iter()
        .map(|purpose| json!({"purpose": purpose.as_str()}))
        .collect::<Vec<_>>();
    sorted_merkle_root("PRIVATE-IDENTITY-DISCLOSURE-PURPOSE", leaves, "purpose")
}

pub fn credential_attribute_root(attributes: &[CredentialAttributeCommitment]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-CREDENTIAL-ATTRIBUTE",
        attributes
            .iter()
            .map(CredentialAttributeCommitment::public_record)
            .collect(),
        "attribute_id",
    )
}

pub fn private_identity_commitment_root(identities: &[ShieldedIdentityCommitment]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-COMMITMENT-ROOT",
        identities
            .iter()
            .map(ShieldedIdentityCommitment::public_record)
            .collect(),
        "identity_id",
    )
}

pub fn private_identity_credential_root(credentials: &[ShieldedCredential]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-CREDENTIAL-ROOT",
        credentials
            .iter()
            .map(ShieldedCredential::public_record)
            .collect(),
        "credential_id",
    )
}

pub fn private_identity_proof_root(proofs: &[ZkCredentialProof]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-PROOF-ROOT",
        proofs
            .iter()
            .map(ZkCredentialProof::public_record)
            .collect(),
        "proof_id",
    )
}

pub fn private_identity_nullifier_root(nullifiers: &[CredentialNullifierRecord]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-NULLIFIER-ROOT",
        nullifiers
            .iter()
            .map(CredentialNullifierRecord::public_record)
            .collect(),
        "nullifier",
    )
}

pub fn private_identity_nullifier_registry_root(
    registries: &[CredentialNullifierRegistry],
) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-NULLIFIER-REGISTRY-ROOT",
        registries
            .iter()
            .map(CredentialNullifierRegistry::public_record)
            .collect(),
        "registry_id",
    )
}

pub fn private_identity_revocation_root(revocations: &[CredentialRevocationRecord]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-REVOCATION-ROOT",
        revocations
            .iter()
            .map(CredentialRevocationRecord::public_record)
            .collect(),
        "revocation_id",
    )
}

pub fn private_identity_revocation_registry_root(
    registries: &[CredentialRevocationRegistry],
) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-REVOCATION-REGISTRY-ROOT",
        registries
            .iter()
            .map(CredentialRevocationRegistry::public_record)
            .collect(),
        "registry_id",
    )
}

pub fn viewing_committee_member_root(members: &[ViewingCommitteeMember]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-VIEWING-COMMITTEE-ROOT",
        members
            .iter()
            .map(ViewingCommitteeMember::public_record)
            .collect(),
        "member_id",
    )
}

pub fn viewing_disclosure_root(disclosures: &[ViewingDisclosure]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-VIEWING-DISCLOSURE-ROOT",
        disclosures
            .iter()
            .map(ViewingDisclosure::public_record)
            .collect(),
        "disclosure_id",
    )
}

pub fn defi_gate_root(gates: &[DefiEligibilityGate]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-DEFI-GATE-ROOT",
        gates
            .iter()
            .map(DefiEligibilityGate::public_record)
            .collect(),
        "gate_id",
    )
}

pub fn defi_grant_root(grants: &[DefiEligibilityGrant]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-DEFI-GRANT-ROOT",
        grants
            .iter()
            .map(DefiEligibilityGrant::public_record)
            .collect(),
        "grant_id",
    )
}

pub fn pq_issuer_root(issuers: &[PqCredentialIssuer]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-PQ-ISSUER-ROOT",
        issuers
            .iter()
            .map(PqCredentialIssuer::public_record)
            .collect(),
        "issuer_id",
    )
}

pub fn pq_issuer_attestation_root(attestations: &[PqIssuerAttestation]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-PQ-ATTESTATION-ROOT",
        attestations
            .iter()
            .map(PqIssuerAttestation::public_record)
            .collect(),
        "attestation_id",
    )
}

pub fn disclosure_sponsorship_root(sponsorships: &[LowFeeDisclosureSponsorship]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-DISCLOSURE-SPONSORSHIP-ROOT",
        sponsorships
            .iter()
            .map(LowFeeDisclosureSponsorship::public_record)
            .collect(),
        "sponsorship_id",
    )
}

pub fn privacy_risk_tag_root(tags: &[PrivacyPreservingRiskTag]) -> String {
    sorted_merkle_root(
        "PRIVATE-IDENTITY-RISK-TAG-ROOT",
        tags.iter()
            .map(PrivacyPreservingRiskTag::public_record)
            .collect(),
        "tag_id",
    )
}

pub fn private_identity_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": normalize_label(value)}))
        .collect::<Vec<_>>();
    sorted_merkle_root(domain, leaves, "value")
}

fn sorted_merkle_root(domain: &str, mut leaves: Vec<Value>, sort_key: &str) -> String {
    leaves.sort_by_key(|record| {
        record
            .get(sort_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    merkle_root(domain, &leaves)
}

fn normalize_label(value: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for character in value.trim().chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateIdentityResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_non_zero(value: u64, label: &str) -> PrivateIdentityResult<()> {
    if value == 0 {
        Err(format!("{label} cannot be zero"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> PrivateIdentityResult<()> {
    if value > PRIVATE_IDENTITY_MAX_BPS {
        Err(format!("{label} exceeds {PRIVATE_IDENTITY_MAX_BPS} bps"))
    } else {
        Ok(())
    }
}
