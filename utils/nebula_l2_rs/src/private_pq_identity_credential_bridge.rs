use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivatePqIdentityCredentialBridgeResult<T> = Result<T, String>;

pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_PROTOCOL_VERSION: &str =
    "nebula-private-pq-identity-credential-bridge-v1";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_SCHEMA_VERSION: &str =
    "private-pq-identity-credential-bridge-state-v1";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEVNET_LABEL: &str =
    "devnet-private-pq-identity-credential-bridge";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-unlinkable-credential-commitment";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_NULLIFIER_SCHEME: &str =
    "shake256-domain-separated-contract-credential-nullifier";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_REVOCATION_SCHEME: &str =
    "issuer-scoped-devnet-revocation-accumulator-v1";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_PQ_KEM_SUITE: &str = "ML-KEM-768";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DISCLOSURE_PROOF_SYSTEM: &str =
    "devnet-mock-zk-selective-disclosure-policy-proof";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_AUTH_RECEIPT_PROOF_SYSTEM: &str =
    "devnet-mock-private-contract-authorization-receipt-proof";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_FEE_ASSET_ID: &str = "piconero";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_LOW_FEE_LANE: &str =
    "private-pq-credential-authorization";
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_HEIGHT: u64 = 192;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_SPONSOR_WINDOW_BLOCKS: u64 = 240;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MIN_ANONYMITY_SET: u64 = 128;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_ATTRIBUTES: usize = 16;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_FEE_UNITS: u64 = 12;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_RISK_SCORE_BPS: u64 = 7_500;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_ISSUERS: usize = 512;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_CREDENTIALS: usize = 65_536;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_POLICIES: usize = 4_096;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_DISCLOSURES: usize = 131_072;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_SPONSORSHIPS: usize = 65_536;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_RECEIPTS: usize = 131_072;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_REVOCATIONS: usize = 131_072;
pub const PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_NULLIFIERS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeNetwork {
    NebulaL2,
    MoneroL1,
    ExternalRollup,
    ContractSubnet,
    Custom,
}

impl BridgeNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NebulaL2 => "nebula_l2",
            Self::MoneroL1 => "monero_l1",
            Self::ExternalRollup => "external_rollup",
            Self::ContractSubnet => "contract_subnet",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStatus {
    Pending,
    Active,
    RateLimited,
    Suspended,
    Retired,
}

impl IssuerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Committed,
    Attested,
    Active,
    Frozen,
    Revoked,
    Expired,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    HumanUniqueness,
    KycLight,
    KycFull,
    AccreditedInvestor,
    SanctionsClear,
    Residency,
    AgeOver,
    ProtocolReputation,
    DefiRiskTier,
    BridgeEligibility,
    ContractDeveloper,
    Custom,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HumanUniqueness => "human_uniqueness",
            Self::KycLight => "kyc_light",
            Self::KycFull => "kyc_full",
            Self::AccreditedInvestor => "accredited_investor",
            Self::SanctionsClear => "sanctions_clear",
            Self::Residency => "residency",
            Self::AgeOver => "age_over",
            Self::ProtocolReputation => "protocol_reputation",
            Self::DefiRiskTier => "defi_risk_tier",
            Self::BridgeEligibility => "bridge_eligibility",
            Self::ContractDeveloper => "contract_developer",
            Self::Custom => "custom",
        }
    }

    pub fn default_assurance(self) -> u8 {
        match self {
            Self::KycFull | Self::AccreditedInvestor | Self::SanctionsClear => 3,
            Self::KycLight | Self::Residency | Self::BridgeEligibility => 2,
            Self::HumanUniqueness
            | Self::AgeOver
            | Self::ProtocolReputation
            | Self::DefiRiskTier
            | Self::ContractDeveloper
            | Self::Custom => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureMode {
    CommitmentOnly,
    PredicateProof,
    AttributeHash,
    EncryptedToContract,
    CommitteeRecoverable,
}

impl DisclosureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::PredicateProof => "predicate_proof",
            Self::AttributeHash => "attribute_hash",
            Self::EncryptedToContract => "encrypted_to_contract",
            Self::CommitteeRecoverable => "committee_recoverable",
        }
    }

    pub fn reveals_attribute_hash(self) -> bool {
        matches!(self, Self::AttributeHash | Self::EncryptedToContract)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    Frozen,
    Retired,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_proofs(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Requested,
    Verified,
    Consumed,
    Rejected,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Verified => "verified",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Requested | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Settled,
    Released,
    Rejected,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Pending,
    Accepted,
    Consumed,
    Rejected,
    Expired,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Pending | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Pending,
    Active,
    Appealed,
    Finalized,
}

impl RevocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Appealed => "appealed",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Spent,
    Revoked,
    Expired,
}

impl NullifierStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractScope {
    View,
    Transfer,
    Swap,
    Lending,
    Derivatives,
    Governance,
    Bridge,
    Deployment,
    Custom,
}

impl ContractScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::Lending => "lending",
            Self::Derivatives => "derivatives",
            Self::Governance => "governance",
            Self::Bridge => "bridge",
            Self::Deployment => "deployment",
            Self::Custom => "custom",
        }
    }

    pub fn defi(self) -> bool {
        matches!(self, Self::Swap | Self::Lending | Self::Derivatives)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivatePqIdentityCredentialBridgeConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub commitment_scheme: String,
    pub nullifier_scheme: String,
    pub revocation_scheme: String,
    pub pq_signature_suite: String,
    pub pq_kem_suite: String,
    pub disclosure_proof_system: String,
    pub auth_receipt_proof_system: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub epoch_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub sponsor_window_blocks: u64,
    pub min_anonymity_set: u64,
    pub min_pq_security_bits: u16,
    pub max_disclosed_attributes: usize,
    pub max_sponsor_fee_units: u64,
    pub max_risk_score_bps: u64,
    pub require_revocation_witness: bool,
    pub require_contract_domain_binding: bool,
    pub privacy_policy_root: String,
}

impl PrivatePqIdentityCredentialBridgeConfig {
    pub fn devnet() -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            commitment_scheme: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_COMMITMENT_SCHEME.to_string(),
            nullifier_scheme: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_NULLIFIER_SCHEME.to_string(),
            revocation_scheme: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_REVOCATION_SCHEME.to_string(),
            pq_signature_suite: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_PQ_SIGNATURE_SUITE
                .to_string(),
            pq_kem_suite: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_PQ_KEM_SUITE.to_string(),
            disclosure_proof_system: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DISCLOSURE_PROOF_SYSTEM
                .to_string(),
            auth_receipt_proof_system:
                PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_AUTH_RECEIPT_PROOF_SYSTEM.to_string(),
            fee_asset_id: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_FEE_ASSET_ID.to_string(),
            low_fee_lane: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_LOW_FEE_LANE.to_string(),
            epoch_blocks: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_EPOCH_BLOCKS,
            disclosure_ttl_blocks:
                PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_RECEIPT_TTL_BLOCKS,
            sponsor_window_blocks:
                PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_SPONSOR_WINDOW_BLOCKS,
            min_anonymity_set: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MIN_ANONYMITY_SET,
            min_pq_security_bits:
                PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_disclosed_attributes: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_ATTRIBUTES,
            max_sponsor_fee_units: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_FEE_UNITS,
            max_risk_score_bps: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_RISK_SCORE_BPS,
            require_revocation_witness: true,
            require_contract_domain_binding: true,
            privacy_policy_root: private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-BRIDGE-PRIVACY-POLICY",
                "public-roots-only-no-linkable-subjects",
            ),
        };
        config.config_id = private_pq_identity_config_id(
            &config.protocol_version,
            &config.schema_version,
            &config.chain_id,
        );
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.config_id, "private pq identity config id")?;
        ensure_non_empty(
            &self.protocol_version,
            "private pq identity protocol version",
        )?;
        ensure_non_empty(&self.schema_version, "private pq identity schema version")?;
        ensure_non_empty(&self.chain_id, "private pq identity chain id")?;
        ensure_non_empty(
            &self.commitment_scheme,
            "private pq identity commitment scheme",
        )?;
        ensure_non_empty(
            &self.nullifier_scheme,
            "private pq identity nullifier scheme",
        )?;
        ensure_non_empty(
            &self.revocation_scheme,
            "private pq identity revocation scheme",
        )?;
        ensure_non_empty(
            &self.pq_signature_suite,
            "private pq identity pq signature suite",
        )?;
        ensure_non_empty(&self.pq_kem_suite, "private pq identity pq kem suite")?;
        ensure_non_empty(
            &self.disclosure_proof_system,
            "private pq identity disclosure proof system",
        )?;
        ensure_non_empty(
            &self.auth_receipt_proof_system,
            "private pq identity auth receipt proof system",
        )?;
        ensure_non_empty(&self.fee_asset_id, "private pq identity fee asset")?;
        ensure_non_empty(&self.low_fee_lane, "private pq identity low fee lane")?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "private pq identity privacy policy root",
        )?;
        if self.epoch_blocks == 0 {
            return Err("private pq identity epoch blocks must be positive".to_string());
        }
        if self.disclosure_ttl_blocks == 0 {
            return Err("private pq identity disclosure ttl must be positive".to_string());
        }
        if self.receipt_ttl_blocks == 0 {
            return Err("private pq identity receipt ttl must be positive".to_string());
        }
        if self.sponsor_window_blocks == 0 {
            return Err("private pq identity sponsor window must be positive".to_string());
        }
        if self.min_anonymity_set == 0 {
            return Err("private pq identity anonymity set must be positive".to_string());
        }
        if self.min_pq_security_bits == 0 {
            return Err("private pq identity pq security bits must be positive".to_string());
        }
        if self.max_disclosed_attributes == 0 {
            return Err(
                "private pq identity max disclosed attributes must be positive".to_string(),
            );
        }
        if self.max_risk_score_bps > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_BPS {
            return Err("private pq identity risk score exceeds bps cap".to_string());
        }
        let expected = private_pq_identity_config_id(
            &self.protocol_version,
            &self.schema_version,
            &self.chain_id,
        );
        if self.config_id != expected {
            return Err("private pq identity config id does not match protocol".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqIssuer {
    pub issuer_id: String,
    pub issuer_label: String,
    pub network: BridgeNetwork,
    pub status: IssuerStatus,
    pub pq_verification_key_root: String,
    pub pq_attestation_policy_root: String,
    pub revocation_accumulator_root: String,
    pub supported_kinds: BTreeSet<CredentialKind>,
    pub supported_scopes: BTreeSet<ContractScope>,
    pub min_pq_security_bits: u16,
    pub fee_sponsor_budget_units: u64,
    pub issued_count: u64,
    pub revoked_count: u64,
    pub registered_height: u64,
    pub metadata_root: String,
}

impl PqIssuer {
    pub fn new(
        issuer_label: &str,
        network: BridgeNetwork,
        pq_verification_key_root: &str,
        pq_attestation_policy_root: &str,
        revocation_accumulator_root: &str,
        registered_height: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let clean_label = normalize_label(issuer_label);
        let issuer_id = pq_issuer_id(
            &clean_label,
            network,
            pq_verification_key_root,
            revocation_accumulator_root,
        );
        let mut supported_kinds = BTreeSet::new();
        supported_kinds.insert(CredentialKind::HumanUniqueness);
        supported_kinds.insert(CredentialKind::KycLight);
        supported_kinds.insert(CredentialKind::DefiRiskTier);
        let mut supported_scopes = BTreeSet::new();
        supported_scopes.insert(ContractScope::View);
        supported_scopes.insert(ContractScope::Swap);
        supported_scopes.insert(ContractScope::Bridge);
        let issuer = Self {
            issuer_id,
            issuer_label: clean_label,
            network,
            status: IssuerStatus::Active,
            pq_verification_key_root: pq_verification_key_root.to_string(),
            pq_attestation_policy_root: pq_attestation_policy_root.to_string(),
            revocation_accumulator_root: revocation_accumulator_root.to_string(),
            supported_kinds,
            supported_scopes,
            min_pq_security_bits:
                PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS,
            fee_sponsor_budget_units: 50_000,
            issued_count: 0,
            revoked_count: 0,
            registered_height,
            metadata_root: private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-ISSUER-METADATA",
                &format!("{issuer_label}:metadata"),
            ),
        };
        issuer.validate()?;
        Ok(issuer)
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.issuer_id, "private pq identity issuer id")?;
        ensure_non_empty(&self.issuer_label, "private pq identity issuer label")?;
        ensure_non_empty(
            &self.pq_verification_key_root,
            "private pq identity issuer pq verification key root",
        )?;
        ensure_non_empty(
            &self.pq_attestation_policy_root,
            "private pq identity issuer attestation policy root",
        )?;
        ensure_non_empty(
            &self.revocation_accumulator_root,
            "private pq identity issuer revocation accumulator root",
        )?;
        ensure_non_empty(
            &self.metadata_root,
            "private pq identity issuer metadata root",
        )?;
        if self.supported_kinds.is_empty() {
            return Err("private pq identity issuer must support a credential kind".to_string());
        }
        if self.supported_scopes.is_empty() {
            return Err("private pq identity issuer must support a contract scope".to_string());
        }
        if self.min_pq_security_bits == 0 {
            return Err("private pq identity issuer pq security bits must be positive".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialCommitment {
    pub credential_id: String,
    pub issuer_id: String,
    pub kind: CredentialKind,
    pub status: CredentialStatus,
    pub subject_commitment: String,
    pub unlinkable_commitment: String,
    pub credential_policy_root: String,
    pub attribute_commitment_root: String,
    pub revocation_handle_commitment: String,
    pub pq_issuer_signature_root: String,
    pub holder_binding_root: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub assurance_level: u8,
    pub anonymity_set_size: u64,
    pub risk_score_bps: u64,
    pub allowed_scopes: BTreeSet<ContractScope>,
    pub tags: BTreeSet<String>,
}

impl CredentialCommitment {
    pub fn new(
        issuer_id: &str,
        kind: CredentialKind,
        subject_commitment: &str,
        credential_policy_root: &str,
        attribute_commitment_root: &str,
        revocation_handle_commitment: &str,
        pq_issuer_signature_root: &str,
        issued_height: u64,
        ttl_blocks: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let unlinkable_commitment = unlinkable_credential_commitment(
            issuer_id,
            kind,
            subject_commitment,
            credential_policy_root,
            attribute_commitment_root,
            issued_height,
        );
        let credential_id = credential_commitment_id(
            issuer_id,
            kind,
            &unlinkable_commitment,
            revocation_handle_commitment,
            pq_issuer_signature_root,
        );
        let mut allowed_scopes = BTreeSet::new();
        allowed_scopes.insert(ContractScope::View);
        if matches!(
            kind,
            CredentialKind::KycLight
                | CredentialKind::KycFull
                | CredentialKind::AccreditedInvestor
                | CredentialKind::DefiRiskTier
                | CredentialKind::BridgeEligibility
        ) {
            allowed_scopes.insert(ContractScope::Swap);
            allowed_scopes.insert(ContractScope::Lending);
        }
        let credential = Self {
            credential_id,
            issuer_id: issuer_id.to_string(),
            kind,
            status: CredentialStatus::Attested,
            subject_commitment: subject_commitment.to_string(),
            unlinkable_commitment,
            credential_policy_root: credential_policy_root.to_string(),
            attribute_commitment_root: attribute_commitment_root.to_string(),
            revocation_handle_commitment: revocation_handle_commitment.to_string(),
            pq_issuer_signature_root: pq_issuer_signature_root.to_string(),
            holder_binding_root: private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-HOLDER-BINDING",
                subject_commitment,
            ),
            issued_height,
            expires_height: issued_height.saturating_add(ttl_blocks),
            assurance_level: kind.default_assurance(),
            anonymity_set_size: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_PRIVACY_SET_SIZE,
            risk_score_bps: 2_500,
            allowed_scopes,
            tags: BTreeSet::new(),
        };
        credential.validate()?;
        Ok(credential)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.credential_id, "private pq identity credential id")?;
        ensure_non_empty(&self.issuer_id, "private pq identity credential issuer id")?;
        ensure_non_empty(
            &self.subject_commitment,
            "private pq identity subject commitment",
        )?;
        ensure_non_empty(
            &self.unlinkable_commitment,
            "private pq identity unlinkable credential commitment",
        )?;
        ensure_non_empty(
            &self.credential_policy_root,
            "private pq identity credential policy root",
        )?;
        ensure_non_empty(
            &self.attribute_commitment_root,
            "private pq identity attribute commitment root",
        )?;
        ensure_non_empty(
            &self.revocation_handle_commitment,
            "private pq identity revocation handle commitment",
        )?;
        ensure_non_empty(
            &self.pq_issuer_signature_root,
            "private pq identity issuer signature root",
        )?;
        ensure_non_empty(
            &self.holder_binding_root,
            "private pq identity holder binding root",
        )?;
        if self.expires_height <= self.issued_height {
            return Err("private pq identity credential expires before issuance".to_string());
        }
        if self.assurance_level == 0 {
            return Err("private pq identity credential assurance must be positive".to_string());
        }
        if self.anonymity_set_size == 0 {
            return Err(
                "private pq identity credential anonymity set must be positive".to_string(),
            );
        }
        if self.risk_score_bps > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_BPS {
            return Err("private pq identity credential risk exceeds bps cap".to_string());
        }
        if self.allowed_scopes.is_empty() {
            return Err("private pq identity credential must allow a contract scope".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosurePolicy {
    pub policy_id: String,
    pub policy_label: String,
    pub status: PolicyStatus,
    pub contract_id: String,
    pub scope: ContractScope,
    pub accepted_issuer_ids: BTreeSet<String>,
    pub required_kinds: BTreeSet<CredentialKind>,
    pub allowed_modes: BTreeSet<DisclosureMode>,
    pub required_attribute_names: BTreeSet<String>,
    pub optional_attribute_names: BTreeSet<String>,
    pub denied_attribute_names: BTreeSet<String>,
    pub min_assurance_level: u8,
    pub min_anonymity_set: u64,
    pub max_risk_score_bps: u64,
    pub max_disclosed_attributes: usize,
    pub require_revocation_witness: bool,
    pub require_fresh_nullifier: bool,
    pub policy_salt_commitment: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl SelectiveDisclosurePolicy {
    pub fn new(
        policy_label: &str,
        contract_id: &str,
        scope: ContractScope,
        accepted_issuer_ids: BTreeSet<String>,
        required_kinds: BTreeSet<CredentialKind>,
        created_height: u64,
        ttl_blocks: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let clean_label = normalize_label(policy_label);
        let policy_salt_commitment = private_pq_identity_string_root(
            "PRIVATE-PQ-IDENTITY-POLICY-SALT",
            &format!("{contract_id}:{clean_label}:salt"),
        );
        let policy_id = selective_disclosure_policy_id(
            &clean_label,
            contract_id,
            scope,
            &accepted_issuer_ids,
            &required_kinds,
            &policy_salt_commitment,
        );
        let mut allowed_modes = BTreeSet::new();
        allowed_modes.insert(DisclosureMode::CommitmentOnly);
        allowed_modes.insert(DisclosureMode::PredicateProof);
        let policy = Self {
            policy_id,
            policy_label: clean_label,
            status: PolicyStatus::Active,
            contract_id: contract_id.to_string(),
            scope,
            accepted_issuer_ids,
            required_kinds,
            allowed_modes,
            required_attribute_names: BTreeSet::new(),
            optional_attribute_names: BTreeSet::new(),
            denied_attribute_names: BTreeSet::new(),
            min_assurance_level: 1,
            min_anonymity_set: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MIN_ANONYMITY_SET,
            max_risk_score_bps: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_RISK_SCORE_BPS,
            max_disclosed_attributes: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_ATTRIBUTES,
            require_revocation_witness: true,
            require_fresh_nullifier: true,
            policy_salt_commitment,
            created_height,
            expires_height: created_height.saturating_add(ttl_blocks),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn accepts(&self, credential: &CredentialCommitment) -> bool {
        self.status.accepts_proofs()
            && self.accepted_issuer_ids.contains(&credential.issuer_id)
            && self.required_kinds.contains(&credential.kind)
            && credential.assurance_level >= self.min_assurance_level
            && credential.anonymity_set_size >= self.min_anonymity_set
            && credential.risk_score_bps <= self.max_risk_score_bps
            && credential.allowed_scopes.contains(&self.scope)
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.policy_id, "private pq identity policy id")?;
        ensure_non_empty(&self.policy_label, "private pq identity policy label")?;
        ensure_non_empty(&self.contract_id, "private pq identity policy contract id")?;
        ensure_non_empty(
            &self.policy_salt_commitment,
            "private pq identity policy salt commitment",
        )?;
        if self.accepted_issuer_ids.is_empty() {
            return Err("private pq identity policy must accept an issuer".to_string());
        }
        if self.required_kinds.is_empty() {
            return Err("private pq identity policy must require a credential kind".to_string());
        }
        if self.allowed_modes.is_empty() {
            return Err("private pq identity policy must allow a disclosure mode".to_string());
        }
        if self.min_assurance_level == 0 {
            return Err("private pq identity policy assurance must be positive".to_string());
        }
        if self.min_anonymity_set == 0 {
            return Err("private pq identity policy anonymity set must be positive".to_string());
        }
        if self.max_risk_score_bps > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_BPS {
            return Err("private pq identity policy risk exceeds bps cap".to_string());
        }
        if self.max_disclosed_attributes == 0 {
            return Err(
                "private pq identity policy max disclosed attributes must be positive".to_string(),
            );
        }
        if self.expires_height <= self.created_height {
            return Err("private pq identity policy expires before creation".to_string());
        }
        for attribute in &self.denied_attribute_names {
            if self.required_attribute_names.contains(attribute) {
                return Err("private pq identity policy denies a required attribute".to_string());
            }
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosureRequest {
    pub disclosure_id: String,
    pub policy_id: String,
    pub credential_id: String,
    pub contract_id: String,
    pub mode: DisclosureMode,
    pub status: DisclosureStatus,
    pub disclosed_attribute_commitments: BTreeMap<String, String>,
    pub predicate_roots: BTreeMap<String, String>,
    pub encrypted_payload_root: String,
    pub revocation_witness_root: String,
    pub nullifier_commitment: String,
    pub proof_root: String,
    pub requested_height: u64,
    pub expires_height: u64,
}

impl SelectiveDisclosureRequest {
    pub fn new(
        policy: &SelectiveDisclosurePolicy,
        credential: &CredentialCommitment,
        mode: DisclosureMode,
        proof_root: &str,
        requested_height: u64,
        ttl_blocks: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let nullifier_commitment = contract_credential_nullifier(
            &credential.credential_id,
            &policy.policy_id,
            &policy.contract_id,
            requested_height,
        );
        let encrypted_payload_root = private_pq_identity_string_root(
            "PRIVATE-PQ-IDENTITY-DISCLOSURE-PAYLOAD",
            &format!("{}:{}", policy.policy_id, credential.credential_id),
        );
        let revocation_witness_root = private_pq_identity_string_root(
            "PRIVATE-PQ-IDENTITY-REVOCATION-WITNESS",
            &credential.revocation_handle_commitment,
        );
        let disclosure_id = selective_disclosure_id(
            &policy.policy_id,
            &credential.credential_id,
            mode,
            &nullifier_commitment,
            proof_root,
        );
        let request = Self {
            disclosure_id,
            policy_id: policy.policy_id.clone(),
            credential_id: credential.credential_id.clone(),
            contract_id: policy.contract_id.clone(),
            mode,
            status: DisclosureStatus::Verified,
            disclosed_attribute_commitments: BTreeMap::new(),
            predicate_roots: BTreeMap::new(),
            encrypted_payload_root,
            revocation_witness_root,
            nullifier_commitment,
            proof_root: proof_root.to_string(),
            requested_height,
            expires_height: requested_height.saturating_add(ttl_blocks),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.disclosure_id, "private pq identity disclosure id")?;
        ensure_non_empty(&self.policy_id, "private pq identity disclosure policy id")?;
        ensure_non_empty(
            &self.credential_id,
            "private pq identity disclosure credential id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private pq identity disclosure contract id",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "private pq identity disclosure encrypted payload root",
        )?;
        ensure_non_empty(
            &self.revocation_witness_root,
            "private pq identity disclosure revocation witness root",
        )?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "private pq identity disclosure nullifier commitment",
        )?;
        ensure_non_empty(
            &self.proof_root,
            "private pq identity disclosure proof root",
        )?;
        if self.expires_height <= self.requested_height {
            return Err("private pq identity disclosure expires before request".to_string());
        }
        if self.disclosed_attribute_commitments.len()
            > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_ATTRIBUTES
        {
            return Err("private pq identity disclosure has too many attributes".to_string());
        }
        for key in self.disclosed_attribute_commitments.keys() {
            ensure_non_empty(key, "private pq identity disclosed attribute name")?;
        }
        for value in self.disclosed_attribute_commitments.values() {
            ensure_non_empty(value, "private pq identity disclosed attribute commitment")?;
        }
        for key in self.predicate_roots.keys() {
            ensure_non_empty(key, "private pq identity predicate name")?;
        }
        for value in self.predicate_roots.values() {
            ensure_non_empty(value, "private pq identity predicate root")?;
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeCredentialSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub disclosure_id: String,
    pub credential_id: String,
    pub policy_id: String,
    pub status: SponsorshipStatus,
    pub fee_asset_id: String,
    pub lane_id: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub discount_bps: u64,
    pub sponsor_budget_root: String,
    pub settlement_receipt_root: String,
    pub reserved_height: u64,
    pub expires_height: u64,
}

impl LowFeeCredentialSponsorship {
    pub fn new(
        sponsor_commitment: &str,
        disclosure: &SelectiveDisclosureRequest,
        max_fee_units: u64,
        discount_bps: u64,
        reserved_height: u64,
        ttl_blocks: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let sponsor_budget_root = private_pq_identity_string_root(
            "PRIVATE-PQ-IDENTITY-SPONSOR-BUDGET",
            sponsor_commitment,
        );
        let settlement_receipt_root = private_pq_identity_string_root(
            "PRIVATE-PQ-IDENTITY-SPONSOR-SETTLEMENT",
            &disclosure.disclosure_id,
        );
        let sponsorship_id = low_fee_credential_sponsorship_id(
            sponsor_commitment,
            &disclosure.disclosure_id,
            &disclosure.nullifier_commitment,
            max_fee_units,
            discount_bps,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            disclosure_id: disclosure.disclosure_id.clone(),
            credential_id: disclosure.credential_id.clone(),
            policy_id: disclosure.policy_id.clone(),
            status: SponsorshipStatus::Reserved,
            fee_asset_id: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_FEE_ASSET_ID.to_string(),
            lane_id: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_LOW_FEE_LANE.to_string(),
            max_fee_units,
            reserved_fee_units: max_fee_units.saturating_mul(discount_bps) / 10_000,
            discount_bps,
            sponsor_budget_root,
            settlement_receipt_root,
            reserved_height,
            expires_height: reserved_height.saturating_add(ttl_blocks),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.sponsorship_id, "private pq identity sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "private pq identity sponsor commitment",
        )?;
        ensure_non_empty(
            &self.disclosure_id,
            "private pq identity sponsorship disclosure id",
        )?;
        ensure_non_empty(
            &self.credential_id,
            "private pq identity sponsorship credential id",
        )?;
        ensure_non_empty(&self.policy_id, "private pq identity sponsorship policy id")?;
        ensure_non_empty(
            &self.fee_asset_id,
            "private pq identity sponsorship fee asset",
        )?;
        ensure_non_empty(&self.lane_id, "private pq identity sponsorship lane")?;
        ensure_non_empty(
            &self.sponsor_budget_root,
            "private pq identity sponsorship budget root",
        )?;
        ensure_non_empty(
            &self.settlement_receipt_root,
            "private pq identity sponsorship settlement receipt root",
        )?;
        if self.max_fee_units == 0 {
            return Err("private pq identity sponsorship max fee must be positive".to_string());
        }
        if self.reserved_fee_units > self.max_fee_units {
            return Err("private pq identity sponsorship reserves more than max fee".to_string());
        }
        if self.discount_bps > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_BPS {
            return Err("private pq identity sponsorship discount exceeds bps cap".to_string());
        }
        if self.expires_height <= self.reserved_height {
            return Err("private pq identity sponsorship expires before reservation".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractAuthorizationReceipt {
    pub receipt_id: String,
    pub contract_id: String,
    pub contract_call_commitment: String,
    pub policy_id: String,
    pub disclosure_id: String,
    pub credential_id: String,
    pub sponsorship_id: Option<String>,
    pub scope: ContractScope,
    pub status: AuthorizationStatus,
    pub authorization_nullifier: String,
    pub receipt_proof_root: String,
    pub gas_sponsor_root: String,
    pub authorized_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
}

impl ContractAuthorizationReceipt {
    pub fn new(
        contract_id: &str,
        contract_call_commitment: &str,
        policy: &SelectiveDisclosurePolicy,
        disclosure: &SelectiveDisclosureRequest,
        sponsorship_id: Option<String>,
        receipt_proof_root: &str,
        authorized_height: u64,
        ttl_blocks: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let authorization_nullifier = contract_authorization_nullifier(
            contract_id,
            contract_call_commitment,
            &disclosure.nullifier_commitment,
            authorized_height,
        );
        let gas_sponsor_root = match &sponsorship_id {
            Some(value) => {
                private_pq_identity_string_root("PRIVATE-PQ-IDENTITY-AUTH-SPONSOR", value.as_str())
            }
            None => {
                private_pq_identity_string_root("PRIVATE-PQ-IDENTITY-AUTH-SPONSOR", "self-paid")
            }
        };
        let receipt_id = contract_authorization_receipt_id(
            contract_id,
            contract_call_commitment,
            &policy.policy_id,
            &disclosure.disclosure_id,
            &authorization_nullifier,
            receipt_proof_root,
        );
        let receipt = Self {
            receipt_id,
            contract_id: contract_id.to_string(),
            contract_call_commitment: contract_call_commitment.to_string(),
            policy_id: policy.policy_id.clone(),
            disclosure_id: disclosure.disclosure_id.clone(),
            credential_id: disclosure.credential_id.clone(),
            sponsorship_id,
            scope: policy.scope,
            status: AuthorizationStatus::Accepted,
            authorization_nullifier,
            receipt_proof_root: receipt_proof_root.to_string(),
            gas_sponsor_root,
            authorized_height,
            expires_height: authorized_height.saturating_add(ttl_blocks),
            consumed_height: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn consume(&mut self, height: u64) -> PrivatePqIdentityCredentialBridgeResult<String> {
        if self.status == AuthorizationStatus::Consumed {
            return Err("private pq identity authorization receipt already consumed".to_string());
        }
        if self.expires_height <= height {
            self.status = AuthorizationStatus::Expired;
            return Err("private pq identity authorization receipt expired".to_string());
        }
        self.status = AuthorizationStatus::Consumed;
        self.consumed_height = Some(height);
        self.validate()
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(
            &self.receipt_id,
            "private pq identity authorization receipt id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private pq identity authorization contract id",
        )?;
        ensure_non_empty(
            &self.contract_call_commitment,
            "private pq identity authorization call commitment",
        )?;
        ensure_non_empty(
            &self.policy_id,
            "private pq identity authorization policy id",
        )?;
        ensure_non_empty(
            &self.disclosure_id,
            "private pq identity authorization disclosure id",
        )?;
        ensure_non_empty(
            &self.credential_id,
            "private pq identity authorization credential id",
        )?;
        ensure_non_empty(
            &self.authorization_nullifier,
            "private pq identity authorization nullifier",
        )?;
        ensure_non_empty(
            &self.receipt_proof_root,
            "private pq identity authorization proof root",
        )?;
        ensure_non_empty(
            &self.gas_sponsor_root,
            "private pq identity authorization gas root",
        )?;
        if self.expires_height <= self.authorized_height {
            return Err(
                "private pq identity authorization expires before authorization".to_string(),
            );
        }
        if let Some(consumed_height) = self.consumed_height {
            if consumed_height < self.authorized_height {
                return Err(
                    "private pq identity authorization consumed before authorization".to_string(),
                );
            }
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub revocation_id: String,
    pub issuer_id: String,
    pub credential_id: String,
    pub revocation_handle_commitment: String,
    pub status: RevocationStatus,
    pub reason_code: String,
    pub accumulator_root_before: String,
    pub accumulator_root_after: String,
    pub pq_revocation_signature_root: String,
    pub revoked_height: u64,
}

impl RevocationEntry {
    pub fn new(
        issuer_id: &str,
        credential_id: &str,
        revocation_handle_commitment: &str,
        reason_code: &str,
        accumulator_root_before: &str,
        pq_revocation_signature_root: &str,
        revoked_height: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let accumulator_root_after = revocation_accumulator_after(
            issuer_id,
            credential_id,
            revocation_handle_commitment,
            accumulator_root_before,
            pq_revocation_signature_root,
        );
        let revocation_id = revocation_entry_id(
            issuer_id,
            credential_id,
            revocation_handle_commitment,
            &accumulator_root_after,
        );
        let entry = Self {
            revocation_id,
            issuer_id: issuer_id.to_string(),
            credential_id: credential_id.to_string(),
            revocation_handle_commitment: revocation_handle_commitment.to_string(),
            status: RevocationStatus::Active,
            reason_code: normalize_label(reason_code),
            accumulator_root_before: accumulator_root_before.to_string(),
            accumulator_root_after,
            pq_revocation_signature_root: pq_revocation_signature_root.to_string(),
            revoked_height,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.revocation_id, "private pq identity revocation id")?;
        ensure_non_empty(&self.issuer_id, "private pq identity revocation issuer id")?;
        ensure_non_empty(
            &self.credential_id,
            "private pq identity revocation credential id",
        )?;
        ensure_non_empty(
            &self.revocation_handle_commitment,
            "private pq identity revocation handle commitment",
        )?;
        ensure_non_empty(&self.reason_code, "private pq identity revocation reason")?;
        ensure_non_empty(
            &self.accumulator_root_before,
            "private pq identity revocation accumulator before",
        )?;
        ensure_non_empty(
            &self.accumulator_root_after,
            "private pq identity revocation accumulator after",
        )?;
        ensure_non_empty(
            &self.pq_revocation_signature_root,
            "private pq identity revocation signature root",
        )?;
        if self.accumulator_root_before == self.accumulator_root_after {
            return Err("private pq identity revocation accumulator did not change".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierEntry {
    pub nullifier_id: String,
    pub nullifier_commitment: String,
    pub credential_id: String,
    pub policy_id: String,
    pub contract_id: String,
    pub status: NullifierStatus,
    pub first_seen_height: u64,
    pub expires_height: u64,
    pub receipt_ids: BTreeSet<String>,
}

impl NullifierEntry {
    pub fn new(
        nullifier_commitment: &str,
        credential_id: &str,
        policy_id: &str,
        contract_id: &str,
        first_seen_height: u64,
        ttl_blocks: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let nullifier_id = nullifier_entry_id(
            nullifier_commitment,
            credential_id,
            policy_id,
            contract_id,
            first_seen_height,
        );
        let entry = Self {
            nullifier_id,
            nullifier_commitment: nullifier_commitment.to_string(),
            credential_id: credential_id.to_string(),
            policy_id: policy_id.to_string(),
            contract_id: contract_id.to_string(),
            status: NullifierStatus::Reserved,
            first_seen_height,
            expires_height: first_seen_height.saturating_add(ttl_blocks),
            receipt_ids: BTreeSet::new(),
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn mark_spent(
        &mut self,
        receipt_id: &str,
    ) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(receipt_id, "private pq identity nullifier receipt id")?;
        self.status = NullifierStatus::Spent;
        self.receipt_ids.insert(receipt_id.to_string());
        self.validate()
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.nullifier_id, "private pq identity nullifier id")?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "private pq identity nullifier commitment",
        )?;
        ensure_non_empty(
            &self.credential_id,
            "private pq identity nullifier credential id",
        )?;
        ensure_non_empty(&self.policy_id, "private pq identity nullifier policy id")?;
        ensure_non_empty(
            &self.contract_id,
            "private pq identity nullifier contract id",
        )?;
        if self.expires_height <= self.first_seen_height {
            return Err("private pq identity nullifier expires before first seen".to_string());
        }
        for receipt_id in &self.receipt_ids {
            ensure_non_empty(receipt_id, "private pq identity nullifier receipt id")?;
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivatePqIdentityCredentialBridgeRoots {
    pub config_root: String,
    pub issuer_root: String,
    pub credential_root: String,
    pub policy_root: String,
    pub disclosure_root: String,
    pub sponsorship_root: String,
    pub authorization_receipt_root: String,
    pub revocation_root: String,
    pub nullifier_root: String,
    pub active_issuer_root: String,
    pub active_credential_root: String,
    pub live_disclosure_root: String,
    pub open_sponsorship_root: String,
    pub usable_receipt_root: String,
    pub revoked_credential_root: String,
    pub spent_nullifier_root: String,
    pub state_root: String,
}

impl PrivatePqIdentityCredentialBridgeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "issuer_root": self.issuer_root,
            "credential_root": self.credential_root,
            "policy_root": self.policy_root,
            "disclosure_root": self.disclosure_root,
            "sponsorship_root": self.sponsorship_root,
            "authorization_receipt_root": self.authorization_receipt_root,
            "revocation_root": self.revocation_root,
            "nullifier_root": self.nullifier_root,
            "active_issuer_root": self.active_issuer_root,
            "active_credential_root": self.active_credential_root,
            "live_disclosure_root": self.live_disclosure_root,
            "open_sponsorship_root": self.open_sponsorship_root,
            "usable_receipt_root": self.usable_receipt_root,
            "revoked_credential_root": self.revoked_credential_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivatePqIdentityCredentialBridgeCounters {
    pub issuer_count: u64,
    pub active_issuer_count: u64,
    pub credential_count: u64,
    pub active_credential_count: u64,
    pub policy_count: u64,
    pub active_policy_count: u64,
    pub disclosure_count: u64,
    pub live_disclosure_count: u64,
    pub sponsorship_count: u64,
    pub open_sponsorship_count: u64,
    pub authorization_receipt_count: u64,
    pub usable_receipt_count: u64,
    pub revocation_count: u64,
    pub active_revocation_count: u64,
    pub nullifier_count: u64,
    pub spent_nullifier_count: u64,
    pub sponsored_fee_units_reserved: u64,
    pub sponsored_fee_units_settled: u64,
}

impl PrivatePqIdentityCredentialBridgeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "issuer_count": self.issuer_count,
            "active_issuer_count": self.active_issuer_count,
            "credential_count": self.credential_count,
            "active_credential_count": self.active_credential_count,
            "policy_count": self.policy_count,
            "active_policy_count": self.active_policy_count,
            "disclosure_count": self.disclosure_count,
            "live_disclosure_count": self.live_disclosure_count,
            "sponsorship_count": self.sponsorship_count,
            "open_sponsorship_count": self.open_sponsorship_count,
            "authorization_receipt_count": self.authorization_receipt_count,
            "usable_receipt_count": self.usable_receipt_count,
            "revocation_count": self.revocation_count,
            "active_revocation_count": self.active_revocation_count,
            "nullifier_count": self.nullifier_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "sponsored_fee_units_reserved": self.sponsored_fee_units_reserved,
            "sponsored_fee_units_settled": self.sponsored_fee_units_settled,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivatePqIdentityCredentialBridgeState {
    pub label: String,
    pub height: u64,
    pub config: PrivatePqIdentityCredentialBridgeConfig,
    pub issuers: BTreeMap<String, PqIssuer>,
    pub credentials: BTreeMap<String, CredentialCommitment>,
    pub policies: BTreeMap<String, SelectiveDisclosurePolicy>,
    pub disclosures: BTreeMap<String, SelectiveDisclosureRequest>,
    pub sponsorships: BTreeMap<String, LowFeeCredentialSponsorship>,
    pub authorization_receipts: BTreeMap<String, ContractAuthorizationReceipt>,
    pub revocations: BTreeMap<String, RevocationEntry>,
    pub nullifiers: BTreeMap<String, NullifierEntry>,
}

impl PrivatePqIdentityCredentialBridgeState {
    pub fn devnet() -> PrivatePqIdentityCredentialBridgeResult<Self> {
        let config = PrivatePqIdentityCredentialBridgeConfig::devnet()?;
        let mut state = Self {
            label: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEVNET_LABEL.to_string(),
            height: PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_HEIGHT,
            config,
            issuers: BTreeMap::new(),
            credentials: BTreeMap::new(),
            policies: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            authorization_receipts: BTreeMap::new(),
            revocations: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
        };

        let issuer = PqIssuer::new(
            "devnet-attestation-issuer",
            BridgeNetwork::NebulaL2,
            &private_pq_identity_string_root("PRIVATE-PQ-IDENTITY-DEVNET-PQ-VK", "issuer-vk"),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-ATTESTATION-POLICY",
                "issuer-policy",
            ),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-REVOCATION-ACCUMULATOR",
                "issuer-revocations",
            ),
            state.height,
        )?;
        let issuer_id = issuer.issuer_id.clone();
        state.register_issuer(issuer)?;

        let credential = CredentialCommitment::new(
            &issuer_id,
            CredentialKind::DefiRiskTier,
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-SUBJECT",
                "unlinkable-subject",
            ),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-CREDENTIAL-POLICY",
                "defi-risk-tier-policy",
            ),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-ATTRIBUTES",
                "risk-tier-under-7500",
            ),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-REVOCATION-HANDLE",
                "credential-revocation-handle",
            ),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-PQ-SIGNATURE",
                "issuer-signature",
            ),
            state.height,
            state.config.epoch_blocks.saturating_mul(32),
        )?;
        let credential_id = credential.credential_id.clone();
        state.commit_credential(credential)?;

        let mut accepted_issuers = BTreeSet::new();
        accepted_issuers.insert(issuer_id);
        let mut required_kinds = BTreeSet::new();
        required_kinds.insert(CredentialKind::DefiRiskTier);
        let policy = SelectiveDisclosurePolicy::new(
            "devnet-defi-contract-policy",
            "devnet-private-swap-contract",
            ContractScope::Swap,
            accepted_issuers,
            required_kinds,
            state.height,
            state.config.epoch_blocks,
        )?;
        let policy_id = policy.policy_id.clone();
        state.register_policy(policy)?;

        let disclosure = state.request_disclosure(
            &policy_id,
            &credential_id,
            DisclosureMode::PredicateProof,
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-DISCLOSURE-PROOF",
                "risk-tier-proof",
            ),
        )?;
        let disclosure_id = disclosure.disclosure_id.clone();
        let sponsorship = state.reserve_sponsorship(
            &private_pq_identity_string_root("PRIVATE-PQ-IDENTITY-DEVNET-SPONSOR", "fee-sponsor"),
            &disclosure_id,
            PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_DEFAULT_MAX_FEE_UNITS,
            8_000,
        )?;
        state.authorize_contract_call(
            "devnet-private-swap-contract",
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-CONTRACT-CALL",
                "swap-call",
            ),
            &policy_id,
            &disclosure_id,
            Some(sponsorship.sponsorship_id),
            &private_pq_identity_string_root(
                "PRIVATE-PQ-IDENTITY-DEVNET-AUTH-PROOF",
                "contract-auth-proof",
            ),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivatePqIdentityCredentialBridgeResult<String> {
        self.height = height;
        self.expire_at_height();
        self.validate()
    }

    pub fn register_issuer(
        &mut self,
        issuer: PqIssuer,
    ) -> PrivatePqIdentityCredentialBridgeResult<String> {
        issuer.validate()?;
        if self.issuers.contains_key(&issuer.issuer_id) {
            return Err("private pq identity issuer already registered".to_string());
        }
        if self.issuers.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_ISSUERS {
            return Err("private pq identity issuer cap reached".to_string());
        }
        let issuer_id = issuer.issuer_id.clone();
        self.issuers.insert(issuer_id, issuer);
        self.validate()
    }

    pub fn commit_credential(
        &mut self,
        credential: CredentialCommitment,
    ) -> PrivatePqIdentityCredentialBridgeResult<String> {
        credential.validate()?;
        if !self.issuers.contains_key(&credential.issuer_id) {
            return Err("private pq identity credential references missing issuer".to_string());
        }
        if self.credentials.contains_key(&credential.credential_id) {
            return Err("private pq identity credential already committed".to_string());
        }
        if self.credentials.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_CREDENTIALS {
            return Err("private pq identity credential cap reached".to_string());
        }
        let issuer = self
            .issuers
            .get_mut(&credential.issuer_id)
            .ok_or_else(|| "private pq identity credential issuer missing".to_string())?;
        if !issuer.status.can_attest() {
            return Err("private pq identity issuer cannot attest".to_string());
        }
        if !issuer.supported_kinds.contains(&credential.kind) {
            return Err("private pq identity issuer does not support credential kind".to_string());
        }
        issuer.issued_count = issuer.issued_count.saturating_add(1);
        let credential_id = credential.credential_id.clone();
        self.credentials.insert(credential_id, credential);
        self.validate()
    }

    pub fn register_policy(
        &mut self,
        policy: SelectiveDisclosurePolicy,
    ) -> PrivatePqIdentityCredentialBridgeResult<String> {
        policy.validate()?;
        if self.policies.contains_key(&policy.policy_id) {
            return Err("private pq identity policy already registered".to_string());
        }
        if self.policies.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_POLICIES {
            return Err("private pq identity policy cap reached".to_string());
        }
        for issuer_id in &policy.accepted_issuer_ids {
            if !self.issuers.contains_key(issuer_id) {
                return Err("private pq identity policy references missing issuer".to_string());
            }
        }
        let policy_id = policy.policy_id.clone();
        self.policies.insert(policy_id, policy);
        self.validate()
    }

    pub fn request_disclosure(
        &mut self,
        policy_id: &str,
        credential_id: &str,
        mode: DisclosureMode,
        proof_root: &str,
    ) -> PrivatePqIdentityCredentialBridgeResult<SelectiveDisclosureRequest> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| "private pq identity policy not found".to_string())?;
        let credential = self
            .credentials
            .get(credential_id)
            .ok_or_else(|| "private pq identity credential not found".to_string())?;
        if !policy.allowed_modes.contains(&mode) {
            return Err("private pq identity disclosure mode not allowed".to_string());
        }
        if !credential.status.usable() {
            return Err("private pq identity credential is not usable".to_string());
        }
        if credential.expired_at(self.height) {
            return Err("private pq identity credential expired".to_string());
        }
        if !policy.accepts(credential) {
            return Err("private pq identity credential does not satisfy policy".to_string());
        }
        if self.disclosures.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_DISCLOSURES {
            return Err("private pq identity disclosure cap reached".to_string());
        }
        let disclosure = SelectiveDisclosureRequest::new(
            policy,
            credential,
            mode,
            proof_root,
            self.height,
            self.config.disclosure_ttl_blocks,
        )?;
        if self
            .nullifiers
            .contains_key(&disclosure.nullifier_commitment)
        {
            return Err("private pq identity disclosure nullifier already seen".to_string());
        }
        let nullifier = NullifierEntry::new(
            &disclosure.nullifier_commitment,
            credential_id,
            policy_id,
            &policy.contract_id,
            self.height,
            self.config.epoch_blocks,
        )?;
        self.nullifiers
            .insert(disclosure.nullifier_commitment.clone(), nullifier);
        self.disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure.clone());
        self.validate()?;
        Ok(disclosure)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsor_commitment: &str,
        disclosure_id: &str,
        max_fee_units: u64,
        discount_bps: u64,
    ) -> PrivatePqIdentityCredentialBridgeResult<LowFeeCredentialSponsorship> {
        let disclosure = self.disclosures.get(disclosure_id).ok_or_else(|| {
            "private pq identity disclosure not found for sponsorship".to_string()
        })?;
        if !disclosure.status.live() {
            return Err("private pq identity disclosure is not live for sponsorship".to_string());
        }
        if max_fee_units > self.config.max_sponsor_fee_units {
            return Err("private pq identity sponsorship fee exceeds config cap".to_string());
        }
        if self.sponsorships.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_SPONSORSHIPS {
            return Err("private pq identity sponsorship cap reached".to_string());
        }
        let sponsorship = LowFeeCredentialSponsorship::new(
            sponsor_commitment,
            disclosure,
            max_fee_units,
            discount_bps,
            self.height,
            self.config.sponsor_window_blocks,
        )?;
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        self.validate()?;
        Ok(sponsorship)
    }

    pub fn authorize_contract_call(
        &mut self,
        contract_id: &str,
        contract_call_commitment: &str,
        policy_id: &str,
        disclosure_id: &str,
        sponsorship_id: Option<String>,
        receipt_proof_root: &str,
    ) -> PrivatePqIdentityCredentialBridgeResult<ContractAuthorizationReceipt> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| "private pq identity policy not found for authorization".to_string())?;
        let disclosure = self.disclosures.get(disclosure_id).ok_or_else(|| {
            "private pq identity disclosure not found for authorization".to_string()
        })?;
        if policy.contract_id != contract_id {
            return Err("private pq identity policy contract mismatch".to_string());
        }
        if disclosure.policy_id != policy_id {
            return Err("private pq identity disclosure policy mismatch".to_string());
        }
        if disclosure.contract_id != contract_id {
            return Err("private pq identity disclosure contract mismatch".to_string());
        }
        if !disclosure.status.live() {
            return Err("private pq identity disclosure not live for authorization".to_string());
        }
        if disclosure.expired_at(self.height) {
            return Err("private pq identity disclosure expired for authorization".to_string());
        }
        if let Some(value) = &sponsorship_id {
            let sponsorship = self.sponsorships.get(value).ok_or_else(|| {
                "private pq identity sponsorship missing for authorization".to_string()
            })?;
            if sponsorship.disclosure_id != disclosure_id {
                return Err("private pq identity sponsorship disclosure mismatch".to_string());
            }
            if !sponsorship.status.open() {
                return Err("private pq identity sponsorship not open".to_string());
            }
        }
        if self.authorization_receipts.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_RECEIPTS {
            return Err("private pq identity authorization receipt cap reached".to_string());
        }
        let receipt = ContractAuthorizationReceipt::new(
            contract_id,
            contract_call_commitment,
            policy,
            disclosure,
            sponsorship_id,
            receipt_proof_root,
            self.height,
            self.config.receipt_ttl_blocks,
        )?;
        self.authorization_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.validate()?;
        Ok(receipt)
    }

    pub fn consume_authorization_receipt(
        &mut self,
        receipt_id: &str,
    ) -> PrivatePqIdentityCredentialBridgeResult<String> {
        let disclosure_id = self
            .authorization_receipts
            .get(receipt_id)
            .ok_or_else(|| "private pq identity authorization receipt missing".to_string())?
            .disclosure_id
            .clone();
        let disclosure_nullifier = self
            .disclosures
            .get(&disclosure_id)
            .ok_or_else(|| "private pq identity disclosure missing for receipt".to_string())?
            .nullifier_commitment
            .clone();
        let receipt = self
            .authorization_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "private pq identity authorization receipt missing".to_string())?;
        receipt.consume(self.height)?;
        if let Some(entry) = self.nullifiers.get_mut(&disclosure_nullifier) {
            entry.mark_spent(receipt_id)?;
        }
        if let Some(sponsorship_id) = &receipt.sponsorship_id {
            if let Some(sponsorship) = self.sponsorships.get_mut(sponsorship_id) {
                sponsorship.status = SponsorshipStatus::Settled;
                sponsorship.validate()?;
            }
        }
        self.validate()
    }

    pub fn revoke_credential(
        &mut self,
        credential_id: &str,
        reason_code: &str,
        pq_revocation_signature_root: &str,
    ) -> PrivatePqIdentityCredentialBridgeResult<RevocationEntry> {
        let credential = self
            .credentials
            .get_mut(credential_id)
            .ok_or_else(|| "private pq identity credential missing for revocation".to_string())?;
        let issuer = self
            .issuers
            .get_mut(&credential.issuer_id)
            .ok_or_else(|| "private pq identity issuer missing for revocation".to_string())?;
        let entry = RevocationEntry::new(
            &credential.issuer_id,
            credential_id,
            &credential.revocation_handle_commitment,
            reason_code,
            &issuer.revocation_accumulator_root,
            pq_revocation_signature_root,
            self.height,
        )?;
        credential.status = CredentialStatus::Revoked;
        issuer.revoked_count = issuer.revoked_count.saturating_add(1);
        issuer.revocation_accumulator_root = entry.accumulator_root_after.clone();
        if self.revocations.len() >= PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_REVOCATIONS {
            return Err("private pq identity revocation cap reached".to_string());
        }
        self.revocations
            .insert(entry.revocation_id.clone(), entry.clone());
        self.validate()?;
        Ok(entry)
    }

    pub fn active_issuer_ids(&self) -> BTreeSet<String> {
        self.issuers
            .values()
            .filter(|issuer| issuer.status.can_attest())
            .map(|issuer| issuer.issuer_id.clone())
            .collect()
    }

    pub fn active_credential_ids(&self) -> BTreeSet<String> {
        self.credentials
            .values()
            .filter(|credential| credential.status.usable() && !credential.expired_at(self.height))
            .map(|credential| credential.credential_id.clone())
            .collect()
    }

    pub fn live_disclosure_ids(&self) -> BTreeSet<String> {
        self.disclosures
            .values()
            .filter(|disclosure| disclosure.status.live() && !disclosure.expired_at(self.height))
            .map(|disclosure| disclosure.disclosure_id.clone())
            .collect()
    }

    pub fn open_sponsorship_ids(&self) -> BTreeSet<String> {
        self.sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status.open())
            .map(|sponsorship| sponsorship.sponsorship_id.clone())
            .collect()
    }

    pub fn usable_receipt_ids(&self) -> BTreeSet<String> {
        self.authorization_receipts
            .values()
            .filter(|receipt| receipt.status.usable() && receipt.expires_height > self.height)
            .map(|receipt| receipt.receipt_id.clone())
            .collect()
    }

    pub fn revoked_credential_ids(&self) -> BTreeSet<String> {
        self.credentials
            .values()
            .filter(|credential| credential.status == CredentialStatus::Revoked)
            .map(|credential| credential.credential_id.clone())
            .collect()
    }

    pub fn spent_nullifier_ids(&self) -> BTreeSet<String> {
        self.nullifiers
            .values()
            .filter(|entry| entry.status == NullifierStatus::Spent)
            .map(|entry| entry.nullifier_id.clone())
            .collect()
    }

    pub fn roots(&self) -> PrivatePqIdentityCredentialBridgeRoots {
        let config_root = self.config.root();
        let issuer_root =
            private_pq_identity_map_root("PRIVATE-PQ-IDENTITY-BRIDGE-ISSUER-MERKLE", &self.issuers);
        let credential_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-CREDENTIAL-MERKLE",
            &self.credentials,
        );
        let policy_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-POLICY-MERKLE",
            &self.policies,
        );
        let disclosure_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-DISCLOSURE-MERKLE",
            &self.disclosures,
        );
        let sponsorship_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-SPONSORSHIP-MERKLE",
            &self.sponsorships,
        );
        let authorization_receipt_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-AUTH-RECEIPT-MERKLE",
            &self.authorization_receipts,
        );
        let revocation_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-REVOCATION-MERKLE",
            &self.revocations,
        );
        let nullifier_root = private_pq_identity_map_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-NULLIFIER-MERKLE",
            &self.nullifiers,
        );
        let active_issuer_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-ACTIVE-ISSUER-SET",
            &self.active_issuer_ids(),
        );
        let active_credential_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-ACTIVE-CREDENTIAL-SET",
            &self.active_credential_ids(),
        );
        let live_disclosure_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-LIVE-DISCLOSURE-SET",
            &self.live_disclosure_ids(),
        );
        let open_sponsorship_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-OPEN-SPONSORSHIP-SET",
            &self.open_sponsorship_ids(),
        );
        let usable_receipt_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-USABLE-RECEIPT-SET",
            &self.usable_receipt_ids(),
        );
        let revoked_credential_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-REVOKED-CREDENTIAL-SET",
            &self.revoked_credential_ids(),
        );
        let spent_nullifier_root = string_set_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-SPENT-NULLIFIER-SET",
            &self.spent_nullifier_ids(),
        );
        let state_root = domain_hash(
            "PRIVATE-PQ-IDENTITY-BRIDGE-STATE-ROOT",
            &[
                HashPart::Str(&self.label),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&issuer_root),
                HashPart::Str(&credential_root),
                HashPart::Str(&policy_root),
                HashPart::Str(&disclosure_root),
                HashPart::Str(&sponsorship_root),
                HashPart::Str(&authorization_receipt_root),
                HashPart::Str(&revocation_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&active_issuer_root),
                HashPart::Str(&active_credential_root),
                HashPart::Str(&live_disclosure_root),
                HashPart::Str(&open_sponsorship_root),
                HashPart::Str(&usable_receipt_root),
                HashPart::Str(&revoked_credential_root),
                HashPart::Str(&spent_nullifier_root),
            ],
            32,
        );
        PrivatePqIdentityCredentialBridgeRoots {
            config_root,
            issuer_root,
            credential_root,
            policy_root,
            disclosure_root,
            sponsorship_root,
            authorization_receipt_root,
            revocation_root,
            nullifier_root,
            active_issuer_root,
            active_credential_root,
            live_disclosure_root,
            open_sponsorship_root,
            usable_receipt_root,
            revoked_credential_root,
            spent_nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivatePqIdentityCredentialBridgeCounters {
        PrivatePqIdentityCredentialBridgeCounters {
            issuer_count: self.issuers.len() as u64,
            active_issuer_count: self
                .issuers
                .values()
                .filter(|issuer| issuer.status.can_attest())
                .count() as u64,
            credential_count: self.credentials.len() as u64,
            active_credential_count: self
                .credentials
                .values()
                .filter(|credential| {
                    credential.status.usable() && !credential.expired_at(self.height)
                })
                .count() as u64,
            policy_count: self.policies.len() as u64,
            active_policy_count: self
                .policies
                .values()
                .filter(|policy| policy.status.accepts_proofs())
                .count() as u64,
            disclosure_count: self.disclosures.len() as u64,
            live_disclosure_count: self
                .disclosures
                .values()
                .filter(|disclosure| {
                    disclosure.status.live() && !disclosure.expired_at(self.height)
                })
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            open_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.open())
                .count() as u64,
            authorization_receipt_count: self.authorization_receipts.len() as u64,
            usable_receipt_count: self
                .authorization_receipts
                .values()
                .filter(|receipt| receipt.status.usable() && receipt.expires_height > self.height)
                .count() as u64,
            revocation_count: self.revocations.len() as u64,
            active_revocation_count: self
                .revocations
                .values()
                .filter(|revocation| {
                    matches!(
                        revocation.status,
                        RevocationStatus::Active | RevocationStatus::Finalized
                    )
                })
                .count() as u64,
            nullifier_count: self.nullifiers.len() as u64,
            spent_nullifier_count: self
                .nullifiers
                .values()
                .filter(|entry| entry.status == NullifierStatus::Spent)
                .count() as u64,
            sponsored_fee_units_reserved: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.open())
                .map(|sponsorship| sponsorship.reserved_fee_units)
                .sum(),
            sponsored_fee_units_settled: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status == SponsorshipStatus::Settled)
                .map(|sponsorship| sponsorship.reserved_fee_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_credential_bridge_state",
            "label": self.label,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_issuer_ids": self.active_issuer_ids(),
            "active_credential_ids": self.active_credential_ids(),
            "live_disclosure_ids": self.live_disclosure_ids(),
            "open_sponsorship_ids": self.open_sponsorship_ids(),
            "usable_receipt_ids": self.usable_receipt_ids(),
            "revoked_credential_ids": self.revoked_credential_ids(),
            "spent_nullifier_ids": self.spent_nullifier_ids(),
        })
    }

    pub fn validate(&self) -> PrivatePqIdentityCredentialBridgeResult<String> {
        ensure_non_empty(&self.label, "private pq identity bridge label")?;
        self.config.validate()?;
        if self.issuers.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_ISSUERS {
            return Err("private pq identity bridge has too many issuers".to_string());
        }
        if self.credentials.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_CREDENTIALS {
            return Err("private pq identity bridge has too many credentials".to_string());
        }
        if self.policies.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_POLICIES {
            return Err("private pq identity bridge has too many policies".to_string());
        }
        if self.disclosures.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_DISCLOSURES {
            return Err("private pq identity bridge has too many disclosures".to_string());
        }
        if self.sponsorships.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_SPONSORSHIPS {
            return Err("private pq identity bridge has too many sponsorships".to_string());
        }
        if self.authorization_receipts.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_RECEIPTS {
            return Err(
                "private pq identity bridge has too many authorization receipts".to_string(),
            );
        }
        if self.revocations.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_REVOCATIONS {
            return Err("private pq identity bridge has too many revocations".to_string());
        }
        if self.nullifiers.len() > PRIVATE_PQ_IDENTITY_CREDENTIAL_BRIDGE_MAX_NULLIFIERS {
            return Err("private pq identity bridge has too many nullifiers".to_string());
        }
        for issuer in self.issuers.values() {
            issuer.validate()?;
        }
        for credential in self.credentials.values() {
            credential.validate()?;
            if !self.issuers.contains_key(&credential.issuer_id) {
                return Err("private pq identity credential references missing issuer".to_string());
            }
        }
        for policy in self.policies.values() {
            policy.validate()?;
            for issuer_id in &policy.accepted_issuer_ids {
                if !self.issuers.contains_key(issuer_id) {
                    return Err("private pq identity policy references missing issuer".to_string());
                }
            }
        }
        for disclosure in self.disclosures.values() {
            disclosure.validate()?;
            if !self.policies.contains_key(&disclosure.policy_id) {
                return Err("private pq identity disclosure references missing policy".to_string());
            }
            if !self.credentials.contains_key(&disclosure.credential_id) {
                return Err(
                    "private pq identity disclosure references missing credential".to_string(),
                );
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self.disclosures.contains_key(&sponsorship.disclosure_id) {
                return Err(
                    "private pq identity sponsorship references missing disclosure".to_string(),
                );
            }
        }
        for receipt in self.authorization_receipts.values() {
            receipt.validate()?;
            if !self.disclosures.contains_key(&receipt.disclosure_id) {
                return Err("private pq identity receipt references missing disclosure".to_string());
            }
            if !self.policies.contains_key(&receipt.policy_id) {
                return Err("private pq identity receipt references missing policy".to_string());
            }
            if let Some(sponsorship_id) = &receipt.sponsorship_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err(
                        "private pq identity receipt references missing sponsorship".to_string()
                    );
                }
            }
        }
        for revocation in self.revocations.values() {
            revocation.validate()?;
            if !self.issuers.contains_key(&revocation.issuer_id) {
                return Err("private pq identity revocation references missing issuer".to_string());
            }
            if !self.credentials.contains_key(&revocation.credential_id) {
                return Err(
                    "private pq identity revocation references missing credential".to_string(),
                );
            }
        }
        for nullifier in self.nullifiers.values() {
            nullifier.validate()?;
        }
        Ok(self.state_root())
    }

    fn expire_at_height(&mut self) {
        for credential in self.credentials.values_mut() {
            if credential.status.usable() && credential.expires_height <= self.height {
                credential.status = CredentialStatus::Expired;
            }
        }
        for disclosure in self.disclosures.values_mut() {
            if disclosure.status.live() && disclosure.expires_height <= self.height {
                disclosure.status = DisclosureStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.open() && sponsorship.expires_height <= self.height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for receipt in self.authorization_receipts.values_mut() {
            if receipt.status.usable() && receipt.expires_height <= self.height {
                receipt.status = AuthorizationStatus::Expired;
            }
        }
        for nullifier in self.nullifiers.values_mut() {
            if nullifier.status == NullifierStatus::Reserved
                && nullifier.expires_height <= self.height
            {
                nullifier.status = NullifierStatus::Expired;
            }
        }
    }
}

pub trait PrivatePqIdentityCredentialBridgeRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

impl PrivatePqIdentityCredentialBridgeRooted for PrivatePqIdentityCredentialBridgeConfig {
    fn root(&self) -> String {
        private_pq_identity_payload_root("PRIVATE-PQ-IDENTITY-BRIDGE-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_credential_bridge_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "commitment_scheme": self.commitment_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "revocation_scheme": self.revocation_scheme,
            "pq_signature_suite": self.pq_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "disclosure_proof_system": self.disclosure_proof_system,
            "auth_receipt_proof_system": self.auth_receipt_proof_system,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "epoch_blocks": self.epoch_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "sponsor_window_blocks": self.sponsor_window_blocks,
            "min_anonymity_set": self.min_anonymity_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_disclosed_attributes": self.max_disclosed_attributes,
            "max_sponsor_fee_units": self.max_sponsor_fee_units,
            "max_risk_score_bps": self.max_risk_score_bps,
            "require_revocation_witness": self.require_revocation_witness,
            "require_contract_domain_binding": self.require_contract_domain_binding,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for PqIssuer {
    fn root(&self) -> String {
        private_pq_identity_payload_root("PRIVATE-PQ-IDENTITY-BRIDGE-ISSUER", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_issuer",
            "issuer_id": self.issuer_id,
            "issuer_label": self.issuer_label,
            "network": self.network.as_str(),
            "status": self.status.as_str(),
            "pq_verification_key_root": self.pq_verification_key_root,
            "pq_attestation_policy_root": self.pq_attestation_policy_root,
            "revocation_accumulator_root": self.revocation_accumulator_root,
            "supported_kinds": self.supported_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>(),
            "supported_scopes": self.supported_scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "fee_sponsor_budget_units": self.fee_sponsor_budget_units,
            "issued_count": self.issued_count,
            "revoked_count": self.revoked_count,
            "registered_height": self.registered_height,
            "metadata_root": self.metadata_root,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for CredentialCommitment {
    fn root(&self) -> String {
        private_pq_identity_payload_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-CREDENTIAL",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_credential_commitment",
            "credential_id": self.credential_id,
            "issuer_id": self.issuer_id,
            "credential_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_commitment": self.subject_commitment,
            "unlinkable_commitment": self.unlinkable_commitment,
            "credential_policy_root": self.credential_policy_root,
            "attribute_commitment_root": self.attribute_commitment_root,
            "revocation_handle_commitment": self.revocation_handle_commitment,
            "pq_issuer_signature_root": self.pq_issuer_signature_root,
            "holder_binding_root": self.holder_binding_root,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "assurance_level": self.assurance_level,
            "anonymity_set_size": self.anonymity_set_size,
            "risk_score_bps": self.risk_score_bps,
            "allowed_scopes": self.allowed_scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>(),
            "tags": self.tags,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for SelectiveDisclosurePolicy {
    fn root(&self) -> String {
        private_pq_identity_payload_root("PRIVATE-PQ-IDENTITY-BRIDGE-POLICY", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_selective_disclosure_policy",
            "policy_id": self.policy_id,
            "policy_label": self.policy_label,
            "status": self.status.as_str(),
            "contract_id": self.contract_id,
            "scope": self.scope.as_str(),
            "accepted_issuer_ids": self.accepted_issuer_ids,
            "required_kinds": self.required_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>(),
            "allowed_modes": self.allowed_modes
                .iter()
                .map(|mode| mode.as_str())
                .collect::<Vec<_>>(),
            "required_attribute_names": self.required_attribute_names,
            "optional_attribute_names": self.optional_attribute_names,
            "denied_attribute_names": self.denied_attribute_names,
            "min_assurance_level": self.min_assurance_level,
            "min_anonymity_set": self.min_anonymity_set,
            "max_risk_score_bps": self.max_risk_score_bps,
            "max_disclosed_attributes": self.max_disclosed_attributes,
            "require_revocation_witness": self.require_revocation_witness,
            "require_fresh_nullifier": self.require_fresh_nullifier,
            "policy_salt_commitment": self.policy_salt_commitment,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for SelectiveDisclosureRequest {
    fn root(&self) -> String {
        private_pq_identity_payload_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-DISCLOSURE",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_selective_disclosure_request",
            "disclosure_id": self.disclosure_id,
            "policy_id": self.policy_id,
            "credential_id": self.credential_id,
            "contract_id": self.contract_id,
            "mode": self.mode.as_str(),
            "status": self.status.as_str(),
            "disclosed_attribute_commitments": self.disclosed_attribute_commitments,
            "predicate_roots": self.predicate_roots,
            "encrypted_payload_root": self.encrypted_payload_root,
            "revocation_witness_root": self.revocation_witness_root,
            "nullifier_commitment": self.nullifier_commitment,
            "proof_root": self.proof_root,
            "requested_height": self.requested_height,
            "expires_height": self.expires_height,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for LowFeeCredentialSponsorship {
    fn root(&self) -> String {
        private_pq_identity_payload_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_low_fee_credential_sponsorship",
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "disclosure_id": self.disclosure_id,
            "credential_id": self.credential_id,
            "policy_id": self.policy_id,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "lane_id": self.lane_id,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "discount_bps": self.discount_bps,
            "sponsor_budget_root": self.sponsor_budget_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for ContractAuthorizationReceipt {
    fn root(&self) -> String {
        private_pq_identity_payload_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-AUTHORIZATION-RECEIPT",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_contract_authorization_receipt",
            "receipt_id": self.receipt_id,
            "contract_id": self.contract_id,
            "contract_call_commitment": self.contract_call_commitment,
            "policy_id": self.policy_id,
            "disclosure_id": self.disclosure_id,
            "credential_id": self.credential_id,
            "sponsorship_id": self.sponsorship_id,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "authorization_nullifier": self.authorization_nullifier,
            "receipt_proof_root": self.receipt_proof_root,
            "gas_sponsor_root": self.gas_sponsor_root,
            "authorized_height": self.authorized_height,
            "expires_height": self.expires_height,
            "consumed_height": self.consumed_height,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for RevocationEntry {
    fn root(&self) -> String {
        private_pq_identity_payload_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-REVOCATION",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_revocation_entry",
            "revocation_id": self.revocation_id,
            "issuer_id": self.issuer_id,
            "credential_id": self.credential_id,
            "revocation_handle_commitment": self.revocation_handle_commitment,
            "status": self.status.as_str(),
            "reason_code": self.reason_code,
            "accumulator_root_before": self.accumulator_root_before,
            "accumulator_root_after": self.accumulator_root_after,
            "pq_revocation_signature_root": self.pq_revocation_signature_root,
            "revoked_height": self.revoked_height,
        })
    }
}

impl PrivatePqIdentityCredentialBridgeRooted for NullifierEntry {
    fn root(&self) -> String {
        private_pq_identity_payload_root(
            "PRIVATE-PQ-IDENTITY-BRIDGE-NULLIFIER",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_pq_identity_nullifier_entry",
            "nullifier_id": self.nullifier_id,
            "nullifier_commitment": self.nullifier_commitment,
            "credential_id": self.credential_id,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "first_seen_height": self.first_seen_height,
            "expires_height": self.expires_height,
            "receipt_ids": self.receipt_ids,
        })
    }
}

pub fn private_pq_identity_config_id(
    protocol_version: &str,
    schema_version: &str,
    chain_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-CONFIG-ID",
        &[
            HashPart::Str(protocol_version),
            HashPart::Str(schema_version),
            HashPart::Str(chain_id),
        ],
        24,
    )
}

pub fn pq_issuer_id(
    issuer_label: &str,
    network: BridgeNetwork,
    pq_verification_key_root: &str,
    revocation_accumulator_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-ISSUER-ID",
        &[
            HashPart::Str(issuer_label),
            HashPart::Str(network.as_str()),
            HashPart::Str(pq_verification_key_root),
            HashPart::Str(revocation_accumulator_root),
        ],
        24,
    )
}

pub fn unlinkable_credential_commitment(
    issuer_id: &str,
    kind: CredentialKind,
    subject_commitment: &str,
    credential_policy_root: &str,
    attribute_commitment_root: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-UNLINKABLE-CREDENTIAL-COMMITMENT",
        &[
            HashPart::Str(issuer_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_commitment),
            HashPart::Str(credential_policy_root),
            HashPart::Str(attribute_commitment_root),
            HashPart::Int(issued_height as i128),
        ],
        32,
    )
}

pub fn credential_commitment_id(
    issuer_id: &str,
    kind: CredentialKind,
    unlinkable_commitment: &str,
    revocation_handle_commitment: &str,
    pq_issuer_signature_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-CREDENTIAL-ID",
        &[
            HashPart::Str(issuer_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(unlinkable_commitment),
            HashPart::Str(revocation_handle_commitment),
            HashPart::Str(pq_issuer_signature_root),
        ],
        24,
    )
}

pub fn selective_disclosure_policy_id(
    policy_label: &str,
    contract_id: &str,
    scope: ContractScope,
    accepted_issuer_ids: &BTreeSet<String>,
    required_kinds: &BTreeSet<CredentialKind>,
    policy_salt_commitment: &str,
) -> String {
    let accepted = accepted_issuer_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let required = required_kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-POLICY-ID",
        &[
            HashPart::Str(policy_label),
            HashPart::Str(contract_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(&accepted),
            HashPart::Str(&required),
            HashPart::Str(policy_salt_commitment),
        ],
        24,
    )
}

pub fn contract_credential_nullifier(
    credential_id: &str,
    policy_id: &str,
    contract_id: &str,
    epoch_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-CONTRACT-CREDENTIAL-NULLIFIER",
        &[
            HashPart::Str(credential_id),
            HashPart::Str(policy_id),
            HashPart::Str(contract_id),
            HashPart::Int(epoch_height as i128),
        ],
        32,
    )
}

pub fn selective_disclosure_id(
    policy_id: &str,
    credential_id: &str,
    mode: DisclosureMode,
    nullifier_commitment: &str,
    proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-DISCLOSURE-ID",
        &[
            HashPart::Str(policy_id),
            HashPart::Str(credential_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(nullifier_commitment),
            HashPart::Str(proof_root),
        ],
        24,
    )
}

pub fn low_fee_credential_sponsorship_id(
    sponsor_commitment: &str,
    disclosure_id: &str,
    nullifier_commitment: &str,
    max_fee_units: u64,
    discount_bps: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-SPONSORSHIP-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(disclosure_id),
            HashPart::Str(nullifier_commitment),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(discount_bps as i128),
        ],
        24,
    )
}

pub fn contract_authorization_nullifier(
    contract_id: &str,
    contract_call_commitment: &str,
    disclosure_nullifier: &str,
    authorized_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-CONTRACT-AUTH-NULLIFIER",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(contract_call_commitment),
            HashPart::Str(disclosure_nullifier),
            HashPart::Int(authorized_height as i128),
        ],
        32,
    )
}

pub fn contract_authorization_receipt_id(
    contract_id: &str,
    contract_call_commitment: &str,
    policy_id: &str,
    disclosure_id: &str,
    authorization_nullifier: &str,
    receipt_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-AUTH-RECEIPT-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(contract_call_commitment),
            HashPart::Str(policy_id),
            HashPart::Str(disclosure_id),
            HashPart::Str(authorization_nullifier),
            HashPart::Str(receipt_proof_root),
        ],
        24,
    )
}

pub fn revocation_accumulator_after(
    issuer_id: &str,
    credential_id: &str,
    revocation_handle_commitment: &str,
    accumulator_root_before: &str,
    pq_revocation_signature_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-REVOCATION-ACCUMULATOR-AFTER",
        &[
            HashPart::Str(issuer_id),
            HashPart::Str(credential_id),
            HashPart::Str(revocation_handle_commitment),
            HashPart::Str(accumulator_root_before),
            HashPart::Str(pq_revocation_signature_root),
        ],
        32,
    )
}

pub fn revocation_entry_id(
    issuer_id: &str,
    credential_id: &str,
    revocation_handle_commitment: &str,
    accumulator_root_after: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-REVOCATION-ID",
        &[
            HashPart::Str(issuer_id),
            HashPart::Str(credential_id),
            HashPart::Str(revocation_handle_commitment),
            HashPart::Str(accumulator_root_after),
        ],
        24,
    )
}

pub fn nullifier_entry_id(
    nullifier_commitment: &str,
    credential_id: &str,
    policy_id: &str,
    contract_id: &str,
    first_seen_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-NULLIFIER-ID",
        &[
            HashPart::Str(nullifier_commitment),
            HashPart::Str(credential_id),
            HashPart::Str(policy_id),
            HashPart::Str(contract_id),
            HashPart::Int(first_seen_height as i128),
        ],
        24,
    )
}

pub fn private_pq_identity_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-PQ-IDENTITY-BRIDGE-STATE-ROOT-FROM-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

fn private_pq_identity_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn private_pq_identity_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn private_pq_identity_map_root<T: PrivatePqIdentityCredentialBridgeRooted>(
    domain: &str,
    map: &BTreeMap<String, T>,
) -> String {
    let leaves = map
        .iter()
        .map(|(id, value)| json!({ "id": id, "root": value.root() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn normalize_label(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
}

fn ensure_non_empty(value: &str, label: &str) -> PrivatePqIdentityCredentialBridgeResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
