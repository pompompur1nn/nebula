use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PqFeeSponsorCredentialsResult<T> = Result<T, String>;

pub const PQ_FEE_SPONSOR_CREDENTIALS_PROTOCOL_VERSION: &str =
    "nebula-pq-fee-sponsor-credentials-v1";
pub const PQ_FEE_SPONSOR_CREDENTIALS_SCHEMA_VERSION: &str = "pq-fee-sponsor-credentials-state-v1";
pub const PQ_FEE_SPONSOR_CREDENTIALS_DEVNET_LABEL: &str = "devnet-pq-fee-sponsor-credentials";
pub const PQ_FEE_SPONSOR_CREDENTIALS_SIGNATURE_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-anonymous-sponsor-credential";
pub const PQ_FEE_SPONSOR_CREDENTIALS_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PQ_FEE_SPONSOR_CREDENTIALS_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const PQ_FEE_SPONSOR_CREDENTIALS_DEFAULT_SPEND_TTL_BLOCKS: u64 = 48;
pub const PQ_FEE_SPONSOR_CREDENTIALS_MAX_ISSUERS: usize = 256;
pub const PQ_FEE_SPONSOR_CREDENTIALS_MAX_CLASSES: usize = 1_024;
pub const PQ_FEE_SPONSOR_CREDENTIALS_MAX_CREDENTIALS: usize = 16_384;
pub const PQ_FEE_SPONSOR_CREDENTIALS_MAX_SPENDS: usize = 32_768;
pub const PQ_FEE_SPONSOR_CREDENTIALS_MAX_EPOCHS: usize = 2_048;
pub const PQ_FEE_SPONSOR_CREDENTIALS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCredentialScope {
    PrivateTransfer,
    ContractCall,
    MoneroBridgeExit,
    LiquiditySwap,
    ProofAggregation,
    WalletRecovery,
}

impl SponsorCredentialScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::LiquiditySwap => "liquidity_swap",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorIssuerStatus {
    Active,
    RateLimited,
    Suspended,
    Retired,
}

impl SponsorIssuerStatus {
    pub fn can_issue(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCredentialStatus {
    Minted,
    Assigned,
    Spent,
    Revoked,
    Expired,
}

impl FeeCredentialStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Minted | Self::Assigned)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Assigned => "assigned",
            Self::Spent => "spent",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCredentialSpendStatus {
    Pending,
    Accepted,
    Rejected,
    Settled,
}

impl FeeCredentialSpendStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Pending | Self::Accepted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
        }
    }
}

pub trait PqFeeSponsorCredentialRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeSponsorCredentialsConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub signature_scheme: String,
    pub commitment_scheme: String,
    pub epoch_blocks: u64,
    pub spend_ttl_blocks: u64,
    pub max_discount_bps: u64,
    pub require_revocation_accumulator: bool,
    pub privacy_policy_root: String,
}

impl PqFeeSponsorCredentialsConfig {
    pub fn devnet() -> PqFeeSponsorCredentialsResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PQ_FEE_SPONSOR_CREDENTIALS_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_FEE_SPONSOR_CREDENTIALS_SCHEMA_VERSION.to_string(),
            signature_scheme: PQ_FEE_SPONSOR_CREDENTIALS_SIGNATURE_SCHEME.to_string(),
            commitment_scheme: PQ_FEE_SPONSOR_CREDENTIALS_COMMITMENT_SCHEME.to_string(),
            epoch_blocks: PQ_FEE_SPONSOR_CREDENTIALS_DEFAULT_EPOCH_BLOCKS,
            spend_ttl_blocks: PQ_FEE_SPONSOR_CREDENTIALS_DEFAULT_SPEND_TTL_BLOCKS,
            max_discount_bps: 8_500,
            require_revocation_accumulator: true,
            privacy_policy_root: pq_fee_sponsor_string_root(
                "PQ-FEE-SPONSOR-PRIVACY-POLICY",
                "issuer-and-spend-roots-only",
            ),
        };
        config.config_id =
            pq_fee_sponsor_config_id(&config.protocol_version, &config.schema_version);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.config_id, "pq fee sponsor config id")?;
        ensure_non_empty(&self.protocol_version, "pq fee sponsor protocol version")?;
        ensure_non_empty(&self.schema_version, "pq fee sponsor schema version")?;
        ensure_non_empty(&self.signature_scheme, "pq fee sponsor signature scheme")?;
        ensure_non_empty(&self.commitment_scheme, "pq fee sponsor commitment scheme")?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "pq fee sponsor privacy policy root",
        )?;
        if self.epoch_blocks == 0 {
            return Err("pq fee sponsor epoch blocks must be positive".to_string());
        }
        if self.spend_ttl_blocks == 0 {
            return Err("pq fee sponsor spend ttl must be positive".to_string());
        }
        if self.max_discount_bps > PQ_FEE_SPONSOR_CREDENTIALS_MAX_BPS {
            return Err("pq fee sponsor discount exceeds bps cap".to_string());
        }
        let expected = pq_fee_sponsor_config_id(&self.protocol_version, &self.schema_version);
        if self.config_id != expected {
            return Err("pq fee sponsor config id does not match protocol".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeSponsorCredentialRooted for PqFeeSponsorCredentialsConfig {
    fn root(&self) -> String {
        pq_fee_sponsor_payload_root("PQ-FEE-SPONSOR-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fee_sponsor_credentials_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "signature_scheme": self.signature_scheme,
            "commitment_scheme": self.commitment_scheme,
            "epoch_blocks": self.epoch_blocks,
            "spend_ttl_blocks": self.spend_ttl_blocks,
            "max_discount_bps": self.max_discount_bps,
            "require_revocation_accumulator": self.require_revocation_accumulator,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorIssuer {
    pub issuer_id: String,
    pub sponsor_commitment: String,
    pub pq_verification_key_root: String,
    pub reserve_commitment_root: String,
    pub status: SponsorIssuerStatus,
    pub supported_scopes: BTreeSet<SponsorCredentialScope>,
    pub max_epoch_budget_units: u64,
}

impl SponsorIssuer {
    pub fn new(
        sponsor_label: &str,
        pq_key_label: &str,
        reserve_label: &str,
        supported_scopes: BTreeSet<SponsorCredentialScope>,
        max_epoch_budget_units: u64,
    ) -> PqFeeSponsorCredentialsResult<Self> {
        ensure_non_empty(sponsor_label, "pq fee sponsor issuer label")?;
        ensure_non_empty(pq_key_label, "pq fee sponsor issuer pq key")?;
        ensure_non_empty(reserve_label, "pq fee sponsor issuer reserve")?;
        if supported_scopes.is_empty() {
            return Err("pq fee sponsor issuer must support at least one scope".to_string());
        }
        if max_epoch_budget_units == 0 {
            return Err("pq fee sponsor issuer budget must be positive".to_string());
        }
        let sponsor_commitment = pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-ISSUER", sponsor_label);
        let pq_verification_key_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-ISSUER-PQ-KEY", pq_key_label);
        let reserve_commitment_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-ISSUER-RESERVE", reserve_label);
        let issuer_id = sponsor_issuer_id(
            &sponsor_commitment,
            &pq_verification_key_root,
            &reserve_commitment_root,
        );
        let issuer = Self {
            issuer_id,
            sponsor_commitment,
            pq_verification_key_root,
            reserve_commitment_root,
            status: SponsorIssuerStatus::Active,
            supported_scopes,
            max_epoch_budget_units,
        };
        issuer.validate()?;
        Ok(issuer)
    }

    pub fn supports_scope(&self, scope: SponsorCredentialScope) -> bool {
        self.status.can_issue() && self.supported_scopes.contains(&scope)
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.issuer_id, "pq fee sponsor issuer id")?;
        ensure_non_empty(&self.sponsor_commitment, "pq fee sponsor issuer commitment")?;
        ensure_non_empty(
            &self.pq_verification_key_root,
            "pq fee sponsor issuer verification key root",
        )?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "pq fee sponsor issuer reserve commitment",
        )?;
        if self.supported_scopes.is_empty() {
            return Err("pq fee sponsor issuer has no supported scopes".to_string());
        }
        if self.max_epoch_budget_units == 0 {
            return Err("pq fee sponsor issuer budget must be positive".to_string());
        }
        let expected = sponsor_issuer_id(
            &self.sponsor_commitment,
            &self.pq_verification_key_root,
            &self.reserve_commitment_root,
        );
        if self.issuer_id != expected {
            return Err("pq fee sponsor issuer id does not match commitments".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeSponsorCredentialRooted for SponsorIssuer {
    fn root(&self) -> String {
        pq_fee_sponsor_payload_root("PQ-FEE-SPONSOR-ISSUER", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_issuer",
            "issuer_id": self.issuer_id,
            "sponsor_commitment": self.sponsor_commitment,
            "pq_verification_key_root": self.pq_verification_key_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "status": self.status.as_str(),
            "supported_scopes": self.supported_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "max_epoch_budget_units": self.max_epoch_budget_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeCredentialClass {
    pub class_id: String,
    pub issuer_id: String,
    pub scope: SponsorCredentialScope,
    pub lane_id: String,
    pub max_fee_units: u64,
    pub discount_bps: u64,
    pub epoch: u64,
    pub credential_policy_root: String,
}

impl FeeCredentialClass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_id: &str,
        scope: SponsorCredentialScope,
        lane_id: &str,
        max_fee_units: u64,
        discount_bps: u64,
        epoch: u64,
        credential_policy_root: &str,
    ) -> PqFeeSponsorCredentialsResult<Self> {
        ensure_non_empty(issuer_id, "pq fee sponsor class issuer id")?;
        ensure_non_empty(lane_id, "pq fee sponsor class lane id")?;
        ensure_non_empty(credential_policy_root, "pq fee sponsor class policy root")?;
        if max_fee_units == 0 {
            return Err("pq fee sponsor class max fee must be positive".to_string());
        }
        if discount_bps > PQ_FEE_SPONSOR_CREDENTIALS_MAX_BPS {
            return Err("pq fee sponsor class discount exceeds bps cap".to_string());
        }
        let class_id = fee_credential_class_id(
            issuer_id,
            scope,
            lane_id,
            max_fee_units,
            discount_bps,
            epoch,
            credential_policy_root,
        );
        let class = Self {
            class_id,
            issuer_id: issuer_id.to_string(),
            scope,
            lane_id: lane_id.to_string(),
            max_fee_units,
            discount_bps,
            epoch,
            credential_policy_root: credential_policy_root.to_string(),
        };
        class.validate()?;
        Ok(class)
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.class_id, "pq fee sponsor class id")?;
        ensure_non_empty(&self.issuer_id, "pq fee sponsor class issuer id")?;
        ensure_non_empty(&self.lane_id, "pq fee sponsor class lane id")?;
        ensure_non_empty(
            &self.credential_policy_root,
            "pq fee sponsor class policy root",
        )?;
        if self.max_fee_units == 0 {
            return Err("pq fee sponsor class max fee must be positive".to_string());
        }
        if self.discount_bps > PQ_FEE_SPONSOR_CREDENTIALS_MAX_BPS {
            return Err("pq fee sponsor class discount exceeds bps cap".to_string());
        }
        let expected = fee_credential_class_id(
            &self.issuer_id,
            self.scope,
            &self.lane_id,
            self.max_fee_units,
            self.discount_bps,
            self.epoch,
            &self.credential_policy_root,
        );
        if self.class_id != expected {
            return Err("pq fee sponsor class id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeSponsorCredentialRooted for FeeCredentialClass {
    fn root(&self) -> String {
        pq_fee_sponsor_payload_root("PQ-FEE-CREDENTIAL-CLASS", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credential_class",
            "class_id": self.class_id,
            "issuer_id": self.issuer_id,
            "scope": self.scope.as_str(),
            "lane_id": self.lane_id,
            "max_fee_units": self.max_fee_units,
            "discount_bps": self.discount_bps,
            "epoch": self.epoch,
            "credential_policy_root": self.credential_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnonymousFeeCredential {
    pub credential_id: String,
    pub class_id: String,
    pub owner_nullifier_root: String,
    pub credential_commitment: String,
    pub pq_issuer_signature_root: String,
    pub status: FeeCredentialStatus,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl AnonymousFeeCredential {
    pub fn new(
        class_id: &str,
        owner_nullifier_root: &str,
        credential_secret_label: &str,
        pq_issuer_signature_root: &str,
        issued_height: u64,
        ttl_blocks: u64,
    ) -> PqFeeSponsorCredentialsResult<Self> {
        ensure_non_empty(class_id, "pq fee credential class id")?;
        ensure_non_empty(
            owner_nullifier_root,
            "pq fee credential owner nullifier root",
        )?;
        ensure_non_empty(credential_secret_label, "pq fee credential secret label")?;
        ensure_non_empty(
            pq_issuer_signature_root,
            "pq fee credential issuer signature root",
        )?;
        if ttl_blocks == 0 {
            return Err("pq fee credential ttl must be positive".to_string());
        }
        let credential_commitment =
            pq_fee_sponsor_string_root("PQ-FEE-CREDENTIAL-COMMITMENT", credential_secret_label);
        let expires_height = issued_height.saturating_add(ttl_blocks);
        let credential_id = anonymous_fee_credential_id(
            class_id,
            owner_nullifier_root,
            &credential_commitment,
            pq_issuer_signature_root,
            issued_height,
        );
        let credential = Self {
            credential_id,
            class_id: class_id.to_string(),
            owner_nullifier_root: owner_nullifier_root.to_string(),
            credential_commitment,
            pq_issuer_signature_root: pq_issuer_signature_root.to_string(),
            status: FeeCredentialStatus::Minted,
            issued_height,
            expires_height,
        };
        credential.validate()?;
        Ok(credential)
    }

    pub fn mark_spent(&mut self) -> PqFeeSponsorCredentialsResult<String> {
        if !self.status.spendable() {
            return Err("pq fee credential is not spendable".to_string());
        }
        self.status = FeeCredentialStatus::Spent;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.credential_id, "pq fee credential id")?;
        ensure_non_empty(&self.class_id, "pq fee credential class id")?;
        ensure_non_empty(
            &self.owner_nullifier_root,
            "pq fee credential owner nullifier",
        )?;
        ensure_non_empty(&self.credential_commitment, "pq fee credential commitment")?;
        ensure_non_empty(
            &self.pq_issuer_signature_root,
            "pq fee credential issuer signature root",
        )?;
        if self.expires_height <= self.issued_height {
            return Err("pq fee credential expiry must exceed issue height".to_string());
        }
        let expected = anonymous_fee_credential_id(
            &self.class_id,
            &self.owner_nullifier_root,
            &self.credential_commitment,
            &self.pq_issuer_signature_root,
            self.issued_height,
        );
        if self.credential_id != expected {
            return Err("pq fee credential id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeSponsorCredentialRooted for AnonymousFeeCredential {
    fn root(&self) -> String {
        pq_fee_sponsor_payload_root("PQ-FEE-CREDENTIAL", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "anonymous_fee_credential",
            "credential_id": self.credential_id,
            "class_id": self.class_id,
            "owner_nullifier_root": self.owner_nullifier_root,
            "credential_commitment": self.credential_commitment,
            "pq_issuer_signature_root": self.pq_issuer_signature_root,
            "status": self.status.as_str(),
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeCredentialSpend {
    pub spend_id: String,
    pub credential_id: String,
    pub class_id: String,
    pub transaction_commitment: String,
    pub nullifier_commitment: String,
    pub spend_proof_root: String,
    pub status: FeeCredentialSpendStatus,
    pub fee_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl FeeCredentialSpend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_id: &str,
        class_id: &str,
        transaction_commitment: &str,
        nullifier_commitment: &str,
        spend_proof_root: &str,
        fee_units: u64,
        opened_height: u64,
        ttl_blocks: u64,
    ) -> PqFeeSponsorCredentialsResult<Self> {
        ensure_non_empty(credential_id, "pq fee credential spend credential id")?;
        ensure_non_empty(class_id, "pq fee credential spend class id")?;
        ensure_non_empty(
            transaction_commitment,
            "pq fee credential spend transaction commitment",
        )?;
        ensure_non_empty(nullifier_commitment, "pq fee credential spend nullifier")?;
        ensure_non_empty(spend_proof_root, "pq fee credential spend proof root")?;
        if fee_units == 0 {
            return Err("pq fee credential spend fee units must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("pq fee credential spend ttl must be positive".to_string());
        }
        let expires_height = opened_height.saturating_add(ttl_blocks);
        let spend_id = fee_credential_spend_id(
            credential_id,
            class_id,
            transaction_commitment,
            nullifier_commitment,
            spend_proof_root,
        );
        let spend = Self {
            spend_id,
            credential_id: credential_id.to_string(),
            class_id: class_id.to_string(),
            transaction_commitment: transaction_commitment.to_string(),
            nullifier_commitment: nullifier_commitment.to_string(),
            spend_proof_root: spend_proof_root.to_string(),
            status: FeeCredentialSpendStatus::Pending,
            fee_units,
            opened_height,
            expires_height,
        };
        spend.validate()?;
        Ok(spend)
    }

    pub fn accept(&mut self) -> PqFeeSponsorCredentialsResult<String> {
        if self.status != FeeCredentialSpendStatus::Pending {
            return Err("pq fee credential spend can only accept from pending".to_string());
        }
        self.status = FeeCredentialSpendStatus::Accepted;
        Ok(self.root())
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.spend_id, "pq fee credential spend id")?;
        ensure_non_empty(&self.credential_id, "pq fee credential spend credential id")?;
        ensure_non_empty(&self.class_id, "pq fee credential spend class id")?;
        ensure_non_empty(
            &self.transaction_commitment,
            "pq fee credential spend transaction commitment",
        )?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "pq fee credential spend nullifier",
        )?;
        ensure_non_empty(&self.spend_proof_root, "pq fee credential spend proof root")?;
        if self.fee_units == 0 {
            return Err("pq fee credential spend fee units must be positive".to_string());
        }
        if self.expires_height <= self.opened_height {
            return Err("pq fee credential spend expiry must exceed open height".to_string());
        }
        let expected = fee_credential_spend_id(
            &self.credential_id,
            &self.class_id,
            &self.transaction_commitment,
            &self.nullifier_commitment,
            &self.spend_proof_root,
        );
        if self.spend_id != expected {
            return Err("pq fee credential spend id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeSponsorCredentialRooted for FeeCredentialSpend {
    fn root(&self) -> String {
        pq_fee_sponsor_payload_root("PQ-FEE-CREDENTIAL-SPEND", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credential_spend",
            "spend_id": self.spend_id,
            "credential_id": self.credential_id,
            "class_id": self.class_id,
            "transaction_commitment": self.transaction_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "spend_proof_root": self.spend_proof_root,
            "status": self.status.as_str(),
            "fee_units": self.fee_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorCredentialEpoch {
    pub epoch_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub issuer_budget_root: String,
    pub revocation_accumulator_root: String,
    pub spent_nullifier_root: String,
}

impl SponsorCredentialEpoch {
    pub fn new(
        epoch: u64,
        start_height: u64,
        epoch_blocks: u64,
        issuer_budget_root: &str,
        revocation_accumulator_root: &str,
        spent_nullifier_root: &str,
    ) -> PqFeeSponsorCredentialsResult<Self> {
        ensure_non_empty(issuer_budget_root, "pq fee sponsor epoch budget root")?;
        ensure_non_empty(
            revocation_accumulator_root,
            "pq fee sponsor epoch revocation root",
        )?;
        ensure_non_empty(spent_nullifier_root, "pq fee sponsor epoch nullifier root")?;
        if epoch_blocks == 0 {
            return Err("pq fee sponsor epoch blocks must be positive".to_string());
        }
        let end_height = start_height.saturating_add(epoch_blocks);
        let epoch_id = sponsor_credential_epoch_id(
            epoch,
            start_height,
            end_height,
            issuer_budget_root,
            revocation_accumulator_root,
        );
        let epoch_record = Self {
            epoch_id,
            epoch,
            start_height,
            end_height,
            issuer_budget_root: issuer_budget_root.to_string(),
            revocation_accumulator_root: revocation_accumulator_root.to_string(),
            spent_nullifier_root: spent_nullifier_root.to_string(),
        };
        epoch_record.validate()?;
        Ok(epoch_record)
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.epoch_id, "pq fee sponsor epoch id")?;
        ensure_non_empty(&self.issuer_budget_root, "pq fee sponsor epoch budget root")?;
        ensure_non_empty(
            &self.revocation_accumulator_root,
            "pq fee sponsor epoch revocation root",
        )?;
        ensure_non_empty(
            &self.spent_nullifier_root,
            "pq fee sponsor epoch nullifier root",
        )?;
        if self.end_height <= self.start_height {
            return Err("pq fee sponsor epoch end must exceed start".to_string());
        }
        let expected = sponsor_credential_epoch_id(
            self.epoch,
            self.start_height,
            self.end_height,
            &self.issuer_budget_root,
            &self.revocation_accumulator_root,
        );
        if self.epoch_id != expected {
            return Err("pq fee sponsor epoch id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PqFeeSponsorCredentialRooted for SponsorCredentialEpoch {
    fn root(&self) -> String {
        pq_fee_sponsor_payload_root("PQ-FEE-SPONSOR-EPOCH", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_credential_epoch",
            "epoch_id": self.epoch_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "issuer_budget_root": self.issuer_budget_root,
            "revocation_accumulator_root": self.revocation_accumulator_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeSponsorCredentialsRoots {
    pub config_root: String,
    pub issuer_root: String,
    pub class_root: String,
    pub credential_root: String,
    pub spend_root: String,
    pub epoch_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl PqFeeSponsorCredentialsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "issuer_root": self.issuer_root,
            "class_root": self.class_root,
            "credential_root": self.credential_root,
            "spend_root": self.spend_root,
            "epoch_root": self.epoch_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeSponsorCredentialsCounters {
    pub height: u64,
    pub issuer_count: u64,
    pub active_issuer_count: u64,
    pub class_count: u64,
    pub credential_count: u64,
    pub spendable_credential_count: u64,
    pub spend_count: u64,
    pub open_spend_count: u64,
    pub epoch_count: u64,
    pub spent_nullifier_count: u64,
}

impl PqFeeSponsorCredentialsCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "issuer_count": self.issuer_count,
            "active_issuer_count": self.active_issuer_count,
            "class_count": self.class_count,
            "credential_count": self.credential_count,
            "spendable_credential_count": self.spendable_credential_count,
            "spend_count": self.spend_count,
            "open_spend_count": self.open_spend_count,
            "epoch_count": self.epoch_count,
            "spent_nullifier_count": self.spent_nullifier_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFeeSponsorCredentialsState {
    pub height: u64,
    pub label: String,
    pub config: PqFeeSponsorCredentialsConfig,
    pub issuers: BTreeMap<String, SponsorIssuer>,
    pub classes: BTreeMap<String, FeeCredentialClass>,
    pub credentials: BTreeMap<String, AnonymousFeeCredential>,
    pub spends: BTreeMap<String, FeeCredentialSpend>,
    pub epochs: BTreeMap<String, SponsorCredentialEpoch>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl PqFeeSponsorCredentialsState {
    pub fn new(
        label: &str,
        config: PqFeeSponsorCredentialsConfig,
    ) -> PqFeeSponsorCredentialsResult<Self> {
        ensure_non_empty(label, "pq fee sponsor credentials label")?;
        config.validate()?;
        let state = Self {
            height: 0,
            label: label.to_string(),
            config,
            issuers: BTreeMap::new(),
            classes: BTreeMap::new(),
            credentials: BTreeMap::new(),
            spends: BTreeMap::new(),
            epochs: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PqFeeSponsorCredentialsResult<Self> {
        let config = PqFeeSponsorCredentialsConfig::devnet()?;
        let mut state = Self::new(PQ_FEE_SPONSOR_CREDENTIALS_DEVNET_LABEL, config)?;
        state.set_height(88)?;
        let mut scopes = BTreeSet::new();
        scopes.insert(SponsorCredentialScope::PrivateTransfer);
        scopes.insert(SponsorCredentialScope::ContractCall);
        scopes.insert(SponsorCredentialScope::MoneroBridgeExit);
        scopes.insert(SponsorCredentialScope::LiquiditySwap);
        let issuer = SponsorIssuer::new(
            "devnet-fee-sponsor",
            "devnet-fee-sponsor-pq-key",
            "devnet-fee-sponsor-reserve",
            scopes,
            2_500_000,
        )?;
        let issuer_id = issuer.issuer_id.clone();
        state.add_issuer(issuer)?;
        let policy_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-POLICY", "low-fee-private-lanes");
        let class = FeeCredentialClass::new(
            &issuer_id,
            SponsorCredentialScope::ContractCall,
            "low_fee_contract_call",
            2_000,
            7_500,
            0,
            &policy_root,
        )?;
        let class_id = class.class_id.clone();
        state.add_class(class)?;
        let signature_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-SIG", "issuer-pq-signature");
        let owner_nullifier_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-OWNER", "wallet-nullifier-root");
        let credential = AnonymousFeeCredential::new(
            &class_id,
            &owner_nullifier_root,
            "devnet-credential-secret",
            &signature_root,
            84,
            state.config.epoch_blocks,
        )?;
        let credential_id = credential.credential_id.clone();
        state.add_credential(credential)?;
        let transaction_commitment =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-TX", "private-contract-call");
        let nullifier_commitment =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-NULLIFIER", "spend-nullifier");
        let spend_proof_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-PROOF", "anonymous-spend-proof");
        let mut spend = FeeCredentialSpend::new(
            &credential_id,
            &class_id,
            &transaction_commitment,
            &nullifier_commitment,
            &spend_proof_root,
            1_600,
            86,
            state.config.spend_ttl_blocks,
        )?;
        spend.accept()?;
        state.add_spend(spend)?;
        let issuer_budget_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-BUDGET", "issuer-budget");
        let revocation_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-REVOCATION", "empty-revocations");
        let spent_nullifier_root =
            pq_fee_sponsor_string_root("PQ-FEE-SPONSOR-DEVNET-SPENT", "spent-nullifiers");
        let epoch = SponsorCredentialEpoch::new(
            0,
            0,
            state.config.epoch_blocks,
            &issuer_budget_root,
            &revocation_root,
            &spent_nullifier_root,
        )?;
        state.add_epoch(epoch)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqFeeSponsorCredentialsResult<String> {
        self.height = height;
        self.validate()
    }

    pub fn add_issuer(&mut self, issuer: SponsorIssuer) -> PqFeeSponsorCredentialsResult<String> {
        if self.issuers.len() >= PQ_FEE_SPONSOR_CREDENTIALS_MAX_ISSUERS {
            return Err("pq fee sponsor issuer limit reached".to_string());
        }
        issuer.validate()?;
        let root = issuer.root();
        self.issuers.insert(issuer.issuer_id.clone(), issuer);
        Ok(root)
    }

    pub fn add_class(
        &mut self,
        class: FeeCredentialClass,
    ) -> PqFeeSponsorCredentialsResult<String> {
        if self.classes.len() >= PQ_FEE_SPONSOR_CREDENTIALS_MAX_CLASSES {
            return Err("pq fee sponsor class limit reached".to_string());
        }
        let issuer = self
            .issuers
            .get(&class.issuer_id)
            .ok_or_else(|| "pq fee sponsor class references unknown issuer".to_string())?;
        if !issuer.supports_scope(class.scope) {
            return Err("pq fee sponsor issuer does not support class scope".to_string());
        }
        if class.discount_bps > self.config.max_discount_bps {
            return Err("pq fee sponsor class exceeds configured discount cap".to_string());
        }
        class.validate()?;
        let root = class.root();
        self.classes.insert(class.class_id.clone(), class);
        Ok(root)
    }

    pub fn add_credential(
        &mut self,
        credential: AnonymousFeeCredential,
    ) -> PqFeeSponsorCredentialsResult<String> {
        if self.credentials.len() >= PQ_FEE_SPONSOR_CREDENTIALS_MAX_CREDENTIALS {
            return Err("pq fee sponsor credential limit reached".to_string());
        }
        if !self.classes.contains_key(&credential.class_id) {
            return Err("pq fee sponsor credential references unknown class".to_string());
        }
        credential.validate()?;
        let root = credential.root();
        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(root)
    }

    pub fn add_spend(
        &mut self,
        spend: FeeCredentialSpend,
    ) -> PqFeeSponsorCredentialsResult<String> {
        if self.spends.len() >= PQ_FEE_SPONSOR_CREDENTIALS_MAX_SPENDS {
            return Err("pq fee sponsor spend limit reached".to_string());
        }
        let credential = self
            .credentials
            .get_mut(&spend.credential_id)
            .ok_or_else(|| "pq fee sponsor spend references unknown credential".to_string())?;
        if credential.class_id != spend.class_id {
            return Err("pq fee sponsor spend class does not match credential".to_string());
        }
        if self.spent_nullifiers.contains(&spend.nullifier_commitment) {
            return Err("pq fee sponsor nullifier already spent".to_string());
        }
        let class = self
            .classes
            .get(&spend.class_id)
            .ok_or_else(|| "pq fee sponsor spend references unknown class".to_string())?;
        if spend.fee_units > class.max_fee_units {
            return Err("pq fee sponsor spend exceeds class max fee".to_string());
        }
        spend.validate()?;
        credential.mark_spent()?;
        self.spent_nullifiers
            .insert(spend.nullifier_commitment.clone());
        let root = spend.root();
        self.spends.insert(spend.spend_id.clone(), spend);
        Ok(root)
    }

    pub fn add_epoch(
        &mut self,
        epoch: SponsorCredentialEpoch,
    ) -> PqFeeSponsorCredentialsResult<String> {
        if self.epochs.len() >= PQ_FEE_SPONSOR_CREDENTIALS_MAX_EPOCHS {
            return Err("pq fee sponsor epoch limit reached".to_string());
        }
        epoch.validate()?;
        let root = epoch.root();
        self.epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(root)
    }

    pub fn active_issuer_ids(&self) -> Vec<String> {
        self.issuers
            .values()
            .filter(|issuer| issuer.status.can_issue())
            .map(|issuer| issuer.issuer_id.clone())
            .collect()
    }

    pub fn spendable_credential_ids(&self) -> Vec<String> {
        self.credentials
            .values()
            .filter(|credential| credential.status.spendable())
            .map(|credential| credential.credential_id.clone())
            .collect()
    }

    pub fn open_spend_ids(&self) -> Vec<String> {
        self.spends
            .values()
            .filter(|spend| spend.status.open())
            .map(|spend| spend.spend_id.clone())
            .collect()
    }

    pub fn lane_budget_map(&self) -> BTreeMap<String, u64> {
        let mut lanes = BTreeMap::new();
        for class in self.classes.values() {
            *lanes.entry(class.lane_id.clone()).or_insert(0) += class.max_fee_units;
        }
        lanes
    }

    pub fn roots(&self) -> PqFeeSponsorCredentialsRoots {
        let config_root = self.config.root();
        let issuer_root = pq_fee_sponsor_map_root("PQ-FEE-SPONSOR-ISSUERS", &self.issuers);
        let class_root = pq_fee_sponsor_map_root("PQ-FEE-SPONSOR-CLASSES", &self.classes);
        let credential_root =
            pq_fee_sponsor_map_root("PQ-FEE-SPONSOR-CREDENTIALS", &self.credentials);
        let spend_root = pq_fee_sponsor_map_root("PQ-FEE-SPONSOR-SPENDS", &self.spends);
        let epoch_root = pq_fee_sponsor_map_root("PQ-FEE-SPONSOR-EPOCHS", &self.epochs);
        let nullifier_root = merkle_root(
            "PQ-FEE-SPONSOR-SPENT-NULLIFIERS",
            &self
                .spent_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier_commitment": nullifier }))
                .collect::<Vec<_>>(),
        );
        let state_root = domain_hash(
            "PQ-FEE-SPONSOR-CREDENTIALS-STATE-ROOT",
            &[
                HashPart::Str(&self.label),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&issuer_root),
                HashPart::Str(&class_root),
                HashPart::Str(&credential_root),
                HashPart::Str(&spend_root),
                HashPart::Str(&epoch_root),
                HashPart::Str(&nullifier_root),
            ],
            32,
        );
        PqFeeSponsorCredentialsRoots {
            config_root,
            issuer_root,
            class_root,
            credential_root,
            spend_root,
            epoch_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PqFeeSponsorCredentialsCounters {
        PqFeeSponsorCredentialsCounters {
            height: self.height,
            issuer_count: self.issuers.len() as u64,
            active_issuer_count: self
                .issuers
                .values()
                .filter(|issuer| issuer.status.can_issue())
                .count() as u64,
            class_count: self.classes.len() as u64,
            credential_count: self.credentials.len() as u64,
            spendable_credential_count: self
                .credentials
                .values()
                .filter(|credential| credential.status.spendable())
                .count() as u64,
            spend_count: self.spends.len() as u64,
            open_spend_count: self
                .spends
                .values()
                .filter(|spend| spend.status.open())
                .count() as u64,
            epoch_count: self.epochs.len() as u64,
            spent_nullifier_count: self.spent_nullifiers.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fee_sponsor_credentials_state",
            "label": self.label,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_issuer_ids": self.active_issuer_ids(),
            "spendable_credential_ids": self.spendable_credential_ids(),
            "open_spend_ids": self.open_spend_ids(),
            "lane_budget_map": self.lane_budget_map(),
        })
    }

    pub fn validate(&self) -> PqFeeSponsorCredentialsResult<String> {
        ensure_non_empty(&self.label, "pq fee sponsor credentials label")?;
        self.config.validate()?;
        if self.issuers.len() > PQ_FEE_SPONSOR_CREDENTIALS_MAX_ISSUERS {
            return Err("pq fee sponsor state has too many issuers".to_string());
        }
        if self.classes.len() > PQ_FEE_SPONSOR_CREDENTIALS_MAX_CLASSES {
            return Err("pq fee sponsor state has too many classes".to_string());
        }
        if self.credentials.len() > PQ_FEE_SPONSOR_CREDENTIALS_MAX_CREDENTIALS {
            return Err("pq fee sponsor state has too many credentials".to_string());
        }
        if self.spends.len() > PQ_FEE_SPONSOR_CREDENTIALS_MAX_SPENDS {
            return Err("pq fee sponsor state has too many spends".to_string());
        }
        if self.epochs.len() > PQ_FEE_SPONSOR_CREDENTIALS_MAX_EPOCHS {
            return Err("pq fee sponsor state has too many epochs".to_string());
        }
        for issuer in self.issuers.values() {
            issuer.validate()?;
        }
        for class in self.classes.values() {
            class.validate()?;
            if !self.issuers.contains_key(&class.issuer_id) {
                return Err("pq fee sponsor class references missing issuer".to_string());
            }
        }
        for credential in self.credentials.values() {
            credential.validate()?;
            if !self.classes.contains_key(&credential.class_id) {
                return Err("pq fee sponsor credential references missing class".to_string());
            }
        }
        for spend in self.spends.values() {
            spend.validate()?;
            if !self.credentials.contains_key(&spend.credential_id) {
                return Err("pq fee sponsor spend references missing credential".to_string());
            }
            if !self.classes.contains_key(&spend.class_id) {
                return Err("pq fee sponsor spend references missing class".to_string());
            }
        }
        for epoch in self.epochs.values() {
            epoch.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn pq_fee_sponsor_credentials_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-FEE-SPONSOR-CREDENTIALS-STATE-ROOT-FROM-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn pq_fee_sponsor_config_id(protocol_version: &str, schema_version: &str) -> String {
    domain_hash(
        "PQ-FEE-SPONSOR-CONFIG-ID",
        &[
            HashPart::Str(protocol_version),
            HashPart::Str(schema_version),
        ],
        24,
    )
}

pub fn sponsor_issuer_id(
    sponsor_commitment: &str,
    pq_verification_key_root: &str,
    reserve_commitment_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-SPONSOR-ISSUER-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(pq_verification_key_root),
            HashPart::Str(reserve_commitment_root),
        ],
        24,
    )
}

pub fn fee_credential_class_id(
    issuer_id: &str,
    scope: SponsorCredentialScope,
    lane_id: &str,
    max_fee_units: u64,
    discount_bps: u64,
    epoch: u64,
    credential_policy_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-CREDENTIAL-CLASS-ID",
        &[
            HashPart::Str(issuer_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(lane_id),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(discount_bps as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(credential_policy_root),
        ],
        24,
    )
}

pub fn anonymous_fee_credential_id(
    class_id: &str,
    owner_nullifier_root: &str,
    credential_commitment: &str,
    pq_issuer_signature_root: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "PQ-FEE-CREDENTIAL-ID",
        &[
            HashPart::Str(class_id),
            HashPart::Str(owner_nullifier_root),
            HashPart::Str(credential_commitment),
            HashPart::Str(pq_issuer_signature_root),
            HashPart::Int(issued_height as i128),
        ],
        24,
    )
}

pub fn fee_credential_spend_id(
    credential_id: &str,
    class_id: &str,
    transaction_commitment: &str,
    nullifier_commitment: &str,
    spend_proof_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-CREDENTIAL-SPEND-ID",
        &[
            HashPart::Str(credential_id),
            HashPart::Str(class_id),
            HashPart::Str(transaction_commitment),
            HashPart::Str(nullifier_commitment),
            HashPart::Str(spend_proof_root),
        ],
        24,
    )
}

pub fn sponsor_credential_epoch_id(
    epoch: u64,
    start_height: u64,
    end_height: u64,
    issuer_budget_root: &str,
    revocation_accumulator_root: &str,
) -> String {
    domain_hash(
        "PQ-FEE-SPONSOR-EPOCH-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(issuer_budget_root),
            HashPart::Str(revocation_accumulator_root),
        ],
        24,
    )
}

fn pq_fee_sponsor_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn pq_fee_sponsor_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn pq_fee_sponsor_map_root<T: PqFeeSponsorCredentialRooted>(
    domain: &str,
    map: &BTreeMap<String, T>,
) -> String {
    let leaves = map
        .iter()
        .map(|(id, value)| json!({ "id": id, "root": value.root() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> PqFeeSponsorCredentialsResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
