use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqViewKeyRecoveryMarketResult<T> = Result<T, String>;

pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-viewkey-recovery-market-v1";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_SECURITY_MODEL: &str =
    "deterministic-devnet-model-not-real-crypto";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_RECOVERY_SHARE_SCHEME: &str =
    "kyber-hpke-shamir-view-key-share-v1";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_RECEIPT_SCHEME: &str =
    "privacy-preserving-audit-receipt-v1";
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_VIEW_TAG_BYTES: u64 = 1;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_HEIGHT: u64 = 304;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_CONFIRMATIONS: u64 = 10;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 720;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SYNC_TTL_BLOCKS: u64 = 96;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 1_440;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 576;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_RECOVERY_THRESHOLD: u64 = 2;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_PROVIDER_STAKE: u64 = 25_000_000_000;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_SPONSOR_BALANCE: u64 = 2_000_000_000;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_SCAN_BLOCKS: u64 = 20_160;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SCAN_PRICE_PER_BLOCK: u64 = 9_000;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_PRICE: u64 = 120_000_000;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 9_500;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_SHARE_BYTES: u64 = 2_048;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_JOB_OUTPUTS: u64 = 8_192;
pub const MONERO_PQ_VIEWKEY_RECOVERY_MARKET_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProviderRole {
    ShareCustodian,
    WatchOnlyScanner,
    Auditor,
    Sponsor,
    SlashingArbiter,
    SafetyGuardian,
}

impl RecoveryProviderRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShareCustodian => "share_custodian",
            Self::WatchOnlyScanner => "watch_only_scanner",
            Self::Auditor => "auditor",
            Self::Sponsor => "sponsor",
            Self::SlashingArbiter => "slashing_arbiter",
            Self::SafetyGuardian => "safety_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Pending,
    Active,
    Throttled,
    Jailed,
    Retiring,
    Retired,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Jailed => "jailed",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }

    pub fn can_accept_work(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEnvelopeScheme {
    MlKem768AesGcm,
    MlKem1024AesGcm,
    HybridX25519MlKem768,
    HybridX25519MlKem1024,
    SlhDsaReceiptBound,
}

impl PqEnvelopeScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem768AesGcm => "ml_kem_768_aes_gcm",
            Self::MlKem1024AesGcm => "ml_kem_1024_aes_gcm",
            Self::HybridX25519MlKem768 => "hybrid_x25519_ml_kem_768",
            Self::HybridX25519MlKem1024 => "hybrid_x25519_ml_kem_1024",
            Self::SlhDsaReceiptBound => "slh_dsa_receipt_bound",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlKem768AesGcm | Self::HybridX25519MlKem768 => 192,
            Self::MlKem1024AesGcm | Self::HybridX25519MlKem1024 => 256,
            Self::SlhDsaReceiptBound => 192,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRequestStatus {
    Draft,
    Open,
    SharesCommitted,
    Reconstructing,
    Completed,
    Cancelled,
    Expired,
    Disputed,
}

impl RecoveryRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::SharesCommitted => "shares_committed",
            Self::Reconstructing => "reconstructing",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::SharesCommitted | Self::Reconstructing | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Advertised,
    Sealed,
    Accepted,
    Used,
    Rejected,
    Revoked,
    Slashed,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Sealed => "sealed",
            Self::Accepted => "accepted",
            Self::Used => "used",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts_for_threshold(self) -> bool {
        matches!(self, Self::Sealed | Self::Accepted | Self::Used)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncJobStatus {
    Queued,
    Assigned,
    Scanning,
    Proving,
    Delivered,
    Challenged,
    Failed,
    Expired,
}

impl SyncJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::Scanning => "scanning",
            Self::Proving => "proving",
            Self::Delivered => "delivered",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Assigned | Self::Scanning | Self::Proving | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCreditStatus {
    Offered,
    Reserved,
    Applied,
    Exhausted,
    Expired,
    Slashed,
}

impl SponsorCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReceiptKind {
    ShareCustody,
    RecoveryReconstruction,
    WatchOnlyScan,
    SponsorCredit,
    ViewTagSafety,
    SubaddressSafety,
    SlashingEvidence,
}

impl AuditReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShareCustody => "share_custody",
            Self::RecoveryReconstruction => "recovery_reconstruction",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::SponsorCredit => "sponsor_credit",
            Self::ViewTagSafety => "view_tag_safety",
            Self::SubaddressSafety => "subaddress_safety",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReceiptStatus {
    Draft,
    Submitted,
    Accepted,
    Challenged,
    Revoked,
    Expired,
}

impl AuditReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_audit(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    InvalidShare,
    ShareWithholding,
    WrongViewTagWindow,
    SubaddressCrossLeak,
    FalseScanDelivery,
    ReceiptEquivocation,
    SponsorCreditFraud,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidShare => "invalid_share",
            Self::ShareWithholding => "share_withholding",
            Self::WrongViewTagWindow => "wrong_view_tag_window",
            Self::SubaddressCrossLeak => "subaddress_cross_leak",
            Self::FalseScanDelivery => "false_scan_delivery",
            Self::ReceiptEquivocation => "receipt_equivocation",
            Self::SponsorCreditFraud => "sponsor_credit_fraud",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Filed,
    UnderReview,
    Accepted,
    Rejected,
    Executed,
    Expired,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::UnderReview => "under_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Filed | Self::UnderReview | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubaddressSafetyLevel {
    Unknown,
    ViewTagOnly,
    SubaddressScoped,
    AccountScoped,
    Hardened,
}

impl SubaddressSafetyLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::ViewTagOnly => "view_tag_only",
            Self::SubaddressScoped => "subaddress_scoped",
            Self::AccountScoped => "account_scoped",
            Self::Hardened => "hardened",
        }
    }

    pub fn prevents_cross_leak(self) -> bool {
        matches!(
            self,
            Self::SubaddressScoped | Self::AccountScoped | Self::Hardened
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagSafetyMode {
    Disabled,
    CandidateOnly,
    ConfirmedOnly,
    ConfirmedWithNullifierHints,
    FullSafetyProof,
}

impl ViewTagSafetyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::CandidateOnly => "candidate_only",
            Self::ConfirmedOnly => "confirmed_only",
            Self::ConfirmedWithNullifierHints => "confirmed_with_nullifier_hints",
            Self::FullSafetyProof => "full_safety_proof",
        }
    }

    pub fn is_private_safe(self) -> bool {
        matches!(self, Self::ConfirmedOnly | Self::FullSafetyProof)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMarketPolicy {
    pub min_confirmations: u64,
    pub recovery_ttl_blocks: u64,
    pub sync_ttl_blocks: u64,
    pub audit_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_recovery_threshold: u64,
    pub min_provider_stake: u64,
    pub min_sponsor_balance: u64,
    pub max_scan_blocks: u64,
    pub scan_price_per_block: u64,
    pub recovery_price: u64,
    pub low_fee_rebate_bps: u64,
    pub max_share_bytes: u64,
    pub max_job_outputs: u64,
}

impl Default for RecoveryMarketPolicy {
    fn default() -> Self {
        Self {
            min_confirmations: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_CONFIRMATIONS,
            recovery_ttl_blocks: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_TTL_BLOCKS,
            sync_ttl_blocks: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SYNC_TTL_BLOCKS,
            audit_ttl_blocks: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_AUDIT_TTL_BLOCKS,
            sponsor_ttl_blocks: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SPONSOR_TTL_BLOCKS,
            challenge_window_blocks:
                MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_recovery_threshold:
                MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_RECOVERY_THRESHOLD,
            min_provider_stake: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_PROVIDER_STAKE,
            min_sponsor_balance: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_SPONSOR_BALANCE,
            max_scan_blocks: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_SCAN_BLOCKS,
            scan_price_per_block: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SCAN_PRICE_PER_BLOCK,
            recovery_price: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_PRICE,
            low_fee_rebate_bps: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_LOW_FEE_REBATE_BPS,
            max_share_bytes: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_SHARE_BYTES,
            max_job_outputs: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_JOB_OUTPUTS,
        }
    }
}

impl RecoveryMarketPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "min_confirmations": self.min_confirmations,
            "recovery_ttl_blocks": self.recovery_ttl_blocks,
            "sync_ttl_blocks": self.sync_ttl_blocks,
            "audit_ttl_blocks": self.audit_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_recovery_threshold": self.min_recovery_threshold,
            "min_provider_stake": self.min_provider_stake,
            "min_sponsor_balance": self.min_sponsor_balance,
            "max_scan_blocks": self.max_scan_blocks,
            "scan_price_per_block": self.scan_price_per_block,
            "recovery_price": self.recovery_price,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_share_bytes": self.max_share_bytes,
            "max_job_outputs": self.max_job_outputs,
        })
    }

    pub fn policy_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.min_confirmations == 0 {
            return Err("policy requires at least one Monero confirmation".to_string());
        }
        if self.min_recovery_threshold == 0 {
            return Err("policy recovery threshold must be nonzero".to_string());
        }
        if self.low_fee_rebate_bps > MONERO_PQ_VIEWKEY_RECOVERY_MARKET_MAX_BPS {
            return Err("policy low fee rebate exceeds max bps".to_string());
        }
        if self.max_scan_blocks == 0 {
            return Err("policy max scan blocks must be nonzero".to_string());
        }
        if self.max_share_bytes == 0 {
            return Err("policy max encrypted share bytes must be nonzero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEndpoint {
    pub endpoint_id: String,
    pub transport: String,
    pub address_commitment: String,
    pub tls_pq_pin: String,
    pub region: String,
    pub weight: u64,
}

impl ProviderEndpoint {
    pub fn new(label: &str, transport: &str, region: &str, weight: u64) -> Self {
        let endpoint_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ENDPOINT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(transport),
                HashPart::Str(region),
                HashPart::Int(weight as i128),
            ],
            32,
        );
        Self {
            endpoint_id: endpoint_id.clone(),
            transport: transport.to_string(),
            address_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ENDPOINT-ADDRESS",
                &[HashPart::Str(&endpoint_id), HashPart::Str(label)],
                32,
            ),
            tls_pq_pin: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ENDPOINT-TLS-PIN",
                &[HashPart::Str(&endpoint_id), HashPart::Str(transport)],
                32,
            ),
            region: region.to_string(),
            weight,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "endpoint_id": self.endpoint_id,
            "transport": self.transport,
            "address_commitment": self.address_commitment,
            "tls_pq_pin": self.tls_pq_pin,
            "region": self.region,
            "weight": self.weight,
        })
    }

    pub fn endpoint_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ENDPOINT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryProvider {
    pub provider_id: String,
    pub operator_commitment: String,
    pub role: RecoveryProviderRole,
    pub status: ProviderStatus,
    pub pq_envelope_scheme: PqEnvelopeScheme,
    pub stake_amount: u64,
    pub reputation_score: u64,
    pub max_parallel_jobs: u64,
    pub endpoint: ProviderEndpoint,
    pub capabilities: BTreeSet<String>,
    pub activation_height: u64,
    pub last_heartbeat_height: u64,
}

impl RecoveryProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        role: RecoveryProviderRole,
        scheme: PqEnvelopeScheme,
        stake_amount: u64,
        reputation_score: u64,
        max_parallel_jobs: u64,
        endpoint: ProviderEndpoint,
        activation_height: u64,
    ) -> Self {
        let provider_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROVIDER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(role.as_str()),
                HashPart::Str(scheme.as_str()),
                HashPart::Int(activation_height as i128),
            ],
            32,
        );
        let mut capabilities = BTreeSet::new();
        capabilities.insert(role.as_str().to_string());
        if matches!(role, RecoveryProviderRole::WatchOnlyScanner) {
            capabilities.insert("view_tag_scan".to_string());
            capabilities.insert("subaddress_scoped_scan".to_string());
        }
        if matches!(role, RecoveryProviderRole::ShareCustodian) {
            capabilities.insert("encrypted_share_custody".to_string());
            capabilities.insert("threshold_release".to_string());
        }
        Self {
            provider_id: provider_id.clone(),
            operator_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROVIDER-OPERATOR",
                &[HashPart::Str(&provider_id), HashPart::Str(label)],
                32,
            ),
            role,
            status: ProviderStatus::Active,
            pq_envelope_scheme: scheme,
            stake_amount,
            reputation_score,
            max_parallel_jobs,
            endpoint,
            capabilities,
            activation_height,
            last_heartbeat_height: activation_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "pq_envelope_scheme": self.pq_envelope_scheme.as_str(),
            "pq_security_bits": self.pq_envelope_scheme.security_bits(),
            "stake_amount": self.stake_amount,
            "reputation_score": self.reputation_score,
            "max_parallel_jobs": self.max_parallel_jobs,
            "endpoint": self.endpoint.public_record(),
            "capabilities": self.capabilities.iter().cloned().collect::<Vec<_>>(),
            "activation_height": self.activation_height,
            "last_heartbeat_height": self.last_heartbeat_height,
        })
    }

    pub fn provider_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROVIDER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        policy: &RecoveryMarketPolicy,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.provider_id.is_empty() {
            return Err("provider id is empty".to_string());
        }
        if self.operator_commitment.is_empty() {
            return Err(format!(
                "provider {} has empty operator commitment",
                self.provider_id
            ));
        }
        if self.stake_amount < policy.min_provider_stake
            && !matches!(self.role, RecoveryProviderRole::Sponsor)
        {
            return Err(format!(
                "provider {} stake below policy minimum",
                self.provider_id
            ));
        }
        if self.max_parallel_jobs == 0 {
            return Err(format!(
                "provider {} cannot advertise zero parallel jobs",
                self.provider_id
            ));
        }
        if self.endpoint.weight == 0 {
            return Err(format!(
                "provider {} endpoint has zero weight",
                self.provider_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewKeyRecoveryProfile {
    pub profile_id: String,
    pub wallet_commitment: String,
    pub monero_network: String,
    pub account_index_commitment: String,
    pub subaddress_scope_root: String,
    pub view_public_key_commitment: String,
    pub spend_public_key_commitment: String,
    pub view_tag_safety_mode: ViewTagSafetyMode,
    pub subaddress_safety_level: SubaddressSafetyLevel,
    pub required_threshold: u64,
    pub allowed_provider_root: String,
    pub sponsor_policy_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl ViewKeyRecoveryProfile {
    pub fn devnet(label: &str, allowed_provider_ids: &[String], height: u64) -> Self {
        let wallet_commitment = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-WALLET",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
            32,
        );
        let provider_leaves = allowed_provider_ids
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        let subaddress_leaves = (0..4_u64)
            .map(|index| {
                Value::String(domain_hash(
                    "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SUBADDRESS-SCOPE",
                    &[
                        HashPart::Str(&wallet_commitment),
                        HashPart::Int(index as i128),
                    ],
                    32,
                ))
            })
            .collect::<Vec<_>>();
        let allowed_provider_root = merkle_root(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ALLOWED-PROVIDER",
            &provider_leaves,
        );
        let sponsor_policy_root = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SPONSOR-POLICY",
            &[
                HashPart::Str(&wallet_commitment),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let profile_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROFILE-ID",
            &[
                HashPart::Str(&wallet_commitment),
                HashPart::Str(&allowed_provider_root),
                HashPart::Str(&sponsor_policy_root),
            ],
            32,
        );
        Self {
            profile_id,
            wallet_commitment: wallet_commitment.clone(),
            monero_network: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_NETWORK.to_string(),
            account_index_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ACCOUNT-INDEX",
                &[HashPart::Str(&wallet_commitment), HashPart::Str(label)],
                32,
            ),
            subaddress_scope_root: merkle_root(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SUBADDRESS-SCOPE",
                &subaddress_leaves,
            ),
            view_public_key_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-VIEW-PUBLIC",
                &[HashPart::Str(&wallet_commitment)],
                32,
            ),
            spend_public_key_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SPEND-PUBLIC",
                &[HashPart::Str(&wallet_commitment)],
                32,
            ),
            view_tag_safety_mode: ViewTagSafetyMode::FullSafetyProof,
            subaddress_safety_level: SubaddressSafetyLevel::Hardened,
            required_threshold: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_RECOVERY_THRESHOLD,
            allowed_provider_root,
            sponsor_policy_root,
            created_height: height,
            expires_height: height + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "wallet_commitment": self.wallet_commitment,
            "monero_network": self.monero_network,
            "account_index_commitment": self.account_index_commitment,
            "subaddress_scope_root": self.subaddress_scope_root,
            "view_public_key_commitment": self.view_public_key_commitment,
            "spend_public_key_commitment": self.spend_public_key_commitment,
            "view_tag_safety_mode": self.view_tag_safety_mode.as_str(),
            "subaddress_safety_level": self.subaddress_safety_level.as_str(),
            "required_threshold": self.required_threshold,
            "allowed_provider_root": self.allowed_provider_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn profile_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROFILE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        policy: &RecoveryMarketPolicy,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.profile_id.is_empty() {
            return Err("profile id is empty".to_string());
        }
        if self.required_threshold < policy.min_recovery_threshold {
            return Err(format!(
                "profile {} threshold below policy minimum",
                self.profile_id
            ));
        }
        if !self.view_tag_safety_mode.is_private_safe() {
            return Err(format!(
                "profile {} view-tag mode is not private safe",
                self.profile_id
            ));
        }
        if !self.subaddress_safety_level.prevents_cross_leak() {
            return Err(format!(
                "profile {} subaddress metadata does not prevent cross leaks",
                self.profile_id
            ));
        }
        if self.expires_height <= self.created_height {
            return Err(format!(
                "profile {} expires before it becomes active",
                self.profile_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecoveryShare {
    pub share_id: String,
    pub profile_id: String,
    pub provider_id: String,
    pub request_id: String,
    pub envelope_scheme: PqEnvelopeScheme,
    pub encrypted_share_root: String,
    pub share_commitment: String,
    pub ciphertext_bytes: u64,
    pub share_index: u64,
    pub threshold: u64,
    pub status: ShareStatus,
    pub custody_receipt_id: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl EncryptedRecoveryShare {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: &str,
        provider_id: &str,
        request_id: &str,
        scheme: PqEnvelopeScheme,
        share_index: u64,
        threshold: u64,
        height: u64,
    ) -> Self {
        let share_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SHARE-ID",
            &[
                HashPart::Str(profile_id),
                HashPart::Str(provider_id),
                HashPart::Str(request_id),
                HashPart::Int(share_index as i128),
            ],
            32,
        );
        let encrypted_share_root = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SHARE-CIPHERTEXT",
            &[HashPart::Str(&share_id), HashPart::Str(scheme.as_str())],
            32,
        );
        Self {
            share_id: share_id.clone(),
            profile_id: profile_id.to_string(),
            provider_id: provider_id.to_string(),
            request_id: request_id.to_string(),
            envelope_scheme: scheme,
            encrypted_share_root: encrypted_share_root.clone(),
            share_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SHARE-COMMITMENT",
                &[
                    HashPart::Str(&share_id),
                    HashPart::Str(&encrypted_share_root),
                ],
                32,
            ),
            ciphertext_bytes: 1_184,
            share_index,
            threshold,
            status: ShareStatus::Sealed,
            custody_receipt_id: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SHARE-CUSTODY-RECEIPT",
                &[HashPart::Str(&share_id), HashPart::Int(height as i128)],
                32,
            ),
            created_height: height,
            expires_height: height + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "profile_id": self.profile_id,
            "provider_id": self.provider_id,
            "request_id": self.request_id,
            "envelope_scheme": self.envelope_scheme.as_str(),
            "encrypted_share_root": self.encrypted_share_root,
            "share_commitment": self.share_commitment,
            "ciphertext_bytes": self.ciphertext_bytes,
            "share_index": self.share_index,
            "threshold": self.threshold,
            "status": self.status.as_str(),
            "custody_receipt_id": self.custody_receipt_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn share_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SHARE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        policy: &RecoveryMarketPolicy,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.share_id.is_empty() || self.profile_id.is_empty() || self.provider_id.is_empty() {
            return Err("encrypted recovery share has an empty identity field".to_string());
        }
        if self.ciphertext_bytes == 0 || self.ciphertext_bytes > policy.max_share_bytes {
            return Err(format!(
                "share {} ciphertext size outside policy",
                self.share_id
            ));
        }
        if self.threshold < policy.min_recovery_threshold {
            return Err(format!("share {} threshold below policy", self.share_id));
        }
        if self.expires_height <= self.created_height {
            return Err(format!("share {} expires before creation", self.share_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub request_id: String,
    pub profile_id: String,
    pub wallet_commitment: String,
    pub requester_commitment: String,
    pub sponsor_credit_id: Option<String>,
    pub requested_threshold: u64,
    pub share_root: String,
    pub nullifier_root: String,
    pub status: RecoveryRequestStatus,
    pub fee_asset_id: String,
    pub max_fee: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl RecoveryRequest {
    pub fn new(
        profile: &ViewKeyRecoveryProfile,
        requester_label: &str,
        sponsor_credit_id: Option<String>,
        share_records: &[EncryptedRecoveryShare],
        height: u64,
    ) -> Self {
        let share_leaves = share_records
            .iter()
            .map(EncryptedRecoveryShare::public_record)
            .collect::<Vec<_>>();
        let share_root = merkle_root(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-REQUEST-SHARE",
            &share_leaves,
        );
        let nullifier_root = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-RECOVERY-NULLIFIER",
            &[
                HashPart::Str(&profile.profile_id),
                HashPart::Str(requester_label),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let request_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-REQUEST-ID",
            &[
                HashPart::Str(&profile.profile_id),
                HashPart::Str(&share_root),
                HashPart::Str(&nullifier_root),
            ],
            32,
        );
        Self {
            request_id,
            profile_id: profile.profile_id.clone(),
            wallet_commitment: profile.wallet_commitment.clone(),
            requester_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-REQUESTER",
                &[
                    HashPart::Str(requester_label),
                    HashPart::Str(&profile.profile_id),
                ],
                32,
            ),
            sponsor_credit_id,
            requested_threshold: profile.required_threshold,
            share_root,
            nullifier_root,
            status: RecoveryRequestStatus::SharesCommitted,
            fee_asset_id: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_FEE_ASSET_ID.to_string(),
            max_fee: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_PRICE,
            created_height: height,
            expires_height: height + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_RECOVERY_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "profile_id": self.profile_id,
            "wallet_commitment": self.wallet_commitment,
            "requester_commitment": self.requester_commitment,
            "sponsor_credit_id": self.sponsor_credit_id,
            "requested_threshold": self.requested_threshold,
            "share_root": self.share_root,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee": self.max_fee,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn request_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-REQUEST",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        policy: &RecoveryMarketPolicy,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.request_id.is_empty() || self.profile_id.is_empty() {
            return Err("recovery request has an empty identity field".to_string());
        }
        if self.requested_threshold < policy.min_recovery_threshold {
            return Err(format!(
                "request {} threshold below policy",
                self.request_id
            ));
        }
        if self.max_fee > 0 && self.fee_asset_id.is_empty() {
            return Err(format!(
                "request {} charges a fee without an asset id",
                self.request_id
            ));
        }
        if self.expires_height <= self.created_height {
            return Err(format!(
                "request {} expires before creation",
                self.request_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroViewTagSafetyMetadata {
    pub safety_id: String,
    pub profile_id: String,
    pub subaddress_scope_root: String,
    pub view_tag_mode: ViewTagSafetyMode,
    pub subaddress_level: SubaddressSafetyLevel,
    pub view_tag_bytes: u64,
    pub lookahead_blocks: u64,
    pub decoy_window_commitment: String,
    pub output_membership_root: String,
    pub no_cross_subaddress_leak_proof: String,
    pub created_height: u64,
}

impl MoneroViewTagSafetyMetadata {
    pub fn from_profile(profile: &ViewKeyRecoveryProfile, height: u64) -> Self {
        let safety_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SAFETY-ID",
            &[
                HashPart::Str(&profile.profile_id),
                HashPart::Int(height as i128),
            ],
            32,
        );
        Self {
            safety_id: safety_id.clone(),
            profile_id: profile.profile_id.clone(),
            subaddress_scope_root: profile.subaddress_scope_root.clone(),
            view_tag_mode: profile.view_tag_safety_mode,
            subaddress_level: profile.subaddress_safety_level,
            view_tag_bytes: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_VIEW_TAG_BYTES,
            lookahead_blocks: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_CONFIRMATIONS * 2,
            decoy_window_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-DECOY-WINDOW",
                &[HashPart::Str(&safety_id)],
                32,
            ),
            output_membership_root: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-OUTPUT-MEMBERSHIP",
                &[
                    HashPart::Str(&safety_id),
                    HashPart::Str(&profile.wallet_commitment),
                ],
                32,
            ),
            no_cross_subaddress_leak_proof: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-NO-CROSS-SUBADDRESS-LEAK",
                &[
                    HashPart::Str(&safety_id),
                    HashPart::Str(&profile.subaddress_scope_root),
                ],
                32,
            ),
            created_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "safety_id": self.safety_id,
            "profile_id": self.profile_id,
            "subaddress_scope_root": self.subaddress_scope_root,
            "view_tag_mode": self.view_tag_mode.as_str(),
            "subaddress_level": self.subaddress_level.as_str(),
            "view_tag_bytes": self.view_tag_bytes,
            "lookahead_blocks": self.lookahead_blocks,
            "decoy_window_commitment": self.decoy_window_commitment,
            "output_membership_root": self.output_membership_root,
            "no_cross_subaddress_leak_proof": self.no_cross_subaddress_leak_proof,
            "created_height": self.created_height,
        })
    }

    pub fn safety_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SAFETY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.view_tag_bytes != MONERO_PQ_VIEWKEY_RECOVERY_MARKET_VIEW_TAG_BYTES {
            return Err(format!(
                "safety metadata {} has invalid view-tag byte size",
                self.safety_id
            ));
        }
        if !self.view_tag_mode.is_private_safe() {
            return Err(format!(
                "safety metadata {} view-tag mode is unsafe",
                self.safety_id
            ));
        }
        if !self.subaddress_level.prevents_cross_leak() {
            return Err(format!(
                "safety metadata {} subaddress scope is unsafe",
                self.safety_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchOnlySyncJob {
    pub job_id: String,
    pub profile_id: String,
    pub provider_id: String,
    pub request_id: Option<String>,
    pub safety_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub view_tag_root: String,
    pub output_commitment_root: String,
    pub result_ciphertext_root: String,
    pub max_outputs: u64,
    pub quoted_fee: u64,
    pub sponsor_credit_id: Option<String>,
    pub status: SyncJobStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl WatchOnlySyncJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: &ViewKeyRecoveryProfile,
        provider_id: &str,
        safety: &MoneroViewTagSafetyMetadata,
        from_height: u64,
        to_height: u64,
        sponsor_credit_id: Option<String>,
        height: u64,
    ) -> Self {
        let view_tag_root = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-JOB-VIEW-TAG-ROOT",
            &[
                HashPart::Str(&profile.profile_id),
                HashPart::Str(&safety.safety_id),
                HashPart::Int(from_height as i128),
                HashPart::Int(to_height as i128),
            ],
            32,
        );
        let job_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-JOB-ID",
            &[
                HashPart::Str(&profile.profile_id),
                HashPart::Str(provider_id),
                HashPart::Str(&view_tag_root),
                HashPart::Int(height as i128),
            ],
            32,
        );
        Self {
            job_id: job_id.clone(),
            profile_id: profile.profile_id.clone(),
            provider_id: provider_id.to_string(),
            request_id: None,
            safety_id: safety.safety_id.clone(),
            from_height,
            to_height,
            view_tag_root: view_tag_root.clone(),
            output_commitment_root: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-JOB-OUTPUT-COMMITMENT",
                &[HashPart::Str(&job_id), HashPart::Str(&view_tag_root)],
                32,
            ),
            result_ciphertext_root: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-JOB-RESULT-CIPHERTEXT",
                &[
                    HashPart::Str(&job_id),
                    HashPart::Str(&profile.wallet_commitment),
                ],
                32,
            ),
            max_outputs: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MAX_JOB_OUTPUTS,
            quoted_fee: (to_height.saturating_sub(from_height))
                * MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SCAN_PRICE_PER_BLOCK,
            sponsor_credit_id,
            status: SyncJobStatus::Scanning,
            created_height: height,
            expires_height: height + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SYNC_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "profile_id": self.profile_id,
            "provider_id": self.provider_id,
            "request_id": self.request_id,
            "safety_id": self.safety_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "view_tag_root": self.view_tag_root,
            "output_commitment_root": self.output_commitment_root,
            "result_ciphertext_root": self.result_ciphertext_root,
            "max_outputs": self.max_outputs,
            "quoted_fee": self.quoted_fee,
            "sponsor_credit_id": self.sponsor_credit_id,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn job_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-JOB",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        policy: &RecoveryMarketPolicy,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.job_id.is_empty() || self.provider_id.is_empty() {
            return Err("watch-only sync job has an empty identity field".to_string());
        }
        if self.to_height <= self.from_height {
            return Err(format!("sync job {} has an empty scan range", self.job_id));
        }
        if self.to_height - self.from_height > policy.max_scan_blocks {
            return Err(format!("sync job {} exceeds max scan blocks", self.job_id));
        }
        if self.max_outputs > policy.max_job_outputs {
            return Err(format!("sync job {} exceeds max output count", self.job_id));
        }
        if self.expires_height <= self.created_height {
            return Err(format!("sync job {} expires before creation", self.job_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorCredit {
    pub credit_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub applicable_profile_root: String,
    pub fee_asset_id: String,
    pub initial_balance: u64,
    pub remaining_balance: u64,
    pub rebate_bps: u64,
    pub reserved_fee: u64,
    pub status: SponsorCreditStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl SponsorCredit {
    pub fn new(sponsor_id: &str, beneficiary_label: &str, profile_root: &str, height: u64) -> Self {
        let beneficiary_commitment = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SPONSOR-BENEFICIARY",
            &[HashPart::Str(sponsor_id), HashPart::Str(beneficiary_label)],
            32,
        );
        let credit_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SPONSOR-CREDIT-ID",
            &[
                HashPart::Str(sponsor_id),
                HashPart::Str(&beneficiary_commitment),
                HashPart::Str(profile_root),
                HashPart::Int(height as i128),
            ],
            32,
        );
        Self {
            credit_id,
            sponsor_id: sponsor_id.to_string(),
            beneficiary_commitment,
            applicable_profile_root: profile_root.to_string(),
            fee_asset_id: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_FEE_ASSET_ID.to_string(),
            initial_balance: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_SPONSOR_BALANCE,
            remaining_balance: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_MIN_SPONSOR_BALANCE,
            rebate_bps: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_LOW_FEE_REBATE_BPS,
            reserved_fee: 0,
            status: SponsorCreditStatus::Offered,
            created_height: height,
            expires_height: height + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_SPONSOR_TTL_BLOCKS,
        }
    }

    pub fn reserve_fee(&mut self, fee: u64) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if fee > self.remaining_balance {
            return Err(format!(
                "sponsor credit {} cannot reserve fee {}",
                self.credit_id, fee
            ));
        }
        self.remaining_balance -= fee;
        self.reserved_fee += fee;
        self.status = SponsorCreditStatus::Reserved;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "applicable_profile_root": self.applicable_profile_root,
            "fee_asset_id": self.fee_asset_id,
            "initial_balance": self.initial_balance,
            "remaining_balance": self.remaining_balance,
            "rebate_bps": self.rebate_bps,
            "reserved_fee": self.reserved_fee,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn credit_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SPONSOR-CREDIT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        policy: &RecoveryMarketPolicy,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.credit_id.is_empty() || self.sponsor_id.is_empty() {
            return Err("sponsor credit has an empty identity field".to_string());
        }
        if self.initial_balance < policy.min_sponsor_balance {
            return Err(format!(
                "sponsor credit {} below minimum balance",
                self.credit_id
            ));
        }
        if self.remaining_balance + self.reserved_fee > self.initial_balance {
            return Err(format!(
                "sponsor credit {} has invalid accounting",
                self.credit_id
            ));
        }
        if self.rebate_bps > MONERO_PQ_VIEWKEY_RECOVERY_MARKET_MAX_BPS {
            return Err(format!(
                "sponsor credit {} rebate exceeds max bps",
                self.credit_id
            ));
        }
        if self.expires_height <= self.created_height {
            return Err(format!(
                "sponsor credit {} expires before creation",
                self.credit_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAuditReceipt {
    pub receipt_id: String,
    pub kind: AuditReceiptKind,
    pub status: AuditReceiptStatus,
    pub subject_root: String,
    pub provider_id: String,
    pub auditor_commitment: String,
    pub hidden_wallet_nullifier: String,
    pub privacy_budget_root: String,
    pub transcript_commitment: String,
    pub proof_system: String,
    pub proof_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl PrivacyAuditReceipt {
    pub fn new(
        kind: AuditReceiptKind,
        subject_root: &str,
        provider_id: &str,
        auditor_label: &str,
        height: u64,
    ) -> Self {
        let hidden_wallet_nullifier = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-HIDDEN-WALLET",
            &[HashPart::Str(subject_root), HashPart::Str(auditor_label)],
            32,
        );
        let receipt_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-RECEIPT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_root),
                HashPart::Str(provider_id),
                HashPart::Str(&hidden_wallet_nullifier),
            ],
            32,
        );
        Self {
            receipt_id: receipt_id.clone(),
            kind,
            status: AuditReceiptStatus::Accepted,
            subject_root: subject_root.to_string(),
            provider_id: provider_id.to_string(),
            auditor_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDITOR",
                &[HashPart::Str(auditor_label), HashPart::Str(provider_id)],
                32,
            ),
            hidden_wallet_nullifier,
            privacy_budget_root: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-PRIVACY-BUDGET",
                &[HashPart::Str(&receipt_id), HashPart::Int(height as i128)],
                32,
            ),
            transcript_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-TRANSCRIPT",
                &[HashPart::Str(&receipt_id), HashPart::Str(subject_root)],
                32,
            ),
            proof_system: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_RECEIPT_SCHEME.to_string(),
            proof_root: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-PROOF",
                &[HashPart::Str(&receipt_id), HashPart::Str(kind.as_str())],
                32,
            ),
            created_height: height,
            expires_height: height + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_AUDIT_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_root": self.subject_root,
            "provider_id": self.provider_id,
            "auditor_commitment": self.auditor_commitment,
            "hidden_wallet_nullifier": self.hidden_wallet_nullifier,
            "privacy_budget_root": self.privacy_budget_root,
            "transcript_commitment": self.transcript_commitment,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.receipt_id.is_empty() || self.subject_root.is_empty() || self.provider_id.is_empty()
        {
            return Err("privacy audit receipt has an empty identity field".to_string());
        }
        if self.proof_system != MONERO_PQ_VIEWKEY_RECOVERY_MARKET_RECEIPT_SCHEME {
            return Err(format!(
                "receipt {} uses unsupported proof system",
                self.receipt_id
            ));
        }
        if self.expires_height <= self.created_height {
            return Err(format!(
                "receipt {} expires before creation",
                self.receipt_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingEvidenceKind,
    pub status: SlashingStatus,
    pub accused_provider_id: String,
    pub reporter_commitment: String,
    pub subject_root: String,
    pub contradictory_receipt_root: Option<String>,
    pub evidence_payload_root: String,
    pub slashing_amount: u64,
    pub bond_asset_id: String,
    pub filed_height: u64,
    pub review_deadline_height: u64,
}

impl SlashingEvidence {
    pub fn new(
        kind: SlashingEvidenceKind,
        accused_provider_id: &str,
        reporter_label: &str,
        subject_root: &str,
        slashing_amount: u64,
        height: u64,
    ) -> Self {
        let evidence_payload_root = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SLASHING-PAYLOAD",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(accused_provider_id),
                HashPart::Str(subject_root),
            ],
            32,
        );
        let evidence_id = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SLASHING-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(accused_provider_id),
                HashPart::Str(&evidence_payload_root),
                HashPart::Int(height as i128),
            ],
            32,
        );
        Self {
            evidence_id,
            kind,
            status: SlashingStatus::Filed,
            accused_provider_id: accused_provider_id.to_string(),
            reporter_commitment: domain_hash(
                "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SLASHING-REPORTER",
                &[
                    HashPart::Str(reporter_label),
                    HashPart::Str(accused_provider_id),
                ],
                32,
            ),
            subject_root: subject_root.to_string(),
            contradictory_receipt_root: None,
            evidence_payload_root,
            slashing_amount,
            bond_asset_id: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_FEE_ASSET_ID.to_string(),
            filed_height: height,
            review_deadline_height: height
                + MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "accused_provider_id": self.accused_provider_id,
            "reporter_commitment": self.reporter_commitment,
            "subject_root": self.subject_root,
            "contradictory_receipt_root": self.contradictory_receipt_root,
            "evidence_payload_root": self.evidence_payload_root,
            "slashing_amount": self.slashing_amount,
            "bond_asset_id": self.bond_asset_id,
            "filed_height": self.filed_height,
            "review_deadline_height": self.review_deadline_height,
        })
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SLASHING",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.evidence_id.is_empty() || self.accused_provider_id.is_empty() {
            return Err("slashing evidence has an empty identity field".to_string());
        }
        if self.slashing_amount == 0 {
            return Err(format!(
                "slashing evidence {} has zero amount",
                self.evidence_id
            ));
        }
        if self.review_deadline_height <= self.filed_height {
            return Err(format!(
                "slashing evidence {} has invalid review window",
                self.evidence_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMarketRoots {
    pub policy_root: String,
    pub provider_root: String,
    pub profile_root: String,
    pub recovery_request_root: String,
    pub encrypted_share_root: String,
    pub sync_job_root: String,
    pub sponsor_credit_root: String,
    pub audit_receipt_root: String,
    pub slashing_evidence_root: String,
    pub safety_metadata_root: String,
}

impl RecoveryMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_root": self.policy_root,
            "provider_root": self.provider_root,
            "profile_root": self.profile_root,
            "recovery_request_root": self.recovery_request_root,
            "encrypted_share_root": self.encrypted_share_root,
            "sync_job_root": self.sync_job_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "audit_receipt_root": self.audit_receipt_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "safety_metadata_root": self.safety_metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-ROOTS",
            &[
                HashPart::Str(&self.policy_root),
                HashPart::Str(&self.provider_root),
                HashPart::Str(&self.profile_root),
                HashPart::Str(&self.recovery_request_root),
                HashPart::Str(&self.encrypted_share_root),
                HashPart::Str(&self.sync_job_root),
                HashPart::Str(&self.sponsor_credit_root),
                HashPart::Str(&self.audit_receipt_root),
                HashPart::Str(&self.slashing_evidence_root),
                HashPart::Str(&self.safety_metadata_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMarketCounters {
    pub provider_count: usize,
    pub active_provider_count: usize,
    pub profile_count: usize,
    pub open_recovery_request_count: usize,
    pub encrypted_share_count: usize,
    pub usable_share_count: usize,
    pub live_sync_job_count: usize,
    pub live_sponsor_credit_count: usize,
    pub accepted_audit_receipt_count: usize,
    pub open_slashing_count: usize,
    pub safety_metadata_count: usize,
    pub total_provider_stake: u64,
    pub total_sponsor_balance: u64,
    pub total_reserved_sponsor_fee: u64,
    pub total_quoted_sync_fee: u64,
}

impl RecoveryMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_count": self.provider_count,
            "active_provider_count": self.active_provider_count,
            "profile_count": self.profile_count,
            "open_recovery_request_count": self.open_recovery_request_count,
            "encrypted_share_count": self.encrypted_share_count,
            "usable_share_count": self.usable_share_count,
            "live_sync_job_count": self.live_sync_job_count,
            "live_sponsor_credit_count": self.live_sponsor_credit_count,
            "accepted_audit_receipt_count": self.accepted_audit_receipt_count,
            "open_slashing_count": self.open_slashing_count,
            "safety_metadata_count": self.safety_metadata_count,
            "total_provider_stake": self.total_provider_stake,
            "total_sponsor_balance": self.total_sponsor_balance,
            "total_reserved_sponsor_fee": self.total_reserved_sponsor_fee,
            "total_quoted_sync_fee": self.total_quoted_sync_fee,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqViewKeyRecoveryMarket {
    pub protocol_version: String,
    pub security_model: String,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub height: u64,
    pub policy: RecoveryMarketPolicy,
    pub providers: BTreeMap<String, RecoveryProvider>,
    pub profiles: BTreeMap<String, ViewKeyRecoveryProfile>,
    pub recovery_requests: BTreeMap<String, RecoveryRequest>,
    pub encrypted_shares: BTreeMap<String, EncryptedRecoveryShare>,
    pub sync_jobs: BTreeMap<String, WatchOnlySyncJob>,
    pub sponsor_credits: BTreeMap<String, SponsorCredit>,
    pub audit_receipts: BTreeMap<String, PrivacyAuditReceipt>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub safety_metadata: BTreeMap<String, MoneroViewTagSafetyMetadata>,
}

impl MoneroPqViewKeyRecoveryMarket {
    pub fn devnet() -> MoneroPqViewKeyRecoveryMarketResult<Self> {
        let height = MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEFAULT_HEIGHT;
        let policy = RecoveryMarketPolicy::default();
        let scanner = RecoveryProvider::new(
            "devnet-scanner-alpha",
            RecoveryProviderRole::WatchOnlyScanner,
            PqEnvelopeScheme::HybridX25519MlKem768,
            policy.min_provider_stake * 2,
            97,
            24,
            ProviderEndpoint::new("devnet-scanner-alpha", "noise_pq_tcp", "iad", 10),
            height,
        );
        let custodian_a = RecoveryProvider::new(
            "devnet-share-custodian-a",
            RecoveryProviderRole::ShareCustodian,
            PqEnvelopeScheme::MlKem768AesGcm,
            policy.min_provider_stake * 3,
            99,
            12,
            ProviderEndpoint::new("devnet-share-custodian-a", "noise_pq_tcp", "nyc", 9),
            height,
        );
        let custodian_b = RecoveryProvider::new(
            "devnet-share-custodian-b",
            RecoveryProviderRole::ShareCustodian,
            PqEnvelopeScheme::HybridX25519MlKem1024,
            policy.min_provider_stake * 3,
            98,
            12,
            ProviderEndpoint::new("devnet-share-custodian-b", "noise_pq_tcp", "sea", 9),
            height,
        );
        let auditor = RecoveryProvider::new(
            "devnet-auditor",
            RecoveryProviderRole::Auditor,
            PqEnvelopeScheme::SlhDsaReceiptBound,
            policy.min_provider_stake,
            95,
            8,
            ProviderEndpoint::new("devnet-auditor", "https_pq", "ord", 8),
            height,
        );
        let sponsor = RecoveryProvider::new(
            "devnet-low-fee-sponsor",
            RecoveryProviderRole::Sponsor,
            PqEnvelopeScheme::MlKem768AesGcm,
            policy.min_sponsor_balance,
            93,
            16,
            ProviderEndpoint::new("devnet-low-fee-sponsor", "https_pq", "atl", 7),
            height,
        );

        let mut providers = BTreeMap::new();
        for provider in [scanner, custodian_a, custodian_b, auditor, sponsor] {
            providers.insert(provider.provider_id.clone(), provider);
        }

        let provider_ids = providers.keys().cloned().collect::<Vec<_>>();
        let profile =
            ViewKeyRecoveryProfile::devnet("devnet-wallet-primary", &provider_ids, height);
        let safety = MoneroViewTagSafetyMetadata::from_profile(&profile, height);
        let custodian_ids = providers
            .values()
            .filter(|provider| provider.role == RecoveryProviderRole::ShareCustodian)
            .map(|provider| provider.provider_id.clone())
            .collect::<Vec<_>>();
        let request_seed = domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-DEVNET-REQUEST-SEED",
            &[
                HashPart::Str(&profile.profile_id),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let mut encrypted_shares = BTreeMap::new();
        for (index, provider_id) in custodian_ids.iter().enumerate() {
            let share = EncryptedRecoveryShare::new(
                &profile.profile_id,
                provider_id,
                &request_seed,
                providers[provider_id].pq_envelope_scheme,
                index as u64,
                profile.required_threshold,
                height,
            );
            encrypted_shares.insert(share.share_id.clone(), share);
        }
        let share_values = encrypted_shares.values().cloned().collect::<Vec<_>>();
        let mut sponsor_credit = SponsorCredit::new(
            providers
                .values()
                .find(|provider| provider.role == RecoveryProviderRole::Sponsor)
                .map(|provider| provider.provider_id.as_str())
                .unwrap_or("devnet-sponsor"),
            "devnet-wallet-primary",
            &profile.profile_root(),
            height,
        );
        sponsor_credit.reserve_fee(policy.recovery_price / 2)?;
        let recovery_request = RecoveryRequest::new(
            &profile,
            "devnet-wallet-owner",
            Some(sponsor_credit.credit_id.clone()),
            &share_values,
            height,
        );
        for share in encrypted_shares.values_mut() {
            share.request_id = recovery_request.request_id.clone();
        }
        let scanner_id = providers
            .values()
            .find(|provider| provider.role == RecoveryProviderRole::WatchOnlyScanner)
            .map(|provider| provider.provider_id.clone())
            .unwrap_or_default();
        let sync_job = WatchOnlySyncJob::new(
            &profile,
            &scanner_id,
            &safety,
            height - 64,
            height,
            Some(sponsor_credit.credit_id.clone()),
            height,
        );

        let mut sponsor_credits = BTreeMap::new();
        sponsor_credits.insert(sponsor_credit.credit_id.clone(), sponsor_credit);

        let mut profiles = BTreeMap::new();
        profiles.insert(profile.profile_id.clone(), profile.clone());

        let mut safety_metadata = BTreeMap::new();
        safety_metadata.insert(safety.safety_id.clone(), safety.clone());

        let mut recovery_requests = BTreeMap::new();
        recovery_requests.insert(
            recovery_request.request_id.clone(),
            recovery_request.clone(),
        );

        let mut sync_jobs = BTreeMap::new();
        sync_jobs.insert(sync_job.job_id.clone(), sync_job.clone());

        let provider_id = providers
            .values()
            .find(|provider| provider.role == RecoveryProviderRole::Auditor)
            .map(|provider| provider.provider_id.clone())
            .unwrap_or_default();
        let receipts = [
            PrivacyAuditReceipt::new(
                AuditReceiptKind::ShareCustody,
                &merkle_root(
                    "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-DEVNET-SHARE-ROOT",
                    &share_values
                        .iter()
                        .map(EncryptedRecoveryShare::public_record)
                        .collect::<Vec<_>>(),
                ),
                &provider_id,
                "devnet-auditor",
                height,
            ),
            PrivacyAuditReceipt::new(
                AuditReceiptKind::WatchOnlyScan,
                &sync_job.job_root(),
                &provider_id,
                "devnet-auditor",
                height,
            ),
            PrivacyAuditReceipt::new(
                AuditReceiptKind::ViewTagSafety,
                &safety.safety_root(),
                &provider_id,
                "devnet-auditor",
                height,
            ),
        ];
        let mut audit_receipts = BTreeMap::new();
        for receipt in receipts {
            audit_receipts.insert(receipt.receipt_id.clone(), receipt);
        }

        let evidence = SlashingEvidence::new(
            SlashingEvidenceKind::ShareWithholding,
            &custodian_ids[0],
            "devnet-watchdog",
            &share_values[0].share_root(),
            policy.min_provider_stake / 10,
            height,
        );
        let mut slashing_evidence = BTreeMap::new();
        slashing_evidence.insert(evidence.evidence_id.clone(), evidence);

        let state = Self {
            protocol_version: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_PROTOCOL_VERSION.to_string(),
            security_model: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_SECURITY_MODEL.to_string(),
            network: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PQ_VIEWKEY_RECOVERY_MARKET_DEVNET_FEE_ASSET_ID.to_string(),
            height,
            policy,
            providers,
            profiles,
            recovery_requests,
            encrypted_shares,
            sync_jobs,
            sponsor_credits,
            audit_receipts,
            slashing_evidence,
            safety_metadata,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for provider in self.providers.values_mut() {
            if provider.status.can_accept_work() {
                provider.last_heartbeat_height = height;
            }
        }
        for request in self.recovery_requests.values_mut() {
            if request.status.is_open() && height > request.expires_height {
                request.status = RecoveryRequestStatus::Expired;
            }
        }
        for share in self.encrypted_shares.values_mut() {
            if share.status.counts_for_threshold() && height > share.expires_height {
                share.status = ShareStatus::Revoked;
            }
        }
        for job in self.sync_jobs.values_mut() {
            if job.status.is_live() && height > job.expires_height {
                job.status = SyncJobStatus::Expired;
            }
        }
        for credit in self.sponsor_credits.values_mut() {
            if credit.status.is_live() && height > credit.expires_height {
                credit.status = SponsorCreditStatus::Expired;
            }
        }
        for receipt in self.audit_receipts.values_mut() {
            if receipt.status.counts_for_audit() && height > receipt.expires_height {
                receipt.status = AuditReceiptStatus::Expired;
            }
        }
        for evidence in self.slashing_evidence.values_mut() {
            if evidence.status.is_open() && height > evidence.review_deadline_height {
                evidence.status = SlashingStatus::Expired;
            }
        }
    }

    pub fn add_provider(
        &mut self,
        provider: RecoveryProvider,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        provider.validate(&self.policy)?;
        if self.providers.contains_key(&provider.provider_id) {
            return Err(format!("provider {} already exists", provider.provider_id));
        }
        self.providers
            .insert(provider.provider_id.clone(), provider);
        Ok(())
    }

    pub fn add_profile(
        &mut self,
        profile: ViewKeyRecoveryProfile,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        profile.validate(&self.policy)?;
        if self.profiles.contains_key(&profile.profile_id) {
            return Err(format!("profile {} already exists", profile.profile_id));
        }
        self.profiles.insert(profile.profile_id.clone(), profile);
        Ok(())
    }

    pub fn add_recovery_request(
        &mut self,
        request: RecoveryRequest,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        request.validate(&self.policy)?;
        if !self.profiles.contains_key(&request.profile_id) {
            return Err(format!(
                "request {} references unknown profile",
                request.request_id
            ));
        }
        if self.recovery_requests.contains_key(&request.request_id) {
            return Err(format!("request {} already exists", request.request_id));
        }
        self.recovery_requests
            .insert(request.request_id.clone(), request);
        Ok(())
    }

    pub fn add_encrypted_share(
        &mut self,
        share: EncryptedRecoveryShare,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        share.validate(&self.policy)?;
        if !self.profiles.contains_key(&share.profile_id) {
            return Err(format!(
                "share {} references unknown profile",
                share.share_id
            ));
        }
        if !self.providers.contains_key(&share.provider_id) {
            return Err(format!(
                "share {} references unknown provider",
                share.share_id
            ));
        }
        if self.encrypted_shares.contains_key(&share.share_id) {
            return Err(format!("share {} already exists", share.share_id));
        }
        self.encrypted_shares.insert(share.share_id.clone(), share);
        Ok(())
    }

    pub fn add_sync_job(
        &mut self,
        job: WatchOnlySyncJob,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        job.validate(&self.policy)?;
        if !self.profiles.contains_key(&job.profile_id) {
            return Err(format!(
                "sync job {} references unknown profile",
                job.job_id
            ));
        }
        if !self.providers.contains_key(&job.provider_id) {
            return Err(format!(
                "sync job {} references unknown provider",
                job.job_id
            ));
        }
        if !self.safety_metadata.contains_key(&job.safety_id) {
            return Err(format!(
                "sync job {} references unknown safety metadata",
                job.job_id
            ));
        }
        if self.sync_jobs.contains_key(&job.job_id) {
            return Err(format!("sync job {} already exists", job.job_id));
        }
        self.sync_jobs.insert(job.job_id.clone(), job);
        Ok(())
    }

    pub fn add_sponsor_credit(
        &mut self,
        credit: SponsorCredit,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        credit.validate(&self.policy)?;
        if !self.providers.contains_key(&credit.sponsor_id) {
            return Err(format!(
                "sponsor credit {} references unknown sponsor",
                credit.credit_id
            ));
        }
        if self.sponsor_credits.contains_key(&credit.credit_id) {
            return Err(format!(
                "sponsor credit {} already exists",
                credit.credit_id
            ));
        }
        self.sponsor_credits
            .insert(credit.credit_id.clone(), credit);
        Ok(())
    }

    pub fn add_audit_receipt(
        &mut self,
        receipt: PrivacyAuditReceipt,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        receipt.validate()?;
        if !self.providers.contains_key(&receipt.provider_id) {
            return Err(format!(
                "audit receipt {} references unknown provider",
                receipt.receipt_id
            ));
        }
        if self.audit_receipts.contains_key(&receipt.receipt_id) {
            return Err(format!(
                "audit receipt {} already exists",
                receipt.receipt_id
            ));
        }
        self.audit_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn add_slashing_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        evidence.validate()?;
        if !self.providers.contains_key(&evidence.accused_provider_id) {
            return Err(format!(
                "slashing evidence {} references unknown provider",
                evidence.evidence_id
            ));
        }
        if self.slashing_evidence.contains_key(&evidence.evidence_id) {
            return Err(format!(
                "slashing evidence {} already exists",
                evidence.evidence_id
            ));
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn add_safety_metadata(
        &mut self,
        safety: MoneroViewTagSafetyMetadata,
    ) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        safety.validate()?;
        if !self.profiles.contains_key(&safety.profile_id) {
            return Err(format!(
                "safety metadata {} references unknown profile",
                safety.safety_id
            ));
        }
        if self.safety_metadata.contains_key(&safety.safety_id) {
            return Err(format!(
                "safety metadata {} already exists",
                safety.safety_id
            ));
        }
        self.safety_metadata
            .insert(safety.safety_id.clone(), safety);
        Ok(())
    }

    pub fn provider_root(&self) -> String {
        let leaves = self
            .providers
            .values()
            .map(RecoveryProvider::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROVIDER", &leaves)
    }

    pub fn profile_root(&self) -> String {
        let leaves = self
            .profiles
            .values()
            .map(ViewKeyRecoveryProfile::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-PROFILE", &leaves)
    }

    pub fn recovery_request_root(&self) -> String {
        let leaves = self
            .recovery_requests
            .values()
            .map(RecoveryRequest::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-REQUEST", &leaves)
    }

    pub fn encrypted_share_root(&self) -> String {
        let leaves = self
            .encrypted_shares
            .values()
            .map(EncryptedRecoveryShare::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SHARE", &leaves)
    }

    pub fn sync_job_root(&self) -> String {
        let leaves = self
            .sync_jobs
            .values()
            .map(WatchOnlySyncJob::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-JOB", &leaves)
    }

    pub fn sponsor_credit_root(&self) -> String {
        let leaves = self
            .sponsor_credits
            .values()
            .map(SponsorCredit::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SPONSOR-CREDIT", &leaves)
    }

    pub fn audit_receipt_root(&self) -> String {
        let leaves = self
            .audit_receipts
            .values()
            .map(PrivacyAuditReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-AUDIT-RECEIPT", &leaves)
    }

    pub fn slashing_evidence_root(&self) -> String {
        let leaves = self
            .slashing_evidence
            .values()
            .map(SlashingEvidence::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SLASHING", &leaves)
    }

    pub fn safety_metadata_root(&self) -> String {
        let leaves = self
            .safety_metadata
            .values()
            .map(MoneroViewTagSafetyMetadata::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-PQ-VIEWKEY-RECOVERY-MARKET-SAFETY", &leaves)
    }

    pub fn roots(&self) -> RecoveryMarketRoots {
        RecoveryMarketRoots {
            policy_root: self.policy.policy_root(),
            provider_root: self.provider_root(),
            profile_root: self.profile_root(),
            recovery_request_root: self.recovery_request_root(),
            encrypted_share_root: self.encrypted_share_root(),
            sync_job_root: self.sync_job_root(),
            sponsor_credit_root: self.sponsor_credit_root(),
            audit_receipt_root: self.audit_receipt_root(),
            slashing_evidence_root: self.slashing_evidence_root(),
            safety_metadata_root: self.safety_metadata_root(),
        }
    }

    pub fn counters(&self) -> RecoveryMarketCounters {
        RecoveryMarketCounters {
            provider_count: self.providers.len(),
            active_provider_count: self
                .providers
                .values()
                .filter(|provider| provider.status.can_accept_work())
                .count(),
            profile_count: self.profiles.len(),
            open_recovery_request_count: self
                .recovery_requests
                .values()
                .filter(|request| request.status.is_open())
                .count(),
            encrypted_share_count: self.encrypted_shares.len(),
            usable_share_count: self
                .encrypted_shares
                .values()
                .filter(|share| share.status.counts_for_threshold())
                .count(),
            live_sync_job_count: self
                .sync_jobs
                .values()
                .filter(|job| job.status.is_live())
                .count(),
            live_sponsor_credit_count: self
                .sponsor_credits
                .values()
                .filter(|credit| credit.status.is_live())
                .count(),
            accepted_audit_receipt_count: self
                .audit_receipts
                .values()
                .filter(|receipt| receipt.status.counts_for_audit())
                .count(),
            open_slashing_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status.is_open())
                .count(),
            safety_metadata_count: self.safety_metadata.len(),
            total_provider_stake: self
                .providers
                .values()
                .map(|provider| provider.stake_amount)
                .sum(),
            total_sponsor_balance: self
                .sponsor_credits
                .values()
                .map(|credit| credit.remaining_balance)
                .sum(),
            total_reserved_sponsor_fee: self
                .sponsor_credits
                .values()
                .map(|credit| credit.reserved_fee)
                .sum(),
            total_quoted_sync_fee: self.sync_jobs.values().map(|job| job.quoted_fee).sum(),
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-PQ-VIEWKEY-RECOVERY-MARKET-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.network),
                HashPart::Str(&self.asset_id),
                HashPart::Str(&self.fee_asset_id),
                HashPart::Int(self.height as i128),
                HashPart::Str(&self.roots().state_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "security_model": self.security_model,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "height": self.height,
            "policy": self.policy.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn validate(&self) -> MoneroPqViewKeyRecoveryMarketResult<()> {
        if self.protocol_version != MONERO_PQ_VIEWKEY_RECOVERY_MARKET_PROTOCOL_VERSION {
            return Err(
                "unexpected Monero PQ view-key recovery market protocol version".to_string(),
            );
        }
        if self.security_model != MONERO_PQ_VIEWKEY_RECOVERY_MARKET_SECURITY_MODEL {
            return Err("unexpected Monero PQ view-key recovery market security model".to_string());
        }
        if self.network.is_empty() || self.asset_id.is_empty() || self.fee_asset_id.is_empty() {
            return Err("market has an empty network or asset identifier".to_string());
        }
        self.policy.validate()?;

        let mut provider_roles = BTreeSet::new();
        for (provider_id, provider) in &self.providers {
            if provider_id != &provider.provider_id {
                return Err(format!(
                    "provider map key mismatch for {}",
                    provider.provider_id
                ));
            }
            provider.validate(&self.policy)?;
            provider_roles.insert(provider.role);
        }
        for required_role in [
            RecoveryProviderRole::ShareCustodian,
            RecoveryProviderRole::WatchOnlyScanner,
            RecoveryProviderRole::Auditor,
            RecoveryProviderRole::Sponsor,
        ] {
            if !provider_roles.contains(&required_role) {
                return Err(format!(
                    "market missing provider role {}",
                    required_role.as_str()
                ));
            }
        }

        for (profile_id, profile) in &self.profiles {
            if profile_id != &profile.profile_id {
                return Err(format!(
                    "profile map key mismatch for {}",
                    profile.profile_id
                ));
            }
            profile.validate(&self.policy)?;
        }

        for (share_id, share) in &self.encrypted_shares {
            if share_id != &share.share_id {
                return Err(format!("share map key mismatch for {}", share.share_id));
            }
            share.validate(&self.policy)?;
            if !self.providers.contains_key(&share.provider_id) {
                return Err(format!(
                    "share {} references missing provider",
                    share.share_id
                ));
            }
            if !self.profiles.contains_key(&share.profile_id) {
                return Err(format!(
                    "share {} references missing profile",
                    share.share_id
                ));
            }
        }

        for (request_id, request) in &self.recovery_requests {
            if request_id != &request.request_id {
                return Err(format!(
                    "request map key mismatch for {}",
                    request.request_id
                ));
            }
            request.validate(&self.policy)?;
            if !self.profiles.contains_key(&request.profile_id) {
                return Err(format!(
                    "request {} references missing profile",
                    request.request_id
                ));
            }
            if let Some(credit_id) = &request.sponsor_credit_id {
                if !self.sponsor_credits.contains_key(credit_id) {
                    return Err(format!(
                        "request {} references missing sponsor credit {}",
                        request.request_id, credit_id
                    ));
                }
            }
            let usable_shares = self
                .encrypted_shares
                .values()
                .filter(|share| {
                    share.request_id == request.request_id && share.status.counts_for_threshold()
                })
                .count() as u64;
            if request.status.is_open() && usable_shares < request.requested_threshold {
                return Err(format!(
                    "request {} has {} usable shares below threshold {}",
                    request.request_id, usable_shares, request.requested_threshold
                ));
            }
        }

        for (job_id, job) in &self.sync_jobs {
            if job_id != &job.job_id {
                return Err(format!("sync job map key mismatch for {}", job.job_id));
            }
            job.validate(&self.policy)?;
            let provider = self
                .providers
                .get(&job.provider_id)
                .ok_or_else(|| format!("sync job {} references missing provider", job.job_id))?;
            if provider.role != RecoveryProviderRole::WatchOnlyScanner {
                return Err(format!(
                    "sync job {} is assigned to a non-scanner provider",
                    job.job_id
                ));
            }
            if !self.safety_metadata.contains_key(&job.safety_id) {
                return Err(format!(
                    "sync job {} references missing safety metadata",
                    job.job_id
                ));
            }
        }

        for (credit_id, credit) in &self.sponsor_credits {
            if credit_id != &credit.credit_id {
                return Err(format!(
                    "sponsor credit map key mismatch for {}",
                    credit.credit_id
                ));
            }
            credit.validate(&self.policy)?;
            let provider = self.providers.get(&credit.sponsor_id).ok_or_else(|| {
                format!(
                    "sponsor credit {} references missing sponsor",
                    credit.credit_id
                )
            })?;
            if provider.role != RecoveryProviderRole::Sponsor {
                return Err(format!(
                    "sponsor credit {} references provider without sponsor role",
                    credit.credit_id
                ));
            }
        }

        for (receipt_id, receipt) in &self.audit_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err(format!(
                    "receipt map key mismatch for {}",
                    receipt.receipt_id
                ));
            }
            receipt.validate()?;
            if !self.providers.contains_key(&receipt.provider_id) {
                return Err(format!(
                    "receipt {} references missing provider",
                    receipt.receipt_id
                ));
            }
        }

        for (evidence_id, evidence) in &self.slashing_evidence {
            if evidence_id != &evidence.evidence_id {
                return Err(format!(
                    "slashing map key mismatch for {}",
                    evidence.evidence_id
                ));
            }
            evidence.validate()?;
            if !self.providers.contains_key(&evidence.accused_provider_id) {
                return Err(format!(
                    "slashing evidence {} references missing provider",
                    evidence.evidence_id
                ));
            }
        }

        for (safety_id, safety) in &self.safety_metadata {
            if safety_id != &safety.safety_id {
                return Err(format!(
                    "safety metadata map key mismatch for {}",
                    safety.safety_id
                ));
            }
            safety.validate()?;
            if !self.profiles.contains_key(&safety.profile_id) {
                return Err(format!(
                    "safety metadata {} references missing profile",
                    safety.safety_id
                ));
            }
        }

        Ok(())
    }
}
