use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroExitPrivacyFeeSponsorshipVaultResult<T> = Result<T, String>;

pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION: &str =
    "nebula-monero-exit-privacy-fee-sponsorship-vault-v1";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_SCHEMA_VERSION: u64 = 1;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_HEIGHT: u64 = 384;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_SPONSORS: usize = 512;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_GRANTS: usize = 32768;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_RECEIPTS: usize = 65536;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_BATCHES: usize = 4096;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_ATTESTATIONS: usize = 65536;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_CREDENTIALS: usize = 16384;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_COOLDOWNS: usize = 32768;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 8;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_GRANT_TTL_BLOCKS: u64 = 96;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 12;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_COOLDOWN_BLOCKS: u64 = 48;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_BATCH_FEE_PICONERO: u64 = 2500000;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_GRANT_FEE_PICONERO: u64 = 500000;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10500;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8000;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_SPONSOR_DAILY_CAP_PICONERO: u64 =
    250000000;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_VAULT_RESERVE_CAP_PICONERO: u64 =
    10000000000;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_VIEW_TAG_BUCKETS: u64 = 256;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_MAX_BPS: u64 = 10000;
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PQ_AUTHORIZATION_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_STEALTH_SPONSORSHIP_SCHEME: &str =
    "monero-stealth-address-sponsored-exit-v1";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_VIEW_TAG_RECEIPT_SCHEME: &str =
    "view-tag-safe-delayed-receipt-v1";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_BATCHING_SCHEME: &str =
    "low-fee-anonymity-set-batched-exit-v1";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_RESERVE_CAP_SCHEME: &str =
    "sponsor-reserve-cap-and-coverage-v1";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_SETTLEMENT_ATTESTATION_SCHEME: &str =
    "monero-exit-settlement-attestation-v1";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_EXIT_ASSET_ID: &str = "xmr-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitGrantKind {
    WalletExit,
    DefiWithdrawal,
    TokenRedemption,
    SmartContractPayout,
    LiquidityMigration,
    EmergencyEscape,
    RecoveryPayout,
    MarketMakerRebalance,
}
impl ExitGrantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletExit => "wallet_exit",
            Self::DefiWithdrawal => "defi_withdrawal",
            Self::TokenRedemption => "token_redemption",
            Self::SmartContractPayout => "smart_contract_payout",
            Self::LiquidityMigration => "liquidity_migration",
            Self::EmergencyEscape => "emergency_escape",
            Self::RecoveryPayout => "recovery_payout",
            Self::MarketMakerRebalance => "market_maker_rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Requested,
    Reserved,
    CredentialBound,
    Batched,
    Settled,
    Expired,
    Cancelled,
    Challenged,
}
impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Reserved => "reserved",
            Self::CredentialBound => "credential_bound",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Requested
                | Self::Reserved
                | Self::CredentialBound
                | Self::Batched
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Throttled,
    Paused,
    Exhausted,
    Slashed,
    Retired,
}
impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Submitted,
    Attested,
    Finalized,
    Disputed,
    Expired,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
    pub fn accepts_grants(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    HybridMlDsaSlhDsa,
    CommitteeThreshold,
}
impl CredentialScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa65",
            Self::MlDsa87 => "ml_dsa87",
            Self::SlhDsaShake128s => "slh_dsa_shake128s",
            Self::HybridMlDsaSlhDsa => "hybrid_ml_dsa_slh_dsa",
            Self::CommitteeThreshold => "committee_threshold",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptReleasePolicy {
    ImmediateHashOnly,
    DelayedViewTagSafe,
    AuditorEscrowed,
    ThresholdDisclosure,
}
impl ReceiptReleasePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImmediateHashOnly => "immediate_hash_only",
            Self::DelayedViewTagSafe => "delayed_view_tag_safe",
            Self::AuditorEscrowed => "auditor_escrowed",
            Self::ThresholdDisclosure => "threshold_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAttestationKind {
    MoneroTxObserved,
    ReserveDebited,
    FeePaid,
    BatchFinalized,
    ReceiptReleased,
    DisputeCleared,
}
impl SettlementAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroTxObserved => "monero_tx_observed",
            Self::ReserveDebited => "reserve_debited",
            Self::FeePaid => "fee_paid",
            Self::BatchFinalized => "batch_finalized",
            Self::ReceiptReleased => "receipt_released",
            Self::DisputeCleared => "dispute_cleared",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRiskLevel {
    Low,
    Medium,
    Elevated,
    Critical,
}
impl PrivacyRiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub exit_asset_id: String,
    pub max_sponsors: usize,
    pub max_grants: usize,
    pub max_receipts: usize,
    pub max_batches: usize,
    pub max_attestations: usize,
    pub max_credentials: usize,
    pub max_cooldowns: usize,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub batch_window_blocks: u64,
    pub grant_ttl_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub anti_linkability_cooldown_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_batch_fee_piconero: u64,
    pub max_grant_fee_piconero: u64,
    pub min_reserve_coverage_bps: u64,
    pub low_fee_target_bps: u64,
    pub sponsor_daily_cap_piconero: u64,
    pub vault_reserve_cap_piconero: u64,
    pub view_tag_buckets: u64,
    pub require_pq_authorization: bool,
    pub require_view_tag_safe_receipts: bool,
    pub require_stealth_address_commitments: bool,
    pub allow_defi_and_token_exits: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub operator_commitment: String,
    pub status: SponsorStatus,
    pub reserve_commitment: String,
    pub reserve_balance_piconero: u64,
    pub reserved_piconero: u64,
    pub daily_cap_piconero: u64,
    pub daily_used_piconero: u64,
    pub min_privacy_score_bps: u64,
    pub credential_root: String,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub last_rotation_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExitGrant {
    pub grant_id: String,
    pub kind: ExitGrantKind,
    pub status: GrantStatus,
    pub recipient_commitment: String,
    pub stealth_address_commitment: String,
    pub view_tag_bucket: u64,
    pub amount_commitment: String,
    pub fee_cap_piconero: u64,
    pub reserved_fee_piconero: u64,
    pub sponsor_id: String,
    pub credential_id: String,
    pub request_nullifier: String,
    pub anti_linkability_set_id: String,
    pub privacy_score_bps: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub batch_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorizationCredential {
    pub credential_id: String,
    pub scheme: CredentialScheme,
    pub subject_commitment: String,
    pub sponsor_id: String,
    pub capability_root: String,
    pub nullifier_root: String,
    pub signature_commitment: String,
    pub kem_ciphertext_commitment: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub max_fee_piconero: u64,
    pub spend_limit_piconero: u64,
    pub spent_piconero: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagSafeReceipt {
    pub receipt_id: String,
    pub grant_id: String,
    pub batch_id: String,
    pub view_tag_bucket: u64,
    pub delayed_release_height: u64,
    pub receipt_commitment: String,
    pub redacted_payment_id: String,
    pub stealth_address_receipt_root: String,
    pub fee_paid_piconero: u64,
    pub privacy_risk: PrivacyRiskLevel,
    pub released: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settled_at_height: u64,
    pub fee_asset_id: String,
    pub grant_root: String,
    pub receipt_root: String,
    pub total_reserved_fee_piconero: u64,
    pub total_paid_fee_piconero: u64,
    pub target_ring_size: u64,
    pub anonymity_set_root: String,
    pub fee_quote_root: String,
    pub settlement_tx_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveCap {
    pub cap_id: String,
    pub sponsor_id: String,
    pub reserve_balance_piconero: u64,
    pub reserved_piconero: u64,
    pub daily_cap_piconero: u64,
    pub daily_used_piconero: u64,
    pub vault_cap_piconero: u64,
    pub coverage_bps: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CooldownEntry {
    pub cooldown_id: String,
    pub anti_linkability_set_id: String,
    pub subject_commitment: String,
    pub view_tag_bucket: u64,
    pub last_grant_height: u64,
    pub available_at_height: u64,
    pub reason_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAttestation {
    pub attestation_id: String,
    pub kind: SettlementAttestationKind,
    pub batch_id: String,
    pub grant_id: String,
    pub attestor_commitment: String,
    pub settlement_tx_commitment: String,
    pub observed_height: u64,
    pub finality_height: u64,
    pub fee_paid_piconero: u64,
    pub evidence_root: String,
    pub pq_signature_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub sponsor_root: String,
    pub grant_root: String,
    pub credential_root: String,
    pub receipt_root: String,
    pub batch_root: String,
    pub reserve_cap_root: String,
    pub cooldown_root: String,
    pub attestation_root: String,
    pub config_root: String,
    pub counters_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub sponsors: u64,
    pub active_sponsors: u64,
    pub grants: u64,
    pub live_grants: u64,
    pub credentials: u64,
    pub receipts: u64,
    pub batches: u64,
    pub open_batches: u64,
    pub attestations: u64,
    pub cooldowns: u64,
    pub reserved_fee_piconero: u64,
    pub paid_fee_piconero: u64,
    pub available_reserve_piconero: u64,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "Config",
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "exit_asset_id": self.exit_asset_id,
            "max_sponsors": self.max_sponsors,
            "max_grants": self.max_grants,
            "max_receipts": self.max_receipts,
            "max_batches": self.max_batches,
            "max_attestations": self.max_attestations,
            "max_credentials": self.max_credentials,
            "max_cooldowns": self.max_cooldowns,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "batch_window_blocks": self.batch_window_blocks,
            "grant_ttl_blocks": self.grant_ttl_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "anti_linkability_cooldown_blocks": self.anti_linkability_cooldown_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "max_batch_fee_piconero": self.max_batch_fee_piconero,
            "max_grant_fee_piconero": self.max_grant_fee_piconero,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "sponsor_daily_cap_piconero": self.sponsor_daily_cap_piconero,
            "vault_reserve_cap_piconero": self.vault_reserve_cap_piconero,
            "view_tag_buckets": self.view_tag_buckets,
            "require_pq_authorization": self.require_pq_authorization,
            "require_view_tag_safe_receipts": self.require_view_tag_safe_receipts,
            "require_stealth_address_commitments": self.require_stealth_address_commitments,
            "allow_defi_and_token_exits": self.allow_defi_and_token_exits,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl SponsorAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "SponsorAccount",
            "sponsor_id": self.sponsor_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "reserve_balance_piconero": self.reserve_balance_piconero,
            "reserved_piconero": self.reserved_piconero,
            "daily_cap_piconero": self.daily_cap_piconero,
            "daily_used_piconero": self.daily_used_piconero,
            "min_privacy_score_bps": self.min_privacy_score_bps,
            "credential_root": self.credential_root,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "last_rotation_height": self.last_rotation_height,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl PrivateExitGrant {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "PrivateExitGrant",
            "grant_id": self.grant_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "stealth_address_commitment": self.stealth_address_commitment,
            "view_tag_bucket": self.view_tag_bucket,
            "amount_commitment": self.amount_commitment,
            "fee_cap_piconero": self.fee_cap_piconero,
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "sponsor_id": self.sponsor_id,
            "credential_id": self.credential_id,
            "request_nullifier": self.request_nullifier,
            "anti_linkability_set_id": self.anti_linkability_set_id,
            "privacy_score_bps": self.privacy_score_bps,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "batch_id": self.batch_id,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl PqAuthorizationCredential {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "PqAuthorizationCredential",
            "credential_id": self.credential_id,
            "scheme": self.scheme.as_str(),
            "subject_commitment": self.subject_commitment,
            "sponsor_id": self.sponsor_id,
            "capability_root": self.capability_root,
            "nullifier_root": self.nullifier_root,
            "signature_commitment": self.signature_commitment,
            "kem_ciphertext_commitment": self.kem_ciphertext_commitment,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "max_fee_piconero": self.max_fee_piconero,
            "spend_limit_piconero": self.spend_limit_piconero,
            "spent_piconero": self.spent_piconero,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl ViewTagSafeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "ViewTagSafeReceipt",
            "receipt_id": self.receipt_id,
            "grant_id": self.grant_id,
            "batch_id": self.batch_id,
            "view_tag_bucket": self.view_tag_bucket,
            "delayed_release_height": self.delayed_release_height,
            "receipt_commitment": self.receipt_commitment,
            "redacted_payment_id": self.redacted_payment_id,
            "stealth_address_receipt_root": self.stealth_address_receipt_root,
            "fee_paid_piconero": self.fee_paid_piconero,
            "privacy_risk": self.privacy_risk.as_str(),
            "released": self.released,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl LowFeeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "LowFeeBatch",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settled_at_height": self.settled_at_height,
            "fee_asset_id": self.fee_asset_id,
            "grant_root": self.grant_root,
            "receipt_root": self.receipt_root,
            "total_reserved_fee_piconero": self.total_reserved_fee_piconero,
            "total_paid_fee_piconero": self.total_paid_fee_piconero,
            "target_ring_size": self.target_ring_size,
            "anonymity_set_root": self.anonymity_set_root,
            "fee_quote_root": self.fee_quote_root,
            "settlement_tx_commitment": self.settlement_tx_commitment,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl ReserveCap {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "ReserveCap",
            "cap_id": self.cap_id,
            "sponsor_id": self.sponsor_id,
            "reserve_balance_piconero": self.reserve_balance_piconero,
            "reserved_piconero": self.reserved_piconero,
            "daily_cap_piconero": self.daily_cap_piconero,
            "daily_used_piconero": self.daily_used_piconero,
            "vault_cap_piconero": self.vault_cap_piconero,
            "coverage_bps": self.coverage_bps,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl CooldownEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "CooldownEntry",
            "cooldown_id": self.cooldown_id,
            "anti_linkability_set_id": self.anti_linkability_set_id,
            "subject_commitment": self.subject_commitment,
            "view_tag_bucket": self.view_tag_bucket,
            "last_grant_height": self.last_grant_height,
            "available_at_height": self.available_at_height,
            "reason_root": self.reason_root,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl SettlementAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "SettlementAttestation",
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "batch_id": self.batch_id,
            "grant_id": self.grant_id,
            "attestor_commitment": self.attestor_commitment,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "observed_height": self.observed_height,
            "finality_height": self.finality_height,
            "fee_paid_piconero": self.fee_paid_piconero,
            "evidence_root": self.evidence_root,
            "pq_signature_commitment": self.pq_signature_commitment,
        })
    }
    pub fn record_root(&self) -> String {
        vault_hash("RECORD", &[HashPart::Json(&self.public_record())])
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "Roots",
            "sponsor_root": self.sponsor_root,
            "grant_root": self.grant_root,
            "credential_root": self.credential_root,
            "receipt_root": self.receipt_root,
            "batch_root": self.batch_root,
            "reserve_cap_root": self.reserve_cap_root,
            "cooldown_root": self.cooldown_root,
            "attestation_root": self.attestation_root,
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,
            "record_type": "Counters",
            "sponsors": self.sponsors,
            "active_sponsors": self.active_sponsors,
            "grants": self.grants,
            "live_grants": self.live_grants,
            "credentials": self.credentials,
            "receipts": self.receipts,
            "batches": self.batches,
            "open_batches": self.open_batches,
            "attestations": self.attestations,
            "cooldowns": self.cooldowns,
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "paid_fee_piconero": self.paid_fee_piconero,
            "available_reserve_piconero": self.available_reserve_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub sponsors: BTreeMap<String, SponsorAccount>,
    pub grants: BTreeMap<String, PrivateExitGrant>,
    pub credentials: BTreeMap<String, PqAuthorizationCredential>,
    pub receipts: BTreeMap<String, ViewTagSafeReceipt>,
    pub batches: BTreeMap<String, LowFeeBatch>,
    pub reserve_caps: BTreeMap<String, ReserveCap>,
    pub cooldowns: BTreeMap<String, CooldownEntry>,
    pub attestations: BTreeMap<String, SettlementAttestation>,
}

impl State {
    pub fn devnet() -> MoneroExitPrivacyFeeSponsorshipVaultResult<Self> {
        build_devnet_state()
    }
    pub fn validate(&self) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
        self.config.validate()?;
        require_len("sponsors", self.sponsors.len(), self.config.max_sponsors)?;
        require_len("grants", self.grants.len(), self.config.max_grants)?;
        require_len(
            "credentials",
            self.credentials.len(),
            self.config.max_credentials,
        )?;
        require_len("receipts", self.receipts.len(), self.config.max_receipts)?;
        require_len("batches", self.batches.len(), self.config.max_batches)?;
        require_len(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        require_len("cooldowns", self.cooldowns.len(), self.config.max_cooldowns)?;
        let mut nullifiers = BTreeSet::new();
        for sponsor in self.sponsors.values() {
            validate_sponsor(sponsor, &self.config, self.height)?;
        }
        for credential in self.credentials.values() {
            validate_credential(credential, self)?;
        }
        for grant in self.grants.values() {
            validate_grant(grant, self, &mut nullifiers)?;
        }
        for receipt in self.receipts.values() {
            validate_receipt(receipt, self)?;
        }
        for batch in self.batches.values() {
            validate_batch(batch, self)?;
        }
        for cap in self.reserve_caps.values() {
            validate_reserve_cap(cap, self)?;
        }
        for cooldown in self.cooldowns.values() {
            validate_cooldown(cooldown, self)?;
        }
        for attestation in self.attestations.values() {
            validate_attestation(attestation, self)?;
        }
        Ok(())
    }
    pub fn set_height(&mut self, height: u64) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
        self.height = height;
        self.validate()
    }
    pub fn update_height(&mut self, delta: u64) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
        self.height = self.height.saturating_add(delta);
        self.validate()
    }
    pub fn roots(&self) -> Roots {
        let sponsor_root = map_root("SPONSOR", &self.sponsors);
        let grant_root = map_root("GRANT", &self.grants);
        let credential_root = map_root("CREDENTIAL", &self.credentials);
        let receipt_root = map_root("RECEIPT", &self.receipts);
        let batch_root = map_root("BATCH", &self.batches);
        let reserve_cap_root = map_root("RESERVE-CAP", &self.reserve_caps);
        let cooldown_root = map_root("COOLDOWN", &self.cooldowns);
        let attestation_root = map_root("ATTESTATION", &self.attestations);
        let config_root = root_from_record(&self.config.public_record());
        let counters_root = root_from_record(&self.counters().public_record());
        let state_record = json!({"chain_id": CHAIN_ID,"protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,"height": self.height,"sponsor_root": sponsor_root,"grant_root": grant_root,"credential_root": credential_root,"receipt_root": receipt_root,"batch_root": batch_root,"reserve_cap_root": reserve_cap_root,"cooldown_root": cooldown_root,"attestation_root": attestation_root,"config_root": config_root,"counters_root": counters_root});
        let state_root = vault_hash("STATE", &[HashPart::Json(&state_record)]);
        Roots {
            sponsor_root,
            grant_root,
            credential_root,
            receipt_root,
            batch_root,
            reserve_cap_root,
            cooldown_root,
            attestation_root,
            config_root,
            counters_root,
            state_root,
        }
    }
    pub fn counters(&self) -> Counters {
        let active_sponsors = self
            .sponsors
            .values()
            .filter(|s| s.status.can_sponsor())
            .count() as u64;
        let live_grants = self.grants.values().filter(|g| g.status.is_live()).count() as u64;
        let open_batches = self
            .batches
            .values()
            .filter(|b| b.status.accepts_grants())
            .count() as u64;
        let reserved_fee_piconero = self.grants.values().map(|g| g.reserved_fee_piconero).sum();
        let paid_fee_piconero = self.receipts.values().map(|r| r.fee_paid_piconero).sum();
        let total_reserve: u64 = self
            .sponsors
            .values()
            .map(|s| s.reserve_balance_piconero)
            .sum();
        let sponsor_reserved: u64 = self.sponsors.values().map(|s| s.reserved_piconero).sum();
        Counters {
            sponsors: self.sponsors.len() as u64,
            active_sponsors,
            grants: self.grants.len() as u64,
            live_grants,
            credentials: self.credentials.len() as u64,
            receipts: self.receipts.len() as u64,
            batches: self.batches.len() as u64,
            open_batches,
            attestations: self.attestations.len() as u64,
            cooldowns: self.cooldowns.len() as u64,
            reserved_fee_piconero,
            paid_fee_piconero,
            available_reserve_piconero: total_reserve.saturating_sub(sponsor_reserved),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"chain_id": CHAIN_ID,"protocol_version": MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_PROTOCOL_VERSION,"height": self.height,"config": self.config.public_record(),"roots": self.roots().public_record(),"counters": self.counters().public_record()})
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            monero_network: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_FEE_ASSET_ID.to_string(),
            exit_asset_id: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_EXIT_ASSET_ID
                .to_string(),
            max_sponsors: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_SPONSORS,
            max_grants: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_GRANTS,
            max_receipts: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_RECEIPTS,
            max_batches: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_BATCHES,
            max_attestations: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_ATTESTATIONS,
            max_credentials: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_CREDENTIALS,
            max_cooldowns: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_COOLDOWNS,
            min_ring_size: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_TARGET_RING_SIZE,
            batch_window_blocks:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_BATCH_WINDOW_BLOCKS,
            grant_ttl_blocks: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_GRANT_TTL_BLOCKS,
            receipt_delay_blocks:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_RECEIPT_DELAY_BLOCKS,
            anti_linkability_cooldown_blocks:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_COOLDOWN_BLOCKS,
            settlement_finality_blocks:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_batch_fee_piconero:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_BATCH_FEE_PICONERO,
            max_grant_fee_piconero:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MAX_GRANT_FEE_PICONERO,
            min_reserve_coverage_bps:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            low_fee_target_bps:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_LOW_FEE_TARGET_BPS,
            sponsor_daily_cap_piconero:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_SPONSOR_DAILY_CAP_PICONERO,
            vault_reserve_cap_piconero:
                MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_VAULT_RESERVE_CAP_PICONERO,
            view_tag_buckets: MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_VIEW_TAG_BUCKETS,
            require_pq_authorization: true,
            require_view_tag_safe_receipts: true,
            require_stealth_address_commitments: true,
            allow_defi_and_token_exits: true,
        }
    }
    pub fn validate(&self) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("exit_asset_id", &self.exit_asset_id)?;
        require_order(
            "target_ring_size",
            self.target_ring_size,
            self.min_ring_size,
        )?;
        require_non_zero("batch_window_blocks", self.batch_window_blocks)?;
        require_non_zero("grant_ttl_blocks", self.grant_ttl_blocks)?;
        require_non_zero("receipt_delay_blocks", self.receipt_delay_blocks)?;
        require_non_zero(
            "anti_linkability_cooldown_blocks",
            self.anti_linkability_cooldown_blocks,
        )?;
        require_non_zero(
            "settlement_finality_blocks",
            self.settlement_finality_blocks,
        )?;
        require_order(
            "max_batch_fee_piconero",
            self.max_batch_fee_piconero,
            self.max_grant_fee_piconero,
        )?;
        require_bps(
            "min_reserve_coverage_bps",
            self.min_reserve_coverage_bps,
            true,
        )?;
        require_bps("low_fee_target_bps", self.low_fee_target_bps, false)?;
        require_non_zero(
            "sponsor_daily_cap_piconero",
            self.sponsor_daily_cap_piconero,
        )?;
        require_non_zero(
            "vault_reserve_cap_piconero",
            self.vault_reserve_cap_piconero,
        )?;
        require_non_zero("view_tag_buckets", self.view_tag_buckets)?;
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    vault_hash("PUBLIC-RECORD", &[HashPart::Json(record)])
}
pub fn devnet() -> MoneroExitPrivacyFeeSponsorshipVaultResult<State> {
    State::devnet()
}
fn vault_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("MONERO-EXIT-PRIVACY-FEE-SPONSORSHIP-VAULT:{domain}"),
        parts,
        32,
    )
}
fn map_root<T: RecordRoot>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let records = values
        .values()
        .map(|value| Value::String(value.record_root_value()))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-EXIT-PRIVACY-FEE-SPONSORSHIP-VAULT-{domain}"),
        &records,
    )
}
pub trait RecordRoot {
    fn record_root_value(&self) -> String;
}
impl RecordRoot for SponsorAccount {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for PrivateExitGrant {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for PqAuthorizationCredential {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for ViewTagSafeReceipt {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for LowFeeBatch {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for ReserveCap {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for CooldownEntry {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
impl RecordRoot for SettlementAttestation {
    fn record_root_value(&self) -> String {
        self.record_root()
    }
}
fn require_non_empty(name: &str, value: &str) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}
fn require_non_zero(name: &str, value: u64) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    if value == 0 {
        Err(format!("{name} must be non-zero"))
    } else {
        Ok(())
    }
}
fn require_order(
    name: &str,
    value: u64,
    floor: u64,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    if value < floor {
        Err(format!("{name} must be at least {floor}"))
    } else {
        Ok(())
    }
}
fn require_len(
    name: &str,
    value: usize,
    cap: usize,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    if value > cap {
        Err(format!("{name} length {value} exceeds cap {cap}"))
    } else {
        Ok(())
    }
}
fn require_bps(
    name: &str,
    value: u64,
    allow_over: bool,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    let cap = if allow_over {
        20_000
    } else {
        MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_MAX_BPS
    };
    if value > cap {
        Err(format!("{name} exceeds basis point cap {cap}"))
    } else {
        Ok(())
    }
}

fn validate_sponsor(
    sponsor: &SponsorAccount,
    config: &Config,
    height: u64,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("sponsor_id", &sponsor.sponsor_id)?;
    require_non_empty("operator_commitment", &sponsor.operator_commitment)?;
    require_non_empty("reserve_commitment", &sponsor.reserve_commitment)?;
    require_non_empty("credential_root", &sponsor.credential_root)?;
    require_non_empty("policy_root", &sponsor.policy_root)?;
    if sponsor.reserved_piconero > sponsor.reserve_balance_piconero {
        return Err(format!(
            "sponsor {} reserved fee exceeds reserve",
            sponsor.sponsor_id
        ));
    }
    if sponsor.reserve_balance_piconero > config.vault_reserve_cap_piconero {
        return Err(format!(
            "sponsor {} exceeds vault reserve cap",
            sponsor.sponsor_id
        ));
    }
    if sponsor.daily_cap_piconero > config.sponsor_daily_cap_piconero {
        return Err(format!("sponsor {} exceeds daily cap", sponsor.sponsor_id));
    }
    if sponsor.daily_used_piconero > sponsor.daily_cap_piconero {
        return Err(format!(
            "sponsor {} daily usage exceeds cap",
            sponsor.sponsor_id
        ));
    }
    require_bps(
        "min_privacy_score_bps",
        sponsor.min_privacy_score_bps,
        false,
    )?;
    if sponsor.opened_at_height > height {
        return Err(format!(
            "sponsor {} opens in the future",
            sponsor.sponsor_id
        ));
    }
    if sponsor.last_rotation_height < sponsor.opened_at_height {
        return Err(format!(
            "sponsor {} rotation predates opening",
            sponsor.sponsor_id
        ));
    }
    Ok(())
}
fn validate_credential(
    credential: &PqAuthorizationCredential,
    state: &State,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("credential_id", &credential.credential_id)?;
    require_non_empty("subject_commitment", &credential.subject_commitment)?;
    require_non_empty("capability_root", &credential.capability_root)?;
    require_non_empty("nullifier_root", &credential.nullifier_root)?;
    require_non_empty("signature_commitment", &credential.signature_commitment)?;
    require_non_empty(
        "kem_ciphertext_commitment",
        &credential.kem_ciphertext_commitment,
    )?;
    if !state.sponsors.contains_key(&credential.sponsor_id) {
        return Err(format!(
            "credential {} references unknown sponsor",
            credential.credential_id
        ));
    }
    if credential.issued_at_height > credential.expires_at_height {
        return Err(format!(
            "credential {} expires before issue",
            credential.credential_id
        ));
    }
    if credential.max_fee_piconero > state.config.max_grant_fee_piconero {
        return Err(format!(
            "credential {} max fee exceeds config cap",
            credential.credential_id
        ));
    }
    if credential.spent_piconero > credential.spend_limit_piconero {
        return Err(format!(
            "credential {} spent amount exceeds limit",
            credential.credential_id
        ));
    }
    Ok(())
}
fn validate_grant(
    grant: &PrivateExitGrant,
    state: &State,
    nullifiers: &mut BTreeSet<String>,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("grant_id", &grant.grant_id)?;
    require_non_empty("recipient_commitment", &grant.recipient_commitment)?;
    require_non_empty(
        "stealth_address_commitment",
        &grant.stealth_address_commitment,
    )?;
    require_non_empty("amount_commitment", &grant.amount_commitment)?;
    require_non_empty("sponsor_id", &grant.sponsor_id)?;
    require_non_empty("credential_id", &grant.credential_id)?;
    require_non_empty("request_nullifier", &grant.request_nullifier)?;
    require_non_empty("anti_linkability_set_id", &grant.anti_linkability_set_id)?;
    if !nullifiers.insert(grant.request_nullifier.clone()) {
        return Err(format!("grant {} reuses request nullifier", grant.grant_id));
    }
    let sponsor = state
        .sponsors
        .get(&grant.sponsor_id)
        .ok_or_else(|| format!("grant {} references unknown sponsor", grant.grant_id))?;
    if !sponsor.status.can_sponsor() && grant.status.is_live() {
        return Err(format!("grant {} uses unavailable sponsor", grant.grant_id));
    }
    let credential = state
        .credentials
        .get(&grant.credential_id)
        .ok_or_else(|| format!("grant {} references unknown credential", grant.grant_id))?;
    if credential.sponsor_id != grant.sponsor_id {
        return Err(format!(
            "grant {} sponsor and credential mismatch",
            grant.grant_id
        ));
    }
    if state.config.require_stealth_address_commitments
        && grant.stealth_address_commitment.len() < 16
    {
        return Err(format!(
            "grant {} has weak stealth address commitment",
            grant.grant_id
        ));
    }
    if grant.view_tag_bucket >= state.config.view_tag_buckets {
        return Err(format!(
            "grant {} view tag bucket outside range",
            grant.grant_id
        ));
    }
    if grant.fee_cap_piconero > state.config.max_grant_fee_piconero {
        return Err(format!(
            "grant {} fee cap exceeds config cap",
            grant.grant_id
        ));
    }
    if grant.reserved_fee_piconero > grant.fee_cap_piconero {
        return Err(format!("grant {} reserve exceeds fee cap", grant.grant_id));
    }
    if grant.privacy_score_bps < sponsor.min_privacy_score_bps {
        return Err(format!(
            "grant {} does not satisfy sponsor privacy floor",
            grant.grant_id
        ));
    }
    if grant.requested_at_height > grant.expires_at_height {
        return Err(format!("grant {} expires before request", grant.grant_id));
    }
    if grant
        .expires_at_height
        .saturating_sub(grant.requested_at_height)
        > state.config.grant_ttl_blocks
    {
        return Err(format!("grant {} ttl exceeds config", grant.grant_id));
    }
    if !grant.batch_id.is_empty() && !state.batches.contains_key(&grant.batch_id) {
        return Err(format!("grant {} references unknown batch", grant.grant_id));
    }
    Ok(())
}
fn validate_receipt(
    receipt: &ViewTagSafeReceipt,
    state: &State,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("receipt_id", &receipt.receipt_id)?;
    require_non_empty("grant_id", &receipt.grant_id)?;
    require_non_empty("batch_id", &receipt.batch_id)?;
    require_non_empty("receipt_commitment", &receipt.receipt_commitment)?;
    require_non_empty("redacted_payment_id", &receipt.redacted_payment_id)?;
    require_non_empty(
        "stealth_address_receipt_root",
        &receipt.stealth_address_receipt_root,
    )?;
    let grant = state
        .grants
        .get(&receipt.grant_id)
        .ok_or_else(|| format!("receipt {} references unknown grant", receipt.receipt_id))?;
    if receipt.view_tag_bucket != grant.view_tag_bucket {
        return Err(format!(
            "receipt {} leaks inconsistent view tag bucket",
            receipt.receipt_id
        ));
    }
    if !state.batches.contains_key(&receipt.batch_id) {
        return Err(format!(
            "receipt {} references unknown batch",
            receipt.receipt_id
        ));
    }
    if receipt.fee_paid_piconero > grant.fee_cap_piconero {
        return Err(format!(
            "receipt {} fee exceeds grant cap",
            receipt.receipt_id
        ));
    }
    if state.config.require_view_tag_safe_receipts
        && receipt.delayed_release_height
            < grant
                .requested_at_height
                .saturating_add(state.config.receipt_delay_blocks)
    {
        return Err(format!(
            "receipt {} releases before delay",
            receipt.receipt_id
        ));
    }
    Ok(())
}
fn validate_batch(
    batch: &LowFeeBatch,
    state: &State,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("batch_id", &batch.batch_id)?;
    require_non_empty("fee_asset_id", &batch.fee_asset_id)?;
    require_non_empty("grant_root", &batch.grant_root)?;
    require_non_empty("receipt_root", &batch.receipt_root)?;
    require_non_empty("anonymity_set_root", &batch.anonymity_set_root)?;
    require_non_empty("fee_quote_root", &batch.fee_quote_root)?;
    if batch.fee_asset_id != state.config.fee_asset_id {
        return Err(format!("batch {} uses wrong fee asset", batch.batch_id));
    }
    if batch.target_ring_size < state.config.min_ring_size {
        return Err(format!("batch {} target ring below floor", batch.batch_id));
    }
    if batch.total_reserved_fee_piconero > state.config.max_batch_fee_piconero {
        return Err(format!(
            "batch {} reserve exceeds low-fee batch cap",
            batch.batch_id
        ));
    }
    if batch.total_paid_fee_piconero > batch.total_reserved_fee_piconero {
        return Err(format!("batch {} paid fee exceeds reserve", batch.batch_id));
    }
    if batch.sealed_at_height != 0 && batch.sealed_at_height < batch.opened_at_height {
        return Err(format!("batch {} sealed before open", batch.batch_id));
    }
    if batch.settled_at_height != 0 && batch.settled_at_height < batch.sealed_at_height {
        return Err(format!("batch {} settled before seal", batch.batch_id));
    }
    Ok(())
}
fn validate_reserve_cap(
    cap: &ReserveCap,
    state: &State,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("cap_id", &cap.cap_id)?;
    require_non_empty("sponsor_id", &cap.sponsor_id)?;
    if !state.sponsors.contains_key(&cap.sponsor_id) {
        return Err(format!(
            "reserve cap {} references unknown sponsor",
            cap.cap_id
        ));
    }
    if cap.reserved_piconero > cap.reserve_balance_piconero {
        return Err(format!("reserve cap {} is over-reserved", cap.cap_id));
    }
    if cap.vault_cap_piconero > state.config.vault_reserve_cap_piconero {
        return Err(format!("reserve cap {} exceeds vault cap", cap.cap_id));
    }
    if cap.daily_used_piconero > cap.daily_cap_piconero {
        return Err(format!(
            "reserve cap {} daily usage exceeds cap",
            cap.cap_id
        ));
    }
    if cap.coverage_bps < state.config.min_reserve_coverage_bps {
        return Err(format!("reserve cap {} below coverage floor", cap.cap_id));
    }
    if cap.window_start_height > cap.window_end_height {
        return Err(format!("reserve cap {} has inverted window", cap.cap_id));
    }
    Ok(())
}
fn validate_cooldown(
    cooldown: &CooldownEntry,
    state: &State,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("cooldown_id", &cooldown.cooldown_id)?;
    require_non_empty("anti_linkability_set_id", &cooldown.anti_linkability_set_id)?;
    require_non_empty("subject_commitment", &cooldown.subject_commitment)?;
    require_non_empty("reason_root", &cooldown.reason_root)?;
    if cooldown.view_tag_bucket >= state.config.view_tag_buckets {
        return Err(format!(
            "cooldown {} view tag bucket outside range",
            cooldown.cooldown_id
        ));
    }
    if cooldown.available_at_height
        < cooldown
            .last_grant_height
            .saturating_add(state.config.anti_linkability_cooldown_blocks)
    {
        return Err(format!(
            "cooldown {} ends before anti-linkability floor",
            cooldown.cooldown_id
        ));
    }
    Ok(())
}
fn validate_attestation(
    attestation: &SettlementAttestation,
    state: &State,
) -> MoneroExitPrivacyFeeSponsorshipVaultResult<()> {
    require_non_empty("attestation_id", &attestation.attestation_id)?;
    require_non_empty("batch_id", &attestation.batch_id)?;
    require_non_empty("attestor_commitment", &attestation.attestor_commitment)?;
    require_non_empty(
        "settlement_tx_commitment",
        &attestation.settlement_tx_commitment,
    )?;
    require_non_empty("evidence_root", &attestation.evidence_root)?;
    require_non_empty(
        "pq_signature_commitment",
        &attestation.pq_signature_commitment,
    )?;
    if !state.batches.contains_key(&attestation.batch_id) {
        return Err(format!(
            "attestation {} references unknown batch",
            attestation.attestation_id
        ));
    }
    if !attestation.grant_id.is_empty() && !state.grants.contains_key(&attestation.grant_id) {
        return Err(format!(
            "attestation {} references unknown grant",
            attestation.attestation_id
        ));
    }
    if attestation.finality_height
        < attestation
            .observed_height
            .saturating_add(state.config.settlement_finality_blocks)
    {
        return Err(format!(
            "attestation {} finality below configured depth",
            attestation.attestation_id
        ));
    }
    Ok(())
}

fn build_devnet_state() -> MoneroExitPrivacyFeeSponsorshipVaultResult<State> {
    let config = Config::devnet();
    let height = MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEVNET_HEIGHT;
    let mut sponsors = BTreeMap::new();
    let mut credentials = BTreeMap::new();
    let mut grants = BTreeMap::new();
    let mut receipts = BTreeMap::new();
    let mut batches = BTreeMap::new();
    let mut reserve_caps = BTreeMap::new();
    let mut cooldowns = BTreeMap::new();
    let mut attestations = BTreeMap::new();
    for index in 0_u64..8 {
        let sponsor = devnet_sponsor(index, height);
        let sponsor_id = sponsor.sponsor_id.clone();
        let credential = devnet_credential(index, &sponsor_id, height);
        let credential_id = credential.credential_id.clone();
        let cap = devnet_reserve_cap(index, &sponsor_id, height);
        sponsors.insert(sponsor_id.clone(), sponsor);
        credentials.insert(credential_id.clone(), credential);
        reserve_caps.insert(cap.cap_id.clone(), cap);
        for offset in 0_u64..4 {
            let serial = index * 4 + offset;
            let batch_id = devnet_batch_id(serial / 8);
            let grant = devnet_grant(serial, &sponsor_id, &credential_id, &batch_id, height);
            let receipt = devnet_receipt(serial, &grant);
            let cooldown = devnet_cooldown(serial, &grant, height);
            grants.insert(grant.grant_id.clone(), grant.clone());
            receipts.insert(receipt.receipt_id.clone(), receipt);
            cooldowns.insert(cooldown.cooldown_id.clone(), cooldown);
        }
    }
    for batch_index in 0_u64..4 {
        let batch = devnet_batch(batch_index, &config, height);
        let attestation = devnet_attestation(batch_index, &batch, height);
        batches.insert(batch.batch_id.clone(), batch);
        attestations.insert(attestation.attestation_id.clone(), attestation);
    }
    let state = State {
        config,
        height,
        sponsors,
        grants,
        credentials,
        receipts,
        batches,
        reserve_caps,
        cooldowns,
        attestations,
    };
    state.validate()?;
    Ok(state)
}
fn devnet_id(domain: &str, index: u64) -> String {
    vault_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Int(index as i128)],
    )
}
fn devnet_sponsor(index: u64, height: u64) -> SponsorAccount {
    let sponsor_id = devnet_id("DEVNET-SPONSOR", index);
    SponsorAccount {
        sponsor_id: sponsor_id.clone(),
        operator_commitment: vault_hash("DEVNET-SPONSOR-OPERATOR", &[HashPart::Str(&sponsor_id)]),
        status: if index == 7 {
            SponsorStatus::Throttled
        } else {
            SponsorStatus::Active
        },
        reserve_commitment: vault_hash("DEVNET-SPONSOR-RESERVE", &[HashPart::Str(&sponsor_id)]),
        reserve_balance_piconero: 900_000_000 + index * 50_000_000,
        reserved_piconero: 1_000_000 + index * 40_000,
        daily_cap_piconero: 200_000_000,
        daily_used_piconero: 4_000_000 + index * 250_000,
        min_privacy_score_bps: 8_500,
        credential_root: devnet_id("DEVNET-SPONSOR-CREDENTIAL-ROOT", index),
        policy_root: devnet_id("DEVNET-SPONSOR-POLICY", index),
        opened_at_height: height.saturating_sub(240 + index),
        last_rotation_height: height.saturating_sub(24 + index),
    }
}
fn devnet_credential(index: u64, sponsor_id: &str, height: u64) -> PqAuthorizationCredential {
    let credential_id = devnet_id("DEVNET-PQ-CREDENTIAL", index);
    PqAuthorizationCredential {
        credential_id: credential_id.clone(),
        scheme: if index % 2 == 0 {
            CredentialScheme::HybridMlDsaSlhDsa
        } else {
            CredentialScheme::MlDsa65
        },
        subject_commitment: vault_hash(
            "DEVNET-CREDENTIAL-SUBJECT",
            &[HashPart::Str(&credential_id)],
        ),
        sponsor_id: sponsor_id.to_string(),
        capability_root: vault_hash(
            "DEVNET-CREDENTIAL-CAPABILITY",
            &[HashPart::Str(&credential_id)],
        ),
        nullifier_root: vault_hash(
            "DEVNET-CREDENTIAL-NULLIFIER",
            &[HashPart::Str(&credential_id)],
        ),
        signature_commitment: vault_hash(
            "DEVNET-CREDENTIAL-SIGNATURE",
            &[HashPart::Str(&credential_id)],
        ),
        kem_ciphertext_commitment: vault_hash(
            "DEVNET-CREDENTIAL-KEM",
            &[HashPart::Str(&credential_id)],
        ),
        issued_at_height: height.saturating_sub(48),
        expires_at_height: height.saturating_add(192),
        max_fee_piconero: 400_000,
        spend_limit_piconero: 6_000_000,
        spent_piconero: index * 100_000,
    }
}
fn devnet_batch_id(index: u64) -> String {
    devnet_id("DEVNET-LOW-FEE-BATCH", index)
}
fn devnet_grant(
    index: u64,
    sponsor_id: &str,
    credential_id: &str,
    batch_id: &str,
    height: u64,
) -> PrivateExitGrant {
    let grant_id = devnet_id("DEVNET-PRIVATE-EXIT-GRANT", index);
    PrivateExitGrant {
        grant_id: grant_id.clone(),
        kind: match index % 8 {
            0 => ExitGrantKind::WalletExit,
            1 => ExitGrantKind::DefiWithdrawal,
            2 => ExitGrantKind::TokenRedemption,
            3 => ExitGrantKind::SmartContractPayout,
            4 => ExitGrantKind::LiquidityMigration,
            5 => ExitGrantKind::EmergencyEscape,
            6 => ExitGrantKind::RecoveryPayout,
            _ => ExitGrantKind::MarketMakerRebalance,
        },
        status: if index % 3 == 0 {
            GrantStatus::Settled
        } else {
            GrantStatus::Batched
        },
        recipient_commitment: vault_hash("DEVNET-GRANT-RECIPIENT", &[HashPart::Str(&grant_id)]),
        stealth_address_commitment: vault_hash(
            "DEVNET-GRANT-STEALTH-ADDRESS",
            &[HashPart::Str(&grant_id)],
        ),
        view_tag_bucket: index % MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_VIEW_TAG_BUCKETS,
        amount_commitment: vault_hash("DEVNET-GRANT-AMOUNT", &[HashPart::Str(&grant_id)]),
        fee_cap_piconero: 300_000 + (index % 5) * 10_000,
        reserved_fee_piconero: 180_000 + (index % 5) * 5_000,
        sponsor_id: sponsor_id.to_string(),
        credential_id: credential_id.to_string(),
        request_nullifier: vault_hash("DEVNET-GRANT-NULLIFIER", &[HashPart::Str(&grant_id)]),
        anti_linkability_set_id: vault_hash(
            "DEVNET-GRANT-SET",
            &[HashPart::Int((index % 16) as i128)],
        ),
        privacy_score_bps: 9_200 + (index % 4) * 100,
        requested_at_height: height.saturating_sub(20 + index),
        expires_at_height: height.saturating_sub(20 + index).saturating_add(72),
        batch_id: batch_id.to_string(),
    }
}
fn devnet_receipt(index: u64, grant: &PrivateExitGrant) -> ViewTagSafeReceipt {
    let receipt_id = devnet_id("DEVNET-VIEW-TAG-SAFE-RECEIPT", index);
    ViewTagSafeReceipt {
        receipt_id: receipt_id.clone(),
        grant_id: grant.grant_id.clone(),
        batch_id: grant.batch_id.clone(),
        view_tag_bucket: grant.view_tag_bucket,
        delayed_release_height: grant
            .requested_at_height
            .saturating_add(MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_RECEIPT_DELAY_BLOCKS),
        receipt_commitment: vault_hash("DEVNET-RECEIPT-COMMITMENT", &[HashPart::Str(&receipt_id)]),
        redacted_payment_id: vault_hash(
            "DEVNET-RECEIPT-REDACTED-PAYMENT",
            &[HashPart::Str(&receipt_id)],
        ),
        stealth_address_receipt_root: vault_hash(
            "DEVNET-RECEIPT-STEALTH-ROOT",
            &[HashPart::Str(&receipt_id)],
        ),
        fee_paid_piconero: grant.reserved_fee_piconero.saturating_sub(10_000),
        privacy_risk: if index % 11 == 0 {
            PrivacyRiskLevel::Medium
        } else {
            PrivacyRiskLevel::Low
        },
        released: true,
    }
}
fn devnet_batch(index: u64, config: &Config, height: u64) -> LowFeeBatch {
    let batch_id = devnet_batch_id(index);
    let grant_leaves = (0_u64..8)
        .map(|offset| Value::String(devnet_id("DEVNET-PRIVATE-EXIT-GRANT", index * 8 + offset)))
        .collect::<Vec<_>>();
    let receipt_leaves = (0_u64..8)
        .map(|offset| {
            Value::String(devnet_id(
                "DEVNET-VIEW-TAG-SAFE-RECEIPT",
                index * 8 + offset,
            ))
        })
        .collect::<Vec<_>>();
    LowFeeBatch {
        batch_id: batch_id.clone(),
        status: BatchStatus::Attested,
        opened_at_height: height.saturating_sub(36 + index * 4),
        sealed_at_height: height.saturating_sub(32 + index * 4),
        settled_at_height: height.saturating_sub(18 + index * 4),
        fee_asset_id: config.fee_asset_id.clone(),
        grant_root: merkle_root(
            "MONERO-EXIT-PRIVACY-FEE-SPONSORSHIP-VAULT-DEVNET-BATCH-GRANTS",
            &grant_leaves,
        ),
        receipt_root: merkle_root(
            "MONERO-EXIT-PRIVACY-FEE-SPONSORSHIP-VAULT-DEVNET-BATCH-RECEIPTS",
            &receipt_leaves,
        ),
        total_reserved_fee_piconero: 1_520_000,
        total_paid_fee_piconero: 1_440_000,
        target_ring_size: config.target_ring_size,
        anonymity_set_root: vault_hash("DEVNET-BATCH-ANONYMITY", &[HashPart::Str(&batch_id)]),
        fee_quote_root: vault_hash("DEVNET-BATCH-FEE-QUOTE", &[HashPart::Str(&batch_id)]),
        settlement_tx_commitment: vault_hash(
            "DEVNET-BATCH-SETTLEMENT-TX",
            &[HashPart::Str(&batch_id)],
        ),
    }
}
fn devnet_reserve_cap(index: u64, sponsor_id: &str, height: u64) -> ReserveCap {
    let cap_id = devnet_id("DEVNET-RESERVE-CAP", index);
    ReserveCap {
        cap_id,
        sponsor_id: sponsor_id.to_string(),
        reserve_balance_piconero: 900_000_000 + index * 50_000_000,
        reserved_piconero: 1_000_000 + index * 40_000,
        daily_cap_piconero: 200_000_000,
        daily_used_piconero: 4_000_000 + index * 250_000,
        vault_cap_piconero:
            MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_VAULT_RESERVE_CAP_PICONERO,
        coverage_bps: 11_200,
        window_start_height: height.saturating_sub(96),
        window_end_height: height.saturating_add(96),
    }
}
fn devnet_cooldown(index: u64, grant: &PrivateExitGrant, height: u64) -> CooldownEntry {
    let cooldown_id = devnet_id("DEVNET-COOLDOWN", index);
    CooldownEntry {
        cooldown_id,
        anti_linkability_set_id: grant.anti_linkability_set_id.clone(),
        subject_commitment: grant.recipient_commitment.clone(),
        view_tag_bucket: grant.view_tag_bucket,
        last_grant_height: height.saturating_sub(20 + index),
        available_at_height: height
            .saturating_sub(20 + index)
            .saturating_add(MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_COOLDOWN_BLOCKS),
        reason_root: vault_hash("DEVNET-COOLDOWN-REASON", &[HashPart::Str(&grant.grant_id)]),
    }
}
fn devnet_attestation(index: u64, batch: &LowFeeBatch, height: u64) -> SettlementAttestation {
    let attestation_id = devnet_id("DEVNET-SETTLEMENT-ATTESTATION", index);
    SettlementAttestation {
        attestation_id: attestation_id.clone(),
        kind: SettlementAttestationKind::BatchFinalized,
        batch_id: batch.batch_id.clone(),
        grant_id: String::new(),
        attestor_commitment: vault_hash("DEVNET-ATTESTOR", &[HashPart::Str(&attestation_id)]),
        settlement_tx_commitment: batch.settlement_tx_commitment.clone(),
        observed_height: height.saturating_sub(18 + index * 4),
        finality_height: height.saturating_sub(18 + index * 4).saturating_add(
            MONERO_EXIT_PRIVACY_FEE_SPONSORSHIP_VAULT_DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
        ),
        fee_paid_piconero: batch.total_paid_fee_piconero,
        evidence_root: vault_hash(
            "DEVNET-ATTESTATION-EVIDENCE",
            &[HashPart::Str(&attestation_id)],
        ),
        pq_signature_commitment: vault_hash(
            "DEVNET-ATTESTATION-PQ-SIGNATURE",
            &[HashPart::Str(&attestation_id)],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn devnet_state_validates_and_roots_are_stable() {
        let state = match devnet() {
            Ok(state) => state,
            Err(error) => {
                assert!(false, "devnet failed: {error}");
                return;
            }
        };
        assert!(state.validate().is_ok());
        assert_eq!(state.state_root(), state.state_root());
        assert_eq!(state.counters().sponsors, 8);
    }
    #[test]
    fn record_roots_change_with_content() {
        let one = json!({"a": 1, "b": 2});
        let two = json!({"a": 1, "b": 3});
        assert_ne!(root_from_record(&one), root_from_record(&two));
    }
}
