use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialRebateVaultRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialRebateVaultRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-rebate-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REBATE_VAULT_SUITE: &str = "confidential-low-fee-rebate-vault-commitment-v1";
pub const SPONSOR_DEPOSIT_SUITE: &str = "pq-sponsored-private-l2-fee-liquidity-deposit-attested-v1";
pub const FEE_COUPON_NOTE_SUITE: &str = "confidential-fee-coupon-note-nullifier-v1";
pub const USAGE_RECEIPT_SUITE: &str = "private-l2-low-fee-usage-receipt-redacted-v1";
pub const PQ_SPONSOR_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-sponsor-attestation-v1";
pub const WITHDRAWAL_WINDOW_SUITE: &str = "confidential-rebate-vault-withdrawal-window-v1";
pub const OVERSPEND_QUARANTINE_SUITE: &str = "confidential-fee-coupon-overspend-quarantine-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str = "selective-disclosure-privacy-redaction-budget-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "xmr-rebate-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 1_482_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_750;
pub const DEFAULT_DEPOSIT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_USAGE_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_WITHDRAWAL_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 4_320;
pub const DEFAULT_REBATE_EXPIRY_BLOCKS: u64 = 10_080;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 64;
pub const MAX_REBATE_VAULTS: usize = 262_144;
pub const MAX_SPONSOR_DEPOSITS: usize = 2_097_152;
pub const MAX_FEE_COUPON_NOTES: usize = 4_194_304;
pub const MAX_USAGE_RECEIPTS: usize = 4_194_304;
pub const MAX_PQ_SPONSOR_ATTESTATIONS: usize = 4_194_304;
pub const MAX_WITHDRAWAL_WINDOWS: usize = 1_048_576;
pub const MAX_OVERSPEND_QUARANTINES: usize = 1_048_576;
pub const MAX_REBATE_EXPIRIES: usize = 2_097_152;
pub const MAX_PRIVACY_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_NULLIFIERS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    MoneroPrivateL2,
    WalletSponsored,
    BridgeRelayer,
}

impl VaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroPrivateL2 => "monero_private_l2",
            Self::WalletSponsored => "wallet_sponsored",
            Self::BridgeRelayer => "bridge_relayer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Attested,
    Active,
    WithdrawalOnly,
    Quarantined,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::WithdrawalOnly => "withdrawal_only",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_usage(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }

    pub fn permits_withdrawal(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::Active | Self::WithdrawalOnly | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorTier {
    Devnet,
    Wallet,
}

impl SponsorTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Wallet => "wallet",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositStatus {
    Pending,
    Attested,
    Active,
    Quarantined,
}

impl DepositStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Attested,
    Redeemed,
    Expired,
    Quarantined,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Attested => "attested",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn redeemable(self) -> bool {
        matches!(self, Self::Minted | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageLane {
    WalletTransfer,
    MerchantPayment,
    BridgeWithdraw,
}

impl UsageLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MerchantPayment => "merchant_payment",
            Self::BridgeWithdraw => "bridge_withdraw",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::WalletTransfer | Self::MerchantPayment => config.target_user_fee_bps,
            Self::BridgeWithdraw => config.target_user_fee_bps + 2,
        }
        .min(config.max_user_fee_bps)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Allow,
    Quarantine,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn permits_activation(self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalWindowStatus {
    Scheduled,
    Open,
    Closed,
    Executed,
    Expired,
}

impl WithdrawalWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Executed => "executed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    CouponOverspend,
    SponsorLimitExceeded,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CouponOverspend => "coupon_overspend",
            Self::SponsorLimitExceeded => "sponsor_limit_exceeded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub deposit_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub usage_receipt_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub withdrawal_window_blocks: u64,
    pub quarantine_blocks: u64,
    pub rebate_expiry_blocks: u64,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub redaction_budget_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            deposit_ttl_blocks: DEFAULT_DEPOSIT_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            usage_receipt_ttl_blocks: DEFAULT_USAGE_RECEIPT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            withdrawal_window_blocks: DEFAULT_WITHDRAWAL_WINDOW_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            rebate_expiry_blocks: DEFAULT_REBATE_EXPIRY_BLOCKS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("rebate_asset_id", &self.rebate_asset_id)?;
        ensure_bps("target_user_fee_bps", self.target_user_fee_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target_user_fee_bps must be <= max_user_fee_bps".to_string());
        }
        if self.min_privacy_set == 0 || self.target_privacy_set < self.min_privacy_set {
            return Err("target_privacy_set must be >= min_privacy_set".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_rebate_vault_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "deposit_ttl_blocks": self.deposit_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "usage_receipt_ttl_blocks": self.usage_receipt_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "withdrawal_window_blocks": self.withdrawal_window_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "rebate_expiry_blocks": self.rebate_expiry_blocks,
            "min_privacy_set": self.min_privacy_set,
            "target_privacy_set": self.target_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "redaction_budget_units": self.redaction_budget_units,
            "hash_suite": HASH_SUITE,
            "rebate_vault_suite": REBATE_VAULT_SUITE,
            "sponsor_deposit_suite": SPONSOR_DEPOSIT_SUITE,
            "fee_coupon_note_suite": FEE_COUPON_NOTE_SUITE,
            "usage_receipt_suite": USAGE_RECEIPT_SUITE,
            "pq_sponsor_attestation_suite": PQ_SPONSOR_ATTESTATION_SUITE,
            "withdrawal_window_suite": WITHDRAWAL_WINDOW_SUITE,
            "overspend_quarantine_suite": OVERSPEND_QUARANTINE_SUITE,
            "privacy_redaction_budget_suite": PRIVACY_REDACTION_BUDGET_SUITE,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub rebate_vaults: u64,
    pub sponsor_deposits: u64,
    pub fee_coupon_notes: u64,
    pub usage_receipts: u64,
    pub pq_sponsor_attestations: u64,
    pub withdrawal_windows: u64,
    pub overspend_quarantines: u64,
    pub rebate_expiries: u64,
    pub privacy_redaction_budgets: u64,
    pub nullifiers: u64,
    pub public_records: u64,
    pub total_deposited_amount: u128,
    pub available_sponsor_amount: u128,
    pub coupon_face_amount: u128,
    pub redeemed_coupon_amount: u128,
    pub usage_fee_amount: u128,
    pub rebate_amount: u128,
    pub quarantined_amount: u128,
    pub expired_rebate_amount: u128,
    pub redaction_budget_units: u64,
    pub redaction_budget_spent: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_rebate_vault_counters",
            "rebate_vaults": self.rebate_vaults,
            "sponsor_deposits": self.sponsor_deposits,
            "fee_coupon_notes": self.fee_coupon_notes,
            "usage_receipts": self.usage_receipts,
            "pq_sponsor_attestations": self.pq_sponsor_attestations,
            "withdrawal_windows": self.withdrawal_windows,
            "overspend_quarantines": self.overspend_quarantines,
            "rebate_expiries": self.rebate_expiries,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "nullifiers": self.nullifiers,
            "public_records": self.public_records,
            "total_deposited_amount": self.total_deposited_amount.to_string(),
            "available_sponsor_amount": self.available_sponsor_amount.to_string(),
            "coupon_face_amount": self.coupon_face_amount.to_string(),
            "redeemed_coupon_amount": self.redeemed_coupon_amount.to_string(),
            "usage_fee_amount": self.usage_fee_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "quarantined_amount": self.quarantined_amount.to_string(),
            "expired_rebate_amount": self.expired_rebate_amount.to_string(),
            "redaction_budget_units": self.redaction_budget_units,
            "redaction_budget_spent": self.redaction_budget_spent,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub rebate_vault_root: String,
    pub sponsor_deposit_root: String,
    pub fee_coupon_note_root: String,
    pub usage_receipt_root: String,
    pub pq_sponsor_attestation_root: String,
    pub withdrawal_window_root: String,
    pub overspend_quarantine_root: String,
    pub rebate_expiry_root: String,
    pub privacy_redaction_budget_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_rebate_vault_roots",
            "rebate_vault_root": self.rebate_vault_root,
            "sponsor_deposit_root": self.sponsor_deposit_root,
            "fee_coupon_note_root": self.fee_coupon_note_root,
            "usage_receipt_root": self.usage_receipt_root,
            "pq_sponsor_attestation_root": self.pq_sponsor_attestation_root,
            "withdrawal_window_root": self.withdrawal_window_root,
            "overspend_quarantine_root": self.overspend_quarantine_root,
            "rebate_expiry_root": self.rebate_expiry_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateVaultRequest {
    pub operator_id: String,
    pub vault_label: String,
    pub vault_kind: VaultKind,
    pub sponsor_set_root: String,
    pub coupon_policy_root: String,
    pub withdrawal_policy_root: String,
    pub max_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_privacy_set: u64,
}

impl RebateVaultRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("operator_id", &self.operator_id)?;
        ensure_nonempty("vault_label", &self.vault_label)?;
        ensure_hash_like("sponsor_set_root", &self.sponsor_set_root)?;
        ensure_hash_like("coupon_policy_root", &self.coupon_policy_root)?;
        ensure_hash_like("withdrawal_policy_root", &self.withdrawal_policy_root)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("vault max_fee_bps exceeds config max_user_fee_bps".to_string());
        }
        if self.min_privacy_set < config.min_privacy_set {
            return Err("vault min_privacy_set below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "vault_label": self.vault_label,
            "vault_kind": self.vault_kind.as_str(),
            "sponsor_set_root": self.sponsor_set_root,
            "coupon_policy_root": self.coupon_policy_root,
            "withdrawal_policy_root": self.withdrawal_policy_root,
            "max_fee_bps": self.max_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "min_privacy_set": self.min_privacy_set,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateVaultRecord {
    pub vault_id: String,
    pub request: RebateVaultRequest,
    pub status: VaultStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl RebateVaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_vault",
            "vault_id": self.vault_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorDepositRequest {
    pub sponsor_id: String,
    pub vault_id: String,
    pub sponsor_tier: SponsorTier,
    pub deposit_commitment: String,
    pub deposit_amount: u128,
    pub available_amount: u128,
    pub max_coupon_face_amount: u128,
    pub sponsor_policy_root: String,
    pub expires_height: u64,
}

impl SponsorDepositRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_hash_like("deposit_commitment", &self.deposit_commitment)?;
        ensure_hash_like("sponsor_policy_root", &self.sponsor_policy_root)?;
        if self.deposit_amount == 0 {
            return Err("deposit_amount must be positive".to_string());
        }
        if self.available_amount > self.deposit_amount {
            return Err("available_amount must be <= deposit_amount".to_string());
        }
        if self.max_coupon_face_amount == 0 {
            return Err("max_coupon_face_amount must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "vault_id": self.vault_id,
            "sponsor_tier": self.sponsor_tier.as_str(),
            "deposit_commitment": self.deposit_commitment,
            "deposit_amount": self.deposit_amount.to_string(),
            "available_amount": self.available_amount.to_string(),
            "max_coupon_face_amount": self.max_coupon_face_amount.to_string(),
            "sponsor_policy_root": self.sponsor_policy_root,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorDepositRecord {
    pub deposit_id: String,
    pub request: SponsorDepositRequest,
    pub status: DepositStatus,
    pub reserved_amount: u128,
    pub spent_amount: u128,
    pub created_height: u64,
    pub updated_height: u64,
}

impl SponsorDepositRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_deposit",
            "deposit_id": self.deposit_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reserved_amount": self.reserved_amount.to_string(),
            "spent_amount": self.spent_amount.to_string(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCouponNoteRequest {
    pub vault_id: String,
    pub sponsor_deposit_id: String,
    pub recipient_commitment: String,
    pub note_commitment: String,
    pub nullifier_hash: String,
    pub face_amount: u128,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub expires_height: u64,
}

impl FeeCouponNoteRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("sponsor_deposit_id", &self.sponsor_deposit_id)?;
        ensure_hash_like("recipient_commitment", &self.recipient_commitment)?;
        ensure_hash_like("note_commitment", &self.note_commitment)?;
        ensure_hash_like("nullifier_hash", &self.nullifier_hash)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        if self.face_amount == 0 {
            return Err("face_amount must be positive".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("coupon max_fee_bps exceeds runtime maximum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("privacy_set_size below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_deposit_id": self.sponsor_deposit_id,
            "recipient_commitment": self.recipient_commitment,
            "note_commitment": self.note_commitment,
            "nullifier_hash": self.nullifier_hash,
            "face_amount": self.face_amount.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCouponNoteRecord {
    pub coupon_id: String,
    pub request: FeeCouponNoteRequest,
    pub status: CouponStatus,
    pub redeemed_amount: u128,
    pub created_height: u64,
    pub updated_height: u64,
}

impl FeeCouponNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_coupon_note",
            "coupon_id": self.coupon_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "redeemed_amount": self.redeemed_amount.to_string(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageReceiptRequest {
    pub vault_id: String,
    pub coupon_id: String,
    pub usage_lane: UsageLane,
    pub tx_commitment: String,
    pub fee_commitment: String,
    pub receipt_nullifier: String,
    pub gross_amount: u128,
    pub fee_amount: u128,
    pub rebate_amount: u128,
    pub redaction_budget_cost: u64,
    pub privacy_set_size: u64,
}

impl UsageReceiptRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("coupon_id", &self.coupon_id)?;
        ensure_hash_like("tx_commitment", &self.tx_commitment)?;
        ensure_hash_like("fee_commitment", &self.fee_commitment)?;
        ensure_hash_like("receipt_nullifier", &self.receipt_nullifier)?;
        if self.gross_amount == 0 {
            return Err("gross_amount must be positive".to_string());
        }
        if self.fee_amount == 0 {
            return Err("fee_amount must be positive".to_string());
        }
        if self.rebate_amount > self.fee_amount {
            return Err("rebate_amount must be <= fee_amount".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("usage privacy_set_size below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "coupon_id": self.coupon_id,
            "usage_lane": self.usage_lane.as_str(),
            "tx_commitment": self.tx_commitment,
            "fee_commitment": self.fee_commitment,
            "receipt_nullifier": self.receipt_nullifier,
            "gross_amount": self.gross_amount.to_string(),
            "fee_amount": self.fee_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "redaction_budget_cost": self.redaction_budget_cost,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageReceiptRecord {
    pub receipt_id: String,
    pub request: UsageReceiptRequest,
    pub created_height: u64,
    pub expires_height: u64,
}

impl UsageReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "usage_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorAttestationRequest {
    pub sponsor_id: String,
    pub vault_id: String,
    pub sponsor_deposit_id: String,
    pub attester_id: String,
    pub verdict: AttestationVerdict,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub disclosure_root: String,
    pub pq_security_bits: u16,
    pub expires_height: u64,
}

impl PqSponsorAttestationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("sponsor_deposit_id", &self.sponsor_deposit_id)?;
        ensure_nonempty("attester_id", &self.attester_id)?;
        ensure_hash_like("public_key_commitment", &self.public_key_commitment)?;
        ensure_hash_like("signature_commitment", &self.signature_commitment)?;
        ensure_hash_like("disclosure_root", &self.disclosure_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "vault_id": self.vault_id,
            "sponsor_deposit_id": self.sponsor_deposit_id,
            "attester_id": self.attester_id,
            "verdict": self.verdict.as_str(),
            "public_key_commitment": self.public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "disclosure_root": self.disclosure_root,
            "pq_security_bits": self.pq_security_bits,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorAttestationRecord {
    pub attestation_id: String,
    pub request: PqSponsorAttestationRequest,
    pub created_height: u64,
}

impl PqSponsorAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sponsor_attestation",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalWindowRequest {
    pub vault_id: String,
    pub sponsor_deposit_id: String,
    pub window_label: String,
    pub withdrawal_commitment: String,
    pub max_withdrawal_amount: u128,
    pub opens_height: u64,
    pub closes_height: u64,
}

impl WithdrawalWindowRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("sponsor_deposit_id", &self.sponsor_deposit_id)?;
        ensure_nonempty("window_label", &self.window_label)?;
        ensure_hash_like("withdrawal_commitment", &self.withdrawal_commitment)?;
        if self.max_withdrawal_amount == 0 {
            return Err("max_withdrawal_amount must be positive".to_string());
        }
        if self.closes_height <= self.opens_height {
            return Err("closes_height must be greater than opens_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_deposit_id": self.sponsor_deposit_id,
            "window_label": self.window_label,
            "withdrawal_commitment": self.withdrawal_commitment,
            "max_withdrawal_amount": self.max_withdrawal_amount.to_string(),
            "opens_height": self.opens_height,
            "closes_height": self.closes_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalWindowRecord {
    pub window_id: String,
    pub request: WithdrawalWindowRequest,
    pub status: WithdrawalWindowStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl WithdrawalWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "withdrawal_window",
            "window_id": self.window_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OverspendQuarantineRequest {
    pub vault_id: String,
    pub coupon_id: String,
    pub sponsor_deposit_id: String,
    pub reason: QuarantineReason,
    pub observed_spend_amount: u128,
    pub allowed_spend_amount: u128,
    pub evidence_root: String,
    pub release_height: u64,
}

impl OverspendQuarantineRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("coupon_id", &self.coupon_id)?;
        ensure_nonempty("sponsor_deposit_id", &self.sponsor_deposit_id)?;
        ensure_hash_like("evidence_root", &self.evidence_root)?;
        if self.observed_spend_amount <= self.allowed_spend_amount {
            return Err("observed_spend_amount must exceed allowed_spend_amount".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "coupon_id": self.coupon_id,
            "sponsor_deposit_id": self.sponsor_deposit_id,
            "reason": self.reason.as_str(),
            "observed_spend_amount": self.observed_spend_amount.to_string(),
            "allowed_spend_amount": self.allowed_spend_amount.to_string(),
            "evidence_root": self.evidence_root,
            "release_height": self.release_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OverspendQuarantineRecord {
    pub quarantine_id: String,
    pub request: OverspendQuarantineRequest,
    pub created_height: u64,
}

impl OverspendQuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "overspend_quarantine",
            "quarantine_id": self.quarantine_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateExpiryRecord {
    pub expiry_id: String,
    pub vault_id: String,
    pub coupon_id: String,
    pub expired_amount: u128,
    pub expiry_height: u64,
    pub note_commitment: String,
}

impl RebateExpiryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_expiry",
            "expiry_id": self.expiry_id,
            "vault_id": self.vault_id,
            "coupon_id": self.coupon_id,
            "expired_amount": self.expired_amount.to_string(),
            "expiry_height": self.expiry_height,
            "note_commitment": self.note_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub budget_id: String,
    pub vault_id: String,
    pub subject_commitment: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub disclosure_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl PrivacyRedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_redaction_budget",
            "budget_id": self.budget_id,
            "vault_id": self.vault_id,
            "subject_commitment": self.subject_commitment,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "disclosure_root": self.disclosure_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRuntimeRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload: Value,
}

impl PublicRuntimeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_rebate_vault_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub rebate_vaults: BTreeMap<String, RebateVaultRecord>,
    pub sponsor_deposits: BTreeMap<String, SponsorDepositRecord>,
    pub fee_coupon_notes: BTreeMap<String, FeeCouponNoteRecord>,
    pub usage_receipts: BTreeMap<String, UsageReceiptRecord>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestationRecord>,
    pub withdrawal_windows: BTreeMap<String, WithdrawalWindowRecord>,
    pub overspend_quarantines: BTreeMap<String, OverspendQuarantineRecord>,
    pub rebate_expiries: BTreeMap<String, RebateExpiryRecord>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRuntimeRecord>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            rebate_vaults: BTreeMap::new(),
            sponsor_deposits: BTreeMap::new(),
            fee_coupon_notes: BTreeMap::new(),
            usage_receipts: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            withdrawal_windows: BTreeMap::new(),
            overspend_quarantines: BTreeMap::new(),
            rebate_expiries: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT)?;
        let vault_id = state.register_rebate_vault(
            RebateVaultRequest {
                operator_id: "operator:devnet-private-l2-fee-desk".to_string(),
                vault_label: "monero-private-l2-low-fee-rebates".to_string(),
                vault_kind: VaultKind::MoneroPrivateL2,
                sponsor_set_root: sample_hash("sponsor-set-root"),
                coupon_policy_root: sample_hash("coupon-policy-root"),
                withdrawal_policy_root: sample_hash("withdrawal-policy-root"),
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                target_rebate_bps: DEFAULT_REBATE_BPS,
                min_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
            },
            VaultStatus::Active,
        )?;
        let deposit_id = state.record_sponsor_deposit(SponsorDepositRequest {
            sponsor_id: "sponsor:devnet-wallet-coop".to_string(),
            vault_id: vault_id.clone(),
            sponsor_tier: SponsorTier::Wallet,
            deposit_commitment: sample_hash("sponsor-deposit"),
            deposit_amount: 5_000_000,
            available_amount: 5_000_000,
            max_coupon_face_amount: 20_000,
            sponsor_policy_root: sample_hash("sponsor-policy"),
            expires_height: state.height + DEFAULT_DEPOSIT_TTL_BLOCKS,
        })?;
        state.record_pq_sponsor_attestation(PqSponsorAttestationRequest {
            sponsor_id: "sponsor:devnet-wallet-coop".to_string(),
            vault_id: vault_id.clone(),
            sponsor_deposit_id: deposit_id.clone(),
            attester_id: "attester:devnet-pq-fee-committee".to_string(),
            verdict: AttestationVerdict::Allow,
            public_key_commitment: sample_hash("pq-public-key"),
            signature_commitment: sample_hash("pq-signature"),
            disclosure_root: sample_hash("pq-disclosure"),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            expires_height: state.height + DEFAULT_ATTESTATION_TTL_BLOCKS,
        })?;
        let coupon_id = state.mint_fee_coupon_note(FeeCouponNoteRequest {
            vault_id: vault_id.clone(),
            sponsor_deposit_id: deposit_id.clone(),
            recipient_commitment: sample_hash("recipient"),
            note_commitment: sample_hash("coupon-note"),
            nullifier_hash: sample_hash("coupon-nullifier"),
            face_amount: 12_000,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
            expires_height: state.height + DEFAULT_COUPON_TTL_BLOCKS,
        })?;
        state.create_privacy_redaction_budget(
            vault_id.clone(),
            sample_hash("recipient"),
            DEFAULT_REDACTION_BUDGET_UNITS,
            sample_hash("budget-disclosure"),
            state.height + DEFAULT_REBATE_EXPIRY_BLOCKS,
        )?;
        state.record_usage_receipt(UsageReceiptRequest {
            vault_id: vault_id.clone(),
            coupon_id: coupon_id.clone(),
            usage_lane: UsageLane::WalletTransfer,
            tx_commitment: sample_hash("private-l2-transfer"),
            fee_commitment: sample_hash("fee-paid"),
            receipt_nullifier: sample_hash("receipt-nullifier"),
            gross_amount: 2_500_000,
            fee_amount: 1_000,
            rebate_amount: 900,
            redaction_budget_cost: 3,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
        })?;
        state.schedule_withdrawal_window(WithdrawalWindowRequest {
            vault_id,
            sponsor_deposit_id: deposit_id,
            window_label: "devnet-sponsor-change-window-0".to_string(),
            withdrawal_commitment: sample_hash("withdrawal-change"),
            max_withdrawal_amount: 1_000_000,
            opens_height: state.height + 12,
            closes_height: state.height + 12 + DEFAULT_WITHDRAWAL_WINDOW_BLOCKS,
        })?;
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::devnet()?;
        let vault_id = state
            .rebate_vaults
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet fixture missing vault".to_string())?;
        let deposit_id = state
            .sponsor_deposits
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet fixture missing sponsor deposit".to_string())?;
        let coupon_id = state
            .fee_coupon_notes
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet fixture missing coupon".to_string())?;
        state.quarantine_overspend(OverspendQuarantineRequest {
            vault_id: vault_id.clone(),
            coupon_id: coupon_id.clone(),
            sponsor_deposit_id: deposit_id,
            reason: QuarantineReason::CouponOverspend,
            observed_spend_amount: 14_000,
            allowed_spend_amount: 12_000,
            evidence_root: sample_hash("demo-overspend-evidence"),
            release_height: state.height + DEFAULT_QUARANTINE_BLOCKS,
        })?;
        state.expire_rebate(
            vault_id,
            coupon_id,
            200,
            state.height + DEFAULT_REBATE_EXPIRY_BLOCKS,
            sample_hash("expired-rebate-note"),
        )?;
        Ok(state)
    }

    pub fn register_rebate_vault(
        &mut self,
        request: RebateVaultRequest,
        status: VaultStatus,
    ) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("rebate_vaults", self.rebate_vaults.len(), MAX_REBATE_VAULTS)?;
        let vault_id = rebate_vault_id(&request);
        if self.rebate_vaults.contains_key(&vault_id) {
            return Err(format!("rebate vault already exists: {vault_id}"));
        }
        let record = RebateVaultRecord {
            vault_id: vault_id.clone(),
            request,
            status,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("rebate_vault", &vault_id, record.public_record())?;
        self.rebate_vaults.insert(vault_id.clone(), record);
        Ok(vault_id)
    }

    pub fn record_sponsor_deposit(&mut self, request: SponsorDepositRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "sponsor_deposits",
            self.sponsor_deposits.len(),
            MAX_SPONSOR_DEPOSITS,
        )?;
        let vault = self
            .rebate_vaults
            .get(&request.vault_id)
            .ok_or_else(|| format!("unknown vault_id: {}", request.vault_id))?;
        if !vault.status.permits_withdrawal() {
            return Err("vault does not accept sponsor deposits".to_string());
        }
        let deposit_id = sponsor_deposit_id(&request);
        if self.sponsor_deposits.contains_key(&deposit_id) {
            return Err(format!("sponsor deposit already exists: {deposit_id}"));
        }
        let record = SponsorDepositRecord {
            deposit_id: deposit_id.clone(),
            request,
            status: DepositStatus::Pending,
            reserved_amount: 0,
            spent_amount: 0,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("sponsor_deposit", &deposit_id, record.public_record())?;
        self.sponsor_deposits.insert(deposit_id.clone(), record);
        Ok(deposit_id)
    }

    pub fn record_pq_sponsor_attestation(
        &mut self,
        request: PqSponsorAttestationRequest,
    ) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "pq_sponsor_attestations",
            self.pq_sponsor_attestations.len(),
            MAX_PQ_SPONSOR_ATTESTATIONS,
        )?;
        let deposit = self
            .sponsor_deposits
            .get_mut(&request.sponsor_deposit_id)
            .ok_or_else(|| format!("unknown sponsor_deposit_id: {}", request.sponsor_deposit_id))?;
        if deposit.request.vault_id != request.vault_id {
            return Err("attestation vault_id does not match deposit".to_string());
        }
        if deposit.request.sponsor_id != request.sponsor_id {
            return Err("attestation sponsor_id does not match deposit".to_string());
        }
        let attestation_id = pq_sponsor_attestation_id(&request);
        if self.pq_sponsor_attestations.contains_key(&attestation_id) {
            return Err(format!(
                "pq sponsor attestation already exists: {attestation_id}"
            ));
        }
        deposit.status = if request.verdict.permits_activation() {
            DepositStatus::Attested
        } else {
            DepositStatus::Quarantined
        };
        deposit.updated_height = self.height;
        let record = PqSponsorAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish(
            "pq_sponsor_attestation",
            &attestation_id,
            record.public_record(),
        )?;
        self.pq_sponsor_attestations
            .insert(attestation_id.clone(), record);
        Ok(attestation_id)
    }

    pub fn mint_fee_coupon_note(&mut self, request: FeeCouponNoteRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "fee_coupon_notes",
            self.fee_coupon_notes.len(),
            MAX_FEE_COUPON_NOTES,
        )?;
        if self.nullifiers.contains(&request.nullifier_hash) {
            return Err("coupon nullifier already exists".to_string());
        }
        let vault = self
            .rebate_vaults
            .get(&request.vault_id)
            .ok_or_else(|| format!("unknown vault_id: {}", request.vault_id))?;
        if !vault.status.accepts_usage() {
            return Err("vault does not accept coupon usage".to_string());
        }
        let deposit = self
            .sponsor_deposits
            .get_mut(&request.sponsor_deposit_id)
            .ok_or_else(|| format!("unknown sponsor_deposit_id: {}", request.sponsor_deposit_id))?;
        if deposit.request.vault_id != request.vault_id {
            return Err("coupon vault_id does not match sponsor deposit".to_string());
        }
        if !deposit.status.spendable() {
            return Err("sponsor deposit is not spendable".to_string());
        }
        if request.face_amount > deposit.request.max_coupon_face_amount {
            return Err("coupon face amount exceeds sponsor cap".to_string());
        }
        let available = deposit
            .request
            .available_amount
            .saturating_sub(deposit.reserved_amount)
            .saturating_sub(deposit.spent_amount);
        if request.face_amount > available {
            return Err("coupon face amount exceeds available sponsor deposit".to_string());
        }
        let coupon_id = fee_coupon_note_id(&request);
        if self.fee_coupon_notes.contains_key(&coupon_id) {
            return Err(format!("fee coupon note already exists: {coupon_id}"));
        }
        deposit.reserved_amount = deposit.reserved_amount.saturating_add(request.face_amount);
        deposit.status = DepositStatus::Active;
        deposit.updated_height = self.height;
        self.nullifiers.insert(request.nullifier_hash.clone());
        let record = FeeCouponNoteRecord {
            coupon_id: coupon_id.clone(),
            request,
            status: CouponStatus::Minted,
            redeemed_amount: 0,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("fee_coupon_note", &coupon_id, record.public_record())?;
        self.fee_coupon_notes.insert(coupon_id.clone(), record);
        Ok(coupon_id)
    }

    pub fn record_usage_receipt(&mut self, request: UsageReceiptRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "usage_receipts",
            self.usage_receipts.len(),
            MAX_USAGE_RECEIPTS,
        )?;
        if self.nullifiers.contains(&request.receipt_nullifier) {
            return Err("receipt nullifier already exists".to_string());
        }
        let coupon = self
            .fee_coupon_notes
            .get_mut(&request.coupon_id)
            .ok_or_else(|| format!("unknown coupon_id: {}", request.coupon_id))?;
        if coupon.request.vault_id != request.vault_id {
            return Err("usage receipt vault_id does not match coupon".to_string());
        }
        if !coupon.status.redeemable() {
            return Err("coupon is not redeemable".to_string());
        }
        let fee_floor = request
            .gross_amount
            .saturating_mul(request.usage_lane.fee_bps(&self.config) as u128)
            / MAX_BPS as u128;
        if request.fee_amount
            > coupon
                .request
                .face_amount
                .saturating_sub(coupon.redeemed_amount)
        {
            return Err("usage fee exceeds remaining coupon amount".to_string());
        }
        if request.fee_amount > fee_floor.saturating_add(coupon.request.face_amount) {
            return Err("usage fee exceeds lane bounded low-fee envelope".to_string());
        }
        coupon.redeemed_amount = coupon.redeemed_amount.saturating_add(request.fee_amount);
        coupon.status = if coupon.redeemed_amount >= coupon.request.face_amount {
            CouponStatus::Redeemed
        } else {
            CouponStatus::Attested
        };
        coupon.updated_height = self.height;
        let deposit = self
            .sponsor_deposits
            .get_mut(&coupon.request.sponsor_deposit_id)
            .ok_or_else(|| {
                format!(
                    "unknown sponsor_deposit_id: {}",
                    coupon.request.sponsor_deposit_id
                )
            })?;
        deposit.reserved_amount = deposit.reserved_amount.saturating_sub(request.fee_amount);
        deposit.spent_amount = deposit.spent_amount.saturating_add(request.fee_amount);
        deposit.updated_height = self.height;
        self.spend_redaction_budget(&request.vault_id, request.redaction_budget_cost)?;
        self.nullifiers.insert(request.receipt_nullifier.clone());
        let receipt_id = usage_receipt_id(&request);
        if self.usage_receipts.contains_key(&receipt_id) {
            return Err(format!("usage receipt already exists: {receipt_id}"));
        }
        let record = UsageReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            created_height: self.height,
            expires_height: self.height + self.config.usage_receipt_ttl_blocks,
        };
        self.publish("usage_receipt", &receipt_id, record.public_record())?;
        self.usage_receipts.insert(receipt_id.clone(), record);
        Ok(receipt_id)
    }

    pub fn schedule_withdrawal_window(
        &mut self,
        request: WithdrawalWindowRequest,
    ) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "withdrawal_windows",
            self.withdrawal_windows.len(),
            MAX_WITHDRAWAL_WINDOWS,
        )?;
        let vault = self
            .rebate_vaults
            .get(&request.vault_id)
            .ok_or_else(|| format!("unknown vault_id: {}", request.vault_id))?;
        if !vault.status.permits_withdrawal() {
            return Err("vault does not permit withdrawal windows".to_string());
        }
        let deposit = self
            .sponsor_deposits
            .get(&request.sponsor_deposit_id)
            .ok_or_else(|| format!("unknown sponsor_deposit_id: {}", request.sponsor_deposit_id))?;
        if deposit.request.vault_id != request.vault_id {
            return Err("withdrawal window vault_id does not match deposit".to_string());
        }
        let window_id = withdrawal_window_id(&request);
        if self.withdrawal_windows.contains_key(&window_id) {
            return Err(format!("withdrawal window already exists: {window_id}"));
        }
        let status = if self.height >= request.opens_height {
            WithdrawalWindowStatus::Open
        } else {
            WithdrawalWindowStatus::Scheduled
        };
        let record = WithdrawalWindowRecord {
            window_id: window_id.clone(),
            request,
            status,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("withdrawal_window", &window_id, record.public_record())?;
        self.withdrawal_windows.insert(window_id.clone(), record);
        Ok(window_id)
    }

    pub fn quarantine_overspend(&mut self, request: OverspendQuarantineRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "overspend_quarantines",
            self.overspend_quarantines.len(),
            MAX_OVERSPEND_QUARANTINES,
        )?;
        let coupon = self
            .fee_coupon_notes
            .get_mut(&request.coupon_id)
            .ok_or_else(|| format!("unknown coupon_id: {}", request.coupon_id))?;
        if coupon.request.vault_id != request.vault_id {
            return Err("quarantine vault_id does not match coupon".to_string());
        }
        coupon.status = CouponStatus::Quarantined;
        coupon.updated_height = self.height;
        let deposit = self
            .sponsor_deposits
            .get_mut(&request.sponsor_deposit_id)
            .ok_or_else(|| format!("unknown sponsor_deposit_id: {}", request.sponsor_deposit_id))?;
        deposit.status = DepositStatus::Quarantined;
        deposit.updated_height = self.height;
        let quarantine_id = overspend_quarantine_id(&request);
        if self.overspend_quarantines.contains_key(&quarantine_id) {
            return Err(format!(
                "overspend quarantine already exists: {quarantine_id}"
            ));
        }
        let record = OverspendQuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish(
            "overspend_quarantine",
            &quarantine_id,
            record.public_record(),
        )?;
        self.overspend_quarantines
            .insert(quarantine_id.clone(), record);
        Ok(quarantine_id)
    }

    pub fn expire_rebate(
        &mut self,
        vault_id: String,
        coupon_id: String,
        expired_amount: u128,
        expiry_height: u64,
        note_commitment: String,
    ) -> Result<String> {
        ensure_capacity(
            "rebate_expiries",
            self.rebate_expiries.len(),
            MAX_REBATE_EXPIRIES,
        )?;
        ensure_nonempty("vault_id", &vault_id)?;
        ensure_nonempty("coupon_id", &coupon_id)?;
        ensure_hash_like("note_commitment", &note_commitment)?;
        if expired_amount == 0 {
            return Err("expired_amount must be positive".to_string());
        }
        let coupon = self
            .fee_coupon_notes
            .get_mut(&coupon_id)
            .ok_or_else(|| format!("unknown coupon_id: {coupon_id}"))?;
        if coupon.request.vault_id != vault_id {
            return Err("rebate expiry vault_id does not match coupon".to_string());
        }
        coupon.status = CouponStatus::Expired;
        coupon.updated_height = self.height.max(expiry_height);
        self.height = self.height.max(expiry_height);
        let expiry_id = rebate_expiry_id(&vault_id, &coupon_id, expired_amount, expiry_height);
        if self.rebate_expiries.contains_key(&expiry_id) {
            return Err(format!("rebate expiry already exists: {expiry_id}"));
        }
        let record = RebateExpiryRecord {
            expiry_id: expiry_id.clone(),
            vault_id,
            coupon_id,
            expired_amount,
            expiry_height,
            note_commitment,
        };
        self.publish("rebate_expiry", &expiry_id, record.public_record())?;
        self.rebate_expiries.insert(expiry_id.clone(), record);
        Ok(expiry_id)
    }

    pub fn create_privacy_redaction_budget(
        &mut self,
        vault_id: String,
        subject_commitment: String,
        budget_units: u64,
        disclosure_root: String,
        expires_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "privacy_redaction_budgets",
            self.privacy_redaction_budgets.len(),
            MAX_PRIVACY_REDACTION_BUDGETS,
        )?;
        ensure_nonempty("vault_id", &vault_id)?;
        ensure_hash_like("subject_commitment", &subject_commitment)?;
        ensure_hash_like("disclosure_root", &disclosure_root)?;
        if budget_units == 0 || budget_units > self.config.redaction_budget_units {
            return Err("budget_units must be positive and within runtime cap".to_string());
        }
        if !self.rebate_vaults.contains_key(&vault_id) {
            return Err(format!("unknown vault_id: {vault_id}"));
        }
        let budget_id = privacy_redaction_budget_id(&vault_id, &subject_commitment);
        if self.privacy_redaction_budgets.contains_key(&budget_id) {
            return Err(format!(
                "privacy redaction budget already exists: {budget_id}"
            ));
        }
        let record = PrivacyRedactionBudgetRecord {
            budget_id: budget_id.clone(),
            vault_id,
            subject_commitment,
            budget_units,
            spent_units: 0,
            disclosure_root,
            created_height: self.height,
            expires_height,
        };
        self.publish(
            "privacy_redaction_budget",
            &budget_id,
            record.public_record(),
        )?;
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), record);
        Ok(budget_id)
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            rebate_vaults: self.rebate_vaults.len() as u64,
            sponsor_deposits: self.sponsor_deposits.len() as u64,
            fee_coupon_notes: self.fee_coupon_notes.len() as u64,
            usage_receipts: self.usage_receipts.len() as u64,
            pq_sponsor_attestations: self.pq_sponsor_attestations.len() as u64,
            withdrawal_windows: self.withdrawal_windows.len() as u64,
            overspend_quarantines: self.overspend_quarantines.len() as u64,
            rebate_expiries: self.rebate_expiries.len() as u64,
            privacy_redaction_budgets: self.privacy_redaction_budgets.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            public_records: self.public_records.len() as u64,
            ..Counters::default()
        };
        for deposit in self.sponsor_deposits.values() {
            counters.total_deposited_amount = counters
                .total_deposited_amount
                .saturating_add(deposit.request.deposit_amount);
            counters.available_sponsor_amount = counters
                .available_sponsor_amount
                .saturating_add(deposit.request.available_amount)
                .saturating_sub(deposit.reserved_amount)
                .saturating_sub(deposit.spent_amount);
        }
        for coupon in self.fee_coupon_notes.values() {
            counters.coupon_face_amount = counters
                .coupon_face_amount
                .saturating_add(coupon.request.face_amount);
            counters.redeemed_coupon_amount = counters
                .redeemed_coupon_amount
                .saturating_add(coupon.redeemed_amount);
        }
        for receipt in self.usage_receipts.values() {
            counters.usage_fee_amount = counters
                .usage_fee_amount
                .saturating_add(receipt.request.fee_amount);
            counters.rebate_amount = counters
                .rebate_amount
                .saturating_add(receipt.request.rebate_amount);
        }
        for quarantine in self.overspend_quarantines.values() {
            counters.quarantined_amount = counters
                .quarantined_amount
                .saturating_add(quarantine.request.observed_spend_amount);
        }
        for expiry in self.rebate_expiries.values() {
            counters.expired_rebate_amount = counters
                .expired_rebate_amount
                .saturating_add(expiry.expired_amount);
        }
        for budget in self.privacy_redaction_budgets.values() {
            counters.redaction_budget_units = counters
                .redaction_budget_units
                .saturating_add(budget.budget_units);
            counters.redaction_budget_spent = counters
                .redaction_budget_spent
                .saturating_add(budget.spent_units);
        }
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            rebate_vault_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:rebate_vaults",
                &self.rebate_vaults,
                RebateVaultRecord::public_record,
            ),
            sponsor_deposit_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:sponsor_deposits",
                &self.sponsor_deposits,
                SponsorDepositRecord::public_record,
            ),
            fee_coupon_note_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:fee_coupon_notes",
                &self.fee_coupon_notes,
                FeeCouponNoteRecord::public_record,
            ),
            usage_receipt_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:usage_receipts",
                &self.usage_receipts,
                UsageReceiptRecord::public_record,
            ),
            pq_sponsor_attestation_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:pq_sponsor_attestations",
                &self.pq_sponsor_attestations,
                PqSponsorAttestationRecord::public_record,
            ),
            withdrawal_window_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:withdrawal_windows",
                &self.withdrawal_windows,
                WithdrawalWindowRecord::public_record,
            ),
            overspend_quarantine_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:overspend_quarantines",
                &self.overspend_quarantines,
                OverspendQuarantineRecord::public_record,
            ),
            rebate_expiry_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:rebate_expiries",
                &self.rebate_expiries,
                RebateExpiryRecord::public_record,
            ),
            privacy_redaction_budget_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:privacy_redaction_budgets",
                &self.privacy_redaction_budgets,
                PrivacyRedactionBudgetRecord::public_record,
            ),
            nullifier_root: set_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:nullifiers",
                &self.nullifiers,
            ),
            public_record_root: map_root(
                "private_l2_low_fee_pq_confidential_rebate_vault:public_records",
                &self.public_records,
                PublicRuntimeRecord::public_record,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_rebate_vault_state",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn spend_redaction_budget(&mut self, vault_id: &str, cost: u64) -> Result<()> {
        if cost == 0 {
            return Ok(());
        }
        let budget = self
            .privacy_redaction_budgets
            .values_mut()
            .find(|budget| {
                budget.vault_id == vault_id && budget.spent_units + cost <= budget.budget_units
            })
            .ok_or_else(|| "privacy redaction budget exceeded".to_string())?;
        budget.spent_units = budget.spent_units.saturating_add(cost);
        Ok(())
    }

    fn publish(&mut self, record_kind: &str, subject_id: &str, payload: Value) -> Result<()> {
        let record_id = public_record_id(record_kind, subject_id, self.height, &payload);
        if self.public_records.contains_key(&record_id) {
            return Err(format!("public record already exists: {record_id}"));
        }
        let record = PublicRuntimeRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            payload,
        };
        self.public_records.insert(record_id, record);
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet().expect("private l2 low fee rebate vault devnet fixture")
}

pub fn demo() -> State {
    State::demo().expect("private l2 low fee rebate vault demo fixture")
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn rebate_vault_id(request: &RebateVaultRequest) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:rebate_vault_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.operator_id.as_str()),
            HashPart::Str(request.vault_label.as_str()),
            HashPart::Str(request.vault_kind.as_str()),
            HashPart::Str(request.sponsor_set_root.as_str()),
            HashPart::Str(request.coupon_policy_root.as_str()),
        ],
        32,
    )
}

pub fn sponsor_deposit_id(request: &SponsorDepositRequest) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:sponsor_deposit_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.sponsor_id.as_str()),
            HashPart::Str(request.vault_id.as_str()),
            HashPart::Str(request.sponsor_tier.as_str()),
            HashPart::Str(request.deposit_commitment.as_str()),
            HashPart::Str(request.sponsor_policy_root.as_str()),
        ],
        32,
    )
}

pub fn fee_coupon_note_id(request: &FeeCouponNoteRequest) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:fee_coupon_note_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.vault_id.as_str()),
            HashPart::Str(request.sponsor_deposit_id.as_str()),
            HashPart::Str(request.recipient_commitment.as_str()),
            HashPart::Str(request.note_commitment.as_str()),
            HashPart::Str(request.nullifier_hash.as_str()),
        ],
        32,
    )
}

pub fn usage_receipt_id(request: &UsageReceiptRequest) -> String {
    let record = request.public_record();
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:usage_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.vault_id.as_str()),
            HashPart::Str(request.coupon_id.as_str()),
            HashPart::Str(request.usage_lane.as_str()),
            HashPart::Str(request.receipt_nullifier.as_str()),
            HashPart::Json(&record),
        ],
        32,
    )
}

pub fn pq_sponsor_attestation_id(request: &PqSponsorAttestationRequest) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:pq_sponsor_attestation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.sponsor_id.as_str()),
            HashPart::Str(request.vault_id.as_str()),
            HashPart::Str(request.sponsor_deposit_id.as_str()),
            HashPart::Str(request.attester_id.as_str()),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(request.signature_commitment.as_str()),
        ],
        32,
    )
}

pub fn withdrawal_window_id(request: &WithdrawalWindowRequest) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:withdrawal_window_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.vault_id.as_str()),
            HashPart::Str(request.sponsor_deposit_id.as_str()),
            HashPart::Str(request.window_label.as_str()),
            HashPart::Str(request.withdrawal_commitment.as_str()),
            HashPart::U64(request.opens_height),
            HashPart::U64(request.closes_height),
        ],
        32,
    )
}

pub fn overspend_quarantine_id(request: &OverspendQuarantineRequest) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:overspend_quarantine_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.vault_id.as_str()),
            HashPart::Str(request.coupon_id.as_str()),
            HashPart::Str(request.sponsor_deposit_id.as_str()),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(request.evidence_root.as_str()),
            HashPart::U64(request.release_height),
        ],
        32,
    )
}

pub fn rebate_expiry_id(
    vault_id: &str,
    coupon_id: &str,
    expired_amount: u128,
    expiry_height: u64,
) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:rebate_expiry_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(coupon_id),
            HashPart::Str(&expired_amount.to_string()),
            HashPart::U64(expiry_height),
        ],
        32,
    )
}

pub fn privacy_redaction_budget_id(vault_id: &str, subject_commitment: &str) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:privacy_redaction_budget_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(subject_commitment),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:state_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    height: u64,
    payload: &Value,
) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:public_record_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must be at least 16 characters"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(field: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn sample_hash(label: &str) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_rebate_vault:devnet_sample",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
