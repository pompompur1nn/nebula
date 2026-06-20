use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSphincsExitReceiptReinsuranceClaimRedemptionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SPHINCS_EXIT_RECEIPT_REINSURANCE_CLAIM_REDEMPTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-sphincs-exit-receipt-reinsurance-claim-redemption-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SPHINCS_EXIT_RECEIPT_REINSURANCE_CLAIM_REDEMPTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SPHINCS_PLUS_SUITE: &str = "SPHINCS+-SHAKE-256f-exit-receipt-redemption-v1";
pub const HASH_BASED_CLAIM_AUTH_SUITE: &str =
    "hash-based-confidential-exit-receipt-claim-redemption-auth-v1";
pub const CONFIDENTIAL_RECEIPT_REDEMPTION_SUITE: &str =
    "confidential-private-l2-exit-receipt-redemption-commitment-v1";
pub const REINSURANCE_CLAIM_ACCOUNTING_SUITE: &str =
    "privacy-preserving-sphincs-reinsurance-claim-redemption-ledger-v1";
pub const LOW_FEE_REDEMPTION_BATCH_SUITE: &str =
    "low-fee-sphincs-exit-receipt-claim-redemption-batch-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-sphincs-exit-receipt-claim-redemption-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 9_312_000;
pub const DEVNET_EPOCH: u64 = 38_800;
pub const DEVNET_SLOT: u64 = 704;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SPHINCS_TREE_HEIGHT: u16 = 68;
pub const DEFAULT_SPHINCS_HYPERTREE_LAYERS: u16 = 17;
pub const DEFAULT_SPHINCS_FORS_TREES: u16 = 35;
pub const DEFAULT_SPHINCS_FORS_HEIGHT: u16 = 9;
pub const DEFAULT_SPHINCS_WINTERNITZ_PARAMETER: u16 = 16;
pub const DEFAULT_REDEMPTION_WINDOW_SLOTS: u64 = 4_320;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 640;
pub const DEFAULT_PROOF_GRACE_SLOTS: u64 = 256;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 192;
pub const DEFAULT_REINSURANCE_POOL_ATOMIC: u64 = 96_000_000_000;
pub const DEFAULT_MIN_SOLVENCY_RESERVE_ATOMIC: u64 = 18_000_000_000;
pub const DEFAULT_MAX_REDEMPTION_ATOMIC: u64 = 12_500_000_000;
pub const DEFAULT_REDEMPTION_ESCROW_ATOMIC: u64 = 1_250_000_000;
pub const DEFAULT_REINSURER_SHARE_BPS: u16 = 7_200;
pub const DEFAULT_CEDENT_SHARE_BPS: u16 = 2_800;
pub const DEFAULT_SOLVENCY_BUFFER_BPS: u16 = 1_500;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 1_024;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 84;
pub const DEFAULT_EPOCH_BUCKET_TARGET_REDEMPTIONS: u64 = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionStatus {
    Drafted,
    ReceiptSealed,
    SphincsAuthorized,
    ReserveLocked,
    Queued,
    Redeemed,
    Settled,
    Rejected,
    Expired,
}

impl RedemptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::ReceiptSealed => "receipt_sealed",
            Self::SphincsAuthorized => "sphincs_authorized",
            Self::ReserveLocked => "reserve_locked",
            Self::Queued => "queued",
            Self::Redeemed => "redeemed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionAccountingSide {
    ReserveLock,
    ClaimEscrow,
    ReinsurerPayable,
    CedentPayable,
    RedeemedPayout,
    Refund,
    Fee,
    SolvencyRelease,
}

impl RedemptionAccountingSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveLock => "reserve_lock",
            Self::ClaimEscrow => "claim_escrow",
            Self::ReinsurerPayable => "reinsurer_payable",
            Self::CedentPayable => "cedent_payable",
            Self::RedeemedPayout => "redeemed_payout",
            Self::Refund => "refund",
            Self::Fee => "fee",
            Self::SolvencyRelease => "solvency_release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Posted,
    Settled,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub sphincs_plus_suite: String,
    pub hash_based_claim_auth_suite: String,
    pub confidential_receipt_redemption_suite: String,
    pub reinsurance_claim_accounting_suite: String,
    pub low_fee_redemption_batch_suite: String,
    pub roots_only_public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub sphincs_tree_height: u16,
    pub sphincs_hypertree_layers: u16,
    pub sphincs_fors_trees: u16,
    pub sphincs_fors_height: u16,
    pub sphincs_winternitz_parameter: u16,
    pub redemption_window_slots: u64,
    pub settlement_delay_slots: u64,
    pub proof_grace_slots: u64,
    pub receipt_retention_epochs: u64,
    pub reinsurance_pool_atomic: u64,
    pub min_solvency_reserve_atomic: u64,
    pub max_redemption_atomic: u64,
    pub redemption_escrow_atomic: u64,
    pub reinsurer_share_bps: u16,
    pub cedent_share_bps: u16,
    pub solvency_buffer_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_redemptions: u64,
    pub sphincs_authorization_required: bool,
    pub confidential_receipts_required: bool,
    pub roots_only_public_records_required: bool,
    pub low_fee_batching_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: "nebula-private-l2-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            sphincs_plus_suite: SPHINCS_PLUS_SUITE.to_string(),
            hash_based_claim_auth_suite: HASH_BASED_CLAIM_AUTH_SUITE.to_string(),
            confidential_receipt_redemption_suite: CONFIDENTIAL_RECEIPT_REDEMPTION_SUITE
                .to_string(),
            reinsurance_claim_accounting_suite: REINSURANCE_CLAIM_ACCOUNTING_SUITE.to_string(),
            low_fee_redemption_batch_suite: LOW_FEE_REDEMPTION_BATCH_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            sphincs_tree_height: DEFAULT_SPHINCS_TREE_HEIGHT,
            sphincs_hypertree_layers: DEFAULT_SPHINCS_HYPERTREE_LAYERS,
            sphincs_fors_trees: DEFAULT_SPHINCS_FORS_TREES,
            sphincs_fors_height: DEFAULT_SPHINCS_FORS_HEIGHT,
            sphincs_winternitz_parameter: DEFAULT_SPHINCS_WINTERNITZ_PARAMETER,
            redemption_window_slots: DEFAULT_REDEMPTION_WINDOW_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            proof_grace_slots: DEFAULT_PROOF_GRACE_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            reinsurance_pool_atomic: DEFAULT_REINSURANCE_POOL_ATOMIC,
            min_solvency_reserve_atomic: DEFAULT_MIN_SOLVENCY_RESERVE_ATOMIC,
            max_redemption_atomic: DEFAULT_MAX_REDEMPTION_ATOMIC,
            redemption_escrow_atomic: DEFAULT_REDEMPTION_ESCROW_ATOMIC,
            reinsurer_share_bps: DEFAULT_REINSURER_SHARE_BPS,
            cedent_share_bps: DEFAULT_CEDENT_SHARE_BPS,
            solvency_buffer_bps: DEFAULT_SOLVENCY_BUFFER_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_redemptions: DEFAULT_EPOCH_BUCKET_TARGET_REDEMPTIONS,
            sphincs_authorization_required: true,
            confidential_receipts_required: true,
            roots_only_public_records_required: true,
            low_fee_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below sphincs redemption minimum".to_string());
        }
        if self.sphincs_tree_height < 60
            || self.sphincs_hypertree_layers == 0
            || self.sphincs_tree_height % self.sphincs_hypertree_layers != 0
        {
            return Err("invalid sphincs hypertree parameters".to_string());
        }
        if self.sphincs_fors_trees < 30
            || self.sphincs_fors_height < 8
            || self.sphincs_winternitz_parameter < 16
        {
            return Err("invalid sphincs fors or winternitz parameters".to_string());
        }
        if self.redemption_window_slots <= self.settlement_delay_slots + self.proof_grace_slots {
            return Err("invalid redemption timing window".to_string());
        }
        if self.receipt_retention_epochs == 0 || self.epoch_bucket_target_redemptions == 0 {
            return Err("retention and epoch bucket targets must be positive".to_string());
        }
        if self.reinsurance_pool_atomic <= self.min_solvency_reserve_atomic
            || self.max_redemption_atomic == 0
            || self.redemption_escrow_atomic == 0
            || self.max_redemption_atomic > self.reinsurance_pool_atomic
        {
            return Err("invalid redemption reinsurance economics".to_string());
        }
        if u32::from(self.reinsurer_share_bps) + u32::from(self.cedent_share_bps) != 10_000 {
            return Err("reinsurance redemption shares must sum to 10000 bps".to_string());
        }
        if self.solvency_buffer_bps > 5_000 {
            return Err("solvency buffer exceeds redemption policy bound".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee redemption batch policy".to_string());
        }
        if !self.sphincs_authorization_required
            || !self.confidential_receipts_required
            || !self.roots_only_public_records_required
        {
            return Err(
                "sphincs authorization, confidential receipts, and roots-only records are mandatory"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "suites": {
                "sphincs_plus": self.sphincs_plus_suite,
                "hash_based_claim_auth": self.hash_based_claim_auth_suite,
                "confidential_receipt_redemption": self.confidential_receipt_redemption_suite,
                "reinsurance_claim_accounting": self.reinsurance_claim_accounting_suite,
                "low_fee_redemption_batch": self.low_fee_redemption_batch_suite,
                "roots_only_public_record": self.roots_only_public_record_suite,
            },
            "security": {
                "min_pq_security_bits": self.min_pq_security_bits,
                "sphincs_tree_height": self.sphincs_tree_height,
                "sphincs_hypertree_layers": self.sphincs_hypertree_layers,
                "sphincs_fors_trees": self.sphincs_fors_trees,
                "sphincs_fors_height": self.sphincs_fors_height,
                "sphincs_winternitz_parameter": self.sphincs_winternitz_parameter,
            },
            "timing": {
                "redemption_window_slots": self.redemption_window_slots,
                "settlement_delay_slots": self.settlement_delay_slots,
                "proof_grace_slots": self.proof_grace_slots,
                "receipt_retention_epochs": self.receipt_retention_epochs,
            },
            "fee_policy": {
                "low_fee_batch_limit": self.low_fee_batch_limit,
                "min_batch_size": self.min_batch_size,
                "max_batch_fee_micro_units": self.max_batch_fee_micro_units,
                "low_fee_batching_enabled": self.low_fee_batching_enabled,
            },
            "privacy": {
                "confidential_receipts_required": self.confidential_receipts_required,
                "roots_only_public_records_required": self.roots_only_public_records_required,
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub receipt_redemptions: u64,
    pub sphincs_authorizations: u64,
    pub accounting_entries: u64,
    pub redemption_batches: u64,
    pub redeemed_claims: u64,
    pub settled_claims: u64,
    pub rejected_claims: u64,
    pub expired_claims: u64,
    pub spent_nullifiers: u64,
    pub total_reserved_atomic: u64,
    pub total_escrowed_atomic: u64,
    pub total_reinsurer_payable_atomic: u64,
    pub total_cedent_payable_atomic: u64,
    pub total_redeemed_atomic: u64,
    pub total_refunded_atomic: u64,
    pub total_solvency_released_atomic: u64,
    pub total_batch_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub receipt_redemption_root: String,
    pub sphincs_authorization_root: String,
    pub accounting_entry_root: String,
    pub redemption_batch_root: String,
    pub nullifier_root: String,
    pub solvency_reserve_root: String,
    pub fee_market_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = record_root("empty", Vec::new());
        Self {
            receipt_redemption_root: empty.clone(),
            sphincs_authorization_root: empty.clone(),
            accounting_entry_root: empty.clone(),
            redemption_batch_root: empty.clone(),
            nullifier_root: empty.clone(),
            solvency_reserve_root: empty.clone(),
            fee_market_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptRedemptionInput {
    pub exit_receipt_commitment_root: String,
    pub claim_commitment_root: String,
    pub claimant_commitment_root: String,
    pub cedent_commitment_root: String,
    pub reinsurer_commitment_root: String,
    pub policy_commitment_root: String,
    pub redemption_amount_commitment: String,
    pub redemption_nullifier: String,
    pub receipt_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SphincsAuthorizationInput {
    pub redemption_id: String,
    pub public_key_root: String,
    pub signature_root: String,
    pub message_digest_root: String,
    pub auth_path_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub authorization_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionAccountingEntryInput {
    pub redemption_id: String,
    pub side: RedemptionAccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub ledger_memo_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRedemptionBatchInput {
    pub epoch: u64,
    pub redemption_ids: BTreeSet<String>,
    pub settled_redemption_ids: BTreeSet<String>,
    pub rejected_redemption_ids: BTreeSet<String>,
    pub compression_root: String,
    pub fee_sponsor_commitment_root: String,
    pub batch_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptRedemption {
    pub redemption_id: String,
    pub exit_receipt_commitment_root: String,
    pub claim_commitment_root: String,
    pub claimant_commitment_root: String,
    pub cedent_commitment_root: String,
    pub reinsurer_commitment_root: String,
    pub policy_commitment_root: String,
    pub redemption_amount_commitment: String,
    pub redemption_nullifier: String,
    pub receipt_slot: u64,
    pub eligible_slot: u64,
    pub expires_slot: u64,
    pub status: RedemptionStatus,
}

impl ReceiptRedemption {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "redemption_id": self.redemption_id,
            "exit_receipt_commitment_root": self.exit_receipt_commitment_root,
            "claim_commitment_root": self.claim_commitment_root,
            "claimant_commitment_root": self.claimant_commitment_root,
            "cedent_commitment_root": self.cedent_commitment_root,
            "reinsurer_commitment_root": self.reinsurer_commitment_root,
            "policy_commitment_root": self.policy_commitment_root,
            "redemption_amount_commitment": self.redemption_amount_commitment,
            "redemption_nullifier": self.redemption_nullifier,
            "receipt_slot": self.receipt_slot,
            "eligible_slot": self.eligible_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SphincsRedemptionAuthorization {
    pub authorization_id: String,
    pub redemption_id: String,
    pub public_key_root: String,
    pub signature_root: String,
    pub message_digest_root: String,
    pub auth_path_root: String,
    pub transcript_root: String,
    pub tree_height: u16,
    pub hypertree_layers: u16,
    pub fors_trees: u16,
    pub fors_height: u16,
    pub pq_security_bits: u16,
    pub authorization_slot: u64,
}

impl SphincsRedemptionAuthorization {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "redemption_id": self.redemption_id,
            "public_key_root": self.public_key_root,
            "signature_root": self.signature_root,
            "message_digest_root": self.message_digest_root,
            "auth_path_root": self.auth_path_root,
            "transcript_root": self.transcript_root,
            "tree_height": self.tree_height,
            "hypertree_layers": self.hypertree_layers,
            "fors_trees": self.fors_trees,
            "fors_height": self.fors_height,
            "pq_security_bits": self.pq_security_bits,
            "authorization_slot": self.authorization_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReinsuranceRedemptionAccountingEntry {
    pub entry_id: String,
    pub redemption_id: String,
    pub side: RedemptionAccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub ledger_memo_root: String,
}

impl ReinsuranceRedemptionAccountingEntry {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "redemption_id": self.redemption_id,
            "side": self.side.as_str(),
            "amount_commitment_root": value_root(
                "sphincs-redemption-accounting-amount-redaction",
                &json!({
                    "entry_id": self.entry_id,
                    "side": self.side.as_str(),
                    "amount_atomic": self.amount_atomic,
                }),
            ),
            "account_commitment_root": self.account_commitment_root,
            "ledger_memo_root": self.ledger_memo_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRedemptionBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub redemption_ids: BTreeSet<String>,
    pub settled_redemption_ids: BTreeSet<String>,
    pub rejected_redemption_ids: BTreeSet<String>,
    pub compression_root: String,
    pub fee_sponsor_commitment_root: String,
    pub batch_fee_micro_units: u64,
    pub status: BatchStatus,
}

impl LowFeeRedemptionBatch {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "redemption_set_root": set_root("batch-redemption-set", &self.redemption_ids),
            "settled_set_root": set_root("batch-settled-redemption-set", &self.settled_redemption_ids),
            "rejected_set_root": set_root("batch-rejected-redemption-set", &self.rejected_redemption_ids),
            "compression_root": self.compression_root,
            "fee_sponsor_commitment_root": self.fee_sponsor_commitment_root,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionRiskBand {
    Micro,
    Standard,
    Elevated,
    SolvencyGuarded,
}

impl RedemptionRiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::SolvencyGuarded => "solvency_guarded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReserveQuoteInput {
    pub redemption_id: String,
    pub amount_atomic: u64,
    pub sponsor_commitment_root: String,
    pub quote_context_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReserveQuote {
    pub quote_id: String,
    pub redemption_id: String,
    pub amount_commitment_root: String,
    pub sponsor_commitment_root: String,
    pub quote_context_root: String,
    pub reinsurer_share_commitment_root: String,
    pub cedent_share_commitment_root: String,
    pub solvency_buffer_commitment_root: String,
    pub estimated_fee_micro_units: u64,
    pub risk_band: RedemptionRiskBand,
}

impl RedemptionReserveQuote {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "redemption_id": self.redemption_id,
            "amount_commitment_root": self.amount_commitment_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "quote_context_root": self.quote_context_root,
            "reinsurer_share_commitment_root": self.reinsurer_share_commitment_root,
            "cedent_share_commitment_root": self.cedent_share_commitment_root,
            "solvency_buffer_commitment_root": self.solvency_buffer_commitment_root,
            "estimated_fee_micro_units": self.estimated_fee_micro_units,
            "risk_band": self.risk_band.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SphincsParameterProfile {
    pub suite: String,
    pub min_pq_security_bits: u16,
    pub tree_height: u16,
    pub hypertree_layers: u16,
    pub subtree_height: u16,
    pub fors_trees: u16,
    pub fors_height: u16,
    pub winternitz_parameter: u16,
    pub estimated_signature_bytes: u64,
    pub stateless_signatures: bool,
}

impl SphincsParameterProfile {
    pub fn from_config(config: &Config) -> Self {
        Self {
            suite: config.sphincs_plus_suite.clone(),
            min_pq_security_bits: config.min_pq_security_bits,
            tree_height: config.sphincs_tree_height,
            hypertree_layers: config.sphincs_hypertree_layers,
            subtree_height: config.sphincs_tree_height / config.sphincs_hypertree_layers,
            fors_trees: config.sphincs_fors_trees,
            fors_height: config.sphincs_fors_height,
            winternitz_parameter: config.sphincs_winternitz_parameter,
            estimated_signature_bytes: estimate_sphincs_signature_bytes(config),
            stateless_signatures: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionQueueSnapshot {
    pub open_redemptions: u64,
    pub authorized_redemptions: u64,
    pub reserve_locked_redemptions: u64,
    pub queued_redemptions: u64,
    pub terminal_redemptions: u64,
    pub next_expiring_slot: Option<u64>,
    pub low_fee_batch_capacity_remaining: u64,
    pub queue_root: String,
}

impl RedemptionQueueSnapshot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolvencySnapshot {
    pub reinsurance_pool_commitment_root: String,
    pub min_reserve_commitment_root: String,
    pub reserved_commitment_root: String,
    pub redeemed_commitment_root: String,
    pub solvency_buffer_bps: u16,
    pub reserve_commitment_count: u64,
    pub reserve_root: String,
}

impl SolvencySnapshot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeMarketSnapshot {
    pub max_batch_fee_micro_units: u64,
    pub total_batch_fee_micro_units: u64,
    pub fee_commitment_count: u64,
    pub fee_market_root: String,
}

impl FeeMarketSnapshot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyApiSnapshot {
    pub snapshot_id: String,
    pub protocol_version: String,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub sphincs_parameter_profile: SphincsParameterProfile,
    pub queue: RedemptionQueueSnapshot,
    pub solvency: SolvencySnapshot,
    pub fee_market: FeeMarketSnapshot,
    pub counters: Counters,
    pub roots: Roots,
}

impl RootsOnlyApiSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "protocol_version": self.protocol_version,
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "sphincs_parameter_profile": self.sphincs_parameter_profile.public_record(),
            "queue": self.queue.public_record(),
            "solvency": self.solvency.public_record(),
            "fee_market": self.fee_market.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub receipt_redemptions: BTreeMap<String, ReceiptRedemption>,
    pub sphincs_authorizations: BTreeMap<String, SphincsRedemptionAuthorization>,
    pub accounting_entries: BTreeMap<String, ReinsuranceRedemptionAccountingEntry>,
    pub redemption_batches: BTreeMap<String, LowFeeRedemptionBatch>,
    pub reserve_quotes: BTreeMap<String, RedemptionReserveQuote>,
    pub spent_nullifiers: BTreeSet<String>,
    pub solvency_reserve_commitments: BTreeSet<String>,
    pub fee_market_commitments: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            slot,
            counters: Counters::default(),
            roots: Roots::default(),
            receipt_redemptions: BTreeMap::new(),
            sphincs_authorizations: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            redemption_batches: BTreeMap::new(),
            reserve_quotes: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            solvency_reserve_commitments: BTreeSet::new(),
            fee_market_commitments: BTreeSet::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH, DEVNET_SLOT)
            .unwrap_or_else(|_| Self::empty_devnet());
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn sphincs_parameter_profile(&self) -> SphincsParameterProfile {
        SphincsParameterProfile::from_config(&self.config)
    }

    pub fn reserve_quote(
        &mut self,
        input: RedemptionReserveQuoteInput,
    ) -> Result<RedemptionReserveQuote> {
        self.validate_root("sponsor_commitment_root", &input.sponsor_commitment_root)?;
        self.validate_root("quote_context_root", &input.quote_context_root)?;
        if input.amount_atomic == 0 || input.amount_atomic > self.config.max_redemption_atomic {
            return Err("redemption reserve quote amount outside policy bounds".to_string());
        }
        if !self.receipt_redemptions.contains_key(&input.redemption_id) {
            return Err("unknown redemption for reserve quote".to_string());
        }

        let quote_id = deterministic_id(
            "sphincs-redemption-reserve-quote",
            &[
                HashPart::Str(&input.redemption_id),
                HashPart::U64(input.amount_atomic),
                HashPart::Str(&input.sponsor_commitment_root),
                HashPart::Str(&input.quote_context_root),
            ],
        );
        if self.reserve_quotes.contains_key(&quote_id) {
            return Err("redemption reserve quote already exists".to_string());
        }

        let reinsurer_share = pro_rata_amount(input.amount_atomic, self.config.reinsurer_share_bps);
        let cedent_share = input.amount_atomic.saturating_sub(reinsurer_share);
        let solvency_buffer = pro_rata_amount(input.amount_atomic, self.config.solvency_buffer_bps);
        let risk_band = self.risk_band_for_amount(input.amount_atomic);
        let estimated_fee_micro_units = self.estimate_low_fee_micro_units(input.amount_atomic);
        let quote = RedemptionReserveQuote {
            quote_id: quote_id.clone(),
            redemption_id: input.redemption_id.clone(),
            amount_commitment_root: value_root(
                "sphincs-redemption-reserve-quote-amount",
                &json!({
                    "redemption_id": input.redemption_id,
                    "amount_atomic": input.amount_atomic,
                }),
            ),
            sponsor_commitment_root: input.sponsor_commitment_root,
            quote_context_root: input.quote_context_root,
            reinsurer_share_commitment_root: value_root(
                "sphincs-redemption-reinsurer-share",
                &json!({
                    "quote_id": quote_id,
                    "amount_atomic": reinsurer_share,
                }),
            ),
            cedent_share_commitment_root: value_root(
                "sphincs-redemption-cedent-share",
                &json!({
                    "redemption_id": input.redemption_id,
                    "amount_atomic": cedent_share,
                }),
            ),
            solvency_buffer_commitment_root: value_root(
                "sphincs-redemption-solvency-buffer",
                &json!({
                    "amount_atomic": solvency_buffer,
                    "buffer_bps": self.config.solvency_buffer_bps,
                }),
            ),
            estimated_fee_micro_units,
            risk_band,
        };
        self.reserve_quotes
            .insert(quote.quote_id.clone(), quote.clone());
        self.refresh();
        Ok(quote)
    }

    pub fn queue_snapshot(&self) -> RedemptionQueueSnapshot {
        let mut open_redemptions = 0_u64;
        let mut authorized_redemptions = 0_u64;
        let mut reserve_locked_redemptions = 0_u64;
        let mut queued_redemptions = 0_u64;
        let mut terminal_redemptions = 0_u64;
        let mut next_expiring_slot = None;

        for redemption in self.receipt_redemptions.values() {
            match redemption.status {
                RedemptionStatus::ReceiptSealed => open_redemptions += 1,
                RedemptionStatus::SphincsAuthorized => authorized_redemptions += 1,
                RedemptionStatus::ReserveLocked => reserve_locked_redemptions += 1,
                RedemptionStatus::Queued => queued_redemptions += 1,
                RedemptionStatus::Redeemed
                | RedemptionStatus::Settled
                | RedemptionStatus::Rejected
                | RedemptionStatus::Expired => terminal_redemptions += 1,
                RedemptionStatus::Drafted => open_redemptions += 1,
            }
            if !matches!(
                redemption.status,
                RedemptionStatus::Settled | RedemptionStatus::Rejected | RedemptionStatus::Expired
            ) {
                next_expiring_slot = Some(
                    next_expiring_slot
                        .map(|slot: u64| slot.min(redemption.expires_slot))
                        .unwrap_or(redemption.expires_slot),
                );
            }
        }

        let low_fee_batch_capacity_remaining = u64::from(self.config.low_fee_batch_limit)
            .saturating_sub(queued_redemptions.min(u64::from(self.config.low_fee_batch_limit)));
        let queue_root = record_root(
            "sphincs-redemption-queue-snapshot",
            self.receipt_redemptions
                .values()
                .filter(|redemption| {
                    !matches!(
                        redemption.status,
                        RedemptionStatus::Settled
                            | RedemptionStatus::Rejected
                            | RedemptionStatus::Expired
                    )
                })
                .map(ReceiptRedemption::roots_only_record)
                .collect(),
        );

        RedemptionQueueSnapshot {
            open_redemptions,
            authorized_redemptions,
            reserve_locked_redemptions,
            queued_redemptions,
            terminal_redemptions,
            next_expiring_slot,
            low_fee_batch_capacity_remaining,
            queue_root,
        }
    }

    pub fn solvency_snapshot(&self) -> SolvencySnapshot {
        SolvencySnapshot {
            reinsurance_pool_commitment_root: value_root(
                "sphincs-redemption-reinsurance-pool-redacted",
                &json!({
                    "pool_atomic": self.config.reinsurance_pool_atomic,
                    "epoch": self.epoch,
                }),
            ),
            min_reserve_commitment_root: value_root(
                "sphincs-redemption-min-reserve-redacted",
                &json!({
                    "min_solvency_reserve_atomic": self.config.min_solvency_reserve_atomic,
                    "epoch": self.epoch,
                }),
            ),
            reserved_commitment_root: value_root(
                "sphincs-redemption-total-reserved-redacted",
                &json!({
                    "total_reserved_atomic": self.counters.total_reserved_atomic,
                    "entry_count": self.counters.accounting_entries,
                }),
            ),
            redeemed_commitment_root: value_root(
                "sphincs-redemption-total-redeemed-redacted",
                &json!({
                    "total_redeemed_atomic": self.counters.total_redeemed_atomic,
                    "settled_claims": self.counters.settled_claims,
                }),
            ),
            solvency_buffer_bps: self.config.solvency_buffer_bps,
            reserve_commitment_count: self.solvency_reserve_commitments.len() as u64,
            reserve_root: self.roots.solvency_reserve_root.clone(),
        }
    }

    pub fn fee_market_snapshot(&self) -> FeeMarketSnapshot {
        FeeMarketSnapshot {
            max_batch_fee_micro_units: self.config.max_batch_fee_micro_units,
            total_batch_fee_micro_units: self.counters.total_batch_fee_micro_units,
            fee_commitment_count: self.fee_market_commitments.len() as u64,
            fee_market_root: self.roots.fee_market_root.clone(),
        }
    }

    pub fn roots_only_api_snapshot(&self) -> RootsOnlyApiSnapshot {
        let queue = self.queue_snapshot();
        let solvency = self.solvency_snapshot();
        let fee_market = self.fee_market_snapshot();
        let sphincs_parameter_profile = self.sphincs_parameter_profile();
        let snapshot_id = deterministic_id(
            "sphincs-redemption-roots-only-api-snapshot",
            &[
                HashPart::Str(&self.roots.state_root),
                HashPart::Str(&queue.queue_root),
                HashPart::Str(&solvency.reserve_root),
                HashPart::Str(&fee_market.fee_market_root),
            ],
        );
        RootsOnlyApiSnapshot {
            snapshot_id,
            protocol_version: self.config.protocol_version.clone(),
            height: self.height,
            epoch: self.epoch,
            slot: self.slot,
            sphincs_parameter_profile,
            queue,
            solvency,
            fee_market,
            counters: self.counters.clone(),
            roots: self.roots.clone(),
        }
    }

    pub fn redemptions_by_status(&self, status: RedemptionStatus) -> BTreeSet<String> {
        self.receipt_redemptions
            .values()
            .filter(|redemption| redemption.status == status)
            .map(|redemption| redemption.redemption_id.clone())
            .collect()
    }

    pub fn redemption_root(&self, redemption_id: &str) -> Option<String> {
        self.receipt_redemptions
            .get(redemption_id)
            .map(|redemption| {
                value_root(
                    "sphincs-redemption-single-record",
                    &redemption.roots_only_record(),
                )
            })
    }

    pub fn authorization_root(&self, authorization_id: &str) -> Option<String> {
        self.sphincs_authorizations
            .get(authorization_id)
            .map(|authorization| {
                value_root(
                    "sphincs-redemption-authorization-single-record",
                    &authorization.roots_only_record(),
                )
            })
    }

    pub fn batch_root(&self, batch_id: &str) -> Option<String> {
        self.redemption_batches.get(batch_id).map(|batch| {
            value_root(
                "sphincs-redemption-batch-single-record",
                &batch.roots_only_record(),
            )
        })
    }

    pub fn has_spent_nullifier(&self, nullifier: &str) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }

    pub fn available_pool_commitment_root(&self) -> String {
        let committed = self
            .counters
            .total_reserved_atomic
            .saturating_add(self.counters.total_redeemed_atomic)
            .saturating_add(self.config.min_solvency_reserve_atomic);
        let available = self
            .config
            .reinsurance_pool_atomic
            .saturating_sub(committed);
        value_root(
            "sphincs-redemption-available-pool-redacted",
            &json!({
                "available_atomic": available,
                "height": self.height,
                "epoch": self.epoch,
            }),
        )
    }

    pub fn risk_band_for_amount(&self, amount_atomic: u64) -> RedemptionRiskBand {
        let quarter = self.config.max_redemption_atomic / 4;
        let half = self.config.max_redemption_atomic / 2;
        let guarded = self
            .config
            .max_redemption_atomic
            .saturating_sub(pro_rata_amount(
                self.config.max_redemption_atomic,
                self.config.solvency_buffer_bps,
            ));
        if amount_atomic <= quarter {
            RedemptionRiskBand::Micro
        } else if amount_atomic <= half {
            RedemptionRiskBand::Standard
        } else if amount_atomic <= guarded {
            RedemptionRiskBand::Elevated
        } else {
            RedemptionRiskBand::SolvencyGuarded
        }
    }

    pub fn estimate_low_fee_micro_units(&self, amount_atomic: u64) -> u64 {
        let base = self.config.max_batch_fee_micro_units / 4;
        let variable = match self.risk_band_for_amount(amount_atomic) {
            RedemptionRiskBand::Micro => 1,
            RedemptionRiskBand::Standard => 2,
            RedemptionRiskBand::Elevated => 3,
            RedemptionRiskBand::SolvencyGuarded => 4,
        };
        base.saturating_mul(variable)
            .min(self.config.max_batch_fee_micro_units)
            .max(1)
    }

    pub fn seal_receipt_redemption(
        &mut self,
        input: ReceiptRedemptionInput,
    ) -> Result<ReceiptRedemption> {
        self.validate_root(
            "exit_receipt_commitment_root",
            &input.exit_receipt_commitment_root,
        )?;
        self.validate_root("claim_commitment_root", &input.claim_commitment_root)?;
        self.validate_root("claimant_commitment_root", &input.claimant_commitment_root)?;
        self.validate_root("cedent_commitment_root", &input.cedent_commitment_root)?;
        self.validate_root(
            "reinsurer_commitment_root",
            &input.reinsurer_commitment_root,
        )?;
        self.validate_root("policy_commitment_root", &input.policy_commitment_root)?;
        self.validate_root(
            "redemption_amount_commitment",
            &input.redemption_amount_commitment,
        )?;
        self.validate_root("redemption_nullifier", &input.redemption_nullifier)?;
        if self.spent_nullifiers.contains(&input.redemption_nullifier) {
            return Err("redemption nullifier already spent".to_string());
        }

        let redemption_id = deterministic_id(
            "sphincs-receipt-redemption",
            &[
                HashPart::Str(&input.exit_receipt_commitment_root),
                HashPart::Str(&input.claim_commitment_root),
                HashPart::Str(&input.redemption_nullifier),
                HashPart::U64(input.receipt_slot),
            ],
        );
        if self.receipt_redemptions.contains_key(&redemption_id) {
            return Err("receipt redemption already sealed".to_string());
        }

        let redemption = ReceiptRedemption {
            redemption_id: redemption_id.clone(),
            exit_receipt_commitment_root: input.exit_receipt_commitment_root,
            claim_commitment_root: input.claim_commitment_root,
            claimant_commitment_root: input.claimant_commitment_root,
            cedent_commitment_root: input.cedent_commitment_root,
            reinsurer_commitment_root: input.reinsurer_commitment_root,
            policy_commitment_root: input.policy_commitment_root,
            redemption_amount_commitment: input.redemption_amount_commitment,
            redemption_nullifier: input.redemption_nullifier,
            receipt_slot: input.receipt_slot,
            eligible_slot: input.receipt_slot + self.config.settlement_delay_slots,
            expires_slot: input.receipt_slot + self.config.redemption_window_slots,
            status: RedemptionStatus::ReceiptSealed,
        };
        self.spent_nullifiers
            .insert(redemption.redemption_nullifier.clone());
        self.receipt_redemptions
            .insert(redemption_id, redemption.clone());
        self.refresh();
        Ok(redemption)
    }

    pub fn attach_sphincs_authorization(
        &mut self,
        input: SphincsAuthorizationInput,
    ) -> Result<SphincsRedemptionAuthorization> {
        self.validate_root("public_key_root", &input.public_key_root)?;
        self.validate_root("signature_root", &input.signature_root)?;
        self.validate_root("message_digest_root", &input.message_digest_root)?;
        self.validate_root("auth_path_root", &input.auth_path_root)?;
        self.validate_root("transcript_root", &input.transcript_root)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("sphincs authorization below configured pq security".to_string());
        }
        let redemption = self
            .receipt_redemptions
            .get_mut(&input.redemption_id)
            .ok_or_else(|| "unknown redemption for sphincs authorization".to_string())?;

        let authorization_id = deterministic_id(
            "sphincs-redemption-authorization",
            &[
                HashPart::Str(&input.redemption_id),
                HashPart::Str(&input.public_key_root),
                HashPart::Str(&input.signature_root),
                HashPart::U64(input.authorization_slot),
            ],
        );
        if self.sphincs_authorizations.contains_key(&authorization_id) {
            return Err("sphincs redemption authorization already exists".to_string());
        }

        redemption.status = RedemptionStatus::SphincsAuthorized;
        let authorization = SphincsRedemptionAuthorization {
            authorization_id: authorization_id.clone(),
            redemption_id: input.redemption_id,
            public_key_root: input.public_key_root,
            signature_root: input.signature_root,
            message_digest_root: input.message_digest_root,
            auth_path_root: input.auth_path_root,
            transcript_root: input.transcript_root,
            tree_height: self.config.sphincs_tree_height,
            hypertree_layers: self.config.sphincs_hypertree_layers,
            fors_trees: self.config.sphincs_fors_trees,
            fors_height: self.config.sphincs_fors_height,
            pq_security_bits: input.pq_security_bits,
            authorization_slot: input.authorization_slot,
        };
        self.sphincs_authorizations
            .insert(authorization_id, authorization.clone());
        self.refresh();
        Ok(authorization)
    }

    pub fn post_accounting_entry(
        &mut self,
        input: RedemptionAccountingEntryInput,
    ) -> Result<ReinsuranceRedemptionAccountingEntry> {
        self.validate_root("account_commitment_root", &input.account_commitment_root)?;
        self.validate_root("ledger_memo_root", &input.ledger_memo_root)?;
        if input.amount_atomic == 0 {
            return Err("redemption accounting amount must be positive".to_string());
        }
        if input.amount_atomic > self.config.max_redemption_atomic
            && matches!(
                input.side,
                RedemptionAccountingSide::RedeemedPayout
                    | RedemptionAccountingSide::ReinsurerPayable
                    | RedemptionAccountingSide::CedentPayable
            )
        {
            return Err("redemption accounting amount exceeds policy maximum".to_string());
        }
        let redemption = self
            .receipt_redemptions
            .get_mut(&input.redemption_id)
            .ok_or_else(|| "unknown redemption for accounting entry".to_string())?;
        let entry_id = deterministic_id(
            "sphincs-redemption-accounting-entry",
            &[
                HashPart::Str(&input.redemption_id),
                HashPart::Str(input.side.as_str()),
                HashPart::U64(input.amount_atomic),
                HashPart::Str(&input.account_commitment_root),
            ],
        );
        if self.accounting_entries.contains_key(&entry_id) {
            return Err("redemption accounting entry already exists".to_string());
        }
        if matches!(input.side, RedemptionAccountingSide::ReserveLock) {
            redemption.status = RedemptionStatus::ReserveLocked;
            self.solvency_reserve_commitments
                .insert(input.account_commitment_root.clone());
        }
        if matches!(input.side, RedemptionAccountingSide::Fee) {
            self.fee_market_commitments
                .insert(input.account_commitment_root.clone());
        }
        let entry = ReinsuranceRedemptionAccountingEntry {
            entry_id: entry_id.clone(),
            redemption_id: input.redemption_id,
            side: input.side,
            amount_atomic: input.amount_atomic,
            account_commitment_root: input.account_commitment_root,
            ledger_memo_root: input.ledger_memo_root,
        };
        self.accounting_entries.insert(entry_id, entry.clone());
        self.refresh();
        Ok(entry)
    }

    pub fn queue_low_fee_batch(
        &mut self,
        input: LowFeeRedemptionBatchInput,
    ) -> Result<LowFeeRedemptionBatch> {
        if input.redemption_ids.len() < usize::from(self.config.min_batch_size)
            || input.redemption_ids.len() > usize::from(self.config.low_fee_batch_limit)
        {
            return Err("redemption batch size outside low-fee bounds".to_string());
        }
        if input.batch_fee_micro_units > self.config.max_batch_fee_micro_units {
            return Err("redemption batch fee exceeds low-fee policy".to_string());
        }
        self.validate_root("compression_root", &input.compression_root)?;
        self.validate_root(
            "fee_sponsor_commitment_root",
            &input.fee_sponsor_commitment_root,
        )?;
        for redemption_id in &input.redemption_ids {
            let redemption = self
                .receipt_redemptions
                .get_mut(redemption_id)
                .ok_or_else(|| format!("unknown redemption in batch: {redemption_id}"))?;
            if matches!(
                redemption.status,
                RedemptionStatus::Rejected | RedemptionStatus::Expired | RedemptionStatus::Settled
            ) {
                return Err("terminal redemption cannot be queued".to_string());
            }
            redemption.status = RedemptionStatus::Queued;
        }
        for redemption_id in &input.settled_redemption_ids {
            let redemption = self
                .receipt_redemptions
                .get_mut(redemption_id)
                .ok_or_else(|| format!("unknown settled redemption in batch: {redemption_id}"))?;
            redemption.status = RedemptionStatus::Settled;
        }
        for redemption_id in &input.rejected_redemption_ids {
            let redemption = self
                .receipt_redemptions
                .get_mut(redemption_id)
                .ok_or_else(|| format!("unknown rejected redemption in batch: {redemption_id}"))?;
            redemption.status = RedemptionStatus::Rejected;
        }
        let batch_id = deterministic_id(
            "sphincs-low-fee-redemption-batch",
            &[
                HashPart::U64(input.epoch),
                HashPart::Str(&set_root("input-redemption-set", &input.redemption_ids)),
                HashPart::Str(&input.compression_root),
            ],
        );
        if self.redemption_batches.contains_key(&batch_id) {
            return Err("redemption batch already exists".to_string());
        }
        let batch = LowFeeRedemptionBatch {
            batch_id: batch_id.clone(),
            epoch: input.epoch,
            redemption_ids: input.redemption_ids,
            settled_redemption_ids: input.settled_redemption_ids,
            rejected_redemption_ids: input.rejected_redemption_ids,
            compression_root: input.compression_root,
            fee_sponsor_commitment_root: input.fee_sponsor_commitment_root,
            batch_fee_micro_units: input.batch_fee_micro_units,
            status: BatchStatus::Posted,
        };
        self.redemption_batches.insert(batch_id, batch.clone());
        self.refresh();
        Ok(batch)
    }

    pub fn mark_redeemed(&mut self, redemption_id: &str) -> Result<()> {
        let redemption = self
            .receipt_redemptions
            .get_mut(redemption_id)
            .ok_or_else(|| "unknown redemption".to_string())?;
        if !matches!(
            redemption.status,
            RedemptionStatus::SphincsAuthorized
                | RedemptionStatus::ReserveLocked
                | RedemptionStatus::Queued
        ) {
            return Err("redemption is not ready for redeemed status".to_string());
        }
        redemption.status = RedemptionStatus::Redeemed;
        self.refresh();
        Ok(())
    }

    pub fn expire_old_redemptions(&mut self, slot: u64) -> u64 {
        let mut expired = 0_u64;
        for redemption in self.receipt_redemptions.values_mut() {
            if slot > redemption.expires_slot
                && !matches!(
                    redemption.status,
                    RedemptionStatus::Settled | RedemptionStatus::Rejected
                )
            {
                redemption.status = RedemptionStatus::Expired;
                expired += 1;
            }
        }
        if expired > 0 {
            self.slot = self.slot.max(slot);
            self.refresh();
        }
        expired
    }

    pub fn refresh(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
    }

    fn compute_counters(&self) -> Counters {
        let mut counters = Counters {
            receipt_redemptions: self.receipt_redemptions.len() as u64,
            sphincs_authorizations: self.sphincs_authorizations.len() as u64,
            accounting_entries: self.accounting_entries.len() as u64,
            redemption_batches: self.redemption_batches.len() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            ..Counters::default()
        };
        for redemption in self.receipt_redemptions.values() {
            match redemption.status {
                RedemptionStatus::Redeemed => counters.redeemed_claims += 1,
                RedemptionStatus::Settled => counters.settled_claims += 1,
                RedemptionStatus::Rejected => counters.rejected_claims += 1,
                RedemptionStatus::Expired => counters.expired_claims += 1,
                _ => {}
            }
        }
        for entry in self.accounting_entries.values() {
            match entry.side {
                RedemptionAccountingSide::ReserveLock => {
                    counters.total_reserved_atomic += entry.amount_atomic
                }
                RedemptionAccountingSide::ClaimEscrow => {
                    counters.total_escrowed_atomic += entry.amount_atomic
                }
                RedemptionAccountingSide::ReinsurerPayable => {
                    counters.total_reinsurer_payable_atomic += entry.amount_atomic
                }
                RedemptionAccountingSide::CedentPayable => {
                    counters.total_cedent_payable_atomic += entry.amount_atomic
                }
                RedemptionAccountingSide::RedeemedPayout => {
                    counters.total_redeemed_atomic += entry.amount_atomic
                }
                RedemptionAccountingSide::Refund => {
                    counters.total_refunded_atomic += entry.amount_atomic
                }
                RedemptionAccountingSide::Fee => {}
                RedemptionAccountingSide::SolvencyRelease => {
                    counters.total_solvency_released_atomic += entry.amount_atomic
                }
            }
        }
        counters.total_batch_fee_micro_units = self
            .redemption_batches
            .values()
            .map(|batch| batch.batch_fee_micro_units)
            .sum();
        counters
    }

    fn compute_roots(&self) -> Roots {
        let receipt_redemption_root = record_root(
            "sphincs-receipt-redemption-root",
            self.receipt_redemptions
                .values()
                .map(ReceiptRedemption::roots_only_record)
                .collect(),
        );
        let sphincs_authorization_root = record_root(
            "sphincs-redemption-authorization-root",
            self.sphincs_authorizations
                .values()
                .map(SphincsRedemptionAuthorization::roots_only_record)
                .collect(),
        );
        let accounting_entry_root = record_root(
            "sphincs-redemption-accounting-root",
            self.accounting_entries
                .values()
                .map(ReinsuranceRedemptionAccountingEntry::roots_only_record)
                .collect(),
        );
        let redemption_batch_root = record_root(
            "sphincs-low-fee-redemption-batch-root",
            self.redemption_batches
                .values()
                .map(LowFeeRedemptionBatch::roots_only_record)
                .collect(),
        );
        let reserve_quote_root = record_root(
            "sphincs-redemption-reserve-quote-root",
            self.reserve_quotes
                .values()
                .map(RedemptionReserveQuote::roots_only_record)
                .collect(),
        );
        let nullifier_root = set_root("sphincs-redemption-nullifier-root", &self.spent_nullifiers);
        let solvency_reserve_root = set_root(
            "sphincs-redemption-solvency-reserve-root",
            &self.solvency_reserve_commitments,
        );
        let fee_market_root = set_root(
            "sphincs-redemption-fee-market-root",
            &self.fee_market_commitments,
        );
        let public_record_root = value_root(
            "sphincs-redemption-public-record-root",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "receipt_redemption_root": receipt_redemption_root,
                "sphincs_authorization_root": sphincs_authorization_root,
                "accounting_entry_root": accounting_entry_root,
                "redemption_batch_root": redemption_batch_root,
                "reserve_quote_root": reserve_quote_root,
                "nullifier_root": nullifier_root,
                "solvency_reserve_root": solvency_reserve_root,
                "fee_market_root": fee_market_root,
            }),
        );
        let state_root = value_root(
            "sphincs-redemption-state-root",
            &json!({
                "height": self.height,
                "epoch": self.epoch,
                "slot": self.slot,
                "public_record_root": public_record_root,
            }),
        );
        Roots {
            receipt_redemption_root,
            sphincs_authorization_root,
            accounting_entry_root,
            redemption_batch_root,
            nullifier_root,
            solvency_reserve_root,
            fee_market_root,
            public_record_root,
            state_root,
        }
    }

    fn seed_devnet(&mut self) {
        for index in 0_u64..5 {
            let redemption = self
                .seal_receipt_redemption(ReceiptRedemptionInput {
                    exit_receipt_commitment_root: sample_root("sphincs-exit-receipt", index),
                    claim_commitment_root: sample_root("sphincs-claim-commitment", index),
                    claimant_commitment_root: sample_root("sphincs-claimant", index),
                    cedent_commitment_root: sample_root("sphincs-cedent", index),
                    reinsurer_commitment_root: sample_root("sphincs-reinsurer", index),
                    policy_commitment_root: sample_root("sphincs-reinsurance-policy", index),
                    redemption_amount_commitment: sample_root("sphincs-redemption-amount", index),
                    redemption_nullifier: sample_root("sphincs-redemption-nullifier", index),
                    receipt_slot: self.slot + index * 8,
                })
                .expect("devnet redemption");
            self.attach_sphincs_authorization(SphincsAuthorizationInput {
                redemption_id: redemption.redemption_id.clone(),
                public_key_root: sample_root("sphincs-redemption-public-key", index),
                signature_root: sample_root("sphincs-redemption-signature", index),
                message_digest_root: sample_root("sphincs-redemption-message-digest", index),
                auth_path_root: sample_root("sphincs-redemption-auth-path", index),
                transcript_root: sample_root("sphincs-redemption-transcript", index),
                pq_security_bits: self.config.min_pq_security_bits,
                authorization_slot: self.slot + index * 8 + 2,
            })
            .expect("devnet sphincs authorization");
            self.post_accounting_entry(RedemptionAccountingEntryInput {
                redemption_id: redemption.redemption_id.clone(),
                side: RedemptionAccountingSide::ReserveLock,
                amount_atomic: self.config.redemption_escrow_atomic + index * 100_000,
                account_commitment_root: sample_root("sphincs-redemption-reserve-account", index),
                ledger_memo_root: sample_root("sphincs-redemption-reserve-memo", index),
            })
            .expect("devnet reserve entry");
            self.post_accounting_entry(RedemptionAccountingEntryInput {
                redemption_id: redemption.redemption_id.clone(),
                side: RedemptionAccountingSide::RedeemedPayout,
                amount_atomic: self.config.max_redemption_atomic / 4 + index * 250_000,
                account_commitment_root: sample_root("sphincs-redemption-payout-account", index),
                ledger_memo_root: sample_root("sphincs-redemption-payout-memo", index),
            })
            .expect("devnet payout entry");
        }

        let ids = self
            .receipt_redemptions
            .keys()
            .take(3)
            .cloned()
            .collect::<BTreeSet<_>>();
        let settled = ids.iter().take(2).cloned().collect::<BTreeSet<_>>();
        let rejected = ids.iter().skip(2).take(1).cloned().collect::<BTreeSet<_>>();
        self.queue_low_fee_batch(LowFeeRedemptionBatchInput {
            epoch: self.epoch,
            redemption_ids: ids,
            settled_redemption_ids: settled,
            rejected_redemption_ids: rejected,
            compression_root: sample_root("sphincs-redemption-batch-compression", 0),
            fee_sponsor_commitment_root: sample_root("sphincs-redemption-fee-sponsor", 0),
            batch_fee_micro_units: self.config.max_batch_fee_micro_units,
        })
        .expect("devnet redemption batch");
        self.refresh();
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            counters: Counters::default(),
            roots: Roots::default(),
            receipt_redemptions: BTreeMap::new(),
            sphincs_authorizations: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            redemption_batches: BTreeMap::new(),
            reserve_quotes: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            solvency_reserve_commitments: BTreeSet::new(),
            fee_market_commitments: BTreeSet::new(),
        }
    }

    fn validate_root(&self, label: &str, value: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(format!("{label} must not be empty"));
        }
        if value.len() < 32 {
            return Err(format!("{label} must be a commitment root"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": state.config.protocol_version,
        "schema_version": state.config.schema_version,
        "height": state.height,
        "epoch": state.epoch,
        "slot": state.slot,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "snapshots": {
            "sphincs_parameter_profile": state.sphincs_parameter_profile().public_record(),
            "queue": state.queue_snapshot().public_record(),
            "solvency": state.solvency_snapshot().public_record(),
            "fee_market": state.fee_market_snapshot().public_record(),
            "available_pool_commitment_root": state.available_pool_commitment_root(),
        },
        "privacy": {
            "records": "roots_only",
            "amounts": "commitment_roots_or_redacted_amount_roots",
            "claimants": "commitment_roots",
            "receipts": "commitment_roots",
            "sphincs_witnesses": "signature_and_auth_path_roots_only",
        },
    })
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{PROTOCOL_VERSION}:{domain}:id"), parts, 32)
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:devnet-sample-root"),
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value_root("sort-key", value));
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &values)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "commitment": value }))
        .collect::<Vec<_>>();
    record_root(domain, leaves)
}

pub fn pro_rata_amount(amount_atomic: u64, share_bps: u16) -> u64 {
    amount_atomic.saturating_mul(u64::from(share_bps)) / 10_000
}

pub fn estimate_sphincs_signature_bytes(config: &Config) -> u64 {
    let n = u64::from(config.min_pq_security_bits / 8);
    let fors_bytes = u64::from(config.sphincs_fors_trees)
        .saturating_mul(u64::from(config.sphincs_fors_height).saturating_add(1))
        .saturating_mul(n);
    let subtree_height = u64::from(config.sphincs_tree_height / config.sphincs_hypertree_layers);
    let hypertree_bytes = u64::from(config.sphincs_hypertree_layers)
        .saturating_mul(subtree_height.saturating_add(1))
        .saturating_mul(n);
    n.saturating_add(fors_bytes).saturating_add(hypertree_bytes)
}
