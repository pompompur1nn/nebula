use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialWinternitzExitReceiptReinsuranceClaimFinalityRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_WINTERNITZ_EXIT_RECEIPT_REINSURANCE_CLAIM_FINALITY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-winternitz-exit-receipt-reinsurance-claim-finality-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_WINTERNITZ_EXIT_RECEIPT_REINSURANCE_CLAIM_FINALITY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const WINTERNITZ_CLAIM_FINALITY_SUITE: &str =
    "winternitz-hash-based-exit-receipt-reinsurance-claim-finality-v1";
pub const CONFIDENTIAL_EXIT_RECEIPT_SUITE: &str =
    "confidential-private-l2-exit-receipt-claim-commitment-v1";
pub const REINSURANCE_LEDGER_SUITE: &str =
    "privacy-preserving-reinsurance-claim-ledger-accounting-v1";
pub const LOW_FEE_AGGREGATION_SUITE: &str =
    "low-fee-winternitz-reinsurance-claim-finality-aggregation-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-winternitz-reinsurance-claim-finality-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 9_024_000;
pub const DEVNET_EPOCH: u64 = 37_600;
pub const DEVNET_SLOT: u64 = 448;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_WINTERNITZ_PARAMETER: u8 = 16;
pub const DEFAULT_WINTERNITZ_CHAIN_COUNT: u16 = 67;
pub const DEFAULT_WINTERNITZ_CHECKSUM_BITS: u16 = 14;
pub const DEFAULT_WINTERNITZ_ROUNDS: u16 = 2;
pub const DEFAULT_FINALITY_DELAY_SLOTS: u64 = 1_280;
pub const DEFAULT_CLAIM_WINDOW_SLOTS: u64 = 5_760;
pub const DEFAULT_PROOF_GRACE_SLOTS: u64 = 384;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 128;
pub const DEFAULT_REINSURANCE_POOL_ATOMIC: u64 = 72_000_000_000;
pub const DEFAULT_MIN_RESERVE_ATOMIC: u64 = 12_000_000_000;
pub const DEFAULT_MAX_CLAIM_PAYOUT_ATOMIC: u64 = 15_000_000_000;
pub const DEFAULT_CLAIM_ESCROW_ATOMIC: u64 = 1_100_000_000;
pub const DEFAULT_SOLVENCY_BUFFER_BPS: u16 = 1_250;
pub const DEFAULT_REINSURER_SHARE_BPS: u16 = 7_500;
pub const DEFAULT_CEDENT_SHARE_BPS: u16 = 2_500;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 896;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 96;
pub const DEFAULT_EPOCH_BUCKET_TARGET_CLAIMS: u64 = 49_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFinalityStatus {
    Drafted,
    ReceiptCommitted,
    WinternitzKeyed,
    WitnessAccepted,
    AccountingReserved,
    Queued,
    Finalized,
    Paid,
    Rejected,
    Expired,
}

impl ClaimFinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::ReceiptCommitted => "receipt_committed",
            Self::WinternitzKeyed => "winternitz_keyed",
            Self::WitnessAccepted => "witness_accepted",
            Self::AccountingReserved => "accounting_reserved",
            Self::Queued => "queued",
            Self::Finalized => "finalized",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAccountingSide {
    ReserveLock,
    ClaimEscrow,
    ReinsurerLiability,
    CedentLiability,
    Payout,
    Refund,
    Fee,
}

impl ClaimAccountingSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveLock => "reserve_lock",
            Self::ClaimEscrow => "claim_escrow",
            Self::ReinsurerLiability => "reinsurer_liability",
            Self::CedentLiability => "cedent_liability",
            Self::Payout => "payout",
            Self::Refund => "refund",
            Self::Fee => "fee",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimBatchStatus {
    Open,
    Posted,
    Settled,
}

impl ClaimBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Posted => "posted",
            Self::Settled => "settled",
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
    pub winternitz_claim_finality_suite: String,
    pub confidential_exit_receipt_suite: String,
    pub reinsurance_ledger_suite: String,
    pub low_fee_aggregation_suite: String,
    pub roots_only_public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub winternitz_parameter: u8,
    pub winternitz_chain_count: u16,
    pub winternitz_checksum_bits: u16,
    pub winternitz_rounds: u16,
    pub finality_delay_slots: u64,
    pub claim_window_slots: u64,
    pub proof_grace_slots: u64,
    pub receipt_retention_epochs: u64,
    pub reinsurance_pool_atomic: u64,
    pub min_reserve_atomic: u64,
    pub max_claim_payout_atomic: u64,
    pub claim_escrow_atomic: u64,
    pub solvency_buffer_bps: u16,
    pub reinsurer_share_bps: u16,
    pub cedent_share_bps: u16,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_claims: u64,
    pub winternitz_witnesses_required: bool,
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
            winternitz_claim_finality_suite: WINTERNITZ_CLAIM_FINALITY_SUITE.to_string(),
            confidential_exit_receipt_suite: CONFIDENTIAL_EXIT_RECEIPT_SUITE.to_string(),
            reinsurance_ledger_suite: REINSURANCE_LEDGER_SUITE.to_string(),
            low_fee_aggregation_suite: LOW_FEE_AGGREGATION_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            winternitz_parameter: DEFAULT_WINTERNITZ_PARAMETER,
            winternitz_chain_count: DEFAULT_WINTERNITZ_CHAIN_COUNT,
            winternitz_checksum_bits: DEFAULT_WINTERNITZ_CHECKSUM_BITS,
            winternitz_rounds: DEFAULT_WINTERNITZ_ROUNDS,
            finality_delay_slots: DEFAULT_FINALITY_DELAY_SLOTS,
            claim_window_slots: DEFAULT_CLAIM_WINDOW_SLOTS,
            proof_grace_slots: DEFAULT_PROOF_GRACE_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            reinsurance_pool_atomic: DEFAULT_REINSURANCE_POOL_ATOMIC,
            min_reserve_atomic: DEFAULT_MIN_RESERVE_ATOMIC,
            max_claim_payout_atomic: DEFAULT_MAX_CLAIM_PAYOUT_ATOMIC,
            claim_escrow_atomic: DEFAULT_CLAIM_ESCROW_ATOMIC,
            solvency_buffer_bps: DEFAULT_SOLVENCY_BUFFER_BPS,
            reinsurer_share_bps: DEFAULT_REINSURER_SHARE_BPS,
            cedent_share_bps: DEFAULT_CEDENT_SHARE_BPS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_claims: DEFAULT_EPOCH_BUCKET_TARGET_CLAIMS,
            winternitz_witnesses_required: true,
            confidential_receipts_required: true,
            roots_only_public_records_required: true,
            low_fee_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below winternitz claim finality minimum".to_string());
        }
        if self.winternitz_parameter < 4 || self.winternitz_parameter.count_ones() != 1 {
            return Err("winternitz parameter must be a supported power of two".to_string());
        }
        if self.winternitz_chain_count < DEFAULT_WINTERNITZ_CHAIN_COUNT
            || self.winternitz_checksum_bits < DEFAULT_WINTERNITZ_CHECKSUM_BITS
            || self.winternitz_rounds == 0
        {
            return Err("invalid winternitz claim finality key schedule".to_string());
        }
        if self.finality_delay_slots == 0
            || self.claim_window_slots < self.finality_delay_slots + self.proof_grace_slots
        {
            return Err("invalid claim finality timing window".to_string());
        }
        if self.receipt_retention_epochs == 0 || self.epoch_bucket_target_claims == 0 {
            return Err("retention and epoch bucket targets must be positive".to_string());
        }
        if self.reinsurance_pool_atomic <= self.min_reserve_atomic
            || self.max_claim_payout_atomic == 0
            || self.claim_escrow_atomic == 0
            || self.max_claim_payout_atomic > self.reinsurance_pool_atomic
        {
            return Err("invalid reinsurance claim accounting policy".to_string());
        }
        if u32::from(self.reinsurer_share_bps) + u32::from(self.cedent_share_bps) != 10_000 {
            return Err("reinsurance participation shares must sum to 10000 bps".to_string());
        }
        if self.solvency_buffer_bps > 5_000 {
            return Err("solvency buffer exceeds low-fee policy bound".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee finality batch policy".to_string());
        }
        if !self.winternitz_witnesses_required
            || !self.confidential_receipts_required
            || !self.roots_only_public_records_required
        {
            return Err(
                "winternitz witnesses, confidential receipts, and roots-only records are mandatory"
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
                "winternitz_claim_finality": self.winternitz_claim_finality_suite,
                "confidential_exit_receipt": self.confidential_exit_receipt_suite,
                "reinsurance_ledger": self.reinsurance_ledger_suite,
                "low_fee_aggregation": self.low_fee_aggregation_suite,
                "roots_only_public_record": self.roots_only_public_record_suite,
            },
            "security": {
                "min_pq_security_bits": self.min_pq_security_bits,
                "winternitz_parameter": self.winternitz_parameter,
                "winternitz_chain_count": self.winternitz_chain_count,
                "winternitz_checksum_bits": self.winternitz_checksum_bits,
                "winternitz_rounds": self.winternitz_rounds,
            },
            "timing": {
                "finality_delay_slots": self.finality_delay_slots,
                "claim_window_slots": self.claim_window_slots,
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
    pub receipt_commitments: u64,
    pub winternitz_key_commitments: u64,
    pub finality_witnesses: u64,
    pub accounting_entries: u64,
    pub finality_batches: u64,
    pub finalized_claims: u64,
    pub paid_claims: u64,
    pub rejected_claims: u64,
    pub expired_claims: u64,
    pub spent_nullifiers: u64,
    pub total_reserved_atomic: u64,
    pub total_escrowed_atomic: u64,
    pub total_reinsurer_liability_atomic: u64,
    pub total_cedent_liability_atomic: u64,
    pub total_paid_atomic: u64,
    pub total_refunded_atomic: u64,
    pub total_batch_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_commitments": self.receipt_commitments,
            "winternitz_key_commitments": self.winternitz_key_commitments,
            "finality_witnesses": self.finality_witnesses,
            "accounting_entries": self.accounting_entries,
            "finality_batches": self.finality_batches,
            "finalized_claims": self.finalized_claims,
            "paid_claims": self.paid_claims,
            "rejected_claims": self.rejected_claims,
            "expired_claims": self.expired_claims,
            "spent_nullifiers": self.spent_nullifiers,
            "total_reserved_atomic": self.total_reserved_atomic,
            "total_escrowed_atomic": self.total_escrowed_atomic,
            "total_reinsurer_liability_atomic": self.total_reinsurer_liability_atomic,
            "total_cedent_liability_atomic": self.total_cedent_liability_atomic,
            "total_paid_atomic": self.total_paid_atomic,
            "total_refunded_atomic": self.total_refunded_atomic,
            "total_batch_fee_micro_units": self.total_batch_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub receipt_commitment_root: String,
    pub winternitz_key_root: String,
    pub winternitz_witness_root: String,
    pub accounting_entry_root: String,
    pub finality_batch_root: String,
    pub nullifier_root: String,
    pub reserve_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = record_root("empty", Vec::new());
        Self {
            receipt_commitment_root: empty.clone(),
            winternitz_key_root: empty.clone(),
            winternitz_witness_root: empty.clone(),
            accounting_entry_root: empty.clone(),
            finality_batch_root: empty.clone(),
            nullifier_root: empty.clone(),
            reserve_accounting_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_commitment_root": self.receipt_commitment_root,
            "winternitz_key_root": self.winternitz_key_root,
            "winternitz_witness_root": self.winternitz_witness_root,
            "accounting_entry_root": self.accounting_entry_root,
            "finality_batch_root": self.finality_batch_root,
            "nullifier_root": self.nullifier_root,
            "reserve_accounting_root": self.reserve_accounting_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceiptCommitmentInput {
    pub receipt_commitment_root: String,
    pub claimant_commitment_root: String,
    pub cedent_commitment_root: String,
    pub reinsurer_commitment_root: String,
    pub claim_amount_commitment: String,
    pub policy_commitment_root: String,
    pub receipt_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinternitzKeyCommitmentInput {
    pub claim_id: String,
    pub public_key_root: String,
    pub chain_commitment_root: String,
    pub checksum_commitment_root: String,
    pub key_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinternitzFinalityWitnessInput {
    pub claim_id: String,
    pub signature_root: String,
    pub message_digest_root: String,
    pub witness_transcript_root: String,
    pub pq_security_bits: u16,
    pub witness_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimAccountingEntryInput {
    pub claim_id: String,
    pub side: ClaimAccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub ledger_memo_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimFinalityBatchInput {
    pub epoch: u64,
    pub claim_ids: BTreeSet<String>,
    pub finalized_claim_ids: BTreeSet<String>,
    pub paid_claim_ids: BTreeSet<String>,
    pub rejected_claim_ids: BTreeSet<String>,
    pub compression_root: String,
    pub fee_sponsor_commitment_root: String,
    pub batch_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceiptClaim {
    pub claim_id: String,
    pub receipt_commitment_root: String,
    pub claimant_commitment_root: String,
    pub cedent_commitment_root: String,
    pub reinsurer_commitment_root: String,
    pub claim_amount_commitment: String,
    pub policy_commitment_root: String,
    pub receipt_slot: u64,
    pub finality_slot: u64,
    pub expires_slot: u64,
    pub status: ClaimFinalityStatus,
}

impl ExitReceiptClaim {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "receipt_commitment_root": self.receipt_commitment_root,
            "claimant_commitment_root": self.claimant_commitment_root,
            "cedent_commitment_root": self.cedent_commitment_root,
            "reinsurer_commitment_root": self.reinsurer_commitment_root,
            "claim_amount_commitment": self.claim_amount_commitment,
            "policy_commitment_root": self.policy_commitment_root,
            "receipt_slot": self.receipt_slot,
            "finality_slot": self.finality_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinternitzKeyCommitment {
    pub key_id: String,
    pub claim_id: String,
    pub public_key_root: String,
    pub chain_commitment_root: String,
    pub checksum_commitment_root: String,
    pub winternitz_parameter: u8,
    pub chain_count: u16,
    pub checksum_bits: u16,
    pub key_epoch: u64,
}

impl WinternitzKeyCommitment {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "key_id": self.key_id,
            "claim_id": self.claim_id,
            "public_key_root": self.public_key_root,
            "chain_commitment_root": self.chain_commitment_root,
            "checksum_commitment_root": self.checksum_commitment_root,
            "winternitz_parameter": self.winternitz_parameter,
            "chain_count": self.chain_count,
            "checksum_bits": self.checksum_bits,
            "key_epoch": self.key_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinternitzFinalityWitness {
    pub witness_id: String,
    pub claim_id: String,
    pub signature_root: String,
    pub message_digest_root: String,
    pub witness_transcript_root: String,
    pub pq_security_bits: u16,
    pub witness_slot: u64,
}

impl WinternitzFinalityWitness {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "claim_id": self.claim_id,
            "signature_root": self.signature_root,
            "message_digest_root": self.message_digest_root,
            "witness_transcript_root": self.witness_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "witness_slot": self.witness_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReinsuranceClaimAccountingEntry {
    pub entry_id: String,
    pub claim_id: String,
    pub side: ClaimAccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub ledger_memo_root: String,
}

impl ReinsuranceClaimAccountingEntry {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "claim_id": self.claim_id,
            "side": self.side.as_str(),
            "amount_commitment_root": value_root(
                "accounting-amount-redaction",
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
pub struct LowFeeClaimFinalityBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub claim_ids: BTreeSet<String>,
    pub finalized_claim_ids: BTreeSet<String>,
    pub paid_claim_ids: BTreeSet<String>,
    pub rejected_claim_ids: BTreeSet<String>,
    pub compression_root: String,
    pub fee_sponsor_commitment_root: String,
    pub batch_fee_micro_units: u64,
    pub status: ClaimBatchStatus,
}

impl LowFeeClaimFinalityBatch {
    pub fn roots_only_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "claim_count": self.claim_ids.len(),
            "finalized_count": self.finalized_claim_ids.len(),
            "paid_count": self.paid_claim_ids.len(),
            "rejected_count": self.rejected_claim_ids.len(),
            "claim_set_root": record_root(
                "batch-claim-set",
                self.claim_ids
                    .iter()
                    .map(|claim_id| json!({ "claim_id": claim_id }))
                    .collect(),
            ),
            "finalized_set_root": record_root(
                "batch-finalized-set",
                self.finalized_claim_ids
                    .iter()
                    .map(|claim_id| json!({ "claim_id": claim_id }))
                    .collect(),
            ),
            "paid_set_root": record_root(
                "batch-paid-set",
                self.paid_claim_ids
                    .iter()
                    .map(|claim_id| json!({ "claim_id": claim_id }))
                    .collect(),
            ),
            "rejected_set_root": record_root(
                "batch-rejected-set",
                self.rejected_claim_ids
                    .iter()
                    .map(|claim_id| json!({ "claim_id": claim_id }))
                    .collect(),
            ),
            "compression_root": self.compression_root,
            "fee_sponsor_commitment_root": self.fee_sponsor_commitment_root,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub reserve_available_atomic: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub receipt_claims: BTreeMap<String, ExitReceiptClaim>,
    pub winternitz_keys: BTreeMap<String, WinternitzKeyCommitment>,
    pub finality_witnesses: BTreeMap<String, WinternitzFinalityWitness>,
    pub accounting_entries: BTreeMap<String, ReinsuranceClaimAccountingEntry>,
    pub finality_batches: BTreeMap<String, LowFeeClaimFinalityBatch>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::empty_devnet();
        state.seed_devnet();
        state.refresh();
        state
    }

    pub fn anchor_receipt(&mut self, input: ExitReceiptCommitmentInput) -> Result<String> {
        self.config.validate()?;
        require_commitment("receipt_commitment_root", &input.receipt_commitment_root)?;
        require_commitment("claimant_commitment_root", &input.claimant_commitment_root)?;
        require_commitment("cedent_commitment_root", &input.cedent_commitment_root)?;
        require_commitment(
            "reinsurer_commitment_root",
            &input.reinsurer_commitment_root,
        )?;
        require_commitment("claim_amount_commitment", &input.claim_amount_commitment)?;
        require_commitment("policy_commitment_root", &input.policy_commitment_root)?;
        if input.receipt_slot > self.slot + self.config.claim_window_slots {
            return Err("receipt slot is outside the accepted claim window".to_string());
        }
        let claim_id = deterministic_id(
            "claim",
            &[
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::Str(&input.claimant_commitment_root),
                HashPart::Str(&input.policy_commitment_root),
                HashPart::U64(input.receipt_slot),
            ],
        );
        if self.receipt_claims.contains_key(&claim_id) {
            return Err("receipt commitment already anchored".to_string());
        }
        let nullifier = deterministic_id(
            "receipt-nullifier",
            &[
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::Str(&input.claimant_commitment_root),
            ],
        );
        if !self.spent_nullifiers.insert(nullifier) {
            return Err("receipt nullifier already spent".to_string());
        }
        let claim = ExitReceiptClaim {
            claim_id: claim_id.clone(),
            receipt_commitment_root: input.receipt_commitment_root,
            claimant_commitment_root: input.claimant_commitment_root,
            cedent_commitment_root: input.cedent_commitment_root,
            reinsurer_commitment_root: input.reinsurer_commitment_root,
            claim_amount_commitment: input.claim_amount_commitment,
            policy_commitment_root: input.policy_commitment_root,
            receipt_slot: input.receipt_slot,
            finality_slot: input.receipt_slot + self.config.finality_delay_slots,
            expires_slot: input.receipt_slot + self.config.claim_window_slots,
            status: ClaimFinalityStatus::ReceiptCommitted,
        };
        self.receipt_claims.insert(claim_id.clone(), claim);
        self.refresh();
        Ok(claim_id)
    }

    pub fn commit_winternitz_key(&mut self, input: WinternitzKeyCommitmentInput) -> Result<String> {
        self.config.validate()?;
        require_commitment("public_key_root", &input.public_key_root)?;
        require_commitment("chain_commitment_root", &input.chain_commitment_root)?;
        require_commitment("checksum_commitment_root", &input.checksum_commitment_root)?;
        if !self.receipt_claims.contains_key(&input.claim_id) {
            return Err("claim must be anchored before winternitz key commitment".to_string());
        }
        let key_id = deterministic_id(
            "winternitz-key",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&input.public_key_root),
                HashPart::Str(&input.chain_commitment_root),
                HashPart::U64(input.key_epoch),
            ],
        );
        if self.winternitz_keys.contains_key(&key_id) {
            return Err("winternitz key commitment already exists".to_string());
        }
        let key = WinternitzKeyCommitment {
            key_id: key_id.clone(),
            claim_id: input.claim_id.clone(),
            public_key_root: input.public_key_root,
            chain_commitment_root: input.chain_commitment_root,
            checksum_commitment_root: input.checksum_commitment_root,
            winternitz_parameter: self.config.winternitz_parameter,
            chain_count: self.config.winternitz_chain_count,
            checksum_bits: self.config.winternitz_checksum_bits,
            key_epoch: input.key_epoch,
        };
        if let Some(claim) = self.receipt_claims.get_mut(&input.claim_id) {
            claim.status = ClaimFinalityStatus::WinternitzKeyed;
        }
        self.winternitz_keys.insert(key_id.clone(), key);
        self.refresh();
        Ok(key_id)
    }

    pub fn submit_winternitz_witness(
        &mut self,
        input: WinternitzFinalityWitnessInput,
    ) -> Result<String> {
        self.config.validate()?;
        require_commitment("signature_root", &input.signature_root)?;
        require_commitment("message_digest_root", &input.message_digest_root)?;
        require_commitment("witness_transcript_root", &input.witness_transcript_root)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("winternitz witness below configured pq security bits".to_string());
        }
        let claim = self
            .receipt_claims
            .get(&input.claim_id)
            .ok_or_else(|| "claim must be anchored before witness".to_string())?;
        if input.witness_slot < claim.receipt_slot {
            return Err("witness slot cannot precede receipt slot".to_string());
        }
        if input.witness_slot > claim.expires_slot + self.config.proof_grace_slots {
            return Err("witness submitted after claim proof grace window".to_string());
        }
        if !self
            .winternitz_keys
            .values()
            .any(|key| key.claim_id == input.claim_id)
        {
            return Err("winternitz key commitment required before witness".to_string());
        }
        let witness_id = deterministic_id(
            "winternitz-witness",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&input.signature_root),
                HashPart::Str(&input.message_digest_root),
                HashPart::U64(input.witness_slot),
            ],
        );
        if self.finality_witnesses.contains_key(&witness_id) {
            return Err("winternitz finality witness already exists".to_string());
        }
        let witness = WinternitzFinalityWitness {
            witness_id: witness_id.clone(),
            claim_id: input.claim_id.clone(),
            signature_root: input.signature_root,
            message_digest_root: input.message_digest_root,
            witness_transcript_root: input.witness_transcript_root,
            pq_security_bits: input.pq_security_bits,
            witness_slot: input.witness_slot,
        };
        if let Some(claim) = self.receipt_claims.get_mut(&input.claim_id) {
            claim.status = ClaimFinalityStatus::WitnessAccepted;
        }
        self.finality_witnesses.insert(witness_id.clone(), witness);
        self.refresh();
        Ok(witness_id)
    }

    pub fn lock_accounting(&mut self, input: ClaimAccountingEntryInput) -> Result<String> {
        self.config.validate()?;
        require_commitment("account_commitment_root", &input.account_commitment_root)?;
        require_commitment("ledger_memo_root", &input.ledger_memo_root)?;
        if input.amount_atomic == 0 {
            return Err("accounting amount must be positive".to_string());
        }
        if input.amount_atomic > self.config.max_claim_payout_atomic {
            return Err("accounting amount exceeds max claim payout".to_string());
        }
        if !self.receipt_claims.contains_key(&input.claim_id) {
            return Err("claim must be anchored before accounting lock".to_string());
        }
        if matches!(
            input.side,
            ClaimAccountingSide::ReserveLock
                | ClaimAccountingSide::ReinsurerLiability
                | ClaimAccountingSide::Payout
        ) && input.amount_atomic > self.reserve_available_atomic
        {
            return Err("insufficient reinsurance reserve for claim accounting".to_string());
        }
        let entry_id = deterministic_id(
            "accounting",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(input.side.as_str()),
                HashPart::Str(&input.account_commitment_root),
                HashPart::Str(&input.ledger_memo_root),
            ],
        );
        if self.accounting_entries.contains_key(&entry_id) {
            return Err("accounting entry already exists".to_string());
        }
        let entry = ReinsuranceClaimAccountingEntry {
            entry_id: entry_id.clone(),
            claim_id: input.claim_id.clone(),
            side: input.side,
            amount_atomic: input.amount_atomic,
            account_commitment_root: input.account_commitment_root,
            ledger_memo_root: input.ledger_memo_root,
        };
        match input.side {
            ClaimAccountingSide::ReserveLock
            | ClaimAccountingSide::ReinsurerLiability
            | ClaimAccountingSide::Payout => {
                self.reserve_available_atomic = self
                    .reserve_available_atomic
                    .saturating_sub(input.amount_atomic);
            }
            ClaimAccountingSide::Refund => {
                self.reserve_available_atomic = self
                    .reserve_available_atomic
                    .saturating_add(input.amount_atomic);
            }
            ClaimAccountingSide::ClaimEscrow
            | ClaimAccountingSide::CedentLiability
            | ClaimAccountingSide::Fee => {}
        }
        if let Some(claim) = self.receipt_claims.get_mut(&input.claim_id) {
            claim.status = ClaimFinalityStatus::AccountingReserved;
        }
        self.accounting_entries.insert(entry_id.clone(), entry);
        self.refresh();
        Ok(entry_id)
    }

    pub fn finalize_batch(&mut self, input: ClaimFinalityBatchInput) -> Result<String> {
        self.config.validate()?;
        require_commitment("compression_root", &input.compression_root)?;
        require_commitment(
            "fee_sponsor_commitment_root",
            &input.fee_sponsor_commitment_root,
        )?;
        if input.claim_ids.len() < usize::from(self.config.min_batch_size)
            || input.claim_ids.len() > usize::from(self.config.low_fee_batch_limit)
        {
            return Err("claim batch size violates low-fee policy".to_string());
        }
        if input.batch_fee_micro_units > self.config.max_batch_fee_micro_units {
            return Err("batch fee exceeds low-fee finality policy".to_string());
        }
        if !input.finalized_claim_ids.is_subset(&input.claim_ids)
            || !input.paid_claim_ids.is_subset(&input.claim_ids)
            || !input.rejected_claim_ids.is_subset(&input.claim_ids)
        {
            return Err("batch outcome sets must be subsets of claim set".to_string());
        }
        if !input.paid_claim_ids.is_subset(&input.finalized_claim_ids) {
            return Err("paid claims must also be finalized".to_string());
        }
        for claim_id in &input.claim_ids {
            let claim = self
                .receipt_claims
                .get(claim_id)
                .ok_or_else(|| format!("unknown claim in finality batch: {claim_id}"))?;
            if self.slot < claim.finality_slot {
                return Err("claim cannot be finalized before finality slot".to_string());
            }
            if !self
                .finality_witnesses
                .values()
                .any(|witness| witness.claim_id == *claim_id)
            {
                return Err("each batched claim requires a winternitz witness".to_string());
            }
        }
        let batch_id = deterministic_id(
            "claim-finality-batch",
            &[
                HashPart::U64(input.epoch),
                HashPart::Str(&input.compression_root),
                HashPart::Str(&input.fee_sponsor_commitment_root),
                HashPart::U64(input.batch_fee_micro_units),
            ],
        );
        if self.finality_batches.contains_key(&batch_id) {
            return Err("claim finality batch already exists".to_string());
        }
        for claim_id in &input.claim_ids {
            if let Some(claim) = self.receipt_claims.get_mut(claim_id) {
                claim.status = ClaimFinalityStatus::Queued;
            }
        }
        for claim_id in &input.finalized_claim_ids {
            if let Some(claim) = self.receipt_claims.get_mut(claim_id) {
                claim.status = ClaimFinalityStatus::Finalized;
            }
        }
        for claim_id in &input.paid_claim_ids {
            if let Some(claim) = self.receipt_claims.get_mut(claim_id) {
                claim.status = ClaimFinalityStatus::Paid;
            }
        }
        for claim_id in &input.rejected_claim_ids {
            if let Some(claim) = self.receipt_claims.get_mut(claim_id) {
                claim.status = ClaimFinalityStatus::Rejected;
            }
        }
        let batch = LowFeeClaimFinalityBatch {
            batch_id: batch_id.clone(),
            epoch: input.epoch,
            claim_ids: input.claim_ids,
            finalized_claim_ids: input.finalized_claim_ids,
            paid_claim_ids: input.paid_claim_ids,
            rejected_claim_ids: input.rejected_claim_ids,
            compression_root: input.compression_root,
            fee_sponsor_commitment_root: input.fee_sponsor_commitment_root,
            batch_fee_micro_units: input.batch_fee_micro_units,
            status: ClaimBatchStatus::Posted,
        };
        self.finality_batches.insert(batch_id.clone(), batch);
        self.refresh();
        Ok(batch_id)
    }

    pub fn expire_old_claims(&mut self, slot: u64) -> usize {
        let mut expired = 0;
        for claim in self.receipt_claims.values_mut() {
            if slot > claim.expires_slot + self.config.proof_grace_slots
                && matches!(
                    claim.status,
                    ClaimFinalityStatus::ReceiptCommitted
                        | ClaimFinalityStatus::WinternitzKeyed
                        | ClaimFinalityStatus::WitnessAccepted
                        | ClaimFinalityStatus::AccountingReserved
                        | ClaimFinalityStatus::Queued
                )
            {
                claim.status = ClaimFinalityStatus::Expired;
                expired += 1;
            }
        }
        self.slot = self.slot.max(slot);
        self.refresh();
        expired
    }

    pub fn state_root(&self) -> String {
        self.compute_roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "hash_suite": HASH_SUITE,
            "winternitz_claim_finality_suite": WINTERNITZ_CLAIM_FINALITY_SUITE,
            "confidential_exit_receipt_suite": CONFIDENTIAL_EXIT_RECEIPT_SUITE,
            "reinsurance_ledger_suite": REINSURANCE_LEDGER_SUITE,
            "low_fee_aggregation_suite": LOW_FEE_AGGREGATION_SUITE,
            "roots_only_public_record_suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            receipt_commitments: self.receipt_claims.len() as u64,
            winternitz_key_commitments: self.winternitz_keys.len() as u64,
            finality_witnesses: self.finality_witnesses.len() as u64,
            accounting_entries: self.accounting_entries.len() as u64,
            finality_batches: self.finality_batches.len() as u64,
            finalized_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == ClaimFinalityStatus::Finalized)
                .count() as u64,
            paid_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == ClaimFinalityStatus::Paid)
                .count() as u64,
            rejected_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == ClaimFinalityStatus::Rejected)
                .count() as u64,
            expired_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == ClaimFinalityStatus::Expired)
                .count() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            total_reserved_atomic: self.sum_accounting(ClaimAccountingSide::ReserveLock),
            total_escrowed_atomic: self.sum_accounting(ClaimAccountingSide::ClaimEscrow),
            total_reinsurer_liability_atomic: self
                .sum_accounting(ClaimAccountingSide::ReinsurerLiability),
            total_cedent_liability_atomic: self
                .sum_accounting(ClaimAccountingSide::CedentLiability),
            total_paid_atomic: self.sum_accounting(ClaimAccountingSide::Payout),
            total_refunded_atomic: self.sum_accounting(ClaimAccountingSide::Refund),
            total_batch_fee_micro_units: self
                .finality_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn sum_accounting(&self, side: ClaimAccountingSide) -> u64 {
        self.accounting_entries
            .values()
            .filter(|entry| entry.side == side)
            .map(|entry| entry.amount_atomic)
            .sum()
    }

    fn compute_roots(&self) -> Roots {
        let receipt_commitment_root = record_root(
            "receipt-commitments",
            self.receipt_claims
                .values()
                .map(ExitReceiptClaim::roots_only_record)
                .collect(),
        );
        let winternitz_key_root = record_root(
            "winternitz-keys",
            self.winternitz_keys
                .values()
                .map(WinternitzKeyCommitment::roots_only_record)
                .collect(),
        );
        let winternitz_witness_root = record_root(
            "winternitz-witnesses",
            self.finality_witnesses
                .values()
                .map(WinternitzFinalityWitness::roots_only_record)
                .collect(),
        );
        let accounting_entry_root = record_root(
            "claim-accounting-entries",
            self.accounting_entries
                .values()
                .map(ReinsuranceClaimAccountingEntry::roots_only_record)
                .collect(),
        );
        let finality_batch_root = record_root(
            "low-fee-claim-finality-batches",
            self.finality_batches
                .values()
                .map(LowFeeClaimFinalityBatch::roots_only_record)
                .collect(),
        );
        let nullifier_root = record_root(
            "claim-nullifiers",
            self.spent_nullifiers
                .iter()
                .map(|nullifier| json!({ "claim_nullifier": nullifier }))
                .collect(),
        );
        let reserve_accounting_root = value_root(
            "reserve-accounting",
            &json!({
                "accounting_entry_root": accounting_entry_root,
                "reserve_available_atomic": self.reserve_available_atomic,
                "redacted_counters": self.counters.public_record(),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "receipt_commitment_root": receipt_commitment_root,
                "winternitz_key_root": winternitz_key_root,
                "winternitz_witness_root": winternitz_witness_root,
                "accounting_entry_root": accounting_entry_root,
                "finality_batch_root": finality_batch_root,
                "nullifier_root": nullifier_root,
                "reserve_accounting_root": reserve_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&receipt_commitment_root),
                HashPart::Str(&winternitz_key_root),
                HashPart::Str(&winternitz_witness_root),
                HashPart::Str(&accounting_entry_root),
                HashPart::Str(&finality_batch_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&reserve_accounting_root),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.reserve_available_atomic),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            receipt_commitment_root,
            winternitz_key_root,
            winternitz_witness_root,
            accounting_entry_root,
            finality_batch_root,
            nullifier_root,
            reserve_accounting_root,
            public_record_root,
            state_root,
        }
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            reserve_available_atomic: DEFAULT_REINSURANCE_POOL_ATOMIC,
            counters: Counters::default(),
            roots: Roots::default(),
            receipt_claims: BTreeMap::new(),
            winternitz_keys: BTreeMap::new(),
            finality_witnesses: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            finality_batches: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    fn seed_devnet(&mut self) {
        for index in 0_u64..5 {
            let receipt_slot =
                self.slot.saturating_sub(self.config.finality_delay_slots) + index * 8;
            let claim_id = self
                .anchor_receipt(ExitReceiptCommitmentInput {
                    receipt_commitment_root: sample_root("receipt-commitment", index),
                    claimant_commitment_root: sample_root("claimant", index),
                    cedent_commitment_root: sample_root("cedent", index),
                    reinsurer_commitment_root: sample_root("reinsurer", index),
                    claim_amount_commitment: sample_root("claim-amount", index),
                    policy_commitment_root: sample_root("policy", index),
                    receipt_slot,
                })
                .expect("devnet receipt anchors are valid");
            self.commit_winternitz_key(WinternitzKeyCommitmentInput {
                claim_id: claim_id.clone(),
                public_key_root: sample_root("winternitz-public-key", index),
                chain_commitment_root: sample_root("winternitz-chain", index),
                checksum_commitment_root: sample_root("winternitz-checksum", index),
                key_epoch: self.epoch,
            })
            .expect("devnet winternitz key commitments are valid");
            self.submit_winternitz_witness(WinternitzFinalityWitnessInput {
                claim_id: claim_id.clone(),
                signature_root: sample_root("winternitz-signature", index),
                message_digest_root: sample_root("message-digest", index),
                witness_transcript_root: sample_root("witness-transcript", index),
                pq_security_bits: self.config.min_pq_security_bits,
                witness_slot: receipt_slot + 16,
            })
            .expect("devnet winternitz witnesses are valid");
            self.lock_accounting(ClaimAccountingEntryInput {
                claim_id: claim_id.clone(),
                side: ClaimAccountingSide::ClaimEscrow,
                amount_atomic: self.config.claim_escrow_atomic,
                account_commitment_root: sample_root("claim-escrow", index),
                ledger_memo_root: sample_root("escrow-memo", index),
            })
            .expect("devnet escrow entries are valid");
            self.lock_accounting(ClaimAccountingEntryInput {
                claim_id,
                side: ClaimAccountingSide::ReserveLock,
                amount_atomic: self.config.claim_escrow_atomic / 2,
                account_commitment_root: sample_root("reserve-lock", index),
                ledger_memo_root: sample_root("reserve-memo", index),
            })
            .expect("devnet reserve entries are valid");
        }
        let claim_ids = self.receipt_claims.keys().cloned().collect::<BTreeSet<_>>();
        let finalized_claim_ids = self
            .receipt_claims
            .keys()
            .take(4)
            .cloned()
            .collect::<BTreeSet<_>>();
        let paid_claim_ids = self
            .receipt_claims
            .keys()
            .take(2)
            .cloned()
            .collect::<BTreeSet<_>>();
        self.finalize_batch(ClaimFinalityBatchInput {
            epoch: self.epoch,
            claim_ids,
            finalized_claim_ids,
            paid_claim_ids,
            rejected_claim_ids: BTreeSet::new(),
            compression_root: sample_root("claim-finality-compression", 0),
            fee_sponsor_commitment_root: sample_root("fee-sponsor", 0),
            batch_fee_micro_units: 72,
        })
        .expect("devnet finality batch is valid");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-{domain}-ID"
        ),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-{domain}"
        ),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-WINTERNITZ-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-{domain}"
        ),
        &values,
    )
}

fn require_commitment(label: &str, value: &str) -> Result<()> {
    if value.len() < 16 {
        return Err(format!("{label} must be a non-trivial commitment"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{label} must not contain whitespace"));
    }
    Ok(())
}
