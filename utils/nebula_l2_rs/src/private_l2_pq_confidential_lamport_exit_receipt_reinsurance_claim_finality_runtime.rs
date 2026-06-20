use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialLamportExitReceiptReinsuranceClaimFinalityRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LAMPORT_EXIT_RECEIPT_REINSURANCE_CLAIM_FINALITY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-lamport-exit-receipt-reinsurance-claim-finality-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LAMPORT_EXIT_RECEIPT_REINSURANCE_CLAIM_FINALITY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LAMPORT_CLAIM_FINALITY_SUITE: &str =
    "lamport-hash-based-exit-receipt-reinsurance-claim-finality-v1";
pub const CONFIDENTIAL_EXIT_RECEIPT_SUITE: &str =
    "confidential-private-l2-exit-receipt-commitment-v1";
pub const REINSURANCE_ACCOUNTING_SUITE: &str = "privacy-preserving-reinsurance-claim-accounting-v1";
pub const LOW_FEE_FINALITY_BATCH_SUITE: &str =
    "low-fee-lamport-reinsurance-claim-finality-batch-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-lamport-reinsurance-claim-finality-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 8_912_000;
pub const DEVNET_EPOCH: u64 = 37_134;
pub const DEVNET_SLOT: u64 = 704;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LAMPORT_PAIR_BITS: u16 = 256;
pub const DEFAULT_LAMPORT_ROUNDS: u16 = 2;
pub const DEFAULT_FINALITY_DELAY_SLOTS: u64 = 1_536;
pub const DEFAULT_CLAIM_WINDOW_SLOTS: u64 = 5_120;
pub const DEFAULT_RECEIPT_RETENTION_EPOCHS: u64 = 96;
pub const DEFAULT_REINSURANCE_POOL_ATOMIC: u64 = 54_000_000_000;
pub const DEFAULT_MIN_RESERVE_ATOMIC: u64 = 9_000_000_000;
pub const DEFAULT_MAX_CLAIM_PAYOUT_ATOMIC: u64 = 12_000_000_000;
pub const DEFAULT_CLAIM_ESCROW_ATOMIC: u64 = 900_000_000;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: u16 = 768;
pub const DEFAULT_MIN_BATCH_SIZE: u16 = 2;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 120;
pub const DEFAULT_EPOCH_BUCKET_TARGET_CLAIMS: u64 = 32_768;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Drafted,
    ReceiptAnchored,
    LamportWitnessed,
    AccountingLocked,
    FinalityQueued,
    Finalized,
    Paid,
    Rejected,
    Expired,
}

impl FinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::ReceiptAnchored => "receipt_anchored",
            Self::LamportWitnessed => "lamport_witnessed",
            Self::AccountingLocked => "accounting_locked",
            Self::FinalityQueued => "finality_queued",
            Self::Finalized => "finalized",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingSide {
    ReserveLock,
    ClaimEscrow,
    Payout,
    Refund,
    Fee,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub lamport_claim_finality_suite: String,
    pub confidential_exit_receipt_suite: String,
    pub reinsurance_accounting_suite: String,
    pub low_fee_finality_batch_suite: String,
    pub roots_only_public_record_suite: String,
    pub min_pq_security_bits: u16,
    pub lamport_pair_bits: u16,
    pub lamport_rounds: u16,
    pub finality_delay_slots: u64,
    pub claim_window_slots: u64,
    pub receipt_retention_epochs: u64,
    pub reinsurance_pool_atomic: u64,
    pub min_reserve_atomic: u64,
    pub max_claim_payout_atomic: u64,
    pub claim_escrow_atomic: u64,
    pub low_fee_batch_limit: u16,
    pub min_batch_size: u16,
    pub max_batch_fee_micro_units: u64,
    pub epoch_bucket_target_claims: u64,
    pub lamport_witnesses_required: bool,
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
            lamport_claim_finality_suite: LAMPORT_CLAIM_FINALITY_SUITE.to_string(),
            confidential_exit_receipt_suite: CONFIDENTIAL_EXIT_RECEIPT_SUITE.to_string(),
            reinsurance_accounting_suite: REINSURANCE_ACCOUNTING_SUITE.to_string(),
            low_fee_finality_batch_suite: LOW_FEE_FINALITY_BATCH_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            lamport_pair_bits: DEFAULT_LAMPORT_PAIR_BITS,
            lamport_rounds: DEFAULT_LAMPORT_ROUNDS,
            finality_delay_slots: DEFAULT_FINALITY_DELAY_SLOTS,
            claim_window_slots: DEFAULT_CLAIM_WINDOW_SLOTS,
            receipt_retention_epochs: DEFAULT_RECEIPT_RETENTION_EPOCHS,
            reinsurance_pool_atomic: DEFAULT_REINSURANCE_POOL_ATOMIC,
            min_reserve_atomic: DEFAULT_MIN_RESERVE_ATOMIC,
            max_claim_payout_atomic: DEFAULT_MAX_CLAIM_PAYOUT_ATOMIC,
            claim_escrow_atomic: DEFAULT_CLAIM_ESCROW_ATOMIC,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            epoch_bucket_target_claims: DEFAULT_EPOCH_BUCKET_TARGET_CLAIMS,
            lamport_witnesses_required: true,
            confidential_receipts_required: true,
            roots_only_public_records_required: true,
            low_fee_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below lamport claim finality minimum".to_string());
        }
        if self.lamport_pair_bits < DEFAULT_LAMPORT_PAIR_BITS || self.lamport_rounds == 0 {
            return Err("invalid lamport claim finality key schedule".to_string());
        }
        if self.finality_delay_slots == 0 || self.claim_window_slots < self.finality_delay_slots {
            return Err("invalid claim finality timing window".to_string());
        }
        if self.receipt_retention_epochs == 0 || self.epoch_bucket_target_claims == 0 {
            return Err("retention and epoch bucket targets must be positive".to_string());
        }
        if self.reinsurance_pool_atomic <= self.min_reserve_atomic
            || self.max_claim_payout_atomic == 0
            || self.claim_escrow_atomic == 0
        {
            return Err("invalid reinsurance claim accounting policy".to_string());
        }
        if self.low_fee_batch_limit == 0
            || self.min_batch_size == 0
            || self.min_batch_size > self.low_fee_batch_limit
            || self.max_batch_fee_micro_units == 0
        {
            return Err("invalid low-fee finality batch policy".to_string());
        }
        if !self.lamport_witnesses_required
            || !self.confidential_receipts_required
            || !self.roots_only_public_records_required
        {
            return Err(
                "lamport witnesses, confidential receipts, and roots-only records are mandatory"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn roots_only_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "suites": {
                "lamport_claim_finality": self.lamport_claim_finality_suite,
                "confidential_exit_receipt": self.confidential_exit_receipt_suite,
                "reinsurance_accounting": self.reinsurance_accounting_suite,
                "low_fee_finality_batch": self.low_fee_finality_batch_suite,
                "roots_only_public_record": self.roots_only_public_record_suite,
            },
            "security": {
                "min_pq_security_bits": self.min_pq_security_bits,
                "lamport_pair_bits": self.lamport_pair_bits,
                "lamport_rounds": self.lamport_rounds,
            },
            "fee_policy": {
                "low_fee_batch_limit": self.low_fee_batch_limit,
                "min_batch_size": self.min_batch_size,
                "max_batch_fee_micro_units": self.max_batch_fee_micro_units,
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub receipt_commitments: u64,
    pub lamport_witnesses: u64,
    pub accounting_entries: u64,
    pub finality_batches: u64,
    pub finalized_claims: u64,
    pub paid_claims: u64,
    pub rejected_claims: u64,
    pub expired_claims: u64,
    pub total_reserved_atomic: u64,
    pub total_escrowed_atomic: u64,
    pub total_paid_atomic: u64,
    pub total_batch_fee_micro_units: u64,
}

impl Counters {
    fn roots_only_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub receipt_commitment_root: String,
    pub lamport_witness_root: String,
    pub accounting_entry_root: String,
    pub finality_batch_root: String,
    pub nullifier_root: String,
    pub private_accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    fn roots_only_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceiptCommitmentInput {
    pub receipt_commitment_root: String,
    pub claimant_commitment_root: String,
    pub insurer_commitment_root: String,
    pub claim_amount_commitment: String,
    pub receipt_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LamportFinalityWitnessInput {
    pub claim_id: String,
    pub lamport_public_root: String,
    pub lamport_signature_root: String,
    pub witness_transcript_root: String,
    pub pq_security_bits: u16,
    pub witness_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountingEntryInput {
    pub claim_id: String,
    pub side: AccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FinalityBatchInput {
    pub epoch: u64,
    pub claim_ids: BTreeSet<String>,
    pub finalized_claim_ids: BTreeSet<String>,
    pub rejected_claim_ids: BTreeSet<String>,
    pub compression_root: String,
    pub batch_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitReceiptClaim {
    pub claim_id: String,
    pub receipt_commitment_root: String,
    pub claimant_commitment_root: String,
    pub insurer_commitment_root: String,
    pub claim_amount_commitment: String,
    pub claim_nullifier: String,
    pub receipt_slot: u64,
    pub finality_slot: u64,
    pub status: FinalityStatus,
}

impl ExitReceiptClaim {
    fn new(input: ExitReceiptCommitmentInput, config: &Config) -> Result<Self> {
        require_commitment("receipt_commitment_root", &input.receipt_commitment_root)?;
        require_commitment("claimant_commitment_root", &input.claimant_commitment_root)?;
        require_commitment("insurer_commitment_root", &input.insurer_commitment_root)?;
        require_commitment("claim_amount_commitment", &input.claim_amount_commitment)?;
        let claim_nullifier = value_root(
            "claim-nullifier",
            &json!({
                "receipt_commitment_root": input.receipt_commitment_root,
                "claimant_commitment_root": input.claimant_commitment_root,
                "receipt_slot": input.receipt_slot,
            }),
        );
        let claim_id = deterministic_id(
            "exit-receipt-claim",
            &[
                HashPart::Str(&input.receipt_commitment_root),
                HashPart::Str(&claim_nullifier),
                HashPart::U64(input.receipt_slot),
            ],
        );
        Ok(Self {
            claim_id,
            receipt_commitment_root: input.receipt_commitment_root,
            claimant_commitment_root: input.claimant_commitment_root,
            insurer_commitment_root: input.insurer_commitment_root,
            claim_amount_commitment: input.claim_amount_commitment,
            claim_nullifier,
            receipt_slot: input.receipt_slot,
            finality_slot: input
                .receipt_slot
                .saturating_add(config.finality_delay_slots),
            status: FinalityStatus::ReceiptAnchored,
        })
    }

    fn roots_only_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "receipt_commitment_root": self.receipt_commitment_root,
            "claim_nullifier": self.claim_nullifier,
            "receipt_slot": self.receipt_slot,
            "finality_slot": self.finality_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LamportFinalityWitness {
    pub witness_id: String,
    pub claim_id: String,
    pub lamport_public_root: String,
    pub lamport_signature_root: String,
    pub lamport_chain_position_root: String,
    pub witness_transcript_root: String,
    pub pq_security_bits: u16,
    pub witness_slot: u64,
}

impl LamportFinalityWitness {
    fn new(input: LamportFinalityWitnessInput, config: &Config) -> Result<Self> {
        require_commitment("lamport_public_root", &input.lamport_public_root)?;
        require_commitment("lamport_signature_root", &input.lamport_signature_root)?;
        require_commitment("witness_transcript_root", &input.witness_transcript_root)?;
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("lamport finality witness below pq security floor".to_string());
        }
        let lamport_chain_position_root = value_root(
            "lamport-chain-position",
            &json!({
                "claim_id": input.claim_id,
                "lamport_public_root": input.lamport_public_root,
                "witness_slot": input.witness_slot,
            }),
        );
        let witness_id = deterministic_id(
            "lamport-finality-witness",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&input.lamport_public_root),
                HashPart::Str(&input.lamport_signature_root),
                HashPart::U64(input.witness_slot),
            ],
        );
        Ok(Self {
            witness_id,
            claim_id: input.claim_id,
            lamport_public_root: input.lamport_public_root,
            lamport_signature_root: input.lamport_signature_root,
            lamport_chain_position_root,
            witness_transcript_root: input.witness_transcript_root,
            pq_security_bits: input.pq_security_bits,
            witness_slot: input.witness_slot,
        })
    }

    fn roots_only_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "claim_id": self.claim_id,
            "lamport_public_root": self.lamport_public_root,
            "lamport_signature_root": self.lamport_signature_root,
            "lamport_chain_position_root": self.lamport_chain_position_root,
            "witness_transcript_root": self.witness_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "witness_slot": self.witness_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReinsuranceAccountingEntry {
    pub entry_id: String,
    pub claim_id: String,
    pub side: AccountingSide,
    pub amount_atomic: u64,
    pub account_commitment_root: String,
    pub entry_root: String,
}

impl ReinsuranceAccountingEntry {
    fn new(input: AccountingEntryInput) -> Result<Self> {
        if input.amount_atomic == 0 {
            return Err("accounting amount must be positive".to_string());
        }
        require_commitment("account_commitment_root", &input.account_commitment_root)?;
        let entry_root = value_root(
            "reinsurance-accounting-entry",
            &json!({
                "claim_id": input.claim_id,
                "side": input.side,
                "amount_atomic": input.amount_atomic,
                "account_commitment_root": input.account_commitment_root,
            }),
        );
        let entry_id = deterministic_id(
            "accounting-entry",
            &[
                HashPart::Str(&input.claim_id),
                HashPart::Str(&entry_root),
                HashPart::U64(input.amount_atomic),
            ],
        );
        Ok(Self {
            entry_id,
            claim_id: input.claim_id,
            side: input.side,
            amount_atomic: input.amount_atomic,
            account_commitment_root: input.account_commitment_root,
            entry_root,
        })
    }

    fn roots_only_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "claim_id": self.claim_id,
            "side": self.side,
            "amount_atomic": self.amount_atomic,
            "entry_root": self.entry_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeFinalityBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub claim_ids: BTreeSet<String>,
    pub finalized_claim_ids: BTreeSet<String>,
    pub rejected_claim_ids: BTreeSet<String>,
    pub aggregate_claim_root: String,
    pub aggregate_witness_root: String,
    pub compression_root: String,
    pub batch_fee_micro_units: u64,
    pub per_claim_fee_micro_units: u64,
}

impl LowFeeFinalityBatch {
    fn roots_only_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "aggregate_claim_root": self.aggregate_claim_root,
            "aggregate_witness_root": self.aggregate_witness_root,
            "compression_root": self.compression_root,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "per_claim_fee_micro_units": self.per_claim_fee_micro_units,
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
    pub lamport_witnesses: BTreeMap<String, LamportFinalityWitness>,
    pub accounting_entries: BTreeMap<String, ReinsuranceAccountingEntry>,
    pub finality_batches: BTreeMap<String, LowFeeFinalityBatch>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            reserve_available_atomic: config.reinsurance_pool_atomic,
            config,
            height,
            epoch,
            slot,
            counters: Counters::default(),
            roots: Roots::default(),
            receipt_claims: BTreeMap::new(),
            lamport_witnesses: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            finality_batches: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH, DEVNET_SLOT)
            .expect("devnet lamport claim finality config is valid");
        state.seed_devnet();
        state
    }

    pub fn anchor_receipt(&mut self, input: ExitReceiptCommitmentInput) -> Result<String> {
        let claim = ExitReceiptClaim::new(input, &self.config)?;
        if self.spent_nullifiers.contains(&claim.claim_nullifier) {
            return Err("exit receipt claim nullifier already anchored".to_string());
        }
        let claim_id = claim.claim_id.clone();
        self.spent_nullifiers.insert(claim.claim_nullifier.clone());
        self.receipt_claims.insert(claim_id.clone(), claim);
        self.refresh();
        Ok(claim_id)
    }

    pub fn submit_lamport_witness(&mut self, input: LamportFinalityWitnessInput) -> Result<String> {
        let claim = self
            .receipt_claims
            .get_mut(&input.claim_id)
            .ok_or_else(|| "cannot witness unknown exit receipt claim".to_string())?;
        if input.witness_slot
            > claim
                .receipt_slot
                .saturating_add(self.config.claim_window_slots)
        {
            return Err("lamport finality witness outside claim window".to_string());
        }
        let witness = LamportFinalityWitness::new(input, &self.config)?;
        let witness_id = witness.witness_id.clone();
        claim.status = FinalityStatus::LamportWitnessed;
        self.lamport_witnesses.insert(witness_id.clone(), witness);
        self.refresh();
        Ok(witness_id)
    }

    pub fn lock_accounting(&mut self, input: AccountingEntryInput) -> Result<String> {
        let claim = self
            .receipt_claims
            .get_mut(&input.claim_id)
            .ok_or_else(|| "cannot account for unknown exit receipt claim".to_string())?;
        if input.side == AccountingSide::Payout
            && input.amount_atomic > self.reserve_available_atomic
        {
            return Err("reinsurance reserve insufficient for confidential payout".to_string());
        }
        let entry = ReinsuranceAccountingEntry::new(input)?;
        let entry_id = entry.entry_id.clone();
        match entry.side {
            AccountingSide::ReserveLock => {
                self.reserve_available_atomic = self
                    .reserve_available_atomic
                    .saturating_sub(entry.amount_atomic);
            }
            AccountingSide::ClaimEscrow => {}
            AccountingSide::Payout => {
                self.reserve_available_atomic = self
                    .reserve_available_atomic
                    .saturating_sub(entry.amount_atomic);
            }
            AccountingSide::Refund => {
                self.reserve_available_atomic = self
                    .reserve_available_atomic
                    .saturating_add(entry.amount_atomic);
            }
            AccountingSide::Fee => {}
        }
        claim.status = FinalityStatus::AccountingLocked;
        self.accounting_entries.insert(entry_id.clone(), entry);
        self.refresh();
        Ok(entry_id)
    }

    pub fn finalize_batch(&mut self, input: FinalityBatchInput) -> Result<String> {
        if input.claim_ids.len() < usize::from(self.config.min_batch_size)
            || input.claim_ids.len() > usize::from(self.config.low_fee_batch_limit)
        {
            return Err("claim finality batch outside configured low-fee bounds".to_string());
        }
        if input.batch_fee_micro_units > self.config.max_batch_fee_micro_units {
            return Err("claim finality batch fee above low-fee ceiling".to_string());
        }
        require_commitment("compression_root", &input.compression_root)?;
        for claim_id in &input.claim_ids {
            let claim = self
                .receipt_claims
                .get_mut(claim_id)
                .ok_or_else(|| "cannot finalize unknown claim".to_string())?;
            if input.finalized_claim_ids.contains(claim_id) {
                claim.status = FinalityStatus::Finalized;
            } else if input.rejected_claim_ids.contains(claim_id) {
                claim.status = FinalityStatus::Rejected;
            } else {
                claim.status = FinalityStatus::FinalityQueued;
            }
        }
        let batch_id = deterministic_id(
            "low-fee-finality-batch",
            &[
                HashPart::U64(input.epoch),
                HashPart::U64(input.claim_ids.len() as u64),
                HashPart::Str(&input.compression_root),
            ],
        );
        let aggregate_claim_root = record_root(
            "batch-aggregate-claims",
            input
                .claim_ids
                .iter()
                .filter_map(|claim_id| self.receipt_claims.get(claim_id))
                .map(ExitReceiptClaim::roots_only_record)
                .collect(),
        );
        let aggregate_witness_root = record_root(
            "batch-aggregate-witnesses",
            self.lamport_witnesses
                .values()
                .filter(|witness| input.claim_ids.contains(&witness.claim_id))
                .map(LamportFinalityWitness::roots_only_record)
                .collect(),
        );
        let per_claim_fee_micro_units = input.batch_fee_micro_units / input.claim_ids.len() as u64;
        let batch = LowFeeFinalityBatch {
            batch_id: batch_id.clone(),
            epoch: input.epoch,
            claim_ids: input.claim_ids,
            finalized_claim_ids: input.finalized_claim_ids,
            rejected_claim_ids: input.rejected_claim_ids,
            aggregate_claim_root,
            aggregate_witness_root,
            compression_root: input.compression_root,
            batch_fee_micro_units: input.batch_fee_micro_units,
            per_claim_fee_micro_units,
        };
        self.finality_batches.insert(batch_id.clone(), batch);
        self.refresh();
        Ok(batch_id)
    }

    pub fn pay_finalized_claim(&mut self, claim_id: &str, amount_atomic: u64) -> Result<()> {
        if amount_atomic == 0 || amount_atomic > self.config.max_claim_payout_atomic {
            return Err("claim payout outside configured bounds".to_string());
        }
        if self.reserve_available_atomic.saturating_sub(amount_atomic)
            < self.config.min_reserve_atomic
        {
            return Err("claim payout would breach minimum reinsurance reserve".to_string());
        }
        let claim = self
            .receipt_claims
            .get_mut(claim_id)
            .ok_or_else(|| "cannot pay unknown exit receipt claim".to_string())?;
        if claim.status != FinalityStatus::Finalized {
            return Err("only finalized claims can be paid".to_string());
        }
        claim.status = FinalityStatus::Paid;
        self.reserve_available_atomic = self.reserve_available_atomic.saturating_sub(amount_atomic);
        let entry = ReinsuranceAccountingEntry::new(AccountingEntryInput {
            claim_id: claim_id.to_string(),
            side: AccountingSide::Payout,
            amount_atomic,
            account_commitment_root: value_root(
                "confidential-payout-account",
                &json!({ "claim_id": claim_id, "slot": self.slot }),
            ),
        })?;
        self.accounting_entries
            .insert(entry.entry_id.clone(), entry);
        self.refresh();
        Ok(())
    }

    pub fn expire_claims(&mut self, slot: u64) -> Result<u64> {
        self.slot = slot;
        let mut expired = 0_u64;
        for claim in self.receipt_claims.values_mut() {
            if !matches!(
                claim.status,
                FinalityStatus::Finalized | FinalityStatus::Paid | FinalityStatus::Rejected
            ) && slot
                > claim
                    .receipt_slot
                    .saturating_add(self.config.claim_window_slots)
            {
                claim.status = FinalityStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        if expired > 0 {
            self.refresh();
        }
        Ok(expired)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "network": self.config.network,
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "hash_suite": self.config.hash_suite,
            "suites": {
                "lamport_claim_finality": self.config.lamport_claim_finality_suite,
                "confidential_exit_receipt": self.config.confidential_exit_receipt_suite,
                "reinsurance_accounting": self.config.reinsurance_accounting_suite,
                "low_fee_finality_batch": self.config.low_fee_finality_batch_suite,
                "roots_only_public_record": self.config.roots_only_public_record_suite,
            },
            "counters": self.counters.roots_only_record(),
            "roots": self.roots.roots_only_record(),
            "state_root": self.state_root(),
        })
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            receipt_commitments: self.receipt_claims.len() as u64,
            lamport_witnesses: self.lamport_witnesses.len() as u64,
            accounting_entries: self.accounting_entries.len() as u64,
            finality_batches: self.finality_batches.len() as u64,
            finalized_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == FinalityStatus::Finalized)
                .count() as u64,
            paid_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == FinalityStatus::Paid)
                .count() as u64,
            rejected_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == FinalityStatus::Rejected)
                .count() as u64,
            expired_claims: self
                .receipt_claims
                .values()
                .filter(|claim| claim.status == FinalityStatus::Expired)
                .count() as u64,
            total_reserved_atomic: self
                .accounting_entries
                .values()
                .filter(|entry| entry.side == AccountingSide::ReserveLock)
                .map(|entry| entry.amount_atomic)
                .sum(),
            total_escrowed_atomic: self
                .accounting_entries
                .values()
                .filter(|entry| entry.side == AccountingSide::ClaimEscrow)
                .map(|entry| entry.amount_atomic)
                .sum(),
            total_paid_atomic: self
                .accounting_entries
                .values()
                .filter(|entry| entry.side == AccountingSide::Payout)
                .map(|entry| entry.amount_atomic)
                .sum(),
            total_batch_fee_micro_units: self
                .finality_batches
                .values()
                .map(|batch| batch.batch_fee_micro_units)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let receipt_commitment_root = record_root(
            "receipt-commitments",
            self.receipt_claims
                .values()
                .map(ExitReceiptClaim::roots_only_record)
                .collect(),
        );
        let lamport_witness_root = record_root(
            "lamport-witnesses",
            self.lamport_witnesses
                .values()
                .map(LamportFinalityWitness::roots_only_record)
                .collect(),
        );
        let accounting_entry_root = record_root(
            "accounting-entries",
            self.accounting_entries
                .values()
                .map(ReinsuranceAccountingEntry::roots_only_record)
                .collect(),
        );
        let finality_batch_root = record_root(
            "finality-batches",
            self.finality_batches
                .values()
                .map(LowFeeFinalityBatch::roots_only_record)
                .collect(),
        );
        let nullifier_root = record_root(
            "claim-nullifiers",
            self.spent_nullifiers
                .iter()
                .map(|nullifier| json!({ "claim_nullifier": nullifier }))
                .collect(),
        );
        let private_accounting_root = value_root(
            "private-accounting",
            &json!({
                "accounting_entry_root": accounting_entry_root,
                "reserve_available_atomic": self.reserve_available_atomic,
                "counters": self.counters.roots_only_record(),
            }),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.roots_only_record(),
                "counters": self.counters.roots_only_record(),
                "receipt_commitment_root": receipt_commitment_root,
                "lamport_witness_root": lamport_witness_root,
                "accounting_entry_root": accounting_entry_root,
                "finality_batch_root": finality_batch_root,
                "nullifier_root": nullifier_root,
                "private_accounting_root": private_accounting_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-STATE",
            &[
                HashPart::Json(&self.config.roots_only_record()),
                HashPart::Json(&self.counters.roots_only_record()),
                HashPart::Str(&receipt_commitment_root),
                HashPart::Str(&lamport_witness_root),
                HashPart::Str(&accounting_entry_root),
                HashPart::Str(&finality_batch_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&private_accounting_root),
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
            lamport_witness_root,
            accounting_entry_root,
            finality_batch_root,
            nullifier_root,
            private_accounting_root,
            public_record_root,
            state_root,
        }
    }

    fn seed_devnet(&mut self) {
        for index in 0_u64..4 {
            let claim_id = self
                .anchor_receipt(ExitReceiptCommitmentInput {
                    receipt_commitment_root: sample_root("receipt-commitment", index),
                    claimant_commitment_root: sample_root("claimant", index),
                    insurer_commitment_root: sample_root("insurer", index),
                    claim_amount_commitment: sample_root("claim-amount", index),
                    receipt_slot: self.slot + index * 16,
                })
                .expect("devnet receipt anchors are valid");
            self.submit_lamport_witness(LamportFinalityWitnessInput {
                claim_id: claim_id.clone(),
                lamport_public_root: sample_root("lamport-public", index),
                lamport_signature_root: sample_root("lamport-signature", index),
                witness_transcript_root: sample_root("witness-transcript", index),
                pq_security_bits: self.config.min_pq_security_bits,
                witness_slot: self.slot + index * 16 + 4,
            })
            .expect("devnet lamport witnesses are valid");
            self.lock_accounting(AccountingEntryInput {
                claim_id,
                side: AccountingSide::ClaimEscrow,
                amount_atomic: self.config.claim_escrow_atomic,
                account_commitment_root: sample_root("claim-escrow", index),
            })
            .expect("devnet accounting entries are valid");
        }
        let claim_ids = self.receipt_claims.keys().cloned().collect::<BTreeSet<_>>();
        let finalized_claim_ids = self
            .receipt_claims
            .keys()
            .take(3)
            .cloned()
            .collect::<BTreeSet<_>>();
        self.finalize_batch(FinalityBatchInput {
            epoch: self.epoch,
            claim_ids,
            finalized_claim_ids,
            rejected_claim_ids: BTreeSet::new(),
            compression_root: sample_root("finality-compression", 0),
            batch_fee_micro_units: 96,
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
            "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-{domain}-ID"
        ),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-{domain}"
        ),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-LAMPORT-EXIT-RECEIPT-REINSURANCE-CLAIM-FINALITY-{domain}"
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
