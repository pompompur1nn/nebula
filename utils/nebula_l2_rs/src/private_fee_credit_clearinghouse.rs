use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateFeeCreditClearinghouseResult<T> = Result<T, String>;

pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PROTOCOL_LABEL: &str =
    "nebula-private-fee-credit-clearinghouse-v1";
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEVNET_HEIGHT: u64 = 1_920;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_CREDIT_SUITE: &str = "zk-private-fee-credit-note-v1";
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-fee-credit";
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_MIN_CREDIT_UNITS: u64 = 25;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_REBATE_BPS: u64 = 8_250;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_SPONSOR_POOL_UNITS: u64 = 480_000;
pub const PRIVATE_FEE_CREDIT_CLEARINGHOUSE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditLane {
    WalletTransfer,
    ContractCall,
    PrivateSwap,
    MoneroExit,
    ProofJob,
    OracleUpdate,
    Emergency,
}

impl FeeCreditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ContractCall => "contract_call",
            Self::PrivateSwap => "private_swap",
            Self::MoneroExit => "monero_exit",
            Self::ProofJob => "proof_job",
            Self::OracleUpdate => "oracle_update",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::MoneroExit => 90,
            Self::ContractCall => 82,
            Self::PrivateSwap => 78,
            Self::WalletTransfer => 72,
            Self::ProofJob => 64,
            Self::OracleUpdate => 58,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditNoteStatus {
    Minted,
    Reserved,
    Applied,
    Settled,
    Expired,
    Revoked,
}

impl CreditNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    Open,
    Netting,
    Settled,
    Challenged,
    Failed,
    Expired,
}

impl ClearingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Netting => "netting",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Netting | Self::Challenged)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditClearinghouseConfig {
    pub epoch_blocks: u64,
    pub settlement_window_blocks: u64,
    pub min_credit_units: u64,
    pub rebate_bps: u64,
    pub sponsor_pool_units: u64,
    pub credit_suite: String,
    pub pq_auth_suite: String,
    pub hash_suite: String,
}

impl PrivateFeeCreditClearinghouseConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS,
            settlement_window_blocks:
                PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            min_credit_units: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_MIN_CREDIT_UNITS,
            rebate_bps: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_REBATE_BPS,
            sponsor_pool_units: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEFAULT_SPONSOR_POOL_UNITS,
            credit_suite: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_CREDIT_SUITE.to_string(),
            pq_auth_suite: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PQ_AUTH_SUITE.to_string(),
            hash_suite: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "min_credit_units": self.min_credit_units,
            "rebate_bps": self.rebate_bps,
            "sponsor_pool_units": self.sponsor_pool_units,
            "credit_suite": self.credit_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        fee_credit_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFeeCreditClearinghouseResult<()> {
        if self.epoch_blocks == 0
            || self.settlement_window_blocks == 0
            || self.min_credit_units == 0
            || self.sponsor_pool_units == 0
        {
            return Err("private fee credit config values must be positive".to_string());
        }
        if self.rebate_bps > PRIVATE_FEE_CREDIT_CLEARINGHOUSE_MAX_BPS {
            return Err("private fee credit rebate exceeds max bps".to_string());
        }
        if self.credit_suite.is_empty()
            || self.pq_auth_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("private fee credit crypto suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditNote {
    pub note_id: String,
    pub lane: FeeCreditLane,
    pub owner_commitment: String,
    pub credit_units: u64,
    pub spent_units: u64,
    pub minted_height: u64,
    pub expiry_height: u64,
    pub status: CreditNoteStatus,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub sponsor_receipt_root: String,
}

impl PrivateFeeCreditNote {
    pub fn new(
        note_id: &str,
        lane: FeeCreditLane,
        owner_commitment: &str,
        credit_units: u64,
        minted_height: u64,
        ttl_blocks: u64,
    ) -> PrivateFeeCreditClearinghouseResult<Self> {
        if note_id.is_empty() || owner_commitment.is_empty() {
            return Err("private fee credit note identifiers must be populated".to_string());
        }
        if credit_units == 0 {
            return Err("private fee credit note amount must be positive".to_string());
        }
        let note_commitment_root = fee_credit_hash(
            "NOTE-COMMITMENT",
            &[
                HashPart::Str(note_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(owner_commitment),
                HashPart::Int(credit_units as i128),
            ],
        );
        let nullifier_root = fee_credit_hash(
            "NOTE-NULLIFIER",
            &[HashPart::Str(note_id), HashPart::Str(owner_commitment)],
        );
        let sponsor_receipt_root = fee_credit_hash(
            "NOTE-SPONSOR-RECEIPT",
            &[HashPart::Str(note_id), HashPart::Int(credit_units as i128)],
        );
        Ok(Self {
            note_id: note_id.to_string(),
            lane,
            owner_commitment: owner_commitment.to_string(),
            credit_units,
            spent_units: 0,
            minted_height,
            expiry_height: minted_height.saturating_add(ttl_blocks),
            status: CreditNoteStatus::Minted,
            note_commitment_root,
            nullifier_root,
            sponsor_receipt_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "credit_units": self.credit_units,
            "spent_units": self.spent_units,
            "minted_height": self.minted_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "note_commitment_root": self.note_commitment_root,
            "nullifier_root": self.nullifier_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
        })
    }

    pub fn root(&self) -> String {
        fee_credit_hash("NOTE", &[HashPart::Json(&self.public_record())])
    }

    pub fn remaining_units(&self) -> u64 {
        self.credit_units.saturating_sub(self.spent_units)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height <= self.expiry_height && self.remaining_units() > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditApplication {
    pub application_id: String,
    pub note_id: String,
    pub lane: FeeCreditLane,
    pub transaction_commitment: String,
    pub applied_units: u64,
    pub rebate_units: u64,
    pub height: u64,
    pub pq_authorization_root: String,
    pub application_root: String,
}

impl PrivateFeeCreditApplication {
    pub fn new(
        application_id: &str,
        note: &PrivateFeeCreditNote,
        transaction_commitment: &str,
        applied_units: u64,
        rebate_bps: u64,
        height: u64,
    ) -> PrivateFeeCreditClearinghouseResult<Self> {
        if application_id.is_empty() || transaction_commitment.is_empty() {
            return Err("private fee credit application identifiers must be populated".to_string());
        }
        if applied_units == 0 || applied_units > note.remaining_units() {
            return Err("private fee credit application amount invalid".to_string());
        }
        let rebate_units =
            applied_units.saturating_mul(rebate_bps) / PRIVATE_FEE_CREDIT_CLEARINGHOUSE_MAX_BPS;
        let pq_authorization_root = fee_credit_hash(
            "APPLICATION-PQ-AUTHORIZATION",
            &[
                HashPart::Str(application_id),
                HashPart::Str(&note.note_id),
                HashPart::Str(transaction_commitment),
            ],
        );
        let application_root = fee_credit_hash(
            "APPLICATION",
            &[
                HashPart::Str(application_id),
                HashPart::Str(&pq_authorization_root),
                HashPart::Int(applied_units as i128),
            ],
        );
        Ok(Self {
            application_id: application_id.to_string(),
            note_id: note.note_id.clone(),
            lane: note.lane,
            transaction_commitment: transaction_commitment.to_string(),
            applied_units,
            rebate_units,
            height,
            pq_authorization_root,
            application_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "application_id": self.application_id,
            "note_id": self.note_id,
            "lane": self.lane.as_str(),
            "transaction_commitment": self.transaction_commitment,
            "applied_units": self.applied_units,
            "rebate_units": self.rebate_units,
            "height": self.height,
            "pq_authorization_root": self.pq_authorization_root,
            "application_root": self.application_root,
        })
    }

    pub fn root(&self) -> String {
        fee_credit_hash(
            "APPLICATION-RECORD",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeClearingBatch {
    pub batch_id: String,
    pub status: ClearingBatchStatus,
    pub lane: FeeCreditLane,
    pub application_ids: Vec<String>,
    pub gross_credit_units: u64,
    pub rebate_units: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub application_root: String,
    pub net_settlement_root: String,
    pub sponsor_debit_root: String,
}

impl PrivateFeeClearingBatch {
    pub fn new(
        batch_id: &str,
        lane: FeeCreditLane,
        applications: &[PrivateFeeCreditApplication],
        opened_height: u64,
        settlement_window_blocks: u64,
    ) -> PrivateFeeCreditClearinghouseResult<Self> {
        if batch_id.is_empty() {
            return Err("private fee clearing batch id must be populated".to_string());
        }
        if applications.is_empty() {
            return Err("private fee clearing batch requires applications".to_string());
        }
        let mut application_ids = Vec::with_capacity(applications.len());
        let mut application_records = Vec::with_capacity(applications.len());
        let mut gross_credit_units = 0_u64;
        let mut rebate_units = 0_u64;
        for application in applications {
            if application.lane != lane {
                return Err("private fee clearing batch cannot mix lanes".to_string());
            }
            application_ids.push(application.application_id.clone());
            application_records.push(application.public_record());
            gross_credit_units = gross_credit_units.saturating_add(application.applied_units);
            rebate_units = rebate_units.saturating_add(application.rebate_units);
        }
        let application_root = merkle_root("PRIVATE-FEE-CREDIT-APPLICATION", &application_records);
        let net_settlement_root = fee_credit_hash(
            "BATCH-NET-SETTLEMENT",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(&application_root),
                HashPart::Int(gross_credit_units as i128),
            ],
        );
        let sponsor_debit_root = fee_credit_hash(
            "BATCH-SPONSOR-DEBIT",
            &[HashPart::Str(batch_id), HashPart::Int(rebate_units as i128)],
        );
        Ok(Self {
            batch_id: batch_id.to_string(),
            status: ClearingBatchStatus::Netting,
            lane,
            application_ids,
            gross_credit_units,
            rebate_units,
            opened_height,
            deadline_height: opened_height.saturating_add(settlement_window_blocks),
            application_root,
            net_settlement_root,
            sponsor_debit_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "application_ids": self.application_ids,
            "gross_credit_units": self.gross_credit_units,
            "rebate_units": self.rebate_units,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "application_root": self.application_root,
            "net_settlement_root": self.net_settlement_root,
            "sponsor_debit_root": self.sponsor_debit_root,
        })
    }

    pub fn root(&self) -> String {
        fee_credit_hash("BATCH", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditClearinghouseRoots {
    pub config_root: String,
    pub note_root: String,
    pub application_root: String,
    pub batch_root: String,
    pub lane_credit_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl PrivateFeeCreditClearinghouseRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "note_root": self.note_root,
            "application_root": self.application_root,
            "batch_root": self.batch_root,
            "lane_credit_root": self.lane_credit_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditClearinghouseCounters {
    pub note_count: u64,
    pub live_note_count: u64,
    pub application_count: u64,
    pub open_batch_count: u64,
    pub total_credit_units: u64,
    pub remaining_credit_units: u64,
    pub applied_credit_units: u64,
    pub rebate_units: u64,
}

impl PrivateFeeCreditClearinghouseCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "note_count": self.note_count,
            "live_note_count": self.live_note_count,
            "application_count": self.application_count,
            "open_batch_count": self.open_batch_count,
            "total_credit_units": self.total_credit_units,
            "remaining_credit_units": self.remaining_credit_units,
            "applied_credit_units": self.applied_credit_units,
            "rebate_units": self.rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditClearinghouseState {
    pub height: u64,
    pub config: PrivateFeeCreditClearinghouseConfig,
    pub notes: BTreeMap<String, PrivateFeeCreditNote>,
    pub applications: BTreeMap<String, PrivateFeeCreditApplication>,
    pub batches: BTreeMap<String, PrivateFeeClearingBatch>,
    pub lane_credits: BTreeMap<FeeCreditLane, u64>,
    pub used_nullifiers: BTreeSet<String>,
    pub paused: bool,
}

impl PrivateFeeCreditClearinghouseState {
    pub fn devnet() -> PrivateFeeCreditClearinghouseResult<Self> {
        let config = PrivateFeeCreditClearinghouseConfig::devnet();
        config.validate()?;
        let mut state = Self {
            height: PRIVATE_FEE_CREDIT_CLEARINGHOUSE_DEVNET_HEIGHT,
            config,
            notes: BTreeMap::new(),
            applications: BTreeMap::new(),
            batches: BTreeMap::new(),
            lane_credits: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            paused: false,
        };
        let note_a = PrivateFeeCreditNote::new(
            "devnet-contract-credit-a",
            FeeCreditLane::ContractCall,
            "fee-credit-owner-contract-desk",
            18_000,
            state.height,
            720,
        )?;
        state.insert_note(note_a)?;
        let note_b = PrivateFeeCreditNote::new(
            "devnet-monero-exit-credit-a",
            FeeCreditLane::MoneroExit,
            "fee-credit-owner-exit-router",
            24_000,
            state.height,
            720,
        )?;
        state.insert_note(note_b)?;
        state.apply_credit(
            "devnet-contract-credit-application-a",
            "devnet-contract-credit-a",
            "tx-commitment-private-contract-a",
            2_200,
        )?;
        state.seal_lane_batch(
            "devnet-contract-credit-batch-a",
            FeeCreditLane::ContractCall,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateFeeCreditClearinghouseResult<()> {
        if height < self.height {
            return Err("private fee credit height cannot move backwards".to_string());
        }
        self.height = height;
        for note in self.notes.values_mut() {
            if note.status.is_live() && height > note.expiry_height {
                note.status = CreditNoteStatus::Expired;
            }
        }
        for batch in self.batches.values_mut() {
            if batch.status.is_open() && height > batch.deadline_height {
                batch.status = ClearingBatchStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_note(
        &mut self,
        note: PrivateFeeCreditNote,
    ) -> PrivateFeeCreditClearinghouseResult<()> {
        if self.paused {
            return Err("private fee credit clearinghouse is paused".to_string());
        }
        if self.notes.contains_key(&note.note_id) {
            return Err("private fee credit note already exists".to_string());
        }
        if self.used_nullifiers.contains(&note.nullifier_root) {
            return Err("private fee credit note nullifier already exists".to_string());
        }
        let lane_credit = self.lane_credits.entry(note.lane).or_insert(0);
        *lane_credit = lane_credit.saturating_add(note.credit_units);
        self.used_nullifiers.insert(note.nullifier_root.clone());
        self.notes.insert(note.note_id.clone(), note);
        Ok(())
    }

    pub fn apply_credit(
        &mut self,
        application_id: &str,
        note_id: &str,
        transaction_commitment: &str,
        applied_units: u64,
    ) -> PrivateFeeCreditClearinghouseResult<String> {
        if self.applications.contains_key(application_id) {
            return Err("private fee credit application already exists".to_string());
        }
        let note = self
            .notes
            .get_mut(note_id)
            .ok_or_else(|| "private fee credit note missing".to_string())?;
        if !note.is_live_at(self.height) {
            return Err("private fee credit note is not live".to_string());
        }
        let application = PrivateFeeCreditApplication::new(
            application_id,
            note,
            transaction_commitment,
            applied_units,
            self.config.rebate_bps,
            self.height,
        )?;
        note.spent_units = note.spent_units.saturating_add(applied_units);
        note.status = if note.remaining_units() == 0 {
            CreditNoteStatus::Applied
        } else {
            CreditNoteStatus::Reserved
        };
        let application_root = application.root();
        self.applications
            .insert(application.application_id.clone(), application);
        Ok(application_root)
    }

    pub fn seal_lane_batch(
        &mut self,
        batch_id: &str,
        lane: FeeCreditLane,
    ) -> PrivateFeeCreditClearinghouseResult<String> {
        if self.batches.contains_key(batch_id) {
            return Err("private fee credit clearing batch already exists".to_string());
        }
        let applications = self
            .applications
            .values()
            .filter(|application| application.lane == lane)
            .cloned()
            .collect::<Vec<_>>();
        let batch = PrivateFeeClearingBatch::new(
            batch_id,
            lane,
            &applications,
            self.height,
            self.config.settlement_window_blocks,
        )?;
        let batch_root = batch.root();
        self.batches.insert(batch.batch_id.clone(), batch);
        Ok(batch_root)
    }

    pub fn live_note_ids(&self) -> Vec<String> {
        self.notes
            .values()
            .filter(|note| note.is_live_at(self.height))
            .map(|note| note.note_id.clone())
            .collect()
    }

    pub fn open_batch_ids(&self) -> Vec<String> {
        self.batches
            .values()
            .filter(|batch| batch.status.is_open())
            .map(|batch| batch.batch_id.clone())
            .collect()
    }

    pub fn lane_credit_map(&self) -> BTreeMap<String, u64> {
        self.lane_credits
            .iter()
            .map(|(lane, units)| (lane.as_str().to_string(), *units))
            .collect()
    }

    pub fn total_credit_units(&self) -> u64 {
        self.notes.values().map(|note| note.credit_units).sum()
    }

    pub fn remaining_credit_units(&self) -> u64 {
        self.notes
            .values()
            .map(PrivateFeeCreditNote::remaining_units)
            .sum()
    }

    pub fn applied_credit_units(&self) -> u64 {
        self.applications
            .values()
            .map(|application| application.applied_units)
            .sum()
    }

    pub fn rebate_units(&self) -> u64 {
        self.applications
            .values()
            .map(|application| application.rebate_units)
            .sum()
    }

    pub fn roots(&self) -> PrivateFeeCreditClearinghouseRoots {
        let config_root = self.config.config_root();
        let note_records = self
            .notes
            .values()
            .map(PrivateFeeCreditNote::public_record)
            .collect::<Vec<_>>();
        let application_records = self
            .applications
            .values()
            .map(PrivateFeeCreditApplication::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(PrivateFeeClearingBatch::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .used_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        let note_root = merkle_root("PRIVATE-FEE-CREDIT-NOTE", &note_records);
        let application_root = merkle_root("PRIVATE-FEE-CREDIT-APPLICATION", &application_records);
        let batch_root = merkle_root("PRIVATE-FEE-CREDIT-BATCH", &batch_records);
        let lane_credit_root = fee_credit_hash(
            "LANE-CREDIT",
            &[HashPart::Json(&json!(self.lane_credit_map()))],
        );
        let nullifier_root = merkle_root("PRIVATE-FEE-CREDIT-NULLIFIER", &nullifier_records);
        let state_root = fee_credit_hash(
            "STATE",
            &[
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&note_root),
                HashPart::Str(&application_root),
                HashPart::Str(&batch_root),
                HashPart::Str(&lane_credit_root),
                HashPart::Str(&nullifier_root),
            ],
        );
        PrivateFeeCreditClearinghouseRoots {
            config_root,
            note_root,
            application_root,
            batch_root,
            lane_credit_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateFeeCreditClearinghouseCounters {
        PrivateFeeCreditClearinghouseCounters {
            note_count: self.notes.len() as u64,
            live_note_count: self.live_note_ids().len() as u64,
            application_count: self.applications.len() as u64,
            open_batch_count: self.open_batch_ids().len() as u64,
            total_credit_units: self.total_credit_units(),
            remaining_credit_units: self.remaining_credit_units(),
            applied_credit_units: self.applied_credit_units(),
            rebate_units: self.rebate_units(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_fee_credit_clearinghouse",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PROTOCOL_VERSION,
            "protocol_label": PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PROTOCOL_LABEL,
            "schema_version": PRIVATE_FEE_CREDIT_CLEARINGHOUSE_SCHEMA_VERSION,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "live_note_ids": self.live_note_ids(),
            "open_batch_ids": self.open_batch_ids(),
            "lane_credit_map": self.lane_credit_map(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateFeeCreditClearinghouseResult<String> {
        self.config.validate()?;
        let mut seen_nullifiers = BTreeSet::new();
        for note in self.notes.values() {
            if !seen_nullifiers.insert(note.nullifier_root.clone()) {
                return Err("duplicate private fee credit note nullifier".to_string());
            }
            if note.expiry_height < note.minted_height {
                return Err("private fee credit note has invalid expiry".to_string());
            }
        }
        for application in self.applications.values() {
            if !self.notes.contains_key(&application.note_id) {
                return Err("private fee credit application references missing note".to_string());
            }
        }
        for batch in self.batches.values() {
            for application_id in &batch.application_ids {
                if !self.applications.contains_key(application_id) {
                    return Err(
                        "private fee clearing batch references missing application".to_string()
                    );
                }
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_fee_credit_clearinghouse_state_root_from_record(record: &Value) -> String {
    fee_credit_hash("STATE-FROM-RECORD", &[HashPart::Json(record)])
}

fn fee_credit_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_FEE_CREDIT_CLEARINGHOUSE_PROTOCOL_LABEL, CHAIN_ID, label
        ),
        parts,
        32,
    )
}
