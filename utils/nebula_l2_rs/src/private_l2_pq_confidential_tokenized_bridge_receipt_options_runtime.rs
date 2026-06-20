use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedBridgeReceiptOptionsRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_RECEIPT_OPTIONS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-bridge-receipt-options-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_RECEIPT_OPTIONS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_EXERCISE_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-receipt-option-exercise-v1";
pub const CONFIDENTIAL_RECEIPT_NOTE_SUITE: &str =
    "ringct-confidential-bridge-receipt-note-commitment-root-v1";
pub const OPTION_SERIES_SUITE: &str = "tokenized-confidential-bridge-receipt-option-series-root-v1";
pub const STRIKE_EXPIRY_BUCKET_SUITE: &str =
    "deterministic-bridge-receipt-option-strike-expiry-bucket-root-v1";
pub const SETTLEMENT_SUITE: &str = "confidential-monero-bridge-receipt-option-settlement-root-v1";
pub const LIQUIDITY_VAULT_SUITE: &str =
    "confidential-bridge-receipt-options-liquidity-vault-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str =
    "low-fee-confidential-bridge-receipt-option-exercise-rebate-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-tokenized-bridge-receipt-options-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_288_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_904_000;
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-bridge-receipt-options-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-private-l2-bridge-receipt-options-devnet";
pub const DEVNET_RECEIPT_ASSET_ID: &str = "pxmr-bridge-receipt-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_EXERCISE_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_EXERCISE_FEE_BPS: u64 = 8;
pub const DEFAULT_REBATE_BPS: u64 = 2_500;
pub const DEFAULT_MIN_VAULT_COVERAGE_BPS: u64 = 10_250;
pub const DEFAULT_ATTESTATION_QUORUM: u16 = 3;
pub const DEFAULT_SETTLEMENT_QUORUM: u16 = 2;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_BUCKET_NOTIONAL_UNITS: u128 = 25_000_000_000;
pub const DEFAULT_MAX_SERIES_PER_BUCKET: usize = 512;
pub const DEFAULT_MAX_EXERCISES_PER_BATCH: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
}

impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
        }
    }

    pub fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::BinaryCall)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptNoteStatus {
    Sealed,
    Bucketed,
    SeriesMinted,
    Exercising,
    Settled,
    Expired,
    Nullified,
    Quarantined,
}

impl ReceiptNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Bucketed => "bucketed",
            Self::SeriesMinted => "series_minted",
            Self::Exercising => "exercising",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Nullified => "nullified",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesStatus {
    Draft,
    Open,
    Halted,
    Expired,
    Settling,
    Settled,
    Retired,
}

impl SeriesStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Halted => "halted",
            Self::Expired => "expired",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Reject,
    NeedsReview,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::NeedsReview => "needs_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    Attested,
    BridgeLocked,
    Settled,
    PartiallySettled,
    Rejected,
    Quarantined,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Attested => "attested",
            Self::BridgeLocked => "bridge_locked",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_exercise_attestation_suite: String,
    pub confidential_receipt_note_suite: String,
    pub bridge_id: String,
    pub receipt_asset_id: String,
    pub collateral_asset_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_exercise_fee_bps: u64,
    pub target_exercise_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_vault_coverage_bps: u64,
    pub attestation_quorum: u16,
    pub settlement_quorum: u16,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_bucket_notional_units: u128,
    pub max_series_per_bucket: usize,
    pub max_exercises_per_batch: usize,
    pub require_monero_finality: bool,
    pub require_confidential_notes: bool,
    pub allow_low_fee_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_exercise_attestation_suite: PQ_EXERCISE_ATTESTATION_SUITE.to_string(),
            confidential_receipt_note_suite: CONFIDENTIAL_RECEIPT_NOTE_SUITE.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            receipt_asset_id: DEVNET_RECEIPT_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_exercise_fee_bps: DEFAULT_MAX_EXERCISE_FEE_BPS,
            target_exercise_fee_bps: DEFAULT_TARGET_EXERCISE_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_vault_coverage_bps: DEFAULT_MIN_VAULT_COVERAGE_BPS,
            attestation_quorum: DEFAULT_ATTESTATION_QUORUM,
            settlement_quorum: DEFAULT_SETTLEMENT_QUORUM,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_bucket_notional_units: DEFAULT_MAX_BUCKET_NOTIONAL_UNITS,
            max_series_per_bucket: DEFAULT_MAX_SERIES_PER_BUCKET,
            max_exercises_per_batch: DEFAULT_MAX_EXERCISES_PER_BATCH,
            require_monero_finality: true,
            require_confidential_notes: true,
            allow_low_fee_rebates: true,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_note_index: u64,
    pub next_series_index: u64,
    pub next_bucket_index: u64,
    pub next_attestation_index: u64,
    pub next_settlement_index: u64,
    pub next_vault_index: u64,
    pub next_rebate_index: u64,
    pub notes_sealed: u64,
    pub series_opened: u64,
    pub exercises_attested: u64,
    pub settlements_completed: u64,
    pub rebates_issued: u64,
    pub total_receipt_notional_units: u128,
    pub total_settled_units: u128,
    pub total_rebate_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_note_index: 1,
            next_series_index: 1,
            next_bucket_index: 1,
            next_attestation_index: 1,
            next_settlement_index: 1,
            next_vault_index: 1,
            next_rebate_index: 1,
            notes_sealed: 0,
            series_opened: 0,
            exercises_attested: 0,
            settlements_completed: 0,
            rebates_issued: 0,
            total_receipt_notional_units: 0,
            total_settled_units: 0,
            total_rebate_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub receipt_notes_root: String,
    pub option_series_root: String,
    pub strike_expiry_buckets_root: String,
    pub exercise_attestations_root: String,
    pub settlements_root: String,
    pub liquidity_vaults_root: String,
    pub rebates_root: String,
    pub nullifier_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialReceiptNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub receipt_commitment_root: String,
    pub encrypted_note_root: String,
    pub bridge_receipt_root: String,
    pub nullifier: String,
    pub receipt_asset_id: String,
    pub notional_units: u128,
    pub privacy_set_size: u64,
    pub monero_lock_height: u64,
    pub status: ReceiptNoteStatus,
}

impl ConfidentialReceiptNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": self.owner_commitment,
            "receipt_commitment_root": self.receipt_commitment_root,
            "encrypted_note_root": self.encrypted_note_root,
            "bridge_receipt_root": self.bridge_receipt_root,
            "receipt_asset_id": self.receipt_asset_id,
            "notional_units": self.notional_units,
            "privacy_set_size": self.privacy_set_size,
            "monero_lock_height": self.monero_lock_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptionSeries {
    pub series_id: String,
    pub bucket_id: String,
    pub option_kind: OptionKind,
    pub strike_price_micro_units: u64,
    pub expiry_l2_height: u64,
    pub receipt_asset_id: String,
    pub collateral_asset_id: String,
    pub minted_contracts: u128,
    pub open_interest_units: u128,
    pub status: SeriesStatus,
}

impl OptionSeries {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StrikeExpiryBucket {
    pub bucket_id: String,
    pub option_kind: OptionKind,
    pub strike_price_micro_units: u64,
    pub expiry_l2_height: u64,
    pub series_count: usize,
    pub notional_units: u128,
    pub bucket_root: String,
}

impl StrikeExpiryBucket {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExerciseAttestation {
    pub attestation_id: String,
    pub series_id: String,
    pub note_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub exercise_payload_root: String,
    pub mark_price_micro_units: u64,
    pub intrinsic_value_units: u128,
    pub verdict: AttestationVerdict,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl PqExerciseAttestation {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeReceiptSettlement {
    pub settlement_id: String,
    pub series_id: String,
    pub note_ids: Vec<String>,
    pub bridge_id: String,
    pub bridge_settlement_root: String,
    pub monero_tx_root: String,
    pub settled_units: u128,
    pub fee_bps: u64,
    pub status: SettlementStatus,
    pub settled_at_l2_height: u64,
    pub observed_monero_height: u64,
}

impl BridgeReceiptSettlement {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityVault {
    pub vault_id: String,
    pub operator_commitment: String,
    pub asset_id: String,
    pub inventory_root: String,
    pub available_units: u128,
    pub reserved_units: u128,
    pub coverage_bps: u64,
    pub rebate_pool_units: u128,
}

impl LiquidityVault {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeExerciseRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_units: u128,
    pub rebate_units: u128,
    pub rebate_commitment_root: String,
    pub issued_at_l2_height: u64,
}

impl LowFeeExerciseRebate {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub root: String,
    pub l2_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub receipt_notes: BTreeMap<String, ConfidentialReceiptNote>,
    pub option_series: BTreeMap<String, OptionSeries>,
    pub strike_expiry_buckets: BTreeMap<String, StrikeExpiryBucket>,
    pub exercise_attestations: BTreeMap<String, PqExerciseAttestation>,
    pub settlements: BTreeMap<String, BridgeReceiptSettlement>,
    pub liquidity_vaults: BTreeMap<String, LiquidityVault>,
    pub rebates: BTreeMap<String, LowFeeExerciseRebate>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::new(),
            roots: Roots::default(),
            receipt_notes: BTreeMap::new(),
            option_series: BTreeMap::new(),
            strike_expiry_buckets: BTreeMap::new(),
            exercise_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            liquidity_vaults: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "bridge_id": self.config.bridge_id,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "operator_safe_counts": {
                "receipt_notes": self.receipt_notes.len(),
                "option_series": self.option_series.len(),
                "strike_expiry_buckets": self.strike_expiry_buckets.len(),
                "exercise_attestations": self.exercise_attestations.len(),
                "settlements": self.settlements.len(),
                "liquidity_vaults": self.liquidity_vaults.len(),
                "rebates": self.rebates.len(),
                "public_records": self.public_records.len(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn upsert_liquidity_vault(
        &mut self,
        request: UpsertLiquidityVaultRequest,
    ) -> Result<String> {
        require_root("operator_commitment", &request.operator_commitment)?;
        require_non_empty("asset_id", &request.asset_id)?;
        require_root("inventory_root", &request.inventory_root)?;
        require(
            request.reserved_units <= request.available_units,
            "reserved vault units exceed available units",
        )?;
        require(
            request.coverage_bps >= self.config.min_vault_coverage_bps,
            "vault coverage below policy",
        )?;
        let vault_id = deterministic_id(
            "bridge-receipt-option-vault",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.inventory_root),
            ],
        );
        let vault = LiquidityVault {
            vault_id: vault_id.clone(),
            operator_commitment: request.operator_commitment,
            asset_id: request.asset_id,
            inventory_root: request.inventory_root,
            available_units: request.available_units,
            reserved_units: request.reserved_units,
            coverage_bps: request.coverage_bps,
            rebate_pool_units: request.rebate_pool_units,
        };
        self.liquidity_vaults.insert(vault_id.clone(), vault);
        self.counters.next_vault_index = self.counters.next_vault_index.saturating_add(1);
        self.record_public("liquidity_vault", &vault_id);
        self.refresh_roots();
        Ok(vault_id)
    }

    pub fn seal_receipt_note(&mut self, request: SealReceiptNoteRequest) -> Result<String> {
        require_root("owner_commitment", &request.owner_commitment)?;
        require_root("receipt_commitment_root", &request.receipt_commitment_root)?;
        require_root("encrypted_note_root", &request.encrypted_note_root)?;
        require_root("bridge_receipt_root", &request.bridge_receipt_root)?;
        require_root("nullifier", &request.nullifier)?;
        require_non_empty("receipt_asset_id", &request.receipt_asset_id)?;
        require(
            request.notional_units > 0,
            "notional_units must be positive",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below policy",
        )?;
        require(
            !self.consumed_nullifiers.contains(&request.nullifier),
            "receipt note nullifier already consumed",
        )?;
        let note_id = deterministic_id(
            "bridge-receipt-option-note",
            &[
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.receipt_commitment_root),
                HashPart::Str(&request.nullifier),
            ],
        );
        let note = ConfidentialReceiptNote {
            note_id: note_id.clone(),
            owner_commitment: request.owner_commitment,
            receipt_commitment_root: request.receipt_commitment_root,
            encrypted_note_root: request.encrypted_note_root,
            bridge_receipt_root: request.bridge_receipt_root,
            nullifier: request.nullifier,
            receipt_asset_id: request.receipt_asset_id,
            notional_units: request.notional_units,
            privacy_set_size: request.privacy_set_size,
            monero_lock_height: request.monero_lock_height,
            status: ReceiptNoteStatus::Sealed,
        };
        self.counters.notes_sealed = self.counters.notes_sealed.saturating_add(1);
        self.counters.next_note_index = self.counters.next_note_index.saturating_add(1);
        self.counters.total_receipt_notional_units = self
            .counters
            .total_receipt_notional_units
            .saturating_add(note.notional_units);
        self.receipt_notes.insert(note_id.clone(), note);
        self.record_public("confidential_receipt_note", &note_id);
        self.refresh_roots();
        Ok(note_id)
    }

    pub fn open_option_series(&mut self, request: OpenOptionSeriesRequest) -> Result<String> {
        require_non_empty("receipt_asset_id", &request.receipt_asset_id)?;
        require_non_empty("collateral_asset_id", &request.collateral_asset_id)?;
        require(
            request.strike_price_micro_units > 0,
            "strike must be positive",
        )?;
        require(
            request.expiry_l2_height > self.config.l2_height,
            "expiry must be in the future",
        )?;
        let bucket_id = deterministic_id(
            "bridge-receipt-option-strike-expiry-bucket",
            &[
                HashPart::Str(request.option_kind.as_str()),
                HashPart::U64(request.strike_price_micro_units),
                HashPart::U64(request.expiry_l2_height),
                HashPart::Str(&request.receipt_asset_id),
            ],
        );
        let series_id = deterministic_id(
            "bridge-receipt-option-series",
            &[
                HashPart::Str(&bucket_id),
                HashPart::Str(&request.collateral_asset_id),
                HashPart::U64(self.counters.next_series_index),
            ],
        );
        let bucket = self
            .strike_expiry_buckets
            .entry(bucket_id.clone())
            .or_insert_with(|| StrikeExpiryBucket {
                bucket_id: bucket_id.clone(),
                option_kind: request.option_kind,
                strike_price_micro_units: request.strike_price_micro_units,
                expiry_l2_height: request.expiry_l2_height,
                series_count: 0,
                notional_units: 0,
                bucket_root: String::new(),
            });
        require(
            bucket.series_count < self.config.max_series_per_bucket,
            "series count exceeds bucket policy",
        )?;
        bucket.series_count += 1;
        bucket.notional_units = bucket
            .notional_units
            .saturating_add(request.open_interest_units);
        require(
            bucket.notional_units <= self.config.max_bucket_notional_units,
            "bucket notional exceeds policy",
        )?;
        bucket.bucket_root = payload_root("STRIKE_EXPIRY_BUCKET", &bucket.public_record());
        let series = OptionSeries {
            series_id: series_id.clone(),
            bucket_id,
            option_kind: request.option_kind,
            strike_price_micro_units: request.strike_price_micro_units,
            expiry_l2_height: request.expiry_l2_height,
            receipt_asset_id: request.receipt_asset_id,
            collateral_asset_id: request.collateral_asset_id,
            minted_contracts: request.minted_contracts,
            open_interest_units: request.open_interest_units,
            status: SeriesStatus::Open,
        };
        self.option_series.insert(series_id.clone(), series);
        self.counters.series_opened = self.counters.series_opened.saturating_add(1);
        self.counters.next_series_index = self.counters.next_series_index.saturating_add(1);
        self.counters.next_bucket_index = self.counters.next_bucket_index.saturating_add(1);
        self.record_public("option_series", &series_id);
        self.refresh_roots();
        Ok(series_id)
    }

    pub fn attest_exercise(&mut self, request: PqExerciseAttestationRequest) -> Result<String> {
        require_non_empty("series_id", &request.series_id)?;
        require_non_empty("note_id", &request.note_id)?;
        require_root("attestor_commitment", &request.attestor_commitment)?;
        require_root("pq_signature_root", &request.pq_signature_root)?;
        require_root("exercise_payload_root", &request.exercise_payload_root)?;
        let series = self
            .option_series
            .get(&request.series_id)
            .ok_or_else(|| "unknown option series".to_string())?;
        let note = self
            .receipt_notes
            .get_mut(&request.note_id)
            .ok_or_else(|| "unknown receipt note".to_string())?;
        require(
            matches!(series.status, SeriesStatus::Open | SeriesStatus::Settling),
            "series is not exerciseable",
        )?;
        require(
            request.fee_bps <= self.config.max_exercise_fee_bps,
            "exercise fee exceeds policy",
        )?;
        let intrinsic_value_units = option_intrinsic_value(
            series.option_kind,
            series.strike_price_micro_units,
            request.mark_price_micro_units,
            note.notional_units,
        );
        let attestation_id = deterministic_id(
            "bridge-receipt-option-exercise-attestation",
            &[
                HashPart::Str(&request.series_id),
                HashPart::Str(&request.note_id),
                HashPart::Str(&request.attestor_commitment),
                HashPart::U64(self.counters.next_attestation_index),
            ],
        );
        let attestation = PqExerciseAttestation {
            attestation_id: attestation_id.clone(),
            series_id: request.series_id,
            note_id: request.note_id.clone(),
            attestor_commitment: request.attestor_commitment,
            pq_signature_root: request.pq_signature_root,
            exercise_payload_root: request.exercise_payload_root,
            mark_price_micro_units: request.mark_price_micro_units,
            intrinsic_value_units,
            verdict: request.verdict,
            attested_at_l2_height: self.config.l2_height,
            expires_at_l2_height: self
                .config
                .l2_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        note.status = ReceiptNoteStatus::Exercising;
        self.exercise_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.exercises_attested = self.counters.exercises_attested.saturating_add(1);
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.record_public("pq_exercise_attestation", &attestation_id);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_bridge_receipts(
        &mut self,
        request: BridgeReceiptSettlementRequest,
    ) -> Result<String> {
        require_non_empty("series_id", &request.series_id)?;
        require(
            !request.note_ids.is_empty(),
            "settlement must include at least one note",
        )?;
        require(
            request.note_ids.len() <= self.config.max_exercises_per_batch,
            "settlement batch exceeds policy",
        )?;
        require_root("bridge_settlement_root", &request.bridge_settlement_root)?;
        require_root("monero_tx_root", &request.monero_tx_root)?;
        require(
            request.fee_bps <= self.config.max_exercise_fee_bps,
            "fee exceeds policy",
        )?;
        require(
            unique_strings(&request.note_ids),
            "duplicate note in settlement",
        )?;
        let accepted = accepted_attestations(
            &self.exercise_attestations,
            &request.series_id,
            self.config.l2_height,
        );
        require(
            accepted >= usize::from(self.config.settlement_quorum),
            "insufficient accepted exercise attestations",
        )?;
        let mut settled_units = 0_u128;
        for note_id in &request.note_ids {
            let note = self
                .receipt_notes
                .get_mut(note_id)
                .ok_or_else(|| format!("unknown receipt note {note_id}"))?;
            require(
                !self.consumed_nullifiers.contains(&note.nullifier),
                "receipt note nullifier already consumed",
            )?;
            settled_units = settled_units.saturating_add(note.notional_units);
            self.consumed_nullifiers.insert(note.nullifier.clone());
            note.status = ReceiptNoteStatus::Settled;
        }
        let settlement_id = deterministic_id(
            "bridge-receipt-option-settlement",
            &[
                HashPart::Str(&request.series_id),
                HashPart::Str(&request.bridge_settlement_root),
                HashPart::U64(self.counters.next_settlement_index),
            ],
        );
        let settlement = BridgeReceiptSettlement {
            settlement_id: settlement_id.clone(),
            series_id: request.series_id,
            note_ids: request.note_ids,
            bridge_id: self.config.bridge_id.clone(),
            bridge_settlement_root: request.bridge_settlement_root,
            monero_tx_root: request.monero_tx_root,
            settled_units,
            fee_bps: request.fee_bps,
            status: SettlementStatus::Settled,
            settled_at_l2_height: self.config.l2_height,
            observed_monero_height: request.observed_monero_height,
        };
        self.counters.settlements_completed = self.counters.settlements_completed.saturating_add(1);
        self.counters.next_settlement_index = self.counters.next_settlement_index.saturating_add(1);
        self.counters.total_settled_units = self
            .counters
            .total_settled_units
            .saturating_add(settled_units);
        self.settlements.insert(settlement_id.clone(), settlement);
        if self.config.allow_low_fee_rebates
            && request.fee_bps > self.config.target_exercise_fee_bps
        {
            self.issue_rebate(
                &settlement_id,
                &request.beneficiary_commitment,
                settled_units,
            )?;
        }
        self.record_public("bridge_receipt_settlement", &settlement_id);
        self.refresh_roots();
        Ok(settlement_id)
    }

    fn issue_rebate(
        &mut self,
        settlement_id: &str,
        beneficiary_commitment: &str,
        settled_units: u128,
    ) -> Result<()> {
        require_root("beneficiary_commitment", beneficiary_commitment)?;
        let fee_paid_units =
            settled_units.saturating_mul(u128::from(self.config.max_exercise_fee_bps)) / 10_000;
        let rebate_units =
            fee_paid_units.saturating_mul(u128::from(self.config.rebate_bps)) / 10_000;
        let rebate_id = deterministic_id(
            "bridge-receipt-option-low-fee-rebate",
            &[
                HashPart::Str(settlement_id),
                HashPart::Str(beneficiary_commitment),
                HashPart::U64(self.counters.next_rebate_index),
            ],
        );
        let rebate_commitment_root = domain_hash(
            "bridge-receipt-option-low-fee-rebate-commitment",
            &[
                HashPart::Str(&rebate_id),
                HashPart::Str(beneficiary_commitment),
                HashPart::Int(rebate_units as i128),
            ],
            32,
        );
        self.rebates.insert(
            rebate_id.clone(),
            LowFeeExerciseRebate {
                rebate_id: rebate_id.clone(),
                settlement_id: settlement_id.to_string(),
                beneficiary_commitment: beneficiary_commitment.to_string(),
                fee_paid_units,
                rebate_units,
                rebate_commitment_root,
                issued_at_l2_height: self.config.l2_height,
            },
        );
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.next_rebate_index = self.counters.next_rebate_index.saturating_add(1);
        self.counters.total_rebate_units = self
            .counters
            .total_rebate_units
            .saturating_add(rebate_units);
        self.record_public("low_fee_exercise_rebate", &rebate_id);
        Ok(())
    }

    fn record_public(&mut self, record_kind: &str, subject_id: &str) {
        let root = domain_hash(
            "bridge-receipt-option-public-record-subject",
            &[HashPart::Str(record_kind), HashPart::Str(subject_id)],
            32,
        );
        let record_id = deterministic_id(
            "bridge-receipt-option-public-record",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&root),
            ],
        );
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                record_kind: record_kind.to_string(),
                subject_id: subject_id.to_string(),
                root,
                l2_height: self.config.l2_height,
            },
        );
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.receipt_notes_root = merkle_root(
            CONFIDENTIAL_RECEIPT_NOTE_SUITE,
            &self
                .receipt_notes
                .values()
                .map(ConfidentialReceiptNote::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.option_series_root = merkle_root(
            OPTION_SERIES_SUITE,
            &self
                .option_series
                .values()
                .map(OptionSeries::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.strike_expiry_buckets_root = merkle_root(
            STRIKE_EXPIRY_BUCKET_SUITE,
            &self
                .strike_expiry_buckets
                .values()
                .map(StrikeExpiryBucket::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.exercise_attestations_root = merkle_root(
            PQ_EXERCISE_ATTESTATION_SUITE,
            &self
                .exercise_attestations
                .values()
                .map(PqExerciseAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.settlements_root = merkle_root(
            SETTLEMENT_SUITE,
            &self
                .settlements
                .values()
                .map(BridgeReceiptSettlement::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.liquidity_vaults_root = merkle_root(
            LIQUIDITY_VAULT_SUITE,
            &self
                .liquidity_vaults
                .values()
                .map(LiquidityVault::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.rebates_root = merkle_root(
            LOW_FEE_REBATE_SUITE,
            &self
                .rebates
                .values()
                .map(LowFeeExerciseRebate::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            "bridge-receipt-options-consumed-nullifier-root-v1",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        self.roots.public_records_root = merkle_root(
            PUBLIC_RECORD_SUITE,
            &self
                .public_records
                .values()
                .map(DeterministicPublicRecord::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = domain_hash(
            "nebula-private-l2-pq-confidential-tokenized-bridge-receipt-options-state-root-v1",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.monero_height),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.receipt_notes_root),
                HashPart::Str(&self.roots.option_series_root),
                HashPart::Str(&self.roots.strike_expiry_buckets_root),
                HashPart::Str(&self.roots.exercise_attestations_root),
                HashPart::Str(&self.roots.settlements_root),
                HashPart::Str(&self.roots.liquidity_vaults_root),
                HashPart::Str(&self.roots.rebates_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealReceiptNoteRequest {
    pub owner_commitment: String,
    pub receipt_commitment_root: String,
    pub encrypted_note_root: String,
    pub bridge_receipt_root: String,
    pub nullifier: String,
    pub receipt_asset_id: String,
    pub notional_units: u128,
    pub privacy_set_size: u64,
    pub monero_lock_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenOptionSeriesRequest {
    pub option_kind: OptionKind,
    pub strike_price_micro_units: u64,
    pub expiry_l2_height: u64,
    pub receipt_asset_id: String,
    pub collateral_asset_id: String,
    pub minted_contracts: u128,
    pub open_interest_units: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExerciseAttestationRequest {
    pub series_id: String,
    pub note_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub exercise_payload_root: String,
    pub mark_price_micro_units: u64,
    pub fee_bps: u64,
    pub verdict: AttestationVerdict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeReceiptSettlementRequest {
    pub series_id: String,
    pub note_ids: Vec<String>,
    pub bridge_settlement_root: String,
    pub monero_tx_root: String,
    pub observed_monero_height: u64,
    pub fee_bps: u64,
    pub beneficiary_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpsertLiquidityVaultRequest {
    pub operator_commitment: String,
    pub asset_id: String,
    pub inventory_root: String,
    pub available_units: u128,
    pub reserved_units: u128,
    pub coverage_bps: u64,
    pub rebate_pool_units: u128,
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    state
        .upsert_liquidity_vault(UpsertLiquidityVaultRequest {
            operator_commitment: hex_root("vault-operator", 1),
            asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            inventory_root: hex_root("vault-inventory", 1),
            available_units: 12_000_000_000,
            reserved_units: 1_750_000_000,
            coverage_bps: 10_650,
            rebate_pool_units: 250_000_000,
        })
        .expect("demo vault");
    let note_id = state
        .seal_receipt_note(SealReceiptNoteRequest {
            owner_commitment: hex_root("note-owner", 1),
            receipt_commitment_root: hex_root("receipt-commitment", 1),
            encrypted_note_root: hex_root("encrypted-note", 1),
            bridge_receipt_root: hex_root("bridge-receipt", 1),
            nullifier: hex_root("receipt-nullifier", 1),
            receipt_asset_id: DEVNET_RECEIPT_ASSET_ID.to_string(),
            notional_units: 1_000_000_000,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            monero_lock_height: DEVNET_MONERO_HEIGHT.saturating_sub(32),
        })
        .expect("demo receipt note");
    let series_id = state
        .open_option_series(OpenOptionSeriesRequest {
            option_kind: OptionKind::Call,
            strike_price_micro_units: 185_000_000,
            expiry_l2_height: DEVNET_L2_HEIGHT + 144,
            receipt_asset_id: DEVNET_RECEIPT_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            minted_contracts: 1_024,
            open_interest_units: 1_000_000_000,
        })
        .expect("demo option series");
    for index in 0..DEFAULT_ATTESTATION_QUORUM {
        state
            .attest_exercise(PqExerciseAttestationRequest {
                series_id: series_id.clone(),
                note_id: note_id.clone(),
                attestor_commitment: hex_root("exercise-attestor", u64::from(index)),
                pq_signature_root: hex_root("exercise-pq-signature", u64::from(index)),
                exercise_payload_root: hex_root("exercise-payload", u64::from(index)),
                mark_price_micro_units: 194_000_000 + u64::from(index) * 25_000,
                fee_bps: DEFAULT_MAX_EXERCISE_FEE_BPS,
                verdict: AttestationVerdict::Accept,
            })
            .expect("demo exercise attestation");
    }
    state
        .settle_bridge_receipts(BridgeReceiptSettlementRequest {
            series_id,
            note_ids: vec![note_id],
            bridge_settlement_root: hex_root("bridge-settlement", 1),
            monero_tx_root: hex_root("monero-settlement-tx", 1),
            observed_monero_height: DEVNET_MONERO_HEIGHT,
            fee_bps: DEFAULT_MAX_EXERCISE_FEE_BPS,
            beneficiary_commitment: hex_root("rebate-beneficiary", 1),
        })
        .expect("demo bridge receipt settlement");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn accepted_attestations(
    attestations: &BTreeMap<String, PqExerciseAttestation>,
    series_id: &str,
    l2_height: u64,
) -> usize {
    attestations
        .values()
        .filter(|attestation| {
            attestation.series_id == series_id
                && attestation.verdict == AttestationVerdict::Accept
                && attestation.expires_at_l2_height >= l2_height
        })
        .count()
}

fn option_intrinsic_value(
    option_kind: OptionKind,
    strike_price_micro_units: u64,
    mark_price_micro_units: u64,
    notional_units: u128,
) -> u128 {
    let price_delta = match option_kind {
        OptionKind::Call => mark_price_micro_units.saturating_sub(strike_price_micro_units),
        OptionKind::Put => strike_price_micro_units.saturating_sub(mark_price_micro_units),
        OptionKind::BinaryCall => {
            if mark_price_micro_units > strike_price_micro_units {
                strike_price_micro_units / 10
            } else {
                0
            }
        }
        OptionKind::BinaryPut => {
            if mark_price_micro_units < strike_price_micro_units {
                strike_price_micro_units / 10
            } else {
                0
            }
        }
    };
    notional_units.saturating_mul(u128::from(price_delta)) / 1_000_000
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{domain}:{}", domain_hash(domain, parts, 16))
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-bridge-receipt-options-payload",
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn stable_record<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serialization")
}

fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn hex_root(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-bridge-receipt-options-demo-root",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
