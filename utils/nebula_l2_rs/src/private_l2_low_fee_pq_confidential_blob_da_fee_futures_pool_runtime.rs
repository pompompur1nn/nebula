use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBlobDaFeeFuturesPoolRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_DA_FEE_FUTURES_POOL_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-blob-da-fee-futures-pool-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_DA_FEE_FUTURES_POOL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFIDENTIAL_FEE_BUCKET_SUITE: &str = "ml-kem-1024-sealed-blob-da-fee-futures-buckets-v1";
pub const PQ_VERIFIER_ELIGIBILITY_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-blob-da-fee-futures-eligibility-v1";
pub const BLOB_DA_FEE_FUTURES_SUITE: &str =
    "low-fee-confidential-blob-da-proof-fee-futures-hedging-smoothing-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_fee_bucket_plaintexts_blob_payloads_view_keys_addresses_or_secret_keys";
pub const DEVNET_L2_HEIGHT: u64 = 4_700_000;
pub const DEVNET_EPOCH: u64 = 15_040;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_FUTURES_ASSET_ID: &str = "blob-da-fee-futures-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_PROOF_FEE_MICRO_UNITS: u64 = 5_250;
pub const DEFAULT_BASE_BLOB_DA_FEE_MICRO_UNITS: u64 = 7_250;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 11;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const DEFAULT_MAX_HEDGE_BPS: u64 = 92;
pub const DEFAULT_TARGET_HEDGE_BPS: u64 = 48;
pub const DEFAULT_BUCKET_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_ELIGIBILITY_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_SMOOTHING_WINDOW_BATCHES: u64 = 24;
pub const DEFAULT_FUTURES_MATURITY_BATCHES: u64 = 64;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:ROOTS";
const D_POOLS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:POOLS";
const D_BUCKETS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:BUCKETS";
const D_ELIGIBILITY: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:ELIGIBILITY";
const D_CONTRACTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:CONTRACTS";
const D_SETTLEMENTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-DA-FEE-FUTURES-POOL:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuturesLane {
    MicroBlob,
    StandardBlob,
    ProofHeavy,
    DaHeavy,
    Congested,
}

impl FuturesLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroBlob => "micro_blob",
            Self::StandardBlob => "standard_blob",
            Self::ProofHeavy => "proof_heavy",
            Self::DaHeavy => "da_heavy",
            Self::Congested => "congested",
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::MicroBlob => 6_500,
            Self::StandardBlob => 10_000,
            Self::ProofHeavy => 12_800,
            Self::DaHeavy => 15_250,
            Self::Congested => 20_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Hedging,
    Settling,
    Exhausted,
    Expired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Hedging => "hedging",
            Self::Settling => "settling",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_contracts(self) -> bool {
        matches!(self, Self::Open | Self::Hedging | Self::Settling)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub futures_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_proof_fee_micro_units: u64,
    pub base_blob_da_fee_micro_units: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_hedge_bps: u64,
    pub max_hedge_bps: u64,
    pub smoothing_window_batches: u64,
    pub futures_maturity_batches: u64,
    pub bucket_ttl_slots: u64,
    pub eligibility_ttl_slots: u64,
    pub devnet_l2_height: u64,
    pub devnet_epoch: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            futures_asset_id: DEFAULT_FUTURES_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_proof_fee_micro_units: DEFAULT_BASE_PROOF_FEE_MICRO_UNITS,
            base_blob_da_fee_micro_units: DEFAULT_BASE_BLOB_DA_FEE_MICRO_UNITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_hedge_bps: DEFAULT_TARGET_HEDGE_BPS,
            max_hedge_bps: DEFAULT_MAX_HEDGE_BPS,
            smoothing_window_batches: DEFAULT_SMOOTHING_WINDOW_BATCHES,
            futures_maturity_batches: DEFAULT_FUTURES_MATURITY_BATCHES,
            bucket_ttl_slots: DEFAULT_BUCKET_TTL_SLOTS,
            eligibility_ttl_slots: DEFAULT_ELIGIBILITY_TTL_SLOTS,
            devnet_l2_height: DEVNET_L2_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "confidential_fee_bucket_suite": CONFIDENTIAL_FEE_BUCKET_SUITE,
            "pq_verifier_eligibility_suite": PQ_VERIFIER_ELIGIBILITY_SUITE,
            "blob_da_fee_futures_suite": BLOB_DA_FEE_FUTURES_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "fee_asset_id": self.fee_asset_id,
            "futures_asset_id": self.futures_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "base_proof_fee_micro_units": self.base_proof_fee_micro_units,
            "base_blob_da_fee_micro_units": self.base_blob_da_fee_micro_units,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_hedge_bps": self.target_hedge_bps,
            "max_hedge_bps": self.max_hedge_bps,
            "smoothing_window_batches": self.smoothing_window_batches,
            "futures_maturity_batches": self.futures_maturity_batches,
            "bucket_ttl_slots": self.bucket_ttl_slots,
            "eligibility_ttl_slots": self.eligibility_ttl_slots,
            "devnet_l2_height": self.devnet_l2_height,
            "devnet_epoch": self.devnet_epoch
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub futures_pools: u64,
    pub confidential_fee_buckets: u64,
    pub pq_verifier_eligibilities: u64,
    pub futures_contracts: u64,
    pub futures_settlements: u64,
    pub nullifiers: u64,
    pub public_events: u64,
    pub deposited_hedge_micro_units: u64,
    pub reserved_hedge_micro_units: u64,
    pub settled_hedge_micro_units: u64,
    pub smoothed_proof_fee_micro_units: u64,
    pub smoothed_blob_da_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub futures_pool_root: String,
    pub confidential_fee_bucket_root: String,
    pub pq_verifier_eligibility_root: String,
    pub futures_contract_root: String,
    pub futures_settlement_root: String,
    pub nullifier_root: String,
    pub public_events_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FuturesPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub lane: FuturesLane,
    pub sealed_pool_root: String,
    pub total_hedge_micro_units: u64,
    pub available_hedge_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub status: PoolStatus,
}

impl FuturesPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": redacted_commitment(&self.sponsor_commitment),
            "lane": self.lane.as_str(),
            "sealed_pool_root": self.sealed_pool_root,
            "total_hedge_micro_units": self.total_hedge_micro_units,
            "available_hedge_micro_units": self.available_hedge_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialFeeBucket {
    pub bucket_id: String,
    pub pool_id: String,
    pub encrypted_bucket_root: String,
    pub bucket_commitment_root: String,
    pub bucket_nullifier: String,
    pub capacity_micro_units: u64,
    pub min_blob_batch_index: u64,
    pub max_blob_batch_index: u64,
    pub slot: u64,
}

impl ConfidentialFeeBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqVerifierEligibility {
    pub eligibility_id: String,
    pub pool_id: String,
    pub verifier_commitment: String,
    pub pq_key_commitment: String,
    pub eligibility_root: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub eligible_until_slot: u64,
}

impl PqVerifierEligibility {
    pub fn public_record(&self) -> Value {
        json!({
            "eligibility_id": self.eligibility_id,
            "pool_id": self.pool_id,
            "verifier_commitment": redacted_commitment(&self.verifier_commitment),
            "pq_key_commitment": redacted_commitment(&self.pq_key_commitment),
            "eligibility_root": self.eligibility_root,
            "signature_commitment": redacted_commitment(&self.signature_commitment),
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "eligible_until_slot": self.eligible_until_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FuturesContract {
    pub contract_id: String,
    pub pool_id: String,
    pub bucket_id: String,
    pub eligibility_id: String,
    pub blob_batch_root: String,
    pub contract_nullifier: String,
    pub blob_batch_index: u64,
    pub proof_work_units: u64,
    pub blob_da_bytes: u64,
    pub reserved_hedge_micro_units: u64,
    pub max_user_fee_micro_units: u64,
    pub maturity_batch_index: u64,
    pub slot: u64,
}

impl FuturesContract {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FuturesSettlement {
    pub settlement_id: String,
    pub contract_id: String,
    pub pool_id: String,
    pub settlement_nullifier: String,
    pub proof_fee_micro_units: u64,
    pub blob_da_fee_micro_units: u64,
    pub gross_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub hedge_credit_micro_units: u64,
    pub smoothing_window_batches: u64,
    pub maturity_batch_index: u64,
    pub slot: u64,
}

impl FuturesSettlement {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub futures_pools: BTreeMap<String, FuturesPool>,
    pub confidential_fee_buckets: BTreeMap<String, ConfidentialFeeBucket>,
    pub pq_verifier_eligibilities: BTreeMap<String, PqVerifierEligibility>,
    pub futures_contracts: BTreeMap<String, FuturesContract>,
    pub futures_settlements: BTreeMap<String, FuturesSettlement>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            futures_pools: BTreeMap::new(),
            confidential_fee_buckets: BTreeMap::new(),
            pq_verifier_eligibilities: BTreeMap::new(),
            futures_contracts: BTreeMap::new(),
            futures_settlements: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn open_futures_pool(
        &mut self,
        sponsor_commitment: impl Into<String>,
        lane: FuturesLane,
        sealed_pool_root: impl Into<String>,
        hedge_micro_units: u64,
        privacy_set_size: u64,
        opened_slot: u64,
    ) -> Result<String> {
        if hedge_micro_units == 0 {
            return Err("futures pool requires positive hedge liquidity".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("futures pool privacy set below configured floor".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        let sealed_pool_root = sealed_pool_root.into();
        let pool_id = deterministic_id(
            "blob-da-fee-futures-pool",
            &[
                &sponsor_commitment,
                lane.as_str(),
                &sealed_pool_root,
                &opened_slot.to_string(),
            ],
        );
        let pool = FuturesPool {
            pool_id: pool_id.clone(),
            sponsor_commitment,
            lane,
            sealed_pool_root,
            total_hedge_micro_units: hedge_micro_units,
            available_hedge_micro_units: hedge_micro_units,
            privacy_set_size,
            opened_slot,
            expires_slot: opened_slot.saturating_add(self.config.bucket_ttl_slots),
            status: PoolStatus::Open,
        };
        self.futures_pools.insert(pool_id.clone(), pool);
        self.counters.deposited_hedge_micro_units = self
            .counters
            .deposited_hedge_micro_units
            .saturating_add(hedge_micro_units);
        self.record_event("blob_da_fee_futures_pool_opened", &pool_id);
        self.recompute_roots();
        Ok(pool_id)
    }

    pub fn commit_confidential_fee_bucket(
        &mut self,
        pool_id: impl Into<String>,
        encrypted_bucket_root: impl Into<String>,
        bucket_commitment_root: impl Into<String>,
        bucket_nullifier: impl Into<String>,
        capacity_micro_units: u64,
        min_blob_batch_index: u64,
        max_blob_batch_index: u64,
        slot: u64,
    ) -> Result<String> {
        let pool_id = pool_id.into();
        if !self.futures_pools.contains_key(&pool_id) {
            return Err("unknown blob DA fee futures pool".to_string());
        }
        if capacity_micro_units == 0 {
            return Err("confidential fee bucket requires positive capacity".to_string());
        }
        if min_blob_batch_index > max_blob_batch_index {
            return Err("confidential fee bucket blob batch range is invalid".to_string());
        }
        let bucket_nullifier = bucket_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &bucket_nullifier)?;
        let encrypted_bucket_root = encrypted_bucket_root.into();
        let bucket_commitment_root = bucket_commitment_root.into();
        let bucket_id = deterministic_id(
            "confidential-fee-bucket",
            &[
                &pool_id,
                &encrypted_bucket_root,
                &bucket_commitment_root,
                &bucket_nullifier,
            ],
        );
        let bucket = ConfidentialFeeBucket {
            bucket_id: bucket_id.clone(),
            pool_id,
            encrypted_bucket_root,
            bucket_commitment_root,
            bucket_nullifier: bucket_nullifier.clone(),
            capacity_micro_units,
            min_blob_batch_index,
            max_blob_batch_index,
            slot,
        };
        self.nullifiers.insert(bucket_nullifier);
        self.confidential_fee_buckets
            .insert(bucket_id.clone(), bucket);
        self.record_event("confidential_blob_da_fee_bucket_committed", &bucket_id);
        self.recompute_roots();
        Ok(bucket_id)
    }

    pub fn record_pq_verifier_eligibility(
        &mut self,
        pool_id: impl Into<String>,
        verifier_commitment: impl Into<String>,
        pq_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        security_bits: u16,
        privacy_set_size: u64,
        slot: u64,
    ) -> Result<String> {
        let pool_id = pool_id.into();
        if !self.futures_pools.contains_key(&pool_id) {
            return Err("unknown futures pool for PQ verifier eligibility".to_string());
        }
        if security_bits < self.config.min_pq_security_bits {
            return Err("PQ verifier eligibility below configured security floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("PQ verifier eligibility privacy set below configured floor".to_string());
        }
        let verifier_commitment = verifier_commitment.into();
        let pq_key_commitment = pq_key_commitment.into();
        let signature_commitment = signature_commitment.into();
        let eligibility_id = deterministic_id(
            "pq-verifier-eligibility",
            &[
                &pool_id,
                &verifier_commitment,
                &pq_key_commitment,
                &slot.to_string(),
            ],
        );
        let eligibility_root = deterministic_leaf(
            "pq-verifier-eligibility-root",
            &[
                &eligibility_id,
                &pool_id,
                &pq_key_commitment,
                &signature_commitment,
            ],
        );
        let eligibility = PqVerifierEligibility {
            eligibility_id: eligibility_id.clone(),
            pool_id,
            verifier_commitment,
            pq_key_commitment,
            eligibility_root,
            signature_commitment,
            security_bits,
            privacy_set_size,
            eligible_until_slot: slot.saturating_add(self.config.eligibility_ttl_slots),
        };
        self.pq_verifier_eligibilities
            .insert(eligibility_id.clone(), eligibility);
        self.record_event("pq_blob_da_verifier_eligibility_recorded", &eligibility_id);
        self.recompute_roots();
        Ok(eligibility_id)
    }

    pub fn open_futures_contract(
        &mut self,
        pool_id: impl Into<String>,
        bucket_id: impl Into<String>,
        eligibility_id: impl Into<String>,
        blob_batch_root: impl Into<String>,
        contract_nullifier: impl Into<String>,
        blob_batch_index: u64,
        proof_work_units: u64,
        blob_da_bytes: u64,
        reserved_hedge_micro_units: u64,
        slot: u64,
    ) -> Result<String> {
        let pool_id = pool_id.into();
        let bucket_id = bucket_id.into();
        let eligibility_id = eligibility_id.into();
        let contract_nullifier = contract_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &contract_nullifier)?;
        let eligibility = self
            .pq_verifier_eligibilities
            .get(&eligibility_id)
            .ok_or_else(|| "unknown PQ verifier eligibility".to_string())?;
        if eligibility.pool_id != pool_id {
            return Err("PQ verifier eligibility is not bound to futures pool".to_string());
        }
        if slot > eligibility.eligible_until_slot {
            return Err("PQ verifier eligibility has expired".to_string());
        }
        let bucket = self
            .confidential_fee_buckets
            .get(&bucket_id)
            .ok_or_else(|| "unknown confidential fee bucket".to_string())?;
        if bucket.pool_id != pool_id {
            return Err("confidential fee bucket is not bound to futures pool".to_string());
        }
        if blob_batch_index < bucket.min_blob_batch_index
            || blob_batch_index > bucket.max_blob_batch_index
        {
            return Err("blob batch index is outside confidential fee bucket range".to_string());
        }
        if reserved_hedge_micro_units == 0
            || reserved_hedge_micro_units > bucket.capacity_micro_units
        {
            return Err("reserved hedge exceeds confidential bucket capacity".to_string());
        }
        if proof_work_units == 0 || blob_da_bytes == 0 {
            return Err(
                "blob DA fee futures contract requires proof work and blob DA bytes".to_string(),
            );
        }
        let pool = self
            .futures_pools
            .get_mut(&pool_id)
            .ok_or_else(|| "unknown blob DA fee futures pool".to_string())?;
        if !pool.status.accepts_contracts() {
            return Err("futures pool is not accepting contracts".to_string());
        }
        if slot > pool.expires_slot {
            pool.status = PoolStatus::Expired;
            return Err("futures pool has expired".to_string());
        }
        if reserved_hedge_micro_units > pool.available_hedge_micro_units {
            return Err("insufficient futures pool hedge liquidity".to_string());
        }
        let gross_fee = estimated_fee(&self.config, pool.lane, proof_work_units, blob_da_bytes);
        let max_hedge = gross_fee
            .saturating_mul(self.config.max_hedge_bps)
            .saturating_div(MAX_BPS);
        if reserved_hedge_micro_units > max_hedge {
            return Err("reserved hedge exceeds configured gross fee bound".to_string());
        }
        let max_user_fee_micro_units = gross_fee
            .saturating_mul(self.config.max_user_fee_bps)
            .saturating_div(MAX_BPS);
        pool.available_hedge_micro_units = pool
            .available_hedge_micro_units
            .saturating_sub(reserved_hedge_micro_units);
        pool.status = if pool.available_hedge_micro_units == 0 {
            PoolStatus::Exhausted
        } else {
            PoolStatus::Hedging
        };
        let blob_batch_root = blob_batch_root.into();
        let maturity_batch_index =
            blob_batch_index.saturating_add(self.config.futures_maturity_batches);
        let contract_id = deterministic_id(
            "blob-da-fee-futures-contract",
            &[
                &pool_id,
                &bucket_id,
                &eligibility_id,
                &blob_batch_root,
                &contract_nullifier,
                &blob_batch_index.to_string(),
            ],
        );
        let contract = FuturesContract {
            contract_id: contract_id.clone(),
            pool_id,
            bucket_id,
            eligibility_id,
            blob_batch_root,
            contract_nullifier: contract_nullifier.clone(),
            blob_batch_index,
            proof_work_units,
            blob_da_bytes,
            reserved_hedge_micro_units,
            max_user_fee_micro_units,
            maturity_batch_index,
            slot,
        };
        self.nullifiers.insert(contract_nullifier);
        self.counters.reserved_hedge_micro_units = self
            .counters
            .reserved_hedge_micro_units
            .saturating_add(reserved_hedge_micro_units);
        self.futures_contracts.insert(contract_id.clone(), contract);
        self.record_event("blob_da_fee_futures_contract_opened", &contract_id);
        self.recompute_roots();
        Ok(contract_id)
    }

    pub fn settle_futures_contract(
        &mut self,
        contract_id: impl Into<String>,
        settlement_nullifier: impl Into<String>,
        user_fee_micro_units: u64,
        realized_blob_batch_index: u64,
        slot: u64,
    ) -> Result<String> {
        let contract_id = contract_id.into();
        let settlement_nullifier = settlement_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &settlement_nullifier)?;
        let contract = self
            .futures_contracts
            .get(&contract_id)
            .ok_or_else(|| "unknown blob DA fee futures contract".to_string())?;
        if realized_blob_batch_index < contract.maturity_batch_index {
            return Err("blob DA fee futures contract has not reached maturity".to_string());
        }
        let pool = self
            .futures_pools
            .get(&contract.pool_id)
            .ok_or_else(|| "unknown futures pool for settlement".to_string())?;
        let proof_fee = smoothed_proof_fee(&self.config, pool.lane, contract.proof_work_units);
        let blob_da_fee = smoothed_blob_da_fee(&self.config, pool.lane, contract.blob_da_bytes);
        let gross_fee = proof_fee.saturating_add(blob_da_fee);
        let target_user_fee = gross_fee
            .saturating_mul(self.config.target_user_fee_bps)
            .saturating_div(MAX_BPS);
        if user_fee_micro_units > contract.max_user_fee_micro_units {
            return Err("user fee exceeds blob DA low-fee futures cap".to_string());
        }
        let target_hedge = gross_fee
            .saturating_mul(self.config.target_hedge_bps)
            .saturating_div(MAX_BPS);
        let fee_gap_hedge = gross_fee
            .saturating_sub(user_fee_micro_units.max(target_user_fee))
            .min(contract.reserved_hedge_micro_units);
        let hedge_credit = fee_gap_hedge
            .max(target_hedge)
            .min(contract.reserved_hedge_micro_units);
        let settlement_id = deterministic_id(
            "blob-da-fee-futures-settlement",
            &[&contract_id, &settlement_nullifier, &slot.to_string()],
        );
        let settlement = FuturesSettlement {
            settlement_id: settlement_id.clone(),
            contract_id,
            pool_id: contract.pool_id.clone(),
            settlement_nullifier: settlement_nullifier.clone(),
            proof_fee_micro_units: proof_fee,
            blob_da_fee_micro_units: blob_da_fee,
            gross_fee_micro_units: gross_fee,
            user_fee_micro_units,
            hedge_credit_micro_units: hedge_credit,
            smoothing_window_batches: self.config.smoothing_window_batches,
            maturity_batch_index: contract.maturity_batch_index,
            slot,
        };
        self.nullifiers.insert(settlement_nullifier);
        self.counters.settled_hedge_micro_units = self
            .counters
            .settled_hedge_micro_units
            .saturating_add(hedge_credit);
        self.counters.smoothed_proof_fee_micro_units = self
            .counters
            .smoothed_proof_fee_micro_units
            .saturating_add(proof_fee);
        self.counters.smoothed_blob_da_fee_micro_units = self
            .counters
            .smoothed_blob_da_fee_micro_units
            .saturating_add(blob_da_fee);
        if let Some(pool) = self.futures_pools.get_mut(&settlement.pool_id) {
            if pool.status == PoolStatus::Hedging {
                pool.status = PoolStatus::Settling;
            }
        }
        self.futures_settlements
            .insert(settlement_id.clone(), settlement);
        self.record_event("blob_da_fee_futures_contract_settled", &settlement_id);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn recompute_roots(&mut self) {
        self.counters.futures_pools = self.futures_pools.len() as u64;
        self.counters.confidential_fee_buckets = self.confidential_fee_buckets.len() as u64;
        self.counters.pq_verifier_eligibilities = self.pq_verifier_eligibilities.len() as u64;
        self.counters.futures_contracts = self.futures_contracts.len() as u64;
        self.counters.futures_settlements = self.futures_settlements.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.futures_pool_root =
            map_root(D_POOLS, &self.futures_pools, FuturesPool::public_record);
        self.roots.confidential_fee_bucket_root = map_root(
            D_BUCKETS,
            &self.confidential_fee_buckets,
            ConfidentialFeeBucket::public_record,
        );
        self.roots.pq_verifier_eligibility_root = map_root(
            D_ELIGIBILITY,
            &self.pq_verifier_eligibilities,
            PqVerifierEligibility::public_record,
        );
        self.roots.futures_contract_root = map_root(
            D_CONTRACTS,
            &self.futures_contracts,
            FuturesContract::public_record,
        );
        self.roots.futures_settlement_root = map_root(
            D_SETTLEMENTS,
            &self.futures_settlements,
            FuturesSettlement::public_record,
        );
        self.roots.nullifier_root = set_root(D_NULLIFIERS, &self.nullifiers);
        self.roots.public_events_root = list_root(D_EVENTS, &self.public_events);
        self.roots.deterministic_state_root = self.state_root();
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "futures_pools": public_map(&self.futures_pools, FuturesPool::public_record),
            "confidential_fee_buckets": public_map(&self.confidential_fee_buckets, ConfidentialFeeBucket::public_record),
            "pq_verifier_eligibilities": public_map(&self.pq_verifier_eligibilities, PqVerifierEligibility::public_record),
            "futures_contracts": public_map(&self.futures_contracts, FuturesContract::public_record),
            "futures_settlements": public_map(&self.futures_settlements, FuturesSettlement::public_record),
            "nullifiers": self.nullifiers,
            "public_events": self.public_events,
            "privacy_boundary": PRIVACY_BOUNDARY
        })
    }

    fn record_event(&mut self, kind: &str, subject_id: &str) {
        self.public_events.push(json!({
            "kind": kind,
            "subject_id": subject_id,
            "event_index": self.public_events.len() as u64,
            "event_root": deterministic_leaf(kind, &[subject_id, &self.public_events.len().to_string()])
        }));
        self.counters.public_events = self.public_events.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool = state
        .open_futures_pool(
            "sponsor_commitment:devnet-blob-da-fee-futures-pool",
            FuturesLane::StandardBlob,
            demo_root("sealed-blob-da-fee-futures-pool"),
            48_000_000,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        )
        .expect("devnet blob DA fee futures pool opens");
    state
        .commit_confidential_fee_bucket(
            pool.clone(),
            demo_root("encrypted-blob-da-fee-futures-bucket"),
            demo_root("blob-da-fee-futures-bucket-commitments"),
            "nullifier:devnet-blob-da-fee-futures-bucket",
            24_000_000,
            0,
            DEFAULT_SMOOTHING_WINDOW_BATCHES - 1,
            DEVNET_EPOCH,
        )
        .expect("devnet confidential blob DA fee bucket commits");
    state
        .record_pq_verifier_eligibility(
            pool,
            "verifier_commitment:devnet-blob-da-fee-futures-verifier",
            "pq_key_commitment:devnet-blob-da-fee-futures-verifier-ml-dsa-87",
            "pq_signature_commitment:devnet-blob-da-fee-futures-verifier",
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH + 1,
        )
        .expect("devnet PQ verifier eligibility records");
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let pool_id = state
        .futures_pools
        .keys()
        .next()
        .cloned()
        .expect("demo has futures pool");
    let bucket_id = state
        .confidential_fee_buckets
        .keys()
        .next()
        .cloned()
        .expect("demo has confidential fee bucket");
    let eligibility_id = state
        .pq_verifier_eligibilities
        .keys()
        .next()
        .cloned()
        .expect("demo has PQ verifier eligibility");
    let contract = state
        .open_futures_contract(
            pool_id,
            bucket_id,
            eligibility_id,
            demo_root("blob-batch-root"),
            "nullifier:devnet-blob-da-fee-futures-contract",
            9,
            13,
            393_216,
            21_000,
            DEVNET_EPOCH + 4,
        )
        .expect("demo blob DA fee futures contract opens");
    state
        .settle_futures_contract(
            contract,
            "nullifier:devnet-blob-da-fee-futures-settlement",
            15,
            9 + DEFAULT_FUTURES_MATURITY_BATCHES,
            DEVNET_EPOCH + 8,
        )
        .expect("demo blob DA fee futures contract settles");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn public_map<T>(map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> Vec<Value> {
    map.iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect()
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": record_root(domain, &json!({ "key": key, "record": public_record(value) }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!({ "value": value })).collect();
    merkle_root(domain, &leaves)
}

fn list_root(domain: &str, values: &[Value]) -> String {
    let leaves: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "record_root": record_root(domain, &json!({ "index": index, "record": value }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn deterministic_id(label: &str, parts: &[&str]) -> String {
    format!("{label}:{}", deterministic_leaf(label, parts))
}

fn deterministic_leaf(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-DA-FEE-FUTURES-POOL:{domain}"),
        &hash_parts,
        32,
    )
}

fn demo_root(label: &str) -> String {
    deterministic_leaf("demo-root", &[label])
}

fn estimated_fee(
    config: &Config,
    lane: FuturesLane,
    proof_work_units: u64,
    blob_da_bytes: u64,
) -> u64 {
    smoothed_proof_fee(config, lane, proof_work_units).saturating_add(smoothed_blob_da_fee(
        config,
        lane,
        blob_da_bytes,
    ))
}

fn smoothed_proof_fee(config: &Config, lane: FuturesLane, proof_work_units: u64) -> u64 {
    config
        .base_proof_fee_micro_units
        .saturating_mul(proof_work_units)
        .saturating_mul(lane.fee_multiplier_bps())
        .saturating_div(MAX_BPS)
}

fn smoothed_blob_da_fee(config: &Config, lane: FuturesLane, blob_da_bytes: u64) -> u64 {
    let blob_chunks = blob_da_bytes
        .saturating_add(131_071)
        .saturating_div(131_072);
    let window_adjustment_bps = MAX_BPS
        .saturating_add(config.smoothing_window_batches.saturating_mul(25))
        .min(12_000);
    config
        .base_blob_da_fee_micro_units
        .saturating_mul(blob_chunks)
        .saturating_mul(lane.fee_multiplier_bps())
        .saturating_mul(window_adjustment_bps)
        .saturating_div(MAX_BPS)
        .saturating_div(MAX_BPS)
}

fn ensure_nullifier_available(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier {nullifier} already consumed"))
    } else {
        Ok(())
    }
}

fn redacted_commitment(commitment: &str) -> String {
    if commitment.is_empty() {
        return "redacted:empty".to_string();
    }
    let digest = domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-DA-FEE-FUTURES-POOL:REDACTED-COMMITMENT",
        &[HashPart::Str(commitment)],
        16,
    );
    format!("redacted:{digest}")
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), value);
    }
}
