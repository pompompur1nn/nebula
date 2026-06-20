use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialRecursiveDaFeeRebatePoolRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_RECURSIVE_DA_FEE_REBATE_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-recursive-da-fee-rebate-pool-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_RECURSIVE_DA_FEE_REBATE_POOL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFIDENTIAL_REBATE_BUCKET_SUITE: &str =
    "ml-kem-1024-sealed-recursive-da-fee-rebate-buckets-v1";
pub const PQ_VERIFIER_ELIGIBILITY_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-recursive-da-fee-rebate-eligibility-v1";
pub const RECURSIVE_DA_FEE_SMOOTHING_SUITE: &str =
    "low-fee-confidential-recursive-da-proof-fee-rebate-smoothing-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_rebate_plaintexts_da_payloads_view_keys_addresses_or_secret_keys";
pub const DEVNET_L2_HEIGHT: u64 = 4_620_000;
pub const DEVNET_EPOCH: u64 = 14_784;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "recursive-da-fee-rebate-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_RECURSIVE_PROOF_FEE_MICRO_UNITS: u64 = 7_000;
pub const DEFAULT_BASE_DA_FEE_MICRO_UNITS: u64 = 5_500;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 42;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 88;
pub const DEFAULT_BUCKET_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_ELIGIBILITY_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_SMOOTHING_WINDOW_BATCHES: u64 = 32;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:ROOTS";
const D_POOLS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:POOLS";
const D_BUCKETS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:BUCKETS";
const D_ELIGIBILITY: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:ELIGIBILITY";
const D_CLAIMS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:CLAIMS";
const D_SETTLEMENTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-DA-FEE-REBATE-POOL:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateLane {
    MicroRecursive,
    StandardRecursive,
    ProofHeavy,
    DaHeavy,
    Congested,
}

impl RebateLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroRecursive => "micro_recursive",
            Self::StandardRecursive => "standard_recursive",
            Self::ProofHeavy => "proof_heavy",
            Self::DaHeavy => "da_heavy",
            Self::Congested => "congested",
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::MicroRecursive => 6_000,
            Self::StandardRecursive => 10_000,
            Self::ProofHeavy => 13_500,
            Self::DaHeavy => 14_750,
            Self::Congested => 19_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Rebating,
    Draining,
    Exhausted,
    Expired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Rebating => "rebating",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Open | Self::Rebating | Self::Draining)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_recursive_proof_fee_micro_units: u64,
    pub base_da_fee_micro_units: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub smoothing_window_batches: u64,
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
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_recursive_proof_fee_micro_units: DEFAULT_BASE_RECURSIVE_PROOF_FEE_MICRO_UNITS,
            base_da_fee_micro_units: DEFAULT_BASE_DA_FEE_MICRO_UNITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            smoothing_window_batches: DEFAULT_SMOOTHING_WINDOW_BATCHES,
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
            "confidential_rebate_bucket_suite": CONFIDENTIAL_REBATE_BUCKET_SUITE,
            "pq_verifier_eligibility_suite": PQ_VERIFIER_ELIGIBILITY_SUITE,
            "recursive_da_fee_smoothing_suite": RECURSIVE_DA_FEE_SMOOTHING_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "base_recursive_proof_fee_micro_units": self.base_recursive_proof_fee_micro_units,
            "base_da_fee_micro_units": self.base_da_fee_micro_units,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "smoothing_window_batches": self.smoothing_window_batches,
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
    pub rebate_pools: u64,
    pub confidential_rebate_buckets: u64,
    pub pq_verifier_eligibilities: u64,
    pub recursive_da_fee_claims: u64,
    pub rebate_settlements: u64,
    pub nullifiers: u64,
    pub public_events: u64,
    pub deposited_rebate_micro_units: u64,
    pub reserved_rebate_micro_units: u64,
    pub settled_rebate_micro_units: u64,
    pub smoothed_recursive_proof_fee_micro_units: u64,
    pub smoothed_da_fee_micro_units: u64,
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
    pub rebate_pool_root: String,
    pub confidential_rebate_bucket_root: String,
    pub pq_verifier_eligibility_root: String,
    pub recursive_da_fee_claim_root: String,
    pub rebate_settlement_root: String,
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
pub struct RebatePool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub lane: RebateLane,
    pub sealed_pool_root: String,
    pub total_rebate_micro_units: u64,
    pub available_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub status: PoolStatus,
}

impl RebatePool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": redacted_commitment(&self.sponsor_commitment),
            "lane": self.lane.as_str(),
            "sealed_pool_root": self.sealed_pool_root,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "available_rebate_micro_units": self.available_rebate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialRebateBucket {
    pub bucket_id: String,
    pub pool_id: String,
    pub encrypted_bucket_root: String,
    pub bucket_commitment_root: String,
    pub bucket_nullifier: String,
    pub capacity_micro_units: u64,
    pub min_recursive_batch_index: u64,
    pub max_recursive_batch_index: u64,
    pub slot: u64,
}

impl ConfidentialRebateBucket {
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
pub struct RecursiveDaFeeClaim {
    pub claim_id: String,
    pub pool_id: String,
    pub bucket_id: String,
    pub eligibility_id: String,
    pub recursive_batch_root: String,
    pub claim_nullifier: String,
    pub recursive_batch_index: u64,
    pub recursive_proof_work_units: u64,
    pub da_bytes: u64,
    pub requested_rebate_micro_units: u64,
    pub max_user_fee_micro_units: u64,
    pub slot: u64,
}

impl RecursiveDaFeeClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlement {
    pub settlement_id: String,
    pub claim_id: String,
    pub pool_id: String,
    pub settlement_nullifier: String,
    pub recursive_proof_fee_micro_units: u64,
    pub da_fee_micro_units: u64,
    pub gross_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub smoothing_window_batches: u64,
    pub slot: u64,
}

impl RebateSettlement {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub rebate_pools: BTreeMap<String, RebatePool>,
    pub confidential_rebate_buckets: BTreeMap<String, ConfidentialRebateBucket>,
    pub pq_verifier_eligibilities: BTreeMap<String, PqVerifierEligibility>,
    pub recursive_da_fee_claims: BTreeMap<String, RecursiveDaFeeClaim>,
    pub rebate_settlements: BTreeMap<String, RebateSettlement>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            rebate_pools: BTreeMap::new(),
            confidential_rebate_buckets: BTreeMap::new(),
            pq_verifier_eligibilities: BTreeMap::new(),
            recursive_da_fee_claims: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
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

    pub fn open_rebate_pool(
        &mut self,
        sponsor_commitment: impl Into<String>,
        lane: RebateLane,
        sealed_pool_root: impl Into<String>,
        rebate_micro_units: u64,
        privacy_set_size: u64,
        opened_slot: u64,
    ) -> Result<String> {
        if rebate_micro_units == 0 {
            return Err("rebate pool requires positive rebate liquidity".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("rebate pool privacy set below configured floor".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        let sealed_pool_root = sealed_pool_root.into();
        let pool_id = deterministic_id(
            "rebate-pool",
            &[
                &sponsor_commitment,
                lane.as_str(),
                &sealed_pool_root,
                &opened_slot.to_string(),
            ],
        );
        let pool = RebatePool {
            pool_id: pool_id.clone(),
            sponsor_commitment,
            lane,
            sealed_pool_root,
            total_rebate_micro_units: rebate_micro_units,
            available_rebate_micro_units: rebate_micro_units,
            privacy_set_size,
            opened_slot,
            expires_slot: opened_slot.saturating_add(self.config.bucket_ttl_slots),
            status: PoolStatus::Open,
        };
        self.rebate_pools.insert(pool_id.clone(), pool);
        self.counters.deposited_rebate_micro_units = self
            .counters
            .deposited_rebate_micro_units
            .saturating_add(rebate_micro_units);
        self.record_event("recursive_da_fee_rebate_pool_opened", &pool_id);
        self.recompute_roots();
        Ok(pool_id)
    }

    pub fn commit_confidential_rebate_bucket(
        &mut self,
        pool_id: impl Into<String>,
        encrypted_bucket_root: impl Into<String>,
        bucket_commitment_root: impl Into<String>,
        bucket_nullifier: impl Into<String>,
        capacity_micro_units: u64,
        min_recursive_batch_index: u64,
        max_recursive_batch_index: u64,
        slot: u64,
    ) -> Result<String> {
        let pool_id = pool_id.into();
        if !self.rebate_pools.contains_key(&pool_id) {
            return Err("unknown rebate pool".to_string());
        }
        if capacity_micro_units == 0 {
            return Err("confidential rebate bucket requires positive capacity".to_string());
        }
        if min_recursive_batch_index > max_recursive_batch_index {
            return Err("confidential rebate bucket recursive batch range is invalid".to_string());
        }
        let bucket_nullifier = bucket_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &bucket_nullifier)?;
        let encrypted_bucket_root = encrypted_bucket_root.into();
        let bucket_commitment_root = bucket_commitment_root.into();
        let bucket_id = deterministic_id(
            "rebate-bucket",
            &[
                &pool_id,
                &encrypted_bucket_root,
                &bucket_commitment_root,
                &bucket_nullifier,
            ],
        );
        let bucket = ConfidentialRebateBucket {
            bucket_id: bucket_id.clone(),
            pool_id,
            encrypted_bucket_root,
            bucket_commitment_root,
            bucket_nullifier: bucket_nullifier.clone(),
            capacity_micro_units,
            min_recursive_batch_index,
            max_recursive_batch_index,
            slot,
        };
        self.nullifiers.insert(bucket_nullifier);
        self.confidential_rebate_buckets
            .insert(bucket_id.clone(), bucket);
        self.record_event(
            "confidential_recursive_da_rebate_bucket_committed",
            &bucket_id,
        );
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
        if !self.rebate_pools.contains_key(&pool_id) {
            return Err("unknown rebate pool for PQ verifier eligibility".to_string());
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
        self.record_event(
            "pq_recursive_da_verifier_eligibility_recorded",
            &eligibility_id,
        );
        self.recompute_roots();
        Ok(eligibility_id)
    }

    pub fn claim_recursive_da_fee_rebate(
        &mut self,
        pool_id: impl Into<String>,
        bucket_id: impl Into<String>,
        eligibility_id: impl Into<String>,
        recursive_batch_root: impl Into<String>,
        claim_nullifier: impl Into<String>,
        recursive_batch_index: u64,
        recursive_proof_work_units: u64,
        da_bytes: u64,
        requested_rebate_micro_units: u64,
        slot: u64,
    ) -> Result<String> {
        let pool_id = pool_id.into();
        let bucket_id = bucket_id.into();
        let eligibility_id = eligibility_id.into();
        let claim_nullifier = claim_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &claim_nullifier)?;
        let eligibility = self
            .pq_verifier_eligibilities
            .get(&eligibility_id)
            .ok_or_else(|| "unknown PQ verifier eligibility".to_string())?;
        if eligibility.pool_id != pool_id {
            return Err("PQ verifier eligibility is not bound to rebate pool".to_string());
        }
        if slot > eligibility.eligible_until_slot {
            return Err("PQ verifier eligibility has expired".to_string());
        }
        let bucket = self
            .confidential_rebate_buckets
            .get(&bucket_id)
            .ok_or_else(|| "unknown confidential rebate bucket".to_string())?;
        if bucket.pool_id != pool_id {
            return Err("confidential rebate bucket is not bound to rebate pool".to_string());
        }
        if recursive_batch_index < bucket.min_recursive_batch_index
            || recursive_batch_index > bucket.max_recursive_batch_index
        {
            return Err("recursive batch index is outside confidential bucket range".to_string());
        }
        if requested_rebate_micro_units == 0
            || requested_rebate_micro_units > bucket.capacity_micro_units
        {
            return Err("requested rebate exceeds confidential bucket capacity".to_string());
        }
        if recursive_proof_work_units == 0 || da_bytes == 0 {
            return Err(
                "recursive DA fee rebate claim requires proof work and DA bytes".to_string(),
            );
        }
        let pool = self
            .rebate_pools
            .get_mut(&pool_id)
            .ok_or_else(|| "unknown rebate pool".to_string())?;
        if !pool.status.accepts_claims() {
            return Err("rebate pool is not accepting claims".to_string());
        }
        if slot > pool.expires_slot {
            pool.status = PoolStatus::Expired;
            return Err("rebate pool has expired".to_string());
        }
        if requested_rebate_micro_units > pool.available_rebate_micro_units {
            return Err("insufficient rebate pool liquidity".to_string());
        }
        let gross_fee = estimated_fee(
            &self.config,
            pool.lane,
            recursive_proof_work_units,
            da_bytes,
        );
        let max_rebate = gross_fee
            .saturating_mul(self.config.max_rebate_bps)
            .saturating_div(MAX_BPS);
        if requested_rebate_micro_units > max_rebate {
            return Err("requested rebate exceeds configured gross fee bound".to_string());
        }
        let max_user_fee_micro_units = gross_fee
            .saturating_mul(self.config.max_user_fee_bps)
            .saturating_div(MAX_BPS);
        pool.available_rebate_micro_units = pool
            .available_rebate_micro_units
            .saturating_sub(requested_rebate_micro_units);
        pool.status = if pool.available_rebate_micro_units == 0 {
            PoolStatus::Exhausted
        } else {
            PoolStatus::Rebating
        };
        let recursive_batch_root = recursive_batch_root.into();
        let claim_id = deterministic_id(
            "recursive-da-fee-claim",
            &[
                &pool_id,
                &bucket_id,
                &eligibility_id,
                &recursive_batch_root,
                &claim_nullifier,
                &recursive_batch_index.to_string(),
            ],
        );
        let claim = RecursiveDaFeeClaim {
            claim_id: claim_id.clone(),
            pool_id,
            bucket_id,
            eligibility_id,
            recursive_batch_root,
            claim_nullifier: claim_nullifier.clone(),
            recursive_batch_index,
            recursive_proof_work_units,
            da_bytes,
            requested_rebate_micro_units,
            max_user_fee_micro_units,
            slot,
        };
        self.nullifiers.insert(claim_nullifier);
        self.counters.reserved_rebate_micro_units = self
            .counters
            .reserved_rebate_micro_units
            .saturating_add(requested_rebate_micro_units);
        self.recursive_da_fee_claims.insert(claim_id.clone(), claim);
        self.record_event("recursive_da_fee_rebate_claimed", &claim_id);
        self.recompute_roots();
        Ok(claim_id)
    }

    pub fn settle_rebate(
        &mut self,
        claim_id: impl Into<String>,
        settlement_nullifier: impl Into<String>,
        user_fee_micro_units: u64,
        slot: u64,
    ) -> Result<String> {
        let claim_id = claim_id.into();
        let settlement_nullifier = settlement_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &settlement_nullifier)?;
        let claim = self
            .recursive_da_fee_claims
            .get(&claim_id)
            .ok_or_else(|| "unknown recursive DA fee rebate claim".to_string())?;
        let pool = self
            .rebate_pools
            .get(&claim.pool_id)
            .ok_or_else(|| "unknown rebate pool for settlement".to_string())?;
        let recursive_proof_fee =
            smoothed_recursive_proof_fee(&self.config, pool.lane, claim.recursive_proof_work_units);
        let da_fee = smoothed_da_fee(&self.config, pool.lane, claim.da_bytes);
        let gross_fee = recursive_proof_fee.saturating_add(da_fee);
        let target_user_fee = gross_fee
            .saturating_mul(self.config.target_user_fee_bps)
            .saturating_div(MAX_BPS);
        if user_fee_micro_units > claim.max_user_fee_micro_units {
            return Err("user fee exceeds recursive DA low-fee cap".to_string());
        }
        let target_rebate = gross_fee
            .saturating_mul(self.config.target_rebate_bps)
            .saturating_div(MAX_BPS);
        let fee_gap_rebate = gross_fee
            .saturating_sub(user_fee_micro_units.max(target_user_fee))
            .min(claim.requested_rebate_micro_units);
        let rebate_micro_units = fee_gap_rebate
            .max(target_rebate)
            .min(claim.requested_rebate_micro_units);
        let settlement_id = deterministic_id(
            "rebate-settlement",
            &[&claim_id, &settlement_nullifier, &slot.to_string()],
        );
        let settlement = RebateSettlement {
            settlement_id: settlement_id.clone(),
            claim_id,
            pool_id: claim.pool_id.clone(),
            settlement_nullifier: settlement_nullifier.clone(),
            recursive_proof_fee_micro_units: recursive_proof_fee,
            da_fee_micro_units: da_fee,
            gross_fee_micro_units: gross_fee,
            user_fee_micro_units,
            rebate_micro_units,
            smoothing_window_batches: self.config.smoothing_window_batches,
            slot,
        };
        self.nullifiers.insert(settlement_nullifier);
        self.counters.settled_rebate_micro_units = self
            .counters
            .settled_rebate_micro_units
            .saturating_add(rebate_micro_units);
        self.counters.smoothed_recursive_proof_fee_micro_units = self
            .counters
            .smoothed_recursive_proof_fee_micro_units
            .saturating_add(recursive_proof_fee);
        self.counters.smoothed_da_fee_micro_units = self
            .counters
            .smoothed_da_fee_micro_units
            .saturating_add(da_fee);
        if let Some(pool) = self.rebate_pools.get_mut(&settlement.pool_id) {
            if pool.status == PoolStatus::Rebating {
                pool.status = PoolStatus::Draining;
            }
        }
        self.rebate_settlements
            .insert(settlement_id.clone(), settlement);
        self.record_event("recursive_da_fee_rebate_settled", &settlement_id);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn recompute_roots(&mut self) {
        self.counters.rebate_pools = self.rebate_pools.len() as u64;
        self.counters.confidential_rebate_buckets = self.confidential_rebate_buckets.len() as u64;
        self.counters.pq_verifier_eligibilities = self.pq_verifier_eligibilities.len() as u64;
        self.counters.recursive_da_fee_claims = self.recursive_da_fee_claims.len() as u64;
        self.counters.rebate_settlements = self.rebate_settlements.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.rebate_pool_root =
            map_root(D_POOLS, &self.rebate_pools, RebatePool::public_record);
        self.roots.confidential_rebate_bucket_root = map_root(
            D_BUCKETS,
            &self.confidential_rebate_buckets,
            ConfidentialRebateBucket::public_record,
        );
        self.roots.pq_verifier_eligibility_root = map_root(
            D_ELIGIBILITY,
            &self.pq_verifier_eligibilities,
            PqVerifierEligibility::public_record,
        );
        self.roots.recursive_da_fee_claim_root = map_root(
            D_CLAIMS,
            &self.recursive_da_fee_claims,
            RecursiveDaFeeClaim::public_record,
        );
        self.roots.rebate_settlement_root = map_root(
            D_SETTLEMENTS,
            &self.rebate_settlements,
            RebateSettlement::public_record,
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
            "rebate_pools": public_map(&self.rebate_pools, RebatePool::public_record),
            "confidential_rebate_buckets": public_map(&self.confidential_rebate_buckets, ConfidentialRebateBucket::public_record),
            "pq_verifier_eligibilities": public_map(&self.pq_verifier_eligibilities, PqVerifierEligibility::public_record),
            "recursive_da_fee_claims": public_map(&self.recursive_da_fee_claims, RecursiveDaFeeClaim::public_record),
            "rebate_settlements": public_map(&self.rebate_settlements, RebateSettlement::public_record),
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
        .open_rebate_pool(
            "sponsor_commitment:devnet-recursive-da-fee-rebate-pool",
            RebateLane::StandardRecursive,
            demo_root("sealed-recursive-da-rebate-pool"),
            45_000_000,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        )
        .expect("devnet recursive DA fee rebate pool opens");
    state
        .commit_confidential_rebate_bucket(
            pool.clone(),
            demo_root("encrypted-recursive-da-rebate-bucket"),
            demo_root("recursive-da-rebate-bucket-commitments"),
            "nullifier:devnet-recursive-da-rebate-bucket",
            22_000_000,
            0,
            DEFAULT_SMOOTHING_WINDOW_BATCHES - 1,
            DEVNET_EPOCH,
        )
        .expect("devnet confidential rebate bucket commits");
    state
        .record_pq_verifier_eligibility(
            pool,
            "verifier_commitment:devnet-recursive-da-verifier",
            "pq_key_commitment:devnet-recursive-da-verifier-ml-dsa-87",
            "pq_signature_commitment:devnet-recursive-da-verifier",
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
        .rebate_pools
        .keys()
        .next()
        .cloned()
        .expect("demo has rebate pool");
    let bucket_id = state
        .confidential_rebate_buckets
        .keys()
        .next()
        .cloned()
        .expect("demo has confidential rebate bucket");
    let eligibility_id = state
        .pq_verifier_eligibilities
        .keys()
        .next()
        .cloned()
        .expect("demo has PQ verifier eligibility");
    let claim = state
        .claim_recursive_da_fee_rebate(
            pool_id,
            bucket_id,
            eligibility_id,
            demo_root("recursive-batch-root"),
            "nullifier:devnet-recursive-da-fee-rebate-claim",
            11,
            12,
            393_216,
            24_000,
            DEVNET_EPOCH + 4,
        )
        .expect("demo recursive DA fee rebate claim succeeds");
    state
        .settle_rebate(
            claim,
            "nullifier:devnet-recursive-da-fee-rebate-settlement",
            16,
            DEVNET_EPOCH + 6,
        )
        .expect("demo recursive DA fee rebate settles");
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
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-RECURSIVE-DA-FEE-REBATE-POOL:{domain}"),
        &hash_parts,
        32,
    )
}

fn demo_root(label: &str) -> String {
    deterministic_leaf("demo-root", &[label])
}

fn estimated_fee(
    config: &Config,
    lane: RebateLane,
    recursive_proof_work_units: u64,
    da_bytes: u64,
) -> u64 {
    smoothed_recursive_proof_fee(config, lane, recursive_proof_work_units)
        .saturating_add(smoothed_da_fee(config, lane, da_bytes))
}

fn smoothed_recursive_proof_fee(
    config: &Config,
    lane: RebateLane,
    recursive_proof_work_units: u64,
) -> u64 {
    config
        .base_recursive_proof_fee_micro_units
        .saturating_mul(recursive_proof_work_units)
        .saturating_mul(lane.fee_multiplier_bps())
        .saturating_div(MAX_BPS)
}

fn smoothed_da_fee(config: &Config, lane: RebateLane, da_bytes: u64) -> u64 {
    let da_chunks = da_bytes.saturating_add(131_071).saturating_div(131_072);
    config
        .base_da_fee_micro_units
        .saturating_mul(da_chunks)
        .saturating_mul(lane.fee_multiplier_bps())
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
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-RECURSIVE-DA-FEE-REBATE-POOL:REDACTED-COMMITMENT",
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
