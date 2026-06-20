use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialDaFeeForwardCouponVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DA_FEE_FORWARD_COUPON_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-da-fee-forward-coupon-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DA_FEE_FORWARD_COUPON_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFIDENTIAL_FEE_BUCKET_SUITE: &str =
    "ml-kem-1024-sealed-da-fee-forward-coupon-buckets-v1";
pub const PQ_VERIFIER_ELIGIBILITY_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-da-fee-forward-coupon-eligibility-v1";
pub const DA_FEE_FORWARD_COUPON_SUITE: &str =
    "low-fee-confidential-forward-da-proof-fee-hedging-smoothing-coupon-vault-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_coupon_bucket_plaintexts_da_payloads_view_keys_addresses_or_secret_keys";
pub const DEVNET_L2_HEIGHT: u64 = 4_760_000;
pub const DEVNET_EPOCH: u64 = 15_232;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_COUPON_ASSET_ID: &str = "da-fee-forward-coupon-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_PROOF_FEE_MICRO_UNITS: u64 = 5_750;
pub const DEFAULT_BASE_DA_FEE_MICRO_UNITS: u64 = 6_250;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 21;
pub const DEFAULT_TARGET_HEDGE_BPS: u64 = 46;
pub const DEFAULT_MAX_HEDGE_BPS: u64 = 90;
pub const DEFAULT_BUCKET_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_ELIGIBILITY_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_SMOOTHING_WINDOW_BATCHES: u64 = 28;
pub const DEFAULT_FORWARD_MATURITY_BATCHES: u64 = 48;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:ROOTS";
const D_VAULTS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:VAULTS";
const D_BUCKETS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:BUCKETS";
const D_ELIGIBILITY: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:ELIGIBILITY";
const D_COUPONS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:COUPONS";
const D_SETTLEMENTS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-DA-FEE-FORWARD-COUPON-VAULT:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponLane {
    MicroDa,
    StandardDa,
    ProofHeavy,
    DaHeavy,
    Congested,
}

impl CouponLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroDa => "micro_da",
            Self::StandardDa => "standard_da",
            Self::ProofHeavy => "proof_heavy",
            Self::DaHeavy => "da_heavy",
            Self::Congested => "congested",
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::MicroDa => 6_250,
            Self::StandardDa => 10_000,
            Self::ProofHeavy => 12_750,
            Self::DaHeavy => 15_000,
            Self::Congested => 19_250,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    Hedging,
    Smoothing,
    Exhausted,
    Expired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Hedging => "hedging",
            Self::Smoothing => "smoothing",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_coupons(self) -> bool {
        matches!(self, Self::Open | Self::Hedging | Self::Smoothing)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_proof_fee_micro_units: u64,
    pub base_da_fee_micro_units: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_hedge_bps: u64,
    pub max_hedge_bps: u64,
    pub smoothing_window_batches: u64,
    pub forward_maturity_batches: u64,
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
            coupon_asset_id: DEFAULT_COUPON_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_proof_fee_micro_units: DEFAULT_BASE_PROOF_FEE_MICRO_UNITS,
            base_da_fee_micro_units: DEFAULT_BASE_DA_FEE_MICRO_UNITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_hedge_bps: DEFAULT_TARGET_HEDGE_BPS,
            max_hedge_bps: DEFAULT_MAX_HEDGE_BPS,
            smoothing_window_batches: DEFAULT_SMOOTHING_WINDOW_BATCHES,
            forward_maturity_batches: DEFAULT_FORWARD_MATURITY_BATCHES,
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
            "da_fee_forward_coupon_suite": DA_FEE_FORWARD_COUPON_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "base_proof_fee_micro_units": self.base_proof_fee_micro_units,
            "base_da_fee_micro_units": self.base_da_fee_micro_units,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_hedge_bps": self.target_hedge_bps,
            "max_hedge_bps": self.max_hedge_bps,
            "smoothing_window_batches": self.smoothing_window_batches,
            "forward_maturity_batches": self.forward_maturity_batches,
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
    pub coupon_vaults: u64,
    pub confidential_fee_buckets: u64,
    pub pq_verifier_eligibilities: u64,
    pub forward_coupons: u64,
    pub coupon_settlements: u64,
    pub nullifiers: u64,
    pub public_events: u64,
    pub deposited_coupon_micro_units: u64,
    pub reserved_coupon_micro_units: u64,
    pub settled_coupon_micro_units: u64,
    pub smoothed_proof_fee_micro_units: u64,
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
    pub coupon_vault_root: String,
    pub confidential_fee_bucket_root: String,
    pub pq_verifier_eligibility_root: String,
    pub forward_coupon_root: String,
    pub coupon_settlement_root: String,
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
pub struct CouponVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub lane: CouponLane,
    pub sealed_vault_root: String,
    pub total_coupon_micro_units: u64,
    pub available_coupon_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub status: VaultStatus,
}

impl CouponVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_commitment": redacted_commitment(&self.sponsor_commitment),
            "lane": self.lane.as_str(),
            "sealed_vault_root": self.sealed_vault_root,
            "total_coupon_micro_units": self.total_coupon_micro_units,
            "available_coupon_micro_units": self.available_coupon_micro_units,
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
    pub vault_id: String,
    pub encrypted_bucket_root: String,
    pub bucket_commitment_root: String,
    pub bucket_nullifier: String,
    pub capacity_micro_units: u64,
    pub min_forward_batch_index: u64,
    pub max_forward_batch_index: u64,
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
    pub vault_id: String,
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
            "vault_id": self.vault_id,
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
pub struct ForwardCoupon {
    pub coupon_id: String,
    pub vault_id: String,
    pub bucket_id: String,
    pub eligibility_id: String,
    pub forward_batch_root: String,
    pub coupon_nullifier: String,
    pub forward_batch_index: u64,
    pub proof_work_units: u64,
    pub da_bytes: u64,
    pub reserved_coupon_micro_units: u64,
    pub max_user_fee_micro_units: u64,
    pub maturity_batch_index: u64,
    pub slot: u64,
}

impl ForwardCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponSettlement {
    pub settlement_id: String,
    pub coupon_id: String,
    pub vault_id: String,
    pub settlement_nullifier: String,
    pub proof_fee_micro_units: u64,
    pub da_fee_micro_units: u64,
    pub gross_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub coupon_credit_micro_units: u64,
    pub smoothing_window_batches: u64,
    pub maturity_batch_index: u64,
    pub slot: u64,
}

impl CouponSettlement {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub coupon_vaults: BTreeMap<String, CouponVault>,
    pub confidential_fee_buckets: BTreeMap<String, ConfidentialFeeBucket>,
    pub pq_verifier_eligibilities: BTreeMap<String, PqVerifierEligibility>,
    pub forward_coupons: BTreeMap<String, ForwardCoupon>,
    pub coupon_settlements: BTreeMap<String, CouponSettlement>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            coupon_vaults: BTreeMap::new(),
            confidential_fee_buckets: BTreeMap::new(),
            pq_verifier_eligibilities: BTreeMap::new(),
            forward_coupons: BTreeMap::new(),
            coupon_settlements: BTreeMap::new(),
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

    pub fn open_coupon_vault(
        &mut self,
        sponsor_commitment: impl Into<String>,
        lane: CouponLane,
        sealed_vault_root: impl Into<String>,
        coupon_micro_units: u64,
        privacy_set_size: u64,
        opened_slot: u64,
    ) -> Result<String> {
        if coupon_micro_units == 0 {
            return Err("coupon vault requires positive forward coupon liquidity".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("coupon vault privacy set below configured floor".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        let sealed_vault_root = sealed_vault_root.into();
        let vault_id = deterministic_id(
            "da-fee-forward-coupon-vault",
            &[
                &sponsor_commitment,
                lane.as_str(),
                &sealed_vault_root,
                &opened_slot.to_string(),
            ],
        );
        let vault = CouponVault {
            vault_id: vault_id.clone(),
            sponsor_commitment,
            lane,
            sealed_vault_root,
            total_coupon_micro_units: coupon_micro_units,
            available_coupon_micro_units: coupon_micro_units,
            privacy_set_size,
            opened_slot,
            expires_slot: opened_slot.saturating_add(self.config.bucket_ttl_slots),
            status: VaultStatus::Open,
        };
        self.coupon_vaults.insert(vault_id.clone(), vault);
        self.counters.deposited_coupon_micro_units = self
            .counters
            .deposited_coupon_micro_units
            .saturating_add(coupon_micro_units);
        self.record_event("da_fee_forward_coupon_vault_opened", &vault_id);
        self.recompute_roots();
        Ok(vault_id)
    }

    pub fn commit_confidential_fee_bucket(
        &mut self,
        vault_id: impl Into<String>,
        encrypted_bucket_root: impl Into<String>,
        bucket_commitment_root: impl Into<String>,
        bucket_nullifier: impl Into<String>,
        capacity_micro_units: u64,
        min_forward_batch_index: u64,
        max_forward_batch_index: u64,
        slot: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        if !self.coupon_vaults.contains_key(&vault_id) {
            return Err("unknown DA fee forward coupon vault".to_string());
        }
        if capacity_micro_units == 0 {
            return Err("confidential fee bucket requires positive capacity".to_string());
        }
        if min_forward_batch_index > max_forward_batch_index {
            return Err("confidential fee bucket forward batch range is invalid".to_string());
        }
        let bucket_nullifier = bucket_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &bucket_nullifier)?;
        let encrypted_bucket_root = encrypted_bucket_root.into();
        let bucket_commitment_root = bucket_commitment_root.into();
        let bucket_id = deterministic_id(
            "confidential-forward-fee-bucket",
            &[
                &vault_id,
                &encrypted_bucket_root,
                &bucket_commitment_root,
                &bucket_nullifier,
            ],
        );
        let bucket = ConfidentialFeeBucket {
            bucket_id: bucket_id.clone(),
            vault_id,
            encrypted_bucket_root,
            bucket_commitment_root,
            bucket_nullifier: bucket_nullifier.clone(),
            capacity_micro_units,
            min_forward_batch_index,
            max_forward_batch_index,
            slot,
        };
        self.nullifiers.insert(bucket_nullifier);
        self.confidential_fee_buckets
            .insert(bucket_id.clone(), bucket);
        self.record_event("confidential_forward_da_fee_bucket_committed", &bucket_id);
        self.recompute_roots();
        Ok(bucket_id)
    }

    pub fn record_pq_verifier_eligibility(
        &mut self,
        vault_id: impl Into<String>,
        verifier_commitment: impl Into<String>,
        pq_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        security_bits: u16,
        privacy_set_size: u64,
        slot: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        if !self.coupon_vaults.contains_key(&vault_id) {
            return Err("unknown coupon vault for PQ verifier eligibility".to_string());
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
                &vault_id,
                &verifier_commitment,
                &pq_key_commitment,
                &slot.to_string(),
            ],
        );
        let eligibility_root = deterministic_leaf(
            "pq-verifier-eligibility-root",
            &[
                &eligibility_id,
                &vault_id,
                &pq_key_commitment,
                &signature_commitment,
            ],
        );
        let eligibility = PqVerifierEligibility {
            eligibility_id: eligibility_id.clone(),
            vault_id,
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
            "pq_forward_da_fee_verifier_eligibility_recorded",
            &eligibility_id,
        );
        self.recompute_roots();
        Ok(eligibility_id)
    }

    pub fn issue_forward_coupon(
        &mut self,
        vault_id: impl Into<String>,
        bucket_id: impl Into<String>,
        eligibility_id: impl Into<String>,
        forward_batch_root: impl Into<String>,
        coupon_nullifier: impl Into<String>,
        forward_batch_index: u64,
        proof_work_units: u64,
        da_bytes: u64,
        reserved_coupon_micro_units: u64,
        slot: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        let bucket_id = bucket_id.into();
        let eligibility_id = eligibility_id.into();
        let coupon_nullifier = coupon_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &coupon_nullifier)?;
        let eligibility = self
            .pq_verifier_eligibilities
            .get(&eligibility_id)
            .ok_or_else(|| "unknown PQ verifier eligibility".to_string())?;
        if eligibility.vault_id != vault_id {
            return Err("PQ verifier eligibility is not bound to coupon vault".to_string());
        }
        if slot > eligibility.eligible_until_slot {
            return Err("PQ verifier eligibility has expired".to_string());
        }
        let bucket = self
            .confidential_fee_buckets
            .get(&bucket_id)
            .ok_or_else(|| "unknown confidential fee bucket".to_string())?;
        if bucket.vault_id != vault_id {
            return Err("confidential fee bucket is not bound to coupon vault".to_string());
        }
        if forward_batch_index < bucket.min_forward_batch_index
            || forward_batch_index > bucket.max_forward_batch_index
        {
            return Err("forward batch index is outside confidential bucket range".to_string());
        }
        if reserved_coupon_micro_units == 0
            || reserved_coupon_micro_units > bucket.capacity_micro_units
        {
            return Err("reserved coupon exceeds confidential bucket capacity".to_string());
        }
        if proof_work_units == 0 || da_bytes == 0 {
            return Err("forward coupon requires proof work and DA bytes".to_string());
        }
        let vault = self
            .coupon_vaults
            .get_mut(&vault_id)
            .ok_or_else(|| "unknown DA fee forward coupon vault".to_string())?;
        if !vault.status.accepts_coupons() {
            return Err("coupon vault is not accepting coupons".to_string());
        }
        if slot > vault.expires_slot {
            vault.status = VaultStatus::Expired;
            return Err("coupon vault has expired".to_string());
        }
        if reserved_coupon_micro_units > vault.available_coupon_micro_units {
            return Err("insufficient coupon vault liquidity".to_string());
        }
        let gross_fee = estimated_fee(&self.config, vault.lane, proof_work_units, da_bytes);
        let max_hedge = gross_fee
            .saturating_mul(self.config.max_hedge_bps)
            .saturating_div(MAX_BPS);
        if reserved_coupon_micro_units > max_hedge {
            return Err("reserved coupon exceeds configured gross fee bound".to_string());
        }
        let max_user_fee_micro_units = gross_fee
            .saturating_mul(self.config.max_user_fee_bps)
            .saturating_div(MAX_BPS);
        vault.available_coupon_micro_units = vault
            .available_coupon_micro_units
            .saturating_sub(reserved_coupon_micro_units);
        vault.status = if vault.available_coupon_micro_units == 0 {
            VaultStatus::Exhausted
        } else {
            VaultStatus::Hedging
        };
        let forward_batch_root = forward_batch_root.into();
        let maturity_batch_index =
            forward_batch_index.saturating_add(self.config.forward_maturity_batches);
        let coupon_id = deterministic_id(
            "da-fee-forward-coupon",
            &[
                &vault_id,
                &bucket_id,
                &eligibility_id,
                &forward_batch_root,
                &coupon_nullifier,
                &forward_batch_index.to_string(),
            ],
        );
        let coupon = ForwardCoupon {
            coupon_id: coupon_id.clone(),
            vault_id,
            bucket_id,
            eligibility_id,
            forward_batch_root,
            coupon_nullifier: coupon_nullifier.clone(),
            forward_batch_index,
            proof_work_units,
            da_bytes,
            reserved_coupon_micro_units,
            max_user_fee_micro_units,
            maturity_batch_index,
            slot,
        };
        self.nullifiers.insert(coupon_nullifier);
        self.counters.reserved_coupon_micro_units = self
            .counters
            .reserved_coupon_micro_units
            .saturating_add(reserved_coupon_micro_units);
        self.forward_coupons.insert(coupon_id.clone(), coupon);
        self.record_event("da_fee_forward_coupon_issued", &coupon_id);
        self.recompute_roots();
        Ok(coupon_id)
    }

    pub fn settle_forward_coupon(
        &mut self,
        coupon_id: impl Into<String>,
        settlement_nullifier: impl Into<String>,
        user_fee_micro_units: u64,
        realized_batch_index: u64,
        slot: u64,
    ) -> Result<String> {
        let coupon_id = coupon_id.into();
        let settlement_nullifier = settlement_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &settlement_nullifier)?;
        let coupon = self
            .forward_coupons
            .get(&coupon_id)
            .ok_or_else(|| "unknown DA fee forward coupon".to_string())?;
        if realized_batch_index < coupon.maturity_batch_index {
            return Err("DA fee forward coupon has not reached maturity".to_string());
        }
        let vault = self
            .coupon_vaults
            .get(&coupon.vault_id)
            .ok_or_else(|| "unknown coupon vault for settlement".to_string())?;
        let proof_fee = smoothed_proof_fee(&self.config, vault.lane, coupon.proof_work_units);
        let da_fee = smoothed_da_fee(&self.config, vault.lane, coupon.da_bytes);
        let gross_fee = proof_fee.saturating_add(da_fee);
        let target_user_fee = gross_fee
            .saturating_mul(self.config.target_user_fee_bps)
            .saturating_div(MAX_BPS);
        if user_fee_micro_units > coupon.max_user_fee_micro_units {
            return Err("user fee exceeds forward coupon low-fee cap".to_string());
        }
        let target_hedge = gross_fee
            .saturating_mul(self.config.target_hedge_bps)
            .saturating_div(MAX_BPS);
        let fee_gap_credit = gross_fee
            .saturating_sub(user_fee_micro_units.max(target_user_fee))
            .min(coupon.reserved_coupon_micro_units);
        let coupon_credit = fee_gap_credit
            .max(target_hedge)
            .min(coupon.reserved_coupon_micro_units);
        let settlement_id = deterministic_id(
            "da-fee-forward-coupon-settlement",
            &[&coupon_id, &settlement_nullifier, &slot.to_string()],
        );
        let settlement = CouponSettlement {
            settlement_id: settlement_id.clone(),
            coupon_id,
            vault_id: coupon.vault_id.clone(),
            settlement_nullifier: settlement_nullifier.clone(),
            proof_fee_micro_units: proof_fee,
            da_fee_micro_units: da_fee,
            gross_fee_micro_units: gross_fee,
            user_fee_micro_units,
            coupon_credit_micro_units: coupon_credit,
            smoothing_window_batches: self.config.smoothing_window_batches,
            maturity_batch_index: coupon.maturity_batch_index,
            slot,
        };
        self.nullifiers.insert(settlement_nullifier);
        self.counters.settled_coupon_micro_units = self
            .counters
            .settled_coupon_micro_units
            .saturating_add(coupon_credit);
        self.counters.smoothed_proof_fee_micro_units = self
            .counters
            .smoothed_proof_fee_micro_units
            .saturating_add(proof_fee);
        self.counters.smoothed_da_fee_micro_units = self
            .counters
            .smoothed_da_fee_micro_units
            .saturating_add(da_fee);
        if let Some(vault) = self.coupon_vaults.get_mut(&settlement.vault_id) {
            if vault.status == VaultStatus::Hedging {
                vault.status = VaultStatus::Smoothing;
            }
        }
        self.coupon_settlements
            .insert(settlement_id.clone(), settlement);
        self.record_event("da_fee_forward_coupon_settled", &settlement_id);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn recompute_roots(&mut self) {
        self.counters.coupon_vaults = self.coupon_vaults.len() as u64;
        self.counters.confidential_fee_buckets = self.confidential_fee_buckets.len() as u64;
        self.counters.pq_verifier_eligibilities = self.pq_verifier_eligibilities.len() as u64;
        self.counters.forward_coupons = self.forward_coupons.len() as u64;
        self.counters.coupon_settlements = self.coupon_settlements.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.coupon_vault_root =
            map_root(D_VAULTS, &self.coupon_vaults, CouponVault::public_record);
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
        self.roots.forward_coupon_root = map_root(
            D_COUPONS,
            &self.forward_coupons,
            ForwardCoupon::public_record,
        );
        self.roots.coupon_settlement_root = map_root(
            D_SETTLEMENTS,
            &self.coupon_settlements,
            CouponSettlement::public_record,
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
            "coupon_vaults": public_map(&self.coupon_vaults, CouponVault::public_record),
            "confidential_fee_buckets": public_map(&self.confidential_fee_buckets, ConfidentialFeeBucket::public_record),
            "pq_verifier_eligibilities": public_map(&self.pq_verifier_eligibilities, PqVerifierEligibility::public_record),
            "forward_coupons": public_map(&self.forward_coupons, ForwardCoupon::public_record),
            "coupon_settlements": public_map(&self.coupon_settlements, CouponSettlement::public_record),
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
    let vault = state
        .open_coupon_vault(
            "sponsor_commitment:devnet-da-fee-forward-coupon-vault",
            CouponLane::StandardDa,
            demo_root("sealed-da-fee-forward-coupon-vault"),
            46_000_000,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        )
        .expect("devnet DA fee forward coupon vault opens");
    state
        .commit_confidential_fee_bucket(
            vault.clone(),
            demo_root("encrypted-da-fee-forward-coupon-bucket"),
            demo_root("da-fee-forward-coupon-bucket-commitments"),
            "nullifier:devnet-da-fee-forward-coupon-bucket",
            23_000_000,
            0,
            DEFAULT_SMOOTHING_WINDOW_BATCHES - 1,
            DEVNET_EPOCH,
        )
        .expect("devnet confidential DA fee forward coupon bucket commits");
    state
        .record_pq_verifier_eligibility(
            vault,
            "verifier_commitment:devnet-da-fee-forward-coupon-verifier",
            "pq_key_commitment:devnet-da-fee-forward-coupon-verifier-ml-dsa-87",
            "pq_signature_commitment:devnet-da-fee-forward-coupon-verifier",
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
    let vault_id = state
        .coupon_vaults
        .keys()
        .next()
        .cloned()
        .expect("demo has coupon vault");
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
    let coupon = state
        .issue_forward_coupon(
            vault_id,
            bucket_id,
            eligibility_id,
            demo_root("forward-da-batch-root"),
            "nullifier:devnet-da-fee-forward-coupon",
            7,
            12,
            393_216,
            20_000,
            DEVNET_EPOCH + 4,
        )
        .expect("demo DA fee forward coupon issues");
    state
        .settle_forward_coupon(
            coupon,
            "nullifier:devnet-da-fee-forward-coupon-settlement",
            14,
            7 + DEFAULT_FORWARD_MATURITY_BATCHES,
            DEVNET_EPOCH + 8,
        )
        .expect("demo DA fee forward coupon settles");
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
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-FORWARD-COUPON-VAULT:{domain}"),
        &hash_parts,
        32,
    )
}

fn demo_root(label: &str) -> String {
    deterministic_leaf("demo-root", &[label])
}

fn estimated_fee(config: &Config, lane: CouponLane, proof_work_units: u64, da_bytes: u64) -> u64 {
    smoothed_proof_fee(config, lane, proof_work_units)
        .saturating_add(smoothed_da_fee(config, lane, da_bytes))
}

fn smoothed_proof_fee(config: &Config, lane: CouponLane, proof_work_units: u64) -> u64 {
    config
        .base_proof_fee_micro_units
        .saturating_mul(proof_work_units)
        .saturating_mul(lane.fee_multiplier_bps())
        .saturating_div(MAX_BPS)
}

fn smoothed_da_fee(config: &Config, lane: CouponLane, da_bytes: u64) -> u64 {
    let da_chunks = da_bytes.saturating_add(131_071).saturating_div(131_072);
    let window_adjustment_bps = MAX_BPS
        .saturating_add(config.smoothing_window_batches.saturating_mul(20))
        .min(11_750);
    config
        .base_da_fee_micro_units
        .saturating_mul(da_chunks)
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
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-FORWARD-COUPON-VAULT:REDACTED-COMMITMENT",
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
