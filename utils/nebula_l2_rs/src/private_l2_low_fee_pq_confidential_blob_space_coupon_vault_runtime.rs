use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBlobSpaceCouponVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_SPACE_COUPON_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-blob-space-coupon-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_SPACE_COUPON_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const COUPON_INVENTORY_SUITE: &str =
    "ml-kem-1024-sealed-confidential-blob-space-coupon-inventory-v1";
pub const PQ_ELIGIBILITY_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-blob-space-vault-eligibility-v1";
pub const AMORTIZED_FEE_SUITE: &str = "low-fee-amortized-proof-da-fee-accounting-coupon-vault-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_coupon_plaintexts_blob_payloads_view_keys_addresses_or_secret_keys";
pub const DEVNET_L2_HEIGHT: u64 = 4_520_000;
pub const DEVNET_EPOCH: u64 = 14_464;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_COUPON_ASSET_ID: &str = "blob-space-coupon-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BLOB_BYTES_PER_COUPON: u64 = 131_072;
pub const DEFAULT_BASE_PROOF_FEE_MICRO_UNITS: u64 = 4_000;
pub const DEFAULT_BASE_DA_FEE_MICRO_UNITS: u64 = 6_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_AMORTIZATION_WINDOW_SLOTS: u64 = 512;
pub const DEFAULT_VAULT_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_ELIGIBILITY_TTL_SLOTS: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:ROOTS";
const D_VAULTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:VAULTS";
const D_INVENTORY: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:INVENTORY";
const D_ELIGIBILITY: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:ELIGIBILITY";
const D_ALLOCATIONS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:ALLOCATIONS";
const D_FEE_LEDGER: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:FEE-LEDGER";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-SPACE-COUPON-VAULT:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobSpaceClass {
    MicroBatch,
    StandardBatch,
    ProofHeavy,
    DaHeavy,
    Emergency,
}

impl BlobSpaceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroBatch => "micro_batch",
            Self::StandardBatch => "standard_batch",
            Self::ProofHeavy => "proof_heavy",
            Self::DaHeavy => "da_heavy",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::MicroBatch => 6_000,
            Self::StandardBatch => 10_000,
            Self::ProofHeavy => 12_500,
            Self::DaHeavy => 14_000,
            Self::Emergency => 20_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    Locked,
    Draining,
    Exhausted,
    Expired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_allocations(self) -> bool {
        matches!(self, Self::Open | Self::Draining)
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
    pub blob_bytes_per_coupon: u64,
    pub base_proof_fee_micro_units: u64,
    pub base_da_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub amortization_window_slots: u64,
    pub vault_ttl_slots: u64,
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
            blob_bytes_per_coupon: DEFAULT_BLOB_BYTES_PER_COUPON,
            base_proof_fee_micro_units: DEFAULT_BASE_PROOF_FEE_MICRO_UNITS,
            base_da_fee_micro_units: DEFAULT_BASE_DA_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            amortization_window_slots: DEFAULT_AMORTIZATION_WINDOW_SLOTS,
            vault_ttl_slots: DEFAULT_VAULT_TTL_SLOTS,
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
            "coupon_inventory_suite": COUPON_INVENTORY_SUITE,
            "pq_eligibility_suite": PQ_ELIGIBILITY_SUITE,
            "amortized_fee_suite": AMORTIZED_FEE_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "blob_bytes_per_coupon": self.blob_bytes_per_coupon,
            "base_proof_fee_micro_units": self.base_proof_fee_micro_units,
            "base_da_fee_micro_units": self.base_da_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "amortization_window_slots": self.amortization_window_slots,
            "vault_ttl_slots": self.vault_ttl_slots,
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
    pub vaults: u64,
    pub inventory_commitments: u64,
    pub pq_eligibility_proofs: u64,
    pub blob_allocations: u64,
    pub fee_ledger_entries: u64,
    pub nullifiers: u64,
    pub public_events: u64,
    pub total_coupon_units: u64,
    pub reserved_coupon_units: u64,
    pub consumed_coupon_units: u64,
    pub amortized_proof_fee_micro_units: u64,
    pub amortized_da_fee_micro_units: u64,
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
    pub vault_root: String,
    pub inventory_root: String,
    pub pq_eligibility_root: String,
    pub blob_allocation_root: String,
    pub amortized_fee_ledger_root: String,
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
    pub blob_space_class: BlobSpaceClass,
    pub sealed_inventory_root: String,
    pub total_coupon_units: u64,
    pub available_coupon_units: u64,
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
            "blob_space_class": self.blob_space_class.as_str(),
            "sealed_inventory_root": self.sealed_inventory_root,
            "total_coupon_units": self.total_coupon_units,
            "available_coupon_units": self.available_coupon_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialInventoryCommitment {
    pub inventory_id: String,
    pub vault_id: String,
    pub encrypted_inventory_root: String,
    pub coupon_commitment_root: String,
    pub coupon_count: u64,
    pub inventory_nullifier: String,
    pub slot: u64,
}

impl ConfidentialInventoryCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "inventory_id": self.inventory_id,
            "vault_id": self.vault_id,
            "encrypted_inventory_root": self.encrypted_inventory_root,
            "coupon_commitment_root": self.coupon_commitment_root,
            "coupon_count": self.coupon_count,
            "inventory_nullifier": self.inventory_nullifier,
            "slot": self.slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqEligibilityProof {
    pub eligibility_id: String,
    pub vault_id: String,
    pub participant_commitment: String,
    pub pq_key_commitment: String,
    pub proof_root: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub eligible_until_slot: u64,
}

impl PqEligibilityProof {
    pub fn public_record(&self) -> Value {
        json!({
            "eligibility_id": self.eligibility_id,
            "vault_id": self.vault_id,
            "participant_commitment": redacted_commitment(&self.participant_commitment),
            "pq_key_commitment": redacted_commitment(&self.pq_key_commitment),
            "proof_root": self.proof_root,
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "eligible_until_slot": self.eligible_until_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobSpaceAllocation {
    pub allocation_id: String,
    pub vault_id: String,
    pub eligibility_id: String,
    pub blob_commitment_root: String,
    pub coupon_nullifier: String,
    pub coupon_units: u64,
    pub blob_bytes_reserved: u64,
    pub slot: u64,
}

impl BlobSpaceAllocation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmortizedFeeLedgerEntry {
    pub fee_entry_id: String,
    pub allocation_id: String,
    pub vault_id: String,
    pub proof_fee_micro_units: u64,
    pub da_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub sponsor_subsidy_micro_units: u64,
    pub amortization_window_slots: u64,
}

impl AmortizedFeeLedgerEntry {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, CouponVault>,
    pub inventory_commitments: BTreeMap<String, ConfidentialInventoryCommitment>,
    pub pq_eligibility_proofs: BTreeMap<String, PqEligibilityProof>,
    pub blob_allocations: BTreeMap<String, BlobSpaceAllocation>,
    pub amortized_fee_ledger: BTreeMap<String, AmortizedFeeLedgerEntry>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            inventory_commitments: BTreeMap::new(),
            pq_eligibility_proofs: BTreeMap::new(),
            blob_allocations: BTreeMap::new(),
            amortized_fee_ledger: BTreeMap::new(),
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

    pub fn open_vault(
        &mut self,
        sponsor_commitment: impl Into<String>,
        blob_space_class: BlobSpaceClass,
        sealed_inventory_root: impl Into<String>,
        coupon_units: u64,
        privacy_set_size: u64,
        opened_slot: u64,
    ) -> Result<String> {
        if coupon_units == 0 {
            return Err("coupon vault requires positive coupon units".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("coupon vault privacy set below configured floor".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        let sealed_inventory_root = sealed_inventory_root.into();
        let vault_id = deterministic_id(
            "vault",
            &[
                &sponsor_commitment,
                blob_space_class.as_str(),
                &sealed_inventory_root,
                &opened_slot.to_string(),
            ],
        );
        let vault = CouponVault {
            vault_id: vault_id.clone(),
            sponsor_commitment,
            blob_space_class,
            sealed_inventory_root,
            total_coupon_units: coupon_units,
            available_coupon_units: coupon_units,
            privacy_set_size,
            opened_slot,
            expires_slot: opened_slot.saturating_add(self.config.vault_ttl_slots),
            status: VaultStatus::Open,
        };
        self.vaults.insert(vault_id.clone(), vault);
        self.counters.total_coupon_units = self
            .counters
            .total_coupon_units
            .saturating_add(coupon_units);
        self.record_event("coupon_vault_opened", &vault_id);
        self.recompute_roots();
        Ok(vault_id)
    }

    pub fn commit_inventory(
        &mut self,
        vault_id: impl Into<String>,
        encrypted_inventory_root: impl Into<String>,
        coupon_commitment_root: impl Into<String>,
        coupon_count: u64,
        inventory_nullifier: impl Into<String>,
        slot: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        if !self.vaults.contains_key(&vault_id) {
            return Err("unknown coupon vault".to_string());
        }
        let inventory_nullifier = inventory_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &inventory_nullifier)?;
        let encrypted_inventory_root = encrypted_inventory_root.into();
        let coupon_commitment_root = coupon_commitment_root.into();
        let inventory_id = deterministic_id(
            "inventory",
            &[
                &vault_id,
                &encrypted_inventory_root,
                &coupon_commitment_root,
                &inventory_nullifier,
            ],
        );
        let inventory = ConfidentialInventoryCommitment {
            inventory_id: inventory_id.clone(),
            vault_id,
            encrypted_inventory_root,
            coupon_commitment_root,
            coupon_count,
            inventory_nullifier: inventory_nullifier.clone(),
            slot,
        };
        self.nullifiers.insert(inventory_nullifier);
        self.inventory_commitments
            .insert(inventory_id.clone(), inventory);
        self.record_event("confidential_inventory_committed", &inventory_id);
        self.recompute_roots();
        Ok(inventory_id)
    }

    pub fn record_pq_eligibility(
        &mut self,
        vault_id: impl Into<String>,
        participant_commitment: impl Into<String>,
        pq_key_commitment: impl Into<String>,
        proof_root: impl Into<String>,
        security_bits: u16,
        privacy_set_size: u64,
        slot: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        if !self.vaults.contains_key(&vault_id) {
            return Err("unknown coupon vault for PQ eligibility".to_string());
        }
        if security_bits < self.config.min_pq_security_bits {
            return Err("PQ eligibility proof below configured security floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("PQ eligibility privacy set below configured floor".to_string());
        }
        let participant_commitment = participant_commitment.into();
        let pq_key_commitment = pq_key_commitment.into();
        let proof_root = proof_root.into();
        let eligibility_id = deterministic_id(
            "pq-eligibility",
            &[
                &vault_id,
                &participant_commitment,
                &pq_key_commitment,
                &proof_root,
            ],
        );
        let proof = PqEligibilityProof {
            eligibility_id: eligibility_id.clone(),
            vault_id,
            participant_commitment,
            pq_key_commitment,
            proof_root,
            security_bits,
            privacy_set_size,
            eligible_until_slot: slot.saturating_add(self.config.eligibility_ttl_slots),
        };
        self.pq_eligibility_proofs
            .insert(eligibility_id.clone(), proof);
        self.record_event("pq_eligibility_recorded", &eligibility_id);
        self.recompute_roots();
        Ok(eligibility_id)
    }

    pub fn allocate_blob_space(
        &mut self,
        vault_id: impl Into<String>,
        eligibility_id: impl Into<String>,
        blob_commitment_root: impl Into<String>,
        coupon_nullifier: impl Into<String>,
        coupon_units: u64,
        slot: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        let eligibility_id = eligibility_id.into();
        let coupon_nullifier = coupon_nullifier.into();
        ensure_nullifier_available(&self.nullifiers, &coupon_nullifier)?;
        let eligibility = self
            .pq_eligibility_proofs
            .get(&eligibility_id)
            .ok_or_else(|| "unknown PQ eligibility proof".to_string())?;
        if eligibility.vault_id != vault_id {
            return Err("PQ eligibility proof is not bound to coupon vault".to_string());
        }
        if slot > eligibility.eligible_until_slot {
            return Err("PQ eligibility proof has expired".to_string());
        }
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or_else(|| "unknown coupon vault".to_string())?;
        if !vault.status.accepts_allocations() {
            return Err("coupon vault is not accepting allocations".to_string());
        }
        if slot > vault.expires_slot {
            vault.status = VaultStatus::Expired;
            return Err("coupon vault has expired".to_string());
        }
        if coupon_units == 0 || coupon_units > vault.available_coupon_units {
            return Err("insufficient confidential coupon inventory".to_string());
        }
        vault.available_coupon_units = vault.available_coupon_units.saturating_sub(coupon_units);
        vault.status = if vault.available_coupon_units == 0 {
            VaultStatus::Exhausted
        } else {
            VaultStatus::Draining
        };
        let blob_commitment_root = blob_commitment_root.into();
        let allocation_id = deterministic_id(
            "blob-allocation",
            &[
                &vault_id,
                &eligibility_id,
                &blob_commitment_root,
                &coupon_nullifier,
                &slot.to_string(),
            ],
        );
        let allocation = BlobSpaceAllocation {
            allocation_id: allocation_id.clone(),
            vault_id: vault_id.clone(),
            eligibility_id,
            blob_commitment_root,
            coupon_nullifier: coupon_nullifier.clone(),
            coupon_units,
            blob_bytes_reserved: coupon_units.saturating_mul(self.config.blob_bytes_per_coupon),
            slot,
        };
        self.nullifiers.insert(coupon_nullifier);
        self.counters.reserved_coupon_units = self
            .counters
            .reserved_coupon_units
            .saturating_add(coupon_units);
        self.blob_allocations
            .insert(allocation_id.clone(), allocation);
        self.record_event("blob_space_allocated", &allocation_id);
        self.recompute_roots();
        Ok(allocation_id)
    }

    pub fn settle_amortized_fees(
        &mut self,
        allocation_id: impl Into<String>,
        user_fee_micro_units: u64,
    ) -> Result<String> {
        let allocation_id = allocation_id.into();
        let allocation = self
            .blob_allocations
            .get(&allocation_id)
            .ok_or_else(|| "unknown blob space allocation".to_string())?;
        let vault = self
            .vaults
            .get(&allocation.vault_id)
            .ok_or_else(|| "unknown coupon vault for fee settlement".to_string())?;
        let proof_fee = amortized_component_fee(
            self.config.base_proof_fee_micro_units,
            allocation.coupon_units,
            vault.blob_space_class,
        );
        let da_fee = amortized_component_fee(
            self.config.base_da_fee_micro_units,
            allocation.coupon_units,
            vault.blob_space_class,
        );
        let gross_fee = proof_fee.saturating_add(da_fee);
        let max_user_fee = gross_fee
            .saturating_mul(self.config.max_user_fee_bps)
            .saturating_div(MAX_BPS);
        if user_fee_micro_units > max_user_fee {
            return Err("user fee exceeds low-fee vault cap".to_string());
        }
        let fee_entry_id = deterministic_id(
            "amortized-fee",
            &[&allocation_id, &user_fee_micro_units.to_string()],
        );
        let entry = AmortizedFeeLedgerEntry {
            fee_entry_id: fee_entry_id.clone(),
            allocation_id: allocation_id.clone(),
            vault_id: allocation.vault_id.clone(),
            proof_fee_micro_units: proof_fee,
            da_fee_micro_units: da_fee,
            user_fee_micro_units,
            sponsor_subsidy_micro_units: gross_fee.saturating_sub(user_fee_micro_units),
            amortization_window_slots: self.config.amortization_window_slots,
        };
        self.counters.consumed_coupon_units = self
            .counters
            .consumed_coupon_units
            .saturating_add(allocation.coupon_units);
        self.counters.amortized_proof_fee_micro_units = self
            .counters
            .amortized_proof_fee_micro_units
            .saturating_add(proof_fee);
        self.counters.amortized_da_fee_micro_units = self
            .counters
            .amortized_da_fee_micro_units
            .saturating_add(da_fee);
        self.amortized_fee_ledger
            .insert(fee_entry_id.clone(), entry);
        self.record_event("amortized_fees_settled", &fee_entry_id);
        self.recompute_roots();
        Ok(fee_entry_id)
    }

    pub fn recompute_roots(&mut self) {
        self.counters.vaults = self.vaults.len() as u64;
        self.counters.inventory_commitments = self.inventory_commitments.len() as u64;
        self.counters.pq_eligibility_proofs = self.pq_eligibility_proofs.len() as u64;
        self.counters.blob_allocations = self.blob_allocations.len() as u64;
        self.counters.fee_ledger_entries = self.amortized_fee_ledger.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.vault_root = map_root(D_VAULTS, &self.vaults, CouponVault::public_record);
        self.roots.inventory_root = map_root(
            D_INVENTORY,
            &self.inventory_commitments,
            ConfidentialInventoryCommitment::public_record,
        );
        self.roots.pq_eligibility_root = map_root(
            D_ELIGIBILITY,
            &self.pq_eligibility_proofs,
            PqEligibilityProof::public_record,
        );
        self.roots.blob_allocation_root = map_root(
            D_ALLOCATIONS,
            &self.blob_allocations,
            BlobSpaceAllocation::public_record,
        );
        self.roots.amortized_fee_ledger_root = map_root(
            D_FEE_LEDGER,
            &self.amortized_fee_ledger,
            AmortizedFeeLedgerEntry::public_record,
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
            "vaults": public_map(&self.vaults, CouponVault::public_record),
            "inventory_commitments": public_map(&self.inventory_commitments, ConfidentialInventoryCommitment::public_record),
            "pq_eligibility_proofs": public_map(&self.pq_eligibility_proofs, PqEligibilityProof::public_record),
            "blob_allocations": public_map(&self.blob_allocations, BlobSpaceAllocation::public_record),
            "amortized_fee_ledger": public_map(&self.amortized_fee_ledger, AmortizedFeeLedgerEntry::public_record),
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
        .open_vault(
            "sponsor_commitment:devnet-blob-space-vault",
            BlobSpaceClass::StandardBatch,
            demo_root("sealed-inventory"),
            50_000,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        )
        .expect("devnet coupon vault opens");
    state
        .commit_inventory(
            vault.clone(),
            demo_root("encrypted-inventory"),
            demo_root("coupon-commitments"),
            50_000,
            "nullifier:devnet-inventory",
            DEVNET_EPOCH,
        )
        .expect("devnet inventory commits");
    state
        .record_pq_eligibility(
            vault,
            "participant_commitment:devnet-blob-builder",
            "pq_key_commitment:devnet-blob-builder-ml-dsa-87",
            demo_root("pq-eligibility-proof"),
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH + 1,
        )
        .expect("devnet PQ eligibility records");
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let vault_id = state
        .vaults
        .keys()
        .next()
        .cloned()
        .expect("demo has coupon vault");
    let eligibility_id = state
        .pq_eligibility_proofs
        .keys()
        .next()
        .cloned()
        .expect("demo has PQ eligibility");
    let allocation = state
        .allocate_blob_space(
            vault_id,
            eligibility_id,
            demo_root("blob-commitment"),
            "nullifier:devnet-coupon-allocation",
            8,
            DEVNET_EPOCH + 4,
        )
        .expect("demo blob allocation succeeds");
    state
        .settle_amortized_fees(allocation, 4)
        .expect("demo fee settlement succeeds");
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
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-SPACE-COUPON-VAULT:{domain}"),
        &hash_parts,
        32,
    )
}

fn demo_root(label: &str) -> String {
    deterministic_leaf("demo-root", &[label])
}

fn amortized_component_fee(
    base_fee_micro_units: u64,
    coupon_units: u64,
    blob_space_class: BlobSpaceClass,
) -> u64 {
    base_fee_micro_units
        .saturating_mul(coupon_units)
        .saturating_mul(blob_space_class.fee_multiplier_bps())
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
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-SPACE-COUPON-VAULT:REDACTED-COMMITMENT",
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
